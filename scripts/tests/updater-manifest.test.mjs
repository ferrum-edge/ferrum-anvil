// Tests of the minisign verification in scripts/updater-manifest.mjs, run in
// hosted CI with `node --test`. The release workflow uses it to check every
// updater signature before it writes latest.json. These tests are supporting
// evidence for REL-003 only: the app's own refusal is tested through the
// updater plugin (apps/desktop/src-tauri/src/cmd_update/signed_update_tests.rs
// and .github/workflows/updater-e2e.yml).
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, randomBytes, sign } from "node:crypto";
import { test } from "node:test";
import { readFileSync } from "node:fs";
import { checkPublishedManifest, checkSignedVersion, decodePublicKey, signedVersion, verifyTrustedComment, verifyUpdaterSignature } from "../updater-manifest.mjs";

const b64 = (b) => Buffer.from(b).toString("base64");

/** A minisign key pair as `tauri signer generate` makes one; `pubkey` is the `.pub` file contents. */
function keyPair() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const keyId = randomBytes(8);
  const raw = Buffer.from(publicKey.export({ format: "jwk" }).x, "base64url");
  const pubFile = `untrusted comment: minisign public key: ${Buffer.from(keyId).reverse().toString("hex").toUpperCase()}\n${b64(Buffer.concat([Buffer.from("Ed"), keyId, raw]))}\n`;
  return { privateKey, keyId, pubkey: b64(pubFile) };
}

/** A prehashed minisign signature (`.sig` contents) as `tauri signer sign --app-version` writes it. */
function signFile(key, data, { version = "1.2.3", keyId = key.keyId, trusted } = {}) {
  const comment = trusted ?? `timestamp:1790000000\tfile:app.AppImage\tversion:${version}`;
  const signature = sign(null, createHash("blake2b512").update(data).digest(), key.privateKey);
  const global = sign(null, Buffer.concat([signature, Buffer.from(comment)]), key.privateKey);
  const text = `untrusted comment: signature from tauri secret key\n${b64(Buffer.concat([Buffer.from("ED"), keyId, signature]))}\ntrusted comment: ${comment}\n${b64(global)}\n`;
  return b64(text);
}

/** Edit one line of a `.sig` file. */
function editSig(sig, line, edit) {
  const lines = Buffer.from(sig, "base64").toString("utf8").split("\n");
  lines[line] = edit(lines[line]);
  return b64(lines.join("\n"));
}

const key = keyPair();
const artifact = randomBytes(4096);

test("verifyUpdaterSignature accepts the configured key's signature and returns the trusted comment", () => {
  const trusted = verifyUpdaterSignature(artifact, signFile(key, artifact), key.pubkey);
  assert.equal(signedVersion(trusted), "1.2.3");
  assert.doesNotThrow(() => checkSignedVersion(trusted, "1.2.3"));
  assert.equal(decodePublicKey(key.pubkey).keyId, key.keyId.toString("hex"));
});

test("verifyUpdaterSignature refuses a signature made with another key", () => {
  const other = keyPair();
  assert.throws(() => verifyUpdaterSignature(artifact, signFile(other, artifact), key.pubkey), /signed with a different key/);
  // Another key's signature under the configured key id fails the Ed25519 check.
  assert.throws(() => verifyUpdaterSignature(artifact, signFile(other, artifact, { keyId: key.keyId }), key.pubkey), /signature does not verify/);
});

test("verifyUpdaterSignature refuses a bad signature", () => {
  const good = signFile(key, artifact);
  const flipped = editSig(good, 1, (l) => {
    const raw = Buffer.from(l, "base64");
    raw[20] ^= 0x01;
    return b64(raw);
  });
  assert.throws(() => verifyUpdaterSignature(artifact, flipped, key.pubkey), /signature does not verify/);
  // The trusted comment (and so the signed version) is covered by the global signature.
  const relabelled = editSig(good, 2, (l) => l.replace("version:1.2.3", "version:9.9.9"));
  assert.throws(() => verifyUpdaterSignature(artifact, relabelled, key.pubkey), /trusted comment signature does not verify/);
  assert.throws(() => verifyUpdaterSignature(artifact, b64("untrusted comment: x\nnot a signature\n"), key.pubkey), /malformed minisign signature/);
});

test("verifyUpdaterSignature refuses an artifact altered after signing", () => {
  const sig = signFile(key, artifact);
  const flipped = Buffer.from(artifact);
  flipped[flipped.length >> 1] ^= 0x01;
  assert.throws(() => verifyUpdaterSignature(flipped, sig, key.pubkey), /signature does not verify/);
  assert.throws(() => verifyUpdaterSignature(Buffer.concat([artifact, Buffer.from("x")]), sig, key.pubkey), /signature does not verify/);
  assert.throws(() => verifyUpdaterSignature(artifact.subarray(1), sig, key.pubkey), /signature does not verify/);
});

test("checkSignedVersion refuses a signature for another version or with none", () => {
  const trusted = verifyUpdaterSignature(artifact, signFile(key, artifact, { version: "1.2.2" }), key.pubkey);
  assert.throws(() => checkSignedVersion(trusted, "1.2.3"), /signed for version 1\.2\.2, not 1\.2\.3/);
  const legacy = verifyUpdaterSignature(artifact, signFile(key, artifact, { trusted: "timestamp:1790000000\tfile:app.AppImage" }), key.pubkey);
  assert.throws(() => checkSignedVersion(legacy, "1.2.3"), /records no version/);
});

// The published latest.json shape (REL-003): anvil-v0.1.9's manifest as
// GitHub serves it, and the owner's updater public key (minisign key
// BFE08514FEC0E65A, also in the repository variable ANVIL_UPDATER_PUBKEY).
const fixture = (name) => readFileSync(new URL(`fixtures/updater/${name}`, import.meta.url), "utf8");
const PUBLISHED = JSON.parse(fixture("latest-anvil-v0.1.9.json"));
const OWNER_PUBKEY = fixture("updater-pubkey-BFE08514FEC0E65A.txt").trim();
const published = { repo: "ferrum-edge/ferrum-anvil", tag: "anvil-v0.1.9", version: "0.1.9", pubkey: OWNER_PUBKEY };

test("the published anvil-v0.1.9 latest.json has the shape and signatures the app accepts", () => {
  assert.equal(decodePublicKey(OWNER_PUBKEY).displayId, "BFE08514FEC0E65A");
  assert.deepEqual(checkPublishedManifest(PUBLISHED, published), [
    "darwin-aarch64",
    "darwin-aarch64-app",
    "darwin-x86_64",
    "darwin-x86_64-app",
    "linux-x86_64-appimage",
    "windows-x86_64-msi",
    "windows-x86_64-nsis",
  ]);
  for (const entry of Object.values(PUBLISHED.platforms)) assert.equal(signedVersion(verifyTrustedComment(entry.signature, OWNER_PUBKEY)), "0.1.9");
});

test("a published latest.json that the app would misread or refuse is rejected", () => {
  const clone = () => JSON.parse(JSON.stringify(PUBLISHED));
  const bad = [
    [(m) => (m.version = "0.1.8"), /version "0\.1\.8" is not 0\.1\.9/],
    [(m) => (m.pub_date = "yesterday"), /pub_date/],
    [(m) => delete m.platforms["windows-x86_64-msi"], /platforms are/],
    [(m) => (m.platforms["linux-x86_64"] = m.platforms["linux-x86_64-appimage"]), /platforms are/],
    [(m) => (m.platforms["linux-x86_64-appimage"].url = m.platforms["linux-x86_64-appimage"].url.replace("anvil-v0.1.9", "anvil-v0.1.8")), /not an asset of anvil-v0\.1\.9/],
    [(m) => (m.platforms["windows-x86_64-msi"].url = m.platforms["windows-x86_64-nsis"].url), /not that platform's updater file/],
    [(m) => (m.platforms["darwin-aarch64"].signature = m.platforms["linux-x86_64-appimage"].signature.slice(0, -8)), /darwin-aarch64:/],
  ];
  for (const [mutate, message] of bad) {
    const m = clone();
    mutate(m);
    assert.throws(() => checkPublishedManifest(m, published), message);
  }
  // Signed by another key, or for another version.
  const other = keyPair();
  const m = clone();
  m.platforms["linux-x86_64-appimage"].signature = signFile(other, Buffer.from("x"), { version: "0.1.9" });
  assert.throws(() => checkPublishedManifest(m, published), /different key/);
  assert.throws(() => checkPublishedManifest(PUBLISHED, { ...published, version: "0.2.0", tag: "anvil-v0.1.9" }), /version "0\.1\.9" is not 0\.2\.0/);
  // A trusted comment edited after signing no longer verifies.
  const forged = clone();
  const sig = Buffer.from(forged.platforms["linux-x86_64-appimage"].signature, "base64").toString("utf8").replace("version:0.1.9", "version:0.2.0");
  forged.platforms["linux-x86_64-appimage"].signature = Buffer.from(sig).toString("base64");
  assert.throws(() => checkPublishedManifest(forged, published), /trusted comment signature does not verify/);
});
