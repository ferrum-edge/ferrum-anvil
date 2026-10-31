// Tests of the minisign verification in scripts/updater-manifest.mjs, run in
// hosted CI with `node --test`. The release workflow uses it to check every
// updater signature before it writes latest.json. These tests are supporting
// evidence for REL-003 only: the app's own refusal is tested through the
// updater plugin (apps/desktop/src-tauri/src/cmd_update/signed_update_tests.rs
// and .github/workflows/updater-e2e.yml).
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, randomBytes, sign } from "node:crypto";
import { test } from "node:test";
import { checkSignedVersion, decodePublicKey, signedVersion, verifyUpdaterSignature } from "../updater-manifest.mjs";

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
