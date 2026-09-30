#!/usr/bin/env node
// Build the Tauri updater manifest (latest.json) for a release.
//
//   ANVIL_UPDATER_PUBKEY=<base64 public key> \
//   node scripts/updater-manifest.mjs --dist <dir> --repo <owner/name> --tag <tag> --version <x.y.z>
//
// <dir> is laid out as for release-evidence.mjs: one sub-directory per build
// target with a build-info.json. Updater artifacts exist only when the build
// ran with the owner's updater key (TAURI_SIGNING_PRIVATE_KEY + the
// ANVIL_UPDATER_PUBKEY variable); each is a file with a `<file>.sig` beside it:
//
//   macOS    <Product>_<version>_<aarch64|x64>.app.tar.gz(.sig)
//   Linux    *.AppImage(.sig)
//   Windows  *-setup.exe(.sig) (NSIS), *.msi(.sig)
//
// Every signature is verified against ANVIL_UPDATER_PUBKEY (minisign, as the
// updater plugin does at install time) and its signed version must match
// --version; any failure exits 1 and no manifest is written. With no updater
// artifacts the script writes nothing and exits 0.
//
// Platform keys follow tauri-plugin-updater 2.12, which looks up
// `{os}-{arch}-{installer}` and then `{os}-{arch}`. Installer-specific keys
// are always written. The bare `{os}-{arch}` key is written only for macOS,
// whose sole updater format is the .app archive: on Linux it would hand the
// AppImage to .deb/.rpm installs, on Windows the NSIS installer to MSI installs.
//
// The manifest is served from releases/latest/download/latest.json, which
// resolves only once the owner publishes the draft release.
import { createHash, createPublicKey, verify } from "node:crypto";
import { existsSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

// ------------------------------------------------------------ minisign
const b64 = (s) => Buffer.from(s.trim(), "base64");
const lines = (text) =>
  text
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter(Boolean);

/** Decode a Tauri updater public key: base64 of a minisign public key file (or its bare key line). */
export function decodePublicKey(pubkey) {
  const text = b64(pubkey).toString("utf8");
  const keyLine = text.startsWith("untrusted comment:") ? lines(text).at(-1) : pubkey.trim();
  const raw = b64(keyLine);
  if (raw.length !== 42 || raw.subarray(0, 2).toString("latin1") !== "Ed") throw new Error("updater public key is not a minisign Ed25519 key");
  return {
    keyId: raw.subarray(2, 10).toString("hex"),
    // As minisign prints it (little-endian), e.g. in "minisign public key E7620F1842B4E81F".
    displayId: Buffer.from(raw.subarray(2, 10)).reverse().toString("hex").toUpperCase(),
    key: createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: raw.subarray(10).toString("base64url") }, format: "jwk" }),
  };
}

/**
 * Verify the contents of a Tauri `.sig` file (base64 of a minisign signature)
 * over `data`, the way tauri-plugin-updater does. Returns the trusted comment.
 */
export function verifyUpdaterSignature(data, sigFileText, pubkey) {
  const pk = decodePublicKey(pubkey);
  const sig = lines(b64(sigFileText).toString("utf8"));
  if (sig.length < 4 || !sig[0].startsWith("untrusted comment:") || !sig[2].startsWith("trusted comment:")) throw new Error("malformed minisign signature");
  const raw = b64(sig[1]);
  if (raw.length !== 74) throw new Error("malformed minisign signature");
  const alg = raw.subarray(0, 2).toString("latin1");
  if (alg !== "Ed" && alg !== "ED") throw new Error(`unsupported minisign algorithm ${alg}`);
  if (raw.subarray(2, 10).toString("hex") !== pk.keyId) throw new Error("signed with a different key than ANVIL_UPDATER_PUBKEY");
  const signature = raw.subarray(10);
  const message = alg === "ED" ? createHash("blake2b512").update(data).digest() : data;
  if (!verify(null, message, pk.key, signature)) throw new Error("signature does not verify");
  const trusted = sig[2].slice("trusted comment:".length).trim();
  if (!verify(null, Buffer.concat([signature, Buffer.from(trusted, "utf8")]), pk.key, b64(sig[3]))) throw new Error("trusted comment signature does not verify");
  return trusted;
}

/** The `version:` field Tauri writes into the trusted comment, if any. */
export const signedVersion = (trusted) =>
  trusted
    .split("\t")
    .find((f) => f.startsWith("version:"))
    ?.slice("version:".length) ?? null;

// ------------------------------------------------------------ discovery
/** Updater payloads in one target directory, with their manifest platform keys. */
export function updaterArtifacts(dir, target) {
  const arch = target.split("-")[0];
  const os = /apple-darwin/.test(target) ? "darwin" : /windows/.test(target) ? "windows" : /linux/.test(target) ? "linux" : null;
  const rules = [
    [/\.app\.tar\.gz$/, "darwin", "app", true],
    [/\.AppImage$/, "linux", "appimage", false],
    [/-setup\.exe$/, "windows", "nsis", false],
    [/\.msi$/, "windows", "msi", false],
  ];
  const found = [];
  for (const name of readdirSync(dir).sort()) {
    const rule = rules.find(([re, o]) => re.test(name) && o === os);
    if (!rule || !existsSync(join(dir, `${name}.sig`))) continue;
    const [, , installer, generic] = rule;
    const keys = [`${os}-${arch}-${installer}`];
    if (generic) keys.push(`${os}-${arch}`);
    found.push({ name, sig: `${name}.sig`, keys });
  }
  return found;
}

/** Every `.sig` in a target directory without the artifact it signs. */
export function unpairedSignatures(dir) {
  const names = new Set(readdirSync(dir));
  return [...names].filter((n) => n.endsWith(".sig") && !names.has(n.slice(0, -4))).sort();
}

export function targetDirs(dist) {
  return readdirSync(dist)
    .sort()
    .map((d) => join(dist, d))
    .filter((d) => statSync(d).isDirectory() && existsSync(join(d, "build-info.json")))
    .map((dir) => ({ dir, target: JSON.parse(readFileSync(join(dir, "build-info.json"), "utf8")).target }));
}

// ------------------------------------------------------------ main
function main() {
  const arg = (name) => {
    const i = process.argv.indexOf(name);
    return i >= 0 ? process.argv[i + 1] : undefined;
  };
  const dist = arg("--dist");
  const repo = arg("--repo");
  const tag = arg("--tag");
  const version = arg("--version");
  if (!dist || !existsSync(dist) || !repo || !tag || !version) {
    console.error("usage: ANVIL_UPDATER_PUBKEY=<key> updater-manifest.mjs --dist <dir> --repo <owner/name> --tag <tag> --version <x.y.z> [--out <file>]");
    process.exit(2);
  }
  const out = arg("--out") ?? join(dist, "latest.json");
  const pubkey = process.env.ANVIL_UPDATER_PUBKEY?.trim();

  const errors = [];
  const platforms = {};
  let count = 0;
  for (const { dir, target } of targetDirs(dist)) {
    for (const s of unpairedSignatures(dir)) errors.push(`${target}: ${s} has no matching artifact`);
    for (const a of updaterArtifacts(dir, target)) {
      count++;
      if (!pubkey) continue;
      const signature = readFileSync(join(dir, a.sig), "utf8").trim();
      try {
        const trusted = verifyUpdaterSignature(readFileSync(join(dir, a.name)), signature, pubkey);
        const sv = signedVersion(trusted);
        if (sv !== null && sv.replace(/^v/, "") !== version) throw new Error(`signed for version ${sv}, not ${version}`);
      } catch (e) {
        errors.push(`${target}: ${a.name}: ${e.message}`);
        continue;
      }
      const url = `https://github.com/${repo}/releases/download/${encodeURIComponent(tag)}/${encodeURIComponent(a.name)}`;
      for (const key of a.keys) {
        if (platforms[key]) errors.push(`${key}: both ${platforms[key].url} and ${url}`);
        platforms[key] = { signature, url };
      }
    }
  }
  if (count === 0 && errors.length === 0) {
    console.log("no updater artifacts (owner updater key not configured); latest.json not written");
    return;
  }
  if (count > 0 && !pubkey) errors.push("updater signatures present but ANVIL_UPDATER_PUBKEY is not set; cannot verify them");
  if (errors.length) {
    console.error("updater manifest not written:\n  " + errors.join("\n  "));
    process.exit(1);
  }
  const manifest = {
    version,
    notes: `Ferrum Anvil ${version}. Release notes: https://github.com/${repo}/releases/tag/${tag}`,
    pub_date: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
    platforms: Object.fromEntries(Object.entries(platforms).sort(([a], [b]) => a.localeCompare(b))),
  };
  writeFileSync(out, JSON.stringify(manifest, null, 2) + "\n");
  console.log(`wrote ${out}: ${Object.keys(manifest.platforms).join(", ")} (${count} signatures verified)`);
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) main();
