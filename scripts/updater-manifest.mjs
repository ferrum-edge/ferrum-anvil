#!/usr/bin/env node
// Build the Tauri updater manifest (latest.json) for a release.
//
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
// Every signature is verified against the public key the builds compiled into
// the app (build-info.json `updater.pubkey`, which must be the same for every
// target), as the updater plugin does at install time, and must record a
// signed version equal to --version (the app sets requireSignedVersion); any
// failure exits 1 and no manifest is written. With no updater
// artifacts the script writes nothing and exits 0.
//
// Platform keys follow tauri-plugin-updater 2.14, which looks up
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
const LINE_BREAK = /\r?\n/;
const LEADING_V = /^v/;
const ISO_MILLISECONDS = /\.\d{3}Z$/;
const b64 = (s) => Buffer.from(s.trim(), "base64");
const lines = (text) =>
  text
    .split(LINE_BREAK)
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

function parseSignature(sigFileText, pubkey) {
  const pk = decodePublicKey(pubkey);
  const sig = lines(b64(sigFileText).toString("utf8"));
  if (sig.length < 4 || !sig[0].startsWith("untrusted comment:") || !sig[2].startsWith("trusted comment:")) throw new Error("malformed minisign signature");
  const raw = b64(sig[1]);
  if (raw.length !== 74) throw new Error("malformed minisign signature");
  const alg = raw.subarray(0, 2).toString("latin1");
  if (alg !== "Ed" && alg !== "ED") throw new Error(`unsupported minisign algorithm ${alg}`);
  if (raw.subarray(2, 10).toString("hex") !== pk.keyId) throw new Error("signed with a different key than the one compiled into the app");
  const signature = raw.subarray(10);
  const trusted = sig[2].slice("trusted comment:".length).trim();
  if (!verify(null, Buffer.concat([signature, Buffer.from(trusted, "utf8")]), pk.key, b64(sig[3]))) throw new Error("trusted comment signature does not verify");
  return { pk, alg, signature, trusted };
}

/**
 * Verify the contents of a Tauri `.sig` file (base64 of a minisign signature)
 * over `data`, the way tauri-plugin-updater does. Returns the trusted comment.
 */
export function verifyUpdaterSignature(data, sigFileText, pubkey) {
  const { pk, alg, signature, trusted } = parseSignature(sigFileText, pubkey);
  const message = alg === "ED" ? createHash("blake2b512").update(data).digest() : data;
  if (!verify(null, message, pk.key, signature)) throw new Error("signature does not verify");
  return trusted;
}

/**
 * Verify a `.sig`'s key and trusted comment without the file it signs: the
 * minisign global signature covers the file signature and the trusted comment,
 * so this proves who signed it and for which version. Returns the comment.
 */
export function verifyTrustedComment(sigFileText, pubkey) {
  return parseSignature(sigFileText, pubkey).trusted;
}

/** The platform keys every Anvil release's latest.json carries (see UPDATER_RULES). */
export const PUBLISHED_PLATFORMS = [
  "darwin-aarch64",
  "darwin-aarch64-app",
  "darwin-x86_64",
  "darwin-x86_64-app",
  "linux-x86_64-appimage",
  "windows-x86_64-msi",
  "windows-x86_64-nsis",
];
const ASSET_FOR = { app: /\.app\.tar\.gz$/, appimage: /\.AppImage$/, nsis: /-setup\.exe$/, msi: /\.msi$/ };
const ARCH_FOR = {
  "darwin-aarch64": /(?:_|-)aarch64\./,
  "darwin-x86_64": /(?:_|-)(?:x64|x86_64)\./,
  "linux-x86_64": /(?:_|-)(?:amd64|x86_64)\./,
  "windows-x86_64": /(?:_|-)(?:x64|x86_64)[._-]/,
};
const PLATFORM_KEY = /^(darwin|linux|windows)-(x86_64|aarch64)(?:-(app|appimage|nsis|msi))?$/;
const ISO_DATE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/;

/** The `file:` field minisign / Tauri writes into the trusted comment, if any. */
export const signedFile = (trusted) =>
  trusted
    .split("\t")
    .find((f) => f.startsWith("file:"))
    ?.slice("file:".length) ?? null;

/**
 * Check a published latest.json (Tauri static format) as the app's updater
 * reads it: `version`, a `pub_date` and `notes`, exactly the platform keys
 * Anvil publishes, each with an https URL to that platform's asset of `tag`
 * in `repo` (matching both installer type and architecture), and a signature
 * by `pubkey` whose trusted comment records `version` and a matching file
 * type. When `evidence` (`release-evidence.json`) and/or `signatures` (a map
 * of `<asset>.sig` filename to published `.sig` contents) are provided, also
 * binds each platform key to the exact asset filename and exact published
 * `.sig` sidecar recorded by the release build. Returns the platform keys.
 */
export function checkPublishedManifest(manifest, { repo, tag, version, pubkey, evidence, signatures } = {}) {
  if (!manifest || typeof manifest !== "object" || Array.isArray(manifest)) throw new Error("latest.json is not a JSON object");
  if (manifest.version !== version) throw new Error(`latest.json version ${JSON.stringify(manifest.version)} is not ${version}`);
  if (typeof manifest.pub_date !== "string" || !ISO_DATE.test(manifest.pub_date)) throw new Error("latest.json pub_date is not an RFC 3339 UTC time");
  if (typeof manifest.notes !== "string") throw new Error("latest.json notes is not a string");
  const platforms = manifest.platforms;
  if (!platforms || typeof platforms !== "object" || Array.isArray(platforms)) throw new Error("latest.json platforms is not an object");
  const keys = Object.keys(platforms).sort();
  if (JSON.stringify(keys) !== JSON.stringify([...PUBLISHED_PLATFORMS].sort())) throw new Error(`latest.json platforms are ${keys.join(", ")}, not ${PUBLISHED_PLATFORMS.join(", ")}`);
  const expectedByPlatform = new Map();
  if (evidence) {
    const pk = decodePublicKey(pubkey);
    if (evidence.updater?.signed !== true || evidence.updater?.manifest !== "latest.json") {
      throw new Error("release-evidence.json does not record a signed latest.json");
    }
    if (evidence.updater?.key_id !== pk.displayId) {
      throw new Error(`release-evidence.json key_id ${JSON.stringify(evidence.updater?.key_id)} does not match ${pk.displayId}`);
    }
    for (const target of evidence.targets ?? []) {
      for (const art of target.updater?.artifacts ?? []) {
        for (const pkey of art.platforms ?? []) {
          if (expectedByPlatform.has(pkey)) throw new Error(`release-evidence.json lists ${pkey} more than once`);
          expectedByPlatform.set(pkey, { name: art.name, signature: art.signature });
        }
      }
    }
  }
  const prefix = `https://github.com/${repo}/releases/download/${encodeURIComponent(tag)}/`;
  for (const key of keys) {
    const [, os, arch, installer] = PLATFORM_KEY.exec(key) ?? [];
    const entry = platforms[key];
    if (!entry || typeof entry.url !== "string" || typeof entry.signature !== "string") throw new Error(`latest.json ${key}: needs url and signature strings`);
    if (!entry.url.startsWith(prefix)) throw new Error(`latest.json ${key}: ${entry.url} is not an asset of ${tag}`);
    const asset = decodeURIComponent(entry.url.slice(prefix.length));
    const wanted = ASSET_FOR[installer ?? (os === "darwin" ? "app" : "")];
    if (!wanted || !wanted.test(asset)) throw new Error(`latest.json ${key}: ${asset} is not that platform's updater file`);
    const wantedArch = ARCH_FOR[`${os}-${arch}`];
    if (!wantedArch || !wantedArch.test(asset)) throw new Error(`latest.json ${key}: ${asset} does not match architecture ${os}-${arch}`);
    let trusted;
    try {
      trusted = verifyTrustedComment(entry.signature, pubkey);
      checkSignedVersion(trusted, version);
    } catch (e) {
      throw new Error(`latest.json ${key}: ${e.message}`);
    }
    const sf = signedFile(trusted);
    if (!sf || !wanted.test(sf)) {
      throw new Error(`latest.json ${key}: signature signed file ${JSON.stringify(sf)} does not match ${asset}`);
    }
    if (evidence) {
      const expected = expectedByPlatform.get(key);
      if (!expected) throw new Error(`latest.json ${key}: missing from release-evidence.json`);
      if (asset !== expected.name) throw new Error(`latest.json ${key}: ${asset} does not match release-evidence.json asset ${expected.name}`);
      if (signatures) {
        const expectedSig = signatures[expected.signature];
        if (typeof expectedSig !== "string") throw new Error(`latest.json ${key}: missing sidecar signature ${expected.signature}`);
        if (entry.signature.trim() !== expectedSig.trim()) {
          throw new Error(`latest.json ${key}: inline signature differs from ${expected.signature}`);
        }
      }
    } else if (signatures) {
      const sidecar = `${asset}.sig`;
      const expectedSig = signatures[sidecar];
      if (typeof expectedSig !== "string") throw new Error(`latest.json ${key}: missing sidecar signature ${sidecar}`);
      if (entry.signature.trim() !== expectedSig.trim()) {
        throw new Error(`latest.json ${key}: inline signature differs from ${sidecar}`);
      }
    }
  }
  for (const arch of ["aarch64", "x86_64"]) {
    const bare = platforms[`darwin-${arch}`];
    const specific = platforms[`darwin-${arch}-app`];
    if (bare.url !== specific.url || bare.signature !== specific.signature) {
      throw new Error(`latest.json darwin-${arch} and darwin-${arch}-app must carry the same url and signature`);
    }
  }
  if (platforms["darwin-aarch64"].url === platforms["darwin-x86_64"].url || platforms["darwin-aarch64"].signature === platforms["darwin-x86_64"].signature) {
    throw new Error("latest.json darwin-aarch64 and darwin-x86_64 must not share a url or signature");
  }
  return keys;
}

/** The `version:` field Tauri writes into the trusted comment, if any. */
export const signedVersion = (trusted) =>
  trusted
    .split("\t")
    .find((f) => f.startsWith("version:"))
    ?.slice("version:".length) ?? null;

// ------------------------------------------------------------ discovery
const DARWIN_TARGET = /apple-darwin/;
const WINDOWS_TARGET = /windows/;
const LINUX_TARGET = /linux/;
// [payload file name, manifest os, installer key, also listed under the generic `<os>-<arch>` key]
const UPDATER_RULES = [
  [/\.app\.tar\.gz$/, "darwin", "app", true],
  [/\.AppImage$/, "linux", "appimage", false],
  [/-setup\.exe$/, "windows", "nsis", false],
  [/\.msi$/, "windows", "msi", false],
];

/** Updater payloads in one target directory, with their manifest platform keys. */
export function updaterArtifacts(dir, target) {
  const arch = target.split("-")[0];
  const os = DARWIN_TARGET.test(target) ? "darwin" : WINDOWS_TARGET.test(target) ? "windows" : LINUX_TARGET.test(target) ? "linux" : null;
  const found = [];
  for (const name of readdirSync(dir).sort()) {
    const rule = UPDATER_RULES.find(([re, o]) => re.test(name) && o === os);
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

/**
 * The updater public key the builds compiled into the app: the same
 * build-info.json `updater.pubkey` on every target built with the key. Null
 * when no target was. Throws when targets disagree or one lacks the key.
 */
export function builtPubkey(targets) {
  const keys = new Set();
  for (const t of targets) {
    const u = t.info.updater;
    if (!u?.configured) continue;
    if (!u.pubkey) throw new Error(`${t.target}: built with the updater key but build-info.json records no public key`);
    if (u.embedded !== true) throw new Error(`${t.target}: the updater public key was not found in the built app`);
    keys.add(String(u.pubkey).trim());
  }
  if (keys.size > 1) throw new Error("targets were built with different updater public keys");
  return keys.size ? [...keys][0] : null;
}

/** Check a verified signature's trusted comment against the release version. */
export function checkSignedVersion(trusted, version) {
  const sv = signedVersion(trusted);
  if (sv === null) throw new Error("the signature records no version (the app requires a signed version)");
  if (sv.replace(LEADING_V, "") !== version) throw new Error(`signed for version ${sv}, not ${version}`);
}

export function targetDirs(dist) {
  return readdirSync(dist)
    .sort()
    .map((d) => join(dist, d))
    .filter((d) => statSync(d).isDirectory() && existsSync(join(d, "build-info.json")))
    .map((dir) => {
      const info = JSON.parse(readFileSync(join(dir, "build-info.json"), "utf8"));
      return { dir, target: info.target, info };
    });
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
    console.error("usage: updater-manifest.mjs --dist <dir> --repo <owner/name> --tag <tag> --version <x.y.z> [--out <file>]");
    process.exit(2);
  }
  const out = arg("--out") ?? join(dist, "latest.json");
  const errors = [];
  const targets = targetDirs(dist);
  let pubkey = null;
  try {
    pubkey = builtPubkey(targets);
  } catch (e) {
    errors.push(e.message);
  }
  const platforms = {};
  let count = 0;
  for (const { dir, target, info } of targets) {
    for (const s of unpairedSignatures(dir)) errors.push(`${target}: ${s} has no matching artifact`);
    const artifacts = updaterArtifacts(dir, target);
    if (info.updater?.configured && artifacts.length === 0) errors.push(`${target}: built with the updater key but no signed updater artifact`);
    for (const a of artifacts) {
      count++;
      if (!pubkey) continue;
      const signature = readFileSync(join(dir, a.sig), "utf8").trim();
      try {
        checkSignedVersion(verifyUpdaterSignature(readFileSync(join(dir, a.name)), signature, pubkey), version);
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
    // Nothing configured and nothing signed.
    console.log("no updater artifacts (owner updater key not configured); latest.json not written");
    return;
  }
  if (count > 0 && !pubkey) errors.push("updater signatures present but no build recorded the updater public key; cannot verify them");
  if (errors.length) {
    console.error("updater manifest not written:\n  " + errors.join("\n  "));
    process.exit(1);
  }
  const manifest = {
    version,
    notes: `Ferrum Anvil ${version}. Release notes: https://github.com/${repo}/releases/tag/${tag}`,
    pub_date: new Date().toISOString().replace(ISO_MILLISECONDS, "Z"),
    platforms: Object.fromEntries(Object.entries(platforms).sort(([a], [b]) => a.localeCompare(b))),
  };
  writeFileSync(out, JSON.stringify(manifest, null, 2) + "\n");
  console.log(`wrote ${out}: ${Object.keys(manifest.platforms).join(", ")} (${count} signatures verified)`);
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) main();
