#!/usr/bin/env node
// Assemble release evidence for a set of built artifacts.
//
//   node scripts/release-evidence.mjs --dist <dir> [--test-runs <runs.json>] [--tag <tag>]
//
// <dir> contains one sub-directory per build target (as downloaded from the
// release workflow's build jobs), each holding that target's shipped files and
// a build-info.json written by the build job. Shared files (npm SBOM, license
// report) may sit directly in <dir>. The script writes, into <dir>:
//
//   SHA256SUMS              "<sha256>  <file>" for every shipped file
//   release-evidence.json   version, commit, per-target artifacts (name, size,
//                           sha256, OS/arch), signing status, release-check
//                           results, SBOMs, license report, compatibility
//                           catalog ids and the CI/E2E/lab runs for the commit
//
// Signing is reported exactly as recorded by the build jobs, which only mark a
// target signed after verifying the signature on the runner. Nothing here can
// turn an unsigned artifact into a signed one.
//
// Updater artifacts (`*.sig` beside an .app.tar.gz, AppImage or Windows
// installer) and the shared latest.json exist only when the build ran with the
// owner's updater key. `updater.signed` is true only when latest.json exists
// and every signature in it verifies here against the public key the builds
// compiled into the app (build-info.json `updater.pubkey`) and records the
// release version.
import { createHash } from "node:crypto";
import { existsSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { basename, dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { builtPubkey, checkSignedVersion, decodePublicKey, unpairedSignatures, updaterArtifacts, verifyUpdaterSignature } from "./updater-manifest.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const arg = (name) => {
  const i = process.argv.indexOf(name);
  return i >= 0 ? process.argv[i + 1] : undefined;
};
const dist = arg("--dist");
if (!dist || !existsSync(dist)) {
  console.error("usage: release-evidence.mjs --dist <dir> [--test-runs <runs.json>] [--tag <tag>]");
  process.exit(2);
}
const UNSIGNED = "unsigned — owner credentials not configured";
const GENERATED = new Set(["SHA256SUMS", "release-evidence.json"]);
const META = new Set(["build-info.json"]);

const sha256 = (file) => createHash("sha256").update(readFileSync(file)).digest("hex");
const readJson = (file) => JSON.parse(readFileSync(file, "utf8"));

function kind(name) {
  if (/\.cdx\.json$/.test(name)) return "sbom";
  if (/^release-check-.*\.json$/.test(name)) return "release-check-report";
  if (name === "license-report.json") return "license-report";
  if (/^anvil-cli-/.test(name)) return "cli";
  if (name === "latest.json") return "updater-manifest";
  if (/\.sig$/.test(name)) return "updater-signature";
  if (/\.app\.tar\.gz$/.test(name)) return "updater-bundle";
  if (/\.(dmg|msi|deb|rpm|AppImage)$/.test(name) || /-setup\.exe$/.test(name)) return "desktop-installer";
  return "other";
}

function files(dir) {
  return readdirSync(dir)
    .filter((f) => statSync(join(dir, f)).isFile() && !GENERATED.has(f) && !META.has(f))
    .sort();
}

function describe(dir, name) {
  const p = join(dir, name);
  return { name, kind: kind(name), size: statSync(p).size, sha256: sha256(p) };
}

// ------------------------------------------------------------ inputs
const workspaceVersion = readFileSync(join(root, "Cargo.toml"), "utf8").match(/\[workspace\.package\][^[]*?version\s*=\s*"([^"]+)"/)?.[1];
const tauriConf = readJson(join(root, "apps/desktop/src-tauri/tauri.conf.json"));
const findings = readJson(join(root, "catalog/diagnostics/findings.en.json"));
const ferrum = readdirSync(join(root, "catalog/ferrum"))
  .filter((d) => existsSync(join(root, "catalog/ferrum", d, "outcomes.json")))
  .sort()
  .map((d) => {
    const c = readJson(join(root, "catalog/ferrum", d, "outcomes.json"));
    return {
      compatibility_id: c.compatibility_id,
      gateway_release: c.gateway?.release_tag ?? null,
      gateway_source_sha: c.gateway?.source_sha ?? null,
      outcomes: Array.isArray(c.outcomes) ? c.outcomes.length : null,
      public_tokens: c.public_tokens ?? [],
    };
  });
const readLock = (file) =>
  Object.fromEntries(
    readFileSync(file, "utf8")
      .split("\n")
      .filter((l) => l.trim() && !l.startsWith("#"))
      .map((l) => l.trim().split(/\s+/)),
  );
const lock = readLock(join(root, "lab/gateway/RELEASE.lock"));
// Every release the lab can run (`anvil-lab --release <tag>`), default pin included.
const labReleases = readdirSync(join(root, "lab/gateway/releases"))
  .filter((f) => f.endsWith(".lock"))
  .sort()
  .map((f) => {
    const l = readLock(join(root, "lab/gateway/releases", f));
    return { release: l.release ?? null, source_sha: l.source_sha ?? null };
  });

const targets = [];
for (const d of readdirSync(dist).sort()) {
  const dir = join(dist, d);
  if (!statSync(dir).isDirectory()) continue;
  const infoPath = join(dir, "build-info.json");
  if (!existsSync(infoPath)) throw new Error(`${relative(process.cwd(), dir)} has no build-info.json`);
  const info = readJson(infoPath);
  const artifacts = files(dir).map((f) => describe(dir, f));
  const reportFile = artifacts.find((a) => a.kind === "release-check-report");
  const report = reportFile ? readJson(join(dir, reportFile.name)) : null;
  const signed = info.signing?.signed === true;
  const updater = updaterArtifacts(dir, info.target);
  targets.push({
    target: info.target,
    os: info.os,
    arch: info.arch,
    runner: info.runner ?? null,
    toolchain: info.toolchain ?? null,
    signed,
    signing: signed ? info.signing.method : UNSIGNED,
    signing_detail: info.signing?.detail ?? null,
    release_check: report ? { result: report.result, graph: report.graph, report: reportFile.name, artifacts: report.artifacts } : { result: "missing" },
    updater: { configured: info.updater?.configured === true, artifacts: updater.map((u) => ({ name: u.name, signature: u.sig, platforms: u.keys })) },
    artifacts,
    _dir: dir,
    _info: info,
    _unpaired: unpairedSignatures(dir),
  });
}
if (targets.length === 0) throw new Error(`no target directories with build-info.json under ${dist}`);
const shared = files(dist).map((f) => describe(dist, f));

// ------------------------------------------------------------ checks
const problems = [];
for (const t of targets) {
  if (t.release_check.result !== "pass") problems.push(`${t.target}: release-check result is ${t.release_check.result}`);
  if (!t.artifacts.some((a) => a.kind === "desktop-installer")) problems.push(`${t.target}: no desktop installer`);
  if (!t.artifacts.some((a) => a.kind === "cli")) problems.push(`${t.target}: no CLI archive`);
  if (!t.artifacts.some((a) => a.kind === "sbom")) problems.push(`${t.target}: no SBOM`);
}
const allNames = [...targets.flatMap((t) => t.artifacts.map((a) => a.name)), ...shared.map((a) => a.name)];
const dupes = allNames.filter((n, i) => allNames.indexOf(n) !== i);
if (dupes.length) problems.push(`duplicate artifact names: ${[...new Set(dupes)].join(", ")}`);

// Updater: every signature pairs with an artifact, every signed artifact is in
// latest.json with the same signature and URL, and each verifies against the
// public key the builds compiled into the app.
const manifestPath = join(dist, "latest.json");
const manifest = existsSync(manifestPath) ? readJson(manifestPath) : null;
const updaterProblems = [];
let pubkey = null;
try {
  pubkey = builtPubkey(targets.map((t) => ({ target: t.target, info: t._info })));
} catch (e) {
  updaterProblems.push(e.message);
}
let keyId = null;
if (pubkey) {
  try {
    keyId = decodePublicKey(pubkey).displayId;
  } catch (e) {
    updaterProblems.push(`compiled-in updater public key: ${e.message}`);
  }
}
const signedFiles = new Map();
for (const t of targets) {
  for (const s of t._unpaired) updaterProblems.push(`${t.target}: ${s} has no matching artifact`);
  if (t.updater.configured && t.updater.artifacts.length === 0) updaterProblems.push(`${t.target}: built with the updater key but no signed updater artifact`);
  if (!t.updater.configured && t.updater.artifacts.length > 0) updaterProblems.push(`${t.target}: updater signatures present although the build recorded no updater key`);
  for (const u of t.updater.artifacts) signedFiles.set(u.name, { target: t, ...u });
}
if (signedFiles.size > 0 && !manifest) updaterProblems.push("updater artifacts present but no latest.json");
if (manifest) {
  if (signedFiles.size === 0) updaterProblems.push("latest.json present but no signed updater artifacts");
  if (manifest.version !== workspaceVersion) updaterProblems.push(`latest.json version ${manifest.version} is not ${workspaceVersion}`);
  if (!pubkey) updaterProblems.push("latest.json present but no build recorded the updater public key; signatures not verified");
  const listed = new Set();
  for (const [key, p] of Object.entries(manifest.platforms ?? {})) {
    const file = decodeURIComponent(String(p.url).split("/").pop());
    const a = signedFiles.get(file);
    if (!a) {
      updaterProblems.push(`latest.json ${key}: ${file} is not a signed updater artifact of this release`);
      continue;
    }
    listed.add(file);
    if (!a.platforms.includes(key)) updaterProblems.push(`latest.json ${key}: ${file} belongs under ${a.platforms.join(" / ")}`);
    if (arg("--tag") && !String(p.url).includes(`/releases/download/${encodeURIComponent(arg("--tag"))}/`)) updaterProblems.push(`latest.json ${key}: URL is not under tag ${arg("--tag")}`);
    const sigText = readFileSync(join(a.target._dir, a.signature), "utf8").trim();
    if (p.signature !== sigText) updaterProblems.push(`latest.json ${key}: signature differs from ${a.signature}`);
    if (pubkey && keyId) {
      try {
        checkSignedVersion(verifyUpdaterSignature(readFileSync(join(a.target._dir, file)), p.signature, pubkey), workspaceVersion);
      } catch (e) {
        updaterProblems.push(`${file}: ${e.message}`);
      }
    }
  }
  for (const f of signedFiles.keys()) if (!listed.has(f)) updaterProblems.push(`${f}: signed but not in latest.json`);
}
problems.push(...updaterProblems.map((p) => `updater: ${p}`));
const updaterSigned = Boolean(manifest && pubkey && keyId && signedFiles.size > 0 && updaterProblems.length === 0);
const updaterEvidence = {
  signed: updaterSigned,
  manifest: manifest ? "latest.json" : null,
  key_id: updaterSigned ? keyId : null,
  platforms: manifest ? Object.keys(manifest.platforms ?? {}).sort() : [],
  detail: updaterSigned
    ? `minisign signatures and signed versions verified against the public key compiled into the app (key ${keyId}); in-app updates resolve releases/latest/download/latest.json only after this draft is published`
    : manifest || signedFiles.size > 0
      ? "unverified — see problems"
      : "not configured — owner updater key (TAURI_SIGNING_PRIVATE_KEY, ANVIL_UPDATER_PUBKEY) not set; no updater artifacts, the app links to the release page",
};
for (const t of targets) {
  delete t._dir;
  delete t._info;
  delete t._unpaired;
}

// ------------------------------------------------------------ outputs
const sums = [...targets.flatMap((t) => t.artifacts), ...shared].sort((a, b) => a.name.localeCompare(b.name)).map((a) => `${a.sha256}  ${a.name}`);
writeFileSync(join(dist, "SHA256SUMS"), sums.join("\n") + "\n");

const env = process.env;
const runs = arg("--test-runs") && existsSync(arg("--test-runs")) ? readJson(arg("--test-runs")) : null;
const allSigned = targets.every((t) => t.signed);
const evidence = {
  format: "anvil-release-evidence",
  version: 1,
  generated_at: new Date().toISOString(),
  product: tauriConf.productName,
  release: {
    version: workspaceVersion,
    app_version: tauriConf.version,
    tag: arg("--tag") ?? null,
    // Releases are only ever created as drafts; publishing is a manual owner step.
    publication: arg("--tag") ? "draft" : "dry run — not published",
  },
  source: {
    repository: env.GITHUB_REPOSITORY ?? null,
    // The checked-out release commit (a manual run may build a tag other than the dispatch ref).
    commit: env.RELEASE_COMMIT ?? env.GITHUB_SHA ?? null,
    ref: arg("--tag") ? `refs/tags/${arg("--tag")}` : (env.GITHUB_REF ?? null),
  },
  build: {
    workflow: env.GITHUB_WORKFLOW ?? null,
    run_id: env.GITHUB_RUN_ID ? Number(env.GITHUB_RUN_ID) : null,
    run_attempt: env.GITHUB_RUN_ATTEMPT ? Number(env.GITHUB_RUN_ATTEMPT) : null,
    run_url: env.GITHUB_RUN_ID ? `${env.GITHUB_SERVER_URL}/${env.GITHUB_REPOSITORY}/actions/runs/${env.GITHUB_RUN_ID}` : null,
  },
  signed: allSigned,
  signing: allSigned ? "signed and verified on the build runner (see targets[].signing)" : UNSIGNED,
  updater: updaterEvidence,
  targets,
  shared_artifacts: shared,
  checksums: { file: "SHA256SUMS", algorithm: "sha256" },
  licensing: {
    project: "PolyForm-Noncommercial-1.0.0 (commercial license available; see LICENSE-COMMERCIAL.md)",
    third_party_report: shared.find((a) => a.kind === "license-report")?.name ?? null,
    third_party_summary: "THIRD_PARTY_LICENSES.md (in the source tree at this commit)",
  },
  compatibility: {
    diagnostics_catalog: findings.version,
    ferrum_catalogs: ferrum,
    lab_gateway: { release: lock.release ?? null, source_sha: lock.source_sha ?? null, supported_releases: labReleases },
  },
  tests: runs
    ? {
        note: "GitHub Actions runs for this commit at release time (CI, desktop E2E, lab). Check each conclusion; a skipped or missing run is not a pass.",
        runs,
      }
    : { note: "no test-run listing supplied" },
  problems,
};
writeFileSync(join(dist, "release-evidence.json"), JSON.stringify(evidence, null, 2) + "\n");
console.log(`wrote ${basename(dist)}/SHA256SUMS (${sums.length} files) and release-evidence.json — signed: ${allSigned}, updater signed: ${updaterSigned}`);
if (problems.length) {
  console.error("release evidence problems:\n  " + problems.join("\n  "));
  process.exit(1);
}
