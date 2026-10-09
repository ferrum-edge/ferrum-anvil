#!/usr/bin/env node
// Write the release notes a GitHub release is published with.
//
//   node scripts/release-notes.mjs --version <x.y.z> --evidence <release-evidence.json> --out <notes.md> [--tag <tag>]
//   node scripts/release-notes.mjs --version <x.y.z> --check
//
// The notes come from the version's CHANGELOG.md section and the release
// evidence: the signing warning (or signing line), the section's lead
// paragraphs as the summary, a security line when the section has a Security
// heading, upgrade notes pointing at its Breaking section, and the build line
// with links to the CHANGELOG and the security advisories index.
//
// The release workflow creates the draft with exactly this body, so the body
// that gets published is never a draft placeholder. Draft-only text ("this
// draft is not published", review reminders) belongs in the workflow run
// summary, never here: the script refuses to write notes that contain it.
//
// --check only verifies that CHANGELOG.md has a usable section for --version,
// so preflight fails before anything is built.
import { existsSync, lstatSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

export const UNSIGNED = "unsigned — owner credentials not configured";
export const SIGNED = "signed and verified on the build runner (see targets[].signing)";
// Text that marks a draft placeholder body. None of it may reach a release body.
export const DRAFT_MARKERS = [/draft release of/i, /this draft is not published/i, /review the evidence .* before publishing/i];
const VERSION = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/;
const escapeRegExp = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

// The `## [version]` section of a Keep a Changelog file: its lead paragraphs
// (hard-wrapped lines joined) and its `###` headings.
export function changelogSection(text, version) {
  if (!VERSION.test(version)) throw new Error(`invalid version ${JSON.stringify(version)}`);
  const lines = text.split(/\r?\n/);
  const heading = new RegExp(`^## \\[${escapeRegExp(version)}\\](?:\\s|$)`);
  const start = lines.findIndex((l) => heading.test(l));
  if (start < 0) throw new Error(`CHANGELOG.md has no "## [${version}]" section`);
  let end = lines.findIndex((l, i) => i > start && /^## /.test(l));
  if (end < 0) end = lines.length;
  const body = lines.slice(start + 1, end);
  const firstHeading = body.findIndex((l) => /^### /.test(l));
  const leadLines = firstHeading < 0 ? body : body.slice(0, firstHeading);
  const paragraphs = [];
  let current = [];
  for (const line of [...leadLines, ""]) {
    if (line.trim() === "") {
      if (current.length) paragraphs.push(current.join(" "));
      current = [];
    } else {
      current.push(line.trim());
    }
  }
  if (paragraphs.length === 0) {
    throw new Error(`CHANGELOG.md section ${version} has no summary paragraph before its first ### heading`);
  }
  const headings = body.filter((l) => /^### /.test(l)).map((l) => l.slice(4).trim());
  return { paragraphs, headings };
}

// "Compatibility release: Anvil adopts ..." -> "**Compatibility release.** Anvil adopts ..."
export function summaryParagraph(paragraph) {
  const m = /^([A-Z][A-Za-z ,-]{0,80} release): (.*)$/.exec(paragraph);
  if (!m) return paragraph;
  const rest = m[2].replace(/^[a-z]/, (c) => c.toUpperCase());
  return `**${m[1]}.** ${rest}`;
}

// The release evidence is data written by an earlier job: read it as JSON and
// check every field the notes use before using it.
export function checkEvidence(evidence, version) {
  if (!evidence || typeof evidence !== "object" || Array.isArray(evidence)) {
    throw new Error("release evidence must be a JSON object");
  }
  if (evidence.format !== "anvil-release-evidence" || evidence.version !== 1) {
    throw new Error("unsupported release evidence format or version");
  }
  if (evidence.release?.version !== version) {
    throw new Error(`release evidence is for version ${JSON.stringify(evidence.release?.version)}, not ${version}`);
  }
  if (![SIGNED, UNSIGNED].includes(evidence.signing) || typeof evidence.signed !== "boolean") {
    throw new Error("release evidence signing has an invalid value");
  }
  if (evidence.signed !== (evidence.signing === SIGNED)) {
    throw new Error("release evidence signed and signing disagree");
  }
  const updater = evidence.updater;
  if (!updater || typeof updater !== "object" || Array.isArray(updater)) {
    throw new Error("release evidence updater must be an object");
  }
  if (
    typeof updater.signed !== "boolean" ||
    !(updater.key_id === null || (typeof updater.key_id === "string" && /^[0-9A-F]{16}$/.test(updater.key_id))) ||
    (updater.signed && updater.key_id === null)
  ) {
    throw new Error("release evidence updater has an invalid shape");
  }
  const repository = evidence.source?.repository;
  if (typeof repository !== "string" || !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository)) {
    throw new Error("release evidence source.repository is missing or invalid");
  }
  const commit = evidence.source?.commit;
  if (typeof commit !== "string" || !/^[0-9a-f]{40}$/.test(commit)) {
    throw new Error("release evidence source.commit is missing or invalid");
  }
  const runId = evidence.build?.run_id;
  if (!Number.isSafeInteger(runId) || runId <= 0) {
    throw new Error("release evidence build.run_id is missing or invalid");
  }
  const runUrl = evidence.build?.run_url;
  if (typeof runUrl !== "string" || !runUrl.endsWith(`/${repository}/actions/runs/${runId}`) || !/^https:\/\/[^\s()<>[\]]+$/.test(runUrl)) {
    throw new Error("release evidence build.run_url is missing or invalid");
  }
  return { repository, commit, runId, runUrl, server: runUrl.slice(0, -`/${repository}/actions/runs/${runId}`.length) };
}

export function assertNoDraftText(body) {
  for (const marker of DRAFT_MARKERS) {
    if (marker.test(body)) throw new Error(`release notes contain draft-only text (${marker})`);
  }
}

export function releaseNotes({ changelog, version, tag, evidence }) {
  const expectedTag = `anvil-v${version}`;
  if (tag && tag !== expectedTag) throw new Error(`tag ${tag} does not match version ${version} (expected ${expectedTag})`);
  const section = changelogSection(changelog, version);
  const { repository, commit, runId, runUrl, server } = checkEvidence(evidence, version);
  const repoUrl = `${server}/${repository}`;
  const changelogUrl = `${repoUrl}/blob/${expectedTag}/CHANGELOG.md`;
  const advisoriesUrl = `${repoUrl}/security/advisories`;
  const updater = evidence.updater.signed
    ? `In-app updates *are* signed and verified (minisign key \`${evidence.updater.key_id}\`).`
    : "In-app updates are not signed for this release: the app links to this release page instead.";

  const out = [];
  if (evidence.signed) {
    out.push(`**Signing:** the installers are code-signed and verified on the build runner. Verify downloads with \`SHA256SUMS\`. ${updater}`, "");
  } else {
    out.push(
      "> [!WARNING]",
      `> **Unsigned installers.** The installers are not code-signed yet (no Apple Developer ID or Windows certificate): macOS Gatekeeper and Windows SmartScreen will warn. Verify downloads with \`SHA256SUMS\` before running them. ${updater}`,
      "",
    );
  }
  section.paragraphs.forEach((p, i) => out.push(i === 0 ? summaryParagraph(p) : p, ""));
  if (section.headings.includes("Security")) {
    out.push(`**Security:** this release fixes security issues present in earlier releases; upgrading is recommended. See the Security section of the [CHANGELOG](${changelogUrl}) and the [security advisories](${advisoriesUrl}).`, "");
  }
  out.push(
    section.headings.includes("Breaking")
      ? `**Upgrade notes:** this release has breaking changes. Read the [Breaking section of the CHANGELOG](${changelogUrl}) before upgrading.`
      : "**Upgrade notes:** the CHANGELOG lists no breaking changes for this release.",
    "",
    `Built from \`${commit}\` by [run ${runId}](${runUrl}). \`release-evidence.json\` ties every artifact to its hash, platform, release check, SBOM, license report, compatibility catalog and test runs. See the [CHANGELOG](${changelogUrl}) for the full list and the [security advisories](${advisoriesUrl}) for published advisories.`,
    "",
  );
  const body = out.join("\n");
  assertNoDraftText(body);
  return body;
}

function main() {
  const arg = (name) => {
    const i = process.argv.indexOf(name);
    return i >= 0 ? process.argv[i + 1] : undefined;
  };
  const usage = "usage: release-notes.mjs --version <x.y.z> (--check | --evidence <release-evidence.json> --out <notes.md> [--tag <tag>])";
  const version = arg("--version");
  if (!version) {
    console.error(usage);
    process.exit(2);
  }
  const changelog = readFileSync(join(root, "CHANGELOG.md"), "utf8");
  if (process.argv.includes("--check")) {
    const section = changelogSection(changelog, version);
    console.log(`CHANGELOG.md ${version}: ${section.paragraphs.length} summary paragraph(s), headings: ${section.headings.join(", ") || "none"}`);
    return;
  }
  const evidencePath = arg("--evidence");
  const outPath = arg("--out");
  if (!evidencePath || !outPath) {
    console.error(usage);
    process.exit(2);
  }
  if (!existsSync(evidencePath) || !lstatSync(evidencePath).isFile()) throw new Error("release evidence must be a regular file");
  const evidence = JSON.parse(readFileSync(evidencePath, "utf8"));
  const body = releaseNotes({ changelog, version, tag: arg("--tag") || undefined, evidence });
  mkdirSync(dirname(resolve(outPath)), { recursive: true });
  writeFileSync(outPath, body);
  console.log(body);
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) main();
