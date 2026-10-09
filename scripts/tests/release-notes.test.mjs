// Tests of scripts/release-notes.mjs, run in hosted CI with `node --test`.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { SIGNED, UNSIGNED, assertNoDraftText, changelogSection, checkEvidence, releaseNotes, summaryParagraph } from "../release-notes.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const COMMIT = "695308f2ce239b4db513c09c07b2353b7b353c3b";
const RUN_URL = "https://github.com/ferrum-edge/ferrum-anvil/actions/runs/37859968362";

const changelog = `# Changelog

## [Unreleased]

## [1.2.0] - 2026-11-01

Hardening release: requests are
bounded and a format changes.

Read the Breaking section below before upgrading.

### Security

- Something is bounded.

### Breaking

- Something changes.

### Added

- A thing.

## [1.1.0] - 2026-10-01

Compatibility release: Anvil adopts a gateway.

### Changed

- A thing changes; JSON Schema draft 2020-12 is read.

## [1.0.0] - 2026-09-01

### Added

- No lead paragraph.
`;

function evidence(overrides = {}) {
  return {
    format: "anvil-release-evidence",
    version: 1,
    release: { version: "1.2.0", tag: "anvil-v1.2.0", publication: "draft" },
    source: { repository: "ferrum-edge/ferrum-anvil", commit: COMMIT, ref: "refs/tags/anvil-v1.2.0" },
    build: { workflow: "Release", run_id: 37859968362, run_attempt: 1, run_url: RUN_URL },
    signed: false,
    signing: UNSIGNED,
    updater: { signed: true, manifest: "latest.json", key_id: "BFE08514FEC0E65A", platforms: ["linux-x86_64-appimage"], detail: "verified" },
    ...overrides,
  };
}

test("reads a section's lead paragraphs and headings", () => {
  const s = changelogSection(changelog, "1.2.0");
  assert.deepEqual(s.paragraphs, ["Hardening release: requests are bounded and a format changes.", "Read the Breaking section below before upgrading."]);
  assert.deepEqual(s.headings, ["Security", "Breaking", "Added"]);
  assert.deepEqual(changelogSection(changelog, "1.1.0").headings, ["Changed"]);
});

test("refuses a missing section, a section without a summary, and an invalid version", () => {
  assert.throws(() => changelogSection(changelog, "9.9.9"), /no "## \[9\.9\.9\]" section/);
  assert.throws(() => changelogSection(changelog, "1.0.0"), /no summary paragraph/);
  assert.throws(() => changelogSection(changelog, "1.2"), /invalid version/);
  // The version is matched literally: "." is not a wildcard.
  assert.throws(() => changelogSection("## [1x2y0] - x\n\nLead.\n", "1.2.0"), /no "## \[1\.2\.0\]" section/);
});

test("bolds a leading release label", () => {
  assert.equal(summaryParagraph("Compatibility release: Anvil adopts v0.9.15."), "**Compatibility release.** Anvil adopts v0.9.15.");
  assert.equal(summaryParagraph("Storage and desktop hardening release: request revisions are bound."), "**Storage and desktop hardening release.** Request revisions are bound.");
  assert.equal(summaryParagraph("Security hardening release covering renderer authority."), "Security hardening release covering renderer authority.");
});

test("unsigned release: warning, summary, security, Breaking pointer and links", () => {
  const body = releaseNotes({ changelog, version: "1.2.0", tag: "anvil-v1.2.0", evidence: evidence() });
  const changelogUrl = "https://github.com/ferrum-edge/ferrum-anvil/blob/anvil-v1.2.0/CHANGELOG.md";
  const advisoriesUrl = "https://github.com/ferrum-edge/ferrum-anvil/security/advisories";
  assert.ok(body.startsWith("> [!WARNING]\n> **Unsigned installers.** The installers are not code-signed yet"));
  assert.ok(body.includes("In-app updates *are* signed and verified (minisign key `BFE08514FEC0E65A`)."));
  assert.ok(body.includes("\n**Hardening release.** Requests are bounded and a format changes.\n\nRead the Breaking section below before upgrading.\n"));
  assert.ok(body.includes(`**Security:** this release fixes security issues present in earlier releases; upgrading is recommended.`));
  assert.ok(body.includes(`**Upgrade notes:** this release has breaking changes. Read the [Breaking section of the CHANGELOG](${changelogUrl}) before upgrading.`));
  assert.ok(body.includes(`Built from \`${COMMIT}\` by [run 37859968362](${RUN_URL}).`));
  assert.ok(body.includes(`See the [CHANGELOG](${changelogUrl}) for the full list and the [security advisories](${advisoriesUrl}) for published advisories.`));
  assert.ok(!/draft/i.test(body), body);
});

test("release without Security or Breaking headings, unsigned updater", () => {
  const ev = evidence({
    release: { version: "1.1.0" },
    updater: { signed: false, manifest: null, key_id: null, platforms: [], detail: "not configured" },
  });
  const body = releaseNotes({ changelog, version: "1.1.0", evidence: ev });
  assert.ok(body.includes("In-app updates are not signed for this release: the app links to this release page instead."));
  assert.ok(body.includes("**Compatibility release.** Anvil adopts a gateway."));
  assert.ok(!body.includes("**Security:**"));
  assert.ok(body.includes("**Upgrade notes:** the CHANGELOG lists no breaking changes for this release."));
  assert.ok(body.includes("/blob/anvil-v1.1.0/CHANGELOG.md"));
});

test("signed release has a signing line instead of the warning", () => {
  const body = releaseNotes({ changelog, version: "1.2.0", evidence: evidence({ signed: true, signing: SIGNED }) });
  assert.ok(!body.includes("[!WARNING]"));
  assert.ok(body.startsWith("**Signing:** the installers are code-signed and verified on the build runner. Verify downloads with `SHA256SUMS`."));
});

test("refuses a tag that is not the version's", () => {
  assert.throws(() => releaseNotes({ changelog, version: "1.2.0", tag: "anvil-v1.1.0", evidence: evidence() }), /does not match version/);
});

test("refuses invalid evidence", () => {
  const bad = [
    [null, /JSON object/],
    [[], /JSON object/],
    [evidence({ format: "other" }), /format or version/],
    [evidence({ release: { version: "1.1.0" } }), /not 1\.2\.0/],
    [evidence({ signing: "signed" }), /signing has an invalid value/],
    [evidence({ signed: true }), /disagree/],
    [evidence({ updater: { signed: true, key_id: null } }), /updater has an invalid shape/],
    [evidence({ updater: { signed: false, key_id: "`) [x](y" } }), /updater has an invalid shape/],
    [evidence({ source: { repository: "a/b c", commit: COMMIT } }), /source\.repository/],
    [evidence({ source: { repository: "ferrum-edge/ferrum-anvil", commit: "main" } }), /source\.commit/],
    [evidence({ build: { run_id: 0, run_url: RUN_URL } }), /run_id/],
    [evidence({ build: { run_id: 37859968362, run_url: "https://example.com/other/repo/actions/runs/37859968362" } }), /run_url/],
    [evidence({ build: { run_id: 37859968362, run_url: `${RUN_URL}#x` } }), /run_url/],
  ];
  for (const [ev, message] of bad) assert.throws(() => checkEvidence(ev, "1.2.0"), message);
  assert.equal(checkEvidence(evidence(), "1.2.0").server, "https://github.com");
});

test("draft-only text is refused", () => {
  for (const text of [
    "Draft release of Ferrum Anvil 0.1.4 built from `x`.",
    "This draft is not published. Review the evidence (docs/release.md) before publishing.",
  ]) {
    assert.throws(() => assertNoDraftText(`Summary.\n\n${text}\n`), /draft-only text/);
  }
  // A summary that mentions a draft specification is still a release body.
  assert.doesNotThrow(() => assertNoDraftText("JSON Schema draft 2020-12 is read."));
  const leaked = changelog.replace("Hardening release: requests are", "This draft is not published. Hardening release: requests are");
  assert.throws(() => releaseNotes({ changelog: leaked, version: "1.2.0", evidence: evidence() }), /draft-only text/);
});

test("the repository CHANGELOG has a usable section for the workspace version", () => {
  const cargo = readFileSync(join(root, "Cargo.toml"), "utf8");
  const version = /\[workspace\.package\][^[]*?\nversion = "([^"]+)"/.exec(cargo)?.[1];
  assert.ok(version, "workspace version not found in Cargo.toml");
  const real = readFileSync(join(root, "CHANGELOG.md"), "utf8");
  const section = changelogSection(real, version);
  assert.ok(section.paragraphs.length > 0);
  const body = releaseNotes({ changelog: real, version, evidence: evidence({ release: { version } }) });
  assert.ok(body.includes(`/blob/anvil-v${version}/CHANGELOG.md`));
});
