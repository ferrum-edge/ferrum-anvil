// Tests of scripts/release-notes.mjs, run in hosted CI with `node --test`.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import {
  DRAFT_TEXT,
  SIGNED,
  UNSIGNED,
  absoluteLinks,
  assertNoDraftText,
  changelogSection,
  checkEvidence,
  releaseNotes,
  summaryParagraph,
} from "../release-notes.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const COMMIT = "695308f2ce239b4db513c09c07b2353b7b353c3b";
const RUN_URL = "https://github.com/ferrum-edge/ferrum-anvil/actions/runs/37859968362";

const changelog = `# Changelog

## [Unreleased]

## [1.3.0] - 2026-12-01

Compatibility release: Anvil adopts
a gateway:
- The catalog is
  adopted.
- HTTP/3 is checked ([lab](./docs/lab/README.md)).

Read the breaking changes below.

### breaking changes

- A format changes.

### Security fixes

- Something is bounded.

## [1.2.0] - 2026-11-01

Hardening release: requests are
bounded and a format changes.

Read the Breaking section below before upgrading.

### Security

- Something is bounded.

### Breaking

- Something changes; see the
  [upgrade guide](docs/upgrade-guide.md#something).
- Another thing changes.

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
  assert.equal(s.security, true);
  assert.deepEqual(s.breaking, [
    "- Something changes; see the [upgrade guide](docs/upgrade-guide.md#something).\n- Another thing changes.",
  ]);
  const plain = changelogSection(changelog, "1.1.0");
  assert.deepEqual(plain.headings, ["Changed"]);
  assert.equal(plain.security, false);
  assert.deepEqual(plain.breaking, []);
});

test("keeps list items in the summary one per line", () => {
  const s = changelogSection(changelog, "1.3.0");
  assert.deepEqual(s.paragraphs, [
    "Compatibility release: Anvil adopts a gateway:\n- The catalog is adopted.\n- HTTP/3 is checked ([lab](./docs/lab/README.md)).",
    "Read the breaking changes below.",
  ]);
  assert.equal(
    summaryParagraph(s.paragraphs[0]),
    "**Compatibility release.** Anvil adopts a gateway:\n- The catalog is adopted.\n- HTTP/3 is checked ([lab](./docs/lab/README.md)).",
  );
});

test("matches Security and Breaking headings on their first word, in any case", () => {
  const s = changelogSection(changelog, "1.3.0");
  assert.deepEqual(s.headings, ["breaking changes", "Security fixes"]);
  assert.equal(s.security, true);
  assert.deepEqual(s.breaking, ["- A format changes."]);
  // "Breakingly" is not Breaking, so it is an unknown heading.
  assert.throws(() => changelogSection("## [2.0.0]\n\nLead.\n\n### Breakingly\n\n- x\n", "2.0.0"), /unknown heading "### Breakingly"/);
});

test("refuses unknown headings and an empty Breaking section", () => {
  assert.throws(() => changelogSection("## [2.0.0]\n\nLead.\n\n### Notes\n\n- x\n", "2.0.0"), /unknown heading "### Notes"/);
  assert.throws(() => changelogSection("## [2.0.0]\n\nLead.\n\n### Breaking\n\n### Added\n\n- x\n", "2.0.0"), /empty Breaking section/);
  // Headings of other sections are not checked.
  assert.doesNotThrow(() => changelogSection("## [2.0.0]\n\nLead.\n\n### Added\n\n- x\n\n## [1.0.0]\n\n### Notes\n", "2.0.0"));
});

test("relative links point at the repository at the tag", () => {
  const base = "https://github.com/o/r/blob/anvil-v1.2.0";
  assert.equal(absoluteLinks("[a](docs/x.md#y) [b](./c.md)", base), `[a](${base}/docs/x.md#y) [b](${base}/c.md)`);
  const kept = "[a](https://example.com/x) [b](#anchor) [c](/abs) [d](mailto:x@example.com)";
  assert.equal(absoluteLinks(kept, base), kept);
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

test("unsigned release: warning, summary, security, Breaking changes and links", () => {
  const body = releaseNotes({ changelog, version: "1.2.0", tag: "anvil-v1.2.0", evidence: evidence() });
  const changelogUrl = "https://github.com/ferrum-edge/ferrum-anvil/blob/anvil-v1.2.0/CHANGELOG.md";
  const advisoriesUrl = "https://github.com/ferrum-edge/ferrum-anvil/security/advisories";
  assert.ok(body.startsWith("> [!WARNING]\n> **Unsigned installers.** The installers are not code-signed yet"));
  assert.ok(body.includes("In-app updates *are* signed and verified (minisign key `BFE08514FEC0E65A`)."));
  assert.ok(body.includes("\n**Hardening release.** Requests are bounded and a format changes.\n\nRead the Breaking section below before upgrading.\n"));
  assert.ok(body.includes(`**Security:** this release fixes security issues present in earlier releases; upgrading is recommended.`));
  // The summary's "Breaking section below" is in the body: the upgrade notes repeat it.
  assert.ok(
    body.includes(
      `**Upgrade notes:** this release has breaking changes; read them before upgrading. From the Breaking section of the [CHANGELOG](${changelogUrl}):\n\n` +
        "- Something changes; see the [upgrade guide](https://github.com/ferrum-edge/ferrum-anvil/blob/anvil-v1.2.0/docs/upgrade-guide.md#something).\n" +
        "- Another thing changes.\n\nBuilt from",
    ),
    body,
  );
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

test("summary lists, lowercase headings and relative links reach the body", () => {
  const body = releaseNotes({ changelog, version: "1.3.0", evidence: evidence({ release: { version: "1.3.0" } }) });
  const base = "https://github.com/ferrum-edge/ferrum-anvil/blob/anvil-v1.3.0";
  assert.ok(
    body.includes(
      "\n**Compatibility release.** Anvil adopts a gateway:\n- The catalog is adopted.\n" +
        `- HTTP/3 is checked ([lab](${base}/docs/lab/README.md)).\n\nRead the breaking changes below.\n\n**Security:**`,
    ),
    body,
  );
  assert.ok(body.includes("From the Breaking section of the [CHANGELOG]"));
  assert.ok(body.includes("\n\n- A format changes.\n\nBuilt from"));
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
  assert.throws(() => assertNoDraftText("REVIEW THE EVIDENCE in docs/release.md BEFORE PUBLISHING"), /draft-only text/);
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

test("release.yml and docs/release.md use the one draft-text pattern", () => {
  const workflow = readFileSync(join(root, ".github", "workflows", "release.yml"), "utf8");
  // Defined once for the release job and quoted exactly as DRAFT_TEXT.
  assert.deepEqual(workflow.match(/^ *DRAFT_TEXT: .*$/gm), [`      DRAFT_TEXT: "${DRAFT_TEXT}"`]);
  const greps = workflow.match(/grep -inE \S+/g) ?? [];
  assert.ok(greps.length >= 2, "release.yml greps for draft text");
  for (const g of greps) assert.equal(g, 'grep -inE "$DRAFT_TEXT"');
  const docs = readFileSync(join(root, "docs", "release.md"), "utf8");
  assert.ok(docs.includes(`grep -inE '${DRAFT_TEXT}'`), "docs/release.md quotes the draft-text pattern");
});

test("the notes artifact is outside the publish job's release-* download pattern", () => {
  const workflow = readFileSync(join(root, ".github", "workflows", "release.yml"), "utf8");
  assert.ok(workflow.includes("pattern: release-*"));
  const names = workflow.match(/name: notes-\$\{\{ needs\.preflight\.outputs\.version \}\}/g) ?? [];
  assert.equal(names.length, 2, "the notes are uploaded and downloaded as notes-<version>");
  assert.ok(!workflow.includes("release-notes-"));
});
