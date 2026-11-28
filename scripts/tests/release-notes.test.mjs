// Tests of scripts/release-notes.mjs, run in hosted CI with `node --test`.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import {
  DRAFT_TEXT,
  PARTIAL,
  SIGNED,
  UNSIGNED,
  absoluteLinks,
  assertNoDraftText,
  changelogSection,
  checkEvidence,
  releaseNotes,
  signingSummary,
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

// Version 2 targets consistent with a platform_signing summary: one target per
// platform (two for "partial", one signed and one not).
const OS_OF = { macos: "macOS", windows: "Windows", linux: "Linux" };
function targetsFor(platforms) {
  return Object.entries(platforms ?? {}).flatMap(([p, status]) => {
    const t = (signed) => ({ os: OS_OF[p] ?? p, signed, signing_applicable: p !== "linux" });
    if (status === "partial") return [t(true), t(false)];
    return [t(status === "signed")];
  });
}

function evidence(overrides = {}) {
  const e = baseEvidence(overrides);
  if (!("targets" in overrides)) e.targets = targetsFor(e.platform_signing);
  return e;
}

function baseEvidence(overrides = {}) {
  return {
    format: "anvil-release-evidence",
    version: 2,
    release: { version: "1.2.0", tag: "anvil-v1.2.0", publication: "draft" },
    source: { repository: "ferrum-edge/ferrum-anvil", commit: COMMIT, ref: "refs/tags/anvil-v1.2.0" },
    build: { workflow: "Release", run_id: 37859968362, run_attempt: 1, run_url: RUN_URL },
    signed: false,
    signing: UNSIGNED,
    platform_signing: { macos: "unsigned", windows: "unsigned", linux: "not applicable" },
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

const SIGNED_PLATFORMS = { macos: "signed", windows: "signed", linux: "not applicable" };

test("signed release has a signing line instead of the warning, and says Linux has no platform signing", () => {
  const body = releaseNotes({ changelog, version: "1.2.0", evidence: evidence({ signed: true, signing: SIGNED, platform_signing: SIGNED_PLATFORMS }) });
  assert.ok(!body.includes("[!WARNING]"));
  assert.ok(
    body.startsWith(
      "**Signing:** the macOS and Windows installers are code-signed and verified on the build runner. " +
        "Linux packages (`.deb`, `.rpm`, AppImage) have no platform code signing. Verify downloads with `SHA256SUMS`.",
    ),
    body,
  );
});

test("partly signed release keeps the warning and names each platform's status", () => {
  const body = releaseNotes({
    changelog,
    version: "1.2.0",
    evidence: evidence({ signing: PARTIAL, platform_signing: { macos: "signed", windows: "unsigned", linux: "not applicable" } }),
  });
  const [first, second] = body.split("\n");
  // release.yml's release job checks exactly these two line prefixes for signed: false.
  assert.equal(first, "> [!WARNING]");
  assert.ok(
    second.startsWith(
      "> **Unsigned installers.** Not every installer is code-signed. Code-signed and verified on the build runner: macOS. " +
        "Not code-signed: Windows (Windows SmartScreen will warn). Linux packages (`.deb`, `.rpm`, AppImage) have no platform code signing.",
    ),
    second,
  );
  assert.ok(!second.includes("not code-signed yet (no Apple Developer ID or Windows certificate)"));
  const some = releaseNotes({
    changelog,
    version: "1.2.0",
    evidence: evidence({ signing: PARTIAL, platform_signing: { macos: "partial", windows: "signed" } }),
  });
  assert.ok(some.includes("Code-signed and verified on the build runner: Windows. Only some macOS installers are code-signed (see `release-evidence.json`)."), some);
});

test("signingSummary: Linux is never signed or unsigned, and every macOS and Windows target must be signed", () => {
  const t = (os, signed, applicable = os !== "Linux") => ({ os, signed, signing_applicable: applicable });
  const none = signingSummary([t("macOS", false), t("macOS", false), t("Linux", false), t("Windows", false)]);
  assert.deepEqual(none, { signed: false, signing: UNSIGNED, platform_signing: { macos: "unsigned", linux: "not applicable", windows: "unsigned" } });
  const all = signingSummary([t("macOS", true), t("macOS", true), t("Linux", false), t("Windows", true)]);
  assert.deepEqual(all, { signed: true, signing: SIGNED, platform_signing: { macos: "signed", linux: "not applicable", windows: "signed" } });
  const mac = signingSummary([t("macOS", true), t("macOS", true), t("Linux", false), t("Windows", false)]);
  assert.deepEqual(mac, { signed: false, signing: PARTIAL, platform_signing: { macos: "signed", linux: "not applicable", windows: "unsigned" } });
  const half = signingSummary([t("macOS", true), t("macOS", false), t("Windows", true)]);
  assert.equal(half.platform_signing.macos, "partial");
  assert.equal(half.signing, PARTIAL);
  // A Linux-only set has nothing to sign: never "signed".
  assert.deepEqual(signingSummary([t("Linux", false)]), { signed: false, signing: UNSIGNED, platform_signing: { linux: "not applicable" } });
  assert.throws(() => signingSummary([t("FreeBSD", false)]), /unknown build OS/);
  // Every summary is accepted by the notes' evidence check.
  for (const s of [none, all, mac, half]) assert.doesNotThrow(() => checkEvidence(evidence(s), "1.2.0"));
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
    [evidence({ signing: PARTIAL }), /signing and platform_signing disagree/],
    [evidence({ platform_signing: { macos: "signed", windows: "unsigned" } }), /signing and platform_signing disagree/],
    [evidence({ signed: true, signing: SIGNED, platform_signing: { macos: "signed", windows: "partial" } }), /signing and platform_signing disagree/],
    [evidence({ signed: true, signing: SIGNED, platform_signing: { linux: "not applicable" } }), /signing and platform_signing disagree/],
    [evidence({ platform_signing: undefined }), /platform_signing has an invalid shape/],
    [evidence({ platform_signing: {} }), /platform_signing has an invalid shape/],
    [evidence({ platform_signing: { ios: "unsigned" } }), /platform_signing has an invalid shape/],
    [evidence({ platform_signing: { macos: "maybe" } }), /platform_signing has an invalid shape/],
    // Version 2 summaries must match their own targets (F5).
    [evidence({ signed: true, signing: SIGNED, platform_signing: SIGNED_PLATFORMS, targets: targetsFor({ macos: "signed", windows: "unsigned", linux: "not applicable" }) }), /disagrees with its targets/],
    [evidence({ signed: true, signing: SIGNED, platform_signing: { macos: "signed", windows: "signed" }, targets: targetsFor({ macos: "signed" }) }), /disagrees with its targets/],
    [evidence({ targets: [] }), /invalid signing record/],
    [evidence({ targets: undefined }), /invalid signing record/],
    [evidence({ targets: [{ os: "Linux", signed: false, signing_applicable: true }] }), /invalid signing record/],
    [evidence({ targets: [{ os: "Windows", signed: false, signing_applicable: false }] }), /invalid signing record/],
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
  const refused = /draft-only text/;
  for (const text of [
    "Draft release of Ferrum Anvil 0.1.4 built from `x`.",
    "This draft is not published. Review the evidence (docs/release.md) before publishing.",
  ]) {
    assert.throws(() => assertNoDraftText(`Summary.\n\n${text}\n`), refused);
  }
  // A summary that mentions a draft specification is still a release body.
  assert.doesNotThrow(() => assertNoDraftText("JSON Schema draft 2020-12 is read."));
  assert.throws(() => assertNoDraftText("REVIEW THE EVIDENCE in docs/release.md BEFORE PUBLISHING"), refused);
  const leaked = changelog.replace("Hardening release: requests are", "This draft is not published. Hardening release: requests are");
  assert.throws(() => releaseNotes({ changelog: leaked, version: "1.2.0", evidence: evidence() }), refused);
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

test("the release job's signing-status check matches the notes' first lines", () => {
  const workflow = readFileSync(join(root, ".github", "workflows", "release.yml"), "utf8");
  assert.ok(workflow.includes(`true) [[ "$first" == '**Signing:** '* ]] ;;`));
  assert.ok(workflow.includes(`false) [ "$first" = '> [!WARNING]' ] && [[ "$(sed -n 2p "$notes")" == '> **Unsigned installers.** '* ]] ;;`));
  const signed = releaseNotes({ changelog, version: "1.2.0", evidence: evidence({ signed: true, signing: SIGNED, platform_signing: SIGNED_PLATFORMS }) });
  assert.ok(signed.split("\n")[0].startsWith("**Signing:** "));
  for (const ev of [evidence(), evidence({ signing: PARTIAL, platform_signing: { macos: "signed", windows: "unsigned", linux: "not applicable" } })]) {
    const lines = releaseNotes({ changelog, version: "1.2.0", evidence: ev }).split("\n");
    assert.equal(lines[0], "> [!WARNING]");
    assert.ok(lines[1].startsWith("> **Unsigned installers.** "));
  }
});

test("version 1 evidence (releases up to 0.1.9, no platform_signing) still renders as published", () => {
  // The shape of anvil-v0.1.9's published release-evidence.json.
  const v1 = (overrides = {}) => {
    const e = evidence({ version: 1, ...overrides });
    delete e.platform_signing;
    return e;
  };
  const unsigned = releaseNotes({ changelog, version: "1.2.0", evidence: v1() });
  assert.ok(unsigned.startsWith("> [!WARNING]\n> **Unsigned installers.** The installers are not code-signed yet (no Apple Developer ID or Windows certificate)"));
  const signed = releaseNotes({ changelog, version: "1.2.0", evidence: v1({ signed: true, signing: SIGNED }) });
  assert.ok(signed.startsWith("**Signing:** the installers are code-signed and verified on the build runner. Verify downloads with `SHA256SUMS`."), signed);
  assert.throws(() => checkEvidence(v1({ signing: PARTIAL }), "1.2.0"), /partial signing needs platform_signing/);
  // A version 1 record that does carry the field is checked like version 2.
  assert.throws(() => checkEvidence(evidence({ version: 1, platform_signing: { macos: "maybe" } }), "1.2.0"), /platform_signing has an invalid shape/);
  assert.throws(() => checkEvidence(evidence({ version: 3 }), "1.2.0"), /format or version/);
});

test("the vendored NSIS template is Tauri CLI's own, with only the uninstaller signing exit code checked", () => {
  // Upstream: crates/tauri-bundler/src/bundle/windows/nsis/installer.nsi at
  // tag @tauri-apps/cli-v2.12.6. Bumping @tauri-apps/cli fails this test until
  // the template is refreshed from the new tag and the hash below updated.
  const lock = JSON.parse(readFileSync(join(root, "apps", "desktop", "package-lock.json"), "utf8"));
  assert.equal(lock.packages["node_modules/@tauri-apps/cli"].version, "2.12.6", "refresh apps/desktop/src-tauri/windows/installer.nsi from the new Tauri CLI tag");
  const conf = JSON.parse(readFileSync(join(root, "apps", "desktop", "src-tauri", "tauri.conf.json"), "utf8"));
  assert.equal(conf.bundle.windows.nsis.template, "windows/installer.nsi");
  const vendored = readFileSync(join(root, "apps", "desktop", "src-tauri", "windows", "installer.nsi"), "utf8");
  const checked = "  !uninstfinalize '${UNINSTALLERSIGNCOMMAND}' = 0\n";
  assert.equal(vendored.split(checked).length, 2, "exactly one checked uninstaller signing hook");
  const upstream = vendored.replace(checked, "  !uninstfinalize '${UNINSTALLERSIGNCOMMAND}'\n");
  assert.equal(createHash("sha256").update(upstream).digest("hex"), "d00089d3b1a2c4a30d7b6e098079100cb8f25e980f84d4515aca4597b95e967d");
});

test("signing-route.sh: half-configured routes fail, precedence applies only to complete sets, values are never read", () => {
  const run = (has, os = "Windows", tag = "anvil-v1.2.0") => {
    const dir = mkdtempSync(join(tmpdir(), "route-"));
    const out = join(dir, "out");
    const env = { PATH: process.env.PATH, TAG: tag, RUNNER_OS: os, TARGET: "t", GITHUB_OUTPUT: out };
    for (const n of has) env[`HAS_${n}`] = "true";
    const r = spawnSync("bash", [join(root, "scripts", "release", "signing-route.sh")], { env, encoding: "utf8" });
    let outputs = {};
    try {
      outputs = Object.fromEntries(readFileSync(out, "utf8").trim().split("\n").map((l) => l.split("=")));
    } catch {}
    rmSync(dir, { recursive: true, force: true });
    return { status: r.status, text: r.stdout + r.stderr, outputs };
  };
  const ats = ["AZURE_TENANT_ID", "AZURE_CLIENT_ID", "ARTIFACT_SIGNING_ENDPOINT", "ARTIFACT_SIGNING_ACCOUNT", "ARTIFACT_SIGNING_CERTIFICATE_PROFILE"];
  const pfx = ["WINDOWS_CERTIFICATE", "WINDOWS_CERTIFICATE_PASSWORD"];
  const mac = ["APPLE_CERTIFICATE", "APPLE_CERTIFICATE_PASSWORD"];
  const api = ["APPLE_API_ISSUER", "APPLE_API_KEY", "APPLE_API_KEY_P8"];
  const appleId = ["APPLE_ID", "APPLE_PASSWORD", "APPLE_TEAM_ID"];

  assert.deepEqual(run([]).outputs, { route: "none", macos: "none", windows: "none" });
  assert.equal(run(ats).outputs.windows, "artifact-signing-oidc");
  assert.equal(run([...ats, "AZURE_CLIENT_SECRET"]).outputs.windows, "artifact-signing-secret");
  assert.equal(run(pfx).outputs.windows, "pfx");
  assert.equal(run([...ats, ...pfx]).outputs.windows, "artifact-signing-oidc");
  // A half-set .pfx fails even though Artifact Signing is complete (F8).
  const half = run([...ats, "WINDOWS_CERTIFICATE"]);
  assert.equal(half.status, 1);
  assert.match(half.text, /Windows \.pfx signing is partly configured .*missing: WINDOWS_CERTIFICATE_PASSWORD/);
  assert.match(run(["AZURE_CLIENT_ID"]).text, /Azure Artifact Signing is partly configured/);
  // macOS: notarization is required; the API key wins over the Apple ID.
  assert.equal(run([...mac, ...api], "macOS").outputs.macos, "api-key");
  assert.equal(run([...mac, ...appleId], "macOS").outputs.macos, "apple-id");
  assert.equal(run([...mac, ...api, ...appleId], "macOS").outputs.macos, "api-key");
  assert.match(run(mac, "macOS").text, /needs notarization credentials too/);
  assert.match(run([...mac, "APPLE_API_KEY"], "macOS").text, /API-key notarization is partly configured/);
  assert.match(run([...mac, ...api, "APPLE_ID"], "macOS").text, /Apple ID notarization is partly configured/);
  // Another OS's route never takes effect: credentials gated on it stay unmapped.
  assert.deepEqual(run([...mac, ...api, ...ats], "Linux").outputs, { route: "none", macos: "none", windows: "none" });
  assert.deepEqual(run([...mac, ...api, ...ats], "Windows").outputs, { route: "artifact-signing-oidc", macos: "none", windows: "artifact-signing-oidc" });
  // A dry run reads nothing.
  assert.deepEqual(run([...mac, ...api, ...ats], "macOS", "").outputs, { route: "none", macos: "none", windows: "none" });
});

test("only bundle-windows can request an OIDC token, and it runs no release check", () => {
  const workflow = readFileSync(join(root, ".github", "workflows", "release.yml"), "utf8");
  // Top-level jobs, each with its own text.
  const jobs = Object.fromEntries(
    workflow
      .split(/\n(?=  [a-z][a-z0-9-]*:\n)/)
      .slice(1)
      .map((block) => [block.match(/^  ([a-z][a-z0-9-]*):/)[1], block]),
  );
  const withToken = Object.entries(jobs).filter(([, text]) => /^\s+id-token: write/m.test(text)).map(([name]) => name);
  assert.deepEqual(withToken, ["bundle-windows"]);
  assert.ok(!jobs["bundle-windows"].includes("check-artifacts.sh"), "the release check (runtime probe) is not in the job with OIDC");
  assert.ok(jobs["check-windows"].includes("bash scripts/release/check-artifacts.sh"));
  assert.ok(!/environment:|secrets\./.test(jobs["check-windows"]), "check-windows has no environment and no secret");
  assert.match(jobs["bundle-windows"], /Binaries match the build job's recorded digests/);
  assert.match(jobs.publish, /needs: \[preflight, build, check-windows\]/);
  assert.match(jobs.build, /name: compiled-\$\{\{ matrix\.target \}\}[\s\S]*?retention-days: 30/);
});

// release.yml's top-level jobs, each with its text, and a job's steps.
function workflowJobs() {
  const workflow = readFileSync(join(root, ".github", "workflows", "release.yml"), "utf8");
  const jobsText = workflow.slice(workflow.indexOf("\njobs:\n"));
  return Object.fromEntries(
    jobsText
      .split(/\n(?=  [a-z][a-z0-9-]*:\n)/)
      .slice(1)
      .map((block) => [block.match(/^  ([a-z][a-z0-9-]*):/)[1], block]),
  );
}
const jobSteps = (jobText) => jobText.split(/\n(?=      - )/).slice(1);
const MOVED_REF_GUARD = "      - name: Checked out the run's own commit";

test("preflight stops a run whose ref moved away from github.sha before any checked-out code runs", () => {
  const steps = jobSteps(workflowJobs().preflight);
  const checkout = steps.findIndex((s) => s.includes("uses: actions/checkout@"));
  const guard = steps.findIndex((s) => s.startsWith(MOVED_REF_GUARD));
  assert.ok(checkout >= 0 && guard === checkout + 1, "the guard is the step right after preflight's checkout");
  const firstCode = steps.findIndex((s, i) => i > checkout && /scripts\/|uses: \.\/\.github\/actions\//.test(s));
  assert.ok(firstCode > guard, "no step runs code from the checkout before the guard");
});

test("the moved-ref guard's own script passes on github.sha and fails on another commit", () => {
  const step = jobSteps(workflowJobs().preflight).find((s) => s.startsWith(MOVED_REF_GUARD));
  const quoted = step.match(/\n        run: '((?:[^']|'')*)'(?:\n|$)/);
  assert.ok(quoted, "the guard's run script is one single-quoted YAML scalar");
  const script = quoted[1].replaceAll("''", "'");
  assert.match(script, /"\$\(git rev-parse HEAD\)" = "\$GITHUB_SHA"/);
  assert.match(script, /exit 1/);

  const dir = mkdtempSync(join(tmpdir(), "moved-ref-"));
  try {
    const git = (...args) => {
      const r = spawnSync("git", ["-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false", ...args], { cwd: dir, encoding: "utf8" });
      assert.equal(r.status, 0, r.stderr);
      return r.stdout.trim();
    };
    git("init", "-q");
    git("commit", "-q", "--allow-empty", "-m", "started");
    const started = git("rev-parse", "HEAD");
    git("commit", "-q", "--allow-empty", "-m", "moved");
    const moved = git("rev-parse", "HEAD");
    const guard = (sha) =>
      spawnSync("bash", ["-e", "-c", script], { cwd: dir, encoding: "utf8", env: { PATH: process.env.PATH, GITHUB_SHA: sha, GITHUB_REF: "refs/heads/main" } });
    const same = guard(moved);
    assert.equal(same.status, 0, same.stdout + same.stderr);
    const other = guard(started);
    assert.notEqual(other.status, 0, "a HEAD that is not github.sha must fail the job");
    assert.match(other.stdout, /::error::refs\/heads\/main is now at [0-9a-f]{40}, not at [0-9a-f]{40}/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("every job after preflight checks out github.sha, never a preflight output", () => {
  const workflow = readFileSync(join(root, ".github", "workflows", "release.yml"), "utf8");
  assert.ok(!/ref: \$\{\{ needs\.preflight\.outputs\./.test(workflow), "no checkout of a needs.preflight output");
  let checkouts = 0;
  for (const [name, text] of Object.entries(workflowJobs())) {
    if (name === "preflight") continue;
    for (const step of jobSteps(text).filter((s) => s.includes("uses: actions/checkout@"))) {
      checkouts++;
      assert.match(step, /\n          ref: \$\{\{ github\.sha \}\}\n/, `${name}: checkout of github.sha`);
    }
  }
  assert.ok(checkouts >= 4, "build, bundle-windows, check-windows and publish check out the code");
});

test("the performance harness takes only its own app's ui_ready line, and buckets launches by index", () => {
  const script = `
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("m", sys.argv[1])
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
log = ('2026-11-27T10:00:00.000Z INFO anvil_desktop: startup milestone milestone="ui_ready" pid=111 startup_ms=500\\n'
       '2026-11-27T10:00:01.000Z INFO anvil_desktop: startup milestone milestone="ui_ready" pid=222 startup_ms=900\\n')
runs = [{"run": 1, "error": "timeout"}, {"run": 2, "ready_ms": 10, "attribution": "a"}, {"run": 3, "ready_ms": 30, "attribution": "b"}]
s = m.summarize(runs)
print(json.dumps({"own": m.ready_in(log, 222), "other": m.ready_in(log, 333), "first": s["first_run"], "warm": s["warm_runs"]["ready_ms"], "atts": s["warm_attributions"]}))
`;
  const r = spawnSync("python3", ["-I", "-c", script, join(root, "scripts", "perf", "measure_desktop.py")], { encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
  const out = JSON.parse(r.stdout);
  assert.equal(out.own, 900, "the line of the started pid");
  assert.equal(out.other, null, "another instance's line never counts");
  assert.deepEqual(out.first, {}, "a failed launch 1 leaves the first-launch column empty");
  assert.deepEqual(out.warm, { median: 20, min: 10, max: 30, n: 2 }, "every valid later launch is in the later median");
  assert.deepEqual(out.atts, ["a", "b"]);
});

test("the performance harness never force-stops provisional helpers, handles early exit and listing failure, and summarizes missing lanes", () => {
  const script = `
import importlib.util, json, os, sys, tempfile
from pathlib import Path

spec = importlib.util.spec_from_file_location("m", sys.argv[1])
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)

# 1. PID reuse does not match alive() or force_stop().
m.processes = lambda: [{"pid": 500, "ppid": 1, "start": "Sat Nov 28 06:00:00 2026", "name": "unrelated", "rss": 1}]
assert m.alive({(500, "Sat Nov 28 05:00:00 2026", "WebKitWebProcess")}) == set()
assert m.alive({(500, "Sat Nov 28 06:00:00 2026", "unrelated")}) == {(500, "Sat Nov 28 06:00:00 2026", "unrelated")}

# 2. Windows ancestry rejects pre-existing helpers and earlier-start stale PPIDs.
m.SYSTEM = "Windows"
win_before = {(400, "2026-11-28T05:00:00.0000000Z", "msedgewebview2.exe")}
win_rows = [
    {"pid": 300, "ppid": 1, "start": "2026-11-28T06:00:00.0000000Z", "name": "anvil-desktop.exe", "rss": 10},
    {"pid": 400, "ppid": 300, "start": "2026-11-28T05:00:00.0000000Z", "name": "msedgewebview2.exe", "rss": 20},
    {"pid": 401, "ppid": 300, "start": "2026-11-28T05:59:59.0000000Z", "name": "msedgewebview2.exe", "rss": 20},
    {"pid": 402, "ppid": 300, "start": "2026-11-28T06:00:01.0000000Z", "name": "msedgewebview2.exe", "rss": 20},
]
wfound, _, wverified = m.helpers(win_rows, 300, win_before)
assert [h["pid"] for h in wfound] == [402] and wverified is True

# 3. macOS shared-responsible-pid and early-exit orphans are provisional and block clean teardown.
m.SYSTEM = "Darwin"
m.responsible_pid = lambda pid: 99 if pid in (100, 200) else None
rows = [
    {"pid": 100, "ppid": 99, "start": "Sat Nov 28 06:00:00 2026", "name": "anvil-desktop", "rss": 10},
    {"pid": 200, "ppid": 1, "start": "Sat Nov 28 06:00:01 2026", "name": "com.apple.WebKit.WebContent", "rss": 20},
]
found, method, verified = m.helpers(rows, 100, set())
assert len(found) == 1 and verified is False and "provisional" in method

# Early macOS exit: app is already gone (responsible_pid(101) -> None), helper still has owner 99.
killed_pids = []
orig_kill = m.os.kill
m.os.kill = lambda pid, sig: killed_pids.append((pid, sig))
m.responsible_pid = lambda pid: 99 if pid == 201 else None
orphan = {"pid": 201, "ppid": 1, "start": "Sat Nov 28 06:00:01 2026", "name": "com.apple.WebKit.WebContent", "rss": 20}
m.log_size = lambda: {}
m.ready_line = lambda sizes, pid: None
orig_wait_quiet = m._wait_teardown_quiet
m._wait_teardown_quiet = lambda before, v, p, timeout=30, quiet_seconds=None: orig_wait_quiet(before, v, p, timeout=0.01, quiet_seconds=0.0)
mac_calls = {"n": 0}
def mac_early_procs():
    mac_calls["n"] += 1
    return [] if mac_calls["n"] == 1 else [orphan]
m.processes = mac_early_procs
class EarlyProc:
    pid = 101
    returncode = 1
    def poll(self):
        return 1
orig_popen = m.subprocess.Popen
m.subprocess.Popen = lambda *a, **kw: EarlyProc()
r_mac = m.one_run("/bin/true", 0, 0.05, 1)
assert r_mac["stopped_cleanly"] is False and r_mac["cleanup_unconfirmed"] is True
assert r_mac.get("provisional_left_running") == [201]
assert killed_pids == [], f"provisional macOS helper must never be SIGKILLed: {killed_pids}"
m.os.kill = orig_kill
m.subprocess.Popen = orig_popen

# 4. Sampling + teardown listing exception preserves ready_ms and cleanup_error.
m.SYSTEM = "Linux"
m.ready_line = lambda sizes, pid: 123
class LiveProc:
    pid = 777
    returncode = None
    def poll(self):
        return self.returncode
    def wait(self, timeout=None):
        self.returncode = 0
        return 0
    def kill(self):
        self.returncode = -9
call_n = {"n": 0}
def flaky_procs():
    call_n["n"] += 1
    if call_n["n"] == 1:
        return []
    raise RuntimeError("ps failed")
m.processes = flaky_procs
m.subprocess.Popen = lambda *a, **kw: LiveProc()
stopped = []
orig_stop = m.stop
m.stop = lambda p, *a: (stopped.append(p.pid) or (True, None))
r = m.one_run("/bin/true", 0, 0.05, 1)
assert stopped == [777], f"expected stop() on listing failure, got {stopped}"
assert r["startup_ms_in_process"] == 123 and "ready_ms" in r
assert r["stopped_cleanly"] is False and r["cleanup_unconfirmed"] is True and "cleanup_error" in r
m.stop = orig_stop
m.subprocess.Popen = orig_popen

# 5. Real Unix stop() terminates a live session process cleanly and never invokes killpg after reap.
if os.name == "posix":
    m.SYSTEM = "Linux"
    real_p = m.subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"], start_new_session=True)
    ok, err = m.stop(real_p)
    assert ok is True and err is None and real_p.returncode is not None
    killpg_calls = []
    orig_killpg = m.os.killpg
    m.os.killpg = lambda pgid, sig: killpg_calls.append((pgid, sig))
    try:
        ok2, err2 = m.stop(real_p)
        assert ok2 is True and err2 is None and killpg_calls == []
    finally:
        m.os.killpg = orig_killpg

# 5b. Linux early exit (even when app still has a zombie row) catches reparented WebKitGTK orphan and never adopts recycled app PID.
m.SYSTEM = "Linux"
zombie_app = {"pid": 101, "ppid": 1, "start": "Sat Nov 28 06:00:00 2026", "name": "unrelated-reused", "rss": 10}
linux_orphan = {"pid": 901, "ppid": 1, "start": "Sat Nov 28 06:00:01 2026", "name": "WebKitWebProcess", "rss": 20}
m.log_size = lambda: {}
m.ready_line = lambda sizes, pid: None
m._wait_teardown_quiet = lambda before, v, p, timeout=30, quiet_seconds=None: orig_wait_quiet(before, v, p, timeout=0.01, quiet_seconds=0.0)
lin_calls = {"n": 0}
def linux_early_procs():
    lin_calls["n"] += 1
    return [] if lin_calls["n"] == 1 else [zombie_app, linux_orphan]
m.processes = linux_early_procs
m.subprocess.Popen = lambda *a, **kw: EarlyProc()
r_lin = m.one_run("/bin/true", 0, 0.05, 1)
assert r_lin["stopped_cleanly"] is False and r_lin["cleanup_unconfirmed"] is True
assert r_lin.get("provisional_left_running") == [901]
assert "left_running" not in r_lin, "reused app PID must never enter verified_owned"
m.subprocess.Popen = orig_popen

# 5c. macOS partial procinfo failure keeps unresolved new WebKit helpers in provisional_out even alongside verified helpers.
m.SYSTEM = "Darwin"
m.responsible_pid = lambda pid: 100 if pid in (100, 202) else None
prov = set()
mfound, _, mver = m.helpers(
    [
        {"pid": 100, "ppid": 99, "start": "Sat Nov 28 06:00:00 2026", "name": "anvil-desktop", "rss": 10},
        {"pid": 202, "ppid": 1, "start": "Sat Nov 28 06:00:01 2026", "name": "com.apple.WebKit.WebContent", "rss": 20},
        {"pid": 203, "ppid": 1, "start": "Sat Nov 28 06:00:01 2026", "name": "com.apple.WebKit.Networking", "rss": 20},
    ],
    100,
    set(),
    known_app_owner=100,
    provisional_out=prov,
)
assert mver is True and [h["pid"] for h in mfound] == [202]
assert (203, "Sat Nov 28 06:00:01 2026", "com.apple.WebKit.Networking") in prov

# 5d. Linux force_stop signals ONLY already-pinned pidfds and returns False if any survivor is unpinned; non-Linux returns False.
m.SYSTEM = "Linux"
m.processes = lambda: [
    {"pid": 888, "ppid": 1, "start": "T1", "name": "WebKitWebProcess", "rss": 10},
    {"pid": 889, "ppid": 1, "start": "T1", "name": "WebKitGPUProcess", "rss": 10},
]
sent_sigs = []
orig_pidfd_send = getattr(m.signal, "pidfd_send_signal", None)
m.signal.pidfd_send_signal = lambda fd, sig: sent_sigs.append((fd, sig))
try:
    id_a = (888, "T1", "WebKitWebProcess")
    id_b = (889, "T1", "WebKitGPUProcess")
    assert m.force_stop({id_a}, {id_a: 42}) is True
    assert sent_sigs == [(42, m.signal.SIGKILL)]
    sent_sigs.clear()
    assert m.force_stop({id_a, id_b}, {id_a: 42}) is False
    assert sent_sigs == [(42, m.signal.SIGKILL)]
finally:
    if orig_pidfd_send is None:
        delattr(m.signal, "pidfd_send_signal")
    else:
        m.signal.pidfd_send_signal = orig_pidfd_send

m.SYSTEM = "Darwin"
assert m.force_stop({(888, "T1", "WebKitWebProcess")}) is False

# 5e. Windows job launch failure (both no-job and valid-job-handle suspended launch failure) never falls back to unsuspended Popen.
m.SYSTEM = "Windows"
m.processes = lambda: []
popen_called = []
m.subprocess.Popen = lambda *a, **kw: popen_called.append(a)
r_win_fail = m.one_run("anvil-desktop.exe", 0, 0.05, 1)
assert popen_called == [] and r_win_fail["cleanup_unconfirmed"] is True and "Windows Job Object" in r_win_fail["error"]

orig_win_job = m._WinJob
class FakeWinJob:
    def __init__(self):
        self.handle = 1234
        self.assigned = False
        self.closed = False
        self.last_error = 0
    def spawn_suspended_and_assign(self, app, env):
        self.last_error = 5
        return None
    def close(self):
        self.closed = True
        self.handle = None
fake_jobs = []
def make_fake_job():
    j = FakeWinJob()
    fake_jobs.append(j)
    return j
m._WinJob = make_fake_job
try:
    r_win_suspended = m.one_run("anvil-desktop.exe", 0, 0.05, 1)
    assert popen_called == [] and r_win_suspended["cleanup_unconfirmed"] is True
    assert "win32 error 5" in r_win_suspended["error"]
    assert len(fake_jobs) == 1 and fake_jobs[0].closed is True
finally:
    m._WinJob = orig_win_job
m.subprocess.Popen = orig_popen

# 5f. Linux pin_linux_pidfd requires exact /proc starttime ticks observed during ancestry verification and closes recycled-PID fds.
m.SYSTEM = "Linux"
closed_fds = []
orig_pidfd_open = getattr(m.os, "pidfd_open", None)
orig_os_close = m.os.close
orig_linux_st = m._linux_proc_starttime
m.os.pidfd_open = lambda pid, flags: 900 + pid
m.os.close = lambda fd: closed_fds.append(fd)
try:
    pinned = {}
    # Non-tick start token must never pin.
    m._linux_proc_starttime = lambda pid: "12345"
    m.pin_linux_pidfd((10, "Sat Nov 28 06:00:00 2026", "WebKitWebProcess"), pinned)
    assert pinned == {} and closed_fds == []
    # Recycled PID whose starttime tick changed between survey and pidfd_open must be rejected and closed.
    m._linux_proc_starttime = lambda pid: "99999"
    m.pin_linux_pidfd((11, "ticks:12345", "WebKitWebProcess"), pinned)
    assert pinned == {} and closed_fds == [911]
    # Exact matching starttime tick is pinned and kept open.
    m._linux_proc_starttime = lambda pid: "12345"
    m.pin_linux_pidfd((12, "ticks:12345", "WebKitWebProcess"), pinned)
    assert pinned == {(12, "ticks:12345", "WebKitWebProcess"): 912} and closed_fds == [911]
finally:
    if orig_pidfd_open is None:
        delattr(m.os, "pidfd_open")
    else:
        m.os.pidfd_open = orig_pidfd_open
    m.os.close = orig_os_close
    m._linux_proc_starttime = orig_linux_st

# 5g. Late-appearing WebKit helper discovered during the real quiet-window final survey (after empty polls) prevents false stopped_cleanly=True.
m.SYSTEM = "Darwin"
class CleanExitProc:
    def __init__(self):
        self.pid = 700
        self.returncode = None
    def poll(self):
        return self.returncode
    def wait(self, timeout=None):
        self.returncode = 0
        return 0
    def kill(self):
        self.returncode = -9
late_calls = {"n": 0}
late_helper = {"pid": 777, "ppid": 1, "start": "Sat Nov 28 06:00:02 2026", "name": "com.apple.WebKit.WebContent", "rss": 20}
def late_darwin_procs():
    late_calls["n"] += 1
    # Pre-launch (1), pre-stop (2), and first quiet-window teardown poll (3) see no helper;
    # the quiet confirmation follow-up survey (4+) sees the late WebKit XPC helper.
    return [] if late_calls["n"] <= 3 else [late_helper]
orig_stop = m.stop
orig_quiet_secs = m.UNIX_QUIET_CONFIRM_SECONDS
m.processes = late_darwin_procs
m.log_size = lambda: {}
m.ready_line = lambda sizes, pid: None
m.stop = lambda proc, *a, **kw: (True, None)
m.UNIX_QUIET_CONFIRM_SECONDS = 0.05
m._wait_teardown_quiet = lambda before, v, p, timeout=30, quiet_seconds=None: orig_wait_quiet(before, v, p, timeout=0.12, quiet_seconds=quiet_seconds)
m.subprocess.Popen = lambda *a, **kw: CleanExitProc()
try:
    r_late = m.one_run("/bin/true", 0, 0.01, 1)
    assert late_calls["n"] >= 4, f"expected quiet confirmation follow-up survey, got {late_calls['n']}"
    assert r_late["stopped_cleanly"] is False and r_late["cleanup_unconfirmed"] is True
    assert r_late.get("provisional_left_running") == [777]
finally:
    m.UNIX_QUIET_CONFIRM_SECONDS = orig_quiet_secs
    m._wait_teardown_quiet = orig_wait_quiet
    m.stop = orig_stop
    m.subprocess.Popen = orig_popen

# 5h. Deadline expiring before Unix quiet confirmation completes reports cleanup_unconfirmed=True and stopped_cleanly=False.
m.SYSTEM = "Darwin"
deadline_calls = {"n": 0}
app_700 = {"pid": 700, "ppid": 1, "start": "Sat Nov 28 06:00:00 2026", "name": "anvil-desktop", "rss": 10}
wk_701 = {"pid": 701, "ppid": 1, "start": "Sat Nov 28 06:00:01 2026", "name": "com.apple.WebKit.WebContent", "rss": 20}
def deadline_procs():
    deadline_calls["n"] += 1
    # Pre-launch (1) empty; sampling + pre-stop (2, 3) see live app + WebKit helper; teardown survey sees them gone right at deadline.
    return [app_700, wk_701] if deadline_calls["n"] in (2, 3) else []
orig_resp = m.responsible_pid
m.responsible_pid = lambda pid: 700 if pid in (700, 701) else None
m.processes = deadline_procs
m.log_size = lambda: {}
m.ready_line = lambda sizes, pid: 10
m.stop = lambda proc, *a, **kw: (True, None)
m.UNIX_QUIET_CONFIRM_SECONDS = 0.2
m._wait_teardown_quiet = lambda before, v, p, timeout=30, quiet_seconds=None: orig_wait_quiet(before, v, p, timeout=0.0, quiet_seconds=quiet_seconds)
m.subprocess.Popen = lambda *a, **kw: CleanExitProc()
try:
    r_deadline = m.one_run("/bin/true", 0, 0.01, 1)
    assert r_deadline["stopped_cleanly"] is False and r_deadline["cleanup_unconfirmed"] is True
    assert "quiet confirmation" in r_deadline["error"], f"unexpected error: {r_deadline.get('error')}"
finally:
    m.responsible_pid = orig_resp
    m.UNIX_QUIET_CONFIRM_SECONDS = orig_quiet_secs
    m._wait_teardown_quiet = orig_wait_quiet
    m.stop = orig_stop
    m.subprocess.Popen = orig_popen

# 5i. Overdue poll crossing both quiet window and deadline must NOT confirm quiet,
# slow survey latency must NOT falsely confirm quiet, and quiet-timeout diagnostics
# are preserved alongside post-force or stop-error failures.
m.SYSTEM = "Darwin"
clock_vals = iter([0.0, 29.8, 29.8, 30.4, 30.4])
orig_monotonic = m.time.monotonic
orig_sleep = m.time.sleep
m.time.monotonic = lambda: next(clock_vals)
m.time.sleep = lambda _s: None
m.processes = lambda: []
try:
    lv, lp, qok = orig_wait_quiet(set(), set(), set(), timeout=30.0, quiet_seconds=0.5)
    assert lv == set() and lp == set() and qok is False, f"expected quiet_ok=False for overdue poll, got {(lv, lp, qok)}"
finally:
    m.time.monotonic = orig_monotonic
    m.time.sleep = orig_sleep

# Slow survey started at 0.1s and returned at 0.55s cannot satisfy a 0.5s quiet window from 0.0s;
# the next poll at 0.55s sees the late helper started at 0.30s.
m.SYSTEM = "Linux"
late_helper_702 = {"pid": 702, "ppid": 1, "start": "ticks:102", "name": "WebKitWebProcess", "rss": 10}
sim_clock = [0.0]
survey_n = [0]
def slow_survey_procs():
    survey_n[0] += 1
    captured = sim_clock[0]
    if survey_n[0] == 2:
        sim_clock[0] += 0.45
    return [late_helper_702] if captured >= 0.3 else []
m.time.monotonic = lambda: sim_clock[0]
m.time.sleep = lambda s: sim_clock.__setitem__(0, sim_clock[0] + s)
m.processes = slow_survey_procs
try:
    lv, lp, qok = orig_wait_quiet(set(), set(), set(), timeout=0.6, quiet_seconds=0.5)
    assert qok is False and lp == {(702, "ticks:102", "WebKitWebProcess")}, f"slow survey missed late helper: {(lv, lp, qok)}"
finally:
    m.time.monotonic = orig_monotonic
    m.time.sleep = orig_sleep

m.SYSTEM = "Linux"
pf_calls = {"n": 0}
app_700_l = {"pid": 700, "ppid": 1, "start": "ticks:100", "name": "anvil-desktop", "rss": 10}
wk_701_l = {"pid": 701, "ppid": 700, "start": "ticks:101", "name": "WebKitWebProcess", "rss": 20}
def pf_procs():
    pf_calls["n"] += 1
    return [app_700_l, wk_701_l] if pf_calls["n"] in (2, 3) else []
wait_seq = iter([
    ({(700, "ticks:100", "anvil-desktop")}, set(), False),
    (set(), set(), False),
])
m.processes = pf_procs
m.log_size = lambda: {}
m.ready_line = lambda sizes, pid: 10
m.stop = lambda proc, *a, **kw: (True, None)
orig_force_stop = m.force_stop
m.force_stop = lambda live, pinned: True
m._wait_teardown_quiet = lambda before, v, p, timeout=30, quiet_seconds=None: next(wait_seq)
m.subprocess.Popen = lambda *a, **kw: CleanExitProc()
try:
    r_pf = m.one_run("/bin/true", 0, 0.01, 1)
    assert r_pf["stopped_cleanly"] is False and r_pf["cleanup_unconfirmed"] is True
    assert "outlived the app's stop" in r_pf["error"], f"missing survivor cause: {r_pf.get('error')}"
    assert "quiet confirmation" in r_pf["error"], f"missing quiet timeout cause: {r_pf.get('error')}"
finally:
    m.force_stop = orig_force_stop
    m._wait_teardown_quiet = orig_wait_quiet
    m.stop = orig_stop
    m.subprocess.Popen = orig_popen

# Stop raising alongside a quiet timeout still preserves the quiet-timeout diagnostic.
m.processes = lambda: []
m.log_size = lambda: {}
m.ready_line = lambda sizes, pid: None
def raising_stop(proc, *a, **kw):
    raise OSError("stop failed")
m.stop = raising_stop
m._wait_teardown_quiet = lambda before, v, p, timeout=30, quiet_seconds=None: (set(), set(), False)
m.subprocess.Popen = lambda *a, **kw: CleanExitProc()
try:
    r_se = m.one_run("/bin/true", 0, 0.0, 1)
    assert r_se["stopped_cleanly"] is False and r_se["cleanup_unconfirmed"] is True
    assert "quiet confirmation" in r_se["error"], f"stop error hid quiet timeout: {r_se.get('error')}"
    assert "stop failed" in r_se["cleanup_error"]
finally:
    m._wait_teardown_quiet = orig_wait_quiet
    m.stop = orig_stop
    m.subprocess.Popen = orig_popen

# 6. summarize.py emits missing-lane rows and --require-expected rejects missing/duplicate/unexpected lanes.
spec2 = importlib.util.spec_from_file_location("s", sys.argv[2])
s = importlib.util.module_from_spec(spec2); spec2.loader.exec_module(s)
import io, contextlib
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    rc = s.main(["--expect", "Darwin:runner 1", "--expect", "Linux:runner 1"])
assert rc == 0
out = buf.getvalue()
assert "Darwin runner 1 | missing (no result uploaded)" in out
assert "Linux runner 1 | missing (no result uploaded)" in out
err_buf = io.StringIO()
with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err_buf):
    rc_req = s.main(["--require-expected", "--expect", "Darwin:runner 1"])
assert rc_req == 1 and "missing lanes" in err_buf.getvalue()
with tempfile.TemporaryDirectory() as td:
    dup_a = Path(td) / "a.json"
    dup_b = Path(td) / "b.json"
    sample = json.dumps({"format": "anvil-desktop-perf", "os": "Darwin", "label": "runner 1", "runs": [], "summary": {"runs_ok": 0, "runs_failed": 0, "first_run": {}, "warm_runs": {}}})
    dup_a.write_text(sample); dup_b.write_text(sample)
    err_buf2 = io.StringIO()
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err_buf2):
        rc_dup = s.main(["--require-expected", "--expect", "Darwin:runner 1", "--expect", "Linux:runner 1", str(dup_a), str(dup_b)])
    assert rc_dup == 1 and "duplicate lanes" in err_buf2.getvalue() and "missing lanes" in err_buf2.getvalue()
    err_buf3 = io.StringIO()
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err_buf3):
        rc_unexp = s.main(["--require-expected", str(dup_a)])
    assert rc_unexp == 1 and "unexpected lanes" in err_buf3.getvalue()
print("OK")
`;
  const r = spawnSync("python3", ["-I", "-c", script, join(root, "scripts", "perf", "measure_desktop.py"), join(root, "scripts", "perf", "summarize.py")], { encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
  assert.equal(r.stdout.trim(), "OK");
});
