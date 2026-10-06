# Releasing Ferrum Anvil

Releases are built by `.github/workflows/release.yml` and always end as a
**draft** GitHub release. Publishing the draft, announcing it and updating the
website are manual owner steps, taken only after the
[owner checklist](#owner-checklist-before-publishing-a-draft) is met.

## Cutting a release

1. Make sure `main` is green in CI, Desktop E2E and the nightly Lab.
2. Bump the version in all three places — `Cargo.toml` (`[workspace.package] version`),
   `apps/desktop/src-tauri/tauri.conf.json` and `apps/desktop/package.json` — and
   commit.
3. Tag and push: `git tag anvil-v0.1.0 && git push origin anvil-v0.1.0`.
   Or run the workflow manually **from the tag** (Run workflow → *Use workflow
   from* → Tags → `anvil-v0.1.0`), optionally with the same tag as input. A
   run from a tag is a full, signed release even with the input empty.
   Preflight refuses an input that is not the tag the run started from, a tag
   that does not exist, or a checkout whose commit is not the tag's; build and
   publish then check out that exact commit (never a branch or tag name, which
   a same-named branch could shadow). A manual run from a branch without a tag
   input is a **dry run**: everything is built and checked and the evidence is
   uploaded to the run, but nothing is signed and no release is created.
4. Review the draft (checklist below), then publish it by hand.

## What the workflow does

**Preflight** (Ubuntu): the tag must equal `anvil-v<version>` and the three
version fields must agree; `cargo deny check`; `node scripts/licenses.mjs --check`;
`scripts/release-check.sh` (dependency graph); the diagnostic catalog drift test.
The hosted AppImage checker regression suite also runs with distribution-provided
`gcc`, `python3` and `mksquashfs`, and the checksum-pinned upstream `unsquashfs`
described below, before any release build.

**Build** (one job per target):

| Target | Runner | Bundles |
| --- | --- | --- |
| `aarch64-apple-darwin` | macOS 15 | `.app` → `.dmg` |
| `x86_64-apple-darwin` | macOS 15 (cross-compiled) | `.app` → `.dmg` |
| `x86_64-unknown-linux-gnu` | Ubuntu 22.04 (older glibc baseline) | `.deb`, `.rpm`, `.AppImage` |
| `x86_64-pc-windows-msvc` | Windows 2025 | `.msi`, NSIS `-setup.exe` |

Each build job:

1. `tauri build --ci --target <t> --no-bundle` — release profile, **default
   features only**, with no signing credentials in its environment and no
   Windows certificate imported yet. The `e2e` feature (embedded WebDriver +
   environment-driven unlock) is never passed. Then, for a tagged release, the
   Windows certificate is imported and `tauri bundle --ci --target <t>
   --bundles <b>` runs as the only step that receives the Apple, Windows and
   updater signing credentials; the certificate is removed afterwards. This is
   defense in depth, not isolation: both steps share the runner, and bundling
   itself runs third-party tools (the AppImage bundler downloads unpinned
   `linuxdeploy` tools while the key is present). Signing the updater artifacts
   in a separate job with `tauri signer sign` would be stronger. With the
   owner's updater key a tagged release also writes signed updater artifacts
   (see [In-app updates](#in-app-updates)).
2. `cargo build --release -p anvil-cli --target <t>`, packaged as
   `anvil-cli-<version>-<t>.tar.gz` (`.zip` on Windows) with `LICENSE`,
   `LICENSE-COMMERCIAL.md` and `THIRD_PARTY_LICENSES.md`. The standalone
   `anvil-load-worker` binary is not packaged: the desktop app and the CLI run
   load workers by re-launching themselves.
3. `scripts/release-check.sh` over every installer, the macOS updater archive
   (if any), the CLI archive and the raw app binary, with the runtime probe on native targets (Linux under Xvfb). Any
   failure stops the release.
4. Signature verification (see [Signing](#signing-and-what-unsigned-means)) and
   `build-info.json` (target, OS/arch, runner, `rustc`/`cargo`/Node/Tauri CLI
   versions, signing status).
5. CycloneDX 1.5 SBOMs for `anvil-desktop` and `anvil-cli` for that target
   (`cargo cyclonedx`); the job fails if the desktop SBOM lists the WebDriver plugin.

**Publish** (Ubuntu): an npm SBOM of the UI's production dependencies
(`@cyclonedx/cyclonedx-npm`), `license-report.json`, the list of GitHub Actions
runs for the release commit, `latest.json` (only with signed updater
artifacts), `SHA256SUMS`, `release-evidence.json` and an uploaded evidence
bundle. For a tag only, it then runs
`gh release create --draft --verify-tag`.

### Release evidence

`release-evidence.json` (written by `scripts/release-evidence.mjs`) records:

- product, version, tag, publication state (`draft` or `dry run — not published`);
- repository, **source commit**, workflow run id/URL/attempt;
- per target: OS, architecture, runner, toolchain versions, `signed`,
  `signing`, the release-check result and report, and every artifact with its
  file name, kind, size and SHA-256;
- shared artifacts (npm SBOM, license report, `latest.json`) and the
  `SHA256SUMS` file;
- updater: `signed`, `manifest`, minisign `key_id`, the `latest.json`
  platform keys and a `detail` line; per target, whether the build had the
  updater key and which files it signed;
- licensing: project license and third-party report;
- compatibility: diagnostics catalog version, every Ferrum compatibility
  catalog (`catalog/ferrum/*/outcomes.json`: compatibility id, gateway release
  tag and source SHA, outcome count, public tokens), the lab gateway pin
  (`lab/gateway/RELEASE.lock`) and every release the lab supports
  (`lab/gateway/releases/*.lock`);
- tests: the CI / Desktop E2E / Lab runs for the commit with their
  conclusions. A missing or skipped run is not a pass — check them.

The script lists every problem in `problems` and exits non-zero if a target
has no passing release check, no installer, no CLI archive or no SBOM, if two
artifacts share a name, or if updater signatures, artifacts and `latest.json`
do not match, do not verify against the public key the builds compiled into
the app, or do not record the release version.

## Release artifact safety check

`scripts/release-check.sh` proves that release artifacts contain no test-only
WebDriver server and no E2E hooks. It is bash and runs on Linux, macOS and
Windows (Git Bash).

```sh
scripts/release-check.sh [--features <list>] [--no-graph] [--runtime-probe] [--report <file>] <artifact>...
```

1. **Graph** — `cargo tree -p anvil-desktop --target all -e normal,build,features`
   for the release feature set must not contain `tauri-plugin-wdio-webdriver`
   or `anvil-desktop feature "e2e"`. (`deny.toml` additionally bans the plugin
   from the default graph.)
2. **Content** — installers and archives are unpacked (`.app`, `.dmg`, `.deb`,
   `.rpm`, `.AppImage`, `.msi` via `msiexec /a`, NSIS via `7z`, `.tar.gz`, `.zip`)
   and every ELF/Mach-O/PE image is searched for strings unique to the plugin
   (`tauri-plugin-wdio-webdriver`, `tauri_plugin_wdio_webdriver`,
   `TAURI_WEBDRIVER_PORT`, `/session/{session_id}/element`, `/wdio/eval`,
   `wdio-webdriver`) and to the E2E unlock (`ANVIL_E2E_PASSPHRASE`,
   `ANVIL_E2E_PROFILE`, `e2e: create profile failed`, `e2e: unlock failed`,
   `e2e_unlock`). Each artifact must also contain an Anvil marker string, so a
   compressed or foreign file can never pass by accident.
   For `.AppImage` inputs, only the [Type 2 ELF + SquashFS format](https://github.com/AppImage/AppImageSpec/blob/master/draft.md#type-2-image-format)
   is supported. Trusted `python3` and `unsquashfs` (`squashfs-tools` 4.5.1 or
   later) must be installed on a trusted `PATH`; hosted provisioning is described
   below. Isolated Python reads the 32/64-bit ELF metadata in either byte order
   and derives the filesystem boundary using the
   [official runtime's layout](https://github.com/AppImage/type2-runtime/blob/main/src/runtime/runtime.c).
   `unsquashfs` reads the filesystem as data into `squashfs-root`, with extraction
   errors treated as fatal. The input is never made executable or invoked to
   extract contents or discover its offset. Missing tools, unsupported types,
   malformed metadata, corrupt filesystems and missing `AppRun` fail closed.
   Every extracted regular file must be readable through EOF. Classification
   and scanning use the same descriptor, with no symlink traversal; read errors
   and changes to the extraction tree are fatal even if another file contains
   a valid Anvil marker. Other artifact scans also reject classification,
   enumeration and `grep` read errors; a normal no-match result remains valid.
3. **Runtime probe** (`--runtime-probe`) — the desktop executable is launched
   with `TAURI_WEBDRIVER_PORT=<free port>`, `ANVIL_E2E_PROFILE` and
   `ANVIL_E2E_PASSPHRASE` set and a throw-away `ANVIL_DATA_DIR`. Nothing may
   answer `GET /status` on that port and no profile may appear in the data
   directory. AppImages launch the extracted `squashfs-root/AppRun` so bundled
   WebKit helpers retain their environment; the input image's runtime is never
   invoked. This option deliberately executes artifact contents: use it only
   after establishing the artifact's provenance and any required signatures.
   The probe stops the process it launched and leftover helpers in its own
   temporary AppImage extraction directory.

Exit status: `0` pass, `1` test hooks found, `2` usage error or an artifact
that could not be inspected (never reported as a pass).

The Ubuntu 22.04 release build keeps its older glibc baseline. Its distribution
[`squashfs-tools` package](https://packages.ubuntu.com/jammy/squashfs-tools)
is `1:4.5-3build1`, whose upstream 4.5 banner is below the checker's 4.5.1
security floor. The CI fixture jobs on both Ubuntu versions, release preflight,
and the Linux release build therefore compile only `unsquashfs` from the
[upstream 4.7.5 release archive](https://github.com/plougher/squashfs-tools/releases/tag/4.7.5).
The repository recipes in `.github/workflows/ci.yml` and `.github/workflows/release.yml`
require a GitHub-hosted runner, fetch the exact release asset over HTTPS, and
verify SHA-256 before unpacking or building:

```text
squashfs-tools-4.7.5.tar.gz
547b7b7f4d2e44bf91b6fc554664850c69563701deab9fd9cd7e21f694c88ea6
```

This digest matches the upstream release asset's GitHub API `digest` field and
the downloaded archive. The pinned archive's
[change log](https://github.com/plougher/squashfs-tools/blob/4.7.5/CHANGES.md#451-17-mar-2022-new-manpages-fix-cve-2021-41072-and-miscellaneous-improvements-and-bug-fixes)
records the 4.5.1 fix for CVE-2021-41072 (writes outside the extraction destination).
Build dependencies come from the runner's authenticated Ubuntu repositories;
the extractor enables gzip, xz, lzo, lz4, zstd and legacy lzma support. Only the
resulting `unsquashfs` is installed into a private runner temporary directory,
its exact version banner is checked, and its directory is prepended to `PATH`
for later steps. Fixture `mksquashfs` and bundling tools remain distribution-provided.
Update all three provisioning recipes together when changing this pin. The
checker still rejects tools below 4.5.1 and unknown banners; provisioning does
not add an exception for the Ubuntu 4.5 package.

The CI release-checker jobs (Ubuntu 22.04 and 24.04) and release preflight run
`scripts/tests/test_release_check.py` against the actual checker. Hosted fixtures
include a native malicious runtime whose sentinel must never appear, real
compressed SquashFS payloads, both ELF boundary layouts across architectures,
forbidden markers in a library, malformed images and missing extraction tools.
Contained `AppRun` symlinks also pass with a trusted symlinked `TMPDIR`; escaping
links still fail under both ordinary and aliased temporary directories.
Separate explicit-probe tests prove that extracted `AppRun` launches only when
requested, that environment-created profiles fail the probe, and that early
exit is inconclusive; a listener answering the WebDriver status request also
fails. These fixture builds and script tests run on hosted CI.

## Signing and what "unsigned" means

Code signing needs the owner's certificates, which are **not** in the
repository. The workflow signs only a tagged release, and only when the
corresponding secrets exist; a dry run is always unsigned. Store these secrets
in the protected `release` environment (see [In-app updates](#in-app-updates)):

| Platform | Secrets | Effect |
| --- | --- | --- |
| macOS | `APPLE_CERTIFICATE` (base64 .p12), `APPLE_CERTIFICATE_PASSWORD`, `APPLE_SIGNING_IDENTITY`; for notarization also `APPLE_ID`, `APPLE_PASSWORD` (app-specific), `APPLE_TEAM_ID` | Tauri signs the `.app`/`.dmg` with the Developer ID and notarizes |
| Windows | `WINDOWS_CERTIFICATE` (base64 .pfx), `WINDOWS_CERTIFICATE_PASSWORD` | the certificate is imported and Tauri signs the MSI/NSIS installers (SHA-256, timestamped) |
| Linux | — | no platform code signing; integrity is via `SHA256SUMS` |

A target is recorded as signed **only after the signature is verified on the
runner** (`codesign --verify --deep --strict` with a Team ID and no ad-hoc
signature, plus `stapler`/`spctl` for notarization on macOS;
`Get-AuthenticodeSignature` = `Valid` for every Windows installer). Otherwise
the evidence says `"signed": false` and
`"signing": "unsigned — owner credentials not configured"`.

Unsigned means the files are exactly what CI built from the recorded commit
(check `SHA256SUMS` and `release-evidence.json`), but the operating system
cannot attribute them to Ferrum Edge. macOS Gatekeeper blocks an unsigned app
downloaded from the internet unless the user explicitly allows it (on Apple
silicon the bundle carries only an ad-hoc signature); Windows SmartScreen
warns. Do not publish unsigned installers as a production download, and never
describe them as signed. No step in this repository creates, simulates or
claims a signature it did not verify.

## In-app updates

**Detection** is opt-in in Settings (off by default). When on, the app asks
`api.github.com` for the latest published release (`anvil-vX.Y.Z`) and
contacts nothing else. It works for every published release, signed or not.

**In-app install** (`tauri-plugin-updater`) needs the owner's updater key,
which is **not** in the repository. Without it the app has no public key
compiled in and the Upgrade button opens the GitHub release page instead.

| Setting | Kind | Value |
| --- | --- | --- |
| `TAURI_SIGNING_PRIVATE_KEY` | secret of the `release` environment | private key file contents from `npx tauri signer generate -w <file>` (generate it offline) |
| `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` | secret of the `release` environment | its password (optional; set one) |
| `ANVIL_UPDATER_PUBKEY` | repository variable | the `.pub` file contents (base64) |

**Protecting the key.** The build job of a tagged release runs in the GitHub
environment `release`; a dry run runs in none, and the workflow also withholds
the key (and the Apple and Windows credentials) from any run without a tag.
The owner must:

- create the `release` environment with required reviewers and a deployment
  rule of **Ref type: Tag**, pattern `anvil-v*`, and store the two updater
  secrets there, together with the Apple and Windows signing secrets (not as
  repository secrets);
- add a tag ruleset for `refs/tags/anvil-v*` that restricts who can create,
  update or delete those tags, and a branch ruleset that blocks creating
  branches named `anvil-v*`;
- do both before pushing the first `anvil-v*` tag.

Only a tagged release with both the private key and `ANVIL_UPDATER_PUBKEY`
passes `bundle.createUpdaterArtifacts: true` and `plugins.updater.pubkey` as an
extra `--config` (to the build, which compiles the key into the app, and to
the bundle step); one without the other logs a warning and builds exactly as
without a key. As defense in depth, the private key is in the environment of
`tauri bundle` only, not of the compile step (build scripts, proc macros,
`beforeBuildCommand`); both share the runner, so this narrows exposure rather
than isolating the key. The build job checks that the public key is in the
built app binary and `build-info.json` records it (`updater.embedded`). Tauri then signs
(minisign), recording the version in each signature's trusted comment:

| Target | Updater file | `latest.json` keys |
| --- | --- | --- |
| macOS | `Ferrum-Anvil_<version>_<aarch64\|x64>.app.tar.gz` (+ `.sig`) | `darwin-<arch>-app`, `darwin-<arch>` |
| Linux | `.AppImage` (+ `.sig`) | `linux-x86_64-appimage` |
| Windows | NSIS `-setup.exe`, `.msi` (+ `.sig` each) | `windows-x86_64-nsis`, `windows-x86_64-msi` |

The publish job (`scripts/updater-manifest.mjs`) verifies every signature
against the public key recorded in `build-info.json` (the same on every
target) and requires its signed version to equal the release version, then
writes `latest.json` (Tauri static format). Any mismatch, or a signature
without a version, fails the run. `latest.json` itself is not signed: the app
sets `requireSignedVersion`, so it rejects an update whose signature records
no version or a version other than the one the manifest announces, and a
crafted manifest cannot pass an older signed build off as newer. The plugin
looks up `{os}-{arch}-{installer}` before `{os}-{arch}`; the bare key is
written only for macOS, so an MSI install never receives the NSIS installer.
`.deb`/`.rpm` installs are not updated in-app: the bundler signs no `.deb` or
`.rpm`, so `latest.json` has no entry for them and those users update from the
release page.

The app reads `releases/latest/download/latest.json`. GitHub serves it only
once the draft is published (drafts and pre-releases are never "latest"), so
publishing the draft is what releases the update. Rotating the key strands
installed apps that carry the old public key: they must update from the
release page once.

## SBOMs and licensing

- **Project license**: PolyForm Noncommercial 1.0.0, with a separate commercial
  license (`LICENSE`, `LICENSE-COMMERCIAL.md`).
- **Dependency policy** (`deny.toml`): permissive licenses only (Apache-2.0,
  MIT, BSD-2/3-Clause, ISC, Zlib, Unicode-3.0, Unlicense, BSL-1.0, CC0-1.0,
  MIT-0, 0BSD, Apache-2.0 WITH LLVM-exception). Copyleft fails the check.
  MPL-2.0 (file-level copyleft) is accepted only as reviewed per-crate
  exceptions — `cssparser`, `cssparser-macros`, `dtoa-short`, `selectors`
  (Tauri's HTML/CSS tooling) and `option-ext` (`dirs`) — all used unmodified.
  Sources: crates.io only. Duplicate crate versions are reported as warnings.
- **Advisories**: RustSec, with two reviewed ignores. Each carries an exit
  condition in `deny.toml` and is an open item for the owner:
  - `RUSTSEC-2023-0071` — `rsa` (Marvin timing side channel) via
    `jsonwebtoken`'s `rust_crypto` backend for RS256 signing in `anvil-auth`.
    Anvil only signs caller-built JWTs locally; no patched `rsa` exists. Consider
    switching `jsonwebtoken` to a constant-time backend.
  - `RUSTSEC-2024-0429` — `glib` 0.18 `VariantStrIter` unsoundness via Tauri's
    Linux GTK stack; not called by Anvil or Tauri. Resolves when Tauri moves to
    gtk 0.19+ (glib ≥ 0.20).
- **npm**: `npm audit --omit=dev --audit-level=high` gates the dependencies that
  ship in the UI bundle. The development-only E2E
  tooling (WebdriverIO 9.30.1, pinned exactly by `@wdio/tauri-service` 1.4.0)
  carries a high-severity advisory in `deepmerge-ts` 7.1.6 (`serialize-javascript`
  is overridden to the fixed 7.0.5); it runs only on developer machines and CI against
  local fixtures and is never shipped. Revisit when the Tauri service moves to
  a fixed WebdriverIO. An npm `overrides` entry moves WebdriverIO's
  `@puppeteer/browsers` to 3.x, which no longer depends on `extract-zip`
  (WebdriverIO v9 still declares `^2.2.0`; its v10 line adopts `^3`). Drop the
  override once WebdriverIO depends on `@puppeteer/browsers` 3.x itself.
- **`THIRD_PARTY_LICENSES.md`** is generated by `node scripts/licenses.mjs` from
  `Cargo.lock` (normal and build dependencies of `anvil-desktop` with its
  release feature set and of `anvil-cli`, for every target) and the UI's npm
  production dependencies, reproduces third-party NOTICE files, and is checked
  for staleness in CI. `--json` produces the release `license-report.json`.
- **SBOMs**: CycloneDX 1.5 JSON per target for the desktop app and the CLI
  (`cargo cyclonedx`), plus one for the UI's npm production dependencies.

## Native desktop E2E

`apps/desktop/e2e/` drives the real app with WebdriverIO through the embedded
WebDriver server of `tauri-plugin-wdio-webdriver` (the `embedded` provider of
`@wdio/tauri-service`). Requests go through the native Rust engine; no command
or network result is mocked.

```sh
cd apps/desktop
npm ci
npm run e2e:build   # tauri build --debug --no-bundle --features e2e  → <target>/debug/anvil-desktop
npm run e2e         # wdio run ./wdio.conf.ts
```

- The config generates, per run, a temporary `ANVIL_DATA_DIR`, a profile name
  (`ANVIL_E2E_PROFILE`) and a random `ANVIL_E2E_PASSPHRASE`. The `e2e` build
  creates/unlocks that profile at startup, so no credential is typed into the
  UI. The data directory is deleted afterwards.
- The WebDriver port is a free port, also exported as `TAURI_WEBDRIVER_PORT`
  for the service's direct-eval client (which otherwise defaults to 4445 and
  could reach another Tauri app under test on the same machine).
- The app binary is `$CARGO_TARGET_DIR/debug/anvil-desktop[.exe]` (default
  `target/`), or `ANVIL_E2E_APP`.
- Set `ANVIL_E2E_GATEWAY=http://127.0.0.1:18080` with `cargo run -p anvil-lab -- up core`
  running to send the success spec through the real Ferrum Edge lab gateway
  (`/ok/echo`) instead of the local fixture and to run the gateway spec (`06`),
  which is skipped otherwise. `e2e.yml` does this on macOS and Linux.
- Linux needs a display: `xvfb-run -a npm run e2e`.
- Screenshots of each key screen are written to `apps/desktop/e2e/screenshots/`
  (git-ignored; uploaded as CI artifacts).

| Spec | Covers |
| --- | --- |
| `01-boot` | boots unlocked into the workbench; backend `app_status` is `unlocked` for the E2E profile; the run uses its own data dir |
| `02-http-success` | new request → local JSON fixture started by the test → 200, transport `completed`, application `success`, the fixture saw exactly that request, Body shows the JSON, History lists it |
| `03-failure-diagnosis` | request to a closed loopback port → `No response`, transport `failed`, application `not evaluated`, dispatch `not dispatched`; finding "The connection was refused" (`client.connect.refused`) with the `Confirmed` badge, scope, and a non-empty "This does not prove" list; no Ferrum attribution |
| `04-effective-request` | Effective request lists user headers and headers Anvil adds; `Authorization` is shown redacted and the secret never reaches the page |
| `06-gateway-diagnosis` | (with `ANVIL_E2E_GATEWAY`) route whose backend refuses connections through the real lab gateway declared as a Ferrum profile → 502; first finding "Gateway could not prepare a connection to the backend" at `Likely`, scope gateway → backend, "does not prove … TLS failed"; no confirmed gateway claim |
| `07-tls-untrusted` | HTTPS fixture whose leaf is signed by a throwaway CA → transport `failed`, dispatch `not dispatched`, `client.tls.untrusted_issuer` on the caller's leg; the first remediation never suggests disabling verification (skipped without `openssl`) |
| `08-load-report` | load plan over a saved request (via real IPC) → Run… keeps Start disabled until the authorization acknowledgement → run through the self-launched worker → `completed` report; the fixture saw exactly 300 requests |
| `09-offline-no-account` | REL-005: a local profile with no account or provider sends a request to a loopback fixture, reopens it from History and opens a saved load report; the app process and its load worker hold no socket to a non-loopback address for the whole spec (`lsof` / `Get-NetTCPConnection`; the test-only WebDriver listener is excluded) |
| `10-file-grants` | file commands take only grants from the backend's own native dialog: a file path, a made-up grant and the old `path` arguments are refused by `read_certificate_file`, `import_private_key_file`, `import_pkcs12_file`, `attachment_add`, `import_preview`/`import_apply`, `dataset_add`, `spec_preview` and `export_to_path`; no file content reaches the page and nothing is written; renderer-selected PEM roles on `file_choose`, the legacy `pem_file` purpose and `read_text_file` disposition arguments are refused; a multi-file save or token-file dialog, a linked-file dialog without its request or dataset, a relocation dialog without its request or dataset or the reference it repoints, a reference to repoint on a dialog for another purpose, and a request or dataset on a dialog for another purpose are refused before anything is shown; `linked_file_status` reports nothing for a request that names no linked file; a spec naming a linked local file is refused by `effective_request`, `send_request`, `session_open`, `oauth_token_status`, `request_create` and `request_save`, and one naming an unbound JWT-SVID token file by the four send-side commands |
| `99-lock` | Lock button → lock screen; backend refuses `history_list`, `workspaces_list`, `tree_get`, `settings_get`, `file_choose` (no dialog opens), `certificate_file_choose`, `private_key_file_choose`, `read_certificate_file`, `import_private_key_file`, `import_pkcs12_file` and `linked_file_status` with `LOCKED` (runs last because the app stays locked) |

`@wdio/tauri-service` expects its companion plugin (`tauri-plugin-wdio`) for
mocking and window-focus helpers; Anvil does not ship it. The config selects the
single window explicitly, which turns the per-command focus check off; the
remaining "Failed to clear mock store" warning is harmless.

The E2E build is instrumented, so it is not packaging evidence: installer,
first-run and dialog smoke tests on the signed packages are still required for
the release gate. `e2e.yml` also runs `scripts/release-check.sh` against the
E2E build and requires it to fail.

## Owner checklist before publishing a draft

- [ ] Preflight, every build job and publish succeeded; `release-evidence.json`
      has an empty `problems` list and every target's `release_check.result` is `pass`.
- [ ] The CI, Desktop E2E and Lab runs listed under `tests.runs` for the commit
      concluded `success` on all platforms.
- [ ] `signed` is `true` for every desktop target you intend to offer — or the
      release is explicitly labelled unsigned/preview and not offered as a
      production download.
- [ ] In-app updates: with the updater key configured (secrets
      `TAURI_SIGNING_PRIVATE_KEY`, `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` in the
      protected `release` environment, variable `ANVIL_UPDATER_PUBKEY`, and
      the `anvil-v*` tag ruleset), `updater.signed` is `true` and
      `updater.platforms` covers every target; otherwise `updater.manifest` is
      `null` and users update from the release page. Publishing makes
      `latest.json` live for every installed app with the key.
- [ ] Clean-install smoke test of each installer (install, first run, create a
      profile, send a request, lock/unlock, uninstall); screenshots attached.
- [ ] Advisory ignores in `deny.toml` re-reviewed.
- [ ] Website changes follow only after publishing and link the exact artifact
      URLs and checksums.

## Open items

- **Signing credentials** (owner): Apple Developer ID + notarization and a
  Windows code-signing certificate. Until then every build is unsigned. Steps,
  secret names and the recommended workflow changes: ferrum-edge/ferrum-anvil#2.
- **Updater key** (owner): `npx tauri signer generate` offline, the secrets in
  the protected `release` environment (required reviewers, `anvil-v*`
  deployment rule) plus an `anvil-v*` tag ruleset, as described in
  [In-app updates](#in-app-updates). Until then the app links to the release
  page.
- **Sign-in providers** (owner): Google/GitHub/Facebook registrations and an
  identity broker before application login can use them:
  ferrum-edge/ferrum-anvil#3.
- **Packaged-app smoke tests** (install, first run, dialogs, uninstall) are not
  automated; the native E2E suite runs against the instrumented debug build.
- The two advisory ignores in `deny.toml` (see above).
- After merging dependency changes, regenerate `THIRD_PARTY_LICENSES.md`
  (`node scripts/licenses.mjs`); CI fails while it is stale.

## Local verification record

Recorded 2026-09-26 on macOS 26 (Darwin 25.6), Apple M4, Rust 1.98.1,
Node 23.11, on draft PR ferrum-edge/ferrum-anvil#1, after the last functional
merge at that time (UDP and DTLS
through HBONE, DTLS through CONNECT-UDP, PROXY headers on HTTP-family
requests, per-protocol load units, the SPIFFE Workload API and JWT-SVIDs,
0-RTT early data, WebSocket permessage-deflate).

| Check | Command | Result |
| --- | --- | --- |
| Format and lints | `cargo fmt --all --check`; `cargo clippy --locked --workspace --all-targets -- -D warnings` | clean |
| Rust tests | `cargo test --locked --workspace --exclude anvil-desktop` | 93 test binaries: 716 passed, 0 failed, 2 ignored (the real OS keychain round trip, which CI runs with `--ignored` on each OS, and the Python `websockets` interop check, run with `ANVIL_INTEROP_PYTHON`) |
| Contract drift | `cargo run -p anvil-cli -- schema --out contracts/schemas` + `npm run contracts` | no drift |
| Renderer | `npx tsc --noEmit -p .`; `npm test` | clean; 78 passed |
| Native E2E through the gateway | `npm run e2e:build`, `anvil-lab up core` (Ferrum Edge v0.9.7), `ANVIL_E2E_GATEWAY=http://127.0.0.1:18080 npm run e2e` | 9 spec files, 18 tests passed (boot, success, refusal diagnosis, effective request, gateway diagnosis, untrusted TLS, load report, offline/no-account, lock) |
| Real-gateway lab | `anvil-lab run <profile> --untrusted-pass` for every profile (Ferrum Edge v0.9.7 release binary, the default pin) and the same with `--release v0.9.5` (v0.9.5 release binary) | each release: 530 passed, 0 failed, 19 skipped with stated reasons: core 36/0/0, policy 48/0/1, admission 8/0/2, drain 4/0/0, tls 66/0/7, auth 80/0/5, streams 98/0/0, cpdp 10/0/0, h3x 40/0/0, mesh 60/0/4, proxyproto 46/0/0, workload 18/0/0, early 16/0/0; `AUTH-009.iss-array`, `AUTH-X01.nbf` and `GW-010-BOT.allow-edge` pass with release-dependent expectations |
| Lab profile lint | `ruby lab/gateway/lint-profiles.rb` | every gateway configuration OK; a mistyped nested plugin key is caught |
| Release check, production artifacts | `npx tauri build --ci --bundles app,dmg`; `cargo build --release --locked -p anvil-cli`; `scripts/release-check.sh --runtime-probe` over the `.app`, `.dmg`, raw `anvil-desktop` and `anvil` | **pass**: graph without the WebDriver plugin or `e2e`, 0 of 11 hook strings in each, no WebDriver listener and no env-driven unlock at runtime |
| Release check, negative control | `scripts/release-check.sh --no-graph target/debug/anvil-desktop` (e2e build) | **fail (exit 1)** as required: all 11 strings found |
| cargo-deny | `cargo deny --locked check` | advisories, bans, licenses, sources ok |
| License inventory | `node scripts/licenses.mjs --check` | up to date: 782 crates, 5 npm packages |
| Secret scan | `gitleaks git` (full history) with `.gitleaks.toml` | no leaks; the RFC 6455 sample `Sec-WebSocket-Key` in the vendored tungstenite tests is allowlisted by value. An earlier `gitleaks dir .` found only git-ignored lab output, build output and throwaway lab keys (`results/`, `target/`, `lab/.run/`), nothing in tracked files |
| Plaintext at rest | `cargo test -p anvil-app --test at_rest` | no planted marker in profile files, WAL/SHM side files or new temp files |
| Failure matrix | `python3 scripts/matrix-coverage.py` (lab evidence from the v0.9.7 runs) | 172 of 182 with executed evidence (97 live, 74 automated, 1 release check; LOAD-013 is now live: gRPC, WebSocket and UDP load through the gateway checked against its transaction log); 6 blocked, 2 not applicable, 2 partial (website, gated on release) |

Earlier runs on the same PR:

| Check | Command | Result |
| --- | --- | --- |
| Native E2E, release-profile build | `npx tauri build --no-bundle --features e2e` (release profile), same suite | 9 spec files passed; app peak RSS 236 MiB, load worker 21 MiB (see `docs/performance.md`) |
| cargo-deny ban guard | `cargo deny --locked --features e2e check bans` | fails as intended: `tauri-plugin-wdio-webdriver` is banned |
| Release check, e2e build | `cargo build -p anvil-desktop --release --features e2e`, then `scripts/release-check.sh --features e2e --runtime-probe <binary>` | **fail (exit 1)** as required — graph contains the plugin, 10 of 11 hook strings found (the `e2e_unlock` symbol is stripped), WebDriver answered HTTP 200 on the probe port |
| Release check, inconclusive input | `/bin/ls`, `README.md` | exit 2 (no Anvil marker / unsupported type) — never a pass |
| Release bundle dry run (macOS arm64) | `npx tauri build --ci --bundles app,dmg`, `cargo build --release -p anvil-cli`, then the release workflow's collect, release-check (with probe), signature-verification, SBOM, license-report and evidence steps | release check **pass** on the `.dmg`, the `.app`, the CLI `.tar.gz` and the raw binary; signing recorded as `unsigned — owner credentials not configured (ad-hoc signature only, not a Developer ID)`; `release-evidence.json` with 7 artifacts, empty `problems`; `shasum -c SHA256SUMS` OK |
| Release check, other formats | synthetic `.deb` (ar fallback) and `.zip` around the release/e2e binaries | clean → pass; `.deb` carrying the e2e binary → fail (exit 1) |
| Catalog drift | `cargo test -p anvil-diagnostics --test catalog_drift` | 5 passed: wording for every code and every release's token vocabulary; both Ferrum catalogs (`ferrum-edge-0.9.5`, `ferrum-edge-0.9.7`) embedded and internally consistent; the desktop dialog offers exactly the embedded releases. Renaming one catalog key makes it fail with the emitting file named |
| Lab gateway pin | `lab/scripts/fetch-gateway.sh [release]`; `anvil-lab [--release v0.9.5] verify`; separately downloaded `ferrum-edge-linux-x86_64` (v0.9.5) and compared with its lock | v0.9.7 (`RELEASE.lock` = `releases/v0.9.7.lock`): macOS asset verified (`f3bd0027…0dd03`). v0.9.5 (`releases/v0.9.5.lock`): macOS asset verified (`6a531f2c…ce5f`); Linux x86_64 asset SHA-256 matches the lock (`31573f0a…297c`). A binary of the other release is refused. |

Not run locally: Windows and Linux builds and tests (they run in CI; see the
PR checks), the x86_64 macOS cross build, `.msi`/NSIS/`.rpm`/`.AppImage`
unpacking, and the signing branches (no credentials).
