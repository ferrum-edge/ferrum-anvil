# Releasing Ferrum Anvil

Releases are built by `.github/workflows/release.yml` and always end as a
**draft** GitHub release. Publishing a draft, announcing it and updating the
website are manual owner steps taken only after the release gate below is met
(plan §16 "Release gates", §18, §19).

## Cutting a release

1. Make sure `main` is green in CI, Desktop E2E and the nightly Lab.
2. Bump the version in all three places — `Cargo.toml` (`[workspace.package] version`),
   `apps/desktop/src-tauri/tauri.conf.json` and `apps/desktop/package.json` — and
   commit.
3. Tag and push: `git tag anvil-v0.1.0 && git push origin anvil-v0.1.0`.
   (Or run the workflow manually with the tag as input. Without a tag, a manual
   run is a **dry run**: everything is built and checked and the evidence is
   uploaded to the run, but no release is created.)
4. Review the draft (checklist below), then publish it by hand.

## What the workflow does

**Preflight** (Ubuntu): the tag must equal `anvil-v<version>` and the three
version fields must agree; `cargo deny check`; `node scripts/licenses.mjs --check`;
`scripts/release-check.sh` (dependency graph); the diagnostic catalog drift test.

**Build** (one job per target):

| Target | Runner | Bundles |
| --- | --- | --- |
| `aarch64-apple-darwin` | macOS 15 | `.app` → `.dmg` |
| `x86_64-apple-darwin` | macOS 15 (cross-compiled) | `.app` → `.dmg` |
| `x86_64-unknown-linux-gnu` | Ubuntu 22.04 (older glibc baseline) | `.deb`, `.rpm`, `.AppImage` |
| `x86_64-pc-windows-msvc` | Windows 2025 | `.msi`, NSIS `-setup.exe` |

Each build job:

1. `tauri build --ci --target <t> --bundles <b>` — release profile, **default
   features only**. The `e2e` feature (embedded WebDriver + environment-driven
   unlock) is never passed.
2. `cargo build --release -p anvil-cli --target <t>` and packages
   `anvil-cli-<version>-<t>.tar.gz|.zip` with `LICENSE`, `LICENSE-COMMERCIAL.md`
   and `THIRD_PARTY_LICENSES.md`. (At the time of writing no shipped application
   launches the `anvil-load-worker` binary, so it is not packaged; add it here
   when a host does.)
3. `scripts/release-check.sh` over every installer, the CLI archive and the raw
   app binary, with the runtime probe on native targets (Linux under Xvfb). Any
   failure stops the release.
4. Signature verification (see [Signing](#signing-and-what-unsigned-means)) and
   `build-info.json` (target, OS/arch, runner, `rustc`/`cargo`/Node/Tauri CLI
   versions, signing status).
5. CycloneDX 1.5 SBOMs for `anvil-desktop` and `anvil-cli` for that target
   (`cargo cyclonedx`); the job fails if the desktop SBOM lists the WebDriver plugin.

**Publish** (Ubuntu): npm SBOM of the UI's production dependencies
(`@cyclonedx/cyclonedx-npm`), `license-report.json`, the list of GitHub Actions
runs for the release commit, `SHA256SUMS`, `release-evidence.json`, an uploaded
evidence bundle, and — for tags only — `gh release create --draft --verify-tag`.

### Release evidence

`release-evidence.json` (written by `scripts/release-evidence.mjs`) records:

- product, version, tag, publication state (`draft` or `dry run — not published`);
- repository, **source commit**, workflow run id/URL/attempt;
- per target: OS, architecture, runner, toolchain versions, `signed`,
  `signing`, the release-check result and report, and every artifact with its
  file name, kind, size and SHA-256;
- shared artifacts (npm SBOM, license report) and the `SHA256SUMS` file;
- licensing: project license and third-party report;
- compatibility: diagnostics catalog version, every Ferrum compatibility
  catalog (`catalog/ferrum/*/outcomes.json`: compatibility id, gateway release
  tag and source SHA, outcome count, public tokens) and the lab gateway pin
  (`lab/gateway/RELEASE.lock`);
- tests: the CI / Desktop E2E / Lab runs for the commit with their
  conclusions. A missing or skipped run is not a pass — check them.

The script refuses to finish (non-zero exit) if a target has no passing release
check, no installer, no CLI archive or no SBOM, or if two artifacts share a name.

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
3. **Runtime probe** (`--runtime-probe`) — the desktop executable is launched
   with `TAURI_WEBDRIVER_PORT=<free port>`, `ANVIL_E2E_PROFILE` and
   `ANVIL_E2E_PASSPHRASE` set and a throw-away `ANVIL_DATA_DIR`. Nothing may
   answer `GET /status` on that port and no profile may appear in the data
   directory. Only the process the probe started is stopped.

Exit status: `0` pass, `1` test hooks found, `2` usage error or an artifact
that could not be inspected (never reported as a pass).

## Signing and what "unsigned" means

Code signing needs the owner's certificates, which are **not** in the
repository. The workflow signs only when the corresponding secrets exist:

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

Unsigned means: the files are exactly what CI built from the recorded commit
(check `SHA256SUMS` and `release-evidence.json`), but the operating system
cannot attribute them to Ferrum Edge. macOS Gatekeeper blocks an unsigned app
downloaded from the internet unless the user explicitly allows it (on Apple
silicon the bundle only carries an ad-hoc signature); Windows SmartScreen warns.
Do not publish unsigned installers as a production download, and never describe
them as signed. Signing is a blocked deliverable until the owner supplies
credentials. No step in this repository creates, simulates or claims a
signature it did not verify.

The Tauri updater is not used, so there is no updater signing key.

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
- **Advisories**: RustSec, with three reviewed ignores that each carry an exit
  condition in `deny.toml` and are open items for the owner:
  - `RUSTSEC-2023-0071` — `rsa` (Marvin timing side channel) via
    `jsonwebtoken`'s `rust_crypto` backend for RS256 signing in `anvil-auth`.
    Anvil only signs caller-built JWTs locally; no patched `rsa` exists. Consider
    switching `jsonwebtoken` to a constant-time backend.
  - `RUSTSEC-2024-0429` — `glib` 0.18 `VariantStrIter` unsoundness via Tauri's
    Linux GTK stack; not called by Anvil or Tauri. Resolves when Tauri moves to
    gtk-rs ≥ 0.20.
  - `RUSTSEC-2025-0134` — `rustls-pemfile` is archived (unmaintained, no
    vulnerability); used by `anvil-transport` and `anvil-fixtures`. Migrate to
    `rustls_pki_types::pem::PemObject`.
- **npm**: `npm audit --omit=dev --audit-level=high` gates the dependencies that
  ship in the UI bundle (currently 0 findings). The development-only E2E
  tooling (WebdriverIO 9.30.1, pinned exactly by `@wdio/tauri-service` 1.4.0)
  carries high-severity advisories in `deepmerge-ts`, `extract-zip` and
  `serialize-javascript`; it runs only on developer machines and CI against
  local fixtures and is never shipped. Revisit when the Tauri service moves to
  a fixed WebdriverIO.
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
  (`/ok/echo`) instead of the local fixture.
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
| `99-lock` | Lock button → lock screen; backend refuses `history_list`, `workspaces_list`, `tree_get`, `settings_get` with `LOCKED` (runs last because the app stays locked) |

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
- [ ] Clean-install smoke test of each installer (install, first run, create a
      profile, send a request, lock/unlock, uninstall); screenshots attached.
- [ ] Advisory ignores in `deny.toml` re-reviewed.
- [ ] Website changes follow only after publishing and link the exact artifact
      URLs and checksums (plan §18).

## Open items

- **Signing credentials** (owner): Apple Developer ID + notarization and a
  Windows code-signing certificate. Until then every build is unsigned.
- **License texts inside the desktop installers**: the CLI archive carries
  `LICENSE`, `LICENSE-COMMERCIAL.md` and `THIRD_PARTY_LICENSES.md`, but the
  `.app`/`.dmg`/`.deb`/`.rpm`/`.AppImage`/`.msi`/NSIS bundles do not yet. Add them
  through `bundle.resources` (and `bundle.licenseFile` for the installer
  license page) in `apps/desktop/src-tauri/tauri.conf.json`.
- **Packaged-app smoke tests** (install, first run, dialogs, uninstall) are not
  automated; the native E2E suite runs against the instrumented debug build.
- The three advisory ignores in `deny.toml` (see above).
- After merging dependency changes, regenerate `THIRD_PARTY_LICENSES.md`
  (`node scripts/licenses.mjs`); CI fails while it is stale.

## Local verification record

Recorded on macOS 26 (Darwin 25.6, Apple silicon), Rust 1.98.1, Node 23.11,
from branch `claude/anvil-desktop-client-3f372d`.

| Check | Command | Result |
| --- | --- | --- |
| CI Rust lane (macOS) | `cargo fmt --all --check`; `cargo clippy --locked --workspace --all-targets -- -D warnings`; `cargo check -p anvil-desktop` with and without `--features e2e`; `cargo test --locked --workspace --exclude anvil-desktop` | all exit 0; tests: 47 test binaries, 308 passed, 0 failed, 0 ignored |
| Contract drift | `cargo run -p anvil-cli -- schema --out contracts/schemas` + `npm run contracts` | **drift found at base commit `29b2f3d`**: `LoadReport.schema.json` and `contracts.ts` were stale (LoadReport gained `requests`, `workload_label`, `offered_rate_per_sec`, … without regeneration). The committed files at the current tip of `claude/anvil-desktop-client-3f372d` match the regenerated schema, i.e. it was fixed upstream; the CI job would have caught it |
| cargo-deny | `cargo deny --locked check` | advisories ok (3 reviewed ignores), bans ok, licenses ok, sources ok; 79 duplicate-version warnings |
| cargo-deny ban guard | `cargo deny --locked --features e2e check bans` | fails as intended: `tauri-plugin-wdio-webdriver` is banned |
| License inventory | `node scripts/licenses.mjs --check` | up to date: 773 crates, 5 npm packages, no violations |
| Secret scan | `gitleaks git` (all local refs, 73 commits) / `gitleaks dir` with `.gitleaks.toml` | no leaks (without the config: 8 findings, then a 9th from the runner tests on the shared branch — all test vectors, fixtures or planted canaries) |
| Release check, release build | `cargo build -p anvil-desktop --release`, then `scripts/release-check.sh --runtime-probe <binary>` | **pass** — graph clean, 0 of 11 hook strings, no WebDriver listener, no profile created |
| Release check, e2e build | `cargo build -p anvil-desktop --release --features e2e`, then `scripts/release-check.sh --features e2e --runtime-probe <binary>` | **fail (exit 1)** as required — graph contains the plugin, 10 of 11 hook strings found (the `e2e_unlock` symbol is stripped), WebDriver answered HTTP 200 on the probe port |
| Release check, debug e2e build | `scripts/release-check.sh --no-graph target/debug/anvil-desktop` | **fail (exit 1)** — all 11 strings found |
| Release check, inconclusive input | `/bin/ls`, `README.md` | exit 2 (no Anvil marker / unsupported type) — never a pass |
| Release bundle dry run (macOS arm64) | `npx tauri build --ci --bundles app,dmg`, `cargo build --release -p anvil-cli`, then the release workflow's collect, release-check (with probe), signature-verification, SBOM, license-report and evidence steps | release check **pass** on the `.dmg`, the `.app`, the CLI `.tar.gz` and the raw binary; signing recorded as `unsigned — owner credentials not configured (ad-hoc signature only, not a Developer ID)`; `release-evidence.json` with 7 artifacts, empty `problems`; `shasum -c SHA256SUMS` OK |
| Release check, other formats | synthetic `.deb` (ar fallback) and `.zip` around the release/e2e binaries | clean → pass; `.deb` carrying the e2e binary → fail (exit 1) |
| Renderer tests | `npm test` | 22 passed (2 files) |
| Catalog drift | `cargo test -p anvil-diagnostics --test catalog_drift` | 3 passed; renaming one catalog key makes it fail with the emitting file named |
| Native E2E | `npm run e2e:build && npm run e2e` | 5 spec files, 11 tests passed (local JSON fixture) |
| Lab gateway pin | `lab/scripts/fetch-gateway.sh`; separately downloaded `ferrum-edge-linux-x86_64` (v0.9.5) and compared with `RELEASE.lock` | macOS asset downloaded and verified; Linux x86_64 asset SHA-256 matches the lock (`31573f0a…297c`) |
| Native E2E through the gateway | `ANVIL_E2E_GATEWAY=http://127.0.0.1:18080 npm run e2e` with the core lab gateway (Ferrum Edge v0.9.5) running | 5 spec files, 11 tests passed; the echo shows the request passed through `via: 1.1 ferrum-edge` |

Not run locally: the Linux and Windows lanes and E2E runs, the x86_64 macOS
cross build, `.msi`/NSIS/`.rpm`/`.AppImage` unpacking, the signing branches
(no credentials), and the lab workflow (another lab was running on the fixed
lab ports on the verification machine).
