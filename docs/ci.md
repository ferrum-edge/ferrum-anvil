# Continuous integration

Ferrum Anvil runs eight GitHub Actions workflows. Every third-party action is
pinned to a full commit SHA (the version is in a trailing comment) and every
tool to an exact version. Workflows default to `permissions: contents: read`.
The release `publish` job gets `actions: read` (to list the test runs for the
release commit). Only the `release` job, which runs for a tag and not for a dry
run, gets `contents: write` (to create the draft release).
`website-evidence.yml` requests no token permissions. `ferrum-edge/ferrumedge`
is private and this repository is public, so `GITHUB_TOKEN` cannot read it: the
job needs the repository secret `FERRUMEDGE_READ_TOKEN`, a fine-grained token
with read-only Contents access to `ferrum-edge/ferrumedge` only. Without the
secret the job fails (it never skips), so a missing secret is never read as a
pass.

| Workflow | Trigger | Runs on | What it proves |
| --- | --- | --- | --- |
| `ci.yml` | every PR, push to `main`, manual | Ubuntu 26.04, macOS 15, Windows 2025 (Rust); Ubuntu (the rest) | Formatting, clippy `-D warnings`, workspace tests, both desktop feature sets compile, the OS credential store round trip, renderer tests and build, contracts and the diagnostic catalog in sync, supply-chain policy, no secrets |
| `lab.yml` | PRs touching `crates/`, `lab/`, `catalog/`, Cargo files, `vendor/`, the workflow or the setup action (all profiles; core profile on macOS); nightly and manual (all profiles by default) | Ubuntu 26.04, macOS 15 | Failure-matrix scenarios against the real, checksum-pinned Ferrum Edge release binary, with and without a trusted Ferrum profile |
| `e2e.yml` | PRs touching the desktop app, crates, catalog, `lab/` or the release check; push to `main`; manual | macOS 15, Windows 2025, Ubuntu 26.04 (under Xvfb) | The native app, built with the test-only `e2e` feature, works end to end through the real Rust engine (and, on macOS and Linux, through the core lab gateway), and the release check rejects that build |
| `release.yml` | tag `anvil-v*`; manual (dry run by default; set `dry_run: false` from a tag for a draft release) | macOS 15 (arm64 + x86_64 cross), Ubuntu 26.04, Windows 2025 | Installers and CLI binaries without test hooks, checksums, SBOMs, license report, release evidence, and optionally a **draft** release. See [release.md](release.md) |
| `release-smoke.yml` | manual; an `anvil-v*` release is published; PRs touching the workflow or `scripts/release-smoke/` | macOS 15 (arm64), macOS 15 Intel, Windows 2025 (NSIS, MSI), Ubuntu 26.04 (`.deb`, AppImage), Fedora 44 container (`.rpm`) | The published, unsigned packages install natively on fresh runners, the installed app launches with its window and webview, and the release CLI imports the example and makes a loopback call (REL-001). See [release.md](release.md#clean-install-smoke-rel-001) |
| `bundle-resources.yml` | PRs touching `crates/anvil-portability/**`, `crates/anvil-app/src/port.rs`, `crates/anvil-app/tests/bundle_import.rs` or the workflow itself; manual | Ubuntu 26.04, macOS 15 | Peak-memory regression ceilings for bundle preview/import against the policy and two baselines. See [bundle-resource-policy.md](security/bundle-resource-policy.md#hosted-qualification) |
| `website-evidence.yml` | every release run (called from `release.yml`, tagged or dry run, beside the build; it does not gate the draft release); manual; PRs and pushes to `main` that change the workflow (e.g. the pin) | Ubuntu 26.04 | The website's JavaScript tests, including its Anvil navigation, download and capability tests (`node --test "tests/**/*.test.js"`, as its own `test.yml` runs them, no live network checks) pass at the pinned `ferrum-edge/ferrumedge` commit; uploads `website-evidence.json` (website SHA, command, counts, Anvil release tag). Failure-matrix REL-006, REL-007, REL-008 |
| `updater-e2e.yml` | PRs touching the update command (`cmd_update.rs`, `cmd_update/`), the plugin and command registration (`src-tauri/src/lib.rs`), `tauri.conf.json`, the desktop `Cargo.toml`, `apps/desktop/e2e/updater/`, the E2E helpers and driver config (`e2e/helpers.ts`, `wdio.conf.ts`), `scripts/updater-manifest.mjs` or its tests, or the workflow; push to `main` (same paths); weekly; manual | Ubuntu 26.04 (AppImage, under Xvfb), macOS 15 (.app) | REL-003 on built bundles: the E2E-instrumented bundle, built with a test updater key and a loopback endpoint, refuses an update signed by another key, with a corrupted signature or altered after signing through its real `update_install` command, with the bundle, its reported version and the persistent profile files (SQLite's `-shm` aside) unchanged during each refusal, and installs a validly signed one. Also runs `scripts/tests/updater-manifest.test.mjs`. See [release.md](release.md#signed-update-refusal-e2e-rel-003) |

The `ci.yml` jobs are the required checks enforced on `main` by the "Main
required checks" ruleset. `e2e.yml` only runs for PRs that touch its paths, so
the ruleset cannot require it; when it runs, it must pass before merging. The
nightly lab run does not replace either.

`lab.yml` is path-filtered too, so the ruleset cannot require it either; when
it runs on a PR, it must pass before merging. A pull request's Ubuntu lab job
runs every profile against the default pin (about 11 to 12 minutes, inside the
time the Rust jobs already take), and its macOS job runs the core profile. The
nightly run adds every earlier supported release on both systems. Before this,
pull requests ran only the core profile, so a dependency bump that broke the
`tls` profile's DTLS mTLS scenario (PROTO-022) merged green and failed every
nightly job afterwards. A failing scenario is read from the job's uploaded
`lab-results-*` artifact before anything is re-run; re-run a job only for a
failure shown to be unrelated to the change, and open an issue for a scenario
that fails that way more than once. The cross-version DTLS mTLS handshake
behind that failure is also a required Rust test
(`crates/anvil-transport/tests/dtls_edge_interop.rs`).

The existing macOS Rust job also compiles the standalone Swift branding helper
with `swift build --package-path apps/desktop/scripts`. Its small SwiftPM
manifest lets CodeQL discover the helper. This step never runs the asset
generator, and adds no runner or merge requirement.

## Dependabot version updates

Dependabot PRs may need manual follow-up before CI passes. On the Dependabot
branch, regenerate the third-party license report with
`node scripts/licenses.mjs`, commit the updated
`THIRD_PARTY_LICENSES.md`, and push that commit to the same branch. Do not add a
workflow that writes repository contents with a token. Contract & catalog
drift can also fail when `json-schema-to-typescript` or `schemars` changes
generated output. Regenerate the contracts with the commands below, and update
any affected catalog entries if the catalog drift check reports a failure;
commit the resulting files and push them to that branch.

Once a person pushes to a Dependabot branch, Dependabot stops rebasing it, and
`@dependabot recreate` discards the pushed commits. After pushing a follow-up,
keep the branch current with a normal merge of `main` instead.

Dependabot ignores major and minor updates for Tauri packages because the Rust
crates and JavaScript packages must move together. Bump `tauri` and the related
`@tauri-apps/*`, `tauri-plugin-wdio-webdriver`, and `@wdio/tauri-service`
packages together by hand, then update both lockfiles in the same change.

## `ci.yml` jobs

| Job | Steps |
| --- | --- |
| **Rust** (3 OSes) | `npm run build` (anvil-desktop embeds `apps/desktop/dist` at compile time) → `cargo fmt --all --check` (Linux) → `cargo clippy --locked --workspace --all-targets -- -D warnings` → `cargo check -p anvil-desktop` → `cargo check -p anvil-desktop --features e2e` → `cargo check --target x86_64-apple-darwin -p anvil-auth -p anvil-transport` (macOS only, the AWS-LC crates for the cross-built release target) → `cargo check -p anvil-auth` (Windows only, the crate on its own) → `cargo test --locked --workspace --exclude anvil-desktop --no-fail-fast` → `cargo test --locked -p anvil-desktop --lib` (not on Windows) → `cargo test -p anvil-storage --test os_keychain -- --ignored` (the real OS credential store; on Linux inside a D-Bus session with an unlocked gnome-keyring) |
| **Frontend** | `npm ci` → `npm run typecheck` → `npm run e2e:typecheck` → `npm test` (vitest, jsdom) → `npm run build` → `npm audit --omit=dev --audit-level=high` |
| **Contract & catalog drift** | `cargo run -p anvil-cli -- schema --out contracts/schemas` and `npm run contracts`, then fail if `contracts/` or `apps/desktop/src/generated/` changed; `cargo test -p anvil-diagnostics --test catalog_drift` |
| **Supply chain & licensing** | `cargo deny --locked check` (cargo-deny 0.20.2); `node scripts/licenses.mjs --check`; `node --test scripts/tests/release-notes.test.mjs` (release notes generator, including the current version's CHANGELOG section); `node --test scripts/tests/updater-manifest.test.mjs` (the signature checks behind `latest.json` refuse another key, a bad signature, an altered artifact and a wrong signed version); `python3 -I scripts/tests/test_release_smoke_record.py` (the release smoke's failure classes: step, finalize and summary, including a job that stopped before recording); `python3 -I scripts/tests/test_matrix_coverage.py` (the failure-matrix classifier's `pinned` cap and `requires` gate); `scripts/release-check.sh` (dependency-graph check only) |
| **Release checker** (Ubuntu 26.04) | the pinned trusted AppImage extractor (`.github/actions/trusted-appimage-extractor`) → `python3 -I scripts/tests/test_release_check.py` |
| **Secret scan** | gitleaks 8.30.1 (downloaded and SHA-256 verified) over the full history of the checked-out commit and over the working tree, with `.gitleaks.toml`. For a PR the commit is its merge commit, so the PR's commits and all of `main` are scanned; other branches are not |

The catalog drift test (`crates/anvil-diagnostics/tests/catalog_drift.rs`)
collects every finding code the rules and engine adapters can emit. It fails
when:

- a code has no wording in `catalog/diagnostics/findings.en.json`;
- a catalog entry is no longer emitted;
- a new call site words its own finding outside the catalog;
- an entry has a malformed placeholder or an owner value outside the contract.

The shared setup action (`.github/actions/setup`) installs the Linux Tauri
libraries (`libwebkit2gtk-4.1-dev`, `libsoup-3.0-dev`,
`libayatana-appindicator3-dev`, `librsvg2-dev`, `libxdo-dev`, …), the Rust
toolchain from `rust-toolchain.toml`, a Rust build cache, Node.js 22.23.3 and
the desktop npm dependencies.

Build settings that keep the Rust lanes fast:

- The Rust build cache is saved even when a job fails (`cache-on-failure`), so
  a lane that keeps failing still starts warm. Release jobs opt out: a failed
  release never writes the cache.
- `ci.yml` builds the dev and test profiles with
  `debug = "line-tables-only"` (`CARGO_PROFILE_{DEV,TEST}_DEBUG`). Backtraces
  keep file and line, while link time and cache size drop.
- `cargo test --no-fail-fast` reports every failing test binary in one run,
  not just the first.

## Reproducing locally

Prerequisites: rustup, Node.js ≥ 22.12, and on Linux the libraries listed above.
From the repository root:

```sh
# Rust (as the Rust job)
(cd apps/desktop && npm ci && npm run build)
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo check --locked -p anvil-desktop
cargo check --locked -p anvil-desktop --features e2e
rustup target add x86_64-apple-darwin && cargo check --locked --target x86_64-apple-darwin -p anvil-auth -p anvil-transport   # macOS only
cargo check --locked -p anvil-auth       # Windows only
ulimit -n 4096; cargo test --locked --workspace --exclude anvil-desktop --no-fail-fast
cargo test --locked -p anvil-desktop --lib   # not on Windows
cargo test --locked -p anvil-storage --test os_keychain -- --ignored   # uses your real OS credential store

# Frontend
(cd apps/desktop && npm run typecheck && npm run e2e:typecheck && npm test && npm run build)

# Contract and catalog drift
cargo run --locked -p anvil-cli -- schema --out contracts/schemas
(cd apps/desktop && npm run contracts)
git status --porcelain contracts apps/desktop/src/generated   # must print nothing
cargo test --locked -p anvil-diagnostics --test catalog_drift

# Supply chain
cargo install --locked cargo-deny@0.20.2
cargo deny --locked check
node scripts/licenses.mjs --check        # regenerate with: node scripts/licenses.mjs
node --test scripts/tests/release-notes.test.mjs
node --test scripts/tests/updater-manifest.test.mjs
python3 -I scripts/tests/test_release_smoke_record.py
python3 -I scripts/tests/test_matrix_coverage.py
scripts/release-check.sh                 # graph check only
gitleaks git --config .gitleaks.toml --log-opts="--full-history --diff-filter=tuxdb HEAD" --redact .   # gitleaks 8.30.1

# Failure matrix (docs/verification/matrix-coverage.{json,md})
# Regenerate after changing matrix-status.json or a test that names a case,
# with the lab results of the cited Lab run under results/lab/ (download
# its artifacts, or link them there; results/ is git-ignored):
python3 -I scripts/matrix-coverage.py
# CI does not check that the committed outputs are current: hosted CI has no
# lab results to regenerate them from, so a diff gate would always differ.

# Lab (fixed loopback ports: stop any other lab first)
ruby lab/gateway/lint-profiles.rb
lab/scripts/fetch-gateway.sh             # needs an authenticated `gh`; verifies RELEASE.lock
ulimit -n 4096; cargo run -p anvil-lab -- run core --untrusted-pass
lab/scripts/fetch-gateway.sh v0.9.5      # an earlier supported release (lab/gateway/releases/v0.9.5.lock)
cargo run -p anvil-lab -- --release v0.9.5 run core --untrusted-pass

# Native E2E
(cd apps/desktop && npm run e2e:build && npm run e2e)
```

The E2E suite is described in
[release.md § Native desktop E2E](release.md#native-desktop-e2e).

## Lab gateway on CI

`lab/scripts/fetch-gateway.sh [release]` downloads a pinned Ferrum Edge
release asset for the runner's OS and architecture with `gh release download`
(authenticated by the workflow's `github.token`) into `lab/bin/<release>/`.
It refuses to keep a binary whose SHA-256 differs from its lock:

- `lab/gateway/RELEASE.lock`: the default pin (v0.9.15, hosted Anvil qualification recorded);
- `lab/gateway/releases/<release>.lock`: every supported release (v0.9.5,
  v0.9.7, v0.9.8, v0.9.9, v0.9.10, v0.9.11, v0.9.14 and v0.9.15).

Each lock pins macOS (arm64, x86_64), Linux (x86_64, arm64) and Windows
(x86_64) assets. The workflow passes the release in `ANVIL_LAB_RELEASE`: pull
requests use the default pin, the nightly run adds v0.9.14, v0.9.11, v0.9.10, v0.9.9, v0.9.8, v0.9.7 and v0.9.5, and a manual run
takes a `release` input. `anvil-lab verify` prints the gateway's identity and
`anvil-lab` re-verifies the checksum before every run. Results in
`results/lab/**` (and the gateway logs under `lab/.run/`) are uploaded as one
artifact per OS and release.

## Pinned versions

| Item | Version |
| --- | --- |
| actions/checkout | v7.0.1 `3d3c42e5aac5ba805825da76410c181273ba90b1` |
| actions/setup-node | v7.1.0 `949feb2413d6458794dcd2491c4babbbce0c15c1` |
| actions/upload-artifact | v7.0.2 `cf430e030ddbb5b0abf93d22962f4752f3646cd9` |
| actions/download-artifact | v8.0.2 `9000827ccba6bdab643e8b6fd33ac0654aef8333` |
| Swatinem/rust-cache | v2.9.3 `d1527c8f67ef9af357290475d4af4b0fab8f12e0` |
| taiki-e/install-action | v2.87.31 `1e29709c0ec63babbe8f266397a465f29a825f91` |
| Node.js | 22.23.3 |
| cargo-deny / cargo-cyclonedx | 0.20.2 / 0.5.9 |
| gitleaks | 8.30.1 (linux x64 SHA-256 `551f6fc8…f2470eb`) |
| @cyclonedx/cyclonedx-npm | 6.0.1 (release workflow, via `npx`) |
| WebdriverIO / @wdio/tauri-service | 9.32.0 / 1.5.0 (direct `devDependencies` in `apps/desktop/package.json`, locked in `package-lock.json`; `@wdio/cli` and `@wdio/mocha-framework` 10.1.0 bring a nested WebdriverIO 10.1.0, see [release.md](release.md)) |
| Rust | `stable` from `rust-toolchain.toml` (not pinned; the exact `rustc` of each release build is recorded in its `build-info.json` and `release-evidence.json`) |

## Not yet exercised

The signing branches of `release.yml` have not run, because no signing
credentials are configured (see [release.md](release.md#signing-and-what-unsigned-means)).
