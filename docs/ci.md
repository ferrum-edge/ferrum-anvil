# Continuous integration

Ferrum Anvil runs four GitHub Actions workflows. Every third-party action is
pinned to a full commit SHA (the version is in a trailing comment) and every
tool to an exact version. Each workflow defaults to `permissions: contents: read`;
only the release publish job gets `contents: write` (to create a draft release)
and `actions: read` (to list the test runs for the release commit).

| Workflow | Trigger | Runs on | What it proves |
| --- | --- | --- | --- |
| `ci.yml` | every PR, push to `main`, manual | Ubuntu 24.04, macOS 15, Windows 2025 (Rust); Ubuntu (the rest) | Formatting, clippy `-D warnings`, workspace tests, both desktop feature sets compile, renderer tests and build, contracts and the diagnostic catalog in sync, supply-chain policy, no secrets |
| `lab.yml` | PRs touching `crates/`, `lab/`, `catalog/` or Cargo files (core profile); nightly and manual (all profiles) | Ubuntu 24.04, macOS 15 | Failure-matrix scenarios against the real, checksum-pinned Ferrum Edge release binary, with and without a trusted Ferrum profile |
| `e2e.yml` | PRs touching the desktop app, crates, catalog or the release check; push to `main`; manual | macOS 15, Windows 2025, Ubuntu 24.04 (under Xvfb) | The native app, built with the test-only `e2e` feature, works end to end through the real Rust engine, and the release check rejects that build |
| `release.yml` | tag `anvil-v*`; manual (with a tag, or as a dry run) | macOS 15 (arm64 + x86_64 cross), Ubuntu 22.04, Windows 2025 | Installers and CLI binaries without test hooks, checksums, SBOMs, license report, release evidence, and a **draft** release. See [release.md](release.md) |

A nightly lab run is not a substitute for the PR checks: `ci.yml` and `e2e.yml`
are the required checks for a change.

## `ci.yml` jobs

| Job | Steps |
| --- | --- |
| **Rust** (3 OSes) | `npm run build` (anvil-desktop embeds `apps/desktop/dist` at compile time) → `cargo fmt --all --check` (Linux) → `cargo clippy --locked --workspace --all-targets -- -D warnings` → `cargo check -p anvil-desktop` → `cargo check -p anvil-desktop --features e2e` → `cargo test --locked --workspace --exclude anvil-desktop` |
| **Frontend** | `npm ci` → `npm run typecheck` → `npm run e2e:typecheck` → `npm test` (vitest, jsdom) → `npm run build` → `npm audit --omit=dev --audit-level=high` |
| **Contract & catalog drift** | `cargo run -p anvil-cli -- schema --out contracts/schemas` and `npm run contracts`, then fail if `contracts/` or `apps/desktop/src/generated/` changed; `cargo test -p anvil-diagnostics --test catalog_drift` |
| **Supply chain & licensing** | `cargo deny --locked check` (cargo-deny 0.20.2); `node scripts/licenses.mjs --check`; `scripts/release-check.sh` (dependency-graph check only) |
| **Secret scan** | gitleaks 8.30.1 (downloaded and SHA-256 verified) over the full git history and the working tree, with `.gitleaks.toml` |

The catalog drift test (`crates/anvil-diagnostics/tests/catalog_drift.rs`)
extracts every finding code the rules and engine adapters can emit and fails
when a code has no wording in `catalog/diagnostics/findings.en.json`, when a
catalog entry is no longer emitted, when a new call site words its own
finding outside the catalog, or when an entry has a malformed placeholder or
an owner value that is not part of the contract.

The shared setup (`.github/actions/setup`) installs the Linux Tauri libraries
(`libwebkit2gtk-4.1-dev`, `libsoup-3.0-dev`, `libayatana-appindicator3-dev`,
`librsvg2-dev`, `libxdo-dev`, …), the Rust toolchain from `rust-toolchain.toml`,
a Rust build cache, Node.js 22.23.3 and the desktop npm dependencies.

## Reproducing locally

Prerequisites: rustup, Node.js ≥ 22, and on Linux the libraries listed above.
From the repository root:

```sh
# Rust (as the Rust job)
(cd apps/desktop && npm ci && npm run build)
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo check --locked -p anvil-desktop
cargo check --locked -p anvil-desktop --features e2e
ulimit -n 4096; cargo test --locked --workspace --exclude anvil-desktop

# Frontend
cd apps/desktop && npm run typecheck && npm run e2e:typecheck && npm test && npm run build; cd -

# Contract and catalog drift
cargo run --locked -p anvil-cli -- schema --out contracts/schemas
(cd apps/desktop && npm run contracts)
git status --porcelain contracts apps/desktop/src/generated   # must print nothing
cargo test --locked -p anvil-diagnostics --test catalog_drift

# Supply chain
cargo install --locked cargo-deny@0.20.2
cargo deny --locked check
node scripts/licenses.mjs --check        # regenerate with: node scripts/licenses.mjs
scripts/release-check.sh                 # graph check only
gitleaks git --config .gitleaks.toml --redact .   # gitleaks 8.30.1

# Lab (fixed ports 18080/18090/19000-19099 — stop any other lab first)
lab/scripts/fetch-gateway.sh             # needs `gh` (authenticated) and verifies RELEASE.lock
ulimit -n 4096; cargo run -p anvil-lab -- run core --untrusted-pass

# Native E2E
cd apps/desktop && npm run e2e:build && npm run e2e
```

The E2E suite and its local-run notes are described in
[release.md § Native E2E](release.md#native-desktop-e2e).

## Lab gateway on CI

`lab/scripts/fetch-gateway.sh` downloads the pinned Ferrum Edge release asset
for the runner's OS/architecture with `gh release download` (authenticated by
the workflow's `github.token`; `ferrum-edge/ferrum-edge` is public) and
refuses to keep a binary whose SHA-256 differs from `lab/gateway/RELEASE.lock`.
The lock already pins macOS (arm64, x86_64), Linux (x86_64, arm64) and Windows
(x86_64) assets of v0.9.5, so no format change was needed for the Linux lane.
`anvil-lab` re-verifies the checksum before every run. Results are uploaded
from `results/lab/**`.

## Pinned versions

| Item | Version |
| --- | --- |
| actions/checkout | v7.0.1 `3d3c42e5aac5ba805825da76410c181273ba90b1` |
| actions/setup-node | v7.0.0 `820762786026740c76f36085b0efc47a31fe5020` |
| actions/upload-artifact | v7.0.1 `043fb46d1a93c77aae656e7c1c64a875d1fc6a0a` |
| actions/download-artifact | v8.0.1 `3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c` |
| Swatinem/rust-cache | v2.9.2 `6323deb102c322ba6fcbdcafc7e3dddab59af2b6` |
| taiki-e/install-action | v2.87.20 `9983c65e42da123ff25d1f78505eb6de315aa172` |
| Node.js | 22.23.3 |
| cargo-deny / cargo-cyclonedx | 0.20.2 / 0.5.9 |
| gitleaks | 8.30.1 (linux x64 SHA-256 `551f6fc8…f2470eb`) |
| @cyclonedx/cyclonedx-npm | 6.0.1 (release workflow, via `npx`) |
| WebdriverIO / @wdio/tauri-service | 9.30.1 / 1.4.0 (lockfile) |
| Rust | `stable` from `rust-toolchain.toml` (not pinned by the repo; the exact `rustc` of each release build is recorded in `release-evidence.json`) |

## What has and has not been run

The workflows were written and linted (`actionlint` 1.7.12, with shellcheck)
on macOS; the steps were executed locally on macOS 26 / Apple silicon (see the
verification record in [release.md](release.md#local-verification-record)).
The Linux and Windows lanes, the Linux/Windows E2E runs, the x86_64 macOS
cross build, MSI/NSIS/deb/rpm/AppImage inspection and the signing branches
have not yet been executed and must be watched on their first CI run.
