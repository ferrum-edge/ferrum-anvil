# Continuous integration

Ferrum Anvil runs four GitHub Actions workflows. Every third-party action is
pinned to a full commit SHA (the version is in a trailing comment) and every
tool to an exact version. Workflows default to `permissions: contents: read`.
Only the release publish job gets more: `contents: write` (to create a draft
release) and `actions: read` (to list the test runs for the release commit).

| Workflow | Trigger | Runs on | What it proves |
| --- | --- | --- | --- |
| `ci.yml` | every PR, push to `main`, manual | Ubuntu 24.04, macOS 15, Windows 2025 (Rust); Ubuntu (the rest) | Formatting, clippy `-D warnings`, workspace tests, both desktop feature sets compile, the OS credential store round trip, renderer tests and build, contracts and the diagnostic catalog in sync, supply-chain policy, no secrets |
| `lab.yml` | PRs touching `crates/`, `lab/`, `catalog/`, Cargo files or the workflow (core profile); nightly and manual (all profiles by default) | Ubuntu 24.04, macOS 15 | Failure-matrix scenarios against the real, checksum-pinned Ferrum Edge release binary, with and without a trusted Ferrum profile |
| `e2e.yml` | PRs touching the desktop app, crates, catalog, `lab/` or the release check; push to `main`; manual | macOS 15, Windows 2025, Ubuntu 24.04 (under Xvfb) | The native app, built with the test-only `e2e` feature, works end to end through the real Rust engine (and, on macOS and Linux, through the core lab gateway), and the release check rejects that build |
| `release.yml` | tag `anvil-v*`; manual (with a tag, or as a dry run) | macOS 15 (arm64 + x86_64 cross), Ubuntu 22.04, Windows 2025 | Installers and CLI binaries without test hooks, checksums, SBOMs, license report, release evidence, and a **draft** release. See [release.md](release.md) |

The `ci.yml` jobs are the required checks enforced on `main` by the "Main
required checks" ruleset. `e2e.yml` only runs for PRs that touch its paths, so
the ruleset cannot require it; when it runs, it must pass before merging. The
nightly lab run does not replace either.

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
| **Rust** (3 OSes) | `npm run build` (anvil-desktop embeds `apps/desktop/dist` at compile time) → `cargo fmt --all --check` (Linux) → `cargo clippy --locked --workspace --all-targets -- -D warnings` → `cargo check -p anvil-desktop` → `cargo check -p anvil-desktop --features e2e` → `cargo test --locked --workspace --exclude anvil-desktop --no-fail-fast` → `cargo test --locked -p anvil-desktop --lib` (not on Windows) → `cargo test -p anvil-storage --test os_keychain -- --ignored` (the real OS credential store; on Linux inside a D-Bus session with an unlocked gnome-keyring) |
| **Frontend** | `npm ci` → `npm run typecheck` → `npm run e2e:typecheck` → `npm test` (vitest, jsdom) → `npm run build` → `npm audit --omit=dev --audit-level=high` |
| **Contract & catalog drift** | `cargo run -p anvil-cli -- schema --out contracts/schemas` and `npm run contracts`, then fail if `contracts/` or `apps/desktop/src/generated/` changed; `cargo test -p anvil-diagnostics --test catalog_drift` |
| **Supply chain & licensing** | `cargo deny --locked check` (cargo-deny 0.20.2); `node scripts/licenses.mjs --check`; `scripts/release-check.sh` (dependency-graph check only) |
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

Prerequisites: rustup, Node.js ≥ 22, and on Linux the libraries listed above.
From the repository root:

```sh
# Rust (as the Rust job)
(cd apps/desktop && npm ci && npm run build)
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo check --locked -p anvil-desktop
cargo check --locked -p anvil-desktop --features e2e
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
scripts/release-check.sh                 # graph check only
gitleaks git --config .gitleaks.toml --log-opts="--full-history --diff-filter=tuxdb HEAD" --redact .   # gitleaks 8.30.1

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

- `lab/gateway/RELEASE.lock`: the candidate default pin (v0.9.11, hosted Anvil gates pending);
- `lab/gateway/releases/<release>.lock`: every supported release (v0.9.5,
  v0.9.7, v0.9.8, v0.9.9, v0.9.10 and v0.9.11).

Each lock pins macOS (arm64, x86_64), Linux (x86_64, arm64) and Windows
(x86_64) assets. The workflow passes the release in `ANVIL_LAB_RELEASE`: pull
requests use the default pin, the nightly run adds v0.9.10, v0.9.9, v0.9.8, v0.9.7 and v0.9.5, and a manual run
takes a `release` input. `anvil-lab verify` prints the gateway's identity and
`anvil-lab` re-verifies the checksum before every run. Results in
`results/lab/**` (and the gateway logs under `lab/.run/`) are uploaded as one
artifact per OS and release.

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
| Rust | `stable` from `rust-toolchain.toml` (not pinned; the exact `rustc` of each release build is recorded in its `build-info.json` and `release-evidence.json`) |

## Not yet exercised

The signing branches of `release.yml` have not run, because no signing
credentials are configured (see [release.md](release.md#signing-and-what-unsigned-means)).
