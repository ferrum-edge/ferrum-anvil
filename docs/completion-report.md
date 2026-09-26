# Completion report

Ferrum Anvil — "Put your APIs to the test". This report covers the build from
the handoff (`docs/handoff/`) to this point. It states what exists, what was
executed, and what is still blocked or missing. A skip is never reported as a
pass.

## References

| What | Where |
|---|---|
| Source | `ferrum-edge/ferrum-anvil`, branch `claude/anvil-desktop-client-3f372d`, draft PR ferrum-edge/ferrum-anvil#1 |
| Website (staged, pre-release) | `ferrum-edge/ferrumedge`, branch `claude/anvil-website`, draft PR ferrum-edge/ferrumedge#54. Do not merge before a release. |
| Gateway compatibility targets | Ferrum Edge v0.9.7 release binary (source `8fed134`, the default pin, `lab/gateway/RELEASE.lock`) and v0.9.5 (source `20e7603`, `lab/gateway/releases/v0.9.5.lock`), both checksum-pinned; each has its own source-audited catalog |
| Gateway changes | None. The proposed authorized diagnostic API (G01) is specified in `docs/g01-gateway-diagnostic-contract.md` but is not implemented in the gateway. |
| Signed artifacts, checksums | None: signing is blocked on owner credentials. The release workflow only produces draft releases (see `docs/release.md`). |

## Implemented

- **Desktop app (Tauri 2 + React/TypeScript) and CLI (`anvil`).**
  - Both run on one Rust engine.
  - Typed IPC only and a strict CSP; the webview does no I/O.
  - The lock is enforced in the backend.
  - Architecture decisions are recorded in `docs/adr/0001–0010`.
- **Build and send.**
  - Workspaces with nested folders, saved requests with immutable revisions, environments, variables and history.
  - Effective-request preview.
  - Live lint.
  - Timing and sizes.
  - Protocols: HTTP/1.1, HTTP/2, h2c and HTTP/3 (forced or with fallback); WebSocket (HTTP/1.1, HTTP/2 and HTTP/3); gRPC in four modes; SSE; TCP/TLS; UDP; DTLS.
  - Interactive sessions for the session protocols.
  - See `docs/protocols.md`.
- **Auth and TLS.**
  - Auth types: API key, Basic, Bearer, JWT, OAuth 2.0 (client credentials, refresh, authorization code + PKCE in the system browser), Ferrum HMAC v2, DPoP, WS-Security UsernameToken, a verbatim user-supplied SAML assertion, and multi-auth.
  - Private CAs and mTLS with PEM or PKCS#12.
  - Verification is on by default; a bypass is scoped to a profile and warned about.
  - Auth is applied after final serialization, and the load engine reuses it unchanged.
- **Evidence-based diagnostics.**
  - Deterministic rules run over typed evidence.
  - Each finding has a confidence (confirmed/likely/unknown/conflicting), a scope (the leg it concerns), an owner, what it does not prove, alternatives and next steps.
  - Source-audited catalogs back the Ferrum-specific findings: 538 Ferrum Edge 0.9.7 outcomes and 528 Ferrum Edge 0.9.5 outcomes. A declared gateway uses the catalog of its own release; a release without a catalog gets no outcome matching and an explicit finding saying so.
  - Markers count only for declared gateways and are capped at "likely". The seven coarse `X-Gateway-Error` values are never refined into precise causes.
  - No cloud service or LLM is involved.
  - See `docs/diagnostics.md` and `catalog/`.
- **Data.**
  - Encrypted local store (XChaCha20-Poly1305). Unlock with a passphrase (plus a recovery key) or the OS keychain.
  - Portable share-safe or encrypted workspace bundles, and full backups that restore into a clean install without the original keychain.
  - Imports are previewed, validated and atomic, with rollback. Imported scenarios, plans and insecure settings stay untrusted until reviewed.
  - See `docs/storage-and-recovery.md`.
- **Import.** OpenAPI 2.0–3.2, WSDL 1.1, Postman, Insomnia, cURL and HAR, with credential redaction and re-import. See `docs/import.md`.
- **Collection runner.** Datasets, extraction, assertions, and JUnit/HTML/JSON reports. See `docs/runner.md`.
- **Native load engine.**
  - Runs in a separate worker process and needs an explicit authorization acknowledgement.
  - Workloads: open, closed and fixed-iteration.
  - Reports: HDR percentiles, balanced ledgers, generator health, comparison, and exports.
  - Locking the app stops the run and keeps a partial report.
  - See `docs/load.md`.
- **Real-gateway failure lab.**
  - 8 profiles (core, policy, admission, drain, tls, auth, streams, cpdp) drive a pinned gateway binary with controllable fixtures: v0.9.7 by default, v0.9.5 with `--release v0.9.5`.
  - Ground truth is independent of the diagnosis.
  - Every scenario runs twice: trusted, and with the gateway untrusted.
  - See `docs/lab/`.
- **Release engineering.**
  - CI covers macOS, Linux and Windows.
  - The release workflow produces draft releases with SBOMs, a license report, `SHA256SUMS`, `release-evidence.json`, and a check that release artifacts contain no WebDriver server or test hooks.
  - See `docs/ci.md` and `docs/release.md`.
- **Samples.** A portable sample workspace and saved sample run/load reports in `samples/`.
- **Measured resource budgets.** See `docs/performance.md`.

## Executed verification (macOS arm64 unless stated)

Exact commands are in `docs/release.md` → "Local verification record".

| Check | Result |
|---|---|
| `cargo fmt --check`, `cargo clippy --workspace --all-targets -D warnings` | clean |
| `cargo test --workspace --exclude anvil-desktop` | 66 test binaries, 433 passed, 0 failed, 0 ignored |
| Renderer (`tsc`, `vitest`) | clean; 24 passed |
| Native desktop E2E (WebdriverIO, real app, real engine, core lab gateway) | 9 spec files, 18 tests passed, on both the debug and release-profile e2e builds |
| `anvil-lab [--release v0.9.5] run all --untrusted-pass` | v0.9.7 and v0.9.5 each: 314 passed, 0 failed, 15 skipped with stated reasons |
| Release check on the production `.app`, `.dmg`, raw binary and CLI, with runtime probe | pass. The e2e build fails as required. |
| Plaintext-at-rest audit (profile files, WAL/SHM side files, temp files) | no leak |
| `cargo deny`, license inventory, `gitleaks` over the branch | clean |
| CI (PR #1) | Linux: Rust, E2E and lab lanes pass. macOS: all lanes pass. Windows: first runs failed on platform-specific test issues. Fixes are pushed; see the PR checks for the current state. |

### Failure matrix (182 seed cases)

`docs/verification/matrix-coverage.md` is generated from test names, lab
results and reasoned statuses.

- **172 cases have executed evidence:**
  - 96 live against the real gateway;
  - 75 automated tests;
  - 1 executed release check.
- **6 are blocked:**
  - TRUST-009/010/011 need the G01 gateway detail API, which no gateway release has.
  - REL-001/003/006 need signed installers, an updater and published assets.
- **2 are not applicable:**
  - TRUST-012: Anvil does not correlate gateway logs.
  - LOAD-012: the optional JMeter adapter was not built.
- **2 are partial:** REL-007/008, website navigation and feature truth. They are staged in the website PR and cannot be published before a release.
- **UP-017 (port exhaustion) and UP-019 (trust withdrawn)** are covered by public-signal contract tests only. Live reproduction needs a gateway dial hook or a mesh/HBONE lab.

## Defects found and fixed during verification (selection)

- History retention deleted stored attachments (datasets, binary bodies, spec sources) on the next send.
- An OIDC login page reached through a redirect was reported as an API success.
- Load reports showed `0 µs` percentiles when no send succeeded.
- A backend's own connection close after a full request write was classified as a write failure, and the retry rule blocked a safe GET retry.
- Anvil's own HTTP/2 frame rejections were reported as a peer GOAWAY.
- WebSocket closes started by Anvil were blamed on the peer.
- The release check could not open license-agreement DMGs.
- Lab expectations that claimed a leg for `backend_error` were corrected.

## Known limitations and unimplemented features

- **No signed release.** There are no installers, notarization, updater or download assets. The website says "not yet released". Owner steps: ferrum-edge/ferrum-anvil#2.
- **Platforms.** Only macOS arm64 was built and exercised locally. Linux and Windows are covered by CI only. No minimum OS versions have been established.
- **G01 is not implemented** in the gateway, so gateway attribution never exceeds "likely".
- **Social sign-in is unavailable.** Google, GitHub and Facebook stay explicitly unavailable until the owner registers the apps and runs an identity broker. See `docs/identity.md` and ferrum-edge/ferrum-anvil#3.
- **Protocol and load gaps:**
  - WebSocket over HTTP/3 relies on a vendored `h3` 0.0.8 carrying one upstream commit (hyperium/h3#236) until an `h3` release includes it (`vendor/README.md`).
  - Load testing is HTTP-family only, one worker on one machine.
  - HTTP/3 has not been exercised under load.
  - gRPC-Web carries only unary and server streaming (the protocol's limit) and cannot use server reflection; gRPC over HTTP/3 opens a fresh QUIC connection per call.
  - See `docs/protocols.md` §5.
- **XML signing.** Anvil does not sign XML. AUTH-030/031 run live with lab-signed fixtures, which Anvil sends verbatim.
- **Ferrum Edge 0.9.5 and 0.9.7 only.** Other gateway versions have no catalog and are not validated. Several 0.9.7 changes are source-audited but not reproduced live (Gateway API route timeouts, Redis quota counting, the WAF `fail_closed` disposition; see `docs/audit/gateway-0.9.7-delta.md`). The gateway relays plain-HTTP/2 trailers inconsistently in the lab (both releases).
- **Measurements.** Resource numbers come from one machine. Webview helper processes and cold start are not measured.

## Reproducing

```bash
cargo build --workspace
lab/scripts/fetch-gateway.sh                     # pinned Ferrum Edge release, checksum-verified
cargo run -p anvil-lab -- run all --untrusted-pass
lab/scripts/fetch-gateway.sh v0.9.5              # the earlier supported release
cargo run -p anvil-lab -- --release v0.9.5 run all --untrusted-pass
(cd apps/desktop && npm ci && npm run e2e:build && npm run e2e)
```
