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
| Gateway compatibility targets | Ferrum Edge v0.9.9 release binary (source `234717c`, the default pin, `lab/gateway/RELEASE.lock`), v0.9.8 (source `e27f210`, `lab/gateway/releases/v0.9.8.lock`), v0.9.7 (source `8fed134`, `lab/gateway/releases/v0.9.7.lock`) and v0.9.5 (source `20e7603`, `lab/gateway/releases/v0.9.5.lock`), each checksum-pinned; each has its own source-audited catalog |
| Gateway changes | G01, the authorized diagnostic reference, ships in Ferrum Edge v0.9.9 (`ferrum-edge/ferrum-edge#5767`; #5845, #5857/#5862 and #5868), and `ferrum-contracts` `contracts-edge-0.9.9` publishes its header and `ferrum.diagnostic_ref.v1` schema. Anvil looks references up for gateway profiles that configure the lookup; only a record bound to the response raises a finding above "likely". The contract is in `docs/g01-gateway-diagnostic-contract.md`; Anvil's use of it is in `docs/diagnostics.md`. |
| Published preview assets and checksums | The public `anvil-v0.1.1` release has downloadable CLI and desktop installers, `SHA256SUMS`, SBOMs and `latest.json` with minisign updater signatures. The installers are unsigned previews: platform code signing and notarization are still blocked on owner credentials, and the release workflow creates a draft an owner publishes by hand (see `docs/release.md`). |

## Implemented

- **Desktop app (Tauri 2 + React/TypeScript) and CLI (`anvil`).**
  - Both run on one Rust engine.
  - Typed IPC only and a strict CSP; the webview does no I/O.
  - The lock is enforced in the backend.
  - Architecture decisions are recorded in `docs/adr/0001–0011`.
- **Build and send.**
  - Workspaces with nested folders, saved requests with immutable revisions, environments, variables and history.
  - Effective-request preview.
  - Live lint.
  - Timing and sizes.
  - Protocols: HTTP/1.1, HTTP/2, h2c and HTTP/3 (forced or with fallback); WebSocket (HTTP/1.1, HTTP/2 and HTTP/3, with opt-in permessage-deflate); gRPC in four modes over HTTP/2 or HTTP/3; gRPC-Web (binary and text); SSE over HTTP/1.1, HTTP/2 or HTTP/3; TCP/TLS; UDP and DTLS, direct, through an HTTP/3 CONNECT-UDP (MASQUE) proxy or through a mesh HBONE datagram tunnel.
  - Opt-in 0-RTT early data (QUIC for HTTP/3, TLS 1.3 over TCP) for replay-safe methods, with `425 Too Early` handled per RFC 8470 and session tickets kept in memory only.
  - Mesh and edge features: HBONE tunnels (HTTP/2 CONNECT over mTLS) for TCP and, as Ferrum Mesh datagram tunnels, UDP and DTLS; SPIFFE ID or trust-domain server verification with X.509-SVID client identities (from files or a SPIFFE Workload API); SNI override; PROXY protocol v1/v2 headers (TCP/TLS and HTTP-family requests over TCP) and datagram envelopes (UDP/DTLS).
  - Interactive sessions for the session protocols.
  - See `docs/protocols.md`.
- **Auth and TLS.**
  - Auth types: API key, Basic, Bearer, JWT, OAuth 2.0 (client credentials, refresh, authorization code + PKCE in the system browser), Ferrum HMAC v2, DPoP, WS-Security UsernameToken, a verbatim user-supplied SAML assertion, JWT-SVID (from a SPIFFE Workload API, a file or a variable, checked locally before sending), and multi-auth.
  - Private CAs and mTLS with PEM or PKCS#12.
  - Verification is on by default; a bypass is scoped to a profile and warned about.
  - Auth is applied after final serialization, and the load engine reuses it unchanged.
- **Evidence-based diagnostics.**
  - Deterministic rules run over typed evidence.
  - Each finding has a confidence (confirmed/likely/unknown/conflicting), a scope (the leg it concerns), an owner, what it does not prove, alternatives and next steps.
  - Source-audited catalogs back the Ferrum-specific findings: 552 Ferrum Edge 0.9.9 outcomes, 540 Ferrum Edge 0.9.8 outcomes, 538 Ferrum Edge 0.9.7 outcomes and 528 Ferrum Edge 0.9.5 outcomes. A declared gateway uses the catalog of its own release; a release without a catalog gets no outcome matching and an explicit finding saying so.
  - Markers count only for declared gateways and are capped at "likely". The coarse `X-Gateway-Error` values (seven in 0.9.5 and 0.9.7; eight from 0.9.8 with `request_timeout`) are never refined into precise causes.
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
  - One load unit per protocol (LOAD-013): HTTP requests (HTTP/1.1, HTTP/2, HTTP/3 with separately counted fallback attempts), unary gRPC calls and server-streaming gRPC streams (native and gRPC-Web, pooled channels per virtual user), SSE streams, WebSocket sessions, TCP exchanges and UDP/DTLS exchanges, with typed denominators (status codes, messages, sessions, frames, datagrams sent vs received) and typed refusals for combinations without a unit.
  - Reports: HDR percentiles, balanced ledgers, generator health, comparison (never across protocols), and exports.
  - Locking the app stops the run and keeps a partial report.
  - See `docs/load.md`.
- **Real-gateway failure lab.**
  - 14 profiles (core, policy, admission, drain, tls, auth, streams, cpdp, h3x, mesh, proxyproto, workload, early, mcp) drive a pinned gateway binary with controllable fixtures: v0.9.9 by default, v0.9.8, v0.9.7 or v0.9.5 with `--release`. The mesh profile runs the gateway in mesh mode (HBONE for TCP and UDP, SPIFFE); h3x covers SSE over HTTP/3 and CONNECT-UDP (UDP and DTLS in the tunnel); proxyproto covers PROXY protocol listeners (TCP, UDP/DTLS, and HTTP listeners that do not expect a header); workload covers the SPIFFE Workload API (X.509-SVIDs and JWT-SVIDs); early covers TLS 1.3 / QUIC 0-RTT early data and `425 Too Early`; mcp covers MCP over Streamable HTTP through the gateway's `mcp_gateway` (allow, deny, hide, schema validation).
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
| `cargo test --workspace --exclude anvil-desktop` | 93 test binaries, 716 passed, 0 failed, 2 ignored (the real OS keychain round trip, run by CI on each OS; the Python `websockets` interop check) |
| Renderer (`tsc`, `vitest`) | clean; 78 passed |
| Native desktop E2E (WebdriverIO, real app, real engine, core lab gateway on Ferrum Edge 0.9.7) | 9 spec files, 18 tests passed (earlier also on the release-profile e2e build) |
| `anvil-lab [--release v0.9.5] run <profile> --untrusted-pass` (13 profiles) | v0.9.7 and v0.9.5 each: 530 passed, 0 failed, 19 skipped with stated reasons. This local record predates the v0.9.8 and v0.9.9 default pins; those releases are exercised by the nightly lab in CI, which runs every supported release. |
| Release check on the production `.app`, `.dmg`, raw binary and CLI, with runtime probe | pass. The e2e build fails as required. |
| Plaintext-at-rest audit (profile files, WAL/SHM side files, temp files) | no leak |
| `cargo deny`, license inventory, `gitleaks` over the branch | clean |
| CI (PR #1) | Linux and macOS: all lanes pass, including the OS credential store round trip. Windows: E2E passes; the Rust lane is re-running after fixes for Unix-only load-test helpers (see the PR checks for the current state). |

### Failure matrix (182 seed cases)

`docs/verification/matrix-coverage.md` is generated from test names, lab
results and reasoned statuses.

- **175 cases have executed evidence:**
  - 97 live against the real gateway;
  - 77 automated tests (TRUST-009/010/011, the G01 lookup cases, also run live in the `core` lab profile on v0.9.9);
  - 1 executed release check.
- **3 are blocked:**
  - REL-001/003/006 need signed installers, an updater and published assets.
- **2 are not applicable:**
  - TRUST-012: Anvil does not correlate gateway logs.
  - LOAD-012: the optional JMeter adapter was not built.
- **2 are partial:** REL-007/008, website navigation and feature truth. They are staged in the website PR and cannot be published before a release.
- **UP-017 (port exhaustion) and UP-019 (trust withdrawn)** are covered by public-signal contract tests only. UP-017 needs a gateway dial hook. UP-019 is mesh-only; the mesh lab now reproduces the unauthenticated-peer refusal, but not a trust withdrawal on a live tunnel.

## Defects found and fixed during verification (selection)

- History retention deleted stored attachments (datasets, binary bodies, spec sources) on the next send.
- An OIDC login page reached through a redirect was reported as an API success.
- Load reports showed `0 µs` percentiles when no send succeeded.
- A backend's own connection close after a full request write was classified as a write failure, and the retry rule blocked a safe GET retry.
- Anvil's own HTTP/2 frame rejections were reported as a peer GOAWAY.
- WebSocket closes started by Anvil were blamed on the peer.
- The release check could not open license-agreement DMGs.
- Lab expectations that claimed a leg for `backend_error` were corrected.
- On Windows, `anvil run` overflowed the 1 MiB main-thread stack in deep engine futures. The CLI, the load worker and the desktop runtime now run on large-stack threads.
- A first address that never answers (for example `::1` on a Windows host) used up the whole connect budget. Connects now use Happy Eyeballs (RFC 8305) and record superseded attempts as canceled.
- The lab's operator-log checks read a stream session's transaction line before the gateway had written it (it is written at teardown); they now wait for it.
- `anvil load run` never exited after a normal completion (the worker waited on stdin after its runtime was dropped).
- TLS session resumption never happened: rustls resumes only with the same verifier instance and Anvil built one per connection. Resumption is now used under the 0-RTT opt-in; other connections keep a full handshake.
- A `425 Too Early` from Ferrum Edge arrives after the gateway stops reading the request body, which Anvil reported as a write failure; the response is now read after a stopped HTTP/3 write.
- UDP and DTLS load units were initially unaware of the tunnels added in parallel; UDP/DTLS through HBONE is now refused for load like MASQUE, and pooled gRPC channels are keyed by the PROXY header plan.

## Known limitations and unimplemented features

- **Installers are unsigned previews.** The published `anvil-v0.1.1` release has CLI and desktop installers, `SHA256SUMS`, SBOMs and signed updater artifacts, but no platform code signing or notarization, so macOS Gatekeeper and Windows SmartScreen warn. The website says "not yet released". Owner steps: ferrum-edge/ferrum-anvil#2.
- **Platforms.** Only macOS arm64 was built and exercised locally. Linux and Windows are covered by CI only. No minimum OS versions have been established.
- **Confirmed gateway attribution needs the G01 lookup** (Ferrum Edge v0.9.9 and later, `ferrum-edge/ferrum-edge#5767`): it is off by default on the gateway (`FERRUM_DIAGNOSTIC_REFS`) and needs a dedicated `diagnostics:read` token with an `ns` claim in the gateway profile. Without both, or for a reference that expired, gateway attribution stays at "likely". Anvil looks a reference up only as the response arrives; there is no later re-lookup from the history view (see [diagnostics.md](diagnostics.md#gateway-diagnostic-references-g01)).
- **Social sign-in is unavailable.** Google, GitHub and Facebook stay explicitly unavailable until the owner registers the apps and runs an identity broker. See `docs/identity.md` and ferrum-edge/ferrum-anvil#3.
- **Protocol and load gaps:**
  - WebSocket over HTTP/3 relies on a vendored `h3` 0.0.8 carrying one upstream commit (hyperium/h3#236) until an `h3` release includes it (`vendor/README.md`).
  - Canceling an HTTP/3 stream while a read waits for data relies on a vendored `h3-quinn` 0.0.10 patched to stop the stream with the requested code (0.0.10 panicked; later releases defer the code, hyperium/h3#361) until an `h3-quinn` release applies it at once (`vendor/README.md`).
  - WebSocket permessage-deflate (opt-in) relies on a vendored tungstenite 0.30.0 with an Anvil-written codec patch until a tungstenite release has one (`vendor/README.md`). Ferrum Edge never negotiates it, so compressed sessions are proven against fixtures and Python `websockets`, and through the gateway only as "offered, not negotiated".
  - Load testing runs one worker on one machine. gRPC with server reflection, gRPC calls the engine refuses on every send (`grpc_unsupported_combination`), UDP through a MASQUE proxy while a proxy profile routes the request (`masque_through_proxy`), SSE with reconnection, requests with 0-RTT early data, HTTP/gRPC through HBONE in persistent mode, mixed-protocol plans and datagram plans that mix direct and tunneled exchanges are refused for load; there is no load action that holds sessions open while messages flow at a rate (see `docs/load.md`).
  - Not built, and not offered by Ferrum Edge either: double HBONE, HBONE over QUIC, CONNECT-IP and WebTransport; CONNECT-UDP over HTTP/2. PROXY headers are refused over HTTP/3 and through proxies.
  - The SPIFFE Workload API client's Windows named-pipe endpoint is implemented but only compiled and tested by CI; SPIRE itself is not in the lab (the Workload API is exercised against Ferrum Edge's dev-mode implementation and an independent fixture).
  - gRPC-Web carries only unary and server streaming (the protocol's limit) and cannot use server reflection; a manually sent gRPC call over HTTP/3 opens a fresh QUIC connection (load runs reuse pooled channels).
  - See `docs/protocols.md` §5.
- **XML signing.** Anvil does not sign XML. AUTH-030/031 run live with lab-signed fixtures, which Anvil sends verbatim.
- **Supported gateway releases: Ferrum Edge 0.9.5, 0.9.7, 0.9.8 and 0.9.9.** Each supports its own source-audited catalog; v0.9.9 is the default pin (`lab/gateway/RELEASE.lock`) and the nightly lab runs every supported release. Other gateway versions have no catalog and get no outcome matching. Several 0.9.7 changes are source-audited but not reproduced live (Gateway API route timeouts, Redis quota counting, the WAF `fail_closed` disposition; see `docs/audit/gateway-0.9.7-delta.md`). The gateway relays plain-HTTP/2 trailers inconsistently in the lab (observed on v0.9.5 and v0.9.7; not re-checked on later releases).
- **Gateway defects and gaps found by the lab** are filed upstream with source citations and reproductions: ferrum-edge/ferrum-edge#5758 (gRPC-Web pass-through gets an extra trailer frame), #5759 (backend-spoofable gateway markers), #5760 (HTTP/2 trailers dropped depending on dispatch path), #5761 (HTTP/3 0-RTT classification race), #5762 (route-timeout 504 labelled `backend_timeout`), #5763 (relay refusal 404 vs documented 403), #5764 (Workload API `ValidateJWTSVID` claims format), #5765 (HBONE UDP relay failures invisible), #5766 (Ambient registry default), and feature requests #5767 (gateway diagnostic contract, G01), #5768 (PROXY protocol on HTTP listeners), #5769 (WebSocket compression).
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
