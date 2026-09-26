# Failure lab: `streams` and `cpdp` profiles

These two profiles run Anvil's shared engine against the **real, pinned Ferrum Edge v0.9.5
release binary**. They do not use mocks of the gateway.

- `streams` sends every protocol Anvil advertises *through* the gateway: HTTP/1.1, HTTP/2
  (TLS and h2c), HTTP/3 on the gateway's QUIC listener, WebSocket bootstraps, gRPC (over
  HTTP/2 and HTTP/3), gRPC-Web (binary and text, through the `grpc_web` plugin and a
  pass-through route), SSE, and the TCP, TCP+TLS, UDP and DTLS stream proxies.
- `cpdp` runs a real control plane (CP, SQLite) and real data planes (DP). It creates
  genuine stale-configuration fences (matrix GW-005).

Every scenario records four things. The **stimulus**. The **public evidence** Anvil saw,
and what it concluded (findings, scope, confidence ceiling, forbidden claims).
**Independent ground truth**, which is never passed to the engine: fixture logs, the
gateway operator log, and admin `/health`. And a **recovery** or positive-control request.
Where the plan requires one, a scenario also runs a **lookalike** that must *not* receive
the diagnosis.

Profile code: `crates/anvil-lab/src/{streams,cpdp,fixtures_streams,fixtures_cpdp}.rs`.
Gateway configuration: `lab/gateway/{streams.conf,streams.yaml,cpdp-*.conf,cpdp-seed-*.json}`.
Fixtures: `crates/anvil-fixtures/src/lab_streams.rs`, plus the existing HTTP, gRPC, stream,
DTLS and PKI fixtures.

## 1. Running

```sh
export PATH=/opt/homebrew/opt/rustup/bin:$PATH
# The pinned binary is verified against lab/gateway/RELEASE.lock before every run.
export ANVIL_LAB_FERRUM_BIN=/path/to/lab-bin/ferrum-edge-macos-aarch64   # or lab/bin/, ../lab-bin/
ulimit -n 4096

cargo run -p anvil-lab -- list streams                    # scenario ids and titles
cargo run -p anvil-lab -- run streams --untrusted-pass    # ~25 s
cargo run -p anvil-lab -- run cpdp --untrusted-pass       # ~50 s
cargo run -p anvil-lab -- run streams --scenario PROTO-014 --scenario UP-002-tcp
cargo run -p anvil-lab -- up streams                      # keep fixtures + gateway up (manual/desktop use)
cargo run -p anvil-lab -- up cpdp
```

- **Results** go to `results/lab/<UTC stamp>-<profile>/` (gitignored). That directory holds:
  - `summary.json`;
  - `<ID>.json` per scenario: checks, observed and recovery summaries, operator-log excerpts, and the skip reason;
  - `<ID>.record.json`: the full Anvil execution record of the main stimulus;
  - the gateway operator logs (`gateway-operator*.log`; for cpdp: the DP, the CP and the orphan DP).
- **Pass structure.** `--untrusted-pass` repeats every scenario with the destination *not*
  declared as a trusted Ferrum gateway. In that pass no `ferrum.token.*` or `ferrum.outcome`
  finding may appear. Markers must surface only as `ferrum.marker.unverified`.
- **Ports and binding.** Everything binds `127.0.0.1` inside the profile's block
  (`docs/audit/gateway-lab-config.md` §3). Each run renders its configuration and a fresh
  ephemeral PKI into `lab/.run/<instance>/`. The PKI is never installed into a trust store.
  Every started gateway process is stopped at the end, including after a failed run
  (`kill_on_drop`).
- **Blocked ports.** A profile cannot start while another process holds its ports. That
  includes another session's `up` of the same profile.

### Ports

| | streams | cpdp |
|---|---|---|
| Gateway | HTTP 18480 (h1 + h2c); HTTPS 18443/tcp and HTTP/3 18443/udp; admin 18490; stream listeners 18401–18409 | CP admin 18790, CP gRPC 18795; DP HTTP 18780, admin 18791; orphan DP HTTP 18770, admin 18771 (its CP URL 18799 is left unbound) |
| Fixtures | 19401 WS echo, 19402 gRPC (h2c; also answers gRPC-Web for `application/grpc-web*` requests), 19403 HTTP echo, 19404 TCP reply-after-half-close, 19405 UDP echo, 19406 UDP silent, 19407 UDP drop-every-other, 19408 TCP echo, 19411 TLS echo (lab CA), 19412 gRPC that holds its headers for 4 s, 19413 SSE, 19414 TLS echo (untrusted CA), 19416 SSE that aborts mid-stream, 19417 HTTPS h2 backend, 19420 TCP-only relay to 18443. **Unbound on purpose:** 19409 (gRPC down) and 19410 (TCP refused). | 19701 HTTP echo; 19795 DP→CP relay (can be cut) |

## 2. `streams` scenarios

"Trusted" is the default pass. Every row also runs untrusted, and must then make no gateway
attribution. Every row passed in every run of the final stability batch (§5).

| Scenario | Matrix | What it proves |
|---|---|---|
| CTRL-STREAMS | control | HTTP/1.1 through the gateway succeeds. The backend receives the request and the operator log records 200. The gateway advertises `Alt-Svc: h3=":18443"`. This is not proof of a QUIC listener: PROTO-006 is. |
| PROTO-001 | PROTO-001 | Two sequential HTTP/1.1 requests. The second is recorded as `reused` with `prior_requests ≥ 1` and the `reused_connection` warning. No fresh DNS/TCP timing is invented. Ground truth: the same local socket address, and the gateway logged both requests. |
| PROTO-002 | PROTO-002 | h2 over verified TLS end to end. The upstream leg is also HTTP/2 (an h2 TLS backend). **Observed:** Ferrum 0.9.5 does not relay the backend's plain-HTTP/2 response trailers, even with `TE: trailers`, while gRPC trailers are relayed. Anvil reports exactly what arrived and invents no trailers. The direct-to-backend control proves Anvil preserves `x-checksum`/`x-fixture-complete` after a complete body. |
| PROTO-005 | PROTO-005 | h2c prior knowledge sent to the gateway's **TLS** port fails as `exchange.protocol_error`, `exchange.closed_before_response` or `exchange.write_failed`, depending on timing. The TLS phase is `not_applicable`. There is no `client.tls.*` claim and no `exchange.h2_goaway` (see fix 1 in §4). Recovery: h2c on 18480 works. Ground truth: the gateway's upstream leg stayed HTTP/1.1 (per-leg protocols differ). |
| PROTO-006 | PROTO-006 | Forced HTTP/3 to 18443/udp. One attempt, ALPN `h3`, verified. A completed `quic_handshake` phase, connect `not_applicable`, no TCP-TLS phase. The response is HTTP/3. The backend received the request that the gateway relayed from QUIC. |
| PROTO-007 | PROTO-007 | Forced HTTP/3 over a UDP-blocked path: the TCP-only relay 19420, with no QUIC behind it. The result is a `quic_handshake_timeout` in a single attempt, with `client.quic.handshake_timeout`. Ground truth: the TCP path saw **no** connection, so there was no silent TCP fallback. Recovery: forced H3 directly on 18443. |
| PROTO-008 | PROTO-008 | H3-with-fallback over the same path. Two attempts are recorded: a failed H3 attempt, then `protocol_fallback{from:h3}`. The final response is not HTTP/3, with `client.h3.fallback_used` and the `protocol_fallback` warning. The fallback really travelled TCP to the gateway (relay and operator log). Contrast: the same policy on 18443 uses H3 in one attempt. |
| PROTO-009 | PROTO-009 | WebSocket over HTTP/1.1 Upgrade through the gateway. The backend's Close 1000 is relayed: `closed_by` is peer, the finding is `ws.closed_normally`, and the transport completed. No `exchange.*` fault. Echo order is kept. |
| PROTO-009-client-close | PROTO-009 | The backend never closes, so Anvil ends the session (1000, `closed_by` client). The finding must **not** say the peer closed it (fix 2 in §4). |
| PROTO-010 | PROTO-010 | The backend drops TCP without a Close frame. **Observed:** the gateway sends its own Close **1002 "protocol error"**, which answers the audit's open question. Anvil reports a peer close that is not normal and not a success. It keeps the message sent before the drop, and does not pin the close on the application (fix 3 in §4). Recovery: a normal session. |
| PROTO-012 | PROTO-012 | RFC 8441 extended CONNECT over h2 (TLS, 18443) and h2c (18480): method CONNECT, protocol h2, a 200 bootstrap, echo, and Close 1000. Ground truth: the gateway re-originated both sessions to the backend as HTTP/1.1 Upgrade (`GET /ws`), never CONNECT. |
| PROTO-013 | PROTO-013 | WebSocket over HTTP/3 (RFC 9220) to the gateway's QUIC listener. Anvil waits for the gateway's `SETTINGS_ENABLE_CONNECT_PROTOCOL`, sends `CONNECT` with `:protocol = websocket`, gets 200, and the echo and the backend's Close 1000 come back over QUIC (ALPN `h3`, no TCP phase). Ground truth: the gateway's operator log records "H3 WebSocket (RFC 9220) upgrade request received", and it re-originates the session to the backend as an HTTP/1.1 Upgrade (`GET /ws`). |
| PROTO-013-blocked | PROTO-013 | The same session to the TCP-only relay (no UDP): a `quic_handshake_timeout` in one attempt, nothing dispatched, and no fallback: the relay sees no TCP connection and the backend no session. Recovery over the real QUIC listener succeeds. |
| PROTO-014 | PROTO-014 | Application error status: HTTP 200 with `grpc-status 5` in trailers. The transport completed, but the RPC failed (`app.grpc_status`), with no gateway token. Ground truth: the backend returned it. |
| PROTO-014-down | PROTO-014 (UP-002 on gRPC) | The gRPC backend is down (19409 unbound). **HTTP 200 trailers-only** `grpc-status 14`, `grpc-message: Backend unavailable`, and **no `X-Gateway-Error`**. That is an RPC failure. Anvil does not claim which component authored a trailers-only status, and makes no client-leg connect claim. Operator `error_class` is `connection_refused`. |
| PROTO-015 | PROTO-015 | The backend replies once, then resets before any status. The gateway resets the client stream: the status is `missing`, the transport `incomplete`, the application never a success, and `app.grpc_status_missing` is emitted. The message before the reset is kept. |
| PROTO-016 | PROTO-016 | Unary, server-streaming (3), client-streaming (3→1) and bidirectional (2→2) over h2c, plus unary over grpcs (verified, ALPN h2). Message boundaries are exact. The backend saw all four methods. |
| PROTO-016-deadline | PROTO-016 | A 300 ms client deadline on a 5 s stream. The call is ended either by Anvil's own deadline (`total_timeout`, `deadline_ms` 300) or by the gateway enforcing the forwarded `grpc-timeout` (`RST_STREAM` after DATA, no trailers). The status is **missing**, not an invented DEADLINE_EXCEEDED. The partial messages are kept. Ground truth: the gateway forwarded `grpc-timeout` to the backend. |
| UP-010-grpc | UP-010 (gRPC), PROTO-016 | The backend holds its headers for 4 s against the gateway's 1 s read timeout. The gateway answers **HTTP 200 trailers-only `grpc-status 4` "Backend deadline exceeded"**. Anvil reports an RPC failure with no local deadline and no token. Operator `error_class` is `read_write_timeout`. |
| PROTO-016-h3 | PROTO-016 (HTTP/3) | Native gRPC over **HTTP/3** to the QUIC listener (`grpcs://127.0.0.1:18443`, forced HTTP/3): unary, server streaming (3), client streaming (3→1) and bidirectional (2→2), each in one attempt with `grpc-status 0` from the **HTTP/3 trailers** and exact message boundaries. ALPN `h3`, verified, completed `quic_handshake`, connect `not_applicable`, no TCP-TLS phase. Ground truth: the backend received all four calls as native `application/grpc`, and the operator log shows the cleartext backend target (`http://127.0.0.1:19402/...`): the gateway bridged HTTP/3 to its h2c gRPC pool. |
| PROTO-014-h3 | PROTO-014 (HTTP/3) | HTTP 200 over HTTP/3 with `grpc-status 5` in the HTTP/3 trailers: transport completed, RPC failed, `app.grpc_status`, no token. Recovery: the same call without `failWith`. |
| PROTO-014-h3-down | PROTO-014-down (HTTP/3) | The `grpc-down` route (backend 19409 unbound) over HTTP/3: the gateway answers a genuine **trailers-only** HTTP/3 response, HTTP 200 with `grpc-status 14` and `grpc-message: Service unavailable` in the response headers (over HTTP/1.1 and HTTP/2 the same condition reads "Backend unavailable"). Anvil reports source `trailers_only`, no HTTP/3 trailers, an RPC failure of unknown origin and no connect claim. Operator `error_class` is `connection_refused`. |
| PROTO-016-h3-blocked | PROTO-007 (gRPC) | Forced gRPC over HTTP/3 to the TCP-only relay 19420: `quic_handshake_timeout` in one attempt, nothing dispatched, no response and no gRPC status claimed, `client.quic.handshake_timeout`, no `app.grpc*` finding. Ground truth: the relay saw **no** TCP connection and the backend no call. Recovery: forced HTTP/3 on 18443. |
| PROTO-016-h3-fallback | PROTO-008 (gRPC) | HTTP/3-with-fallback on the same path: two attempts, the failed HTTP/3 one (`not_dispatched`) and `protocol_fallback{from:h3}` over HTTP/2 (TLS, ALPN `h2`), `grpc-status 0`, `client.h3.fallback_used` and the `protocol_fallback` warning. Ground truth: the fallback travelled the relay and the backend was called **exactly once**. |
| GRPCWEB-001 | gRPC-Web | Binary gRPC-Web through the `grpc_web` plugin (`/grpcweb` → h2c backend): unary and server streaming (3) over HTTP/1.1 (18480), unary over HTTP/2 over verified TLS (18443). Each: `grpc-status 0` from the **trailer frame**, `application/grpc-web+proto`, exact boundaries, no `grpc_web.*` finding, no token, no translation claim. Ground truth: the backend received native `application/grpc` (the gateway translated). |
| GRPCWEB-002 | gRPC-Web | Text gRPC-Web (base64 both ways) through the plugin: unary and server streaming over HTTP/1.1, unary over **HTTP/3** (QUIC checks as in PROTO-006). The captured body is base64 text, decoded incrementally. Ground truth: the backend received native `application/grpc` for the HTTP/1.1 and HTTP/3 calls. |
| GRPCWEB-003 | gRPC-Web, PROTO-014 | The backend's native `grpc-status 5` reaches the client as **HTTP 200 + trailer frame `grpc-status: 5`** (binary, HTTP/1.1); text mode over HTTP/2: two messages, then `grpc-status 9` in the trailer frame. RPC failure, `app.grpc_status`, no missing-status or framing claim. |
| GRPCWEB-down | gRPC-Web, UP-002 | Plugin route to the unbound 19409: **HTTP 200 + a gateway-authored trailer frame** `grpc-status: 14`, `grpc-message: Backend unavailable` (`Content-Length` 57, `x-grpc-web: 1`). Valid framing, an RPC failure of unknown origin (no connect claim, no "which component" claim). Operator `error_class` is `connection_refused` (read after the streamed body is logged). |
| GRPCWEB-lookalike | gRPC-Web (lookalike) | The same gRPC-Web request to `/grpcweb-raw`, the same backend **without** the plugin, over HTTP/1.1, HTTP/2 and HTTP/3. Ground truth: the backend received `application/grpc-web+proto` with `x-grpc-web: 1`, i.e. untranslated (and answered gRPC-Web itself), while the translating control received `application/grpc`. Anvil makes **no translation claim** either way. **Observed on v0.9.7:** over HTTP/1.1 and HTTP/2 the gateway appends its own synthesized trailer frame `grpc-status: 2` after the backend's `grpc-status: 0` frame (the body is 11 + 21 + 21 bytes, and the operator log records `grpc_status: 2` for all three calls); over HTTP/3 the body passes through unchanged. Anvil reports the appended frame as `grpc.framing_invalid` ("a second trailer frame (grpc-status 2) followed the first (grpc-status 0)"), with the HTTP body complete and the call not a success. The check accepts either a clean pass-through or this invalid framing, and records which. |
| GRPCWEB-refused | gRPC-Web | Client streaming over gRPC-Web is refused before traffic: `unsupported_combination` in the prepare phase, field `grpc.wire`, with the reason; `not_dispatched`. Ground truth: neither the gateway nor the backend saw a request. |
| PROTO-018 | PROTO-018 | SSE events, then an explicit cancel at 500 ms. The transport is `canceled` with `sse.canceled`, and no finding contains "timeout". Ground truth: the gateway forwarded `Accept: text/event-stream` and `Last-Event-ID`. Recovery: a complete 3-event stream. |
| PROTO-018-idle | PROTO-018 | One event, then silence past the 800 ms idle limit. The stream is `closed_by timeout` with `sse.idle_timeout`. It is not a cancel, and there is no confirmed failure claim. |
| TRUST-007-sse | TRUST-007, UP-011 | The backend aborts its event stream after 3 events. Through the gateway, HTTP 200 turns into an **incomplete** abnormal end. Anvil does not report success, keeps the events, and makes no retrospective gateway-error claim (the status stays 200). |
| PROTO-019 | PROTO-019 | TCP half-close through the stream proxy. 5 bytes are sent, then FIN. The reply arrives after the half-close, followed by the peer's FIN, and `tcp.reply_after_half_close` is emitted. Ground truth: the backend read exactly 5 bytes, then EOF (FIN propagated). |
| PROTO-019-echo | PROTO-019 (TCP row, §7) | A newline-framed echo through the stream proxy. Anvil stops at `expect_frames`. |
| PROTO-019-tls | PROTO-019 (TCP/TLS row, §7) | TLS is terminated at the gateway (verified against the lab root) and re-originated as **tcps** to a TLS echo that the gateway verifies. The frames are echoed. |
| UP-002-tcp | UP-002 (L4) | The TCP proxy's backend is refused. The gateway accepts the client and then resets it without data. Anvil reports `tcp.closed_without_data` (new finding; fix 4 in §4), and the client's own connect is shown as completed. There is no `client.connect.*` or `client.tls.*` claim. Operator `error_class` is `connection_refused`. |
| UP-004-tcps | UP-004 (L4 lookalike) | The client's TLS to the gateway **verifies**. Then the gateway's tcps leg rejects an untrusted backend certificate and closes without data. Anvil must not blame the client TLS leg. Operator `error_class` is `tls_error`. Recovery: the trusted tcps route. |
| PROTO-020 | PROTO-020 | UDP to a silent backend. The result is only `udp.no_response`, which states that it proves neither delivery nor an outage. Dispatch is `may_have_been_sent`. Ground truth: the backend *did* receive the relayed datagram. |
| PROTO-021 | PROTO-021 | UDP where every other reply is dropped: 4 sent, 2 received, with per-datagram boundaries. The finding is `udp.partial_responses`, with no confirmed loss claim. |
| PROTO-022 | PROTO-022 | DTLS terminated at the gateway (18405). A completed `dtls_handshake`, verified, no TLS-adapter phase, and echo. The plain UDP backend received the decrypted datagram. |
| PROTO-022-wrong-root | PROTO-022 | The client trusts the wrong root. The failure is a client-side `tls_untrusted_issuer` in `dtls_handshake`, with nothing dispatched and no datagram at the backend. Recovery: the correct root. The wrong-*client-identity* leg (DTLS client CA) belongs to the `tls` profile. |

## 3. `cpdp` scenarios: genuine stale fences

- **Setup.** `start()` wipes the CP's SQLite file and starts the CP (`-m cp`). It seeds the
  route `/cpdp/echo → 19701` and a global `stdout_logging` plugin through the CP **Admin
  API**, using an HS256 admin JWT minted from a per-run secret. It then starts the DP
  (`-m dp`). The DP has no local routes. It serves `/cpdp/echo` only after applying the
  CP's snapshot.
- **The DP→CP path.** The DP reaches the CP gRPC port only through a lab TCP relay
  (19795 → 18795). This lets the lab partition a DP from a CP that keeps running.
- **Fresh snapshots.** Before each fence, the scenario publishes a new route through the CP
  (a "tick") and waits until the DP serves it. The DP's last-applied snapshot is then known
  to be fresh. The fence must appear only once `FERRUM_DP_CONFIG_MAX_STALE_SECONDS` (5 s)
  has elapsed since that snapshot.

| Scenario | Matrix | Stimulus | What it proves |
|---|---|---|---|
| CTRL-CPDP | control | GET `/cpdp/echo/` on the DP | The CP-delivered route works. Ground truth: DP `/health` is ready, and the route exists only in the CP database. |
| GW-005-lookalike | GW-005 (lookalike) | The backend returns 503 with the fence's exact body and tries to set `X-Gateway-Error: config_stale` | The gateway replaced the backend's marker with `backend_error`. Anvil does **not** diagnose a stale fence: no `config_stale` finding, no catalog match, no confirmed "stale" claim. Ground truth: the backend produced the 503, and the DP is ready. |
| GW-005-partition | GW-005 | A fresh snapshot, then the DP→CP relay is **cut** (connections torn down and new ones closed at accept). The CP keeps running. | **Inside** the window the DP answers 200 and shows nothing: no marker, no finding. The fence appears ≈5.0 s after the snapshot, never earlier. Public evidence: 503, `X-Gateway-Error: config_stale`, and `{"error":"Gateway configuration stale"}`. Trusted: `ferrum.token.config_stale` at **likely** (plain HTTP, and the marker is backend-spoofable on 0.9.5), scope `gateway_admission`, with a "changing the payload will not help" statement. No client, auth or crash claim. Ground truth: the refused request never reached the backend, DP `/health` is `unavailable`, CP `/health` is **ready**, and the DP log says `stale beyond the configured bound … new_traffic_blocked:true`. Recovery: heal the relay, and the DP serves again (≈2.5 s). |
| GW-005 | GW-005 | A fresh snapshot, then the CP is **killed** (SIGKILL, like a crash) | As for the partition. Also: the CP admin port refuses. **The public signal is byte-identical to the partition's** (status, marker, header set, body), so different root causes get indistinguishable, cautious explanations. Recovery: restart the CP on the same database; the DP reconnects and re-applies (≈2.5–3.6 s). |
| GW-005-orphan | GW-005 | A DP whose CP address (18799) never had a listener | Before its bound (4 s), the config-less DP answers **404**. To the client that is a plain route miss (`http.not_found`, no stale claim), and it reveals nothing about missing configuration. After the bound: the same stale 503 and marker, with the fence produced without any CP ever being authoritative. Ground truth: orphan `/health` is unavailable, nothing listens on 18799, and the orphan log has the stale line. No recovery exists by design; the positive control is that the CP-backed DP still serves. |

**What the DP exposes to a client, and what it does not** (checked in every fence scenario):

- **Exposed:** only the 503, the `config_stale` token and the fixed body. The fence runs
  before routing, so any path gets it.
- **Not exposed:** a `Retry-After`, the snapshot age, the bound, the CP's identity, or
  whether the CP crashed, was partitioned, or never existed. There is also no `Via`: the
  request never reached the proxy path.
- **Only in operator evidence:** DP `/health` (`unavailable`, `ready:false`) and the DP's
  WARN log line (`reason: snapshot_stale`, `snapshot_age_seconds`, `max_stale_seconds`).

## 4. Diagnostics fixes found by these runs

1. **A locally detected HTTP/2 error was reported as the peer's GOAWAY**
   (`crates/anvil-transport/src/errors.rs`).
   - **Symptom.** In PROTO-005, h2c to a TLS listener: Anvil's h2 library read the TLS alert
     as an oversized frame and raised a *library* GOAWAY (FRAME_SIZE_ERROR). The transport
     typed that as `H2GoAway`, and the finding said "the server is closing the HTTP/2
     connection".
   - **Fix.** Only a GOAWAY or RST_STREAM whose initiator is the remote peer
     (`h2::Error::is_remote`) maps to `H2GoAway`, `H2StreamReset` or `H2RefusedStream`.
     Locally detected errors are `HttpProtocolError`, which yields `exchange.protocol_error`.
   - **Tests.** A new test,
     `http_evidence::proto_005_h2c_against_a_tls_listener_is_a_protocol_mismatch_not_a_peer_goaway`.
     The existing h2c test no longer accepts `H2GoAway`.
2. **`ws.closed_normally` always said "The peer closed the session"**, even when Anvil
   closed it (a user close, or an automation idle close). The same was true for 1008 in
   `ws.closed_policy`.
   - **Fix.** The rule now passes `{closer}` from `closed_by`: "The peer", "Anvil", and
     so on. The catalog wording uses it.
   - **Tests.** `a_normal_close_names_who_closed` and
     `a_scripted_policy_close_is_not_attributed_to_the_peer`; the live check is
     PROTO-009-client-close.
3. **`ws.closed_other` had no alternatives.** Through Ferrum, a backend's silent drop
   becomes a gateway-authored 1002.
   - **Fix.** The wording now leaves open which hop authored the Close.
   - **Tests.** `a_peer_close_leaves_open_which_hop_authored_it`; the live check is PROTO-010.
4. **A TCP session closed or reset by the peer before any data produced no finding**, or an
   unexplained `tcp.closed_abnormally`. L4 gateway setup failures look exactly like this.
   - **Fix.** A new finding, `tcp.closed_without_data`, reports it (confirmed observation,
     client-to-peer scope). It says the client's own setup completed and that layer-4
     proxies cannot say why they closed, lists upstream/policy alternatives, and points to
     operator logs. `tcp.closed_abnormally` now fires only after data was received, and
     gained alternatives and `does_not_prove` statements.
   - **Tests.** `a_tcp_close_without_any_data_is_explained_without_blaming_the_client_leg`
     and `a_reset_after_data_stays_an_abnormal_end_and_ordinary_ends_are_silent`; the live
     checks are UP-002-tcp and UP-004-tcps.

Catalog version: `2026.09.25-3` (`catalog/diagnostics/findings.en.json`).

## 5. Stability

Consecutive runs with `--untrusted-pass` on 2026-09-25 (macOS arm64, Ferrum Edge v0.9.5,
sha256 `6a531f2c…`). The counts are harness totals: the trusted pass, the untrusted pass,
and PROTO-013 skipped once. A streams run takes about 24 s and a cpdp run about 47 s.

After RFC 9220 support was added, three more consecutive streams runs gave 62 passed,
0 failed, 0 skipped each (31 scenarios × 2 passes).

After gRPC over HTTP/3 and gRPC-Web were added (Ferrum Edge **v0.9.7**, sha256
`f3bd0027…`, 2026-09-26), three consecutive `run streams --untrusted-pass` runs gave
**84 passed, 0 failed, 0 skipped** each (42 scenarios × 2 passes, about 30–40 s per run), with
no `ferrum.*` finding in any untrusted record. The GRPCWEB-lookalike observation (an appended
`grpc-status: 2` trailer frame over HTTP/1.1 and HTTP/2, none over HTTP/3) was the same in
every run. An earlier batch had one failure in three runs: UP-002-tcp read the operator log
before the gateway had written the stream's transaction line (the line was present a moment
later). The `error_class` checks of UP-002-tcp, UP-004-tcps, PROTO-014-down and UP-010-grpc
now wait up to 3 s for the line, as the new gRPC-Web and HTTP/3 scenarios do.

| Run | streams (29 × 2 + 1 skip) | cpdp (5 × 2) |
|---|---|---|
| 1 | 58 passed, 0 failed, 1 skipped | 10 passed, 0 failed |
| 2 | 58 passed, 0 failed, 1 skipped | 10 passed, 0 failed |
| 3 | 58 passed, 0 failed, 1 skipped | 10 passed, 0 failed |
| 4 | 58 passed, 0 failed, 1 skipped | — |
| 5 | 58 passed, 0 failed, 1 skipped | — |

An earlier batch of three streams runs had one failure in each run. Two scenarios have
legitimate race outcomes, and their checks were initially too narrow:

- **PROTO-016-deadline.** Anvil and the gateway enforce the same 300 ms `grpc-timeout`.
  Twice, the gateway won and reset the stream after DATA (`RST_STREAM INTERNAL_ERROR`, no
  trailers). The status is missing either way.
- **PROTO-005.** Once, the TLS listener closed the connection while the h2c preface was
  still being written (`exchange.write_failed`).

Both checks now accept every truthful outcome. They still forbid a TLS claim, a peer-GOAWAY
claim, and an invented `DEADLINE_EXCEEDED`. Each run records which path was taken. In the
five runs above, Anvil's own deadline fired first every time. PROTO-005 alternated between
`exchange.protocol_error` and `exchange.closed_before_response`.

## 6. Skips and limitations

- **PROTO-013 runs on a vendored `h3`.** `h3` 0.0.8 cannot send `:protocol = websocket`;
  the workspace carries the upstream fix (hyperium/h3#236) until a release includes it
  (`vendor/README.md`). Until that change, PROTO-013 was recorded as skipped.
- **Plain-HTTP/2 trailers through Ferrum.** 0.9.5 was observed not to relay them
  (PROTO-002). So the lab verifies Anvil's trailer preservation against the backend
  directly, and verifies through the gateway only that Anvil invents nothing. A cleartext
  h2c-capable backend is reached over HTTP/1.1 for non-gRPC traffic, which is why PROTO-002
  uses an h2 TLS backend.
- **gRPC and Ferrum markers.**
  - The gateway-authored gRPC rejects seen here (`14 Backend unavailable`,
    `4 Backend deadline exceeded`) carry no `X-Gateway-Error` on H1/H2. Anvil reports them
    only as RPC failures of unknown origin.
  - Keying a Ferrum catalog match on `grpc-status` plus the exact `grpc-message` (audit
    §11 item 5) is not implemented.
  - The gRPC variant of the stale fence (200 / 14 without a marker on H1/H2) is not
    exercised.
- **gRPC over HTTP/3 and gRPC-Web** (the PROTO-016-h3 … GRPCWEB-refused rows, 11 scenarios) were added
  against the pinned **v0.9.7** binary. Configuration: the `grpcweb-translated`,
  `grpcweb-passthrough` and `grpcweb-down` proxies and two proxy-scoped `grpc_web` plugin
  configs in `streams.yaml` (checked by `lint-profiles.rb` and the binary's `validate`).
  - **Pass-through gRPC-Web on v0.9.7 appends a trailer frame** over HTTP/1.1 and HTTP/2
    (GRPCWEB-lookalike). Without the plugin the request reaches the backend untranslated, as
    documented, but the gateway adds its own `grpc-status: 2` frame after the backend's
    complete gRPC-Web body; it also logs `grpc_status: 2` for these calls, including over
    HTTP/3 where the body is left alone. That looks like a gateway defect: a gRPC-Web client
    that stops at the first trailer frame sees status 0, one that reads on sees malformed
    framing. Anvil reports what is on the wire and claims nothing about translation.
  - The gRPC-Web routes have no marker to attribute: gateway-authored terminal statuses
    (`14 Backend unavailable`) arrive in the trailer frame with `x-grpc-web: 1` and no
    `X-Gateway-Error`, so Anvil reports RPC failures of unknown origin.
  - Not exercised: gRPC-Web through the native HTTP/3 backend path (the backend is h2c),
    gRPC-Web `+json`, request trailer frames, and `Accept`-negotiated mode switching.
- **gRPC client deadline wording.** A local gRPC deadline is typed as `total_timeout` with
  `deadline_ms`. The generic `response.body_total_timeout` wording then speaks of the
  "total deadline", when this was the gRPC deadline. The value is right, but the wording is
  generic.
- **Partition style.** The lab partition *rejects* DP→CP connections. In development, a
  black-hole relay was tried: it accepted TCP but never forwarded. With it, the 0.9.5 DP
  logged "Connected to CP" and did **not** fence for over 30 s, until the socket was
  dropped. Silent partitions may therefore go undetected by the DP for longer than
  `FERRUM_DP_CONFIG_MAX_STALE_SECONDS`. This is not a lab assertion.
- **Timing.**
  - The fence scenarios depend on the 5 s bound (the orphan's is 4 s) and on the DP's
    reconnect back-off. Recovery is polled for up to 90 s.
  - The orphan's early-404 check relies on the first request landing within 4 s of start.
- **Not covered here.**
  - PROTO-003/004 (H2 reset and GOAWAY via the gateway) and PROTO-011 (WS size limits via
    the gateway).
  - PROTO-017 (reflection through the gateway) and PROTO-023–025.
  - The DTLS client-certificate leg, which is in the `tls` profile.
  - Load or throughput through any of these protocols.
- **Harness evidence for extra requests.** Only the main stimulus of each scenario is saved
  as a full execution record. Lookalike, early-window and control requests appear as check
  details and as recovery summaries.
