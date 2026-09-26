# Failure lab: `h3x` profile (SSE over HTTP/3, CONNECT-UDP)

This profile runs Anvil's shared engine against the **real, pinned Ferrum Edge v0.9.7
release binary** (`lab/gateway/RELEASE.lock`). It exercises two HTTP/3 extensions through
the gateway's QUIC listener:

- **Server-sent events over HTTP/3.** The event stream is parsed from the HTTP/3 request
  stream's DATA frames as they arrive (`docs/protocols.md` §3.3).
- **RFC 9298 CONNECT-UDP (MASQUE).** UDP datagrams go through the gateway as HTTP
  Datagrams in an extended CONNECT tunnel (`docs/protocols.md` §3.8).

Every scenario records the stimulus, the public evidence and what Anvil concluded, and
independent ground truth: fixture logs and the gateway operator log. The ground truth is
never passed to the engine. Most scenarios also run a recovery request.

Profile code: `crates/anvil-lab/src/{h3x,fixtures_h3x}.rs`.
Gateway configuration: `lab/gateway/{h3x.conf,h3x-off.conf,h3x-noext.conf,h3x.yaml}`.
Fixtures: `crates/anvil-fixtures/src/lab_streams.rs` (`sse_abort`, `sse_flaky`, the TCP
relay), plus the HTTP and UDP stream fixtures.

## 1. Running

```sh
export PATH=/opt/homebrew/opt/rustup/bin:$PATH
export ANVIL_LAB_FERRUM_BIN=/path/to/lab-bin/ferrum-edge-macos-aarch64   # verified against RELEASE.lock
ulimit -n 4096

cargo run -p anvil-lab -- list h3x
cargo run -p anvil-lab -- run h3x --untrusted-pass     # ~27 s, 3 gateway processes
cargo run -p anvil-lab -- run h3x --scenario MASQUE-003
cargo run -p anvil-lab -- up h3x                       # keep fixtures + gateways up
```

Results go to `results/lab/<UTC stamp>-h3x/` as for the other profiles. The directory holds
`summary.json`, `<ID>.json`, `<ID>.record.json`, and the three operator logs
(`gateway-operator.log` for 18843, `-1` for 18844, `-2` for 18845). With `--untrusted-pass`
every scenario runs again with the gateway *not* declared as a trusted Ferrum destination.
In that pass no `ferrum.token.*` or `ferrum.outcome` finding may appear. For CONNECT-UDP,
trust follows the MASQUE proxy, which is the only HTTP peer.

Before every start the harness runs the real binary's `ferrum-edge validate` on each
rendered configuration (`lab/.run/h3x*/`). All three pass on v0.9.7.

### Ports

| | Ports |
|---|---|
| Gateway `h3x` (CONNECT-UDP on) | HTTP 18880, HTTPS 18843/tcp and HTTP/3 18843/udp, admin 18890 |
| Gateway `h3x-off` (CONNECT-UDP off, WebSocket over HTTP/3 on) | HTTP 18881, HTTPS + HTTP/3 18844, admin 18891 |
| Gateway `h3x-noext` (neither: no extended CONNECT) | HTTP 18882, HTTPS + HTTP/3 18845, admin 18892 |
| HTTP echo (control backend) | 19803 |
| SSE: `/sse` fixture, `sse_abort`, `sse_flaky` | 19813, 19816, 19817 |
| UDP echo, UDP silent (admitted MASQUE destinations) | 19805, 19806 |
| UDP echo that is **not** admitted | 19807 |
| TCP-only relay to 18843 (models a UDP-blocked path) | 19820 |

## 2. Gateway configuration

- `FERRUM_ENABLE_HTTP3 = true` binds QUIC on the HTTPS port.
- `FERRUM_HTTP3_CONNECT_UDP_ENABLED = true` on the main instance only. This is
  process-wide, so the gateway documentation recommends a **dedicated MASQUE route** and
  explicit `allowed_methods` on every other route. `h3x.yaml` does exactly that:
  - `h3x-masque` (`/.well-known/masque`) is the only route without a method filter;
  - its destinations come from the `h3x-udp-targets` upstream (19805, 19806);
  - `h3x-masque-get-only` shows the method policy refusing CONNECT.
- Destinations are **admitted, not load balanced**. The requested
  `target_host:target_port` must be one of the route's configured targets, else 403
  before any socket exists. The 403 body is identical for every refusal kind, so it
  discloses nothing.
- Ferrum Edge advertises `SETTINGS_ENABLE_CONNECT_PROTOCOL` when either WebSocket over
  HTTP/3 or CONNECT-UDP is enabled. It never negotiates `SETTINGS_H3_DATAGRAM`: HTTP
  Datagrams travel as DATAGRAM capsules on the CONNECT stream. That is why:
  - `h3x-off` still offers extended CONNECT and answers CONNECT-UDP with 501;
  - `h3x-noext` offers no extended CONNECT at all.
- `FERRUM_POOL_WARMUP_ENABLED = false`: the MASQUE route's backends are UDP sockets.

## 3. Scenarios

| ID | Stimulus | Anvil must conclude | Ground truth |
|---|---|---|---|
| CTRL-H3X | Forced HTTP/3 GET through 18843 | Success, h3 over verified QUIC, QUIC handshake measured, no TCP phase | Backend got the request; operator log 200 |
| PROTO-018-h3 | SSE `/sse?count=5&interval=60`, forced HTTP/3 | 5 events, `closed_by = peer`, success, one attempt recorded as HTTP/3; events spread over the backend's intervals (parsed as they arrive, not in one burst) | Backend saw `Accept: text/event-stream`; operator log 200 |
| PROTO-018-h3-idle | `count=2&interval=4000`, idle 800 ms | 1 event, `closed_by = timeout`, `sse.idle_timeout`, not a cancel, no confirmed failure claim | Recovery stream completes |
| PROTO-018-h3-cancel | Cancel after 500 ms | ≥ 3 events, `closed_by = client`, transport `canceled`, `sse.canceled`, no timeout finding | Recovery stream completes |
| TRUST-007-sse-h3 | Backend aborts after 3 events | 3 events kept, `closed_by = abnormal`, `body_reset` (the gateway resets the HTTP/3 stream with `H3_INTERNAL_ERROR`, code kept), transport `incomplete`, never success, status stays 200, no gateway token | Fixture applied `sse_abort_mid_stream` |
| PROTO-018-h3-reconnect | `sse_flaky` with reconnect on | Two attempts (abnormal end, then `retry`), each with its own QUIC handshake; events 1, 2, 3; clean peer end; success | Through the gateway the backend saw no `Last-Event-ID`, then `Last-Event-ID: 2` |
| PROTO-018-h3-blocked | Forced HTTP/3 SSE to the TCP-only path | One attempt, `quic_handshake_timeout`, nothing dispatched, no stream or response, no gateway finding | The TCP path saw no connection; the backend no request |
| MASQUE-001 | CONNECT-UDP to the echo, 3 datagrams | 3 sent, 3 received with per-datagram boundaries; 200; extended CONNECT on, `h3_datagrams = false`, encoding `capsule` (3 capsules each way); CONNECT to the RFC 9298 default template; no MASQUE/UDP problem finding; dispatch `sent` | Echo got 3 datagrams; operator log 200 and "tunnel established" |
| MASQUE-002 | To the silent target | Tunnel 200; 1 sent, 0 received; only `udp.no_response` (proves neither delivery nor an outage); no MASQUE finding; `may_have_been_sent`; not success | The silent target did receive the datagram through the gateway |
| MASQUE-003 | To 19807, not a configured destination | `masque_refused` 403, `masque.proxy_refused` (confirmed, scope forward proxy, the target only in "does not prove"), body kept (`…not an allowed destination…`), `not_dispatched`, application failure, no `udp.no_response` | 19807 (a live echo) received nothing; operator log 403 and `connect_udp_target_not_allowed` |
| MASQUE-004 | Template with `UDP` (case-sensitive literal) | Refused 400 with the body kept (`…does not expand the connect-udp URI template`) | Operator log 400 and `template_anchor_missing`; target untouched |
| MASQUE-005 | Template on the `allowed_methods: [GET]` route | Refused 405 (`{"error":"Method Not Allowed"}`), same refusal checks | Operator log 405 for `h3x-masque-get-only` |
| MASQUE-006 | To 18844 (CONNECT-UDP disabled) | Refused 501 with the body kept; the SETTINGS did enable extended CONNECT, so the request was legitimately sent | That gateway logged "profile not available on this gateway"; target untouched |
| MASQUE-007 | To 18845 (no extended CONNECT) | `masque_unsupported` before any request; `masque.extended_connect_unavailable`; QUIC phases measured; no response; `not_dispatched`; no UDP finding | That gateway logged no request; target untouched |
| MASQUE-008 | QUIC DATAGRAM frames required, 18843 | `masque_unsupported` before the request; `masque.no_datagram_support` with evidence `h3.settings.h3_datagram = not enabled` | The gateway logged no CONNECT-UDP request; target untouched. Recovery in `auto` mode uses capsules |
| MASQUE-009 | MASQUE proxy URL on the TCP-only path | One attempt, `quic_handshake_timeout`, nothing dispatched, no tunnel/response/UDP finding | No fallback: the TCP path saw nothing, the target nothing |
| MASQUE-010 | `dtls://` target with MASQUE | `unsupported_combination` in `prepare` (field `udp.masque`), `local.unsupported_combination`, nothing sent | The gateway saw no request; target untouched |

The harness adds its untrusted-pass checks on top: no `ferrum.token.*` and no
`ferrum.outcome` finding without a trusted profile. In the trusted pass, the 405 of
MASQUE-005 matches a catalog outcome (`ferrum.outcome`, capped at **likely**). The 501 of
MASQUE-006 yields `ferrum.marker.absent` (**unknown**). No CONNECT-UDP refusal carries
`X-Gateway-Error`.

## 4. Results

Three consecutive runs of `anvil-lab run h3x --untrusted-pass` on macOS aarch64 with
v0.9.7 (sha256 `f3bd0027…`): **34 passed, 0 failed, 0 skipped** each time (17 scenarios
× trusted and untrusted passes).

Observations about v0.9.7 that the scenarios rely on, each confirmed by the operator log
or the wire:

- HTTP/3 SSE through the gateway streams: events arrive about 60 ms apart as sent by the
  backend, not buffered.
- A backend abort after committed HTTP/3 headers becomes `RESET_STREAM(H3_INTERNAL_ERROR)`
  (0x102), never a clean FIN.
- CONNECT-UDP answers 200 with `capsule-protocol: ?1`. The gateway advertises extended
  CONNECT but not `SETTINGS_H3_DATAGRAM`, so Anvil's automatic mode uses DATAGRAM capsules.

## 5. Limitations

- One QUIC connection per SSE attempt or MASQUE tunnel; there is no pooling across sessions.
- CONNECT-UDP runs over HTTP/3 only (no RFC 9298 over HTTP/2 or HTTP/1.1), so a UDP-blocked
  path to the proxy has no fallback. DTLS inside the tunnel is refused, not implemented.
- The gateway's QUIC-datagram path cannot be exercised live because v0.9.7 never negotiates
  `SETTINGS_H3_DATAGRAM`. QUIC DATAGRAM frames in both directions are covered by the
  `h3server` fixture tests (`crates/anvil-transport/tests/h3_sse_masque.rs`).
- Authorization-lifetime resets of authenticated tunnels, the session limit (503) and DNS
  refusals (502/504) are not staged. They would surface as `masque.tunnel_ended_abnormally`
  and `masque.proxy_refused` respectively.
