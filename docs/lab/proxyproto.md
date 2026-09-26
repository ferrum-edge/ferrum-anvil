# Failure lab: `proxyproto` profile

This profile runs Anvil's shared engine as a **load balancer that speaks the PROXY protocol**
against the **real, pinned Ferrum Edge v0.9.7 release binary** (`lab/gateway/RELEASE.lock`).
Every stream proxy sets `stream_proxy_protocol: true`: `tcp` and `tcp_tls` listeners require a
PROXY v1/v2 header at the head of each connection, and `udp` / `dtls` listeners require the
PROXY v2 `DGRAM` envelope on every datagram. There are no gateway mocks.

Two more scenarios (PP-HTTP-001/002) send an **HTTP-family request with a PROXY header** to
the gateway's ordinary HTTP and HTTPS listeners. Ferrum Edge HTTP listeners never read a PROXY
header (`stream_proxy_protocol` is rejected for HTTP-family proxies, `src/config/types.rs`
v0.9.7; `src/proxy/gateway_listener.rs` has no PROXY parsing), so they show what a listener that
does not expect the header does, and that Anvil reports only the public outcome.

What Anvil sends is described in [protocols.md §3.10](../protocols.md). The gateway behaviour
under test is Ferrum Edge `docs/tcp_udp_proxy.md` ("Inbound PROXY Protocol", "Datagram
Client-Address Metadata (UDP / DTLS)") and its source: `src/proxy/proxy_protocol.rs`,
`src/proxy/datagram_client_address.rs`, `src/proxy/tcp_proxy.rs` (trust gating),
`src/dtls/mod.rs` (envelope stripped before the DTLS demux).

Each scenario records the stimulus, what Anvil concluded (findings, confidence ceilings,
forbidden claims), and **independent ground truth** that is never passed to the engine:

- the gateway's operator log: the stream transaction summary (`client_ip` is the forwarded
  client after trust gating), the PROXY warnings (`not in FERRUM_TRUSTED_PROXIES`, `did not
  start with a valid PROXY header`) and the datagram drop reasons (`reason` field);
- the fixtures behind the gateway. The TCP backends themselves require PROXY v2: the gateway's
  `backend_proxy_protocol: v2` re-advertises the client identity it resolved from Anvil's
  header, so the backend records exactly which client the gateway concluded. The UDP backends
  record every payload byte, so a backend that received envelope bytes would show them.

Profile code: `crates/anvil-lab/src/{proxyproto,fixtures_proxyproto}.rs`. Receivers:
`crates/anvil-fixtures/src/proxy_protocol.rs`. Gateway configuration:
`lab/gateway/proxyproto{,-auth,-v6}.{conf,yaml}`.

## 1. Running

```sh
export PATH=/opt/homebrew/opt/rustup/bin:$PATH
export ANVIL_LAB_FERRUM_BIN=/path/to/lab-bin/ferrum-edge-macos-aarch64   # verified against RELEASE.lock
ulimit -n 4096

cargo run -p anvil-lab -- list proxyproto
cargo run -p anvil-lab -- run proxyproto --untrusted-pass          # ~60 s
cargo run -p anvil-lab -- run proxyproto --scenario PP-013
cargo run -p anvil-lab -- up proxyproto                            # manual/desktop use (authenticated scenarios need `run`)
```

Every start runs the binary's `validate` first (the three configurations pass: `Validation
passed.`). Results go to `results/lab/<UTC stamp>-proxyproto/` with the three operator logs
(`gateway-operator.log` main, `-1` authenticated, `-2` untrusted-peer instance).

## 2. Instances and ports

Profile 9 of the port plan: gateway 189xx, fixtures 199xx, **everything on loopback**.

| Instance | Settings | Listeners | Fixtures |
|---|---|---|---|
| `proxyproto` | `FERRUM_TRUSTED_PROXIES=127.0.0.1/32`; no datagram secret (address-trust posture); streams on `127.0.0.1` | HTTP 18980, HTTPS 18981 (unused), admin 18990; `pp-tcp` 18901, `pp-tcp-tls` 18902 (TLS terminated), `pp-udp` 18903, `pp-dtls` 18904 (DTLS terminated) | 19901, 19902 (PROXY v2 echo), 19903, 19904 (UDP echo) |
| `proxyproto-auth` | as above plus `FERRUM_DATAGRAM_PROXY_PROTOCOL_SECRET` (random 64 characters per run, passed only in the process environment and Anvil's in-memory vault) | HTTP 18982, HTTPS 18983 (unused), admin 18991; `pp-udp-auth` 18911, `pp-dtls-auth` 18912 | 19913, 19914 |
| `proxyproto-v6` | the same trust list; streams on `::1` | HTTP 18984, admin 18992; `pp-v6-tcp` [::1]:18921, `pp-v6-udp` [::1]:18923 | 19921, 19923 (must stay silent) |

Why three instances: the datagram secret is process-global (it switches every udp/dtls PROXY
listener of a process to the authenticated posture), and an **untrusted peer on loopback**
needs a second loopback source address. macOS has only `127.0.0.1` on `lo0` (binding
`127.0.0.2` fails with `EADDRNOTAVAIL` unless an administrator adds an alias), but `::1` is a
loopback peer outside `127.0.0.1/32`, so the third instance binds its stream listeners to `::1`
and keeps the same trust list. If that instance cannot start (no IPv6 loopback), PP-006 and
PP-019 are reported as **skipped** with the reason, never as passed.

Listener identities for the authenticated envelope (what Anvil must be told):
`udp 127.0.0.1:18911` and `dtls 127.0.0.1:18912` (receive boundary, bind address as bound,
port). A wildcard bind would be `0.0.0.0` / `::`, which is a *different* identity (PP-015).

## 3. Scenarios

| ID | Stimulus | Anvil must conclude | Ground truth |
|---|---|---|---|
| PP-001 | v1 `PROXY TCP4 203.0.113.7 127.0.0.1 40001 18901` + a frame to 18901 | Echo; `proxy_protocol_header` phase completed after connect; the exact v1 line in the evidence; no `tcp.*` finding | Summary `client_ip` 203.0.113.7; backend's gateway header names 203.0.113.7:40001; backend got only the frame |
| PP-002 | v2 source 198.51.100.23:40002 + authority TLV `pp.anvil.test` | Echo; v2 bytes `…2111…` and the TLV in the evidence | `client_ip` 198.51.100.23; backend header names it |
| PP-002-socket | v2 with no configured addresses | Declared source = the real local socket address (origin `socket`) | Backend header source equals Anvil's local address and port |
| PP-003 | No header | Closed without data; `tcp.closed_without_data` with "the listener may require a PROXY protocol header" as an **alternative**; no `tcp.proxy_header_*`; no confirmed PROXY claim; no `client.*` finding | Warning `did not start with a valid PROXY header` (`invalid PROXY protocol signature`); backend saw nothing |
| PP-004 | Raw `PROXY TCP4 not-an-ip …` | Bytes sent verbatim and recorded as malformed; `tcp.proxy_header_maybe_rejected` at most **likely** | Warning with `invalid src IP`; backend saw nothing |
| PP-005 | v2 LOCAL (no addresses, `0x20 0x00`) | Echo | `client_ip` 127.0.0.1 and the backend header names Anvil's own socket address: the balancer is the client |
| PP-005-unknown | v1 `PROXY UNKNOWN` | Echo | As PP-005 |
| PP-006 | Valid v2 from `[::1]` to the `::1` instance | Closed without data; `tcp.proxy_header_maybe_rejected` **unknown**, "not in FERRUM_TRUSTED_PROXIES" only among the alternatives | Warning `socket peer is not in FERRUM_TRUSTED_PROXIES` with peer `[::1]`; backend saw nothing |
| PP-007 | v2 then TLS to 18902 | Echo over verified TLS; header phase ends before the TLS handshake starts | `client_ip` 203.0.113.77; backend header names 203.0.113.77:40077 |
| PP-008 | TLS to 18902 without header | `client.tls.connection_closed` (unknown) with the PROXY alternative; no `tcp.proxy_header_*` | Warning `did not start with a valid PROXY header` (the ClientHello was read as the header) |
| PP-009 | Envelope (source 203.0.113.99:5099) + a datagram to 18903 | Echo; `0x21 0x12`, 12-byte block, unauthenticated | Backend received exactly the payload; session summary `client_ip` 203.0.113.99 |
| PP-010 | A bare datagram | `udp.no_response` only; no PROXY claim | Drop reason `invalid_signature`; backend received nothing |
| PP-011 | Authenticated envelope, vault secret, listener `udp 127.0.0.1:18911` | Echo; binding, tag (`‹tag›`) and freshness summaries in the evidence; the secret nowhere in the record | Backend received the payload; `client_ip` 203.0.113.111; the gateway never logged the secret |
| PP-012 | Wrong secret | `udp.no_response` with the envelope drop as an alternative; no PROXY claim | Drop reason `authentication_tag_mismatch` |
| PP-013 | The same (sender 13, epoch, sequence 0) twice | First echoed; second: no response, envelope drop only an alternative | Drop reason `replay_duplicate`; backend received only the first |
| PP-014 | Timestamp 60 s in the past | No response only | Drop reason `freshness_outside_horizon` |
| PP-015 | Tag minted for `udp 0.0.0.0:18911` | No response only | Drop reason `authentication_tag_mismatch` (listener-domain binding) |
| PP-016 | DTLS to 18904 with the envelope | Handshake completes; ≥ 3 datagrams wrapped (flights included); echo | Backend received the decrypted payload; `client_ip` 203.0.113.116 |
| PP-017 | DTLS to 18904 without envelope | `client.dtls.handshake_timeout`; no PROXY claim | DTLS drop reason `invalid_signature` for each flight |
| PP-018 | Authenticated DTLS, identity `dtls 127.0.0.1:18912` (the default for `dtls://`) | Echo | Backend received the payload; `client_ip` 203.0.113.118 |
| PP-019 | Envelope from `[::1]` to the `::1` instance | No response only | Drop reason `untrusted_peer`; backend received nothing |
| PP-HTTP-001 | `GET http://127.0.0.1:18980/pp-http/echo` with a v1 header (source 203.0.113.80:48080) | The header written in its own phase on a new connection; the public outcome as observed: either HTTP 400 (`http.client_error` with "the listener may not expect a PROXY protocol header" as its only PROXY alternative) or, when the listener's answer arrives before the request is written, a close before any response (`exchange.closed_before_response` with that alternative, next to `tcp.proxy_header_maybe_rejected` **unknown**); no confirmed PROXY claim | The backend saw no request; no `pp-http` transaction in the operator log. Recovery without the header: 200, the backend got it, operator log 200 |
| PP-HTTP-002 | `GET https://127.0.0.1:18981/pp-http/echo` with a v2 header | The header phase ends before the TLS handshake starts; the handshake fails as observed (a `decode_error` alert: `client.tls.peer_alert` **unknown** with "the listener may not expect a PROXY protocol header" as an alternative); no confirmed PROXY claim, no `ferrum.*` finding | The backend saw no request; no `pp-http` transaction. Recovery without the header: 200 over verified TLS |

Datagram drops are silent on the wire, and Ferrum rate-limits the drop warning to one per
second per listener, so each drop scenario waits 1.1 s before sending.

## 4. Results

`anvil-lab run proxyproto --untrusted-pass`, three consecutive runs on macOS 26 (aarch64),
Ferrum Edge v0.9.7: **42 passed, 0 failed, 0 skipped** each time (21 scenarios × trusted and
untrusted destination passes). The untrusted pass (destination not declared as a Ferrum
gateway) produces no `ferrum.token.*` / `ferrum.outcome` finding.

After merging into the main branch (2026-09-26), `anvil-lab run all --untrusted-pass` and
`anvil-lab --release v0.9.5 run all --untrusted-pass` gave proxyproto **42/0/0 on both v0.9.7 and
v0.9.5**.

With PP-HTTP-001/002 (2026-09-26): three consecutive runs on v0.9.7 gave **46 passed, 0 failed,
0 skipped** each time (23 scenarios × both passes), and one run on v0.9.5 **46/0/0**. In every run
PP-HTTP-001 was observed as a close before any response and PP-HTTP-002 as a `decode_error` alert.

## 5. Observations

- **Fail-closed behaviour matches the documentation.** No header, an invalid header and an
  untrusted peer are all an immediate close without data (a FIN or RST, observed as `peer` or
  `abnormal`); the gateway never dials the backend. Anvil keeps these as observations, with
  PROXY protocol as one possible cause among the existing alternatives.
- **TLS listeners read the header first.** Without a header, the ClientHello's first bytes are
  parsed as a PROXY signature and rejected, so the client sees a close during the TLS
  handshake (`client.tls.connection_closed`), not a TLS alert.
- **LOCAL / UNKNOWN** keep the balancer's socket peer as `client_ip`; with
  `backend_proxy_protocol: v2` the backend then sees Anvil's own address and ephemeral port.
- **The envelope is stripped before anything else.** Backends never see envelope bytes, DTLS
  flights are unwrapped before the DTLS record layer, and replies are sent unwrapped.
- **Authenticated drops carry exact reasons** in the operator log, which is what separates the
  wrong-secret, replay, stale and wrong-listener cases; Anvil itself sees only silence for all
  of them and says so.
- **HTTP listeners answer the PROXY line at once.** A raw probe of 18980 with only
  `PROXY TCP4 … \r\n` gets `HTTP/1.1 400 Bad Request` with `connection: close` and
  `content-length: 0`, then the connection closes (with a reset when more bytes were sent).
  Because the answer arrives before Anvil's HTTP/1.1 request is written, the HTTP client
  discards it and reports a close before any response ("received unexpected message from
  connection" in the failure message); an HTTP server that waits for more bytes (the HTTP
  fixture) is seen answering 400. The HTTPS listener reads the header as a TLS record and sends
  a `decode_error` alert. Neither logs a transaction, and the backend is never contacted.
