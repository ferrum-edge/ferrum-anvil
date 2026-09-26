# Protocol adapters: capabilities and limitations

Status as of this change. It covers the non-request/response adapters: WebSocket, gRPC, server-sent events (SSE), raw TCP/TLS and UDP/DTLS. It also covers the HTTP/3 policy cases in the failure matrix. HTTP/1.1 and HTTP/2 are documented with the HTTP adapter.

Support is not one yes/no per protocol (build plan §7). Each protocol is rated on four separate dimensions:

- **Interactive**: the desktop session API, `Engine::open_session`.
- **Automation**: collection/CLI execution, `Engine::execute`.
- **Load readiness**: whether a load engine could use this adapter today.
- **Diagnostic detail**: what the evidence and findings actually cover.

## 1. Capability matrix

| Protocol / mode | Interactive | Automation | Load readiness | Diagnostic detail |
|---|---|---|---|---|
| WebSocket, HTTP/1.1 Upgrade (`ws://`, `wss://`) | **Yes.** Send text, binary (hex) and ping. Close with a code and reason. Cancel. The transcript streams live. | **Yes.** Scripted messages, then a stop on `expect_messages`, idle close, peer close or the total deadline. | **Refused.** `anvil-load` runs HTTP-family requests only; plan validation refuses session protocols with `Unsupported` (LOAD-013). The adapter opens one connection per run and has no session or message metrics for load. | Phases DNS, connect, proxy, TLS, handshake, session. 101 validation (`Upgrade`, `Connection`, `Sec-WebSocket-Accept`). Subprotocol negotiation. Close code, reason and `closed_by`. 1006 is reported as abnormal. 1009 is split into local limit vs peer limit. |
| WebSocket over HTTP/2 extended CONNECT (RFC 8441) | **Yes**, same commands | **Yes** | Not built | A separate bootstrap. The client waits for the peer's `SETTINGS_ENABLE_CONNECT_PROTOCOL`. A 200 is success. Works over TLS (ALPN `h2`) and h2c. |
| WebSocket over HTTP/3 extended CONNECT (RFC 9220) | **Yes**, same commands | **Yes** | Not built | A separate bootstrap on a fresh QUIC connection. The client waits for the server's `SETTINGS_ENABLE_CONNECT_PROTOCOL` before sending `:protocol = websocket`. A 200 is success. Needs `wss://` and no proxy. QUIC phases as for HTTP/3 (no TCP phase). See §3.1. |
| gRPC unary / server streaming (`grpc://`, `grpcs://`, `http(s)://`) | No, by design. Use `execute`. `open_session` returns `unsupported_combination`. | **Yes** | Not built (one connection per call, no channel reuse) | HTTP status and gRPC status reported separately. Trailers vs trailers-only vs missing. `grpc-message` is percent-decoded. `grpc-status-details-bin` is decoded. Message boundaries are kept, each shown as JSON. |
| gRPC client streaming / bidirectional | **Yes.** `SendText` sends a JSON message, `SendBinaryHex` sends pre-encoded protobuf. `HalfClose` or `Close` ends the client stream. | **Yes.** Scripted messages, then a half-close. | Not built | As above. The half-close is recorded in the transcript. |
| SSE (`http(s)://`) | **Receive-only.** Close or cancel. Other commands are rejected. | **Yes.** Stops on `max_events`, idle, the deadline, cancel or the peer's end. Optional reconnect. | Not built | Every event is recorded with its id, type and data. `closed_by` is Client, Timeout, Peer or Abnormal. The raw stream is kept up to the capture limit. |
| Raw TCP (`tcp://`) / TCP+TLS (`tls://`) | **Yes.** Send text or hex frames. `HalfClose` (FIN). `Close`. | **Yes.** Stops on expected frames, max bytes, read-idle, the peer's close or the deadline. | Not built | The same connector phases and TLS/mTLS evidence as HTTP. Framing presets. Half-close semantics. Bytes sent and received. Partial trailing frames. |
| UDP (`udp://`) | **Yes.** Send datagrams. `Close`. | **Yes.** Sends datagrams, then waits out the response window. | Not built | A per-datagram transcript. Sent and received counts. ICMP port-unreachable when the OS reports it. A count of repeated payloads. It never infers delivery. |
| DTLS 1.2/1.3 (`dtls://`) | **Yes**, like UDP | **Yes** | Not built | A separate `dtls_handshake` phase. Peer leaf verified against the TLS profile. Client identity, and whether a CertificateRequest was seen (DTLS 1.2). The alert name when a peer rejects the handshake. |
| HTTP/3 forced / automatic fallback | n/a (request/response) | **Yes.** From the existing H3 transport, now covered by tests. | Load runs use the same HTTP engine path, so a forced-H3 request is accepted, but H3 has not been exercised under load (see load.md). | Measured QUIC phases, and no TCP phase. Forced H3 never falls back. Automatic fallback records both attempts and the `client.h3.fallback_used` finding. |

"Not built" in the load column means what it says. `anvil-load` (see [load.md](load.md)) drives HTTP-family requests only and refuses every protocol in this table except HTTP/3 at plan validation, so no count can imply delivery. Every adapter here is correct for functional runs: one execution, one connection, a full record. Per-protocol load actions (build plan §7, §14) need the metrics defined there: sessions, messages, datagrams and their denominators. They also need connection or channel reuse. That work is still to be designed.

## 2. Shared behavior (all session protocols)

- **One preparation path.** `sessions.rs` reuses `http_exec::prepare_all`, so these behave exactly as for HTTP: variables, settings layers, the auth profile, TLS profile, trust, proxy selection, DNS overrides, IP preference and timeouts. Accepted schemes are `ws`/`wss`, `grpc`/`grpcs`/`http`/`https`, `http`/`https` for SSE, `tcp`/`tls` and `udp`/`dtls`.
- **Auth.** Auth is applied per send, as headers or query parameters, for WebSocket, gRPC and SSE. OAuth tokens come from the shared token cache. A few combinations fail before any traffic with `unsupported_combination`:
  - an auth profile that rewrites the body (WS-Security);
  - query-parameter auth on gRPC;
  - any auth profile on raw TCP/UDP, because payloads are sent verbatim. Client certificates come from the TLS profile instead.
- **Combinations refused before traffic** (`unsupported_combination`, `phase = prepare`, `dispatch = not_dispatched`):
  - a proxy with UDP/DTLS (HTTP CONNECT, SOCKS5 and HBONE tunnels carry only TCP);
  - WebSocket over HTTP/3 with `ws://` (QUIC is always encrypted) or through a proxy;
  - gRPC with the HTTP/1.1-only or HTTP/3 policies, or `plaintext` with a TLS URL;
  - SSE over HTTP/3;
  - a gRPC call mode that does not match the method descriptor. Unary alone never proves streaming.
- **Proxies.** TCP-based sessions go through the configured HTTP or SOCKS5 proxy as a CONNECT tunnel. This includes `ws://` and cleartext SSE. A mesh HBONE proxy works the same way (§3.8): WebSocket, raw TCP/TLS, SSE and gRPC run over the HTTP/2 CONNECT stream.
- **Transcripts.** Every message, event, frame or datagram becomes a `StreamMessage` and is also emitted live as `ExecutionEvent::Message`. The transcript is bounded:
  - The defaults are 2,000 entries and a 2 KiB preview per entry.
  - It keeps the first half and the most recent half. Entries in between are counted in `dropped_messages`.
  - `sent_count`/`received_count` and the byte totals always cover the whole session. The `MessageCount` assertion uses `received_count`.
  - Previews and event ids pass through the engine's `Redactor`, as do WebSocket close reasons and `grpc-message`. That redactor scrubs the exact secret values used in the run, so no transcript or live event contains a resolved secret. A test covers this for WSS with bearer auth.
  - Binary previews are hex.
- **Outcome derivation.** The adapters return a `ProtocolStatus` override and a transcript to `record::assemble`. When a session actually opened, transport completion comes from how the session ended, not from HTTP body framing:
  - no failure → `completed`;
  - user cancel → `canceled`;
  - any other failure → `incomplete`. Examples: an abnormal close, a mid-stream reset, or a gRPC deadline with no status.

  gRPC with a missing terminal status is always `incomplete`, and its application state is never success. Application state comes from the protocol status: gRPC codes, WebSocket close codes and the SSE HTTP status.
- **Interactive API.** `Engine::open_session(ctx, events)` prepares the session immediately. If preparation fails, the returned handle finishes at once with a local-failure record. Otherwise the session runs in a task:
  - `SessionHandle::send(SessionCommand)` rejects commands a protocol cannot express, such as WebSocket `HalfClose` or TCP `Ping`, with `SessionError::Unsupported` instead of dropping them silently.
  - `close()` is a graceful close. `cancel()` aborts.
  - `finish()` waits for the end and returns the full `ExecutionOutput`. It does not close the session, so call `close()` or `cancel()` first unless the peer is expected to end it.
  - Interactive sessions ignore the total deadline and the automation idle-close.
  - Dropping every command sender also ends the session gracefully.
- **Engine-derived findings.** The generic rules have no finding for a few adapter observations. For these, the engine adds findings with inline wording: `grpc.reflection_unavailable`, `udp.icmp_port_unreachable` and `udp.repeated_payloads`. Each one states what it does not prove.

## 3. Per-protocol details

### 3.1 WebSocket

- **Libraries.** hyper 1.x does the bootstrap for HTTP/1.1 and HTTP/2, and `hyper::upgrade::on` hands over the stream. For HTTP/3, quinn + `h3` carry the extended CONNECT, and the request stream's DATA frames are bridged to a byte stream. tokio-tungstenite 0.30 runs the frames in all three cases, with the same session code.
- **Bootstrap request.** For HTTP/1.1, Anvil generates `Sec-WebSocket-Key` and verifies the accept key. Over TLS, HTTP/1.1 offers ALPN `http/1.1` only. User headers win over the handshake defaults, which allows deliberately malformed handshake tests.
- **Subprotocols.** They are offered in order. If the server selects one that was not offered, that is a `ws_protocol_error`. If the server selects none, that is recorded as a note.
- **Message limit.** `max_message_bytes` is a local inbound ceiling on both messages and frames. Outbound size is not limited. When an inbound message goes over the limit, Anvil closes with **1009**, sets `closed_by = client` and records a `ws_message_too_large` failure. When the peer's limit triggers the 1009, it is recorded with `closed_by = peer` and no transport failure. `ws.closed_too_big` keeps both explanations as alternatives.
- **Abnormal ends.** A connection that ends without a Close frame is reported as `close_code = 1006` with `closed_by = abnormal` and a `body_incomplete`/`body_reset` failure. 1006 is a local designation, not a code the peer sent (RFC 6455 §7.1.5).
- **Teardown after Close.** Once the peer's Close frame has arrived, the way TCP/TLS is torn down does not change the outcome. That covers an RST, or a missing TLS `close_notify`.
- **Rejected handshakes.** A non-101 answer (non-200 for HTTP/2) keeps the HTTP response as evidence (status, headers, bounded body) with a `ws_handshake_rejected` failure. The HTTP status findings still apply.
- **RFC 9220 (WebSocket over HTTP/3).**
  - **Library.** `h3` 0.0.8 models `:protocol` as a closed type that cannot express `websocket`. Upstream fixed this in hyperium/h3#236 (`Protocol::WEBSOCKET`), which no release contains yet. The workspace vendors `h3` 0.0.8 with exactly that commit applied (`vendor/README.md`), the same approach Ferrum Edge 0.9.5 uses.
  - **Settings first.** RFC 9220 §3 forbids sending `:protocol` until the server's SETTINGS enable extended CONNECT. Anvil waits for the SETTINGS frame (up to the response-header timeout, at most 5 s). If they do not enable it, or none arrive, it fails with `ws_handshake_rejected` in the `protocol_handshake` phase and sends nothing.
  - **Refused before traffic.** `ws://` (QUIC is always encrypted) and any proxy give `unsupported_combination`. There is never a fallback to HTTP/1.1 or HTTP/2: a UDP-blocked path is a `quic_handshake_timeout`.
  - **Evidence.** The connection record is the HTTP/3 one: DNS, QUIC handshake (TLS 1.3 inside) and HTTP/3 setup, with connect `not_applicable`. The session's byte counters are the WebSocket bytes carried in the stream's DATA frames, not QUIC packet bytes. A stream error that ends the session is appended to the failure message.
  - **Live.** PROTO-013 passes against Ferrum Edge 0.9.5 (`docs/lab/streams-cpdp.md`), which bridges the session to the backend as an HTTP/1.1 Upgrade.
- **Not implemented.** permessage-deflate and other extensions (none are offered), fragmented-send controls, and automatic reconnect.

### 3.2 gRPC

- **Transport.**
  - TLS with ALPN `h2` is required. Negotiating anything else is a `tls_alpn_mismatch`.
  - Cleartext targets (`grpc://`, `http://`) use h2c with prior knowledge.
  - An optional URL path prefix goes in front of `/<service>/<method>`, for gateway routing.
- **Request headers.** `content-type: application/grpc`, `te: trailers`, `user-agent: grpc-anvil/<version>`, the metadata entries, and the auth headers. `grpc-*` metadata keys are refused. `grpc-timeout` is sent from `deadline_ms`.
- **Deadline.** The deadline is also enforced locally. When it elapses the stream is reset, the failure is `total_timeout` with `deadline_ms`, and the status is recorded as **missing**. Anvil does not invent a `DEADLINE_EXCEEDED`.
- **Status.** It comes from the trailers, or from the headers of a trailers-only response, and is labeled with its source. `grpc-status-details-bin` is decoded as `google.rpc.Status` (code, message and detail type URLs), and the summary goes into the prepared inferred notes.
- **Schemas.**
  - `.proto` sources are compiled in-process by `protox`. Imports resolve only among the provided files, by attachment file name, plus the bundled Google well-known types. Nothing is read from disk.
  - A serialized `FileDescriptorSet` is also accepted.
  - The third source is server reflection. v1 is tried first; if it is UNIMPLEMENTED, v1alpha is tried. The dependency closure is fetched with `file_by_filename`, capped at 64 requests. Reflection runs on the same HTTP/2 connection as the call.
  - A refused reflection (PROTO-017) produces `grpc.reflection_unavailable`. The method is not called, dispatch is `not_dispatched`, and there is no `app.grpc_status` finding about the service.
- **JSON mapping.** `prost-reflect` handles JSON ↔ DynamicMessage using proto3 JSON mapping. Received messages are shown as JSON with default serialization options.
- **Compression.** Inbound `grpc-encoding: gzip` messages are decompressed up to the per-message limit. Anvil never compresses outbound messages and does not advertise `grpc-accept-encoding`.
- **Receive limit.** The default is 64 MiB per message, and it is also capped by `limits.max_response_bytes`.
- **Not implemented.** gRPC-Web; gRPC over HTTP/3; retries, hedging and service config; load-balancing policies; outbound compression; keepalive pings as a session command. HTTP/2 PING is connection-level.
- **Proto import names** must match the stored attachment file names. A project that imports `foo/bar.proto` must store the file under that name.

### 3.3 Server-sent events

- **Parsing.** Incremental parsing per the HTML Standard's event-stream rules: `id`, `event`, `data` (multi-line), `retry`, comments, CR/LF/CRLF split across chunks, and a leading BOM. An `id` that contains NUL is ignored. A single line is capped at 1 MiB, or `max_response_bytes` if that is lower.
- **Request headers.** `Accept: text/event-stream` and `Cache-Control: no-cache`. `Accept-Encoding: identity` is sent unless the user set it, because events are parsed as they arrive and are not decompressed. `Last-Event-ID` is sent when configured.
- **Stop conditions.** `max_events` gives `closed_by = client` and a transport of `completed`. An idle period with no bytes at all gives `closed_by = timeout` (keep-alive comments count as activity). Explicit cancel gives `closed_by = client` and a transport of `canceled`, and the `sse.canceled` finding says this is not a server timeout. The server ending the stream gives `closed_by = peer`.
- **Reconnect.** It is off by default and happens only when enabled. It triggers only after an **abnormal** end, such as a reset or a truncated chunked body, and is limited to 5 attempts.
  - It honors the server's `retry:` delay (default 1 s, capped at 30 s) and sends `Last-Event-ID`.
  - Partial event data from the broken stream is discarded.
  - Each reconnection is its own attempt, with reason `retry{after: <kind>}`.
  - A clean end of stream is recorded as the server closing and is **not** reconnected. That is a deliberate difference from browser `EventSource`.
- **Not implemented.** SSE over HTTP/3, and decompression of compressed event streams.

### 3.4 Raw TCP / TLS

- **Connection setup.** Uses the shared connector: DNS, TCP, proxy tunnel (HTTP CONNECT or SOCKS5), then TLS with the profile's trust and client identity. TLS evidence matches HTTPS, including the client-certificate request and what was presented. No ALPN is offered.
- **Payloads.** Text (UTF-8, verbatim), hex (whitespace, `:` and `0x` allowed) or base64. Variables are resolved first.
- **Framing presets.** None, newline-delimited (`\r\n` accepted on receive), or a big-endian u16 or u32 length prefix. A payload the preset cannot represent fails locally with `body_serialization`, for example more than 65,535 bytes with a u16 prefix. Incoming frames above the read limit stop with `response_too_large_local`. Without a preset, each read is recorded as a chunk and `expect_frames` is ignored with a note, because TCP has no message boundaries.
- **Half-close.** `shutdown(Write)`, with a TLS `close_notify` first, keeps the read side open. A reply that arrives afterwards is preserved and gets the `tcp.reply_after_half_close` finding.
- **Stop conditions.** `expect_frames`, `max_read_bytes`, `read_idle_ms` (`closed_by = timeout`), the peer's FIN (`closed_by = peer`), a reset (`closed_by = abnormal` plus a `body_reset` failure), the total deadline, or cancel.
- **Not implemented.** Application codecs (only arbitrary bytes are supported), PROXY-protocol headers, and Unix sockets.

### 3.5 UDP

- **Socket.** The socket is bound to an ephemeral local port and `connect`ed to the destination. Only datagrams from that address are accepted, and the OS can report ICMP errors to it. There is no connect phase; it is marked not applicable.
- **Evidence.** Sent datagrams are recorded one per entry. The response window starts after the last send, or after each interactive send. Received datagrams are counted until `max_datagrams`.
- **Silence** is `udp.no_response`: "no response observed". It never claims delivery or an outage. Dispatch is `may_have_been_sent`, because UDP gives no acknowledgement.
- **ICMP port unreachable.** When the OS reports it, it is recorded as `udp.icmp_port_unreachable` with confidence **likely**. It is stronger than silence, but a firewall can generate it.
- **Loss and duplication.** Fewer responses than sends is `udp.partial_responses`. Payloads byte-identical to an earlier received payload are counted in `udp.repeated_payloads`, which is an observation and not a claim of duplicate delivery. Sequence-level loss or reorder accounting is not attempted, because UDP has no sequence numbers unless the application adds them.
- **Not implemented.** Unconnected mode (replies from another address or port, as in TFTP), multicast or broadcast, and datagrams larger than 65,535 bytes.

### 3.6 DTLS

- **Implementation.** `dimpl` 0.6 with its RustCrypto provider, a dedicated DTLS implementation that is separate from the TLS adapter. The client sends a hybrid ClientHello that offers DTLS 1.2 and 1.3, and the negotiated version is recorded (`DTLSv1_2` / `DTLSv1_3`). Retransmissions follow dimpl's timers. The handshake deadline is the TLS-handshake timeout class, and when it expires the result is `dtls_handshake_timeout` with `deadline_ms`.
- **Certificate verification.**
  - dimpl verifies handshake signatures but does no PKI validation.
  - Anvil validates the peer's leaf itself, with the same webpki verifier the TLS profile builds for TLS: trust anchors, validity and name. It does this before releasing its next flight.
  - A failure aborts the handshake, typed as TLS verification (`tls_untrusted_issuer`, `tls_name_mismatch`, and so on) in the `dtls_handshake` phase. The presented certificate is kept as evidence and no application data is sent.
  - `verify = false` keeps encryption and records `bypassed{would_have_failed}`.
- **Client identity.** Taken from the TLS profile, with the same host bindings as TLS. It must be ECDSA P-256 or P-384. RSA and other keys fail locally with `client_identity_invalid`.
- **Peer rejection.** A fatal alert from the peer, such as an `unknown_ca` rejection of the client identity, is typed as `dtls_handshake_failed` with `tls_alert` set to the alert name. Our own verification result is kept separately, so the evidence shows which side rejected.
- **CertificateRequest.** Seen from the peer's plaintext flight for DTLS 1.2. It is reported as not observed (`None`) for DTLS 1.3, where that message is encrypted.
- **Library limits, stated plainly.**
  - dimpl exposes only the peer's **leaf** certificate. A server chain that needs an intermediate validates only if that intermediate is itself a configured trust anchor.
  - dimpl sends a **single** client certificate, never a chain. When the chain has more certificates, a note says so.
  - dimpl always needs a key pair. If the server asks for a client certificate and no identity is configured, an ephemeral self-signed certificate (`CN=anvil-ephemeral-dtls-client`) is what the server sees, and the evidence and notes say so.
  - The negotiated cipher suite is not exposed.
  - There is no session resumption, PSK mode, SRTP keying or connection ID.
- **Alert codes.** dimpl reports received alerts only in its formatted error text (`description=N`). The adapter reads the numeric code from that fixed format and infers nothing else from the text.

### 3.7 HTTP/3 policy (PROTO-006/007/008)

The HTTP/3 transport already existed. This change adds an HTTP/3 fixture server (quinn + h3) and the tests:

- **PROTO-006, forced success.** The record shows `protocol = h3`, ALPN `h3`, a completed `quic_handshake` phase, and connect `not_applicable`. There is no TCP or TLS-over-TCP phase.
- **PROTO-007, no UDP listener.** The result is `quic_handshake_timeout`, with a single attempt, and the TCP fixture on the same port sees no connection.
- **PROTO-008, automatic fallback.** Two attempts are recorded, the second with reason `protocol_fallback{from: h3}`. The response is not HTTP/3, and there is a `client.h3.fallback_used` finding plus a `protocol_fallback` warning. The fallback finding previously never fired, because the engine did not pass `protocol_fallback_from`. That is fixed.

### 3.8 Mesh client: HBONE tunnels, SPIFFE server identity, SNI override

Anvil can test Ferrum Mesh (and Istio-style) mesh listeners directly, without being part of the mesh.

**HBONE proxy profile (`ProxyKind::Hbone`).** A proxy profile of kind `hbone` names the HBONE endpoint (`host:port`, for example a mesh proxy's HBONE listener or a sidecar's inbound mTLS listener) and a **TLS profile** (`tls_profile_id`, required). For each connection Anvil:

1. resolves and connects to the endpoint (`dns`, `connect`);
2. runs **mutual TLS** with ALPN `h2`, presenting the TLS profile's client identity (the client SVID) and verifying the endpoint's server identity with the same profile (normally by SPIFFE ID, see below);
3. sends the HTTP/2 connection preface, then `CONNECT` with `:authority = <request host:port>` (IPv6 bracketed). Optional headers come from the profile: a protocol marker (`x-ferrum-mesh-protocol: hbone` or `x-istio-protocol: hbone`; none by default, as Istio ztunnel sends none), a W3C `baggage` value (for example `source.principal=…`, honored by the endpoint only for trusted assertors) and extra headers. Connection-specific headers are refused before traffic;
4. treats a `2xx` as an open tunnel. The inner connection (HTTP/1.1, HTTP/2 with its own ALPN, TLS with the request's own TLS profile, raw TCP/TLS, WebSocket, SSE, gRPC) then runs over the tunnel stream exactly as over an HTTP CONNECT proxy tunnel. The endpoint resolves and dials the destination, so Anvil records the inner `dns` and `connect` phases as `not_applicable`.

Evidence keeps the two legs apart:

- The attempt's phases show the whole outer leg as one `proxy_tunnel` phase. `ConnectionObservation::tunnel` (`TunnelObservation`) holds the outer phases (`dns`, `connect`, `tls_handshake`, `protocol_handshake`, `proxy_tunnel`) on the same clock, the endpoint's addresses, the outer mTLS observation (client SVID presented, the endpoint's certificate, its SPIFFE ID and the identity check applied), the `CONNECT` headers sent, the `CONNECT` status and response headers.
- `connection.tls` stays the **inner** TLS with the destination.
- A non-2xx `CONNECT` is a typed `hbone_connect_refused` failure (phase `proxy_tunnel`) with the status and a bounded (8 KiB) body preview kept in the tunnel evidence. It is **not** a destination response: `response` is empty, dispatch is `not_dispatched`, and no HTTP-status finding is produced for the destination.
- Tunnel-leg failures are typed separately from the destination: `proxy_connect_failed` (endpoint DNS/TCP), `hbone_endpoint_tls_failed` (the mTLS handshake; the precise TLS kind and alert are in `tunnel.failure`), `hbone_protocol_error` (no `h2`, preface, stream reset, GOAWAY or the connect deadline before a `CONNECT` answer) and `hbone_connect_refused`. A TLS 1.3 client-certificate alert that arrives after Anvil's handshake is read from the mTLS stream and attributed to the TLS leg.
- Timeouts: the endpoint's DNS, TCP and TLS use the request's DNS, connect and TLS deadlines; the HTTP/2 preface and the `CONNECT` answer share the connect deadline.

A fresh HBONE connection (one HTTP/2 connection, one `CONNECT` stream) is opened per inner connection and never pooled, because the tunnel carries one execution's identity and headers. HTTP/3 and UDP/DTLS through an HBONE proxy are refused before traffic (`unsupported_combination`). Proxy credentials are refused for HBONE (the client is authenticated by its SVID).

**SPIFFE server identity (`TlsProfile::server_spiffe`).** A TLS profile can set `expected_server_spiffe_id`, `trust_domain`, or both (the ID must then be in that trust domain; invalid values are refused before traffic). When set, the peer's X.509-SVID is verified as the SPIFFE X.509-SVID specification requires, **instead of** host-name verification:

- the chain must anchor in the profile's CA certificates (the trust bundle; server-auth EKU when present), with no DNS-name check;
- the leaf must carry **exactly one** URI SAN that is a valid `spiffe://` ID, must not be a CA, must set `digitalSignature` and neither `keyCertSign` nor `cRLSign` (a certificate with several URI SANs is invalid);
- its trust domain must equal the configured one, and with an expected ID the ID must match exactly.

Verification stays **on by default**: without `server_spiffe` the ordinary host-name verification applies. Failures are typed (`tls_spiffe_id_mismatch`, `tls_untrusted_trust_domain`, `tls_invalid_svid`; an unanchored SVID that names another trust domain is `tls_untrusted_trust_domain`) and stop the handshake before any request byte. `verify = false` still records what the SPIFFE check would have concluded. The same check applies to HTTP/1.1, HTTP/2, HTTP/3, raw TLS, WebSocket, gRPC, SSE, DTLS and the HBONE endpoint. The peer's SPIFFE ID (a single `spiffe://` URI SAN) is recorded in `TlsObservation::peer_spiffe_id` for **every** TLS server, verified or not, and `identity_check` records which check applied (`host_name`, `spiffe_id` or `spiffe_trust_domain`).

**SNI override (`TlsProfile::server_name_override`).** The configured name is sent as SNI instead of the URL host (the HTTP authority is unchanged), for example an east-west passthrough name like `outbound_.8080_._.svc.ns.svc.cluster.local` (underscores are accepted). The certificate is verified against that name, or against the SPIFFE identity when one is configured. `TlsObservation::sni` records the SNI actually sent (`None` when the name is an IP address, which TLS never sends as SNI), and `server_name_overridden` marks that it came from the profile. An invalid override is refused before traffic.

Live coverage: the `mesh` lab profile (`docs/lab/mesh.md`) drives the real Ferrum Edge 0.9.7 in mesh mode.

## 4. Failure-matrix coverage

| Case | Test (real sockets) |
|---|---|
| PROTO-006 | `anvil-engine/tests/sessions.rs::proto_006_forced_h3_success_measures_quic_not_tcp` |
| PROTO-007 | `…::proto_007_forced_h3_without_udp_listener_fails_typed_without_tcp` |
| PROTO-008 | `…::proto_008_h3_auto_fallback_records_both_attempts` |
| PROTO-009 | `…::proto_009_ws_normal_close_is_not_a_fault` |
| PROTO-010 | `…::proto_010_ws_abnormal_close_is_reported_as_local_1006` |
| PROTO-011 | `…::proto_011_ws_oversize_local_limit_and_peer_limit` |
| PROTO-012 | `…::proto_012_ws_over_h2_extended_connect_is_its_own_bootstrap` (TLS and h2c) |
| PROTO-013 | `…::proto_013_ws_over_h3_extended_connect_echoes_over_quic`, `…::ws_over_h3_without_extended_connect_sends_nothing`, `…::ws_over_h3_needs_wss_and_sends_nothing_for_ws`, `…::ws_over_h3_rejected_connect_keeps_http_evidence`, `…::ws_over_h3_abnormal_end_is_reported_as_local_1006`; live in the streams lab |
| PROTO-014 | `…::proto_014_grpc_http_200_with_error_status_is_an_rpc_failure` |
| PROTO-015 | `…::proto_015_grpc_missing_terminal_status_is_incomplete_not_success` |
| PROTO-016 | `…::proto_016_grpc_four_modes_with_message_boundaries`, `…_deadline_is_sent_and_enforced_without_fabricating_a_status`, `…_cancellation_and_mode_mismatch`, `…_interactive_bidi_session`; `anvil-transport/tests/sessions_streams.rs::proto_016_grpc_adapter_with_a_compiled_proto_and_trailers` |
| PROTO-017 | `…::proto_017_reflection_denied_but_local_proto_works` |
| PROTO-018 | `…::proto_018_sse_cancel_is_expected_and_keeps_bounded_history`; `sessions_streams.rs::proto_018_sse_history_is_bounded_but_counted` |
| PROTO-019 | `…::proto_019_tcp_half_close_keeps_the_reply` |
| PROTO-020 | `…::proto_020_udp_silence_is_only_no_response_observed`; `sessions_streams.rs::proto_020_udp_icmp_unreachable_is_recorded_as_such` |
| PROTO-021 | `…::proto_021_udp_loss_and_repeats_are_counted_not_explained` |
| PROTO-022 | `…::proto_022_dtls_handshake_with_verified_peer`, `…_wrong_root_is_a_typed_client_side_verification_failure`, `…_mutual_tls_positive_and_negative`; `sessions_streams.rs::proto_022_dtls_to_a_non_dtls_listener_times_out_with_a_deadline` |

Mesh client tests (real sockets, the `anvil_fixtures::hbone` HTTP/2 CONNECT-over-mTLS fixture and the SPIFFE certificates in `anvil_fixtures::mesh_pki`):

- `anvil-transport/tests/mesh_spiffe_hbone.rs`: SPIFFE ID and trust-domain verification of a URI-only SVID, host-name verification staying on by default, wrong ID, foreign trust domain (anchored and unanchored), several URI SANs, no URI SAN, a bypass recording what SPIFFE would have concluded, invalid SPIFFE settings refused before traffic, SNI override sent and verified (including an east-west name), and HBONE: inner HTTP/1.1 and inner TLS + HTTP/2 through the tunnel with separate outer evidence, no pooling, 403/503 refusals with their bodies, missing client SVID (mTLS refusal or the unauthenticated-peer 403), an untrusted client SVID, an endpoint identity mismatch, the SNI the endpoint received, an unreachable endpoint and an endpoint without `h2`.
- `anvil-engine/tests/mesh_hbone.rs`: the same through proxy/TLS profiles and the findings, plus WebSocket and raw TCP over HBONE, HTTP/3 through HBONE refused, and an HBONE profile without a TLS profile refused before traffic.
- `anvil-diagnostics/tests/mesh_hbone_contract.rs`: tunnel-leg findings over public evidence and their lookalikes.

Other tests cover SSE reconnect with `Last-Event-ID`, WebSocket handshake rejection, WSS auth with secret redaction, interactive WebSocket/TCP/UDP/gRPC sessions, TCP framing with mTLS, and refusal before traffic for UDP through a proxy and for auth on raw TCP.

New fixtures, all lab-only in `anvil-fixtures`:

- `h3server`: HTTP/3 over quinn and h3.
- `dtls`: a dimpl DTLS 1.2 echo server that validates client certificates itself and rejects an untrusted identity with a plaintext `unknown_ca` alert.
- The gRPC echo `fail_with = -1` sentinel: reply once, then reset the stream before any status.

The HTTP fixture's WebSocket route now flushes its Close reply, so a client-initiated closing handshake completes. Before, it dropped the socket, which is correctly a 1006 for the client.

## 5. Honest limitations summary

1. **WebSocket over HTTP/3 (RFC 9220)** depends on a vendored `h3` 0.0.8 carrying one upstream commit until an `h3` release includes it. Each session opens its own QUIC connection; there is no pooling across sessions.
2. **Load generation.** `anvil-load` drives HTTP-family requests only (see `docs/load.md`). Plan validation refuses every session protocol in this document, and HTTP/3 has not been exercised under load.
3. **DTLS.** dimpl validates only the leaf and sends only the leaf. It is ECDSA-only, and it presents an ephemeral certificate when an identity is requested but none is configured. It does not expose the cipher suite. CertificateRequest cannot be observed for DTLS 1.3.
4. **gRPC.** No gRPC-Web, no HTTP/3, no outbound compression, and no retry or service-config semantics. Proto imports resolve by attachment file name only.
5. **SSE.** No reconnect after a clean end of stream, which differs from browser behavior. Compressed streams are not supported.
6. **UDP.** Connected-socket mode only. Replies from a different address or port are not accepted.
7. **Connections.** Session adapters open a fresh connection per execution or session. Unlike HTTP/1.1, HTTP/2 and HTTP/3, they do not use the pool.
8. **HBONE.** One tunnel per inner connection (no HTTP/2 stream sharing across executions). No double-HBONE (tunnel inside a tunnel), no HBONE over HTTP/3 (QUIC), and no Anvil-side capture: Anvil is a direct client of the endpoint. A `CONNECT` refusal is reported with its public status and body only; which mesh policy refused is never claimed.
9. **SPIFFE.** X.509-SVID only (no JWT-SVID), one trust bundle per TLS profile (its CA certificates), no SPIFFE federation bundle endpoint and no revocation checking (as for every TLS profile).
10. **Diagnostic wording.** Three findings (`grpc.reflection_unavailable`, `udp.icmp_port_unreachable`, `udp.repeated_payloads`) carry their wording inline in the engine, not in `catalog/diagnostics/findings.en.json`. They should move into the catalog once the catalog owners agree.
