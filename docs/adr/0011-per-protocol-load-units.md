# ADR 0011: Per-protocol load units

## Context
ADR 0006 refused load for every non-HTTP protocol until denominators existed
(LOAD-013). Build plan §7 and §14 ask for load actions for HTTP/3, unary gRPC,
WebSocket, TCP and UDP/DTLS, with protocol-specific completion semantics and
denominators, and never a sent datagram counted as delivered.

## Decision
- A load step stays one `Engine::execute` call through the protocol's own
  session adapter, so preparation, auth, TLS, proxy and DNS are those of a
  manual Send. Each call is one **unit**: an HTTP request, a unary gRPC call,
  a server-streaming gRPC stream, an SSE stream, a WebSocket session, a TCP
  exchange or a UDP/DTLS exchange (`LoadUnitKind`).
- A plan has exactly one unit kind. The unit ledger keeps its existing
  identity; each kind adds typed denominators (`ProtocolLoadMetrics`, versioned,
  inside the sealed report) that must balance against it. Snapshots are one
  consistent cut (shard lock, then ledger lock) so they balance live and in
  crash reports too.
- Completion and success are defined per unit and written into every report:
  gRPC completes only with a terminal status (missing status = incomplete,
  never success); a UDP exchange with nothing received is "no response
  observed", neither success nor failure, and has no latency; a UDP
  exchange's latency is its time to first response; a WebSocket round trip
  exists only when the request defines `expect_messages`.
- The engine gains two load-only, typed hooks rather than a second client
  stack: optional per-engine gRPC **channels** (a pooled HTTP/2, HTTP/3 or
  HTTP/1.1 connection per destination, used when keep-alive is on), and the
  adapter's `SessionFacts` on `ExecutionOutput` (echoed / repeated datagram
  payloads, ICMP unreachable). Manual Send never uses channels.
- Combinations without a defined unit are refused before traffic with a typed
  `Refusal`: mixed unit kinds, client-streaming and bidirectional gRPC, gRPC
  with server reflection, SSE with reconnection, UDP through MASQUE, and HTTP
  or gRPC through HBONE in persistent mode.
- Runs of different unit kinds are never compared.

## Consequences
- Every protocol Anvil sends can be load tested except the refused ones,
  with counts that match independent ground truth (fixtures, and the real
  gateway's transaction log in the streams lab).
- A mixed chain such as an HTTP login followed by a WebSocket session cannot
  run as one plan; it needs two plans until a unit model for setup steps
  exists.
- Long-lived stream load (sessions held open while messages flow at a rate)
  remains a separate, future load action.
