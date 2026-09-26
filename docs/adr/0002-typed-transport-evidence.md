# ADR 0002: Instrumented transport with typed phase evidence

## Context
Diagnostics must rest on what actually happened, not on reworded status codes
or error strings (agent prompt: "A message containing 'handshake' is not
sufficient proof of dispatch safety").

## Decision
- Build on hyper 1.x client connections (`try_send_request`), rustls 0.23
  (ring provider), tokio-rustls, quinn/h3 and hickory-resolver. Wrap every
  socket in `CountingIo`.
- Record phases (DNS, connect, TLS, protocol handshake, request write, await
  headers, body) with status `completed | failed | timed_out | canceled |
  reused | not_applicable`. A pooled connection reports `reused`, never a
  zero-length handshake.
- Capture TLS evidence with an observing certificate verifier and client-cert
  resolver: peer chain, verification result or bypass (with the would-have-
  failed reason), whether a client certificate was requested or presented,
  and received alerts. A `TlsErrorTap` preserves typed rustls errors that h2
  would otherwise flatten into strings.
- Derive `DispatchState` (not_dispatched / sent / may_have_been_sent /
  unknown) from bytes written, `TrySendError::take_message()` and HTTP/2
  `REFUSED_STREAM`.

## Consequences
- The safe-retry and "never replay a possibly processed non-idempotent
  request" rules become decidable.
- Evidence for the client-to-peer leg is exact. Evidence about the
  gateway-to-upstream leg can only come from the gateway (see ADR 0003 and G01).
