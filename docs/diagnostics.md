# Diagnostics

Anvil explains what happened to a request from evidence it actually
observed. It does not paraphrase status codes. This document covers the
evidence model, the confidence rules, the Ferrum Edge compatibility catalog,
and what Anvil deliberately does **not** claim.

## Outcome model

Every execution record keeps separate dimensions:

| Dimension | Values | Meaning |
|---|---|---|
| Transport | `completed`, `failed`, `incomplete`, `canceled`, `unknown` | Did the exchange finish on the wire? |
| Application | `success`, `failure`, `not_evaluated` | Did the protocol report success (HTTP status, gRPC status, SOAP fault, GraphQL errors)? |
| Assertions | `pass`, `fail`, `not_run` | The user's checks. |
| Dispatch | `not_dispatched`, `sent`, `may_have_been_sent`, `unknown` | Could the peer have acted on the request? This is derived from bytes written and protocol signals, never from error text. |

An HTTP 200 with an incomplete body is `completed`/`success` for headers but
`incomplete` for transport. A gRPC call with HTTP 200 and `grpc-status: 14`
is an application failure. A graceful WebSocket close is not a failure.

## Findings

A finding is produced by a deterministic rule (`crates/anvil-diagnostics/src/rules/`)
and worded from `catalog/diagnostics/findings.en.json`. Each finding has:

- **confidence**: `confirmed` (directly observed), `likely` (strong but
  indirect or spoofable evidence), `unknown` (the evidence cannot separate
  the listed causes) or `conflicting_evidence`;
- **scope**: which leg the claim is about (`local_client`, `forward_proxy`,
  `client_to_peer`, `gateway_admission`, `gateway_to_upstream`,
  `upstream_application`, `response_delivery`, `unknown`);
- **owner**: who can act (caller, network, proxy operator, gateway operator,
  backend owner, …);
- **evidence**: the observed facts with their source (transport, TLS,
  headers, body, timing, local config);
- **does not prove**, **alternatives**, **remediation** and **confirm with**.

Wording shared by several findings lives in the catalog's `fragments` map. A
rule attaches a fragment to a finding's alternatives only when the evidence
calls for it (for example "the listener may require a PROXY protocol header"
on a TCP close, or a close of a new HTTP-family connection, when Anvil sent no
header, and "the listener may not expect a PROXY protocol header" on a 400, a
TLS alert or a close right after Anvil sent one; see
[protocols.md §3.10](protocols.md)); a fragment never changes a finding's
confidence.

The catalog has 168 finding codes (catalog version shown in the app status
bar; every record names the findings catalog and the Ferrum catalog it used):

| Family | Codes | Examples |
|---|---|---|
| `local.*` | 19 | unresolved variable, lint blocked, vault locked, invalid client identity, SPIFFE Workload API unreachable / no identity issued / failed; nothing was sent |
| `client.*` | 39 | DNS, connect, TLS (untrusted issuer, name mismatch, expired, client cert required/rejected, ALPN, SPIFFE ID mismatch, untrusted trust domain, invalid SVID, SNI override), QUIC/H3, DTLS |
| `proxy.*` | 4 | forward-proxy CONNECT failures and authentication |
| `hbone.*` | 12 | mesh HBONE tunnel leg: endpoint unreachable, mTLS split by leg, CONNECT refused/unavailable, HTTP/2 tunnel errors; UDP datagram tunnels: ended by the endpoint, truncated record, datagram over the record limit |
| `exchange.*` | 11 | write failures, header timeout, HTTP/2 GOAWAY/RST/REFUSED_STREAM, closed before response |
| `response.*` | 4 | incomplete body, idle/total body timeouts, stream reset mid-body |
| `request.*` | 5 | canceled; processing uncertain; an earlier attempt may have processed; `425 Too Early` with the retry outcome |
| `early_data.*` | 4 | TLS 1.3 / QUIC 0-RTT: accepted (with the replay note), rejected and re-sent by the transport, no session ticket, tickets without early data |
| `http.*` | 14 | generic status explanations (fallbacks, listed after hop-specific findings) |
| `ferrum.*` | 18 | trusted marker tokens, outcome matches, ambiguity, unverified/absent/conflicting/unknown markers, missing release catalog |
| `app.*`, `auth.*` | 11 | gRPC status, SOAP fault, GraphQL errors; locally observed token expiry; JWT-SVID local checks (expired, wrong audience, invalid) and a 401 after sending one |
| `grpc.*`, `grpc_web.*` | 2 | invalid length-prefixed framing; a gRPC-Web response with no trailer frame |
| `masque.*` | 5 | CONNECT-UDP tunnel: proxy refused, no extended CONNECT or HTTP/3 datagrams, SETTINGS never arrived, abnormal end |
| `ws.*`, `sse.*`, `tcp.*`, `udp.*`, `dtls.*` | 20 | close codes, idle/cancel, abnormal close, WebSocket permessage-deflate (offered but not negotiated, a refused extension answer, compressed frames never negotiated, undecodable data, the local limit reached after decompression), no UDP response observed, PROXY header possibly rejected |

## TLS identity: host names, SPIFFE IDs and SNI

Every TLS observation (HTTPS, raw TLS, WebSocket, gRPC, SSE, QUIC, DTLS and
the HBONE endpoint's mTLS) records which identity the verifier checked and
what the peer presented:

| Evidence | Meaning |
|---|---|
| `tls.identity_check` | `host_name` (RFC 6125, the default), `spiffe_id` (exact X.509-SVID ID) or `spiffe_trust_domain` |
| `peer.spiffe_id` | the leaf's single `spiffe://` URI SAN, recorded for any server that presents one, verified or not |
| `tls.sni` | the SNI actually sent (none for an IP address) |
| `tls.server_name_override` | the SNI / verification name came from the TLS profile, not the URL |

SPIFFE verification replaces host-name matching **only** when a TLS profile
sets an expected server SPIFFE ID or trust domain; otherwise host-name
verification stays on. Its failures are local, confirmed decisions made by
Anvil before any request byte (dispatch `not_dispatched`, scope
`client_to_peer`):

| Code | When |
|---|---|
| `client.tls.spiffe_id_mismatch` | valid SVID of the trusted trust domain, but not the expected ID |
| `client.tls.untrusted_trust_domain` | the SVID is in another trust domain, whether or not its chain anchors in the profile's bundle |
| `client.tls.invalid_svid` | no URI SAN, several URI SANs, a malformed SPIFFE ID, a CA leaf or an invalid key usage |
| `client.tls.untrusted_issuer` | the chain does not anchor in the bundle (and names no other trust domain) |

`client.tls.sni_override` (info) notes which SNI was sent from the profile
and which identity was checked; `client.tls.name_mismatch` lists the override
as an alternative when it was used. The bypass warning
(`client.tls.verification_bypassed`) also records what the SPIFFE check would
have concluded.

## Mesh HBONE tunnels

With an HBONE proxy profile the path has two legs: Anvil ↔ HBONE endpoint
(the tunnel, scope `forward_proxy`) and endpoint ↔ destination. Tunnel-leg
failures carry their own failure kinds and `hbone.*` findings, dispatch is
`not_dispatched`, and **no rule describes the inner destination as failed**
(no `http.*`, `client.connect.*`, `client.dns.*`, `ferrum.*` or
`request.processing_uncertain` finding): the destination was never contacted.

| Code | Leg / decision | Confidence |
|---|---|---|
| `hbone.endpoint_unreachable` | Anvil could not resolve or connect to the endpoint | confirmed |
| `hbone.endpoint_identity_rejected` | **Anvil** rejected the endpoint's certificate (SPIFFE mismatch, untrusted trust domain, invalid SVID, untrusted issuer) | confirmed |
| `hbone.client_svid_required` | the **endpoint** sent `certificate_required` and Anvil presented no SVID | confirmed |
| `hbone.client_svid_rejected` | the **endpoint** answered a presented SVID with a client-certificate alert (or TLS 1.3 `handshake_failure` after Anvil's Finished) | likely |
| `hbone.closed_after_certificate_request` | TLS 1.3: certificate requested, Anvil finished, the connection closed before any `CONNECT` answer and no alert was readable | likely (no SVID) / unknown (SVID presented) |
| `hbone.endpoint_tls_failed` | any other mTLS failure | unknown (timeouts confirmed) |
| `hbone.tunnel_refused` | the endpoint answered `CONNECT` with a non-2xx, non-5xx status | confirmed that the endpoint refused (likely when its identity was not verified) |
| `hbone.tunnel_unavailable` | the endpoint answered `CONNECT` with a 5xx; no leg claim | confirmed that it answered, cause unknown |
| `hbone.tunnel_protocol_error` | HTTP/2 failure before a `CONNECT` answer (no `h2`, reset, GOAWAY, deadline) | unknown (deadline confirmed) |
| `hbone.udp_tunnel_ended` | UDP tunnel: the endpoint ended the datagram tunnel before Anvil did (`END_STREAM`: warning; `RST_STREAM`/`GOAWAY` or a lost connection: error) | confirmed that the endpoint sent the frame over a verified endpoint (likely otherwise); unknown for a lost connection; never why |
| `hbone.udp_record_truncated` | UDP tunnel: the stream ended inside a `[u16 length][payload]` record; the partial record was discarded | confirmed (likely over an unverified endpoint) |
| `hbone.udp_datagram_too_large` | UDP tunnel: Anvil refused a datagram over the 65,535 bytes one record carries (scope `local_client`) | confirmed |

A `CONNECT` refusal quotes the endpoint's public body (its JSON `error`
string, bounded) and never claims a precise mesh-policy cause: several
admission reasons share one public response (Ferrum Edge uses one body for an
unauthenticated peer, a withdrawn trust and a revoked SVID, and 0.9.7 answers
a destination it does not terminate with the same `404 {"error":"Not Found"}`
as a route miss). The attribution to the endpoint is `confirmed` only when the
endpoint's identity was verified, because the refusal arrives on that
authenticated HTTP/2 connection before any tunnel exists. A verification bypass
on the endpoint's TLS profile produces `client.tls.verification_bypassed` with
scope `forward_proxy`.

A UDP (datagram) tunnel adds catalog fragments, never a claimed cause: a
refusal lists why an endpoint may not relay a UDP tunnel (not an inbound mesh
listener, a destination it does not terminate, no authenticated peer, no
datagram-tunnel support: 404/405) or could not open it (DNS, socket, session
limit; UDP has no handshake, so a 5xx says nothing about a listener at the
destination), and silence (`udp.no_response`) adds that the relay gives no
acknowledgement and that ICMP errors reach the endpoint's socket, not Anvil.
The endpoint sends no reason when it ends a tunnel (Ferrum Edge ends its relay
with `END_STREAM` after an ICMP error on its socket, at its idle limit, on a
revoked admission), so `hbone.udp_tunnel_ended` keeps those as alternatives
and says it does not prove the destination is down. An end mid-session never
produces an `exchange.*` finding: the stream is the endpoint's.

The untrusted-destination rule is unchanged: Ferrum markers are only
interpreted for a destination declared as a Ferrum gateway, and the `hbone.*`
findings make no Ferrum-specific attribution.

## SPIFFE Workload API and JWT-SVIDs

Identities from the Workload API ([protocols.md §3.11](protocols.md)) are
obtained before anything is sent, so their failures are local observations
(scope `local_client`, dispatch `not_dispatched`, no destination blamed), with
the Workload API call as typed evidence: the RPC, the endpoint and where the
setting came from, the typed result (I/O error kind, deadline, gRPC status and
the server's bounded message) and, when no identity was issued, the uid this
process presents in the socket's peer credentials (what the server attests).

| Code | When | Confidence |
|---|---|---|
| `local.workload_api_unavailable` | no socket, permission denied, nothing listening, not HTTP/2 gRPC, deadline | confirmed |
| `local.workload_api_denied` | `PERMISSION_DENIED`, or an OK answer without the SVID asked for | confirmed that none was issued; why is only an alternative |
| `local.workload_api_failed` | any other status (for example `UNIMPLEMENTED` from an X.509-only Workload API) or an undecodable answer | confirmed that the call failed |
| `auth.jwt_svid_expired` | `exp` (or `nbf`) fails by this machine's clock | confirmed local comparison; error when refused, warning when sent anyway |
| `auth.jwt_svid_audience_mismatch` | a configured audience is missing from `aud` | confirmed; error / warning |
| `auth.jwt_svid_invalid` | format, algorithm (`none`, HMAC), subject or bundle-signature check failed | confirmed; error / warning |
| `auth.jwt_svid_rejected` | the final status is 401 and a JWT-SVID was sent | **unknown**, scope unknown |

`auth.jwt_svid_rejected` quotes the public body, lists every local check as
evidence and names a failed check only as one alternative; it never claims
the verifier's reason. Ferrum Edge's `jwks_auth` answers an expired token, a
wrong audience and an unknown key with the same `401 {"error":"Invalid or
unrecognized JWT"}`, and a backend can send that body too (lab `WL-009`).

## 0-RTT early data and `425 Too Early`

With the early-data opt-in ([protocols.md §3.12](protocols.md)) every attempt carries
`early_data` evidence: whether a session ticket was offered and the server resumed,
whether early data was offered and accepted, the bytes written before the handshake
completed, whether the transport re-sent rejected early data, which tickets arrived,
and why early data was not used. The `protocol.early_data` rule reads only that
evidence and the observed status:

| Code | When | Confidence, scope |
|---|---|---|
| `early_data.accepted` | the request was written as early data and the server accepted it | confirmed, `client_to_peer`, info; "does not prove" says that early data can be replayed and that the server's anti-replay is invisible to the client |
| `early_data.rejected` | early data was offered and rejected; the request was re-sent after the handshake | confirmed, info; the re-send is the protocol delivering discarded data, not an application retry; why it was rejected stays an alternative |
| `early_data.no_ticket` | a completed full handshake under the opt-in delivered no session ticket | confirmed that none arrived during the exchange, info; not that the server never issues them |
| `early_data.ticket_without_early_data` | a resumed session whose ticket did not allow early data | confirmed, info |
| `request.too_early` | an attempt was answered `425 Too Early` | confirmed that the server declined to process it, **scope unknown**: a gateway's early-data method policy and a backend that saw `Early-Data: 1` give the same public answer; names the retry outcome (one retry after the handshake, only for requests eligible under the opt-in); for a request that did not travel as early data it says so and lists the alternatives (a server that counts requests racing the handshake as early data, an `Early-Data: 1` request header, another component) |

A request that missed the 0-RTT window (the handshake completed before it was written)
is recorded as `handshake_completed_first` and never gets `early_data.accepted`. For a
declared Ferrum gateway, a final `425 {"error":"Method not allowed in 0-RTT early data"}`
also matches the release catalog's `gateway.admission.early_data_rejected` (HTTPS header
path and HTTP/3 0-RTT path), capped at likely because a backend can send the same body.

## Ferrum Edge catalogs (`catalog/ferrum/<compatibility-id>/outcomes.json`)

Anvil embeds one source-audited catalog per supported gateway release:

| Compatibility id | Release | Outcomes | Audit |
|---|---|---|---|
| `ferrum-edge-0.9.7` (default for new profiles) | v0.9.7, `8fed134` | **538** | `docs/audit/gateway-0.9.7-delta.md` (delta on top of the 0.9.5 audit) |
| `ferrum-edge-0.9.5` | v0.9.5, `20e7603` | **528** | `docs/audit/gateway-source-audit.md` |

Each catalog inventories the release's client-observable outcomes, the **7**
public `X-Gateway-Error` tokens (identical in both releases: `src/retry.rs` did
not change), the **19** internal error classes, the gateway-written headers,
and each outcome's `shared_signal_with` siblings. Its `drift` section records
the reconciliation with the previous release, and `marker_semantics` holds the
release-specific sentences Anvil adds to token findings.

Anvil matches an observed response against a catalog only when the
destination matches a user-declared **Ferrum gateway integration profile**,
and only against the catalog whose id equals the profile's
`compatibility_id`. Without a profile, a Ferrum-looking header yields
`ferrum.marker.unverified`: any server can send it. A profile whose
`compatibility_id` has no embedded catalog never borrows another release's:
Anvil reports `ferrum.catalog.unavailable` (confidence unknown), does no
outcome matching, and reads a token only with the coarse meaning every audited
release shares.

### Confidence ceilings (why most gateway findings say "likely")

- On v0.9.5 and v0.9.7, `X-Gateway-Error` and `X-Gateway-Upstream-Status` can be
  injected by a backend on some paths (native gRPC responses, plugin reject
  maps). Marker-derived claims are therefore capped at **likely**, even for
  trusted gateways over verified TLS. The same cap applies to a release
  without a catalog.
- A trusted profile used over plain HTTP (lab use) is also capped at likely.
- `confirmed` gateway attribution requires a gateway-owned, authenticated
  diagnostic contract that does not exist yet (see
  `docs/g01-gateway-diagnostic-contract.md`).

### The seven tokens are coarse, and stay coarse

| Token | What Anvil says | What Anvil never claims from the token alone |
|---|---|---|
| `connection_failure` | The gateway could not set up a connection to the configured backend (DNS, TCP, TLS, pool, …). | That TLS failed; that DNS failed; that your client certificate is wrong (the gateway uses its own identity). |
| `backend_timeout` | The gateway's backend deadline elapsed (any 504 gets this token). | That the backend received the request (on v0.9.5 a pooled-connection bug can strand it; on v0.9.7 a Gateway API route's request timeout can fire before dispatch); that the backend is slow rather than unreachable. |
| `backend_error` | The backend path failed or the gateway refused locally (buffer capacity, in-flight limit, egress policy, …). | That the backend returned this error. |
| `circuit_breaker_open` | The gateway's breaker for this backend is open. | That the backend is down right now. |
| `overload` | The gateway shed load, was draining, or hit the response-transform ceiling (502). | CPU pressure. |
| `config_stale` | The data plane's configuration fence is stale. | Which configuration change is missing. |
| `concurrency_limit` | An adaptive or static concurrency limit rejected the request. | The limit value or the load cause. |

A missing marker does not prove the response came from the backend
(`ferrum.marker.absent` explains this). A 403 alone never proves a WAF,
because WAF and bot-detection default bodies are byte-identical, and backend
403s look the same.

## Ordering

Findings are ordered by severity, then specificity (hop- or phase-specific
findings before the generic `http.*` fallback), then confidence. Ordering is
only presentation; every card shows its own confidence.

## Safety rules built into remediation

- Never suggest disabling TLS verification or the WAF as a default fix.
  Verification bypass is a scoped, warned, explicit profile setting.
- Never recommend retrying a request whose dispatch state is
  `may_have_been_sent` when its method is not idempotent. The engine does
  not replay it automatically either.
- The only automatic retry after a status is the one RFC 8470 allows: a
  request eligible for early data that got `425 Too Early` is sent once more
  after the handshake, never as early data and never twice.
- Remediation names an owner. Gateway-to-backend problems go to the gateway
  operator or backend owner, not to the caller's credentials.

## How this is verified

- Unit tests for each rule family and for catalog drift (every rule code has
  wording; every catalog on disk is embedded and internally consistent; the
  desktop profile dialog offers exactly the embedded releases).
- Per-release selection tests: a 0.9.7-only signal is not matched against
  the 0.9.5 catalog, release notes follow the profile's release, and an
  unknown release gets no catalog.
- Engine scenario tests over real sockets (`crates/anvil-engine/tests`).
- The real-gateway lab (`docs/lab/*.md`), against every supported release
  (`anvil-lab --release v0.9.5 …`; the default is the `RELEASE.lock` pin,
  v0.9.7). The lab's trusted profile declares the running release's
  compatibility id. Every scenario runs trusted and
  untrusted: no `ferrum.*` gateway attribution may appear when the
  destination is untrusted. Lookalikes (backend 403/5xx/404) must not be
  attributed to the gateway. Operator log `error_class` values are used only
  as ground truth, never as engine input.
