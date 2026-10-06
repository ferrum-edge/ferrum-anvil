# Diagnostics

Anvil explains what happened to a request from evidence it actually
observed. It does not paraphrase status codes. This page covers the evidence
model, the confidence rules, the Ferrum Edge compatibility catalogs, and what
Anvil deliberately does **not** claim.

## Outcome model

Every execution record keeps separate dimensions:

| Dimension | Values | Meaning |
|---|---|---|
| Transport | `completed`, `failed`, `incomplete`, `canceled`, `unknown` | Did the exchange finish on the wire? |
| Application | `success`, `failure`, `not_evaluated` | Did the protocol report success (HTTP status, gRPC status, SOAP fault, GraphQL errors)? |
| Assertions | `pass`, `fail`, `not_run` | The user's checks. |
| Dispatch | `not_dispatched`, `sent`, `may_have_been_sent`, `unknown` | Could the peer have acted on the request? Derived from bytes written and protocol signals, never from error text. |

Examples: an HTTP 200 whose body ends early is an application `success`
with transport `incomplete`. A gRPC call with HTTP 200 and `grpc-status: 14`
is an application failure. A graceful WebSocket close is not a failure.

## Findings

A finding comes from a deterministic rule (`crates/anvil-diagnostics/src/rules/`)
and is worded from `catalog/diagnostics/findings.en.json`. Each finding has:

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

Wording shared by several findings lives in the catalog's `fragments` map.
A rule adds a fragment to a finding's alternatives only when the evidence
calls for it, and a fragment never changes a finding's confidence. For
example, a TCP close with no PROXY header sent gains "the listener may
require a PROXY protocol header"; a 400, TLS alert or close right after
Anvil sent one gains "the listener may not expect a PROXY protocol header"
(see [protocols.md §3.10](protocols.md)).

The catalog has 182 finding codes. The status bar shows the catalog version,
and every record names the findings catalog and Ferrum catalog it used.

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
| `ferrum.*` | 30 | trusted marker tokens, outcome matches, ambiguity, unverified/absent/conflicting/unknown markers, missing release catalog; the gateway's own diagnostic records and their lookup outcomes (`ferrum.detail.*`, G01) |
| `app.*`, `auth.*` | 13 | gRPC status, SOAP fault, GraphQL errors; locally observed token expiry; JWT-SVID local checks (expired, wrong audience, invalid) and a 401 after sending one |
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
verification stays on. SPIFFE failures are local, confirmed decisions Anvil
makes before sending any request byte (dispatch `not_dispatched`, scope
`client_to_peer`):

| Code | When |
|---|---|
| `client.tls.spiffe_id_mismatch` | valid SVID of the trusted trust domain, but not the expected ID |
| `client.tls.untrusted_trust_domain` | the SVID is in another trust domain, whether or not its chain anchors in the profile's bundle |
| `client.tls.invalid_svid` | no URI SAN, several URI SANs, a malformed SPIFFE ID, a CA leaf or an invalid key usage |
| `client.tls.untrusted_issuer` | the chain does not anchor in the bundle (and names no other trust domain) |

`client.tls.sni_override` (info) notes which SNI came from the profile and
which identity was checked. `client.tls.name_mismatch` lists the override as
an alternative when one was used. The bypass warning
(`client.tls.verification_bypassed`) also records what the SPIFFE check would
have concluded.

## Mesh HBONE tunnels

With an HBONE proxy profile the path has two legs: Anvil ↔ HBONE endpoint
(the tunnel, scope `forward_proxy`) and endpoint ↔ destination. Tunnel-leg
failures have their own failure kinds and `hbone.*` findings, and dispatch is
`not_dispatched`. Because the destination was never contacted, **no rule
describes it as failed**: there is no `http.*`, `client.connect.*`,
`client.dns.*`, `ferrum.*` or `request.processing_uncertain` finding.

| Code | Leg / decision | Confidence |
|---|---|---|
| `hbone.endpoint_unreachable` | Anvil could not resolve or connect to the endpoint | confirmed |
| `hbone.endpoint_identity_rejected` | **Anvil** rejected the endpoint's certificate (SPIFFE mismatch, untrusted trust domain, invalid SVID, untrusted issuer) | confirmed |
| `hbone.client_svid_required` | the **endpoint** sent `certificate_required` and Anvil presented no SVID | confirmed |
| `hbone.client_svid_rejected` | the **endpoint** answered a presented SVID with a client-certificate alert (or TLS 1.3 `handshake_failure` after Anvil's Finished) | likely |
| `hbone.closed_after_certificate_request` | TLS 1.3: certificate requested, Anvil finished, the connection closed before any `CONNECT` answer and no alert was readable | likely (no SVID) / unknown (SVID presented) |
| `hbone.endpoint_tls_failed` | any other mTLS failure | unknown (timeout: confirmed; version mismatch: likely) |
| `hbone.tunnel_refused` | the endpoint answered `CONNECT` with a non-2xx, non-5xx status | confirmed that the endpoint refused (likely when its identity was not verified) |
| `hbone.tunnel_unavailable` | the endpoint answered `CONNECT` with a 5xx; no leg claim | confirmed that it answered (likely when its identity was not verified); cause unknown |
| `hbone.tunnel_protocol_error` | HTTP/2 failure before a `CONNECT` answer (no `h2`, reset, GOAWAY, deadline) | unknown (deadline: confirmed) |
| `hbone.udp_tunnel_ended` | UDP tunnel: the endpoint ended the datagram tunnel before Anvil did. Severity: `END_STREAM` warning; `RST_STREAM`/`GOAWAY` or a lost connection error; any end during a DTLS handshake inside the tunnel error (it failed the handshake) | confirmed that the endpoint sent the frame over a verified endpoint (likely otherwise); unknown for a lost connection; never why |
| `hbone.udp_record_truncated` | UDP tunnel: the stream ended inside a `[u16 length][payload]` record; the partial record was discarded | confirmed (likely over an unverified endpoint) |
| `hbone.udp_datagram_too_large` | UDP tunnel: Anvil refused a datagram over the 65,535 bytes one record carries (scope `local_client`) | confirmed |

**CONNECT refusals.** Anvil quotes the endpoint's public body (its JSON
`error` string, bounded) and never claims a precise mesh-policy cause.
Several admission reasons share one public response: Ferrum Edge uses one
body for an unauthenticated peer, a withdrawn trust and a revoked SVID.
0.9.5 and 0.9.7 answer a destination the endpoint does not terminate with the
same `404 {"error":"Not Found"}` as a route miss; 0.9.8 and later answer it with the
documented `403 {"error":"HBONE relay destination not allowed"}`, and a
terminator without its mesh configuration with
`503 {"error":"HBONE relay not ready"}`. The refusal is attributed to the
endpoint as `confirmed` only when the endpoint's identity was verified,
because it arrives on that authenticated HTTP/2 connection before any tunnel
exists. A verification bypass on the endpoint's TLS profile produces
`client.tls.verification_bypassed` with scope `forward_proxy`.

**UDP (datagram) tunnels** add catalog fragments, never a claimed cause:

- A refusal lists why an endpoint may not relay a UDP tunnel (not an inbound
  mesh listener, a destination it does not terminate, no authenticated peer,
  no datagram-tunnel support: 404/405) or could not open it (DNS, socket,
  session limit). UDP has no handshake, so a 5xx says nothing about a
  listener at the destination.
- Silence (`udp.no_response`) adds that the relay sends no acknowledgement
  and that ICMP errors reach the endpoint's socket, not Anvil.
- The endpoint sends no reason when it ends a tunnel. Ferrum Edge ends its
  relay with `END_STREAM` after an ICMP error on its socket, at its idle
  limit, or on a revoked admission, so `hbone.udp_tunnel_ended` keeps those
  as alternatives and says it does not prove the destination is down. An end
  mid-session never produces an `exchange.*` finding: the stream belongs to
  the endpoint.
- With DTLS inside the tunnel, the channel counts DTLS records (the finding
  says so). An end during the DTLS handshake is what failed it, so there is
  no `client.dtls.*` or `exchange.*` finding about the DTLS peer, and a DTLS
  handshake timeout lists the relay's missing acknowledgement as an
  alternative. DTLS verification failures and peer alerts stay findings about
  the DTLS peer (`client.tls.*`, `client.dtls.handshake_failed`), never about
  the endpoint.

The untrusted-destination rule applies here too: Ferrum markers are only
interpreted for a destination declared as a Ferrum gateway, and `hbone.*`
findings make no Ferrum-specific attribution.

## SPIFFE Workload API and JWT-SVIDs

Identities from the Workload API ([protocols.md §3.11](protocols.md)) are
obtained before anything is sent, so their failures are local observations:
scope `local_client`, dispatch `not_dispatched`, no destination blamed. The
Workload API call is recorded as typed evidence: the RPC, the endpoint and
where the setting came from, the typed result (I/O error kind, deadline, gRPC
status and the server's bounded message) and, when no identity was issued,
the uid this process presents in the socket's peer credentials (what the
server attests).

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
evidence, and names a failed check only as one alternative. It never claims
the verifier's reason: Ferrum Edge's `jwks_auth` answers an expired token, a
wrong audience and an unknown key with the same `401 {"error":"Invalid or
unrecognized JWT"}`, and a backend can send that body too (lab scenario
`WL-009` in [lab/workload.md](lab/workload.md)).

## 0-RTT early data and `425 Too Early`

With the early-data opt-in ([protocols.md §3.12](protocols.md)) every attempt
carries `early_data` evidence: whether a session ticket was offered and the
server resumed, whether early data was offered and accepted, the bytes
written before the handshake completed, whether the transport re-sent
rejected early data, which tickets arrived, and why early data was not used.
The `protocol.early_data` rule reads only that evidence and the observed
status:

| Code | When | Confidence, scope |
|---|---|---|
| `early_data.accepted` | the request was written as early data and the server accepted it | confirmed, `client_to_peer`, info. "Does not prove" says that early data can be replayed and that the server's anti-replay is invisible to the client. |
| `early_data.rejected` | early data was offered and rejected; the request was re-sent after the handshake | confirmed, info. The re-send is the protocol delivering discarded data, not an application retry; why it was rejected stays an alternative. |
| `early_data.no_ticket` | a completed full handshake under the opt-in delivered no session ticket | confirmed that none arrived during the exchange, info; not that the server never issues them |
| `early_data.ticket_without_early_data` | a resumed session whose ticket did not allow early data | confirmed, info |
| `request.too_early` | an attempt was answered `425 Too Early` | confirmed that the server declined to process it, **scope unknown**: a gateway's early-data method policy and a backend that saw `Early-Data: 1` give the same public answer. Names the retry outcome (one retry after the handshake, only for requests eligible under the opt-in). For a request that did not travel as early data it says so and lists the alternatives (a server that counts requests racing the handshake as early data, an `Early-Data: 1` request header, another component). |

A request that missed the 0-RTT window (the handshake completed before it
was written) is recorded as `handshake_completed_first` and never gets
`early_data.accepted`. For a declared Ferrum gateway, a final
`425 {"error":"Method not allowed in 0-RTT early data"}` also matches the
release catalog's `gateway.admission.early_data_rejected` (HTTPS header path
and HTTP/3 0-RTT path), capped at likely because a backend can send the same
body.

## Ferrum Edge catalogs (`catalog/ferrum/<compatibility-id>/outcomes.json`)

Anvil embeds one source-audited catalog per supported gateway release:

| Compatibility id | Release | Outcomes | Audit |
|---|---|---|---|
| `ferrum-edge-0.9.11` (default; hosted qualification recorded) | v0.9.11, `c764084` | **553 carried IDs** | [audit/gateway-0.9.11-delta.md](audit/gateway-0.9.11-delta.md) (source delta; hosted qualification recorded) |
| `ferrum-edge-0.9.10` | v0.9.10, `ee040d5` | **553** | [audit/gateway-0.9.10-delta.md](audit/gateway-0.9.10-delta.md) (delta on top of the 0.9.9 audit) |
| `ferrum-edge-0.9.9` | v0.9.9, `234717c` | **553** | [audit/gateway-0.9.9-delta.md](audit/gateway-0.9.9-delta.md) (delta on top of the 0.9.8 audit) |
| `ferrum-edge-0.9.8` | v0.9.8, `e27f210` | **540** | [audit/gateway-0.9.8-delta.md](audit/gateway-0.9.8-delta.md) (delta on top of the 0.9.7 audit) |
| `ferrum-edge-0.9.7` | v0.9.7, `8fed134` | **538** | [audit/gateway-0.9.7-delta.md](audit/gateway-0.9.7-delta.md) (delta on top of the 0.9.5 audit) |
| `ferrum-edge-0.9.5` | v0.9.5, `20e7603` | **528** | [audit/gateway-source-audit.md](audit/gateway-source-audit.md) |

Each catalog inventories the release's client-observable outcomes, the public
`X-Gateway-Error` tokens (**7** in 0.9.5 and 0.9.7; 0.9.8 adds
`request_timeout`, so **8**, unchanged in 0.9.9, 0.9.10 and 0.9.11), the **19**
internal error classes, the gateway-written headers, and each outcome's
`shared_signal_with` siblings. Its `drift` section records the reconciliation
with the previous release, and `marker_semantics` holds the release-specific
sentences Anvil adds to token findings.

Anvil matches a response against a catalog only when the destination matches
a user-declared **Ferrum gateway integration profile**, and only against the
catalog whose id equals the profile's `compatibility_id`:

- After redirects, the destination is the origin that produced the final
  response. Its own profile (or none) and its own `require_verified_tls`
  apply, never those of the original request URL.
- Without a profile, a Ferrum-looking header yields `ferrum.marker.unverified`,
  because any server can send it.
- A profile whose `compatibility_id` has no embedded catalog never borrows
  another release's. Anvil reports `ferrum.catalog.unavailable` (confidence
  unknown), does no outcome matching, and reads a token only with the coarse
  meaning every audited release shares.

### JSON-RPC outcomes (MCP and A2A gateways)

The `mcp_gateway` and `a2a_gateway` outcomes answer with a JSON-RPC error
whose body echoes the request's id (`{"jsonrpc":"2.0","id":{id},"error":…}`),
so no fixed body pattern matches them. For a JSON-RPC error response (MCP
POSTs, and any JSON-RPC API; an MCP execution reads it out of an event-stream
answer), when no body pattern matched, Anvil compares the status, the error
`code`, the `message` and the `data.gateway` marker with each such outcome's
catalog body:

- **All match** (a marker the catalog body shows must be present; one it does
  not show is allowed): `ferrum.outcome` with the outcome's text, capped at
  `likely` (a server behind the gateway could send the same bytes). Several
  outcomes: `ferrum.outcome_ambiguous`.
- **Only the code** (the body's code, or one the outcome's catalog notes list
  for the same condition, e.g. `-32601` for `plugin.mcp_gateway.unknown_item`):
  `ferrum.jsonrpc_code` (warning, confidence `unknown`), listing the outcomes
  that use the code and saying the gateway may not have produced it: upstream
  MCP servers use the same standard codes.

Independently of any gateway, a JSON-RPC error in a 2xx body is an
application failure (`app.jsonrpc_error`, with the code's JSON-RPC 2.0
meaning), and an MCP tool result with `isError: true` is the tool's own
failure (`app.mcp_tool_error`, scope upstream application).

### Confidence ceilings (why most gateway findings say "likely")

- On v0.9.5 and v0.9.7 a backend can inject `X-Gateway-Error` and
  `X-Gateway-Upstream-Status` on some paths (native gRPC responses, plugin
  reject maps). v0.9.8 and later strip a backend's copies at every backend response
  boundary, but a plugin rejection can still carry any value and any
  non-Ferrum endpoint can send the headers. Marker-derived claims are
  therefore capped at **likely**, even for trusted gateways over verified
  TLS. The same cap applies to a release without a catalog.
- A trusted profile used over plain HTTP (lab use) is also capped at likely.
- The only path above *likely* is the gateway's own diagnostic record (G01,
  Ferrum Edge v0.9.9 and later): a lookup the profile configures, whose
  record binds to this exact response, with the request and the lookup both
  over verified TLS or a direct loopback connection. Its `ferrum.detail.*`
  finding can then be `confirmed`; the marker and catalog findings keep their
  own ceiling beside it. See
  [Gateway diagnostic references](#gateway-diagnostic-references-g01).

### The tokens are coarse, and stay coarse

| Token | What Anvil says | What Anvil never claims from the token alone |
|---|---|---|
| `connection_failure` | The gateway could not set up a connection to the configured backend (DNS, TCP, TLS, pool, …). | That TLS failed; that DNS failed; that your client certificate is wrong (the gateway uses its own identity). |
| `backend_timeout` | The gateway's backend deadline elapsed (any 504 gets this token, except a 0.9.8 or later route timeout that no backend held). | That the backend received the request (on v0.9.5 a pooled-connection bug can strand it; on v0.9.7 a Gateway API route's request timeout can fire before dispatch); that the backend is slow rather than unreachable. |
| `request_timeout` (0.9.8 and later) | The route's total request timeout expired before any backend held the attempt (upload, gateway processing or admission, retry backoff). | That the backend is slow; which phase used the time; that no earlier attempt reached a backend. |
| `backend_error` | The backend path failed or the gateway refused locally (buffer capacity, in-flight limit, egress policy, …). | That the backend returned this error. |
| `circuit_breaker_open` | The gateway's breaker for this backend is open. | That the backend is down right now. |
| `overload` | The gateway shed load, was draining, or hit the response-transform ceiling (502). | CPU pressure. |
| `config_stale` | The data plane's configuration fence is stale. | Which configuration change is missing. |
| `concurrency_limit` | An adaptive or static concurrency limit rejected the request. | The limit value or the load cause. |

A missing marker does not prove the response came from the backend
(`ferrum.marker.absent` explains this). A 403 alone never proves a WAF:
WAF and bot-detection default bodies are byte-identical, and backend 403s
look the same.

<a id="adopting-the-gateway-diagnostic-reference-g01"></a>

## Gateway diagnostic references (G01)

Ferrum Edge v0.9.9 is the first release with G01 (`ferrum-edge/ferrum-edge#5767`;
#5845, #5857/#5862 and #5868). With `FERRUM_DIAGNOSTIC_REFS=errors` or `all`
(the default is `off`) the gateway stamps the error responses it authors with
`X-Ferrum-Diagnostic-Ref` (`fd1_<32 hex>`, or `fd2_<8 hex replica>_<32 hex>`
with replica tagging), and resolves a reference only through the
authenticated admin lookup `GET /diagnostics/v1/refs/<ref>`, which answers a
`ferrum.diagnostic_ref.v1` record: the public token and status, the client
protocol, the granular `error_class`, the body-streaming class, the
rejecting policy or route-timeout phase, how far the request reached a
backend, the matched `proxy_id` and backend origin, each attempt's outcome
and a coarse duration bucket. The record never holds bodies, headers, paths,
credentials or client addresses. The contract, and how it differs from the
original proposal, is in
[g01-gateway-diagnostic-contract.md](g01-gateway-diagnostic-contract.md).

### Configuring the lookup

A Ferrum gateway profile's **Diagnostic reference lookup** (`detail` in the
profile: `base_url`, `credential`, optional `namespace`) names the gateway's
admin listener and the token Anvil sends to it:

- The token is a dedicated, short-lived admin JWT signed with the gateway's
  primary admin key, with role `viewer`, a `scope` that includes
  `diagnostics:read` and an `ns` claim naming the gateway's namespace. The
  admin role implies neither the scope nor the claim, and a token signed with
  the read-only viewer key never holds a scope. Never use a general admin
  token.
- The token is a sensitive value, stored like any profile credential: a
  vault secret, or a template such as `{{FERRUM_DIAGNOSTICS_TOKEN}}` from an
  environment. Anvil resolves it for the lookup only, sends it only to the
  configured admin listener (never to the gateway's proxy listener), adds it
  to the execution's redactor, and never logs it or writes it to a record. A
  safe-share export replaces a literal with a placeholder; load workers never
  receive the lookup at all.
- With `namespace` set, a record of another namespace is not used.
- The admin URL must be `https` (always verified: the request's TLS profile
  contributes only its trust roots, never a verification bypass, SNI override,
  SPIFFE expectation or client identity), or plain `http` to a loopback
  address literal (`127.0.0.0/8` or `::1`, not `localhost`). Anything else is
  refused before a byte is sent. Only an `https` lookup may cross the
  request's forward proxy, and redirects from the admin listener are never
  followed.
- A bundle import drops every gateway profile's lookup and says so: configure
  it again with your own admin URL and token. A full backup restore keeps
  it, but paused (records say "diagnostic lookup paused") until you allow
  the restored workspace on this device: Allow on this device in the
  workspace settings' Auth tab, or `anvil workspace allow-device-identity`,
  the same seal as this device's workload identity. When
  several profiles match one destination, the first one is used and the
  record names the others (an import that adds such a profile is reported
  too).

### When Anvil looks a reference up, and what it believes

For the final response of a request to a destination matching the profile,
Anvil looks up a well-formed reference as soon as the response arrives,
through the engine transport and the request's DNS settings. A lookup is
bounded on its own: connect within 2 s and everything within 5 s (or the
request's shorter timeouts), including one retry 250 ms later when the
record has no detail yet. The header alone is never evidence: a backend, a plugin or a server
that is not Ferrum Edge can send it. A destination without a profile is never
looked up, and a malformed reference (or several different ones) is reported
without a lookup.

A record is gateway evidence only when it is a valid
`ferrum.diagnostic_ref.v1` body (every key the schema requires, closed
vocabularies only, checked against the pinned schema) that **binds to this
response**: the same reference (and replica), status, `X-Gateway-Error` value
or none, a known client protocol and, when the profile names one, namespace,
created while the recorded attempt was in flight (five minutes of clock
difference allowed). A record whose error class is not in the pinned
vocabulary is shown but capped at *likely*. Its finding cites the record as
`gateway_detail` evidence and is `confirmed` only when both the request and
the lookup used verified TLS or a direct loopback connection (nothing else
could have answered on either path); otherwise it is `likely`. The marker and
catalog findings stay beside it with their own ceiling, for comparison.

| Code | When | Confidence |
|---|---|---|
| `ferrum.detail.failure` | The record classifies the failure: an `error_class` (scope from the class: gateway to upstream for connection, TLS, DNS and timeout classes), a body-streaming class or a route-timeout phase. Names the TLS failure when an attempt has one, the dispatch and every attempt. | confirmed (likely off verified TLS or loopback) |
| `ferrum.detail.rejected` | A plugin (with its phase), a gateway policy, admission control or routing refused the request. | as above |
| `ferrum.detail.backend_response` | A backend answered and the gateway relayed its outcome. | as above |
| `ferrum.detail.authored` | The record names no failure, refusal or backend answer (for example, detail not recorded yet). | as above |
| `ferrum.detail.mismatch` | A valid record that describes another response (field by field). Not used. | conflicting_evidence |
| `ferrum.detail.refused` | `401`/`403`: the token is invalid, or lacks the scope or the `ns` claim. | confirmed that it was refused |
| `ferrum.detail.unavailable` | `404`: expired, evicted, outside the token's namespaces, minted by another replica (the owner hint is listed), unknown or forged, or references off. Ferrum Edge answers all of these alike. | unknown |
| `ferrum.detail.lookup_failed` | `429`, a transport failure, another status, or a body Anvil does not accept. | unknown |
| `ferrum.detail.no_reference` | A gateway-marked error without a reference (references off, a release before v0.9.9, a replayed cached response). | unknown |
| `ferrum.detail.invalid_reference` | The header is not a reference Ferrum Edge mints. | unknown |

None of the outcomes after the first four adds `gateway_detail` evidence or
raises any other finding. A record whose final attempt failed before dispatch
but whose earlier attempt reached a backend says so (TRUST-008), and Anvil
never uses `backend_dispatch` to relax the never-auto-replay rule.

### How it is verified

- Unit tests for reference parsing, the closed vocabularies, binding and the
  confidence ceiling (`crates/anvil-diagnostics/src/gateway_detail.rs`,
  `src/rules/ferrum_detail.rs`); the contract drift test checks Anvil's
  vocabularies against the pinned schema and runs its fixtures through
  Anvil's reader.
- Engine tests with a fake admin listener
  (`crates/anvil-engine/tests/diagnostic_ref.rs`): a bound record,
  cross-tenant and under-scoped lookups (TRUST-009), expired references
  (TRUST-010), spoofed and replayed references (TRUST-011), references off,
  rate limits and owner-replica hints, and that the token never leaves the
  lookup.
- The lab's `core` profile on v0.9.9 and later turns references on and signs
  lookup tokens itself (G01-001, G01-002, TRUST-009, TRUST-010, TRUST-011;
  see [lab/README.md](lab/README.md#g01-diagnostic-references-core-profile)).

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

- Unit tests for each rule family and for catalog drift: every rule code has
  wording, every catalog on disk is embedded and internally consistent, and
  the desktop profile dialog offers exactly the embedded releases.
- Per-release selection tests: a 0.9.7-only signal is not matched against
  the 0.9.5 catalog, `request_timeout` (0.9.8 and later) is unknown to the older
  catalogs, outcomes new in 0.9.9 (the `;` path-parameter refusal, MCP tool-call
  rate limits) do not match the 0.9.8 catalog, the `ai_prompt_shield` MCP
  refusals new in 0.9.10 (non-UTF-8 charset, unparseable body) match the
  0.9.10 and 0.9.11 catalogs, and the v0.9.9 content-encoding refusal matches
  0.9.9, 0.9.10 and 0.9.11 but not 0.9.8. Release notes follow the profile's
  release, and an unknown release gets no catalog.
- Engine scenario tests over real sockets (`crates/anvil-engine/tests`).
- The real-gateway lab ([lab/](lab/)), run against every supported release
  (`anvil-lab --release v0.9.5 …`; the default is the `RELEASE.lock` pin,
  v0.9.11, with hosted qualification recorded). Every lab profile's trusted profile declares the running release's
  compatibility id, and the lab refuses to run a release without its own
  catalog. Every scenario runs trusted and untrusted: no `ferrum.*`
  gateway attribution may appear when the destination is untrusted, and
  lookalikes (backend 403/5xx/404) must not be attributed to the gateway.
  Operator log `error_class` values are used only as ground truth, never as
  engine input.
