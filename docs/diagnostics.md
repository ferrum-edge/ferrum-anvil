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

The catalog has 139 finding codes (catalog version shown in the app status
bar and in every record):

| Family | Codes | Examples |
|---|---|---|
| `local.*` | 16 | unresolved variable, lint blocked, vault locked, invalid client identity; nothing was sent |
| `client.*` | 39 | DNS, connect, TLS (untrusted issuer, name mismatch, expired, client cert required/rejected, ALPN, SPIFFE ID mismatch, untrusted trust domain, invalid SVID, SNI override), QUIC/H3, DTLS |
| `proxy.*` | 4 | forward-proxy CONNECT failures and authentication |
| `hbone.*` | 9 | mesh HBONE tunnel leg: endpoint unreachable, mTLS split by leg, CONNECT refused/unavailable, HTTP/2 tunnel errors |
| `exchange.*` | 11 | write failures, header timeout, HTTP/2 GOAWAY/RST/REFUSED_STREAM, closed before response |
| `response.*` | 4 | incomplete body, idle/total body timeouts, stream reset mid-body |
| `request.*` | 4 | canceled; processing uncertain; an earlier attempt may have processed |
| `http.*` | 14 | generic status explanations (fallbacks, listed after hop-specific findings) |
| `ferrum.*` | 17 | trusted marker tokens, outcome matches, ambiguity, unverified/absent/conflicting/unknown markers |
| `app.*`, `auth.*` | 7 | gRPC status, SOAP fault, GraphQL errors; locally observed token expiry |
| `ws.*`, `sse.*`, `tcp.*`, `udp.*`, `dtls.*` | 14 | close codes, idle/cancel, abnormal close, no UDP response observed |

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

The untrusted-destination rule is unchanged: Ferrum markers are only
interpreted for a destination declared as a Ferrum gateway, and the `hbone.*`
findings make no Ferrum-specific attribution.

## Ferrum Edge catalog (`catalog/ferrum/ferrum-edge-0.9.5/outcomes.json`)

The source audit (`docs/audit/gateway-source-audit.md`) inventories **528**
client-observable outcomes of Ferrum Edge v0.9.5 (tag `20e7603`), the **7**
public `X-Gateway-Error` tokens, the **19** internal error classes, the **14**
headers, and each outcome's `shared_signal_with` siblings.

Anvil matches an observed response against this catalog only when the
destination matches a user-declared **Ferrum gateway integration profile**.
Without one, a Ferrum-looking header yields `ferrum.marker.unverified`: any
server can send it.

### Confidence ceilings (why most gateway findings say "likely")

- On v0.9.5, `X-Gateway-Error` and `X-Gateway-Upstream-Status` can be
  injected by a backend on some paths (native gRPC responses, plugin reject
  maps). Marker-derived claims are therefore capped at **likely**, even for
  trusted gateways over verified TLS.
- A trusted profile used over plain HTTP (lab use) is also capped at likely.
- `confirmed` gateway attribution requires a gateway-owned, authenticated
  diagnostic contract that does not exist yet (see
  `docs/g01-gateway-diagnostic-contract.md`).

### The seven tokens are coarse, and stay coarse

| Token | What Anvil says | What Anvil never claims from the token alone |
|---|---|---|
| `connection_failure` | The gateway could not set up a connection to the configured backend (DNS, TCP, TLS, pool, …). | That TLS failed; that DNS failed; that your client certificate is wrong (the gateway uses its own identity). |
| `backend_timeout` | The gateway's backend deadline elapsed (any 504 gets this token). | That the backend received the request (a v0.9.5 pooled-connection bug can strand it); that the backend is slow rather than unreachable. |
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
- Remediation names an owner. Gateway-to-backend problems go to the gateway
  operator or backend owner, not to the caller's credentials.

## How this is verified

- Unit tests for each rule family and for catalog drift (every rule code has
  wording).
- Engine scenario tests over real sockets (`crates/anvil-engine/tests`).
- The real-gateway lab (`docs/lab/*.md`). Every scenario runs trusted and
  untrusted: no `ferrum.*` gateway attribution may appear when the
  destination is untrusted. Lookalikes (backend 403/5xx/404) must not be
  attributed to the gateway. Operator log `error_class` values are used only
  as ground truth, never as engine input.
