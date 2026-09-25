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

The catalog has 119 finding codes (catalog version shown in the app status
bar and in every record):

| Family | Codes | Examples |
|---|---|---|
| `local.*` | 15 | unresolved variable, lint blocked, vault locked, invalid client identity; nothing was sent |
| `client.*` | 34 | DNS, connect, TLS (untrusted issuer, name mismatch, expired, client cert required/rejected, ALPN), QUIC/H3, DTLS |
| `proxy.*` | 4 | forward-proxy CONNECT failures and authentication |
| `exchange.*` | 11 | write failures, header timeout, HTTP/2 GOAWAY/RST/REFUSED_STREAM, closed before response |
| `response.*` | 4 | incomplete body, idle/total body timeouts, stream reset mid-body |
| `request.*` | 4 | canceled; processing uncertain; an earlier attempt may have processed |
| `http.*` | 14 | generic status explanations (fallbacks, listed after hop-specific findings) |
| `ferrum.*` | 15 | trusted marker tokens, outcome matches, ambiguity, unverified/absent/conflicting/unknown markers |
| `app.*`, `auth.*` | 6 | gRPC status, SOAP fault, GraphQL errors; locally observed token expiry |
| `ws.*`, `sse.*`, `tcp.*`, `udp.*` | 12 | close codes, idle/cancel, abnormal close, no UDP response observed |

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
