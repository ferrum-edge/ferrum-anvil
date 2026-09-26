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

The catalog has 127 finding codes (catalog version shown in the app status
bar; every record names the findings catalog and the Ferrum catalog it used):

| Family | Codes | Examples |
|---|---|---|
| `local.*` | 16 | unresolved variable, lint blocked, vault locked, invalid client identity; nothing was sent |
| `client.*` | 35 | DNS, connect, TLS (untrusted issuer, name mismatch, expired, client cert required/rejected, ALPN), QUIC/H3, DTLS |
| `proxy.*` | 4 | forward-proxy CONNECT failures and authentication |
| `exchange.*` | 11 | write failures, header timeout, HTTP/2 GOAWAY/RST/REFUSED_STREAM, closed before response |
| `response.*` | 4 | incomplete body, idle/total body timeouts, stream reset mid-body |
| `request.*` | 4 | canceled; processing uncertain; an earlier attempt may have processed |
| `http.*` | 14 | generic status explanations (fallbacks, listed after hop-specific findings) |
| `ferrum.*` | 18 | trusted marker tokens, outcome matches, ambiguity, unverified/absent/conflicting/unknown markers, missing release catalog |
| `app.*`, `auth.*` | 7 | gRPC status, SOAP fault, GraphQL errors; locally observed token expiry |
| `ws.*`, `sse.*`, `tcp.*`, `udp.*`, `dtls.*` | 14 | close codes, idle/cancel, abnormal close, no UDP response observed |

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
