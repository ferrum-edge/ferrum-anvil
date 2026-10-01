# G01 — Gateway diagnostic contract (v1)

| | |
|---|---|
| **Status** | Implemented in Ferrum Edge v0.9.9 (`FERRUM_DIAGNOSTIC_REFS`, default `off`; v0.9.8 and earlier lack it). Adopted by Anvil: a trusted gateway profile can configure the lookup (see [diagnostics.md](diagnostics.md#gateway-diagnostic-references-g01)). |
| **Owner** | Ferrum Edge maintainers (gateway-owned contract). Anvil is one consumer. |
| **Tracking** | ferrum-edge/ferrum-edge#5767, ferrum-edge/ferrum-edge#5845 (implementation), ferrum-edge/ferrum-edge#5759 (backend-spoofable markers) |
| **Compatibility** | Additive. The public `X-Gateway-Error` tokens (seven through v0.9.7, eight from v0.9.8; unchanged in v0.9.9), their statuses and bodies stay unchanged. |

## Problem

Without a diagnostic reference, a client sees a coarse token
(`connection_failure`, `backend_timeout`, …) and a status. On v0.9.5, v0.9.7,
v0.9.8, and on v0.9.9 without a lookup:

- a token merges several causes. For example, `connection_failure` covers
  DNS, TCP, TLS, pool and egress policy;
- the marker is unauthenticated: on v0.9.5 and v0.9.7 a backend can inject
  it on some paths (native gRPC responses), and on every release a plugin
  rejection or a non-Ferrum endpoint can carry any value, so a client can
  never *confirm* that the gateway authored it;
- the operator has the precise `error_class`, but only in logs the caller
  cannot see.

From public evidence alone, Anvil therefore caps gateway findings at *likely*
and lists the alternatives (see [diagnostics.md](diagnostics.md#confidence-ceilings-why-most-gateway-findings-say-likely)).
Precise, confirmed attribution needs evidence that is **authored by the
gateway, authenticated, and scoped**.

## Implemented in Ferrum Edge v0.9.9

The contract is implemented in Ferrum Edge v0.9.9 (`ferrum-edge/ferrum-edge#5767`;
#5845, #5857/#5862 and #5868). The Edge release is normative: see Edge's
[`docs/admin_api.md` "Diagnostic References"](https://github.com/ferrum-edge/ferrum-edge/blob/v0.9.9/docs/admin_api.md#diagnostic-references),
[`docs/error_classification.md`](https://github.com/ferrum-edge/ferrum-edge/blob/v0.9.9/docs/error_classification.md#gateway-diagnostic-references),
`src/diagnostic_ref.rs`, the `DiagnosticRefLookup` schemas in `openapi.yaml`,
and the `ferrum.diagnostic_ref.v1` schema in `ferrum-contracts`
`contracts-edge-0.9.9` (vendored by Anvil under
`contracts/ferrum-contracts/schemas/diagnostic-ref/v1.schema.json`, with its
fixtures).

What Edge provides:

- `X-Ferrum-Diagnostic-Ref` on gateway-authored error responses, off by
  default. `FERRUM_DIAGNOSTIC_REFS=errors` references every response that
  carries the gateway's own `X-Gateway-Error` token; `all` also references
  plugin rejections, gateway policy fences and routing `404`s (with a `null`
  `gateway_error`). A backend's own response never carries one, and the
  gateway strips any copy a backend, plugin or hook sets.
- `GET /diagnostics/v1/refs/{ref}` on the admin listener, rate-limited and
  audit-logged, answering a bounded `ferrum.diagnostic_ref.v1` record.
- Retention in a bounded in-memory store per process
  (`FERRUM_DIAGNOSTIC_REF_TTL_SECONDS`, default 900;
  `FERRUM_DIAGNOSTIC_REF_MAX_ENTRIES`, default 10,000).

How it differs from the proposal below:

- **Reference forms.** `fd1_<32 lowercase hex>`, or
  `fd2_<8 lowercase hex replica>_<32 lowercase hex>` with
  `FERRUM_DIAGNOSTIC_REF_REPLICA_TAG=true`; not base64url.
- **Schema.** The body is `schema_version: "ferrum.diagnostic_ref.v1"` with
  `ref`, `replica_id` (tagged references only), `namespace`, `created_at`,
  `expires_at`, `protocol`, `status`, `gateway_error`, `detail_available` and
  `detail`. `detail` holds `error_class`, `body_error_class`,
  `rejection_phase`, `route_timeout_phase`, `backend_dispatch`, `proxy_id`,
  `backend_target`, `duration_bucket`, and optionally `rejection`, `attempts`
  (each with its own dispatch, status or error class, and a closed TLS
  failure) and `attempts_omitted`. There is no `version: 1` envelope, no
  `outcome_id` and no `authored_by_gateway` field.
- **Dispatch values.** `not_dispatched`, `pre_wire_failure`,
  `ambiguous_failure` or `backend_response`, instead of
  `not_sent | sent | may_have_been_sent`. The request-level value describes
  the final attempt; earlier attempts are in `detail.attempts`.
- **Scope and namespace rules.** The lookup needs an admin JWT whose `scope`
  includes `diagnostics:read` **and** that carries an `ns` claim. The admin
  `role` implies neither, and a token signed with the read-only viewer key
  never holds a scope. A missing scope or `ns` claim is refused with `403`
  (decided from the credential alone); a malformed, unknown, expired or
  evicted reference, one outside the token's namespaces, one another replica
  minted, and every reference while the feature is off all answer the same
  `404`. The proposal had "everything is `404`".
- **Replica header.** Asked for an `fd2_` reference another replica minted,
  a gateway answers the same `404` plus `X-Ferrum-Diagnostic-Owner-Replica`
  naming the owner, only for a caller authorized for its own namespace. The
  control plane does not proxy lookups. The proposal had no replica concept.

## Original proposal (historical)

The following design predates the implemented Edge contract above. It is
kept as historical context and is not normative.

### 1. Public response: an opaque reference only

Every response the gateway authors or rewrites gets:

```
X-Ferrum-Diagnostic-Ref: fd1_<128-bit random, base64url>
```

- The value is random, unguessable and unique per exchange. It is not
  sequential and carries no timestamp.
- It carries no cause, class, route, backend or tenant information.
- The gateway strips any `X-Ferrum-Diagnostic-Ref` coming from a backend
  (anti-spoofing). A spoofed ref that reaches a client is harmless, because
  it resolves to nothing (see below).
- Toggle: `FERRUM_DIAGNOSTIC_REFS=off|errors|all` (default `off`). With
  `errors`, only gateway-authored error responses carry the header.

### 2. Authenticated detail lookup

`GET /diagnostics/v1/refs/{ref}` on the **admin** listener (or a dedicated
diagnostic listener).

- **AuthN:** a bearer credential with the `diagnostics:read` scope. It can be
  bound to namespaces (tenants) and optionally to caller mTLS identities.
- **AuthZ:** a ref resolves only within the credential's namespaces.
  Everything else returns `404` (never `403`, so refs cannot be probed across
  tenants).
- **Rate-limited per credential.** Every lookup is audit-logged with the
  credential id, never the credential itself.

Response (bounded JSON, versioned):

```json
{
  "version": 1,
  "ref": "fd1_…",
  "authored_by_gateway": true,
  "observed_at": "2026-09-25T12:00:00Z",
  "namespace": "ferrum",
  "proxy_id": "orders-api",
  "phase": "backend_connect",
  "error_class": "tls_error",
  "public_token": "connection_failure",
  "outcome_id": "upstream.tls.untrusted_backend_cert",
  "backend": { "target": "orders.internal:8443", "scheme": "https", "attempts": 2 },
  "attempts": [
    { "index": 1, "error_class": "tls_error", "tls": { "alert": "unknown_ca", "verification": "untrusted_issuer" }, "dispatch": "not_sent", "duration_bucket_ms": "10-50" },
    { "index": 2, "error_class": "tls_error", "tls": { "alert": "unknown_ca", "verification": "untrusted_issuer" }, "dispatch": "not_sent", "duration_bucket_ms": "10-50" }
  ],
  "policy": null,
  "retained_until": "2026-09-25T12:15:00Z"
}
```

Field rules:

- `error_class` is one of the 19 gateway error classes, and `outcome_id`
  comes from the published outcome catalog (the same ids as Anvil's
  `catalog/ferrum/<version>/outcomes.json`).
- `dispatch` describes the **gateway → backend** leg: `not_sent | sent |
  may_have_been_sent`. This is what allows a client to know whether retrying
  a POST is safe.
- `policy` is set for plugin rejections: `{ "plugin": "waf", "phase":
  "access", "rule_id": "…" }`. It contains no rule content, no matched
  payload and no user data. Custom plugins report only `{ "plugin": "custom"
  }` unless their author opts in.
- **Never included:** request or response headers and bodies, credentials,
  tokens, cookies, client IPs of other tenants, backend secrets, full
  certificates (only verification problem kinds and alert names), or config
  values.
- Durations are bucketed to avoid building a timing oracle.

### 3. Bounds and performance

- Refs live in a fixed-size in-memory ring (for example 10,000 entries per
  worker) with a TTL (default 15 minutes). Memory is O(ring size) and
  insertion is O(1). Nothing is written to disk by default.
- Recording must add no measurable latency (budget: under 1 µs p99 per
  request when enabled). The hot path must not allocate beyond one small
  struct.
- When disabled, there is no header and no ring.

### 4. Required gateway tests

- **Disclosure:** golden tests prove every field is in the allowlist, with no
  headers, bodies or secrets, and that custom plugin reason text is withheld.
- **Tenant isolation:** a namespace-A credential cannot resolve namespace-B
  refs (it gets 404), and error timing is constant.
- **Anti-spoofing:** a backend-supplied `X-Ferrum-Diagnostic-Ref` is
  stripped, and a forged ref returns 404.
- **Bounds:** ring overflow evicts the oldest entry, TTL expiry works, and
  the rate limit is enforced.
- **Performance:** a benchmark with the feature on and off, under a documented
  budget.
- **Coverage:** every `error_class` and every public token path produces a
  ref when enabled (live tests, mirroring the Anvil lab profiles).

## Anvil integration

Implemented (see [diagnostics.md](diagnostics.md#gateway-diagnostic-references-g01)):

- A Ferrum gateway integration profile can configure the lookup in its
  `detail` field (`DiagnosticDetailAccess { base_url, credential, namespace? }`,
  `crates/anvil-domain/src/integration.rs`): the admin listener's base URL, a
  bearer token, and optionally the gateway's namespace. The token is a
  sensitive value (a vault secret, or a template such as an environment
  variable): a dedicated, short-lived admin JWT with role `viewer`, scope
  `diagnostics:read` and an `ns` claim, never a general admin token. It is
  sent only to that admin listener, added to the execution's redactor, never
  logged or written to a record, replaced by a placeholder in safe-share
  exports, and never handed to load workers.
- For a response from a destination that matches such a profile, Anvil looks
  up a well-formed reference as soon as the response arrives, through the
  same transport, TLS, proxy and DNS settings as the request. An untrusted
  destination's reference is never looked up, and a malformed one is
  reported, not looked up.
- The header alone is never evidence. The record is used only when it is a
  valid `ferrum.diagnostic_ref.v1` body that binds to this exact response:
  the same reference (and replica), status, `X-Gateway-Error` value (or
  none), client protocol and, when the profile names one, namespace, created
  while the request was in flight (five minutes of clock difference are
  allowed). Findings from it (`ferrum.detail.*`) cite the record as
  `gateway_detail` evidence and reach `confirmed` only when both the request
  and the lookup used verified TLS or a direct loopback connection;
  otherwise they are `likely`.
- `403`, `404` (with any owner-replica hint), `429`, transport failures and
  records of another response are reported with their own findings and leave
  every other Ferrum finding at the public evidence's ceiling. Public-marker
  findings keep their own confidence for comparison.
- Anvil does not use `backend_dispatch` to relax the never-auto-replay rule;
  a record whose earlier attempt reached a backend says so.

## Rollout

1. Edge implements and tests the header plus authenticated lookup (Ferrum
   Edge v0.9.9).
2. `ferrum-contracts` `contracts-edge-0.9.9` publishes the header and the
   `ferrum.diagnostic_ref.v1` schema; Anvil pins it, and its CI fails on drift
   from the pinned schema, fixtures and header vocabulary.
3. Anvil adopts the lookup for profiles that configure it, with the lab's
   `core` profile running it against the real v0.9.9 gateway (G01-001,
   G01-002, TRUST-009, TRUST-010 and TRUST-011; skipped on earlier releases).

Without a configured lookup, or with references off, Anvil's answers stay as
they were: "likely, with these alternatives" is the correct result, not a
gap to hide.
