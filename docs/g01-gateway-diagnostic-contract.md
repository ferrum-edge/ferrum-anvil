# G01 — Gateway diagnostic contract (v1)

| | |
|---|---|
| **Status** | Implemented in Ferrum Edge (ferrum-edge#5767, #5845). The public contract is implemented on Edge `main`; the reference header remains unreleased in v0.9.8. |
| **Owner** | Ferrum Edge maintainers (gateway-owned contract). Anvil is one consumer. |
| **Tracking** | ferrum-edge/ferrum-edge#5767, ferrum-edge/ferrum-edge#5845 (implementation), ferrum-edge/ferrum-edge#5759 (backend-spoofable markers) |
| **Compatibility** | Additive. The public `X-Gateway-Error` tokens (seven through v0.9.7, eight from v0.9.8), their statuses and bodies stay unchanged. |

## Problem

Today a client sees a coarse token (`connection_failure`, `backend_timeout`,
…) and a status. On v0.9.5, v0.9.7 and v0.9.8:

- a token merges several causes. For example, `connection_failure` covers
  DNS, TCP, TLS, pool and egress policy;
- the marker is unauthenticated: on v0.9.5 and v0.9.7 a backend can inject
  it on some paths (native gRPC responses), and on every release a plugin
  rejection or a non-Ferrum endpoint can carry any value, so a client can
  never *confirm* that the gateway authored it;
- the operator has the precise `error_class`, but only in logs the caller
  cannot see.

Anvil therefore caps gateway findings at *likely* and lists the alternatives
(see [diagnostics.md](diagnostics.md#confidence-ceilings-why-most-gateway-findings-say-likely)).
Precise, confirmed attribution needs evidence that is **authored by the
gateway, authenticated, and scoped**.

## Design

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

Already modelled in Anvil:

- A Ferrum gateway integration profile has an optional `detail` field
  (`DiagnosticDetailAccess { base_url, credential, namespace? }`,
  `crates/anvil-domain/src/integration.rs`). The credential is a sensitive
  value (a vault reference or a template), meant to be a dedicated
  least-privilege diagnostic credential, never an admin token.
- Evidence source `gateway_detail` exists for authenticated gateway detail.

The Edge implementation provides the reference header and authenticated
diagnostic lookup. Anvil currently models the access configuration and
evidence source, but does not fetch diagnostic details yet:

- When a response carries a ref **and** the destination matches a gateway
  profile with detail access, the user can ask Anvil to fetch the detail.
  Fetching is explicit and never automatic for untrusted destinations. It
  runs through the same transport and TLS rules as any other request.
- Findings sourced from the detail endpoint:
  - may reach **confirmed** for gateway-to-backend claims, because the
    evidence is gateway-authored and authenticated;
  - keep public-marker findings visible, with their original confidence,
    for comparison;
  - use evidence source `gateway_detail` and cite the ref.
- A `dispatch: not_sent` on the gateway → backend leg lets Anvil say "safe to
  retry" for a non-idempotent request. Anything else keeps the
  never-auto-replay rule.

## Rollout

1. Edge implements and tests the header plus authenticated lookup (complete
   on Edge `main`; see the tracking issues above).
2. Publish the matching Edge release and contract vocabulary so compatibility
   catalogs stay in sync. Anvil CI fails on drift from its pinned contract.
3. Anvil can add detail fetching when a released Edge version exposes the
   capability; it should only fetch for destinations with configured,
   authenticated detail access.

Until Anvil implements diagnostic-detail fetching, its answers remain honest
about uncertainty. Stating "likely, with these alternatives" is the correct
result, not a gap to hide.
