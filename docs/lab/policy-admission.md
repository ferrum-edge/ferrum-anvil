# Failure lab: policy, admission and drain profiles

The v0.9.11 default is a source-audited release with hosted Anvil qualification recorded.
Results and observations below remain historical; see
[the 0.9.11 source delta](../audit/gateway-0.9.11-delta.md).

Three real-gateway profiles for the WAF/policy and gateway-admission families of the failure matrix.
Every stimulus drives a pinned Ferrum Edge release binary (v0.9.11 candidate default, v0.9.10, v0.9.9, v0.9.8, v0.9.7 or v0.9.5 with
`--release`) with controllable local fixtures. No response is faked, and no failure is
injected as an enum. Behaviour recorded below as "0.9.5" was re-observed on 0.9.7: every scenario
passes on both releases with the same expectations, except `GW-010-BOT.allow-edge`, whose verdict is
release-dependent (see [gateway-0.9.7-delta.md](../audit/gateway-0.9.7-delta.md)). v0.9.8 and later strip
an injected `X-Gateway-Upstream-Status` (GW-019-ERROR/OK/FORGED); those expectations follow the source
audit ([gateway-0.9.8-delta.md](../audit/gateway-0.9.8-delta.md); unchanged in
[gateway-0.9.9-delta.md](../audit/gateway-0.9.9-delta.md) and [gateway-0.9.10-delta.md](../audit/gateway-0.9.10-delta.md)).

| Profile | Gateway listeners | Fixture ports | Config | Scenarios |
|---|---|---|---|---|
| `policy` | HTTP 127.0.0.1:18280, admin :18290 | 19201–19210 (19207 and 19209 stay unbound on purpose) | `lab/gateway/policy.{conf,yaml}` | `crates/anvil-lab/src/policy.rs` |
| `admission` | HTTP 127.0.0.1:18580, admin :18590; **mesh instance**: egress mTLS 127.0.0.1:18589, admin :18592 (plus loopback 18581/18586/18588) | 19501–19503 | `lab/gateway/admission.{conf,yaml}`, `lab/gateway/admission-mesh.{conf,json}` | `crates/anvil-lab/src/admission.rs`, `fixtures_admission_mesh.rs` |
| `drain` | HTTP 127.0.0.1:18680, admin :18690 | 19601–19602 | `lab/gateway/drain.{conf,yaml}` | `crates/anvil-lab/src/drain.rs` |

Fixtures and shared helpers are in `crates/anvil-lab/src/fixtures_policy.rs`. The OPA and AI-provider
mocks are in `crates/anvil-fixtures/src/policy.rs`. `admission` and `drain` each change process-wide
behaviour (`FERRUM_MAX_REQUESTS=1`, a 64 KiB retained-response budget, SIGTERM), so each one runs as its
own gateway instance.

The `admission` profile also starts a **second gateway process in mesh mode** for UP-018. On 0.9.5
(and still on 0.9.7) the only per-destination physical-connection ceiling is DestinationRule
`connectionPool.tcp.maxConnections` (`Upstream.port_overrides[].max_connections`). File mode rejects
that field, and only the mesh slice-apply layer projects it. The instance runs the egress-gateway
topology from a localized mesh document (`FERRUM_MESH_CONFIG_PROTOCOL=file`):

- One `mesh_external` ServiceEntry, `localhost:19503`, with a DestinationRule `max_connections: 1`.
- A per-run SPIFFE PKI from `crates/anvil-fixtures/src/mesh_pki.rs`.
- The egress listener is SVID-mTLS. Anvil drives it with a verified TLS profile: it presents the lab
  client SVID and trusts the lab mesh root. There is no verification bypass.

## 1. Running

```sh
cargo run -p anvil-lab -- run policy --untrusted-pass
cargo run -p anvil-lab -- run admission --untrusted-pass
cargo run -p anvil-lab -- run drain --untrusted-pass
cargo run -p anvil-lab -- run policy --scenario GW-013-TIMEOUT   # one scenario
cargo run -p anvil-lab -- up policy       # keep fixtures + gateway up for manual/desktop use
cargo run -p anvil-lab -- --release v0.9.5 run policy --untrusted-pass   # the earlier release
```

Setup, binary lookup, results layout and the two passes: [README.md](README.md). The drain profile
also archives the operator log of every drained instance (`gateway-operator*.log`). In the untrusted
pass a Ferrum-like header may only surface as `ferrum.marker.unverified`: confirmed header
observation with unknown scope, without gateway token/outcome attribution. UP-018 asserts
these semantics for the ceiling and both application lookalikes on every supported release.

**Trust ceiling.** The ordinary profile uses plain HTTP; UP-018 uses verified SVID-mTLS to the
mesh egress listener. Every marker-derived and body-derived attribution remains capped at `likely`,
including on that authenticated channel: public markers do not prove who authored the body.
`X-Gateway-Error` and `X-Gateway-Upstream-Status` can be spoofed on 0.9.5 and 0.9.7 (see GW-019
below), so these public signals cannot confirm gateway attribution.

### Evidence types

- **Diagnosis checks.** These are Anvil's own conclusions from public evidence only: status, headers,
  body and transport phases.
- **Ground-truth checks.** These use fixture logs (what the backend, OPA mock or provider mock
  actually received and answered) and the gateway operator log. The operator log gives stdout
  transaction lines with `error_class`, `metadata.rejection_phase` and `waf.*`, plus runtime WARN/INFO
  lines. Admin `/health` and the authenticated `/overload` snapshot are also used. None of this is
  ever given to the engine.
- **Recovery checks.** A positive request after the fault is removed or bypassed.

### Scenario pattern

Every scenario has a stimulus, a ground-truth check that the intended condition was really reached,
and public-evidence checks:

- expected findings;
- scope;
- maximum confidence;
- forbidden claims such as "waf", "cpu", "rate limit", "crash" or "unreachable".

Where the failure matrix asks for it, a scenario also has a deceptively similar lookalike that must *not*
receive the gateway diagnosis, plus a positive recovery.

## 2. Scenarios

"Lookalike" means an application-authored response through the plain `/ok` route. It is
byte-identical where noted.

### `policy` (24 scenarios per pass, plus 1 skip)

| ID | Matrix | What it proves |
|---|---|---|
| CTRL-POL-001 | — | Positive control. 200; the backend saw the request; no marker findings. |
| GW-010 | GW-010, TRUST-006 | **WAF header rule** gives 403 `{"error":"Forbidden"}`. Ground truth: `waf.action=blocked`, `waf.first_blocking_rule=ANVIL-LAB-HEADER`, and the backend was never hit. Anvil reports `http.forbidden` plus `ferrum.outcome_ambiguous` (unknown), no WAF/bot claim at ≥ likely, and no single-cause `ferrum.outcome`. **Lookalike:** the application answers a byte-identical 403, and Anvil gives the **identical** finding set. Recovery: the same route without the marker returns 200. |
| GW-010-BODY | GW-010 | **WAF request-body rule** (POST JSON marker) gives 403. Ground truth: rule `ANVIL-LAB-BODY`; the backend was not hit. Same cautious diagnosis. Recovery: a clean body returns 200. |
| GW-010-BOT | GW-010, TRUST-006 | **Bot detection** (User-Agent `anvil-lab-bot/1.0`) gives a 403 byte-identical to the WAF reject. Ground truth: `rejection_phase=on_request_received`, no `waf.*` metadata. Anvil's findings are identical to the WAF case. Recovery: a normal User-Agent returns 200. |
| GW-010-BOT.allow-edge | GW-010 | **Release-dependent.** A User-Agent that matches the bot pattern and also contains the `allow_list` entry `anvil-lab-monitor/` (ending in punctuation, followed by a non-word character). On 0.9.5 the entry never matches (`\b…\b` anchoring), so the request gets the bot 403 and the backend is not hit; Anvil makes no bot claim at ≥ likely. On 0.9.7 the entry matches and the request reaches the backend (200, no `ferrum.outcome*`). Operator log records the User-Agent. |
| GW-012 | GW-012 | **OPA deny** gives 403 `{"error":"forbidden by policy"}`. Ground truth: the OPA mock received the `anvil/lab/deny` query and its input; `rejection_phase=authorize`; the backend was not hit. Anvil reports `ferrum.outcome` = `plugin.opa.policy_denied` (≤ likely, gateway admission, identical-bytes caveat), no 401 or credential claim, and no WAF claim. **Lookalikes:** an application 403 with its own body gets no catalog attribution. An application 403 with byte-identical text stays ≤ likely and states the identical-bytes caveat. Recovery: `/gw/opa-allow` returns 200 after an `allow` query. |
| GW-013-TIMEOUT | GW-013 | **OPA stalls** (it accepts and reads the query but never answers; plugin timeout 500 ms). The gateway fails closed with 503 `{"error":"authorization service unavailable"}` and **no X-Gateway-Error**. Anvil reports `http.service_unavailable`, `ferrum.outcome` = `plugin.opa.fail_closed` (≤ likely), and `ferrum.marker.absent` (unknown) naming plugin rejections. It makes no credential or CPU claim and no backend-passthrough claim. **Lookalike:** the application's own 503 with byte-identical text is stamped `backend_error` by the gateway, so Anvil does *not* call it an OPA failure. Recovery: 200. |
| GW-013-REFUSED | GW-013 | **OPA unreachable** (nothing on 19209) gives the same fail-closed 503. Recovery removes the fault: an OPA mock is bound on 19209, the same route returns 200, and the mock answered the decision. |
| GW-013-ERROR | GW-013 | **OPA answers HTTP 500** (ground truth: the mock logged status 500) and the gateway fails closed with 503. Recovery: the fault is cleared on the same route, which returns 200. |
| GW-014 | GW-014 | **IP restriction** gives 403 `{"error":"IP address denied"}`. Ground truth: `rejection_phase=on_request_received`; the backend was not hit. Anvil reports `plugin.ip_restriction.ip_denied` (≤ likely), no client-leg finding, and no "unreachable" claim. Lookalike: an application 403 with a different body gets no attribution. |
| GW-015 | GW-015 | **OpenAPI validation.** Malformed JSON, a schema violation (`qty` minimum) and an unknown operation each return 400 `application/problem+json`. Ground truth: `rejection_phase=validate_client_request_contract`; the backend was not hit. The syntax and schema cases are distinguishable in the preserved body. There is no TLS or transport claim. **Lookalike:** an application-authored problem+json 400 gets identical findings. Recovery: a valid body reaches the echo fixture and returns 200. |
| GW-009 | GW-009 | **Response-transformer ceiling.** The origin served `{}` (ground truth); the transformer output of 129 bytes exceeds 128, giving 502 `{"error":"Response body too large","limit":128}` with `X-Gateway-Error: overload`. The operator log shows `error_class=dispatch_policy_rejected`. Anvil reports `ferrum.token.overload` (≤ likely, gateway admission) with the transformer and CPU caveats, `ferrum.outcome` = `gateway.response.transformer_output_ceiling`, and no CPU claim at any confidence. **Lookalikes:** an application 502 with the same bytes is stamped `backend_error`, with no overload claim. A plain response-size ceiling (`error_class=response_body_too_large`) gives no overload claim. Recovery: the 114-character transform fits and returns 200. |
| GW-004 | GW-004 | **Adaptive concurrency** (limit 1). While one request holds the permit for 3 s, a second gets 503 `concurrency_limit` with `x-adaptive-concurrency-limit: 1`. Ground truth: `rejection_phase=adaptive_concurrency`; only the occupant reached the backend. Anvil reports the token (≤ likely, gateway admission) and the catalog match. There is no 429 finding and no "rate limit" claim. **Lookalike:** an application 503 with byte-identical text gets `backend_error` and no `concurrency_limit` claim. Recovery: 200. |
| EXT-RL-001 | Lab extension, no matrix seed (related to GW-004) | **Gateway rate limit** (2 per 2 s per IP; token bucket). The third request gets 429 `{"error":"Rate limit exceeded"}` with `x-ratelimit-*` headers. Ground truth: exactly 2 backend hits; `rejection_phase=on_request_received`. **Lookalike:** the application answers a byte-identical 429 with the same `x-ratelimit-*` headers, and Anvil gives **identical** findings (`http.too_many_requests` plus an ambiguous catalog finding). Recovery after refill: 200. |
| GW-020-GUARD | GW-020 | **AI request guard**, model not allowed: 400 `{"error":"Model not allowed",...}`. Ground truth: the provider was never called; `rejection_phase=before_proxy`. **Lookalike:** the provider's own 400 gets identical generic findings. Recovery: an allowed model returns 200. |
| GW-020-BUDGET | GW-020 | **AI token budget** (50 tokens per 3 s; the mock reports 30 per call). Two calls pass (60 tokens used, per provider ground truth), then the third gets 429 with `x-ai-ratelimit-remaining: 0`, refused before dispatch. **Lookalike:** the provider's own 429 (with Retry-After) is not attributed to a gateway budget. Recovery after the window: 200. |
| GW-020-PROVIDER | GW-020 | The **provider's 500** passes through and the gateway stamps `backend_error`. Anvil reports the token (≤ likely) with the "application itself produced" caveat and no gateway catalog attribution for the provider's envelope. Recovery: 200. |
| GW-020-CONTENT | GW-020 | **AI response content guard.** The provider answered 200 (ground truth); the gateway blocks it with 502 `{"error":"AI response blocked by content guard",...}` **and stamps `backend_error`**. Anvil must not blame the application or the gateway-to-provider leg: no passthrough claim and no `upstream_application` or `gateway_to_upstream` finding at ≥ likely. `ferrum.token.backend_error` lists response-policy rejections. Recovery: a clean reply returns 200. |
| GW-001-HALFOPEN | GW-001 (beyond core's open-state check) | **Circuit breaker.** Two backend 500s (ground truth: 2 hits) open it. A would-succeed request then gets 503 `circuit_breaker_open` with 0 backend hits. After 2 s, exactly one half-open probe is admitted; it fails, and the breaker re-opens immediately. After another 2 s a successful probe closes it, and traffic flows again. Operator log: `rejection_phase=circuit_breaker_open`. **Lookalike:** an application 503 with the breaker's exact body gets `backend_error` and no breaker claim. |
| GW-019-ERROR | GW-019 | A **response hook** writes `X-Gateway-Error: lab-spoofed-token` and `X-Gateway-Upstream-Status: degraded` on a refused-backend 502. The gateway **restores** the authoritative `connection_failure`, and Anvil sees no unknown token. The hook's `degraded` **survives** on 0.9.5 and 0.9.7 (verified live); Anvil keeps it ≤ likely and names plugins as possible writers. From 0.9.8 the builder strips it (#5759) and no degraded-routing finding appears. |
| GW-019-OK | GW-019 | The same hook on a 200. `X-Gateway-Error` is stripped and, on 0.9.5 and 0.9.7, `degraded` passes. Anvil reports success and only a degraded-routing warning (≤ likely); untrusted, it reports only an unverified-marker warning. From 0.9.8 both headers are stripped and Anvil reports plain success with no marker warning. |
| GW-019-FORGED | GW-019, TRUST-011 | The **backend** forges both headers on a 200 (ground truth: fixture). Same result as GW-019-OK. |
| GW-019-REJECT-UNKNOWN | GW-019, TRUST-003 | A reject-path hook adds `X-Gateway-Error: lab-future-token` to an IP-deny 403, and it reaches the client. Anvil reports `ferrum.marker.unknown_token` (unknown) and no token meaning. |
| GW-019-REJECT-KNOWN | GW-019, TRUST-011 | A reject-path hook adds a **known** token (`overload`) to an IP-deny 403. Anvil reports `ferrum.marker.inconsistent` (conflicting evidence), with no token finding and no overload or CPU claim (§4). |
| GW-014-GEO | GW-014 | **Skipped.** `geo_restriction` needs a readable MaxMind country `.mmdb`. `ferrum-edge validate` rejects a missing `db_path` ("not accessible before open"). No database is vendored and the lab may not download one, so neither the country-deny path nor the database-unavailable path is reachable. |

### `admission` (4 scenarios per pass, plus 2 skips)

| ID | Matrix | What it proves |
|---|---|---|
| CTRL-ADM-001 | — | Positive control. |
| UP-015 | UP-015 | **Retained-buffer exhaustion.** The backend answered a valid 200 with 256 KiB (ground truth); the gateway returns 503 `{"error":"Response buffering capacity exceeded"}` with **`X-Gateway-Error: backend_error`**. Operator log: `error_class=gateway_buffer_capacity`. Anvil reports `ferrum.token.backend_error` (≤ likely, scope **unknown**, gateway-local-limit caveat) and `ferrum.outcome_ambiguous`, whose candidates include `gateway.capacity.response_buffer`: 0.9.5 has two sources of this exact signal. There is no backend-passthrough claim, no `upstream_application` or `gateway_to_upstream` finding at ≥ likely, and no "unhealthy" claim. **Lookalike:** the application's own 503 is not called a buffer-capacity refusal. Recovery: 32 KiB fits and returns 200. |
| GW-002 | GW-002 | **Overload refusal** with `FERRUM_MAX_REQUESTS=1`. While one request holds the slot, the operator `/overload` level is `critical` and the log shows `Overload CRITICAL: rejecting new requests`. The probe gets 503 `{"error":"Service overloaded"}` with `overload` and never reaches a backend. An **unrouted** path also gets 503 `overload`, not 404, which shows the refusal precedes routing. Anvil reports `ferrum.token.overload` (≤ likely, gateway admission, CPU caveat) and the catalog match, with no application blame and no CPU claim. The fence lifts at the next monitor tick (about 50–100 ms after the slot frees; ground truth: `level` back to `normal`). **Lookalike:** the application's byte-identical 503 gets `backend_error` and no overload claim. Recovery: 200. |
| UP-018 | UP-018 | **Backend connection ceiling, HTTP/1.1 lane**, on the mesh egress gateway. A 3 s request holds the destination's only permitted connection; a probe 500 ms later needs a second socket. **0.9.5/7/8/9/10 (reqwest):** require exactly 503 `{"error":"Backend connection limit exceeded"}`, `X-Gateway-Error: backend_error`, operator `dispatch_policy_rejected`, and `ferrum.outcome` = `upstream.connection_limit.reqwest` (≤ likely, gateway admission, identical-bytes caveat); the token stays ≤ likely with scope unknown. **0.9.11 (eligible direct H1):** require exactly 502 `{"error":"Backend unavailable"}`, `connection_failure`, operator `backend_connection_limit`, and `ferrum.outcome_ambiguous` (unknown confidence/scope) including `upstream.connection_limit.pooled` and other setup causes; the token stays ≤ likely, gateway to upstream. Independent ground truth requires the backend to serve the occupant, never see the probe and accept at most one new socket. No backend-passthrough, application/client-leg blame, crash, unhealthy/down or overload claim; the direct-H1 signal cannot identify the ceiling as the cause. **Lookalikes:** the application's own 503 is never a ceiling. An identical status/body from the application stays ≤ likely on reqwest; on direct H1 its `backend_error` token excludes the ceiling family. Both must reach the backend. Recovery must return 200 and reach the backend after the occupant finishes. Untrusted outputs get no token/outcome attribution. The 0.9.11 admission qualification is recorded in [the 0.9.11 source delta audit](../audit/gateway-0.9.11-delta.md). |
| GW-005 | GW-005 | **Skipped.** It needs a real CP plus DP pair; file mode never installs the DP freshness fence. It is owned by the `cpdp` profile (ports 187xx/197xx). |
| UP-018-H2 | UP-018 | **Skipped: the pooled lanes (direct H2, gRPC, H3) could not be driven into the ceiling here.** The direct-H2 pool multiplexes, so it never re-dials. With the backend advertising `SETTINGS_MAX_CONCURRENT_STREAMS=1`, the second request queued about 2.5 s behind the first on the one connection (200, one backend connection). With a backend that sends GOAWAY on each connection, the pool reused the draining connection and got 502 `connection_failure` with operator `error_class=connection_pool_error`: a pool cancellation, not the ceiling. That public signal (502 `connection_failure` "Backend unavailable") is covered by the contract test below. |

### `drain` (2 scenarios per pass)

| ID | Matrix | What it proves |
|---|---|---|
| CTRL-DRN-001 | — | Positive control. |
| GW-003 | GW-003 | **Graceful drain.** A keep-alive connection and a 6 s in-flight request are open when the gateway gets SIGTERM. The sequence that follows: (a) admin `/health` gives 503 `{"status":"draining","ready":false}` while a new connection in the 3 s pre-drain is still served (Anvil: plain success). (b) After the pre-drain, a raw connect is refused. Anvil reports `client.connect.refused` (confirmed, client-to-peer) with no `ferrum.*` finding and no "crash" claim; the "service is restarting" caveat is shown. (c) The in-flight request completes with 200 and `Connection: close`. (d) The keep-alive request during the drain is **racy by design**: a 503 overload, a closed socket or a refused re-dial are all possible. The check asserts that Anvil's explanation matches whatever occurred; in every recorded run the idle socket was closed and the re-dial refused. The gateway exits 0 after "All connections and requests drained successfully". Recovery: a fresh instance serves 200. |

### Public-signal contract tests (not live)

`crates/anvil-diagnostics/tests/upstream_setup_contract.rs` feeds only the exact public signal that the
source-audited catalog records into the diagnosis. These are **not** live reproductions and **not**
hook-based tests.

| Test | Matrix | Why not live |
|---|---|---|
| `up_017_port_exhaustion_signal_is_coarse_and_hook_free`, `up_017_untrusted_destination_gets_no_gateway_family` | UP-017 | 0.9.5 assigns `port_exhaustion` only to EADDRNOTAVAIL at connect and ships no dial hook. Exhausting the host's real ephemeral ports is unsafe. |
| `up_019_trust_withdrawn_signal_makes_no_certificate_claim` | UP-019 | Trust withdrawal is emitted only on mesh HBONE / sidecar-mTLS transports, and no such trust-publication lab exists. |
| `up_018_pooled_lane_ceiling_stays_in_the_ambiguous_family`, `up_018_reqwest_lane_ceiling_is_a_gateway_limit_not_a_backend_failure` | UP-018 | Direct H2/gRPC/H3 remain outside the live ceiling reproduction (see UP-018-H2). The reqwest signal is asserted live on historical releases and retained as a contract on all six catalogs. |
| `up_018_direct_h1_ceiling_uses_the_0_9_11_ambiguous_setup_signal` | UP-018 | Exact 0.9.11 direct-H1 public signal, confidence/scope ceilings, untrusted and application-lookalike controls. Live UP-018 asserts this lane on 0.9.11; hosted qualification is recorded. |

The shared 502 `connection_failure` "Backend unavailable" signal stays in the ambiguous
connection-failure family:

- Port exhaustion, trust withdrawal and the pooled ceiling appear only as unknown-confidence catalog
  candidates.
- No finding at likely or above states port exhaustion, host resources, a certificate problem, TLS or
  DNS.
- The caller's own certificate is never blamed.

## 3. Live 0.9.5 behaviour recorded by these runs (re-observed on 0.9.7)

These results confirm or correct [gateway-lab-config.md](../audit/gateway-lab-config.md) items that
were marked "verify live". The same scenarios pass unchanged against v0.9.7; the one release
difference is `GW-010-BOT.allow-edge` (§2).

- **Plugin rejections carry no marker.** WAF, bot, OPA deny, OPA fail-closed 503, IP, validator, rate
  limit, AI guard and AI budget responses carry no `X-Gateway-Error`. The operator transaction line has
  no `error_class`; it has `metadata.rejection_phase` instead: `authorize`, `on_request_received`,
  `before_proxy`, `validate_client_request_contract`, `adaptive_concurrency` or `circuit_breaker_open`.
- **Header protection is partial** (GW-019). The gateway restores `X-Gateway-Error` on its own error
  responses and strips hook- or backend-supplied copies on successful responses. It does **not**
  protect `X-Gateway-Upstream-Status` anywhere on 0.9.5 and 0.9.7 (0.9.8 and later strip it on the
  backend-response builder, #5759). No release protects `X-Gateway-Error` on plugin rejection
  responses, which is why §4 item 1 exists.
- **`ai_response_guard` rejections are stamped `backend_error`** even though the provider answered
  200. The source catalogs (`catalog/ferrum/ferrum-edge-{0.9.5,0.9.7}/outcomes.json`,
  `plugin.ai_response_guard.*`) list no token: a known catalog drift.
- **The `ai_request_guard` allow-list body** is `"Model '<m>' is not in the allowed models list"` under
  `"error":"Model not allowed"`. The catalog body shape shows only the block-list wording.
- **The AI budget is reservation-based.** A request whose reservation (prompt estimate plus
  `max_tokens`) would exceed the remaining budget is refused before dispatch, even with 0 tokens used.
  The body then says `Token usage 0 exceeds limit 50`.
- **Short rate-limit windows are token buckets.** `rate_limiting` windows of 5 s or less use a token
  bucket, not a fixed window, so recovery depends on refill.
- **Declared-size responses use the core limit.** A declared Content-Length response over a
  `response_size_limiting` ceiling returns the core body
  `{"error":"Backend response body exceeds maximum size"}` (`error_class=response_body_too_large`),
  not the plugin body.
- **The overload fence outlives the occupant** by up to one `FERRUM_OVERLOAD_CHECK_INTERVAL_MS` tick.
  Requests in that gap still get 503 `overload`.
- **Some runtime WARNs are sampled.** OPA, IP, transformer-ceiling and similar plugin WARNs are
  sampled to one per 10 s per reason. The lab keeps them as supporting evidence but asserts only on
  transaction-line fields.
- **The connection ceiling is mesh-only and fragile.** DestinationRule `maxConnections` exists only
  in mesh mode. In the egress gateway it attaches by matching the DR host against the upstream
  **target** host. A `resolution: static` ServiceEntry's target is its endpoint IP, so a DR on its
  hostname silently never applies; the lab uses a DNS-resolved `localhost` entry.
- **The startup probe can occupy the ceiling.** The capability probe to a plain-HTTP backend is an
  h2c prior-knowledge connection. When the backend accepts h2c, that pooled connection occupies a
  `maxConnections: 1` slot, and every request on the reqwest lane is refused. The lab backend is
  therefore strictly HTTP/1.1 (`crates/anvil-fixtures/src/http1_only.rs`).
- **The ceiling body is distinct but the token is misleading.** The HTTP/1.1 ceiling answers 503
  `{"error":"Backend connection limit exceeded"}` with `backend_error`, and the operator class is
  `dispatch_policy_rejected`. The idle pooled connection keeps the slot after a request finishes,
  so reuse succeeds and only a *second concurrent* socket is refused.
- **Via differs, and Anvil ignores it.** A WAF header-phase reject has no `Via`; the body-phase reject
  and backend responses do. Anvil does not use `Via`, which is spoofable.

## 4. Diagnostics fixes made from these runs

These rules are in `crates/anvil-diagnostics/src/rules/ferrum_rules.rs` (unit tests in the same file),
with wording in `catalog/diagnostics/findings.en.json`. Each exists because a run below showed a wrong
or overconfident diagnosis.

1. **A known token on a non-5xx HTTP response gives `ferrum.marker.inconsistent`** (conflicting
   evidence, scope unknown), with no token finding and no catalog match. gRPC-shaped responses (HTTP
   200 trailers-only) are exempt. Source: GW-019-REJECT-KNOWN, where an IP-deny 403 decorated with
   `X-Gateway-Error: overload` would otherwise read as a likely gateway overload.
2. **The `backend_error` token claims no leg and no owner** (scope and owner unknown), and its wording
   includes response-phase policy rejections. Source: UP-015 and GW-020-CONTENT, where the gateway
   stamps `backend_error` on its own refusals.
3. **`ferrum.marker.absent` names plugin rejections first** (GW-013: OPA fail-closed 503).
4. **`ferrum.outcome_ambiguous`** says a backend can return identical bytes, and does not call its
   candidates "gateway causes" (GW-010, GW-010-BOT, EXT-RL-001).
5. **`ferrum.degraded_routing`** names response-header plugins as possible writers (GW-019).

None of these raises any confidence. The seven tokens keep their coarse meaning. No remediation
suggests disabling the WAF, TLS or a policy.

## 5. Limitations

- **Evidence mode.** Only plain-HTTP trusted profiles without a diagnostic reference lookup are
  exercised, so `confirmed` gateway attribution is never expected. It requires the gateway's own
  diagnostic record (G01, Ferrum Edge v0.9.9 and later,
  [g01-gateway-diagnostic-contract.md](../g01-gateway-diagnostic-contract.md)), which the `core`
  profile exercises ([README.md](README.md#g01-diagnostic-references-core-profile)).
- **Mocks.** The OPA and AI mocks verify the gateway's adapter behaviour only, not any real policy
  engine or provider.
- **Not covered here.** ACL denial (GW-011) belongs to the `auth` profile, and stale DP config
  (GW-005) to `cpdp`.
- **UP-017, UP-019 and pooled-lane UP-018** have public-signal contract tests only (see above).
  `docs/verification/matrix-status.json` records UP-017 and UP-019 as blocked.
- **Mesh instance scope.** The admission mesh instance is a single egress gateway with plaintext
  external destinations. It exercises no HBONE, sidecar-mTLS or multi-workload mesh behaviour.
- **Drain.** The in-connection overload refusal is racy and cannot be forced. Only its diagnosis is
  checked, whichever branch occurs.
- **Timing.** Scenarios depend on wall-clock gaps:
  - 500 ms to occupy a permit;
  - 2–3 s rate and AI windows;
  - the 3 s pre-drain.
  They passed on an idle Apple-silicon Mac. A heavily loaded host may need longer gaps.
- **Platform.** The runs recorded here are macOS arm64. CI (`.github/workflows/lab.yml`) also runs the
  lab on Ubuntu 24.04 and macOS 15; the Windows gateway asset is pinned but not exercised.

## 6. Stability record

Both releases, `anvil-lab [--release v0.9.5] run all --untrusted-pass` (2026-09-26, macOS 26 arm64):
policy 48 passed / 0 failed / 1 skipped, admission 8 / 0 / 2 and drain 4 / 0 / 0 on **v0.9.7** and on
**v0.9.5** (policy gained `GW-010-BOT.allow-edge`, run trusted and untrusted).

Earlier runs, v0.9.5 only (`anvil-lab run <profile> --untrusted-pass`, macOS 26 arm64, 2026-09-25),
three consecutive runs per profile:

| Profile | Run 1 | Run 2 | Run 3 | Wall time per run |
|---|---|---|---|---|
| policy (23 scenarios) | 46 passed / 0 failed / 1 skipped | 46 / 0 / 1 | 46 / 0 / 1 | ~40 s |
| admission (before UP-018) | 6 / 0 / 1 | 6 / 0 / 1 | 6 / 0 / 1 | ~8 s |
| admission (with the UP-018 mesh instance) | 8 / 0 / 2 | 8 / 0 / 2 | 8 / 0 / 2 | ~15 s |
| drain | 4 / 0 / 0 | 4 / 0 / 0 | 4 / 0 / 0 | ~22 s |

- Passed counts include both passes; skips are listed once and never counted as passes. The second
  admission skip is UP-018-H2.
- Across all eight recorded GW-003 passes, the keep-alive request during drain ended the same way:
  the idle socket was closed and the re-dial refused, and Anvil reported `client.connect.refused`.
- The unchanged `core` profile passed 36/36 with these diagnostics changes.
