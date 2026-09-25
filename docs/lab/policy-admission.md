# Failure lab: policy, admission and drain profiles

Three real-gateway profiles for the WAF/policy and gateway-admission families of the failure matrix
(build plan §15.3, §15.4). Every stimulus drives the pinned Ferrum Edge **v0.9.5** release binary
(`lab/gateway/RELEASE.lock`) with controllable local fixtures. No response is faked, and no failure
is injected as an enum.

| Profile | Gateway listeners | Fixture ports | Config | Scenarios |
|---|---|---|---|---|
| `policy` | HTTP 127.0.0.1:18280, admin :18290 | 19201–19210 (19207 and 19209 stay unbound on purpose) | `lab/gateway/policy.{conf,yaml}` | `crates/anvil-lab/src/policy.rs` |
| `admission` | HTTP 127.0.0.1:18580, admin :18590 | 19501–19502 | `lab/gateway/admission.{conf,yaml}` | `crates/anvil-lab/src/admission.rs` |
| `drain` | HTTP 127.0.0.1:18680, admin :18690 | 19601–19602 | `lab/gateway/drain.{conf,yaml}` | `crates/anvil-lab/src/drain.rs` |

Fixtures and shared helpers are in `crates/anvil-lab/src/fixtures_policy.rs`. The OPA and AI-provider
mocks are in `crates/anvil-fixtures/src/policy.rs`. `admission` and `drain` each change process-wide
behaviour (`FERRUM_MAX_REQUESTS=1`, a 64 KiB retained-response budget, SIGTERM), so each one runs as its
own gateway instance.

## 1. Running

```sh
export PATH=/opt/homebrew/opt/rustup/bin:$PATH   # macOS/Homebrew rustup
ulimit -n 4096
cargo run -p anvil-lab -- run policy --untrusted-pass
cargo run -p anvil-lab -- run admission --untrusted-pass
cargo run -p anvil-lab -- run drain --untrusted-pass
cargo run -p anvil-lab -- run policy --scenario GW-013-TIMEOUT   # one scenario
cargo run -p anvil-lab -- up policy       # keep fixtures + gateway up for manual/desktop use
```

- **Binary.** The lab looks for the verified binary in `$ANVIL_LAB_FERRUM_BIN`, then `lab/bin/`, then
  `../lab-bin/`. A git worktree under `.claude/worktrees/` should set `ANVIL_LAB_FERRUM_BIN` explicitly.
- **Results.** Each run writes `results/lab/<stamp>-<profile>/`:
  - `summary.json`
  - `<ID>.json`: checks, observed summary, recovery summary and operator-log evidence
  - `<ID>.record.json`: the full execution record
  - `gateway-operator*.log`: the drain profile also archives the log of every drained instance
- **Two passes.** `--untrusted-pass` repeats every scenario with the destination *not* declared as a
  Ferrum profile. In that pass no `ferrum.token.*` or `ferrum.outcome*` finding may appear, and a
  Ferrum-like header may only surface as `ferrum.marker.unverified`.
- **Trust ceiling.** In the trusted pass the destination is a trusted Ferrum profile over plain HTTP,
  so every marker-derived and body-derived claim is capped at `likely`. `X-Gateway-Error` and
  `X-Gateway-Upstream-Status` can be spoofed on 0.9.5 (see GW-019 below), so `confirmed` is not
  reachable in any case.

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

Where the plan asks for it, a scenario also has a deceptively similar lookalike that must *not*
receive the gateway diagnosis, plus a positive recovery.

## 2. Scenarios

"Lookalike" means an application-authored response through the plain `/ok` route. It is
byte-identical where noted.

### `policy` (23 scenarios per pass, plus 1 skip)

| ID | Matrix | What it proves |
|---|---|---|
| CTRL-POL-001 | — | Positive control. 200; the backend saw the request; no marker findings. |
| GW-010 | GW-010, TRUST-006 | **WAF header rule** gives 403 `{"error":"Forbidden"}`. Ground truth: `waf.action=blocked`, `waf.first_blocking_rule=ANVIL-LAB-HEADER`, and the backend was never hit. Anvil reports `http.forbidden` plus `ferrum.outcome_ambiguous` (unknown), no WAF/bot claim at ≥ likely, and no single-cause `ferrum.outcome`. **Lookalike:** the application answers a byte-identical 403, and Anvil gives the **identical** finding set. Recovery: the same route without the marker returns 200. |
| GW-010-BODY | GW-010 | **WAF request-body rule** (POST JSON marker) gives 403. Ground truth: rule `ANVIL-LAB-BODY`; the backend was not hit. Same cautious diagnosis. Recovery: a clean body returns 200. |
| GW-010-BOT | GW-010, TRUST-006 | **Bot detection** (User-Agent `anvil-lab-bot/1.0`) gives a 403 byte-identical to the WAF reject. Ground truth: `rejection_phase=on_request_received`, no `waf.*` metadata. Anvil's findings are identical to the WAF case. Recovery: a normal User-Agent returns 200. |
| GW-012 | GW-012 | **OPA deny** gives 403 `{"error":"forbidden by policy"}`. Ground truth: the OPA mock received the `anvil/lab/deny` query and its input; `rejection_phase=authorize`; the backend was not hit. Anvil reports `ferrum.outcome` = `plugin.opa.policy_denied` (≤ likely, gateway admission, identical-bytes caveat), no 401 or credential claim, and no WAF claim. **Lookalikes:** an application 403 with its own body gets no catalog attribution. An application 403 with byte-identical text stays ≤ likely and states the identical-bytes caveat. Recovery: `/gw/opa-allow` returns 200 after an `allow` query. |
| GW-013-TIMEOUT | GW-013 | **OPA stalls** (it accepts and reads the query but never answers; plugin timeout 500 ms). The gateway fails closed with 503 `{"error":"authorization service unavailable"}` and **no X-Gateway-Error**. Anvil reports `http.service_unavailable`, `ferrum.outcome` = `plugin.opa.fail_closed` (≤ likely), and `ferrum.marker.absent` (unknown) naming plugin rejections. It makes no credential or CPU claim and no backend-passthrough claim. **Lookalike:** the application's own 503 with byte-identical text is stamped `backend_error` by the gateway, so Anvil does *not* call it an OPA failure. Recovery: 200. |
| GW-013-REFUSED | GW-013 | **OPA unreachable** (nothing on 19209) gives the same fail-closed 503. Recovery removes the fault: an OPA mock is bound on 19209, the same route returns 200, and the mock answered the decision. |
| GW-013-ERROR | GW-013 | **OPA answers HTTP 500** (ground truth: the mock logged status 500) and the gateway fails closed with 503. Recovery: the fault is cleared on the same route, which returns 200. |
| GW-014 | GW-014 | **IP restriction** gives 403 `{"error":"IP address denied"}`. Ground truth: `rejection_phase=on_request_received`; the backend was not hit. Anvil reports `plugin.ip_restriction.ip_denied` (≤ likely), no client-leg finding, and no "unreachable" claim. Lookalike: an application 403 with a different body gets no attribution. |
| GW-015 | GW-015 | **OpenAPI validation.** Malformed JSON, a schema violation (`qty` minimum) and an unknown operation each return 400 `application/problem+json`. Ground truth: `rejection_phase=validate_client_request_contract`; the backend was not hit. The syntax and schema cases are distinguishable in the preserved body. There is no TLS or transport claim. **Lookalike:** an application-authored problem+json 400 gets identical findings. Recovery: a valid body reaches the echo fixture and returns 200. |
| GW-009 | GW-009 | **Response-transformer ceiling.** The origin served `{}` (ground truth); the transformer output of 129 bytes exceeds 128, giving 502 `{"error":"Response body too large","limit":128}` with `X-Gateway-Error: overload`. The operator log shows `error_class=dispatch_policy_rejected`. Anvil reports `ferrum.token.overload` (≤ likely, gateway admission) with the transformer and CPU caveats, `ferrum.outcome` = `gateway.response.transformer_output_ceiling`, and no CPU claim at any confidence. **Lookalikes:** an application 502 with the same bytes is stamped `backend_error`, with no overload claim. A plain response-size ceiling (`error_class=response_body_too_large`) gives no overload claim. Recovery: the 114-character transform fits and returns 200. |
| GW-004 | GW-004 | **Adaptive concurrency** (limit 1). While one request holds the permit for 3 s, a second gets 503 `concurrency_limit` with `x-adaptive-concurrency-limit: 1`. Ground truth: `rejection_phase=adaptive_concurrency`; only the occupant reached the backend. Anvil reports the token (≤ likely, gateway admission) and the catalog match. There is no 429 finding and no "rate limit" claim. **Lookalike:** an application 503 with byte-identical text gets `backend_error` and no `concurrency_limit` claim. Recovery: 200. |
| EXT-RL-001 | Plan §15.4 rate-limit extension (no seed ID; related to GW-004) | **Gateway rate limit** (2 per 2 s per IP; token bucket). The third request gets 429 `{"error":"Rate limit exceeded"}` with `x-ratelimit-*` headers. Ground truth: exactly 2 backend hits; `rejection_phase=on_request_received`. **Lookalike:** the application answers a byte-identical 429 with the same `x-ratelimit-*` headers, and Anvil gives **identical** findings (`http.too_many_requests` plus an ambiguous catalog finding). Recovery after refill: 200. |
| GW-020-GUARD | GW-020 | **AI request guard**, model not allowed: 400 `{"error":"Model not allowed",...}`. Ground truth: the provider was never called; `rejection_phase=before_proxy`. **Lookalike:** the provider's own 400 gets identical generic findings. Recovery: an allowed model returns 200. |
| GW-020-BUDGET | GW-020 | **AI token budget** (50 tokens per 3 s; the mock reports 30 per call). Two calls pass (60 tokens used, per provider ground truth), then the third gets 429 with `x-ai-ratelimit-remaining: 0`, refused before dispatch. **Lookalike:** the provider's own 429 (with Retry-After) is not attributed to a gateway budget. Recovery after the window: 200. |
| GW-020-PROVIDER | GW-020 | The **provider's 500** passes through and the gateway stamps `backend_error`. Anvil reports the token (≤ likely) with the "application itself produced" caveat and no gateway catalog attribution for the provider's envelope. Recovery: 200. |
| GW-020-CONTENT | GW-020 | **AI response content guard.** The provider answered 200 (ground truth); the gateway blocks it with 502 `{"error":"AI response blocked by content guard",...}` **and stamps `backend_error`**. Anvil must not blame the application or the gateway-to-provider leg: no passthrough claim and no `upstream_application` or `gateway_to_upstream` finding at ≥ likely. `ferrum.token.backend_error` lists response-policy rejections. Recovery: a clean reply returns 200. |
| GW-001-HALFOPEN | GW-001 (beyond core's open-state check) | **Circuit breaker.** Two backend 500s (ground truth: 2 hits) open it. A would-succeed request then gets 503 `circuit_breaker_open` with 0 backend hits. After 2 s, exactly one half-open probe is admitted; it fails, and the breaker re-opens immediately. After another 2 s a successful probe closes it, and traffic flows again. Operator log: `rejection_phase=circuit_breaker_open`. **Lookalike:** an application 503 with the breaker's exact body gets `backend_error` and no breaker claim. |
| GW-019-ERROR | GW-019 | A **response hook** writes `X-Gateway-Error: lab-spoofed-token` and `X-Gateway-Upstream-Status: degraded` on a refused-backend 502. The gateway **restores** the authoritative `connection_failure`, and Anvil sees no unknown token. The hook's `degraded` **survives** (verified live); Anvil keeps it ≤ likely and names plugins as possible writers. |
| GW-019-OK | GW-019 | The same hook on a 200. `X-Gateway-Error` is stripped and `degraded` passes. Anvil reports success and only a degraded-routing warning (≤ likely); untrusted, it reports only an unverified-marker warning. |
| GW-019-FORGED | GW-019, TRUST-011 | The **backend** forges both headers on a 200 (ground truth: fixture). Same result as GW-019-OK. |
| GW-019-REJECT-UNKNOWN | GW-019, TRUST-003 | A reject-path hook adds `X-Gateway-Error: lab-future-token` to an IP-deny 403, and it reaches the client. Anvil reports `ferrum.marker.unknown_token` (unknown) and no token meaning. |
| GW-019-REJECT-KNOWN | GW-019, TRUST-011 | A reject-path hook adds a **known** token (`overload`) to an IP-deny 403. Before the fix, Anvil reported "Gateway refused the request (overload category)" as **likely**. It now reports `ferrum.marker.inconsistent` (conflicting evidence), with no token finding and no overload or CPU claim (§4). |
| GW-014-GEO | GW-014 | **Skipped.** `geo_restriction` needs a readable MaxMind country `.mmdb`. `ferrum-edge validate` rejects a missing `db_path` ("not accessible before open"). No database is vendored and the lab may not download one, so neither the country-deny path nor the database-unavailable path is reachable. |

### `admission` (3 scenarios per pass, plus 1 skip)

| ID | Matrix | What it proves |
|---|---|---|
| CTRL-ADM-001 | — | Positive control. |
| UP-015 | UP-015 | **Retained-buffer exhaustion.** The backend answered a valid 200 with 256 KiB (ground truth); the gateway returns 503 `{"error":"Response buffering capacity exceeded"}` with **`X-Gateway-Error: backend_error`**. Operator log: `error_class=gateway_buffer_capacity`. Anvil reports `ferrum.token.backend_error` (≤ likely, scope **unknown**, gateway-local-limit caveat) and `ferrum.outcome_ambiguous`, whose candidates include `gateway.capacity.response_buffer`: 0.9.5 has two sources of this exact signal. There is no backend-passthrough claim, no `upstream_application` or `gateway_to_upstream` finding at ≥ likely, and no "unhealthy" claim. **Lookalike:** the application's own 503 is not called a buffer-capacity refusal. Recovery: 32 KiB fits and returns 200. |
| GW-002 | GW-002 | **Overload refusal** with `FERRUM_MAX_REQUESTS=1`. While one request holds the slot, the operator `/overload` level is `critical` and the log shows `Overload CRITICAL: rejecting new requests`. The probe gets 503 `{"error":"Service overloaded"}` with `overload` and never reaches a backend. An **unrouted** path also gets 503 `overload`, not 404, which shows the refusal precedes routing. Anvil reports `ferrum.token.overload` (≤ likely, gateway admission, CPU caveat) and the catalog match, with no application blame and no CPU claim. The fence lifts at the next monitor tick (about 50–100 ms after the slot frees; ground truth: `level` back to `normal`). **Lookalike:** the application's byte-identical 503 gets `backend_error` and no overload claim. Recovery: 200. |
| GW-005 | GW-005 | **Skipped.** It needs a real CP plus DP pair; file mode never installs the DP freshness fence. It is owned by the `cpdp` profile (ports 187xx/197xx). |

### `drain` (2 scenarios per pass)

| ID | Matrix | What it proves |
|---|---|---|
| CTRL-DRN-001 | — | Positive control. |
| GW-003 | GW-003 | **Graceful drain.** A keep-alive connection and a 6 s in-flight request are open when the gateway gets SIGTERM. The sequence that follows: (a) admin `/health` gives 503 `{"status":"draining","ready":false}` while a new connection in the 3 s pre-drain is still served (Anvil: plain success). (b) After the pre-drain, a raw connect is refused. Anvil reports `client.connect.refused` (confirmed, client-to-peer) with no `ferrum.*` finding and no "crash" claim; the "service is restarting" caveat is shown. (c) The in-flight request completes with 200 and `Connection: close`. (d) The keep-alive request during the drain is **racy by design**: a 503 overload, a closed socket or a refused re-dial are all possible. The check asserts that Anvil's explanation matches whatever occurred; in every recorded run the idle socket was closed and the re-dial refused. The gateway exits 0 after "All connections and requests drained successfully". Recovery: a fresh instance serves 200. |

## 3. Live 0.9.5 behaviour recorded by these runs

These results confirm or correct `docs/audit/gateway-lab-config.md` items that were marked "verify live".

- **Plugin rejections carry no marker.** WAF, bot, OPA deny, OPA fail-closed 503, IP, validator, rate
  limit, AI guard and AI budget responses carry no `X-Gateway-Error`. The operator transaction line has
  no `error_class`; it has `metadata.rejection_phase` instead: `authorize`, `on_request_received`,
  `before_proxy`, `validate_client_request_contract`, `adaptive_concurrency` or `circuit_breaker_open`.
- **Header protection is partial** (GW-019). The gateway restores `X-Gateway-Error` on its own error
  responses and strips hook- or backend-supplied copies on successful responses. It does **not**
  protect `X-Gateway-Upstream-Status` anywhere. It does **not** protect `X-Gateway-Error` on plugin
  rejection responses, which is the basis of the §4 fix.
- **`ai_response_guard` rejections are stamped `backend_error`** even though the provider answered
  200. The source catalog (`catalog/ferrum/ferrum-edge-0.9.5/outcomes.json`,
  `plugin.ai_response_guard.*`) lists no token. This is a catalog drift to correct; that file is outside
  this change.
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
- **Via differs, and Anvil ignores it.** A WAF header-phase reject has no `Via`; the body-phase reject
  and backend responses do. Anvil does not use `Via`, which is spoofable.

## 4. Diagnostics fixes made from these runs

All fixes are in `crates/anvil-diagnostics/src/rules/ferrum_rules.rs`, with wording in
`catalog/diagnostics/findings.en.json` (version `2026.09.25-3`). Each has a unit test in the same file.

1. **Known token on a non-5xx HTTP response gives `ferrum.marker.inconsistent`.** Confidence is
   conflicting evidence and scope is unknown. There is no token finding and no catalog match.
   - Found by GW-019-REJECT-KNOWN: an IP-deny 403 decorated with `X-Gateway-Error: overload` was
     reported as a likely gateway overload.
   - gRPC-shaped responses (HTTP 200 trailers-only) are exempt.
2. **The `backend_error` token no longer claims a leg or an owner.** Scope and owner are now unknown,
   and the wording adds response-phase policy rejections.
   - Found by UP-015 and GW-020-CONTENT: the gateway stamps `backend_error` on its own refusals, so
     the old `gateway_to_upstream` scope was wrong in both cases.
3. **`ferrum.marker.absent` names plugin rejections first** (GW-013: OPA fail-closed 503).
4. **`ferrum.outcome_ambiguous` wording.** It says a backend can return identical bytes, and its title
   no longer says "gateway causes" (GW-010, GW-010-BOT, EXT-RL-001).
5. **`ferrum.degraded_routing` wording.** It names response-header plugins as possible writers
   (GW-019).

No fix raises any confidence. The seven tokens keep their coarse meaning. No remediation suggests
disabling the WAF, TLS or a policy.

## 5. Limitations

- **Evidence mode.** Only plain-HTTP trusted profiles are exercised, so `confirmed` gateway
  attribution is never expected. On 0.9.5 it would require the proposed gateway-owned diagnostic
  contract (plan §9.4).
- **Mocks.** The OPA and AI mocks verify the gateway's adapter behaviour only, not any real policy
  engine or provider.
- **Not covered here.** ACL denial (GW-011) belongs to the `auth` profile, and stale DP config
  (GW-005) to `cpdp`.
- **Drain.** The in-connection overload refusal is racy and cannot be forced. Only its diagnosis is
  checked, whichever branch occurs.
- **Timing.** Scenarios depend on wall-clock gaps:
  - 500 ms to occupy a permit;
  - 2–3 s rate and AI windows;
  - the 3 s pre-drain.
  They passed on an idle Apple-silicon Mac. A heavily loaded host may need longer gaps.
- **Platform.** The lab has run on macOS arm64 only. Linux and Windows gateway assets are pinned in
  `RELEASE.lock` but were not exercised.

## 6. Stability record

The runs below used `anvil-lab run <profile> --untrusted-pass` against v0.9.5, on macOS 26 arm64, on
2026-09-25. There were three consecutive runs per profile after the final commit.

| Profile | Run 1 | Run 2 | Run 3 | Wall time per run |
|---|---|---|---|---|
| policy | 46 passed / 0 failed / 1 skipped | 46 / 0 / 1 | 46 / 0 / 1 | ~40 s |
| admission | 6 / 0 / 1 | 6 / 0 / 1 | 6 / 0 / 1 | ~8 s |
| drain | 4 / 0 / 0 | 4 / 0 / 0 | 4 / 0 / 0 | ~22 s |

- The passed counts include both passes: the trusted pass and the `-untrusted` repeat of each
  scenario. Skips are listed once, with their reason, and are never counted as passes.
- Across all eight recorded GW-003 passes, the keep-alive request during drain ended the same way:
  the idle socket was closed and the re-dial refused, and Anvil reported `client.connect.refused`.
- **Core regression check.** The unchanged `core` profile passed 36/36 with these diagnostics changes.
  Another session held the core ports (180xx/190xx) at the time, so the check ran from a scratch copy
  of this tree with only core's port numbers shifted into the idle policy block (182xx/192xx).
