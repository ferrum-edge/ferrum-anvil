# Ferrum Edge 0.9.5 → 0.9.7: client-observable delta (A00 addendum)

| Item | Value |
|---|---|
| Compatibility ids | `ferrum-edge-0.9.5` (unchanged) and `ferrum-edge-0.9.7` (new, the default for new profiles) |
| Releases compared | tag `v0.9.5` = `20e76030a05dc49c3804e969516c94ab101110b9` (`20e7603`) → tag `v0.9.7` = `8fed1346ce2e267eb69c03683cb89ea44d785e0b` (`8fed134`). `v0.9.6` was tagged but never published; 0.9.7 ships its content. |
| Audit date | 2026-09-25 |
| Machine-readable inventory | [`catalog/ferrum/ferrum-edge-0.9.7/outcomes.json`](../../catalog/ferrum/ferrum-edge-0.9.7/outcomes.json): **538** outcomes (528 − 1 removed + 11 added), 47 changed, 1339 source citations |
| Baseline audit | [`gateway-source-audit.md`](gateway-source-audit.md) and [`catalog/ferrum/ferrum-edge-0.9.5/outcomes.json`](../../catalog/ferrum/ferrum-edge-0.9.5/outcomes.json) |
| Source diff | 285 files under `src/` differ; about 43,000 changed lines (`src/proxy/mod.rs` 2,928) |
| Wire libraries | rustls 0.23.40 → 0.23.45; hyper 1.9.0, h2 0.4.19, h3 0.0.8, quinn 0.11.9, reqwest 0.13.3 and tungstenite unchanged; hyper-util 0.1.20 is now vendored with a Ferrum patch |

All `path:line` citations below are at `v0.9.7` (`8fed134`) unless marked `@20e7603`.

## Method

- **Read-only.** Both trees were exported with `git archive --remote` into a scratch directory. The gateway repository was never checked out, modified or switched.
- **Mechanical carry-forward.** Each of the 1216 source citations in the 0.9.5 catalog was remapped through the `diff` line map of its file. 1212 landed on unchanged lines, and the line text was checked to be identical in both trees. The other 4 landed in changed hunks (the WAF `finish_timeout` and `parse_redis_failure_policy`) and were re-cited by hand. Path:line references in prose were remapped the same way. Bare line numbers without a path (e.g. "line 492") were mapped one by one. Every citation now carries sha `8fed134`.
- **Re-audit of changed code.** An outcome was flagged when the function around any of its citations changed. That flagged 159 of the 528 outcomes. The flagged outcomes were split into five read-only slices, each audited in both trees against the shared rules below:
  - HTTP proxy core;
  - gRPC, WebSocket, HTTP/2 connection, HTTP/3 and L4;
  - authentication and authorization plugins;
  - traffic, WAF, validation and transform plugins;
  - AI and agent plugins.
- **Rules for each slice:**
  - read the response builder, the reject helper and every helper the outcome depends on, not only the cited line;
  - diff the set of status, JSON body, header-name, gRPC-status, WebSocket close-code and H3 error-code literals per file, to catch new or removed signals the flagging missed;
  - check every CHANGELOG `[0.9.7]` entry and every drift note in the 0.9.5 catalog against the code.
- **Spot checks.** Each key literal and line was re-read at the cited location, for example: `ROUTE_REQUEST_TIMEOUT_BODY` `src/proxy/mod.rs:48962`; `route_request_timeout_response` `:49270` with `connection_error: false`; the H3 refusal `src/http3/server.rs:4708`/`:18296`; `parse_redis_failure_policy` `src/plugins/utils/rate_limit.rs:95-104`; `SPEC_RESPONSE_CSP` `src/plugins/spec_expose.rs:728`; `NOT_YET_VALID_BODY` `src/plugins/oauth2_introspection.rs:1210`; the `iss` check `src/plugins/jwt_auth.rs:262-264`; the bot-detection anchors `src/plugins/bot_detection.rs:187-219` against `@20e7603` `:188-205`; `matches_endpoint` `src/plugins/mcp_gateway.rs:1213@20e7603`; and `alt_svc_for_frontend_port` `src/proxy/mod.rs:10647`.
- **Mechanical checks of the result.**
  - Every citation in the new catalog points at an existing line. It is either a text-identical remap of a 0.9.5 citation (1203) or a token of its symbol appears within ±6 lines (the rest; 7 cite a line inside the named function and were checked by hand).
  - Every prose `path:line` is in range and non-blank at `v0.9.7`, apart from references explicitly marked `@20e7603`.
  - The drift test (`crates/anvil-diagnostics/tests/catalog_drift.rs`) checks both catalogs for internal consistency: sibling, fixture and removal ids resolve, tokens are in the vocabulary, and every citation uses the catalog's own sha.
- **Live checks.** `anvil-lab run all --untrusted-pass` against both release binaries. Three new release-aware scenarios reproduce three deltas (see [Lab](#lab)).
- **Not a completeness proof.** As with the 0.9.5 audit, only strings seen in code are recorded, and wire behaviour owned by hyper, h2, rustls or quinn is marked as such.

## Unchanged: the marker contract

- `src/retry.rs` is byte-identical, and so are `src/proxy/headers.rs` (response strip list), `src/proxy/stream_error.rs`, `src/proxy/response_buffer_budget.rs`, `src/proxy/auth_lifetime.rs` and `src/plugins/utils/openai_error.rs`.
- The 19 error classes, the 7 `X-Gateway-Error` tokens and their derivation are identical: `(connection_error, status)` → `connection_failure` / 504 `backend_timeout` / ≥500 `backend_error` (`src/retry.rs:281`).
- The HTTP→gRPC reject map `http_reject_status_to_grpc_status` is identical. It moved from `src/proxy/grpc_proxy.rs:2225@20e7603` to `:2307`.
- The reject builders (`build_response` `src/proxy/mod.rs:48094`, `build_response_with_gateway_error` `:48107`, `build_pre_plugin_reject_response` `:28688`, `normalize_reject_response_with_provenance` `:25802`) and the Via, Allow and `restore_authoritative_*` writers have no diff hunks.

**Consequences for Anvil.** The markers are still spoofable, so marker-derived claims stay capped at likely. `backend_error` still carries scope Unknown. The 4xx-marker inconsistency rule and "a missing marker proves nothing" hold on both releases. These are the only token semantics Anvil applies to a profile whose compatibility id has no catalog.

## Removed outcome

| Outcome | 0.9.5 signal | 0.9.7 behaviour | Evidence |
|---|---|---|---|
| `upstream.h1_stranded_pooled_request_v095` | A pooled HTTP/1 connection that closes at enqueue time strands the request until `backend_read_timeout_ms`, then 504 `{"error":"Backend timeout"}` + `backend_timeout`, although nothing reached the backend. | On a reused connection the request is replayed on a new one (any method; nothing was sent). On a fresh connection it fails at once: 502 `{"error":"Backend unavailable"}` + `connection_failure` (`connection_pool_error`, `upstream.pool.dispatch_canceled`). The same applies to HBONE inner and Unix-socket HTTP/1. | `vendor/hyper-util-0.1.20-ferrum-patched/src/client/legacy/client.rs:327, :901, :1001`; `src/proxy/h1_send_release.rs:73`; `src/proxy/mod.rs:43680`, `:43695`, `:51550`, `:52509`; CHANGELOG #5714/#5719/#5720 |

It is listed under `removed_outcomes` in the 0.9.7 catalog. The 0.9.5 catalog keeps it.

## New outcomes

| Outcome | Public signal | Where | Notes |
|---|---|---|---|
| `upstream.route_request_timeout.backend_held` | 504 `{"error":"Request timeout"}` + `backend_timeout` | `src/proxy/mod.rs:48962`, `:49270`, `:49291`; `src/plugins/mod.rs:4379` | Gateway API HTTPRoute `timeouts.request` / `mesh_route_dispatch` `request_timeout_ms` expired while a backend held the attempt. `error_class` `read_write_timeout`. HTTP/1.1 and HTTP/2 only. Never retried. |
| `upstream.route_request_timeout.not_dispatched` | same bytes | same, plus `:49211`, `:38314` | Same deadline expired before any backend got the request (upload, hooks, DNS, admission) or in retry backoff. `error_class` `dispatch_policy_rejected`. **Before dispatch this is a 504 `backend_timeout` that never reached a backend**; in retry backoff an earlier attempt did reach one. |
| `upstream.timeout.route_attempt_budget` | 504 `{"error":"Backend timeout"}` + `backend_timeout` | `src/proxy/mod.rs:49296`; `src/plugins/mod.rs:4416` | Per-attempt budget (`timeouts.backendRequest` / `attempt_timeout_ms`). Byte-identical to the read-timeout 504, so it joins that ambiguous family. |
| `streaming.route_deadline_cut_after_headers` | partial body; HTTP/2 reset or HTTP/1.1 close; `Content-Length` kept | `src/proxy/body.rs:1047`, `:4644`, `:4889`; `src/proxy/mod.rs:41001` | Either route deadline cuts a response still streaming, including healthy downloads, SSE and long polls. |
| `protocol.http3.route_timeout_unsupported` | 503 `{"error":"Route request timeout is not supported over HTTP/3"}`, no token | `src/http3/server.rs:4708`, `:18296` | Plain (non-gRPC) HTTP/3 request on a rule with a route timeout. The code passes grpc-status 14 to the writer, but the gate only admits the plain flavor, so no gRPC or gRPC-Web client can receive it. Rejection phase `route_request_timeout_unsupported`. |
| `protocol.hbone.connect_peer_not_admitted` | 403 `{"error":"HBONE tunnel requires an authenticated mesh peer"}` \| `{"error":"HBONE UDP tunnel requires an authenticated mesh peer"}` | `src/proxy/hbone_proxy.rs:679`, `:730`, `:1466`, `:1507` | Mesh only. The bodies already existed at 0.9.5 for unauthenticated peers (`hbone_proxy.rs:629/1216@20e7603`). 0.9.7 adds the same body for peers whose chain is no longer trusted or is revoked. |
| `protocol.hbone.tunnel_admission_revoked` | reasonless tunnel end | `src/proxy/hbone_proxy.rs:1257`; `src/proxy/hbone_admission_fence.rs:213`, `:325` | Mesh only. A live tunnel is cut when a later policy or trust publication would refuse it. |
| `plugin.oauth2_introspection.token_not_yet_valid` | 401 `{"error":"Token is not yet valid"}` + `WWW-Authenticate: Bearer error="invalid_token"` (gRPC 16) | `src/plugins/oauth2_introspection.rs:1210`, `:1301`, `:1242`, `:854` | The provider returned a future integer `nbf` (#5523). 0.9.5 ignored `nbf`. **Lab `AUTH-X01.nbf`.** |
| `plugin.mesh_outbound_registry.destination_not_registered` | 502 `{"error":"destination not in mesh registry (REGISTRY_ONLY policy)"}` (configurable) | `src/plugins/mesh/outbound_registry.rs:572`, `:314`, `:605` | Already present but uncatalogued at 0.9.5. 0.9.7 never enforces it on Inbound listeners (#5595). |
| `plugin.mesh_outbound_registry.host_header_missing` | 502 `{"error":"host header required"}` | `src/plugins/mesh/outbound_registry.rs:562`, `:314` | Same as the entry above. |
| `plugin.response_transformer.response_trailers_dropped` | backend trailers missing | `src/plugins/response_transformer.rs:1283`, `:713`, `:1306` | Already present but uncatalogued at 0.9.5. 0.9.7 narrows it for rules-free route-override consumers. |

Three of these (the outbound-registry pair and the trailer drop) are 0.9.5 gaps found during this audit. They were not backfilled into the 0.9.5 catalog, whose content stays as audited apart from the fixes listed at the end.

## Changed outcomes

Each change was read in both trees. "Signal" means the status, body, token, headers, gRPC status or close code that the client sees.

### Route timeouts (Gateway API HTTPRoute / `mesh_route_dispatch`, #5646)

These affect only rules that carry `timeouts.request` / `timeouts.backendRequest` (or `request_timeout_ms` / `attempt_timeout_ms`). No such rule exists at 0.9.5.

| Outcome | Change | Evidence |
|---|---|---|
| `upstream.timeout.response_header_wait`, `upstream.timeout.upload_write_stall`, `upstream.timeout.buffered_body_idle` | The signal is unchanged. `shared_signal_with` gains `upstream.timeout.route_attempt_budget` and drops the removed stranded-request race. | `src/proxy/mod.rs:43680`, `:46191`, `:46870`; default timeouts `src/config/types.rs:5699`, `:5703` |
| `upstream.application_504` | `must_not_claim` also excepts the gateway's new `{"error":"Request timeout"}` 504 body. | `src/proxy/mod.rs:48962` |
| `streaming.backend_body_failure_after_headers`, `streaming.idle_read_timeout_after_headers`, `streaming.response_size_exceeded_mid_stream`, `streaming.authorization_lifetime_expired_after_commit` | Now share their signal with the route-deadline body cut. | `src/proxy/body.rs:1047` |
| `protocol.grpc.client_deadline_exceeded` | Same trailers-only grpc-status 4 `Deadline exceeded at gateway`. A route rule timeout folded into the RPC deadline now produces the identical signal, so the owner changes from caller to unknown. | `src/plugins/mod.rs:4379`; `src/proxy/mod.rs:32949`, `:33206`; `src/http3/server.rs:4708` |
| `protocol.grpc.deadline_streaming_before_data`, `protocol.grpc.deadline_streaming_after_data` | Same terminals (synthesized trailers, or a reset after DATA). The cause set now includes route timeouts. | `src/proxy/body.rs:983`, `:4729`, `:4630`; `src/plugins/mod.rs:4429` |
| `protocol.grpc.backend_timeout` | `Backend deadline exceeded` can also be a route per-attempt budget that expired after send (H1/H2 only; H3 never re-shapes it). | `src/proxy/mod.rs:49404`, `:49426` |
| `plugin.grpc_deadline.deadline_exceeded_at_gateway`, `plugin.custom.hook_timeout` | Plugin hooks on gRPC requests are bounded by the folded route deadline too. | `src/plugins/mod.rs:4379`, `:7022` |

The headers change as well:
- `Alt-Svc` is withheld on every frontend port that serves such a rule, and on all ports when the rule is global or its proxy has no `listen_port` (`src/proxy/mod.rs:6647`, `:10647`, `:10670`).
- The `X-Gateway-Error` entry now notes that the route-deadline 504 carries `backend_timeout` even when not dispatched.

### Backend pool (#5714, #5720)

| Outcome | Change | Evidence |
|---|---|---|
| `upstream.pool.dispatch_canceled` | Now also the immediate result of the stranded-request race on a fresh HTTP/1 connection (see Removed). A never-sent request on a fresh HBONE or Unix-socket lease is `connection_pool_error` even with a streaming body. | `vendor/hyper-util-0.1.20-ferrum-patched/.../client.rs:327`; `src/proxy/h1_send_release.rs:73`; `src/proxy/mod.rs:51556`, `:52515` |

### WAF scan budget (#5528)

| Outcome | Change | Evidence |
|---|---|---|
| `plugin.waf.request_rule_block`, `plugin.waf.response_rule_block` | The body scan always runs to completion and hits decide first. At 0.9.5, scheduler delay could skip the scan and forward the body unscanned under the default `log_and_allow`. Same 403. | `src/plugins/waf/mod.rs:633`, `:686`; `@20e7603` `src/plugins/waf/mod.rs:596-615` |
| `plugin.waf.scan_timeout_block` | New `on_scan_timeout: fail_closed`: 403 on a clean over-budget body scan, only where an enforcing body policy applies. `block` is unchanged. The budget clock starts after the fairness yield. | `src/plugins/waf/mod.rs:1056-1060`, `:1086`, `:2096` |
| `plugin.waf.no_client_signal` | An over-budget pass is now always an inspected, clean body. `fail_closed` passes when no enforcing policy applies. | `src/plugins/waf/mod.rs:1060` |
| `plugin.waf.ws_rule_close`, `plugin.waf.ws_uninspectable_close` | An enforcing hit over budget still closes 1008 "message rejected by security policy". `fail_closed` can produce the "could not be inspected" close. | `src/plugins/waf/websocket.rs:340`, `:407`, `:436`, `:472` |

### Redis request quotas (#5517, #5519, #5692)

| Outcome | Change | Evidence |
|---|---|---|
| `plugin.rate_limiting.enforcement_unavailable` | No longer the default on a Redis outage: `rate_limiting` now defaults `redis_failure_policy` to `local_fallback`. With explicit `fail_closed` it also fires when Redis refuses `TIME` (ACL lacks `+time`) or when charges keep mis-settling. The body is unchanged. | `src/plugins/utils/rate_limit.rs:95-104`; `src/plugins/utils/redis_rate_limiter.rs:4415`; `@20e7603` `src/plugins/utils/rate_limit.rs:84-86` |
| `plugin.rate_limiting.exceeded`, `plugin.rate_limiting.admitted_decoration`, `plugin.rate_limiting.local_state_capacity`, `plugin.rate_limiting.stream_refused` | Same 429 bytes and still no `Retry-After`. Redis counting is a 16-sub-bucket trailing window with refund-on-refusal, so the 429 boundary and `x-ratelimit-remaining` values differ. An outage now gives per-process 429s instead of the 503, and streams are refused only under explicit `fail_closed`. | `src/plugins/utils/rate_limit.rs:2447`, `:2594`, `:2620`; `src/plugins/rate_limiting.rs:542`, `:658`, `:835` |
| `plugin.graphql.rate_limited`, `plugin.grpc_method_router.method_rate_limited` | The same Redis counting applies, and consumer keys are tagged `consumer:` / `ip:`, so counters restart once on upgrade. | `src/plugins/graphql.rs:500`; `src/plugins/grpc_method_router.rs:467` |
| `plugin.graphql.rate_enforcement_unavailable`, `plugin.grpc_method_router.enforcement_unavailable` | The default stays `fail_closed`. A missing `TIME` and mis-settlement are new triggers. | `src/plugins/graphql.rs:292`; `src/plugins/grpc_method_router.rs:275` |

### Authentication

| Outcome | Change | Evidence |
|---|---|---|
| `plugin.jwt_auth.invalid_jwt_token` | A token whose `iss` is not a single string (array, null, number, object) gets the existing 401 `{"error":"Invalid JWT token"}`, whether or not an issuer is configured (#5522). | `src/plugins/jwt_auth.rs:262-264`; `src/plugins/utils/jwt_verifier.rs:72`; **lab `AUTH-009.iss-array`** |
| `plugin.jwks_auth.invalid_or_unrecognized_jwt` | Same rule in the shared verifier: 401 `{"error":"Invalid or unrecognized JWT"}`. | `src/plugins/utils/jwt_verifier.rs:54`; **lab `AUTH-009.iss-array`** |
| `plugin.oidc_relying_party.callback_invalid_id_token` | Same rule: 400 `{"error":"Invalid ID token"}`. | `src/plugins/oidc_relying_party.rs:1552` |
| `plugin.oauth2_introspection.introspection_unavailable` | A present, non-null, non-integer `nbf` now gives 503. | `src/plugins/oauth2_introspection.rs:1289-1306` |
| `plugin.oidc_relying_party.challenge_api_invalid_or_expired_session`, `plugin.oidc_relying_party.challenge_browser_redirect_clear_session` | A fractional ID-token `exp` now bounds the session (#5521). Signal unchanged, timing earlier. | `src/plugins/oidc_relying_party.rs:3983`, `:4049`, `:1690` |

### Other plugins and relays

| Outcome | Change | Evidence |
|---|---|---|
| `plugin.bot_detection.forbidden` | `allow_list` entries with a punctuation edge now match, so fewer 403s (#5685). Body unchanged. | `src/plugins/bot_detection.rs:187-219` vs `@20e7603` `:196-198`; **lab `GW-010-BOT.allow-edge`** |
| `plugin.mcp_gateway.unknown_endpoint` | Case variants (`/MCP`, `/Mcp/x`) and `%`-suffixed paths of the MCP scope now get the 404 JSON-RPC `Unknown MCP endpoint` instead of reaching the backend. | `src/plugins/mcp_gateway.rs:1220`, `:8355`, `:5691` |
| `plugin.spec_expose.spec_served` | Adds `Content-Security-Policy: default-src 'none'; sandbox` (#5686). A new `Content-Security-Policy` header entry was added. | `src/plugins/spec_expose.rs:728`, `:1031-1034` |
| `plugin.response_caching.hit`, `plugin.request_deduplication.replay`, `plugin.ai_semantic_cache.hit`, `plugin.ai_semantic_cache.miss_bypass` | Replay keys bind the route's response-header transforms and the route-override backend TLS/DNS policy (#5709, #5710). Entries do not cross such rules, and every key misses once after the upgrade. | `src/plugins/utils/replay_partition.rs:574`, `:655-682`, `:709` |
| `plugin.ai_stream_router.translation_rejected` | Anthropic `reasoning_effort` is validated: unsupported values get 400 `invalid_reasoning_effort`, where 0.9.5 silently dropped the field. Adaptive `thinking.display` summarized/omitted is now accepted. Not in the CHANGELOG. | `src/plugins/ai_stream_router.rs:2024`, `:2037`, `:1988-2008`, `:3004-3013` |
| `plugin.ai_federation.invalid_request` | Two messages quote the tool name with `"` instead of `'`. | `src/plugins/ai_federation.rs:2435`, `:2497` |
| `l4.tcp.mid_stream_disconnect`, `protocol.ws.tunnel_mode_stop` | Relays flush a TLS writer before parking. TCP/TLS relays keep `backend_write_timeout_ms` armed across the flush and the half-close, so a stall that hung on 0.9.5 now ends with "backend write inactivity timeout". WebSocket tunnel mode arms no write timeout, so it gains the flush but no new close. The client still sees a reasonless close. | `src/proxy/tcp_proxy.rs:8706`, `:8755`, `:8839`, `:8984`; `src/proxy/mod.rs:19362`, `:19600` |

### Other catalog-level changes

- `rejection_phases_operator_only` gains `route_request_timeout_unsupported`. The literal diff over all `log_*rejected_request` sites found no other new phase.
- `X-Ferrum-*`: the mesh-only `x-ferrum-mesh-tunnel-reuse: fenced` on HBONE CONNECT 200s is now the one client-visible `X-Ferrum-*` header (`src/proxy/hbone_proxy.rs:1411`). It is seen only by a peer mesh proxy and is not a diagnostic marker.

## Corrections to the 0.9.5 catalog's drift notes

The 0.9.5 audit had a preliminary look at `8ef06f2`/`main` (now `v0.9.7`). Reading the code corrected three of its notes:

1. **MCP trailing slash.** At 0.9.5 `/mcp/` was already a 404 when `endpoint.path` is `/mcp` (`matches_endpoint` was exact, `src/plugins/mcp_gateway.rs:1213@20e7603`). The #5536 alias existed only between the tags. The real delta is the case-insensitive and `%`-suffixed scope.
2. **HTTP/3 route-timeout refusal.** The drift note's "gRPC 14" is unreachable: the gate is plain-flavor only, and gRPC/gRPC-Web fold the budget into their deadline (DEADLINE_EXCEEDED).
3. **HBONE 403.** The bodies are not new (see `protocol.hbone.connect_peer_not_admitted`).

In addition, `null nbf treated as absent` belongs to `oauth2_introspection` (`src/plugins/oauth2_introspection.rs:1293`), not to `jwt_auth`.

## Catalog data fixes found in passing (both catalogs)

These are errors in data carried over from the 0.9.5 audit, not gateway changes. They are fixed in both catalogs and recorded in each catalog's `drift` section (`v095_audit_corrections` / `catalog_corrections_v097_audit`).

1. **gRPC status.** Fifteen native-gRPC records carried `public_signal.grpc_status: 13` while their own audited `grpc-status` header value was different, for example 7 or 8. Affected ids include `plugin.grpc_method_router.*`, `plugin.grpc_deadline.*`, `plugin.waf.grpc_reject_mapping` and `proxy.auth_phase.grpc_deadline_exceeded`.
   - `grpc_status` now equals the audited value where it is a single number, and is null (unconstrained) where the header varies.
   - Each fixed record's notes say so.
   - None of these records has a body pattern, so none could match a response before or after the fix.
2. **Content-Type on backend-failure bodies.** The 0.9.5 audit recorded `Content-Type: application/json` on the gateway's backend-failure responses. On the HTTP/1.1 and HTTP/2 path these carry **no** `Content-Type` header, because the builders use an empty header map (`http_backend_dispatch_error_response` `src/proxy/mod.rs:43695`; `backend_dns_resolution_failed_response` `:43947`; `route_request_timeout_response` `:49270`).
   - Affected bodies: 502 `Backend unavailable`, `Backend DNS resolution failed`, `Backend response body read failed` and `Backend response body exceeds maximum size`; 503 `Response buffering capacity exceeded` and `Backend connection limit exceeded`; 504 `Backend timeout`.
   - Observed live over HTTP/1.1 on both releases in UP-001, UP-002, UP-009, UP-010, UP-013, UP-014, UP-015, UP-018, UP-020 and GW-019-ERROR.
   - Plugin rejects and admission fences (GW-001/002/004/005, GW-013, AUTH-*) do carry `application/json`.
   - 26 outcomes and the `Content-Type` header entry are corrected. The WebSocket upgrade variant (`protocol.ws.backend_connection_limit`) sets `application/json` itself and is unchanged. The HTTP/3 writer was not lab-checked.
   - `other_headers` is never used for matching.

## Anvil changes this delta drives

- **Per-release catalogs.** `anvil_diagnostics::ferrum` embeds both catalogs and selects the one whose id equals the trusted profile's `compatibility_id` (`catalog_for`).
  - An id with no catalog never borrows another release's catalog. Anvil emits `ferrum.catalog.unavailable` (confidence unknown), skips outcome matching, and keeps only the token vocabulary and coarse meaning that every audited release shares (`shared_tokens`).
  - Every execution record's `catalog_version` names the catalog actually used, for example `findings:… ferrum:ferrum-edge-0.9.7`, `…(no-catalog)` or `none`.
- **Release notes on token findings.** Release-specific sentences are no longer hard-coded in `catalog/diagnostics/findings.en.json`. Each catalog carries them in `marker_semantics`:
  - 0.9.5: "a pooled HTTP/1.1 connection … can hold a request until the read timeout";
  - 0.9.7: "a route's total request timeout can end a request with a 504 before any backend received it".
- **Default release.** New profiles default to `ferrum-edge-0.9.7`: the desktop dialog, the CLI `--trust-ferrum` and the lab default pin.

## Lab

`anvil-lab --release <r> run all --untrusted-pass`. Every scenario runs trusted, where the lab's Ferrum profile declares the running release's compatibility id, and again untrusted.

| Release | Binary | Result |
|---|---|---|
| v0.9.7 (`lab/gateway/RELEASE.lock`, `lab/gateway/releases/v0.9.7.lock`) | `ferrum-edge-macos-aarch64` sha256 `f3bd0027…0dd03` | 442 passed, 0 failed, 17 skipped: core 36/0/0, policy 48/0/1, admission 8/0/2, drain 4/0/0, tls 66/0/7, auth 80/0/5, streams 84/0/0, cpdp 10/0/0, h3x 34/0/0, mesh 30/0/2, proxyproto 42/0/0 (2026-09-26, after the protocol merges) |
| v0.9.5 (`lab/gateway/releases/v0.9.5.lock`) | `ferrum-edge-macos-aarch64` sha256 `6a531f2c…ce5f` | 442 passed, 0 failed, 17 skipped: the same per-profile counts |

Behaviour differences observed live:

| Scenario | v0.9.5 | v0.9.7 |
|---|---|---|
| `AUTH-009.iss-array`: HS256 token with `iss: [issuer, other]` on `jwt_auth` (no issuer configured), ES256 token with the same array on `jwks_auth` (issuer configured) | both accepted (200) | 401 `Invalid JWT token` and 401 `Invalid or unrecognized JWT`; the catalog match is at most likely, and none untrusted |
| `GW-010-BOT.allow-edge`: `User-Agent: anvil-lab-bot/1.0 (anvil-lab-monitor/)` with `allow_list: [anvil-lab-monitor/]` | 403 `{"error":"Forbidden"}` (blocked; backend untouched) | 200 (allowed; backend reached) |
| `AUTH-X01.nbf`: the IdP fixture reports an active opaque token with `nbf` = now + 600 s | 200 (`nbf` ignored; backend reached) | 401 `{"error":"Token is not yet valid"}` + `Bearer error="invalid_token"`; matched to `plugin.oauth2_introspection.token_not_yet_valid` at most likely; backend untouched |

Every other scenario gave the same result on both releases. That includes UP-016, the backend mTLS rejection class: the lab drives the TLS-alert path, not the enqueue race, so it does not exercise the removed outcome.

## Not verified live (source only)

- **Route timeouts.** They need Gateway API or `mesh_route_dispatch` rules with `request_timeout_ms` / `attempt_timeout_ms`, which `ferrum-edge validate` rejects on 0.9.5, and the file-mode lab shares one config across releases. This covers the 504 `Request timeout` pair, the body cut, gRPC folding, the HTTP/3 503 and Alt-Svc withholding.
- **The stranded pooled HTTP/1 race** (#5714). It is timing-dependent.
- **Redis quota counting, the `TIME` requirement and the `local_fallback` default.** The lab has no Redis.
- **WAF `fail_closed`.** It needs a reliably over-budget clean scan.
- **MCP case variants and the spec_expose CSP header.** These plugins are not in the lab profiles.
- **The introspection non-integer `nbf` 503.** Only the future-integer `nbf` 401 is reproduced live (`AUTH-X01.nbf`).
- **Library-owned details.** The HTTP/2 RST code on a route-deadline cut and FIN vs RST on a relay write-timeout close belong to hyper, h2 and the OS.
- **HTTP/3 `Content-Type` on backend-failure bodies.** Only the HTTP/1.1 path was observed.
