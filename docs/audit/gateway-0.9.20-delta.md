# Ferrum Edge 0.9.15 → 0.9.20: source delta audit

| Item | Immutable identity / status |
|---|---|
| Baseline | `v0.9.15`, `25b37395ff61bfea0f3ffd189d9011c4984fa755` (source-audited and hosted-qualified in [gateway-0.9.15-delta.md](gateway-0.9.15-delta.md)) |
| Audited target | `v0.9.20`, `e4a606a00352674daaef08636e3e359e6c48ba18` (merge of Edge #7016), [release 432463173][release], published 2026-11-03T08:58:10Z |
| Contracts | Published `contracts-edge-0.9.20`, `39da322083044c2e92617209e62983c92387f0ad` |
| Catalog | [`ferrum-edge-0.9.20/outcomes.json`](../../catalog/ferrum/ferrum-edge-0.9.20/outcomes.json), 620 outcome IDs: the 556 of 0.9.15 − 2 removed + 66 new |
| Lab selection | `lab/gateway/RELEASE.lock` and `lab/gateway/releases/v0.9.20.lock`; the only supported release: v0.9.5 to v0.9.15 were retired with Anvil's vendored dimpl after adoption (see [#7001](#dtls-13-certificaterequest-omits-the-empty-certificate_authorities-list-7001)) |
| Hosted qualification | All-profile Lab run 41810892175 on `main` at `cfd4e196`; results are recorded below |
| Audit date | 2026-11-03 |

The [immutable comparison][compare] spans 456 commits and four tags: v0.9.16 and v0.9.18 were
tagged but never published, v0.9.17 and v0.9.19 were published, then v0.9.20. It changes 293 files
under `src/` (106,065 insertions, 16,520 deletions; 16 new files, among them
`src/proxy/hop_limit.rs`, `src/proxy/client_abort.rs`, `src/proxy/client_abort_scope.rs`,
`src/proxy/client_write_stall.rs`, `src/proxy/request_headers.rs`, `src/plugins/config_contract.rs`,
`src/plugins/cors_psl_ancestors.rs`, `src/plugins/waf/json_doc.rs` and `src/plugins/waf/grpc.rs`), plus
vendored crate patches, tests, benchmarks and documentation. This is a separate source delta audit on
top of the [0.9.15 record](gateway-0.9.15-delta.md), not a new comprehensive inventory. The
historical 0.9.5, 0.9.7, 0.9.8, 0.9.9, 0.9.10, 0.9.11, 0.9.14 and 0.9.15 catalogs and release locks
remain available and unchanged.

All `file:line` citations below are at v0.9.20 (`e4a606a`) unless a release is named. A change is
labelled with the first **published** release that contains it: a commit first tagged in v0.9.16 is
labelled v0.9.17, and one first tagged in v0.9.18 is labelled v0.9.19.

## Method and limits

Both source trees were read at the exact commits above with `git show`, `git diff` and `git log`,
without checkout, build, formatting, test, script, binary or container execution. The audit was split
into seven areas (gateway core and taxonomy; upstream and streaming; protocols and L4; authentication
plugins; policy and transform plugins; AI, MCP and A2A plugins; mesh and lab configuration). Every
`file:line` in the new catalog and in the sections below was read back at v0.9.20.

Every structured catalog citation and every unqualified prose citation (full path, or `:line` after
one) was remapped through the immutable unified diff, and the cited line text was required to be
identical at both ends: 1,377 structured and 410 prose citations remapped that way. 136 citations fell
inside changed hunks and were repointed by hand to the code that plays the same role at v0.9.20.
About 30 more were repointed because, although their text was identical, they no longer anchored the
emitter they name. A second pass compared the nine lines around every remapped citation at both
ends; the only generic-text citations it flagged were carried faithfully. Explicitly historical
`@sha` prose citations remain historical.

Citation text equality alone does not establish behavioral equality. Every carried outcome's
emitter was read at v0.9.20 for its status, body, `X-Gateway-Error`, headers, gRPC status and message,
WebSocket close code and transport shape, and for callers that now swallow or rewrite it, against the
[0.9.20 changelog][changelog] (sections 0.9.16 to 0.9.20) and the [upgrade guide][upgrade]. A global
comparison of every catalog public signal (status, token, body pattern, gRPC status) within the new
catalog checked `shared_signal_with`. The links are conservative candidate associations over the
fields `match_signal` compares (status, token, body, gRPC status): headers the matcher does not model
may differ between linked outcomes (for example `plugin.openapi_validator.response_decode_capacity`
sends `Content-Type: application/json`, `gateway.capacity.response_buffer` none on the H1/H2 path),
and the list is neither a full-wire equivalence nor a complete closure. Some pairs that agree on
those fields are not linked because a header separates them, for example `plugin.cors.actual_origin_not_allowed` and
`plugin.cors.preflight_origin_not_allowed` (`Vary`) or `plugin.rate_limiting.exceeded` and
`plugin.rate_limiting.local_state_capacity` (`Retry-After`). `match_signal` does not compare those
headers, so it still returns such a pair together and the diagnosis stays ambiguous (the safe
direction). Outcomes with no client-visible signal, such as `plugin.body_validator.log_only_no_signal`
and `plugin.openapi_validator.log_only_no_signal`, have nothing to share and list no sibling. The
byte-identical `gateway.capacity.request_decode` and `plugin.compression.decode_capacity` now list
each other (#483). A catalog-to-catalog comparison cannot detect an emitter that stopped firing; the
two removals below were found by reading the call sites.

Local validation is static inspection, `git diff --check`, `rustfmt --check` on the changed Rust
files, the lab profile lint and read-only consistency checks of the new JSON (the invariants of
`catalog_drift.rs`, and a port of `match_signal` over the signals the tests assert). No Rust test,
build or lab ran locally. Unit, parser and catalog checks cannot establish live gateway compatibility.

## Summary of public-signal changes

These change what Anvil matches, so they are the ones a diagnosis on 0.9.20 depends on:

- **Ninth `X-Gateway-Error` token, `loop_detected`** (v0.9.17, #6127): the proxy hop limit answers
  508 `{"error":"Proxy hop limit exceeded"}`; a malformed or repeated `X-Ferrum-Hops` is a 400.
  New outcomes `gateway.admission.proxy_hop_limit` and `frontend_parse.proxy_hops_invalid`; Anvil
  words `ferrum.token.loop_detected` as a gateway-admission refusal.
- **Backend connect timeout is 504** `{"error":"Backend timeout"}` with `connection_failure`, and a
  pooled `maxConnections` refusal is 503 `{"error":"Backend connection limit exceeded"}` with
  `connection_failure` (v0.9.19, #6777). `upstream.connect.timeout` and
  `upstream.connection_limit.pooled` leave the shared 502 setup-failure family and each match alone;
  the reqwest lane's 503 differs only by its `backend_error` token. WebSocket upgrades get the same
  504 (folded into `upstream.connect.timeout`).
- **Every gateway 401 carries a `WWW-Authenticate` challenge** (v0.9.19, #6779), joined into one
  field when several mechanisms apply; the bare `ferrum-edge` fallback is now rare.
- **`backend_timeout` no longer proves a backend held the request**: a route total that expires after
  dispatch began counts even during connection setup.
- **gRPC**: H1/H2 pre-routing refusals answer native gRPC Trailers-Only (v0.9.19 #6940, v0.9.20
  #6965); `GrpcProxyError::Internal` is INTERNAL (13); 499 maps to CANCELLED.
- **Plugins**: the `request_size_limiting` 413 body is now the core 413 body; `rate_limiting` and
  `ai_rate_limiter` quota 429s carry `Retry-After`; `mcp_gateway` denies `prompts/get` and
  `resources/read` by default; WAF, body and OpenAPI validation refuse more by default; 66 new
  outcomes in all (listed in the catalog with `New in v0.9.NN` notes).
- **Not matchable from the public signal alone**: four new outcomes have a concrete status but an
  empty body, so `match_signal` has no body pattern and never returns them (status alone would
  over-match): `protocol.grpc.dispatch_internal_error`, `plugin.load_testing.fanout_auth_refused`,
  `plugin.load_testing.fanout_resource_refused` and `plugin.response_mock.delay_client_gone`. They
  are catalogued for completeness, and each one's notes say so.
- **Removed**: `protocol.grpc.request_body_read_failed` (its INTERNAL emitter is gone since v0.9.17,
  #6150) and `plugin.response_mock.status_101_non_websocket` (a 101 mock is refused at load since
  v0.9.19, #6869). `plugin.oidc_relying_party.challenge_browser_state_cache_full`, removed in 0.9.15,
  returns (v0.9.19, #6833).

## Lab-scenario impacts fixed here

No lab profile key, value or `FERRUM_*` setting is refused, renamed or reinterpreted on v0.9.20
(76 settings re-read from source); the profiles stay valid on every supported release. Four scenario
expectations and one Anvil rule would have been wrong on v0.9.20:

1. **AUTH-001** expected the bare `ferrum-edge` challenge on the key_auth-only route; from v0.9.19 it
   is `ApiKey realm="ferrum-edge"` (`src/plugins/utils/auth_flow.rs:648`). Release-gated in
   `crates/anvil-lab/src/auth.rs`.
2. **UP-007**'s stalled backend TLS handshake runs under the connect budget, so it now answers the
   504; the scenario expects 504 from v0.9.19 and moves to `upstream.connect.timeout`'s fixtures in
   this catalog (`crates/anvil-lab/src/tls.rs`).
3. **UP-018**'s direct-H1 lane answers the 503 from v0.9.19 and diagnoses as the single outcome
   `upstream.connection_limit.pooled` (`crates/anvil-lab/src/admission.rs`; the public-signal
   contract tests in `crates/anvil-diagnostics/tests/upstream_setup_contract.rs` follow).
4. **MESH-008** sent a bare CONNECT to the sidecar's `http` port 17801, which v0.9.17 (#6125) refuses
   with 403 `HBONE relay destination not allowed` (`src/proxy/hbone_proxy.rs:139`). The workload now
   declares a `tcp` port 17808 (not a Service port) with its own echo fixture, which every supported
   release relays (`lab/gateway/mesh-sidecar.json`, `crates/anvil-lab/src/mesh.rs`).
5. Anvil's **`auth.browser_session_required`** rule read any OIDC-realm challenge on a 401 as a login
   step. On a route that chains OIDC with another mechanism, v0.9.19 lists both challenges on every
   401, including a rejected API key's. The rule now fires only when every challenge offered is the
   OIDC one (`crates/anvil-diagnostics/src/rules/auth_session.rs`).

The new defaults `FERRUM_HTTP_CLIENT_WRITE_TIMEOUT_SECONDS=60` and `FERRUM_MAX_PROXY_HOPS=10` reach no
lab scenario. v0.9.20 omits the empty DTLS 1.3 `certificate_authorities` extension (#7001), which
every earlier release sends. After this adoption Anvil retired v0.9.5 to v0.9.15 and its vendored
dimpl (`vendor/dimpl-0.8.0-empty-ca`), which accepted the empty list.

## Gateway core, frontend and taxonomy

The per-area sections from here on are the area auditors' notes, kept largely as written before the
adoption merged. The header, the [summary](#summary-of-public-signal-changes) and [Lab-scenario
impacts fixed here](#lab-scenario-impacts-fixed-here) record the outcome; where a note below
differs, they hold. In particular: a hand-off between areas ("open question", "should keep one id",
"may need to") was written before the catalog merged, and the catalog is what was decided; an Anvil
line cite next to a later "Fixed here" is the pre-fix line; a clause that keeps something "while
v0.9.5 to v0.9.15 are supported" or "run nightly" is moot, since v0.9.20 is the only supported
release and the only nightly pin; and the `lab/gateway/lint-profiles.rb` cite updates suggested
below were not all made.

All `file:line` citations are at v0.9.20 (`e4a606a`) unless a release is named. Changes tagged
in the unpublished v0.9.16 and v0.9.18 are attributed to v0.9.17 and v0.9.19, where the
changelog carries them. 60 outcomes in this slice: 33 carried unchanged, 27 modified, 0 removed,
6 new. 20 citations repointed (16 flagged, 4 stale ones the mechanical pass matched on a bare
comment line or one line late).

### Ninth `X-Gateway-Error` token: `loop_detected` (proxy hop limit)

v0.9.17 (#6127, issue #6109; plugin calls #6132). Each Ferrum hop stamps the gateway-owned
request header `X-Ferrum-Hops` with the received count plus one, on every HTTP-family transport and
on request-scoped plugin calls. A request that arrives at `FERRUM_MAX_PROXY_HOPS` (default 10,
maximum 255, `0` disables the feature) is refused before routing and before any plugin with `508`
`{"error":"Proxy hop limit exceeded"}` and `X-Gateway-Error: loop_detected`. Native gRPC gets
Trailers-Only `FAILED_PRECONDITION` (9) with no token. gRPC-Web gets the JSON 508. A malformed or
repeated field gets `400` `{"error":"Invalid X-Ferrum-Hops header"}` (gRPC `INVALID_ARGUMENT`)
with no token. A backend `508` is never retried, and an outer Ferrum hop that relays one labels
it `backend_error`.

Edge: `src/proxy/hop_limit.rs:211` (decision), `:113` and `:119` (bodies), `src/proxy/mod.rs:34851`
(H1/H2 refusal), `:35432` (frontend call), `src/http3/server.rs:20778` (H3), `src/retry.rs:229`
(`OBS_LOOP_DETECTED`), `:247-257` (closed list), `:346` (phase to token), `:2006` (no retry),
`src/config/env_config.rs:5327`.

Catalog impact: two new outcomes, `gateway.admission.proxy_hop_limit` and
`frontend_parse.proxy_hops_invalid`. `public_tokens` gains `loop_detected`. The `X-Gateway-Error`
header entry becomes a nine-token vocabulary. New `headers` entry `X-Ferrum-Hops` (request-side
only). `marker_semantics` gains `loop_detected`. `ErrorClass` is unchanged at 19 variants. The
hop fence emits no transaction summary, so `proxy_hop_limit` appears only as a diagnostic-reference
`rejection.phase`. A request already at `FERRUM_MAX_HEADER_COUNT` can draw the 431 at the next
Ferrum hop because the stamp adds a field (`size.request_header_count_exceeded` notes).

### A 504 can carry `connection_failure`; `backend_timeout` no longer implies a backend held the request

v0.9.19 (#6777; issues #6770, #6771, #6773, #6775). `http_backend_failure_status_and_body`
(`src/proxy/mod.rs:50117`) maps `ConnectionTimeout` to `504 {"error":"Backend timeout"}`; before,
it was `502 Backend unavailable`. The token stays `connection_failure`, because `connection_error`
wins over status in `src/retry.rs:301`. `BackendConnectionLimit` is `503 {"error":"Backend
connection limit exceeded"}` on every transport (`:50120`, `:50130`). Native gRPC internal gateway
errors are `INTERNAL`. The documentation now defines `backend_timeout` as a dispatch attempt that
did not answer in time. That includes a route total that expires while TCP/TLS setup is still in
progress (`docs/error_classification.md:507`, `:519`), so the 0.9.15 marker sentence "a backend
held the request" over-claims.

Catalog impact: `error_class_semantics` for `connection_timeout`, `backend_connection_limit` and
`client_disconnect`; `marker_semantics` rewritten for 0.9.20 (`backend_timeout`, `request_timeout`,
`backend_error`, new `loop_detected` and `connection_failure`). The `X-Gateway-Error` semantics drop
"status 504 -> backend_timeout" as a safe inference. The upstream outcomes belong to B1.

### H1/H2 pre-routing refusals are framed for gRPC and gRPC-Web

v0.9.19 (#6940): native gRPC protocol-header refusals are Trailers-Only `INVALID_ARGUMENT`.
v0.9.20 (#6965): every other HTTP/1.1 and HTTP/2 pre-routing refusal goes through
`pre_routing_refusal_response` (`src/proxy/mod.rs:34784`) and uses the HTTP/3 codes and messages.
That covers URL length (8), query count (3), Host/authority (3), per-IP 429 (8), 0-RTT 425 (14) and
retired listener 421 (14). Header limits are 8 for native gRPC only; gRPC-Web keeps the JSON 431.
TRACE is `UNIMPLEMENTED` with `Allow` kept (`:34807`). Plain HTTP and WebSocket keep JSON. HTTP/3
already did this at v0.9.15, so the old `grpc_status: null` on these outcomes was wrong for HTTP/3
too.

Catalog impact: `public_signal.grpc_status`, `transport` and `protocols` set on `size.request_header_*`
(3), `size.url_too_long`, `size.query_param_count_exceeded`, `frontend_parse.protocol_header_violation`,
`frontend_parse.host_authority_violation`, `gateway.admission.per_ip_concurrency` (http3 added),
`gateway.routing.trace_or_connect_blocked`. Notes are added to `gateway.admission.early_data_rejected`
and `gateway.routing.listener_retired`. The 421 now also closes HTTP/1.x for a gRPC answer
(#6969).

### CONNECT is never gRPC; HBONE CONNECT with a gRPC content type is refused

v0.9.20 (#6969). A CONNECT that is not a WebSocket Extended CONNECT is classified as plain HTTP on
every frontend. A refused CONNECT that carries a gRPC Content-Type therefore keeps its JSON status
instead of a `200` that reads as an established tunnel. A mesh HBONE CONNECT that declares a gRPC
or gRPC-Web Content-Type gets a plain `400 {"error":"gRPC requires POST method"}` before routing
(`src/proxy/mod.rs:35706`, `:35722`).

Catalog impact: new outcome `gateway.routing.hbone_connect_grpc_content_type` (mesh peers only;
the mesh slice may take ownership). A note on `gateway.routing.grpc_requires_post`, whose
Trailers-Only form (`:36748`) is unchanged.

### One `Authorization` credential per request

v0.9.19 (#6882). Check 6 of the protocol-header guard (`src/proxy/mod.rs:56175`) refuses two
`Authorization` field lines (`:56187`, "Request contains multiple Authorization headers"). It also
refuses one value carrying a second credential after a top-level comma (`:56190`, "Authorization
header contains more than one credential"). Both are refused before routing and authentication.

Catalog impact: two body variants and a condition sentence on
`frontend_parse.protocol_header_violation`.

### Unencoded `;` in the query on chains with a query-reading trigger

v0.9.19 (#6690, issue #6655). When any plugin instance on the request's view has an execution
trigger that reads `query`, the gateway refuses a raw query containing an unencoded `;` after
method admission and before any plugin phase. The answer is `400
{"error":"ambiguous query parameters","reason":"semicolon_separator"}` (gRPC `INVALID_ARGUMENT`).
It is logged `query_trigger_admission`. Edge: `src/proxy/mod.rs:298`, `:314`, `:36778`;
`src/http3/server.rs:4446`; `src/diagnostic_ref.rs:204`.

Catalog impact: new outcome `plugin.trigger.query_semicolon_refused`. The phase is added to
`rejection_phases_operator_only`.

### Route protocol admission now also refuses plain HTTP on gRPC-intended routes

v0.9.17 (#6125, issue #6110). `view_omits_route_admission_policy` (`src/plugin_cache.rs:6224`)
also marks the plain HTTP and WebSocket views of a route configured at proxy or proxy-group scope
with a gRPC-only admission plugin such as `grpc_method_router`. A global instance does not mark a
route. The composed gRPC-Web view is marked when it cannot run such a gate; only
`grpc_method_router` and `grpc_deadline` are carried. A bodiless CORS preflight is exempt
(`src/proxy/mod.rs:2800`). The 403 signal is unchanged (`:36652`).

Catalog impact: `gateway.routing.protocol_not_permitted` condition rewritten. The 0.9.15 sentence
"gRPC-Web keeps every HTTP plugin and is never refused this way" is withdrawn. Open question:
the framing of the gRPC-Web refusal.

### Every gateway-generated 401 carries a challenge

v0.9.19 (#6779, issue #6774). Every built-in mechanism now advertises a challenge
(`src/plugins/utils/auth_flow.rs:610-664`). The values are `ApiKey realm="ferrum-edge"`, `Bearer`
(with RFC 6750 error codes), `DPoP`, `hmac realm="ferrum-edge"`, `Basic …`,
`ClientCertificate realm="ferrum-edge"`, `WS-Security realm="ferrum-edge"` and
`Bearer realm="oidc"`. The missing-credential 401 joins every applicable challenge with `, `
(`src/proxy/mod.rs:33347`). `ensure_unauthorized_response_challenge` (`:33475`) repairs any other
gateway or plugin 401. The authorization-expiry 401 (`:59261`) and the client-trust-withdrawn 401
(`:56285`) carry one too. v0.9.19 (#6864): the H1/H2 expiry 401 also gets the route's static
`security_headers`. The bare `ferrum-edge` fallback now appears only when no applicable mechanism
advertises a challenge.

Catalog impact: `other_headers` on `proxy.auth_phase.missing_credential` (notes rewritten),
`proxy.auth_phase.openai_envelope_invalid`, `auth.authorization_lifetime_expired_before_commit` and
`gateway.admission.client_trust_withdrawn`. The `WWW-Authenticate` header entry is updated and its
writers repointed (`auth_flow.rs:681`, `basic_auth.rs:231`, `ldap_auth.rs:140`). Lab impact:
AUTH-001 expects `ferrum-edge` on the `key_auth` route and will see `ApiKey realm="ferrum-edge"`.

### Client-abort terminals and the malformed-upload 400

v0.9.17 (#6146, #6150) and v0.9.19 (#6778, #6780, #6781; #6769). A proven client abort logs
`499` (gRPC `CANCELLED`) on every HTTP/3 and gRPC path and for H1/H2 handlers that hyper drops
(`src/proxy/client_abort.rs:42`, `src/proxy/client_abort_scope.rs:81`). A gateway-closed request
logs `444` and a local HTTP/2 protocol reset logs `400`. All three are log vocabulary only.
`http_reject_status_to_grpc_status` maps `499` to `CANCELLED` (`src/proxy/grpc_proxy.rs:3150`).
This covers plugin-defined 499 rejects too. A malformed or early-ended upload on mesh-mTLS, HBONE
or Unix-socket dispatch is no longer a backend `502 protocol_error`. It is answered `400
{"error":"Malformed request body"}` (gRPC `INVALID_ARGUMENT`) and is health-neutral
(`src/proxy/mod.rs:56815`). On HTTP/3 the same outcome is log-only.

Catalog impact: `gateway.client_disconnect_during_buffering` gains http3/grpc, `grpc_status` 1 and a
new condition. The `generic.reject.grpc_normalization` map and `grpc_reject_status_mapping` gain
`499 -> 1`. New outcome `gateway.client_upload_malformed` (ownership to agree with the mesh slice).
`rejection_phases_operator_only` gains 18 phases.

### Client write-stall bound

v0.9.20 (#6998, #7005). `FERRUM_HTTP_CLIENT_WRITE_TIMEOUT_SECONDS` (default 60, `0` disables)
closes an HTTP/1.1, WebSocket or HTTP/2 client connection whose socket accepts no response bytes
for that long (`src/proxy/client_write_stall.rs:142`, `src/proxy/mod.rs:15622`). On HTTP/2 it
also resets with `RST_STREAM(CANCEL)` a stream whose ready chunk the client grants no window
(`:15665`, hyper patch 008). HTTP/3 and admin listeners are not covered.

Catalog impact: new client-local outcome `streaming.client_write_stall_cut`.

### Response-builder fallback answers 500, not 200

v0.9.19 (#6777, issue #6775). When `http::Response::builder` rejects a prepared response, the
gateway now answers through `internal_error_fallback_response` (`src/proxy/mod.rs:56296`). That is
`500` with a fixed body and Content-Type. Before, it went through `Response::new`, which meant a
`200` carrying the error body.

Catalog impact: `gateway.internal_error` body and headers; `Content-Type` header entry note.

### Smaller signal and condition changes

- v0.9.19 (#6709): gateway-authored HEAD responses carry no body bytes on HTTP/2 and HTTP/3
  (`src/proxy/headers.rs:1431`). This adds notes on `no_route`, `method_not_allowed`,
  `protocol_not_permitted` and `path_parameter_refused`.
- v0.9.19 (#6938, #6876): a global `correlation_id` decorates the route-miss 404
  (`src/proxy/mod.rs:36429`), so `x-request-id` on a 404 no longer proves a route matched. Adds
  `inbound_policy`. Updates `gateway.routing.no_route` and the `x-request-id` header entry.
- v0.9.17 (#6117): HTTP/2 WebSocket early data is gated on the wire `CONNECT`
  (`src/proxy/mod.rs:35749`). This changes the condition of `gateway.admission.early_data_rejected`.
- v0.9.17 (#6146): request-buffer exhaustion uses the trusted flavor (`src/proxy/mod.rs:56470`).
  Native gRPC on every dispatcher gets Trailers-Only 8, and pass-through gRPC-Web is framed. Adds
  notes to `gateway.capacity.request_buffer`.
- v0.9.19 (#6875): `request_size_limiting` returns the core 413 body, without the `limit` field.
  `size.request_body_too_large` can no longer be told apart from it by body; `shared_signal_with`
  is extended.
- v0.9.19 (#6853): the `hmac_auth` pre-authentication body ceiling is now `max_body_bytes`
  (`src/plugins/hmac_auth.rs:149`). Updates the condition of `proxy.request_body_prebuffer_too_large`.
- v0.9.20 (#7004): adaptive-concurrency route keys include streaming `ai_federation` destinations.
  The signal of `gateway.admission.adaptive_concurrency` is unchanged.
- v0.9.19 (#6550, #6316): frontend listeners that enforce CRLs no longer resume TLS sessions. This
  is not a failure outcome.
- v0.9.20 (#6981): plugin-free routes dispatch from wire headers (`src/proxy/request_headers.rs`).
  No client-visible effect was found.

### Unchanged taxonomy surfaces

The response-side gateway-owned list (`src/proxy/headers.rs:1200`, three names) and the backend
strip boundary (`:1157`) are unchanged. `x_gateway_error_for_response` (`src/proxy/mod.rs:28709`)
and `normalize_reject_response_with_provenance` (`:29222`) are unchanged. Plugin reject maps are
still not stripped of `X-Gateway-Error`, so lab GW-019 stays valid. `h1_framing_guard.rs` changed
only comments. The `ErrorClass` set is unchanged. `src/diagnostic_ref.rs` adds only the labels
listed above and the always-on unmatched-route counter (#6827).

### Removed-outcome reason no longer holds in full (OIDC pending-login cache)

v0.9.19 (#6833). `insert_pending_flow_or_use_sealed_cookie` (`src/plugins/oidc_relying_party.rs:3768-3785`)
no longer treats a full cache as success. It calls `admit_sealed_only` (`:3781`), which refuses at
the per-source cap (`:3544`, "Too many pending OIDC logins") or when the overflow set is also full
(`:3554`, `STATE_CACHE_FULL_ERROR`). The caller answers `503` (`:2513`). The removed outcome
`plugin.oidc_relying_party.challenge_browser_state_cache_full` is restored in the 0.9.20 catalog
(see the [summary](#summary-of-public-signal-changes)).

## Upstream and streaming

All `file:line` citations are at v0.9.20 (`e4a606a`). The slice covers 43 carried `upstream.*` and `streaming.*`
outcomes. Of these, 18 carry their signal and condition unchanged and 25 get notes or field changes. Two change
their public signal. One outcome is new and none is removed. `src/retry.rs` changes only the hop-limit additions
(the `loop_detected` token, the never-retry rule for 508) and one comment. `ErrorClass` and
`request_reached_wire` are unchanged. The buffered collector (`src/proxy/mod.rs:54623-54993`) is byte-identical to
v0.9.15. The DNS, egress and DNS-override builders (`:50369`, `:50387`, `:50420`) and the TLS-SNI refusal
(`:4021`) are also byte-identical.

### Backend connect timeouts answer 504 (#6777, issue #6770; v0.9.19)

`http_backend_failure_status_and_body` now maps `ConnectionTimeout` together with `ReadWriteTimeout` to
`504 {"error":"Backend timeout"}` (`src/proxy/mod.rs:50117`). Connect timeouts used to share the generic
`502 {"error":"Backend unavailable"}`. The class stays pre-wire, so `http_backend_dispatch_error_response` keeps
`connection_error=true` (`:50166`) and the token stays `connection_failure` (`src/retry.rs:302`). Retry, target
rotation and circuit-breaker meaning do not change, and a `504` listed in `retryable_status_codes` does not make
the timeout status-retryable. Every HTTP-family path uses the same mapper:

- reqwest and direct H1/H2
- the native-H3 frontend (`src/http3/server.rs:12737`)
- the HTTP/3 bridge (`src/http3/cross_protocol.rs:1758`)
- H1/H2 to native-H3 backends (`src/proxy/mod.rs:66902`)
- HBONE and sidecar-mTLS pools (`:56581`)

On H1/H2 to native H3, a post-wire QUIC connection timeout is now `504` with `backend_timeout`. It used to be
`502 {"error":"HTTP/3 backend request failed"}`.

**Catalog:** `upstream.connect.timeout` changes to 504 / `connection_failure` / `{"error":"Backend timeout"}`
with `public` visibility and an empty `shared_signal_with`. The token is now the only thing that separates it
from `upstream.timeout.response_header_wait` and `upstream.application_504`; the notes on all three say so. The
eight 502 setup-failure siblings drop it from `shared_signal_with`. **Lab:** UP-007 breaks: its operator class
is `connection_timeout`, and `upstream_setup_failure` asserts 502 (`crates/anvil-lab/src/tls.rs:966`). UP-003
still passes because it allows 502, 503 and 504.

### Pooled-lane maxConnections refusals answer 503 (#6777, issue #6771; v0.9.19)

`BackendConnectionLimit` now maps to `503 {"error":"Backend connection limit exceeded"}`
(`src/proxy/mod.rs:50120`; the shared constant is at `:50129`). The class is still pre-wire
(`src/retry.rs:480`), so the token stays `connection_failure`. The reqwest lane's refusal has the same status
and body but carries `backend_error` (`:53336`, `:48933`). The upgrade guide lists direct HTTP/2, native HTTP/3,
HBONE and sidecar mTLS. Eligible direct-H1 dispatch changes as well: `direct_h1_checkout_error_response`
(`:53554`) goes through the same mapper.

**Catalog:** `upstream.connection_limit.pooled` changes to 503 / `connection_failure` / limit body with
`public` visibility. Its diagnosis now names the connection ceiling. It no longer shares a signal with the
setup-failure family, and it differs from `upstream.connection_limit.reqwest` only by its token. **Lab:** the
UP-018 direct-H1 branch (`crates/anvil-lab/src/admission.rs:339-341`) expects 502 "Backend unavailable" and the
ambiguous pooled diagnosis, so it breaks on v0.9.20. The UP-018-H2 skip text and the anvil-diagnostics contract
test `up_018_pooled_lane_ceiling_stays_in_the_ambiguous_family`
(`crates/anvil-diagnostics/tests/upstream_setup_contract.rs:246`) also need a v0.9.19+ branch.

### Late backend failures settle as the earlier bound (#6973, #6979, issues #6022 / #6976; v0.9.20)

`settle_reqwest_header_wait` (`src/proxy/mod.rs:59012`; call sites `:52790` and `:48660`) attributes outcomes by
the captured instants. When a reset or close is observed at or after `backend_read_timeout_ms`, and that header
bound is earlier than any dispatch bound, the result is the `504 backend_timeout` answer, not a 502. The header
bound wins an exact tie. The direct H1 pool settles a late send failure at its handoff bound in the same way. In
the inline deadline adapter, a backend body error observed at or after the route deadline is the health-neutral
route cut (`src/proxy/body.rs:5956`).

**Catalog:** notes only, on `upstream.reset_before_headers`, `closed_before_headers`,
`protocol_error_before_headers`, `request_error_catchall`, `timeout.response_header_wait`,
`streaming.route_deadline_cut_after_headers` and `streaming.backend_body_failure_after_headers`. No signal
changes.

### Mesh upload aborts no longer read as backend resets (#6778, issue #6776; v0.9.19)

This applies to the sidecar mesh-mTLS, HBONE and Unix-socket dispatchers. Before, when a client abandoned its
upload, the gateway reset the backend exchange itself and answered 502 `protocol_error`. Now the dispatcher
checks for typed proof that the gateway's own request body ended the exchange
(`attribute_gateway_ended_upload`, `src/proxy/mod.rs:56691`). With that proof it answers 499
`client_disconnect`, or 400 for a malformed or incomplete upload. A reset, CANCEL or close sent by the backend
still gives the 502.

**Catalog:** condition notes on the before-headers 502 outcomes. The 499 and 400 terminals belong to the
client-abort outcomes in another slice.

### New: client write stall cuts the response (#6998, #7005; v0.9.20)

`FERRUM_HTTP_CLIENT_WRITE_TIMEOUT_SECONDS` defaults to 60 s; `0` disables it and the maximum is 86400
(`src/config/env_config.rs:5352`). When a client socket accepts no bytes for that long while the gateway has
bytes to write, the gateway closes the client connection. The socket wrapper is `ClientWriteStallIo`
(`src/proxy/client_write_stall.rs:142`), which sits below hyper on plaintext listeners and below rustls on TLS
listeners (`src/proxy/mod.rs:15622`, `:25190`). On h2c and ALPN `h2`, a stream that has a ready chunk but no
flow-control window for that long is reset with `RST_STREAM(CANCEL)` (hyper patch 008,
`vendor/hyper-1.10.0-ferrum-patched/src/proto/h2/mod.rs:464`). Time spent waiting on a slow backend never
counts. HTTP/3 and admin listeners are not covered. The operator sees `error_kind=client_write_stall`
(`src/proxy/mod.rs:15870`).

**Catalog:** new outcome `streaming.client_write_stall_cut` (`client_local_only`, owner `caller`). It is added
to the `shared_signal_with` lists of the five streaming cut outcomes. No lab scenario stalls a client this long.

### Rewritten streams obey the response-size ceiling (#6880; v0.9.19)

Inspector and normalizer output, gRPC-Web translation and the MCP SSE aggregate are now cut when they would
cross the effective response ceiling (`src/proxy/body.rs:6786`). They end with the same `ResponseBodyTooLarge`
body error (`:6891`).

**Catalog:** the condition of `streaming.response_size_exceeded_mid_stream` is widened. Its signal is unchanged.

### Smaller condition changes

- **Refused backend TLS** (#6119, v0.9.17): a refused tenant DestinationRule TLS file now fails at the pool
  entry:
  - reqwest: `src/connection_pool.rs:496`, which gives `upstream.pool.client_build_failed`
  - direct H1/H2: `src/proxy/http2_pool.rs:1047` and `:1858`, which give `connection_pool_error` and
    `upstream.pool.dispatch_canceled`

  It no longer falls back to a no-verify pool.
- **Backend 508** (#6127, v0.9.17): a backend 508 is never retried (`src/retry.rs:2006`). This is a note on
  `upstream.application_5xx`.
- **Sidecar mesh-mTLS uploads** (#6788, v0.9.19): unauthenticated uploads are bounded by hyper's HTTP/2 pipe
  (`src/proxy/mod.rs:63421`). The 504 is the same; this is a note on `upstream.timeout.upload_write_stall`.
- **Pool defaults** (#6797, #6806, v0.9.19): `FERRUM_POOL_MAX_IDLE_PER_HOST` defaults to 256 (was 64), and
  check-ins that race a drain are retired. No public signal changes.

### Citation repoints

| Outcome | Old | New (v0.9.20) | Note |
|---|---|---|---|
| `streaming.route_deadline_cut_after_headers` | `src/proxy/body.rs:2058` (v0.9.15) | `src/proxy/body.rs:2181` | `let health_neutral = disconnected \|\| route_policy_cut;` (flagged) |
| `upstream.dns.resolution_failed.reqwest_preflight` | `src/proxy/mod.rs:50905` | `src/proxy/mod.rs:50904` | The citation was one line low, on the closing brace (already wrong at v0.9.15) |
| `upstream.dns.resolution_failed.pooled` (prose) | `src/proxy/http2_pool.rs:1472` | `src/proxy/http2_pool.rs:1707` | Stale; `BackendUnavailableSource::Dns` |
| `upstream.pool.dispatch_canceled` (prose) | `src/proxy/mod.rs:57934` | `src/proxy/mod.rs:62042` | Bare `:57934` (Unix-socket replay) was never remapped |

## Protocols and L4

### gRPC: H1/H2 pre-routing refusals are trailers-only

On HTTP/1.1 and HTTP/2, a native gRPC request refused before routing now gets a trailers-only 200 response instead of the JSON 4xx. Header size and count limits, URL length and the per-IP concurrency limit answer 8 `RESOURCE_EXHAUSTED`. Query count, protocol headers, Host/`:authority` and the canonical path answer 3 `INVALID_ARGUMENT`. TRACE answers 12 `UNIMPLEMENTED` with `Allow`. This was #6965 (issue #6943) in v0.9.20. Protocol headers had already moved in v0.9.19 (#6940), and the canonical path was already framed on v0.9.15. gRPC-Web gets the same status in a framed trailer, except for the header size and count limits, which keep the JSON 431 as on HTTP/3. HTTP/3 already answered this way.

- Shared builder: `src/proxy/mod.rs:34784` (`pre_routing_refusal_response`).
- Messages: `:35391`, `:35405`, `:35421`, `:35544`, `:35564`, `:35594`, `:35610`, `:35861`, `:35897`.
- TRACE: `:35675`.
- HTTP/3 counterparts: `src/http3/server.rs:3261`, `:3652`, `:3968`.

**Catalog impact:**
- `protocol.grpc.header_limits_not_grpc_shaped` now covers only the gRPC-Web JSON 431. Its condition, signal and diagnosis are rewritten.
- `protocol.grpc_web.error_shape`: notes only.
- The native gRPC and gRPC-Web forms are recorded on the owning A_core outcomes (`size.*`, `frontend_parse.protocol_header_violation`, `.host_authority_violation`, `gateway.admission.per_ip_concurrency`, `gateway.routing.trace_or_connect_blocked`). No umbrella gRPC outcome is added, because it would match the same signal twice.

### gRPC: `GrpcProxyError::Internal` is INTERNAL (new outcome)

A native gRPC dispatch that fails inside the gateway now answers trailers-only 13 `Internal gateway error`. It used to answer 14 `Backend unavailable` on H1/H2 and 14 `Service unavailable` toward native HTTP/3 backends. The failure cases are a backend TLS config that cannot be built and an invalid backend URL or authority. This was #6777 (issues #6770–#6775) in v0.9.19. Accounting is health-neutral.

Edge source: `src/proxy/mod.rs:43444`, `:43454`, `src/proxy/grpc_proxy.rs:84`, `:1841`, `src/http3/server.rs:15123`.

**Catalog impact:**
- New outcome `protocol.grpc.dispatch_internal_error` (owner: gateway operator). It shares its signal with `gateway.internal_error`.
- `protocol.grpc.backend_unavailable`: Internal is dropped from its condition.
- `protocol.grpc.response_build_failed` keeps 14 with the same message; this is noted.

### gRPC: connect timeouts answer DEADLINE_EXCEEDED on native H3 and sidecar paths

Two connect timeouts now answer 4 `Backend deadline exceeded` (#6777, v0.9.19):
- A native HTTP/3 backend connect timeout. It used to answer 14 `Service unavailable`.
- A sidecar mesh-mTLS gRPC connect timeout. It used to answer 14 `sidecar mTLS backend unavailable`.

Edge source: `src/http3/server.rs:15130`, `:15161`, `src/proxy/mod.rs:57424`.

**Catalog impact:** notes and transport text on `protocol.grpc.backend_timeout` and `protocol.grpc.h3_backend_error_mapping`. The sidecar 14 message itself has never been catalogued (open question).

### gRPC: the client deadline owns late backend failures

A backend failure (reset, `CANCEL`, connect or read error) observed at or after the client RPC deadline is now answered 4 `Deadline exceeded at gateway` and is health-neutral. Before, it got the backend failure status. This was #6973 (issue #6022) and #6979 (issue #6976), both v0.9.20. The rule is a clock cutoff, not proof of cause. When two bounds race, the earlier one owns the outcome: a buffered native call that fails after an earlier operator read bound settles as that bound's `BackendTimeout`.

Edge source: `src/proxy/grpc_proxy.rs:7084` (`client_deadline_owns_failure`).

**Catalog impact:** condition and notes on `protocol.grpc.client_deadline_exceeded`, `.backend_unavailable` and `.backend_timeout`. Anvil must not read a 4 near the deadline as proof that the gateway timer fired first.

### gRPC: streaming deadlines enforced by a gateway timer; 2 s close grace

On HTTP/1.1 and HTTP/2, a gateway-owned response pump now enforces a streaming RPC deadline even when the client withholds flow-control credit (#6870, v0.9.19). If the client has not drained the `DEADLINE_EXCEEDED` terminal within 2 s, the gateway closes the client connection, which can end sibling HTTP/2 streams. An open upload is reset toward the backend with `RST_STREAM(CANCEL)`. A response that is already complete skips the pump but keeps the expiry and close grace (#6982, v0.9.20). The trailer shape is unchanged.

Edge source: `src/proxy/body.rs:1378`, `src/proxy/response_watchdog.rs:193`, `:440`, `:731`.

**Catalog impact:** transport notes on `protocol.grpc.deadline_streaming_before_data` and `.deadline_streaming_after_data`.

### gRPC: HTTP/3 upload terminals

HTTP/3 gRPC upload failures on the native H3 path and the H3-to-gRPC bridge now get their own statuses (#6780, issue #6772, v0.9.19):

| Upload failure | grpc-status | grpc-message |
|---|---|---|
| Client aborted the upload before headers | 1 `CANCELLED` | `Client disconnected` (normally unseen) |
| The gateway closed the upload | 14 | `Request stream closed by the gateway` |
| Malformed upload body | 3 | `Malformed request body` |

Edge source: `src/http3/server.rs:15148`, `:15150`, `src/http3/cross_protocol.rs:11199`, `:11203`, `src/proxy/client_abort.rs:107`.

**Catalog impact:** the `public_signal.transport` list of `protocol.grpc.h3_backend_error_mapping` is extended.

### Removed: `protocol.grpc.request_body_read_failed`

The INTERNAL `Failed to read gRPC request body: {Debug}` arm no longer exists (#6150, v0.9.17). `GrpcRequestBodyCollectError` lost its `Proxy` variant. A failed read of a buffered upload is now `ClientDisconnected`. It answers trailers-only 1 `Client disconnected` and is logged as `499 client_disconnect`. The client has normally already gone.

Edge source: `src/proxy/mod.rs:40113`, `src/proxy/client_abort.rs:49`.

**Catalog impact:** remove the outcome. This is the gRPC form of `gateway.client_disconnect_during_buffering` (A_core, open question).

### gRPC reject mapping: 499 → CANCELLED; CONNECT never gRPC

Two changes affect how gRPC rejects are shaped:
- An operator-defined 499 reject without an explicit grpc-status now maps to 1 `CANCELLED` with the default message `Cancelled`. It used to map to 13. This was #6146 and #6150 in v0.9.17. Edge source: `src/proxy/grpc_proxy.rs:3150`, `src/proxy/mod.rs:28886`.
- A CONNECT is never classified as gRPC (#6969, v0.9.20), so a refused CONNECT that carries a gRPC Content-Type keeps its HTTP answer. Edge source: `src/proxy/backend_dispatch.rs:66`.

**Catalog impact:** notes on `protocol.grpc.plugin_reject_mapping` and `.trailers_only_shape`.

### gRPC outcomes carried unchanged

The emitters and signals of these 16 outcomes are unchanged at v0.9.20:
- `protocol.grpc.config_stale_h3`, `.overload_h3`, `.route_method_not_allowed`, `.circuit_breaker_open`
- `.concurrency_limit` (adaptive_concurrency adds decision metrics only), `.destination_active_request_limit`
- `.response_too_large_buffered`, `.request_payload_too_large`
- `.auth_expired_precommit` (the WWW-Authenticate from #6779 applies only to the JSON 401 branch), `.auth_expired_streaming_before_data`
- `.backend_stream_error_after_headers`, `.backend_status_passthrough`
- `.mesh_dispatch_refused`, `.egress_policy_denied`, `.response_uninspectable`
- `protocol.http.retry_after_spec_expose`

Repoints:
- The flagged `charge_generic_grpc_route_attempt_budget_expiry` citation moves to `src/proxy/mod.rs:58026`. Its signature is now generic over `RequestHeaderLookup`.
- Three mechanically remapped lines moved onto the emitter line: `src/proxy/mod.rs:40146` and `:40447`, and `src/plugins/grpc_web.rs:2603`.

No gRPC lab assertion changes: PROTO-014-down and GRPCWEB-down use an unbound port, so they get a connection refusal and still answer 14.

### WebSocket backend failures follow the shared status mapper (#6777)

v0.9.19 (issues #6770 / #6773; first tagged in the unpublished v0.9.18). Both WebSocket frontends now get the status and body for a failed backend dial or upgrade handshake from `websocket_backend_failure_status_and_body` (`src/proxy/mod.rs:16241`), which delegates to the shared HTTP mapper (`src/proxy/mod.rs:50113`):

- A connect or handshake timeout (`ConnectionTimeout`, or `ReadWriteTimeout` when tungstenite reports a timed-out read after the upgrade request was written, `src/retry.rs:874`) is answered with **504** `{"error":"Backend timeout"}` instead of 502.
- Every other class keeps 502 `{"error":"Backend WebSocket connection failed"}`.
- On HTTP/3, a DNS failure still answers `{"error":"DNS resolution for backend failed"}` (`src/http3/websocket.rs:1528`).

Every one of these answers now carries `X-Gateway-Error`: H1/H2 in the WebSocket builder (`src/proxy/mod.rs:16214`) and H3 in `send_h3_backend_failure_body` (`src/http3/websocket.rs:433`, call at `:1532`). The token is `connection_failure` for a pre-wire failure. It is `backend_error` for a backend that received the upgrade and refused it (`WsError::Http`, which maps to `RequestError`, `src/retry.rs:844`) and for a denied literal-IP backend. It is `backend_timeout` for a post-wire 504.

Through v0.9.15 every case was a bare 502 with no token, from the call sites now at `src/proxy/mod.rs:17362` and `:17056`.

**Catalog impact:**
- `protocol.ws.backend_connect_failed` is modified: the public signal gains `X-Gateway-Error`, the condition excludes timeouts, and the two flagged citations move to `:17362` and `:17056`. The old note "no 504 variant; no X-Gateway-Error" no longer holds.
- **Folded into `upstream.connect.timeout`** (not a separate outcome, since the signal is identical): 504 with `{"error":"Backend timeout"}`, `X-Gateway-Error: connection_failure` (or `backend_timeout`) and `Content-Type: application/json` (`src/proxy/mod.rs:16200`). It shares status, body and token with `upstream.connect.timeout`.
- The mapper's `BackendConnectionLimit` arm returns 503 `Backend connection limit exceeded` with `connection_failure`. It is not shown to be reachable from a WebSocket dial: the direct path refuses at its pre-dial `maxConnections` check (`src/proxy/mod.rs:16653`, no token). So `protocol.ws.backend_connection_limit` is unchanged.

### Credential-expired WebSocket 401 carries `WWW-Authenticate` (#6779)

v0.9.19 (issue #6774). The pre-upgrade 401 `{"error":"Credential expired before WebSocket upgrade"}` now names the committing mechanism's challenge from `reauthentication_challenge` (`src/plugins/utils/auth_flow.rs:969`), for example `Bearer error="invalid_token"`, or `ferrum-edge` when no mechanism applies. It does this on H1/H2 (`src/proxy/mod.rs:16361`, and after the backend handshake at `:17461`) and on H3 (`src/http3/websocket.rs:628`). Status and body are unchanged.

**Catalog impact:** `protocol.ws.credential_expired_before_upgrade`: `other_headers` gains `www-authenticate`, and the notes are updated.

### Directional `ws_message_size_limiting` and the deflate close reason (#6881, #6940)

v0.9.19. The plugin accepts `client_to_backend` and `backend_to_client` override objects, each with its own `max_frame_bytes`, `max_message_bytes` and `close_reason` (`src/plugins/ws_message_size_limiting.rs:39`). The relay builds each framer's limits for its direction (`src/proxy/mod.rs:20724`).

Under `websocket_permessage_deflate: terminate`, a deflate size fault exactly at the binding plugin ceiling now closes with the plugin's `close_reason` (`src/proxy/mod.rs:20829`). Before, it used the adapter's fixed reason. Global and `FERRUM_WEBSOCKET_PERMESSAGE_DEFLATE_MAX_MESSAGE_BYTES` ceilings keep the fixed reasons. The default reason is unchanged, now held in a constant (`src/plugins/ws_message_size_limiting.rs:51`). The flagged `plugin_close_for_error` citation moves to `src/proxy/mod.rs:20785`.

Separately, #6940 (issue #6912) keeps a queued 1009 Close from being dropped when a Sidecar mesh H2 backend is torn down; this adds a drain of at most 100 ms.

**Catalog impact:** `protocol.ws.close_too_big_1009`: code 1009 is unchanged, and the condition, sources and notes are updated. The custom-plugin `websocket_size_limits()` API change is not client-visible.

### `api_chargeback` bandwidth pricing disables WebSocket tunnel mode (#6842)

v0.9.19. A bandwidth-priced `api_chargeback` instance requires WebSocket framing (`src/plugins/api_chargeback.rs:3995`). Its proxy's sessions therefore stay on the parsed relay even with `FERRUM_WEBSOCKET_TUNNEL_MODE=true`, and they stop with Close frames rather than a dropped transport.

**Catalog impact:** `protocol.ws.tunnel_mode_stop`: condition and notes updated.

### Client-write stall bound covers upgraded WebSockets (#6998)

v0.9.20. `FERRUM_HTTP_CLIENT_WRITE_TIMEOUT_SECONDS` (default 60, `0` disables; `src/config/env_config.rs:5352`) wraps H1/H2 client sockets (`src/proxy/mod.rs:15622`, `:25190`). An upgraded WebSocket whose client socket accepts no bytes for that long is ended through the relay's own close path (`src/proxy/client_write_stall.rs:1`, module doc).

The stalled client gets no Close frame it can read. The backend leg is expected to get 1011 `relay error` (`src/proxy/mod.rs:20938`), but this was not traced end to end. HTTP/3 WebSockets are not affected.

**Catalog impact:** `protocol.ws.close_relay_error_1011`: condition and notes extended; no new outcome.

### WebSocket outcomes verified unchanged

The following 13 outcomes were re-read at v0.9.20; the emitter text, status, body, close code and builder (no token) are identical to v0.9.15:

- `connection_limit` (`src/proxy/mod.rs:16454`, `:16493`; H3 `src/http3/websocket.rs:791`)
- `origin_not_allowed`
- `max_lifetime_before_upgrade` (`src/proxy/mod.rs:16344`)
- `backend_connection_limit` (`src/proxy/mod.rs:16653`; H3 `src/http3/websocket.rs:1073`)
- `upgrade_internal_error`
- `circuit_breaker_or_concurrency`
- `close_policy_1008` (`src/proxy/mod.rs:20252`, `:20560`)
- `close_going_away_1001`
- `close_protocol_error_1002` (`src/proxy/mod.rs:20945`)
- `close_peer_relayed`
- `h3_disabled`
- `backend_extension_negotiation_failed` (`src/proxy/mod.rs:17512`)
- `close_invalid_payload_1007` (`src/proxy/ws_permessage_deflate.rs`, unchanged file)

The extension-negotiation 502 is now also charged to adaptive concurrency (#6879) without changing its signal. Seven mechanically remapped citations that had landed on comments or argument lines are repointed to the emitting line.

The WebSocket lab scenarios (PROTO-009/010/012/013) assert close codes and handshake success only, so they see no change.

### DTLS 1.3 CertificateRequest omits the empty `certificate_authorities` list (#7001)

New in v0.9.20 (issue #7000, merge `bcb3c56e`). The vendored dimpl 0.6.1 server used to append a `certificate_authorities` extension with zero names to every DTLS 1.3 `CertificateRequest`. RFC 8446 §4.2.4 forbids an empty list. Strict clients (dimpl 0.8+, Chrome/BoringSSL) dropped that flight without an alert and timed out, even with a valid certificate. The backport of upstream algesten/dimpl#153 omits the extension and keeps `signature_algorithms`. Client certificates are still required and verified exactly as before.

Edge source:
- `vendor/dimpl-0.6.1-ferrum-patched/src/dtls13/server.rs:1405` (`handshake_create_certificate_request`; only `signature_algorithms` at `:1414`)
- `docs/frontend_tls.md:223-227`

The refusal path in `src/dtls/mod.rs` is unchanged. The release adds only the #6119 `tls_refused` check at `:1139`, which shifts every later line by +9. The queued final flight is still discarded (`src/dtls/mod.rs:4250-4261`). The code comment still says `close()` during an in-progress handshake queues no alert (`:4269-4270`). `docs/frontend_tls.md:231` still says the refusal alert is emitted, so the code/doc disagreement recorded in the notes stands.

**Catalog impact:** `l4.dtls.handshake_refused` is modified:
- The transport text cites `src/dtls/mod.rs:4250-4261` / `:4269-4270`.
- The notes doc reference moves to `docs/frontend_tls.md:217-239`.
- The condition names refused backend TLS material (#6119, v0.9.17).
- A note records the change. On v0.9.15–v0.9.19, a strict client's DTLS 1.3 handshake timeout against a client-certificate listener is not evidence of a certificate refusal. On v0.9.20 that stall is gone.

**Lab:** PROTO-022 and its `.nocert`, `.rogue` and `.root` variants, and PROTO-022-wrong-root, are unaffected. dimpl 0.8.0 parses a request without the extension normally, and the refusals behave as before. Unpatched, it drops the empty list every earlier release sends, so the vendored patch was retired together with v0.9.5 to v0.9.15. `crates/anvil-transport/tests/dtls_edge_interop.rs` now runs the handshake against a listener that omits the extension, as v0.9.20 does.

### UDP/DTLS sessions end when the datagram-hook policy changes (#6868)

v0.9.19. Each UDP and DTLS session now carries a policy fence (`src/proxy/udp_proxy.rs:675`, checked at `:691`). The fence ends the session after a reload that changes the proxy's datagram-hook configuration:
- On plain UDP, the worker drops the datagram that observes the change and retires the session (`src/proxy/udp_proxy.rs:1303`). The client's next datagram opens a new session with a new backend source port.
- On DTLS, the relay ends (`:8119`) and the client must handshake again.

Reloads that leave those plugin configs unchanged do not end sessions.

**Catalog impact:** the condition and notes of `l4.udp.datagram_dropped` change; the signal is still silence. The lab streams profile does not reload.

### NodeWaypoint TCP drops unvouched captured streams (#6964)

v0.9.20. A NodeWaypoint-captured TCP stream whose capture source is no longer vouched for is dropped at accept, before any setup (`src/proxy/tcp_proxy.rs:2838`). It used to fall back to mesh-wide policy. Separately, since v0.9.19 (#6877) the `RejectedByPlugin` detail names the plugin (`:3516`); this is log only.

**Catalog impact:** F_mesh_lab catalogues the drop as the new outcome `l4.tcp.node_waypoint_capture_source_refused`. `l4.tcp.setup_failed` lists it in `shared_signal_with` and gains notes; the client still sees a close without data. `l4.tcp.sni_admission_refused` and `l4.tcp.mid_stream_disconnect` are unchanged: the `tcp_proxy.rs` relay changes are circuit-breaker generation bookkeeping only.

### HTTP/2 streams with no client window are reset (#7005)

New in v0.9.20. A response stream that has a chunk ready but no client flow-control window for `FERRUM_HTTP_CLIENT_WRITE_TIMEOUT_SECONDS` (default 60, `0` disables) is reset with `RST_STREAM(CANCEL)`. The connection and its other streams continue. A full send buffer that still has window does not count.

Edge source:
- Hyper patch 008: `vendor/hyper-1.10.0-ferrum-patched/src/proto/h2/mod.rs:464`
- Wiring: `src/proxy/mod.rs:15665` (h2c) and `:25315` (TLS)
- Setting: `src/config/env_config.rs:5352`

Before this release such a stream held its backend connection indefinitely.

**Catalog impact:** A_core (`streaming.client_write_stall_cut`) and B1 (`streaming.client_write_stall_cut`) have each drafted this stream reset together with the connection close below. B2 does not draft a third; the merge should keep one id. Anvil's lab clients always grant window.

### Slow-read bound closes H1/H2 client connections (#6998)

New in v0.9.20. `ClientWriteStallIo` wraps every proxy client socket below hyper, or below rustls on TLS listeners (`src/proxy/mod.rs:15622`, `:25190`). When the gateway has bytes to write and the socket accepts none for `FERRUM_HTTP_CLIENT_WRITE_TIMEOUT_SECONDS` (default 60, at most 86400), the connection closes with a `TimedOut` write error (`src/proxy/client_write_stall.rs:99`). The bound also covers upgraded WebSockets. HTTP/3 and admin listeners are not wrapped.

**Catalog impact:** the outcome is drafted by A_core and B1 (see above). The WebSocket side is recorded on `protocol.ws.close_relay_error_1011` (see the WebSocket section). The lab's slow scenarios (PROTO-018-idle) idle the backend, not the client socket, so they never arm the bound.

### Proxy hop limit: 508 Loop Detected and a ninth `X-Gateway-Error` token (#6127)

New in v0.9.17 (issue #6109; first tagged in the unpublished v0.9.16). Every forwarded HTTP-family request carries `X-Ferrum-Hops`. Before routing and plugins, H1/H2 (`src/proxy/mod.rs:35432`) and H3 (`src/http3/server.rs:3474`) refuse in two cases:
- **Hop limit reached** (`FERRUM_MAX_PROXY_HOPS`, default 10, `src/config/env_config.rs:5327`): 508 `{"error":"Proxy hop limit exceeded"}` with `X-Gateway-Error: loop_detected`. Native gRPC gets trailers-only 9.
- **Malformed field:** 400 `{"error":"Invalid X-Ferrum-Hops header"}` with no token. Native gRPC gets 3.

gRPC-Web and WebSocket upgrades get the JSON answers. A 508 from a backend is never retried (`src/retry.rs:235`). Stream proxies are exempt.

Edge source: builder at `src/proxy/mod.rs:34851`; H3 at `src/http3/server.rs:20778`; bodies at `src/proxy/hop_limit.rs:113` and `:119`; token at `src/retry.rs:229`.

**Catalog impact:** A_core drafts `gateway.admission.proxy_hop_limit` and `frontend_parse.proxy_hops_invalid` and records the ninth token, `loop_detected`; the `ErrorClass` set stays at 19. B2 confirms the gRPC and WebSocket forms above and adds no outcome.

**Lab:** no lab route loops back to a gateway port in the streams, tls, early or h3x profiles. No lab check asserts the exact header set a backend receives, so the forwarded `X-Ferrum-Hops` is harmless.

### HTTP/2 connection closes: gRPC deadline grace and shutdown drain (#6870, #6781)

v0.9.19. The connection-close path that authorization expiry uses (GOAWAY, then a hard close after 2 s; `src/proxy/mod.rs:15912`) gains a trigger: a gRPC RPC deadline whose `DEADLINE_EXCEEDED` terminal the client has not drained within `TRANSPORT_CLOSE_GRACE` (2 s, `src/proxy/response_watchdog.rs:193`, request at `:458`).

On shutdown, after GOAWAY, an H1/H2 connection now also closes when the drain wait ends (`src/proxy/mod.rs:15811`, issue #6768). Streams still in flight are cut; before, the connection was polled to completion.

**Catalog impact:** condition and notes for `protocol.http2.forced_connection_close` and `protocol.http2.graceful_shutdown_goaway`. The `mod.rs:14704` short-path prose, already stale at v0.9.15, is repointed to `src/proxy/mod.rs:15912`. `protocol.http2.max_concurrent_streams` and `.reset_flood_protection` are unchanged; h2 moves to 0.4.20 (#6062) with the same builder settings.

### HTTP/3: one shutdown budget; CONNECT is never gRPC (#6730, #6969)

**Shutdown budget** (v0.9.19, issue #6714). The H3 drain, the H3 endpoint-close wait and the global drain share one `FERRUM_SHUTDOWN_DRAIN_SECONDS` deadline. The close code is unchanged: `0x0100` with reason `shutdown` (`src/http3/server.rs:2072`, `:2243`).

**CONNECT classification** (v0.9.20). Every CONNECT that is not a WebSocket Extended CONNECT is now classified as plain HTTP (`src/http3/server.rs:3313`). A refused CONNECT or CONNECT-UDP carrying a gRPC Content-Type therefore gets its JSON status instead of a trailers-only 200.

Unchanged files and dependencies:
- `src/http3/connect_udp.rs`, `address_validation.rs` and `config.rs` are byte-identical, so CONNECT-UDP refusals, Retry/address validation, the DATAGRAM refusal and field-section limits are unchanged.
- Quinn moves to 0.11.12 and quinn-proto to 0.11.19 (#6115, upstream security fixes) without a code change.

**Catalog impact:**
- Notes for `protocol.http3.graceful_shutdown_goaway` and `.unsupported_extended_connect`.
- Repoints for `.header_wait_timeout` (`src/http3/server.rs:2998`; prose `docs/http3.md:1672-1679`, where the baseline doc reference was already stale), `.field_section_limits` (`:3062`) and `.unsupported_extended_connect` (`:3748`).
- The other `protocol.http3.*` outcomes are unchanged.

### HBONE: Sidecar HTTP-route CONNECT refused, live tunnels re-judged (#6125, #6873)

**Sidecar HTTP-route CONNECT** (v0.9.17, issue #6110). A bare byte-stream CONNECT on the Sidecar inbound listener that matches an HTTP-family route is refused before the route's plugins. It gets the 403 relay-denied answer (reason `http_application_port`). Source: `src/proxy/mod.rs:36216`, predicate `:2734`.

**Live-tunnel re-judging.** The admission fence now revokes a live tunnel in two more cases:
- A reload turns its route into such an HTTP route (`relay_destination`, `src/proxy/hbone_admission_fence.rs:2218`).
- Since v0.9.19 (#6873), its mapped Consumer is deleted or loses ACL access (`authorization_denied`, `:2157`).

**gRPC Content-Type on CONNECT** (v0.9.20, #6969). An HBONE CONNECT that declares a gRPC Content-Type is refused with plain 400 `{"error":"gRPC requires POST method"}` (`src/proxy/mod.rs:35722`). That is A_core's `gateway.routing.grpc_requires_post`.

**Catalog impact:**
- Condition and notes for `protocol.hbone.relay_destination_denied` and notes for `.tunnel_admission_revoked`; the signals are unchanged.
- Prose repoints `hbone_proxy.rs:1668` → `src/proxy/hbone_proxy.rs:1743` and `retry.rs:946` → `src/retry.rs:967`.

### HBONE relay dial failures: kernel ETIMEDOUT is now 504 (#6777)

v0.9.19 (issue #6770). When the inbound HBONE terminator's own dial to the destination workload fails with a kernel `ETIMEDOUT`, it now answers 504 `{"error":"Backend HBONE connection timed out"}`, the same answer as its own connect timer (`src/proxy/hbone_proxy.rs:748`, timer at `:769`). This happens when the connect budget is longer than the OS TCP timeout. Before, the answer was 502 `{"error":"Backend HBONE connection failed"}` (`:753`). A DNS failure answers 502 `{"error":"DNS resolution for backend failed"}`.

These three bodies predate v0.9.15 but were never catalogued. They go through the reject finalizer (`src/proxy/mod.rs:32421`, reached from `src/proxy/hbone_proxy.rs:1399`), which stamps no `X-Gateway-Error`.

**Catalog impact:** new outcome `protocol.hbone.relay_backend_connect_failed` (502 | 504, no token, owner unknown). F_mesh_lab flagged it for this slice.

## Authentication plugins

### Every gateway 401 carries a `WWW-Authenticate` challenge (#6779, v0.9.19)

`AuthMechanism::authentication_challenge` is now required, and the shared runner attaches a challenge to every 401 through `auth_rejection` (`src/plugins/utils/auth_flow.rs:681`). Extraction failures use the mechanism's `InvalidFormat` challenge (`:1103`). Rejected credentials use its `InvalidCredential` challenge (`:1150`). Auth 403 and 500 responses carry none.
- `key_auth` answers `ApiKey realm="ferrum-edge"` (`src/plugins/key_auth.rs:344`, `auth_flow.rs:648`).
- `jwt_auth` answers `Bearer error="invalid_request"` for a malformed credential and `Bearer error="invalid_token"` for a rejected token (`src/plugins/jwt_auth.rs:287`).
- `mtls_auth` answers `ClientCertificate realm="ferrum-edge"` (`src/plugins/mtls_auth.rs:1102`).
- `basic_auth` keeps its value, now the shared constant (`auth_flow.rs:613`).

An authentication-phase 401 lists the rejecting mechanisms' challenges first, then every other applicable mechanism's advertised challenge, de-duplicated and comma-joined (`src/proxy/mod.rs:33448`). The missing-credential 401 lists every applicable advertised challenge (`src/proxy/mod.rs:33347`). `ferrum-edge` is used only when no mechanism advertises one. Before this change, a key_auth-only route answered a missing credential with `ferrum-edge` and a multi-auth rejection kept only the last mechanism's headers. The CHANGELOG lists this under 0.9.19, because v0.9.18 was tagged but not published. Status codes and bodies are unchanged.

**Catalog impact:** `public_signal.other_headers` gains the challenge on 10 outcomes:
- `plugin.key_auth.invalid_key_format`, `.blank_key`, `.invalid_key`
- `plugin.jwt_auth.invalid_jwt_token`, `.missing_identity_claim`, `.missing_nbf_claim`, `.empty_bearer_token`
- `plugin.mtls_auth.invalid_certificate`, `.certificate_not_currently_valid`, `.no_consumer_for_certificate`

`plugin.jwt_auth.invalid_jwt_token` has two values: `invalid_token`, or `invalid_request` when the configured header is present but not visible ASCII (`jwt_auth.rs:227`).

`plugin.jwt_auth.empty_bearer_token` now sends the same signal as `plugin.oauth2_introspection.empty_bearer_token`, so `shared_signal_with` is set on both.

The old notes "key_auth defines no challenge", "mtls: No WWW-Authenticate" and "hmac has NO WWW-Authenticate" (on `basic_auth.invalid_credentials`) are superseded.

`proxy.auth_phase.missing_credential` belongs to A_core. Its challenge template must change: a key_auth-only route now answers `ApiKey realm="ferrum-edge"`.

### An OIDC realm appears on other mechanisms' 401s (#6779, v0.9.19)

`oidc_relying_party` applies to every request (`src/plugins/mod.rs:13511`) and advertises `Bearer realm="oidc"` (`src/plugins/oidc_relying_party.rs:3216`). On a route that chains it with another mechanism, that mechanism's rejection now lists the OIDC challenge after its own. For example, `Invalid API key` answers `ApiKey realm="ferrum-edge", Bearer realm="oidc"`.

**Anvil impact:** before this adoption the `auth_session` rule treated any 401 whose `WWW-Authenticate` contained `realm="oidc"` as a login step, so on v0.9.20 it would also have fired on a rejected API key or JWT on such a route. It now fires only when every challenge offered is the OIDC one (`crates/anvil-diagnostics/src/rules/auth_session.rs`, `oidc_realm`; see [Lab-scenario impacts fixed here](#lab-scenario-impacts-fixed-here), item 5). No lab route combines OIDC with another mechanism.

### `key_auth`: two new 401 refusals and multiple key locations (#6882, #6937, v0.9.19)

- **`;` query aliases (#6882, BREAKING):** with a `query:<name>` location, a raw query that also carries `<name>` as a `;`-separated sub-parameter (`?carrier=;api_key=k`, or `api_key;x=1`) is refused before lookup with 401 `{"error":"Ambiguous API key query parameter"}` (`src/plugins/key_auth.rs:131`, body `:45`). When another mechanism authenticates the request, the alias is redacted and stripped instead (`:379`).
- **Several locations (#6937):** `key_location` also accepts an ordered array of 1 to 8 `header:`/`query:` locations (`:178`). A credential in more than one of them, even with equal values, gets 401 `{"error":"Ambiguous API key locations"}` (`:239`, body `:46`).
- **Shared emitter:** both rejections leave through `run_key_auth` (`:325`) with the `ApiKey` challenge.

The authenticate hook now borrows the key. Blank-key and unknown-key verification moved into `verify_api_key` (`:301`, `:306`).

**Catalog impact:**
- Two new outcomes, `plugin.key_auth.ambiguous_query_key` and `plugin.key_auth.ambiguous_key_locations` (owner caller, gRPC 16).
- Repoints for `invalid_key_format` (`:252`), `blank_key` (`:301`) and `invalid_key` (`:306`).
- The lab sends neither shape. The array form is a new config shape that older releases refuse.

### Requests with more than one `Authorization` credential get 400 (#6882, v0.9.19)

The ingress protocol guard refuses these before routing and authentication, on H1, H2, H3 and WebSocket:
- Two `Authorization` field lines get 400 `{"error":"Request contains multiple Authorization headers"}` (`src/proxy/mod.rs:56187`).
- One value with a second credential after a top-level comma gets 400 `{"error":"Authorization header contains more than one credential"}` (`:56190`, `check_single_authorization_credential` `:56183`).

gRPC keeps the flavor-aware `INVALID_ARGUMENT` framing. A second `Basic` line can no longer slip past `basic_auth`'s `hide_credentials`.

**Catalog impact:** this extends the body set of `frontend_parse.protocol_header_violation`, which belongs to A_core and is not drafted here. The `basic_auth.invalid_credentials` notes now say that a multi-credential request never reaches `basic_auth`.

### `jwt_auth` verification policy (#6597, #6865, #6930, v0.9.19)

The body is the same, `Invalid JWT token`, but it has new triggers:
- **`aud` without configured audiences (#6597, BREAKING):** with no `audiences` configured, a token carrying `aud` is now rejected (`src/plugins/jwt_auth.rs:372`). It used to pass.
- **Pinned algorithm (#6865):** the HMAC algorithm comes from the new `algorithm` key (`HS256` default, `HS384`, `HS512`), never from the token header.
- **Weak secrets (#6865):** a stored Consumer secret below 32 non-whitespace characters is never used to verify (`src/config/types.rs:326`). When no Consumer secret is eligible, the plugin runs one equalizing verification and returns the `VerificationFailed` body (`jwt_auth.rs:389`, `:398`). This replaces the old early return that the flagged citation pointed at.
- **Shared secrets (#6865, #6930):** a secret held by two Consumers is refused at admission and quarantined on every holder at load (`src/config/types.rs:5471`).
- **`hide_credentials` (#6865):** a new key, default false.

**Catalog impact:** `plugin.jwt_auth.invalid_jwt_token` condition and notes extended. Its `:250` citation is repointed to `:389`. The lab's jwt_auth tokens carry no `aud`, and its secret is 48 hex characters and unshared.

### `auth_flow` and `scope_role_check`

`run_auth_impl`'s commit-and-reject step moved into `finish_verified_auth_attempt` (`src/plugins/utils/auth_flow.rs:1122`), which `key_auth` reuses. The oversized-identity refusal is unchanged: still 403, no challenge (`:1154`, check `:191`). `src/plugins/utils/scope_role_check.rs` is byte-identical, and its three callers are unchanged in role.

The new `src/plugins/config_contract.rs` (#6967) is the custom-plugin config-closure test contract. The #6967 nested-object closure touches no authentication plugin, so it changes no refusal in this area.

#6975 (`lifecycle_hooks`) only skips undeclared no-op hooks. `authenticate` is not gated by it.

**Catalog impact:**
- `plugin.auth_flow.identity_oversized` is repointed (`:666` → `:1154`).
- `plugin.scope_role_check.*` carry over unchanged.

### `key_auth` key length floor (#6602, v0.9.19)

Consumer keyauth keys now need 16 non-whitespace characters (`src/config/types.rs:133`):
- Admin writes answer 400.
- File mode fails to load.
- A data plane refuses a CP snapshot that holds one.

Nothing changes at request time. A client still presenting a dropped short key gets the existing 401 `Invalid API key`. The lab's keys are 30 characters.

### Lab: key, basic, jwt and mtls profiles; AUTH-001

- **AUTH-001 breaks on v0.9.20.** `crates/anvil-lab/src/auth.rs:332-337` expects the missing-credential challenge on `/auth/key`, a key_auth-only route, to be exactly `ferrum-edge`. From v0.9.19 the gateway sends `ApiKey realm="ferrum-edge"`. **Fix:** gate the expected value: `ApiKey realm="ferrum-edge"` on v0.9.19 and later, `ferrum-edge` on v0.9.15 and earlier.
- **AUTH-003 and AUTH-032 still pass.** AUTH-003 checks that the value *contains* `Basic realm="ferrum-edge"`, which still holds. AUTH-032's bad-key case now gets `ApiKey realm="ferrum-edge", Bearer`, but its check reads only status and body.
- **No config key the lab uses is refused or renamed:**
  - `key_auth` `key_location` (string) and `hide_credentials` (`src/plugins/key_auth.rs:162`).
  - `basic_auth` `hide_credentials` (`src/plugins/basic_auth.rs:51`).
  - The eight `jwt_auth` allowlisted keys (`src/plugins/jwt_auth.rs:257`).
  - `mtls_auth` `cert_field`, `allowed_issuers` and `allowed_ca_fingerprints_sha256` (`src/plugins/mtls_auth.rs:974`, nested `:221`).
- **`lint-profiles.rb`:** keep the new `jwt_auth` keys `algorithm` and `hide_credentials`, and the array form of `key_location`, out of the allowlists while v0.9.15 and older are supported.

### `jwks_auth` 401s now carry a challenge (#6779)

Every `jwks_auth` rejection goes through `auth_flow::auth_rejection`, so each 401 carries `WWW-Authenticate`. Extraction failures (`Invalid Authorization header`, `Empty bearer token`, `Empty DPoP token`, `Invalid token`, `Empty token`) answer `Bearer error="invalid_request"` (`src/plugins/jwks_auth.rs:1694`). A rejected token (`Invalid or unrecognized JWT`) answers `Bearer error="invalid_token"`, or `DPoP error="invalid_token"` when it came as `Authorization: DPoP` (`:1703`, `:1714`). `mTLS binding mismatch` is an `invalid_token` under the presented scheme, and under `DPoP` for a `require_dpop` provider (`:1736`). `DPoP proof required`, `Invalid DPoP proof`, `DPoP URL mismatch` and `DPoP replay` answer `DPoP error="invalid_dpop_proof"` (`:1729`, `:1747`). `DPoP validation failed` answers `invalid_dpop_proof` for a proof fault, or `DPoP error="invalid_token"` when the token lacks `cnf.jkt`, its `cnf.jkt` does not match the proof key, or it lacks `iss` or both `sub` and `client_id` (`:1562`, `src/plugins/utils/dpop.rs:129`, `jwks_auth.rs:1513`). The 503 replay refusals carry none. On a route with several auth plugins, the authentication phase lists the rejecting mechanism's challenge first, then every other applicable mechanism's (`src/proxy/mod.rs:33448`). Before this change the last rejection's headers won. Tag ancestry: v0.9.18 (unpublished; released in v0.9.19).

**Catalog impact:** `public_signal.other_headers` updated on the 11 `plugin.jwks_auth.*` 401 outcomes. The "no WWW-Authenticate" notes are obsolete. `jwks_auth.invalid_authorization_header` lists `Bearer error="invalid_request"` (jwks) or `hmac realm="ferrum-edge"` (hmac, `src/plugins/hmac_auth.rs:2510`), so the challenge now separates jwks from hmac. The following pairs now send the same signal, and `shared_signal_with` is set on both sides:
- `jwks_auth.invalid_token_location` and `oauth2_introspection.invalid_token_location`
- `jwks_auth.empty_token_location` and `oauth2_introspection.empty_token_location`
- `jwks_auth.invalid_authorization_header` and `oauth2_introspection.invalid_authorization_header`
- `jwt_auth.empty_bearer_token` and `oauth2_introspection.empty_bearer_token` (`jwt_auth` uses the same `rejection_challenge` mapping, `src/plugins/jwt_auth.rs:287`)

`oauth2_introspection` challenge values are unchanged.

### `jwks_auth` missing-credential behavior: `allow_missing_token` and the advertised challenge (#6596, #6779)

`emit_mesh_request_principal_metadata` no longer makes a sole `jwks_auth` optional. Only the new `allow_missing_token: true` sets the permissive marker (`src/plugins/jwks_auth.rs:1685`, `:2072`; consumer `src/proxy/mod.rs:34348`). Mesh mode sets it on its generated RequestAuthentication. A standalone instance that set only the metadata flag now answers credential-less requests with the auth-phase 401. That 401 now advertises `Bearer`, or `DPoP` when every provider sets `require_dpop` (`jwks_auth.rs:1119`). Both changes are BREAKING per the changelog; tag v0.9.18.

**Catalog impact:** `proxy.auth_phase.missing_credential` (outside this slice) needs its "jwks permissive-missing-token metadata" exception and challenge alternatives updated. No lab profile sets either key.

### `jwks_auth` verification policy (#6828, #6597, #6644)

The body is unchanged: still `Invalid or unrecognized JWT`, still indistinguishable from a JWKS outage. The conditions under which it fires changed:
- `clock_skew_seconds` (root and per provider, default 0, max 300) is the `exp`/`nbf` leeway (`src/plugins/utils/jwt_verifier.rs:222`).
- `PS256`/`PS384`/`PS512` and Ed25519 `EdDSA` keys verify. Ed25519 is refused under FIPS.
- `aud` must be a string or a non-empty string array, and any `aud` is refused when no audiences are configured (`jwt_verifier.rs:159`).
- A token is tried only against providers pinning its exact `iss`, plus issuer-less providers, at most 8 (`jwks_auth.rs:1365`).
- A token whose `iss` is pinned by a `require_dpop`/`require_mtls_binding` provider, and which fails that provider, is no longer accepted by an issuer-less sibling (`:1384`).
- A `discovery_url` provider re-runs discovery every `jwks_refresh_interval_secs` (`:2447`).

`jwks_auth` no longer calls `verify_jwt_with_jwks`; it verifies through `verify_jwt_with_compiled_validation` (`jwt_verifier.rs:109`, called at `jwks_auth.rs:2655`). The mechanically remapped `jwt_verifier.rs:34` citation is repointed. DPoP proofs now also accept `ES384`, `RS384`/`RS512`, `PS*` and `EdDSA` (`dpop.rs:139`). They refuse RSA proof keys outside 2048–8192 bits (`:159`), and they compare the proof `htu` path after the frontend's canonicalization (`:285`). All of these failures still produce the one `DPoP validation failed` body.

**Catalog impact:** conditions and notes updated on `plugin.jwks_auth.invalid_or_unrecognized_jwt` and `.dpop_validation_failed`. Admission-only refusals add no outcome: more than 64 providers, more than 8 candidates, `clock_skew_seconds` above 300, and an issuer-less `require_mtls_binding` provider beside an unbound one (`jwks_auth.rs:1002`).

### Expired DPoP replay markers re-admitted across principals (#6116)

In the process replay lane, an expired marker presented by a different principal is now re-admitted and charged to that principal. Before, it answered `DPoP replay` (`src/plugins/utils/replay_authority.rs:681`). Tag v0.9.16.

**Catalog impact:** condition of `plugin.jwks_auth.dpop_replay` narrowed. The 601 s retention and the 300 s proof `iat` window make this practically unreachable for a single proof.

### New: `oauth2_introspection` certificate-bound tokens (#6840)

With `providers[].accept_mtls_bound_tokens: true`, an active response whose `cnf` is exactly one non-empty `x5t#S256` is admitted only on a connection whose client certificate has that thumbprint (`src/plugins/oauth2_introspection.rs:2502`, `:2525`). This is re-checked on every request, cache hits included, before any scope or role verdict. Otherwise the request gets 401 `{"error":"mTLS binding mismatch"}` with `Bearer error="invalid_token"` (`:700`, `:704`). Without the option, any non-null `cnf` is still `Sender-constrained tokens are not supported` (`:2517`, called at `:998`), and a JSON-null `cnf` now reads as absent. Tag v0.9.18.

**Catalog impact:** **new outcome** `plugin.oauth2_introspection.mtls_binding_mismatch` (owner caller, gRPC 16). Its signal is identical to the Bearer variant of `plugin.jwks_auth.mtls_binding_mismatch`, so the two share a signal. Condition of `.sender_constrained_unsupported` narrowed. Citation repointed from `:848` to `:2517`.

### `oauth2_introspection` dependency conditions (#6840, #6637, #6132)

The 503 `Token introspection unavailable` is unchanged; what triggers it changed:
- **Concurrency limits.** The fixed 32/128 caps became `providers[].max_concurrent_introspections` (default 32) and a plugin-level `max_concurrent_introspections` (default 128), under a fixed 1024 process ceiling (`oauth2_introspection.rs:847`, `:859`). They do not queue, and instances no longer share one budget.
- **`private_key_jwt` assertion audience.** It is now `client_auth.client_assertion_audience` or the endpoint, no longer the pinned `issuer` (`:910`). This is BREAKING: a server that wants the issuer now refuses the call, which surfaces as this 503.
- **Null members.** JSON-null `exp`/`active_until`/`expires_in` (`:1516`, `:1525`, #6637) and `token_type` (`:1002`) read as omitted instead of 503.
- **Hop count.** Introspection calls carry the proxy hop count (`:934`, #6132, v0.9.17), so a loop back through the gateway gets a 508 and then this 503.
- **Discovery.** It refreshes every `discovery_refresh_interval_secs` (default 900) and keeps the last known endpoint on failure.

**Catalog impact:** conditions updated on `.introspection_unavailable`. Notes updated on `.unsupported_token_type`. Seven other oauth2 outcomes and `jwks_auth.dpop_replay_capacity` carry unchanged.

### Lab: jwks and oauth2 configuration and checks

No `jwks_auth` or `oauth2_introspection` key used in `lab/gateway/auth.yaml`, `tls.yaml` or `workload-proxy.yaml` is refused or renamed on v0.9.20. Every key in the `lint-profiles.rb` jwks and oauth2 allowlists is still accepted. `tls-bound-token` pins `issuer`, and `wl-jwt-svid` has one issuer-less provider, so the new admission limits do not apply. The new keys must stay out of the allowlists while older releases are supported. The jwks scenarios now receive a challenge; no lab check asserts its absence. AUTH-X01/X01-nbf (`invalid_token`) and AUTH-X02 (no challenge on 503) hold. Outside this fork: AUTH-001 expects exactly `ferrum-edge` on the `key_auth` route, which v0.9.20 answers with `ApiKey realm="ferrum-edge"`.

### `hmac_auth` 401s carry the `hmac` challenge (#6779)

Every `hmac_auth` 401 now goes through `hmac_reject`, which calls the shared `auth_rejection` with
`WWW-Authenticate: hmac realm="ferrum-edge"` (`src/plugins/hmac_auth.rs:2510`, constant
`src/plugins/utils/auth_flow.rs:652`). This covers extraction, verification, digest, Date and
replay rejects, on the ordinary and pre-buffered paths. On v0.9.15 `hmac_reject` returned an empty
header map. The 403, 500 and 503 rejects carry no challenge. On a route with several auth
mechanisms, the proxy writes one field: the rejecting mechanisms' challenges come first, then every
other applicable challenge (`src/proxy/mod.rs:33448`). First tagged v0.9.18.

**Catalog impact:** `public_signal.other_headers` gains the challenge on the 20 hmac 401 outcomes.
Status, body and gRPC status are unchanged. `plugin.hmac_auth.invalid_credentials` and
`plugin.basic_auth.invalid_credentials` share the body `{"error":"Invalid credentials"}`, but they
can now be told apart by the challenge (`hmac` vs `Basic`). No lab assertion reads the hmac
challenge.

### `hmac_auth` `signing_profile: rfc9421` (#6853)

A new profile verifies exactly one RFC 9421 `Signature-Input`/`Signature` pair with `hmac-sha256`.
The Consumer secret is looked up by `keyid`. The signature must cover `@method`, `@authority`,
`@path`, `@query`, `content-digest` and any configured `signed_headers`/`required_components`.
`created`, `keyid` and `nonce` are required, `expires` is enforced, and the nonce is single-use in
its own replay domain (`extract_rfc9421` `src/plugins/hmac_auth.rs:2264`;
parser `:795`). Fourteen new 401 bodies come from this path, all with the hmac
challenge and gRPC 16:

| New outcome | Body | Edge (v0.9.20) |
|---|---|---|
| `plugin.hmac_auth.rfc9421_malformed_signature` | `Malformed Signature-Input or Signature header` | `:336`, `:804`, `:2295` |
| `plugin.hmac_auth.rfc9421_incomplete_signature` | `Signature-Input and Signature must be sent together` | `:338`, `:801` |
| `plugin.hmac_auth.rfc9421_multiple_signatures` | `Exactly one HTTP message signature is accepted` | `:340`, `:810` |
| `plugin.hmac_auth.rfc9421_unsupported_component` | `Unsupported covered component in Signature-Input` | `:342`, `:881`, `:722` |
| `plugin.hmac_auth.rfc9421_unsupported_parameter` | `Unsupported signature parameter in Signature-Input` | `:344`, `:846` |
| `plugin.hmac_auth.rfc9421_unsupported_algorithm` | `Unsupported signature algorithm` | `:346`, `:2276` |
| `plugin.hmac_auth.rfc9421_uncovered_component` | `Signature does not cover a required component` | `:347`, `:2283` |
| `plugin.hmac_auth.rfc9421_missing_covered_component` | `Covered component is missing from the request` | `:349`, `:723`, `:692` |
| `plugin.hmac_auth.rfc9421_missing_keyid` | `Missing or malformed keyid in Signature-Input` | `:351`, `:2289` |
| `plugin.hmac_auth.rfc9421_missing_created` | `Missing created in Signature-Input` | `:352`, `:2292` |
| `plugin.hmac_auth.rfc9421_missing_nonce` | `Missing nonce in Signature-Input` | `:353`, `:2298` |
| `plugin.hmac_auth.rfc9421_malformed_nonce` | `Malformed nonce in Signature-Input` | `:354`, `:2301` |
| `plugin.hmac_auth.rfc9421_signature_expired` | `Signature is outside its validity window` | `:355`, `:1878`, `:2464`, `:2170` |
| `plugin.hmac_auth.rfc9421_content_digest_required` | `rfc9421 requires a Content-Digest header` | `:356`, `:2309` |

Under `rfc9421` the gateway never reads `Authorization`. The nine Ferrum-format parse outcomes
therefore fire only under `ferrum-hmac-v2`/`v1`, and so does `date_missing_or_expired`, whose body
is now chosen per profile (`stale_body` `:1876`). Their conditions are scoped to those profiles.
The digest, authority, namespace, HBONE, digest-mismatch, invalid-credentials and replay outcomes
fire under both profiles; their notes now say so.

**Catalog impact:** 14 new outcomes. Conditions and notes are updated on the Ferrum-only outcomes.
The new outcomes are first tagged v0.9.18; that tag was not published, so the first published
release with them is v0.9.19.

### `hmac_auth` `signed_headers` and `max_body_bytes` (#6853)

`signed_headers` takes up to 32 lowercase field names, refused at admission otherwise
(`src/plugins/hmac_auth.rs:2698`). Each named header must be present, and its canonical value is
appended to the Ferrum signing base as a `name:value` line (`:2886`). There are two new 401s:
`{"error":"Missing required signed header"}` (`:1968`) and
`{"error":"Malformed signed header value"}` (`:646`). The second also fires for an rfc9421-covered
header line that is not visible ASCII.

`max_body_bytes` (default 10 MiB, range 1 to 256 MiB, `:2783`) replaces the fixed pre-auth body
ceiling (`request_body_buffer_limit` `:2659`). Under `rfc9421`, a `Signature-Input` or `Signature`
header triggers the pre-auth buffering (`:1919`).

**Catalog impact:** new outcomes `plugin.hmac_auth.missing_signed_header` and
`.malformed_signed_header`. One fix is outside this slice: `proxy.request_body_prebuffer_too_large`
still cites `src/plugins/hmac_auth.rs:121@25b3739` (`HMAC_REQUEST_BODY_LIMIT_BYTES`, now removed).
Repoint it to `:2659` and change its condition from "hmac_auth 10 MiB" to "hmac_auth
`max_body_bytes`".

### `hmac_auth` RFC 9421 CONNECT target (#6925)

For an authority-form CONNECT, `@request-target` is now the exact target as sent: original host
spelling, port and IPv6 brackets (`unreconstructible_request_target` `src/plugins/hmac_auth.rs:734`).
It is no longer a reconstructed `/`. A signature over the old value gets
`401 {"error":"Invalid credentials"}`. #6853 and #6925 both first ship in v0.9.19 (tagged v0.9.18), so no published
rfc9421 client ever signed the old value.

**Catalog impact:** notes on `plugin.hmac_auth.invalid_credentials`.

### `hmac_auth` replay and admission bounds (#6853, #6925, #6636)

None of these change a client signal:
- **Admission:** `replay_max_entries` above 10,000,000, or set under `ferrum-hmac-v1`, is refused
  (`:1587`).
- **Replay reclamation:** process-lane reclamation now pops only expired markers from an ordered
  expiry index, in batches of at most 64. Live markers are still never evicted, and capacity still
  fails closed with 503.
- **Replay logging:** a verified replay logs `replay_rejected_consumer` (`:186`).
- **Timing:** every username now costs the same number of MAC rounds (`:2009`, #6636).

**Catalog impact:** none. `replay_capacity` and `replay_unavailable` are carried unchanged apart
from their repointed citations.

### `ldap_auth` unknown-user equalization and cached group re-check (#6645)

Search-then-bind now spends one throwaway bind on an unknown username before answering
`401 LDAP authentication failed` (`src/plugins/ldap_auth.rs:1917`, `:2035`). If that bind meets
a transport, busy or unavailable failure on every endpoint, the client gets
`500 LDAP authentication temporarily unavailable` instead.

With the opt-in credential cache (`cache_ttl_seconds` > 0), a cache hit whose group check is older
than `group_cache_ttl_seconds` (default 60, `:100`) re-runs the check under the same request
deadline. That re-check can answer the existing 403 (`:3792`), the 500
`LDAP group membership check failed` (`:3797`) or the 500 `temporarily unavailable` (`:3764`).

**Catalog impact:** conditions and notes updated on `authentication_failed`,
`temporarily_unavailable`, `group_forbidden` and `group_check_failed`. Signals are unchanged.

### `ldap_auth` authoritative `group_attribute`, membership modes, failover, credential guards (#6846)

**Group matching.** A returned group entry now matches only through its `group_attribute` values
(`src/plugins/ldap_auth.rs:2332`). The entry's first `cn` RDN stands in only when
`group_attribute` is `cn` and the directory omits it (`:2342`). A look-alike
`CN=gateway-admins` in a delegated OU therefore gets the 403.

**Membership modes.** There are new modes `ad_in_chain` and `member_of`, plus a new
`group_member_attribute` setting.

**Failover.** `failover_ldap_urls` are tried in order, but only after connection, transport, `busy`
(51) or `unavailable` (52) failures (`:1810`). A credential rejection is final.

**Credential guards.** Two opt-in guards answer the ordinary 401 without a directory round trip:
a negative cache (`:3629`) and a per-username backoff (`:3635`). If the failure tracker is
saturated, the request gets the 500 `temporarily unavailable` (`:3639`).

**Admission.** DN-shaped settings and attribute settings are now validated, and port 0 is refused.
These changes are admission-only.

**Catalog impact:** condition updates only. The lab's LDAP configs still pass admission.

### `ldap_auth` `member_of` proof budget (#6922)

`group_membership_mode: member_of` now allows 16 reverse-membership proofs per request in total
(`src/plugins/ldap_auth.rs:3146`, `:2418`). The budget is shared across endpoints and across
the cached re-check plus the uncached fallback. A request that needs more fails closed with
`500 {"error":"LDAP group membership check failed"}` (`:2440`). The CHANGELOG lists this under
0.9.19; the change is first tagged v0.9.18.

**Catalog impact:** condition updated on `plugin.ldap_auth.group_check_failed`.

### Lab: hmac and LDAP profiles

Neither `auth018-hmac` nor `auth027-ldap`/`auth028-ldap-down` in `lab/gateway/auth.yaml` uses a key
that v0.9.20 refuses or renames. The hmac config is `ferrum-hmac-v2`, `replay_scope: process`,
`clock_skew_seconds: 300` (`src/plugins/hmac_auth.rs:272`). The LDAP configs use a loopback
`ldap://`, a `bind_dn_template` and `canonical_identity_attribute: uid`
(`src/plugins/ldap_auth.rs:2617`). The template expands to a valid RFC 4514 DN (`:872`), and
plaintext loopback stays allowed without `allow_plaintext` (`:1162`).

The new hmac keys (`signed_headers`, `required_components`, `max_body_bytes`) and the new LDAP keys
are refused by v0.9.15 and older. They must therefore stay out of the `lint-profiles.rb`
every-release allowlists. Its hmac comment still cites the v0.9.15 key lines (`:177-183`); at
v0.9.20 the keys are at `:272-281`.

AUTH-018 through AUTH-023 and AUTH-027/028 keep their status and body. The hmac 401s now also carry
the `hmac` challenge, which no scenario checks.

### `oidc_relying_party`: the state-cache-full 503 is back (#6833, v0.9.19)

v0.9.15 removed `plugin.oidc_relying_party.challenge_browser_state_cache_full`, because a full instance-local pending-login cache let every login continue on the sealed cookie. From v0.9.19, `insert_pending_flow_or_use_sealed_cookie` (`src/plugins/oidc_relying_party.rs:3768-3785`) sends a full-cache login through `StateCache::admit_sealed_only` (`:3781`). That function checks the per-source cap first (`:3544`), keeps the slot charged until the flow expires or its callback arrives, and allows one extra cache-worth of sealed-only flows. After that it returns `STATE_CACHE_FULL_ERROR` (`:3554`, constant `:120`), which `create_flow` propagates (`:2597`) and the challenge turns into 503 `{"error":"OIDC state cache full"}` (`:2513`).

**Catalog impact:** the outcome is drafted under `new_outcomes` with its 0.9.15 id, not as a modification, with notes starting "New in v0.9.19" that say it was absent in 0.9.15, and the v0.9.20 catalog must drop it from `removed_outcomes`. The notes on `challenge_browser_too_many_pending_logins` are replaced, because the v0.9.15 statement that "this 503 is not sent in that state" no longer holds. Its prose citation is repointed from `:3081-3096` to `:3768-3785`.

### `oidc_relying_party` logout forgery screen: new 403 and 405 (#6833, issue #6660, v0.9.19)

`logout_request_refusal` (`src/plugins/oidc_relying_party.rs:4903`, called at `:3245`) runs before anything is cleared or contacted:

| Request | Result |
|---|---|
| GET/HEAD with `Sec-Fetch-Site: same-origin` or `none` | Allowed |
| POST without `Sec-Fetch-Site`, or with `same-origin`/`none` | Allowed |
| GET/HEAD without the header or with any other value | 403 `{"error":"Logout must be a same-origin request"}` (`:4912`) |
| POST with `Sec-Fetch-Site: cross-site` or `same-site` | 403 `{"error":"Logout must be a same-origin request"}` (`:4912`) |
| Any other method | 405 `{"error":"Method not allowed"}` with `Allow: GET, HEAD, POST` (`:4922-4923`) |

**Catalog impact:** two new outcomes, `plugin.oidc_relying_party.logout_cross_site_refused` (gRPC 7) and `.logout_method_not_allowed` (gRPC 12). The 405 body differs from `gateway.routing.method_not_allowed` (`Method Not Allowed`) only by letter case; the fixed `Allow` value tells them apart. The condition of `logout_short_circuit` is narrowed: a scripted GET without `Sec-Fetch-Site` now gets the 403.

### `oidc_relying_party` `max_age_secs`: new callback 400 and re-challenge (#6833, v0.9.19)

The new `providers[].max_age_secs` key does three things:
- adds `max_age` to the authorization URL (`src/plugins/oidc_relying_party.rs:2625`);
- makes the callback refuse an ID token with no `auth_time`, or one older than `max_age` plus `id_token_clock_skew_secs`: 400 `{"error":"Invalid ID token auth_time"}` with the correlation cookie cleared (`:1585`);
- re-challenges a session whose login is older than `max_age` (`:1914`).

The new `providers[].authorization_params` key also appends static parameters to the authorization URL (`:2628`); reserved names are refused at load (`:4515`).

**Catalog impact:** new outcome `plugin.oidc_relying_party.callback_invalid_id_token_auth_time`. The `Location` template of `challenge_browser_redirect` and the conditions of `challenge_api_invalid_or_expired_session` and `challenge_browser_redirect_clear_session` are extended.

### `oidc_relying_party` session size: named 400 and chunk cookies (#6833, v0.9.19)

`seal_session_value` now refuses a session whose estimated sealed size exceeds `session.max_cookie_bytes` with 400 `{"error":"OIDC session exceeds session.max_cookie_bytes"}` (`src/plugins/oidc_relying_party.rs:2863`, sent at the callback via `:1648`). Before, this failed the AEAD seal and answered `Session creation failed`.

Sessions are now set with `Max-Age` equal to their remaining absolute lifetime. A session whose cookie line would exceed 4000 bytes is split into `<name>.0` … `<name>.N` chunk cookies. Every session clear (`clear_session_cookies`, `:3019`, formerly `clear_cookie`) also expires the chunk cookies the request carried. Pending flows are read up to the 8000-byte admission maximum, not the current cap (`:2658`).

**Catalog impact:** new outcome `plugin.oidc_relying_party.callback_session_too_large` (owner gateway operator). The condition of `callback_session_creation_failed` is narrowed. The `Set-Cookie` shapes of `challenge_api_invalid_or_expired_session`, `challenge_browser_redirect_clear_session` and `logout_short_circuit` are updated. Two structured citations move from `:2491` to `:3019`. The sibling body `OIDC session exceeds browser cookie limits` (`:2767`) appears unreachable under the 8000-byte cap and is left uncatalogued (open question).

### `oidc_relying_party` spent refresh no longer clears the cookie (#6833, v0.9.19)

A claims-freshness re-challenge after a spent (`invalid_grant`) or indeterminate refresh now calls `challenge(ctx, !refresh.must_not_reseal)` (`src/plugins/oidc_relying_party.rs:1969`). It no longer deletes a cookie that another replica may already have rotated. In that case the API 401 carries no `Set-Cookie` and matches `challenge_api_no_session` exactly. A browser in the same case gets `challenge_browser_redirect`, not the clear-session variant.

A 2xx refresh whose response fails validation now drops the consumed refresh token. The session keeps serving until its claims expire.

**Catalog impact:** the condition and distinguishability notes on the four challenge outcomes are updated. Flagged citations `:1661`, `:1664` and `:1722` are repointed to `:1885`, `:1888` and `:1969`.

### `oidc_relying_party` challenges under #6779 (v0.9.19)

The API challenge value is unchanged: `Bearer realm="oidc", error="invalid_token"`, now the constant `OIDC_INVALID_SESSION_CHALLENGE` (`src/plugins/utils/auth_flow.rs:640`, used at `src/plugins/oidc_relying_party.rs:2554`). What changed around it:
- On a route with other authentication mechanisms, the auth-phase finalizer folds the field into one value. That value lists the oidc challenge, then every other applicable mechanism's challenge (`src/proxy/mod.rs:33448`).
- The plugin now advertises `Bearer realm="oidc"` (`src/plugins/utils/auth_flow.rs:637`, `src/plugins/oidc_relying_party.rs:3215`) on other mechanisms' 401s.
- A header policy can no longer strip the field.
- `apply_verify_outcome` 401s now carry the challenge too (`:4006`); no catalogued outcome maps to them.

**Catalog impact:** notes only, on `challenge_api_no_session` and `challenge_api_invalid_or_expired_session`. Anvil should match the oidc challenge as one element of a challenge list.

### `oidc_relying_party` callback `error` relay (#6636, v0.9.19)

The callback relays the IdP's `error` only when it is 1–64 bytes of `[A-Za-z0-9_.-]` (`src/plugins/oidc_relying_party.rs:1533`, `:5560`). Anything else becomes `{"error":"authorization_failed"}` (`:1536`).

**Catalog impact:** `body_shape` of `callback_idp_error` is updated.

### `oidc_relying_party` discovery issuer check and cross-origin endpoints (#6833, v0.9.19)

A discovery document whose `issuer` is missing or differs from the configured issuer is refused (`src/plugins/oidc_relying_party.rs:5306-5311`). Discovery then never loads, and the plugin keeps answering `OIDC discovery unavailable`: 503 on the browser challenge, 400 at the callback.

HTTPS endpoints may now be cross-origin (Google, Entra ID). Plain HTTP is confined to the loopback `discovery_url`'s own origin, and endpoint URLs with userinfo are refused (`:4459-4470`).

**Catalog impact:** notes on `challenge_browser_discovery_unavailable` and `callback_discovery_unavailable`.

### `oidc_relying_party` minor condition changes

- Session AEAD context seed version 3 (`src/plugins/oidc_relying_party.rs:148`) invalidates every existing session and in-flight login once on upgrade.
- Token and UserInfo calls carry the proxy hop count (#6132, v0.9.17, `:1748`). A looping token endpoint therefore lands in `callback_token_exchange_failed`.
- The shared JWKS store admits PS256/PS384/PS512 and EdDSA keys (#6828, v0.9.19, `src/plugins/utils/jwks_store.rs:919`). ID tokens signed that way no longer fail `callback_invalid_id_token`.
- These are now refused at config load, with no request-time signal:
  - non-canonical `callback_path`/`logout_path` (`:4597`);
  - non-authority `trusted_redirect_hosts` entries (`:4499`);
  - reserved or oversized `authorization_params` (`:4515`);
  - cookie attributes that leave less than 1024 bytes per chunk.

  Post-login redirects are now matched as origins (`:3156`).
- `lifecycle_hooks` (#6975, v0.9.20) declares exactly the three hooks the plugin implements, so behaviour is unchanged.

**Catalog impact:** notes on `callback_token_exchange_failed`, `callback_invalid_id_token` and `callback_invalid_state`. 14 of the 27 carried oidc outcomes are verified unchanged.

**Lab:** no impact. The AUTH-017 configuration keys are all in the v0.9.20 field lists. The callback and logout paths are canonical. The lab IdP's discovery document returns `issuer` equal to the configured `https://idp.anvil-lab.invalid` (`crates/anvil-fixtures/src/gateway_idp.rs:296`, set by `crates/anvil-lab/src/fixtures_auth.rs:134`), with loopback endpoints on the `discovery_url` origin. The lab session (a short opaque access token, a small ES256 ID token and no refresh token) stays a single cookie. No scenario calls the logout path. The new provider keys (`authorization_params`, `max_age_secs`, `forward_access_token`) stay out of `lint-profiles.rb` while older releases are supported.

### `soap_ws_security` 401s carry a `WS-Security` challenge (#6779, v0.9.19)

Every `soap_ws_security` rejection goes through `SoapRejection::into_plugin_result`, which now calls `auth_flow::auth_rejection` with `WS-Security realm="ferrum-edge"` (`src/plugins/soap_ws_security.rs:5368`, constant `src/plugins/utils/auth_flow.rs:664`). A 401 now carries `WWW-Authenticate: WS-Security realm="ferrum-edge"`; 400, 415 and 500 refusals carry none. This applies to timestamp-only (`before_proxy`) policies too: `Plugin::authentication_challenge` is gated on `establishes_identity()` (`:6075`), but that gate only decides whether the challenge is also listed on other mechanisms' 401s. On an identity-establishing policy the auth-phase 401 also lists the challenge of every other applicable mechanism on the route (`src/proxy/mod.rs:33448`). Status codes and bodies are unchanged.

**Catalog impact:** `public_signal.other_headers` gains the challenge on the 10 soap 401 outcomes (`missing_security_header`, `timestamp_rejected`, `username_token_invalid_credentials`, `username_token_structural`, `nonce_replay`, `replay_backend_unavailable`, `replay_state_saturated`, `x509_signature_rejected`, `saml_rejected`, `saml_assertion_replay`). The note on `missing_security_header` saying there is no challenge is removed. The lab proxies each run one SOAP instance, so they answer exactly `WS-Security realm="ferrum-edge"`. The AUTH-029/030/031 checks compare status and body only and still pass.

### New 400: XML namespace and attribute bounds (#6820, v0.9.19)

Before the parser runs, `screen_raw_namespace_markup` (`src/plugins/soap_ws_security.rs:7540`) checks a governed envelope against fixed ceilings:

- at most 64 attributes per start tag
- attribute names up to 128 bytes, namespace-declaration names up to 70 bytes, namespace URIs up to 2048 bytes
- at most 256 namespace declarations in scope at any element, and at most 256 distinct bindings per envelope
- comparison work up to 32 × the envelope length (floor 1 MiB)

Anything over a ceiling gets 400 `{"error":"SOAP request exceeds the supported XML namespace and attribute bounds"}` (`:5443`). Markup the screen cannot frame gets the existing `malformed_xml` body with category `document ended before markup was complete` (`:5453`). Canonicalization also has a new namespace-resolution budget (`:6741`) and its own 64-attribute check (`:7189`). Both answer the existing `{message}` 401.

**Catalog impact:** new outcome `plugin.soap_ws_security.xml_namespace_bounds_exceeded`. `malformed_xml` condition extended; `x509_signature_rejected` and `saml_rejected` notes list the new messages.

### New 401 and config key: `require_mechanisms: any` (#6820, v0.9.19)

`require_mechanisms` takes `all` (the default, behaviour unchanged) or `any` (`:2570`). `any` needs at least two enabled identity mechanisms, otherwise admission refuses it (`:2592`). Under `any`, a mechanism runs only when its token is presented, and a presented token that fails still rejects the message. A message that presents none of the enabled tokens gets 401 `{"error":"WS-Security: none of the accepted security tokens was presented"}` with the WS-Security challenge (`:5619`).

**Catalog impact:** new outcome `plugin.soap_ws_security.no_mechanism_presented`. `username_token_structural` notes say an absent token is skipped under `any`. The lab does not use the key, and `lint-profiles.rb` must keep it out while older releases are supported.

### Forbidden XML declaration only in the prolog (#6820, v0.9.19)

The case-insensitive whole-body search for `<!doctype`/`<!entity` is gone. `prolog_contains_markup_declaration` (`:8054`, called at `:5425`) refuses any `<!` declaration found before the root element, after a BOM, the XML declaration, PIs, comments and whitespace. The same text inside CDATA, a comment or character data is now accepted. A declaration after the prolog fails as `malformed_xml`.

**Catalog impact:** both flagged citations repointed (`:4829` → `:5425`; `contains_forbidden_xml_declaration` `:7060` → `prolog_contains_markup_declaration` `:8054`). `forbidden_xml_declaration` condition narrowed. Signal unchanged.

### Pinned signer validity and zoned instants (#6632, v0.9.19)

A trusted certificate in `x509_signature.trusted_certs` or `saml.trusted_signing_certs` is honoured only within notBefore..notAfter. Outside that window the signature gets 401 `WS-Security: signing certificate is outside its validity period` (`:3884`) or `WS-Security: SAML signing certificate is outside its validity period` (`:4703`). Such a pin is still admitted, and a warning is logged when the plugin is built. Timestamp, UsernameToken `Created` and SAML `NotBefore`/`NotOnOrAfter` values without `Z` or `±hh:mm` are now refused as invalid instead of read as UTC (`:9116`).

**Catalog impact:** notes on `x509_signature_rejected`, `saml_rejected`, `timestamp_rejected` and `username_token_structural`. The lab signs with `Z` instants and with fresh `openssl -days 2` certificates (`crates/anvil-lab/src/fixtures_auth_soap.rs:119`, `:170`), so it is unaffected.

### SAML Conditions and SubjectConfirmation (#6820, #6804, v0.9.19)

Every element child of `Conditions` is now evaluated. Only a standard `AudienceRestriction`, at most one `OneTimeUse` and at most one `ProxyRestriction` are accepted, with no derived `xsi:type` and no extension content (`:4350`). Anything else gets 401 with the fixed message `WS-Security: SAML Conditions carries an unsupported condition …` (`:5241`). A second `OneTimeUse` or `ProxyRestriction` has its own message (`:4359`, `:4373`). A `SubjectConfirmation` that does not qualify is skipped, and its reason is reported only when none qualifies (`:4527`). Two qualifying confirmations are still rejected as ambiguous. X.509 References may now resolve inside any SOAP Header block, and the out-of-scope message changed (`:4066`). With roxmltree 0.21.2 (#6804), `ID`, `URI`, `Algorithm`, `Type`, `Method`, `Recipient` and the validity attributes are read only in unqualified form.

**Catalog impact:** `saml_rejected` and `x509_signature_rejected` notes. The lab assertion carries only an AudienceRestriction and one bearer confirmation.

### Shared replay refuses an evicting Redis (#6820, #6649, v0.9.19)

`nonce.replay_scope: shared` now uses `RedisRateLimitClient::for_retention_authority` (`:2543`, `src/plugins/utils/redis_rate_limiter.rs:3507`). Each connection must prove `maxmemory 0` or `noeviction` through `INFO MEMORY`. Three cases fail closed with the existing 401 `WS-Security: replay protection backend is unavailable`:

- an evicting policy, which is terminal for that config generation
- a policy that cannot be proven, which is treated as a recoverable outage
- a `SET NX` reply other than `OK` or nil (#6649)

**Catalog impact:** `replay_backend_unavailable` condition extended. The lab uses process scope.

### Replay claims re-admitted under a new principal (#6116, v0.9.17)

In process scope, a live nonce or SAML claim is a replay whichever principal presents it. At v0.9.15, an *expired* claim presented by a different principal also got the replay 401; it is now re-admitted, and its quota charge moves to the presenting principal (`:3362`–`:3364`). If the store is over its current caps or the principal is at its share, the stale entry is reclaimed and the normal fresh-claim path decides, which can still answer `replay_state_saturated`.

**Catalog impact:** `nonce_replay` and `saml_assertion_replay` conditions narrowed, and a note on `replay_state_saturated`. AUTH-029 and AUTH-031 replay within the retention window and are unaffected.

### `${...}` UsernameToken passwords (#6820, v0.9.19)

A `username_token.credentials[].password` of exactly `${FERRUM_PLUGIN_SECRET_<NAME>}` is now read from that environment variable when the config is admitted. Any other `${...}` value is refused at admission (`:1095`). This is not a client signal; it is noted on `username_token_invalid_credentials`. The lab password is `soap-<hex>` (`crates/anvil-lab/src/fixtures_auth.rs:64`).

### Unchanged

15 soap outcomes keep their signal and condition: media-type, MTOM, charset, encoding, empty-body, nesting-depth, envelope, ambiguous-header, the two credential-removal refusals, and `authenticated_body_mutated`. The MTOM boundary search now uses `memchr::memmem`, a performance change only. No `soap_ws_security` config key used by the lab is refused or renamed.

## Policy and transform plugins

### WAF refuses unlisted request bodies by default (#6646)

`on_unlisted_content_type` now defaults to `fail_closed` (it was `allow`): `src/plugins/waf/mod.rs:486`. A non-empty request body whose `Content-Type` is outside the scan scope gets the configured WAF reject (default 403 `{"error":"Forbidden"}`, grpc-status 7 on native gRPC) whenever an enforcing request-body policy applies. Examples are protobuf `application/grpc`, `application/octet-stream` and images. Only such bodies are buffered (`src/plugins/waf/mod.rs:2145`), and the refusal itself is `src/plugins/waf/mod.rs:948`. A rule with `score: 0` no longer makes a body policy enforcing (`src/plugins/waf/mod.rs:338`). Monitor-only deployments are unaffected.

**Catalog impact:** `plugin.waf.request_rule_block` condition and notes updated, and `plugin.waf.grpc_reject_mapping` notes updated. The signal is unchanged. A WAF-shaped 403 on a gRPC protobuf call or a binary upload no longer means a payload matched a rule.

### WAF governs request bodies on every method (#6813)

Request bodies are buffered and judged on any method except `CONNECT` when a body may follow the head (`Waf::request_may_carry_governed_body`, `src/plugins/waf/mod.rs:770`). That covers a `Content-Type`, declared HTTP/1.1 framing, HTTP/2 HEADERS without END_STREAM, or any HTTP/3 request. `body_methods` now only lists the methods that are always buffered, and its default gains `DELETE` (`src/plugins/waf/mod.rs:2636`). This applies to rule blocks, `on_body_too_large` and `on_scan_timeout` (`src/plugins/waf/mod.rs:2231`).

**Catalog impact:** `plugin.waf.request_rule_block`, `plugin.waf.body_too_large` and `plugin.waf.scan_timeout_block` conditions and notes updated. The signal is unchanged.

### WAF `body_json_path` rules fail closed on unparseable JSON (#6807, #6760, #6729, #6745, #6761)

The v0.9.15 early return that skipped every JSON-path rule on a body `serde_json` refused (`src/plugins/waf/scan.rs:491` at v0.9.15) is gone. When a body cannot be read but opens like a JSON object or array, or is declared JSON, every applicable JSON-path rule now records a hit and its own action decides (`JsonReadings::fail_closed`, `src/plugins/waf/scan.rs:208`; `push_unparsed_json_hits`, `src/plugins/waf/scan.rs:819-820`). Typical triggers are `NaN`, comments, trailing commas, nesting deeper than 128 levels and trailing text. Rules also read UTF-16/32, BOM-disagreeing, duplicate-member and lenient (U+FFFD) readings. The same pass runs on client-to-backend WebSocket messages (`src/plugins/waf/scan.rs:640`), so those now close with 1008 "message rejected by security policy".

**Catalog impact:** `plugin.waf.no_client_signal` citation repointed `scan.rs:491` → `scan.rs:208` and its condition narrowed. `plugin.waf.request_rule_block` and `plugin.waf.ws_rule_close` conditions updated.

### New: WAF refuses gRPC bodies it cannot inspect message by message (#6813)

Framed gRPC and gRPC-Web bodies in scan scope are now split into their length-prefixed messages (`grpc::split_messages`, `src/plugins/waf/grpc.rs:138`; called at `src/plugins/waf/mod.rs:2214`). Every rule runs per message in both directions. The body is refused with the WAF reject (`Waf::decide_uninspectable_grpc_body`, `src/plugins/waf/mod.rs:964`, `Err(self.reject())` at `:997`) when all of these hold:

- It contains a compressed message, a framing defect, or more than 1024 messages (`src/plugins/waf/grpc.rs:37`, `:48`).
- No rule hit decided first.
- That direction has an enforcing body policy.

Otherwise the gap is only recorded in metadata (`waf.body_uninspected=grpc_*`).

**Catalog impact:** new outcome `plugin.waf.grpc_message_uninspectable`, with the same 403 / grpc-status 7 signal as every other WAF/bot reject. It is added to `shared_signal_with` of the five 403 WAF outcomes and `plugin.bot_detection.forbidden`. The gRPC-Web rendering was not traced.

### New `on_unlisted_response_content_type` and relabeled-SSE response scanning (#6646, #6813)

The new key (`src/plugins/waf/mod.rs:81`, default `fail_closed` at `:496`) refuses a non-empty response body whose type is outside the scan scope (`Waf::decide_unlisted_response_content_type`, `src/plugins/waf/mod.rs:871`, `self.reject()` at `:905`). It needs response-body inspection with an enforcing rule; a missing type counts as outside the scope. A finite body that a later hook relabeled `text/event-stream` (`sse` `wrap_non_sse_responses`, response transformers) is no longer skipped: it is judged under its origin media type (`src/plugins/waf/mod.rs:2523-2549`). Only a pristine origin event stream stays `plugin.waf.response_event_stream_uninspectable`.

**Catalog impact:** `plugin.waf.response_rule_block` condition, sources and notes updated, and `plugin.waf.response_event_stream_uninspectable` condition updated. The signal is unchanged: the backend's 2xx is replaced by the WAF 403.

### WAF exemption and CIDR semantics tightened (#6646, #6684, #6813)

- `global_exemptions` criteria now AND-combine by default (`match: all`, `src/plugins/waf/exemptions.rs:123`).
- `header_present` values must be shared secrets of at least 16 characters (`src/plugins/waf/exemptions.rs:30`); presence-only entries are refused at admission.
- Non-canonical exemption paths are refused at construction (`src/plugins/waf/exemptions.rs:86`).
- CIDR rules and IP exemptions match `::ffff:a.b.c.d` spellings of IPv4 networks. An IPv6 network, `::/0` included, no longer matches native IPv4 callers (`src/plugins/waf/rules.rs:615`).
- A matched `header_present` secret now also suppresses the strict `block` dispositions (`strict_block_applies`, `src/plugins/waf/mod.rs:356`; `finish_timeout`, `:1545`; WebSocket `src/plugins/waf/websocket.rs:148`, `:285`, `:458`).
- FE-HPP-001 compares duplicates under both the `&` and `;` conventions (#6595).

**Catalog impact:** these notes and conditions are updated:

- `plugin.waf.request_rule_block`
- `plugin.waf.no_client_signal`
- `plugin.waf.body_too_large`
- `plugin.waf.scan_timeout_block`
- `plugin.waf.response_event_stream_uninspectable`
- `plugin.waf.ws_too_large_close`
- `plugin.waf.ws_uninspectable_close`

Requests that an OR-combined exemption used to exempt can now be blocked.

### `bot_detection` rejects non-UTF-8 User-Agents and treats blank ones as missing (#6878)

A `User-Agent` field line that is not valid UTF-8 is now rejected (`src/plugins/bot_detection.rs:377`), whatever `allow_list` and `allow_missing_user_agent` say. It used to count as missing and was allowed under the default. An empty or whitespace-only User-Agent is treated as missing (`user_agent_view`, `src/plugins/bot_detection.rs:308`), and the missing-UA reject is at `:369`. The blocked-pattern reject moved to `:403`. All three go through `BotDetection::reject` (`:93`) with the same status and body.

**Catalog impact:** `plugin.bot_detection.forbidden` citations repointed (`:330` → `:403`, `:300` → `:369`), with `:377` added. Its condition is updated and its signal is unchanged.

### Carried unchanged: WAF stream, datagram and trailer outcomes

These were verified on v0.9.20 with an unchanged condition and signal:

- `plugin.waf.tcp_connection_rejected`: `src/plugins/waf/mod.rs:1885`, `:1945`, `:1966`.
- `plugin.waf.udp_datagram_dropped`: `src/plugins/waf/mod.rs:1979`, `:2043`.
- `plugin.waf.response_trailers_dropped`: `src/plugins/waf/mod.rs:2284`.

The WAF reject builder is unchanged (`src/plugins/waf/mod.rs:1167`). #6975 adds `lifecycle_hooks` declarations (WAF `AFTER_PROXY`, bot_detection `ON_REQUEST_RECEIVED`) that match the hooks each plugin overrides, so no hook is skipped.

### Lab: GW-010 unaffected; new WAF defaults not yet pinned

`lab/gateway/policy.yaml` `gw010-waf` has an enforce-action `body_text` rule, so the v0.9.19 `on_unlisted_content_type: fail_closed` default applies to it. GW-010, GW-010-BODY and GW-010-BOT send only body-less GETs, `application/json` POSTs and ASCII User-Agents, so their assertions still hold. No WAF or bot_detection key used by the lab was removed or renamed, so `lint-profiles.rb` needs no change. Two optional release-gated scenarios would pin the new behaviour:

- an `application/octet-stream` POST to `/gw/waf`, expecting 403 with `waf.block_reason=content_type`;
- a non-UTF-8 User-Agent to `/gw/bot`, expecting 403.

### `body_validator` response validation is limited to `response_status_codes` (default 2XX)

v0.9.19 (#6845, BREAKING; tagged v0.9.18, unpublished). Response validation now runs only for statuses in the new `response_status_codes`. The default is `["2XX"]` (`src/plugins/body_validator.rs:467`, `:151`), and a `206` or `226` fragment is never validated (`:1470`). In v0.9.15 a backend `404`, `422` or `500` JSON error document that failed the success schema was replaced by the gateway `502 {"error":"Response body validation failed",...}`. On v0.9.20 it keeps its own status and body. The event-stream `502` (`:4840`) and the response-side descriptor-unavailable `502` (`:4956`) carry the same gate (`:4833`, `:4911`).

**Catalog impact:** the conditions of `plugin.body_validator.response_validation_failed` and `.response_event_stream` change, and notes are appended to `.protobuf_descriptor_unavailable`. On default config, a body_validator `502` now implies a 2XX backend status. The signal is unchanged.

### `body_validator` default media types add structured suffixes; empty lists refused

v0.9.19 (#6845). The default `content_types` and `response_content_types` add `application/*+json` and `application/*+xml` (`src/plugins/body_validator.rs:3280`, `:3282`). As a result, `application/problem+json`, `application/vnd.*+json` and `application/soap+xml` bodies are now validated. An explicit empty list used to mean "every media type" and is now refused at load (`:3251`).

**Catalog impact:** the conditions and notes of the request schema, request parse and response validation outcomes are updated. The signals are unchanged.

### `body_validator` validates gRPC-Web and tightens gRPC framing

v0.9.19 (#6845, #6733, #6638). Protobuf validation now covers gRPC-Web, both binary and text, in both directions (`src/plugins/body_validator.rs:1139`, `:1162`). The following also changed:

- A `protobuf_method_messages` entry is direction-authoritative.
- Per-method rules now apply on HTTP/3 and generic dispatch.
- A compressed frame must be exactly one fully consumed gzip member. A compression flag other than 0 or 1 is rejected (`:1572`, `:1594`).
- Preflight bounds (50000 messages, 32 levels) apply for every descriptor pool.
- `grpc_max_decompressed_size_bytes` is capped at 64 MiB at admission (`:1524`).

The `400` / `INVALID_ARGUMENT` and `502` / `UNAVAILABLE` signals are unchanged. They now come from the unified `BodyValidator::violation` (`:782`, titles `:816`-`:817`), which replaces `request_reject`, `response_reject` and `protobuf_reject`.

**Catalog impact:** 12 body_validator citations are repointed. The condition of `plugin.body_validator.request_protobuf_invalid` changes.

### New: `body_validator` strict media-type admission (415)

v0.9.19 (#6845). With `reject_unsupported_media_types: true` (default false), a non-empty request body that no configured rule inspects gets `415 {"error":"Unsupported request media type","details":"Request media type is not one this validator is configured to inspect"}`. This covers a gRPC body when no protobuf request rule is configured. Sources: `src/plugins/body_validator.rs:733`, `:4498`-`:4518`, `:815`, `:289`. gRPC has no specific mapping for 415, so it falls to `INTERNAL` (`src/proxy/grpc_proxy.rs:3132`).

**Catalog impact:** new outcome `plugin.body_validator.unsupported_media_type` (owner caller).

### New: `body_validator` protobuf decode-capacity refusal (503 / RESOURCE_EXHAUSTED)

v0.9.19 (#6845). The protobuf decompression and reflected decode are charged against the aggregate budgets: request-decode on the request side, retained-response on the response side. A refused reservation returns the shared capacity terminal with `grpc-status: 8` (`src/plugins/body_validator.rs:835`, `:654`, `:4978`, headers `:874`-`:875`). The bodies are `src/proxy/response_buffer_budget.rs:382` and `:479`. In v0.9.15 the decode was uncharged.

**Catalog impact:** new outcomes `plugin.body_validator.decode_capacity` (request side) and `plugin.body_validator.response_decode_capacity` (response side). The request-side refusal is a plugin reject before dispatch and carries no `X-Gateway-Error`; its signal is shared with `gateway.capacity.request_decode` and `plugin.compression.decode_capacity`. The response-side 503 replaces a backend response, so the final builder derives `backend_error` from its status (`x_gateway_error_for_response`, `src/proxy/mod.rs:46459`; `src/http3/server.rs:12549`; `src/retry.rs:301`), and its signal is shared with `gateway.capacity.response_buffer` and `plugin.custom.undeclared_response_body_producer`. The two sides were one outcome recording no token until #483 split them. There is no synthetic-response form: gRPC-Web requests classify as gRPC (`src/proxy/mod.rs:36574`), and synthetic gRPC bodies are governed only in the native serverless terminate representation (`:26976`), which renders as gRPC rather than an HTTP 503.

### New: `body_validator` `enforcement_mode: log_only`

v0.9.19 (#6845). In `log_only` mode every violation and capacity refusal is recorded under `body_validator.{request,response}_{outcome,status,detail}`, and the exchange continues (`src/plugins/body_validator.rs:470`, `:808`, keys `:271`-`:276`).

**Catalog impact:** new no-signal outcome `plugin.body_validator.log_only_no_signal`.

### New: `openapi_validator` request parameter validation (400)

v0.9.19 (#6837). Declared path, query, header and cookie parameters are validated in `before_proxy`, before any request transformer. Header and cookie values are read from the pristine wire headers. A missing required parameter, a repeated scalar, an unconvertible value, a schema failure, malformed cookie percent-encoding, or more than 1024 pairs gets the configured request status (default 400, `src/plugins/openapi_validator.rs:962`). The response is problem+json titled `Request parameter validation failed` (`:193`, `:1649`, `:2392`, `:2534`).

**Catalog impact:** new outcome `plugin.openapi_validator.request_parameter_violation`. The title is its only discriminator from body violations. The catalog records the default 400, so its diagnosis says "default configuration" and `match_signal` misses a non-default `request_status_code`.

### New: `openapi_validator` Content-Encoding decode capacity (503)

v0.9.19 (#6837, #6848). Content-Encoding is now undone through the strict, budget-charged decoder (`src/plugins/openapi_validator.rs:3568`), and zstd is accepted. A budget refusal returns the shared `503` capacity body with `content-type: application/json` instead of a problem+json violation (`:1533`, `:1459`, `:1962`).

**Catalog impact:** new outcomes `plugin.openapi_validator.decode_capacity` (request side, no token), `plugin.openapi_validator.response_decode_capacity` (response side, `backend_error` from the final builder as for `body_validator`; split in #483), and `plugin.openapi_validator.synthetic_response_decode_capacity`: openapi_validator also validates governed synthetic (plugin short-circuit) responses (`src/proxy/mod.rs:26781`, `:27753`), whose capacity refusal is finalized on the reject path (`:26698`, `:32441`) without `X-Gateway-Error`. Core budget refusals of a synthetic response send the same token-less bytes with no OpenAPI involvement (for example `ai_response_guard` in redact mode whose scratch window cannot open, `src/plugins/ai_response_guard.rs:5136`, installed through `src/proxy/mod.rs:27493`, `:27348` and `:30024`), so the new core outcome `gateway.capacity.synthetic_response_buffer` is listed first and is the ambiguous finding's capacity-only common conclusion: it names no plugin, decompression or backend handoff. The two link each other; `gateway.capacity.response_buffer` covers only the backend-response form (`backend_error`). Notes are appended to `.request_decode_or_conversion_failure`, which is repointed to `CONTENT_ENCODING_DETAIL` `:3513`, and to `.response_decode_failure`.

### `openapi_validator` asserts `format` under every draft

v0.9.19 (#6837). `should_validate_formats(true)` (`src/plugins/openapi_validator.rs:2941`) makes `uuid`, `date-time`, `email` and the other formats assertions, including for Draft 2020-12 / OpenAPI 3.1 imports. Traffic with malformed formatted strings that used to pass now gets the schema-violation 400 (or 502 on responses). The conversion fixes in the same PR add new refusals: a multipart Encoding `contentType` is enforced on serialized parts, XML array items must match `xml.name`, and XML strings are validated untrimmed.

**Catalog impact:** notes are appended to `.request_schema_violation` and `.request_decode_or_conversion_failure`. The signals are unchanged.

### `openapi_validator` releases declared event streams

v0.9.19 (#6837). A `text/event-stream` that the status-selected response object declares is released unvalidated, with `skip_reason=event_stream_declared` (`src/plugins/openapi_validator.rs:1825`, `:1880`). Only undeclared streams still get the `502`.

**Catalog impact:** the condition of `plugin.openapi_validator.response_event_stream` changes.

### `openapi_validator` `bypass.header_present` requires a secret

v0.9.19 (#6634, BREAKING). Each entry maps a header name to a secret of 16-4096 visible ASCII characters, compared in constant time (`src/plugins/openapi_validator.rs:1154`, `:211`). Presence-only entries are refused at load, so a client can no longer skip validation by sending only a header name.

**Catalog impact:** the condition of `plugin.openapi_validator.log_only_no_signal` changes.

### Admission caps and stricter `openapi_validator` admission

v0.9.19 (#6638, #6837). Two size knobs are capped at admission:

- `openapi_validator.max_body_bytes` at 64 MiB (`src/plugins/openapi_validator.rs:68`, `:829`).
- `body_validator.grpc_max_decompressed_size_bytes` at 64 MiB (`src/plugins/body_validator.rs:1524`).

`openapi_validator` admission also refuses empty content-type lists, duplicate method+`path_regex` operations, and `global` / `proxy_group` instances. Overlapping templates are now ordered by literal segments.

**Catalog impact:** notes only, on `.request_body_too_large` and `.unknown_operation`.

### `graphql` unchanged; Redis quota charges are cancellation-safe

`graphql.rs` only gains `commit_background_tasks` (#6616/#6967) and a `BEFORE_PROXY` lifecycle declaration (#6975). The final-body hook is not gated by `PluginHooks`. All graphql signals were re-read at v0.9.20 and are unchanged. In Redis mode the quota charge now runs on its own task (#6814, `src/plugins/utils/rate_limit.rs:2436`), so a cancelled request no longer strands an over-limit charge.

**Catalog impact:** a note is appended to `plugin.graphql.rate_limited`.

### Lab: `lint-profiles.rb` openapi_validator key lists

GW-015's `openapi_validator` config is still accepted, and its assertions still hold on v0.9.20: `Invalid JSON` detail, `minimum` keyword, unknown-operation 400, problem+json, and rejection phase `validate_client_request_contract`. `lab/gateway/lint-profiles.rb` cites `openapi_validator.rs:144-158` and `:159-167`; at v0.9.20 those are `:158-172` (CONFIG_KEYS) and `:173-182` (OPERATION_KEYS). OPERATION_KEYS now includes `parameters` (#6837).

**Lab impact:** update the cites and add `parameters` to the lint list.

### `rate_limiting` quota 429 now carries `Retry-After` (#6814, v0.9.19)

`RateLimiting::reject` inserts `retry-after` on every quota refusal, whether or not `expose_headers` is set
(`src/plugins/rate_limiting.rs:812`, header constant `:46`). The value is whole seconds and at least 1: exact for the
local token bucket and sliding aggregate (`src/plugins/utils/rate_limit.rs:2405`). In Redis mode it is a conservative
bound of at most 19/16 of the window (`src/plugins/utils/rate_limit.rs:2493`, `:2916`). When several windows refuse,
it is the longest wait. The local-capacity 429 (`src/plugins/rate_limiting.rs:931`) and the MCP JSON-RPC refusals carry
no `Retry-After`.

Catalog: `plugin.rate_limiting.exceeded` gains `Retry-After` in `other_headers`. Its note "no Retry-After header is ever
set" is now false. `Retry-After` now separates the quota 429 from the capacity 429, which has the same body.

### `rate_limiting` gains `limit_by: service` and `max_state_entries` (#6814, v0.9.19)

`limit_by: service` (`src/plugins/rate_limiting.rs:1703`, key `:734`) charges one aggregate budget per policy in
`authorize`, and once per connection or session on TCP/UDP. The hard-coded 100,000-key cap is now `max_state_entries`
(default `src/plugins/rate_limiting.rs:32`, parser `:1717`, range 1 to 10,000,000). The flagged citation
`rate_limiting.rs:29` is repointed to `:32`. Successful WebSocket handshake responses now carry `x-ratelimit-*` under
`expose_headers` (`src/plugins/rate_limiting.rs:1454`). Ties between equal budgets are broken by limit, window and
policy id (#6331).

Catalog: condition updates on `exceeded`, `local_state_capacity`, `stream_refused` and `admitted_decoration`. The wire
signal is otherwise unchanged.

### New: `rate_limiting` `mcp_tool_calls` refuses uninspectable MCP bodies with -32600 (#6814, v0.9.19)

An in-scope MCP POST is refused with HTTP 200
`{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"Invalid MCP JSON-RPC request"}}`
(`src/plugins/rate_limiting.rs:1609`, `:1616`) when any of these holds:
- its `Content-Type` names a charset other than UTF-8 (`:1130`)
- the body could carry `tools/call` but is not strict JSON (`:1067`)
- the recognizer cannot decide (`:1072`)
- no body snapshot exists (`:1155`)

Only the ambiguous arm existed in v0.9.15, and it was not catalogued. The charset check runs before the
`Content-Encoding` check, so a request that has both now gets -32600 instead of -32017.

Catalog: new outcome `plugin.rate_limiting.mcp_uninspectable_body`. Its body is byte-identical to
`plugin.mcp_gateway.invalid_request`. The `mcp_uninspectable_encoding` condition gains the precedence note.

### Redis limiters read counters with `GETRANGE` (#6681, issue #6653, v0.9.19)

Request-quota charges now read counters with `GETRANGE key 0 20` (`src/plugins/utils/redis_rate_limiter.rs:6329`,
`:2737`). An unreadable counter marks the endpoint unavailable (`:6378`). A Redis ACL without `GETRANGE` on the key
prefix, or a counter longer than 20 bytes or not an integer, now trips `redis_failure_policy`:
- under `fail_closed`: 503, grpc-status 14, or MCP -32016
- under the `rate_limiting` default `local_fallback`: per-process budgets

Charges also run on a task of their own, so a cancelled request no longer strands an over-limit `INCR` (#6814).

Catalog: condition append on `plugin.rate_limiting.enforcement_unavailable` and
`plugin.grpc_method_router.enforcement_unavailable`, and a note on `mcp_tool_calls_unavailable`.

### BREAKING: `request_size_limiting` returns the shared 413 body (#6875, v0.9.19)

The plugin's 413 is now `{"error":"Request body exceeds maximum size"}` (`src/plugins/request_size_limiting.rs:216`,
`src/util/body_limit.rs:30`), byte-identical to the proxy-core streaming overflow and global-ceiling 413
(`src/proxy/mod.rs:4645`). The H3 bridge returns the same body. The `limit` field is gone from this 413 and from the
ambiguous-`Content-Length` 400 (`src/plugins/request_size_limiting.rs:55`). Limit, observed size, reason and
plugin-config id go to `request_size_limiting.*` metadata, which only the operator sees.

Flagged emitters are repointed: `:130` to `:286`, `:169` to `:323`, `:192` to `:339` (the context variant is at
`:363`). The `size_limit.rs:138 rejection_body` citation is no longer this plugin's body and is replaced by
`body_limit.rs:30`.

Since #6875 and #6939, HTTP/2 GET, HEAD and OPTIONS uploads without a `Content-Length` are forwarded to HTTP/1.1
backends. Before, such a body was silently emptied. Now an over-limit upload gets this 413.

Catalog: `too_large` changes `body_shape` and becomes `public_coarse`, sharing its signal with
`plugin.request_size_limiting.streaming_overflow_core` and the global ceiling 413. `content_length_ambiguous` changes
`body_shape`. Diagnoses must be version-gated, because v0.9.15 and earlier still send `limit`.

### Strict `response_size_limiting` changes which event streams it refuses (#6880, v0.9.19)

With `require_buffered_check: true`, behaviour changes in two directions:
- **Now admitted:** an event stream whose backend sent one exact in-limit `Content-Length`, when no streaming response
  inspector can rewrite it (`src/plugins/response_size_limiting.rs:107`).
- **Now refused (BREAKING):** the `mcp_gateway` aggregate SSE listener. The core refuses it before commit with the same
  502 `Streaming response size cannot be verified` body (`src/proxy/mod.rs:26911`, `:26948`). Before, it streamed
  unbounded.

The flagged `:226` is repointed to `:307`. Separately, byte-changing stream rewrites are now charged against the
ceiling and end the committed stream with a `ResponseBodyTooLarge` abort or reset. That extends
`streaming.response_size_exceeded_mid_stream`, which is outside D_policy.

Catalog: condition and source update on `plugin.response_size_limiting.stream_unverifiable`. `too_large` and
`content_length_ambiguous` are unchanged.

### `ws_message_size_limiting`: limits per direction and close reason under deflate (#6881, v0.9.19)

Optional `client_to_backend` and `backend_to_client` objects override `max_frame_bytes`, `max_message_bytes` and
`close_reason` per direction (`src/plugins/ws_message_size_limiting.rs:114`). The default `max_message_bytes` is 4×
that direction's frame limit (`:189`). The default reason is unchanged (`:51`).

Under `websocket_permessage_deflate: terminate`, an overflow of a plugin ceiling now closes 1009 with the plugin's
`close_reason` (`src/proxy/mod.rs:20850`). Before, the adapter's fixed reasons were used, such as
`decompressed message too large` (`src/proxy/ws_permessage_deflate.rs:652`). Flagged citations are repointed:
`proxy/mod.rs:19661` to `:20809`. The global-capacity prose citation is repointed to `:20914`; the mechanical remap had
put it on an unrelated line.

Catalog: condition, sources and note on `plugin.ws_message_size_limiting.too_large`.

### `ws_rate_limiting` gains aggregate `limit_by` (#6867, v0.9.19)

The new values are `connection` (the default), `consumer`, `ip` and `service` (`src/plugins/ws_rate_limiting.rs:100`,
scope `:398`). Each sets up a budget shared by sessions and is bound at the upgrade.

Other changes:
- Local mode accepts any `frames_per_second` and `burst_size` pair from 1 to 1,000,000; the extra checks now apply only
  with Redis (`:199`).
- Idle entries are reclaimed at the 50,000-key cap.
- Connection budgets are released on disconnect.

The close is still 1008 with the configured reason (`:494`, default `:203`).

Catalog: condition only.

### `tcp_connection_throttle` and `udp_rate_limiting`: `ipv6_prefix`, `direction`, attachment and reload (#6877, #6868, v0.9.19)

**`tcp_connection_throttle`:** the IPv6 grouping is configurable (`src/plugins/tcp_connection_throttle.rs:252`,
default /64 at `:30`). The prose citation `:219` is repointed to `:250`.

**`udp_rate_limiting`** gains:
- `ipv6_prefix` (`src/plugins/udp_rate_limiting.rs:613`, default `:60`)
- `direction` (`:607`); a one-direction policy neither counts nor drops traffic the other way

Two more `udp_rate_limiting` changes are BREAKING:
- A proxy- or group-scoped `udp_rate_limiting` on a non-UDP proxy is refused at config admission
  (`src/plugin_cache.rs:2793`).
- A reload that changes the datagram hooks ends established UDP/DTLS sessions.

Wire signals are unchanged.

Catalog: condition and notes only.

### `grpc_method_router`: service-level and default rules; gRPC-intended routes refuse plain HTTP (#6861 v0.9.19, #6125 v0.9.17)

Allow, deny and rate rules accept `package.Service/*` (`src/plugins/grpc_method_router.rs:696`). A new
`default_rate_limit` (`:284`) covers methods with no other rule. Exactly one rule is charged: exact first, then
service-level, then default (`:539`). Service-level and default budgets are pooled per caller. The flagged `rate_key`
citation is repointed from `:468` to `:563`, and it now keys by rule. Status, messages and `x-grpc-ratelimit-*` names
are unchanged; `-limit` is the matched rule's `max_requests`.

Since v0.9.17 (#6125, issue #6110), a route-scoped `grpc_method_router` marks the route gRPC-intended
(`gates_request_admission`, `src/plugins/grpc_method_router.rs:843`; `src/plugin_cache.rs:6259`). Plain HTTP and
WebSocket requests on that route are refused with 403 `{"error":"Request protocol not permitted on this route"}`.

Catalog: condition updates on `method_not_permitted` and `method_rate_limited`. Extend
`gateway.routing.protocol_not_permitted` (A_core) to cover this direction.

### Lab impact

- `crates/anvil-lab/src/policy.rs` `ext_rate_limit`: on v0.9.20 the gateway 429 carries `retry-after`, but the
  application lookalike (policy.rs:592) does not. The check compares finding codes only, so it should still pass. For
  v0.9.19 and later, mirror the observed `retry-after` in the lookalike and assert that the gateway sends it.
- GW-008 (`core.yaml` `gw008-limit`): the 413 body loses `limit`. The scenario checks only the status and
  `http.payload_too_large`, so it passes. Expect the body shared with the core ceiling when re-binding fixtures.
- `lint-profiles.rb`: every key the lab uses is still accepted. The new optional keys are refused by older supported
  releases, so profiles must not use them yet.

### `request_deduplication`: in-flight capacity 503 and logical keys v7 (#6818, v0.9.19)

New `max_inflight_entries` (default `max_entries`, `src/plugins/request_deduplication.rs:1290`) caps live local in-flight markers. A new key past the cap gets `503 {"error":"Idempotency in-flight capacity is saturated"}` (`src/plugins/request_deduplication.rs:4373`, body `:185`). Tracked keys still replay or conflict, and Redis ownership taken for the refused request is released. Logical keys move from `v6` to `v7` (`:160`), so a key first used before the upgrade is not found and its retry executes once more.

Catalog: new `plugin.request_deduplication.inflight_capacity`. Note on `replay`. Distinguishability note on `execution_barrier_capacity`.

(Tag ancestry puts these commits in v0.9.18, which was tagged but never published. The CHANGELOG lists them under 0.9.19, and this section uses 0.9.19 throughout. Likewise, v0.9.16 commits are listed as 0.9.17.)

### `request_deduplication`: case-variant header 400s (#6818, v0.9.19)

There are two new 400 responses, both deterministic:
- `{"error":"Conflicting values for the idempotency header"}` (`src/plugins/request_deduplication.rs:4107`). This applies even when `enforce_required` is false.
- `{"error":"Request carries conflicting case-variant header fields"}` for `:authority`, `host`, `content-encoding`, `content-length` and `transfer-encoding` (`:1821`).

Wire header names are lowercased, so either response needs an earlier plugin that inserted a header under different casing (`:3520-3521`).

Catalog: new `plugin.request_deduplication.ambiguous_idempotency_header` and `plugin.request_deduplication.ambiguous_fingerprint_header`.

### `request_deduplication`: route response-header policy moves from the key to the fingerprint (#6818, v0.9.19)

The logical key now uses `append_execution_destination_partition` (`src/plugins/request_deduplication.rs:1732`). That function hashes `dst.response_transform_scope` (`src/plugins/utils/replay_partition.rs:794`) and does not hash the transform list. The fingerprint binds the full destination, including the list (`request_deduplication.rs:1859`, binding at `replay_partition.rs:775-791`). Before this change, a reload that touched only a `mesh_route_dispatch` `response_transform` gave the retry a fresh key, so the request ran again. Now the retry gets `409 Idempotency key was reused for a different request`. The v0.9.7 prose on `replay` is wrong for dedup from this release on.

Catalog: repoint the prose citation `replay_partition.rs:655-670` to `:775-791` on both `request_deduplication.replay` and `response_caching.hit`. Update the condition on `fingerprint_mismatch`.

### `request_deduplication`: `caller_partition: authenticated_identity` and rename chains (#6818, #6914, v0.9.19)

This is an opt-in setting (`src/plugins/request_deduplication.rs:1305-1307`). When the gateway has verified a principal (`src/plugins/utils/replay_partition.rs:583`), the key binds that principal. Credential headers and the signature-context headers bind only their presence. As a result, a retry after a token refresh, a re-signature or an address change replays where it used to execute again. With #6914, values renamed onto credential names stay value-bound, and so does every value of a repeated credential query name (`request_deduplication.rs:3589`). A changed business value is therefore `409`, not a replay.

Catalog: condition updates on `replay` and `fingerprint_mismatch`.

### `request_deduplication`: bounded Redis reads and Redis ACLs (#6649, issue #6622, v0.9.19)

Records are now read with `EXISTS`/`STRLEN`/`GETRANGE`, capped at `max_entry_size_bytes` + 4 KiB (`src/plugins/request_deduplication.rs:2191`, cap `:2169`). An empty or oversized record is classed as `Unreadable` (`:2197`) and returns `409 A request with this idempotency key is already in progress` (`:2300`). A Redis ACL that does not allow the new commands makes every keyed request `503 Idempotency coordination store is unavailable` under `fail_closed`. Malformed `WATCH`/`MULTI`/`SET` replies now fail closed too. A completed record over the cap is published as the non-replayable tombstone, which peers answer with a 409.

Catalog: condition updates on `in_progress` and `redis_unavailable`. Note on `non_replayable_completion`.

### `request_deduplication`: replay waits for the Redis publication verdict (#6336, v0.9.19)

In Redis mode, a local completion cannot be replayed until its fenced publication settles (`src/plugins/request_deduplication.rs:1945`, `:2067`). A matching retry inside that window gets `409 in progress` instead of the stored response.

Catalog: condition on `in_progress`. Note on `replay`.

### `request_deduplication`: HTTP/3 pre-wire failures release the lease (#7002, v0.9.20)

Previously, the HTTP/3 to H1/H2 bridge did not run the `response_committed` plugins after a backend failure that was proven to happen before the request reached the wire (502 or 504). The idempotency lease stayed until `inflight_ttl_seconds`, so an immediate retry got `409 in progress`. The bridge now releases the lease, matching HTTP/1.1 and HTTP/2 (`CHANGELOG.md:141`; the code is in `src/proxy`).

Catalog: note on `in_progress`.

### Replay partitions ignore `rate_limiting` `expose_headers` telemetry (#6999, v0.9.20)

`x-ratelimit-*` request values that the owning limiter staged are now left out of the `response_caching` key (`src/plugins/utils/replay_partition.rs:966`) and the dedup fingerprint (`src/plugins/request_deduplication.rs:3708`). Before this, every repeat request behind `expose_headers: true` was a cache `MISS`, and every identical idempotent retry got `409 Idempotency key was reused for a different request`. Now these requests can HIT or replay.

Catalog: notes on `response_caching.hit`, `response_caching.miss_marker`, `request_deduplication.replay` and `request_deduplication.fingerprint_mismatch`.

### `response_caching`: freshness, key binding, sanitation, 401/407 (#6830, v0.9.19)

Changes when `respect_no_cache` is true:
- The cache now honors request `max-age` and `min-fresh` (`src/plugins/response_caching.rs:3826`). An entry the client would not accept is not served: the response is `x-cache-status: MISS` and goes to the origin (`:3886`).
- A conditional request with `max-age=0` no longer gets the gateway's 304.

Other changes:
- The key binds the frontend scheme (`:3258`) and the matched proxy's `backend_path`, `strip_listen_path` and `preserve_host_header` (`:3262-3264`).
- Retained headers pass through the shared replay sanitizer (`:402`). A HIT no longer replays trace or correlation ids, `Retry-After`, `Set-Cookie2` or `WWW-Authenticate`.
- `401` and `407` are refused in `cacheable_status_codes` at config admission, and also at store time (`:347`).

Catalog: condition and notes on `hit`, `revalidated_304` and `miss_marker`.

### `response_caching`: `BYPASS` on a no-cache refresh now carries `Vary` (#6830, v0.9.19)

An honored request `Cache-Control: no-cache` refresh (`src/plugins/response_caching.rs:3764`) now publishes the same downstream `Vary` contract as a MISS (`:3917`). Other `BYPASS` reasons and `PREDICTED-BYPASS` responses get no `Vary`.

Catalog: `bypass_marker.public_signal.other_headers` gains a conditional `vary`.

### `response_caching`: config-only changes (#6830, #6913, #6638, v0.9.19)

`ignore_request_headers` is new. The named headers are stripped before the key is built and never reach the origin (`src/plugins/response_caching.rs:3646`). It refuses credential, hop-by-hop, forwarding and `Vary` names, including their underscore spellings. A non-empty list makes the instance a request-header mutator, so it cannot share a proxy with `request_deduplication`. `max_entries` is now capped at 10,000,000.

Catalog: none.

### `serverless_function`: Lambda service errors, default-chain credentials, bounds (#6843, v0.9.19)

A non-2xx AWS Lambda Invoke API status is now `502 {"error":"serverless function invocation failed","code":"lambda_service_error"}` in every mode (`src/plugins/serverless_function.rs:1384`). Before this, terminate mode passed the AWS error body (ARNs, account ids) to the client. Native gRPC terminate refused it as `invalid_grpc_terminate_status`, and that refusal was mandatory. The new code is not a function-output failure, so with `on_error: continue` a native gRPC terminate request now goes on to the backend (`:4308`).

`aws_credentials: default_chain` adds the code `aws_credentials_unavailable` (`:1306`). This is a pre-wire failure, so the dedup lease is released. `timeout_ms` is now limited to 1-900000 and `max_response_body_bytes` to at most 64 MiB, checked at admission.

Catalog: condition updates on `invocation_failure`, `terminate_passthrough`, `pre_proxy_invalid_response` and `grpc_terminate_contract_failure`.

### `serverless_function`: API Gateway v2 payload format (#6843, v0.9.19)

With `payload_format: aws_api_gateway_v2` (terminate mode), the gateway maps the proxy-integration result to the client response: `statusCode` 200-599, `headers`, `multiValueHeaders`, `cookies`, `body` and `isBase64Encoded` (`src/plugins/serverless_function.rs:2369`). A malformed result is `502 ... "code":"invalid_api_gateway_response"` (`:2267`). A native gRPC terminate request with this format is refused before invocation with `unsupported_grpc_payload_format` (`:4258`, must_reject).

Catalog: new `plugin.serverless_function.api_gateway_response_invalid`. Condition updates on `governed_input_rejected` and `terminate_passthrough`.

### `serverless_function`: unencoded `;` in the query is ambiguous (#6595, issue #6579, v0.9.19)

With `forward_query_params`, an unencoded `;` in the query is now `502 ... "code":"ambiguous_query_encoding"` (`src/plugins/serverless_function.rs:2010-2012`, must_reject). An encoded `%3B` is still accepted. The `request_body_unavailable` refusal moved into `forwarded_body` (`:2068`).

Catalog: repoint `governed_input_rejected` source 0 from `:909` to `:2068`, and update its condition.

### `serverless_function`: endpoint admission (#6118, v0.9.17; #6659, v0.9.19)

Process-environment and default-chain AWS credentials are now refused at construction for non-official Lambda endpoints (`src/plugins/serverless_function.rs:1004-1005`). An `http://` `function_url` or `aws_endpoint_url` whose host is not a loopback IP literal now needs `allow_plaintext: true`; `localhost` counts as non-loopback here (`:1884`). There is also a runtime re-check that returns a fixed `500 ... "code":"ambient_credential_endpoint_refused"` (`:4222`). Construction already refuses the same URL and scope, so the re-check looks unreachable.

Catalog: none (open question).

### Lab

None of the lab profiles (`lab/gateway/*`) or `crates/anvil-lab/src/*` configure `request_deduplication`, `response_caching` or `serverless_function`, so this group has no lab impact.

### New: query-reading plugin triggers refuse a raw `;` in the query

When any instance on a request's chain has an execution trigger whose predicate reads `query`,
a request whose raw query contains an unencoded `;` is refused before any plugin phase runs
(`query_trigger_refuses_request`, `src/proxy/mod.rs:314`; H1/H2 at `src/proxy/mod.rs:36778`,
H3 at `src/http3/server.rs:4446`). The answer is `400`
`{"error":"ambiguous query parameters","reason":"semicolon_separator"}`
(`src/proxy/mod.rs:299`); native gRPC gets Trailers-Only `INVALID_ARGUMENT`, gRPC-Web a framed
trailer status. `%3B` is accepted. The refusal is logged with `rejection_phase:
query_trigger_admission`. Introduced by #6690 (issue #6655), tagged v0.9.18 and published in
v0.9.19. Catalog: new `plugin.trigger.query_semicolon_refused`; `plugin.trigger.skip_semantics`
notes point to it. The body differs from `mesh_route_dispatch`'s 400 for the same ambiguity
(`src/plugins/mesh_route_dispatch.rs:2784`).

### `opa` denies before calling the policy, and deny responses can be policy-defined

The `403 {"error":"forbidden by policy"}` default is unchanged (`src/plugins/opa.rs:45-46`,
`reject_policy_denial` at `:914`), but it now also fires without any OPA call:

- a repeated non-list request header, with the default `include_headers: true` and
  `header_ambiguity_policy: reject` (`:1004`; #6860);
- any unencoded `;` in the query, now a query ambiguity under the default
  `query_ambiguity_policy: reject` (`:985`; #6595);
- an allow or deny decision whose obligations cannot be honoured (`invalid_obligation`, `:834`).

With the opt-in `decision_deny_response`, a deny decision chooses its own status (400-599), body
and headers (`deny_response_obligation`, `:880`), so the deny signal becomes policy-defined. The
fail-closed `503 {"error":"authorization service unavailable"}` (`:47-48`, `:922`) gains two
triggers: a saturated `max_concurrent_decisions` bulkhead (`:1020`) and a
`decision_request_headers` destination that is an active credential location, which fails closed
whatever `fail_open` says (`:967`; #6926). An `http://` `opa_host` other than a `127.x`/`[::1]`
literal now needs `allow_plaintext: true` (`:1304`; #6659). All released in v0.9.19. Catalog:
both OPA outcomes get wider conditions; a `403 forbidden by policy` no longer proves OPA was
consulted. The carried constant citations were off by one at v0.9.15 (`:34/:35` for constants at
`:35/:36`) and the mechanical remap kept the error; they are repointed to `:45-48`.

### `access_control` external identity rules

#6873 (v0.9.19) adds `allowed_external_identities` / `disallowed_external_identities`
(`{identity, mechanism?}`). External identities are now judged in `authorize_external_identity`
(`src/plugins/access_control.rs:327`). The bodies are unchanged:

- `Authenticated identity is not authorized` (`:340`) now requires no external allow-list as well
  as `allow_authenticated_identity=false`;
- `Identity is not allowed` covers too-long identities (`:353`), deny matches (`:373`, where a
  mechanism-scoped deny also matches an unknown realm) and the new external allow-list miss
  (`:395`).

An external allow-list counts as an allow-list (`:163-165`). Configuring only
`allowed_external_identities` therefore denies every mapped Consumer with `Consumer is not
allowed` (`:307`). Since #6635 (issue #6607), an explicitly empty allow-list array is refused at
load (`:447`).
Catalog: conditions and sources updated on `identity_not_allowed`,
`external_identity_not_authorized` and `consumer_not_allowed`.

### `ip_restriction` and `geo_restriction`: refactor, same bodies

`ip_restriction` builds all three 403s in `Rejection::into_result`
(`src/plugins/ip_restriction.rs:80`, `:89`, `:98`, `:101`) and stamps `ip_restriction.reason`
metadata. Rule spellings are canonical-only, so `/08`, `/+8` and `fe80::1%` fail config load
(`parse_rule`, `:387`; #6872). `mode` is deprecated and decision-neutral (#6635).
`geo_restriction` returns a `GeoVerdict` with the same four reject sites (`:381`, `:421`, `:445`,
`:465`; #6882). It now decodes `registered_country` only when a record has no direct country
(`:342`), so a valid country with a malformed `registered_country` no longer yields
`location_undetermined`. Catalog: repoints plus notes. Signals are unchanged.

### `cors`: Private Network Access, bounded lists, public-suffix interlock

Opt-in `allow_private_network` adds `access-control-allow-private-network: true` to approved
preflights that ask for it (`src/plugins/cors.rs:1822`). Method, header and expose lists are
capped at 128 entries of 256 bytes (`:119`). Composed policies keep an explicit
`exposed_headers` list when another policy uses an uncredentialed `*` (`:707`). All three are
#6844. Credentialed public-suffix wildcards and non-pinning regexes are refused at load (#6639),
and the PSL ancestor index in `src/plugins/cors_psl_ancestors.rs` was refreshed (#6954). All
released in v0.9.19. The reject bodies and vary sets are unchanged. Catalog: `preflight_approved`
gains the optional header; `response_decoration` gets a note.

### `correlation_id` on route misses and `inbound_policy`

A global `correlation_id` now also decorates unmatched-route `404`s on H1/H2/H3
(`collect_unrouted_correlation_plugins`, `src/plugin_cache.rs:6305`; #6938).
`inbound_policy: generate` always mints a fresh UUID (`src/plugins/correlation_id.rs:147`), and
`header_name` refuses `x-geo-country` and `x-real-ip` (`:67`; #6876). Both are v0.9.19. Catalog:
the `request_id` condition is updated. A replaced ID no longer implies an invalid client value
when `generate` is set.

### `security_headers` hardening

Defaults are unchanged. Since v0.9.19 the plugin also decorates the H1/H2 authorization-expiry
`401`, and with `override_existing: false` it replaces backend values browsers ignore (#6864).
Config admission refuses gateway-owned or representation headers, malformed HSTS, more than 64
`set`/`remove` entries and values over 8192 bytes (`src/plugins/security_headers.rs:24-30`), and
non-`DENY`/`SAMEORIGIN` frame options (`:632`; #6685). Backend STS/nosniff case variants
collapse (#6929). Catalog: notes only.

### Custom plugins and chain order

The producer refusal moved (`src/proxy/mod.rs:31592`, `src/plugins/mod.rs:8895`) and now also
fires when a plugin declared as a non-producer returns a replacement body (`:31693`; #6339,
v0.9.19). The catalog's `grpc_status: 14` on
`plugin.custom.undeclared_response_body_producer` was wrong at v0.9.15 too: the refusal uses
`RESOURCE_EXHAUSTED` (`src/proxy/response_buffer_budget.rs:474`), so it is corrected to `8`.
Equal-priority plugins now run in a fixed order: priority, name, scope, then plugin-config id
(`plugin_chain_order`, `src/plugin_cache.rs:5187`; #6641, v0.9.19). Since v0.9.20, built-ins
skip lifecycle hooks they do not declare (#6975); every G5 plugin's declaration matches the
hooks it implements. In v0.9.20, custom plugins must export `config_contract()`, and nested
unknown config keys are rejected (#6967). The `PluginResult`, `PluginFailurePolicy` and
reject-normalization functions are unchanged. No built-in plugin was added or removed (the
`BUILTIN_PLUGIN_REGISTRATIONS` name set is identical).

### No-signal plugins stay silent

`request_transformer`, `response_transformer`, `transaction_debugger`, `proxy_alerts`,
`api_chargeback` and `request_mirror` still contain no `PluginResult::Reject`, and
`request_mirror::authorize` only returns `Continue` (`src/plugins/request_mirror.rs:3022`). Their
outcomes carry unchanged.

### Lab

No G5 plugin config in `lab/gateway/{policy,auth,core,admission,streams,drain,proxyproto}*` is
refused at v0.9.20:

- OPA `opa_host: http://127.0.0.1:*` is exempt from the cleartext opt-in, and
  `policy_path: anvil/lab/*` passes the Data-API-prefix check.
- `ip_restriction` `mode: allow_first` still loads.
- The `access_control` allow-lists are non-empty.
- The `response_transformer` rules are unchanged.

GW-012/GW-013 must not send repeated non-list headers or a raw `;` in the query. If they did, OPA
would never be asked and GW-012's ground truth would fail. In `lab/gateway/lint-profiles.rb`,
the key tables are subsets of the v0.9.20 sets; only the line-reference comments need a refresh.

### response_mock: the 101 outcome is gone, and a 2xx rule on a WebSocket handshake now gets a different 500 (#6869, v0.9.19)

`status_code: 101` (and every 1xx) is now refused when the plugin is built (`src/plugins/response_mock.rs:735`). The `before_proxy` branch that answered 500 `{"error":"response_mock status 101 requires a WebSocket handshake"}` no longer exists. Instead, a matching rule with a 2xx status on a WebSocket handshake (HTTP/1.1 Upgrade, or HTTP/2 or HTTP/3 Extended CONNECT) gets 500 `{"error":"response_mock cannot mock a successful WebSocket handshake; configure a non-2xx status_code"}` (`src/plugins/response_mock.rs:830`, body `:207`). Before, an HTTP/2 Extended CONNECT 2xx with a body was reset.

Other changes:
- Rules gain `match.headers` and `match.query_params` conditions, 1 to 16 of each (`src/plugins/response_mock.rs:553`). A rule whose conditions fail falls through to the next rule, so it can now end in the 404 no-match (`:818`).
- The `delay_ms` maximum drops from 3600000 to 60000. The delay now runs under the shared fault-delay budget (`:856`). When the budget is exhausted or the gateway is shutting down, the mock is served at once.
- A client that disconnects during the delay gets 499 (`:838`).
- Configs are capped at 1024 rules, 262144-byte bodies, 64 headers per rule and 8192-byte header values.

Catalog impact:
- Remove `plugin.response_mock.status_101_non_websocket`.
- New `plugin.response_mock.websocket_success_refused` and `plugin.response_mock.delay_client_gone` (499, low visibility).
- `matched_rule` and `no_match`: update the conditions and repoint to `:844` and `:818`.

### load_testing: fan-out acknowledgements carry a run id, with new 403 and 503 refusals (#6856, #6384, v0.9.19)

- **Ack header.** The peer's 204 ack now carries `X-Loadtesting-Ack: <run id>` (`src/plugins/load_testing.rs:1747`, header `:145`). The controller counts a peer only on a 204 with a matching ack, so a peer on an older build (bare 204) is reported as not acknowledged.
- **Wrong key.** A request that carries `X-Loadtesting-Fanout` but whose key does not authenticate is now refused with an empty 403 (`:1163`, `:1755`). Before, it was forwarded as an application request.
- **Budget refusal.** An authenticated fan-out refused by the process client or body budget answers an empty 503 (`:742`, `:1763`).
- **Large declared bodies.** A trigger that declares a `Content-Length` above 10 MiB is now forwarded without starting a run, instead of 413 (`:1108`). An undeclared-length body above 10 MiB still gets 413.
- **Plaintext fan-out.** `http://` `gateway_addresses` off a loopback IP literal now need `allow_plaintext: true`.

Catalog impact:
- New `plugin.load_testing.fanout_auth_refused` and `plugin.load_testing.fanout_resource_refused`.
- `fanout_ack`: gains the `x-loadtesting-ack` header and a repoint (old `:1466` to `:1747`).

### fault_injection: header-scoped and expiring experiments, single UDP first roll, and 499 maps to CANCELLED (#6855 v0.9.19, #6146 v0.9.17)

- **Header scope.** Optional `match.headers` (`src/plugins/fault_injection.rs:372`) limits HTTP faults to traffic marked with those headers. Unmatched requests never consume a roll. A header-targeted instance never faults TCP, UDP or DTLS traffic (`:536`).
- **Expiry.** Optional `expires_at` (`:424`, `:520`) turns every hook into a no-op from that instant.
- **UDP first datagram.** A new UDP or DTLS client's first datagram is no longer rolled twice (the effective rate used to be 1-(1-p)^2). The connect hook now owns that decision (`:756`).
- **499 on gRPC.** Since v0.9.17 `http_reject_status_to_grpc_status` maps 499 to grpc-status 1 CANCELLED instead of 13 (`src/proxy/grpc_proxy.rs:3132`).

Catalog impact:
- `delay_client_gone`: grpc_status changes from 13 to 1.
- `abort_grpc`: the mapping note gains 499 -> 1.
- `abort_http`, `delay` and `stream_abort`: conditions updated.

### sse becomes route admission policy (#6831, v0.9.19)

While `require_get_method` or `require_accept_header` is on (the default), `sse` declares `gates_request_admission` (`src/plugins/sse.rs:764`). Native gRPC requests and WebSocket upgrades on the route are therefore refused with 403 `{"error":"Request protocol not permitted on this route"}` (`src/proxy/mod.rs:293`) instead of reaching the backend.

`wrap_non_sse_responses` now frames only bodies that the plugin's own `after_proxy` selected. A `response_mock` reply, a terminate-mode `serverless_function` reply, a cache hit or a gateway-replaced response is no longer framed with `data:`. `force_sse_content_type` no longer relabels 206, 226 or content-coded responses. `retry_ms` now also prefixes streamed backend event streams.

The 405, 406 and 400 rejections themselves are unchanged (`:901`, `:927`, `:947`).

Catalog impact:
- `gateway.routing.protocol_not_permitted` (core slice) should list `sse` among the admission-gating plugins.
- Add notes to `sse.method_not_get` and `sse.accept_missing`.
- `sse.response_decoration`: update the condition.

### compression: opt-in zstd and weak ETags, negotiation on the client's own Accept-Encoding, stricter config (#6848, v0.9.19)

- **zstd.** `algorithms` accepts `zstd` (`src/plugins/compression.rs:217`, `zstd_level` at `:704`), so `Content-Encoding: zstd` can appear. An instance that lists it also decodes zstd uploads through the strict decoder: one frame per layer, 8 MiB window (`src/plugins/charged_decode.rs:169`). Otherwise zstd uploads still get the 400 Content-Encoding refusal (`:908`).
- **Weak ETags.** With `weaken_strong_etag` (`:662`, `:1953`), a strong-ETag response is compressed and carries the weak form of its ETag.
- **Negotiation.** Compression reads the client's Accept-Encoding as captured at request start (`:318`), so a `request_transformer` rewrite no longer changes which coding the client gets.
- **Relabel to 406.** A later hook that relabels a committed coding while identity is forbidden now produces the 406 (`:436`-`:440`).
- **Large response limits.** When the response limit is 0 or above 32 MiB, compression is length-gated instead of switched off (`:1137`).
- **BREAKING config.** Duplicate algorithms, more than 64 or repeated `content_types`, and `*/*` or non-`type/*` wildcards are refused.

Catalog impact:
- `response_encoded`: the public signal gains zstd and the weak ETag.
- `response_not_acceptable`, `request_content_encoding_invalid` and `request_body_malformed`: conditions and notes updated.

### grpc_web refuses requests it cannot translate (#6826, v0.9.19)

A `grpc-web-text` body that is not valid base64 is now refused with the gRPC-Web invalid-request shape. The message is `gRPC-Web text request body is not valid base64` (`src/plugins/grpc_web.rs:553`, latched at `:4836`). Before, the body was forwarded undecoded.

Missing or malformed translation state is refused with `gRPC-Web translation state is missing or malformed` (`:554`, `:4709`, `:4958`).

Catalog impact: `plugin.grpc_web.invalid_request` gains these triggers and messages; the shape is unchanged (`:489`). `accept_not_acceptable` is unchanged (`:4640`).

### request_termination: operator headers and OWS-normalised header trigger (#6866, v0.9.19)

- **Headers.** A new optional `headers` setting (up to 32 entries, values up to 4096 bytes; `src/plugins/request_termination.rs:417`) adds headers to the canned response. Reserved names are refused (`:468`).
- **Header trigger.** `trigger.header_value` now matches a field value with surrounding spaces and tabs stripped (`:720`), so H2 and H3 clients that pad values match the same way H1 clients do.
- **BREAKING config.** `content_type` and trigger values that could never match are refused at load.

The reject is now `RejectBinary` (`:786`, CONNECT refusal at `:775`). The proxy converts `Reject` and `RejectBinary` into the same response parts (`src/proxy/mod.rs:7365`), so the status and body are unchanged.

Catalog impact: `default_json_envelope` and `xml_envelope` gain the operator-header note; repoint `:557` to `:786` and `:542` to `:775`.

### grpc_deadline: headroom_ms and timer-enforced streaming deadlines (#6870, v0.9.19)

- **headroom_ms.** The new `headroom_ms` reserves a fixed margin from a valid client `grpc-timeout` (`src/plugins/grpc_deadline.rs:450`), so `DEADLINE_EXCEEDED` (status 4, "Deadline exceeded at gateway") can reach the client before its own deadline.
- **Caps and rounding.** `max_deadline_ms` caps now combine across instances in any order, and coarsened units round down.
- **Streaming RPCs.** On HTTP/1.1 and HTTP/2, streaming responses are cut at the deadline by a gateway timer. A client that does not drain the terminal is closed after 2 s (`src/proxy/response_watchdog.rs:193`).

`reject_no_deadline` (400 to grpc-status 3) is unchanged (`:398`).

Catalog impact: notes only for `deadline_exceeded_at_gateway`.

### spec_expose fetch client follows CRL generations (#6669, v0.9.19)

A failed client rebuild for the current CRL generation fails the fetch closed with the existing 502 `Failed to fetch API specification from upstream` (`src/plugins/spec_expose.rs:596`). The transport-error emitter moved from `:570` to `:605`.

`spec_served` and `fetch_busy` are unchanged.

### Lab: grpc_web key comment

`lab/gateway/lint-profiles.rb` cites `grpc_web.rs:1218` for "v0.9.7 to v0.9.15". At v0.9.20 `GRPC_WEB_CONFIG_KEYS` is `src/plugins/grpc_web.rs:122` and `parse_expose_headers` is at `:1278`; the only key is still `expose_headers`. This is a comment-only fix.

The lab's `grpcweb-*` plugins use `config: {}`. The GRPCWEB-002 scenario sends valid base64, so the new refusal does not affect it. No lab route uses `request_termination`, `response_mock`, `fault_injection`, `spec_expose`, `sse`, `grpc_deadline`, `load_testing` or `compression`.

## AI, MCP and A2A plugins

Citations are at v0.9.20 (`e4a606a`). The #68xx/#69xx hardening PRs are first contained in the unpublished v0.9.18 tag, and the CHANGELOG carries them under 0.9.19, so this section labels them v0.9.19. #6118 and #6127 (first in the unpublished v0.9.16 tag) are labelled v0.9.17. Edge #7004 is in v0.9.20: `git merge-base --is-ancestor 97fbb3f37 v0.9.20` succeeds.

The slice has 93 outcomes. 25 flagged citations were repointed by hand (24 structured, 1 prose). 40 outcomes change their condition, signal or notes, 53 carry over unchanged and 9 outcomes are new. No outcome is removed: every carried emitter still exists and is still reachable. The status, token and body checks covered `openai_error_response` (`src/plugins/ai_federation.rs:10012`, unchanged), the federation stream error frame and `STREAM_REASON_*` constants (unchanged), `src/plugins/utils/openai_error.rs` (byte-identical) and `encode_sse_error_event` / `original_response_is_event_stream` in `src/plugins/utils/sse.rs` (unchanged). The `src/plugins/utils/metadata_redaction.rs` changes affect only log sinks.

### ai_rate_limiter: budget and capacity 429s now carry Retry-After (#6847)

`reject` (`src/plugins/ai_rate_limiter.rs:1030`) always adds `retry-after` = `window_seconds` (`:913`, `:1033`), whatever `expose_headers` says. The state-capacity 429 does the same (`:1089`). The budget check moved from `before_proxy` into `admit` (`:1153` for the 429, `:1140` for the 503). `admit` is called from `before_proxy` (`:3463`) and from three final-body re-admissions (`:1566`, `:1639`, `:1716`). The limit is now the effective one: a `consumer_limits` / `model_limits` override, or else `token_limit`. That limit is what the body and `x-ai-ratelimit-limit` report. Only POST requests classified as AI calls consult the budget, so GET, framed gRPC-Web and parsed non-LLM JSON never get 429/503. An AI body sent as `text/plain` or with no label is now metered. Under the default `charge_estimate`, an unparseable JSON AI candidate is flagged like a compressed one (`:3483`), so a 2xx without usage gets the `usage_missing` 502 (`:1885`). #6648 counts cache, thinking and tool-use tokens.

Catalog: `public_signal` of `token_limit_exceeded` and `state_capacity_exceeded` gains `Retry-After`. The old note "No Retry-After is emitted" is now false. `usage_missing` and `enforcement_unavailable` get condition updates. Repoints: `:822 → :1030`, `:2572 → :1153` and `:2559 → :1140`.

### ai_rate_limiter: new 415/400 when model_limits cannot read the model (#6847)

When `model_limits` is set and the model of an AI candidate cannot be read, `reject_unknown_model` (`src/plugins/ai_rate_limiter.rs:874`) refuses it with body `UNKNOWN_MODEL_REJECT_BODY` (`:82`). The status is 415 with `Accept-Encoding: identity` when the body is still encoded, and 400 when it does not parse. Both `before_proxy` (`:3448`) and the deferred final-body classification (`:1547`) emit it. New outcome: `plugin.ai_rate_limiter.model_unattributable`.

### ai_request_guard: new 400s, path models and changed detail strings (#6849, #6924)

All validation failures now go through `policy_reject` (`src/plugins/ai_request_guard.rs:1310`, status 400 at `:1326`), called from `before_proxy` (`:2769`) and the final-body hook (`:2874`). The body shape `{"error":…,"details":…}` is unchanged. The new refusals are:

- `Invalid max_tokens field` (`:912`)
- `Conflicting field spellings` (`:847`, Gemini camel- and snake-case spellings)
- `Invalid completion count field` (`:936`)
- `Too many completions requested` (`:951`, from the new `max_choices` setting)
- `Invalid batch request entry` (`:1417`, Anthropic Message Batches)

Duplicate-member bodies get the uninspectable 400 with details `Ambiguous JSON request body (duplicate object member names or an over-budget document)` (`:1250`). Path models from Gemini/Vertex, Bedrock and Azure URLs are checked by `check_model_name` (`:859`, `:803`, `:814`). POSTs whose body opens a JSON object are evaluated even when the Content-Type is missing, non-JSON or joined. A `null` or blank `user` or required metadata field is refused. The details text changed to `The 'user' field must be a non-empty string for audit trail purposes` (`:1065`) and `Required field '{field}' is missing, null, or empty in the request` (`:1076`). #6924: a lone null Gemini generation container is filled with the default cap instead of being refused.

Catalog: three new outcomes, `generation_control_invalid`, `max_choices_exceeded` and `batch_entry_invalid`. `body_uninspectable` gains the ambiguous detail in `body_shape`. `model_not_allowed` and `structural_policy` get condition updates. There are 17 structured repoints: `:493→803`, `:505→814`, `:2021→2769`, `:539→923`, `:671→1108`, `:550→965`, `:564→980`, `:598→1020`, `:606→1029`, `:615→1039`, `:627→1052`, `:636→1064`, `:645→1074`, `:466→837` and `:680→1118`.

### ai_prompt_shield: uninspectable prompts are refused, not forwarded (#6838)

In content and all modes with reject or redact, a body that is or may be JSON gets 400 `{"error":"Request body could not be inspected","message":"non_utf8_body|malformed_json|unsupported_charset"}` (`src/plugins/ai_prompt_shield.rs:1578`) when it is not UTF-8, fails the strict parser, or declares a non-UTF-8 charset. The emitters are `:2446`, `:2510`, `:1679` and `:2923`. Warn mode records the condition and forwards. Every POST, PUT and PATCH that is not framed gRPC is buffered. Replayed tool-call arguments are scanned. A custom-pattern walk that runs out of budget gets the existing redaction-limit 413 (`:2710`).

Catalog: new outcome `plugin.ai_prompt_shield.body_uninspectable`. It shares its `error` with `uninspectable`, but its message is a bare reason code. `pii_detected` and `size_limit` get notes. `mcp_body_uninspectable` is repointed: `:1977→2413`, `:2357→2833` and `:2417→2912`. The MCP answer is still `reject_uninspectable_mcp_body` (`:1677`).

### ai_prompt_compressor: residual preserve markers get a 400 (#6854)

With `preserve_tag` set, the final-body hook re-verifies the exact backend-visible body. A body that still carries a marker, or an encoded body with no decoded view (`src/plugins/ai_prompt_compressor.rs:2305`), maps to `Unsanitizable → 400` (`:2327`) with body `{"error":"Request contains AI prompt preserve markers that could not be sanitized"}` (`:2340`). Encoded candidates are claimed by the shared request representation gate. A bad `Content-Encoding` therefore gets `gateway.request.representation_uninspectable` (400) instead of passing through.

Catalog: new outcome `plugin.ai_prompt_compressor.residual_marker`. Repoint `:1548 → :2292`.

### ai_stream_router: unrepresentable parameters get a 400 (#6824)

For Anthropic and Gemini providers, `before_proxy` (`src/plugins/ai_stream_router.rs:4035`, `:4048`) returns an OpenAI-shaped 400 `Invalid request for {Anthropic|Gemini} translation: {detail}`. `param` names the field, and `code` is `unsupported_parameter` (`:2444`) or `invalid_parameter` (`:2452`). These parameters used to be dropped silently. The affected ones are `logit_bias`, `logprobs`, Anthropic `n>1`, penalties, `seed` and JSON `response_format`, Gemini `parallel_tool_calls:false` with tools, a strict schema Gemini cannot enforce, and a mistyped `max_tokens` (`:2701`, `:2742`). The existing translation 400 adds new details for Anthropic extended thinking with tools (`:2359`, `invalid_thinking`) and image data URLs (`:1686`).

Catalog: new outcome `plugin.ai_stream_router.parameter_unrepresentable`. `translation_rejected` gets notes.

### ai_stream_router: Anthropic Content-Type check, new 502 wording, provider TLS isolation (#6824)

`classify_provider_stream_media` now requires `text/event-stream` from Anthropic (`src/plugins/ai_stream_router.rs:5363`). The 502 messages now read `…suitable for provider stream normalization` and `…unexpected Content-Type for provider stream normalization` (`:5387`, `:5390`). The v0.9.15 "Gemini stream normalization" strings are gone. New mid-stream reasons are at `:5980`, `:6009`, `:7218` and `:8247`. An https provider without `inherit_backend_tls` now trusts only the public roots. Providers behind a private CA therefore fail with the proxy's connection-failure 502.

Catalog: `unsupported_provider_stream` gets condition and notes updates. `normalized_stream_error` and `provider_error_passthrough` get notes. A new `azure_openai` provider type passes streams through unchanged.

### ai_federation: unrepresentable generation controls, thought signatures and stream circuit scoring (#6816, #6118, #7004)

`translated_generation_controls` (`src/plugins/ai_federation.rs:3625`) refuses, per provider before any I/O, the controls that Anthropic, Gemini/Vertex or Bedrock cannot represent (`:3289`). Fallback can still reach a provider that supports them. If no provider is attempted, the existing 400 `provider_translation_failed` fires (`:9913`). A malformed `extra_content.google.thought_signature` is a 400 `invalid_request` (`:2873`). Streaming transport faults now count as circuit failures (`:6797`). Since #6118 (v0.9.17), ambient AWS credentials are limited to official Bedrock endpoints: admission enforces it (`:1761`), and an out-of-scope URL at signing time fails as a pre-wire 502 (`:6525`). Weight, timeout caps (`:146`, `:166`) and secret references are admission-only changes. With #7004, streaming provider destinations become `adaptive_concurrency` route keys, with no new response.

Catalog: `provider_translation_failed` gets a condition update. `invalid_request`, `provider_circuit_open` and `provider_request_failed` get notes.

### ai_response_guard: duplicate members are uninspectable (#6839, #6640, #6682)

Duplicate-member JSON, SSE data and tool arguments now get the existing uninspectable 502 for enforcing actions. The reasons are `response JSON contains duplicate object members` (`src/plugins/ai_response_guard.rs:5050`) and `SSE data contains duplicate JSON object members` (`:4876`). An empty synthetic 200 fails `require_json` / `required_fields`. Redaction growth beyond the allowance or the live-capacity window fails closed. The PII catalog changes and the new `allowlist` shift what `content_blocked` matches.

Catalog: notes on `uninspectable` and `content_blocked`. Repoint `:4088 → :4723`.

### ai_semantic_firewall: allow_topics ordering, undeclared streams and segment cap (#6823)

A request that matches a warn rule but no allowed topic is now rejected with 403. A streaming target the request did not declare (Gemini `:streamGenerateContent`, Bedrock stream paths) gets the streaming 400 with a second message, `…use the provider's non-streaming endpoint.` (`src/plugins/ai_semantic_firewall.rs:1339`). A request with more than 1024 segments is `too_many_segments` (`:197`, `:1392`). The 10 MiB ceiling is enforced in `before_proxy` (`:234`). A provider concurrency-admission timeout is a 503 under `on_error=reject` (`:1947`).

Catalog: notes and condition updates on five outcomes. The bodies are unchanged.

### ai_semantic_cache: v4 keys and new BYPASS triggers (#6822, #6999)

Entries stored by v0.9.15 are never hit after the upgrade. BYPASS now also covers:

- duplicate JSON members (`src/plugins/ai_semantic_cache.rs:5427`)
- request `Cache-Control` `no-store` / `no-cache` (`:5470`)
- an unprovable response presentation policy (`:5484`)
- a Cohere v1 `conversation_id`

Successful `ai_federation` answers are now stored. The cache never rejects a request.

Catalog: notes on `hit` and `miss_bypass`.

### ai_tool_governor: scopes, deep JSON and SSE cuts (#6835)

Caller scopes add deny details such as `tool '{name}' is restricted to identified consumers` (`src/plugins/ai_tool_governor.rs:1143`, `:589`–`:608`). JSON nested too deep is uninspectable (`:332`). An SSE event that is not valid UTF-8 cuts the stream (`:6261`, `:6421`). Approval resolution moved into `resolve_require_approval` (`:1758`). Non-loopback `http://` approval endpoints are refused at admission.

Catalog: notes on three outcomes. Repoint `fail_closed` `:1298 → :1758`.

### mcp_gateway: prompts and resources are gated by policy (default deny) (#6819)

`prompts/get` and `resources/read` that policy does not allow get HTTP 200 JSON-RPC `-32001` `MCP prompt request denied by gateway policy` (`src/plugins/mcp_gateway.rs:5671`) or `MCP resource read denied by gateway policy` (`:5921`). The family defaults fall back to `policy.default_action`, which defaults to deny (`:11144`), so a v0.9.15 config with no prompt or resource policy now refuses every prompt and resource read. When the resource policy cannot be decided, the answer is `-32006` (`:5909`). An aggregate DELETE without a session header now gets the missing-session 400 (`:8058`) where v0.9.15 answered 200. A tool whose `inputSchema` fails the bounded audit is omitted (`:10461`). Client credentials and the query string no longer reach upstreams chosen by the tool call unless `forward_client_credentials` is set.

Catalog: new outcomes `plugin.mcp_gateway.prompt_denied` and `plugin.mcp_gateway.resource_read_denied` (the prompt and resource messages are separate outcomes, so each matches exactly). `session_or_version_rejected` gets a condition update and source `:8058`. `catalog_unavailable` and `unknown_item` get notes. The `invalid_request` prose citation `rate_limiting.rs:1014` is repointed to `src/plugins/rate_limiting.rs:1617`, which is the same body. Under #6814 rate_limiting now also refuses non-UTF-8 charsets and unparseable bodies that may carry `tools/call` (`:1130`, `:1159`).

### mcp_aggregate_sse and the OpenAPI bridge (#6880, #6127)

The aggregate listener now stops at the response ceiling with a `ResponseBodyTooLarge` abort (`src/plugins/mcp_aggregate_sse.rs:2387`). Strict `response_size_limiting` refuses it before commit with that plugin's 502. The bridge recognises `loop_detected` (`src/plugins/mcp_openapi_bridge.rs:1385`).

Catalog: notes on `listener_errors` and `openapi_bridge_error_result`.

### a2a_gateway: method grants, final-body class change and card representation (#6841, #6919)

`policy.methods.*` allow entries accept `allowed_groups` / `denied_groups`, checked by `A2aMethodGrant::admits` (`src/plugins/a2a_gateway.rs:316`). An ungranted method gets the existing deny on all three bindings. A final body that changed operation class or can no longer be classified gets HTTP 200 `-32001` `A2A operation changed after gateway admission` with `data.gateway` set (`:3032`, `:2220`, `:2187`). A final body over the detection limit gets the existing 413 (`:2185`). Encoded HTTP Agent Cards are decoded and rewritten. Partial (206/226, including multipart) and undecodable cards are refused by `gateway.response.representation_uninspectable` (502). A card still encoded after the gate records `agent_card_representation_uninspectable` (`:1392`). GRPC and HTTP+JSON interface URLs are now rewritten.

Catalog: new outcome `plugin.a2a_gateway.operation_class_changed`. Notes on the three denial outcomes, `request_too_large` and `agent_card_rewrite_failed`. `agent_card_rewrite_failed` has two wire forms: a JSON 502 on the HTTP bindings (`src/plugins/a2a_gateway.rs:3554`-`:3561`) and, on the gRPC binding, HTTP 200 with an empty body, `content-type: application/grpc` and `grpc-status: 13` set by the plugin (`:3757`-`:3764`). Its `grpc_status` was corrected from 14 (the mapped value of a 502) to 13 (#483).

### ai_token_metrics and ai_transcript_audit: no client-visible change (#6857, #6815)

`ai_token_metrics` meters streams without buffering, and its priority moves to 4070. `buffer_streaming_responses: true` still buffers (`src/plugins/ai_token_metrics.rs:768`). The `audit_unavailable` 503 (`src/plugins/ai_transcript_audit.rs:6760`) is unchanged. With a reject sink policy, an encoded candidate request now goes through the shared representation gate.

Catalog: unchanged.

### Lab impact

- **GW-020-BUDGET.** The gateway 429 now carries `Retry-After: 3`. The scenario's assertions still hold (429, `x-ai-ratelimit-remaining: 0`, `rejection_phase` `before_proxy`), and its POST chat body stays in scope. Only a matcher that relies on the gateway 429 lacking Retry-After would need to change.
- **MCP profile.** No break found. All `mcp.yaml` keys are still accepted under the closed config (#6967, `src/plugins/mcp_gateway.rs:115`–`:195`). The scenarios use tools only, and every DELETE sends the session header. If a scenario for prompts or resources is added, set `policy.default_prompt_action` / `default_resource_action` explicitly.
- **GW-020-GUARD and GW-020-CONTENT.** No change.

## Mesh and lab configuration

### Mesh RequestAuthentication refusal (new outcome)

A RequestAuthentication that Kubernetes translation rejects is now kept as a refused marker rather than dropped. Mesh mode then forces a `request_termination` (`__mesh_request_auth_refused`) on the workload's inbound routes. The refusal answers `503 {"message":"RequestAuthentication for this workload was rejected by the gateway; requests are refused until it is fixed","status_code":503}`. The config is at `src/modes/mesh/mod.rs:14352`, the install at `:14244` and the message at `:141`. This arrived in PR #6668 / issue #6656, listed under v0.9.19 (the commit was first tagged v0.9.18). Before that change, the workload ran with no JWT validation.

v0.9.20 (#6961, issue #6670) extends the refusal in two ways:
- **NodeWaypoint Service routes.** The refusal covers routes whose destination is selected by a refused RA, by RA sets that disagree or by an unresolvable modeled destination, and routes whose provider union is too large.
- **Managed `mesh_authz` relays.** The managed `mesh_authz` refuses an inbound HBONE relay to such a destination with the same JSON (`src/plugins/mesh/authz.rs:3590`, `:3209`; metadata `mesh_authz.deny_policy=request_authentication_refused`). On a NodeWaypoint capture TCP relay the same check drops the stream (`:4603`).

**Catalog:** new `plugin.request_termination.mesh_request_authentication_refused`. Its status and envelope are shared with `plugin.request_termination.default_json_envelope`, and only the fixed message tells them apart. `plugin.mesh_authz.stream_denied` gets a condition note.

### NodeWaypoint rechecks the source pod per request (new outcomes)

On a NodeWaypoint, every HTTP request on a captured connection now re-validates the source pod against the live slice. A withdrawn or conflicted pod gets `403 {"error":"node-waypoint source identity is no longer enrolled"}` (`src/proxy/mod.rs:35348`, resolver `src/modes/mesh/node_waypoint.rs:1000`). A captured TCP stream whose capture record no longer resolves is dropped at accept (`src/proxy/tcp_proxy.rs:2838`). Before this change it was evaluated with mesh-wide policy only. Both behaviours come from PR #6964 / issue #6800 in v0.9.20.

**Catalog:** new `gateway.admission.node_waypoint_source_not_enrolled` (unique body) and `l4.tcp.node_waypoint_capture_source_refused` (connection drop, operator logs only).

### `mesh_authz` judges more requests, same signal

These changes leave the 403 signal alone but widen when it fires:
- **Repeated headers (v0.9.19, #6825).** `to.headers`, `when: request.headers[...]` and the CUSTOM check now read every field line of a repeated header (`src/plugins/mesh/authz.rs:1426`), after header case variants are canonicalized (#6932, `:3576`).
- **Never-matching matchers.** Direct `mesh_policies` / embedded `mesh_slice` matchers that can never match are refused at construction (`:2195`).
- **NodeWaypoint capture policies (#6809).** NodeWaypoint capture relays evaluate the destination pod's own AuthorizationPolicy. Scoped capture policies also count toward the missing-scope fail-closed rule (`:4010`), and an ambiguous capture-inventory match yields no destination scope (`:2882`).
- **Namespace-keyed lookups (v0.9.20, #6961).** Destination-scope lookups are keyed by namespace as well as upstream id (`:2795`, `:2956`).

The signals stay `403 {"error":"Mesh authorization denied"}` (`:2989`), `...: missing per-pod policy scope` (`:4079`) and `...: missing destination policy scope` (`:4104`).

**Catalog:** notes on `plugin.mesh_authz.denied`, `per_pod_scope_missing` (condition) and `destination_scope_missing`. Repoints: `decision_to_result` moves 2348 → `:2974`, and the scope-missing gate moves 3301 → `:4063`.

### `mesh_ext_authz` denials forward every provider header line

`collect_headers` (`src/plugins/mesh/ext_authz.rs:1339`) now folds every field line of each `headersToDownstreamOnDeny` header instead of keeping the first. Two `Set-Cookie` lines or several `WWW-Authenticate` challenges therefore all reach the client (#6825, v0.9.19).

Check requests now carry gateway-stamped `x-ferrum-source-principal`, `-namespace`, `-service-account` and `x-ferrum-request-principal`, with any client copies removed (`:1393`), plus the hop header. Allowed checks can now set backend request headers (`headersToUpstreamOnAllow`, `authz.rs:4485`) and client response headers (`headersToDownstreamOnAllow`, `authz.rs:5145`). Status coercion is unchanged (`:1309`).

**Catalog:** `other_headers` updated on `provider_denied` and `provider_denied_status_coerced`. Repoints: the Deny construction moves 857 → `:1259`, and `collect_headers` moves 926 → `:1339`. `check_failed_closed` and `body_too_large` are unchanged.

### `mesh_outbound_registry` port grammar and wildcards

From #6859 (v0.9.19):
- **Port grammar.** Authority ports must be decimal 1–65535 (`src/plugins/mesh/outbound_registry.rs:752`). `svc:0` and `svc:+8443` now get the REGISTRY_ONLY reject instead of matching.
- **Wildcards.** A new `wildcard_match: dns_suffix` option (`:132`) admits deeper names for operator-managed instances. Mesh auto-injection keeps `one_label`.
- **Malformed mesh hosts.** Malformed mesh ServiceEntry hosts are dropped one by one with a warning instead of failing the whole config.

The signal is unchanged (`:713`, `:859`; default 502).

**Catalog:** notes on `destination_not_registered`; `host_header_missing` is unchanged.

### HBONE relay changes seen from the mesh side (owned by the protocol.hbone slice)

- **HTTP application ports (#6125, v0.9.17, tagged v0.9.16).** A bare Sidecar CONNECT to a port served by an HTTP inbound route is refused `403` with reason `http_application_port` (`src/proxy/mod.rs:3038`, `src/modes/mesh/config.rs:5563`).
- **Consumer re-judging (#6873).** Live HBONE tunnels are revoked when their mapped Consumer is deleted or leaves an allowed group (`src/proxy/hbone_admission_fence.rs:2157`).
- **Kernel connect timeout (#6777).** A kernel `ETIMEDOUT` on the relay's backend connect now answers `504 Backend HBONE connection timed out` instead of `502` (`src/proxy/hbone_proxy.rs:748`).

**Lab:** MESH-008 sends a bare CONNECT to 127.0.0.1:17801. That port is declared `http` in `mesh-sidecar.json`, so from v0.9.17 the CONNECT is refused rather than relayed. To keep one profile working on every release, point MESH-008 at a separate `tcp` workload port backed by the echo fixture.

### Lab: MESH-008 bare CONNECT to the sidecar's HTTP port is refused (#6125, v0.9.17)

MESH-008 sends a bare HTTP/2 CONNECT to `127.0.0.1:17801` on the STRICT sidecar inbound listener and expects the echo workload to answer. `mesh-sidecar.json` declares 17801 as an `http` port, so the sidecar materializes an HTTP inbound route and records the port in `sidecar_inbound_http_app_ports` (`src/modes/mesh/mod.rs:6585`).

From v0.9.17, a byte-stream CONNECT to such a port is refused. This was #6125 (issue #6110; first tagged in v0.9.16, which was not published). The refusal applies on the route miss (`src/modes/mesh/config.rs:6089`, `src/proxy/mod.rs:3038`) and on a matched HTTP route (`src/proxy/mod.rs:36216`). The client gets `403 {"error":"HBONE relay destination not allowed"}` (`src/proxy/hbone_proxy.rs:139`) with reason `http_application_port` (`src/modes/mesh/config.rs:5563`). Nothing reaches the workload.

MESH-015 still gets the unauthenticated-peer 403. A peerless CONNECT is answered before the destination reason is used (`src/proxy/mod.rs:3225-3227`).

**Fixed here (one profile for v0.9.5–v0.9.20):**
- Add a workload-only port `{"port": 17808, "protocol": "tcp", "name": "tcp-echo"}` to `mesh-sidecar.json`. Leave it off the Service.
- Bind an HTTP echo fixture on `127.0.0.1:17808`.
- Aim MESH-008 at `127.0.0.1:17808`. Every release relays a declared non-HTTP port.
- Correct the relay wording in `mesh-sidecar.conf`.

### Lab: UP-018's direct-HTTP/1.1 connection ceiling answers 503 on v0.9.20 (#6777, v0.9.19)

UP-018 calls `release_from_through_pin("v0.9.11")`. With the pin at v0.9.20, that range now includes v0.9.20, so the check expects `502 {"error":"Backend unavailable"}` / `connection_failure`.

On v0.9.20, the direct-H1 checkout refusal at the DestinationRule `maxConnections` ceiling is still classed `BackendConnectionLimit` (`src/proxy/http2_pool.rs:2093`). It reaches the shared mapper through `direct_h1_checkout_error_response` (`src/proxy/mod.rs:53577`). #6777 changed that mapper (first tagged in v0.9.18, which was not published; listed under 0.9.19) so the class now answers `503 {"error":"Backend connection limit exceeded"}` (`src/proxy/mod.rs:50120`).

The class is still pre-wire (`src/retry.rs:480`). So `X-Gateway-Error` stays `connection_failure` (`src/retry.rs:303`), and the operator `error_class` stays `backend_connection_limit`.

The upgrade guide names only direct HTTP/2, native HTTP/3, HBONE and sidecar mTLS. The direct-H1 pool uses the same pool error and mapper, and its eligibility function is unchanged.

**Fixed here (lab code only, no profile change):** the release gate in `admission.rs` is split:

| Releases | Status | Marker | Body |
|---|---|---|---|
| v0.9.5–v0.9.10 (reqwest) | 503 | `backend_error` | `Backend connection limit exceeded` |
| v0.9.11–v0.9.15 | 502 | `connection_failure` | `Backend unavailable` |
| from v0.9.19 (v0.9.20) | 503 | `connection_failure` | `Backend connection limit exceeded` |

For the last row the Diagnosis checks expect the single catalog outcome `upstream.connection_limit.pooled` instead of the shared 502 family, and the `admission-mesh.conf` comment names the new answer.

### Lab: stale Edge line citations in CP/DP profile comments

`cpdp-cp.conf:7` cites `src/config/env_config.rs:6897-6905`; the code is now at `src/config/env_config.rs:7747-7750`. `cpdp-dp.conf:15` cites `src/proxy/mod.rs:29874-29903`; the code is now at `src/proxy/mod.rs:34949-34969`. The stale-fence signal itself is unchanged: `503 {"error":"Gateway configuration stale"}`, `config_stale`, and the DP WARN at `src/modes/data_plane.rs:1205`. `src/dp_config_freshness.rs` is byte-identical between v0.9.15 and v0.9.20. The comments are documentation only; they now cite symbols instead.

### Lab: mesh, workload and CP/DP profiles otherwise accepted unchanged

- **Mesh documents.** Every mesh JSON member the lab uses is still a field under the #6967/#6972 closure. That covers PeerAuthentication (`src/modes/mesh/config.rs:3165`), MeshPolicy (`:386`), ServiceEntry (`:3227`) and DestinationRule `traffic_policy.max_connections` (`:4344`).
- **Env vars.** Every `FERRUM_*` these profiles set is declared identically at v0.9.15 and v0.9.20.
- **Pod registry.** An empty `FERRUM_MESH_NODE_WAYPOINT_POD_REGISTRY_DIR` still disarms the pod-registry bound (`src/modes/mesh/mod.rs:15664`).
- **Outbound registry.** `mesh_outbound_registry` stays unarmed (`allow_any`, `src/config/env_config.rs:5249`).
- **Relay metadata.** The relay keys the lab greps for are on the built-in safe list (`src/plugins/utils/metadata_redaction.rs:432`).
- **Workload API.** The Workload API and JWT-SVID sources are unchanged.
- **CP seeding.** The CP is seeded with POST only, so #6744's `expected_proxy_ids` (PUT/DELETE only, `src/admin/crud.rs:4736`) does not apply.
- **Admin JWT.** The lab's admin JWT has no `aud` or `ns` claim and is still accepted.

### Lab: AUTH-001 expects the old `ferrum-edge` challenge on a key_auth 401

From v0.9.19, key_auth's missing-credential 401 carries `WWW-Authenticate: ApiKey realm="ferrum-edge"`. Before that it carried the bare `ferrum-edge`.

- Source: #6779, issue #6774. The commit was first tagged v0.9.18, which was not published.
- Edge: `src/plugins/key_auth.rs:344` returns `API_KEY_AUTHENTICATION_CHALLENGE` (`src/plugins/utils/auth_flow.rs:648`).
- The status 401 and body `{"error":"Authentication required"}` are unchanged.

AUTH-001 (`crates/anvil-lab/src/auth.rs:332-337`) requires the raw value to equal `ferrum-edge`, so the check fails on v0.9.20. `auth.yaml` itself is still valid.

**Fixed here (lab code only):** AUTH-001 expects `ApiKey realm="ferrum-edge"` when `gateway::release_at_least("v0.9.19")` and `ferrum-edge` otherwise, so each release keeps its own exact value.

Other challenge checks still pass:
- Basic: the value now ends `, charset="UTF-8"`, but the lab's substring check still matches.
- Introspection: `Bearer error="invalid_token"`.
- Introspection-down 503: carries no challenge.
- Relayed backend 401s (AUTH-X04/X05): forwarded untouched.

### Lab: UP-007 backend TLS stall now answers 504

From v0.9.19, a backend connect timeout answers 504 `{"error":"Backend timeout"}` instead of 502. This also covers a TLS handshake that runs past `backend_connect_timeout_ms`.

- Source: #6777, issue #6770. The commit was first tagged v0.9.18, which was not published.
- Edge: `src/proxy/mod.rs:50117-50118`.
- `X-Gateway-Error: connection_failure` and `error_class=connection_timeout` are unchanged.

UP-007 (`crates/anvil-lab/src/tls.rs:1103`, through `upstream_setup_failure` at `tls.rs:966`) asserts 502 and fails on v0.9.20. `tls.yaml` is unchanged.

**Fixed here (lab code only):** `upstream_setup_failure_status` takes the expected status, and UP-007 expects 504 from `release_at_least("v0.9.19")`, where the confirmed `http.gateway_timeout` status finding is not counted as a timeout claim. UP-004/005/006/008 stay 502, because TLS, refused and protocol failures stay 502 in the same mapper (`src/proxy/mod.rs:50120`).

### Lab: auth, tls and workload-proxy profiles load unchanged on v0.9.20

Every plugin key, nested key, consumer credential and proxy field in `auth.yaml`, `tls.yaml`, `tls.tls12.yaml` and `workload-proxy.yaml` is accepted at v0.9.20. No profile edit is needed.

**Nested-key closure.** #6967 (v0.9.20) closes nested objects only in plugins the lab does not use here. The auth plugins were already closed, and their allowlists still contain every lab key:
- `jwks_auth.rs:352/380`
- `oauth2_introspection.rs:312/372`
- `oidc_relying_party.rs:155-217`
- `soap_ws_security.rs:755-822`
- `ldap_auth.rs:2617`
- `hmac_auth.rs:272`
- `jwt_auth.rs:257`
- `key_auth.rs:162`
- `access_control.rs:422`

**Credential floors and uniqueness.** The lab's per-run credentials (`crates/anvil-lab/src/fixtures_auth.rs:53-66`) pass every new rule:
- keyauth keys are 28 and 30 characters; the floor is 16 (#6577, `types.rs:133`).
- The jwt and hmac secrets are 48 characters; the floors are 32 (#6865, `types.rs:124/126`).
- All values are distinct, so the shared-credential refusal never fires (#6572).

**Loopback cleartext endpoints.** These are all still admitted:
- `jwks_uri` (`jwks_auth.rs:2846`)
- introspection `client_auth: none` (`oauth2_introspection.rs:1989`)
- OIDC discovery and its discovered endpoints (`oidc_relying_party.rs:4483`)
- `ldap://` without STARTTLS (`ldap_auth.rs:1159`)

**OIDC (#6833).** The configured issuer matches the lab IdP's discovery `issuer` exactly (`oidc_relying_party.rs:5309`). The new same-origin logout rule (`:4912`) is never exercised, because AUTH-017 does not call `logout_path`.

**jwks_auth (#6828, #6644).**
- AUTH-026 pins `issuer`, so the issuer-less `require_mtls_binding` refusal does not apply.
- Sender-constraint realms are per plugin instance (`jwks_auth.rs:1397`), so the DPoP route does not change AUTH-008.
- Each jwks instance has one provider, well under the #6644 provider limits.

**Not used by the lab.** `${...}` SOAP passwords, non-standard SAML conditions, duplicate `Authorization` headers (#6882) and `aud` on HS256 tokens (#6576) do not occur in these profiles.

**lint-profiles.rb.** The PLUGIN_KEYS/NESTED lists for these plugins need no change. Keys added after v0.9.15 must stay out of profiles while v0.9.5–v0.9.15 run nightly, and the lint already rejects them. Examples: jwt_auth `algorithm`, jwks_auth `clock_skew_seconds`, hmac_auth `signed_headers`.

### Lab: file-mode profiles policy, mcp, core, admission, drain, early, streams, h3x and proxyproto load unchanged on v0.9.20

Every key and value these profiles set is still accepted at v0.9.20. That covers the gateway, proxy, upstream, health-check and circuit-breaker fields, and the config of every plugin they use: stdout_logging, adaptive_concurrency, response/request_size_limiting, response_transformer, bot_detection, rate_limiting, waf, opa, ip_restriction, openapi_validator, ai_request_guard, ai_rate_limiter, ai_response_guard, mcp_gateway and grpc_web.

- The config structs gain only `serde(skip)` runtime fields.
- #6967 (v0.9.20, `src/plugins/config_contract.rs:1`) newly closes nested objects in workload_metrics, mesh_authz and the mesh slice only. The plugins above already rejected unknown nested keys.
- opa's cleartext opt-in (#6659) exempts loopback IP literals (`src/plugins/opa.rs:1358`).
- openapi_validator must now be proxy-scoped on every load (`src/config/types.rs:6058`, #6837). `gw015-openapi` already is.

Catalog impact: none. No profile edit is needed, so the profiles stay valid on v0.9.5–v0.9.15.

### Lab: lint-profiles.rb claims v0.9.20 without a v0.9.20 source note

`lab/gateway/lint-profiles.rb` line 5 lists v0.9.20, but its per-release notes stop at v0.9.15. The key lists for every plugin above were re-checked against v0.9.20 source and nothing is missing.

Two rules v0.9.20 enforces are not linted:

- openapi_validator must have `scope: proxy` (`src/config/types.rs:6058`, #6837).
- stdout_logging is KeepLastKnownGood, so a refused config fails startup (#6863).

Fix: add a v0.9.20 note to the header and, optionally, an openapi_validator scope check. The lint is the only thing that changes.

### Lab: rate_limiting 429 gains Retry-After, so the policy lookalike is no longer header-identical

From v0.9.19 every rate_limiting quota 429 carries `Retry-After` (`src/plugins/rate_limiting.rs:812`, #6814, first tagged v0.9.18). The body is unchanged.

- `ext_rate_limit`'s application lookalike (crates/anvil-lab/src/policy.rs) omits it.
- The checks still pass, because Anvil uses `Retry-After` only as text (`anvil-diagnostics/src/rules/http_status.rs:56`).
- Fix: when the locked release is v0.9.19 or later, add `retry-after:2` to the lookalike headers. Do not add it for older releases.
- GW-020b's ai_rate_limiter 429 also gains `Retry-After` (`src/plugins/ai_rate_limiter.rs:1033`, #6847). No change is needed there.

### Lab: UP-003 connect timeout is now 504 (scenario already tolerant)

A backend connect timeout now answers `504 {"error":"Backend timeout"}` (`src/proxy/mod.rs:50117`, #6777 for #6770, v0.9.19). `X-Gateway-Error: connection_failure` and `error_class=connection_timeout` are unchanged.

`core.rs` up003 already accepts 502/503/504. Catalog impact: the connect-timeout outcome needs 504 (A_core/B1 slices).

### Lab: GW-008 413 body changed (scenario already tolerant)

request_size_limiting now answers `{"error":"Request body exceeds maximum size"}` (`src/util/body_limit.rs:30`, `src/plugins/request_size_limiting.rs:216`, #6875, v0.9.19). Before, the body carried `limit`. GW-008 asserts only status 413. Catalog body update belongs to the policy slice.

### Lab: behaviour changes checked and found not to affect these scenarios

- **WAF unlisted content type (#6646):** the default is now fail_closed, but response inspection stays off by default (`src/plugins/waf/mod.rs:452`).
- **bot_detection (#6878):** stricter blank and non-UTF-8 User-Agent handling does not apply to the lab's ASCII UAs.
- **mcp_gateway (#6819):**
  - Prompts and resources are now policy-gated; the lab tests tools only.
  - A DELETE without a session id now gets 400; anvil-engine sends DELETE only with a session id.
- **stdout_logging route-miss lines (#6863, `src/proxy/mod.rs:25633`):** the runners filter log lines by `proxy_id`.
- **New slow-reader cut-off (#6998/#7005):** `FERRUM_HTTP_CLIENT_WRITE_TIMEOUT_SECONDS` defaults to 60 (`src/config/env_config.rs:5352`). No scenario stalls a client.
- **H2 WebSocket early data gated on CONNECT (#6107):** early.yaml has no WebSocket.
- **Unchanged source:** CONNECT-UDP (`src/http3/connect_udp.rs`) and the PROXY-protocol parsers have no changes v0.9.15..v0.9.20.
- **gRPC:**
  - A down backend is still `UNAVAILABLE`.
  - The pre-routing and protocol-header refusals (#6940/#6965) are not triggered.
  - The gRPC-Web pass-through lookalike is not refused (#6110).

### Lab: every `FERRUM_*` setting the lab uses is still accepted on v0.9.20

The lab sets 76 distinct `FERRUM_*` names. They come from the 23 `lab/gateway/*.conf` profiles and from the per-run environment named in their headers: `FERRUM_ADMIN_JWT_SECRET`, `FERRUM_CP_DP_GRPC_JWT_SECRET`, `FERRUM_BASIC_AUTH_HMAC_SECRET`, `FERRUM_METRICS_BEARER_TOKEN`, `FERRUM_DIAGNOSTIC_REFS`, `FERRUM_DIAGNOSTIC_REF_TTL_SECONDS`, `FERRUM_MESH_CA_BOOTSTRAP_DEV`, `FERRUM_MESH_JWT_SIGNING_KEY_PEM`, `FERRUM_DATAGRAM_PROXY_PROTOCOL_SECRET`. Lab code also sets `FERRUM_MESH_EGRESS_STREAM_ENABLED` and `FERRUM_UDP_MAX_SESSIONS`.

Every one of these names is read at the same number of `src/` sites in v0.9.15 and v0.9.20. The `src/config/env_config.rs`, `conf_file.rs` and `public_env_inventory.rs` diff does not touch the parsing, validation or default of any of them. `conf_file.rs` gains only the fallible `resolve_ferrum_var_checked` lookup. The `.conf` format and its refusal of unknown keys are unchanged, so no lab key is refused, renamed, ignored or reinterpreted.

The release adds two process defaults, and neither changes a lab scenario:
- **Client write stall, 60 s:** `FERRUM_HTTP_CLIENT_WRITE_TIMEOUT_SECONDS` defaults to 60 (`src/config/env_config.rs:5352`, #6998 / #7005). No scenario holds a client unread for 60 s.
- **Proxy hop limit, 10:** `FERRUM_MAX_PROXY_HOPS` defaults to 10 (`src/config/env_config.rs:5327`, `src/proxy/hop_limit.rs:100`, #6127). No profile routes a proxy back to a gateway listener. A grep of every `backend_port` against each profile's own HTTP, HTTPS and admin ports finds no loop.

The A_core slice owns the outcomes for both limits.

**Lab impact:** none for the profiles.

### Lab: the pin and its scenario fixes land together

The default pin moves to v0.9.20 in the same change as the MESH-008, UP-018, AUTH-001 and UP-007 fixes and the two profile header corrections (see [Lab-scenario impacts fixed here](#lab-scenario-impacts-fixed-here)). Each fix keeps v0.9.5–v0.9.15 on their own expectations.

## Contracts and G01

`contracts/ferrum-contracts/PIN` moves to `contracts-edge-0.9.20` @
`39da322083044c2e92617209e62983c92387f0ad`; every vendored file is byte-exact from the tag. Four
vendored files change:

- `vocabularies/gateway-errors.json` and `vocabularies/gateway-headers.json` target Edge v0.9.20
  (`e4a606a`). The closed token vocabulary adds `loop_detected`; the 19 error classes and their
  token mappings are unchanged and agree with the 0.9.20 catalog.
- `schemas/diagnostic-ref/v1.schema.json` adds `loop_detected` to `gateway_error` and to
  `detail.rejection_phase`. Anvil's reader (`crates/anvil-diagnostics/src/gateway_detail.rs`)
  accepts both; every other field and pattern is unchanged.
- `fixtures/invalid-expectations.json` names five new invalid diagnostic-ref fixtures. They and
  their five valid counterparts (`client-disconnect-upload`, `gateway-closed-h3-upload`,
  `proxy-hop-limit`, `proxy-hops-invalid`, `query-trigger-admission`) are vendored, so the
  diagnostic-ref fixtures are now 10 valid and 12 invalid, and `diagnostic_import.rs` still exercises
  every listed diagnostic expectation. The original negative expectations are unchanged.

The pinned vocabulary now covers the 0.9.20 catalog only: the retained 0.9.9 to 0.9.15 catalogs do
not have `loop_detected`, and their historical mappings remain `contracts-edge-0.9.9(-r2)`,
`contracts-edge-0.9.11`, `contracts-edge-0.9.14` and `contracts-edge-0.9.15`. The diagnostic-report and
diagnostic-finding schemas and the three diagnostic headers Anvil reads are unchanged. Three
vocabularies Anvil does not read (`backend-egress-policy`, `plugin-catalog`, `provisioned-by`) stay
unvendored.

## Qualification status

The hosted all-profile Lab run
[41810892175](https://github.com/ferrum-edge/ferrum-anvil/actions/runs/41810892175)
(`workflow_dispatch`, `profile=all`, attempt 1) ran all 14 profiles against v0.9.20 on `main` at
`cfd4e196`, after this adoption (#480) and the retirement of v0.9.5 to v0.9.15 (#481). macOS 15
reported 558 passed / 0 failed / 19 skipped and Ubuntu 26.04 554 passed / 0 failed / 21 skipped;
Ubuntu's two extra skips are AUTH-030 and AUTH-031, whose lab XML signer needs `xmllint`, which
that runner lacks. AUTH-001, UP-007, UP-018 and MESH-008 passed, trusted and untrusted, on both
operating systems; UP-018-H2 is skipped as unreachable in a single-destination lab. No earlier
release ran: all were retired. No physical-device native acceptance, platform signing, OAuth,
provider-account or broader performance acceptance is claimed.

[compare]: https://github.com/ferrum-edge/ferrum-edge/compare/25b37395ff61bfea0f3ffd189d9011c4984fa755...e4a606a00352674daaef08636e3e359e6c48ba18
[changelog]: https://github.com/ferrum-edge/ferrum-edge/blob/e4a606a00352674daaef08636e3e359e6c48ba18/CHANGELOG.md
[upgrade]: https://github.com/ferrum-edge/ferrum-edge/blob/e4a606a00352674daaef08636e3e359e6c48ba18/docs/upgrade_guide.md
[release]: https://github.com/ferrum-edge/ferrum-edge/releases/tag/v0.9.20
