# Ferrum Edge 0.9.20 → 0.9.21: source delta audit

| Item | Immutable identity / status |
|---|---|
| Baseline | `v0.9.20`, `e4a606a00352674daaef08636e3e359e6c48ba18` (source-audited and hosted-qualified in [gateway-0.9.20-delta.md](gateway-0.9.20-delta.md)) |
| Audited target | `v0.9.21`, `f9915358c8032214f4034a17c28cdf72d14006c3` (merge of Edge #7472), [release 454250773][release], published 2026-11-22T06:29:03Z |
| Contracts | Published `contracts-edge-0.9.21`, `92d8da5be93ea1ece9f47729b1f7aa10ae8a7c3f` |
| Catalog | [`ferrum-edge-0.9.21/outcomes.json`](../../catalog/ferrum/ferrum-edge-0.9.21/outcomes.json), 626 outcome IDs: the 620 of 0.9.20 − 1 removed + 7 new |
| Lab selection | `lab/gateway/RELEASE.lock` and `lab/gateway/releases/v0.9.21.lock`; the only supported release. v0.9.20 was retired with this adoption ([why](#v0920-is-retired)) |
| Hosted qualification | See [Qualification status](#qualification-status) |
| Audit date | 2026-11-27 |

The [immutable comparison][compare] spans 837 commits. v0.9.21 follows published v0.9.20 directly,
with no unpublished tag in between. It changes 451 files under `src/` (63,728 insertions, 39,545
deletions; 10 new files, 7 deleted, and `src/plugins/utils/tcp_endpoint.rs` renamed to
`socket_endpoint.rs`), plus charts, vendored crate patches, tests and documentation. This is a
separate source delta audit on top of the [0.9.20 record](gateway-0.9.20-delta.md), not a new
comprehensive inventory. The historical 0.9.5 to 0.9.20 catalogs stay embedded and unchanged.

All `file:line` citations below are at v0.9.21 (`f991535`) unless a release is named.

## Method and limits

Both source trees were read at the exact commits above with `git show`, `git diff` and `git log`,
without checkout, build, test, binary or container execution.

**Citations.** Every structured catalog citation and every unqualified prose citation (a full path,
a bare file name that resolves to one file, or `:line` after one) was remapped through the
immutable unified diff (`git diff -U0 --histogram`), per file and with rename detection. A line
outside every hunk moves by the hunk offsets, so its text is identical by construction:

- 1,760 of the 1,786 structured citations and 1,306 prose citations remapped that way.
- 26 structured citations fell inside changed hunks and were repointed by hand. Most name helpers
  that v0.9.21 renamed or folded into others, for example `build_request_body_too_large_response`
  and `build_request_buffer_capacity_response`, now finalized by
  `boxed_finalize_request_body_read_refusal` at `src/proxy/mod.rs:33518`, or
  `await_route_request_deadline`, now `await_backend_attempt_route_deadline` at
  `src/proxy/mod.rs:59666`.
- One citation was dropped: the `ldap_auth` `consumer_mapping` refusal no longer exists.
- Eleven prose citations whose v0.9.20 line text is gone were repointed or replaced by a description.

A read-back confirms every structured citation is a non-blank line at v0.9.21 and cites `f991535`.

**Semantics.** Citation text equality does not establish behavioral equality. Unlike the 0.9.20
audit, this audit did **not** re-read every carried outcome's emitter. It took the client-visible
changes from the [0.9.21 changelog][changelog] (Security, Changed and Fixed items that name a
status, body, `X-Gateway-Error`, gRPC status, JSON-RPC code or challenge) and the
[upgrade guide][upgrade]. It read each named emitter at v0.9.21. It also compared mechanically:

- every catalog body message against the v0.9.21 `src/` tree. Exactly one message disappeared: the
  `hmac_auth` v1 nonce refusal.
- the error-like string literals of both trees, to find new public bodies.

A carried outcome whose emitter changed in a way neither the changelog nor these scans reveal
would not be caught. The hosted Lab run is the backstop for the scenarios it covers.

**Out of scope.** Admin API, Kubernetes and Istio translation, CNI, charts, database baseline and
control-plane behaviour have no client-visible data-plane signal Anvil diagnoses, so they are
summarized in [Not client-diagnostic](#not-client-diagnostic) and not catalogued.

## Summary of public-signal changes

| Change | Edge reference | Catalog impact |
|---|---|---|
| `jwt_auth`, `jwks_auth`, `oauth2_introspection`: a `;`-aliased query token is refused with 401 `{"error":"Ambiguous token query parameter"}`, `WWW-Authenticate: Bearer error="invalid_request"` | #7464, GHSA-c259-vchc-3vgr; `src/plugins/utils/token_extract.rs:41` | three new outcomes with one shared signal |
| `request_transformer` / `response_transformer` with JSON body rules refuse duplicate-member or unevaluable JSON: 400 for a request, 502 replacing a backend response | #7469, GHSA-pq95-952r-2x32; `src/plugins/request_transformer.rs:1158`, `src/plugins/response_transformer.rs:265` | two new outcomes; `plugin.request_transformer.no_runtime_failure` narrowed |
| Untranslated gRPC-Web on a route with gateway-asserted headers: 415 | #7064; `src/proxy/mod.rs:34886` | new outcome |
| Repeated or list-valued `Content-Type`: 400 before routing (gRPC framing for gRPC clients) | #7064; `src/proxy/mod.rs:58153` | two bodies added to `frontend_parse.protocol_header_violation` |
| A backend's 3xx–5xx answer to a WebSocket upgrade is relayed (status, filtered headers, body up to 64 KiB), with no `X-Gateway-Error` | #7414, GHSA-7x2j-3389-2h35; `src/proxy/mod.rs:16792`, `src/http3/websocket.rs:416` | `protocol.ws.backend_connect_failed` narrowed; a relayed refusal is the backend's response |
| `mcp_gateway` OpenAPI bridge calls outside the route's literal listen prefix: JSON-RPC −32603 | #7410, GHSA-26x8-8jq5-f73p; `src/plugins/mcp_gateway.rs:2318` | new outcome (message existed, uncatalogued) |
| `hmac_auth` `ferrum-hmac-v1` profile removed | #7114 | `plugin.hmac_auth.nonce_not_accepted_v1` removed |
| gRPC-Web on H1/H2 gets framed 200 trailer-frame refusals for route protocol admission and an open breaker | #7155 | notes only; gRPC status unchanged |
| `a2a_gateway` with Agent Card rewriting requires classification under any policy | GHSA-q25c-76f4-fp7h; `src/plugins/a2a_gateway.rs:1663` | same −32001 deny response; condition widened in notes |
| Duplicate JSON member screens in `ai_prompt_shield`, `ai_semantic_firewall`, `a2a_gateway`, `ai_rate_limiter` | GHSA-49cr-v28q-9hgp, #7417 | `ai_prompt_shield` message noted; the others reuse existing bodies |
| New operator-only rejection phases; `circuit_breaker` alias dropped | #7156, #7157, #7158, #7163, #7407 | `rejection_phases_operator_only` note |

The nine `X-Gateway-Error` tokens, the 19 `ErrorClass` values, the class-to-token mapping and
`http_backend_failure_status_and_body` are unchanged (contracts `gateway-errors.json` re-read at
v0.9.21).

## Lab-scenario impacts fixed here

No scenario expectation changed. Three lab inputs would have stopped v0.9.21 from loading, and one
ground-truth source changed:

1. **PeerAuthentication `scope` is required** (#7243; `src/modes/mesh/config.rs:3230`,
   `scope: PolicyScope` is no longer optional). `mesh-sidecar.json`, `mesh-ambient.json` and
   `workload-mesh.json` carried scope-less policies. They now declare
   `scope: {kind: namespace, namespace: ferrum}`, which v0.9.20 also accepted.
2. **`mcp_gateway` `discovery.hide_denied_items` is removed** (#7136). `mcp.yaml` set it false
   because v0.9.20 defaulted it true. v0.9.21 refuses the key, and `policy.hide_denied_tools: false`
   alone keeps denied tools listed.
3. **`pool_max_requests_per_connection` is removed** (#7218). No profile set it. `lint-profiles.rb`
   drops it from the proxy keys, and its self-check now requires it, `discovery.hide_denied_items`
   and the three keys #7114 retired to be reported.
4. **The invalid-PROXY-header warning is sampled.** `warn_invalid_proxy_header`
   (`src/proxy/proxy_protocol.rs:617`) now uses `warn_sampled!`: at most one warn line per 10 s per
   call site, and a debug line for every event. The first hosted run on v0.9.21 failed PP-004 and
   PP-008 (trusted and untrusted, both operating systems). Their operator-log ground truth found no
   line, because PP-003 had logged the sampled warning a few seconds earlier. The client-visible
   behaviour (an immediate close) and Anvil's diagnoses were correct. `proxyproto.conf` now sets
   `FERRUM_LOG_LEVEL = info,ferrum_edge::proxy::proxy_protocol=debug`, so every event is logged; the
   scenario code is unchanged.

The other refusals in the upgrade guide were checked against the profiles. None applies:

- `request_mirror` cleartext;
- `FERRUM_TLS_CURVES`;
- `tcp_connection_throttle` `cleanup_interval_seconds`;
- `allowed_ws_origins: ["*"]`;
- OAuth `client_secret` placeholders;
- the DP token file;
- ACME auto-renew outside the modes that run it;
- `workload_metrics` reserved tags.

The lab's mesh services declare no `target_port`, and their service and container ports are equal,
so the #7236 default ("absent targetPort means the service port") changes nothing there.

## v0.9.20 is retired

The repository keeps one supported Lab release since #481. Scenario code expects only the pinned
release's signals, and v0.9.21 refuses a key that the v0.9.20 `mcp` profile needed, so supporting
both would need per-release profiles. `releases/v0.9.20.lock` is removed and
`anvil-lab --release v0.9.20` is refused. The 0.9.20 catalog and this record's predecessor stay as
history, and the desktop picker labels the catalog "(no longer supported)". It stays selectable
because profiles and imports that declare it keep their diagnoses, and the embedded-catalog drift
test requires the picker to list every embedded catalog.

## Gateway core, frontend and taxonomy

### One `Content-Type` per request (#7064)

`check_protocol_headers` gains check 7, `check_single_content_type` (`src/proxy/mod.rs:58137`,
`:58153`). Before routing, on every HTTP version, it refuses:

- two `Content-Type` field lines, with `{"error":"Request contains multiple Content-Type headers"}`
  (`src/proxy/mod.rs:58157`);
- one value listing more than one media type after a comma outside a quoted string, with
  `{"error":"Content-Type header contains more than one media type"}` (`:58160`).

Native gRPC and gRPC-Web get the protocol-error framing already recorded for the other checks. A
comma inside a quoted parameter is not a list. Both bodies join
`frontend_parse.protocol_header_violation`.

### Gateway-asserted request headers and untranslated gRPC-Web (#7064)

On a route where a plugin owns gateway-asserted request headers, a recognized gRPC-Web request that
no `grpc_web` translator claimed is refused before any `before_proxy` hook
(`refuse_untranslated_grpc_web_on_assertion_route`, `src/proxy/mod.rs:34886`; called at `:34682`).
Such plugins are `claim_headers` / `output_claim_headers`, `opa` `decision_request_headers`, and
`spiffe_identity` `forward_identity`. The refusal is 415
`{"error":"gRPC-Web must be translated on a route with gateway-asserted headers"}` (`:34989`). New
outcome `gateway.routing.grpc_web_untranslated_on_assertion_route`.

Not settled: whether a gRPC-Web client receives the JSON 415 or the generic gRPC-Web reject
rendering. The upgrade guide says 415. The native HTTP/3 path was not separately checked. Client
copies of owned headers are now stripped even when a trigger skips the owning instance. That
changes what reaches the backend, not the client-visible signal.

### Operator-only phases and diagnostic references (#7156, #7157, #7158, #7163, #7407)

- `token_for_rejection_phase` drops the `circuit_breaker` alias. HTTP/3 now logs
  `circuit_breaker_open` like H1/H2.
- These new raw phases enter `src/diagnostic_ref.rs` with no token mapping:
  - `invalid_backend_path`;
  - `websocket_upgrade_unavailable`;
  - `mesh_transport_dispatch_required`;
  - `request_body_refused_before_{authenticate,authorize,before_proxy,dispatch}`;
  - `grpc_post_required`.
- The gRPC non-`POST` refusal is now logged once with status 200. With
  `FERRUM_DIAGNOSTIC_REFS=all`, gRPC-Web rejections are referenced and resolve with `status: 200`.
  The new contracts fixture `diagnostic-ref/valid/grpc-post-required.json` is accepted by Anvil's
  reader (`contracts_adoption.rs`, `diagnostic_import.rs`).
- None of these phases is ever a response header.
- The pre-dispatch 413 now runs reject-path `after_proxy` hooks and response-header policy. Its
  body is unchanged.

### gRPC-Web framed refusals (#7155)

On HTTP/1.1 and HTTP/2, gRPC-Web clients get a framed HTTP 200 trailer-frame refusal instead of the
native-gRPC header-only status:

- route protocol admission: grpc-status 7 (`gateway.routing.protocol_not_permitted`);
- an open circuit breaker: grpc-status 14, keeping `X-Gateway-Error: circuit_breaker_open`
  (`gateway.admission.circuit_open`).

The gRPC status each outcome records is unchanged.

### Unchanged taxonomy surfaces

`src/retry.rs` keeps the nine-token `HTTP_OBSERVABILITY_ERROR_CLASSES` list and the 19
`ErrorClass` labels. `StreamSetupKind` adds `L4RouteRefused`, which maps to
`dispatch_policy_rejected` like `SniAdmissionRefused` (`src/retry.rs:562`), and
`BackendFirstBytesForward`. Post-connect classification is phase-gated (#7213), so pre-wire classes
are no longer issued after connect. Those are operator log classes, not client signals.

## Upstream and streaming

### WebSocket backend refusals are relayed (#7414, GHSA-7x2j-3389-2h35)

`websocket_backend_refusal` (`src/proxy/mod.rs:16792`) walks the dial error chain for tungstenite's
`Error::Http` and the Sidecar mesh-mTLS Extended CONNECT refusal. A 3xx–5xx answer from a direct,
Unix-socket, Ambient HBONE or Sidecar mesh-mTLS backend is relayed on H1, H2 Extended CONNECT and
H3 Extended CONNECT (`send_h3_backend_refusal`, `src/http3/websocket.rs:416`). The client receives:

- its status;
- its headers after the backend-response strip and response policy (`WWW-Authenticate`,
  `Retry-After`, `Location`);
- its body when complete with the head (up to 64 KiB).

There is no `X-Gateway-Error` and no `error_class`, and the breaker counts the status as on the HTTP
path.

The gateway 502 `{"error":"Backend WebSocket connection failed"}` remains, with either token, for:

- a 2xx other than 101;
- an invalid `Sec-WebSocket-Accept`;
- a malformed response;
- the pre-wire dial failures.

`protocol.ws.backend_connect_failed` is narrowed accordingly. The absent-marker release note now
says a relayed WebSocket refusal carries no token. Successful upgrades also forward the backend's
end-to-end handshake headers (#7391), and `preserve_host_header` applies to WebSocket backends
(#7392). Neither changes a failure signal.

### Request-body refusals

The request-buffer budget now charges retained bytes as they arrive rather than the full ceiling up
front. That changes when a 503 `Request buffering capacity exceeded` happens, not its signal.
Uploads to a native HTTP/3 backend classify 413 / 499 / 400 by typed evidence (#7187). The bodies
are those already catalogued.

### Citation repoints

The H1/H2 request-body refusals (`size.request_body_too_large`, `gateway.capacity.request_buffer`,
`proxy.request_body_prebuffer_too_large`) are finalized by `boxed_finalize_request_body_read_refusal`
(`src/proxy/mod.rs:33518`). The shared body constant is `src/util/body_limit.rs:30`. The route
deadline wrapper is `await_backend_attempt_route_deadline` (`src/proxy/mod.rs:59666`). Global
overload admission reads `overload.request_admission.rejects()` (`src/proxy/mod.rs:36375`).

## Protocols and L4

- **WebSocket internal 500s** (`protocol.ws.upgrade_internal_error`, `src/proxy/mod.rs:17046`,
  `:17081`): now logged and counted under `invalid_backend_path` or
  `websocket_upgrade_unavailable`. The H1/H2 body is JSON on every arm.
- **L4.** `stream_match` refusals classify as `dispatch_policy_rejected` (#7185). A TCP relay ending
  on its idle window or half-close cap settles the breaker as a success (#7084). Both are operator
  signals.
- **HTTP/3.** Plain-bridge client terminals (authorization-expiry 401, oversized upload 413) no
  longer move backend health (GHSA-3c72-7f45-wvr2). The signal is unchanged.

## Authentication plugins

### Ambiguous query tokens (#7464, GHSA-c259-vchc-3vgr)

`jwt_auth` (`token_lookup: query:<name>`, `src/plugins/jwt_auth.rs:262`), `jwks_auth`
(`src/plugins/jwks_auth.rs:1862`) and `oauth2_introspection` (`src/plugins/oauth2_introspection.rs:1225`)
apply the `key_auth` issue #6579 contract to query token locations. A configured name that also
appears behind a `;` sub-parameter is an invalid credential format. Each plugin answers 401 with
`AMBIGUOUS_QUERY_TOKEN_BODY` (`src/plugins/utils/token_extract.rs:41`) and
`WWW-Authenticate: Bearer error="invalid_request"`:

- `jwt_auth` through `auth_flow`, `src/plugins/utils/auth_flow.rs:1101`;
- `jwks_auth` at `src/plugins/jwks_auth.rs:1721`;
- `oauth2_introspection` at `src/plugins/oauth2_introspection.rs:694`.

For `jwks_auth` and `oauth2_introspection` an alias at any provider's query location is terminal
for the instance. Three new outcomes, `plugin.{jwt_auth,jwks_auth,oauth2_introspection}.ambiguous_query_token`,
share one signal and name each other. `key_auth` keeps its own body.

### Other authentication changes

- **`hmac_auth`:** `signing_profile: ferrum-hmac-v1` and `allow_unsafe_replayable_v1` are removed
  (#7114). The v1 nonce refusal has no emitter, and `plugin.hmac_auth.nonce_not_accepted_v1` moves
  to `removed_outcomes`. Every remaining profile requires the nonce (`plugin.hmac_auth.missing_nonce`).
- **`jwks_auth`:** the singular `audience` is removed. Admin-managed JWKS (`jwks_source: managed://`)
  is a new key source whose withdrawal refuses tokens like an expired remote set. That is the
  existing `Invalid or unrecognized JWT` signal.
- **External identities:** consumer-name lists no longer match unmapped external identities
  (GHSA-rxwj-x6c6-f4j5), and `access_control` entries can bind an `authority`. Who is refused
  changes, not how.
- **`oidc_relying_party`:** post-login redirects are canonicalized (GHSA-6rwj-gc4r-3jm9). The target
  is judged at login start (`pending_flow_original_url`, `src/plugins/oidc_relying_party.rs:3322`),
  so a refused target no longer makes the challenge fail with 503.
  `plugin.oidc_relying_party.challenge_browser_pending_redirect_too_large` keeps its body
  (`src/plugins/oidc_relying_party.rs:2741`) and is reached less often.
- **`soap_ws_security`:** an assertion carrying only the SAML 1.x `AssertionID` is now refused. Which
  of the existing `soap_ws_security` refusal bodies it produces was not re-read; no new body literal
  appears at v0.9.21.

## Policy and transform plugins

- **Transformers (#7469, GHSA-pq95-952r-2x32).**
  - `request_transformer` with JSON body rules refuses a body that repeats an object member name, or
    that the rule engine cannot evaluate, with 400 (`AMBIGUOUS_JSON_BODY_ERROR`,
    `src/plugins/request_transformer.rs:1158`; `ambiguous_json_body_reject`, `:1160`).
  - `response_transformer` replaces such a backend response with 502
    (`src/plugins/response_transformer.rs:265`, `finalize_client_visible_response_body` at `:1580`).
  - The 502's `backend_error` token follows the backend-response builder's ≥500 mapping, as for the
    other response-side replacements. It was not lab-observed.
  - Two new outcomes. `plugin.request_transformer.no_runtime_failure` is narrowed: the plugin now
    has a runtime refusal.
- **`ip_restriction`:** `mode` is removed (#7114). An address failing both lists is always
  `IP address not allowed`.
- **`response_caching`:** `cache_key_include_*` is removed. `Vary`/`ETag`/`Last-Modified` are read
  case-insensitively (#7148). These change hit or miss, not refusal signals.
- **`request_mirror`:** a non-loopback cleartext mirror is refused at configuration. There is no
  runtime signal.

## AI, MCP and A2A plugins

- **`mcp_gateway` OpenAPI bridge (#7410).** A bridged call whose operation path is outside the
  matched proxy's literal listen prefix gets JSON-RPC −32603
  `OpenAPI bridge operation path is outside this proxy's route` (`src/plugins/mcp_gateway.rs:2318`;
  confinement in `bridge_backend_path`, `:11875`). Every bridged call on an exact or regex route
  gets the same answer. v0.9.20 already sent this message for a stripping prefix route, but no
  outcome listed it. New outcome `plugin.mcp_gateway.openapi_bridge_outside_route`.
  `discovery.hide_denied_items` is removed, and `emit_metadata: false` suppresses more `mcp.*`
  keys. Neither is a client signal.
- **`a2a_gateway` (GHSA-q25c-76f4-fp7h).** With Agent Card rewriting on for the `jsonrpc` binding,
  unclassifiable JSON-RPC is refused under any policy with the existing deny response (−32001, `a2a.error`
  `request_body_uninspectable`; `deny_response`, `src/plugins/a2a_gateway.rs:3126`). An oversized
  body is refused with the existing −32013. This is recorded on `plugin.a2a_gateway.jsonrpc_method_denied`.
- **Duplicate-member screens (GHSA-49cr-v28q-9hgp).**
  - `ai_prompt_shield` refuses with
    `Request blocked because the JSON request body has duplicate member names.`
    (`src/plugins/ai_prompt_shield.rs:1624`; MCP form `:1622`). This is recorded on
    `plugin.ai_prompt_shield.uninspectable`.
  - `ai_semantic_firewall` treats such a body as uninspectable, and `ai_rate_limiter` (with
    `model_limits`) refuses it. Neither adds a new body literal at v0.9.21. Which existing body each
    answers with was not re-read emitter by emitter.
- **AI translation (#7070, #7124, #7126).** `ai_federation` and `ai_stream_router` share one OpenAI
  translation admission. Malformed bounds, sampling values and tools are OpenAI-shaped 400s. The
  claim-time `tools` refusal now reports `param: "tools"`, `code: "invalid_tools"`. The bodies keep
  the existing `{"error":{"message":…,"type":"invalid_request_error",…}}` family the catalog matches
  by pattern.

## Mesh and lab configuration

Mesh data-plane work in v0.9.21 changes which requests are routed, authorized or refused, but not
the refusal signals the catalog records:

- Sidecar and NodeWaypoint VirtualService HTTP routes;
- wildcard DestinationRules;
- fail-closed markers for refused AuthorizationPolicy, PeerAuthentication and Sidecar resources;
- per-destination authorization of dispatch branches;
- EgressGateway TLS origination following the DestinationRule.

Two examples: a fail-closed DENY marker answers with the existing `plugin.mesh_authz.denied` 403,
and a refused carried route keeps its Service route. The lab changes for PeerAuthentication `scope`
are described [above](#lab-scenario-impacts-fixed-here). ConfigSync moves to revision 6, so the CP
and DP must run the same build. The lab's `cpdp` profile runs one binary for both.

## Not client-diagnostic

These are not catalogued:

- the Admin API: conditional consumer credential writes (412), managed TLS cross-namespace delete
  guards (409/503), `/admin/tls/jwks` admission (400), viewer-key ETag and generation withholding,
  the export fingerprint key, and the `charges:collect` scope;
- the `V001` baseline change and database rebuild;
- chart value removals and render checks;
- CNI fail-closed ADD;
- `ws_frame_logging` direction spelling;
- log sinks becoming `KeepLastKnownGood`;
- the DB-less admin audit retention file;
- the security advisories in CI policy and vendored patches.

## Removed outcomes

| Outcome | Removed in | Reason |
|---|---|---|
| `plugin.hmac_auth.nonce_not_accepted_v1` | v0.9.21 | #7114 removes the `ferrum-hmac-v1` signing profile; its `UNEXPECTED_NONCE_BODY` refusal has no emitter |

## Contracts and G01

`contracts/ferrum-contracts/PIN` pins `contracts-edge-0.9.21` at
`92d8da5be93ea1ece9f47729b1f7aa10ae8a7c3f`. Every vendored file is byte-exact from the tag.

- **Changed:**
  - `vocabularies/gateway-errors.json`: v0.9.21 provenance, and `circuit_breaker_open`'s rejection
    phases drop `circuit_breaker`.
  - `vocabularies/gateway-headers.json`: repinned. No gateway diagnostic header is added, removed
    or renamed, and `X-Ferrum-Diagnostic-Ref` stays `v0.9.9`.
  - `fixtures/invalid-expectations.json`.
- **New:** `fixtures/diagnostic-ref/valid/grpc-post-required.json` and
  `fixtures/diagnostic-ref/invalid/grpc-post-required-as-detail-phase.json`. Diagnostic-ref
  fixtures are now 11 valid and 13 invalid.
- **Unchanged:** the diagnostic-ref, finding and report schemas. `gateway_detail` needs no change:
  the raw `rejection.phase` is open, and `status: 200` is already admitted.

The pinned vocabulary covers the 0.9.21 catalog only (`contracts_adoption.rs` `PINNED_RELEASES`).
The 0.9.20 catalog keeps its historical mapping to `contracts-edge-0.9.20`.

## Qualification status

**Pending.** The catalog is source-audited, not yet live-qualified. Two hosted Lab runs check
this adoption against the v0.9.21 binary:

- the PR's own `lab.yml` run (all profiles on Ubuntu, core on macOS);
- a `workflow_dispatch` all-profile run on the adoption branch,
  [45972426825](https://github.com/ferrum-edge/ferrum-anvil/actions/runs/45972426825)
  (`profile=all`, `release=v0.9.21`, head `c1e3061a`).

Their results are recorded here once they finish, and on `main` after merge. No physical-device
native acceptance, platform signing, OAuth, provider-account or broader performance acceptance is
claimed.

[compare]: https://github.com/ferrum-edge/ferrum-edge/compare/e4a606a00352674daaef08636e3e359e6c48ba18...f9915358c8032214f4034a17c28cdf72d14006c3
[changelog]: https://github.com/ferrum-edge/ferrum-edge/blob/f9915358c8032214f4034a17c28cdf72d14006c3/CHANGELOG.md
[upgrade]: https://github.com/ferrum-edge/ferrum-edge/blob/f9915358c8032214f4034a17c28cdf72d14006c3/docs/upgrade_guide.md
[release]: https://github.com/ferrum-edge/ferrum-edge/releases/tag/v0.9.21
