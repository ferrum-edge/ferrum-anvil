# Ferrum Edge 0.9.8 → 0.9.9: client-observable delta (A00 addendum)

| Item | Value |
|---|---|
| Compatibility ids | `ferrum-edge-0.9.5`, `ferrum-edge-0.9.7`, `ferrum-edge-0.9.8` (unchanged) and `ferrum-edge-0.9.9` (new, the default for new profiles and the lab's default pin) |
| Releases compared | tag `v0.9.8` = `e27f2109216352c3fe9e67a7014611f3f66daa91` (`e27f210`) → tag `v0.9.9` = `234717ce41965cd1e2b5c6c761a25475c5d7628c` (`234717c`, the merge commit of release PR #5953) |
| Audit date | 2026-10-01 |
| Machine-readable inventory | [`catalog/ferrum/ferrum-edge-0.9.9/outcomes.json`](../../catalog/ferrum/ferrum-edge-0.9.9/outcomes.json): **553** outcomes (540 + 13 added, none removed), 16 changed, 1,406 source citations |
| Baseline audit | [`gateway-0.9.8-delta.md`](gateway-0.9.8-delta.md) and [`catalog/ferrum/ferrum-edge-0.9.8/outcomes.json`](../../catalog/ferrum/ferrum-edge-0.9.8/outcomes.json) |
| Source diff | 129 files under `src/` differ; 27,607 insertions and 3,989 deletions (`src/plugins/mcp_gateway.rs` 2,403 changed lines, `src/proxy/mod.rs` 2,103, `src/diagnostic_ref.rs` 2,097 new, `src/proxy/gateway_listener.rs` 1,901) |
| Wire libraries | rustls 0.23.45, hyper 1.9.0, h2 0.4.19, h3 0.0.8, quinn 0.11.9, reqwest 0.13.3 and hyper-util 0.1.21 unchanged in `Cargo.lock`; hyper is now vendored with three Ferrum patches (`vendor/hyper-1.9.0-ferrum-patched/`: the upgraded-stream `CONNECT_ERROR` reset, the HTTP/2 body-pipe capacity claim, the HTTP/1 TLS read-ahead) |
| Release pin | `lab/gateway/RELEASE.lock` = `lab/gateway/releases/v0.9.9.lock`: the published `.sha256` of each release asset (identical to the GitHub asset digests) |
| Contracts | `contracts/ferrum-contracts/` re-vendored from `ferrum-contracts` `contracts-edge-0.9.9` (`25c4e9e`), which refreshes the vocabularies from v0.9.9 and marks `X-Ferrum-Diagnostic-Ref` released |

All `path:line` citations below are at `v0.9.9` (`234717c`) unless marked otherwise.

## Method

- **Read-only.** Both tags were read with `git show` / `git diff` from a clone of
  `ferrum-edge/ferrum-edge`. The gateway repository was never checked out, built or run.
- **Mechanical carry-forward.** Every source citation of the 540 carried outcomes was remapped
  through the `git diff -U0 v0.9.8 v0.9.9` line map of its file, and the cited line text is
  identical in both trees. Eight citations landed in changed hunks and were re-cited by hand: the
  frontend canonical-path rejection (now `canonicalize_request_path`, `src/proxy/mod.rs:32603`), the
  auth-flow 403 arm (`src/plugins/utils/auth_flow.rs:665`), three graphql document refusals
  (`src/plugins/graphql.rs:717`, `:1273`, `:759`), the `rate_limiting` 429 literal
  (`src/plugins/rate_limiting.rs:681`), the `mcp_gateway` tools/call policy denial
  (`src/plugins/mcp_gateway.rs:4863`) and the gateway-owned header list (`src/proxy/headers.rs:852`).
  Path:line references in prose were remapped the same way. Every citation carries sha `234717c`.
- **Changed-function screen.** An outcome was flagged when a hunk of the diff falls inside the
  function around any of its citations: 100 outcomes, most of them in the very large
  `src/proxy/mod.rs`, `src/http3/server.rs` and `src/plugins/mcp_gateway.rs` functions. For each, the
  public literals (status, JSON body, header names, gRPC status, JSON-RPC code, close code) were
  compared between the trees; the ones whose behaviour changed were re-read and are listed under
  "Changed outcomes". The rest keep their public signal; their diff hunks add diagnostic-reference
  recording, attempt spans or refactors.
- **Literal diff.** Status, JSON body, JSON-RPC code, close-code and rejection-phase literals were
  diffed per file between the trees, to catch new or removed signals the screen missed. New
  proxied-response literals: `Request path contains an empty path segment`, `Request path contains
  a path parameter`, `Misdirected Request`, `Backend WebSocket extension negotiation failed`,
  JSON-RPC `-32014` to `-32017`, the `ai_prompt_shield` MCP refusals, the graphql strict-lexer
  messages, the `1007` / `1009` deflate closes and the transaction phase
  `websocket_permessage_deflate`. None was removed except the graphql message "Query contains
  fragments but could not be structurally analyzed". The admin API's new literals (diagnostic
  reference lookup, configuration export, MCP tool catalog) are outside the proxied inventory.
- **CHANGELOG.** Every `[0.9.9]` entry was checked against the code and the merged PRs
  (`git log --first-parent v0.9.8..v0.9.9`, 81 merges). The ones that change a proxied response are
  recorded below; the rest under `drift` (`not_client_observable`, `admin_api`).
- **Mechanical checks of the result.** Every citation points at a non-blank line at `v0.9.9`; every
  prose `path:line` reference is in range; the drift test
  (`crates/anvil-diagnostics/tests/catalog_drift.rs`) checks the four catalogs for internal
  consistency.
- **Not verified live.** This change was prepared without running the lab or any test. GitHub CI
  runs the `core` profile against the new default pin on the pull request; the nightly lab runs
  every profile against v0.9.9, v0.9.8, v0.9.7 and v0.9.5. Until then the v0.9.9 lab expectations
  below are source-derived.
- **Not a completeness proof.** As with the earlier audits, only strings seen in code are
  recorded, and wire behaviour owned by hyper, h2, rustls or quinn is marked as such.

## Unchanged: the marker contract

`src/retry.rs` differs only in the visibility of one private helper. The eight `X-Gateway-Error`
tokens, the 19 error classes, `request_reached_wire`, `should_retry` and the
`(connection_error, status)` derivation (`src/retry.rs:287`) are unchanged, and so are
`x_gateway_error_for_response` and the H1/H2 and HTTP/3 writers. `contracts-edge-0.9.9` confirms it:
the error vocabulary has no value change from v0.9.8. The 0.9.9 catalog's `marker_semantics` carry
the 0.9.8 sentences with the release name changed.

`X-Ferrum-Diagnostic-Ref` joins the gateway-owned list (`src/proxy/headers.rs:852`), so a backend copy
is stripped at every backend response boundary like the two markers, and a plugin copy at the final
client boundary (`src/diagnostic_ref.rs:1651`). The markers stay spoofable on plugin rejection paths
and from non-Ferrum endpoints, so marker-derived claims stay capped at likely.

## New outcomes

| Outcome | Public signal | Where | Notes |
|---|---|---|---|
| `frontend_parse.empty_path_segment` | 400 `{"error":"Request path contains an empty path segment"}`; gRPC 3 | `src/policy_path.rs:300`, `:444`; `src/proxy/mod.rs:32603`; `src/http3/server.rs:2871` | GHSA-fcqw-793q-wg5x (PR #5936). `//admin`, `/a//b`, `/;x/admin` on every proxy, before routing. |
| `gateway.routing.path_parameter_refused` | 400 `{"error":"Request path contains a path parameter"}`; gRPC 3 | `src/policy_path.rs:301`, `:604`; `src/proxy/mod.rs:31164`, `:33348`; `src/http3/server.rs:3324`; `src/router_cache.rs:3863` | GHSA-fcqw-793q-wg5x (PRs #5936, #5945, #5947). A `;` (or `%3B`) on a proxy without `allow_path_parameters`, or whose stripped path belongs to another proxy. Breaking for `;jsessionid=` clients. |
| `gateway.routing.listener_retired` | 421 `{"error":"Misdirected Request"}` (HTTP/1.x adds `Connection: close`); gRPC 14 | `src/proxy/mod.rs:32045`; `src/http3/server.rs:3186`; `src/proxy/gateway_listener.rs:389` | #5921 (PR #5927). Gateway API listeners only; replaces the reload window of 404s. |
| `plugin.mcp_gateway.admission_changed` | 200 JSON-RPC `-32014` "MCP request changed after gateway admission" | `src/plugins/mcp_gateway.rs:97`, `:6555` | GHSA-3w98-6p32-8qm2 (PR #5905). Final-body re-check of the admitted MCP request. |
| `plugin.rate_limiting.mcp_tool_calls_exceeded` | 200 JSON-RPC `-32015` "MCP tool-call rate limit exceeded" | `src/plugins/rate_limiting.rs:120`, `:939`, `:1398` | #5908 (PR #5943). One error per batch member. |
| `plugin.rate_limiting.mcp_tool_calls_unavailable` | 200 JSON-RPC `-32016` "MCP tool-call rate limit unavailable" | `src/plugins/rate_limiting.rs:124`, `:939`, `:1398` | `redis_failure_policy: fail_closed` during an outage. |
| `plugin.rate_limiting.mcp_uninspectable_encoding` | 200 JSON-RPC `-32017` "MCP request content encoding cannot be inspected" | `src/plugins/rate_limiting.rs:129`, `:939`, `:1398` | Any non-identity `Content-Encoding` on an in-scope POST. |
| `plugin.ai_prompt_shield.mcp_arguments_refused` | 400 `{"error":"MCP JSON-RPC id cannot be preserved during redaction",…}` and two siblings | `src/plugins/ai_prompt_shield.rs:2053`, `:2069`, `:2085` | #5908 (PR #5943), `scan_fields: mcp_arguments`. |
| `protocol.ws.backend_extension_negotiation_failed` | 502 `{"error":"Backend WebSocket extension negotiation failed"}` | `src/proxy/mod.rs:16283`; `src/http3/websocket.rs:1449` | #5769 (PRs #5853, #5869). Only with `websocket_permessage_deflate: passthrough` or `terminate`. |
| `protocol.ws.close_invalid_payload_1007` | WebSocket close 1007 "invalid compressed data" | `src/proxy/ws_permessage_deflate.rs:659` | `terminate` only. |
| `plugin.mcp_gateway.openapi_bridge_error_result` | 200 JSON-RPC result `isError: true`, text `HTTP <status> <reason> (gateway error: <token>)` | `src/plugins/mcp_openapi_bridge.rs:1465`, `:1567`, `:1401` | #5906 (PR #5930). Not matched by body; recorded so a gateway-authored tool error is not mistaken for the tool's own. |
| `frontend_parse.proxy_protocol_header_rejected` | connection closed before TLS/HTTP | `src/proxy/frontend_proxy_protocol.rs:220`, `:56` | #5768 (PRs #5838, #5849). Opt-in, off by default. |

## Changed outcomes

### Canonical request path (GHSA-5mrg-vq2h-6j3w, GHSA-fcqw-793q-wg5x; PRs #5933, #5936, #5945, #5947)

| Outcome | Change | Evidence |
|---|---|---|
| `frontend_parse.ambiguous_path_encoding` | A segment whose text before its first `;` is `.` or `..` (`..;`, `.;x`, `..;jsessionid=1`) is a dot segment: the same "dot segment" / "encoded dot segment" bodies. The canonicalizer is now `canonicalize_request_path`. | `src/policy_path.rs:394`; `src/proxy/mod.rs:32603` |

`;` itself is accepted only on a proxy with `allow_path_parameters` (new outcome above). On such a proxy
the request is re-resolved with every parameter removed and refused when that path belongs to another
proxy; a less specific ancestor of a literal `;` `listen_path` does not count (#5938, PR #5945), and
the re-resolve repeats the request's mesh resolution (#5937). GHSA-653r-wc8x-4fch (same PR) stops
`ai_stream_router` / `ai_federation` from decoding the query of a provider override path; it changes
what the provider receives, not a gateway-authored signal.

### Mesh authorization (PRs #5950, #5952; #5903)

| Outcome | Change | Evidence |
|---|---|---|
| `plugin.mesh_authz.denied` | On a route that allows `;` parameters, `paths` / `notPaths` and `request.headers[:path]` are judged on the raw and the parameter-stripped path: DENY, CUSTOM and AUDIT on either, ALLOW on both (#5948). `connection.sni` values and the received SNI are normalized, so a DENY on `admin.example.com` also fires for `admin.example.com.` (#5903). A `to.headers` pseudo-header rule is refused at config validation (#5951, PR #5952). Same 403 body. | `src/plugins/mesh/authz.rs:3087`; `src/modes/mesh/policy.rs:492` |

### MCP (PRs #5905, #5919, #5930, #5943)

| Outcome | Change | Evidence |
|---|---|---|
| `plugin.mcp_gateway.tool_denied` | Also a group-conditioned tool the request's Consumer is not granted (`allowed_groups` / `denied_groups`), re-decided at the final body, and a bridged tool whose method the route's `allowed_methods` refuses. | `src/plugins/mcp_gateway.rs:4863`, `:8803` |
| `plugin.mcp_gateway.unknown_item` | With grants configured, an unknown tool answers `-32001` (tool_denied) instead of `-32003`. | `src/plugins/mcp_gateway.rs:4833` |
| `plugin.mcp_gateway.session_not_found` | External-identity sessions are bound to their authentication realm (GHSA-wr96-j2c3-qh66), so another issuer's same `sub` gets this 404. | CHANGELOG [0.9.9] Security |
| `plugin.mcp_gateway.invalid_request` | `rate_limiting`'s `mcp_tool_calls` answers an unscannable body with the same `-32600` body. | `src/plugins/rate_limiting.rs:984` |
| `plugin.ai_prompt_shield.uninspectable` | With `scan_fields: mcp_arguments`, duplicate member names give the same error with its own message. | `src/plugins/ai_prompt_shield.rs:1202` |
| `plugin.rate_limiting.exceeded` | With `mcp_tool_calls`, refusals are JSON-RPC errors on HTTP 200 instead (new outcomes); the 429 is unchanged otherwise. | `src/plugins/rate_limiting.rs:681`, `:939` |

`aggregate_router`'s `initialize` advertises `listChanged: false` (#5907); the admin
`GET /proxies/{id}/mcp/tools` catalog (#5926, PR #5949) is an admin-API read.

### Gateway listeners (PRs #5913, #5918, #5927)

| Outcome | Change | Evidence |
|---|---|---|
| `gateway.routing.no_route` | Reloads no longer answer this 404 on listener routes that were already serving; a retired listener answers 421 instead; a wrong-class route on a process-global port is refused at validation instead of blacking out that frontend with 404s. | `src/proxy/mod.rs:32045` |

### HBONE relays (PRs #5856, #5863)

| Outcome | Change | Evidence |
|---|---|---|
| `protocol.hbone.tunnel_admission_revoked` | The CONNECT stream is reset with `RST_STREAM(CONNECT_ERROR)` instead of a clean `END_STREAM`, for a revocation and for every other relay ending except a peer close or idle expiry (socket errors, backend read/write deadlines, a datagram write stall, the TCP half-close cap). | `src/proxy/hbone_proxy.rs:305`, `:514`, `:526` |

### Other

| Outcome | Change | Evidence |
|---|---|---|
| `plugin.graphql.document_rejected` | Strict GraphQL lexing (GHSA-chqw-m79r-hgjx, PR #5902): documents that do not lex or parse are refused with "Malformed GraphQL document: {detail}" or "Query spreads a fragment the document does not define"; the heuristic fallback scan is gone. | `src/plugins/graphql.rs:759`, `:1273` |
| `plugin.graphql.uninspectable_transport` | A JSON body repeating `query`, `operationName`, `variables` or `extensions` is refused. | `src/plugins/graphql.rs:1765`, `:1856` |
| `protocol.ws.close_too_big_1009` | `terminate` adds the deflate size closes ("compressed frame too large", "decompressed frame too large", "decompressed message too large"). | `src/proxy/ws_permessage_deflate.rs:650` |
| `protocol.ws.backend_connect_failed` | An upgrade refused by the gateway's own dial policy is refused before an attempt begins (same 502). | PR #5877 |
| `plugin.waf.request_rule_block` | `on_unlisted_content_type`, detection paranoia band, category modes, field exclusions, broader normalization and rule pack (PRs #5837, #5841, #5847, #5848, #5873, #5876, #5887). Same 403. | `src/plugins/waf/mod.rs:748` |
| `gateway.admission.config_stale` | ConfigSync requires the same build on CP and DP (PR #5882); a skewed DP keeps its last-known-good config and eventually answers this 503. | CHANGELOG [0.9.9] Changed |

### Other catalog-level changes

- `headers` gains `X-Ferrum-Diagnostic-Ref`: opaque `fd1_` / `fd2_` reference, sent only when
  `FERRUM_DIAGNOSTIC_REFS` is `errors` or `all` (default `off`), gateway-owned
  (`spoofable_by_backend: false` for backend copies; a non-Ferrum endpoint can still send it). The
  `X-Gateway-Error` spoofing notes and the `X-Ferrum-*` entry mention it.
- `rejection_phases_operator_only` gains `websocket_permessage_deflate`.
- `removed_outcomes` is empty: nothing catalogued at 0.9.8 is gone.
- `fixture_index` maps the lab's AUTH-021 to `gateway.routing.path_parameter_refused`.
- The `drift` section records the v0.9.8 → v0.9.9 reconciliation, including the changes with no
  catalogued signal: the `x-consumer-*` request-header namespace (PR #5880), mesh compatibility shims
  (PR #5883; a single-port Sidecar inbound route now fails closed with 502 on a mismatched explicit
  port, an outcome that was not catalogued at 0.9.8 either), HTTP/1 and HTTP/2 framing fixes (PRs
  #5895, #5897, #5899, #5900, #5909, #5917), the admin API (PRs #5923, #5941, #5942, #5946, #5949)
  and observability-only work (otel attempt spans, UDP port handoff, Docker publishing).

## Anvil changes this delta drives

- **Catalogs.** `anvil_diagnostics::ferrum` embeds `ferrum-edge-0.9.9` and makes it the default for
  new profiles (desktop dialog, CLI `--trust-ferrum`). The 0.9.9-only outcomes match only a profile
  declaring `ferrum-edge-0.9.9`.
- **Wording.** No new finding codes: the new outcomes are worded from the catalog through
  `ferrum.outcome`, and no new `X-Gateway-Error` token exists.
- **Contracts.** `contracts/ferrum-contracts/` is re-vendored from `contracts-edge-0.9.9`
  (`vocabularies/gateway-errors.json` and `vocabularies/gateway-headers.json` change; the schema and
  fixtures are byte-identical). The drift test (`crates/anvil-diagnostics/tests/contracts_adoption.rs`)
  pins the new tag and commit, compares the 0.9.9 catalog with the vocabularies, requires
  `X-Ferrum-Diagnostic-Ref` to be released in v0.9.9, and listed it as released but not read by
  Anvil's rules when this catalog was added. G01 adoption (#224) since vendored the
  `diagnostic-ref` schema and fixtures, counts the header among those Anvil reads, and checks Anvil's
  lookup reader against the schema (`docs/diagnostics.md`, "Gateway diagnostic references").
- **Lab.** The default pin is v0.9.9 (`lab/gateway/RELEASE.lock`, `lab/gateway/releases/v0.9.9.lock`);
  v0.9.8 joins the earlier supported releases and the nightly matrix. The lab profiles validate on
  v0.9.9 unchanged: `src/config/types.rs` only adds `Proxy` fields (`allow_path_parameters`,
  `websocket_permessage_deflate`) and the plugins the lab configures only gain keys
  (`lab/gateway/lint-profiles.rb`).

## Lab

Expected release differences (source-derived; see "Not verified live" above):

| Scenario | v0.9.5 / v0.9.7 / v0.9.8 | v0.9.9 |
|---|---|---|
| AUTH-021 (HMAC over a path with sub-delims) | signs and sends `/auth/hmac/echo/a;b=c/x:y@z` | the `;` path is refused 400 `Request path contains a path parameter` before `hmac_auth` (backend untouched); the signing check uses `/auth/hmac/echo/a,b=c/x:y@z`. The route cannot opt in with `allow_path_parameters`, which older releases reject as an unknown field. |
| MESH-026, MESH-027 (UDP relay ends on the workload port's ICMP error) | clean `END_STREAM` (debug `… ended on a socket error` from 0.9.8) | `RST_STREAM(CONNECT_ERROR)` on the CONNECT stream; the lab checks the channel's reset code on v0.9.9 and later |

The scenarios pick the release's expectation with `gateway::release_at_least("v0.9.9")`. Every other
scenario keeps its expectation: the lab sends no `;` or empty segment elsewhere, leaves
`FERRUM_DIAGNOSTIC_REFS`, the frontend PROXY protocol and `websocket_permessage_deflate` at their
defaults, configures no WAF built-in rules, graphql plugin or `x-consumer-*` header writes, and sends
no explicit port to the mesh Sidecar inbound listener.

## Not verified live (source only)

- Everything in this delta until the nightly lab has run v0.9.9, including AUTH-021 and MESH-026/027
  above.
- The Gateway listener retirement 421, the OpenAPI bridge, MCP grants and AI governance, the WebSocket
  deflate modes and the frontend PROXY protocol: the file-mode lab has no Gateway API listeners and
  configures none of these features.
- The admission re-check `-32014`: it needs a plugin that rewrites an MCP request after admission.
- Library-owned details (HTTP/2 and HTTP/3 reset codes, FIN vs RST, HTTP/1 framing) belong to the
  vendored hyper, h2, h3 and quinn.

## Addendum: catalog gap backfilled for issue #282

The original v0.9.9 audit omitted an `ai_prompt_shield` refusal already
present in that release. With `scan_fields: mcp_arguments`, a non-identity
`Content-Encoding` on an in-scope MCP POST is refused with HTTP 400 and
`{"error":"MCP request body could not be inspected","message":"unsupported_content_encoding"}`
before dispatch, including when the action is `warn`. The body builder is at
`src/plugins/ai_prompt_shield.rs:498`, and the refusal is at `:1858` in
Ferrum Edge v0.9.9 (`234717c`). The catalog now records this as
`plugin.ai_prompt_shield.mcp_body_uninspectable`; this is a catalog correction,
not a gateway behavior change. The 0.9.10 catalog also records the two newer
reasons, `unsupported_charset` and `jsonrpc_request_unparseable`.
