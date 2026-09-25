# Ferrum Edge gateway source audit (A00): client-observable outcomes

| Item | Value |
|---|---|
| Compatibility id | `ferrum-edge-0.9.5` |
| Pinned release | tag `v0.9.5` = `20e76030a05dc49c3804e969516c94ab101110b9` (short `20e7603`), the latest published release |
| Compared refs | `8ef06f2cece2847b552b7858c73fa9a1a265442f` (tag `v0.9.6`: tagged, never published; the handoff plan's reviewed SHA) and `origin/main` `8fed1346ce2e267eb69c03683cb89ea44d785e0b` (release prep for v0.9.7, which ships the 0.9.6 content) |
| Audit date | 2026-09-25 |
| Machine-readable inventory | [`catalog/ferrum/ferrum-edge-0.9.5/outcomes.json`](../../catalog/ferrum/ferrum-edge-0.9.5/outcomes.json) (528 outcomes) |
| Libraries that decide some wire behaviour (v0.9.5 `Cargo.lock`) | hyper 1.9.0, h2 0.4.19, rustls 0.23.40, h3 0.0.8, quinn; vendored patches for reqwest, h3, h3-quinn and tungstenite |

## Method

- **Read-only.** The gateway repository was never modified, checked out or switched. Every file was read from `git archive v0.9.5`, so every `path:line` in this report equals `git show v0.9.5:<path>` line numbers. All citations are at `20e7603` unless stated.
- **Core paths were read directly:** `src/retry.rs` (whole file), the admission, routing, backend-failure and response-builder sections of `src/proxy/mod.rs`, `src/proxy/headers.rs`, `src/proxy/response_buffer_budget.rs`, `src/dp_config_freshness.rs`, `src/overload.rs`, `src/tls/mod.rs`, `src/tls/multi_cert.rs`, `src/proxy/stream_error.rs`, `src/proxy/h1_framing_guard.rs` and `src/proxy/body.rs`.
- **Plugins and protocols were covered by parallel read-only sub-audits:** auth/authorization plugins, traffic/WAF/validation/transform plugins, AI/agent plugins, and gRPC/WebSocket/HTTP/2/HTTP/3. I spot-checked their key literals and line numbers against the source and corrected the ones that were off.
- **Only strings seen in code are recorded.** Where the wire behaviour belongs to hyper, h2, rustls or quinn rather than Ferrum code, the entry says so and needs lab verification.
- **This is not a completeness proof.** `src/proxy/mod.rs` alone is 68,475 lines and `src/http3/server.rs` is 20,107. A grep count does not prove coverage. See "Gaps / not audited".

## Inventory at a glance

**Counts**
- **528 outcomes** by family: auth 137, policy 95, ai_policy 57, protocol 43, upstream_network 34, transform 29, size_limit 24, gateway_admission 24, rate_limit 19, authorization 17, streaming 14, waf 9, frontend_parse 8, frontend_tls 7, gateway_routing 6, l4 5.
- **67 outcomes** list at least one indistinguishable sibling in `shared_signal_with`.
- **19** error classes, **7** public tokens and **14** header entries.
- **68** plugin identifiers are covered: every built-in that can reject or synthesize a response, plus the no-signal plugins and custom plugins.

**How the file is organised**
- **Top-level keys:**
  - `error_class_semantics`: one row per class.
  - `grpc_reject_status_mapping`.
  - `rejection_phases_operator_only`.
  - `drift`: v0.9.5 compared with 8ef06f2 and main.
  - `fixture_index`: matrix case id to outcome ids.
  - `matrix_seed_reconciliation`.
- **Id prefixes:** `upstream.*`, `gateway.*`, `size.*`, `frontend_parse.*`, `frontend_tls.*`, `streaming.*`, `l4.*` and `auth.*` are the core outcomes. `protocol.*` holds gRPC, WebSocket, HTTP/2 and HTTP/3 outcomes. `plugin.*`, `proxy.auth_*`, `generic.*` and `size_limit.*` hold plugin outcomes.

**Field conventions**
- `http_status`, `grpc_status` and `ws_close_code` are integers or null.
- When a value is not fixed, it is null and the text goes in a sibling `*_note` field. For example, the status is the backend's own, or the token is whatever a plugin sets.
- Body templates mark dynamic parts as `{name}` or `<name>`. In SSE bodies, `\n` stands for a line feed.

## Headline findings for diagnostic design

1. **`X-Gateway-Error` is not a 5xx-only header, and not a gateway-only one.**
   - Native-gRPC trailers-only rejects are HTTP **200**. They carry `x-gateway-error: circuit_breaker_open` or `concurrency_limit` on every frontend, and `overload` / `config_stale` on HTTP/3 only. The HTTP/1 and HTTP/2 gRPC siblings of the overload and config_stale fences carry no header, and neither does any gRPC backend dispatch error.
   - Backend copies of the header are stripped on the plain HTTP builders. No strip exists on the native-gRPC response path, so a gRPC backend can inject the header.
   - Plugin reject maps are not sanitized, so any plugin, including custom ones, can emit the header on a rejection.
2. **Token to status is not one-to-one, and `backend_error` does not mean "the backend returned 5xx".**
   - `backend_error` is also stamped on gateway-local refusals with no backend fault:
     - 503 `{"error":"Response buffering capacity exceeded"}`
     - 503 `{"error":"HTTP/1.1 in-flight request limit reached"}`
     - 503 `{"error":"Backend connection limit exceeded"}` (reqwest lane)
     - 502 egress-policy and DNS-override refusals
     - response-phase plugin 5xx replacements
   - `backend_timeout` is keyed on status 504 alone (`src/retry.rs:284`), so a backend's own 504 gets it too.
   - `overload` is used both for the 503 overload/drain fence and for a **502** response-transformer output ceiling.
3. **At v0.9.5 a 504 `backend_timeout` does not prove the backend received the request.** A pooled HTTP/1 connection that closes while the request is being enqueued strands the request until `backend_read_timeout_ms` (default 30 s) expires. Fixed in 0.9.6: it now fails straight away as 502 `connection_failure`.
4. **The same misconfiguration can produce different public signals depending on dispatch path.**
   - **Backend mTLS rejection on the reqwest HTTP/1 pool:**
     - If hyper reports the request as canceled: `connection_pool_error`, which maps to `connection_failure`.
     - If a rustls alert arrives after TCP connect: `connection_reset`, which maps to `backend_error`.
     - Both return the body `{"error":"Backend unavailable"}`.
   - **Backend `maxConnections` ceiling:**
     - reqwest lane: 503 `Backend connection limit exceeded` + `backend_error`.
     - direct-H2 / H3 / gRPC pools: 502 `Backend unavailable` + `connection_failure`, or gRPC 14.
     - WebSocket: 503 with no token.
   - **DNS failure:**
     - reqwest preflight: 502 `{"error":"Backend DNS resolution failed"}` + `connection_failure`.
     - Pools: the generic 502 `Backend unavailable`.
     - An egress-policy denial reuses the DNS body but carries `backend_error`.
5. **Overload and shutdown drain are byte-identical** (503 `{"error":"Service overloaded"}` + `overload`). Connection-level shedding (`reject_new_connections`, `FERRUM_MAX_CONNECTIONS`) is not HTTP at all: the accepted socket is dropped.
6. **Streaming failures after the status line never produce a gateway marker.**
   - HTTP/1.1 streaming responses are always chunked with `Content-Length` removed, so truncation shows as a missing terminal chunk plus connection close.
   - HTTP/2 gets a stream reset chosen by hyper.
   - HTTP/3 gets `RESET_STREAM(H3_INTERNAL_ERROR)`.
   - Only native gRPC gets synthesized `grpc-status` trailers, and only before any DATA.
7. **Identity-provider outages can look exactly like bad credentials.**
   - `jwks_auth` with keys more than 3600 s stale returns the same 401 `{"error":"Invalid or unrecognized JWT"}` as a bad signature.
   - mesh ext-authz outage defaults to the same 403 as a deny.
   - OPA, introspection, LDAP and the HMAC/DPoP replay stores do fail distinguishably, with a 5xx.
8. **Ferrum-like markers exist, but none authenticates the gateway.**
   - `Via: <ver> ferrum-edge`: on by default, configurable, and only on backend-path responses.
   - `WWW-Authenticate: ferrum-edge` or `Basic realm="ferrum-edge"`.
   - The seven tokens, the `{"error":"..."}` body family, and `gateway-error-reason`.
   - There is no `Server` header and no `X-Ferrum-*` header on proxy responses.
9. **`X-Gateway-Upstream-Status: degraded` is spoofable by any backend** on the HTTP/1 and HTTP/2 builder path: it is not stripped when the gateway did not use fallback.
10. **WebSocket closes authored by the gateway use only 1001, 1002, 1008, 1009 and 1011**, each with a fixed reason string. A backend's Close frame is relayed verbatim. Tunnel mode drops the transport without a Close frame.
11. **Several gateway outcomes look like something else.**
    - `fault_injection`, `response_mock` and `request_termination` responses are unmarked. The default termination is 503 `{"message":"Service unavailable","status_code":503}` with no token.
    - `graphql`, `mcp_gateway`/`a2a_gateway` and `ai_federation` author GraphQL-shaped, JSON-RPC-shaped (often under HTTP 200) and OpenAI-shaped errors.
    - Release builds use `panic = "abort"`, so a panic in any plugin kills the gateway process. Every in-flight client sees a connection reset.
12. **`Retry-After` is almost never sent.** It appears only on `spec_expose` responses, plus provider values that `ai_federation` passes through. The overload, circuit-breaker, concurrency and rate-limit rejects carry none.

## 1. Error classes (`ErrorClass`) and the public token set

`ErrorClass::ALL` has exactly **19** variants (`src/retry.rs:180-200`). Their serialized names come from `as_str`, `src/retry.rs:151-173`. The client-visible `X-Gateway-Error` vocabulary is exactly **7** tokens (`src/retry.rs:212-238`):

`connection_failure`, `backend_timeout`, `backend_error`, `circuit_breaker_open`, `overload`, `config_stale`, `concurrency_limit`

These spellings match the handoff plan. The HTTP metric label set has 24 values: the 19 classes plus 5 non-class tokens (`src/retry.rs:252-275`). Logs carry the granular class. The header carries only the coarse token. Nothing in the response carries `error_class` or `rejection_phase`.

How the header is derived on HTTP backend-dispatch responses:
- The value comes from `(connection_error, final status)` only, via `http_observability_error_class` (`src/retry.rs:281-291`): `connection_error` gives `connection_failure`, status 504 gives `backend_timeout`, any other status of 500 or more gives `backend_error`, and anything else gives no header.
- `connection_error` is `!request_reached_wire(class)` (`src/retry.rs:448-460`, `src/proxy/mod.rs:42803-42817`).
- The typical body pair is `http_backend_failure_status_and_body` (`src/proxy/mod.rs:42788-42797`): a read/write timeout gives 504 `{"error":"Backend timeout"}`, and every other class gives 502 `{"error":"Backend unavailable"}`.

Column notes for the table below:
- **Reached wire**: whether the gateway treats the request as possibly sent (`request_reached_wire`). This is a conservative retry boundary, not proof that the application processed the request.
- **Retry** (`should_retry`, `src/retry.rs:1846-1892`):
  - "Connect retry" means the class is retried when `retry_on_connect_failure` is on, for any method.
  - "Status retry" means it is retried only if both `retryable_methods` and `retryable_status_codes` match.
  - "Never" is enforced at `src/retry.rs:1856-1870`.
- **Neutral**: `client_side_no_backend_signal` (`src/proxy/backend_dispatch.rs:1143`). A neutral class does not trip the circuit breaker or charge passive health.

| # | Class (`src/retry.rs` variant line) | Reached wire | Typical token | Typical client HTTP | Retry | Neutral | `error_kind` log |
|---|---|---|---|---|---|---|---|
| 1 | `connection_timeout` (27) | no | connection_failure | 502 Backend unavailable | connect retry | no | connect_timeout |
| 2 | `connection_refused` (29) | no | connection_failure | 502 Backend unavailable | connect retry | no | connect_failure |
| 3 | `connection_reset` (33) | yes | backend_error | 502 before headers, or truncated stream after them | status retry | no | connection_reset |
| 4 | `connection_closed` (35) | yes | backend_error | 502 before headers, or truncated stream after them | status retry | no | connection_closed |
| 5 | `dns_lookup_error` (37) | no | connection_failure | 502 `Backend DNS resolution failed` (reqwest) or `Backend unavailable` (pools) | connect retry | no | dns_failure |
| 6 | `tls_error` (44) | no | connection_failure | 502 Backend unavailable | connect retry | no | tls_error |
| 7 | `read_write_timeout` (47) | yes | backend_timeout | 504 Backend timeout | status retry | no | read_timeout |
| 8 | `client_disconnect` (49) | yes | only when the public status is 5xx | 408, 499 (internal) or the auth-expiry 401 | never | yes | client_disconnect |
| 9 | `protocol_error` (51) | yes | backend_error | 502, or an HTTP/2 or HTTP/3 reset | status retry | no | protocol_error |
| 10 | `response_body_too_large` (53) | yes | backend_error | 502 Backend response body exceeds maximum size | never | no | response_body_too_large |
| 11 | `gateway_buffer_capacity` (66) | yes | backend_error (see drift) | 503 Response/Request buffering capacity exceeded | never | yes | gateway_buffer_capacity |
| 12 | `request_body_too_large` (68) | yes | none (4xx) | 413 | never | yes | request_body_too_large |
| 13 | `connection_pool_error` (72) | no | connection_failure | 502 Backend unavailable | connect retry | no | pool_error |
| 14 | `port_exhaustion` (74) | no | connection_failure | 502 Backend unavailable | connect retry | no | port_exhaustion |
| 15 | `graceful_remote_close` (85) | yes | backend_error | 502 (HTTP/3 before headers), or a WebSocket normal close | status retry | no | graceful_remote_close |
| 16 | `dispatch_policy_rejected` (94) | yes (by design) | backend_error, or overload for the transformer ceiling | various 502/503 gateway bodies | never | yes | dispatch_policy_rejected |
| 17 | `backend_connection_limit` (119) | no | connection_failure | 502 on the pools; the reqwest lane uses 503 + `dispatch_policy_rejected` | connect retry | yes | backend_connection_limit |
| 18 | `trust_withdrawn` (144) | no | connection_failure | 502 (mesh transports only) | connect retry | yes | trust_withdrawn |
| 19 | `request_error` (146) | yes | backend_error | 502 Backend unavailable | status retry | no | request_error |

Dispatch and retry facts that matter to a client:
- Retries are **opt-in per proxy** and invisible to the client. No header reports how many attempts were made, and `X-Gateway-Error` describes only the final attempt.
- A circuit-breaker 503 after a retry does **not** prove that earlier attempts never reached a backend.
- RFC 9113 protocol NACKs (`REFUSED_STREAM`, GOAWAY `NO_ERROR`) are replayed internally up to 2 times with no retry config (`src/retry.rs:1409-1430`; `docs/retry.md:104-108`).
- Classes 8, 10, 11, 12 and 16 are never retried, even when their status appears in `retryable_status_codes`.

Where the gateway decides a request reached the backend ("phase comes from the caller", `src/retry.rs:1015-1048`, `1437-1491`):
- `classify_reqwest_error` treats anything seen after reqwest's TCP-only `is_connect()` phase as post-wire, except hyper `is_canceled`, which is taken as proof the request was never dispatched.
- **This is where the HTTP/1 pooled path loses typed handshake evidence** (`src/retry.rs:1448-1471`; `docs/error_classification.md:40-64`). A backend demanding a client certificate on the reqwest HTTP/1 pool surfaces in one of two ways:
  - hyper `is_canceled` with no rustls error in the chain, classified `connection_pool_error` (pre-wire, `connection_failure`; issue #4406).
  - A typed rustls alert after TCP connect, conservatively classified `connection_reset` (post-wire, `backend_error`; issue #4536).
- Every pool that dials for itself keeps `tls_error` from its own setup phase: direct H2, gRPC, native H3, HBONE/mesh, the WebSocket dial, and `GenericPool`.
- The plaintext-backend-on-https case is `tls_error`; the gateway logs `error_reason=https_to_plaintext_backend` (`src/retry.rs:1136`), and the client body is unchanged.

### The seven tokens

| Token | Status(es) seen | Writer | Notes |
|---|---|---|---|
| `connection_failure` | 502 | `src/proxy/mod.rs:39448-39461` via `src/retry.rs:283`; HTTP/3 via `src/proxy/mod.rs:24836` | Pre-wire classes 1, 2, 5, 6, 13, 14, 17, 18. Body `Backend unavailable`, or `Backend DNS resolution failed` on the reqwest DNS preflight. |
| `backend_timeout` | 504 | `src/retry.rs:284` | Any 504 on the backend path, including the backend's own 504 and the v0.9.5 stranded pooled HTTP/1 request. |
| `backend_error` | any other 5xx on the backend path | `src/retry.rs:286` | Includes gateway-local 503s and 502s and response-phase plugin 5xx (section 4). |
| `circuit_breaker_open` | 503 HTTP, WebSocket pre-upgrade; gRPC 200 + `grpc-status: 14` | `src/proxy/mod.rs:272-278`, restored at `33120-33123`; HTTP/3 `src/http3/server.rs:5620` | Body `{"error":"Service temporarily unavailable (circuit breaker open)"}`. |
| `overload` | 503 overload/drain; **502** transformer ceiling | `src/proxy/mod.rs:29979-29983`, `47187-47201`, `24790-24800`, `26156`; HTTP/3 `src/http3/server.rs:2457` | Missing on HTTP/1 and HTTP/2 gRPC. Transformer-ceiling body is `{"error":"Response body too large","limit":N}`. |
| `config_stale` | 503 | `src/proxy/mod.rs:29899-29903`; HTTP/3 `src/http3/server.rs:2488` | Missing on HTTP/1 and HTTP/2 gRPC. Body `{"error":"Gateway configuration stale"}`. |
| `concurrency_limit` | 503; gRPC 200 + `grpc-status: 14` | `src/plugins/adaptive_concurrency.rs:23-28,123-136` | Body `{"error":"Upstream concurrency limit reached"}`. With `expose_headers` it also sends `x-adaptive-concurrency-limit` and `x-adaptive-concurrency-inflight`. Not authoritatively restored, so a reject hook could strip it. |

## 2. Public response headers

| Header | Writer (at `20e7603`) | Semantics | Spoofable by backend |
|---|---|---|---|
| `X-Gateway-Error` | `src/proxy/mod.rs:39460`, `47195`, `272-294`, `24804`, `24836`; `src/plugins/adaptive_concurrency.rs:26` | The 7-token vocabulary (section 1) | **Partly.** Stripped and replaced on the plain HTTP backend builders (`src/proxy/mod.rs:39449`, `24827`). Not stripped on native-gRPC responses (`src/proxy/mod.rs:36800-36840` only removes hop-by-hop fields). Not sanitized on plugin reject maps. |
| `X-Gateway-Upstream-Status` | `src/proxy/mod.rs:39464`; `src/http3/server.rs:10326-10327` | Only value `degraded`: all-unhealthy or unhealthy-subset fallback. Can accompany any status, including 2xx. | **Yes.** Not stripped on the HTTP/1 and HTTP/2 path when there was no fallback. Appended rather than replaced when there was. |
| `gateway-error-reason` | `src/proxy/mod.rs:3452`, `37754`, `37824`, `37874`, `42316`; `src/http3/server.rs:6212`, `8961`; `src/http3/cross_protocol.rs:1571`, `1618`, `1699`; `src/http3/websocket.rs:840` | Undocumented reason on some `dispatch_policy_rejected` 502s. Values include `backend_tls_sni_requires_direct_h2`, `backend-egress-policy-denied` (HTTP/3 bridge only), and mesh reason strings. | Yes (not in the strip list, `src/proxy/headers.rs:745`) |
| `Via` | `src/proxy/mod.rs:39517`, values built at `9373-9381` | `1.1`, `2.0` or `3.0` followed by `FERRUM_VIA_PSEUDONYM` (default `ferrum-edge`); `FERRUM_ADD_VIA_HEADER` defaults to true. Present on responses through the backend builder, including gateway-built 502/504. **Absent** on pre-dispatch rejects (404, 405, 401, 431, 503 fences, circuit breaker). | Yes |
| `Alt-Svc` | `src/proxy/mod.rs:39470` (value at `9366`) | `h3=":<https port>"; ma=86400` when HTTP/3 is enabled; backend-path responses only | Yes (backend value is kept and the gateway's is appended) |
| `Allow` | `src/proxy/mod.rs:24747`, `24776` | Route 405: the configured methods. Protocol 405: `GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS`. | No, on gateway 405s |
| `WWW-Authenticate` | `src/plugins/utils/auth_flow.rs:657`; `src/proxy/mod.rs:28989`; `src/plugins/basic_auth.rs:225`; `src/plugins/ldap_auth.rs:91`; `src/plugins/oauth2_introspection.rs:1321` | 401 only. Values: `Basic realm="ferrum-edge", charset="UTF-8"` (basic_auth, ldap_auth); `Bearer`, `Bearer error="invalid_request"`, `Bearer error="invalid_token"` (oauth2_introspection); `Bearer realm="oidc", error="invalid_token"` (oidc API branch); the literal fallback **`ferrum-edge`**. Never aggregated across plugins. No DPoP challenge and no `DPoP-Nonce`. | Yes (the backend's own 401 challenge passes through) |
| `x-ratelimit-limit`, `x-ratelimit-remaining`, `x-ratelimit-window` | `src/plugins/rate_limiting.rs:546-550` | `rate_limiting` plugin. `x-ai-ratelimit-*` comes from `ai_rate_limiter` (only with `expose_headers`), and `x-grpc-ratelimit-*` from `grpc_method_router`. | Yes |
| `Retry-After` | only `src/plugins/spec_expose.rs:130`, `1036` (and `ai_federation` passing through a provider value) | **No core gateway reject sends it**: not overload, circuit breaker, concurrency, rate limiting, WebSocket or HTTP/3. | Yes |
| `x-request-id` | `src/plugins/correlation_id.rs:103`, `121`, `328` | Only when the `correlation_id` plugin is enabled. It is echoed by default, including on rejects. The gateway core emits no request id. | n/a |
| `Connection: close` | `src/proxy/mod.rs:39510`, `29867`; `src/proxy/h1_framing_guard.rs:71-73` | HTTP/1.1 only. Sent during drain or overload pressure (RED-probabilistic) and on parse rejects. | No (hop-by-hop; the backend's is stripped) |
| `grpc-status`, `grpc-message` (gateway-built) | `src/proxy/grpc_proxy.rs:4105-4190` | Trailers-only 200, `content-type: application/grpc`, raw (not percent-encoded) message | Yes |
| `Server` | none | Ferrum writes no `Server` header | n/a |
| `X-Ferrum-*` | none on proxy responses | Only on admin responses (`X-Ferrum-Namespace-Unserved`, `src/admin/mod.rs:2361`) or as internal markers stripped before the wire | n/a |

### Can a client tell a response came from Ferrum?

Not with authentication. There are only Ferrum-*like* signals:
- `Via: … ferrum-edge`. It is the default, but the name is configurable and it can be switched off. It appears only on responses that went through the backend path.
- `WWW-Authenticate: ferrum-edge`, or `realm="ferrum-edge"`.
- A value from the closed 7-token `X-Gateway-Error` set.
- Exact gateway body literals (sections 3-5).
- `gateway-error-reason`.

Every one of these can be forged by a backend or intermediary, and some can be removed by operator config. So a rule should say "Ferrum-like marker observed", and should confirm Ferrum origin only for an explicitly trusted destination profile, as plan §9.2 requires.

## 3. Gateway rejection phases and admission fences (pipeline order)

`handle_proxy_request_on_frontend_port` (`src/proxy/mod.rs:29837`) runs these first, before any request context, routing or plugin.

| Order | Fence | Condition | Client signal (HTTP) | gRPC | Source |
|---|---|---|---|---|---|
| 0 | Connection admission | `reject_new_connections` (critical pressure) or the `FERRUM_MAX_CONNECTIONS` semaphore (default 100000) | The accepted socket is dropped; no TLS or HTTP. On HTTP/3, QUIC `refuse()`. | same | `src/proxy/mod.rs:21462`, `21472`; `src/http3/server.rs:1149` |
| 0 | TLS handshake / pre-request timeout | `FERRUM_FRONTEND_TLS_HANDSHAKE_TIMEOUT_SECONDS` and `FERRUM_HTTP_HEADER_READ_TIMEOUT_SECONDS` (both default 10) | Connection closed, no response | same | `src/proxy/mod.rs:21705`, `14001`, `14111` |
| 0 | Client certificate | Client CA bundle configured, so the certificate is **mandatory at the handshake** (`WebPkiClientVerifier` without `allow_unauthenticated`) | A TLS alert from rustls; no HTTP 401 | same | `src/tls/mod.rs:1341-1413` |
| 0 | HTTP/1 parse guard | First head has conflicting `Content-Length`, HTTP/1.0 with `Transfer-Encoding`, or an invalid UTF-8 target | Raw `400` + `connection: close` + `{"error":…}` | n/a | `src/proxy/h1_framing_guard.rs:59-73` |
| 0 | Other hyper parse failures | Anything else hyper rejects | hyper's own empty-bodied 400 (not Ferrum-authored) | n/a | `docs/error_classification.md:262-270` |
| 1 | Framing observer failed | Observer overflowed | 400 `{"error":"HTTP/1 request framing could not be verified; connection will be closed"}` + `Connection: close` | — | `src/proxy/mod.rs:29856` |
| 2 | Stale data-plane config | Data-plane snapshot older than `FERRUM_DP_CONFIG_MAX_STALE_SECONDS` (3600) with the control plane lost, and `fail_closed` (the default) | 503 `{"error":"Gateway configuration stale"}` + `config_stale` | 200 / 14; header only on HTTP/3 | `src/proxy/mod.rs:29890` |
| 3 | Client trust withdrawn | The client certificate's CA or CRL trust was withdrawn | 401 `{"error":"Client certificate trust withdrawn"}` (no token) | 200 / 16 | `src/proxy/mod.rs:29923` |
| 4 | Overload or drain | `reject_new_requests` | 503 `{"error":"Service overloaded"}` + `overload` | 200 / 14; header only on HTTP/3 | `src/proxy/mod.rs:29968` |
| 5 | Header limits | single header > 16384, total > 32768, count > 100 | 431 with 3 bodies (one names the header) | plain 431 | `src/proxy/mod.rs:30165-30202` |
| 6 | URL and query | URL > 8192 bytes, more than 100 query parameters | 414, 400 | plain | `src/proxy/mod.rs:30219`, `30232` |
| 7 | Protocol headers, Host | CL+TE, TE rules, missing or duplicate Host, authority mismatch | 400, about 20 fixed bodies | plain | `src/proxy/mod.rs:30248`, `46897-47170` |
| 8 | Ambiguous path encoding | `canonicalize_policy_path` refuses the path | 400, 9 fixed bodies | 200 / 3 | `src/proxy/mod.rs:30328`; `src/policy_path.rs:201-238` |
| 9 | TRACE, non-WebSocket CONNECT | always | 405 + `Allow` | plain | `src/proxy/mod.rs:30373`, `30390` |
| 10 | 0-RTT method | `Early-Data: 1` and the method is not allowed | 425 | 200 / 14 | `src/proxy/mod.rs:30409` |
| 11 | Per-IP concurrency | `FERRUM_MAX_CONCURRENT_REQUESTS_PER_IP` (0 = off) | 429 `{"error":"Too many concurrent requests from this IP"}`, no `Retry-After` | plain | `src/proxy/mod.rs:30516` |
| 12 | Route miss | no proxy matches | 404 `{"error":"Not Found"}` | 200 / 12 | `src/proxy/mod.rs:30967` |
| 13 | Route method | method not in `allowed_methods` | 405 `{"error":"Method Not Allowed"}` + authoritative `Allow` | 200 / 12 | `src/proxy/mod.rs:31063` |
| 14 | gRPC non-POST | gRPC content type with a method other than POST | (becomes gRPC) | 200 / 3 `gRPC requires POST method` | `src/proxy/mod.rs:31116` |
| 15 | Plugin phases | `on_request_received` (ip/geo), `authenticate`, `authorize` (ACL, OPA, mesh authz), `before_proxy`, `on_final_request_body`, `finalized_request_egress` | Plugin-defined (section 4). No token unless the plugin sets one. | mapped | `src/proxy/mod.rs:29617-29780` and on |
| 16 | Request body | over the size limit, read timeout, buffer budget | 413, 408, 503 `Request buffering capacity exceeded`, 503 `Request inspection capacity exceeded` | 200 / 8, 4, 8, 8 | `src/proxy/mod.rs:47217-47330` |
| 17 | Circuit breaker | breaker open for the target | 503 + `circuit_breaker_open` | 200 / 14 + header | `src/proxy/mod.rs:33107` |
| 18 | Backend admission | adaptive concurrency; DestinationRule `http2MaxRequests` | 503 + `concurrency_limit`; 503 `{"error":"Destination active request limit reached"}` (no token) | 200 / 14 | `src/plugins/adaptive_concurrency.rs:107`; `src/proxy/backend_dispatch.rs:896` |
| 19 | Dispatch policy | egress denial, DNS-override conflict, SNI, `http1MaxPendingRequests`, `maxConnections` | 502 or 503 + `backend_error` | 200 / 14 | section 5 |
| 20 | Backend exchange | the 19 classes | 502 or 504 + token | 200 / 14, 4, 8 | section 1 |
| 21 | Response phase | size limit, buffer budget, transformer ceiling, uninspectable representation, redaction failure, response plugins | 502 or 503 (see section 4) | 200 / 8, 13 | `src/proxy/mod.rs:26030-26420` |

`rejection_phase` (logged values: `on_request_received`, `authenticate`, `authorize`, `before_proxy`, `allowed_methods`, `circuit_breaker_open`, `circuit_breaker`, `on_backend_path_resolved`, `on_final_request_body`, `finalized_request_egress`, `validate_client_request_contract`, `grpc_deadline_preflight`, `backend_max_connections`, `websocket_connection_limit`, `websocket_per_ip_connection_limit`, `after_proxy`, `error`) exists only in transaction-log metadata. It never reaches the client.

## 4. Built-in plugin rejection and result paths

**How rejects are rendered** (`src/proxy/mod.rs:25252`, `normalize_reject_response_with_provenance`):
- Plugins return `PluginResult::Reject { status_code, body, headers }` (`src/plugins/mod.rs:6408`).
- **Non-gRPC:** the plugin's status, body and headers are sent as-is, with `content-type: application/json` added when the plugin set none (`src/proxy/mod.rs:25267`). This includes the plain-text 403 body for an oversized identity and the OIDC logout HTML page.
- **gRPC:** trailers-only 200, using the mapping in section 6.
- **WebSocket:** an ordinary HTTP response to the upgrade request.
- **TCP/UDP:** a close; status and body are discarded.
- Rejects raised in request phases get **no** `X-Gateway-Error` unless the plugin sets one. 5xx replacements raised at the final request body or in response phases go through the backend-response builder, and so very likely carry `X-Gateway-Error: backend_error` (inferred; `src/proxy/mod.rs:6453`, `39448`).

**Authentication phase** (`src/proxy/mod.rs:29617-29780`):
- Plugins run in ascending priority:
  - `ip_restriction` 150 and `geo_restriction` 175 (in `on_request_received`)
  - then `mtls_auth` 950, `jwks_auth` 1000, `oauth2_introspection` 1050, `oidc_relying_party` 1075, `jwt_auth` 1100, `key_auth` 1200, `ldap_auth` 1250, `basic_auth` 1300, `hmac_auth` 1400, `soap_ws_security` 1500
  - then `access_control` 2000, `mesh_authz` 2075, `opa` 2080 (authorize)
- **Single mode:** the first reject is returned.
- **Multi mode:** the first success wins. Otherwise the first 5xx beats any 4xx, and otherwise the last 4xx is returned.
- If nothing identified the caller, the result is 401 `{"error":"Authentication required"}` with `WWW-Authenticate` set to the first applicable challenge, or the literal `ferrum-edge` (`src/proxy/mod.rs:28957-29001`).
- On routes with `ai_federation` or `ai_stream_router`, 401s are rewritten into OpenAI-shaped bodies: `{"error":{"message":…,"type":"invalid_request_error","param":null,"code":"missing_api_key"|"invalid_api_key"}}` (`src/proxy/mod.rs:28959`).

### 4.1 Authentication and authorization plugins

| Plugin | Distinct client-visible signals (status, body literal) | Challenge / headers | Dependency outage looks like |
|---|---|---|---|
| key_auth | 401 `Invalid API key format` · `Missing API key` (blank key) · `Invalid API key` | none | n/a |
| basic_auth | 401 `Invalid Authorization header` · `Invalid Basic auth format` · `Invalid base64 in Basic auth` · `Invalid UTF-8 in Basic auth` · `Invalid credentials` | `Basic realm="ferrum-edge", charset="UTF-8"` | n/a |
| jwt_auth | 401 `Invalid JWT token` (collapses signature, expiry, issuer/audience and unknown subject) · `JWT missing identity claim` (decided before signature verification) · `JWT missing nbf claim` · `Empty bearer token` | none | n/a |
| jwks_auth (+DPoP, mTLS binding, scope/role) | 401 `Invalid or unrecognized JWT` · `mTLS binding mismatch` · `DPoP proof required` · `Invalid DPoP proof` · `DPoP URL mismatch` · `DPoP validation failed` · `DPoP replay` · `Empty DPoP token`/`Empty token`/`Invalid token`; 503 `DPoP replay protection is at capacity` · `DPoP replay protection unavailable`; 403 `{"error":"Insufficient scope","required":"<scope>"}` · `Insufficient role` | none; **no `DPoP-Nonce`, no `use_dpop_nonce`** | JWKS/IdP outage past `max_stale` (3600 s) gives **the same 401** as a bad token |
| hmac_auth | 401 with ~20 distinct literals: format and parameter errors, `Missing nonce…`, `Missing required Digest header`, `Ambiguous Digest and Content-Digest headers`, `Digest header does not match request body`, `Missing or expired Date header`, `Invalid credentials`, `Signed request has already been used` (replay), and the v1-profile nonce rejection; 503 `Signed-request replay protection is at capacity` / `…unavailable` | none | replay store down: 503 |
| mtls_auth | 401 `Invalid client certificate` · `Client certificate is not currently valid` · issuer/consumer mismatch literals | none | n/a (a missing certificate gives `Authentication required`) |
| oauth2_introspection | 401 `Inactive token` · `Invalid or unrecognized token` · `Invalid token issuer`/`audience` · `Unsupported introspected token type` · `Sender-constrained tokens are not supported` · `Bearer token exceeds maximum length` …; 503 `Token introspection unavailable`; 403 scope/role | `Bearer error="invalid_token"` / `error="invalid_request"` | 503 (distinguishable) |
| oidc_relying_party | Browser flow: 302 to IdP; callback 400s (`Invalid state`, `Missing code`, `Token exchange failed`, `Invalid ID token*`, `JWKS unavailable`, `Session creation failed`, …). API branch: 401 `Authentication required` with `Bearer realm="oidc", error="invalid_token"`. 503 before first discovery. Logout: 302/200 HTML. | `Set-Cookie` (session/correlation) | IdP outage is mostly **not** distinguishable (400 at callback) |
| ldap_auth | 401 `LDAP authentication failed` · Basic format literals (shared with basic_auth) · `Username must not be empty` · `Password must not be empty`; 403 `User is not a member of any required group`; 500 `LDAP authentication temporarily unavailable` / `LDAP group membership check failed` | `Basic realm="ferrum-edge", charset="UTF-8"` | 500 (distinguishable) |
| soap_ws_security | 415/400 media-type and XML literals; 401 `WS-Security header is missing` · `WS-Security: invalid credentials` · Timestamp, UsernameToken, X.509 and SAML families (about 90 `WS-Security: …` literals) · `WS-Security: nonce replay detected`; **401** `WS-Security: replay protection backend is unavailable`; 500 `WS-Security: the authenticated SOAP message was modified before backend dispatch` | none (JSON bodies, **not SOAP faults**) | replay store down: 401, distinguishable only by body |
| access_control | 403 `Consumer is not allowed` · `Identity is not allowed` · `Authenticated identity is not authorized` · `No consumer identified` (fixed literals) | none | n/a |
| opa | 403 `{"error":"forbidden by policy"}` (deny, undefined decision, or ambiguous query); 503 `{"error":"authorization service unavailable"}` (fail-closed default). Both statuses, bodies and headers are configurable; `fail_open` is available. | configurable | 503 (distinguishable under defaults) |
| ip_restriction | 403 `IP address denied` · `IP address not allowed` · `client IP could not be determined` | none | n/a |
| geo_restriction | 403 `Access denied from your geographic location` · `Access denied: GeoIP database not available` · `Access denied: unable to determine geographic location` | none | GeoIP missing: unique 403 (fail-open by default) |
| mesh_authz / ext_authz | 403 `Mesh authorization denied` (+ internal-cause variants); ext-authz provider status is passed through verbatim | provider allow-listed headers | ext-authz outage defaults to the **same 403** as a deny |
| (auth phase) | 401 `Authentication required`; 403 plain-text identity-over-512-bytes message; 413 pre-auth body buffer | `ferrum-edge` fallback challenge | — |

Complete per-literal records with source lines are in `outcomes.json` (families `auth` and `authorization`).

### 4.2 AI / LLM and agent-protocol plugins

- **Body families:**
  - OpenAI-shaped `{"error":{"message","type","param","code"}}`: only `ai_federation`, `ai_stream_router`, and the auth-envelope rewrite. Gateway-specific codes include `provider_request_failed`, `provider_circuit_open`, `provider_concurrency_exhausted`, `streaming_not_supported` and `upstream_error`. The codes `model_not_found`, `invalid_api_key` and `invalid_model` collide with real OpenAI codes; the message text (for example "No ai_federation provider…") disambiguates.
  - Plain `{"error":…,"details"|"detail"|"decision"…}`: the other AI plugins.
  - `{"error":{"code","message"}}` with no `type`: `ai_semantic_firewall`.
  - JSON-RPC 2.0 errors **under HTTP 200**: `mcp_gateway` (-32600 … -32013) and `a2a_gateway` (-32001, -32013). `data.gateway` marks gateway authorship.
- **Buffered `ai_federation` never forwards a provider error body.** The client gets the provider's status, the provider's allow-listed headers (`retry-after`, `*-request-id`, `x-ratelimit-*`, `anthropic-ratelimit-*`) and a gateway body `Upstream provider returned status N` with type `upstream_error`.
- **Streaming paths relay the provider's own error body.**
- **No marker reveals a fallback provider.**
- **Error frames inside a streamed 200:**
  - `ai_federation`: `event: error` + `provider_stream_failed`, with no `[DONE]`.
  - `ai_stream_router`: `data: {"error":{"message","type":"upstream_error"}}` then `[DONE]`.
  - `ai_semantic_firewall` and `ai_tool_governor`: `event: error` + code, then `[DONE]`.
  - A `[DONE]` after an error frame is **not** success.
- **Budgets and quotas:**
  - `ai_rate_limiter`: 429 `{"error":"AI token rate limit exceeded","details":…}`. `x-ai-ratelimit-*` headers appear only with `expose_headers`, and there is no `Retry-After`.
  - The same plugin returns 503 when Redis is down (fail-closed) and 502 `AI token usage missing`.
- **Policy rejects:**
  - `ai_request_guard`: 400.
  - `ai_prompt_shield`: 400/413.
  - `ai_semantic_firewall`: 403 request, 502 response, 503 `…could not be evaluated`, 400 for streaming when response rules exist.
  - `ai_response_guard`: 502 for blocked content, including every SSE response when enforcing.
  - `ai_tool_governor`: 403 (configurable) and 502 fail-closed.
  - `ai_transcript_audit`: 503 `audit_unavailable`, only if configured to reject.
- **Several response-phase rejects happen after the provider has already run and billed.**

### 4.3 Traffic, size, WAF, validation, transform, cache and misc plugins

| Plugin | Client-visible signals (status, body literal) | Headers | Configurable / notes |
|---|---|---|---|
| rate_limiting | 429 `{"error":"Rate limit exceeded"}`; 503 `{"error":"Rate limit enforcement is temporarily unavailable"}` when Redis is down (v0.9.5 default `redis_failure_policy: fail_closed`) | `x-ratelimit-limit`, `x-ratelimit-remaining`, `x-ratelimit-window`, only with `expose_headers` (default false); **never `Retry-After` or `RateLimit-*`** | The local state-capacity 429 has the same body and no headers. TCP: connection closed. |
| graphql | 400/403/429 with a **GraphQL-shaped** body `{"errors":[{"message":…}]}` (depth, complexity, introspection, rate limit), 503 when enforcement is unavailable | `x-graphql-ratelimit-limit`, `x-graphql-ratelimit-remaining` | Looks like an application GraphQL error, but uses a 4xx status |
| grpc_method_router | 200 trailers-only: 7 `gRPC method '…' is not permitted`, 8 `Rate limit exceeded for gRPC method '…'`, 14 enforcement unavailable | `x-grpc-ratelimit-limit`, `-remaining`, `-method` | |
| grpc_deadline | 200 trailers-only: 3 `a positive grpc-timeout header is required`; 4 `Deadline exceeded at gateway` | | |
| ws_rate_limiting / ws_message_size_limiting | Close 1008 `Frame rate exceeded` / Close 1009 `Message too large` (reasons configurable) | | |
| tcp_connection_throttle / udp_rate_limiting | TCP close (the 429 body is discarded) / silent datagram drop | | |
| request_size_limiting | 413 `{"error":"Request body too large","limit":N}` · 400 `{"error":"Request Content-Length is ambiguous","limit":N}` · core 413 `Request body exceeds maximum size` | | The `limit` field distinguishes the plugin from the core ceiling |
| response_size_limiting | 502 `{"error":"Response body too large","limit":N}` · `Response Content-Length is ambiguous` · `Streaming response size cannot be verified` | `X-Gateway-Error: backend_error` (response phase) | **Same body as the transformer ceiling, but `backend_error` instead of `overload`** |
| waf | 403 `{"error":"Forbidden"}` (default); request/response bodies; WebSocket Close 1008 with three reasons | none (no `X-WAF-*`) | Status (400-599), body and content-type configurable. No rule ID or payload is exposed. Monitor mode passes traffic through. |
| bot_detection | 403 `{"error":"Forbidden"}` (`custom_response_code` 400-599) | | **Byte-identical to WAF's default** |
| body_validator | 400 `{"error":"Request body validation failed","details":…}` · 502 `{"error":"Response body validation failed","details":…}` | 502 gets `backend_error` (inferred) | `details` is payload-free and bounded |
| openapi_validator | Problem JSON `{"type":"about:blank","title":…,"status":…,"detail":…,"operation":…}`: 400 request, 502 response, 415 media type, "Unknown OpenAPI operation" | `content-type: application/problem+json` (configurable) | Statuses configurable (`error_response.*`); log-only mode available |
| cors | 403 `{"error":"CORS origin not allowed"}` / `CORS method not allowed` / `CORS header not allowed` (only when `unmatched_preflights: reject`); preflight 204 (or 200) | `access-control-*` | A missing allow-origin header is the usual browser-side failure |
| request_termination | 503 (default) `{"message":"Service unavailable","status_code":503}` (Kong-like envelope), or configured JSON/XML/text | | **A gateway-authored 503 without a token**; status 200-599 configurable |
| response_mock | configured status/body/headers; 404 `{"error":"no mock rule matched"}` | | No marker header |
| fault_injection | configured abort status/body (default empty body); injected delays | | **No marker**: injected failures are indistinguishable from real ones |
| serverless_function | 502 `{"error":"serverless function invocation failed","code":"…"}`; function output relayed | | |
| response_caching | Cached replay | `x-cache-status` (HIT/MISS/…), `age` | |
| request_deduplication | 409 `A request with this idempotency key is already in progress` / `Idempotency key was reused for a different request` …; 400 missing key; 503 store unavailable; replays | `x-idempotent-replayed: true` | Replay status = original response status |
| compression | 400 `Malformed or unsupported Content-Encoding` / `Malformed compressed request body`; 406 no acceptable coding; 503 `Compression workers unavailable` / `Request inspection capacity exceeded` | `content-encoding`, `vary` | Shares bodies with the core representation gate |
| sse | 405 `SSE requires GET method` · 406 `Accept header must include text/event-stream` · 400 `Last-Event-ID exceeds maximum length` | `x-accel-buffering: no` | |
| grpc_web | 406 `Not Acceptable: no supported gRPC-Web response media type` (JSON); otherwise trailer frames | `x-grpc-web: 1` | |
| spec_expose | 502/503 fetch failures, 503 busy | **`retry-after`** | The only gateway `Retry-After` source |
| security_headers | Decoration only | adds `x-content-type-options`, `referrer-policy`, …; **removes `Server` and `X-Powered-By`** | Changes what backend-identification headers the client sees |
| correlation_id | Decoration only | `x-request-id` echoed by default (UUIDv4 when the client value is invalid or longer than 256 bytes) | |
| request_transformer, request_mirror, transaction_debugger, api_chargeback, proxy_alerts, trigger, load_testing | No client-visible rejection; load_testing only returns a 204 acknowledgement | | |

### 4.4 Custom plugins

- **Rendering.** Custom plugins (`custom_plugins/*.rs`, compiled in at build time, selected with `FERRUM_CUSTOM_PLUGINS`) return the same `PluginResult` as built-ins, so their rejects are rendered exactly like the built-ins' (section 4 intro).
- **Out-of-range status.** A status outside 100-999 falls back by phase: 500 in `on_request_received`, 401 in `authenticate`, 403 in `authorize`, and 500 in the body and `before_proxy` phases.
- **Headers are not sanitized.** A custom plugin can set any header on a reject, **including `X-Gateway-Error`**. On the backend-response path the gateway re-derives that header anyway.
- **No request-time error channel.** Hooks return `PluginResult`, not `Result`. `PluginFailurePolicy` (`FailClosed`, `KeepLastKnownGood`, `OptionalFailOpen`, `src/plugins/mod.rs:1293-1301`) applies only when the plugin is constructed or reloaded.
- **Panics.** Release builds use `panic = "abort"` (`Cargo.toml:461`), so a panic in **any** plugin hook kills the gateway process and resets every connection. There is no generic plugin-error 500.
- **Timeouts.** There is no per-hook HTTP timeout. On gRPC, the client deadline produces 4 `Deadline exceeded at gateway`.
- **Undeclared response producers.** A custom plugin that produces response bodies without declaring `response_body_production` surfaces as 503 `Response buffering capacity exceeded`.
- **Consequence for Anvil.** An unknown plugin outcome can only get a generic explanation, unless a signed, schema-validated local rule extension is supplied (plan §9.3).

## 5. Upstream failures and gateway-local terminals on the HTTP backend path

| Outcome | Status | Body | Token | Class | Source |
|---|---|---|---|---|---|
| DNS failure, reqwest preflight | 502 | `{"error":"Backend DNS resolution failed"}` | connection_failure | dns_lookup_error | `src/proxy/mod.rs:43055`, `41061`, `41818` |
| Egress-policy denial of a resolved hostname | 502 | same DNS body | **backend_error** | dispatch_policy_rejected | `src/proxy/mod.rs:43055-43075` |
| Egress-policy denial of a literal IP | 502 | `{"error":"backend address blocked by egress policy"}` | backend_error | dispatch_policy_rejected | `src/proxy/mod.rs:43008` |
| DNS override conflicts with a literal target | 502 | `{"error":"backend DNS override cannot be applied to literal target"}` | backend_error | dispatch_policy_rejected | `src/proxy/mod.rs:43024` |
| SNI override cannot be honoured | 502 | `{"error":"Bad Gateway"}` + `gateway-error-reason: backend_tls_sni_requires_direct_h2` | backend_error | dispatch_policy_rejected | `src/proxy/mod.rs:3447` |
| Refused, connect timeout, TLS, pool, port exhaustion, DNS (pools), connection limit (pools), trust withdrawn | 502 | `{"error":"Backend unavailable"}` | connection_failure | pre-wire classes | `src/proxy/mod.rs:42788-42817` |
| Reset, closed, protocol, graceful close, catch-all (before headers) | 502 | `{"error":"Backend unavailable"}` | backend_error | post-wire classes | same |
| Header wait, upload stall, or buffered-body idle timeout | 504 | `{"error":"Backend timeout"}` | backend_timeout | read_write_timeout | `src/proxy/mod.rs:45278-45292`, `42839`, `54862` |
| Eager-buffered small body read fails | 502 | `{"error":"Backend response body read failed"}` | backend_error | post-wire class | `src/proxy/mod.rs:42852` |
| Buffered collector read fails | 502 | `{"error":"Backend response read error"}` | backend_error | logged as response_body_too_large (sic) | `src/proxy/mod.rs:45859` |
| Response too large (declared or buffered) | 502 | `{"error":"Backend response body exceeds maximum size"}` | backend_error | response_body_too_large | `src/proxy/mod.rs:41537`, `45844` |
| Retained-response budget exhausted | 503 | `{"error":"Response buffering capacity exceeded"}` | **backend_error** | gateway_buffer_capacity | `src/proxy/response_buffer_budget.rs:469-491`; `src/proxy/mod.rs:45882` |
| `http1MaxPendingRequests` reached | 503 | `{"error":"HTTP/1.1 in-flight request limit reached"}` | **backend_error** | dispatch_policy_rejected | `src/proxy/mod.rs:45145`, `41368` |
| `maxConnections` reached (reqwest lane) | 503 | `{"error":"Backend connection limit exceeded"}` | **backend_error** | dispatch_policy_rejected | `src/proxy/mod.rs:45762`, `41687` |
| Transformer output over the ceiling | 502 | `{"error":"Response body too large","limit":N}` | **overload** | dispatch_policy_rejected | `src/proxy/mod.rs:26149-26157` |
| Response representation uninspectable | 502 | `{"error":"response representation could not be inspected"}` | backend_error (inferred) | — | `src/proxy/mod.rs:26216`, `26408` |
| Backend's own 5xx / 504 / other | backend's | backend's | backend_error / backend_timeout / none | — | `src/retry.rs:281-291` |

## 6. Protocol-specific outcomes

### gRPC

- **Shape.** Every gateway-built gRPC error is HTTP 200 Trailers-Only: a single END_STREAM HEADERS frame with `content-type: application/grpc`, `grpc-status` and `grpc-message`, no DATA, no Content-Length (`src/proxy/grpc_proxy.rs:4105-4190`). `grpc-message` is sent raw, with CR/LF replaced by spaces; it is not percent-encoded. A NO_ERROR reset may follow the END_STREAM HEADERS (`src/proxy/grpc_proxy.rs:4160-4171`).
- **Plugin and admission rejects** are mapped by `http_reject_status_to_grpc_status` (`src/proxy/grpc_proxy.rs:2225`):

  | HTTP | grpc-status |
  |---|---|
  | 400 | 3 |
  | 401 | 16 |
  | 403 | 7 |
  | 404, 405, 501 | 12 |
  | 408, 504 | 4 |
  | 409 | 10 |
  | 412 | 9 |
  | 413, 414, 429 | 8 |
  | 502, 503 | 14 |
  | anything else | 13 |

  A plugin-supplied numeric `grpc-status` header wins. `grpc-message` comes from the header, else the JSON body's `grpc_message`, `message`, `error` or `details` key (`src/proxy/mod.rs:24941`). On HTTP/3, 425 maps to 14.
- **Backend dispatch errors, HTTP/1 and HTTP/2 frontend** (`src/proxy/mod.rs:36921-36955`):
  - `BackendUnavailable` and `Internal`: 14 `Backend unavailable`.
  - `BackendTimeout`: 4 `Backend deadline exceeded`.
  - Client deadline: 4 `Deadline exceeded at gateway`.
  - `ResourceExhausted` and `ResponseTooLarge`: 8 `Resource exhausted`.
  - Buffer capacity: 8 `Response buffering capacity exceeded`.
  - **No `X-Gateway-Error` on any of these.**
- **HTTP/3 frontend** uses different messages (`src/http3/cross_protocol.rs:7829`): 14 `Service unavailable`, 8 `Request payload exceeded backend limit` / `Response payload exceeded limit`, and 13 `Internal gateway error`.
- **After response HEADERS:**
  - Client deadline before any DATA: synthesized trailers `grpc-status: 4`, `grpc-message: Deadline%20exceeded%20at%20gateway` (`src/proxy/body.rs:4573`).
  - Credential expiry before any DATA: `grpc-status: 16`.
  - Anything after DATA: the stream is reset with no trailers. HTTP/2 uses hyper's code; HTTP/3 uses `H3_INTERNAL_ERROR`.
  - A backend `grpc-status` is relayed unchanged. If the backend omits it, `UNKNOWN(2)` is recorded in logs only and nothing is synthesized.
- **Header limits, per-IP 429 and protocol-header 400s are *not* gRPC-shaped.** A gRPC client sees plain HTTP errors and applies its own status mapping.
- **gRPC-Web** uses body-framed trailers with the same codes. When the backend omits `grpc-status`, a different mapping applies (`src/plugins/grpc_web.rs:2531`).

### WebSocket

- **Pre-upgrade rejects are ordinary HTTP responses:**
  - 503 `WebSocket connection limit exceeded`
  - 403 `WebSocket Origin not allowed`
  - 401 `Credential expired before WebSocket upgrade`
  - 503 `WebSocket maximum lifetime elapsed before upgrade`
  - 502 `Backend WebSocket connection failed`: covers DNS, connect, TLS, timeout, **and a backend that refused the upgrade**. The backend's own status and body are not relayed.
  - 503 `Backend connection limit exceeded`
  - 500 internal errors
- Only the circuit-breaker, concurrency, overload and config_stale rejects carry `X-Gateway-Error`.
- **Close codes the gateway authors** (`src/proxy/mod.rs:17811-18440`):

  | Code | Reason strings |
  |---|---|
  | 1001 | `gateway draining`, `idle timeout` (`FERRUM_WEBSOCKET_IDLE_TIMEOUT_SECONDS`, default 300) |
  | 1002 | `protocol error` |
  | 1008 | `credential expired`, `maximum lifetime reached`, `client trust withdrawn`, `fragmented message limit`, `Frame rate exceeded` (configurable), and the WAF reasons `message rejected by security policy`, `message exceeds inspectable size`, `message could not be inspected` |
  | 1009 | empty reason for the global limit, or the plugin's reason (default `Message too large`) |
  | 1011 | `relay error` |

  No 1012, 1013 or 4xxx codes.
- A peer's Close frame is relayed verbatim.
- Tunnel mode drops the transport with no Close frame, so the client sees 1006.
- It is unverified whether a backend TCP FIN without a Close frame becomes 1002 or 1011.

### HTTP/2 and HTTP/3

- **HTTP/2** (all wire codes come from hyper or h2, not Ferrum code):
  - Graceful shutdown: GOAWAY `NO_ERROR`.
  - More streams than the advertised limit (`FERRUM_SERVER_HTTP2_MAX_CONCURRENT_STREAMS`, default 1000): `REFUSED_STREAM`.
  - Rapid-reset flood: GOAWAY `ENHANCE_YOUR_CALM`.
  - Mid-body failure: `RST_STREAM`, `INTERNAL_ERROR` expected.
  - A credential that expired on a client that won't drain: GOAWAY, then a hard TCP close after 2 s (`src/proxy/mod.rs:14128`, `14205`).
- **HTTP/3** (codes Ferrum writes itself):
  - `RESET_STREAM(H3_INTERNAL_ERROR 0x102)` on a mid-body failure (`src/http3/stream_util.rs:402`).
  - `STOP_SENDING(H3_NO_ERROR)` after answering. This is **not** an error.
  - Connection close `H3_REQUEST_REJECTED (0x010B)` with reason `client certificate trust withdrawn`.
  - Shutdown close `H3_NO_ERROR` with reason `shutdown`.
  - GOAWAY under keepalive pressure.
  - QUIC `refuse()` under overload.
  - App code 0 with reason `handshake timeout` on the 0-RTT path.
- **CONNECT-UDP** has its own 400/403/502/503/504 JSON bodies (`src/http3/connect_udp.rs`).

### Streaming after headers are committed

- **HTTP/1.1.** Streaming responses always drop `Content-Length` (`src/proxy/headers.rs:873-889`) and are sent chunked. A backend reset or early FIN, an idle gap past `backend_read_timeout_ms` (applied per frame, `src/proxy/body.rs:3171`), a size overrun (`src/proxy/body.rs:3187`), or a credential expiry all end the body **without the terminal chunk**, followed by a connection close.
- **HTTP/2** gets `RST_STREAM`; **HTTP/3** gets `RESET_STREAM(H3_INTERNAL_ERROR)`.
- The status (often 200) and headers have already been sent. No `X-Gateway-Error` is added and no trailer is synthesized for plain HTTP or SSE.
- A small body with `Content-Length` at or below `FERRUM_RESPONSE_BUFFER_CUTOFF_BYTES` (65536) is eagerly buffered instead. The same fault then becomes a clean 502 `Backend response body read failed`, and the backend status is replaced.
- AI plugins add their own in-stream error events (section 4).

### TCP, UDP and DTLS

- **There is no in-band signal at L4.** Every setup failure closes the client connection without data: DNS, connect or backend TLS failure, no healthy targets, breaker open, `maxConnections`, a plugin reject, authorization expiry, trust withdrawal, or an unsupported policy (`StreamSetupKind`, 13 variants, `src/proxy/stream_error.rs:52-139`). With frontend TLS termination, this happens after a successful handshake.
- **SNI admission refusal:** the client sees RST (`docs/tcp_udp_proxy.md:268`).
- **Overload or stale config at accept:** the socket is dropped (`src/proxy/tcp_proxy.rs:2480-2494`).
- **UDP:** silent drops.
- **DTLS client-certificate refusal:** the server discards its final flight. The code comment and the docs disagree on whether a DTLS 1.2 alert is sent (`src/dtls/mod.rs:4241-4259`).
- **Causes are visible only in operator logs:** `error_class`, `disconnect_cause` (`idle_timeout`, `recv_error`, `backend_error`, `graceful_shutdown`, `gateway_policy`) and `disconnect_direction`.

### Frontend TLS

- **Client certificates.** When a client CA bundle is configured, the proxy frontend **requires** a client certificate at the handshake (`src/tls/mod.rs:1341-1413`). A missing or invalid certificate is a rustls alert with no HTTP response. The plain proxy frontend has no optional mode; mesh listeners have Required, Optional and None.
- **mtls_auth.** The plugin sees a certificate only when the listener requested one. Otherwise it treats the credential as missing and returns 401 `Authentication required`.
- **Unknown SNI** gets the fallback certificate (`src/tls/multi_cert.rs:141-158`), so the client sees a name mismatch in its own validation.
- **ALPN** is limited to `h2`, `http/1.1` and `acme-tls/1` (`src/tls/mod.rs:1431`). No overlap gives rustls' `no_application_protocol` alert.
- There is no special response for plaintext sent to a TLS port or TLS sent to a plaintext port (not found).

## 7. Spoofing and stripping behaviour

- **Headers a backend cannot set on HTTP/1, HTTP/2 and HTTP/3 builder responses:**
  - `X-Gateway-Error`: every case variant is removed, then re-derived (`src/proxy/mod.rs:39449`, `24809`, `24827`).
  - Hop-by-hop headers: `connection`, `keep-alive`, `proxy-authenticate`, `proxy-connection`, `te`, `trailer`, `transfer-encoding`, `upgrade` (`src/proxy/headers.rs:745`).
  - Streaming trailers named like a gateway-owned header when the gateway wrote that header (`src/proxy/headers.rs:1500-1720`).
- **Headers a backend can inject:**
  - `X-Gateway-Upstream-Status`
  - `gateway-error-reason`
  - `Via` (the gateway appends its own)
  - `Alt-Svc`
  - `WWW-Authenticate` (on relayed 401s)
  - `x-ratelimit-*`
  - `X-Gateway-Error` on native-gRPC responses
  - any JSON body that mimics a gateway literal
- **Plugins, including custom plugins and after-proxy decorators on rejects**, can emit any header on a gateway rejection, including `X-Gateway-Error`, and several statuses and bodies are operator-configurable (section 4).

## 8. Doc-vs-code drift (v0.9.5)

| Doc claim | Code | Impact |
|---|---|---|
| `docs/load_balancing.md:689`: `backend_error` means "the backend returned a 5xx error response"; other tokens mean "without contacting a backend". Also `docs/error_classification.md:325`: "Do not reuse `backend_error` for a response that never reached a backend". | `backend_error` is stamped on gateway-local 503s (buffer capacity, `http1MaxPendingRequests`, reqwest `maxConnections`), dispatch-policy 502s (egress, DNS override, SNI), and response-phase 5xx replacements (`src/retry.rs:286`, via `src/proxy/mod.rs:39448`) | Never read `backend_error` as proof of backend fault. Use the body literal. |
| `docs/load_balancing.md`: `overload` means "the gateway returned 503" | `overload` also appears on a **502** transformer ceiling (`src/proxy/mod.rs:24795`, `26156`). `docs/error_classification.md:321` does document this. | Status + body are needed to tell overload apart from the transformer ceiling. |
| `docs/load_balancing.md:671`: the headers are "only set on error responses (5xx) or degraded routing" | gRPC trailers-only **200** responses carry `circuit_breaker_open` and `concurrency_limit` (and `overload`/`config_stale` on HTTP/3) | Rules keyed on "5xx only" miss gRPC. |
| `docs/load_balancing.md:707`: `degraded` means "all targets in the upstream were marked unhealthy" | Also emitted for an unhealthy subset falling back to its parent upstream (`docs/load_balancing.md:131`, `665`) | Minor |
| `docs/error_classification.md:91-101`: `StreamSetupKind` code block lists 9 variants | The code has 13; `ClientDisconnectedDuringAdmission`, `UnsupportedStreamPolicy`, `AuthorizationExpired` and `ClientTrustWithdrawn` are missing from the doc (`src/proxy/stream_error.rs:52-139`) | Operator-log mapping only |
| `docs/load_balancing.md:678-680`: "plus the four gateway-authored tokens" | The metric set has five non-class tokens (`src/retry.rs:252-258`); `docs/error_classification.md:305` says five | Minor inconsistency |
| `docs/error_classification.md` token table implies one token per class | The mapping is path-dependent: `backend_connection_limit` (pools) vs `dispatch_policy_rejected` 503 (reqwest lane); `tls_error` vs `connection_pool_error` vs `connection_reset` for backend mTLS | Explained in the doc prose, but a rule table cannot assume one mapping |
| `src/plugins/jwks_auth.rs` doc comment on `DEFAULT_DPOP_REPLAY_MAX_ENTRIES` says 401 | The code returns 503 `DPoP replay protection is at capacity` | Plugin detail |
| `docs/frontend_tls.md:270-287` says a DTLS refusal "emits the refusal alert" | The `src/dtls/mod.rs:4241-4252` comment says `close()` queues no alert during an in-progress DTLS 1.2 handshake | Needs a lab check |
| Plan §2.1: "public error vocabulary applies to HTTP-family 5xx paths" | True for backend paths, but see the gRPC 200 cases and the WebSocket pre-upgrade cases above | Update the plan wording |

## 9. Changes after v0.9.5 that affect client-visible outcomes

`src/retry.rs` is **byte-identical** across all three refs, so the 19 classes, 7 tokens, `request_reached_wire` and `should_retry` are unchanged. `origin/main` (`8fed134`) has no `src/` changes relative to `8ef06f2`: it is release prep for v0.9.7, which ships the 0.9.6 content. v0.9.6 was tagged but never published.

| Change (v0.9.5 → 8ef06f2) | Client-visible effect | Evidence |
|---|---|---|
| Gateway API HTTPRoute `timeouts` (#5646, #5677, #5728) | New 504 `{"error":"Request timeout"}` + `backend_timeout`. It can fire **before dispatch** or during retry backoff (`dispatch_policy_rejected`). The streaming body is cut: HTTP/2 reset or HTTP/1.1 close. HTTP/3 refuses these routes with 503 `{"error":"Route request timeout is not supported over HTTP/3"}` and stops advertising Alt-Svc for them. | `8ef06f2:src/proxy/mod.rs:48962`; `src/http3/server.rs:18297` |
| HTTPRoute rule `retry` (#5695) | More hidden retries on Gateway-API routes | CHANGELOG 0.9.7 |
| Stranded pooled HTTP/1 request (#5714, #5719, #5720) | Was 504 `backend_timeout` after 30 s; now an immediate 502 `connection_failure` (`connection_pool_error`) | commit `6044b0e55` |
| `rate_limiting` `redis_failure_policy` default (#5519) | `fail_closed` (v0.9.5, `src/plugins/utils/rate_limit.rs:64`) becomes `local_fallback`. Redis request-quota clients now need the `+time` ACL. Different 429 window accounting. | CHANGELOG 0.9.7 |
| `jwt_auth` array `iss` (#5522) | Now 401 `Invalid JWT token` (was accepted); a null `nbf` is treated as absent | `8ef06f2:src/plugins/jwt_auth.rs:258-265` |
| `oauth2_introspection` not-yet-valid token | New 401 `{"error":"Token is not yet valid"}` | `8ef06f2:src/plugins/oauth2_introspection.rs:1210` |
| MCP exact endpoint (#5582) | `/mcp/` alias now 404 `Unknown MCP endpoint` | CHANGELOG 0.9.7 |
| spec_expose CSP (#5686), bot_detection allow-list edges (#5685), graphql/grpc_method_router key namespacing (#5692) | Header added; fewer false 403s; counters reset once | CHANGELOG 0.9.7 |
| Relay flush / write timeout (#5588, #5676) | TLS relays and WebSocket tunnel mode may now close with a write-inactivity timeout where v0.9.5 hung | CHANGELOG 0.9.7 |
| HBONE peer auth (mesh only) | New 403 `HBONE tunnel requires an authenticated mesh peer` | `8ef06f2:src/proxy/hbone_proxy.rs` |

The full list is in `outcomes.json` → `drift`.

## 10. Reconciliation with the failure-matrix seeds

`FERRUM_ANVIL_FAILURE_MATRIX.json` → `source_class_seed_coverage` and `public_header_seed_coverage`, checked against the v0.9.5 source.

| Seed | Case | Reconciliation |
|---|---|---|
| `dns_lookup_error` | UP-001 | The public body differs by path. The reqwest HTTP/1 lane returns `Backend DNS resolution failed`; the pools return `Backend unavailable`. Fixtures must pin the dispatch path. |
| `connection_refused`, `connection_timeout` | UP-002, UP-003 | OK. Default connect timeout is 5000 ms (`src/config/types.rs:5613`). |
| `tls_error` | UP-004 | OK for server-certificate failures in the connector. Backend **mTLS** (UP-006) on the reqwest HTTP/1 pool yields `connection_pool_error` or `connection_reset` instead of `tls_error`. |
| `read_write_timeout` | UP-009, UP-010, UP-011 | Same public pair for all three: 504 `Backend timeout` + `backend_timeout`. The watermark that fired appears only in logs. UP-011 on a **streaming** response is a truncated body, not a 504. |
| `connection_reset`, `connection_closed` | UP-012, UP-013 | Before response headers: 502 `backend_error`. After headers: truncated stream. Eager-buffered bodies up to 64 KiB with `Content-Length` become 502 `Backend response body read failed`. |
| `response_body_too_large` | UP-014 | A declared or buffered over-limit body gives 502. A streamed body without `Content-Length` is truncated mid-stream. |
| `gateway_buffer_capacity` | UP-015 | 503 with **`backend_error`**, not a dedicated token. |
| `connection_pool_error` | UP-016 | At v0.9.5 the stranded-pooled-request race gives **504 `backend_timeout`** after 30 s, not 502. That is fixed in v0.9.6. |
| `port_exhaustion` | UP-017 | Needs the lab hook, as the plan says. |
| `backend_connection_limit` | UP-018 | **Path-dependent.** The reqwest lane returns 503 `Backend connection limit exceeded` + `backend_error` with class `dispatch_policy_rejected`, **not** `backend_connection_limit`. The class is only produced on the direct-H2, H3, gRPC and HBONE pools. |
| `trust_withdrawn` | UP-019 | Only on mesh transports (HBONE / sidecar mTLS). It is unreachable on a plain gateway-to-HTTP backend. |
| `request_error` | UP-020 | OK: 502 `backend_error`. |
| `client_disconnect` | LOCAL-011 | Client-side. The gateway may log 499; the client normally sees nothing. |
| `protocol_error` | PROTO-003 | A backend HTTP/2 reset before headers gives 502 `backend_error`. After headers, the frontend stream is reset. |
| `graceful_remote_close` | PROTO-009 | For WebSocket this class is only used in logs; the client sees the peer's relayed Close frame. On HTTP it is the HTTP/3-backend `H3_NO_ERROR`-before-headers case: 502 `backend_error`. |
| `request_body_too_large` | GW-008 | 413 with no token. gRPC gets 8. |
| `dispatch_policy_rejected` | GW-009 | The transformer ceiling uses 502 + `overload`. Many other `dispatch_policy_rejected` paths use `backend_error` (section 5). |
| token `overload` | GW-002, GW-003, GW-009 | The bytes are identical for overload and drain. GW-009 differs by status (502) and body. |
| token `config_stale` | GW-005 | Needs data-plane mode and a lost control plane for more than `FERRUM_DP_CONFIG_MAX_STALE_SECONDS` with `fail_closed`. A `readiness_only` stale action produces no client signal. |
| token `backend_error` | GW-017, UP-012, UP-014, UP-015 | OK. Add gateway-local lookalikes as negative controls: buffer capacity, `http1MaxPendingRequests`, egress denial. |
| token `connection_failure` | UP-001…004, UP-016 | UP-016 at v0.9.5 may surface as `backend_timeout` (see above). |

**Cases the matrix does not yet name:**
- A backend-spoofed `X-Gateway-Upstream-Status`.
- `X-Gateway-Error` on a gRPC 200.
- A gRPC backend injecting `X-Gateway-Error`.
- The `WWW-Authenticate: ferrum-edge` fallback.
- `Destination active request limit reached` (503, no token).
- Per-IP 429.
- The AI in-stream error frames followed by `[DONE]`.
- JSON-RPC errors carried under HTTP 200 (MCP, A2A).
- Parse-layer 400 envelopes, and hyper's empty-bodied 400s.

## 11. Implications for Anvil diagnostic rules

These are concrete rule-design facts for v0.9.5. Each rule should declare `compatibility_id: ferrum-edge-0.9.5`.

**Provenance and trust**

1. Treat every Ferrum marker as **"Ferrum-like, unverified"** unless the destination is an explicitly trusted Ferrum profile. That covers the 7 tokens, `Via … ferrum-edge`, `WWW-Authenticate: ferrum-edge`, `realm="ferrum-edge"`, `gateway-error-reason` and the gateway body literals. All of them can be forged, and `Via` can be renamed or switched off.
2. Missing `Via` is **not** evidence that no gateway was involved. Pre-dispatch gateway rejects never carry it: 404, 405, 401 and other plugin rejects, 431, the 503 fences, and the circuit-breaker 503.
3. `X-Gateway-Upstream-Status` is backend-spoofable on HTTP/1 and HTTP/2. At most report "degraded routing reported" as a warning, never a confirmed fact.
4. Handle duplicate header lines. The gateway *appends* `X-Gateway-Upstream-Status`, `Via` and `Alt-Svc` next to any backend copy.

**Reading `X-Gateway-Error`**

5. Evaluate the token together with the protocol:
   - It can appear on **HTTP 200 gRPC trailers-only** responses (`circuit_breaker_open`, `concurrency_limit`; also `overload` and `config_stale` on HTTP/3).
   - It is **absent** on HTTP/1 and HTTP/2 gRPC overload and config_stale rejects, and on **all** gRPC backend dispatch errors (14 `Backend unavailable`, 4 `Backend deadline exceeded`).
   - For gRPC, rules must key on `grpc-status` plus the exact `grpc-message` literal.
6. `connection_failure` means "pre-wire setup failure: DNS, TCP, TLS, pool, port exhaustion, connection ceiling or trust withdrawal". The only public sub-signal is the reqwest body `{"error":"Backend DNS resolution failed"}`, which confirms a gateway-side DNS failure on that path. The generic `Backend unavailable` body must stay broad. Never infer "TLS" or "DNS" from it.
7. `backend_error` must be explained as "failure at or after the upstream exchange, **or** a gateway-local refusal". Downgrade to gateway-local when the body is one of these exact gateway literals:
   - `Response buffering capacity exceeded`
   - `HTTP/1.1 in-flight request limit reached`
   - `Backend connection limit exceeded`
   - `backend address blocked by egress policy`
   - `backend DNS override cannot be applied to literal target`
   - `Bad Gateway` + `gateway-error-reason`
   - `response representation could not be inspected`
   - `response redaction failed`

   Do the same when the body is `Backend DNS resolution failed` **with** `backend_error`: that is an egress-policy denial, not DNS.
8. `backend_timeout` is keyed on status 504 alone:
   - Body `{"error":"Backend timeout"}` (trusted Ferrum): the gateway's backend timeout. Upload stall vs header wait vs buffered-body idle cannot be told apart.
   - Any other 504 body: the upstream's own 504, relayed.
   - At v0.9.5 a gateway 504 **does not prove the backend received the request** (stranded pooled HTTP/1 request). Never say "the backend was slow" with certainty.
9. `overload`:
   - 503 + `{"error":"Service overloaded"}` means overload **or** drain. They are indistinguishable.
   - 502 + `{"error":"Response body too large","limit":N}` means the response-transformer ceiling, not load.
   - The same `{"error":"Response body too large","limit":N}` body with **502 + `backend_error`** comes from the `response_size_limiting` plugin.
10. `circuit_breaker_open` rejects only *this* attempt. With retries, earlier attempts may have reached the backend, so dispatch state for the whole request is `may_have_been_sent` unless retries are known to be off.
11. `config_stale` is only reachable in data-plane mode, and only after `FERRUM_DP_CONFIG_MAX_STALE_SECONDS` (3600 s default). Owner: gateway operator. Never suggest client payload changes.
12. `concurrency_limit` comes only from the `adaptive_concurrency` plugin. Other 503 shedders use no token: `Destination active request limit reached`, `WebSocket connection limit exceeded`, and AI `provider_concurrency_exhausted`.

**Dispatch state and retry safety**

13. Map dispatch state from the public signal conservatively:
    - `connection_failure`: `not_dispatched` for the **final** attempt only.
    - `backend_error` with a `Backend unavailable` body: `may_have_been_sent`.
    - Gateway-local literal bodies (the list in item 7): `not_dispatched`.
    - 504: `may_have_been_sent` (at v0.9.5 possibly not sent at all).
    - Truncated stream: `sent`.
14. Never auto-retry a non-idempotent request on `backend_error`, `backend_timeout`, a stream reset, or a missing gRPC status.

**Transport and streaming**

15. Transport-first findings:
    - A dropped connection right after TCP accept is consistent with gateway connection shedding (`FERRUM_MAX_CONNECTIONS`, overload), but also with any middlebox.
    - A missing chunked terminator on HTTP/1.1, `RST_STREAM` on HTTP/2, or `RESET_STREAM(0x102)` on HTTP/3 after a 2xx means "incomplete response". The gateway never downgrades the status.
    - HTTP/3 `STOP_SENDING(H3_NO_ERROR)` after a complete response is benign.
16. SSE and AI streams: `event: error` or `data: {"error":…}` frames inside a 200 stream are failures even when followed by `data: [DONE]` (see section 4).

**Authentication and policy**

17. Auth 401s:
    - **Per-plugin body literals are distinct and stable** for most mechanisms (key_auth, basic_auth, hmac_auth, the jwks DPoP family, SOAP messages). Rules may name the *likely* mechanism from the body, but only with a trusted gateway.
    - `jwks_auth` `Invalid or unrecognized JWT` and `jwt_auth` `Invalid JWT token` each collapse expiry, signature, issuer, audience and key-id causes. Anvil's own local JWT decode is the only way to be more specific, and that is a client-side finding.
    - A **JWKS outage is indistinguishable** from a bad token.
    - `WWW-Authenticate: ferrum-edge` plus `{"error":"Authentication required"}` means no usable credential was presented for any configured mechanism.
    - `hmac_auth` rejects any non-HMAC `Authorization` scheme, and `ldap_auth` rejects any non-Basic one. In single-auth mode that can mask the credential the caller meant for another plugin.
18. Dependency outages that **are** distinguishable:
    - OPA fail-closed: 503 `authorization service unavailable` (vs 403 `forbidden by policy`).
    - Introspection: 503 `Token introspection unavailable`.
    - LDAP: 500 `LDAP authentication temporarily unavailable`.
    - HMAC/DPoP replay store: 503.
    - GeoIP: 403 with a unique body.

    Outages that are **not** distinguishable: mesh ext-authz (403 by default), `soap_ws_security` replay store (401).
19. 403 without provenance must stay ambiguous. Many gateway 403 bodies are generic (`{"error":"Forbidden"}` from WAF and bot_detection by default) and operator-configurable, and backends return the same shapes.
20. Statuses and bodies are **operator-configurable** for WAF, OPA, request_termination, response_mock, ai_tool_governor and several validators. Rules keyed on default literals must lower confidence when a body does not match exactly, and must never use the status alone.
21. Frontend mTLS failure is a TLS alert, never an HTTP 401, when the listener requires a client certificate. A 401 from `mtls_auth` means the certificate was accepted at TLS but not mapped to a consumer (or the listener did not request one).

**gRPC and other protocols**

22. For gRPC, apply `http_reject_status_to_grpc_status` in reverse only as a *hint*. For example, 16 can come from any auth plugin, credential expiry or client-trust withdrawal. Header-limit (431), per-IP (429) and protocol-header (400) rejects reach gRPC clients as **plain HTTP**, so the client library's synthesized status is not a gateway status.
23. WebSocket: a gateway-authored close is one of 1001, 1002, 1008, 1009 or 1011 with a known reason string. Any other code, or a known code with a different reason, was relayed from the peer.
24. L4 (TCP, UDP, DTLS) outcomes cannot carry a cause. Anvil must say "the connection closed or no datagram was answered", and suggest operator log correlation.

**Versioning**

25. Scope rules by version. Against v0.9.6/0.9.7:
    - A 504 `{"error":"Request timeout"}` can mean "not dispatched" on Gateway-API routes.
    - Stranded HTTP/1 requests become 502 `connection_failure`.
    - `rate_limiting` fails open per pod during a Redis outage by default.
    - New 401 bodies exist (see section 9).

**Gateway-authored lookalikes**

26. Several gateway-authored responses carry **no marker**, so they must never be assumed to come from the backend:
    - `fault_injection` aborts and delays.
    - `response_mock` bodies.
    - `request_termination`, which returns 503 `{"message":"Service unavailable","status_code":503}` by default.
    - `serverless_function` output.
    - `response_caching` / `request_deduplication` replays. These do add `x-cache-status` / `x-idempotent-replayed`.
27. `security_headers` removes `Server` and `X-Powered-By`, so a missing backend `Server` header says nothing about the path.
28. A panic in any plugin aborts the whole gateway process in release builds (`panic = "abort"`). The client sees an abrupt connection reset for every in-flight request, with no HTTP error.
29. GraphQL-shaped (`{"errors":[…]}`), JSON-RPC-shaped (MCP/A2A, often under HTTP 200) and OpenAI-shaped (ai_federation) errors can be gateway-authored. Body-shape heuristics must not equate "application-shaped error" with "the application answered".

## 12. Gaps / not audited

- **Wire codes owned by libraries:**
  - hyper's HTTP/2 `RST_STREAM` reason on body errors, including whether a backend's own reason propagates.
  - h2's `REFUSED_STREAM` and `ENHANCE_YOUR_CALM`, and its header-list overflow behaviour.
  - The exact rustls alert per client-certificate failure.
  - The QUIC close code on a full-handshake timeout.
  - hyper's automatic 400/431 bodies and statuses per parse error.

  Ferrum code only configures these. They need lab confirmation.
- **Inferred but not traced end to end:**
  - `X-Gateway-Error: backend_error` on response-phase or final-body 5xx plugin replacements, such as `response_size_limiting`, AI response guards, the `soap_ws_security` 500, and representation-uninspectable.
  - The H3 variants of the pre-auth body-buffer 413.
  - Streamed-upload overflow after response headers on the HTTP/1 and HTTP/2 gRPC path.
  - Whether a backend TCP FIN without a WebSocket Close becomes 1002 or 1011.
- **Not enumerated exhaustively:**
  - The ~90 SOAP WS-Security and SAML message literals (the families and key messages are recorded).
  - ai_federation translation error strings.
  - MCP `-32006` catalog messages.
  - The full CONNECT-UDP 400 list (`src/http3/connect_udp.rs:316-480`).
  - Every `{"error":…}` in mesh-only paths (HBONE, waypoint, sidecar ingress).
- **Mesh and Kubernetes modes** (HBONE, waypoints, SPIFFE, ext-authz providers from mesh slices) were covered only where an ordinary gateway client could hit them.
- **Admin API, control-plane gRPC, CNI and node-agent** surfaces were out of scope.
- **Custom plugins.** Behaviour is recorded generically (section 4). Build-time custom plugins can emit any status, body or header.
- **Coverage method.** No live binary was run. Every outcome is a source reading of v0.9.5 and needs the lab fixtures in plan §15 before a rule can claim `confirmed`. The outcome list is a manual inventory, not a proof of completeness. New `ErrorClass` variants, tokens or rejection phases in later refs must fail the contract-drift gate. As a starting point, `ErrorClass::ALL` and `HTTP_OBSERVABILITY_ERROR_CLASSES` are unchanged in 8ef06f2 and main.
