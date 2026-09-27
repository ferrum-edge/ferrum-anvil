# Ferrum Edge 0.9.7 → 0.9.8: client-observable delta (A00 addendum)

| Item | Value |
|---|---|
| Compatibility ids | `ferrum-edge-0.9.5`, `ferrum-edge-0.9.7` (unchanged) and `ferrum-edge-0.9.8` (new, the default for new profiles and the lab's default pin) |
| Releases compared | tag `v0.9.7` = `8fed1346ce2e267eb69c03683cb89ea44d785e0b` (`8fed134`) → tag `v0.9.8` = `e27f2109216352c3fe9e67a7014611f3f66daa91` (`e27f210`) |
| Audit date | 2026-09-27 |
| Machine-readable inventory | [`catalog/ferrum/ferrum-edge-0.9.8/outcomes.json`](../../catalog/ferrum/ferrum-edge-0.9.8/outcomes.json): **540** outcomes (538 − 1 removed + 3 added), 30 changed, 1360 source citations |
| Baseline audit | [`gateway-0.9.7-delta.md`](gateway-0.9.7-delta.md) and [`catalog/ferrum/ferrum-edge-0.9.7/outcomes.json`](../../catalog/ferrum/ferrum-edge-0.9.7/outcomes.json) |
| Source diff | 56 files under `src/` differ; 13,277 insertions and 2,807 deletions (`src/http3/cross_protocol.rs` 3,061 changed lines, `src/proxy/mod.rs` 2,112, `src/http3/server.rs` 1,571) |
| Wire libraries | rustls 0.23.45, hyper 1.9.0, h2 0.4.19, h3 0.0.8, quinn 0.11.9, reqwest 0.13.3 and tungstenite unchanged; the vendored hyper-util moves from 0.1.20 to 0.1.21 with the same Ferrum patch |
| Release pin | `lab/gateway/RELEASE.lock` = `lab/gateway/releases/v0.9.8.lock`: the published `.sha256` of each release asset |

All `path:line` citations below are at `v0.9.8` (`e27f210`) unless marked `@8fed134`.

## Method

- **Read-only.** Both tags were exported with `git archive` into a scratch directory. The gateway
  repository was never checked out, modified or switched.
- **Mechanical carry-forward.** Every source citation of the 537 carried outcomes was remapped
  through the `diff` line map of its file (`vendor/hyper-util-0.1.20-ferrum-patched/` →
  `vendor/hyper-util-0.1.21-ferrum-patched/`), and the cited line text is identical in both trees.
  Eight citations landed in changed hunks and were re-cited by hand: the final builder's
  `X-Gateway-Error` strip and write (`src/proxy/mod.rs:41000`, `:41001`), the idle-read wrapper
  (`src/proxy/body.rs:5493`), the two gRPC attempt-budget charge helpers (`src/proxy/mod.rs:50415`,
  `:50448`), the HTTP/3 accept loop's GOAWAY and 0-RTT handshake-timeout lines
  (`src/http3/server.rs:2055`, `:1821`) and the datagram relay's revocation arm
  (`src/proxy/hbone_proxy.rs:2751`). Four citations carried over since the 0.9.5 audit pointed at a
  blank line; they now cite their symbol. Path:line references in prose were remapped the same way.
  Every citation carries sha `e27f210`.
- **Re-audit of changed code.** An outcome was flagged when the function around any of its
  citations changed: 46 outcomes. Each flagged function was read in both trees.
- **Literal diff.** Status, JSON body, header-name, gRPC-status and rejection-phase literals were
  diffed per file between the trees, to catch new or removed signals the flagging missed.
- **CHANGELOG.** Every `[0.9.8]` entry was checked against the code; the ones that change a
  proxied response are recorded below, the rest under `drift` → `not_client_observable`.
- **Mechanical checks of the result.** Every citation points at a non-blank line at `v0.9.8`; the
  330 prose `path:line` references are in range; the drift test
  (`crates/anvil-diagnostics/tests/catalog_drift.rs`) checks the three catalogs for internal
  consistency (sibling, fixture and removal ids resolve, tokens are in the release's vocabulary,
  every citation uses the catalog's own sha).
- **Not verified live.** This change was prepared without running the lab. GitHub CI runs the
  `core` profile against the new default pin on the pull request; the nightly lab runs every
  profile against v0.9.8, v0.9.7 and v0.9.5. Until that run, the v0.9.8 lab expectations below
  are source-derived.
- **Not a completeness proof.** As with the earlier audits, only strings seen in code are recorded,
  and wire behaviour owned by hyper, h2, rustls or quinn is marked as such.

## Changed: the marker contract

`src/retry.rs` gains an eighth `X-Gateway-Error` token (#5762, #5778):

- `request_timeout` (`src/retry.rs:223`) marks a route-deadline 504 `{"error":"Request timeout"}`
  that **no backend held**: the recorded route-timeout phase is `before_dispatch`, `retry_backoff`,
  or an HTTP/3 upload still being buffered (`x_gateway_error_for_response`,
  `src/proxy/mod.rs:25658`; `route_request_timeout_before_backend`, `src/plugins/mod.rs:4555`). The
  phase is a typed marker only trusted proxy code sets; a plugin writing the `route_request_timeout`
  metadata key cannot change it (#5783).
- `backend_timeout` therefore always means a backend held the request, including the route-deadline
  504 logged as `dispatch` and a backend's own 504.
- The 19 error classes, `request_reached_wire`, `should_retry` and the `(connection_error, status)`
  derivation (`src/retry.rs:287`) are unchanged. `http_reject_status_to_grpc_status` is
  byte-identical (moved to `src/proxy/grpc_proxy.rs:2304`).

The gateway-owned headers are hardened (#5759, #5783, #5798, #5807):

- `X-Gateway-Error` and `X-Gateway-Upstream-Status` are one gateway-owned list
  (`src/proxy/headers.rs:791`). Every backend response boundary strips a backend copy in headers or
  trailers (`src/proxy/headers.rs:754`): reqwest, direct HTTP/2, native gRPC, native HTTP/3, the
  HTTP/3 bridge and serverless functions.
- The H1/H2 builder (`src/proxy/mod.rs:41001`, `:41014`, `:41018`), the H1/H2 native gRPC builders
  (`:36970`, `:38038`) and every HTTP/3 response (`src/http3/server.rs:10692`) write the token after
  the last hook, replacing a hook- or plugin-written copy. A backend 5xx over any HTTP/3 path, or from
  a gRPC backend over H1/H2, now carries `backend_error`.
- Plugin reject paths still keep a plugin-written value (lab GW-019 reject-decorated), and any
  non-Ferrum endpoint can send the headers.

**Consequences for Anvil.** `request_timeout` is a known token only for the `ferrum-edge-0.9.8`
catalog. It is not part of the vocabulary every audited release shares, so a profile without a
catalog (or with an older one) reports it as `ferrum.marker.unknown_token`. Its finding
(`ferrum.token.request_timeout`) claims scope gateway admission and owner unknown: a slow client
upload is the caller's, gateway processing and the route budget the operator's. The markers stay
spoofable, so marker-derived claims stay capped at likely; `backend_error` keeps scope Unknown; the
4xx-marker inconsistency rule holds (the new token is only written on a 504).

## Removed outcome

| Outcome | 0.9.7 signal | 0.9.8 behaviour | Evidence |
|---|---|---|---|
| `protocol.http3.route_timeout_unsupported` | A plain HTTP/3 request on a route rule with request or attempt timeouts: 503 `{"error":"Route request timeout is not supported over HTTP/3"}`, rejection phase `route_request_timeout_unsupported`; `Alt-Svc` withheld on ports serving such rules. | Native HTTP/3 and the HTTP/3 bridge enforce the timeouts: the same 504, token and phase as HTTP/1.1 / HTTP/2; a body cut is an `H3_REQUEST_CANCELLED` reset; `Alt-Svc` is advertised again. | `src/http3/server.rs:4708@8fed134` (gate removed), `src/http3/server.rs:4752`; `src/http3/route_deadline.rs:57`, `:168`; CHANGELOG #5646, #5729 |

It is listed under `removed_outcomes` in the 0.9.8 catalog. The 0.9.7 catalog keeps it.

## New outcomes

| Outcome | Public signal | Where | Notes |
|---|---|---|---|
| `protocol.hbone.relay_destination_denied` | 403 `{"error":"HBONE relay destination not allowed"}` \| the `UDP` variant | `src/proxy/hbone_proxy.rs:135`, `:142`, `:204`, `:1139`, `:1309`, `:1913`; `src/proxy/mod.rs:2701`, `:2842` | Mesh only. At relay synthesis new in 0.9.8 (was a 404 route miss); at the post-plugin re-check and post-DNS screens already present but uncatalogued at 0.9.7. |
| `protocol.hbone.relay_not_ready` | 503 `{"error":"HBONE relay not ready"}` \| the `UDP` variant | `src/proxy/hbone_proxy.rs:121`, `:128`, `:173`; `src/proxy/mod.rs:2842` | Mesh only. A terminator that has not applied its first mesh slice (#5763). |
| `upstream.pool.client_build_failed` | 502 `{"error":"Bad Gateway"}` + `connection_failure` | `src/proxy/mod.rs:44491`, `:44496`, `:46209`, `:42788`; `src/http3/cross_protocol.rs:1856` | A reqwest client that cannot be built (backend TLS material, egress refusal). Present but uncatalogued on the 0.9.7 first attempt; 0.9.8 uses the same fixed body on the retry path (was `Backend unavailable: <error text>`) and tokens the HTTP/3 bridge's answer (#5778, #5824). |

## Changed outcomes

### Route timeouts (#5646, #5729, #5738, #5741, #5743, #5762)

| Outcome | Change | Evidence |
|---|---|---|
| `upstream.route_request_timeout.not_dispatched` | Token `request_timeout` instead of `backend_timeout`; HTTP/3 added; no longer shares its signal with `backend_held`; family `gateway_admission` (the token says no backend held the attempt). An HTTP/3 upload timeout is a plugin-style reject with `Content-Type: application/json`, phase `route_request_timeout_h3_upload`. | `src/proxy/mod.rs:25658`, `:50009`; `src/plugins/mod.rs:4555`; `src/http3/server.rs:17600`, `:17607`, `:16701` |
| `upstream.route_request_timeout.backend_held` | HTTP/3 added; `backend_timeout` on this body now means a backend held the attempt. | `src/http3/cross_protocol.rs:600` |
| `upstream.timeout.route_attempt_budget` | HTTP/3 added; a fresh budget per retry attempt; an expiry is retried when the rule's retry lists 504. | `src/http3/route_deadline.rs:168` |
| `streaming.route_deadline_cut_after_headers` | HTTP/3 added: `H3_REQUEST_CANCELLED` reset; a client that withholds flow control is cut too. | `src/http3/route_deadline.rs:57` |
| `protocol.grpc.client_deadline_exceeded`, `protocol.grpc.backend_timeout` | The HTTP/3 bridge charges a post-send attempt-budget expiry as `Backend deadline exceeded` (was `Deadline exceeded at gateway`); `after_proxy` plugins no longer turn the charged terminal into the gateway's own; gRPC-Web terminals carry CORS decorations. | `src/proxy/mod.rs:50415`, `:50448`; CHANGELOG #5734, #5744, #5747 |

### Markers on relayed responses (#5759, #5783, #5798, #5804, #5805)

| Outcome | Change | Evidence |
|---|---|---|
| `upstream.application_5xx` | A backend 5xx over every HTTP/3 path and from a gRPC backend over H1/H2 now carries `backend_error`. | `src/http3/server.rs:10692`; `src/proxy/mod.rs:36970`, `:38038` |
| `upstream.application_non5xx` | A backend's `X-Gateway-Upstream-Status` is stripped too. | `src/proxy/headers.rs:754` |
| `upstream.degraded_routing` | A backend- or hook-written copy is stripped; `degraded` is written once, only on fallback. | `src/proxy/mod.rs:41001`, `:41018`; `src/http3/server.rs:10637` |
| `upstream.response_too_large.declared_or_buffered` | The HTTP/3 declared-oversize 502 and the bridge's buffered refusals carry `backend_error`. | CHANGELOG #5804, #5805, #5807 |

### Mesh (#5763, #5765)

| Outcome | Change | Evidence |
|---|---|---|
| `gateway.routing.no_route` | An inbound HBONE CONNECT the terminator does not own no longer gets this 404. | `src/proxy/mod.rs:2701` |
| `protocol.hbone.connect_peer_not_admitted` | Also a peerless CONNECT refused at relay synthesis. | `src/proxy/mod.rs:2856`; `src/proxy/hbone_proxy.rs:107` |
| `protocol.hbone.tunnel_admission_revoked` | A datagram relay that ends on a socket error records `hbone.udp.termination_reason` (operator log only). | `src/proxy/hbone_proxy.rs:241`, `:2751` |

### Other

| Outcome | Change | Evidence |
|---|---|---|
| `gateway.admission.early_data_rejected` | HTTP/3 classifies early data per accepted stream, so a 1-RTT request racing the handshake no longer draws the 425 (#5761). | `src/http3/peer_identity.rs:146`, `:370`; `src/http3/server.rs:2146` |
| `streaming.backend_body_failure_after_headers`, `streaming.response_size_exceeded_mid_stream`, `streaming.idle_read_timeout_after_headers` | The terminal error is held one scheduler turn, so an HTTP/1.1 client sees the committed status line before the truncation (#5801, #5802, #5811). | `src/proxy/body.rs:5493` |
| `protocol.grpc.backend_unavailable`, `protocol.grpc.response_build_failed` | gRPC-Web terminals run the reject-path `after_proxy` decorators (#5747); pass-through gRPC-Web is relayed byte for byte, with no synthesized `grpc-status: 2` frame (#5758). | `src/proxy/mod.rs:37222`, `:38268` |
| `upstream.pool.dispatch_canceled` | A reqwest client that cannot be built is now its own outcome. | `src/proxy/mod.rs:44496` |
| `plugin.response_caching.hit`, `plugin.request_deduplication.replay`, `plugin.ai_semantic_cache.hit` | Rate-limit fields are not stored or replayed (#5788, #5789, #5793). | CHANGELOG |
| `gateway.admission.adaptive_concurrency` | The latency baseline relearns over two windows of `baseline_window_samples` (#5737). | `src/plugins/adaptive_concurrency.rs:162`, `:184` |
| `plugin.ai_semantic_firewall.*`, `plugin.ai_response_guard.*`, `plugin.ai_tool_governor.stream_cut` | WHATWG SSE framing (BOM, CR, LF, CRLF) for inspection; a stream cut ends a partial line before its error event (#5795, #5803, #5820, #5826). | `src/plugins/utils/sse.rs`; `src/plugins/ai_tool_governor.rs:5107` |

### Other catalog-level changes

- `public_tokens` gains `request_timeout`; `marker_semantics` gains its release note and new
  `backend_timeout` / `backend_error` notes.
- `rejection_phases_operator_only` drops `route_request_timeout_unsupported` and gains
  `route_request_timeout_h3_upload` and the HBONE deny policies a relay-synthesis refusal now logs.
- The `X-Gateway-Error`, `X-Gateway-Upstream-Status` and `Alt-Svc` header entries are rewritten.
  `spoofable_by_backend` stays `true` for both markers: a plugin rejection or a non-Ferrum endpoint
  can still send them.
- The `drift` section records the v0.9.7 → v0.9.8 reconciliation, including the changes with no
  catalogued signal (HTTP/2 trailers relayed on the reqwest and buffered paths, #5760; the
  Workload API `ValidateJWTSVIDResponse.claims` becoming a `google.protobuf.Struct`, #5780, which
  Anvil does not read; Gateway API redirect validation and route response headers, #5752/#5753;
  off-worker backend TLS builds, #5754/#5782; HTTP/3 stream-error handling, #5741/#5751).

## Anvil changes this delta drives

- **Catalogs.** `anvil_diagnostics::ferrum` embeds `ferrum-edge-0.9.8` and makes it the default for
  new profiles (desktop dialog, CLI `--trust-ferrum`). Records name it as the catalog used.
- **Wording.** `catalog/diagnostics/findings.en.json` gains `ferrum.token.request_timeout`
  (release-neutral; the catalog's `marker_semantics` adds the release sentence).
- **Lab.** The default pin is v0.9.8 (`lab/gateway/RELEASE.lock`, `lab/gateway/releases/v0.9.8.lock`).
  Every lab profile's trusted Ferrum profile declares the running release's compatibility id: `h3x`,
  `proxyproto` and `mesh` declared `ferrum-edge-0.9.5` whatever release ran (ferrum-anvil#137).
  `anvil-lab run` and `up` refuse a release with no catalog, or with one audited at another commit.

## Lab

Expected release differences (source-derived; see "Not verified live" above):

| Scenario | v0.9.5 / v0.9.7 | v0.9.8 |
|---|---|---|
| MESH-009, MESH-010, MESH-011 (relay synthesis refuses an authority) | 404 `{"error":"Not Found"}`, debug line only | 403 `{"error":"HBONE relay destination not allowed"}`, transaction line with `mesh.relay.denial_reason` |
| MESH-023, MESH-028, MESH-033 (the same over a datagram CONNECT) | 404 `{"error":"Not Found"}` | 403 `{"error":"HBONE UDP relay destination not allowed"}` |
| MESH-026, MESH-027 (UDP relay ends on the workload port's ICMP error) | debug `HBONE UDP tunnel relay completed` | debug `HBONE UDP tunnel relay ended on a socket error` (same byte counts) |
| GW-019-ERROR, GW-019-OK, GW-019-FORGED (injected `X-Gateway-Upstream-Status`) | passes to the client; Anvil reports a capped degraded-routing warning | stripped; no marker warning |
| GRPCWEB-lookalike (pass-through gRPC-Web) | a synthesized trailer frame follows the backend's (v0.9.7) | the backend's body byte for byte (the scenario accepts both) |

The scenarios pick the release's expectation with `gateway::release_at_least("v0.9.8")`.

## Not verified live (source only)

- Everything in this delta until the nightly lab has run v0.9.8: the lab expectations above, and
  the route-timeout, marker-hardening, HTTP/3 early-data and streaming-flush changes.
- Route timeouts over HTTP/3, as for 0.9.7: they need Gateway API or `mesh_route_dispatch` rules
  with timeouts, which `ferrum-edge validate` rejects on 0.9.5, and the file-mode lab shares one
  config across releases.
- `hbone_relay_not_ready`: the lab's mesh instances always have their file-source slice.
- The pool-client build failure: the lab has no way to make a reqwest client fail to build without
  unreadable TLS material.
- Library-owned details (HTTP/2 and HTTP/3 reset codes, FIN vs RST) belong to hyper, h2, h3 and
  quinn.
