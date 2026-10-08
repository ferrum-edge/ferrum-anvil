# Ferrum Edge 0.9.11 → 0.9.14: source delta audit

| Item | Immutable identity / status |
|---|---|
| Baseline | `v0.9.11`, `c764084b3b51c3f7ffde268c039688d35e49c553` (source-audited and hosted-qualified in [gateway-0.9.11-delta.md](gateway-0.9.11-delta.md)) |
| Covered intermediate releases | `v0.9.12`, `0d917701b63ef38210c49df830f48cf0457cbc7d`; `v0.9.13`, `9b83115de7ec23ab51ec4feae6bed65e596db425` (audited through this delta, not pinned separately) |
| Audited target | `v0.9.14`, `9bd4d5f9caa4ebe8f0ea13e76d8a6e2172eaca7d`, [release 405571232][release] |
| Contracts | Published `contracts-edge-0.9.14`, `ddbdd845733b7046c4393ac951011dafb774db33` |
| Catalog | [`ferrum-edge-0.9.14/outcomes.json`](../../catalog/ferrum/ferrum-edge-0.9.14/outcomes.json), 553 carried outcome IDs with the delta below |
| Lab selection | `lab/gateway/RELEASE.lock` and `lab/gateway/releases/v0.9.14.lock`; v0.9.11 is retained as an earlier supported release |
| Hosted qualification | All-profile Lab run 37758644110 on the PR head and scheduled all-profile Lab run 37770270997 after the MESH-011 fix (#342); results are recorded below |
| Audit date | 2026-10-08 |

The [immutable comparison][compare] changes 57 files under `src/` (8,316 insertions, 1,091
deletions; four new files), plus vendored Hyper/h2 patches, dependency floors, tests and
documentation. By release: v0.9.11→v0.9.12 changes 10 `src/` files, v0.9.12→v0.9.13 33 and
v0.9.13→v0.9.14 40. This is a separate source delta audit on top of the
[0.9.11 inventory](gateway-0.9.11-delta.md), not a new comprehensive inventory. The historical
0.9.5, 0.9.7, 0.9.8, 0.9.9, 0.9.10 and 0.9.11 catalogs and release locks remain available and
unchanged.

All `file:line` citations below are at v0.9.14 (`9bd4d5f`) unless a release is named.

## Method and limits

Both source trees were read at the exact commits above with `git show` and `git diff`, without
checkout, build, formatting, test, script, binary or container execution. Every structured
catalog citation and every unqualified full-path prose citation was remapped through the
immutable unified diff, and the cited line text was required to be identical at both ends.
1,437 structured and 334 prose citations remapped that way; four structured citations fell
inside changed hunks and were repointed by hand to the current code (the buffered collector's
`read_error` and the gRPC H2 EOF-versus-reset check, which three outcomes cite). Explicitly
historical `@sha` prose citations remain historical.

Citation text equality alone does not establish behavioral equality. The changed dispatch,
classifier, buffering, upload, plugin-trust, admin and pool paths below were separately read
against their surrounding source, the [0.9.12–0.9.14 changelog][changelog] and the
[upgrade guide][upgrade]. A global comparison of every catalog public signal (status, token and
JSON body) against both catalogs finds exactly one changed match set, the buffered read error
below. The catalog records no new outcome ID, no new token and no new diagnostic cause.

Local validation is static inspection, `git diff --check` and read-only consistency checks of
the new JSON only; no project tooling ran locally. Unit, parser and catalog checks cannot
establish live gateway compatibility. Hosted Lab evidence is recorded below; no physical-device
acceptance or performance measurement is claimed.

## Marker, error class and header decisions

The [ErrorClass enum][retry-class] still has 19 classes and the
[closed token list][retry-tokens] eight `X-Gateway-Error` values. The
[status-derived token][retry-status] and [class-to-token][retry-token-class] mappings are
unchanged. [`src/proxy/headers.rs`][headers] and [`src/diagnostic_ref.rs`][diagnostic-ref] are
byte-identical to v0.9.11 (the latter still SHA-256
`4a7dde19a3cc713c13c60231574916d32342e4d257a70cf3acde1fa6f900e006`), so the gateway-owned
diagnostic header list, the strip boundaries and the G01 reference format did not move. The
[authoritative token finalizer][token-finalizer] keeps its overwrite rules. Marker-derived
attribution remains at most likely; an untrusted `ferrum.marker.unverified` finding still
confirms only that a header was observed.

| Finding | Edge source (v0.9.14) | Anvil impact |
|---|---|---|
| **Backend HTTP/2 resets are `protocol_error`** (#6019, #6022). A backend `RST_STREAM` or `GOAWAY` with any reason except `NO_ERROR`, received from the peer or raised by h2 for a peer violation, is classified `protocol_error` instead of `request_error`: before response headers on a reqwest route (including `REFUSED_STREAM`), during a buffered body read, and while a direct-H2/gRPC body streams. It is post-wire and now charged to circuit breakers and passive health; a reset the gateway raises itself is not. | [`classify_reqwest_error`][reqwest-reset] `src/retry.rs:1583`; [`is_backend_h2_reset`][h2-reset] `src/retry.rs:1650`; [`classify_body_error`][body-reset] `src/retry.rs:1764` | **Catalog outcomes unchanged in public signal; conditions/notes updated.** `upstream.protocol_error_before_headers` condition extended, `upstream.request_error_catchall`, `streaming.backend_body_failure_after_headers`, `protocol.grpc.backend_stream_error_after_headers` and `upstream.body_read_failed.eager_buffer` noted. The 502/`backend_error`/`{"error":"Backend unavailable"}` family stays one ambiguous family; operator classes are never Anvil inputs. |
| **Buffered read errors report their real class** (#6022). `collect_response_with_limit` read errors (responses above the eager cutoff or under a size limit) used to answer 502 `{"error":"Backend response read error"}` logged `response_body_too_large`. They now classify exactly like the eager collector: 502 `{"error":"Backend response body read failed"}` with the real class, or 504 `{"error":"Backend timeout"}`/`backend_timeout` for a reqwest read timeout. Those 502s become retryable under `retryable_status_codes`. The failure response has an empty header map. | [`BufferedCollectFailure::read_error`][read-error] `src/proxy/mod.rs:51096`; [collector][collector] `src/proxy/mod.rs:51178`; [`eager_buffer_body_read_error_body`][eager-body] `src/proxy/mod.rs:46772`; [header map][buffered-headers] `src/proxy/mod.rs:45531` | **Catalog outcome changed.** `upstream.body_read_failed.buffered_collector` now carries the eager body, class `connection_closed` (real class varies), no `Content-Type`, and `shared_signal_with` `upstream.body_read_failed.eager_buffer` (and back). On 0.9.14 that body is ambiguous between the two collectors; the old body matches only the earlier catalogs. The 504 arm reuses the existing read-timeout signal. `anvil-diagnostics` test `buffered_read_error_body_changed_in_0_9_14` pins both. |
| **504 route timeout in the early upload phase** (v0.9.13, #6008). A body collected before `before_proxy` (`soap_ws_security`, `hmac_auth`, `waf`) on a rule with `request_timeout_ms` is bounded by the previewed route total. Expiry answers the existing 504 `{"error":"Request timeout"}` with `X-Gateway-Error: request_timeout` and `Content-Type: application/json`, health-neutral, logged `before_dispatch` under the new rejection phase `route_request_timeout_early_upload` on HTTP/1.1, HTTP/2 and native HTTP/3; gRPC folds it into `DEADLINE_EXCEEDED`. | [phase][early-phase] `src/proxy/mod.rs:31034`; [`finalize_early_route_upload_timeout`][early-finalize] `src/proxy/mod.rs:31043`; [`early_route_total_at`][early-preview] `src/plugin_cache.rs:6183`; [native H3][early-h3] `src/http3/server.rs:18508`; [preview][early-total] `src/plugins/early_route_total.rs:139` | **Catalog outcome unchanged in public signal; condition extended.** `upstream.route_request_timeout.not_dispatched` (token still separates it from `backend_held`), `protocol.grpc.client_deadline_exceeded` notes, the operator-only rejection-phase list and the `request_timeout` marker sentence. The lab configures no route totals. |
| **gRPC request-buffer refusal aligned on `RESOURCE_EXHAUSTED`** (#6022). The H1/H2 terminal final-body drain answered an exhausted `FERRUM_REQUEST_BUFFER_MAX_TOTAL_BYTES` with 503 mapped to gRPC `UNAVAILABLE` (14); it now carries `RESOURCE_EXHAUSTED` (8). A gRPC-Web client on the plain H3 bridge also moves from `UNAVAILABLE` to `RESOURCE_EXHAUSTED`. Plain HTTP keeps 503. The mesh backend-seam refusal is unchanged. | [`request_buffer_capacity_reject_headers`][reject-headers] `src/proxy/mod.rs:52694`; [bridge drain][bridge-refusal] `src/http3/cross_protocol.rs:12573` | **Catalog outcome unchanged in public signal.** `gateway.capacity.request_buffer` already records gRPC status 8; its notes now name the corrected paths. No lab scenario drives this budget. |
| **H3 admission 503/`RESOURCE_EXHAUSTED`** (v0.9.13, #6009). Native HTTP/3 buffered uploads, including the collectors that run before `authenticate`/`authorize`/`before_proxy` and the H3 bridge drains, reserve from the shared request-buffer budget; an upload it cannot admit gets 503 / gRPC `RESOURCE_EXHAUSTED` (`gateway_buffer_capacity`, health-neutral). | [`H3_REQUEST_BUFFER_CAPACITY_REFUSAL`][h3-capacity] `src/http3/server.rs:426` | **Catalog outcome unchanged in public signal; condition extended** (`gateway.capacity.request_buffer` now covers native H3). |
| **H3 dispatch-stage 413 and bridge drains run reject hooks** (#6022). The native buffered, cross-protocol and native dispatch drains, and both bridge drains, commit their 413 and capacity refusals through the shared terminal path: reject-path `after_proxy` and committed-response hooks run and the transaction log records `on_final_request_body`. Status, body and gRPC status 8 are unchanged. | [`H3_REQUEST_BODY_TOO_LARGE_REFUSAL`][h3-413] `src/http3/server.rs:434`; [`finalize_h3_terminal_body_read_rejection`][h3-terminal] `src/http3/server.rs:593` | **Catalog outcomes unchanged in public signal; notes updated** (`size.request_body_too_large`, `proxy.request_body_prebuffer_too_large`): reject-path decorations such as CORS can now appear on these H3 413s. The H3 bridge's own 413 body `{"error":"Request body too large"}` is unchanged since v0.9.11 and remains outside the catalog; no outcome ID was invented for it. |
| **An HTTP/2 client reset is never relayed as a complete upload** (#6022, #6038). Every streaming upload dispatcher (reqwest, direct H1/H2, sidecar mesh-mTLS, HBONE, Unix socket, native H3, and the upload pump) requires the client's own `END_STREAM`; a client `RST_STREAM(NO_ERROR)` reaches the backend as `RST_STREAM(CANCEL)`, an aborted H1 body, or `H3_REQUEST_CANCELLED`. A native H3 request then ends as 499 client disconnect. | [`h2_upload_reset_error`][upload-reset] `src/proxy/body.rs:2881`; [pump][upload-pump] `src/proxy/upload_pump.rs:920`; [H3 499][h3-499] `src/http3/server.rs:5958` | **Catalog outcome unchanged in public signal; notes updated** (`gateway.client_disconnect_during_buffering`). Anvil never inferred upload completion from a gateway response. |
| **Authorization lifetime and gRPC deadline bookkeeping** (v0.9.13, v0.9.14). A buffered native gRPC/gRPC-Web response whose credential expires during the response hooks writes one transaction summary with `grpc-status: 16`; the backend outcome is recorded before hooks; the expiry terminal keeps only gateway headers whose provenance the completed hooks recorded. A refused streamed-gRPC handoff keeps the upload. `GrpcProxyError::ClientDeadlineExceeded` carries a typed `GrpcDeadlinePhase`; messages and statuses are unchanged. | [outcome before hooks][grpc-outcome] `src/proxy/mod.rs:38180`; [in-place terminal][grpc-terminal] `src/proxy/mod.rs:39907`; [handoff gate][grpc-handoff] `src/proxy/grpc_proxy.rs:5528`; [`GrpcDeadlinePhase`][grpc-phase] `src/proxy/grpc_proxy.rs:2754` | **Catalog outcomes unchanged in public signal; notes updated** (`auth.authorization_lifetime_expired_before_commit`, `protocol.grpc.auth_expired_precommit`, `protocol.grpc.client_deadline_exceeded`). A native gRPC expiry response may omit decorations such as correlation IDs; no Anvil rule depends on them. |

`src/retry.rs` also adds `classify_body_error`, `classify_reqwest_error` and
`is_backend_h2_reset` to the contracts provenance; `contracts-edge-0.9.14` adds the
reclassification notes to the `protocol_error`, `read_write_timeout` and
`response_body_too_large` meanings without changing a class, token, status or
`request_reached_wire` value (see [Contracts](#contracts-and-g01)).

## Transport, pool and plugin changes

| Surface | Exact delta / reuse decision | Edge source (v0.9.14) | Anvil impact |
|---|---|---|---|
| hickory-resolver 0.26.2 (v0.9.13) | CNAME following, record-class rejection and the truncated-response retry bound changed; resolver edge cases can affect whether a backend name resolves. | `Cargo.lock`; `src/proxy/mod.rs:46979`; `src/retry.rs:481` | The Anvil DNS-failure classification remains `dns_lookup_error`. When resolution fails, the path-specific 502 body/token remain `Backend DNS resolution failed` / `connection_failure` on shared preflight and `Backend unavailable` / `backend_error` on pooled paths. |
| Capability-probe setup (#6032) | A gRPC, direct-H2, H3 or gateway-to-mesh HBONE request that joined a capability probe's backend setup (connect budget capped at 5 s) shared the probe's failure. A failed probe-owned create is no longer authoritative for a joined request; it re-dials under its own `backend_connect_timeout_ms`. | [`probe_owned`][probe] `src/pool/mod.rs:418` | **Unchanged signal; notes updated** (`upstream.connect.timeout`). Fewer spurious startup failures; no timing claim. |
| Native H3 connect timing (v0.9.13) | An established cold H3 connection is no longer misreported as `connection_timeout` when its task wakes after the connect instant. | [`src/http3/client.rs:1494`][h3-connect] | **Unchanged signal; note on `upstream.connect.timeout`.** |
| gRPC affinity (v0.9.13) | A missing or closed shard is created on a detached single-flight task while a ready sibling serves the call; a connection pins at most `min(32, SETTINGS_MAX_CONCURRENT_STREAMS)` calls; slot tables are per gateway. Up to `FERRUM_POOL_HTTP2_CONNECTIONS_PER_HOST` backend connections per host are possible. The vendored h2 stream-lifetime patch is retired. | [`src/proxy/frontend_affinity.rs:44`][affinity], [`:94`][affinity-limit] | **No outcome change.** Recorded in drift; live connection width needs lab evidence. |
| HTTP/2 small-window coalescing (#6033, #6038) | Hyper patch 005 holds send capacity below `min(chunk remaining, 256)` bytes for at most 2 ms before sending exactly the assigned capacity, avoiding one DATA frame per tiny window increment (and the `ENHANCE_YOUR_CALM` GOAWAY it provoked from unpatched h2 peers). | [`MIN_COALESCED_DATA_FRAME`][coalesce] `vendor/hyper-1.10.0-ferrum-patched/src/proto/h2/mod.rs:111`, [`MAX_COALESCE_WAIT`][coalesce-wait] `:118` | **No outcome change.** Framing only; no completion or timing claim. |
| Built-in plugin trust follows the type (#6022) | Trust, composition checks and finalizer cleanup use the registered concrete type, not `name()`. A custom plugin reporting a built-in name gets custom-plugin treatment; its response-body production stays `Undeclared` unless declared. | [`is_builtin_plugin`][builtin] `src/plugins/mod.rs:13757`; [cache lookup][builtin-cache] `src/plugin_cache.rs:552` | **Notes updated** (`plugin.custom.undeclared_response_body_producer`). The lab uses only built-in plugins. |
| Auth plugins name the headers they strip (#6022) | `basic_auth`, `ldap_auth`, `key_auth`, `jwks_auth`, `oauth2_introspection` and `oidc_relying_party` declare their stripped credential and owned claim headers, so the early route preview keeps rules on other headers decided. | [`src/plugins/early_route_total.rs:51`][early-headers] | **No outcome change** (feeds the early route bound above). |
| OIDC session-secret screening (#6037) | `session.encryption_secret(_previous)` also refuses two fixture keys Edge's tests published; an unresolved `${NAME}` placeholder fails with its own error. Admission and config load only. | [`src/plugins/utils/session_cookie.rs:152`][session-secret] | **Not a client diagnostic.** The lab generates a random session key. |
| `ai_semantic_cache` and deduplication Redis (#6018) | Per-key single-flight quarantine with at most 4 dedicated connections per instance; quarantine connect refusals keep the client available; `UNWATCH` is no longer sent; deduplication sends `MULTI` alone and requires `QUEUED`. | [`src/plugins/ai_semantic_cache.rs`][cache], [`src/plugins/utils/redis_rate_limiter.rs`][redis] | **No outcome change.** Existing HIT/MISS/BYPASS and fail-open signals retained. |
| Configuration and plugin keys | `src/config/types.rs`, `env_config.rs` and `conf_file.rs` are byte-identical to v0.9.11; no plugin config key set changed. | [comparison][compare] | Lab profiles and `lab/gateway/lint-profiles.rb` allowlists unchanged (comments only). |

## Admin, deployment and control-plane scope

These are admin-only or control-plane surfaces. None is a proxy diagnostic outcome, and Anvil
adds no admin apply, fetch, lookup or trust escalation for them.

| Surface | Delta | Edge source (v0.9.14) |
|---|---|---|
| Deployment mutations (v0.9.12) | `GET /deployment-snapshot` issues `deployment-v1` evidence for conditional proxy DELETE and API-spec PUT, with dependency-fenced partial writes and typed 409 external-dependency refusals. | [`src/admin/deployment_mutations.rs`][deploy] |
| Deployment-mode refusals (v0.9.12, documented in v0.9.13) | An ordinary `PUT /api-specs/{id}` with any `If-Match`, or any mutating admin request with a `conditional` key or a `deployment-v1-` `If-Match` outside the two deployment routes, returns 400. | [`src/admin/mod.rs:4015`][deploy-refusal] |
| Bounded snapshot authority (v0.9.13) | Backup namespace tags and `deployment-v1` tokens MAC a bounded SHA-256 of the canonical snapshot; tags from v0.9.12 or earlier fail with 412; over 64 MiB is 507. | [`src/admin/conditional_snapshots.rs`][snapshots] |
| Backend egress policy v2 (v0.9.13, #5994/#5999) | `GET /backend-egress-policy` `schema_version` 2: `public_only_guaranteed` requires `enforcement_scope=local-data-plane`. | [`src/admin/backend_egress_policy.rs:94`][egress] |
| Data-plane egress attestation (v0.9.14, #6020) | Data planes report bounded policy metadata on ConfigSync `Subscribe` (protocol revision 3); a CP adds the optional `data_plane_attestation` and `GET /cluster` aggregates. `schema_version` stays 2. | [`src/grpc/backend_egress_attestation.rs:99`][attestation] |
| Mutation `durable` values (v0.9.14, #6021) | A failure before the mutation transaction reports `durable: "not_started"`, a rolled-back transaction `"not_committed"`; only commit uncertainty stays `"unknown"`. | [`src/admin/deployment_mutations.rs:119`][durable] |

## Contracts and G01

Canonical `contracts-edge-0.9.14` (`ddbdd845733b7046c4393ac951011dafb774db33`) targets Edge
`9bd4d5f`. Anvil vendors the same 33 paths as before, byte-exact from the tag, and four changed:

- `vocabularies/gateway-errors.json`: `edge_release` and provenance move to v0.9.14; the
  `protocol_error`, `read_write_timeout` and `response_body_too_large` meanings describe the
  reclassification above. The same eight tokens and 19 classes, each with the same token.
- `vocabularies/gateway-headers.json`: v0.9.14 provenance and admin `ETag`/`If-Match`
  deployment-token wording. The 24 header names and the three gateway diagnostic headers are
  unchanged; `X-Ferrum-Diagnostic-Ref` is still available from v0.9.9.
- `schemas/diagnostic-ref/v1.schema.json`: provenance re-read at v0.9.12 source; the wire
  contract and every closed vocabulary Anvil's reader checks are unchanged.
- `fixtures/invalid-expectations.json`: new scopes for the egress-policy v2 and deployment
  schemas. The original 13 diagnostic failure paths, keywords and top keyword are unchanged.

The diagnostic-report and diagnostic-finding schemas and every diagnostic fixture are
byte-identical to `contracts-edge-0.9.11`. `contracts_adoption.rs` checks the 0.9.9, 0.9.10,
0.9.11 and 0.9.14 catalogs against the pinned vocabularies and the lab default (now v0.9.14)
against the pin. The real Alloy exporter golden remains historical Edge 0.9.10 evidence.

## Distribution pins and lab scope

Edge [release v0.9.14][release] is published, not inferred from a Cargo version string. Root's
verified distribution record ties release `405571232` to `9bd4d5f` and the successful
[release workflow](https://github.com/ferrum-edge/ferrum-edge/actions/runs/37585311307). Both new
locks name all five gateway assets with the GitHub API digests, which match the published
`.sha256` sidecars (Windows: `ferrum-edge-windows-x86_64.exe`, SHA-256
`b22e5cc4b18973aa834166acdfb825690cc829260753db6867449c420d942e6b`). The lab runs release
binaries, not images; the Docker Hub `ferrumedge/ferrum-edge:0.9.14` index
`sha256:15442f1b1d1758023fe871fe57be50f19caf34bbe6c499a6812f4ffd0da5e3f8` (amd64
`sha256:12a8cd56090c0d4511bb3015b240e606b1b87989c644157566b8f6b6f635b3c2`, arm64
`sha256:19d2886ed8c192cb0daba48ef0a27a0cd0526449dac74bf9438502322aabd9f2`) is recorded here
for provenance only.

The PR lab runs the v0.9.14 default. Nightly retains all seven supported releases and adds
v0.9.11 as an explicit historical selector. No lab profile, key allowlist, skip or status
acceptance changed. The source audit found no scenario whose asserted signal moves:

- **UP-018.** The direct-H1 checkout classifier and its typed 502/`connection_failure`
  ceiling are unchanged ([`direct_h1_checkout_error_response`][h1-checkout],
  `src/proxy/mod.rs:50037`). `anvil-lab` now expects that lane from v0.9.11 through the pinned
  release (`release_from_through_pin`), so the v0.9.14 default and the retained v0.9.11 both
  assert the direct-H1 signal while 0.9.5/7/8/9/10 keep reqwest. `#323`'s equality with the
  pin would have sent nightly v0.9.11 to the reqwest expectation. The public-signal contract
  test runs the direct-H1 controls against both catalogs.
- **Operator-class checks.** No lab scenario drives a backend HTTP/2 reset, a buffered-collector
  read failure, a route total or the request-buffer budget. UP-008 already accepts
  `protocol_error`; GW-009's declared-size ceiling stays `response_body_too_large`
  (`BufferedCollectFailure::too_large`, `src/proxy/mod.rs:51078`).
- **Skip reasons.** `src/tls`, `src/modes`, `src/identity`, `src/proxy/hbone_proxy.rs` and
  `src/proxy/mesh_udp_frame.rs` are unchanged since v0.9.11, so the release-templated
  infeasibility reasons remain true for v0.9.14. `jwks_auth` still has no DPoP-Nonce challenge.

## Qualification status

The hosted all-profile Lab run 37758644110 (`workflow_dispatch`, `profile=all`) ran on PR
head `7b19d50e`. macOS reported 556 passed / 2 failed / 19 skipped; Ubuntu reported 552
passed / 2 failed / 21 skipped. UP-018 and UP-018-untrusted passed on both operating systems.
The only failures were MESH-011 and MESH-011-untrusted on both operating systems. The main
nightly run 37612351285 failed those same scenarios across v0.9.5–v0.9.11. That was a
pre-existing Anvil issue ([#341](https://github.com/ferrum-edge/ferrum-anvil/issues/341)),
unrelated to this Edge adoption: Anvil's destination policy refused the scenario's TEST-NET
target locally, before the CONNECT reached the gateway. It is fixed by
[#342](https://github.com/ferrum-edge/ferrum-anvil/pull/342), which moves the target to an
address the policy admits and asserts that no local refusal occurred.

The scheduled all-profile Lab run 37770270997 on main at `615739ae` (the #342 merge) passed
MESH-011 and MESH-011-untrusted on both operating systems, for v0.9.14 and for every earlier
supported release. For v0.9.14, macOS reported 558 passed / 0 failed / 19 skipped and Ubuntu
553 passed / 1 failed / 21 skipped. The Ubuntu failure was GW-020-BUDGET-untrusted: the lab read the
gateway operator log before the rejected request's line was written (a lab-side read race, not a
gateway behaviour change); it passed on macOS in that run and on both operating systems in run
37758644110. No physical-device native acceptance, platform signing,
OAuth, provider-account or broader performance acceptance is claimed.

[compare]: https://github.com/ferrum-edge/ferrum-edge/compare/c764084b3b51c3f7ffde268c039688d35e49c553...9bd4d5f9caa4ebe8f0ea13e76d8a6e2172eaca7d
[changelog]: https://github.com/ferrum-edge/ferrum-edge/blob/9bd4d5f9caa4ebe8f0ea13e76d8a6e2172eaca7d/CHANGELOG.md
[upgrade]: https://github.com/ferrum-edge/ferrum-edge/blob/9bd4d5f9caa4ebe8f0ea13e76d8a6e2172eaca7d/docs/upgrade_guide.md#upgrading-to-0914
[release]: https://github.com/ferrum-edge/ferrum-edge/releases/tag/v0.9.14
[retry-class]: https://github.com/ferrum-edge/ferrum-edge/blob/9bd4d5f9caa4ebe8f0ea13e76d8a6e2172eaca7d/src/retry.rs#L25
[retry-tokens]: https://github.com/ferrum-edge/ferrum-edge/blob/9bd4d5f9caa4ebe8f0ea13e76d8a6e2172eaca7d/src/retry.rs#L212
[retry-status]: https://github.com/ferrum-edge/ferrum-edge/blob/9bd4d5f9caa4ebe8f0ea13e76d8a6e2172eaca7d/src/retry.rs#L287
[retry-token-class]: https://github.com/ferrum-edge/ferrum-edge/blob/9bd4d5f9caa4ebe8f0ea13e76d8a6e2172eaca7d/src/retry.rs#L310
[headers]: https://github.com/ferrum-edge/ferrum-edge/blob/9bd4d5f9caa4ebe8f0ea13e76d8a6e2172eaca7d/src/proxy/headers.rs#L860
[diagnostic-ref]: https://github.com/ferrum-edge/ferrum-edge/blob/9bd4d5f9caa4ebe8f0ea13e76d8a6e2172eaca7d/src/diagnostic_ref.rs
[token-finalizer]: https://github.com/ferrum-edge/ferrum-edge/blob/9bd4d5f9caa4ebe8f0ea13e76d8a6e2172eaca7d/src/proxy/mod.rs#L26850
[reqwest-reset]: https://github.com/ferrum-edge/ferrum-edge/blob/9bd4d5f9caa4ebe8f0ea13e76d8a6e2172eaca7d/src/retry.rs#L1583
[h2-reset]: https://github.com/ferrum-edge/ferrum-edge/blob/9bd4d5f9caa4ebe8f0ea13e76d8a6e2172eaca7d/src/retry.rs#L1650
[body-reset]: https://github.com/ferrum-edge/ferrum-edge/blob/9bd4d5f9caa4ebe8f0ea13e76d8a6e2172eaca7d/src/retry.rs#L1764
[read-error]: https://github.com/ferrum-edge/ferrum-edge/blob/9bd4d5f9caa4ebe8f0ea13e76d8a6e2172eaca7d/src/proxy/mod.rs#L51096
[collector]: https://github.com/ferrum-edge/ferrum-edge/blob/9bd4d5f9caa4ebe8f0ea13e76d8a6e2172eaca7d/src/proxy/mod.rs#L51178
[eager-body]: https://github.com/ferrum-edge/ferrum-edge/blob/9bd4d5f9caa4ebe8f0ea13e76d8a6e2172eaca7d/src/proxy/mod.rs#L46772
[buffered-headers]: https://github.com/ferrum-edge/ferrum-edge/blob/9bd4d5f9caa4ebe8f0ea13e76d8a6e2172eaca7d/src/proxy/mod.rs#L45531
[early-phase]: https://github.com/ferrum-edge/ferrum-edge/blob/9bd4d5f9caa4ebe8f0ea13e76d8a6e2172eaca7d/src/proxy/mod.rs#L31034
[early-finalize]: https://github.com/ferrum-edge/ferrum-edge/blob/9bd4d5f9caa4ebe8f0ea13e76d8a6e2172eaca7d/src/proxy/mod.rs#L31043
[early-preview]: https://github.com/ferrum-edge/ferrum-edge/blob/9bd4d5f9caa4ebe8f0ea13e76d8a6e2172eaca7d/src/plugin_cache.rs#L6183
[early-h3]: https://github.com/ferrum-edge/ferrum-edge/blob/9bd4d5f9caa4ebe8f0ea13e76d8a6e2172eaca7d/src/http3/server.rs#L18508
[early-total]: https://github.com/ferrum-edge/ferrum-edge/blob/9bd4d5f9caa4ebe8f0ea13e76d8a6e2172eaca7d/src/plugins/early_route_total.rs#L139
[early-headers]: https://github.com/ferrum-edge/ferrum-edge/blob/9bd4d5f9caa4ebe8f0ea13e76d8a6e2172eaca7d/src/plugins/early_route_total.rs#L51
[reject-headers]: https://github.com/ferrum-edge/ferrum-edge/blob/9bd4d5f9caa4ebe8f0ea13e76d8a6e2172eaca7d/src/proxy/mod.rs#L52694
[bridge-refusal]: https://github.com/ferrum-edge/ferrum-edge/blob/9bd4d5f9caa4ebe8f0ea13e76d8a6e2172eaca7d/src/http3/cross_protocol.rs#L12573
[h3-capacity]: https://github.com/ferrum-edge/ferrum-edge/blob/9bd4d5f9caa4ebe8f0ea13e76d8a6e2172eaca7d/src/http3/server.rs#L426
[h3-413]: https://github.com/ferrum-edge/ferrum-edge/blob/9bd4d5f9caa4ebe8f0ea13e76d8a6e2172eaca7d/src/http3/server.rs#L434
[h3-terminal]: https://github.com/ferrum-edge/ferrum-edge/blob/9bd4d5f9caa4ebe8f0ea13e76d8a6e2172eaca7d/src/http3/server.rs#L593
[upload-reset]: https://github.com/ferrum-edge/ferrum-edge/blob/9bd4d5f9caa4ebe8f0ea13e76d8a6e2172eaca7d/src/proxy/body.rs#L2881
[upload-pump]: https://github.com/ferrum-edge/ferrum-edge/blob/9bd4d5f9caa4ebe8f0ea13e76d8a6e2172eaca7d/src/proxy/upload_pump.rs#L920
[h3-499]: https://github.com/ferrum-edge/ferrum-edge/blob/9bd4d5f9caa4ebe8f0ea13e76d8a6e2172eaca7d/src/http3/server.rs#L5958
[grpc-outcome]: https://github.com/ferrum-edge/ferrum-edge/blob/9bd4d5f9caa4ebe8f0ea13e76d8a6e2172eaca7d/src/proxy/mod.rs#L38180
[grpc-terminal]: https://github.com/ferrum-edge/ferrum-edge/blob/9bd4d5f9caa4ebe8f0ea13e76d8a6e2172eaca7d/src/proxy/mod.rs#L39907
[grpc-handoff]: https://github.com/ferrum-edge/ferrum-edge/blob/9bd4d5f9caa4ebe8f0ea13e76d8a6e2172eaca7d/src/proxy/grpc_proxy.rs#L5528
[grpc-phase]: https://github.com/ferrum-edge/ferrum-edge/blob/9bd4d5f9caa4ebe8f0ea13e76d8a6e2172eaca7d/src/proxy/grpc_proxy.rs#L2754
[probe]: https://github.com/ferrum-edge/ferrum-edge/blob/9bd4d5f9caa4ebe8f0ea13e76d8a6e2172eaca7d/src/pool/mod.rs#L418
[h3-connect]: https://github.com/ferrum-edge/ferrum-edge/blob/9bd4d5f9caa4ebe8f0ea13e76d8a6e2172eaca7d/src/http3/client.rs#L1494
[affinity]: https://github.com/ferrum-edge/ferrum-edge/blob/9bd4d5f9caa4ebe8f0ea13e76d8a6e2172eaca7d/src/proxy/frontend_affinity.rs#L44
[affinity-limit]: https://github.com/ferrum-edge/ferrum-edge/blob/9bd4d5f9caa4ebe8f0ea13e76d8a6e2172eaca7d/src/proxy/frontend_affinity.rs#L94
[coalesce]: https://github.com/ferrum-edge/ferrum-edge/blob/9bd4d5f9caa4ebe8f0ea13e76d8a6e2172eaca7d/vendor/hyper-1.10.0-ferrum-patched/src/proto/h2/mod.rs#L111
[coalesce-wait]: https://github.com/ferrum-edge/ferrum-edge/blob/9bd4d5f9caa4ebe8f0ea13e76d8a6e2172eaca7d/vendor/hyper-1.10.0-ferrum-patched/src/proto/h2/mod.rs#L118
[builtin]: https://github.com/ferrum-edge/ferrum-edge/blob/9bd4d5f9caa4ebe8f0ea13e76d8a6e2172eaca7d/src/plugins/mod.rs#L13757
[builtin-cache]: https://github.com/ferrum-edge/ferrum-edge/blob/9bd4d5f9caa4ebe8f0ea13e76d8a6e2172eaca7d/src/plugin_cache.rs#L552
[session-secret]: https://github.com/ferrum-edge/ferrum-edge/blob/9bd4d5f9caa4ebe8f0ea13e76d8a6e2172eaca7d/src/plugins/utils/session_cookie.rs#L152
[cache]: https://github.com/ferrum-edge/ferrum-edge/blob/9bd4d5f9caa4ebe8f0ea13e76d8a6e2172eaca7d/src/plugins/ai_semantic_cache.rs
[redis]: https://github.com/ferrum-edge/ferrum-edge/blob/9bd4d5f9caa4ebe8f0ea13e76d8a6e2172eaca7d/src/plugins/utils/redis_rate_limiter.rs
[deploy]: https://github.com/ferrum-edge/ferrum-edge/blob/9bd4d5f9caa4ebe8f0ea13e76d8a6e2172eaca7d/src/admin/deployment_mutations.rs
[deploy-refusal]: https://github.com/ferrum-edge/ferrum-edge/blob/9bd4d5f9caa4ebe8f0ea13e76d8a6e2172eaca7d/src/admin/mod.rs#L4015
[snapshots]: https://github.com/ferrum-edge/ferrum-edge/blob/9bd4d5f9caa4ebe8f0ea13e76d8a6e2172eaca7d/src/admin/conditional_snapshots.rs
[egress]: https://github.com/ferrum-edge/ferrum-edge/blob/9bd4d5f9caa4ebe8f0ea13e76d8a6e2172eaca7d/src/admin/backend_egress_policy.rs#L94
[attestation]: https://github.com/ferrum-edge/ferrum-edge/blob/9bd4d5f9caa4ebe8f0ea13e76d8a6e2172eaca7d/src/grpc/backend_egress_attestation.rs#L99
[durable]: https://github.com/ferrum-edge/ferrum-edge/blob/9bd4d5f9caa4ebe8f0ea13e76d8a6e2172eaca7d/src/admin/deployment_mutations.rs#L119
[h1-checkout]: https://github.com/ferrum-edge/ferrum-edge/blob/9bd4d5f9caa4ebe8f0ea13e76d8a6e2172eaca7d/src/proxy/mod.rs#L50037
