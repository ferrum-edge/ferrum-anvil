# Ferrum Edge 0.9.14 → 0.9.15: source delta audit

| Item | Immutable identity / status |
|---|---|
| Baseline | `v0.9.14`, `9bd4d5f9caa4ebe8f0ea13e76d8a6e2172eaca7d` (source-audited and hosted-qualified in [gateway-0.9.14-delta.md](gateway-0.9.14-delta.md)) |
| Audited target | `v0.9.15`, `25b37395ff61bfea0f3ffd189d9011c4984fa755` (merge of Edge #6103), [release 407222520][release], published 2026-10-08T20:11:03Z |
| Contracts | Published `contracts-edge-0.9.15`, `6fb64c5dc2e014204c17609fc717d976f3b4589e` |
| Catalog | [`ferrum-edge-0.9.15/outcomes.json`](../../catalog/ferrum/ferrum-edge-0.9.15/outcomes.json), 553 carried outcome IDs plus 4 new ones (557) |
| Lab selection | `lab/gateway/RELEASE.lock` and `lab/gateway/releases/v0.9.15.lock`; v0.9.14 is retained as an earlier supported release |
| Hosted qualification | Pending: root dispatches the manual all-profile Lab run (`workflow_dispatch`, `profile=all`) on the PR head |
| Audit date | 2026-10-08 |

v0.9.15 is a security release (26 published advisories). The [immutable comparison][compare]
changes 100 files under `src/` (6,266 insertions, 1,490 deletions; four new files:
`src/http3/address_validation.rs`, `src/plugins/utils/plugin_secret_env.rs`,
`src/config/policy_graph_scope.rs` and `src/grpc/response_admission.rs`), plus vendored h2 and
Hyper patches, tests, benchmarks and documentation. This is a separate source delta audit on top
of the [0.9.14 record](gateway-0.9.14-delta.md), not a new comprehensive inventory. The historical
0.9.5, 0.9.7, 0.9.8, 0.9.9, 0.9.10, 0.9.11 and 0.9.14 catalogs and release locks remain available
and unchanged.

All `file:line` citations below are at v0.9.15 (`25b3739`) unless a release is named.

## Method and limits

Both source trees were read at the exact commits above with `git show` and `git diff`, without
checkout, build, formatting, test, script, binary or container execution. Every structured
catalog citation and every unqualified full-path prose citation was remapped through the
immutable unified diff, and the cited line text was required to be identical at both ends.
1,453 structured and 348 prose citations remapped that way; three structured citations fell
inside changed hunks and were repointed by hand to the current code (the OIDC challenge's
`clear` branch after the new pending-cookie expiry, the state-cache-full return, and
`claim_saml_assertion`, which now takes the principal). Explicitly historical `@sha` prose
citations remain historical.

Citation text equality alone does not establish behavioral equality. Every changed request
path below was read against its surrounding source, the [0.9.15 changelog][changelog] and the
[upgrade guide][upgrade]. A global comparison of every catalog public signal (status, token and
JSON body, 398 signals) against the 0.9.14 and 0.9.15 catalogs finds exactly four changed match
sets, all of them the new outcomes below; every carried signal matches the same outcomes as on
0.9.14. No token, error class or diagnostic cause is new.

Local validation is static inspection, `git diff --check` and read-only consistency checks of
the new JSON only; no project tooling ran locally. Unit, parser and catalog checks cannot
establish live gateway compatibility.

## Marker, error class and header decisions

`src/retry.rs` and `docs/error_classification.md` are byte-identical to v0.9.14, so the 19
`ErrorClass` values, the eight `X-Gateway-Error` tokens, the status-derived token and the
class-to-token mappings did not move. The gateway-owned diagnostic header list and the backend
strip boundary in `src/proxy/headers.rs` are unchanged (the file's changes are the assertion
header and `Connection` rules below). `src/diagnostic_ref.rs` only adds the
`route_protocol_admission` rejection label. Marker-derived attribution remains at most likely;
an untrusted `ferrum.marker.unverified` finding still confirms only that a header was observed.

| Finding | Edge source (v0.9.15) | Anvil impact |
|---|---|---|
| **Route protocol admission: new 403** (#6090, issue #6087). On an HTTP-family route a native gRPC request or a WebSocket upgrade whose flavor plugin view omits an instance that gates request admission (`Plugin::gates_request_admission`: every authentication plugin, including custom ones on the HTTP-only `supported_protocols()` default; `soap_ws_security`; `openapi_validator` in `block` mode; `mcp_gateway`; `request_deduplication` with `enforce_required`; the AI admission plugins; `rate_limiting` with `mcp_tool_calls`; `graphql` with a protection rule on gRPC; `a2a_gateway` with a deny policy on WebSocket) is refused before any plugin runs: 403 `{"error":"Request protocol not permitted on this route"}`, native gRPC trailers-only `PERMISSION_DENIED`. gRPC-Web keeps every HTTP plugin. | [body][rpa-body] `src/proxy/mod.rs:285`; [H1/H2 refusal][rpa-h1] `src/proxy/mod.rs:34019`; [native H3][rpa-h3] `src/http3/server.rs:3961`; [view bit][rpa-view] `src/plugin_cache.rs:5346`; [hook][rpa-hook] `src/plugins/mod.rs:12169` | **New outcome** `gateway.routing.protocol_not_permitted` (403, gRPC 7, no token, owner gateway operator). Earlier catalogs do not match its body. `ferrum.rs` test `outcomes_new_in_0_9_15_match_only_their_own_catalog`. |
| **`route_protocol_admission` rejection phase**. The refusal logs `rejection_phase: "route_protocol_admission"`; `token_for_rejection_phase` maps it to no token, so the 403 carries no `X-Gateway-Error`. A diagnostic reference records it as `detail.rejection.phase`; `detail.rejection_phase` stays limited to token-mapped phases. | [label][rpa-phase] `src/diagnostic_ref.rs:200`; [H1/H2 log][rpa-log] `src/proxy/mod.rs:34045`; [H3 log][rpa-log-h3] `src/http3/server.rs:3986` | Operator-only phase list extended. Anvil's reference reader already accepts any bounded label in `rejection.phase` and keeps `detail.rejection_phase` closed; `contracts-edge-0.9.15` adds a valid and an invalid fixture for exactly that, now vendored and exercised. |
| **WebSocket method policy: new 405** (#6080, #6098). An HTTP/1.1 WebSocket upgrade with a method other than GET gets 405 `{"error":"WebSocket upgrades require GET"}` with `Allow: GET`, before routing. HTTP/2 Extended CONNECT and HTTP/3 `:protocol=websocket` requests are evaluated as GET by route `allowed_methods`, `mesh_authz` `:method` and `opa` `input.method`; a WebSocket route that lists `CONNECT` but not `GET` now answers the route 405. Plain CONNECT and CONNECT-UDP keep CONNECT; the 0-RTT gate reads the wire method. | [H1 405][ws-h1] `src/proxy/mod.rs:32841`; [builder][ws-405] `src/proxy/mod.rs:52816`; [H2 as GET][ws-h2] `src/proxy/mod.rs:32851`; [H3 as GET][ws-h3] `src/http3/server.rs:3478` | **New outcome** `gateway.routing.websocket_upgrade_requires_get`. `gateway.routing.method_not_allowed` condition and notes, `gateway.routing.trace_or_connect_blocked` and `plugin.request_termination.connect_2xx_refused` (an Extended CONNECT WebSocket is still a tunnel there, [`src/plugins/request_termination.rs:536`][rt-tunnel]) notes updated; the `Allow` header entry names the new writer. No lab route lists `CONNECT` for WebSocket. |
| **Brotli decode: new 400 and 503** (#6079). `request_deduplication` decodes a `br` body for its fingerprint with the charged strict-window decoder: 400 `{"error":"Request body encoding is invalid or exceeds fingerprint limits"}` for a malformed or over-limit body, 503 `{"error":"Request decode capacity is temporarily unavailable"}` when the shared request-decode budget refuses. Earlier releases fingerprinted the raw bytes on a decode failure; a malformed gzip body still does. `ai_semantic_firewall` uses the same decoder for gzip and Brotli inspection. | [charged decode][dedup-decode] `src/plugins/request_deduplication.rs:3270`; [503][dedup-503] `:3290`; [400][dedup-400] `:3294`; [firewall][firewall-decode] `src/plugins/ai_semantic_firewall.rs:7942` | **New outcomes** `plugin.request_deduplication.body_encoding_rejected` (owner caller) and `plugin.request_deduplication.decode_capacity` (owner gateway operator). A refused firewall decode is the existing `plugin.ai_semantic_firewall.uninspectable`; notes updated. |
| **HTTP/3 CONNECT-UDP per-client cap** (#6098, #6100). Each RFC 9298 tunnel also holds a per-client slot (`FERRUM_HTTP3_CONNECT_UDP_MAX_SESSIONS_PER_IP`, default 32, `0` disables; IPv6 grouped by `FERRUM_PER_IP_IPV6_PREFIX`) for its lifetime, taken before the process-wide permit. Over the cap: the existing 503 `{"error":"CONNECT-UDP session limit exceeded"}`, before any socket, logged `connect_udp_per_ip_session_limit`. | [slot][cudp-slot] `src/http3/connect_udp.rs:1723`; [refusal][cudp-reject] `src/http3/connect_udp.rs:2106` | **Unchanged signal; condition and notes extended** (`protocol.http3.connect_udp_rejections`). The body cannot tell the per-client limit from the process-wide one. The h3x profile holds far fewer than 32 concurrent tunnels. |
| **MTOM framing** (#6077). `soap_ws_security` frames MTOM packages strictly: the `--boundary` token only as an exact CRLF delimiter line at the start of the body or after a CRLF (no padding, LF terminator, trailing characters, bare-LF/CR opener or mid-line token), the root is always the first part and `start` must name it, and a `Content-ID`/`start` with `%`, `+` or embedded whitespace is refused: the existing 400 `{"error":"SOAP request body is not valid for its character encoding"}`. RFC 2231 `boundary*`/`type*`/`start*` on the package `Content-Type` gets the existing 400 MTOM packaging refusal; a SOAP `charset*` the existing 415 conflicting-charset refusal. | [delimiters][mtom-delim] `src/plugins/soap_ws_security.rs:7228`; [root first][mtom-root] `:7512`; [package parameters][mtom-2231] `:4596`; [charset*][mtom-charset] `:7639` | **Unchanged signals; conditions and notes extended** (`plugin.soap_ws_security.malformed_encoding`, `.malformed_multipart_content_type`, `.conflicting_charset`). The lab sends no MTOM package (AUTH-029/030/031 are plain SOAP). |
| **`mcp_gateway` session caps** (#6079). Aggregate sessions are capped per authenticated principal (`sessions.max_sessions_per_principal`, default 128); anonymous callers are grouped by client /64. At its own cap a caller's oldest session is replaced. A full store (`sessions.max_sessions`) no longer evicts another caller's live session: a caller with a session of its own replaces its oldest, and one without is refused with the existing -32013 `MCP session capacity unavailable`. | [quota][mcp-quota] `src/plugins/mcp_gateway.rs:2614`; [refusal][mcp-refuse] `:2625`; [anonymous key][mcp-anon] `:2571` | **Unchanged signals; conditions and notes extended** (`plugin.mcp_gateway.session_capacity`, `.session_not_found`, which a replaced session answers afterwards). The mcp profile creates well under 128 sessions per run. |
| **Per-IP IPv6 grouping** (#6079). Gateway-wide per-source caps (`FERRUM_MAX_CONCURRENT_REQUESTS_PER_IP`, WebSocket, TCP, UDP, admin, CP gRPC, mesh app probe and CONNECT-UDP) group native IPv6 sources by `FERRUM_PER_IP_IPV6_PREFIX` (default /64; 128 restores per-address). `rate_limiting` IP keys use the policy's new `ipv6_prefix` (default 64). `graphql`, `grpc_method_router`, `udp_rate_limiting`, `ai_rate_limiter`, `tcp_connection_throttle`, MCP anonymous quotas and OIDC pending-login quotas use a fixed /64. IPv4 and IPv4-mapped IPv6 stay per-address. | [slot][perip-slot] `src/proxy/mod.rs:15212`; [request key][perip-req] `src/proxy/mod.rs:33308`; [rate_limiting][rl-prefix] `src/plugins/rate_limiting.rs:333` | **Unchanged signals; notes updated** on the per-IP 429/503 refusals, `l4.udp.datagram_dropped` and the IP-keyed plugin limits. Anvil cannot tell from a response which client shared a budget. No lab profile sets a per-IP cap; `proxyproto-v6` uses `::1` only for the PROXY trust gate. |
| **Mesh relay Layer-4 authorization** (#6081). A byte-stream or datagram HBONE CONNECT, including a bare authenticated HTTP/2 CONNECT on the Sidecar inbound listener, is authorized as a Layer-4 session: `to.operation` methods, paths, hosts and headers, `requestPrincipals`, and `when: request.headers[...]`/`request.auth.*` are unobservable, so a DENY rule ignores them and matches on its remaining constraints, an ALLOW or AUDIT rule that needs one never matches, and a matched CUSTOM rule refuses the relay without calling the provider. Refusals keep 403 `{"error":"Mesh authorization denied"}`. | [relay flag][mesh-relay] `src/plugins/mesh/authz.rs:3028`; [tag][mesh-tag] `src/proxy/hbone_proxy.rs:358`; [CUSTOM][mesh-custom] `src/plugins/mesh/authz.rs:3413`; [DENY on missing L7][mesh-deny] `src/modes/mesh/policy.rs:939` | **Unchanged signal; notes updated** (`plugin.mesh_authz.denied`, the three `plugin.mesh_ext_authz.*` provider outcomes). **Lab impact, fixed here:** the sidecar's MeshPolicy denied the lab client SVID on `paths: ["/denied/*"]`; on v0.9.15 that DENY ignores `paths` for the HBONE scenarios (MESH-008, the sidecar UDP and DTLS tunnels) and would refuse every tunnel. The rule now names `spiffe://cluster.local/ns/ferrum/sa/anvil-lab-other`, and MESH-007 presents that SVID, so MESH-007 keeps its DENY on every release and the tunnels keep the client identity. |
| **External identity header** (#6088, issue #6082). `X-Consumer-Username` carries only a mapped Consumer's username; an external identity or display claim without a mapped Consumer is sent as the gateway-owned `X-Authenticated-Identity` (never with `X-Consumer-Username`). External authentication (`jwks_auth`, `oauth2_introspection`, `oidc_relying_party`, `ldap_auth`, `soap_ws_security`) no longer maps a principal to a Consumer by matching a username, ID or custom ID, and LDAP `consumer_mapping` is refused. Client copies of `X-Authenticated-Identity` (`_` equivalent to `-`) are removed before any plugin and refused as a configured header destination. | [assertion check][xai-check] `src/proxy/headers.rs:131`; [backend write][xai-write] `src/proxy/mod.rs:17460`; [accessor][xai-accessor] `src/plugins/mod.rs:6982`; [`backend_consumer_username`][xcu] `src/plugins/mod.rs:6972`; [jwks][jwks-none] `src/plugins/jwks_auth.rs:1115`; [LDAP][ldap-removed] `src/plugins/ldap_auth.rs:1325` | Both are gateway-to-backend headers, not client signals; Anvil reads neither and no lab check does. **Notes updated** on `plugin.access_control.external_identity_not_authorized` and `.consumer_not_allowed` (an external identity no longer inherits a Consumer, so Consumer ACLs see it unmapped). `contracts-edge-0.9.15` `gateway-headers.json` adds the header as a `gateway_assertion`; the three `gateway_diagnostic` headers Anvil reads are unchanged. |
| **`Connection` nominations at ingress** (#6090). HTTP/1.1 and HTTP/3 ingress remove the fields a client's `Connection` header nominates before any plugin runs (except `Host`, `Content-Length`, `Expect` and the forwarding fields) and rewrite `Connection` to `close` plus hop-by-hop names; a nominated `Authorization` now gets the auth-phase 401. HTTP/2 rejects `Connection` and is unchanged. | [confine][conn-confine] `src/proxy/headers.rs:542`; [H1][conn-h1] `src/proxy/mod.rs:32997`; [H3][conn-h3] `src/http3/server.rs:3182` | **Notes updated** (`proxy.auth_phase.missing_credential`). Anvil's lab sends only `Connection: close` (retained). |
| **Replay capacity per principal** (#6088). Process-scoped DPoP, HMAC, PasswordDigest and SAML replay stores limit each authenticated principal to a quarter of the entry ceiling and still never evict a live marker; DPoP charges the access token's `iss` and `sub`/`client_id`, so a `require_dpop` token without them gets 401 `DPoP validation failed`. OIDC login challenges expire an older pending-flow cookie beyond two. | [quota][replay-quota] `src/plugins/utils/replay_authority.rs:540`; [DPoP principal][dpop-principal] `src/plugins/jwks_auth.rs:1249` | **Unchanged signals; notes updated** (`plugin.jwks_auth.dpop_replay_capacity`, `plugin.hmac_auth.replay_capacity`, `plugin.soap_ws_security.replay_state_saturated`, `plugin.jwks_auth.dpop_validation_failed`). The lab's DPoP token carries `iss` and `sub`, and its stores use default ceilings. |

## Transport and QUIC changes

| Surface | Exact delta / reuse decision | Edge source (v0.9.15) | Anvil impact |
|---|---|---|---|
| QUIC address validation and Retry (#6085) | A QUIC Initial from an unvalidated source (no Retry or NEW_TOKEN token) runs inside a per-listener handshake budget, `FERRUM_HTTP3_MAX_UNVALIDATED_HANDSHAKES` (default 1024), and is charged to the shared overload connection budget only after its handshake. Past the budget the source gets a stateless Retry (one extra round trip; quinn answers it transparently); an Initial that already followed a Retry is refused. | [classify][qv-classify] `src/http3/address_validation.rs:99`; [accept loop][qv-accept] `src/http3/server.rs:1640` | **No new outcome; notes updated** (`protocol.http3.connection_refused`, `gateway.admission.connection_refused_at_accept`). A Retry is not an error and produces no Anvil finding. |
| 0.5-RTT reserved for validated sources (#6085) | The 0.5-RTT path, where a 0-RTT request is served before the handshake completes (and can draw 425), is taken only for a source validated before the handshake began. An unvalidated client's 0-RTT request is served after the handshake as 1-RTT. | [`source_validated`][qv-zero-rtt] `src/http3/server.rs:2299` | **Notes updated** (`gateway.admission.early_data_rejected`). **Lab and client impact, fixed here:** Anvil built a fresh quinn client config per connection, so the NEW_TOKEN tokens the gateway issues were dropped and every 0-RTT reconnection was unvalidated; EARLY-001/EARLY-002 would see the 0-RTT GET/PUT handled after the handshake. Anvil's QUIC session-ticket context now also keeps the server's address-validation tokens (`crates/anvil-transport/src/tickets.rs`, same isolation and lifetime as the tickets, cleared with them), so a resumed connection presents one, as browsers do. Earlier releases are unaffected. |
| QUIC DATAGRAM no longer advertised (#6085) | The listener and backend pools stop advertising `max_datagram_frame_size`; a peer that sends a DATAGRAM frame is closed with `PROTOCOL_VIOLATION`. CONNECT-UDP carries HTTP Datagrams as capsules on the request stream; the gateway never negotiated `SETTINGS_H3_DATAGRAM`. | [`disable_quic_datagrams`][qv-datagram] `src/http3/config.rs:440` | **Notes updated** (`protocol.http3.connection_refused`). Anvil sends capsules whenever `SETTINGS_H3_DATAGRAM` is absent and checks that setting first, so MASQUE-008's evidence (`h3.settings.h3_datagram`) is unchanged. |
| DTLS passthrough SNI (#6080) | A ClientHello whose SNI is malformed or unrepresentable is dropped before catch-all routing; a well-formed ClientHello without SNI can still use the catch-all. | [drop][dtls-sni] `src/proxy/udp_proxy.rs:2112` | **Notes updated** (`l4.udp.datagram_dropped`). Anvil's DTLS client sends no SNI (its evidence records `sni: None`), which the catch-all still admits. |
| HTTP/2 framing and pool hygiene (#6052, #6055) | Vendored h2 patch 004 closes an idle client connection whose last handle drops mid-poll; Hyper patch 005 splits a body chunk only when the stream's window is short (`SendStream::capacity_and_assigned`). | `vendor/h2-0.4.19-ferrum-patched/src/proto/streams/streams.rs:1414` | **No outcome change.** Framing and connection lifetime only; no completion or timing claim. |
| Configuration and plugin keys | `src/config/types.rs` adds helper methods, no struct field; `env_config.rs` adds `FERRUM_PER_IP_IPV6_PREFIX`, `FERRUM_HTTP3_CONNECT_UDP_MAX_SESSIONS_PER_IP`, `FERRUM_HTTP3_MAX_UNVALIDATED_HANDSHAKES` and `FERRUM_MESH_TENANT_TLS_FILE_ROOTS`; `conf_file.rs` is unchanged. Plugin keys: `ldap_auth` drops `consumer_mapping`, `rate_limiting` adds `ipv6_prefix`, `mcp_gateway` adds `sessions.max_sessions_per_principal`, `body_validator` refuses `grpc_max_decompressed_size_bytes: 0`, and plugin environment references must name `FERRUM_PLUGIN_SECRET_<NAME>` ([`src/plugins/utils/plugin_secret_env.rs:69`][secret-env]). | [comparison][compare] | Lab profiles use none of these keys. `lab/gateway/lint-profiles.rb` drops `consumer_mapping` from the `ldap_auth` allowlist and keeps the new keys out while older releases are supported. |

## Admin, deployment and control-plane scope

These are admission, Kubernetes translation or control-plane surfaces. None is a proxy
diagnostic outcome, and Anvil adds no admin apply, fetch, lookup or trust escalation for them.

| Surface | Delta |
|---|---|
| Namespace isolation (issue #6092) | Gateway API route ids bound to the full source identity (`<id>__<digest>` across namespaces); duplicate `(namespace, id)` resources refused by the control plane and data planes; `ExternalName` backendRefs unsupported; DestinationRule TLS material outside the mesh root namespace scoped to its namespace (`FERRUM_MESH_TENANT_TLS_FILE_ROOTS`); namespace-scoped `operator` tokens refused with 400 for out-of-namespace `backend_tls_*` material. |
| Plugin secrets (issue #6086) | Plugin-config environment references confined to `FERRUM_PLUGIN_SECRET_<NAME>` (Admin API 400, validate failure); `serverless_function` Azure/GCP fallbacks renamed. |
| Control plane (#6078) | `GetFullConfig` requires `node_id` equal to the JWT subject and is rate limited per principal; CORS snapshots filtered by namespace visibility. |
| Database mode (#6056–#6070) | Stage logging, neighborhood-scoped plugin-graph admission, consumer deltas, MongoDB proxy-scoped attachments. |
| Chart and node agent (issue #6096) | Separate workload ServiceAccounts, opt-in Ambient Secret access, node-agent capture only on a dedicated pod interface. |

## Contracts and G01

Canonical `contracts-edge-0.9.15` (`6fb64c5dc2e014204c17609fc717d976f3b4589e`, release
407246047) targets Edge `25b3739`. Anvil vendors 35 paths, byte-exact from the tag: the same 33 as
before, three of them changed, and two new diagnostic-ref fixtures:

- `vocabularies/gateway-errors.json`: `edge_release` and provenance move to v0.9.15; a note
  records that `route_protocol_admission` maps to no token. The same eight tokens and 19 classes,
  each with the same token.
- `vocabularies/gateway-headers.json`: v0.9.15 provenance, the new `X-Authenticated-Identity`
  `gateway_assertion` entry (availability v0.9.15), the narrower `X-Consumer-Username` and
  `X-Consumer-Custom-Id` meaning, and the `Connection`-nomination and `_`/`-` notes. The three
  `gateway_diagnostic` headers are unchanged; `X-Ferrum-Diagnostic-Ref` is still available from
  v0.9.9.
- `fixtures/invalid-expectations.json`: entries for the new diagnostic-ref invalid fixture and a
  gateway-headers vocabulary fixture. The original 13 diagnostic failure paths, keywords and top
  keyword are unchanged.
- New `fixtures/diagnostic-ref/valid/route-protocol-admission.json` (an `all`-mode reference of the
  WebSocket refusal: `rejection.source` gateway, `rejection.phase` `route_protocol_admission`) and
  `fixtures/diagnostic-ref/invalid/route-protocol-admission-as-detail-phase.json` (the label in
  `detail.rejection_phase`). They are vendored because the manifest now names the invalid one and
  `diagnostic_import.rs` exercises every diagnostic expectation it lists; Anvil's reader accepts
  the first and refuses the second, as the schema does.

The diagnostic-report, diagnostic-finding and diagnostic-ref schemas and every earlier diagnostic
fixture are byte-identical to `contracts-edge-0.9.14`. `contracts_adoption.rs` checks the 0.9.9,
0.9.10, 0.9.11, 0.9.14 and 0.9.15 catalogs against the pinned vocabularies and the lab default
(now v0.9.15) against the pin. The real Alloy exporter golden remains historical Edge 0.9.10
evidence.

## Distribution pins and lab scope

Edge [release v0.9.15][release] is published, not inferred from a Cargo version string. Root's
verified distribution record ties release `407222520` to `25b3739` (release workflow run
37823250818, success). Both new locks name all five gateway assets with the GitHub API digests,
which match the published `.sha256` sidecars (Windows: `ferrum-edge-windows-x86_64.exe`, SHA-256
`89817cb54ce2c99535a0c5eec5e4e222f712d57b9b219dbad6957a8c65d160cb`). The lab runs release
binaries, not images; the Docker Hub `ferrumedge/ferrum-edge:0.9.15` index
`sha256:29b468dfeea13b1ecaac8dfbc7e019f310e71e647611d43800a1dc64436eaca3` (amd64
`sha256:0404dc6d70d67abb70feea4e5aa295fdb1c19a0968900f467fc4b908528d19d1`, arm64
`sha256:51b8134770441b3ad340ba87ca9acd8a03fd864315c54d79911b27d95437c91a`) and the
`0.9.15-ebpf` index `sha256:d0888799f8c72b9c07aa208a842355263e5cf547d2edd8cc7de87dfc42b2b4f7`
are recorded here for provenance only.

The PR lab runs the v0.9.15 default. Nightly retains all eight supported releases and adds v0.9.14
as an explicit historical selector. No status acceptance or skip changed. Two lab-scenario impacts
were found and fixed on the Anvil side, both release-independent:

- **MESH-007 and the sidecar HBONE scenarios.** See the mesh relay row above: the sidecar
  MeshPolicy now denies `sa/anvil-lab-other` on `/denied/*`, and MESH-007 presents that SVID
  (`crates/anvil-lab/src/mesh.rs`, `lab/gateway/mesh-sidecar.json`). On v0.9.14 and earlier the
  rule behaves exactly as before for MESH-007, and it never matched the client tunnels.
- **EARLY-001 and EARLY-002.** See the 0.5-RTT row above: Anvil now presents the gateway's
  NEW_TOKEN token on the 0-RTT reconnection.

The source audit found no other scenario whose asserted signal moves:

- **UP-018.** The direct-H1 checkout classifier ([`direct_h1_checkout_error_response`][h1-checkout],
  `src/proxy/mod.rs:50228`) is byte-identical to v0.9.14 and `src/pool` is unchanged. `anvil-lab`
  expects the direct-H1 lane from v0.9.11 through the pin (`release_from_through_pin`), so v0.9.15,
  v0.9.14 and v0.9.11 assert it while 0.9.5/7/8/9/10 keep reqwest; the public-signal contract test
  runs the direct-H1 controls against the 0.9.11, 0.9.14 and 0.9.15 catalogs.
- **Route protocol admission.** The lab sends native gRPC and WebSocket only on `streams` routes,
  whose plugins (`grpc_web`, `stdout_logging`) gate nothing; no gRPC or WebSocket request reaches a
  route with `soap_ws_security`, `openapi_validator`, `mcp_gateway`, `ai_rate_limiter` or an
  authentication plugin.
- **Skip reasons.** `src/identity`, `src/proxy/mesh_udp_frame.rs` and `src/pool` are unchanged;
  `src/proxy/hbone_proxy.rs` only marks relays for Layer-4 authorization; `src/modes` and
  `src/tls/source` change Kubernetes, node-agent and tenant TLS-file admission. The
  release-templated infeasibility reasons remain true for v0.9.15. `jwks_auth` still has no
  DPoP-Nonce challenge.

## Qualification status

Pending. Root dispatches the hosted manual Lab run (`workflow_dispatch`, `profile=all`) on the PR
head; its results, including MESH-007/008, the sidecar UDP/DTLS tunnels, EARLY-001/002 and UP-018,
belong in this section. No physical-device native acceptance, platform signing, OAuth,
provider-account or broader performance acceptance is claimed.

[compare]: https://github.com/ferrum-edge/ferrum-edge/compare/9bd4d5f9caa4ebe8f0ea13e76d8a6e2172eaca7d...25b37395ff61bfea0f3ffd189d9011c4984fa755
[changelog]: https://github.com/ferrum-edge/ferrum-edge/blob/25b37395ff61bfea0f3ffd189d9011c4984fa755/CHANGELOG.md
[upgrade]: https://github.com/ferrum-edge/ferrum-edge/blob/25b37395ff61bfea0f3ffd189d9011c4984fa755/docs/upgrade_guide.md#upgrading-to-0915
[release]: https://github.com/ferrum-edge/ferrum-edge/releases/tag/v0.9.15
[rpa-body]: https://github.com/ferrum-edge/ferrum-edge/blob/25b37395ff61bfea0f3ffd189d9011c4984fa755/src/proxy/mod.rs#L285
[rpa-h1]: https://github.com/ferrum-edge/ferrum-edge/blob/25b37395ff61bfea0f3ffd189d9011c4984fa755/src/proxy/mod.rs#L34019
[rpa-h3]: https://github.com/ferrum-edge/ferrum-edge/blob/25b37395ff61bfea0f3ffd189d9011c4984fa755/src/http3/server.rs#L3961
[rpa-view]: https://github.com/ferrum-edge/ferrum-edge/blob/25b37395ff61bfea0f3ffd189d9011c4984fa755/src/plugin_cache.rs#L5346
[rpa-hook]: https://github.com/ferrum-edge/ferrum-edge/blob/25b37395ff61bfea0f3ffd189d9011c4984fa755/src/plugins/mod.rs#L12169
[rpa-phase]: https://github.com/ferrum-edge/ferrum-edge/blob/25b37395ff61bfea0f3ffd189d9011c4984fa755/src/diagnostic_ref.rs#L200
[rpa-log]: https://github.com/ferrum-edge/ferrum-edge/blob/25b37395ff61bfea0f3ffd189d9011c4984fa755/src/proxy/mod.rs#L34045
[rpa-log-h3]: https://github.com/ferrum-edge/ferrum-edge/blob/25b37395ff61bfea0f3ffd189d9011c4984fa755/src/http3/server.rs#L3986
[ws-h1]: https://github.com/ferrum-edge/ferrum-edge/blob/25b37395ff61bfea0f3ffd189d9011c4984fa755/src/proxy/mod.rs#L32841
[ws-405]: https://github.com/ferrum-edge/ferrum-edge/blob/25b37395ff61bfea0f3ffd189d9011c4984fa755/src/proxy/mod.rs#L52816
[ws-h2]: https://github.com/ferrum-edge/ferrum-edge/blob/25b37395ff61bfea0f3ffd189d9011c4984fa755/src/proxy/mod.rs#L32851
[ws-h3]: https://github.com/ferrum-edge/ferrum-edge/blob/25b37395ff61bfea0f3ffd189d9011c4984fa755/src/http3/server.rs#L3478
[rt-tunnel]: https://github.com/ferrum-edge/ferrum-edge/blob/25b37395ff61bfea0f3ffd189d9011c4984fa755/src/plugins/request_termination.rs#L536
[dedup-decode]: https://github.com/ferrum-edge/ferrum-edge/blob/25b37395ff61bfea0f3ffd189d9011c4984fa755/src/plugins/request_deduplication.rs#L3270
[dedup-503]: https://github.com/ferrum-edge/ferrum-edge/blob/25b37395ff61bfea0f3ffd189d9011c4984fa755/src/plugins/request_deduplication.rs#L3290
[dedup-400]: https://github.com/ferrum-edge/ferrum-edge/blob/25b37395ff61bfea0f3ffd189d9011c4984fa755/src/plugins/request_deduplication.rs#L3294
[firewall-decode]: https://github.com/ferrum-edge/ferrum-edge/blob/25b37395ff61bfea0f3ffd189d9011c4984fa755/src/plugins/ai_semantic_firewall.rs#L7942
[cudp-slot]: https://github.com/ferrum-edge/ferrum-edge/blob/25b37395ff61bfea0f3ffd189d9011c4984fa755/src/http3/connect_udp.rs#L1723
[cudp-reject]: https://github.com/ferrum-edge/ferrum-edge/blob/25b37395ff61bfea0f3ffd189d9011c4984fa755/src/http3/connect_udp.rs#L2106
[mtom-delim]: https://github.com/ferrum-edge/ferrum-edge/blob/25b37395ff61bfea0f3ffd189d9011c4984fa755/src/plugins/soap_ws_security.rs#L7228
[mtom-root]: https://github.com/ferrum-edge/ferrum-edge/blob/25b37395ff61bfea0f3ffd189d9011c4984fa755/src/plugins/soap_ws_security.rs#L7512
[mtom-2231]: https://github.com/ferrum-edge/ferrum-edge/blob/25b37395ff61bfea0f3ffd189d9011c4984fa755/src/plugins/soap_ws_security.rs#L4596
[mtom-charset]: https://github.com/ferrum-edge/ferrum-edge/blob/25b37395ff61bfea0f3ffd189d9011c4984fa755/src/plugins/soap_ws_security.rs#L7639
[mcp-quota]: https://github.com/ferrum-edge/ferrum-edge/blob/25b37395ff61bfea0f3ffd189d9011c4984fa755/src/plugins/mcp_gateway.rs#L2614
[mcp-refuse]: https://github.com/ferrum-edge/ferrum-edge/blob/25b37395ff61bfea0f3ffd189d9011c4984fa755/src/plugins/mcp_gateway.rs#L2625
[mcp-anon]: https://github.com/ferrum-edge/ferrum-edge/blob/25b37395ff61bfea0f3ffd189d9011c4984fa755/src/plugins/mcp_gateway.rs#L2571
[perip-slot]: https://github.com/ferrum-edge/ferrum-edge/blob/25b37395ff61bfea0f3ffd189d9011c4984fa755/src/proxy/mod.rs#L15212
[perip-req]: https://github.com/ferrum-edge/ferrum-edge/blob/25b37395ff61bfea0f3ffd189d9011c4984fa755/src/proxy/mod.rs#L33308
[rl-prefix]: https://github.com/ferrum-edge/ferrum-edge/blob/25b37395ff61bfea0f3ffd189d9011c4984fa755/src/plugins/rate_limiting.rs#L333
[mesh-relay]: https://github.com/ferrum-edge/ferrum-edge/blob/25b37395ff61bfea0f3ffd189d9011c4984fa755/src/plugins/mesh/authz.rs#L3028
[mesh-tag]: https://github.com/ferrum-edge/ferrum-edge/blob/25b37395ff61bfea0f3ffd189d9011c4984fa755/src/proxy/hbone_proxy.rs#L358
[mesh-custom]: https://github.com/ferrum-edge/ferrum-edge/blob/25b37395ff61bfea0f3ffd189d9011c4984fa755/src/plugins/mesh/authz.rs#L3413
[mesh-deny]: https://github.com/ferrum-edge/ferrum-edge/blob/25b37395ff61bfea0f3ffd189d9011c4984fa755/src/modes/mesh/policy.rs#L939
[xai-check]: https://github.com/ferrum-edge/ferrum-edge/blob/25b37395ff61bfea0f3ffd189d9011c4984fa755/src/proxy/headers.rs#L131
[xai-write]: https://github.com/ferrum-edge/ferrum-edge/blob/25b37395ff61bfea0f3ffd189d9011c4984fa755/src/proxy/mod.rs#L17460
[xai-accessor]: https://github.com/ferrum-edge/ferrum-edge/blob/25b37395ff61bfea0f3ffd189d9011c4984fa755/src/plugins/mod.rs#L6982
[xcu]: https://github.com/ferrum-edge/ferrum-edge/blob/25b37395ff61bfea0f3ffd189d9011c4984fa755/src/plugins/mod.rs#L6972
[jwks-none]: https://github.com/ferrum-edge/ferrum-edge/blob/25b37395ff61bfea0f3ffd189d9011c4984fa755/src/plugins/jwks_auth.rs#L1115
[ldap-removed]: https://github.com/ferrum-edge/ferrum-edge/blob/25b37395ff61bfea0f3ffd189d9011c4984fa755/src/plugins/ldap_auth.rs#L1325
[conn-confine]: https://github.com/ferrum-edge/ferrum-edge/blob/25b37395ff61bfea0f3ffd189d9011c4984fa755/src/proxy/headers.rs#L542
[conn-h1]: https://github.com/ferrum-edge/ferrum-edge/blob/25b37395ff61bfea0f3ffd189d9011c4984fa755/src/proxy/mod.rs#L32997
[conn-h3]: https://github.com/ferrum-edge/ferrum-edge/blob/25b37395ff61bfea0f3ffd189d9011c4984fa755/src/http3/server.rs#L3182
[replay-quota]: https://github.com/ferrum-edge/ferrum-edge/blob/25b37395ff61bfea0f3ffd189d9011c4984fa755/src/plugins/utils/replay_authority.rs#L540
[dpop-principal]: https://github.com/ferrum-edge/ferrum-edge/blob/25b37395ff61bfea0f3ffd189d9011c4984fa755/src/plugins/jwks_auth.rs#L1249
[qv-classify]: https://github.com/ferrum-edge/ferrum-edge/blob/25b37395ff61bfea0f3ffd189d9011c4984fa755/src/http3/address_validation.rs#L99
[qv-accept]: https://github.com/ferrum-edge/ferrum-edge/blob/25b37395ff61bfea0f3ffd189d9011c4984fa755/src/http3/server.rs#L1640
[qv-zero-rtt]: https://github.com/ferrum-edge/ferrum-edge/blob/25b37395ff61bfea0f3ffd189d9011c4984fa755/src/http3/server.rs#L2299
[qv-datagram]: https://github.com/ferrum-edge/ferrum-edge/blob/25b37395ff61bfea0f3ffd189d9011c4984fa755/src/http3/config.rs#L440
[dtls-sni]: https://github.com/ferrum-edge/ferrum-edge/blob/25b37395ff61bfea0f3ffd189d9011c4984fa755/src/proxy/udp_proxy.rs#L2112
[secret-env]: https://github.com/ferrum-edge/ferrum-edge/blob/25b37395ff61bfea0f3ffd189d9011c4984fa755/src/plugins/utils/plugin_secret_env.rs#L69
[h1-checkout]: https://github.com/ferrum-edge/ferrum-edge/blob/25b37395ff61bfea0f3ffd189d9011c4984fa755/src/proxy/mod.rs#L50228
