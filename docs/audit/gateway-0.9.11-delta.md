# Ferrum Edge 0.9.10 → 0.9.11: source delta and hosted qualification

| Item | Immutable identity / status |
|---|---|
| Baseline | `v0.9.10`, `ee040d5e3281fde424aa65f5b18004852c5b53b0` |
| Audited target | `v0.9.11`, `c764084b3b51c3f7ffde268c039688d35e49c553` |
| Contracts | Published `contracts-edge-0.9.11`, `390edbd5b2485af0988e02f7827fde778d76ae0a` |
| Catalog | [`ferrum-edge-0.9.11/outcomes.json`](../../catalog/ferrum/ferrum-edge-0.9.11/outcomes.json), 553 carried outcome IDs with the delta below |
| Lab selection | `lab/gateway/RELEASE.lock` and `lab/gateway/releases/v0.9.11.lock`; hosted source qualification recorded below |
| Qualified Anvil source | [`28876cc6623fdba01289b450fe12c7c16649b655`](https://github.com/ferrum-edge/ferrum-anvil/commit/28876cc6623fdba01289b450fe12c7c16649b655), [PR #313](https://github.com/ferrum-edge/ferrum-anvil/pull/313) |
| Documentation record | Merged with [PR #313](https://github.com/ferrum-edge/ferrum-anvil/pull/313); hosted source qualification recorded below |
| Audit date | 2026-10-04 |

The [immutable comparison][compare] changes 105 files under `src/` (11,369 insertions,
2,060 deletions), plus dependency/vendor, test and documentation changes. This is a separate
source delta audit on top of the [0.9.10 inventory](gateway-0.9.10-delta.md), not a new
comprehensive inventory. Hosted Anvil qualification is limited to the exact source and coverage
recorded below. The historical 0.9.5, 0.9.7, 0.9.8, 0.9.9 and 0.9.10 catalogs and release locks
remain available and unchanged.

## Method and limits

Both full source archives were read at the exact commits above, without checkout, build,
formatting, test, script, binary or container execution. Structured baseline citations were
remapped through the immutable unified diff, retaining unchanged cited source text. The
shared DNS preflight citation was corrected to its current call site. Citation text equality
alone does not establish behavioral equality: the changed dispatch, classifier, header,
authentication, plugin and stream paths below were separately inspected against their
surrounding source and the [0.9.11 changelog][changelog]. New citations support those notes.
Explicitly historical `@sha` prose citations remain historical.

The carried signals are status/body/header/gRPC literals, not operator-only causes or timing
measurements. Unchanged-source plugin entries retain their old observable semantics; changed
plugins are reconciled below. The catalog records no new outcome IDs or new diagnostic cause.
Admin conditional operations, config admission errors and dependency behavior are described
at their actual scope rather than fabricated as new proxy diagnostic outcomes.

Local validation uses static inspection and `git diff --check` only; no project tooling runs
locally. Completed hosted CI, Desktop E2E and real pinned-binary lab evidence below qualify
Anvil source `28876cc6623fdba01289b450fe12c7c16649b655`. Unit schema/parser/catalog checks
alone cannot establish live gateway compatibility. The subsequent documentation record still
requires root's whole-record review and fresh hosted CI at its own exact pushed head; the source
runs are not results for that later commit. No physical-device native acceptance or broader
performance measurement is claimed.

## Marker, error class and header decisions

The [ErrorClass/token definitions][retry] still have 19 granular classes and eight coarse
`X-Gateway-Error` values: `connection_failure`, `backend_timeout`, `request_timeout`,
`backend_error`, `circuit_breaker_open`, `overload`, `config_stale`, `concurrency_limit`.
The enum, spellings and class-to-token mapping did not change. `retry.rs` adds
`AuthorizationExpired` → `client_disconnect`, a direct-H1 Hyper classifier, and an independent
`BackendResponse.request_on_wire` field. Health classification therefore does not prove
request handoff. The catalog table retains the unchanged class-method defaults and explicitly
identifies them as classification, not per-request wire proof. An authorization refusal is health-neutral before and after handoff;
`client_disconnect` is not proof that the caller physically disconnected.

The [gateway-owned diagnostic list][headers] remains `X-Gateway-Error`,
`X-Gateway-Upstream-Status` and `X-Ferrum-Diagnostic-Ref`. Header merging changes allocation
and lookup work while retaining repeated-header and invalid-value behavior. The
[authoritative token finalizer][token-finalizer] and [H3 finalizers][h3-finalizers] keep the
same overwrite/strip boundaries. `degraded` remains fallback selection, not failure by itself.
Plugin reject decorators and non-Ferrum endpoints can still imitate public markers.
Marker-derived attribution remains at most likely; absent markers do not establish upstream origin.
An untrusted `ferrum.marker.unverified` finding confirms only that a header was observed:
its confidence is confirmed, its scope is unknown and it grants no gateway attribution.

There is one actual protocol-header correction: [Via selection][via] now reads the response's
HTTP version for streamed direct-H1, Unix-socket and HBONE inner H1 bodies. Unix/HBONE H1
previously inherited HTTP/2 Via from the shared `StreamingH2` representation. With the new
default direct-H1 pool, [verified backend Content-Length][content-length] is also retained on
those streamed H1 paths instead of rechunking. Neither header establishes provenance, complete
body delivery, a new handshake, or timing attribution.

## Authorization, gRPC lifetime and cancellation

[GrpcDispatchBounds][grpc-bounds] composes the admitted receipt-anchored authorization instant
with the original client deadline before acquisition. Acquisition, synchronous final handoff,
response-header wait, collection and retries retain those absolute instants. The earliest
captured authorization/client/operator source wins even if observation occurs after several
bounds elapsed. The [shared lifetime design][lifetime] and inspected direct H1/H2, Unix/HBONE,
sidecar mesh, native H3 and H3-to-gRPC bridge call sites retain that plan. An immediately ready
acquisition preserves the timer-free path; unauthenticated paths avoid authorization clock work.

Before client response commitment, the existing terminals remain plain HTTP `401`
`{"error":"Unauthorized"}`, native gRPC HTTP `200` with `grpc-status: 16`, and the corresponding
gRPC-Web framed terminal. An earlier client deadline stays `DEADLINE_EXCEEDED`; an earlier
operator read bound keeps its existing backend timeout. Expiry is latched/counted once, never
retried and does not train passive health, circuit breakers or backend admission. The same
terminal can occur before or after backend handoff, so public evidence cannot infer dispatch.
The catalog extends the existing authorization/deadline notes without introducing a new signal.

[gRPC source EOF handling][grpc-eof] distinguishes H2 CANCEL/NO_ERROR from genuine END_STREAM.
Source EOF can still leave DATA queued inside h2. [Frontend affinity][affinity] retains ownership
until the frontend response and every backend attempt/stream end, including buffered/retry and
translated gRPC-Web uploads. Physical shard-create failures/cancellations record one cooldown;
ready siblings may serve waiting callers, cold pools can recover, and calls above the 32-open-call
threshold spill. Failure bookkeeping is bounded at 4,096 keys. None of this proves a public
request was processed, or supplies per-request setup timing on a reused connection.

The H3 bridge pump and queued channel check the original lifetime independently of backend
polling. [Native H3's upload guard][h3-reset] sends `H3_REQUEST_CANCELLED` for unfinished uploads
on expiry, write failure, malformed trailers, oversize input or cancellation, including a stall
waiting for more frontend DATA. The pool's wire marker is HEADERS completion; a pending poll
can already have offered partial HEADERS. It does not identify exact first-wire submission.
Lifetime failures suppress replay regardless of that marker. Existing before/after-commit
terminals and all catalog forbidden claims remain in force.

## Request timeout and transport decisions

[Route deadline classification][route-deadline] remains `request_timeout` when a total route
budget expires before backend handoff (gateway processing, upload/admission or retry backoff),
and `backend_timeout` when a backend held the canceled attempt. The same 504 body alone does
not distinguish those phases. The new independent handoff field avoids using a health-neutral
class as a wire-state proxy. Per-attempt budgets remain separate and may permit another attempt
only under the original retry rules; a total deadline stops the retry loop.

[Eligible H1 dispatch][direct-h1] now defaults to exclusive Hyper connection lanes under
`FERRUM_POOL_HTTP1_DIRECT=true`. Clean completion returns a lease; incomplete/error exits retire
it. DNS preflight precedes that selection, preserving the specific preflight DNS body. Later
checkout failures use the typed pooled classifier and existing ordinary failure bodies; the
pooled `backend_connection_limit` class now also applies to eligible H1. Its
[typed checkout response][h1-checkout] uses the existing coarse 502/connection_failure/body;
the retained reqwest refusal stays 503/backend_error with its specific connection-ceiling body.
Bodies still needing plugin work and retries retain reqwest. An idle canceled-send replay is at most once and only
when Hyper proves it was not on wire. The catalog retains ambiguous backend-processing claims.

[Unlimited direct-H2 uploads][h2-write] now enforce `backend_write_timeout_ms` inside Hyper.
Unauthenticated streamed native gRPC uses the same pipe bound instead of the pump; authenticated
uploads retain the authorization pump. A ready chunk blocked on capacity is a backend write
stall; a slow frontend with no ready chunk is not. Before headers, HTTP keeps
504/`backend_timeout`/`read_write_timeout`, and native gRPC keeps status 4. After headers the
stream resets, so HTTP 200/HEADERS cannot be reported as complete success. Zero opts out.
[Hyper's small-window change][hyper-pipe] progresses with any positive capacity rather than
waiting for 1 KiB. [h2's automatic framing budget][h2-budget] follows target receive-window
changes while preserving configured budgets and outstanding charges. Existing outcome IDs
and completion/uncertainty assertions remain appropriate. Hosted profile coverage is recorded
below; it does not establish broader small-window/write or performance acceptance.

## Plugin/auth and remaining source scope

| Surface | Exact delta / reuse decision | Immutable evidence |
|---|---|---|
| `sse` | Same 406/body now rejects absent affirmative event-stream intent, including `q=0`, malformed or duplicate quality. Another affirmative range can admit; `require_accept_header=false` remains opt-out. Existing `plugin.sse.accept_missing` condition updated. | [request admission][sse], [quality predicate][sse-quality] |
| `response_mock` | Standard methods keep case-folding; extension methods preserve exact case (`Foo` matches `Foo`, not `FOO`). Existing match/no-match notes updated; configured statuses/bodies remain. | [constructor][mock] |
| `oidc_relying_party` | Config construction rejects known public/placeholder session keys, including normalized/Base64 spellings and unresolved templates. This is admission, not a new runtime login terminal. Existing runtime challenge/callback signals retained. The lab already generates its session key; no Anvil identity/secret handling changed. | [construction][oidc], [screening][session-secret] |
| `ai_semantic_cache` | Generation-qualified local eviction preserves fresh same-key entries; Redis quarantine compares exact observed bytes before deletion and bounds transfer. Oversized remote values remain until TTL. Existing HIT/MISS/BYPASS and fail-open dependency outcomes retained. | [cache][cache], [Redis helper][redis] |
| MCP/auth/WAF and other unchanged-source plugins | `ai_prompt_shield`, `ai_transcript_audit`, `mcp_gateway`, token-auth and WAF outcome sources retain the v0.9.10 source bytes. The charset/unparseable refusals introduced in 0.9.10 remain known in 0.9.11; older release matching boundaries remain. Atomic update replacements in changed logging/rate/auth helpers retain the same orderings and closures. | [comparison][compare] |
| TLS admission | Fragmentless CA references use their declared material kind; contradictory material selectors are refused at admission. Lab PEM cert/key/CA paths remain appropriate. No inferred TLS cause added to the coarse connection token. | [types][types], [TLS source][tls-source] |
| TCP/mesh relays | Read coalescing starts at 8 KiB instead of 16 KiB; smaller reads remain immediate. Existing stream status/close/error outcomes retain their meaning. | [relay delta][tcp-relay] |
| Admin surfaces | Authoritative conditional snapshots/restores, consumer verification and inherited backend-egress discovery are admin-only additions. They do not expose a new public diagnostic cause or authorize an imported report. No admin apply/fetch path was added to Anvil. | [conditional operations][conditional], [egress discovery][egress] |
| Dependencies and internal dispatch | Edge rebases retained Hyper/reqwest patches onto 1.10.0/0.13.4, adds patched h2 0.4.19 behavior, changes boxed child futures/plugin-view lookup and physical pooling. Anvil dependencies are unchanged. No performance/timing claim imported from Edge benchmarks. | [changelog][changelog], [owner lockfile][owner-lock] |

## G01 and the unchanged shared v1 freeze

`src/diagnostic_ref.rs` is byte-identical across the compared trees (SHA-256
`4a7dde19a3cc713c13c60231574916d32342e4d257a70cf3acde1fa6f900e006`).
[Its source][diagnostic-ref] still defines opaque fd1/fd2 references, owner-process admin lookup,
namespace/scope restrictions, TTL, redacted bounded details and fixed v1 vocabularies.
A reference is not an embedded cause, bearer permission or proof of a trusted record. Only the
existing verified, response-bound authorized lookup can raise Anvil's live G01 finding above
likely. Imported reports/references remain read-only, unverified and unknown; no lookup follows
preview, no supplied claim becomes trusted/confirmed, and no timing attribution is performed.

Canonical `contracts-edge-0.9.11` was published at 2026-10-04 22:41:21 UTC after
[contracts PR #13](https://github.com/ferrum-edge/ferrum-contracts/pull/13) and successful
[main publication qualification](https://github.com/ferrum-edge/ferrum-contracts/actions/runs/37240886730).
It targets immutable Edge c764084 and records the root-accepted unchanged Alloy shared v1
freeze at `81cbb410d34ff5fba1f3d54cfd2e7ebccaed397e`. Its shared status is EXISTING/implemented;
Alloy owner availability remains unreleased. Historical PROPOSED descriptions and preparation-time
pending-publication wording in those immutable bytes are preserved, including strict description
parity after removing only `$id`/`x-contract`. Anvil documents actual publication separately.
Every previously adopted canonical path is vendored byte-exact, including the expanded negative
manifest. The original 13 diagnostic failure paths/keywords/top-keyword and all reader/token/class/
header checks remain strict. New unrelated manifest scopes do not expand Anvil's import formats.

The real Alloy exporter golden, CLI/schema source copies and their PIN remain exact historical
bytes from owner `0c260f5379939ff46d681666bfbcd65b8518b08d`, hosted artifact `11305688717` from
run `37208769030`, against Edge 0.9.10. They are not new 0.9.11 producer or lab evidence.
See [shared diagnostic import](../architecture/shared-diagnostics-import.md).

## Distribution pins and hosted gates

Edge [release v0.9.11][release] is published, not inferred from Cargo version strings.
Root's verified distribution record ties release `403215981` to c764084 and the successful
[release workflow](https://github.com/ferrum-edge/ferrum-edge/actions/runs/37229572280).
All five actual gateway assets are named in both new locks; their downloaded-byte digests match
GitHub API digests and published checksum assets. In particular Windows is
`ferrum-edge-windows-x86_64.exe`, SHA-256
`9bc7c9240fa0898a9efeb6e2dabb74c696772af0bb0ba2f7e57ab70c3d0a86e9`.
The lock files record all other exact byte digests without guessed naming.

Hosted lab still fetches real release binaries and verifies the selected lock before execution.
The PR matrix uses the 0.9.11 default; nightly retains all six releases, with 0.9.10 as an
explicit historical selector. Existing loopback profiles, resource counts and configuration key
allowlists are unchanged. UP-018 now asserts each release's exact HTTP/1.1 ceiling signal:
0.9.5/7/8/9/10 retain 503/`backend_error`/`{"error":"Backend connection limit exceeded"}` and
operator `dispatch_policy_rejected`; the eligible bodyless GET on 0.9.11 requires
502/`connection_failure`/`{"error":"Backend unavailable"}` and operator `backend_connection_limit`.
The latter diagnosis stays in the unknown-confidence ambiguous pooled family, with its token
at most likely. Both paths require independent occupant/no-probe and connection-count evidence,
backend-observed recovery and application lookalikes; the untrusted pass permits no token/outcome
attribution. The ceiling and both lookalikes explicitly require the unverified marker observation
to be confirmed with unknown scope; every other public Ferrum finding stays at most likely.
No broad status acceptance, profile override or new skip was introduced. The retained
reqwest signature remains covered by public-signal contract tests on every catalog.

Fresh review and hosted Rust failures at `32da237dc255cc8159c93fdbbcfd1f85b9cceedf` also
identified stale unsupported-release and record-version test expectations. Negative controls now
use the deliberately unsupported `ferrum-edge-unsupported-test-release`; positive timeout/token
and per-record catalog expectations include 0.9.11 while retaining confidence, scope and forbidden
claims. The new catalog's shipping panic citations now point to `Cargo.toml:507` and `:537`
at c764084, and its retained reqwest condition explicitly excludes eligible direct-H1 attempts.
Fresh review and completed native failure logs at `c74fcc340838eb6d28bb5334d8d9629176e3c0e2`
identified a blanket confidence assertion that rejected valid untrusted marker observations.
The controls now distinguish observation from attribution without changing diagnosis behavior.
All formatter edits from that head's hosted Linux diff have been applied to the three Rust files.

Qualification succeeded after those source/control/formatter repairs. The earlier failures
were not treated as flakes or rerun into acceptance. The green
[initial Lab run 37243246063](https://github.com/ferrum-edge/ferrum-anvil/actions/runs/37243246063)
selected only `core`; it supplies no UP-018 qualification.

## Exact-source hosted qualification

Root's static qualification covered all 80 original PR files, all catalog projections, the
33 canonical file byte hashes and the complete c74fcc3/28876cc repair diffs. The fresh third
read-only review reported `NO_FINDINGS`. Hosted evidence below belongs to Anvil source
`28876cc6623fdba01289b450fe12c7c16649b655`; each run completed successfully at attempt 1.

| Hosted run | Applicable coverage / result |
|---|---|
| [CI 37245583522](https://github.com/ferrum-edge/ferrum-anvil/actions/runs/37245583522) | All applicable gates successful: Rust on ubuntu-24.04, macos-15 and windows-2025; frontend; contract/catalog drift; supply chain/licensing; secrets; release checker on ubuntu-22.04 and ubuntu-24.04 |
| [Desktop E2E 37245583544](https://github.com/ferrum-edge/ferrum-anvil/actions/runs/37245583544) | Successful on ubuntu-24.04, macos-15 and windows-2025 |
| [PR Lab 37245583561](https://github.com/ferrum-edge/ferrum-anvil/actions/runs/37245583561) | Successful on ubuntu-24.04 and macos-15; `core` only, no UP-018 qualification |
| [Manual Lab 37245804710, attempt 1](https://github.com/ferrum-edge/ferrum-anvil/actions/runs/37245804710/attempts/1) | Root's actual `workflow_dispatch` with `profile=all`, `release=v0.9.11`, trusted and untrusted passes; both OS jobs successful |

The manual lab fetched and verified the published pinned Edge v0.9.11 binaries and ran all
14 profiles. Its completed job logs record these totals, including the predefined skips:

| Manual lab job | Passed | Failed | Skipped | `admission` passed / failed / skipped | UP-018 |
|---|---|---|---|---|---|
| [Ubuntu 111563355759](https://github.com/ferrum-edge/ferrum-anvil/actions/runs/37245804710/job/111563355759) | 554 | 0 | 21 | 8 / 0 / 2 | Trusted and untrusted passed |
| [macOS 111563356038](https://github.com/ferrum-edge/ferrum-anvil/actions/runs/37245804710/job/111563356038) | 558 | 0 | 19 | 8 / 0 / 2 | Trusted and untrusted passed |

These are successful job conclusions with skipped cases, not a claim that every case passed.
Ubuntu skipped AUTH-030 and AUTH-031 because `xmllint` was unavailable; macOS passed each
case in both trusted and untrusted mode. The other 19 predefined skips are common to both jobs.
The exact logged reasons are retained below, with line wrapping only and identical reasons
grouped by case ID. No skip was added or widened to obtain qualification.

```text
GW-014-GEO (Ubuntu and macOS):
  geo_restriction needs a readable MaxMind country .mmdb: `ferrum-edge validate` rejects a missing
  db_path ('not accessible before open'), no database is vendored in the repo and the lab may not
  download one, so neither the country-deny nor the database-unavailable path is reachable with
  Ferrum Edge 0.9.11 file mode here.

GW-005 (Ubuntu and macOS):
  Needs a real CP + DP pair (a file-mode gateway never installs the DP freshness fence,
  src/modes/data_plane.rs:44); it is owned by the cpdp profile (ports 187xx/197xx), not this
  file-mode admission instance.

UP-018-H2 (Ubuntu and macOS):
  Not reachable with a single-destination lab on Ferrum Edge 0.9.11: the direct-H2 pool multiplexes,
  so a maxConnections=1 ceiling is never re-dialled. Observed live on 0.9.5: with
  SETTINGS_MAX_CONCURRENT_STREAMS=1 the second request queued ~2.5 s behind the first on the one
  connection (200, one backend connection), and a backend that GOAWAYs each connection made the pool
  reuse the draining connection (502 connection_failure, operator error_class connection_pool_error
  = pool cancellation, not the ceiling). The pooled-lane public signal (502 connection_failure
  "Backend unavailable") is covered by the contract test
  up_018_pooled_lane_ceiling_stays_in_the_ambiguous_family
  (crates/anvil-diagnostics/tests/upstream_setup_contract.rs).

TLS-003 (Ubuntu and macOS):
  infeasible on Ferrum Edge 0.9.11: the gateway refuses to start with an expired frontend
  certificate (the live `ferrum-edge validate` refused it: Validation error: Startup security
  validation failed: Invalid TLS configuration: `server TLS cert`: certificate record #1 in
  <redacted scalar> has expired), so no client can observe one from it. Expired-certificate handling
  is exercised on the upstream leg by UP-004.expired and on the client leg by anvil-transport tests.

TLS-004 (Ubuntu and macOS):
  infeasible on Ferrum Edge 0.9.11: the gateway refuses to start with a not-yet-valid frontend
  certificate (the live `ferrum-edge validate` refused it: Validation error: Startup security
  validation failed: Invalid TLS configuration: `server TLS cert`: certificate record #1 in
  <redacted scalar> is not yet valid). Client-side not-yet-valid classification is covered by
  anvil-transport tests.

TLS-010 (Ubuntu and macOS):
  infeasible against the real gateway: the Ferrum Edge 0.9.11 frontend always answers a ClientHello
  (its handshake timeout only closes clients that stall). A client-leg stall needs a non-gateway
  fault fixture; UP-007 covers the stall on the gateway-to-backend leg.

TLS-011 (Ubuntu and macOS):
  infeasible against the real gateway: Ferrum Edge 0.9.11 ends every frontend handshake refusal with
  a TLS alert; a bare reset needs a client-leg fault fixture that would not be the gateway.

TLS-012 (Ubuntu and macOS):
  infeasible against the real gateway: every Ferrum Edge 0.9.11 TLS listener (HTTPS and TCP+TLS
  share one rustls ServerConfig) offers h2, http/1.1 and acme-tls/1 (src/tls/mod.rs), and every
  Anvil HTTP-family policy offers h2 and/or http/1.1, so there is never an ALPN gap to observe.

TLS-017 (Ubuntu and macOS):
  out of this profile: needs a forward-proxy fixture in front of the gateway; the gateway plays no
  part in the proxy CONNECT leg.

TLS-018 (Ubuntu and macOS):
  out of this profile: the gateway only relays a backend redirect; the certificate-boundary decision
  is Anvil's redirect policy, covered by engine tests.

AUTH-030, AUTH-031 (Ubuntu):
  xmllint (libxml2 Exclusive XML Canonicalization, the audited canonicalizer the lab signer needs)
  is not installed on this host; Anvil itself never signs XML

AUTH-011, AUTH-012, AUTH-013, AUTH-014 (Ubuntu and macOS):
  client-side OAuth flow with no gateway leg (external browser, loopback redirect, state/PKCE,
  refresh single-flight); covered by anvil-auth unit tests and the anvil-identity fixture-IdP tests
  (tests/api_oauth.rs), not a live-gateway scenario

AUTH-025.nonce (Ubuntu and macOS):
  infeasible on Ferrum Edge 0.9.11: jwks_auth implements no DPoP-Nonce / use_dpop_nonce challenge
  (audit §5.4, re-checked in the 0.9.7 to 0.9.10 source); AUTH-025 covers the replay half live

MESH-016 (Ubuntu and macOS):
  infeasible on a loopback-only host without Kubernetes: Ferrum Edge 0.9.11's Ambient inbound relay
  guard categorically refuses loopback destinations (docs/mesh.md "Inbound Relay Destination Guard";
  src/modes/mesh/config.rs inbound_relay_destination_decision) and admits only a non-loopback
  accepted pod address or node-agent-enrolled pod IPs; the lab binds 127.0.0.1 only and has no node
  agent. MESH-010/011 verify the Ambient guard live; MESH-008 drives the same transparent CONNECT
  relay to a workload on the Sidecar inbound listener.

MESH-017 (Ubuntu and macOS):
  not reachable without a control plane: the post-plugin re-check runs only after a before_proxy
  route override (mesh_route_dispatch from a VirtualService) moved the effective destination, and
  the localized file source carries no VirtualService (gateway plugin_configs are rejected in mesh
  file mode). MESH-009/010/011 verify the relay-synthesis refusal of Ferrum Edge 0.9.11 live
  (src/proxy/mod.rs build_inbound_hbone_relay_proxy: a generic 404 {"error":"Not Found"} on 0.9.5
  and 0.9.7, the same documented 403 hbone_relay_destination_denied from 0.9.8). The 403 refusal
  contract is covered by the HBONE fixture tests (crates/anvil-engine/tests/mesh_hbone.rs).

MESH-029 (Ubuntu and macOS):
  infeasible on a loopback-only host without Kubernetes, for the reason MESH-016 states: the Ambient
  relay guard refuses loopback authorities (MESH-028), and the datagram relay also drops loopback
  DNS answers for a declared name (MESH-024; src/proxy/hbone_proxy.rs
  screen_ordinary_inbound_hbone_relay_dns_candidates); a positive Ambient UDP relay needs a
  non-loopback pod address or a node-agent-enrolled pod. MESH-018 drives the same datagram relay on
  the Sidecar inbound listener.

MESH-030 (Ubuntu and macOS):
  not in this profile: the EgressGateway relays a udp-marked CONNECT only to MESH_EXTERNAL
  ServiceEntry UDP destinations with FERRUM_MESH_EGRESS_STREAM_ENABLED (src/proxy/mod.rs
  mesh_egress_udp_destination_dial_endpoint) and caps them at FERRUM_UDP_MAX_SESSIONS (503
  {"error":"UDP egress relay session capacity exhausted"}); that needs a fourth,
  EgressGateway-topology instance with a ServiceEntry, which the mesh profile does not run. The 503
  refusal shape is covered by the HBONE fixture tests (crates/anvil-engine/tests/mesh_hbone_udp.rs).
```

The source key/field audit and the hosted profile results retain their separate scopes.
They do not establish comprehensive acceptance of every changed Edge path, including direct-H1
reuse/framing, gRPC cancellation, small-window/write bounds or SSE quality beyond the scenarios
actually exercised. This record changes only documentation: all source, catalog, contract PIN,
release lock, golden, test and workflow bytes stay at the qualified source; historical catalogs,
locks and the Alloy exporter golden/PIN remain unchanged.

Root must review this whole documentation record and run fresh hosted CI at the new exact
pushed head. The successful source runs above do not qualify that documentation commit.
This adoption grants no Anvil release/tag, available-now status, platform signing, OAuth,
physical-device native acceptance, provider-account or broader performance acceptance.
Published unsigned `anvil-v0.1.1` preview assets remain unchanged; human identity/signing gates
remain open. Other owners' pending proposals are not adopted, and the six separate safety
proposals #306–#311 remain outside this worktree's assignment.

[compare]: https://github.com/ferrum-edge/ferrum-edge/compare/ee040d5e3281fde424aa65f5b18004852c5b53b0...c764084b3b51c3f7ffde268c039688d35e49c553
[changelog]: https://github.com/ferrum-edge/ferrum-edge/blob/c764084b3b51c3f7ffde268c039688d35e49c553/CHANGELOG.md
[retry]: https://github.com/ferrum-edge/ferrum-edge/blob/c764084b3b51c3f7ffde268c039688d35e49c553/src/retry.rs#L212
[headers]: https://github.com/ferrum-edge/ferrum-edge/blob/c764084b3b51c3f7ffde268c039688d35e49c553/src/proxy/headers.rs#L860
[token-finalizer]: https://github.com/ferrum-edge/ferrum-edge/blob/c764084b3b51c3f7ffde268c039688d35e49c553/src/proxy/mod.rs#L26772
[h3-finalizers]: https://github.com/ferrum-edge/ferrum-edge/blob/c764084b3b51c3f7ffde268c039688d35e49c553/src/http3/server.rs#L10986
[via]: https://github.com/ferrum-edge/ferrum-edge/blob/c764084b3b51c3f7ffde268c039688d35e49c553/src/proxy/mod.rs#L7384
[content-length]: https://github.com/ferrum-edge/ferrum-edge/blob/c764084b3b51c3f7ffde268c039688d35e49c553/src/proxy/mod.rs#L43254
[grpc-bounds]: https://github.com/ferrum-edge/ferrum-edge/blob/c764084b3b51c3f7ffde268c039688d35e49c553/src/proxy/grpc_proxy.rs#L5114
[lifetime]: https://github.com/ferrum-edge/ferrum-edge/blob/c764084b3b51c3f7ffde268c039688d35e49c553/docs/request_lifetime_dispatch.md
[grpc-eof]: https://github.com/ferrum-edge/ferrum-edge/blob/c764084b3b51c3f7ffde268c039688d35e49c553/src/proxy/grpc_proxy.rs#L417
[affinity]: https://github.com/ferrum-edge/ferrum-edge/blob/c764084b3b51c3f7ffde268c039688d35e49c553/src/proxy/frontend_affinity.rs
[h3-reset]: https://github.com/ferrum-edge/ferrum-edge/blob/c764084b3b51c3f7ffde268c039688d35e49c553/src/http3/client.rs#L964
[route-deadline]: https://github.com/ferrum-edge/ferrum-edge/blob/c764084b3b51c3f7ffde268c039688d35e49c553/src/proxy/mod.rs#L53562
[direct-h1]: https://github.com/ferrum-edge/ferrum-edge/blob/c764084b3b51c3f7ffde268c039688d35e49c553/src/proxy/mod.rs#L49659
[h2-write]: https://github.com/ferrum-edge/ferrum-edge/blob/c764084b3b51c3f7ffde268c039688d35e49c553/src/proxy/mod.rs#L59680
[hyper-pipe]: https://github.com/ferrum-edge/ferrum-edge/blob/c764084b3b51c3f7ffde268c039688d35e49c553/vendor/hyper-1.10.0-ferrum-patched/src/proto/h2/mod.rs#L220
[h2-budget]: https://github.com/ferrum-edge/ferrum-edge/blob/c764084b3b51c3f7ffde268c039688d35e49c553/vendor/h2-0.4.19-ferrum-patched/src/proto/streams/counts.rs#L112
[sse]: https://github.com/ferrum-edge/ferrum-edge/blob/c764084b3b51c3f7ffde268c039688d35e49c553/src/plugins/sse.rs#L731
[sse-quality]: https://github.com/ferrum-edge/ferrum-edge/blob/c764084b3b51c3f7ffde268c039688d35e49c553/src/plugins/utils/sse.rs#L2065
[mock]: https://github.com/ferrum-edge/ferrum-edge/blob/c764084b3b51c3f7ffde268c039688d35e49c553/src/plugins/response_mock.rs#L203
[oidc]: https://github.com/ferrum-edge/ferrum-edge/blob/c764084b3b51c3f7ffde268c039688d35e49c553/src/plugins/oidc_relying_party.rs#L1025
[session-secret]: https://github.com/ferrum-edge/ferrum-edge/blob/c764084b3b51c3f7ffde268c039688d35e49c553/src/plugins/utils/session_cookie.rs#L152
[cache]: https://github.com/ferrum-edge/ferrum-edge/blob/c764084b3b51c3f7ffde268c039688d35e49c553/src/plugins/ai_semantic_cache.rs
[redis]: https://github.com/ferrum-edge/ferrum-edge/blob/c764084b3b51c3f7ffde268c039688d35e49c553/src/plugins/utils/redis_rate_limiter.rs
[types]: https://github.com/ferrum-edge/ferrum-edge/blob/c764084b3b51c3f7ffde268c039688d35e49c553/src/config/types.rs#L6258
[tls-source]: https://github.com/ferrum-edge/ferrum-edge/blob/c764084b3b51c3f7ffde268c039688d35e49c553/src/tls/source/mod.rs#L933
[tcp-relay]: https://github.com/ferrum-edge/ferrum-edge/blob/c764084b3b51c3f7ffde268c039688d35e49c553/src/proxy/tcp_proxy.rs#L8484
[conditional]: https://github.com/ferrum-edge/ferrum-edge/blob/c764084b3b51c3f7ffde268c039688d35e49c553/src/admin/conditional_snapshots.rs
[egress]: https://github.com/ferrum-edge/ferrum-edge/blob/c764084b3b51c3f7ffde268c039688d35e49c553/src/admin/backend_egress_policy.rs
[owner-lock]: https://github.com/ferrum-edge/ferrum-edge/blob/c764084b3b51c3f7ffde268c039688d35e49c553/Cargo.lock
[diagnostic-ref]: https://github.com/ferrum-edge/ferrum-edge/blob/c764084b3b51c3f7ffde268c039688d35e49c553/src/diagnostic_ref.rs
[release]: https://github.com/ferrum-edge/ferrum-edge/releases/tag/v0.9.11

[h1-checkout]: https://github.com/ferrum-edge/ferrum-edge/blob/c764084b3b51c3f7ffde268c039688d35e49c553/src/proxy/mod.rs#L49776
