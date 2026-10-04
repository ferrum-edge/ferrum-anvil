# Ferrum Edge 0.9.10 → 0.9.11: source delta and adoption candidate

| Item | Immutable identity / status |
|---|---|
| Baseline | `v0.9.10`, `ee040d5e3281fde424aa65f5b18004852c5b53b0` |
| Audited target | `v0.9.11`, `c764084b3b51c3f7ffde268c039688d35e49c553` |
| Contracts | Published `contracts-edge-0.9.11`, `390edbd5b2485af0988e02f7827fde778d76ae0a` |
| Catalog | [`ferrum-edge-0.9.11/outcomes.json`](../../catalog/ferrum/ferrum-edge-0.9.11/outcomes.json), 553 carried outcome IDs with the delta below |
| Lab selection | `lab/gateway/RELEASE.lock` and `lab/gateway/releases/v0.9.11.lock`; reviewed candidate pending hosted Anvil gates |
| Audit date | 2026-10-04 |

The [immutable comparison][compare] changes 105 files under `src/` (11,369 insertions,
2,060 deletions), plus dependency/vendor, test and documentation changes. This is a separate
source delta audit on top of the [0.9.10 inventory](gateway-0.9.10-delta.md), not a new
comprehensive inventory or a claim of live Anvil compatibility. The historical 0.9.5, 0.9.7,
0.9.8, 0.9.9 and 0.9.10 catalogs and release locks remain available and unchanged.

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

Only static diff inspection and `git diff --check` qualify this Anvil change locally.
Unit schema/parser/catalog checks are future hosted gates and cannot establish live gateway
compatibility. No new lab pass/skip count, native acceptance result or performance measurement
is claimed. Root must qualify the exact pushed Anvil head with hosted CI, native E2E and
real pinned-binary lab evidence before accepting the candidate.

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
Marker-derived findings remain at most likely; absent markers do not establish upstream origin.

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
and completion/uncertainty assertions remain appropriate; live effects await hosted evidence.

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
The PR matrix uses the candidate default; nightly retains all six releases, with 0.9.10 as an
explicit historical selector. Existing loopback profiles, resource counts, configuration key
allowlists, protocol assertions and untrusted-pass/forbidden-claim checks are unchanged.
The new source key/field audit does not replace hosted gateway config validation. Root must
inspect red logs and qualify the exact head, especially direct-H1 reuse/framing, gRPC cancellation,
small-window/write bounds, SSE quality and live G01. In particular, historical UP-018's
reqwest-H1 assertions require 503/backend_error and the specific ceiling body. The new eligible
direct-H1 first attempt uses the pooled 502/connection_failure response; this source-visible
risk needs hosted investigation. The original UP-018 assertions are preserved, with no relaxed
status/body/confidence checks or invented pass. This adoption grants no Anvil release/tag,
available-now status or native signing/OAuth acceptance; human identity/signing gates remain open.
The six separate safety proposals #306–#311 are outside this worktree's assignment.

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
