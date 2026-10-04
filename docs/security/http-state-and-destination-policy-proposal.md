# HTTP state and destination policy — reviewable draft

Status: candidate only, owner unapproved. This branch changes the supported HTTP
profile and security tradeoffs. It must not be merged, activated, represented as an
approved release profile, or used to close the advisories until root completes its
review and fresh exact-head hosted qualification of the final documentation
commit, and then obtains the owner's explicit decision. Root and independent
security/concurrency reviews of the code candidate are complete.
Candidate preparation was authorized; adopting these defaults was not.

The candidate now implements the core, App preflight, target-API sign-in/status
and desktop guidance contract described below. Implementation is not runtime
qualification or owner approval. Cookie eviction/output omission, unknown-suffix
domain behavior, intentional private-original authority, original proxy trust,
proxy redirect refusal and HTTP issuer restrictions remain DRAFT and OWNER
UNAPPROVED. No scope approval is inferred from fixing the accepted findings.

## Source and finding scope

The inspected base and remote main on preparation were
`4254ea84c101bdc9231a4c6f455421e22468d0ec`. The draft addresses:

- [GHSA-jq6r-57w6-qp5w](https://github.com/ferrum-edge/ferrum-anvil/security/advisories/GHSA-jq6r-57w6-qp5w): cumulative cookie retention and request output.
- [GHSA-8g83-498m-r38r](https://github.com/ferrum-edge/ferrum-anvil/security/advisories/GHSA-8g83-498m-r38r): resolved redirect destinations.
- [GHSA-xmww-2phg-v997](https://github.com/ferrum-edge/ferrum-anvil/security/advisories/GHSA-xmww-2phg-v997): cleartext OAuth acquisition.

All three reports concern a source snapshot based on
`b7aca6f46988dacdaec97f4d2a0af0f8fe238d7e`. That report is not proof that a
distributed 0.1.1 binary or any other released version is affected. This candidate
does not establish an affected or patched release range.

Current main still retained an unbounded `CookieStore` per isolation, resolved
OAuth client secrets before endpoint policy, and followed redirects without a
resolved-address authority boundary. Existing epoch/generation fences, native
purpose controls, token revocation, prepared private-key handling, client identity
bindings and cross-origin credential/body stripping are retained.

## Cookie proposal

| Scope | Candidate limit |
|---|---:|
| Incoming Set-Cookie value, before parse/redaction/owned copy | 4,096 bytes |
| One retained cookie, including accounted metadata | 8,192 bytes |
| Registrable site, ICANN and private PSL | 180 live cookies / 128 KiB accounted |
| Workspace isolation | 3,000 live cookies / 2 MiB accounted |
| Final Cookie field values together, including configured cookies | 8,192 bytes |

The item/count choices follow common browser-scale cookie budgets. These are
finite candidate constants, not a renderer-controlled bypass or a claim of a
standards-mandated application limit. Site/isolation byte limits also accommodate
the Rust cookie objects and metadata; they remain tighter than simply multiplying
every count by the maximum value length.

Accounting charges the original serialized cookie backing string, separately
owned parsed domain and effective path, site key, and fixed `Entry` size. Name and
value are already included in the backing string; there are no duplicated map
keys. Fixed-size ordering stamps live only with their cookie. A flat bounded
vector avoids empty path/domain buckets and LRU tombstones. Vector capacity,
allocator overhead and bounded temporary selection/accounting collections mean
the accounted byte ceiling is not a process RSS ceiling. There is no lifetime
memory benchmark claim.

Expired entries are physically purged on every insertion and header access,
before quota calculations. An expired incoming replacement deletes its tuple
immediately. No expired-cookie tombstone remains after an operation; an idle jar
has no timer and is purged on its next access or cleared by lock/delete. Replacement
uses `(canonical domain, effective path, name)` as cookie_store does, preserving
creation order and refreshing recency without charging an extra live cookie.
Within a site, eviction uses least recent access then creation order. At an
isolation limit, it evicts from the site with the most accounted bytes, then count,
then lexical site tie-break, and chooses that site's LRU cookie. This prevents
one large site's retained state from displacing small sites first; many sites
still encounter the isolation ceiling.

Header serialization sorts by descending path length then creation order. It
counts complete name/value pairs and separators before reserving the jar output,
includes equality at 8,192, and skips whole pairs that cannot fit. Configured
cookies retain precedence over stored cookies with the same name. The final
merge separately counts all configured Cookie values and separators, withholding
over-budget configured fields and stored pairs before combined allocation. Budget
notes contain no cookie material. Existing header validation, request redaction
and refusal of response cookie names containing request secrets remain in force.

The aggregate check runs after every HTTP attempt's signing and after session
signing, including the initial SSE send, TCP fallback, every SSE reconnection,
gRPC reflection requests and reflected calls. A JWT targeting Cookie cannot
restore an initially withheld field when its time claims change. Session records
retain a generic budget reason without the token or cookie value. MASQUE applies
the same aggregate check after CONNECT auth and before constructing the HTTP/3
tunnel wire plan, including configured fields when automatic cookies are off.

Domain, path, Secure, HttpOnly and expiry parsing/matching still use cookie_store.
The pinned PSL still includes private suffixes such as github.io. Unknown suffixes
are now host-only: a Domain attribute is accepted only when it equals the request
host, and never delegates to sibling hosts. Oversized inherited URL host/path
metadata is refused before cookie parsing too. This can change custom internal
domain sharing and cookies on exceptionally long request paths. Eviction and
output omission can end sessions or alter load workloads; owners must review
these compatibility changes.

Static published-source inspection verified `cookie_store` 0.22.1's parse,
domain/path matching, Max-Age precedence, same-tuple update/expiry and removal
semantics. Its insertion marks an expired replacement expired rather than
physically removing it; this implementation instead stores parsed cookies in the
bounded flat collection and removes expired tuples. Downloaded crate SHA-256s
matched Cargo.lock:

```text
cookie_store 0.22.1 15b2c103cf610ec6cae3da84a766285b42fd16aad564758459e6ecf128c75206
cookie 0.18.2       1a373e3602691c3cdea496d2f0ee5935151e6168fe87739483c463db1b2f2f87
psl 2.1.238        2e6aa2cd4e8e062e78ac5d7df6206e2f8e39b624f658efd6f34f9aa1928ac5da
quinn-proto 0.11.18 a9746dbde176634f4f2f1faf2404e30a31b2bc1e9cafb5329c95d8177a18c9fc
```

Jar reads and writes still linearize under `CookieJars`' existing shared mutex.
The existing epoch and per-isolation generation are checked under that mutex
before retention. Session tasks still clone this same jar handle. Neither quotas
nor ordering state can recreate cookies across a lock or workspace deletion.

## OAuth proposal

Resolve the effective token URL's templates first, then require HTTPS or a
literal loopback HTTP address before resolving client ID/secret templates or
vault references. Repeat the check at acquisition, code redemption and the common
`EngineTokenHttp` sink before form serialization, Basic authorization construction,
TLS/proxy secret preparation or dispatch. Client credentials, refresh tokens,
authorization codes and PKCE use that same boundary. Errors do not quote the
endpoint or credential material.

For OAuth execution contexts, vault-backed variables retain their references
until the effective OAuth endpoint has been checked. The normal recursive
resolver still applies layer precedence, nesting and cycle detection; unrelated
ordinary requests retain their frozen variable values. A fixed eligible endpoint
can prefetch credential and variable outcomes after its literal check. A templated
or ineligible endpoint defers all credential aliases, including mixed-auth and
selected-profile references, so headers or other request fields cannot bypass
the endpoint-first order. Credential and variable lookup failures are sanitized
before App errors, browser flow events, history or worker IPC are constructed.

The load producer repeats eligibility validation before resolving or serializing
any credentials or variables. Acknowledgement does not bypass this check. Dataset,
extraction and dynamic-helper values cannot authorize a per-run issuer origin;
per-run paths and ports after a fixed literal-loopback host retain the existing
preflight rules. The worker repeats the literal policy at actual acquisition.
These ordering repairs still require fresh independent review and exact-head
Linux, macOS and Windows hosted qualification; they do not qualify the whole
original PR or approve either candidate policy.

IPv4, IPv6 and IPv4-mapped IPv6 loopback literals are accepted after URL
canonicalization (including shortened IPv4 spelling). DNS names, including
localhost and names overridden to loopback, do not qualify for cleartext. HTTPS
and intentional literal-loopback issuers remain supported. No insecure override
is added. App load preflight uses the same public engine predicate for the
resolved token endpoint before client credential expansion or dispatch. Proxy
routing, NO_PROXY and fixed client DNS pins do not make a cleartext DNS-name token
endpoint eligible. Eligible HTTPS endpoints still need remote load consent when
their destination is remote or unproven; literal eligibility is not a promise
that a configured proxy stays on this machine.

Target-API browser token validation uses that same predicate, including mapped
loopback literals. App token status and browser sign-in return the same generic
configuration failure for an ineligible token URL, before opening a browser or
contacting the issuer. The browser observer receives a terminal configuration
failure. The desktop auth editor surfaces rejected status queries as unavailable
with their reason, rather than silently showing an ordinary signed-out status,
and guides users to HTTPS or a loopback IP. The external browser's separate
authorization-URL policy still permits HTTP localhost; client DNS overrides
cannot prove that browser destination local. This candidate's stricter literal
rule governs token acquisition, not application-login provider policy.

Proxy settings remain available for original token acquisition, and requests do
not automatically follow issuer redirects. HTTPS alone does not remove configured
TLS-verification exceptions, private CA or intercepting-proxy trust, plain
proxy-leg trust, routing/NAT or malicious issuer risks. Cache key identity, refresh
rotation, epoch revocation, cancellation and redaction behavior remain unchanged.

## Redirect proposal and transport trace

One `DestinationPolicy` belongs to each engine HTTP execution, shared across
redirects, retries, pooled unsent redispatch, HTTP/3 and TCP fallback. An original
direct target grants the zone of its actual first validated resolution. All
eligible addresses must be permitted and in one zone; a mixed public/private
answer fails before dialing even if Happy Eyeballs would have chosen the public
address. IP-family filtering is the existing resolver's filtering, and every
address that can reach the dial is checked.

The transport checks before pool checkout, TLS/early-data exchange or request
dispatch. It resolves once using the configured system/custom resolver or fixed
override, validates the returned address set and pins that exact set into an
attempt-owned override. The connector's subsequent fixed-resolution operation
does no second network lookup. TCP races only those pinned addresses; QUIC chooses
only from the pinned answer. Both pool keys include the DNS configuration and
pinned answer; another execution's private connection or an older answer cannot
serve a newly public-authorized attempt. The next attempt resolves again and is
checked again, including internal redispatch after an unsent pooled request.
Host/SNI/certificate identity remain the original target host, not the pinned IP.
Static review of locked quinn-proto 0.11.18 found that client connections reject
peer migration (`ConnectionSide::remote_may_migrate` is false for clients); the
server preferred-address handling retains a CID without dialing that address.
The transport does not initiate server-address migration. This dependency
behavior must be rechecked on a QUIC dependency upgrade.

The guard's DNS operation participates in cancellation and the attempt's existing
total and DNS deadlines. Actual validation is recorded as a DNS phase; the
connector records its fixed override/literal phase or connection reuse. Existing
connection and ticket fences and per-isolation keys remain intact.
Resolving before each reuse adds resolver work/latency; changed answer sets can
reduce pool reuse. Stable answers still reuse connections. No performance
benchmark or assertion of unchanged DNS traffic is made.

| Original zone | Allowed subsequent direct zones |
|---|---|
| Public | Public |
| RFC1918 / IPv6 ULA private | Same private class, or public |
| Loopback | Loopback, or public |
| Link-local | Link-local, or public |
| Shared carrier space | Shared carrier space, or public |
| Proxy-resolved, unverifiable | No automatic redirect |

This is an address-class boundary, not subnet or server identity authorization.
An explicit private original may delegate within its private class across
subnets; a loopback original may delegate to other local services. Existing
credential stripping and secret-body refusal still apply. Public origins never
gain private/loopback/link-local/shared authority. Mapped IPv6 addresses are
classified by their IPv4 address. Multicast, unspecified, IPv4 reserved,
documentation and benchmarking ranges, IPv6 reserved/site-local/documentation,
well-known NAT64, 6to4, Teredo and ISATAP transition forms are refused even for an
original target. This deliberately changes invalid/special-address development
targets and mixed-zone DNS compatibility.

Remote-resolution proxy limitations are explicit: HTTP absolute-form and HTTP/2
authority routing, HTTPS CONNECT, SOCKS5 and HBONE do not expose a verifiable
destination IP to this client. This candidate refuses every redirect routed
through them, including same-host HTTP-to-HTTPS, before connecting to the proxy
for that hop. An original proxied request remains supported, but grants opaque
authority; a later NO_PROXY direct hop is also refused. A direct original may
continue through direct NO_PROXY same-zone hops, but cannot redirect into a proxy
route. There is no client-side DNS preflight falsely presented as proof of a
remote proxy's resolution, and no replacement of proxy CONNECT names with IPs
that could silently change virtual-host routing. This is a material supported
profile tradeoff for owner review, not a claim that all proxy requests are SSRF
protected. Known invalid original IP literals are refused; unknown remote-proxy
resolutions cannot be classified and remain explicit original-request trust.

Direct intentional initial HTTP API/development requests and safe direct
same-zone redirects remain supported. A refusal is a typed `UnsupportedCombination`
with `NotDispatched`; the preceding 3xx remains in attempt evidence, and the
refused hop is the final failed attempt. The implementation does not suppress
ordinary redirect statuses, disable all redirect following, alter retry signing,
change TLS policy or grant renderer-controlled network exceptions. Arbitrary
custom translation prefixes, operator routing/VPN/NAT, DNS server trust and
privileged services exposed on public addresses remain outside address-class
proof. Address tables need review as allocation standards evolve.

## Qualification and required root work

Local validation was static only: source/dependency/API review and `git diff
--check`. No repository executable, formatter, build, test, server, container,
hook or project script was run. No workflow was manually dispatched by the
implementer. The root qualification
record below gives the subsequent hosted results; release qualification and
owner approval remain unclaimed.

Added tests exercise per-site/isolation count and byte ceilings, metadata charges,
expiry/removal, same-tuple replacement, deterministic LRU ties, PSL/private and
unknown suffixes, oversized input, path/creation ordering, exact output equality,
configured-cookie precedence/redaction and post-lock/delete retention. Real HTTP
responses fill a jar, a real SSE handshake inserts beyond its site limit, and
redirect/SSE requests verify bounded output. Existing gated session and lock/delete
race regressions remain present. OAuth tests cover the resolved endpoint before
credential template expansion, all grant variants, mapped loopback and the common
form/Basic sink. A new trusted HTTPS issuer test checks real Basic client
acquisition and token delivery; existing real loopback acquisition, refresh, code
redemption and revocation tests continue to supply positive transport coverage.

Additional production-path regressions cover an initially withheld oversized
Cookie JWT with changed time claims on a real SSE reconnection and on a gRPC call
signed after real reflection, alongside under-budget controls. HTTP and SSE cover
automatic jars both on and off. Real MASQUE CONNECT-UDP tests cover configured
and auth-added over-budget fields, good under-budget fields, and several fields
whose individual sizes fit but aggregate does not. Tests check wire ground truth,
generic omission reasons and record redaction without printing credentials.
These tests are included in the successful code-head hosted qualification below.

Destination tests cover literal classes, mapped/transition classes, mixed-record
and override rejection before pool checkout, all proxy modes, QUIC refusal and
cancellation/deadline boundaries. A deterministic UDP DNS server supplies actual
CNAME/A responses, changes public answers to loopback and verifies pinning avoids
a second lookup; the checked next attempt cannot dial the private fixture. The
public authorization is established by consuming the public DNS answer without
opening an internet connection; this is a controlled transport regression, not a
claim of an executed end-to-end public-server exploit. Real loopback engine 307/308
redirects test different-zone refusal and same-zone override positives. Cached
private sockets and safe same-zone reuse have explicit negative/positive controls.

Root obtained the code-head hosted formatting, compilation, clippy and suite
results below, investigated the failures and commissioned fresh independent
security/concurrency reviews of the flat-cookie accounting/eviction semantics,
DNS/CNAME pinning, TCP/QUIC reuse/resend/fallback paths and proxy compatibility.
Fresh final-documentation-head checks remain required before the owner decision. The
repository currently configures rustfmt at 140 columns with Max heuristics; this
assignment requested hand formatting at 100/60. Root must apply the actual hosted
formatter diff as directed during qualification; no local formatter was used.

Completed App and desktop contract work:

- `crates/anvil-app/src/load.rs` shares the token endpoint policy with the engine
  sink. `load_preflight_security.rs` replaces incompatible cleartext-name positives
  with HTTPS proxy authority and literal-loopback HTTP direct controls, and adds
  no-dispatch negatives before missing client credentials. Consent, browser
  locality, proxy authority, native purpose and dynamic-origin proofs remain.
- `crates/anvil-app/src/identity.rs`, its tests and
  `crates/anvil-identity/src/api_oauth.rs` align token status/browser failure and
  mapped-loopback token eligibility. A real mapped-loopback App sign-in control
  complements the existing IPv4 loopback flow; failures check no browser opening,
  no issuer grants and the same secret-free observer/status reason.
- `apps/desktop/src/AuthEditor.tsx` and `ScopeSettings.tsx` expose the token
  restriction, quotas, unknown-suffix rules, special-address refusal and proxy
  redirect tradeoffs as an owner-unapproved draft. Renderer tests cover workspace
  and folder guidance, status errors, successful status refresh and stale-status
  rejection. No schema change, bypass or new setting is introduced.

Same-head Linux CI evidence from `7fa3505dbbe1111c7f74399dbbb5f639f6d16a36`
([job](https://github.com/ferrum-edge/ferrum-anvil/actions/runs/37201500822/job/111433994603))
passed formatting and clippy but failed the two older App cleartext-name issuer
expectations and `matrix_local_tls::local_010_connect_deadline_does_not_claim_firewall_or_backend`.
The latter used TEST-NET, now rejected before dialing. Its candidate replacement
uses the existing saturated-loopback listener with the same 400 ms connect
deadline, requires an actual ConnectTimeout, retains no-dispatch/diagnostic
assertions and adds an accepting-loopback control. No timeout increase, skip or
policy bypass was added. The subsequent code-head hosted qualification below
includes these repairs.

`CHANGELOG.md` now records this candidate under Unreleased. The owner decision
and a fresh hosted pass on the final documentation commit remain required.

The draft remains owner-unapproved. Root owns further qualification and the
explicit adoption decision; the implementation and code-head evidence establish
neither advisory closure nor approval of the supported behavior changes.

### Root code-head qualification

Root read the entire code change and all repair deltas. Fresh independent
security/concurrency reviews, including the recorded-lookup/native-ordering
review and the final unique-workload-fixture review, found no remaining findings
in their assigned scopes. On code head
`3c1baed5eb83c867bc7a747216b0226535a6d6c2`, all 14 check-runs from GitHub
Actions app 15368 and all three pull-request workflows succeeded:

- [CI 37210938477](https://github.com/ferrum-edge/ferrum-anvil/actions/runs/37210938477):
  formatting, compilation, clippy, source/contract policy and Rust suites on
  Ubuntu 24.04, macOS 15 and Windows 2025.
- [Desktop E2E 37210938502](https://github.com/ferrum-edge/ferrum-anvil/actions/runs/37210938502):
  ten native Tauri spec files passed on each of the three operating systems.
- [Lab 37210938583](https://github.com/ferrum-edge/ferrum-anvil/actions/runs/37210938583):
  Ubuntu and macOS lab qualification passed.

Root inspected actual logs for the bounded cookie accounting/output, resolved
OAuth endpoint and credential preflight, destination classes, cached-connection
controls, real DNS answer pinning and native E2E results. The UUIDv7 fixture repair
uses the random/counter suffix rather than the shared millisecond prefix; it fixes
the demonstrated parallel socket/pipe collision without rerunning an identical
failed tree. The standard Windows Rust job does not execute desktop library unit
tests; native Windows E2E does execute the app. These results establish the
recorded candidate's hosted coverage, not physical OS-provider acceptance,
renderer-independent native network consent, a memory/RSS benchmark, an
authenticated diagnostic producer, or a patched released binary.

This qualification-only documentation update creates a new head. Root must wait
for all hosted checks on that exact head before presenting the adoption decision.
Owner approval of cookie eviction/omission, issuer restrictions, address classes
and proxy redirect compatibility remains required. None of the three advisories
is closed by this qualification record.
