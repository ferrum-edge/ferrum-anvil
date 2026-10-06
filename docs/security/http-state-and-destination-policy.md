# HTTP state and destination policy

This is the supported policy for retained HTTP cookies, OAuth token acquisition
and redirect destinations. The owner's delegate approved it on 2026-10-06
(PR #308). It changes compatibility in the ways listed under
[Compatibility changes](#compatibility-changes).

It addresses three advisories:

- [GHSA-jq6r-57w6-qp5w](https://github.com/ferrum-edge/ferrum-anvil/security/advisories/GHSA-jq6r-57w6-qp5w):
  unbounded cookie retention and request output.
- [GHSA-8g83-498m-r38r](https://github.com/ferrum-edge/ferrum-anvil/security/advisories/GHSA-8g83-498m-r38r):
  redirects to loopback or private destinations.
- [GHSA-xmww-2phg-v997](https://github.com/ferrum-edge/ferrum-anvil/security/advisories/GHSA-xmww-2phg-v997):
  cleartext OAuth acquisition.

The reports concern a source snapshot based on
`b7aca6f46988dacdaec97f4d2a0af0f8fe238d7e`. That snapshot does not prove that a
distributed 0.1.1 binary, or any other release, is affected. This policy ships
under `[Unreleased]`, and no patched release is claimed until one is published.

Several existing protections are unchanged:

- Epoch and generation fences.
- Native purpose controls and token revocation.
- Prepared private-key handling and client identity bindings.
- Stripping of credentials and bodies on cross-origin redirects.

## Cookies

| Scope | Limit |
|---|---:|
| One incoming `Set-Cookie` value, checked before parsing, redaction or copying | 4,096 bytes |
| One retained cookie, including accounted metadata | 8,192 bytes |
| One registrable site (ICANN and private PSL entries) | 180 live cookies / 128 KiB accounted |
| One workspace isolation | 3,000 live cookies / 2 MiB accounted |
| All outgoing `Cookie` field values together, including configured cookies | 8,192 bytes |

The count and size limits follow common browser cookie budgets. They are fixed
constants. The renderer cannot raise them.

### What is counted

Accounting charges four things for each cookie:

- its serialized backing string, which includes the name and value;
- the parsed domain and the effective path;
- the site key;
- a fixed per-entry size.

Cookies live in one flat, bounded vector, so there are no empty buckets and no
tombstones. The accounted bytes are not a ceiling on process memory: vector
capacity, allocator overhead and short-lived selection buffers are not counted.

### Expiry and eviction

- Expired cookies are removed on every insert and every header read, before
  quotas are checked. An expired replacement deletes its cookie immediately.
- An idle jar has no timer. It is purged on its next access, or cleared by a
  lock or a workspace delete.
- A cookie is replaced when its `(domain, path, name)` matches an existing one,
  as in `cookie_store`. The replacement keeps the creation order and refreshes
  its recency.
- When a site is over its limit, its least recently used cookie is evicted.
  Ties go to creation order.
- When the workspace is over its limit, the cookie is evicted from the site with
  the most accounted bytes (then the most cookies, then by site name). That
  site's least recently used cookie goes. This way one large site cannot push
  out small sites first.

### Outgoing `Cookie` header

- Stored cookies are sorted by path length (longest first), then by creation
  order.
- A stored pair is sent only if the whole pair fits in the 8 KiB budget,
  including its separators. A total of exactly 8,192 bytes fits.
- Configured cookies win over stored cookies with the same name.
- The final merge counts every configured `Cookie` field. Configured fields and
  stored pairs that do not fit are withheld as a whole, never truncated.
- The note about the budget contains no cookie material.

The budget is checked after signing, wherever a request is sent:

- every HTTP attempt;
- the first SSE send, the TCP fallback and every SSE reconnection;
- gRPC reflection requests and reflected calls;
- MASQUE CONNECT-UDP, after CONNECT auth and before the HTTP/3 tunnel is built.

The check applies whether the cookie jar is on or off. A JWT aimed at `Cookie`
cannot bring back a field that was withheld at first, even when its time claims
change.

### Domain and path rules

Domain, path, `Secure`, `HttpOnly` and expiry parsing and matching are done by
`cookie_store` 0.22.1. The pinned PSL includes private suffixes such as
`github.io`.

For an unknown suffix, cookies are host-only: a `Domain` attribute is accepted
only when it equals the request host, and is never shared with sibling hosts.
URL host or path metadata that is too large is refused before the cookie is
parsed.

Jar reads and writes go through the shared `CookieJars` mutex. The epoch and the
per-isolation generation are checked under that mutex before a cookie is kept, so
a lock or a workspace delete cannot bring cookies back.

## OAuth token endpoints

### The rule

A token request goes to one of two kinds of endpoint:

- an HTTPS endpoint;
- a plain HTTP endpoint whose host is a **literal loopback address**, sent over
  a **direct connection**.

The rule covers every grant: client credentials, authorization code with PKCE,
and refresh token.

Literal loopback addresses include IPv4 loopback, `::1` and IPv4-mapped IPv6
loopback, after URL canonicalization (so a short form like `127.1` counts).

These never qualify for cleartext:

- **DNS names.** This includes `localhost`, `localhost.`, and names that a DNS
  override points at loopback.
- **A proxied route.** When the request's selected proxy profile would carry the
  token request, a literal-loopback HTTP endpoint is refused. This applies to
  HTTP, SOCKS5 and HBONE proxies alike. The proxy would receive the client
  secret, refresh token, or code and PKCE verifier in cleartext, and would
  deliver them to *its own* loopback.
  - The proxy's `NO_PROXY` list can bypass the endpoint. In a load plan whose
    token endpoint port changes per run, only a port-free `NO_PROXY` entry
    counts.
  - A selected proxy profile that no longer exists counts as a proxy.

There is no insecure override.

### Where it is checked

The rule is checked at each of these points, and always before any credential is
read:

1. Once the token URL's templates are resolved, before the client ID, the client
   secret or any vault reference is resolved. This applies to sends, sessions,
   previews, recorded gateway lookups and the interactive sign-in.
2. Again at acquisition and at code redemption.
3. Again in the shared `EngineTokenHttp` sink, before the form or Basic
   authorization is built. The sink also refuses any HTTP plan that its actual
   proxy selection would route through a proxy.

Errors never quote the endpoint or any credential.

### Load runs and the desktop app

- **App load preflight.** It applies the same predicate, through the same engine
  function, to the resolved token endpoint. This happens before the API URL,
  headers or mixed auth are resolved.
- **Load producer.** It checks every plan request before exporting any secret or
  variable. Per-run values (dataset cells, extracted values, dynamic helpers)
  cannot authorize a token endpoint's origin. A per-run port is allowed only
  after a fixed literal-loopback host.
- **Load worker.** It checks the actual endpoint again at acquisition.
- **Credential prefetch.** When the App builds a context, it prefetches OAuth
  credentials only for a fixed endpoint that passes the full rule, including
  the direct-route check. Otherwise vault-backed variables keep their references
  and are resolved on use, after the endpoint check.
- **No silent stand-ins.** A resolver created without the context's secrets
  cannot read a deferred vault variable. Instead of substituting an empty
  string, it fails with a clear error. Load-plan classification then refuses a
  plan whose unit depends on such a URL (`IncompleteRequest`), rather than
  judging it from a stand-in.
- **Browser sign-in.** Token status and browser sign-in return the same generic
  configuration error before a browser opens or the issuer is contacted. The
  desktop auth editor shows a rejected status as unavailable, with the reason.
- **Authorization URL.** The URL the external browser opens is governed by the
  browser, not by this rule. Client DNS overrides cannot prove it local.

HTTPS does not remove other risks:

- configured exceptions to TLS verification;
- trust in a private CA or an intercepting proxy;
- routing and NAT;
- a malicious issuer.

Token requests do not follow issuer redirects.

## Destinations and redirects

### Pinning

Each engine HTTP execution has one `DestinationPolicy`. It is shared across:

- redirects and retries;
- the internal resend of an unsent pooled request;
- HTTP/3 and the TCP fallback.

For every attempt, the transport does the following before pool checkout, TLS,
early data or dispatch:

1. Resolve the host once, with the configured resolver or a fixed override.
2. Validate the whole answer.
3. Pin exactly that answer into the attempt's DNS configuration.

The connector's later lookup reads the pinned answer and makes no second network
query. TCP races only the pinned addresses, and QUIC picks only from them.
Host, SNI and certificate identity remain the original host name.

The TCP and HTTP/3 pool keys include the pinned answer, so neither another
execution's connection nor a connection from an older answer can serve the
attempt. Each address set is sorted and deduplicated for the key, so a
round-robin resolver that rotates a stable set keeps reusing connections. The
dial order is unchanged.

The cost is one resolution per attempt:

- `System`: a `getaddrinfo` call on a blocking thread.
- `Custom`: a DNS query.

This applies to load-test iterations too. Answer sets that genuinely change
reduce connection reuse.

### Network zones

| Zone | Addresses |
|---|---|
| Loopback | `127.0.0.0/8`, `::1` |
| Private | RFC 1918, IPv6 ULA `fc00::/7` |
| Link-local | `169.254.0.0/16`, `fe80::/10` |
| Shared | `100.64.0.0/10` (carrier-grade NAT, Tailscale) |
| Benchmark | `198.18.0.0/15` (fake-IP TUN proxies) |
| Public | Global unicast that is not listed below |

- IPv4-mapped IPv6 addresses are classified by their IPv4 address.
- Addresses under the well-known NAT64 prefix `64:ff9b::/96` are classified by
  their embedded IPv4 address.

These are refused even for an original request:

- multicast and unspecified addresses (including `0.0.0.0`);
- IPv4 reserved and documentation ranges;
- IPv6 reserved, site-local and documentation ranges;
- local-use NAT64 and other translation prefixes;
- 6to4, Teredo and ISATAP forms.

### Authority

**The original request.** Every address in its answer must belong to a zone. The
zones do not have to match: the original request is authorized for exactly the
set of zones its answer contains, and that exact answer is pinned. So these
first requests work:

| Setup | Answer |
|---|---|
| Tailscale MagicDNS | `100.x` plus `fd7a:115c:a1e0::/48` |
| mDNS `.local` | `192.168.x` plus `fe80::` |
| DNS64/NAT64 | `64:ff9b::/96` |
| Fake-IP TUN proxy | `198.18.x` |

**Retries and fallbacks of the original request.** They stay within the
original zones, or go to public addresses.

**Redirects.** Each hop is checked against the original request:

- A hop is either wholly public, or wholly within the original request's
  non-public zones. A redirect answer that mixes public and non-public zones is
  refused.
- **Taint.** Once any hop can reach a public address, every later hop must be
  wholly public. This includes an original answer that contains a public
  address. So a public server cannot bounce the chain back to loopback, private,
  link-local, shared or benchmark addresses.
- A public original never gains any non-public authority.

| Original answer | Later direct redirect hops |
|---|---|
| Public (any public address) | Public only |
| Non-public zones Z | Zones within Z, or public; after a public hop, public only |
| Through a proxy (resolved remotely) | No automatic redirect |

This is an address-class boundary. It does not authorize a particular subnet or
server. A private original can delegate within its zones across subnets, and a
loopback original can delegate to other local services. Credential stripping and
the refusal of secret bodies still apply.

### Proxies

A proxy resolves the destination itself, so the client cannot verify the
destination IP. That covers:

- HTTP absolute-form and HTTP/2 authority routing;
- HTTPS CONNECT;
- SOCKS5;
- HBONE.

So **every redirect routed through a proxy is refused** before the client
connects to the proxy for that hop, including same-host HTTP-to-HTTPS redirects.

- An original proxied request is still supported. It grants no authority that a
  later direct `NO_PROXY` hop could use.
- A direct original cannot redirect into a proxy route.
- Known invalid original IP literals are refused even through a proxy.

A refused hop is recorded as `UnsupportedCombination` with `NotDispatched`. The
preceding 3xx stays in the attempt evidence.

## Compatibility changes

These changes are **breaking**:

- **Cookies.** Eviction and output omission can end sessions or change load
  results. Cookies with an unknown suffix are host-only, so custom internal
  domains no longer share cookies across sibling hosts.
- **OAuth.**
  - A cleartext token endpoint must be a literal loopback address on a direct
    connection.
  - `localhost`, DNS names, DNS overrides and proxied routes no longer qualify
    for HTTP.
  - A load plan whose unit depends on a vault variable deferred for OAuth (for
    example, a gRPC or UDP URL) is refused before traffic.
- **Redirects and destinations.**
  - Redirects through any proxy are refused.
  - Redirects that mix public and non-public answers, or that return to a
    non-public zone after a public hop, are refused.
  - Original requests to special or reserved addresses are refused. This
    includes `0.0.0.0` development targets, documentation ranges and
    translation prefixes other than the well-known NAT64 prefix.
- **Link-local IPv6.** A pinned `fe80::` address carries no interface scope, so
  dual-stack mDNS hosts are reached over their IPv4 address.

## Verification

Unit and integration tests cover the following:

- **Cookies:**
  - count and byte limits, and metadata charges;
  - expiry and replacement;
  - deterministic LRU ties;
  - PSL, private and unknown suffixes;
  - output ordering and exact budget equality;
  - configured-cookie precedence;
  - retention after a lock or delete;
  - real HTTP, SSE, gRPC-reflection and MASQUE budgets.
- **OAuth:**
  - endpoint-first ordering for every grant;
  - mapped loopback;
  - the form and Basic sink;
  - proxied literal-loopback refusal with a fixture proxy that receives nothing,
    and a direct `NO_PROXY` control;
  - App preflight refusal and prefetch gating;
  - the deferred-vault fail-closed path.
- **Destinations:**
  - zone classes, including NAT64 and fake-IP;
  - mixed-zone originals (Tailscale-like and mDNS-like);
  - refusal of mixed public/non-public redirects and of the public bounce back to
    loopback;
  - override and cached-connection bypasses refused before checkout;
  - every proxy mode;
  - QUIC refusal and cancellation/deadline boundaries;
  - a real custom-DNS rebinding test that proves the dial uses the validated
    answer;
  - pooled reuse across a rotated answer set.

The QUIC dependency (`quinn-proto` 0.11.19) disables client migration, and
server preferred-address handling does not dial a new address. Recheck this on
any QUIC dependency upgrade.
