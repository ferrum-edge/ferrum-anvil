# Gateway failure lab: `auth` and `tls` profiles

These two profiles drive the **real, pinned Ferrum Edge v0.9.5 release binary**
(`lab/gateway/RELEASE.lock`) with controllable fixtures and check what Anvil's
shared engine concludes from the public evidence alone. Nothing is faked: no
injected headers, no injected failure enums, no fixture pretending to be the
gateway. Every result records the gateway release, source SHA, binary sha256
and platform.

Three kinds of evidence are kept apart (build plan §15.1):

| Kind | Source | Used for |
|---|---|---|
| Public evidence | What Anvil observes as a client (typed TLS/DTLS evidence, status, headers, body) | The only input to the diagnostic engine |
| Operator ground truth | The gateway's own logs: stdout transaction lines (`proxy_id`, `error_class`, status) and runtime WARN lines (for example `Frontend TLS handshake failed … peer sent no certificates`) | `GroundTruth` checks only; never given to the engine |
| Fixture ground truth | Echo/TLS/IdP/LDAP fixture logs (request received, handshake completed/failed, client-certificate CN, bind accepted/rejected) | `GroundTruth` checks only |

Each scenario asserts the stimulus really happened (ground truth), what Anvil
must and must not conclude (expected finding codes, scope, **maximum**
confidence, forbidden claims), a lookalike where the plan needs one, and a
positive recovery request after the fault is removed.

## Running

```sh
export ANVIL_LAB_FERRUM_BIN=/path/to/ferrum-edge-macos-aarch64   # or lab/bin/<asset>, see gateway.rs::binary()
ulimit -n 4096
cargo run -p anvil-lab -- verify                      # checks the pinned sha256
cargo run -p anvil-lab -- list tls                    # scenario ids (skips included)
cargo run -p anvil-lab -- run tls  --untrusted-pass
cargo run -p anvil-lab -- run auth --untrusted-pass
cargo run -p anvil-lab -- run auth --scenario AUTH-X04   # one scenario
cargo run -p anvil-lab -- up tls                      # keep fixtures + gateways up for manual work
```

Results go to `results/lab/<UTC stamp>-<profile>/` (`summary.json`, one
`<id>.json` per scenario, `<id>.record.json` with the full redacted execution
record, and the archived gateway logs). `--untrusted-pass` repeats every
scenario with the destination **not** configured as a trusted Ferrum profile;
the harness then also asserts that no `ferrum.token*` / `ferrum.outcome*`
finding appears.

**Ids.** A result id is the failure-matrix id (`docs/handoff/FERRUM_ANVIL_FAILURE_MATRIX.json`),
optionally followed by `.<variant>` (for example `TLS-005.tls12`). Ids with an
`X` (`TLS-X01`, `AUTH-X01`…) are lab extensions with no matrix seed; `CTRL-*`
are positive controls. The matrix id is always the part before the first `.`.

**Hygiene.** Everything binds 127.0.0.1. Certificates (`anvil_fixtures::gateway_pki`)
and all credentials (API keys, JWT/HMAC secrets, passwords, OAuth client
secret, IdP signing keys) are generated fresh per run under `lab/.run/`
(git-ignored), never committed and never added to any trust store. CA
private keys are never written to disk. Each run starts and stops its own
gateway processes; afterwards `pgrep -fl ferrum-edge` shows none from the run.

## Topology and ports

| Profile | Gateway listeners | Fixtures |
|---|---|---|
| `tls` | instance A (`tls.conf`/`tls.yaml`): HTTP 18380, HTTPS 18343 (client certificate **mandatory**, TLS 1.2–1.3), admin 18390, DTLS 18301/udp (client certificate mandatory), TCP+TLS 18302 (same). Instance B (`tls.tls12.conf`/`tls.tls12.yaml`): HTTPS 18344 (mTLS, **TLS 1.2 only**), admin 18391 | 19301 TLS backend (trusted), 19302 self-signed, 19303 wrong name, 19304 TLS 1.3 requiring a client certificate, 19305 the same on TLS 1.2, 19306 accepts TCP and never answers the ClientHello, 19307 plaintext HTTP, 19308 TLS (for the plaintext-to-TLS case), 19309 echo, 19310 UDP echo, 19311 TCP echo, 19312 expired backend certificate, 19313 JWKS of the lab issuer (AUTH-026). All backend TLS fixtures offer only `http/1.1` so the gateway's startup capability probe keeps every route on the audited reqwest HTTP/1 path. |
| `auth` | HTTP 18180, admin 18190 | 19101 echo, 19102 identity provider (JWKS, RFC 7662 introspection, client-credentials and authorization-code token endpoint, OIDC discovery, login page), 19103 second JWKS host (switched off mid-run), 19106 LDAP directory; 19104 and 19107 deliberately unbound |

The second tls instance exists because `FERRUM_TLS_MAX_VERSION` is
process-wide: the TLS-1.2 refusal shape and the version-mismatch scenario
need a listener that stops at TLS 1.2, while the main instance must keep TLS
1.3. Both instances stay inside the tls port block.

The auth profile's identity provider is the lab itself: it owns the ES256
issuer key, publishes the JWKS and mints issuer tokens the way a real IdP
would. Anvil never mints issuer tokens; scenarios hand them to it as a
bearer/DPoP access token, as a user would. The LDAP fixture implements the
simple-bind + base-search flow `ldap_auth` uses (bounded BER, no password
logging); it verifies adapter behaviour, not any real directory.

**Signed SOAP fixtures (AUTH-030/031).** Anvil does not sign XML: X.509
XML signing is unavailable in Anvil (the WS-Security auth profile offers
UsernameToken and embeds a *user-supplied* SAML assertion verbatim; a
pre-signed envelope is sent as the request body, byte for byte). For these
scenarios the lab plays the external signer and the SAML identity provider,
with audited tools already on the host and never a hand-written
canonicalizer: libxml2's Exclusive XML Canonicalization (`xmllint
--exc-c14n`, the implementation xmlsec1 also uses) and OpenSSL RSA-SHA256.
Throwaway RSA-2048 keys and self-signed certificates are generated per run
under `lab/.run/auth/soap/` and trusted only by the lab gateway's routes. Each
signed element is canonicalized in a standalone form declaring exactly the
namespaces it visibly uses, so it equals the in-context exclusive canonical
form; the gateway's own, independent canonicalizer accepting the result is
the cross-check. `xmlsec1` is not installed on this host and was not
downloaded. Without `xmllint`, AUTH-030/031 are reported as skipped with that
reason; `openssl` is required to start the auth profile at all (the gateway
config references the certificates).

## `tls` scenarios

Frontend (client ↔ gateway). Anvil's findings here come from its own typed
TLS/DTLS evidence; the gateway log confirms what the gateway saw.

| Id | Matrix | Stimulus | What passing proves |
|---|---|---|---|
| TLS-008 | TLS-008 | Correct root, name and client certificate on 18343 | 200 through the gateway; the gateway's certificate request, the verified chain and the presented identity (subject only) are recorded; the private key never appears in the record |
| TLS-008.tls12 | TLS-008 | Same on the TLS-1.2-only listener | TLS 1.2 negotiated end to end |
| TLS-001 | TLS-001 | Client trusts only a rogue root | `client.tls.untrusted_issuer` confirmed, client-to-peer; no HTTP status, no gateway/upstream attribution, no bypass advice; gateway log shows Anvil's `UnknownCA` alert; backend untouched |
| TLS-002 | TLS-002 | URL host not in the gateway certificate (DNS override to 127.0.0.1) | `client.tls.name_mismatch` confirmed; nothing about tokens/auth; gateway logs `BadCertificate` |
| TLS-005 | TLS-005 | No client certificate, TLS 1.3 | `client.tls.client_cert_required` (confirmed from the `certificate_required` alert); refusal shape is *after* the client's handshake (`tls_alert_after_handshake`) — or, when the gateway's reset discards the alert, a close before any response explained as `client.tls.closed_after_certificate_request` (likely); never an HTTP 401; gateway logs `peer sent no certificates` |
| TLS-005.tls12 | TLS-005 | Same, TLS 1.2 | Same finding, but the alert lands *inside* the handshake (`tls_alert_received`) |
| TLS-006 / .tls12 | TLS-006 | Client certificate from a rogue CA | `client.tls.client_cert_rejected` capped at **likely** (alert `unknown_ca`), with the alternatives listed — **unknown** when the TLS 1.3 alert was lost; not "client certificate required"; no claim about the gateway's backend certificate; gateway logs `UnknownIssuer` |
| TLS-006.lookalike | TLS-006 | Valid chain, but `mtls_auth` maps no consumer to the CN | An HTTP 401 with a verified, completed handshake: no `client.tls.*` finding; recovery with the mapped identity |
| TLS-007 | TLS-007 | Certificate with an unrelated private key | `local.client_identity_key_mismatch`; the failure is local — no connection attempted |
| TLS-009 | TLS-009 | `https://` to the plaintext listener 18380 | `client.tls.not_tls` (likely); never "expired"; recovery over `http://` |
| TLS-X01 | — | Client requires TLS 1.3, listener allows only 1.2 | `client.tls.version_mismatch` confirmed (alert `protocol_version`); gateway logs `Tls12NotOfferedOrEnabled` |
| TLS-013 | TLS-013 | Private CA in workspace A only | A succeeds, B fails trust validation, A still succeeds (profile-scoped trust) |
| TLS-014 | TLS-014 | Workspace A authenticates with a client certificate; B (and A with another profile) send without one | B and A-without-identity get their own connections and are refused — no reuse of A's authenticated connection |
| TLS-015 | TLS-015 | Verification disabled for one request | Succeeds with the insecure-TLS warning and `client.tls.verification_bypassed`, which still records that strict verification would have failed (untrusted issuer); the next strict request fails and carries no warning; no finding ever recommends disabling verification |
| TLS-016 | TLS-016 | Plaintext HTTP vs HTTPS with verification off | Plaintext has no TLS session and no insecure-TLS warning; the bypass has both |
| AUTH-026 | AUTH-026 | `jwks_auth` with `require_mtls_binding`: a token bound (`cnf.x5t#S256`) to `client-good` presented over a connection authenticated with another valid certificate → 401 `mTLS binding mismatch` | An HTTP 401 with a completed handshake: no `client.tls.*` finding, gateway outcome ≤ likely, no "change the bearer prefix" advice, token not recorded; a token bound to the presented certificate succeeds |
| TLS-008.tcp | TLS-008 | TCP+TLS listener with the right identity | Payload echoed through the gateway to the TCP backend |
| TLS-005.tcp | TLS-005 | TCP+TLS listener without identity | `client.tls.client_cert_required`; no echoed data; the TCP backend is never dialled |
| PROTO-022 | PROTO-022 | DTLS listener with the right identity | Datagram echoed via the gateway (DTLS 1.3 negotiated) |
| PROTO-022.nocert / .rogue | PROTO-022 | DTLS without a configured identity (Anvil presents an ephemeral self-signed one) / with a rogue identity | `dtls.closed_without_response` (the gateway sends close_notify after the handshake), not `udp.no_response`; no datagram reached the backend; gateway logs `DTLS client certificate verification failed` |
| PROTO-022.root | PROTO-022 | Client trusts the wrong root | Anvil aborts the DTLS handshake itself: `client.tls.untrusted_issuer` confirmed |

Gateway to backend (through the plaintext listener; the client leg is fine).
The only public signal is the coarse token, so no scenario may claim TLS.

| Id | Matrix | Stimulus | Observed on 0.9.5 (operator `error_class`) | What passing proves |
|---|---|---|---|---|
| CTRL-UP-TLS | — | Trusted backend | 200 | Positive control; the backend completed TLS with the gateway |
| UP-004 | UP-004 | Self-signed backend | 502 `connection_failure` (`tls_error`) | `ferrum.token.connection_failure` ≤ likely, gateway-to-upstream; no confirmed TLS/certificate claim; Anvil's own client identity is never blamed; the backend fixture saw the handshake fail |
| UP-004.expired | UP-004 | Expired backend certificate | same | same |
| UP-005 | UP-005 | Backend certificate for another name | same | same |
| UP-006 | UP-006 | TLS 1.3 backend requires a client certificate, gateway has none | 502 `backend_error` (`connection_reset`) — the post-connect-alert path | Accepts either documented token; recovery route presents the gateway's backend identity and the backend logs its CN (`anvil-lab-gateway-backend-client`, identity #3, not Anvil's) |
| UP-006.tls12 | UP-006 | Same on TLS 1.2 | 502 `connection_failure` (`tls_error`) | as UP-006 |
| UP-007 | UP-007 | Backend never answers the ClientHello (1 s connect budget) | 502 `connection_failure` (`connection_timeout`) | No confirmed timeout/TLS claim; no frontend-TLS finding |
| UP-008 | UP-008 | Gateway speaks TLS to plaintext | 502 `connection_failure` (`tls_error`) | Never "expired certificate" |
| UP-008.http-to-tls | UP-008 | Gateway speaks plaintext to TLS | 502 `backend_error` (`request_error`) | as above |
| UP-016 | UP-016 | UP-006 route five times | every run so far: `connection_reset` → `backend_error` | Every public token matches the operator-side class mapping (pool cancellation ↔ `connection_failure`, reset ↔ `backend_error`); never a confirmed TLS claim |

## `auth` scenarios

Gateway authentication rejections carry **no** `X-Gateway-Error`; the only
gateway-specific public signal is the body literal (plus `WWW-Authenticate`
on some), which a backend can reproduce. With a trusted plain-HTTP profile the
engine may therefore say "likely a gateway <plugin> outcome" and no more.
Challenge headers are checked with a separate raw probe because execution
records redact `WWW-Authenticate`.

| Id | Matrix | Stimulus → gateway signal | What passing proves |
|---|---|---|---|
| CTRL-AUTH | — | Valid API key → 200 | `hide_credentials`: the backend never saw the key; the key is not in the record |
| AUTH-001 | AUTH-001 | Right key under `X-API-Key` → 401 `Authentication required` + `WWW-Authenticate: ferrum-edge`; wrong key → 401 `Invalid API key` | Generic 401 plus a gateway-outcome claim capped at likely (ambiguous where several gateway paths share the body); the key never appears in the record; recovery |
| AUTH-002 | AUTH-002 | Key in the query string | The attempt URL keeps `api_key=` but redacts the value |
| AUTH-003 | AUTH-003 | Wrong Basic password → 401 `Invalid credentials` + `Basic realm="ferrum-edge"` | Ambiguous with hmac_auth's identical body (unknown); no TLS claim; password not recorded |
| AUTH-004 | AUTH-004 | Expired HS256 bearer → 401 `Invalid JWT token` | Local `auth.token_expired_locally` (likely, local-client, "decoded, not verified") kept separate from the server verdict |
| AUTH-005 | AUTH-005 | `nbf` in the future → same 401 | `auth.token_not_yet_valid_locally`; no confirmed clock claim |
| AUTH-006 | AUTH-006 | Signed with the wrong secret → same 401 | No local signature verdict at all (Anvil holds no key) |
| AUTH-007 | AUTH-007 | Only `sub` → `JWT missing identity claim`; unknown consumer → `Invalid JWT token` | Profile mismatch vs unknown identity are distinct signals; recovery with Anvil's JWT helper |
| AUTH-008 | AUTH-008 | ES256 token from an unpublished key → 401 `Invalid or unrecognized JWT` | Likely at most; nothing "malicious"; the gateway re-fetches the JWKS on the unknown kid |
| AUTH-009 | AUTH-009 | Wrong `iss`, wrong `aud` → same 401 | Never suggests disabling audience/issuer validation |
| AUTH-010 | AUTH-010 | `alg: none` on jwt_auth, HS256 and `alg: none` on jwks_auth → 401 | No claim that anything was verified |
| AUTH-X03 | — | JWKS host switched off, cached keys expire after `jwks_max_stale_seconds` (2 s) → a **valid** token gets the same 401 | The IdP-dependency explanation stays open; no confirmed "invalid" or "unavailable"; ground truth: the gateway's refreshes hit the outage and the same token works again after recovery |
| AUTH-015 | AUTH-015 | OAuth token endpoint returns 503 | `local.auth_preparation_failed`: nothing sent, no HTTP finding; the gateway and backend never saw a request |
| AUTH-016 | AUTH-016 | Client credentials → opaque token → gateway introspects it → 200 | One token request, gateway introspection at the IdP, cached token reused, client secret not recorded |
| AUTH-X01 | — | Token the IdP says is inactive → 401 `Inactive token` + `Bearer error="invalid_token"` | Credential rejection (401), never "unavailable"; the gateway did ask the IdP |
| AUTH-X02 | — | Introspection endpoint refused (and, as a variant, the IdP answering 503) → 503 `Token introspection unavailable`, no challenge | Dependency failure: 503, never an unauthorized/credential claim; same credential works once the IdP is reachable |
| AUTH-018 | AUTH-018 | Engine-signed `ferrum-hmac-v2` GET and POST | Accepted; one fresh nonce per send; secret not recorded |
| AUTH-018.skew | AUTH-018 | Date header 10 min old → 401 `Missing or expired Date header` | No confirmed clock claim |
| AUTH-019 | AUTH-019 | Body changed after signing → 401 `Digest header does not match request body` | The same edit through Anvil re-signs the final bytes and succeeds |
| AUTH-020 | AUTH-020 | Captured signed request replayed → 200 then 401 `Signed request has already been used` | Anvil's own signer never reuses a nonce (three back-to-back sends accepted) |
| AUTH-021 | AUTH-021 | `a;b=c/x:y@z` path and `b=2&a=1&a=0&empty=&z=%41` query | Accepted; the backend received the raw query byte for byte; a reordered query fails verification |
| AUTH-022 | AUTH-022 | Both `Digest` and `Content-Digest` → 401 `Ambiguous …` | Anvil refuses locally to sign a request that already carries a digest header (nothing sent) |
| AUTH-023 | AUTH-023 | Legacy `ferrum-hmac-v1` without the unsafe opt-in | Refused locally; nothing reaches the gateway |
| AUTH-024 | AUTH-024 | DPoP-bound ES256 token + per-send proof | Accepted; binding facts (jkt/htu/jti) recorded without the key; missing proof → `DPoP proof required`, proof for another URL and proof from an unbound key are rejected |
| AUTH-025 | AUTH-025 | Captured proof replayed → 401 `DPoP replay` | No `DPoP-Nonce` challenge on 0.9.5 and no automatic retry loop; fresh proofs per send accepted |
| AUTH-027 | AUTH-027 | Wrong LDAP password → 401 `LDAP authentication failed` | Directory really rejected the bind; no "unavailable/unreachable" claim |
| AUTH-028 | AUTH-028 | Directory unreachable → 500 `LDAP authentication temporarily unavailable` | Never a password/credential claim; the same credentials work against the reachable directory |
| AUTH-032 | AUTH-032 | Multi-auth: JWT(alice)+key(bob) → 403 `Consumer is not allowed`; bad JWT + key(bob) → 200; key(bob) → 200 | The first successful identity is judged alone (no privilege union); a later valid mechanism wins over an earlier rejection |
| GW-011 | GW-011 | alice's key on an ACL route → 403 `Consumer is not allowed` | Authorization category, never "invalid password", never WAF |
| AUTH-X04 | — | Valid gateway key; the **backend** answers 401 `{"error":"Invalid API key"}` (byte-identical to key_auth) | Not attributed to the gateway: `ferrum.relayed_backend_response` (likely, upstream application), no `ferrum.outcome*` |
| AUTH-X05 | — | No auth plugin; the backend answers 401 `Authentication required` + `WWW-Authenticate: ferrum-edge` | Same: the gateway's own fallback challenge, copied by a backend, is not a gateway rejection |
| AUTH-029 | AUTH-029 | `soap_ws_security` PasswordDigest (in-process nonce store, 2 s clock skew): Anvil's WS-Security auth → 200; wrong password → 401 `WS-Security: invalid credentials`; an envelope Anvil's own signer produced, captured and sent twice as raw bytes → 200, then 401 `WS-Security: nonce replay detected` | Anvil sent the captured bytes verbatim (body hash); the replay rejection is a generic 401 plus a gateway-outcome claim ≤ likely; no confirmed claim about the password, signature, expiry or replay; the password never on the wire and never in the record; three fresh Anvil envelopes in a row accepted (fresh nonce and `Created` per send — the load path is covered by `crates/anvil-load/tests/load_wsse.rs`) |
| AUTH-029.text | AUTH-029 | PasswordText with `remove_credential` → 200; the right password sent as PasswordText to the PasswordDigest route → 401 `WS-Security: Password Type does not match the configured password_type` | The backend received the envelope without the password; the profile mismatch is not reported as a wrong password; password not recorded |
| AUTH-029.expired | AUTH-029 | An envelope Anvil generated with a 1 s Timestamp lifetime, sent raw 4 s later → 401 `WS-Security: Timestamp has expired` | Generic 401, no confirmed expiry/clock claim (0.9.5 renders all WS-Security structural rejections as one `{"error":"<message>"}` family, so no gateway outcome is claimed); backend untouched; a fresh envelope recovers |
| AUTH-030 | AUTH-030 | `x509_signature` (RSA-SHA256, exclusive C14N, Body and Timestamp signed): lab-signed envelope → 200; the signed Body altered after signing → 401 `WS-Security: Reference digest mismatch`; a valid signature by an untrusted key → 401 `WS-Security: signing certificate is not trusted` | Anvil sent the signed envelope byte for byte (body hash; the backend received exactly those bytes); a certificate problem inside XML is never reported as a TLS failure (`client.tls.*` absent); no confirmed signature/certificate claim; backend untouched on rejection; a freshly signed envelope recovers |
| AUTH-031 | AUTH-031 | `saml` (+ PasswordDigest UsernameToken): Anvil embeds a lab-issued signed SAML 2.0 bearer assertion verbatim → 200; the same assertion again → 401 `WS-Security: SAML assertion has already been used`; wrong audience, expired, untrusted issuer and untrusted signing certificate → their 401s | The backend received the assertion byte for byte; the assertion's signature never appears in the record; replay gets a gateway outcome ≤ likely, the other rejections a generic 401 with no confirmed SAML claim; a new assertion recovers (a SAML bearer assertion is single-use by design) |
| AUTH-017 | AUTH-017 | `oidc_relying_party` (discovery at the lab IdP). Ground truth first: the lab's raw-HTTP "system browser" completes the real login (gateway 302 → IdP login page → credentials → callback → session cookie → 200). Then Anvil, without that cookie: API request → 401 `Authentication required` + `Bearer realm="oidc"`; browser-shaped request (`Accept: text/html`) → 302, followed to the IdP login page (200 HTML) | `auth.browser_session_required` (likely) says the request stopped at a login step, that a browser session stays in the browser and Anvil never imports browser cookies, and names the supported paths (an API credential or an explicitly configured, authorized session cookie); the followed login page is recorded as application **not evaluated**, never success; Anvil sent no Cookie, never submitted IdP credentials and carried no Authorization/Cookie to the IdP. Recovery: the session cookie configured explicitly as a secret → 200, and its value never appears in the record |
| AUTH-017.lookalike | AUTH-017 | An ordinary backend redirect (even one whose target mentions `client_id`) and a backend 401 with a plain `Bearer` challenge | No `auth.browser_session_required`; the redirect stays a successful exchange |

## Skipped scenarios (never counted as passes)

| Id | Reason |
|---|---|
| TLS-003, TLS-004 | Infeasible on 0.9.5: the gateway refuses to start (`validate` and `run`) with an expired or not-yet-valid frontend certificate. The profile re-checks this live on every run with `ferrum-edge validate` and quotes the refusal in the skip reason. UP-004.expired covers expiry on the upstream leg. |
| TLS-010, TLS-011 | Infeasible against the real gateway: its frontend always answers a ClientHello and ends every refusal with an alert; a client-leg stall/bare reset would need a non-gateway fault fixture. UP-007 covers the stall on the upstream leg. |
| TLS-012 | Infeasible: every 0.9.5 TLS listener (HTTPS and TCP+TLS share one rustls config) offers `h2`, `http/1.1`, `acme-tls/1`; every Anvil HTTP policy offers one of the first two. |
| TLS-017, TLS-018 | Out of this profile (forward-proxy leg; Anvil's own redirect policy). |
| AUTH-011..014 | Client-side OAuth flows with no gateway leg; covered by anvil-auth unit tests. |
| AUTH-025.nonce | Infeasible: 0.9.5 has no DPoP-Nonce / `use_dpop_nonce` challenge. |
| AUTH-030, AUTH-031 (conditional) | Only on hosts without `xmllint`: the lab cannot produce signed fixtures without an audited canonicalizer, and Anvil itself never signs XML. Present on this host, so both ran live. |

## Diagnostics fixes found by these profiles

1. **DTLS refusal reported as silent UDP** (PROTO-022). After refusing a
   client certificate, the 0.9.5 DTLS 1.3 frontend lets the client finish its
   handshake flight and then sends `close_notify`. Anvil said
   `udp.no_response`, whose alternatives include "nothing is listening" —
   contradicted by a completed handshake. New finding
   `dtls.closed_without_response` (confirmed observation, client-to-peer,
   cause left open). Tests: `crates/anvil-diagnostics/tests/lab_dtls_close.rs`.
2. **TLS 1.3 refusal whose alert was lost** (TLS-005/006/014). In some runs
   the gateway reset the connection so quickly after refusing a missing or
   untrusted client certificate that the TLS 1.3 alert never reached Anvil,
   which then said only "connection closed before a response" although it had
   observed the certificate request and a fresh TLS 1.3 connection. New
   finding `client.tls.closed_after_certificate_request`: likely when no
   certificate was presented, unknown when one was; never on reused
   connections, without an observed request, on TLS 1.2 or when an alert was
   read. Tests: `crates/anvil-diagnostics/tests/lab_tls13_refusal.rs`.
3. **Backend 401 attributed to a gateway auth plugin** (AUTH-X04/X05). The lab
   showed that 0.9.5 builds authentication/authorization rejections without a
   `Via` header, while every response on its backend path carries
   `Via: 1.1 ferrum-edge`. When that hop is present and every exact catalog
   candidate is such a pre-dispatch rejection, the new
   `ferrum.relayed_backend_response` finding (likely, upstream application)
   replaces the gateway attribution. Genuine gateway rejections, foreign `Via`
   hops, untrusted destinations and gateway-built upstream failures are
   unchanged. Tests: `crates/anvil-diagnostics/tests/lab_via_relay.rs`.
4. **A login page reported as a successful API exchange** (AUTH-017). A
   browser-shaped request to the OIDC route was redirected to the identity
   provider; Anvil followed it and reported the provider's 200 login page as
   a complete success, with nothing explaining that a browser session is not
   shared. New rule `auth.session` emits `auth.browser_session_required`
   (likely) from typed evidence only — a followed redirect or a 3xx
   `Location` carrying the RFC 6749 authorization-request parameters
   (`response_type` and `client_id`), or a 401 challenge naming the `oidc`
   realm — and `Diagnosis.stopped_at_login` makes the engine record such an
   exchange as application *not evaluated* (one line in
   `crates/anvil-engine/src/record.rs`). Ordinary redirects, plain bearer
   challenges and requests sent directly to an authorization endpoint are
   unchanged. Tests: `crates/anvil-diagnostics/tests/lab_browser_session.rs`.
   Catalog version `2026.09.25-7`.

## Gateway behaviour observed live (0.9.5, macOS arm64)

- Frontend refusals are always TLS alerts. rustls sends `certificate_required`
  for a missing client certificate on **both** TLS 1.3 (after the client's
  flight) and TLS 1.2 (inside the handshake); `unknown_ca` for an untrusted
  client certificate. On TLS 1.3 the gateway's reset sometimes discards the
  alert before the client reads it: 15 of 105 HTTPS refusals (TLS-005,
  TLS-006, TLS-014) across 20 tls runs; 0 of 70 TLS 1.2 refusals and 0 of 35
  TCP+TLS refusals.
- The gateway logs every frontend refusal as
  `Frontend TLS handshake failed from <ip>: <reason>` and DTLS refusals as
  `Client cert validation failed: DTLS client certificate verification failed …`.
- DTLS: 1.3 is negotiated with Anvil's hybrid ClientHello; the refusal is a
  `close_notify` right after the handshake (no alert, no timeout).
- Backend mTLS rejection on TLS 1.3 surfaced as `connection_reset` →
  `backend_error` in every observation (175 of 175 UP-016 requests); on TLS
  1.2 as `tls_error` → `connection_failure`.
- `jwks_auth`: a JWKS store that never loaded keeps `/health` at
  `ready:false`; an outage after startup is indistinguishable from a bad token
  once `jwks_max_stale_seconds` passes.
- An unknown kid triggers a JWKS re-fetch.
- `oauth2_introspection` / `ldap_auth` dependency outages are distinguishable
  (503 / 500, no challenge) from credential rejections (401 + challenge).
- Plugin rejections carry no `Via`; relayed backend responses do.
- `soap_ws_security`: one identity-establishing instance per proxy and no
  other auth plugin beside it; credentials are inline plaintext in the plugin
  (PasswordDigest needs the plaintext); the nonce replay store keys on the
  nonce alone; a SAML assertion id is single-use; X.509 trust is an exact
  certificate (SHA-256 fingerprint), RSA only. The gateway's in-house
  exclusive canonicalizer agreed with libxml2's on every signed fixture.
- `oidc_relying_party`: browser vs API is decided by `Accept: text/html`
  (GET/HEAD); the API branch answers 401 with `Bearer realm="oidc",
  error="invalid_token"`; the browser branch 302s with a sealed correlation
  cookie; discovery is fetched in the background after startup (browser
  requests get 503 `OIDC discovery unavailable` until then).

## Known limitations

- Marker- and body-derived claims stay at **likely** even with a trusted
  gateway (the markers and bodies are backend-spoofable on 0.9.5; the auth
  profile is plain HTTP). That ceiling is deliberate, not a test gap.
- On the TCP+TLS listener (TLS-005.tcp) the payload is written before the
  gateway's `certificate_required` alert arrives, so Anvil conservatively adds
  `request.processing_uncertain` although the gateway never accepted the
  handshake. Over-cautious, not over-confident; left as is.
- `WWW-Authenticate` values are redacted in execution records (the header
  name contains "auth"); challenge values are verified with a raw probe.
- UP-016 only ever observed the reset path (`connection_reset`) in these runs;
  the pool-cancellation path is accepted but not forced.
- The relay rule keys on the default `ferrum-edge` Via pseudonym; a renamed or
  disabled pseudonym falls back to the previous (body-based, likely) behaviour.
- Both profiles need a free port block (18180/18190, 19100–19199; 18380,
  18343, 18344, 18390, 18391, 18301, 18302, 19300–19399).
- WS-Security rejections other than `invalid credentials`, `nonce replay
  detected` and `SAML assertion has already been used` are recorded in the
  0.9.5 outcome catalog as one `{"error":"{message}"}` family, so Anvil gives
  them only the generic 401 meaning (no gateway attribution, no specific
  cause). Honest, but less specific than the body text.
- AUTH-030/031 depend on `xmllint` and `openssl` on the host (signed fixtures
  are generated per run; nothing signed is committed). Anvil has no XML
  signer; a user must bring a pre-signed envelope or a signed assertion.
- AUTH-017 drives the browser side with a raw HTTP client, not a real
  browser; the IdP login page is a fixture. The recovery path shown is an
  explicitly configured session cookie (the lab route carries only the OIDC
  plugin, so the API-token path is not exercised here).

## Stability

Command per run: `cargo run -p anvil-lab -- run <profile> --untrusted-pass`
(macOS 26 arm64, Ferrum Edge v0.9.5 `6a531f2c…`), each run starting and
stopping its own gateways and fixtures. Counts include both passes (trusted
and untrusted destination); skips are reported separately and never counted
as passes.

| Batch | tls (per run) | auth (per run) |
|---|---|---|
| With AUTH-017/029/030/031 live (current), 4 consecutive auth runs + 1 tls run | 66 passed, 0 failed, 7 skipped ×1 | 76 passed, 0 failed, 5 skipped ×4 |
| Before AUTH-017/029/030/031, 3 consecutive runs | 66 passed, 0 failed, 7 skipped ×3 | 62 passed, 0 failed, 9 skipped ×3 |
| Before AUTH-026 moved into tls, 5 consecutive runs | 64 passed, 0 failed, 7 skipped ×5 | 62 passed, 0 failed, 10 skipped ×5 |
| With AUTH-026 in tls, 5 consecutive runs | 66 passed, 0 failed, 7 skipped ×5 | 62 passed, 0 failed, 9 skipped ×5 |

One earlier batch failed 3 of 64 tls results (TLS-005/006/014, untrusted
pass): the TLS 1.3 alert was lost to the gateway's reset and Anvil reported
only "connection closed before a response". That was a diagnostics gap, not
a flaky test; it is fixed by `client.tls.closed_after_certificate_request`
(fix 2 above), and the scenarios accept exactly that alternative shape.

After every batch `pgrep -fl ferrum-edge` showed no gateway left from this
lab.

The `core` profile (`run core --untrusted-pass`, 36 scenarios) could not be
re-run from this worktree while this work was done: another session held the
core port block with `anvil-lab up core`. None of the diagnostics changes
can fire on core's evidence (no UDP/DTLS, no TLS client leg, no
authentication or authorization catalog candidates, no redirect into an
authorization endpoint and no `oidc`-realm challenge), and the engine and
diagnostics test suites pass.

`python3 scripts/matrix-coverage.py` (with the newest auth/tls runs above and
the other profiles' baseline runs) moves AUTH-017, AUTH-029, AUTH-030 and
AUTH-031 from *skipped (live)* to *verified live*: 94 verified live,
74 automated test, 1 executed check, 6 blocked, 2 partial, 2 not applicable,
3 not covered (UP-017/018/019, owned by the admission profile).
