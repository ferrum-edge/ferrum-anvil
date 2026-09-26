# Identity in Ferrum Anvil

Anvil keeps three identities apart (build plan §8.1). They never stand in for
one another:

| # | Identity | What it is | Where it lives |
|---|---|---|---|
| 1 | **Application identity** | Who may unlock Anvil on this device: a local profile, unlocked by a passphrase, a recovery key or the OS keychain. It can optionally be *linked* to a provider account (Google, GitHub, Facebook) as an extra unlock policy. | `anvil-storage` (vault), `anvil-app::profiles`, `anvil-app::identity`, `anvil-identity::provider` |
| 2 | **Target-API identity** | The credential Anvil presents to an API or gateway: API key, Basic, bearer, JWT, OAuth 2, HMAC, DPoP, mTLS, WS-Security, and SPIFFE SVIDs the Workload API issues to Anvil (an X.509-SVID as the mTLS identity, a JWT-SVID as the bearer token, §8). The OAuth authorization-code + PKCE sign-in belongs here. | auth and TLS profiles on workspace/folder/request, `anvil-engine`, `anvil-identity::api_oauth` |
| 3 | **Gateway-to-backend identity** | How the gateway authenticates to its upstream. Configured on the gateway; Anvil cannot change it, and no diagnostic suggests that changing identity 2 fixes identity 3. | the gateway |

Rules that follow from this:

- Signing in to an API (2) does not sign you in to Anvil (1), and vice versa.
- A provider identity is **not an encryption key**. The profile data key is
  random and is wrapped only by the passphrase (Argon2id), the recovery key or
  the OS keychain. Nothing derives key material from an e-mail address or a
  provider subject.
- Provider client secrets never ship in the desktop bundle.
- No client id, token endpoint or issuer assertion is invented to make a
  provider "work". What is missing is reported as unavailable.

---

## 1. Target-API OAuth: authorization code + PKCE

### Behaviour of a send

For an auth profile with grant `authorization_code_pkce` (or `refresh_token`),
the engine:

1. uses a cached, unexpired token;
2. otherwise refreshes it with the cached refresh token (single-flight: many
   concurrent sends cause one refresh);
3. otherwise **fails locally before the request exists on the wire** with
   `FailureKind::OAuthInteractionRequired`, dispatch `not_dispatched`, and
   the finding `local.oauth_interaction_required` ("Sign in before sending
   with this OAuth profile").

It never falls back to the client-credentials grant. If the issuer rejects the
refresh token with `invalid_grant`, the token is dropped and the next send asks
for a sign-in. If the issuer is unreachable or failing (HTTP 5xx, TLS or network
errors), the send fails with `local.auth_preparation_failed` and the refresh
token is kept for a later attempt (matrix AUTH-015). Client-credentials profiles
behave as before. WebSocket, gRPC, SSE, TCP and UDP sessions behave the same way.

Tokens are cached per **token identity**: the workspace isolation, token URL,
authorization URL (interactive grants; its query, such as an organization,
connection or identity-provider hint, included), client id,
client-authentication method, grant, audience, scope and the profile's
`token_cache_id`. When a profile sets no `token_cache_id`, the app uses the id
of the workspace, folder or request that defines it: requests that inherit one
profile share its sign-in, while the same settings defined in two places do
not. A change to any of them needs its own token: a token acquired with client
credentials is never sent for an authorization-code profile, a token for one
audience is never sent to another, and a sign-in through one organization is
never sent for another. Sends, sign-in, token status and sign-out all use the
same key.

Canceling an execution ends its wait for a token at once; the send ends as
`canceled`, not dispatched. A client-credentials request is abandoned with it.
A refresh keeps running on its own task until the issuer answers (the issuer
may already have rotated the refresh token), and its token is cached for the
next send; sends that arrive meanwhile wait for it rather than presenting the
old refresh token again. Locking (which clears the token cache) or signing out
of a profile invalidates every acquisition, refresh and code redemption still
in flight for it, and a completed sign-in invalidates every acquisition and
refresh that began before it: a token that arrives afterwards is discarded,
never cached and never sent, and that send ends as `canceled`.

### The sign-in flow (RFC 8252 native app, RFC 7636 S256)

`anvil_identity::authorize_api` (or `App::oauth_sign_in` from the app layer):

1. Resolves the OAuth profile in effect for the request (request → folders →
   workspace, including a profile inside a multi-auth set), with variables and
   vault secrets. Client-credentials profiles, non-OAuth auth and missing
   authorization URLs are refused as configuration errors.
2. Requires `https` for the authorization and token URLs. Plain `http` is
   accepted only for a loopback test issuer (`127.0.0.1`, `::1`, `localhost`).
3. Binds a listener on `127.0.0.1` with an ephemeral port. The redirect URI is
   `http://127.0.0.1:<port>/callback`.
4. Builds the authorization URL: `response_type=code`, `client_id`,
   `redirect_uri`, `state` (24 random bytes), `code_challenge` (S256 of a
   48-byte random verifier), `code_challenge_method=S256`, `scope`.
5. Calls the caller's `BrowserOpener` to launch the **system browser** (never
   an embedded webview). If the opener fails, the attempt keeps waiting and the
   `browser_open_failed` event carries the URL so the user can open it by hand.
6. Accepts **exactly one** callback for the attempt:
   - requests with another `Host` (for example a DNS-rebinding page), another
     path (`/favicon.ico`, probes), or another method get a static page and are
     ignored (`callback_ignored` event);
   - the first request on the bound path decides the attempt. A `state`
     mismatch, repeated `code`/`state`/`error` parameters or a missing code end
     it with `CallbackRejected`; an `error=` answer ends it with
     `AuthorizationDenied`. There is no token exchange in either case;
   - later requests get "already handled".
7. Answers the browser with fixed HTML: no scripts, no reflected query values,
   `Content-Security-Policy: default-src 'none'`, `Cache-Control: no-store`,
   `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff`,
   `X-Frame-Options: DENY`.
8. Stops at the timeout (default 5 minutes) or on cancellation; the port closes
   with the attempt.
9. Redeems the code **through the engine transport** with the request's
   settings: the TLS profile (private CAs, verification policy, client
   certificate bindings), the proxy profile (with NO_PROXY), DNS overrides and
   timeouts. A confidential client's secret, if the profile has one, is sent
   according to the profile's client-authentication setting.
10. Stores the token in the engine token cache under the same key sends use
    (the token identity above). If the app was locked, or the user signed out
    of this profile, since the attempt began, the redeemed token is discarded
    and the attempt ends as canceled. A refresh that began before the sign-in
    can no longer overwrite it. Tokens are held in memory only: they are
    cleared on lock, not written to disk and never exported.

Codes, verifiers and tokens are zeroized on drop, are never part of an event,
an error message, a log line or an execution record, and are never returned to
the UI. `ApiAuthorization` and `TokenSummary` carry only metadata (token type,
expiry, whether a refresh token exists).

### What an API owner registers

The API owner registers a **public client** (no secret) with their authorization
server and allows the loopback redirect `http://127.0.0.1/callback` **with any
port** (RFC 8252 §7.3). Anvil uses the literal IP `127.0.0.1`, not `localhost`.
Issuers that only accept exact redirect URIs with fixed ports are not supported
by this flow.

---

## 2. Application login (provider-protected mode)

### Modes

| Mode | Unlock | Offline |
|---|---|---|
| Local, no account | OS keychain or passphrase profile | yes |
| Local protected | passphrase, with a recovery key shown once; or the OS keychain (a keychain profile has no recovery key — the keychain item is its only wrap, so keep a portable backup) | yes |
| Provider-linked | as above; a provider account is bound to the profile | yes (the link alone changes nothing) |
| Provider-linked, `require_fresh_login` | passphrase/keychain **and** a provider sign-in from the last 5 minutes | only with the recovery key (passphrase profiles) |

No mode implies cloud synchronization, and no mode needs a Ferrum account.

### How the policy is enforced

- `ProfileManager::unlock(dir, Unlock::Passphrase | Unlock::Keychain)` refuses
  a profile with `require_fresh_login` with
  `IdentityPolicyError::FreshLoginRequired` **before** the data key is
  unwrapped. The check is in the backend, not in the webview.
- `ProfileManager::unlock_with_fresh_login(dir, how, proof)` needs both: the
  local secret must still unwrap the key, and `proof` must be a
  `VerifiedIdentity` for the linked provider and subject, at most 5 minutes old
  (60 s tolerance for a clock ahead). Otherwise: `IdentityMismatch`,
  `StaleProof`, or the vault's `WrongSecret`.
- The **recovery key** always unlocks without a provider (DATA-019). That is
  the documented offline and provider-outage path.
- A `VerifiedIdentity` can only be created by a provider implementation inside
  `anvil-identity`. It is not `Clone` and not deserializable, so it cannot
  arrive over IPC from the webview, and one proof serves one unlock.

### Where the binding is stored

`<profile dir>/identity.json`, next to `profile.json`:

- a plaintext **hint** (provider, subject, policy, link time; no e-mail) so the
  lock screen can say "Sign in with … required" before unlocking;
- a **sealed** copy of the full binding (including e-mail), encrypted with
  XChaCha20-Poly1305 under the profile's data key, with the profile id as
  associated data.

The pre-unlock check uses the hint. After the key is unwrapped, the sealed copy
is authoritative: if the hint was edited (for example to switch the policy off
or to change the subject) or the file is unreadable, passphrase/keychain unlock
fails with `BindingTampered`. The recovery key still unlocks and can remove the
binding so it can be linked again. `profile.json` (the key wraps) is never
touched by linking.

Linking asks for the local unlock secret again. Under the fresh-login policy,
switching the policy for the same account needs a fresh proof of that account.
Replacing the account needs the recovery key, or unlinking first, which in turn
needs a fresh proof or the recovery key.

Workspace exports and full-app backups never contain `identity.json`, and
imports never write it. Restoring someone else's backup cannot replace the
local linked identity or its policy (tested).

### Honest limits of the policy

- It is enforced by Anvil, not by cryptography. Someone who has the passphrase
  (or recovery key) and a copy of the profile files can decrypt them with other
  tools, provider or not. Someone who can write to the profile directory can
  delete `identity.json`, which removes the policy. With that level of access
  they could also copy the ciphertext for an offline attack on the passphrase.
- An online-only policy depends on the provider being reachable. The recovery
  key is the fallback. Keep it safe; resetting a passphrase without it cannot
  decrypt anything.

---

## 3. What is unavailable in this build

`anvil_app::identity::login_providers()` lists Google, GitHub and Facebook with
`availability: unavailable` and reason
`requires registered OAuth client id / redirect URI / broker (owner action)`.
Their `authenticate` returns `FlowError::ProviderUnavailable` without opening a
browser or touching the network. Consequently, in release builds no
`VerifiedIdentity` can be produced yet, so linking and the fresh-login policy
become usable only once a real provider is implemented against owner
registrations.

The owner has to supply:

| Provider | How native apps authenticate | Owner registrations and decisions | Secret location |
|---|---|---|---|
| Google | OpenID Connect authorization code + PKCE in the system browser with a loopback IP redirect. The ID token must be verified: signature against Google's published keys, `iss`, `aud` = client id, `exp`, `nonce`. | A Google Cloud OAuth client of type *Desktop app*; the OAuth consent screen (openid, email) and any verification it requires; the client id in the deployment configuration. Google issues a client secret for desktop clients and documents it as non-confidential for installed apps; this build ships none. The owner decides whether it goes in the bundle per Google's guidance or the exchange goes through the broker. | Broker, if the secret is kept off the device |
| GitHub | OAuth, not OpenID Connect. The web application flow's code exchange requires the client secret, so a desktop app needs a broker holding it, or the device flow enabled on the app. The account is identified by the numeric user id from the authenticated-user API. | A GitHub OAuth App or GitHub App with the broker's callback URL (or the device flow enabled); the client id and broker URL in the deployment configuration. | Broker only |
| Facebook | Facebook Login manual flow. The code exchange and token inspection need the app secret, so they run in a broker. The account is identified by the app-scoped user id. | A Meta app with Facebook Login; the exact redirect URI(s); any app review it requires; the app id and broker URL in the deployment configuration. | Broker only |
| Identity broker (GitHub, Facebook, optionally Google) | Not built. | A minimal HTTPS service run by the owner. It receives the authorization code, PKCE verifier and state binding from the desktop, exchanges them with the provider using the secret, verifies the account, and returns a short-lived signed identity assertion whose issuer and signing key are pinned in the desktop build. It receives identity and session data only: never API bodies, workspace data or keys. | Holds all provider secrets |

Tracked as ferrum-edge/ferrum-anvil#3. Provider documentation changes. Re-check these requirements during
registration. Before production provider support is claimed, the plan also
requires real-provider acceptance tests with test accounts.

---

## 4. CI-only mock provider

`anvil_identity::mock::MockProvider` (cargo feature `mock-provider`, enabled
only by dev-dependencies) runs the real loopback PKCE flow against the fixture
issuer (`anvil_fixtures::idp`), redeems the code through the engine transport
and reads the subject from the issuer's userinfo endpoint with the new access
token. It refuses any non-loopback endpoint, is not part of
`builtin_providers()`, and `anvil_identity::MOCK_PROVIDER_COMPILED` lets
release checks assert that it is absent.

---

## 5. Desktop integration

All functions are plain async Rust with no Tauri dependency. The desktop
supplies:

- **Opener**: any `Fn(&str) -> Result<(), String> + Send + Sync`, for example
  `move |url| handle.opener().open_url(url, None::<&str>).map_err(|e| e.to_string())`.
  It must return once the browser was asked to open.
- **Observer**: any `Fn(FlowEvent) + Send + Sync`, for example
  `move |ev| { let _ = handle.emit("identity-flow", ev); }`. `FlowEvent` is
  serde-tagged (`type`): `listener_ready`, `browser_opened`,
  `browser_open_failed`, `callback_ignored`, `callback_accepted`,
  `exchanging_code`, `verifying_identity`, `completed`,
  `failed { kind, message }`.
- **Cancellation**: a `CancellationToken` per attempt, kept like running
  executions so that a Cancel button and app lock can cancel it.

Target-API sign-in (identity 2):

```rust
App::oauth_sign_in(&self, request_id: Option<Id>, ws: &Id, draft: Option<RequestSpec>,
    opts: &SendOptions, opener: &dyn BrowserOpener, observer: &dyn FlowObserver,
    flow: &FlowOptions, cancel: &CancellationToken) -> Result<ApiAuthorization>
App::oauth_token_status(&self, request_id, ws, draft, opts) -> Result<Option<TokenSummary>>
App::oauth_sign_out(&self, request_id, ws, draft, opts) -> Result<bool>
```

Application login (identity 1):

```rust
anvil_app::identity::login_providers() -> Vec<ProviderInfo>
anvil_identity::find_provider(id)?.authenticate(opener, observer, &FlowOptions, &cancel)
    -> Result<VerifiedIdentity, FlowError>
ProfileManager::unlock_requirements(dir) -> Result<UnlockRequirements>
ProfileManager::unlock(dir, Unlock) -> Result<(ProfileHeader, Key)>          // enforces the policy
ProfileManager::unlock_with_fresh_login(dir, Unlock, VerifiedIdentity) -> Result<(ProfileHeader, Key)>
ProfileManager::link_identity(dir, Unlock, VerifiedIdentity, require_fresh_login: bool) -> Result<LinkedIdentity>
ProfileManager::unlink_identity(dir, Unlock, Option<VerifiedIdentity>) -> Result<()>
ProfileManager::linked_identity(dir, &Key) -> Result<Option<LinkedIdentity>>
```

Errors: `AppError::Identity(IdentityPolicyError::{FreshLoginRequired, IdentityMismatch, StaleProof, NotLinked, BindingTampered})`,
`AppError::SignIn(FlowError)` (with `FlowError::kind()` for the UI), and the
existing `AppError::Vault(WrongSecret)` and `AppError::Locked`.

The provider flow and the unlock must run in the same backend command (or the
backend keeps the `VerifiedIdentity` in its own state between two commands).
The webview only ever sees `IdentitySummary`.

---

## 6. Threat notes

- **Local processes can reach the loopback listener.** The ephemeral port,
  192-bit `state`, the PKCE verifier (which never leaves the process except to
  the token endpoint), the single decisive callback and the `Host` check limit
  this. A local process that races the browser with a forged callback can make
  the attempt fail (the user retries). It cannot get a token from it.
  Malware able to read the browser or Anvil's memory is out of scope.
- **Redirect interception** through custom URL schemes does not apply:
  the redirect is loopback only.
- **Mix-up**: each profile names one issuer. The RFC 9207 `iss` response
  parameter is not validated yet (limitation).
- **Issuer TLS** follows the request's TLS profile. A private CA works. A
  verification bypass that the user set on that profile also applies to the
  issuer. Verification stays on by default.
- **Tokens** are memory-only and cleared on lock. After a restart the user
  signs in again: refresh tokens are not persisted in this build.
- **App login** is an enforced policy on top of the vault, never a key (see
  the limits above).

---

## 7. Tests

| Area | Tests | Matrix |
|---|---|---|
| Token cache: no client-credentials fallback, refresh, `invalid_grant`, issuer outage, single-flight | `crates/anvil-auth/src/oauth.rs` | AUTH-014, AUTH-015 |
| Token identity (grant, audience, authorization URL, token-cache id, …); lock, sign-out and a newer sign-in win over in-flight acquisitions and refreshes; dropped client-credentials acquisitions cache nothing; a refresh whose caller stops waiting still stores the rotated refresh token | `crates/anvil-auth/tests/oauth_cache.rs` | — |
| Grant, audience and authorization-URL switches through `Engine::execute`; cancel and lock while the issuer holds its answer; a send canceled during a refresh keeps the rotated refresh token | `crates/anvil-engine/tests/oauth_cache.rs` | — |
| Callback binding, duplicates, bounded error codes | `crates/anvil-auth/src/oauth.rs` | AUTH-012, AUTH-013 |
| Full browser round trip, then a real API request with the token; forged state; stray paths and DNS-rebinding Host; timeout; cancellation; denial; refresh; revoked refresh; issuer outage and recovery; the exchange uses the request's TLS profile; refused configurations; WebSocket parity | `crates/anvil-identity/tests/api_oauth.rs` | AUTH-011–015 |
| Real providers typed unavailable; mock provider round trip and denial | `crates/anvil-identity/src/{provider,mock}.rs` | — |
| Link with the mock provider; fresh-login policy (refused, allowed, wrong passphrase, stale, other account, recovery offline); identity is not a key; edited hint; relink and unlink; restoring another user's backup; target-API sign-in through the app, dropped on lock; token-cache identity per defining workspace, folder or request | `crates/anvil-app/tests/identity.rs` | DATA-015, DATA-017, DATA-018, DATA-019 |
| SPIFFE Workload API: X.509-SVID and JWT-SVID sources, local checks, caching, cleared on lock, never recorded; the probe; the import stance | `crates/anvil-transport/tests/workload_api.rs`, `crates/anvil-engine/tests/workload_api.rs`, `crates/anvil-cli/tests/cli_workload.rs`, `crates/anvil-portability/tests/bundles.rs`; live: lab `workload` (`docs/lab/workload.md`) | — |

---

## 8. Target-API workload identity: the SPIFFE Workload API

A SPIFFE workload does not hold a credential file: it asks the local Workload
API (a SPIRE agent, or Ferrum Edge's in-process server) which identity it has,
and the API decides from the calling process's kernel peer credentials — for
Anvil, the operating-system user it runs as. Anvil uses that identity as
identity #2 only; it never becomes the app login (#1) and never stands in for
a gateway's backend identity (#3). The protocol details are in
[protocols.md §3.11](protocols.md).

- **Where.** A TLS profile's client identity can be *SPIFFE Workload API
  (X.509-SVID)*; an auth profile can be *JWT-SVID (SPIFFE)*. The endpoint is a
  `unix:///…` socket (`npipe:` on Windows) or, when empty, the
  `SPIFFE_ENDPOINT_SOCKET` environment variable. The record names the endpoint
  that was dialed and where the setting came from.
- **What is issued is not stored.** The X.509-SVID's private key, the
  JWT-SVID and the JWT bundles are held only in the engine's memory cache
  (zeroized buffers), refreshed at half their lifetime, cleared on lock with
  the OAuth tokens, never written to the vault, history, exports or logs, and
  never sent to the webview. The record keeps public data: SPIFFE IDs, the
  certificate summary, `aud`, `exp`, `alg`, `kid` and the check results.
- **Checked before use.** A JWT-SVID must be a JWT-SVID (asymmetric `alg`, a
  workload SPIFFE ID as `sub`), carry every configured audience and be
  unexpired by this machine's clock; with bundle verification, its signature
  must verify against the trust domain's JWT bundle. A failure stops the
  request unless the profile deliberately sends anyway to test a verifier.
- **Nothing is invented.** Anvil never mints an SVID or a JWT-SVID, never
  picks an identity the Workload API did not issue, and never claims why a
  verifier refused one: a 401 after a JWT-SVID is reported with the local
  checks as evidence and the verifier's reason left unknown.
- **Imports.** A Workload API source carries no secret, so an imported
  profile would draw on *this* machine's identity. Imports therefore never
  activate "send despite failed checks" and name every imported profile that
  fetches a JWT-SVID or presents an X.509-SVID, so the user reviews their
  audiences, destinations and host bindings before sending.
- **Probe.** *Test the Workload API* in the editors and `anvil workload probe`
  show what the endpoint issues to Anvil (and, when refused, the uid it
  attested) without keeping a key or showing a token.
