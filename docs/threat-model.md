# Threat model

Scope: the Anvil desktop app, the `anvil` CLI, the load worker and their local
data. Out of scope: the security of the APIs being tested, and malware already
running as the user inside an unlocked Anvil process (we do not claim protection
against it).

## Assets

1. Credentials: vault secrets, auth material (API keys, passwords, tokens, HMAC
   secrets, private keys, PKCS#12 bundles), OAuth tokens in memory.
2. Workspace data: URLs, headers, bodies, history, datasets — often sensitive.
3. The data-encryption key and its wrappings (passphrase, recovery key, keychain).
4. Integrity of diagnostics: users act on them; false *confirmed* attribution is
   a defect class of its own.
5. Other people's systems: Anvil can generate load; it must not do so by
   accident.

## Trust boundaries

| Boundary | Untrusted side | Controls |
|---|---|---|
| Network responses → app | Response bytes, headers, TLS peers, stream messages | Rendered as inert text/hex only; strict CSP (no remote script/frame/fetch); bounded buffering and decompression; typed parsing; no response can call IPC or change settings |
| Imported files → app | Bundles, OpenAPI/WSDL/Postman/Insomnia/cURL/HAR | Size/node/ref limits, no external `$ref`/DTD fetching, XXE disabled, zip traversal/symlink/bomb checks, checksums, preview before apply, trust normalisation, nothing executes on import, scripts kept as inert notes |
| Webview → Rust backend | A compromised renderer | Narrow typed commands; lock enforced in backend; secrets returned only as references; file access only through the backend's own native dialogs: file commands take an opaque, purpose-bound grant instead of a path (grants expire, are revoked on lock, a choice in progress when the app locks grants nothing, and a read is refused if the file or a folder on its path was replaced); a request spec from the webview may not name a linked local file; a JWT-SVID token file is read only if it was bound in the vault through the dialog; capability allowlist (`capabilities/default.json`: no open or save dialog, no filesystem plugin). Linked files already stored in a workspace (for example from an imported bundle) are still read when that saved request runs without an edited draft, and datasets linked to a local file are still read by the load plans and scenarios that use them |
| Anvil → destinations | User mistakes, redirects | TLS verification on by default; bypass scoped to a profile with persistent warnings; client certs bound to hosts; credentials stripped on cross-origin redirects; load runs need explicit acknowledgement; imported plans untrusted |
| Disk | Other local users, backups, forensic reads | Everything sealed with AEAD; key wrapping with Argon2id or OS keychain; leak audit covers WAL/journal/blobs |
| Worker process | — | Job over stdin (not argv/env), only referenced secrets, killed with the parent, no inherited UI state |
| Remote diagnostics text | Server-authored explanations | Never used as instructions; findings come from local rules and catalog wording only |

## Threats and mitigations (STRIDE-style highlights)

- **Spoofed gateway markers** (a backend injects `X-Gateway-Error`): markers only
  count for declared gateways, capped at *likely*; lookalike tests in the lab.
  After redirects, attribution comes from the origin that produced the final
  response (its own profile and TLS requirement), never the original request's.
- **Credential leakage via redirects or logs:** cross-origin credential stripping;
  redaction by name and by exact secret value across records, history, reports,
  exports and support bundles; query-string key warning. Headers, query
  parameters and form fields the user marks sensitive are redacted by name and
  by value. URL path segments, query names and values and fragments are
  compared after percent-decoding, and a component that hides a secret is
  replaced whole, so no reversible encoding of it is kept; a URL that still
  reveals one once decoded keeps only its scheme and authority. A collection
  run drops a content-encoded response body it cannot check for sensitive run
  values.
- **Redirect hops:** every hop is evaluated for its own target. Once a redirect
  leaves the request's origin (scheme, host or port), unless
  `redirects.forward_credentials_cross_origin` is on, configured headers that
  carry credentials are dropped for the rest of the chain: known credential
  names (`Authorization`, a manual `Cookie` header, `X-API-Key`, names
  containing `token`, `secret`, `auth`, ... or ending in `-key` / `_key`),
  headers marked sensitive, and headers whose value holds a secret variable.
  The prepared request notes the names (never the values) of the headers
  withheld. Auth (headers, API-key query parameters and API-key cookies) is no
  longer applied. The workspace cookie jar is separate: on each hop it sends
  the stored cookies that match that hop's target under cookie rules, which
  do not separate ports (nor schemes, for cookies without `Secure`). A
  redirect that would resend a body to another origin is not followed when
  preparing the body substituted a secret variable, whatever the body type
  and its encoding (form fields are percent-encoded, GraphQL variables are
  re-serialized), or when the body holds a resolved secret value byte for
  byte (an attachment, say). This also covers 301/302 redirects that retain
  the body, such as for PUT, PATCH and DELETE. Setting
  `redirects.forward_credentials_cross_origin` lifts this refusal. The TLS
  client identity is never presented to another origin unless a TLS profile
  is bound to it, whatever the redirect policy.
  The TLS settings are prepared for each hop's target; a hop whose route or
  TLS settings cannot be prepared is not followed.
- **Redirects and NO_PROXY:** the proxy route is decided for each hop's host
  and port. A redirect from a NO_PROXY host to any other host goes through the
  proxy, and a redirect to a NO_PROXY host goes direct, so a server can only
  move a request onto or off the proxy within the NO_PROXY list the user
  configured. Each attempt records its own route; the record's proxy and TLS
  summary describe the hop that produced the final response.
- **Replay by the client itself:** HMAC nonce, DPoP proof and JWT regenerated per
  send; no automatic retry of possibly-processed non-idempotent requests.
- **Replay of 0-RTT early data by the network:** data sent before a TLS 1.3 / QUIC
  handshake completes can be captured and replayed to the server by anyone on the
  path (RFC 8446 §8). Early data is off by default and opt-in per settings layer;
  only GET, HEAD, OPTIONS and explicitly listed idempotent methods (PUT, DELETE,
  TRACE) are sent as early data, a policy listing any other method is refused
  before traffic, imports turn the opt-in off, and load runs refuse it. An accepted
  early request carries a finding that says it could be replayed. The retry after
  `425 Too Early` happens once, after the handshake, only for eligible requests.
- **Session tickets:** the tickets early data needs are secrets that let the
  holder resume a session. They are kept in memory only, per workspace, transport,
  host and port, TLS profile and client identity, never persisted or exported, and
  dropped with pooled connections and OAuth tokens when the vault locks.
- **Accidental load against third parties:** explicit preflight acknowledgement,
  destination list, imported plans untrusted, bounded arrivals and abort rules.
- **Malicious bundle trying to enable insecure settings:** import normalisation
  (TLS bypass, plain-HTTP marker trust, credential forwarding, legacy HMAC,
  scenario/plan trust) with warnings in the preview.
- **Bundle key-derivation costs:** the Argon2id costs in a bundle manifest are
  read before the vault authenticates, so costs outside documented bounds
  (memory, passes, lanes, memory × passes, salt length; see
  [storage-and-recovery.md](storage-and-recovery.md#export-and-import)) are
  refused before any derivation.
- **Bundle identities:** bundle secrets must belong to a workspace in the
  bundle, object ids must be unique, and a Duplicate import gives every object,
  revision and secret a new id.
- **Lock bypass:** backend refuses privileged commands while locked; key dropped;
  sessions/executions/load runs stopped.
- **Test backdoors shipped:** E2E WebDriver and env unlock only under the `e2e`
  feature; release check fails if present (ADR 0009).
- **Supply chain:** pinned dependencies with lockfiles, `cargo deny` (licenses,
  advisories, sources), SBOMs, secret scanning in CI.

## Residual risks

- Keychain-protected profiles are as strong as the OS session.
- Memory of the running unlocked process can contain secrets; zeroization is
  best-effort.
- Unsigned development builds cannot prove provenance; release signing is blocked
  on owner credentials (see `docs/release.md`).
