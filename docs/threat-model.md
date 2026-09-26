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
| Webview → Rust backend | A compromised renderer | Narrow typed commands; lock enforced in backend; secrets returned only as references; file access only through the backend's own native dialogs: file commands take an opaque, purpose-bound grant instead of a path (grants expire, are revoked on lock, a choice in progress when the app locks grants nothing, and a read is refused if the file or a folder on its path was replaced); a request spec from the webview may not name a linked local file; a JWT-SVID token file is read only if it was bound in the vault through the dialog; capability allowlist (`capabilities/default.json`: no open or save dialog, no filesystem plugin). Linked files already stored in a workspace (for example from an imported bundle) are still read when that saved request runs without an edited draft |
| Anvil → destinations | User mistakes, redirects | TLS verification on by default; bypass scoped to a profile with persistent warnings; client certs bound to hosts; credentials stripped on cross-origin redirects; load runs need explicit acknowledgement; imported plans untrusted |
| Disk | Other local users, backups, forensic reads | Everything sealed with AEAD; key wrapping with Argon2id or OS keychain; leak audit covers WAL/journal/blobs |
| Worker process | — | Job over stdin (not argv/env), only referenced secrets, killed with the parent, no inherited UI state |
| Remote diagnostics text | Server-authored explanations | Never used as instructions; findings come from local rules and catalog wording only |

## Threats and mitigations (STRIDE-style highlights)

- **Spoofed gateway markers** (a backend injects `X-Gateway-Error`): markers only
  count for declared gateways, capped at *likely*; lookalike tests in the lab.
- **Credential leakage via redirects or logs:** cross-origin credential stripping;
  redaction by name and by exact secret value across records, history, reports,
  exports and support bundles; query-string key warning.
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
