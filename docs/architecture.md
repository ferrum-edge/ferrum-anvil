# Ferrum Anvil architecture

Ferrum Anvil is a local-first desktop and CLI API client. One Rust core
prepares, sends, observes and diagnoses every request. The desktop app, the
CLI, the collection runner and the load worker all use that core. The
webview never performs network I/O, never sees a vault key, and renders only
redacted results.

## Process and trust boundaries

```text
┌──────────────────────── Desktop process (Tauri 2) ────────────────────────┐
│  Webview (React/TS)          IPC (typed commands)       Rust backend      │
│  - renders redacted views  ───────────────────────▶  anvil-app services  │
│  - strict CSP, no remote     ◀──── events ─────────   (lock enforced here) │
│    scripts/frames/fetch                               anvil-engine        │
└───────────────────────────────────────────────┬───────────────────────────┘
                                                │ spawn self with
                                                │ --anvil-load-worker
                                                ▼ (job on stdin only)
                                   ┌────────────────────────────┐
                                   │ Load worker process         │
                                   │ same engine, bounded queues │
                                   │ NDJSON progress on stdout   │
                                   └────────────────────────────┘
CLI (`anvil`) = same anvil-app services without a webview.
```

- **Lock is enforced in the backend.** Every data command goes through
  `DesktopState::app()`, which refuses while locked. Locking drops the data
  key, clears token caches, pooled connections and TLS/QUIC session tickets,
  cancels executions and sessions, and stops load workers. The lock screen is
  only a view of that state.
- **File commands never take a path from the webview.** The backend shows
  the native open or save dialog itself (`file_choose`), keeps the chosen
  path and returns an opaque grant bound to one purpose (bundle import or
  export, attachment, PEM or PKCS#12 file, spec source, dataset, load or run
  report export); file commands accept only such a grant
  (`anvil_app::file_grants`). A read grant is refused if the file or a folder
  on its path was replaced after the choice; a write goes to a new temporary
  file that is renamed over the chosen name, and spends the grant (a bundle
  or backup is created readable only by its owner on Unix). Grants expire
  after 30 minutes, are capped at 32 and are revoked on lock; a dialog that
  was open when the app locked grants nothing.
- **Request specs from the webview name no local file.** `build_context`
  refuses an unsaved draft that references a linked file
  (`AttachmentRef::LinkedFile`), and the desktop refuses to create or save
  a request that does. A JWT-SVID token file is re-read at every send, so
  it is bound instead of granted: `file_choose` with purpose
  `jwt_svid_file` records the chosen canonical path in the vault
  (`anvil_app::token_files`, never exported or imported), and the desktop
  confines the app so a token-file path that is not bound is refused before
  anything is read. A linked file that a saved request, gRPC schema or
  dataset names is bound the same way, for that request or dataset
  (`file_choose` with purpose `linked_file` and the referrer,
  `anvil_app::linked_files`); until then it is refused before anything is
  read, in the desktop and the CLI alike. The CLI cannot bind one itself.
- **Pooled HTTP connections are bounded.** Each engine keeps at most 8 idle
  HTTP/1.1 or HTTP/2 connections per pool key (isolation, destination and
  security context) and 64 in total; one more closes the connection idle
  longest. A background sweep closes connections idle for 90 s even when their
  destination is never used again, and stops while the pool is empty. An
  HTTP/2 connection counts as idle only with no request in flight, so neither
  expiry nor eviction cuts a request short.
- **Load traffic never runs in the UI process.** The desktop re-launches its
  own executable with a fixed, non-secret flag and sends the job over stdin.
  The job carries only the secrets its requests reference.
- **Remote content is inert.** Bodies, headers and messages are shown as
  text or hex. The CSP forbids remote scripts, frames and fetches. No
  response text can change settings or reach the vault.

## Crates

| Crate | Responsibility |
|---|---|
| `anvil-domain` | Versioned data contracts (serde + JSON Schema): requests, auth, settings, TLS/proxy/integration profiles, execution records and evidence, findings, load plans/reports, events. `contracts/schemas/*.schema.json` and the TypeScript bindings are generated from it. |
| `anvil-transport` | Instrumented connections: DNS (system/custom), TCP happy-eyeballs, HTTP CONNECT / SOCKS5 proxies, rustls with an observing verifier and client-cert resolver, HTTP/1.1 and HTTP/2 (hyper), HTTP/3 (quinn + h3), and WS/gRPC/SSE/TCP/UDP/DTLS session adapters. Records typed phases, byte counts, connection reuse, TLS evidence and a dispatch state derived from bytes actually written. |
| `anvil-auth` | Final-byte auth: API key, Basic, Bearer, JWT (HS/RS/ES), OAuth2 (client credentials, refresh, auth-code + PKCE helpers, single-flight token cache), Ferrum HMAC v2 (legacy v1 opt-in only), DPoP, WS-Security UsernameToken and user-supplied SAML, and multi-auth. |
| `anvil-engine` | Variable resolution (precedence, cycles, helpers), request preparation and lint, per-send auth, redirects with cross-origin credential stripping, safe-retry rules, assertions and extraction, redaction by name and by exact secret value, the effective-request preview, session execution, and record assembly. |
| `anvil-diagnostics` | Deterministic rules over typed evidence that produce findings with confidence, scope, owner, evidence, alternatives, "does not prove" statements, remediation and confirm-with steps. Includes Ferrum catalog matching with trust and confidence ceilings. Wording lives in `catalog/diagnostics/findings.en.json`. |
| `anvil-storage` | SQLite store in which every payload is sealed with XChaCha20-Poly1305 and a record-bound AAD. Data keys are wrapped by an Argon2id passphrase key and a recovery key, or held in the OS keychain. Covers migrations, checkpoints and the plaintext-leak audit. |
| `anvil-portability` | Workspace and whole-app bundles: share-safely (placeholders), encrypted transfer and full backup. Import is hardened (limits, traversal, symlinks, bombs, checksums), normalises trust, uses conflict policies, and writes objects and secrets in one transaction that a failure rolls back (see `storage-and-recovery.md`). |
| `anvil-import` | OpenAPI 2.0/3.0/3.1/3.2, WSDL 1.1, Postman, Insomnia, cURL and HAR importers with reports and reimport diffs. |
| `anvil-load` | Open, closed and iteration workloads over the same engine; mergeable HDR histograms; balanced ledgers; generator health; the worker protocol; JSON, CSV and HTML reports; run comparison. |
| `anvil-runner` | Collection runner: scenarios and folders, datasets, chained extraction, stop-on-failure, JUnit/HTML/JSON reports. |
| `anvil-app` | Services shared by the desktop and CLI: profiles/unlock, the workspace tree, revisions, environments, secrets, profiles, the history policy, send/record, export/import, spec import, load plans/runs, and scenarios. |
| `anvil-cli` | The `anvil` command-line client. |
| `anvil-lab` | Real-gateway failure laboratory: the pinned Ferrum Edge binary, profile configs, fixtures, operator-log ground truth, and trusted/untrusted passes. |
| `anvil-fixtures` | Controllable test peers: HTTP(S) routes, raw fault modes, TLS servers, WS, gRPC with reflection, SSE, TCP/UDP, DTLS, DNS, and an OAuth IdP. |
| `apps/desktop` | Tauri 2 shell (`src-tauri`) and React UI (`src`). |

## One execution, end to end

1. **Freeze the context.** `anvil-app` freezes an `ExecutionContext`: the
   request spec (draft or saved revision), variable layers (workspace → environment → folders → request →
   iteration), settings layers (app → workspace → folders → request →
   run), auth inheritance, TLS/proxy/integration profiles and a scoped
   secret resolver.
2. **Prepare.** `anvil-engine` interpolates, lints the body (block or warn),
   serialises it, infers the content type, and then applies auth over the
   final bytes. HMAC digests and DPoP proofs are regenerated on every send.
3. **Send and observe.** `anvil-transport` resolves, connects, negotiates
   TLS and ALPN, writes the request and reads the response. It records each
   phase with a status (completed, failed, timed out, reused, not applicable)
   and tracks written bytes so that dispatch is never guessed from error
   text.
4. **Assemble the record.** The engine combines attempts (redirects and safe
   retries) into one redacted `ExecutionRecord` with three separate
   dimensions: transport completion, application status and assertions.
   Content decoding is recorded separately from wire completeness
   (`response.body.decoding`). Decoding does not complete when it stops at
   `max_decoded_bytes`, when the bytes do not decode, or when the coding is
   unsupported, including bogus codings such as `Content-Encoding: none`.
   Then a `partial_visibility` warning says so, body assertions fail with
   "could not evaluate" (the body was not fully decoded), body extractions
   are not run, and a response below HTTP 400 gets the application status
   `not_evaluated`. A collection run keeps a content-encoded body in history
   only when it was fully decoded and holds no sensitive run value.
5. **Diagnose.** `anvil-diagnostics` turns the typed evidence into
   findings. It uses Ferrum markers only for destinations declared as Ferrum
   gateways, caps their confidence (see `docs/diagnostics.md`), and orders
   hop-specific findings before the generic status-code explanation.
6. **Store.** `anvil-app` stores the record in encrypted history. Response
   bodies are kept only if the history policy allows it.

## Data contracts

`anvil-domain` is the single source of truth. `anvil schema` writes
`contracts/schemas/*.schema.json`, and `npm run contracts` generates
`apps/desktop/src/generated/contracts.ts`. CI regenerates both and fails on
drift.

## Where to read next

- `docs/adr/`: architecture decisions and their rationale.
- `docs/threat-model.md`: assets, trust boundaries and mitigations.
- `docs/diagnostics.md`: the evidence model, confidence rules and the Ferrum catalog.
- `docs/storage-and-recovery.md`: the vault, recovery, backups and migration.
- `docs/g01-gateway-diagnostic-contract.md`: the proposed gateway contract.
- `docs/protocols.md`, `docs/import.md`, `docs/load.md`, `docs/runner.md`, `docs/identity.md`, `docs/lab/*.md`.
