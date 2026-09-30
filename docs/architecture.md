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

### Lock

- **The backend enforces the lock.** Every data command goes through
  `DesktopState::app()`, which refuses while locked. The lock screen is only a
  view of that state.
- **Locking stops everything.** It drops the data key, clears token caches,
  pooled connections and TLS/QUIC session tickets, revokes file grants,
  cancels executions, imports, sign-ins and sessions, and stops load workers.
  Opening another profile (`DesktopState::set_app_since`) locks the previous
  one and stops its work the same way.
- **Work stays with its profile.** A send, session, collection run or load run
  records only into the profile it started under. A load report that finishes
  while its profile is locked is held for that profile (`state::VaultId`) and
  saved when it is next unlocked, never into another.
- **Work is cancelable from its first moment.** Every attempt registers its
  cancellation token before it reads the profile: `session_open`,
  `send_request`, collection runs, bundle imports and OAuth sign-ins through
  `state::PendingEntry`, and `load_run_start` through `LoadRunEntry`. A lock
  first locks the profile, then cancels every registered token, so an attempt
  that registered earlier is stopped, and one that registers later is refused
  when it reads the profile. A `PendingEntry` is removed on every path, a
  panic included, and an id that is still registered is refused. A session is
  published to the open sessions before its pending
  token is retired, so a concurrent cancel always finds one of the two. An
  Abort that reaches the backend before the open has registered finds nothing
  to stop, so the renderer cancels again once the open returns.
- **A lock wins over work that ran off the lock.** `DesktopState` keeps a
  lock epoch that every lock and profile switch bumps first. Unlock and
  profile creation read it before deriving the key and open the profile only
  if it is unchanged (`set_app_since`, `unlock_since`). An unlock of the open
  profile checks it under the write lock of the store's key, before the key is
  set (`Store::unlock_if`), so the profile is never usable in between.
  `commands::blocking` returns `LOCKED` instead of its result if the epoch
  changed while it ran; writes that return no data use `blocking_unchecked`,
  so a committed write is not reported as `LOCKED`.

### Store work

Each profile has one SQLite connection, and a long transaction (an import, a
spec import, a folder or workspace delete) holds it until it ends. Work that
writes in bulk, reads many records or derives a key therefore runs on a
blocking thread, not on the async runtime:

- `commands::blocking`: profile creation, unlock and passphrase changes, spec
  imports, folder and workspace deletes, history lists, views and clears,
  export previews, and attachment, PEM/PKCS#12 and dataset reads.
- `import_work`: bundle imports and previews, one at a time.
- `anvil_app::off_runtime`: building the context of a send, session open or
  OAuth sign-in; recording a send or session in history; preparing and saving
  a collection run (each step is recorded through `block_in_place`); preparing
  and saving a load run.

A cancel while a send, session open or collection run waits for its
preparation ends it at once, with nothing sent or recorded. Shorter commands
run on the UI thread in the order they were called, and wait for a long
transaction to end.

### Files

- **File commands never take a path from the webview.** The backend shows the
  native open or save dialog itself (`file_choose`), keeps the chosen path and
  returns an opaque grant bound to one purpose: bundle import or export,
  attachment, PEM or PKCS#12 file, spec source, API-standards ruleset,
  dataset, or load, run or standards report export (`anvil_app::file_grants`).
- A read grant is refused if the file, or a folder on its path, was replaced
  after the choice. A write goes to a new temporary file that is renamed over
  the chosen name, and spends the grant. A bundle or backup is created
  readable only by its owner on Unix.
- Grants expire after 30 minutes, are capped at 32, and are revoked on lock
  and when another profile is opened. A dialog that was open at that moment
  grants nothing.
- **Request specs from the webview name no local file.** `build_context`
  refuses an unsaved draft that references a linked file
  (`AttachmentRef::LinkedFile`), and the desktop refuses to create or save a
  request that does. The only way the desktop writes a linked path into a
  saved request or dataset is a relocation (below): the path is the one the
  user picked in the backend's own dialog, never one from the webview.
- **Files read at send time are bound, not granted.** A JWT-SVID token file is
  re-read at every send. `file_choose` with purpose `jwt_svid_file` records the
  chosen path in the vault (`anvil_app::token_files`; never exported or
  imported). Links are kept, so a rotating token keeps working; the path is
  canonicalised only to check that it leads to a regular file. The desktop
  refuses a token-file path that is not bound before reading anything. The
  JWT-SVID editor lists and removes bound files (`token_files_list`,
  `token_file_remove`); an auth setting that names a removed file is refused
  until it is chosen again.
- A linked file that a saved request, gRPC schema or dataset names is bound
  the same way, for that request or dataset (`file_choose` with purpose
  `linked_file` and the referrer, `anvil_app::linked_files`), and only if
  that request or dataset names the chosen file's canonical path. Until it
  is bound the file is refused before anything is read, in the desktop and
  the CLI alike; the CLI cannot bind one.
- The desktop shows each linked file beside the request's binary body or
  multipart part, its gRPC schema, or a load plan's dataset, with its
  binding state (`linked_file_status`): chosen on this device, not chosen,
  or chosen but missing or changed (moved, deleted, replaced by a folder, or
  its path now resolving to another location). **Choose file…** or
  **Rebind…** opens the dialog for that request or dataset. The status query
  binds nothing, runs off the UI thread, and looks only at the metadata of
  files already bound for that referrer; an unbound path is never touched.
  "Chosen" does not check the size limit: that depends on what reads the
  file, and is enforced when it is read. A file found at another path cannot
  be bound for a reference that names the old one: put it back, relocate the
  reference, or attach a copy.
- **Relocating a linked file.** A reference whose file is elsewhere on this
  device (typically one imported from another machine) is repointed with
  **Choose new location…**, shown for a request's linked file that is not
  chosen yet or is missing or changed. `file_choose` with purpose
  `linked_file_relocate`, the referrer and `old_path` shows the open dialog;
  picking the file there is the consent. `App::relocate_linked_file`
  requires `old_path` to be a linked file that request or dataset names, and
  never looks at it on disk. The picked file must be a regular file with an
  absolute, UTF-8 path without `{{`, and is named by its canonical path.
  One write transaction checks that the referrer still names `old_path`,
  rewrites every reference to it in that request (filing a new revision) or
  dataset only, drops that referrer's binding of the old path and binds the
  new one. Another request or dataset naming the old path is untouched and
  stays unbound until the file is chosen for it. The lock and profile checks
  of a bind apply before and after the write, and a dialog open when the app
  locks or another profile opens relocates nothing. The editor then reloads
  the saved request into its draft (a draft naming a linked file cannot be
  saved anyway). The new path is saved in the request or dataset, so a later
  export carries it: see the threat model.

### Connection pools

- Each engine keeps at most 8 idle HTTP/1.1 or HTTP/2 connections per pool
  key (isolation, destination and security context) and 64 in total. One
  more closes the connection idle longest: within the key when the key is
  full, else across all keys.
- The HTTP/3 pool keeps at most 64 idle QUIC connections, on its own cap
  (see [protocols.md](protocols.md) §3.7).
- A background sweep closes connections idle for 90 s, even when their
  destination is never used again. It stops while the pool is empty and ends
  with its engine.
- A connection counts as idle only with no request in flight, so neither
  expiry nor eviction cuts a request short.
- A load run gives each slot (virtual user or concurrency lane) its own
  engine with smaller caps. N is the number of distinct requests in the
  plan's chain or mix, clamped to 4..=64, so a persistent chain finds each
  step's connection still pooled on the next iteration. Per slot, the HTTP/1.1
  and HTTP/2 pool keeps at most 2 idle connections per key and N in total,
  and the QUIC pool at most N. These caps leave out connections carrying a
  request, the one connection per key kept for a retry after `425 Too Early`
  (up to 10 s, or the shorter idle TTL), and the slot's gRPC channels (one
  per destination).

### Webview

- **The workbench shows the selected workspace only.** Its lists (collection
  tree, history, TLS/proxy/gateway profiles, environments) are cleared when
  the workspace changes and filled only from the latest read of the workspace
  still selected; a late earlier read is dropped.
- **Saving keeps the editor usable.** Saves of one request are written one at
  a time, in order. Each moves the saved baseline to what it wrote, and edits
  made while a save was pending stay unsaved.
- **Remote content is inert.** Bodies, headers and messages are shown as text
  or hex. The CSP forbids remote scripts, frames and fetches. No response text
  can change settings or reach the vault.

### Load worker

Load traffic never runs in the UI process. The desktop (and the CLI)
re-launches its own executable with the fixed, non-secret flag
`--anvil-load-worker` and sends the job over stdin. The job carries only the
secrets its requests reference. See [load.md](load.md#worker-process-and-ipc).

## Crates

| Crate | Responsibility |
|---|---|
| `anvil-domain` | Versioned data contracts (serde + JSON Schema): requests, auth, settings, TLS/proxy/integration profiles, execution records and evidence, findings, load plans/reports, events. `contracts/schemas/*.schema.json` and the TypeScript bindings are generated from it. |
| `anvil-transport` | Instrumented connections: DNS (system/custom), TCP happy-eyeballs, HTTP CONNECT / SOCKS5 proxies, rustls with an observing verifier and client-cert resolver, HTTP/1.1 and HTTP/2 (hyper), HTTP/3 (quinn + h3), and WS/gRPC/SSE/TCP/UDP/DTLS session adapters. Records typed phases, byte counts, connection reuse, TLS evidence and a dispatch state derived from bytes actually written. |
| `anvil-auth` | Auth applied to the final bytes: API key, Basic, Bearer, JWT (HS/RS/ES), OAuth2 (client credentials, refresh, auth-code + PKCE helpers, single-flight token cache), Ferrum HMAC v2 (legacy v1 opt-in only), DPoP, WS-Security UsernameToken and user-supplied SAML, and multi-auth. |
| `anvil-engine` | Variable resolution (precedence, cycles, helpers), request preparation and lint, per-send auth, redirects with cross-origin credential stripping, safe-retry rules, assertions and extraction, redaction by name and by exact secret value, the effective-request preview, session execution, and record assembly. |
| `anvil-diagnostics` | Deterministic rules over typed evidence that produce findings with confidence, scope, owner, evidence, alternatives, "does not prove" statements, remediation and confirm-with steps. Includes Ferrum catalog matching with trust and confidence ceilings. Wording lives in `catalog/diagnostics/findings.en.json`. |
| `anvil-storage` | SQLite store in which every payload is sealed with XChaCha20-Poly1305 and a record-bound AAD. Data keys are wrapped by an Argon2id passphrase key and a recovery key, or held in the OS keychain. Covers migrations, checkpoints and the plaintext-leak audit. |
| `anvil-portability` | Workspace bundles: share-safely (placeholders) and encrypted transfer. Bundles that describe a full backup are refused (full backups are ANVILBAK files, see `anvil-app`). Import is hardened (limits, traversal, symlinks, bombs, checksums), normalises trust, applies conflict policies, and writes objects and secrets in one transaction that a failure rolls back (see [storage-and-recovery.md](storage-and-recovery.md)). |
| `anvil-import` | OpenAPI 2.0/3.0/3.1/3.2, WSDL 1.1, Postman, Insomnia, cURL and HAR importers with reports and reimport diffs. |
| `anvil-contract` | OpenAPI contract tooling: API-standards rulesets and the linter (a version-neutral model of Swagger 2.0 and OpenAPI 3.x, source positions, OpenAPI schemas as JSON Schema 2020-12, SARIF output). |
| `anvil-identity` | Interactive identity flows: the OAuth authorization-code + PKCE sign-in to a target API (loopback redirect) and optional provider accounts linked to a profile (see [identity.md](identity.md)). |
| `anvil-load` | Open, closed and iteration workloads over the same engine; mergeable HDR histograms; balanced ledgers; generator health; the worker protocol; JSON, CSV and HTML reports; run comparison. |
| `anvil-runner` | Collection runner: scenarios and folders, datasets, chained extraction, stop-on-failure, JUnit/HTML/JSON reports. |
| `anvil-app` | Services shared by the desktop and CLI: profiles and unlock, the workspace tree, revisions, environments, secrets, profiles, the history policy, send and record, export and import, full backups (one encrypted, authenticated file; see [storage-and-recovery.md](storage-and-recovery.md)), spec import, load plans and runs, and scenarios. |
| `anvil-cli` | The `anvil` command-line client. |
| `anvil-lab` | Real-gateway failure laboratory: the pinned Ferrum Edge binary, profile configs, fixtures, operator-log ground truth, and trusted/untrusted passes. |
| `anvil-fixtures` | Controllable test peers: HTTP(S) routes, raw fault modes, TLS servers, WS, gRPC with reflection, SSE, TCP/UDP, DTLS, DNS, and an OAuth IdP. |
| `apps/desktop` | Tauri 2 shell (`src-tauri`) and React UI (`src`). |

## One execution, end to end

1. **Freeze the context.** `anvil-app` freezes an `ExecutionContext`: the
   request spec (draft or saved revision), the variable layers (workspace →
   environment → folders; runs add iteration layers on top), the settings
   layers (app → workspace → folders → request → run), auth inheritance,
   TLS/proxy/integration profiles, and a secret resolver scoped to the
   workspace's own vault
   (`exec::ResolvedSecrets`). The secrets of the spec, the effective auth and
   the selected profiles are looked up now; any other secret when the engine
   uses it. All fail closed once the profile locks.
2. **Prepare.** `anvil-engine` interpolates, lints the body (block or warn),
   serialises it, infers the content type, and then applies auth over the
   final bytes. HMAC digests and DPoP proofs are regenerated on every send.
3. **Send and observe.** `anvil-transport` resolves, connects, negotiates TLS
   and ALPN, writes the request and reads the response. It records each phase
   with a status (completed, failed, timed out, reused, not applicable) and
   tracks written bytes, so dispatch is never guessed from error text.
4. **Assemble the record.** The engine combines attempts (redirects and safe
   retries) into one redacted `ExecutionRecord` with three separate
   dimensions: transport completion, application status and assertions.
   See [Partial bodies](#partial-bodies) for what happens when only part of
   the body is available.
5. **Diagnose.** `anvil-diagnostics` turns the typed evidence into findings.
   It uses Ferrum markers only for destinations declared as Ferrum gateways,
   caps their confidence (see [diagnostics.md](diagnostics.md)), and orders
   hop-specific findings before the generic status-code explanation.
6. **Store.** `anvil-app` stores the record in encrypted history. Response
   bodies are kept only if the history policy allows it.

### Partial bodies

A whole-body check never passes on a prefix, and a prefix never publishes a
shortened value. The record keeps two things apart:

- **Wire completeness.** Only a prefix is available when the body exceeded
  `limits.capture_bytes`, or an HTTP response ended before its framing
  completed, was canceled, or stopped at `max_response_bytes`. For a streaming
  session (WebSocket, gRPC stream, SSE, TCP, UDP), which ends on its own
  terms, only the capture limit counts.
- **Content decoding** (`response.body.decoding`). Decoding is not complete
  when it stops at `max_decoded_bytes` (`truncated_at_limit`), when the bytes
  do not decode or data follows the end of the compressed stream (`failed`;
  a gzip body may still hold several members and a zstd body several frames),
  or when the coding is unsupported, including bogus codings such as
  `Content-Encoding: none` (`unsupported`). Encoded bytes that are only a
  prefix of the body are never `complete`, even when they decode cleanly: a
  prefix cut by a local limit is `truncated_at_limit`, and one the peer or a
  cancel cut short is `failed`.

In either case:

- body assertions fail with "could not evaluate" and body extractions are not
  run;
- status, header, trailer, latency and transport assertions still run;
- a `partial_visibility` warning names the gap when the request has
  assertions or extractions.

When decoding is incomplete, a response below HTTP 400 gets the application
status `not_evaluated`. A SOAP or GraphQL request reports its fault or errors
in a 2xx body, so when only a prefix of that body was captured its application
status is also `not_evaluated`, never `success`, with a `partial_visibility`
warning. Other requests are judged by their status, which a prefix does not
hide. A collection run keeps a content-encoded body in history only under the
rules in [runner.md](runner.md#redaction).

## Data contracts

`anvil-domain` is the single source of truth (with the lint report of
`anvil-contract`). `anvil schema` writes
`contracts/schemas/*.schema.json`, and `npm run contracts` (in `apps/desktop`)
generates `apps/desktop/src/generated/contracts.ts`. CI regenerates both and
fails on drift.

## Where to read next

- [adr/](adr/): architecture decisions and their rationale.
- [threat-model.md](threat-model.md): assets, trust boundaries and mitigations.
- [diagnostics.md](diagnostics.md): the evidence model, confidence rules and the Ferrum catalog.
- [storage-and-recovery.md](storage-and-recovery.md): the vault, recovery, backups and migration.
- [g01-gateway-diagnostic-contract.md](g01-gateway-diagnostic-contract.md): the proposed gateway contract.
- [protocols.md](protocols.md), [import.md](import.md), [contract.md](contract.md), [load.md](load.md), [runner.md](runner.md), [identity.md](identity.md), [lab/](lab/).
