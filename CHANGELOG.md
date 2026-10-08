# Changelog

## [Unreleased]

### Added

- Adopt published `contracts-edge-0.9.14` (`ddbdd845733b7046c4393ac951011dafb774db33`)
  byte-exact. Four vendored files change: the gateway error and header vocabularies
  (v0.9.14 provenance and reclassification notes, with the same tokens, classes and diagnostic
  headers), diagnostic-ref provenance and the canonical negative-expectations manifest. The
  diagnostic-report schema and every diagnostic fixture are unchanged.
- Add the separately source-audited Edge v0.9.14 catalog and release-asset locks at
  `9bd4d5f9caa4ebe8f0ea13e76d8a6e2172eaca7d` (release 405571232), selected as the lab and
  new-profile candidate default pending hosted Anvil gates. v0.9.12 and v0.9.13 are covered by
  the audit, not pinned. v0.9.11 and the earlier catalogs and locks stay supported, and the
  nightly lab now also runs v0.9.11. See `docs/audit/gateway-0.9.14-delta.md`.

### Changed

- Gateway catalog 0.9.14: a buffered-collector read error answers the eager collector's
  502 `{"error":"Backend response body read failed"}`, so that body is ambiguous between the two
  collectors on 0.9.14 and the old `{"error":"Backend response read error"}` body is matched only
  on earlier releases. Backend HTTP/2 resets now logged `protocol_error`, the early-upload
  route-timeout phase, request-buffer `RESOURCE_EXHAUSTED` alignment, HTTP/3 buffer admission and
  client-reset upload handling are recorded on the existing outcomes without changing their
  public signals.
- Lab UP-018 expects the direct-H1 connection-ceiling signal from v0.9.11 through the pinned
  release instead of on the pinned release only, so the retained v0.9.11 keeps its signal now
  that the pin is v0.9.14.
- Name Ferrum Edge LLC as the copyright holder and commercial licensor in `LICENSE` (Required Notice, previously "Ferrum Foundry"), `LICENSE-COMMERCIAL.md` and the desktop bundle copyright.

### Fixed

- Lab MESH-011 reaches the Ambient gateway again (#341). Its TEST-NET target `192.0.2.10` was
  refused locally by the destination policy added in #308, before the CONNECT was sent, so the
  scenario failed instead of proving the gateway's refusal. It now targets the unrouted
  benchmarking address `198.18.0.10`, which the policy admits and no lab workload declares, and
  asserts that no local refusal occurred. The policy itself is unchanged.

## [0.1.3] - 2026-10-06

Storage and desktop hardening release: request revisions, history records and load reports are
bound to the workspace that owns them (database schema 3, which earlier builds cannot open), the
desktop's native dialogs are shown only by the backend, and bundle and backup imports check a
file before reading all of it. Read the Breaking section below before upgrading.

### Security

- Request revisions are sealed together with the workspace and request that own them, and are
  read only while that request still belongs to that workspace. History records and load
  reports are read only under the workspace (and, for history, the request) sealed in them, on
  every read path, and a write must index them under that owner. A history record is also
  sealed together with the response body it references and is read only with that body. A
  write never replaces a stored history record or load report under another owner. See
  [docs/security/workspace-owner-binding.md](docs/security/workspace-owner-binding.md).
  - The database schema moves from 2 to 3. At the first open or unlock (or when a checkpoint
    from an earlier schema is restored), each existing revision whose request authenticates and
    belongs to the workspace it is filed under is sealed again under that workspace, and each
    existing history record that opens under its owner is sealed again with its body, in one
    transaction with the version bump. Every revision that schema 2 could read, and every history
    record an earlier build wrote, stays readable. Any other revision or record is left as it
    was, is refused and is never adopted; the number left is logged and recorded in the
    database's `meta` table (`revisions_left_at_v3`, `history_left_at_v3`). A database whose
    recorded version was set back below 3 is refused and the profile stays locked.
  - Before that step, a `before-schema-3` checkpoint of the database is taken in the profile's
    `checkpoints` folder. If it cannot be written (for example, the disk is full), the
    migration does not run and the profile does not open or unlock until space is freed.
  - A profile-wide read that meets a history record or load report failing these checks names
    its id, so it can be found and deleted.
- The desktop webview no longer holds the dialog plugin's `allow-message` and `allow-ask`
  permissions; native dialogs are shown only by the backend. The webview's confirmations
  (closing a tab with live work or unsaved edits, sending an invalid body, deleting, relocating
  a linked file over unsaved edits) are drawn inside the window, and the desktop UI no longer
  depends on the `@tauri-apps/plugin-dialog` npm package (#319).

### Breaking

- Storage: earlier builds (0.1.0 to 0.1.2, database schema 2) refuse a profile database once
  0.1.3 has opened or unlocked it, and a full backup made by 0.1.3, as written by a newer
  version. Portable bundles keep their format (2) and object schema, so a bundle exported by
  0.1.3 still imports into earlier builds. Close every earlier build before upgrading: one that
  still has the profile open keeps writing revisions and history records the old way, and once
  the database is at schema 3 those rows are refused until they are deleted. To go back to an
  earlier build, restore the `before-schema-3` checkpoint as described in
  [Going back to an earlier build](docs/storage-and-recovery.md#going-back-to-an-earlier-build);
  everything changed since the upgrade is lost.

### Added

- Settings → Storage shows the last storage cleanup on request, runs one now, and lists
  stored revisions whose own payload does not decode. Such a revision survives its request's
  or workspace's delete and blocks every cleanup release. A damaged one (it decrypts under
  neither the schema 3 nor the schema 1 revision seal) can now be removed, alone or all
  together, once the user confirms it in the backend's native dialog, behind one checkpoint of
  the profile that keeps them; one that decrypts under either seal but that this version cannot
  read (a newer Anvil may have written it) is kept (`App::undecodable_revisions`,
  `App::remove_undecodable_revisions`; desktop `storage_undecodable_revisions`,
  `storage_revisions_remove`, `storage_cleanup_now`) (#319).

### Changed

- Importing a bundle or full backup checks the start of the chosen file before reading the
  rest: a backup whose header cannot be opened, or chosen without a passphrase, is refused
  unread, and anything else is read only up to the largest bundle (the 256 MiB budget plus
  64 MiB of zip framing, `MAX_BUNDLE_FILE_BYTES`, also enforced by `bundle::open`) instead of
  2 GiB (#319).
- Stored objects are decoded once per read instead of twice (the identity check's decode is
  reused), and a list of revisions reads each revision's request once (#319).
- The storage cleanup decrypts no revision to look for orphans while no revision or request row
  has been added, removed or written since a pass that left none (#319).

### Fixed

- The workbench forgets the session attempts whose end it waits for when the profile locks, so
  a closed tab's session whose end event the lock kept from the window is not kept for the rest
  of the session. An open aborted while still pending is still cancelled once it resolves (#319).

## [0.1.2] - 2026-10-06

Security hardening release covering renderer authority and native confirmations, linked-file and
export path handling, OAuth HTTPS-only policy, redirect and cookie policy, bundle and spec limits,
and diagnostic import off the UI thread.

### Security

- Bound retained HTTP state and authorize resolved destinations (PR #308;
  GHSA-jq6r-57w6-qp5w, GHSA-8g83-498m-r38r, GHSA-xmww-2phg-v997). The policy is in
  [docs/security/http-state-and-destination-policy.md](docs/security/http-state-and-destination-policy.md).
  No released version is claimed patched.
  - Cookie jars are bounded: 4 KiB per incoming `Set-Cookie` value, 8 KiB per retained
    cookie, 180 cookies / 128 KiB per registrable site and 3,000 cookies / 2 MiB per
    workspace. Expired cookies are purged on access, and the least recently used are
    evicted first. All outgoing `Cookie` fields together are capped at 8 KiB after
    signing, on every HTTP attempt, SSE reconnection, gRPC reflection call and MASQUE
    CONNECT.
  - OAuth token requests for every grant and refresh require HTTPS, or literal-loopback
    HTTP on a direct connection. The check runs before any credential is resolved, in
    the engine sink, the App load preflight, the load producer and worker, and browser
    sign-in/status.
  - Every direct HTTP attempt resolves once, validates the whole answer and pins it
    into the dial and the connection pool key. The key sorts the answer, so round-robin
    DNS keeps connection reuse. The original request is authorized for the network
    zones of its answer, so Tailscale, mDNS, NAT64 and fake-IP first requests work.
    Redirects stay within those zones or go wholly public. After any public hop, only
    public hops follow. A fake-IP redirect must return to the original host. Well-known
    NAT64 addresses are classified by their embedded IPv4; operator-specific NAT64
    prefixes are treated as public.
  - Vault variables that are deferred until the OAuth endpoint is validated fail
    closed with a clear error in resolvers that lack the context's secrets, instead of
    resolving to an empty string.
  - **BREAKING:** cookie eviction and output omission can end sessions or change load
    results, and unknown suffixes use host-only cookies.
  - **BREAKING:** `localhost`, DNS names, loopback DNS overrides and proxied routes no
    longer qualify for a cleartext OAuth token endpoint. Use HTTPS, or a literal
    loopback address that the proxy's `NO_PROXY` list bypasses.
  - **BREAKING:** the following are refused: redirects through any proxy (including
    same-host redirects), redirect answers that mix public and non-public zones,
    returns to a non-public zone after a public hop, and original requests to special
    or reserved addresses (including `0.0.0.0`). A load plan whose unit depends on an
    OAuth-deferred vault URL is refused before traffic.
- Linked-file reads and granted file reads and exports no longer follow a symlinked
  ancestor directory. The chosen path is walked one folder at a time without following
  a link (on Unix `openat` with `O_NOFOLLOW | O_DIRECTORY`, then the file is opened,
  created and renamed relative to the opened folder). On macOS a single open refuses a
  link at any folder on the path (`O_NOFOLLOW_ANY`): a file is read by opening it
  directly and an export opens only its own folder, so no folder above a chosen file
  (such as Documents, Desktop or a removable volume) is opened. This needs macOS 11 or
  later, which the desktop bundle now requires. On Windows each folder on the path is
  opened as itself, refused if it is a symbolic link or junction, and held without
  delete sharing until the operation is done. An export also checks that its folder is
  still the one chosen, and a failed export removes only a temporary file it created.
  Size limits, grant semantics and error messages are unchanged. On Windows and on Unix
  other than Linux and macOS, every folder on a chosen path must be one Anvil can list
  (on Windows, open for reading): a path through a folder it may traverse but not list
  is refused.

- Portable bundles (GHSA-jqq4-v58m-6fcw): an untrusted bundle can no longer
  make preview or import exhaust memory. The owner-delegate policy of
  2026-10-06 ([bundle resource policy](docs/security/bundle-resource-policy.md))
  sets these limits for import and export:
  - 256 MiB total and 128 MiB per entry, down from 1 GiB and 512 MiB. The
    manifest, checksum list, objects, history, attachments and sealed vault
    share the per-entry limit.
  - 4,194,304 JSON values across every JSON entry, counted from the text
    before anything is parsed. A bundle of about 1 MiB could otherwise
    expand to about 5 GiB of parsed JSON.
  - The ZIP end record's entry count and directory size are checked before
    the directory is indexed, and ZIP64 archives are refused.

  Every limit is inclusive: one byte, value or entry over is refused. An
  export over any limit is refused in preview and write, naming the entry,
  and is never split. A file over 128 MiB is now refused when it is attached.
  An export that holds such a file attached earlier fails, naming the file
  and the request or dataset that holds it. So does an export whose attached
  file is a ZIP64 archive that would carry its end records into the bundle,
  which import would refuse.

  **Migration:** bundles exported by 0.1.x that are over 256 MiB, have an
  entry over 128 MiB, or hold more than 4 Mi JSON values no longer import.
  The error reads "archive exceeds safety limits" and names the entry. To
  move such a workspace, open it in the Anvil that exported it and export
  again in smaller parts:
  - one workspace per bundle;
  - without history;
  - with large files linked rather than attached.
- Desktop: session, send and collection-run payloads (live messages, final
  responses and detailed errors) from work started before a lock or profile
  switch are no longer delivered after it, even once the profile is unlocked
  again. Cancelling a session also interrupts a send waiting on its command
  queue (GHSA-mg45-vx3j-wmq8).
- Desktop: a spec import or reimport applies exactly the source bytes and
  plan that were reviewed, for the same profile session and destination. A
  source that changed after review, or a stale review, is refused before
  anything is written (GHSA-3793-f3j3-mjpr).
- Desktop: replacing the profile passphrase, converting a keychain profile to
  a passphrase, lifting a workspace's device-identity seal, opening an
  imported collection to its workspace, moving a request or folder out of an
  imported collection that is not open to its workspace, and weakening the
  lock policy (a longer or no idle timeout, no lock on sleep, no clipboard
  clearing) now go ahead only once the user confirms them in a native dialog
  that the backend shows itself. A full-backup restore keeps the profile's
  lock policy when the backup's is weaker, and the desktop then offers the
  backup's in the same kind of dialog. Saving a folder no longer moves it.
  Names from the webview (profile, workspace, folder, request) appear in
  these dialogs on one line, without control or format characters, with at
  most two Unicode Mn/Me combining marks in a row, and cut to 64 characters. Declining refuses the change with `NOT_CONFIRMED`; no
  webview argument stands in for the answer, each answer covers one change,
  and a lock while the dialog is open refuses it. Strengthening changes are
  not asked about, and the passphrase change right after a recovery-key
  unlock needs no extra confirmation. The webview's activity reports now
  postpone the idle lock only within four hours (or the idle timeout, if
  longer) of the last native sign of the user: an unlock, a native
  confirmation or the window gaining focus (GHSA-hrwp-5q93-w52f).
- Desktop: a request draft sent from the webview (send, interactive session
  or OAuth sign-in) that carries vault-backed authority (auth in effect,
  vault references, secret variables or a TLS client identity) uses it only
  where its saved request would: the same destination origin, request
  authority (an explicit Host header included), MASQUE route, auth and
  connection settings, worked out in the backend from the very context it
  then executes. A destination, Host or MASQUE route that a per-send value
  (`{{$randomFrom}}`, `{{$randomInt}}`, `{{$counter}}`, `{{$uuid}}`, a
  timestamp) reaches is never taken as matching, since each send draws it
  again. Otherwise, and for a draft without a saved request, the user must
  confirm it in a native dialog for that one use; the dialog names the
  destination first, then the workspace and what differs from the saved
  request (destination, Host, DNS overrides, proxy, TLS profile and
  verification, auth kind and placement). An OAuth sign-in runs exactly the
  context that was checked. The desktop's send, preview and session
  commands no longer take a per-send settings override (`run_override`,
  which the desktop UI never set; the CLI keeps its own). A draft's
  request-level connection settings come from the webview and are compared
  against the saved request; workspace and profile settings apply to both.
  Secrets are resolved only in the backend and never returned to the webview.
  Drafts without vault-backed authority retain existing behavior.
- Desktop development dependencies: an npm override moves WebdriverIO's
  `@puppeteer/browsers` from 2.13.2 to 3.2.3, which drops `extract-zip`
  2.0.1 (GHSA-7pqw-9j4j-h8q3, GHSA-jmr9-qjv8-65gv; no patched release) and
  its `yauzl` chain, plus 2.x's `proxy-agent`, `tar-fs` and `progress`
  subtrees, from the lockfile (#232). It is used only by the E2E tooling and
  is not shipped. `@puppeteer/browsers` 3.x requires Node.js 22.12 or newer,
  so the desktop app's `engines` floor is now `>=22.12`.

### Breaking

- Desktop IPC: `session_open`, `session_send` and `session_cancel` require an
  `attemptId` (a fresh, non-nil UUID for each open) alongside `executionId`,
  and SEND/CANCEL must pass the `attemptId` of the open they control.
  Interactive-session `execution-event` and `session-ended` packets carry the
  matching `attempt_id`. Calls without it are rejected before any work starts.
  OPEN still returns the execution-id string; session command bodies and the
  domain and CLI event shapes are unchanged. The bundled Workbench already
  does this. See the
  [upgrade guide](docs/upgrade-guide.md#interactive-session-attempts).
- Desktop IPC: spec import and reimport apply only what was reviewed.
  `spec_preview` requires `target` and returns an `approval`, which
  `spec_import` now requires. `spec_reimport_plan` returns `{ plan, approval }`
  instead of a bare plan, and `spec_reimport_apply` takes the overwrite/delete
  choices as `decisions` (previously `approval`) plus that `approval`. The
  bundled import dialog already does this; the CLI is unchanged. See the
  [upgrade guide](docs/upgrade-guide.md#spec-import-review-approvals).

### Fixed

- Storage: validate sealed object IDs, workspace owners and parents against
  row metadata, and reject existing-owner changes in transactional saves.
  Folder/request moves retain their relationship checks. User-visible
  changes: full backups exclude authentic orphan revisions (listed in the manifest); saving
  a request with a changed workspace now errors; creating or saving a folder
  refuses a foreign parent; spec reimport now deletes the removed requests'
  revisions and releases their attachments; undecodable revisions are kept and
  block attachment cleanup. See `docs/security/workspace-owner-binding.md`.
- Repair Edge 0.9.11 adoption controls: use a deliberately unsupported release sentinel,
  assert all six supported record catalogs and include 0.9.11 in timeout/token expectations.
  UP-018 now requires the exact version-specific H1 ceiling signal and keeps independent
  no-probe/recovery evidence, ambiguous diagnosis, confidence ceilings and lookalikes.
  Untrusted marker observations are explicitly confirmed with unknown scope, without
  gateway token/outcome attribution; all other public Ferrum findings stay at most likely.
  Apply the hosted Linux formatter diff to the changed Rust files.
  Correct the new catalog's shipping panic citations and retained reqwest condition.
  Record hosted qualification of source `28876cc6623fdba01289b450fe12c7c16649b655` with
  [CI run 37245583522](https://github.com/ferrum-edge/ferrum-anvil/actions/runs/37245583522)
  (all applicable gates successful) and
  [Desktop E2E run 37245583544](https://github.com/ferrum-edge/ferrum-anvil/actions/runs/37245583544)
  (Ubuntu, macOS and Windows successful). The
  [PR Lab run 37245583561](https://github.com/ferrum-edge/ferrum-anvil/actions/runs/37245583561)
  passed `core` only. Root's actual manual `all` / `v0.9.11`
  [Lab run 37245804710, attempt 1](https://github.com/ferrum-edge/ferrum-anvil/actions/runs/37245804710/attempts/1)
  succeeded: Ubuntu 554 passed / 0 failed / 21 predefined skips; macOS 558 / 0 / 19.
  Trusted and untrusted UP-018 passed on both; `admission` was 8 / 0 / 2 on each.
  The audit retains exact skip reasons in `docs/audit/gateway-0.9.11-delta.md`. These results qualify
  that source; root's whole-record review and fresh exact-head hosted CI for this subsequent
  documentation commit remain pending. No Anvil release/tag, platform signing, OAuth,
  physical-device native acceptance, provider-account or broader performance acceptance is
  claimed. Published unsigned `anvil-v0.1.1` remains unchanged; other owners' pending proposals
  are not adopted. This record changes no source, historical catalog, PIN, lock, golden,
  test or workflow bytes.
- Release checks inspect ordinary Type 2 AppImages as data: trusted isolated
  Python reads and validates ELF metadata, then trusted `unsquashfs` extracts
  the filesystem. Missing tools, unsupported formats, malformed metadata,
  extraction errors or a missing `AppRun` fail closed. The intentional
  `--runtime-probe` remains a separate explicit opt-in that launches the
  extracted `AppRun`.

- Desktop security: PEM selection uses purpose-bound native choosers.
  Certificate reads return validated certificate PEM and refuse key material;
  private-key grants are consumed once into the workspace vault, returning
  only a secret reference to the renderer. A PEM file that combines a
  certificate and a private key is refused by the certificate picker; split it
  into a certificate file and a key file first (see
  [docs/identity.md §9](docs/identity.md#9-client-certificates-mtls-pem-files)).
- Portable bundles: validate archive declarations and mandatory manifest,
  checksum, format, schema and vault metadata before expanding payloads.
  Charge the remaining aggregate budget before allocating each entry,
  verify actual ZIP sizes against declarations, and hash attachments during
  reading without retaining a second copy. This fix kept the 1 GiB total and
  512 MiB per-entry limits; the bundle resource policy under Security has
  since lowered them to 256 MiB and 128 MiB. It addressed the
  validation-order and accounting part of GHSA-jqq4-v58m-6fcw.
- Load preflight: iteration variables, dataset columns, values extracted by
  earlier chain steps and dynamic helpers in the path, query, method, headers
  or body of a fixed origin no longer stop a plan (#288). The preflight judges
  each URL origin, with every per-run value layered above
  workspace, environment and folder variables as the worker layers it, and a
  repeated chain step sees what its earlier positions extracted. For HTTP and
  every session protocol (WebSocket, SSE, gRPC, MCP, TCP, UDP and a MASQUE
  proxy URL), a per-run value that reaches the URL's scheme or host is
  refused, naming its source but never its value. A per-run port is allowed
  only after a fixed loopback host. Locality now uses the execution parser
  and connector's fixed literals/overrides with IP-family filtering.
  `localhost` and `*.localhost` count as loopback with the system resolver
  unless an override is configured, in which case its addresses are checked;
  custom DNS and other unpinned names still require remote-traffic consent
  without a preflight lookup, preventing DNS rebinding and resolver waits.
  Proxy-resolved target names remain unproven despite client overrides, and
  proxy addresses use the connector's host spelling. HTTP forward-proxy
  authority checks cover HTTP/1.1 and h2c with fixed, templated and auth-written
  Host headers; per-run Host values/names require the warning. Session protocols
  use their actual CONNECT target. MASQUE requires the canonical routing
  template for local classification; custom or per-run templates require the
  warning even with loopback target and proxy origins. OAuth token endpoints use
  the same origin, fixed-address and NO_PROXY checks; external-browser
  authorization names remain unproven. Nested conflicting OAuth profiles
  are refused consistently before acquiring any token, while valid
  single-OAuth multi-auth remains supported (#295, #296). Empty optional
  OAuth authorization URLs are skipped; present values are still checked.
- Desktop imports: refresh the selected workspace's environments, profiles,
  history and request tree after a spec import or bundle import. Open tabs for
  replaced requests now reload when clean; unsaved drafts and running sends or
  sessions are preserved safely.
- Diagnostics: `tcp.reply_after_half_close` now uses the retained stream transcript to verify that received bytes followed Anvil's half-close, and reports only those bytes. Missing transcript evidence no longer produces a chronology claim (#285).
- Diagnostics: cancellation findings now use the local-client scope only when
  dispatch recorded no request bytes; canceled requests that may have reached
  the peer use the client-to-peer scope.
- DTLS over MASQUE: when the tunnel ends while a handshake flight is being
  written, the failure is now always `DtlsHandshakeFailed` in the
  `DtlsHandshake` phase, with the write error as its message. It used to be
  `RequestWriteFailed` or `DtlsHandshakeFailed` depending on which side
  noticed first (#270).
- Desktop: the update dialog shows release notes as readable text instead of
  raw Markdown. GitHub callouts read "Warning: …", emphasis, quote, heading
  and code markers are dropped, bullets read "•" and links read
  "text (url)". The notes are still text: nothing is rendered as markup and
  links are not clickable.
- The ignored Python `websockets` permessage-deflate interoperability test
  now runs on `websockets` 14 and 15 as well as 13.x: its fixture
  feature-detects the negotiated extensions (`.extensions` on 13.x, the new
  asyncio `ServerConnection.protocol.extensions` on 14/15), and the supported
  version range is documented where the run instructions live (#275).
- Desktop: switching a request to MCP now saves the default `tools/list`
  operation, so the editor shows exactly what will be sent and Send no longer
  refuses a new MCP request for missing settings (#286).
- Desktop: choosing `.proto files…` as the gRPC schema source now records it as
  `proto_files`, not a descriptor set, even though the controlled select
  re-renders while the native dialog is open; the choice is merged into the
  latest draft rather than one captured before the dialog opened (#287).
- Desktop: the vault-authority confirmation dialog tells two identically named
  proxy or TLS profiles apart with a short id suffix, and when the difference
  is past the third DNS override it says how many more differ instead of
  falling back to the generic "connection settings differ" line (#319, N4).

### Added

- Adopt published `contracts-edge-0.9.11` (`390edbd5b2485af0988e02f7827fde778d76ae0a`)
  byte-exact, with the accepted unchanged EXISTING shared v1 freeze and strict original
  diagnostic negative expectations, reader vocabularies and producer description parity.
  Read-only preview stays unverified/unknown; the real historical Alloy golden is unchanged.
- Add the separately source-audited Edge v0.9.11 catalog and actual release-asset locks
  at `c764084b3b51c3f7ffde268c039688d35e49c553`, selected as the lab/new-profile
  default qualified at source `28876cc` by the hosted runs above. Preserve 0.9.5/7/8/9/10
  catalogs, locks and nightly coverage. Record lifetime/cancellation, timeout, H1 headers/pooling
  and plugin deltas in `docs/audit/gateway-0.9.11-delta.md`, including the source qualification
  and its limits.
- Desktop diagnostics: a read-only JSON import preview for shared diagnostic-report,
  finding and reference v1 contracts, plus Alloy CLI JSON. Bounded browser file/paste
  input and a stateless IPC parser preserve redacted producer facts as unverified
  claims with unknown Anvil confidence, including forged authentication claims.
  Pins the additive `contracts-edge-0.9.9-r2` contracts and a real immutable Alloy
  hosted exporter golden. No requests, persistence, vault access or Edge lookups
  follow an import (ferrum-edge/ferrum-alloy#27; cross-repo qualification pending).
- Diagnostics: a `ferrum-edge-0.9.10` compatibility catalog for Ferrum Edge
  v0.9.10 (553 source-audited outcomes, `docs/audit/gateway-0.9.10-delta.md`).
  It knows the release's new `ai_prompt_shield` MCP refusals: `400`
  `{"error":"MCP request body could not be inspected"}` with message
  `unsupported_charset` for a non-UTF-8 request charset (GHSA-4f9m-cfqg-fhx9)
  or `jsonrpc_request_unparseable` for a body it could not parse that may
  still carry a tool call (GHSA-f2jp-59r9-fp64), and records that
  `mcp_gateway` answers a non-UTF-8 charset with its JSON-RPC `-32600`.
  It also records `unsupported_content_encoding`, a refusal Edge has sent
  since v0.9.9. Issue #282 backfills it into the 0.9.9 catalog as well; the
  0.9.8 catalog still does not match it. Profiles declaring v0.9.9 match this
  existing refusal but do not match the two new v0.9.10 refusals.
- Diagnostics: a `ferrum-edge-0.9.9` compatibility catalog for Ferrum Edge
  v0.9.9 (553 source-audited outcomes, `docs/audit/gateway-0.9.9-delta.md`).
  It knows the release's new public signals: the `400` refusals of an empty
  path segment and of a `;` path parameter on a route without
  `allow_path_parameters` (GHSA-fcqw-793q-wg5x), the `421 Misdirected
  Request` of a retired Gateway listener, the MCP JSON-RPC refusals
  `-32014` (request changed after admission) and `-32015`/`-32016`/`-32017`
  (`rate_limiting` tool-call limits), the `ai_prompt_shield` MCP argument
  refusals, the WebSocket `permessage-deflate` negotiation `502` and `1007`
  close, and OpenAPI-bridge tool results whose text names a gateway error.
  Profiles declaring an older release do not match them.
- Diagnostics: Ferrum Edge v0.9.9's gateway diagnostic references (G01,
  #224). A Ferrum gateway profile can configure a diagnostic reference lookup
  (the admin listener URL, a token held as a vault secret or template, and
  optionally the gateway's namespace; desktop profile dialog). For a trusted
  gateway's response that carries `X-Ferrum-Diagnostic-Ref`, Anvil calls
  `GET /diagnostics/v1/refs/<ref>` as the response arrives and uses the
  `ferrum.diagnostic_ref.v1` record only when it binds to that response
  (reference, status, token, protocol, namespace, creation time). The new
  `ferrum.detail.*` findings cite it as `gateway_detail` evidence and are the
  only Ferrum findings that can be `confirmed`, and only when the request and
  the lookup both used verified TLS or a direct loopback connection.
  Refused (`401`/`403`), unknown or expired (`404`, with any owner-replica
  hint), rate-limited, malformed and mismatched lookups are reported and keep
  the public evidence's confidence. The header alone is never trusted, and
  the token is sent only to the admin listener, redacted, and never logged
  or recorded. The admin URL must be `https` (always verified, whatever the
  request's TLS profile bypasses or overrides) or plain `http` to a loopback
  address literal, or the lookup is refused before sending; it is bounded
  at 2 s to connect and 5 s in all, retries once when the record has no
  detail yet, and never follows a redirect. A record must carry every key
  the schema requires, and one with an error class outside the pinned
  vocabulary is capped at likely. Bundle imports drop gateway profiles'
  lookups with a warning, and a full backup restore keeps them paused
  ("diagnostic lookup paused" on the record) until the restored workspace is
  allowed on this device, the same seal as the device's workload identity;
  an imported profile that
  covers an existing profile's hosts is reported, and a record names the
  profile used when several match its destination.
- Failure matrix: TRUST-009 (cross-tenant lookup), TRUST-010 (expired
  reference) and TRUST-011 (spoofed reference) are no longer blocked: engine
  tests cover them, and on Ferrum Edge v0.9.9 and later the lab's `core`
  profile turns references on (`FERRUM_DIAGNOSTIC_REFS=all`), signs
  `diagnostics:read` tokens with an `ns` claim, and runs them with G01-001
  and G01-002 against the real gateway (skipped on earlier releases).

### Changed

- Desktop: macOS 11 is now the minimum supported version.
- Documentation: link Anvil's contract pin to the immutable Ferrum contract
  release and describe the central store, consumed files and re-vendoring rule.
- Documentation: reconcile the completion report's current-state statements
  with `main`: 14 lab profiles including `mcp`, the four supported Edge
  releases (0.9.5/0.9.7/0.9.8/0.9.9), eight `X-Gateway-Error` tokens from
  0.9.8, and the published `anvil-v0.1.1` preview assets, checksums and
  updater signatures against still-missing platform signing (#276).
- CLI help: `spec-drift --import` now points to the import id printed by
  `import-spec` (there is no `--json` flag), and `doctor` lists the checks it
  performs (data dir, system trust store, profiles, engine/catalog) instead of
  claiming a keychain self-check (#277).
- Keychain unlock now explains when macOS refuses access to a stored profile key
  after an app update, and how to allow Ferrum Anvil in Keychain Access and retry.
- REL-003 records the verified signed in-app update from 0.1.0 to 0.1.1 on
  macOS arm64, with the release runs and updater key evidence; Windows and Linux
  remain untested.

- New Ferrum gateway profiles default to `ferrum-edge-0.9.10` (desktop dialog
  and CLI), and the failure lab's default pin is Ferrum Edge v0.9.10
  (`lab/gateway/RELEASE.lock`, the release's published sha256 for every
  asset). v0.9.9, v0.9.8, v0.9.7 and v0.9.5 stay supported with `--release`;
  the nightly lab runs all five. No lab scenario changes: the lab sends no
  non-UTF-8 charset and configures no `ai_prompt_shield`. The vendored
  contracts stay at `contracts-edge-0.9.9`, which `ferrum-contracts` maps to
  Edge v0.9.10 too; the contract drift test now checks the 0.9.9 and 0.9.10
  catalogs against it. `anvil-lab` lists supported releases in version order
  (`v0.9.10` after `v0.9.9`).
- New Ferrum gateway profiles default to `ferrum-edge-0.9.9` (desktop dialog
  and CLI), and the failure lab's default pin is Ferrum Edge v0.9.9
  (`lab/gateway/RELEASE.lock`, the release's published sha256 for every
  asset). v0.9.8, v0.9.7 and v0.9.5 stay supported with `--release`; the
  nightly lab runs all four. On v0.9.9 the lab's AUTH-021 signs a path
  without `;` and checks that the `;` path is refused with `400`, and
  MESH-026/027 check that the gateway resets a UDP tunnel that ended on a
  socket error with `RST_STREAM(CONNECT_ERROR)`.
- The vendored Ferrum contracts move to `ferrum-contracts`
  `contracts-edge-0.9.9`, including the `ferrum.diagnostic_ref.v1` schema and
  fixtures. `X-Ferrum-Diagnostic-Ref` is released in Ferrum Edge v0.9.9: the
  0.9.9 catalog records it, and the contract drift test counts it among the
  headers Anvil reads and checks Anvil's lookup reader against the pinned
  schema.

## [0.1.1] - 2026-10-01

### Changed

- No functional changes. Released to exercise the in-app upgrade from 0.1.0
  (signed update, verified and installed by the app).

## [0.1.0] - 2026-10-01

### Changed

- The desktop API standards view and mutations return ruleset metadata and
  load status without source text. The selected ruleset's text is fetched on
  demand when its details are opened.

- Workspace bundles now omit profile-wide API standards unless explicitly
  included (`--include-standards` in the CLI or **Include API standards** in
  the desktop). Bundle imports keep those rulesets disabled, recompute their
  hashes, and enforce profile-wide limits together with local records.
- Bundle imports append new API standards records after existing ones. Replace
  keeps a matching local ruleset's enabled flag and position; only new
  rulesets arrive disabled. Full backups continue to restore their order and
  enabled flags.

### Added

- MCP (Model Context Protocol, JSON-RPC over Streamable HTTP) as a request
  kind (`protocol: mcp`, `RequestSpec.mcp`). One request is one operation
  (`tools/list`, `tools/call`, `resources/*`, `prompts/*` or any raw
  JSON-RPC request or notification) in a session of its own: the engine
  sends `initialize` and `notifications/initialized`, carries the
  `Mcp-Session-Id` and the negotiated `MCP-Protocol-Version`, reads JSON or
  event-stream answers to each POST, and ends the session with `DELETE`.
  Every exchange is an ordinary HTTP execution (auth per send, TLS and proxy
  profiles, limits, deadlines, cancellation, redaction). The session id is a
  credential: it is sent as a sensitive header and redacted in records,
  previews, history and exports. The record's notes say how the session
  went (server text in them redacted like the record); a failed handshake is
  the result, with the operation not sent and a session it opened still
  ended. One deadline, the request's total timeout, covers the whole
  session. See docs/protocols.md §3.14.
- Assertions `json_rpc_error {code}`, `json_rpc_result`, `mcp_is_error`,
  `tool_present` / `tool_absent` (in a `tools/list` result) and
  `tool_input_schema` (the listed schema, or its SHA-256 over sorted-key
  JSON). `json_path` reads the JSON-RPC response of an event-stream answer,
  so `$.result.structuredContent…` works for both kinds of answer.
- Diagnostics: a JSON-RPC error in a 2xx body is an application failure
  (`app.jsonrpc_error`, with the code's JSON-RPC 2.0 meaning), and so is an
  MCP tool result with `isError: true` (`app.mcp_tool_error`). With a trusted
  Ferrum profile, JSON-RPC errors are matched against the release catalog's
  `mcp_gateway` and `a2a_gateway` outcomes by status, code, message and the
  `data.gateway` marker (their bodies echo the request id, which no fixed
  pattern matched), so a `-32001` gets the `plugin.mcp_gateway.tool_denied`
  explanation; a matching code with another message is reported only as
  consistent with those outcomes (`ferrum.jsonrpc_code`).
- MCP "discover tools": `App::mcp_discover_tools`, `anvil mcp-discover
  <request>` and the desktop MCP tab's **Discover tools** run `tools/list`
  with a saved MCP request and save one request per tool beside it, with
  arguments from each tool's `inputSchema` (examples, defaults, constants,
  then blank required values) and checks that the call is a result the tool
  did not mark as an error. A tool name or argument text holding `{{` is
  never read as a variable reference. See docs/import.md.
- CLI: `anvil send --url … --mcp-list-tools | --mcp-call TOOL [--mcp-args
  JSON]` (and the same on `anvil add`) make an ad-hoc MCP request.
- Desktop: MCP in the protocol list, an MCP tab (operation, arguments,
  protocol version, client info and capabilities, session options) and the
  new assertions in the Tests tab.
- Lab: an `mcp` profile runs the pinned Ferrum Edge with `mcp_gateway` in
  aggregate-router mode in front of a fixture MCP server
  (`anvil_fixtures::mcp`): allowed, denied, hidden and unconfigured tools,
  schema validation of arguments, unknown tools, a request without a session
  and a tool's own error, each cross-checked with the catalog outcome and the
  calls that reached the server (docs/lab/mcp.md).
- Load: a plan with an MCP request is refused before traffic
  (`mcp_unsupported`); an MCP load unit is a follow-up.

- Desktop: update check and upgrade. **Settings → Updates → Check for updates
  when Anvil opens** (the existing `check_for_updates` setting, still off by
  default) asks the GitHub Releases API for the latest published
  `anvil-vX.Y.Z` release once per launch, after unlock; **Check now** asks on
  demand. A newer release shows a prompt (**Upgrade…** / **Later**) and an
  **Update** chip in the status bar. **Upgrade…** shows the release notes and,
  in a build that carries the owner's updater public key, downloads the update,
  verifies its minisign signature (`tauri-plugin-updater`), installs it and
  offers **Restart now**. A build without the key (every build until the owner
  configures it), and `.deb`/`.rpm` installs, open the release page instead.
  The app requires the signed version (`requireSignedVersion`), so an unsigned
  `latest.json` cannot pass an older signed build off as newer. The release
  workflow creates signed updater artifacts and `latest.json` only for a tagged
  release with that key, which lives in the protected `release` environment.
  The release workflow now signs only tagged releases (dry runs are unsigned)
  and, as defense in depth, keeps signing material out of the compile step:
  the updater key and the Apple credentials go to the `tauri bundle` step,
  and the Windows certificate is imported just before it and removed after.
  A manual release must run from its tag, and every job builds the tag's
  exact commit (docs/release.md, In-app updates). The launch check fails
  silently; the request carries only Anvil's version.
- Contract drift: compare observed traffic with an OpenAPI description
  (`anvil_contract::analyze`). Exchanges are routed to operations through
  the declared server base paths and checked for undeclared paths, methods,
  statuses, media types, request body types and query parameters; JSON
  bodies that do not match their schema; missing required parameters and
  response headers; deprecated operations; unknown servers; and calls slower
  or larger than an `x-anvil-expectations` budget. Findings are grouped with
  a count and a coverage table lists every operation. Suggested revisions
  are dialect-aware patches (additions recommended, relaxations not) with
  schemas inferred from the shape of observed bodies, never their values;
  undeclared paths keep only short lower-case words (other segments become
  parameters) and map keys become `*`. `revise` returns the revised
  description, an RFC 6902 JSON Patch and a digest; reimporting applies only
  the previewed digest.
- CLI: `anvil spec-drift <spec> --har FILE` (no profile) or
  `anvil spec-drift --import ID` (an imported spec's history) prints the
  report, writes `--revised`/`--patch`, and exits 2 at `--fail-on`.
- Desktop: an imported spec in the Contract view has a **Live traffic** tab
  (differences, suggestions to select, coverage, undeclared endpoints) that
  saves the revision or its JSON Patch (file purpose
  `spec_revision_export`) or reimports it as the import's new version after
  a preview. The response panel shows a **Contract** tab for a send of a
  request that belongs to an OpenAPI import.
- Diagnostics: vendor Ferrum contracts at `contracts-edge-0.9.8` and verify
  their SHA-256 pins in the offline CI suite. See
  [ferrum-contracts.md](docs/ferrum-contracts.md) for the pin and update steps.
- API standards: check OpenAPI descriptions against a team's own rules.
  A ruleset (YAML or JSON, `anvil_ruleset: 1`) targets version-neutral
  objects (operations, parameters, responses, media types, schemas,
  properties, servers, tags, security schemes, or any node by JSONPath) with
  checks such as `pattern`, `casing`, `enumeration`, `includes`, `length`
  and `schema`, so one standard applies to Swagger 2.0 and OpenAPI 3.0, 3.1
  and 3.2 alike. Rulesets layer in order, may extend the built-in
  `anvil:recommended` rules and change or turn off inherited ones, and are
  checked when loaded. Each finding names the rule, the JSON Pointer and the
  line and column to edit, and how to fix it; body examples are validated
  against their schemas. New crate `anvil-contract`; see
  `docs/contract.md` and `samples/api-standards/`.
- CLI: `anvil lint-spec <spec> [--ruleset FILE]...` prints text, JSON or
  SARIF 2.1.0 (for code scanning) and exits with 2 when a finding reaches
  `--fail-on` (default `error`), and with 3 on a local error, including a
  description too large to lint completely unless `--allow-incomplete` is
  passed. It needs no profile.
- Desktop: a **Contract** view checks the workspace's imported OpenAPI
  descriptions, or a chosen file, against the profile's API standards,
  filters findings by severity and exports JSON or SARIF. Rulesets are kept
  as separate encrypted records, added from a file (file purpose `ruleset`),
  replaced, enabled and removed there; each can be up to 1 MiB, with bounded
  count and aggregate size. Existing settings rulesets migrate on profile open.
  A change that would not load with the others is refused. The settings dialog
  never changes them. Rulesets travel in bundles and full backups.

- Desktop: a linked local file that a saved request names (for example one
  imported from another machine) can be repointed to where the file is on
  this device. When the file is not chosen yet, or is missing or changed,
  **Choose new location…** opens the native dialog for that request and
  reference (`file_choose` with the new purpose `linked_file_relocate`,
  the referrer and `old_path`). The backend rewrites every reference to the
  old path in that request only (filing a new revision) to the canonical
  path of the regular file picked there, moves the request's binding to it
  in the same transaction, and never looks at the old path. Other requests
  naming the old path stay unbound. The editor then reloads the saved
  request. The new path is saved in the request, so a later export carries
  it; the export preview warns that linked local files are named. A load
  plan's linked-file dataset offers the same **Choose new location…**: the
  backend rewrites that dataset only, and the load view then reloads its
  datasets.
- Desktop: an imported collection's root folder has a **Workspace scope** tab
  in its folder settings. It shows whether the collection is isolated from
  its workspace (the default) or opened to it on this device, and which
  variables, environments, auth, run values and identities its requests
  resolve either way. **Open to workspace…** asks for confirmation first;
  **Isolate again** does not. Ordinary folders have no such tab, and an
  import still never opens a collection.
- CLI: `anvil storage-cleanup` prints the profile's last storage cleanup:
  when it ran, how many orphaned revisions it removed and stored files it
  released, and the kind and id of each stored object that did not decode
  (which keeps every stored file until it is repaired or deleted).
  `--json` prints it as JSON; `--now` runs a pass first. The desktop exposes
  the same record through the `storage_cleanup_last` command
  (`api.storageCleanupLast()`); it has no screen for it yet.
- Desktop: a linked local file that a saved request or dataset names (for
  example one from an imported bundle) can now be chosen on this device. The
  request's binary body or multipart part, its gRPC schema, and a load
  plan's dataset show the file with its binding state: chosen on this
  device, not chosen, or chosen but missing or changed since. **Choose
  file…** or **Rebind…** opens the native dialog for that request or
  dataset. The backend still binds only the exact file the reference names
  (canonical path, regular file, and that request or dataset), and the new
  read-only `linked_file_status` command reads no file and never looks at a
  path that was not chosen. The import preview points to where linked files
  are chosen, and the refusal of an unchosen linked file names Choose file…
  instead of saying the chooser is not available.
- Diagnostics: a `ferrum-edge-0.9.8` compatibility catalog for Ferrum Edge
  v0.9.8 (540 source-audited outcomes, `docs/audit/gateway-0.9.8-delta.md`).
  It knows the new `X-Gateway-Error: request_timeout` token: a route's total
  request timeout that expired before any backend held the request. Anvil
  reports it as a gateway-side timeout, not a slow backend, and on v0.9.8 a
  route-timeout 504 with `backend_timeout` means a backend held the request.
  Profiles declaring an older release report the new token as unknown.
- Load testing covers every gRPC call mode: client-streaming and
  bidirectional calls are load units of their own (`grpc_client_stream`,
  `grpc_bidi_stream`). Each unit is one call: the request's scripted
  messages, a half-close, and reading until the terminal status, on the same
  pooled channels as unary calls. Reports add the messages sent to the gRPC
  and stream counts; no round trip is claimed.
- Load testing covers UDP and DTLS through a MASQUE (CONNECT-UDP) proxy or a
  mesh HBONE datagram tunnel. Every exchange opens its own tunnel, and the
  report counts them (attempted, established, refused by the proxy, failed,
  timed out, canceled when the run stopped) with the tunnel setup time. An
  exchange whose tunnel did not open is incomplete, never "no response
  observed". The preflight names the proxy the traffic goes to (with
  variables resolved), and warns that traffic leaves this machine when
  either the target or the proxy is not local. Runs over different datagram
  paths are not compared. A plan that mixes direct and tunneled exchanges,
  or two kinds of tunnel, is refused (`mixed_tunnels`), and so is UDP
  through a MASQUE proxy while a proxy profile routes the request
  (`masque_through_proxy`), which the engine would refuse on every send.
  A target the HBONE profile's `NO_PROXY` list bypasses is sent directly,
  as the engine does: it counts as a direct exchange, and HTTP or gRPC to it
  is not refused in persistent mode (`hbone_persistent`).
- Load plan checks refuse a gRPC call the engine would refuse on every send,
  such as gRPC-Web with client or bidirectional streaming
  (`grpc_unsupported_combination`, quoting the engine's reason).

### Changed

- Docs: refresh the completion report, architecture and load docs for the
  Ferrum Edge v0.9.8 default pin and its 540-outcome catalog, mark G01
  implemented on Edge main (not in a release), correct the load limitations
  (native client-streaming and bidirectional gRPC are supported; only their
  gRPC-Web forms are refused), and record the plan to adopt the gateway
  diagnostic reference. See
  [diagnostics.md](docs/diagnostics.md#adopting-the-gateway-diagnostic-reference-g01).
- Load testing: JSON dataset cells keep their source text, including number
  spelling such as `1.50` or `1e2`, nested `\u` escapes, and nested duplicate
  keys.
- CI: Dependabot now covers GitHub composite actions, keeps patched vendored
  crates pinned, and leaves coordinated Tauri updates for a manual bump.
  Dependabot dependency PRs may require manual license and generated-contract
  updates before the required CI checks pass.
- New Ferrum gateway profiles default to `ferrum-edge-0.9.8` (desktop dialog
  and CLI), and the failure lab's default pin is Ferrum Edge v0.9.8
  (`lab/gateway/RELEASE.lock`, the release's published sha256 for every
  asset). v0.9.7 and v0.9.5 stay supported with `--release`; the nightly lab
  runs all three. Lab scenarios whose public signal changed in v0.9.8 (HBONE
  relay-synthesis refusals are now 403, an injected
  `X-Gateway-Upstream-Status` is stripped) expect the running release's
  signal.
- Encrypted-transfer bundles now use bundle format 2: the encrypted vault is
  bound to every other entry of the bundle, so a bundle changed after export
  is refused before any secret is restored. Encrypted bundles exported by
  earlier builds (format 1), including whole-profile zip backups from early
  development builds, are refused on import; export them again with this
  version. Share-safe bundles of either format still import, but only
  without a passphrase: one given for a bundle that is not encrypted is
  refused, since it would verify nothing.
- Desktop: opening another profile now locks the previous one and stops its
  runs, sends, sessions and load runs. Each records only into the profile it
  started under, and a load report that finished while its profile was
  locked is saved when that profile is next unlocked, never into another.
  Progress of a closed profile's work no longer reaches the new profile's
  window, and its sessions cannot be driven from there. A JWT-SVID token
  file is read through links (such as a Kubernetes projected token), but
  the file opened must be a regular file of at most 16 KiB.
- A bundle import or full-backup restore now seals, on this device only,
  every workspace it writes into, including Duplicate copies and new
  workspaces: its requests are refused this device's workload identity
  (JWT-SVID or X.509-SVID), that is a JWT-SVID from the Workload API or a
  token file, and a TLS profile, the request's own or its proxy's, whose
  client identity is an X.509-SVID from the Workload API, until you allow it
  with **Allow on this device** in the workspace settings' Auth tab or
  `anvil workspace allow-device-identity <workspace>` (a workspace id, or an
  exact name no other workspace has). A JWT-SVID from a vault or variable
  value is unaffected. Seals are never exported or backed up, so after
  restoring your own backup on a new device, allow each workspace you trust.
  The desktop now binds a token file by the path you chose rather than the
  file it resolved to, so a Kubernetes projected token keeps working after
  it rotates; a projected token file bound by an earlier build names the
  file of one rotation, so choose it again. A run or load run of a closed
  profile ends with a generic message in the new profile's window.
- Bundle imports now store the load plans and history records a bundle
  carries (exports include load plans, and list a plan left out because it
  names a deleted object among the excluded items), and a Duplicate import
  gives them new ids. A history record that is not a valid execution record
  is left out with a warning instead of refusing the bundle, one dated after
  the import is stored with the import time, and a record overwritten under
  Replace no longer leaves its old response body behind. Approving an import or restore into an existing workspace now names
  the previewed file's `bundle_sha256`, and a file that changed since the
  preview is refused (CLI: `--bundle-sha256`, which a `--dry-run` checks
  too). Imported OAuth 2 profiles no
  longer keep a token-cache id, a Duplicate preview no longer lists foreign
  secrets, and profile headers with key-derivation costs outside the bundle
  bounds are refused before unlocking. The CLI treats an empty
  `ANVIL_EXPORT_PASSPHRASE` as unset and says to unset it when importing a
  bundle that is not encrypted.
- A vault secret is now sealed together with the workspace that owns it, so
  a secret whose owner is changed in the database file no longer decrypts.
  Database schema 2 re-seals existing secrets once, in one transaction, when
  a profile is opened or unlocked, trusting the owner each row names at that
  time. A secret that already failed to decrypt is left as it is (it still
  fails and can be deleted) and counted in the log; a secret already sealed
  for its owner in a database still marked schema 1 fails the unlock and
  nothing is written. Earlier builds refuse a
  schema 2 database, and a full backup made from one, as newer. Restoring a
  checkpoint refuses a newer or foreign one before touching the profile. The
  desktop reads an imported bundle or backup and derives its key on a worker
  thread, one import at a time. The key a preview derives is not kept for the
  import that follows.
- Full-backup restore: the preview now says when Replace restores the
  backup's app settings, which then apply to every workspace in the profile.
  A load report of a workspace that is not in the backup is left out with a
  warning, as a history record already was, instead of refusing the
  restore, and a restored history record dated after the restore is stored
  with the restore time.
- Profile headers now carry a MAC, under a key derived from the data key,
  over their protection mode, checked at every unlock and before a
  passphrase change or conversion rewrites the header, so a header edited to
  claim keychain mode (or stripped of the MAC) no longer opens a profile
  converted to a passphrase from its old keychain entry. A conversion tags
  the keychain entry before it writes the passphrase header, and stops with
  nothing changed if the credential store refuses; an old entry the store
  refuses to delete is overwritten with a marker that opens nothing. Headers
  and keychain entries from earlier builds still open, are trusted as found
  at their first unlock on this build, and are upgraded then; a keychain
  header without a MAC that carries passphrase or recovery wraps is refused.
  An old entry left by a conversion done in an earlier build stays usable
  by a header edited back to keychain mode (MAC and wraps removed) only if
  the store refuses both to delete and to overwrite it, and a copy of the
  header saved before a conversion opens from that entry until it is removed
  or overwritten. Keychain entries
  written by this build are not readable by earlier development builds.
  Header writes use a temporary file per writer under an advisory lock
  (`profile.lock`), and a writer holding the lock removes temporary files
  older than ten minutes. Settings lists a keychain entry whose removal is
  still pending, offers neither converting nor changing the passphrase until
  the profile's mode is known, and stays open until a new recovery key is
  confirmed stored. A conversion reports the old entry as removed whenever
  the delete succeeded.
- A spec reimport now also compares the settings of the folders inside the
  import: a folder's name, description, settings, variables and auth (a
  Postman folder's auth or variables, an OpenAPI tag's description), by the
  same rules as the import's own scope (keys `folders/<id>/…`). A folder
  only the source or only your workspace has is not compared: a new one
  still arrives with the requests added in it, and one gone from the source
  is left in place. An apply is refused, with nothing written, when one of
  these folders changed after the diff was made.
- A reimport no longer overwrites a request you renamed. A request's name,
  description and tags are each compared on their own, like its spec: a
  request you renamed keeps your name when only its spec changed upstream
  (the spec is still updated), and one the source renamed too is a conflict
  kept until you approve overwriting it. A declined conflict keeps only the
  parts you edited: the rest of what changed upstream is still applied, so a
  request whose name conflicts gets the source's new spec and keeps your
  name (`ReimportChange::conflicting_fields` lists the parts that conflict).
  A rename by the source alone is now applied; before, it was ignored unless
  the spec changed as well. For an import made by an earlier build, this
  works from its stored original file unless it was reimported since; then
  a name that differs from the source's awaits approval.
- A reimport now refreshes the import's source record in the same
  transaction: it then holds the file just applied as the stored original,
  with its name, hash, size and import time, instead of the first import's.
  The file it replaces is released from the attachment store in that
  transaction unless something else still references it (another import of
  the same file, or a saved request body or dataset) or you attached the
  same file yourself, even to a request or dataset not saved yet.
- **Breaking (API):** `App::spec_reimport_apply` takes the name of the file
  it applies: `spec_reimport_apply(import_id, bytes, file_name, approval)`.
- **API:** `App::register_load_run` registers a load run with its profile
  before its job is prepared; the returned guard's tokens are canceled when
  the profile locks or the run's workspace is deleted (the desktop stops the
  worker then). It fails, registering nothing, when whether the workspace
  exists cannot be read. `App::save_load_report` now fails with
  `AppError::NotFound` once the report's workspace is deleted.
  `App::clean_up_storage` runs a storage cleanup pass now and returns what it
  removed and which stored objects did not decode;
  `App::clean_up_storage_if_due` runs one only when opening a profile would
  (`cleanup::CLEANUP_INTERVAL`), and `App::last_storage_cleanup` returns the
  last pass. `anvil_app::logging` installs the log the desktop and the CLI
  write to (`log_to_file`, `log_to_stderr`).
- **Breaking (API):** `App::release_attachment` keeps a file a user attached
  (`App::put_attachment`) and returns `false` for it, even when nothing
  references it. `App::save_request`, `App::create_request` and
  `App::save_dataset` can now fail with `AppError::Invalid` ("an attached
  file ... is no longer stored; attach it again, then save") when they name a
  stored file the item did not hold before and that is not stored.
- **Breaking (API):** `anvil_load::RefusalCode` no longer has
  `grpc_client_streaming`, `grpc_bidirectional`, `udp_masque` and
  `udp_hbone` (those plans are now load tested), and adds `mixed_tunnels`,
  `grpc_unsupported_combination` and `masque_through_proxy`.
- The export preview now lists each linked local file path the bundle will
  carry, with the request or dataset that names it (`linked_files`, as
  `request 'Upload': /path/to/file`), beside the existing warning that
  linked local files are named. A path repointed with **Choose new
  location…** is a path on this device, so the preview shows which ones
  leave with the export. The bundle's manifest does not repeat them. The
  desktop export dialog lists them under its rebinding warning (Windows
  paths without the `\\?\` verbatim prefix), and `anvil export --preview`
  prints them.

### Fixed

- Windows: the DNS and replay-guard fixtures now bind UDP (including QUIC)
  on port 0 before binding TCP to the assigned port. If TCP refuses the port,
  they retry up to 64 times while holding rejected UDP candidates, and the
  final error lists the ports tried.
- The failure lab's EARLY-001 and EARLY-002 test the gateway's pending
  0-RTT window deterministically. The client's "offered and accepted"
  evidence does not prove the gateway saw the request early: Ferrum Edge
  classifies each HTTP/3 stream when it accepts it and handles a 0-RTT
  stream accepted after its handshake as 1-RTT (RFC 8470 section 6.4), and
  lab run 36557709775 got one 200 for EARLY-002's PUT and failed (#221).
  The scenarios now reach the gateway's HTTP/3 listener through a UDP relay
  fixture (`127.0.0.1:17302`). The relay holds the client's
  Handshake-space packets (its TLS Finished), its 1-RTT packets and any
  packet it cannot read, while its 0-RTT packets pass. It releases the
  Finished on an event: the backend receiving a request of the round's
  method, or the gateway logging its refusal. When neither happens, it
  releases after at most 2 s. The gateway's handshake is therefore still
  pending when it handles the 0-RTT stream.
  - A request of the method that reached the backend before the release
    was processed while the handshake was pending. For EARLY-002's PUT that
    is a hard failure.
  - EARLY-001 requires its admitted GET to arrive before the release,
    unless the hold ran to its cap.
  - EARLY-002 also accepts a 425 with the refusal log after the cap.
  - A round whose hold ran to the cap and that then served the permitted
    shape (one 200, no retry, one backend request without `Early-Data`, no
    refusal logged) is retried. Running out of rounds fails; there is no
    run-time skip.
  - The client's queued 1-RTT data, such as EARLY-002's retry, waits for
    the first gateway datagram relayed after the release, and 20 ms more on
    releases before v0.9.8. Their accept loop can take a 1-RTT stream that
    arrives with the Finished for early data (ferrum-edge#5761).
  - 1-RTT data coalesced into a Handshake datagram goes out without that
    wait. The check detail counts such datagrams (#223).
- UDP load-scenario silence coverage keeps its non-responding target socket
  bound for the whole sub-case, then checks ICMP-unreachable counts on a
  released port with up to five fresh-port retries for parallel UDP replies.
  PROTO-020 uses the same bounded retry for its ICMP-unreachable assertion;
  both tests fail clearly if every attempt receives foreign traffic.
- The effective-request preview reports a multi-auth as varying per send
  when any of its profiles is HMAC, DPoP, JWT, WS-Security or JWT-SVID
  (nested sets included), and an SSE preview with such a multi-auth says
  each send is signed again. It used to report, say, an API key with HMAC
  as not varying, with no note, although the HMAC signature changes on
  every send. A multi-auth of static credentials (bearer, Basic, API key,
  a cached OAuth2 token) is still shown as sent.
- Creating or duplicating a request (`create_request`, `duplicate_request`)
  checks that its workspace and folder exist and belong together in the
  write transaction that stores it, not before. A workspace or folder
  delete that committed in between used to leave the new request, with its
  first revision, under the deleted workspace or folder; the create is now
  refused and nothing is stored.
- HTTP/1.1 and HTTP/2: a request on a reused pooled connection that the
  server closed just as the request went out no longer fails with "closed
  before response" when resending it is safe. When none of it was written,
  the transport sends it once more on a new connection. When it may have
  been written and its method is idempotent, the engine signs it again (a
  new HMAC nonce, DPoP proof and JWT time claims, since the server may
  already have seen the first ones) and sends it once more on a new
  connection. The resend happens at most once per execution, never on a
  pooled connection or the one kept after `425 Too Early`, and is not a
  retry: it happens with retries set to 0 and does not count toward them.
  Both attempts are recorded, the second with the new attempt reason
  `reused_connection_closed` and the failure kind that preceded it. A
  written non-idempotent request, such as a `POST`, is never resent, even as
  the retry after `425 Too Early`; its message now says why. This also
  fixes an intermittent failure of the retry after `425 Too Early` when the
  server had just closed the kept connection.
- HTTP/3 with fallback to TCP: the fallback no longer sends a request over
  TCP that may already have been received over HTTP/3 unless its method is
  idempotent. It falls back when nothing of the request was sent over
  HTTP/3 (the QUIC connection or handshake failed before the request stream
  was written, or the server refused its 0-RTT early data unread and the
  resend after the handshake never started), whatever
  the method, or when the method is idempotent. A written non-idempotent
  request, such as a `POST` whose HTTP/3 stream was reset before a response,
  used to be sent a second time over TCP; it is now not sent again, and its
  HTTP/3 attempt's message says why. The fallback is now a new attempt of
  the engine, signed again (a new HMAC nonce, DPoP proof and JWT time
  claims): it used to repeat the HTTP/3 attempt's signature, which a server
  that checks for replays rejects. Both attempts are still recorded, the
  second with reason `protocol_fallback{from: h3}`.
- Server-sent events: each send of a stream is now signed afresh (a new
  HMAC nonce, DPoP proof and JWT time claims): the initial send, the TCP
  fallback after HTTP/3 and each reconnection. A stream used to be signed
  once, when it was prepared, and the fallback and every reconnection
  repeated that signature, which a server that checks for replays rejects,
  so such a server refused every reconnection. A reconnection is signed once
  its `retry:` delay is over and still sends `Last-Event-ID`; when the
  fallback is made is unchanged. A JWT's only per-send claim is `iat`, in
  whole seconds, so two sends within the same second can carry the same JWT
  (as can legacy Ferrum HMAC v1). The record's prepared request and auth
  facts are the last send's. A fallback or reconnection that auth cannot
  sign again is not made, and the session notes why; it is never sent with
  an earlier send's signature.
- Server-sent events: a send is now signed just before it is made, after
  the HTTP/3 checks, so an HTTP/3 attempt refused before any traffic (the
  automatic policy with an `http://` URL or through a proxy, which then
  falls back to TCP) is no longer signed. A send whose auth would add other query
  parameters than it did when the stream was prepared is not made
  (`unsupported_combination`): only headers are signed again for each send,
  and the URL is fixed. No current auth does this; an API key in the query
  is the same on every send. The effective-request preview of a stream with
  auth now notes that each send (the initial one, the TCP fallback and each
  reconnection) is signed again when it is sent, not with the signature
  shown.
- HTTP/3: a request on a reused pooled QUIC connection that the server
  closed (or let time out) just as the request went out is now sent once
  more on a new connection when that is safe, as over HTTP/1.1 and HTTP/2:
  at once by the transport when none of it left, else by the engine, signed
  again, for an idempotent method. A request the server rejected with
  `H3_REQUEST_REJECTED`, or whose HEADERS the closing connection cut short,
  was not processed: it is now reported `not_dispatched` and, on a reused
  connection, signed again and sent once more whatever its method (on a new
  connection the TCP fallback may now take it, whatever its method). A
  written `POST` whose connection closed under it is still not sent again,
  and its message says why. A pooled connection whose server sent `GOAWAY`
  is no longer handed out: its next request used to fail on it. The resend
  has reason `reused_connection_closed`, happens with retries set to 0 and
  does not count toward them.
- HTTP/2: a request on a reused pooled connection that the server refused
  unprocessed, with `REFUSED_STREAM` or by a graceful `GOAWAY` whose
  last-stream-id is below its stream (RFC 9113 §8.7), is now signed again
  and sent once more on a new connection whatever its method, a `POST`
  included; it used to fail. A stream above such a `GOAWAY` is now reported
  `not_dispatched`; a `GOAWAY` carrying an error code proves nothing and
  keeps the previous rules. Only an `RST_STREAM` with `REFUSED_STREAM` is
  now classified `h2_refused_stream`; a `GOAWAY` whose error code happens to
  be `REFUSED_STREAM` is `h2_go_away`.
- Saving a request (`save_request`) keeps the workspace, folder and position
  it has in storage, read in the save's write transaction, whatever the
  saved copy names; the name, description, tags and spec are saved as
  before. An editor's copy loaded before the request was moved used to write
  back its old folder and position, so the save silently undid the move.
  Only a new request is placed by a save; moving one takes `move_request`.
- Saving a request that is no longer stored (`save_request`, the desktop
  **Save**) is refused with "request (it was deleted) not found". An editor
  tab left open after its request, folder or workspace was deleted used to
  recreate the request on save, possibly under a deleted folder or another
  workspace's folder. New requests are made only by creating or duplicating
  one.
- Desktop Load: Discard is disabled while a new plan's save or Run… is on its
  way and disappears as soon as the save is acknowledged, before the list
  reload finishes. A save that lands after another plan or report was
  selected keeps that selection instead of reopening the saved plan. The
  discarded-plan guard is cleared on workspace switch.
- Desktop linked files: Choose new location… now names the hosts the file is
  used for (the request's saved URL, or a dataset's plan requests; host and
  port only, never the path or query; template variables are omitted), and
  asks before discarding a request tab's unsaved edits, which the relocation
  replaces with the saved request.
  Windows paths are shown without the `\\?\` verbatim prefix (`\\?\UNC\`
  as `\\`); the stored path is unchanged.
- Moving a request (`move_request`) reads and writes it in one write
  transaction and changes only its folder and position. It used to read the
  request first and save that copy afterwards, so a save or a linked-file
  relocation that landed in between could be undone, leaving the request
  naming its old, unbound path. A move never files a revision.
- Desktop Load: switching workspaces now clears the selected plan or report
  and closes a pending run confirmation, so the Load view never shows, saves,
  runs or deletes the previous workspace's plan; the plan editor also refuses
  to save or start a plan that belongs to another workspace. A live run's
  Stop control is kept. Unsaved plan edits and unsaved new plans are kept per
  workspace for the session (not written to disk): they are hidden while
  another workspace is shown, marked **unsaved** on return, and an edit is
  dropped once its plan is no longer in its workspace. A new plan is kept
  only once it has been edited: an untouched one is dropped when something
  else is selected or the workspace switches. An unsaved new plan has
  **Discard** instead of Delete, which removes it without asking the backend
  to delete a plan that was never saved. The sidebar row shows an edited
  plan's unsaved name. The previous workspace's plans and reports leave the
  sidebar at once instead of staying until the new workspace's lists arrive,
  and a report delete that completes after a switch no longer clears the new
  workspace's selection.
- The load preflight's "Traffic leaves this machine" warning now compares
  each destination's whole host: a host that only contains `localhost` or
  `127.0.0.1` (such as `localhost.example.com`) no longer counts as this
  machine, and a tunnel's proxy is judged apart from its target.
- The load preflight now judges the proxy profile a request is actually sent
  through, whatever its kind: a loopback target behind a remote HTTP, HTTPS
  or SOCKS5 proxy (as well as MASQUE or HBONE) warns that traffic leaves
  this machine, and each destination names that proxy. The profile's
  `NO_PROXY` list is applied as the engine applies it, so a bypassed target
  (including a UDP target under an HBONE profile, which was labelled "via
  HBONE proxy") is shown as direct and the proxy's host is not judged.
- The effective-request preview now shows what a WebSocket, SSE or gRPC
  request sends. A `ws://`, `wss://`, `grpc://` or `grpcs://` URL is
  previewed (before, it was refused, and a URL without a scheme was
  previewed as `https://`). A WebSocket over HTTP/2 or HTTP/3 shows its
  `CONNECT`, a gRPC or gRPC-Web call shows `POST` to the method's path with
  its request message as redacted JSON (and the size of the framed message
  sent), and each shows the headers the session transport adds or leaves
  out. The preview and the session build the request with the same code. An HMAC or DPoP signature in the preview
  covers the same method, path, authority and body as the one sent, with a
  `ws`/`grpc` URL signed as its `http` counterpart. An auth profile the
  session refuses (one that rewrites the body, or adds query parameters to
  a gRPC call) is shown as a request that would not be sent. Raw TCP and UDP
  say the preview is not supported for them.
- CLI: `anvil load create --rate N` and `--vus N` now hold `N` for
  `--duration` from the start, as their help says. Before, they built a
  single stage that ramped linearly from 0 to `N`, so `--rate 100
  --duration 20` planned 1,000 arrivals instead of 2,000. The plan is now a
  zero-duration step to `N` followed by a hold of `N` for `--duration`.
- The failure lab's `h3x`, `proxyproto` and `mesh` profiles declared the
  Ferrum Edge 0.9.5 catalog whatever release ran, so on the default pin their
  diagnoses used another release's catalog. Every lab profile now declares
  the running release's own catalog, and `anvil-lab run` and `up` refuse a
  release Anvil has no catalog for, or only one audited at another commit
  (#137).
  The `early` profile's ground-truth checks on 1-RTT HTTP/3 requests now
  accept `Early-Data: 1` (and EARLY-005 a 425 and its retry) on gateway
  releases before 0.9.8, which can mark such a request as early data
  (ferrum-edge#5775), and name that in the check detail; 0.9.8 and later
  stay strict.
- WebSocket over HTTP/2 and HTTP/3, SSE over HTTP/2 and gRPC (native and
  gRPC-Web, every HTTP version) now send an explicit `Host` header as the
  request's authority (`:authority`, or `Host` over HTTP/1.1), as HTTP
  requests do. Before, they sent the URL's authority while an HMAC or DPoP
  signature covered the explicit `Host`, so the server's signature check
  failed. A WebSocket over extended CONNECT is now signed, and recorded,
  with the method it is sent with (`CONNECT`) instead of `GET`. A DPoP
  proof for a WebSocket or native gRPC session is now bound (`htu`) to the
  `http` or `https` counterpart of its `ws`, `wss`, `grpc` or `grpcs` URL,
  the HTTP URL the request is sent to. Before, DPoP refused those sessions
  before sending anything.
- gRPC calls now use the workspace cookie jar as HTTP requests and SSE and
  WebSocket handshakes do: with the Cookies setting on, they send the
  stored cookies that match their URL (a `grpc://` or `grpcs://` URL counts
  as its `http://` or `https://` counterpart, so `Secure` cookies stay on
  TLS), within the workspace only, and the `Set-Cookie` of their response
  headers is stored when the call ends, unless the profile was locked or
  the workspace deleted since the call started. The server reflection
  requests of a call send the jar's cookies too, but their `Set-Cookie` is
  not stored. Before, gRPC ignored the jar as if Cookies were off.
- An SSE stream set to reconnect is no longer reconnected without
  `Last-Event-ID` when the id the server sent is not a valid header value
  (it holds a control character other than a tab), which would have asked
  the server to start the stream over. The session ends with a note that
  says why and never holds the id. Before, the reconnection silently left
  the header out.
- The effective-request preview now resolves the `Host` / `:authority` the
  way Send does: an explicit `Host` header wins over the URL's authority, and
  an HMAC or DPoP signature shown in the preview covers that value. Before,
  the preview signed for the URL's authority, so for a request with an
  explicit `Host` it did not match what was sent. The preview also shows the
  `Host` / `:authority` that will be sent (including a `Host` an auth
  profile sets) and the non-secret facts of the generated credential (for
  example the DPoP proof's `htu`), and when the auth profile cannot be
  applied (for example an HMAC request with a manual `Content-Digest`
  header, also beside a JWT-SVID the preview does not fetch) it says the
  request would not be sent, instead of showing it without its credentials.
- The effective-request preview now shows the body an auth profile rewrites
  as it is sent: a WS-Security request's body includes its `wsse:Security`
  header block (with the password redacted), and the body size is that of
  the body sent. Before, the preview showed the body without the header
  block and its size.
- A file you attach (a request body or multipart file, a gRPC schema file, a
  dataset) can no longer be deleted before the request or dataset that uses
  it is saved. Before, a release in between, such as a reimport releasing
  the source file it replaces while that same file was attached as a body,
  left the saved request naming content that was gone. An attached file is
  now marked in the attachment index and is released only when a request or
  dataset that held it is deleted or replaced (a request's revisions are
  deleted with it), never automatically. A save of a request or dataset that
  names a stored file it did not hold before, and that is not stored, is
  refused with a message to attach the file again. `App::delete_request` and
  `App::delete_dataset` now also release, in the same transaction, the files
  their item held that nothing else references; attachment index entries
  written by earlier builds read as not marked. A marked entry records when
  the file was attached. A duplicate of a request whose file is no longer
  stored still saves.
- A header an auth profile produces that is not valid on the wire (for
  example a token pasted with a trailing line break, or an API-key or JWT
  header name with a space) now fails the request before anything is sent,
  with an invalid-header error that names the header and never its value.
  Before, the header was left out and the request was sent without the
  credential. This applies to HTTP requests and to WebSocket, SSE, gRPC and
  MASQUE handshakes alike.
- SSE and WebSocket handshakes now use the workspace cookie jar as HTTP
  requests do: with the Cookies setting on, they send the stored cookies
  that match their URL (a `ws://` or `wss://` URL counts as its `http://` or
  `https://` counterpart, so `Secure` and `HttpOnly` cookies apply), within
  the workspace only, and the `Set-Cookie` of their handshake responses is
  stored when the session ends, unless the profile was locked or the
  workspace deleted since the session started. With Cookies off they
  neither send nor store cookies.
- A request or session still in flight when its workspace is deleted no
  longer recreates that workspace's cookie jar with the cookies it
  receives, so a workspace restored from a backup with the same id does not
  send them.
- An SSE `Last-Event-ID` that resolves to a value that is not a valid header
  value now fails the request before anything is sent, with an
  invalid-header error naming `sse.last_event_id`. Before, the header was
  left out and the stream was opened without it.
- The effective-request preview now says a request would not be sent when
  its auth profile produces a header that is not valid on the wire, instead
  of showing it. A redirect or retry whose freshly applied auth is refused
  is noted in the prepared request.
- A stored cookie with the same name as a cookie the request sends itself
  (a `Cookie` header or a cookie API key) is no longer sent as well: the
  request's own cookie wins, and the jar's other cookies follow it.
- Work still in flight when a profile locks no longer refills what the lock
  cleared. The desktop lock cancels a SPIFFE Workload API call in flight,
  and an answer that arrives after the lock anyway (an X.509-SVID, a
  JWT-SVID or JWT bundles) is never cached; before, a JWT-SVID fetched
  across a lock could stay in memory after it. Likewise, for an execution
  that began before the lock, even one that is not canceled: the cookies of
  its responses are not stored, the TLS configuration it prepares (which
  holds a client identity's private key) is not cached, its connections
  (HTTP/1.1, HTTP/2 and HTTP/3) are closed instead of pooled, and its TLS or
  QUIC connections keep none of the session tickets they receive.
- Work still in flight when its workspace is deleted no longer refills that
  workspace's caches: a request, session or gRPC call of the deleted
  workspace closes its connections instead of pooling them, caches none of
  the TLS configurations it prepares and keeps none of the session tickets
  it receives, even on a later redirect or retry. Other workspaces' work in
  flight at the same time is not affected. An execution that starts while
  its workspace is being deleted is now fenced on one side of the delete
  for all of its caches: before, it could keep its connections and session
  tickets while its cookies were refused. A send, interactive session or
  collection run step whose context the app prepared from storage before
  the delete is fenced too, even when it starts executing after the delete:
  it takes the workspace's generations when the context is built, not when
  it executes. Before, it could keep cookies, a prepared TLS
  configuration (with a client identity's private key), pooled connections
  and session tickets under the deleted workspace, where a workspace
  restored with the same id would find them. Requests of the restored
  workspace, built after the delete, are not affected.
- `Engine::execute` now runs each protocol's execution boxed, so the future
  a caller awaits is small. Before, a caller that awaited several gRPC
  calls inline could overflow its thread's stack in a debug build.
- Prepared TLS configurations are now kept per workspace (every workspace
  without a TLS profile shared one configuration), and a workspace delete
  drops them. Connections without the early-data opt-in still never resume
  a session, and they no longer keep the TLS 1.3 session tickets and TLS 1.2
  sessions servers send: only the key-exchange group each server chose is
  kept, so the next handshake still needs no HelloRetryRequest. Under the
  opt-in, a connection resumes only its own workspace's tickets.
- Pooled gRPC channels, which only a load run's virtual users keep, are no
  longer shared between workspaces, and a call that began before its
  engine's channels were cleared no longer returns its connection to them.
  Deleting a workspace now stops that workspace's running load runs, and
  `App::lock` stops every load run, so a run's engines no longer keep a
  deleted workspace's pooled connections, session tickets, cookies, prepared
  TLS configurations and gRPC channels until the run ends. The desktop ends
  the worker of a run stopped by its workspace's delete at once, and keeps
  no report of it; only the window of the run's profile is told why.
- Deleting a workspace now also releases the stored files (request bodies,
  multipart and gRPC schema files, datasets, imported spec sources) its
  items held, unless an item of another workspace still references them or
  you attached the file within the last 30 days (a draft not saved yet may
  hold it; the 30-day cleanup below decides it). Before, their encrypted
  content and pins stayed in the profile for good.
- A file you attached to a request or dataset that was never saved is now
  released by the storage cleanup, 30 days after it was last attached,
  unless a saved item references it. Saving an item that names such a file
  is refused with "attach it again", as for any released file.
- The storage cleanup also removes request revisions whose request no
  longer exists (earlier builds left them behind when a request was
  deleted) and releases the stored files only they referenced, except one
  you attached again within the last 30 days.
- Opening a profile runs the storage cleanup at most once a day. It reads
  without taking the database write lock and writes in a short transaction
  only if nothing changed meanwhile. While a stored object that does not
  decode blocks it, the cleanup at open is skipped until something it reads
  changes.
- A stored object that does not decode, which keeps every stored file from
  being released, is now logged as a warning naming its kind and id (never
  its content), and the cleanup keeps it in its last pass, which
  `anvil storage-cleanup` prints, so the damaged row can be found and
  repaired or deleted. Warnings now reach a log: before, none was installed,
  so they were dropped. The desktop writes `anvil.log` in its log directory
  (on macOS `~/Library/Logs/com.ferrumedge.anvil/`) at level `info`,
  rotated to `anvil.log.1` at 5 MiB; the CLI writes warnings and errors to
  stderr. `ANVIL_LOG` (`off`, `error`, `warn`, `info`, `debug`, `trace`)
  sets another level for Anvil's own crates.
- Deleting a request, a folder with its requests or a dataset, or replacing
  a dataset's file, no longer releases a file you attached within the last
  30 days, as a workspace delete already did not: a draft of another request
  or dataset may have attached the same file moments before, and its save
  was then refused with "attach it again". The 30-day cleanup decides it
  instead.
- A file attached by a build that did not record when (a mark with no
  `attached_at`) now ages from the first storage cleanup that sees it, which
  records the time. Before, it counted as recently attached for good, so an
  unsaved one was never released.
- A spec reimport now compares the import's scoped configuration too, not
  only its requests: the source's own variables, auth, settings and
  description (on the new workspace, or on the import root in an existing
  workspace) and its environments. An OpenAPI server change, which leaves
  every `{{baseUrl}}/…` request as it was, is now listed as a change to its
  environment's `baseUrl` and applied, so requests are sent to the new
  server. The same rules as for requests apply: a value you edited is a
  conflict kept until you approve overwriting it (`overwrite_scope`), a
  variable or environment gone from the source is kept until you approve
  deleting it (`delete_scope`), your own variables stay, and a new server
  arrives as a new environment. An environment you deleted is a conflict
  when the source changed any of it, and one gone from the source is marked
  as edited when you changed any of its variables. An approved deletion of
  the active environment leaves none active, as deleting it yourself does.
  Imports made by earlier builds work this out from their stored original
  file, unless they were reimported since or that file cannot be read; then
  every difference awaits approval, and a removal you decline is kept as
  your own from then on. A reimport of an import root that was deleted is
  refused, and so is an apply when the import's requests, scope or
  environments changed after the diff was made; nothing is written then.
- A reimport that changes a saved request now records a new revision for
  it, in the same transaction, and points the request at it, so a send, run
  or history record names the spec that was actually sent. The revision of
  its old spec stays as it was; a request the reimport leaves unchanged
  keeps its revision and gains none.
- Desktop Runner: **Run folder** and **Run** start one run at a time. A
  second click while the start is still pending no longer starts another
  run, and a run that finishes before the start answers (an empty folder,
  for example) is no longer shown as running with a Stop control that does
  nothing. **Stop run** pressed while a run is starting stops it as soon as
  it starts, and a run the backend no longer has is cleared when stopped.
  Switching workspaces now clears the Runner's selected scenario, report,
  folder choice and pending confirmation, so the Runner never offers to run
  the previous workspace's scenario; a live run's Stop control is kept.
  Unsaved edits to a scenario's run options are kept per workspace for the
  session (not written to disk): they are hidden while another workspace is
  shown, marked **unsaved** again on return, and dropped once the scenario is
  no longer in its workspace.
- Deleting an environment clears its active workspace selection in the same
  transaction. Older profiles with a missing workspace-default environment
  now prepare requests without an environment, and collection run reports say
  when that fallback was used; an explicitly selected missing environment
  still fails clearly.
- Server-sent events: an event whose data (its `data:` lines joined with
  newlines) passes the parser's event bound, four times the line bound
  (`min(max_response_bytes, 1 MiB)`, at least 1 KiB), now stops the attempt
  with `response_too_large_local` instead of being dispatched with the
  extra data lines silently dropped. Events completed earlier in the same
  read are still recorded.
- Server-sent events: a leading UTF-8 byte order mark is now stripped even
  when its three bytes arrive in separate reads; the stream's first event
  was lost when the transport split it. A BOM later in the stream is still
  not stripped.
- A load run now hands its worker every vault secret the plan's requests
  resolve: the datagram PROXY-protocol authentication secret of a UDP
  request, and the client identity of the selected proxy's own TLS profile
  (which also travels to the worker now), were missing, so those requests
  failed preparation in the worker ("the datagram secret is not available",
  or the proxy's TLS profile "no longer exists"). A request of another
  protocol with a leftover UDP section ships no datagram secret.
- Desktop: long store work no longer holds the async runtime. Spec imports
  and re-imports, folder and workspace deletes, profile creation, unlock and
  passphrase changes (their key derivation), history lists, views and
  clears, export previews, and reading an attachment, a PEM/PKCS#12 file or
  a dataset now run on a worker thread. A send, session open, collection
  run, load run and OAuth sign-in prepare the request, look up the vault
  secrets its spec, effective auth and selected profiles name, and record
  their history or report on a worker thread, so they no longer hold the
  runtime while an import holds the database. A send, session open or
  collection run canceled while it waits for that returns at once, with
  nothing sent or recorded. A synchronous store command issued during a
  long import still waits for the database connection until the import
  ends.
- Desktop: a lock now wins over an unlock or profile creation whose key
  derivation it overlaps: the profile stays locked, and is never usable in
  between (a new profile is still created, and its recovery key still
  shown). A command that runs on a worker thread and returns what it read
  from the store (a history list or entry, an export or spec preview, a
  re-import plan, a request preview) returns `LOCKED` instead when a lock or
  a profile switch overlaps it; one that only writes (a folder or workspace
  delete, a history clear, a spec import or re-import, an attachment)
  reports its own outcome. A history list that meets the lock midway fails
  as locked instead of returning the records read so far, and a load run
  whose preparation overlaps a lock is not handed to a worker.
- History records are indexed by their response body, so releasing a
  replaced body and history retention no longer scan whole tables. The index
  is created, as a best effort, when a profile is opened or unlocked (one
  that cannot be created is logged and only slows those lookups, and never
  keeps the profile from opening); it changes no stored data,
  so the database schema version stays 2, and earlier builds still read the
  database and its full backups. Restoring a checkpoint whose recorded
  version was set back below schema 2 after its secrets were re-sealed is
  now refused before the profile is touched, instead of leaving it locked.
  Deleting an attachment's last use checks for other references and deletes
  it in one transaction, and the pins re-applied when a profile opens are
  written in one transaction. Deletes, blob pins and releases, and history
  and load-report clean-up check the lock only once they hold the database,
  so one that raced a failed checkpoint restore fails as locked.
- Desktop: canceling an import or a full-backup restore now works from the
  import dialog (Cancel while it runs; closing the dialog cancels it too),
  and a restore can be canceled until its key is derived and its contents
  checked instead of only before it starts; a canceled one writes nothing,
  not even its checkpoint. A lock or a profile switch during an import's key
  derivation ends it without writing even when it was started without an
  `attempt` id and the profile is unlocked again before the derivation ends,
  and a preview that a lock overlaps returns `LOCKED`. A preview or import
  refused because an earlier one is still finishing returns `IMPORT_BUSY`,
  which the dialog explains, instead of a sentence.
- Desktop: OAuth sign-in attempts are canceled from their own registry, so
  `oauth_cancel` never cancels a request execution with the same id, nor
  `cancel_execution` a sign-in; a lock still cancels both.
- An unlock refused by its gate (a lock that landed during the key
  derivation) no longer locks the store itself: the lock that caused the
  refusal clears the key itself, and locking again could undo a newer unlock
  that completed meanwhile.
- A request under an import root that is not opened to its workspace is now
  also refused when the selected proxy's own TLS profile has a client
  identity bound to no host, whatever the proxy's kind or `no_proxy`, as it
  already was for the request's own TLS profile. This applies to a send, a
  session, a collection run and a load run.
- Multi auth now applies each profile to the request as it will be sent
  after the earlier profiles' changes. Cookie API keys from several profiles
  all reach the one `Cookie` header, after the request's own cookies (from
  every `Cookie` header it has); earlier builds sent only the last profile's
  cookie. A profile's cookie replaces a cookie of the same name already in
  the request, as a header API key replaces a header of the same name. An
  HMAC profile signs the query, body and `Host` the earlier profiles
  produced (a query API key, a WS-Security header), where it signed the
  request before them and the gateway refused the signature. Before anything
  is sent, a multi-auth set is now refused when two profiles would set the
  same header, cookie or query parameter (including inside a nested set),
  or when a profile would change what an earlier signature covers: after
  HMAC, the query, the body or the `Host`, `Date`, `Digest` or
  `Content-Digest` header; after DPoP, the `Host` header. Put such a profile
  before the signing one. A multi-auth set can hold one HMAC profile and one
  DPoP profile.
- A cookie API key whose name is not an RFC 6265 cookie name (a token) or
  whose value is not made of cookie octets (optionally in double quotes) is
  refused before anything is sent, so its value cannot add or change another
  cookie (for example a value `a; x=y`). The message names the cookie, never
  its value.
- HMAC evidence no longer records `hmac.signing_string_sha256`. With multi
  auth the signing string can include an earlier profile's query API key,
  and its hash could be checked against guesses of that key offline. The
  nonce is still recorded.
- An explicit `Host` header must now be a host with an optional port
  (`uri-host[:port]`: a host name, an IPv4 address or an IPv6 address in
  brackets). A value with userinfo, a path, a query, a fragment or
  whitespace, or an IPv6 address without brackets, is refused before
  anything is sent, for HTTP/1.1, HTTP/2 and HTTP/3 requests, WebSocket,
  SSE and gRPC, and so is such a `Host` set by an auth profile. An empty
  `Host` is refused too; before, it was sent empty (leave the header out to
  send the URL's host and port). The message names the reason, never the
  value. Before, a `Host` such as
  `a.test/admin` changed the path an HTTP/2 or HTTP/3 request was sent
  with, while the signature covered the original path.
- A gRPC URL with a query, or a gRPC request with query parameters, is now
  refused before anything is sent (`unsupported_combination`, field `url`),
  by a send, an interactive session and the preview. The call is sent to the
  method's path without a query, so the query was signed but never sent and
  an HMAC signature always failed verification.
- A gRPC call whose schema comes from server reflection is now signed over
  the framed request message it sends, once reflection has resolved the
  schema and the message is encoded, as a call with a `.proto` file or a
  descriptor set is. Before, the message was encoded after signing, so an
  HMAC `Content-Digest` and signature covered an empty body and a gateway
  that checks the digest refused the call. The record's prepared request is
  the one signed and sent. The effective-request preview shows the request
  message as redacted JSON and says that a digest or signature it shows
  covers an empty body, since the call is signed when it is sent.
- gRPC: a unary or server-streaming call with a local schema and no request
  message is now signed over the empty message it sends (a 5-byte frame,
  base64-encoded for gRPC-Web text). Before, an HMAC `Content-Digest` and
  signature covered an empty body, so a gateway that verifies the digest
  refused the call. The prepared request and the effective-request preview
  show the empty message `{}` and the size of that frame.
- gRPC: each server reflection request is now signed for its own path and
  message when auth is set: an HMAC signature and `Content-Digest` of its
  own (and a fresh nonce with Ferrum HMAC v2), or a fresh DPoP proof bound
  to the reflection URL. Before, reflection requests reused the headers
  signed for the call's method path, so a gateway that verifies HMAC or
  DPoP refused them and reflection failed. docs/protocols.md explains why
  reflection is signed rather than sent without those headers. A token
  minted for a reflection request (a JWT) is redacted in the record and
  history, including where the server echoes it in its refusal. A
  reflection request that auth cannot sign is not sent, and
  `grpc.reflection_unavailable` says that auth preparation failed for it
  instead of reporting a transport failure and advising the operator to
  allow reflection.
- Windows: the DNS fixture binds a UDP socket and a TCP listener to one
  ephemeral port, and the replay-guard fixture does the same for its QUIC
  endpoint and TCP listener. Both now retry the whole pair on a fresh
  OS-assigned port when either bind lands in an excluded or reserved port
  range (WSAEACCES, os error 10013) or on a port another socket holds,
  instead of failing the test with a bind error.

### Security

- XML parsing (GHSA-mvjp-hhjj-mh63): the pre-parse scan WSDL imports use
  now runs before every XML parse, from the new internal crate
  `anvil-xml-limits`, with limits chosen per site. It bounds `xmlns`
  declarations, the declarations in scope of any element and the work of
  resolving namespace scopes, attributes per element, attribute pairs over
  the document, and the length of attribute names, namespace prefixes and
  namespace URIs. Every site parses with DTDs refused and a node limit.
  WSDL imports now also refuse, before parsing, an element with more than
  256 declarations in scope. Request body lint returns the new status
  `refused` ("too complex to lint safely"), which a send treats like a lint
  error. XPath assertions and extractions fail with "XML too complex to
  evaluate safely" (a response body is now also limited to 4,000,000 XML
  nodes; see [runner.md](docs/runner.md#xpath-subset)). A SOAP envelope in a
  response that is over the limits, or has more than 50,000 nodes, is not
  inspected for a fault: its application outcome is `not_evaluated`, with a
  `partial_visibility` warning. XML whose root is not an `Envelope` is no
  longer parsed for a SOAP fault. WS-Security refuses the envelope (now also
  limited to 1,000,000 XML nodes).
- Imports (GHSA-c9jq-p5rq-wj3h): more of the work a small spec can repeat
  during preview is now charged or done once. OpenAPI samples charge the
  schema lists they read on every visit to the import's byte budget: each
  member looked at (optional members are skipped before their schema is
  resolved), the `required` names (now a set, not a list scanned per
  member), the `enum` values scanned and each `const`/`enum` comparison. A
  `null` inserted for a required name counts as a generated value, so once a
  budget is spent the remaining members are left out
  (`sample_size_limit`). The structural lookups made while writing XML and
  multipart payloads borrow the resolved schema instead of copying it, so
  they no longer spend the byte budget and cut samples short. WSDL imports
  read each binding, binding operation and portType operation once however
  many ports use it, and charge the message parts and `soap:header`s each
  operation writes. An XML document with more than 1024 `xmlns`
  declarations, or an element with more than 256 attributes, is refused
  before it is parsed (`LimitExceeded`): the parser copies the namespaces in
  scope for every element that declares one and compares every attribute
  with each earlier one. A quote-, comment- and CDATA-aware scan counts both
  in one pass, which also bounds the attribute pairs of the whole document
  (2^24), attribute names (1 KiB), namespace prefixes (256 bytes) and
  namespace URIs (2 KiB), since the parser compares names and full URIs per
  pair. Also charged or done once now: the pointer of every generated
  value and every `$ref` resolution (a `$ref` over 2048 bytes is not
  followed, `ref_too_long`), `type` arrays, `$ref` sibling keys,
  `oneOf`/`anyOf` alternatives and discriminator mappings, and the lookups
  and comparisons of `allOf` merges (non-string `required` entries are
  ignored with `invalid_required`). Text copied into imported objects
  (names, keys, request URLs and pointers, folder names, descriptions, SOAP
  actions, server URLs and variables, OpenAPI 3.2 additional-operation
  pointers, and each operation and security scheme every time it is
  imported) has a budget of four times `max_bytes`; once it is spent, later
  operations are skipped (`text_size_limit`). A Path Item `$ref` is read in
  place instead of copied for every path, server variables are rendered
  once per server (one environment variable per name), a WSDL port's folder
  is created only once one of its operations is admitted, and a repeated
  operation key takes its `#n` suffix from a counter. The report keeps at
  most 1000 findings per code (`report_truncated`), clips stored pointers
  (keeping a hash of the whole pointer) and messages, and indexes its
  external references and required variables. HAR and cURL imports decide
  whether a JSON body was scrubbed from a redaction count that the report's
  list limit does not cap, so bodies stay scrubbed past 10,000 redactions.
- Cookie domains that are a single, unknown label (`internal`, `lan`, `corp`)
  are no longer shared across matching hosts; a cookie may still be stored
  host-only when its single-label domain is the responding host. URL-encoded
  and multipart text fields named as credentials are now treated as
  secret-bearing for cross-origin redirects, even when their literal values
  were not marked sensitive. This also applies to 301/302 redirects that keep
  the body, such as for PUT, PATCH and DELETE.
- Redaction of credential headers (`Authorization`, `Proxy-Authorization`,
  `Cookie`, `Set-Cookie` and other sensitive names) now scrubs every known
  secret value from the parts it keeps: the authorization scheme word,
  cookie names and `Set-Cookie` attributes. Before, a response that echoed
  a credential the request sent into one of those parts kept it in the
  execution record, run history and history-inclusive exports. The whole
  value is scrubbed before it is split, so a secret that spans a `;`, `=`
  or space is replaced whole; a header value marked sensitive as a whole
  (scheme included) is now shown as `‹redacted›` without its scheme.
  Mixed and double percent-encoded secret echoes in `Set-Cookie` names,
  Path and Domain attributes are redacted too. A `Set-Cookie` whose name
  contains a secret used by that execution is not kept in the workspace cookie
  jar, so it cannot appear in a later request's `Cookie` header or notes. History
  recorded before this change is not rewritten.
  (GHSA-vvjj-4xxf-966f)
- gRPC metadata marked sensitive is now redacted by name and by value, like
  a request header marked sensitive, in the effective-request preview, the
  live session events, the execution record and run history, for gRPC and
  both gRPC-Web modes. Before, a literal value under a name that is not a
  known credential name was shown as is. (GHSA-653v-gxx9-r5pv)
- The WS-Security SAML assertion (as stored and as embedded, trimmed) and
  the XML-escaped form of a PasswordText password are now known secrets of
  the request, so the effective-request preview of a WS-Security body and
  the execution record redact them. Before, an assertion taken directly
  from the vault was shown in the preview. (GHSA-6j83-rrqr-953h)
- A redirect that would resend a request body to another origin is no
  longer followed when the body has a form field marked sensitive, even
  when its value is a literal rather than a secret variable. Before, only
  secret variables marked the body structurally, and a literal whose form
  encoding changed its bytes (such as one holding `@` or a space) was
  resent by a 307 or 308 redirect. Allowing credentials to be forwarded
  cross-origin in the redirect policy still lifts the refusal.
  (GHSA-c8jq-hq57-v523)
- The workspace cookie jar no longer stores a cookie whose `Domain` is a
  public suffix, such as `com`, `co.uk` or a private-section suffix like
  `github.io`, so one site can no longer set a cookie that Anvil then sends
  to unrelated sites under that suffix. When the suffix is the responding
  host itself, the cookie is kept for that host only. Cookies scoped to a
  registrable parent domain and host-only cookies are unchanged. The Public
  Suffix List is compiled in (the `psl` crate). (GHSA-vv3h-gm7f-3hm7)
- Fixed GHSA-6g2g-2mvw-7h7v and GHSA-x6q9-gx98-c5wc: gRPC reflection now
  has a 30-second absolute deadline, shortened by the call's total deadline,
  including interactive sessions. Its cumulative budget counts wire and
  decoded response bytes across every reflection request, and it accepts only
  one response message per request. gRPC-Web percent decoding reads escape
  digits as bytes, preserving malformed escapes without panicking on
  multibyte UTF-8.
- Full backup restores now reject spec provenance whose root is missing,
  belongs to another workspace, or is not an import root. Import roots may be
  nested in their workspace and remain valid for restore and reimport; a
  deleted root retains the guidance to import the source again. Restore rejects
  an imported spec namespace already used in another workspace, and reimport
  refuses generated IDs owned by another workspace before writing. This keeps
  restored provenance from changing unrelated objects. Fixes
  GHSA-2c97-mfx4-3g7r.
- Datasets are now bounded at 4,194,304 cells (rows × columns), with at most
  1 MiB of raw JSON text per cell. CSV checks the cell budget before storing
  each row; JSON parses one object at a time and checks row, column and cell
  limits before expanding the stored matrix. A 64 MiB dataset can retain up
  to about 350 MiB of dataset data at the configured maxima, before allocator
  and parser overhead. This prevents mostly empty JSON rows from first being
  built into a multi-gigabyte `Value` tree. The collection runner's
  100,000-row limit is enforced while parsing, and parsed rows are moved
  instead of copied.
- A load run's gRPC status counts now keep one entry per valid code (0–16)
  and count every other `grpc-status` together under `-1` ("invalid: any
  code outside 0–16"). Before, each distinct value a target returned added
  an entry, growing the worker's memory and the work of every progress
  snapshot for the length of the run. The raw value is still kept in the
  execution record and the bounded failure examples.
- The HTML export of a load report now escapes the unit nouns from the
  report's protocol semantics everywhere it writes them. A report imported
  from a file or a full backup could otherwise place markup and inline
  styles in the exported page (the page's CSP already blocked scripts).

- Imports: parsing a JSON or YAML document now also bounds the string bytes
  it keeps (string values and map keys, every YAML alias expansion
  included) at twice `max_bytes`, charged before each string is copied. A
  long scalar that many aliases repeat was charged one node per copy, so a
  small file could make the preview allocate far more than its size; it is
  now refused with `LimitExceeded` ("document string bytes").
- WSDL imports: envelope generation is bounded by the envelope's
  `max_sample_nodes` budget and by the bytes it may generate (8 MiB per
  envelope, four times `max_bytes` per import, both charged before the text
  is built). Every schema node looked at counts: group and attributeGroup
  references, extension bases, particles, attributes, message parts and the
  children of each construct. `group` and `attributeGroup` references back to
  a group being expanded stop at the first repetition (`recursive_schema`).
  An attribute is written once per element. Once the import's envelope budget
  is spent, the remaining envelopes are left empty (`sample_size_limit`).
  A document in which an element has more than 256 namespaces in scope is
  refused (`LimitExceeded`), and once `max_operations` is reached the
  remaining operations are counted without being walked again for each
  port. Branching or self-referencing groups and types could make generation
  grow exponentially, and many message parts could exceed the envelope limit.
- OpenAPI imports: `allOf` merging charges each branch against the payload's
  `max_sample_nodes` budget, and a `$ref` it follows counts toward
  `max_ref_depth` like a direct `$ref` (`ref_depth_limit`). Generated
  values (including `minLength` padding), examples, defaults, merged schemas
  and per-operation parameter copies now share a byte budget for the whole
  import (four times `max_bytes`), charged before each value is made. When
  it is spent, the remaining samples are left out (`sample_size_limit`).
  The structural lookups made while writing one payload (XML names,
  multipart parts) share a node budget of their own and no longer use up the
  payload's. Long or branching composition chains, large examples reused
  many times and long generated strings in many operations could previously
  do unbounded work.
- Insomnia v4 imports: an export in which a workspace, request group or
  environment shares its `_id` with another resource is refused (`Invalid`,
  naming both). A repeated id of any other resource skips the later copy
  (`duplicate_resource_id`). A resource without an `_id` is never treated as
  a parent, the walk lists each parent's children once, and each request or
  group is imported at most once. Repeated, empty or self-referencing ids
  could make the import repeat subtrees exponentially.
- HTTP/3 response headers and trailers are now held to
  `max_response_header_bytes` (256 KiB by default) on every HTTP/3
  connection: requests, SSE, WebSocket, gRPC and the connection to a MASQUE
  proxy. For HTTP/3 the limit is at least 8 KiB (as for HTTP/1) and at most
  2^62-1 bytes, the largest a SETTINGS value can carry. Anvil advertises it
  as `SETTINGS_MAX_FIELD_SECTION_SIZE` (before, it advertised no limit), and
  a pooled connection (or gRPC channel) is reused only by requests with the
  same limit. It refuses a HEADERS frame that declares more before
  buffering any more of it, and refuses a decoded field section over it
  before keeping any of it. The request fails with
  `response_headers_too_large` (for gRPC trailers too) and the response
  stream is stopped. A pooled HTTP/3 request connection stays usable; a
  gRPC call that ends this way closes its HTTP/3 connection, as any call
  that does not end cleanly does. Other frames with a payload are bounded
  as well (at most 64 KiB on the control stream), and an unknown frame over
  the bound is skipped without being buffered. The vendored `h3` carries
  the change as a second patch (`vendor/README.md`).
- An HTTP/3 response can no longer outlive its deadlines or a cancel. The
  total deadline now also ends the response body (a body that keeps
  arriving just inside the idle deadline stopped only at
  `max_response_bytes`), and the wait for the end of the stream after the
  trailers is bounded by the body idle deadline, the total deadline and
  cancellation (before, it waited for the server however long it took).
  When any of them ends the response, Anvil stops the stream with
  `H3_REQUEST_CANCELLED` instead of leaving it open, and the response body
  phase is recorded as timed out or canceled rather than failed.
- Session transcript previews (text and hex), SSE event ids and types, and
  the effective-request body preview are now redacted before they are cut
  to their display size, not after. A known secret that crosses the cut is
  replaced whole, and the preview ends with the redaction marker where the
  secret starts, instead of keeping all but the part past the cut in live
  events and stored records (GHSA-jjvp-frqf-xw3p). An OAuth issuer's
  `error_description` now has the token request's own credentials replaced
  before it is cut to 200 characters.
- An SSE stream can no longer make a session retain metadata out of
  proportion to its limits (GHSA-gwfc-m32p-636g). An `id:` or `event:`
  value over 4 KiB stops the stream as a local limit as soon as the partial
  line is one, not once the line reaches the 1 MiB line bound; events share
  the last event id instead of copying it, and the transcript redacts that
  shared id once instead of once per event; a chunk is parsed only until
  `max_events` events are in hand; and a transcript entry keeps at most
  256 bytes of an event id or type (a longer one ends with `…`).
- A session peer that stops reading, or withholds HTTP/2 or QUIC
  flow-control credit, can no longer keep a session running after it is
  canceled (or the profile locks) or past its deadline
  (GHSA-24m4-27gj-gvmx). WebSocket scripted messages, interactive commands
  and automatic Pong and Close frames, raw TCP scripted and interactive
  sends and half-closes (scripted sends now honour the total deadline too,
  not only the write deadline), DTLS handshake flights and datagrams (over
  UDP, HBONE or MASQUE), HBONE interactive datagrams and MASQUE capsules are
  raced against cancellation and the applicable deadline. An interrupted
  write is never followed by a clean end: raw TCP skips its shutdown,
  WebSocket over HTTP/3 resets its stream, and HBONE and MASQUE tunnels
  (DTLS ones included) are reset. A raw TCP payload that was partly written
  is reported as possibly dispatched. Graceful Close frames and
  `close_notify` have their own short bound.
- Follow-ups to the three entries above (GHSA-jjvp-frqf-xw3p,
  GHSA-gwfc-m32p-636g, GHSA-24m4-27gj-gvmx):
  - The excerpts a diagnostic finding quotes from a response (a JSON
    `error`, a GraphQL or SOAP fault message, an HBONE tunnel refusal body,
    a Ferrum Edge body signature) are now redacted with the record's
    redactor before they are cut to 160–300 characters. Before, a secret
    the response echoed across the cut kept its prefix in the finding,
    because the record's redaction could no longer match it.
    `DiagnosticInput` has a new `redact` field for this. An HBONE refusal
    body is now captured up to 64 KiB past its 8 KiB bound and redacted
    before the record cuts it to the bound, and a malformed gRPC-Web trailer
    line quoted in a failure is redacted before it is cut to 64 characters.
  - An OAuth issuer's `error_description` also has the percent-encoded and
    form-encoded forms of the token request's credentials replaced before
    it is cut.
  - An interactive session no longer outlives its `SessionHandle`: dropping
    the handle cancels the session and aborts its task. A session task that
    ignores its cancel is aborted 5 s after `cancel()`, so `finish()` and
    `is_finished()` are bounded once a session is canceled (the record then
    says the session was aborted).
  - A raw TCP session, or a WebSocket session over HTTP/1.1 or HTTP/2, whose
    write was interrupted now resets its connection (`SO_LINGER` 0: RST
    instead of FIN), so the peer cannot read a partly written payload as a
    complete one. A WebSocket Close frame sent after a
    peer's protocol violation that is not written within 500 ms now counts
    as an interrupted write (over HTTP/3 the stream is reset, not finished).
  - DTLS inside an HBONE or MASQUE tunnel resets the tunnel only when a
    record was being sent when the cancel or deadline stopped it. Before,
    every cancel, total timeout and handshake timeout reset the tunnel, even
    while the session was only waiting for the peer.
  - The SSE transcript redacts the shared last event id again on each
    connection attempt, so the credentials a reconnection is signed with
    are redacted in it too.
- A WS-Security PasswordDigest UsernameToken's digest and nonce are now
  known secrets of the request, redacted in the effective-request preview
  and the execution record like the password. Together with the creation
  time they can be replayed against a service that keeps no nonce cache or
  Timestamp limit. (Part of #244.)
- Desktop development dependencies now override Mocha's vulnerable
  `serialize-javascript` dependency with patched version 7.0.5.
- A secret variable used only in what a session sends once it is open (a
  WebSocket message or subprotocol, a gRPC message, method or metadata
  value, an SSE `Last-Event-ID`, a raw TCP or UDP payload) is now redacted
  in the live transcript events and in the stored history, like a secret
  used in the URL or a header. The session's redactor was built before
  those values were resolved; it now takes them in once they are, before
  anything is redacted with it, and the stored transcript is redacted again
  with the record's redactor. Hex previews (binary messages, pings and
  payloads that are not printable text) are now redacted too, live and
  stored: a secret's lowercase hex is recognised. An SSE event type is now
  redacted in live events, as it was in the stored record. A secret in a
  hex- or base64-encoded field (a WebSocket binary message or ping, a TCP
  payload, a UDP datagram, a PROXY header TLV) is also redacted as the bytes
  it decodes to, as text and as hex, when they are at least 4 bytes long.
  The secrets a gRPC call signs with once server reflection resolves its
  schema (such as a freshly minted token) are now redacted in live events
  too, not only in the stored record.
- Follow-up to the session redaction above: a secret in a hex- or
  base64-encoded field that decodes to only 2 or 3 bytes is now redacted in
  hex previews, since the 4-character minimum applies to each redacted form
  rather than to the decoded byte count. A secret split across the
  encoding's alignment no longer makes the whole decoded field (up to
  8 MiB) a redaction pattern: only the bytes it covers, widened to whole
  bytes or base64 groups, are, so it is also recognised in the truncated
  preview of a field longer than the preview limit. The run history's
  scrub of a stored transcript now redacts event ids and event types as
  well as previews.
- Deleting a workspace now also forgets the OAuth tokens (access and
  refresh tokens, including interactive sign-ins) cached for it. Before, they
  stayed in memory until the lock, and a workspace restored with the same id
  sent them without a new sign-in. A token request or refresh of that
  workspace in flight across the delete, and a sign-in completed after it,
  no longer caches its token, and a send or sign-in whose context was built
  before the delete caches nothing for the workspace: a client-credentials
  token is acquired for that send only, and an interactive grant needs a new
  sign-in. Workload API SVIDs are not kept per workspace and are still
  cleared on lock.
