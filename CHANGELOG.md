# Changelog

## [Unreleased]

### Added

- Desktop: an imported collection's root folder has a **Workspace scope** tab
  in its folder settings. It shows whether the collection is isolated from
  its workspace (the default) or opened to it on this device, and which
  variables, environments, auth, run values and identities its requests
  resolve either way. **Open to workspace…** asks for confirmation first;
  **Isolate again** does not. Ordinary folders have no such tab, and an
  import still never opens a collection.

### Changed

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
- **Breaking (API):** `App::release_attachment` keeps a file a user attached
  (`App::put_attachment`) and returns `false` for it, even when nothing
  references it. `App::save_request`, `App::create_request` and
  `App::save_dataset` can now fail with `AppError::Invalid` ("an attached
  file ... is no longer stored; attach it again, then save") when they name a
  stored file the item did not hold before and that is not stored.

### Fixed

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
  tickets while its cookies were refused.
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
  The app's lock and a workspace delete do not clear a load run's engines:
  runs are expected to be stopped on lock (see #162).
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
