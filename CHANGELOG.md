# Changelog

## [Unreleased]

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

### Fixed

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
