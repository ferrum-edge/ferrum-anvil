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
  thread, one import at a time, and a preview or import can be canceled while
  the key is derived (`import_apply` and `import_preview` take an optional
  `attempt` id for `import_cancel`); a canceled import writes nothing. For
  now cancellation is backend-only (the UI does not pass `attempt` yet), and
  a full-backup restore can be canceled only before it starts. The key a
  preview derives is not kept for the import that follows.
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

- A load run now hands its worker every vault secret the plan's requests
  resolve: the datagram PROXY-protocol authentication secret of a UDP
  request, and the client identity of the selected proxy's own TLS profile
  (which also travels to the worker now), were missing, so those requests
  failed preparation in the worker ("the datagram secret is not available",
  or the proxy's TLS profile "no longer exists"). A request of another
  protocol with a leftover UDP section ships no datagram secret.
