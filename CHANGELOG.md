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
