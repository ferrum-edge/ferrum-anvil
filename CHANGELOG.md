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
- A bundle import now seals, on this device only, every workspace it writes
  into, including Duplicate copies and new workspaces: its requests are
  refused this device's JWT-SVID (from the Workload API or a token file)
  until you allow it with **Allow on this device** in the workspace
  settings' Auth tab or `anvil workspace allow-device-identity <workspace>`.
  A JWT-SVID from a vault or variable value is unaffected. The desktop now
  binds a token file by the path you chose rather than the file it resolved
  to, so a Kubernetes projected token keeps working after it rotates, and a
  run or load run of a closed profile ends with a generic message in the
  new profile's window.
