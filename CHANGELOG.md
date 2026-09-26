# Changelog

## [Unreleased]

### Changed

- Encrypted-transfer bundles now use bundle format 2: the encrypted vault is
  bound to every other entry of the bundle, so a bundle changed after export
  is refused before any secret is restored. Encrypted bundles exported by
  earlier builds (format 1), including whole-profile zip backups from early
  development builds, are refused on import; export them again with this
  version. Share-safe bundles of either format still import.
