# ADR 0005: Portable bundles

## Decision
- Zip bundles containing `manifest.json`, `workspace/objects.json`,
  `settings/portable.json`, `attachments/<sha256>`, `history/records.jsonl`,
  `secrets/portable-vault.enc` and `checksums.json`.
- Modes:
  - **Share safely** (default): no secrets. Sensitive literals are replaced
    by placeholders listed in the manifest.
  - **Encrypted transfer**: vault secrets are included, encrypted under an
    export passphrase.
  - **Full backup**: everything, encrypted. It restores into a clean install
    without the original keychain.
- Import happens in two steps: preview, then apply.
  - **Checks:** size limits, path traversal, symlinks, zip bombs and
    checksums. A wrong passphrase is rejected before anything changes.
  - **Conflicts:** merge, replace or duplicate (duplicate remaps ids and
    labels name clashes).
  - **Atomicity:** a checkpoint is taken first and the import runs as one
    transaction.
- Trust normalisation on import: TLS verification bypasses are re-enabled,
  plain-HTTP Ferrum marker trust is turned off, cross-origin credential
  forwarding is turned off, the legacy HMAC opt-in is turned off, and
  scenarios and load plans become untrusted. Imports never run anything.
