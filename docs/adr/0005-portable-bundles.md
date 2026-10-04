# ADR 0005: Portable bundles

## Decision
- Zip bundles containing `manifest.json`, `workspace/objects.json`,
  `attachments/<sha256>`, `history/records.jsonl`,
  `secrets/portable-vault.enc` and `checksums.json`.
- Modes:
  - **Share safely** (default): no secrets. Sensitive literals are replaced
    by placeholders listed in the manifest.
  - **Encrypted transfer**: vault secrets and sensitive literals are
    included, encrypted under an export passphrase. The vault is sealed with
    the SHA-256 of every other entry (manifest included) as associated data,
    so it opens only inside the exact bundle it was exported with; the other
    entries are not encrypted. Encrypted bundles of format 1, whose vault
    bound nothing else, are refused.
  - **Full backup**: everything, encrypted. It restores into a clean install
    without the original keychain. It is not a zip bundle: one AEAD envelope
    seals the whole payload, bound to the header that names its key-derivation
    costs and salt, so no part of it is readable or modifiable without the
    passphrase (see `docs/storage-and-recovery.md#full-backups`). A zip
    bundle that describes a full backup is refused on import.
- Import happens in two steps: preview, then apply.
  - **Checks:** size limits, path traversal, symlinks, zip bombs and
    checksums. A wrong passphrase is rejected before anything changes.
    Before expanding entries, the reader checks central-directory names,
    regular-file types, duplicates (including raw names hidden by the ZIP
    name index), entry counts, declared sizes and the declared aggregate,
    and requires the manifest, checksum list and objects entry. It reads
    the manifest and checksums first, validates checksum coverage and the
    manifest digest, then checks format, schema and vault metadata before
    reading objects, the vault, attachments or history. Each subsequent
    entry is hashed while reading and verified before use; every digest is
    verified before an opened bundle is returned.
  - **Budgets:** at most 20,000 entries, 512 MiB per entry and 1 GiB total
    inflated bytes, including manifest and checksums. Metadata uses the
    same per-entry budget. The compression-ratio check preserves the
    existing integer quotient: inflated bytes / max(compressed bytes, 1)
    must be at most 200. The remaining aggregate is charged before each
    allocation. Reads stop at the smaller of the entry and remaining
    budgets plus one sentinel byte, and also probe the declared size plus
    one; actual sizes must equal declarations. Attachments move directly
    into the opened graph without a second retained copy.
    These are byte/work limits, not a resident-memory guarantee: valid
    untrusted bundles can still retain close to 1 GiB, with additional
    archive, parser, ciphertext/plaintext, input-buffer and KDF overhead.
    Large mandatory metadata remains supported too. Reducing these
    budgets or changing the in-memory opened-bundle contract needs an
    owner decision; see the [resource-policy proposal](../security/bundle-resource-policy-proposal.md).
  - **Conflicts:** merge, replace or duplicate (duplicate remaps ids and
    labels name clashes).
  - **Atomicity:** a checkpoint is taken first and the import runs as one
    transaction.
- Trust normalisation on import: TLS verification bypasses are re-enabled,
  plain-HTTP Ferrum marker trust is turned off, cross-origin credential
  forwarding is turned off, the legacy HMAC opt-in is turned off, and
  scenarios and load plans become untrusted. Imports never run anything.
