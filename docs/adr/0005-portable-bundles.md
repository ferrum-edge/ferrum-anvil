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
  - **Budgets:** at most 20,000 entries, 128 MiB per entry and 256 MiB
    total inflated bytes, including manifest and checksums, and 4 Mi
    (4,194,304) JSON values across every JSON entry. Metadata uses the same
    per-entry budget. The compression-ratio check preserves the existing
    integer quotient: inflated bytes / max(compressed bytes, 1) must be at
    most 200. Before `zip` indexes the central directory, the raw
    end-of-central-directory records are checked: none may be ZIP64, and
    the last must declare at most 20,000 entries in a directory that fits
    before it. Before each entry is allocated, its declared size must fit
    both the per-entry budget and the remaining total (a reservation check
    that charges nothing). Every byte actually inflated is then charged
    against the one remaining total, with no refunds, metadata whose
    buffer is later dropped included. Reads stop at the declared size plus
    one sentinel byte, so actual sizes must equal declarations. Each JSON
    entry's values (strings, keys, containers and bare scalars) are counted
    from its text, without parsing, and charged against the JSON budget
    before it is parsed. Attachments move directly into the opened graph
    without a second retained copy. Exports count exact serialized lengths
    and JSON values against the same budgets and are refused, never split,
    when over them. Files over 128 MiB are refused when they are attached.
    These bound inflated, retained and parsed data, not the whole process:
    the input file, ciphertext/plaintext copies and key derivation add to
    it. The owner delegate adopted these budgets on 2026-10-06, replacing
    1 GiB/512 MiB; see the [resource policy](../security/bundle-resource-policy.md).
  - **Conflicts:** merge, replace or duplicate (duplicate remaps ids and
    labels name clashes).
  - **Atomicity:** a checkpoint is taken first and the import runs as one
    transaction.
- Trust normalisation on import: TLS verification bypasses are re-enabled,
  plain-HTTP Ferrum marker trust is turned off, cross-origin credential
  forwarding is turned off, the legacy HMAC opt-in is turned off, and
  scenarios and load plans become untrusted. Imports never run anything.
