# Storage, locking, recovery and migration

## Where data lives

| Platform | Default data directory |
|---|---|
| macOS | `~/Library/Application Support/Ferrum Anvil/` |
| Windows | `%APPDATA%\Ferrum Anvil\` |
| Linux | `$XDG_DATA_HOME/Ferrum Anvil/` (default `~/.local/share/Ferrum Anvil/`) |

`ANVIL_DATA_DIR` overrides the location for both the desktop and the CLI (`--data-dir`).
Each local profile has its own directory with a header (`profile.json`: KDF
parameters, wrapped keys, protection mode — no plaintext key) and an encrypted
SQLite database.

## What is encrypted

Everything the user creates or observes: workspaces, folders, requests and their
immutable revisions, environments, secrets, TLS/proxy/gateway profiles, datasets
and attachments, scenarios, load plans and reports, history records and (when
enabled) response bodies, and app settings. Each payload is sealed with
XChaCha20-Poly1305 using a record-bound AAD (table, kind, id). Only structural
columns needed for listing (ids, kinds, parent ids, sort keys, timestamps) are
stored in the clear. The plaintext-leak test searches the database, its WAL and
journal, and blobs for known secret and body values.

## Unlocking

| Protection | How the data key is obtained |
|---|---|
| Passphrase | Argon2id(passphrase, salt, parameters in the header) unwraps the data key |
| Recovery key | A random recovery key (shown once at creation of a passphrase profile) unwraps a second copy of the data key |
| OS keychain | The data key is stored in the platform credential store: the macOS Keychain, the Windows Credential Manager (per user, "local machine" persistence, so it does not roam with domain profiles), or the freedesktop Secret Service on Linux and the BSDs (GNOME Keyring, KWallet). There is no in-memory fallback. `crates/anvil-storage/tests/os_keychain.rs` round-trips a real entry on all three in CI. This is the first-run default ("Start now — no password"): at launch a single keychain profile opens without any input, but never after a manual, idle or sleep lock. Where no credential store exists (e.g. Linux without a Secret Service) the app falls back to a passphrase; it never stores data unencrypted. A keychain profile has no recovery key: if the keychain item is lost, only a portable backup restores the data |

A linked provider identity is **not** an unlock method; see `docs/identity.md`.

Locking (button, ⌘/Ctrl+L, idle timeout, system sleep) drops the data key,
cached OAuth tokens and pooled connections, aborts executions and interactive
sessions and stops load workers (their partial reports are kept). Backend
commands return `LOCKED` until unlock.

## Recovery

- **Forgot the passphrase:** use the recovery key on the lock screen, then set a
  new passphrase. Without the recovery key the data cannot be decrypted; Anvil
  will not pretend otherwise.
- **Lost machine / reinstall:** restore a **full backup** (encrypted with an
  export passphrase) into a new profile. It does not need the original OS
  keychain or data key.
- **Bad import:** every import takes a checkpoint (`VACUUM INTO`) before its
  transaction, and a failure rolls back that transaction only. Not every write
  is inside it:
  - A bundle import writes its objects and secrets in the transaction; its
    attachments are stored after the commit and stay if storing one fails.
  - A spec import writes its folders, requests, environments and source record
    in the transaction; the new workspace or root folder and the stored
    original file are written before it and stay if the transaction fails.
  - A full-backup restore writes everything, attachments included, in the
    transaction.

  Changes saved meanwhile by other commands are kept, so the checkpoint is not
  restored automatically; it stays on disk for a manual restore.

## Export and import

| Mode | Contents | Secrets |
|---|---|---|
| Share safely | One workspace | None — literal secrets become `{{placeholders}}` listed in the manifest |
| Encrypted transfer | One workspace | Vault secrets, encrypted with a passphrase you share separately |
| Full backup | Everything including history and settings | Encrypted; an ANVILBAK file, not a bundle ([below](#full-backups)) |

Import is preview-then-apply with conflict policies (duplicate, merge, replace).
Duplicate gives every imported object, request revision and secret a new id and
makes each copied secret belong to the copied workspace, so the copy never
overwrites or depends on its source: deleting either leaves the other working.
Merge keeps objects, revisions and secrets that already exist. A bundle whose
secrets belong to a workspace it does not contain, or that gives two objects
one id, is refused.

An encrypted bundle's vault key is derived with the Argon2id costs its manifest
names, before the vault can be authenticated. Those costs are refused, before
any passphrase is asked for or any derivation runs, unless they are within:

| Cost | Allowed |
|---|---|
| Memory | 8 KiB per lane up to 256 MiB |
| Passes | 1 to 10 |
| Lanes | 1 to 4 |
| Memory × passes | at most 1 GiB (e.g. 256 MiB for 4 passes) |
| Salt | 8 to 64 bytes |

Exports use 64 MiB, 3 passes and 1 lane.
Imports never send requests, run scripts or load plans, and never activate TLS
bypasses, plain-HTTP marker trust, cross-origin credential forwarding or the
legacy HMAC opt-in; the preview lists what was normalised. Device-bound items
(keychain entries, provider sessions, linked local files) are reported as
needing rebinding.

## Full backups

A full backup (*Whole app backup* in the desktop, `anvil export --mode backup`
in the CLI) has its own file format, separate from zip bundles, so that nothing
in it can be read or changed without the export passphrase:

- The file is a short header (format version, Argon2id costs and salt)
  followed by one XChaCha20-Poly1305 envelope that seals the whole payload: the
  manifest and every object, secret, attachment, history record and load
  report. The header bytes are the envelope's associated data. Without the
  passphrase nothing in the file is readable. The header (JSON, at most 4 KiB)
  is the only part parsed before authentication, and only to check its format
  and costs; a change to any byte (header, costs, salt or payload) then makes
  the restore fail before the payload is parsed or anything is written.
- The Argon2id costs are read before anything can be authenticated, so they
  are held to the same bounds as a bundle vault's (above) before any
  derivation runs. Exports use 64 MiB, 3 passes and 1 lane.
- Full backups are only ever ANVILBAK files. A zip bundle whose manifest has
  kind `backup` or mode `full_backup` (as early development builds wrote
  them), or that carries app settings, is refused on import with
  "legacy full backups are not supported; restore from an ANVILBAK backup",
  and nothing of it is restored. Bundle exports never write that kind or mode.
- It carries every row of every stored object kind (workspaces, folders,
  requests and all their revisions, environments, TLS, proxy and gateway
  profiles, datasets, scenarios, load plans, app settings, user profiles,
  spec-import provenance and run reports), every vault secret (workspace-owned
  and profile-level), every stored attachment, the complete history with its
  stored response bodies, and every load report.
- It does not carry OS keychain entries, local data keys, provider sessions or
  token-file bindings (they name files on this device); the preview lists them.
  Attachment index entries and blob pins are specific to one database and are
  rebuilt on restore. Linked local files are listed as needing rebinding.
- `crates/anvil-app/tests/backup.rs` fails when the store gains a table or an
  object kind that a full backup neither carries nor lists as left out, and
  compares the whole inventory of a restored profile with its source.

Restore is preview-then-apply. Every item is checked against its schema
version, its type and the rest of the backup (ids, owning workspaces,
attachment hashes), the import trust normalisation above applies, and
everything is written in one
transaction after a checkpoint. A request revision is restored under its
request, in that request's workspace: revisions whose request is not in the
backup (it was deleted) are left out with a warning, and one stored under
another request or workspace is refused. Replace overwrites items that have
the same id; Merge keeps them, including this profile's settings; Duplicate is refused,
because a backup restores items under their own ids. Nothing else in the
profile is deleted.

## Schema versions and migration

- Every object and record carries `schema_version`; the database carries
  `DB_SCHEMA_VERSION`. Migrations run forward in a transaction at open.
- A database or bundle written by a **newer** schema is refused with a clear
  message instead of being modified.
- Bundles carry `format_version`; unknown future formats are rejected.
- A bundle's manifest `schema_version`, and the `schema_version` of every object,
  settings record and history record in it, is checked before anything is
  decrypted, interpreted or written. A newer schema is refused, and so is an
  older one that has no migration step, so fields from another schema are never
  silently dropped.
- Contracts (`contracts/schemas`) are generated from the Rust types; additive
  fields use serde defaults so older records keep loading.

## History retention

Configurable in Settings: enable/disable history, keep or drop response bodies,
maximum age (days) and total size; pruning keeps the newest records within the
budget. "Clear all history" deletes history records only.

Stored attachments (binary and multipart bodies, datasets, imported spec
sources) are separate from history: their encrypted blobs are pinned, so
retention never removes them. Deleting a dataset deletes its content once no
request, revision, dataset, spec source, scenario or load plan still refers to
the same (content-addressed) attachment. Pins are re-applied to existing
attachments whenever a profile opens.

## Plaintext at rest

`crates/anvil-app/tests/at_rest.rs` plants a distinct marker in a workspace
name, a request name, URL, header and body, a vault secret, a secret variable,
an attachment and a dataset, sends the request (so the echoed exchange lands in
history), and then scans every file under the profile root (database, `-wal`,
`-shm` and journal side files, headers) and new files in the system temp
directory, as UTF-8 and UTF-16. No marker may appear, both while the store is
open and after it is closed. Anvil writes no crash reports.
