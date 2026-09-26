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
| Recovery key | A random recovery key (shown once at creation of a passphrase profile, or when a keychain profile is converted to a passphrase) unwraps a second copy of the data key |
| OS keychain | The data key is stored in the platform credential store: the macOS Keychain, the Windows Credential Manager (per user, "local machine" persistence, so it does not roam with domain profiles), or the freedesktop Secret Service on Linux and the BSDs (GNOME Keyring, KWallet). There is no in-memory fallback. `crates/anvil-storage/tests/os_keychain.rs` round-trips a real entry on all three in CI. This is the first-run default ("Start now — no password"): at launch a single keychain profile opens without any input, but never after a manual, idle or sleep lock. Where no credential store exists (e.g. Linux without a Secret Service) the app falls back to a passphrase; it never stores data unencrypted. A keychain profile has no recovery key: if the keychain item is lost, only a portable backup restores the data |

The backend accepts only the unlock methods of the profile's protection mode
(recorded in the plaintext header): the passphrase and recovery key for a
passphrase profile, the OS keychain for a keychain profile.

**Adding a passphrase to a keychain profile.** Settings → *Require an unlock
passphrase* converts an unlocked keychain profile to passphrase protection
(*Change unlock passphrase* is for passphrase profiles only). The data key is
not changed, so nothing is re-encrypted. In order:

1. The header is rewritten atomically with the passphrase wrap, a wrap for a
   **new recovery key** (shown once) and the passphrase mode: a synced
   temporary file is renamed over the header, then the directory is flushed
   (`fsync` on macOS, Linux and the BSDs; `FlushFileBuffers` on a directory
   handle on Windows). The directory flush is best effort: a file system that
   refuses it (some FUSE and SMB mounts) is logged, not treated as a failure,
   because the new header is already in place. From here on the keychain no
   longer opens the profile.
2. The keychain entry is removed and its account name dropped from the header.
   If the credential store refuses, or the app stops between the two steps,
   the header keeps the account name, and until the old entry is removed the
   removal is retried after each successful unlock. The retry edits the
   header as it is on disk at that moment, so a passphrase changed meanwhile
   is kept. An entry that holds a different key is left alone.

`crates/anvil-storage/tests/keychain_conversion.rs` and
`crates/anvil-app/tests/keychain_conversion.rs` cover this with keyring-core's
in-memory mock credential store.

A linked provider identity is **not** an unlock method; see `docs/identity.md`.

Locking (button, ⌘/Ctrl+L, idle timeout, system sleep) drops the data key,
cached OAuth tokens and pooled connections, aborts executions and interactive
sessions and stops load workers (their partial reports are kept). Backend
commands return `LOCKED` until unlock.

## Recovery

- **Forgot the passphrase:** use the recovery key on the lock screen, then set a
  new passphrase. A keychain profile converted to a passphrase has the
  recovery key shown at the conversion. Without the recovery key the data cannot be decrypted; Anvil
  will not pretend otherwise.
- **Lost machine / reinstall:** restore a **full backup** (encrypted with an
  export passphrase) into a new profile. It does not need the original OS
  keychain or data key.
- **Bad import:** every import takes a checkpoint (`VACUUM INTO`) before its
  transaction, and a failure rolls back that transaction only. Not every write
  is inside it:
  - A bundle import writes its objects and secrets in the transaction; its
    attachments are stored after the commit and stay if storing one fails.
  - A spec import writes everything in the transaction: the new workspace or
    root folder, the stored original file, its folders, requests,
    environments and source record. A failure, including one taking the
    checkpoint, leaves the profile as it was.

  Changes saved meanwhile by other commands are kept, so the checkpoint is not
  restored automatically; it stays on disk for a manual restore.

## Export and import

| Mode | Contents | Secrets |
|---|---|---|
| Share safely | One workspace | None — literal secrets become `{{placeholders}}` listed in the manifest |
| Encrypted transfer | One workspace | Vault secrets, encrypted with a passphrase you share separately |
| Full backup | Everything including history and settings | Encrypted |

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
legacy HMAC opt-in, and never open an imported collection's root folder to its
workspace; the preview lists what was normalised. Device-bound items
(keychain entries, provider sessions, linked local files) are reported as
needing rebinding, and the preview lists each linked local file with the
request or dataset that names it. A bundle import drops this device's
linked-file bindings for every request and dataset it overwrites.

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
