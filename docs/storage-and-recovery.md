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

Each vault secret belongs to one workspace. A request resolves a secret
reference only when its own workspace owns that secret, whether the reference
is in its auth, a variable, an environment or a profile. A reference to any
other secret (another workspace's, or one no workspace owns) fails as if the
secret were not stored, and nothing is sent. A saved request is prepared
only in its own workspace, and only with folders of that workspace; a scenario
or load plan runs only requests and a dataset of its own workspace. Creating a
secret requires the workspace that will own it.

A secret stored with no owning workspace (possible only through older builds)
no longer resolves for any request. Store its value again from the workspace
that uses it: open the field, choose **Replace**, and keep the value in the
vault again.

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
  - A full-backup restore writes everything, attachments included, in the
    transaction.

  Changes saved meanwhile by other commands are kept, so the checkpoint is not
  restored automatically; it stays on disk for a manual restore.

## Export and import

| Mode | Contents | Secrets |
|---|---|---|
| Share safely | One workspace, or every workspace when none is chosen | None — literal secrets become `{{placeholders}}` listed in the manifest |
| Encrypted transfer | One workspace, or every workspace when none is chosen | Vault secrets and the literal secrets, encrypted with a passphrase you share separately |
| Full backup | Everything including history and settings | Encrypted; an ANVILBAK file, not a bundle ([below](#full-backups)) |

An export without a workspace (`anvil export` without `--workspace`) is a
bundle of every workspace, not a backup: it carries no app settings, profiles,
spec-import records or load reports, and its bundle kind is `workspace`.

In either bundle mode only the vault is encrypted. The objects (names, URLs,
header and body text), attachments and history are ordinary zip entries that
anyone holding the file can read; secrets and literal secrets never appear in
them, but a credential typed into a body or URL is exported as written, with
a warning in the preview.

An encrypted-transfer bundle (format 2) seals its vault with the SHA-256 of
every other entry as associated data: the manifest (kind, mode, placeholders
and vault parameters included), `workspace/objects.json`, each attachment and
the history, with the format version. The vault therefore opens only inside
the exact bundle it was exported with. A change to any entry, or an entry
added or removed, is refused as a wrong passphrase or a modified bundle,
before any secret or literal is restored and before anything is written;
recomputing `checksums.json` does not change that. Each literal is restored
only to the field the export recorded, and only while that field still holds
its placeholder. A bundle whose manifest mode and vault disagree is refused.
Encrypted bundles written by earlier builds (format 1) sealed the vault
without binding anything else in the archive; they are refused, with or
without the passphrase, and must be exported again. Share-safe bundles of
either format still import.

Import is preview-then-apply with conflict policies (duplicate, merge, replace).
Duplicate gives every imported object, request revision and secret a new id and
makes each copied secret belong to the copied workspace, so the copy never
overwrites or depends on its source: deleting either leaves the other working.
A copy whose bundle left a secret out does not use the source's secret either.
Merge keeps objects, revisions and secrets that already exist. Replace
overwrites them, but never a secret that a workspace outside the bundle (or no
workspace) owns, and never an object stored in a different workspace from the
one the bundle gives it: the preview lists both, and a Replace import that
would overwrite one is refused and changes nothing. The preview lists every
object and secret that shares an id with one already stored.

Workspace ids travel in every bundle, so a bundle can claim a workspace that is
already stored here, such as a re-imported backup. Under Merge or Replace the
import then writes into that workspace, and whatever it adds there (a request
to any URL, a variable, an auth setting) can use that workspace's vault
secrets. The preview lists every such workspace as an error, and applying is
refused unless the user confirms each one after the preview (the desktop's
checkbox; `anvil import --into-existing <WORKSPACE_ID>`). Confirm only for a
bundle you trust: a passphrase shows the bundle was not altered after it was
exported, not who wrote it, and a share-safe bundle has no passphrase at all.
Duplicate never writes into a stored workspace.

A bundle is refused when any workspace-scoped object (folder, request,
environment, TLS, proxy or integration profile, dataset, scenario, load plan)
belongs to a workspace it does not contain; when a folder's parent, a
request's folder, or a request, dataset or environment that a scenario or load
plan names is missing from it or in another of its workspaces; when a secret
belongs to a workspace it does not contain; or when it gives two objects one
id. These checks are about the bundle's own consistency: "a workspace it
contains" can be one already stored here, as above. A request keeps its
current-revision link only when the bundle carries that revision of it.

Stored attachments (a binary or multipart body file, a gRPC schema file, a
dataset's data) are found by their content hash alone. Exports include the
bytes of every stored attachment their requests and datasets use, as long as
its content can be read on the exporting device; one whose content is missing
there (a blob lost to retention, or a request created without its file) travels
without it, and the export lists that request or dataset among its excluded
items. On import or restore, a request or dataset that names a stored
attachment without its bytes would resolve to content already stored on this
device, which may belong to another workspace. So the whole file is refused,
and nothing is written, when content with that hash is stored here. Otherwise
the reference is accepted, and the preview and report name the item: it will
fail until the file is attached again.

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
- Full backups are only ever ANVILBAK files. Early development builds wrote
  them as zip bundles whose vault bound nothing else in the archive. One whose
  manifest has kind `backup` or mode `full_backup`, or that carries app
  settings, is refused on import with "legacy full backups are not supported;
  restore from an ANVILBAK backup". One relabelled as an encrypted workspace
  bundle is refused because its vault is format 1 (above), and one whose
  manifest claims the current format fails the vault's authentication. No
  secret or literal from such a vault is ever restored. Their other entries
  were never encrypted, so a copy of one should be treated as plaintext.
  Bundle exports never write that kind or mode.
- It carries every row of every stored object kind (workspaces, folders,
  requests and all their revisions, environments, TLS, proxy and gateway
  profiles, datasets, scenarios, load plans, app settings, user profiles,
  spec-import provenance and run reports), every vault secret (workspace-owned
  and profile-level), every stored attachment, the complete history with its
  stored response bodies, and every load report.
- It does not carry OS keychain entries, local data keys, provider sessions,
  token-file bindings or linked-file bindings (they name files on this
  device); the preview lists them. Attachment index entries and blob pins are
  specific to one database and are rebuilt on restore. The restore preview
  lists each linked local file with the request or dataset that names it; a
  restore drops this device's linked-file bindings for every request and
  dataset it overwrites.
- `crates/anvil-app/tests/backup.rs` fails when the store gains a table or an
  object kind that a full backup neither carries nor lists as left out, and
  compares the whole inventory of a restored profile with its source.

Restore is preview-then-apply. Every item is checked against its schema
version, its type and the rest of the backup (ids, owning workspaces and
attachment hashes), stored attachments named without their bytes are handled
as for bundles (above), the import trust normalisation above applies (an
imported collection opened to its workspace is closed again; the backup's app
settings are normalised like workspace, folder and request settings), and
everything is written in one transaction after a checkpoint. A request
revision is restored under its request, in that request's workspace:
revisions whose request is not in the backup (it was deleted) are left out
with a warning, and one stored under another request or workspace is refused.
History records of a workspace that is not in the backup (it was deleted) are
left out with a warning. Replace overwrites items that have the same id; Merge
keeps them, including this profile's settings; Duplicate is refused, because a
backup restores items under their own ids. Nothing else in the profile is
deleted.

App settings are the lowest settings layer of every workspace's requests, so
Replace restores the backup's app settings only when every workspace stored
here is one the backup claims: into an empty profile, or over the backup's
own workspaces once they are approved (below). While the profile holds any
other workspace, Replace keeps this profile's app settings; the preview and
the report say so, and the plan counts them as kept.

Restore only a full backup that is your own or that you otherwise trust. Like
a bundle, a backup can claim a workspace already stored here, and what it
writes there can use that workspace's vault secrets. The preview lists every
such workspace, and the restore is refused, changing nothing, unless the user
confirms each one after the preview (the desktop's checkbox;
`anvil import --into-existing <WORKSPACE_ID>`). Replace is also refused when it
would overwrite an object, history record or load report stored in a
different workspace from the one the backup gives it, or a secret stored here
under a different owner; Merge keeps those. A restore into an empty profile
needs no confirmation.

## Schema versions and migration

- Every object and record carries `schema_version`; the database carries
  `DB_SCHEMA_VERSION`. Migrations run forward in a transaction at open.
- A database or bundle written by a **newer** schema is refused with a clear
  message instead of being modified.
- Bundles carry `format_version`; unknown future formats are rejected, and so
  are encrypted bundles of format 1 (see [Export and import](#export-and-import)).
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
