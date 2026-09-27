# Storage, locking, recovery and migration

## Where data lives

| Platform | Default data directory |
|---|---|
| macOS | `~/Library/Application Support/Ferrum Anvil/` |
| Windows | `%APPDATA%\Ferrum Anvil\` |
| Linux | `$XDG_DATA_HOME/Ferrum Anvil/` (default `~/.local/share/Ferrum Anvil/`) |

`ANVIL_DATA_DIR` overrides the location for both the desktop and the CLI (the
CLI also takes `--data-dir`). Each local profile has its own directory with a
header (`profile.json`: KDF parameters, wrapped keys and protection mode, no
plaintext key) and an encrypted SQLite database.

Warnings, such as a stored object that does not decode, go to a log. The
desktop writes `anvil.log` in its log directory at level `info`:

| Platform | Desktop log directory |
|---|---|
| macOS | `~/Library/Logs/com.ferrumedge.anvil/` |
| Windows | `%LOCALAPPDATA%\com.ferrumedge.anvil\logs\` |
| Linux | `$XDG_DATA_HOME/com.ferrumedge.anvil/logs/` (default `~/.local/share/com.ferrumedge.anvil/logs/`) |

Once it would pass 5 MiB (`anvil_app::logging::LOG_FILE_LIMIT`), it is
renamed `anvil.log.1`, replacing the one before, and a new one is started.
The CLI writes warnings and errors to stderr. `ANVIL_LOG` (`off`, `error`,
`warn`, `info`, `debug` or `trace`) sets another level for Anvil's own
crates in both; other crates log warnings and errors at most. A log line
names what its call site names (a kind and id, an error), never request
content or secrets.

## What is encrypted

Everything the user creates or observes: workspaces, folders, requests and
their immutable revisions, environments, secrets, TLS/proxy/gateway profiles,
datasets and attachments, scenarios, load plans and reports, history records
and (when enabled) response bodies, and app settings.

Each payload is sealed with XChaCha20-Poly1305 using a record-bound AAD
(table, kind, id). A vault secret's AAD also names the workspace that owns it
(or none), so a secret whose owner is changed in the database file no longer
decrypts. Only structural columns needed for listing (ids, kinds, parent ids,
sort keys, owners, timestamps) are stored in the clear. See
[Plaintext at rest](#plaintext-at-rest) for the leak test.

**Secrets belong to one workspace.** A request resolves a secret reference
only when its own workspace owns that secret, whether the reference is in its
auth, a variable, an environment or a profile. A reference to any other
secret (another workspace's, or one no workspace owns) fails as if the secret
were not stored, and nothing is sent. A saved request is prepared only in its
own workspace and with folders of that workspace; a scenario or load plan
runs only requests and a dataset of its own workspace. Creating a secret
requires the workspace that will own it.

A secret with no owning workspace (possible only from older builds) no longer
resolves for any request. Store its value again from the workspace that uses
it: open the field, choose **Replace**, and save the value to the vault again.

## Unlocking

| Protection | How the data key is obtained |
|---|---|
| Passphrase | Argon2id(passphrase, salt, parameters in the header) unwraps the data key. |
| Recovery key | A random recovery key unwraps a second copy of the data key. It is shown once: when a passphrase profile is created, or when a keychain profile is converted to a passphrase. |
| OS keychain | The data key is stored in the platform credential store: the macOS Keychain, the Windows Credential Manager (per user, "local machine" persistence, so it does not roam with domain profiles), or the freedesktop Secret Service on Linux and the BSDs (GNOME Keyring, KWallet). |

**OS keychain details.** This is the first-run default ("Start now — no
password"). At launch a single keychain profile opens without any input, but
never after a manual, idle or sleep lock. There is no in-memory fallback:
where no credential store exists (for example Linux without a Secret
Service) the app falls back to a passphrase, and it never stores data
unencrypted. A keychain profile has no recovery key, so if the keychain item
is lost only a portable backup restores the data.
`crates/anvil-storage/tests/os_keychain.rs` round-trips a real entry on all
three platforms in CI.

The backend accepts only the unlock methods of the profile's protection mode
(recorded in the plaintext header): the passphrase and recovery key for a
passphrase profile, the OS keychain for a keychain profile.

**The protection mode is authenticated.** The header carries an HMAC-SHA256
over the profile id, the protection mode and the key check, under a MAC key
derived from the data key (HKDF-SHA256, info `anvil-profile-protection-v1`).
Every unlock verifies it once the data key is obtained:

- A header edited to claim another mode is refused. Changing the passphrase
  or converting rewrites only a header that still verifies.
- Keychain entries written for a header with this MAC are tagged, and a
  tagged entry never opens a header without a MAC, so removing the MAC does
  not help.
- A keychain header never carries a passphrase or recovery wrap, so one
  without a MAC that does is refused too.

Headers and keychain entries from earlier builds have neither the MAC nor
the tag. They still open, and get both at their next successful unlock (the
MAC first, then the tag); such a header is trusted as found at its first
unlock on this build. One gap remains until the entry is gone: a keychain
entry left over from a conversion done by an earlier build holds the
untagged key. If the credential store refuses both to delete and to
overwrite it (step 3 below), a header edited back to keychain mode, with its
MAC and both wraps removed, still opens from it.

The header is plaintext, so its Argon2id costs and salts are checked before
any derivation runs, against the same bounds as a bundle's or backup's
([below](#export-and-import)). A header outside them is refused as
unreadable, for the passphrase and the recovery key alike, and no key is ever
wrapped with costs outside them.

### Adding a passphrase to a keychain profile

Settings → *Require an unlock passphrase* converts an unlocked keychain
profile to passphrase protection (*Change unlock passphrase* is for
passphrase profiles only). The data key does not change, so nothing is
re-encrypted. In order:

1. A header from an earlier build gets its MAC, and the keychain entry is
   tagged if it is not yet. If the credential store refuses, the conversion
   stops; nothing has changed beyond the MAC, which any unlock on this build
   also writes.
2. The header is rewritten atomically with the passphrase wrap, a wrap for a
   **new recovery key** (shown once) and the passphrase mode with its MAC.
   From here on the keychain no longer opens the profile.
   - The rewrite reads the header on disk under an advisory lock on
     `profile.lock` in the profile directory, which every header writer
     takes, and the header must still verify under the data key.
   - The writer syncs its own temporary file (named after its process and a
     random suffix), renames it over the header, then flushes the directory
     (`fsync` on macOS, Linux and the BSDs; `FlushFileBuffers` on a directory
     handle on Windows). The directory flush is best effort: a file system
     that refuses it (some FUSE and SMB mounts) is logged, not treated as a
     failure, because the new header is already in place.
   - A temporary file older than ten minutes, left by a writer that stopped
     before the rename, is removed by the next writer holding the lock.
3. The keychain entry is removed and its account name dropped from the
   header.
   - If the credential store refuses the delete, the header keeps the account
     name and the entry is overwritten with a marker that holds no key. If the
     app stops between the two steps, the header keeps the account name too.
   - Until the old entry is gone, removal is retried after each successful
     unlock. The retry edits the header as it is on disk, under the same
     lock, so a passphrase changed meanwhile by another process is kept. An
     entry that holds a different key is left alone. Each retry may raise the
     credential store's own permission prompt.
   - Settings lists such a leftover entry (service `com.ferrumedge.anvil`,
     account `profile-<id>`) so it can also be removed by hand. While the
     entry still holds the key (the store refused the overwrite too, or the
     app stopped before the delete), a copy of the header saved before the
     conversion is still a valid keychain header for it. Removing the entry
     is what fully ends keychain access.

`crates/anvil-storage/tests/keychain_conversion.rs` and
`crates/anvil-app/tests/keychain_conversion.rs` cover this with
keyring-core's in-memory mock credential store.

A linked provider identity is **not** an unlock method; see
[identity.md](identity.md).

### Locking

Locking (button, ⌘/Ctrl+L, idle timeout, system sleep) drops the data key,
cached OAuth tokens and pooled connections, aborts executions and
interactive sessions, and stops load workers (their partial reports are
kept). Deleting a workspace stops that workspace's load workers; their
reports are not kept. Backend commands return `LOCKED` until unlock.

## Recovery

- **Forgot the passphrase:** use the recovery key on the lock screen, then
  set a new passphrase. A keychain profile converted to a passphrase got its
  recovery key at the conversion. Without the recovery key the data cannot
  be decrypted.
- **Lost machine / reinstall:** restore a **full backup** (encrypted with an
  export passphrase) into a new profile. It does not need the original OS
  keychain or data key.
- **Bad import:** every import takes a checkpoint (`VACUUM INTO`) before its
  transaction, and a failure rolls back that transaction only. What the
  transaction covers depends on the import:
  - A bundle import writes its objects, secrets, load plans and history
    records in the transaction. Its attachments are stored after the commit
    and stay if storing one fails.
  - A spec import writes everything in the transaction: the new workspace or
    root folder, the stored original file, its folders, requests,
    environments and source record. A failure, including one taking the
    checkpoint, leaves the profile as it was.
  - A full-backup restore writes everything, attachments included, in the
    transaction.

  Changes saved meanwhile by other commands are kept, so the checkpoint is
  not restored automatically; it stays on disk for a manual restore.

## Export and import

| Mode | Contents | Secrets |
|---|---|---|
| Share safely | One workspace, or every workspace when none is chosen | None: literal secrets become `{{placeholders}}` listed in the manifest |
| Encrypted transfer | One workspace, or every workspace when none is chosen | Vault secrets and the literal secrets, encrypted with a passphrase you share separately |
| Full backup | Everything, including history and settings | Encrypted; an ANVILBAK file, not a bundle ([below](#full-backups)) |

An export without a workspace (`anvil export` without `--workspace`) is a
bundle of every workspace, not a backup. It carries no app settings,
profiles, spec-import records or load reports, and its bundle kind is
`workspace`.

### What a bundle carries

- Each workspace's load plans, except one that names a request, dataset or
  environment deleted since (an import would refuse it; the export lists it
  among its excluded items).
- When history is included, the workspace's history records without their
  response bodies. On import, a history record is kept only when it belongs
  to a workspace in the bundle. It keeps its request, revision and
  environment links only when the bundle carries that object in the record's
  workspace (a revision only as one of the linked request). A record that is
  not a valid execution record is left out with a warning, and one dated
  after the import is stored with the import time as its start, so history
  retention still ages it out.
- The bytes of every stored attachment its requests and datasets use (a
  binary or multipart body file, a gRPC schema file, a dataset's data), when
  the content can be read on the exporting device. One whose content is
  missing (a blob lost to retention, or a request created without its file)
  travels without it, and the export lists that request or dataset among its
  excluded items.
- The path of every linked local file its requests and datasets name, in
  every mode: a path on the exporting device, which can show its user name
  and folder layout. Only the binding stays on the device. The export
  preview warns that linked local files are named and lists each one with
  the request or dataset that names it (`linked_files` in the preview, as
  `request 'Upload': /path/to/file`); the manifest does not repeat them.
  Attach a copy instead to keep a local path out of a bundle.

In either bundle mode **only the vault is encrypted**. The objects (names,
URLs, header and body text), attachments and history are ordinary zip
entries that anyone holding the file can read. Secrets and literal secrets
never appear in them, but a credential typed into a body or URL is exported
as written, with a warning in the preview.

### Encrypted bundles are tamper-evident

An encrypted-transfer bundle (format 2) seals its vault with the SHA-256 of
every other entry as associated data: the manifest (kind, mode, placeholders
and vault parameters included), `workspace/objects.json`, each attachment and
the history, plus the format version. The vault therefore opens only inside
the exact bundle it was exported with:

- A change to any other entry, or an entry added or removed, is refused as a
  wrong passphrase or a modified bundle, before any secret or literal is
  restored and before anything is written. Recomputing `checksums.json` does
  not change that.
- Each literal is restored only to the field the export recorded, and only
  while that field still holds its placeholder.
- A bundle whose manifest mode and vault disagree is refused. Removing the
  vault, with the manifest relabelled to match, does not fail
  authentication: it turns the bundle into a share-safe one, from which no
  secret or literal is restored.
- A passphrase given for a share-safe bundle is refused rather than accepted
  as though it verified anything. In the CLI, unset `ANVIL_EXPORT_PASSPHRASE`
  (an empty value counts as unset) to import one.
- Encrypted bundles from earlier builds (format 1) sealed the vault without
  binding anything else in the archive. They are refused, with or without the
  passphrase, and must be exported again. Share-safe bundles of either format
  still import.

### Conflict policies

Import is preview-then-apply with a conflict policy. The preview lists every
object, secret and history record that shares an id with one already stored.

- **Duplicate** gives every imported object, request revision and secret a
  new id, and makes each copied secret belong to the copied workspace, so the
  copy never overwrites or depends on its source: deleting either leaves the
  other working. Load plans and history records get new ids too and follow
  the copied requests, dataset, environment and workspace. A copy whose
  bundle left a secret out does not use the source's secret either.
- **Merge** keeps objects, revisions and secrets that already exist.
- **Replace** overwrites them, but never a secret that a workspace outside
  the bundle (or no workspace) owns, an object stored in a different
  workspace from the one the bundle gives it, or a history record stored
  under another workspace (or none). The preview lists them, and a Replace
  import that would overwrite one is refused and changes nothing.

### Writing into a stored workspace

Workspace ids travel in every bundle, so a bundle can claim a workspace that
is already stored here, such as a re-imported backup. Under Merge or Replace
the import then writes into that workspace, and whatever it adds there (a
request to any URL, a variable, an auth setting) can use that workspace's
vault secrets. Duplicate never writes into a stored workspace.

The preview lists every such workspace as an error, and applying is refused
unless the user confirms each one after the preview (the desktop's checkbox;
`anvil import --into-existing <WORKSPACE_ID>`). Confirm only for a bundle you
trust. For an encrypted bundle whose vault opened, the passphrase shows the
bundle was not altered after it was exported, not who wrote it. A share-safe
bundle has no passphrase, and nothing shows it was not altered.

The confirmation holds only for the file that was previewed. The preview
reports the file's SHA-256 (`bundle_sha256`); an approval that names a stored
workspace must name that digest too, and a file with any other digest (one
replaced or changed since the preview) is refused before anything is read
from it. The desktop passes the digest back itself. In the CLI,
`--into-existing` approves the file as that command reads it, and
`--bundle-sha256 <SHA256>` from a reviewed `--dry-run` pins the approval to
that file (a `--dry-run` given it is refused for any other file). The same
applies to full backups.

### Consistency checks

A bundle is refused when:

- any workspace-scoped object (folder, request, environment, TLS, proxy or
  integration profile, dataset, scenario, load plan) or secret belongs to a
  workspace it does not contain;
- a folder's parent, a request's folder, or a request, dataset or
  environment that a scenario or load plan names is missing from it or in
  another of its workspaces;
- it gives two objects one id.

These checks are about the bundle's own consistency: "a workspace it
contains" can be one already stored here, as above. A request keeps its
current-revision link only when the bundle carries that revision of it.

Stored attachments are found by their content hash alone. On import or
restore, a request or dataset that names a stored attachment without its
bytes would resolve to content already stored on this device, which may
belong to another workspace. So the whole file is refused, and nothing is
written, when content with that hash is stored here. Otherwise the reference
is accepted, and the preview and report name the item: it will fail until
the file is attached again.

### Key-derivation bounds

An encrypted bundle's vault key is derived with the Argon2id costs its
manifest names, before the vault can be authenticated. Those costs are
refused, before any passphrase is asked for or any derivation runs, unless
they are within:

| Cost | Allowed |
|---|---|
| Memory | 8 KiB per lane up to 256 MiB |
| Passes | 1 to 10 |
| Lanes | 1 to 4 |
| Memory × passes | at most 1 GiB (e.g. 256 MiB for 4 passes) |
| Salt | 8 to 64 bytes |

Exports use 64 MiB, 3 passes and 1 lane. The same bounds apply to a
profile's own header ([Unlocking](#unlocking)) and to full backups.

### Canceling an import (desktop)

The desktop reads the file and derives the key on a worker thread.

- A preview or import started with an `attempt` id can be canceled with
  `import_cancel` (a lock cancels it too). The command returns `CANCELED` at
  once; the worker, which cannot interrupt the derivation, drops what it
  derived and writes nothing, not even the restore checkpoint.
- A bundle import or full-backup restore can be canceled until its key is
  derived and its contents checked. One that has begun writing finishes and
  reports its result.
- A lock or profile switch that lands before then also ends an import
  without writing, with or without an `attempt` id, even if the profile is
  unlocked again meanwhile.
- One import or preview worker runs at a time. While one is still running,
  including one canceled and still finishing its derivation, a new preview
  or import is refused with `IMPORT_BUSY`.
- `import_cancel` cancels only imports, restores and previews, never an
  execution or a sign-in.

The import dialog passes an `attempt` id, shows Cancel while a preview or
import runs (closing the dialog cancels it too), and explains a busy
refusal. The key a preview derives is not kept for the import that follows,
so the import derives it again: a preview can stay open indefinitely, and
keeping the key would keep material that opens the bundle in memory for that
long.

### Import trust normalisation

Imports never send requests or run scripts or load plans. They never
activate TLS bypasses, plain-HTTP marker trust, cross-origin credential
forwarding, 0-RTT early data or the legacy HMAC opt-in, and never open an
imported collection's root folder to its workspace. The preview lists what
was normalised.

Device-bound items (keychain entries, provider sessions, linked local files)
are reported as needing rebinding, and the preview lists each linked local
file with the request or dataset that names it. A bundle import drops this
device's linked-file bindings for every request and dataset it overwrites.
In the desktop, choose each linked file again with **Choose file…** beside
the request's body or gRPC schema, or beside the dataset in a load plan. A
request's file that is somewhere else on this device is repointed with
**Choose new location…**: the saved request then names the path picked in
the dialog, and only that request is bound to it. A later export carries the
new path, like any linked path.
An OAuth 2 profile imported from a bundle never keeps the token-cache id the
bundle gives it, so it caches its token under the workspace, folder or
request that defines it, never alongside a profile stored here that names
the same id.

## Full backups

A full backup (*Whole app backup* in the desktop, `anvil export --mode backup`
in the CLI) has its own file format, separate from zip bundles, so that
nothing in it can be read or changed without the export passphrase.

**Format.** The file is a short header (format version, Argon2id costs and
salt) followed by one XChaCha20-Poly1305 envelope that seals the whole
payload: the manifest and every object, secret, attachment, history record
and load report. The header bytes are the envelope's associated data.

- The header (JSON, at most 4 KiB) is the only part parsed before
  authentication, and only to check its format and costs. Its Argon2id costs
  are held to the same [bounds](#key-derivation-bounds) as a bundle vault's
  before any derivation runs. Exports use 64 MiB, 3 passes and 1 lane.
- A change to any byte (header, costs, salt or payload) makes the restore
  fail before the payload is parsed or anything is written.

**Legacy zip backups.** Full backups are only ever ANVILBAK files. Early
development builds wrote them as zip bundles whose vault bound nothing else
in the archive. On import:

- one whose manifest has kind `backup` or mode `full_backup`, or that carries
  app settings, is refused with "legacy full backups are not supported;
  restore from an ANVILBAK backup";
- one relabelled as an encrypted workspace bundle is refused because its
  vault is format 1;
- one whose manifest claims the current format fails the vault's
  authentication.

No secret or literal from such a vault is ever restored, and bundle exports
never write that kind or mode. Their other entries were never encrypted, so
treat a copy of one as plaintext.

**What it carries.** Every row of every stored object kind (workspaces,
folders, requests and all their revisions, environments, TLS, proxy and
gateway profiles, datasets, scenarios, load plans, app settings, user
profiles, spec-import provenance and run reports), every vault secret
(workspace-owned and profile-level), every stored attachment, the complete
history with its stored response bodies, and every load report.
`crates/anvil-app/tests/backup.rs` fails when the store gains a table or an
object kind that a full backup neither carries nor lists as left out, and
compares the whole inventory of a restored profile with its source.

**What it leaves out.** OS keychain entries, local data keys, provider
sessions, and token-file and linked-file bindings (they name files on this
device); the preview lists them. Attachment index entries and blob pins are
specific to one database and are rebuilt on restore. Device-identity seals
(this device's own choice) are not carried either, and the preview does not
list the seals held where the backup was taken: a restore seals every
workspace in the backup, in the same transaction, as a bundle import does
(see [identity.md](identity.md#8-target-api-workload-identity-the-spiffe-workload-api)).
The preview and report say so.

### Restoring

Restore is preview-then-apply, and everything is written in one transaction
after a checkpoint.

- Every item is checked against its schema version, its type and the rest of
  the backup (ids, owning workspaces and attachment hashes). Stored
  attachments named without their bytes are handled as for bundles.
- The import trust normalisation applies. An imported collection opened to
  its workspace is closed again, and the backup's app settings are
  normalised like workspace, folder and request settings.
- A request revision is restored under its request, in that request's
  workspace. Revisions whose request is not in the backup (it was deleted)
  are left out with a warning; one stored under another request or
  workspace is refused.
- History records and load reports of a workspace that is not in the backup
  are left out with a warning (deleting a workspace deletes both, so only an
  edited backup holds one). A restored history record is never dated after
  the restore, so age-based retention always reaches it.
- The restore preview lists each linked local file with the request or
  dataset that names it, and a restore drops this device's linked-file
  bindings for every request and dataset it overwrites.
- User profiles are restored as carried; nothing reads them yet, so they
  affect no request.
- Replace overwrites items that have the same id. Merge keeps them,
  including this profile's settings. Duplicate is refused, because a backup
  restores items under their own ids. Nothing else in the profile is
  deleted.

**App settings.** App settings are the lowest settings layer of every
workspace's requests. Replace therefore restores the backup's app settings
only when every workspace stored here is one the backup claims: into an
empty profile, or over the backup's own workspaces once they are approved
(below). While the profile holds any other workspace, Replace keeps this
profile's app settings, and the preview, the report and the plan say so.
When Replace does restore them, the preview and report say that too: they
then apply to every workspace here, including ones created later. App
settings also carry the lock, history retention and redaction policies. In
their default request settings a restore turns off only cross-origin
credential forwarding on redirect and 0-RTT early data; everything else,
including DNS overrides, resolver, proxy and TLS defaults and these
policies, is restored as the backup has them.

**Trust.** Restore only a full backup that is your own or that you otherwise
trust. Like a bundle, a backup can claim a workspace already stored here, and
what it writes there can use that workspace's vault secrets. The preview
lists every such workspace, and the restore is refused, changing nothing,
unless the user confirms each one after the preview (the desktop's checkbox;
`anvil import --into-existing <WORKSPACE_ID>`). A restore into an empty
profile needs no confirmation. Replace is also refused when it would
overwrite an object, history record or load report stored in a different
workspace from the one the backup gives it, or a secret stored here under a
different owner; Merge keeps those.

## Schema versions and migration

- Every object and record carries `schema_version`; the database carries
  `DB_SCHEMA_VERSION` (currently 2). Migrations run forward at open and at
  unlock, each step in one write transaction with the version bump that
  records it, so a step runs once and one that fails changes nothing.
- **Database schema 2** re-seals every vault secret so its AAD names its
  owner (id and owner each length-prefixed).
  - The owner is taken from the secret's owner column as the step finds it.
    Schema 1 did not bind that column, so the migration trusts it and binds
    whatever it names from then on.
  - The key is checked against the database's canary first, so a wrong key
    fails the unlock and changes nothing.
  - A secret that does not decrypt under its schema 1 AAD was already
    corrupt or altered (that AAD never changed). It is left sealed under the
    schema 1 AAD, which no schema 2 AAD equals, so reading it keeps failing
    and it can be deleted. The step still commits; the number left is logged
    and recorded in the database's `meta` table (`secrets_left_at_v2`,
    removed when none is left).
  - A secret that opens under its schema 2 AAD instead shows that the
    recorded version was set back after the step ran. The unlock fails as an
    integrity error, the profile stays locked and nothing is written. This
    detects a set-back database only while one of its schema 2 secrets still
    names its owner.
  - Earlier builds refuse a schema 2 database, and a full backup made from
    one, as newer.
- The history table is indexed by the response body each record references,
  so releasing a replaced body and retention find a blob's uses without a
  scan. The index has no schema version of its own: it is created, where
  missing, each time a profile is opened or unlocked, after the versioned
  steps. This is best effort: if it cannot be created, a warning is logged
  and the profile still opens. It changes no stored data, so the schema
  stays 2 and earlier builds of schema 2 still read the database and its
  full backups.
- Skipped secrets and the migration trust the database as found. Replacing
  the whole database with an older checkpoint, or restoring a schema 1
  checkpoint whose owner column was edited, cannot be detected without state
  kept outside the database.
- Restoring a checkpoint opens it read-only and, before the live database is
  touched, refuses one that was written by a newer schema, sealed with
  another data key, or whose recorded version was set back below schema 2
  while a vault secret in it opens under its schema 2 AAD (the migration
  would fail on it). A checkpoint from an older schema is migrated under the
  same hold of the connection as the copy; if the copy or the migration
  fails, the profile is left locked. Every write, sealing or not, checks the
  lock only once it holds the connection, so one that raced a failed restore
  fails as locked instead of writing to the copied database.
- A database or bundle written by a **newer** schema is refused with a clear
  message instead of being modified.
- Bundles carry `format_version`. Unknown future formats are rejected, and
  so are encrypted bundles of format 1 (see
  [Export and import](#export-and-import)).
- A bundle's manifest `schema_version`, and the `schema_version` of every
  object, settings record and history record in it, is checked before
  anything is decrypted, interpreted or written. A newer schema is refused,
  and so is an older one that has no migration step, so fields from another
  schema are never silently dropped.
- Contracts (`contracts/schemas`) are generated from the Rust types. Additive
  fields use serde defaults so older records keep loading.

## History retention

Configurable in Settings: enable or disable history, keep or drop response
bodies, maximum age (days) and total size. Pruning keeps the newest records
within the budget. "Clear all history" deletes history records only. A
history record that is overwritten (an import under Replace) releases its old
response body unless another record, or the new version of the same record,
still uses it. Retention and that release look up a blob's uses by index and
its pin by primary key.

Stored attachments (binary and multipart bodies, datasets, imported spec
sources) are separate from history: their encrypted blobs are pinned, so
retention never removes them. Deleting a request (with its revisions, also
when its folder is deleted) or a dataset, or replacing a dataset's file,
deletes the content it held (unless a user attached it within the grace
period, below) once no request, revision, dataset, spec source,
scenario or load plan still refers to the same (content-addressed)
attachment. The check and the delete run in one write transaction, so
nothing can refer to it in between.

A file the user attaches (`App::put_attachment`: a body or multipart file, a
gRPC schema file, a dataset) is stored before the request or dataset that
uses it is saved, in a separate call. Its index entry is marked as added by
a user (`"user": true`, with `"attached_at"`, the time in unix
milliseconds it was last attached; entries written earlier have neither),
and no automatic release, such as a reimport releasing the source file it
replaces or `App::release_attachment`, deletes a marked attachment: only
deleting or replacing an item that held it does. A bundle import or a
restore stores the files its items reference without marking them (an entry
already marked stays marked). A save checks, in its own write transaction,
that every stored attachment the request or dataset names and did not hold
when last saved is still stored, and is refused otherwise (attach the file
again), so a saved item never names content deleted in between. A duplicate
of a request may name the files that request holds even when one is no
longer stored.

The mark does not record which draft holds a file. Deleting a request (also
when its folder is deleted) or a dataset, or replacing a dataset's file,
therefore keeps a file a user attached within the grace period (below; a
mark without a time counts as recent until the cleanup at open records
one), even when nothing saved references it any more: a request or dataset
not saved yet may hold it, and the cleanup of files attached and never
saved decides it once the period is over. A file attached longer ago is
released once nothing saved references it; a draft that still has it
attached is then refused on save with "attach it again", and attaching the
file again stores it again.

Deleting a request decrypts only its own revisions, found by the request
they are filed under, and the reference check reads every object of those
kinds once for all the files the request held. An object there that does not
decrypt could reference any of them, so the delete then keeps every file it
held instead of failing. That object is logged as a warning naming its kind
and id (never its content), so the damaged row can be found and repaired or
deleted. Pins are re-applied to existing attachments, in one write
transaction, whenever a profile opens.

Deleting a workspace deletes its items and, in the same write transaction,
releases every stored file they referenced that no item of another
workspace still references, except a file a user attached within the grace
period (below; a mark without a time counts as recent until the cleanup at
open records one): a request or dataset of another workspace not saved yet
may hold it, so the cleanup of files attached and never saved decides it
once the period is over. A file referenced by any saved item in any
workspace is never released.

### Cleanup when a profile opens

After the pins are re-applied, opening a profile runs a cleanup
(`App::clean_up_storage_if_due`) once a day at most
(`anvil_app::cleanup::CLEANUP_INTERVAL`, measured from the last pass;
`App::clean_up_storage` runs one at once):

- Revisions filed under a request that no longer exists are removed
  (builds before deletes removed a request's revisions left them behind;
  after the first pass, and unless a backup restores such a profile, there
  are none). A revision filed under no request is kept. The stored files
  only those revisions referenced are released, except one a user attached
  within the grace period: attaching it again restarts its wait.
- A file a user attached (`"user": true`) whose `"attached_at"` is older
  than the grace period, **30 days** (`anvil_app::cleanup::ATTACHMENT_GRACE`),
  is released if no saved item references it: it was attached to a request
  or dataset that was never saved. Attaching the same content again restarts
  the period, and a later save naming a released file is refused ("attach it
  again"). One that a saved item references loses its mark: from then on it
  is held like any other file, and later passes do not check it again.
- A mark with no `"attached_at"` (written before the time was recorded)
  counts as recent, so on its own it would never age. The first pass that
  sees one records its own time there (even a pass blocked by an object that
  does not decode), and the grace period runs from then.

Both use the same reference check as a delete. The pass reads what
references each file in a read transaction, which never takes the database
write lock, then removes and releases in a short write transaction only if
nothing was written to the database in between (by this connection, another
process or a checkpoint restore; `anvil_storage::store::ChangeMarker`).
Otherwise it reads again, up to three times, and then gives up until the
next pass. When an object does not decode, it could name any file, so the
pass removes and releases nothing (the orphaned revisions stay, and so keep
track of their files, until it is repaired or deleted); each such object is
logged as a warning by kind and id, and the pass reports them. A pass with
nothing to release decrypts only the attachment index entries and any
orphaned revisions; a pass blocked by an object that does not decode reads
every object that can reference a file, so while none of those objects and
no attachment index entry has changed since (by id, parent and time
written), the pass at open is skipped: it would find the same. A cleanup
that fails does not stop the profile opening; it is logged and runs again at
a later open.

The last pass is kept in the database's `meta` table (a plaintext note of
this device, never carried by a backup or export): when it ran, how many
revisions it removed and files it released, and the kind and id of each
object that did not decode. `anvil storage-cleanup` prints it (`--json` as
JSON, `--now` runs a pass first), and the desktop reads it with the
`storage_cleanup_last` command (`api.storageCleanupLast()`); the desktop has
no screen for it yet.

## Plaintext at rest

`crates/anvil-app/tests/at_rest.rs` plants a distinct marker in a workspace
name, a request name, URL, header and body, a vault secret, a secret
variable, an attachment and a dataset, and sends the request (so the echoed
exchange lands in history). It then scans every file under the profile root
(database, `-wal`, `-shm` and journal side files, headers) and new files in
the system temp directory, as UTF-8 and UTF-16. No marker may appear, both
while the store is open and after it is closed. Anvil writes no crash
reports.
