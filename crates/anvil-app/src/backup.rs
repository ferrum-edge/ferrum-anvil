//! Full backups: all portable data of a profile in one encrypted,
//! authenticated file.
//!
//! ```text
//! "ANVILBAK" || header length (u32, big endian) || header (JSON) || envelope
//! ```
//!
//! The header holds only what opening needs before a key exists: format,
//! format version, cipher, and the Argon2id costs and salt. The envelope
//! (XChaCha20-Poly1305, see `anvil_storage::crypto`) seals the whole payload
//! (manifest, objects, secrets, attachments, history and load reports) with
//! everything before it (signature, length and header) as associated data.
//! Nothing in the file is readable without the passphrase. The header (JSON,
//! at most 4 KiB) is the only part parsed before authentication, and only to
//! check its format and bounded key-derivation costs; a change to any byte,
//! header included, then fails authentication before the payload is parsed
//! or anything is written.
//!
//! Full backups are never zip bundles: a bundle that describes one is refused
//! by `anvil_portability::bundle::open`.
//!
//! Every store table and object kind is either carried or listed with the
//! reason it stays behind ([`TABLES`], [`OBJECT_KINDS`], [`NOT_CARRIED_KINDS`]);
//! `tests/backup.rs` fails when the store gains one that is in neither.
//!
//! A restore validates every item against its type, applies the same safety
//! normalisation as bundle imports (app settings included), and writes
//! everything in one transaction after taking a checkpoint. Like a bundle
//! import, it writes into a workspace stored here only once the user approves
//! it: a backup's passphrase says nothing about who made it. App settings
//! apply to every workspace's requests, so Replace also keeps this profile's
//! app settings while it holds a workspace the backup does not claim.

use crate::linked_files::LinkedFileBinding;
use crate::port::{self, ImportApproval, ImportReport};
use crate::specs::SpecSourceRecord;
use crate::workspace::attachment_index_id;
use crate::{App, AppError, Result, settings_id};
use anvil_domain::Id;
use anvil_domain::execution::ExecutionRecord;
use anvil_domain::integration::IntegrationProfile;
use anvil_domain::load::{LoadPlan, LoadReport};
use anvil_domain::runner::RunReport;
use anvil_domain::settings::AppSettings;
use anvil_domain::tls::{ProxyProfile, TlsProfile};
use anvil_domain::workspace::{Dataset, Environment, Folder, RequestDefinition, RequestRevision, Scenario, UserProfile, Workspace};
use anvil_portability::PortableGraph;
use anvil_portability::bundle::{BundleError, BundleKind, ExportMode, MIN_SCHEMA_VERSION, Placeholder};
use anvil_portability::plan::{self, ConflictPolicy, Existing, ImportPlan};
use anvil_portability::sanitize::ContentWarning;
use anvil_portability::validate::UncarriedAttachment;
use anvil_storage::crypto::{self, KdfParams};
use anvil_storage::store::DB_SCHEMA_VERSION;
use anvil_storage::{StoreError, StoreRead, StoreTx, kind};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const MAGIC: &[u8; 8] = b"ANVILBAK";
pub const FORMAT: &str = "anvil-backup";
pub const FORMAT_VERSION: u32 = 1;
const CIPHER: &str = "xchacha20poly1305";
const MAX_HEADER_BYTES: usize = 4096;
/// Largest backup file written or opened.
pub const MAX_BACKUP_BYTES: u64 = 2 * 1024 * 1024 * 1024;
pub const MIN_PASSPHRASE_LEN: usize = 8;
const SALT_LEN: usize = 16;
const MIN_SALT_LEN: usize = 8;
const MAX_SALT_LEN: usize = 64;
const MAX_LISTED_CONFLICTS: usize = 50;

/// Bounds on the Argon2id costs a backup may name: the same as for bundle
/// vaults.
pub use anvil_portability::bundle::{MAX_KDF_ITERATIONS, MAX_KDF_MEMORY_KIB, MAX_KDF_PARALLELISM, MAX_KDF_WORK};

/// Plan labels of the items that are not objects.
const SECRET: &str = "secret";
const HISTORY: &str = "history";
const LOAD_REPORT: &str = "load_report";

/// Object kinds a full backup carries, every row of each.
pub const OBJECT_KINDS: &[&str] = &[
    kind::WORKSPACE,
    kind::FOLDER,
    kind::REQUEST,
    kind::REVISION,
    kind::ENVIRONMENT,
    kind::TLS_PROFILE,
    kind::PROXY_PROFILE,
    kind::INTEGRATION,
    kind::DATASET,
    kind::SCENARIO,
    kind::LOAD_PLAN,
    kind::APP_SETTINGS,
    kind::USER_PROFILE,
    kind::SPEC_SOURCE,
    kind::RUN_REPORT,
];

/// Object kinds a full backup does not carry as rows, and why.
pub const NOT_CARRIED_KINDS: &[(&str, &str)] = &[
    (kind::IMPORT_SOURCE, "attachment index entries name blobs by a key of this profile; restore rebuilds them from the attachments"),
    (kind::TOKEN_FILE, "token-file bindings name files on this device; they are bound again on the target machine"),
    (kind::LINKED_FILE, "linked-file bindings name files on this device; they are chosen again on the target machine"),
];

/// Every store table and how a full backup covers it.
pub const TABLES: &[(&str, &str)] = &[
    ("objects", "every row of the kinds in OBJECT_KINDS; attachment index rows are rebuilt from the attachments"),
    ("secrets", "every vault secret, workspace-owned and profile-level"),
    ("blobs", "attachment contents and stored response bodies, with the attachments and history records that use them"),
    ("history", "every execution record with its stored response body"),
    ("load_reports", "every load report"),
    ("meta", "not carried: the schema version, key check and blob pins belong to this database and are recreated"),
];

const KEYCHAIN_NOTE: &str =
    "OS keychain entries, local master keys and signed-in provider sessions are device-bound and are never exported.";
const LINKED_FILES_NOTE: &str =
    "Some items reference linked local files; attach them to the workspace or relink them on the target machine.";
const MERGE_NOTE: &str =
    "Merge keeps this profile's settings and every item that already exists here; Replace restores the backup's versions.";
const KEPT_SETTINGS_NOTE: &str =
    "Replace keeps this profile's app settings: they apply to every workspace here, and some are not in the backup.";

#[derive(Debug, thiserror::Error)]
pub enum BackupError {
    #[error("not an Anvil full backup: {0}")]
    NotABackup(String),
    #[error("this backup was created by a newer Anvil (format {found}); this version supports format {supported}")]
    FutureFormat { found: u32, supported: u32 },
    #[error("this backup holds data from a newer Anvil ({what} {found}; this version supports {supported}); nothing was restored")]
    FutureSchema { what: &'static str, found: i64, supported: i64 },
    #[error("the backup's key-derivation settings are not supported ({0}); nothing was restored")]
    UnsupportedKdf(String),
    #[error("the backup is larger than {max} bytes", max = MAX_BACKUP_BYTES)]
    TooLarge,
    #[error("a full backup needs a passphrase of at least {min} characters", min = MIN_PASSPHRASE_LEN)]
    WeakPassphrase,
    #[error("the backup is encrypted; a passphrase is required")]
    PassphraseRequired,
    #[error("the passphrase is not correct, or the backup was modified; nothing was restored")]
    Authentication,
    #[error("a full backup restores every item under its own id; choose merge or replace")]
    DuplicateUnsupported,
    #[error("the backup is not valid: {0}")]
    Invalid(String),
}

/// What a full backup holds besides its contents. Sealed with them.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BackupManifest {
    pub format: String,
    pub format_version: u32,
    pub kind: BundleKind,
    pub mode: ExportMode,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub app_version: String,
    pub schema_version: u32,
    pub db_schema_version: i64,
    /// Rows per object kind, and secrets, attachments, history and load reports.
    pub counts: BTreeMap<String, usize>,
    /// Stored items that could not be carried (labels only).
    pub excluded: Vec<String>,
    /// Device-specific items that need rebinding on the target machine.
    pub device_bindings: Vec<String>,
    /// Always empty: a full backup carries every value itself, encrypted.
    #[serde(default)]
    pub placeholders: Vec<Placeholder>,
    /// Always empty: nothing is rewritten on export.
    #[serde(default)]
    pub content_warnings: Vec<ContentWarning>,
    pub includes_history: bool,
}

/// Summary shown before writing (and returned after).
#[derive(Debug, Clone, Serialize)]
pub struct BackupPreview {
    pub manifest: BackupManifest,
    pub secrets_included: usize,
    /// Always 0: no value is replaced by a placeholder.
    pub literals_moved: usize,
}

/// Everything a full backup carries, decrypted.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct BackupContents {
    pub objects: Vec<ObjectRow>,
    pub secrets: Vec<SecretRow>,
    pub attachments: Vec<AttachmentRow>,
    pub history: Vec<HistoryRow>,
    pub load_reports: Vec<Value>,
}

/// One row of the store's object table.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ObjectRow {
    pub kind: String,
    pub id: String,
    #[serde(default)]
    pub workspace_id: Option<String>,
    #[serde(default)]
    pub parent_id: Option<String>,
    #[serde(default)]
    pub sort_key: f64,
    pub value: Value,
}

/// One vault secret; `workspace_id` is `None` for a profile-level secret.
#[derive(Clone, PartialEq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SecretRow {
    pub id: String,
    #[serde(default)]
    pub workspace_id: Option<String>,
    pub label: String,
    pub value: String,
}

impl std::fmt::Debug for SecretRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretRow").field("id", &self.id).field("workspace_id", &self.workspace_id).field("label", &self.label).finish()
    }
}

/// A stored attachment, addressed by the SHA-256 of its content.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AttachmentRow {
    pub sha256: String,
    pub content_b64: String,
}

/// One execution record and its stored response body, if any.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HistoryRow {
    pub id: String,
    #[serde(default)]
    pub workspace_id: Option<String>,
    #[serde(default)]
    pub request_id: Option<String>,
    pub started_at: i64,
    pub record: Value,
    #[serde(default)]
    pub body_b64: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Header {
    format: String,
    format_version: u32,
    cipher: String,
    kdf: KdfParams,
    salt_b64: String,
}

#[derive(Serialize)]
struct PayloadRef<'a> {
    manifest: &'a BackupManifest,
    contents: &'a BackupContents,
}

#[derive(Deserialize)]
struct Payload {
    manifest: BackupManifest,
    contents: BackupContents,
}

/// Whether `bytes` start like a full backup (as opposed to a zip bundle).
pub fn is_backup(bytes: &[u8]) -> bool {
    bytes.starts_with(MAGIC)
}

/// Refuse Argon2id costs outside the bundle-vault bounds. A backup's costs
/// are read before anything can be authenticated, so they are checked before
/// any derivation runs.
pub fn check_kdf(p: &KdfParams) -> std::result::Result<(), BackupError> {
    anvil_portability::bundle::check_kdf(p).map_err(|e| match e {
        BundleError::UnsupportedKdf(why) => BackupError::UnsupportedKdf(why),
        other => BackupError::UnsupportedKdf(other.to_string()),
    })
}

/// Refuse a record whose `schema_version` this build cannot read: serde
/// would silently drop the fields a newer schema added.
fn check_record_schema(record: &Value, what: &str, id: &str) -> std::result::Result<(), BackupError> {
    let Some(v) = record.get("schema_version") else { return Ok(()) };
    let found = v.as_u64().ok_or_else(|| invalid(format!("{what} {id} has an invalid schema_version")))?;
    if found > u64::from(anvil_domain::SCHEMA_VERSION) {
        let (found, supported) = (i64::try_from(found).unwrap_or(i64::MAX), i64::from(anvil_domain::SCHEMA_VERSION));
        return Err(BackupError::FutureSchema { what: "object schema", found, supported });
    }
    if found < u64::from(MIN_SCHEMA_VERSION) {
        return Err(invalid(format!("{what} {id} uses schema {found}, which this version cannot read")));
    }
    Ok(())
}

/// Encrypt and authenticate `manifest` and `contents` as one full-backup file.
pub fn seal(
    manifest: &BackupManifest,
    contents: &BackupContents,
    passphrase: &str,
    kdf: KdfParams,
) -> std::result::Result<Vec<u8>, BackupError> {
    if passphrase.len() < MIN_PASSPHRASE_LEN {
        return Err(BackupError::WeakPassphrase);
    }
    check_kdf(&kdf)?;
    let payload = Zeroizing::new(serde_json::to_vec(&PayloadRef { manifest, contents }).map_err(|e| BackupError::Invalid(e.to_string()))?);
    if payload.len() as u64 > MAX_BACKUP_BYTES {
        return Err(BackupError::TooLarge);
    }
    let salt = crypto::random_bytes(SALT_LEN);
    let header = Header { format: FORMAT.into(), format_version: FORMAT_VERSION, cipher: CIPHER.into(), kdf, salt_b64: B64.encode(&salt) };
    let header = serde_json::to_vec(&header).map_err(|e| BackupError::Invalid(e.to_string()))?;
    let len = u32::try_from(header.len()).map_err(|_| BackupError::Invalid("header too large".into()))?;
    let key = crypto::derive(passphrase.as_bytes(), &salt, &kdf).map_err(|e| BackupError::UnsupportedKdf(e.to_string()))?;
    let mut out = Vec::with_capacity(MAGIC.len() + 4 + header.len() + payload.len() + 64);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&header);
    // Everything before the envelope is its associated data.
    let envelope = crypto::seal(&key, &out, &payload);
    out.extend_from_slice(&envelope);
    if out.len() as u64 > MAX_BACKUP_BYTES {
        return Err(BackupError::TooLarge);
    }
    Ok(out)
}

/// Authenticate and decrypt a full-backup file. Only the header's format,
/// cipher and key-derivation fields are read before authentication succeeds.
pub fn open(bytes: &[u8], passphrase: Option<&str>) -> std::result::Result<(BackupManifest, BackupContents), BackupError> {
    if bytes.len() as u64 > MAX_BACKUP_BYTES {
        return Err(BackupError::TooLarge);
    }
    let truncated = || BackupError::NotABackup("the file is truncated".into());
    let rest =
        bytes.strip_prefix(MAGIC.as_slice()).ok_or_else(|| BackupError::NotABackup("the full-backup signature is missing".into()))?;
    let len = rest.get(..4).ok_or_else(truncated)?;
    let len = u32::from_be_bytes([len[0], len[1], len[2], len[3]]) as usize;
    if len > MAX_HEADER_BYTES {
        return Err(BackupError::NotABackup(format!("the header is {len} bytes (at most {MAX_HEADER_BYTES})")));
    }
    let header_end = MAGIC.len() + 4 + len;
    let header_bytes = bytes.get(MAGIC.len() + 4..header_end).ok_or_else(truncated)?;
    let header: Header = serde_json::from_slice(header_bytes).map_err(|e| BackupError::NotABackup(format!("header: {e}")))?;
    if header.format != FORMAT {
        return Err(BackupError::NotABackup(format!("unknown format '{}'", header.format)));
    }
    if header.format_version > FORMAT_VERSION {
        return Err(BackupError::FutureFormat { found: header.format_version, supported: FORMAT_VERSION });
    }
    if header.format_version != FORMAT_VERSION {
        return Err(BackupError::NotABackup(format!("unknown format version {}", header.format_version)));
    }
    if header.cipher != CIPHER {
        return Err(BackupError::NotABackup(format!("unsupported cipher '{}'", header.cipher)));
    }
    check_kdf(&header.kdf)?;
    let salt = B64.decode(&header.salt_b64).map_err(|_| BackupError::NotABackup("the salt is not base64".into()))?;
    if !(MIN_SALT_LEN..=MAX_SALT_LEN).contains(&salt.len()) {
        return Err(BackupError::UnsupportedKdf(format!("{}-byte salt; allowed {MIN_SALT_LEN} to {MAX_SALT_LEN} bytes", salt.len())));
    }
    let passphrase = passphrase.ok_or(BackupError::PassphraseRequired)?;
    let (aad, envelope) = bytes.split_at(header_end);
    let key = crypto::derive(passphrase.as_bytes(), &salt, &header.kdf).map_err(|e| BackupError::UnsupportedKdf(e.to_string()))?;
    let plaintext = crypto::open(&key, aad, envelope).map_err(|_| BackupError::Authentication)?;
    let payload: Payload = serde_json::from_slice(&plaintext).map_err(|e| BackupError::Invalid(format!("contents: {e}")))?;
    let m = &payload.manifest;
    if m.format != FORMAT || m.format_version != header.format_version || m.kind != BundleKind::Backup || m.mode != ExportMode::FullBackup {
        return Err(BackupError::Invalid("the manifest does not describe this full backup".into()));
    }
    if m.schema_version > anvil_domain::SCHEMA_VERSION {
        let (found, supported) = (i64::from(m.schema_version), i64::from(anvil_domain::SCHEMA_VERSION));
        return Err(BackupError::FutureSchema { what: "object schema", found, supported });
    }
    if m.schema_version < MIN_SCHEMA_VERSION {
        return Err(BackupError::Invalid(format!("schema {} is older than this version can read", m.schema_version)));
    }
    if m.db_schema_version > DB_SCHEMA_VERSION {
        return Err(BackupError::FutureSchema { what: "database schema", found: m.db_schema_version, supported: DB_SCHEMA_VERSION });
    }
    Ok((payload.manifest, payload.contents))
}

/// The store's contents as read in one transaction, before attachments are
/// checked.
struct Raw {
    objects: Vec<ObjectRow>,
    /// Attachment index entries and the blob each names.
    index: Vec<(Value, Option<Zeroizing<Vec<u8>>>)>,
    secrets: Vec<SecretRow>,
    history: Vec<HistoryRow>,
    load_reports: Vec<Value>,
    token_files: usize,
    linked_files: usize,
}

struct Snapshot {
    contents: BackupContents,
    excluded: Vec<String>,
    token_files: usize,
    linked_files: usize,
}

/// Validated, typed and normalised backup contents, ready to write.
#[derive(Default)]
struct Decoded {
    graph: PortableGraph,
    user_profiles: Vec<UserProfile>,
    spec_sources: Vec<SpecSourceRecord>,
    run_reports: Vec<RunReport>,
    secrets: Vec<(Id, Option<Id>, SecretRow)>,
    history: Vec<(ExecutionRecord, Option<Vec<u8>>)>,
    load_reports: Vec<LoadReport>,
    /// (plan label, id) of every item the restore writes, attachments aside.
    items: Vec<(String, String)>,
    missing_secrets: Vec<String>,
    warnings: Vec<String>,
    /// Stored attachments a request or dataset names without their bytes.
    uncarried: Vec<UncarriedAttachment>,
}

impl Decoded {
    fn workspace_ids(&self) -> HashSet<Id> {
        self.graph.workspaces.iter().map(|w| w.meta.id).collect()
    }
}

/// What the profile holds, as far as a restore can collide with it.
struct Local {
    /// (plan label, id) of every stored item.
    items: HashSet<(String, String)>,
    /// (plan label, id) of every stored history record and load report, with
    /// the workspace that owns it.
    records: HashMap<(String, String), Option<String>>,
    /// Stored objects and secrets with their owners, and stored workspaces.
    existing: Existing,
    /// The content hashes among the backup's uncarried attachments whose
    /// content is stored here.
    stored: HashSet<String>,
}

impl App {
    /// Everything a full backup of this profile carries, read from one
    /// consistent state of the store.
    pub fn backup_contents(&self) -> Result<BackupContents> {
        Ok(self.snapshot()?.contents)
    }

    /// What [`App::export_backup`] would write.
    pub fn backup_preview(&self) -> Result<BackupPreview> {
        let snap = self.snapshot()?;
        // A backup this build could not restore is refused now, not later.
        decode(&snap.contents)?;
        Ok(BackupPreview { manifest: build_manifest(&snap), secrets_included: snap.contents.secrets.len(), literals_moved: 0 })
    }

    /// Write a full backup encrypted under `passphrase`.
    pub fn export_backup(&self, passphrase: &str) -> Result<(Vec<u8>, BackupPreview)> {
        self.export_backup_with(passphrase, KdfParams::interactive())
    }

    /// [`App::export_backup`] with explicit Argon2id costs (within the bounds
    /// of [`check_kdf`]).
    pub fn export_backup_with(&self, passphrase: &str, kdf: KdfParams) -> Result<(Vec<u8>, BackupPreview)> {
        if passphrase.len() < MIN_PASSPHRASE_LEN {
            return Err(BackupError::WeakPassphrase.into());
        }
        check_kdf(&kdf)?;
        let snap = self.snapshot()?;
        decode(&snap.contents)?;
        let manifest = build_manifest(&snap);
        let bytes = seal(&manifest, &snap.contents, passphrase, kdf)?;
        Ok((bytes, BackupPreview { manifest, secrets_included: snap.contents.secrets.len(), literals_moved: 0 }))
    }

    /// Dry run of [`App::restore`]: authenticate, validate and plan without
    /// changing anything.
    pub fn restore_preview(&self, bytes: &[u8], passphrase: Option<&str>, policy: ConflictPolicy) -> Result<ImportReport> {
        let (manifest, d) = open_for_restore(bytes, passphrase, policy)?;
        let local = self.store.read_consistently(|r| local(r, &d))?;
        let notes = restore_notes(&d, &local, policy)?;
        let plan = restore_plan(&d, &local, policy);
        Ok(report(plan, &manifest, &d, notes, None))
    }

    /// [`App::restore_approved`] with nothing approved: a backup that claims
    /// a workspace stored here is refused.
    pub fn restore(&self, bytes: &[u8], passphrase: Option<&str>, policy: ConflictPolicy) -> Result<ImportReport> {
        self.restore_approved(bytes, passphrase, policy, &ImportApproval::default())
    }

    /// Restore a full backup. Nothing is written unless the whole file
    /// authenticates under `passphrase` and every item in it is valid. Then a
    /// checkpoint is taken and every item is written in one transaction:
    /// `Replace` overwrites items with the same id, `Merge` keeps them
    /// (including this profile's settings). Nothing else is deleted. App
    /// settings apply to every workspace's requests, so `Replace` keeps this
    /// profile's too while it holds a workspace the backup does not claim.
    ///
    /// The whole restore is refused, before anything is written, when:
    /// - a request or dataset names a stored attachment by content hash that
    ///   the backup does not carry, and content with that hash is stored
    ///   here: it would resolve to bytes the backup never carried. One whose
    ///   content is not stored here is accepted with a warning;
    /// - the backup claims a workspace stored here that `approval` does not
    ///   name (the preview's `plan.existing_workspaces`): what it writes there
    ///   could use that workspace's vault secrets;
    /// - under Replace, a backup object's, history record's or load report's
    ///   kind and id are stored here in another workspace, or a backup
    ///   secret's id is stored here under another owner: nothing is ever
    ///   overwritten or moved out of its workspace.
    pub fn restore_approved(
        &self,
        bytes: &[u8],
        passphrase: Option<&str>,
        policy: ConflictPolicy,
        approval: &ImportApproval,
    ) -> Result<ImportReport> {
        let (manifest, d) = open_for_restore(bytes, passphrase, policy)?;
        let checkpoint = self.store.checkpoint("before-restore")?;
        // A refusal returns before anything is written; the transaction then
        // commits no change.
        let (plan, notes) = self.store.atomically(|s| {
            // Read inside the transaction, so every check sees exactly what
            // the writes below land on.
            let local = local(&s.as_read(), &d)?;
            let (plan, notes) = match checked_plan(&d, &local, policy, approval) {
                Ok(checked) => checked,
                Err(e) => return Ok(Err(e)),
            };
            let keep_settings = keeps_local_settings(&d, &local, policy);
            write(&Writer { tx: s, existing: &local.items, merge: policy == ConflictPolicy::Merge, keep_settings }, &d)?;
            Ok(Ok((plan, notes)))
        })??;
        Ok(report(plan, &manifest, &d, notes, Some(checkpoint.display().to_string())))
    }

    fn snapshot(&self) -> Result<Snapshot> {
        let raw = self.store.read_consistently(|r| {
            let mut objects = Vec::new();
            for k in OBJECT_KINDS {
                let mut rows = r.object_meta(k)?;
                rows.sort_by(|a, b| a.id.as_str().cmp(b.id.as_str()));
                for m in rows {
                    let id: Id = m.id.parse().map_err(|_| StoreError::Integrity)?;
                    let value: Value = r.get(k, &id)?.ok_or_else(|| StoreError::NotFound(format!("{k} {id}")))?;
                    let (workspace_id, parent_id, sort_key) = (m.workspace_id, m.parent_id, m.sort_key);
                    objects.push(ObjectRow { kind: (*k).to_string(), id: m.id, workspace_id, parent_id, sort_key, value });
                }
            }
            let mut index = Vec::new();
            for v in r.list::<Value>(kind::IMPORT_SOURCE, None)? {
                let blob = match v.get("blob").and_then(Value::as_str) {
                    Some(b) => r.get_blob(b)?,
                    None => None,
                };
                index.push((v, blob));
            }
            let secrets = r
                .secrets()?
                .into_iter()
                .map(|s| SecretRow { id: s.id, workspace_id: s.workspace_id, label: s.label, value: s.value.as_str().to_owned() })
                .collect();
            let mut history = Vec::new();
            for h in r.history_entries()? {
                if let Some((record, body)) = r.get_history::<Value>(&h.id)? {
                    let body_b64 = body.map(|b| B64.encode(&b[..]));
                    let (id, workspace_id, request_id, started_at) = (h.id, h.workspace_id, h.request_id, h.started_at);
                    history.push(HistoryRow { id, workspace_id, request_id, started_at, record, body_b64 });
                }
            }
            history.sort_by(|a, b| a.id.as_str().cmp(b.id.as_str()));
            let mut load_reports: Vec<Value> = r.list_load_reports(None)?;
            load_reports.sort_by(|a, b| run_id(a).cmp(run_id(b)));
            let token_files = r.object_meta(kind::TOKEN_FILE)?.len();
            let linked_files = r.object_meta(kind::LINKED_FILE)?.len();
            Ok(Raw { objects, index, secrets, history, load_reports, token_files, linked_files })
        })?;
        let Raw { objects, index, secrets, history, load_reports, token_files, linked_files } = raw;
        let mut attachments = Vec::new();
        let mut excluded = Vec::new();
        for (entry, blob) in &index {
            match (entry.get("attachment").and_then(Value::as_str), blob) {
                (Some(sha), Some(bytes)) => {
                    if hex::encode(Sha256::digest(&bytes[..])) != sha {
                        return Err(BackupError::Invalid(format!("stored attachment {sha} failed its integrity check")).into());
                    }
                    attachments.push(AttachmentRow { sha256: sha.to_string(), content_b64: B64.encode(&bytes[..]) });
                }
                (Some(sha), None) => excluded.push(format!("attachment {sha} (its stored content is missing)")),
                (None, _) => excluded.push("an attachment index entry that names no attachment".to_string()),
            }
        }
        attachments.sort_by(|a, b| a.sha256.as_str().cmp(b.sha256.as_str()));
        let contents = BackupContents { objects, secrets, attachments, history, load_reports };
        Ok(Snapshot { contents, excluded, token_files, linked_files })
    }
}

fn run_id(report: &Value) -> &str {
    report.get("run_id").and_then(Value::as_str).unwrap_or_default()
}

fn build_manifest(snap: &Snapshot) -> BackupManifest {
    let c = &snap.contents;
    let mut counts: BTreeMap<String, usize> = OBJECT_KINDS.iter().map(|k| ((*k).to_string(), 0)).collect();
    for o in &c.objects {
        *counts.entry(o.kind.clone()).or_default() += 1;
    }
    counts.insert("secrets".into(), c.secrets.len());
    counts.insert("attachments".into(), c.attachments.len());
    counts.insert("history".into(), c.history.len());
    counts.insert("load_reports".into(), c.load_reports.len());
    let mut device_bindings = vec![KEYCHAIN_NOTE.to_string()];
    if c.objects.iter().any(|o| o.value.to_string().contains("\"kind\":\"linked_file\"")) {
        device_bindings.push(LINKED_FILES_NOTE.into());
    }
    if snap.token_files > 0 {
        device_bindings.push(format!(
            "{} token-file binding(s) name files on this device and are not in the backup; bind them again on the target machine.",
            snap.token_files
        ));
    }
    if snap.linked_files > 0 {
        device_bindings.push(format!(
            "{} linked-file binding(s) name files on this device and are not in the backup; choose the files again on the target machine.",
            snap.linked_files
        ));
    }
    BackupManifest {
        format: FORMAT.into(),
        format_version: FORMAT_VERSION,
        kind: BundleKind::Backup,
        mode: ExportMode::FullBackup,
        created_at: chrono::Utc::now(),
        app_version: env!("CARGO_PKG_VERSION").into(),
        schema_version: anvil_domain::SCHEMA_VERSION,
        db_schema_version: DB_SCHEMA_VERSION,
        counts,
        excluded: snap.excluded.clone(),
        device_bindings,
        placeholders: vec![],
        content_warnings: vec![],
        includes_history: true,
    }
}

fn open_for_restore(
    bytes: &[u8],
    passphrase: Option<&str>,
    policy: ConflictPolicy,
) -> std::result::Result<(BackupManifest, Decoded), BackupError> {
    if policy == ConflictPolicy::Duplicate {
        return Err(BackupError::DuplicateUnsupported);
    }
    let (manifest, contents) = open(bytes, passphrase)?;
    let decoded = decode(&contents)?;
    Ok((manifest, decoded))
}

fn invalid(msg: String) -> BackupError {
    BackupError::Invalid(msg)
}

/// Deserialize a row into its type and check that it holds the object its
/// id names.
fn typed<T: DeserializeOwned>(o: &ObjectRow, id_of: impl Fn(&T) -> Id) -> std::result::Result<T, BackupError> {
    let v: T = serde_json::from_value(o.value.clone()).map_err(|e| invalid(format!("{} {}: {e}", o.kind, o.id)))?;
    let id = id_of(&v);
    if id.to_string() != o.id {
        return Err(invalid(format!("{} {} holds the object {id}", o.kind, o.id)));
    }
    Ok(v)
}

fn owned_by(ws: &HashSet<Id>, what: &str, name: &str, owner: &Id) -> std::result::Result<(), BackupError> {
    if ws.contains(owner) {
        return Ok(());
    }
    Err(invalid(format!("{what} '{name}' belongs to a workspace that is not in the backup")))
}

fn parse_id(what: &str, id: &str) -> std::result::Result<Id, BackupError> {
    id.parse().map_err(|_| invalid(format!("{what} has an invalid id '{id}'")))
}

/// Validate every item of `c` against its type and the rest of the backup,
/// then apply the bundle-import safety normalisation.
fn decode(c: &BackupContents) -> std::result::Result<Decoded, BackupError> {
    let mut d = Decoded::default();
    let mut seen = HashSet::new();
    let mut revision_rows: HashMap<Id, &ObjectRow> = HashMap::new();
    let g = &mut d.graph;
    for o in &c.objects {
        if !seen.insert((o.kind.as_str(), o.id.as_str())) {
            return Err(invalid(format!("{} {} appears twice", o.kind, o.id)));
        }
        check_record_schema(&o.value, &o.kind, &o.id)?;
        match o.kind.as_str() {
            kind::WORKSPACE => g.workspaces.push(typed(o, |x: &Workspace| x.meta.id)?),
            kind::FOLDER => g.folders.push(typed(o, |x: &Folder| x.meta.id)?),
            kind::REQUEST => g.requests.push(typed(o, |x: &RequestDefinition| x.meta.id)?),
            kind::REVISION => {
                let r = typed(o, |x: &RequestRevision| x.id)?;
                revision_rows.insert(r.id, o);
                g.revisions.push(r);
            }
            kind::ENVIRONMENT => g.environments.push(typed(o, |x: &Environment| x.meta.id)?),
            kind::TLS_PROFILE => g.tls_profiles.push(typed(o, |x: &TlsProfile| x.id)?),
            kind::PROXY_PROFILE => g.proxy_profiles.push(typed(o, |x: &ProxyProfile| x.id)?),
            kind::INTEGRATION => g.integrations.push(typed(o, |x: &IntegrationProfile| x.id)?),
            kind::DATASET => g.datasets.push(typed(o, |x: &Dataset| x.meta.id)?),
            kind::SCENARIO => g.scenarios.push(typed(o, |x: &Scenario| x.meta.id)?),
            kind::LOAD_PLAN => g.load_plans.push(typed(o, |x: &LoadPlan| x.id)?),
            kind::APP_SETTINGS => g.app_settings = Some(typed(o, |_: &AppSettings| settings_id())?),
            kind::USER_PROFILE => d.user_profiles.push(typed(o, |x: &UserProfile| x.meta.id)?),
            kind::SPEC_SOURCE => d.spec_sources.push(typed(o, |x: &SpecSourceRecord| x.source.import_id)?),
            kind::RUN_REPORT => d.run_reports.push(typed(o, |x: &RunReport| x.run_id)?),
            other => return Err(invalid(format!("the backup holds '{other}' objects, which a full backup never carries"))),
        }
        d.items.push((o.kind.clone(), o.id.clone()));
    }
    // Workspace-scoped items must belong to a workspace in the backup, so a
    // restore never attaches anything to an unrelated local workspace.
    // Folders, requests and environments are checked by the normalisation.
    let ws: HashSet<Id> = g.workspaces.iter().map(|w| w.meta.id).collect();
    let owned = |what: &str, name: &str, owner: &Id| owned_by(&ws, what, name, owner);
    for x in &g.tls_profiles {
        owned("TLS profile", &x.name, &x.workspace_id)?;
    }
    for x in &g.proxy_profiles {
        owned("proxy profile", &x.name, &x.workspace_id)?;
    }
    for x in &g.integrations {
        owned("gateway profile", &x.name, &x.workspace_id)?;
    }
    for x in &g.datasets {
        owned("dataset", &x.name, &x.workspace_id)?;
    }
    for x in &g.scenarios {
        owned("scenario", &x.name, &x.workspace_id)?;
    }
    for x in &g.load_plans {
        owned("load plan", &x.name, &x.workspace_id)?;
    }
    for x in &d.spec_sources {
        owned("spec import", &x.file_name, &x.workspace_id)?;
    }
    for x in &d.run_reports {
        owned("run report", &x.name, &x.workspace_id)?;
    }
    let mut secret_ids = HashSet::new();
    for s in &c.secrets {
        let id = parse_id("a secret", &s.id)?;
        if !secret_ids.insert(id) {
            return Err(invalid(format!("secret {id} appears twice")));
        }
        let owner = s.workspace_id.as_deref().map(|w| parse_id("a secret's workspace", w)).transpose()?;
        if let Some(w) = &owner {
            owned("secret", &s.label, w)?;
        }
        d.secrets.push((id, owner, s.clone()));
        d.items.push((SECRET.into(), s.id.clone()));
    }
    let mut shas = HashSet::new();
    for a in &c.attachments {
        let well_formed = a.sha256.len() == 64 && a.sha256.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if !well_formed || !shas.insert(a.sha256.as_str()) {
            return Err(invalid(format!("attachment '{}' is not a unique SHA-256 content hash", a.sha256)));
        }
        let bytes = B64.decode(&a.content_b64).map_err(|_| invalid(format!("attachment {} is not base64", a.sha256)))?;
        if hex::encode(Sha256::digest(&bytes)) != a.sha256 {
            return Err(invalid(format!("attachment {} does not match its content hash", a.sha256)));
        }
        // In the graph, so every stored attachment a request or dataset
        // names is checked against the ones the backup carries.
        d.graph.attachments.insert(a.sha256.clone(), bytes);
    }
    let mut history_ids = HashSet::new();
    let mut outside_history = 0;
    for h in &c.history {
        check_record_schema(&h.record, "history record", &h.id)?;
        let rec: ExecutionRecord =
            serde_json::from_value(h.record.clone()).map_err(|e| invalid(format!("history record {}: {e}", h.id)))?;
        if rec.id.to_string() != h.id || !history_ids.insert(rec.id) {
            return Err(invalid(format!("history record {} is not unique or holds another record", h.id)));
        }
        // A record is written under the workspace it names; one outside the
        // backup (its workspace was deleted) would land in an unrelated
        // local workspace.
        if rec.workspace_id.is_some_and(|w| !ws.contains(&w)) {
            outside_history += 1;
            continue;
        }
        let body = match &h.body_b64 {
            Some(b) => Some(B64.decode(b).map_err(|_| invalid(format!("history body {} is not base64", h.id)))?),
            None => None,
        };
        d.items.push((HISTORY.into(), h.id.clone()));
        d.history.push((rec, body));
    }
    let mut report_ids = HashSet::new();
    for v in &c.load_reports {
        check_record_schema(v, "load report", run_id(v))?;
        let r: LoadReport = serde_json::from_value(v.clone()).map_err(|e| invalid(format!("load report {}: {e}", run_id(v))))?;
        if !report_ids.insert(r.run_id) {
            return Err(invalid(format!("load report {} appears twice", r.run_id)));
        }
        owned("load report", &r.plan.name, &r.plan.workspace_id)?;
        d.items.push((LOAD_REPORT.into(), r.run_id.to_string()));
        d.load_reports.push(r);
    }
    let mut refs = Vec::new();
    for o in &c.objects {
        secret_refs(&o.value, &mut refs);
    }
    let mut missing = Vec::new();
    for (id, label) in refs {
        if !c.secrets.iter().any(|s| s.id == id) {
            missing.push(format!("{label} ({id})"));
        }
    }
    missing.sort();
    missing.dedup();
    d.missing_secrets = missing;
    // Same checks and trust normalisation as a bundle import: referential
    // integrity, TLS bypasses, marker trust, credential forwarding, early
    // data, legacy HMAC and scenario/plan trust. Revisions of requests that
    // are not in the backup (their request was deleted) are left out.
    d.warnings = anvil_portability::validate::validate_and_normalize(&mut d.graph).map_err(|e| invalid(e.to_string()))?;
    if outside_history > 0 {
        d.warnings.push(format!("{outside_history} history record(s) of workspaces that are not in the backup were left out."));
    }
    // Stored attachments named without their bytes, as after the loss of a
    // blob: checked against this device's attachments before writing.
    d.uncarried = anvil_portability::validate::uncarried_attachments(&d.graph).map_err(|e| invalid(e.to_string()))?;
    // A revision is written under its request, in that request's workspace;
    // one stored under another request or workspace is refused.
    let request_ws: HashMap<Id, Id> = d.graph.requests.iter().map(|r| (r.meta.id, r.workspace_id)).collect();
    for r in &d.graph.revisions {
        let (Some(ws), Some(row)) = (request_ws.get(&r.request_id), revision_rows.get(&r.id)) else {
            return Err(invalid(format!("revision {} belongs to a request that is not in the backup", r.id)));
        };
        let names = |stored: &Option<String>, id: &Id| stored.as_deref().is_none_or(|s| s == id.to_string());
        if !names(&row.workspace_id, ws) || !names(&row.parent_id, &r.request_id) {
            return Err(invalid(format!("revision {} is stored under a request or workspace other than its own", r.id)));
        }
    }
    let kept: HashSet<String> = d.graph.revisions.iter().map(|r| r.id.to_string()).collect();
    d.items.retain(|(k, id)| k != kind::REVISION || kept.contains(id));
    Ok(d)
}

/// Secret references (`{"kind":"secret","secret":{"id":..,"label":..}}`) in `v`.
fn secret_refs(v: &Value, out: &mut Vec<(String, String)>) {
    match v {
        Value::Object(m) => {
            if m.get("kind").and_then(Value::as_str) == Some("secret")
                && let Some(s) = m.get("secret")
                && let Some(id) = s.get("id").and_then(Value::as_str)
            {
                out.push((id.to_string(), s.get("label").and_then(Value::as_str).unwrap_or_default().to_string()));
            }
            m.values().for_each(|x| secret_refs(x, out));
        }
        Value::Array(a) => a.iter().for_each(|x| secret_refs(x, out)),
        _ => {}
    }
}

/// (plan label, id) of every object and secret stored in the profile.
fn existing_items(r: &StoreRead<'_>) -> anvil_storage::store::Result<HashSet<(String, String)>> {
    let mut out = HashSet::new();
    for k in OBJECT_KINDS {
        out.extend(r.object_meta(k)?.into_iter().map(|m| ((*k).to_string(), m.id)));
    }
    out.extend(r.secrets()?.into_iter().map(|s| (SECRET.to_string(), s.id)));
    Ok(out)
}

/// (plan label, id) of every history record and load report stored in the
/// profile, with the workspace that owns it.
fn existing_records(r: &StoreRead<'_>) -> anvil_storage::store::Result<HashMap<(String, String), Option<String>>> {
    let history = r.history_entries()?.into_iter().map(|h| ((HISTORY.to_string(), h.id), h.workspace_id));
    let reports = r.load_report_entries()?.into_iter().map(|(id, ws)| ((LOAD_REPORT.to_string(), id), ws));
    Ok(history.chain(reports).collect())
}

/// What the profile holds, read through `r`.
fn local(r: &StoreRead<'_>, d: &Decoded) -> anvil_storage::store::Result<Local> {
    let records = existing_records(r)?;
    let mut items = existing_items(r)?;
    items.extend(records.keys().cloned());
    Ok(Local { items, records, existing: port::existing(r)?, stored: port::stored_among(r, &d.uncarried)? })
}

/// Whether a restore keeps this profile's app settings although the backup
/// carries its own: always under Merge (they are stored here), and under
/// Replace while the profile holds a workspace the backup does not claim.
/// App settings are the lowest settings layer of every workspace's requests,
/// so the backup's would reach workspaces it never names; a workspace it does
/// claim is written only once the user approves it.
fn keeps_local_settings(d: &Decoded, local: &Local, policy: ConflictPolicy) -> bool {
    let ws = d.workspace_ids();
    d.graph.app_settings.is_some() && (policy == ConflictPolicy::Merge || local.existing.workspaces.keys().any(|w| !ws.contains(w)))
}

/// Warnings a restore reports before writing: each item that names a stored
/// file the backup does not include, and app settings kept under Replace.
fn restore_notes(d: &Decoded, local: &Local, policy: ConflictPolicy) -> Result<Vec<String>> {
    let mut notes = port::uncarried_warnings(&d.uncarried, &local.stored, "backup", "restored")?;
    if policy == ConflictPolicy::Replace && keeps_local_settings(d, local, policy) {
        notes.push(KEPT_SETTINGS_NOTE.into());
    }
    Ok(notes)
}

fn restore_plan(d: &Decoded, local: &Local, policy: ConflictPolicy) -> ImportPlan {
    let clashes: Vec<&(String, String)> = d.items.iter().filter(|i| local.items.contains(*i)).collect();
    let (n, c) = (d.items.len(), clashes.len());
    let mut conflicts: Vec<String> = clashes.iter().take(MAX_LISTED_CONFLICTS).map(|(k, id)| format!("{k} {id}")).collect();
    if c > MAX_LISTED_CONFLICTS {
        conflicts.push(format!("and {} more", c - MAX_LISTED_CONFLICTS));
    }
    // App settings Replace keeps are counted as kept, not replaced.
    let settings = (kind::APP_SETTINGS.to_string(), settings_id().to_string());
    let kept_settings = policy == ConflictPolicy::Replace && keeps_local_settings(d, local, policy);
    let (to_create, to_replace, skipped_existing) = match policy {
        ConflictPolicy::Merge => (n - c, 0, c),
        _ if kept_settings && local.items.contains(&settings) => (n - c, c - 1, 1),
        _ if kept_settings => (n - c - 1, c, 1),
        _ => (n - c, c, 0),
    };
    ImportPlan {
        policy,
        to_create,
        to_replace,
        skipped_existing,
        conflicts,
        foreign_secrets: foreign_secrets(d, &local.existing),
        foreign_objects: foreign_objects(d, local),
        existing_workspaces: plan::existing_workspaces(&d.graph, &local.existing),
    }
}

/// Backup objects whose kind and id are stored here in a different workspace
/// than the backup gives them, as `folder 'name' (id)`, and backup history
/// records and load reports whose id is stored here under another workspace
/// (or none), as `history (id)`.
fn foreign_objects(d: &Decoded, local: &Local) -> Vec<String> {
    let existing = &local.existing;
    let mut out = plan::foreign_objects(&d.graph, existing);
    let specs = d.spec_sources.iter().map(|x| (kind::SPEC_SOURCE, x.source.import_id, &x.file_name, x.workspace_id));
    let runs = d.run_reports.iter().map(|x| (kind::RUN_REPORT, x.run_id, &x.name, x.workspace_id));
    for (k, id, name, ws) in specs.chain(runs) {
        if existing.owners.get(&(k.to_string(), id)).is_some_and(|stored| *stored != Some(ws)) {
            out.push(format!("{k} '{name}' ({id})"));
        }
    }
    // INSERT OR REPLACE writes these by id alone, so a record stored under
    // another owner would be overwritten and moved.
    let history = d.history.iter().map(|(rec, _)| (HISTORY, rec.id, rec.workspace_id));
    let reports = d.load_reports.iter().map(|r| (LOAD_REPORT, r.run_id, Some(r.plan.workspace_id)));
    for (label, id, ws) in history.chain(reports) {
        if local.records.get(&(label.to_string(), id.to_string())).is_some_and(|stored| *stored != ws.map(|w| w.to_string())) {
            out.push(format!("{label} ({id})"));
        }
    }
    out
}

/// Backup secrets whose id is stored here under another owner than the
/// backup gives them (a workspace, or none), as `secret 'label' (id)`.
fn foreign_secrets(d: &Decoded, existing: &Existing) -> Vec<String> {
    d.secrets
        .iter()
        .filter(|(id, owner, _)| existing.secrets.get(id).is_some_and(|stored| stored != owner))
        .map(|(id, _, s)| format!("secret '{}' ({id})", s.label))
        .collect()
}

/// Every check a restore makes before writing: its plan, and a warning for
/// each item that names a stored file the backup does not include.
fn checked_plan(d: &Decoded, local: &Local, policy: ConflictPolicy, approval: &ImportApproval) -> Result<(ImportPlan, Vec<String>)> {
    let notes = restore_notes(d, local, policy)?;
    let plan = restore_plan(d, local, policy);
    refuse_unapproved(&plan, approval)?;
    Ok((plan, notes))
}

/// Refuse a restore that writes into a workspace stored here that the user
/// did not approve after the preview, or that under Replace would overwrite
/// an object or secret another workspace (or none) owns here.
fn refuse_unapproved(plan: &ImportPlan, approval: &ImportApproval) -> Result<()> {
    let unapproved: Vec<String> = plan
        .existing_workspaces
        .iter()
        .filter(|w| !approval.existing_workspaces.contains(&w.id))
        .map(|w| format!("'{}' ({})", w.name, w.id))
        .collect();
    if !unapproved.is_empty() {
        return Err(AppError::Invalid(format!(
            "this backup writes into your existing workspace {}, and what it restores there can use that workspace's vault secrets; nothing was restored. Confirm writing into it after the preview only if the backup is your own or otherwise trusted.",
            unapproved.join(", ")
        )));
    }
    if plan.policy == ConflictPolicy::Replace && !plan.foreign_objects.is_empty() {
        return Err(AppError::Invalid(format!(
            "Replace cannot overwrite objects that belong to another workspace ({}); nothing was restored.",
            plan.foreign_objects.join(", ")
        )));
    }
    if plan.policy == ConflictPolicy::Replace && !plan.foreign_secrets.is_empty() {
        return Err(AppError::Invalid(format!(
            "Replace cannot overwrite secrets that belong to another workspace, or to none ({}); nothing was restored.",
            plan.foreign_secrets.join(", ")
        )));
    }
    Ok(())
}

fn report(plan: ImportPlan, manifest: &BackupManifest, d: &Decoded, notes: Vec<String>, checkpoint: Option<String>) -> ImportReport {
    let mut warnings = d.warnings.clone();
    warnings.extend(notes);
    if plan.policy == ConflictPolicy::Merge {
        warnings.push(MERGE_NOTE.into());
    }
    warnings.extend(manifest.excluded.iter().map(|e| format!("Not in the backup: {e}")));
    warnings.extend(manifest.device_bindings.iter().cloned());
    ImportReport {
        plan,
        warnings,
        secrets_restored: true,
        missing_secrets: d.missing_secrets.clone(),
        linked_files: d.graph.linked_files(),
        checkpoint,
        workspaces: d.graph.workspaces.iter().map(|w| w.name.clone()).collect(),
        workspace_ids: d.graph.workspaces.iter().map(|w| w.meta.id.to_string()).collect(),
        full_backup: true,
    }
}

/// Writes rows inside a restore's transaction, keeping existing items under
/// `Merge` and this profile's app settings when `keep_settings`.
struct Writer<'a, 't> {
    tx: &'a StoreTx<'t>,
    existing: &'a HashSet<(String, String)>,
    merge: bool,
    keep_settings: bool,
}

impl Writer<'_, '_> {
    fn keep(&self, label: &str, id: &str) -> bool {
        self.merge && self.existing.contains(&(label.to_string(), id.to_string()))
    }

    fn put<T: Serialize>(
        &self,
        k: &str,
        id: &Id,
        workspace_id: Option<&Id>,
        parent_id: Option<&Id>,
        sort_key: f64,
        v: &T,
    ) -> anvil_storage::store::Result<()> {
        if self.keep(k, &id.to_string()) {
            return Ok(());
        }
        self.tx.put(k, id, workspace_id, parent_id, sort_key, v)
    }
}

/// Write every item with the row metadata the app itself gives it.
fn write(w: &Writer<'_, '_>, d: &Decoded) -> anvil_storage::store::Result<()> {
    let g = &d.graph;
    for x in &g.workspaces {
        w.put(kind::WORKSPACE, &x.meta.id, None, None, 0.0, x)?;
    }
    for x in &g.folders {
        w.put(kind::FOLDER, &x.meta.id, Some(&x.workspace_id), x.parent_id.as_ref(), x.sort_key, x)?;
    }
    for x in &g.requests {
        w.put(kind::REQUEST, &x.meta.id, Some(&x.workspace_id), x.folder_id.as_ref(), x.sort_key, x)?;
    }
    // Decoding keeps only revisions whose request is in the backup.
    let request_ws: HashMap<Id, Id> = g.requests.iter().map(|r| (r.meta.id, r.workspace_id)).collect();
    for x in &g.revisions {
        w.put(kind::REVISION, &x.id, request_ws.get(&x.request_id), Some(&x.request_id), 0.0, x)?;
    }
    for x in &g.environments {
        w.put(kind::ENVIRONMENT, &x.meta.id, Some(&x.workspace_id), None, 0.0, x)?;
    }
    for x in &g.tls_profiles {
        w.put(kind::TLS_PROFILE, &x.id, Some(&x.workspace_id), None, 0.0, x)?;
    }
    for x in &g.proxy_profiles {
        w.put(kind::PROXY_PROFILE, &x.id, Some(&x.workspace_id), None, 0.0, x)?;
    }
    for x in &g.integrations {
        w.put(kind::INTEGRATION, &x.id, Some(&x.workspace_id), None, 0.0, x)?;
    }
    for x in &g.datasets {
        w.put(kind::DATASET, &x.meta.id, Some(&x.workspace_id), None, 0.0, x)?;
    }
    for x in &g.scenarios {
        w.put(kind::SCENARIO, &x.meta.id, Some(&x.workspace_id), None, 0.0, x)?;
    }
    for x in &g.load_plans {
        w.put(kind::LOAD_PLAN, &x.id, Some(&x.workspace_id), None, 0.0, x)?;
    }
    if let Some(x) = &g.app_settings
        && !w.keep_settings
    {
        w.put(kind::APP_SETTINGS, &settings_id(), None, None, 0.0, x)?;
    }
    for x in &d.user_profiles {
        w.put(kind::USER_PROFILE, &x.meta.id, None, None, 0.0, x)?;
    }
    for x in &d.spec_sources {
        w.put(kind::SPEC_SOURCE, &x.source.import_id, Some(&x.workspace_id), None, 0.0, x)?;
    }
    for x in &d.run_reports {
        w.put(kind::RUN_REPORT, &x.run_id, Some(&x.workspace_id), None, x.started_at.timestamp_millis() as f64, x)?;
    }
    // A linked-file binding was chosen for the request or dataset it names;
    // one this restore overwrites is not that object any more.
    let requests = g.requests.iter().map(|r| (kind::REQUEST, r.meta.id));
    let datasets = g.datasets.iter().map(|x| (kind::DATASET, x.meta.id));
    let written: HashSet<Id> = requests.chain(datasets).filter(|(k, id)| !w.keep(k, &id.to_string())).map(|(_, id)| id).collect();
    let bindings: Vec<LinkedFileBinding> = w.tx.list(kind::LINKED_FILE, None)?;
    for b in bindings.iter().filter(|b| written.contains(&b.referrer.id())) {
        w.tx.delete(kind::LINKED_FILE, &b.id)?;
    }
    for (id, owner, s) in &d.secrets {
        if !w.keep(SECRET, &s.id) {
            w.tx.put_secret(id, owner.as_ref(), &s.label, &s.value)?;
        }
    }
    // Content-addressed and idempotent, so written under either policy.
    for (sha, bytes) in &g.attachments {
        let blob = w.tx.put_blob(bytes)?;
        w.tx.pin_blob(&blob)?;
        let index = serde_json::json!({"attachment": sha, "blob": blob});
        w.tx.put(kind::IMPORT_SOURCE, &attachment_index_id(sha), None, None, 0.0, &index)?;
    }
    for (rec, body) in &d.history {
        if !w.keep(HISTORY, &rec.id.to_string()) {
            let started_at = rec.started_at.timestamp_millis();
            w.tx.add_history(&rec.id, rec.workspace_id.as_ref(), rec.request_id.as_ref(), started_at, rec, body.as_deref())?;
        }
    }
    for r in &d.load_reports {
        if !w.keep(LOAD_REPORT, &r.run_id.to_string()) {
            w.tx.put_load_report(&r.run_id, Some(&r.plan.workspace_id), r.started_at.timestamp_millis(), r)?;
        }
    }
    Ok(())
}
