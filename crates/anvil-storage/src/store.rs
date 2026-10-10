//! Encrypted SQLite store.
//!
//! Every payload (objects, secrets, history records, response bodies,
//! attachments, load reports) is sealed with the profile DEK and bound to its
//! table/kind/id through associated data (a vault secret also to the
//! workspace that owns it), so the database file, its WAL and any SQLite temp
//! data hold only ciphertext plus structural metadata (ids, parent ids, kinds,
//! timestamps, sizes). While locked, the store has no key
//! and every data operation fails with `Locked` — enforcement lives here, not
//! in the UI.
//! Object reads also compare the sealed identity with row metadata; object
//! updates authenticate the old identity and preserve its workspace inside
//! a write transaction. Revisions seal the workspace and request that own
//! them (schema 3) and must still match their request's sealed owner.
//! History records and load reports are read only under the workspace sealed
//! in them, and a history record is bound to the response body it references
//! (schema 3). Profile-only kinds must have no workspace or parent index.
//!
//! One connection serves the whole profile. Ordinary operations lock it per
//! statement; [`Store::atomically`] holds it for its whole transaction and
//! hands the closure a [`StoreTx`], so no other caller can write into, read
//! from, commit or roll back a transaction it does not own.
//! [`Store::read_consistently`] does the same for reads only: its closure gets
//! a [`StoreRead`] over one consistent state and never takes the write lock.
//!
//! Another `Store` opened on the same profile has its own connection and its
//! own lock, so writes that must be seen together by it (a history body and
//! the row that references it) share one SQLite transaction; a connection
//! waits up to [`BUSY_TIMEOUT`] for another connection's write lock.

use crate::crypto::{self, Key};
use anvil_domain::Id;
use parking_lot::{Mutex, MutexGuard, RwLock};
use rusqlite::{Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, params};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use std::any::Any;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread::ThreadId;
use std::time::Duration;
use zeroize::Zeroizing;

/// A decrypted history record and its optional stored response body.
pub type HistoryRecord<T> = (T, Option<Zeroizing<Vec<u8>>>);
pub const DB_FILE: &str = "anvil.db";
/// How long a statement waits for another connection's lock on the database
/// before failing with `SQLITE_BUSY`.
pub const BUSY_TIMEOUT: Duration = Duration::from_secs(5);
/// Current on-disk schema version. Increase only with a migration below.
pub const DB_SCHEMA_VERSION: i64 = 4;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("Anvil is locked")]
    Locked,
    #[error("not found: {0}")]
    NotFound(String),
    #[error(
        "this data was written by a newer version of Anvil (schema {found}, this build supports {supported}); open it with that version or restore a compatible backup"
    )]
    FutureSchema { found: i64, supported: i64 },
    #[error("stored data could not be decrypted (wrong key or corruption)")]
    Integrity,
    #[error("an existing object's workspace or immutable parent cannot be changed")]
    Ownership,
    #[error("the parent folder belongs to another workspace")]
    ForeignFolderParent,
    #[error("stored {kind} {id} failed its ownership or integrity check")]
    ObjectIntegrity { kind: String, id: String },
    /// A `Store` method was called from inside that store's own
    /// [`Store::atomically`] closure. The closure must use its [`StoreTx`];
    /// nested transactions are not supported.
    #[error("store called directly from inside its own transaction; use the transaction handle")]
    TransactionActive,
    /// A transaction could not be rolled back, so the connection is still
    /// inside it. Nothing further runs on the connection until it has ended.
    #[error("a store transaction could not be rolled back{}{}", because(.cause), after(.original))]
    TransactionNotEnded {
        /// Why the last rollback failed, when SQLite gave a reason.
        cause: Option<rusqlite::Error>,
        /// The error the transaction was already failing with, if any.
        original: Option<Box<StoreError>>,
    },
    #[error("database: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("serialization: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, StoreError>;

fn because(cause: &Option<rusqlite::Error>) -> String {
    cause.as_ref().map(|e| format!(": {e}")).unwrap_or_default()
}

fn after(original: &Option<Box<StoreError>>) -> String {
    original.as_ref().map(|e| format!(" after: {e}")).unwrap_or_default()
}

/// Object kinds stored in the `objects` table.
pub mod kind {
    pub const WORKSPACE: &str = "workspace";
    pub const FOLDER: &str = "folder";
    pub const REQUEST: &str = "request";
    pub const REVISION: &str = "revision";
    pub const ENVIRONMENT: &str = "environment";
    pub const TLS_PROFILE: &str = "tls_profile";
    pub const PROXY_PROFILE: &str = "proxy_profile";
    pub const INTEGRATION: &str = "integration";
    pub const DATASET: &str = "dataset";
    pub const SCENARIO: &str = "scenario";
    pub const LOAD_PLAN: &str = "load_plan";
    pub const APP_SETTINGS: &str = "app_settings";
    pub const USER_PROFILE: &str = "user_profile";
    pub const IMPORT_SOURCE: &str = "import_source";
    /// Provenance of spec/collection imports (OpenAPI, WSDL, Postman, …).
    pub const SPEC_SOURCE: &str = "spec_source";
    /// Saved collection-run reports (`anvil_domain::runner::RunReport`).
    pub const RUN_REPORT: &str = "run_report";
    /// User-provided API standards rulesets, ordered by `sort_key`.
    pub const API_RULESET: &str = "api_ruleset";
    /// Token files the user bound in the desktop's native open dialog
    /// (`anvil_app::token_files`). Device-specific: not in [`ALL`], never
    /// exported or imported.
    pub const TOKEN_FILE: &str = "token_file";
    /// Linked local files the user bound in the desktop's native open dialog
    /// (`anvil_app::linked_files`). Device-specific: not in [`ALL`], never
    /// exported or imported.
    pub const LINKED_FILE: &str = "linked_file";
    /// Workspaces sealed from this device's workload identity, stored under
    /// the id of the workspace each seals (`anvil_app::device_identity`).
    /// Device-specific: not in [`ALL`], never exported, backed up or
    /// imported.
    pub const DEVICE_IDENTITY_SEAL: &str = "device_identity_seal";
    pub const ALL: &[&str] = &[
        WORKSPACE,
        FOLDER,
        REQUEST,
        REVISION,
        ENVIRONMENT,
        TLS_PROFILE,
        PROXY_PROFILE,
        INTEGRATION,
        DATASET,
        SCENARIO,
        LOAD_PLAN,
        APP_SETTINGS,
        USER_PROFILE,
        IMPORT_SOURCE,
        SPEC_SOURCE,
        RUN_REPORT,
        API_RULESET,
    ];
}

#[derive(Debug, Clone)]
pub struct RowMeta {
    pub kind: String,
    pub id: String,
    pub workspace_id: Option<String>,
    pub parent_id: Option<String>,
    pub sort_key: f64,
    pub updated_at: i64,
}

/// Every table the migrations create, besides SQLite's own. Full backups
/// (`anvil_app::backup`) classify each one as carried or device-bound, and a
/// test fails when a table is added without that decision.
pub const TABLES: &[&str] = &["meta", "objects", "secrets", "blobs", "history", "load_reports"];

/// A decrypted vault secret with its owner (`None` for profile-level).
pub struct SecretRecord {
    pub id: String,
    pub workspace_id: Option<String>,
    pub label: String,
    pub value: Zeroizing<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HistoryEntry {
    pub id: String,
    pub workspace_id: Option<String>,
    pub request_id: Option<String>,
    pub started_at: i64,
    pub size: i64,
}

pub struct Store {
    dir: PathBuf,
    conn: Mutex<Connection>,
    /// Thread running an [`Store::atomically`] closure, set and cleared only
    /// while that thread holds `conn`. A match means re-locking `conn` would
    /// self-deadlock, so such calls fail with `TransactionActive` instead.
    tx_owner: Mutex<Option<ThreadId>>,
    key: RwLock<Option<Key>>,
    /// Checkpoint restores run on `conn`, which rewrite the database without
    /// a change SQLite counts (see [`ChangeMarker`]).
    restores: AtomicU64,
}

struct ConnectionGuard<'a> {
    conn: MutexGuard<'a, Connection>,
    _data_lock: std::fs::File,
}
impl std::ops::Deref for ConnectionGuard<'_> {
    type Target = Connection;
    fn deref(&self) -> &Connection {
        &self.conn
    }
}
impl std::ops::DerefMut for ConnectionGuard<'_> {
    fn deref_mut(&mut self) -> &mut Connection {
        &mut self.conn
    }
}

/// What a connection can tell of the writes to its database: one taken in a
/// read transaction and one taken in a later transaction differ if anything
/// was committed in between, by this connection (its change count, or a
/// checkpoint restore) or by another one (SQLite's `data_version`). Lets a
/// caller read in a [`Store::read_consistently`] pass and apply what it
/// decided in a short [`Store::atomically`] one only while nothing changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChangeMarker {
    data_version: i64,
    total_changes: u64,
    restores: u64,
}

/// Prefix of the notes [`StoreTx::put_note`] keeps in `meta`.
const NOTE_PREFIX: &str = "note:";

fn aad(table: &str, kind: &str, id: &str) -> Vec<u8> {
    format!("anvil/v1/{table}/{kind}/{id}").into_bytes()
}

/// Identity already inside the released encrypted payload. Kind and row id
/// are authenticated by `aad`; owner and parent must agree with these sealed
/// fields before plaintext indexing metadata can select an object.
struct ObjectIdentity {
    id: Option<Id>,
    owner: Option<Id>,
    parent: Option<Id>,
}

/// A payload as its identity check decoded it: the whole object, of its
/// kind's type, when the check needed that type. A read of the same type
/// takes it ([`typed`]) instead of decoding the payload again.
type Decoded = Option<Box<dyn Any>>;

/// `decoded` when the identity check already decoded the payload as `T`;
/// otherwise `json` decoded as `T`.
fn typed<T: DeserializeOwned + 'static>(decoded: Decoded, json: &[u8]) -> Result<T> {
    match decoded.map(|d| d.downcast::<T>()) {
        Some(Ok(v)) => Ok(*v),
        _ => Ok(serde_json::from_slice(json)?),
    }
}

fn object_identity(k: &str, json: &[u8]) -> Result<(ObjectIdentity, Decoded)> {
    use anvil_domain::workspace::*;

    fn decode<T: DeserializeOwned>(json: &[u8]) -> Result<T> {
        serde_json::from_slice(json).map_err(|_| StoreError::Integrity)
    }

    fn kept<T: 'static>(v: T) -> Decoded {
        Some(Box::new(v))
    }

    let ((id, owner, parent), decoded) = match k {
        kind::WORKSPACE => {
            let v: Workspace = decode(json)?;
            ((Some(v.meta.id), None, None), kept(v))
        }
        kind::FOLDER => {
            let v: Folder = decode(json)?;
            ((Some(v.meta.id), Some(v.workspace_id), v.parent_id), kept(v))
        }
        kind::REQUEST => {
            let v: RequestDefinition = decode(json)?;
            ((Some(v.meta.id), Some(v.workspace_id), v.folder_id), kept(v))
        }
        kind::REVISION => {
            let v: RequestRevision = decode(json)?;
            // This released type has no workspace field: the owner is sealed
            // around it (see `SealedRevision`) and checked in `open_object`.
            ((Some(v.id), None, Some(v.request_id)), kept(v))
        }
        kind::ENVIRONMENT => {
            let v: Environment = decode(json)?;
            ((Some(v.meta.id), Some(v.workspace_id), None), kept(v))
        }
        kind::TLS_PROFILE => {
            let v: anvil_domain::tls::TlsProfile = decode(json)?;
            ((Some(v.id), Some(v.workspace_id), None), kept(v))
        }
        kind::PROXY_PROFILE => {
            let v: anvil_domain::tls::ProxyProfile = decode(json)?;
            ((Some(v.id), Some(v.workspace_id), None), kept(v))
        }
        kind::INTEGRATION => {
            let v: anvil_domain::integration::IntegrationProfile = decode(json)?;
            ((Some(v.id), Some(v.workspace_id), None), kept(v))
        }
        kind::DATASET => {
            let v: Dataset = decode(json)?;
            ((Some(v.meta.id), Some(v.workspace_id), None), kept(v))
        }
        kind::SCENARIO => {
            let v: Scenario = decode(json)?;
            ((Some(v.meta.id), Some(v.workspace_id), None), kept(v))
        }
        kind::LOAD_PLAN => {
            let v: anvil_domain::load::LoadPlan = decode(json)?;
            ((Some(v.id), Some(v.workspace_id), None), kept(v))
        }
        kind::RUN_REPORT => {
            let v: anvil_domain::runner::RunReport = decode(json)?;
            ((Some(v.run_id), Some(v.workspace_id), None), kept(v))
        }
        kind::USER_PROFILE => {
            let v: UserProfile = decode(json)?;
            ((Some(v.meta.id), None, None), kept(v))
        }
        kind::API_RULESET => {
            let v: anvil_domain::settings::StoredRuleset = decode(json)?;
            ((Some(v.id), None, None), kept(v))
        }
        kind::APP_SETTINGS => {
            let v: anvil_domain::settings::AppSettings = decode(json)?;
            // Profile-only, with no embedded id. The row id is in the AAD.
            ((None, None, None), kept(v))
        }
        kind::SPEC_SOURCE => {
            // App-owned type: project only the sealed identity fields so
            // storage does not depend on the application crate.
            #[derive(Deserialize)]
            struct Source {
                import_id: Id,
            }
            #[derive(Deserialize)]
            struct Record {
                source: Source,
                workspace_id: Id,
            }
            let v: Record = decode(json)?;
            ((Some(v.source.import_id), Some(v.workspace_id), None), None)
        }
        kind::DEVICE_IDENTITY_SEAL => {
            #[derive(Deserialize)]
            struct Seal {
                workspace_id: Id,
            }
            let v: Seal = decode(json)?;
            ((Some(v.workspace_id), Some(v.workspace_id), None), None)
        }
        kind::TOKEN_FILE | kind::LINKED_FILE => {
            #[derive(Deserialize)]
            struct Binding {
                id: Id,
            }
            let v: Binding = decode(json)?;
            ((Some(v.id), None, None), None)
        }
        kind::IMPORT_SOURCE => {
            // Attachment indexes are profile-only and have no embedded id.
            // Reject treating them as workspace objects; AAD binds kind/id.
            #[derive(Deserialize)]
            struct Index {
                attachment: String,
                blob: String,
            }
            let v: Index = decode(json)?;
            let _ = (v.attachment, v.blob);
            ((None, None, None), None)
        }
        _ => return Err(StoreError::Integrity),
    };
    Ok((ObjectIdentity { id, owner, parent }, decoded))
}

/// Check a payload's sealed identity against its row; returns the payload as
/// the check decoded it.
fn validate_object(k: &str, id: &str, owner: Option<&str>, parent: Option<&str>, json: &[u8]) -> Result<Decoded> {
    let (identity, decoded) = object_identity(k, json)?;
    if identity.id.is_some_and(|sealed| sealed.to_string() != id)
        || identity.parent.map(|p| p.to_string()).as_deref() != parent
        || (k != kind::REVISION && identity.owner.map(|w| w.to_string()).as_deref() != owner)
        || (k == kind::REVISION && owner.is_none())
    {
        return Err(StoreError::Integrity);
    }
    Ok(decoded)
}

/// Associated data of a vault secret: its id and the workspace that owns it
/// (`None`: no workspace does). A secret whose owner column is changed no
/// longer decrypts, so it cannot be moved into another workspace. The id and
/// the owner are each prefixed with their length, so no other id and owner
/// give the same bytes, and the `v2` prefix keeps it apart from every
/// schema 1 [`aad`].
fn secret_aad(id: &str, owner: Option<&str>) -> Vec<u8> {
    match owner {
        Some(ws) => format!("anvil/v2/secrets/secret/{}:{id}/workspace/{}:{ws}", id.len(), ws.len()).into_bytes(),
        None => format!("anvil/v2/secrets/secret/{}:{id}/profile", id.len()).into_bytes(),
    }
}

/// Associated data of a request revision sealed by schema 3, whose plaintext
/// is a [`SealedRevision`]. The id is prefixed with its length, and the `v3`
/// prefix keeps it apart from the schema 1 [`aad`] that earlier revisions
/// were sealed under, so neither opens as the other.
fn revision_aad(id: &str) -> Vec<u8> {
    format!("anvil/v3/objects/revision/{}:{id}", id.len()).into_bytes()
}

/// Plaintext of a schema 3 request revision: the released revision JSON with
/// the request and the workspace that owned it when it was sealed. The owner
/// is part of the authenticated payload, so a revision put back under another
/// workspace, or under a request id reused elsewhere, no longer validates.
#[derive(Serialize, Deserialize)]
struct SealedRevision<'a> {
    workspace_id: Id,
    request_id: Id,
    #[serde(borrow)]
    revision: &'a RawValue,
}

/// Seal `json`, revision `id` of `request_id`, for workspace `workspace_id`.
fn seal_revision(key: &Key, id: &str, workspace_id: Id, request_id: Id, json: &[u8]) -> Result<Vec<u8>> {
    let revision: &RawValue = serde_json::from_slice(json)?;
    let pt = Zeroizing::new(serde_json::to_vec(&SealedRevision { workspace_id, request_id, revision })?);
    Ok(crypto::seal(key, &revision_aad(id), &pt))
}

/// Open schema 3 revision `id`: its sealed owner, its sealed request and the
/// released revision JSON. Row indexes are not consulted.
fn open_revision(key: &Key, id: &str, env: &[u8]) -> Result<(Id, Id, Zeroizing<Vec<u8>>)> {
    let pt = crypto::open(key, &revision_aad(id), env).map_err(|_| StoreError::Integrity)?;
    let sealed: SealedRevision<'_> = serde_json::from_slice(&pt).map_err(|_| StoreError::Integrity)?;
    Ok((sealed.workspace_id, sealed.request_id, Zeroizing::new(sealed.revision.get().as_bytes().to_vec())))
}

/// Associated data of a history record sealed by schema 3: its id and the
/// response body blob its row references (`None`: no body). A blob id is a
/// keyed hash of its content and a blob opens only under its own id, so a
/// record whose body column is pointed at another blob, or cleared, no longer
/// opens. The id and the blob id are each prefixed with their length, and the
/// `v3` prefix keeps it apart from the schema 1 [`aad`] that earlier records
/// were sealed under.
fn history_aad(id: &str, body: Option<&str>) -> Vec<u8> {
    match body {
        Some(b) => format!("anvil/v3/history/record/{}:{id}/body/{}:{b}", id.len(), b.len()).into_bytes(),
        None => format!("anvil/v3/history/record/{}:{id}/no-body", id.len()).into_bytes(),
    }
}

/// The owner fields an execution record seals. A record without them (no
/// workspace or request) has `None`.
#[derive(Deserialize)]
struct HistoryOwner {
    #[serde(default)]
    workspace_id: Option<Id>,
    #[serde(default)]
    request_id: Option<Id>,
}

/// Refuse a history record whose sealed workspace or request differs from
/// the row's plaintext indexes.
fn check_history_owner(json: &[u8], workspace_id: Option<&str>, request_id: Option<&str>) -> Result<()> {
    let sealed: HistoryOwner = serde_json::from_slice(json).map_err(|_| StoreError::Integrity)?;
    if sealed.workspace_id.map(|w| w.to_string()).as_deref() != workspace_id
        || sealed.request_id.map(|r| r.to_string()).as_deref() != request_id
    {
        return Err(StoreError::Integrity);
    }
    Ok(())
}

/// The owner a load report seals: the workspace of the plan it ran.
#[derive(Deserialize)]
struct ReportOwner {
    plan: ReportPlan,
}

#[derive(Deserialize)]
struct ReportPlan {
    workspace_id: Id,
}

/// Refuse a load report whose sealed workspace differs from the row's
/// plaintext index.
fn check_report_owner(json: &[u8], workspace_id: Option<&str>) -> Result<()> {
    let sealed: ReportOwner = serde_json::from_slice(json).map_err(|_| StoreError::Integrity)?;
    if Some(sealed.plan.workspace_id.to_string()).as_deref() != workspace_id {
        return Err(StoreError::Integrity);
    }
    Ok(())
}

/// One schema step. Each runs in its own write transaction together with the
/// version bump that records it.
enum Migration {
    /// Schema changes only.
    Sql(&'static str),
    /// Re-seal every vault secret under [`secret_aad`] (v2).
    SecretOwners,
    /// Seal every request revision with its owner under [`revision_aad`], and
    /// every history record with its response body under [`history_aad`] (v3).
    RecordBindings,
}

impl Migration {
    /// Whether the step seals existing rows again, after which earlier builds
    /// refuse the database (see [`migrate_on`]).
    fn reseals(&self) -> bool {
        !matches!(self, Migration::Sql(_))
    }
}

const MIGRATIONS: &[Migration] = &[
    // v1 — baseline schema.
    Migration::Sql(BASELINE),
    // v2 — vault secrets bind their owner.
    Migration::SecretOwners,
    // v3 — request revisions bind their workspace and request, history
    // records the response body they reference.
    Migration::RecordBindings,
    // v4 — older builds must not open a database supporting local rotation.
    Migration::Sql("SELECT 1;"),
];

/// How many rows a step that seals rows again reads at a time, so it never
/// holds a whole table in memory.
const MIGRATION_BATCH: i64 = 256;

const BASELINE: &str = r#"
    CREATE TABLE objects (
        kind TEXT NOT NULL,
        id TEXT NOT NULL,
        workspace_id TEXT,
        parent_id TEXT,
        sort_key REAL NOT NULL DEFAULT 0,
        updated_at INTEGER NOT NULL,
        payload BLOB NOT NULL,
        PRIMARY KEY (kind, id)
    );
    CREATE INDEX objects_ws ON objects(workspace_id, kind);
    CREATE TABLE secrets (id TEXT PRIMARY KEY, workspace_id TEXT, updated_at INTEGER NOT NULL, payload BLOB NOT NULL);
    CREATE TABLE blobs (id TEXT PRIMARY KEY, size INTEGER NOT NULL, created_at INTEGER NOT NULL, payload BLOB NOT NULL);
    CREATE TABLE history (
        id TEXT PRIMARY KEY, workspace_id TEXT, request_id TEXT, started_at INTEGER NOT NULL,
        size INTEGER NOT NULL, body_blob TEXT, payload BLOB NOT NULL
    );
    CREATE INDEX history_ws ON history(workspace_id, started_at);
    CREATE TABLE load_reports (id TEXT PRIMARY KEY, workspace_id TEXT, started_at INTEGER NOT NULL, payload BLOB NOT NULL);
    "#;

/// History bodies are looked up by index when a blob is released or retention
/// runs. Unversioned: [`migrate_on`] creates it on every database it opens
/// once the versioned steps have run, and an index changes no stored data, so
/// earlier builds of the same schema still read the database and its backups.
const HISTORY_BODY_INDEX: &str = "CREATE INDEX IF NOT EXISTS history_body_blob ON history(body_blob);";

/// The schema version recorded in `meta` (0 for a new database).
fn stored_schema_version(conn: &Connection) -> Result<i64> {
    let v = conn.query_row("SELECT value FROM meta WHERE key='schema_version'", [], |r| r.get::<_, String>(0)).optional()?;
    Ok(v.and_then(|v| v.parse().ok()).unwrap_or(0))
}

/// v2: re-seal each vault secret, sealed under [`aad`] until now, under
/// [`secret_aad`] with the owner its row names when the step runs. A row that
/// does not open was already corrupt or altered, since schema 1 never changed
/// its associated data: it is left as it is, still sealed under that data,
/// which no [`secret_aad`] equals, so reading it keeps failing with
/// `Integrity` and it can be deleted. Returns how many rows were left, also
/// recorded in `meta` (`secrets_left_at_v2`, removed when none was).
///
/// A row that opens under [`secret_aad`] instead was sealed by schema 2, so
/// the version recorded in `meta` was set back after this step ran: the step
/// fails with `Integrity` and its transaction writes nothing.
fn reseal_secret_owners(conn: &Connection, key: &Key) -> Result<u64> {
    let rows: Vec<(String, Option<String>, Vec<u8>)> = {
        let mut st = conn.prepare("SELECT id, workspace_id, payload FROM secrets")?;
        st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?.collect::<std::result::Result<_, _>>()?
    };
    let mut left = 0;
    for (id, owner, env) in rows {
        let v2 = secret_aad(&id, owner.as_deref());
        let Ok(pt) = crypto::open(key, &aad("secrets", "secret", &id), &env) else {
            if crypto::open(key, &v2, &env).is_ok() {
                return Err(StoreError::Integrity);
            }
            left += 1;
            continue;
        };
        let env = crypto::seal(key, &v2, &pt);
        conn.execute("UPDATE secrets SET payload=?1 WHERE id=?2", params![env, id])?;
    }
    record_left(conn, "secrets_left_at_v2", left)?;
    Ok(left)
}

/// Record in `meta` under `name` how many rows a step left as they were, or
/// remove an earlier count when it left none.
fn record_left(conn: &Connection, name: &str, left: u64) -> Result<()> {
    if left > 0 {
        conn.execute(
            "INSERT INTO meta(key, value) VALUES(?1, ?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            params![name, left.to_string()],
        )?;
    } else {
        conn.execute("DELETE FROM meta WHERE key=?1", params![name])?;
    }
    Ok(())
}

/// v3: seal each request revision, sealed under [`aad`] until now, as a
/// [`SealedRevision`] under [`revision_aad`] with the workspace that owns its
/// request. Only a revision that the schema 2 read accepts is sealed: it
/// decrypts, its sealed request id is its parent index, and that request
/// itself authenticates with the revision's workspace index as its sealed
/// owner. The owner comes from that request, never from the revision's
/// indexes alone. Any other revision (an orphan, or one whose request does
/// not authenticate or is owned elsewhere) is left as it is, still sealed
/// under [`aad`], which ordinary reads no longer accept: it stays refused,
/// as it already was, and is never adopted. Returns how many were left, also
/// recorded in `meta` (`revisions_left_at_v3`, removed when none was).
///
/// Revisions are read [`MIGRATION_BATCH`] at a time in row order, and each
/// request is authenticated once however many revisions it has.
///
/// A row that opens under [`revision_aad`] instead was sealed by schema 3,
/// so the version recorded in `meta` was set back after this step ran: the
/// step fails with `Integrity` and its transaction writes nothing.
fn seal_revision_owners(conn: &Connection, key: &Key) -> Result<u64> {
    let records = Records { key: key.clone(), conn };
    // Request id -> the workspace it authenticates under, if it does.
    let mut owners: HashMap<String, Option<String>> = HashMap::new();
    let sql = "SELECT workspace_id, parent_id, payload, id, rowid FROM objects
               WHERE kind=?1 AND (?2 IS NULL OR rowid>?2) ORDER BY rowid LIMIT ?3";
    let mut st = conn.prepare(sql)?;
    let mut left = 0;
    // The last row id read; `None` before the first batch.
    let mut after: Option<i64> = None;
    loop {
        let rows = st.query_map(params![kind::REVISION, after, MIGRATION_BATCH], |r| {
            Ok((r.get::<_, i64>(4)?, r.get::<_, String>(3)?, ObjectRow::read(r)?))
        })?;
        let rows: Vec<(i64, String, ObjectRow)> = rows.collect::<std::result::Result<_, _>>()?;
        let Some(&(last, ..)) = rows.last() else { break };
        after = Some(last);
        for (_, id, row) in rows {
            if crypto::open(key, &revision_aad(&id), &row.payload).is_ok() {
                return Err(StoreError::Integrity);
            }
            let owner = match row.parent.as_deref() {
                None => None,
                Some(request) => match owners.get(request) {
                    Some(owner) => owner.clone(),
                    None => {
                        let owner = records.request_owner(request)?;
                        owners.insert(request.to_string(), owner.clone());
                        owner
                    }
                },
            };
            let env = match records.reseal_legacy_revision(&id, &row, owner.as_deref()) {
                Ok(env) => env,
                Err(StoreError::Integrity | StoreError::Serde(_)) => {
                    left += 1;
                    continue;
                }
                Err(e) => return Err(e),
            };
            conn.execute("UPDATE objects SET payload=?1 WHERE kind=?2 AND id=?3", params![env, kind::REVISION, id])?;
        }
    }
    record_left(conn, "revisions_left_at_v3", left)?;
    Ok(left)
}

/// v3: seal each history record, sealed under [`aad`] until now, under
/// [`history_aad`] with the response body its row references when the step
/// runs, as revisions take their request's owner once. Only a record that
/// the schema 2 read accepts is sealed: it decrypts, and the workspace and
/// request it seals are its row's indexes. Any other record is left as it
/// is, still sealed under [`aad`], which reads no longer accept: it stays
/// refused and can be deleted. Returns how many were left, also recorded in
/// `meta` (`history_left_at_v3`, removed when none was). Records are read
/// [`MIGRATION_BATCH`] at a time in row order.
///
/// A row that opens under [`history_aad`] instead was sealed by schema 3, so
/// the version recorded in `meta` was set back after this step ran: the step
/// fails with `Integrity` and its transaction writes nothing.
fn seal_history_bodies(conn: &Connection, key: &Key) -> Result<u64> {
    let sql = format!("SELECT rowid, {HISTORY_COLUMNS} FROM history WHERE (?1 IS NULL OR rowid>?1) ORDER BY rowid LIMIT ?2");
    let mut st = conn.prepare(&sql)?;
    let mut left = 0;
    // The last row id read; `None` before the first batch.
    let mut after: Option<i64> = None;
    loop {
        let rows = st.query_map(params![after, MIGRATION_BATCH], |r| Ok((r.get::<_, i64>(0)?, HistoryRow::read_from(r, 1)?)))?;
        let rows: Vec<(i64, HistoryRow)> = rows.collect::<std::result::Result<_, _>>()?;
        let Some(&(last, _)) = rows.last() else { break };
        after = Some(last);
        for (_, row) in rows {
            let bound = history_aad(&row.id, row.body_blob.as_deref());
            if crypto::open(key, &bound, &row.payload).is_ok() {
                return Err(StoreError::Integrity);
            }
            let Ok(pt) = crypto::open(key, &aad("history", "record", &row.id), &row.payload) else {
                left += 1;
                continue;
            };
            if check_history_owner(&pt, row.workspace_id.as_deref(), row.request_id.as_deref()).is_err() {
                left += 1;
                continue;
            }
            let env = crypto::seal(key, &bound, &pt);
            conn.execute("UPDATE history SET payload=?1 WHERE id=?2", params![env, row.id])?;
        }
    }
    record_left(conn, "history_left_at_v3", left)?;
    Ok(left)
}

/// Check `key` against the sealed canary of the database on `conn` without
/// writing: `false` when it has none yet, [`StoreError::Integrity`] when `key`
/// does not open it.
fn check_canary(conn: &Connection, key: &Key) -> Result<bool> {
    let canary: Option<String> = conn.query_row("SELECT value FROM meta WHERE key='key_canary'", [], |r| r.get(0)).optional()?;
    let Some(c) = canary else { return Ok(false) };
    if let Some(c) = c.strip_prefix("rotated-v1:") {
        if stored_schema_version(conn)? < 4 {
            return Err(StoreError::Integrity);
        }
        let state = crate::rotation::read_on(conn).map_err(|_| StoreError::Integrity)?.ok_or(StoreError::Integrity)?;
        crate::vault::check_current(&state.header, &state.header, key).map_err(|_| StoreError::Integrity)?;
        let env = hex::decode(c).map_err(|_| StoreError::Integrity)?;
        crypto::open(key, b"anvil/v2/rotated-canary", &env).map_err(|_| StoreError::Integrity)?;
    } else {
        if crate::rotation::read_on(conn).map_err(|_| StoreError::Integrity)?.is_some() {
            return Err(StoreError::Integrity);
        }
        let env = hex::decode(c).map_err(|_| StoreError::Integrity)?;
        crypto::open(key, b"anvil/v1/canary", &env).map_err(|_| StoreError::Integrity)?;
    }
    Ok(true)
}

/// A sealed canary proves `key` matches the database on `conn`; a database
/// without one gets one sealed with `key`.
fn verify_key_on(conn: &Connection, key: &Key) -> Result<()> {
    if !check_canary(conn, key)? {
        // A missing canary in an existing populated or enrolled store is
        // corruption, never an invitation to enroll an attacker-selected key.
        if crate::rotation::read_on(conn).map_err(|_| StoreError::Integrity)?.is_some() {
            return Err(StoreError::Integrity);
        }
        for table in ["objects", "secrets", "blobs", "history", "load_reports"] {
            if has_table(conn, table)? && conn.query_row(&format!("SELECT EXISTS(SELECT 1 FROM {table})"), [], |r| r.get::<_, bool>(0))? {
                return Err(StoreError::Integrity);
            }
        }
        let env = crypto::seal(key, b"anvil/v1/canary", b"ok");
        conn.execute("INSERT INTO meta(key, value) VALUES('key_canary', ?1)", params![hex::encode(env)])?;
    }
    Ok(())
}

/// Copy the database on `conn`, as it stands, into the `checkpoints` folder
/// of the profile in `dir` (see [`Store::checkpoint`]). A name already taken
/// in the same millisecond gets a number, so an earlier checkpoint is never
/// in the way.
fn checkpoint_on(conn: &Connection, dir: &Path, label: &str) -> Result<PathBuf> {
    let dir = dir.join("checkpoints");
    std::fs::create_dir_all(&dir)?;
    let safe: String = label.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-').take(40).collect();
    let stamp = chrono::Utc::now().format("%Y%m%dT%H%M%S%3fZ").to_string();
    let mut path = dir.join(format!("{stamp}-{safe}.db"));
    let mut n = 1;
    while path.exists() {
        n += 1;
        path = dir.join(format!("{stamp}-{safe}-{n}.db"));
    }
    conn.execute("VACUUM INTO ?1", params![path.display().to_string()])?;
    Ok(path)
}

/// Apply the pending migrations to the database on `conn` with `key`, which
/// [`verify_key_on`] has checked first, so a wrong key fails before anything
/// is re-sealed with it. Each step runs in its own write transaction that
/// reads the version again first, so a step another connection has applied
/// meanwhile is skipped, and a step that fails leaves nothing behind. Then it
/// creates the unversioned indexes ([`HISTORY_BODY_INDEX`]) where they are
/// missing, as a best effort; with nothing pending and every index in place
/// it only reads.
///
/// Before a step seals the rows of an existing database again, which earlier
/// builds then refuse, a checkpoint of the database as it was is taken in the
/// `checkpoints` folder of profile `profile` (`before-schema-<version>`), so
/// an earlier build can still be gone back to. A checkpoint that cannot be
/// taken fails the migration before anything is written. `None` takes none:
/// a checkpoint being restored is itself such a copy.
fn migrate_on(conn: &mut Connection, key: &Key, profile: Option<&Path>) -> Result<()> {
    let found = stored_schema_version(conn)?;
    if found > DB_SCHEMA_VERSION {
        return Err(StoreError::FutureSchema { found, supported: DB_SCHEMA_VERSION });
    }
    let reseal = (1i64..).zip(MIGRATIONS).find(|(v, step)| *v > found && step.reseals());
    if found > 0
        && let (Some(dir), Some((v, _))) = (profile, reseal)
    {
        checkpoint_on(conn, dir, &format!("before-schema-{v}"))?;
    }
    for (v, step) in (1i64..).zip(MIGRATIONS) {
        if v <= found {
            continue;
        }
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let found = stored_schema_version(&tx)?;
        if found > DB_SCHEMA_VERSION {
            return Err(StoreError::FutureSchema { found, supported: DB_SCHEMA_VERSION });
        }
        // Dropping `tx` rolls it back; it has written nothing.
        if v <= found {
            continue;
        }
        let left: Vec<(u64, &str)> = match step {
            Migration::Sql(sql) => {
                tx.execute_batch(sql)?;
                Vec::new()
            }
            Migration::SecretOwners => vec![(reseal_secret_owners(&tx, key)?, "vault secrets that did not decrypt were left unchanged")],
            Migration::RecordBindings => vec![
                (seal_revision_owners(&tx, key)?, "request revisions whose request did not authenticate were left unchanged"),
                (seal_history_bodies(&tx, key)?, "history records that did not decrypt under their owner were left unchanged"),
            ],
        };
        tx.execute(
            "INSERT INTO meta(key, value) VALUES('schema_version', ?1) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            params![v.to_string()],
        )?;
        tx.commit()?;
        for (left, what) in left {
            if left > 0 {
                tracing::warn!(schema = v, left, "{what}");
            }
        }
    }
    // Best effort: a missing index only slows lookups, so it never keeps a
    // profile from opening or unlocking.
    if let Err(e) = conn.execute_batch(HISTORY_BODY_INDEX) {
        tracing::warn!(error = %e, "the history body index could not be created");
    }
    Ok(())
}

fn has_table(conn: &Connection, name: &str) -> Result<bool> {
    let sql = "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)";
    Ok(conn.query_row(sql, params![name], |r| r.get::<_, bool>(0))?)
}

/// Refuse the database on `conn` when its recorded version was set back below
/// a step that has run: below 2 while a vault secret in it opens under
/// [`secret_aad`], or below 3 while a request revision opens under
/// [`revision_aad`] or a history record under [`history_aad`]. Only that step
/// seals with that data, so it would fail on the row (see
/// [`reseal_secret_owners`], [`seal_revision_owners`] and
/// [`seal_history_bodies`]). Reads only.
fn check_not_set_back(conn: &Connection, key: &Key) -> Result<()> {
    let found = stored_schema_version(conn)?;
    if found < 2 && has_table(conn, "secrets")? {
        let mut st = conn.prepare("SELECT id, workspace_id, payload FROM secrets")?;
        let rows = st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?, r.get::<_, Vec<u8>>(2)?)))?;
        for row in rows {
            let (id, owner, env) = row?;
            if crypto::open(key, &secret_aad(&id, owner.as_deref()), &env).is_ok() {
                return Err(StoreError::Integrity);
            }
        }
    }
    if found < 3 && has_table(conn, "objects")? {
        let mut st = conn.prepare("SELECT id, payload FROM objects WHERE kind=?1")?;
        let rows = st.query_map(params![kind::REVISION], |r| Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?)))?;
        for row in rows {
            let (id, env) = row?;
            if crypto::open(key, &revision_aad(&id), &env).is_ok() {
                return Err(StoreError::Integrity);
            }
        }
    }
    if found < 3 && has_table(conn, "history")? {
        let mut st = conn.prepare(&format!("SELECT {HISTORY_COLUMNS} FROM history"))?;
        for row in st.query_map([], |r| HistoryRow::read_from(r, 0))? {
            let row = row?;
            if crypto::open(key, &history_aad(&row.id, row.body_blob.as_deref()), &row.payload).is_ok() {
                return Err(StoreError::Integrity);
            }
        }
    }
    Ok(())
}

/// Copy the database `src` over the one on `conn`, then check `key` against
/// the copy and migrate it. The checkpoint `src` is itself the copy a
/// migration would keep, so it takes none.
fn restore_on(conn: &mut Connection, src: &Connection, key: &Key, dir: &Path) -> Result<()> {
    let current = crate::rotation::read_on(conn).map_err(|_| StoreError::Integrity)?;
    if let Some(state) = current {
        // A disk-backed ciphertext staging copy keeps large checkpoints from
        // exhausting memory, and preserves current credentials before the
        // backup API's atomic destination commit. No plaintext/key bridge.
        let staging = StagedDatabase::create(dir)?;
        let mut staged = Connection::open(&staging.path)?;
        staged.execute_batch("PRAGMA synchronous=FULL; PRAGMA temp_store=MEMORY;")?;
        {
            let backup = rusqlite::backup::Backup::new(src, &mut staged)?;
            backup.run_to_completion(256, Duration::from_millis(0), None)?;
        }
        crate::rotation::write_on(&staged, &state).map_err(|_| StoreError::Integrity)?;
        {
            let backup = rusqlite::backup::Backup::new(&staged, conn)?;
            backup.run_to_completion(256, Duration::from_millis(0), None)?;
        }
    } else {
        let backup = rusqlite::backup::Backup::new(src, conn)?;
        backup.run_to_completion(256, Duration::from_millis(0), None)?;
    }
    verify_key_on(conn, key)?;
    migrate_on(conn, key, None)
}
struct StagedDatabase {
    path: PathBuf,
}
impl StagedDatabase {
    fn create(dir: &Path) -> Result<Self> {
        let path = dir.join(format!("checkpoint-restore.{}.tmp", hex::encode(crypto::random_bytes(16))));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options.open(&path)?;
        Ok(Self { path })
    }
}
impl Drop for StagedDatabase {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Reseal every persisted ciphertext payload, retaining metadata and blob ids.
fn reseal_all(conn: &Connection, old: &Key, new: &Key) -> Result<()> {
    for table in ["objects", "secrets", "blobs", "history", "load_reports"] {
        let mut after: Option<i64> = None;
        loop {
            let query = match table {
                "objects" => "SELECT rowid,id,kind,NULL,payload FROM objects WHERE (?1 IS NULL OR rowid>?1) ORDER BY rowid LIMIT ?2",
                "secrets" => {
                    "SELECT rowid,id,NULL,workspace_id,payload FROM secrets WHERE (?1 IS NULL OR rowid>?1) ORDER BY rowid LIMIT ?2"
                }
                "history" => "SELECT rowid,id,NULL,body_blob,payload FROM history WHERE (?1 IS NULL OR rowid>?1) ORDER BY rowid LIMIT ?2",
                "blobs" => "SELECT rowid,id,NULL,NULL,payload FROM blobs WHERE (?1 IS NULL OR rowid>?1) ORDER BY rowid LIMIT ?2",
                _ => "SELECT rowid,id,NULL,NULL,payload FROM load_reports WHERE (?1 IS NULL OR rowid>?1) ORDER BY rowid LIMIT ?2",
            };
            let rows = {
                let mut st = conn.prepare(query)?;
                st.query_map(params![after, MIGRATION_BATCH], |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, Option<String>>(2)?,
                        r.get::<_, Option<String>>(3)?,
                        r.get::<_, Vec<u8>>(4)?,
                    ))
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?
            };
            if rows.is_empty() {
                break;
            }
            for (rowid, id, kind, owner, env) in rows {
                let primary = match table {
                    "objects" if kind.as_deref() == Some(kind::REVISION) => revision_aad(&id),
                    "objects" => aad(table, kind.as_deref().ok_or(StoreError::Integrity)?, &id),
                    "secrets" => secret_aad(&id, owner.as_deref()),
                    "history" => history_aad(&id, owner.as_deref()),
                    "blobs" => aad(table, "blob", &id),
                    _ => aad(table, "report", &id),
                };
                let legacy = match table {
                    "objects" if kind.as_deref() == Some(kind::REVISION) => Some(aad(table, kind::REVISION, &id)),
                    "secrets" => Some(aad(table, "secret", &id)),
                    "history" => Some(aad(table, "record", &id)),
                    _ => None,
                };
                let (data, pt) = match crypto::open(old, &primary, &env) {
                    Ok(pt) => (primary, pt),
                    Err(_) => {
                        let data = legacy.ok_or(StoreError::Integrity)?;
                        let pt = crypto::open(old, &data, &env).map_err(|_| StoreError::Integrity)?;
                        (data, pt)
                    }
                };
                let resealed = crypto::seal(new, &data, &pt);
                conn.execute(&format!("UPDATE {table} SET payload=?1 WHERE rowid=?2"), params![resealed, rowid])?;
                after = Some(rowid);
                #[cfg(test)]
                rotation_tests::crash_point("after-first-row");
            }
        }
    }
    Ok(())
}

impl Store {
    /// Open (or create) the store in `dir`, applying pending migrations.
    pub fn open(dir: &Path, key: Key) -> Result<Store> {
        std::fs::create_dir_all(dir)?;
        let _data_lock = crate::profile_lock::shared(dir)?;
        let mut conn = Connection::open(dir.join(DB_FILE))?;
        conn.busy_timeout(BUSY_TIMEOUT)?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA secure_delete=ON; PRAGMA temp_store=MEMORY;",
        )?;
        conn.execute_batch("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);")?;
        let found = stored_schema_version(&conn)?;
        if found > DB_SCHEMA_VERSION {
            return Err(StoreError::FutureSchema { found, supported: DB_SCHEMA_VERSION });
        }
        // The key is checked before a migration re-seals anything with it.
        verify_key_on(&conn, &key)?;
        migrate_on(&mut conn, &key, Some(dir))?;
        Ok(Store {
            dir: dir.to_path_buf(),
            conn: Mutex::new(conn),
            tx_owner: Mutex::new(None),
            key: RwLock::new(Some(key)),
            restores: AtomicU64::new(0),
        })
    }

    /// Deliberately replace the data key, wrapped header, and linked policy
    /// in one durable SQLite commit. The successful store is left locked;
    /// reopen the App to refresh its immutable capability identity.
    pub fn rotate_data_key<F>(
        &self,
        passphrase: &str,
        kdf: crate::KdfParams,
        prepare_binding: F,
    ) -> std::result::Result<crate::vault::KeychainConversion, crate::vault::VaultError>
    where
        F: FnOnce(
            &crate::vault::ProfileHeader,
            &Key,
            &Key,
            Option<Option<serde_json::Value>>,
        ) -> std::result::Result<Option<serde_json::Value>, crate::vault::VaultError>,
    {
        use crate::vault::{self, VaultError};
        if *self.tx_owner.lock() == Some(std::thread::current().id()) {
            return Err(VaultError::Header("rotation cannot run inside a store transaction".into()));
        }
        let mut conn = self.conn.lock();
        let _data_lock = crate::profile_lock::exclusive(&self.dir)?;
        let key = self.key().map_err(|e| VaultError::Header(e.to_string()))?;
        end_transaction(&conn, Ok(())).map_err(|e| VaultError::Header(e.to_string()))?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate).map_err(|e| VaultError::Header(e.to_string()))?;
        if !check_canary(&tx, &key).map_err(|e| VaultError::Header(e.to_string()))? {
            return Err(VaultError::HeaderTampered);
        }
        let state = crate::rotation::read_on(&tx)?;
        let h = match &state {
            Some(s) => s.header.clone(),
            None => vault::read_header_unlocked(&self.dir)?,
        };
        vault::check_current(&h, &h, &key)?;
        let new_key = Key::random();
        let binding = prepare_binding(&h, &key, &new_key, state.map(|s| s.binding))?;
        let (mut next, recovery_key) = vault::rotated_header(&h, &new_key, passphrase, kdf)?;
        vault::bind_rotation(&mut next, &new_key, &binding);
        // Abort on the first unauthenticatable row. Do not retain old-key
        // ciphertext, and do not reinterpret legacy residual payloads.
        reseal_all(&tx, &key, &new_key).map_err(|e| VaultError::Header(e.to_string()))?;
        crate::rotation::write_on(&tx, &crate::rotation::State { header: next.clone(), binding })?;
        let env = crypto::seal(&new_key, b"anvil/v2/rotated-canary", b"ok");
        tx.execute("UPDATE meta SET value=?1 WHERE key='key_canary'", [format!("rotated-v1:{}", hex::encode(env))])
            .map_err(|e| VaultError::Header(e.to_string()))?;
        #[cfg(test)]
        rotation_tests::crash_point("before-commit");
        tx.commit().map_err(|e| VaultError::Header(e.to_string()))?;
        #[cfg(test)]
        rotation_tests::crash_point("after-commit");
        *self.key.write() = None;
        drop(_data_lock);
        // Historical sidecars are deliberately not a publication bridge:
        // unlock discovers the new wrapped key directly from the database.
        let keychain_entry_removed =
            if next.keychain_account.is_some() { vault::retire_rotated_keychain(&self.dir, &mut next, &new_key).is_ok() } else { true };
        Ok(vault::KeychainConversion { recovery_key, keychain_entry_removed })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn schema_version(&self) -> i64 {
        DB_SCHEMA_VERSION
    }

    /// Names of the tables in the database, besides SQLite's own.
    pub fn table_names(&self) -> Result<Vec<String>> {
        let conn = self.conn()?;
        let mut st = conn.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")?;
        let names = st.query_map([], |r| r.get(0))?.collect::<std::result::Result<Vec<String>, _>>()?;
        Ok(names)
    }

    fn key(&self) -> Result<Key> {
        self.key.read().clone().ok_or(StoreError::Locked)
    }

    /// The connection and the key for an operation that seals. The key is
    /// read only once the connection is held, so a call that raced a failed
    /// [`Store::restore_checkpoint`], which locks the store under that hold,
    /// fails with `Locked` instead of writing with the key it read before.
    fn sealing(&self) -> Result<(ConnectionGuard<'_>, Key)> {
        let conn = self.conn()?;
        let key = self.key()?;
        Ok((conn, key))
    }

    /// The connection for an operation that writes without sealing. As in
    /// [`Store::sealing`], whether the store is locked is read only once the
    /// connection is held, so a call that raced a failed
    /// [`Store::restore_checkpoint`] never writes to the database it copied.
    fn writing(&self) -> Result<ConnectionGuard<'_>> {
        let conn = self.conn()?;
        if self.is_locked() {
            return Err(StoreError::Locked);
        }
        Ok(conn)
    }

    /// The connection for one ordinary operation. It waits for a transaction
    /// open on another thread to finish, so it never runs inside a
    /// transaction it does not own.
    fn conn(&self) -> Result<ConnectionGuard<'_>> {
        if *self.tx_owner.lock() == Some(std::thread::current().id()) {
            return Err(StoreError::TransactionActive);
        }
        let conn = self.conn.lock();
        let data_lock = crate::profile_lock::shared(&self.dir)?;
        // A transaction still open here was left by a failed rollback and
        // belongs to no caller: end it rather than run inside it.
        end_transaction(&conn, Ok(()))?;
        let held_key = self.key.read().clone();
        if let Some(key) = held_key {
            // The shared file fence prevents rotation between this check and
            // the last SQL statement, including writes without encryption.
            if !matches!(check_canary(&conn, &key), Ok(true)) {
                *self.key.write() = None;
                return Err(StoreError::Locked);
            }
        }
        Ok(ConnectionGuard { conn, _data_lock: data_lock })
    }

    pub fn is_locked(&self) -> bool {
        self.key.read().is_none()
    }

    /// Run `f` with the unlocked data key (for re-wrapping it under a new
    /// passphrase). Fails while locked; the key never leaves the backend.
    pub fn with_key<R>(&self, f: impl FnOnce(&Key) -> R) -> Result<R> {
        let (_conn, k) = self.sealing()?;
        Ok(f(&k))
    }

    /// Drop the in-memory key. Every subsequent data call returns `Locked`.
    pub fn lock(&self) {
        *self.key.write() = None;
    }

    /// Unlock with `key`: check it, apply any pending migration (such as the
    /// v2 re-seal of vault secrets or the v3 seal of revision owners and
    /// history bodies) with it, and only then keep it, all under one hold of the connection, so no
    /// other call runs with a key that is not yet checked or on a database
    /// not yet migrated. A wrong key, or a migration that fails, leaves the
    /// store locked.
    pub fn unlock(&self, key: Key) -> Result<()> {
        self.unlock_if(key, || true)
    }

    /// [`Store::unlock`], keeping `key` only if `gate` still allows it:
    /// `gate` runs under the write lock of the key, right before the key is
    /// set, so no other call can use the store unlocked before it has
    /// passed. When it refuses, `key` is not kept and the error is `Locked`.
    /// A caller whose lock takes effect before it calls [`Store::lock`]
    /// (such as bumping a counter `gate` reads) thereby either fails the gate
    /// or finds the key set and clears it.
    ///
    /// A refusal leaves the key as it is: the lock that made `gate` refuse
    /// clears it itself, and clearing it here could undo a newer unlock that
    /// `gate` allowed meanwhile. Any other failure leaves the store locked.
    pub fn unlock_if(&self, key: Key, gate: impl FnOnce() -> bool) -> Result<()> {
        let r = self.conn().and_then(|mut conn| {
            verify_key_on(&conn, &key)?;
            migrate_on(&mut conn, &key, Some(&self.dir))?;
            let mut k = self.key.write();
            if !gate() {
                return Ok(false);
            }
            *k = Some(key);
            Ok(true)
        });
        // The write guard is released with the closure, before this locks.
        match r {
            Ok(true) => Ok(()),
            Ok(false) => Err(StoreError::Locked),
            Err(e) => {
                self.lock();
                Err(e)
            }
        }
    }

    // ------------------------------------------------------------ objects

    pub fn put<T: Serialize>(
        &self,
        kind: &str,
        id: &Id,
        workspace_id: Option<&Id>,
        parent_id: Option<&Id>,
        sort_key: f64,
        value: &T,
    ) -> Result<()> {
        // Authenticate the existing row and compare owners under SQLite's
        // write lock, including against writers on another Store connection.
        self.atomically(|tx| tx.put(kind, id, workspace_id, parent_id, sort_key, value))
    }

    pub fn get<T: DeserializeOwned + 'static>(&self, kind: &str, id: &Id) -> Result<Option<T>> {
        self.read_consistently(|read| read.get(kind, id))
    }

    pub fn list<T: DeserializeOwned + 'static>(&self, kind: &str, workspace_id: Option<&Id>) -> Result<Vec<T>> {
        self.read_consistently(|read| read.list(kind, workspace_id))
    }

    pub fn delete(&self, kind: &str, id: &Id) -> Result<bool> {
        let (conn, key) = self.sealing()?;
        Records { key, conn: &conn }.delete(kind, id)
    }

    /// Delete every object belonging to a workspace (and the workspace).
    pub fn delete_workspace(&self, ws: &Id) -> Result<()> {
        self.atomically(|tx| tx.delete_workspace(ws))
    }

    pub fn object_meta(&self, kind: &str) -> Result<Vec<RowMeta>> {
        let (conn, key) = self.sealing()?;
        Records { key, conn: &conn }.object_meta(kind)
    }

    // ------------------------------------------------------------ secrets

    pub fn put_secret(&self, id: &Id, workspace_id: Option<&Id>, label: &str, value: &str) -> Result<()> {
        let (conn, key) = self.sealing()?;
        Records { key, conn: &conn }.put_secret(id, workspace_id, label, value)
    }

    /// Returns (label, value).
    pub fn get_secret(&self, id: &Id) -> Result<Option<(String, Zeroizing<String>)>> {
        let (conn, key) = self.sealing()?;
        Records { key, conn: &conn }.get_secret(id)
    }

    /// Returns (label, value) of secret `id` only if workspace `ws` owns it;
    /// `None` for a secret another workspace, or none, owns.
    pub fn get_workspace_secret(&self, id: &Id, ws: &Id) -> Result<Option<(String, Zeroizing<String>)>> {
        let (conn, key) = self.sealing()?;
        Records { key, conn: &conn }.get_workspace_secret(id, ws)
    }

    pub fn list_secret_ids(&self, workspace_id: Option<&Id>) -> Result<Vec<String>> {
        let _ = self.key()?;
        let conn = self.conn()?;
        let ids = match workspace_id {
            Some(w) => {
                let mut st = conn.prepare("SELECT id FROM secrets WHERE workspace_id=?1")?;
                st.query_map(params![w.to_string()], |r| r.get(0))?.collect::<std::result::Result<Vec<String>, _>>()?
            }
            None => {
                let mut st = conn.prepare("SELECT id FROM secrets")?;
                st.query_map([], |r| r.get(0))?.collect::<std::result::Result<Vec<String>, _>>()?
            }
        };
        Ok(ids)
    }

    pub fn delete_secret(&self, id: &Id) -> Result<()> {
        let (conn, key) = self.sealing()?;
        Records { key, conn: &conn }.delete_secret(id)
    }

    // ------------------------------------------------------------ blobs

    /// Store bytes; the id is a keyed hash (content-addressed without
    /// revealing a plain hash of the content).
    pub fn put_blob(&self, bytes: &[u8]) -> Result<String> {
        // One lock for check and insert: a concurrent put of the same bytes
        // cannot slip in between and trip the primary key.
        let (conn, key) = self.sealing()?;
        Records { key, conn: &conn }.put_blob(bytes)
    }

    /// Keep a blob out of history retention. Attachments (binary bodies,
    /// multipart files, datasets, imported spec sources) are referenced from
    /// encrypted objects that `prune_history` cannot see. The pin row holds
    /// only the keyed blob id, never content.
    pub fn pin_blob(&self, id: &str) -> Result<()> {
        let (conn, key) = self.sealing()?;
        Records { key, conn: &conn }.pin_blob(id)
    }

    /// Drop a blob's pin and delete it unless a history body still uses it.
    pub fn release_blob(&self, id: &str) -> Result<()> {
        self.atomically(|tx| tx.release_blob(id))
    }

    pub fn get_blob(&self, id: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let (conn, key) = self.sealing()?;
        Records { key, conn: &conn }.get_blob(id)
    }

    // ------------------------------------------------------------ history

    /// Store a history record and its optional response body. The body blob
    /// and the history row that references it commit in one write
    /// transaction, so `prune_history` on any connection to this profile
    /// never sees the body unreferenced and collects it. The record is sealed
    /// together with the id of its body. One already stored under `id` must
    /// authenticate and seal the same workspace and request, or the write
    /// fails with `Ownership`.
    pub fn add_history<T: Serialize>(
        &self,
        id: &Id,
        workspace_id: Option<&Id>,
        request_id: Option<&Id>,
        started_at_ms: i64,
        record: &T,
        body: Option<&[u8]>,
    ) -> Result<()> {
        self.atomically(|tx| tx.add_history(id, workspace_id, request_id, started_at_ms, record, body))
    }

    pub fn list_history(&self, workspace_id: Option<&Id>, request_id: Option<&Id>, limit: usize) -> Result<Vec<HistoryEntry>> {
        let (conn, key) = self.sealing()?;
        Records { key, conn: &conn }.list_history(workspace_id, request_id, Some(limit))
    }

    pub fn get_history<T: DeserializeOwned>(&self, id: &str) -> Result<Option<HistoryRecord<T>>> {
        let (conn, key) = self.sealing()?;
        Records { key, conn: &conn }.get_history(id)
    }

    /// Enforce history retention by age and total bytes; removes orphaned blobs.
    pub fn prune_history(&self, max_age_days: u32, max_total_bytes: u64) -> Result<usize> {
        let mut conn = self.writing()?;
        // Take the write lock up front: blobs are collected against one state
        // of `history` and the pins, never against a snapshot another
        // connection has since written past.
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let cutoff = chrono::Utc::now().timestamp_millis() - (max_age_days as i64) * 86_400_000;
        let mut removed = tx.execute("DELETE FROM history WHERE started_at < ?1", params![cutoff])?;
        // Keep the newest entries whose cumulative size fits the budget.
        let rows: Vec<(String, i64)> = {
            let mut st = tx.prepare("SELECT id, size FROM history ORDER BY started_at DESC")?;
            st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<std::result::Result<_, _>>()?
        };
        let mut total: u64 = 0;
        for (id, size) in rows {
            total += size.max(0) as u64;
            if total > max_total_bytes {
                removed += tx.execute("DELETE FROM history WHERE id=?1", params![id])?;
            }
        }
        // Only history bodies are collectable here: attachment blobs are
        // pinned (see `pin_blob`) because the objects referencing them are
        // encrypted and invisible to this query.
        tx.execute(
            "DELETE FROM blobs WHERE NOT EXISTS (SELECT 1 FROM history WHERE body_blob=blobs.id) AND NOT EXISTS (SELECT 1 FROM meta WHERE key='pin:'||blobs.id)",
            [],
        )?;
        tx.commit()?;
        Ok(removed)
    }

    pub fn clear_history(&self, workspace_id: Option<&Id>) -> Result<()> {
        let conn = self.writing()?;
        conn.execute("DELETE FROM history WHERE (?1 IS NULL OR workspace_id=?1)", params![workspace_id.map(|w| w.to_string())])?;
        Ok(())
    }

    // ------------------------------------------------------------ load reports

    /// Store a load report. One already stored under `id` must authenticate
    /// and seal the same workspace, which is checked under SQLite's write
    /// lock, or the write fails with `Ownership`.
    pub fn put_load_report<T: Serialize>(&self, id: &Id, workspace_id: Option<&Id>, started_at_ms: i64, report: &T) -> Result<()> {
        self.atomically(|tx| tx.put_load_report(id, workspace_id, started_at_ms, report))
    }

    /// Load report `id`, checked against the workspace it seals.
    pub fn get_load_report<T: DeserializeOwned>(&self, id: &Id) -> Result<Option<T>> {
        let (conn, key) = self.sealing()?;
        Records { key, conn: &conn }.get_load_report(id)
    }

    pub fn list_load_reports<T: DeserializeOwned>(&self, workspace_id: Option<&Id>) -> Result<Vec<T>> {
        let (conn, key) = self.sealing()?;
        Records { key, conn: &conn }.list_load_reports(workspace_id)
    }

    pub fn delete_load_report(&self, id: &Id) -> Result<bool> {
        Ok(self.writing()?.execute("DELETE FROM load_reports WHERE id=?1", params![id.to_string()])? > 0)
    }

    // ------------------------------------------------------------ atomicity

    /// Run `f` inside one SQLite transaction owned by this call. An error or
    /// panic in `f` rolls back `f`'s writes and nothing else.
    ///
    /// The connection stays locked from `BEGIN` to `COMMIT`/`ROLLBACK`, so
    /// every other operation, on any thread, waits for the transaction to end
    /// instead of joining it or reading its uncommitted rows. `f` works through
    /// the [`StoreTx`] it is given: calling this `Store` from inside `f`,
    /// including a nested `atomically`, fails with
    /// [`StoreError::TransactionActive`] instead of deadlocking. `f` must not
    /// wait on another thread that uses this store.
    pub fn atomically<R>(&self, f: impl FnOnce(&StoreTx<'_>) -> Result<R>) -> Result<R> {
        self.transaction(TransactionBehavior::Immediate, f)
    }

    /// Run `f` against one consistent state of the store. Same guarantees as
    /// [`Store::atomically`], but `f` gets a read-only [`StoreRead`] and the
    /// transaction is `DEFERRED`, so it never takes the write lock.
    pub fn read_consistently<R>(&self, f: impl FnOnce(&StoreRead<'_>) -> Result<R>) -> Result<R> {
        self.transaction(TransactionBehavior::Deferred, |tx| f(&tx.as_read()))
    }

    fn transaction<R>(&self, behavior: TransactionBehavior, f: impl FnOnce(&StoreTx<'_>) -> Result<R>) -> Result<R> {
        // Also for a read: the lock state is read once the connection is held.
        let mut conn = self.writing()?;
        // Declared after `conn` so the owner is cleared before the lock is
        // released.
        let _owner = TxOwner::claim(&self.tx_owner);
        // The transaction borrows `conn`, so it ends with this block.
        let r = {
            let tx = StoreTx { store: self, tx: conn.transaction_with_behavior(behavior)? };
            match f(&tx) {
                Ok(r) => tx.tx.commit().map(|()| r).map_err(StoreError::from),
                Err(e) => {
                    // A failed rollback is caught and reported just below.
                    let _ = tx.tx.rollback();
                    Err(e)
                }
            }
        };
        // A failed commit or rollback can leave the transaction open; never
        // release the connection inside it.
        end_transaction(&conn, r)
    }

    /// Consistent copy of the database (ciphertext) for restore checkpoints.
    pub fn checkpoint(&self, label: &str) -> Result<PathBuf> {
        let conn = self.writing()?;
        checkpoint_on(&conn, &self.dir, label)
    }

    /// Replace the live database with a checkpoint, discarding every change
    /// made since it was taken. Nothing calls this automatically. Besides
    /// those the app takes, a `before-schema-<version>` checkpoint is taken
    /// before a migration seals existing rows again (see `migrate_on`). A
    /// checkpoint written by a newer schema, sealed with another key, or
    /// whose recorded version was set back below a step that already ran on
    /// it (see `check_not_set_back`), is refused before the live database
    /// is touched; one taken before a migration is migrated again, under the
    /// same hold of the connection as the copy. A copy or migration that
    /// fails leaves the store locked.
    pub fn restore_checkpoint(&self, path: &Path) -> Result<()> {
        let mut conn = self.writing()?;
        let key = self.key()?;
        let src = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let found = stored_schema_version(&src)?;
        if found > DB_SCHEMA_VERSION {
            return Err(StoreError::FutureSchema { found, supported: DB_SCHEMA_VERSION });
        }
        check_canary(&src, &key)?;
        check_not_set_back(&src, &key)?;
        // The current key is held under the shared rotation fence.
        self.restores.fetch_add(1, Ordering::SeqCst);
        let r = restore_on(&mut conn, &src, &key, &self.dir);
        if r.is_err() {
            *self.key.write() = None;
        }
        r
    }
}

/// Roll back any transaction still open on `conn` and confirm it ended, so a
/// connection is never handed on inside a transaction. `r` is the outcome of
/// the work done on `conn`; if the transaction cannot be ended, its error is
/// kept in the returned [`StoreError::TransactionNotEnded`].
fn end_transaction<R>(conn: &Connection, r: Result<R>) -> Result<R> {
    if conn.is_autocommit() {
        return r;
    }
    let cause = conn.execute_batch("ROLLBACK").err();
    if conn.is_autocommit() {
        return r;
    }
    Err(StoreError::TransactionNotEnded { cause, original: r.err().map(Box::new) })
}

/// Marks the current thread as the transaction owner until dropped. Claimed
/// and dropped only while the connection lock is held.
struct TxOwner<'a>(&'a Mutex<Option<ThreadId>>);

impl<'a> TxOwner<'a> {
    fn claim(slot: &'a Mutex<Option<ThreadId>>) -> TxOwner<'a> {
        *slot.lock() = Some(std::thread::current().id());
        TxOwner(slot)
    }
}

impl Drop for TxOwner<'_> {
    fn drop(&mut self) {
        *self.0.lock() = None;
    }
}

/// The open transaction of one [`Store::atomically`] call. It owns the
/// store's connection until the call returns; nothing else can use it.
/// Every operation still fails with `Locked` once the store is locked.
pub struct StoreTx<'a> {
    store: &'a Store,
    tx: Transaction<'a>,
}

impl StoreTx<'_> {
    fn records(&self) -> Result<Records<'_>> {
        Ok(Records { key: self.store.key()?, conn: &self.tx })
    }

    /// The read-only operations of this transaction.
    pub fn as_read(&self) -> StoreRead<'_> {
        StoreRead { store: self.store, conn: &self.tx }
    }

    pub fn put<T: Serialize>(
        &self,
        kind: &str,
        id: &Id,
        workspace_id: Option<&Id>,
        parent_id: Option<&Id>,
        sort_key: f64,
        value: &T,
    ) -> Result<()> {
        self.records()?.put(kind, id, workspace_id, parent_id, sort_key, value)
    }

    pub fn get<T: DeserializeOwned + 'static>(&self, kind: &str, id: &Id) -> Result<Option<T>> {
        self.records()?.get(kind, id)
    }

    pub fn list<T: DeserializeOwned + 'static>(&self, kind: &str, workspace_id: Option<&Id>) -> Result<Vec<T>> {
        self.records()?.list(kind, workspace_id)
    }

    pub fn delete(&self, kind: &str, id: &Id) -> Result<bool> {
        self.records()?.delete(kind, id)
    }

    pub fn object_meta(&self, kind: &str) -> Result<Vec<RowMeta>> {
        self.records()?.object_meta(kind)
    }

    /// [`Store::delete_workspace`] inside this transaction: rolled back with it.
    pub fn delete_workspace(&self, ws: &Id) -> Result<()> {
        let _ = self.store.key()?;
        let ws = ws.to_string();
        // Authenticate live revision owners before removing any parent.
        // An orphan's index supplies no historical owner; preserve it (and
        // any undecodable revision) for profile-wide reference accounting.
        let mut revisions = Vec::new();
        for row in self.object_meta(kind::REVISION)? {
            if row.workspace_id.as_deref() != Some(ws.as_str()) {
                continue;
            }
            let Ok(id) = row.id.parse::<Id>() else { continue };
            match self.get::<anvil_domain::workspace::RequestRevision>(kind::REVISION, &id) {
                Ok(Some(_)) => revisions.push(id),
                Ok(None) | Err(StoreError::Integrity | StoreError::Serde(_)) => {}
                Err(e) => return Err(e),
            }
        }
        for id in revisions {
            self.delete(kind::REVISION, &id)?;
        }
        self.tx.execute("DELETE FROM objects WHERE workspace_id=?1 AND kind<>?2", params![ws, kind::REVISION])?;
        self.tx.execute("DELETE FROM objects WHERE kind='workspace' AND id=?1", params![ws])?;
        self.tx.execute("DELETE FROM secrets WHERE workspace_id=?1", params![ws])?;
        self.tx.execute("DELETE FROM history WHERE workspace_id=?1", params![ws])?;
        self.tx.execute("DELETE FROM load_reports WHERE workspace_id=?1", params![ws])?;
        Ok(())
    }

    /// Keep `value` as this database's note `name` (see [`StoreRead::note`]).
    pub fn put_note(&self, name: &str, value: &str) -> Result<()> {
        let _ = self.store.key()?;
        self.tx.execute(
            "INSERT INTO meta(key, value) VALUES(?1, ?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            params![format!("{NOTE_PREFIX}{name}"), value],
        )?;
        Ok(())
    }

    pub fn put_secret(&self, id: &Id, workspace_id: Option<&Id>, label: &str, value: &str) -> Result<()> {
        self.records()?.put_secret(id, workspace_id, label, value)
    }

    /// Returns (label, value).
    pub fn get_secret(&self, id: &Id) -> Result<Option<(String, Zeroizing<String>)>> {
        self.records()?.get_secret(id)
    }

    pub fn delete_secret(&self, id: &Id) -> Result<()> {
        self.records()?.delete_secret(id)
    }

    /// [`Store::put_blob`] inside this transaction: rolled back with it.
    pub fn put_blob(&self, bytes: &[u8]) -> Result<String> {
        self.records()?.put_blob(bytes)
    }

    /// [`Store::pin_blob`] inside this transaction: rolled back with it.
    pub fn pin_blob(&self, id: &str) -> Result<()> {
        self.records()?.pin_blob(id)
    }

    /// [`Store::release_blob`] inside this transaction: rolled back with it.
    pub fn release_blob(&self, id: &str) -> Result<()> {
        self.records()?.release_blob(id)
    }

    /// Whether blob `id` is stored in this transaction, without decrypting it.
    pub fn has_blob(&self, id: &str) -> Result<bool> {
        self.records()?.has_blob(id)
    }

    /// See [`Store::add_history`].
    pub fn add_history<T: Serialize>(
        &self,
        id: &Id,
        workspace_id: Option<&Id>,
        request_id: Option<&Id>,
        started_at_ms: i64,
        record: &T,
        body: Option<&[u8]>,
    ) -> Result<()> {
        self.records()?.add_history(id, workspace_id, request_id, started_at_ms, record, body)
    }

    /// See [`Store::put_load_report`].
    pub fn put_load_report<T: Serialize>(&self, id: &Id, workspace_id: Option<&Id>, started_at_ms: i64, report: &T) -> Result<()> {
        self.records()?.put_load_report(id, workspace_id, started_at_ms, report)
    }
}

/// Read-only access to an open transaction: from [`Store::read_consistently`]
/// or [`StoreTx::as_read`]. It has no operation that writes.
pub struct StoreRead<'a> {
    store: &'a Store,
    conn: &'a Connection,
}

impl StoreRead<'_> {
    fn records(&self) -> Result<Records<'_>> {
        Ok(Records { key: self.store.key()?, conn: self.conn })
    }

    pub fn get<T: DeserializeOwned + 'static>(&self, kind: &str, id: &Id) -> Result<Option<T>> {
        self.records()?.get(kind, id)
    }

    /// Internal profile-wide retention inspection, never revision access or
    /// workspace authorization. `Some` contains only stored attachment hashes
    /// from an authentic revision whose sealed request ID has no parent row.
    /// No spec, route, owner, file name or other revision data is returned.
    /// `None` requires callers to use ordinary validated reads instead.
    ///
    /// Revisions left under the schema 1 seal by the schema 3 migration have
    /// no authenticated historical workspace owner, and neither plaintext
    /// owner/parent indexes nor a recreated request supply that proof. This
    /// read opens them, and schema 3 revisions, ignoring those indexes only
    /// to preserve references or exclude an orphan from a portable backup; it
    /// never adopts or reseals the row. Keep undecodable rows and their pins
    /// until safely resolved.
    #[doc(hidden)]
    pub fn orphan_revision_attachment_refs_for_retention(&self, id: &Id) -> Result<Option<HashSet<String>>> {
        self.records()?.orphan_revision_attachment_refs_for_retention(id)
    }

    /// Whether stored revision `id`'s sealed payload authenticates under this
    /// store's key (`None`: no such row), for telling a damaged revision from
    /// one this version cannot parse. Either seal counts: the schema 3 one
    /// ([`revision_aad`]), whatever its plaintext holds, and the schema 1 one
    /// ([`aad`]) a revision the v3 migration left keeps. Nothing of its
    /// content is returned.
    #[doc(hidden)]
    pub fn revision_payload_authenticates(&self, id: &Id) -> Result<Option<bool>> {
        self.records()?.revision_payload_authenticates(id)
    }

    pub fn list<T: DeserializeOwned + 'static>(&self, kind: &str, workspace_id: Option<&Id>) -> Result<Vec<T>> {
        self.records()?.list(kind, workspace_id)
    }

    pub fn object_meta(&self, kind: &str) -> Result<Vec<RowMeta>> {
        self.records()?.object_meta(kind)
    }

    /// Where this connection's database stands (see [`ChangeMarker`]). Taken
    /// first in a [`Store::read_consistently`] pass, it is that pass's state.
    pub fn change_marker(&self) -> Result<ChangeMarker> {
        let _ = self.store.key()?;
        let data_version = self.conn.query_row("PRAGMA data_version", [], |r| r.get(0))?;
        Ok(ChangeMarker { data_version, total_changes: self.conn.total_changes(), restores: self.store.restores.load(Ordering::SeqCst) })
    }

    /// This database's note `name`: a small plaintext value the app keeps
    /// about this database (in `meta`), such as when it last ran a cleanup.
    /// Never sealed and never carried by a backup or export, so never secret.
    pub fn note(&self, name: &str) -> Result<Option<String>> {
        let _ = self.store.key()?;
        let key = format!("{NOTE_PREFIX}{name}");
        Ok(self.conn.query_row("SELECT value FROM meta WHERE key=?1", params![key], |r| r.get(0)).optional()?)
    }

    /// Returns (label, value).
    pub fn get_secret(&self, id: &Id) -> Result<Option<(String, Zeroizing<String>)>> {
        self.records()?.get_secret(id)
    }

    /// Every stored secret's id with the workspace that owns it (`None`: no
    /// workspace does).
    pub fn secret_owners(&self) -> Result<Vec<(String, Option<String>)>> {
        let _ = self.store.key()?;
        let mut st = self.conn.prepare("SELECT id, workspace_id FROM secrets")?;
        let owners = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
        let owners: Vec<(String, Option<String>)> = owners.collect::<std::result::Result<_, _>>()?;
        Ok(owners)
    }

    /// Every vault secret, decrypted, with its owner.
    pub fn secrets(&self) -> Result<Vec<SecretRecord>> {
        self.records()?.secrets()
    }

    pub fn get_blob(&self, id: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
        self.records()?.get_blob(id)
    }

    /// Every history entry (no limit), newest first, each checked against the
    /// workspace and request its record seals and the body it is bound to. An
    /// entry that fails names its id (`ObjectIntegrity`), so it can be found
    /// and deleted.
    pub fn history_entries(&self) -> Result<Vec<HistoryEntry>> {
        self.records()?.list_history(None, None, None)
    }

    pub fn get_history<T: DeserializeOwned>(&self, id: &str) -> Result<Option<HistoryRecord<T>>> {
        self.records()?.get_history(id)
    }

    pub fn list_load_reports<T: DeserializeOwned>(&self, workspace_id: Option<&Id>) -> Result<Vec<T>> {
        self.records()?.list_load_reports(workspace_id)
    }

    /// Id and workspace of every stored load report, each checked against
    /// the workspace it seals. A report that fails names its id
    /// (`ObjectIntegrity`), so it can be found and deleted.
    pub fn load_report_entries(&self) -> Result<Vec<(String, Option<String>)>> {
        Ok(self.records()?.load_report_rows(None)?.into_iter().map(|(id, ws, _)| (id, ws)).collect())
    }
}

/// Object, secret, blob, history and load-report operations on one
/// connection: a `Store`'s (autocommit) or a `StoreTx`'s (inside its
/// transaction).
struct Records<'c> {
    key: Key,
    conn: &'c Connection,
}

/// The sealed workspace of each request read so far, by request id.
type RequestOwners = HashMap<Id, Id>;

/// A history row: its id, workspace and request indexes, start, size, the
/// response body blob it references and the sealed record.
struct HistoryRow {
    id: String,
    workspace_id: Option<String>,
    request_id: Option<String>,
    started_at: i64,
    size: i64,
    body_blob: Option<String>,
    payload: Vec<u8>,
}

/// The columns [`HistoryRow::read_from`] reads, in order.
const HISTORY_COLUMNS: &str = "id, workspace_id, request_id, started_at, size, body_blob, payload";

impl HistoryRow {
    /// Read [`HISTORY_COLUMNS`] from `row`, starting at column `first`.
    fn read_from(row: &rusqlite::Row<'_>, first: usize) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get(first)?,
            workspace_id: row.get(first + 1)?,
            request_id: row.get(first + 2)?,
            started_at: row.get(first + 3)?,
            size: row.get(first + 4)?,
            body_blob: row.get(first + 5)?,
            payload: row.get(first + 6)?,
        })
    }
}

/// Name the history record or load report `id` a profile read failed on, so
/// it can be found and deleted, instead of the generic decrypt error. Only
/// the kind and id are disclosed.
fn row_integrity(kind: &str, id: &str, e: StoreError) -> StoreError {
    match e {
        StoreError::Integrity => StoreError::ObjectIntegrity { kind: kind.to_string(), id: id.to_string() },
        other => other,
    }
}

/// A load report checked against its sealed workspace: id, workspace index
/// and the decrypted report.
type ReportRow = (String, Option<String>, Zeroizing<Vec<u8>>);

struct ObjectRow {
    owner: Option<String>,
    parent: Option<String>,
    payload: Vec<u8>,
}

impl ObjectRow {
    fn read(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self { owner: row.get(0)?, parent: row.get(1)?, payload: row.get(2)? })
    }
}

// Only canonical content hashes may leave the restricted orphan inspection.
// Walk the typed spec's serialization so all stored attachment variants count.
fn collect_retention_attachment_refs(value: &serde_json::Value, refs: &mut HashSet<String>) -> Result<()> {
    match value {
        serde_json::Value::Object(fields) => {
            if fields.get("kind").and_then(|v| v.as_str()) == Some("stored") {
                let sha = fields.get("sha256").and_then(|v| v.as_str()).ok_or(StoreError::Integrity)?;
                let canonical = sha.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
                if sha.len() != 64 || !canonical {
                    return Err(StoreError::Integrity);
                }
                refs.insert(sha.to_string());
            }
            for v in fields.values() {
                collect_retention_attachment_refs(v, refs)?;
            }
        }
        serde_json::Value::Array(values) => {
            for v in values {
                collect_retention_attachment_refs(v, refs)?;
            }
        }
        _ => {}
    }
    Ok(())
}

impl Records<'_> {
    fn put<T: Serialize>(
        &self,
        kind: &str,
        id: &Id,
        workspace_id: Option<&Id>,
        parent_id: Option<&Id>,
        sort_key: f64,
        value: &T,
    ) -> Result<()> {
        let json = Zeroizing::new(serde_json::to_vec(value)?);
        let id_s = id.to_string();
        let owner = workspace_id.map(|w| w.to_string());
        let parent = parent_id.map(|p| p.to_string());
        validate_object(kind, &id_s, owner.as_deref(), parent.as_deref(), &json)?;
        if let Some(existing) = self.object_row(kind, &id_s)? {
            // An altered index must fail before a save can seal its lie into
            // a new payload, even when the submitted owner matches that index.
            self.open_object(kind, &id_s, &existing, &mut RequestOwners::new())?;
            if existing.owner != owner || (kind == kind::REVISION && existing.parent != parent) {
                return Err(StoreError::Ownership);
            }
        }
        if let Some(ws) = workspace_id
            && self.get::<anvil_domain::workspace::Workspace>(kind::WORKSPACE, ws)?.is_none()
        {
            return Err(StoreError::NotFound("workspace".into()));
        }
        let env = if kind == kind::REVISION {
            self.validate_revision_owner(owner.as_deref(), parent.as_deref(), &mut RequestOwners::new())?;
            let (Some(ws), Some(request)) = (workspace_id, parent_id) else { return Err(StoreError::Integrity) };
            seal_revision(&self.key, &id_s, *ws, *request, &json)?
        } else {
            crypto::seal(&self.key, &aad("objects", kind, &id_s), &json)
        };
        self.conn.execute(
            "INSERT INTO objects(kind,id,workspace_id,parent_id,sort_key,updated_at,payload) VALUES(?1,?2,?3,?4,?5,?6,?7)
             ON CONFLICT(kind,id) DO UPDATE SET workspace_id=excluded.workspace_id, parent_id=excluded.parent_id, sort_key=excluded.sort_key, updated_at=excluded.updated_at, payload=excluded.payload",
            params![
                kind,
                id_s,
                owner,
                parent,
                sort_key,
                chrono::Utc::now().timestamp_millis(),
                env
            ],
        )?;
        Ok(())
    }

    fn get<T: DeserializeOwned + 'static>(&self, kind: &str, id: &Id) -> Result<Option<T>> {
        let id_s = id.to_string();
        match self.object_row(kind, &id_s)? {
            None => Ok(None),
            Some(row) => {
                let (pt, decoded) = self.open_object(kind, &id_s, &row, &mut RequestOwners::new())?;
                Ok(Some(typed(decoded, &pt)?))
            }
        }
    }

    fn object_row(&self, kind: &str, id: &str) -> Result<Option<ObjectRow>> {
        Ok(self
            .conn
            .query_row("SELECT workspace_id, parent_id, payload FROM objects WHERE kind=?1 AND id=?2", params![kind, id], ObjectRow::read)
            .optional()?)
    }

    /// Decrypt and check a row: its plaintext, and the object as the check
    /// decoded it. A revision's request is read through `owners`.
    fn open_object(&self, kind: &str, id: &str, row: &ObjectRow, owners: &mut RequestOwners) -> Result<(Zeroizing<Vec<u8>>, Decoded)> {
        if kind != kind::REVISION {
            let pt = crypto::open(&self.key, &aad("objects", kind, id), &row.payload).map_err(|_| StoreError::Integrity)?;
            let decoded = validate_object(kind, id, row.owner.as_deref(), row.parent.as_deref(), &pt)?;
            return Ok((pt, decoded));
        }
        // Only schema 3 revisions open here: a revision left under the schema
        // 1 seal at the migration has no authenticated owner and stays refused.
        let (owner, request, pt) = open_revision(&self.key, id, &row.payload)?;
        if row.owner.as_deref() != Some(owner.to_string().as_str()) || row.parent.as_deref() != Some(request.to_string().as_str()) {
            return Err(StoreError::Integrity);
        }
        let decoded = validate_object(kind, id, row.owner.as_deref(), row.parent.as_deref(), &pt)?;
        // The sealed owner is historical: the request must still be that
        // workspace's, so one deleted and its id reused elsewhere does not
        // take the revision along.
        self.validate_revision_owner(row.owner.as_deref(), row.parent.as_deref(), owners)?;
        Ok((pt, decoded))
    }

    /// The schema 3 envelope of legacy revision `id`, for the v3 migration
    /// only, if the schema 2 read accepts it: it opens under the schema 1
    /// [`aad`], its sealed id and request match the row, and that request
    /// authenticates with the revision's workspace index as its sealed owner,
    /// `request_owner` (see [`Records::request_owner`]). `Integrity`
    /// otherwise.
    fn reseal_legacy_revision(&self, id: &str, row: &ObjectRow, request_owner: Option<&str>) -> Result<Vec<u8>> {
        let pt = crypto::open(&self.key, &aad("objects", kind::REVISION, id), &row.payload).map_err(|_| StoreError::Integrity)?;
        validate_object(kind::REVISION, id, row.owner.as_deref(), row.parent.as_deref(), &pt)?;
        // `validate_object` requires an owner index, so a request that does
        // not authenticate (`None`) never matches.
        if request_owner != row.owner.as_deref() {
            return Err(StoreError::Integrity);
        }
        let parse = |v: Option<&str>| v.and_then(|v| v.parse::<Id>().ok()).ok_or(StoreError::Integrity);
        seal_revision(&self.key, id, parse(row.owner.as_deref())?, parse(row.parent.as_deref())?, &pt)
    }

    /// The workspace request `id` authenticates under: its sealed owner,
    /// which its owner index matches. `None` when it is missing or does not
    /// decrypt or validate.
    fn request_owner(&self, id: &str) -> Result<Option<String>> {
        let Ok(id) = id.parse::<Id>() else { return Ok(None) };
        match self.get::<anvil_domain::workspace::RequestDefinition>(kind::REQUEST, &id) {
            Ok(request) => Ok(request.map(|r| r.workspace_id.to_string())),
            Err(StoreError::Integrity | StoreError::Serde(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// A revision's owner is its request's sealed workspace. Each request is
    /// read once per `owners`: a list of revisions shares one.
    fn validate_revision_owner(&self, owner: Option<&str>, parent: Option<&str>, owners: &mut RequestOwners) -> Result<()> {
        use anvil_domain::workspace::RequestDefinition;
        let request_id: Id = parent.ok_or(StoreError::Integrity)?.parse().map_err(|_| StoreError::Integrity)?;
        let workspace = match owners.get(&request_id).copied() {
            Some(workspace) => workspace,
            None => {
                let request: RequestDefinition = self.get(kind::REQUEST, &request_id)?.ok_or(StoreError::Integrity)?;
                owners.insert(request_id, request.workspace_id);
                request.workspace_id
            }
        };
        if Some(workspace.to_string()).as_deref() != owner {
            return Err(StoreError::Integrity);
        }
        Ok(())
    }

    fn revision_payload_authenticates(&self, id: &Id) -> Result<Option<bool>> {
        let id_s = id.to_string();
        let Some(row) = self.object_row(kind::REVISION, &id_s)? else {
            return Ok(None);
        };
        // Only the AEAD is checked, never the plaintext: a revision a newer
        // build sealed under either seal in a format this one cannot parse
        // still authenticates, so it is kept, not offered for removal.
        let sealed = |data: &[u8]| crypto::open(&self.key, data, &row.payload).is_ok();
        Ok(Some(sealed(&revision_aad(&id_s)) || sealed(&aad("objects", kind::REVISION, &id_s))))
    }

    fn orphan_revision_attachment_refs_for_retention(&self, id: &Id) -> Result<Option<HashSet<String>>> {
        let id_s = id.to_string();
        let Some(row) = self.object_row(kind::REVISION, &id_s)? else {
            return Ok(None);
        };
        // A schema 3 revision seals its request; one left under the schema 1
        // seal at the migration (an orphan already then) has only its own.
        let (sealed_request, pt) = match open_revision(&self.key, &id_s, &row.payload) {
            Ok((_, request, pt)) => (Some(request), pt),
            Err(_) => {
                let legacy = crypto::open(&self.key, &aad("objects", kind::REVISION, &id_s), &row.payload);
                (None, legacy.map_err(|_| StoreError::Integrity)?)
            }
        };
        let revision: anvil_domain::workspace::RequestRevision = serde_json::from_slice(&pt)?;
        if revision.id != *id || sealed_request.is_some_and(|r| r != revision.request_id) {
            return Err(StoreError::Integrity);
        }
        // Presence, not the parent index or a failed ordinary parent read:
        // a corrupt or metadata-tampered existing request is not an orphan.
        if self.object_row(kind::REQUEST, &revision.request_id.to_string())?.is_some() {
            return Ok(None);
        }
        let spec = serde_json::to_value(&revision.spec)?;
        let mut refs = HashSet::new();
        collect_retention_attachment_refs(&spec, &mut refs)?;
        Ok(Some(refs))
    }

    fn list<T: DeserializeOwned + 'static>(&self, kind: &str, workspace_id: Option<&Id>) -> Result<Vec<T>> {
        let mut out = Vec::new();
        let mut owners = RequestOwners::new();
        let query_owner = workspace_id.map(|ws| ws.to_string());
        let rows: Vec<(String, ObjectRow)> = match workspace_id {
            Some(w) => {
                let mut st = self.conn.prepare(
                    "SELECT workspace_id, parent_id, payload, id FROM objects
                     WHERE kind=?1 AND workspace_id=?2 ORDER BY sort_key, updated_at",
                )?;
                st.query_map(params![kind, w.to_string()], |r| Ok((r.get(3)?, ObjectRow::read(r)?)))?
                    .collect::<std::result::Result<_, _>>()?
            }
            None => {
                let mut st = self.conn.prepare(
                    "SELECT workspace_id, parent_id, payload, id FROM objects
                     WHERE kind=?1 ORDER BY sort_key, updated_at",
                )?;
                st.query_map(params![kind], |r| Ok((r.get(3)?, ObjectRow::read(r)?)))?.collect::<std::result::Result<_, _>>()?
            }
        };
        for (id, row) in rows {
            if query_owner.is_some() && row.owner.as_deref() != query_owner.as_deref() {
                return Err(StoreError::Integrity);
            }
            let (pt, decoded) = self.open_object(kind, &id, &row, &mut owners)?;
            out.push(typed(decoded, &pt)?);
        }
        Ok(out)
    }

    fn delete(&self, kind: &str, id: &Id) -> Result<bool> {
        Ok(self.conn.execute("DELETE FROM objects WHERE kind=?1 AND id=?2", params![kind, id.to_string()])? > 0)
    }

    fn object_meta(&self, kind: &str) -> Result<Vec<RowMeta>> {
        let mut st = self.conn.prepare("SELECT kind,id,workspace_id,parent_id,sort_key,updated_at FROM objects WHERE kind=?1")?;
        let rows = st
            .query_map(params![kind], |r| {
                Ok(RowMeta {
                    kind: r.get(0)?,
                    id: r.get(1)?,
                    workspace_id: r.get(2)?,
                    parent_id: r.get(3)?,
                    sort_key: r.get(4)?,
                    updated_at: r.get(5)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    fn put_secret(&self, id: &Id, workspace_id: Option<&Id>, label: &str, value: &str) -> Result<()> {
        let payload = Zeroizing::new(serde_json::to_vec(&serde_json::json!({"label": label, "value": value}))?);
        let id_s = id.to_string();
        let owner = workspace_id.map(|w| w.to_string());
        let env = crypto::seal(&self.key, &secret_aad(&id_s, owner.as_deref()), &payload);
        self.conn.execute(
            "INSERT INTO secrets(id,workspace_id,updated_at,payload) VALUES(?1,?2,?3,?4) ON CONFLICT(id) DO UPDATE SET workspace_id=excluded.workspace_id, updated_at=excluded.updated_at, payload=excluded.payload",
            params![id_s, owner, chrono::Utc::now().timestamp_millis(), env],
        )?;
        Ok(())
    }

    fn get_secret(&self, id: &Id) -> Result<Option<(String, Zeroizing<String>)>> {
        let id_s = id.to_string();
        let sql = "SELECT workspace_id, payload FROM secrets WHERE id=?1";
        let row: Option<(Option<String>, Vec<u8>)> = self.conn.query_row(sql, params![id_s], |r| Ok((r.get(0)?, r.get(1)?))).optional()?;
        let Some((owner, env)) = row else { return Ok(None) };
        self.open_secret(&id_s, owner.as_deref(), &env).map(Some)
    }

    fn get_workspace_secret(&self, id: &Id, ws: &Id) -> Result<Option<(String, Zeroizing<String>)>> {
        let (id_s, ws_s) = (id.to_string(), ws.to_string());
        let sql = "SELECT payload FROM secrets WHERE id=?1 AND workspace_id=?2";
        let env: Option<Vec<u8>> = self.conn.query_row(sql, params![id_s, ws_s], |r| r.get(0)).optional()?;
        let Some(env) = env else { return Ok(None) };
        self.open_secret(&id_s, Some(&ws_s), &env).map(Some)
    }

    /// Decrypt a secret row's payload, sealed for `owner`, into (label, value).
    fn open_secret(&self, id_s: &str, owner: Option<&str>, env: &[u8]) -> Result<(String, Zeroizing<String>)> {
        let pt = crypto::open(&self.key, &secret_aad(id_s, owner), env).map_err(|_| StoreError::Integrity)?;
        let v: serde_json::Value = serde_json::from_slice(&pt)?;
        Ok((
            v.get("label").and_then(|x| x.as_str()).unwrap_or("").to_string(),
            Zeroizing::new(v.get("value").and_then(|x| x.as_str()).unwrap_or("").to_string()),
        ))
    }

    fn delete_secret(&self, id: &Id) -> Result<()> {
        self.conn.execute("DELETE FROM secrets WHERE id=?1", params![id.to_string()])?;
        Ok(())
    }

    fn secrets(&self) -> Result<Vec<SecretRecord>> {
        let rows: Vec<(String, Option<String>)> = {
            let mut st = self.conn.prepare("SELECT id, workspace_id FROM secrets ORDER BY id")?;
            st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<std::result::Result<_, _>>()?
        };
        let mut out = Vec::with_capacity(rows.len());
        for (id, workspace_id) in rows {
            let parsed: Id = id.parse().map_err(|_| StoreError::Integrity)?;
            let (label, value) = self.get_secret(&parsed)?.ok_or_else(|| StoreError::NotFound(format!("secret {id}")))?;
            out.push(SecretRecord { id, workspace_id, label, value });
        }
        Ok(out)
    }

    fn put_blob(&self, bytes: &[u8]) -> Result<String> {
        use hmac::{KeyInit, Mac};
        let mut m = hmac::Hmac::<sha2::Sha256>::new_from_slice(self.key.as_bytes()).expect("key");
        m.update(b"anvil-blob-id-v1");
        m.update(bytes);
        let id = hex::encode(&m.finalize().into_bytes()[..20]);
        let exists: Option<i64> = self.conn.query_row("SELECT 1 FROM blobs WHERE id=?1", params![id], |r| r.get(0)).optional()?;
        if exists.is_none() {
            let env = crypto::seal(&self.key, &aad("blobs", "blob", &id), bytes);
            self.conn.execute(
                "INSERT INTO blobs(id,size,created_at,payload) VALUES(?1,?2,?3,?4)",
                params![id, bytes.len() as i64, chrono::Utc::now().timestamp_millis(), env],
            )?;
        }
        Ok(id)
    }

    fn pin_blob(&self, id: &str) -> Result<()> {
        self.conn.execute("INSERT INTO meta(key, value) VALUES(?1, ?2) ON CONFLICT(key) DO NOTHING", params![format!("pin:{id}"), id])?;
        Ok(())
    }

    fn release_blob(&self, id: &str) -> Result<()> {
        self.conn.execute("DELETE FROM meta WHERE key=?1", params![format!("pin:{id}")])?;
        self.conn.execute("DELETE FROM blobs WHERE id=?1 AND NOT EXISTS (SELECT 1 FROM history WHERE body_blob=?1)", params![id])?;
        Ok(())
    }

    fn has_blob(&self, id: &str) -> Result<bool> {
        let found: Option<i64> = self.conn.query_row("SELECT 1 FROM blobs WHERE id=?1", params![id], |r| r.get(0)).optional()?;
        Ok(found.is_some())
    }

    fn get_blob(&self, id: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let env: Option<Vec<u8>> = self.conn.query_row("SELECT payload FROM blobs WHERE id=?1", params![id], |r| r.get(0)).optional()?;
        match env {
            None => Ok(None),
            Some(e) => Ok(Some(crypto::open(&self.key, &aad("blobs", "blob", id), &e).map_err(|_| StoreError::Integrity)?)),
        }
    }

    fn add_history<T: Serialize>(
        &self,
        id: &Id,
        workspace_id: Option<&Id>,
        request_id: Option<&Id>,
        started_at_ms: i64,
        record: &T,
        body: Option<&[u8]>,
    ) -> Result<()> {
        let json = Zeroizing::new(serde_json::to_vec(record)?);
        let (ws, request) = (workspace_id.map(|w| w.to_string()), request_id.map(|r| r.to_string()));
        // The indexes must name the owner the record seals, or reading it
        // back would refuse it.
        check_history_owner(&json, ws.as_deref(), request.as_deref())?;
        let id_s = id.to_string();
        // A record already stored under this id must authenticate, and is
        // replaced only by one with the same owner, as an object's is.
        let replaced = match self.history_row(&id_s)? {
            Some(old) => {
                self.open_history(&old)?;
                if old.workspace_id != ws || old.request_id != request {
                    return Err(StoreError::Ownership);
                }
                old.body_blob
            }
            None => None,
        };
        // The blob is unreferenced until the history row below is written:
        // callers run this inside one transaction (see `Store::add_history`).
        let body_blob = match body {
            Some(b) if !b.is_empty() => Some(self.put_blob(b)?),
            _ => None,
        };
        let env = crypto::seal(&self.key, &history_aad(&id_s, body_blob.as_deref()), &json);
        let size = env.len() as i64 + body.map(|b| b.len() as i64).unwrap_or(0);
        self.conn.execute(
            "INSERT OR REPLACE INTO history(id,workspace_id,request_id,started_at,size,body_blob,payload) VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![id_s, ws, request, started_at_ms, size, body_blob, env],
        )?;
        // Replacing a record drops its reference to the old body. As
        // `Store::release_blob`: the old body goes unless another history
        // record, or this one again, still uses it. A pinned blob is an
        // attachment's and stays.
        if let Some(old) = replaced {
            self.conn.execute(
                "DELETE FROM blobs WHERE id=?1 AND NOT EXISTS (SELECT 1 FROM history WHERE body_blob=?1) AND NOT EXISTS (SELECT 1 FROM meta WHERE key='pin:'||?1)",
                params![old],
            )?;
        }
        Ok(())
    }

    /// Newest first; `None` lists every entry. Each entry's workspace and
    /// request indexes are checked against the ones its record seals, and its
    /// body column against the one it is bound to, so a listing never names a
    /// record under an owner it does not have. An entry that fails names its
    /// id.
    fn list_history(&self, workspace_id: Option<&Id>, request_id: Option<&Id>, limit: Option<usize>) -> Result<Vec<HistoryEntry>> {
        // SQLite treats a negative LIMIT as no limit.
        let limit = limit.map(|l| i64::try_from(l).unwrap_or(i64::MAX)).unwrap_or(-1);
        let filter = "(?1 IS NULL OR workspace_id=?1) AND (?2 IS NULL OR request_id=?2)";
        let sql = format!("SELECT {HISTORY_COLUMNS} FROM history WHERE {filter} ORDER BY started_at DESC, id DESC LIMIT ?3");
        let mut st = self.conn.prepare(&sql)?;
        let (ws, request) = (workspace_id.map(|w| w.to_string()), request_id.map(|r| r.to_string()));
        let rows = st.query_map(params![ws, request, limit], |r| HistoryRow::read_from(r, 0))?;
        let mut out = Vec::new();
        // One row in memory at a time.
        for row in rows {
            let row = row?;
            self.open_history(&row).map_err(|e| row_integrity("history record", &row.id, e))?;
            let HistoryRow { id, workspace_id, request_id, started_at, size, .. } = row;
            out.push(HistoryEntry { id, workspace_id, request_id, started_at, size });
        }
        Ok(out)
    }

    fn history_row(&self, id: &str) -> Result<Option<HistoryRow>> {
        let sql = format!("SELECT {HISTORY_COLUMNS} FROM history WHERE id=?1");
        Ok(self.conn.query_row(&sql, params![id], |r| HistoryRow::read_from(r, 0)).optional()?)
    }

    /// Decrypt a history record, bound to its row's id and body column, and
    /// check that its sealed workspace and request are the row's indexes.
    fn open_history(&self, row: &HistoryRow) -> Result<Zeroizing<Vec<u8>>> {
        let bound = history_aad(&row.id, row.body_blob.as_deref());
        let pt = crypto::open(&self.key, &bound, &row.payload).map_err(|_| StoreError::Integrity)?;
        check_history_owner(&pt, row.workspace_id.as_deref(), row.request_id.as_deref())?;
        Ok(pt)
    }

    fn get_history<T: DeserializeOwned>(&self, id: &str) -> Result<Option<HistoryRecord<T>>> {
        let Some(row) = self.history_row(id)? else { return Ok(None) };
        let pt = self.open_history(&row)?;
        let rec: T = serde_json::from_slice(&pt)?;
        // The record opened under this body id, and a blob opens only under
        // its own, so the body is the one stored with the record.
        let body = match &row.body_blob {
            Some(b) => self.get_blob(b)?,
            None => None,
        };
        Ok(Some((rec, body)))
    }

    fn put_load_report<T: Serialize>(&self, id: &Id, workspace_id: Option<&Id>, started_at_ms: i64, report: &T) -> Result<()> {
        let json = serde_json::to_vec(report)?;
        let ws = workspace_id.map(|w| w.to_string());
        // The index must name the workspace the report seals.
        check_report_owner(&json, ws.as_deref())?;
        let id_s = id.to_string();
        // A report already stored under this id must authenticate, and is
        // replaced only by one for the same workspace.
        if let Some((old_ws, old)) = self.report_row(&id_s)? {
            self.open_report(&id_s, old_ws.as_deref(), &old)?;
            if old_ws != ws {
                return Err(StoreError::Ownership);
            }
        }
        let env = crypto::seal(&self.key, &aad("load_reports", "report", &id_s), &json);
        self.conn.execute(
            "INSERT OR REPLACE INTO load_reports(id,workspace_id,started_at,payload) VALUES(?1,?2,?3,?4)",
            params![id_s, ws, started_at_ms, env],
        )?;
        Ok(())
    }

    /// The workspace index and sealed payload of load report `id`.
    fn report_row(&self, id: &str) -> Result<Option<(Option<String>, Vec<u8>)>> {
        let sql = "SELECT workspace_id, payload FROM load_reports WHERE id=?1";
        Ok(self.conn.query_row(sql, params![id], |r| Ok((r.get(0)?, r.get(1)?))).optional()?)
    }

    /// Decrypt load report `id` and check that its sealed workspace is the
    /// row's index, `workspace_id`.
    fn open_report(&self, id: &str, workspace_id: Option<&str>, env: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let pt = crypto::open(&self.key, &aad("load_reports", "report", id), env).map_err(|_| StoreError::Integrity)?;
        check_report_owner(&pt, workspace_id)?;
        Ok(pt)
    }

    fn get_load_report<T: DeserializeOwned>(&self, id: &Id) -> Result<Option<T>> {
        let id_s = id.to_string();
        let Some((ws, env)) = self.report_row(&id_s)? else { return Ok(None) };
        let pt = self.open_report(&id_s, ws.as_deref(), &env)?;
        Ok(Some(serde_json::from_slice(&pt)?))
    }

    /// Every load report of `workspace_id` (`None`: of every workspace),
    /// newest first, each checked against the workspace it seals: a decrypted
    /// report and its row id and workspace index. A report that fails names
    /// its id.
    fn load_report_rows(&self, workspace_id: Option<&Id>) -> Result<Vec<ReportRow>> {
        let mut st = self
            .conn
            .prepare("SELECT id,workspace_id,payload FROM load_reports WHERE (?1 IS NULL OR workspace_id=?1) ORDER BY started_at DESC")?;
        let filter = workspace_id.map(|w| w.to_string());
        let rows = st.query_map(params![filter], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
        let mut out = Vec::new();
        for row in rows {
            let (id, ws, env): (String, Option<String>, Vec<u8>) = row?;
            let pt = self.open_report(&id, ws.as_deref(), &env).map_err(|e| row_integrity("load report", &id, e))?;
            out.push((id, ws, pt));
        }
        Ok(out)
    }

    fn list_load_reports<T: DeserializeOwned>(&self, workspace_id: Option<&Id>) -> Result<Vec<T>> {
        let mut out = Vec::new();
        for (_, _, pt) in self.load_report_rows(workspace_id)? {
            out.push(serde_json::from_slice(&pt)?);
        }
        Ok(out)
    }
}

#[cfg(test)]
#[path = "rotation_tests.rs"]
mod rotation_tests;
