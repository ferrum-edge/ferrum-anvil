//! Encrypted SQLite store.
//!
//! Every payload (objects, secrets, history records, response bodies,
//! attachments, load reports) is sealed with the profile DEK and bound to its
//! table/kind/id through associated data, so the database file, its WAL and
//! any SQLite temp data hold only ciphertext plus structural metadata (ids,
//! parent ids, kinds, timestamps, sizes). While locked, the store has no key
//! and every data operation fails with `Locked` — enforcement lives here, not
//! in the UI.

use crate::crypto::{self, Key};
use anvil_domain::Id;
use parking_lot::{Mutex, RwLock};
use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

pub const DB_FILE: &str = "anvil.db";
/// Current on-disk schema version. Increase only with a migration below.
pub const DB_SCHEMA_VERSION: i64 = 1;

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
    #[error("database: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("serialization: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, StoreError>;

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
    key: RwLock<Option<Key>>,
}

fn aad(table: &str, kind: &str, id: &str) -> Vec<u8> {
    format!("anvil/v1/{table}/{kind}/{id}").into_bytes()
}

const MIGRATIONS: &[&str] = &[
    // v1 — baseline schema.
    r#"
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
    "#,
];

impl Store {
    /// Open (or create) the store in `dir`, applying pending migrations.
    pub fn open(dir: &Path, key: Key) -> Result<Store> {
        std::fs::create_dir_all(dir)?;
        let conn = Connection::open(dir.join(DB_FILE))?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA secure_delete=ON; PRAGMA temp_store=MEMORY;",
        )?;
        conn.execute_batch("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);")?;
        let found: i64 = conn
            .query_row("SELECT value FROM meta WHERE key='schema_version'", [], |r| r.get::<_, String>(0))
            .optional()?
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        if found > DB_SCHEMA_VERSION {
            return Err(StoreError::FutureSchema { found, supported: DB_SCHEMA_VERSION });
        }
        let store = Store { dir: dir.to_path_buf(), conn: Mutex::new(conn), key: RwLock::new(Some(key)) };
        store.migrate(found)?;
        store.verify_key()?;
        Ok(store)
    }

    fn migrate(&self, from: i64) -> Result<()> {
        let mut conn = self.conn.lock();
        for (i, sql) in MIGRATIONS.iter().enumerate() {
            let v = i as i64 + 1;
            if v <= from {
                continue;
            }
            let tx = conn.transaction()?;
            tx.execute_batch(sql)?;
            tx.execute(
                "INSERT INTO meta(key, value) VALUES('schema_version', ?1) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                params![v.to_string()],
            )?;
            tx.commit()?;
        }
        Ok(())
    }

    /// A sealed canary proves the key matches this database.
    fn verify_key(&self) -> Result<()> {
        let key = self.key()?;
        let conn = self.conn.lock();
        let canary: Option<String> = conn.query_row("SELECT value FROM meta WHERE key='key_canary'", [], |r| r.get(0)).optional()?;
        match canary {
            Some(c) => {
                let env = hex::decode(c).map_err(|_| StoreError::Integrity)?;
                crypto::open(&key, b"anvil/v1/canary", &env).map_err(|_| StoreError::Integrity)?;
            }
            None => {
                let env = crypto::seal(&key, b"anvil/v1/canary", b"ok");
                conn.execute("INSERT INTO meta(key, value) VALUES('key_canary', ?1)", params![hex::encode(env)])?;
            }
        }
        Ok(())
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn schema_version(&self) -> i64 {
        DB_SCHEMA_VERSION
    }

    fn key(&self) -> Result<Key> {
        self.key.read().clone().ok_or(StoreError::Locked)
    }

    pub fn is_locked(&self) -> bool {
        self.key.read().is_none()
    }

    /// Drop the in-memory key. Every subsequent data call returns `Locked`.
    pub fn lock(&self) {
        *self.key.write() = None;
    }

    pub fn unlock(&self, key: Key) -> Result<()> {
        *self.key.write() = Some(key);
        if let Err(e) = self.verify_key() {
            self.lock();
            return Err(e);
        }
        Ok(())
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
        let key = self.key()?;
        let json = Zeroizing::new(serde_json::to_vec(value)?);
        let id_s = id.to_string();
        let env = crypto::seal(&key, &aad("objects", kind, &id_s), &json);
        self.conn.lock().execute(
            "INSERT INTO objects(kind,id,workspace_id,parent_id,sort_key,updated_at,payload) VALUES(?1,?2,?3,?4,?5,?6,?7)
             ON CONFLICT(kind,id) DO UPDATE SET workspace_id=excluded.workspace_id, parent_id=excluded.parent_id, sort_key=excluded.sort_key, updated_at=excluded.updated_at, payload=excluded.payload",
            params![kind, id_s, workspace_id.map(|w| w.to_string()), parent_id.map(|p| p.to_string()), sort_key, chrono::Utc::now().timestamp_millis(), env],
        )?;
        Ok(())
    }

    pub fn get<T: DeserializeOwned>(&self, kind: &str, id: &Id) -> Result<Option<T>> {
        let key = self.key()?;
        let id_s = id.to_string();
        let env: Option<Vec<u8>> = self
            .conn
            .lock()
            .query_row("SELECT payload FROM objects WHERE kind=?1 AND id=?2", params![kind, id_s], |r| r.get(0))
            .optional()?;
        match env {
            None => Ok(None),
            Some(e) => {
                let pt = crypto::open(&key, &aad("objects", kind, &id_s), &e).map_err(|_| StoreError::Integrity)?;
                Ok(Some(serde_json::from_slice(&pt)?))
            }
        }
    }

    pub fn list<T: DeserializeOwned>(&self, kind: &str, workspace_id: Option<&Id>) -> Result<Vec<T>> {
        let key = self.key()?;
        let conn = self.conn.lock();
        let mut out = Vec::new();
        let rows: Vec<(String, Vec<u8>)> = match workspace_id {
            Some(w) => {
                let mut st =
                    conn.prepare("SELECT id, payload FROM objects WHERE kind=?1 AND workspace_id=?2 ORDER BY sort_key, updated_at")?;
                st.query_map(params![kind, w.to_string()], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<std::result::Result<_, _>>()?
            }
            None => {
                let mut st = conn.prepare("SELECT id, payload FROM objects WHERE kind=?1 ORDER BY sort_key, updated_at")?;
                st.query_map(params![kind], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<std::result::Result<_, _>>()?
            }
        };
        for (id, env) in rows {
            let pt = crypto::open(&key, &aad("objects", kind, &id), &env).map_err(|_| StoreError::Integrity)?;
            out.push(serde_json::from_slice(&pt)?);
        }
        Ok(out)
    }

    pub fn delete(&self, kind: &str, id: &Id) -> Result<bool> {
        let _ = self.key()?;
        Ok(self.conn.lock().execute("DELETE FROM objects WHERE kind=?1 AND id=?2", params![kind, id.to_string()])? > 0)
    }

    /// Delete every object belonging to a workspace (and the workspace).
    pub fn delete_workspace(&self, ws: &Id) -> Result<()> {
        let _ = self.key()?;
        let mut conn = self.conn.lock();
        let tx = conn.transaction()?;
        tx.execute("DELETE FROM objects WHERE workspace_id=?1", params![ws.to_string()])?;
        tx.execute("DELETE FROM objects WHERE kind='workspace' AND id=?1", params![ws.to_string()])?;
        tx.execute("DELETE FROM secrets WHERE workspace_id=?1", params![ws.to_string()])?;
        tx.execute("DELETE FROM history WHERE workspace_id=?1", params![ws.to_string()])?;
        tx.execute("DELETE FROM load_reports WHERE workspace_id=?1", params![ws.to_string()])?;
        tx.commit()?;
        Ok(())
    }

    pub fn object_meta(&self, kind: &str) -> Result<Vec<RowMeta>> {
        let _ = self.key()?;
        let conn = self.conn.lock();
        let mut st = conn.prepare("SELECT kind,id,workspace_id,parent_id,sort_key,updated_at FROM objects WHERE kind=?1")?;
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

    // ------------------------------------------------------------ secrets

    pub fn put_secret(&self, id: &Id, workspace_id: Option<&Id>, label: &str, value: &str) -> Result<()> {
        let key = self.key()?;
        let payload = Zeroizing::new(serde_json::to_vec(&serde_json::json!({"label": label, "value": value}))?);
        let id_s = id.to_string();
        let env = crypto::seal(&key, &aad("secrets", "secret", &id_s), &payload);
        self.conn.lock().execute(
            "INSERT INTO secrets(id,workspace_id,updated_at,payload) VALUES(?1,?2,?3,?4) ON CONFLICT(id) DO UPDATE SET workspace_id=excluded.workspace_id, updated_at=excluded.updated_at, payload=excluded.payload",
            params![id_s, workspace_id.map(|w| w.to_string()), chrono::Utc::now().timestamp_millis(), env],
        )?;
        Ok(())
    }

    /// Returns (label, value).
    pub fn get_secret(&self, id: &Id) -> Result<Option<(String, Zeroizing<String>)>> {
        let key = self.key()?;
        let id_s = id.to_string();
        let env: Option<Vec<u8>> =
            self.conn.lock().query_row("SELECT payload FROM secrets WHERE id=?1", params![id_s], |r| r.get(0)).optional()?;
        let Some(env) = env else { return Ok(None) };
        let pt = crypto::open(&key, &aad("secrets", "secret", &id_s), &env).map_err(|_| StoreError::Integrity)?;
        let v: serde_json::Value = serde_json::from_slice(&pt)?;
        Ok(Some((
            v.get("label").and_then(|x| x.as_str()).unwrap_or("").to_string(),
            Zeroizing::new(v.get("value").and_then(|x| x.as_str()).unwrap_or("").to_string()),
        )))
    }

    pub fn list_secret_ids(&self, workspace_id: Option<&Id>) -> Result<Vec<String>> {
        let _ = self.key()?;
        let conn = self.conn.lock();
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
        let _ = self.key()?;
        self.conn.lock().execute("DELETE FROM secrets WHERE id=?1", params![id.to_string()])?;
        Ok(())
    }

    // ------------------------------------------------------------ blobs

    /// Store bytes; the id is a keyed hash (content-addressed without
    /// revealing a plain hash of the content).
    pub fn put_blob(&self, bytes: &[u8]) -> Result<String> {
        let key = self.key()?;
        use hmac::{KeyInit, Mac};
        let mut m = hmac::Hmac::<sha2::Sha256>::new_from_slice(key.as_bytes()).expect("key");
        m.update(b"anvil-blob-id-v1");
        m.update(bytes);
        let id = hex::encode(&m.finalize().into_bytes()[..20]);
        let exists: Option<i64> = self.conn.lock().query_row("SELECT 1 FROM blobs WHERE id=?1", params![id], |r| r.get(0)).optional()?;
        if exists.is_none() {
            let env = crypto::seal(&key, &aad("blobs", "blob", &id), bytes);
            self.conn.lock().execute(
                "INSERT INTO blobs(id,size,created_at,payload) VALUES(?1,?2,?3,?4)",
                params![id, bytes.len() as i64, chrono::Utc::now().timestamp_millis(), env],
            )?;
        }
        Ok(id)
    }

    pub fn get_blob(&self, id: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let key = self.key()?;
        let env: Option<Vec<u8>> =
            self.conn.lock().query_row("SELECT payload FROM blobs WHERE id=?1", params![id], |r| r.get(0)).optional()?;
        match env {
            None => Ok(None),
            Some(e) => Ok(Some(crypto::open(&key, &aad("blobs", "blob", id), &e).map_err(|_| StoreError::Integrity)?)),
        }
    }

    // ------------------------------------------------------------ history

    pub fn add_history<T: Serialize>(
        &self,
        id: &Id,
        workspace_id: Option<&Id>,
        request_id: Option<&Id>,
        started_at_ms: i64,
        record: &T,
        body: Option<&[u8]>,
    ) -> Result<()> {
        let key = self.key()?;
        let body_blob = match body {
            Some(b) if !b.is_empty() => Some(self.put_blob(b)?),
            _ => None,
        };
        let json = Zeroizing::new(serde_json::to_vec(record)?);
        let id_s = id.to_string();
        let env = crypto::seal(&key, &aad("history", "record", &id_s), &json);
        let size = env.len() as i64 + body.map(|b| b.len() as i64).unwrap_or(0);
        self.conn.lock().execute(
            "INSERT OR REPLACE INTO history(id,workspace_id,request_id,started_at,size,body_blob,payload) VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![id_s, workspace_id.map(|w| w.to_string()), request_id.map(|r| r.to_string()), started_at_ms, size, body_blob, env],
        )?;
        Ok(())
    }

    pub fn list_history(&self, workspace_id: Option<&Id>, request_id: Option<&Id>, limit: usize) -> Result<Vec<HistoryEntry>> {
        let _ = self.key()?;
        let conn = self.conn.lock();
        let mut st = conn.prepare(
            "SELECT id,workspace_id,request_id,started_at,size FROM history WHERE (?1 IS NULL OR workspace_id=?1) AND (?2 IS NULL OR request_id=?2) ORDER BY started_at DESC LIMIT ?3",
        )?;
        let rows = st
            .query_map(params![workspace_id.map(|w| w.to_string()), request_id.map(|r| r.to_string()), limit as i64], |r| {
                Ok(HistoryEntry { id: r.get(0)?, workspace_id: r.get(1)?, request_id: r.get(2)?, started_at: r.get(3)?, size: r.get(4)? })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn get_history<T: DeserializeOwned>(&self, id: &str) -> Result<Option<(T, Option<Zeroizing<Vec<u8>>>)>> {
        let key = self.key()?;
        let row: Option<(Vec<u8>, Option<String>)> = self
            .conn
            .lock()
            .query_row("SELECT payload, body_blob FROM history WHERE id=?1", params![id], |r| Ok((r.get(0)?, r.get(1)?)))
            .optional()?;
        let Some((env, blob)) = row else { return Ok(None) };
        let pt = crypto::open(&key, &aad("history", "record", id), &env).map_err(|_| StoreError::Integrity)?;
        let rec: T = serde_json::from_slice(&pt)?;
        let body = match blob {
            Some(b) => self.get_blob(&b)?,
            None => None,
        };
        Ok(Some((rec, body)))
    }

    /// Enforce history retention by age and total bytes; removes orphaned blobs.
    pub fn prune_history(&self, max_age_days: u32, max_total_bytes: u64) -> Result<usize> {
        let _ = self.key()?;
        let mut conn = self.conn.lock();
        let tx = conn.transaction()?;
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
        tx.execute("DELETE FROM blobs WHERE id NOT IN (SELECT body_blob FROM history WHERE body_blob IS NOT NULL) AND id NOT IN (SELECT id FROM blobs WHERE id IN (SELECT value FROM meta WHERE key LIKE 'pin:%'))", [])?;
        tx.commit()?;
        Ok(removed)
    }

    pub fn clear_history(&self, workspace_id: Option<&Id>) -> Result<()> {
        let _ = self.key()?;
        self.conn
            .lock()
            .execute("DELETE FROM history WHERE (?1 IS NULL OR workspace_id=?1)", params![workspace_id.map(|w| w.to_string())])?;
        Ok(())
    }

    // ------------------------------------------------------------ load reports

    pub fn put_load_report<T: Serialize>(&self, id: &Id, workspace_id: Option<&Id>, started_at_ms: i64, report: &T) -> Result<()> {
        let key = self.key()?;
        let json = serde_json::to_vec(report)?;
        let id_s = id.to_string();
        let env = crypto::seal(&key, &aad("load_reports", "report", &id_s), &json);
        self.conn.lock().execute(
            "INSERT OR REPLACE INTO load_reports(id,workspace_id,started_at,payload) VALUES(?1,?2,?3,?4)",
            params![id_s, workspace_id.map(|w| w.to_string()), started_at_ms, env],
        )?;
        Ok(())
    }

    pub fn list_load_reports<T: DeserializeOwned>(&self, workspace_id: Option<&Id>) -> Result<Vec<T>> {
        let key = self.key()?;
        let conn = self.conn.lock();
        let mut st = conn.prepare("SELECT id,payload FROM load_reports WHERE (?1 IS NULL OR workspace_id=?1) ORDER BY started_at DESC")?;
        let rows: Vec<(String, Vec<u8>)> = st
            .query_map(params![workspace_id.map(|w| w.to_string())], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<std::result::Result<_, _>>()?;
        let mut out = Vec::new();
        for (id, env) in rows {
            let pt = crypto::open(&key, &aad("load_reports", "report", &id), &env).map_err(|_| StoreError::Integrity)?;
            out.push(serde_json::from_slice(&pt)?);
        }
        Ok(out)
    }

    // ------------------------------------------------------------ atomicity

    /// Run `f` inside one SQLite transaction; any error rolls everything back.
    pub fn atomically<R>(&self, f: impl FnOnce(&Store) -> Result<R>) -> Result<R> {
        {
            let conn = self.conn.lock();
            conn.execute_batch("BEGIN IMMEDIATE")?;
        }
        match f(self) {
            Ok(r) => {
                self.conn.lock().execute_batch("COMMIT")?;
                Ok(r)
            }
            Err(e) => {
                let _ = self.conn.lock().execute_batch("ROLLBACK");
                Err(e)
            }
        }
    }

    /// Consistent copy of the database (ciphertext) for restore checkpoints.
    pub fn checkpoint(&self, label: &str) -> Result<PathBuf> {
        let _ = self.key()?;
        let dir = self.dir.join("checkpoints");
        std::fs::create_dir_all(&dir)?;
        let safe: String = label.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-').take(40).collect();
        let path = dir.join(format!("{}-{safe}.db", chrono::Utc::now().format("%Y%m%dT%H%M%S%3fZ")));
        let conn = self.conn.lock();
        conn.execute("VACUUM INTO ?1", params![path.display().to_string()])?;
        Ok(path)
    }

    /// Replace the live database with a checkpoint (used after a failed import).
    pub fn restore_checkpoint(&self, path: &Path) -> Result<()> {
        let _ = self.key()?;
        let mut conn = self.conn.lock();
        let src = Connection::open(path)?;
        let backup = rusqlite::backup::Backup::new(&src, &mut conn)?;
        backup.run_to_completion(256, std::time::Duration::from_millis(0), None)?;
        Ok(())
    }
}
