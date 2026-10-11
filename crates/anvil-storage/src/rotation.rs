//! The wrapped key header and identity policy commit with rotated ciphertext.
//! This protects future ciphertext, not replay of a complete historical database.
use crate::{
    Key, StoreError,
    store::DB_FILE,
    vault::{ProfileHeader, VaultError},
};
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::{Path, PathBuf};
pub(crate) const STATE: &str = "local_key_state_v1";
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct State {
    pub header: ProfileHeader,
    pub binding: Option<Value>,
}
/// Why the canonical key state could not be read: the database failed (which
/// may be transient), or what it holds is not valid key state.
enum ReadError {
    Db(rusqlite::Error),
    Invalid(VaultError),
}
impl From<rusqlite::Error> for ReadError {
    fn from(e: rusqlite::Error) -> Self {
        ReadError::Db(e)
    }
}
fn read_raw(conn: &Connection) -> Result<Option<State>, ReadError> {
    let exists: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='meta')", [], |r| r.get(0))?;
    if !exists {
        return Ok(None);
    }
    let text: Option<String> = conn.query_row("SELECT value FROM meta WHERE key=?1", [STATE], |r| r.get(0)).optional()?;
    let state: Option<State> =
        text.map(|text| serde_json::from_str(&text).map_err(|e| ReadError::Invalid(VaultError::Header(e.to_string())))).transpose()?;
    if state.as_ref().is_some_and(|s| s.header.rotation.is_none()) {
        return Err(ReadError::Invalid(VaultError::HeaderTampered));
    }
    let canary: Option<String> = conn.query_row("SELECT value FROM meta WHERE key='key_canary'", [], |r| r.get(0)).optional()?;
    if state.is_none() && canary.as_deref().is_some_and(|c| c.starts_with("rotated-v1:") || c.starts_with(crate::manifest::CANARY)) {
        return Err(ReadError::Invalid(VaultError::Header("the rotated profile's canonical key state is missing".into())));
    }
    Ok(state)
}
pub(crate) fn read_on(conn: &Connection) -> Result<Option<State>, VaultError> {
    read_raw(conn).map_err(|e| match e {
        ReadError::Db(e) => db(e),
        ReadError::Invalid(e) => e,
    })
}
/// [`read_on`] for the store: a database failure is returned as one (busy,
/// I/O), so it is never taken for evidence of tampering; invalid key state is
/// [`StoreError::Integrity`].
pub(crate) fn read_checked(conn: &Connection) -> Result<Option<State>, StoreError> {
    read_raw(conn).map_err(|e| match e {
        ReadError::Db(e) => StoreError::from(e),
        ReadError::Invalid(_) => StoreError::Integrity,
    })
}
pub(crate) fn read(dir: &Path) -> Result<Option<State>, VaultError> {
    let path = dir.join(DB_FILE);
    if !path.exists() {
        return Ok(None);
    }
    let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY).map_err(db)?;
    conn.busy_timeout(crate::store::BUSY_TIMEOUT).map_err(db)?;
    read_on(&conn)
}
fn db(e: rusqlite::Error) -> VaultError {
    VaultError::Header(format!("local key state: {e}"))
}
pub(crate) fn write_on(conn: &Connection, state: &State) -> Result<(), VaultError> {
    let text = serde_json::to_string(state).map_err(|e| VaultError::Header(e.to_string()))?;
    conn.execute("INSERT INTO meta(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value", params![STATE, text])
        .map_err(db)?;
    Ok(())
}
/// Canonical binding after rotation. Outer None means a legacy sidecar profile;
/// inner None is an authenticated unlinked policy, not a missing-file fallback.
pub fn binding(dir: &Path) -> Result<Option<Option<Value>>, VaultError> {
    let _lock = crate::profile_lock::shared(dir)?;
    Ok(read(dir)?.map(|s| s.binding))
}
/// Refuse same-key policy publication. Policy changes require full key rotation.
pub fn set_binding(dir: &Path, header: &ProfileHeader, key: &Key, binding: Option<Value>) -> Result<bool, VaultError> {
    let _lock = crate::profile_lock::shared(dir)?;
    let mut conn = Connection::open(dir.join(DB_FILE)).map_err(db)?;
    conn.busy_timeout(crate::store::BUSY_TIMEOUT).map_err(db)?;
    conn.execute_batch("PRAGMA synchronous=FULL;").map_err(db)?;
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate).map_err(db)?;
    let Some(state) = read_on(&tx)? else {
        return Ok(false);
    };
    crate::vault::check_current(&state.header, header, key)?;
    // Authorization happened against this authenticated policy snapshot.
    // A competing link/unlink must force reauthorization, even under the same DEK.
    crate::vault::check_protection_mac(header, key)?;
    if state.header.rotation.as_ref().map(|p| &p.binding_digest) != header.rotation.as_ref().map(|p| &p.binding_digest) {
        return Err(VaultError::Header("identity policy changed; unlock and authorize the operation again".into()));
    }
    let _ = binding;
    Err(VaultError::Header("identity changes require encryption-key rotation".into()))
}

/// Hold the cooperative data fence across a legacy sidecar operation, so
/// it cannot publish an ignored identity change after rotation commits.
pub fn profile_data_guard(dir: &Path) -> Result<std::fs::File, VaultError> {
    Ok(crate::profile_lock::shared(dir)?)
}

/// Old-key material a committed rotation leaves outside the canonical state:
/// the `profile.json` sidecar's wraps, checkpoints sealed with an earlier key,
/// interrupted checkpoint-restore staging copies, and WAL frames and main-file
/// pages written before the commit. Scrubbed under the exclusive data fence
/// right after the commit, with the connection that committed it. Failures
/// are logged; the next unlock retries ([`scrub_superseded`]).
pub(crate) fn scrub_after_commit(dir: &Path, conn: &Connection, header: &ProfileHeader, key: &Key) {
    if let Err(e) = scrub_locked(dir, conn, header, key) {
        tracing::warn!(dir = %dir.display(), error = %e, "old-key material is left after rotation; removal is retried at the next unlock");
    }
}

/// Retry [`scrub_after_commit`] for the profile in `dir` unlocked with its
/// current `key`. Cheap when nothing is left: the exclusive data fence is
/// taken only when the sidecar, a checkpoint or a staging copy still holds
/// another key. A profile without canonical state (never rotated) is left
/// alone, as is one whose current key `key` is not.
pub fn scrub_superseded(dir: &Path, key: &Key) -> Result<(), VaultError> {
    let current = |dir: &Path| -> Result<Option<ProfileHeader>, VaultError> {
        Ok(read(dir)?.map(|s| s.header).filter(|h| crate::vault::check_app_key(h, key).is_ok()))
    };
    {
        let _lock = crate::profile_lock::shared(dir)?;
        let Some(h) = current(dir)? else { return Ok(()) };
        if crate::vault::sidecar_matches(dir, &h) && superseded_files(dir, &h, key)?.is_empty() {
            return Ok(());
        }
    }
    let _lock = crate::profile_lock::exclusive(dir)?;
    let Some(h) = current(dir)? else { return Ok(()) };
    let conn = Connection::open(dir.join(DB_FILE)).map_err(db)?;
    conn.busy_timeout(crate::store::BUSY_TIMEOUT).map_err(db)?;
    scrub_locked(dir, &conn, &h, key)
}

/// The caller holds the exclusive data fence. The sidecar is rewritten last,
/// so a sidecar still holding old wraps marks an unfinished scrub.
fn scrub_locked(dir: &Path, conn: &Connection, header: &ProfileHeader, key: &Key) -> Result<(), VaultError> {
    // Copy the committed pages over the main file's pages from before the
    // rotation, then empty the WAL. No supported reader holds a snapshot.
    let busy: i64 = conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| r.get(0)).map_err(db)?;
    if busy != 0 {
        tracing::warn!(dir = %dir.display(), "the WAL could not be fully checkpointed after rotation");
    }
    for path in superseded_files(dir, header, key)? {
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    crate::vault::write_header_sidecar(dir, header)
}

/// Files under `dir` sealed with a key other than `header`'s: checkpoints
/// whose key state names another key, or whose legacy canary `key` does not
/// open, and checkpoint-restore staging copies. A checkpoint whose key
/// cannot be told (unreadable, or no canary) is kept.
fn superseded_files(dir: &Path, header: &ProfileHeader, key: &Key) -> Result<Vec<PathBuf>, VaultError> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir)?.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with("checkpoint-restore.") && name.ends_with(".tmp") {
            out.push(entry.path());
        }
    }
    let checkpoints = match std::fs::read_dir(dir.join("checkpoints")) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(e.into()),
    };
    for entry in checkpoints.flatten() {
        let path = entry.path();
        if path.extension().is_some_and(|x| x == "db") && checkpoint_superseded(&path, header, key) {
            out.push(path);
        }
    }
    Ok(out)
}

fn checkpoint_superseded(path: &Path, header: &ProfileHeader, key: &Key) -> bool {
    let Ok(conn) = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY) else {
        return false;
    };
    match read_raw(&conn) {
        Ok(Some(state)) => return state.header.key_check != header.key_check,
        Ok(None) => {}
        Err(_) => return false,
    }
    let canary: Option<String> =
        conn.query_row("SELECT value FROM meta WHERE key='key_canary'", [], |r| r.get(0)).optional().ok().flatten();
    match canary.as_deref().and_then(|c| hex::decode(c).ok()) {
        Some(env) => crate::crypto::open(key, b"anvil/v1/canary", &env).is_err(),
        None => false,
    }
}
