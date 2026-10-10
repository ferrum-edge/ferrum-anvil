//! The wrapped key header and identity policy commit with rotated ciphertext.
//! This protects future ciphertext, not replay of a complete historical database.
use crate::{
    Key,
    store::DB_FILE,
    vault::{ProfileHeader, VaultError},
};
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::Path;
pub(crate) const STATE: &str = "local_key_state_v1";
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct State {
    pub header: ProfileHeader,
    pub binding: Option<Value>,
}
pub(crate) fn read_on(conn: &Connection) -> Result<Option<State>, VaultError> {
    let exists: bool =
        conn.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='meta')", [], |r| r.get(0)).map_err(db)?;
    if !exists {
        return Ok(None);
    }
    let text: Option<String> = conn.query_row("SELECT value FROM meta WHERE key=?1", [STATE], |r| r.get(0)).optional().map_err(db)?;
    let state: Option<State> = text.map(|text| serde_json::from_str(&text).map_err(|e| VaultError::Header(e.to_string()))).transpose()?;
    if state.as_ref().is_some_and(|s| s.header.rotation.is_none()) {
        return Err(VaultError::HeaderTampered);
    }
    let canary: Option<String> =
        conn.query_row("SELECT value FROM meta WHERE key='key_canary'", [], |r| r.get(0)).optional().map_err(db)?;
    if state.is_none() && canary.as_deref().is_some_and(|c| c.starts_with("rotated-v1:")) {
        return Err(VaultError::Header("the rotated profile's canonical key state is missing".into()));
    }
    Ok(state)
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
/// Change an enrolled identity and its authenticated presence together.
pub fn set_binding(dir: &Path, header: &ProfileHeader, key: &Key, binding: Option<Value>) -> Result<bool, VaultError> {
    let _lock = crate::profile_lock::shared(dir)?;
    let mut conn = Connection::open(dir.join(DB_FILE)).map_err(db)?;
    conn.busy_timeout(crate::store::BUSY_TIMEOUT).map_err(db)?;
    conn.execute_batch("PRAGMA synchronous=FULL;").map_err(db)?;
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate).map_err(db)?;
    let Some(mut state) = read_on(&tx)? else {
        return Ok(false);
    };
    crate::vault::check_current(&state.header, header, key)?;
    // Authorization happened against this authenticated policy snapshot.
    // A competing link/unlink must force reauthorization, even under the same DEK.
    crate::vault::check_protection_mac(header, key)?;
    if state.header.rotation.as_ref().map(|p| &p.binding_digest) != header.rotation.as_ref().map(|p| &p.binding_digest) {
        return Err(VaultError::Header("identity policy changed; unlock and authorize the operation again".into()));
    }
    state.binding = binding;
    crate::vault::bind_rotation(&mut state.header, key, &state.binding);
    write_on(&tx, &state)?;
    tx.commit().map_err(db)?;
    Ok(true)
}

/// Hold the cooperative data fence across a legacy sidecar operation, so
/// it cannot publish an ignored identity change after rotation commits.
pub fn profile_data_guard(dir: &Path) -> Result<std::fs::File, VaultError> {
    Ok(crate::profile_lock::shared(dir)?)
}
