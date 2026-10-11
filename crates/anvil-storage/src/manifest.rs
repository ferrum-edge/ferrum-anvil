//! Authenticated presence and ciphertext identity for live configuration and
//! secrets. This is a local authority, not an independent freshness oracle.
use crate::{
    Key, crypto, rotation,
    store::{Result, StoreError},
    vault,
};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const META: &str = "protected_records_v1";
pub(crate) const CANARY: &str = "manifest-v1:";

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Entry {
    pub table: String,
    pub kind: String,
    pub id: String,
    pub owner: Option<String>,
    pub parent: Option<String>,
    digest: String,
    sort_bits: u64,
    updated_at: i64,
}
impl Entry {
    pub fn new(table: &str, kind: &str, id: &str, owner: Option<&str>, parent: Option<&str>, payload: &[u8]) -> Self {
        Self {
            table: table.into(),
            kind: kind.into(),
            id: id.into(),
            owner: owner.map(str::to_string),
            parent: parent.map(str::to_string),
            digest: hex::encode(Sha256::digest(payload)),
            sort_bits: 0.0f64.to_bits(),
            updated_at: 0,
        }
    }
    pub fn ordered(mut self, sort_key: f64, updated_at: i64) -> Self {
        self.sort_bits = sort_key.to_bits();
        self.updated_at = updated_at;
        self
    }
    fn name(&self) -> String {
        name(&self.table, &self.kind, &self.id)
    }
}
fn name(table: &str, kind: &str, id: &str) -> String {
    serde_json::to_string(&[table, kind, id]).expect("string array serializes")
}
pub(crate) struct Manifest {
    pub(crate) entries: BTreeMap<String, Entry>,
    pub dirty: bool,
}
impl Manifest {
    pub fn capture(conn: &Connection) -> Result<Self> {
        let mut manifest = Self { entries: BTreeMap::new(), dirty: true };
        let mut st = conn.prepare("SELECT kind,id,workspace_id,parent_id,payload,sort_key,updated_at FROM objects")?;
        for row in st.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<String>>(2)?,
                r.get::<_, Option<String>>(3)?,
                r.get::<_, Vec<u8>>(4)?,
                r.get::<_, f64>(5)?,
                r.get::<_, i64>(6)?,
            ))
        })? {
            let (kind, id, owner, parent, payload, sort, updated) = row?;
            manifest.insert(Entry::new("objects", &kind, &id, owner.as_deref(), parent.as_deref(), &payload).ordered(sort, updated));
        }
        let mut st = conn.prepare("SELECT id,workspace_id,payload,updated_at FROM secrets")?;
        for row in st
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?, r.get::<_, Vec<u8>>(2)?, r.get::<_, i64>(3)?)))?
        {
            let (id, owner, payload, updated) = row?;
            manifest.insert(Entry::new("secrets", "", &id, owner.as_deref(), None, &payload).ordered(0.0, updated));
        }
        Ok(manifest)
    }
    pub fn insert(&mut self, entry: Entry) {
        self.entries.insert(entry.name(), entry);
        self.dirty = true;
    }
    pub fn verify_all(&self, conn: &Connection) -> Result<()> {
        if self.entries == Self::capture(conn)?.entries { Ok(()) } else { Err(StoreError::Integrity) }
    }
    pub fn check_metadata(
        &self,
        table: &str,
        kind: &str,
        id: &str,
        row: Option<(Option<&str>, Option<&str>)>,
        ordering: Option<(f64, i64)>,
    ) -> Result<()> {
        match (self.entries.get(&name(table, kind, id)), row) {
            (None, None) => Ok(()),
            (Some(e), Some((owner, parent)))
                if e.owner.as_deref() == owner
                    && e.parent.as_deref() == parent
                    && ordering.is_some_and(|(sort, updated)| e.sort_bits == sort.to_bits() && e.updated_at == updated) =>
            {
                Ok(())
            }
            _ => Err(StoreError::Integrity),
        }
    }
    pub fn remove(&mut self, table: &str, kind: &str, id: &str) {
        self.entries.remove(&name(table, kind, id));
        self.dirty = true;
    }
    pub fn remove_workspace(&mut self, ws: &str) {
        self.entries.retain(|_, e| {
            !(e.owner.as_deref() == Some(ws) && (e.table == "secrets" || e.kind != crate::store::kind::REVISION))
                && !(e.table == "objects" && e.kind == crate::store::kind::WORKSPACE && e.id == ws)
        });
        self.dirty = true;
    }
    pub fn check(
        &self,
        table: &str,
        kind: &str,
        id: &str,
        row: Option<(Option<&str>, Option<&str>, &[u8])>,
        ordering: Option<(f64, i64)>,
    ) -> Result<()> {
        match (self.entries.get(&name(table, kind, id)), row) {
            (None, None) => Ok(()),
            (Some(expected), Some((owner, parent, payload)))
                if ordering.is_some_and(|(sort, updated)| {
                    *expected == Entry::new(table, kind, id, owner, parent, payload).ordered(sort, updated)
                }) =>
            {
                Ok(())
            }
            _ => Err(StoreError::Integrity),
        }
    }
    /// Compare the whole queried index, including expected-but-missing rows.
    /// Payload checking remains separate so damaged rows can be enumerated for
    /// deliberate removal without returning their contents.
    pub fn check_index(
        &self,
        table: &str,
        kind: Option<&str>,
        owner: Option<&str>,
        rows: &[(String, String, Option<String>, Option<String>)],
    ) -> Result<()> {
        let actual: BTreeMap<_, _> = rows.iter().map(|(k, id, w, p)| (name(table, k, id), (w.as_deref(), p.as_deref()))).collect();
        let expected: BTreeMap<_, _> = self
            .entries
            .values()
            .filter(|e| e.table == table && kind.is_none_or(|k| e.kind == k) && owner.is_none_or(|w| e.owner.as_deref() == Some(w)))
            .map(|e| (e.name(), (e.owner.as_deref(), e.parent.as_deref())))
            .collect();
        if actual == expected { Ok(()) } else { Err(StoreError::Integrity) }
    }
    pub fn publish(&self, conn: &Connection, key: &Key, state: &mut rotation::State) -> Result<()> {
        let text = serde_json::to_string(&self.entries)?;
        let root = hex::encode(Sha256::digest(text.as_bytes()));
        vault::bind_manifest_root(&mut state.header, key, root.clone()).map_err(|_| StoreError::Integrity)?;
        rotation::write_on(conn, state).map_err(|_| StoreError::Integrity)?;
        conn.execute("INSERT INTO meta(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value", params![META, text])?;
        let env = crypto::seal(key, b"anvil/v3/manifest-canary", root.as_bytes());
        conn.execute("UPDATE meta SET value=?1 WHERE key='key_canary'", [format!("{CANARY}{}", hex::encode(env))])?;
        Ok(())
    }
}

pub(crate) fn load(conn: &Connection, key: &Key) -> Result<Option<Manifest>> {
    let state = rotation::read_on(conn).map_err(|_| StoreError::Integrity)?;
    let root = state.as_ref().and_then(|s| s.header.rotation.as_ref()).and_then(|p| p.manifest_root.as_deref());
    let canary: Option<String> = conn.query_row("SELECT value FROM meta WHERE key='key_canary'", [], |r| r.get(0)).optional()?;
    let Some(root) = root else {
        let catalogue_exists: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM meta WHERE key=?1)", [META], |r| r.get(0))?;
        if catalogue_exists
            || canary.as_deref().is_some_and(|c| c.starts_with(CANARY))
            || (state.is_some() && crate::store::stored_schema_version(conn)? >= 5)
        {
            return Err(StoreError::Integrity);
        }
        return Ok(None);
    };
    if crate::store::stored_schema_version(conn)? < 5 {
        return Err(StoreError::Integrity);
    }
    let state = state.as_ref().ok_or(StoreError::Integrity)?;
    vault::check_current(&state.header, &state.header, key).map_err(|_| StoreError::Integrity)?;
    let env = canary.as_deref().and_then(|c| c.strip_prefix(CANARY)).ok_or(StoreError::Integrity)?;
    let env = hex::decode(env).map_err(|_| StoreError::Integrity)?;
    let pt = crypto::open(key, b"anvil/v3/manifest-canary", &env).map_err(|_| StoreError::Integrity)?;
    if pt.as_slice() != root.as_bytes() {
        return Err(StoreError::Integrity);
    }
    let text: String =
        conn.query_row("SELECT value FROM meta WHERE key=?1", [META], |r| r.get(0)).optional()?.ok_or(StoreError::Integrity)?;
    if hex::encode(Sha256::digest(text.as_bytes())) != root {
        return Err(StoreError::Integrity);
    }
    let entries: BTreeMap<String, Entry> = serde_json::from_str(&text).map_err(|_| StoreError::Integrity)?;
    if entries.iter().any(|(name, e)| *name != e.name() || !matches!(e.table.as_str(), "objects" | "secrets")) {
        return Err(StoreError::Integrity);
    }
    Ok(Some(Manifest { entries, dirty: false }))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pre_catalogue_replay_cannot_disable_an_open_handle_or_silently_reenroll() {
        let dir = tempfile::tempdir().unwrap();
        let created = vault::create_enrolled_passphrase_profile(dir.path(), "test", "original", crate::KdfParams::testing()).unwrap();
        let store = crate::Store::open(dir.path(), created.dek.clone()).unwrap();
        let secret = anvil_domain::Id::new();
        store.put_secret(&secret, None, "label", "current").unwrap();
        let conn = Connection::open(dir.path().join(crate::store::DB_FILE)).unwrap();
        // An authentic pre-catalogue authority under the SAME unchanged DEK,
        // with mixed current records, must not disable the enrolled handle.
        let mut historical = rotation::read_on(&conn).unwrap().unwrap();
        historical.header.rotation.as_mut().unwrap().manifest_root = None;
        vault::bind_rotation(&mut historical.header, &created.dek, &historical.binding);
        rotation::write_on(&conn, &historical).unwrap();
        let env = crypto::seal(&created.dek, b"anvil/v2/rotated-canary", b"ok");
        conn.execute("UPDATE meta SET value=?1 WHERE key='key_canary'", [format!("rotated-v1:{}", hex::encode(env))]).unwrap();
        conn.execute("UPDATE meta SET value='4' WHERE key='schema_version'", []).unwrap();
        conn.execute("DELETE FROM meta WHERE key=?1", [META]).unwrap();
        assert!(store.protected_authority().is_err());
        assert!(store.is_locked());
        assert!(store.unlock(created.dek.clone()).is_err());
        assert!(matches!(crate::Store::open(dir.path(), created.dek.clone()), Err(StoreError::PolicyEnrollmentRequired)));
        let still_absent: bool = conn.query_row("SELECT NOT EXISTS(SELECT 1 FROM meta WHERE key=?1)", [META], |r| r.get(0)).unwrap();
        assert!(still_absent, "ordinary reopen must not authenticate the mixed rows");
        let rotation = crate::Store::open_for_rotation(dir.path(), created.dek).unwrap();
        let recovery = vault::RotationRecoveryKey::generate();
        rotation.rotate_data_key("replacement", &recovery, crate::KdfParams::testing(), |_, _, _, binding| Ok(binding.flatten())).unwrap();
        let header = vault::read_header(dir.path()).unwrap();
        let key = vault::unlock_with_recovery(&header, recovery.as_str()).unwrap();
        assert!(vault::unlock_with_passphrase(&header, "original").is_err());
        let reopened = crate::Store::open(dir.path(), key).unwrap();
        assert_eq!(reopened.get_secret(&secret).unwrap().unwrap().1.as_str(), "current");
        assert!(reopened.protected_authority().unwrap().is_some());
    }

    #[test]
    fn enrolled_authority_cannot_be_removed_or_downgraded_at_schema_five() {
        for damage in ["catalogue", "canary", "pre-manifest"] {
            let dir = tempfile::tempdir().unwrap();
            let created = vault::create_enrolled_passphrase_profile(dir.path(), "test", "original", crate::KdfParams::testing()).unwrap();
            let conn = Connection::open(dir.path().join(crate::store::DB_FILE)).unwrap();
            if damage != "canary" {
                conn.execute("DELETE FROM meta WHERE key=?1", [META]).unwrap();
            }
            if damage != "catalogue" {
                let env = crypto::seal(&created.dek, b"anvil/v2/rotated-canary", b"ok");
                conn.execute("UPDATE meta SET value=?1 WHERE key='key_canary'", [format!("rotated-v1:{}", hex::encode(env))]).unwrap();
            }
            if damage == "pre-manifest" {
                let mut state = rotation::read_on(&conn).unwrap().unwrap();
                state.header.rotation.as_mut().unwrap().manifest_root = None;
                vault::bind_rotation(&mut state.header, &created.dek, &state.binding);
                rotation::write_on(&conn, &state).unwrap();
            }
            assert!(crate::Store::open(dir.path(), created.dek).is_err(), "{damage} must fail with the original correct key");
        }
    }
}
