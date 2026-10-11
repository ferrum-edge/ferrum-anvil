//! Authenticated presence and ciphertext identity for live configuration and
//! secrets. This is a local authority, not an independent freshness oracle.
//!
//! The catalogue holds one [`Entry`] per protected object and vault secret,
//! one row each in the `catalogue` table. Entries are grouped into
//! [`BUCKETS`] buckets by a hash of their name; each bucket has a digest over
//! its entries in name order, and the root is a digest over every bucket
//! digest. The root is MAC-authenticated in the canonical wrapped header and
//! sealed into the key canary, so a catalogue row that is changed, removed,
//! added or swapped no longer reproduces it.
//!
//! A write changes only its own catalogue rows and recomputes the digests of
//! the buckets they fall in plus the root: O(changed records + buckets),
//! independent of the profile size. Loading the catalogue from the database
//! (at open, or after another connection committed) reads and checks every
//! row once; the store keeps the verified result in memory while nothing
//! else writes the database (see `Store::verified_catalogue`).
use crate::{
    Key, crypto, rotation,
    store::{Result, StoreError},
    vault,
};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// Where schema 5 kept the whole catalogue as one JSON text. Converted to
/// the `catalogue` table by the schema 6 step, and never written since.
pub(crate) const LEGACY_META: &str = "protected_records_v1";
pub(crate) const CANARY: &str = "manifest-v1:";
pub(crate) const TABLE: &str = "catalogue";
const CREATE_TABLE: &str = "CREATE TABLE IF NOT EXISTS catalogue (name TEXT PRIMARY KEY, entry TEXT NOT NULL) WITHOUT ROWID;";
/// Number of digest buckets. A write rehashes one bucket (about n/BUCKETS
/// entries) per changed entry and the BUCKETS digests once.
pub(crate) const BUCKETS: usize = 1024;
const BUCKET_DOMAIN: &[u8] = b"anvil/v4/catalogue-bucket\0";
const ROOT_DOMAIN: &[u8] = b"anvil/v4/catalogue-root\0";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
    pub fn name(&self) -> String {
        name(&self.table, &self.kind, &self.id)
    }
    fn encode(&self) -> String {
        serde_json::to_string(self).expect("entry serializes")
    }
}
pub(crate) fn name(table: &str, kind: &str, id: &str) -> String {
    serde_json::to_string(&[table, kind, id]).expect("string array serializes")
}
/// The common name prefix of every entry of `table` (and `kind`).
fn prefix(table: &str, kind: Option<&str>) -> String {
    let mut p = match kind {
        Some(kind) => serde_json::to_string(&[table, kind]),
        None => serde_json::to_string(&[table]),
    }
    .expect("string array serializes");
    p.pop();
    p.push(',');
    p
}
fn bucket(name: &str) -> usize {
    let h = Sha256::digest(name.as_bytes());
    usize::from(u16::from_be_bytes([h[0], h[1]])) % BUCKETS
}

/// A catalogue whose rows have been checked against an authenticated root,
/// or built from rows being certified.
#[derive(Clone)]
pub(crate) struct Catalogue {
    entries: BTreeMap<String, Entry>,
    members: Vec<BTreeSet<String>>,
    digests: Vec<[u8; 32]>,
}
impl Catalogue {
    fn from_entries(entries: BTreeMap<String, Entry>) -> Self {
        let mut members = vec![BTreeSet::new(); BUCKETS];
        for name in entries.keys() {
            members[bucket(name)].insert(name.clone());
        }
        let mut catalogue = Self { entries, members, digests: vec![[0; 32]; BUCKETS] };
        for b in 0..BUCKETS {
            catalogue.digests[b] = catalogue.bucket_digest(b);
        }
        catalogue
    }
    fn bucket_digest(&self, b: usize) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(BUCKET_DOMAIN);
        h.update((b as u32).to_be_bytes());
        for name in &self.members[b] {
            let encoded = self.entries[name].encode();
            h.update((encoded.len() as u64).to_be_bytes());
            h.update(encoded.as_bytes());
        }
        h.finalize().into()
    }
    pub fn root(&self) -> String {
        let mut h = Sha256::new();
        h.update(ROOT_DOMAIN);
        for d in &self.digests {
            h.update(d);
        }
        hex::encode(h.finalize())
    }
    fn apply(&mut self, changes: &BTreeMap<String, Option<Entry>>) {
        let mut touched = BTreeSet::new();
        for (name, change) in changes {
            let b = bucket(name);
            touched.insert(b);
            match change {
                Some(e) => {
                    self.entries.insert(name.clone(), e.clone());
                    self.members[b].insert(name.clone());
                }
                None => {
                    self.entries.remove(name);
                    self.members[b].remove(name);
                }
            }
        }
        for b in touched {
            self.digests[b] = self.bucket_digest(b);
        }
    }

    /// Every protected row as it is stored now, hashed. O(profile).
    pub fn capture(conn: &Connection) -> Result<Self> {
        let mut entries = BTreeMap::new();
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
            let e = Entry::new("objects", &kind, &id, owner.as_deref(), parent.as_deref(), &payload).ordered(sort, updated);
            entries.insert(e.name(), e);
        }
        let mut st = conn.prepare("SELECT id,workspace_id,payload,updated_at FROM secrets")?;
        for row in st
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?, r.get::<_, Vec<u8>>(2)?, r.get::<_, i64>(3)?)))?
        {
            let (id, owner, payload, updated) = row?;
            let e = Entry::new("secrets", "", &id, owner.as_deref(), None, &payload).ordered(0.0, updated);
            entries.insert(e.name(), e);
        }
        Ok(Self::from_entries(entries))
    }

    /// The stored catalogue, refused unless it reproduces `root`. O(profile).
    pub fn load(conn: &Connection, root: &str) -> Result<Self> {
        if !crate::store::has_table(conn, TABLE)? {
            return Err(StoreError::Integrity);
        }
        let mut entries = BTreeMap::new();
        let mut st = conn.prepare("SELECT name, entry FROM catalogue")?;
        for row in st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))? {
            let (name, text) = row?;
            let e: Entry = serde_json::from_str(&text).map_err(|_| StoreError::Integrity)?;
            if name != e.name() || !matches!(e.table.as_str(), "objects" | "secrets") {
                return Err(StoreError::Integrity);
            }
            entries.insert(name, e);
        }
        let catalogue = Self::from_entries(entries);
        if catalogue.root() != root {
            return Err(StoreError::Integrity);
        }
        Ok(catalogue)
    }

    /// Compare every stored protected row with this catalogue. O(profile).
    pub fn verify_rows(&self, conn: &Connection) -> Result<()> {
        if self.entries == Self::capture(conn)?.entries { Ok(()) } else { Err(StoreError::Integrity) }
    }

    /// Replace the whole stored catalogue with this one and publish its root.
    /// Only for certifying captured rows (enrollment, owner restore, rotation)
    /// and the schema 6 conversion. O(profile).
    pub fn publish_full(&self, conn: &Connection, key: &Key, state: &mut rotation::State) -> Result<()> {
        conn.execute_batch(CREATE_TABLE)?;
        conn.execute("DELETE FROM catalogue", [])?;
        {
            let mut st = conn.prepare("INSERT OR ABORT INTO catalogue(name, entry) VALUES(?1, ?2)")?;
            for (name, e) in &self.entries {
                st.execute(params![name, e.encode()])?;
            }
        }
        conn.execute("DELETE FROM meta WHERE key=?1", [LEGACY_META])?;
        publish_root(conn, key, state, self.root())
    }
}

fn publish_root(conn: &Connection, key: &Key, state: &mut rotation::State, root: String) -> Result<()> {
    vault::bind_manifest_root(&mut state.header, key, root.clone()).map_err(|_| StoreError::Integrity)?;
    rotation::write_on(conn, state).map_err(|_| StoreError::Integrity)?;
    let env = crypto::seal(key, b"anvil/v3/manifest-canary", root.as_bytes());
    conn.execute("UPDATE OR ABORT meta SET value=?1 WHERE key='key_canary'", [format!("{CANARY}{}", hex::encode(env))])?;
    Ok(())
}

/// One transaction's view of the catalogue: the verified catalogue it began
/// with, plus the entries it changed. Nothing is copied per transaction.
pub(crate) struct Manifest {
    base: Arc<Catalogue>,
    changes: BTreeMap<String, Option<Entry>>,
    /// The authenticated root and `PRAGMA data_version` the transaction
    /// began with: the key of the store's verified-catalogue cache.
    pub root: String,
    pub data_version: i64,
    /// Set by a bulk removal that bypasses per-entry bookkeeping: the rows
    /// are compared in full again before a context relies on them.
    pub reverify: bool,
}
impl Manifest {
    pub fn new(base: Arc<Catalogue>, root: String, data_version: i64) -> Self {
        Self { base, changes: BTreeMap::new(), root, data_version, reverify: false }
    }
    pub fn dirty(&self) -> bool {
        !self.changes.is_empty() || self.reverify
    }
    pub fn get(&self, name: &str) -> Option<&Entry> {
        match self.changes.get(name) {
            Some(change) => change.as_ref(),
            None => self.base.entries.get(name),
        }
    }
    pub fn insert(&mut self, entry: Entry) {
        self.changes.insert(entry.name(), Some(entry));
    }
    pub fn remove(&mut self, table: &str, kind: &str, id: &str) {
        self.changes.insert(name(table, kind, id), None);
    }
    /// Entries of `table` (and `kind`) as this transaction sees them.
    fn view(&self, table: &str, kind: Option<&str>) -> BTreeMap<&str, &Entry> {
        let p = prefix(table, kind);
        let mut view: BTreeMap<&str, &Entry> =
            self.base.entries.range(p.clone()..).take_while(|(n, _)| n.starts_with(&p)).map(|(n, e)| (n.as_str(), e)).collect();
        for (n, change) in self.changes.range(p.clone()..).take_while(|(n, _)| n.starts_with(&p)) {
            match change {
                Some(e) => view.insert(n.as_str(), e),
                None => view.remove(n.as_str()),
            };
        }
        view
    }
    pub fn remove_workspace(&mut self, ws: &str) {
        let mut gone: Vec<String> = self
            .view("objects", None)
            .into_iter()
            .filter(|(_, e)| {
                (e.owner.as_deref() == Some(ws) && e.kind != crate::store::kind::REVISION)
                    || (e.kind == crate::store::kind::WORKSPACE && e.id == ws)
            })
            .map(|(n, _)| n.to_string())
            .collect();
        gone.extend(self.view("secrets", None).into_iter().filter(|(_, e)| e.owner.as_deref() == Some(ws)).map(|(n, _)| n.to_string()));
        for n in gone {
            self.changes.insert(n, None);
        }
        self.reverify = true;
    }
    pub fn check_metadata(
        &self,
        table: &str,
        kind: &str,
        id: &str,
        row: Option<(Option<&str>, Option<&str>)>,
        ordering: Option<(f64, i64)>,
    ) -> Result<()> {
        match (self.get(&name(table, kind, id)), row) {
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
    pub fn check(
        &self,
        table: &str,
        kind: &str,
        id: &str,
        row: Option<(Option<&str>, Option<&str>, &[u8])>,
        ordering: Option<(f64, i64)>,
    ) -> Result<()> {
        match (self.get(&name(table, kind, id)), row) {
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
            .view(table, kind)
            .into_values()
            .filter(|e| owner.is_none_or(|w| e.owner.as_deref() == Some(w)))
            .map(|e| (e.name(), (e.owner.as_deref(), e.parent.as_deref())))
            .collect();
        if actual == expected { Ok(()) } else { Err(StoreError::Integrity) }
    }
    /// Compare every stored protected row with this view. O(profile).
    pub fn verify_rows(&self, conn: &Connection) -> Result<()> {
        if self.changes.is_empty() {
            return self.base.verify_rows(conn);
        }
        let mut merged = self.base.entries.clone();
        for (n, change) in &self.changes {
            match change {
                Some(e) => merged.insert(n.clone(), e.clone()),
                None => merged.remove(n),
            };
        }
        if merged == Catalogue::capture(conn)?.entries { Ok(()) } else { Err(StoreError::Integrity) }
    }
    /// Write this transaction's changed entries and publish the new root, in
    /// the transaction on `conn`. Returns the resulting catalogue and root.
    /// The base is updated in place when nothing else holds it.
    pub fn publish(self, conn: &Connection, key: &Key, state: &mut rotation::State) -> Result<(Arc<Catalogue>, String)> {
        let Self { mut base, changes, .. } = self;
        {
            let mut upsert = conn.prepare_cached(
                "INSERT OR ABORT INTO catalogue(name, entry) VALUES(?1, ?2) ON CONFLICT(name) DO UPDATE SET entry=excluded.entry",
            )?;
            let mut delete = conn.prepare_cached("DELETE FROM catalogue WHERE name=?1")?;
            for (n, change) in &changes {
                match change {
                    Some(e) => upsert.execute(params![n, e.encode()])?,
                    None => delete.execute([n])?,
                };
            }
        }
        let catalogue = Arc::make_mut(&mut base);
        catalogue.apply(&changes);
        let root = catalogue.root();
        publish_root(conn, key, state, root.clone())?;
        Ok((base, root))
    }
}

/// The catalogue root authenticated by the canonical header's MAC and the
/// key canary, without reading the catalogue itself: `None` for a profile
/// with no catalogue authority (legacy or pre-catalogue). O(1).
pub(crate) fn authenticated_root(conn: &Connection, key: &Key) -> Result<Option<String>> {
    let state = rotation::read_on(conn).map_err(|_| StoreError::Integrity)?;
    let root = state.as_ref().and_then(|s| s.header.rotation.as_ref()).and_then(|p| p.manifest_root.clone());
    let canary: Option<String> = conn.query_row("SELECT value FROM meta WHERE key='key_canary'", [], |r| r.get(0)).optional()?;
    let Some(root) = root else {
        let legacy: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM meta WHERE key=?1)", [LEGACY_META], |r| r.get(0))?;
        if legacy
            || crate::store::has_table(conn, TABLE)?
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
    Ok(Some(root))
}

/// Authenticated root and the catalogue that reproduces it, read in full.
/// O(profile); the store caches the result (`Store::verified_catalogue`).
pub(crate) fn load(conn: &Connection, key: &Key) -> Result<Option<(String, Catalogue)>> {
    let Some(root) = authenticated_root(conn, key)? else { return Ok(None) };
    let catalogue = Catalogue::load(conn, &root)?;
    Ok(Some((root, catalogue)))
}

/// Schema 6: move a schema 5 catalogue, kept as one JSON text in `meta` whose
/// SHA-256 was the authenticated root, into the `catalogue` table under the
/// bucketed root. The text must still reproduce the authenticated root. A
/// profile without catalogue authority is left as it is.
pub(crate) fn convert_legacy(conn: &Connection, key: &Key) -> Result<()> {
    let text: Option<String> = conn.query_row("SELECT value FROM meta WHERE key=?1", [LEGACY_META], |r| r.get(0)).optional()?;
    let Some(text) = text else { return Ok(()) };
    let mut state = rotation::read_on(conn).map_err(|_| StoreError::Integrity)?.ok_or(StoreError::Integrity)?;
    let root = state.header.rotation.as_ref().and_then(|p| p.manifest_root.clone()).ok_or(StoreError::Integrity)?;
    vault::check_current(&state.header, &state.header, key).map_err(|_| StoreError::Integrity)?;
    let canary: Option<String> = conn.query_row("SELECT value FROM meta WHERE key='key_canary'", [], |r| r.get(0)).optional()?;
    let env = canary.as_deref().and_then(|c| c.strip_prefix(CANARY)).ok_or(StoreError::Integrity)?;
    let pt = crypto::open(key, b"anvil/v3/manifest-canary", &hex::decode(env).map_err(|_| StoreError::Integrity)?)
        .map_err(|_| StoreError::Integrity)?;
    if pt.as_slice() != root.as_bytes() || hex::encode(Sha256::digest(text.as_bytes())) != root {
        return Err(StoreError::Integrity);
    }
    let entries: BTreeMap<String, Entry> = serde_json::from_str(&text).map_err(|_| StoreError::Integrity)?;
    if entries.iter().any(|(name, e)| *name != e.name() || !matches!(e.table.as_str(), "objects" | "secrets")) {
        return Err(StoreError::Integrity);
    }
    Catalogue::from_entries(entries).publish_full(conn, key, &mut state)
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
        conn.execute_batch("DROP TABLE catalogue").unwrap();
        assert!(store.protected_authority().is_err());
        assert!(store.is_locked());
        assert!(store.unlock(created.dek.clone()).is_err());
        assert!(matches!(crate::Store::open(dir.path(), created.dek.clone()), Err(StoreError::PolicyEnrollmentRequired)));
        let still_absent = !crate::store::has_table(&conn, TABLE).unwrap();
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
                conn.execute_batch("DROP TABLE catalogue").unwrap();
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

    /// Put an enrolled profile's catalogue back in the schema 5 layout: one
    /// JSON text in `meta` whose SHA-256 is the authenticated root.
    fn as_schema_five(dir: &std::path::Path, key: &Key, damage: bool) {
        let conn = Connection::open(dir.join(crate::store::DB_FILE)).unwrap();
        let mut entries = BTreeMap::new();
        let mut st = conn.prepare("SELECT name, entry FROM catalogue").unwrap();
        for row in st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))).unwrap() {
            let (name, entry) = row.unwrap();
            entries.insert(name, serde_json::from_str::<Entry>(&entry).unwrap());
        }
        drop(st);
        let text = serde_json::to_string(&entries).unwrap();
        let root = hex::encode(Sha256::digest(text.as_bytes()));
        let mut state = rotation::read_on(&conn).unwrap().unwrap();
        vault::bind_manifest_root(&mut state.header, key, root.clone()).unwrap();
        rotation::write_on(&conn, &state).unwrap();
        let env = crypto::seal(key, b"anvil/v3/manifest-canary", root.as_bytes());
        conn.execute("UPDATE meta SET value=?1 WHERE key='key_canary'", [format!("{CANARY}{}", hex::encode(env))]).unwrap();
        let stored = if damage { text.replacen("\"secrets\"", "\"objects\"", 1) } else { text };
        conn.execute("INSERT INTO meta(key, value) VALUES(?1, ?2)", params![LEGACY_META, stored]).unwrap();
        conn.execute_batch("DROP TABLE catalogue; UPDATE meta SET value='5' WHERE key='schema_version';").unwrap();
    }

    #[test]
    fn schema_five_catalogue_is_converted_only_when_it_reproduces_its_root() {
        for damage in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let created = vault::create_enrolled_passphrase_profile(dir.path(), "test", "original", crate::KdfParams::testing()).unwrap();
            let store = crate::Store::open(dir.path(), created.dek.clone()).unwrap();
            let secret = anvil_domain::Id::new();
            store.put_secret(&secret, None, "label", "kept").unwrap();
            drop(store);
            as_schema_five(dir.path(), &created.dek, damage);
            let opened = crate::Store::open(dir.path(), created.dek.clone());
            if damage {
                assert!(opened.is_err(), "a catalogue text that no longer reproduces its root is refused");
                continue;
            }
            let store = opened.unwrap();
            assert_eq!(store.get_secret(&secret).unwrap().unwrap().1.as_str(), "kept");
            store.protected_authority().unwrap();
            let conn = Connection::open(dir.path().join(crate::store::DB_FILE)).unwrap();
            let legacy: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM meta WHERE key=?1)", [LEGACY_META], |r| r.get(0)).unwrap();
            assert!(!legacy);
            assert_eq!(crate::store::stored_schema_version(&conn).unwrap(), crate::store::DB_SCHEMA_VERSION);
        }
    }

    #[test]
    fn bucket_digests_follow_incremental_changes_exactly() {
        let mut changes = BTreeMap::new();
        let mut all = BTreeMap::new();
        for i in 0..3000 {
            let e = Entry::new("objects", "request", &format!("id-{i}"), Some("ws"), None, format!("payload-{i}").as_bytes());
            all.insert(e.name(), e.clone());
            changes.insert(e.name(), Some(e));
        }
        let mut incremental = Catalogue::from_entries(BTreeMap::new());
        incremental.apply(&changes);
        assert_eq!(incremental.root(), Catalogue::from_entries(all.clone()).root());
        let mut more = BTreeMap::new();
        for i in (0..3000).step_by(7) {
            let n = name("objects", "request", &format!("id-{i}"));
            if i % 2 == 0 {
                all.remove(&n);
                more.insert(n, None);
            } else {
                let e = Entry::new("objects", "request", &format!("id-{i}"), Some("ws"), None, b"changed");
                all.insert(n.clone(), e.clone());
                more.insert(n, Some(e));
            }
        }
        let before = incremental.root();
        incremental.apply(&more);
        assert_ne!(incremental.root(), before);
        assert_eq!(incremental.root(), Catalogue::from_entries(all).root());
    }
}
