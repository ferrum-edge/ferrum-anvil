//! Opaque, ephemeral dependency proofs. Global integrity is verified before
//! comparison; unrelated legitimate writes may change the catalogue root.
use crate::{
    Store, StoreRead,
    manifest::Entry,
    store::{Result, StoreError},
};
use anvil_domain::Id;
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::{cell::RefCell, collections::BTreeMap};
use zeroize::Zeroizing;

/// This capability is produced only by a verified read transaction. It is
/// deliberately neither serializable nor constructible from IPC data.
#[derive(Clone)]
pub struct ContextAuthority {
    generation: Value,
    restore_epoch: u64,
    points: BTreeMap<String, Option<Entry>>,
    queries: Vec<Query>,
}
#[derive(Clone)]
struct Query {
    kind: String,
    owner: Option<Id>,
    fields: Vec<(String, Value)>,
    entries: Vec<Entry>,
}

/// Context inputs and their proof are observed in the same SQLite snapshot.
/// Do not call Store/App readers or perform external IO inside this read.
pub struct ContextRead<'a, 'b> {
    read: &'a StoreRead<'b>,
    authority: RefCell<ContextAuthority>,
}
fn name(table: &str, kind: &str, id: &Id) -> String {
    serde_json::to_string(&[table, kind, &id.to_string()]).expect("strings serialize")
}
impl<'a, 'b> ContextRead<'a, 'b> {
    fn new(read: &'a StoreRead<'b>) -> Result<Self> {
        read.verify_context_snapshot()?;
        if read.manifest.borrow().is_none() {
            return Err(StoreError::PolicyEnrollmentRequired);
        }
        let state = crate::rotation::read_on(read.conn).map_err(|_| StoreError::Integrity)?;
        let generation = match state {
            Some(s) => serde_json::json!([
                s.header.profile_id,
                s.header.key_check,
                s.header.protection,
                s.header.rotation.map(|p| p.binding_digest)
            ]),
            None => Value::Null,
        };
        Ok(Self {
            read,
            authority: RefCell::new(ContextAuthority {
                generation,
                restore_epoch: read.context_restore_epoch(),
                points: BTreeMap::new(),
                queries: vec![],
            }),
        })
    }
    fn entry(&self, name: &str) -> Option<Entry> {
        self.read.manifest.borrow().as_ref().and_then(|m| m.entries.get(name).cloned())
    }
    pub fn finish(&self) -> ContextAuthority {
        self.authority.borrow().clone()
    }
    pub fn depend_object(&self, kind: &str, id: &Id) {
        let key = name("objects", kind, id);
        self.authority.borrow_mut().points.insert(key.clone(), self.entry(&key));
    }
    /// Record even deferred/missing aliases without decrypting credentials.
    pub fn depend_secret(&self, id: &Id) {
        let key = name("secrets", "", id);
        self.authority.borrow_mut().points.insert(key.clone(), self.entry(&key));
    }
    pub fn get<T: DeserializeOwned + 'static>(&self, kind: &str, id: &Id) -> Result<Option<T>> {
        self.depend_object(kind, id);
        self.read.get(kind, id)
    }
    pub fn get_workspace_secret(&self, id: &Id, ws: &Id) -> Result<Option<(String, Zeroizing<String>)>> {
        self.depend_secret(id);
        self.read.get_workspace_secret(id, ws)
    }
    pub fn get_blob(&self, id: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
        self.read.get_blob(id)
    }
    /// Read candidates without depending on unused rows. Callers must record
    /// each selected point (including failed/negative selections).
    pub fn candidates<T: DeserializeOwned + 'static>(&self, kind: &str, owner: Option<&Id>) -> Result<Vec<T>> {
        self.read.list(kind, owner)
    }
    /// Ordered query membership, including absence. JSON pointers are trusted
    /// selectors defined by App code, never raw SQL or caller callbacks.
    /// Missing optional fields normalize to JSON null.
    pub fn query<T: DeserializeOwned>(&self, kind: &str, owner: Option<&Id>, fields: &[(String, Value)]) -> Result<Vec<T>> {
        let (values, entries) = self.select(kind, owner, fields)?;
        self.authority.borrow_mut().queries.push(Query { kind: kind.into(), owner: owner.copied(), fields: fields.to_vec(), entries });
        values.into_iter().map(|v| serde_json::from_value(v).map_err(StoreError::from)).collect()
    }
    fn select(&self, kind: &str, owner: Option<&Id>, fields: &[(String, Value)]) -> Result<(Vec<Value>, Vec<Entry>)> {
        let values: Vec<Value> = self.read.list(kind, owner)?;
        let mut st = self
            .read
            .conn
            .prepare("SELECT id FROM objects WHERE kind=?1 AND (?2 IS NULL OR workspace_id=?2) ORDER BY sort_key, updated_at")?;
        let ids = st
            .query_map(rusqlite::params![kind, owner.map(|id| id.to_string())], |r| r.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        if ids.len() != values.len() {
            return Err(StoreError::Integrity);
        }
        let mut selected = vec![];
        let mut entries = vec![];
        for id in ids {
            let id: Id = id.parse().map_err(|_| StoreError::Integrity)?;
            let value: Value = self.read.get(kind, &id)?.ok_or(StoreError::Integrity)?;
            if fields.iter().all(|(pointer, expected)| value.pointer(pointer).unwrap_or(&Value::Null) == expected) {
                let entry = self.entry(&name("objects", kind, &id)).ok_or(StoreError::Integrity)?;
                entries.push(entry);
                selected.push(value);
            }
        }
        Ok((selected, entries))
    }
    pub fn check(&self, expected: &ContextAuthority) -> Result<()> {
        if self.authority.borrow().generation != expected.generation || self.authority.borrow().restore_epoch != expected.restore_epoch {
            return Err(StoreError::StaleAuthority);
        }
        for (name, entry) in &expected.points {
            if &self.entry(name) != entry {
                return Err(StoreError::StaleAuthority);
            }
        }
        for query in &expected.queries {
            if self.select(&query.kind, query.owner.as_ref(), &query.fields)?.1 != query.entries {
                return Err(StoreError::StaleAuthority);
            }
        }
        Ok(())
    }
}
impl ContextAuthority {
    pub fn includes_secret(&self, id: &Id) -> bool {
        self.points.contains_key(&name("secrets", "", id))
    }
}
impl Store {
    pub fn read_context<R>(&self, f: impl FnOnce(&ContextRead<'_, '_>) -> Result<R>) -> Result<R> {
        let result = self.read_consistently(|read| f(&ContextRead::new(read)?));
        // Clear keys only after the transaction and connection/key guards end.
        if matches!(&result, Err(StoreError::Integrity | StoreError::Locked)) {
            self.lock();
        }
        result
    }
    pub fn check_context(&self, expected: &ContextAuthority) -> Result<()> {
        self.read_context(|read| read.check(expected))
    }
}
