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
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
use zeroize::Zeroizing;

/// The objects of one kind a query reads: every owner's for `None`.
type Scope = (String, Option<Id>);

/// This capability is produced only by a verified read transaction. It is
/// deliberately neither serializable nor constructible from IPC data.
#[derive(Clone)]
pub struct ContextAuthority {
    generation: Value,
    restore_epoch: u64,
    points: BTreeMap<String, Option<Entry>>,
    queries: Vec<Query>,
    /// The catalogue entries of every object in each scope a query read, as
    /// they were then. An entry carries its row's payload digest and order,
    /// so while a scope's entries are unchanged so is every query over it,
    /// and the check need not decrypt the scope again.
    scopes: BTreeMap<Scope, Arc<Vec<Entry>>>,
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
    /// Each scope's objects, decrypted once per read: a folder walk queries
    /// the same scope once per folder, and a check replays every query.
    listed: RefCell<BTreeMap<Scope, Arc<Vec<(Id, Value)>>>>,
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
        let state = crate::rotation::read_checked(read.conn)?;
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
                scopes: BTreeMap::new(),
            }),
            listed: RefCell::new(BTreeMap::new()),
        })
    }
    fn entry(&self, name: &str) -> Option<Entry> {
        self.read.manifest.borrow().as_ref().and_then(|m| m.get(name).cloned())
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
        let mut authority = self.authority.borrow_mut();
        authority.scopes.entry((kind.into(), owner.copied())).or_insert_with(|| Arc::new(self.scope_entries(kind, owner)));
        // The same query in the same snapshot has the same membership: one
        // record of it is enough.
        if !authority.queries.iter().any(|q| q.kind == kind && q.owner.as_ref() == owner && q.fields.as_slice() == fields) {
            authority.queries.push(Query { kind: kind.into(), owner: owner.copied(), fields: fields.to_vec(), entries });
        }
        drop(authority);
        values.into_iter().map(|v| serde_json::from_value(v).map_err(StoreError::from)).collect()
    }
    /// Every object of `kind` that `owner` owns, with its id, in query order.
    /// Read with the same integrity checks as [`StoreRead::list`], once per
    /// read.
    fn listing(&self, kind: &str, owner: Option<&Id>) -> Result<Arc<Vec<(Id, Value)>>> {
        let scope = (kind.to_string(), owner.copied());
        if let Some(rows) = self.listed.borrow().get(&scope) {
            return Ok(rows.clone());
        }
        let rows = self
            .read
            .list_with_ids::<Value>(kind, owner)?
            .into_iter()
            .map(|(id, value)| Ok::<_, StoreError>((id.parse::<Id>().map_err(|_| StoreError::Integrity)?, value)))
            .collect::<Result<Vec<_>>>()?;
        let rows = Arc::new(rows);
        self.listed.borrow_mut().insert(scope, rows.clone());
        Ok(rows)
    }
    /// The catalogue entries of every object in a scope, as this read sees them.
    fn scope_entries(&self, kind: &str, owner: Option<&Id>) -> Vec<Entry> {
        let owner = owner.map(|id| id.to_string());
        self.read.manifest.borrow().as_ref().map(|m| m.owned("objects", kind, owner.as_deref())).unwrap_or_default()
    }
    fn select(&self, kind: &str, owner: Option<&Id>, fields: &[(String, Value)]) -> Result<(Vec<Value>, Vec<Entry>)> {
        let rows = self.listing(kind, owner)?;
        let mut selected = vec![];
        let mut entries = vec![];
        for (id, value) in rows.iter() {
            if fields.iter().all(|(pointer, expected)| value.pointer(pointer).unwrap_or(&Value::Null) == expected) {
                let entry = self.entry(&name("objects", kind, id)).ok_or(StoreError::Integrity)?;
                entries.push(entry);
                selected.push(value.clone());
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
        // A scope whose objects all keep their payload and order answers
        // every query as before: only a changed scope is read again.
        let unchanged: BTreeSet<&Scope> = expected
            .scopes
            .iter()
            .filter(|((kind, owner), was)| was.as_slice() == self.scope_entries(kind, owner.as_ref()).as_slice())
            .map(|(scope, _)| scope)
            .collect();
        for query in &expected.queries {
            if unchanged.contains(&(query.kind.clone(), query.owner)) {
                continue;
            }
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
