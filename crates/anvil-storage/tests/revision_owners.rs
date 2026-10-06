//! A request revision is sealed together with the workspace and request that
//! own it (schema 3). Revisions sealed before that are sealed again once, in
//! one transaction, when the store is opened or unlocked or a checkpoint is
//! restored, under the workspace of their authenticated request. A revision
//! whose request does not authenticate is left exactly as it was and stays
//! refused: it is never adopted by a workspace.

use anvil_domain::Id;
use anvil_domain::request::RequestSpec;
use anvil_storage::store::{DB_FILE, DB_SCHEMA_VERSION};
use anvil_storage::{KdfParams, Key, Store, StoreError, crypto, kind, vault};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};
use std::collections::HashSet;
use std::path::Path;

fn db(dir: &Path) -> Connection {
    Connection::open(dir.join(DB_FILE)).unwrap()
}

fn profile() -> (tempfile::TempDir, Key) {
    let dir = tempfile::tempdir().unwrap();
    let created = vault::create_passphrase_profile(dir.path(), "t", "pw", KdfParams::testing()).unwrap();
    (dir, created.dek)
}

fn stored_version(dir: &Path) -> String {
    db(dir).query_row("SELECT value FROM meta WHERE key='schema_version'", [], |r| r.get(0)).unwrap()
}

/// Put the database back at `version`, as an earlier build left it.
fn set_version(dir: &Path, version: &str) {
    db(dir).execute("UPDATE meta SET value=?1 WHERE key='schema_version'", params![version]).unwrap();
}

fn left_at_v3(dir: &Path) -> Option<String> {
    let sql = "SELECT value FROM meta WHERE key='revisions_left_at_v3'";
    db(dir).query_row(sql, [], |r| r.get(0)).optional().unwrap()
}

fn payload(dir: &Path, id: &Id) -> Vec<u8> {
    db(dir).query_row("SELECT payload FROM objects WHERE kind='revision' AND id=?1", params![id.to_string()], |r| r.get(0)).unwrap()
}

// This attacker has no key. Change only the plaintext owner index of a row.
fn set_owner_index(dir: &Path, k: &str, id: &Id, owner: &Id) {
    let sql = "UPDATE objects SET workspace_id=?1 WHERE kind=?2 AND id=?3";
    assert_eq!(db(dir).execute(sql, params![owner.to_string(), k, id.to_string()]).unwrap(), 1);
}

fn workspace(store: &Store) -> Id {
    let id = Id::new();
    let now = chrono::Utc::now();
    let value = json!({"id": id, "schema_version": anvil_domain::SCHEMA_VERSION, "created_at": now, "updated_at": now, "name": "w"});
    store.put(kind::WORKSPACE, &id, None, None, 0.0, &value).unwrap();
    id
}

fn request(store: &Store, ws: Id) -> Id {
    let id = Id::new();
    let now = chrono::Utc::now();
    let value = json!({
        "id": id, "workspace_id": ws, "schema_version": anvil_domain::SCHEMA_VERSION,
        "created_at": now, "updated_at": now, "name": "r", "sort_key": 1.0,
        "spec": RequestSpec::http("GET", "https://original.invalid/"),
    });
    store.put(kind::REQUEST, &id, Some(&ws), None, 1.0, &value).unwrap();
    id
}

/// A revision of `request` whose body names the stored attachment `sha`.
fn revision(request: Id, sha: &str) -> Value {
    let mut spec = json!(RequestSpec::http("GET", "https://original.invalid/"));
    spec["body"] = json!({
        "type": "binary",
        "attachment": {"kind": "stored", "sha256": sha, "size": 3, "file_name": "file"}
    });
    json!({"id": Id::new(), "request_id": request, "created_at": chrono::Utc::now(), "spec_sha256": "fixture hash", "spec": spec})
}

fn id_of(revision: &Value) -> Id {
    serde_json::from_value(revision["id"].clone()).unwrap()
}

/// A revision row stored as `id`, as schema 2 and earlier sealed it: bound to
/// its id only, with the owner and parent indexes given.
fn plant_v1_as(dir: &Path, key: &Key, id: Id, revision: &Value, owner: Option<Id>, parent: Option<Id>) {
    let env = crypto::seal(key, format!("anvil/v1/objects/revision/{id}").as_bytes(), &serde_json::to_vec(revision).unwrap());
    let sql = "INSERT INTO objects(kind,id,workspace_id,parent_id,sort_key,updated_at,payload) VALUES('revision',?1,?2,?3,0,0,?4)";
    db(dir).execute(sql, params![id.to_string(), owner.map(|w| w.to_string()), parent.map(|p| p.to_string()), env]).unwrap();
}

fn plant_v1(dir: &Path, key: &Key, revision: &Value, owner: Option<Id>, parent: Option<Id>) -> Id {
    let id = id_of(revision);
    plant_v1_as(dir, key, id, revision, owner, parent);
    id
}

fn get(store: &Store, id: &Id) -> Result<Option<Value>, StoreError> {
    store.get::<Value>(kind::REVISION, id)
}

#[test]
fn a_new_database_is_at_schema_3_and_seals_revision_owners() {
    let (dir, dek) = profile();
    let store = Store::open(dir.path(), dek).unwrap();
    assert_eq!(DB_SCHEMA_VERSION, 3);
    assert_eq!(stored_version(dir.path()), "3");
    let ws = workspace(&store);
    let request = request(&store, ws);
    let value = revision(request, &"0".repeat(64));
    let id = id_of(&value);
    store.put(kind::REVISION, &id, Some(&ws), Some(&request), 0.0, &value).unwrap();
    assert_eq!(get(&store, &id).unwrap(), Some(value));
    assert_eq!(left_at_v3(dir.path()), None);
}

#[test]
fn opening_seals_schema_2_revisions_once_under_their_requests_workspace() {
    let (dir, dek) = profile();
    let store = Store::open(dir.path(), dek.clone()).unwrap();
    let (a, b) = (workspace(&store), workspace(&store));
    let request = request(&store, a);
    drop(store);
    set_version(dir.path(), "2");
    let value = revision(request, &"a".repeat(64));
    let id = plant_v1(dir.path(), &dek, &value, Some(a), Some(request));
    let legacy = payload(dir.path(), &id);

    let store = Store::open(dir.path(), dek.clone()).unwrap();
    assert_eq!(stored_version(dir.path()), DB_SCHEMA_VERSION.to_string());
    assert_ne!(payload(dir.path(), &id), legacy, "the revision is sealed again");
    assert_eq!(get(&store, &id).unwrap(), Some(value.clone()));
    assert_eq!(store.list::<Value>(kind::REVISION, Some(&a)).unwrap(), vec![value.clone()]);
    assert_eq!(left_at_v3(dir.path()), None);
    drop(store);

    // Run once: opening again leaves the sealed row as it is.
    let sealed = payload(dir.path(), &id);
    let store = Store::open(dir.path(), dek).unwrap();
    assert_eq!(payload(dir.path(), &id), sealed);
    assert_eq!(get(&store, &id).unwrap(), Some(value));

    // The owner is now sealed: under another workspace index it does not open.
    set_owner_index(dir.path(), kind::REVISION, &id, &b);
    assert!(matches!(get(&store, &id), Err(StoreError::Integrity)));
    assert!(matches!(store.list::<Value>(kind::REVISION, Some(&b)), Err(StoreError::Integrity)));
}

#[test]
fn unlocking_seals_schema_2_revisions() {
    let (dir, dek) = profile();
    let store = Store::open(dir.path(), dek.clone()).unwrap();
    let ws = workspace(&store);
    let request = request(&store, ws);
    store.lock();
    set_version(dir.path(), "2");
    let value = revision(request, &"b".repeat(64));
    let id = plant_v1(dir.path(), &dek, &value, Some(ws), Some(request));
    let legacy = payload(dir.path(), &id);

    store.unlock(dek).unwrap();
    assert_eq!(stored_version(dir.path()), DB_SCHEMA_VERSION.to_string());
    assert_ne!(payload(dir.path(), &id), legacy);
    assert_eq!(get(&store, &id).unwrap(), Some(value));
}

#[test]
fn a_schema_1_database_is_migrated_through_every_step() {
    let (dir, dek) = profile();
    let store = Store::open(dir.path(), dek.clone()).unwrap();
    let ws = workspace(&store);
    let request = request(&store, ws);
    drop(store);
    set_version(dir.path(), "1");
    let value = revision(request, &"1".repeat(64));
    let id = plant_v1(dir.path(), &dek, &value, Some(ws), Some(request));
    // A vault secret as schema 1 sealed it, which the v2 step re-seals first.
    let secret = Id::new();
    let json = serde_json::to_vec(&json!({"label": "legacy", "value": "v1-secret"})).unwrap();
    let env = crypto::seal(&dek, format!("anvil/v1/secrets/secret/{secret}").as_bytes(), &json);
    let sql = "INSERT INTO secrets(id,workspace_id,updated_at,payload) VALUES(?1,?2,0,?3)";
    db(dir.path()).execute(sql, params![secret.to_string(), ws.to_string(), env]).unwrap();

    let store = Store::open(dir.path(), dek).unwrap();
    assert_eq!(stored_version(dir.path()), DB_SCHEMA_VERSION.to_string());
    assert_eq!(store.get_workspace_secret(&secret, &ws).unwrap().unwrap().1.as_str(), "v1-secret");
    assert_eq!(get(&store, &id).unwrap(), Some(value));
}

#[test]
fn a_restored_schema_2_checkpoint_is_sealed() {
    let (dir, dek) = profile();
    let store = Store::open(dir.path(), dek.clone()).unwrap();
    let ws = workspace(&store);
    let request = request(&store, ws);
    drop(store);
    set_version(dir.path(), "2");
    let value = revision(request, &"2".repeat(64));
    let id = plant_v1(dir.path(), &dek, &value, Some(ws), Some(request));
    let legacy = payload(dir.path(), &id);
    // A copy of the schema 2 database, as a checkpoint taken by an earlier build.
    let checkpoint = dir.path().join("schema-2.db");
    db(dir.path()).execute("VACUUM INTO ?1", params![checkpoint.display().to_string()]).unwrap();

    let store = Store::open(dir.path(), dek).unwrap();
    store.delete(kind::REVISION, &id).unwrap();
    store.restore_checkpoint(&checkpoint).unwrap();
    assert_eq!(stored_version(dir.path()), DB_SCHEMA_VERSION.to_string());
    assert_ne!(payload(dir.path(), &id), legacy);
    assert_eq!(get(&store, &id).unwrap(), Some(value));
}

#[test]
fn revisions_whose_request_does_not_authenticate_are_left_as_they_were_and_never_adopted() {
    let (dir, dek) = profile();
    let store = Store::open(dir.path(), dek.clone()).unwrap();
    let (a, b) = (workspace(&store), workspace(&store));
    let live = request(&store, a);
    let corrupt = request(&store, a);
    let edited = request(&store, a);
    drop(store);
    set_version(dir.path(), "2");
    db(dir.path()).execute("UPDATE objects SET payload=x'00' WHERE kind='request' AND id=?1", params![corrupt.to_string()]).unwrap();
    set_owner_index(dir.path(), kind::REQUEST, &edited, &b);

    let good = revision(live, &"d".repeat(64));
    let good_id = plant_v1(dir.path(), &dek, &good, Some(a), Some(live));
    let deleted = Id::new();
    let orphan_sha = "c".repeat(64);
    let orphan = plant_v1(dir.path(), &dek, &revision(deleted, &orphan_sha), Some(a), Some(deleted));
    let foreign_id = Id::new();
    plant_v1_as(dir.path(), &dek, foreign_id, &revision(live, &"e".repeat(64)), Some(a), Some(live));
    let left = [
        // Its request was deleted: no workspace can be established for it.
        orphan,
        // Its request does not decrypt.
        plant_v1(dir.path(), &dek, &revision(corrupt, &"e".repeat(64)), Some(a), Some(corrupt)),
        // Its request's owner index was edited.
        plant_v1(dir.path(), &dek, &revision(edited, &"e".repeat(64)), Some(b), Some(edited)),
        // Indexed under a workspace its request does not belong to.
        plant_v1(dir.path(), &dek, &revision(live, &"e".repeat(64)), Some(b), Some(live)),
        // Indexed under another request than the one it seals.
        plant_v1(dir.path(), &dek, &revision(live, &"e".repeat(64)), Some(a), Some(corrupt)),
        // Sealed with another revision's id.
        foreign_id,
    ];
    let before: Vec<Vec<u8>> = left.iter().map(|id| payload(dir.path(), id)).collect();

    let store = Store::open(dir.path(), dek.clone()).unwrap();
    assert_eq!(stored_version(dir.path()), DB_SCHEMA_VERSION.to_string());
    assert_eq!(get(&store, &good_id).unwrap(), Some(good));
    assert_eq!(left_at_v3(dir.path()).as_deref(), Some("6"));
    let after: Vec<Vec<u8>> = left.iter().map(|id| payload(dir.path(), id)).collect();
    assert_eq!(after, before, "every other revision is left exactly as it was");
    for id in &left {
        assert!(matches!(get(&store, id), Err(StoreError::Integrity)), "{id}");
    }
    assert!(matches!(store.list::<Value>(kind::REVISION, Some(&a)), Err(StoreError::Integrity)));
    // The orphan's files stay accounted for, without exposing its spec.
    let refs = store.read_consistently(|r| r.orphan_revision_attachment_refs_for_retention(&orphan)).unwrap();
    assert_eq!(refs, Some(HashSet::from([orphan_sha])));
    drop(store);

    // Repairing the indexes later does not adopt a revision left behind.
    set_owner_index(dir.path(), kind::REQUEST, &edited, &a);
    set_owner_index(dir.path(), kind::REVISION, &left[3], &a);
    let store = Store::open(dir.path(), dek).unwrap();
    assert_eq!(left.iter().map(|id| payload(dir.path(), id)).collect::<Vec<_>>(), before);
    assert!(matches!(get(&store, &left[2]), Err(StoreError::Integrity)));
    assert!(matches!(get(&store, &left[3]), Err(StoreError::Integrity)));
    // Each can be deleted; the migration does not run again.
    for id in &left {
        assert!(store.delete(kind::REVISION, id).unwrap());
    }
    assert_eq!(store.list::<Value>(kind::REVISION, Some(&a)).unwrap().len(), 1);
    assert_eq!(left_at_v3(dir.path()).as_deref(), Some("6"));
}

#[test]
fn a_migration_that_leaves_no_revision_removes_an_earlier_count() {
    let (dir, dek) = profile();
    let store = Store::open(dir.path(), dek.clone()).unwrap();
    let ws = workspace(&store);
    let request = request(&store, ws);
    drop(store);
    set_version(dir.path(), "2");
    db(dir.path()).execute("INSERT INTO meta(key, value) VALUES('revisions_left_at_v3', '3')", []).unwrap();
    let value = revision(request, &"f".repeat(64));
    let id = plant_v1(dir.path(), &dek, &value, Some(ws), Some(request));

    let store = Store::open(dir.path(), dek).unwrap();
    assert_eq!(get(&store, &id).unwrap(), Some(value));
    assert_eq!(left_at_v3(dir.path()), None);
}

#[test]
fn a_wrong_key_fails_before_the_revision_migration_and_changes_nothing() {
    let (dir, dek) = profile();
    let store = Store::open(dir.path(), dek.clone()).unwrap();
    let ws = workspace(&store);
    let request = request(&store, ws);
    store.lock();
    set_version(dir.path(), "2");
    let id = plant_v1(dir.path(), &dek, &revision(request, &"9".repeat(64)), Some(ws), Some(request));
    let before = payload(dir.path(), &id);

    assert!(matches!(Store::open(dir.path(), Key::random()), Err(StoreError::Integrity)));
    assert!(matches!(store.unlock(Key::random()), Err(StoreError::Integrity)));
    assert!(store.is_locked(), "a wrong key leaves the store locked");
    assert_eq!(stored_version(dir.path()), "2");
    assert_eq!(payload(dir.path(), &id), before);
    assert_eq!(left_at_v3(dir.path()), None);
}

#[test]
fn a_schema_3_revision_in_a_database_set_back_to_schema_2_fails_the_migration_and_changes_nothing() {
    let (dir, dek) = profile();
    let store = Store::open(dir.path(), dek.clone()).unwrap();
    let (a, b) = (workspace(&store), workspace(&store));
    let request_a = request(&store, a);
    let request_b = request(&store, b);
    let value = revision(request_a, &"3".repeat(64));
    let genuine = id_of(&value);
    store.put(kind::REVISION, &genuine, Some(&a), Some(&request_a), 0.0, &value).unwrap();
    store.lock();
    // The version set back, and a revision from an older copy of the database
    // put back under workspace `b`'s request.
    set_version(dir.path(), "2");
    let planted = plant_v1(dir.path(), &dek, &revision(request_b, &"4".repeat(64)), Some(b), Some(request_b));
    let before = (payload(dir.path(), &genuine), payload(dir.path(), &planted));

    assert!(matches!(store.unlock(dek.clone()), Err(StoreError::Integrity)));
    assert!(store.is_locked(), "a failed migration leaves the store locked");
    assert!(matches!(Store::open(dir.path(), dek), Err(StoreError::Integrity)));
    assert_eq!(stored_version(dir.path()), "2");
    assert_eq!((payload(dir.path(), &genuine), payload(dir.path(), &planted)), before);
    assert_eq!(left_at_v3(dir.path()), None);
}

#[test]
fn a_checkpoint_set_back_to_schema_2_is_refused_before_the_live_database_is_touched() {
    let (dir, dek) = profile();
    let store = Store::open(dir.path(), dek).unwrap();
    let ws = workspace(&store);
    let request = request(&store, ws);
    let value = revision(request, &"5".repeat(64));
    let id = id_of(&value);
    store.put(kind::REVISION, &id, Some(&ws), Some(&request), 0.0, &value).unwrap();
    let checkpoint = store.checkpoint("set-back").unwrap();
    Connection::open(&checkpoint).unwrap().execute("UPDATE meta SET value='2' WHERE key='schema_version'", []).unwrap();
    store.delete(kind::REVISION, &id).unwrap();

    assert!(matches!(store.restore_checkpoint(&checkpoint), Err(StoreError::Integrity)));
    assert!(!store.is_locked(), "a refused checkpoint leaves the store unlocked");
    assert_eq!(stored_version(dir.path()), DB_SCHEMA_VERSION.to_string());
    assert_eq!(get(&store, &id).unwrap(), None, "the live database is as it was");
}
