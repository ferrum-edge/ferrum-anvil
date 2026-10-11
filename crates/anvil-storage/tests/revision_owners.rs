//! A request revision is sealed together with the workspace and request that
//! own it, and a history record together with the response body it references
//! (schema 3). Rows sealed before that are sealed again once, in one
//! transaction, when the store is opened or unlocked or a checkpoint is
//! restored: a revision under the workspace of its authenticated request, a
//! history record with the body its row references then. A revision whose
//! request does not authenticate, or a history record that does not open
//! under its owner, is left exactly as it was and stays refused: it is never
//! adopted. A checkpoint of the database is taken before it is sealed again.

use anvil_domain::Id;
use anvil_domain::request::RequestSpec;
use anvil_storage::store::{DB_FILE, DB_SCHEMA_VERSION};
use anvil_storage::{KdfParams, Key, Store, StoreError, crypto, kind, vault};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

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

fn meta(dir: &Path, key: &str) -> Option<String> {
    db(dir).query_row("SELECT value FROM meta WHERE key=?1", params![key], |r| r.get(0)).optional().unwrap()
}

fn left_at_v3(dir: &Path) -> Option<String> {
    meta(dir, "revisions_left_at_v3")
}

fn payload(dir: &Path, id: &Id) -> Vec<u8> {
    db(dir).query_row("SELECT payload FROM objects WHERE kind='revision' AND id=?1", params![id.to_string()], |r| r.get(0)).unwrap()
}

fn history_payload(dir: &Path, id: &Id) -> Vec<u8> {
    db(dir).query_row("SELECT payload FROM history WHERE id=?1", params![id.to_string()], |r| r.get(0)).unwrap()
}

/// The checkpoints taken in the profile in `dir`.
fn checkpoints(dir: &Path) -> Vec<PathBuf> {
    match std::fs::read_dir(dir.join("checkpoints")) {
        Ok(entries) => entries.map(|e| e.unwrap().path()).filter(|p| p.extension().is_some_and(|x| x == "db")).collect(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => panic!("{e}"),
    }
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

/// A history row stored as `id`, as schema 2 and earlier sealed it: bound to
/// its id only, with the indexes and body given.
fn plant_v1_history(dir: &Path, key: &Key, id: Id, record: &Value, owner: Option<Id>, request: Option<Id>, body: Option<&str>) {
    let env = crypto::seal(key, format!("anvil/v1/history/record/{id}").as_bytes(), &serde_json::to_vec(record).unwrap());
    let sql = "INSERT INTO history(id,workspace_id,request_id,started_at,size,body_blob,payload) VALUES(?1,?2,?3,0,0,?4,?5)";
    db(dir).execute(sql, params![id.to_string(), owner.map(|w| w.to_string()), request.map(|r| r.to_string()), body, env]).unwrap();
}

fn get(store: &Store, id: &Id) -> Result<Option<Value>, StoreError> {
    store.get::<Value>(kind::REVISION, id)
}

#[test]
fn a_new_database_is_at_current_schema_and_seals_revision_owners() {
    let (dir, dek) = profile();
    let store = Store::open(dir.path(), dek).unwrap();
    assert_eq!(DB_SCHEMA_VERSION, 5);
    assert_eq!(stored_version(dir.path()), DB_SCHEMA_VERSION.to_string());
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
    assert!(checkpoints(dir.path()).is_empty(), "no checkpoint is taken with a wrong key");
}

#[test]
fn a_schema_3_revision_in_a_database_set_back_to_schema_2_fails_the_migration_and_changes_nothing() {
    let (dir, dek) = profile();
    let store = Store::open(dir.path(), dek.clone()).unwrap();
    let (a, b) = (workspace(&store), workspace(&store));
    let request_a = request(&store, a);
    let request_b = request(&store, b);
    // A revision from an older copy of the database put back under workspace
    // `b`'s request, before the genuine one: the step seals it again first,
    // then fails on the genuine one, so its write is rolled back.
    let planted = plant_v1(dir.path(), &dek, &revision(request_b, &"4".repeat(64)), Some(b), Some(request_b));
    let value = revision(request_a, &"3".repeat(64));
    let genuine = id_of(&value);
    store.put(kind::REVISION, &genuine, Some(&a), Some(&request_a), 0.0, &value).unwrap();
    store.lock();
    // The version set back.
    set_version(dir.path(), "2");
    let before = (payload(dir.path(), &genuine), payload(dir.path(), &planted));
    let rowid = |id: &Id| -> i64 {
        let sql = "SELECT rowid FROM objects WHERE kind='revision' AND id=?1";
        db(dir.path()).query_row(sql, params![id.to_string()], |r| r.get(0)).unwrap()
    };
    assert!(rowid(&planted) < rowid(&genuine), "the legacy row is read first");

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

#[test]
fn opening_binds_schema_2_history_records_to_their_body_once() {
    let (dir, dek) = profile();
    let store = Store::open(dir.path(), dek.clone()).unwrap();
    let (a, b) = (workspace(&store), workspace(&store));
    let request = request(&store, a);
    let body = store.put_blob(b"response body").unwrap();
    let other = store.put_blob(b"another body").unwrap();
    drop(store);
    set_version(dir.path(), "2");
    let record = |id: Id| json!({"id": id, "workspace_id": a, "request_id": request, "status": 200});
    let (with_body, without, corrupt, misfiled) = (Id::new(), Id::new(), Id::new(), Id::new());
    plant_v1_history(dir.path(), &dek, with_body, &record(with_body), Some(a), Some(request), Some(body.as_str()));
    plant_v1_history(dir.path(), &dek, without, &record(without), Some(a), Some(request), None);
    // Left as they were: one that does not decrypt, and one filed under
    // another workspace than the one it seals.
    plant_v1_history(dir.path(), &Key::random(), corrupt, &record(corrupt), Some(a), Some(request), None);
    plant_v1_history(dir.path(), &dek, misfiled, &record(misfiled), Some(b), Some(request), Some(body.as_str()));
    let legacy = history_payload(dir.path(), &with_body);
    let left = [corrupt, misfiled];
    let before: Vec<Vec<u8>> = left.iter().map(|id| history_payload(dir.path(), id)).collect();

    let store = Store::open(dir.path(), dek.clone()).unwrap();
    assert_eq!(stored_version(dir.path()), DB_SCHEMA_VERSION.to_string());
    assert_ne!(history_payload(dir.path(), &with_body), legacy, "the record is sealed again");
    let (rec, got) = store.get_history::<Value>(&with_body.to_string()).unwrap().unwrap();
    assert_eq!(rec, record(with_body));
    assert_eq!(got.unwrap().as_slice(), b"response body");
    let (rec, got) = store.get_history::<Value>(&without.to_string()).unwrap().unwrap();
    assert_eq!(rec, record(without));
    assert!(got.is_none());
    assert_eq!(meta(dir.path(), "history_left_at_v3").as_deref(), Some("2"));
    assert_eq!(left.iter().map(|id| history_payload(dir.path(), id)).collect::<Vec<_>>(), before);
    for id in &left {
        assert!(matches!(store.get_history::<Value>(&id.to_string()), Err(StoreError::Integrity)), "{id}");
    }

    // The body is now bound: pointed at another blob, or at none, the record
    // no longer opens.
    let set_body = |id: &Id, body: Option<&str>| {
        db(dir.path()).execute("UPDATE history SET body_blob=?1 WHERE id=?2", params![body, id.to_string()]).unwrap();
    };
    for (id, swapped) in [(&with_body, Some(other.as_str())), (&with_body, None), (&without, Some(body.as_str()))] {
        set_body(id, swapped);
        assert!(matches!(store.get_history::<Value>(&id.to_string()), Err(StoreError::Integrity)), "{id}");
    }
    set_body(&with_body, Some(body.as_str()));
    set_body(&without, None);
    drop(store);

    // Run once: opening again leaves every record as it is.
    let sealed = history_payload(dir.path(), &with_body);
    let store = Store::open(dir.path(), dek).unwrap();
    assert_eq!(history_payload(dir.path(), &with_body), sealed);
    assert_eq!(store.get_history::<Value>(&with_body.to_string()).unwrap().unwrap().0, record(with_body));
    for id in &left {
        db(dir.path()).execute("DELETE FROM history WHERE id=?1", params![id.to_string()]).unwrap();
    }
    assert_eq!(store.list_history(Some(&a), None, 10).unwrap().len(), 2);
}

#[test]
fn a_schema_3_history_record_in_a_database_set_back_to_schema_2_fails_the_migration_and_changes_nothing() {
    let (dir, dek) = profile();
    let store = Store::open(dir.path(), dek.clone()).unwrap();
    let ws = workspace(&store);
    let request = request(&store, ws);
    // A record from an older copy of the database, read before the genuine
    // one: the step seals it again first, then fails on the genuine one.
    let planted = Id::new();
    let record = |id: Id| json!({"id": id, "workspace_id": ws, "request_id": request, "status": 200});
    plant_v1_history(dir.path(), &dek, planted, &record(planted), Some(ws), Some(request), None);
    let genuine = Id::new();
    store.add_history(&genuine, Some(&ws), Some(&request), 1, &record(genuine), Some(b"body".as_slice())).unwrap();
    store.lock();
    set_version(dir.path(), "2");
    let before = (history_payload(dir.path(), &planted), history_payload(dir.path(), &genuine));

    assert!(matches!(store.unlock(dek.clone()), Err(StoreError::Integrity)));
    assert!(store.is_locked(), "a failed migration leaves the store locked");
    assert!(matches!(Store::open(dir.path(), dek), Err(StoreError::Integrity)));
    assert_eq!(stored_version(dir.path()), "2");
    assert_eq!((history_payload(dir.path(), &planted), history_payload(dir.path(), &genuine)), before);
    assert_eq!(meta(dir.path(), "history_left_at_v3"), None);
}

#[test]
fn a_checkpoint_with_a_schema_3_history_record_set_back_to_schema_2_is_refused() {
    let (dir, dek) = profile();
    let store = Store::open(dir.path(), dek).unwrap();
    let ws = workspace(&store);
    let id = Id::new();
    let record = json!({"id": id, "workspace_id": ws, "status": 200});
    store.add_history(&id, Some(&ws), None, 1, &record, Some(b"body".as_slice())).unwrap();
    let checkpoint = store.checkpoint("set-back").unwrap();
    Connection::open(&checkpoint).unwrap().execute("UPDATE meta SET value='2' WHERE key='schema_version'", []).unwrap();
    store.clear_history(None).unwrap();

    assert!(matches!(store.restore_checkpoint(&checkpoint), Err(StoreError::Integrity)));
    assert!(!store.is_locked(), "a refused checkpoint leaves the store unlocked");
    assert!(store.get_history::<Value>(&id.to_string()).unwrap().is_none(), "the live database is as it was");
}

#[test]
fn a_checkpoint_of_the_database_is_taken_before_it_is_sealed_again() {
    let (dir, dek) = profile();
    let store = Store::open(dir.path(), dek.clone()).unwrap();
    assert!(checkpoints(dir.path()).is_empty(), "a new database needs none");
    let ws = workspace(&store);
    let request = request(&store, ws);
    drop(store);
    set_version(dir.path(), "2");
    let value = revision(request, &"6".repeat(64));
    let id = plant_v1(dir.path(), &dek, &value, Some(ws), Some(request));
    let legacy = payload(dir.path(), &id);

    let store = Store::open(dir.path(), dek.clone()).unwrap();
    assert_ne!(payload(dir.path(), &id), legacy);
    let taken = checkpoints(dir.path());
    assert_eq!(taken.len(), 1, "{taken:?}");
    assert!(taken[0].to_string_lossy().ends_with("-before-schema-3.db"), "{taken:?}");
    // It is the database as the earlier build left it.
    {
        let copy = Connection::open(&taken[0]).unwrap();
        let version: String = copy.query_row("SELECT value FROM meta WHERE key='schema_version'", [], |r| r.get(0)).unwrap();
        assert_eq!(version, "2");
        let sql = "SELECT payload FROM objects WHERE kind='revision' AND id=?1";
        let copied: Vec<u8> = copy.query_row(sql, params![id.to_string()], |r| r.get(0)).unwrap();
        assert_eq!(copied, legacy);
    }

    // None is taken once the database is at schema 3, nor by restoring that
    // checkpoint, which is sealed again like an upgrade.
    store.lock();
    store.unlock(dek.clone()).unwrap();
    drop(store);
    let store = Store::open(dir.path(), dek).unwrap();
    store.restore_checkpoint(&taken[0]).unwrap();
    assert_eq!(get(&store, &id).unwrap(), Some(value));
    assert_eq!(checkpoints(dir.path()), taken);
}
