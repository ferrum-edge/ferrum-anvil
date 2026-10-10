use anvil_domain::Id;
use anvil_storage::{KdfParams, Store, StoreError, store::DB_FILE, vault};
use rusqlite::{Connection, params};
use serde_json::json;

fn store() -> (tempfile::TempDir, Store) {
    let dir = tempfile::tempdir().unwrap();
    let created = vault::create_enrolled_passphrase_profile(dir.path(), "test", "original", KdfParams::testing()).unwrap();
    let store = Store::open(dir.path(), created.dek).unwrap();
    (dir, store)
}
fn put(store: &Store, id: &Id, path: &str, order: f64) {
    store.put(anvil_storage::kind::TOKEN_FILE, id, None, None, order, &json!({"id":id,"path":path,"bound_at":chrono::Utc::now()})).unwrap();
}
#[test]
fn point_expectations_survive_unrelated_writes_and_refuse_relevant_reseals() {
    let (_dir, store) = store();
    let id = Id::new();
    put(&store, &id, "selected", 0.0);
    let proof = store
        .read_context(|read| {
            let _: Option<serde_json::Value> = read.get(anvil_storage::kind::TOKEN_FILE, &id)?;
            Ok(read.finish())
        })
        .unwrap();
    let root = store.protected_authority().unwrap();
    put(&store, &Id::new(), "other", 0.0);
    assert_ne!(store.protected_authority().unwrap(), root);
    store.check_context(&proof).unwrap();
    put(&store, &id, "selected", 0.0);
    assert!(matches!(store.check_context(&proof), Err(StoreError::StaleAuthority)));
    assert!(!store.is_locked());
}
#[test]
fn absent_points_and_secret_aliases_are_dependencies_without_plaintext_reads() {
    let (_dir, store) = store();
    let id = Id::new();
    let proof = store
        .read_context(|read| {
            let missing: Option<serde_json::Value> = read.get(anvil_storage::kind::TOKEN_FILE, &id)?;
            assert!(missing.is_none());
            read.depend_secret(&id);
            Ok(read.finish())
        })
        .unwrap();
    store.put_secret(&Id::new(), None, "unused", "not captured").unwrap();
    store.check_context(&proof).unwrap();
    store.put_secret(&id, None, "selected", "replacement").unwrap();
    assert!(matches!(store.check_context(&proof), Err(StoreError::StaleAuthority)));
    store.delete_secret(&id).unwrap();
    store.check_context(&proof).unwrap();
    put(&store, &id, "appeared", 0.0);
    assert!(matches!(store.check_context(&proof), Err(StoreError::StaleAuthority)));
}
#[test]
fn filtered_queries_cover_empty_membership_duplicates_and_repointing() {
    let (_dir, store) = store();
    let fields = vec![("/path".into(), json!("selected"))];
    let capture = || {
        store
            .read_context(|read| {
                let _: Vec<serde_json::Value> = read.query(anvil_storage::kind::TOKEN_FILE, None, &fields)?;
                Ok(read.finish())
            })
            .unwrap()
    };
    let empty = capture();
    put(&store, &Id::new(), "other", 0.0);
    store.check_context(&empty).unwrap();
    let id = Id::new();
    put(&store, &id, "selected", 0.0);
    assert!(matches!(store.check_context(&empty), Err(StoreError::StaleAuthority)));
    let positive = capture();
    let duplicate = Id::new();
    put(&store, &duplicate, "selected", 0.0);
    assert!(matches!(store.check_context(&positive), Err(StoreError::StaleAuthority)));
    store.delete(anvil_storage::kind::TOKEN_FILE, &duplicate).unwrap();
    store.check_context(&positive).unwrap();
    put(&store, &id, "other", 0.0);
    assert!(matches!(store.check_context(&positive), Err(StoreError::StaleAuthority)));
}
#[test]
fn ordered_candidate_query_covers_shadowing_reordering_and_removal() {
    let (_dir, store) = store();
    let first = Id::new();
    let second = Id::new();
    put(&store, &first, "first", 0.0);
    put(&store, &second, "second", 1.0);
    let proof = store
        .read_context(|read| {
            let _: Vec<serde_json::Value> = read.query(anvil_storage::kind::TOKEN_FILE, None, &[])?;
            Ok(read.finish())
        })
        .unwrap();
    put(&store, &second, "second", -1.0);
    assert!(matches!(store.check_context(&proof), Err(StoreError::StaleAuthority)));
}
#[test]
fn unrelated_raw_tampering_still_locks_the_whole_profile() {
    let (dir, store) = store();
    let selected = Id::new();
    let other = Id::new();
    put(&store, &selected, "selected", 0.0);
    put(&store, &other, "other", 0.0);
    let proof = store
        .read_context(|read| {
            read.depend_object(anvil_storage::kind::TOKEN_FILE, &selected);
            Ok(read.finish())
        })
        .unwrap();
    let raw = Connection::open(dir.path().join(DB_FILE)).unwrap();
    raw.execute("DELETE FROM objects WHERE kind=?1 AND id=?2", params![anvil_storage::kind::TOKEN_FILE, other.to_string()]).unwrap();
    assert!(matches!(store.check_context(&proof), Err(StoreError::Integrity)));
    assert!(store.is_locked());
}
#[test]
fn captured_inputs_and_proof_share_one_snapshot_during_a_concurrent_write() {
    use std::sync::{Arc, mpsc};
    let (_dir, store) = store();
    let store = Arc::new(store);
    let id = Id::new();
    put(&store, &id, "original", 0.0);
    let (started_tx, started_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    let writer_store = store.clone();
    let writer = std::thread::spawn(move || {
        started_rx.recv().unwrap();
        put(&writer_store, &id, "replacement", 0.0);
        done_tx.send(()).unwrap();
    });
    let proof = store
        .read_context(|read| {
            let value: serde_json::Value = read.get(anvil_storage::kind::TOKEN_FILE, &id)?.unwrap();
            started_tx.send(()).unwrap();
            assert_eq!(value["path"], "original");
            assert!(done_rx.try_recv().is_err());
            Ok(read.finish())
        })
        .unwrap();
    writer.join().unwrap();
    assert!(matches!(store.check_context(&proof), Err(StoreError::StaleAuthority)));
}
