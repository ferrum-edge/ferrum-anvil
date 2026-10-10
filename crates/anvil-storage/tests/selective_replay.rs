//! Raw replay with the CURRENT wrapped header and key canary left intact.
use anvil_domain::Id;
use anvil_storage::store::DB_FILE;
use anvil_storage::{KdfParams, Store, StoreError, kind, vault};
use rusqlite::{Connection, params};
use serde_json::{Value, json};

fn profile() -> (tempfile::TempDir, Store, anvil_storage::Key) {
    let dir = tempfile::tempdir().unwrap();
    let created = vault::create_enrolled_passphrase_profile(dir.path(), "test", "original", KdfParams::testing()).unwrap();
    let store = Store::open(dir.path(), created.dek.clone()).unwrap();
    (dir, store, created.dek)
}
fn workspace(id: Id) -> Value {
    json!({"id":id,"schema_version":anvil_domain::SCHEMA_VERSION,"created_at":chrono::Utc::now(),"updated_at":chrono::Utc::now(),"name":"test"})
}

#[test]
fn deleted_secret_cannot_be_reinserted_under_current_authority() {
    let (dir, store, _) = profile();
    let id = Id::new();
    store.put_secret(&id, None, "label", "historical secret").unwrap();
    let raw = Connection::open(dir.path().join(DB_FILE)).unwrap();
    let payload: Vec<u8> = raw.query_row("SELECT payload FROM secrets WHERE id=?1", [id.to_string()], |r| r.get(0)).unwrap();
    store.delete_secret(&id).unwrap();
    raw.execute("INSERT INTO secrets(id,workspace_id,updated_at,payload) VALUES(?1,NULL,0,?2)", params![id.to_string(), payload]).unwrap();
    assert!(matches!(store.get_secret(&id), Err(StoreError::Integrity)));
    assert!(store.list_secret_ids(None).is_err());
}

#[test]
fn authentic_older_value_and_missing_deny_record_fail_closed() {
    let (dir, store, _) = profile();
    let id = Id::new();
    store.put_secret(&id, None, "label", "old").unwrap();
    let raw = Connection::open(dir.path().join(DB_FILE)).unwrap();
    let old: Vec<u8> = raw.query_row("SELECT payload FROM secrets WHERE id=?1", [id.to_string()], |r| r.get(0)).unwrap();
    store.put_secret(&id, None, "label", "replacement").unwrap();
    raw.execute("UPDATE secrets SET payload=?1 WHERE id=?2", params![old, id.to_string()]).unwrap();
    // An unrelated authorized write must not bless the replayed row.
    store.put_secret(&Id::new(), None, "other", "unrelated").unwrap();
    assert!(matches!(store.get_secret(&id), Err(StoreError::Integrity)));
    let ws = Id::new();
    store.put(kind::WORKSPACE, &ws, None, None, 0.0, &workspace(ws)).unwrap();
    store.put(kind::DEVICE_IDENTITY_SEAL, &ws, Some(&ws), None, 0.0, &json!({"workspace_id":ws,"sealed_at":chrono::Utc::now()})).unwrap();
    raw.execute("DELETE FROM objects WHERE kind=?1 AND id=?2", params![kind::DEVICE_IDENTITY_SEAL, ws.to_string()]).unwrap();
    assert!(matches!(store.get::<Value>(kind::DEVICE_IDENTITY_SEAL, &ws), Err(StoreError::Integrity)));
    assert!(store.list::<Value>(kind::DEVICE_IDENTITY_SEAL, Some(&ws)).is_err());
}

#[test]
fn rollback_and_multi_connection_writes_keep_catalogue_atomic() {
    let (dir, store, key) = profile();
    let second = Store::open(dir.path(), key).unwrap();
    let id = Id::new();
    store.put_secret(&id, None, "label", "before").unwrap();
    let result: Result<(), StoreError> = store.atomically(|tx| {
        tx.put_secret(&id, None, "label", "rolled back")?;
        assert_eq!(tx.get_secret(&id)?.unwrap().1.as_str(), "rolled back");
        Err(StoreError::NotFound("injected".into()))
    });
    assert!(result.is_err());
    assert_eq!(second.get_secret(&id).unwrap().unwrap().1.as_str(), "before");
    second.put_secret(&id, None, "label", "committed").unwrap();
    assert_eq!(store.get_secret(&id).unwrap().unwrap().1.as_str(), "committed");
}

#[test]
fn deliberate_checkpoint_restore_rebuilds_current_authority() {
    let (dir, store, _) = profile();
    let id = Id::new();
    store.put_secret(&id, None, "label", "historical").unwrap();
    let checkpoint = store.checkpoint("owner-approved").unwrap();
    store.delete_secret(&id).unwrap();
    let before = vault::read_header(dir.path()).unwrap();
    store.restore_checkpoint(&checkpoint).unwrap();
    let after = vault::read_header(dir.path()).unwrap();
    assert_eq!(before.key_check, after.key_check);
    assert_eq!(before.passphrase_wrap.as_ref().unwrap().envelope, after.passphrase_wrap.as_ref().unwrap().envelope);
    assert_eq!(store.get_secret(&id).unwrap().unwrap().1.as_str(), "historical");
}

#[test]
fn missing_catalogue_is_never_reinitialized_and_rotation_refuses_replay() {
    let (dir, store, key) = profile();
    let id = Id::new();
    store.put_secret(&id, None, "label", "present").unwrap();
    let raw = Connection::open(dir.path().join(DB_FILE)).unwrap();
    raw.execute("DELETE FROM secrets WHERE id=?1", [id.to_string()]).unwrap();
    let recovery = vault::RotationRecoveryKey::generate();
    assert!(store.rotate_data_key("replacement", &recovery, KdfParams::testing(), |_, _, _, binding| Ok(binding.flatten())).is_err());
    raw.execute("DELETE FROM meta WHERE key='protected_records_v1'", []).unwrap();
    assert!(store.get_secret(&id).is_err());
    assert!(Store::open(dir.path(), key).is_err());
}

#[test]
fn altered_index_and_order_cannot_hide_or_reorder_protected_policy() {
    let (dir, store, _) = profile();
    let ws = Id::new();
    store.put(kind::WORKSPACE, &ws, None, None, 0.0, &workspace(ws)).unwrap();
    store.put(kind::DEVICE_IDENTITY_SEAL, &ws, Some(&ws), None, 0.0, &json!({"workspace_id":ws,"sealed_at":chrono::Utc::now()})).unwrap();
    let raw = Connection::open(dir.path().join(DB_FILE)).unwrap();
    raw.execute(
        "UPDATE objects SET workspace_id=?1 WHERE kind=?2 AND id=?3",
        params![Id::new().to_string(), kind::DEVICE_IDENTITY_SEAL, ws.to_string()],
    )
    .unwrap();
    assert!(store.list::<Value>(kind::DEVICE_IDENTITY_SEAL, Some(&ws)).is_err());
    raw.execute("UPDATE objects SET sort_key=99 WHERE kind=?1 AND id=?2", params![kind::WORKSPACE, ws.to_string()]).unwrap();
    assert!(store.get::<Value>(kind::WORKSPACE, &ws).is_err());
    assert!(store.object_meta(kind::WORKSPACE).is_err());
}
