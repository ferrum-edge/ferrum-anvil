//! A raw SQLite reader does not participate in the profile's advisory fence.
use anvil_domain::Id;
use anvil_storage::{KdfParams, Store, rotation, store::DB_FILE, vault};
use rusqlite::Connection;

#[test]
fn external_reader_keeps_rotation_cleanup_pending_until_the_next_scrub() {
    let dir = tempfile::tempdir().unwrap();
    let created = vault::create_enrolled_passphrase_profile(dir.path(), "test", "original", KdfParams::testing()).unwrap();
    let store = Store::open(dir.path(), created.dek).unwrap();
    let id = Id::new();
    store.put_secret(&id, None, "label", "value").unwrap();
    let old_sidecar = std::fs::read(dir.path().join("profile.json")).unwrap();
    let reader = Connection::open(dir.path().join(DB_FILE)).unwrap();
    reader.execute_batch("BEGIN DEFERRED").unwrap();
    let _: i64 = reader.query_row("SELECT COUNT(*) FROM secrets", [], |r| r.get(0)).unwrap();
    let recovery = vault::RotationRecoveryKey::generate();
    store.rotate_data_key("replacement", &recovery, KdfParams::testing(), |_, _, _, binding| Ok(binding.flatten())).unwrap();
    let header = vault::read_header(dir.path()).unwrap();
    let key = vault::unlock_with_passphrase(&header, "replacement").unwrap();
    // Rotation committed, but the busy checkpoint must not publish its
    // completion marker or lose the retry signal.
    assert_eq!(std::fs::read(dir.path().join("profile.json")).unwrap(), old_sidecar);
    let wal = dir.path().join(format!("{DB_FILE}-wal"));
    assert!(std::fs::metadata(&wal).unwrap().len() > 0);
    reader.execute_batch("ROLLBACK").unwrap();
    rotation::scrub_superseded(dir.path(), &key).unwrap();
    assert_eq!(std::fs::metadata(&wal).map(|m| m.len()).unwrap_or(0), 0);
    let sidecar: vault::ProfileHeader = serde_json::from_slice(&std::fs::read(dir.path().join("profile.json")).unwrap()).unwrap();
    assert_eq!(sidecar.key_check, header.key_check);
    assert_ne!(std::fs::read(dir.path().join("profile.json")).unwrap(), old_sidecar);
    let reopened = Store::open(dir.path(), key).unwrap();
    assert_eq!(reopened.get_secret(&id).unwrap().unwrap().1.as_str(), "value");
}
