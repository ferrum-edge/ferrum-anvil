//! Storage security tests: plaintext-leak audit of every file the store
//! writes, backend lock enforcement, key binding and schema guards.

use anvil_domain::Id;
use anvil_storage::store::StoreError;
use anvil_storage::{KdfParams, Key, Store, kind, vault};

const PLANTED: &[&str] =
    &["PLANTED-TOKEN-8d2f1c", "https://internal.corp.example/private/path", "hunter2-password-literal", "BODY-SECRET-77aa"];

fn all_bytes(dir: &std::path::Path) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    for e in walk(dir) {
        if let Ok(b) = std::fs::read(&e) {
            out.push((e.display().to_string(), b));
        }
    }
    out
}

fn walk(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut v = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                v.extend(walk(&p));
            } else {
                v.push(p);
            }
        }
    }
    v
}

#[test]
fn plaintext_leak_audit_db_wal_checkpoints() {
    let dir = tempfile::tempdir().unwrap();
    let created = vault::create_passphrase_profile(dir.path(), "auditor", "pw", KdfParams::testing()).unwrap();
    let store = Store::open(dir.path(), created.dek.clone()).unwrap();
    let ws = Id::new();
    let req = serde_json::json!({"url": PLANTED[1], "headers": [["Authorization", format!("Bearer {}", PLANTED[0])]], "body": PLANTED[3]});
    store.put(kind::REQUEST, &Id::new(), Some(&ws), None, 1.0, &req).unwrap();
    store.put_secret(&Id::new(), Some(&ws), "db password", PLANTED[2]).unwrap();
    store.add_history(&Id::new(), Some(&ws), None, 1, &req, Some(format!("response containing {}", PLANTED[3]).as_bytes())).unwrap();
    store.put_blob(PLANTED[0].as_bytes()).unwrap();
    store.checkpoint("audit").unwrap();
    // Force WAL content to exist on disk before scanning.
    for (path, bytes) in all_bytes(dir.path()) {
        for p in PLANTED {
            let hay = String::from_utf8_lossy(&bytes);
            assert!(!hay.contains(p), "plaintext {p:?} found in {path}");
        }
    }
    // Header never contains the passphrase.
    let header = std::fs::read_to_string(dir.path().join("profile.json")).unwrap();
    assert!(!header.contains("\"pw\""));
}

#[test]
fn data_015_backend_rejects_every_operation_while_locked() {
    let dir = tempfile::tempdir().unwrap();
    let created = vault::create_passphrase_profile(dir.path(), "t", "pw", KdfParams::testing()).unwrap();
    let store = Store::open(dir.path(), created.dek.clone()).unwrap();
    let id = Id::new();
    store.put(kind::WORKSPACE, &id, None, None, 0.0, &serde_json::json!({"name": "w"})).unwrap();
    store.lock();
    assert!(matches!(store.get::<serde_json::Value>(kind::WORKSPACE, &id), Err(StoreError::Locked)));
    assert!(matches!(store.list::<serde_json::Value>(kind::WORKSPACE, None), Err(StoreError::Locked)));
    assert!(matches!(store.put(kind::WORKSPACE, &Id::new(), None, None, 0.0, &1), Err(StoreError::Locked)));
    assert!(matches!(store.get_secret(&id), Err(StoreError::Locked)));
    assert!(matches!(store.list_history(None, None, 10), Err(StoreError::Locked)));
    // Unlock with the recovery key restores access.
    let h = vault::read_header(dir.path()).unwrap();
    let k = vault::unlock_with_recovery(&h, created.recovery_key.as_ref().unwrap()).unwrap();
    store.unlock(k).unwrap();
    assert!(store.get::<serde_json::Value>(kind::WORKSPACE, &id).unwrap().is_some());
}

#[test]
fn wrong_key_is_refused_and_does_not_unlock() {
    let dir = tempfile::tempdir().unwrap();
    let created = vault::create_passphrase_profile(dir.path(), "t", "pw", KdfParams::testing()).unwrap();
    drop(Store::open(dir.path(), created.dek.clone()).unwrap());
    assert!(matches!(Store::open(dir.path(), Key::random()), Err(StoreError::Integrity)));
    let s = Store::open(dir.path(), created.dek.clone()).unwrap();
    s.lock();
    assert!(s.unlock(Key::random()).is_err());
    assert!(s.is_locked(), "a failed unlock leaves the store locked");
}

#[test]
fn rel_004_future_schema_is_refused_without_mutation() {
    let dir = tempfile::tempdir().unwrap();
    let created = vault::create_passphrase_profile(dir.path(), "t", "pw", KdfParams::testing()).unwrap();
    drop(Store::open(dir.path(), created.dek.clone()).unwrap());
    let conn = rusqlite::Connection::open(dir.path().join("anvil.db")).unwrap();
    conn.execute("UPDATE meta SET value='999' WHERE key='schema_version'", []).unwrap();
    drop(conn);
    match Store::open(dir.path(), created.dek.clone()) {
        Err(StoreError::FutureSchema { found: 999, .. }) => {}
        other => panic!("expected FutureSchema, got {:?}", other.err()),
    }
}

#[test]
fn atomic_sections_roll_back_on_error() {
    let dir = tempfile::tempdir().unwrap();
    let created = vault::create_passphrase_profile(dir.path(), "t", "pw", KdfParams::testing()).unwrap();
    let store = Store::open(dir.path(), created.dek.clone()).unwrap();
    let r: Result<(), StoreError> = store.atomically(|s| {
        s.put(kind::WORKSPACE, &Id::new(), None, None, 0.0, &serde_json::json!({"n": 1}))?;
        Err(StoreError::NotFound("simulated failure mid-import".into()))
    });
    assert!(r.is_err());
    assert!(store.list::<serde_json::Value>(kind::WORKSPACE, None).unwrap().is_empty(), "partial writes were rolled back");
}

#[test]
fn history_retention_prunes_by_size() {
    let dir = tempfile::tempdir().unwrap();
    let created = vault::create_passphrase_profile(dir.path(), "t", "pw", KdfParams::testing()).unwrap();
    let store = Store::open(dir.path(), created.dek.clone()).unwrap();
    let now = chrono::Utc::now().timestamp_millis();
    for i in 0..20 {
        store.add_history(&Id::new(), None, None, now + i, &serde_json::json!({"i": i}), Some(&vec![b'x'; 10_000])).unwrap();
    }
    store.prune_history(30, 50_000).unwrap();
    let left = store.list_history(None, None, 100).unwrap();
    assert!(left.len() < 20 && !left.is_empty());
    assert!(left.iter().map(|h| h.size).sum::<i64>() <= 50_000);
}
