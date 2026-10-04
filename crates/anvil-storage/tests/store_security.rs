//! Storage security tests: plaintext-leak audit of every file the store
//! writes, backend lock enforcement, key binding and schema guards.

use anvil_domain::Id;
use anvil_storage::store::{DB_SCHEMA_VERSION, StoreError};
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

fn workspace(id: &Id, name: &str) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "schema_version": anvil_domain::SCHEMA_VERSION,
        "created_at": chrono::Utc::now(),
        "updated_at": chrono::Utc::now(),
        "name": name,
    })
}

#[test]
fn plaintext_leak_audit_db_wal_checkpoints() {
    let dir = tempfile::tempdir().unwrap();
    let created = vault::create_passphrase_profile(dir.path(), "auditor", "pw", KdfParams::testing()).unwrap();
    let store = Store::open(dir.path(), created.dek.clone()).unwrap();
    let ws = Id::new();
    store.put(kind::WORKSPACE, &ws, None, None, 0.0, &workspace(&ws, "audit")).unwrap();
    let id = Id::new();
    let mut spec = anvil_domain::request::RequestSpec::http("GET", PLANTED[1]);
    spec.headers.push(anvil_domain::request::KeyValue::new(
        "Authorization",
        format!("Bearer {}", PLANTED[0]),
    ));
    spec.body = anvil_domain::request::Body::Raw {
        text: PLANTED[3].into(),
        content_type: None,
    };
    let req = serde_json::json!({
        "id": id,
        "schema_version": anvil_domain::SCHEMA_VERSION,
        "created_at": chrono::Utc::now(),
        "updated_at": chrono::Utc::now(),
        "workspace_id": ws,
        "name": PLANTED[3],
        "description": PLANTED[0],
        "sort_key": 1.0,
        "spec": spec,
    });
    store.put(kind::REQUEST, &id, Some(&ws), None, 1.0, &req).unwrap();
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
    store.put(kind::WORKSPACE, &id, None, None, 0.0, &workspace(&id, "w")).unwrap();
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
fn an_unlock_whose_gate_refuses_never_sets_the_key() {
    let dir = tempfile::tempdir().unwrap();
    let created = vault::create_passphrase_profile(dir.path(), "t", "pw", KdfParams::testing()).unwrap();
    let s = Store::open(dir.path(), created.dek.clone()).unwrap();
    let id = Id::new();
    s.put(kind::WORKSPACE, &id, None, None, 0.0, &workspace(&id, "w")).unwrap();
    s.lock();
    // A gate that refuses, as for a lock that landed during the unlock.
    assert!(matches!(s.unlock_if(created.dek.clone(), || false), Err(StoreError::Locked)));
    assert!(s.is_locked());
    assert!(matches!(s.get::<serde_json::Value>(kind::WORKSPACE, &id), Err(StoreError::Locked)));
    s.unlock_if(created.dek.clone(), || true).unwrap();
    assert!(s.get::<serde_json::Value>(kind::WORKSPACE, &id).unwrap().is_some());
}

#[test]
fn an_unlock_whose_gate_refuses_never_clears_a_newer_key() {
    let dir = tempfile::tempdir().unwrap();
    let created = vault::create_passphrase_profile(dir.path(), "t", "pw", KdfParams::testing()).unwrap();
    let s = Store::open(dir.path(), created.dek.clone()).unwrap();
    let id = Id::new();
    s.put(kind::WORKSPACE, &id, None, None, 0.0, &workspace(&id, "w")).unwrap();
    // The key is set, as by a newer unlock that its own gate allowed after the
    // lock that makes this older one refuse.
    assert!(matches!(s.unlock_if(created.dek.clone(), || false), Err(StoreError::Locked)));
    assert!(!s.is_locked(), "a refused unlock leaves the newer unlock's key in place");
    assert!(s.get::<serde_json::Value>(kind::WORKSPACE, &id).unwrap().is_some());
    // A wrong key still leaves the store locked.
    assert!(s.unlock_if(Key::random(), || true).is_err());
    assert!(s.is_locked());
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
        let id = Id::new();
        s.put(kind::WORKSPACE, &id, None, None, 0.0, &workspace(&id, "rolled back"))?;
        Err(StoreError::NotFound("simulated failure mid-import".into()))
    });
    assert!(r.is_err());
    assert!(store.list::<serde_json::Value>(kind::WORKSPACE, None).unwrap().is_empty(), "partial writes were rolled back");
}

#[test]
fn blobs_written_in_a_transaction_roll_back_with_it() {
    let dir = tempfile::tempdir().unwrap();
    let created = vault::create_passphrase_profile(dir.path(), "t", "pw", KdfParams::testing()).unwrap();
    let store = Store::open(dir.path(), created.dek.clone()).unwrap();
    let mut blob = String::new();
    let r: Result<(), StoreError> = store.atomically(|s| {
        blob = s.put_blob(b"rolled back")?;
        s.pin_blob(&blob)?;
        Err(StoreError::NotFound("simulated failure mid-import".into()))
    });
    assert!(r.is_err());
    assert!(store.get_blob(&blob).unwrap().is_none(), "the blob was rolled back");

    let kept = store
        .atomically(|s| {
            let id = s.put_blob(b"committed")?;
            s.pin_blob(&id)?;
            Ok(id)
        })
        .unwrap();
    assert_eq!(store.get_blob(&kept).unwrap().unwrap().as_slice(), b"committed");
    // Same content, same id, inside or outside a transaction.
    assert_eq!(store.put_blob(b"committed").unwrap(), kept);
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

#[test]
fn replacing_a_history_record_releases_its_old_body() {
    let dir = tempfile::tempdir().unwrap();
    let created = vault::create_passphrase_profile(dir.path(), "t", "pw", KdfParams::testing()).unwrap();
    let store = Store::open(dir.path(), created.dek.clone()).unwrap();
    let body_of = |id: &Id| -> Option<String> {
        let conn = rusqlite::Connection::open(dir.path().join("anvil.db")).unwrap();
        conn.query_row("SELECT body_blob FROM history WHERE id=?1", [id.to_string()], |r| r.get(0)).unwrap()
    };
    let record = serde_json::json!({"n": 1});
    let (replaced, shared, other) = (Id::new(), Id::new(), Id::new());
    store.add_history(&replaced, None, None, 1, &record, Some(b"old body")).unwrap();
    let old = body_of(&replaced).unwrap();
    store.add_history(&replaced, None, None, 1, &record, None).unwrap();
    assert!(body_of(&replaced).is_none());
    assert!(store.get_blob(&old).unwrap().is_none(), "the replaced body was released");

    // A body another record still uses stays.
    store.add_history(&shared, None, None, 1, &record, Some(b"shared body")).unwrap();
    store.add_history(&other, None, None, 1, &record, Some(b"shared body")).unwrap();
    let shared_body = body_of(&shared).unwrap();
    store.add_history(&shared, None, None, 1, &record, None).unwrap();
    assert!(store.get_blob(&shared_body).unwrap().is_some(), "another record uses it");

    // A pinned attachment with the same content stays; the last use of the
    // shared body goes.
    let pinned = store.put_blob(b"attachment").unwrap();
    store.pin_blob(&pinned).unwrap();
    store.add_history(&other, None, None, 1, &record, Some(b"attachment")).unwrap();
    assert!(store.get_blob(&shared_body).unwrap().is_none(), "no record uses it any more");
    store.add_history(&other, None, None, 1, &record, None).unwrap();
    assert_eq!(store.get_blob(&pinned).unwrap().unwrap().as_slice(), b"attachment");
}

#[test]
fn replacing_a_history_record_with_the_same_body_keeps_it() {
    let dir = tempfile::tempdir().unwrap();
    let created = vault::create_passphrase_profile(dir.path(), "t", "pw", KdfParams::testing()).unwrap();
    let store = Store::open(dir.path(), created.dek.clone()).unwrap();
    let id = Id::new();
    store.add_history(&id, None, None, 1, &serde_json::json!({"n": 1}), Some(b"same body")).unwrap();
    store.add_history(&id, None, None, 2, &serde_json::json!({"n": 2}), Some(b"same body")).unwrap();
    let (record, body) = store.get_history::<serde_json::Value>(&id.to_string()).unwrap().unwrap();
    assert_eq!(record, serde_json::json!({"n": 2}));
    assert_eq!(body.expect("the body is kept").as_slice(), b"same body");
    // Retention does not collect it either.
    store.prune_history(u32::MAX, u64::MAX).unwrap();
    let (_, body) = store.get_history::<serde_json::Value>(&id.to_string()).unwrap().unwrap();
    assert_eq!(body.expect("the body is kept").as_slice(), b"same body");
}

#[test]
fn history_bodies_are_indexed_on_open_and_unlock_without_a_schema_step() {
    let dir = tempfile::tempdir().unwrap();
    let created = vault::create_passphrase_profile(dir.path(), "t", "pw", KdfParams::testing()).unwrap();
    let db = || rusqlite::Connection::open(dir.path().join("anvil.db")).unwrap();
    let indexed = || -> bool {
        let sql = "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='index' AND name='history_body_blob')";
        db().query_row(sql, [], |r| r.get(0)).unwrap()
    };
    let version = || db().query_row("SELECT value FROM meta WHERE key='schema_version'", [], |r| r.get::<_, String>(0)).unwrap();
    drop(Store::open(dir.path(), created.dek.clone()).unwrap());
    assert!(indexed());
    // An index changes no stored data: the schema version, which earlier
    // builds check, stays the same.
    assert_eq!(version(), DB_SCHEMA_VERSION.to_string());

    // A database an earlier build left without the index gets it when opened.
    db().execute_batch("DROP INDEX history_body_blob;").unwrap();
    let store = Store::open(dir.path(), created.dek.clone()).unwrap();
    assert!(indexed());
    assert_eq!(version(), DB_SCHEMA_VERSION.to_string());

    // And when unlocked; with the index in place, opening again changes nothing.
    store.lock();
    db().execute_batch("DROP INDEX history_body_blob;").unwrap();
    store.unlock(created.dek.clone()).unwrap();
    assert!(indexed());
    drop(store);
    drop(Store::open(dir.path(), created.dek.clone()).unwrap());
    assert!(indexed());
    assert_eq!(version(), DB_SCHEMA_VERSION.to_string());
}

#[test]
fn unlock_refuses_key_derivation_settings_outside_the_bounds() {
    use anvil_storage::crypto::{MAX_KDF_ITERATIONS, MAX_KDF_MEMORY_KIB, MAX_KDF_PARALLELISM};
    let dir = tempfile::tempdir().unwrap();
    let created = vault::create_passphrase_profile(dir.path(), "t", "pw", KdfParams::testing()).unwrap();
    let recovery = created.recovery_key.clone().unwrap();
    let header = vault::read_header(dir.path()).unwrap();
    let with = |kdf: Option<KdfParams>, salt: Option<&str>| {
        let mut h = header.clone();
        for w in [h.passphrase_wrap.as_mut().unwrap(), h.recovery_wrap.as_mut().unwrap()] {
            if let Some(kdf) = kdf {
                w.kdf = Some(kdf);
            }
            if let Some(salt) = salt {
                w.salt = salt.into();
            }
        }
        h
    };
    let testing = KdfParams::testing();
    let refused = [
        ("memory", with(Some(KdfParams { m_cost: MAX_KDF_MEMORY_KIB + 1, ..testing }), None)),
        ("passes", with(Some(KdfParams { t_cost: MAX_KDF_ITERATIONS + 1, ..testing }), None)),
        ("no passes", with(Some(KdfParams { t_cost: 0, ..testing }), None)),
        ("lanes", with(Some(KdfParams { p_cost: MAX_KDF_PARALLELISM + 1, ..testing }), None)),
        ("memory x passes", with(Some(KdfParams { m_cost: MAX_KDF_MEMORY_KIB, t_cost: 5, ..testing }), None)),
        ("short salt", with(None, Some("AAAAAA=="))),
    ];
    // Refused before any derivation: none of these costs is ever paid.
    for (why, h) in &refused {
        let e = vault::unlock_with_passphrase(h, "pw").unwrap_err();
        assert!(matches!(&e, vault::VaultError::Header(m) if m.contains("unsupported key-derivation settings")), "{why}: {e}");
        let e = vault::unlock_with_recovery(h, &recovery).unwrap_err();
        assert!(matches!(&e, vault::VaultError::Header(m) if m.contains("unsupported key-derivation settings")), "{why}: {e}");
    }
    // The header as written still unlocks.
    assert_eq!(vault::unlock_with_passphrase(&header, "pw").unwrap().as_bytes(), created.dek.as_bytes());
    // A key is never wrapped with settings unlock would refuse.
    let other = tempfile::tempdir().unwrap();
    let costly = KdfParams { m_cost: MAX_KDF_MEMORY_KIB + 1, ..testing };
    assert!(vault::create_passphrase_profile(other.path(), "t", "pw", costly).is_err());
}
