//! Exercise actual Store rotation, filesystem reopen and abrupt child exits.
use super::*;
use crate::{KdfParams, vault};
use std::path::Path;
const OLD: &str = "old passphrase 123";
const NEW: &str = "new passphrase 456";

pub(super) fn crash_point(stage: &str) {
    if std::env::var("ANVIL_ROTATION_TEST_CRASH").as_deref() == Ok(stage) {
        // Simulate abrupt process death: do not run Rust/SQLite destructors.
        std::process::exit(97);
    }
}
fn profile(dir: &Path) -> (Store, Key, vault::ProfileHeader) {
    let c = vault::create_passphrase_profile(dir, "rotation", OLD, KdfParams::testing()).unwrap();
    (Store::open(dir, c.dek.clone()).unwrap(), c.dek, c.header)
}
fn rotate(store: &Store) -> vault::KeychainConversion {
    store.rotate_data_key(NEW, &vault::RotationRecoveryKey::generate(), KdfParams::testing(), |_, _, _, state| Ok(state.flatten())).unwrap()
}
fn open_new(dir: &Path) -> Store {
    let h = vault::read_header(dir).unwrap();
    let k = vault::unlock_with_passphrase(&h, NEW).unwrap();
    Store::open(dir, k).unwrap()
}

#[test]
fn catalogue_downgrade_between_connection_preflight_and_record_snapshot_is_refused() {
    for behavior in [TransactionBehavior::Deferred, TransactionBehavior::Immediate] {
        let dir = tempfile::tempdir().unwrap();
        let c = vault::create_enrolled_passphrase_profile(dir.path(), "rotation", OLD, KdfParams::testing()).unwrap();
        let store = Store::open(dir.path(), c.dek.clone()).unwrap();
        let secret = Id::new();
        store.put_secret(&secret, None, "label", "current").unwrap();
        // Pass the connection preflight, then replay authority using a raw
        // SQLite writer that does not participate in the app's file fence.
        let mut guarded = store.writing().unwrap();
        {
            let control = store.begin_records(&mut guarded, behavior).unwrap();
            assert_eq!(control.get_secret(&secret).unwrap().unwrap().1.as_str(), "current");
            control.tx.rollback().unwrap();
        }
        let mut raw = Connection::open(dir.path().join(DB_FILE)).unwrap();
        let tx = raw.transaction().unwrap();
        let mut historical = crate::rotation::read_on(&tx).unwrap().unwrap();
        historical.header.rotation.as_mut().unwrap().manifest_root = None;
        vault::bind_rotation(&mut historical.header, &c.dek, &historical.binding);
        crate::rotation::write_on(&tx, &historical).unwrap();
        let env = crypto::seal(&c.dek, b"anvil/v2/rotated-canary", b"ok");
        tx.execute("UPDATE meta SET value=?1 WHERE key='key_canary'", [format!("rotated-v1:{}", hex::encode(env))]).unwrap();
        tx.execute("UPDATE meta SET value='4' WHERE key='schema_version'", []).unwrap();
        tx.execute("DELETE FROM meta WHERE key='protected_records_v1'", []).unwrap();
        tx.commit().unwrap();
        assert!(matches!(store.begin_records(&mut guarded, behavior), Err(StoreError::Integrity)));
    }
}

fn rows(conn: &Connection) -> Vec<(String, Vec<u8>, Vec<u8>)> {
    let mut out = Vec::new();
    for table in ["objects", "secrets", "blobs", "history", "load_reports"] {
        let query = match table {
            "objects" => "SELECT id,kind,NULL,payload FROM objects ORDER BY rowid",
            "secrets" => "SELECT id,NULL,workspace_id,payload FROM secrets ORDER BY rowid",
            "history" => "SELECT id,NULL,body_blob,payload FROM history ORDER BY rowid",
            "blobs" => "SELECT id,NULL,NULL,payload FROM blobs ORDER BY rowid",
            _ => "SELECT id,NULL,NULL,payload FROM load_reports ORDER BY rowid",
        };
        let mut st = conn.prepare(query).unwrap();
        for row in st
            .query_map([], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?, r.get::<_, Option<String>>(2)?, r.get::<_, Vec<u8>>(3)?))
            })
            .unwrap()
        {
            let (id, kind, owner, payload) = row.unwrap();
            let ad = match table {
                "objects" if kind.as_deref() == Some(kind::REVISION) => revision_aad(&id),
                "objects" => aad(table, kind.as_deref().unwrap(), &id),
                "secrets" => secret_aad(&id, owner.as_deref()),
                "history" => history_aad(&id, owner.as_deref()),
                "blobs" => aad(table, "blob", &id),
                _ => aad(table, "report", &id),
            };
            out.push((format!("{table}/{id}"), ad, payload));
        }
    }
    out
}
fn seed_every_payload(store: &Store, key: &Key) -> String {
    let ws = Id::new();
    let value = serde_json::json!({"id":ws,"schema_version":1,"created_at":chrono::Utc::now(),"updated_at":chrono::Utc::now(),"name":"kept workspace"});
    store.put(kind::WORKSPACE, &ws, None, None, 0.0, &value).unwrap();
    store.put_secret(&Id::new(), Some(&ws), "label", "secret marker").unwrap();
    let blob = store.put_blob(b"attachment marker").unwrap();
    store.pin_blob(&blob).unwrap();
    store
        .add_history(&Id::new(), Some(&ws), None, 1, &serde_json::json!({"workspace_id":ws,"request_id":null}), Some(b"response marker"))
        .unwrap();
    store.put_load_report(&Id::new(), Some(&ws), 1, &serde_json::json!({"plan":{"workspace_id":ws}})).unwrap();
    let conn = store.conn().unwrap();
    // Device kinds do not occur in export kind::ALL. All raw persisted kinds,
    // negative rowids and revision seals must still be re-encrypted.
    for (i, kind) in [kind::TOKEN_FILE, kind::LINKED_FILE, kind::DEVICE_IDENTITY_SEAL, kind::REVISION].into_iter().enumerate() {
        let id = Id::new().to_string();
        let ad = if kind == kind::REVISION { revision_aad(&id) } else { aad("objects", kind, &id) };
        let env = crypto::seal(key, &ad, b"retained payload marker");
        conn.execute(
            "INSERT INTO objects(rowid,kind,id,updated_at,payload) VALUES(?1,?2,?3,0,?4)",
            params![-(i as i64) - 1, kind, id, env],
        )
        .unwrap();
    }
    blob
}
#[test]
fn every_ciphertext_changes_key_without_losing_payload_or_blob_references() {
    let dir = tempfile::tempdir().unwrap();
    let (store, old, header) = profile(dir.path());
    let blob = seed_every_payload(&store, &old);
    let before = rows(&store.conn().unwrap());
    assert_eq!(before.len(), 10);
    let recovery = header.recovery_wrap.clone().unwrap().envelope;
    let rotated = rotate(&store);
    assert!(store.is_locked());
    let h = vault::read_header(dir.path()).unwrap();
    assert_ne!(h.key_check, header.key_check);
    assert_ne!(h.recovery_wrap.as_ref().unwrap().envelope, recovery);
    assert!(vault::unlock_with_passphrase(&h, OLD).is_err());
    let new = vault::unlock_with_passphrase(&h, NEW).unwrap();
    assert_eq!(vault::unlock_with_recovery(&h, &rotated.recovery_key).unwrap().as_bytes(), new.as_bytes());
    let reopened = Store::open(dir.path(), new.clone()).unwrap();
    let after = rows(&reopened.conn().unwrap());
    for ((id, ad, env), (id2, ad2, env2)) in before.iter().zip(after.iter()) {
        assert_eq!((id, ad), (id2, ad2));
        assert_eq!(crypto::open(&old, ad, env).unwrap(), crypto::open(&new, ad2, env2).unwrap());
        assert!(crypto::open(&old, ad2, env2).is_err(), "old raw header must not decrypt {id2}");
    }
    assert_eq!(reopened.get_blob(&blob).unwrap().unwrap().as_slice(), b"attachment marker");
    assert!(Store::open(dir.path(), vault::unlock_with_passphrase(&header, OLD).unwrap()).is_err());
    // Restoring only the old sidecar cannot select the old key over canonical state.
    vault::write_header(dir.path(), &header).unwrap_err();
    std::fs::write(vault::header_path(dir.path()), serde_json::to_vec(&header).unwrap()).unwrap();
    assert!(vault::unlock_with_passphrase(&vault::read_header(dir.path()).unwrap(), OLD).is_err());
}
#[test]
fn corruption_aborts_without_committing_a_partial_generation() {
    let dir = tempfile::tempdir().unwrap();
    let (store, old, h) = profile(dir.path());
    let blob = seed_every_payload(&store, &old);
    let before = rows(&store.conn().unwrap());
    store.conn().unwrap().execute("UPDATE blobs SET payload=x'00' WHERE id=?1", [&blob]).unwrap();
    assert!(store.rotate_data_key(NEW, &vault::RotationRecoveryKey::generate(), KdfParams::testing(), |_, _, _, _| Ok(None)).is_err());
    assert!(!store.is_locked());
    assert_eq!(vault::read_header(dir.path()).unwrap().key_check, h.key_check);
    let after = rows(&store.conn().unwrap());
    for ((id, _, env), (id2, _, env2)) in before.iter().zip(after.iter()) {
        assert_eq!(id, id2);
        if id != &format!("blobs/{blob}") {
            assert_eq!(env, env2);
        }
    }
    assert!(crate::rotation::read(dir.path()).unwrap().is_none());
}
#[test]
fn stale_supported_handles_cannot_read_rewrap_or_write_after_rotation() {
    let dir = tempfile::tempdir().unwrap();
    let (store, old, _) = profile(dir.path());
    let stale = Store::open(dir.path(), old).unwrap();
    rotate(&store);
    assert!(matches!(stale.put_blob(b"must not be sealed under old key"), Err(StoreError::Locked)));
    assert!(matches!(stale.delete_load_report(&Id::new()), Err(StoreError::Locked)));
    assert!(stale.with_key(|_| ()).is_err());
    assert!(stale.checkpoint("stale").is_err());
}
#[test]
fn metadata_deletion_downgrade_and_canary_deletion_fail_closed() {
    for attack in [
        "DELETE FROM meta WHERE key='local_key_state_v1'",
        "DELETE FROM meta WHERE key='key_canary'",
        "UPDATE meta SET value='3' WHERE key='schema_version'",
        "DELETE FROM meta WHERE key IN ('local_key_state_v1','key_canary'); UPDATE meta SET value='3' WHERE key='schema_version'",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let (store, old, old_header) = profile(dir.path());
        seed_every_payload(&store, &old);
        rotate(&store);
        let h = vault::read_header(dir.path()).unwrap();
        let new = vault::unlock_with_passphrase(&h, NEW).unwrap();
        drop(store);
        let conn = Connection::open(dir.path().join(DB_FILE)).unwrap();
        conn.execute_batch(attack).unwrap();
        assert!(Store::open(dir.path(), new).is_err(), "{attack}");
        assert!(Store::open(dir.path(), vault::unlock_with_passphrase(&old_header, OLD).unwrap()).is_err(), "{attack}");
    }
}
#[test]
fn checkpoints_keep_current_unlock_policy_and_reject_pre_rotation_key() {
    let dir = tempfile::tempdir().unwrap();
    let (store, _, _) = profile(dir.path());
    store.put_blob(b"old data").unwrap();
    let old_checkpoint = store.checkpoint("old").unwrap();
    rotate(&store);
    let reopened = open_new(dir.path());
    assert!(reopened.restore_checkpoint(&old_checkpoint).is_err());
    let checkpoint = reopened.checkpoint("rotated").unwrap();
    let mut h = vault::read_header(dir.path()).unwrap();
    reopened
        .with_key(|key| vault::change_passphrase(dir.path(), &mut h, key, "later password 789", KdfParams::testing()))
        .unwrap()
        .unwrap();
    reopened.restore_checkpoint(&checkpoint).unwrap();
    let h = vault::read_header(dir.path()).unwrap();
    assert!(vault::unlock_with_passphrase(&h, NEW).is_err());
    assert!(vault::unlock_with_passphrase(&h, "later password 789").is_ok());
}
#[test]
fn crash_worker() {
    let Ok(dir) = std::env::var("ANVIL_ROTATION_TEST_DIR") else {
        return;
    };
    let h = vault::read_header(Path::new(&dir)).unwrap();
    let old = vault::unlock_with_passphrase(&h, OLD).unwrap();
    let store = Store::open(Path::new(&dir), old).unwrap();
    rotate(&store);
}
#[test]
fn abrupt_process_exit_has_only_old_or_new_committed_generation() {
    for stage in ["after-first-row", "before-commit", "after-commit"] {
        let dir = tempfile::tempdir().unwrap();
        let (store, old, _) = profile(dir.path());
        let blob = seed_every_payload(&store, &old);
        drop(store);
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "store::rotation_tests::crash_worker", "--nocapture", "--test-threads=1"])
            .env("ANVIL_ROTATION_TEST_DIR", dir.path())
            .env("ANVIL_ROTATION_TEST_CRASH", stage)
            .output()
            .unwrap();
        assert_eq!(result.status.code(), Some(97), "{stage}: {}", String::from_utf8_lossy(&result.stderr));
        let h = vault::read_header(dir.path()).unwrap();
        let password = if stage == "after-commit" { NEW } else { OLD };
        let key = vault::unlock_with_passphrase(&h, password).unwrap();
        let reopened = Store::open(dir.path(), key).unwrap();
        assert_eq!(reopened.get_blob(&blob).unwrap().unwrap().as_slice(), b"attachment marker");
        assert_eq!(rows(&reopened.conn().unwrap()).len(), 10);
    }
}

#[test]
fn writer_worker() {
    let Ok(dir) = std::env::var("ANVIL_ROTATION_WRITER_DIR") else {
        return;
    };
    let dir = Path::new(&dir);
    let h = vault::read_header(dir).unwrap();
    let old = vault::unlock_with_passphrase(&h, OLD).unwrap();
    let stale = Store::open(dir, old).unwrap();
    std::fs::write(dir.join("writer-ready"), b"ready").unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    while !dir.join("writer-go").exists() {
        assert!(std::time::Instant::now() < deadline, "parent did not release writer");
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(matches!(stale.put_blob(b"stale process write"), Err(StoreError::Locked)));
}
#[test]
fn independent_process_cannot_publish_old_key_ciphertext_after_rotation() {
    let dir = tempfile::tempdir().unwrap();
    let (store, _, _) = profile(dir.path());
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "store::rotation_tests::writer_worker", "--test-threads=1"])
        .env("ANVIL_ROTATION_WRITER_DIR", dir.path())
        .stdout(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    while !dir.path().join("writer-ready").exists() {
        assert!(std::time::Instant::now() < deadline, "child did not open its stale handle");
        std::thread::sleep(Duration::from_millis(10));
    }
    rotate(&store);
    std::fs::write(dir.path().join("writer-go"), b"go").unwrap();
    assert!(child.wait().unwrap().success());
    assert_eq!(open_new(dir.path()).conn().unwrap().query_row("SELECT COUNT(*) FROM blobs", [], |r| r.get::<_, i64>(0)).unwrap(), 0);
}

#[test]
fn rotated_header_cannot_drop_its_mac_or_downgrade_its_wrap_domain() {
    let dir = tempfile::tempdir().unwrap();
    let (store, _, _) = profile(dir.path());
    rotate(&store);
    let h = vault::read_header(dir.path()).unwrap();
    let mut unsigned = h.clone();
    unsigned.protection_mac = None;
    assert!(vault::unlock_with_passphrase(&unsigned, NEW).is_err());
    let mut legacy = unsigned;
    legacy.rotation = None;
    assert!(vault::unlock_with_passphrase(&legacy, NEW).is_err());
}

#[test]
fn authenticated_legacy_residual_rows_are_resealed_without_becoming_readable() {
    let dir = tempfile::tempdir().unwrap();
    let (store, old, _) = profile(dir.path());
    let mut payloads = Vec::new();
    for (table, kind) in [("objects", kind::REVISION), ("secrets", "secret"), ("history", "record")] {
        let id = Id::new().to_string();
        let ad = aad(table, kind, &id);
        let env = crypto::seal(&old, &ad, b"legacy residual non-json payload");
        let conn = store.conn().unwrap();
        let sql = match table {
            "objects" => "INSERT INTO objects(id,kind,updated_at,payload) VALUES(?1,?2,0,?3)",
            "secrets" => "INSERT INTO secrets(id,updated_at,payload) VALUES(?1,0,?3)",
            _ => "INSERT INTO history(id,started_at,size,payload) VALUES(?1,0,0,?3)",
        };
        // Non-object queries have a numbered unused second parameter slot.
        conn.execute(sql, params![id, kind, env]).unwrap();
        payloads.push((table, id, ad));
    }
    rotate(&store);
    let h = vault::read_header(dir.path()).unwrap();
    let new = vault::unlock_with_passphrase(&h, NEW).unwrap();
    let reopened = Store::open(dir.path(), new.clone()).unwrap();
    for (table, id, ad) in payloads {
        let conn = reopened.conn().unwrap();
        let env: Vec<u8> = conn.query_row(&format!("SELECT payload FROM {table} WHERE id=?1"), [&id], |r| r.get(0)).unwrap();
        assert_eq!(crypto::open(&new, &ad, &env).unwrap().as_slice(), b"legacy residual non-json payload");
        assert!(crypto::open(&old, &ad, &env).is_err());
        let current_ad = match table {
            "objects" => revision_aad(&id),
            "secrets" => secret_aad(&id, None),
            _ => history_aad(&id, None),
        };
        assert!(crypto::open(&new, &current_ad, &env).is_err());
    }
}
