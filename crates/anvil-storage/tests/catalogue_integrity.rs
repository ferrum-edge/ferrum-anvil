//! The incremental catalogue and its verified cache keep every record-level
//! integrity property: a single record that is tampered with, rolled back,
//! deleted, resurrected or swapped with another id is refused on read and by
//! a cached context, also once the store has cached a verified catalogue and
//! verified rows. Raw writes go through another SQLite connection, as an
//! attacker with file access would.
use anvil_domain::Id;
use anvil_storage::store::DB_FILE;
use anvil_storage::{KdfParams, Key, Store, StoreError, crypto, kind, vault};
use rusqlite::{Connection, params};
use serde_json::{Value, json};

fn profile() -> (tempfile::TempDir, Store, Key) {
    let dir = tempfile::tempdir().unwrap();
    let created = vault::create_enrolled_passphrase_profile(dir.path(), "test", "original", KdfParams::testing()).unwrap();
    let store = Store::open(dir.path(), created.dek.clone()).unwrap();
    (dir, store, created.dek)
}
fn raw(dir: &tempfile::TempDir) -> Connection {
    Connection::open(dir.path().join(DB_FILE)).unwrap()
}
fn put_file(store: &Store, id: &Id, path: &str) {
    store.put(kind::TOKEN_FILE, id, None, None, 0.0, &json!({"id":id,"path":path,"bound_at":chrono::Utc::now()})).unwrap();
}
fn secret_payload(c: &Connection, id: &Id) -> Vec<u8> {
    c.query_row("SELECT payload FROM secrets WHERE id=?1", [id.to_string()], |r| r.get(0)).unwrap()
}
fn object_payload(c: &Connection, id: &Id) -> Vec<u8> {
    c.query_row("SELECT payload FROM objects WHERE kind=?1 AND id=?2", params![kind::TOKEN_FILE, id.to_string()], |r| r.get(0)).unwrap()
}
/// A context depending on `secret` and token file `file`, captured after the
/// store has verified (and cached) every row.
fn warm_context(store: &Store, secret: &Id, file: &Id) -> anvil_storage::ContextAuthority {
    let proof = store
        .read_context(|read| {
            read.depend_secret(secret);
            let _: Option<Value> = read.get(kind::TOKEN_FILE, file)?;
            Ok(read.finish())
        })
        .unwrap();
    for _ in 0..3 {
        store.check_context(&proof).unwrap();
    }
    proof
}

#[test]
fn single_record_tampering_is_refused_on_read_and_by_a_cached_context() {
    for table in ["secrets", "objects"] {
        let (dir, store, _) = profile();
        let (secret, file) = (Id::new(), Id::new());
        store.put_secret(&secret, None, "label", "current").unwrap();
        put_file(&store, &file, "current");
        let proof = warm_context(&store, &secret, &file);
        let c = raw(&dir);
        if table == "secrets" {
            let mut p = secret_payload(&c, &secret);
            *p.last_mut().unwrap() ^= 1;
            c.execute("UPDATE secrets SET payload=?1 WHERE id=?2", params![p, secret.to_string()]).unwrap();
        } else {
            let mut p = object_payload(&c, &file);
            *p.last_mut().unwrap() ^= 1;
            c.execute("UPDATE objects SET payload=?1 WHERE kind=?2 AND id=?3", params![p, kind::TOKEN_FILE, file.to_string()]).unwrap();
        }
        assert!(matches!(store.check_context(&proof), Err(StoreError::Integrity)), "{table}");
        assert!(store.is_locked(), "{table}");
    }
}

#[test]
fn rolled_back_record_is_refused_on_read_and_by_a_cached_context() {
    let (dir, store, key) = profile();
    let (secret, file) = (Id::new(), Id::new());
    store.put_secret(&secret, None, "label", "old").unwrap();
    put_file(&store, &file, "old");
    let c = raw(&dir);
    let old_secret = secret_payload(&c, &secret);
    store.put_secret(&secret, None, "label", "new").unwrap();
    put_file(&store, &file, "new");
    let proof = warm_context(&store, &secret, &file);

    c.execute("UPDATE secrets SET payload=?1 WHERE id=?2", params![old_secret, secret.to_string()]).unwrap();
    assert!(matches!(store.get_secret(&secret), Err(StoreError::Integrity)));
    let store = Store::open(dir.path(), key.clone()).unwrap();
    assert!(matches!(store.get_secret(&secret), Err(StoreError::Integrity)));
    assert!(matches!(store.check_context(&proof), Err(StoreError::Integrity)));

    let (dir, store, _) = profile();
    store.put_secret(&secret, None, "label", "current").unwrap();
    put_file(&store, &file, "old");
    let c = raw(&dir);
    let old_file = object_payload(&c, &file);
    put_file(&store, &file, "new");
    let proof = warm_context(&store, &secret, &file);
    c.execute("UPDATE objects SET payload=?1 WHERE kind=?2 AND id=?3", params![old_file, kind::TOKEN_FILE, file.to_string()]).unwrap();
    assert!(store.get::<Value>(kind::TOKEN_FILE, &file).is_err());
    assert!(matches!(store.check_context(&proof), Err(StoreError::Integrity)));
}

#[test]
fn deleted_or_resurrected_record_is_refused_by_a_cached_context() {
    let (dir, store, _) = profile();
    let (secret, file, other) = (Id::new(), Id::new(), Id::new());
    store.put_secret(&secret, None, "label", "current").unwrap();
    put_file(&store, &file, "current");
    store.put_secret(&other, None, "unrelated", "kept").unwrap();
    let proof = warm_context(&store, &secret, &file);
    raw(&dir).execute("DELETE FROM secrets WHERE id=?1", [secret.to_string()]).unwrap();
    assert!(matches!(store.check_context(&proof), Err(StoreError::Integrity)));

    // A deleted record put back with its authentic last ciphertext.
    let (dir, store, key) = profile();
    store.put_secret(&secret, None, "label", "current").unwrap();
    put_file(&store, &file, "current");
    let c = raw(&dir);
    let payload = secret_payload(&c, &secret);
    store.delete_secret(&secret).unwrap();
    let proof = warm_context(&store, &secret, &file);
    c.execute("INSERT INTO secrets(id,workspace_id,updated_at,payload) VALUES(?1,NULL,0,?2)", params![secret.to_string(), payload])
        .unwrap();
    assert!(matches!(store.check_context(&proof), Err(StoreError::Integrity)));
    let store = Store::open(dir.path(), key).unwrap();
    assert!(matches!(store.get_secret(&secret), Err(StoreError::Integrity)));
}

#[test]
fn records_swapped_between_ids_are_refused() {
    let (dir, store, _) = profile();
    let (a, b, file) = (Id::new(), Id::new(), Id::new());
    store.put_secret(&a, None, "a", "value-a").unwrap();
    store.put_secret(&b, None, "b", "value-b").unwrap();
    put_file(&store, &file, "current");
    let proof = warm_context(&store, &a, &file);
    let c = raw(&dir);
    let (pa, pb) = (secret_payload(&c, &a), secret_payload(&c, &b));
    c.execute("UPDATE secrets SET payload=?1 WHERE id=?2", params![pb, a.to_string()]).unwrap();
    c.execute("UPDATE secrets SET payload=?1 WHERE id=?2", params![pa, b.to_string()]).unwrap();
    assert!(matches!(store.check_context(&proof), Err(StoreError::Integrity)));

    // Swapping the catalogue entries along with the rows does not help: the
    // entries name their ids and the root covers every entry.
    let (dir, store, key) = profile();
    store.put_secret(&a, None, "a", "value-a").unwrap();
    store.put_secret(&b, None, "b", "value-b").unwrap();
    let c = raw(&dir);
    let entry = |id: &Id| -> String {
        c.query_row("SELECT entry FROM catalogue WHERE name=?1", [json!(["secrets", "", id.to_string()]).to_string()], |r| r.get(0))
            .unwrap()
    };
    let (ea, eb) = (entry(&a), entry(&b));
    let (pa, pb) = (secret_payload(&c, &a), secret_payload(&c, &b));
    c.execute("UPDATE secrets SET payload=?1 WHERE id=?2", params![pb, a.to_string()]).unwrap();
    c.execute("UPDATE secrets SET payload=?1 WHERE id=?2", params![pa, b.to_string()]).unwrap();
    let name = |id: &Id| json!(["secrets", "", id.to_string()]).to_string();
    c.execute("UPDATE catalogue SET entry=?1 WHERE name=?2", params![eb, name(&a)]).unwrap();
    c.execute("UPDATE catalogue SET entry=?1 WHERE name=?2", params![ea, name(&b)]).unwrap();
    // The catalogue no longer reproduces its root: the preflight locks.
    assert!(store.get_secret(&a).is_err());
    assert!(store.is_locked());
    assert!(Store::open(dir.path(), key).is_err());
}

#[test]
fn catalogue_rows_rolled_back_with_their_record_are_refused() {
    let (dir, store, key) = profile();
    let id = Id::new();
    store.put_secret(&id, None, "label", "old").unwrap();
    let c = raw(&dir);
    let name = json!(["secrets", "", id.to_string()]).to_string();
    let old_entry: String = c.query_row("SELECT entry FROM catalogue WHERE name=?1", [&name], |r| r.get(0)).unwrap();
    let (old_payload, old_updated): (Vec<u8>, i64) =
        c.query_row("SELECT payload, updated_at FROM secrets WHERE id=?1", [id.to_string()], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
    store.put_secret(&id, None, "label", "new").unwrap();
    // Warm the cache, then replay the record and its catalogue entry together.
    assert_eq!(store.get_secret(&id).unwrap().unwrap().1.as_str(), "new");
    c.execute("UPDATE secrets SET payload=?1, updated_at=?2 WHERE id=?3", params![old_payload, old_updated, id.to_string()]).unwrap();
    c.execute("UPDATE catalogue SET entry=?1 WHERE name=?2", params![old_entry, name]).unwrap();
    // The catalogue no longer reproduces its root: the preflight locks.
    assert!(store.get_secret(&id).is_err());
    assert!(store.is_locked());
    assert!(Store::open(dir.path(), key).is_err());
}

#[test]
fn externally_installed_triggers_cannot_change_other_records_during_own_writes() {
    let (dir, store, key) = profile();
    let victim = Id::new();
    store.put_secret(&victim, None, "victim", "kept").unwrap();
    let c = raw(&dir);
    c.execute_batch(&format!("CREATE TRIGGER delete_victim AFTER INSERT ON secrets BEGIN DELETE FROM secrets WHERE id='{}'; END;", victim))
        .unwrap();
    // Warm verification after the foreign schema commit, then exercise the
    // exact own-connection write that used to retain an incorrect cache.
    store.protected_authority().unwrap();
    store.put_secret(&Id::new(), None, "new", "value").unwrap();
    store.protected_authority().unwrap();
    assert_eq!(store.get_secret(&victim).unwrap().unwrap().1.as_str(), "kept");
    let reopened = Store::open(dir.path(), key).unwrap();
    reopened.put_secret(&Id::new(), None, "reopened", "value").unwrap();
    reopened.protected_authority().unwrap();
    assert_eq!(reopened.get_secret(&victim).unwrap().unwrap().1.as_str(), "kept");
    // The trigger remains on disk and can still act on a foreign connection;
    // those commits must invalidate verification and fail closed.
    c.execute(
        "INSERT INTO secrets SELECT ?1, workspace_id, updated_at, payload FROM secrets WHERE id=?2",
        params![Id::new().to_string(), victim.to_string()],
    )
    .unwrap();
    assert!(matches!(reopened.protected_authority(), Err(StoreError::Integrity)));
}

#[test]
fn externally_installed_foreign_key_cascades_cannot_delete_untracked_records() {
    let (dir, store, _) = profile();
    let (parent, victim) = (Id::new(), Id::new());
    store.put_secret(&parent, None, "parent", "value").unwrap();
    store.put_secret(&victim, Some(&parent), "victim", "kept").unwrap();
    raw(&dir)
        .execute_batch(
            "BEGIN IMMEDIATE;
             ALTER TABLE secrets RENAME TO old_secrets;
             CREATE TABLE secrets (id TEXT PRIMARY KEY, workspace_id TEXT REFERENCES secrets(id) ON DELETE CASCADE,
                 updated_at INTEGER NOT NULL, payload BLOB NOT NULL);
             INSERT INTO secrets SELECT * FROM old_secrets;
             DROP TABLE old_secrets;
             COMMIT;",
        )
        .unwrap();
    store.protected_authority().unwrap();
    store.delete_secret(&parent).unwrap();
    store.protected_authority().unwrap();
    assert_eq!(store.get_secret(&victim).unwrap().unwrap().1.as_str(), "kept");
}

#[test]
fn schema_replace_cannot_delete_a_secret_outside_the_upsert_target() {
    let (dir, store, _) = profile();
    let (workspace, victim, new) = (Id::new(), Id::new(), Id::new());
    store.put_secret(&victim, Some(&workspace), "victim", "kept").unwrap();
    raw(&dir)
        .execute_batch(
            "BEGIN IMMEDIATE;
             ALTER TABLE secrets RENAME TO old_secrets;
             CREATE TABLE secrets (id TEXT PRIMARY KEY, workspace_id TEXT UNIQUE ON CONFLICT REPLACE,
                 updated_at INTEGER NOT NULL, payload BLOB NOT NULL);
             INSERT INTO secrets SELECT * FROM old_secrets;
             DROP TABLE old_secrets;
             COMMIT;",
        )
        .unwrap();
    store.protected_authority().unwrap();
    // Updating the intended id still works; a conflict on a different
    // schema-controlled key must not silently remove that id.
    store.put_secret(&victim, Some(&workspace), "victim", "updated").unwrap();
    let authority = store.protected_authority().unwrap();
    assert!(store.put_secret(&new, Some(&workspace), "new", "rejected").is_err());
    assert_eq!(store.protected_authority().unwrap(), authority);
    assert_eq!(store.get_secret(&victim).unwrap().unwrap().1.as_str(), "updated");
    assert!(store.get_secret(&new).unwrap().is_none());
    store.put_secret(&new, Some(&Id::new()), "new", "allowed").unwrap();
    store.protected_authority().unwrap();
}

#[test]
fn schema_replace_cannot_delete_an_object_outside_the_upsert_target() {
    let (dir, store, _) = profile();
    let (victim, new) = (Id::new(), Id::new());
    put_file(&store, &victim, "kept");
    raw(&dir)
        .execute_batch(
            "BEGIN IMMEDIATE;
             ALTER TABLE objects RENAME TO old_objects;
             CREATE TABLE objects (kind TEXT NOT NULL, id TEXT NOT NULL, workspace_id TEXT, parent_id TEXT,
                 sort_key REAL NOT NULL DEFAULT 0 UNIQUE ON CONFLICT REPLACE,
                 updated_at INTEGER NOT NULL, payload BLOB NOT NULL, PRIMARY KEY(kind,id));
             INSERT INTO objects SELECT * FROM old_objects;
             DROP TABLE old_objects;
             COMMIT;",
        )
        .unwrap();
    store.protected_authority().unwrap();
    put_file(&store, &victim, "updated");
    let authority = store.protected_authority().unwrap();
    let value = json!({"id":new,"path":"rejected","bound_at":chrono::Utc::now()});
    assert!(store.put(kind::TOKEN_FILE, &new, None, None, 0.0, &value).is_err());
    assert_eq!(store.protected_authority().unwrap(), authority);
    assert_eq!(store.get::<Value>(kind::TOKEN_FILE, &victim).unwrap().unwrap()["path"], "updated");
    assert!(store.get::<Value>(kind::TOKEN_FILE, &new).unwrap().is_none());
}

#[test]
fn schema_replace_during_catalogue_publication_rolls_back_the_record_write() {
    let (dir, store, key) = profile();
    let (victim, new) = (Id::new(), Id::new());
    store.put_secret(&victim, None, "victim", "kept").unwrap();
    let c = raw(&dir);
    c.execute_batch(
        "BEGIN IMMEDIATE;
         ALTER TABLE catalogue RENAME TO old_catalogue;
         CREATE TABLE catalogue (name TEXT PRIMARY KEY, entry TEXT NOT NULL,
             collision INTEGER GENERATED ALWAYS AS (0) VIRTUAL UNIQUE ON CONFLICT REPLACE) WITHOUT ROWID;
         INSERT INTO catalogue(name,entry) SELECT name,entry FROM old_catalogue;
         DROP TABLE old_catalogue;
         COMMIT;",
    )
    .unwrap();
    let authority = store.protected_authority().unwrap();
    assert!(store.put_secret(&new, None, "new", "rejected").is_err());
    assert_eq!(store.protected_authority().unwrap(), authority);
    assert_eq!(store.get_secret(&victim).unwrap().unwrap().1.as_str(), "kept");
    assert!(store.get_secret(&new).unwrap().is_none());
    let count: i64 = c.query_row("SELECT COUNT(*) FROM catalogue", [], |r| r.get(0)).unwrap();
    assert_eq!(count, 1);
    Store::open(dir.path(), key).unwrap().protected_authority().unwrap();
}

#[test]
fn schema_replace_cannot_remove_authority_metadata_during_a_note_write() {
    let (dir, store, _) = profile();
    let c = raw(&dir);
    c.execute_batch(
        "BEGIN IMMEDIATE;
         ALTER TABLE meta RENAME TO old_meta;
         CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL UNIQUE ON CONFLICT REPLACE);
         INSERT INTO meta SELECT * FROM old_meta;
         DROP TABLE old_meta;
         COMMIT;",
    )
    .unwrap();
    let authority = store.protected_authority().unwrap();
    let value: String = c.query_row("SELECT value FROM meta WHERE key='local_key_state_v1'", [], |r| r.get(0)).unwrap();
    assert!(store.atomically(|tx| tx.put_note("collision", &value)).is_err());
    assert_eq!(store.protected_authority().unwrap(), authority);
    let retained: String = c.query_row("SELECT value FROM meta WHERE key='local_key_state_v1'", [], |r| r.get(0)).unwrap();
    assert_eq!(retained, value);
    store.atomically(|tx| tx.put_note("normal", "unique note value")).unwrap();
    store.protected_authority().unwrap();
}

#[test]
fn many_own_writes_keep_the_cached_catalogue_and_rows_exact() {
    let (dir, store, key) = profile();
    let second = Store::open(dir.path(), key.clone()).unwrap();
    let (secret, file) = (Id::new(), Id::new());
    store.put_secret(&secret, None, "label", "v0").unwrap();
    put_file(&store, &file, "v0");
    let mut proof = warm_context(&store, &secret, &file);
    for i in 1..50 {
        store.put_secret(&Id::new(), None, "unrelated", &format!("u{i}")).unwrap();
        put_file(&store, &Id::new(), &format!("u{i}"));
        store.check_context(&proof).unwrap();
        if i % 10 == 0 {
            // Another connection's commit, then this one's again.
            second.put_secret(&secret, None, "label", &format!("v{i}")).unwrap();
            assert!(matches!(store.check_context(&proof), Err(StoreError::StaleAuthority)));
            assert_eq!(store.get_secret(&secret).unwrap().unwrap().1.as_str(), format!("v{i}"));
            proof = warm_context(&store, &secret, &file);
        }
    }
    // Everything the cache produced matches what a fresh open verifies.
    let reopened = Store::open(dir.path(), key).unwrap();
    assert_eq!(reopened.protected_authority().unwrap(), store.protected_authority().unwrap());
    assert_eq!(reopened.list_secret_ids(None).unwrap().len(), store.list_secret_ids(None).unwrap().len());
}

#[test]
fn a_damaged_secret_can_be_overwritten_with_a_new_value() {
    let (dir, store, _) = profile();
    let id = Id::new();
    store.put_secret(&id, None, "label", "original").unwrap();
    let c = raw(&dir);
    let mut p = secret_payload(&c, &id);
    p[30] ^= 0xff;
    c.execute("UPDATE secrets SET payload=?1 WHERE id=?2", params![p, id.to_string()]).unwrap();
    assert!(matches!(store.get_secret(&id), Err(StoreError::Integrity)));
    // Reading a damaged row locks the store; an owner unlocks it again.
    let key = vault::unlock_with_passphrase(&vault::read_header(dir.path()).unwrap(), "original").unwrap();
    store.unlock(key).unwrap();
    store.put_secret(&id, None, "label", "replacement").unwrap();
    assert_eq!(store.get_secret(&id).unwrap().unwrap().1.as_str(), "replacement");
    store.protected_authority().unwrap();
}

/// A checkpoint whose authority was stripped and replaced by a same-key
/// legacy canary (as the creation-time database had) must not get the rows
/// it carries certified, even though each row is authentic ciphertext.
#[test]
fn a_checkpoint_without_its_own_catalogue_is_not_certified_into_an_enrolled_profile() {
    let (dir, store, key) = profile();
    let id = Id::new();
    store.put_secret(&id, None, "label", "old").unwrap();
    let old = secret_payload(&raw(&dir), &id);
    store.put_secret(&id, None, "label", "current").unwrap();
    let checkpoint = store.checkpoint("tampered").unwrap();
    {
        let c = Connection::open(&checkpoint).unwrap();
        c.execute("UPDATE secrets SET payload=?1 WHERE id=?2", params![old, id.to_string()]).unwrap();
        c.execute("DELETE FROM meta WHERE key IN ('local_key_state_v1', 'protected_records_v1')", []).unwrap();
        c.execute_batch("DROP TABLE IF EXISTS catalogue").unwrap();
        let canary = crypto::seal(&key, b"anvil/v1/canary", b"ok");
        c.execute("UPDATE meta SET value=?1 WHERE key='key_canary'", [hex::encode(canary)]).unwrap();
    }
    assert!(store.restore_checkpoint(&checkpoint).is_err());
    let reopened = Store::open(dir.path(), key).unwrap();
    assert_eq!(reopened.get_secret(&id).unwrap().unwrap().1.as_str(), "current");
}

#[test]
fn a_checkpoint_with_a_record_rolled_back_against_its_own_catalogue_is_refused() {
    let (dir, store, key) = profile();
    let id = Id::new();
    store.put_secret(&id, None, "label", "old").unwrap();
    let old = secret_payload(&raw(&dir), &id);
    store.put_secret(&id, None, "label", "current").unwrap();
    let checkpoint = store.checkpoint("rolled-back").unwrap();
    Connection::open(&checkpoint).unwrap().execute("UPDATE secrets SET payload=?1 WHERE id=?2", params![old, id.to_string()]).unwrap();
    assert!(store.restore_checkpoint(&checkpoint).is_err());
    let reopened = Store::open(dir.path(), key).unwrap();
    assert_eq!(reopened.get_secret(&id).unwrap().unwrap().1.as_str(), "current");
}
