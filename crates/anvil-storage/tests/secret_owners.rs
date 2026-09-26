//! A vault secret is sealed together with the workspace that owns it, and
//! secrets sealed before that (schema 1) are re-sealed once, in one
//! transaction, when the store is opened or unlocked. A schema 1 secret that
//! does not decrypt is left as it is.

use anvil_domain::Id;
use anvil_storage::store::{DB_FILE, DB_SCHEMA_VERSION, StoreError};
use anvil_storage::{KdfParams, Key, Store, crypto, vault};
use rusqlite::{Connection, OptionalExtension, params};
use std::path::Path;

fn db(dir: &Path) -> Connection {
    Connection::open(dir.join(DB_FILE)).unwrap()
}

fn profile() -> (tempfile::TempDir, Key) {
    let dir = tempfile::tempdir().unwrap();
    let created = vault::create_passphrase_profile(dir.path(), "t", "pw", KdfParams::testing()).unwrap();
    (dir, created.dek)
}

fn set_owner(dir: &Path, id: &Id, owner: Option<&Id>) {
    let n = db(dir).execute("UPDATE secrets SET workspace_id=?1 WHERE id=?2", params![owner.map(|w| w.to_string()), id.to_string()]);
    assert_eq!(n.unwrap(), 1);
}

fn payload(dir: &Path, id: &Id) -> Vec<u8> {
    db(dir).query_row("SELECT payload FROM secrets WHERE id=?1", params![id.to_string()], |r| r.get(0)).unwrap()
}

fn stored_version(dir: &Path) -> String {
    db(dir).query_row("SELECT value FROM meta WHERE key='schema_version'", [], |r| r.get(0)).unwrap()
}

/// Put the database back at schema 1, as an earlier build left it.
fn downgrade(dir: &Path) {
    db(dir).execute("UPDATE meta SET value='1' WHERE key='schema_version'", []).unwrap();
}

/// A secret row as schema 1 sealed it: bound to its id, not to its owner.
fn plant_v1_secret(dir: &Path, key: &Key, id: &Id, owner: Option<&Id>, value: &str) {
    let json = serde_json::to_vec(&serde_json::json!({"label": "legacy", "value": value})).unwrap();
    let env = crypto::seal(key, format!("anvil/v1/secrets/secret/{id}").as_bytes(), &json);
    let sql = "INSERT INTO secrets(id,workspace_id,updated_at,payload) VALUES(?1,?2,0,?3)";
    db(dir).execute(sql, params![id.to_string(), owner.map(|w| w.to_string()), env]).unwrap();
}

fn value(store: &Store, id: &Id) -> String {
    store.get_secret(id).unwrap().expect("stored").1.as_str().to_owned()
}

#[test]
fn a_secret_whose_owner_is_changed_no_longer_opens() {
    let (dir, dek) = profile();
    let store = Store::open(dir.path(), dek).unwrap();
    let (a, b) = (Id::new(), Id::new());
    let owned = Id::new();
    let unowned = Id::new();
    store.put_secret(&owned, Some(&a), "token", "owned-by-a").unwrap();
    store.put_secret(&unowned, None, "token", "owned-by-none").unwrap();
    assert_eq!(store.get_workspace_secret(&owned, &a).unwrap().unwrap().1.as_str(), "owned-by-a");

    // Moved to another workspace: that workspace's lookup does not resolve it.
    set_owner(dir.path(), &owned, Some(&b));
    assert!(matches!(store.get_workspace_secret(&owned, &b), Err(StoreError::Integrity)));
    assert!(matches!(store.get_secret(&owned), Err(StoreError::Integrity)));
    assert!(store.get_workspace_secret(&owned, &a).unwrap().is_none());
    // Moved out of every workspace, or a profile-level secret moved into one.
    set_owner(dir.path(), &owned, None);
    assert!(matches!(store.get_secret(&owned), Err(StoreError::Integrity)));
    set_owner(dir.path(), &unowned, Some(&b));
    assert!(matches!(store.get_workspace_secret(&unowned, &b), Err(StoreError::Integrity)));

    // Back with the owner each was sealed for, both open again.
    set_owner(dir.path(), &owned, Some(&a));
    set_owner(dir.path(), &unowned, None);
    assert_eq!(value(&store, &owned), "owned-by-a");
    assert_eq!(value(&store, &unowned), "owned-by-none");
}

#[test]
fn a_secret_given_a_new_owner_through_the_store_is_sealed_for_it() {
    let (dir, dek) = profile();
    let store = Store::open(dir.path(), dek).unwrap();
    let (a, b) = (Id::new(), Id::new());
    let id = Id::new();
    store.put_secret(&id, Some(&a), "token", "first").unwrap();
    store.put_secret(&id, Some(&b), "token", "second").unwrap();
    assert!(store.get_workspace_secret(&id, &a).unwrap().is_none());
    assert_eq!(store.get_workspace_secret(&id, &b).unwrap().unwrap().1.as_str(), "second");
    let secrets = store.read_consistently(|r| r.secrets()).unwrap();
    assert_eq!(secrets.len(), 1);
    assert_eq!(secrets[0].workspace_id, Some(b.to_string()));
}

#[test]
fn opening_reseals_schema_1_secrets_once_with_their_owner() {
    let (dir, dek) = profile();
    drop(Store::open(dir.path(), dek.clone()).unwrap());
    let (a, b) = (Id::new(), Id::new());
    let (owned, unowned) = (Id::new(), Id::new());
    downgrade(dir.path());
    plant_v1_secret(dir.path(), &dek, &owned, Some(&a), "legacy-owned");
    plant_v1_secret(dir.path(), &dek, &unowned, None, "legacy-unowned");

    let store = Store::open(dir.path(), dek.clone()).unwrap();
    assert_eq!(stored_version(dir.path()), DB_SCHEMA_VERSION.to_string());
    assert_eq!(store.get_workspace_secret(&owned, &a).unwrap().unwrap().1.as_str(), "legacy-owned");
    assert_eq!(value(&store, &unowned), "legacy-unowned");
    drop(store);

    // Run once: opening again leaves the re-sealed rows as they are.
    let sealed = (payload(dir.path(), &owned), payload(dir.path(), &unowned));
    let store = Store::open(dir.path(), dek.clone()).unwrap();
    assert_eq!((payload(dir.path(), &owned), payload(dir.path(), &unowned)), sealed);
    let store_again = Store::open(dir.path(), dek).unwrap();
    assert_eq!(payload(dir.path(), &owned), sealed.0);
    drop(store_again);

    // The owner is now bound: moved to another workspace, it does not open.
    set_owner(dir.path(), &owned, Some(&b));
    assert!(matches!(store.get_workspace_secret(&owned, &b), Err(StoreError::Integrity)));
}

#[test]
fn unlocking_reseals_schema_1_secrets() {
    let (dir, dek) = profile();
    let store = Store::open(dir.path(), dek.clone()).unwrap();
    store.lock();
    let ws = Id::new();
    let id = Id::new();
    downgrade(dir.path());
    plant_v1_secret(dir.path(), &dek, &id, Some(&ws), "legacy-at-unlock");

    store.unlock(dek).unwrap();
    assert_eq!(stored_version(dir.path()), DB_SCHEMA_VERSION.to_string());
    assert_eq!(store.get_workspace_secret(&id, &ws).unwrap().unwrap().1.as_str(), "legacy-at-unlock");
    set_owner(dir.path(), &id, None);
    assert!(matches!(store.get_secret(&id), Err(StoreError::Integrity)));
}

/// Schema 1 rows: one that opens, and one sealed under another secret's id,
/// which does not open as its own.
fn plant_good_and_bad(dir: &Path, key: &Key) -> (Id, Id) {
    let ws = Id::new();
    let (good, bad) = (Id::new(), Id::new());
    plant_v1_secret(dir, key, &good, Some(&ws), "legacy-good");
    let json = serde_json::to_vec(&serde_json::json!({"label": "x", "value": "y"})).unwrap();
    let env = crypto::seal(key, format!("anvil/v1/secrets/secret/{good}").as_bytes(), &json);
    let sql = "INSERT INTO secrets(id,workspace_id,updated_at,payload) VALUES(?1,?2,0,?3)";
    db(dir).execute(sql, params![bad.to_string(), ws.to_string(), env]).unwrap();
    (good, bad)
}

fn left_at_v2(dir: &Path) -> Option<String> {
    let sql = "SELECT value FROM meta WHERE key='secrets_left_at_v2'";
    db(dir).query_row(sql, [], |r| r.get(0)).optional().unwrap()
}

/// After the migration: the good row is re-sealed and opens, the bad row is
/// left exactly as it was, still fails, and can be deleted.
fn assert_bad_row_left(store: &Store, dir: &Path, good: &Id, bad: &Id, before: &(Vec<u8>, Vec<u8>)) {
    assert_eq!(stored_version(dir), DB_SCHEMA_VERSION.to_string());
    assert_ne!(payload(dir, good), before.0, "the good row is re-sealed");
    assert_eq!(value(store, good), "legacy-good");
    assert_eq!(payload(dir, bad), before.1, "the bad row is left as it was");
    assert!(matches!(store.get_secret(bad), Err(StoreError::Integrity)));
    assert_eq!(left_at_v2(dir).as_deref(), Some("1"));
    store.delete_secret(bad).unwrap();
    assert!(store.get_secret(bad).unwrap().is_none());
    assert_eq!(value(store, good), "legacy-good");
}

#[test]
fn a_secret_that_does_not_open_is_left_as_it_is_at_open() {
    let (dir, dek) = profile();
    drop(Store::open(dir.path(), dek.clone()).unwrap());
    downgrade(dir.path());
    let (good, bad) = plant_good_and_bad(dir.path(), &dek);
    let before = (payload(dir.path(), &good), payload(dir.path(), &bad));

    let store = Store::open(dir.path(), dek).unwrap();
    assert_bad_row_left(&store, dir.path(), &good, &bad, &before);
}

#[test]
fn a_secret_that_does_not_open_is_left_as_it_is_at_unlock() {
    let (dir, dek) = profile();
    let store = Store::open(dir.path(), dek.clone()).unwrap();
    store.lock();
    downgrade(dir.path());
    let (good, bad) = plant_good_and_bad(dir.path(), &dek);
    let before = (payload(dir.path(), &good), payload(dir.path(), &bad));

    store.unlock(dek).unwrap();
    assert!(!store.is_locked());
    assert_bad_row_left(&store, dir.path(), &good, &bad, &before);
}

#[test]
fn a_wrong_key_fails_before_the_migration_and_changes_nothing() {
    let (dir, dek) = profile();
    let store = Store::open(dir.path(), dek.clone()).unwrap();
    store.lock();
    downgrade(dir.path());
    let (good, bad) = plant_good_and_bad(dir.path(), &dek);
    let before = (payload(dir.path(), &good), payload(dir.path(), &bad));

    assert!(matches!(Store::open(dir.path(), Key::random()), Err(StoreError::Integrity)));
    assert!(matches!(store.unlock(Key::random()), Err(StoreError::Integrity)));
    assert!(store.is_locked(), "a wrong key leaves the store locked");
    assert_eq!(stored_version(dir.path()), "1");
    assert_eq!((payload(dir.path(), &good), payload(dir.path(), &bad)), before);
    assert_eq!(left_at_v2(dir.path()), None);
}

#[test]
fn a_checkpoint_from_a_newer_schema_is_refused_before_the_live_database_is_touched() {
    let (dir, dek) = profile();
    let store = Store::open(dir.path(), dek).unwrap();
    let (ws, id) = (Id::new(), Id::new());
    store.put_secret(&id, Some(&ws), "token", "live").unwrap();
    let checkpoint = store.checkpoint("newer").unwrap();
    let newer = (DB_SCHEMA_VERSION + 1).to_string();
    Connection::open(&checkpoint).unwrap().execute("UPDATE meta SET value=?1 WHERE key='schema_version'", params![newer]).unwrap();
    store.put_secret(&id, Some(&ws), "token", "after-checkpoint").unwrap();

    assert!(matches!(store.restore_checkpoint(&checkpoint), Err(StoreError::FutureSchema { .. })));
    assert!(!store.is_locked());
    assert_eq!(stored_version(dir.path()), DB_SCHEMA_VERSION.to_string());
    assert_eq!(store.get_workspace_secret(&id, &ws).unwrap().unwrap().1.as_str(), "after-checkpoint");
}

#[test]
fn a_checkpoint_sealed_with_another_key_is_refused_before_the_live_database_is_touched() {
    let (dir, dek) = profile();
    let store = Store::open(dir.path(), dek).unwrap();
    let (ws, id) = (Id::new(), Id::new());
    store.put_secret(&id, Some(&ws), "token", "live").unwrap();
    let (other_dir, other_dek) = profile();
    let other = Store::open(other_dir.path(), other_dek).unwrap();
    let foreign = other.checkpoint("foreign").unwrap();

    assert!(matches!(store.restore_checkpoint(&foreign), Err(StoreError::Integrity)));
    assert!(!store.is_locked());
    assert_eq!(store.get_workspace_secret(&id, &ws).unwrap().unwrap().1.as_str(), "live");
}

#[test]
fn a_restored_checkpoint_from_schema_1_is_resealed() {
    let (dir, dek) = profile();
    drop(Store::open(dir.path(), dek.clone()).unwrap());
    let ws = Id::new();
    let id = Id::new();
    downgrade(dir.path());
    plant_v1_secret(dir.path(), &dek, &id, Some(&ws), "legacy-in-checkpoint");
    // A copy of the schema 1 database, as a checkpoint taken by an earlier build.
    let checkpoint = dir.path().join("schema-1.db");
    db(dir.path()).execute("VACUUM INTO ?1", params![checkpoint.display().to_string()]).unwrap();

    let store = Store::open(dir.path(), dek).unwrap();
    store.delete_secret(&id).unwrap();
    store.restore_checkpoint(&checkpoint).unwrap();
    assert_eq!(stored_version(dir.path()), DB_SCHEMA_VERSION.to_string());
    assert_eq!(store.get_workspace_secret(&id, &ws).unwrap().unwrap().1.as_str(), "legacy-in-checkpoint");
    set_owner(dir.path(), &id, None);
    assert!(matches!(store.get_secret(&id), Err(StoreError::Integrity)));
}
