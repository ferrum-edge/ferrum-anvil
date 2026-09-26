//! A failed store transaction never takes an unrelated, acknowledged
//! `App::save_workspace` down with it, and a transaction always ends.

use anvil_app::App;
use anvil_app::profiles::{ProfileManager, Unlock};
use anvil_domain::Id;
use anvil_domain::request::RequestSpec;
use anvil_storage::{KdfParams, StoreError, kind};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::Duration;

const PASSPHRASE: &str = "correct horse battery";

#[test]
fn failed_transaction_does_not_roll_back_a_concurrent_workspace_save() {
    let root = tempfile::tempdir().unwrap();
    let pm = ProfileManager::new(root.path());
    let (s, dek, _recovery) = pm.create_passphrase("isolation", PASSPHRASE, KdfParams::testing()).unwrap();
    let h = anvil_storage::vault::read_header(&s.dir).unwrap();
    let app = App::open(s.dir.clone(), h, dek).unwrap();
    let ws = app.create_workspace("old name").unwrap();
    let mut renamed = app.workspace(&ws.meta.id).unwrap();
    renamed.name = "new name".into();
    let doomed = Id::new();

    // Caller A: a transaction that writes, then fails.
    let (began, began_rx) = mpsc::channel();
    let (saved, saved_rx) = mpsc::channel();
    let store = Arc::clone(&app.store);
    let a = thread::spawn(move || {
        let mut saved_inside = false;
        let r: Result<(), StoreError> = store.atomically(|tx| {
            tx.put(kind::WORKSPACE, &doomed, None, None, 0.0, &serde_json::json!({"name": "doomed"}))?;
            began.send(()).unwrap();
            saved_inside = saved_rx.recv_timeout(Duration::from_millis(500)).is_ok();
            Err(StoreError::NotFound("injected failure".into()))
        });
        assert!(r.is_err());
        saved_inside
    });

    // Caller B: a workspace rename while A's transaction is open.
    began_rx.recv().unwrap();
    app.save_workspace(renamed).unwrap();
    let _ = saved.send(());
    assert!(!a.join().unwrap(), "the save completed inside another caller's open transaction");

    assert_eq!(app.workspace(&ws.meta.id).unwrap().name, "new name", "the other caller's rollback erased an acknowledged save");
    assert!(app.store.get::<serde_json::Value>(kind::WORKSPACE, &doomed).unwrap().is_none());
    drop(app);

    // The acknowledged save survives reopening the profile.
    let (h, dek) = ProfileManager::unlock(&s.dir, Unlock::Passphrase(PASSPHRASE)).unwrap();
    let app = App::open(s.dir.clone(), h, dek).unwrap();
    assert_eq!(app.workspace(&ws.meta.id).unwrap().name, "new name");
}

#[test]
fn deleting_a_folder_in_a_parent_cycle_terminates() {
    let root = tempfile::tempdir().unwrap();
    let pm = ProfileManager::new(root.path());
    let (s, dek, _recovery) = pm.create_passphrase("cycle", PASSPHRASE, KdfParams::testing()).unwrap();
    let h = anvil_storage::vault::read_header(&s.dir).unwrap();
    let app = App::open(s.dir.clone(), h, dek).unwrap();
    let ws = app.create_workspace("cycle").unwrap();
    let a = app.create_folder(&ws.meta.id, None, "a").unwrap();
    let b = app.create_folder(&ws.meta.id, Some(a.meta.id), "b").unwrap();
    let req = app.create_request(&ws.meta.id, Some(b.meta.id), "in b", RequestSpec::http("GET", "http://127.0.0.1/")).unwrap();
    // `save_folder` does not validate ancestry, so it can close the cycle
    // a -> b -> a, as an imported bundle could.
    let mut a = app.folder(&a.meta.id).unwrap();
    a.parent_id = Some(b.meta.id);
    let a = app.save_folder(a).unwrap();

    app.delete_folder(&a.meta.id).unwrap();
    assert!(app.folders(&ws.meta.id).unwrap().is_empty());
    assert!(app.requests(&ws.meta.id).unwrap().iter().all(|r| r.meta.id != req.meta.id));
}
