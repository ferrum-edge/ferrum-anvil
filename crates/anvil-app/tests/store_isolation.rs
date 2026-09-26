//! A failed store transaction never takes an unrelated, acknowledged
//! `App::save_workspace` down with it, and a transaction always ends.

use anvil_app::App;
use anvil_app::profiles::{ProfileManager, Unlock};
use anvil_domain::Id;
use anvil_domain::request::RequestSpec;
use anvil_storage::{KdfParams, StoreError, kind};
use anvil_app::AppError;
use std::sync::{Arc, Barrier, mpsc};
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

fn open_app(name: &str) -> (tempfile::TempDir, App) {
    let root = tempfile::tempdir().unwrap();
    let pm = ProfileManager::new(root.path());
    let (s, dek, _recovery) = pm.create_passphrase(name, PASSPHRASE, KdfParams::testing()).unwrap();
    let h = anvil_storage::vault::read_header(&s.dir).unwrap();
    let app = App::open(s.dir.clone(), h, dek).unwrap();
    (root, app)
}

/// Run `f` on another thread and fail the test, instead of hanging it, if it
/// does not finish in time.
fn within_timeout<R: Send + 'static>(f: impl FnOnce() -> R + Send + 'static) -> R {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(Duration::from_secs(20)).expect("the folder walk did not terminate")
}

/// Close the parent cycle a -> b -> a with `save_folder`, which does not
/// validate ancestry, as an imported bundle could. Returns (a, b).
fn folder_cycle(app: &App, ws: &Id) -> (Id, Id) {
    let a = app.create_folder(ws, None, "a").unwrap();
    let b = app.create_folder(ws, Some(a.meta.id), "b").unwrap();
    let mut a = app.folder(&a.meta.id).unwrap();
    a.parent_id = Some(b.meta.id);
    let a = app.save_folder(a).unwrap();
    (a.meta.id, b.meta.id)
}

#[test]
fn moving_a_folder_under_a_parent_cycle_terminates() {
    let (_root, app) = open_app("move-cycle");
    let app = Arc::new(app);
    let ws = app.create_workspace("cycle").unwrap();
    let (a, _b) = folder_cycle(&app, &ws.meta.id);
    let x = app.create_folder(&ws.meta.id, None, "x").unwrap();

    let moved = within_timeout({
        let app = Arc::clone(&app);
        move || app.move_folder(&x.meta.id, Some(a), 1.0)
    });
    assert!(matches!(moved, Err(AppError::Invalid(_))), "{moved:?}");
    assert_eq!(app.folder(&x.meta.id).unwrap().parent_id, None, "a refused move must not be saved");
}

#[test]
fn finding_a_request_inside_a_parent_cycle_terminates() {
    let (_root, app) = open_app("find-cycle");
    let app = Arc::new(app);
    let ws = app.create_workspace("cycle").unwrap();
    let (_a, b) = folder_cycle(&app, &ws.meta.id);
    let req = app.create_request(&ws.meta.id, Some(b), "in b", RequestSpec::http("GET", "http://127.0.0.1/")).unwrap();
    let other = app.create_request(&ws.meta.id, None, "other", RequestSpec::http("GET", "http://127.0.0.1/")).unwrap();

    let found = within_timeout({
        let (app, ws) = (Arc::clone(&app), ws.meta.id);
        move || (app.find_request(&ws, "in b").map(|r| r.meta.id), app.find_request(&ws, "other").map(|r| r.meta.id))
    });
    assert_eq!(found.0.unwrap(), req.meta.id);
    assert_eq!(found.1.unwrap(), other.meta.id);
}

#[test]
fn concurrent_opposing_folder_moves_cannot_create_a_cycle() {
    let (_root, app) = open_app("move-race");
    let app = Arc::new(app);
    let ws = app.create_workspace("race").unwrap();
    for round in 0..50 {
        let a = app.create_folder(&ws.meta.id, None, &format!("a{round}")).unwrap().meta.id;
        let b = app.create_folder(&ws.meta.id, None, &format!("b{round}")).unwrap().meta.id;
        let start = Arc::new(Barrier::new(2));
        let mover = |id: Id, under: Id| {
            let (app, start) = (Arc::clone(&app), Arc::clone(&start));
            thread::spawn(move || {
                start.wait();
                app.move_folder(&id, Some(under), 1.0).is_ok()
            })
        };
        let (ab, ba) = (mover(a, b), mover(b, a));
        let moved = [ab.join().unwrap(), ba.join().unwrap()];
        assert_eq!(moved.iter().filter(|m| **m).count(), 1, "round {round}: exactly one of the opposing moves may succeed");
        let (fa, fb) = (app.folder(&a).unwrap(), app.folder(&b).unwrap());
        assert!(!(fa.parent_id == Some(b) && fb.parent_id == Some(a)), "round {round}: the moves created a parent cycle");
    }
}
