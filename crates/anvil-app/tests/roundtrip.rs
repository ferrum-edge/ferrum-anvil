//! DATA-001/002/003: workspace and whole-app round trips into a clean
//! profile (different data key, no shared keychain), then a successful send.

use anvil_app::exec::SendOptions;
use anvil_app::profiles::ProfileManager;
use anvil_app::{App, AppError};
use anvil_domain::auth::{AuthConfig, KeyLocation};
use anvil_domain::request::{KeyValue, RequestSpec};
use anvil_domain::secret::SensitiveValue;
use anvil_domain::workspace::{RequestDefinition, Variable};
use anvil_portability::ExportMode;
use anvil_portability::plan::ConflictPolicy;
use anvil_storage::KdfParams;
use anvil_transport::recorder::EventCtx;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use tokio_util::sync::CancellationToken;

fn new_app(root: &std::path::Path, name: &str) -> App {
    let pm = ProfileManager::new(root);
    let (s, dek, _recovery) = pm.create_passphrase(name, "correct horse battery", KdfParams::testing()).unwrap();
    let h = anvil_storage::vault::read_header(&s.dir).unwrap();
    App::open(s.dir, h, dek).unwrap()
}

#[tokio::test]
async fn data_002_full_backup_restores_into_clean_profile_and_sends() {
    anvil_fixtures::init();
    let fx = anvil_fixtures::http::serve("127.0.0.1:0", None).await.unwrap();
    let a_root = tempfile::tempdir().unwrap();
    let a = new_app(a_root.path(), "machine-a");
    let ws = a.create_workspace("Payments").unwrap();
    let orders = a.create_folder(&ws.meta.id, None, "Orders").unwrap();
    let refunds = a.create_folder(&ws.meta.id, Some(orders.meta.id), "Refunds").unwrap();
    let key_ref = a.set_secret(&ws.meta.id, "api key", "k-SECRET-4242").unwrap();
    let mut env_vars = vec![Variable::plain("base", &fx.url(""))];
    env_vars.push(Variable {
        name: "tok".into(),
        value: SensitiveValue::template("ENV-TOKEN-777"),
        secret: true,
        enabled: true,
        description: String::new(),
    });
    let env = a.create_environment(&ws.meta.id, "lab", env_vars).unwrap();
    let mut spec = RequestSpec::http("GET", "{{base}}/auth/apikey?name=x-api-key&value=k-SECRET-4242");
    spec.headers.push(KeyValue::new("X-Env-Token", "{{tok}}"));
    spec.auth = AuthConfig::ApiKey {
        name: "X-API-Key".into(),
        value: SensitiveValue::Secret { secret: key_ref.clone() },
        location: KeyLocation::Header,
    };
    let req = a.create_request(&ws.meta.id, Some(refunds.meta.id), "Check key", spec).unwrap();
    let opts = SendOptions { environment: Some(env.meta.id), record_history: true, ..Default::default() };
    let out = a.send(Some(req.meta.id), &ws.meta.id, None, opts.clone(), EventCtx::none(), CancellationToken::new()).await.unwrap();
    assert_eq!(out.record.response.as_ref().unwrap().status, 200, "{:?}", out.record.findings);
    assert_eq!(a.store.list_history(Some(&ws.meta.id), None, 10).unwrap().len(), 1);

    // Whole-app encrypted backup.
    let (bytes, preview) = a.export_backup_with("export passphrase 1", KdfParams::testing()).unwrap();
    assert!(anvil_app::backup::is_backup(&bytes));
    assert_eq!(preview.secrets_included, 1);
    let text = String::from_utf8_lossy(&bytes);
    assert!(!text.contains("k-SECRET-4242") && !text.contains("ENV-TOKEN-777"));

    // Clean install elsewhere: a different profile/key.
    let b_root = tempfile::tempdir().unwrap();
    let b = new_app(b_root.path(), "machine-b");
    let dry = b.restore_preview(&bytes, Some("export passphrase 1"), ConflictPolicy::Merge).unwrap();
    assert!(dry.missing_secrets.is_empty());
    assert!(b.workspaces().unwrap().is_empty(), "preview does not mutate");
    let rep = b.restore(&bytes, Some("export passphrase 1"), ConflictPolicy::Merge).unwrap();
    assert!(rep.secrets_restored);
    let ws_b = b.find_workspace("Payments").unwrap();
    let tree = b.tree(&ws_b.meta.id).unwrap();
    assert_eq!(tree[0].name, "Orders");
    assert_eq!(tree[0].children[0].name, "Refunds");
    let req_b = b.find_request(&ws_b.meta.id, "Orders/Refunds/Check key").unwrap();
    let out_b = b
        .send(
            Some(req_b.meta.id),
            &ws_b.meta.id,
            None,
            SendOptions { environment: Some(env.meta.id), record_history: true, ..Default::default() },
            EventCtx::none(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(out_b.record.response.as_ref().unwrap().status, 200, "restored profile sends successfully: {:?}", out_b.record.findings);
    let hdrs = fx.log.last_request_headers().unwrap();
    assert!(hdrs.iter().any(|(n, v)| n == "x-env-token" && v == "ENV-TOKEN-777"), "secret variable restored");

    // Restoring the same backup again with Merge is idempotent. It writes
    // into the restored workspace, which the user approves.
    let approval = anvil_app::port::ImportApproval::for_file(&bytes, vec![ws_b.meta.id]);
    b.restore_approved(&bytes, Some("export passphrase 1"), ConflictPolicy::Merge, &approval).unwrap();
    assert_eq!(b.workspaces().unwrap().len(), 1);
    // A full backup restores every item under its own id; it is never duplicated.
    let e = b.restore(&bytes, Some("export passphrase 1"), ConflictPolicy::Duplicate).unwrap_err();
    assert!(matches!(e, AppError::Backup(anvil_app::backup::BackupError::DuplicateUnsupported)), "{e}");
    assert_eq!(b.workspaces().unwrap().len(), 1);
}

#[tokio::test]
async fn data_001_share_safely_import_reports_missing_secrets_and_fails_locally() {
    anvil_fixtures::init();
    let fx = anvil_fixtures::http::serve("127.0.0.1:0", None).await.unwrap();
    let a_root = tempfile::tempdir().unwrap();
    let a = new_app(a_root.path(), "a");
    let ws = a.create_workspace("Shared").unwrap();
    let key_ref = a.set_secret(&ws.meta.id, "token", "tok-SHOULD-NOT-TRAVEL").unwrap();
    let mut spec = RequestSpec::http("GET", &fx.url("/echo"));
    spec.auth = AuthConfig::Bearer { token: SensitiveValue::Secret { secret: key_ref }, prefix: "Bearer".into() };
    a.create_request(&ws.meta.id, None, "Echo", spec).unwrap();
    let (bytes, _) = a.export(Some(&ws.meta.id), ExportMode::ShareSafely, None, false).unwrap();
    let b_root = tempfile::tempdir().unwrap();
    let b = new_app(b_root.path(), "b");
    let rep = b.import(&bytes, None, ConflictPolicy::Merge).unwrap();
    assert_eq!(rep.missing_secrets.len(), 1);
    let wsb = b.find_workspace("Shared").unwrap();
    let r = b.find_request(&wsb.meta.id, "Echo").unwrap();
    let out =
        b.send(Some(r.meta.id), &wsb.meta.id, None, SendOptions::default(), EventCtx::none(), CancellationToken::new()).await.unwrap();
    assert!(out.record.findings.iter().any(|f| f.code == "local.auth_preparation_failed"), "{:?}", out.record.findings);
    assert_eq!(fx.log.count_requests(), 0, "nothing was sent without the secret");
}

#[tokio::test]
async fn data_015_locked_app_refuses_privileged_operations() {
    let root = tempfile::tempdir().unwrap();
    let a = new_app(root.path(), "locky");
    let ws = a.create_workspace("W").unwrap();
    a.lock();
    assert!(matches!(a.workspaces(), Err(AppError::Locked)));
    assert!(matches!(a.set_secret(&ws.meta.id, "x", "y"), Err(AppError::Locked)));
    assert!(matches!(
        a.send(
            None,
            &ws.meta.id,
            Some(RequestSpec::http("GET", "http://127.0.0.1:9/")),
            SendOptions::default(),
            EventCtx::none(),
            CancellationToken::new()
        )
        .await,
        Err(AppError::Locked)
    ));
    let h = anvil_storage::vault::read_header(&a.dir).unwrap();
    let k = anvil_storage::vault::unlock_with_passphrase(&h, "correct horse battery").unwrap();
    a.unlock(k).unwrap();
    assert_eq!(a.workspaces().unwrap().len(), 1);
}

#[test]
fn folder_moves_cannot_create_cycles() {
    let root = tempfile::tempdir().unwrap();
    let a = new_app(root.path(), "t");
    let ws = a.create_workspace("W").unwrap();
    let p = a.create_folder(&ws.meta.id, None, "P").unwrap();
    let c = a.create_folder(&ws.meta.id, Some(p.meta.id), "C").unwrap();
    assert!(a.move_folder(&p.meta.id, Some(c.meta.id), 1.0).is_err());
    assert!(a.move_folder(&p.meta.id, Some(p.meta.id), 1.0).is_err());
    a.move_folder(&c.meta.id, None, 5.0).unwrap();
}

#[test]
fn revisions_are_immutable_history() {
    let root = tempfile::tempdir().unwrap();
    let a = new_app(root.path(), "t");
    let ws = a.create_workspace("W").unwrap();
    let r = a.create_request(&ws.meta.id, None, "R", RequestSpec::http("GET", "http://a/")).unwrap();
    let rev1 = r.revision_id.unwrap();
    let mut r2 = r.clone();
    r2.spec.url = "http://b/".into();
    let r2 = a.save_request(r2).unwrap();
    assert_ne!(r2.revision_id.unwrap(), rev1);
    assert_eq!(a.revision(&rev1).unwrap().spec.url, "http://a/", "old revision unchanged");
    let same = a.save_request(r2.clone()).unwrap();
    assert_eq!(same.revision_id, r2.revision_id, "no new revision when unchanged");
}

#[test]
fn a_save_changes_a_request_but_never_its_placement() {
    let root = tempfile::tempdir().unwrap();
    let a = new_app(root.path(), "t");
    let ws = a.create_workspace("W").unwrap();
    let f = a.create_folder(&ws.meta.id, None, "F").unwrap();
    let r = a.create_request(&ws.meta.id, Some(f.meta.id), "R", RequestSpec::http("GET", "http://a/")).unwrap();
    assert_eq!((r.workspace_id, r.folder_id, r.sort_key), (ws.meta.id, Some(f.meta.id), 1.0));

    let saved = a.save_request(RequestDefinition { name: "S".into(), spec: RequestSpec::http("POST", "http://b/"), ..r.clone() }).unwrap();
    assert_eq!((saved.name.as_str(), saved.spec.url.as_str()), ("S", "http://b/"));
    assert_ne!(saved.revision_id, r.revision_id, "the changed spec files a revision");
    assert_eq!(a.revision(&saved.revision_id.unwrap()).unwrap().spec, saved.spec);
    assert_eq!(a.request(&r.meta.id).unwrap(), saved);

    // The placement a save names is not written: only a move places a
    // request, and never into another workspace.
    let other = a.create_workspace("X").unwrap();
    let theirs = a.create_folder(&other.meta.id, None, "theirs").unwrap();
    let placed = RequestDefinition { workspace_id: other.meta.id, folder_id: Some(theirs.meta.id), sort_key: 9.0, ..saved.clone() };
    let kept = a.save_request(placed).unwrap();
    assert_eq!((kept.workspace_id, kept.folder_id, kept.sort_key), (ws.meta.id, Some(f.meta.id), 1.0));
    assert_eq!(kept.revision_id, saved.revision_id, "an unchanged spec files no revision");
    assert_eq!(a.request(&r.meta.id).unwrap(), kept);
    assert!(a.requests(&other.meta.id).unwrap().is_empty());
}

#[test]
fn a_save_keeps_a_move_that_landed_after_the_editor_loaded_the_request() {
    let root = tempfile::tempdir().unwrap();
    let a = new_app(root.path(), "t");
    let ws = a.create_workspace("W").unwrap();
    let f = a.create_folder(&ws.meta.id, None, "F").unwrap();
    let r = a.create_request(&ws.meta.id, None, "R", RequestSpec::http("GET", "http://a/")).unwrap();

    // The editor loads the request; the request is then moved; the editor
    // then saves its copy, which still names the old folder and position.
    let mut editing = a.request(&r.meta.id).unwrap();
    let moved = a.move_request(&r.meta.id, Some(f.meta.id), 7.5).unwrap();
    editing.name = "renamed".into();
    editing.spec.url = "http://b/".into();
    let saved = a.save_request(editing).unwrap();

    // The save's edits are stored where the move put the request.
    assert_eq!((saved.folder_id, saved.sort_key), (Some(f.meta.id), 7.5));
    assert_eq!((saved.name.as_str(), saved.spec.url.as_str()), ("renamed", "http://b/"));
    assert_ne!(saved.revision_id, moved.revision_id);
    assert_eq!(a.revision(&saved.revision_id.unwrap()).unwrap().spec, saved.spec);
    assert_eq!(a.request(&r.meta.id).unwrap(), saved);
    let in_folder: Vec<_> = a.requests(&ws.meta.id).unwrap().into_iter().filter(|q| q.folder_id == Some(f.meta.id)).collect();
    assert_eq!(in_folder, vec![saved]);
}

#[test]
fn moves_that_land_during_saves_are_kept() {
    let root = tempfile::tempdir().unwrap();
    let a = Arc::new(new_app(root.path(), "t"));
    let ws = a.create_workspace("W").unwrap();
    let one = a.create_folder(&ws.meta.id, None, "one").unwrap();
    let two = a.create_folder(&ws.meta.id, None, "two").unwrap();
    let folders = [Some(one.meta.id), Some(two.meta.id), None];
    let r = a.create_request(&ws.meta.id, None, "R", RequestSpec::http("GET", "http://a/")).unwrap();
    // The copy an editor loaded before any move.
    let stale = r.clone();

    // Move `i` puts the request in `folders[i % 3]` at position 100 + i, so
    // a placement tells which move made it.
    let placed_by = |q: &RequestDefinition| -> usize {
        assert!(q.sort_key >= 100.0, "a save put back the placement the request was created with");
        let i = q.sort_key as usize - 100;
        assert_eq!(q.folder_id, folders[i % folders.len()]);
        i
    };

    // One thread keeps moving the request while this one keeps saving the
    // stale copy. A save that wrote back the copy's placement would undo
    // the moves made before it.
    const SAVES: usize = 60;
    let moved = Arc::new(AtomicUsize::new(0));
    let done = Arc::new(AtomicBool::new(false));
    let mover = {
        let (a, moved, done, id) = (a.clone(), moved.clone(), done.clone(), r.meta.id);
        std::thread::spawn(move || {
            let mut moves = 0;
            loop {
                a.move_request(&id, folders[moves % folders.len()], (100 + moves) as f64).unwrap();
                moves += 1;
                moved.store(moves, Ordering::SeqCst);
                if done.load(Ordering::SeqCst) {
                    return moves;
                }
            }
        })
    };
    while moved.load(Ordering::SeqCst) == 0 {
        std::thread::yield_now();
    }
    let mut saved = None;
    for i in 0..SAVES {
        // Every move finished before this save started is kept by it.
        let before = moved.load(Ordering::SeqCst);
        let spec = RequestSpec::http("GET", &format!("http://a/{i}"));
        let q = a.save_request(RequestDefinition { spec, ..stale.clone() }).unwrap();
        assert!(placed_by(&q) + 1 >= before, "save {i} undid move {}", before - 1);
        saved = Some(q);
    }
    done.store(true, Ordering::SeqCst);
    let moves = mover.join().unwrap();

    // The request sits where the last move put it, with the last save's
    // spec as its latest revision.
    let stored = a.request(&r.meta.id).unwrap();
    assert_eq!(placed_by(&stored), moves - 1);
    assert_eq!(stored.spec, RequestSpec::http("GET", &format!("http://a/{}", SAVES - 1)));
    assert_eq!(stored.revision_id, saved.unwrap().revision_id);
    assert_eq!(a.revision(&stored.revision_id.unwrap()).unwrap().spec, stored.spec);
}
