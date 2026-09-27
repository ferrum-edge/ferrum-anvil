//! Stored attachments (binary bodies, datasets, imported spec sources) must
//! survive history retention, and deleting their last owner must remove the
//! encrypted content.

use anvil_app::App;
use anvil_app::exec::SendOptions;
use anvil_app::profiles::ProfileManager;
use anvil_domain::request::{AttachmentRef, Body, RequestSpec};
use anvil_domain::workspace::{Dataset, DatasetFormat, RequestDefinition};
use anvil_storage::{KdfParams, kind};
use anvil_transport::recorder::EventCtx;
use tokio_util::sync::CancellationToken;

fn new_app(root: &std::path::Path) -> App {
    let pm = ProfileManager::new(root);
    let (s, dek, _recovery) = pm.create_passphrase("att", "correct horse battery", KdfParams::testing()).unwrap();
    let h = anvil_storage::vault::read_header(&s.dir).unwrap();
    App::open(s.dir, h, dek).unwrap()
}

fn sha(a: &AttachmentRef) -> String {
    match a {
        AttachmentRef::Stored { sha256, .. } => sha256.clone(),
        other => panic!("unexpected {other:?}"),
    }
}

#[tokio::test]
async fn attachments_and_datasets_survive_sends_and_history_retention() {
    anvil_fixtures::init();
    let fx = anvil_fixtures::http::serve("127.0.0.1:0", None).await.unwrap();
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let ws = app.create_workspace("W").unwrap();
    let att = app.put_attachment("payload.bin", b"\x00\x01binary payload", None).unwrap();
    let ds = app.create_dataset(&ws.meta.id, "users", DatasetFormat::Csv, b"user\nalice\nbob\n", vec![]).unwrap();
    let req = app.create_request(&ws.meta.id, None, "r", RequestSpec::http("GET", &fx.url("/"))).unwrap();
    // Each send records history and applies retention (which used to delete
    // every blob that no history entry referenced).
    for _ in 0..3 {
        let opts = SendOptions { record_history: true, ..Default::default() };
        app.send(Some(req.meta.id), &ws.meta.id, None, opts, EventCtx::none(), CancellationToken::new()).await.unwrap();
    }
    app.store.prune_history(0, 0).unwrap();
    assert_eq!(app.get_attachment(&sha(&att)).unwrap().as_deref(), Some(&b"\x00\x01binary payload"[..]));
    assert_eq!(app.run_dataset(&app.dataset(&ds.meta.id).unwrap()).unwrap().rows.len(), 2);
}

#[tokio::test]
async fn deleting_the_last_dataset_owner_removes_the_content() {
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let ws = app.create_workspace("W").unwrap();
    let a = app.create_dataset(&ws.meta.id, "a", DatasetFormat::Csv, b"user\nshared\n", vec![]).unwrap();
    let b = app.create_dataset(&ws.meta.id, "b", DatasetFormat::Csv, b"user\nshared\n", vec![]).unwrap();
    let key = sha(&a.attachment);
    assert_eq!(key, sha(&b.attachment), "content-addressed: one stored copy");
    app.delete_dataset(&a.meta.id).unwrap();
    assert!(app.get_attachment(&key).unwrap().is_some(), "still used by dataset b");
    app.delete_dataset(&b.meta.id).unwrap();
    assert!(app.get_attachment(&key).unwrap().is_none(), "no owner left: content deleted");
}

fn upload(attachment: &AttachmentRef) -> RequestSpec {
    RequestSpec {
        body: Body::Binary { attachment: attachment.clone(), content_type: None },
        ..RequestSpec::http("POST", "http://127.0.0.1:9/")
    }
}

#[test]
fn deleting_the_request_that_holds_an_attached_file_removes_the_content() {
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let ws = app.create_workspace("W").unwrap().meta.id;
    let att = app.put_attachment("payload.bin", b"attached payload", None).unwrap();
    // An attached file is kept by an automatic release, even with no owner yet.
    assert!(!app.release_attachment(&sha(&att)).unwrap(), "attached, not saved yet: kept");
    let a = app.create_request(&ws, None, "a", upload(&att)).unwrap();
    // Edited since: an earlier revision still names the file.
    app.save_request(RequestDefinition { spec: RequestSpec::http("GET", "http://127.0.0.1:9/"), ..a.clone() }).unwrap();
    let folder = app.create_folder(&ws, None, "F").unwrap().meta.id;
    let b = app.create_request(&ws, Some(folder), "b", upload(&att)).unwrap();
    app.delete_request(&a.meta.id).unwrap();
    assert!(app.get_attachment(&sha(&att)).unwrap().is_some(), "still held by request b");
    app.delete_folder(&folder).unwrap();
    assert!(app.get_attachment(&sha(&att)).unwrap().is_none(), "no owner left: content deleted");
    assert!(app.request(&b.meta.id).is_err());
}

#[test]
fn a_save_naming_a_file_released_since_it_was_attached_is_refused() {
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let ws = app.create_workspace("W").unwrap().meta.id;
    let att = app.put_attachment("payload.bin", b"shared payload", None).unwrap();
    // One request holds the file; another is being edited to attach it too.
    let first = app.create_request(&ws, None, "first", upload(&att)).unwrap();
    let draft = app.create_request(&ws, None, "draft", RequestSpec::http("POST", "http://127.0.0.1:9/")).unwrap();
    // Deleting the request that held it releases it before the draft is saved.
    app.delete_request(&first.meta.id).unwrap();
    assert!(app.get_attachment(&sha(&att)).unwrap().is_none());
    let e = app.save_request(RequestDefinition { spec: upload(&att), ..draft.clone() }).unwrap_err();
    assert!(e.to_string().contains("no longer stored; attach it again"), "{e}");
    assert_eq!(app.request(&draft.meta.id).unwrap().spec, draft.spec, "nothing was saved");
    // A dataset saved with it is refused the same way.
    let rows = app.create_dataset(&ws, "rows", DatasetFormat::Csv, b"user\nalice\n", vec![]).unwrap();
    let e = app.save_dataset(Dataset { attachment: att.clone(), ..rows.clone() }).unwrap_err();
    assert!(e.to_string().contains("no longer stored; attach it again"), "{e}");
    assert_eq!(app.dataset(&rows.meta.id).unwrap().attachment, rows.attachment, "nothing was saved");

    // Attached again, it is stored again and the save goes through.
    app.put_attachment("payload.bin", b"shared payload", None).unwrap();
    app.save_request(RequestDefinition { spec: upload(&att), ..draft }).unwrap();
}

#[test]
fn a_request_already_holding_a_file_that_is_not_stored_still_saves() {
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let ws = app.create_workspace("W").unwrap().meta.id;
    // As after an import without the file's content: only a file added by
    // the save is checked.
    let missing = AttachmentRef::Stored { sha256: "0".repeat(64), size: 1, file_name: "lost.bin".into(), media_type: None };
    let mut q = app.create_request(&ws, None, "q", RequestSpec::http("POST", "http://127.0.0.1:9/")).unwrap();
    q.spec = upload(&missing);
    app.store.put(kind::REQUEST, &q.meta.id, Some(&ws), None, q.sort_key, &q).unwrap();
    let renamed = app.save_request(RequestDefinition { name: "renamed".into(), ..q }).unwrap();
    assert_eq!(app.request(&renamed.meta.id).unwrap().name, "renamed");
}

#[test]
fn replacing_a_datasets_file_removes_the_old_content() {
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let ws = app.create_workspace("W").unwrap().meta.id;
    let d = app.create_dataset(&ws, "rows", DatasetFormat::Csv, b"user\nalice\n", vec![]).unwrap();
    let old = sha(&d.attachment);
    let next = app.put_attachment("rows.csv", b"user\nbob\n", None).unwrap();
    app.save_dataset(Dataset { attachment: next.clone(), ..d }).unwrap();
    assert!(app.get_attachment(&old).unwrap().is_none(), "the replaced file had no other owner");
    assert!(app.get_attachment(&sha(&next)).unwrap().is_some());
}
