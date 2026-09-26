//! Stored attachments (binary bodies, datasets, imported spec sources) must
//! survive history retention, and deleting their last owner must remove the
//! encrypted content.

use anvil_app::App;
use anvil_app::exec::SendOptions;
use anvil_app::profiles::ProfileManager;
use anvil_domain::request::{AttachmentRef, RequestSpec};
use anvil_domain::workspace::DatasetFormat;
use anvil_storage::KdfParams;
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
