//! Stored files no saved item can reach any more are released: a
//! workspace's on its delete, and when a profile opens those attached and
//! never saved past the grace period and those only orphaned revisions
//! name. A file any saved item of any workspace references is never
//! released.

use anvil_app::App;
use anvil_app::cleanup::{ATTACHMENT_GRACE, StorageCleanup, UndecodableObject};
use anvil_app::profiles::{ProfileManager, Unlock};
use anvil_domain::Id;
use anvil_domain::request::{AttachmentRef, Body, RequestSpec};
use anvil_domain::workspace::{DatasetFormat, RequestDefinition};
use anvil_storage::store::DB_FILE;
use anvil_storage::{KdfParams, kind};

const PASSPHRASE: &str = "correct horse battery";

fn new_app(root: &std::path::Path) -> App {
    let pm = ProfileManager::new(root);
    let (s, dek, _recovery) = pm.create_passphrase("cleanup", PASSPHRASE, KdfParams::testing()).unwrap();
    let h = anvil_storage::vault::read_header(&s.dir).unwrap();
    App::open(s.dir, h, dek).unwrap()
}

/// Close `app` and open its profile again, as a restart does.
fn reopen(app: App) -> App {
    let dir = app.dir.clone();
    drop(app);
    let (h, dek) = ProfileManager::unlock(&dir, Unlock::Passphrase(PASSPHRASE)).unwrap();
    App::open(dir, h, dek).unwrap()
}

fn sha(a: &AttachmentRef) -> String {
    match a {
        AttachmentRef::Stored { sha256, .. } => sha256.clone(),
        other => panic!("unexpected {other:?}"),
    }
}

fn upload(attachment: &AttachmentRef) -> RequestSpec {
    RequestSpec {
        body: Body::Binary { attachment: attachment.clone(), content_type: None },
        ..RequestSpec::http("POST", "http://127.0.0.1:9/")
    }
}

fn stored(app: &App, a: &AttachmentRef) -> bool {
    app.get_attachment(&sha(a)).unwrap().is_some()
}

/// The index entry of stored attachment `a`, with its object id.
fn index_entry(app: &App, a: &AttachmentRef) -> (Id, serde_json::Value) {
    app.store
        .object_meta(kind::IMPORT_SOURCE)
        .unwrap()
        .into_iter()
        .map(|m| m.id.parse::<Id>().unwrap())
        .filter_map(|id| app.store.get::<serde_json::Value>(kind::IMPORT_SOURCE, &id).unwrap().map(|v| (id, v)))
        .find(|(_, v)| v["attachment"] == sha(a).as_str())
        .expect("its index entry")
}

/// How many revisions are filed under request `r`.
fn revisions_of(app: &App, r: &Id) -> usize {
    app.store.object_meta(kind::REVISION).unwrap().into_iter().filter(|m| m.parent_id == Some(r.to_string())).count()
}

/// Mark attachment `a` as attached `days` ago.
fn attached_days_ago(app: &App, a: &AttachmentRef, days: i64) {
    let (id, mut entry) = index_entry(app, a);
    entry["attached_at"] = (chrono::Utc::now() - chrono::Duration::days(days)).timestamp_millis().into();
    app.store.put(kind::IMPORT_SOURCE, &id, None, None, 0.0, &entry).unwrap();
}

#[test]
fn deleting_a_workspace_releases_its_files_unless_another_workspace_references_them() {
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let one = app.create_workspace("One").unwrap().meta.id;
    let two = app.create_workspace("Two").unwrap().meta.id;
    let only = app.put_attachment("only.bin", b"payload only workspace One holds", None).unwrap();
    let shared = app.put_attachment("shared.bin", b"payload both workspaces hold", None).unwrap();
    let edited = app.put_attachment("edited.bin", b"payload an old revision holds", None).unwrap();
    let r = app.create_request(&one, None, "only", upload(&only)).unwrap();
    // Edited since: only a revision still names the file.
    let e = app.create_request(&one, None, "edited", upload(&edited)).unwrap();
    app.save_request(RequestDefinition { spec: RequestSpec::http("GET", "http://127.0.0.1:9/"), ..e }).unwrap();
    app.create_request(&one, None, "shared", upload(&shared)).unwrap();
    app.create_request(&two, None, "shared", upload(&shared)).unwrap();
    let rows = app.create_dataset(&one, "rows", DatasetFormat::Csv, b"user\nalice\n", vec![]).unwrap();

    app.delete_workspace(&one).unwrap();
    assert!(!stored(&app, &only), "held only by workspace One: released");
    assert!(!stored(&app, &edited), "held only by a revision in workspace One: released");
    assert!(!stored(&app, &rows.attachment), "its dataset's file: released");
    assert!(stored(&app, &shared), "workspace Two still holds it");
    assert!(app.request(&r.meta.id).is_err());
    // The released files' index entries went with their content.
    let index: Vec<serde_json::Value> = app.store.list(kind::IMPORT_SOURCE, None).unwrap();
    assert_eq!(index.len(), 1, "{index:?}");
}

#[test]
fn a_file_attached_and_never_saved_is_released_after_the_grace_period() {
    assert_eq!(ATTACHMENT_GRACE.as_secs(), 30 * 24 * 60 * 60, "the documented period");
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let ws = app.create_workspace("W").unwrap().meta.id;
    let other = app.create_workspace("Other").unwrap().meta.id;
    let abandoned = app.put_attachment("abandoned.bin", b"attached to a draft never saved", None).unwrap();
    let recent = app.put_attachment("recent.bin", b"attached to a draft today", None).unwrap();
    let saved = app.put_attachment("saved.bin", b"attached and saved long ago", None).unwrap();
    app.create_request(&other, None, "saved", upload(&saved)).unwrap();
    attached_days_ago(&app, &abandoned, 31);
    attached_days_ago(&app, &saved, 31);
    attached_days_ago(&app, &recent, 29);

    let app = reopen(app);
    assert!(!stored(&app, &abandoned), "past the grace period and no saved item names it: released");
    assert!(stored(&app, &recent), "still within the grace period: kept");
    assert!(stored(&app, &saved), "a saved item in another workspace references it: kept");
    // Held by a saved item now: its mark is dropped, so later passes skip it.
    let (_, entry) = index_entry(&app, &saved);
    assert!(entry.get("user").is_none() && entry.get("attached_at").is_none(), "{entry}");
    assert_eq!(app.clean_up_storage().unwrap(), StorageCleanup::default(), "nothing left to do");

    // A draft that still names the released file cannot save it.
    let draft = app.create_request(&ws, None, "draft", RequestSpec::http("POST", "http://127.0.0.1:9/")).unwrap();
    let e = app.save_request(RequestDefinition { spec: upload(&abandoned), ..draft }).unwrap_err();
    assert!(e.to_string().contains("no longer stored; attach it again"), "{e}");
}

#[test]
fn opening_a_profile_removes_orphaned_revisions_and_the_files_only_they_name() {
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let ws = app.create_workspace("W").unwrap().meta.id;
    let other = app.create_workspace("Other").unwrap().meta.id;
    let gone = app.put_attachment("gone.bin", b"payload of a request deleted long ago", None).unwrap();
    let shared = app.put_attachment("shared.bin", b"payload another workspace still holds", None).unwrap();
    let old = app.create_request(&ws, None, "old", upload(&gone)).unwrap();
    app.save_request(RequestDefinition { spec: upload(&shared), ..old.clone() }).unwrap();
    let kept = app.create_request(&other, None, "kept", upload(&shared)).unwrap();
    // As a build before deletes removed revisions left it: the request is
    // gone, its revisions are not.
    app.store.delete(kind::REQUEST, &old.meta.id).unwrap();
    assert_eq!(revisions_of(&app, &old.meta.id), 2);

    let app = reopen(app);
    assert_eq!(revisions_of(&app, &old.meta.id), 0, "the orphaned revisions are removed");
    assert_eq!(revisions_of(&app, &kept.meta.id), 1, "a revision of a request that exists is kept");
    assert!(!stored(&app, &gone), "named only by the orphaned revisions: released");
    assert!(stored(&app, &shared), "a saved request in another workspace references it: kept");
    assert_eq!(app.clean_up_storage().unwrap(), StorageCleanup::default(), "a second pass finds nothing");
}

#[test]
fn an_object_that_does_not_decode_keeps_every_file_and_is_named() {
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let ws = app.create_workspace("W").unwrap().meta.id;
    let damaged = app.create_request(&ws, None, "damaged", RequestSpec::http("GET", "http://127.0.0.1:9/")).unwrap();
    let abandoned = app.put_attachment("abandoned.bin", b"attached to a draft never saved", None).unwrap();
    attached_days_ago(&app, &abandoned, 31);
    let db = rusqlite::Connection::open(app.dir.join(DB_FILE)).unwrap();
    let id = damaged.meta.id.to_string();
    db.execute("UPDATE objects SET payload=x'00' WHERE kind=?1 AND id=?2", rusqlite::params![kind::REQUEST, id]).unwrap();

    let done = app.clean_up_storage().unwrap();
    assert_eq!(done.undecodable, vec![UndecodableObject { kind: kind::REQUEST.into(), id }]);
    assert_eq!(done.released_attachments, 0);
    assert!(stored(&app, &abandoned), "the damaged request could name it: kept");
    // Opening the profile runs the same pass, and still opens.
    let app = reopen(app);
    assert!(stored(&app, &abandoned));

    // Once the damaged row is deleted, the file is released.
    app.store.delete(kind::REQUEST, &damaged.meta.id).unwrap();
    let done = app.clean_up_storage().unwrap();
    assert_eq!(done.released_attachments, 1);
    assert!(done.undecodable.is_empty());
    assert!(!stored(&app, &abandoned));
}
