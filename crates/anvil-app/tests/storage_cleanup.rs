//! Stored files no saved item can reach any more are released: a
//! workspace's on its delete, and when a profile opens (at most once a day)
//! those attached and never saved past the grace period and those only
//! orphaned revisions name. A file a user attached within the grace period,
//! which a draft may hold, and a file any saved item of any workspace
//! references are never released. A damaged revision that does not decode,
//! which keeps every file, can be removed (a checkpoint keeps it); one a
//! newer Anvil may have written is kept.

use anvil_app::App;
use anvil_app::cleanup::{ATTACHMENT_GRACE, CLEANUP_INTERVAL, StorageCleanup, Undecodable, UndecodableObject, UndecodableRevision};
use anvil_app::profiles::{ProfileManager, Unlock};
use anvil_domain::Id;
use anvil_domain::request::{AttachmentRef, Body, RequestSpec};
use anvil_domain::workspace::{DatasetFormat, RequestDefinition};
use anvil_storage::store::DB_FILE;
use anvil_storage::{KdfParams, Key, crypto, kind};

const PASSPHRASE: &str = "correct horse battery";

fn new_app(root: &std::path::Path) -> App {
    new_app_with_key(root).0
}

/// [`new_app`], and the key its store seals with.
fn new_app_with_key(root: &std::path::Path) -> (App, Key) {
    let pm = ProfileManager::new(root);
    let (s, dek, _recovery) = pm.create_passphrase("cleanup", PASSPHRASE, KdfParams::testing()).unwrap();
    let h = anvil_storage::vault::read_header(&s.dir).unwrap();
    (App::open(s.dir, h, dek.clone()).unwrap(), dek)
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

/// Record the last cleanup pass as run `hours` ago.
fn last_pass_ran_hours_ago(app: &App, hours: i64) {
    let db = rusqlite::Connection::open(app.dir.join(DB_FILE)).unwrap();
    let key = "note:storage_cleanup";
    let note: String = db.query_row("SELECT value FROM meta WHERE key=?1", [key], |r| r.get(0)).unwrap();
    let mut note: serde_json::Value = serde_json::from_str(&note).unwrap();
    note["ran_at"] = (chrono::Utc::now() - chrono::Duration::hours(hours)).to_rfc3339().into();
    db.execute("UPDATE meta SET value=?1 WHERE key=?2", [note.to_string().as_str(), key]).unwrap();
}

/// How long ago the last cleanup pass ran.
fn since_last_pass(app: &App) -> chrono::Duration {
    chrono::Utc::now() - app.last_storage_cleanup().unwrap().expect("a pass ran").ran_at
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
    // Attached within the grace period: a draft elsewhere may hold it.
    let fresh = app.put_attachment("fresh.bin", b"payload attached to workspace One today", None).unwrap();
    app.create_request(&one, None, "fresh", upload(&fresh)).unwrap();
    for a in [&only, &shared, &edited, &rows.attachment] {
        attached_days_ago(&app, a, 31);
    }

    app.delete_workspace(&one).unwrap();
    assert!(!stored(&app, &only), "held only by workspace One: released");
    assert!(!stored(&app, &edited), "held only by a revision in workspace One: released");
    assert!(!stored(&app, &rows.attachment), "its dataset's file: released");
    assert!(stored(&app, &shared), "workspace Two still holds it");
    assert!(stored(&app, &fresh), "attached within the grace period: kept");
    assert!(app.request(&r.meta.id).is_err());
    // The released files' index entries went with their content.
    let index: Vec<serde_json::Value> = app.store.list(kind::IMPORT_SOURCE, None).unwrap();
    assert_eq!(index.len(), 2, "{index:?}");

    // Once its grace period is over and no saved item names it, the cleanup
    // releases it.
    assert_eq!(app.clean_up_storage().unwrap(), StorageCleanup::default(), "still within the grace period");
    attached_days_ago(&app, &fresh, 31);
    assert_eq!(app.clean_up_storage().unwrap().released_attachments, 1);
    assert!(!stored(&app, &fresh));
    assert!(stored(&app, &shared));
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

    let done = app.clean_up_storage().unwrap();
    assert_eq!(done, StorageCleanup { released_attachments: 1, ..Default::default() });
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
fn a_cleanup_removes_orphaned_revisions_and_the_files_only_they_name() {
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let ws = app.create_workspace("W").unwrap().meta.id;
    let other = app.create_workspace("Other").unwrap().meta.id;
    let gone = app.put_attachment("gone.bin", b"payload of a request deleted long ago", None).unwrap();
    let shared = app.put_attachment("shared.bin", b"payload another workspace still holds", None).unwrap();
    let again = b"payload of a deleted request, attached again to a draft";
    let reattached = app.put_attachment("again.bin", again, None).unwrap();
    let old = app.create_request(&ws, None, "old", upload(&gone)).unwrap();
    let old = app.save_request(RequestDefinition { spec: upload(&shared), ..old }).unwrap();
    app.save_request(RequestDefinition { spec: upload(&reattached), ..old.clone() }).unwrap();
    let kept = app.create_request(&other, None, "kept", upload(&shared)).unwrap();
    for a in [&gone, &shared, &reattached] {
        attached_days_ago(&app, a, 31);
    }
    // As a build before deletes removed revisions left it: the request is
    // gone, its revisions are not.
    app.store.delete(kind::REQUEST, &old.meta.id).unwrap();
    assert_eq!(revisions_of(&app, &old.meta.id), 3);
    // Attaching it again restarts its wait: a draft may hold it now.
    app.put_attachment("again.bin", again, None).unwrap();

    let done = app.clean_up_storage().unwrap();
    assert_eq!(done, StorageCleanup { orphaned_revisions: 3, released_attachments: 1, ..Default::default() });
    assert_eq!(revisions_of(&app, &old.meta.id), 0, "the orphaned revisions are removed");
    assert_eq!(revisions_of(&app, &kept.meta.id), 1, "a revision of a request that exists is kept");
    assert!(!stored(&app, &gone), "named only by the orphaned revisions: released");
    assert!(stored(&app, &reattached), "attached again within the grace period: kept");
    assert!(stored(&app, &shared), "a saved request in another workspace references it: kept");
    assert_eq!(app.clean_up_storage().unwrap(), StorageCleanup::default(), "a second pass finds nothing");

    // Its new wait over and still not saved, it is released.
    attached_days_ago(&app, &reattached, 31);
    assert_eq!(app.clean_up_storage().unwrap().released_attachments, 1);
    assert!(!stored(&app, &reattached));
    assert!(stored(&app, &shared));
}

#[test]
fn opening_a_profile_cleans_up_at_most_once_a_day_and_keeps_the_last_pass() {
    assert_eq!(CLEANUP_INTERVAL.as_secs(), 24 * 60 * 60, "the documented interval");
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    // Opening the new profile ran a pass.
    let first = app.last_storage_cleanup().unwrap().expect("the pass at open is kept");
    assert_eq!(first.result, StorageCleanup::default());
    assert!(since_last_pass(&app) < chrono::Duration::minutes(5));
    let ws = app.create_workspace("W").unwrap().meta.id;
    let gone = app.put_attachment("gone.bin", b"payload of a request deleted long ago", None).unwrap();
    let old = app.create_request(&ws, None, "old", upload(&gone)).unwrap();
    attached_days_ago(&app, &gone, 31);
    app.store.delete(kind::REQUEST, &old.meta.id).unwrap();

    // Within a day of that pass, opening the profile runs none.
    let app = reopen(app);
    assert_eq!(revisions_of(&app, &old.meta.id), 1);
    assert!(stored(&app, &gone));
    assert_eq!(app.last_storage_cleanup().unwrap(), Some(first));
    assert_eq!(app.clean_up_storage_if_due().unwrap(), None);

    // A day later, it does.
    last_pass_ran_hours_ago(&app, 25);
    let app = reopen(app);
    assert_eq!(revisions_of(&app, &old.meta.id), 0);
    assert!(!stored(&app, &gone));
    let last = app.last_storage_cleanup().unwrap().unwrap();
    assert_eq!(last.result, StorageCleanup { orphaned_revisions: 1, released_attachments: 1, ..Default::default() });
    assert!(since_last_pass(&app) < chrono::Duration::minutes(5));
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
    let named = vec![
        UndecodableObject { kind: kind::REQUEST.into(), id },
        UndecodableObject { kind: kind::REVISION.into(), id: damaged.revision_id.unwrap().to_string() },
    ];
    assert_eq!(done.undecodable, named);
    assert_eq!(done.orphaned_revisions, 0);
    assert_eq!(revisions_of(&app, &damaged.meta.id), 1, "the revision is retained");
    assert_eq!(done.released_attachments, 0);
    assert!(stored(&app, &abandoned), "the damaged request could name it: kept");
    // The pass is kept, so the damaged row can be found.
    assert_eq!(app.last_storage_cleanup().unwrap().unwrap().result.undecodable, named);

    // A day later, nothing it read has changed: opening the profile does not
    // decode everything again only to find the same. It still opens.
    last_pass_ran_hours_ago(&app, 25);
    let app = reopen(app);
    assert!(stored(&app, &abandoned));
    assert_eq!(app.clean_up_storage_if_due().unwrap(), None);
    assert!(since_last_pass(&app) > chrono::Duration::hours(24), "no pass ran");

    // Once the damaged row is deleted, the next pass releases the file.
    app.store.delete(kind::REQUEST, &damaged.meta.id).unwrap();
    let done = app.clean_up_storage_if_due().unwrap().expect("something it read changed");
    assert_eq!(done.released_attachments, 1);
    assert!(done.undecodable.is_empty());
    assert!(!stored(&app, &abandoned));
    assert!(app.last_storage_cleanup().unwrap().unwrap().result.undecodable.is_empty());
}

#[test]
fn a_mark_with_no_time_ages_from_the_first_pass_that_sees_it() {
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let legacy = app.put_attachment("legacy.bin", b"attached before the time was recorded", None).unwrap();
    // As a build before the time was recorded wrote it: marked, with no time.
    let (id, mut entry) = index_entry(&app, &legacy);
    entry.as_object_mut().unwrap().remove("attached_at");
    app.store.put(kind::IMPORT_SOURCE, &id, None, None, 0.0, &entry).unwrap();

    let before = chrono::Utc::now().timestamp_millis();
    assert_eq!(app.clean_up_storage().unwrap(), StorageCleanup::default(), "its age is unknown: kept");
    assert!(stored(&app, &legacy));
    let (_, entry) = index_entry(&app, &legacy);
    assert_eq!(entry["user"], true, "{entry}");
    assert!(entry["attached_at"].as_i64().is_some_and(|t| t >= before), "the pass recorded when it first saw it: {entry}");

    // From then on it ages like any other: past the grace period and never
    // saved, it is released.
    attached_days_ago(&app, &legacy, 31);
    assert_eq!(app.clean_up_storage().unwrap().released_attachments, 1);
    assert!(!stored(&app, &legacy));
}

#[test]
fn a_write_between_the_read_and_the_removals_makes_the_cleanup_read_again() {
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let ws = app.create_workspace("W").unwrap().meta.id;
    let abandoned = app.put_attachment("abandoned.bin", b"attached to a draft saved while the pass runs", None).unwrap();
    attached_days_ago(&app, &abandoned, 31);

    // After the first read found the file unreferenced, and before its write
    // transaction, a save references it.
    let mut reads = 0;
    let save_once = || {
        reads += 1;
        if reads == 1 {
            app.create_request(&ws, None, "saved", upload(&abandoned)).unwrap();
        }
    };
    let done = app.clean_up_storage_between_phases(save_once).unwrap();
    assert_eq!(reads, 2, "the write sent the pass back to read again");
    assert_eq!(done, StorageCleanup::default(), "the second read saw the reference");
    assert!(stored(&app, &abandoned), "a saved request references it: kept");
    // Held by a saved item now: its mark is dropped.
    let (_, entry) = index_entry(&app, &abandoned);
    assert!(entry.get("user").is_none(), "{entry}");

    // A profile that changes before every write transaction is left as it is
    // until a later pass.
    let other = app.put_attachment("other.bin", b"attached to a draft never saved", None).unwrap();
    attached_days_ago(&app, &other, 31);
    let mut writes = 0;
    let keep_writing = || {
        writes += 1;
        app.create_workspace(&format!("W{writes}")).unwrap();
    };
    let e = app.clean_up_storage_between_phases(keep_writing).unwrap_err();
    assert!(e.to_string().contains("kept changing"), "{e}");
    assert!(writes > 1, "it read again before giving up");
    assert!(stored(&app, &other), "nothing was released");
    assert_eq!(app.clean_up_storage().unwrap().released_attachments, 1, "the next pass releases it");
    assert!(!stored(&app, &other));
}

#[test]
fn a_mark_stamped_by_a_pass_an_undecodable_object_blocked_does_not_make_the_next_one_due() {
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let ws = app.create_workspace("W").unwrap().meta.id;
    let damaged = app.create_request(&ws, None, "damaged", RequestSpec::http("GET", "http://127.0.0.1:9/")).unwrap();
    // A pass decodes the referrers only when there is a file to release.
    let abandoned = app.put_attachment("abandoned.bin", b"attached to a draft never saved", None).unwrap();
    attached_days_ago(&app, &abandoned, 31);
    let legacy = app.put_attachment("legacy.bin", b"attached before the time was recorded", None).unwrap();
    let (id, mut entry) = index_entry(&app, &legacy);
    entry.as_object_mut().unwrap().remove("attached_at");
    app.store.put(kind::IMPORT_SOURCE, &id, None, None, 0.0, &entry).unwrap();
    let db = rusqlite::Connection::open(app.dir.join(DB_FILE)).unwrap();
    let row = damaged.meta.id.to_string();
    db.execute("UPDATE objects SET payload=x'00' WHERE kind=?1 AND id=?2", rusqlite::params![kind::REQUEST, row]).unwrap();
    drop(db);

    let done = app.clean_up_storage().unwrap();
    assert_eq!(done.undecodable.len(), 2, "the damaged parent also blocks its revision");
    assert_eq!(done.orphaned_revisions, 0);
    assert_eq!(revisions_of(&app, &damaged.meta.id), 1, "no revision is deleted");
    assert_eq!(done.released_attachments, 0);
    let (_, entry) = index_entry(&app, &legacy);
    assert!(entry["attached_at"].as_i64().is_some(), "stamped though the pass released nothing: {entry}");

    // The kept digest covers the stamped mark: a day later, nothing changed
    // since, so no pass is due.
    last_pass_ran_hours_ago(&app, 25);
    let app = reopen(app);
    assert_eq!(app.clean_up_storage_if_due().unwrap(), None);
    assert!(since_last_pass(&app) > chrono::Duration::hours(24), "no pass ran");
    assert!(stored(&app, &abandoned) && stored(&app, &legacy));
}

/// Overwrite the stored payload of `kind` row `id`, as damage would, leaving
/// its index and write time as they were.
fn damage(app: &App, kind: &str, id: &Id) {
    let db = rusqlite::Connection::open(app.dir.join(DB_FILE)).unwrap();
    db.execute("UPDATE objects SET payload=x'00' WHERE kind=?1 AND id=?2", rusqlite::params![kind, id.to_string()]).unwrap();
}

#[test]
fn a_revision_that_does_not_decode_survives_its_requests_delete_and_can_be_removed() {
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let ws = app.create_workspace("W").unwrap().meta.id;
    let gone = app.put_attachment("gone.bin", b"payload of a request whose revision is damaged", None).unwrap();
    let damaged = app.create_request(&ws, None, "damaged", upload(&gone)).unwrap();
    let live = app.create_request(&ws, None, "live", RequestSpec::http("GET", "http://127.0.0.1:9/")).unwrap();
    attached_days_ago(&app, &gone, 31);
    let revision = damaged.revision_id.unwrap();
    damage(&app, kind::REVISION, &revision);

    // The delete keeps the revision: it could name any stored file.
    app.delete_request(&damaged.meta.id).unwrap();
    assert_eq!(revisions_of(&app, &damaged.meta.id), 1);
    let done = app.clean_up_storage().unwrap();
    assert_eq!(done.undecodable, vec![UndecodableObject { kind: kind::REVISION.into(), id: revision.to_string() }]);
    assert!(stored(&app, &gone), "the damaged revision blocks every release");

    let found = app.undecodable_revisions().unwrap();
    assert_eq!(found.iter().map(|r| (r.id.clone(), r.cause)).collect::<Vec<_>>(), vec![(revision.to_string(), Undecodable::Damaged)]);
    // A revision that decodes is never removed here, nor with a damaged one.
    let kept = live.revision_id.unwrap();
    let e = app.remove_undecodable_revisions(&[kept]).unwrap_err();
    assert!(e.to_string().contains("decodes"), "{e}");
    assert!(app.remove_undecodable_revisions(&[revision, kept]).is_err());
    assert!(app.remove_undecodable_revisions(&[]).is_err());
    assert_eq!(revisions_of(&app, &live.meta.id), 1);
    assert_eq!(revisions_of(&app, &damaged.meta.id), 1);
    assert!(!app.dir.join("checkpoints").exists(), "a refused removal takes no checkpoint");

    let removed = app.remove_undecodable_revisions(&[revision]).unwrap();
    assert_eq!(removed.removed, vec![revision.to_string()]);
    assert!(app.dir.join("checkpoints").join(&removed.checkpoint).is_file(), "a checkpoint keeps the removed row: {removed:?}");
    assert_eq!(revisions_of(&app, &damaged.meta.id), 0);
    assert_eq!(app.undecodable_revisions().unwrap(), Vec::<UndecodableRevision>::new());
    assert!(app.remove_undecodable_revisions(&[revision]).is_err(), "already removed");

    // Nothing blocks the cleanup any more: the file only it could name goes.
    let done = app.clean_up_storage().unwrap();
    assert!(done.undecodable.is_empty(), "{done:?}");
    assert_eq!(done.released_attachments, 1);
    assert!(!stored(&app, &gone));
    assert_eq!(revisions_of(&app, &live.meta.id), 1, "the live request's revision is kept");
}

#[test]
fn a_pass_looks_for_orphans_again_only_once_a_revision_or_request_row_changed() {
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let ws = app.create_workspace("W").unwrap().meta.id;
    let r = app.create_request(&ws, None, "r", RequestSpec::http("GET", "http://127.0.0.1:9/")).unwrap();
    assert_eq!(app.clean_up_storage().unwrap(), StorageCleanup::default());

    // Damage that leaves every row's index and write time as they were: with
    // no file to release, a pass reads no revision, so it finds nothing.
    let revision = r.revision_id.unwrap();
    damage(&app, kind::REVISION, &revision);
    assert_eq!(app.clean_up_storage().unwrap(), StorageCleanup::default());

    // Once a request row is gone, every revision is authenticated again.
    app.store.delete(kind::REQUEST, &r.meta.id).unwrap();
    let done = app.clean_up_storage().unwrap();
    assert_eq!(done.undecodable, vec![UndecodableObject { kind: kind::REVISION.into(), id: revision.to_string() }]);
    assert_eq!(done.orphaned_revisions, 0);
    assert_eq!(revisions_of(&app, &r.meta.id), 1, "a revision that does not decode is kept");
}

#[test]
fn damaged_revisions_are_removed_together_behind_one_checkpoint() {
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let ws = app.create_workspace("W").unwrap().meta.id;
    let revisions: Vec<Id> = (0..3)
        .map(|n| app.create_request(&ws, None, &format!("r{n}"), RequestSpec::http("GET", "http://127.0.0.1:9/")).unwrap())
        .map(|r| r.revision_id.unwrap())
        .collect();
    for revision in &revisions {
        damage(&app, kind::REVISION, revision);
    }

    let removed = app.remove_undecodable_revisions(&revisions).unwrap();
    let mut ids: Vec<String> = revisions.iter().map(Id::to_string).collect();
    ids.sort();
    let mut gone = removed.removed.clone();
    gone.sort();
    assert_eq!(gone, ids);
    let taken = std::fs::read_dir(app.dir.join("checkpoints")).unwrap().count();
    assert_eq!(taken, 1, "one checkpoint keeps every removed row");
    assert!(app.undecodable_revisions().unwrap().is_empty());
}

#[test]
fn a_revision_a_newer_anvil_may_have_written_is_listed_but_kept() {
    let root = tempfile::tempdir().unwrap();
    let (app, key) = new_app_with_key(root.path());
    let ws = app.create_workspace("W").unwrap().meta.id;
    let r = app.create_request(&ws, None, "r", RequestSpec::http("GET", "http://127.0.0.1:9/")).unwrap();
    let revision = r.revision_id.unwrap();

    // Sealed under the profile's key, so it authenticates, but with a body
    // kind this version does not know, as a newer Anvil could write.
    let mut newer = app.store.get::<serde_json::Value>(kind::REVISION, &revision).unwrap().expect("the revision");
    newer["spec"]["body"] = serde_json::json!({ "type": "from_a_newer_anvil" });
    let aad = format!("anvil/v1/objects/{}/{revision}", kind::REVISION);
    let payload = crypto::seal(&key, aad.as_bytes(), &serde_json::to_vec(&newer).unwrap());
    let db = rusqlite::Connection::open(app.dir.join(DB_FILE)).unwrap();
    let sql = "UPDATE objects SET payload=?1 WHERE kind=?2 AND id=?3";
    db.execute(sql, rusqlite::params![payload, kind::REVISION, revision.to_string()]).unwrap();

    let found = app.undecodable_revisions().unwrap();
    assert_eq!(found.iter().map(|r| (r.id.clone(), r.cause)).collect::<Vec<_>>(), vec![(revision.to_string(), Undecodable::UnknownFormat)]);
    let e = app.remove_undecodable_revisions(&[revision]).unwrap_err();
    assert!(e.to_string().contains("newer Anvil"), "{e}");
    assert_eq!(revisions_of(&app, &r.meta.id), 1, "it is kept for the version that wrote it");
    assert!(!app.dir.join("checkpoints").exists(), "a refused removal takes no checkpoint");
}
