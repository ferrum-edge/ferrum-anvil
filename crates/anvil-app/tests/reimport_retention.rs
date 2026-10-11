//! Production imports, revision deletion, backup and attachment retention.
//! SQL-only metadata edits never authorize legacy revision data or routing.

use anvil_app::exec::SendOptions;
use anvil_app::profiles::ProfileManager;
use anvil_app::specs::{SpecImported, SpecTarget};
use anvil_app::{App, AppError};
use anvil_domain::Id;
use anvil_domain::request::{AttachmentRef, Body, RequestSpec};
use anvil_domain::workspace::{RequestDefinition, RequestRevision};
use anvil_import::{ImportOptions, ReimportApproval};
use anvil_portability::ExportMode;
use anvil_storage::store::DB_FILE;
use anvil_storage::{KdfParams, StoreError, kind};
use rusqlite::{Connection, params};
use serde_json::{Value, json};
use std::collections::HashSet;

const PASSPHRASE: &str = "test backup passphrase";

fn open() -> (tempfile::TempDir, App) {
    let root = tempfile::tempdir().unwrap();
    let pm = ProfileManager::new(root.path());
    let (profile, key, _) = pm.create_passphrase("reimport retention", PASSPHRASE, KdfParams::testing()).unwrap();
    let header = anvil_storage::vault::read_header(&profile.dir).unwrap();
    let app = App::open(profile.dir, header, key).unwrap();
    (root, app)
}

/// These raw-metadata fixtures exercise intentional low-level historical
/// recovery. Enrolled active profiles reject the same edits at the catalogue.
fn open_historical() -> (tempfile::TempDir, App) {
    let root = tempfile::tempdir().unwrap();
    let c = anvil_storage::vault::create_passphrase_profile(root.path(), "historical", PASSPHRASE, KdfParams::testing()).unwrap();
    let app = App::open(root.path().to_path_buf(), c.header, c.dek).unwrap();
    (root, app)
}

fn db(app: &App) -> Connection {
    Connection::open(app.dir.join(DB_FILE)).unwrap()
}

fn collection(names: &[&str], version: u64) -> Vec<u8> {
    let items: Vec<Value> = names
        .iter()
        .map(|name| {
            json!({
                "id": name,
                "name": name,
                "request": {
                    "method": "GET",
                    "url": {"raw": format!("https://example.invalid/{name}")},
                    "header": [{"key": "X-Version", "value": version.to_string()}]
                }
            })
        })
        .collect();
    serde_json::to_vec(&json!({
        "info": {
            "name": "Retention",
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
        },
        "auth": {"type": "noauth"},
        "item": items
    }))
    .unwrap()
}

fn import(app: &App, bytes: &[u8]) -> SpecImported {
    app.spec_import(bytes, "collection.json", &ImportOptions::default(), SpecTarget::NewWorkspace).unwrap()
}

fn named(app: &App, ws: &Id, name: &str) -> RequestDefinition {
    app.requests(ws).unwrap().into_iter().find(|r| r.name == name).unwrap()
}

fn original(app: &App, ws: &Id, bytes: &[u8]) -> AttachmentRef {
    let rec = app.spec_sources(ws).unwrap().pop().unwrap();
    AttachmentRef::Stored { sha256: rec.original_sha256, size: bytes.len() as u64, file_name: "collection.json".into(), media_type: None }
}

fn sha(attachment: &AttachmentRef) -> &str {
    let AttachmentRef::Stored { sha256, .. } = attachment else { panic!("stored attachment") };
    sha256
}

fn with_attachment(mut request: RequestDefinition, attachment: &AttachmentRef) -> RequestDefinition {
    request.spec.body = Body::Binary { attachment: attachment.clone(), content_type: None };
    request
}

fn index(app: &App, attachment: &AttachmentRef) -> Value {
    app.store.list::<Value>(kind::IMPORT_SOURCE, None).unwrap().into_iter().find(|v| v["attachment"] == sha(attachment)).unwrap()
}

// Include ciphertext, all routing metadata, blob rows and pins in rollback checks.
fn inventory(app: &App) -> Vec<String> {
    let conn = db(app);
    let mut statement = conn
        .prepare(
            "SELECT 'object:' || quote(kind) || quote(id) || quote(workspace_id) ||
                    quote(parent_id) || quote(sort_key) || quote(updated_at) ||
                    quote(payload) AS row
             FROM objects
             UNION ALL
             SELECT 'blob:' || quote(id) || quote(size) || quote(created_at) || quote(payload)
             FROM blobs
             UNION ALL SELECT 'meta:' || quote(key) || quote(value) FROM meta
             ORDER BY row",
        )
        .unwrap();
    statement.query_map([], |r| r.get(0)).unwrap().collect::<rusqlite::Result<_>>().unwrap()
}

#[test]
fn production_create_add_save_and_reimport_delete_leave_a_restorable_full_backup() {
    let (_root, app) = open();
    let v1 = collection(&["removed", "kept"], 1);
    let done = import(&app, &v1);
    let attachment = original(&app, &done.workspace_id, &v1);
    assert!(!index(&app, &attachment)["user"].as_bool().unwrap_or(false));
    let removed = named(&app, &done.workspace_id, "removed");
    assert_eq!(removed.revision_id, None, "new imports create requests without revisions");
    let removed = app.save_request(with_attachment(removed, &attachment)).unwrap();
    let old_revision = removed.revision_id.unwrap();
    let mut changed = removed;
    changed.spec.method = "POST".into();
    changed.spec.body = Body::None;
    let removed = app.save_request(changed).unwrap();
    assert_eq!(app.revision(&old_revision).unwrap().request_id, removed.meta.id);

    let v2 = collection(&["kept", "added"], 2);
    let plan = app.spec_reimport_plan(&done.import_id, &v2).unwrap();
    assert_eq!(plan.added.len(), 1);
    let approval = ReimportApproval { delete: vec![removed.meta.id], ..Default::default() };
    app.spec_reimport_apply(&done.import_id, &v2, "v2.json", &approval).unwrap();
    assert!(app.request(&removed.meta.id).is_err());
    assert!(app.revision(&old_revision).is_err());
    assert!(app.revision(&removed.revision_id.unwrap()).is_err());
    assert!(app.get_attachment(sha(&attachment)).unwrap().is_none());
    assert!(
        app.store
            .object_meta(kind::REVISION)
            .unwrap()
            .iter()
            .all(|m| { m.parent_id.as_deref() != Some(removed.meta.id.to_string().as_str()) })
    );

    let added = named(&app, &done.workspace_id, "added");
    assert_eq!(added.revision_id, None, "an added request needs no missing-parent revision write");
    let added = app.save_request(added).unwrap();
    assert_eq!(app.revision(&added.revision_id.unwrap()).unwrap().spec, added.spec);
    let kept = named(&app, &done.workspace_id, "kept");
    assert_eq!(app.revision(&kept.revision_id.unwrap()).unwrap().spec, kept.spec);
    let created =
        app.create_request(&done.workspace_id, None, "ordinary create", RequestSpec::http("GET", "https://example.invalid/new")).unwrap();
    assert_eq!(app.revision(&created.revision_id.unwrap()).unwrap().spec, created.spec);

    let (bytes, preview) = app.export_backup_with(PASSPHRASE, KdfParams::testing()).unwrap();
    assert_eq!(preview.manifest.counts[kind::REQUEST], 3);
    assert_eq!(preview.manifest.counts[kind::REVISION], 3);
    assert!(preview.manifest.excluded.is_empty());
    let (_target_root, target) = open();
    target.restore_preview(&bytes, Some(PASSPHRASE), anvil_portability::plan::ConflictPolicy::Merge).unwrap();
    target.restore(&bytes, Some(PASSPHRASE), anvil_portability::plan::ConflictPolicy::Merge).unwrap();
    assert_eq!(target.requests(&done.workspace_id).unwrap().len(), 3);
    assert_eq!(target.revision(&added.revision_id.unwrap()).unwrap().spec, added.spec);
    assert_eq!(app.clean_up_storage().unwrap().orphaned_revisions, 0);
}

#[test]
fn reimport_delete_preserves_an_undecodable_revision_and_its_imported_attachment() {
    let (_root, app) = open();
    let v1 = collection(&["removed"], 1);
    let done = import(&app, &v1);
    let attachment = original(&app, &done.workspace_id, &v1);
    let removed = with_attachment(named(&app, &done.workspace_id, "removed"), &attachment);
    let removed = app.save_request(removed).unwrap();
    let revision_id = removed.revision_id.unwrap();
    db(&app).execute("UPDATE objects SET payload=x'00' WHERE kind=?1 AND id=?2", params![kind::REVISION, revision_id.to_string()]).unwrap();
    let v2 = collection(&["added"], 2);
    let approval = ReimportApproval { delete: vec![removed.meta.id], ..Default::default() };
    app.spec_reimport_apply(&done.import_id, &v2, "v2.json", &approval).unwrap();
    assert!(app.request(&removed.meta.id).is_err());
    assert!(app.store.object_meta(kind::REVISION).unwrap().iter().any(|m| m.id == revision_id.to_string()));
    let done = app.clean_up_storage().unwrap();
    assert_eq!((done.orphaned_revisions, done.released_attachments), (0, 0));
    assert_eq!(done.undecodable.len(), 1);
    app.store.prune_history(0, 0).unwrap();
    assert_eq!(app.get_attachment(sha(&attachment)).unwrap(), Some(v1));
    assert!(!index(&app, &attachment)["user"].as_bool().unwrap_or(false));
}

#[test]
fn a_late_reimport_failure_rolls_back_added_requests_cascade_revisions_and_blob_pins() {
    let (_root, app) = open();
    let v1 = collection(&["removed", "kept"], 1);
    let done = import(&app, &v1);
    let attachment = original(&app, &done.workspace_id, &v1);
    let removed = with_attachment(named(&app, &done.workspace_id, "removed"), &attachment);
    let removed = app.save_request(removed).unwrap();
    let before = inventory(&app);
    db(&app)
        .execute_batch(
            "CREATE TRIGGER refuse_source_write BEFORE INSERT ON objects
             WHEN NEW.kind='spec_source' BEGIN SELECT RAISE(ABORT, 'injected failure'); END;",
        )
        .unwrap();
    let approval = ReimportApproval { delete: vec![removed.meta.id], ..Default::default() };
    let v2 = collection(&["kept", "added"], 2);
    assert!(matches!(app.spec_reimport_apply(&done.import_id, &v2, "v2.json", &approval), Err(AppError::Store(StoreError::Db(_)))));
    assert_eq!(inventory(&app), before, "all writes, deletions, releases and pins roll back");
    assert_eq!(app.revision(&removed.revision_id.unwrap()).unwrap().spec, removed.spec);
    assert_eq!(app.get_attachment(sha(&attachment)).unwrap(), Some(v1));
}

// A released profile orphan, with its sole file imported as user:false.
// Replacing provenance must retain that file through the restricted scan.
fn orphan(app: &App) -> (Id, Id, AttachmentRef, Vec<u8>) {
    let v1 = collection(&["old"], 1);
    let done = import(app, &v1);
    let attachment = original(app, &done.workspace_id, &v1);
    let request = with_attachment(named(app, &done.workspace_id, "old"), &attachment);
    let request = app.save_request(request).unwrap();
    app.store.delete(kind::REQUEST, &request.meta.id).unwrap();
    let v2 = collection(&["new"], 2);
    app.spec_reimport_apply(&done.import_id, &v2, "v2.json", &ReimportApproval::default()).unwrap();
    assert!(!index(app, &attachment)["user"].as_bool().unwrap_or(false));
    assert_eq!(app.get_attachment(sha(&attachment)).unwrap(), Some(v1.clone()));
    (request.meta.id, request.revision_id.unwrap(), attachment, v1)
}

#[test]
fn old_orphan_metadata_cannot_route_revision_data_and_backup_retains_its_imported_file() {
    let (_root, app) = open_historical();
    let (request_id, revision_id, attachment, bytes) = orphan(&app);
    let other = app.create_workspace("Other").unwrap().meta.id;
    let live = app.create_request(&other, None, "live", RequestSpec::http("GET", "https://other.invalid/")).unwrap();
    // Forge both indexes to a live foreign request, then clear them. Neither
    // edit changes the authenticated missing parent or supplies an old owner.
    for indexes in [Some((other.to_string(), live.meta.id.to_string())), None] {
        let (owner, parent) = match indexes {
            Some((owner, parent)) => (Some(owner), Some(parent)),
            None => (None, None),
        };
        db(&app)
            .execute(
                "UPDATE objects SET workspace_id=?1,parent_id=?2 WHERE kind=?3 AND id=?4",
                params![owner, parent, kind::REVISION, revision_id.to_string()],
            )
            .unwrap();
        let before = inventory(&app);
        assert!(app.revision(&revision_id).is_err());
        assert!(matches!(app.store.get::<Value>(kind::REVISION, &revision_id), Err(StoreError::Integrity)));
        assert!(app.store.list::<RequestRevision>(kind::REVISION, None).is_err());
        if owner.is_some() {
            assert!(app.store.list::<Value>(kind::REVISION, Some(&other)).is_err());
        }
        let graph = app.graph(Some(&other), false, false).unwrap();
        assert!(graph.revisions.iter().all(|r| r.id != revision_id));
        assert!(graph.attachments.is_empty(), "an orphan's file cannot enter a workspace export");
        app.export_preview(Some(&other), ExportMode::ShareSafely, false).unwrap();
        assert!(app.build_context(Some(request_id), &other, None, &SendOptions::default(),).is_err());
        let refs = app.store.read_consistently(|s| s.orphan_revision_attachment_refs_for_retention(&revision_id)).unwrap().unwrap();
        assert_eq!(refs, HashSet::from([sha(&attachment).to_string()]));
        let contents = app.backup_contents().unwrap();
        assert!(contents.objects.iter().all(|o| o.id != revision_id.to_string()));
        assert!(contents.attachments.iter().any(|a| a.sha256 == sha(&attachment)));
        let (_, preview) = app.export_backup_with(PASSPHRASE, KdfParams::testing()).unwrap();
        assert_eq!(preview.manifest.counts[kind::REVISION], 1, "only the live revision");
        assert_eq!(preview.manifest.counts["attachments"], 2);
        assert_eq!(preview.manifest.excluded.len(), 1);
        assert!(preview.manifest.excluded[0].contains(&format!("orphan revision {revision_id}")));
        assert_eq!(inventory(&app), before, "backup and inspection never reseal or adopt an orphan");
    }

    let blob = index(&app, &attachment)["blob"].as_str().unwrap().to_string();
    assert!(!app.release_attachment(sha(&attachment)).unwrap(), "the orphan keeps its reference");
    app.store.prune_history(0, 0).unwrap();
    assert_eq!(app.get_attachment(sha(&attachment)).unwrap(), Some(bytes.clone()));
    assert!(app.store.get_blob(&blob).unwrap().is_some(), "the import's blob pin remains");
    let checkpoint = app.store.checkpoint("before-orphan-cleanup").unwrap();
    let done = app.clean_up_storage().unwrap();
    assert_eq!(done.orphaned_revisions, 1);
    assert_eq!(done.released_attachments, 1);
    assert!(done.undecodable.is_empty());
    assert!(app.get_attachment(sha(&attachment)).unwrap().is_none());
    assert!(app.store.get_blob(&blob).unwrap().is_none());
    app.store.restore_checkpoint(&checkpoint).unwrap();
    app.store.prune_history(0, 0).unwrap();
    assert_eq!(app.get_attachment(sha(&attachment)).unwrap(), Some(bytes));
    assert!(app.store.object_meta(kind::REVISION).unwrap().iter().any(|m| m.id == revision_id.to_string()));
    assert!(app.revision(&revision_id).is_err(), "a checkpoint does not adopt historical ownership");
}

#[test]
fn deleting_a_workspace_cannot_drop_an_orphans_references_using_a_forged_owner_index() {
    let (_root, app) = open_historical();
    let (_request_id, revision_id, attachment, bytes) = orphan(&app);
    let foreign = app.create_workspace("Foreign").unwrap().meta.id;
    db(&app)
        .execute(
            "UPDATE objects SET workspace_id=?1 WHERE kind=?2 AND id=?3",
            params![foreign.to_string(), kind::REVISION, revision_id.to_string()],
        )
        .unwrap();
    app.delete_workspace(&foreign).unwrap();
    assert!(app.store.object_meta(kind::REVISION).unwrap().iter().any(|m| m.id == revision_id.to_string()));
    assert!(app.revision(&revision_id).is_err());
    assert_eq!(app.get_attachment(sha(&attachment)).unwrap(), Some(bytes));
    assert!(!app.release_attachment(sha(&attachment)).unwrap());
    let done = app.clean_up_storage().unwrap();
    assert_eq!((done.orphaned_revisions, done.released_attachments), (1, 1));
    assert!(app.get_attachment(sha(&attachment)).unwrap().is_none());
}

#[test]
fn blocked_cleanup_keeps_orphan_references_until_a_safe_pass_and_keeps_corrupt_orphan_rows() {
    let (_root, app) = open();
    let (_request_id, revision_id, attachment, bytes) = orphan(&app);
    let ws = app.create_workspace("Damaged").unwrap().meta.id;
    let damaged = app.create_request(&ws, None, "damaged", RequestSpec::http("GET", "https://damaged.invalid/")).unwrap();
    db(&app)
        .execute("UPDATE objects SET payload=x'00' WHERE kind=?1 AND id=?2", params![kind::REQUEST, damaged.meta.id.to_string()])
        .unwrap();
    let before = inventory(&app);
    let done = app.clean_up_storage().unwrap();
    assert_eq!((done.orphaned_revisions, done.released_attachments), (0, 0));
    assert_eq!(done.undecodable.len(), 2);
    assert!(app.store.object_meta(kind::REVISION).unwrap().iter().any(|m| m.id == revision_id.to_string()));
    app.store.prune_history(0, 0).unwrap();
    assert_eq!(app.get_attachment(sha(&attachment)).unwrap(), Some(bytes.clone()));
    assert!(!app.release_attachment(sha(&attachment)).unwrap());
    // Cleanup writes only its result note; all object rows, blobs and pins survive.
    let without_note = |rows: Vec<String>| rows.into_iter().filter(|r| !r.starts_with("meta:'note:storage_cleanup'")).collect::<Vec<_>>();
    assert_eq!(without_note(inventory(&app)), without_note(before));

    app.store.delete(kind::REQUEST, &damaged.meta.id).unwrap();
    let done = app.clean_up_storage().unwrap();
    assert_eq!((done.orphaned_revisions, done.released_attachments), (2, 1));
    assert!(app.get_attachment(sha(&attachment)).unwrap().is_none());

    let (_, corrupt_revision, corrupt_attachment, corrupt_bytes) = orphan(&app);
    let checkpoint = app.store.checkpoint("before-corrupt-orphan").unwrap();
    db(&app)
        .execute("UPDATE objects SET payload=x'00' WHERE kind=?1 AND id=?2", params![kind::REVISION, corrupt_revision.to_string()])
        .unwrap();
    let done = app.clean_up_storage().unwrap();
    assert_eq!((done.orphaned_revisions, done.released_attachments), (0, 0));
    assert!(done.undecodable.iter().any(|m| m.id == corrupt_revision.to_string()));
    assert!(app.store.object_meta(kind::REVISION).unwrap().iter().any(|m| m.id == corrupt_revision.to_string()));
    assert!(app.backup_preview().is_err(), "corrupt ciphertext is not silently excluded");
    app.store.prune_history(0, 0).unwrap();
    assert_eq!(app.get_attachment(sha(&corrupt_attachment)).unwrap(), Some(corrupt_bytes));
    app.store.restore_checkpoint(&checkpoint).unwrap();
    let done = app.clean_up_storage().unwrap();
    assert_eq!((done.orphaned_revisions, done.released_attachments), (1, 1));
    assert!(app.get_attachment(sha(&corrupt_attachment)).unwrap().is_none());
}
