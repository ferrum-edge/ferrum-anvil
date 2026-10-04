//! Hosted-only filesystem race proofs. The pause is inside the real native
//! selection/read/export entrypoint, not a substitute filesystem helper.

use super::{test_checkpoint, with_test_hook};
use crate::App;
use crate::file_grants::{FileGrants, FilePurpose, GrantError};
use crate::linked_files::{LinkedFileReferrer, LinkedFileState};
use crate::profiles::ProfileManager;
use anvil_domain::request::{AttachmentRef, Body, RequestSpec};
use anvil_domain::workspace::{Dataset, DatasetFormat, Meta};
use std::path::{Path, PathBuf};
use std::sync::{Arc, mpsc};
use std::time::Duration;

const CHOSEN: &[u8] = b"value\nchosen\n";
const OUTSIDE: &[u8] = b"value\noutside-secret-canary\n";

/// A bounded two-way rendezvous: I/O cannot continue until the actual rename
/// and symlink/junction operation completes. No timing sleeps are involved.
fn race<T: Send + 'static>(point: &'static str, operation: impl FnOnce() -> T + Send + 'static, interfere: impl FnOnce()) -> T {
    let (ready_tx, ready_rx) = mpsc::sync_channel(0);
    let (resume_tx, resume_rx) = mpsc::sync_channel(0);
    let (done_tx, done_rx) = mpsc::sync_channel(1);
    let worker = std::thread::spawn(move || {
        let result = with_test_hook(
            move |observed| {
                if observed == point {
                    ready_tx.send(()).unwrap();
                    resume_rx.recv_timeout(Duration::from_secs(30)).unwrap();
                }
            },
            operation,
        );
        assert!(done_tx.send(result).is_ok());
    });
    ready_rx.recv_timeout(Duration::from_secs(30)).expect("the real entrypoint reached its barrier");
    interfere();
    resume_tx.send(()).unwrap();
    let result = done_rx.recv_timeout(Duration::from_secs(30)).expect("the actual I/O finished without blocking");
    worker.join().unwrap();
    result
}

struct Tree {
    _root: tempfile::TempDir,
    ancestor: PathBuf,
    moved: PathBuf,
    outside: PathBuf,
}

impl Tree {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(root.path()).unwrap();
        let ancestor = base.join("selected");
        let outside = base.join("outside");
        std::fs::create_dir_all(ancestor.join("inner")).unwrap();
        std::fs::create_dir_all(outside.join("inner")).unwrap();
        std::fs::write(ancestor.join("inner/rows.csv"), CHOSEN).unwrap();
        std::fs::write(outside.join("inner/rows.csv"), OUTSIDE).unwrap();
        Self { _root: root, ancestor, moved: base.join("moved"), outside }
    }

    fn source(&self) -> PathBuf {
        self.ancestor.join("inner/rows.csv")
    }

    fn destination(&self) -> PathBuf {
        self.ancestor.join("inner/report.json")
    }

    fn original_dir(&self) -> PathBuf {
        if self.moved.exists() { self.moved.join("inner") } else { self.ancestor.join("inner") }
    }

    fn swap(&self, may_be_locked: bool) {
        match std::fs::rename(&self.ancestor, &self.moved) {
            Ok(()) => self.redirect(),
            Err(err) => {
                // cap-std retains non-delete-sharing directory handles on
                // Windows. Blocking the ancestor rename is the safe outcome.
                assert!(cfg!(windows) && may_be_locked, "unexpected rename failure: {err}");
                assert!(matches!(err.raw_os_error(), Some(5 | 32)), "unexpected Windows error: {err}");
                assert!(!self.moved.exists());
            }
        }
    }

    #[cfg(unix)]
    fn redirect(&self) {
        std::os::unix::fs::symlink(&self.outside, &self.ancestor).unwrap();
    }

    #[cfg(windows)]
    fn redirect(&self) {
        // Native junctions do not require the symbolic-link privilege.
        // Fail the hosted test if its CI account cannot create one; do not
        // silently skip all Windows race coverage.
        let output = std::process::Command::new("cmd.exe")
            .args(["/D", "/C", "mklink", "/J"])
            .arg(&self.ancestor)
            .arg(&self.outside)
            .output()
            .unwrap();
        assert!(output.status.success(), "native junction failed: {}", String::from_utf8_lossy(&output.stderr));
        use std::os::windows::fs::MetadataExt;
        assert_ne!(std::fs::symlink_metadata(&self.ancestor).unwrap().file_attributes() & 0x400, 0);
    }

    fn outside_untouched(&self) {
        assert_eq!(std::fs::read(self.outside.join("inner/rows.csv")).unwrap(), OUTSIDE);
        assert!(!self.outside.join("inner/report.json").exists());
        assert_eq!(std::fs::read_dir(self.outside.join("inner")).unwrap().count(), 1);
    }
}

fn app(root: &Path) -> App {
    let profiles = ProfileManager::new(root);
    let (profile, key, _) = profiles.create_passphrase("handles", "test passphrase", anvil_storage::KdfParams::testing()).unwrap();
    let header = anvil_storage::vault::read_header(&profile.dir).unwrap();
    App::open(profile.dir, header, key).unwrap()
}

fn dataset(app: &App, path: &Path) -> Dataset {
    let workspace = app.create_workspace("files").unwrap();
    app.save_dataset(Dataset {
        meta: Meta::new(),
        workspace_id: workspace.meta.id,
        name: "rows".into(),
        format: DatasetFormat::Csv,
        attachment: AttachmentRef::LinkedFile { path: path.to_str().unwrap().into() },
        sensitive_columns: vec![],
    })
    .unwrap()
}

fn assert_dataset_bytes(dataset: anvil_runner::dataset::RunDataset, expected: &[u8]) {
    use sha2::Digest;
    assert_eq!(dataset.sha256, hex::encode(sha2::Sha256::digest(expected)));
}

#[test]
fn linked_dataset_read_survives_a_real_ancestor_swap_without_reading_outside_bytes() {
    let tree = Tree::new();
    let profiles = tempfile::tempdir().unwrap();
    let app = app(profiles.path());
    let dataset = dataset(&app, &tree.source());
    app.bind_linked_file(LinkedFileReferrer::Dataset { id: dataset.meta.id }, &tree.source()).unwrap();
    let result = race("linked_read_selected", move || app.run_dataset(&dataset), || tree.swap(true));
    assert_dataset_bytes(result.unwrap(), CHOSEN);
    tree.outside_untouched();
}

#[test]
fn linked_request_resolver_uses_the_retained_selection_at_the_real_read_barrier() {
    let tree = Tree::new();
    let profiles = tempfile::tempdir().unwrap();
    let app = app(profiles.path());
    let workspace = app.create_workspace("files").unwrap();
    let attachment = AttachmentRef::LinkedFile { path: tree.source().to_str().unwrap().into() };
    let mut spec = RequestSpec::http("POST", "http://127.0.0.1:9");
    spec.body = Body::Binary { attachment: attachment.clone(), content_type: None };
    let request = app.create_request(&workspace.meta.id, None, "upload", spec).unwrap();
    app.bind_linked_file(LinkedFileReferrer::Request { id: request.meta.id }, &tree.source()).unwrap();
    let context = app.build_context(Some(request.meta.id), &workspace.meta.id, None, &Default::default()).unwrap();
    let result = race("linked_read_selected", move || context.attachments.load(&attachment), || tree.swap(true));
    assert_eq!(result.unwrap().as_ref(), CHOSEN);
    tree.outside_untouched();
}

#[test]
fn grant_write_creates_only_in_the_retained_parent_after_a_real_ancestor_swap() {
    let tree = Tree::new();
    let grants = FileGrants::default();
    let grant = grants.grant_write(FilePurpose::BundleExport, &tree.destination()).unwrap();
    let result = race(
        "write_selected",
        move || grants.write(&grant.token, FilePurpose::BundleExport, b"chosen export"),
        || tree.swap(true),
    );
    assert_eq!(result.unwrap(), 13);
    assert_eq!(std::fs::read(tree.original_dir().join("report.json")).unwrap(), b"chosen export");
    tree.outside_untouched();
}

#[test]
fn negative_controls_redirect_real_unprotected_read_and_export_on_posix_and_windows() {
    let tree = Tree::new();
    let source = tree.source();
    let read = race(
        "legacy_checked",
        move || {
            let canonical = std::fs::canonicalize(source).unwrap();
            test_checkpoint("legacy_checked");
            std::fs::read(canonical).unwrap()
        },
        || tree.swap(false),
    );
    assert_eq!(read, OUTSIDE, "the negative control must actually disclose the scratch outside canary");

    let tree = Tree::new();
    let destination = tree.destination();
    race(
        "legacy_checked",
        move || {
            let parent = std::fs::canonicalize(destination.parent().unwrap()).unwrap();
            test_checkpoint("legacy_checked");
            std::fs::write(parent.join("report.json"), b"redirected control").unwrap();
        },
        || tree.swap(false),
    );
    assert_eq!(std::fs::read(tree.outside.join("inner/report.json")).unwrap(), b"redirected control");
    assert!(!tree.original_dir().join("report.json").exists());
}

#[test]
fn native_linked_selection_refuses_an_ancestor_junction_or_symlink_swapped_after_canonicalization() {
    let tree = Tree::new();
    let profiles = tempfile::tempdir().unwrap();
    let app = app(profiles.path());
    let dataset = dataset(&app, &tree.source());
    let path = tree.source();
    let result = race(
        "choose_canonical",
        move || app.bind_linked_file(LinkedFileReferrer::Dataset { id: dataset.meta.id }, &path),
        || tree.swap(false),
    );
    assert!(result.is_err());
    tree.outside_untouched();
}

#[test]
fn native_export_selection_refuses_an_ancestor_junction_or_symlink_at_the_handle_open_barrier() {
    let tree = Tree::new();
    let destination = tree.destination();
    let result = race(
        "write_choose_canonical",
        move || FileGrants::default().grant_write(FilePurpose::BundleExport, &destination),
        || tree.swap(false),
    );
    assert!(result.is_err());
    tree.outside_untouched();
}

#[test]
fn a_destination_planted_after_sync_is_never_truncated_or_unlinked() {
    let tree = Tree::new();
    let grants = FileGrants::default();
    let grant = grants.grant_write(FilePurpose::BundleExport, &tree.destination()).unwrap();
    let result = race(
        "write_synced",
        move || grants.write(&grant.token, FilePurpose::BundleExport, b"our export"),
        || std::fs::write(tree.destination(), b"foreign replacement").unwrap(),
    );
    assert!(result.is_err());
    assert_eq!(std::fs::read(tree.destination()).unwrap(), b"foreign replacement");
    tree.outside_untouched();
}

#[test]
fn a_foreign_temporary_name_is_preserved_when_the_open_file_identity_disagrees() {
    let tree = Tree::new();
    let grants = FileGrants::default();
    let grant = grants.grant_write(FilePurpose::BundleExport, &tree.destination()).unwrap();
    let mut temporary = None;
    let result = race(
        "write_synced",
        move || grants.write(&grant.token, FilePurpose::BundleExport, b"our export"),
        || {
            let path = std::fs::read_dir(tree.original_dir())
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .find(|path| path.extension().is_some_and(|ext| ext == "partial"))
                .unwrap();
            std::fs::rename(&path, tree.original_dir().join("our-preserved-partial")).unwrap();
            std::fs::write(&path, b"foreign temporary").unwrap();
            temporary = Some(path);
        },
    );
    assert_eq!(result.unwrap_err(), GrantError::Changed);
    assert_eq!(std::fs::read(temporary.unwrap()).unwrap(), b"foreign temporary");
    assert_eq!(std::fs::read(tree.original_dir().join("our-preserved-partial")).unwrap(), b"our export");
    assert!(!tree.destination().exists());
    tree.outside_untouched();
}

#[test]
fn draft_publish_blocker_a_name_swap_after_identity_check_is_detected_but_not_rolled_back() {
    let tree = Tree::new();
    let grants = FileGrants::default();
    let grant = grants.grant_write(FilePurpose::BundleExport, &tree.destination()).unwrap();
    let result = race(
        "write_verified",
        move || grants.write(&grant.token, FilePurpose::BundleExport, b"our export"),
        || {
            let temporary = std::fs::read_dir(tree.original_dir())
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .find(|path| path.extension().is_some_and(|ext| ext == "partial"))
                .unwrap();
            std::fs::rename(&temporary, tree.original_dir().join("our-preserved-partial")).unwrap();
            std::fs::write(temporary, b"foreign temporary").unwrap();
        },
    );
    assert_eq!(result.unwrap_err(), GrantError::Changed);
    // This deliberately proves the remaining blocker: a name-based publish
    // can move the foreign source before the post-publish check refuses it.
    // Preserve both objects instead of attempting an unsafe rollback/unlink.
    assert_eq!(std::fs::read(tree.destination()).unwrap(), b"foreign temporary");
    assert_eq!(std::fs::read(tree.original_dir().join("our-preserved-partial")).unwrap(), b"our export");
    tree.outside_untouched();
}

#[test]
fn revoke_does_not_wait_for_export_io_and_a_reserved_write_keeps_its_existing_semantics() {
    let tree = Tree::new();
    let grants = Arc::new(FileGrants::default());
    let grant = grants.grant_write(FilePurpose::BundleExport, &tree.destination()).unwrap();
    let worker_grants = grants.clone();
    let token = grant.token.clone();
    let result = race(
        "write_synced",
        move || worker_grants.write(&token, FilePurpose::BundleExport, b"reserved before lock"),
        || grants.revoke_all(),
    );
    assert!(result.is_ok());
    assert_eq!(grants.write(&grant.token, FilePurpose::BundleExport, b"later").unwrap_err(), GrantError::Unknown);
    assert!(grants.is_empty());
    tree.outside_untouched();
}

#[test]
fn in_place_edits_remain_visible_but_atomic_replacement_needs_a_new_native_selection() {
    let tree = Tree::new();
    let profiles = tempfile::tempdir().unwrap();
    let app = app(profiles.path());
    let dataset = dataset(&app, &tree.source());
    let referrer = LinkedFileReferrer::Dataset { id: dataset.meta.id };
    let binding = app.bind_linked_file(referrer, &tree.source()).unwrap();
    std::fs::write(tree.source(), b"value\nedited\n").unwrap();
    assert_dataset_bytes(app.run_dataset(&dataset).unwrap(), b"value\nedited\n");
    let replacement = tree.original_dir().join("replacement");
    std::fs::write(&replacement, OUTSIDE).unwrap();
    std::fs::rename(replacement, tree.source()).unwrap();
    assert!(app.run_dataset(&dataset).is_err());
    assert_eq!(app.linked_file_status(referrer).unwrap()[0].state, LinkedFileState::Invalid);
    assert_eq!(app.bind_linked_file(referrer, &tree.source()).unwrap().id, binding.id);
    assert_dataset_bytes(app.run_dataset(&dataset).unwrap(), OUTSIDE);
}

#[test]
fn draft_restart_policy_keeps_old_binding_records_inert_until_native_reselection() {
    let tree = Tree::new();
    let profiles = tempfile::tempdir().unwrap();
    let app = app(profiles.path());
    let dataset = dataset(&app, &tree.source());
    let referrer = LinkedFileReferrer::Dataset { id: dataset.meta.id };
    let binding = app.bind_linked_file(referrer, &tree.source()).unwrap();
    assert_dataset_bytes(app.run_dataset(&dataset).unwrap(), CHOSEN);
    let dir = app.dir.clone();
    app.lock();
    drop(app);
    let (_, key) = ProfileManager::unlock(&dir, crate::profiles::Unlock::Passphrase("test passphrase")).unwrap();
    let header = anvil_storage::vault::read_header(&dir).unwrap();
    let reopened = App::open(dir, header, key).unwrap();
    assert_eq!(reopened.linked_file_bindings().unwrap()[0].id, binding.id);
    assert_eq!(reopened.linked_file_status(referrer).unwrap()[0].state, LinkedFileState::Invalid);
    let error = reopened.run_dataset(&dataset).unwrap_err().to_string();
    assert!(error.contains("fresh native selection"));
    assert!(!error.contains("outside-secret-canary"));
    assert_eq!(reopened.bind_linked_file(referrer, &tree.source()).unwrap().id, binding.id);
    assert_dataset_bytes(reopened.run_dataset(&dataset).unwrap(), CHOSEN);
}

#[test]
fn a_request_context_from_an_old_lock_epoch_cannot_read_after_unlock_or_reselection() {
    let tree = Tree::new();
    let profiles = tempfile::tempdir().unwrap();
    let app = app(profiles.path());
    let workspace = app.create_workspace("files").unwrap();
    let attachment = AttachmentRef::LinkedFile { path: tree.source().to_str().unwrap().into() };
    let mut spec = RequestSpec::http("POST", "http://127.0.0.1:9");
    spec.body = Body::Binary { attachment: attachment.clone(), content_type: None };
    let request = app.create_request(&workspace.meta.id, None, "upload", spec).unwrap();
    let referrer = LinkedFileReferrer::Request { id: request.meta.id };
    app.bind_linked_file(referrer, &tree.source()).unwrap();
    let context = app.build_context(Some(request.meta.id), &workspace.meta.id, None, &Default::default()).unwrap();
    app.lock();
    let (_, key) = ProfileManager::unlock(&app.dir, crate::profiles::Unlock::Passphrase("test passphrase")).unwrap();
    app.unlock(key).unwrap();
    assert!(context.attachments.load(&attachment).is_err());
    app.bind_linked_file(referrer, &tree.source()).unwrap();
    assert!(context.attachments.load(&attachment).is_err());
    let fresh = app.build_context(Some(request.meta.id), &workspace.meta.id, None, &Default::default()).unwrap();
    assert_eq!(fresh.attachments.load(&attachment).unwrap().as_ref(), CHOSEN);
}

#[cfg(unix)]
#[test]
fn a_fifo_swapped_after_the_regular_leaf_filter_never_blocks_the_actual_linked_read() {
    let tree = Tree::new();
    let profiles = tempfile::tempdir().unwrap();
    let app = app(profiles.path());
    let dataset = dataset(&app, &tree.source());
    app.bind_linked_file(LinkedFileReferrer::Dataset { id: dataset.meta.id }, &tree.source()).unwrap();
    let result = race(
        "leaf_checked",
        move || app.run_dataset(&dataset),
        || {
            std::fs::remove_file(tree.source()).unwrap();
            assert!(std::process::Command::new("mkfifo").arg(tree.source()).status().unwrap().success());
        },
    );
    assert!(result.unwrap_err().to_string().contains("not a regular file"));
    tree.outside_untouched();
}
