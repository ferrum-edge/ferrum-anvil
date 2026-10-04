//! Hosted native regressions through the production grant issuers and I/O.

use super::*;
use crate::file_handles::with_test_hook;
use std::path::Component;
use std::sync::mpsc;

fn at_checkpoint<T: Send + 'static>(point: &'static str, operation: impl FnOnce() -> T + Send + 'static, interfere: impl FnOnce()) -> T {
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
    ready_rx.recv_timeout(Duration::from_secs(30)).expect("production I/O reached the barrier");
    interfere();
    resume_tx.send(()).unwrap();
    let result = done_rx.recv_timeout(Duration::from_secs(30)).expect("production I/O finished");
    worker.join().unwrap();
    result
}

struct NativeTree {
    _root: tempfile::TempDir,
    source: PathBuf,
    destination: PathBuf,
}

impl NativeTree {
    fn new(access: Access) -> Self {
        let root = tempfile::tempdir().unwrap();
        let mut directory = std::fs::canonicalize(root.path()).unwrap();
        // Production charges one root, every normal directory component,
        // and (for reads) the original file. Make each grant cost exactly 16
        // on every native CI platform, including Windows drive prefixes.
        let target = if access == Access::Read { 14 } else { 15 };
        let depth = directory.components().filter(|c| matches!(c, Component::Normal(_))).count();
        assert!(depth <= target);
        for level in depth..target {
            directory.push(format!("level-{level}"));
            std::fs::create_dir(&directory).unwrap();
        }
        let source = directory.join("chosen.txt");
        std::fs::write(&source, b"chosen native bytes").unwrap();
        Self { _root: root, source, destination: directory.join("export.anvil") }
    }

    fn issue(&self, grants: &FileGrants, access: Access) -> FileGrant {
        match access {
            Access::Read => grants.grant_read(FilePurpose::Attachment, &self.source).unwrap(),
            Access::Write => grants.grant_write(FilePurpose::BundleExport, &self.destination).unwrap(),
            Access::Bind => unreachable!(),
        }
    }
}

fn expire_registry(grants: &FileGrants) {
    // Advance only issuance timestamps, deterministically, without sleeping.
    // All objects, chains, registry removal and descriptor charges are real;
    // no test changes a budget counter or releases a lease on their behalf.
    let issued = Instant::now().checked_sub(GRANT_TTL).unwrap();
    for entry in grants.state.lock().entries.values_mut() {
        entry.issued = issued;
    }
}

#[test]
fn expired_full_native_registry_is_retired_before_read_and_write_acquisition() {
    for old_access in [Access::Read, Access::Write] {
        for new_access in [Access::Read, Access::Write] {
            let old_tree = NativeTree::new(old_access);
            let new_tree = NativeTree::new(new_access);
            let grants = FileGrants::default();
            let mut old = Vec::new();
            for _ in 0..MAX_GRANTS {
                old.push(old_tree.issue(&grants, old_access));
            }
            assert_eq!(grants.budget.used(), 512);
            assert_eq!(grants.state.lock().entries.len(), 32);
            let full = match new_access {
                Access::Read => grants.grant_read(FilePurpose::Attachment, &new_tree.source),
                Access::Write => grants.grant_write(FilePurpose::BundleExport, &new_tree.destination),
                Access::Bind => unreachable!(),
            };
            assert!(full.is_err(), "live descriptor owners must remain charged");
            assert_eq!(grants.budget.used(), 512);

            expire_registry(&grants);
            // No len/lookup/take/revoke call may prune before this issuer.
            let fresh = new_tree.issue(&grants, new_access);
            assert_eq!(grants.budget.used(), 16);
            let state = grants.state.lock();
            assert_eq!(state.entries.len(), 1);
            assert!(state.entries.contains_key(&fresh.token));
            assert!(old.iter().all(|grant| !state.entries.contains_key(&grant.token)));
            drop(state);
            if new_access == Access::Read {
                let read = grants.read(&fresh.token, FilePurpose::Attachment).unwrap();
                assert_eq!(read.bytes, b"chosen native bytes");
            }
            grants.revoke_all();
            assert_eq!(grants.budget.used(), 0, "real descriptor closure returns every charge",);
        }
    }
}

#[test]
fn expired_registry_cannot_release_charges_owned_by_retained_operations() {
    let tree = NativeTree::new(Access::Read);
    let grants = FileGrants::default();
    let mut retained = Vec::new();
    for _ in 0..MAX_GRANTS {
        let grant = tree.issue(&grants, Access::Read);
        // Same Arc-bearing entry a production read retains after lookup.
        retained.push(grants.lookup(&grant.token, FilePurpose::Attachment).unwrap());
    }
    assert_eq!(grants.budget.used(), 512);
    expire_registry(&grants);
    assert!(grants.grant_read(FilePurpose::Attachment, &tree.source).is_err());
    assert!(grants.state.lock().entries.is_empty());
    assert_eq!(grants.budget.used(), 512, "expiry cannot reset a live object's lifetime charge",);
    drop(retained.pop());
    assert_eq!(grants.budget.used(), 496);
    tree.issue(&grants, Access::Read);
    assert_eq!(grants.budget.used(), 512);
    grants.revoke_all();
    assert_eq!(grants.budget.used(), 496);
    drop(retained);
    assert_eq!(grants.budget.used(), 0);
}

#[test]
fn expiry_during_a_real_read_keeps_the_operation_and_its_native_chain_charged() {
    let tree = NativeTree::new(Access::Read);
    let grants = Arc::new(FileGrants::default());
    let first = tree.issue(&grants, Access::Read);
    for _ in 1..MAX_GRANTS {
        tree.issue(&grants, Access::Read);
    }
    let held = grants.lookup(&first.token, FilePurpose::Attachment).unwrap();
    let Target::Read(selected) = held.target else { unreachable!() };
    let chain = selected.parent.clone();
    drop(selected);
    let reader_grants = grants.clone();
    let read = at_checkpoint(
        "leaf_checked",
        move || reader_grants.read(&first.token, FilePurpose::Attachment),
        || {
            expire_registry(&grants);
            grants.grant_read(FilePurpose::Attachment, &tree.source).unwrap();
            assert_eq!(grants.budget.used(), 32);
            grants.revoke_all();
            assert_eq!(grants.budget.used(), 16, "the read still owns its object");
        },
    );
    assert_eq!(read.unwrap().bytes, b"chosen native bytes");
    assert_eq!(grants.budget.used(), 15, "the separately retained directory chain stays charged",);
    drop(chain);
    assert_eq!(grants.budget.used(), 0);
    tree.issue(&grants, Access::Read);
    assert_eq!(grants.budget.used(), 16);
    grants.revoke_all();
    assert_eq!(grants.budget.used(), 0);
}

#[test]
fn expiry_during_a_real_write_keeps_the_directory_and_staging_descriptor_charged() {
    let tree = NativeTree::new(Access::Write);
    let grants = Arc::new(FileGrants::default());
    let first = tree.issue(&grants, Access::Write);
    // Leave room for the real operation's additional staging descriptor.
    for _ in 1..MAX_GRANTS - 1 {
        tree.issue(&grants, Access::Write);
    }
    let writer_grants = grants.clone();
    let written = at_checkpoint(
        "write_staged",
        move || writer_grants.write(&first.token, FilePurpose::BundleExport, b"owned native export"),
        || {
            assert_eq!(grants.budget.used(), 497);
            expire_registry(&grants);
            grants.grant_write(FilePurpose::BundleExport, &tree.destination).unwrap();
            assert_eq!(grants.budget.used(), 33);
            grants.revoke_all();
            assert_eq!(grants.budget.used(), 17);
        },
    );
    assert_eq!(written.unwrap(), 19);
    assert_eq!(std::fs::read(&tree.destination).unwrap(), b"owned native export");
    assert_eq!(grants.budget.used(), 0);
}

#[test]
fn revocation_between_pre_acquisition_pruning_and_insert_rejects_both_issuers() {
    for access in [Access::Read, Access::Write] {
        let tree = NativeTree::new(access);
        let grants = Arc::new(FileGrants::default());
        for _ in 0..MAX_GRANTS {
            tree.issue(&grants, access);
        }
        expire_registry(&grants);
        let generation = grants.generation();
        let issuer_grants = grants.clone();
        let source = tree.source.clone();
        let destination = tree.destination.clone();
        let issued = at_checkpoint(
            "grant_acquisition_prepared",
            move || match access {
                Access::Read => issuer_grants.grant_read_at(FilePurpose::Attachment, &source, generation),
                Access::Write => issuer_grants.grant_write_at(FilePurpose::BundleExport, &destination, generation),
                Access::Bind => unreachable!(),
            },
            || {
                assert_eq!(grants.budget.used(), 0);
                // The bounded worker cannot finish with the old dialog
                // epoch, even though it opens the native chain after revoke.
                grants.revoke_all();
            },
        );
        assert_eq!(issued.unwrap_err(), GrantError::Revoked);
        assert!(grants.state.lock().entries.is_empty());
        assert_eq!(grants.budget.used(), 0);
        tree.issue(&grants, access);
        assert_eq!(grants.budget.used(), 16);
        grants.revoke_all();
        assert_eq!(grants.budget.used(), 0);
    }
}

#[cfg(target_os = "macos")]
mod macos_acl {
    use super::*;
    use crate::file_handles::publication::{MountProfile, set_test_mount_profile, test_mount_profile, with_test_mount_profile};
    use std::cell::Cell;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    use std::process::{Command, Output};
    use std::rc::Rc;

    const CHANGED_ACL: &str = "everyone allow read,write,readsecurity,writesecurity,file_inherit";

    fn inheritable_acl(directory: &Path, acl: &str) {
        let output = Command::new("/bin/chmod").args(["+a", acl]).arg(directory).output().unwrap();
        assert!(output.status.success(), "chmod ACL failed: {output:?}");
    }

    fn non_owner_read(path: &Path) -> Output {
        Command::new("/usr/bin/sudo").args(["-n", "-u", "nobody", "/bin/cat"]).arg(path).output().unwrap()
    }

    fn assert_acl_control(directory: &Path, name: &str) {
        let path = directory.join(name);
        let mut file = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&path).unwrap();
        file.write_all(b"inherited ACL canary").unwrap();
        assert_eq!(file.metadata().unwrap().permissions().mode() & 0o777, 0o600);
        let acl = Command::new("/bin/ls").arg("-le").arg(&path).output().unwrap();
        assert!(acl.status.success());
        assert!(String::from_utf8_lossy(&acl.stdout).contains("inherited"));
        let read = non_owner_read(&path);
        assert!(read.status.success(), "hosted non-owner ACL control failed: {read:?}",);
        assert_eq!(read.stdout, b"inherited ACL canary");
    }

    fn assert_denied(path: &Path) {
        let read = non_owner_read(path);
        assert!(!read.status.success(), "non-owner read succeeded: {read:?}");
        assert!(read.stdout.is_empty());
        assert!(String::from_utf8_lossy(&read.stderr).contains("Permission denied"), "{read:?}",);
    }

    fn profile(name: &[u8], flags: u32, extended_flags: u32) -> MountProfile {
        let mut bytes = [0; 16];
        bytes[..name.len()].copy_from_slice(name);
        MountProfile { name: bytes, flags, extended_flags }
    }

    fn assert_rejected_before_staging(directory: &Path, injected: Option<MountProfile>) {
        let grants = FileGrants::default();
        let destination = directory.join("rejected.anvil");
        let mut before: Vec<_> = std::fs::read_dir(directory).unwrap().map(|entry| entry.unwrap().file_name()).collect();
        before.sort();
        let grant = grants.grant_write(FilePurpose::BundleExport, &destination).unwrap();
        let charged = grants.budget.used();
        let result = with_test_mount_profile(injected, || {
            with_test_hook(
                |point| {
                    assert_ne!(point, "macos_staging_dispatch", "rejected before native creation",);
                    assert_ne!(point, "write_staged", "rejected before plaintext I/O");
                },
                || grants.write(&grant.token, FilePurpose::BundleExport, b"must never be staged"),
            )
        });
        let error = result.unwrap_err().to_string();
        assert!(error.contains("local APFS with ownership enabled"), "{error}");
        let mut after: Vec<_> = std::fs::read_dir(directory).unwrap().map(|entry| entry.unwrap().file_name()).collect();
        after.sort();
        assert_eq!(after, before, "rejection must create no staging or final entry");
        assert_eq!(grants.budget.used(), charged, "no staging descriptor charge survives",);
        // Failure preserves the original retry grant and generation.
        assert_eq!(grants.len(), 1);
        grants.revoke_all();
        assert_eq!(grants.budget.used(), 0);
    }

    #[test]
    fn volfs_capability_and_observed_owned_apfs_profile_allow_native_export() {
        // First isolate LOCAL plus DOVOLFS, then replay the exact hosted
        // descriptor profile from 34fb901: 0x04909000, extended flags 1.
        // The seam changes policy input only; staging, ACL checks, writing
        // and descriptor cloning still execute the production native path.
        let local = profile(b"apfs", 0x1000, 0);
        let volfs = profile(b"apfs", 0x9000, 0);
        let observed = profile(b"apfs", 0x0490_9000, 1);
        let canary = b"owned APFS canary";
        for injected in [local, volfs, observed] {
            let root = tempfile::tempdir().unwrap();
            let directory = std::fs::canonicalize(root.path()).unwrap();
            let destination = directory.join("bundle.anvil");
            let grants = FileGrants::default();
            let grant = grants.grant_write(FilePurpose::BundleExport, &destination).unwrap();
            let reached = Rc::new(Cell::new(0u8));
            let hook_reached = reached.clone();
            let written = with_test_mount_profile(Some(injected), || {
                with_test_hook(
                    move |point| {
                        let bit = match point {
                            "macos_staging_dispatch" => 1,
                            "write_staged" => 2,
                            "write_synced" => 4,
                            "write_verified" => 8,
                            _ => 0,
                        };
                        hook_reached.set(hook_reached.get() | bit);
                    },
                    || grants.write(&grant.token, FilePurpose::BundleExport, canary),
                )
            });
            assert_eq!(reached.get(), 15, "native export reached all barriers");
            assert_eq!(written.unwrap(), canary.len());
            assert_eq!(std::fs::read(&destination).unwrap(), canary);
            let mode = std::fs::metadata(&destination).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
            let staging = std::fs::read_dir(&directory)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .find(|path| path.extension().is_some_and(|ext| ext == "partial"))
                .unwrap();
            assert_eq!(std::fs::read(&staging).unwrap(), canary);
            let mode = std::fs::metadata(&staging).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
            assert_eq!(grants.len(), 0, "export consumes its grant");
            assert_eq!(grants.budget.used(), 0);
        }
    }

    #[test]
    fn synthetic_unsupported_profiles_are_rejected_before_native_creation() {
        // These exercise the production policy seam, not SMB/NFS servers.
        // Even a spoofed LOCAL flag cannot qualify an unsupported type name.
        let root = tempfile::tempdir().unwrap();
        let directory = std::fs::canonicalize(root.path()).unwrap();
        for name in [
            b"smbfs".as_slice(),
            b"nfs",
            b"webdav",
            b"fusefs",
            b"msdos",
            b"exfat",
            b"ntfs",
            b"hfs",
            b"unknown",
            b"APFS",
            b"apfs-extra",
            b"",
            b"abcdefghijklmnop",
        ] {
            assert_rejected_before_staging(&directory, Some(profile(name, 0x1000, 0)));
        }
        assert_rejected_before_staging(&directory, Some(profile(b"apfs", 0, 0)));
        assert_rejected_before_staging(&directory, Some(profile(b"apfs", 0x8000, 0)));
        // Every unsupported bit in the SDK's 32-bit visible mount field:
        // read-only, union, exported, unused, command bits,
        // ignore ownership, automount, unknown and snapshot respectively.
        // Bit 15 is intentionally absent: Apple identifies MNT_DOVOLFS as
        // an innocuous capability, covered by the positive export above.
        // It must not make any unsupported bit safe on the observed profile.
        for base_flags in [0x1000, 0x0490_9000] {
            for bit in [0, 5, 8, 11, 16, 17, 18, 19, 21, 22, 29, 30] {
                let flags = base_flags | (1u32 << bit);
                assert_rejected_before_staging(&directory, Some(profile(b"apfs", flags, 0)));
            }
            // FSKit (bit 1) and ALL unknown extended bits fail closed.
            for bit in 1..32 {
                let extended = 1u32 << bit;
                assert_rejected_before_staging(&directory, Some(profile(b"apfs", base_flags, extended)));
            }
        }
    }

    #[test]
    fn mount_policy_is_rechecked_before_plaintext_and_at_publication() {
        for point in ["write_staged", "write_synced", "write_verified"] {
            let root = tempfile::tempdir().unwrap();
            let directory = std::fs::canonicalize(root.path()).unwrap();
            let destination = directory.join("bundle.anvil");
            let grants = FileGrants::default();
            let grant = grants.grant_write(FilePurpose::BundleExport, &destination).unwrap();
            let reached = Rc::new(Cell::new(false));
            let hook_reached = reached.clone();
            let result = with_test_mount_profile(None, || {
                with_test_hook(
                    move |observed| {
                        if observed == point {
                            assert!(!hook_reached.replace(true));
                            set_test_mount_profile(Some(profile(b"apfs", 0x0020_1000, 0)));
                        }
                    },
                    || grants.write(&grant.token, FilePurpose::BundleExport, b"private canary"),
                )
            });
            assert!(reached.get(), "production export must reach the policy barrier");
            assert!(result.unwrap_err().to_string().contains("local APFS with ownership enabled"));
            assert!(!destination.exists(), "policy rejection must precede cloning");
            let staging = std::fs::read_dir(&directory)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .find(|path| path.extension().is_some_and(|ext| ext == "partial"))
                .unwrap();
            let expected: &[u8] = if point == "write_staged" { b"" } else { b"private canary" };
            assert_eq!(std::fs::read(staging).unwrap(), expected);
            grants.revoke_all();
            assert_eq!(grants.budget.used(), 0);
        }
    }

    #[test]
    #[ignore = "requires the dedicated GitHub-hosted private APFS image workflow"]
    fn real_ignore_ownership_image_is_rejected_before_staging() {
        assert_eq!(std::env::var("GITHUB_ACTIONS").as_deref(), Ok("true"));
        assert_eq!(std::env::var("RUNNER_ENVIRONMENT").as_deref(), Ok("github-hosted"),);
        let directory = PathBuf::from(std::env::var_os("ANVIL_TEST_IGNORE_OWNERSHIP_MOUNT").unwrap());
        let directory = std::fs::canonicalize(directory).unwrap();
        let grants = FileGrants::default();
        let grant = grants.grant_write(FilePurpose::BundleExport, &directory.join("probe.anvil")).unwrap();
        let entry = grants.lookup(&grant.token, FilePurpose::BundleExport).unwrap();
        let Target::Write { dir, .. } = &entry.target else { unreachable!() };
        let native = test_mount_profile(dir).unwrap();
        assert_eq!(&native.name[..5], b"apfs\0", "must use a real APFS image");
        assert_ne!(native.flags & 0x1000, 0, "image must be local");
        assert_ne!(native.flags & 0x0020_0000, 0, "native Ignore Ownership flag is required",);
        eprintln!("real image descriptor profile: {native:?}; private mount: {directory:?}");
        drop(entry);
        grants.revoke_all();
        assert_rejected_before_staging(&directory, None);

        // A safe replacement at the former selected pathname must not
        // override the unsafe mount of the retained directory descriptor.
        let selected = directory.join("selected");
        let retained = directory.join("retained");
        std::fs::create_dir(&selected).unwrap();
        let replacement = tempfile::tempdir().unwrap();
        let grants = FileGrants::default();
        let grant = grants.grant_write(FilePurpose::BundleExport, &selected.join("redirect.anvil")).unwrap();
        std::fs::rename(&selected, &retained).unwrap();
        std::os::unix::fs::symlink(replacement.path(), &selected).unwrap();
        let result = with_test_hook(
            |point| assert_ne!(point, "macos_staging_dispatch"),
            || grants.write(&grant.token, FilePurpose::BundleExport, b"must stay private"),
        );
        assert!(result.unwrap_err().to_string().contains("local APFS with ownership enabled"));
        assert_eq!(std::fs::read_dir(&retained).unwrap().count(), 0);
        assert_eq!(std::fs::read_dir(replacement.path()).unwrap().count(), 0);
        grants.revoke_all();
        assert_eq!(grants.budget.used(), 0);
    }

    #[test]
    fn inherited_acl_never_exposes_staging_or_final_exports_even_when_changed_before_publish() {
        // /Users/Shared is searchable by the separate native account. A
        // successful mode-0600 inherited-ACL control proves permissions are
        // actually exercised, rather than denied by a private temp ancestor.
        for point in ["write_staged", "write_synced", "write_verified"] {
            let root = tempfile::Builder::new().prefix("anvil-native-acl-").tempdir_in("/Users/Shared").unwrap();
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
            let directory = std::fs::canonicalize(root.path()).unwrap();
            inheritable_acl(&directory, "everyone allow read,file_inherit");
            assert_acl_control(&directory, "before-control");
            let destination = directory.join("bundle.anvil");
            let grants = FileGrants::default();
            let grant = grants.grant_write(FilePurpose::BundleExport, &destination).unwrap();
            let entry = grants.lookup(&grant.token, FilePurpose::BundleExport).unwrap();
            let Target::Write { dir, .. } = &entry.target else { unreachable!() };
            let native = test_mount_profile(dir).unwrap();
            assert_eq!(&native.name[..5], b"apfs\0");
            assert_ne!(native.flags & 0x1000, 0);
            assert_eq!(native.flags & 0x0020_0000, 0, "positive control enforces ownership",);
            eprintln!("inherited-ACL descriptor profile: {native:?}");
            drop(entry);
            let hook_directory = directory.clone();
            let reached = Rc::new(Cell::new(false));
            let hook_reached = reached.clone();
            let written = with_test_hook(
                move |observed| {
                    if observed == point {
                        assert!(!hook_reached.replace(true));
                        let staging = std::fs::read_dir(&hook_directory)
                            .unwrap()
                            .map(|entry| entry.unwrap().path())
                            .find(|path| path.extension().is_some_and(|ext| ext == "partial"))
                            .unwrap();
                        // At write_staged this also proves that a non-owner
                        // cannot pre-open an empty file before secrets arrive.
                        assert_denied(&staging);
                        let cleared = Command::new("/bin/chmod").arg("-N").arg(&hook_directory).output().unwrap();
                        assert!(cleared.status.success());
                        inheritable_acl(&hook_directory, CHANGED_ACL);
                        assert_acl_control(&hook_directory, "after-control");
                        assert_denied(&staging);
                    }
                },
                || grants.write(&grant.token, FilePurpose::BundleExport, b"owner-only bundle canary"),
            );
            assert!(reached.get(), "production export must reach the ACL mutation barrier",);
            assert_eq!(written.unwrap(), 24);
            assert_eq!(std::fs::read(&destination).unwrap(), b"owner-only bundle canary");
            assert_denied(&destination);
            let staging = std::fs::read_dir(&directory)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .find(|path| path.extension().is_some_and(|ext| ext == "partial"))
                .unwrap();
            assert_eq!(std::fs::read(&staging).unwrap(), b"owner-only bundle canary");
            assert_denied(&staging);
            assert_eq!(grants.budget.used(), 0);
        }
    }
}
