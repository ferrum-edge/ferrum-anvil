//! Deliberate local rotation keeps portable recovery and rejects old local keys.
use anvil_app::{
    App,
    profiles::{ProfileManager, Unlock},
};
use anvil_portability::plan::ConflictPolicy;
use anvil_storage::{KdfParams, vault};
const OLD: &str = "old passphrase 123";
const NEW: &str = "new passphrase 456";
fn app(root: &std::path::Path, name: &str) -> (App, String) {
    let (s, k, recovery) = ProfileManager::new(root).create_passphrase(name, OLD, KdfParams::testing()).unwrap();
    let h = vault::read_header(&s.dir).unwrap();
    (App::open(s.dir, h, k).unwrap(), recovery.to_string())
}
#[test]
fn rotation_rejects_the_current_passphrase_without_changing_committed_state() {
    let root = tempfile::tempdir().unwrap();
    let (source, old_recovery) = app(root.path(), "unchanged credential");
    let ws = source.create_workspace("kept").unwrap();
    let before = serde_json::to_value(vault::read_header(&source.dir).unwrap()).unwrap();
    for ordinary_change in [false, true] {
        let replacement = vault::RotationRecoveryKey::generate();
        let result = if ordinary_change {
            source.change_passphrase(OLD, &replacement, KdfParams::testing())
        } else {
            source.rotate_data_key(OLD, &replacement, KdfParams::testing())
        };
        let refusal = match result {
            Err(e) => e,
            Ok(_) => panic!("current passphrase must be refused"),
        };
        assert!(refusal.to_string().contains("different from the current"));
        assert!(!source.is_locked(), "refused rotation keeps the active store usable");
        assert_eq!(serde_json::to_value(vault::read_header(&source.dir).unwrap()).unwrap(), before);
        assert_eq!(source.workspace(&ws.meta.id).unwrap().name, "kept");
        assert!(ProfileManager::unlock(&source.dir, Unlock::RecoveryKey(replacement.as_str())).is_err());
        assert!(ProfileManager::unlock(&source.dir, Unlock::RecoveryKey(&old_recovery)).is_ok());
        assert!(ProfileManager::unlock(&source.dir, Unlock::Passphrase(OLD)).is_ok());
    }
}
#[test]
fn rotation_replaces_recovery_and_retains_portable_backup_restore() {
    let root = tempfile::tempdir().unwrap();
    let (source, old_recovery) = app(root.path(), "source");
    let ws = source.create_workspace("historical workspace").unwrap();
    source.store.put_secret(&anvil_domain::Id::new(), Some(&ws.meta.id), "credential", "secret marker").unwrap();
    let before = source.backup_contents().unwrap();
    let portable = source.export_backup_with("portable backup password", KdfParams::testing()).unwrap().0;
    assert!(source.rotate_data_key("short", &vault::RotationRecoveryKey::generate(), KdfParams::testing()).is_err());
    let result = source.rotate_data_key(NEW, &vault::RotationRecoveryKey::generate(), KdfParams::testing()).unwrap();
    assert!(source.is_locked());
    assert!(ProfileManager::unlock(&source.dir, Unlock::Passphrase(OLD)).is_err());
    assert!(ProfileManager::unlock(&source.dir, Unlock::RecoveryKey(&old_recovery)).is_err());
    let (h, k) = ProfileManager::unlock(&source.dir, Unlock::RecoveryKey(&result.recovery_key)).unwrap();
    assert!(source.unlock(k.clone()).is_err(), "old immutable App/capability identity must be reopened");
    let reopened = App::open(source.dir.clone(), h, k).unwrap();
    assert_eq!(reopened.workspace(&ws.meta.id).unwrap().name, "historical workspace");
    assert_eq!(reopened.backup_contents().unwrap().secrets.len(), before.secrets.len());
    let (target, _) = app(root.path(), "portable target");
    target.restore(&portable, Some("portable backup password"), ConflictPolicy::Replace).unwrap();
    assert_eq!(target.workspace(&ws.meta.id).unwrap().name, "historical workspace");
    let (fresh, _) = app(root.path(), "post rotation target");
    let target_header = vault::read_header(&fresh.dir).unwrap();
    let after = reopened.export_backup_with("portable backup password", KdfParams::testing()).unwrap().0;
    fresh.restore(&after, Some("portable backup password"), ConflictPolicy::Replace).unwrap();
    assert_eq!(fresh.workspace(&ws.meta.id).unwrap().name, "historical workspace");
    let credentials_and_policy = |mut header: anvil_storage::ProfileHeader| {
        header.protection_mac = None;
        header.rotation.as_mut().unwrap().manifest_root = None;
        serde_json::to_value(header).unwrap()
    };
    assert_eq!(
        credentials_and_policy(vault::read_header(&fresh.dir).unwrap()),
        credentials_and_policy(target_header),
        "exports do not transfer local unlock/key policy"
    );
    // The deliberate operation is repeatable, with no old-key bridge.
    let result2 = reopened.rotate_data_key("third passphrase 789", &vault::RotationRecoveryKey::generate(), KdfParams::testing()).unwrap();
    assert!(ProfileManager::unlock(&source.dir, Unlock::RecoveryKey(&result.recovery_key)).is_err());
    assert!(ProfileManager::unlock(&source.dir, Unlock::RecoveryKey(&result2.recovery_key)).is_ok());
}
fn mock_store() {
    static MOCK: std::sync::Once = std::sync::Once::new();
    MOCK.call_once(|| keyring_core::set_default_store(keyring_core::mock::Store::new().unwrap()));
}

#[test]
fn keychain_rotation_commits_new_passphrase_key_then_retires_old_entry() {
    mock_store();
    let root = tempfile::tempdir().unwrap();
    let (s, k) = ProfileManager::new(root.path()).create_keychain("keychain").unwrap();
    let old = vault::read_header(&s.dir).unwrap();
    let account = old.keychain_account.clone().unwrap();
    let source = App::open(s.dir.clone(), old.clone(), k).unwrap();
    let ws = source.create_workspace("kept").unwrap();
    let rotated = source.rotate_data_key(NEW, &vault::RotationRecoveryKey::generate(), KdfParams::testing()).unwrap();
    assert!(rotated.keychain_entry_removed);
    assert!(vault::unlock_with_keychain(&old).is_err());
    assert!(matches!(keyring_core::Entry::new(vault::KEYCHAIN_SERVICE, &account).unwrap().get_secret(), Err(keyring_core::Error::NoEntry)));
    let (h, k) = ProfileManager::unlock(&s.dir, Unlock::Passphrase(NEW)).unwrap();
    assert!(h.keychain_account.is_none());
    assert!(h.rotation.as_ref().unwrap().retired_keychain.is_empty());
    assert_eq!(App::open(s.dir, h, k).unwrap().workspace(&ws.meta.id).unwrap().name, "kept");
}

#[test]
fn keychain_cleanup_denial_is_retryable_and_unrelated_replacements_survive() {
    mock_store();
    for replace in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let (s, k) = ProfileManager::new(root.path()).create_keychain("denied cleanup").unwrap();
        let old = vault::read_header(&s.dir).unwrap();
        let account = old.keychain_account.clone().unwrap();
        let entry = keyring_core::Entry::new(vault::KEYCHAIN_SERVICE, &account).unwrap();
        let app = App::open(s.dir.clone(), old.clone(), k).unwrap();
        entry
            .as_any()
            .downcast_ref::<keyring_core::mock::Cred>()
            .unwrap()
            .set_error(keyring_core::Error::NoStorageAccess(Box::new(std::io::Error::other("test store unavailable"))));
        let result = app.rotate_data_key(NEW, &vault::RotationRecoveryKey::generate(), KdfParams::testing()).unwrap();
        assert!(!result.keychain_entry_removed);
        let old_key = vault::unlock_with_keychain(&old).unwrap();
        assert!(anvil_storage::Store::open(&s.dir, old_key).is_err(), "retained credential cannot decrypt new data");
        let unrelated = anvil_storage::Key::random();
        if replace {
            entry.set_secret(unrelated.as_bytes()).unwrap();
        }
        let (h, _) = ProfileManager::unlock(&s.dir, Unlock::Passphrase(NEW)).unwrap();
        assert!(h.keychain_account.is_none());
        if replace {
            assert_eq!(entry.get_secret().unwrap(), unrelated.as_bytes());
        } else {
            assert!(matches!(entry.get_secret(), Err(keyring_core::Error::NoEntry)));
        }
    }
}

#[test]
fn keychain_rotation_can_keep_the_profile_in_the_keychain() {
    mock_store();
    let root = tempfile::tempdir().unwrap();
    let pm = ProfileManager::new(root.path());
    let (s, k) = pm.create_keychain("stays in keychain").unwrap();
    let old = vault::read_header(&s.dir).unwrap();
    let old_key = anvil_storage::Key::from_bytes(k.as_bytes()).unwrap();
    let old_account = old.keychain_account.clone().unwrap();
    let source = App::open(s.dir.clone(), old.clone(), k).unwrap();
    let ws = source.create_workspace("kept").unwrap();
    let checkpoint = source.store.checkpoint("before").unwrap();
    let rotated = source.rotate_keychain_data_key().unwrap();
    assert!(rotated.keychain_entry_removed && source.is_locked());
    let h = vault::read_header(&s.dir).unwrap();
    assert_eq!(h.protection, anvil_domain::workspace::ProtectionMode::OsKeychain);
    assert!(h.passphrase_wrap.is_none() && h.recovery_wrap.is_none(), "a keychain header carries no wraps");
    assert_ne!(h.keychain_account.as_deref(), Some(old_account.as_str()), "the new key is in a new entry");
    assert!(h.rotation.as_ref().unwrap().retired_keychain.is_empty());
    assert!(matches!(
        keyring_core::Entry::new(vault::KEYCHAIN_SERVICE, &old_account).unwrap().get_secret(),
        Err(keyring_core::Error::NoEntry)
    ));
    assert!(vault::unlock_with_keychain(&old).is_err());
    assert!(anvil_storage::Store::open(&s.dir, old_key).is_err(), "the old key cannot read the rotated data");
    assert!(!checkpoint.exists(), "the old-key checkpoint was removed");
    assert_eq!(pm.find(&s.profile_id).unwrap().protection, anvil_domain::workspace::ProtectionMode::OsKeychain);
    let (h, k) = ProfileManager::unlock(&s.dir, Unlock::Keychain).unwrap();
    let reopened = App::open(s.dir.clone(), h, k).unwrap();
    assert_eq!(reopened.workspace(&ws.meta.id).unwrap().name, "kept");
    // A passphrase profile is refused, and converting stays available.
    assert!(reopened.rotate_keychain_data_key().is_ok());
    let (h, k) = ProfileManager::unlock(&s.dir, Unlock::Keychain).unwrap();
    let again = App::open(s.dir.clone(), h, k).unwrap();
    let recovery = vault::RotationRecoveryKey::generate();
    again.convert_to_passphrase(NEW, &recovery, KdfParams::testing()).unwrap();
    let (h, k) = ProfileManager::unlock(&s.dir, Unlock::Passphrase(NEW)).unwrap();
    assert!(h.keychain_account.is_none());
    assert!(matches!(App::open(s.dir.clone(), h, k).unwrap().rotate_keychain_data_key(), Err(anvil_app::AppError::Invalid(_))));
}

#[test]
fn a_refused_old_keychain_entry_is_retired_at_the_next_unlock() {
    mock_store();
    let root = tempfile::tempdir().unwrap();
    let pm = ProfileManager::new(root.path());
    let (s, k) = pm.create_keychain("retire later").unwrap();
    let old = vault::read_header(&s.dir).unwrap();
    let account = old.keychain_account.clone().unwrap();
    let entry = keyring_core::Entry::new(vault::KEYCHAIN_SERVICE, &account).unwrap();
    let app = App::open(s.dir.clone(), old.clone(), k).unwrap();
    entry
        .as_any()
        .downcast_ref::<keyring_core::mock::Cred>()
        .unwrap()
        .set_error(keyring_core::Error::NoStorageAccess(Box::new(std::io::Error::other("test store unavailable"))));
    assert!(!app.rotate_keychain_data_key().unwrap().keychain_entry_removed);
    assert_eq!(pm.find(&s.profile_id).unwrap().leftover_keychain_entry.unwrap().account, account);
    let old_key = vault::unlock_with_keychain(&old).unwrap();
    assert!(anvil_storage::Store::open(&s.dir, old_key).is_err(), "the retained entry cannot decrypt new data");
    let (h, _) = ProfileManager::unlock(&s.dir, Unlock::Keychain).unwrap();
    assert!(h.rotation.as_ref().unwrap().retired_keychain.is_empty());
    assert!(matches!(entry.get_secret(), Err(keyring_core::Error::NoEntry)));
    assert!(pm.find(&s.profile_id).unwrap().leftover_keychain_entry.is_none());
}

/// Attachment blob ids derive from the data key and rotation keeps them, so
/// attaching the same bytes after a rotation stores a new blob. The index
/// entry's previous blob is released, so deleting the attachment leaves no
/// pinned, unreachable blob behind.
#[test]
fn reattaching_after_rotation_leaves_no_orphaned_attachment_blob() {
    use anvil_domain::request::{AttachmentRef, Body, RequestSpec};
    let root = tempfile::tempdir().unwrap();
    let (source, _) = app(root.path(), "reattach");
    // Rotation may replace the database file: each count opens it afresh.
    let path = source.dir.join(anvil_storage::store::DB_FILE);
    let counts = || -> (i64, i64) {
        let db = rusqlite::Connection::open(&path).unwrap();
        let blobs = db.query_row("SELECT COUNT(*) FROM blobs", [], |r| r.get(0)).unwrap();
        let pins = db.query_row("SELECT COUNT(*) FROM meta WHERE key LIKE 'pin:%'", [], |r| r.get(0)).unwrap();
        (blobs, pins)
    };
    let base = counts();
    let plus = |n: i64| (base.0 + n, base.1 + n);
    let bytes = b"attachment bytes kept across a key rotation";
    let first = source.put_attachment("a.bin", bytes, None).unwrap();
    source.rotate_data_key(NEW, &vault::RotationRecoveryKey::generate(), KdfParams::testing()).unwrap();
    let (h, k) = ProfileManager::unlock(&source.dir, Unlock::Passphrase(NEW)).unwrap();
    let app = App::open(source.dir.clone(), h, k).unwrap();
    assert_eq!(counts(), plus(1));

    let again = app.put_attachment("a.bin", bytes, None).unwrap();
    let (AttachmentRef::Stored { sha256: a, .. }, AttachmentRef::Stored { sha256: b, .. }) = (&first, &again) else { panic!() };
    assert_eq!(a, b);
    assert_eq!(counts(), plus(1), "the pre-rotation blob is released when the index moves to the new one");
    assert_eq!(app.get_attachment(b).unwrap().as_deref(), Some(&bytes[..]));

    // Past the grace period, deleting the only request that holds it removes
    // the content entirely, and retention has nothing left to keep.
    let ws = app.create_workspace("W").unwrap().meta.id;
    let spec = RequestSpec {
        body: Body::Binary { attachment: again.clone(), content_type: None },
        ..RequestSpec::http("POST", "http://127.0.0.1:9/")
    };
    let req = app.create_request(&ws, None, "upload", spec).unwrap();
    let index = app
        .store
        .object_meta(anvil_storage::kind::IMPORT_SOURCE)
        .unwrap()
        .into_iter()
        .map(|m| m.id.parse::<anvil_domain::Id>().unwrap())
        .find(|id| {
            app.store
                .get::<serde_json::Value>(anvil_storage::kind::IMPORT_SOURCE, id)
                .unwrap()
                .is_some_and(|v| v["attachment"] == b.as_str())
        })
        .expect("its index entry");
    let mut entry: serde_json::Value = app.store.get(anvil_storage::kind::IMPORT_SOURCE, &index).unwrap().unwrap();
    entry["attached_at"] = (chrono::Utc::now() - chrono::Duration::days(31)).timestamp_millis().into();
    app.store.put(anvil_storage::kind::IMPORT_SOURCE, &index, None, None, 0.0, &entry).unwrap();
    app.delete_request(&req.meta.id).unwrap();
    app.store.prune_history(0, 0).unwrap();
    assert!(app.get_attachment(b).unwrap().is_none());
    assert_eq!(counts(), base);
}
