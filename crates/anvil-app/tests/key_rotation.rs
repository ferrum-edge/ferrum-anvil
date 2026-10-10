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
fn rotation_replaces_recovery_and_retains_portable_backup_restore() {
    let root = tempfile::tempdir().unwrap();
    let (source, old_recovery) = app(root.path(), "source");
    let ws = source.create_workspace("historical workspace").unwrap();
    source.store.put_secret(&anvil_domain::Id::new(), Some(&ws.meta.id), "credential", "secret marker").unwrap();
    let before = source.backup_contents().unwrap();
    let portable = source.export_backup_with("portable backup password", KdfParams::testing()).unwrap().0;
    assert!(source.rotate_data_key("short", KdfParams::testing()).is_err());
    let result = source.rotate_data_key(NEW, KdfParams::testing()).unwrap();
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
    let after = reopened.export_backup_with("portable backup password", KdfParams::testing()).unwrap().0;
    fresh.restore(&after, Some("portable backup password"), ConflictPolicy::Replace).unwrap();
    assert_eq!(fresh.workspace(&ws.meta.id).unwrap().name, "historical workspace");
    assert!(vault::read_header(&fresh.dir).unwrap().rotation.is_none(), "exports do not transfer local unlock/key policy");
    // The deliberate operation is repeatable, with no old-key bridge.
    let result2 = reopened.rotate_data_key("third passphrase 789", KdfParams::testing()).unwrap();
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
    let rotated = source.rotate_data_key(NEW, KdfParams::testing()).unwrap();
    assert!(rotated.keychain_entry_removed);
    assert!(vault::unlock_with_keychain(&old).is_err());
    assert!(matches!(keyring_core::Entry::new(vault::KEYCHAIN_SERVICE, &account).unwrap().get_secret(), Err(keyring_core::Error::NoEntry)));
    let (h, k) = ProfileManager::unlock(&s.dir, Unlock::Passphrase(NEW)).unwrap();
    assert!(h.keychain_account.is_none());
    assert!(h.rotation.as_ref().unwrap().retired_key_check.is_none());
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
        let result = app.rotate_data_key(NEW, KdfParams::testing()).unwrap();
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
