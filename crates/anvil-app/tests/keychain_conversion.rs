//! Product credential changes rotate every ciphertext; OS access uses a mock.
use anvil_app::profiles::{ProfileManager, Unlock};
use anvil_app::{App, AppError};
use anvil_domain::workspace::ProtectionMode;
use anvil_storage::vault::{self, RotationRecoveryKey};
use anvil_storage::{KdfParams, Key, Store};
const PASS: &str = "new passphrase 123";
fn mock_store() {
    static INSTALL: std::sync::Once = std::sync::Once::new();
    INSTALL.call_once(|| keyring_core::set_default_store(keyring_core::mock::Store::new().unwrap()));
    assert!(keyring_core::get_default_store().unwrap().as_any().is::<keyring_core::mock::Store>());
}
fn entry(account: &str) -> keyring_core::Entry {
    keyring_core::Entry::new(vault::KEYCHAIN_SERVICE, account).unwrap()
}

#[test]
fn conversion_rotates_data_and_locks_the_old_app() {
    mock_store();
    let root = tempfile::tempdir().unwrap();
    let pm = ProfileManager::new(root.path());
    let (s, dek) = pm.create_keychain("Local").unwrap();
    let old = Key::from_bytes(dek.as_bytes()).unwrap();
    let header = vault::read_header(&s.dir).unwrap();
    let account = header.keychain_account.clone().unwrap();
    let app = App::open(s.dir.clone(), header.clone(), dek).unwrap();
    let ws = app.create_workspace("kept").unwrap();
    let replacement = RotationRecoveryKey::generate();
    assert!(matches!(app.change_passphrase(PASS, &replacement, KdfParams::testing()), Err(AppError::Invalid(_))));
    assert!(app.convert_to_passphrase("short", &replacement, KdfParams::testing()).is_err());
    let converted = app.convert_to_passphrase(PASS, &replacement, KdfParams::testing()).unwrap();
    assert!(converted.keychain_entry_removed && app.is_locked());
    assert!(Store::open(&s.dir, old).is_err(), "old OS data key cannot read newer ciphertext");
    assert!(ProfileManager::unlock(&s.dir, Unlock::Keychain).is_err());
    assert!(matches!(entry(&account).get_secret(), Err(keyring_core::Error::NoEntry)));
    assert_eq!(pm.find(&s.profile_id).unwrap().protection, ProtectionMode::Passphrase);
    let (h, key) = ProfileManager::unlock(&s.dir, Unlock::RecoveryKey(replacement.as_str())).unwrap();
    let reopened = App::open(s.dir.clone(), h, key).unwrap();
    assert_eq!(reopened.workspace(&ws.meta.id).unwrap().name, "kept");
    let next = RotationRecoveryKey::generate();
    reopened.change_passphrase("another passphrase 9", &next, KdfParams::testing()).unwrap();
    assert!(ProfileManager::unlock(&s.dir, Unlock::RecoveryKey(replacement.as_str())).is_err());
    assert!(ProfileManager::unlock(&s.dir, Unlock::RecoveryKey(next.as_str())).is_ok());
}

#[test]
fn cleanup_failure_keeps_the_committed_rotation_and_retries_safely() {
    mock_store();
    let root = tempfile::tempdir().unwrap();
    let pm = ProfileManager::new(root.path());
    let (s, key) = pm.create_keychain("cleanup").unwrap();
    let h = vault::read_header(&s.dir).unwrap();
    let account = h.keychain_account.clone().unwrap();
    let app = App::open(s.dir.clone(), h, key).unwrap();
    let e = entry(&account);
    e.as_any()
        .downcast_ref::<keyring_core::mock::Cred>()
        .unwrap()
        .set_error(keyring_core::Error::NoStorageAccess(Box::new(std::io::Error::other("store locked"))));
    let recovery = RotationRecoveryKey::generate();
    let result = app.convert_to_passphrase(PASS, &recovery, KdfParams::testing()).unwrap();
    assert!(!result.keychain_entry_removed);
    assert!(pm.find(&s.profile_id).unwrap().leftover_keychain_entry.is_some());
    assert!(ProfileManager::unlock(&s.dir, Unlock::Keychain).is_err());
    ProfileManager::unlock(&s.dir, Unlock::Passphrase(PASS)).unwrap();
    assert!(matches!(entry(&account).get_secret(), Err(keyring_core::Error::NoEntry)));
    assert!(pm.find(&s.profile_id).unwrap().leftover_keychain_entry.is_none());
}

#[test]
fn an_unrelated_replacement_entry_is_not_deleted() {
    mock_store();
    let root = tempfile::tempdir().unwrap();
    let (s, key) = ProfileManager::new(root.path()).create_keychain("replacement").unwrap();
    let h = vault::read_header(&s.dir).unwrap();
    let account = h.keychain_account.clone().unwrap();
    let app = App::open(s.dir.clone(), h, key).unwrap();
    let unrelated = Key::random();
    let secret = [b"anvil-dek-v2:".as_slice(), unrelated.as_bytes().as_slice()].concat();
    entry(&account).set_secret(&secret).unwrap();
    app.convert_to_passphrase(PASS, &RotationRecoveryKey::generate(), KdfParams::testing()).unwrap();
    assert_eq!(entry(&account).get_secret().unwrap(), secret);
    entry(&account).delete_credential().unwrap();
}

#[test]
fn enrolled_os_credential_refuses_a_legacy_header_downgrade() {
    mock_store();
    let root = tempfile::tempdir().unwrap();
    let (s, _) = ProfileManager::new(root.path()).create_keychain("enrolled").unwrap();
    let h = vault::read_header(&s.dir).unwrap();
    let legacy: vault::ProfileHeader = serde_json::from_slice(&std::fs::read(vault::header_path(&s.dir)).unwrap()).unwrap();
    assert!(h.rotation.is_some());
    assert!(vault::unlock_with_keychain(&legacy).is_err(), "enrolled credential cannot authorize old header domain");
    assert!(ProfileManager::unlock(&s.dir, Unlock::Keychain).is_ok());
}
