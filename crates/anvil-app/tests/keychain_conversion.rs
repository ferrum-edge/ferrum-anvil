//! Adding a passphrase to an OS-keychain profile through the app services.
//! Runs against keyring-core's in-memory mock credential store, installed
//! before any entry is created; no real OS keychain is touched.

use anvil_app::profiles::{KeychainEntryName, ProfileManager, Unlock};
use anvil_app::{App, AppError};
use anvil_domain::workspace::ProtectionMode;
use anvil_storage::KdfParams;
use anvil_storage::vault::{self, VaultError};

const PASS: &str = "new passphrase 123";

fn mock_store() {
    static INSTALL: std::sync::Once = std::sync::Once::new();
    INSTALL.call_once(|| keyring_core::set_default_store(keyring_core::mock::Store::new().unwrap()));
    let store = keyring_core::get_default_store().expect("a default store is installed");
    assert!(store.as_any().is::<keyring_core::mock::Store>(), "tests must only use the mock credential store");
}

fn entry(account: &str) -> keyring_core::Entry {
    keyring_core::Entry::new("com.ferrumedge.anvil", account).unwrap()
}

#[test]
fn keychain_profile_converted_to_passphrase_needs_the_passphrase() {
    mock_store();
    let root = tempfile::tempdir().unwrap();
    let pm = ProfileManager::new(root.path());
    let (s, dek) = pm.create_keychain("Local").unwrap();
    let account = vault::read_header(&s.dir).unwrap().keychain_account.unwrap();
    let h = vault::read_header(&s.dir).unwrap();
    let app = App::open(s.dir.clone(), h, dek).unwrap();
    let ws = app.create_workspace("kept").unwrap();

    // Changing a passphrase is for passphrase profiles; a keychain profile converts.
    assert!(matches!(app.change_passphrase(PASS, KdfParams::testing()), Err(AppError::Invalid(_))));
    assert!(app.convert_to_passphrase("short", KdfParams::testing()).is_err());
    let conv = app.convert_to_passphrase(PASS, KdfParams::testing()).unwrap();
    assert!(conv.keychain_entry_removed);
    assert!(matches!(app.convert_to_passphrase(PASS, KdfParams::testing()), Err(AppError::Invalid(_))));
    app.lock();
    drop(app);

    // Listing and the lock screen show the new mode and the recovery key.
    assert_eq!(pm.find(&s.profile_id).unwrap().protection, ProtectionMode::Passphrase);
    let req = ProfileManager::unlock_requirements(&s.dir).unwrap();
    assert_eq!(req.protection, ProtectionMode::Passphrase);
    assert!(req.recovery_key_available);

    let r = ProfileManager::unlock(&s.dir, Unlock::Keychain);
    assert!(matches!(r, Err(AppError::Vault(VaultError::WrongProtection(_)))));
    assert!(matches!(entry(&account).get_secret(), Err(keyring_core::Error::NoEntry)));
    assert!(ProfileManager::unlock(&s.dir, Unlock::Passphrase("wrong passphrase 1")).is_err());
    assert!(ProfileManager::unlock(&s.dir, Unlock::RecoveryKey(&conv.recovery_key)).is_ok());
    let (h, dek) = ProfileManager::unlock(&s.dir, Unlock::Passphrase(PASS)).unwrap();
    let app = App::open(s.dir.clone(), h, dek).unwrap();
    assert_eq!(app.workspace(&ws.meta.id).unwrap().name, "kept");
    // From now on it is an ordinary passphrase profile.
    app.change_passphrase("another passphrase 9", KdfParams::testing()).unwrap();
    assert!(ProfileManager::unlock(&s.dir, Unlock::RecoveryKey(&conv.recovery_key)).is_ok());
}

#[test]
fn a_leftover_keychain_entry_is_removed_at_the_next_unlock() {
    mock_store();
    let root = tempfile::tempdir().unwrap();
    let pm = ProfileManager::new(root.path());
    let (s, dek) = pm.create_keychain("Local").unwrap();
    let account = vault::read_header(&s.dir).unwrap().keychain_account.unwrap();
    let h = vault::read_header(&s.dir).unwrap();
    let app = App::open(s.dir.clone(), h, dek).unwrap();

    // The credential store refuses once, during the conversion.
    let e = entry(&account);
    let cred = e.as_any().downcast_ref::<keyring_core::mock::Cred>().unwrap();
    cred.set_error(keyring_core::Error::NoStorageAccess(Box::new(std::io::Error::other("store locked"))));
    let conv = app.convert_to_passphrase(PASS, KdfParams::testing()).unwrap();
    assert!(!conv.keychain_entry_removed);
    drop(app);

    assert!(entry(&account).get_secret().is_ok());
    // The profile list tells Settings which entry is still waiting.
    let pending = pm.find(&s.profile_id).unwrap().leftover_keychain_entry.expect("listed as pending removal");
    assert_eq!(pending, KeychainEntryName { service: "com.ferrumedge.anvil".into(), account: account.clone() });
    assert!(ProfileManager::unlock(&s.dir, Unlock::Keychain).is_err(), "the leftover entry does not unlock");
    ProfileManager::unlock(&s.dir, Unlock::Passphrase(PASS)).unwrap();
    assert!(matches!(entry(&account).get_secret(), Err(keyring_core::Error::NoEntry)));
    assert!(vault::read_header(&s.dir).unwrap().keychain_account.is_none());
    assert!(pm.find(&s.profile_id).unwrap().leftover_keychain_entry.is_none());
}

#[test]
fn a_leftover_entry_does_not_reopen_a_header_edited_back_to_keychain_mode() {
    mock_store();
    let root = tempfile::tempdir().unwrap();
    let pm = ProfileManager::new(root.path());
    let (s, dek) = pm.create_keychain("Local").unwrap();
    let account = vault::read_header(&s.dir).unwrap().keychain_account.unwrap();
    let app = App::open(s.dir.clone(), vault::read_header(&s.dir).unwrap(), dek).unwrap();
    let e = entry(&account);
    let cred = e.as_any().downcast_ref::<keyring_core::mock::Cred>().unwrap();
    cred.set_error(keyring_core::Error::NoStorageAccess(Box::new(std::io::Error::other("store locked"))));
    assert!(!app.convert_to_passphrase(PASS, KdfParams::testing()).unwrap().keychain_entry_removed);
    drop(app);

    let mut h = vault::read_header(&s.dir).unwrap();
    h.protection = ProtectionMode::OsKeychain;
    vault::write_header(&s.dir, &h).unwrap();
    let r = ProfileManager::unlock(&s.dir, Unlock::Keychain);
    assert!(matches!(r, Err(AppError::Vault(VaultError::HeaderTampered))));
    h.protection_mac = None;
    vault::write_header(&s.dir, &h).unwrap();
    let r = ProfileManager::unlock(&s.dir, Unlock::Keychain);
    assert!(matches!(r, Err(AppError::Vault(VaultError::HeaderTampered))));
    assert!(entry(&account).get_secret().is_ok(), "nothing was unlocked, so nothing was retired");
}

#[test]
fn unlocking_upgrades_a_header_from_an_earlier_build() {
    mock_store();
    let root = tempfile::tempdir().unwrap();
    let pm = ProfileManager::new(root.path());
    let (s, dek) = pm.create_keychain("Local").unwrap();
    let account = vault::read_header(&s.dir).unwrap().keychain_account.unwrap();
    // As an earlier build wrote it: the bare key and no MAC.
    entry(&account).set_secret(dek.as_bytes()).unwrap();
    let mut h = vault::read_header(&s.dir).unwrap();
    h.protection_mac = None;
    vault::write_header(&s.dir, &h).unwrap();

    let (h, key) = ProfileManager::unlock(&s.dir, Unlock::Keychain).unwrap();
    assert_eq!(key.as_bytes(), dek.as_bytes());
    assert!(h.protection_mac.is_some(), "the returned header is the upgraded one");
    assert_eq!(vault::read_header(&s.dir).unwrap().protection_mac, h.protection_mac);
    assert_ne!(entry(&account).get_secret().unwrap(), dek.as_bytes(), "the entry is tagged");
    assert!(ProfileManager::unlock(&s.dir, Unlock::Keychain).is_ok());
}
