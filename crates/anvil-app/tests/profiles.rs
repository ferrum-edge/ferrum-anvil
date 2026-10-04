//! Draft enrollment refusal and legacy keychain compatibility (mock OS store).

use anvil_app::profiles::{ProfileManager, Unlock};
use anvil_storage::vault::{self, VaultError};

#[test]
fn draft_keychain_refusal_has_no_effect_and_legacy_keychain_still_installs() {
    let store = keyring_core::mock::Store::new().unwrap();
    keyring_core::set_default_store(store.clone());
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("draft");
    let before = store.inner.lock().unwrap().borrow().len();
    assert!(matches!(
        vault::create_keychain_profile_with_identity_expectation(&dir, "draft"),
        Err(VaultError::DraftKeychainEnrollmentDeferred),
    ));
    assert!(!dir.exists());
    assert_eq!(store.inner.lock().unwrap().borrow().len(), before);
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);

    let occupied = root.path().join("occupied");
    std::fs::create_dir(&occupied).unwrap();
    std::fs::write(occupied.join(vault::PROFILE_FILE), b"existing profile bytes").unwrap();
    assert!(matches!(
        vault::create_keychain_profile_with_identity_expectation(&occupied, "draft"),
        Err(VaultError::DraftKeychainEnrollmentDeferred),
    ));
    assert_eq!(std::fs::read(occupied.join(vault::PROFILE_FILE)).unwrap(), b"existing profile bytes");
    assert_eq!(std::fs::read_dir(&occupied).unwrap().count(), 1);
    assert_eq!(store.inner.lock().unwrap().borrow().len(), before);

    let manager = ProfileManager::new(root.path());
    let (summary, _) = manager.create_keychain("legacy").unwrap();
    let header = vault::read_header(&summary.dir).unwrap();
    assert_eq!(header.format, "anvil-profile");
    assert!(header.identity_binding.is_none());
    let app = ProfileManager::authorize_unlock(&summary.dir, Unlock::Keychain, None).unwrap().open().unwrap();
    assert!(!app.is_locked());
    app.create_workspace("legacy support").unwrap();
    app.lock();
    let authorization = ProfileManager::authorize_unlock(&summary.dir, Unlock::Keychain, None).unwrap();
    authorization.install(|_, _, key| app.unlock(key)).unwrap();
    assert!(app.find_workspace("legacy support").is_ok());
    drop(app);

    // Earlier builds stored an untagged key and a header without a MAC.
    let key = vault::unlock_with_keychain(&header).unwrap();
    let account = header.keychain_account.as_deref().unwrap();
    let entry = keyring_core::Entry::new(vault::KEYCHAIN_SERVICE, account).unwrap();
    entry.set_secret(key.as_bytes()).unwrap();
    let mut earlier = header;
    earlier.protection_mac = None;
    vault::write_header(&summary.dir, &earlier).unwrap();
    let app = ProfileManager::authorize_unlock(&summary.dir, Unlock::Keychain, None).unwrap().open().unwrap();
    assert!(app.header.protection_mac.is_some());
    assert_ne!(entry.get_secret().unwrap(), key.as_bytes());
    assert!(app.find_workspace("legacy support").is_ok());
}
