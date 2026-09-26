//! Keychain profiles against the real OS credential store: the macOS
//! Keychain, the Windows Credential Manager and the freedesktop Secret
//! Service on Linux. This is the first-run "Start now — no password" path, so
//! it must work on every desktop platform.
//!
//! Ignored by default so a developer's own keychain is never touched (or a
//! permission prompt raised) by a plain `cargo test`. CI runs it on all three
//! platforms with `cargo test -p anvil-storage --test os_keychain -- --ignored`;
//! Linux CI provides a Secret Service with gnome-keyring in a D-Bus session.
#![cfg(feature = "os-keychain")]

use anvil_domain::workspace::ProtectionMode;
use anvil_storage::vault::{self, VaultError};

#[test]
#[ignore = "touches the real OS credential store; CI runs it with --ignored"]
fn keychain_profile_round_trips_through_the_os_credential_store() {
    let dir = tempfile::tempdir().unwrap();
    let created = vault::create_keychain_profile(dir.path(), "ci keychain").expect("the OS credential store accepted the data key");
    let h = vault::read_header(dir.path()).unwrap();
    assert_eq!(h.protection, ProtectionMode::OsKeychain);
    assert!(h.passphrase_wrap.is_none() && h.recovery_wrap.is_none(), "a keychain profile has no passphrase or recovery wrap");

    // A later launch reads the same key back from the store.
    let key = vault::unlock_with_keychain(&h).expect("the key comes back from the OS credential store");
    assert_eq!(key.as_bytes(), created.dek.as_bytes());

    // The key itself is not in the profile directory.
    for entry in std::fs::read_dir(dir.path()).unwrap() {
        let bytes = std::fs::read(entry.unwrap().path()).unwrap();
        assert!(!bytes.windows(created.dek.as_bytes().len()).any(|w| w == created.dek.as_bytes()), "data key written to disk");
    }

    // Removing the entry makes the profile unopenable (only a backup restores it).
    vault::delete_keychain_entry(&h).expect("the entry is removed");
    assert!(matches!(vault::unlock_with_keychain(&h), Err(VaultError::KeychainUnavailable(_))));
}
