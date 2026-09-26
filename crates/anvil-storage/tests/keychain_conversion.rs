//! Converting an OS-keychain profile to passphrase protection, against
//! keyring-core's in-memory mock credential store. The mock is installed as
//! the default store before any entry is created, so no real OS keychain is
//! read or written.
#![cfg(feature = "os-keychain")]

use anvil_domain::workspace::ProtectionMode;
use anvil_storage::vault::{self, VaultError};
use anvil_storage::{KdfParams, Key};

const SERVICE: &str = "com.ferrumedge.anvil";
const PASS: &str = "new passphrase 123";

fn mock_store() {
    static INSTALL: std::sync::Once = std::sync::Once::new();
    INSTALL.call_once(|| keyring_core::set_default_store(keyring_core::mock::Store::new().unwrap()));
    let store = keyring_core::get_default_store().expect("a default store is installed");
    assert!(store.as_any().is::<keyring_core::mock::Store>(), "tests must only use the mock credential store");
}

fn entry(account: &str) -> keyring_core::Entry {
    keyring_core::Entry::new(SERVICE, account).unwrap()
}

/// Make the next operation on this mock entry fail, as a locked or
/// unreachable credential store would.
fn fail_next(account: &str) {
    let e = entry(account);
    let cred = e.as_any().downcast_ref::<keyring_core::mock::Cred>().unwrap();
    cred.set_error(keyring_core::Error::NoStorageAccess(Box::new(std::io::Error::other("store locked"))));
}

/// What this build stores for `dek`: the key behind the entry tag.
fn tagged(dek: &Key) -> Vec<u8> {
    [b"anvil-dek-v2:".as_slice(), dek.as_bytes().as_slice()].concat()
}

/// Put a converted profile's old entry (holding `secret`) and its account
/// name back, as a conversion leaves them when it stops after publishing the
/// passphrase header, or when the store refuses both the delete and the
/// overwrite with the marker.
fn leave_entry_behind(dir: &std::path::Path, account: &str, secret: &[u8]) {
    entry(account).set_secret(secret).unwrap();
    let mut h = vault::read_header(dir).unwrap();
    h.keychain_account = Some(account.into());
    vault::write_header(dir, &h).unwrap();
}

#[test]
fn converted_profile_unlocks_only_with_passphrase_or_recovery_key() {
    mock_store();
    let dir = tempfile::tempdir().unwrap();
    let created = vault::create_keychain_profile(dir.path(), "local").unwrap();
    let old = created.header.clone();
    let account = old.keychain_account.clone().unwrap();
    let mut h = vault::read_header(dir.path()).unwrap();

    let conv = vault::convert_keychain_to_passphrase(dir.path(), &mut h, &created.dek, PASS, KdfParams::testing()).unwrap();
    assert!(conv.keychain_entry_removed);

    let h = vault::read_header(dir.path()).unwrap();
    assert_eq!(h.protection, ProtectionMode::Passphrase);
    assert!(h.keychain_account.is_none(), "the retired account name is forgotten");
    assert!(h.recovery_wrap.is_some(), "a converted profile gets a recovery key");
    assert_eq!(vault::unlock_with_passphrase(&h, PASS).unwrap().as_bytes(), created.dek.as_bytes());
    assert_eq!(vault::unlock_with_recovery(&h, &conv.recovery_key).unwrap().as_bytes(), created.dek.as_bytes());
    assert!(matches!(vault::unlock_with_passphrase(&h, "not the passphrase"), Err(VaultError::WrongSecret)));

    // The keychain path is refused by mode, and the key is gone from the store.
    assert!(matches!(vault::unlock_with_keychain(&h), Err(VaultError::WrongProtection(_))));
    assert!(matches!(entry(&account).get_secret(), Err(keyring_core::Error::NoEntry)));
    assert!(vault::unlock_with_keychain(&old).is_err(), "the pre-conversion header no longer unlocks either");

    // Unlock methods follow the header's mode: a header claiming keychain
    // mode does not accept the passphrase or recovery key.
    let mut flipped = h.clone();
    flipped.protection = ProtectionMode::OsKeychain;
    assert!(matches!(vault::unlock_with_passphrase(&flipped, PASS), Err(VaultError::WrongProtection(_))));
    assert!(matches!(vault::unlock_with_recovery(&flipped, &conv.recovery_key), Err(VaultError::WrongProtection(_))));
}

#[test]
fn a_conversion_stops_unchanged_when_the_store_refuses_to_tag_the_entry() {
    mock_store();
    let dir = tempfile::tempdir().unwrap();
    let created = vault::create_keychain_profile(dir.path(), "local").unwrap();
    let account = created.header.keychain_account.clone().unwrap();
    let before = std::fs::read(vault::header_path(dir.path())).unwrap();
    let mut h = vault::read_header(dir.path()).unwrap();

    fail_next(&account);
    let r = vault::convert_keychain_to_passphrase(dir.path(), &mut h, &created.dek, PASS, KdfParams::testing());
    assert!(matches!(r, Err(VaultError::KeychainUnavailable(_))));
    assert_eq!(std::fs::read(vault::header_path(dir.path())).unwrap(), before, "the header is unchanged");
    let h = vault::read_header(dir.path()).unwrap();
    assert_eq!(vault::unlock_with_keychain(&h).unwrap().as_bytes(), created.dek.as_bytes(), "still a keychain profile");
}

#[test]
fn an_entry_left_behind_still_refuses_keychain_unlock_and_is_retried() {
    mock_store();
    let dir = tempfile::tempdir().unwrap();
    let created = vault::create_keychain_profile(dir.path(), "local").unwrap();
    let account = created.header.keychain_account.clone().unwrap();
    let mut h = vault::read_header(dir.path()).unwrap();
    vault::convert_keychain_to_passphrase(dir.path(), &mut h, &created.dek, PASS, KdfParams::testing()).unwrap();
    leave_entry_behind(dir.path(), &account, &tagged(&created.dek));

    let mut h = vault::read_header(dir.path()).unwrap();
    assert_eq!(h.protection, ProtectionMode::Passphrase);
    assert!(matches!(vault::unlock_with_keychain(&h), Err(VaultError::WrongProtection(_))));
    assert!(vault::unlock_with_passphrase(&h, PASS).is_ok());

    vault::retire_keychain_entry(dir.path(), &mut h).unwrap();
    assert!(matches!(entry(&account).get_secret(), Err(keyring_core::Error::NoEntry)));
    assert!(vault::read_header(dir.path()).unwrap().keychain_account.is_none());
    // Nothing left to do.
    vault::retire_keychain_entry(dir.path(), &mut h).unwrap();
}

#[test]
fn modes_are_not_crossed_by_passphrase_operations() {
    mock_store();
    let kc_dir = tempfile::tempdir().unwrap();
    let kc = vault::create_keychain_profile(kc_dir.path(), "local").unwrap();
    let mut h = vault::read_header(kc_dir.path()).unwrap();
    let r = vault::change_passphrase(kc_dir.path(), &mut h, &kc.dek, PASS, KdfParams::testing());
    assert!(matches!(r, Err(VaultError::WrongProtection(_))));
    let h = vault::read_header(kc_dir.path()).unwrap();
    assert_eq!(h.protection, ProtectionMode::OsKeychain);
    assert!(h.passphrase_wrap.is_none());
    assert_eq!(vault::unlock_with_keychain(&h).unwrap().as_bytes(), kc.dek.as_bytes());
    // Keychain profiles never have their entry retired.
    let mut still_keychain = h.clone();
    assert!(vault::retire_keychain_entry(kc_dir.path(), &mut still_keychain).is_err());
    assert!(vault::unlock_with_keychain(&h).is_ok());

    let pw_dir = tempfile::tempdir().unwrap();
    let pw = vault::create_passphrase_profile(pw_dir.path(), "pw", "old passphrase 1", KdfParams::testing()).unwrap();
    let mut h = vault::read_header(pw_dir.path()).unwrap();
    let r = vault::convert_keychain_to_passphrase(pw_dir.path(), &mut h, &pw.dek, PASS, KdfParams::testing());
    assert!(matches!(r, Err(VaultError::WrongProtection(_))));
    assert!(vault::unlock_with_passphrase(&vault::read_header(pw_dir.path()).unwrap(), "old passphrase 1").is_ok());

    // A key that is not this profile's is never wrapped.
    let mut h = vault::read_header(kc_dir.path()).unwrap();
    let r = vault::convert_keychain_to_passphrase(kc_dir.path(), &mut h, &pw.dek, PASS, KdfParams::testing());
    assert!(matches!(r, Err(VaultError::WrongSecret)));
    assert_eq!(vault::read_header(kc_dir.path()).unwrap().protection, ProtectionMode::OsKeychain);
}

#[test]
fn retiring_never_deletes_another_profiles_entry() {
    mock_store();
    let other_dir = tempfile::tempdir().unwrap();
    let other = vault::create_keychain_profile(other_dir.path(), "other").unwrap();
    let other_account = other.header.keychain_account.clone().unwrap();

    let dir = tempfile::tempdir().unwrap();
    vault::create_passphrase_profile(dir.path(), "pw", PASS, KdfParams::testing()).unwrap();
    let mut h = vault::read_header(dir.path()).unwrap();
    h.keychain_account = Some(other_account.clone());
    vault::write_header(dir.path(), &h).unwrap();

    vault::retire_keychain_entry(dir.path(), &mut h).unwrap();
    assert!(vault::read_header(dir.path()).unwrap().keychain_account.is_none());
    let other_h = vault::read_header(other_dir.path()).unwrap();
    assert_eq!(vault::unlock_with_keychain(&other_h).unwrap().as_bytes(), other.dek.as_bytes());
}

#[test]
fn retry_with_a_stale_header_keeps_a_newer_passphrase() {
    mock_store();
    let dir = tempfile::tempdir().unwrap();
    let created = vault::create_keychain_profile(dir.path(), "local").unwrap();
    let account = created.header.keychain_account.clone().unwrap();
    let mut h = vault::read_header(dir.path()).unwrap();
    vault::convert_keychain_to_passphrase(dir.path(), &mut h, &created.dek, PASS, KdfParams::testing()).unwrap();
    leave_entry_behind(dir.path(), &account, &tagged(&created.dek));

    // An unlock read this header, then another process changed the passphrase
    // before the unlock retried the removal.
    let mut stale = vault::read_header(dir.path()).unwrap();
    let mut other = stale.clone();
    vault::change_passphrase(dir.path(), &mut other, &created.dek, "changed elsewhere 1", KdfParams::testing()).unwrap();

    vault::retire_keychain_entry(dir.path(), &mut stale).unwrap();
    assert!(matches!(entry(&account).get_secret(), Err(keyring_core::Error::NoEntry)));
    let h = vault::read_header(dir.path()).unwrap();
    assert!(h.keychain_account.is_none());
    assert!(vault::unlock_with_passphrase(&h, "changed elsewhere 1").is_ok(), "the newer passphrase is kept");
    assert!(matches!(vault::unlock_with_passphrase(&h, PASS), Err(VaultError::WrongSecret)));

    // A header that no longer names the account is left untouched, and the
    // caller's stale copy becomes the header on disk.
    let mut named = h.clone();
    named.keychain_account = Some(account.clone());
    named.passphrase_wrap = None;
    let before = std::fs::read(vault::header_path(dir.path())).unwrap();
    vault::retire_keychain_entry(dir.path(), &mut named).unwrap();
    assert_eq!(std::fs::read(vault::header_path(dir.path())).unwrap(), before);
    assert!(named.keychain_account.is_none());
    assert!(vault::unlock_with_passphrase(&named, "changed elsewhere 1").is_ok());
}

/// Strip the protection MAC, as a header written by an earlier build has none.
fn strip_mac(dir: &std::path::Path) -> vault::ProfileHeader {
    let mut h = vault::read_header(dir).unwrap();
    h.protection_mac = None;
    vault::write_header(dir, &h).unwrap();
    h
}

#[test]
fn a_header_edited_back_to_keychain_mode_does_not_unlock_from_the_leftover_entry() {
    mock_store();
    let dir = tempfile::tempdir().unwrap();
    let created = vault::create_keychain_profile(dir.path(), "local").unwrap();
    let account = created.header.keychain_account.clone().unwrap();
    let mut h = vault::read_header(dir.path()).unwrap();
    let conv = vault::convert_keychain_to_passphrase(dir.path(), &mut h, &created.dek, PASS, KdfParams::testing()).unwrap();
    leave_entry_behind(dir.path(), &account, &tagged(&created.dek));

    // The mode is authenticated: flipping it back breaks the MAC.
    let mut flipped = vault::read_header(dir.path()).unwrap();
    flipped.protection = ProtectionMode::OsKeychain;
    assert!(matches!(vault::unlock_with_keychain(&flipped), Err(VaultError::HeaderTampered)));
    // Without a MAC it would pass for an earlier build's header, but the
    // entry was written for a MAC'd header.
    flipped.protection_mac = None;
    assert!(matches!(vault::unlock_with_keychain(&flipped), Err(VaultError::HeaderTampered)));
    // A MAC that is not even hex is refused as well.
    flipped.protection_mac = Some("zz".into());
    assert!(matches!(vault::unlock_with_keychain(&flipped), Err(VaultError::HeaderTampered)));

    // The genuine passphrase header still opens, and its MAC is checked too.
    let h = vault::read_header(dir.path()).unwrap();
    assert!(vault::unlock_with_passphrase(&h, PASS).is_ok());
    let mut forged = h.clone();
    forged.profile_id = "another profile".into();
    assert!(matches!(vault::unlock_with_passphrase(&forged, PASS), Err(VaultError::HeaderTampered)));
    assert!(matches!(vault::unlock_with_recovery(&forged, &conv.recovery_key), Err(VaultError::HeaderTampered)));
}

#[test]
fn a_keychain_profile_from_an_earlier_build_is_upgraded_at_unlock() {
    mock_store();
    let dir = tempfile::tempdir().unwrap();
    let created = vault::create_keychain_profile(dir.path(), "local").unwrap();
    let account = created.header.keychain_account.clone().unwrap();
    // Earlier builds stored the bare key and wrote no MAC.
    entry(&account).set_secret(created.dek.as_bytes()).unwrap();
    let mut h = strip_mac(dir.path());

    let dek = vault::unlock_with_keychain(&h).unwrap();
    assert_eq!(dek.as_bytes(), created.dek.as_bytes(), "still opens");
    vault::upgrade_header(dir.path(), &mut h, &dek).unwrap();
    assert!(h.protection_mac.is_some());
    assert_eq!(vault::read_header(dir.path()).unwrap().protection_mac, h.protection_mac);
    assert_ne!(entry(&account).get_secret().unwrap(), created.dek.as_bytes(), "the entry is tagged");
    assert_eq!(vault::unlock_with_keychain(&h).unwrap().as_bytes(), created.dek.as_bytes());

    // From now on a header without a MAC does not unlock from the entry.
    let stripped = strip_mac(dir.path());
    assert!(matches!(vault::unlock_with_keychain(&stripped), Err(VaultError::HeaderTampered)));
}

#[test]
fn an_untagged_entry_is_tagged_at_the_next_unlock_once_the_header_has_a_mac() {
    mock_store();
    let dir = tempfile::tempdir().unwrap();
    let created = vault::create_keychain_profile(dir.path(), "local").unwrap();
    let account = created.header.keychain_account.clone().unwrap();
    // The MAC was written but tagging the entry failed.
    entry(&account).set_secret(created.dek.as_bytes()).unwrap();
    let h = vault::read_header(dir.path()).unwrap();
    assert!(h.protection_mac.is_some());

    assert_eq!(vault::unlock_with_keychain(&h).unwrap().as_bytes(), created.dek.as_bytes());
    assert_ne!(entry(&account).get_secret().unwrap(), created.dek.as_bytes(), "the entry is tagged");
    assert!(matches!(vault::unlock_with_keychain(&strip_mac(dir.path())), Err(VaultError::HeaderTampered)));
}

#[test]
fn a_converted_header_from_an_earlier_build_is_sealed_at_the_next_unlock() {
    mock_store();
    let dir = tempfile::tempdir().unwrap();
    let created = vault::create_keychain_profile(dir.path(), "local").unwrap();
    let account = created.header.keychain_account.clone().unwrap();
    let mut h = vault::read_header(dir.path()).unwrap();
    vault::convert_keychain_to_passphrase(dir.path(), &mut h, &created.dek, PASS, KdfParams::testing()).unwrap();
    // As an earlier build left it: no MAC, the bare key still in the store.
    leave_entry_behind(dir.path(), &account, created.dek.as_bytes());
    let mut h = strip_mac(dir.path());

    // Edited back to keychain mode, it still carries the passphrase and
    // recovery wraps no keychain header has, so it is neither unlocked from
    // the untagged entry nor sealed.
    let mut flipped = h.clone();
    flipped.protection = ProtectionMode::OsKeychain;
    assert!(matches!(vault::unlock_with_keychain(&flipped), Err(VaultError::HeaderTampered)));
    assert!(matches!(vault::upgrade_header(dir.path(), &mut flipped, &created.dek), Err(VaultError::HeaderTampered)));
    assert!(vault::read_header(dir.path()).unwrap().protection_mac.is_none(), "nothing was sealed");

    let dek = vault::unlock_with_passphrase(&h, PASS).unwrap();
    vault::upgrade_header(dir.path(), &mut h, &dek).unwrap();
    assert!(h.protection_mac.is_some());
    assert_eq!(h.keychain_account.as_deref(), Some(account.as_str()), "the upgrade leaves the leftover entry to retiring");

    // Once sealed, the header cannot be turned back to keychain mode.
    let mut flipped = vault::read_header(dir.path()).unwrap();
    flipped.protection = ProtectionMode::OsKeychain;
    assert!(matches!(vault::unlock_with_keychain(&flipped), Err(VaultError::HeaderTampered)));

    // Upgrading an up-to-date header changes nothing.
    let before = std::fs::read(vault::header_path(dir.path())).unwrap();
    vault::upgrade_header(dir.path(), &mut h, &dek).unwrap();
    assert_eq!(std::fs::read(vault::header_path(dir.path())).unwrap(), before);
}

#[test]
fn a_passphrase_profile_from_an_earlier_build_is_sealed_at_unlock() {
    let dir = tempfile::tempdir().unwrap();
    let created = vault::create_passphrase_profile(dir.path(), "pw", PASS, KdfParams::testing()).unwrap();
    assert!(created.header.protection_mac.is_some(), "new headers are sealed");
    let mut h = strip_mac(dir.path());
    let dek = vault::unlock_with_passphrase(&h, PASS).unwrap();
    // Another key cannot seal it.
    let other = vault::create_passphrase_profile(tempfile::tempdir().unwrap().path(), "other", PASS, KdfParams::testing()).unwrap();
    assert!(matches!(vault::upgrade_header(dir.path(), &mut h, &other.dek), Err(VaultError::WrongSecret)));
    assert!(vault::read_header(dir.path()).unwrap().protection_mac.is_none());

    vault::upgrade_header(dir.path(), &mut h, &dek).unwrap();
    let sealed = vault::read_header(dir.path()).unwrap();
    assert!(sealed.protection_mac.is_some());
    assert!(vault::unlock_with_passphrase(&sealed, PASS).is_ok());
    assert!(vault::unlock_with_recovery(&sealed, created.recovery_key.as_ref().unwrap()).is_ok());
}

#[test]
fn concurrent_header_writers_do_not_share_a_temporary_file() {
    let dir = tempfile::tempdir().unwrap();
    vault::create_passphrase_profile(dir.path(), "pw", PASS, KdfParams::testing()).unwrap();
    let h = vault::read_header(dir.path()).unwrap();
    std::thread::scope(|s| {
        for i in 0..8 {
            let (path, mut h) = (dir.path(), h.clone());
            s.spawn(move || {
                for j in 0..25 {
                    h.display_name = format!("writer {i} write {j}");
                    vault::write_header(path, &h).unwrap();
                }
            });
        }
    });
    assert!(vault::read_header(dir.path()).unwrap().display_name.starts_with("writer "));
    let mut left: Vec<String> =
        std::fs::read_dir(dir.path()).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
    left.sort();
    assert_eq!(left, ["profile.json", "profile.lock"], "no temporary file is left behind");
}

#[test]
fn a_header_write_removes_temporary_files_abandoned_long_ago() {
    let dir = tempfile::tempdir().unwrap();
    vault::create_passphrase_profile(dir.path(), "pw", PASS, KdfParams::testing()).unwrap();
    let file = |name: &str, age_secs: u64| {
        let path = dir.path().join(name);
        let f = std::fs::File::create(&path).unwrap();
        f.set_modified(std::time::SystemTime::now() - std::time::Duration::from_secs(age_secs)).unwrap();
        path
    };
    let abandoned = file("profile.json.4242.00ff00ff00ff00ff.tmp", 3600);
    let in_flight = file("profile.json.4243.0123456789abcdef.tmp", 0);
    let unrelated = file("notes.tmp", 3600);

    vault::write_header(dir.path(), &vault::read_header(dir.path()).unwrap()).unwrap();
    assert!(!abandoned.exists(), "a writer that stopped an hour ago left it");
    assert!(in_flight.exists(), "a recent one may still be another writer's");
    assert!(unrelated.exists());
}
