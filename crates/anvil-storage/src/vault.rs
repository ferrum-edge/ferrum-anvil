//! Profile vault: the data-encryption key (DEK) and how it is unlocked.
//!
//! * The DEK is random and encrypts all profile data.
//! * Passphrase mode: the DEK is wrapped by an Argon2id-derived key and,
//!   separately, by a random recovery key shown once at setup. Either unlocks.
//!   Resetting a forgotten passphrase is impossible without the recovery key
//!   or a portable encrypted backup — by design.
//! * OS-keychain mode: the DEK lives in the OS credential store (Keychain,
//!   Credential Manager, Secret Service). Data stays encrypted at rest, but an
//!   unlocked OS session is the only barrier; this is stated in the UI.
//! * An OS-keychain profile can be converted to passphrase mode. The new
//!   header is published first; from then on only the passphrase or the new
//!   recovery key unlocks, and the keychain entry is removed (retried at
//!   each unlock until it is gone if the credential store refuses).
//! * A linked provider identity (Google/GitHub/Facebook) is never a key.

use crate::crypto::{self, CryptoError, KdfParams, Key};
use anvil_domain::workspace::ProtectionMode;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

pub const PROFILE_FILE: &str = "profile.json";
const KEYCHAIN_SERVICE: &str = "com.ferrumedge.anvil";
const PASSPHRASE_LABEL: &[u8] = b"anvil-dek-passphrase-v1";
const RECOVERY_LABEL: &[u8] = b"anvil-dek-recovery-v1";

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("the passphrase or recovery key is not correct")]
    WrongSecret,
    #[error("the OS credential store is unavailable ({0}); use a passphrase-protected profile instead")]
    KeychainUnavailable(String),
    #[error("this profile is not protected by {0}")]
    WrongProtection(&'static str),
    #[error("profile header is missing or unreadable: {0}")]
    Header(String),
    #[error("{0}")]
    Crypto(#[from] CryptoError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrappedKey {
    pub kdf: Option<KdfParams>,
    /// base64 salt (passphrase wrapping only).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub salt: String,
    /// base64 AEAD envelope of the DEK.
    pub envelope: String,
}

/// Plaintext profile header (contains no secrets).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileHeader {
    pub format: String,
    pub schema_version: u32,
    pub profile_id: String,
    pub display_name: String,
    pub protection: ProtectionMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passphrase_wrap: Option<WrappedKey>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_wrap: Option<WrappedKey>,
    /// Keychain account name (OS-keychain mode).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keychain_account: Option<String>,
    /// SHA-256 of the DEK under a fixed label — lets the app detect a
    /// keychain entry that belongs to a different profile.
    pub key_check: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

fn key_check(k: &Key) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"anvil-dek-check-v1");
    h.update(k.as_bytes());
    hex::encode(&h.finalize()[..16])
}

fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}

fn unb64(s: &str) -> Result<Vec<u8>, VaultError> {
    base64::engine::general_purpose::STANDARD.decode(s).map_err(|e| VaultError::Header(e.to_string()))
}

fn wrap_with_passphrase(dek: &Key, passphrase: &str, kdf: KdfParams, label: &[u8]) -> Result<WrappedKey, VaultError> {
    let salt = crypto::random_bytes(16);
    let kek = crypto::derive(passphrase.as_bytes(), &salt, &kdf)?;
    Ok(WrappedKey { kdf: Some(kdf), salt: b64(&salt), envelope: b64(&crypto::seal(&kek, label, dek.as_bytes())) })
}

fn unwrap_with_passphrase(w: &WrappedKey, passphrase: &str, label: &[u8]) -> Result<Key, VaultError> {
    let kdf = w.kdf.ok_or_else(|| VaultError::Header("missing KDF parameters".into()))?;
    let kek = crypto::derive(passphrase.as_bytes(), &unb64(&w.salt)?, &kdf)?;
    let dek = crypto::open(&kek, label, &unb64(&w.envelope)?).map_err(|_| VaultError::WrongSecret)?;
    Ok(Key::from_bytes(&dek)?)
}

/// Human-friendly recovery key: 32 random bytes as base32 groups.
pub fn format_recovery_key(raw: &[u8]) -> String {
    const ALPHA: &[u8; 32] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut bits = 0u32;
    let mut nbits = 0;
    let mut out = String::new();
    for &b in raw {
        bits = (bits << 8) | b as u32;
        nbits += 8;
        while nbits >= 5 {
            nbits -= 5;
            out.push(ALPHA[((bits >> nbits) & 31) as usize] as char);
        }
    }
    if nbits > 0 {
        out.push(ALPHA[((bits << (5 - nbits)) & 31) as usize] as char);
    }
    out.as_bytes().chunks(4).map(|c| std::str::from_utf8(c).unwrap_or("")).collect::<Vec<_>>().join("-")
}

fn normalize_recovery(s: &str) -> String {
    s.chars().filter(|c| c.is_ascii_alphanumeric()).map(|c| c.to_ascii_uppercase()).collect()
}

pub struct CreatedProfile {
    pub header: ProfileHeader,
    pub dek: Key,
    /// Shown to the user once; never stored.
    pub recovery_key: Option<Zeroizing<String>>,
}

pub fn header_path(dir: &Path) -> PathBuf {
    dir.join(PROFILE_FILE)
}

pub fn read_header(dir: &Path) -> Result<ProfileHeader, VaultError> {
    let text = std::fs::read_to_string(header_path(dir)).map_err(|e| VaultError::Header(e.to_string()))?;
    serde_json::from_str(&text).map_err(|e| VaultError::Header(e.to_string()))
}

/// Atomically replace the header: write a synced temporary file, rename it
/// over the old one and sync the directory so the rename persists.
///
/// Once the rename has succeeded the new header is live, so the directory
/// sync is best effort: some file systems (FUSE, SMB) refuse it, and failing
/// there would report an error for a header that was in fact written.
pub fn write_header(dir: &Path, h: &ProfileHeader) -> Result<(), VaultError> {
    use std::io::Write;
    std::fs::create_dir_all(dir)?;
    let tmp = dir.join(format!("{PROFILE_FILE}.tmp"));
    let mut f = std::fs::File::create(&tmp)?;
    f.write_all(&serde_json::to_vec_pretty(h).map_err(|e| VaultError::Header(e.to_string()))?)?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(tmp, header_path(dir))?;
    if let Err(e) = sync_dir(dir) {
        tracing::warn!(dir = %dir.display(), error = %e, "profile directory sync failed after the header was replaced");
    }
    Ok(())
}

/// Flush a directory so a rename inside it survives a power loss.
#[cfg(unix)]
fn sync_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::File::open(dir)?.sync_all()
}

/// Flush a directory so a rename inside it survives a power loss. A directory
/// handle needs backup semantics, and FlushFileBuffers needs write access.
#[cfg(windows)]
fn sync_dir(dir: &Path) -> std::io::Result<()> {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    std::fs::OpenOptions::new().write(true).custom_flags(FILE_FLAG_BACKUP_SEMANTICS).open(dir)?.sync_all()
}

#[cfg(not(any(unix, windows)))]
fn sync_dir(_dir: &Path) -> std::io::Result<()> {
    Ok(())
}

fn require_protection(h: &ProfileHeader, mode: ProtectionMode) -> Result<(), VaultError> {
    if h.protection == mode {
        return Ok(());
    }
    Err(VaultError::WrongProtection(match mode {
        ProtectionMode::Passphrase => "a passphrase",
        ProtectionMode::OsKeychain => "the OS keychain",
    }))
}

/// The unlocked data key must be this profile's before it is re-wrapped.
fn require_profile_key(h: &ProfileHeader, dek: &Key) -> Result<(), VaultError> {
    if key_check(dek) != h.key_check {
        return Err(VaultError::WrongSecret);
    }
    Ok(())
}

/// Create a new passphrase-protected profile.
pub fn create_passphrase_profile(dir: &Path, display_name: &str, passphrase: &str, kdf: KdfParams) -> Result<CreatedProfile, VaultError> {
    let dek = Key::random();
    let recovery_raw = crypto::random_bytes(20);
    let recovery = format_recovery_key(&recovery_raw);
    let header = ProfileHeader {
        format: "anvil-profile".into(),
        schema_version: anvil_domain::SCHEMA_VERSION,
        profile_id: uuid::Uuid::now_v7().to_string(),
        display_name: display_name.into(),
        protection: ProtectionMode::Passphrase,
        passphrase_wrap: Some(wrap_with_passphrase(&dek, passphrase, kdf, PASSPHRASE_LABEL)?),
        recovery_wrap: Some(wrap_with_passphrase(&dek, &normalize_recovery(&recovery), kdf, RECOVERY_LABEL)?),
        keychain_account: None,
        key_check: key_check(&dek),
        created_at: chrono::Utc::now(),
    };
    write_header(dir, &header)?;
    Ok(CreatedProfile { header, dek, recovery_key: Some(Zeroizing::new(recovery)) })
}

pub fn unlock_with_passphrase(h: &ProfileHeader, passphrase: &str) -> Result<Key, VaultError> {
    require_protection(h, ProtectionMode::Passphrase)?;
    let w = h.passphrase_wrap.as_ref().ok_or(VaultError::WrongSecret)?;
    let k = unwrap_with_passphrase(w, passphrase, PASSPHRASE_LABEL)?;
    if key_check(&k) != h.key_check {
        return Err(VaultError::WrongSecret);
    }
    Ok(k)
}

pub fn unlock_with_recovery(h: &ProfileHeader, recovery: &str) -> Result<Key, VaultError> {
    require_protection(h, ProtectionMode::Passphrase)?;
    let w = h.recovery_wrap.as_ref().ok_or(VaultError::WrongSecret)?;
    let k = unwrap_with_passphrase(w, &normalize_recovery(recovery), RECOVERY_LABEL)?;
    if key_check(&k) != h.key_check {
        return Err(VaultError::WrongSecret);
    }
    Ok(k)
}

/// Replace the passphrase wrap of a passphrase profile (requires the
/// unlocked DEK). The recovery key stays valid. An OS-keychain profile is
/// refused; it changes mode with [`convert_keychain_to_passphrase`].
pub fn change_passphrase(dir: &Path, h: &mut ProfileHeader, dek: &Key, new_passphrase: &str, kdf: KdfParams) -> Result<(), VaultError> {
    require_protection(h, ProtectionMode::Passphrase)?;
    require_profile_key(h, dek)?;
    let mut next = h.clone();
    next.passphrase_wrap = Some(wrap_with_passphrase(dek, new_passphrase, kdf, PASSPHRASE_LABEL)?);
    write_header(dir, &next)?;
    *h = next;
    Ok(())
}

/// Result of [`convert_keychain_to_passphrase`].
#[cfg(feature = "os-keychain")]
pub struct KeychainConversion {
    /// The new recovery key. Shown to the user once; never stored.
    pub recovery_key: Zeroizing<String>,
    /// False when the OS credential store did not remove the old entry. The
    /// profile no longer unlocks from the keychain either way, and removal is
    /// retried by [`retire_keychain_entry`].
    pub keychain_entry_removed: bool,
}

/// Convert an OS-keychain profile to passphrase protection (requires the
/// unlocked DEK). The data key is unchanged, so nothing is re-encrypted.
///
/// The passphrase header, with a new recovery wrap, is durably written
/// before the keychain entry is touched; from that point the keychain path
/// is refused because the header's protection mode is `Passphrase`. The
/// header keeps the old account name only until the entry is gone.
#[cfg(feature = "os-keychain")]
pub fn convert_keychain_to_passphrase(
    dir: &Path,
    h: &mut ProfileHeader,
    dek: &Key,
    new_passphrase: &str,
    kdf: KdfParams,
) -> Result<KeychainConversion, VaultError> {
    require_protection(h, ProtectionMode::OsKeychain)?;
    require_profile_key(h, dek)?;
    let recovery = Zeroizing::new(format_recovery_key(&crypto::random_bytes(20)));
    let mut next = h.clone();
    next.protection = ProtectionMode::Passphrase;
    next.passphrase_wrap = Some(wrap_with_passphrase(dek, new_passphrase, kdf, PASSPHRASE_LABEL)?);
    next.recovery_wrap = Some(wrap_with_passphrase(dek, &normalize_recovery(&recovery), kdf, RECOVERY_LABEL)?);
    write_header(dir, &next)?;
    *h = next;
    let keychain_entry_removed = retire_keychain_entry(dir, h).is_ok();
    Ok(KeychainConversion { recovery_key: recovery, keychain_entry_removed })
}

/// Remove the keychain entry a converted (now passphrase) profile left
/// behind, then forget its account name. A no-op when none is recorded.
/// An entry holding a different key is not this profile's: it is forgotten,
/// never deleted. Keychain profiles are refused (their entry is their key).
#[cfg(feature = "os-keychain")]
pub fn retire_keychain_entry(dir: &Path, h: &mut ProfileHeader) -> Result<(), VaultError> {
    require_protection(h, ProtectionMode::Passphrase)?;
    let Some(account) = h.keychain_account.as_deref() else {
        return Ok(());
    };
    let entry = keychain_entry(account)?;
    let unavailable = |e: keyring_core::Error| VaultError::KeychainUnavailable(e.to_string());
    match entry.get_secret() {
        Ok(secret) => {
            let secret = Zeroizing::new(secret);
            if Key::from_bytes(&secret).is_ok_and(|k| key_check(&k) == h.key_check) {
                #[cfg(test)]
                if let Some(hook) = BEFORE_DELETE.get() {
                    hook(&entry);
                }
                match entry.delete_credential() {
                    Ok(()) | Err(keyring_core::Error::NoEntry) => {}
                    Err(e) => return Err(unavailable(e)),
                }
            }
        }
        Err(keyring_core::Error::NoEntry) => {}
        Err(e) => return Err(unavailable(e)),
    }
    // `h` may have been read long before (an unlock runs the KDF first), so
    // edit the header on disk now rather than write `h` back: a passphrase
    // changed meanwhile by another process must not be undone. If the header
    // no longer names this account in passphrase mode, leave it alone.
    let mut next = read_header(dir)?;
    let same_profile = next.protection == ProtectionMode::Passphrase && next.key_check == h.key_check;
    if !same_profile || next.keychain_account.as_deref() != Some(account) {
        return Ok(());
    }
    next.keychain_account = None;
    write_header(dir, &next)?;
    *h = next;
    Ok(())
}

#[cfg(all(test, feature = "os-keychain"))]
thread_local! {
    /// Runs just before a retired entry is deleted, so a test can make the
    /// mock store refuse the delete after the read succeeded.
    static BEFORE_DELETE: std::cell::Cell<Option<fn(&keyring_core::Entry)>> = const { std::cell::Cell::new(None) };
}

/// The OS credential store entry holding a keychain profile's data key: the
/// macOS Keychain, the Windows Credential Manager, or the freedesktop Secret
/// Service (GNOME Keyring, KWallet) on Linux and the BSDs. There is no
/// in-memory fallback: a missing store is `KeychainUnavailable`.
#[cfg(feature = "os-keychain")]
fn keychain_entry(account: &str) -> Result<keyring_core::Entry, VaultError> {
    let unavailable = |e: &dyn std::fmt::Display| VaultError::KeychainUnavailable(e.to_string());
    // The platform store is installed on first use. A store installed
    // earlier (the in-memory mock in tests) is kept.
    if keyring_core::get_default_store().is_none() {
        keyring::Entry::store_status().as_ref().map_err(|e| unavailable(e))?;
    }
    // Windows defaults to "Enterprise" persistence, which roams with domain
    // user profiles. The key only unlocks files on this machine, so keep it here.
    // The in-memory mock store used by tests accepts no modifiers.
    #[cfg(windows)]
    let entry = if keyring_core::get_default_store().is_some_and(|s| s.as_any().is::<keyring_core::mock::Store>()) {
        keyring_core::Entry::new(KEYCHAIN_SERVICE, account)
    } else {
        keyring_core::Entry::new_with_modifiers(KEYCHAIN_SERVICE, account, &std::collections::HashMap::from([("persistence", "local")]))
    };
    #[cfg(not(windows))]
    let entry = keyring_core::Entry::new(KEYCHAIN_SERVICE, account);
    entry.map_err(|e| unavailable(&e))
}

#[cfg(feature = "os-keychain")]
pub fn create_keychain_profile(dir: &Path, display_name: &str) -> Result<CreatedProfile, VaultError> {
    let dek = Key::random();
    let profile_id = uuid::Uuid::now_v7().to_string();
    let account = format!("profile-{profile_id}");
    let entry = keychain_entry(&account)?;
    entry.set_secret(dek.as_bytes()).map_err(|e| VaultError::KeychainUnavailable(e.to_string()))?;
    let header = ProfileHeader {
        format: "anvil-profile".into(),
        schema_version: anvil_domain::SCHEMA_VERSION,
        profile_id,
        display_name: display_name.into(),
        protection: ProtectionMode::OsKeychain,
        passphrase_wrap: None,
        recovery_wrap: None,
        keychain_account: Some(account),
        key_check: key_check(&dek),
        created_at: chrono::Utc::now(),
    };
    write_header(dir, &header)?;
    Ok(CreatedProfile { header, dek, recovery_key: None })
}

#[cfg(feature = "os-keychain")]
pub fn unlock_with_keychain(h: &ProfileHeader) -> Result<Key, VaultError> {
    // Checked before the store is touched: a converted profile may still
    // name its old account until that entry is removed.
    require_protection(h, ProtectionMode::OsKeychain)?;
    let account = h.keychain_account.as_deref().ok_or_else(|| VaultError::Header("no keychain account recorded".into()))?;
    let entry = keychain_entry(account)?;
    let secret = entry.get_secret().map_err(|e| VaultError::KeychainUnavailable(e.to_string()))?;
    let k = Key::from_bytes(&secret)?;
    if key_check(&k) != h.key_check {
        return Err(VaultError::WrongSecret);
    }
    Ok(k)
}

/// Remove a keychain profile's data key from the OS credential store. The
/// profile can no longer be opened afterwards (portable backups still restore).
#[cfg(feature = "os-keychain")]
pub fn delete_keychain_entry(h: &ProfileHeader) -> Result<(), VaultError> {
    let account = h.keychain_account.as_deref().ok_or_else(|| VaultError::Header("no keychain account recorded".into()))?;
    let entry = keychain_entry(account)?;
    entry.delete_credential().map_err(|e| VaultError::KeychainUnavailable(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passphrase_and_recovery_both_unlock_and_wrong_fails() {
        let dir = tempfile::tempdir().unwrap();
        let c = create_passphrase_profile(dir.path(), "tester", "correct horse", KdfParams::testing()).unwrap();
        let h = read_header(dir.path()).unwrap();
        let k1 = unlock_with_passphrase(&h, "correct horse").unwrap();
        assert_eq!(k1.as_bytes(), c.dek.as_bytes());
        let k2 = unlock_with_recovery(&h, &c.recovery_key.as_ref().unwrap().to_lowercase()).unwrap();
        assert_eq!(k2.as_bytes(), c.dek.as_bytes());
        assert!(matches!(unlock_with_passphrase(&h, "wrong"), Err(VaultError::WrongSecret)));
        let raw = std::fs::read_to_string(header_path(dir.path())).unwrap();
        assert!(!raw.contains("correct horse"));
    }

    #[test]
    fn data_017_lost_passphrase_needs_recovery_key() {
        let dir = tempfile::tempdir().unwrap();
        let c = create_passphrase_profile(dir.path(), "t", "pw1", KdfParams::testing()).unwrap();
        let mut h = read_header(dir.path()).unwrap();
        // Recover with the recovery key, then set a new passphrase.
        let dek = unlock_with_recovery(&h, c.recovery_key.as_ref().unwrap()).unwrap();
        change_passphrase(dir.path(), &mut h, &dek, "pw2", KdfParams::testing()).unwrap();
        let h2 = read_header(dir.path()).unwrap();
        assert!(unlock_with_passphrase(&h2, "pw2").is_ok());
        assert!(unlock_with_passphrase(&h2, "pw1").is_err());
    }

    #[cfg(feature = "os-keychain")]
    #[test]
    fn keychain_delete_refused_after_a_successful_read_is_retried() {
        fn refuse_delete(entry: &keyring_core::Entry) {
            let cred = entry.as_any().downcast_ref::<keyring_core::mock::Cred>().unwrap();
            cred.set_error(keyring_core::Error::NoStorageAccess(Box::new(std::io::Error::other("store locked"))));
        }

        static INSTALL: std::sync::Once = std::sync::Once::new();
        INSTALL.call_once(|| keyring_core::set_default_store(keyring_core::mock::Store::new().unwrap()));
        let store = keyring_core::get_default_store().expect("a default store is installed");
        assert!(store.as_any().is::<keyring_core::mock::Store>(), "tests must only use the mock credential store");

        let dir = tempfile::tempdir().unwrap();
        let created = create_keychain_profile(dir.path(), "local").unwrap();
        let account = created.header.keychain_account.clone().unwrap();
        let mut h = read_header(dir.path()).unwrap();

        BEFORE_DELETE.set(Some(refuse_delete));
        let conv = convert_keychain_to_passphrase(dir.path(), &mut h, &created.dek, "pw", KdfParams::testing());
        BEFORE_DELETE.set(None);
        let conv = conv.unwrap();
        assert!(!conv.keychain_entry_removed);

        let mut h = read_header(dir.path()).unwrap();
        assert_eq!(h.protection, ProtectionMode::Passphrase);
        assert_eq!(h.keychain_account.as_deref(), Some(account.as_str()), "kept so removal can be retried");
        let entry = keychain_entry(&account).unwrap();
        assert!(entry.get_secret().is_ok(), "the delete was refused, so the entry is still there");
        assert!(matches!(unlock_with_keychain(&h), Err(VaultError::WrongProtection(_))));
        assert!(unlock_with_recovery(&h, &conv.recovery_key).is_ok());

        retire_keychain_entry(dir.path(), &mut h).unwrap();
        assert!(matches!(entry.get_secret(), Err(keyring_core::Error::NoEntry)));
        assert!(read_header(dir.path()).unwrap().keychain_account.is_none());
    }
}
