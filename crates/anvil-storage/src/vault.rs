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
//! * A linked provider identity (Google/GitHub/Facebook) is never a key.

use crate::crypto::{self, CryptoError, KdfParams, Key};
use anvil_domain::workspace::ProtectionMode;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

pub const PROFILE_FILE: &str = "profile.json";
const KEYCHAIN_SERVICE: &str = "com.ferrumedge.anvil";

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("the passphrase or recovery key is not correct")]
    WrongSecret,
    #[error("the OS credential store is unavailable ({0}); use a passphrase-protected profile instead")]
    KeychainUnavailable(String),
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

pub fn write_header(dir: &Path, h: &ProfileHeader) -> Result<(), VaultError> {
    std::fs::create_dir_all(dir)?;
    let tmp = dir.join(format!("{PROFILE_FILE}.tmp"));
    std::fs::write(&tmp, serde_json::to_vec_pretty(h).map_err(|e| VaultError::Header(e.to_string()))?)?;
    std::fs::rename(tmp, header_path(dir))?;
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
        passphrase_wrap: Some(wrap_with_passphrase(&dek, passphrase, kdf, b"anvil-dek-passphrase-v1")?),
        recovery_wrap: Some(wrap_with_passphrase(&dek, &normalize_recovery(&recovery), kdf, b"anvil-dek-recovery-v1")?),
        keychain_account: None,
        key_check: key_check(&dek),
        created_at: chrono::Utc::now(),
    };
    write_header(dir, &header)?;
    Ok(CreatedProfile { header, dek, recovery_key: Some(Zeroizing::new(recovery)) })
}

pub fn unlock_with_passphrase(h: &ProfileHeader, passphrase: &str) -> Result<Key, VaultError> {
    let w = h.passphrase_wrap.as_ref().ok_or(VaultError::WrongSecret)?;
    let k = unwrap_with_passphrase(w, passphrase, b"anvil-dek-passphrase-v1")?;
    if key_check(&k) != h.key_check {
        return Err(VaultError::WrongSecret);
    }
    Ok(k)
}

pub fn unlock_with_recovery(h: &ProfileHeader, recovery: &str) -> Result<Key, VaultError> {
    let w = h.recovery_wrap.as_ref().ok_or(VaultError::WrongSecret)?;
    let k = unwrap_with_passphrase(w, &normalize_recovery(recovery), b"anvil-dek-recovery-v1")?;
    if key_check(&k) != h.key_check {
        return Err(VaultError::WrongSecret);
    }
    Ok(k)
}

/// Replace the passphrase wrap (requires the unlocked DEK).
pub fn change_passphrase(dir: &Path, h: &mut ProfileHeader, dek: &Key, new_passphrase: &str, kdf: KdfParams) -> Result<(), VaultError> {
    h.passphrase_wrap = Some(wrap_with_passphrase(dek, new_passphrase, kdf, b"anvil-dek-passphrase-v1")?);
    h.protection = ProtectionMode::Passphrase;
    write_header(dir, h)
}

/// The OS credential store entry holding a keychain profile's data key: the
/// macOS Keychain, the Windows Credential Manager, or the freedesktop Secret
/// Service (GNOME Keyring, KWallet) on Linux and the BSDs. There is no
/// in-memory fallback: a missing store is `KeychainUnavailable`.
#[cfg(feature = "os-keychain")]
fn keychain_entry(account: &str) -> Result<keyring_core::Entry, VaultError> {
    let unavailable = |e: &dyn std::fmt::Display| VaultError::KeychainUnavailable(e.to_string());
    keyring::Entry::store_status().as_ref().map_err(|e| unavailable(e))?;
    // Windows defaults to "Enterprise" persistence, which roams with domain
    // user profiles. The key only unlocks files on this machine, so keep it here.
    #[cfg(windows)]
    let entry =
        keyring_core::Entry::new_with_modifiers(KEYCHAIN_SERVICE, account, &std::collections::HashMap::from([("persistence", "local")]));
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
}
