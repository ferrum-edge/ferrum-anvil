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
//! * An OS-keychain profile can be converted to passphrase mode. Its entry
//!   is tagged, then the new header is published; from then on only the
//!   passphrase or the new recovery key unlocks, and the keychain entry is
//!   removed (retried at each unlock until it is gone if the credential
//!   store refuses, and overwritten with a marker that opens nothing
//!   meanwhile).
//! * The header's protection mode is authenticated by a MAC under a key
//!   derived from the DEK and checked at every unlock, so editing
//!   `profile.json` cannot turn a converted profile back into a keychain one
//!   while its old entry is still in the credential store. Keychain entries
//!   written with a MAC'd header are tagged, so a header whose MAC was
//!   removed is refused too. Headers and entries written by earlier builds
//!   get both at their next unlock; until then they are trusted as found.
//! * A linked provider identity (Google/GitHub/Facebook) is never a key.

use crate::crypto::{self, CryptoError, KdfParams, Key};
use anvil_domain::workspace::ProtectionMode;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

pub const PROFILE_FILE: &str = "profile.json";
/// Advisory lock file serialising header writers across processes.
const LOCK_FILE: &str = "profile.lock";
/// Service name of the profiles' OS credential store entries.
pub const KEYCHAIN_SERVICE: &str = "com.ferrumedge.anvil";
const PASSPHRASE_LABEL: &[u8] = b"anvil-dek-passphrase-v1";
const RECOVERY_LABEL: &[u8] = b"anvil-dek-recovery-v1";
const PROTECTION_MAC_LABEL: &[u8] = b"anvil-profile-protection-v1";
/// Prefix of a keychain entry written for a header with a protection MAC.
/// An untagged entry holds the bare key (earlier builds) and still unlocks
/// a header without a MAC; a tagged one never does.
#[cfg(feature = "os-keychain")]
const KEYCHAIN_SECRET_TAG: &[u8] = b"anvil-dek-v2:";
/// Prefix of the marker that replaces a converted profile's entry when the
/// credential store refuses to delete it: followed by the profile's key
/// check, it holds no key and opens nothing.
#[cfg(feature = "os-keychain")]
const KEYCHAIN_RETIRED_TAG: &[u8] = b"anvil-dek-retired-v1:";
/// A leftover `profile.json.<pid>.<random>.tmp` older than this is from a
/// writer that stopped before renaming it, and is removed under the lock.
const STALE_TEMPORARY_AGE: std::time::Duration = std::time::Duration::from_secs(10 * 60);

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
    #[error("the profile header was changed outside Anvil and does not match its data key")]
    HeaderTampered,
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
    /// Hex HMAC-SHA256, under a key derived from the DEK, of the profile id,
    /// protection mode and key check. Absent only in headers written by
    /// earlier builds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protection_mac: Option<String>,
}

fn key_check(k: &Key) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"anvil-dek-check-v1");
    h.update(k.as_bytes());
    hex::encode(&h.finalize()[..16])
}

/// The protection MAC key: HKDF-SHA256 (RFC 5869) of the DEK with no salt
/// and [`PROTECTION_MAC_LABEL`] as info, so the DEK itself never keys an HMAC.
fn protection_mac_key(dek: &Key) -> Key {
    use hmac::{KeyInit, Mac};
    let mut extract = hmac::Hmac::<sha2::Sha256>::new_from_slice(&[0u8; 32]).expect("HMAC accepts any key length");
    extract.update(dek.as_bytes());
    let prk = Zeroizing::new(extract.finalize().into_bytes().to_vec());
    let mut expand = hmac::Hmac::<sha2::Sha256>::new_from_slice(&prk).expect("HMAC accepts any key length");
    expand.update(PROTECTION_MAC_LABEL);
    expand.update(&[1]);
    let okm = Zeroizing::new(expand.finalize().into_bytes().to_vec());
    Key::from_bytes(&okm).expect("a SHA-256 output is a key's length")
}

fn protection_mac_state(dek: &Key, h: &ProfileHeader) -> hmac::Hmac<sha2::Sha256> {
    use hmac::{KeyInit, Mac};
    let mode: &[u8] = match h.protection {
        ProtectionMode::Passphrase => b"passphrase",
        ProtectionMode::OsKeychain => b"os_keychain",
    };
    let key = protection_mac_key(dek);
    let mut m = hmac::Hmac::<sha2::Sha256>::new_from_slice(key.as_bytes()).expect("HMAC accepts any key length");
    for part in [PROTECTION_MAC_LABEL, h.profile_id.as_bytes(), mode, h.key_check.as_bytes()] {
        m.update(&(part.len() as u64).to_be_bytes());
        m.update(part);
    }
    m
}

/// The protection MAC of `h` under `dek`.
fn protection_mac(dek: &Key, h: &ProfileHeader) -> String {
    use hmac::Mac;
    hex::encode(&protection_mac_state(dek, h).finalize().into_bytes()[..])
}

/// A header's protection MAC, when it has one, must be `dek`'s MAC of it.
/// Headers written by earlier builds have none until [`upgrade_header`].
fn check_protection_mac(h: &ProfileHeader, dek: &Key) -> Result<(), VaultError> {
    use hmac::Mac;
    let Some(mac) = h.protection_mac.as_deref() else {
        return Ok(());
    };
    let tag = hex::decode(mac).map_err(|_| VaultError::HeaderTampered)?;
    protection_mac_state(dek, h).verify_slice(&tag).map_err(|_| VaultError::HeaderTampered)
}

/// A keychain header never carries a passphrase or recovery wrap. One
/// without a MAC that does was edited from a passphrase header, so it is
/// neither unlocked from the keychain nor sealed.
fn check_unsealed_keychain_header(h: &ProfileHeader) -> Result<(), VaultError> {
    let wrapped = h.passphrase_wrap.is_some() || h.recovery_wrap.is_some();
    if h.protection == ProtectionMode::OsKeychain && h.protection_mac.is_none() && wrapped {
        return Err(VaultError::HeaderTampered);
    }
    Ok(())
}

fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}

fn unb64(s: &str) -> Result<Vec<u8>, VaultError> {
    base64::engine::general_purpose::STANDARD.decode(s).map_err(|e| VaultError::Header(e.to_string()))
}

/// Refuse key-derivation settings outside the bounds bundles and backups
/// use ([`KdfParams::check_bounds`]). The header is plaintext on disk, so
/// they are checked before any derivation.
fn check_kdf(kdf: &KdfParams, salt: &[u8]) -> Result<(), VaultError> {
    kdf.check_bounds()
        .and_then(|()| crypto::check_salt(salt))
        .map_err(|why| VaultError::Header(format!("unsupported key-derivation settings ({why})")))
}

fn wrap_with_passphrase(dek: &Key, passphrase: &str, kdf: KdfParams, label: &[u8]) -> Result<WrappedKey, VaultError> {
    let salt = crypto::random_bytes(16);
    // A key wrapped with settings unlock would refuse could never be unwrapped.
    check_kdf(&kdf, &salt)?;
    let kek = crypto::derive(passphrase.as_bytes(), &salt, &kdf)?;
    Ok(WrappedKey { kdf: Some(kdf), salt: b64(&salt), envelope: b64(&crypto::seal(&kek, label, dek.as_bytes())) })
}

fn unwrap_with_passphrase(w: &WrappedKey, passphrase: &str, label: &[u8]) -> Result<Key, VaultError> {
    let kdf = w.kdf.ok_or_else(|| VaultError::Header("missing KDF parameters".into()))?;
    let salt = unb64(&w.salt)?;
    check_kdf(&kdf, &salt)?;
    let kek = crypto::derive(passphrase.as_bytes(), &salt, &kdf)?;
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

/// Atomically replace the header, under the profile's header lock.
pub fn write_header(dir: &Path, h: &ProfileHeader) -> Result<(), VaultError> {
    let _lock = lock_header(dir);
    replace_header(dir, h)
}

/// Take the advisory lock that serialises header writers across processes;
/// it is released when the returned file is dropped. Best effort: on a file
/// system without locks the header is still replaced atomically. Once held,
/// temporary files abandoned by earlier writers are removed.
fn lock_header(dir: &Path) -> Option<std::fs::File> {
    let lock = open_locked(dir).inspect_err(|e| tracing::warn!(dir = %dir.display(), error = %e, "profile header lock unavailable")).ok();
    if lock.is_some() {
        remove_stale_temporaries(dir);
    }
    lock
}

/// Remove `profile.json.<pid>.<random>.tmp` files older than
/// [`STALE_TEMPORARY_AGE`]: a writer holds the lock while its own exists,
/// so one this old was left by a writer that stopped before the rename.
fn remove_stale_temporaries(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let prefix = format!("{PROFILE_FILE}.");
    for e in entries.flatten() {
        let name = e.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !name.starts_with(&prefix) || !name.ends_with(".tmp") {
            continue;
        }
        let age = e.metadata().and_then(|m| m.modified()).ok().and_then(|t| t.elapsed().ok());
        let stale = age.is_some_and(|age| age >= STALE_TEMPORARY_AGE);
        if stale && let Err(err) = std::fs::remove_file(e.path()) {
            tracing::warn!(file = %e.path().display(), error = %err, "could not remove a stale profile header temporary file");
        }
    }
}

fn open_locked(dir: &Path) -> std::io::Result<std::fs::File> {
    std::fs::create_dir_all(dir)?;
    let f = std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(dir.join(LOCK_FILE))?;
    f.lock()?;
    Ok(f)
}

/// Edit the header on disk under the header lock, so no other writer lands
/// between the read and the write. `edit` returns whether it changed
/// anything; the result is the header as it now is on disk.
fn update_header(dir: &Path, edit: impl FnOnce(&mut ProfileHeader) -> Result<bool, VaultError>) -> Result<ProfileHeader, VaultError> {
    let _lock = lock_header(dir);
    let mut h = read_header(dir)?;
    if edit(&mut h)? {
        replace_header(dir, &h)?;
    }
    Ok(h)
}

/// Write a synced temporary file of this writer's own, rename it over the
/// header and sync the directory so the rename persists.
///
/// Once the rename has succeeded the new header is live, so the directory
/// sync is best effort: some file systems (FUSE, SMB) refuse it, and failing
/// there would report an error for a header that was in fact written.
fn replace_header(dir: &Path, h: &ProfileHeader) -> Result<(), VaultError> {
    let bytes = serde_json::to_vec_pretty(h).map_err(|e| VaultError::Header(e.to_string()))?;
    std::fs::create_dir_all(dir)?;
    let tmp = dir.join(format!("{PROFILE_FILE}.{}.{}.tmp", std::process::id(), hex::encode(crypto::random_bytes(8))));
    let written = write_new_synced(&tmp, &bytes).and_then(|()| std::fs::rename(&tmp, header_path(dir)));
    if let Err(e) = written {
        std::fs::remove_file(&tmp).ok();
        return Err(e.into());
    }
    if let Err(e) = sync_dir(dir) {
        tracing::warn!(dir = %dir.display(), error = %e, "profile directory sync failed after the header was replaced");
    }
    Ok(())
}

/// Create `path` (never an existing file), write `bytes` and sync them.
fn write_new_synced(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).open(path)?;
    f.write_all(bytes)?;
    f.sync_all()
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
    let mut header = ProfileHeader {
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
        protection_mac: None,
    };
    header.protection_mac = Some(protection_mac(&dek, &header));
    write_header(dir, &header)?;
    Ok(CreatedProfile { header, dek, recovery_key: Some(Zeroizing::new(recovery)) })
}

pub fn unlock_with_passphrase(h: &ProfileHeader, passphrase: &str) -> Result<Key, VaultError> {
    require_protection(h, ProtectionMode::Passphrase)?;
    let w = h.passphrase_wrap.as_ref().ok_or(VaultError::WrongSecret)?;
    let k = unwrap_with_passphrase(w, passphrase, PASSPHRASE_LABEL)?;
    require_profile_key(h, &k)?;
    check_protection_mac(h, &k)?;
    Ok(k)
}

pub fn unlock_with_recovery(h: &ProfileHeader, recovery: &str) -> Result<Key, VaultError> {
    require_protection(h, ProtectionMode::Passphrase)?;
    let w = h.recovery_wrap.as_ref().ok_or(VaultError::WrongSecret)?;
    let k = unwrap_with_passphrase(w, &normalize_recovery(recovery), RECOVERY_LABEL)?;
    require_profile_key(h, &k)?;
    check_protection_mac(h, &k)?;
    Ok(k)
}

/// Bring the header of a profile just unlocked with `dek` up to date: add
/// the protection MAC a header written by an earlier build lacks and, for a
/// keychain profile, tag its entry so a header without a MAC no longer
/// unlocks from it. The header on disk is edited, as in
/// [`retire_keychain_entry`], and adopted into `h` once its MAC verifies.
///
/// Such a header has no MAC to check, so it is trusted as found, except that
/// a keychain header carrying passphrase or recovery wraps is refused.
pub fn upgrade_header(dir: &Path, h: &mut ProfileHeader, dek: &Key) -> Result<(), VaultError> {
    require_profile_key(h, dek)?;
    if h.protection_mac.is_some() {
        return Ok(());
    }
    check_unsealed_keychain_header(h)?;
    let next = update_header(dir, |next| {
        let same = next.profile_id == h.profile_id && next.key_check == h.key_check && next.protection == h.protection;
        if !same || next.protection_mac.is_some() {
            return Ok(false);
        }
        check_unsealed_keychain_header(next)?;
        next.protection_mac = Some(protection_mac(dek, next));
        Ok(true)
    })?;
    if next.profile_id != h.profile_id || next.key_check != h.key_check || next.protection_mac.is_none() {
        return Ok(());
    }
    check_protection_mac(&next, dek)?;
    *h = next;
    // The MAC is on disk first: a tagged entry refuses a header without one.
    #[cfg(feature = "os-keychain")]
    if h.protection == ProtectionMode::OsKeychain {
        tag_keychain_entry(h, dek)?;
    }
    Ok(())
}

/// Replace the passphrase wrap of a passphrase profile (requires the
/// unlocked DEK). The recovery key stays valid. An OS-keychain profile is
/// refused; it changes mode with [`convert_keychain_to_passphrase`].
///
/// The header rewritten is the one on disk, read under the header lock; `h`
/// becomes it.
pub fn change_passphrase(dir: &Path, h: &mut ProfileHeader, dek: &Key, new_passphrase: &str, kdf: KdfParams) -> Result<(), VaultError> {
    require_protection(h, ProtectionMode::Passphrase)?;
    require_profile_key(h, dek)?;
    check_protection_mac(h, dek)?;
    let wrap = wrap_with_passphrase(dek, new_passphrase, kdf, PASSPHRASE_LABEL)?;
    *h = rewrite_header(dir, h, dek, ProtectionMode::Passphrase, |next| {
        next.passphrase_wrap = Some(wrap);
        Ok(())
    })?;
    Ok(())
}

/// Rewrite the header of `h`'s profile under the header lock. The header on
/// disk is read there and must still be that profile's, in `mode`, and hold
/// for `dek` (key check and MAC) before `edit` changes it and it is sealed
/// again, so a mode flipped on disk cannot drive the rewrite.
fn rewrite_header(
    dir: &Path,
    h: &ProfileHeader,
    dek: &Key,
    mode: ProtectionMode,
    edit: impl FnOnce(&mut ProfileHeader) -> Result<(), VaultError>,
) -> Result<ProfileHeader, VaultError> {
    let _lock = lock_header(dir);
    let mut next = read_header(dir)?;
    if next.profile_id != h.profile_id {
        return Err(VaultError::Header("the profile header on disk belongs to another profile".into()));
    }
    require_protection(&next, mode)?;
    require_profile_key(&next, dek)?;
    check_unsealed_keychain_header(&next)?;
    check_protection_mac(&next, dek)?;
    edit(&mut next)?;
    next.protection_mac = Some(protection_mac(dek, &next));
    replace_header(dir, &next)?;
    Ok(next)
}

/// Result of [`convert_keychain_to_passphrase`].
#[cfg(feature = "os-keychain")]
pub struct KeychainConversion {
    /// The new recovery key. Shown to the user once; never stored.
    pub recovery_key: Zeroizing<String>,
    /// False when the OS credential store did not remove the old entry. The
    /// profile no longer unlocks from the keychain either way, and removal is
    /// retried by [`retire_keychain_entry`]. True once the entry is gone, even
    /// if forgetting its account name in the header failed (also retried).
    pub keychain_entry_removed: bool,
}

/// Convert an OS-keychain profile to passphrase protection (requires the
/// unlocked DEK). The data key is unchanged, so nothing is re-encrypted.
///
/// A header written by an earlier build is sealed first ([`upgrade_header`]).
/// Then, under the header lock, the keychain entry is tagged — if the store
/// refuses, the conversion stops with nothing changed — and the passphrase
/// header, with a new recovery wrap and its protection MAC, is durably
/// written before the entry is removed. From that point the keychain path
/// is refused: the header's authenticated mode is `Passphrase`, and a copy
/// edited back to keychain mode without its MAC meets a tagged entry. The
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
    check_unsealed_keychain_header(h)?;
    check_protection_mac(h, dek)?;
    upgrade_header(dir, h, dek)?;
    let recovery = Zeroizing::new(format_recovery_key(&crypto::random_bytes(20)));
    let passphrase_wrap = wrap_with_passphrase(dek, new_passphrase, kdf, PASSPHRASE_LABEL)?;
    let recovery_wrap = wrap_with_passphrase(dek, &normalize_recovery(&recovery), kdf, RECOVERY_LABEL)?;
    *h = rewrite_header(dir, h, dek, ProtectionMode::OsKeychain, |next| {
        // Tagging an entry refuses it to headers without a MAC, so the
        // header on disk must already have one.
        if next.protection_mac.is_none() {
            return Err(VaultError::Header("the profile header was replaced during the conversion".into()));
        }
        if next.keychain_account.is_some() {
            tag_keychain_entry(next, dek)?;
        }
        next.protection = ProtectionMode::Passphrase;
        next.passphrase_wrap = Some(passphrase_wrap);
        next.recovery_wrap = Some(recovery_wrap);
        Ok(())
    })?;
    let Some(account) = h.keychain_account.clone() else {
        return Ok(KeychainConversion { recovery_key: recovery, keychain_entry_removed: true });
    };
    let keychain_entry_removed = delete_retired_entry(h, &account).is_ok();
    if keychain_entry_removed && let Err(e) = forget_keychain_account(dir, h, &account) {
        tracing::warn!(dir = %dir.display(), error = %e, "the old keychain entry was removed but the header still names it");
    }
    Ok(KeychainConversion { recovery_key: recovery, keychain_entry_removed })
}

/// Remove the keychain entry a converted (now passphrase) profile left
/// behind, then forget its account name. A no-op when none is recorded.
/// An entry holding a different key is not this profile's: it is forgotten,
/// never deleted. Keychain profiles are refused (their entry is their key).
#[cfg(feature = "os-keychain")]
pub fn retire_keychain_entry(dir: &Path, h: &mut ProfileHeader) -> Result<(), VaultError> {
    require_protection(h, ProtectionMode::Passphrase)?;
    let Some(account) = h.keychain_account.clone() else {
        return Ok(());
    };
    delete_retired_entry(h, &account)?;
    forget_keychain_account(dir, h, &account)
}

/// Delete `account`'s entry if it holds this profile's key, or the marker
/// that replaced it. Succeeds when the entry is gone or is not this
/// profile's.
///
/// If the store refuses to delete an entry holding the key, the entry is
/// overwritten with the marker (see [`KEYCHAIN_RETIRED_TAG`]) so that a copy
/// of the header saved before the conversion cannot unlock from it; the
/// removal is still reported as failed and retried.
#[cfg(feature = "os-keychain")]
fn delete_retired_entry(h: &ProfileHeader, account: &str) -> Result<(), VaultError> {
    let entry = keychain_entry(account)?;
    let unavailable = |e: keyring_core::Error| VaultError::KeychainUnavailable(e.to_string());
    let secret = match entry.get_secret() {
        Ok(secret) => Zeroizing::new(secret),
        Err(keyring_core::Error::NoEntry) => return Ok(()),
        Err(e) => return Err(unavailable(e)),
    };
    let retired = retired_secret(&h.key_check);
    let holds_key = parse_keychain_secret(&secret).is_ok_and(|(k, _)| key_check(&k) == h.key_check);
    if !holds_key && secret.as_slice() != retired.as_slice() {
        return Ok(());
    }
    #[cfg(test)]
    if let Some(hook) = BEFORE_DELETE.get() {
        hook(&entry);
    }
    let refused = match entry.delete_credential() {
        Ok(()) | Err(keyring_core::Error::NoEntry) => return Ok(()),
        Err(e) => e,
    };
    if holds_key {
        #[cfg(test)]
        if let Some(hook) = BEFORE_OVERWRITE.get() {
            hook(&entry);
        }
        if let Err(e) = entry.set_secret(&retired) {
            tracing::warn!(error = %e, "could not overwrite the old keychain entry either; its removal is retried at each unlock");
        }
    }
    Err(unavailable(refused))
}

/// The marker left in place of a converted profile's keychain entry that
/// the store refused to delete. It holds no key.
#[cfg(feature = "os-keychain")]
fn retired_secret(key_check: &str) -> Vec<u8> {
    [KEYCHAIN_RETIRED_TAG, key_check.as_bytes()].concat()
}

/// Drop `account` from the header once its entry is gone.
///
/// `h` may have been read long before (an unlock runs the KDF first), so
/// the header on disk is edited under the lock rather than `h` written
/// back: a passphrase changed meanwhile by another process must not be
/// undone. If the header no longer names this account in passphrase mode it
/// is left alone. Either way `h` becomes the header on disk when that is
/// still this profile's passphrase header.
#[cfg(feature = "os-keychain")]
fn forget_keychain_account(dir: &Path, h: &mut ProfileHeader, account: &str) -> Result<(), VaultError> {
    let same_profile =
        |x: &ProfileHeader| x.protection == ProtectionMode::Passphrase && x.profile_id == h.profile_id && x.key_check == h.key_check;
    let next = update_header(dir, |next| {
        if !same_profile(next) || next.keychain_account.as_deref() != Some(account) {
            return Ok(false);
        }
        next.keychain_account = None;
        Ok(true)
    })?;
    if same_profile(&next) {
        *h = next;
    }
    Ok(())
}

/// The keychain secret stored for `dek`: tagged, see [`KEYCHAIN_SECRET_TAG`].
#[cfg(feature = "os-keychain")]
fn keychain_secret(dek: &Key) -> Zeroizing<Vec<u8>> {
    let mut secret = Zeroizing::new(Vec::with_capacity(KEYCHAIN_SECRET_TAG.len() + crypto::KEY_LEN));
    secret.extend_from_slice(KEYCHAIN_SECRET_TAG);
    secret.extend_from_slice(dek.as_bytes());
    secret
}

/// The key in a keychain secret, and whether the secret is tagged.
#[cfg(feature = "os-keychain")]
fn parse_keychain_secret(secret: &[u8]) -> Result<(Key, bool), VaultError> {
    match secret.strip_prefix(KEYCHAIN_SECRET_TAG) {
        Some(key) => Ok((Key::from_bytes(key)?, true)),
        None => Ok((Key::from_bytes(secret)?, false)),
    }
}

/// Tag the untagged entry of a keychain profile whose header has a MAC. An
/// entry that is missing, holds no key or holds another key cannot open
/// this profile, and is left alone.
#[cfg(feature = "os-keychain")]
fn tag_keychain_entry(h: &ProfileHeader, dek: &Key) -> Result<(), VaultError> {
    let account = h.keychain_account.as_deref().ok_or_else(|| VaultError::Header("no keychain account recorded".into()))?;
    let entry = keychain_entry(account)?;
    let unavailable = |e: keyring_core::Error| VaultError::KeychainUnavailable(e.to_string());
    let secret = match entry.get_secret() {
        Ok(secret) => Zeroizing::new(secret),
        Err(keyring_core::Error::NoEntry) => return Ok(()),
        Err(e) => return Err(unavailable(e)),
    };
    match parse_keychain_secret(&secret) {
        Ok((k, false)) if key_check(&k) == h.key_check => entry.set_secret(&keychain_secret(dek)).map_err(unavailable),
        _ => Ok(()),
    }
}

#[cfg(all(test, feature = "os-keychain"))]
thread_local! {
    /// Runs just before a retired entry is deleted, so a test can make the
    /// mock store refuse the delete after the read succeeded.
    static BEFORE_DELETE: std::cell::Cell<Option<fn(&keyring_core::Entry)>> = const { std::cell::Cell::new(None) };
    /// Runs just before a retired entry the store refused to delete is
    /// overwritten with the marker, so a test can make that fail too.
    static BEFORE_OVERWRITE: std::cell::Cell<Option<fn(&keyring_core::Entry)>> = const { std::cell::Cell::new(None) };
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
    entry.set_secret(&keychain_secret(&dek)).map_err(|e| VaultError::KeychainUnavailable(e.to_string()))?;
    let mut header = ProfileHeader {
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
        protection_mac: None,
    };
    header.protection_mac = Some(protection_mac(&dek, &header));
    write_header(dir, &header)?;
    Ok(CreatedProfile { header, dek, recovery_key: None })
}

/// Unlock a keychain profile. An entry written by an earlier build is
/// tagged here once its header has a protection MAC (best effort; retried
/// at each unlock).
#[cfg(feature = "os-keychain")]
pub fn unlock_with_keychain(h: &ProfileHeader) -> Result<Key, VaultError> {
    // Checked before the store is touched: a converted profile may still
    // name its old account until that entry is removed.
    require_protection(h, ProtectionMode::OsKeychain)?;
    check_unsealed_keychain_header(h)?;
    let account = h.keychain_account.as_deref().ok_or_else(|| VaultError::Header("no keychain account recorded".into()))?;
    let entry = keychain_entry(account)?;
    let secret = Zeroizing::new(entry.get_secret().map_err(|e| VaultError::KeychainUnavailable(e.to_string()))?);
    // The marker a conversion left in place of the key: this header is a
    // copy saved before the profile was converted.
    if secret.starts_with(KEYCHAIN_RETIRED_TAG) {
        return Err(VaultError::WrongProtection("the OS keychain"));
    }
    let (k, tagged) = parse_keychain_secret(&secret)?;
    require_profile_key(h, &k)?;
    // A tagged entry was written with a MAC'd header: one without a MAC was
    // edited, e.g. to reopen a converted profile from its leftover entry.
    if tagged && h.protection_mac.is_none() {
        return Err(VaultError::HeaderTampered);
    }
    check_protection_mac(h, &k)?;
    if !tagged
        && h.protection_mac.is_some()
        && let Err(e) = entry.set_secret(&keychain_secret(&k))
    {
        tracing::warn!(error = %e, "could not tag the keychain entry; retried at the next unlock");
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

    /// Install keyring-core's in-memory mock as the credential store, once
    /// for every test in this binary.
    #[cfg(feature = "os-keychain")]
    fn mock_store() {
        static INSTALL: std::sync::Once = std::sync::Once::new();
        INSTALL.call_once(|| keyring_core::set_default_store(keyring_core::mock::Store::new().unwrap()));
        let store = keyring_core::get_default_store().expect("a default store is installed");
        assert!(store.as_any().is::<keyring_core::mock::Store>(), "tests must only use the mock credential store");
    }

    /// Make the mock store refuse the next operation on this entry.
    #[cfg(feature = "os-keychain")]
    fn refuse(entry: &keyring_core::Entry) {
        let cred = entry.as_any().downcast_ref::<keyring_core::mock::Cred>().unwrap();
        cred.set_error(keyring_core::Error::NoStorageAccess(Box::new(std::io::Error::other("store locked"))));
    }

    #[cfg(feature = "os-keychain")]
    #[test]
    fn keychain_delete_refused_after_a_successful_read_is_retried() {
        mock_store();

        let dir = tempfile::tempdir().unwrap();
        let created = create_keychain_profile(dir.path(), "local").unwrap();
        let account = created.header.keychain_account.clone().unwrap();
        let mut h = read_header(dir.path()).unwrap();

        BEFORE_DELETE.set(Some(refuse));
        let conv = convert_keychain_to_passphrase(dir.path(), &mut h, &created.dek, "pw", KdfParams::testing());
        BEFORE_DELETE.set(None);
        let conv = conv.unwrap();
        assert!(!conv.keychain_entry_removed);

        let mut h = read_header(dir.path()).unwrap();
        assert_eq!(h.protection, ProtectionMode::Passphrase);
        assert_eq!(h.keychain_account.as_deref(), Some(account.as_str()), "kept so removal can be retried");
        let entry = keychain_entry(&account).unwrap();
        let left = entry.get_secret().expect("the delete was refused, so the entry is still there");
        assert_eq!(left, retired_secret(&h.key_check), "the key was overwritten with the marker");
        assert!(matches!(unlock_with_keychain(&h), Err(VaultError::WrongProtection(_))));
        // A copy of the header saved before the conversion no longer opens.
        assert!(matches!(unlock_with_keychain(&created.header), Err(VaultError::WrongProtection(_))));
        assert!(unlock_with_recovery(&h, &conv.recovery_key).is_ok());

        // The marker is this profile's, so retiring removes it.
        retire_keychain_entry(dir.path(), &mut h).unwrap();
        assert!(matches!(entry.get_secret(), Err(keyring_core::Error::NoEntry)));
        assert!(read_header(dir.path()).unwrap().keychain_account.is_none());
    }

    #[cfg(feature = "os-keychain")]
    #[test]
    fn an_untagged_entry_left_behind_does_not_reopen_a_flipped_header_without_its_mac() {
        mock_store();

        let dir = tempfile::tempdir().unwrap();
        let created = create_keychain_profile(dir.path(), "local").unwrap();
        let account = created.header.keychain_account.clone().unwrap();
        let entry = keychain_entry(&account).unwrap();
        // The header has its MAC, but tagging the entry failed: it still
        // holds the bare key, as an earlier build wrote it.
        entry.set_secret(created.dek.as_bytes()).unwrap();
        let mut h = read_header(dir.path()).unwrap();

        // The store refuses both the delete and the overwrite with the marker.
        BEFORE_DELETE.set(Some(refuse));
        BEFORE_OVERWRITE.set(Some(refuse));
        let conv = convert_keychain_to_passphrase(dir.path(), &mut h, &created.dek, "pw", KdfParams::testing());
        BEFORE_DELETE.set(None);
        BEFORE_OVERWRITE.set(None);
        assert!(!conv.unwrap().keychain_entry_removed);
        assert_eq!(entry.get_secret().unwrap(), *keychain_secret(&created.dek), "tagged before the header was written");

        // Edited back to keychain mode and stripped of its MAC, the header
        // meets a tagged entry.
        let mut flipped = read_header(dir.path()).unwrap();
        flipped.protection = ProtectionMode::OsKeychain;
        flipped.protection_mac = None;
        assert!(matches!(unlock_with_keychain(&flipped), Err(VaultError::HeaderTampered)));
        flipped.passphrase_wrap = None;
        flipped.recovery_wrap = None;
        assert!(matches!(unlock_with_keychain(&flipped), Err(VaultError::HeaderTampered)));
    }

    #[cfg(feature = "os-keychain")]
    #[test]
    fn a_conversion_stops_unchanged_when_the_entry_cannot_be_tagged() {
        mock_store();

        let dir = tempfile::tempdir().unwrap();
        let created = create_keychain_profile(dir.path(), "local").unwrap();
        let account = created.header.keychain_account.clone().unwrap();
        let entry = keychain_entry(&account).unwrap();
        entry.set_secret(created.dek.as_bytes()).unwrap();
        let before = std::fs::read(header_path(dir.path())).unwrap();
        let mut h = read_header(dir.path()).unwrap();

        // The store refuses the read that tagging starts with.
        refuse(&entry);
        let r = convert_keychain_to_passphrase(dir.path(), &mut h, &created.dek, "pw", KdfParams::testing());
        assert!(matches!(r, Err(VaultError::KeychainUnavailable(_))));
        assert_eq!(std::fs::read(header_path(dir.path())).unwrap(), before, "nothing was written");
        assert_eq!(unlock_with_keychain(&read_header(dir.path()).unwrap()).unwrap().as_bytes(), created.dek.as_bytes());
    }

    #[cfg(feature = "os-keychain")]
    thread_local! {
        static PROFILE_DIR: std::cell::RefCell<Option<PathBuf>> = const { std::cell::RefCell::new(None) };
    }

    #[cfg(feature = "os-keychain")]
    #[test]
    fn a_removed_entry_is_reported_even_if_the_header_update_fails() {
        fn break_header(_: &keyring_core::Entry) {
            let dir = PROFILE_DIR.with_borrow(|d| d.clone()).unwrap();
            std::fs::write(header_path(&dir), b"{").unwrap();
        }

        mock_store();

        let dir = tempfile::tempdir().unwrap();
        let created = create_keychain_profile(dir.path(), "local").unwrap();
        let account = created.header.keychain_account.clone().unwrap();
        let mut h = read_header(dir.path()).unwrap();

        // The delete succeeds, then the header cannot be read back.
        PROFILE_DIR.set(Some(dir.path().to_path_buf()));
        BEFORE_DELETE.set(Some(break_header));
        let conv = convert_keychain_to_passphrase(dir.path(), &mut h, &created.dek, "pw", KdfParams::testing());
        BEFORE_DELETE.set(None);
        PROFILE_DIR.set(None);
        assert!(conv.unwrap().keychain_entry_removed, "the entry is gone");
        assert!(matches!(keychain_entry(&account).unwrap().get_secret(), Err(keyring_core::Error::NoEntry)));
        assert_eq!(h.protection, ProtectionMode::Passphrase);
    }
}
