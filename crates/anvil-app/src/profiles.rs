//! Local profiles (selectors, not OS security boundaries) and unlocking.
//!
//! A linked provider identity (see [`crate::identity`]) is an additional
//! unlock *policy*, never a key: every unlock still unwraps the data key
//! with the passphrase, the recovery key or the OS keychain.

use crate::identity::{self, IdentityPolicyError, UnlockRequirements};
use crate::{AppError, Result};
use anvil_domain::workspace::{LinkedIdentity, ProtectionMode};
use anvil_identity::VerifiedIdentity;
use anvil_storage::vault::{self, KeychainConversion, ProfileHeader};
use anvil_storage::{KdfParams, Key};
use serde::Serialize;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

#[derive(Debug, Clone, Serialize)]
pub struct ProfileSummary {
    pub profile_id: String,
    pub display_name: String,
    pub protection: anvil_domain::workspace::ProtectionMode,
    pub dir: PathBuf,
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// The OS credential store entry a profile converted to a passphrase
    /// left behind because the store refused to delete it. It no longer
    /// unlocks the profile; its removal is retried at each unlock until it is
    /// gone, and it can be removed by hand.
    pub leftover_keychain_entry: Option<KeychainEntryName>,
}

/// Where an OS credential store entry is: its service and account names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct KeychainEntryName {
    pub service: String,
    pub account: String,
}

fn leftover_keychain_entry(h: &ProfileHeader) -> Option<KeychainEntryName> {
    let account = h.keychain_account.as_ref().filter(|_| h.protection == ProtectionMode::Passphrase)?;
    Some(KeychainEntryName { service: vault::KEYCHAIN_SERVICE.into(), account: account.clone() })
}

pub struct ProfileManager {
    pub root: PathBuf,
}

#[derive(Clone, Copy)]
pub enum Unlock<'a> {
    Passphrase(&'a str),
    RecoveryKey(&'a str),
    Keychain,
}

/// A single-use authorization, never a released installation lease. The
/// checked header, key and provider proof remain private until the final fence.
pub struct UnlockAuthorization {
    dir: PathBuf,
    header: ProfileHeader,
    key: Key,
    recovery: bool,
    proof: Option<VerifiedIdentity>,
}

impl UnlockAuthorization {
    /// Recheck the authenticated snapshot and current binding under the
    /// profile lock, then keep the lock and binding descriptor through the
    /// synchronous installation callback. Do not await or nest header writers
    /// in this callback. This serializes cooperating Anvil writers, not an
    /// external user replacing directories, lock files or mounted filesystems.
    pub fn install<T>(self, install: impl FnOnce(PathBuf, ProfileHeader, Key) -> Result<T>) -> Result<T> {
        let guard = vault::lock_identity_header(&self.dir)?;
        let current = guard.read()?;
        vault::authenticate_header(&current, &self.key)?;
        if serde_json::to_vec(&current)? != serde_json::to_vec(&self.header)? {
            return Err(vault::VaultError::HeaderTampered.into());
        }
        let binding = if self.recovery { None } else { identity::read_binding(&self.dir, &current)? };
        if !self.recovery {
            ProfileManager::check_binding(&current, &self.key, binding.as_ref(), self.proof.as_ref(), chrono::Utc::now())?;
        }
        let result = install(self.dir.clone(), current, self.key);
        drop(binding);
        drop(guard);
        result
    }

    /// Open a new application while the final verification fence is held.
    pub fn open(self) -> Result<crate::App> {
        self.install(crate::App::open)
    }
}

impl ProfileManager {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        ProfileManager { root: root.into() }
    }

    fn profiles_dir(&self) -> PathBuf {
        self.root.join("profiles")
    }

    pub fn list(&self) -> Vec<ProfileSummary> {
        let mut out = Vec::new();
        if let Ok(rd) = std::fs::read_dir(self.profiles_dir()) {
            for e in rd.flatten() {
                if let Ok(h) = vault::read_header(&e.path()) {
                    out.push(ProfileSummary {
                        leftover_keychain_entry: leftover_keychain_entry(&h),
                        profile_id: h.profile_id,
                        display_name: h.display_name,
                        protection: h.protection,
                        dir: e.path(),
                        created_at: h.created_at,
                    });
                }
            }
        }
        out.sort_by_key(|a| a.created_at);
        out
    }

    pub fn find(&self, id_or_name: &str) -> Result<ProfileSummary> {
        self.list()
            .into_iter()
            .find(|p| p.profile_id == id_or_name || p.display_name.eq_ignore_ascii_case(id_or_name))
            .ok_or_else(|| AppError::NotFound(format!("profile '{id_or_name}'")))
    }

    /// Create a passphrase-protected profile. Returns (summary, dek, recovery key shown once).
    pub fn create_passphrase(
        &self,
        display_name: &str,
        passphrase: &str,
        kdf: KdfParams,
    ) -> Result<(ProfileSummary, Key, Zeroizing<String>)> {
        self.create_passphrase_for_format(display_name, passphrase, kdf, false)
    }

    /// Opt-in draft format for owner evaluation; the normal creation path is unchanged.
    pub fn create_passphrase_with_identity_expectation(
        &self,
        display_name: &str,
        passphrase: &str,
        kdf: KdfParams,
    ) -> Result<(ProfileSummary, Key, Zeroizing<String>)> {
        self.create_passphrase_for_format(display_name, passphrase, kdf, true)
    }

    fn create_passphrase_for_format(
        &self,
        display_name: &str,
        passphrase: &str,
        kdf: KdfParams,
        identity: bool,
    ) -> Result<(ProfileSummary, Key, Zeroizing<String>)> {
        if passphrase.chars().count() < 8 {
            return Err(AppError::Invalid("the unlock passphrase must have at least 8 characters".into()));
        }
        let dir = self.profiles_dir().join(uuid::Uuid::now_v7().to_string());
        let c = if identity {
            vault::create_passphrase_profile_with_identity_expectation(&dir, display_name, passphrase, kdf)?
        } else {
            vault::create_passphrase_profile(&dir, display_name, passphrase, kdf)?
        };
        let s = ProfileSummary {
            profile_id: c.header.profile_id.clone(),
            display_name: c.header.display_name.clone(),
            protection: c.header.protection,
            dir,
            created_at: c.header.created_at,
            leftover_keychain_entry: None,
        };
        Ok((s, c.dek, c.recovery_key.unwrap_or_default()))
    }

    pub fn create_keychain(&self, display_name: &str) -> Result<(ProfileSummary, Key)> {
        let dir = self.profiles_dir().join(uuid::Uuid::now_v7().to_string());
        let c = vault::create_keychain_profile(&dir, display_name)?;
        let s = ProfileSummary {
            profile_id: c.header.profile_id.clone(),
            display_name: c.header.display_name.clone(),
            protection: c.header.protection,
            dir,
            created_at: c.header.created_at,
            leftover_keychain_entry: None,
        };
        Ok((s, c.dek))
    }

    /// Unlock with the passphrase, recovery key or OS keychain.
    ///
    /// When a linked provider identity requires a fresh sign-in, the
    /// passphrase and keychain paths are refused here — in the backend — with
    /// [`IdentityPolicyError::FreshLoginRequired`]; use
    /// [`ProfileManager::unlock_with_fresh_login`]. The recovery key always
    /// works without a provider (offline/recovery path).
    pub fn unlock(dir: &Path, how: Unlock<'_>) -> Result<(ProfileHeader, Key)> {
        Self::unlock_checked(dir, how, None, chrono::Utc::now())
    }

    /// Draft source-compatible addition for installation consumers. Unlike
    /// the historical tuple APIs, this carries authorization to the final
    /// fence. No profile lock or binding descriptor survives between calls.
    pub fn authorize_unlock(dir: &Path, how: Unlock<'_>, proof: Option<VerifiedIdentity>) -> Result<UnlockAuthorization> {
        let recovery = matches!(how, Unlock::RecoveryKey(_));
        let (header, key) = Self::unlock_checked(dir, how, proof.as_ref(), chrono::Utc::now())?;
        Ok(UnlockAuthorization { dir: dir.to_path_buf(), header, key, recovery, proof })
    }

    /// Unlock with the local secret *and* a provider sign-in that just
    /// happened. The proof never unlocks anything by itself: `how` must
    /// still unwrap the data key.
    pub fn unlock_with_fresh_login(dir: &Path, how: Unlock<'_>, proof: VerifiedIdentity) -> Result<(ProfileHeader, Key)> {
        Self::unlock_with_fresh_login_at(dir, how, proof, chrono::Utc::now())
    }

    /// [`ProfileManager::unlock_with_fresh_login`] with an explicit clock (tests).
    pub fn unlock_with_fresh_login_at(
        dir: &Path,
        how: Unlock<'_>,
        proof: VerifiedIdentity,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<(ProfileHeader, Key)> {
        Self::unlock_checked(dir, how, Some(&proof), now)
    }

    fn unlock_checked(
        dir: &Path,
        how: Unlock<'_>,
        proof: Option<&VerifiedIdentity>,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<(ProfileHeader, Key)> {
        let guard = vault::lock_identity_header(dir)?;
        let h = guard.read()?;
        let (h, k) = Self::unlock_header_checked(dir, &h, how, proof, now)?;
        drop(guard);
        if h.protection_mac.is_none() || (h.protection == ProtectionMode::Passphrase && h.keychain_account.is_some()) {
            Self::maintain_unlocked(dir, &h, &k);
            // Maintenance's returned header never substitutes for authority.
            // Re-enter the credential and recheck the current binding/policy
            // under the profile lock before adopting any updated header.
            let guard = vault::lock_identity_header(dir)?;
            let current = guard.read()?;
            return Self::unlock_header_checked(dir, &current, how, proof, now);
        }
        Ok((h, k))
    }

    fn maintain_unlocked(dir: &Path, h: &ProfileHeader, key: &Key) {
        let mut maintenance = h.clone();
        // A header written by an earlier build gets its protection MAC (and
        // a keychain profile's entry its tag) now that the key is proven.
        if h.identity_binding.is_none() {
            vault::upgrade_header(dir, &mut maintenance, key).ok();
        }
        // A keychain entry left over from converting this profile to a
        // passphrase. It no longer unlocks anything; removing it is retried
        // at each unlock until it is gone.
        if h.protection == ProtectionMode::Passphrase && h.keychain_account.is_some() {
            // Do not replace the checked snapshot with a concurrently changed
            // identity expectation returned by maintenance after releasing the lock.
            vault::retire_keychain_entry(dir, &mut maintenance).ok();
            // Maintenance is never authority for this already checked tuple.
        }
    }

    fn unwrap_header(h: &ProfileHeader, how: Unlock<'_>) -> Result<Key> {
        Ok(match how {
            Unlock::Passphrase(p) => vault::unlock_with_passphrase(h, p)?,
            Unlock::RecoveryKey(r) => vault::unlock_with_recovery(h, r)?,
            Unlock::Keychain => vault::unlock_with_keychain(h)?,
        })
    }

    fn unlock_header_checked(
        dir: &Path,
        h: &ProfileHeader,
        how: Unlock<'_>,
        proof: Option<&VerifiedIdentity>,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<(ProfileHeader, Key)> {
        let recovery = matches!(how, Unlock::RecoveryKey(_));
        // Authenticate the recovery credential/header without even opening
        // the binding. A FIFO, device or oversized file cannot impede recovery.
        if recovery {
            return Ok((h.clone(), Self::unwrap_header(h, how)?));
        }
        let binding = identity::read_binding(dir, h)?;
        // Early refusals use only the hint. Authentication below is mandatory
        // before ordinary unlock returns a key to an installer.
        if !recovery {
            match (&binding, proof) {
                (Some(b), Some(p)) => identity::check_proof(b.provider(), b.subject(), p, now)?,
                (Some(b), None) if b.require_fresh_login() => {
                    return Err(IdentityPolicyError::FreshLoginRequired { provider: b.provider().to_string() }.into());
                }
                (None, Some(_)) => return Err(IdentityPolicyError::NotLinked.into()),
                _ => {}
            }
        }
        let k = Self::unwrap_header(h, how)?;
        Self::check_binding(h, &k, binding.as_ref(), proof, now)?;
        Ok((h.clone(), k))
    }

    fn check_binding(
        h: &ProfileHeader,
        key: &Key,
        binding: Option<&identity::ReadBinding>,
        proof: Option<&VerifiedIdentity>,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<()> {
        match (binding, proof) {
            (Some(b), Some(p)) => identity::check_proof(b.provider(), b.subject(), p, now)?,
            (Some(b), None) if b.require_fresh_login() => {
                return Err(IdentityPolicyError::FreshLoginRequired { provider: b.provider().to_string() }.into());
            }
            (None, Some(_)) => return Err(IdentityPolicyError::NotLinked.into()),
            _ => {}
        }
        if let Some(b) = binding {
            identity::verify_read_binding(b, h, key)?;
        }
        Ok(())
    }

    /// Resume only a previously authenticated journal, after explicit local
    /// credential re-entry. Ordinary unlock never repairs files. This does
    /// not reconstruct state from a plaintext hint or enroll a legacy profile.
    pub fn recover_identity_publication(dir: &Path, how: Unlock<'_>) -> Result<()> {
        let guard = vault::lock_identity_header(dir)?;
        let h = guard.read()?;
        let key = Self::unwrap_header(&h, how)?;
        identity::recover_publication(&guard, &h, &key)
    }

    /// Lock-screen view: protection mode, linked identity and whether a
    /// fresh provider sign-in is required. Reads no secrets.
    pub fn unlock_requirements(dir: &Path) -> Result<UnlockRequirements> {
        let guard = vault::lock_identity_header(dir)?;
        let h = guard.read()?;
        let linked = identity::hint(dir, &h)?;
        Ok(UnlockRequirements {
            protection: h.protection,
            fresh_login_required: linked.as_ref().map(|l| l.require_fresh_login).unwrap_or(false),
            linked,
            recovery_key_available: h.recovery_wrap.is_some(),
        })
    }

    /// Link a freshly verified provider identity to this profile. Requires
    /// the local unlock secret again (`how`); when the current binding
    /// demands a fresh sign-in, the proof must be for that same account —
    /// replacing it needs the recovery key (or unlinking first).
    pub fn link_identity(dir: &Path, how: Unlock<'_>, proof: VerifiedIdentity, require_fresh_login: bool) -> Result<LinkedIdentity> {
        Self::link_identity_at(dir, how, proof, require_fresh_login, chrono::Utc::now())
    }

    pub fn link_identity_at(
        dir: &Path,
        how: Unlock<'_>,
        proof: VerifiedIdentity,
        require_fresh_login: bool,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<LinkedIdentity> {
        identity::check_fresh(&proof, now)?;
        let recovery = matches!(how, Unlock::RecoveryKey(_));
        let guard = vault::lock_identity_header(dir)?;
        let h = guard.read()?;
        identity::require_enrolled(&h)?;
        let current = if recovery { None } else { identity::read_binding(dir, &h)? };
        let (h, k) = match &current {
            // Re-linking the same account (e.g. toggling the policy): the new
            // proof is also the fresh proof the current policy asks for.
            Some(b) if !recovery && b.provider() == proof.provider() && b.subject() == proof.subject() => {
                Self::unlock_header_checked(dir, &h, how, Some(&proof), now)?
            }
            _ => Self::unlock_header_checked(dir, &h, how, None, now)?,
        };
        drop(current);
        identity::link(&guard, &h, &k, &proof, require_fresh_login, now)
    }

    /// Remove the linked identity. Under a fresh-login policy this needs a
    /// fresh proof for the linked account, or the recovery key.
    pub fn unlink_identity(dir: &Path, how: Unlock<'_>, proof: Option<VerifiedIdentity>) -> Result<()> {
        let recovery = matches!(how, Unlock::RecoveryKey(_));
        let guard = vault::lock_identity_header(dir)?;
        let h = guard.read()?;
        identity::require_enrolled(&h)?;
        let current = if recovery { None } else { identity::read_binding(dir, &h)? };
        if current.is_none() && !recovery {
            return Err(IdentityPolicyError::NotLinked.into());
        }
        let (h, key) = Self::unlock_header_checked(dir, &h, how, proof.as_ref(), chrono::Utc::now())?;
        drop(current);
        identity::unlink(&guard, &h, &key)
    }

    /// The full linked identity (with e-mail), verified against its sealed
    /// copy. Needs the unlocked data key.
    pub fn linked_identity(dir: &Path, key: &Key) -> Result<Option<LinkedIdentity>> {
        let guard = vault::lock_identity_header(dir)?;
        let h = guard.read()?;
        vault::authenticate_header(&h, key)?;
        match identity::read_binding(dir, &h)? {
            Some(b) => Ok(Some(identity::verify_read_binding(&b, &h, key)?)),
            None => Ok(None),
        }
    }
}

fn check_new_passphrase(p: &str) -> Result<()> {
    if p.chars().count() < 8 {
        return Err(AppError::Invalid("the passphrase needs at least 8 characters".into()));
    }
    Ok(())
}

impl crate::App {
    /// Set a new unlock passphrase on a passphrase profile (e.g. after
    /// unlocking with the recovery key). Re-wraps the existing data key;
    /// nothing is re-encrypted and the recovery key stays valid. An
    /// OS-keychain profile is refused: see [`crate::App::convert_to_passphrase`].
    ///
    /// The read here only picks the message for the wrong mode: the header
    /// rewritten is read and checked again under the header lock
    /// ([`vault::change_passphrase`]).
    pub fn change_passphrase(&self, new_passphrase: &str, kdf: KdfParams) -> Result<()> {
        check_new_passphrase(new_passphrase)?;
        let mut h = vault::read_header(&self.dir)?;
        if h.format != self.header.format || h.profile_id != self.header.profile_id {
            return Err(vault::VaultError::HeaderTampered.into());
        }
        if h.protection != ProtectionMode::Passphrase {
            return Err(AppError::Invalid("this profile uses the OS keychain; convert it to passphrase protection instead".into()));
        }
        self.store.with_key(|k| vault::change_passphrase(&self.dir, &mut h, k, new_passphrase, kdf))??;
        Ok(())
    }

    /// Convert an OS-keychain profile to passphrase protection. Returns the
    /// new recovery key (shown once). Afterwards the profile unlocks only
    /// with the passphrase or recovery key, and its keychain entry is
    /// removed; if the credential store refuses, removal is retried at each
    /// unlock until the entry is removed (see
    /// [`ProfileSummary::leftover_keychain_entry`]). A passphrase profile is
    /// refused, as is a conversion whose keychain entry the credential store
    /// refuses to tag first (nothing is changed then). As in
    /// [`crate::App::change_passphrase`], the header rewritten is read and
    /// checked under the header lock.
    pub fn convert_to_passphrase(&self, new_passphrase: &str, kdf: KdfParams) -> Result<KeychainConversion> {
        check_new_passphrase(new_passphrase)?;
        let mut h = vault::read_header(&self.dir)?;
        if h.format != self.header.format || h.profile_id != self.header.profile_id {
            return Err(vault::VaultError::HeaderTampered.into());
        }
        if h.protection != ProtectionMode::OsKeychain {
            return Err(AppError::Invalid("this profile already uses a passphrase; change it instead".into()));
        }
        let conversion = self.store.with_key(|k| vault::convert_keychain_to_passphrase(&self.dir, &mut h, k, new_passphrase, kdf))??;
        Ok(conversion)
    }
}
