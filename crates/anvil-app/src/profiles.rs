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

pub enum Unlock<'a> {
    Passphrase(&'a str),
    RecoveryKey(&'a str),
    Keychain,
}

/// Policy mutations create a new encryption epoch. Deliver and acknowledge the
/// replacement recovery credential before invoking them; they also convert an
/// OS-keychain-only profile to explicit passphrase protection.
pub struct PolicyRotation<'a> {
    pub new_passphrase: &'a str,
    pub recovery: &'a vault::RotationRecoveryKey,
    pub kdf: KdfParams,
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
        if passphrase.chars().count() < 8 {
            return Err(AppError::Invalid("the unlock passphrase must have at least 8 characters".into()));
        }
        let dir = self.profiles_dir().join(uuid::Uuid::now_v7().to_string());
        let c = vault::create_enrolled_passphrase_profile(&dir, display_name, passphrase, kdf)?;
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
        let c = vault::create_enrolled_keychain_profile(&dir, display_name)?;
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
        Self::unlock_checked_policy(dir, how, proof, now, false)
    }

    fn unlock_checked_policy(
        dir: &Path,
        how: Unlock<'_>,
        proof: Option<&VerifiedIdentity>,
        now: chrono::DateTime<chrono::Utc>,
        enroll_missing: bool,
    ) -> Result<(ProfileHeader, Key)> {
        let mut h = vault::read_header(dir)?;
        let recovery = matches!(how, Unlock::RecoveryKey(_));
        let binding = match identity::read_binding(dir) {
            Ok(b) => b,
            // An unreadable binding blocks the ordinary paths only.
            Err(e) if !recovery => return Err(e),
            Err(_) => None,
        };
        if !recovery && !enroll_missing && h.rotation.is_none() && binding.is_none() {
            return Err(IdentityPolicyError::PolicyEnrollmentRequired.into());
        }
        // Gate before the key is unwrapped, from the plaintext hint.
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
        let k = match how {
            Unlock::Passphrase(p) => vault::unlock_with_passphrase(&h, p)?,
            Unlock::RecoveryKey(r) => vault::unlock_with_recovery(&h, r)?,
            Unlock::Keychain => vault::unlock_with_keychain(&h)?,
        };
        // After unwrapping, the sealed binding is authoritative: an edited
        // hint cannot switch the policy off. The recovery key stays usable.
        if let Some(b) = &binding
            && !recovery
        {
            identity::verify_binding(b, &h, &k)?;
        }
        if !recovery && h.rotation.is_some() {
            let canonical = anvil_storage::rotation::binding(dir)?.ok_or(vault::VaultError::HeaderTampered)?;
            vault::verify_rotation_binding(&h, &k, &canonical)?;
        }
        anvil_storage::Store::verify_profile_key(dir, &k)?;
        // A header written by an earlier build gets its protection MAC (and
        // a keychain profile's entry its tag) now that the key is proven.
        vault::upgrade_header(dir, &mut h, &k).ok();
        // A keychain entry left over from converting this profile to a
        // passphrase. It no longer unlocks anything; removing it is retried
        // at each unlock until it is gone.
        if h.protection == ProtectionMode::Passphrase && h.keychain_account.is_some() {
            if h.rotation.is_some() {
                vault::retire_rotated_keychain(dir, &mut h, &k).ok();
            } else {
                vault::retire_keychain_entry(dir, &mut h).ok();
            }
        }
        Ok((h, k))
    }

    /// Lock-screen view: protection mode, linked identity and whether a
    /// fresh provider sign-in is required. Reads no secrets.
    pub fn unlock_requirements(dir: &Path) -> Result<UnlockRequirements> {
        let h = vault::read_header(dir)?;
        let linked = identity::hint(dir)?;
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
    pub fn link_identity(
        dir: &Path,
        how: Unlock<'_>,
        proof: VerifiedIdentity,
        require_fresh_login: bool,
        rotation: PolicyRotation<'_>,
    ) -> Result<LinkedIdentity> {
        Self::link_identity_at(dir, how, proof, require_fresh_login, chrono::Utc::now(), rotation)
    }

    pub fn link_identity_at(
        dir: &Path,
        how: Unlock<'_>,
        proof: VerifiedIdentity,
        require_fresh_login: bool,
        now: chrono::DateTime<chrono::Utc>,
        rotation: PolicyRotation<'_>,
    ) -> Result<LinkedIdentity> {
        identity::check_fresh(&proof, now)?;
        let recovery = matches!(how, Unlock::RecoveryKey(_));
        let current = identity::read_binding(dir).or_else(|e| if recovery { Ok(None) } else { Err(e) })?;
        let (h, k) = match &current {
            // Re-linking the same account (e.g. toggling the policy): the new
            // proof is also the fresh proof the current policy asks for.
            Some(b) if !recovery && b.provider() == proof.provider() && b.subject() == proof.subject() => {
                Self::unlock_checked(dir, how, Some(&proof), now)?
            }
            _ => Self::unlock_checked(dir, how, None, now)?,
        };
        check_new_passphrase(rotation.new_passphrase)?;
        let linked = LinkedIdentity {
            provider: proof.provider().to_string(),
            subject: proof.subject().to_string(),
            email: proof.email().map(str::to_string),
            require_fresh_login,
            linked_at: now,
        };
        let store = anvil_storage::Store::open(dir, k)?;
        store.rotate_data_key(rotation.new_passphrase, rotation.recovery, rotation.kdf, |current, _, new, _| {
            if current.protection_mac != h.protection_mac {
                return Err(vault::VaultError::HeaderTampered);
            }
            identity::sealed_binding(current, new, &linked).map(Some).map_err(|e| vault::VaultError::Header(e.to_string()))
        })?;
        Ok(linked)
    }

    /// Remove the linked identity. Under a fresh-login policy this needs a
    /// fresh proof for the linked account, or the recovery key.
    pub fn unlink_identity(dir: &Path, how: Unlock<'_>, proof: Option<VerifiedIdentity>, rotation: PolicyRotation<'_>) -> Result<()> {
        let recovery = matches!(how, Unlock::RecoveryKey(_));
        let current = identity::read_binding(dir).or_else(|e| if recovery { Ok(None) } else { Err(e) })?;
        if current.is_none() && !recovery {
            return Err(IdentityPolicyError::NotLinked.into());
        }
        let (h, key) = Self::unlock_checked(dir, how, proof.as_ref(), chrono::Utc::now())?;
        Self::rotate_policy(dir, h, key, rotation)
    }

    /// Explicit owner decision for an unknown historical policy. A local secret
    /// proves key possession, not the lost policy's history. Callers must obtain
    /// native/CLI consent to replace that unknown policy before invoking this.
    pub fn enroll_unlinked_policy(dir: &Path, how: Unlock<'_>, rotation: PolicyRotation<'_>) -> Result<()> {
        let h = vault::read_header(dir)?;
        if h.rotation.is_some() || identity::read_binding(dir)?.is_some() {
            return Err(AppError::Invalid("this profile already has a policy; authorize an unlink instead".into()));
        }
        let (h, key) = Self::unlock_checked_policy(dir, how, None, chrono::Utc::now(), true)?;
        if h.rotation.is_some() || identity::read_binding(dir)?.is_some() {
            return Err(AppError::Invalid("policy enrollment changed; authorize the current policy explicitly".into()));
        }
        Self::rotate_policy(dir, h, key, rotation)
    }

    fn rotate_policy(dir: &Path, h: ProfileHeader, key: Key, rotation: PolicyRotation<'_>) -> Result<()> {
        check_new_passphrase(rotation.new_passphrase)?;
        let store = anvil_storage::Store::open(dir, key)?;
        store.rotate_data_key(rotation.new_passphrase, rotation.recovery, rotation.kdf, |current, _, _, _| {
            if current.protection_mac != h.protection_mac {
                return Err(vault::VaultError::HeaderTampered);
            }
            Ok(None)
        })?;
        Ok(())
    }

    /// The full linked identity (with e-mail), verified against its sealed
    /// copy. Needs the unlocked data key.
    pub fn linked_identity(dir: &Path, key: &Key) -> Result<Option<LinkedIdentity>> {
        let h = vault::read_header(dir)?;
        if h.rotation.is_some() {
            let binding = anvil_storage::rotation::binding(dir)?.ok_or(vault::VaultError::HeaderTampered)?;
            vault::verify_rotation_binding(&h, key, &binding)?;
        }
        match identity::read_binding(dir)? {
            Some(b) => Ok(Some(identity::verify_binding(&b, &h, key)?)),
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
    /// Deliberately rotate the local data key and re-encrypt all active data.
    /// The new passphrase and new recovery key replace every old local unlock
    /// credential. Portable backups and raw historical copies remain historical.
    /// Success locks this App; reopen it with the new header/key before use.
    /// Save and acknowledge `recovery` before calling; success revokes the old one.
    pub fn rotate_data_key(
        &self,
        new_passphrase: &str,
        recovery: &vault::RotationRecoveryKey,
        kdf: KdfParams,
    ) -> Result<KeychainConversion> {
        check_new_passphrase(new_passphrase)?;
        let result = self.store.rotate_data_key(new_passphrase, recovery, kdf, |h, old, new, binding| {
            identity::rotate_binding(h, old, new, binding, &self.dir)
        })?;
        self.lock();
        Ok(result)
    }

    /// Replace the passphrase and recovery credential by rotating every
    /// active ciphertext. Save and acknowledge `recovery` before calling.
    /// Success locks this App; reopening refreshes its key identity.
    pub fn change_passphrase(
        &self,
        new_passphrase: &str,
        recovery: &vault::RotationRecoveryKey,
        kdf: KdfParams,
    ) -> Result<KeychainConversion> {
        check_new_passphrase(new_passphrase)?;
        let h = vault::read_header(&self.dir)?;
        if h.protection != ProtectionMode::Passphrase {
            return Err(AppError::Invalid("this profile uses the OS keychain; convert it to passphrase protection instead".into()));
        }
        self.rotate_data_key(new_passphrase, recovery, kdf)
    }

    /// Convert an OS-keychain profile by rotating every active ciphertext.
    /// Save and acknowledge `recovery` first. Success locks this App. Credential
    /// cleanup failure does not roll back the durable rotation; it is reported
    /// and retried on unlock, and the old OS key cannot decrypt current data.
    pub fn convert_to_passphrase(
        &self,
        new_passphrase: &str,
        recovery: &vault::RotationRecoveryKey,
        kdf: KdfParams,
    ) -> Result<KeychainConversion> {
        check_new_passphrase(new_passphrase)?;
        let h = vault::read_header(&self.dir)?;
        if h.protection != ProtectionMode::OsKeychain {
            return Err(AppError::Invalid("this profile already uses a passphrase; change it instead".into()));
        }
        self.rotate_data_key(new_passphrase, recovery, kdf)
    }
}
