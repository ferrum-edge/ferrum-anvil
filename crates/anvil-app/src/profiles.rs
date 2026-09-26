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
}

pub struct ProfileManager {
    pub root: PathBuf,
}

pub enum Unlock<'a> {
    Passphrase(&'a str),
    RecoveryKey(&'a str),
    Keychain,
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
        let c = vault::create_passphrase_profile(&dir, display_name, passphrase, kdf)?;
        let s = ProfileSummary {
            profile_id: c.header.profile_id.clone(),
            display_name: c.header.display_name.clone(),
            protection: c.header.protection,
            dir,
            created_at: c.header.created_at,
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
        let mut h = vault::read_header(dir)?;
        let recovery = matches!(how, Unlock::RecoveryKey(_));
        let binding = match identity::read_binding(dir) {
            Ok(b) => b,
            // An unreadable binding blocks the ordinary paths only.
            Err(e) if !recovery => return Err(e),
            Err(_) => None,
        };
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
        // A keychain entry left over from converting this profile to a
        // passphrase. It no longer unlocks anything; retry removing it.
        if h.protection == ProtectionMode::Passphrase && h.keychain_account.is_some() {
            vault::retire_keychain_entry(dir, &mut h).ok();
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
        let current = identity::read_binding(dir).or_else(|e| if recovery { Ok(None) } else { Err(e) })?;
        let (h, k) = match &current {
            // Re-linking the same account (e.g. toggling the policy): the new
            // proof is also the fresh proof the current policy asks for.
            Some(b) if !recovery && b.provider() == proof.provider() && b.subject() == proof.subject() => {
                Self::unlock_checked(dir, how, Some(&proof), now)?
            }
            _ => Self::unlock_checked(dir, how, None, now)?,
        };
        identity::link(dir, &h, &k, &proof, require_fresh_login, now)
    }

    /// Remove the linked identity. Under a fresh-login policy this needs a
    /// fresh proof for the linked account, or the recovery key.
    pub fn unlink_identity(dir: &Path, how: Unlock<'_>, proof: Option<VerifiedIdentity>) -> Result<()> {
        let recovery = matches!(how, Unlock::RecoveryKey(_));
        let current = identity::read_binding(dir).or_else(|e| if recovery { Ok(None) } else { Err(e) })?;
        if current.is_none() && !recovery {
            return Err(IdentityPolicyError::NotLinked.into());
        }
        Self::unlock_checked(dir, how, proof.as_ref(), chrono::Utc::now())?;
        identity::remove_binding(dir)
    }

    /// The full linked identity (with e-mail), verified against its sealed
    /// copy. Needs the unlocked data key.
    pub fn linked_identity(dir: &Path, key: &Key) -> Result<Option<LinkedIdentity>> {
        let h = vault::read_header(dir)?;
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
    /// Set a new unlock passphrase on a passphrase profile (e.g. after
    /// unlocking with the recovery key). Re-wraps the existing data key;
    /// nothing is re-encrypted and the recovery key stays valid. An
    /// OS-keychain profile is refused: see [`crate::App::convert_to_passphrase`].
    pub fn change_passphrase(&self, new_passphrase: &str, kdf: KdfParams) -> Result<()> {
        check_new_passphrase(new_passphrase)?;
        let mut h = vault::read_header(&self.dir)?;
        if h.protection != ProtectionMode::Passphrase {
            return Err(AppError::Invalid("this profile uses the OS keychain; convert it to passphrase protection instead".into()));
        }
        self.store.with_key(|k| vault::change_passphrase(&self.dir, &mut h, k, new_passphrase, kdf))??;
        Ok(())
    }

    /// Convert an OS-keychain profile to passphrase protection. Returns the
    /// new recovery key (shown once). Afterwards the profile unlocks only
    /// with the passphrase or recovery key, and its keychain entry is
    /// removed; if the credential store refuses, removal is retried at the
    /// next unlock. A passphrase profile is refused.
    pub fn convert_to_passphrase(&self, new_passphrase: &str, kdf: KdfParams) -> Result<KeychainConversion> {
        check_new_passphrase(new_passphrase)?;
        let mut h = vault::read_header(&self.dir)?;
        if h.protection != ProtectionMode::OsKeychain {
            return Err(AppError::Invalid("this profile already uses a passphrase; change it instead".into()));
        }
        let conversion = self.store.with_key(|k| vault::convert_keychain_to_passphrase(&self.dir, &mut h, k, new_passphrase, kdf))??;
        Ok(conversion)
    }
}
