//! Local profiles (selectors, not OS security boundaries) and unlocking.

use crate::{AppError, Result};
use anvil_storage::vault::{self, ProfileHeader};
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

    pub fn unlock(dir: &Path, how: Unlock<'_>) -> Result<(ProfileHeader, Key)> {
        let h = vault::read_header(dir)?;
        let k = match how {
            Unlock::Passphrase(p) => vault::unlock_with_passphrase(&h, p)?,
            Unlock::RecoveryKey(r) => vault::unlock_with_recovery(&h, r)?,
            Unlock::Keychain => vault::unlock_with_keychain(&h)?,
        };
        Ok((h, k))
    }
}

impl crate::App {
    /// Set a new unlock passphrase (e.g. after unlocking with the recovery
    /// key). Re-wraps the existing data key; nothing is re-encrypted and the
    /// recovery key stays valid.
    pub fn change_passphrase(&self, new_passphrase: &str, kdf: KdfParams) -> Result<()> {
        if new_passphrase.chars().count() < 8 {
            return Err(AppError::Invalid("the passphrase needs at least 8 characters".into()));
        }
        let mut h = vault::read_header(&self.dir)?;
        self.store.with_key(|k| vault::change_passphrase(&self.dir, &mut h, k, new_passphrase, kdf))??;
        Ok(())
    }
}
