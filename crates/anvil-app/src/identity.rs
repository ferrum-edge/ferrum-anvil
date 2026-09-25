//! Identity services for the desktop shell and CLI.
//!
//! **Application identity (who may unlock Anvil).** A provider account can be
//! *linked* to a local profile. The link is a policy, never a key: the data
//! key stays wrapped only by the passphrase, the recovery key or the OS
//! keychain, and nothing here derives, wraps or unwraps it. With
//! `require_fresh_login` the backend additionally demands a provider sign-in
//! from the last few minutes before a passphrase/keychain unlock; the
//! recovery key remains the offline path (docs/identity.md).
//!
//! The binding lives beside the profile header in `identity.json`: a
//! plaintext hint (provider, subject, policy — no e-mail) that lets the lock
//! screen and the pre-unlock check work, plus the full binding sealed with
//! the profile's data key. After the key is unwrapped the sealed copy is
//! authoritative: editing the hint (for example to switch the policy off)
//! makes passphrase/keychain unlock fail until the recovery key is used.
//! This is an application-enforced policy, not cryptography: whoever holds
//! the passphrase and the files can decrypt them with other tools.
//!
//! Imports and backups never carry this file, so restoring someone else's
//! backup cannot replace the local linked identity.
//!
//! **Target-API identity.** [`App::oauth_sign_in`] runs the interactive
//! OAuth authorization-code + PKCE flow for the auth profile in effect for a
//! request and caches the token in this profile's engine (memory only,
//! cleared on lock).

use crate::exec::SendOptions;
use crate::{App, AppError, Result};
use anvil_domain::Id;
use anvil_domain::request::RequestSpec;
use anvil_domain::workspace::LinkedIdentity;
use anvil_engine::oauth_http::TokenSummary;
use anvil_identity::{ApiAuthorization, BrowserOpener, FlowObserver, FlowOptions, ProviderInfo, VerifiedIdentity};
use anvil_storage::vault::ProfileHeader;
use anvil_storage::{Key, crypto};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tokio_util::sync::CancellationToken;

pub const IDENTITY_FILE: &str = "identity.json";
const FORMAT: &str = "anvil-identity-binding";
const VERSION: u32 = 1;
/// A provider sign-in older than this does not count as "fresh".
pub const FRESH_LOGIN_MAX_AGE_SECS: i64 = 300;
/// Tolerated clock difference for a sign-in timestamped in the future.
const FUTURE_SKEW_SECS: i64 = 60;

/// Typed identity-policy refusals.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IdentityPolicyError {
    #[error(
        "this profile requires a fresh {provider} sign-in in addition to the passphrase or keychain; sign in, or unlock with the recovery key"
    )]
    FreshLoginRequired { provider: String },
    #[error("that sign-in belongs to a different {provider} account than the one linked to this profile")]
    IdentityMismatch { provider: String },
    #[error("that sign-in is older than {max_age_secs} seconds; sign in again")]
    StaleProof { max_age_secs: i64 },
    #[error("no provider identity is linked to this profile")]
    NotLinked,
    #[error("the identity binding of this profile was changed outside Anvil; unlock with the recovery key and link the account again")]
    BindingTampered,
}

/// What the lock screen can know before unlocking (no e-mail, no secrets).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IdentityHint {
    pub provider: String,
    pub subject: String,
    pub require_fresh_login: bool,
    pub linked_at: DateTime<Utc>,
}

/// How a profile can be unlocked right now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UnlockRequirements {
    pub protection: anvil_domain::workspace::ProtectionMode,
    pub linked: Option<IdentityHint>,
    /// Passphrase/keychain unlock also needs a fresh provider sign-in.
    pub fresh_login_required: bool,
    /// The recovery key unlocks without a provider sign-in (offline path).
    pub recovery_key_available: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct BindingFile {
    format: String,
    version: u32,
    provider: String,
    subject: String,
    require_fresh_login: bool,
    linked_at: DateTime<Utc>,
    /// Hex AEAD envelope (profile data key) of the full [`LinkedIdentity`].
    sealed: String,
}

impl BindingFile {
    pub(crate) fn require_fresh_login(&self) -> bool {
        self.require_fresh_login
    }

    pub(crate) fn provider(&self) -> &str {
        &self.provider
    }

    pub(crate) fn subject(&self) -> &str {
        &self.subject
    }

    fn hint(&self) -> IdentityHint {
        IdentityHint {
            provider: self.provider.clone(),
            subject: self.subject.clone(),
            require_fresh_login: self.require_fresh_login,
            linked_at: self.linked_at,
        }
    }
}

fn path(dir: &Path) -> PathBuf {
    dir.join(IDENTITY_FILE)
}

fn aad(h: &ProfileHeader) -> Vec<u8> {
    format!("anvil-identity-binding-v1/{}", h.profile_id).into_bytes()
}

/// The plaintext binding, if any. A present but unreadable file is treated
/// as tampering, never as "not linked".
pub(crate) fn read_binding(dir: &Path) -> Result<Option<BindingFile>> {
    let p = path(dir);
    let bytes = match std::fs::read(&p) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let f: BindingFile = serde_json::from_slice(&bytes).map_err(|_| IdentityPolicyError::BindingTampered)?;
    if f.format != FORMAT || f.version != VERSION {
        return Err(IdentityPolicyError::BindingTampered.into());
    }
    Ok(Some(f))
}

/// Open the sealed copy with the data key and require the plaintext hint to
/// match it field for field.
pub(crate) fn verify_binding(f: &BindingFile, h: &ProfileHeader, dek: &Key) -> Result<LinkedIdentity> {
    let env = hex::decode(&f.sealed).map_err(|_| IdentityPolicyError::BindingTampered)?;
    let pt = crypto::open(dek, &aad(h), &env).map_err(|_| IdentityPolicyError::BindingTampered)?;
    let linked: LinkedIdentity = serde_json::from_slice(&pt).map_err(|_| IdentityPolicyError::BindingTampered)?;
    if linked.provider != f.provider
        || linked.subject != f.subject
        || linked.require_fresh_login != f.require_fresh_login
        || linked.linked_at != f.linked_at
    {
        return Err(IdentityPolicyError::BindingTampered.into());
    }
    Ok(linked)
}

fn write_binding(dir: &Path, h: &ProfileHeader, dek: &Key, linked: &LinkedIdentity) -> Result<()> {
    let sealed = hex::encode(crypto::seal(dek, &aad(h), &serde_json::to_vec(linked)?));
    let f = BindingFile {
        format: FORMAT.into(),
        version: VERSION,
        provider: linked.provider.clone(),
        subject: linked.subject.clone(),
        require_fresh_login: linked.require_fresh_login,
        linked_at: linked.linked_at,
        sealed,
    };
    let tmp = dir.join(format!("{IDENTITY_FILE}.tmp"));
    std::fs::write(&tmp, serde_json::to_vec_pretty(&f)?)?;
    std::fs::rename(tmp, path(dir))?;
    Ok(())
}

pub(crate) fn remove_binding(dir: &Path) -> Result<()> {
    match std::fs::remove_file(path(dir)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// A proof counts only for the linked provider and subject, and only while fresh.
pub(crate) fn check_proof(provider: &str, subject: &str, proof: &VerifiedIdentity, now: DateTime<Utc>) -> Result<()> {
    if proof.provider() != provider || proof.subject() != subject {
        return Err(IdentityPolicyError::IdentityMismatch { provider: provider.to_string() }.into());
    }
    check_fresh(proof, now)
}

pub(crate) fn check_fresh(proof: &VerifiedIdentity, now: DateTime<Utc>) -> Result<()> {
    let age = now - proof.authenticated_at();
    if age > Duration::seconds(FRESH_LOGIN_MAX_AGE_SECS) || age < -Duration::seconds(FUTURE_SKEW_SECS) {
        return Err(IdentityPolicyError::StaleProof { max_age_secs: FRESH_LOGIN_MAX_AGE_SECS }.into());
    }
    Ok(())
}

pub(crate) fn hint(dir: &Path) -> Result<Option<IdentityHint>> {
    Ok(read_binding(dir)?.map(|f| f.hint()))
}

pub(crate) fn link(
    dir: &Path,
    h: &ProfileHeader,
    dek: &Key,
    proof: &VerifiedIdentity,
    require_fresh_login: bool,
    now: DateTime<Utc>,
) -> Result<LinkedIdentity> {
    let linked = LinkedIdentity {
        provider: proof.provider().to_string(),
        subject: proof.subject().to_string(),
        email: proof.email().map(str::to_string),
        linked_at: now,
        require_fresh_login,
    };
    write_binding(dir, h, dek, &linked)?;
    Ok(linked)
}

/// Application-login providers known to this build and their availability
/// (Google, GitHub and Facebook are unavailable until the owner registers
/// them; see docs/identity.md).
pub fn login_providers() -> Vec<ProviderInfo> {
    anvil_identity::builtin_providers().iter().map(|p| p.info()).collect()
}

impl App {
    /// Sign in to the OAuth-protected API that `request_id` (or `draft`)
    /// would call, in the system browser, and cache the token for sends
    /// from this profile. The token is never returned; see
    /// [`ApiAuthorization`]. Canceled by `cancel`; refused while locked, and
    /// discarded if the app was locked while the browser was open.
    #[allow(clippy::too_many_arguments)]
    pub async fn oauth_sign_in(
        &self,
        request_id: Option<Id>,
        ws: &Id,
        draft: Option<RequestSpec>,
        opts: &SendOptions,
        opener: &dyn BrowserOpener,
        observer: &dyn FlowObserver,
        flow: &FlowOptions,
        cancel: &CancellationToken,
    ) -> Result<ApiAuthorization> {
        if self.is_locked() {
            return Err(AppError::Locked);
        }
        let ctx = self.build_context(request_id, ws, draft, opts)?;
        let auth = anvil_identity::authorize_api(&self.engine, &ctx, opener, observer, flow, cancel).await?;
        if self.is_locked() {
            let _ = anvil_identity::api_oauth::sign_out(&self.engine, &ctx);
            return Err(AppError::Locked);
        }
        Ok(auth)
    }

    /// Whether a token is cached for the OAuth profile in effect (metadata only).
    pub fn oauth_token_status(
        &self,
        request_id: Option<Id>,
        ws: &Id,
        draft: Option<RequestSpec>,
        opts: &SendOptions,
    ) -> Result<Option<TokenSummary>> {
        let ctx = self.build_context(request_id, ws, draft, opts)?;
        Ok(anvil_identity::api_oauth::token_status(&self.engine, &ctx)?)
    }

    /// Forget the cached token for the OAuth profile in effect.
    pub fn oauth_sign_out(&self, request_id: Option<Id>, ws: &Id, draft: Option<RequestSpec>, opts: &SendOptions) -> Result<bool> {
        let ctx = self.build_context(request_id, ws, draft, opts)?;
        Ok(anvil_identity::api_oauth::sign_out(&self.engine, &ctx)?)
    }
}
