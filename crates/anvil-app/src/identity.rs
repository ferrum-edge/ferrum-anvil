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
//! New profiles keep the binding and its authenticated presence in the
//! canonical SQLite key state. Historical legacy profiles used `identity.json`: a
//! plaintext hint (provider, subject, policy — no e-mail) that lets the lock
//! screen and the pre-unlock check work, plus the full binding sealed with
//! the profile's data key. After the key is unwrapped the sealed copy is
//! authoritative: editing the hint (for example to switch the policy off)
//! makes passphrase/keychain unlock fail until the recovery key is used.
//! This is an application-enforced policy, not cryptography: whoever holds
//! the passphrase and the files can decrypt them with other tools.
//!
//! Missing legacy policy requires explicit enrollment; policy mutations rotate
//! the data key and require saving a replacement recovery credential first.
//! Imports and backups never carry local policy, so restoring someone else's
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
use anvil_engine::context::ExecutionContext;
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
    #[error(
        "POLICY_ENROLLMENT_REQUIRED: this legacy profile needs canonical policy enrollment and key rotation before active use; preserve a verified linked policy, or explicitly replace unknown policy"
    )]
    PolicyEnrollmentRequired,
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
    let _guard = anvil_storage::rotation::profile_data_guard(dir)?;
    if let Some(binding) = anvil_storage::rotation::binding(dir)? {
        return binding.map(serde_json::from_value).transpose().map_err(|_| IdentityPolicyError::BindingTampered.into());
    }
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

pub(crate) fn sealed_binding(h: &ProfileHeader, key: &Key, linked: &LinkedIdentity) -> Result<serde_json::Value> {
    let f = BindingFile {
        format: FORMAT.into(),
        version: VERSION,
        provider: linked.provider.clone(),
        subject: linked.subject.clone(),
        require_fresh_login: linked.require_fresh_login,
        linked_at: linked.linked_at,
        sealed: hex::encode(crypto::seal(key, &aad(h), &serde_json::to_vec(linked)?)),
    };
    Ok(serde_json::to_value(f)?)
}

/// Prepare the policy for the same atomic commit as its new data key.
pub(crate) fn rotate_binding(
    h: &ProfileHeader,
    old: &Key,
    new: &Key,
    canonical: Option<Option<serde_json::Value>>,
    dir: &Path,
) -> std::result::Result<Option<serde_json::Value>, anvil_storage::VaultError> {
    let bad = || anvil_storage::VaultError::Header("the linked identity must be repaired with the recovery key before rotation".into());
    if let Some(value) = &canonical {
        anvil_storage::vault::verify_rotation_binding(h, old, value)?;
    }
    let binding: Option<BindingFile> = match canonical {
        Some(value) => value.map(serde_json::from_value).transpose().map_err(|_| bad())?,
        None => match std::fs::read(path(dir)) {
            Ok(bytes) => Some(serde_json::from_slice(&bytes).map_err(|_| bad())?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(anvil_storage::VaultError::Header(
                    "POLICY_ENROLLMENT_REQUIRED: explicitly enroll the unknown legacy policy before rotation".into(),
                ));
            }
            Err(e) => return Err(e.into()),
        },
    };
    let Some(mut binding) = binding else {
        return Ok(None);
    };
    if binding.format != FORMAT || binding.version != VERSION {
        return Err(bad());
    }
    verify_binding(&binding, h, old).map_err(|_| bad())?;
    let env = hex::decode(&binding.sealed).map_err(|_| bad())?;
    let pt = crypto::open(old, &aad(h), &env).map_err(|_| bad())?;
    binding.sealed = hex::encode(crypto::seal(new, &aad(h), &pt));
    Ok(Some(serde_json::to_value(binding).map_err(|_| bad())?))
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
        let ctx = self.build_context_off_runtime(request_id, *ws, draft, opts.clone(), cancel).await?;
        self.oauth_sign_in_with(&ctx, opener, observer, flow, cancel).await
    }

    /// [`App::oauth_sign_in`] for the context `ctx` exactly as given (built
    /// by [`App::build_context`]), so a caller that checked it signs in with
    /// what it checked, never with a context built again later.
    pub async fn oauth_sign_in_with(
        &self,
        ctx: &ExecutionContext,
        opener: &dyn BrowserOpener,
        observer: &dyn FlowObserver,
        flow: &FlowOptions,
        cancel: &CancellationToken,
    ) -> Result<ApiAuthorization> {
        if self.is_locked() {
            return Err(AppError::Locked);
        }
        ctx.secrets.validate_context().map_err(AppError::Invalid)?;
        let auth = anvil_identity::authorize_api(&self.engine, ctx, opener, observer, flow, cancel).await?;
        if self.is_locked() {
            let _ = anvil_identity::api_oauth::sign_out(&self.engine, ctx);
            return Err(AppError::Locked);
        }
        Ok(auth)
    }

    /// Whether a token is cached for the OAuth profile in effect (metadata only).
    /// Invalid token endpoints return the same configuration refusal as sign-in,
    /// before credential expansion; callers must surface it instead of reporting
    /// an ordinary signed-out status. HTTP requires a literal loopback address.
    pub fn oauth_token_status(
        &self,
        request_id: Option<Id>,
        ws: &Id,
        draft: Option<RequestSpec>,
        opts: &SendOptions,
    ) -> Result<Option<TokenSummary>> {
        let ctx = self.build_context(request_id, ws, draft, opts)?;
        let target = anvil_engine::oauth_http::interactive_oauth(&ctx)
            .map_err(|failure| anvil_identity::FlowError::Configuration(failure.message))?;
        Ok(anvil_engine::oauth_http::token_status(&self.engine, &target))
    }

    /// Forget the cached token for the OAuth profile in effect.
    pub fn oauth_sign_out(&self, request_id: Option<Id>, ws: &Id, draft: Option<RequestSpec>, opts: &SendOptions) -> Result<bool> {
        let ctx = self.build_context(request_id, ws, draft, opts)?;
        Ok(anvil_identity::api_oauth::sign_out(&self.engine, &ctx)?)
    }
}
