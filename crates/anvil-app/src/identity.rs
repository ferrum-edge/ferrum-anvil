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
use anvil_storage::vault::{self, IdentityBindingPublication, IdentityHeaderGuard, ProfileHeader};
use anvil_storage::{Key, crypto};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::fs::{File, Metadata, OpenOptions};
use std::io::Read;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use tokio_util::sync::CancellationToken;

pub const IDENTITY_FILE: &str = "identity.json";
const FORMAT: &str = "anvil-identity-binding";
const VERSION: u32 = 1;
/// Includes the hex-encoded sealed envelope and the public hint.
const MAX_BINDING_BYTES: u64 = 64 * 1024;
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
    #[error("an identity change was interrupted; explicitly recover its authenticated publication before ordinary unlock")]
    PublicationPending,
    #[error("this legacy profile has no authenticated identity expectation; linking requires an explicitly created draft-format profile")]
    LegacyEnrollmentRequired,
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
#[serde(deny_unknown_fields)]
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

/// Keep the descriptor alive until the sealed identity has been verified.
pub(crate) struct ReadBinding {
    binding: BindingFile,
    file: File,
    metadata: Metadata,
    path: PathBuf,
}

impl Deref for ReadBinding {
    type Target = BindingFile;

    fn deref(&self) -> &BindingFile {
        &self.binding
    }
}

impl ReadBinding {
    fn check_current(&self) -> Result<()> {
        let current = std::fs::symlink_metadata(&self.path)?;
        let held = self.file.metadata()?;
        if !regular_binding(&current) || held.len() != self.metadata.len() || held.modified()? != self.metadata.modified()? {
            return Err(IdentityPolicyError::BindingTampered.into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if current.dev() != held.dev() || current.ino() != held.ino() {
                return Err(IdentityPolicyError::BindingTampered.into());
            }
        }
        // Windows opens below deny write/delete sharing while this handle is
        // held. Query its real type and attributes, not a path-only hint.
        #[cfg(windows)]
        {
            let info = winapi_util::file::information(&self.file)?;
            let current_file = open_binding(&self.path)?.ok_or(IdentityPolicyError::BindingTampered)?;
            let current_info = winapi_util::file::information(&current_file)?;
            if !winapi_util::file::typ(&self.file)?.is_disk()
                || info.file_attributes() & 0x400 != 0
                || info.volume_serial_number() != current_info.volume_serial_number()
                || info.file_index() != current_info.file_index()
            {
                return Err(IdentityPolicyError::BindingTampered.into());
            }
        }
        Ok(())
    }
}

fn regular_binding(metadata: &Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        // FILE_ATTRIBUTE_REPARSE_POINT, including non-symlink reparse tags.
        metadata.is_file() && metadata.file_attributes() & 0x400 == 0
    }
    #[cfg(not(windows))]
    {
        metadata.is_file()
    }
}

fn open_binding(path: &Path) -> Result<Option<File>> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    if !regular_binding(&metadata) || metadata.len() > MAX_BINDING_BYTES {
        return Err(IdentityPolicyError::BindingTampered.into());
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // FILE_FLAG_OPEN_REPARSE_POINT; FILE_SHARE_READ only. No dependency
        // on the pending filesystem-grant proposal is needed.
        options.custom_flags(0x0020_0000).share_mode(1);
    }
    #[cfg(test)]
    BEFORE_BINDING_OPEN.with(|hook| {
        if let Some(hook) = hook.take() {
            hook(path);
        }
    });
    #[cfg(not(any(unix, windows)))]
    return Err(IdentityPolicyError::BindingTampered.into());
    #[cfg(any(unix, windows))]
    {
        let file = options.open(path)?;
        if !regular_binding(&file.metadata()?) {
            return Err(IdentityPolicyError::BindingTampered.into());
        }
        #[cfg(windows)]
        if !winapi_util::file::typ(&file)?.is_disk() {
            return Err(IdentityPolicyError::BindingTampered.into());
        }
        Ok(Some(file))
    }
}

#[cfg(test)]
thread_local! {
    static BEFORE_BINDING_OPEN: std::cell::Cell<Option<fn(&Path)>> = const { std::cell::Cell::new(None) };
}

fn path(dir: &Path) -> PathBuf {
    dir.join(IDENTITY_FILE)
}

fn aad(h: &ProfileHeader) -> Vec<u8> {
    format!("anvil-identity-binding-v1/{}", h.profile_id).into_bytes()
}

/// Read the exact binding committed by the header. Lock-screen callers have
/// only an untrusted hint; ordinary unlock authenticates the header with its
/// DEK before returning a key to the profile installer.
pub(crate) fn read_binding(dir: &Path, h: &ProfileHeader) -> Result<Option<ReadBinding>> {
    if h.identity_binding.as_ref().is_some_and(|e| e.pending.is_some()) {
        return Err(IdentityPolicyError::PublicationPending.into());
    }
    let path = path(dir);
    let file = open_binding(&path)?;
    let mut bytes = Vec::new();
    let metadata = match &file {
        Some(file) => {
            let metadata = file.metadata()?;
            if metadata.len() > MAX_BINDING_BYTES {
                return Err(IdentityPolicyError::BindingTampered.into());
            }
            file.take(MAX_BINDING_BYTES + 1).read_to_end(&mut bytes)?;
            if bytes.len() as u64 > MAX_BINDING_BYTES {
                return Err(IdentityPolicyError::BindingTampered.into());
            }
            Some(metadata)
        }
        None => None,
    };
    if let Some(expectation) = &h.identity_binding {
        match (&expectation.binding, &file) {
            (None, None) => return Ok(None),
            (Some(expected), Some(_)) if expected.version == VERSION && *expected == vault::identity_binding_digest(&bytes, VERSION) => {}
            _ => return Err(IdentityPolicyError::BindingTampered.into()),
        }
    }
    match (file, metadata) {
        (Some(file), Some(metadata)) => {
            let binding = ReadBinding { binding: parse_binding(&bytes)?, file, metadata, path };
            binding.check_current()?;
            Ok(Some(binding))
        }
        _ => Ok(None),
    }
}

fn parse_binding(bytes: &[u8]) -> Result<BindingFile> {
    if bytes.len() as u64 > MAX_BINDING_BYTES {
        return Err(IdentityPolicyError::BindingTampered.into());
    }
    let f: BindingFile = serde_json::from_slice(bytes).map_err(|_| IdentityPolicyError::BindingTampered)?;
    if f.format != FORMAT || f.version != VERSION {
        return Err(IdentityPolicyError::BindingTampered.into());
    }
    Ok(f)
}

pub(crate) fn verify_read_binding(f: &ReadBinding, h: &ProfileHeader, dek: &Key) -> Result<LinkedIdentity> {
    f.check_current()?;
    let linked = verify_binding(f, h, dek)?;
    f.check_current()?;
    Ok(linked)
}

/// Open the sealed copy with the data key and require the plaintext hint to
/// match it field for field.
pub(crate) fn verify_binding(f: &BindingFile, h: &ProfileHeader, dek: &Key) -> Result<LinkedIdentity> {
    vault::authenticate_header(h, dek)?;
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

fn binding_contents(h: &ProfileHeader, dek: &Key, linked: &LinkedIdentity) -> Result<String> {
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
    let contents = serde_json::to_string_pretty(&f)?;
    if contents.len() as u64 > MAX_BINDING_BYTES {
        return Err(AppError::Invalid("the identity binding exceeds 64 KiB".into()));
    }
    Ok(contents)
}

pub(crate) fn require_enrolled(h: &ProfileHeader) -> Result<()> {
    if h.format != vault::IDENTITY_PROFILE_FORMAT {
        return Err(IdentityPolicyError::LegacyEnrollmentRequired.into());
    }
    Ok(())
}

pub(crate) fn unlink(guard: &IdentityHeaderGuard<'_>, h: &ProfileHeader, dek: &Key) -> Result<()> {
    require_enrolled(h)?;
    guard.begin_identity_publication(h, dek, IdentityBindingPublication { binding: None, contents: None })?;
    guard.finish_identity_publication(dek)?;
    Ok(())
}

/// Validate journal data under the proven DEK before resuming publication.
pub(crate) fn recover_publication(guard: &IdentityHeaderGuard<'_>, h: &ProfileHeader, dek: &Key) -> Result<()> {
    require_enrolled(h)?;
    vault::authenticate_header(h, dek)?;
    let pending = h
        .identity_binding
        .as_ref()
        .and_then(|e| e.pending.as_ref())
        .ok_or_else(|| AppError::Invalid("no pending identity publication".into()))?;
    if let Some(contents) = &pending.contents {
        let binding = parse_binding(contents.as_bytes())?;
        verify_binding(&binding, h, dek)?;
    }
    guard.finish_identity_publication(dek)?;
    Ok(())
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

pub(crate) fn hint(dir: &Path, h: &ProfileHeader) -> Result<Option<IdentityHint>> {
    Ok(read_binding(dir, h)?.map(|f| f.hint()))
}

pub(crate) fn link(
    guard: &IdentityHeaderGuard<'_>,
    h: &ProfileHeader,
    dek: &Key,
    proof: &VerifiedIdentity,
    require_fresh_login: bool,
    now: DateTime<Utc>,
) -> Result<LinkedIdentity> {
    require_enrolled(h)?;
    let linked = LinkedIdentity {
        provider: proof.provider().to_string(),
        subject: proof.subject().to_string(),
        email: proof.email().map(str::to_string),
        linked_at: now,
        require_fresh_login,
    };
    let contents = binding_contents(h, dek, &linked)?;
    let binding = Some(vault::identity_binding_digest(contents.as_bytes(), VERSION));
    guard.begin_identity_publication(h, dek, IdentityBindingPublication { binding, contents: Some(contents) })?;
    guard.finish_identity_publication(dek)?;
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
        let ctx = self.build_context_off_runtime(request_id, *ws, draft, opts.clone(), cancel).await?;
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

#[cfg(test)]
mod binding_descriptor_tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::Duration;

    fn bounded<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
        let (tx, rx) = mpsc::channel();
        let worker = std::thread::spawn(move || tx.send(f()).unwrap());
        let result = rx.recv_timeout(Duration::from_secs(5)).expect("binding read blocked");
        worker.join().unwrap();
        result
    }

    #[cfg(unix)]
    #[test]
    fn an_actual_character_device_is_refused_without_reading_it() {
        use std::os::unix::fs::FileTypeExt;
        assert!(std::fs::symlink_metadata("/dev/zero").unwrap().file_type().is_char_device());
        bounded(|| assert!(open_binding(Path::new("/dev/zero")).is_err()));
    }

    #[cfg(unix)]
    #[test]
    fn a_fifo_swapped_in_after_metadata_never_blocks_the_descriptor_open() {
        #[allow(unsafe_code)]
        fn swap(path: &Path) {
            use std::os::unix::ffi::OsStrExt;
            std::fs::remove_file(path).unwrap();
            let path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
            // SAFETY: a live NUL-terminated path, no pointer retained by mkfifo.
            assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
        }
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join(IDENTITY_FILE);
        std::fs::write(&path, b"regular file before swap").unwrap();
        bounded(move || {
            BEFORE_BINDING_OPEN.with(|hook| hook.set(Some(swap)));
            assert!(open_binding(&path).is_err());
        });
    }

    #[cfg(windows)]
    #[test]
    fn a_reparse_point_swapped_in_after_metadata_is_not_followed() {
        fn swap(path: &Path) {
            let target = path.with_extension("target");
            std::fs::write(&target, b"outside target").unwrap();
            std::fs::remove_file(path).unwrap();
            std::os::windows::fs::symlink_file(target, path).unwrap();
        }
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join(IDENTITY_FILE);
        std::fs::write(&path, b"regular file before swap").unwrap();
        bounded(move || {
            BEFORE_BINDING_OPEN.with(|hook| hook.set(Some(swap)));
            assert!(open_binding(&path).is_err());
        });
    }

    #[test]
    fn parallel_replacement_cannot_substitute_the_descriptor_being_verified() {
        let root = tempfile::tempdir().unwrap();
        let created = vault::create_passphrase_profile_with_identity_expectation(
            root.path(),
            "descriptor",
            "passphrase",
            anvil_storage::KdfParams::testing(),
        )
        .unwrap();
        let linked = LinkedIdentity {
            provider: "mock".into(),
            subject: "fixture".into(),
            email: None,
            require_fresh_login: false,
            linked_at: Utc::now(),
        };
        let contents = binding_contents(&created.header, &created.dek, &linked).unwrap();
        let guard = vault::lock_identity_header(root.path()).unwrap();
        guard
            .begin_identity_publication(
                &created.header,
                &created.dek,
                IdentityBindingPublication {
                    binding: Some(vault::identity_binding_digest(contents.as_bytes(), VERSION)),
                    contents: Some(contents),
                },
            )
            .unwrap();
        let header = guard.finish_identity_publication(&created.dek).unwrap();
        let held = read_binding(root.path(), &header).unwrap().unwrap();
        let path = root.path().join(IDENTITY_FILE);
        let replacement = path.clone();
        let changed = bounded(move || std::fs::remove_file(&replacement));
        #[cfg(unix)]
        {
            changed.unwrap();
            std::os::unix::fs::symlink("/dev/zero", &path).unwrap();
            assert!(verify_read_binding(&held, &header, &created.dek).is_err());
        }
        #[cfg(windows)]
        {
            // The actual Windows handle denies delete sharing throughout
            // verification, so the competing replacement must fail.
            assert!(changed.is_err());
            assert_eq!(verify_read_binding(&held, &header, &created.dek).unwrap(), linked);
            drop(held);
            std::fs::remove_file(&path).unwrap();
            let target = path.with_extension("target");
            std::fs::write(&target, b"replacement").unwrap();
            std::os::windows::fs::symlink_file(target, &path).unwrap();
            assert!(read_binding(root.path(), &header).is_err());
        }
    }
}
