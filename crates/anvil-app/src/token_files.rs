//! JWT-SVID token files the user chose in the desktop's native open dialog.
//!
//! A token file (for example one written by spiffe-helper) is re-read at
//! every send because it rotates, so a session grant does not fit. Instead
//! the backend keeps a binding in the vault: the path the user picked for
//! this purpose, as picked. It is not canonicalised: a rotating token (a
//! Kubernetes projected service-account token) is a link into a directory
//! that the next rotation deletes, so the link, not its current target, is
//! what is read at every send. The engine follows it and reads only a
//! regular file of bounded size. When the desktop confines token files
//! ([`App::confine_token_files`]), a JWT-SVID `file` source is honoured only
//! if its path is bound, so a path the webview wrote into an auth setting is
//! never read. Bindings are device-specific: they are not exported, and an
//! import cannot create one. The user lists them and removes one that should
//! no longer be read ([`App::remove_token_file_binding`]).

use crate::{App, AppError, Result};
use anvil_domain::Id;
use anvil_domain::auth::AuthConfig;
use anvil_domain::workload::JwtSvidSource;
use anvil_storage::store::kind;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;

/// A token file bound through the native dialog.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenFileBinding {
    pub id: Id,
    /// Absolute path of the chosen file, as chosen (links not resolved).
    pub path: String,
    pub bound_at: DateTime<Utc>,
}

impl App {
    /// Honour only bound token files from now on (the desktop shell calls
    /// this for every profile it opens). The CLI leaves it off.
    pub fn confine_token_files(&self) {
        self.confined_token_files.store(true, Ordering::SeqCst);
    }

    /// Bind the token file the user picked in the native open dialog. Only
    /// the desktop's `file_choose` calls this, with the dialog's result.
    pub fn bind_token_file(&self, picked: &Path) -> Result<TokenFileBinding> {
        let path = chosen_link(picked, "token file")?;
        if let Some(b) = self.token_file_bindings()?.into_iter().find(|b| b.path == path) {
            return Ok(b);
        }
        let b = TokenFileBinding { id: Id::new(), path, bound_at: Utc::now() };
        self.store.put(kind::TOKEN_FILE, &b.id, None, None, 0.0, &b)?;
        Ok(b)
    }

    /// Every bound token file, oldest first.
    pub fn token_file_bindings(&self) -> Result<Vec<TokenFileBinding>> {
        let mut bindings: Vec<TokenFileBinding> = self.store.list(kind::TOKEN_FILE, None)?;
        bindings.sort_by(|a, b| a.bound_at.cmp(&b.bound_at).then_with(|| a.path.cmp(&b.path)));
        Ok(bindings)
    }

    /// Remove a binding. From the next send on, an auth setting that names its
    /// file is refused (when token files are confined) until the user chooses
    /// the file again.
    pub fn remove_token_file_binding(&self, id: &Id) -> Result<()> {
        if !self.store.delete(kind::TOKEN_FILE, id)? {
            return Err(AppError::NotFound(format!("token file binding {id}")));
        }
        Ok(())
    }

    /// Refuse an auth setting that would read a token file that is not
    /// bound, when token files are confined.
    pub(crate) fn check_token_files(&self, auth: &AuthConfig) -> Result<()> {
        if !self.confined_token_files.load(Ordering::SeqCst) {
            return Ok(());
        }
        let mut paths = Vec::new();
        jwt_svid_files(auth, &mut paths);
        if paths.is_empty() {
            return Ok(());
        }
        let bound = self.token_file_bindings()?;
        for p in paths {
            if !bound.iter().any(|b| b.path == p.trim()) {
                return Err(AppError::Invalid(
                    "the JWT-SVID token file was not chosen with Choose… on this device; choose it in the auth settings".into(),
                ));
            }
        }
        Ok(())
    }
}

/// The canonical path of a regular file the user picked in the native
/// dialog, as it is bound. `what` names the file in errors.
pub(crate) fn chosen_path(picked: &Path, what: &str) -> Result<String> {
    literal(&regular_file(picked, what)?, what)
}

/// The path of a file the user picked in the native dialog, as picked: links
/// in it are kept, and resolved again at every read. It must lead to a
/// regular file now; it is canonicalised only to check that.
pub(crate) fn chosen_link(picked: &Path, what: &str) -> Result<String> {
    regular_file(picked, what)?;
    literal(picked, what)
}

/// The canonical path of `picked`, which must be absolute and lead to a
/// regular file.
fn regular_file(picked: &Path, what: &str) -> Result<PathBuf> {
    if !picked.is_absolute() {
        return Err(AppError::Invalid("the chosen file has no absolute path".into()));
    }
    let canonical = std::fs::canonicalize(picked)?;
    if !std::fs::metadata(&canonical)?.is_file() {
        return Err(AppError::Invalid(format!("the chosen {what} is not a regular file")));
    }
    Ok(canonical)
}

/// `path` as it is bound and later named in a setting.
fn literal(path: &Path, what: &str) -> Result<String> {
    let path = path.to_str().ok_or_else(|| AppError::Invalid(format!("the {what}'s path is not valid UTF-8")))?.to_string();
    // Setting paths are templates; a bound path must read as itself.
    if path.contains("{{") {
        return Err(AppError::Invalid(format!("the {what}'s path contains '{{{{', which Anvil reads as a variable")));
    }
    Ok(path)
}

/// Paths of every JWT-SVID `file` source in an auth setting.
fn jwt_svid_files<'a>(auth: &'a AuthConfig, out: &mut Vec<&'a str>) {
    match auth {
        AuthConfig::JwtSvid { config } => {
            if let JwtSvidSource::File { path } = &config.source {
                out.push(path);
            }
        }
        AuthConfig::Multi { profiles } => profiles.iter().for_each(|p| jwt_svid_files(p, out)),
        _ => {}
    }
}
