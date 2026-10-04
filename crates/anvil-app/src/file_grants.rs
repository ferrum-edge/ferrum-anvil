//! Native-dialog file grants for the desktop shell.
//!
//! The webview never names a file on disk. The backend shows the native
//! open/save dialog itself, records what the user picked here and hands the
//! webview an opaque, unguessable token bound to one purpose. File commands
//! accept only such a token, so the renderer reaches exactly the files the
//! user chose for that purpose in this session, and nothing else.
//!
//! - A read grant retains the selected directory and original file. Reads
//!   reopen the leaf relative to that directory and compare the descriptor's
//!   identity. In-place edits are visible; replacing the leaf is refused.
//! - Certificate reads return only validated certificate blocks. A private
//!   key selection belongs to its issuing vault, is consumed once and keeps
//!   its revocation generation fenced through the vault commit. Only a
//!   secret reference returns, never bytes to the renderer.
//! - A write grant retains the selected folder and the chosen file name. Data
//!   goes to a newly created temporary file in that folder (never through an
//!   existing file or link) that is published without replacing an occupied
//!   name. A successful write spends the grant. See the draft compatibility
//!   decisions in docs/security/file-handle-safety.md.
//! - Grants expire, are bounded in number and are all revoked on lock and
//!   when the desktop opens another profile. A choice that was still in
//!   progress then grants nothing.
//!
//! A JWT-SVID token file (`jwt_svid_file`) is different: it is re-read at
//! every send, so the choice is kept as a persistent binding in the vault
//! (`anvil_app::token_files`) rather than as a session grant. A linked
//! local file has a persistent referrer record plus a session handle in this
//! draft (`linked_file`, or
//! `linked_file_relocate` to repoint it to a new location,
//! `anvil_app::linked_files`).

use crate::file_handles::{SelectedDirectory, SelectedFile, file_id, no_reparse, open_regular_at};
use anvil_domain::Id;
use anvil_domain::secret::SecretRef;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

/// How long a selection stays usable.
pub const GRANT_TTL: Duration = Duration::from_secs(30 * 60);
/// Outstanding grants kept at most; the oldest is dropped beyond this.
pub const MAX_GRANTS: usize = 32;

/// What a chosen file may be used for. A grant is honoured only by the
/// command that serves its purpose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FilePurpose {
    /// Read an Anvil bundle or backup to import.
    BundleImport,
    /// Read a file into a request as a stored attachment.
    Attachment,
    /// Read PEM certificates into the renderer, refusing private keys.
    PemCertificate,
    /// Ingest a PEM private key into the vault once; never return its text.
    PemPrivateKey,
    /// Read a PKCS#12 keystore (carried as base64).
    Pkcs12File,
    /// Read an API spec or collection to import.
    SpecSource,
    /// Read a CSV/JSON load-test dataset.
    Dataset,
    /// Read an API-standards ruleset (YAML or JSON) to keep in the profile.
    Ruleset,
    /// Write an Anvil bundle or backup.
    BundleExport,
    /// Write a load-test report.
    LoadReportExport,
    /// Write a collection-run report.
    RunReportExport,
    /// Write an API-standards lint report (JSON or SARIF).
    LintReportExport,
    /// Write a description revised with contract-drift suggestions, or its
    /// JSON Patch.
    SpecRevisionExport,
    /// Bind a JWT-SVID token file that the backend reads at send time.
    JwtSvidFile,
    /// Bind a linked local file that a saved request or dataset names, so
    /// the backend may read it at send time.
    LinkedFile,
    /// Repoint a linked local file that a saved request or dataset names to
    /// a file the user picked at a new location, and bind it for that
    /// request or dataset.
    LinkedFileRelocate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// Open dialog; the file is read through a session grant.
    Read,
    /// Save dialog; the file is written through a session grant.
    Write,
    /// Open dialog; the choice is bound persistently in the vault and the
    /// backend reads the file itself (never through a grant).
    Bind,
}

impl FilePurpose {
    pub fn access(self) -> Access {
        match self {
            FilePurpose::BundleExport
            | FilePurpose::LoadReportExport
            | FilePurpose::RunReportExport
            | FilePurpose::LintReportExport
            | FilePurpose::SpecRevisionExport => Access::Write,
            FilePurpose::BundleImport
            | FilePurpose::Attachment
            | FilePurpose::PemCertificate
            | FilePurpose::PemPrivateKey
            | FilePurpose::Pkcs12File
            | FilePurpose::SpecSource
            | FilePurpose::Dataset
            | FilePurpose::Ruleset => Access::Read,
            FilePurpose::JwtSvidFile | FilePurpose::LinkedFile | FilePurpose::LinkedFileRelocate => Access::Bind,
        }
    }

    /// Whether a written file is created readable only by its owner (Unix):
    /// bundles and backups can carry secrets.
    pub fn owner_only(self) -> bool {
        matches!(self, FilePurpose::BundleExport)
    }

    /// Largest file read for this purpose (0 for write purposes).
    pub fn max_read_bytes(self) -> u64 {
        const MIB: u64 = 1024 * 1024;
        match self {
            FilePurpose::BundleImport => 2 * 1024 * MIB,
            FilePurpose::Attachment => 256 * MIB,
            FilePurpose::PemCertificate | FilePurpose::PemPrivateKey | FilePurpose::Pkcs12File => MIB,
            FilePurpose::SpecSource => 32 * MIB,
            FilePurpose::Dataset => 64 * MIB,
            FilePurpose::Ruleset => MIB,
            FilePurpose::BundleExport
            | FilePurpose::LoadReportExport
            | FilePurpose::RunReportExport
            | FilePurpose::LintReportExport
            | FilePurpose::SpecRevisionExport
            | FilePurpose::JwtSvidFile
            | FilePurpose::LinkedFile
            | FilePurpose::LinkedFileRelocate => 0,
        }
    }
}

/// What the webview receives for a chosen file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FileGrant {
    /// Opaque token that file commands accept in place of a path.
    pub token: String,
    /// The chosen file's name without its folder, for display.
    pub file_name: String,
    /// Only for a bound file (`jwt_svid_file`, `linked_file`,
    /// `linked_file_relocate`): the bound path, which the auth setting or
    /// linked-file reference names. The backend reads it only while it is
    /// bound.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

/// Contents of a file read through a grant.
#[derive(Debug)]
pub struct ReadFile {
    pub bytes: Vec<u8>,
    pub file_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GrantError {
    #[error("the file selection is unknown or has expired; choose the file again")]
    Unknown,
    #[error("this file was chosen for a different purpose; choose the file again")]
    WrongPurpose,
    #[error("the chosen file changed after it was selected; choose the file again")]
    Changed,
    #[error("Anvil locked while the file was being chosen; choose the file again")]
    Revoked,
    #[error("{0}")]
    Invalid(String),
    #[error("the file is larger than {0}")]
    TooLarge(String),
    #[error("{0}")]
    Io(String),
}

fn io(err: std::io::Error) -> GrantError {
    GrantError::Io(err.to_string())
}

#[derive(Debug, Clone)]
enum Target {
    Read(Arc<SelectedFile>),
    Write { dir: Arc<SelectedDirectory>, name: OsString },
}

/// The profile and data key that the private-key chooser was shown for.
/// Reopening the same vault preserves its identity; revocation still fences
/// every claim from the earlier session.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Vault {
    dir: PathBuf,
    profile_id: String,
    key_check: String,
}

impl Vault {
    fn of(app: &crate::App) -> Self {
        Self { dir: app.dir.clone(), profile_id: app.header.profile_id.clone(), key_check: app.header.key_check.clone() }
    }
}

#[derive(Debug, Clone)]
struct Entry {
    purpose: FilePurpose,
    /// Required for private-key grants; never supplied by the renderer.
    vault: Option<Vault>,
    target: Target,
    file_name: String,
    issued: Instant,
    /// Issue order, for dropping the oldest grant.
    seq: u64,
}

struct State {
    entries: HashMap<String, Entry>,
    /// Bumped by `revoke_all`. A grant is recorded only while the generation
    /// its choice started in is still current. A private-key claim checks
    /// this again under the same mutex held through its vault commit.
    generation: u64,
}

/// The session's outstanding grants.
pub struct FileGrants {
    state: Mutex<State>,
    next_seq: AtomicU64,
    ttl: Duration,
}

/// A spent private-key grant awaiting its vault write. Its bytes stay native
/// and zeroize on every exit, including abandonment before the write.
pub struct PrivateKeyImport<'a> {
    grants: &'a FileGrants,
    app: &'a crate::App,
    generation: u64,
    bytes: Zeroizing<Vec<u8>>,
}

impl PrivateKeyImport<'_> {
    /// Write only if the claim has not been revoked and the caller's session
    /// gate still allows it. The revocation mutex stays held through the
    /// vault transaction's commit, not just through the generation check.
    pub fn store(self, workspace: &Id, label: &str, gate: impl FnOnce() -> bool) -> crate::Result<SecretRef> {
        let text = std::str::from_utf8(&self.bytes).map_err(|_| crate::AppError::Invalid("the file is not UTF-8 text".into()))?;
        self.app.set_secret_guarded(workspace, label, text, || {
            let state = self.grants.state.lock();
            if state.generation != self.generation || !gate() {
                return None;
            }
            Some(state)
        })
    }
}

impl Default for FileGrants {
    fn default() -> Self {
        FileGrants::new(GRANT_TTL)
    }
}

impl FileGrants {
    pub fn new(ttl: Duration) -> Self {
        FileGrants { state: Mutex::new(State { entries: HashMap::new(), generation: 0 }), next_seq: AtomicU64::new(0), ttl }
    }

    /// The current revocation generation. Take it before showing a dialog and
    /// pass it to the corresponding `grant_*_at` issuer, so that a lock while
    /// the dialog was open grants nothing.
    pub fn generation(&self) -> u64 {
        self.state.lock().generation
    }

    /// Record a file the user picked in the native open dialog for `purpose`.
    pub fn grant_read(&self, purpose: FilePurpose, picked: &Path) -> Result<FileGrant, GrantError> {
        self.grant_read_at(purpose, picked, self.generation())
    }

    /// `grant_read` for a choice that started in `generation`.
    pub fn grant_read_at(&self, purpose: FilePurpose, picked: &Path, generation: u64) -> Result<FileGrant, GrantError> {
        if purpose == FilePurpose::PemPrivateKey {
            return Err(GrantError::WrongPurpose);
        }
        self.grant_read_for(purpose, picked, generation, None)
    }

    /// Record a private-key choice for its issuing vault. The generic read
    /// issuer cannot create unbound private-key grants.
    pub fn grant_private_key(&self, app: &crate::App, picked: &Path) -> Result<FileGrant, GrantError> {
        self.grant_private_key_at(app, picked, self.generation())
    }

    /// A private-key choice whose dialog started in `generation` for `app`.
    pub fn grant_private_key_at(&self, app: &crate::App, picked: &Path, generation: u64) -> Result<FileGrant, GrantError> {
        if app.is_locked() {
            return Err(GrantError::Revoked);
        }
        self.grant_read_for(FilePurpose::PemPrivateKey, picked, generation, Some(Vault::of(app)))
    }

    fn grant_read_for(&self, purpose: FilePurpose, picked: &Path, generation: u64, vault: Option<Vault>) -> Result<FileGrant, GrantError> {
        if purpose.access() != Access::Read {
            return Err(GrantError::WrongPurpose);
        }
        if !picked.is_absolute() {
            return Err(GrantError::Invalid("the chosen file has no absolute path".into()));
        }
        let selected = SelectedFile::choose(picked).map_err(|err| {
            if err.kind() == std::io::ErrorKind::InvalidInput { GrantError::Invalid(err.to_string()) } else { io(err) }
        })?;
        let file_name = display_name(selected.path.file_name());
        self.insert(purpose, Target::Read(Arc::new(selected)), file_name, generation, vault)
    }

    /// Record a destination the user picked in the native save dialog for
    /// `purpose`.
    pub fn grant_write(&self, purpose: FilePurpose, picked: &Path) -> Result<FileGrant, GrantError> {
        self.grant_write_at(purpose, picked, self.generation())
    }

    /// `grant_write` for a choice that started in `generation`.
    pub fn grant_write_at(&self, purpose: FilePurpose, picked: &Path, generation: u64) -> Result<FileGrant, GrantError> {
        if purpose.access() != Access::Write {
            return Err(GrantError::WrongPurpose);
        }
        if !picked.is_absolute() {
            return Err(GrantError::Invalid("the chosen destination has no absolute path".into()));
        }
        let (Some(parent), Some(_)) = (picked.parent(), picked.file_name()) else {
            return Err(GrantError::Invalid("choose a file name, not a folder".into()));
        };
        let canonical = std::fs::canonicalize(parent).map_err(io)?;
        #[cfg(test)]
        crate::file_handles::test_checkpoint("write_choose_canonical");
        let dir = Arc::new(SelectedDirectory::open(&canonical).map_err(io)?);
        let name = SelectedDirectory::leaf(picked).map_err(io)?;
        refuse_directory(&dir, &name)?;
        let file_name = display_name(Some(&name));
        self.insert(purpose, Target::Write { dir, name }, file_name, generation, None)
    }

    /// Read the file behind a readable grant issued for `purpose`. The grant
    /// stays usable until it expires or the app locks. Private-key grants are
    /// refused here and served only by one-shot vault ingestion.
    pub fn read(&self, token: &str, purpose: FilePurpose) -> Result<ReadFile, GrantError> {
        if purpose.access() != Access::Read || purpose == FilePurpose::PemPrivateKey {
            return Err(GrantError::WrongPurpose);
        }
        self.read_file(self.lookup(token, purpose)?, purpose)
    }

    /// Consume a private-key selection and store it in the workspace vault.
    /// The purpose and disposition are fixed here, not supplied by a renderer.
    /// A failed ingestion also spends the grant; a retry needs a fresh choice.
    pub fn import_private_key(&self, app: &crate::App, token: &str, workspace: &Id, label: &str) -> crate::Result<SecretRef> {
        self.claim_private_key(app, token)?.store(workspace, label, || true)
    }

    /// Spend the grant before reading, retaining its issuing vault and claim
    /// generation through the later atomic write. There is no bytes/text
    /// accessor on the returned claim.
    pub fn claim_private_key<'a>(&'a self, app: &'a crate::App, token: &str) -> crate::Result<PrivateKeyImport<'a>> {
        // Taking the grant under its mutex prevents concurrent ingestion or
        // reuse, including after a read or vault write fails.
        let (entry, generation) = self.take(token, FilePurpose::PemPrivateKey).map_err(|err| crate::AppError::Invalid(err.to_string()))?;
        if entry.vault.as_ref() != Some(&Vault::of(app)) {
            return Err(crate::AppError::Invalid("the file selection belongs to a different vault; choose the file again".into()));
        }
        let file = self.read_file(entry, FilePurpose::PemPrivateKey).map_err(|err| crate::AppError::Invalid(err.to_string()))?;
        Ok(PrivateKeyImport { grants: self, app, generation, bytes: Zeroizing::new(file.bytes) })
    }

    fn read_file(&self, entry: Entry, purpose: FilePurpose) -> Result<ReadFile, GrantError> {
        let Target::Read(selected) = entry.target else {
            return Err(GrantError::WrongPurpose);
        };
        let Some((file, meta)) = selected.open().map_err(|_| GrantError::Changed)? else {
            return Err(GrantError::Changed);
        };
        let max = purpose.max_read_bytes();
        if meta.len() > max {
            return Err(GrantError::TooLarge(size_label(max)));
        }
        let mut bytes = Vec::with_capacity(meta.len() as usize);
        // Bounded even if the file grows while it is read.
        file.take(max + 1).read_to_end(&mut bytes).map_err(io)?;
        if bytes.len() as u64 > max {
            return Err(GrantError::TooLarge(size_label(max)));
        }
        if purpose == FilePurpose::PemCertificate {
            let selected = Zeroizing::new(bytes);
            bytes = certificate_pem(&selected)?.into_bytes();
        }
        Ok(ReadFile { bytes, file_name: entry.file_name })
    }

    /// Replace the destination behind a write grant issued for `purpose` with
    /// `bytes`. The grant is spent when the write succeeds; after a failure it
    /// stays usable for a retry, unless the app locked in the meantime.
    pub fn write(&self, token: &str, purpose: FilePurpose, bytes: &[u8]) -> Result<usize, GrantError> {
        if purpose.access() != Access::Write {
            return Err(GrantError::WrongPurpose);
        }
        let (entry, generation) = self.take(token, purpose)?;
        let result = write_target(&entry.target, bytes, purpose.owner_only());
        if result.is_err() {
            let mut g = self.state.lock();
            let retired = if g.generation == generation { self.admit(&mut g, token.to_owned(), entry) } else { Vec::new() };
            drop(g);
            drop(retired);
        }
        result.map(|()| bytes.len())
    }

    /// Drop every grant (on lock); choices still in progress grant nothing.
    pub fn revoke_all(&self) {
        let entries = {
            let mut g = self.state.lock();
            g.generation = g.generation.wrapping_add(1);
            std::mem::take(&mut g.entries)
        };
        drop(entries);
    }

    /// Outstanding, unexpired grants.
    pub fn len(&self) -> usize {
        let mut g = self.state.lock();
        let retired = self.prune(&mut g.entries);
        let len = g.entries.len();
        drop(g);
        drop(retired);
        len
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn insert(
        &self,
        purpose: FilePurpose,
        target: Target,
        file_name: String,
        generation: u64,
        vault: Option<Vault>,
    ) -> Result<FileGrant, GrantError> {
        let token = format!("fg-{}", uuid::Uuid::new_v4().simple());
        let seq = self.next_seq.fetch_add(1, Ordering::Relaxed);
        let mut g = self.state.lock();
        if g.generation != generation {
            return Err(GrantError::Revoked);
        }
        let entry = Entry { purpose, vault, target, file_name: file_name.clone(), issued: Instant::now(), seq };
        let retired = self.admit(&mut g, token.clone(), entry);
        drop(g);
        drop(retired);
        Ok(FileGrant { token, file_name, path: None })
    }

    /// Add a grant, dropping the oldest ones beyond `MAX_GRANTS`.
    fn admit(&self, g: &mut State, token: String, entry: Entry) -> Vec<Entry> {
        let mut retired = self.prune(&mut g.entries);
        retired.extend(g.entries.insert(token, entry));
        while g.entries.len() > MAX_GRANTS {
            let Some(oldest) = g.entries.iter().min_by_key(|(_, e)| e.seq).map(|(k, _)| k.clone()) else { break };
            retired.extend(g.entries.remove(&oldest));
        }
        retired
    }

    // Return retired handles so callers close them after releasing the mutex.
    fn prune(&self, entries: &mut HashMap<String, Entry>) -> Vec<Entry> {
        entries.extract_if(|_, e| e.issued.elapsed() >= self.ttl).map(|(_, entry)| entry).collect()
    }

    fn lookup(&self, token: &str, purpose: FilePurpose) -> Result<Entry, GrantError> {
        let mut g = self.state.lock();
        let mut retired = self.prune(&mut g.entries);
        let result = match g.entries.get(token) {
            None => Err(GrantError::Unknown),
            Some(entry) if entry.purpose == purpose => Ok(entry.clone()),
            Some(_) => {
                // Presenting a grant to the wrong command revokes it.
                retired.extend(g.entries.remove(token));
                Err(GrantError::WrongPurpose)
            }
        };
        drop(g);
        drop(retired);
        result
    }

    /// Remove a grant for use, with the generation it was taken in.
    fn take(&self, token: &str, purpose: FilePurpose) -> Result<(Entry, u64), GrantError> {
        let mut g = self.state.lock();
        let mut retired = self.prune(&mut g.entries);
        let result = match g.entries.remove(token) {
            None => Err(GrantError::Unknown),
            Some(entry) if entry.purpose == purpose => Ok((entry, g.generation)),
            Some(entry) => {
                retired.push(entry);
                Err(GrantError::WrongPurpose)
            }
        };
        drop(g);
        drop(retired);
        result
    }
}

/// Return only complete certificate blocks, never comments or other PEM
/// material. Validate the DER as certificates too: changing a private key's
/// PEM label to CERTIFICATE must not make it readable by the renderer.
fn certificate_pem(bytes: &[u8]) -> Result<String, GrantError> {
    let invalid = || GrantError::Invalid("choose a certificate-only PEM file; private keys stay in the vault".into());
    let text = std::str::from_utf8(bytes).map_err(|_| invalid())?;
    let mut pem = String::new();
    let mut in_certificate = false;
    let mut certificates = 0;
    for line in text.lines() {
        let line = line.trim().trim_start_matches('\u{feff}');
        match line {
            "-----BEGIN CERTIFICATE-----" if !in_certificate => {
                in_certificate = true;
            }
            "-----END CERTIFICATE-----" if in_certificate => {
                in_certificate = false;
                certificates += 1;
                pem.push_str(line);
                pem.push('\n');
                continue;
            }
            _ if line.contains("-----BEGIN") || line.contains("-----END") => return Err(invalid()),
            _ if !in_certificate => continue,
            _ => {}
        }
        pem.push_str(line);
        pem.push('\n');
    }
    if in_certificate || certificates == 0 {
        return Err(invalid());
    }
    // Reuse the transport's certificate DER validation without system roots,
    // a client identity, or any network access. Do not expose parser errors
    // that could quote untrusted file contents.
    let settings = anvil_transport::tls::TlsSettings { extra_roots_pem: vec![pem.clone()], ..Default::default() };
    anvil_transport::tls::prepare(&settings).map_err(|_| invalid())?;
    Ok(pem)
}

/// Publish only to an unoccupied leaf. A regular-file/owner check followed by
/// replacing rename cannot exclude a raced replacement on POSIX. This draft
/// refuses overwrites rather than unlinking a different object.
fn write_target(target: &Target, bytes: &[u8], owner_only: bool) -> Result<(), GrantError> {
    use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt};
    use cap_std::fs::OpenOptions;

    let Target::Write { dir, name } = target else {
        return Err(GrantError::WrongPurpose);
    };
    #[cfg(test)]
    crate::file_handles::test_checkpoint("write_selected");
    refuse_occupied(dir, name)?;
    let tmp = OsString::from(format!(".anvil-{}.partial", uuid::Uuid::new_v4().simple()));
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true).follow(FollowSymlinks::No);
    #[cfg(unix)]
    if owner_only {
        use cap_std::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    #[cfg(not(unix))]
    let _ = owner_only;
    let mut file = dir.dir().open_with(&tmp, &options).map_err(io)?.into_std();
    let meta = file.metadata().map_err(io)?;
    if !meta.is_file() || !no_reparse(&meta) {
        return Err(GrantError::Changed);
    }
    let id = file_id(&file, &meta).map_err(io)?;
    // Never remove a temporary pathname on failure: its name may already
    // belong to somebody else. Leaking our partial is preferable to unlinking
    // a foreign replacement. The same rule applies after publication.
    file.write_all(bytes).map_err(io)?;
    file.sync_all().map_err(io)?;
    #[cfg(test)]
    crate::file_handles::test_checkpoint("write_synced");
    let Some((check, meta)) = open_regular_at(dir.dir(), &tmp).map_err(io)? else {
        return Err(GrantError::Changed);
    };
    if file_id(&check, &meta).map_err(io)? != id {
        return Err(GrantError::Changed);
    }
    #[cfg(test)]
    crate::file_handles::test_checkpoint("write_verified");
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    rustix::fs::renameat_with(dir.dir(), &tmp, dir.dir(), name, rustix::fs::RenameFlags::NOREPLACE).map_err(|err| io(err.into()))?;
    #[cfg(windows)]
    {
        // cap-std 4.0.3 has no no-replace rename on Windows. Hard-link
        // publication never removes an occupied destination. The partial is
        // deliberately retained. This is an explicit qualification blocker,
        // not a claim of handle-relative atomic rename on Windows.
        dir.dir().hard_link(&tmp, dir.dir(), name).map_err(io)?;
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    return Err(GrantError::Invalid("export publication is unsupported on this platform".into()));
    let Some((published, meta)) = open_regular_at(dir.dir(), name).map_err(io)? else {
        return Err(GrantError::Changed);
    };
    if file_id(&published, &meta).map_err(io)? != id {
        return Err(GrantError::Changed);
    }
    Ok(())
}

fn refuse_directory(dir: &SelectedDirectory, name: &std::ffi::OsStr) -> Result<(), GrantError> {
    match dir.dir().symlink_metadata(name) {
        Ok(meta) if meta.is_dir() => Err(GrantError::Invalid("the destination is a folder".into())),
        Ok(_) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(io(err)),
    }
}

fn refuse_occupied(dir: &SelectedDirectory, name: &std::ffi::OsStr) -> Result<(), GrantError> {
    refuse_directory(dir, name)?;
    match dir.dir().symlink_metadata(name) {
        Ok(_) => Err(GrantError::Invalid("the destination already exists; choose an unused file name".into())),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(io(err)),
    }
}

fn display_name(name: Option<&std::ffi::OsStr>) -> String {
    name.map(|n| n.to_string_lossy().into_owned()).filter(|n| !n.is_empty()).unwrap_or_else(|| "file".into())
}

fn size_label(bytes: u64) -> String {
    const GIB: u64 = 1024 * 1024 * 1024;
    if bytes.is_multiple_of(GIB) { format!("{} GiB", bytes / GIB) } else { format!("{} MiB", bytes >> 20) }
}
