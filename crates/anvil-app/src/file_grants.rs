//! Native-dialog file grants for the desktop shell.
//!
//! The webview never names a file on disk. The backend shows the native
//! open/save dialog itself, records what the user picked here and hands the
//! webview an opaque, unguessable token bound to one purpose. File commands
//! accept only such a token, so the renderer reaches exactly the files the
//! user chose for that purpose in this session, and nothing else.
//!
//! - A read grant pins the canonical path (and the file's identity)
//!   at selection time; if the file or a folder on its path is replaced
//!   afterwards, the read is refused.
//! - A write grant pins the canonical folder and the chosen file name. Data
//!   goes to a newly created temporary file in that folder (never through an
//!   existing file or link) that is then renamed over the chosen name. A
//!   successful write spends the grant.
//! - Grants expire, are bounded in number and are all revoked on lock. A
//!   choice that was still in progress when the app locked grants nothing.
//!
//! A JWT-SVID token file (`jwt_svid_file`) is different: it is re-read at
//! every send, so the choice is kept as a persistent binding in the vault
//! (`anvil_app::token_files`) rather than as a session grant. So is a linked
//! local file a saved request or dataset names (`linked_file`,
//! `anvil_app::linked_files`).

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::ffi::OsString;
use std::fs::{File, Metadata, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

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
    /// Read a PEM certificate or key.
    PemFile,
    /// Read a PKCS#12 keystore (carried as base64).
    Pkcs12File,
    /// Read an API spec or collection to import.
    SpecSource,
    /// Read a CSV/JSON load-test dataset.
    Dataset,
    /// Write an Anvil bundle or backup.
    BundleExport,
    /// Write a load-test report.
    LoadReportExport,
    /// Write a collection-run report.
    RunReportExport,
    /// Bind a JWT-SVID token file that the backend reads at send time.
    JwtSvidFile,
    /// Bind a linked local file that a saved request or dataset names, so
    /// the backend may read it at send time.
    LinkedFile,
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
            FilePurpose::BundleExport | FilePurpose::LoadReportExport | FilePurpose::RunReportExport => Access::Write,
            FilePurpose::BundleImport
            | FilePurpose::Attachment
            | FilePurpose::PemFile
            | FilePurpose::Pkcs12File
            | FilePurpose::SpecSource
            | FilePurpose::Dataset => Access::Read,
            FilePurpose::JwtSvidFile | FilePurpose::LinkedFile => Access::Bind,
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
            FilePurpose::PemFile | FilePurpose::Pkcs12File => MIB,
            FilePurpose::SpecSource => 32 * MIB,
            FilePurpose::Dataset => 64 * MIB,
            FilePurpose::BundleExport
            | FilePurpose::LoadReportExport
            | FilePurpose::RunReportExport
            | FilePurpose::JwtSvidFile
            | FilePurpose::LinkedFile => 0,
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
    /// Only for a bound file (`jwt_svid_file`, `linked_file`): the bound
    /// path, which the auth setting or linked-file reference names. The
    /// backend reads it only while it is bound.
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

/// Identifies the file a path named when it was chosen, so a replacement
/// under the same name is noticed: device and inode on Unix, volume serial
/// number and file index on Windows.
type FileId = (u64, u64);

#[cfg(unix)]
fn file_id(_file: &File, meta: &Metadata) -> std::io::Result<FileId> {
    use std::os::unix::fs::MetadataExt;
    Ok((meta.dev(), meta.ino()))
}

#[cfg(windows)]
fn file_id(file: &File, _meta: &Metadata) -> std::io::Result<FileId> {
    let info = winapi_util::file::information(file)?;
    Ok((info.volume_serial_number(), info.file_index()))
}

#[cfg(not(any(unix, windows)))]
fn file_id(_file: &File, _meta: &Metadata) -> std::io::Result<FileId> {
    Ok((0, 0))
}

#[derive(Debug, Clone)]
enum Target {
    Read { path: PathBuf, id: FileId },
    Write { dir: PathBuf, name: OsString },
}

#[derive(Debug, Clone)]
struct Entry {
    purpose: FilePurpose,
    target: Target,
    file_name: String,
    issued: Instant,
    /// Issue order, for dropping the oldest grant.
    seq: u64,
}

struct State {
    entries: HashMap<String, Entry>,
    /// Bumped by `revoke_all`. A grant is recorded only while the generation
    /// its choice started in is still current.
    generation: u64,
}

/// The session's outstanding grants.
pub struct FileGrants {
    state: Mutex<State>,
    next_seq: AtomicU64,
    ttl: Duration,
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
    /// pass it to `grant_read_at`/`grant_write_at`, so that a lock while the
    /// dialog was open grants nothing.
    pub fn generation(&self) -> u64 {
        self.state.lock().generation
    }

    /// Record a file the user picked in the native open dialog for `purpose`.
    pub fn grant_read(&self, purpose: FilePurpose, picked: &Path) -> Result<FileGrant, GrantError> {
        self.grant_read_at(purpose, picked, self.generation())
    }

    /// `grant_read` for a choice that started in `generation`.
    pub fn grant_read_at(&self, purpose: FilePurpose, picked: &Path, generation: u64) -> Result<FileGrant, GrantError> {
        if purpose.access() != Access::Read {
            return Err(GrantError::WrongPurpose);
        }
        if !picked.is_absolute() {
            return Err(GrantError::Invalid("the chosen file has no absolute path".into()));
        }
        let path = std::fs::canonicalize(picked).map_err(io)?;
        // Checked before opening, so a FIFO or device is never opened.
        if !std::fs::metadata(&path).map_err(io)?.is_file() {
            return Err(GrantError::Invalid("not a regular file".into()));
        }
        let file = File::open(&path).map_err(io)?;
        let meta = file.metadata().map_err(io)?;
        if !meta.is_file() {
            return Err(GrantError::Invalid("not a regular file".into()));
        }
        let id = file_id(&file, &meta).map_err(io)?;
        let file_name = display_name(path.file_name());
        self.insert(purpose, Target::Read { id, path }, file_name, generation)
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
        let (Some(parent), Some(name)) = (picked.parent(), picked.file_name()) else {
            return Err(GrantError::Invalid("choose a file name, not a folder".into()));
        };
        let dir = std::fs::canonicalize(parent).map_err(io)?;
        if !std::fs::metadata(&dir).map_err(io)?.is_dir() {
            return Err(GrantError::Invalid("the destination folder is not a folder".into()));
        }
        refuse_directory(&dir.join(name))?;
        let file_name = display_name(Some(name));
        self.insert(purpose, Target::Write { dir, name: name.to_owned() }, file_name, generation)
    }

    /// Read the file behind a read grant issued for `purpose`. The grant stays
    /// usable (preview then apply read the same file) until it expires or the
    /// app locks.
    pub fn read(&self, token: &str, purpose: FilePurpose) -> Result<ReadFile, GrantError> {
        if purpose.access() != Access::Read {
            return Err(GrantError::WrongPurpose);
        }
        let entry = self.lookup(token, purpose)?;
        let Target::Read { path, id } = entry.target else {
            return Err(GrantError::WrongPurpose);
        };
        // A folder on the path (or the file itself) swapped for a link now
        // resolves somewhere else; anything but a regular file is not opened.
        if std::fs::canonicalize(&path).map_err(io)? != path || !std::fs::metadata(&path).map_err(io)?.is_file() {
            return Err(GrantError::Changed);
        }
        let file = File::open(&path).map_err(io)?;
        let meta = file.metadata().map_err(io)?;
        if !meta.is_file() || file_id(&file, &meta).map_err(io)? != id {
            return Err(GrantError::Changed);
        }
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
            if g.generation == generation {
                self.admit(&mut g, token.to_owned(), entry);
            }
        }
        result.map(|()| bytes.len())
    }

    /// Drop every grant (on lock); choices still in progress grant nothing.
    pub fn revoke_all(&self) {
        let mut g = self.state.lock();
        g.entries.clear();
        g.generation = g.generation.wrapping_add(1);
    }

    /// Outstanding, unexpired grants.
    pub fn len(&self) -> usize {
        let mut g = self.state.lock();
        self.prune(&mut g.entries);
        g.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn insert(&self, purpose: FilePurpose, target: Target, file_name: String, generation: u64) -> Result<FileGrant, GrantError> {
        let token = format!("fg-{}", uuid::Uuid::new_v4().simple());
        let seq = self.next_seq.fetch_add(1, Ordering::Relaxed);
        let mut g = self.state.lock();
        if g.generation != generation {
            return Err(GrantError::Revoked);
        }
        let entry = Entry { purpose, target, file_name: file_name.clone(), issued: Instant::now(), seq };
        self.admit(&mut g, token.clone(), entry);
        Ok(FileGrant { token, file_name, path: None })
    }

    /// Add a grant, dropping the oldest ones beyond `MAX_GRANTS`.
    fn admit(&self, g: &mut State, token: String, entry: Entry) {
        self.prune(&mut g.entries);
        g.entries.insert(token, entry);
        while g.entries.len() > MAX_GRANTS {
            let Some(oldest) = g.entries.iter().min_by_key(|(_, e)| e.seq).map(|(k, _)| k.clone()) else { break };
            g.entries.remove(&oldest);
        }
    }

    fn prune(&self, entries: &mut HashMap<String, Entry>) {
        entries.retain(|_, e| e.issued.elapsed() < self.ttl);
    }

    fn lookup(&self, token: &str, purpose: FilePurpose) -> Result<Entry, GrantError> {
        let mut g = self.state.lock();
        self.prune(&mut g.entries);
        let entry = g.entries.get(token).cloned().ok_or(GrantError::Unknown)?;
        if entry.purpose != purpose {
            // Presenting a grant to the wrong command revokes it.
            g.entries.remove(token);
            return Err(GrantError::WrongPurpose);
        }
        Ok(entry)
    }

    /// Remove a grant for use, with the generation it was taken in.
    fn take(&self, token: &str, purpose: FilePurpose) -> Result<(Entry, u64), GrantError> {
        let mut g = self.state.lock();
        self.prune(&mut g.entries);
        let entry = g.entries.remove(token).ok_or(GrantError::Unknown)?;
        if entry.purpose != purpose {
            return Err(GrantError::WrongPurpose);
        }
        Ok((entry, g.generation))
    }
}

fn write_target(target: &Target, bytes: &[u8], owner_only: bool) -> Result<(), GrantError> {
    let Target::Write { dir, name } = target else {
        return Err(GrantError::WrongPurpose);
    };
    // The folder itself (or one above it) swapped for a link now resolves
    // somewhere else.
    if std::fs::canonicalize(dir).map_err(io)? != *dir {
        return Err(GrantError::Changed);
    }
    let dest = dir.join(name);
    refuse_directory(&dest)?;
    // A fresh, exclusively created file: an existing file or link under the
    // temporary name is never opened or followed.
    let tmp = dir.join(format!(".anvil-{}.partial", uuid::Uuid::new_v4().simple()));
    // Renaming replaces the destination entry itself; a link there is
    // replaced, not followed.
    match write_new(&tmp, bytes, owner_only).and_then(|()| std::fs::rename(&tmp, &dest)) {
        Ok(()) => Ok(()),
        Err(err) => {
            let _ = std::fs::remove_file(&tmp);
            Err(io(err))
        }
    }
}

fn write_new(path: &Path, bytes: &[u8], owner_only: bool) -> std::io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    if owner_only {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    #[cfg(not(unix))]
    let _ = owner_only;
    let mut f = options.open(path)?;
    f.write_all(bytes)?;
    f.sync_all()
}

fn refuse_directory(dest: &Path) -> Result<(), GrantError> {
    match std::fs::symlink_metadata(dest) {
        Ok(m) if m.is_dir() => Err(GrantError::Invalid("the destination is a folder".into())),
        _ => Ok(()),
    }
}

fn display_name(name: Option<&std::ffi::OsStr>) -> String {
    name.map(|n| n.to_string_lossy().into_owned()).filter(|n| !n.is_empty()).unwrap_or_else(|| "file".into())
}

fn size_label(bytes: u64) -> String {
    const GIB: u64 = 1024 * 1024 * 1024;
    if bytes.is_multiple_of(GIB) { format!("{} GiB", bytes / GIB) } else { format!("{} MiB", bytes >> 20) }
}
