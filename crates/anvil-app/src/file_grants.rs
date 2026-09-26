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
//! - Grants expire, are bounded in number and are all revoked on lock.

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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    Read,
    Write,
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
        }
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
            FilePurpose::BundleExport | FilePurpose::LoadReportExport | FilePurpose::RunReportExport => 0,
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
/// under the same name is noticed: device and inode on Unix, the creation
/// time on Windows.
type FileId = (u64, u64);

#[cfg(unix)]
fn file_id(meta: &Metadata) -> FileId {
    use std::os::unix::fs::MetadataExt;
    (meta.dev(), meta.ino())
}

#[cfg(windows)]
fn file_id(meta: &Metadata) -> FileId {
    use std::os::windows::fs::MetadataExt;
    (meta.creation_time(), 0)
}

#[cfg(not(any(unix, windows)))]
fn file_id(_meta: &Metadata) -> FileId {
    (0, 0)
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

/// The session's outstanding grants.
pub struct FileGrants {
    entries: Mutex<HashMap<String, Entry>>,
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
        FileGrants { entries: Mutex::new(HashMap::new()), next_seq: AtomicU64::new(0), ttl }
    }

    /// Record a file the user picked in the native open dialog for `purpose`.
    pub fn grant_read(&self, purpose: FilePurpose, picked: &Path) -> Result<FileGrant, GrantError> {
        if purpose.access() != Access::Read {
            return Err(GrantError::WrongPurpose);
        }
        if !picked.is_absolute() {
            return Err(GrantError::Invalid("the chosen file has no absolute path".into()));
        }
        let path = std::fs::canonicalize(picked).map_err(io)?;
        let meta = std::fs::metadata(&path).map_err(io)?;
        if !meta.is_file() {
            return Err(GrantError::Invalid("not a regular file".into()));
        }
        let file_name = display_name(path.file_name());
        Ok(self.insert(purpose, Target::Read { id: file_id(&meta), path }, file_name))
    }

    /// Record a destination the user picked in the native save dialog for
    /// `purpose`.
    pub fn grant_write(&self, purpose: FilePurpose, picked: &Path) -> Result<FileGrant, GrantError> {
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
        Ok(self.insert(purpose, Target::Write { dir, name: name.to_owned() }, file_name))
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
        if !meta.is_file() || file_id(&meta) != id {
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
    /// stays usable for a retry.
    pub fn write(&self, token: &str, purpose: FilePurpose, bytes: &[u8]) -> Result<usize, GrantError> {
        if purpose.access() != Access::Write {
            return Err(GrantError::WrongPurpose);
        }
        let entry = self.take(token, purpose)?;
        let result = write_target(&entry.target, bytes);
        if result.is_err() {
            self.entries.lock().insert(token.to_owned(), entry);
        }
        result.map(|()| bytes.len())
    }

    /// Drop every grant (on lock).
    pub fn revoke_all(&self) {
        self.entries.lock().clear();
    }

    /// Outstanding, unexpired grants.
    pub fn len(&self) -> usize {
        let mut g = self.entries.lock();
        self.prune(&mut g);
        g.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn insert(&self, purpose: FilePurpose, target: Target, file_name: String) -> FileGrant {
        let token = format!("fg-{}", uuid::Uuid::new_v4().simple());
        let seq = self.next_seq.fetch_add(1, Ordering::Relaxed);
        let mut g = self.entries.lock();
        self.prune(&mut g);
        while g.len() >= MAX_GRANTS {
            let Some(oldest) = g.iter().min_by_key(|(_, e)| e.seq).map(|(k, _)| k.clone()) else { break };
            g.remove(&oldest);
        }
        g.insert(token.clone(), Entry { purpose, target, file_name: file_name.clone(), issued: Instant::now(), seq });
        FileGrant { token, file_name }
    }

    fn prune(&self, g: &mut HashMap<String, Entry>) {
        g.retain(|_, e| e.issued.elapsed() < self.ttl);
    }

    fn lookup(&self, token: &str, purpose: FilePurpose) -> Result<Entry, GrantError> {
        let mut g = self.entries.lock();
        self.prune(&mut g);
        let entry = g.get(token).cloned().ok_or(GrantError::Unknown)?;
        if entry.purpose != purpose {
            // Presenting a grant to the wrong command revokes it.
            g.remove(token);
            return Err(GrantError::WrongPurpose);
        }
        Ok(entry)
    }

    fn take(&self, token: &str, purpose: FilePurpose) -> Result<Entry, GrantError> {
        let mut g = self.entries.lock();
        self.prune(&mut g);
        let entry = g.remove(token).ok_or(GrantError::Unknown)?;
        if entry.purpose != purpose {
            return Err(GrantError::WrongPurpose);
        }
        Ok(entry)
    }
}

fn write_target(target: &Target, bytes: &[u8]) -> Result<(), GrantError> {
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
    match write_new(&tmp, bytes).and_then(|()| std::fs::rename(&tmp, &dest)) {
        Ok(()) => Ok(()),
        Err(err) => {
            let _ = std::fs::remove_file(&tmp);
            Err(io(err))
        }
    }
}

fn write_new(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut f = OpenOptions::new().write(true).create_new(true).open(path)?;
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
