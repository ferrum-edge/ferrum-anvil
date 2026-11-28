//! Chosen files and folders reached without following a link anywhere on
//! their path.
//!
//! A chosen path is canonical when it is recorded, and is checked to still
//! resolve to itself just before it is used. That check alone leaves a
//! window: a folder on the path renamed and replaced by a link in between
//! would send the open, create or rename that follows somewhere else. So the
//! path is walked here one folder at a time from the root, and a link at any
//! of them (on Windows also a junction or another reparse point that
//! redirects the path) is refused, never followed:
//!
//! - On Unix each folder is opened relative to the one above it, without
//!   following a link (`O_NOFOLLOW | O_DIRECTORY`). The file is then opened,
//!   created, renamed or removed relative to the opened folder (`openat`,
//!   `renameat`, `unlinkat`), so its path is never resolved again.
//! - On macOS (and Apple's other systems) a single open refuses a link at any
//!   folder on the path, and at the file itself (`O_NOFOLLOW_ANY`, macOS 11
//!   and later), so no folder above is opened: a protected folder such as
//!   Documents, Desktop or a removable volume above a chosen file is never
//!   opened for listing, which would need access to that whole folder. A file
//!   read opens the file directly; an export opens only its folder and then
//!   works relative to it as above.
//! - On Windows each folder is opened in turn as itself
//!   (`FILE_FLAG_OPEN_REPARSE_POINT`), checked not to be a link, and held open
//!   without delete sharing until the operation is done: a held folder cannot
//!   be renamed, removed or replaced, so the path, resolved again below it,
//!   still leads where it was walked. A file read is held the same way while
//!   it is opened. A folder or file that another program holds open with
//!   delete access cannot be held, and the operation fails.
//! - Elsewhere the path is used as it is.
//!
//! Each folder on the path must be one Anvil can open: on Windows and on Unix
//! other than Linux and macOS, one it can list.

use crate::file_grants::{FileId, file_id};
use std::ffi::{OsStr, OsString};
use std::fs::{File, Metadata};
use std::io;
#[cfg(any(unix, windows))]
use std::path::Component;
use std::path::Path;
#[cfg(not(unix))]
use std::path::PathBuf;

/// A folder reached from the root without following a link.
pub(crate) struct Dir {
    /// The opened folder; everything below is resolved relative to it.
    #[cfg(unix)]
    fd: File,
    /// The folder's path. Everything below is resolved by path again, while
    /// `held` keeps it leading to the folder walked.
    #[cfg(not(unix))]
    path: PathBuf,
    /// Every folder on the path from the root, the folder itself last, held
    /// open so none can be renamed, removed or replaced until this is dropped.
    #[cfg(windows)]
    held: Vec<File>,
}

/// A staged temporary file inside a [`Dir`]. On macOS, owner-only files are
/// created inside a freshly created `0o700` ACL-cleared private staging
/// directory so the file is born with mode `0o600` and zero ACL entries
/// (eliminating any inheritance TOCTOU window before publish).
pub(crate) enum StagedFile {
    Direct(OsString),
    #[cfg(target_vendor = "apple")]
    ApplePrivateDir {
        dir_name: OsString,
        dir_fd: File,
        file_name: OsString,
    },
}

/// Reserved advisory lock filename inside an export output directory.
pub(crate) const EXPORT_LOCK_NAME: &str = ".anvil-export.lock";

/// A backup of a pre-existing regular file inside a [`Dir`], used to roll back
/// a sidecar replacement if the companion test plan fails to publish.
pub(crate) struct ExistingBackup {
    name: OsString,
    moved: bool,
    original_id: FileId,
}

impl ExistingBackup {
    pub(crate) fn name(&self) -> &OsStr {
        &self.name
    }

    pub(crate) fn into_name(self) -> OsString {
        self.name
    }

    pub(crate) fn is_moved(&self) -> bool {
        self.moved
    }
}

/// Outcome of an ownership-verified rollback of a published sibling file.
pub(crate) enum RollbackOutcome {
    /// Ownership matched the live staged handle and the file was safely removed
    /// or restored from its backup without clobbering any concurrent entry.
    Restored,
    /// Ownership did not match (or atomic quarantine was unavailable), so
    /// rollback was skipped; any backup was preserved on disk. If a swapped
    /// entry could not be moved back out of quarantine without clobbering a
    /// newer file, `quarantine_left` carries its filename and error for recovery.
    Skipped { backup_name: Option<OsString>, quarantine_left: Option<(OsString, io::Error)> },
    /// Ownership matched and our published entry was removed, but restoring the
    /// previous backup via no-clobber rename failed; the backup was preserved.
    Failed { backup_name: OsString, err: io::Error },
}

fn not_absolute() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "the path is not absolute and normalized")
}

/// Open the absolute, normalized `path` for reading if it is a regular file;
/// `None` when it is not, a link at it or at a folder on it included. A FIFO
/// or device never blocks the open: it is opened non-blocking (which does not
/// change how a regular file reads) and never as a controlling terminal, and
/// the opened handle is checked.
#[cfg(target_vendor = "apple")]
pub(crate) fn open_regular(path: &Path) -> io::Result<Option<(File, Metadata)>> {
    use rustix::fs::{Mode, OFlags};
    if !is_normalized(path) {
        return Err(not_absolute());
    }
    let flags = OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::NOFOLLOW_ANY | OFlags::CLOEXEC;
    regular(rustix::fs::open(path, flags, Mode::empty()))
}

/// Open the absolute, normalized `path` for reading if it is a regular file;
/// `None` when it is not, a link at it or at a folder on it included
/// ([`Dir::open_regular`]).
#[cfg(not(target_vendor = "apple"))]
pub(crate) fn open_regular(path: &Path) -> io::Result<Option<(File, Metadata)>> {
    let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
        return Ok(None);
    };
    let Some(dir) = Dir::open(parent)? else {
        return Ok(None);
    };
    dir.open_regular(name)
}

/// Whether `path` is the root followed only by folder and file names.
#[cfg(target_vendor = "apple")]
fn is_normalized(path: &Path) -> bool {
    let mut components = path.components();
    components.next() == Some(Component::RootDir) && components.all(|c| matches!(c, Component::Normal(_)))
}

#[cfg(unix)]
impl Dir {
    /// Open the folder at the absolute, normalized `path`; `None` when a
    /// folder on it (or the folder itself) is a link or not a folder. Only
    /// the folder itself is opened.
    #[cfg(target_vendor = "apple")]
    pub(crate) fn open(path: &Path) -> io::Result<Option<Dir>> {
        use rustix::fs::{Mode, OFlags};
        if !is_normalized(path) {
            return Err(not_absolute());
        }
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW_ANY | OFlags::CLOEXEC;
        let fd = match rustix::fs::open(path, flags, Mode::empty()) {
            Ok(fd) => File::from(fd),
            Err(e) if is_link(e) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        // The check that counts is on the opened handle.
        if !fd.metadata()?.is_dir() {
            return Ok(None);
        }
        Ok(Some(Dir { fd }))
    }

    /// Open the folder at the absolute, normalized `path`; `None` when a
    /// folder on it (or the folder itself) is a link or not a folder.
    #[cfg(not(target_vendor = "apple"))]
    pub(crate) fn open(path: &Path) -> io::Result<Option<Dir>> {
        use rustix::fs::{Mode, OFlags};
        // Opening a folder only to walk below it needs no permission to list
        // it where the platform allows that.
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let access = OFlags::PATH;
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        let access = OFlags::RDONLY;
        let flags = access | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let mut dir: Option<File> = None;
        for component in path.components() {
            let opened = match (component, &dir) {
                (Component::RootDir, None) => rustix::fs::open("/", flags, Mode::empty()),
                (Component::Normal(name), Some(parent)) => rustix::fs::openat(parent, name, flags, Mode::empty()),
                _ => return Err(not_absolute()),
            };
            let next = match opened {
                Ok(fd) => File::from(fd),
                Err(e) if is_link(e) => return Ok(None),
                Err(e) => return Err(e.into()),
            };
            // The check that counts is on the opened handle.
            if !next.metadata()?.is_dir() {
                return Ok(None);
            }
            dir = Some(next);
        }
        let fd = dir.ok_or_else(not_absolute)?;
        Ok(Some(Dir { fd }))
    }

    /// The folder's identity (device and inode).
    pub(crate) fn id(&self) -> io::Result<FileId> {
        file_id(&self.fd, &self.fd.metadata()?)
    }

    /// Open `name` in this folder for reading if it is a regular file; `None`
    /// when it is not, a link included. A FIFO or device never blocks the
    /// open: it is opened non-blocking (which does not change how a regular
    /// file reads) and never as a controlling terminal, and the opened handle
    /// is checked.
    #[cfg(not(target_vendor = "apple"))]
    pub(crate) fn open_regular(&self, name: &OsStr) -> io::Result<Option<(File, Metadata)>> {
        use rustix::fs::{Mode, OFlags};
        let flags = OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        regular(rustix::fs::openat(&self.fd, name, flags, Mode::empty()))
    }

    /// Create `name` in this folder for writing. Anything already there under
    /// that name, a link included, makes it fail: nothing existing is opened
    /// or followed. When `owner_only` is true, enforces `0o600` on the open
    /// descriptor, clears any inherited macOS extended ACL, and verifies
    /// effective owner-only permissions before returning (failing closed and
    /// unlinking the newly created file if privacy cannot be established).
    pub(crate) fn create_new(&self, name: &OsStr, owner_only: bool) -> io::Result<File> {
        use rustix::fs::{Mode, OFlags};
        let flags = OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let mode = Mode::from_raw_mode(if owner_only { 0o600 } else { 0o666 });
        let file = File::from(rustix::fs::openat(&self.fd, name, flags, mode)?);
        if owner_only && let Err(err) = enforce_owner_only(&file) {
            drop(file);
            let _ = self.remove_file(name);
            return Err(err);
        }
        Ok(file)
    }

    /// Rename `from` to `to` within this folder. A link at `to` is replaced,
    /// not followed.
    pub(crate) fn rename(&self, from: &OsStr, to: &OsStr) -> io::Result<()> {
        Ok(rustix::fs::renameat(&self.fd, from, &self.fd, to)?)
    }

    /// Atomically publish `from` at `to` within this folder only if `to` does
    /// not already exist (a file, folder, or symlink, even dangling, fails
    /// with `AlreadyExists` without clobbering it). Uses an atomic exclusive
    /// rename (`RENAME_NOREPLACE` / `RENAME_EXCL`) where supported so FAT32 and
    /// exFAT volumes without hard links work, falling back to `linkat` +
    /// `unlinkat` only when the filesystem or OS lacks exclusive rename.
    pub(crate) fn publish_no_clobber(&self, from: &OsStr, to: &OsStr) -> io::Result<()> {
        rename_no_clobber(&self.fd, from, &self.fd, to)
    }

    pub(crate) fn remove_file(&self, name: &OsStr) -> io::Result<()> {
        Ok(rustix::fs::unlinkat(&self.fd, name, rustix::fs::AtFlags::empty())?)
    }

    /// Stage a new temporary file inside this folder. On macOS, when
    /// `owner_only` is true, creates an empty `0o700` private subdirectory,
    /// strips and verifies zero extended ACL entries on that empty directory,
    /// and creates the `0o600` file inside it so the file never inherits a
    /// parent ACL even momentarily before `publish_staged_no_clobber` or
    /// `rename_staged`.
    pub(crate) fn stage_new(&self, owner_only: bool) -> io::Result<(File, StagedFile)> {
        #[cfg(target_vendor = "apple")]
        if owner_only {
            use rustix::fs::{AtFlags, Mode, OFlags};
            let dir_name = OsString::from(format!(".anvil-stage-{}", uuid::Uuid::new_v4().simple()));
            rustix::fs::mkdirat(&self.fd, &dir_name, Mode::from_raw_mode(0o700))?;
            let dir_flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
            let dir_fd = match rustix::fs::openat(&self.fd, &dir_name, dir_flags, Mode::empty()) {
                Ok(fd) => File::from(fd),
                Err(err) => {
                    let _ = rustix::fs::unlinkat(&self.fd, &dir_name, AtFlags::REMOVEDIR);
                    return Err(err.into());
                }
            };
            if let Err(err) = enforce_owner_only_mode(&dir_fd, 0o700) {
                drop(dir_fd);
                let _ = rustix::fs::unlinkat(&self.fd, &dir_name, AtFlags::REMOVEDIR);
                return Err(err);
            }
            let file_name = OsString::from("staged");
            let file_flags = OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
            let file = match rustix::fs::openat(&dir_fd, &file_name, file_flags, Mode::from_raw_mode(0o600)) {
                Ok(fd) => File::from(fd),
                Err(err) => {
                    drop(dir_fd);
                    let _ = rustix::fs::unlinkat(&self.fd, &dir_name, AtFlags::REMOVEDIR);
                    return Err(err.into());
                }
            };
            if let Err(err) = enforce_owner_only_mode(&file, 0o600) {
                drop(file);
                let _ = rustix::fs::unlinkat(&dir_fd, &file_name, AtFlags::empty());
                drop(dir_fd);
                let _ = rustix::fs::unlinkat(&self.fd, &dir_name, AtFlags::REMOVEDIR);
                return Err(err);
            }
            return Ok((file, StagedFile::ApplePrivateDir { dir_name, dir_fd, file_name }));
        }
        let tmp = OsString::from(format!(".anvil-{}.partial", uuid::Uuid::new_v4().simple()));
        let file = self.create_new(&tmp, owner_only)?;
        Ok((file, StagedFile::Direct(tmp)))
    }

    pub(crate) fn publish_staged_no_clobber(&self, staged: &StagedFile, to: &OsStr) -> io::Result<()> {
        match staged {
            StagedFile::Direct(from) => self.publish_no_clobber(from, to),
            #[cfg(target_vendor = "apple")]
            StagedFile::ApplePrivateDir { dir_name, dir_fd, file_name } => {
                use rustix::fs::AtFlags;
                rename_no_clobber(dir_fd, file_name, &self.fd, to)?;
                let _ = rustix::fs::unlinkat(&self.fd, dir_name, AtFlags::REMOVEDIR);
                Ok(())
            }
        }
    }

    pub(crate) fn rename_staged(&self, staged: &StagedFile, to: &OsStr) -> io::Result<()> {
        match staged {
            StagedFile::Direct(from) => self.rename(from, to),
            #[cfg(target_vendor = "apple")]
            StagedFile::ApplePrivateDir { dir_name, dir_fd, file_name } => {
                use rustix::fs::AtFlags;
                rustix::fs::renameat(dir_fd, file_name, &self.fd, to)?;
                let _ = rustix::fs::unlinkat(&self.fd, dir_name, AtFlags::REMOVEDIR);
                Ok(())
            }
        }
    }

    pub(crate) fn cleanup_staged(&self, staged: &StagedFile) {
        match staged {
            StagedFile::Direct(name) => {
                let _ = self.remove_file(name);
            }
            #[cfg(target_vendor = "apple")]
            StagedFile::ApplePrivateDir { dir_name, dir_fd, file_name } => {
                use rustix::fs::AtFlags;
                let _ = rustix::fs::unlinkat(dir_fd, file_name, AtFlags::empty());
                let _ = rustix::fs::unlinkat(&self.fd, dir_name, AtFlags::REMOVEDIR);
            }
        }
    }

    /// No-follow metadata lookup of `name` inside this opened folder
    /// (`fstatat` with `AT_SYMLINK_NOFOLLOW`, requiring no read permission on
    /// the entry itself). Returns `Ok(None)` only when `name` does not exist;
    /// otherwise `Ok(Some((is_symlink, (dev, ino))))`.
    pub(crate) fn entry_identity(&self, name: &OsStr) -> io::Result<Option<(bool, FileId)>> {
        use rustix::fs::{AtFlags, FileType, statat};
        use rustix::io::Errno;
        match statat(&self.fd, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(st) => {
                #[allow(clippy::unnecessary_cast)]
                let id = (st.st_dev as u64, st.st_ino as u64);
                Ok(Some((FileType::from_raw_mode(st.st_mode) == FileType::Symlink, id)))
            }
            Err(Errno::NOENT) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Whether this directory sits on a filesystem with stable file identities
    /// across renames and atomic exclusive rename (`RENAME_NOREPLACE` /
    /// `RENAME_EXCL`), required for safe dataset replacement and rollback.
    pub(crate) fn supports_reliable_identity(&self) -> io::Result<bool> {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            let st = rustix::fs::fstatfs(&self.fd)?;
            #[allow(clippy::unnecessary_cast)]
            let fs_type = st.f_type as u64;
            // FAT (MSDOS_SUPER_MAGIC = 0x4d44) and exFAT (EXFAT_SUPER_MAGIC = 0x2011_bab0)
            // derive inode numbers from directory entries, which can change on rename.
            Ok(!matches!(fs_type, 0x4d44 | 0x2011_bab0))
        }
        #[cfg(target_vendor = "apple")]
        {
            let st = rustix::fs::fstatfs(&self.fd)?;
            let bytes: Vec<u8> = st.f_fstypename.iter().map(|&c| c as u8).take_while(|&b| b != 0).collect();
            let fs_name = std::str::from_utf8(&bytes).unwrap_or("");
            Ok(!(fs_name.eq_ignore_ascii_case("msdos") || fs_name.eq_ignore_ascii_case("exfat") || fs_name.eq_ignore_ascii_case("fat")))
        }
        #[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
        {
            Ok(false)
        }
    }

    /// Return a live keep-alive handle to a freshly staged file whose open
    /// descriptor pins the OS file object against identity reuse through
    /// settlement. On Unix the staged descriptor itself serves as that handle.
    pub(crate) fn into_staged_keepalive(&self, _staged: &StagedFile, file: File) -> io::Result<File> {
        Ok(file)
    }

    /// Verify that `name` currently resolves (without following links) to the
    /// exact live OS file object pinned by `live_handle`.
    pub(crate) fn verify_live_entry(&self, name: &OsStr, live_handle: &File) -> io::Result<bool> {
        let live_meta = live_handle.metadata()?;
        let live_id = file_id(live_handle, &live_meta)?;
        Ok(matches!(self.entry_identity(name)?, Some((false, cur)) if cur == live_id))
    }

    /// Atomically rename `from` to `to` within this folder only when `to` does
    /// not exist, without any non-atomic `linkat`/`unlinkat` fallback.
    pub(crate) fn rename_no_clobber_atomic(&self, from: &OsStr, to: &OsStr) -> io::Result<()> {
        rename_no_clobber_atomic(&self.fd, from, &self.fd, to)
    }

    /// Acquire an exclusive cross-process `flock` on a stable lock file opened
    /// without following links inside this pinned directory. Initializes and
    /// verifies new lock files under a private temporary name before publishing
    /// via no-clobber rename (so a failed init can never expose or unlink the
    /// canonical lock name and split exporters across two inodes), requires
    /// group alignment only when access depends on group ownership (allowing
    /// `1777` root-owned `/tmp` directories for ordinary users), opens existing
    /// entries with `O_NONBLOCK` without `O_CREAT`, and reports actionable
    /// errors if an existing lock cannot be locked exclusively.
    pub(crate) fn lock_exclusive(&self) -> io::Result<(File, FileId)> {
        use rustix::fs::{Gid, Mode, OFlags};
        use rustix::io::Errno;
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let dir_meta = self.fd.metadata()?;
        let dir_mode = dir_meta.permissions().mode();
        let dir_gid = dir_meta.gid();
        let group_writable = dir_mode & 0o020 != 0;
        let world_writable = dir_mode & 0o002 != 0;
        let need_group_owner = group_writable && !world_writable;
        let mut target_mode: u32 = 0o600;
        if group_writable {
            target_mode |= 0o060;
        }
        if world_writable {
            target_mode |= 0o006;
        }

        let create_flags = OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let open_rw_flags = OFlags::RDWR | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let open_ro_flags = OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        #[allow(clippy::unnecessary_cast)]
        let create_mode = Mode::from_raw_mode(target_mode as rustix::fs::RawMode);

        let mut last_err = None;
        for _ in 0..8 {
            match rustix::fs::openat(&self.fd, EXPORT_LOCK_NAME, open_rw_flags, Mode::empty()) {
                Ok(fd) => {
                    let file = File::from(fd);
                    let meta = file.metadata()?;
                    if !meta.is_file() {
                        return Err(io::Error::new(io::ErrorKind::InvalidInput, "export directory lock is not a regular file"));
                    }
                    let id = file_id(&file, &meta)?;
                    file.lock()?;
                    return Ok((file, id));
                }
                Err(Errno::ACCESS) => match rustix::fs::openat(&self.fd, EXPORT_LOCK_NAME, open_ro_flags, Mode::empty()) {
                    Ok(fd) => {
                        let file = File::from(fd);
                        let meta = file.metadata()?;
                        if !meta.is_file() {
                            return Err(io::Error::new(io::ErrorKind::InvalidInput, "export directory lock is not a regular file"));
                        }
                        let id = file_id(&file, &meta)?;
                        file.lock().map_err(|err| {
                            io::Error::new(
                                err.kind(),
                                format!(
                                    "cannot lock existing '{EXPORT_LOCK_NAME}' without write permission ({err}); grant write access or remove the stale lock file"
                                ),
                            )
                        })?;
                        return Ok((file, id));
                    }
                    Err(Errno::NOENT) => continue,
                    Err(e) => {
                        return Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            format!("cannot open existing '{EXPORT_LOCK_NAME}' ({e}); grant write access or remove the stale lock file"),
                        ));
                    }
                },
                Err(Errno::NOENT) => {
                    // Initialize and verify a private candidate before exposing
                    // it at the canonical lock name via no-clobber publish so a
                    // failed initialization never leaves or unlinks a visible
                    // `.anvil-export.lock`.
                    let candidate = OsString::from(format!(".anvil-export-lock-{}.partial", uuid::Uuid::new_v4().simple()));
                    let fd = match rustix::fs::openat(&self.fd, &candidate, create_flags, create_mode) {
                        Ok(fd) => fd,
                        Err(e) => {
                            last_err = Some(e.into());
                            break;
                        }
                    };
                    let file = File::from(fd);
                    let meta = match file.metadata() {
                        Ok(m) => m,
                        Err(err) => {
                            drop(file);
                            let _ = self.remove_file(&candidate);
                            return Err(err);
                        }
                    };
                    if !meta.is_file() {
                        drop(file);
                        let _ = self.remove_file(&candidate);
                        return Err(io::Error::new(io::ErrorKind::InvalidInput, "export directory lock is not a regular file"));
                    }
                    if group_writable && meta.gid() != dir_gid {
                        match rustix::fs::fchown(&file, None, Some(Gid::from_raw(dir_gid))) {
                            Ok(()) => {}
                            Err(err) if need_group_owner => {
                                drop(file);
                                let _ = self.remove_file(&candidate);
                                return Err(io::Error::new(
                                    io::ErrorKind::PermissionDenied,
                                    format!(
                                        "cannot align '{EXPORT_LOCK_NAME}' group ownership with shared output directory (gid {dir_gid}): {err}; set the directory setgid bit or adjust group permissions"
                                    ),
                                ));
                            }
                            Err(_) => {}
                        }
                    }
                    #[allow(clippy::unnecessary_cast)]
                    if let Err(err) = rustix::fs::fchmod(&file, Mode::from_raw_mode(target_mode as rustix::fs::RawMode)) {
                        drop(file);
                        let _ = self.remove_file(&candidate);
                        return Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            format!("cannot set shared permissions ({target_mode:04o}) on '{EXPORT_LOCK_NAME}': {err}"),
                        ));
                    }
                    let meta = match file.metadata() {
                        Ok(m) => m,
                        Err(err) => {
                            drop(file);
                            let _ = self.remove_file(&candidate);
                            return Err(err);
                        }
                    };
                    let actual_mode = meta.permissions().mode() & 0o777;
                    if (need_group_owner && (meta.gid() != dir_gid || actual_mode & 0o060 != 0o060))
                        || (world_writable && (actual_mode & 0o006 != 0o006 || (group_writable && actual_mode & 0o060 != 0o060)))
                    {
                        drop(file);
                        let _ = self.remove_file(&candidate);
                        return Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            format!(
                                "cannot verify shared write permissions on '{EXPORT_LOCK_NAME}' (mode {actual_mode:04o}, gid {}); check output directory permissions",
                                meta.gid()
                            ),
                        ));
                    }
                    match self.publish_no_clobber(&candidate, OsStr::new(EXPORT_LOCK_NAME)) {
                        Ok(()) => {
                            let id = file_id(&file, &meta)?;
                            file.lock()?;
                            return Ok((file, id));
                        }
                        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
                            drop(file);
                            let _ = self.remove_file(&candidate);
                            continue;
                        }
                        Err(err) => {
                            drop(file);
                            let _ = self.remove_file(&candidate);
                            return Err(err);
                        }
                    }
                }
                Err(e) => {
                    last_err = Some(e.into());
                    break;
                }
            }
        }
        Err(last_err.unwrap_or_else(|| io::Error::other("could not open export directory lock file")))
    }

    /// Whether `name` resolves to the same OS file identity as an existing
    /// `.anvil-export.lock` entry in this directory (catches Unicode case-fold,
    /// NFC/NFD, or hard-link aliases even for writers that do not lock).
    pub(crate) fn entry_aliases_export_lock(&self, name: &OsStr) -> io::Result<bool> {
        let Some((_, lock_id)) = self.entry_identity(OsStr::new(EXPORT_LOCK_NAME))? else {
            return Ok(false);
        };
        Ok(matches!(self.entry_identity(name)?, Some((_, dest_id)) if dest_id == lock_id))
    }

    /// Back up an existing regular file `name` inside this folder without
    /// following symlinks so a subsequent companion-file failure can restore
    /// it. Refuses replacement up front on filesystems without reliable file
    /// identity or atomic exclusive rename. Prefers an atomic hard link (zero
    /// gap while `name` stays live) and falls back to an atomic exclusive
    /// rename on filesystems without hard links.
    pub(crate) fn backup_existing_regular(&self, name: &OsStr) -> io::Result<Option<ExistingBackup>> {
        use rustix::fs::{AtFlags, FileType, statat};
        use rustix::io::Errno;
        match statat(&self.fd, name, AtFlags::SYMLINK_NOFOLLOW) {
            Err(Errno::NOENT) => Ok(None),
            Err(e) => Err(e.into()),
            Ok(st) => {
                let ft = FileType::from_raw_mode(st.st_mode);
                if ft == FileType::Symlink {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "destination is a symbolic link; refusing to back up or replace a symlink",
                    ));
                }
                if ft != FileType::RegularFile {
                    return Err(io::Error::new(io::ErrorKind::InvalidInput, "destination is not a regular file"));
                }
                if !self.supports_reliable_identity()? {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "cannot safely replace an existing dataset file on a filesystem without reliable file identity or atomic exclusive rename",
                    ));
                }
                let backup = OsString::from(format!(".anvil-backup-{}.partial", uuid::Uuid::new_v4().simple()));
                match rustix::fs::linkat(&self.fd, name, &self.fd, &backup, AtFlags::empty()) {
                    Ok(()) => {
                        let Some((false, original_id)) = self.entry_identity(&backup)? else {
                            let _ = self.remove_file(&backup);
                            return Err(io::Error::other("cannot verify backed-up dataset identity"));
                        };
                        Ok(Some(ExistingBackup { name: backup, moved: false, original_id }))
                    }
                    Err(e)
                        if matches!(e, Errno::PERM | Errno::NOSYS | Errno::INVAL | Errno::XDEV | Errno::MLINK)
                            || e == Errno::OPNOTSUPP
                            || e == Errno::NOTSUP =>
                    {
                        self.rename_no_clobber_atomic(name, &backup)?;
                        let Some((false, original_id)) = self.entry_identity(&backup)? else {
                            return Err(io::Error::other("cannot verify moved dataset backup identity"));
                        };
                        Ok(Some(ExistingBackup { name: backup, moved: true, original_id }))
                    }
                    Err(e) => Err(e.into()),
                }
            }
        }
    }

    /// Abort a backup before replacement landed. When the backup moved the
    /// original entry aside, restores it with no-clobber rename so a concurrent
    /// entry is never overwritten. When the backup is a hard link, removes the
    /// backup ONLY after verifying `target` still names the original inode;
    /// otherwise preserves the backup and returns its filename alongside the
    /// error.
    pub(crate) fn abort_backup(&self, backup: ExistingBackup, target: &OsStr) -> std::result::Result<(), (OsString, io::Error)> {
        if backup.moved {
            if let Err(err) = self.publish_no_clobber(&backup.name, target) {
                return Err((backup.name, err));
            }
        } else {
            let same_original = matches!(
                (self.entry_identity(&backup.name), self.entry_identity(target)),
                (Ok(Some((false, bid))), Ok(Some((false, tid)))) if bid == backup.original_id && tid == backup.original_id
            );
            if !same_original {
                return Err((
                    backup.name,
                    io::Error::other("destination changed before publication completed; preserving original backup"),
                ));
            }
            let _ = self.remove_file(&backup.name);
        }
        Ok(())
    }

    /// Roll back a published `target` only if it still names the live object
    /// pinned by `live_handle`, preserving any concurrently installed entry.
    /// Quarantines `target` via strictly atomic exclusive rename (never
    /// `linkat`/`unlinkat`), re-verifies the quarantined entry against the
    /// live handle before deleting it, and restores `backup` via atomic
    /// no-clobber rename.
    pub(crate) fn rollback_owned(&self, target: &OsStr, live_handle: File, backup: Option<ExistingBackup>) -> RollbackOutcome {
        let live_id_now = |h: &File| -> Option<FileId> { h.metadata().and_then(|m| file_id(h, &m)).ok() };
        let Some(expected_id) = live_id_now(&live_handle) else {
            return RollbackOutcome::Skipped { backup_name: backup.map(ExistingBackup::into_name), quarantine_left: None };
        };
        if !matches!(self.entry_identity(target), Ok(Some((false, cur))) if cur == expected_id) {
            return RollbackOutcome::Skipped { backup_name: backup.map(ExistingBackup::into_name), quarantine_left: None };
        }
        let quarantine = OsString::from(format!(".anvil-rollback-{}.partial", uuid::Uuid::new_v4().simple()));
        if self.rename_no_clobber_atomic(target, &quarantine).is_err() {
            return RollbackOutcome::Skipped { backup_name: backup.map(ExistingBackup::into_name), quarantine_left: None };
        }
        let live_matches = live_id_now(&live_handle)
            .zip(self.entry_identity(&quarantine).ok().flatten())
            .is_some_and(|(live_id, (is_sym, q_id))| !is_sym && q_id == live_id);
        if !live_matches {
            // A concurrent writer swapped `target` right before quarantine; put
            // their entry back atomically without clobbering anything newer and
            // surface the quarantine path + error if restoration fails.
            let quarantine_left = match self.rename_no_clobber_atomic(&quarantine, target) {
                Ok(()) => None,
                Err(err) => Some((quarantine, err)),
            };
            return RollbackOutcome::Skipped { backup_name: backup.map(ExistingBackup::into_name), quarantine_left };
        }
        match backup {
            Some(b) => match self.publish_no_clobber(&b.name, target) {
                Ok(()) => {
                    let _ = self.remove_file(&quarantine);
                    drop(live_handle);
                    RollbackOutcome::Restored
                }
                Err(err) => {
                    let _ = self.remove_file(&quarantine);
                    drop(live_handle);
                    RollbackOutcome::Failed { backup_name: b.name, err }
                }
            },
            None => {
                let _ = self.remove_file(&quarantine);
                drop(live_handle);
                RollbackOutcome::Restored
            }
        }
    }

    pub(crate) fn discard_backup(&self, backup: ExistingBackup) {
        let _ = self.remove_file(&backup.name);
    }
}

/// Strictly atomic exclusive rename (`RENAME_NOREPLACE` / `RENAME_EXCL`) with
/// NO `linkat`/`unlinkat` fallback, used when quarantining or returning a live
/// destination so a concurrent swap can never be unlinked.
#[cfg(unix)]
fn rename_no_clobber_atomic(from_dir: &File, from: &OsStr, to_dir: &File, to: &OsStr) -> io::Result<()> {
    #[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
    {
        use rustix::fs::RenameFlags;
        use rustix::io::Errno;
        match rustix::fs::renameat_with(from_dir, from, to_dir, to, RenameFlags::NOREPLACE) {
            Ok(()) => Ok(()),
            Err(Errno::EXIST) => Err(io::Error::from(io::ErrorKind::AlreadyExists)),
            Err(e) if matches!(e, Errno::NOSYS | Errno::INVAL) || e == Errno::OPNOTSUPP || e == Errno::NOTSUP => {
                Err(io::Error::new(io::ErrorKind::Unsupported, format!("atomic exclusive rename unsupported: {e}")))
            }
            Err(e) => Err(e.into()),
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
    {
        let _ = (from_dir, from, to_dir, to);
        Err(io::Error::new(io::ErrorKind::Unsupported, "atomic exclusive rename unsupported on this platform"))
    }
}

/// Atomically move `from` in `from_dir` to `to` in `to_dir` only when `to`
/// does not already exist. Prefers atomic exclusive rename (`RENAME_NOREPLACE`
/// on Linux, `RENAME_EXCL` on Apple) so filesystems without hard-link support
/// (FAT32, exFAT) succeed, falling back to `linkat` + `unlinkat` only when
/// exclusive rename is unsupported.
#[cfg(unix)]
fn rename_no_clobber(from_dir: &File, from: &OsStr, to_dir: &File, to: &OsStr) -> io::Result<()> {
    #[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
    {
        use rustix::fs::RenameFlags;
        use rustix::io::Errno;
        match rustix::fs::renameat_with(from_dir, from, to_dir, to, RenameFlags::NOREPLACE) {
            Ok(()) => return Ok(()),
            Err(Errno::EXIST) => return Err(io::Error::from(io::ErrorKind::AlreadyExists)),
            Err(Errno::NOSYS | Errno::NOTSUP | Errno::INVAL) => {}
            Err(e) => return Err(e.into()),
        }
    }
    rustix::fs::linkat(from_dir, from, to_dir, to, rustix::fs::AtFlags::empty())?;
    let _ = rustix::fs::unlinkat(from_dir, from, rustix::fs::AtFlags::empty());
    Ok(())
}

/// Enforce owner-only permissions on a newly created open file descriptor
/// before any secret bytes are written: `fchmod(0o600)` (which also zeroes
/// Linux POSIX `ACL_MASK`), clear any inherited macOS extended ACL, and verify
/// both the resulting mode and absence of ACL entries. Fails closed if privacy
/// cannot be established.
#[cfg(unix)]
fn enforce_owner_only(file: &File) -> io::Result<()> {
    enforce_owner_only_mode(file, 0o600)
}

#[cfg(unix)]
fn enforce_owner_only_mode(file: &File, expected_mode: u32) -> io::Result<()> {
    use rustix::fs::Mode;
    use std::os::unix::fs::PermissionsExt;

    #[allow(clippy::unnecessary_cast)]
    rustix::fs::fchmod(file, Mode::from_raw_mode(expected_mode as rustix::fs::RawMode))?;
    #[cfg(target_vendor = "apple")]
    clear_and_verify_macos_acl(file)?;

    let mode = file.metadata()?.permissions().mode() & 0o7777;
    if mode != expected_mode {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("cannot verify owner-only permissions on new entry (mode {:04o})", mode),
        ));
    }
    Ok(())
}

/// Clear any inherited extended ACL on `file` and confirm no ACL entries
/// remain. Fails closed on unexpected errors so an inherited macOS ACL can
/// never grant another user read access to a secret file.
#[cfg(target_vendor = "apple")]
#[allow(unsafe_code)]
fn clear_and_verify_macos_acl(file: &File) -> io::Result<()> {
    use std::ffi::{c_int, c_void};
    use std::os::fd::AsRawFd;

    const ACL_TYPE_EXTENDED: c_int = 0x0000_0100;
    const ACL_FIRST_ENTRY: c_int = 0;
    const ENOENT: i32 = 2;
    const ENOTSUP: i32 = 45;

    unsafe extern "C" {
        fn acl_init(count: c_int) -> *mut c_void;
        fn acl_set_fd_np(fd: c_int, acl: *mut c_void, acl_type: c_int) -> c_int;
        fn acl_get_fd_np(fd: c_int, acl_type: c_int) -> *mut c_void;
        fn acl_get_entry(acl: *mut c_void, entry_id: c_int, entry_p: *mut *mut c_void) -> c_int;
        fn acl_free(obj_p: *mut c_void) -> c_int;
    }

    let fd = file.as_raw_fd();
    // SAFETY: `acl_init(0)` allocates an empty macOS `acl_t` (or NULL on OOM).
    let empty = unsafe { acl_init(0) };
    if empty.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a valid open descriptor and `empty` is a valid `acl_t`;
    // `acl_free` releases `empty` unconditionally afterwards.
    let set_rc = unsafe { acl_set_fd_np(fd, empty, ACL_TYPE_EXTENDED) };
    let set_err = if set_rc != 0 { Some(io::Error::last_os_error()) } else { None };
    unsafe {
        acl_free(empty);
    }
    if let Some(err) = set_err
        && err.raw_os_error() != Some(ENOTSUP)
    {
        return Err(err);
    }

    // Verify no extended ACL entries remain on the descriptor.
    // SAFETY: `fd` is open; a non-NULL `acl` is freed before returning.
    let current = unsafe { acl_get_fd_np(fd, ACL_TYPE_EXTENDED) };
    if current.is_null() {
        let err = io::Error::last_os_error();
        if matches!(err.raw_os_error(), Some(ENOENT | ENOTSUP)) {
            return Ok(());
        }
        return Err(err);
    }
    let mut entry: *mut c_void = std::ptr::null_mut();
    // SAFETY: `current` is a valid `acl_t` returned by `acl_get_fd_np`.
    let has_entry = unsafe { acl_get_entry(current, ACL_FIRST_ENTRY, &mut entry) == 0 };
    unsafe {
        acl_free(current);
    }
    if has_entry {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "cannot clear inherited ACL on owner-only file"));
    }
    Ok(())
}

/// The file just opened without following a link, if it is a regular file;
/// `None` when it is not, a link included.
#[cfg(unix)]
fn regular(opened: rustix::io::Result<rustix::fd::OwnedFd>) -> io::Result<Option<(File, Metadata)>> {
    let file = match opened {
        Ok(fd) => File::from(fd),
        Err(e) if is_link(e) => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    // The check that counts is on the opened handle.
    let meta = file.metadata()?;
    Ok(meta.is_file().then_some((file, meta)))
}

/// Whether opening without following a link failed because of one (or
/// because a folder on the path is not a folder).
#[cfg(unix)]
fn is_link(e: rustix::io::Errno) -> bool {
    use rustix::io::Errno;
    // FreeBSD reports a link not followed as EMLINK.
    [Errno::LOOP, Errno::NOTDIR, Errno::MLINK].contains(&e)
}

#[cfg(windows)]
impl Dir {
    /// Open the folder at the absolute, normalized `path`; `None` when a
    /// folder on it (or the folder itself) is a link or not a folder.
    pub(crate) fn open(path: &Path) -> io::Result<Option<Dir>> {
        let mut walked = PathBuf::new();
        let mut held: Vec<File> = Vec::new();
        for component in path.components() {
            match component {
                Component::Prefix(_) if held.is_empty() => {
                    walked.push(component);
                    continue;
                }
                Component::RootDir | Component::Normal(_) => walked.push(component),
                _ => return Err(not_absolute()),
            }
            let Some((folder, meta)) = hold(&walked)? else {
                return Ok(None);
            };
            if !meta.is_dir() {
                return Ok(None);
            }
            held.push(folder);
        }
        if held.is_empty() {
            return Err(not_absolute());
        }
        Ok(Some(Dir { path: walked, held }))
    }

    /// The folder's identity (volume serial number and file index).
    pub(crate) fn id(&self) -> io::Result<FileId> {
        let folder = self.held.last().ok_or_else(not_absolute)?;
        file_id(folder, &folder.metadata()?)
    }

    /// Open `name` in this folder for reading if it is a regular file; `None`
    /// when it is not, a link included. The file is held as itself while it
    /// is opened for reading, so the name still leads to it.
    pub(crate) fn open_regular(&self, name: &OsStr) -> io::Result<Option<(File, Metadata)>> {
        let path = self.path.join(name);
        let Some((itself, meta)) = hold(&path)? else {
            return Ok(None);
        };
        if !meta.is_file() {
            return Ok(None);
        }
        // Opened again normally, so a file kept by a cloud provider is read
        // as its contents rather than its placeholder.
        let file = File::open(&path)?;
        let opened = file.metadata()?;
        if !opened.is_file() || file_id(&file, &opened)? != file_id(&itself, &meta)? {
            return Ok(None);
        }
        Ok(Some((file, opened)))
    }

    /// Create `name` in this folder for writing. Anything already there under
    /// that name, a link included, makes it fail: nothing existing is opened
    /// or followed.
    pub(crate) fn create_new(&self, name: &OsStr, owner_only: bool) -> io::Result<File> {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_SHARE_ALL: u32 = 0x1 | 0x2 | 0x4;
        let _ = owner_only;
        std::fs::OpenOptions::new().write(true).create_new(true).share_mode(FILE_SHARE_ALL).open(self.path.join(name))
    }

    /// Whether this held folder sits on NTFS or ReFS, where Windows file IDs
    /// remain stable across renames and `MoveFileExW` supports atomic no-clobber
    /// rename while an attribute-only handle is open (unlike FAT/FAT32/exFAT).
    #[allow(unsafe_code)]
    pub(crate) fn supports_reliable_identity(&self) -> io::Result<bool> {
        use std::os::windows::io::AsRawHandle;

        unsafe extern "system" {
            fn GetVolumeInformationByHandleW(
                hfile: *mut std::ffi::c_void,
                lp_volume_name_buffer: *mut u16,
                n_volume_name_size: u32,
                lp_volume_serial_number: *mut u32,
                lp_maximum_component_length: *mut u32,
                lp_file_system_flags: *mut u32,
                lp_file_system_name_buffer: *mut u16,
                n_file_system_name_size: u32,
            ) -> i32;
        }

        let folder = self.held.last().ok_or_else(not_absolute)?;
        let mut fs_flags: u32 = 0;
        let mut fs_name_buf = [0u16; 64];
        // SAFETY: `folder.as_raw_handle()` is a valid open directory handle;
        // `fs_name_buf` is a writable UTF-16 buffer of length `fs_name_buf.len()`.
        let ok = unsafe {
            GetVolumeInformationByHandleW(
                folder.as_raw_handle(),
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut fs_flags,
                fs_name_buf.as_mut_ptr(),
                fs_name_buf.len() as u32,
            )
        };
        if ok == 0 {
            return Ok(false);
        }
        let len = fs_name_buf.iter().position(|&c| c == 0).unwrap_or(fs_name_buf.len());
        let fs_name = String::from_utf16_lossy(&fs_name_buf[..len]);
        Ok(fs_name.eq_ignore_ascii_case("NTFS") || fs_name.eq_ignore_ascii_case("ReFS"))
    }

    /// Open a lightweight attribute-only keep-alive handle to a freshly staged
    /// file while its write handle is still open (zero gap), verify both point
    /// to the same file object, then drop the write handle so the file is
    /// closed for writing while its NTFS/ReFS file identity stays pinned.
    pub(crate) fn into_staged_keepalive(&self, staged: &StagedFile, write_file: File) -> io::Result<File> {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_READ_ATTRIBUTES: u32 = 0x0080;
        const FILE_SHARE_ALL: u32 = 0x1 | 0x2 | 0x4;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        let StagedFile::Direct(name) = staged;
        let expected = file_id(&write_file, &write_file.metadata()?)?;
        let live = std::fs::OpenOptions::new()
            .access_mode(FILE_READ_ATTRIBUTES)
            .share_mode(FILE_SHARE_ALL)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(self.path.join(name))?;
        let actual = file_id(&live, &live.metadata()?)?;
        drop(write_file);
        if actual != expected {
            return Err(io::Error::other("staged file changed while opening keep-alive handle"));
        }
        Ok(live)
    }

    /// Verify that `name` currently resolves (without following links) to the
    /// exact live OS file object pinned by `live_handle`.
    pub(crate) fn verify_live_entry(&self, name: &OsStr, live_handle: &File) -> io::Result<bool> {
        let live_meta = live_handle.metadata()?;
        let live_id = file_id(live_handle, &live_meta)?;
        Ok(matches!(self.entry_identity(name)?, Some((false, cur)) if cur == live_id))
    }

    pub(crate) fn rename_no_clobber_atomic(&self, from: &OsStr, to: &OsStr) -> io::Result<()> {
        self.publish_no_clobber(from, to)
    }

    /// Rename `from` to `to` within this folder. A link at `to` is replaced,
    /// not followed.
    pub(crate) fn rename(&self, from: &OsStr, to: &OsStr) -> io::Result<()> {
        std::fs::rename(self.path.join(from), self.path.join(to))
    }

    /// Atomically publish `from` at `to` within this folder only if `to` does
    /// not already exist. Uses a same-volume `MoveFileExW` without
    /// `MOVEFILE_REPLACE_EXISTING` so it works on NTFS, ReFS, exFAT, and FAT32
    /// (unlike `hard_link`, which fails on exFAT/FAT32).
    #[allow(unsafe_code)]
    pub(crate) fn publish_no_clobber(&self, from: &OsStr, to: &OsStr) -> io::Result<()> {
        use std::os::windows::ffi::OsStrExt;

        unsafe extern "system" {
            fn MoveFileExW(existing: *const u16, new: *const u16, flags: u32) -> i32;
        }

        let src: Vec<u16> = self.path.join(from).as_os_str().encode_wide().chain(Some(0)).collect();
        let dst: Vec<u16> = self.path.join(to).as_os_str().encode_wide().chain(Some(0)).collect();
        // SAFETY: `src` and `dst` are valid NUL-terminated UTF-16 paths; flags=0
        // requests a same-volume rename that fails with ERROR_ALREADY_EXISTS if
        // `dst` already exists.
        if unsafe { MoveFileExW(src.as_ptr(), dst.as_ptr(), 0) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub(crate) fn remove_file(&self, name: &OsStr) -> io::Result<()> {
        std::fs::remove_file(self.path.join(name))
    }

    pub(crate) fn stage_new(&self, owner_only: bool) -> io::Result<(File, StagedFile)> {
        let tmp = OsString::from(format!(".anvil-{}.partial", uuid::Uuid::new_v4().simple()));
        let file = self.create_new(&tmp, owner_only)?;
        Ok((file, StagedFile::Direct(tmp)))
    }

    pub(crate) fn publish_staged_no_clobber(&self, staged: &StagedFile, to: &OsStr) -> io::Result<()> {
        match staged {
            StagedFile::Direct(from) => self.publish_no_clobber(from, to),
        }
    }

    pub(crate) fn rename_staged(&self, staged: &StagedFile, to: &OsStr) -> io::Result<()> {
        match staged {
            StagedFile::Direct(from) => self.rename(from, to),
        }
    }

    pub(crate) fn cleanup_staged(&self, staged: &StagedFile) {
        match staged {
            StagedFile::Direct(name) => {
                let _ = self.remove_file(name);
            }
        }
    }

    /// No-follow metadata lookup of `name` inside this held folder using
    /// attribute-only access (requiring no read permission on the file data).
    /// Returns `Ok(None)` only when `name` does not exist; otherwise
    /// `Ok(Some((is_symlink, (volume_serial, file_index))))`.
    pub(crate) fn entry_identity(&self, name: &OsStr) -> io::Result<Option<(bool, FileId)>> {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_READ_ATTRIBUTES: u32 = 0x0080;
        const FILE_SHARE_ALL: u32 = 0x1 | 0x2 | 0x4;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
        let opened = std::fs::OpenOptions::new()
            .access_mode(FILE_READ_ATTRIBUTES)
            .share_mode(FILE_SHARE_ALL)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
            .open(self.path.join(name));
        let file = match opened {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        let meta = file.metadata()?;
        let id = file_id(&file, &meta)?;
        Ok(Some((meta.file_type().is_symlink(), id)))
    }

    /// Acquire an exclusive cross-process lock on a stable, writable lock file
    /// opened without following links inside this held directory so concurrent
    /// exports targeting the same folder serialize regardless of `%TMP%`.
    pub(crate) fn lock_exclusive(&self) -> io::Result<(File, FileId)> {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        let lock_path = self.path.join(EXPORT_LOCK_NAME);
        let file =
            std::fs::OpenOptions::new().create(true).read(true).write(true).custom_flags(FILE_FLAG_OPEN_REPARSE_POINT).open(&lock_path)?;
        let meta = file.metadata()?;
        if meta.file_type().is_symlink() || !meta.is_file() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "export directory lock is a symbolic link or not a regular file"));
        }
        let id = file_id(&file, &meta)?;
        file.lock()?;
        Ok((file, id))
    }

    pub(crate) fn entry_aliases_export_lock(&self, name: &OsStr) -> io::Result<bool> {
        let Some((_, lock_id)) = self.entry_identity(OsStr::new(EXPORT_LOCK_NAME))? else {
            return Ok(false);
        };
        Ok(matches!(self.entry_identity(name)?, Some((_, dest_id)) if dest_id == lock_id))
    }

    pub(crate) fn backup_existing_regular(&self, name: &OsStr) -> io::Result<Option<ExistingBackup>> {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_READ_ATTRIBUTES: u32 = 0x0080;
        const FILE_SHARE_ALL: u32 = 0x1 | 0x2 | 0x4;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
        let path = self.path.join(name);
        let opened = std::fs::OpenOptions::new()
            .access_mode(FILE_READ_ATTRIBUTES)
            .share_mode(FILE_SHARE_ALL)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
            .open(&path);
        let file = match opened {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        let meta = file.metadata()?;
        drop(file);
        if meta.file_type().is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "destination is a symbolic link; refusing to back up or replace a symlink",
            ));
        }
        if !meta.is_file() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "destination is not a regular file"));
        }
        if !self.supports_reliable_identity()? {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "cannot safely replace an existing dataset file on a filesystem without reliable file identity or atomic exclusive rename",
            ));
        }
        let backup = OsString::from(format!(".anvil-backup-{}.partial", uuid::Uuid::new_v4().simple()));
        if std::fs::hard_link(&path, self.path.join(&backup)).is_ok() {
            let Some((false, original_id)) = self.entry_identity(&backup)? else {
                let _ = self.remove_file(&backup);
                return Err(io::Error::other("cannot verify backed-up dataset identity"));
            };
            Ok(Some(ExistingBackup { name: backup, moved: false, original_id }))
        } else {
            self.rename_no_clobber_atomic(name, &backup)?;
            let Some((false, original_id)) = self.entry_identity(&backup)? else {
                return Err(io::Error::other("cannot verify moved dataset backup identity"));
            };
            Ok(Some(ExistingBackup { name: backup, moved: true, original_id }))
        }
    }

    pub(crate) fn abort_backup(&self, backup: ExistingBackup, target: &OsStr) -> std::result::Result<(), (OsString, io::Error)> {
        if backup.moved {
            if let Err(err) = self.publish_no_clobber(&backup.name, target) {
                return Err((backup.name, err));
            }
        } else {
            let same_original = matches!(
                (self.entry_identity(&backup.name), self.entry_identity(target)),
                (Ok(Some((false, bid))), Ok(Some((false, tid)))) if bid == backup.original_id && tid == backup.original_id
            );
            if !same_original {
                return Err((
                    backup.name,
                    io::Error::other("destination changed before publication completed; preserving original backup"),
                ));
            }
            let _ = self.remove_file(&backup.name);
        }
        Ok(())
    }

    pub(crate) fn rollback_owned(&self, target: &OsStr, live_handle: File, backup: Option<ExistingBackup>) -> RollbackOutcome {
        let live_id_now = |h: &File| -> Option<FileId> { h.metadata().and_then(|m| file_id(h, &m)).ok() };
        let Some(expected_id) = live_id_now(&live_handle) else {
            return RollbackOutcome::Skipped { backup_name: backup.map(ExistingBackup::into_name), quarantine_left: None };
        };
        if !matches!(self.entry_identity(target), Ok(Some((false, cur))) if cur == expected_id) {
            return RollbackOutcome::Skipped { backup_name: backup.map(ExistingBackup::into_name), quarantine_left: None };
        }
        let quarantine = OsString::from(format!(".anvil-rollback-{}.partial", uuid::Uuid::new_v4().simple()));
        if self.rename_no_clobber_atomic(target, &quarantine).is_err() {
            return RollbackOutcome::Skipped { backup_name: backup.map(ExistingBackup::into_name), quarantine_left: None };
        }
        let live_matches = live_id_now(&live_handle)
            .zip(self.entry_identity(&quarantine).ok().flatten())
            .is_some_and(|(live_id, (is_sym, q_id))| !is_sym && q_id == live_id);
        if !live_matches {
            let quarantine_left = match self.rename_no_clobber_atomic(&quarantine, target) {
                Ok(()) => None,
                Err(err) => Some((quarantine, err)),
            };
            return RollbackOutcome::Skipped { backup_name: backup.map(ExistingBackup::into_name), quarantine_left };
        }
        match backup {
            Some(b) => match self.publish_no_clobber(&b.name, target) {
                Ok(()) => {
                    let _ = self.remove_file(&quarantine);
                    drop(live_handle);
                    RollbackOutcome::Restored
                }
                Err(err) => {
                    let _ = self.remove_file(&quarantine);
                    drop(live_handle);
                    RollbackOutcome::Failed { backup_name: b.name, err }
                }
            },
            None => {
                let _ = self.remove_file(&quarantine);
                drop(live_handle);
                RollbackOutcome::Restored
            }
        }
    }

    pub(crate) fn discard_backup(&self, backup: ExistingBackup) {
        let _ = self.remove_file(&backup.name);
    }
}

/// Open `path` itself, a link or other reparse point at it included, and hold
/// it: without delete sharing it cannot be renamed, removed or replaced while
/// the handle is open. `None` when it is a link or a junction.
#[cfg(windows)]
fn hold(path: &Path) -> io::Result<Option<(File, Metadata)>> {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_SHARE_READ: u32 = 0x1;
    const FILE_SHARE_WRITE: u32 = 0x2;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    // Needed to open a folder.
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    // Read access, not attributes only: a handle without data access
    // reserves no sharing, so it would not keep the path from changing.
    let file = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)?;
    let meta = file.metadata()?;
    // A symbolic link or junction (a name-surrogate reparse point) redirects
    // the path; other reparse points, such as a cloud provider's, do not.
    Ok((!meta.file_type().is_symlink()).then_some((file, meta)))
}

#[cfg(not(any(unix, windows)))]
impl Dir {
    pub(crate) fn open(path: &Path) -> io::Result<Option<Dir>> {
        if !path.is_absolute() {
            return Err(not_absolute());
        }
        Ok(std::fs::metadata(path)?.is_dir().then(|| Dir { path: path.to_path_buf() }))
    }

    pub(crate) fn id(&self) -> io::Result<FileId> {
        let folder = File::open(&self.path)?;
        file_id(&folder, &folder.metadata()?)
    }

    pub(crate) fn open_regular(&self, name: &OsStr) -> io::Result<Option<(File, Metadata)>> {
        let file = File::open(self.path.join(name))?;
        let meta = file.metadata()?;
        Ok(meta.is_file().then_some((file, meta)))
    }

    pub(crate) fn create_new(&self, name: &OsStr, owner_only: bool) -> io::Result<File> {
        let _ = owner_only;
        std::fs::OpenOptions::new().write(true).create_new(true).open(self.path.join(name))
    }

    pub(crate) fn rename(&self, from: &OsStr, to: &OsStr) -> io::Result<()> {
        std::fs::rename(self.path.join(from), self.path.join(to))
    }

    pub(crate) fn publish_no_clobber(&self, from: &OsStr, to: &OsStr) -> io::Result<()> {
        std::fs::hard_link(self.path.join(from), self.path.join(to))?;
        let _ = self.remove_file(from);
        Ok(())
    }

    pub(crate) fn remove_file(&self, name: &OsStr) -> io::Result<()> {
        std::fs::remove_file(self.path.join(name))
    }

    pub(crate) fn stage_new(&self, owner_only: bool) -> io::Result<(File, StagedFile)> {
        let tmp = OsString::from(format!(".anvil-{}.partial", uuid::Uuid::new_v4().simple()));
        let file = self.create_new(&tmp, owner_only)?;
        Ok((file, StagedFile::Direct(tmp)))
    }

    pub(crate) fn publish_staged_no_clobber(&self, staged: &StagedFile, to: &OsStr) -> io::Result<()> {
        match staged {
            StagedFile::Direct(from) => self.publish_no_clobber(from, to),
        }
    }

    pub(crate) fn rename_staged(&self, staged: &StagedFile, to: &OsStr) -> io::Result<()> {
        match staged {
            StagedFile::Direct(from) => self.rename(from, to),
        }
    }

    pub(crate) fn cleanup_staged(&self, staged: &StagedFile) {
        match staged {
            StagedFile::Direct(name) => {
                let _ = self.remove_file(name);
            }
        }
    }

    pub(crate) fn lock_exclusive(&self) -> io::Result<(File, FileId)> {
        let file = std::fs::OpenOptions::new().create(true).read(true).write(true).open(self.path.join(EXPORT_LOCK_NAME))?;
        let meta = file.metadata()?;
        let id = file_id(&file, &meta)?;
        file.lock()?;
        Ok((file, id))
    }

    pub(crate) fn entry_identity(&self, name: &OsStr) -> io::Result<Option<(bool, FileId)>> {
        match std::fs::symlink_metadata(self.path.join(name)) {
            Ok(meta) => Ok(Some((meta.file_type().is_symlink(), (0, 0)))),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub(crate) fn entry_aliases_export_lock(&self, _name: &OsStr) -> io::Result<bool> {
        Ok(false)
    }

    pub(crate) fn supports_reliable_identity(&self) -> io::Result<bool> {
        Ok(false)
    }

    pub(crate) fn into_staged_keepalive(&self, _staged: &StagedFile, file: File) -> io::Result<File> {
        Ok(file)
    }

    pub(crate) fn verify_live_entry(&self, _name: &OsStr, _live_handle: &File) -> io::Result<bool> {
        Ok(false)
    }

    pub(crate) fn backup_existing_regular(&self, name: &OsStr) -> io::Result<Option<ExistingBackup>> {
        let path = self.path.join(name);
        let meta = match std::fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        if meta.file_type().is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "destination is a symbolic link; refusing to back up or replace a symlink",
            ));
        }
        if !meta.is_file() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "destination is not a regular file"));
        }
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "cannot safely replace an existing dataset file on a platform without reliable file identity",
        ))
    }

    pub(crate) fn abort_backup(&self, backup: ExistingBackup, target: &OsStr) -> std::result::Result<(), (OsString, io::Error)> {
        if backup.moved {
            if let Err(err) = self.publish_no_clobber(&backup.name, target) {
                return Err((backup.name, err));
            }
            Ok(())
        } else {
            Err((backup.name, io::Error::other("cannot verify original dataset identity on this platform; preserving backup")))
        }
    }

    pub(crate) fn rollback_owned(&self, _target: &OsStr, _live_handle: File, backup: Option<ExistingBackup>) -> RollbackOutcome {
        // Fallback platforms lack reliable inode identities; preserve any backup.
        RollbackOutcome::Skipped { backup_name: backup.map(ExistingBackup::into_name), quarantine_left: None }
    }

    pub(crate) fn discard_backup(&self, backup: ExistingBackup) {
        let _ = self.remove_file(&backup.name);
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::{Dir, open_regular};
    use std::ffi::OsStr;
    use std::os::unix::fs::symlink;

    #[test]
    fn a_folder_on_the_path_that_is_a_link_is_not_followed() {
        let root = tempfile::tempdir().unwrap();
        // The temporary folder itself may sit below a link (macOS /var).
        let root = std::fs::canonicalize(root.path()).unwrap();
        let chosen = root.join("chosen");
        std::fs::create_dir_all(chosen.join("inner")).unwrap();
        let rows = chosen.join("inner/rows.csv");
        std::fs::write(&rows, "id\n1\n").unwrap();
        assert!(Dir::open(&chosen.join("inner")).unwrap().is_some());
        assert!(open_regular(&rows).unwrap().is_some());

        // The chosen folder swapped for a link to another one with the same
        // layout.
        let elsewhere = root.join("elsewhere");
        std::fs::create_dir_all(elsewhere.join("inner")).unwrap();
        std::fs::write(elsewhere.join("inner/rows.csv"), "secret\n").unwrap();
        std::fs::rename(&chosen, root.join("moved")).unwrap();
        symlink(&elsewhere, &chosen).unwrap();
        assert!(Dir::open(&chosen.join("inner")).unwrap().is_none());
        assert!(Dir::open(&chosen).unwrap().is_none());
        assert!(open_regular(&rows).unwrap().is_none());
        // The real folder still opens.
        assert!(Dir::open(&elsewhere.join("inner")).unwrap().is_some());
        assert!(open_regular(&elsewhere.join("inner/rows.csv")).unwrap().is_some());
    }

    #[test]
    fn an_opened_folder_is_used_even_if_its_path_is_swapped_for_a_link_later() {
        let root = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(root.path()).unwrap();
        let chosen = root.join("chosen");
        let elsewhere = root.join("elsewhere");
        std::fs::create_dir_all(&chosen).unwrap();
        std::fs::create_dir_all(&elsewhere).unwrap();
        let dir = Dir::open(&chosen).unwrap().unwrap();
        std::fs::rename(&chosen, root.join("moved")).unwrap();
        symlink(&elsewhere, &chosen).unwrap();
        let mut file = dir.create_new(OsStr::new("out.partial"), false).unwrap();
        std::io::Write::write_all(&mut file, b"report").unwrap();
        drop(file);
        dir.rename(OsStr::new("out.partial"), OsStr::new("out.json")).unwrap();
        // Written in the folder opened, never through the link.
        assert_eq!(std::fs::read(root.join("moved/out.json")).unwrap(), b"report");
        assert!(std::fs::read_dir(&elsewhere).unwrap().next().is_none());
    }

    #[test]
    fn a_link_in_place_of_the_file_is_not_followed_or_created_through() {
        let root = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(root.path()).unwrap();
        let target = root.join("target.txt");
        std::fs::write(&target, "secret").unwrap();
        symlink(&target, root.join("link.txt")).unwrap();
        let dir = Dir::open(&root).unwrap().unwrap();
        assert!(open_regular(&root.join("link.txt")).unwrap().is_none());
        assert!(dir.create_new(OsStr::new("link.txt"), false).is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"secret");
    }
}

#[cfg(all(test, windows))]
pub(crate) mod windows_tests {
    use super::{Dir, open_regular};
    use std::path::Path;

    /// Make `link` a junction to the folder `target` (unlike a symbolic link,
    /// one needs neither administrator rights nor developer mode).
    pub(crate) fn junction(link: &Path, target: &Path) {
        let out = std::process::Command::new("cmd").args(["/C", "mklink", "/J"]).arg(link).arg(target).output().unwrap();
        assert!(out.status.success(), "mklink /J failed: {}", String::from_utf8_lossy(&out.stderr));
    }

    #[test]
    fn a_junction_on_the_path_is_not_followed() {
        let temp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(temp.path()).unwrap();
        let elsewhere = root.join("elsewhere");
        std::fs::create_dir_all(elsewhere.join("inner")).unwrap();
        std::fs::write(elsewhere.join("inner").join("rows.csv"), "secret\n").unwrap();
        junction(&temp.path().join("chosen"), &temp.path().join("elsewhere"));
        // Not canonicalized: that would resolve the junction.
        let chosen = root.join("chosen");
        assert!(Dir::open(&chosen).unwrap().is_none());
        assert!(Dir::open(&chosen.join("inner")).unwrap().is_none());
        assert!(open_regular(&chosen.join("inner").join("rows.csv")).unwrap().is_none());
        // The real folder still opens.
        assert!(Dir::open(&elsewhere.join("inner")).unwrap().is_some());
        assert!(open_regular(&elsewhere.join("inner").join("rows.csv")).unwrap().is_some());
    }

    #[test]
    fn a_held_folder_cannot_be_moved_aside_until_it_is_released() {
        let temp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(temp.path()).unwrap();
        let parent = root.join("parent");
        let chosen = parent.join("chosen");
        std::fs::create_dir_all(&chosen).unwrap();
        let dir = Dir::open(&chosen).unwrap().unwrap();
        // Neither the folder nor one above it can be renamed to make room for
        // a junction in its place.
        assert!(std::fs::rename(&chosen, parent.join("moved")).is_err());
        assert!(std::fs::rename(&parent, root.join("moved")).is_err());
        assert!(std::fs::metadata(&chosen).unwrap().is_dir());
        drop(dir);
        std::fs::rename(&parent, root.join("moved")).unwrap();
    }
}
