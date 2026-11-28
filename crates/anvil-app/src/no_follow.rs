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
        let _ = owner_only;
        std::fs::OpenOptions::new().write(true).create_new(true).open(self.path.join(name))
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

    pub(crate) fn entry_identity(&self, name: &OsStr) -> io::Result<Option<(bool, FileId)>> {
        match std::fs::symlink_metadata(self.path.join(name)) {
            Ok(meta) => Ok(Some((meta.file_type().is_symlink(), (0, 0)))),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
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
