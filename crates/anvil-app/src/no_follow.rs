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
use std::ffi::OsStr;
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
    /// or followed.
    pub(crate) fn create_new(&self, name: &OsStr, owner_only: bool) -> io::Result<File> {
        use rustix::fs::{Mode, OFlags};
        let flags = OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let mode = Mode::from_raw_mode(if owner_only { 0o600 } else { 0o666 });
        Ok(File::from(rustix::fs::openat(&self.fd, name, flags, mode)?))
    }

    /// Rename `from` to `to` within this folder. A link at `to` is replaced,
    /// not followed.
    pub(crate) fn rename(&self, from: &OsStr, to: &OsStr) -> io::Result<()> {
        Ok(rustix::fs::renameat(&self.fd, from, &self.fd, to)?)
    }

    pub(crate) fn remove_file(&self, name: &OsStr) -> io::Result<()> {
        Ok(rustix::fs::unlinkat(&self.fd, name, rustix::fs::AtFlags::empty())?)
    }
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

    pub(crate) fn remove_file(&self, name: &OsStr) -> io::Result<()> {
        std::fs::remove_file(self.path.join(name))
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

    pub(crate) fn remove_file(&self, name: &OsStr) -> io::Result<()> {
        std::fs::remove_file(self.path.join(name))
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
