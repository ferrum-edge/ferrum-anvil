//! Publish the owned file, never a checked-then-resolved source pathname.
//! Native contracts and filesystem limits: docs/security/file-handle-safety.md.

use super::{DescriptorLease, SelectedDirectory};
use std::ffi::OsStr;
use std::fs::File;
use std::io;

pub(crate) struct OwnedPublication {
    pub(crate) file: File,
    _lease: DescriptorLease,
}

impl OwnedPublication {
    pub(crate) fn create(dir: &SelectedDirectory, owner_only: bool) -> io::Result<Self> {
        let lease = dir.reserve()?;
        let file = create(dir, owner_only)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || !super::no_reparse(&metadata) {
            return Err(io::Error::other("export staging is not a regular file"));
        }
        Ok(Self { file, _lease: lease })
    }

    pub(crate) fn publish(&self, dir: &SelectedDirectory, name: &OsStr) -> io::Result<()> {
        publish(&self.file, dir, name)
    }
}

#[cfg(target_os = "linux")]
fn create(dir: &SelectedDirectory, owner_only: bool) -> io::Result<File> {
    use rustix::fs::{Mode, OFlags, openat};
    let mode = if owner_only { 0o600 } else { 0o666 };
    let flags = OFlags::TMPFILE | OFlags::RDWR | OFlags::CLOEXEC;
    let fd = openat(dir.dir(), ".", flags, Mode::from_raw_mode(mode))?;
    Ok(File::from(fd))
}

#[cfg(target_os = "linux")]
fn publish(file: &File, dir: &SelectedDirectory, name: &OsStr) -> io::Result<()> {
    use rustix::fs::{AtFlags, Mode, OFlags, fstatfs, linkat, open, openat};
    use std::os::fd::AsRawFd;

    // AT_EMPTY_PATH normally requires CAP_DAC_READ_SEARCH. Try it first;
    // unprivileged callers use the documented, kernel-owned procfs fd link.
    match linkat(file, "", dir.dir(), name, AtFlags::EMPTY_PATH) {
        Ok(()) => return Ok(()),
        Err(rustix::io::Errno::PERM | rustix::io::Errno::NOENT) => {}
        Err(err) => return Err(err.into()),
    }
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC;
    let proc = open("/proc", flags | OFlags::NOFOLLOW, Mode::empty())?;
    // Refuse an ordinary directory masquerading as procfs. Mount namespace
    // administration and process/descriptor injection are outside the threat.
    if fstatfs(&proc)?.f_type != libc::PROC_SUPER_MAGIC as _ {
        return Err(io::Error::other("descriptor publication needs authentic procfs"));
    }
    let descriptors = openat(&proc, "self/fd", flags, Mode::empty())?;
    let source = file.as_raw_fd().to_string();
    linkat(
        &descriptors,
        source,
        dir.dir(),
        name,
        AtFlags::SYMLINK_FOLLOW,
    )?;
    Ok(())
}

#[cfg(any(target_os = "macos", windows))]
fn create(dir: &SelectedDirectory, _owner_only: bool) -> io::Result<File> {
    use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt};
    use cap_std::fs::{OpenOptions, OpenOptionsExt};

    let temporary = format!(".anvil-{}.partial", uuid::Uuid::new_v4().simple());
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true).follow(FollowSymlinks::No);
    #[cfg(target_os = "macos")]
    options.mode(0o600);
    #[cfg(windows)]
    {
        // GENERIC_READ | GENERIC_WRITE | DELETE; FILE_SHARE_READ only.
        // Source replacement and writes by another handle are denied, and
        // the retained handle itself has the access native rename requires.
        options.access_mode(0xc0010000).share_mode(1);
    }
    Ok(dir.dir().open_with(temporary, &options)?.into_std())
}

#[cfg(target_os = "macos")]
fn publish(file: &File, dir: &SelectedDirectory, name: &OsStr) -> io::Result<()> {
    use rustix::fs::{CloneFlags, fclonefileat};
    // Apple specifies atomic all-or-nothing creation and EEXIST. Source is
    // the open vnode; renaming/replacing its temporary name cannot redirect
    // this call. Requires same-volume clone support (normally APFS).
    let flags = CloneFlags::NOFOLLOW | CloneFlags::NOOWNERCOPY;
    fclonefileat(file, dir.dir(), name, flags)?;
    // No unlink-by-fd primitive is used here. Preserve the uncertain source
    // name rather than removing somebody else's replacement. See the
    // explicit staging-data retention limitation in the security document.
    Ok(())
}

#[cfg(windows)]
fn publish(file: &File, dir: &SelectedDirectory, name: &OsStr) -> io::Result<()> {
    windows::publish(file, dir, name)
}

// A single audited FFI boundary, with no new dependency or lockfile graph.
// All pathname acquisition remains in cap-std; this operation takes handles.
#[cfg(windows)]
#[allow(unsafe_code)]
mod windows {
    use super::*;
    use std::ffi::c_void;
    use std::mem::{align_of, offset_of, size_of};
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::AsRawHandle;

    #[repr(C)]
    struct RenameInfo {
        flags: u32,
        root_directory: *mut c_void,
        file_name_length: u32,
        file_name: [u16; 1],
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        #[link_name = "SetFileInformationByHandle"]
        fn set_file_information_by_handle(
            file: *mut c_void,
            class: i32,
            information: *const c_void,
            size: u32,
        ) -> i32;
    }

    pub(super) fn publish(file: &File, dir: &SelectedDirectory, name: &OsStr) -> io::Result<()> {
        let name: Vec<u16> = name.encode_wide().collect();
        let special = name == [46] || name == [46, 46];
        if name.is_empty() || special || name.iter().any(|c| matches!(*c, 0 | 47 | 58 | 92)) {
            return Err(io::Error::other("publication requires one ordinary file name"));
        }
        let bytes = name.len().checked_mul(2).ok_or_else(|| io::Error::other("name too long"))?;
        let offset = offset_of!(RenameInfo, file_name);
        let size = size_of::<RenameInfo>()
            .checked_add(bytes)
            .ok_or_else(|| io::Error::other("name too long"))?;
        let size32 = u32::try_from(size).map_err(|_| io::Error::other("name too long"))?;
        let bytes32 = u32::try_from(bytes).map_err(|_| io::Error::other("name too long"))?;
        // usize storage provides the C struct's pointer alignment on both
        // Windows architectures. Zeroed padding and a trailing NUL are kept.
        assert!(align_of::<usize>() >= align_of::<RenameInfo>());
        let mut storage = vec![0usize; size.div_ceil(size_of::<usize>())];
        let pointer = storage.as_mut_ptr().cast::<RenameInfo>();
        // SAFETY: storage is aligned, initialized and large enough for the
        // complete header plus all UTF-16 units. Both handles are borrowed
        // from live owners through the synchronous call. Class 22 is
        // FileRenameInfoEx; flags 0 forbids replacement/POSIX overwrite.
        let ok = unsafe {
            pointer.write(RenameInfo {
                flags: 0,
                root_directory: dir.dir().as_raw_handle(),
                file_name_length: bytes32,
                file_name: [0],
            });
            let destination = storage.as_mut_ptr().cast::<u8>().add(offset).cast::<u16>();
            std::ptr::copy_nonoverlapping(name.as_ptr(), destination, name.len());
            set_file_information_by_handle(
                file.as_raw_handle(),
                22,
                pointer.cast(),
                size32,
            )
        };
        if ok == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn create(_dir: &SelectedDirectory, _owner_only: bool) -> io::Result<File> {
    Err(io::Error::other("owned export publication is unsupported on this platform"))
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn publish(_file: &File, _dir: &SelectedDirectory, _name: &OsStr) -> io::Result<()> {
    Err(io::Error::other("owned export publication is unsupported on this platform"))
}
