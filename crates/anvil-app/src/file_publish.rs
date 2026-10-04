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

#[cfg(target_os = "macos")]
fn create(dir: &SelectedDirectory, _owner_only: bool) -> io::Result<File> {
    // Preserve macOS's existing 0600 policy for all exports, but establish
    // the ACL atomically too. Clearing an inherited ACL after open would
    // leave a window for a non-owner to retain a readable staging handle.
    macos::create(dir)
}

#[cfg(windows)]
fn create(dir: &SelectedDirectory, _owner_only: bool) -> io::Result<File> {
    use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt};
    use cap_std::fs::{OpenOptions, OpenOptionsExt};

    let temporary = format!(".anvil-{}.partial", uuid::Uuid::new_v4().simple());
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true).follow(FollowSymlinks::No);
    // GENERIC_READ | GENERIC_WRITE | DELETE; FILE_SHARE_READ only.
    // Source replacement and writes by another handle are denied, and
    // the retained handle itself has the access native rename requires.
    options.access_mode(0xc0010000).share_mode(1);
    Ok(dir.dir().open_with(temporary, &options)?.into_std())
}

#[cfg(target_os = "macos")]
fn publish(file: &File, dir: &SelectedDirectory, name: &OsStr) -> io::Result<()> {
    use rustix::fs::{CloneFlags, fclonefileat};
    macos::check_owner_only(file)?;
    // Apple specifies atomic all-or-nothing creation and EEXIST. Source is
    // the open vnode; renaming/replacing its temporary name cannot redirect
    // this call. Requires same-volume clone support (normally APFS).
    // CLONE_ACL (0x0004 in sys/clonefile.h) copies the explicit empty ACL
    // with ACL_FLAG_NO_INHERIT. XNU kauth_acl_inherit then rejects ALL
    // destination inheritance during the clone, even if the directory's ACL
    // changed after staging. There is no exposed clone followed by chmod.
    // rustix 1.1.5 accepts externally defined flags but does not name this one.
    let flags = CloneFlags::NOFOLLOW | CloneFlags::NOOWNERCOPY | CloneFlags::from_bits_retain(4);
    fclonefileat(file, dir.dir(), name, flags)?;
    // No unlink-by-fd primitive is used here. Preserve the uncertain source
    // name rather than removing somebody else's replacement. See the
    // explicit staging-data retention limitation in the security document.
    Ok(())
}

// Audited Darwin boundary: public opaque ACL/filesec APIs, no C struct layout.
// Primary contracts: Apple Libc sys/openx_np.c and include/sys/acl.h;
// XNU bsd/kern/kern_authorization.c (kauth_acl_inherit) and
// bsd/vfs/vfs_syscalls.c (open_extended, fchdir, clonefile_internal).
#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
mod macos {
    use super::*;
    use std::ffi::{CString, c_char, c_int, c_void};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::MetadataExt;

    const ACL_TYPE_EXTENDED: c_int = 0x100;
    const ACL_FLAG_NO_INHERIT: c_int = 1 << 17;
    const FILESEC_MODE: c_int = 4;
    const FILESEC_ACL: c_int = 5;

    unsafe extern "C" {
        fn acl_init(count: c_int) -> *mut c_void;
        fn acl_free(acl: *mut c_void) -> c_int;
        fn acl_get_fd_np(fd: c_int, kind: c_int) -> *mut c_void;
        fn acl_set_fd_np(fd: c_int, acl: *mut c_void, kind: c_int) -> c_int;
        fn acl_get_entry(acl: *mut c_void, index: c_int, entry: *mut *mut c_void) -> c_int;
        fn acl_get_flagset_np(acl: *mut c_void, flags: *mut *mut c_void) -> c_int;
        fn acl_add_flag_np(flags: *mut c_void, flag: c_int) -> c_int;
        fn acl_get_flag_np(flags: *mut c_void, flag: c_int) -> c_int;
        fn filesec_init() -> *mut c_void;
        fn filesec_free(security: *mut c_void);
        fn filesec_set_property(
            security: *mut c_void,
            property: c_int,
            value: *const c_void,
        ) -> c_int;
        fn openx_np(name: *const c_char, flags: c_int, security: *mut c_void) -> c_int;
        fn pthread_fchdir_np(fd: c_int) -> c_int;
    }

    struct Acl(*mut c_void);

    impl Acl {
        fn new(pointer: *mut c_void) -> io::Result<Self> {
            if pointer.is_null() {
                Err(io::Error::last_os_error())
            } else {
                Ok(Self(pointer))
            }
        }

        fn flags(&self) -> io::Result<*mut c_void> {
            let mut flags = std::ptr::null_mut();
            // SAFETY: self owns a live ACL; the API borrows its flagset.
            checked(unsafe { acl_get_flagset_np(self.0, &mut flags) })?;
            Ok(flags)
        }
    }

    impl Drop for Acl {
        fn drop(&mut self) {
            // SAFETY: this is the sole owner of an ACL allocated by Libc.
            unsafe { acl_free(self.0) };
        }
    }

    struct Security(*mut c_void);

    impl Drop for Security {
        fn drop(&mut self) {
            // SAFETY: this is the sole owner of a filesec allocated by Libc.
            unsafe { filesec_free(self.0) };
        }
    }

    fn checked(result: c_int) -> io::Result<()> {
        if result == -1 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    pub(super) fn create(dir: &SelectedDirectory) -> io::Result<File> {
        // openx_np has no *at variant. A dedicated, joined thread uses the
        // retained directory as its thread-only cwd and resolves ONE leaf.
        // Neither the caller's thread cwd nor the process cwd is changed;
        // thread teardown releases its cwd on every success/failure/panic.
        // No async suspension, repository callback, or source reopen occurs.
        std::thread::scope(|scope| {
            std::thread::Builder::new()
                .spawn_scoped(scope, || create_here(dir))?
                .join()
                .map_err(|_| io::Error::other("export staging thread panicked"))?
        })
    }

    fn create_here(dir: &SelectedDirectory) -> io::Result<File> {
        let name = CString::new(format!(".anvil-{}.partial", uuid::Uuid::new_v4().simple()))?;
        // SAFETY: both APIs allocate their own opaque objects, owned below.
        let acl = Acl::new(unsafe { acl_init(0) })?;
        let security = unsafe { filesec_init() };
        if security.is_null() {
            return Err(io::Error::last_os_error());
        }
        let security = Security(security);
        let mode: libc::mode_t = 0o600;
        let flags = acl.flags()?;
        // SAFETY: flagset is borrowed from acl. Property values have the
        // exact public ABI types (mode_t and acl_t); filesec copies them.
        unsafe {
            checked(acl_add_flag_np(flags, ACL_FLAG_NO_INHERIT))?;
            checked(filesec_set_property(
                security.0,
                FILESEC_MODE,
                (&mode as *const libc::mode_t).cast(),
            ))?;
            checked(filesec_set_property(
                security.0,
                FILESEC_ACL,
                (&acl.0 as *const *mut c_void).cast(),
            ))?;
            checked(pthread_fchdir_np(dir.dir().as_raw_fd()))?;
        }
        let flags =
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC;
        // SAFETY: a live filesec and NUL-terminated single component are
        // borrowed through atomic exclusive creation relative to the vnode
        // retained by this thread's cwd. No inherited allow ACE can appear.
        let fd = unsafe { openx_np(name.as_ptr(), flags, security.0) };
        checked(fd)?;
        // SAFETY: successful openx_np transfers this new descriptor to us.
        let file = unsafe { File::from_raw_fd(fd) };
        // XNU consumes NO_INHERIT while composing the creation ACL. The
        // object was already created with no inherited ACEs and mode 0600,
        // so this descriptor-only update has no pre-open exposure window.
        // Reinstate the flag on the source for the later CLONE_ACL operation.
        // SAFETY: both the descriptor and the original ACL remain owned.
        checked(unsafe { acl_set_fd_np(file.as_raw_fd(), acl.0, ACL_TYPE_EXTENDED) })?;
        // Refuse a filesystem that does not retain the requested ACL policy
        // before any data is written. No pathname postcheck or cleanup.
        check_owner_only(&file)?;
        Ok(file)
    }

    pub(super) fn check_owner_only(file: &File) -> io::Result<()> {
        let metadata = file.metadata()?;
        // SAFETY: geteuid has no preconditions; the descriptor stays owned.
        if metadata.mode() & 0o777 != 0o600 || metadata.uid() != unsafe { libc::geteuid() } {
            return Err(io::Error::other("export requires owner-only mode and ownership"));
        }
        // SAFETY: live borrowed descriptor; Libc returns a separately owned ACL.
        let acl = Acl::new(unsafe { acl_get_fd_np(file.as_raw_fd(), ACL_TYPE_EXTENDED) })?;
        let flags = acl.flags()?;
        let mut entry = std::ptr::null_mut();
        // SAFETY: live ACL/flagset and an initialized entry output pointer.
        // Darwin returns -1 with EINVAL at the end of an empty ACL, unlike
        // the POSIX ACL iterator convention. Other errors fail closed.
        let (no_inherit, first) = unsafe {
            (
                acl_get_flag_np(flags, ACL_FLAG_NO_INHERIT),
                acl_get_entry(acl.0, 0, &mut entry),
            )
        };
        let empty = first == -1 && io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL);
        if no_inherit != 1 || !empty {
            return Err(io::Error::other("export requires an empty non-inheriting ACL"));
        }
        Ok(())
    }
}

#[cfg(windows)]
fn publish(file: &File, dir: &SelectedDirectory, name: &OsStr) -> io::Result<()> {
    windows::publish(file, dir, name)
}

// Audited Windows FFI boundary, with no new dependency or lockfile graph.
// Windows pathname acquisition stays in cap-std; this operation takes handles.
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
