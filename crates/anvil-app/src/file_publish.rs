//! Publish the owned file, never a checked-then-resolved source pathname.
//! Native contracts and filesystem limits: docs/security/file-handle-safety.md.

use super::{DescriptorLease, SelectedDirectory};
use std::ffi::OsStr;
use std::fs::File;
use std::io;

#[cfg(all(test, target_os = "macos"))]
pub(crate) use macos::{MountProfile, set_test_mount_profile, with_test_mount_profile};

#[cfg(all(test, target_os = "macos"))]
pub(crate) fn test_mount_profile(dir: &SelectedDirectory) -> io::Result<MountProfile> {
    macos::mount_profile(dir)
}

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

    #[cfg(target_os = "macos")]
    pub(crate) fn check_before_write(&self, dir: &SelectedDirectory) -> io::Result<()> {
        macos::check_mount_policy(dir)?;
        macos::check_owner_only(&self.file)
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
    let is_procfs = libc::c_long::try_from(fstatfs(&proc)?.f_type).is_ok_and(|f_type| f_type == libc::PROC_SUPER_MAGIC);
    if !is_procfs {
        return Err(io::Error::other("descriptor publication needs authentic procfs"));
    }
    let descriptors = openat(&proc, "self/fd", flags, Mode::empty())?;
    let source = file.as_raw_fd().to_string();
    linkat(&descriptors, source, dir.dir(), name, AtFlags::SYMLINK_FOLLOW)?;
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
    macos::check_mount_policy(dir)?;
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

// Audited Darwin boundary: public ACL/filesec APIs and SDK attribute layout.
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

    // Darwin statfs.f_flags is uint32_t, while libc's MNT_* constants are
    // c_int. Preserve their bits explicitly, without an inferred `as _`.
    // Only these understood flags are allowed. In particular, read-only,
    // union, exported, ignore-ownership, automount and snapshot are refused.
    // Apple SDK sys/mount.h identifies MNT_DOVOLFS (0x00008000) as the
    // deprecated volfs capability, distinct from MNT_IGNORE_OWNERSHIP.
    // Hosted owned APFS reports it; admit only this identified extra bit.
    // These three public SDK sys/mount.h flags are not named by libc 0.2.189.
    const MNT_REMOVABLE: u32 = 0x0000_0200;
    const MNT_NOFOLLOW: u32 = 0x0800_0000;
    const MNT_STRICTATIME: u32 = 0x8000_0000;
    const ALLOWED_MOUNT_FLAGS: u32 = u32::from_ne_bytes(
        (libc::MNT_SYNCHRONOUS
            | libc::MNT_NOEXEC
            | libc::MNT_NOSUID
            | libc::MNT_NODEV
            | libc::MNT_ASYNC
            | libc::MNT_CPROTECT
            | libc::MNT_QUARANTINE
            | libc::MNT_LOCAL
            | libc::MNT_QUOTA
            | libc::MNT_ROOTFS
            | libc::MNT_DOVOLFS
            | libc::MNT_DONTBROWSE
            | libc::MNT_JOURNALED
            | libc::MNT_NOUSERXATTR
            | libc::MNT_DEFWRITE
            | libc::MNT_MULTILABEL
            | libc::MNT_NOATIME)
            .to_ne_bytes(),
    ) | MNT_REMOVABLE
        | MNT_NOFOLLOW
        | MNT_STRICTATIME;
    // Only MNT_EXT_ROOT_DATA_VOL is understood; FSKit and unknown extended
    // flags are refused. Both fields exist in the locked libc 0.2.189 ABI.
    const ALLOWED_EXT_FLAGS: u32 = 0x0000_0001;

    #[derive(Clone, Copy, Debug)]
    pub(crate) struct MountProfile {
        pub(crate) name: [u8; 16],
        pub(crate) flags: u32,
        pub(crate) extended_flags: u32,
    }

    pub(super) fn mount_profile(dir: &SelectedDirectory) -> io::Result<MountProfile> {
        // rustix's Darwin StatFs is the native libc::statfs. XNU gets this
        // mount from the held descriptor's vnode, never a fresh path walk.
        // f_type is a runtime VFS registration number, not a stable APFS ID;
        // f_fstypename is the kernel's filesystem type name.
        let stat = rustix::fs::fstatfs(dir.dir())?;
        Ok(MountProfile {
            name: stat.f_fstypename.map(|byte| byte.to_ne_bytes()[0]),
            flags: stat.f_flags,
            extended_flags: stat.f_flags_ext,
        })
    }

    pub(super) fn check_mount_policy(dir: &SelectedDirectory) -> io::Result<()> {
        let profile = mount_profile(dir)?;
        #[cfg(test)]
        let profile = TEST_MOUNT_PROFILE.with(|slot| slot.get().unwrap_or(profile));
        let end = profile.name.iter().position(|byte| *byte == 0);
        let local = u32::from_ne_bytes(libc::MNT_LOCAL.to_ne_bytes());
        let owners_ignored = u32::from_ne_bytes(libc::MNT_IGNORE_OWNERSHIP.to_ne_bytes());
        if end.is_none_or(|end| &profile.name[..end] != b"apfs")
            || profile.flags & local == 0
            || profile.flags & owners_ignored != 0
            || profile.flags & !ALLOWED_MOUNT_FLAGS != 0
            || profile.extended_flags & !ALLOWED_EXT_FLAGS != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "macOS exports require local APFS with ownership enabled and audited mount flags",
            ));
        }
        Ok(())
    }

    #[cfg(test)]
    thread_local! {
        static TEST_MOUNT_PROFILE: std::cell::Cell<Option<MountProfile>> = const {
            std::cell::Cell::new(None)
        };
    }

    #[cfg(test)]
    pub(crate) fn set_test_mount_profile(profile: Option<MountProfile>) {
        TEST_MOUNT_PROFILE.with(|slot| slot.set(profile));
    }

    #[cfg(test)]
    pub(crate) fn with_test_mount_profile<T>(profile: Option<MountProfile>, operation: impl FnOnce() -> T) -> T {
        struct Restore(Option<MountProfile>);
        impl Drop for Restore {
            fn drop(&mut self) {
                set_test_mount_profile(self.0);
            }
        }
        let restore = Restore(TEST_MOUNT_PROFILE.with(|slot| slot.replace(profile)));
        let result = operation();
        drop(restore);
        result
    }

    unsafe extern "C" {
        fn acl_init(count: c_int) -> *mut c_void;
        fn acl_free(acl: *mut c_void) -> c_int;
        fn acl_set_fd_np(fd: c_int, acl: *mut c_void, kind: c_int) -> c_int;
        fn acl_get_flagset_np(acl: *mut c_void, flags: *mut *mut c_void) -> c_int;
        fn acl_add_flag_np(flags: *mut c_void, flag: c_int) -> c_int;
        fn filesec_init() -> *mut c_void;
        fn filesec_free(security: *mut c_void);
        fn filesec_set_property(security: *mut c_void, property: c_int, value: *const c_void) -> c_int;
        fn openx_np(name: *const c_char, flags: c_int, security: *mut c_void) -> c_int;
        fn pthread_fchdir_np(fd: c_int) -> c_int;
    }

    struct Acl(*mut c_void);

    impl Acl {
        fn new(pointer: *mut c_void) -> io::Result<Self> {
            if pointer.is_null() { Err(io::Error::last_os_error()) } else { Ok(Self(pointer)) }
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
        if result == -1 { Err(io::Error::last_os_error()) } else { Ok(()) }
    }

    pub(super) fn create(dir: &SelectedDirectory) -> io::Result<File> {
        // Fail before dispatching ANY native staging creation. Descriptor
        // metadata after open cannot revoke a foreign pre-opened handle.
        check_mount_policy(dir)?;
        #[cfg(test)]
        crate::file_handles::test_checkpoint("macos_staging_dispatch");
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
            checked(filesec_set_property(security.0, FILESEC_MODE, (&mode as *const libc::mode_t).cast()))?;
            checked(filesec_set_property(security.0, FILESEC_ACL, (&acl.0 as *const *mut c_void).cast()))?;
            checked(pthread_fchdir_np(dir.dir().as_raw_fd()))?;
        }
        let flags = libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC;
        // Requery the held DIRECTORY on the creating thread immediately
        // before openx_np. Mount-administration races remain outside the
        // contract; retaining a descriptor does not freeze mount options.
        check_mount_policy(dir)?;
        // SAFETY: a live filesec and NUL-terminated single component are
        // borrowed through exclusive creation on the audited local APFS
        // mount, relative to this thread's retained directory vnode. XNU's
        // initial NO_INHERIT ACL suppresses directory ACE inheritance here.
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
        check_empty_acl(file)
    }

    // sys/kauth.h: KAUTH_FILESEC_SIZE(0), without the placeholder first ACE.
    // Libc's acl_get_fd_np/statx_np loses this valid 44-byte empty ACL by
    // testing against sizeof(kauth_filesec), which includes one 24-byte ACE.
    // getattrlist(2) returns the native filesec directly, including its flags.
    #[repr(C)]
    #[derive(Default)]
    struct EmptyFilesec {
        magic: u32,
        _owner: [u8; 16],
        _group: [u8; 16],
        entry_count: u32,
        flags: u32,
    }

    #[repr(C)]
    struct SecurityAttributes {
        length: u32,
        reference: libc::attrreference_t,
        security: EmptyFilesec,
    }

    fn check_empty_acl(file: &File) -> io::Result<()> {
        use std::mem::{offset_of, size_of};

        let mut attributes = libc::attrlist {
            bitmapcount: libc::ATTR_BIT_MAP_COUNT,
            reserved: 0,
            commonattr: libc::ATTR_CMN_EXTENDED_SECURITY,
            volattr: 0,
            dirattr: 0,
            fileattr: 0,
            forkattr: 0,
        };
        let mut result = SecurityAttributes {
            length: 0,
            reference: libc::attrreference_t { attr_dataoffset: 0, attr_length: 0 },
            security: EmptyFilesec::default(),
        };
        const _: () = assert!(size_of::<EmptyFilesec>() == 44);
        const _: () = assert!(offset_of!(SecurityAttributes, security) == 12);
        const _: () = assert!(size_of::<SecurityAttributes>() == 56);
        // SAFETY: SDK attrlist and a fully initialized, 4-byte-aligned output
        // buffer are borrowed for a synchronous descriptor query. Request
        // only extended security. REPORT_FULLSIZE detects truncation of a
        // nonempty ACL; no absent, truncated or unexpected layout is accepted.
        checked(unsafe {
            libc::fgetattrlist(
                file.as_raw_fd(),
                (&mut attributes as *mut libc::attrlist).cast(),
                (&mut result as *mut SecurityAttributes).cast(),
                size_of::<SecurityAttributes>(),
                libc::FSOPT_REPORT_FULLSIZE,
            )
        })?;
        if result.length != 56
            || result.reference.attr_dataoffset != 8
            || result.reference.attr_length != 44
            || result.security.magic != 0x012c_c16d
            || result.security.entry_count != 0
            || result.security.flags & (1 << 17) == 0
        {
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
        replace_if_exists: u8,
        root_directory: *mut c_void,
        file_name_length: u32,
        file_name: [u16; 1],
    }

    // winternl.h IO_STATUS_BLOCK: NTSTATUS/PVOID union, then ULONG_PTR.
    #[repr(C)]
    union IoStatus {
        _status: i32,
        pointer: *mut c_void,
    }

    #[repr(C)]
    struct IoStatusBlock {
        status: IoStatus,
        information: usize,
    }

    #[link(name = "ntdll")]
    unsafe extern "system" {
        #[link_name = "NtSetInformationFile"]
        fn nt_set_information_file(file: *mut c_void, status: *mut IoStatusBlock, information: *mut c_void, size: u32, class: i32) -> i32;
        #[link_name = "RtlNtStatusToDosError"]
        fn rtl_nt_status_to_dos_error(status: i32) -> u32;
    }

    pub(super) fn publish(file: &File, dir: &SelectedDirectory, name: &OsStr) -> io::Result<()> {
        let name: Vec<u16> = name.encode_wide().collect();
        let special = name == [46] || name == [46, 46];
        if name.is_empty() || special || name.iter().any(|c| matches!(*c, 0 | 47 | 58 | 92)) {
            return Err(io::Error::other("publication requires one ordinary file name"));
        }
        let bytes = name.len().checked_mul(2).ok_or_else(|| io::Error::other("name too long"))?;
        let offset = offset_of!(RenameInfo, file_name);
        let size = size_of::<RenameInfo>().checked_add(bytes).ok_or_else(|| io::Error::other("name too long"))?;
        let size32 = u32::try_from(size).map_err(|_| io::Error::other("name too long"))?;
        let bytes32 = u32::try_from(bytes).map_err(|_| io::Error::other("name too long"))?;
        // usize storage provides the C struct's pointer alignment on both
        // Windows architectures. Zeroed padding and a trailing NUL are kept.
        assert!(align_of::<usize>() >= align_of::<RenameInfo>());
        let mut storage = vec![0usize; size.div_ceil(size_of::<usize>())];
        let pointer = storage.as_mut_ptr().cast::<RenameInfo>();
        let mut completion = IoStatusBlock { status: IoStatus { pointer: std::ptr::null_mut() }, information: 0 };
        // SAFETY: storage is aligned, initialized and large enough for the
        // complete header plus all UTF-16 units. Both handles are borrowed
        // from live owners. create() uses cap-std's synchronous NtCreateFile
        // handle (FILE_SYNCHRONOUS_IO_NONALERT), so all I/O completes before
        // these buffers drop. NT class 10 is FileRenameInformation, whose
        // documented relative form takes a directory handle and simple name.
        // FALSE forbids replacement; no extended/POSIX flags are requested.
        // Use the native rooted-name contract directly instead of relying on
        // SetFileInformationByHandle's Win32 path-form handling.
        let status = unsafe {
            // Write fields individually so the zeroed union/padding bytes
            // stay initialized too, rather than copying Rust struct padding.
            (*pointer).replace_if_exists = 0;
            (*pointer).root_directory = dir.dir().as_raw_handle();
            (*pointer).file_name_length = bytes32;
            let destination = storage.as_mut_ptr().cast::<u8>().add(offset).cast::<u16>();
            std::ptr::copy_nonoverlapping(name.as_ptr(), destination, name.len());
            nt_set_information_file(file.as_raw_handle(), &mut completion, pointer.cast(), size32, 10)
        };
        if status < 0 {
            // Nt APIs return NTSTATUS, not a Win32 last-error value.
            // SAFETY: this conversion accepts any NTSTATUS and borrows nothing.
            let code = unsafe { rtl_nt_status_to_dos_error(status) };
            let code = i32::try_from(code).map_err(|_| io::Error::other(format!("rename failed: NTSTATUS {status:#x}")))?;
            Err(io::Error::from_raw_os_error(code))
        } else {
            Ok(())
        }
    }

    #[test]
    fn native_rename_layout_matches_the_windows_sdk() {
        let pointer = size_of::<usize>();
        assert_eq!(offset_of!(RenameInfo, root_directory), pointer);
        assert_eq!(offset_of!(RenameInfo, file_name_length), 2 * pointer);
        assert_eq!(offset_of!(RenameInfo, file_name), 2 * pointer + 4);
        assert_eq!(size_of::<RenameInfo>(), 2 * pointer + 8);
        assert_eq!(size_of::<IoStatus>(), pointer);
        assert_eq!(offset_of!(IoStatusBlock, information), pointer);
        assert_eq!(size_of::<IoStatusBlock>(), 2 * pointer);
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
