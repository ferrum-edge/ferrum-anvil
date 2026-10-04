//! Handle-backed native selections. Absolute paths are display/binding keys;
//! after selection, I/O uses one-component names and retained directories.

use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::fs::{Dir, OpenOptions};
use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::fs::{File, Metadata};
use std::io;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

#[path = "file_publish.rs"]
pub(crate) mod publication;

/// Charged until the last retained handle closes, including old contexts.
/// Each grant registry and opened profile has its own 512-descriptor budget.
#[derive(Debug, Default)]
pub(crate) struct DescriptorBudget {
    used: AtomicUsize,
}

const MAX_DESCRIPTORS: usize = 512;

#[derive(Debug)]
pub(crate) struct DescriptorLease {
    budget: Arc<DescriptorBudget>,
    count: usize,
}

impl DescriptorBudget {
    pub(crate) fn reserve(self: &Arc<Self>) -> io::Result<DescriptorLease> {
        let mut lease = DescriptorLease { budget: self.clone(), count: 0 };
        lease.grow()?;
        Ok(lease)
    }

    #[cfg(test)]
    pub(crate) fn used(&self) -> usize {
        self.used.load(Ordering::Acquire)
    }
}

impl DescriptorLease {
    fn grow(&mut self) -> io::Result<()> {
        self.budget
            .used
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| (used < MAX_DESCRIPTORS).then_some(used + 1))
            .map_err(|_| invalid("too many retained file descriptors; release selections first"))?;
        self.count += 1;
        Ok(())
    }
}

impl Drop for DescriptorLease {
    fn drop(&mut self) {
        self.budget.used.fetch_sub(self.count, Ordering::AcqRel);
    }
}

#[derive(Default)]
pub(crate) struct LinkedSelections {
    pub(crate) generation: u64,
    pub(crate) handles: HashMap<anvil_domain::Id, Arc<SelectedFile>>,
    pub(crate) budget: Arc<DescriptorBudget>,
}

impl LinkedSelections {
    pub(crate) fn revoke(&mut self) -> HashMap<anvil_domain::Id, Arc<SelectedFile>> {
        for selected in self.handles.values() {
            selected.revoke();
        }
        self.generation = self.generation.wrapping_add(1);
        std::mem::take(&mut self.handles)
    }
}

impl Drop for LinkedSelections {
    fn drop(&mut self) {
        drop(self.revoke());
    }
}

pub(crate) type FileId = (u64, u64);

#[cfg(unix)]
pub(crate) fn file_id(_file: &File, meta: &Metadata) -> io::Result<FileId> {
    use std::os::unix::fs::MetadataExt;
    Ok((meta.dev(), meta.ino()))
}

#[cfg(windows)]
pub(crate) fn file_id(file: &File, _meta: &Metadata) -> io::Result<FileId> {
    let info = winapi_util::file::information(file)?;
    Ok((info.volume_serial_number(), info.file_index()))
}

#[cfg(not(any(unix, windows)))]
compile_error!("native file selections need a supported filesystem handle implementation");

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

pub(crate) fn no_reparse(meta: &Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0
    }
    #[cfg(not(windows))]
    {
        !meta.file_type().is_symlink()
    }
}

/// Keep the entire chain, including on Windows where retained handles deny
/// directory deletion throughout component acquisition and selected I/O.
/// No absolute pathname is reconstructed by application code for I/O.
#[derive(Debug)]
pub(crate) struct SelectedDirectory {
    chain: Vec<Dir>,
    // Drop the descriptors before returning their budget.
    _lease: DescriptorLease,
}

impl SelectedDirectory {
    /// `path` is an absolute, already canonical chooser result. Each normal
    /// component is opened alone with no-follow, relative to the preceding
    /// descriptor. A swapped symlink/junction cannot be traversed.
    pub(crate) fn open(path: &Path, budget: &Arc<DescriptorBudget>) -> io::Result<Self> {
        if !path.is_absolute() {
            return Err(invalid("the chosen directory has no absolute path"));
        }
        let mut root = PathBuf::new();
        let mut names = Vec::new();
        for component in path.components() {
            match component {
                Component::Prefix(prefix) => {
                    #[cfg(windows)]
                    {
                        use std::path::Prefix;
                        if !matches!(
                            prefix.kind(),
                            Prefix::Disk(_) | Prefix::VerbatimDisk(_) | Prefix::UNC(_, _) | Prefix::VerbatimUNC(_, _)
                        ) {
                            return Err(invalid("the chosen directory uses an unsupported Windows namespace"));
                        }
                    }
                    root.push(prefix.as_os_str());
                }
                Component::RootDir => root.push(component.as_os_str()),
                Component::Normal(name) => names.push(name),
                _ => return Err(invalid("the chosen directory contains a non-normal component")),
            }
        }
        let mut lease = budget.reserve()?;
        let mut chain = vec![Dir::open_ambient_dir(root, cap_std::ambient_authority())?];
        for name in names {
            lease.grow()?;
            let next = chain.last().expect("root handle").open_dir_nofollow(name)?;
            let meta = next.try_clone()?.into_std_file().metadata()?;
            if !meta.is_dir() || !no_reparse(&meta) {
                return Err(invalid("the chosen directory contains a link or reparse point"));
            }
            chain.push(next);
        }
        Ok(Self { chain, _lease: lease })
    }

    pub(crate) fn dir(&self) -> &Dir {
        self.chain.last().expect("root handle")
    }

    pub(crate) fn reserve(&self) -> io::Result<DescriptorLease> {
        self._lease.budget.reserve()
    }

    pub(crate) fn leaf(path: &Path) -> io::Result<OsString> {
        let name = path.file_name().ok_or_else(|| invalid("choose a file name, not a folder"))?;
        #[cfg(windows)]
        if name.to_string_lossy().contains(':') {
            return Err(invalid("alternate data streams are not file selections"));
        }
        Ok(name.to_owned())
    }
}

/// The original file remains open to prevent file-ID reuse during a session.
/// Reads reopen only its leaf relative to the selected directory and compare
/// the actual opened object. In-place edits remain visible; replacement files
/// require a new native selection.
#[derive(Debug)]
pub(crate) struct SelectedFile {
    pub(crate) path: PathBuf,
    pub(crate) parent: Arc<SelectedDirectory>,
    name: OsString,
    original: File,
    id: FileId,
    revoked: AtomicBool,
    _lease: DescriptorLease,
}

impl SelectedFile {
    pub(crate) fn choose(picked: &Path, budget: &Arc<DescriptorBudget>) -> io::Result<Self> {
        if !picked.is_absolute() {
            return Err(invalid("the chosen file has no absolute path"));
        }
        let path = std::fs::canonicalize(picked)?;
        Self::open_canonical(path, budget)
    }

    pub(crate) fn open_canonical(path: PathBuf, budget: &Arc<DescriptorBudget>) -> io::Result<Self> {
        #[cfg(test)]
        test_checkpoint("choose_canonical");
        let directory = path.parent().ok_or_else(|| invalid("not a regular file"))?;
        let parent = Arc::new(SelectedDirectory::open(directory, budget)?);
        let name = SelectedDirectory::leaf(&path)?;
        let lease = budget.reserve()?;
        let (original, meta) = open_regular_at(parent.dir(), &name)?.ok_or_else(|| invalid("not a regular file"))?;
        let id = file_id(&original, &meta)?;
        Ok(Self { path, parent, name, original, id, revoked: AtomicBool::new(false), _lease: lease })
    }

    pub(crate) fn open(&self) -> io::Result<Option<(File, Metadata)>> {
        if self.revoked.load(Ordering::Acquire) {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "the native selection was revoked; choose it again"));
        }
        // Keep the original descriptor alive through comparison and reading.
        let _original = &self.original;
        let Some((file, meta)) = open_regular_at(self.parent.dir(), &self.name)? else {
            return Ok(None);
        };
        if file_id(&file, &meta)? != self.id {
            return Ok(None);
        }
        Ok(Some((file, meta)))
    }

    pub(crate) fn revoke(&self) {
        self.revoked.store(true, Ordering::Release);
    }
}

#[cfg(test)]
type TestHook = Box<dyn FnMut(&str)>;

#[cfg(test)]
thread_local! {
    static TEST_HOOK: std::cell::RefCell<Option<TestHook>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(crate) fn test_checkpoint(point: &str) {
    TEST_HOOK.with_borrow_mut(|hook| {
        if let Some(hook) = hook {
            hook(point);
        }
    });
}

#[cfg(test)]
pub(crate) fn with_test_hook<T>(hook: impl FnMut(&str) + 'static, operation: impl FnOnce() -> T) -> T {
    TEST_HOOK.with_borrow_mut(|slot| *slot = Some(Box::new(hook)));
    let result = operation();
    TEST_HOOK.with_borrow_mut(|slot| *slot = None);
    result
}

pub(crate) fn open_regular_at(dir: &Dir, name: &OsStr) -> io::Result<Option<(File, Metadata)>> {
    // Cheap nonblocking filter only; authorization below uses the descriptor.
    if !dir.symlink_metadata(name)?.is_file() {
        return Ok(None);
    }
    #[cfg(test)]
    test_checkpoint("leaf_checked");
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY);
    }
    let file = dir.open_with(name, &options)?.into_std();
    let meta = file.metadata()?;
    Ok((meta.is_file() && no_reparse(&meta)).then_some((file, meta)))
}

#[cfg(test)]
#[path = "file_handle_tests.rs"]
mod tests;
