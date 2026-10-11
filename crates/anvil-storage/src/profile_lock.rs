//! Cooperative process fence for key changes. Lock failure is never ignored.
//!
//! Waits are bounded: a holder that keeps the fence longer than
//! [`LOCK_WAIT`] (a long rotation in another process, or a stuck one) makes
//! the waiter fail with a "profile busy" error it may retry, rather than
//! hang. A file system that does not support file locks fails with a clear
//! error naming that, never with a bare I/O error.
use std::{
    fs::{File, OpenOptions, TryLockError},
    path::Path,
    time::{Duration, Instant},
};

pub(crate) const LOCK_FILE: &str = "profile-data.lock";
/// How long a data operation or rotation waits for the fence.
pub(crate) const LOCK_WAIT: Duration = Duration::from_secs(15);
const POLL: Duration = Duration::from_millis(10);
const MAX_POLL: Duration = Duration::from_millis(200);

/// Message of the error returned when the fence was not free in time.
pub(crate) const BUSY: &str = "the profile is busy: another Anvil window or process is changing its encryption key; try again";

pub(crate) fn shared(dir: &Path) -> std::io::Result<File> {
    acquire(dir, LOCK_FILE, lock_wait(), File::try_lock_shared)
}
pub(crate) fn exclusive(dir: &Path) -> std::io::Result<File> {
    acquire(dir, LOCK_FILE, lock_wait(), File::try_lock)
}
/// The exclusive lock on another lock file of the profile (the header
/// writers' lock), with the same bounded wait.
pub(crate) fn exclusive_named(dir: &Path, name: &str) -> std::io::Result<File> {
    acquire(dir, name, lock_wait(), File::try_lock)
}

fn lock_wait() -> Duration {
    #[cfg(test)]
    if let Some(wait) = TEST_LOCK_WAIT.get() {
        return wait;
    }
    LOCK_WAIT
}

#[cfg(test)]
thread_local! {
    /// Shortens [`LOCK_WAIT`] for the tests of the current thread.
    pub(crate) static TEST_LOCK_WAIT: std::cell::Cell<Option<Duration>> = const { std::cell::Cell::new(None) };
}

/// Whether `e` is the bounded wait running out (see [`LOCK_WAIT`]).
pub(crate) fn is_busy(e: &std::io::Error) -> bool {
    e.kind() == std::io::ErrorKind::WouldBlock
}

fn acquire(dir: &Path, name: &str, wait: Duration, try_lock: fn(&File) -> Result<(), TryLockError>) -> std::io::Result<File> {
    let file = open(dir, name)?;
    let deadline = Instant::now() + wait;
    let mut pause = POLL;
    loop {
        match try_lock(&file) {
            Ok(()) => return Ok(file),
            Err(TryLockError::WouldBlock) if Instant::now() < deadline => {
                std::thread::sleep(pause.min(deadline.saturating_duration_since(Instant::now())));
                pause = (pause * 2).min(MAX_POLL);
            }
            Err(TryLockError::WouldBlock) => return Err(std::io::Error::new(std::io::ErrorKind::WouldBlock, BUSY)),
            Err(TryLockError::Error(e)) => return Err(unsupported(dir, e)),
        }
    }
}

/// A file system without lock support (some network and FUSE mounts) gets
/// an error that says so; other failures are returned as they are.
fn unsupported(dir: &Path, e: std::io::Error) -> std::io::Error {
    #[cfg(unix)]
    let no_locks = e.raw_os_error().is_some_and(|c| c == libc::ENOLCK || c == libc::ENOTSUP || c == libc::EOPNOTSUPP);
    #[cfg(not(unix))]
    let no_locks = false;
    if no_locks || e.kind() == std::io::ErrorKind::Unsupported {
        return std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            format!(
                "the file system holding the profile at {} does not support file locks, which Anvil requires; move the profile to a local disk ({e})",
                dir.display()
            ),
        );
    }
    e
}

fn open(dir: &Path, name: &str) -> std::io::Result<File> {
    std::fs::create_dir_all(dir)?;
    OpenOptions::new().create(true).truncate(false).read(true).write(true).open(dir.join(name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_held_exclusive_fence_makes_waiters_fail_busy_within_the_bound() {
        let dir = tempfile::tempdir().unwrap();
        let _held = exclusive(dir.path()).unwrap();
        let started = Instant::now();
        let e = acquire(dir.path(), LOCK_FILE, Duration::from_millis(150), File::try_lock_shared).unwrap_err();
        assert!(is_busy(&e), "{e}");
        assert!(e.to_string().contains("profile is busy"));
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn a_fence_released_during_the_wait_is_acquired() {
        let dir = tempfile::tempdir().unwrap();
        let held = exclusive(dir.path()).unwrap();
        let path = dir.path().to_path_buf();
        let waiter = std::thread::spawn(move || acquire(&path, LOCK_FILE, Duration::from_secs(10), File::try_lock_shared).map(drop));
        std::thread::sleep(Duration::from_millis(50));
        drop(held);
        waiter.join().unwrap().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_file_system_without_locks_is_named_as_such() {
        for code in [libc::ENOLCK, libc::ENOTSUP, libc::EOPNOTSUPP] {
            let e = unsupported(Path::new("/profiles/p"), std::io::Error::from_raw_os_error(code));
            assert_eq!(e.kind(), std::io::ErrorKind::Unsupported);
            assert!(e.to_string().contains("does not support file locks"), "{e}");
        }
        let other = unsupported(Path::new("/profiles/p"), std::io::Error::from_raw_os_error(libc::EACCES));
        assert_eq!(other.kind(), std::io::ErrorKind::PermissionDenied);
    }
}
