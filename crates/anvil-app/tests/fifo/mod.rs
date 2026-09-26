//! FIFO helpers shared by the local-file tests (Unix only).

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::time::Duration;

/// Runs `f` on its own thread, failing the test instead of hanging if it blocks.
pub fn within_seconds<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(Duration::from_secs(30)).expect("the open blocked")
}

/// Makes a FIFO at `path`.
#[allow(unsafe_code)]
pub fn mkfifo(path: &Path) {
    let c_path = CString::new(path.as_os_str().as_bytes()).unwrap();
    // SAFETY: `c_path` is a NUL-terminated string that outlives the call.
    let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) };
    assert_eq!(rc, 0, "mkfifo {}: {}", path.display(), std::io::Error::last_os_error());
}
