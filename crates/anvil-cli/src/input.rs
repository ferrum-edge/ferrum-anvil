//! Bounded reads of the files a command imports. A limit is enforced while
//! the file is read, not only from its size beforehand: a file that grows
//! while it is read, or a pipe whose size is unknown, is never buffered
//! past its limit.

use anyhow::{Context, Result};
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

/// Append what `reader` yields to `bytes` until it is exhausted or `bytes`
/// holds more than `max` bytes. At most `max + 1` bytes are held, however
/// much `reader` would yield. Returns whether everything fit in `max`.
fn read_within(reader: impl Read, max: u64, bytes: &mut Vec<u8>) -> io::Result<bool> {
    reader.take(max.saturating_add(1).saturating_sub(bytes.len() as u64)).read_to_end(bytes)?;
    Ok(bytes.len() as u64 <= max)
}

/// Read the file at `path` (or the pipe or device there, such as a shell's
/// process substitution) if it holds at most `max` bytes; `None` when it
/// holds more. A regular file larger than `max` is refused before anything
/// is read.
pub fn read_file_within(path: &Path, max: u64) -> io::Result<Option<Vec<u8>>> {
    let file = File::open(path)?;
    let meta = file.metadata()?;
    let mut bytes = Vec::new();
    if meta.is_file() {
        if meta.len() > max {
            return Ok(None);
        }
        bytes.reserve(meta.len() as usize);
    }
    Ok(read_within(&file, max, &mut bytes)?.then_some(bytes))
}

/// The bundle or full backup `anvil import` reads from `path`, which must be
/// a regular file. As the desktop's import does, its start decides the most
/// that is read (see [`anvil_app::backup::import_read_limit`]): a backup
/// whose header cannot be opened, or that came with no passphrase, is refused
/// before the rest is read, and anything else is read only up to the largest
/// bundle. A larger file is refused unread.
pub fn read_import_file(path: &Path, passphrase: Option<&str>) -> Result<Vec<u8>> {
    let context = || format!("reading {}", path.display());
    let not_regular = || anyhow::anyhow!("{} is not a regular file; nothing was imported", path.display());
    // A cheap filter. What counts is the opened handle: the open does not
    // wait for a writer on a FIFO swapped in since (a blocking open would),
    // and anything but a regular file is refused before it is read.
    if !std::fs::metadata(path).with_context(context)?.is_file() {
        return Err(not_regular());
    }
    let (file, meta) = anvil_app::file_grants::open_regular_file(path).with_context(context)?.ok_or_else(not_regular)?;
    read_import(&file, meta.len(), passphrase).with_context(context)
}

/// [`read_import_file`] of what `reader` yields, `size` bytes by its
/// metadata (it may yield more: what is read is bounded too).
fn read_import(reader: impl Read, size: u64, passphrase: Option<&str>) -> Result<Vec<u8>> {
    read_import_with(reader, size, |start, size| Ok(anvil_app::backup::import_read_limit(start, size, passphrase)?))
}

/// Read what `reader` yields, up to the limit `limit` decides from its first
/// [`anvil_app::backup::HEADER_PREFIX_BYTES`] and `size`.
fn read_import_with(mut reader: impl Read, size: u64, limit: impl FnOnce(&[u8], u64) -> Result<u64>) -> Result<Vec<u8>> {
    let too_large = |max: u64| anyhow::anyhow!("the file is larger than {max} bytes, the most an import reads of it; nothing was imported");
    let mut bytes = Vec::new();
    // The start first: what it says can refuse the file before the rest is read.
    reader.by_ref().take(anvil_app::backup::HEADER_PREFIX_BYTES as u64).read_to_end(&mut bytes)?;
    let max = limit(&bytes, size)?;
    if size > max {
        return Err(too_large(max));
    }
    bytes.reserve(size.saturating_sub(bytes.len() as u64) as usize);
    if !read_within(reader, max, &mut bytes)? {
        return Err(too_large(max));
    }
    Ok(bytes)
}

/// Runs `f` on its own thread, failing the test instead of hanging if it
/// blocks (an open of a FIFO that waits for its other end, say).
#[cfg(all(test, unix))]
pub(crate) fn within_seconds<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(std::time::Duration::from_secs(30)).expect("it blocked")
}

/// Makes a FIFO at `path`.
#[cfg(all(test, unix))]
pub(crate) fn mkfifo(path: &Path) {
    let made = std::process::Command::new("mkfifo").arg(path).status().unwrap();
    assert!(made.success(), "mkfifo {}", path.display());
}

/// A FIFO at `path`, and a thread writing `len` bytes into it once a reader
/// opens it. Wait for the writer with [`writer_done`].
#[cfg(all(test, unix))]
pub(crate) fn fifo_with(path: &Path, len: usize) -> std::sync::mpsc::Receiver<()> {
    mkfifo(path);
    let path = path.to_path_buf();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        use std::io::Write;
        if let Ok(mut w) = std::fs::OpenOptions::new().write(true).open(path) {
            // The reader stops one byte past its limit and closes the pipe,
            // so the rest of a longer write fails; that is expected.
            let _ = w.write_all(&vec![b'a'; len]);
        }
        let _ = tx.send(());
    });
    rx
}

/// Wait for a [`fifo_with`] writer to finish, failing instead of hanging
/// when no reader ever opened the FIFO.
#[cfg(all(test, unix))]
pub(crate) fn writer_done(writer: std::sync::mpsc::Receiver<()>) {
    writer.recv_timeout(std::time::Duration::from_secs(30)).expect("the FIFO writer finished (a reader opened the FIFO)");
}

#[cfg(test)]
mod tests {
    use super::*;
    use anvil_app::backup::{HEADER_PREFIX_BYTES, MAX_BACKUP_BYTES};
    use anvil_portability::bundle::MAX_BUNDLE_FILE_BYTES;

    /// Counts what is read from `inner`.
    struct Counting<R> {
        inner: R,
        read: u64,
    }

    impl<R: Read> Read for Counting<R> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let n = self.inner.read(buf)?;
            self.read += n as u64;
            Ok(n)
        }
    }

    fn counting<R: Read>(inner: R) -> Counting<R> {
        Counting { inner, read: 0 }
    }

    #[test]
    fn a_reader_yielding_more_than_the_limit_is_refused_after_one_byte_more() {
        let mut endless = counting(io::repeat(7));
        let mut bytes = Vec::new();
        assert!(!read_within(&mut endless, 1024, &mut bytes).unwrap());
        assert_eq!(bytes.len(), 1025);
        assert_eq!(endless.read, 1025, "never more than one byte past the limit");

        let mut bytes = Vec::new();
        assert!(read_within(&[1u8; 1024][..], 1024, &mut bytes).unwrap(), "exactly the limit fits");
        assert_eq!(bytes.len(), 1024);
    }

    #[test]
    fn an_oversized_import_is_refused_after_its_start_only() {
        // A bundle (anything without the backup signature) larger than the
        // largest bundle is refused once its start has been read.
        let mut file = counting(io::repeat(0));
        let err = read_import(&mut file, MAX_BUNDLE_FILE_BYTES + 1, None).unwrap_err();
        assert!(err.to_string().contains(&format!("larger than {MAX_BUNDLE_FILE_BYTES} bytes")), "{err:#}");
        assert_eq!(file.read, HEADER_PREFIX_BYTES as u64, "only the start was read");

        // A full backup's own ceiling is decided from its start as well.
        let mut start = b"ANVILBAK".to_vec();
        start.extend_from_slice(&64u32.to_be_bytes());
        let mut file = counting(Read::chain(&start[..], io::repeat(0)));
        let err = read_import(&mut file, MAX_BACKUP_BYTES + 1, Some("passphrase")).unwrap_err();
        assert!(err.to_string().contains(&format!("larger than {MAX_BACKUP_BYTES} bytes")), "{err:#}");
        assert_eq!(file.read, HEADER_PREFIX_BYTES as u64, "only the start was read");
    }

    #[test]
    fn a_backup_whose_header_cannot_be_opened_is_refused_after_its_start_only() {
        // The signature, then a header length over the header limit.
        let mut start = b"ANVILBAK".to_vec();
        start.extend_from_slice(&(HEADER_PREFIX_BYTES as u32).to_be_bytes());
        let mut file = counting(Read::chain(&start[..], io::repeat(0)));
        let err = read_import(&mut file, 64 * 1024 * 1024, Some("passphrase")).unwrap_err();
        assert!(err.to_string().contains("not an Anvil full backup"), "{err:#}");
        assert_eq!(file.read, HEADER_PREFIX_BYTES as u64, "only the start was read");
    }

    #[test]
    fn an_import_that_grows_past_its_size_is_read_only_to_its_limit() {
        // A small bundle file: all of it is read.
        let bundle = vec![b'P'; HEADER_PREFIX_BYTES + 10];
        assert_eq!(read_import(&bundle[..], bundle.len() as u64, None).unwrap(), bundle);
        // One whose size said little but that yields more is cut one byte
        // past the limit its start decided.
        let mut grown = counting(io::repeat(0));
        let limit = HEADER_PREFIX_BYTES as u64 + 1024;
        let err = read_import_with(&mut grown, 10, |start, size| {
            assert_eq!((start.len(), size), (HEADER_PREFIX_BYTES, 10));
            Ok(limit)
        })
        .unwrap_err();
        assert!(err.to_string().contains(&format!("larger than {limit} bytes")), "{err:#}");
        assert_eq!(grown.read, limit + 1, "never more than one byte past the limit");
    }

    #[test]
    fn a_regular_file_over_the_limit_is_refused_unread() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("big");
        std::fs::File::create(&path).unwrap().set_len(1025).unwrap();
        assert!(read_file_within(&path, 1024).unwrap().is_none());
        std::fs::write(&path, [1u8; 1024]).unwrap();
        assert_eq!(read_file_within(&path, 1024).unwrap().unwrap(), vec![1u8; 1024]);
    }

    #[test]
    fn an_import_of_a_file_that_is_not_regular_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let err = read_import_file(dir.path(), None).unwrap_err();
        assert!(err.to_string().contains("not a regular file"), "{err:#}");
    }

    #[cfg(unix)]
    #[test]
    fn a_pipe_is_read_only_to_its_limit() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("over");
        let writer = fifo_with(&path, 1024 * 1024);
        let read = within_seconds(move || read_file_within(&path, 1024));
        assert!(read.unwrap().is_none(), "a pipe has no size to check first");
        writer_done(writer);

        let path = dir.path().join("within");
        let writer = fifo_with(&path, 100);
        let read = within_seconds(move || read_file_within(&path, 1024));
        assert_eq!(read.unwrap().unwrap(), vec![b'a'; 100]);
        writer_done(writer);
    }

    #[cfg(unix)]
    #[test]
    fn an_import_of_a_pipe_is_refused_without_waiting_for_a_writer() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pipe");
        mkfifo(&path);
        // There is no writer: a blocking open would wait for one forever.
        let p = path.clone();
        let err = within_seconds(move || read_import_file(&p, None)).unwrap_err();
        assert!(err.to_string().contains("not a regular file"), "{err:#}");
        // A link to it too.
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        let err = within_seconds(move || read_import_file(&link, None)).unwrap_err();
        assert!(err.to_string().contains("not a regular file"), "{err:#}");
    }

    /// The path check is only a filter: a FIFO swapped in after it reaches
    /// the opener, which must neither wait for a writer nor accept it.
    #[cfg(unix)]
    #[test]
    fn the_opener_refuses_a_pipe_without_waiting_for_a_writer() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pipe");
        mkfifo(&path);
        let opened = within_seconds(move || anvil_app::file_grants::open_regular_file(&path));
        assert!(opened.unwrap().is_none(), "a FIFO is not a regular file");
    }

    #[cfg(unix)]
    #[test]
    fn an_import_follows_a_link_to_a_regular_file() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("bundle.anvil-workspace");
        std::fs::write(&target, b"PK not really a bundle").unwrap();
        let link = dir.path().join("link.anvil-workspace");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert_eq!(read_import_file(&link, None).unwrap(), b"PK not really a bundle");
    }
}
