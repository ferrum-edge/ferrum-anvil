//! Connection-level byte and timing instrumentation.
//!
//! `CountingIo` wraps the raw transport (TCP or TLS-over-TCP) and records
//! bytes read/written plus the first read after a caller-set mark. Counters
//! are connection-scoped: on multiplexed HTTP/2 connections they include other
//! streams and control frames, and are reported with that scope.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Instant;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[derive(Debug)]
pub struct ConnStats {
    epoch: Instant,
    bytes_read: AtomicU64,
    bytes_written: AtomicU64,
    /// Nanoseconds since epoch of the first read after `mark_awaiting_read`,
    /// or 0 when none yet.
    first_read_after_mark_ns: AtomicU64,
    mark_armed: AtomicU64,
    /// Typed TLS error observed on the decrypted stream (captured before
    /// higher layers such as h2 flatten it into text).
    tls_error: parking_lot::Mutex<Option<(anvil_domain::execution::FailureKind, Option<String>)>>,
}

impl ConnStats {
    pub fn new() -> Arc<Self> {
        Arc::new(ConnStats {
            epoch: Instant::now(),
            bytes_read: AtomicU64::new(0),
            bytes_written: AtomicU64::new(0),
            first_read_after_mark_ns: AtomicU64::new(0),
            mark_armed: AtomicU64::new(0),
            tls_error: parking_lot::Mutex::new(None),
        })
    }

    pub fn bytes_read(&self) -> u64 {
        self.bytes_read.load(Ordering::Relaxed)
    }

    pub fn bytes_written(&self) -> u64 {
        self.bytes_written.load(Ordering::Relaxed)
    }

    /// Arm the "first read after now" probe (used for first-response-byte timing).
    pub fn mark_awaiting_read(&self) {
        self.first_read_after_mark_ns.store(0, Ordering::Relaxed);
        self.mark_armed.store(1, Ordering::Relaxed);
    }

    /// Instant of the first read observed after the last mark, if any.
    pub fn first_read_after_mark(&self) -> Option<Instant> {
        let ns = self.first_read_after_mark_ns.load(Ordering::Relaxed);
        if ns == 0 {
            None
        } else {
            Some(self.epoch + std::time::Duration::from_nanos(ns))
        }
    }

    /// Typed TLS failure seen on this connection after the handshake, if any.
    pub fn tls_error(&self) -> Option<(anvil_domain::execution::FailureKind, Option<String>)> {
        self.tls_error.lock().clone()
    }

    fn record_io_error(&self, e: &io::Error) {
        if let Some(r) = e.get_ref().and_then(|i| i.downcast_ref::<rustls::Error>()) {
            let mut g = self.tls_error.lock();
            if g.is_none() {
                *g = Some(crate::errors::classify_rustls(r, true));
            }
        }
    }

    fn record_read(&self, n: usize) {
        if n == 0 {
            return;
        }
        self.bytes_read.fetch_add(n as u64, Ordering::Relaxed);
        if self.mark_armed.load(Ordering::Relaxed) == 1 {
            let ns = self.epoch.elapsed().as_nanos().max(1) as u64;
            if self
                .first_read_after_mark_ns
                .compare_exchange(0, ns, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                self.mark_armed.store(0, Ordering::Relaxed);
            }
        }
    }

    fn record_write(&self, n: usize) {
        self.bytes_written.fetch_add(n as u64, Ordering::Relaxed);
    }
}

/// Byte-counting I/O wrapper.
pub struct CountingIo<T> {
    inner: T,
    stats: Arc<ConnStats>,
}

impl<T> CountingIo<T> {
    pub fn new(inner: T, stats: Arc<ConnStats>) -> Self {
        CountingIo { inner, stats }
    }

    pub fn get_ref(&self) -> &T {
        &self.inner
    }

    pub fn get_mut(&mut self) -> &mut T {
        &mut self.inner
    }

    pub fn into_inner(self) -> T {
        self.inner
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for CountingIo<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let r = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &r {
            let n = buf.filled().len() - before;
            self.stats.record_read(n);
        }
        r
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for CountingIo<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let r = Pin::new(&mut self.inner).poll_write(cx, data);
        if let Poll::Ready(Ok(n)) = &r {
            self.stats.record_write(*n);
        }
        r
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let r = Pin::new(&mut self.inner).poll_write_vectored(cx, bufs);
        if let Poll::Ready(Ok(n)) = &r {
            self.stats.record_write(*n);
        }
        r
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Error tap placed directly above the TLS stream: records typed rustls
/// errors (e.g. a `certificate_required` alert delivered after the client
/// finished its handshake) into [`ConnStats`].
pub struct TlsErrorTap<T> {
    inner: T,
    stats: Arc<ConnStats>,
}

impl<T> TlsErrorTap<T> {
    pub fn new(inner: T, stats: Arc<ConnStats>) -> Self {
        TlsErrorTap { inner, stats }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for TlsErrorTap<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let r = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Err(e)) = &r {
            self.stats.record_io_error(e);
        }
        r
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for TlsErrorTap<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let r = Pin::new(&mut self.inner).poll_write(cx, data);
        if let Poll::Ready(Err(e)) = &r {
            self.stats.record_io_error(e);
        }
        r
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let r = Pin::new(&mut self.inner).poll_write_vectored(cx, bufs);
        if let Poll::Ready(Err(e)) = &r {
            self.stats.record_io_error(e);
        }
        r
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
