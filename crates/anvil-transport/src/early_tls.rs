//! TLS 1.3 early data over TCP (HTTP/1.1 and HTTP/2).
//!
//! With the early-data opt-in and a ticket that allows it, tokio-rustls hands
//! the stream over before the handshake completes: bytes written then go into
//! TLS early data behind the ClientHello, and the first flush completes the
//! handshake. When the server rejects the early data, tokio-rustls writes the
//! same bytes again as ordinary application data after the handshake (the
//! server discarded the first copy unread).
//!
//! [`EarlyTlsIo`] wraps that stream to observe what the handshake did: how
//! many plaintext bytes went into early data, when the handshake completed,
//! whether the server accepted the early data and resumed the session. It
//! releases the resumption context's handshake gate when the handshake is
//! over (or the connection is dropped).

use crate::tickets::{HandshakeGuard, ResumptionContext};
use crate::tls::ObservationHandle;
use parking_lot::Mutex;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Instant;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::client::TlsStream;

/// What the completed handshake of an early-data connection reported.
#[derive(Clone, Debug)]
pub(crate) struct TlsDone {
    pub at: Instant,
    pub early_accepted: bool,
    pub resumed: bool,
}

#[derive(Default)]
pub(crate) struct EarlyTlsState {
    early_bytes: AtomicU64,
    done: Mutex<Option<TlsDone>>,
    guard: Mutex<Option<HandshakeGuard>>,
    /// The completed connection's TLS evidence (built once, when done).
    observation: Mutex<Option<anvil_domain::execution::TlsObservation>>,
}

impl EarlyTlsState {
    pub(crate) fn early_bytes(&self) -> u64 {
        self.early_bytes.load(Ordering::SeqCst)
    }

    pub(crate) fn done(&self) -> Option<TlsDone> {
        self.done.lock().clone()
    }

    pub(crate) fn observation(&self) -> Option<anvil_domain::execution::TlsObservation> {
        self.observation.lock().clone()
    }
}

/// A connection whose handshake is still in flight while the request is
/// written as early data, plus what finishing its evidence needs.
pub(crate) struct EarlyPending {
    pub state: Arc<EarlyTlsState>,
    /// Index of the attempt's `tls_handshake` phase, closed at completion.
    pub tls_phase: usize,
}

/// Evidence of a connection made through a TCP resumption context.
pub struct ResumableInfo {
    pub(crate) ctx: Arc<ResumptionContext>,
    pub(crate) tickets_before: u32,
    /// `max_early_data_size` of the ticket the ClientHello offered, if any.
    pub(crate) taken: Option<u32>,
    /// Known when the handshake completed before the request was written.
    pub(crate) resumed: Option<bool>,
    pub(crate) early: Option<EarlyPending>,
}

pub(crate) struct EarlyTlsIo<S> {
    inner: TlsStream<S>,
    state: Arc<EarlyTlsState>,
    handle: ObservationHandle,
    prepared: Arc<crate::tls::PreparedTls>,
}

impl<S> EarlyTlsIo<S> {
    pub(crate) fn new(
        inner: TlsStream<S>,
        guard: HandshakeGuard,
        handle: ObservationHandle,
        prepared: Arc<crate::tls::PreparedTls>,
    ) -> (Self, Arc<EarlyTlsState>) {
        let state = Arc::new(EarlyTlsState::default());
        *state.guard.lock() = Some(guard);
        (EarlyTlsIo { inner, state: state.clone(), handle, prepared }, state)
    }

    fn handshaking(&self) -> bool {
        self.inner.get_ref().1.is_handshaking()
    }

    /// Record the handshake's outcome the first time it is complete.
    fn check(&self) {
        if self.handshaking() || self.state.done.lock().is_some() {
            return;
        }
        let conn = self.inner.get_ref().1;
        let (obs, resumed) = crate::tls::completed_observation(&self.handle, &self.prepared, conn);
        *self.state.observation.lock() = Some(obs);
        *self.state.done.lock() = Some(TlsDone { at: Instant::now(), early_accepted: conn.is_early_data_accepted(), resumed });
        self.state.guard.lock().take();
    }
}

impl<S> Drop for EarlyTlsIo<S> {
    fn drop(&mut self) {
        self.state.guard.lock().take();
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for EarlyTlsIo<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let r = Pin::new(&mut self.inner).poll_read(cx, buf);
        self.check();
        r
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for EarlyTlsIo<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        let before = self.handshaking();
        let r = Pin::new(&mut self.inner).poll_write(cx, data);
        // Accepted while the handshake is still running: early data.
        if let Poll::Ready(Ok(n)) = &r
            && before
            && self.handshaking()
        {
            self.state.early_bytes.fetch_add(*n as u64, Ordering::SeqCst);
        }
        self.check();
        r
    }

    fn poll_write_vectored(mut self: Pin<&mut Self>, cx: &mut Context<'_>, bufs: &[io::IoSlice<'_>]) -> Poll<io::Result<usize>> {
        let before = self.handshaking();
        let r = Pin::new(&mut self.inner).poll_write_vectored(cx, bufs);
        if let Poll::Ready(Ok(n)) = &r
            && before
            && self.handshaking()
        {
            self.state.early_bytes.fetch_add(*n as u64, Ordering::SeqCst);
        }
        self.check();
        r
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let r = Pin::new(&mut self.inner).poll_flush(cx);
        self.check();
        r
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let r = Pin::new(&mut self.inner).poll_shutdown(cx);
        self.check();
        r
    }
}
