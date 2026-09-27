//! A relay in front of another fixture that holds one connection until the
//! test releases it: the client's call is in flight (connected and waiting)
//! for as long as the test needs, then completes against the real fixture.
//! Makes "the answer arrives after X happened" deterministic, without sleeps.
//!
//! The held connection is the `hold`-th one accepted (0-based). Nothing of it
//! reaches the fixture behind the gate before [`Gate::release`]; every other
//! connection is relayed at once.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

struct Shared {
    hold: usize,
    /// The held connection was accepted.
    arrived: watch::Sender<bool>,
    released: watch::Sender<bool>,
}

pub struct Gate {
    /// The listening address (TCP gates).
    pub addr: Option<SocketAddr>,
    /// The listening socket path (Unix gates).
    pub path: Option<std::path::PathBuf>,
    shared: Arc<Shared>,
    cancel: CancellationToken,
}

fn new_shared(hold: usize) -> Arc<Shared> {
    let (arrived, _) = watch::channel(false);
    let (released, _) = watch::channel(false);
    Arc::new(Shared { hold, arrived, released })
}

impl Gate {
    /// `unix://<path>` of a Unix gate.
    pub fn uri(&self) -> String {
        format!("unix://{}", self.path.as_ref().map(|p| p.display().to_string()).unwrap_or_default())
    }

    /// Wait until the held connection has been accepted, i.e. the client's
    /// call is in flight.
    pub async fn held(&self) {
        let mut rx = self.shared.arrived.subscribe();
        let _ = rx.wait_for(|arrived| *arrived).await;
    }

    /// Let the held connection through to the fixture.
    pub fn release(&self) {
        self.shared.released.send_replace(true);
    }
}

impl Drop for Gate {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

async fn relay<C, U, F>(mut client: C, upstream: F, shared: Arc<Shared>, index: usize)
where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
    F: Future<Output = std::io::Result<U>>,
{
    if index == shared.hold {
        let mut released = shared.released.subscribe();
        shared.arrived.send_replace(true);
        let _ = released.wait_for(|released| *released).await;
    }
    let Ok(mut upstream) = upstream.await else { return };
    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
}

/// A TCP gate in front of `upstream`, holding the `hold`-th connection.
pub async fn tcp(upstream: SocketAddr, hold: usize) -> anyhow::Result<Gate> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let (shared, cancel) = (new_shared(hold), CancellationToken::new());
    let (sh, stop) = (shared.clone(), cancel.clone());
    tokio::spawn(async move {
        for index in 0.. {
            let client = tokio::select! {
                r = listener.accept() => match r {
                    Ok((c, _)) => c,
                    Err(_) => break,
                },
                _ = stop.cancelled() => break,
            };
            tokio::spawn(relay(client, TcpStream::connect(upstream), sh.clone(), index));
        }
    });
    Ok(Gate { addr: Some(addr), path: None, shared, cancel })
}

/// A Unix-socket gate listening at `path` in front of the socket at
/// `upstream`, holding the `hold`-th connection.
#[cfg(unix)]
pub async fn unix(path: &std::path::Path, upstream: &std::path::Path, hold: usize) -> anyhow::Result<Gate> {
    let _ = std::fs::remove_file(path);
    let listener = tokio::net::UnixListener::bind(path)?;
    let (shared, cancel) = (new_shared(hold), CancellationToken::new());
    let (sh, stop, upstream) = (shared.clone(), cancel.clone(), upstream.to_path_buf());
    tokio::spawn(async move {
        for index in 0.. {
            let client = tokio::select! {
                r = listener.accept() => match r {
                    Ok((c, _)) => c,
                    Err(_) => break,
                },
                _ = stop.cancelled() => break,
            };
            tokio::spawn(relay(client, tokio::net::UnixStream::connect(upstream.clone()), sh.clone(), index));
        }
    });
    Ok(Gate { addr: None, path: Some(path.to_path_buf()), shared, cancel })
}
