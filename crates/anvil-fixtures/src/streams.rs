//! TCP and UDP stream fixtures.

use crate::log::{GroundTruth, GroundTruthLog};
use crate::tlsserver::{TlsServerOptions, server_config};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Copy, Debug)]
pub enum TcpMode {
    /// Echo each read immediately.
    Echo,
    /// Read until the client half-closes, then reply with a summary and close
    /// (exercises half-close semantics).
    ReplyAfterHalfClose,
}

pub struct StreamFixture {
    pub addr: SocketAddr,
    pub log: GroundTruthLog,
    cancel: CancellationToken,
}

impl Drop for StreamFixture {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

pub async fn tcp(bind: &str, mode: TcpMode, tls: Option<TlsServerOptions>) -> anyhow::Result<StreamFixture> {
    let listener = TcpListener::bind(bind).await?;
    let addr = listener.local_addr()?;
    let log = GroundTruthLog::default();
    let cancel = CancellationToken::new();
    let acceptor = match &tls {
        Some(o) => Some(tokio_rustls::TlsAcceptor::from(server_config(o)?)),
        None => None,
    };
    let (l2, c2) = (log.clone(), cancel.clone());
    tokio::spawn(async move {
        loop {
            let (stream, peer) = tokio::select! {
                r = listener.accept() => match r { Ok(x) => x, Err(_) => continue },
                _ = c2.cancelled() => break,
            };
            l2.push(GroundTruth::ConnectionAccepted { peer: peer.to_string() });
            let (log, acceptor) = (l2.clone(), acceptor.clone());
            tokio::spawn(async move {
                match acceptor {
                    Some(acc) => {
                        if let Ok(s) = acc.accept(stream).await {
                            tcp_session(s, mode, log).await
                        }
                    }
                    None => tcp_session(stream, mode, log).await,
                }
            });
        }
    });
    Ok(StreamFixture { addr, log, cancel })
}

async fn tcp_session<S: AsyncRead + AsyncWrite + Unpin>(mut s: S, mode: TcpMode, log: GroundTruthLog) {
    let mut buf = vec![0u8; 16 * 1024];
    let mut total = 0u64;
    loop {
        let n = match tokio::time::timeout(Duration::from_secs(60), s.read(&mut buf)).await {
            Ok(Ok(n)) => n,
            _ => return,
        };
        if n == 0 {
            break;
        }
        total += n as u64;
        log.push(GroundTruth::MessageReceived { bytes: n as u64 });
        if let TcpMode::Echo = mode
            && s.write_all(&buf[..n]).await.is_err()
        {
            return;
        }
    }
    if let TcpMode::ReplyAfterHalfClose = mode {
        let _ = s.write_all(format!("received {total} bytes after half-close\n").as_bytes()).await;
    }
    let _ = s.shutdown().await;
}

#[derive(Clone, Copy, Debug)]
pub enum UdpMode {
    Echo,
    /// Receive but never answer.
    Silent,
    /// Answer only every other datagram.
    DropEveryOther,
    /// Answer each datagram twice (duplicate delivery).
    Duplicate,
    /// Answer the first datagram, then close the socket: later datagrams
    /// meet a closed port (ICMP port unreachable to their sender).
    CloseAfterFirst,
}

pub async fn udp(bind: &str, mode: UdpMode) -> anyhow::Result<StreamFixture> {
    let sock = UdpSocket::bind(bind).await?;
    let addr = sock.local_addr()?;
    let log = GroundTruthLog::default();
    let cancel = CancellationToken::new();
    let (l2, c2) = (log.clone(), cancel.clone());
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65_535];
        let mut n_seen: u64 = 0;
        loop {
            let (n, peer) = tokio::select! {
                r = sock.recv_from(&mut buf) => match r { Ok(x) => x, Err(_) => continue },
                _ = c2.cancelled() => break,
            };
            n_seen += 1;
            l2.push(GroundTruth::DatagramReceived { bytes: n as u64 });
            match mode {
                UdpMode::Echo => {
                    let _ = sock.send_to(&buf[..n], peer).await;
                }
                UdpMode::Silent => {}
                UdpMode::DropEveryOther => {
                    if n_seen % 2 == 1 {
                        let _ = sock.send_to(&buf[..n], peer).await;
                    }
                }
                UdpMode::Duplicate => {
                    let _ = sock.send_to(&buf[..n], peer).await;
                    let _ = sock.send_to(&buf[..n], peer).await;
                }
                UdpMode::CloseAfterFirst => {
                    let _ = sock.send_to(&buf[..n], peer).await;
                    l2.push(GroundTruth::FaultApplied { fault: "udp_socket_closed".into() });
                    break;
                }
            }
        }
    });
    Ok(StreamFixture { addr, log, cancel })
}
