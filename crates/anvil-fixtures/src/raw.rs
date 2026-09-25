//! Raw-socket fault listeners (TCP level, optionally TLS) for failures that a
//! well-behaved HTTP server cannot produce: silent stalls, resets, short
//! bodies, garbage responses.

use crate::log::{GroundTruth, GroundTruthLog};
use crate::tlsserver::{TlsServerOptions, server_config};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Debug)]
pub enum RawMode {
    /// Accept, then close immediately (FIN).
    AcceptClose,
    /// Accept, then reset (RST).
    AcceptReset,
    /// Accept and never read or write (stalls TLS handshakes / requests).
    AcceptStall,
    /// Read the request head, then never answer.
    ReadThenStall,
    /// Read the request head, then reset.
    ResetAfterRequest,
    /// Answer with `Content-Length: declared` but send only `sent` bytes, then FIN.
    ShortBody { declared: u64, sent: u64 },
    /// Answer headers + `sent` body bytes, then reset.
    ResetMidBody { sent: u64 },
    /// Answer headers + `sent` body bytes, then stall forever.
    HeadersThenStall { sent: u64 },
    /// Answer with bytes that are not HTTP.
    Garbage,
    /// Answer a complete, well-formed response with the given raw head/body
    /// (lets tests produce exact duplicated/conflicting headers).
    Exact { response: Vec<u8> },
}

pub struct RawFixture {
    pub addr: SocketAddr,
    pub log: GroundTruthLog,
    cancel: CancellationToken,
}

impl Drop for RawFixture {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

impl RawFixture {
    pub fn url(&self, tls: bool, path: &str) -> String {
        format!(
            "{}://{}{}",
            if tls { "https" } else { "http" },
            self.addr,
            path
        )
    }
}

pub async fn serve(
    bind: &str,
    mode: RawMode,
    tls: Option<TlsServerOptions>,
) -> anyhow::Result<RawFixture> {
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
            l2.push(GroundTruth::ConnectionAccepted {
                peer: peer.to_string(),
            });
            let (log, mode, acceptor, cancel) =
                (l2.clone(), mode.clone(), acceptor.clone(), c2.clone());
            tokio::spawn(async move {
                match (&mode, acceptor) {
                    (RawMode::AcceptClose, _) => {
                        log.push(GroundTruth::FaultApplied {
                            fault: "accept_close".into(),
                        });
                        drop(stream);
                    }
                    (RawMode::AcceptReset, _) => {
                        log.push(GroundTruth::FaultApplied {
                            fault: "accept_reset".into(),
                        });
                        reset(stream);
                    }
                    (RawMode::AcceptStall, _) => {
                        log.push(GroundTruth::FaultApplied {
                            fault: "accept_stall".into(),
                        });
                        tokio::select! { _ = tokio::time::sleep(Duration::from_secs(300)) => {}, _ = cancel.cancelled() => {} }
                        drop(stream);
                    }
                    (_, Some(acc)) => match acc.accept(stream).await {
                        Ok(s) => {
                            log.push(GroundTruth::TlsHandshakeCompleted {
                                alpn: None,
                                client_cert_cn: None,
                            });
                            let (s, tcp_reset) = (s, ());
                            let _ = tcp_reset;
                            handle(s, mode, log, cancel, None).await;
                        }
                        Err(e) => log.push(GroundTruth::TlsHandshakeFailed {
                            error: e.to_string(),
                        }),
                    },
                    (_, None) => {
                        let std = stream.into_std().ok();
                        let sock_for_reset = std.as_ref().and_then(|s| s.try_clone().ok());
                        if let Some(s) = std
                            && let Ok(t) = TcpStream::from_std(s)
                        {
                            handle(t, mode, log, cancel, sock_for_reset).await;
                        }
                    }
                }
            });
        }
    });
    Ok(RawFixture { addr, log, cancel })
}

fn reset(stream: TcpStream) {
    let _ = socket2::SockRef::from(&stream).set_linger(Some(Duration::ZERO));
    drop(stream);
}

fn reset_std(s: Option<std::net::TcpStream>) {
    if let Some(s) = s {
        let _ = socket2::SockRef::from(&s).set_linger(Some(Duration::ZERO));
        drop(s);
    }
}

async fn read_head<S: AsyncRead + Unpin>(s: &mut S) -> Option<String> {
    let mut buf = Vec::new();
    let mut b = [0u8; 1024];
    loop {
        let n = tokio::time::timeout(Duration::from_secs(30), s.read(&mut b))
            .await
            .ok()?
            .ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&b[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() > 64 * 1024 {
            return Some(String::from_utf8_lossy(&buf).into_owned());
        }
    }
}

async fn handle<S>(
    mut s: S,
    mode: RawMode,
    log: GroundTruthLog,
    cancel: CancellationToken,
    std_clone: Option<std::net::TcpStream>,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let Some(head) = read_head(&mut s).await else {
        return;
    };
    let first = head.lines().next().unwrap_or("").to_string();
    let mut parts = first.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("").to_string();
    log.push(GroundTruth::RequestReceived {
        method,
        path,
        body_bytes: 0,
        headers: vec![],
    });
    match mode {
        RawMode::ReadThenStall => {
            log.push(GroundTruth::FaultApplied {
                fault: "read_then_stall".into(),
            });
            tokio::select! { _ = tokio::time::sleep(Duration::from_secs(300)) => {}, _ = cancel.cancelled() => {} }
        }
        RawMode::ResetAfterRequest => {
            log.push(GroundTruth::FaultApplied {
                fault: "reset_after_request".into(),
            });
            drop(s);
            reset_std(std_clone);
        }
        RawMode::ShortBody { declared, sent } => {
            log.push(GroundTruth::FaultApplied {
                fault: format!("short_body_{sent}_of_{declared}"),
            });
            let _ = s.write_all(format!("HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: {declared}\r\n\r\n").as_bytes()).await;
            let _ = s.write_all(&vec![b'y'; sent as usize]).await;
            let _ = s.flush().await;
            let _ = s.shutdown().await;
        }
        RawMode::ResetMidBody { sent } => {
            log.push(GroundTruth::FaultApplied {
                fault: format!("reset_mid_body_after_{sent}"),
            });
            let _ = s.write_all(b"HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: 1000000\r\n\r\n").await;
            let _ = s.write_all(&vec![b'z'; sent as usize]).await;
            let _ = s.flush().await;
            tokio::time::sleep(Duration::from_millis(50)).await;
            drop(s);
            reset_std(std_clone);
        }
        RawMode::HeadersThenStall { sent } => {
            log.push(GroundTruth::FaultApplied {
                fault: "headers_then_stall".into(),
            });
            let _ = s.write_all(b"HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: 1000000\r\n\r\n").await;
            let _ = s.write_all(&vec![b'z'; sent as usize]).await;
            let _ = s.flush().await;
            tokio::select! { _ = tokio::time::sleep(Duration::from_secs(300)) => {}, _ = cancel.cancelled() => {} }
        }
        RawMode::Garbage => {
            log.push(GroundTruth::FaultApplied {
                fault: "garbage".into(),
            });
            let _ = s
                .write_all(b"\x00\x01\x02 this is not http \xff\xfe\r\n\r\n")
                .await;
            let _ = s.shutdown().await;
        }
        RawMode::Exact { response } => {
            let _ = s.write_all(&response).await;
            let _ = s.flush().await;
            let _ = s.shutdown().await;
        }
        RawMode::AcceptClose | RawMode::AcceptReset | RawMode::AcceptStall => {}
    }
}
