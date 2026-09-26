//! Minimal DNS fixture (UDP + TCP): answers every query with a fixed RCODE
//! (default NXDOMAIN), or never answers (`Silent`) to produce resolver timeouts.

use crate::log::{GroundTruth, GroundTruthLog};
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Copy, Debug)]
pub enum DnsMode {
    NxDomain,
    ServFail,
    Silent,
}

pub struct DnsFixture {
    pub addr: SocketAddr,
    pub log: GroundTruthLog,
    cancel: CancellationToken,
}

impl Drop for DnsFixture {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

fn answer(query: &[u8], mode: DnsMode) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }
    let rcode = match mode {
        DnsMode::NxDomain => 3u8,
        DnsMode::ServFail => 2u8,
        DnsMode::Silent => return None,
    };
    let mut r = query.to_vec();
    // QR=1, keep opcode and RD, set RA; RCODE.
    r[2] = 0x80 | (query[2] & 0x79);
    r[3] = 0x80 | rcode;
    // ANCOUNT/NSCOUNT/ARCOUNT = 0 (drop EDNS additional records).
    r[6..12].copy_from_slice(&[0, 0, 0, 0, 0, 0]);
    // Keep only the question section.
    let mut i = 12;
    while i < r.len() && r[i] != 0 {
        i += r[i] as usize + 1;
    }
    let end = (i + 5).min(r.len());
    r.truncate(end);
    Some(r)
}

pub async fn serve(bind: &str, mode: DnsMode) -> anyhow::Result<DnsFixture> {
    let udp = UdpSocket::bind(bind).await?;
    let addr = udp.local_addr()?;
    let tcp = TcpListener::bind(addr).await?;
    let log = GroundTruthLog::default();
    let cancel = CancellationToken::new();
    let (l1, c1) = (log.clone(), cancel.clone());
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let (n, peer) = tokio::select! {
                r = udp.recv_from(&mut buf) => match r { Ok(x) => x, Err(_) => continue },
                _ = c1.cancelled() => break,
            };
            l1.push(GroundTruth::DatagramReceived { bytes: n as u64 });
            if let Some(a) = answer(&buf[..n], mode) {
                let _ = udp.send_to(&a, peer).await;
            }
        }
    });
    let (l2, c2) = (log.clone(), cancel.clone());
    tokio::spawn(async move {
        loop {
            let (mut s, _) = tokio::select! {
                r = tcp.accept() => match r { Ok(x) => x, Err(_) => continue },
                _ = c2.cancelled() => break,
            };
            let log = l2.clone();
            tokio::spawn(async move {
                let mut len = [0u8; 2];
                if s.read_exact(&mut len).await.is_err() {
                    return;
                }
                let n = u16::from_be_bytes(len) as usize;
                let mut q = vec![0u8; n];
                if s.read_exact(&mut q).await.is_err() {
                    return;
                }
                log.push(GroundTruth::MessageReceived { bytes: n as u64 });
                if let Some(a) = answer(&q, mode) {
                    let _ = s.write_all(&(a.len() as u16).to_be_bytes()).await;
                    let _ = s.write_all(&a).await;
                }
            });
        }
    });
    Ok(DnsFixture { addr, log, cancel })
}

/// A TCP listener whose accept backlog is saturated and never drained, so new
/// connection attempts stall in SYN handling (connect-timeout fixture).
pub struct StalledListener {
    pub addr: SocketAddr,
    _listener: std::net::TcpListener,
    _fillers: Vec<std::net::TcpStream>,
}

pub fn stalled_listener(bind: &str) -> anyhow::Result<StalledListener> {
    use socket2::{Domain, Socket, Type};
    let addr: SocketAddr = bind.parse()?;
    let sock = Socket::new(Domain::for_address(addr), Type::STREAM, None)?;
    sock.set_reuse_address(true)?;
    sock.bind(&addr.into())?;
    sock.listen(0)?;
    let listener: std::net::TcpListener = sock.into();
    let local = listener.local_addr()?;
    let mut fillers = Vec::new();
    for _ in 0..8 {
        match std::net::TcpStream::connect_timeout(&local, std::time::Duration::from_millis(200)) {
            Ok(s) => fillers.push(s),
            Err(_) => break,
        }
    }
    Ok(StalledListener { addr: local, _listener: listener, _fillers: fillers })
}
