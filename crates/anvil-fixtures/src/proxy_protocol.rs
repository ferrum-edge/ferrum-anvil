//! PROXY protocol receivers: an independent reference for what Anvil sends.
//!
//! The parsing here is written separately from `anvil-transport`'s encoder,
//! from Ferrum Edge v0.9.7's receive semantics (`src/proxy/proxy_protocol.rs`
//! `read_proxy_header`, `src/proxy/datagram_client_address.rs`
//! `parse_datagram_header_inner` / `verify_authentication_tag` /
//! `DatagramReplayGuard`), so tests compare two implementations.
//!
//! * [`tcp_echo`]: requires a v1/v2 header on every connection (optionally
//!   only from trusted peers), records it, then echoes the stream (optionally
//!   after a TLS handshake that starts *after* the header). A missing, invalid
//!   or untrusted header closes the connection without data, like Ferrum.
//! * [`udp_echo`]: requires the PROXY v2 `DGRAM` envelope on every datagram
//!   (optionally authenticated), echoes the payload unwrapped; refusals are
//!   silent drops.
//! * [`udp_relay`]: strips (and checks) the envelope and relays the payload
//!   to a UDP target, replies unwrapped — a datagram load-balancer receiver in
//!   front of, e.g., a DTLS server.
//!
//! Ground truth goes to [`ProxyLog`]; it is never given to the diagnostic engine.

use crate::tlsserver::{TlsServerOptions, server_config};
use hmac::{KeyInit, Mac};
use parking_lot::Mutex;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio_util::sync::CancellationToken;

const SIG: &[u8; 12] = b"\r\n\r\n\x00\r\nQUIT\n";

/// What a receiver observed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyEvent {
    /// A connection header was accepted.
    Header {
        peer: SocketAddr,
        v2: bool,
        local: bool,
        source: Option<SocketAddr>,
        destination: Option<SocketAddr>,
        tlvs: Vec<(u8, Vec<u8>)>,
    },
    /// A connection was closed because of its header (or its peer).
    Rejected { peer: SocketAddr, reason: String },
    /// Stream bytes after the header (and TLS, when configured).
    StreamData { bytes: Vec<u8> },
    /// A datagram envelope was accepted; `payload` is what follows it.
    Datagram { peer: SocketAddr, source: Option<SocketAddr>, sequence: Option<u64>, authenticated: bool, payload: Vec<u8> },
    /// A datagram was dropped (reason names the failed check).
    Dropped { peer: SocketAddr, reason: String },
}

#[derive(Default, Clone)]
pub struct ProxyLog(Arc<Mutex<Vec<ProxyEvent>>>);

impl ProxyLog {
    fn push(&self, e: ProxyEvent) {
        let mut g = self.0.lock();
        if g.len() < 10_000 {
            g.push(e);
        }
    }

    pub fn events(&self) -> Vec<ProxyEvent> {
        self.0.lock().clone()
    }

    pub fn clear(&self) {
        self.0.lock().clear();
    }

    pub fn headers(&self) -> Vec<ProxyEvent> {
        self.events().into_iter().filter(|e| matches!(e, ProxyEvent::Header { .. })).collect()
    }

    pub fn rejections(&self) -> Vec<String> {
        self.events()
            .into_iter()
            .filter_map(|e| match e {
                ProxyEvent::Rejected { reason, .. } | ProxyEvent::Dropped { reason, .. } => Some(reason),
                _ => None,
            })
            .collect()
    }

    pub fn stream_bytes(&self) -> Vec<u8> {
        self.events()
            .into_iter()
            .filter_map(|e| match e {
                ProxyEvent::StreamData { bytes } => Some(bytes),
                _ => None,
            })
            .flatten()
            .collect()
    }

    pub fn datagrams(&self) -> Vec<ProxyEvent> {
        self.events().into_iter().filter(|e| matches!(e, ProxyEvent::Datagram { .. })).collect()
    }
}

pub struct ProxyFixture {
    pub addr: SocketAddr,
    pub log: ProxyLog,
    cancel: CancellationToken,
}

impl Drop for ProxyFixture {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

fn trusted(peer: &SocketAddr, list: &[IpAddr]) -> bool {
    let ip = match peer.ip() {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    };
    list.is_empty() || list.contains(&ip)
}

// ================================================================ TCP ===

/// A parsed connection header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub v2: bool,
    pub local: bool,
    pub source: Option<SocketAddr>,
    pub destination: Option<SocketAddr>,
    pub tlvs: Vec<(u8, Vec<u8>)>,
}

/// Read one PROXY header from the head of `s` (Ferrum `read_proxy_header`).
pub async fn read_header<R: AsyncRead + Unpin>(s: &mut R) -> Result<Header, String> {
    let io = |e: std::io::Error| format!("I/O error reading the PROXY header: {e}");
    let mut prefix = [0u8; 6];
    s.read_exact(&mut prefix).await.map_err(io)?;
    if &prefix == b"PROXY " {
        let mut line = prefix.to_vec();
        loop {
            if line.len() >= 109 {
                return Err("PROXY v1 header too long".into());
            }
            let mut b = [0u8; 1];
            s.read_exact(&mut b).await.map_err(io)?;
            line.push(b[0]);
            if line.ends_with(b"\r\n") {
                break;
            }
        }
        let text = std::str::from_utf8(&line[..line.len() - 2]).map_err(|_| "non-UTF-8 v1 header".to_string())?;
        let f: Vec<&str> = text.split_ascii_whitespace().collect();
        return match f.get(1).copied() {
            Some("UNKNOWN") => Ok(Header { v2: false, local: false, source: None, destination: None, tlvs: vec![] }),
            Some(p @ ("TCP4" | "TCP6")) => {
                if f.len() < 6 {
                    return Err("missing v1 fields".into());
                }
                let src: IpAddr = f[2].parse().map_err(|_| "invalid v1 source IP".to_string())?;
                let dst: IpAddr = f[3].parse().map_err(|_| "invalid v1 destination IP".to_string())?;
                let sp: u16 = f[4].parse().map_err(|_| "invalid v1 source port".to_string())?;
                let dp: u16 = f[5].parse().map_err(|_| "invalid v1 destination port".to_string())?;
                if (p == "TCP4") != src.is_ipv4() || (p == "TCP4") != dst.is_ipv4() {
                    return Err("v1 family mismatch".into());
                }
                Ok(Header {
                    v2: false,
                    local: false,
                    source: Some(SocketAddr::new(src, sp)),
                    destination: Some(SocketAddr::new(dst, dp)),
                    tlvs: vec![],
                })
            }
            other => Err(format!("unsupported v1 protocol {other:?}")),
        };
    }
    if prefix != SIG[..6] {
        return Err("invalid PROXY signature".into());
    }
    let mut rest = [0u8; 10];
    s.read_exact(&mut rest).await.map_err(io)?;
    if rest[..6] != SIG[6..] {
        return Err("invalid PROXY v2 signature".into());
    }
    let (ver_cmd, fam) = (rest[6], rest[7]);
    let len = u16::from_be_bytes([rest[8], rest[9]]) as usize;
    if ver_cmd >> 4 != 2 {
        return Err("unsupported PROXY v2 version".into());
    }
    if len > 512 {
        return Err("PROXY v2 address block exceeds 512 bytes".into());
    }
    let mut block = vec![0u8; len];
    s.read_exact(&mut block).await.map_err(io)?;
    let (source, destination, fixed) = match (ver_cmd & 0x0f, fam >> 4) {
        (0x00, _) => (None, None, 0),
        (0x01, 0x00 | 0x03) => (None, None, 0),
        (0x01, 0x01) => {
            if block.len() < 12 {
                return Err("AF_INET block too short".into());
            }
            let src =
                SocketAddr::new(Ipv4Addr::new(block[0], block[1], block[2], block[3]).into(), u16::from_be_bytes([block[8], block[9]]));
            let dst =
                SocketAddr::new(Ipv4Addr::new(block[4], block[5], block[6], block[7]).into(), u16::from_be_bytes([block[10], block[11]]));
            if fam & 0x0f == 0x01 { (Some(src), Some(dst), 12) } else { (None, None, 12) }
        }
        (0x01, 0x02) => {
            if block.len() < 36 {
                return Err("AF_INET6 block too short".into());
            }
            let s6: [u8; 16] = block[..16].try_into().unwrap_or([0; 16]);
            let d6: [u8; 16] = block[16..32].try_into().unwrap_or([0; 16]);
            let src = SocketAddr::new(Ipv6Addr::from(s6).into(), u16::from_be_bytes([block[32], block[33]]));
            let dst = SocketAddr::new(Ipv6Addr::from(d6).into(), u16::from_be_bytes([block[34], block[35]]));
            if fam & 0x0f == 0x01 { (Some(src), Some(dst), 36) } else { (None, None, 36) }
        }
        (0x01, f) => return Err(format!("unsupported PROXY v2 family 0x{f:x}")),
        (c, _) => return Err(format!("unsupported PROXY v2 command 0x{c:x}")),
    };
    // TLVs are informational here (Ferrum's TCP parser ignores them).
    let mut tlvs = Vec::new();
    let mut at = fixed.min(block.len());
    while at + 3 <= block.len() {
        let l = u16::from_be_bytes([block[at + 1], block[at + 2]]) as usize;
        if at + 3 + l > block.len() {
            break;
        }
        tlvs.push((block[at], block[at + 3..at + 3 + l].to_vec()));
        at += 3 + l;
    }
    Ok(Header { v2: true, local: ver_cmd & 0x0f == 0, source, destination, tlvs })
}

/// PROXY-header-requiring TCP echo. `trusted` empty = every peer is trusted.
pub async fn tcp_echo(bind: &str, trusted_peers: Vec<IpAddr>, tls: Option<TlsServerOptions>) -> anyhow::Result<ProxyFixture> {
    let listener = TcpListener::bind(bind).await?;
    let addr = listener.local_addr()?;
    let log = ProxyLog::default();
    let cancel = CancellationToken::new();
    let acceptor = match &tls {
        Some(o) => Some(tokio_rustls::TlsAcceptor::from(server_config(o)?)),
        None => None,
    };
    let (l2, c2) = (log.clone(), cancel.clone());
    tokio::spawn(async move {
        loop {
            let (mut stream, peer) = tokio::select! {
                r = listener.accept() => match r { Ok(x) => x, Err(_) => continue },
                _ = c2.cancelled() => break,
            };
            let (log, acceptor, trusted_peers) = (l2.clone(), acceptor.clone(), trusted_peers.clone());
            tokio::spawn(async move {
                if !trusted(&peer, &trusted_peers) {
                    log.push(ProxyEvent::Rejected { peer, reason: "untrusted peer".into() });
                    return;
                }
                match tokio::time::timeout(Duration::from_secs(5), read_header(&mut stream)).await {
                    Ok(Ok(h)) => log.push(ProxyEvent::Header {
                        peer,
                        v2: h.v2,
                        local: h.local,
                        source: h.source,
                        destination: h.destination,
                        tlvs: h.tlvs,
                    }),
                    Ok(Err(reason)) => {
                        log.push(ProxyEvent::Rejected { peer, reason });
                        return;
                    }
                    Err(_) => {
                        log.push(ProxyEvent::Rejected { peer, reason: "timeout reading the PROXY header".into() });
                        return;
                    }
                }
                match acceptor {
                    Some(acc) => {
                        if let Ok(s) = acc.accept(stream).await {
                            echo(s, log).await
                        }
                    }
                    None => echo(stream, log).await,
                }
            });
        }
    });
    Ok(ProxyFixture { addr, log, cancel })
}

async fn echo<S: AsyncRead + AsyncWrite + Unpin>(mut s: S, log: ProxyLog) {
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let n = match tokio::time::timeout(Duration::from_secs(60), s.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => n,
            _ => break,
        };
        log.push(ProxyEvent::StreamData { bytes: buf[..n].to_vec() });
        if s.write_all(&buf[..n]).await.is_err() {
            return;
        }
    }
    let _ = s.shutdown().await;
}

// =========================================================== datagram ===

/// Envelope verification settings for an authenticated receiver.
#[derive(Clone)]
pub struct DatagramAuth {
    pub secret: Vec<u8>,
    /// `(protocol tag 1 = udp / 2 = dtls, bind address, port)`.
    pub protocol_tag: u8,
    pub bind_addr: IpAddr,
    pub port: u16,
}

impl DatagramAuth {
    fn domain(&self) -> Vec<u8> {
        let mut d = b"ferrum-datagram-proxy-v1".to_vec();
        d.push(1);
        d.push(self.protocol_tag);
        let bind = match self.bind_addr {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)),
            v4 => v4,
        };
        match bind {
            IpAddr::V4(v4) => {
                d.push(4);
                d.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                d.push(6);
                d.extend_from_slice(&v6.octets());
            }
        }
        d.extend_from_slice(&self.port.to_be_bytes());
        d
    }
}

/// Highest epoch per sender, and every admitted `(sender, epoch, sequence)`.
type ReplayState = (HashMap<u32, u64>, HashSet<(u32, u64, u64)>);

/// Receiver-side state: trust list, optional authentication, replay window.
pub struct DatagramGate {
    pub trusted: Vec<IpAddr>,
    pub auth: Option<DatagramAuth>,
    /// Destination port an address-bearing envelope must declare.
    pub listen_port: Option<u16>,
    seen: Mutex<ReplayState>,
}

/// An accepted datagram.
pub struct Opened {
    pub source: Option<SocketAddr>,
    pub sequence: Option<u64>,
    pub payload_at: usize,
}

impl DatagramGate {
    pub fn new(trusted: Vec<IpAddr>, auth: Option<DatagramAuth>, listen_port: Option<u16>) -> Self {
        DatagramGate { trusted, auth, listen_port, seen: Mutex::new((HashMap::new(), HashSet::new())) }
    }

    /// Check one datagram; `Err` names the failed check.
    pub fn open(&self, d: &[u8], peer: &SocketAddr) -> Result<Opened, &'static str> {
        if !trusted(peer, &self.trusted) {
            return Err("untrusted_peer");
        }
        if d.len() < 16 {
            return Err("truncated_header");
        }
        if &d[..12] != SIG {
            return Err("invalid_signature");
        }
        if d[12] >> 4 != 2 {
            return Err("unsupported_version");
        }
        let len = u16::from_be_bytes([d[14], d[15]]) as usize;
        if len > 512 {
            return Err("address_block_too_long");
        }
        if d.len() - 16 < len {
            return Err("truncated_address_block");
        }
        let block = &d[16..16 + len];
        let local = match d[12] & 0x0f {
            0 => true,
            1 => false,
            _ => return Err("unsupported_command"),
        };
        if !local && d[13] & 0x0f != 0x02 {
            return Err("non_datagram_transport");
        }
        let (source, dport, fixed) = match d[13] >> 4 {
            0 => (None, None, 0),
            1 => {
                if block.len() < 12 {
                    return Err("address_block_too_short");
                }
                let s =
                    SocketAddr::new(Ipv4Addr::new(block[0], block[1], block[2], block[3]).into(), u16::from_be_bytes([block[8], block[9]]));
                (Some(s), Some(u16::from_be_bytes([block[10], block[11]])), 12)
            }
            2 => {
                if block.len() < 36 {
                    return Err("address_block_too_short");
                }
                let s6: [u8; 16] = block[..16].try_into().unwrap_or([0; 16]);
                let s = SocketAddr::new(Ipv6Addr::from(s6).into(), u16::from_be_bytes([block[32], block[33]]));
                (Some(s), Some(u16::from_be_bytes([block[34], block[35]])), 36)
            }
            _ => return Err("unsupported_address_family"),
        };
        let (mut tag, mut fresh) = (None, None);
        let mut at = fixed;
        while at < block.len() {
            if block.len() - at < 3 {
                return Err("malformed_tlv");
            }
            let l = u16::from_be_bytes([block[at + 1], block[at + 2]]) as usize;
            if at + 3 + l > block.len() {
                return Err("malformed_tlv");
            }
            let range = (16 + at + 3, 16 + at + 3 + l);
            match block[at] {
                0xE0 => {
                    if tag.replace(range).is_some() {
                        return Err("duplicate_authentication_tag");
                    }
                    if l != 32 {
                        return Err("invalid_authentication_tag_length");
                    }
                }
                0xE1 => {
                    if fresh.replace(range).is_some() {
                        return Err("duplicate_freshness");
                    }
                    if l != 29 {
                        return Err("malformed_freshness");
                    }
                }
                _ => {}
            }
            at += 3 + l;
        }
        let source = if local { None } else { source };
        if source.is_some() && dport != self.listen_port.or(dport) {
            return Err("listener_binding_mismatch");
        }
        let mut sequence = None;
        if let Some(auth) = &self.auth {
            let Some((ts, te)) = tag else { return Err("missing_authentication_tag") };
            let mut mac =
                <hmac::Hmac<sha2::Sha256> as KeyInit>::new_from_slice(&auth.secret).map_err(|_| "authentication_key_unavailable")?;
            mac.update(&auth.domain());
            mac.update(&d[..ts]);
            mac.update(&d[te..]);
            if mac.verify_slice(&d[ts..te]).is_err() {
                return Err("authentication_tag_mismatch");
            }
            let Some((fs, _)) = fresh else { return Err("missing_freshness") };
            let v = &d[fs..fs + 29];
            if v[0] != 1 {
                return Err("unsupported_freshness_version");
            }
            let sender = u32::from_be_bytes(v[1..5].try_into().unwrap_or_default());
            let epoch = u64::from_be_bytes(v[5..13].try_into().unwrap_or_default());
            let seq = u64::from_be_bytes(v[13..21].try_into().unwrap_or_default());
            let ts_ms = u64::from_be_bytes(v[21..29].try_into().unwrap_or_default());
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|x| x.as_millis() as u64).unwrap_or(0);
            if now.abs_diff(ts_ms) > 30_000 {
                return Err("freshness_outside_horizon");
            }
            if seq == u64::MAX {
                return Err("replay_sequence_exhausted");
            }
            let mut g = self.seen.lock();
            if g.0.get(&sender).is_some_and(|e| epoch < *e) {
                return Err("replay_epoch_stale");
            }
            if !g.1.insert((sender, epoch, seq)) {
                return Err("replay_duplicate");
            }
            g.0.insert(sender, epoch);
            sequence = Some(seq);
        }
        Ok(Opened { source, sequence, payload_at: 16 + len })
    }
}

/// Envelope-requiring UDP echo: answers with the payload only.
pub async fn udp_echo(bind: &str, gate: DatagramGate) -> anyhow::Result<ProxyFixture> {
    let sock = UdpSocket::bind(bind).await?;
    let addr = sock.local_addr()?;
    let log = ProxyLog::default();
    let cancel = CancellationToken::new();
    let (l2, c2) = (log.clone(), cancel.clone());
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65_535];
        loop {
            let (n, peer) = tokio::select! {
                r = sock.recv_from(&mut buf) => match r { Ok(x) => x, Err(_) => continue },
                _ = c2.cancelled() => break,
            };
            match gate.open(&buf[..n], &peer) {
                Ok(o) => {
                    let payload = buf[o.payload_at..n].to_vec();
                    let _ = sock.send_to(&payload, peer).await;
                    l2.push(ProxyEvent::Datagram {
                        peer,
                        source: o.source,
                        sequence: o.sequence,
                        authenticated: gate.auth.is_some(),
                        payload,
                    });
                }
                Err(reason) => l2.push(ProxyEvent::Dropped { peer, reason: reason.into() }),
            }
        }
    });
    Ok(ProxyFixture { addr, log, cancel })
}

/// Envelope-stripping relay `bind -> target` (one upstream socket per client).
pub async fn udp_relay(bind: &str, target: SocketAddr, gate: DatagramGate) -> anyhow::Result<ProxyFixture> {
    let sock = Arc::new(UdpSocket::bind(bind).await?);
    let addr = sock.local_addr()?;
    let log = ProxyLog::default();
    let cancel = CancellationToken::new();
    let (l2, c2) = (log.clone(), cancel.clone());
    tokio::spawn(async move {
        let mut upstreams: HashMap<SocketAddr, Arc<UdpSocket>> = HashMap::new();
        let mut buf = vec![0u8; 65_535];
        loop {
            let (n, peer) = tokio::select! {
                r = sock.recv_from(&mut buf) => match r { Ok(x) => x, Err(_) => continue },
                _ = c2.cancelled() => break,
            };
            let o = match gate.open(&buf[..n], &peer) {
                Ok(o) => o,
                Err(reason) => {
                    l2.push(ProxyEvent::Dropped { peer, reason: reason.into() });
                    continue;
                }
            };
            let payload = buf[o.payload_at..n].to_vec();
            l2.push(ProxyEvent::Datagram {
                peer,
                source: o.source,
                sequence: o.sequence,
                authenticated: gate.auth.is_some(),
                payload: payload.clone(),
            });
            let up = match upstreams.get(&peer) {
                Some(u) => u.clone(),
                None => {
                    let Ok(u) = UdpSocket::bind("127.0.0.1:0").await else { continue };
                    if u.connect(target).await.is_err() {
                        continue;
                    }
                    let u = Arc::new(u);
                    let (front, back, c3) = (sock.clone(), u.clone(), c2.clone());
                    tokio::spawn(async move {
                        let mut b = vec![0u8; 65_535];
                        loop {
                            let n = tokio::select! {
                                r = back.recv(&mut b) => match r { Ok(n) => n, Err(_) => continue },
                                _ = c3.cancelled() => break,
                            };
                            let _ = front.send_to(&b[..n], peer).await;
                        }
                    });
                    upstreams.insert(peer, u.clone());
                    u
                }
            };
            let _ = up.send(&payload).await;
        }
    });
    Ok(ProxyFixture { addr, log, cancel })
}

/// Plain UDP echo that records every payload exactly as received (a backend
/// behind a gateway that strips the envelope: it must see no envelope bytes).
pub async fn udp_plain_echo(bind: &str) -> anyhow::Result<ProxyFixture> {
    let sock = UdpSocket::bind(bind).await?;
    let addr = sock.local_addr()?;
    let log = ProxyLog::default();
    let cancel = CancellationToken::new();
    let (l2, c2) = (log.clone(), cancel.clone());
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65_535];
        loop {
            let (n, peer) = tokio::select! {
                r = sock.recv_from(&mut buf) => match r { Ok(x) => x, Err(_) => continue },
                _ = c2.cancelled() => break,
            };
            let _ = sock.send_to(&buf[..n], peer).await;
            l2.push(ProxyEvent::Datagram { peer, source: None, sequence: None, authenticated: false, payload: buf[..n].to_vec() });
        }
    });
    Ok(ProxyFixture { addr, log, cancel })
}
