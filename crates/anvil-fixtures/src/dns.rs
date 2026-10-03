//! Minimal DNS fixture (UDP + TCP): answers every query with a fixed RCODE
//! (default NXDOMAIN), or never answers (`Silent`) to produce resolver timeouts.

use crate::log::{GroundTruth, GroundTruthLog};
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio_util::sync::CancellationToken;

const PORT_ZERO_BIND_ATTEMPTS: usize = 64;
const SEQUENTIAL_BIND_ATTEMPTS: usize = 4;
const DYNAMIC_PORT_START: u16 = 49_152;
const DYNAMIC_PORT_COUNT: u16 = u16::MAX - DYNAMIC_PORT_START + 1;
const DYNAMIC_PORT_STRIDE: u16 = 9_973;

/// `WSAEACCES`: Windows refuses a bind that lands inside a reserved/excluded
/// port range (Hyper-V, WinNAT, WSL). Rust maps it to `PermissionDenied` on
/// Windows, but the raw code is matched too, so the retry can be exercised on
/// any platform.
const WINDOWS_WSAEACCES: i32 = 10013;

type TcpBindFuture<Tcp> = Pin<Box<dyn Future<Output = io::Result<Tcp>> + Send>>;
type UdpBindFuture<Udp> = Pin<Box<dyn Future<Output = io::Result<Udp>> + Send>>;

trait BoundUdpSocket {
    fn local_addr(&self) -> io::Result<SocketAddr>;
}

impl BoundUdpSocket for UdpSocket {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        UdpSocket::local_addr(self)
    }
}

/// A `'static` UDP bind future: the address is copied, so the future does not
/// borrow the caller's `&str`.
fn bind_udp_future(bind: &str) -> UdpBindFuture<UdpSocket> {
    let bind = bind.to_owned();
    Box::pin(async move { UdpSocket::bind(bind).await })
}

fn retryable_bind_error(error: &io::Error) -> bool {
    if error.raw_os_error() == Some(WINDOWS_WSAEACCES) {
        return true;
    }
    matches!(error.kind(), io::ErrorKind::PermissionDenied | io::ErrorKind::AddrInUse)
}

/// Binds a TCP listener and a UDP socket to the same ephemeral port.
///
/// Windows reserves blocks of TCP ports (Hyper-V/WinNAT excluded ranges), and
/// an explicit TCP bind to one fails with WSAEACCES (10013). The UDP port is
/// assigned first, then TCP is bound to that port. If TCP refuses it, the UDP
/// socket is kept until the function returns so another attempt cannot
/// receive the same port. Port 0 binds take this path; an explicitly
/// requested port is bound once and reported as-is.
async fn bind_ephemeral_pair_with<Tcp, Udp, T, U>(
    bind: &str,
    bind_udp: U,
    bind_tcp: T,
) -> io::Result<(Udp, Tcp)>
where
    Udp: BoundUdpSocket,
    T: FnMut(SocketAddr) -> TcpBindFuture<Tcp>,
    U: FnMut(&str) -> UdpBindFuture<Udp>,
{
    bind_ephemeral_pair_with_start(
        bind,
        rand::random_range(0..DYNAMIC_PORT_COUNT),
        bind_udp,
        bind_tcp,
    )
    .await
}

async fn bind_ephemeral_pair_with_start<Tcp, Udp, T, U>(
    bind: &str,
    random_start: u16,
    mut bind_udp: U,
    mut bind_tcp: T,
) -> io::Result<(Udp, Tcp)>
where
    Udp: BoundUdpSocket,
    T: FnMut(SocketAddr) -> TcpBindFuture<Tcp>,
    U: FnMut(&str) -> UdpBindFuture<Udp>,
{
    let mut rejected = Vec::new();
    let mut tried_ports = Vec::new();
    let mut last_error = None;
    for attempt in 0..PORT_ZERO_BIND_ATTEMPTS {
        let candidate_bind = if requests_ephemeral_port(bind) && attempt >= SEQUENTIAL_BIND_ATTEMPTS {
            let mut offset = attempt - SEQUENTIAL_BIND_ATTEMPTS;
            let port = loop {
                let port = dynamic_port_candidate(random_start, offset);
                if !tried_ports.contains(&port) {
                    break port;
                }
                offset += 1;
            };
            tried_ports.push(port);
            bind_with_port(bind, port)
        } else {
            bind.to_owned()
        };
        let udp = match bind_udp(&candidate_bind).await {
            Ok(udp) => udp,
            Err(error) if retryable_bind_error(&error) => {
                last_error = Some(error);
                continue;
            }
            Err(error) => return Err(error),
        };
        let addr = udp.local_addr()?;
        if !tried_ports.contains(&addr.port()) {
            tried_ports.push(addr.port());
        }
        match bind_tcp(addr).await {
            Ok(tcp) => return Ok((udp, tcp)),
            Err(error) if retryable_bind_error(&error) => {
                last_error = Some(error);
                rejected.push(udp);
            }
            Err(error) => return Err(error),
        }
    }

    let error = last_error.unwrap_or_else(|| io::Error::other("the DNS fixture pair bind made no attempts"));
    Err(io::Error::new(
        error.kind(),
        format!("could not bind a DNS UDP/TCP pair after {PORT_ZERO_BIND_ATTEMPTS} attempts; tried UDP ports {tried_ports:?}: {error}"),
    ))
}

fn dynamic_port_candidate(random_start: u16, offset: usize) -> u16 {
    let position = (u32::from(random_start) + (offset as u32 * u32::from(DYNAMIC_PORT_STRIDE))) % u32::from(DYNAMIC_PORT_COUNT);
    DYNAMIC_PORT_START + position as u16
}

fn bind_with_port(bind: &str, port: u16) -> String {
    let (host, _) = bind.rsplit_once(':').expect("socket address includes a port");
    format!("{host}:{port}")
}

fn requests_ephemeral_port(bind: &str) -> bool {
    bind.rsplit_once(':').and_then(|(_, port)| port.parse::<u16>().ok()) == Some(0)
}

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
    let (udp, tcp) = if requests_ephemeral_port(bind) {
        bind_ephemeral_pair_with(bind, bind_udp_future, |addr| Box::pin(TcpListener::bind(addr))).await?
    } else {
        let udp = UdpSocket::bind(bind).await?;
        let addr = udp.local_addr()?;
        let tcp = TcpListener::bind(addr).await?;
        (udp, tcp)
    };
    let addr = udp.local_addr()?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Copy)]
    struct MockUdpSocket(SocketAddr);

    impl BoundUdpSocket for MockUdpSocket {
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok(self.0)
        }
    }

    struct MockTcpListener(SocketAddr);

    #[tokio::test]
    async fn ephemeral_pair_retries_when_udp_port_is_occupied() {
        let calls = Arc::new(Mutex::new(0usize));
        let bind_calls = calls.clone();

        let (udp, tcp) = bind_ephemeral_pair_with(
            "127.0.0.1:0",
            move |_| {
                let attempt = {
                    let mut calls = bind_calls.lock().unwrap();
                    *calls += 1;
                    *calls
                };
                if attempt == 1 {
                    let error = io::Error::from(io::ErrorKind::AddrInUse);
                    Box::pin(async move { Err(error) }) as UdpBindFuture<MockUdpSocket>
                } else {
                    let socket = MockUdpSocket(SocketAddr::from(([127, 0, 0, 1], 54_321)));
                    Box::pin(async move { Ok(socket) }) as UdpBindFuture<MockUdpSocket>
                }
            },
            |addr| Box::pin(async move { Ok(MockTcpListener(addr)) }) as TcpBindFuture<MockTcpListener>,
        )
        .await
        .unwrap();

        assert_eq!(*calls.lock().unwrap(), 2);
        assert_eq!(udp.local_addr().unwrap().port(), 54_321);
        assert_eq!(udp.local_addr().unwrap().port(), tcp.0.port());
    }

    #[tokio::test]
    async fn ephemeral_pair_binds_udp_first_and_retries_tcp_refusal() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let bind_calls = calls.clone();
        let order = Arc::new(Mutex::new(Vec::new()));
        let udp_order = order.clone();
        let tcp_order = order.clone();
        let udp_calls = Arc::new(Mutex::new(0usize));
        let bind_udp_calls = udp_calls.clone();

        let (udp, tcp) = bind_ephemeral_pair_with(
            "127.0.0.1:0",
            move |_| {
                udp_order.lock().unwrap().push("udp");
                let attempt = {
                    let mut calls = bind_udp_calls.lock().unwrap();
                    *calls += 1;
                    *calls
                };
                let port = if attempt == 1 { 54_321 } else { 54_322 };
                let socket = MockUdpSocket(SocketAddr::from(([127, 0, 0, 1], port)));
                Box::pin(async move { Ok(socket) }) as UdpBindFuture<MockUdpSocket>
            },
            move |addr| {
                tcp_order.lock().unwrap().push("tcp");
                let attempt = {
                    let mut calls = bind_calls.lock().unwrap();
                    calls.push(addr.port());
                    calls.len()
                };
                if attempt == 1 {
                    let denied: io::Result<MockTcpListener> = Err(io::Error::from_raw_os_error(WINDOWS_WSAEACCES));
                    Box::pin(async move { denied }) as TcpBindFuture<MockTcpListener>
                } else {
                    Box::pin(async move { Ok(MockTcpListener(addr)) }) as TcpBindFuture<MockTcpListener>
                }
            },
        )
        .await
        .unwrap();

        let calls = calls.lock().unwrap();
        assert_eq!(calls.len(), 2, "the denied TCP bind was not retried");
        assert_ne!(calls[0], calls[1], "the rejected UDP candidate was released and handed back");
        assert_eq!(*order.lock().unwrap(), ["udp", "tcp", "udp", "tcp"]);
        assert_eq!(udp.local_addr().unwrap().port(), calls[1]);
        assert_eq!(udp.local_addr().unwrap().port(), tcp.0.port());
    }

    #[tokio::test]
    async fn ephemeral_pair_escapes_a_contiguous_tcp_exclusion() {
        let exclusion_start = 55_000;
        let exclusion_end = exclusion_start + 500;
        let random_start = 60_000 - DYNAMIC_PORT_START;
        let next_port = Arc::new(Mutex::new(exclusion_start));
        let ports = Arc::new(Mutex::new(Vec::new()));
        let bind_next = next_port.clone();
        let tcp_ports = ports.clone();

        let (udp, tcp) = bind_ephemeral_pair_with_start(
            "127.0.0.1:0",
            random_start,
            move |bind| {
                let addr = if bind.ends_with(":0") {
                    let mut port = bind_next.lock().unwrap();
                    let addr = SocketAddr::from(([127, 0, 0, 1], *port));
                    *port += 1;
                    addr
                } else {
                    bind.parse().unwrap()
                };
                Box::pin(async move { Ok(MockUdpSocket(addr)) }) as UdpBindFuture<MockUdpSocket>
            },
            move |addr| {
                tcp_ports.lock().unwrap().push(addr.port());
                if (exclusion_start..exclusion_end).contains(&addr.port()) {
                    let denied: io::Result<MockTcpListener> =
                        Err(io::Error::from_raw_os_error(WINDOWS_WSAEACCES));
                    Box::pin(async move { denied }) as TcpBindFuture<MockTcpListener>
                } else {
                    Box::pin(async move { Ok(MockTcpListener(addr)) })
                        as TcpBindFuture<MockTcpListener>
                }
            },
        )
        .await
        .unwrap();

        let tried = ports.lock().unwrap();
        assert_eq!(tried.len(), SEQUENTIAL_BIND_ATTEMPTS + 1);
        assert_eq!(tried[..SEQUENTIAL_BIND_ATTEMPTS], [55_000, 55_001, 55_002, 55_003]);
        assert_eq!(tried[SEQUENTIAL_BIND_ATTEMPTS], 60_000);
        assert!(tried[..SEQUENTIAL_BIND_ATTEMPTS]
            .iter()
            .all(|port| (exclusion_start..exclusion_end).contains(port)));
        assert!(!(exclusion_start..exclusion_end).contains(&tried[SEQUENTIAL_BIND_ATTEMPTS]));
        assert_eq!(udp.local_addr().unwrap().port(), tried[SEQUENTIAL_BIND_ATTEMPTS]);
        assert_eq!(udp.local_addr().unwrap().port(), tcp.0.port());
    }

    #[tokio::test]
    async fn ephemeral_pair_final_error_lists_tried_ports() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let attempts = Arc::new(AtomicUsize::new(0));
        let udp_attempts = attempts.clone();
        let ports = Arc::new(Mutex::new(Vec::new()));
        let bind_ports = ports.clone();
        let result = bind_ephemeral_pair_with(
            "127.0.0.1:0",
            move |bind: &str| {
                let attempt = udp_attempts.fetch_add(1, Ordering::SeqCst);
                let port = if bind.ends_with(":0") {
                    55_000 + attempt as u16
                } else {
                    bind.rsplit_once(':').unwrap().1.parse().unwrap()
                };
                let socket = MockUdpSocket(SocketAddr::from(([127, 0, 0, 1], port)));
                Box::pin(async move { Ok(socket) }) as UdpBindFuture<MockUdpSocket>
            },
            move |addr| {
                bind_ports.lock().unwrap().push(addr.port());
                let denied: io::Result<MockTcpListener> =
                    Err(io::Error::from_raw_os_error(WINDOWS_WSAEACCES));
                Box::pin(async move { denied }) as TcpBindFuture<MockTcpListener>
            },
        )
        .await;

        let tried = ports.lock().unwrap();
        assert_eq!(attempts.load(Ordering::SeqCst), PORT_ZERO_BIND_ATTEMPTS);
        assert_eq!(tried.len(), PORT_ZERO_BIND_ATTEMPTS);
        assert_eq!(
            tried
                .iter()
                .copied()
                .collect::<std::collections::HashSet<_>>()
                .len(),
            tried.len()
        );
        let error = result.unwrap_err().to_string();
        assert!(error.contains("tried UDP ports ["));
        for port in tried.iter() {
            assert!(error.contains(&port.to_string()), "error omitted tried port {port}: {error}");
        }
    }

    #[test]
    fn windows_excluded_port_and_addr_in_use_are_retryable() {
        assert!(retryable_bind_error(&io::Error::from_raw_os_error(WINDOWS_WSAEACCES)));
        assert!(retryable_bind_error(&io::Error::from(io::ErrorKind::PermissionDenied)));
        assert!(retryable_bind_error(&io::Error::from(io::ErrorKind::AddrInUse)));
        assert!(!retryable_bind_error(&io::Error::from(io::ErrorKind::ConnectionRefused)));
    }
}
