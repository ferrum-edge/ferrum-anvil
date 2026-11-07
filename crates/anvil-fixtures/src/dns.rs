//! Minimal DNS fixture (UDP + TCP): answers every query with a fixed RCODE
//! (default NXDOMAIN), or never answers (`Silent`) to produce resolver timeouts.

use crate::log::{GroundTruth, GroundTruthLog};
use crate::ports::{self, PORT_ZERO_BIND_ATTEMPTS, PairBindError, TcpBindFuture, retryable_bind_error};
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio_util::sync::CancellationToken;

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

/// Binds a TCP listener and a UDP socket to the same ephemeral port of
/// `bind`'s host ([`crate::ports`]: UDP first, a TCP refusal retried on
/// another port). Only for a port-0 `bind`: [`serve`] binds an explicitly
/// requested port once and reports any failure as-is.
///
/// A UDP bind is retried only when [`retryable_bind_error`]; any other UDP
/// error is returned at once.
async fn bind_ephemeral_pair_with<Tcp, Udp, T, U>(bind: &str, bind_udp: U, bind_tcp: T) -> io::Result<(Udp, Tcp)>
where
    Udp: BoundUdpSocket + Send + 'static,
    T: FnMut(SocketAddr) -> TcpBindFuture<Tcp>,
    U: FnMut(&str) -> UdpBindFuture<Udp>,
{
    bind_ephemeral_pair_with_start(bind, ports::random_start(), bind_udp, bind_tcp).await
}

async fn bind_ephemeral_pair_with_start<Tcp, Udp, T, U>(
    bind: &str,
    random_start: u16,
    mut bind_udp: U,
    bind_tcp: T,
) -> io::Result<(Udp, Tcp)>
where
    Udp: BoundUdpSocket + Send + 'static,
    T: FnMut(SocketAddr) -> TcpBindFuture<Tcp>,
    U: FnMut(&str) -> UdpBindFuture<Udp>,
{
    let bind_udp = |port: Option<u16>| -> ports::UdpBindFuture<Udp, io::Error> {
        let bound = bind_udp(&port.map_or_else(|| bind.to_owned(), |port| bind_with_port(bind, port)));
        Box::pin(async move {
            let udp = bound.await?;
            let addr = udp.local_addr()?;
            Ok((udp, addr))
        })
    };
    match ports::bind_udp_tcp_pair(random_start, retryable_bind_error, bind_udp, bind_tcp).await {
        Ok(pair) => Ok(pair),
        Err(PairBindError::Fatal(error)) => Err(error),
        Err(PairBindError::Exhausted { tried_ports, last_error }) => {
            let error = last_error.unwrap_or_else(|| io::Error::other("the DNS fixture pair bind made no attempts"));
            Err(io::Error::new(
                error.kind(),
                format!(
                    "could not bind a DNS UDP/TCP pair after {PORT_ZERO_BIND_ATTEMPTS} attempts; tried UDP ports {tried_ports:?}: {error}"
                ),
            ))
        }
    }
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
    use crate::ports::{DYNAMIC_PORT_START, SEQUENTIAL_BIND_ATTEMPTS, WINDOWS_WSAEACCES};
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Copy, Debug)]
    struct MockUdpSocket(SocketAddr);

    impl BoundUdpSocket for MockUdpSocket {
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok(self.0)
        }
    }

    #[derive(Debug)]
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
    async fn ephemeral_pair_returns_a_non_retryable_udp_error_at_once() {
        // Unlike the HTTP/3 replay fixture, which retries every failed QUIC endpoint creation.
        let calls = Arc::new(Mutex::new(0usize));
        let bind_calls = calls.clone();
        let result = bind_ephemeral_pair_with(
            "127.0.0.1:0",
            move |_| {
                *bind_calls.lock().unwrap() += 1;
                let error = io::Error::from(io::ErrorKind::AddrNotAvailable);
                Box::pin(async move { Err(error) }) as UdpBindFuture<MockUdpSocket>
            },
            |addr| Box::pin(async move { Ok(MockTcpListener(addr)) }) as TcpBindFuture<MockTcpListener>,
        )
        .await;

        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::AddrNotAvailable);
        assert_eq!(*calls.lock().unwrap(), 1);
    }

    #[tokio::test]
    async fn ephemeral_pair_walks_ports_of_the_requested_host() {
        let binds = Arc::new(Mutex::new(Vec::new()));
        let seen = binds.clone();
        let result = bind_ephemeral_pair_with_start(
            "[::1]:0",
            0,
            move |bind: &str| {
                seen.lock().unwrap().push(bind.to_owned());
                let error = io::Error::from(io::ErrorKind::AddrInUse);
                Box::pin(async move { Err(error) }) as UdpBindFuture<MockUdpSocket>
            },
            |addr| Box::pin(async move { Ok(MockTcpListener(addr)) }) as TcpBindFuture<MockTcpListener>,
        )
        .await;

        let error = result.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
        assert!(error.to_string().starts_with("could not bind a DNS UDP/TCP pair after 64 attempts"), "{error}");
        let binds = binds.lock().unwrap();
        assert!(binds[..SEQUENTIAL_BIND_ATTEMPTS].iter().all(|b| b == "[::1]:0"), "{binds:?}");
        assert_eq!(binds[SEQUENTIAL_BIND_ATTEMPTS], format!("[::1]:{DYNAMIC_PORT_START}"));
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
                    let denied: io::Result<MockTcpListener> = Err(io::Error::from_raw_os_error(WINDOWS_WSAEACCES));
                    Box::pin(async move { denied }) as TcpBindFuture<MockTcpListener>
                } else {
                    Box::pin(async move { Ok(MockTcpListener(addr)) }) as TcpBindFuture<MockTcpListener>
                }
            },
        )
        .await
        .unwrap();

        let tried = ports.lock().unwrap();
        assert_eq!(tried.len(), SEQUENTIAL_BIND_ATTEMPTS + 1);
        assert_eq!(tried[..SEQUENTIAL_BIND_ATTEMPTS], [55_000, 55_001, 55_002, 55_003]);
        assert_eq!(tried[SEQUENTIAL_BIND_ATTEMPTS], 60_000);
        assert!(tried[..SEQUENTIAL_BIND_ATTEMPTS].iter().all(|port| (exclusion_start..exclusion_end).contains(port)));
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
                let port = if bind.ends_with(":0") { 55_000 + attempt as u16 } else { bind.rsplit_once(':').unwrap().1.parse().unwrap() };
                let socket = MockUdpSocket(SocketAddr::from(([127, 0, 0, 1], port)));
                Box::pin(async move { Ok(socket) }) as UdpBindFuture<MockUdpSocket>
            },
            move |addr| {
                bind_ports.lock().unwrap().push(addr.port());
                let denied: io::Result<MockTcpListener> = Err(io::Error::from_raw_os_error(WINDOWS_WSAEACCES));
                Box::pin(async move { denied }) as TcpBindFuture<MockTcpListener>
            },
        )
        .await;

        let tried = ports.lock().unwrap();
        assert_eq!(attempts.load(Ordering::SeqCst), PORT_ZERO_BIND_ATTEMPTS);
        assert_eq!(tried.len(), PORT_ZERO_BIND_ATTEMPTS);
        assert_eq!(tried.iter().copied().collect::<std::collections::HashSet<_>>().len(), tried.len());
        let error = result.unwrap_err().to_string();
        assert!(error.contains("tried UDP ports ["));
        for port in tried.iter() {
            assert!(error.contains(&port.to_string()), "error omitted tried port {port}: {error}");
        }
    }
}
