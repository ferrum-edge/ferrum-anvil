//! TCP connect and forward-proxy tunnels with per-address evidence.

use crate::errors::{classify_connect_io, display_chain, io_kind_name};
use anvil_domain::execution::{ConnectAttempt, FailureKind, Phase, TransportFailure};
use base64::Engine;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

pub struct ConnectResult {
    pub stream: TcpStream,
    pub attempts: Vec<ConnectAttempt>,
    pub remote: SocketAddr,
}

/// RFC 8305 "Connection Attempt Delay": how long an attempt may run before
/// the next address is tried in parallel.
const ATTEMPT_DELAY: Duration = Duration::from_millis(250);

/// Connect to the first reachable address within one overall deadline, in
/// the resolver's order, Happy-Eyeballs style (RFC 8305 §5): the next address
/// starts when the current attempt fails or has not finished within
/// [`ATTEMPT_DELAY`], and the first connection wins. An unreachable first
/// address (for example `::1` when only IPv4 listens; Windows retries a
/// refused loopback SYN for about two seconds) therefore does not consume the
/// whole connect budget. Every attempt is recorded in start order; attempts
/// still in flight when another address won are recorded as `canceled`.
pub async fn connect_tcp(
    addrs: &[SocketAddr],
    deadline: Option<Duration>,
) -> Result<ConnectResult, (TransportFailure, Vec<ConnectAttempt>)> {
    use futures::stream::{FuturesUnordered, StreamExt};
    let started = Instant::now();
    let overall = deadline.map(|d| tokio::time::Instant::now() + d);
    let mut attempts: Vec<ConnectAttempt> = Vec::with_capacity(addrs.len());
    let mut in_flight = FuturesUnordered::new();
    let mut next = 0usize;
    let mut last: Option<TransportFailure> = None;
    let launch = |i: usize, attempts: &mut Vec<ConnectAttempt>| {
        let addr = addrs[i];
        attempts.push(ConnectAttempt { address: addr.to_string(), failure: None, duration_us: None });
        let slot = attempts.len() - 1;
        async move {
            let t = Instant::now();
            let r = TcpStream::connect(addr).await;
            (slot, addr, r, t.elapsed().as_micros() as u64)
        }
    };
    loop {
        if in_flight.is_empty() {
            if next >= addrs.len() {
                break;
            }
            in_flight.push(launch(next, &mut attempts));
            next += 1;
        }
        let stagger = if next < addrs.len() { Some(tokio::time::sleep(ATTEMPT_DELAY)) } else { None };
        tokio::select! {
            Some((slot, addr, res, dur)) = in_flight.next() => match res {
                Ok(stream) => {
                    let _ = stream.set_nodelay(true);
                    attempts[slot].duration_us = Some(dur);
                    for (k, a) in attempts.iter_mut().enumerate() {
                        if k != slot && a.failure.is_none() && a.duration_us.is_none() {
                            a.failure = Some(FailureKind::Canceled);
                            a.duration_us = Some(started.elapsed().as_micros() as u64);
                        }
                    }
                    return Ok(ConnectResult { stream, attempts, remote: addr });
                }
                Err(e) => {
                    let kind = classify_connect_io(&e);
                    attempts[slot].failure = Some(kind);
                    attempts[slot].duration_us = Some(dur);
                    let mut f = TransportFailure::new(Phase::Connect, kind, format!("connect to {addr} failed: {}", display_chain(&e)));
                    f.io_error_kind = Some(io_kind_name(e.kind()));
                    f.os_error_code = e.raw_os_error();
                    last = Some(f);
                }
            },
            _ = async { stagger.expect("guarded").await }, if stagger.is_some() => {
                in_flight.push(launch(next, &mut attempts));
                next += 1;
            }
            _ = async { tokio::time::sleep_until(overall.expect("guarded")).await }, if overall.is_some() => {
                for a in attempts.iter_mut().filter(|a| a.failure.is_none()) {
                    a.failure = Some(FailureKind::ConnectTimeout);
                    a.duration_us = Some(started.elapsed().as_micros() as u64);
                }
                let tried = attempts.iter().map(|a| a.address.as_str()).collect::<Vec<_>>().join(", ");
                let f = TransportFailure::new(
                    Phase::Connect,
                    FailureKind::ConnectTimeout,
                    format!("TCP connect did not complete before the connect deadline (tried {tried})"),
                )
                .with_deadline(deadline.map(|d| d.as_millis() as u64));
                return Err((f, attempts));
            }
        }
    }
    let f = last.unwrap_or_else(|| {
        TransportFailure::new(Phase::Connect, FailureKind::ConnectTimeout, "connect deadline elapsed before any address was tried")
            .with_deadline(deadline.map(|d| d.as_millis() as u64))
    });
    Err((f, attempts))
}

/// Establish an HTTP CONNECT tunnel through an already-connected proxy stream.
pub async fn http_connect_tunnel<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    target_authority: &str,
    credentials: Option<(&str, &str)>,
    deadline: Option<Duration>,
) -> Result<(), TransportFailure> {
    let fut = async {
        let mut req = format!("CONNECT {target_authority} HTTP/1.1\r\nHost: {target_authority}\r\n");
        if let Some((u, p)) = credentials {
            let token = base64::engine::general_purpose::STANDARD.encode(format!("{u}:{p}"));
            req.push_str(&format!("Proxy-Authorization: Basic {token}\r\n"));
        }
        req.push_str("\r\n");
        stream.write_all(req.as_bytes()).await.map_err(|e| {
            TransportFailure::new(Phase::ProxyTunnel, FailureKind::ProxyProtocolError, format!("writing CONNECT to proxy failed: {e}"))
        })?;
        // Read the proxy's response head, bounded to 16 KiB.
        let mut buf = Vec::with_capacity(512);
        let mut byte = [0u8; 1];
        loop {
            let n = stream.read(&mut byte).await.map_err(|e| {
                TransportFailure::new(Phase::ProxyTunnel, FailureKind::ProxyProtocolError, format!("reading CONNECT response failed: {e}"))
            })?;
            if n == 0 {
                return Err(TransportFailure::new(
                    Phase::ProxyTunnel,
                    FailureKind::ProxyProtocolError,
                    "proxy closed the connection before answering CONNECT",
                ));
            }
            buf.push(byte[0]);
            if buf.ends_with(b"\r\n\r\n") {
                break;
            }
            if buf.len() > 16 * 1024 {
                return Err(TransportFailure::new(
                    Phase::ProxyTunnel,
                    FailureKind::ProxyProtocolError,
                    "proxy CONNECT response head too large",
                ));
            }
        }
        let head = String::from_utf8_lossy(&buf);
        let status: u16 = head.lines().next().and_then(|l| l.split_whitespace().nth(1)).and_then(|s| s.parse().ok()).ok_or_else(|| {
            TransportFailure::new(Phase::ProxyTunnel, FailureKind::ProxyProtocolError, "proxy sent an unparseable CONNECT response")
        })?;
        if (200..300).contains(&status) {
            Ok(())
        } else {
            let kind = if status == 407 { FailureKind::ProxyAuthRequired } else { FailureKind::ProxyTunnelRejected };
            let mut f =
                TransportFailure::new(Phase::ProxyTunnel, kind, format!("proxy refused CONNECT to {target_authority} with HTTP {status}"));
            f.status = Some(status);
            Err(f)
        }
    };
    match deadline {
        Some(d) => tokio::time::timeout(d, fut).await.unwrap_or_else(|_| {
            Err(TransportFailure::new(
                Phase::ProxyTunnel,
                FailureKind::ProxyProtocolError,
                "proxy did not answer CONNECT before the connect deadline",
            )
            .with_deadline(Some(d.as_millis() as u64)))
        }),
        None => fut.await,
    }
}

/// Minimal SOCKS5 (RFC 1928/1929) CONNECT with optional username/password.
pub async fn socks5_connect<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    host: &str,
    port: u16,
    credentials: Option<(&str, &str)>,
    deadline: Option<Duration>,
) -> Result<(), TransportFailure> {
    let perr = |m: String| TransportFailure::new(Phase::ProxyTunnel, FailureKind::ProxyProtocolError, m);
    let fut = async {
        let methods: &[u8] = if credentials.is_some() { &[0x05, 0x02, 0x00, 0x02] } else { &[0x05, 0x01, 0x00] };
        stream.write_all(methods).await.map_err(|e| perr(format!("SOCKS5 greeting failed: {e}")))?;
        let mut sel = [0u8; 2];
        stream.read_exact(&mut sel).await.map_err(|e| perr(format!("SOCKS5 method selection failed: {e}")))?;
        if sel[0] != 0x05 {
            return Err(perr("peer is not a SOCKS5 proxy".into()));
        }
        match sel[1] {
            0x00 => {}
            0x02 => {
                let (u, p) = credentials.ok_or_else(|| perr("SOCKS5 proxy requested credentials".into()))?;
                if u.len() > 255 || p.len() > 255 {
                    return Err(TransportFailure::new(
                        Phase::Prepare,
                        FailureKind::ProxyConfigInvalid,
                        "SOCKS5 credentials exceed 255 bytes",
                    ));
                }
                let mut m = vec![0x01, u.len() as u8];
                m.extend_from_slice(u.as_bytes());
                m.push(p.len() as u8);
                m.extend_from_slice(p.as_bytes());
                stream.write_all(&m).await.map_err(|e| perr(format!("SOCKS5 auth write failed: {e}")))?;
                let mut r = [0u8; 2];
                stream.read_exact(&mut r).await.map_err(|e| perr(format!("SOCKS5 auth read failed: {e}")))?;
                if r[1] != 0 {
                    return Err(TransportFailure::new(
                        Phase::ProxyTunnel,
                        FailureKind::ProxyAuthRequired,
                        "SOCKS5 proxy rejected the credentials",
                    ));
                }
            }
            0xFF => {
                return Err(TransportFailure::new(
                    Phase::ProxyTunnel,
                    FailureKind::ProxyAuthRequired,
                    "SOCKS5 proxy accepted none of the offered auth methods",
                ));
            }
            m => {
                return Err(perr(format!("SOCKS5 proxy selected unsupported method {m}")));
            }
        }
        let mut req = vec![0x05, 0x01, 0x00];
        match host.trim_start_matches('[').trim_end_matches(']').parse::<std::net::IpAddr>() {
            Ok(std::net::IpAddr::V4(v4)) => {
                req.push(0x01);
                req.extend_from_slice(&v4.octets());
            }
            Ok(std::net::IpAddr::V6(v6)) => {
                req.push(0x04);
                req.extend_from_slice(&v6.octets());
            }
            Err(_) => {
                if host.len() > 255 {
                    return Err(TransportFailure::new(Phase::Prepare, FailureKind::InvalidUrl, "host name too long for SOCKS5"));
                }
                req.push(0x03);
                req.push(host.len() as u8);
                req.extend_from_slice(host.as_bytes());
            }
        }
        req.extend_from_slice(&port.to_be_bytes());
        stream.write_all(&req).await.map_err(|e| perr(format!("SOCKS5 connect write failed: {e}")))?;
        let mut head = [0u8; 4];
        stream.read_exact(&mut head).await.map_err(|e| perr(format!("SOCKS5 connect reply failed: {e}")))?;
        if head[1] != 0x00 {
            let mut f = TransportFailure::new(
                Phase::ProxyTunnel,
                FailureKind::ProxyTunnelRejected,
                format!("SOCKS5 proxy could not connect to {host}:{port} (reply code {})", head[1]),
            );
            f.status = Some(head[1] as u16);
            return Err(f);
        }
        let skip = match head[3] {
            0x01 => 4 + 2,
            0x04 => 16 + 2,
            0x03 => {
                let mut l = [0u8; 1];
                stream.read_exact(&mut l).await.map_err(|e| perr(format!("SOCKS5 reply read failed: {e}")))?;
                l[0] as usize + 2
            }
            _ => return Err(perr("SOCKS5 reply has unknown address type".into())),
        };
        let mut rest = vec![0u8; skip];
        stream.read_exact(&mut rest).await.map_err(|e| perr(format!("SOCKS5 reply read failed: {e}")))?;
        Ok(())
    };
    match deadline {
        Some(d) => tokio::time::timeout(d, fut).await.unwrap_or_else(|_| {
            Err(perr("SOCKS5 proxy did not complete the tunnel before the connect deadline".into())
                .with_deadline(Some(d.as_millis() as u64)))
        }),
        None => fut.await,
    }
}

/// `NO_PROXY` matching: `*`, exact hosts, `.suffix` / `suffix` domain matches,
/// IP literals and CIDR blocks. Ports in entries (`host:port`) must match.
pub fn no_proxy_matches(no_proxy: &str, host: &str, port: u16) -> bool {
    let host = host.trim_start_matches('[').trim_end_matches(']').to_ascii_lowercase();
    for raw in no_proxy.split(',') {
        let entry = raw.trim().to_ascii_lowercase();
        if entry.is_empty() {
            continue;
        }
        if entry == "*" {
            return true;
        }
        let (name, eport) = match entry.rsplit_once(':') {
            Some((n, p)) if !n.contains(':') || n.ends_with(']') => match p.parse::<u16>() {
                Ok(pp) => (n.trim_start_matches('[').trim_end_matches(']').to_string(), Some(pp)),
                Err(_) => (entry.clone(), None),
            },
            _ => (entry.trim_start_matches('[').trim_end_matches(']').to_string(), None),
        };
        if let Some(p) = eport
            && p != port
        {
            continue;
        }
        if let Some((net, bits)) = name.split_once('/')
            && let (Ok(net), Ok(bits)) = (net.parse::<std::net::IpAddr>(), bits.parse::<u8>())
            && let Ok(ip) = host.parse::<std::net::IpAddr>()
        {
            if cidr_contains(net, bits, ip) {
                return true;
            }
            continue;
        }
        let suffix = name.trim_start_matches('.');
        if host == suffix || host.ends_with(&format!(".{suffix}")) {
            return true;
        }
    }
    false
}

fn cidr_contains(net: std::net::IpAddr, bits: u8, ip: std::net::IpAddr) -> bool {
    use std::net::IpAddr::*;
    match (net, ip) {
        (V4(n), V4(i)) => {
            if bits > 32 {
                return false;
            }
            let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
            (u32::from(n) & mask) == (u32::from(i) & mask)
        }
        (V6(n), V6(i)) => {
            if bits > 128 {
                return false;
            }
            let mask = if bits == 0 { 0 } else { u128::MAX << (128 - bits) };
            (u128::from(n) & mask) == (u128::from(i) & mask)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_proxy_semantics() {
        assert!(no_proxy_matches("*", "example.com", 443));
        assert!(no_proxy_matches("example.com", "api.example.com", 443));
        assert!(no_proxy_matches(".example.com", "example.com", 443));
        assert!(!no_proxy_matches("example.com", "badexample.com", 443));
        assert!(no_proxy_matches("10.0.0.0/8", "10.1.2.3", 80));
        assert!(!no_proxy_matches("10.0.0.0/8", "11.1.2.3", 80));
        assert!(no_proxy_matches("localhost:8080", "localhost", 8080));
        assert!(!no_proxy_matches("localhost:8080", "localhost", 9090));
        assert!(no_proxy_matches("::1", "[::1]", 80));
    }
}

#[cfg(test)]
mod happy_eyeballs_tests {
    use super::*;

    /// An address that never answers (TEST-NET-1, RFC 5737), so its attempt
    /// hangs like a refused `::1` on Windows or a black-holed IPv6 route.
    fn black_hole() -> SocketAddr {
        "192.0.2.1:9".parse().unwrap()
    }

    #[tokio::test]
    async fn a_hanging_first_address_does_not_consume_the_connect_budget() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let live = l.local_addr().unwrap();
        let t = Instant::now();
        let r = connect_tcp(&[black_hole(), live], Some(Duration::from_secs(5))).await.map_err(|(f, _)| f).unwrap();
        assert!(t.elapsed() < Duration::from_secs(2), "took {:?}", t.elapsed());
        assert_eq!(r.remote, live);
        assert_eq!(r.attempts.len(), 2);
        assert_eq!(r.attempts[0].failure, Some(FailureKind::Canceled), "superseded, not connected: {:?}", r.attempts);
        assert_eq!(r.attempts[1].failure, None);
    }

    /// Where a refusal is immediate (Linux, macOS) the next address is tried at
    /// once, without waiting out the stagger. Windows retransmits the SYN to a
    /// closed loopback port for about 2 s before reporting the refusal, so there
    /// the attempt is still pending when the stagger starts the next address and
    /// is recorded as superseded.
    #[tokio::test]
    async fn a_refused_first_address_moves_on_immediately() {
        let closed = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap()
        };
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let live = l.local_addr().unwrap();
        let t = Instant::now();
        let r = connect_tcp(&[closed, live], Some(Duration::from_secs(5))).await.map_err(|(f, _)| f).unwrap();
        assert_eq!(r.remote, live);
        assert_eq!(r.attempts.len(), 2);
        assert_eq!(r.attempts[1].failure, None);
        if cfg!(windows) {
            assert_eq!(r.attempts[0].failure, Some(FailureKind::Canceled), "{:?}", r.attempts);
            assert!(t.elapsed() < Duration::from_secs(2), "took {:?}", t.elapsed());
        } else {
            assert_eq!(r.attempts[0].failure, Some(FailureKind::ConnectRefused), "{:?}", r.attempts);
            assert!(t.elapsed() < ATTEMPT_DELAY, "moved on before the stagger: {:?}", t.elapsed());
        }
    }

    #[tokio::test]
    async fn the_overall_deadline_covers_every_address() {
        let t = Instant::now();
        let (f, attempts) =
            connect_tcp(&[black_hole(), "192.0.2.2:9".parse().unwrap()], Some(Duration::from_millis(600))).await.err().unwrap();
        assert!(t.elapsed() < Duration::from_millis(1_500));
        assert_eq!(f.kind, FailureKind::ConnectTimeout);
        assert_eq!(attempts.len(), 2, "both addresses were tried within the budget");
        assert!(attempts.iter().all(|a| a.failure == Some(FailureKind::ConnectTimeout)));
    }
}
