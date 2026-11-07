//! One port over both UDP and TCP, for fixtures that serve both on the same
//! port (the DNS fixture; HTTP/3 with its TCP fallback).
//!
//! Windows reserves blocks of TCP ports (Hyper-V/WinNAT/WSL excluded ranges),
//! and an explicit TCP bind to one fails with WSAEACCES (10013). The UDP port
//! is therefore assigned first (Windows assigns UDP port 0 outside those
//! ranges), then TCP is bound to it. When TCP refuses the port, the UDP
//! socket is held until the pair bind returns so a later attempt cannot be
//! handed the same port. After [`SEQUENTIAL_BIND_ATTEMPTS`] port-0 attempts,
//! candidates come from a strided walk over the dynamic range that starts at
//! a random position, so a contiguous exclusion is escaped.
//!
//! What each fixture binds, which failed UDP binds it retries, and how it
//! reports running out of attempts stay with the fixture.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;

pub(crate) const PORT_ZERO_BIND_ATTEMPTS: usize = 64;
pub(crate) const SEQUENTIAL_BIND_ATTEMPTS: usize = 4;
pub(crate) const DYNAMIC_PORT_START: u16 = 49_152;
pub(crate) const DYNAMIC_PORT_COUNT: u16 = u16::MAX - DYNAMIC_PORT_START + 1;
const DYNAMIC_PORT_STRIDE: u16 = 9_973;

/// `WSAEACCES`: Windows refuses a bind that lands inside a reserved/excluded
/// port range (Hyper-V, WinNAT, WSL). Rust maps it to `PermissionDenied` on
/// Windows, but the raw code is matched too, so the retry can be exercised on
/// any platform.
pub(crate) const WINDOWS_WSAEACCES: i32 = 10013;

pub(crate) type TcpBindFuture<Tcp> = Pin<Box<dyn Future<Output = io::Result<Tcp>> + Send>>;

/// A UDP bind to the given port (`None`: port 0, the system assigns one),
/// with the address it got.
pub(crate) type UdpBindFuture<Udp, E> = Pin<Box<dyn Future<Output = Result<(Udp, SocketAddr), E>> + Send>>;

/// A bind refused because the port is excluded (WSAEACCES), not permitted or
/// already in use: another port may work.
pub(crate) fn retryable_bind_error(error: &io::Error) -> bool {
    error.raw_os_error() == Some(WINDOWS_WSAEACCES) || matches!(error.kind(), io::ErrorKind::PermissionDenied | io::ErrorKind::AddrInUse)
}

/// Where the dynamic-port walk starts.
pub(crate) fn random_start() -> u16 {
    rand::random_range(0..DYNAMIC_PORT_COUNT)
}

/// The `offset`-th port of the strided walk over the dynamic range.
pub(crate) fn dynamic_port_candidate(random_start: u16, offset: usize) -> u16 {
    let position = (u32::from(random_start) + (offset as u32 * u32::from(DYNAMIC_PORT_STRIDE))) % u32::from(DYNAMIC_PORT_COUNT);
    DYNAMIC_PORT_START + position as u16
}

/// Why [`bind_udp_tcp_pair`] returned no pair.
#[derive(Debug)]
pub(crate) enum PairBindError<E> {
    /// A bind failed in a way that is not retried.
    Fatal(E),
    /// Every one of [`PORT_ZERO_BIND_ATTEMPTS`] attempts failed.
    Exhausted { tried_ports: Vec<u16>, last_error: Option<E> },
}

/// A UDP socket and a TCP listener on the same port (see the module docs).
///
/// `udp_error_retryable` decides which failed UDP binds are retried; any
/// other UDP error is returned at once. A TCP bind is retried on another
/// port only when [`retryable_bind_error`]; any other TCP error is returned
/// at once.
pub(crate) async fn bind_udp_tcp_pair<Udp, Tcp, E, U, T>(
    random_start: u16,
    udp_error_retryable: fn(&E) -> bool,
    mut bind_udp: U,
    mut bind_tcp: T,
) -> Result<(Udp, Tcp), PairBindError<E>>
where
    E: From<io::Error>,
    U: FnMut(Option<u16>) -> UdpBindFuture<Udp, E>,
    T: FnMut(SocketAddr) -> TcpBindFuture<Tcp>,
{
    let mut rejected = Vec::new();
    let mut tried_ports = Vec::new();
    let mut last_error = None;
    for attempt in 0..PORT_ZERO_BIND_ATTEMPTS {
        let candidate_port = (attempt >= SEQUENTIAL_BIND_ATTEMPTS).then(|| {
            let mut offset = attempt - SEQUENTIAL_BIND_ATTEMPTS;
            loop {
                let port = dynamic_port_candidate(random_start, offset);
                if !tried_ports.contains(&port) {
                    break port;
                }
                offset += 1;
            }
        });
        if let Some(port) = candidate_port {
            tried_ports.push(port);
        }
        let (udp, addr) = match bind_udp(candidate_port).await {
            Ok(bound) => bound,
            Err(error) if udp_error_retryable(&error) => {
                last_error = Some(error);
                continue;
            }
            Err(error) => return Err(PairBindError::Fatal(error)),
        };
        if !tried_ports.contains(&addr.port()) {
            tried_ports.push(addr.port());
        }
        match bind_tcp(addr).await {
            Ok(tcp) => return Ok((udp, tcp)),
            Err(error) if retryable_bind_error(&error) => {
                last_error = Some(error.into());
                rejected.push(udp);
            }
            Err(error) => return Err(PairBindError::Fatal(error.into())),
        }
    }
    Err(PairBindError::Exhausted { tried_ports, last_error })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::sync::{Arc, Mutex};

    fn udp_ok(port: u16) -> UdpBindFuture<u16, io::Error> {
        Box::pin(async move { Ok((port, SocketAddr::from(([127, 0, 0, 1], port)))) })
    }

    fn udp_err(error: io::Error) -> UdpBindFuture<u16, io::Error> {
        Box::pin(async move { Err(error) })
    }

    fn tcp_ok(addr: SocketAddr) -> TcpBindFuture<SocketAddr> {
        Box::pin(async move { Ok(addr) })
    }

    fn tcp_err(error: io::Error) -> TcpBindFuture<SocketAddr> {
        Box::pin(async move { Err(error) })
    }

    #[test]
    fn windows_excluded_port_and_addr_in_use_are_retryable() {
        assert!(retryable_bind_error(&io::Error::from_raw_os_error(WINDOWS_WSAEACCES)));
        assert!(retryable_bind_error(&io::Error::from(io::ErrorKind::PermissionDenied)));
        assert!(retryable_bind_error(&io::Error::from(io::ErrorKind::AddrInUse)));
        assert!(!retryable_bind_error(&io::Error::from(io::ErrorKind::ConnectionRefused)));
    }

    #[test]
    fn the_port_walk_stays_in_the_dynamic_range_and_does_not_repeat() {
        for start in [0, 1, DYNAMIC_PORT_COUNT / 2, DYNAMIC_PORT_COUNT - 1] {
            let walk: Vec<u16> = (0..PORT_ZERO_BIND_ATTEMPTS).map(|offset| dynamic_port_candidate(start, offset)).collect();
            assert!(walk.iter().all(|port| *port >= DYNAMIC_PORT_START), "start {start}: {walk:?}");
            assert_eq!(walk.iter().collect::<HashSet<_>>().len(), walk.len(), "start {start}");
            assert_eq!(walk[0], DYNAMIC_PORT_START + start);
        }
        // Consecutive candidates are a stride apart (mod the range), so a contiguous exclusion is left at once.
        assert_eq!(dynamic_port_candidate(0, 1) - dynamic_port_candidate(0, 0), DYNAMIC_PORT_STRIDE);
    }

    #[tokio::test]
    async fn udp_errors_are_retried_only_as_the_caller_decides() {
        // Retried: the next attempt gets a pair.
        let calls = Arc::new(Mutex::new(0usize));
        let udp_calls = calls.clone();
        let pair = bind_udp_tcp_pair(
            0,
            |_| true,
            move |_| {
                let mut n = udp_calls.lock().unwrap();
                *n += 1;
                if *n == 1 { udp_err(io::Error::from(io::ErrorKind::ConnectionRefused)) } else { udp_ok(54_321) }
            },
            tcp_ok,
        )
        .await;
        assert!(matches!(pair, Ok((54_321, addr)) if addr.port() == 54_321));
        assert_eq!(*calls.lock().unwrap(), 2);

        // Not retried: the first error is returned as it is, and TCP is never tried.
        let calls = Arc::new(Mutex::new(0usize));
        let udp_calls = calls.clone();
        let pair = bind_udp_tcp_pair(
            0,
            retryable_bind_error,
            move |_| {
                *udp_calls.lock().unwrap() += 1;
                udp_err(io::Error::from(io::ErrorKind::ConnectionRefused))
            },
            |_| -> TcpBindFuture<SocketAddr> { unreachable!("TCP is bound only after UDP") },
        )
        .await;
        assert!(matches!(pair, Err(PairBindError::Fatal(e)) if e.kind() == io::ErrorKind::ConnectionRefused));
        assert_eq!(*calls.lock().unwrap(), 1);
    }

    /// A UDP socket that gives its port back to the mock system when dropped.
    struct Held(u16, Arc<Mutex<Vec<u16>>>);

    impl Drop for Held {
        fn drop(&mut self) {
            self.1.lock().unwrap().retain(|port| *port != self.0);
        }
    }

    #[tokio::test]
    async fn a_tcp_refusal_holds_the_udp_port_and_other_tcp_errors_are_fatal() {
        // The mock system assigns the lowest port from 54_321 on that no live socket holds.
        let live = Arc::new(Mutex::new(Vec::new()));
        let udp_live = live.clone();
        let tcp_calls = Arc::new(Mutex::new(Vec::new()));
        let tcp_seen = tcp_calls.clone();
        let pair = bind_udp_tcp_pair(
            0,
            retryable_bind_error,
            move |port| -> UdpBindFuture<Held, io::Error> {
                let mut held = udp_live.lock().unwrap();
                let port = port.unwrap_or_else(|| (54_321..).find(|p| !held.contains(p)).unwrap());
                held.push(port);
                let socket = Held(port, udp_live.clone());
                Box::pin(async move { Ok((socket, SocketAddr::from(([127, 0, 0, 1], port)))) })
            },
            move |addr| {
                let mut seen = tcp_seen.lock().unwrap();
                seen.push(addr.port());
                if seen.len() < 3 { tcp_err(io::Error::from_raw_os_error(WINDOWS_WSAEACCES)) } else { tcp_ok(addr) }
            },
        )
        .await;
        let (udp, tcp) = pair.unwrap();
        assert_eq!((udp.0, tcp.port()), (54_323, 54_323));
        assert_eq!(*tcp_calls.lock().unwrap(), [54_321, 54_322, 54_323], "a refused port was handed out again");
        assert_eq!(*live.lock().unwrap(), [54_323], "the refused UDP sockets are released when the bind returns");
        drop(udp);

        let pair = bind_udp_tcp_pair(0, |_| true, |_| udp_ok(54_321), |_| tcp_err(io::Error::from(io::ErrorKind::ConnectionRefused))).await;
        assert!(matches!(pair, Err(PairBindError::Fatal(e)) if e.kind() == io::ErrorKind::ConnectionRefused));
    }

    #[tokio::test]
    async fn exhaustion_reports_every_tried_port_and_the_last_error() {
        let attempts = Arc::new(Mutex::new(0u16));
        let udp_attempts = attempts.clone();
        let pair = bind_udp_tcp_pair(
            7,
            retryable_bind_error,
            move |port| {
                let mut n = udp_attempts.lock().unwrap();
                *n += 1;
                udp_ok(port.unwrap_or(55_000 + *n))
            },
            |_| tcp_err(io::Error::from(io::ErrorKind::AddrInUse)),
        )
        .await;
        let Err(PairBindError::Exhausted { tried_ports, last_error }) = pair else { panic!("expected exhaustion") };
        assert_eq!(usize::from(*attempts.lock().unwrap()), PORT_ZERO_BIND_ATTEMPTS);
        assert_eq!(tried_ports.len(), PORT_ZERO_BIND_ATTEMPTS);
        assert_eq!(tried_ports[..SEQUENTIAL_BIND_ATTEMPTS], [55_001, 55_002, 55_003, 55_004]);
        assert_eq!(tried_ports[SEQUENTIAL_BIND_ATTEMPTS], dynamic_port_candidate(7, 0));
        assert_eq!(last_error.map(|e| e.kind()), Some(io::ErrorKind::AddrInUse));
    }
}
