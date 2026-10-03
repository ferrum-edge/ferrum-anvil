//! One destination for the HTTP/3 → TCP fallback: HTTP/3 on a UDP port and
//! TLS (HTTP/2, HTTP/1.1) on the same TCP port. It checks per-send auth for
//! replays, as a gateway that verifies signatures does: a request whose
//! `authorization` and `dpop` headers were both already received, over
//! either protocol, is a replay.
//!
//! * Over HTTP/3, [`serve`] reads every request whole, then resets its
//!   stream (`H3_INTERNAL_ERROR`) without a response: the request reached
//!   the server, and the client cannot know whether it was processed.
//!   [`serve_h3`] follows an [`H3Script`] instead: it can answer, and leave
//!   only the request that reuses the first QUIC connection unanswered.
//! * Over TCP, a replay is answered `401`, any other request `200`. A
//!   request to `/sse` that is not a replay gets an event stream: without
//!   `Last-Event-ID`, `retry: 50` and event `1`, then the stream is cut (an
//!   abnormal end a client may reconnect after); with it, event `2` and a
//!   clean end.
//!
//! Without QUIC ([`serve`] with `quic = false`) only the TCP port is bound:
//! a QUIC handshake to it gets no answer.

use crate::tlsserver::{TlsServerOptions, server_config};
use bytes::{Buf, Bytes};
use futures::SinkExt;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::Frame;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use parking_lot::Mutex;
use std::convert::Infallible;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

const PORT_ZERO_BIND_ATTEMPTS: usize = 64;
const SEQUENTIAL_BIND_ATTEMPTS: usize = 4;
const DYNAMIC_PORT_START: u16 = 49_152;
const DYNAMIC_PORT_COUNT: u16 = u16::MAX - DYNAMIC_PORT_START + 1;
const DYNAMIC_PORT_STRIDE: u16 = 9_973;
const WINDOWS_WSAEACCES: i32 = 10013;

type TcpBindFuture<Tcp> = Pin<Box<dyn Future<Output = io::Result<Tcp>> + Send>>;
type UdpBindFuture<E> = Pin<Box<dyn Future<Output = anyhow::Result<(E, SocketAddr)>> + Send>>;

fn retryable_bind_error(error: &io::Error) -> bool {
    error.raw_os_error() == Some(WINDOWS_WSAEACCES) || matches!(error.kind(), io::ErrorKind::PermissionDenied | io::ErrorKind::AddrInUse)
}

async fn bind_udp_tcp_pair_with<E, Tcp, U, T>(
    bind_udp: U,
    bind_tcp: T,
) -> anyhow::Result<(E, Tcp)>
where
    E: Send,
    U: FnMut(Option<u16>) -> UdpBindFuture<E>,
    T: FnMut(SocketAddr) -> TcpBindFuture<Tcp>,
{
    bind_udp_tcp_pair_with_start(
        rand::random_range(0..DYNAMIC_PORT_COUNT),
        bind_udp,
        bind_tcp,
    )
    .await
}

async fn bind_udp_tcp_pair_with_start<E, Tcp, U, T>(
    random_start: u16,
    mut bind_udp: U,
    mut bind_tcp: T,
) -> anyhow::Result<(E, Tcp)>
where
    E: Send,
    U: FnMut(Option<u16>) -> UdpBindFuture<E>,
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
        let (endpoint, addr) = match bind_udp(candidate_port).await {
            Ok(bound) => bound,
            Err(error) => {
                last_error = Some(error);
                continue;
            }
        };
        if !tried_ports.contains(&addr.port()) {
            tried_ports.push(addr.port());
        }
        match bind_tcp(addr).await {
            Ok(listener) => return Ok((endpoint, listener)),
            Err(error) if retryable_bind_error(&error) => {
                last_error = Some(error.into());
                rejected.push(endpoint);
            }
            Err(error) => return Err(error.into()),
        }
    }

    let error = last_error.unwrap_or_else(|| anyhow::anyhow!("the fixture pair bind made no attempts"));
    Err(anyhow::anyhow!(
        "no port was free over both UDP and TCP after {PORT_ZERO_BIND_ATTEMPTS} attempts; tried UDP ports {tried_ports:?}: {error}"
    ))
}

fn dynamic_port_candidate(random_start: u16, offset: usize) -> u16 {
    let position = (u32::from(random_start) + (offset as u32 * u32::from(DYNAMIC_PORT_STRIDE))) % u32::from(DYNAMIC_PORT_COUNT);
    DYNAMIC_PORT_START + position as u16
}

/// One request the fixture received.
#[derive(Clone, Debug)]
pub struct Received {
    /// `h3`, `h2` or `http/1.1`.
    pub protocol: String,
    pub method: String,
    /// Its `authorization` header, or "".
    pub authorization: String,
    /// Its `dpop` header, or "".
    pub dpop: String,
    /// Its `last-event-id` header, or "".
    pub last_event_id: String,
    /// The same `authorization` and `dpop` were received before.
    pub replayed: bool,
}

/// What the fixture does with requests over HTTP/3.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum H3Script {
    /// Read every request whole, then reset its stream (`H3_INTERNAL_ERROR`)
    /// without a response.
    ResetEvery,
    /// Answer every request as the TCP port does (`401` for a replay, else
    /// `200`), except the second one on the first QUIC connection, which
    /// reuses it: read it whole, then leave it unanswered as said.
    SecondOnReuse(Unanswered),
    /// Answer every request as the TCP port does. On the first QUIC
    /// connection, send `GOAWAY` once the first request arrived (allowing
    /// only that one), and keep the connection open.
    GoAwayAfterFirst,
}

/// How [`H3Script::SecondOnReuse`] leaves a request unanswered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unanswered {
    /// Reset its stream with `H3_REQUEST_REJECTED`: the server did not
    /// process it (RFC 9114 §4.1.1).
    Rejected,
    /// Close the QUIC connection (`H3_NO_ERROR`): the server may have
    /// processed it.
    ConnectionClosed,
}

/// What one HTTP/3 request gets.
#[derive(Clone, Copy)]
enum H3Action {
    Reset,
    Answer,
    Leave(Unanswered),
}

pub struct ReplayFixture {
    pub addr: SocketAddr,
    received: Arc<Mutex<Vec<Received>>>,
    quic_connections: Arc<AtomicUsize>,
    endpoint: Option<quinn::Endpoint>,
    cancel: CancellationToken,
}

impl ReplayFixture {
    pub fn url(&self, path: &str) -> String {
        format!("https://{}{}", self.addr, path)
    }

    /// Every request received, over either protocol, in arrival order.
    pub fn received(&self) -> Vec<Received> {
        self.received.lock().clone()
    }

    /// QUIC connections accepted.
    pub fn quic_connections(&self) -> usize {
        self.quic_connections.load(Ordering::SeqCst)
    }
}

impl Drop for ReplayFixture {
    fn drop(&mut self) {
        self.cancel.cancel();
        if let Some(e) = &self.endpoint {
            e.close(0u32.into(), b"fixture shutdown");
        }
    }
}

/// Record a request: whether it is a replay.
fn record(received: &Mutex<Vec<Received>>, protocol: &str, method: &str, headers: &http::HeaderMap) -> bool {
    let value = |n: &str| headers.get(n).map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned()).unwrap_or_default();
    let (authorization, dpop, last_event_id) = (value("authorization"), value("dpop"), value("last-event-id"));
    let mut r = received.lock();
    let replayed = r.iter().any(|x| x.authorization == authorization && x.dpop == dpop);
    r.push(Received { protocol: protocol.into(), method: method.into(), authorization, dpop, last_event_id, replayed });
    replayed
}

type Body = BoxBody<Bytes, std::io::Error>;

/// The `/sse` event stream: after a `Last-Event-ID` (a reconnection), event
/// `2` and a clean end; otherwise event `1`, then the stream is cut.
fn event_stream(reconnected: bool) -> http::Response<Body> {
    let (mut tx, rx) = futures::channel::mpsc::channel::<Result<Frame<Bytes>, std::io::Error>>(4);
    tokio::spawn(async move {
        if reconnected {
            let _ = tx.send(Ok(Frame::data(Bytes::from_static(b"id: 2\ndata: two\n\n")))).await;
            return;
        }
        let _ = tx.send(Ok(Frame::data(Bytes::from_static(b"retry: 50\nid: 1\ndata: one\n\n")))).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        let _ = tx.send(Err(std::io::Error::other("replay guard: the event stream is cut"))).await;
    });
    http::Response::builder()
        .status(200)
        .header("content-type", "text/event-stream")
        .body(BodyExt::boxed(StreamBody::new(rx)))
        .expect("static response")
}

/// A UDP port for QUIC and the same TCP port, on 127.0.0.1. Bind UDP first
/// because Windows assigns UDP port 0 outside its excluded ranges, then bind
/// TCP to the assigned port. Rejected QUIC endpoints stay held until return.
async fn bind(tls: &TlsServerOptions, quic: bool) -> anyhow::Result<(Option<quinn::Endpoint>, TcpListener)> {
    if !quic {
        return Ok((None, TcpListener::bind("127.0.0.1:0").await?));
    }
    let mut opts = tls.clone();
    opts.alpn = vec!["h3".into()];
    opts.tls13_only = true;
    opts.tls12_only = false;
    let quic_cfg = quinn::crypto::rustls::QuicServerConfig::try_from(server_config(&opts)?)?;
    let server_cfg = quinn::ServerConfig::with_crypto(Arc::new(quic_cfg));
    let (endpoint, listener) = bind_udp_tcp_pair_with(
        |port| {
            let server_cfg = server_cfg.clone();
            Box::pin(async move {
                let endpoint = quinn::Endpoint::server(server_cfg, SocketAddr::from(([127, 0, 0, 1], port.unwrap_or(0))))?;
                let addr = endpoint.local_addr()?;
                Ok((endpoint, addr))
            })
        },
        |addr| Box::pin(TcpListener::bind(addr)),
    )
    .await?;
    Ok((Some(endpoint), listener))
}

/// Start the fixture on 127.0.0.1, with HTTP/3 when `quic`, whose every
/// request is reset without a response ([`H3Script::ResetEvery`]).
pub async fn serve(tls: TlsServerOptions, quic: bool) -> anyhow::Result<ReplayFixture> {
    serve_with(tls, quic.then_some(H3Script::ResetEvery)).await
}

/// Start the fixture on 127.0.0.1, with HTTP/3 following `script`.
pub async fn serve_h3(tls: TlsServerOptions, script: H3Script) -> anyhow::Result<ReplayFixture> {
    serve_with(tls, Some(script)).await
}

async fn serve_with(tls: TlsServerOptions, script: Option<H3Script>) -> anyhow::Result<ReplayFixture> {
    let (endpoint, listener) = bind(&tls, script.is_some()).await?;
    let addr = listener.local_addr()?;
    let received = Arc::new(Mutex::new(Vec::new()));
    let quic_connections = Arc::new(AtomicUsize::new(0));
    let cancel = CancellationToken::new();
    if let (Some(ep), Some(script)) = (endpoint.clone(), script) {
        let (received, conns, cancel) = (received.clone(), quic_connections.clone(), cancel.clone());
        tokio::spawn(async move {
            loop {
                let incoming = tokio::select! {
                    i = ep.accept() => match i { Some(i) => i, None => break },
                    _ = cancel.cancelled() => break,
                };
                let (received, conns, cancel) = (received.clone(), conns.clone(), cancel.clone());
                tokio::spawn(async move {
                    let Ok(conn) = incoming.await else { return };
                    let first_connection = conns.fetch_add(1, Ordering::SeqCst) == 0;
                    let quic = conn.clone();
                    let Ok(mut h3c) = h3::server::builder().build::<_, Bytes>(h3_quinn::Connection::new(conn)).await else { return };
                    for nth in 0.. {
                        let accepted = tokio::select! {
                            r = h3c.accept() => r,
                            _ = cancel.cancelled() => break,
                        };
                        let Ok(Some(resolver)) = accepted else { break };
                        let action = match script {
                            H3Script::ResetEvery => H3Action::Reset,
                            H3Script::SecondOnReuse(how) if first_connection && nth == 1 => H3Action::Leave(how),
                            H3Script::SecondOnReuse(_) | H3Script::GoAwayAfterFirst => H3Action::Answer,
                        };
                        let (received, quic) = (received.clone(), quic.clone());
                        tokio::spawn(async move {
                            let Ok((req, mut stream)) = resolver.resolve_request().await else { return };
                            while let Ok(Some(mut chunk)) = stream.recv_data().await {
                                let n = chunk.remaining();
                                chunk.advance(n);
                            }
                            let replayed = record(&received, "h3", req.method().as_str(), req.headers());
                            match action {
                                H3Action::Reset => stream.stop_stream(h3::error::Code::H3_INTERNAL_ERROR),
                                H3Action::Leave(Unanswered::Rejected) => stream.stop_stream(h3::error::Code::H3_REQUEST_REJECTED),
                                H3Action::Leave(Unanswered::ConnectionClosed) => quic.close(0x100u32.into(), b""),
                                H3Action::Answer => {
                                    let status = if replayed { 401 } else { 200 };
                                    let resp = http::Response::builder().status(status).body(()).expect("static response");
                                    if stream.send_response(resp).await.is_ok() {
                                        let _ = stream.send_data(Bytes::from_static(b"ok")).await;
                                        let _ = stream.finish().await;
                                    }
                                }
                            }
                        });
                        if script == H3Script::GoAwayAfterFirst && first_connection && nth == 0 {
                            let _ = h3c.shutdown(1).await;
                        }
                    }
                });
            }
        });
    }
    let acceptor = tokio_rustls::TlsAcceptor::from(server_config(&tls)?);
    let (r2, c2) = (received.clone(), cancel.clone());
    tokio::spawn(async move {
        loop {
            let (tcp, _) = tokio::select! {
                r = listener.accept() => match r { Ok(x) => x, Err(_) => continue },
                _ = c2.cancelled() => break,
            };
            let (acceptor, received, cancel) = (acceptor.clone(), r2.clone(), c2.clone());
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else { return };
                let protocol = if tls.get_ref().1.alpn_protocol() == Some(b"h2".as_slice()) { "h2" } else { "http/1.1" };
                let svc = service_fn(move |req: http::Request<hyper::body::Incoming>| {
                    let received = received.clone();
                    async move {
                        let (parts, body) = req.into_parts();
                        let _ = body.collect().await;
                        let replayed = record(&received, protocol, parts.method.as_str(), &parts.headers);
                        if !replayed && parts.uri.path() == "/sse" {
                            return Ok::<_, Infallible>(event_stream(parts.headers.contains_key("last-event-id")));
                        }
                        let status = if replayed { 401 } else { 200 };
                        let body: Body = Full::new(Bytes::from_static(b"ok")).map_err(|never| match never {}).boxed();
                        let resp = http::Response::builder().status(status).body(body).expect("static response");
                        Ok::<_, Infallible>(resp)
                    }
                });
                let builder = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
                tokio::select! {
                    _ = builder.serve_connection(TokioIo::new(tls), svc) => {}
                    _ = cancel.cancelled() => {}
                }
            });
        }
    });
    Ok(ReplayFixture { addr, received, quic_connections, endpoint, cancel })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::sync::Mutex as StdMutex;
    use tokio::net::UdpSocket;

    #[derive(Clone, Copy)]
    struct MockUdpSocket(SocketAddr);

    impl MockUdpSocket {
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok(self.0)
        }
    }

    struct MockTcpListener(SocketAddr);

    impl MockTcpListener {
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok(self.0)
        }
    }

    #[tokio::test]
    async fn pair_binds_udp_first_and_retries_tcp_refusal() {
        let order = Arc::new(StdMutex::new(Vec::new()));
        let udp_order = order.clone();
        let tcp_order = order.clone();
        let calls = Arc::new(StdMutex::new(Vec::new()));
        let tcp_calls = calls.clone();
        let udp_calls = Arc::new(StdMutex::new(0usize));
        let bind_udp_calls = udp_calls.clone();

        let (udp, tcp) = bind_udp_tcp_pair_with(
            move |_| {
                udp_order.lock().unwrap().push("udp");
                let attempt = {
                    let mut calls = bind_udp_calls.lock().unwrap();
                    *calls += 1;
                    *calls
                };
                let port = if attempt == 1 { 54_321 } else { 54_322 };
                let addr = SocketAddr::from(([127, 0, 0, 1], port));
                Box::pin(async move { Ok((MockUdpSocket(addr), addr)) })
            },
            move |addr| {
                tcp_order.lock().unwrap().push("tcp");
                let attempt = {
                    let mut calls = tcp_calls.lock().unwrap();
                    calls.push(addr.port());
                    calls.len()
                };
                if attempt == 1 {
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

        assert_eq!(*order.lock().unwrap(), ["udp", "tcp", "udp", "tcp"]);
        let calls = calls.lock().unwrap();
        assert_eq!(calls.len(), 2);
        assert_ne!(calls[0], calls[1]);
        assert_eq!(udp.local_addr().unwrap().port(), calls[1]);
        assert_eq!(udp.local_addr().unwrap().port(), tcp.local_addr().unwrap().port());
    }

    #[tokio::test]
    async fn pair_escapes_a_contiguous_tcp_exclusion() {
        let exclusion_start = 55_000;
        let exclusion_end = exclusion_start + 500;
        let random_start = 60_000 - DYNAMIC_PORT_START;
        let next_port = Arc::new(StdMutex::new(exclusion_start));
        let ports = Arc::new(StdMutex::new(Vec::new()));
        let bind_next = next_port.clone();
        let tcp_ports = ports.clone();

        let (udp, tcp) = bind_udp_tcp_pair_with_start(
            random_start,
            move |candidate_port| {
                let port = candidate_port.unwrap_or_else(|| {
                    let mut port = bind_next.lock().unwrap();
                    let next = *port;
                    *port += 1;
                    next
                });
                let addr = SocketAddr::from(([127, 0, 0, 1], port));
                Box::pin(async move { Ok((MockUdpSocket(addr), addr)) })
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
        assert_eq!(udp.local_addr().unwrap().port(), tcp.local_addr().unwrap().port());
    }

    #[tokio::test]
    async fn pair_error_lists_every_tried_udp_port() {
        let ports = Arc::new(StdMutex::new(Vec::new()));
        let bind_ports = ports.clone();
        let udp_attempts = Arc::new(StdMutex::new(0usize));
        let bind_udp_attempts = udp_attempts.clone();
        let result = bind_udp_tcp_pair_with(
            |candidate_port| {
                let mut attempts = bind_udp_attempts.lock().unwrap();
                let port = candidate_port.unwrap_or(55_000 + *attempts as u16);
                *attempts += 1;
                let addr = SocketAddr::from(([127, 0, 0, 1], port));
                Box::pin(async move { Ok((MockUdpSocket(addr), addr)) })
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
        assert_eq!(*udp_attempts.lock().unwrap(), PORT_ZERO_BIND_ATTEMPTS);
        assert_eq!(tried.len(), PORT_ZERO_BIND_ATTEMPTS);
        assert_eq!(tried.iter().copied().collect::<HashSet<_>>().len(), tried.len());
        let error = result.unwrap_err().to_string();
        assert!(error.contains("tried UDP ports ["));
        for port in tried.iter() {
            assert!(error.contains(&port.to_string()), "error omitted tried port {port}: {error}");
        }
    }
}
