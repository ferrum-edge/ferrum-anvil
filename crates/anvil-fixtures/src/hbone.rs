//! HBONE endpoint fixture: HTTP/2 `CONNECT` over mutual TLS that relays an
//! admitted tunnel to its `:authority` (a local echo fixture).
//!
//! Admission mirrors the public shape of a mesh HBONE terminator so Anvil's
//! client and diagnostics can be tested without a mesh:
//!
//! * the TLS server presents a (SPIFFE) server certificate and requests,
//!   requires or ignores a client certificate chaining to `client_ca_pem`;
//! * a `CONNECT` without a verified client certificate is refused `403`
//!   `{"error":"HBONE tunnel requires an authenticated mesh peer"}`;
//! * a `CONNECT` whose authority is not in `allowed` is refused `403`
//!   `{"error":"HBONE relay destination not allowed"}`;
//! * an authority in `unavailable` answers `503`; a dial failure `502`;
//! * otherwise `200` and the stream is spliced to a TCP connection.
//!
//! A `CONNECT` carrying the `udp` protocol marker (`x-ferrum-mesh-protocol`,
//! else `x-istio-protocol`, value `udp` in any case — the precedence Ferrum
//! Edge uses) is a datagram tunnel, answered with Ferrum Edge's public UDP
//! bodies (`HBONE UDP tunnel requires an authenticated mesh peer`, `HBONE UDP
//! relay destination not allowed`, `503 UDP egress relay session capacity
//! exhausted`). An admitted one relays `[u16 big-endian length][payload]`
//! records to a UDP socket connected to the authority and frames every reply
//! the same way (its own codec, independent of Anvil's). Records are opaque:
//! DTLS records inside the tunnel are relayed like any UDP payload. Per
//! authority, a [`UdpTunnelFault`] ends the tunnel the way a relay can:
//! `END_STREAM` (after some replies or after a delay), a dropped connection,
//! a truncated record, or replies packed with zero-length records into one
//! DATA frame. [`serve_resetting`] is a raw-h2
//! variant that resets the tunnel stream (`RST_STREAM(CANCEL)`), which a
//! hyper-based endpoint cannot do.
//!
//! Every CONNECT is recorded (authority, headers, peer SPIFFE ID, status) as
//! ground truth for tests; the log is never given to Anvil's diagnostics.

use crate::tlsserver::{ClientAuth, TlsServerOptions, server_config};
use bytes::Bytes;
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use parking_lot::Mutex;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio_util::sync::CancellationToken;

pub const UNAUTHENTICATED_BODY: &str = r#"{"error":"HBONE tunnel requires an authenticated mesh peer"}"#;
pub const DESTINATION_DENIED_BODY: &str = r#"{"error":"HBONE relay destination not allowed"}"#;
/// Ferrum Edge 0.9.7's datagram-tunnel refusals (`src/proxy/hbone_proxy.rs`).
pub const UDP_UNAUTHENTICATED_BODY: &str = r#"{"error":"HBONE UDP tunnel requires an authenticated mesh peer"}"#;
pub const UDP_DESTINATION_DENIED_BODY: &str = r#"{"error":"HBONE UDP relay destination not allowed"}"#;
pub const UDP_CAPACITY_BODY: &str = r#"{"error":"UDP egress relay session capacity exhausted"}"#;

/// How the fixture ends an admitted datagram tunnel (per authority).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UdpTunnelFault {
    /// After relaying `n` replies, end the stream with `END_STREAM` (what a
    /// hyper-based relay such as Ferrum Edge's sends whenever its relay
    /// ends: hyper turns a dropped upgraded stream into `END_STREAM`).
    EndAfter(usize),
    /// `ms` after the tunnel opened, end the stream with `END_STREAM`
    /// (whatever was relayed by then): for sessions whose reply count is not
    /// fixed, such as a DTLS handshake inside the tunnel.
    EndAfterMs(u64),
    /// After `n` replies, drop the whole HTTP/2 connection (TLS and TCP)
    /// without GOAWAY: the endpoint vanishing mid-session.
    DropConnectionAfter(usize),
    /// After `n` replies, write the first 6 bytes of a record that claims 16
    /// payload bytes, then `END_STREAM`.
    TruncateAfter(usize),
    /// Frame each reply followed by a zero-length record, in one write
    /// (several records in one DATA frame).
    PackWithEmpty,
}

#[derive(Clone, Debug)]
pub struct HboneOptions {
    pub server_cert_chain_pem: String,
    pub server_key_pem: String,
    pub client_auth: ClientAuth,
    /// ALPN offered by the server (HBONE requires `h2`).
    pub alpn: Vec<String>,
    /// Authorities (`host:port`) the endpoint relays to.
    pub allowed: Vec<String>,
    /// Authorities answered with `503` (the endpoint cannot open the tunnel).
    pub unavailable: Vec<String>,
    /// Datagram-tunnel faults by authority (`host:port`).
    pub udp_faults: Vec<(String, UdpTunnelFault)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectRecord {
    pub authority: String,
    pub headers: Vec<(String, String)>,
    pub peer_spiffe_id: Option<String>,
    pub status: u16,
}

#[derive(Default)]
pub struct HboneLog {
    pub connects: Mutex<Vec<ConnectRecord>>,
    pub tls_failures: Mutex<Vec<String>>,
    pub connections: Mutex<u64>,
    /// SNI received on each completed handshake (`None`: no SNI sent).
    pub snis: Mutex<Vec<Option<String>>>,
    /// Payload sizes of the datagrams relayed to each UDP destination.
    pub udp_relayed: Mutex<Vec<(String, usize)>>,
    /// How each datagram tunnel ended: `client_end` (the client's
    /// `END_STREAM` or reset), `destination_error`, or `fault:<fault>`.
    pub udp_tunnel_ends: Mutex<Vec<String>>,
}

pub struct HboneFixture {
    pub addr: SocketAddr,
    pub log: Arc<HboneLog>,
    cancel: CancellationToken,
}

impl HboneFixture {
    pub fn address(&self) -> String {
        self.addr.to_string()
    }

    pub fn connects(&self) -> Vec<ConnectRecord> {
        self.log.connects.lock().clone()
    }
}

impl Drop for HboneFixture {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

type Body = BoxBody<Bytes, Infallible>;

fn text(status: u16, body: &'static str) -> Response<Body> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from_static(body.as_bytes())).boxed())
        .expect("response")
}

fn peer_spiffe(conn: &rustls::ServerConnection) -> Option<String> {
    use x509_parser::prelude::*;
    let der = conn.peer_certificates()?.first()?.as_ref().to_vec();
    let (_, cert) = X509Certificate::from_der(&der).ok()?;
    let ext = cert.subject_alternative_name().ok()??;
    let uris: Vec<String> = ext
        .value
        .general_names
        .iter()
        .filter_map(|g| match g {
            GeneralName::URI(u) => Some(u.to_string()),
            _ => None,
        })
        .collect();
    match uris.as_slice() {
        [one] if one.starts_with("spiffe://") => Some(one.clone()),
        _ => None,
    }
}

/// Start the fixture on `bind` (e.g. `127.0.0.1:0`).
pub async fn serve(bind: &str, opts: HboneOptions) -> anyhow::Result<HboneFixture> {
    let mut tls_opts = TlsServerOptions::new(opts.server_cert_chain_pem.clone(), opts.server_key_pem.clone());
    tls_opts.client_auth = opts.client_auth.clone();
    tls_opts.alpn = opts.alpn.clone();
    let acceptor = tokio_rustls::TlsAcceptor::from(server_config(&tls_opts)?);
    let listener = TcpListener::bind(bind).await?;
    let addr = listener.local_addr()?;
    let log = Arc::new(HboneLog::default());
    let cancel = CancellationToken::new();
    let opts = Arc::new(opts);
    let (l2, c2) = (log.clone(), cancel.clone());
    tokio::spawn(async move {
        loop {
            let stream = tokio::select! {
                r = listener.accept() => match r { Ok((s, _)) => s, Err(_) => continue },
                _ = c2.cancelled() => break,
            };
            let _ = stream.set_nodelay(true);
            *l2.connections.lock() += 1;
            let (log, acceptor, opts, cancel) = (l2.clone(), acceptor.clone(), opts.clone(), c2.clone());
            tokio::spawn(async move {
                let tls = match acceptor.accept(stream).await {
                    Ok(t) => t,
                    Err(e) => {
                        log.tls_failures.lock().push(e.to_string());
                        return;
                    }
                };
                let peer = peer_spiffe(tls.get_ref().1);
                log.snis.lock().push(tls.get_ref().1.server_name().map(|s| s.to_string()));
                // Cancelled by a fault that drops the whole connection.
                let drop_conn = CancellationToken::new();
                let dc = drop_conn.clone();
                let svc = service_fn(move |req| {
                    let (log, opts, peer, dc) = (log.clone(), opts.clone(), peer.clone(), dc.clone());
                    async move { Ok::<_, Infallible>(handle(req, log, opts, peer, dc).await) }
                });
                let conn = hyper::server::conn::http2::Builder::new(TokioExecutor::new()).serve_connection(TokioIo::new(tls), svc);
                tokio::select! {
                    _ = conn => {}
                    _ = cancel.cancelled() => {}
                    _ = drop_conn.cancelled() => {}
                }
            });
        }
    });
    Ok(HboneFixture { addr, log, cancel })
}

async fn handle(
    req: Request<Incoming>,
    log: Arc<HboneLog>,
    opts: Arc<HboneOptions>,
    peer: Option<String>,
    drop_conn: CancellationToken,
) -> Response<Body> {
    if req.method() != Method::CONNECT || req.extensions().get::<hyper::ext::Protocol>().is_some() {
        return text(405, r#"{"error":"only a bare HTTP/2 CONNECT is accepted"}"#);
    }
    let authority = req.uri().authority().map(|a| a.to_string()).unwrap_or_default();
    let headers: Vec<(String, String)> =
        req.headers().iter().map(|(n, v)| (n.as_str().to_string(), String::from_utf8_lossy(v.as_bytes()).into_owned())).collect();
    let record = |status: u16| {
        log.connects.lock().push(ConnectRecord {
            authority: authority.clone(),
            headers: headers.clone(),
            peer_spiffe_id: peer.clone(),
            status,
        });
    };
    // Ferrum's precedence: the first marker present decides (x-ferrum-mesh-protocol wins).
    let marker = req.headers().get("x-ferrum-mesh-protocol").or_else(|| req.headers().get("x-istio-protocol"));
    if marker.and_then(|v| v.to_str().ok()).is_some_and(|v| v.eq_ignore_ascii_case("udp")) {
        if peer.is_none() {
            record(403);
            return text(403, UDP_UNAUTHENTICATED_BODY);
        }
        if opts.unavailable.contains(&authority) {
            record(503);
            return text(503, UDP_CAPACITY_BODY);
        }
        if !opts.allowed.contains(&authority) {
            record(403);
            return text(403, UDP_DESTINATION_DENIED_BODY);
        }
        let sock = match udp_socket(&authority).await {
            Some(s) => s,
            None => {
                record(502);
                return text(502, r#"{"error":"HBONE UDP local socket connect failed"}"#);
            }
        };
        record(200);
        let fault = opts.udp_faults.iter().find(|(a, _)| *a == authority).map(|(_, f)| *f);
        tokio::spawn(async move {
            let Ok(upgraded) = hyper::upgrade::on(req).await else { return };
            relay_udp(TokioIo::new(upgraded), sock, authority, fault, log, drop_conn).await;
        });
        return Response::builder().status(StatusCode::OK).body(Full::new(Bytes::new()).boxed()).expect("response");
    }
    if peer.is_none() {
        record(403);
        return text(403, UNAUTHENTICATED_BODY);
    }
    if opts.unavailable.contains(&authority) {
        record(503);
        return text(503, r#"{"error":"HBONE backend unavailable"}"#);
    }
    if !opts.allowed.contains(&authority) {
        record(403);
        return text(403, DESTINATION_DENIED_BODY);
    }
    let upstream = match TcpStream::connect(&authority).await {
        Ok(s) => s,
        Err(_) => {
            record(502);
            return text(502, r#"{"error":"HBONE relay dial failed"}"#);
        }
    };
    record(200);
    tokio::spawn(async move {
        let Ok(upgraded) = hyper::upgrade::on(req).await else { return };
        let mut client = TokioIo::new(upgraded);
        let mut upstream = upstream;
        let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
    });
    Response::builder().status(StatusCode::OK).body(Full::new(Bytes::new()).boxed()).expect("response")
}

/// A minimal HBONE endpoint driven with `h2` directly, for the one tunnel
/// end hyper cannot produce: it relays a `udp`-marked CONNECT from a
/// verified peer like [`serve`] and, after `replies` replies, resets the
/// stream with `RST_STREAM(CANCEL)` (how an HBONE implementation that drives
/// HTTP/2 itself may end a tunnel). Other CONNECTs are answered 405 or 403
/// without a body. Mutual TLS and the log are as in [`serve`].
pub async fn serve_resetting(bind: &str, opts: HboneOptions, replies: usize) -> anyhow::Result<HboneFixture> {
    let mut tls_opts = TlsServerOptions::new(opts.server_cert_chain_pem.clone(), opts.server_key_pem.clone());
    tls_opts.client_auth = opts.client_auth.clone();
    tls_opts.alpn = opts.alpn.clone();
    let acceptor = tokio_rustls::TlsAcceptor::from(server_config(&tls_opts)?);
    let listener = TcpListener::bind(bind).await?;
    let addr = listener.local_addr()?;
    let log = Arc::new(HboneLog::default());
    let cancel = CancellationToken::new();
    let (l2, c2) = (log.clone(), cancel.clone());
    tokio::spawn(async move {
        loop {
            let stream = tokio::select! {
                r = listener.accept() => match r { Ok((s, _)) => s, Err(_) => continue },
                _ = c2.cancelled() => break,
            };
            *l2.connections.lock() += 1;
            let (log, acceptor, cancel) = (l2.clone(), acceptor.clone(), c2.clone());
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(stream).await else { return };
                let peer = peer_spiffe(tls.get_ref().1);
                let Ok(mut conn) = h2::server::handshake(tls).await else { return };
                loop {
                    let next = tokio::select! {
                        n = conn.accept() => n,
                        _ = cancel.cancelled() => return,
                    };
                    let Some(Ok((req, mut respond))) = next else { return };
                    let authority = req.uri().authority().map(|a| a.to_string()).unwrap_or_default();
                    let headers: Vec<(String, String)> = req
                        .headers()
                        .iter()
                        .map(|(n, v)| (n.as_str().to_string(), String::from_utf8_lossy(v.as_bytes()).into_owned()))
                        .collect();
                    let udp = req
                        .headers()
                        .get("x-ferrum-mesh-protocol")
                        .or_else(|| req.headers().get("x-istio-protocol"))
                        .and_then(|v| v.to_str().ok())
                        .is_some_and(|v| v.eq_ignore_ascii_case("udp"));
                    let sock = if req.method() == Method::CONNECT && udp && peer.is_some() { udp_socket(&authority).await } else { None };
                    let status: u16 = match (&sock, req.method() == Method::CONNECT && udp, peer.is_some()) {
                        (Some(_), _, _) => 200,
                        (None, false, _) => 405,
                        (None, true, false) => 403,
                        (None, true, true) => 502,
                    };
                    log.connects.lock().push(ConnectRecord { authority: authority.clone(), headers, peer_spiffe_id: peer.clone(), status });
                    let head = Response::builder().status(status).body(()).expect("response");
                    let Some(sock) = sock else {
                        let _ = respond.send_response(head, true);
                        continue;
                    };
                    let Ok(mut send) = respond.send_response(head, false) else { continue };
                    let mut body = req.into_body();
                    let log = log.clone();
                    tokio::spawn(async move {
                        let mut pending: Vec<u8> = Vec::new();
                        let mut dgram = vec![0u8; 65_535];
                        let mut sent = 0usize;
                        loop {
                            tokio::select! {
                                d = body.data() => match d {
                                    Some(Ok(chunk)) => {
                                        let _ = body.flow_control().release_capacity(chunk.len());
                                        pending.extend_from_slice(&chunk);
                                        while pending.len() >= 2 {
                                            let len = u16::from_be_bytes([pending[0], pending[1]]) as usize;
                                            if pending.len() < 2 + len {
                                                break;
                                            }
                                            let d: Vec<u8> = pending[2..2 + len].to_vec();
                                            pending.drain(..2 + len);
                                            log.udp_relayed.lock().push((authority.clone(), d.len()));
                                            let _ = sock.send(&d).await;
                                        }
                                    }
                                    _ => {
                                        log.udp_tunnel_ends.lock().push("client_end".into());
                                        return;
                                    }
                                },
                                r = sock.recv(&mut dgram) => {
                                    let Ok(n) = r else {
                                        log.udp_tunnel_ends.lock().push("destination_error".into());
                                        send.send_reset(h2::Reason::CANCEL);
                                        return;
                                    };
                                    let _ = send.send_data(Bytes::from(frame(&dgram[..n])), false);
                                    sent += 1;
                                    if sent >= replies {
                                        log.udp_tunnel_ends.lock().push("fault:reset".into());
                                        // A reset discards queued frames: let the reply leave first.
                                        tokio::time::sleep(Duration::from_millis(50)).await;
                                        send.send_reset(h2::Reason::CANCEL);
                                        return;
                                    }
                                }
                            }
                        }
                    });
                }
            });
        }
    });
    Ok(HboneFixture { addr, log, cancel })
}

/// A UDP socket connected to `authority` (`host:port`, IPv6 bracketed).
async fn udp_socket(authority: &str) -> Option<UdpSocket> {
    let addr = tokio::net::lookup_host(authority).await.ok()?.next()?;
    let bind = if addr.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
    let sock = UdpSocket::bind(bind).await.ok()?;
    sock.connect(addr).await.ok()?;
    Some(sock)
}

/// One `[u16 big-endian length][payload]` record (the fixture's own codec).
fn frame(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 2);
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Relay records from the tunnel to the connected UDP socket and datagrams
/// from the socket back as records, until the client ends the stream, the
/// socket fails (an ICMP error), or `fault` ends the tunnel.
async fn relay_udp<S>(
    tunnel: S,
    sock: UdpSocket,
    authority: String,
    fault: Option<UdpTunnelFault>,
    log: Arc<HboneLog>,
    drop_conn: CancellationToken,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut rd, mut wr) = tokio::io::split(tunnel);
    let mut pending: Vec<u8> = Vec::new();
    let mut chunk = vec![0u8; 16 * 1024];
    let mut dgram = vec![0u8; 65_535];
    let mut replies = 0usize;
    let end = |why: &str| log.udp_tunnel_ends.lock().push(why.to_string());
    let end_at = match fault {
        Some(UdpTunnelFault::EndAfterMs(ms)) => Some(tokio::time::Instant::now() + Duration::from_millis(ms)),
        _ => None,
    };
    let timer = async move {
        match end_at {
            Some(t) => tokio::time::sleep_until(t).await,
            None => std::future::pending().await,
        }
    };
    tokio::pin!(timer);
    loop {
        tokio::select! {
            _ = &mut timer => {
                end("fault:end_stream");
                let _ = wr.shutdown().await;
                // Keep the stream until the client ends its side.
                let _ = tokio::time::timeout(Duration::from_secs(5), async {
                    while let Ok(n) = rd.read(&mut chunk).await {
                        if n == 0 {
                            break;
                        }
                    }
                })
                .await;
                return;
            }
            r = rd.read(&mut chunk) => match r {
                Ok(0) | Err(_) => {
                    end("client_end");
                    let _ = wr.shutdown().await;
                    return;
                }
                Ok(n) => {
                    pending.extend_from_slice(&chunk[..n]);
                    while pending.len() >= 2 {
                        let len = u16::from_be_bytes([pending[0], pending[1]]) as usize;
                        if pending.len() < 2 + len {
                            break;
                        }
                        let d: Vec<u8> = pending[2..2 + len].to_vec();
                        pending.drain(..2 + len);
                        log.udp_relayed.lock().push((authority.clone(), d.len()));
                        let _ = sock.send(&d).await;
                    }
                }
            },
            r = sock.recv(&mut dgram) => match r {
                Ok(n) => {
                    let mut out = frame(&dgram[..n]);
                    if fault == Some(UdpTunnelFault::PackWithEmpty) {
                        out.extend_from_slice(&frame(&[]));
                    }
                    if wr.write_all(&out).await.is_err() {
                        end("write_failed");
                        return;
                    }
                    replies += 1;
                    match fault {
                        Some(UdpTunnelFault::EndAfter(k)) if replies >= k => {
                            end("fault:end_stream");
                            let _ = wr.shutdown().await;
                            // Keep the stream until the client ends its side.
                            let _ = tokio::time::timeout(Duration::from_secs(5), rd.read(&mut chunk)).await;
                            return;
                        }
                        Some(UdpTunnelFault::DropConnectionAfter(k)) if replies >= k => {
                            end("fault:connection_dropped");
                            // Give the reply a moment to leave, then vanish.
                            tokio::time::sleep(Duration::from_millis(50)).await;
                            drop_conn.cancel();
                            return;
                        }
                        Some(UdpTunnelFault::TruncateAfter(k)) if replies >= k => {
                            end("fault:truncated_record");
                            let _ = wr.write_all(&[0x00, 0x10, 1, 2, 3, 4]).await;
                            let _ = wr.flush().await;
                            let _ = wr.shutdown().await;
                            let _ = tokio::time::timeout(Duration::from_secs(5), rd.read(&mut chunk)).await;
                            return;
                        }
                        _ => {}
                    }
                }
                Err(_) => {
                    // An ICMP error on the connected socket ends the relay, as in Ferrum Edge.
                    end("destination_error");
                    let _ = wr.shutdown().await;
                    return;
                }
            },
        }
    }
}
