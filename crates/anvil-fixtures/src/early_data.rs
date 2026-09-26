//! 0-RTT early-data fixtures: an HTTP/3 server (quinn + h3) and a TLS 1.3
//! HTTP/1.1 + HTTP/2 server (tokio-rustls + hyper). Both issue stateful
//! session tickets from one in-memory store that survives mode switches, so a
//! ticket issued in one mode is presented in the next.
//!
//! Modes ([`EarlyMode`], switchable at runtime):
//! * `Accept` — tickets allow early data and the server accepts it;
//! * `Reject` — new tickets do not allow early data and early data presented
//!   with an older ticket is rejected (the session still resumes);
//! * `TooEarly` — early data is accepted, but a request that arrived in it
//!   with a method outside `allowed` is answered `425 Too Early` with the body
//!   `{"error":"Method not allowed in 0-RTT early data"}` (the same answer
//!   Ferrum Edge's HTTP/3 listener gives);
//! * `Disabled` — tickets never allow early data (resumption only);
//! * `NoTickets` — no session tickets are issued.
//!
//! Ground truth, per request, is [`GroundTruth::EarlyDataRequest`]: whether
//! the request arrived in early data the server accepted. Over TCP that is
//! exact: rustls hands the early bytes over separately, and the first request
//! of the connection counts as early when those bytes hold its whole head (an
//! HTTP/1.1 head, or an HTTP/2 HEADERS frame after the preface). Over QUIC the fixture
//! wraps quinn's rustls session to learn whether the connection accepted
//! 0-RTT, and counts its first request stream (stream 0) as early: Anvil
//! writes exactly one request as 0-RTT data, always on the first stream.
//!
//! Every response carries `x-fixture-early-data: 1|0`. Route `/echo` returns
//! JSON (method, path, headers, `early_data`); any other path gets 200 text.

use crate::log::{GroundTruth, GroundTruthLog};
use crate::tlsserver::{TlsServerOptions, server_config};
use bytes::{Buf, Bytes};
use http_body_util::{BodyExt, Full, Limited};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use parking_lot::Mutex;
use quinn_proto::crypto::{self as qcrypto, ExportKeyingMaterialError, HeaderKey, KeyPair, Keys, PacketKey, UnsupportedVersion};
use quinn_proto::transport_parameters::TransportParameters;
use quinn_proto::{ConnectionId, Side, TransportError};
use rustls::server::{ServerSessionMemoryCache, StoresServerSessions};
use std::any::Any;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EarlyMode {
    Accept,
    Reject,
    TooEarly {
        allowed: Vec<String>,
    },
    Disabled,
    NoTickets,
    /// A lookalike: early data is accepted, but *every* request is answered
    /// `425 Too Early`, whether it arrived in early data or not.
    AlwaysTooEarly,
}

impl EarlyMode {
    fn refuses(&self, method: &str, early: bool) -> bool {
        match self {
            EarlyMode::TooEarly { allowed } => early && !allowed.iter().any(|m| m.eq_ignore_ascii_case(method)),
            EarlyMode::AlwaysTooEarly => true,
            _ => false,
        }
    }
}

/// Mode and ticket store shared by a fixture's connections.
struct Shared {
    mode: Mutex<EarlyMode>,
    tls: TlsServerOptions,
    sessions: Arc<dyn StoresServerSessions>,
}

impl Shared {
    fn new(tls: TlsServerOptions, mode: EarlyMode) -> Arc<Self> {
        Arc::new(Shared { mode: Mutex::new(mode), tls, sessions: ServerSessionMemoryCache::new(256) })
    }

    /// A TLS 1.3 server config for the current mode (stateful tickets from
    /// the shared store; rustls accepts early data only with those).
    fn rustls(&self, alpn: &[&str]) -> anyhow::Result<rustls::ServerConfig> {
        let mut opts = self.tls.clone();
        opts.alpn = alpn.iter().map(|s| s.to_string()).collect();
        opts.tls13_only = true;
        opts.tls12_only = false;
        let mut cfg = (*server_config(&opts)?).clone();
        cfg.session_storage = self.sessions.clone();
        let mode = self.mode.lock().clone();
        cfg.max_early_data_size = match mode {
            EarlyMode::Accept | EarlyMode::TooEarly { .. } | EarlyMode::AlwaysTooEarly => u32::MAX,
            EarlyMode::Reject | EarlyMode::Disabled | EarlyMode::NoTickets => 0,
        };
        if mode == EarlyMode::NoTickets {
            cfg.send_tls13_tickets = 0;
        }
        Ok(cfg)
    }
}

fn early_header(early: bool) -> &'static str {
    if early { "1" } else { "0" }
}

fn answer(
    mode: &EarlyMode,
    method: &str,
    path: &str,
    early: bool,
    headers: &[(String, String)],
    body_len: usize,
    protocol: &str,
) -> (u16, &'static str, Bytes) {
    if mode.refuses(method, early) {
        return (425, "application/json", Bytes::from_static(br#"{"error":"Method not allowed in 0-RTT early data"}"#));
    }
    if path.starts_with("/echo") {
        let v = serde_json::json!({
            "method": method, "path": path, "protocol": protocol, "early_data": early, "body_len": body_len,
            "headers": headers.iter().map(|(n, v)| serde_json::json!([n, v])).collect::<Vec<_>>(),
        });
        return (200, "application/json", Bytes::from(serde_json::to_vec(&v).unwrap_or_default()));
    }
    (200, "text/plain", Bytes::from_static(b"anvil early-data fixture ok\n"))
}

// ------------------------------------------------------------------ QUIC ---

/// quinn's rustls server config, wrapped so each session reports whether it
/// accepted 0-RTT: quinn asks the session for early keys once, right after the
/// ClientHello, and rustls only has them when it accepted early data.
struct EarlyAwareConfig(Arc<quinn::crypto::rustls::QuicServerConfig>);

impl qcrypto::ServerConfig for EarlyAwareConfig {
    fn initial_keys(&self, version: u32, dst_cid: &ConnectionId) -> Result<Keys, UnsupportedVersion> {
        self.0.initial_keys(version, dst_cid)
    }

    fn retry_tag(&self, version: u32, orig_dst_cid: &ConnectionId, packet: &[u8]) -> [u8; 16] {
        self.0.retry_tag(version, orig_dst_cid, packet)
    }

    fn start_session(self: Arc<Self>, version: u32, params: &TransportParameters) -> Box<dyn qcrypto::Session> {
        Box::new(EarlyAwareSession { inner: self.0.clone().start_session(version, params), early: Arc::new(AtomicBool::new(false)) })
    }
}

struct EarlyAwareSession {
    inner: Box<dyn qcrypto::Session>,
    early: Arc<AtomicBool>,
}

/// What `Connection::handshake_data()` returns on the fixture's connections.
pub struct EarlyHandshakeData {
    pub alpn: Option<Vec<u8>>,
    pub zero_rtt_accepted: Arc<AtomicBool>,
}

impl qcrypto::Session for EarlyAwareSession {
    fn initial_keys(&self, dst_cid: &ConnectionId, side: Side) -> Keys {
        self.inner.initial_keys(dst_cid, side)
    }

    fn handshake_data(&self) -> Option<Box<dyn Any>> {
        let d = self.inner.handshake_data()?;
        let alpn = d.downcast::<quinn::crypto::rustls::HandshakeData>().ok().and_then(|h| h.protocol);
        Some(Box::new(EarlyHandshakeData { alpn, zero_rtt_accepted: self.early.clone() }))
    }

    fn peer_identity(&self) -> Option<Box<dyn Any>> {
        self.inner.peer_identity()
    }

    fn early_crypto(&self) -> Option<(Box<dyn HeaderKey>, Box<dyn PacketKey>)> {
        let keys = self.inner.early_crypto();
        if keys.is_some() {
            self.early.store(true, Ordering::SeqCst);
        }
        keys
    }

    fn early_data_accepted(&self) -> Option<bool> {
        self.inner.early_data_accepted()
    }

    fn is_handshaking(&self) -> bool {
        self.inner.is_handshaking()
    }

    fn read_handshake(&mut self, buf: &[u8]) -> Result<bool, TransportError> {
        self.inner.read_handshake(buf)
    }

    fn transport_parameters(&self) -> Result<Option<TransportParameters>, TransportError> {
        self.inner.transport_parameters()
    }

    fn write_handshake(&mut self, buf: &mut Vec<u8>) -> Option<Keys> {
        self.inner.write_handshake(buf)
    }

    fn next_1rtt_keys(&mut self) -> Option<KeyPair<Box<dyn PacketKey>>> {
        self.inner.next_1rtt_keys()
    }

    fn is_valid_retry(&self, orig_dst_cid: &ConnectionId, header: &[u8], payload: &[u8]) -> bool {
        self.inner.is_valid_retry(orig_dst_cid, header, payload)
    }

    fn export_keying_material(&self, output: &mut [u8], label: &[u8], context: &[u8]) -> Result<(), ExportKeyingMaterialError> {
        self.inner.export_keying_material(output, label, context)
    }
}

pub struct EarlyH3Fixture {
    pub addr: SocketAddr,
    pub log: GroundTruthLog,
    endpoint: quinn::Endpoint,
    shared: Arc<Shared>,
    cancel: CancellationToken,
}

impl EarlyH3Fixture {
    pub fn url(&self, path: &str) -> String {
        format!("https://{}{}", self.addr, path)
    }

    /// Switch the behaviour for new connections (tickets already issued keep
    /// what they allowed).
    pub fn set_mode(&self, mode: EarlyMode) -> anyhow::Result<()> {
        *self.shared.mode.lock() = mode;
        self.endpoint.set_server_config(Some(quic_config(&self.shared)?));
        Ok(())
    }

    /// `(early, method, status)` of every request, in arrival order.
    pub fn requests(&self) -> Vec<(bool, String, u16)> {
        early_requests(&self.log)
    }
}

impl Drop for EarlyH3Fixture {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.endpoint.close(0u32.into(), b"fixture shutdown");
    }
}

pub fn early_requests(log: &GroundTruthLog) -> Vec<(bool, String, u16)> {
    log.entries()
        .into_iter()
        .filter_map(|e| match e.event {
            GroundTruth::EarlyDataRequest { method, early, status, .. } => Some((early, method, status)),
            _ => None,
        })
        .collect()
}

fn quic_config(shared: &Shared) -> anyhow::Result<quinn::ServerConfig> {
    let quic = quinn::crypto::rustls::QuicServerConfig::try_from(shared.rustls(&["h3"])?)?;
    Ok(quinn::ServerConfig::with_crypto(Arc::new(EarlyAwareConfig(Arc::new(quic)))))
}

/// Start the HTTP/3 early-data fixture. `bind` like `127.0.0.1:0`.
pub async fn serve_h3(bind: &str, tls: TlsServerOptions, mode: EarlyMode) -> anyhow::Result<EarlyH3Fixture> {
    let shared = Shared::new(tls, mode);
    let addr: SocketAddr = bind.parse()?;
    let endpoint = quinn::Endpoint::server(quic_config(&shared)?, addr)?;
    let addr = endpoint.local_addr()?;
    let log = GroundTruthLog::default();
    let cancel = CancellationToken::new();
    let (ep, l2, c2, s2) = (endpoint.clone(), log.clone(), cancel.clone(), shared.clone());
    tokio::spawn(async move {
        loop {
            let incoming = tokio::select! {
                i = ep.accept() => match i { Some(i) => i, None => break },
                _ = c2.cancelled() => break,
            };
            let (log, cancel, shared) = (l2.clone(), c2.clone(), s2.clone());
            tokio::spawn(async move {
                let conn = match incoming.await {
                    Ok(c) => c,
                    Err(e) => {
                        log.push(GroundTruth::TlsHandshakeFailed { error: e.to_string() });
                        return;
                    }
                };
                log.push(GroundTruth::ConnectionAccepted { peer: conn.remote_address().to_string() });
                let hd = conn.handshake_data().and_then(|d| d.downcast::<EarlyHandshakeData>().ok());
                let zero_rtt = hd.as_ref().map(|h| h.zero_rtt_accepted.load(Ordering::SeqCst)).unwrap_or(false);
                let alpn = hd.and_then(|h| h.alpn).map(|p| String::from_utf8_lossy(&p).into_owned());
                log.push(GroundTruth::TlsHandshakeCompleted { alpn, client_cert_cn: None });
                let Ok(mut h3c) = h3::server::builder().build::<_, Bytes>(h3_quinn::Connection::new(conn)).await else { return };
                loop {
                    let accepted = tokio::select! {
                        r = h3c.accept() => r,
                        _ = cancel.cancelled() => break,
                    };
                    let Ok(Some(resolver)) = accepted else { break };
                    let (log, shared) = (log.clone(), shared.clone());
                    tokio::spawn(async move {
                        let Ok((req, mut stream)) = resolver.resolve_request().await else { return };
                        let early = zero_rtt && stream.id().into_inner() == 0;
                        let mut body_len = 0usize;
                        while let Ok(Some(mut chunk)) = stream.recv_data().await {
                            let n = chunk.remaining();
                            body_len += n;
                            chunk.advance(n);
                        }
                        let path = req.uri().path_and_query().map(|p| p.as_str().to_string()).unwrap_or_else(|| "/".into());
                        let headers: Vec<(String, String)> = req
                            .headers()
                            .iter()
                            .map(|(n, v)| (n.as_str().to_string(), String::from_utf8_lossy(v.as_bytes()).into_owned()))
                            .collect();
                        let method = req.method().to_string();
                        log.push(GroundTruth::RequestReceived {
                            method: method.clone(),
                            path: path.clone(),
                            body_bytes: body_len as u64,
                            headers: headers.clone(),
                        });
                        let mode = shared.mode.lock().clone();
                        let (status, ct, body) = answer(&mode, &method, &path, early, &headers, body_len, "h3");
                        log.push(GroundTruth::EarlyDataRequest { method, path, early, status });
                        let resp = http::Response::builder()
                            .status(status)
                            .header("content-type", ct)
                            .header("x-fixture-early-data", early_header(early))
                            .body(())
                            .expect("static response");
                        if stream.send_response(resp).await.is_ok() {
                            let _ = stream.send_data(body).await;
                            let _ = stream.finish().await;
                        }
                    });
                }
            });
        }
    });
    Ok(EarlyH3Fixture { addr, log, endpoint, shared, cancel })
}

// ------------------------------------------------------------ TLS / TCP ---

/// Replays the early-data bytes rustls handed over, then the TLS stream.
struct Prefixed<S> {
    prefix: Bytes,
    inner: S,
}

impl<S: AsyncRead + Unpin> AsyncRead for Prefixed<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        if !self.prefix.is_empty() {
            let n = self.prefix.len().min(buf.remaining());
            let chunk = self.prefix.split_to(n);
            buf.put_slice(&chunk);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Prefixed<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

pub struct EarlyTlsFixture {
    pub addr: SocketAddr,
    pub log: GroundTruthLog,
    shared: Arc<Shared>,
    cancel: CancellationToken,
}

impl EarlyTlsFixture {
    pub fn url(&self, path: &str) -> String {
        format!("https://{}{}", self.addr, path)
    }

    pub fn set_mode(&self, mode: EarlyMode) {
        *self.shared.mode.lock() = mode;
    }

    pub fn requests(&self) -> Vec<(bool, String, u16)> {
        early_requests(&self.log)
    }
}

impl Drop for EarlyTlsFixture {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

/// Whether the accepted early data carries a whole request head: an HTTP/1.1
/// head up to its blank line, or an HTTP/2 HEADERS frame after the preface
/// (the preface and SETTINGS alone are not a request).
fn early_holds_request(alpn: Option<&str>, early: &[u8]) -> bool {
    if alpn == Some("h2") {
        const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        let Some(mut rest) = early.strip_prefix(PREFACE) else { return false };
        while rest.len() >= 9 {
            let len = ((rest[0] as usize) << 16) | ((rest[1] as usize) << 8) | rest[2] as usize;
            if rest.len() < 9 + len {
                return false;
            }
            if rest[3] == 0x1 {
                return true;
            }
            rest = &rest[9 + len..];
        }
        false
    } else {
        early.windows(4).any(|w| w == b"\r\n\r\n")
    }
}

/// Start the TLS 1.3 (HTTP/1.1 and HTTP/2) early-data fixture.
pub async fn serve_tls(bind: &str, tls: TlsServerOptions, mode: EarlyMode) -> anyhow::Result<EarlyTlsFixture> {
    let shared = Shared::new(tls, mode);
    shared.rustls(&["h2", "http/1.1"])?;
    let listener = tokio::net::TcpListener::bind(bind).await?;
    let addr = listener.local_addr()?;
    let log = GroundTruthLog::default();
    let cancel = CancellationToken::new();
    let (l2, c2, s2) = (log.clone(), cancel.clone(), shared.clone());
    tokio::spawn(async move {
        loop {
            let (tcp, peer) = tokio::select! {
                r = listener.accept() => match r { Ok(x) => x, Err(_) => continue },
                _ = c2.cancelled() => break,
            };
            let _ = tcp.set_nodelay(true);
            l2.push(GroundTruth::ConnectionAccepted { peer: peer.to_string() });
            let (log, cancel, shared) = (l2.clone(), c2.clone(), s2.clone());
            tokio::spawn(async move {
                let Ok(cfg) = shared.rustls(&["h2", "http/1.1"]) else { return };
                let mut tls = match tokio_rustls::TlsAcceptor::from(Arc::new(cfg)).accept(tcp).await {
                    Ok(t) => t,
                    Err(e) => {
                        log.push(GroundTruth::TlsHandshakeFailed { error: e.to_string() });
                        return;
                    }
                };
                let (_, sc) = tls.get_mut();
                let alpn = sc.alpn_protocol().map(|p| String::from_utf8_lossy(p).into_owned());
                let mut early = Vec::new();
                if let Some(mut ed) = sc.early_data() {
                    let _ = std::io::Read::read_to_end(&mut ed, &mut early);
                }
                log.push(GroundTruth::TlsHandshakeCompleted { alpn: alpn.clone(), client_cert_cn: None });
                let conn_early = early_holds_request(alpn.as_deref(), &early);
                let first = Arc::new(AtomicBool::new(true));
                let io = TokioIo::new(Prefixed { prefix: Bytes::from(early), inner: tls });
                let protocol = if alpn.as_deref() == Some("h2") { "h2" } else { "http/1.1" };
                let svc = service_fn(move |req: http::Request<hyper::body::Incoming>| {
                    let (log, shared, first) = (log.clone(), shared.clone(), first.clone());
                    async move {
                        let early = conn_early && first.swap(false, Ordering::SeqCst);
                        let method = req.method().to_string();
                        let path = req.uri().path_and_query().map(|p| p.as_str().to_string()).unwrap_or_else(|| "/".into());
                        let headers: Vec<(String, String)> = req
                            .headers()
                            .iter()
                            .map(|(n, v)| (n.as_str().to_string(), String::from_utf8_lossy(v.as_bytes()).into_owned()))
                            .collect();
                        let body =
                            Limited::new(req.into_body(), 16 * 1024 * 1024).collect().await.map(|b| b.to_bytes()).unwrap_or_default();
                        log.push(GroundTruth::RequestReceived {
                            method: method.clone(),
                            path: path.clone(),
                            body_bytes: body.len() as u64,
                            headers: headers.clone(),
                        });
                        let mode = shared.mode.lock().clone();
                        let (status, ct, out) = answer(&mode, &method, &path, early, &headers, body.len(), protocol);
                        log.push(GroundTruth::EarlyDataRequest { method, path, early, status });
                        let resp = http::Response::builder()
                            .status(status)
                            .header("content-type", ct)
                            .header("x-fixture-early-data", early_header(early))
                            .body(Full::new(out))
                            .expect("static response");
                        Ok::<_, Infallible>(resp)
                    }
                });
                let builder = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
                tokio::select! {
                    _ = builder.serve_connection(io, svc) => {}
                    _ = cancel.cancelled() => {}
                }
            });
        }
    });
    Ok(EarlyTlsFixture { addr, log, shared, cancel })
}
