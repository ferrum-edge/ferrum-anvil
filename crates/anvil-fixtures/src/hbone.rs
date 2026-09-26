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
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

pub const UNAUTHENTICATED_BODY: &str = r#"{"error":"HBONE tunnel requires an authenticated mesh peer"}"#;
pub const DESTINATION_DENIED_BODY: &str = r#"{"error":"HBONE relay destination not allowed"}"#;

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
                let svc = service_fn(move |req| {
                    let (log, opts, peer) = (log.clone(), opts.clone(), peer.clone());
                    async move { Ok::<_, Infallible>(handle(req, log, opts, peer).await) }
                });
                let conn = hyper::server::conn::http2::Builder::new(TokioExecutor::new()).serve_connection(TokioIo::new(tls), svc);
                tokio::select! {
                    _ = conn => {}
                    _ = cancel.cancelled() => {}
                }
            });
        }
    });
    Ok(HboneFixture { addr, log, cancel })
}

async fn handle(req: Request<Incoming>, log: Arc<HboneLog>, opts: Arc<HboneOptions>, peer: Option<String>) -> Response<Body> {
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
