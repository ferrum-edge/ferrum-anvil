//! One destination for the HTTP/3 → TCP fallback: HTTP/3 on a UDP port and
//! TLS (HTTP/2, HTTP/1.1) on the same TCP port. It checks per-send auth for
//! replays, as a gateway that verifies signatures does: a request whose
//! `authorization` and `dpop` headers were both already received, over
//! either protocol, is a replay.
//!
//! * Over HTTP/3, every request is read whole, then its stream is reset
//!   (`H3_INTERNAL_ERROR`) without a response: the request reached the
//!   server, and the client cannot know whether it was processed.
//! * Over TCP, a replay is answered `401`, any other request `200`.
//!
//! Without QUIC ([`serve`] with `quic = false`) only the TCP port is bound:
//! a QUIC handshake to it gets no answer.

use crate::tlsserver::{TlsServerOptions, server_config};
use bytes::{Buf, Bytes};
use http_body_util::{BodyExt, Full};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use parking_lot::Mutex;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

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
    /// The same `authorization` and `dpop` were received before.
    pub replayed: bool,
}

pub struct ReplayFixture {
    pub addr: SocketAddr,
    received: Arc<Mutex<Vec<Received>>>,
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
    let (authorization, dpop) = (value("authorization"), value("dpop"));
    let mut r = received.lock();
    let replayed = r.iter().any(|x| x.authorization == authorization && x.dpop == dpop);
    r.push(Received { protocol: protocol.into(), method: method.into(), authorization, dpop, replayed });
    replayed
}

/// A UDP port for QUIC and the same TCP port, on 127.0.0.1. Another socket
/// may hold that TCP port: a new UDP port is then tried.
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
    let mut last = None;
    for _ in 0..16 {
        let endpoint = quinn::Endpoint::server(server_cfg.clone(), "127.0.0.1:0".parse()?)?;
        match TcpListener::bind(endpoint.local_addr()?).await {
            Ok(l) => return Ok((Some(endpoint), l)),
            Err(e) => {
                endpoint.close(0u32.into(), b"");
                last = Some(e);
            }
        }
    }
    Err(anyhow::anyhow!("no port was free over both UDP and TCP: {last:?}"))
}

/// Start the fixture on 127.0.0.1, with HTTP/3 when `quic`.
pub async fn serve(tls: TlsServerOptions, quic: bool) -> anyhow::Result<ReplayFixture> {
    let (endpoint, listener) = bind(&tls, quic).await?;
    let addr = listener.local_addr()?;
    let received = Arc::new(Mutex::new(Vec::new()));
    let cancel = CancellationToken::new();
    if let Some(ep) = endpoint.clone() {
        let (received, cancel) = (received.clone(), cancel.clone());
        tokio::spawn(async move {
            loop {
                let incoming = tokio::select! {
                    i = ep.accept() => match i { Some(i) => i, None => break },
                    _ = cancel.cancelled() => break,
                };
                let (received, cancel) = (received.clone(), cancel.clone());
                tokio::spawn(async move {
                    let Ok(conn) = incoming.await else { return };
                    let Ok(mut h3c) = h3::server::builder().build::<_, Bytes>(h3_quinn::Connection::new(conn)).await else { return };
                    loop {
                        let accepted = tokio::select! {
                            r = h3c.accept() => r,
                            _ = cancel.cancelled() => break,
                        };
                        let Ok(Some(resolver)) = accepted else { break };
                        let received = received.clone();
                        tokio::spawn(async move {
                            let Ok((req, mut stream)) = resolver.resolve_request().await else { return };
                            while let Ok(Some(mut chunk)) = stream.recv_data().await {
                                let n = chunk.remaining();
                                chunk.advance(n);
                            }
                            record(&received, "h3", req.method().as_str(), req.headers());
                            stream.stop_stream(h3::error::Code::H3_INTERNAL_ERROR);
                        });
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
                        let status = if replayed { 401 } else { 200 };
                        let resp =
                            http::Response::builder().status(status).body(Full::new(Bytes::from_static(b"ok"))).expect("static response");
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
    Ok(ReplayFixture { addr, received, endpoint, cancel })
}
