//! HTTP/3 (QUIC) fixture server built on quinn + h3.
//!
//! Routes (all bounded):
//! * `/` — 200 text
//! * `/status/{code}` — arbitrary status with a small JSON body
//! * `/echo` — JSON echo of method, path, headers and body length
//!
//! Ground truth records QUIC connections, the negotiated ALPN and every
//! request, so tests can prove that a request really travelled over QUIC.

use crate::log::{GroundTruth, GroundTruthLog};
use crate::tlsserver::{TlsServerOptions, server_config};
use bytes::{Buf, Bytes};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

pub struct H3Fixture {
    pub addr: SocketAddr,
    pub log: GroundTruthLog,
    endpoint: quinn::Endpoint,
    cancel: CancellationToken,
}

impl H3Fixture {
    pub fn url(&self, path: &str) -> String {
        format!("https://{}{}", self.addr, path)
    }

    pub fn url_host(&self, host: &str, path: &str) -> String {
        format!("https://{}:{}{}", host, self.addr.port(), path)
    }

    /// Number of QUIC connections the fixture accepted.
    pub fn connections(&self) -> usize {
        self.log.entries().iter().filter(|e| matches!(e.event, GroundTruth::ConnectionAccepted { .. })).count()
    }
}

impl Drop for H3Fixture {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.endpoint.close(0u32.into(), b"fixture shutdown");
    }
}

/// Start an HTTP/3 fixture on a UDP socket. `bind` like `127.0.0.1:0`.
/// The TLS options' ALPN list is replaced with `h3` and TLS 1.3 is enforced
/// (QUIC requires it).
pub async fn serve(bind: &str, tls: TlsServerOptions) -> anyhow::Result<H3Fixture> {
    let mut opts = tls;
    opts.alpn = vec!["h3".into()];
    opts.tls13_only = true;
    opts.tls12_only = false;
    let rustls_cfg = server_config(&opts)?;
    let quic_cfg = quinn::crypto::rustls::QuicServerConfig::try_from(rustls_cfg)?;
    let server_cfg = quinn::ServerConfig::with_crypto(Arc::new(quic_cfg));
    let addr: SocketAddr = bind.parse()?;
    let endpoint = quinn::Endpoint::server(server_cfg, addr)?;
    let addr = endpoint.local_addr()?;
    let log = GroundTruthLog::default();
    let cancel = CancellationToken::new();
    let (ep, l2, c2) = (endpoint.clone(), log.clone(), cancel.clone());
    tokio::spawn(async move {
        loop {
            let incoming = tokio::select! {
                i = ep.accept() => match i { Some(i) => i, None => break },
                _ = c2.cancelled() => break,
            };
            let (log, cancel) = (l2.clone(), c2.clone());
            tokio::spawn(async move {
                let conn = match incoming.await {
                    Ok(c) => c,
                    Err(e) => {
                        log.push(GroundTruth::TlsHandshakeFailed { error: e.to_string() });
                        return;
                    }
                };
                log.push(GroundTruth::ConnectionAccepted { peer: conn.remote_address().to_string() });
                let alpn = conn
                    .handshake_data()
                    .and_then(|d| d.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
                    .and_then(|d| d.protocol.map(|p| String::from_utf8_lossy(&p).into_owned()));
                log.push(GroundTruth::TlsHandshakeCompleted { alpn, client_cert_cn: None });
                let mut h3c = match h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(conn)).await {
                    Ok(c) => c,
                    Err(e) => {
                        log.push(GroundTruth::FaultApplied { fault: format!("h3_setup_failed: {e}") });
                        return;
                    }
                };
                loop {
                    let accepted = tokio::select! {
                        r = h3c.accept() => r,
                        _ = cancel.cancelled() => break,
                    };
                    match accepted {
                        Ok(Some(resolver)) => {
                            let log = log.clone();
                            tokio::spawn(async move {
                                let Ok((req, mut stream)) = resolver.resolve_request().await else { return };
                                let mut body_bytes = 0u64;
                                while let Ok(Some(mut chunk)) = stream.recv_data().await {
                                    let n = chunk.remaining();
                                    body_bytes += n as u64;
                                    chunk.advance(n);
                                    if body_bytes > 16 * 1024 * 1024 {
                                        break;
                                    }
                                }
                                let path = req.uri().path_and_query().map(|p| p.as_str().to_string()).unwrap_or_else(|| "/".into());
                                let headers: Vec<(String, String)> = req
                                    .headers()
                                    .iter()
                                    .map(|(n, v)| (n.as_str().to_string(), String::from_utf8_lossy(v.as_bytes()).into_owned()))
                                    .collect();
                                log.push(GroundTruth::RequestReceived {
                                    method: req.method().to_string(),
                                    path: path.clone(),
                                    body_bytes,
                                    headers: headers.clone(),
                                });
                                let segs: Vec<&str> = req.uri().path().trim_start_matches('/').split('/').collect();
                                let (status, ct, body) = match segs.as_slice() {
                                    [""] => (200u16, "text/plain", Bytes::from_static(b"anvil h3 fixture ok\n")),
                                    ["status", code] => {
                                        let code: u16 = code.parse().unwrap_or(500);
                                        (code, "application/json", Bytes::from(format!("{{\"status\":{code},\"protocol\":\"h3\"}}")))
                                    }
                                    ["echo"] => {
                                        let v = serde_json::json!({
                                            "method": req.method().as_str(), "path": path, "protocol": "h3",
                                            "headers": headers.iter().map(|(n, v)| serde_json::json!([n, v])).collect::<Vec<_>>(),
                                            "body_len": body_bytes,
                                        });
                                        (200, "application/json", Bytes::from(serde_json::to_vec(&v).unwrap_or_default()))
                                    }
                                    _ => (404, "application/json", Bytes::from_static(b"{\"error\":\"no fixture route\"}")),
                                };
                                log.push(GroundTruth::ResponseStarted { status });
                                let resp = http::Response::builder()
                                    .status(status)
                                    .header("content-type", ct)
                                    .header("x-fixture-protocol", "h3")
                                    .body(())
                                    .expect("static response");
                                if stream.send_response(resp).await.is_ok() {
                                    let _ = stream.send_data(body).await;
                                    let _ = stream.finish().await;
                                }
                            });
                        }
                        Ok(None) | Err(_) => break,
                    }
                }
            });
        }
    });
    Ok(H3Fixture { addr, log, endpoint, cancel })
}
