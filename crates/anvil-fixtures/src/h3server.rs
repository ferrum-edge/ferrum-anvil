//! HTTP/3 (QUIC) fixture server built on quinn + h3.
//!
//! Routes (all bounded):
//! * `/` — 200 text
//! * `/status/{code}` — arbitrary status with a small JSON body
//! * `/echo` — JSON echo of method, path, headers and body length
//! * `CONNECT /ws` with `:protocol = websocket` (RFC 9220) — WebSocket echo
//!   with the same `close_after` / `abnormal_after` / `max` query options as
//!   the TCP fixture's `/ws`; a CONNECT elsewhere or without that protocol
//!   gets 400
//! * `/anvil.lab.v1.Echo/*`, `/grpc.reflection.*` — native gRPC over HTTP/3
//!   (all four call modes, full duplex, status in HTTP/3 trailers), or
//!   gRPC-Web (binary/text) for an `application/grpc-web*` content type
//!
//! Ground truth records QUIC connections, the negotiated ALPN and every
//! request, so tests can prove that a request really travelled over QUIC.

use crate::log::{GroundTruth, GroundTruthLog};
use crate::tlsserver::{TlsServerOptions, server_config};
use bytes::{Buf, Bytes};
use futures::{SinkExt, StreamExt};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::{CloseFrame, Role, WebSocketConfig};
use tokio_tungstenite::tungstenite::{self, Message};
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

/// Server behaviour switches.
#[derive(Clone, Copy, Debug)]
pub struct H3Options {
    /// Advertise `SETTINGS_ENABLE_CONNECT_PROTOCOL` (RFC 9220 WebSocket).
    pub extended_connect: bool,
}

impl Default for H3Options {
    fn default() -> Self {
        H3Options { extended_connect: true }
    }
}

/// Start an HTTP/3 fixture on a UDP socket. `bind` like `127.0.0.1:0`.
/// The TLS options' ALPN list is replaced with `h3` and TLS 1.3 is enforced
/// (QUIC requires it).
pub async fn serve(bind: &str, tls: TlsServerOptions) -> anyhow::Result<H3Fixture> {
    serve_with(bind, tls, H3Options::default()).await
}

/// [`serve`] with explicit options.
pub async fn serve_with(bind: &str, tls: TlsServerOptions, options: H3Options) -> anyhow::Result<H3Fixture> {
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
                let built = h3::server::builder()
                    .enable_extended_connect(options.extended_connect)
                    .build::<_, Bytes>(h3_quinn::Connection::new(conn))
                    .await;
                let mut h3c = match built {
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
                                if req.method() == http::Method::CONNECT {
                                    return websocket(req, stream, log).await;
                                }
                                let p = req.uri().path();
                                if p.starts_with("/anvil.lab.v1.") || p.starts_with("/grpc.reflection.") {
                                    if crate::grpc_web::is_grpc_web(req.headers()) {
                                        return crate::grpc_web::handle_h3(req, stream, log).await;
                                    }
                                    let headers: Vec<(String, String)> = req
                                        .headers()
                                        .iter()
                                        .map(|(n, v)| (n.as_str().to_string(), String::from_utf8_lossy(v.as_bytes()).into_owned()))
                                        .collect();
                                    log.push(GroundTruth::RequestReceived {
                                        method: req.method().to_string(),
                                        path: p.to_string(),
                                        body_bytes: 0,
                                        headers,
                                    });
                                    return crate::grpc::handle_h3(req, stream, log).await;
                                }
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

type ServerStream = h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

/// RFC 9220 extended CONNECT: answer 200, then echo WebSocket messages
/// carried in the stream's DATA frames.
async fn websocket(req: http::Request<()>, mut stream: ServerStream, log: GroundTruthLog) {
    let path = req.uri().path_and_query().map(|p| p.as_str().to_string()).unwrap_or_else(|| "/".into());
    let headers: Vec<(String, String)> =
        req.headers().iter().map(|(n, v)| (n.as_str().to_string(), String::from_utf8_lossy(v.as_bytes()).into_owned())).collect();
    log.push(GroundTruth::RequestReceived { method: "CONNECT".into(), path: path.clone(), body_bytes: 0, headers });
    let is_ws = req.extensions().get::<h3::ext::Protocol>() == Some(&h3::ext::Protocol::WEBSOCKET);
    if !is_ws || req.uri().path() != "/ws" {
        log.push(GroundTruth::ResponseStarted { status: 400 });
        let resp = http::Response::builder().status(400).header("content-type", "application/json").body(()).expect("static response");
        if stream.send_response(resp).await.is_ok() {
            let _ = stream.send_data(Bytes::from_static(b"{\"error\":\"extended CONNECT requires :protocol websocket on /ws\"}")).await;
            let _ = stream.finish().await;
        }
        return;
    }
    let qs: Vec<(String, String)> = req
        .uri()
        .query()
        .unwrap_or("")
        .split('&')
        .filter_map(|kv| kv.split_once('=').map(|(k, v)| (k.to_string(), v.to_string())))
        .collect();
    let q = |k: &str| qs.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
    let close_after: Option<u32> = q("close_after").and_then(|s| s.parse().ok());
    let abnormal_after: Option<u32> = q("abnormal_after").and_then(|s| s.parse().ok());
    let max: usize = q("max").and_then(|s| s.parse().ok()).unwrap_or(1 << 20);
    let proto = req
        .headers()
        .get("sec-websocket-protocol")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string());
    let mut resp = http::Response::builder().status(200).header("x-fixture-protocol", "h3");
    if let Some(p) = &proto {
        resp = resp.header("sec-websocket-protocol", p);
    }
    log.push(GroundTruth::ResponseStarted { status: 200 });
    if stream.send_response(resp.body(()).expect("static response")).await.is_err() {
        return;
    }
    // Bridge the stream to a byte stream for the WebSocket codec.
    let (mut send, mut recv) = stream.split();
    let (app, h3_side) = tokio::io::duplex(64 * 1024);
    let (mut rd, mut wr) = tokio::io::split(h3_side);
    let uplink = tokio::spawn(async move {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            match rd.read(&mut buf).await {
                Ok(0) | Err(_) => {
                    let _ = send.finish().await;
                    break;
                }
                Ok(n) => {
                    if send.send_data(Bytes::copy_from_slice(&buf[..n])).await.is_err() {
                        break;
                    }
                }
            }
        }
    });
    tokio::spawn(async move {
        while let Ok(Some(mut chunk)) = recv.recv_data().await {
            let n = chunk.remaining();
            if wr.write_all(&chunk.copy_to_bytes(n)).await.is_err() {
                break;
            }
        }
        let _ = wr.shutdown().await;
    });
    let cfg = WebSocketConfig::default().max_message_size(Some(max)).max_frame_size(Some(max));
    let mut ws = tokio_tungstenite::WebSocketStream::from_raw_socket(app, Role::Server, Some(cfg)).await;
    let mut n = 0u32;
    while let Some(msg) = ws.next().await {
        let msg = match msg {
            Ok(m) => m,
            Err(tungstenite::Error::Capacity(_)) => {
                let _ = ws.send(Message::Close(Some(CloseFrame { code: CloseCode::Size, reason: "message too big".into() }))).await;
                break;
            }
            Err(_) => break,
        };
        match msg {
            Message::Text(_) | Message::Binary(_) => {
                log.push(GroundTruth::MessageReceived { bytes: msg.len() as u64 });
                n += 1;
                if ws.send(msg).await.is_err() {
                    break;
                }
                if abnormal_after == Some(n) {
                    log.push(GroundTruth::FaultApplied { fault: "ws_abnormal_drop".into() });
                    break; // end the stream without a Close frame
                }
                if close_after == Some(n) {
                    let _ = ws.send(Message::Close(Some(CloseFrame { code: CloseCode::Normal, reason: "fixture done".into() }))).await;
                }
            }
            Message::Close(_) => {
                let _ = ws.flush().await;
                break;
            }
            _ => {}
        }
    }
    drop(ws);
    let _ = tokio::time::timeout(std::time::Duration::from_millis(500), uplink).await;
}
