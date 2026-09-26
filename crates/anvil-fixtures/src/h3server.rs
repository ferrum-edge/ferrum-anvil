//! HTTP/3 (QUIC) fixture server built on quinn + h3.
//!
//! Routes (all bounded):
//! * `/` — 200 text
//! * `/status/{code}` — arbitrary status with a small JSON body
//! * `/echo` — JSON echo of method, path, headers and body length
//! * `CONNECT /ws` with `:protocol = websocket` (RFC 9220) — WebSocket echo
//!   with the same `close_after` / `abnormal_after` / `max` query options as
//!   the TCP fixture's `/ws` (and, with a permessage-deflate offer or `pmd`
//!   options, the same RFC 7692 peer, [`crate::ws_deflate`]); a CONNECT
//!   elsewhere or without that protocol gets 400
//! * `/anvil.lab.v1.Echo/*`, `/grpc.reflection.*` — native gRPC over HTTP/3
//!   (all four call modes, full duplex, status in HTTP/3 trailers), or
//!   gRPC-Web (binary/text) for an `application/grpc-web*` content type
//! * `/sse?count=&interval=` — server-sent events (`id: n`, `event: tick`),
//!   then a clean end of stream; `/sse-abort?…` resets the stream
//!   (`H3_INTERNAL_ERROR`) after the events; `/sse-flaky` sends `retry: 50`
//!   and events 1–2 then resets when the request has no `Last-Event-ID`, and
//!   one more event then a clean end when it has one
//! * `CONNECT …/udp/{host}/{port}/` with `:protocol = connect-udp` (RFC 9298)
//!   — a MASQUE proxy that relays to that UDP target over a connected socket.
//!   It answers `200` with `capsule-protocol: ?1`, accepts HTTP Datagrams as
//!   DATAGRAM capsules and (when [`H3Options::h3_datagrams`]) QUIC DATAGRAM
//!   frames, and answers in QUIC DATAGRAM frames only when both sides enabled
//!   `SETTINGS_H3_DATAGRAM`, otherwise in capsules. Query options:
//!   `refuse=<status>` answers that status with a JSON body;
//!   `reset_after=N` / `fin_after=N` reset (`H3_INTERNAL_ERROR`) or finish
//!   the stream after N replies; `reset_after_ms=N` / `fin_after_ms=N` do so
//!   N ms after the first client datagram arrived (independent of how many
//!   datagrams a handshake inside the tunnel took). The client only sends
//!   once it has the 2xx, so the end never overtakes the response headers,
//!   and with `N = 0` it lands during a handshake the client already began.
//!   CONNECT-UDP while
//!   [`H3Options::connect_udp`] is off gets `501`, a path that is not a
//!   template expansion `400`.
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
    /// Advertise `SETTINGS_ENABLE_CONNECT_PROTOCOL` (RFC 9220 WebSocket, RFC 9298 CONNECT-UDP).
    pub extended_connect: bool,
    /// Serve RFC 9298 CONNECT-UDP (otherwise such requests get `501`).
    pub connect_udp: bool,
    /// Advertise `SETTINGS_H3_DATAGRAM` and use QUIC DATAGRAM frames for
    /// CONNECT-UDP replies when the client advertised it too.
    pub h3_datagrams: bool,
}

impl Default for H3Options {
    fn default() -> Self {
        H3Options { extended_connect: true, connect_udp: true, h3_datagrams: false }
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
                let router = DatagramRouter::default();
                tokio::spawn(route_datagrams(conn.clone(), router.clone()));
                let quic = conn.clone();
                let built = h3::server::builder()
                    .enable_extended_connect(options.extended_connect)
                    .enable_datagram(options.h3_datagrams)
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
                            let (quic, router) = (quic.clone(), router.clone());
                            tokio::spawn(async move {
                                let Ok((req, mut stream)) = resolver.resolve_request().await else { return };
                                if req.method() == http::Method::CONNECT {
                                    if req.extensions().get::<h3::ext::Protocol>() == Some(&h3::ext::Protocol::CONNECT_UDP) {
                                        return connect_udp(req, stream, log, options, quic, router).await;
                                    }
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
                                if let [route @ ("sse" | "sse-abort" | "sse-flaky")] = segs.as_slice() {
                                    return sse(route, &req, stream, log).await;
                                }
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
    let offer: Option<String> = {
        let v: Vec<&str> = req.headers().get_all("sec-websocket-extensions").iter().filter_map(|v| v.to_str().ok()).collect();
        (!v.is_empty()).then(|| v.join(", "))
    };
    let mode = crate::ws_deflate::Mode::parse(req.uri().query());
    let deflate = mode.applies(offer.as_deref()).then(|| crate::ws_deflate::negotiate(offer.as_deref(), &mode, &log));
    let mut resp = http::Response::builder().status(200).header("x-fixture-protocol", "h3");
    if let Some(p) = &proto {
        resp = resp.header("sec-websocket-protocol", p);
    }
    if let Some(answer) = deflate.as_ref().and_then(|s| s.answer.as_deref()) {
        resp = resp.header("sec-websocket-extensions", answer);
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
    if let Some(session) = deflate {
        crate::ws_deflate::serve(app, session, log).await;
        let _ = tokio::time::timeout(std::time::Duration::from_millis(500), uplink).await;
        return;
    }
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

// ------------------------------------------------------------------- SSE ---

fn query(req: &http::Request<()>) -> Vec<(String, String)> {
    req.uri().query().unwrap_or("").split('&').filter_map(|kv| kv.split_once('=').map(|(k, v)| (k.to_string(), v.to_string()))).collect()
}

fn query_u64(qs: &[(String, String)], k: &str) -> Option<u64> {
    qs.iter().find(|(n, _)| n == k).and_then(|(_, v)| v.parse().ok())
}

/// Server-sent events over an HTTP/3 request stream.
async fn sse(route: &str, req: &http::Request<()>, mut stream: ServerStream, log: GroundTruthLog) {
    let qs = query(req);
    let count = query_u64(&qs, "count").unwrap_or(3).min(10_000);
    let interval = std::time::Duration::from_millis(query_u64(&qs, "interval").unwrap_or(30).min(60_000));
    let last_id: Option<u64> = req.headers().get("last-event-id").and_then(|v| v.to_str().ok()).and_then(|s| s.trim().parse().ok());
    log.push(GroundTruth::ResponseStarted { status: 200 });
    let resp = http::Response::builder()
        .status(200)
        .header("content-type", "text/event-stream")
        .header("cache-control", "no-cache")
        .header("x-fixture-protocol", "h3")
        .body(())
        .expect("static response");
    if stream.send_response(resp).await.is_err() {
        return;
    }
    let event = |i: u64| Bytes::from(format!("id: {i}\nevent: tick\ndata: {{\"n\":{i}}}\n\n"));
    match (route, last_id) {
        ("sse-flaky", None) => {
            let _ = stream.send_data(Bytes::from_static(b"retry: 50\n")).await;
            for i in 1..=2 {
                if stream.send_data(event(i)).await.is_err() {
                    return;
                }
                tokio::time::sleep(interval).await;
            }
            log.push(GroundTruth::FaultApplied { fault: "sse_flaky_reset".into() });
            stream.stop_stream(h3::error::Code::H3_INTERNAL_ERROR);
        }
        ("sse-flaky", Some(last)) => {
            let _ = stream.send_data(event(last + 1)).await;
            let _ = stream.finish().await;
        }
        _ => {
            for i in 0..count {
                if stream.send_data(event(i)).await.is_err() {
                    return;
                }
                tokio::time::sleep(interval).await;
            }
            if route == "sse-abort" {
                log.push(GroundTruth::FaultApplied { fault: "sse_abort_mid_stream".into() });
                stream.stop_stream(h3::error::Code::H3_INTERNAL_ERROR);
            } else {
                let _ = stream.finish().await;
            }
        }
    }
}

// ------------------------------------------------------------ CONNECT-UDP ---

/// QUIC DATAGRAM frames of one connection, routed by quarter stream ID to
/// the CONNECT-UDP stream they belong to (RFC 9297 §2.1).
#[derive(Clone, Default)]
struct DatagramRouter(Arc<parking_lot::Mutex<std::collections::HashMap<u64, tokio::sync::mpsc::Sender<Bytes>>>>);

fn put_varint(out: &mut Vec<u8>, v: u64) {
    if v < 1 << 6 {
        out.push(v as u8);
    } else if v < 1 << 14 {
        out.extend_from_slice(&(0x4000 | v as u16).to_be_bytes());
    } else if v < 1 << 30 {
        out.extend_from_slice(&(0x8000_0000 | v as u32).to_be_bytes());
    } else {
        out.extend_from_slice(&(0xc000_0000_0000_0000 | v).to_be_bytes());
    }
}

fn read_varint(buf: &[u8], pos: &mut usize) -> Option<u64> {
    let first = *buf.get(*pos)?;
    let len = 1usize << (first >> 6);
    if buf.len() - *pos < len {
        return None;
    }
    let mut v = u64::from(first & 0x3f);
    for i in 1..len {
        v = (v << 8) | u64::from(buf[*pos + i]);
    }
    *pos += len;
    Some(v)
}

async fn route_datagrams(conn: quinn::Connection, router: DatagramRouter) {
    while let Ok(d) = conn.read_datagram().await {
        let mut pos = 0;
        let Some(q) = read_varint(&d, &mut pos) else { continue };
        let tx = router.0.lock().get(&q).cloned();
        if let Some(tx) = tx {
            let _ = tx.try_send(d.slice(pos..));
        }
    }
}

/// `…/udp/{target_host}/{target_port}/` with percent-decoding of the host.
fn connect_udp_target(path: &str) -> Option<(String, u16)> {
    let segs: Vec<&str> = path.split('/').collect();
    if !path.ends_with('/') || segs.len() < 4 || segs[segs.len() - 4] != "udp" {
        return None;
    }
    let raw = segs[segs.len() - 3];
    let mut host = Vec::with_capacity(raw.len());
    let b = raw.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            host.push(u8::from_str_radix(std::str::from_utf8(&b[i + 1..i + 3]).ok()?, 16).ok()?);
            i += 3;
        } else {
            host.push(b[i]);
            i += 1;
        }
    }
    let port: u16 = segs[segs.len() - 2].parse().ok().filter(|p| *p > 0)?;
    Some((String::from_utf8(host).ok()?, port))
}

async fn reply_json(stream: &mut ServerStream, log: &GroundTruthLog, status: u16, body: String) {
    log.push(GroundTruth::ResponseStarted { status });
    let resp = http::Response::builder().status(status).header("content-type", "application/json").body(()).expect("static response");
    if stream.send_response(resp).await.is_ok() {
        let _ = stream.send_data(Bytes::from(body)).await;
        let _ = stream.finish().await;
    }
}

/// RFC 9298 CONNECT-UDP: relay HTTP Datagrams to and from the UDP target.
async fn connect_udp(
    req: http::Request<()>,
    mut stream: ServerStream,
    log: GroundTruthLog,
    options: H3Options,
    quic: quinn::Connection,
    router: DatagramRouter,
) {
    use h3::ConnectionState;
    let path = req.uri().path_and_query().map(|p| p.as_str().to_string()).unwrap_or_else(|| "/".into());
    let headers: Vec<(String, String)> =
        req.headers().iter().map(|(n, v)| (n.as_str().to_string(), String::from_utf8_lossy(v.as_bytes()).into_owned())).collect();
    log.push(GroundTruth::RequestReceived { method: "CONNECT".into(), path: path.clone(), body_bytes: 0, headers });
    if !options.connect_udp {
        return reply_json(&mut stream, &log, 501, r#"{"error":"CONNECT-UDP is disabled on this fixture"}"#.into()).await;
    }
    let qs = query(&req);
    if let Some(code) = query_u64(&qs, "refuse") {
        let body = format!(r#"{{"error":"the fixture refused this CONNECT-UDP request","status":{code}}}"#);
        return reply_json(&mut stream, &log, code as u16, body).await;
    }
    let Some((host, port)) = connect_udp_target(req.uri().path()) else {
        return reply_json(&mut stream, &log, 400, r#"{"error":"path does not expand the connect-udp URI template"}"#.into()).await;
    };
    let addr = match tokio::net::lookup_host((host.as_str(), port)).await.ok().and_then(|mut a| a.next()) {
        Some(a) => a,
        None => return reply_json(&mut stream, &log, 502, r#"{"error":"CONNECT-UDP target could not be resolved"}"#.into()).await,
    };
    let bind: SocketAddr = if addr.is_ipv6() { "[::]:0".parse().expect("v6") } else { "0.0.0.0:0".parse().expect("v4") };
    let sock = match tokio::net::UdpSocket::bind(bind).await {
        Ok(s) if s.connect(addr).await.is_ok() => s,
        _ => return reply_json(&mut stream, &log, 502, r#"{"error":"CONNECT-UDP tunnel socket could not be created"}"#.into()).await,
    };
    let client_datagrams = matches!(stream.settings(), std::borrow::Cow::Borrowed(s) if s.enable_datagram());
    let quic_replies = options.h3_datagrams && client_datagrams && quic.max_datagram_size().is_some();
    log.push(GroundTruth::ResponseStarted { status: 200 });
    let resp = http::Response::builder().status(200).header("capsule-protocol", "?1").body(()).expect("static response");
    if stream.send_response(resp).await.is_err() {
        return;
    }
    let reset_after = query_u64(&qs, "reset_after");
    let fin_after = query_u64(&qs, "fin_after");
    let timed_end = match (query_u64(&qs, "reset_after_ms"), query_u64(&qs, "fin_after_ms")) {
        (Some(ms), _) => Some((std::time::Duration::from_millis(ms), true)),
        (None, Some(ms)) => Some((std::time::Duration::from_millis(ms), false)),
        (None, None) => None,
    };
    // Armed by the first client datagram: a reset abandons unsent stream data,
    // so one timed from the 2xx could reach the client before the headers did.
    let mut end_at: Option<tokio::time::Instant> = None;
    let arm = |end_at: &mut Option<tokio::time::Instant>| {
        if end_at.is_none() {
            *end_at = timed_end.map(|(after, _)| tokio::time::Instant::now() + after);
        }
    };
    let quarter = stream.id().into_inner() / 4;
    let (tx_dgram, mut rx_dgram) = tokio::sync::mpsc::channel::<Bytes>(64);
    router.0.lock().insert(quarter, tx_dgram);
    let (mut send, mut recv) = stream.split();
    let mut pending: Vec<u8> = Vec::new();
    let mut buf = vec![0u8; 65_536];
    let mut replies = 0u64;
    let mut ended = false;
    // Client → target: one Context ID 0 payload.
    let relay = |ctx_and_payload: &[u8], via: &str| -> Option<Vec<u8>> {
        let mut pos = 0;
        let ctx = read_varint(ctx_and_payload, &mut pos)?;
        if ctx != 0 {
            return None;
        }
        log.push(GroundTruth::DatagramRelayed { bytes: (ctx_and_payload.len() - pos) as u64, via: via.into() });
        Some(ctx_and_payload[pos..].to_vec())
    };
    loop {
        tokio::select! {
            // A due end goes first, so a zero delay ends the tunnel before any
            // reply to the first datagram can come back through it.
            biased;
            _ = tokio::time::sleep_until(end_at.unwrap_or_else(tokio::time::Instant::now)), if end_at.is_some() => {
                if timed_end.map(|t| t.1).unwrap_or(false) {
                    log.push(GroundTruth::FaultApplied { fault: "masque_reset".into() });
                    send.stop_stream(h3::error::Code::H3_INTERNAL_ERROR);
                } else {
                    log.push(GroundTruth::FaultApplied { fault: "masque_fin".into() });
                    let _ = send.finish().await;
                }
                ended = true;
                break;
            }
            c = recv.recv_data() => match c {
                Ok(Some(mut chunk)) => {
                    let n = chunk.remaining();
                    pending.extend_from_slice(&chunk.copy_to_bytes(n));
                    loop {
                        let mut pos = 0;
                        let (Some(ty), Some(len)) = (read_varint(&pending, &mut pos), read_varint(&pending, &mut pos)) else { break };
                        let len = len as usize;
                        if pending.len() - pos < len {
                            break;
                        }
                        let value: Vec<u8> = pending[pos..pos + len].to_vec();
                        pending.drain(..pos + len);
                        if ty == 0
                            && let Some(p) = relay(&value, "capsule")
                        {
                            let _ = sock.send(&p).await;
                            arm(&mut end_at);
                        }
                    }
                }
                _ => break,
            },
            Some(d) = rx_dgram.recv() => {
                if let Some(p) = relay(&d, "quic_datagram") {
                    let _ = sock.send(&p).await;
                    arm(&mut end_at);
                }
            }
            r = sock.recv(&mut buf) => {
                let Ok(n) = r else { break };
                let sent = if quic_replies {
                    let mut out = Vec::with_capacity(n + 9);
                    put_varint(&mut out, quarter);
                    put_varint(&mut out, 0);
                    out.extend_from_slice(&buf[..n]);
                    quic.send_datagram(Bytes::from(out)).is_ok()
                } else {
                    let mut out = Vec::with_capacity(n + 10);
                    put_varint(&mut out, 0);
                    put_varint(&mut out, n as u64 + 1);
                    put_varint(&mut out, 0);
                    out.extend_from_slice(&buf[..n]);
                    send.send_data(Bytes::from(out)).await.is_ok()
                };
                if !sent {
                    break;
                }
                replies += 1;
                if reset_after == Some(replies) {
                    // Let the reply leave before the reset abandons unsent stream data.
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    log.push(GroundTruth::FaultApplied { fault: "masque_reset".into() });
                    send.stop_stream(h3::error::Code::H3_INTERNAL_ERROR);
                    ended = true;
                    break;
                }
                if fin_after == Some(replies) {
                    log.push(GroundTruth::FaultApplied { fault: "masque_fin".into() });
                    let _ = send.finish().await;
                    ended = true;
                    break;
                }
            }
        }
    }
    router.0.lock().remove(&quarter);
    if !ended {
        let _ = tokio::time::timeout(std::time::Duration::from_millis(200), send.finish()).await;
    }
}
