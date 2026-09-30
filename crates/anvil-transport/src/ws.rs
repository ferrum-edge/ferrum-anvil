//! WebSocket sessions (RFC 6455) over the instrumented connector.
//!
//! Bootstraps are separate, individually tested features:
//! * **HTTP/1.1 Upgrade** (RFC 6455 §4): `GET` with `Upgrade: websocket`; the
//!   `101` response's `Upgrade`, `Connection` and `Sec-WebSocket-Accept` are
//!   verified before the session starts.
//! * **HTTP/2 extended CONNECT** (RFC 8441): the client waits for the peer's
//!   `SETTINGS_ENABLE_CONNECT_PROTOCOL`, then sends `CONNECT` with
//!   `:protocol = websocket`; a `200` opens the tunnel stream.
//! * **HTTP/3 extended CONNECT** (RFC 9220): over a fresh QUIC connection the
//!   client waits for the server's `SETTINGS_ENABLE_CONNECT_PROTOCOL`, then
//!   sends `CONNECT` with `:protocol = websocket`; a `200` opens the stream,
//!   whose DATA frames carry the WebSocket bytes. `h3` 0.0.8 cannot express
//!   `:protocol = websocket`, so the workspace patches in the upstream
//!   `Protocol::WEBSOCKET` commit (`vendor/README.md`). HTTP/3 needs `wss://`
//!   and no proxy; there is never a silent fallback to another bootstrap.
//!
//! Session evidence: every message (bounded, redacted), ping/pong, the close
//! code/reason and who closed. A connection that ends without a Close frame
//! is reported as 1006 with `closed_by = abnormal` — 1006 is a local
//! designation, never a code the peer transmitted.
//!
//! RFC 7692 `permessage-deflate` is offered only when the request enables it
//! ([`crate::ws_deflate`]). The same negotiation runs for every bootstrap:
//! an answer that does not fit the offer, or names an extension that was not
//! offered, fails the handshake with a typed reason. The codec runs inside
//! the (vendored) tungstenite; previews show the decompressed payload, and
//! `max_message_bytes` limits the decompressed size.

use crate::connector::{ProxyPlan, Target};
use crate::dns::DnsConfig;
use crate::errors::{HyperStage, classify_hyper};
use crate::http::sleep_until_opt;
use crate::recorder::{EventCtx, Recorder};
use crate::session::*;
use crate::tls::PreparedTls;
use crate::ws_deflate::{self, DeflateOffer, FrameMeter, Metered};
use anvil_domain::events::{ExecutionEvent, SessionCommand};
use anvil_domain::execution::*;
use anvil_domain::outcome::{
    ClosedBy, ProtocolStatus, WsCompressionTraffic, WsCompressionViolation, WsExtensions, WsNegotiation, WsViolationKind,
};
use anvil_domain::request::{WsBootstrap, WsMessage};
use anvil_domain::settings::{Limits, Timeouts};
use bytes::{Buf, Bytes, BytesMut};
use futures::{SinkExt, StreamExt};
use http::{HeaderMap, HeaderName, HeaderValue, Method, Request};
use http_body_util::{BodyExt, Empty};
use hyper_util::rt::TokioIo;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::{CloseFrame, DeflateConfig, Role, WebSocketConfig};
use tokio_tungstenite::tungstenite::{self, Message};
use tokio_util::sync::CancellationToken;

/// Fully prepared WebSocket session (auth already applied to `headers`).
#[derive(Clone)]
pub struct WsPlan {
    pub bootstrap: WsBootstrap,
    /// `wss://` (TLS) vs `ws://`.
    pub secure: bool,
    pub host: String,
    pub port: u16,
    /// The HTTP/1.1 `Host` default, or the `:authority` over HTTP/2 and
    /// HTTP/3: the request's explicit `Host` when it has one (what auth signed).
    pub authority: String,
    /// Origin-form target (`/path?query`).
    pub request_target: String,
    pub headers: Vec<(HeaderName, HeaderValue)>,
    pub subprotocols: Vec<String>,
    /// The RFC 7692 `permessage-deflate` offer (`None`: not offered).
    pub deflate: Option<DeflateOffer>,
    /// Messages sent right after the session opens.
    pub script: Vec<WsMessage>,
    /// Automation: close after this many inbound data messages (0 = idle-driven).
    pub expect_messages: u32,
    /// Automation: close after this much inbound silence.
    pub idle_close_ms: u64,
    /// Inbound message/frame ceiling (local policy).
    pub max_message_bytes: u64,
    pub timeouts: Timeouts,
    pub limits: Limits,
    pub dns: DnsConfig,
    pub proxy: Option<ProxyPlan>,
    pub tls: Option<Arc<PreparedTls>>,
    /// Redacted URL for evidence.
    pub display_url: String,
    pub transcript: TranscriptLimits,
    pub redact: Option<RedactFn>,
    /// PROXY protocol header written at the head of each new TCP connection,
    /// before TLS (TCP legs only; HTTP/3 is refused before traffic).
    pub proxy_header: Option<crate::proxy_protocol::ConnectionHeader>,
}

async fn next_cmd(rx: &mut Option<CommandRx>) -> Option<SessionCommand> {
    match rx {
        Some(r) => r.recv().await,
        None => std::future::pending().await,
    }
}

struct Close {
    code: Option<u16>,
    reason: String,
    closed_by: ClosedBy,
}

/// How long a Close frame the client sends on its way out (cancel, total
/// deadline) may take to be written.
const FINAL_CLOSE_WRITE: Duration = Duration::from_millis(250);

/// Why a pending write ended the session.
enum WriteStop {
    /// The session was canceled, or its total deadline passed, while a write
    /// was pending (the peer was not reading).
    Interrupted(Interrupted),
    /// A Close frame was not written within the close wait.
    CloseStalled { code: u16, reason: String },
}

/// How a guarded send ended.
enum Wrote {
    Done,
    Failed(tungstenite::Error),
    Stopped(WriteStop),
}

/// Send one message (write and flush), raced against cancellation and
/// `deadline` ([`guarded`]).
async fn send_guarded<S: AsyncRead + AsyncWrite + Unpin>(
    ws: &mut WebSocketStream<S>,
    msg: Message,
    cancel: &CancellationToken,
    deadline: Option<Instant>,
) -> Wrote {
    match guarded(ws.send(msg), cancel, deadline).await {
        Ok(Ok(())) => Wrote::Done,
        Ok(Err(e)) => Wrote::Failed(e),
        Err(i) => Wrote::Stopped(WriteStop::Interrupted(i)),
    }
}

/// Send a Close frame within `wait` (and the total deadline): a graceful
/// close must not wait on a peer that is not reading.
async fn send_close_guarded<S: AsyncRead + AsyncWrite + Unpin>(
    ws: &mut WebSocketStream<S>,
    code: u16,
    reason: &str,
    cancel: &CancellationToken,
    total_deadline: Option<Instant>,
    wait: Duration,
) -> Wrote {
    let bound = Instant::now() + wait;
    match send_guarded(ws, close_frame(code, reason), cancel, earliest(total_deadline, Some(bound))).await {
        Wrote::Stopped(WriteStop::Interrupted(Interrupted::Deadline)) if total_deadline.is_none_or(|d| bound < d) => {
            Wrote::Stopped(WriteStop::CloseStalled { code, reason: reason.to_string() })
        }
        w => w,
    }
}

/// Wait up to `ms` for the peer's `SETTINGS_ENABLE_CONNECT_PROTOCOL`.
async fn await_extended_connect(
    flag: Option<tokio::sync::watch::Receiver<bool>>,
    ms: u64,
    cancel: &CancellationToken,
) -> Result<(), &'static str> {
    let Some(mut rx) = flag else { return Err("timeout") };
    tokio::select! {
        r = tokio::time::timeout(Duration::from_millis(ms), rx.wait_for(|v| *v)) => match r {
            Ok(Ok(_)) => Ok(()),
            _ => Err("timeout"),
        },
        _ = cancel.cancelled() => Err("canceled"),
    }
}

fn build_request(plan: &WsPlan, h2: bool, key: &str) -> Result<Request<Empty<Bytes>>, String> {
    let mut headers = HeaderMap::new();
    for (n, v) in &plan.headers {
        if h2
            && (n == http::header::HOST
                || n == http::header::CONNECTION
                || n == http::header::UPGRADE
                || n == http::header::TRANSFER_ENCODING
                || n.as_str() == "keep-alive"
                || n.as_str() == "sec-websocket-key")
        {
            continue; // connection-specific / H1-only fields are illegal in HTTP/2
        }
        headers.append(n.clone(), v.clone());
    }
    let mut set_default = |name: &str, value: &str| -> Result<(), String> {
        let n = HeaderName::from_bytes(name.as_bytes()).map_err(|e| e.to_string())?;
        if !headers.contains_key(&n) {
            headers.insert(n, HeaderValue::from_str(value).map_err(|e| e.to_string())?);
        }
        Ok(())
    };
    set_default("sec-websocket-version", "13")?;
    if !plan.subprotocols.is_empty() {
        set_default("sec-websocket-protocol", &plan.subprotocols.join(", "))?;
    }
    if let Some(d) = &plan.deflate {
        set_default("sec-websocket-extensions", &d.header_value())?;
    }
    let mut req = if h2 {
        set_default("user-agent", concat!("Ferrum-Anvil/", env!("CARGO_PKG_VERSION")))?;
        let uri = format!("{}://{}{}", if plan.secure { "https" } else { "http" }, plan.authority, plan.request_target);
        let mut r = Request::builder().method(Method::CONNECT).uri(uri).body(Empty::new()).map_err(|e| e.to_string())?;
        r.extensions_mut().insert(hyper::ext::Protocol::from_static("websocket"));
        r
    } else {
        set_default("host", &plan.authority)?;
        set_default("connection", "Upgrade")?;
        set_default("upgrade", "websocket")?;
        set_default("sec-websocket-key", key)?;
        Request::builder().method(Method::GET).uri(plan.request_target.as_str()).body(Empty::new()).map_err(|e| e.to_string())?
    };
    *req.headers_mut() = headers;
    Ok(req)
}

/// Validate an RFC 6455 `101` response (H1 bootstrap only).
fn validate_upgrade(resp_headers: &HeaderMap, key: &str) -> Result<(), String> {
    let has = |name: &str, token: &str| {
        resp_headers
            .get_all(name)
            .iter()
            .any(|v| v.to_str().map(|s| s.split(',').any(|t| t.trim().eq_ignore_ascii_case(token))).unwrap_or(false))
    };
    if !has("upgrade", "websocket") {
        return Err("the 101 response has no 'Upgrade: websocket' header".into());
    }
    if !has("connection", "upgrade") {
        return Err("the 101 response has no 'Connection: Upgrade' header".into());
    }
    let expected = tungstenite::handshake::derive_accept_key(key.as_bytes());
    match resp_headers.get("sec-websocket-accept").and_then(|v| v.to_str().ok()) {
        Some(a) if a.trim() == expected => Ok(()),
        Some(_) => Err("Sec-WebSocket-Accept does not match the key that was sent".into()),
        None => Err("the 101 response has no Sec-WebSocket-Accept header".into()),
    }
}

fn close_frame(code: u16, reason: &str) -> Message {
    Message::Close(Some(CloseFrame { code: CloseCode::from(code), reason: reason.to_string().into() }))
}

/// Check the server's `Sec-WebSocket-Protocol` choice against the offer.
fn negotiate_subprotocol(plan: &WsPlan, headers: &HeaderMap, facts: &mut SessionFacts) -> Result<(), String> {
    if let Some(p) = headers.get("sec-websocket-protocol").and_then(|v| v.to_str().ok()).map(|s| s.trim().to_string()) {
        if !plan.subprotocols.iter().any(|s| s.eq_ignore_ascii_case(&p)) {
            return Err(format!("the server selected subprotocol '{p}', which was not offered"));
        }
        facts.notes.push(format!("subprotocol negotiated: {p}"));
        facts.subprotocol = Some(p);
    } else if !plan.subprotocols.is_empty() {
        facts.notes.push(format!("subprotocols offered ({}) but the server selected none", plan.subprotocols.join(", ")));
    }
    Ok(())
}

/// What was offered: Anvil's permessage-deflate, or a user-supplied header.
fn offer_name(plan: &WsPlan) -> &'static str {
    if plan.deflate.is_some() { "permessage-deflate" } else { "a Sec-WebSocket-Extensions header" }
}

/// Every `Sec-WebSocket-Extensions` value in `h`, in order.
fn extension_values(h: &HeaderMap) -> Vec<String> {
    h.get_all("sec-websocket-extensions").iter().map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned()).collect()
}

/// Check the server's `Sec-WebSocket-Extensions` answer against what the
/// request offered (RFC 6455 §4.1, RFC 7692 §7). Returns the evidence
/// (`None` when nothing was offered or answered) and the codec to run, or
/// the reason the answer is refused.
fn negotiate_extensions(
    plan: &WsPlan,
    offered: &[String],
    resp: &HeaderMap,
    facts: &mut SessionFacts,
) -> (Option<WsExtensions>, Result<Option<DeflateConfig>, String>) {
    let answered = extension_values(resp);
    if offered.is_empty() && answered.is_empty() {
        return (None, Ok(None));
    }
    let redact = |s: String| match &plan.redact {
        Some(r) => r(&s),
        None => s,
    };
    let bounded = |s: String| {
        if s.len() <= 512 {
            return s;
        }
        let mut end = 512;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}…", &s[..end])
    };
    let mut ext = WsExtensions {
        offered: (!offered.is_empty()).then(|| redact(offered.join(", "))),
        answered: (!answered.is_empty()).then(|| redact(bounded(answered.join(", ")))),
        negotiation: WsNegotiation::NotOffered,
        problem: None,
        deflate: None,
        traffic: None,
        violation: None,
    };
    let answer: Vec<&str> = answered.iter().map(String::as_str).collect();
    // A user-supplied header with the toggle off: Anvil sent it, but runs no codec for it.
    let raw_offer = plan.deflate.is_none() && !offered.is_empty();
    match ws_deflate::negotiate(plan.deflate.as_ref(), &answer, raw_offer) {
        Ok(Some(a)) => {
            facts.notes.push(ws_deflate::describe(&a.params));
            ext.negotiation = WsNegotiation::Negotiated;
            ext.deflate = Some(a.params);
            (Some(ext), Ok(Some(a.codec)))
        }
        Ok(None) => {
            facts.notes.push(format!(
                "{} offered but not negotiated: the answer named no extension, so the session is uncompressed",
                offer_name(plan)
            ));
            ext.negotiation = WsNegotiation::NotNegotiated;
            (Some(ext), Ok(None))
        }
        Err(e) => {
            let e = redact(e);
            ext.negotiation = WsNegotiation::Rejected;
            ext.problem = Some(e.clone());
            (Some(ext), Err(e))
        }
    }
}

/// Wait up to `ms` for the HTTP/3 peer's SETTINGS. `Ok(enabled)` says whether
/// they enable extended CONNECT (`SETTINGS_ENABLE_CONNECT_PROTOCOL`, RFC 9220 §3).
async fn await_h3_settings(send: &crate::h3::SendReq, ms: u64, cancel: &CancellationToken) -> Result<bool, &'static str> {
    use h3::ConnectionState;
    let deadline = Instant::now() + Duration::from_millis(ms);
    loop {
        // Borrowed once the peer's SETTINGS frame has arrived; before that h3
        // hands out RFC 9114 defaults, which say nothing about the peer.
        if let std::borrow::Cow::Borrowed(s) = send.settings() {
            return Ok(s.enable_extended_connect());
        }
        if Instant::now() >= deadline {
            return Err("timeout");
        }
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(5)) => {}
            _ = cancel.cancelled() => return Err("canceled"),
        }
    }
}

/// Bridge an accepted RFC 9220 stream to a byte stream the WebSocket codec
/// can drive: DATA frame payloads are the WebSocket bytes. Counts those bytes
/// in `stats`, and keeps the h3 stream error, if the stream fails, as evidence.
fn bridge_h3_stream<T>(
    stream: h3::client::RequestStream<T, Bytes>,
    stats: Arc<crate::stats::ConnStats>,
    stream_error: Arc<parking_lot::Mutex<Option<String>>>,
    abort: CancellationToken,
) -> (tokio::io::DuplexStream, tokio::task::JoinHandle<()>)
where
    T: h3::quic::BidiStream<Bytes> + Send + 'static,
    T::SendStream: Send + 'static,
    T::RecvStream: Send + 'static,
{
    let (mut send, mut recv) = stream.split();
    let (app, h3_side) = tokio::io::duplex(64 * 1024);
    let (mut rd, mut wr) = tokio::io::split(h3_side);
    let up_stats = stats.clone();
    // `abort` (an interrupted write) resets the send side instead of
    // finishing it, even while a send waits for flow-control credit.
    let up = tokio::spawn(async move {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            let read = tokio::select! {
                biased;
                _ = abort.cancelled() => None,
                r = rd.read(&mut buf) => Some(r),
            };
            let n = match read {
                Some(Ok(0) | Err(_)) if !abort.is_cancelled() => {
                    let _ = send.finish().await;
                    break;
                }
                Some(Ok(n)) if n > 0 && !abort.is_cancelled() => n,
                _ => {
                    send.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
                    break;
                }
            };
            let sent = tokio::select! {
                biased;
                _ = abort.cancelled() => None,
                r = send.send_data(Bytes::copy_from_slice(&buf[..n])) => Some(r),
            };
            match sent {
                Some(Ok(())) => up_stats.record_write(n),
                Some(Err(_)) => break,
                None => {
                    send.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
                    break;
                }
            }
        }
    });
    tokio::spawn(async move {
        loop {
            match recv.recv_data().await {
                Ok(Some(mut chunk)) => {
                    let n = chunk.remaining();
                    let data = chunk.copy_to_bytes(n);
                    stats.record_read(n);
                    if wr.write_all(&data).await.is_err() {
                        break;
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    *stream_error.lock() = Some(e.to_string());
                    break;
                }
            }
        }
        let _ = wr.shutdown().await;
    });
    (app, up)
}

/// RFC 9220: WebSocket over an HTTP/3 extended CONNECT stream on a fresh
/// QUIC connection. The QUIC and TLS evidence is the same as for HTTP/3
/// requests (there is no TCP phase).
async fn run_h3(plan: &WsPlan, events: &EventCtx, cancel: &CancellationToken, commands: Option<CommandRx>) -> SessionOutput {
    let interactive = commands.is_some();
    let mut rec = Recorder::new(0, events.clone());
    events.emit(ExecutionEvent::AttemptStarted { execution_id: events.execution_id, attempt: 0 });
    let mut obs = new_attempt(0, AttemptReason::Initial, "CONNECT", &plan.display_url);
    let mut facts = SessionFacts::default();
    let early = |rec: Recorder, obs: AttemptObservation, f: TransportFailure, dispatch: DispatchState, facts: SessionFacts| {
        SessionOutput::single(fail_attempt(rec, obs, f, dispatch, events), None, ProtocolStatus::None, facts)
    };
    if !plan.secure {
        let f = TransportFailure::new(
            Phase::Prepare,
            FailureKind::UnsupportedCombination,
            "WebSocket over HTTP/3 needs TLS (QUIC is always encrypted): use a wss:// URL, or the HTTP/1.1 or HTTP/2 bootstrap for ws://",
        )
        .with_field("websocket.bootstrap");
        return early(rec, obs, f, DispatchState::NotDispatched, facts);
    }
    if plan.proxy.is_some() {
        let f = TransportFailure::new(
            Phase::Prepare,
            FailureKind::UnsupportedCombination,
            "WebSocket over HTTP/3 cannot be sent through the configured HTTP/SOCKS proxy",
        )
        .with_field("settings.proxy");
        return early(rec, obs, f, DispatchState::NotDispatched, facts);
    }
    let Some(tls) = plan.tls.clone() else {
        let f = TransportFailure::new(Phase::Prepare, FailureKind::TlsProfileInvalid, "no TLS configuration for a wss:// session");
        return early(rec, obs, f, DispatchState::NotDispatched, facts);
    };
    let total_deadline = if interactive { None } else { deadline_from(plan.timeouts.total_ms) };

    // ---- QUIC + HTTP/3 connection ----
    let connected = match crate::h3::quic_connect(
        &mut rec,
        &plan.host,
        plan.port,
        &plan.dns,
        &plan.timeouts,
        &plan.limits,
        &tls,
        crate::h3::client_endpoint,
        cancel,
    )
    .await
    {
        Ok(c) => c,
        Err((f, cobs)) => {
            obs.connection = cobs;
            return early(rec, obs, f, DispatchState::NotDispatched, facts);
        }
    };
    let crate::h3::QuicConnected { quic, mut send, observation: cobs } = connected;
    obs.connection = Some(cobs);
    let close_quic = |quic: &quinn::Connection| quic.close(0x100u32.into(), b""); // H3_NO_ERROR
    let wait_ms = plan.timeouts.response_headers_ms.unwrap_or(5_000).min(5_000);
    match await_h3_settings(&send, wait_ms, cancel).await {
        Ok(true) => rec.mark(Phase::ProtocolHandshake, PhaseStatus::Completed, Some("peer enabled extended CONNECT (RFC 9220)")),
        other => {
            let f = match other {
                Err("canceled") => {
                    TransportFailure::new(Phase::ProtocolHandshake, FailureKind::Canceled, "canceled while waiting for HTTP/3 settings")
                }
                Ok(_) => TransportFailure::new(
                    Phase::ProtocolHandshake,
                    FailureKind::WsHandshakeRejected,
                    "the HTTP/3 server's SETTINGS do not enable extended CONNECT (SETTINGS_ENABLE_CONNECT_PROTOCOL), so the RFC 9220 WebSocket bootstrap is unavailable on this connection; nothing was sent",
                ),
                Err(_) => {
                    let mut f = TransportFailure::new(
                        Phase::ProtocolHandshake,
                        FailureKind::WsHandshakeRejected,
                        format!(
                            "the HTTP/3 server sent no SETTINGS within {wait_ms} ms, so it is unknown whether it allows extended CONNECT (RFC 9220); nothing was sent"
                        ),
                    );
                    f.deadline_ms = Some(wait_ms);
                    f
                }
            };
            close_quic(&quic);
            return early(rec, obs, f, DispatchState::NotDispatched, facts);
        }
    }

    // ---- extended CONNECT ----
    let req = match build_request(plan, true, "") {
        Ok(r) => {
            let (mut parts, _) = r.into_parts();
            parts.extensions.remove::<hyper::ext::Protocol>();
            parts.extensions.insert(h3::ext::Protocol::WEBSOCKET);
            Request::from_parts(parts, ())
        }
        Err(e) => {
            close_quic(&quic);
            let f =
                TransportFailure::new(Phase::Prepare, FailureKind::InvalidHeader, format!("the WebSocket request could not be built: {e}"));
            return early(rec, obs, f, DispatchState::NotDispatched, facts);
        }
    };
    let req_headers = header_entries(req.headers());
    let offered = extension_values(req.headers());
    obs.bytes.request_headers_logical = logical_header_bytes(&req_headers) + plan.request_target.len() as u64 + 16;
    obs.bytes.request_headers_estimated = true;
    let w_idx = rec.start(Phase::RequestWrite);
    let sent = tokio::select! {
        r = send.send_request(req) => r.map_err(|e| TransportFailure::new(Phase::RequestWrite, FailureKind::RequestWriteFailed,
            format!("sending the HTTP/3 extended CONNECT failed: {e}"))),
        _ = sleep_until_opt(total_deadline) => Err(TransportFailure::new(Phase::RequestWrite, FailureKind::TotalTimeout,
            "total deadline elapsed while sending the extended CONNECT").with_deadline(plan.timeouts.total_ms)),
        _ = cancel.cancelled() => Err(TransportFailure::new(Phase::RequestWrite, FailureKind::Canceled, "canceled while sending the extended CONNECT")),
    };
    let mut stream = match sent {
        Ok(s) => s,
        Err(f) => {
            close_quic(&quic);
            return early(rec, obs, f, DispatchState::MayHaveBeenSent, facts);
        }
    };
    rec.finish_with(w_idx, PhaseStatus::Completed, "extended CONNECT headers sent on a new request stream (no body)");
    let h_idx = rec.start(Phase::AwaitResponseHeaders);
    let headers_deadline = deadline_from(plan.timeouts.response_headers_ms);
    let resp = tokio::select! {
        r = stream.recv_response() => r.map_err(|e| crate::h3::stream_failure(&e, Phase::AwaitResponseHeaders, FailureKind::ResetBeforeResponse,
            "the HTTP/3 stream ended before an answer to the extended CONNECT")),
        _ = sleep_until_opt(headers_deadline) => Err(TransportFailure::new(Phase::AwaitResponseHeaders, FailureKind::ResponseHeadersTimeout,
            "no answer to the WebSocket extended CONNECT before the response-header deadline").with_deadline(plan.timeouts.response_headers_ms)),
        _ = sleep_until_opt(total_deadline) => Err(TransportFailure::new(Phase::AwaitResponseHeaders, FailureKind::TotalTimeout,
            "total deadline elapsed during the WebSocket handshake").with_deadline(plan.timeouts.total_ms)),
        _ = cancel.cancelled() => Err(TransportFailure::new(Phase::AwaitResponseHeaders, FailureKind::Canceled, "canceled during the WebSocket handshake")),
    };
    let resp = match resp {
        Ok(r) => r,
        Err(f) => {
            close_quic(&quic);
            return early(rec, obs, f, DispatchState::MayHaveBeenSent, facts);
        }
    };
    rec.finish(h_idx, PhaseStatus::Completed);
    let status = resp.status().as_u16();
    obs.response_status = Some(status);
    obs.dispatch = DispatchState::Sent;
    events.emit(ExecutionEvent::ResponseHead { execution_id: events.execution_id, attempt: 0, status });
    let headers = header_entries(resp.headers());
    obs.bytes.response_headers_logical = Some(logical_header_bytes(&headers));
    let content_type = resp.headers().get(http::header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).map(|s| s.to_string());
    let ws_status = |closed_by: ClosedBy, extensions: Option<WsExtensions>| ProtocolStatus::WebSocket {
        handshake_status: Some(status),
        close_code: None,
        close_reason: String::new(),
        closed_by,
        extensions,
    };

    // ---- rejected handshake: keep the (bounded) response as evidence ----
    if status != 200 {
        let b_idx = rec.start(Phase::ResponseBody);
        let mut captured = BytesMut::new();
        let mut wire = 0u64;
        let mut completeness = BodyCompleteness::Complete;
        loop {
            let idle = deadline_from(plan.timeouts.body_idle_ms.or(Some(5_000)));
            let chunk = tokio::select! {
                c = stream.recv_data() => c,
                _ = sleep_until_opt(idle) => { completeness = BodyCompleteness::Incomplete; break; }
                _ = cancel.cancelled() => { completeness = BodyCompleteness::Canceled; break; }
            };
            match chunk {
                Ok(Some(mut c)) => {
                    let n = c.remaining();
                    let d = c.copy_to_bytes(n);
                    wire += n as u64;
                    let room = (plan.limits.capture_bytes as usize).saturating_sub(captured.len());
                    captured.extend_from_slice(&d[..d.len().min(room)]);
                    if wire > plan.limits.max_response_bytes {
                        completeness = BodyCompleteness::StoppedAtLocalLimit;
                        break;
                    }
                }
                Ok(None) => break,
                Err(_) => {
                    completeness = BodyCompleteness::Incomplete;
                    break;
                }
            }
        }
        rec.finish(b_idx, if completeness == BodyCompleteness::Complete { PhaseStatus::Completed } else { PhaseStatus::Failed });
        close_quic(&quic);
        let mut f = TransportFailure::new(
            Phase::ProtocolHandshake,
            FailureKind::WsHandshakeRejected,
            format!("the server answered the WebSocket extended CONNECT over HTTP/3 with HTTP {status} instead of 200"),
        );
        f.status = Some(status);
        obs.failure = Some(f);
        obs.bytes.response_body_wire = Some(wire);
        let obs = finish_attempt(rec, obs, events);
        let captured = captured.freeze();
        let response = response_record(status, http::Version::HTTP_3, headers, body_capture(completeness, wire, &captured, content_type));
        return SessionOutput::single(
            crate::http::AttemptOutput { observation: obs, response: Some(response), body: captured },
            None,
            ws_status(ClosedBy::NotClosed, None),
            facts,
        );
    }

    let response = response_record(status, http::Version::HTTP_3, headers, body_capture(BodyCompleteness::NoBody, 0, &[], content_type));
    let (extensions, deflate) = negotiate_extensions(plan, &offered, resp.headers(), &mut facts);
    let checked = match deflate {
        Ok(d) => negotiate_subprotocol(plan, resp.headers(), &mut facts).map(|()| d),
        Err(e) => Err(format!("the server's Sec-WebSocket-Extensions answer is refused: {e}")),
    };
    let deflate = match checked {
        Ok(d) => d,
        Err(e) => {
            close_quic(&quic);
            let mut f = TransportFailure::new(Phase::ProtocolHandshake, FailureKind::WsProtocolError, e);
            f.status = Some(status);
            obs.failure = Some(f);
            let obs = finish_attempt(rec, obs, events);
            return SessionOutput::single(
                crate::http::AttemptOutput { observation: obs, response: Some(response), body: Bytes::new() },
                None,
                ws_status(ClosedBy::NotClosed, extensions),
                facts,
            );
        }
    };

    // ---- session over the HTTP/3 stream ----
    let stats = crate::stats::ConnStats::new();
    let stream_error = Arc::new(parking_lot::Mutex::new(None));
    let write_interrupted = CancellationToken::new();
    let (io, mut uplink) = bridge_h3_stream(stream, stats.clone(), stream_error.clone(), write_interrupted.clone());
    let cx = SessionCtx {
        plan,
        events,
        cancel,
        interactive,
        total_deadline,
        stats,
        written_before: 0,
        read_before: 0,
        status,
        response,
        deflate,
        extensions,
        write_interrupted: write_interrupted.clone(),
    };
    let mut out = run_session(io, rec, obs, facts, commands, cx).await;
    if write_interrupted.is_cancelled() {
        // The uplink resets the stream (H3_REQUEST_CANCELLED) instead of
        // ending it: a partial frame must not be followed by a clean FIN.
        let _ = tokio::time::timeout(Duration::from_millis(100), &mut uplink).await;
        uplink.abort();
    } else {
        // Let the last frames (normally our Close) leave before the connection closes.
        let _ = tokio::time::timeout(Duration::from_millis(500), &mut uplink).await;
    }
    close_quic(&quic);
    if let Some(e) = stream_error.lock().take()
        && let Some(a) = out.attempts.last_mut()
        && let Some(f) = a.observation.failure.as_mut()
    {
        f.message = format!("{} (HTTP/3 stream error: {e})", f.message);
    }
    out
}

pub async fn run(plan: &WsPlan, events: &EventCtx, cancel: &CancellationToken, commands: Option<CommandRx>) -> SessionOutput {
    if plan.bootstrap == WsBootstrap::Http3ExtendedConnect {
        return run_h3(plan, events, cancel, commands).await;
    }
    let interactive = commands.is_some();
    let mut rec = Recorder::new(0, events.clone());
    events.emit(ExecutionEvent::AttemptStarted { execution_id: events.execution_id, attempt: 0 });
    let h2 = plan.bootstrap == WsBootstrap::Http2ExtendedConnect;
    let mut obs = new_attempt(0, AttemptReason::Initial, if h2 { "CONNECT" } else { "GET" }, &plan.display_url);
    let mut facts = SessionFacts::default();
    let early = |rec: Recorder, obs: AttemptObservation, f: TransportFailure, facts: SessionFacts| {
        SessionOutput::single(fail_attempt(rec, obs, f, DispatchState::NotDispatched, events), None, ProtocolStatus::None, facts)
    };
    if plan.secure && plan.tls.is_none() {
        let f = TransportFailure::new(Phase::Prepare, FailureKind::TlsProfileInvalid, "no TLS configuration for a wss:// session");
        return early(rec, obs, f, facts);
    }
    let total_deadline = if interactive { None } else { deadline_from(plan.timeouts.total_ms) };

    // ---- connection ----
    let alpn: &[&str] = match (plan.secure, h2) {
        (true, true) => &["h2"],
        (true, false) => &["http/1.1"],
        _ => &[],
    };
    let target = Target { host: &plan.host, port: plan.port, tls: plan.tls.as_deref(), alpn, http_forward_via_proxy: false };
    let header = plan.proxy_header.as_ref().map(crate::connector::PreTlsHeader::of);
    let est =
        match establish_guarded_with(&mut rec, &target, &plan.dns, &plan.timeouts, plan.proxy.as_ref(), cancel, total_deadline, header)
            .await
        {
            Ok(e) => e,
            Err((f, o)) => {
                obs.connection = o;
                return early(rec, obs, f, facts);
            }
        };
    if h2 && plan.secure {
        let negotiated = est.observation.tls.as_ref().and_then(|t| t.alpn_negotiated.clone());
        if negotiated.as_deref() != Some("h2") {
            let f = TransportFailure::new(
                Phase::TlsHandshake,
                FailureKind::TlsAlpnMismatch,
                format!(
                    "WebSocket over HTTP/2 needs ALPN 'h2', but the peer negotiated {}; the HTTP/2 bootstrap is not available here",
                    negotiated.map(|s| format!("'{s}'")).unwrap_or_else(|| "no ALPN protocol".into())
                ),
            );
            obs.connection = Some(est.observation);
            return early(rec, obs, f, facts);
        }
    }
    let HttpConn { mut sender, stats, observation: cobs, extended_connect } =
        match http_handshake::<Empty<Bytes>>(&mut rec, est, h2, &plan.limits).await {
            Ok(x) => x,
            Err((f, o)) => {
                obs.connection = Some(o);
                return early(rec, obs, f, facts);
            }
        };
    obs.connection = Some(cobs);
    if h2 {
        let wait_ms = plan.timeouts.response_headers_ms.unwrap_or(5_000).min(5_000);
        match await_extended_connect(extended_connect, wait_ms, cancel).await {
            Ok(()) => rec.mark(Phase::ProtocolHandshake, PhaseStatus::Completed, Some("peer enabled extended CONNECT (RFC 8441)")),
            Err(why) => {
                let f = if why == "canceled" {
                    TransportFailure::new(Phase::ProtocolHandshake, FailureKind::Canceled, "canceled while waiting for HTTP/2 settings")
                } else {
                    let mut f = TransportFailure::new(
                        Phase::ProtocolHandshake,
                        FailureKind::WsHandshakeRejected,
                        format!(
                            "the HTTP/2 peer did not enable extended CONNECT (SETTINGS_ENABLE_CONNECT_PROTOCOL) within {wait_ms} ms, so the RFC 8441 WebSocket bootstrap is unavailable on this connection; nothing was sent"
                        ),
                    );
                    f.deadline_ms = Some(wait_ms);
                    f
                };
                return early(rec, obs, f, facts);
            }
        }
    }

    // ---- bootstrap request ----
    let key = tungstenite::handshake::client::generate_key();
    let req = match build_request(plan, h2, &key) {
        Ok(r) => r,
        Err(e) => {
            let f =
                TransportFailure::new(Phase::Prepare, FailureKind::InvalidHeader, format!("the WebSocket request could not be built: {e}"));
            return early(rec, obs, f, facts);
        }
    };
    let req_headers = header_entries(req.headers());
    let offered = extension_values(req.headers());
    obs.bytes.request_headers_logical = logical_header_bytes(&req_headers) + plan.request_target.len() as u64 + 16;
    obs.bytes.request_headers_estimated = h2;
    let written_before = stats.bytes_written();
    let read_before = stats.bytes_read();
    let w_idx = rec.start(Phase::RequestWrite);
    rec.finish_with(w_idx, PhaseStatus::Completed, "handshake request handed to the connection (no body)");
    let h_idx = rec.start(Phase::AwaitResponseHeaders);
    let headers_deadline = deadline_from(plan.timeouts.response_headers_ms);
    let may_have_sent = |stats: &crate::stats::ConnStats| {
        if stats.bytes_written() > written_before { DispatchState::MayHaveBeenSent } else { DispatchState::NotDispatched }
    };
    let resp = tokio::select! {
        r = sender.send(req) => Ok(r),
        _ = sleep_until_opt(headers_deadline) => Err(TransportFailure::new(Phase::AwaitResponseHeaders, FailureKind::ResponseHeadersTimeout,
            "no answer to the WebSocket handshake before the response-header deadline").with_deadline(plan.timeouts.response_headers_ms)),
        _ = sleep_until_opt(total_deadline) => Err(TransportFailure::new(Phase::AwaitResponseHeaders, FailureKind::TotalTimeout,
            "total deadline elapsed during the WebSocket handshake").with_deadline(plan.timeouts.total_ms)),
        _ = cancel.cancelled() => Err(TransportFailure::new(Phase::AwaitResponseHeaders, FailureKind::Canceled, "canceled during the WebSocket handshake")),
    };
    let resp = match resp {
        Ok(r) => r,
        Err(f) => {
            return SessionOutput::single(fail_attempt(rec, obs, f, may_have_sent(&stats), events), None, ProtocolStatus::None, facts);
        }
    };
    let resp = match resp {
        Ok(r) => r,
        Err(e) => {
            let mut f = classify_hyper(&e, HyperStage::AwaitHeaders);
            if let Some((k, alert)) = stats.tls_error() {
                f.kind = k;
                f.tls_alert = alert;
            }
            return SessionOutput::single(fail_attempt(rec, obs, f, may_have_sent(&stats), events), None, ProtocolStatus::None, facts);
        }
    };
    rec.finish(h_idx, PhaseStatus::Completed);
    let status = resp.status().as_u16();
    obs.response_status = Some(status);
    obs.dispatch = DispatchState::Sent;
    events.emit(ExecutionEvent::ResponseHead { execution_id: events.execution_id, attempt: 0, status });
    let version = resp.version();
    let headers = header_entries(resp.headers());
    obs.bytes.response_headers_logical = Some(logical_header_bytes(&headers));
    let content_type = resp.headers().get(http::header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).map(|s| s.to_string());
    let accepted = if h2 { status == 200 } else { status == 101 };

    // ---- rejected handshake: keep the (bounded) response as evidence ----
    if !accepted {
        let b_idx = rec.start(Phase::ResponseBody);
        let mut body = resp.into_body();
        let mut captured = BytesMut::new();
        let mut wire = 0u64;
        let mut completeness = BodyCompleteness::Complete;
        loop {
            let idle = deadline_from(plan.timeouts.body_idle_ms.or(Some(5_000)));
            let f = tokio::select! {
                f = body.frame() => f,
                _ = sleep_until_opt(idle) => { completeness = BodyCompleteness::Incomplete; break; }
                _ = cancel.cancelled() => { completeness = BodyCompleteness::Canceled; break; }
            };
            match f {
                None => break,
                Some(Ok(frame)) => {
                    if let Ok(d) = frame.into_data() {
                        wire += d.len() as u64;
                        let room = (plan.limits.capture_bytes as usize).saturating_sub(captured.len());
                        captured.extend_from_slice(&d[..d.len().min(room)]);
                        if wire > plan.limits.max_response_bytes {
                            completeness = BodyCompleteness::StoppedAtLocalLimit;
                            break;
                        }
                    }
                }
                Some(Err(_)) => {
                    completeness = BodyCompleteness::Incomplete;
                    break;
                }
            }
        }
        rec.finish(b_idx, if completeness == BodyCompleteness::Complete { PhaseStatus::Completed } else { PhaseStatus::Failed });
        let mut f = TransportFailure::new(
            Phase::ProtocolHandshake,
            FailureKind::WsHandshakeRejected,
            format!(
                "the server answered the WebSocket {} with HTTP {status} instead of {}",
                if h2 { "extended CONNECT" } else { "upgrade" },
                if h2 { "200" } else { "101 Switching Protocols" }
            ),
        );
        f.status = Some(status);
        obs.failure = Some(f);
        obs.bytes.response_body_wire = Some(wire);
        obs.bytes.connection_bytes_written = Some(stats.bytes_written().saturating_sub(written_before));
        obs.bytes.connection_bytes_read = Some(stats.bytes_read().saturating_sub(read_before));
        let obs = finish_attempt(rec, obs, events);
        let captured = captured.freeze();
        let response = response_record(status, version, headers, body_capture(completeness, wire, &captured, content_type));
        let ps = ProtocolStatus::WebSocket {
            handshake_status: Some(status),
            close_code: None,
            close_reason: String::new(),
            closed_by: ClosedBy::NotClosed,
            extensions: None,
        };
        return SessionOutput::single(
            crate::http::AttemptOutput { observation: obs, response: Some(response), body: captured },
            None,
            ps,
            facts,
        );
    }

    let response = response_record(status, version, headers.clone(), body_capture(BodyCompleteness::NoBody, 0, &[], content_type));
    let handshake_fail =
        |rec: Recorder, mut obs: AttemptObservation, msg: String, facts: SessionFacts, extensions: Option<WsExtensions>| {
            let mut f = TransportFailure::new(Phase::ProtocolHandshake, FailureKind::WsProtocolError, msg);
            f.status = Some(status);
            obs.failure = Some(f);
            let obs = finish_attempt(rec, obs, events);
            let ps = ProtocolStatus::WebSocket {
                handshake_status: Some(status),
                close_code: None,
                close_reason: String::new(),
                closed_by: ClosedBy::NotClosed,
                extensions,
            };
            SessionOutput::single(
                crate::http::AttemptOutput { observation: obs, response: Some(response.clone()), body: Bytes::new() },
                None,
                ps,
                facts,
            )
        };
    if !h2 && let Err(e) = validate_upgrade(resp.headers(), &key) {
        return handshake_fail(rec, obs, format!("invalid WebSocket handshake response: {e}"), facts, None);
    }
    let (extensions, deflate) = negotiate_extensions(plan, &offered, resp.headers(), &mut facts);
    let deflate = match deflate {
        Ok(d) => d,
        Err(e) => {
            let msg = format!("the server's Sec-WebSocket-Extensions answer is refused: {e}");
            return handshake_fail(rec, obs, msg, facts, extensions);
        }
    };
    if let Err(e) = negotiate_subprotocol(plan, resp.headers(), &mut facts) {
        return handshake_fail(rec, obs, e, facts, extensions);
    }
    let upgraded = tokio::select! {
        u = hyper::upgrade::on(resp) => Some(u),
        _ = cancel.cancelled() => None,
    };
    let upgraded = match upgraded {
        Some(Ok(u)) => u,
        Some(Err(e)) => {
            return handshake_fail(rec, obs, format!("the connection could not be switched to WebSocket: {e}"), facts, extensions);
        }
        None => {
            let f = TransportFailure::new(Phase::ProtocolHandshake, FailureKind::Canceled, "canceled while opening the WebSocket stream");
            obs.failure = Some(f);
            let obs = finish_attempt(rec, obs, events);
            let ps = ProtocolStatus::WebSocket {
                handshake_status: Some(status),
                close_code: None,
                close_reason: String::new(),
                closed_by: ClosedBy::Client,
                extensions,
            };
            return SessionOutput::single(
                crate::http::AttemptOutput { observation: obs, response: Some(response), body: Bytes::new() },
                None,
                ps,
                facts,
            );
        }
    };

    let cx = SessionCtx {
        plan,
        events,
        cancel,
        interactive,
        total_deadline,
        stats,
        written_before,
        read_before,
        status,
        response,
        deflate,
        extensions,
        write_interrupted: CancellationToken::new(),
    };
    run_session(TokioIo::new(upgraded), rec, obs, facts, commands, cx).await
}

/// Everything the session phase needs from the bootstrap.
struct SessionCtx<'a> {
    plan: &'a WsPlan,
    events: &'a EventCtx,
    cancel: &'a CancellationToken,
    interactive: bool,
    total_deadline: Option<Instant>,
    /// Byte counters for the evidence. TCP: the whole connection. HTTP/3:
    /// the WebSocket bytes carried in this stream's DATA frames.
    stats: Arc<crate::stats::ConnStats>,
    written_before: u64,
    read_before: u64,
    status: u16,
    response: ResponseRecord,
    /// The negotiated `permessage-deflate` codec (`None`: none).
    deflate: Option<DeflateConfig>,
    /// Extension evidence from the handshake; the session adds its traffic.
    extensions: Option<WsExtensions>,
    /// Canceled when a write was interrupted (it may have left a partial
    /// frame): the stream is then reset, not ended cleanly.
    write_interrupted: CancellationToken,
}

/// The WebSocket session itself, over whichever stream the bootstrap opened
/// (an upgraded HTTP/1.1 connection, an HTTP/2 stream or an HTTP/3 stream).
async fn run_session<S>(
    io: S,
    mut rec: Recorder,
    mut obs: AttemptObservation,
    facts: SessionFacts,
    mut commands: Option<CommandRx>,
    cx: SessionCtx<'_>,
) -> SessionOutput
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let SessionCtx {
        plan,
        events,
        cancel,
        interactive,
        total_deadline,
        stats,
        written_before,
        read_before,
        status,
        response,
        deflate,
        extensions,
        write_interrupted,
    } = cx;
    // ---- session ----
    let s_idx = rec.start(Phase::Session);
    let max = plan.max_message_bytes.clamp(16, usize::MAX as u64) as usize;
    // The frame limit is on the wire; the message limit is on the
    // (decompressed) message.
    let cfg = WebSocketConfig::default().max_message_size(Some(max)).max_frame_size(Some(max)).deflate(deflate);
    let meter = Arc::new(parking_lot::Mutex::new(FrameMeter::default()));
    let mut ws = WebSocketStream::from_raw_socket(Metered::new(io, meter.clone()), Role::Client, Some(cfg)).await;
    let mut tr = Transcript::new(rec.t0, plan.transcript, events.clone(), plan.redact.clone());
    if let Some(e) = &extensions {
        let note = match &e.deflate {
            Some(p) => ws_deflate::describe(p),
            None => format!("{} offered but not negotiated: the session is uncompressed", offer_name(plan)),
        };
        tr.note("extension", &note);
    }
    let mut violation: Option<WsCompressionViolation> = None;
    let mut close: Option<Close> = None;
    let mut client_close_sent: Option<(u16, String)> = None;
    let mut peer_close_seen = false;
    let mut failure: Option<TransportFailure> = None;
    let close_wait = Duration::from_millis(plan.idle_close_ms.clamp(250, 5_000));
    let mut close_deadline: Option<Instant> = None;

    // Scripted messages (automation, and the opening of interactive sessions).
    // Every write below is raced against cancellation and the deadline that
    // applies to it: a peer that stops reading must not hold the session.
    let mut send_error: Option<tungstenite::Error> = None;
    let mut write_stop: Option<WriteStop> = None;
    for m in &plan.script {
        let (msg, kind, payload): (Message, &str, Vec<u8>) = match m {
            WsMessage::Text { text } => (Message::Text(text.clone().into()), "text", text.clone().into_bytes()),
            WsMessage::Binary { hex } => match decode_hex(hex) {
                Ok(b) => (Message::Binary(Bytes::from(b.clone())), "binary", b),
                Err(e) => {
                    tr.note("error", &format!("binary message not sent: {e}"));
                    continue;
                }
            },
            WsMessage::Ping { hex } => match decode_hex(hex) {
                Ok(b) => (Message::Ping(Bytes::from(b.clone())), "ping", b),
                Err(e) => {
                    tr.note("error", &format!("ping not sent: {e}"));
                    continue;
                }
            },
            WsMessage::Close { code, reason } => (close_frame(*code, reason), "close", format!("{code} {reason}").into_bytes()),
        };
        let is_close = matches!(msg, Message::Close(_));
        let wrote = match m {
            WsMessage::Close { code, reason } => send_close_guarded(&mut ws, *code, reason, cancel, total_deadline, close_wait).await,
            _ => send_guarded(&mut ws, msg, cancel, total_deadline).await,
        };
        match wrote {
            Wrote::Done => {}
            Wrote::Failed(e) => {
                send_error = Some(e);
                break;
            }
            Wrote::Stopped(s) => {
                write_stop = Some(s);
                break;
            }
        }
        match kind {
            "text" | "binary" => tr.data(Direction::Sent, kind, &payload),
            _ => tr.control(Direction::Sent, kind, &payload),
        }
        if is_close && let WsMessage::Close { code, reason } = m {
            client_close_sent = Some((*code, reason.clone()));
            close_deadline = Some(Instant::now() + close_wait);
            break;
        }
    }

    let mut last_inbound = Instant::now();
    let idle = Duration::from_millis(plan.idle_close_ms.max(1));
    let expect = plan.expect_messages as u64;
    let mut pending_error = send_error;
    enum Ev {
        Inbound(Option<Result<Message, tungstenite::Error>>),
        Cmd(Option<SessionCommand>),
        Idle,
        CloseWait,
        Deadline,
        Canceled,
    }
    loop {
        if let Some(stop) = write_stop.take() {
            // The stalled write may have been partly sent: nothing more is
            // written, the connection is dropped (an HTTP/3 stream is reset).
            write_interrupted.cancel();
            match stop {
                WriteStop::Interrupted(Interrupted::Canceled) => {
                    close.get_or_insert(Close { code: None, reason: String::new(), closed_by: ClosedBy::Client });
                    failure = Some(TransportFailure::new(
                        Phase::Session,
                        FailureKind::Canceled,
                        "canceled while a write was pending (the peer was not reading); the connection was dropped",
                    ));
                }
                WriteStop::Interrupted(Interrupted::Deadline) => {
                    close.get_or_insert(Close { code: None, reason: String::new(), closed_by: ClosedBy::Timeout });
                    failure = Some(
                        TransportFailure::new(
                            Phase::Session,
                            FailureKind::TotalTimeout,
                            "the total deadline elapsed while a write was pending (the peer was not reading); the connection was dropped",
                        )
                        .with_deadline(plan.timeouts.total_ms),
                    );
                }
                WriteStop::CloseStalled { code, reason } => {
                    close.get_or_insert(Close { code: Some(code), reason, closed_by: ClosedBy::Client });
                    tr.note(
                        "close_incomplete",
                        "the Close frame was not written within the close wait (the peer was not reading); the connection was dropped",
                    );
                }
            }
            break;
        }
        if let Some(e) = pending_error.take() {
            let st =
                ErrorState { close: &mut close, failure: &mut failure, violation: &mut violation, write_interrupted: &write_interrupted };
            classify_ws_error(e, st, &mut ws, &mut tr, peer_close_seen, &stats).await;
            break;
        }
        let idle_deadline = if !interactive && client_close_sent.is_none() && !peer_close_seen { Some(last_inbound + idle) } else { None };
        let want_cmd = interactive && client_close_sent.is_none() && !peer_close_seen;
        let ev = tokio::select! {
            m = ws.next() => Ev::Inbound(m),
            c = next_cmd(&mut commands), if want_cmd => Ev::Cmd(c),
            _ = sleep_until_opt(idle_deadline) => Ev::Idle,
            _ = sleep_until_opt(close_deadline) => Ev::CloseWait,
            _ = sleep_until_opt(total_deadline) => Ev::Deadline,
            _ = cancel.cancelled() => Ev::Canceled,
        };
        match ev {
            Ev::Inbound(Some(Ok(msg))) => {
                last_inbound = Instant::now();
                match msg {
                    Message::Text(t) => tr.data(Direction::Received, "text", t.as_bytes()),
                    Message::Binary(b) => tr.data(Direction::Received, "binary", &b),
                    Message::Ping(p) => {
                        tr.control(Direction::Received, "ping", &p);
                        // tungstenite queued the Pong.
                        match guarded(ws.flush(), cancel, total_deadline).await {
                            Ok(_) => tr.control(Direction::Sent, "pong", &p),
                            Err(i) => write_stop = Some(WriteStop::Interrupted(i)),
                        }
                    }
                    Message::Pong(p) => tr.control(Direction::Received, "pong", &p),
                    Message::Close(frame) => {
                        peer_close_seen = true;
                        let (code, reason) = match frame {
                            Some(f) => (Some(u16::from(f.code)), f.reason.to_string()),
                            None => (None, String::new()),
                        };
                        let shown = format!("{} {}", code.map(|c| c.to_string()).unwrap_or_else(|| "(no code)".into()), reason);
                        tr.control(Direction::Received, "close", shown.trim().as_bytes());
                        match &client_close_sent {
                            Some((c, r)) => {
                                close.get_or_insert(Close { code: Some(*c), reason: r.clone(), closed_by: ClosedBy::Client });
                            }
                            None => {
                                close = Some(Close { code, reason, closed_by: ClosedBy::Peer });
                                close_deadline = Some(Instant::now() + close_wait);
                            }
                        }
                    }
                    Message::Frame(_) => {}
                }
                if write_stop.is_none()
                    && !interactive
                    && expect > 0
                    && tr.received_count() >= expect
                    && client_close_sent.is_none()
                    && !peer_close_seen
                {
                    match send_close_guarded(&mut ws, 1000, "", cancel, total_deadline, close_wait).await {
                        Wrote::Done => {
                            tr.control(Direction::Sent, "close", b"1000");
                            client_close_sent = Some((1000, String::new()));
                            close_deadline = Some(Instant::now() + close_wait);
                        }
                        Wrote::Failed(e) => pending_error = Some(e),
                        Wrote::Stopped(s) => write_stop = Some(s),
                    }
                }
            }
            Ev::Inbound(Some(Err(e))) => pending_error = Some(e),
            Ev::Inbound(None) => {
                if close.is_none() {
                    close = Some(Close { code: Some(1006), reason: String::new(), closed_by: ClosedBy::Abnormal });
                    failure = Some(TransportFailure::new(
                        Phase::Session,
                        FailureKind::BodyIncomplete,
                        "the connection ended without a WebSocket Close frame (reported as 1006; 1006 is never sent by a peer)",
                    ));
                }
                break;
            }
            Ev::Cmd(c) => {
                let wrote = match c {
                    Some(SessionCommand::SendText { text }) => {
                        let w = send_guarded(&mut ws, Message::Text(text.clone().into()), cancel, total_deadline).await;
                        if matches!(w, Wrote::Done) {
                            tr.data(Direction::Sent, "text", text.as_bytes());
                        }
                        w
                    }
                    Some(SessionCommand::SendBinaryHex { hex }) => match decode_hex(&hex) {
                        Ok(b) => {
                            let w = send_guarded(&mut ws, Message::Binary(Bytes::from(b.clone())), cancel, total_deadline).await;
                            if matches!(w, Wrote::Done) {
                                tr.data(Direction::Sent, "binary", &b);
                            }
                            w
                        }
                        Err(e) => {
                            tr.note("error", &format!("binary message not sent: {e}"));
                            Wrote::Done
                        }
                    },
                    Some(SessionCommand::Ping) => {
                        let w = send_guarded(&mut ws, Message::Ping(Bytes::from_static(b"anvil")), cancel, total_deadline).await;
                        if matches!(w, Wrote::Done) {
                            tr.control(Direction::Sent, "ping", b"anvil");
                        }
                        w
                    }
                    Some(SessionCommand::HalfClose) => {
                        tr.note("unsupported_command", "WebSocket has no half-close; send Close instead");
                        Wrote::Done
                    }
                    Some(SessionCommand::Close { code, reason }) => {
                        let w = send_close_guarded(&mut ws, code, &reason, cancel, total_deadline, close_wait).await;
                        if matches!(w, Wrote::Done) {
                            tr.control(Direction::Sent, "close", format!("{code} {reason}").trim().as_bytes());
                            client_close_sent = Some((code, reason));
                            close_deadline = Some(Instant::now() + close_wait);
                        }
                        w
                    }
                    None => {
                        // The session handle was dropped: close politely.
                        let w = send_close_guarded(&mut ws, 1000, "session ended", cancel, total_deadline, close_wait).await;
                        if matches!(w, Wrote::Done) {
                            tr.control(Direction::Sent, "close", b"1000 session ended");
                            client_close_sent = Some((1000, "session ended".into()));
                            close_deadline = Some(Instant::now() + close_wait);
                        }
                        w
                    }
                };
                match wrote {
                    Wrote::Done => {}
                    Wrote::Failed(e) => pending_error = Some(e),
                    Wrote::Stopped(s) => write_stop = Some(s),
                }
            }
            Ev::Idle => match send_close_guarded(&mut ws, 1000, "", cancel, total_deadline, close_wait).await {
                Wrote::Done => {
                    tr.control(Direction::Sent, "close", b"1000 (idle)");
                    client_close_sent = Some((1000, String::new()));
                    close_deadline = Some(Instant::now() + close_wait);
                }
                Wrote::Failed(e) => pending_error = Some(e),
                Wrote::Stopped(s) => write_stop = Some(s),
            },
            Ev::CloseWait => {
                if close.is_none() {
                    close = Some(match &client_close_sent {
                        Some((code, reason)) => Close { code: Some(*code), reason: reason.clone(), closed_by: ClosedBy::Client },
                        None => Close { code: None, reason: String::new(), closed_by: ClosedBy::Peer },
                    });
                }
                tr.note(
                    "close_incomplete",
                    "the closing handshake did not finish before the close wait elapsed; the connection was dropped",
                );
                break;
            }
            Ev::Deadline => {
                // Its own short bound: the deadline has passed already.
                if tokio::time::timeout(FINAL_CLOSE_WRITE, ws.send(close_frame(1001, "deadline"))).await.is_ok_and(|r| r.is_ok()) {
                    tr.control(Direction::Sent, "close", b"1001 deadline");
                } else {
                    write_interrupted.cancel();
                    tr.note("close_incomplete", "the Close frame could not be written at the deadline; the connection was dropped");
                }
                close.get_or_insert(Close { code: Some(1001), reason: "deadline".into(), closed_by: ClosedBy::Timeout });
                failure = Some(
                    TransportFailure::new(
                        Phase::Session,
                        FailureKind::TotalTimeout,
                        "the total deadline elapsed during the WebSocket session",
                    )
                    .with_deadline(plan.timeouts.total_ms),
                );
                break;
            }
            Ev::Canceled => {
                if tokio::time::timeout(FINAL_CLOSE_WRITE, ws.send(close_frame(1001, "canceled"))).await.is_ok_and(|r| r.is_ok()) {
                    tr.control(Direction::Sent, "close", b"1001 canceled");
                } else {
                    write_interrupted.cancel();
                    tr.note("close_incomplete", "the Close frame could not be written on cancel; the connection was dropped");
                }
                close.get_or_insert(Close { code: Some(1001), reason: "canceled".into(), closed_by: ClosedBy::Client });
                failure = Some(TransportFailure::new(Phase::Session, FailureKind::Canceled, "the WebSocket session was canceled"));
                break;
            }
        }
    }
    let close = close.unwrap_or(match &client_close_sent {
        Some((c, r)) => Close { code: Some(*c), reason: r.clone(), closed_by: ClosedBy::Client },
        None => Close { code: None, reason: String::new(), closed_by: ClosedBy::NotClosed },
    });
    rec.finish(
        s_idx,
        match &failure {
            Some(f) => phase_status_for(f.kind),
            None => PhaseStatus::Completed,
        },
    );
    obs.failure = failure;
    obs.bytes.request_body = tr.sent_bytes();
    obs.bytes.response_body_wire = Some(tr.received_bytes());
    obs.bytes.connection_bytes_written = Some(stats.bytes_written().saturating_sub(written_before));
    obs.bytes.connection_bytes_read = Some(stats.bytes_read().saturating_sub(read_before));
    let obs = finish_attempt(rec, obs, events);
    let reason = match &plan.redact {
        Some(r) => r(&close.reason),
        None => close.reason,
    };
    // A frame that claimed compression when none was negotiated is evidence
    // even when nothing was offered.
    let extensions = match (extensions, &violation) {
        (Some(e), _) => Some(e),
        (None, Some(_)) => Some(WsExtensions {
            offered: None,
            answered: None,
            negotiation: WsNegotiation::NotOffered,
            problem: None,
            deflate: None,
            traffic: None,
            violation: None,
        }),
        (None, None) => None,
    };
    let extensions = extensions.map(|mut e| {
        let (mut sent, mut received) = meter.lock().totals();
        sent.payload_bytes = tr.sent_bytes();
        received.payload_bytes = tr.received_bytes();
        e.traffic = Some(WsCompressionTraffic { sent, received });
        e.violation = violation;
        e
    });
    let ps = ProtocolStatus::WebSocket {
        handshake_status: Some(status),
        close_code: close.code,
        close_reason: reason,
        closed_by: close.closed_by,
        extensions,
    };
    SessionOutput::single(
        crate::http::AttemptOutput { observation: obs, response: Some(response), body: Bytes::new() },
        Some(tr.finish()),
        ps,
        facts,
    )
}

/// Where [`classify_ws_error`] records its conclusions.
struct ErrorState<'a> {
    close: &'a mut Option<Close>,
    failure: &'a mut Option<TransportFailure>,
    violation: &'a mut Option<WsCompressionViolation>,
    /// Canceled when the Close frame sent after a local policy violation is
    /// not written in time (it may be partly written).
    write_interrupted: &'a CancellationToken,
}

/// Map a WebSocket error to the close outcome and a typed failure. For
/// local policy violations the client sends the matching Close code.
async fn classify_ws_error<S: AsyncRead + AsyncWrite + Unpin>(
    e: tungstenite::Error,
    st: ErrorState<'_>,
    ws: &mut WebSocketStream<S>,
    tr: &mut Transcript,
    peer_close_seen: bool,
    stats: &crate::stats::ConnStats,
) {
    use tungstenite::Error as E;
    use tungstenite::error::{CapacityError as C, ProtocolError as P};
    // Once the peer's Close frame has arrived the WebSocket session is over;
    // how the TCP/TLS connection is torn down afterwards (FIN, RST, or no TLS
    // close_notify) does not change the close outcome.
    if peer_close_seen && matches!(e, E::ConnectionClosed | E::AlreadyClosed | E::Io(_) | E::Protocol(P::ResetWithoutClosingHandshake)) {
        if let E::Io(ioe) = &e {
            tr.note("transport_teardown", &format!("the connection was torn down after the close handshake ({:?})", ioe.kind()));
        }
        return;
    }
    let ErrorState { close, failure, violation, write_interrupted } = st;
    let mut close_with = |code: u16, reason: &str| {
        *close = Some(Close { code: Some(code), reason: reason.into(), closed_by: ClosedBy::Client });
        (code, reason.to_string())
    };
    match e {
        // A clean end; the caller derives the outcome from the Close frames seen.
        E::ConnectionClosed | E::AlreadyClosed => {}
        // The local limit applies to the decompressed message (decompression-bomb protection).
        E::Capacity(C::DecompressedMessageTooLong { compressed_size, max_size }) => {
            let (code, reason) = close_with(1009, "message too big");
            *failure = Some(TransportFailure::new(
                Phase::Session,
                FailureKind::WsMessageTooLarge,
                format!(
                    "a compressed inbound message grew past Anvil's local message limit ({max_size} bytes) while it was decompressed, after {compressed_size} compressed bytes; Anvil stopped decompressing and closed the session with 1009. This is a local size policy applied after decompression, not a protocol corruption"
                ),
            ));
            *violation = Some(WsCompressionViolation {
                kind: WsViolationKind::TooLargeAfterDecompression,
                compressed_bytes: Some(compressed_size as u64),
                limit_bytes: Some(max_size as u64),
                detail: None,
            });
            send_close_and_drain(ws, tr, code, &reason, write_interrupted).await;
        }
        E::Capacity(c) => {
            let (code, reason) = close_with(1009, "message too big");
            *failure = Some(TransportFailure::new(
                Phase::Session,
                FailureKind::WsMessageTooLarge,
                format!(
                    "an inbound message exceeded Anvil's local message limit ({c}); Anvil closed the session with 1009. This is a local size policy, not a protocol corruption"
                ),
            ));
            send_close_and_drain(ws, tr, code, &reason, write_interrupted).await;
        }
        E::Utf8(_) => {
            let (code, reason) = close_with(1007, "invalid UTF-8");
            *failure = Some(TransportFailure::new(
                Phase::Session,
                FailureKind::WsProtocolError,
                "a text message was not valid UTF-8; Anvil closed with 1007",
            ));
            send_close_and_drain(ws, tr, code, &reason, write_interrupted).await;
        }
        E::Protocol(P::ResetWithoutClosingHandshake) => {
            *close = Some(Close { code: Some(1006), reason: String::new(), closed_by: ClosedBy::Abnormal });
            *failure = Some(TransportFailure::new(
                Phase::Session,
                FailureKind::BodyIncomplete,
                "the connection ended without a WebSocket Close frame (reported as 1006; 1006 is never sent by a peer)",
            ));
        }
        E::Protocol(P::CompressedMessageNotNegotiated) => {
            let (code, reason) = close_with(1002, "protocol error");
            *failure = Some(TransportFailure::new(
                Phase::Session,
                FailureKind::WsProtocolError,
                "WebSocket protocol violation by the peer: a data message arrived with RSV1 set (compressed), but no permessage-deflate was negotiated; Anvil closed with 1002",
            ));
            *violation = Some(WsCompressionViolation {
                kind: WsViolationKind::CompressedWithoutNegotiation,
                compressed_bytes: None,
                limit_bytes: None,
                detail: None,
            });
            send_close_and_drain(ws, tr, code, &reason, write_interrupted).await;
        }
        E::Protocol(P::InvalidCompressedMessage(detail)) => {
            let (code, reason) = close_with(1002, "protocol error");
            *failure = Some(TransportFailure::new(
                Phase::Session,
                FailureKind::WsProtocolError,
                format!(
                    "WebSocket protocol violation by the peer: a permessage-deflate message could not be decompressed ({detail}); Anvil closed with 1002"
                ),
            ));
            *violation = Some(WsCompressionViolation {
                kind: WsViolationKind::Undecodable,
                compressed_bytes: None,
                limit_bytes: None,
                detail: Some(detail),
            });
            send_close_and_drain(ws, tr, code, &reason, write_interrupted).await;
        }
        E::Protocol(p) => {
            let (code, reason) = close_with(1002, "protocol error");
            *failure = Some(TransportFailure::new(
                Phase::Session,
                FailureKind::WsProtocolError,
                format!("WebSocket protocol violation by the peer: {p}"),
            ));
            send_close_and_drain(ws, tr, code, &reason, write_interrupted).await;
        }
        E::Io(ioe) => {
            let kind = match ioe.kind() {
                std::io::ErrorKind::UnexpectedEof => FailureKind::BodyIncomplete,
                _ => FailureKind::BodyReset,
            };
            let mut f = TransportFailure::new(
                Phase::Session,
                kind,
                format!("the connection failed without a WebSocket Close frame (reported as 1006): {ioe}"),
            );
            f.io_error_kind = Some(format!("{:?}", ioe.kind()));
            f.os_error_code = ioe.raw_os_error();
            if let Some((k, alert)) = stats.tls_error() {
                f.kind = k;
                f.tls_alert = alert;
            }
            *failure = Some(f);
            *close = Some(Close { code: Some(1006), reason: String::new(), closed_by: ClosedBy::Abnormal });
        }
        other => {
            *failure = Some(TransportFailure::new(Phase::Session, FailureKind::WsProtocolError, format!("WebSocket error: {other}")));
            if close.is_none() {
                *close = Some(Close { code: Some(1006), reason: String::new(), closed_by: ClosedBy::Abnormal });
            }
        }
    }
}

/// How long the Close frame sent after a local policy violation may take to
/// be written, and how long the peer then has to acknowledge it.
const VIOLATION_CLOSE_WAIT: Duration = Duration::from_millis(500);

/// Send the Close frame for a local policy violation, then give the peer a
/// bounded moment to acknowledge it. A Close frame not written within its
/// bound may have been partly written: `write_interrupted` is canceled, so
/// the stream is reset (HTTP/3) instead of ended cleanly, and nothing more
/// is written or read.
async fn send_close_and_drain<S: AsyncRead + AsyncWrite + Unpin>(
    ws: &mut WebSocketStream<S>,
    tr: &mut Transcript,
    code: u16,
    reason: &str,
    write_interrupted: &CancellationToken,
) {
    match tokio::time::timeout(VIOLATION_CLOSE_WAIT, ws.send(close_frame(code, reason))).await {
        Ok(Ok(())) => tr.control(Direction::Sent, "close", format!("{code} {reason}").as_bytes()),
        Ok(Err(_)) => {}
        Err(_) => {
            write_interrupted.cancel();
            tr.note("close_incomplete", "the Close frame could not be written (the peer was not reading); the connection was dropped");
            return;
        }
    }
    // Give the peer a bounded moment to acknowledge; ignore whatever arrives.
    let _ = tokio::time::timeout(VIOLATION_CLOSE_WAIT, async {
        while let Some(Ok(m)) = ws.next().await {
            if let Message::Close(_) = m {
                tr.control(Direction::Received, "close", b"(acknowledgement)");
                break;
            }
        }
    })
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::DuplexStream;

    fn plan(script: Vec<WsMessage>, total_ms: Option<u64>) -> WsPlan {
        WsPlan {
            bootstrap: WsBootstrap::Http1Upgrade,
            secure: false,
            host: "127.0.0.1".into(),
            port: 9,
            authority: "127.0.0.1:9".into(),
            request_target: "/".into(),
            headers: vec![],
            subprotocols: vec![],
            deflate: None,
            script,
            expect_messages: 0,
            idle_close_ms: 5_000,
            max_message_bytes: 16 * 1024 * 1024,
            timeouts: Timeouts { total_ms, ..Timeouts::default() },
            limits: Limits::default(),
            dns: DnsConfig::default(),
            proxy: None,
            tls: None,
            display_url: "ws://127.0.0.1:9/".into(),
            transcript: TranscriptLimits::default(),
            redact: None,
            proxy_header: None,
        }
    }

    /// The session phase over an in-memory pipe (the handshake is not part of it).
    async fn session(io: DuplexStream, plan: &WsPlan, cancel: &CancellationToken, commands: Option<CommandRx>) -> SessionOutput {
        session_with(io, plan, cancel, commands, CancellationToken::new()).await
    }

    /// [`session`] with the token an interrupted write cancels.
    async fn session_with(
        io: DuplexStream,
        plan: &WsPlan,
        cancel: &CancellationToken,
        commands: Option<CommandRx>,
        write_interrupted: CancellationToken,
    ) -> SessionOutput {
        let events = EventCtx::none();
        let interactive = commands.is_some();
        let cx = SessionCtx {
            plan,
            events: &events,
            cancel,
            interactive,
            total_deadline: if interactive { None } else { deadline_from(plan.timeouts.total_ms) },
            stats: crate::stats::ConnStats::new(),
            written_before: 0,
            read_before: 0,
            status: 101,
            response: response_record(101, http::Version::HTTP_11, vec![], body_capture(BodyCompleteness::NoBody, 0, &[], None)),
            deflate: None,
            extensions: None,
            write_interrupted,
        };
        let rec = Recorder::new(0, events.clone());
        let obs = new_attempt(0, AttemptReason::Initial, "GET", &plan.display_url);
        let run = run_session(io, rec, obs, SessionFacts::default(), commands, cx);
        tokio::time::timeout(Duration::from_secs(5), run).await.expect("the session must end although the peer never reads")
    }

    fn cancel_after(ms: u64) -> CancellationToken {
        let cancel = CancellationToken::new();
        let c = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(ms)).await;
            c.cancel();
        });
        cancel
    }

    /// Far larger than the pipe: the write only finishes if the peer reads.
    fn big_text() -> WsMessage {
        WsMessage::Text { text: "x".repeat(1 << 20) }
    }

    fn failure(out: &SessionOutput) -> Option<FailureKind> {
        out.attempts[0].observation.failure.as_ref().map(|f| f.kind)
    }

    fn closed(out: &SessionOutput) -> (Option<u16>, ClosedBy) {
        match &out.status {
            ProtocolStatus::WebSocket { close_code, closed_by, .. } => (*close_code, *closed_by),
            other => panic!("not a WebSocket status: {other:?}"),
        }
    }

    #[tokio::test]
    async fn cancel_ends_a_scripted_write_the_peer_never_reads() {
        let (io, _peer) = tokio::io::duplex(1024);
        let plan = plan(vec![big_text()], None);
        let out = session(io, &plan, &cancel_after(100), None).await;
        assert_eq!(failure(&out), Some(FailureKind::Canceled));
        assert_eq!(closed(&out), (None, ClosedBy::Client), "no Close frame follows a partly written message");
        assert_eq!(out.transcript.unwrap().sent_count, 0, "the stalled message is not recorded as sent");
    }

    #[tokio::test]
    async fn the_total_deadline_ends_a_scripted_write_the_peer_never_reads() {
        let (io, _peer) = tokio::io::duplex(1024);
        let plan = plan(vec![big_text()], Some(200));
        let out = session(io, &plan, &CancellationToken::new(), None).await;
        assert_eq!(failure(&out), Some(FailureKind::TotalTimeout));
        assert_eq!(closed(&out), (None, ClosedBy::Timeout));
    }

    #[tokio::test]
    async fn cancel_ends_an_interactive_send_the_peer_never_reads() {
        let (io, _peer) = tokio::io::duplex(1024);
        let plan = plan(vec![], None);
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        tx.send(SessionCommand::SendText { text: "x".repeat(1 << 20) }).await.unwrap();
        let out = session(io, &plan, &cancel_after(200), Some(rx)).await;
        assert_eq!(failure(&out), Some(FailureKind::Canceled));
        assert_eq!(out.transcript.unwrap().sent_count, 0);
        drop(tx);
    }

    /// A 52-byte text is 58 bytes on the wire (masked): it fits a 64-byte pipe, a Close frame after it does not.
    fn filler() -> WsMessage {
        WsMessage::Text { text: "y".repeat(52) }
    }

    #[tokio::test]
    async fn a_close_command_the_peer_never_reads_is_bounded_by_the_close_wait() {
        let (io, _peer) = tokio::io::duplex(64);
        let mut plan = plan(vec![filler()], None);
        plan.idle_close_ms = 250;
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        tx.send(SessionCommand::Close { code: 1000, reason: String::new() }).await.unwrap();
        // Never canceled: only the close wait bounds the Close frame.
        let out = session(io, &plan, &CancellationToken::new(), Some(rx)).await;
        assert_eq!(failure(&out), None);
        assert_eq!(closed(&out), (Some(1000), ClosedBy::Client));
        let t = out.transcript.unwrap();
        assert_eq!(t.sent_count, 1);
        assert!(t.messages.iter().any(|m| m.kind == "close_incomplete"), "{:?}", t.messages);
        assert!(!t.messages.iter().any(|m| m.kind == "close" && m.direction == Direction::Sent), "the Close frame was not written");
        drop(tx);
    }

    #[tokio::test]
    async fn the_close_sent_at_the_total_deadline_has_its_own_short_bound() {
        let (io, _peer) = tokio::io::duplex(64);
        let plan = plan(vec![filler()], Some(300));
        let started = Instant::now();
        let out = session(io, &plan, &CancellationToken::new(), None).await;
        assert!(started.elapsed() < Duration::from_secs(2), "{:?}", started.elapsed());
        assert_eq!(failure(&out), Some(FailureKind::TotalTimeout));
        let t = out.transcript.unwrap();
        assert!(t.messages.iter().any(|m| m.kind == "close_incomplete"), "{:?}", t.messages);
    }

    #[tokio::test]
    async fn cancel_ends_a_pong_the_peer_never_reads() {
        let (io, mut peer) = tokio::io::duplex(64);
        // The filler leaves 6 bytes of the pipe: the Pong to a 4-byte Ping (10 bytes masked) does not fit.
        let plan = plan(vec![filler()], None);
        // An unmasked server Ping with the payload "abcd".
        peer.write_all(&[0x89, 0x04, b'a', b'b', b'c', b'd']).await.unwrap();
        let out = session(io, &plan, &cancel_after(200), None).await;
        let f = out.attempts[0].observation.failure.as_ref().expect("canceled");
        assert_eq!(f.kind, FailureKind::Canceled);
        assert!(f.message.contains("while a write was pending"), "the cancel must interrupt the Pong flush: {}", f.message);
        let t = out.transcript.unwrap();
        assert!(t.messages.iter().any(|m| m.kind == "ping" && m.direction == Direction::Received));
        assert!(!t.messages.iter().any(|m| m.kind == "pong"), "the stalled Pong is not recorded as sent");
        drop(peer);
    }

    /// An unmasked text frame from the server that is not valid UTF-8.
    const INVALID_UTF8_TEXT: [u8; 4] = [0x81, 0x02, 0xff, 0xfe];

    /// The Close frame Anvil sends after a peer's protocol violation is
    /// bounded; when the peer is not reading it may be left partly written,
    /// so the write counts as interrupted (an HTTP/3 stream is then reset,
    /// not finished) and nothing more is written or read.
    #[tokio::test]
    async fn a_violation_close_the_peer_never_reads_is_an_interrupted_write() {
        let (io, mut peer) = tokio::io::duplex(64);
        // The filler leaves 6 bytes of the pipe: the 1007 Close frame (21 bytes masked) does not fit.
        let plan = plan(vec![filler()], None);
        peer.write_all(&INVALID_UTF8_TEXT).await.unwrap();
        let interrupted = CancellationToken::new();
        let out = session_with(io, &plan, &CancellationToken::new(), None, interrupted.clone()).await;
        assert_eq!(failure(&out), Some(FailureKind::WsProtocolError));
        assert!(interrupted.is_cancelled(), "the stalled Close frame counts as an interrupted write");
        let t = out.transcript.unwrap();
        assert!(t.messages.iter().any(|m| m.kind == "close_incomplete"), "{:?}", t.messages);
        assert!(!t.messages.iter().any(|m| m.kind == "close" && m.direction == Direction::Sent), "the Close frame was not written");
        drop(peer);
    }

    /// Positive control: a peer that reads gets the Close frame, and no write
    /// was interrupted.
    #[tokio::test]
    async fn a_violation_close_the_peer_reads_is_sent() {
        let (io, mut peer) = tokio::io::duplex(1024);
        let plan = plan(vec![], None);
        peer.write_all(&INVALID_UTF8_TEXT).await.unwrap();
        let interrupted = CancellationToken::new();
        let out = session_with(io, &plan, &CancellationToken::new(), None, interrupted.clone()).await;
        assert_eq!(failure(&out), Some(FailureKind::WsProtocolError));
        assert!(!interrupted.is_cancelled());
        assert_eq!(closed(&out), (Some(1007), ClosedBy::Client));
        let t = out.transcript.unwrap();
        assert!(t.messages.iter().any(|m| m.kind == "close" && m.direction == Direction::Sent), "{:?}", t.messages);
        drop(peer);
    }

    #[tokio::test]
    async fn a_peer_that_reads_gets_every_scripted_message_and_a_clean_close() {
        let (io, peer) = tokio::io::duplex(1024);
        tokio::spawn(async move {
            let mut server = WebSocketStream::from_raw_socket(peer, Role::Server, None).await;
            // Echo text; after the client's Close, the next poll sends the reply and ends the stream.
            while let Some(Ok(m)) = server.next().await {
                if let Message::Text(t) = m {
                    let _ = server.send(Message::Text(t)).await;
                }
            }
        });
        let mut plan = plan(vec![big_text()], Some(10_000));
        plan.expect_messages = 1;
        let out = session(io, &plan, &CancellationToken::new(), None).await;
        assert_eq!(failure(&out), None);
        assert_eq!(closed(&out), (Some(1000), ClosedBy::Client));
        let t = out.transcript.unwrap();
        assert_eq!((t.sent_count, t.received_count), (1, 1));
        assert_eq!(t.received_bytes, 1 << 20);
    }
}
