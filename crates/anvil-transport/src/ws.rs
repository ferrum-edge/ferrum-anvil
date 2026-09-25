//! WebSocket sessions (RFC 6455) over the instrumented connector.
//!
//! Bootstraps are separate, individually tested features:
//! * **HTTP/1.1 Upgrade** (RFC 6455 §4): `GET` with `Upgrade: websocket`; the
//!   `101` response's `Upgrade`, `Connection` and `Sec-WebSocket-Accept` are
//!   verified before the session starts.
//! * **HTTP/2 extended CONNECT** (RFC 8441): the client waits for the peer's
//!   `SETTINGS_ENABLE_CONNECT_PROTOCOL`, then sends `CONNECT` with
//!   `:protocol = websocket`; a `200` opens the tunnel stream.
//! * **HTTP/3 extended CONNECT** (RFC 9220) is **not supported**: the `h3`
//!   0.0.8 crate models `:protocol` as a closed type (`webtransport` and
//!   `connect-udp` only), so a client cannot send `:protocol = websocket` and
//!   its header decoder rejects the value. Anvil returns a typed
//!   `unsupported_combination` failure before any traffic instead of
//!   pretending, and never silently falls back to another bootstrap.
//!
//! Session evidence: every message (bounded, redacted), ping/pong, the close
//! code/reason and who closed. A connection that ends without a Close frame
//! is reported as 1006 with `closed_by = abnormal` — 1006 is a local
//! designation, never a code the peer transmitted.

use crate::connector::{ProxyPlan, Target};
use crate::dns::DnsConfig;
use crate::errors::{HyperStage, classify_hyper};
use crate::http::sleep_until_opt;
use crate::recorder::{EventCtx, Recorder};
use crate::session::*;
use crate::tls::PreparedTls;
use anvil_domain::events::{ExecutionEvent, SessionCommand};
use anvil_domain::execution::*;
use anvil_domain::outcome::{ClosedBy, ProtocolStatus};
use anvil_domain::request::{WsBootstrap, WsMessage};
use anvil_domain::settings::{Limits, Timeouts};
use bytes::{Bytes, BytesMut};
use futures::{SinkExt, StreamExt};
use http::{HeaderMap, HeaderName, HeaderValue, Method, Request};
use http_body_util::{BodyExt, Empty};
use hyper_util::rt::TokioIo;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::{CloseFrame, Role, WebSocketConfig};
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
    pub authority: String,
    /// Origin-form target (`/path?query`).
    pub request_target: String,
    pub headers: Vec<(HeaderName, HeaderValue)>,
    pub subprotocols: Vec<String>,
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
}

/// Why a bootstrap cannot be used with the current crate versions, if so.
pub fn bootstrap_unsupported(b: WsBootstrap) -> Option<TransportFailure> {
    match b {
        WsBootstrap::Http3ExtendedConnect => Some(
            TransportFailure::new(
                Phase::Prepare,
                FailureKind::UnsupportedCombination,
                "WebSocket over HTTP/3 (RFC 9220 extended CONNECT) is not supported: the h3 0.0.8 library cannot send the \
                 ':protocol = websocket' pseudo-header (it only models 'webtransport' and 'connect-udp'). Nothing was sent; \
                 choose the HTTP/1.1 Upgrade or HTTP/2 extended CONNECT bootstrap.",
            )
            .with_field("websocket.bootstrap"),
        ),
        _ => None,
    }
}

type Ws = WebSocketStream<TokioIo<hyper::upgrade::Upgraded>>;

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

pub async fn run(plan: &WsPlan, events: &EventCtx, cancel: &CancellationToken, mut commands: Option<CommandRx>) -> SessionOutput {
    let interactive = commands.is_some();
    let mut rec = Recorder::new(0, events.clone());
    events.emit(ExecutionEvent::AttemptStarted { execution_id: events.execution_id, attempt: 0 });
    let h2 = plan.bootstrap == WsBootstrap::Http2ExtendedConnect;
    let mut obs = new_attempt(0, AttemptReason::Initial, if h2 { "CONNECT" } else { "GET" }, &plan.display_url);
    let mut facts = SessionFacts::default();
    let early = |rec: Recorder, obs: AttemptObservation, f: TransportFailure, facts: SessionFacts| {
        SessionOutput::single(fail_attempt(rec, obs, f, DispatchState::NotDispatched, events), None, ProtocolStatus::None, facts)
    };
    if let Some(f) = bootstrap_unsupported(plan.bootstrap) {
        return early(rec, obs, f, facts);
    }
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
    let est = match establish_guarded(&mut rec, &target, &plan.dns, &plan.timeouts, plan.proxy.as_ref(), cancel, total_deadline).await {
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
        };
        return SessionOutput::single(
            crate::http::AttemptOutput { observation: obs, response: Some(response), body: captured },
            None,
            ps,
            facts,
        );
    }

    let response = response_record(status, version, headers.clone(), body_capture(BodyCompleteness::NoBody, 0, &[], content_type));
    let handshake_fail = |rec: Recorder, mut obs: AttemptObservation, msg: String, facts: SessionFacts| {
        let mut f = TransportFailure::new(Phase::ProtocolHandshake, FailureKind::WsProtocolError, msg);
        f.status = Some(status);
        obs.failure = Some(f);
        let obs = finish_attempt(rec, obs, events);
        let ps = ProtocolStatus::WebSocket {
            handshake_status: Some(status),
            close_code: None,
            close_reason: String::new(),
            closed_by: ClosedBy::NotClosed,
        };
        SessionOutput::single(
            crate::http::AttemptOutput { observation: obs, response: Some(response.clone()), body: Bytes::new() },
            None,
            ps,
            facts,
        )
    };
    if !h2 && let Err(e) = validate_upgrade(resp.headers(), &key) {
        return handshake_fail(rec, obs, format!("invalid WebSocket handshake response: {e}"), facts);
    }
    if let Some(p) = resp.headers().get("sec-websocket-protocol").and_then(|v| v.to_str().ok()).map(|s| s.trim().to_string()) {
        if !plan.subprotocols.iter().any(|s| s.eq_ignore_ascii_case(&p)) {
            return handshake_fail(rec, obs, format!("the server selected subprotocol '{p}', which was not offered"), facts);
        }
        facts.notes.push(format!("subprotocol negotiated: {p}"));
        facts.subprotocol = Some(p);
    } else if !plan.subprotocols.is_empty() {
        facts.notes.push(format!("subprotocols offered ({}) but the server selected none", plan.subprotocols.join(", ")));
    }
    let upgraded = tokio::select! {
        u = hyper::upgrade::on(resp) => Some(u),
        _ = cancel.cancelled() => None,
    };
    let upgraded = match upgraded {
        Some(Ok(u)) => u,
        Some(Err(e)) => return handshake_fail(rec, obs, format!("the connection could not be switched to WebSocket: {e}"), facts),
        None => {
            let f = TransportFailure::new(Phase::ProtocolHandshake, FailureKind::Canceled, "canceled while opening the WebSocket stream");
            obs.failure = Some(f);
            let obs = finish_attempt(rec, obs, events);
            let ps = ProtocolStatus::WebSocket {
                handshake_status: Some(status),
                close_code: None,
                close_reason: String::new(),
                closed_by: ClosedBy::Client,
            };
            return SessionOutput::single(
                crate::http::AttemptOutput { observation: obs, response: Some(response), body: Bytes::new() },
                None,
                ps,
                facts,
            );
        }
    };

    // ---- session ----
    let s_idx = rec.start(Phase::Session);
    let max = plan.max_message_bytes.clamp(16, usize::MAX as u64) as usize;
    let cfg = WebSocketConfig::default().max_message_size(Some(max)).max_frame_size(Some(max));
    let mut ws: Ws = WebSocketStream::from_raw_socket(TokioIo::new(upgraded), Role::Client, Some(cfg)).await;
    let mut tr = Transcript::new(rec.t0, plan.transcript, events.clone(), plan.redact.clone());
    let mut close: Option<Close> = None;
    let mut client_close_sent: Option<(u16, String)> = None;
    let mut peer_close_seen = false;
    let mut failure: Option<TransportFailure> = None;
    let close_wait = Duration::from_millis(plan.idle_close_ms.clamp(250, 5_000));
    let mut close_deadline: Option<Instant> = None;

    // Scripted messages (automation, and the opening of interactive sessions).
    let mut send_error: Option<tungstenite::Error> = None;
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
        if let Err(e) = ws.send(msg).await {
            send_error = Some(e);
            break;
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
        if let Some(e) = pending_error.take() {
            classify_ws_error(e, &mut close, &mut failure, &mut ws, &mut tr, peer_close_seen, &stats).await;
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
                        let _ = ws.flush().await; // tungstenite queued the Pong
                        tr.control(Direction::Sent, "pong", &p);
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
                if !interactive && expect > 0 && tr.received_count() >= expect && client_close_sent.is_none() && !peer_close_seen {
                    match ws.send(close_frame(1000, "")).await {
                        Ok(()) => {
                            tr.control(Direction::Sent, "close", b"1000");
                            client_close_sent = Some((1000, String::new()));
                            close_deadline = Some(Instant::now() + close_wait);
                        }
                        Err(e) => pending_error = Some(e),
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
                let r = match c {
                    Some(SessionCommand::SendText { text }) => {
                        let r = ws.send(Message::Text(text.clone().into())).await;
                        if r.is_ok() {
                            tr.data(Direction::Sent, "text", text.as_bytes());
                        }
                        r
                    }
                    Some(SessionCommand::SendBinaryHex { hex }) => match decode_hex(&hex) {
                        Ok(b) => {
                            let r = ws.send(Message::Binary(Bytes::from(b.clone()))).await;
                            if r.is_ok() {
                                tr.data(Direction::Sent, "binary", &b);
                            }
                            r
                        }
                        Err(e) => {
                            tr.note("error", &format!("binary message not sent: {e}"));
                            Ok(())
                        }
                    },
                    Some(SessionCommand::Ping) => {
                        let r = ws.send(Message::Ping(Bytes::from_static(b"anvil"))).await;
                        if r.is_ok() {
                            tr.control(Direction::Sent, "ping", b"anvil");
                        }
                        r
                    }
                    Some(SessionCommand::HalfClose) => {
                        tr.note("unsupported_command", "WebSocket has no half-close; send Close instead");
                        Ok(())
                    }
                    Some(SessionCommand::Close { code, reason }) => {
                        let r = ws.send(close_frame(code, &reason)).await;
                        if r.is_ok() {
                            tr.control(Direction::Sent, "close", format!("{code} {reason}").trim().as_bytes());
                            client_close_sent = Some((code, reason));
                            close_deadline = Some(Instant::now() + close_wait);
                        }
                        r
                    }
                    None => {
                        // The session handle was dropped: close politely.
                        let r = ws.send(close_frame(1000, "session ended")).await;
                        if r.is_ok() {
                            tr.control(Direction::Sent, "close", b"1000 session ended");
                            client_close_sent = Some((1000, "session ended".into()));
                            close_deadline = Some(Instant::now() + close_wait);
                        }
                        r
                    }
                };
                if let Err(e) = r {
                    pending_error = Some(e);
                }
            }
            Ev::Idle => match ws.send(close_frame(1000, "")).await {
                Ok(()) => {
                    tr.control(Direction::Sent, "close", b"1000 (idle)");
                    client_close_sent = Some((1000, String::new()));
                    close_deadline = Some(Instant::now() + close_wait);
                }
                Err(e) => pending_error = Some(e),
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
                let _ = ws.send(close_frame(1001, "deadline")).await;
                tr.control(Direction::Sent, "close", b"1001 deadline");
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
                let _ = tokio::time::timeout(Duration::from_millis(250), ws.send(close_frame(1001, "canceled"))).await;
                tr.control(Direction::Sent, "close", b"1001 canceled");
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
    let ps = ProtocolStatus::WebSocket {
        handshake_status: Some(status),
        close_code: close.code,
        close_reason: reason,
        closed_by: close.closed_by,
    };
    SessionOutput::single(
        crate::http::AttemptOutput { observation: obs, response: Some(response), body: Bytes::new() },
        Some(tr.finish()),
        ps,
        facts,
    )
}

/// Map a WebSocket error to the close outcome and a typed failure. For
/// local policy violations the client sends the matching Close code.
async fn classify_ws_error(
    e: tungstenite::Error,
    close: &mut Option<Close>,
    failure: &mut Option<TransportFailure>,
    ws: &mut Ws,
    tr: &mut Transcript,
    peer_close_seen: bool,
    stats: &crate::stats::ConnStats,
) {
    use tungstenite::Error as E;
    use tungstenite::error::ProtocolError as P;
    // Once the peer's Close frame has arrived the WebSocket session is over;
    // how the TCP/TLS connection is torn down afterwards (FIN, RST, or no TLS
    // close_notify) does not change the close outcome.
    if peer_close_seen && matches!(e, E::ConnectionClosed | E::AlreadyClosed | E::Io(_) | E::Protocol(P::ResetWithoutClosingHandshake)) {
        if let E::Io(ioe) = &e {
            tr.note("transport_teardown", &format!("the connection was torn down after the close handshake ({:?})", ioe.kind()));
        }
        return;
    }
    let mut close_with = |code: u16, reason: &str| {
        *close = Some(Close { code: Some(code), reason: reason.into(), closed_by: ClosedBy::Client });
        (code, reason.to_string())
    };
    match e {
        // A clean end; the caller derives the outcome from the Close frames seen.
        E::ConnectionClosed | E::AlreadyClosed => {}
        E::Capacity(c) => {
            let (code, reason) = close_with(1009, "message too big");
            *failure = Some(TransportFailure::new(
                Phase::Session,
                FailureKind::WsMessageTooLarge,
                format!(
                    "an inbound message exceeded Anvil's local message limit ({c}); Anvil closed the session with 1009. This is a local size policy, not a protocol corruption"
                ),
            ));
            send_close_and_drain(ws, tr, code, &reason).await;
        }
        E::Utf8(_) => {
            let (code, reason) = close_with(1007, "invalid UTF-8");
            *failure = Some(TransportFailure::new(
                Phase::Session,
                FailureKind::WsProtocolError,
                "a text message was not valid UTF-8; Anvil closed with 1007",
            ));
            send_close_and_drain(ws, tr, code, &reason).await;
        }
        E::Protocol(P::ResetWithoutClosingHandshake) => {
            *close = Some(Close { code: Some(1006), reason: String::new(), closed_by: ClosedBy::Abnormal });
            *failure = Some(TransportFailure::new(
                Phase::Session,
                FailureKind::BodyIncomplete,
                "the connection ended without a WebSocket Close frame (reported as 1006; 1006 is never sent by a peer)",
            ));
        }
        E::Protocol(p) => {
            let (code, reason) = close_with(1002, "protocol error");
            *failure = Some(TransportFailure::new(
                Phase::Session,
                FailureKind::WsProtocolError,
                format!("WebSocket protocol violation by the peer: {p}"),
            ));
            send_close_and_drain(ws, tr, code, &reason).await;
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

async fn send_close_and_drain(ws: &mut Ws, tr: &mut Transcript, code: u16, reason: &str) {
    if tokio::time::timeout(Duration::from_millis(500), ws.send(close_frame(code, reason))).await.map(|r| r.is_ok()).unwrap_or(false) {
        tr.control(Direction::Sent, "close", format!("{code} {reason}").as_bytes());
    }
    // Give the peer a bounded moment to acknowledge; ignore whatever arrives.
    let _ = tokio::time::timeout(Duration::from_millis(500), async {
        while let Some(Ok(m)) = ws.next().await {
            if let Message::Close(_) = m {
                tr.control(Direction::Received, "close", b"(acknowledgement)");
                break;
            }
        }
    })
    .await;
}
