//! Server-sent events (`text/event-stream`) with an incremental parser.
//!
//! * The stream is parsed as bytes arrive (id / event / data / retry fields,
//!   comments, CR / LF / CRLF line endings, a leading BOM) — the body is never
//!   buffered unboundedly: raw bytes are captured only up to the capture
//!   limit and the transcript keeps a bounded event history.
//! * Stop conditions are explicit: `max_events`, an idle timeout (no bytes at
//!   all, so keep-alive comments count as activity), the total deadline, an
//!   explicit cancel/Close command, or the server ending the stream.
//! * Reconnection happens only when enabled, only after an abnormal end
//!   (reset / truncated stream), bounded in count, honoring the server's
//!   `retry:` delay and sending `Last-Event-ID`. Each reconnection is its own
//!   recorded attempt. A clean end of stream is recorded as the server
//!   closing the stream and is not reconnected.
//! * Transports: HTTP/1.1 and HTTP/2 over the instrumented TCP connector, or
//!   HTTP/3 over QUIC (`Http3Only` / `Http3WithFallback`): DNS and the QUIC
//!   handshake are measured (no TCP phase) and the event stream is parsed
//!   from the request stream's DATA frames as they arrive. Every attempt,
//!   including each reconnection, uses a fresh QUIC connection. Forced
//!   HTTP/3 never touches TCP; the automatic policy records the failed
//!   HTTP/3 attempt and then falls back to TCP as a separate attempt.

use crate::connector::{ProxyPlan, Target};
use crate::dns::DnsConfig;
use crate::errors::{HyperStage, classify_hyper};
use crate::http::{AttemptOutput, sleep_until_opt};
use crate::recorder::{EventCtx, Recorder};
use crate::session::*;
use crate::tls::PreparedTls;
use anvil_domain::events::{ExecutionEvent, SessionCommand};
use anvil_domain::execution::*;
use anvil_domain::outcome::{ClosedBy, ProtocolStatus};
use anvil_domain::settings::{HttpVersionPolicy, Limits, Timeouts};
use bytes::{Buf, Bytes, BytesMut};
use http::{HeaderMap, HeaderName, HeaderValue, Method, Request};
use http_body_util::{BodyExt, Full};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

/// One dispatched event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SseEvent {
    /// The last event id in effect when the event was dispatched.
    pub id: Option<String>,
    pub event_type: String,
    pub data: String,
}

/// Incremental `text/event-stream` parser (HTML Living Standard §9.2.6).
#[derive(Debug, Default)]
pub struct SseParser {
    line: Vec<u8>,
    data: String,
    has_data: bool,
    event_type: String,
    /// Last event ID buffer (persists across events).
    pub last_event_id: Option<String>,
    /// Reconnection time requested by the server (`retry:`).
    pub retry_ms: Option<u64>,
    bom_checked: bool,
    pending_cr: bool,
    max_line: usize,
}

impl SseParser {
    pub fn new(max_line: usize) -> Self {
        SseParser { max_line: max_line.max(1024), ..Default::default() }
    }

    /// Discard partially received event state on a new connection; the last
    /// event ID and the reconnection time persist (spec).
    pub fn reset_stream(&mut self) {
        self.line.clear();
        self.data.clear();
        self.has_data = false;
        self.event_type.clear();
        self.bom_checked = false;
        self.pending_cr = false;
    }

    /// Feed bytes; dispatched events are appended to `out`. Returns an error
    /// when a single line exceeds the configured bound.
    pub fn feed(&mut self, mut chunk: &[u8], out: &mut Vec<SseEvent>) -> Result<(), String> {
        if !self.bom_checked && !chunk.is_empty() {
            self.bom_checked = true;
            if chunk.starts_with(&[0xEF, 0xBB, 0xBF]) {
                chunk = &chunk[3..];
            }
        }
        for &b in chunk {
            if self.pending_cr {
                self.pending_cr = false;
                if b == b'\n' {
                    continue; // CRLF
                }
            }
            match b {
                b'\n' => self.end_line(out),
                b'\r' => {
                    self.pending_cr = true;
                    self.end_line(out);
                }
                _ => {
                    if self.line.len() >= self.max_line {
                        return Err(format!("an event-stream line exceeded {} bytes", self.max_line));
                    }
                    self.line.push(b);
                }
            }
        }
        Ok(())
    }

    fn end_line(&mut self, out: &mut Vec<SseEvent>) {
        let line = String::from_utf8_lossy(&std::mem::take(&mut self.line)).into_owned();
        if line.is_empty() {
            if self.has_data {
                let mut data = std::mem::take(&mut self.data);
                if data.ends_with('\n') {
                    data.pop();
                }
                let event_type = if self.event_type.is_empty() { "message".to_string() } else { std::mem::take(&mut self.event_type) };
                out.push(SseEvent { id: self.last_event_id.clone(), event_type, data });
            }
            self.data.clear();
            self.has_data = false;
            self.event_type.clear();
            return;
        }
        if line.starts_with(':') {
            return; // comment / keep-alive
        }
        let (field, value) = match line.split_once(':') {
            Some((f, v)) => (f.to_string(), v.strip_prefix(' ').unwrap_or(v).to_string()),
            None => (line.clone(), String::new()),
        };
        match field.as_str() {
            "event" => self.event_type = value,
            "data" => {
                if self.data.len() + value.len() <= self.max_line.saturating_mul(4) {
                    self.data.push_str(&value);
                    self.data.push('\n');
                }
                self.has_data = true;
            }
            // An id containing NUL is ignored (spec); a non-numeric retry too.
            "id" if !value.contains('\0') => self.last_event_id = Some(value),
            "retry" if !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()) => self.retry_ms = value.parse().ok(),
            _ => {}
        }
    }
}

#[derive(Clone)]
pub struct SsePlan {
    pub method: Method,
    pub https: bool,
    pub host: String,
    pub port: u16,
    pub authority: String,
    pub request_target: String,
    pub headers: Vec<(HeaderName, HeaderValue)>,
    pub body: Bytes,
    pub version: HttpVersionPolicy,
    pub timeouts: Timeouts,
    pub limits: Limits,
    pub dns: DnsConfig,
    pub proxy: Option<ProxyPlan>,
    pub tls: Option<Arc<PreparedTls>>,
    pub display_url: String,
    /// Stop after this many events (0 = until cancel/idle/deadline/end).
    pub max_events: u32,
    pub idle_timeout_ms: u64,
    pub last_event_id: Option<String>,
    pub reconnect: bool,
    pub max_reconnects: u32,
    pub transcript: TranscriptLimits,
    pub redact: Option<RedactFn>,
}

async fn next_cmd(rx: &mut Option<CommandRx>) -> Option<SessionCommand> {
    match rx {
        Some(r) => r.recv().await,
        None => std::future::pending().await,
    }
}

/// Version policies that cannot be honoured fail before traffic. Forced
/// HTTP/3 needs an `https://` URL (QUIC is always encrypted) and cannot go
/// through an HTTP/SOCKS proxy. The automatic HTTP/3 policy instead records
/// the refused HTTP/3 attempt and falls back to TCP, as HTTP requests do.
pub fn version_unsupported(v: HttpVersionPolicy, https: bool, proxied: bool) -> Option<TransportFailure> {
    if v != HttpVersionPolicy::Http3Only {
        return None;
    }
    h3_unsupported(https, proxied)
}

fn h3_unsupported(https: bool, proxied: bool) -> Option<TransportFailure> {
    if !https {
        return Some(
            TransportFailure::new(
                Phase::Prepare,
                FailureKind::UnsupportedCombination,
                "server-sent events over HTTP/3 need an https:// URL (QUIC is always encrypted); use HTTP/1.1 or HTTP/2 for http://",
            )
            .with_field("settings.http_version"),
        );
    }
    if proxied {
        return Some(
            TransportFailure::new(
                Phase::Prepare,
                FailureKind::UnsupportedCombination,
                "server-sent events over HTTP/3 cannot be sent through the configured HTTP/SOCKS proxy",
            )
            .with_field("settings.proxy"),
        );
    }
    None
}

enum End {
    /// Server ended the stream cleanly.
    Peer,
    /// Planned client stop (max events, Close command).
    Client,
    Idle,
    Failed(TransportFailure),
    Canceled,
    Deadline,
}

type H3Stream = h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

/// Where one attempt's event-stream bytes come from.
enum Source {
    Tcp {
        body: hyper::body::Incoming,
        stats: Arc<crate::stats::ConnStats>,
        /// Kept so the HTTP/2 connection is not shut down under the stream.
        _sender: HttpSender<Full<Bytes>>,
        written_before: u64,
        read_before: u64,
    },
    H3 {
        stream: Box<H3Stream>,
        quic: quinn::Connection,
        /// h3 closes the connection once its last request sender is dropped.
        _send: crate::h3::SendReq,
        tx_before: u64,
        rx_before: u64,
    },
}

impl Source {
    /// The next DATA bytes; `None` is a clean end of stream. Cancel-safe: a
    /// chunk is only taken from the connection once it is ready.
    async fn next(&mut self, phase: Phase) -> Option<Result<Bytes, TransportFailure>> {
        match self {
            Source::Tcp { body, stats, .. } => loop {
                match body.frame().await {
                    None => return None,
                    Some(Ok(frame)) => {
                        if let Ok(d) = frame.into_data() {
                            return Some(Ok(d));
                        }
                    }
                    Some(Err(e)) => {
                        let mut f = classify_hyper(&e, HyperStage::Body);
                        f.phase = phase;
                        if let Some((k, a)) = stats.tls_error() {
                            f.kind = k;
                            f.tls_alert = a;
                        }
                        return Some(Err(f));
                    }
                }
            },
            Source::H3 { stream, .. } => match stream.recv_data().await {
                Ok(Some(mut chunk)) => {
                    let n = chunk.remaining();
                    Some(Ok(chunk.copy_to_bytes(n)))
                }
                Ok(None) => None,
                Err(e) => {
                    Some(Err(crate::h3::stream_failure(&e, phase, FailureKind::BodyReset, "the HTTP/3 event stream ended abnormally")))
                }
            },
        }
    }

    /// Connection byte counters for this attempt (TCP bytes, or QUIC UDP
    /// payload bytes for HTTP/3), measured since the request was sent.
    fn connection_bytes(&self) -> (u64, u64) {
        match self {
            Source::Tcp { stats, written_before, read_before, .. } => {
                (stats.bytes_written().saturating_sub(*written_before), stats.bytes_read().saturating_sub(*read_before))
            }
            Source::H3 { quic, tx_before, rx_before, .. } => {
                let s = quic.stats();
                (s.udp_tx.bytes.saturating_sub(*tx_before), s.udp_rx.bytes.saturating_sub(*rx_before))
            }
        }
    }

    /// End the attempt's connection. HTTP/3: close the QUIC connection with
    /// `H3_NO_ERROR`, which also ends the request stream. (h3-quinn 0.0.10
    /// panics on `stop_sending` after a canceled read, so the stream is not
    /// stopped on its own.)
    fn close(self) {
        if let Source::H3 { stream, quic, .. } = self {
            drop(stream);
            quic.close(crate::h3::H3_NO_ERROR.into(), b"");
        }
    }
}

/// An attempt whose response head arrived.
struct Opened {
    status: u16,
    version: http::Version,
    headers: HeaderMap,
    source: Source,
}

/// Request headers for an event stream. `pseudo` (HTTP/2, HTTP/3) drops
/// connection-specific fields; HTTP/1.1 gets a `Host`.
fn request_headers(plan: &SsePlan, pseudo: bool, last_event_id: Option<&String>) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for (n, v) in &plan.headers {
        if pseudo
            && (n == http::header::HOST
                || n == http::header::CONNECTION
                || n == http::header::TRANSFER_ENCODING
                || n == http::header::UPGRADE
                || n.as_str() == "keep-alive")
        {
            continue;
        }
        headers.append(n.clone(), v.clone());
    }
    if !pseudo && !headers.contains_key(http::header::HOST) {
        headers.insert(http::header::HOST, HeaderValue::from_str(&plan.authority).unwrap_or(HeaderValue::from_static("localhost")));
    }
    headers.insert(http::header::ACCEPT, HeaderValue::from_static("text/event-stream"));
    if !headers.contains_key(http::header::CACHE_CONTROL) {
        headers.insert(http::header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    }
    if let Some(id) = last_event_id
        && let Ok(v) = HeaderValue::from_str(id)
    {
        headers.insert("last-event-id", v);
    }
    headers
}

/// HTTP/1.1 or HTTP/2 over the instrumented TCP (+TLS, +proxy) connector.
async fn open_tcp(
    plan: &SsePlan,
    rec: &mut Recorder,
    obs: &mut AttemptObservation,
    last_event_id: Option<&String>,
    cancel: &CancellationToken,
    total_deadline: Option<Instant>,
) -> Result<Opened, (TransportFailure, DispatchState)> {
    if plan.https && plan.tls.is_none() {
        let f = TransportFailure::new(Phase::Prepare, FailureKind::TlsProfileInvalid, "no TLS configuration for an https:// event stream");
        return Err((f, DispatchState::NotDispatched));
    }
    let alpn: &[&str] = match (plan.https, plan.version) {
        (false, _) => &[],
        (true, HttpVersionPolicy::Http1Only) => &["http/1.1"],
        (true, HttpVersionPolicy::Http2Only) => &["h2"],
        (true, _) => &["h2", "http/1.1"],
    };
    let target = Target { host: &plan.host, port: plan.port, tls: plan.tls.as_deref(), alpn, http_forward_via_proxy: false };
    let est = match establish_guarded(rec, &target, &plan.dns, &plan.timeouts, plan.proxy.as_ref(), cancel, total_deadline).await {
        Ok(e) => e,
        Err((f, o)) => {
            obs.connection = o;
            return Err((f, DispatchState::NotDispatched));
        }
    };
    let negotiated = est.observation.tls.as_ref().and_then(|t| t.alpn_negotiated.clone());
    let use_h2 = match plan.version {
        HttpVersionPolicy::H2c => true,
        HttpVersionPolicy::Http1Only => false,
        HttpVersionPolicy::Http2Only if negotiated.as_deref() != Some("h2") => {
            let f = TransportFailure::new(
                Phase::TlsHandshake,
                FailureKind::TlsAlpnMismatch,
                "HTTP/2 was required but the peer did not negotiate h2",
            );
            obs.connection = Some(est.observation);
            return Err((f, DispatchState::NotDispatched));
        }
        _ => negotiated.as_deref() == Some("h2"),
    };
    let HttpConn { mut sender, stats, observation: cobs, .. } = match http_handshake::<Full<Bytes>>(rec, est, use_h2, &plan.limits).await {
        Ok(x) => x,
        Err((f, o)) => {
            obs.connection = Some(o);
            return Err((f, DispatchState::NotDispatched));
        }
    };
    obs.connection = Some(cobs);

    let headers = request_headers(plan, use_h2, last_event_id);
    let uri = if use_h2 {
        format!("{}://{}{}", if plan.https { "https" } else { "http" }, plan.authority, plan.request_target)
    } else {
        plan.request_target.clone()
    };
    let mut req = match Request::builder().method(plan.method.clone()).uri(uri).body(Full::new(plan.body.clone())) {
        Ok(r) => r,
        Err(e) => {
            let f = TransportFailure::new(Phase::Prepare, FailureKind::InvalidUrl, format!("the request could not be built: {e}"));
            return Err((f, DispatchState::NotDispatched));
        }
    };
    let sent_headers = header_entries(&headers);
    *req.headers_mut() = headers;
    obs.bytes.request_headers_logical = logical_header_bytes(&sent_headers) + plan.request_target.len() as u64 + 16;
    obs.bytes.request_headers_estimated = use_h2;
    obs.bytes.request_body = plan.body.len() as u64;
    let written_before = stats.bytes_written();
    let read_before = stats.bytes_read();
    let w_idx = rec.start(Phase::RequestWrite);
    let h_idx;
    let resp = {
        let fut = sender.send(req);
        tokio::pin!(fut);
        rec.finish_with(w_idx, PhaseStatus::Completed, "request handed to the connection");
        h_idx = rec.start(Phase::AwaitResponseHeaders);
        let headers_deadline = deadline_from(plan.timeouts.response_headers_ms);
        tokio::select! {
            r = &mut fut => r.map_err(|e| {
                let mut f = classify_hyper(&e, HyperStage::AwaitHeaders);
                if let Some((k, a)) = stats.tls_error() { f.kind = k; f.tls_alert = a; }
                f
            }),
            _ = sleep_until_opt(headers_deadline) => Err(TransportFailure::new(Phase::AwaitResponseHeaders, FailureKind::ResponseHeadersTimeout,
                "no response headers before the response-header deadline").with_deadline(plan.timeouts.response_headers_ms)),
            _ = sleep_until_opt(total_deadline) => Err(TransportFailure::new(Phase::AwaitResponseHeaders, FailureKind::TotalTimeout,
                "total deadline elapsed before response headers").with_deadline(plan.timeouts.total_ms)),
            _ = cancel.cancelled() => Err(TransportFailure::new(Phase::AwaitResponseHeaders, FailureKind::Canceled, "canceled before response headers")),
        }
    };
    let resp = match resp {
        Ok(r) => r,
        Err(f) => {
            let d = if stats.bytes_written() > written_before { DispatchState::MayHaveBeenSent } else { DispatchState::NotDispatched };
            return Err((f, d));
        }
    };
    rec.finish(h_idx, PhaseStatus::Completed);
    let status = resp.status().as_u16();
    let version = resp.version();
    let headers = resp.headers().clone();
    let body = resp.into_body();
    Ok(Opened { status, version, headers, source: Source::Tcp { body, stats, _sender: sender, written_before, read_before } })
}

/// HTTP/3 over a fresh QUIC connection (DNS, QUIC handshake with TLS 1.3
/// inside; no TCP phase). The event stream is the request stream's DATA frames.
async fn open_h3(
    plan: &SsePlan,
    rec: &mut Recorder,
    obs: &mut AttemptObservation,
    last_event_id: Option<&String>,
    cancel: &CancellationToken,
    total_deadline: Option<Instant>,
) -> Result<Opened, (TransportFailure, DispatchState)> {
    if let Some(f) = h3_unsupported(plan.https, plan.proxy.is_some()) {
        return Err((f, DispatchState::NotDispatched));
    }
    let Some(tls) = plan.tls.clone() else {
        let f = TransportFailure::new(Phase::Prepare, FailureKind::TlsProfileInvalid, "no TLS configuration for an HTTP/3 event stream");
        return Err((f, DispatchState::NotDispatched));
    };
    let connected = {
        let connect =
            crate::h3::quic_connect(rec, &plan.host, plan.port, &plan.dns, &plan.timeouts, &tls, crate::h3::client_endpoint, cancel);
        tokio::select! {
            r = connect => Some(r),
            _ = sleep_until_opt(total_deadline) => None,
        }
    };
    let crate::h3::QuicConnected { quic, mut send, observation } = match connected {
        Some(Ok(c)) => c,
        Some(Err((f, cobs))) => {
            obs.connection = cobs;
            return Err((f, DispatchState::NotDispatched));
        }
        None => {
            let f = TransportFailure::new(
                rec.open_phase().unwrap_or(Phase::QuicHandshake),
                FailureKind::TotalTimeout,
                "total deadline elapsed during QUIC connection setup",
            )
            .with_deadline(plan.timeouts.total_ms);
            return Err((f, DispatchState::NotDispatched));
        }
    };
    obs.connection = Some(observation);
    let fail = |quic: &quinn::Connection, f: TransportFailure, d: DispatchState| {
        quic.close(crate::h3::H3_NO_ERROR.into(), b"");
        Err((f, d))
    };

    let headers = request_headers(plan, true, last_event_id);
    let authority = plan
        .headers
        .iter()
        .find(|(n, _)| n == http::header::HOST)
        .and_then(|(_, v)| v.to_str().ok().map(|s| s.to_string()))
        .unwrap_or_else(|| plan.authority.clone());
    let mut req = match Request::builder().method(plan.method.clone()).uri(format!("https://{authority}{}", plan.request_target)).body(()) {
        Ok(r) => r,
        Err(e) => {
            let f = TransportFailure::new(Phase::Prepare, FailureKind::InvalidUrl, format!("the request could not be built: {e}"));
            return fail(&quic, f, DispatchState::NotDispatched);
        }
    };
    let sent_headers = header_entries(&headers);
    *req.headers_mut() = headers;
    obs.bytes.request_headers_logical = logical_header_bytes(&sent_headers) + plan.request_target.len() as u64 + 16;
    obs.bytes.request_headers_estimated = true;
    obs.bytes.request_body = plan.body.len() as u64;
    let before = quic.stats();
    let w_idx = rec.start(Phase::RequestWrite);
    let write_deadline = deadline_from(plan.timeouts.request_write_ms);
    let sent = async {
        let mut stream = send.send_request(req).await?;
        if !plan.body.is_empty() {
            stream.send_data(plan.body.clone()).await?;
        }
        stream.finish().await?;
        Ok::<_, h3::error::StreamError>(stream)
    };
    let sent = tokio::select! {
        r = sent => r.map_err(|e| crate::h3::stream_failure(&e, Phase::RequestWrite, FailureKind::RequestWriteFailed, "sending the HTTP/3 request failed")),
        _ = sleep_until_opt(write_deadline) => Err(TransportFailure::new(Phase::RequestWrite, FailureKind::RequestWriteTimeout,
            "the HTTP/3 request could not be sent before the write deadline").with_deadline(plan.timeouts.request_write_ms)),
        _ = sleep_until_opt(total_deadline) => Err(TransportFailure::new(Phase::RequestWrite, FailureKind::TotalTimeout,
            "total deadline elapsed while sending the request").with_deadline(plan.timeouts.total_ms)),
        _ = cancel.cancelled() => Err(TransportFailure::new(Phase::RequestWrite, FailureKind::Canceled, "canceled while sending")),
    };
    let mut stream = match sent {
        Ok(s) => s,
        Err(f) => return fail(&quic, f, DispatchState::MayHaveBeenSent),
    };
    rec.finish(w_idx, PhaseStatus::Completed);
    let h_idx = rec.start(Phase::AwaitResponseHeaders);
    let headers_deadline = deadline_from(plan.timeouts.response_headers_ms);
    let resp = tokio::select! {
        r = stream.recv_response() => r.map_err(|e| crate::h3::stream_failure(&e, Phase::AwaitResponseHeaders, FailureKind::ResetBeforeResponse,
            "the HTTP/3 stream ended before a response")),
        _ = sleep_until_opt(headers_deadline) => Err(TransportFailure::new(Phase::AwaitResponseHeaders, FailureKind::ResponseHeadersTimeout,
            "no HTTP/3 response headers before the response-header deadline").with_deadline(plan.timeouts.response_headers_ms)),
        _ = sleep_until_opt(total_deadline) => Err(TransportFailure::new(Phase::AwaitResponseHeaders, FailureKind::TotalTimeout,
            "total deadline elapsed before response headers").with_deadline(plan.timeouts.total_ms)),
        _ = cancel.cancelled() => Err(TransportFailure::new(Phase::AwaitResponseHeaders, FailureKind::Canceled, "canceled before response headers")),
    };
    let resp = match resp {
        Ok(r) => r,
        Err(f) => return fail(&quic, f, DispatchState::MayHaveBeenSent),
    };
    rec.finish(h_idx, PhaseStatus::Completed);
    Ok(Opened {
        status: resp.status().as_u16(),
        version: http::Version::HTTP_3,
        headers: resp.headers().clone(),
        source: Source::H3 { stream: Box::new(stream), quic, _send: send, tx_before: before.udp_tx.bytes, rx_before: before.udp_rx.bytes },
    })
}

pub async fn run(plan: &SsePlan, events: &EventCtx, cancel: &CancellationToken, mut commands: Option<CommandRx>) -> SessionOutput {
    let interactive = commands.is_some();
    let t0 = Instant::now();
    let mut tr = Transcript::new(t0, plan.transcript, events.clone(), plan.redact.clone());
    let mut parser = SseParser::new((plan.limits.max_response_bytes as usize).min(1 << 20));
    parser.last_event_id = plan.last_event_id.clone();
    let total_deadline = if interactive { None } else { deadline_from(plan.timeouts.total_ms) };
    let mut attempts: Vec<AttemptOutput> = Vec::new();
    let mut facts = SessionFacts::default();
    let mut reason = AttemptReason::Initial;
    let mut total_events: u64 = 0;
    let mut last_status: Option<u16> = None;
    let mut closed_by = ClosedBy::NotClosed;
    let mut opened = false;
    let mut use_h3 = matches!(plan.version, HttpVersionPolicy::Http3Only | HttpVersionPolicy::Http3WithFallback);
    let mut index: u32 = 0;
    let mut reconnects: u32 = 0;

    loop {
        let mut rec = Recorder::new(index, events.clone());
        events.emit(ExecutionEvent::AttemptStarted { execution_id: events.execution_id, attempt: index });
        let mut obs = new_attempt(index, reason.clone(), plan.method.as_str(), &plan.display_url);
        if let Some(f) = version_unsupported(plan.version, plan.https, plan.proxy.is_some()) {
            attempts.push(fail_attempt(rec, obs, f, DispatchState::NotDispatched, events));
            break;
        }
        let last_id = parser.last_event_id.clone();
        let opened_attempt = if use_h3 {
            open_h3(plan, &mut rec, &mut obs, last_id.as_ref(), cancel, total_deadline).await
        } else {
            open_tcp(plan, &mut rec, &mut obs, last_id.as_ref(), cancel, total_deadline).await
        };
        let Opened { status, version, headers: resp_headers_map, mut source } = match opened_attempt {
            Ok(o) => o,
            Err((f, dispatch)) => {
                // The automatic policy falls back to TCP when HTTP/3 produced
                // no response — recorded as its own attempt, never hidden. A
                // request that may have been processed is replayed only when
                // its method is idempotent.
                let fallback = use_h3
                    && plan.version == HttpVersionPolicy::Http3WithFallback
                    && f.kind != FailureKind::Canceled
                    && (dispatch == DispatchState::NotDispatched || plan.method.is_idempotent());
                if fallback {
                    facts.notes.push(format!(
                        "HTTP/3 did not produce a response ({:?} during {:?}); the automatic policy fell back to TCP",
                        f.kind, f.phase
                    ));
                }
                attempts.push(fail_attempt(rec, obs, f, dispatch, events));
                if fallback {
                    use_h3 = false;
                    index += 1;
                    reason = AttemptReason::ProtocolFallback { from: "h3".into() };
                    continue;
                }
                break;
            }
        };
        last_status = Some(status);
        obs.response_status = Some(status);
        obs.dispatch = DispatchState::Sent;
        events.emit(ExecutionEvent::ResponseHead { execution_id: events.execution_id, attempt: index, status });
        let resp_headers = header_entries(&resp_headers_map);
        obs.bytes.response_headers_logical = Some(logical_header_bytes(&resp_headers));
        let content_type = resp_headers_map.get(http::header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).map(|s| s.to_string());
        let is_stream = (200..300).contains(&status) && status != 204;
        if is_stream && !content_type.as_deref().map(|c| c.to_ascii_lowercase().starts_with("text/event-stream")).unwrap_or(false) {
            facts.notes.push(format!(
                "the response content type is {} rather than text/event-stream; it was still parsed as an event stream",
                content_type.clone().unwrap_or_else(|| "missing".into())
            ));
        }

        // ---- body / event stream ----
        let phase = if is_stream { Phase::Session } else { Phase::ResponseBody };
        let s_idx = rec.start(phase);
        if is_stream {
            opened = true;
        }
        let mut captured = BytesMut::new();
        let mut wire = 0u64;
        let mut last_activity = Instant::now();
        let idle = Duration::from_millis(plan.idle_timeout_ms.max(1));
        let mut batch: Vec<SseEvent> = Vec::new();
        let end = loop {
            // Interactive streams stay open until Close/cancel; automation stops when idle.
            let idle_deadline = match (is_stream, interactive) {
                (true, true) => None,
                (true, false) => Some(last_activity + idle),
                (false, _) => Some(last_activity + Duration::from_millis(plan.timeouts.body_idle_ms.unwrap_or(30_000))),
            };
            tokio::select! {
                f = source.next(phase) => match f {
                    None => break End::Peer,
                    Some(Ok(d)) => {
                        last_activity = Instant::now();
                        wire += d.len() as u64;
                        let room = (plan.limits.capture_bytes as usize).saturating_sub(captured.len());
                        captured.extend_from_slice(&d[..d.len().min(room)]);
                        if !is_stream {
                            if wire > plan.limits.max_response_bytes {
                                break End::Failed(TransportFailure::new(Phase::ResponseBody, FailureKind::ResponseTooLargeLocal, "stopped at the local max_response_bytes limit"));
                            }
                            continue;
                        }
                        if let Err(e) = parser.feed(&d, &mut batch) {
                            break End::Failed(TransportFailure::new(Phase::Session, FailureKind::ResponseTooLargeLocal, format!("{e} (local limit)")));
                        }
                        let mut stop = false;
                        for ev in batch.drain(..) {
                            total_events += 1;
                            tr.event(Direction::Received, "event", ev.data.as_bytes(), ev.id.clone(), Some(ev.event_type.clone()));
                            if plan.max_events > 0 && total_events >= plan.max_events as u64 {
                                stop = true;
                                break;
                            }
                        }
                        if stop {
                            break End::Client;
                        }
                    }
                    Some(Err(f)) => break End::Failed(f),
                },
                c = next_cmd(&mut commands), if interactive => match c {
                    Some(SessionCommand::Close { .. }) | None => break End::Client,
                    Some(_) => tr.note("unsupported_command", "an event stream is receive-only; only Close/cancel apply"),
                },
                _ = sleep_until_opt(idle_deadline) => {
                    if is_stream {
                        break End::Idle;
                    }
                    break End::Failed(TransportFailure::new(Phase::ResponseBody, FailureKind::BodyIdleTimeout, "response body stalled")
                        .with_deadline(plan.timeouts.body_idle_ms));
                }
                _ = sleep_until_opt(total_deadline) => break End::Deadline,
                _ = cancel.cancelled() => break End::Canceled,
            }
        };
        let (bytes_written, bytes_read) = source.connection_bytes();
        source.close();
        let (completeness, failure, by) = match end {
            End::Peer => (BodyCompleteness::Complete, None, ClosedBy::Peer),
            End::Client => (BodyCompleteness::Canceled, None, ClosedBy::Client),
            End::Idle => (BodyCompleteness::Canceled, None, ClosedBy::Timeout),
            End::Canceled => (
                BodyCompleteness::Canceled,
                Some(TransportFailure::new(phase, FailureKind::Canceled, "the event stream was canceled by the user")),
                ClosedBy::Client,
            ),
            End::Deadline => (
                BodyCompleteness::Incomplete,
                Some(
                    TransportFailure::new(phase, FailureKind::TotalTimeout, "the total deadline elapsed while reading the stream")
                        .with_deadline(plan.timeouts.total_ms),
                ),
                ClosedBy::Timeout,
            ),
            End::Failed(f) => {
                let c = if f.kind == FailureKind::ResponseTooLargeLocal {
                    BodyCompleteness::StoppedAtLocalLimit
                } else {
                    BodyCompleteness::Incomplete
                };
                (c, Some(f), ClosedBy::Abnormal)
            }
        };
        closed_by = by;
        rec.finish(
            s_idx,
            match &failure {
                Some(f) => phase_status_for(f.kind),
                None => PhaseStatus::Completed,
            },
        );
        let reconnectable = is_stream
            && plan.reconnect
            && completeness == BodyCompleteness::Incomplete
            && failure.as_ref().map(|f| !matches!(f.kind, FailureKind::TotalTimeout | FailureKind::Canceled)).unwrap_or(false);
        let after_kind = failure.as_ref().map(|f| f.kind);
        obs.failure = failure;
        obs.bytes.response_body_wire = Some(wire);
        obs.bytes.connection_bytes_written = Some(bytes_written);
        obs.bytes.connection_bytes_read = Some(bytes_read);
        let obs = finish_attempt(rec, obs, events);
        let captured = captured.freeze();
        let response = response_record(status, version, resp_headers, body_capture(completeness, wire, &captured, content_type));
        attempts.push(AttemptOutput { observation: obs, response: Some(response), body: captured });
        if !reconnectable || reconnects >= plan.max_reconnects {
            break;
        }
        // Explicit, bounded reconnection with Last-Event-ID; each one is a new
        // attempt on a new connection (a new QUIC connection for HTTP/3).
        let delay = Duration::from_millis(parser.retry_ms.unwrap_or(1_000).min(30_000));
        facts.notes.push(format!(
            "reconnecting after an abnormal end in {} ms with Last-Event-ID {}",
            delay.as_millis(),
            parser.last_event_id.clone().unwrap_or_else(|| "(none)".into())
        ));
        tokio::select! {
            _ = tokio::time::sleep(delay) => {}
            _ = cancel.cancelled() => break,
            _ = sleep_until_opt(total_deadline) => break,
        }
        reconnects += 1;
        index += 1;
        reason = AttemptReason::Retry { after: after_kind.unwrap_or(FailureKind::BodyIncomplete) };
        parser.reset_stream();
    }

    let status = match last_status {
        Some(s) => ProtocolStatus::Sse { http_status: s, events: total_events, closed_by },
        None => ProtocolStatus::None,
    };
    let transcript = if opened { Some(tr.finish()) } else { None };
    SessionOutput { attempts, transcript, status, facts }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(chunks: &[&[u8]]) -> (Vec<SseEvent>, SseParser) {
        let mut p = SseParser::new(4096);
        let mut out = Vec::new();
        for c in chunks {
            p.feed(c, &mut out).unwrap();
        }
        (out, p)
    }

    #[test]
    fn fields_ids_types_and_multiline_data() {
        let (ev, p) = parse(&[b"\xEF\xBB\xBFid: 7\nevent: tick\ndata: a\ndata: b\n\n: keep-alive\n\ndata:c\n\nretry: 2500\n"]);
        assert_eq!(ev.len(), 2);
        assert_eq!(ev[0], SseEvent { id: Some("7".into()), event_type: "tick".into(), data: "a\nb".into() });
        assert_eq!(ev[1], SseEvent { id: Some("7".into()), event_type: "message".into(), data: "c".into() }, "id persists; default type");
        assert_eq!(p.retry_ms, Some(2500));
    }

    #[test]
    fn line_endings_split_across_chunks() {
        let (ev, _) = parse(&[b"data: x\r", b"\n\r", b"\ndata: y\r\r"]);
        assert_eq!(ev.iter().map(|e| e.data.as_str()).collect::<Vec<_>>(), vec!["x", "y"]);
    }

    #[test]
    fn empty_data_is_not_dispatched_and_long_lines_are_bounded() {
        let (ev, _) = parse(&[b"event: x\n\nid: 1\n\n"]);
        assert!(ev.is_empty());
        let mut p = SseParser::new(1024);
        let mut out = vec![];
        assert!(p.feed(&vec![b'a'; 2000], &mut out).is_err());
    }
}
