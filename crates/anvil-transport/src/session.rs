//! Shared plumbing for long-lived session adapters (WebSocket, gRPC streams,
//! SSE, raw TCP/TLS, UDP/DTLS).
//!
//! * [`Transcript`] keeps a bounded, redacted message history (the first half
//!   of the bound plus the most recent half; everything in between is counted
//!   as dropped) and emits every entry live as [`ExecutionEvent::Message`].
//!   Counters always cover the whole session, not just retained entries.
//! * [`SessionOutput`] is what every session adapter returns: the attempt(s)
//!   with native evidence, the transcript and a typed [`ProtocolStatus`].
//! * Interactive sessions receive [`SessionCommand`]s over a bounded channel
//!   ([`CommandRx`]); automation runs pass `None` and follow the scripted spec.

use crate::connector::{self, Established, ProxyPlan, Target};
use crate::dns::DnsConfig;
use crate::errors::{HyperStage, classify_hyper};
use crate::http::{AttemptOutput, sleep_until_opt};
use crate::recorder::{EventCtx, Recorder};
use anvil_domain::events::{ExecutionEvent, SessionCommand};
use anvil_domain::execution::*;
use anvil_domain::outcome::ProtocolStatus;
use anvil_domain::request::{PayloadEncoding, StreamPayload};
use anvil_domain::settings::{Limits, Timeouts};
use base64::Engine;
use bytes::Bytes;
use chrono::Utc;
use hyper::body::Body;
use hyper::client::conn::{http1, http2};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::collections::VecDeque;
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

/// Exact-value secret scrubber supplied by the engine (never inspects names).
pub type RedactFn = Arc<dyn Fn(&str) -> String + Send + Sync>;

/// Interactive command channel (bounded; the UI never blocks the session).
pub type CommandRx = tokio::sync::mpsc::Receiver<SessionCommand>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TranscriptLimits {
    /// Transcript entries retained (first half + most recent half).
    pub max_messages: usize,
    /// Bytes of each payload kept as a preview.
    pub preview_bytes: usize,
}

impl Default for TranscriptLimits {
    fn default() -> Self {
        TranscriptLimits { max_messages: 2_000, preview_bytes: 2_048 }
    }
}

/// Bounded, redacted session transcript with live event emission.
pub struct Transcript {
    t0: Instant,
    limits: TranscriptLimits,
    head: Vec<StreamMessage>,
    tail: VecDeque<StreamMessage>,
    dropped: u64,
    sent_count: u64,
    received_count: u64,
    sent_bytes: u64,
    received_bytes: u64,
    events: EventCtx,
    redact: Option<RedactFn>,
}

fn printable(s: &str) -> bool {
    s.chars().all(|c| !c.is_control() || matches!(c, '\n' | '\r' | '\t'))
}

impl Transcript {
    pub fn new(t0: Instant, limits: TranscriptLimits, events: EventCtx, redact: Option<RedactFn>) -> Self {
        Transcript {
            t0,
            limits: TranscriptLimits { max_messages: limits.max_messages.max(2), preview_bytes: limits.preview_bytes.max(16) },
            head: Vec::new(),
            tail: VecDeque::new(),
            dropped: 0,
            sent_count: 0,
            received_count: 0,
            sent_bytes: 0,
            received_bytes: 0,
            events,
            redact,
        }
    }

    fn preview(&self, payload: &[u8], force_hex: bool) -> (String, bool, bool) {
        let limit = self.limits.preview_bytes;
        if !force_hex
            && let Ok(s) = std::str::from_utf8(payload)
            && printable(s)
        {
            let mut end = s.len().min(limit);
            while !s.is_char_boundary(end) {
                end -= 1;
            }
            let text = match &self.redact {
                Some(r) => r(&s[..end]),
                None => s[..end].to_string(),
            };
            return (text, false, end < s.len());
        }
        let n = payload.len().min(limit / 2);
        (hex::encode(&payload[..n]), true, n < payload.len())
    }

    fn push(&mut self, m: StreamMessage) {
        self.events.emit(ExecutionEvent::Message { execution_id: self.events.execution_id, message: m.clone() });
        let head_cap = self.limits.max_messages / 2;
        let tail_cap = self.limits.max_messages - head_cap;
        if self.head.len() < head_cap {
            self.head.push(m);
            return;
        }
        if self.tail.len() >= tail_cap {
            self.tail.pop_front();
            self.dropped += 1;
        }
        self.tail.push_back(m);
    }

    fn entry(
        &mut self,
        direction: Direction,
        kind: &str,
        payload: &[u8],
        force_hex: bool,
        event_id: Option<String>,
        event_type: Option<String>,
    ) -> StreamMessage {
        let (preview, preview_is_hex, preview_truncated) = self.preview(payload, force_hex);
        let redact = |s: String| match &self.redact {
            Some(r) => r(&s),
            None => s,
        };
        StreamMessage {
            direction,
            offset_us: self.t0.elapsed().as_micros() as u64,
            kind: kind.to_string(),
            size: payload.len() as u64,
            preview,
            preview_is_hex,
            preview_truncated,
            event_id: event_id.map(redact),
            event_type,
        }
    }

    fn count(&mut self, direction: Direction, size: usize) {
        match direction {
            Direction::Sent => {
                self.sent_count += 1;
                self.sent_bytes += size as u64;
            }
            Direction::Received => {
                self.received_count += 1;
                self.received_bytes += size as u64;
            }
        }
    }

    /// Record an application message (counted in the session totals).
    pub fn data(&mut self, direction: Direction, kind: &str, payload: &[u8]) {
        self.count(direction, payload.len());
        let m = self.entry(direction, kind, payload, kind == "binary", None, None);
        self.push(m);
    }

    /// Record an application message whose wire size differs from its
    /// display form (e.g. a protobuf message shown as JSON). Counted.
    pub fn data_text(&mut self, direction: Direction, kind: &str, wire_size: u64, text: &str) {
        self.count(direction, wire_size as usize);
        let mut m = self.entry(direction, kind, text.as_bytes(), false, None, None);
        m.size = wire_size;
        self.push(m);
    }

    /// Record an application event with SSE-style metadata (counted).
    pub fn event(&mut self, direction: Direction, kind: &str, payload: &[u8], event_id: Option<String>, event_type: Option<String>) {
        self.count(direction, payload.len());
        let m = self.entry(direction, kind, payload, false, event_id, event_type);
        self.push(m);
    }

    /// Record a control entry (ping/pong/close/half-close/notes). Kept in the
    /// transcript but not counted as an application message.
    pub fn control(&mut self, direction: Direction, kind: &str, payload: &[u8]) {
        let force_hex = matches!(kind, "ping" | "pong");
        let m = self.entry(direction, kind, payload, force_hex, None, None);
        self.push(m);
    }

    /// A local note (e.g. a command that could not be applied).
    pub fn note(&mut self, kind: &str, text: &str) {
        self.control(Direction::Sent, kind, text.as_bytes());
    }

    pub fn received_count(&self) -> u64 {
        self.received_count
    }

    pub fn sent_count(&self) -> u64 {
        self.sent_count
    }

    pub fn sent_bytes(&self) -> u64 {
        self.sent_bytes
    }

    pub fn received_bytes(&self) -> u64 {
        self.received_bytes
    }

    pub fn finish(self) -> StreamTranscript {
        let mut messages = self.head;
        messages.extend(self.tail);
        StreamTranscript {
            messages,
            dropped_messages: self.dropped,
            sent_count: self.sent_count,
            received_count: self.received_count,
            sent_bytes: self.sent_bytes,
            received_bytes: self.received_bytes,
        }
    }
}

/// gRPC server-reflection outcome when reflection was the schema source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReflectionOutcome {
    /// `grpc.reflection.v1` or `grpc.reflection.v1alpha`.
    pub service: String,
    pub http_status: Option<u16>,
    pub grpc_status: Option<i32>,
    pub grpc_message: Option<String>,
    /// Schema obtained (the method call proceeded).
    pub succeeded: bool,
    /// Why no usable schema was obtained, when it was not.
    pub problem: Option<String>,
}

/// How a gRPC-Web response body was framed (set once response headers arrived).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GrpcWebFacts {
    pub response_content_type: Option<String>,
    /// The body was decoded as base64 text.
    pub text: bool,
    /// A trailer frame (flag `0x80`) ended the body.
    pub trailer_frame: bool,
    /// The body reached its end without a transport or framing failure.
    pub body_complete: bool,
    /// The status came from HTTP trailers instead of a trailer frame.
    pub status_in_http_trailers: bool,
}

/// Protocol-specific facts an adapter observed beyond the typed status.
#[derive(Debug, Clone, Default)]
pub struct SessionFacts {
    /// Plain-language evidence notes for the Effective request inspector.
    pub notes: Vec<String>,
    /// WebSocket subprotocol selected by the server.
    pub subprotocol: Option<String>,
    pub grpc_reflection: Option<ReflectionOutcome>,
    /// Decoded summary of `grpc-status-details-bin`, when present.
    pub grpc_status_details: Option<String>,
    /// gRPC-Web response framing, for gRPC-Web calls that got a response.
    pub grpc_web: Option<GrpcWebFacts>,
    /// The response body was readable but its gRPC or gRPC-Web framing was
    /// invalid (parsing stopped at this problem).
    pub grpc_framing_error: Option<String>,
    /// Received datagrams byte-identical to an earlier received datagram.
    /// UDP may duplicate datagrams, but the peer may also send identical
    /// replies; the count is an observation, not a duplicate-delivery claim.
    pub repeated_datagrams: u64,
    /// The OS reported an ICMP port-unreachable for the UDP destination.
    pub icmp_port_unreachable: bool,
}

/// Result of one session adapter run.
pub struct SessionOutput {
    /// One attempt per connection (SSE reconnects add attempts). Never empty;
    /// the last one is final.
    pub attempts: Vec<AttemptOutput>,
    /// `None` when the session never opened (setup or handshake failed).
    pub transcript: Option<StreamTranscript>,
    pub status: ProtocolStatus,
    pub facts: SessionFacts,
}

impl SessionOutput {
    pub fn single(attempt: AttemptOutput, transcript: Option<StreamTranscript>, status: ProtocolStatus, facts: SessionFacts) -> Self {
        SessionOutput { attempts: vec![attempt], transcript, status, facts }
    }
}

/// Fresh attempt observation for a session attempt.
pub fn new_attempt(index: u32, reason: AttemptReason, method: &str, url: &str) -> AttemptObservation {
    AttemptObservation {
        index,
        reason,
        method: method.to_string(),
        url: url.to_string(),
        started_at: Utc::now(),
        connection: None,
        phases: vec![],
        dispatch: DispatchState::NotDispatched,
        bytes: ByteCounts::default(),
        response_status: None,
        failure: None,
        duration_us: 0,
    }
}

/// Phase status matching a failure kind.
pub fn phase_status_for(kind: FailureKind) -> PhaseStatus {
    match kind {
        FailureKind::Canceled => PhaseStatus::Canceled,
        FailureKind::TotalTimeout
        | FailureKind::ResponseHeadersTimeout
        | FailureKind::RequestWriteTimeout
        | FailureKind::BodyIdleTimeout
        | FailureKind::ConnectTimeout
        | FailureKind::TlsHandshakeTimeout
        | FailureKind::DnsTimeout
        | FailureKind::QuicHandshakeTimeout
        | FailureKind::DtlsHandshakeTimeout => PhaseStatus::TimedOut,
        _ => PhaseStatus::Failed,
    }
}

/// Close the attempt with a failure (open phases are closed with the
/// matching status).
pub fn fail_attempt(
    mut rec: Recorder,
    mut obs: AttemptObservation,
    f: TransportFailure,
    dispatch: DispatchState,
    events: &EventCtx,
) -> AttemptOutput {
    rec.close_open(phase_status_for(f.kind));
    events.emit(ExecutionEvent::AttemptFailed { execution_id: events.execution_id, attempt: obs.index, kind: f.kind });
    obs.duration_us = rec.us();
    obs.phases = std::mem::take(&mut rec.phases);
    obs.dispatch = dispatch;
    obs.failure = Some(f);
    AttemptOutput { observation: obs, response: None, body: Bytes::new() }
}

/// Close the attempt normally (the failure, if any, is already set).
pub fn finish_attempt(mut rec: Recorder, mut obs: AttemptObservation, events: &EventCtx) -> AttemptObservation {
    if let Some(f) = &obs.failure {
        rec.close_open(phase_status_for(f.kind));
        events.emit(ExecutionEvent::AttemptFailed { execution_id: events.execution_id, attempt: obs.index, kind: f.kind });
    } else {
        rec.close_open(PhaseStatus::Completed);
    }
    obs.duration_us = rec.us();
    obs.phases = std::mem::take(&mut rec.phases);
    obs
}

pub fn deadline_from(ms: Option<u64>) -> Option<Instant> {
    ms.map(|m| Instant::now() + Duration::from_millis(m))
}

/// DNS → TCP → proxy → TLS with cancellation and the total deadline.
#[allow(clippy::too_many_arguments)]
pub async fn establish_guarded(
    rec: &mut Recorder,
    target: &Target<'_>,
    dns: &DnsConfig,
    timeouts: &Timeouts,
    proxy: Option<&ProxyPlan>,
    cancel: &CancellationToken,
    total_deadline: Option<Instant>,
) -> Result<Established, (TransportFailure, Option<ConnectionObservation>)> {
    establish_guarded_with(rec, target, dns, timeouts, proxy, cancel, total_deadline, None).await
}

/// [`establish_guarded`] with an optional PROXY protocol header before TLS.
#[allow(clippy::too_many_arguments)]
pub async fn establish_guarded_with(
    rec: &mut Recorder,
    target: &Target<'_>,
    dns: &DnsConfig,
    timeouts: &Timeouts,
    proxy: Option<&ProxyPlan>,
    cancel: &CancellationToken,
    total_deadline: Option<Instant>,
    header: Option<connector::PreTlsHeader<'_>>,
) -> Result<Established, (TransportFailure, Option<ConnectionObservation>)> {
    enum Ev<T> {
        Done(T),
        Canceled,
        Deadline,
    }
    let ev = {
        let fut = connector::establish_with(rec, target, dns, timeouts, proxy, header);
        tokio::select! {
            r = fut => Ev::Done(r),
            _ = cancel.cancelled() => Ev::Canceled,
            _ = sleep_until_opt(total_deadline) => Ev::Deadline,
        }
    };
    match ev {
        Ev::Done(r) => r.map_err(|(f, o)| (f, Some(o))),
        Ev::Canceled => {
            let f = TransportFailure::new(
                rec.open_phase().unwrap_or(Phase::Connect),
                FailureKind::Canceled,
                "canceled during connection setup",
            );
            Err((f, None))
        }
        Ev::Deadline => {
            let f = TransportFailure::new(
                rec.open_phase().unwrap_or(Phase::Connect),
                FailureKind::TotalTimeout,
                "total deadline elapsed during connection setup",
            )
            .with_deadline(timeouts.total_ms);
            Err((f, None))
        }
    }
}

/// A hyper client connection used by the HTTP-bootstrapped session adapters.
pub enum HttpSender<B> {
    H1(http1::SendRequest<B>),
    H2(http2::SendRequest<B>),
}

impl<B> HttpSender<B>
where
    B: Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    pub async fn send(&mut self, req: http::Request<B>) -> Result<hyper::Response<hyper::body::Incoming>, hyper::Error> {
        match self {
            HttpSender::H1(s) => s.send_request(req).await,
            HttpSender::H2(s) => s.send_request(req).await,
        }
    }

    pub fn is_h2(&self) -> bool {
        matches!(self, HttpSender::H2(_))
    }
}

/// An HTTP client connection ready for requests.
pub struct HttpConn<B> {
    pub sender: HttpSender<B>,
    pub stats: Arc<crate::stats::ConnStats>,
    pub observation: ConnectionObservation,
    /// HTTP/2 only: becomes `true` once the peer's SETTINGS enable extended
    /// CONNECT (RFC 8441 `SETTINGS_ENABLE_CONNECT_PROTOCOL`).
    pub extended_connect: Option<tokio::sync::watch::Receiver<bool>>,
}

/// HTTP/1.1 or HTTP/2 client handshake over an established stream. The
/// connection task is spawned; HTTP/1.1 connections keep upgrade support.
pub async fn http_handshake<B>(
    rec: &mut Recorder,
    est: Established,
    h2: bool,
    limits: &Limits,
) -> Result<HttpConn<B>, (TransportFailure, ConnectionObservation)>
where
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let Established { io, stats, mut observation } = est;
    let idx = rec.start(Phase::ProtocolHandshake);
    let io = TokioIo::new(io);
    if h2 {
        let mut b = http2::Builder::new(TokioExecutor::new());
        b.max_header_list_size(limits.max_response_header_bytes.min(u32::MAX as u64) as u32);
        match b.handshake::<_, B>(io).await {
            Ok((s, conn)) => {
                // Drive the connection and publish the peer's extended-CONNECT
                // setting. hyper runs the h2 connection in its own task, so the
                // setting is re-checked on a short ticker — only while a caller
                // still waits for it.
                let (flag_tx, flag_rx) = tokio::sync::watch::channel(false);
                let mut conn = Box::pin(conn);
                let mut tick = tokio::time::interval(Duration::from_millis(5));
                tokio::spawn(async move {
                    let _ = futures::future::poll_fn(|cx| {
                        let r = conn.as_mut().poll(cx);
                        if !*flag_tx.borrow() && flag_tx.receiver_count() > 0 {
                            if conn.is_extended_connect_protocol_enabled() {
                                let _ = flag_tx.send(true);
                            } else {
                                while tick.poll_tick(cx).is_ready() {}
                            }
                        }
                        r
                    })
                    .await;
                });
                rec.finish_with(idx, PhaseStatus::Completed, "HTTP/2 connection preface");
                observation.protocol = Some("h2".into());
                Ok(HttpConn { sender: HttpSender::H2(s), stats, observation, extended_connect: Some(flag_rx) })
            }
            Err(e) => {
                rec.finish(idx, PhaseStatus::Failed);
                Err((classify_hyper(&e, HyperStage::Handshake), observation))
            }
        }
    } else {
        let mut b = http1::Builder::new();
        b.max_buf_size((limits.max_response_header_bytes as usize).max(8192));
        match b.handshake::<_, B>(io).await {
            Ok((s, conn)) => {
                tokio::spawn(async move {
                    let _ = conn.with_upgrades().await;
                });
                rec.finish_with(idx, PhaseStatus::Completed, "HTTP/1.1 connection ready");
                observation.protocol = Some("http/1.1".into());
                Ok(HttpConn { sender: HttpSender::H1(s), stats, observation, extended_connect: None })
            }
            Err(e) => {
                rec.finish(idx, PhaseStatus::Failed);
                Err((classify_hyper(&e, HyperStage::Handshake), observation))
            }
        }
    }
}

pub fn http_version_label(v: http::Version) -> String {
    match v {
        http::Version::HTTP_10 => "HTTP/1.0",
        http::Version::HTTP_11 => "HTTP/1.1",
        http::Version::HTTP_2 => "HTTP/2",
        http::Version::HTTP_3 => "HTTP/3",
        _ => "HTTP/?",
    }
    .to_string()
}

pub fn header_entries(h: &http::HeaderMap) -> Vec<HeaderEntry> {
    h.iter().map(|(n, v)| HeaderEntry { name: n.as_str().to_string(), value: String::from_utf8_lossy(v.as_bytes()).into_owned() }).collect()
}

pub fn logical_header_bytes(h: &[HeaderEntry]) -> u64 {
    h.iter().map(|e| (e.name.len() + e.value.len() + 4) as u64).sum()
}

/// Decode a `hex` string (whitespace, `:` separators and a `0x` prefix allowed).
pub fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    let cleaned: String = s.trim().trim_start_matches("0x").chars().filter(|c| !c.is_whitespace() && *c != ':').collect();
    hex::decode(&cleaned).map_err(|e| format!("not valid hex: {e}"))
}

/// Decode a stream payload into bytes (text is sent as UTF-8 verbatim).
pub fn decode_payload(p: &StreamPayload) -> Result<Bytes, String> {
    match p.encoding {
        PayloadEncoding::Text => Ok(Bytes::from(p.data.clone().into_bytes())),
        PayloadEncoding::Hex => decode_hex(&p.data).map(Bytes::from),
        PayloadEncoding::Base64 => {
            base64::engine::general_purpose::STANDARD.decode(p.data.trim()).map(Bytes::from).map_err(|e| format!("not valid base64: {e}"))
        }
    }
}

/// Response record for an HTTP bootstrap response (WebSocket 101/200, SSE,
/// gRPC). Body fields are filled by the adapter.
pub fn response_record(status: u16, version: http::Version, headers: Vec<HeaderEntry>, body: BodyCapture) -> ResponseRecord {
    ResponseRecord {
        status,
        reason: http::StatusCode::from_u16(status).ok().and_then(|s| s.canonical_reason().map(|r| r.to_string())),
        http_version: http_version_label(version),
        headers,
        trailers: vec![],
        trailers_received: false,
        body,
    }
}

pub fn body_capture(completeness: BodyCompleteness, wire: u64, captured: &[u8], content_type: Option<String>) -> BodyCapture {
    BodyCapture {
        completeness,
        wire_bytes: wire,
        declared_length: None,
        captured_bytes: captured.len() as u64,
        display_truncated: wire > captured.len() as u64,
        content_type,
        content_encoding: None,
        decoded_bytes: None,
        blob_sha256: if captured.is_empty() { None } else { Some(crate::certs::sha256_hex(captured)) },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transcript_keeps_head_and_tail_and_counts_everything() {
        let mut t = Transcript::new(Instant::now(), TranscriptLimits { max_messages: 4, preview_bytes: 64 }, EventCtx::none(), None);
        for i in 0..10u8 {
            t.data(Direction::Received, "text", format!("m{i}").as_bytes());
        }
        let s = t.finish();
        assert_eq!(s.received_count, 10);
        assert_eq!(s.dropped_messages, 6);
        let previews: Vec<&str> = s.messages.iter().map(|m| m.preview.as_str()).collect();
        assert_eq!(previews, vec!["m0", "m1", "m8", "m9"]);
    }

    #[test]
    fn previews_are_redacted_and_binary_is_hex() {
        let redact: RedactFn = Arc::new(|s: &str| s.replace("sekret-value", "‹redacted›"));
        let mut t = Transcript::new(Instant::now(), TranscriptLimits::default(), EventCtx::none(), Some(redact));
        t.data(Direction::Sent, "text", b"token=sekret-value");
        t.data(Direction::Received, "binary", &[0xde, 0xad]);
        t.data(Direction::Received, "bytes", &[0xff, 0x00, 0x41]);
        let s = t.finish();
        assert_eq!(s.messages[0].preview, "token=‹redacted›");
        assert!(s.messages[1].preview_is_hex && s.messages[1].preview == "dead");
        assert!(s.messages[2].preview_is_hex, "non-UTF-8 bytes are shown as hex");
    }

    #[test]
    fn payload_decoding() {
        let p = |d: &str, e| StreamPayload { data: d.into(), encoding: e };
        assert_eq!(decode_payload(&p("0x de:ad be ef", PayloadEncoding::Hex)).unwrap().as_ref(), &[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(decode_payload(&p("aGk=", PayloadEncoding::Base64)).unwrap().as_ref(), b"hi");
        assert!(decode_payload(&p("zz", PayloadEncoding::Hex)).is_err());
    }
}
