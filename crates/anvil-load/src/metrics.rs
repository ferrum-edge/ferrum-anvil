//! Mergeable load metrics.
//!
//! Each shard (a group of slots / virtual users) owns a [`Metrics`] with its
//! own HDR histograms. Aggregation always **merges histograms first and then
//! computes percentiles**; percentile values from different shards are never
//! averaged (LOAD-003). Success and failure latency are kept in separate
//! distributions. Timeouts are censored observations (the true latency is at
//! least the elapsed time) and are summarised separately, never mixed into
//! either latency distribution (LOAD-004). Failure samples are bounded per
//! category and come from the engine's already-redacted execution record
//! (LOAD-010). Protocol denominators (messages, sessions, frames, datagrams,
//! handshakes) come from the same typed record and session facts and are
//! accumulated in [`ProtoAccum`] (LOAD-013).

use crate::protocol::StepUnit;
use anvil_domain::diagnostics::Severity;
use anvil_domain::execution::{AttemptReason, Direction, ExecutionRecord, FailureKind, Phase, PhaseStatus, exchange_duration_us};
use anvil_domain::load::*;
use anvil_domain::outcome::{ApplicationState, AssertionState, ClosedBy, GrpcStatusSource, ProtocolStatus, TransportState};
use anvil_engine::ExecutionOutput;
use base64::Engine as _;
use hdrhistogram::Histogram;
use hdrhistogram::serialization::{Deserializer, Serializer, V2DeflateSerializer};
use std::collections::{BTreeMap, BTreeSet};

/// Highest trackable latency (1 hour, µs). Larger values saturate.
pub const LATENCY_MAX_US: u64 = 3_600_000_000;
/// Significant figures for the primary latency histograms (≤ 0.1 % error).
pub const PRIMARY_SIGFIG: u8 = 3;
/// Significant figures for secondary distributions (lag, setup, censored, timeline).
pub const SECONDARY_SIGFIG: u8 = 2;
pub const MAX_CATEGORIES: usize = 32;
pub const MAX_EXAMPLES: usize = 5;
pub const MAX_EXAMPLE_CHARS: usize = 400;
pub const MAX_DESTINATIONS: usize = 16;
pub const MAX_PROTOCOLS: usize = 8;
pub const OTHER_CATEGORY: &str = "other (category limit reached)";

pub fn new_histogram(sigfig: u8) -> Histogram<u64> {
    Histogram::new_with_bounds(1, LATENCY_MAX_US, sigfig).expect("static histogram bounds are valid")
}

/// A latency distribution with exact min/max/sum alongside the histogram.
#[derive(Debug, Clone)]
pub struct LatencyStat {
    pub hist: Histogram<u64>,
    min: u64,
    max: u64,
    sum: u128,
}

impl LatencyStat {
    pub fn new(sigfig: u8) -> Self {
        LatencyStat { hist: new_histogram(sigfig), min: u64::MAX, max: 0, sum: 0 }
    }

    pub fn record(&mut self, us: u64) {
        self.hist.saturating_record(us.clamp(1, LATENCY_MAX_US));
        self.min = self.min.min(us);
        self.max = self.max.max(us);
        self.sum += us as u128;
    }

    pub fn count(&self) -> u64 {
        self.hist.len()
    }

    /// Merge another distribution's *histogram* (never its percentiles).
    pub fn merge(&mut self, o: &LatencyStat) {
        if o.count() == 0 {
            return;
        }
        self.hist.add(&o.hist).expect("identical histogram bounds");
        self.min = self.min.min(o.min);
        self.max = self.max.max(o.max);
        self.sum += o.sum;
    }

    pub fn summary(&self) -> LatencySummary {
        let n = self.count();
        if n == 0 {
            return LatencySummary::default();
        }
        // HDR returns the highest value equivalent to the quantile's bucket;
        // clamp to the exact extremes so a percentile never exceeds the max.
        let q = |p: f64| self.hist.value_at_quantile(p).clamp(self.min, self.max);
        LatencySummary {
            count: n,
            min_us: self.min,
            max_us: self.max,
            mean_us: (self.sum / n as u128) as u64,
            p50_us: q(0.50),
            p90_us: q(0.90),
            p95_us: q(0.95),
            p99_us: q(0.99),
        }
    }

    pub fn to_b64(&self) -> String {
        histogram_to_b64(&self.hist)
    }
}

pub fn histogram_to_b64(h: &Histogram<u64>) -> String {
    let mut buf = Vec::new();
    V2DeflateSerializer::new().serialize(h, &mut buf).expect("serializing to memory cannot fail");
    base64::engine::general_purpose::STANDARD.encode(buf)
}

pub fn histogram_from_b64(s: &str) -> Result<Histogram<u64>, String> {
    let bytes = base64::engine::general_purpose::STANDARD.decode(s).map_err(|e| format!("histogram base64: {e}"))?;
    Deserializer::new().deserialize(&mut std::io::Cursor::new(bytes)).map_err(|e| format!("histogram: {e:?}"))
}

/// Summary from a (possibly reopened / merged) histogram alone. Min/max/mean
/// come from the histogram and are therefore within its precision.
pub fn summarize_histogram(h: &Histogram<u64>) -> LatencySummary {
    if h.is_empty() {
        return LatencySummary::default();
    }
    LatencySummary {
        count: h.len(),
        min_us: h.min(),
        max_us: h.max(),
        mean_us: h.mean().round() as u64,
        p50_us: h.value_at_quantile(0.50),
        p90_us: h.value_at_quantile(0.90),
        p95_us: h.value_at_quantile(0.95),
        p99_us: h.value_at_quantile(0.99),
    }
}

/// How a send ended. Exactly one per send; the four classes (plus
/// "in flight") partition the started sends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Terminal {
    /// A complete response was received (any status).
    Completed,
    /// No complete response, not because of a deadline or cancellation.
    TransportFailure,
    /// A configured deadline elapsed (censored latency).
    Timeout,
    /// The run canceled the send (user cancel, abort rule, graceful-stop limit).
    Canceled,
}

/// Everything the load engine keeps from one send (the response body and the
/// full record are dropped immediately).
#[derive(Debug, Clone)]
pub struct SendObservation {
    pub terminal: Terminal,
    pub application_failure: bool,
    pub assertion_failure: bool,
    /// A completed UDP/DTLS exchange in which no datagram was received: "no
    /// response observed" — neither a success nor a failure, and no latency.
    pub no_response: bool,
    /// Sum of attempt durations (connect … last body byte), µs.
    pub latency_us: u64,
    /// Local time outside the attempts: preparation, token acquisition,
    /// retry backoff, record assembly (µs).
    pub setup_us: u64,
    pub deadline_ms: Option<u64>,
    pub status: Option<u16>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub connections_opened: u64,
    pub connections_reused: u64,
    pub protocol: Option<String>,
    pub category: Option<String>,
    pub example: Option<String>,
    pub destination: Option<String>,
    /// Protocol facts for the unit's denominators.
    pub proto: ProtoObs,
}

impl Default for SendObservation {
    fn default() -> Self {
        SendObservation {
            terminal: Terminal::Completed,
            application_failure: false,
            assertion_failure: false,
            no_response: false,
            latency_us: 0,
            setup_us: 0,
            deadline_ms: None,
            status: None,
            bytes_sent: 0,
            bytes_received: 0,
            connections_opened: 0,
            connections_reused: 0,
            protocol: None,
            category: None,
            example: None,
            destination: None,
            proto: ProtoObs::default(),
        }
    }
}

impl SendObservation {
    pub fn is_success(&self) -> bool {
        self.terminal == Terminal::Completed && !self.application_failure && !self.assertion_failure && !self.no_response
    }

    /// Counts toward the failure distribution / failure ratio.
    pub fn is_failure(&self) -> bool {
        match self.terminal {
            Terminal::Completed => self.application_failure || self.assertion_failure,
            Terminal::TransportFailure | Terminal::Timeout => true,
            Terminal::Canceled => false,
        }
    }
}

pub fn is_timeout(kind: FailureKind) -> bool {
    use FailureKind::*;
    matches!(
        kind,
        TotalTimeout
            | ResponseHeadersTimeout
            | RequestWriteTimeout
            | BodyIdleTimeout
            | ConnectTimeout
            | TlsHandshakeTimeout
            | DnsTimeout
            | QuicHandshakeTimeout
            | QuicIdleTimeout
            | DtlsHandshakeTimeout
    )
}

fn snake<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_value(v).ok().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_else(|| "unknown".into())
}

fn truncate_chars(s: &str, max: usize) -> String {
    match s.char_indices().nth(max) {
        Some((i, _)) => format!("{}…", &s[..i]),
        None => s.to_string(),
    }
}

/// Origin (`scheme://host:port`) of a redacted URL.
fn origin(url: &str) -> Option<String> {
    let u = url::Url::parse(url).ok()?;
    let host = u.host_str()?;
    Some(match u.port_or_known_default() {
        Some(p) => format!("{}://{}:{}", u.scheme(), host, p),
        None => format!("{}://{}", u.scheme(), host),
    })
}

/// Classify one engine execution. Uses only the engine's typed outcome, its
/// (already redacted) record and the adapter's typed session facts; never
/// re-parses message text. `step` says which unit the send is and which
/// request settings define its expectations.
pub fn observe(out: &ExecutionOutput, wall_us: u64, step: &StepUnit) -> SendObservation {
    let rec = &out.record;
    let mut obs = observe_record(rec, wall_us);
    obs.proto = protocol_obs(out, step, obs.terminal);
    if obs.terminal == Terminal::Completed {
        match step.kind {
            // Fewer framed replies than the request expects: the exchange
            // completed at the transport level, but not as specified.
            LoadUnitKind::TcpExchange if obs.proto.tcp.as_ref().and_then(|t| t.expectation) == Some(false) => {
                obs.application_failure = true;
            }
            // A SOAP fault or GraphQL error arrives with a 2xx: an outcome the
            // engine could not determine from the body (only part of it was
            // captured, say) is not a success; it counts as an application
            // failure.
            LoadUnitKind::HttpRequest if not_determined_from_body(rec, step) => obs.application_failure = true,
            LoadUnitKind::UdpExchange | LoadUnitKind::DtlsExchange => match &obs.proto.dgram {
                Some(d) if d.received == 0 => obs.no_response = true,
                // The latency of an exchange is the observed time to first
                // response, not its duration (which includes the fixed window).
                Some(DgramObs { ttfr_us: Some(t), .. }) => obs.latency_us = *t,
                _ => {}
            },
            _ => {}
        }
    }
    if obs.is_failure() && obs.category.is_none() {
        describe_failure(&mut obs, rec, step);
    }
    obs
}

/// A SOAP or GraphQL request whose application outcome the engine did not
/// determine from the response body.
fn not_determined_from_body(rec: &ExecutionRecord, step: &StepUnit) -> bool {
    step.application_from_body && rec.outcome.application == ApplicationState::NotEvaluated
}

/// The unit-independent part of [`observe`]: terminal class, application and
/// assertion state, attempt latency, bytes and connections. Failure samples
/// are added by [`observe`].
pub fn observe_record(rec: &ExecutionRecord, wall_us: u64) -> SendObservation {
    let last_failure = rec.attempts.last().and_then(|a| a.failure.as_ref());
    let terminal = match rec.outcome.transport {
        TransportState::Completed => Terminal::Completed,
        TransportState::Canceled => Terminal::Canceled,
        _ => match last_failure {
            Some(f) if f.kind == FailureKind::Canceled => Terminal::Canceled,
            Some(f) if is_timeout(f.kind) => Terminal::Timeout,
            _ => Terminal::TransportFailure,
        },
    };
    let application_failure = terminal == Terminal::Completed && rec.outcome.application == ApplicationState::Failure;
    let assertion_failure = terminal == Terminal::Completed && rec.outcome.assertions == AssertionState::Fail;
    let latency_us = exchange_duration_us(&rec.attempts).unwrap_or(0);
    let mut obs = SendObservation {
        terminal,
        application_failure,
        assertion_failure,
        no_response: false,
        latency_us,
        setup_us: wall_us.saturating_sub(latency_us),
        deadline_ms: if terminal == Terminal::Timeout { last_failure.and_then(|f| f.deadline_ms) } else { None },
        status: rec.response.as_ref().map(|r| r.status),
        bytes_sent: 0,
        bytes_received: 0,
        connections_opened: 0,
        connections_reused: 0,
        protocol: rec.attempts.last().and_then(|a| a.connection.as_ref()).and_then(|c| c.protocol.clone()),
        category: None,
        example: None,
        destination: origin(&rec.prepared.url),
        proto: ProtoObs::default(),
    };
    for a in &rec.attempts {
        obs.bytes_sent += a.bytes.request_headers_logical + a.bytes.request_body;
        obs.bytes_received += a.bytes.response_headers_logical.unwrap_or(0) + a.bytes.response_body_wire.unwrap_or(0);
        if let Some(c) = &a.connection {
            if c.reused {
                obs.connections_reused += 1;
            } else {
                obs.connections_opened += 1;
            }
        }
    }
    obs
}

/// Failure category (class + top finding / failure kind / status / assertion
/// label) and one bounded, redacted example.
fn describe_failure(obs: &mut SendObservation, rec: &ExecutionRecord, step: &StepUnit) {
    let terminal = obs.terminal;
    let (application_failure, assertion_failure) = (obs.application_failure, obs.assertion_failure);
    let last_failure = rec.attempts.last().and_then(|a| a.failure.as_ref());
    let expectation_short = obs.proto.tcp.as_ref().and_then(|t| t.expectation) == Some(false);
    let top = rec
        .findings
        .iter()
        .filter(|f| f.severity >= Severity::Warning)
        .max_by_key(|f| f.severity)
        .or(rec.findings.first())
        .map(|f| f.code.clone());
    let kind = last_failure.map(|f| snake(&f.kind));
    let class = match terminal {
        Terminal::Timeout => "timeout",
        Terminal::TransportFailure => "transport_failure",
        _ if application_failure => "application_failure",
        _ => "assertion_failure",
    };
    let detail = match terminal {
        Terminal::Timeout => kind.clone().unwrap_or_else(|| "deadline".into()),
        Terminal::Completed if expectation_short => "tcp.expected_frames_not_received".into(),
        Terminal::Completed if not_determined_from_body(rec, step) => {
            top.clone().unwrap_or_else(|| "application.not_determined_from_body".into())
        }
        _ if assertion_failure && !application_failure => rec
            .assertion_results
            .iter()
            .find(|r| !r.passed)
            .map(|r| r.label.clone())
            .filter(|l| !l.is_empty())
            .unwrap_or_else(|| "assertion".into()),
        _ => top.clone().or(kind.clone()).or(obs.status.map(|s| format!("http_{s}"))).unwrap_or_else(|| "unknown".into()),
    };
    obs.category = Some(truncate_chars(&format!("{class}: {detail}"), 120));
    let mut example = format!("{} {} → {}", rec.prepared.method, rec.prepared.url, rec.outcome.summary);
    if let Some(f) = last_failure
        && terminal != Terminal::Completed
    {
        example.push_str(&format!(" [{}: {}]", snake(&f.kind), f.message));
    }
    if expectation_short && let Some(t) = &obs.proto.tcp {
        example.push_str(&format!(" [expected {} frame(s), received {}]", step.tcp_expect_frames.unwrap_or(0), t.frames_received));
    }
    if assertion_failure && let Some(r) = rec.assertion_results.iter().find(|r| !r.passed) {
        example.push_str(&format!(" [assertion: {}]", r.message));
    }
    obs.example = Some(truncate_chars(&example, MAX_EXAMPLE_CHARS));
}

// ------------------------------------------------------ protocol facts ---

/// WebSocket session facts.
#[derive(Debug, Clone, Default)]
pub struct WsObs {
    pub opened: bool,
    pub rejected: bool,
    /// Who closed and the close code, for opened sessions.
    pub close: Option<(ClosedBy, Option<u16>)>,
    pub sent: u64,
    pub received: u64,
    /// Round trips (µs) when the request defines `expect_messages`.
    pub rtts: Vec<u64>,
    /// Pairing was expected but impossible for this session.
    pub unpaired: bool,
}

/// TCP exchange facts.
#[derive(Debug, Clone, Default)]
pub struct TcpObs {
    pub connected: bool,
    pub frames_sent: u64,
    pub frames_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub partial: bool,
    pub peer_close: bool,
    /// `Some(met)` for a completed exchange whose request expects frames.
    pub expectation: Option<bool>,
}

/// UDP/DTLS exchange facts.
#[derive(Debug, Clone, Default)]
pub struct DgramObs {
    pub sent: u64,
    pub received: u64,
    pub repeated: u64,
    pub echoed: u64,
    pub icmp: bool,
    /// First datagram sent → first received (µs).
    pub ttfr_us: Option<u64>,
    /// DTLS handshake phase status and duration, when it started.
    pub handshake: Option<(PhaseStatus, Option<u64>)>,
}

/// Protocol facts of one unit; only the family of its kind is filled.
#[derive(Debug, Clone, Default)]
pub struct ProtoObs {
    /// Attempts made after an HTTP/3 → TCP fallback.
    pub fallback_attempts: u64,
    pub final_h3: bool,
    pub grpc_status: Option<i32>,
    /// A gRPC response without a terminal status (not canceled).
    pub grpc_missing_status: bool,
    pub stream_opened: bool,
    pub messages_received: u64,
    /// Unit start → first message/event (µs).
    pub first_message_us: Option<u64>,
    /// SSE: how an opened stream ended.
    pub stream_end: Option<ClosedBy>,
    pub ws: Option<WsObs>,
    pub tcp: Option<TcpObs>,
    pub dgram: Option<DgramObs>,
}

fn first_offset(rec: &ExecutionRecord, dir: Direction, kinds: &[&str]) -> Option<u64> {
    rec.stream.as_ref()?.messages.iter().find(|m| m.direction == dir && kinds.contains(&m.kind.as_str())).map(|m| m.offset_us)
}

fn protocol_obs(out: &ExecutionOutput, step: &StepUnit, terminal: Terminal) -> ProtoObs {
    let rec = &out.record;
    let tr = rec.stream.as_ref();
    let status = &rec.outcome.protocol_status;
    let mut p = ProtoObs {
        fallback_attempts: rec.attempts.iter().filter(|a| matches!(a.reason, AttemptReason::ProtocolFallback { .. })).count() as u64,
        final_h3: rec.attempts.last().and_then(|a| a.connection.as_ref()).and_then(|c| c.protocol.as_deref()) == Some("h3"),
        ..Default::default()
    };
    match step.kind {
        LoadUnitKind::HttpRequest => {}
        LoadUnitKind::GrpcCall | LoadUnitKind::GrpcStream => {
            if let ProtocolStatus::Grpc { http_status, grpc_status, source, .. } = status {
                p.grpc_status = *grpc_status;
                p.grpc_missing_status = *source == GrpcStatusSource::Missing && http_status.is_some() && terminal != Terminal::Canceled;
                p.stream_opened = *http_status == Some(200);
            }
            p.messages_received = tr.map(|t| t.received_count).unwrap_or(0);
            // The transcript clock starts with the attempt that carried the
            // call; earlier (failed HTTP/3) attempts come before it.
            let prior: u64 = rec.attempts.iter().rev().skip(1).map(|a| a.duration_us).sum();
            p.first_message_us = first_offset(rec, Direction::Received, &["grpc_message"]).map(|o| o + prior);
        }
        LoadUnitKind::SseStream => {
            // A transcript exists only for a stream that opened (2xx).
            p.stream_opened = tr.is_some();
            if let ProtocolStatus::Sse { events, closed_by, .. } = status {
                p.messages_received = *events;
                if p.stream_opened {
                    p.stream_end = Some(*closed_by);
                }
            }
            // The SSE transcript clock starts with the stream request.
            p.first_message_us = first_offset(rec, Direction::Received, &["event"]);
        }
        LoadUnitKind::WebsocketSession => {
            let (handshake, code, by) = match status {
                ProtocolStatus::WebSocket { handshake_status, close_code, closed_by, .. } => (*handshake_status, *close_code, *closed_by),
                _ => (None, None, ClosedBy::NotClosed),
            };
            // A transcript exists only once the session opened.
            let opened = tr.is_some();
            let mut ws = WsObs {
                opened,
                rejected: !opened && handshake.is_some_and(|s| s != 101 && s != 200),
                close: opened.then_some((by, code)),
                sent: tr.map(|t| t.sent_count).unwrap_or(0),
                received: tr.map(|t| t.received_count).unwrap_or(0),
                ..Default::default()
            };
            if let Some(t) = tr.filter(|_| step.ws_expect_messages > 0) {
                if t.dropped_messages > 0 {
                    ws.unpaired = true;
                } else {
                    let data = |d: Direction| -> Vec<u64> {
                        t.messages
                            .iter()
                            .filter(|m| m.direction == d && matches!(m.kind.as_str(), "text" | "binary"))
                            .map(|m| m.offset_us)
                            .collect()
                    };
                    let (sent_at, recv_at) = (data(Direction::Sent), data(Direction::Received));
                    let n = sent_at.len().min(recv_at.len()).min(step.ws_expect_messages as usize);
                    for i in 0..n {
                        if recv_at[i] < sent_at[i] {
                            // A reply before its message: the exchange is not
                            // echo-shaped, so no round trip is claimed from it.
                            ws.unpaired = true;
                            ws.rtts.clear();
                            break;
                        }
                        ws.rtts.push(recv_at[i] - sent_at[i]);
                    }
                }
            }
            p.ws = Some(ws);
        }
        LoadUnitKind::TcpExchange => {
            let (bytes_sent, bytes_received, by) = match status {
                ProtocolStatus::Tcp { bytes_sent, bytes_received, closed_by, .. } => (*bytes_sent, *bytes_received, *closed_by),
                _ => (0, 0, ClosedBy::NotClosed),
            };
            let frames_received = tr.map(|t| t.received_count).unwrap_or(0);
            p.tcp = Some(TcpObs {
                connected: tr.is_some(),
                frames_sent: tr.map(|t| t.sent_count).unwrap_or(0),
                frames_received,
                bytes_sent,
                bytes_received,
                partial: tr.is_some_and(|t| t.messages.iter().any(|m| m.kind == "partial_frame")),
                peer_close: tr.is_some() && by == ClosedBy::Peer,
                expectation: step.tcp_expect_frames.filter(|_| terminal == Terminal::Completed).map(|n| frames_received >= n as u64),
            });
        }
        LoadUnitKind::UdpExchange | LoadUnitKind::DtlsExchange => {
            let (sent, received) = match status {
                ProtocolStatus::Udp { datagrams_sent, datagrams_received, .. } => (*datagrams_sent, *datagrams_received),
                _ => (0, 0),
            };
            let facts = out.session_facts.as_ref();
            let first_sent = first_offset(rec, Direction::Sent, &["datagram"]);
            let first_received = first_offset(rec, Direction::Received, &["datagram"]);
            p.dgram = Some(DgramObs {
                sent,
                received,
                repeated: facts.map(|f| f.repeated_datagrams).unwrap_or(0),
                echoed: facts.map(|f| f.echoed_datagrams).unwrap_or(0),
                icmp: facts.is_some_and(|f| f.icmp_port_unreachable),
                ttfr_us: match (first_sent, first_received) {
                    (Some(s), Some(r)) => Some(r.saturating_sub(s)),
                    _ => None,
                },
                handshake: if step.kind == LoadUnitKind::DtlsExchange {
                    rec.attempts.last().and_then(|a| a.phase(Phase::DtlsHandshake)).map(|ph| (ph.status, ph.duration_us()))
                } else {
                    None
                },
            });
        }
    }
    p
}

fn closed_key(c: ClosedBy) -> u8 {
    match c {
        ClosedBy::Peer => 0,
        ClosedBy::Client => 1,
        ClosedBy::Abnormal => 2,
        ClosedBy::Timeout => 3,
        ClosedBy::NotClosed => 4,
    }
}

fn closed_from(k: u8) -> ClosedBy {
    match k {
        0 => ClosedBy::Peer,
        1 => ClosedBy::Client,
        2 => ClosedBy::Abnormal,
        3 => ClosedBy::Timeout,
        _ => ClosedBy::NotClosed,
    }
}

/// Mergeable protocol denominators of the measured window (one shard).
#[derive(Debug, Clone)]
pub struct ProtoAccum {
    pub fallback_attempts: u64,
    pub units_with_fallback: u64,
    pub units_over_h3: u64,
    pub grpc_codes: BTreeMap<i32, u64>,
    pub grpc_missing_status: u64,
    pub streams_opened: u64,
    pub messages_received: u64,
    pub with_messages: u64,
    pub first_message: LatencyStat,
    /// (closed-by key, close code) → units: SSE stream ends, WebSocket closes.
    pub ends: BTreeMap<(u8, Option<u16>), u64>,
    pub ws_opened: u64,
    pub ws_rejected: u64,
    pub ws_not_opened: u64,
    pub ws_clean: u64,
    pub ws_sent: u64,
    pub ws_received: u64,
    pub rtt: LatencyStat,
    pub rtt_unpaired: u64,
    pub tcp_connected: u64,
    pub frames_sent: u64,
    pub frames_received: u64,
    pub tcp_bytes_sent: u64,
    pub tcp_bytes_received: u64,
    pub partial_frames: u64,
    pub peer_closes: u64,
    pub expectation_met: u64,
    pub expectation_short: u64,
    pub dg_sent: u64,
    pub dg_received: u64,
    pub with_response: u64,
    pub silent: u64,
    pub repeated: u64,
    pub echoed: u64,
    pub icmp: u64,
    pub first_response: LatencyStat,
    pub hs_attempted: u64,
    pub hs_completed: u64,
    pub hs_failed: u64,
    pub hs_timed_out: u64,
    pub hs_duration: LatencyStat,
}

impl Default for ProtoAccum {
    fn default() -> Self {
        Self::new()
    }
}

impl ProtoAccum {
    pub fn new() -> Self {
        ProtoAccum {
            fallback_attempts: 0,
            units_with_fallback: 0,
            units_over_h3: 0,
            grpc_codes: BTreeMap::new(),
            grpc_missing_status: 0,
            streams_opened: 0,
            messages_received: 0,
            with_messages: 0,
            first_message: LatencyStat::new(SECONDARY_SIGFIG),
            ends: BTreeMap::new(),
            ws_opened: 0,
            ws_rejected: 0,
            ws_not_opened: 0,
            ws_clean: 0,
            ws_sent: 0,
            ws_received: 0,
            rtt: LatencyStat::new(SECONDARY_SIGFIG),
            rtt_unpaired: 0,
            tcp_connected: 0,
            frames_sent: 0,
            frames_received: 0,
            tcp_bytes_sent: 0,
            tcp_bytes_received: 0,
            partial_frames: 0,
            peer_closes: 0,
            expectation_met: 0,
            expectation_short: 0,
            dg_sent: 0,
            dg_received: 0,
            with_response: 0,
            silent: 0,
            repeated: 0,
            echoed: 0,
            icmp: 0,
            first_response: LatencyStat::new(SECONDARY_SIGFIG),
            hs_attempted: 0,
            hs_completed: 0,
            hs_failed: 0,
            hs_timed_out: 0,
            hs_duration: LatencyStat::new(SECONDARY_SIGFIG),
        }
    }

    pub fn record(&mut self, o: &SendObservation) {
        let p = &o.proto;
        let completed = o.terminal == Terminal::Completed;
        self.fallback_attempts += p.fallback_attempts;
        self.units_with_fallback += (p.fallback_attempts > 0) as u64;
        self.units_over_h3 += p.final_h3 as u64;
        if completed && let Some(c) = p.grpc_status {
            *self.grpc_codes.entry(c).or_default() += 1;
        }
        self.grpc_missing_status += p.grpc_missing_status as u64;
        self.streams_opened += p.stream_opened as u64;
        self.messages_received += p.messages_received;
        if p.stream_opened && p.messages_received > 0 {
            self.with_messages += 1;
            if let Some(t) = p.first_message_us {
                self.first_message.record(t);
            }
        }
        if let Some(by) = p.stream_end {
            *self.ends.entry((closed_key(by), None)).or_default() += 1;
        }
        if let Some(w) = &p.ws {
            if w.opened {
                self.ws_opened += 1;
                self.ws_clean += completed as u64;
                if let Some((by, code)) = w.close {
                    *self.ends.entry((closed_key(by), code)).or_default() += 1;
                }
            } else if w.rejected {
                self.ws_rejected += 1;
            } else {
                self.ws_not_opened += 1;
            }
            self.ws_sent += w.sent;
            self.ws_received += w.received;
            for r in &w.rtts {
                self.rtt.record(*r);
            }
            self.rtt_unpaired += w.unpaired as u64;
        }
        if let Some(t) = &p.tcp {
            self.tcp_connected += t.connected as u64;
            self.frames_sent += t.frames_sent;
            self.frames_received += t.frames_received;
            self.tcp_bytes_sent += t.bytes_sent;
            self.tcp_bytes_received += t.bytes_received;
            self.partial_frames += t.partial as u64;
            self.peer_closes += t.peer_close as u64;
            match t.expectation {
                Some(true) => self.expectation_met += 1,
                Some(false) => self.expectation_short += 1,
                None => {}
            }
        }
        if let Some(d) = &p.dgram {
            self.dg_sent += d.sent;
            self.dg_received += d.received;
            if completed {
                if d.received > 0 {
                    self.with_response += 1;
                    if let Some(t) = d.ttfr_us {
                        self.first_response.record(t);
                    }
                } else {
                    self.silent += 1;
                }
            }
            self.repeated += d.repeated;
            self.echoed += d.echoed;
            self.icmp += d.icmp as u64;
            if let Some((status, dur)) = d.handshake {
                self.hs_attempted += 1;
                match status {
                    PhaseStatus::Completed => {
                        self.hs_completed += 1;
                        if let Some(us) = dur {
                            self.hs_duration.record(us);
                        }
                    }
                    PhaseStatus::Failed => self.hs_failed += 1,
                    PhaseStatus::TimedOut => self.hs_timed_out += 1,
                    _ => {}
                }
            }
        }
    }

    pub fn merge(&mut self, o: &ProtoAccum) {
        self.fallback_attempts += o.fallback_attempts;
        self.units_with_fallback += o.units_with_fallback;
        self.units_over_h3 += o.units_over_h3;
        for (c, n) in &o.grpc_codes {
            *self.grpc_codes.entry(*c).or_default() += n;
        }
        self.grpc_missing_status += o.grpc_missing_status;
        self.streams_opened += o.streams_opened;
        self.messages_received += o.messages_received;
        self.with_messages += o.with_messages;
        self.first_message.merge(&o.first_message);
        for (k, n) in &o.ends {
            *self.ends.entry(*k).or_default() += n;
        }
        self.ws_opened += o.ws_opened;
        self.ws_rejected += o.ws_rejected;
        self.ws_not_opened += o.ws_not_opened;
        self.ws_clean += o.ws_clean;
        self.ws_sent += o.ws_sent;
        self.ws_received += o.ws_received;
        self.rtt.merge(&o.rtt);
        self.rtt_unpaired += o.rtt_unpaired;
        self.tcp_connected += o.tcp_connected;
        self.frames_sent += o.frames_sent;
        self.frames_received += o.frames_received;
        self.tcp_bytes_sent += o.tcp_bytes_sent;
        self.tcp_bytes_received += o.tcp_bytes_received;
        self.partial_frames += o.partial_frames;
        self.peer_closes += o.peer_closes;
        self.expectation_met += o.expectation_met;
        self.expectation_short += o.expectation_short;
        self.dg_sent += o.dg_sent;
        self.dg_received += o.dg_received;
        self.with_response += o.with_response;
        self.silent += o.silent;
        self.repeated += o.repeated;
        self.echoed += o.echoed;
        self.icmp += o.icmp;
        self.first_response.merge(&o.first_response);
        self.hs_attempted += o.hs_attempted;
        self.hs_completed += o.hs_completed;
        self.hs_failed += o.hs_failed;
        self.hs_timed_out += o.hs_timed_out;
        self.hs_duration.merge(&o.hs_duration);
    }

    fn ends(&self) -> Vec<ClosedCount> {
        self.ends.iter().map(|((by, code), n)| ClosedCount { closed_by: closed_from(*by), code: *code, count: *n }).collect()
    }

    /// The report block for the plan's unit kind. `steps` are the plan's
    /// classified steps (they carry the request-level expectations).
    pub fn summary(&self, kind: LoadUnitKind, mode: ConnectionMode, steps: &[StepUnit]) -> ProtocolLoadMetrics {
        let mut m = ProtocolLoadMetrics {
            version: PROTOCOL_METRICS_VERSION,
            unit: kind,
            semantics: crate::protocol::semantics(kind, mode),
            ..Default::default()
        };
        let grpc = || {
            let ok = self.grpc_codes.get(&0).copied().unwrap_or(0);
            GrpcLoadMetrics {
                status_codes: self.grpc_codes.iter().map(|(c, n)| (*c, *n)).collect(),
                ok,
                non_ok: self.grpc_codes.values().sum::<u64>() - ok,
                missing_status: self.grpc_missing_status,
                protocol_fallback_attempts: self.fallback_attempts,
            }
        };
        let stream = |ended_by: Vec<ClosedCount>| StreamLoadMetrics {
            opened: self.streams_opened,
            messages_received: self.messages_received,
            with_messages: self.with_messages,
            time_to_first_message: self.first_message.summary(),
            ended_by,
        };
        match kind {
            LoadUnitKind::HttpRequest => {
                m.http = Some(HttpLoadMetrics {
                    protocol_fallback_attempts: self.fallback_attempts,
                    units_with_fallback: self.units_with_fallback,
                    units_over_h3: self.units_over_h3,
                })
            }
            LoadUnitKind::GrpcCall => m.grpc = Some(grpc()),
            LoadUnitKind::GrpcStream => {
                m.grpc = Some(grpc());
                m.stream = Some(stream(vec![]));
            }
            LoadUnitKind::SseStream => m.stream = Some(stream(self.ends())),
            LoadUnitKind::WebsocketSession => {
                let rtt_defined = steps.iter().any(|s| s.ws_expect_messages > 0);
                m.websocket = Some(WebSocketLoadMetrics {
                    opened: self.ws_opened,
                    handshake_rejected: self.ws_rejected,
                    not_opened: self.ws_not_opened,
                    closed_cleanly: self.ws_clean,
                    messages_sent: self.ws_sent,
                    messages_received: self.ws_received,
                    rtt_defined,
                    rtt_pairs: self.rtt.count(),
                    rtt: self.rtt.summary(),
                    rtt_unpaired_sessions: self.rtt_unpaired,
                    close_codes: self.ends(),
                })
            }
            LoadUnitKind::TcpExchange => {
                let expected: Vec<u32> = steps.iter().filter_map(|s| s.tcp_expect_frames).collect();
                m.tcp = Some(TcpLoadMetrics {
                    connected: self.tcp_connected,
                    frames_sent: self.frames_sent,
                    frames_received: self.frames_received,
                    payload_bytes_sent: self.tcp_bytes_sent,
                    payload_bytes_received: self.tcp_bytes_received,
                    partial_frames: self.partial_frames,
                    peer_closes: self.peer_closes,
                    // One value when every step expects the same count.
                    expected_frames: expected.first().copied().filter(|f| expected.len() == steps.len() && expected.iter().all(|e| e == f)),
                    expectation_met: self.expectation_met,
                    expectation_short: self.expectation_short,
                })
            }
            LoadUnitKind::UdpExchange | LoadUnitKind::DtlsExchange => {
                m.datagram = Some(DatagramLoadMetrics {
                    datagrams_sent: self.dg_sent,
                    datagrams_received: self.dg_received,
                    exchanges_with_response: self.with_response,
                    exchanges_silent: self.silent,
                    repeated_payloads: self.repeated,
                    echoed_payloads: self.echoed,
                    icmp_unreachable_exchanges: self.icmp,
                    time_to_first_datagram: self.first_response.summary(),
                    dtls_handshakes: (kind == LoadUnitKind::DtlsExchange).then(|| HandshakeMetrics {
                        attempted: self.hs_attempted,
                        completed: self.hs_completed,
                        failed: self.hs_failed,
                        timed_out: self.hs_timed_out,
                        duration: self.hs_duration.summary(),
                    }),
                })
            }
        }
        m
    }
}

#[derive(Debug, Clone, Default)]
pub struct Category {
    pub count: u64,
    pub examples: Vec<String>,
}

/// Mergeable per-shard metrics of the measured window.
#[derive(Debug, Clone)]
pub struct Metrics {
    pub success: LatencyStat,
    pub failure: LatencyStat,
    pub setup: LatencyStat,
    /// Elapsed time of timed-out sends (censored values).
    pub censored: LatencyStat,
    pub deadline_ms_min: Option<u64>,
    pub deadline_ms_max: Option<u64>,
    /// Open-workload start lag (scheduled → started).
    pub lag: LatencyStat,
    pub status: BTreeMap<u16, u64>,
    pub categories: BTreeMap<String, Category>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub protocols: BTreeMap<String, u64>,
    pub destinations: BTreeSet<String>,
    /// Protocol denominators (messages, sessions, frames, datagrams).
    pub proto: ProtoAccum,
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

impl Metrics {
    pub fn new() -> Self {
        Metrics {
            success: LatencyStat::new(PRIMARY_SIGFIG),
            failure: LatencyStat::new(PRIMARY_SIGFIG),
            setup: LatencyStat::new(SECONDARY_SIGFIG),
            censored: LatencyStat::new(SECONDARY_SIGFIG),
            deadline_ms_min: None,
            deadline_ms_max: None,
            lag: LatencyStat::new(SECONDARY_SIGFIG),
            status: BTreeMap::new(),
            categories: BTreeMap::new(),
            bytes_sent: 0,
            bytes_received: 0,
            protocols: BTreeMap::new(),
            destinations: BTreeSet::new(),
            proto: ProtoAccum::new(),
        }
    }

    pub fn record(&mut self, o: &SendObservation) {
        match o.terminal {
            Terminal::Canceled => {}
            Terminal::Timeout => {
                self.censored.record(o.latency_us);
                if let Some(d) = o.deadline_ms {
                    self.deadline_ms_min = Some(self.deadline_ms_min.map_or(d, |m| m.min(d)));
                    self.deadline_ms_max = Some(self.deadline_ms_max.map_or(d, |m| m.max(d)));
                }
            }
            _ if o.is_success() => self.success.record(o.latency_us),
            _ if o.is_failure() => self.failure.record(o.latency_us),
            // Completed without a response observed (UDP/DTLS): no latency exists.
            _ => {}
        }
        self.proto.record(o);
        if o.terminal != Terminal::Canceled {
            self.setup.record(o.setup_us);
        }
        if let Some(s) = o.status {
            *self.status.entry(s).or_default() += 1;
        }
        if let Some(c) = &o.category {
            self.add_category(c, 1, o.example.iter().cloned());
        }
        self.bytes_sent += o.bytes_sent;
        self.bytes_received += o.bytes_received;
        if let Some(p) = &o.protocol
            && (self.protocols.contains_key(p) || self.protocols.len() < MAX_PROTOCOLS)
        {
            *self.protocols.entry(p.clone()).or_default() += 1;
        }
        if let Some(d) = &o.destination
            && self.destinations.len() < MAX_DESTINATIONS
        {
            self.destinations.insert(d.clone());
        }
    }

    fn add_category(&mut self, name: &str, count: u64, examples: impl Iterator<Item = String>) {
        let key = if self.categories.contains_key(name) || self.categories.len() < MAX_CATEGORIES - 1 {
            name.to_string()
        } else {
            OTHER_CATEGORY.to_string()
        };
        let c = self.categories.entry(key).or_default();
        c.count += count;
        for e in examples {
            if c.examples.len() >= MAX_EXAMPLES {
                break;
            }
            c.examples.push(e);
        }
    }

    /// Merge another shard: histograms are added, counters summed, bounded
    /// collections stay bounded.
    pub fn merge(&mut self, o: &Metrics) {
        self.proto.merge(&o.proto);
        self.success.merge(&o.success);
        self.failure.merge(&o.failure);
        self.setup.merge(&o.setup);
        self.censored.merge(&o.censored);
        self.lag.merge(&o.lag);
        if let Some(b) = o.deadline_ms_min {
            self.deadline_ms_min = Some(self.deadline_ms_min.map_or(b, |x| x.min(b)));
        }
        if let Some(b) = o.deadline_ms_max {
            self.deadline_ms_max = Some(self.deadline_ms_max.map_or(b, |x| x.max(b)));
        }
        for (s, n) in &o.status {
            *self.status.entry(*s).or_default() += n;
        }
        for (name, c) in &o.categories {
            self.add_category(name, c.count, c.examples.iter().cloned());
        }
        self.bytes_sent += o.bytes_sent;
        self.bytes_received += o.bytes_received;
        for (p, n) in &o.protocols {
            if self.protocols.contains_key(p) || self.protocols.len() < MAX_PROTOCOLS {
                *self.protocols.entry(p.clone()).or_default() += n;
            }
        }
        for d in &o.destinations {
            if self.destinations.len() < MAX_DESTINATIONS {
                self.destinations.insert(d.clone());
            }
        }
    }

    /// Failure categories, most frequent first.
    pub fn failure_samples(&self) -> Vec<FailureSample> {
        let mut v: Vec<FailureSample> = self
            .categories
            .iter()
            .map(|(k, c)| FailureSample { category: k.clone(), count: c.count, examples: c.examples.clone() })
            .collect();
        v.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.category.cmp(&b.category)));
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Brute-force percentile over all raw samples, using the same rank rule
    /// as HdrHistogram (`round(q·n)`, at least 1).
    fn brute(sorted: &[u64], q: f64) -> u64 {
        let rank = ((q * sorted.len() as f64) + 0.5) as usize;
        sorted[rank.clamp(1, sorted.len()) - 1]
    }

    #[test]
    fn load_003_merge_histograms_before_percentiles() {
        // Two workers with deliberately unequal distributions: a fast, busy
        // worker and a slow, lightly loaded one.
        let mut fast = Metrics::new();
        let mut slow = Metrics::new();
        let mut all = Vec::new();
        let obs = |us: u64| SendObservation {
            terminal: Terminal::Completed,
            application_failure: false,
            assertion_failure: false,
            latency_us: us,
            setup_us: 0,
            deadline_ms: None,
            status: Some(200),
            bytes_sent: 0,
            bytes_received: 0,
            connections_opened: 0,
            connections_reused: 0,
            protocol: None,
            category: None,
            example: None,
            destination: None,
            ..Default::default()
        };
        for i in 0..10_000u64 {
            let v = 1_000 + (i * 7919) % 1_000; // 1.000–1.999 ms, shuffled
            fast.record(&obs(v));
            all.push(v);
        }
        for i in 0..100u64 {
            let v = 500_000 + i * 5_000; // 500–995 ms
            slow.record(&obs(v));
            all.push(v);
        }
        all.sort_unstable();
        let mut merged = Metrics::new();
        merged.merge(&fast);
        merged.merge(&slow);
        let s = merged.success.summary();
        assert_eq!(s.count, 10_100);
        for (q, got) in [(0.50, s.p50_us), (0.90, s.p90_us), (0.95, s.p95_us), (0.99, s.p99_us)] {
            let want = brute(&all, q);
            let tol = want / 1000 + 1; // HDR 3 significant figures
            assert!(got.abs_diff(want) <= tol, "q={q}: merged {got} vs brute force {want}");
        }
        for q in [0.995, 0.999] {
            let want = brute(&all, q);
            let got = merged.success.hist.value_at_quantile(q);
            assert!(got.abs_diff(want) <= want / 1000 + 1, "q={q}: merged {got} vs brute force {want}");
        }
        assert_eq!(s.min_us, 1_000);
        assert_eq!(s.max_us, 995_000);
        assert_eq!(s.mean_us, (all.iter().map(|v| *v as u128).sum::<u128>() / all.len() as u128) as u64);
        // Averaging per-worker p99 values would report ~0.5 s where the true
        // p99 is ~2 ms.
        let averaged = (fast.success.summary().p99_us + slow.success.summary().p99_us) / 2;
        assert!(averaged > 100 * s.p99_us, "averaged p99 {averaged} must be wildly off the merged {}", s.p99_us);

        // Serialized histograms merge identically after a round trip.
        let mut h = histogram_from_b64(&fast.success.to_b64()).unwrap();
        h.add(histogram_from_b64(&slow.success.to_b64()).unwrap()).unwrap();
        assert_eq!(summarize_histogram(&h).p99_us, merged.success.hist.value_at_quantile(0.99));
    }

    #[test]
    fn load_004_timeouts_never_enter_latency_distributions() {
        let mut m = Metrics::new();
        let mut o = SendObservation {
            terminal: Terminal::Timeout,
            application_failure: false,
            assertion_failure: false,
            latency_us: 150_000,
            setup_us: 10,
            deadline_ms: Some(150),
            status: None,
            bytes_sent: 10,
            bytes_received: 0,
            connections_opened: 1,
            connections_reused: 0,
            protocol: None,
            category: Some("timeout: total_timeout".into()),
            example: Some("GET … → no response".into()),
            destination: None,
            ..Default::default()
        };
        m.record(&o);
        o.terminal = Terminal::Completed;
        o.latency_us = 1_000;
        o.category = None;
        m.record(&o);
        assert_eq!(m.success.count(), 1);
        assert_eq!(m.failure.count(), 0);
        assert_eq!(m.censored.count(), 1);
        assert_eq!((m.deadline_ms_min, m.deadline_ms_max), (Some(150), Some(150)));
    }

    #[test]
    fn load_010_failure_samples_are_bounded() {
        let mut shards: Vec<Metrics> = (0..4).map(|_| Metrics::new()).collect();
        for i in 0..10_000u64 {
            let o = SendObservation {
                terminal: Terminal::TransportFailure,
                application_failure: false,
                assertion_failure: false,
                latency_us: 5,
                setup_us: 1,
                deadline_ms: None,
                status: None,
                bytes_sent: 0,
                bytes_received: 0,
                connections_opened: 0,
                connections_reused: 0,
                protocol: None,
                category: Some(format!("transport_failure: kind_{}", i % 100)),
                example: Some("x".repeat(MAX_EXAMPLE_CHARS)),
                destination: Some(format!("http://h{i}:1")),
                ..Default::default()
            };
            shards[(i % 4) as usize].record(&o);
        }
        let mut merged = Metrics::new();
        shards.iter().for_each(|s| merged.merge(s));
        let samples = merged.failure_samples();
        assert!(samples.len() <= MAX_CATEGORIES);
        assert_eq!(samples.iter().map(|s| s.count).sum::<u64>(), 10_000, "overflow is counted, not discarded");
        assert!(samples.iter().any(|s| s.category == OTHER_CATEGORY));
        assert!(samples.iter().all(|s| s.examples.len() <= MAX_EXAMPLES));
        assert!(merged.destinations.len() <= MAX_DESTINATIONS);
    }

    #[test]
    fn examples_are_truncated_on_char_boundaries() {
        let s = "é".repeat(MAX_EXAMPLE_CHARS + 10);
        let t = truncate_chars(&s, MAX_EXAMPLE_CHARS);
        assert_eq!(t.chars().count(), MAX_EXAMPLE_CHARS + 1);
    }
}
