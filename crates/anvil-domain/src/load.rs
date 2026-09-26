//! Load-plan and load-report contracts. Load runs execute the same prepared
//! requests, auth generation, TLS policy and outcome classifier as a manual
//! Send, in a separate worker process.

use crate::Id;
use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Stage {
    pub duration_secs: u64,
    /// Target at the end of the stage (arrivals/s for open workloads, VUs for
    /// closed); linear ramp from the previous stage's target.
    pub target: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "model", rename_all = "snake_case")]
pub enum Workload {
    /// Closed workload: fixed virtual users; slow responses reduce offered rate.
    ClosedVirtualUsers {
        stages: Vec<Stage>,
        #[serde(default)]
        think_time_ms: u64,
    },
    /// Open workload: scheduled arrivals independent of response time. Late
    /// arrivals beyond `max_in_flight` are dropped and counted, never queued
    /// without bound.
    OpenArrivalRate { stages: Vec<Stage>, max_in_flight: u64 },
    /// Fixed number of iterations as fast as `concurrency` allows.
    Iterations { iterations: u64, concurrency: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionMode {
    /// Reuse connections within each virtual user / slot.
    #[default]
    Persistent,
    /// Force a new connection per iteration.
    Fresh,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct WeightedStep {
    pub request_id: Id,
    #[serde(default = "one")]
    pub weight: u32,
}

fn one() -> u32 {
    1
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AbortRule {
    /// Abort when the failure ratio over the last window exceeds this (0–1, as permille).
    pub max_failure_permille: u32,
    pub window_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct LoadPlan {
    pub id: Id,
    pub workspace_id: Id,
    pub name: String,
    pub workload: Workload,
    /// A sequential chain executed per iteration (with extraction), or a
    /// weighted mix (one request per iteration) when `mix` is non-empty.
    #[serde(default)]
    pub chain: Vec<Id>,
    #[serde(default)]
    pub mix: Vec<WeightedStep>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dataset_id: Option<Id>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment_id: Option<Id>,
    #[serde(default)]
    pub connection_mode: ConnectionMode,
    #[serde(default)]
    pub warmup_secs: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub abort: Option<AbortRule>,
    /// Seed for weighted selection / generated data.
    #[serde(default)]
    pub seed: u64,
    /// Imported plans are never auto-started; the user must acknowledge the
    /// destination and ownership reminder for each run.
    #[serde(default)]
    pub trusted: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
pub struct LatencySummary {
    pub count: u64,
    pub min_us: u64,
    pub max_us: u64,
    pub mean_us: u64,
    pub p50_us: u64,
    pub p90_us: u64,
    pub p95_us: u64,
    pub p99_us: u64,
}

/// Iteration ledger of the measured window. One *iteration* is one arrival
/// (open workload) or one pass of a virtual user / concurrency lane: a single
/// request for a weighted mix, or the whole sequential chain.
///
/// The counts always balance:
/// * `scheduled = started + dropped` (only open workloads drop; closed and
///   iteration workloads schedule exactly what they start);
/// * `started = completed + transport_failures + timeouts + canceled + in_flight_at_end`
///   — the five terminal classes are disjoint.
///
/// `application_failures` and `assertion_failures` are *subsets* of
/// `completed` (a complete response that failed at the application level or
/// an assertion) and may overlap each other.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
pub struct LoadCounts {
    pub scheduled: u64,
    pub started: u64,
    /// Open-workload arrivals not started because `max_in_flight` was reached.
    pub dropped: u64,
    /// Every step of the iteration received a complete response (any status).
    pub completed: u64,
    /// Ended by a transport failure other than a deadline (no complete response).
    pub transport_failures: u64,
    /// Completed iterations with at least one application failure (4xx/5xx, gRPC non-OK).
    pub application_failures: u64,
    /// Completed iterations with at least one failed assertion.
    pub assertion_failures: u64,
    /// Ended by a deadline (censored latency; see [`CensoredTimeouts`]).
    pub timeouts: u64,
    /// Ended by run cancellation (user cancel, abort rule, graceful-stop limit).
    pub canceled: u64,
    /// Started but with no known outcome when the report was produced (worker
    /// crash, or a send that ignored cancellation past the drain limit).
    pub in_flight_at_end: u64,
}

/// Unit ledger of the measured window: one entry per `Engine::execute` call,
/// i.e. one *unit* of the plan's [`LoadUnitKind`] (an HTTP request, a gRPC
/// call or stream, an SSE stream, a WebSocket session, a TCP exchange or a
/// UDP/DTLS exchange). Balances like [`LoadCounts`]:
/// `started = completed + transport_failures + timeouts + canceled + in_flight_at_end`.
///
/// What `completed` means depends on the unit (see
/// [`ProtocolLoadMetrics::semantics`]): a complete response for HTTP, a
/// terminal gRPC status with complete framing, a stream or session that ended
/// without a failure, an exchange that ran to its stop condition. Messages,
/// events, frames and datagrams are counted per unit in
/// [`ProtocolLoadMetrics`]; they are never folded into these counts, and a
/// datagram sent is never counted as delivered (LOAD-013).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
pub struct RequestCounts {
    pub started: u64,
    pub completed: u64,
    pub transport_failures: u64,
    pub timeouts: u64,
    pub canceled: u64,
    pub in_flight_at_end: u64,
    /// Subset of `completed`.
    pub application_failures: u64,
    /// Subset of `completed`.
    pub assertion_failures: u64,
    /// Attempts that opened a new connection (engine evidence).
    pub connections_opened: u64,
    /// Attempts served on a reused pooled connection.
    pub connections_reused: u64,
}

/// Sends abandoned at a deadline. Their elapsed time is a *lower bound* on the
/// latency the target would have produced, so they are excluded from both
/// latency distributions and summarised separately.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
pub struct CensoredTimeouts {
    pub count: u64,
    /// Smallest / largest configured deadline that elapsed, when recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deadline_ms_min: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deadline_ms_max: Option<u64>,
    /// Elapsed time when each send was abandoned (censored values, not latencies).
    pub elapsed_at_timeout: LatencySummary,
    pub label: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Default)]
pub struct GeneratorHealth {
    /// Peak process CPU (user + system time over wall time; 100 = one core).
    /// `None` when the platform measurement is unavailable.
    pub peak_cpu_percent: Option<f64>,
    pub peak_rss_bytes: Option<u64>,
    /// Peak open file descriptors (sockets included), when measurable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peak_open_fds: Option<u64>,
    /// Maximum observed lag between a scheduled arrival and its start.
    pub max_schedule_lag_us: u64,
    pub p99_schedule_lag_us: u64,
    /// True when the generator could not sustain the planned target.
    pub target_not_achieved: bool,
    pub notes: Vec<String>,
}

/// One timeline bucket (send level, except `dropped`, which counts arrivals).
/// Includes warmup seconds, flagged, which are excluded from summary metrics.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct TimeBucket {
    /// Bucket start, seconds from run start.
    pub second: u64,
    /// Sends started in the bucket.
    pub started: u64,
    /// Sends that received a complete response in the bucket (any status).
    pub completed: u64,
    /// Sends that failed in the bucket (transport, timeout, application or assertion).
    pub failures: u64,
    /// Arrivals dropped in the bucket (open workloads).
    pub dropped: u64,
    /// Successful-send latency percentiles of sends completing in the bucket.
    pub p50_us: u64,
    pub p99_us: u64,
    /// Peak sends in flight during the bucket.
    pub in_flight: u64,
    #[serde(default)]
    pub warmup: bool,
    /// p99 start lag (scheduled arrival → actual start) of arrivals in the bucket.
    #[serde(default)]
    pub p99_schedule_lag_us: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct FailureSample {
    pub category: String,
    pub count: u64,
    /// Up to a bounded number of representative redacted examples.
    pub examples: Vec<String>,
}

/// What one load *unit* is (LOAD-013). A plan has exactly one unit kind:
/// every request in its chain or mix must produce the same kind, so every
/// count, rate and latency in a report has a single denominator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum LoadUnitKind {
    /// One HTTP request/response over HTTP/1.1, HTTP/2 or HTTP/3 (redirects,
    /// retries and an HTTP/3 → TCP fallback are attempts inside it).
    #[default]
    HttpRequest,
    /// One unary gRPC or gRPC-Web call.
    GrpcCall,
    /// One server-streaming gRPC or gRPC-Web call.
    GrpcStream,
    /// One server-sent-events stream.
    SseStream,
    /// One WebSocket session: handshake, scripted messages, close.
    WebsocketSession,
    /// One TCP or TLS connection carrying the request's scripted frames.
    TcpExchange,
    /// One UDP exchange: the request's datagrams, then its response window.
    UdpExchange,
    /// One DTLS handshake, then the request's datagrams and response window.
    DtlsExchange,
}

/// Version of [`ProtocolLoadMetrics`]; bumped when a field changes meaning.
pub const PROTOCOL_METRICS_VERSION: u32 = 1;

/// Plain-language definitions that travel with every report, so a reader
/// never has to guess what a count or a latency refers to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
pub struct UnitSemantics {
    /// `request`, `call`, `stream`, `session`, `exchange`.
    pub unit_singular: String,
    pub unit_plural: String,
    /// When a unit counts as `completed` in the unit ledger.
    pub completed_means: String,
    /// When a completed unit is a success (and enters the success latency).
    pub success_means: String,
    /// What `latency_success` / `latency_failure` measure for this unit.
    pub latency_means: String,
    /// How the plan's connection mode applies to this unit.
    pub connection_mode_means: String,
}

/// HTTP requests (all HTTP versions).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
pub struct HttpLoadMetrics {
    /// Attempts made over TCP after HTTP/3 failed before a response (the
    /// automatic HTTP/3 policy). Extra attempts inside a request, never
    /// extra requests.
    pub protocol_fallback_attempts: u64,
    /// Requests that needed such a fallback.
    pub units_with_fallback: u64,
    /// Requests whose final attempt ran over HTTP/3.
    pub units_over_h3: u64,
}

/// gRPC calls and streams (native gRPC and gRPC-Web).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
pub struct GrpcLoadMetrics {
    /// Terminal `grpc-status` of every completed unit (code → count). Sums to
    /// the unit ledger's `completed`: a unit completes only with a status and
    /// complete framing.
    pub status_codes: Vec<(i32, u64)>,
    /// Completed with status 0 (OK).
    pub ok: u64,
    /// Completed with a non-OK status; equals the ledger's application failures.
    pub non_ok: u64,
    /// A response arrived but no terminal status did: the RPC result is
    /// unknown, so the unit is incomplete (a transport failure or timeout in
    /// the ledger) and never a success.
    pub missing_status: u64,
    /// Attempts over TCP after HTTP/3 failed before the call was sent.
    pub protocol_fallback_attempts: u64,
}

/// Server-streaming gRPC calls and SSE streams.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
pub struct StreamLoadMetrics {
    /// Streams whose response head was accepted (gRPC: HTTP 200; SSE: 2xx).
    pub opened: u64,
    /// gRPC response messages or SSE events received, over all measured streams.
    pub messages_received: u64,
    /// Opened streams that received at least one message or event.
    pub with_messages: u64,
    /// Unit start → first message/event, over streams that received one.
    pub time_to_first_message: LatencySummary,
    /// SSE only: how opened streams ended (`peer` = the server ended it,
    /// `client` = the request's `max_events`, `timeout` = its idle timeout or
    /// the total deadline, `abnormal` = a failure).
    #[serde(default)]
    pub ended_by: Vec<ClosedCount>,
}

/// How many units ended one way.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ClosedCount {
    pub closed_by: crate::outcome::ClosedBy,
    /// WebSocket close code, when one was exchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<u16>,
    pub count: u64,
}

/// WebSocket sessions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
pub struct WebSocketLoadMetrics {
    /// Handshake accepted (101, or 200 for extended CONNECT).
    pub opened: u64,
    /// The server answered the handshake with another status (see the status distribution).
    pub handshake_rejected: u64,
    /// No usable handshake answer: DNS, connect, proxy, TLS, an invalid
    /// handshake response, a timeout or a cancel before the session opened.
    pub not_opened: u64,
    /// Opened sessions that ended without a failure (a close handshake by
    /// either side, the request's `expect_messages`, or its idle close).
    pub closed_cleanly: u64,
    /// Text and binary messages sent / received (control frames excluded).
    pub messages_sent: u64,
    pub messages_received: u64,
    /// Round-trip times exist only when a request defines `expect_messages`:
    /// the i-th scripted data message sent is paired with the i-th data
    /// message received (an echo-style exchange). Otherwise no RTT is claimed.
    pub rtt_defined: bool,
    pub rtt_pairs: u64,
    pub rtt: LatencySummary,
    /// Opened sessions whose messages could not be paired (transcript bound
    /// reached, or a reply arrived before its message was sent).
    pub rtt_unpaired_sessions: u64,
    /// Opened sessions by who closed and the close code.
    pub close_codes: Vec<ClosedCount>,
}

/// TCP/TLS framed exchanges.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
pub struct TcpLoadMetrics {
    /// Connections that completed setup (TCP, proxy tunnel, TLS) — one per exchange.
    pub connected: u64,
    /// Frames (with a framing preset) or chunks (without one) sent / received.
    pub frames_sent: u64,
    pub frames_received: u64,
    pub payload_bytes_sent: u64,
    pub payload_bytes_received: u64,
    /// Exchanges that ended with a partial trailing frame.
    pub partial_frames: u64,
    /// Exchanges the peer closed (FIN) before a local stop condition.
    pub peer_closes: u64,
    /// The request's `expect_frames`, when it has a framing preset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_frames: Option<u32>,
    /// Completed exchanges that received the expected frames.
    pub expectation_met: u64,
    /// Completed exchanges that received fewer (counted as application failures).
    pub expectation_short: u64,
}

/// A DTLS handshake measured as its own phase.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
pub struct HandshakeMetrics {
    pub attempted: u64,
    pub completed: u64,
    pub failed: u64,
    pub timed_out: u64,
    /// Duration of completed handshakes.
    pub duration: LatencySummary,
}

/// UDP and DTLS datagram exchanges. Sent and received are separate counts:
/// UDP has no acknowledgement, so nothing here infers delivery or loss.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
pub struct DatagramLoadMetrics {
    pub datagrams_sent: u64,
    pub datagrams_received: u64,
    /// Completed exchanges with at least one datagram received.
    pub exchanges_with_response: u64,
    /// Completed exchanges with none received in the window: "no response
    /// observed" — not a failure, not a loss, not a delivery.
    pub exchanges_silent: u64,
    /// Received datagrams byte-identical to an earlier one in the same exchange.
    pub repeated_payloads: u64,
    /// Received datagrams byte-identical to a datagram sent in the same
    /// exchange (echo-shaped). The rest are "other payloads"; neither says
    /// which datagram, if any, was delivered.
    pub echoed_payloads: u64,
    /// Exchanges in which the OS reported ICMP port unreachable.
    pub icmp_unreachable_exchanges: u64,
    /// First datagram sent → first datagram received, per responding exchange.
    pub time_to_first_datagram: LatencySummary,
    /// DTLS exchanges only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dtls_handshakes: Option<HandshakeMetrics>,
}

/// Protocol-specific denominators of a run (LOAD-013). Exactly one family
/// block is set for the plan's unit kind (gRPC streams set `grpc` and `stream`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
pub struct ProtocolLoadMetrics {
    /// [`PROTOCOL_METRICS_VERSION`] of the producing engine.
    pub version: u32,
    pub unit: LoadUnitKind,
    pub semantics: UnitSemantics,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http: Option<HttpLoadMetrics>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grpc: Option<GrpcLoadMetrics>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream: Option<StreamLoadMetrics>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub websocket: Option<WebSocketLoadMetrics>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcp: Option<TcpLoadMetrics>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub datagram: Option<DatagramLoadMetrics>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RunCompletion {
    Completed,
    CanceledByUser,
    AbortedByRule,
    WorkerCrashed,
    StoppedByLock,
}

/// Saved, self-describing load report. Viewable offline.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct LoadReport {
    pub run_id: Id,
    pub schema_version: u32,
    pub engine: String,
    pub engine_version: String,
    pub plan: LoadPlan,
    /// Revision ids of the requests executed.
    pub request_revisions: Vec<Id>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dataset_sha256: Option<String>,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    pub completion: RunCompletion,
    /// True if the report is partial (cancel, crash, abort, lock).
    pub partial: bool,
    pub warmup_included_in_metrics: bool,
    pub destination_summary: Vec<String>,
    pub counts: LoadCounts,
    /// Iterations started per second over the measured window.
    pub achieved_rate_per_sec: f64,
    /// Network-exchange latency (sum of attempt durations) of successful sends:
    /// complete response, application success, assertions passed or not run.
    pub latency_success: LatencySummary,
    /// Latency of failed sends to their failure point: transport failures,
    /// application failures and assertion failures. Timeouts (censored) and
    /// cancellations are excluded.
    pub latency_failure: LatencySummary,
    /// Mergeable serialized HDR histogram (V2 + DEFLATE, base64) of success latency.
    pub histogram_success_b64: String,
    pub status_distribution: Vec<(u16, u64)>,
    pub failure_categories: Vec<FailureSample>,
    pub timeline: Vec<TimeBucket>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub generator: GeneratorHealth,
    pub notes: Vec<String>,
    /// Send ledger (see [`RequestCounts`]); equals `counts` for single-request iterations.
    #[serde(default)]
    pub requests: RequestCounts,
    /// Human label of the workload semantics (closed/open/iterations).
    #[serde(default)]
    pub workload_label: String,
    /// Scheduled arrivals per second over the measured window (open workloads only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offered_rate_per_sec: Option<f64>,
    /// Length of the measured window (after warmup, until scheduling stopped).
    #[serde(default)]
    pub measured_duration_secs: f64,
    #[serde(default)]
    pub timeouts_censored: CensoredTimeouts,
    /// Local time around the network exchange: preparation, token
    /// acquisition/refresh, retry backoff and record assembly.
    #[serde(default)]
    pub latency_setup: LatencySummary,
    /// Mergeable serialized HDR histogram (V2 + DEFLATE, base64) of failure latency.
    #[serde(default)]
    pub histogram_failure_b64: String,
    /// Negotiated application protocols observed (e.g. `http/1.1`, `h2`) → sends.
    #[serde(default)]
    pub protocols: Vec<(String, u64)>,
    #[serde(default)]
    pub warmup_iterations_excluded: u64,
    #[serde(default)]
    pub warmup_sends_excluded: u64,
    /// The unit kind, its definitions and its protocol-specific denominators
    /// (messages, sessions, frames, datagrams). `None` only in reports written
    /// before protocol load existed, which were HTTP-only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol_metrics: Option<ProtocolLoadMetrics>,
    /// SHA-256 of the canonical JSON of this report with this field unset;
    /// verified when a saved report is reopened.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub integrity_sha256: Option<String>,
}
