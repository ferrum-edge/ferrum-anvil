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

/// Send ledger of the measured window: one entry per `Engine::execute` call.
/// Balances like [`LoadCounts`]:
/// `started = completed + transport_failures + timeouts + canceled + in_flight_at_end`.
///
/// `completed` means a complete response was received for a request/response
/// protocol. Datagram and stream denominators (UDP datagrams sent/received,
/// WebSocket messages, gRPC stream messages) are not modelled here: the load
/// engine refuses non-HTTP requests rather than implying delivery (LOAD-013).
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
    /// SHA-256 of the canonical JSON of this report with this field unset;
    /// verified when a saved report is reopened.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub integrity_sha256: Option<String>,
}
