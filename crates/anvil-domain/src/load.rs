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

/// Counts that must balance: scheduled = started + dropped (open workloads);
/// started = completed + failed + canceled + in-flight-at-end.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
pub struct LoadCounts {
    pub scheduled: u64,
    pub started: u64,
    pub dropped: u64,
    pub completed: u64,
    /// Transport failures (no complete response).
    pub transport_failures: u64,
    /// Complete responses with application failure (4xx/5xx, gRPC non-OK).
    pub application_failures: u64,
    pub assertion_failures: u64,
    /// Requests that hit a deadline (censored latency).
    pub timeouts: u64,
    pub canceled: u64,
    pub in_flight_at_end: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Default)]
pub struct GeneratorHealth {
    pub peak_cpu_percent: Option<f64>,
    pub peak_rss_bytes: Option<u64>,
    /// Maximum observed lag between a scheduled arrival and its start.
    pub max_schedule_lag_us: u64,
    pub p99_schedule_lag_us: u64,
    /// True when the generator could not sustain the planned target.
    pub target_not_achieved: bool,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct TimeBucket {
    pub second: u64,
    pub started: u64,
    pub completed: u64,
    pub failures: u64,
    pub dropped: u64,
    pub p50_us: u64,
    pub p99_us: u64,
    pub in_flight: u64,
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
    pub achieved_rate_per_sec: f64,
    /// Latency of complete successful responses.
    pub latency_success: LatencySummary,
    /// Latency of failed attempts (to failure time).
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
}
