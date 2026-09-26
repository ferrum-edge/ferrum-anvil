//! Workload execution.
//!
//! * **Closed** (`ClosedVirtualUsers`): each virtual user runs iterations back
//!   to back (plus think time). Slow responses reduce the offered rate; the
//!   report labels this.
//! * **Open** (`OpenArrivalRate`): arrivals follow the stage schedule
//!   independently of response time. Each arrival is started if a slot is
//!   free, otherwise it is **dropped and counted** — never queued. Start lag
//!   (scheduled → actual start) is measured.
//! * **Iterations**: a fixed number of iterations over bounded concurrency.
//!
//! Every send is one `Engine::execute(ctx, EventCtx::none(), cancel)` call,
//! so request bytes, auth generation and TLS policy match a manual Send. Each
//! slot (virtual user / concurrency lane / in-flight slot) has its own engine
//! (own connection pool, gRPC channels and cookie jar) while all slots share
//! one OAuth [`TokenCache`](anvil_auth::oauth::TokenCache), so token refresh
//! stays single-flight across the whole run. Each send is one *unit* of the
//! plan's [`LoadUnitKind`] (see [`crate::protocol`]).

use crate::LoadError;
use crate::dataset::Dataset;
use crate::health::{self, HealthSampler};
use crate::metrics::{self, Metrics, SECONDARY_SIGFIG, SendObservation, Terminal, new_histogram};
use crate::protocol::{self, StepUnit};
use crate::report::{self, RunMeta};
use crate::schedule;
use anvil_domain::Id;
use anvil_domain::load::*;
use anvil_domain::settings::{Limits, SettingsOverrides};
use anvil_engine::context::DATASET_SKIPPED_UNDER_IMPORT_ROOT;
use anvil_engine::vars::{VarEntry, VarLayer};
use anvil_engine::{Engine, ExecutionContext};
use anvil_transport::recorder::EventCtx;
use chrono::Utc;
use hdrhistogram::Histogram;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

pub const MAX_VUS: u64 = 5_000;
pub const MAX_CONCURRENCY: u64 = 5_000;
pub const MAX_IN_FLIGHT: u64 = 10_000;
pub const MAX_RATE_PER_SEC: u64 = 100_000;
pub const MAX_DURATION_SECS: u64 = 24 * 3600;
pub const MAX_ITERATIONS: u64 = 100_000_000;
pub const MAX_CHAIN_STEPS: usize = 64;
pub const MAX_TIMELINE_BUCKETS: u64 = 3_600;
pub const MAX_SHARDS: usize = 8;
/// Response bytes retained in memory per send for assertions/extraction
/// (the full body is still read and counted).
pub const DEFAULT_CAPTURE_BYTES: u64 = 1024 * 1024;
/// Minimum sends in the abort window before the ratio is evaluated.
pub const ABORT_MIN_SENDS: u64 = 10;
/// After in-flight sends are canceled, how long to wait for them to report.
pub const HARD_CANCEL_GRACE: Duration = Duration::from_secs(2);
pub const MIN_PROGRESS_INTERVAL_MS: u64 = 250;

/// Resolved inputs for a run (in process). The worker builds this from a
/// [`crate::job::WorkerJob`].
pub struct LoadJob {
    /// Frozen execution context per request id referenced by the plan
    /// (secrets resolve through each context's scoped resolver).
    pub requests: HashMap<Id, ExecutionContext>,
    pub dataset: Option<Dataset>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunOptions {
    /// The user saw the destination, planned rate/concurrency/duration and
    /// the ownership reminder, and explicitly started this run. Required for
    /// every run; imported plans are never auto-started.
    pub acknowledged: bool,
    /// After the schedule ends, how long in-flight iterations may finish
    /// before they are canceled.
    #[serde(default = "d_graceful")]
    pub graceful_stop_ms: u64,
    /// After a user cancel or abort, how long in-flight sends may finish
    /// before they are canceled.
    #[serde(default = "d_cancel")]
    pub cancel_drain_ms: u64,
    /// Progress cadence (clamped to ≥ 250 ms, i.e. ≤ 4 events/s).
    #[serde(default = "d_progress")]
    pub progress_interval_ms: u64,
    /// Per-send in-memory response capture ceiling (never raised above the
    /// request's own setting).
    #[serde(default = "d_capture")]
    pub response_capture_bytes: u64,
}

fn d_graceful() -> u64 {
    5_000
}
fn d_cancel() -> u64 {
    2_000
}
fn d_progress() -> u64 {
    500
}
fn d_capture() -> u64 {
    DEFAULT_CAPTURE_BYTES
}

impl Default for RunOptions {
    fn default() -> Self {
        RunOptions {
            acknowledged: false,
            graceful_stop_ms: d_graceful(),
            cancel_drain_ms: d_cancel(),
            progress_interval_ms: d_progress(),
            response_capture_bytes: d_capture(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunPhase {
    Warmup,
    Measuring,
    Draining,
}

/// Metrics of the measured window at one instant. Counts balance at every
/// snapshot (in-flight work is reported as `in_flight_at_end`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct MetricsSnapshot {
    pub counts: LoadCounts,
    pub requests: RequestCounts,
    pub warmup_iterations_excluded: u64,
    pub warmup_sends_excluded: u64,
    pub measured_duration_secs: f64,
    pub achieved_rate_per_sec: f64,
    pub offered_rate_per_sec: Option<f64>,
    pub latency_success: LatencySummary,
    pub latency_failure: LatencySummary,
    pub latency_setup: LatencySummary,
    pub histogram_success_b64: String,
    pub histogram_failure_b64: String,
    pub timeouts_censored: CensoredTimeouts,
    pub status_distribution: Vec<(u16, u64)>,
    pub failure_categories: Vec<FailureSample>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub protocols: Vec<(String, u64)>,
    pub destinations: Vec<String>,
    pub generator: GeneratorHealth,
    /// Protocol denominators of the plan's unit kind (LOAD-013).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<ProtocolLoadMetrics>,
}

/// Throttled progress event (≤ 4/s). `timeline_delta` carries only buckets
/// finalized since the last *delivered* progress, starting at `timeline_from`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Progress {
    pub run_id: Id,
    pub elapsed_secs: f64,
    pub phase: RunPhase,
    /// Sends in flight right now (warmup and measured).
    pub in_flight: u64,
    pub snapshot: MetricsSnapshot,
    pub timeline_from: usize,
    pub timeline_delta: Vec<TimeBucket>,
}

/// Receives progress; returns `true` when the event was delivered (a lossy
/// sink may drop events under backpressure).
pub type ProgressSink = Arc<dyn Fn(&Progress) -> bool + Send + Sync>;

// ------------------------------------------------------------------ ledger

#[derive(Debug, Clone, Default)]
struct Ledger {
    counts: LoadCounts,
    requests: RequestCounts,
    iter_in_flight: u64,
    send_in_flight: u64,
}

impl Ledger {
    fn balanced(&self) -> (LoadCounts, RequestCounts) {
        let mut c = self.counts.clone();
        c.in_flight_at_end = self.iter_in_flight;
        let mut r = self.requests.clone();
        r.in_flight_at_end = self.send_in_flight;
        (c, r)
    }
}

#[derive(Default)]
struct LedgerState {
    measured: Ledger,
    warmup: Ledger,
    /// Timeline bucket → peak sends in flight.
    peaks: BTreeMap<u64, u64>,
    /// Abort-rule window: (second, finished sends, failed sends).
    ring: VecDeque<(u64, u64, u64)>,
}

impl LedgerState {
    fn side(&mut self, measured: bool) -> &mut Ledger {
        if measured { &mut self.measured } else { &mut self.warmup }
    }
}

// ---------------------------------------------------------------- timeline

#[derive(Default)]
struct BucketAccum {
    started: u64,
    completed: u64,
    failures: u64,
    dropped: u64,
    success: Option<Histogram<u64>>,
    lag: Option<Histogram<u64>>,
}

fn add_hist(slot: &mut Option<Histogram<u64>>, v: u64) {
    slot.get_or_insert_with(|| new_histogram(SECONDARY_SIGFIG)).saturating_record(v.clamp(1, metrics::LATENCY_MAX_US));
}

fn merge_hist(slot: &mut Option<Histogram<u64>>, o: Option<Histogram<u64>>) {
    match (slot.as_mut(), o) {
        (Some(a), Some(b)) => a.add(&b).expect("identical bounds"),
        (None, Some(b)) => *slot = Some(b),
        _ => {}
    }
}

impl BucketAccum {
    fn merge(&mut self, o: BucketAccum) {
        self.started += o.started;
        self.completed += o.completed;
        self.failures += o.failures;
        self.dropped += o.dropped;
        merge_hist(&mut self.success, o.success);
        merge_hist(&mut self.lag, o.lag);
    }
}

struct Shard {
    metrics: Metrics,
    pending: BTreeMap<u64, BucketAccum>,
}

// ------------------------------------------------------------------ shared

#[derive(Debug, Clone, PartialEq)]
enum StopReason {
    ScheduleEnd,
    UserCancel,
    /// The vault locked: the app's stop-runs-on-lock policy.
    Lock,
    Abort(String),
}

struct Shared {
    plan: LoadPlan,
    run_id: Id,
    steps: Vec<Arc<ExecutionContext>>,
    /// The unit each step produces (same order as `steps`).
    units: Vec<StepUnit>,
    unit: LoadUnitKind,
    /// Cumulative weights for a weighted mix; empty for a chain.
    mix_cumulative: Vec<u64>,
    dataset: Option<Dataset>,
    t0: Instant,
    warmup: Duration,
    bucket_width_secs: u64,
    engines: Vec<OnceLock<Arc<Engine>>>,
    /// Idle connections each slot's engine keeps per pool ([`slot_idle_cap`]).
    slot_idle: usize,
    tokens: Arc<anvil_auth::oauth::TokenCache>,
    ledger: Mutex<LedgerState>,
    shards: Vec<Mutex<Shard>>,
    iteration_seq: AtomicU64,
    /// No new iterations (schedule end, cancel, abort).
    stop: CancellationToken,
    /// No new chain steps either (cancel, abort, drain limit).
    halt: CancellationToken,
    /// Cancel in-flight sends.
    hard: CancellationToken,
    reason: Mutex<Option<StopReason>>,
    timeline_truncated: AtomicBool,
}

fn splitmix64(mut z: u64) -> u64 {
    z = z.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Deterministic weighted choice for iteration `iteration` under `seed`.
pub fn pick_weighted(seed: u64, cumulative: &[u64], iteration: u64) -> usize {
    let total = *cumulative.last().expect("non-empty mix");
    let r = splitmix64(seed ^ splitmix64(iteration)) % total;
    cumulative.iter().position(|c| r < *c).expect("r < total")
}

fn derive_seed(plan_seed: u64, ctx_seed: u64, iteration: u64, step: u64) -> u64 {
    splitmix64(plan_seed ^ splitmix64(ctx_seed ^ splitmix64(iteration.wrapping_mul(1_000_003).wrapping_add(step))))
}

/// Bounds of the idle connections one slot's engine keeps in total, per
/// pool.
const SLOT_MIN_IDLE: usize = 4;
const SLOT_MAX_IDLE: usize = 64;

/// Idle connections one slot keeps in total: one per distinct request of the
/// plan (chain steps or mix entries), within 4..=64. Each request sends to
/// one pool key at a time, so a persistent chain or mix touching up to 64
/// requests finds each one's connection still pooled on the next iteration
/// instead of the global cap closing it just before its reuse. Requests
/// beyond that (or redirects to other destinations) share the cap.
fn slot_idle_cap(ids: &[Id]) -> usize {
    let distinct: std::collections::HashSet<&Id> = ids.iter().collect();
    distinct.len().clamp(SLOT_MIN_IDLE, SLOT_MAX_IDLE)
}

/// Idle HTTP/1.1 and HTTP/2 connections one slot's engine keeps. A slot
/// sends one request at a time, so it rarely has more than one connection
/// per destination to return; the caps keep a run with many slots from
/// holding slots × 64 idle sockets (the default cap of an engine) unless
/// its plan touches that many destinations.
fn slot_http_pool(idle_total: usize) -> anvil_transport::http::PoolLimits {
    anvil_transport::http::PoolLimits { max_idle_per_key: 2, max_idle_total: idle_total, ..Default::default() }
}

/// Idle QUIC connections one slot's engine keeps (one per destination).
fn slot_h3_pool(idle_total: usize) -> anvil_transport::h3::PoolLimits {
    anvil_transport::h3::PoolLimits { max_idle_total: idle_total, ..Default::default() }
}

/// The engine of one slot: its own small connection pools and gRPC
/// channels, and the run's shared token cache.
fn slot_engine(tokens: Arc<anvil_auth::oauth::TokenCache>, idle_total: usize) -> Engine {
    let mut e = Engine::new();
    e.http = Arc::new(anvil_transport::http::HttpTransport::with_pool_limits(slot_http_pool(idle_total)));
    e.h3 = anvil_transport::h3::H3Transport::with_pool_limits(slot_h3_pool(idle_total));
    e.tokens = tokens;
    // gRPC calls reuse this slot's channels while keep-alive is on (the
    // persistent connection mode); fresh mode turns it off.
    e.grpc_channels = Some(Arc::new(anvil_transport::grpc::Channels::new()));
    e
}

impl Shared {
    fn engine(&self, slot: usize) -> Arc<Engine> {
        self.engines[slot].get_or_init(|| Arc::new(slot_engine(self.tokens.clone(), self.slot_idle))).clone()
    }

    fn shard(&self, slot: usize) -> &Mutex<Shard> {
        &self.shards[slot % self.shards.len()]
    }

    fn bucket_of(&self, at: Instant) -> u64 {
        at.saturating_duration_since(self.t0).as_secs() / self.bucket_width_secs
    }

    fn measured_at(&self, at: Instant) -> bool {
        at.saturating_duration_since(self.t0) >= self.warmup
    }

    fn with_bucket(&self, shard: &mut Shard, at: Instant, f: impl FnOnce(&mut BucketAccum)) {
        let b = self.bucket_of(at);
        if b >= MAX_TIMELINE_BUCKETS {
            self.timeline_truncated.store(true, Ordering::Relaxed);
            return;
        }
        f(shard.pending.entry(b).or_default());
    }

    fn set_reason(&self, r: StopReason) {
        let mut g = self.reason.lock();
        if g.is_none() {
            *g = Some(r);
        }
    }

    fn begin_iteration(&self, measured: bool) {
        let mut l = self.ledger.lock();
        let s = l.side(measured);
        s.counts.scheduled += 1;
        s.counts.started += 1;
        s.iter_in_flight += 1;
    }

    fn arrival_dropped(&self, measured: bool) {
        {
            let mut l = self.ledger.lock();
            let s = l.side(measured);
            s.counts.scheduled += 1;
            s.counts.dropped += 1;
        }
        let now = Instant::now();
        let mut sh = self.shards[0].lock();
        self.with_bucket(&mut sh, now, |b| b.dropped += 1);
    }

    fn record_lag(&self, slot: usize, measured: bool, lag: Duration) {
        let us = lag.as_micros() as u64;
        let now = Instant::now();
        let mut sh = self.shard(slot).lock();
        if measured {
            sh.metrics.lag.record(us);
        }
        self.with_bucket(&mut sh, now, |b| add_hist(&mut b.lag, us));
    }

    fn begin_send(&self, slot: usize, measured: bool) {
        let now = Instant::now();
        {
            let mut l = self.ledger.lock();
            let s = l.side(measured);
            s.requests.started += 1;
            s.send_in_flight += 1;
            let total = l.measured.send_in_flight + l.warmup.send_in_flight;
            let b = self.bucket_of(now);
            if b < MAX_TIMELINE_BUCKETS {
                let p = l.peaks.entry(b).or_default();
                *p = (*p).max(total);
            }
        }
        let mut sh = self.shard(slot).lock();
        self.with_bucket(&mut sh, now, |b| b.started += 1);
    }

    fn end_send(&self, slot: usize, measured: bool, o: &SendObservation) {
        let now = Instant::now();
        // Shard, then ledger (the order `snapshot` uses): a snapshot sees a
        // finished unit in both the ledger and the metrics, or in neither,
        // so protocol denominators balance in every progress snapshot.
        let mut sh = self.shard(slot).lock();
        {
            let mut l = self.ledger.lock();
            let s = l.side(measured);
            s.send_in_flight -= 1;
            let r = &mut s.requests;
            match o.terminal {
                Terminal::Completed => r.completed += 1,
                Terminal::TransportFailure => r.transport_failures += 1,
                Terminal::Timeout => r.timeouts += 1,
                Terminal::Canceled => r.canceled += 1,
            }
            r.application_failures += o.application_failure as u64;
            r.assertion_failures += o.assertion_failure as u64;
            r.connections_opened += o.connections_opened;
            r.connections_reused += o.connections_reused;
            if let Some(rule) = &self.plan.abort
                && o.terminal != Terminal::Canceled
            {
                let sec = now.saturating_duration_since(self.t0).as_secs();
                match l.ring.back_mut() {
                    Some(e) if e.0 == sec => {
                        e.1 += 1;
                        e.2 += o.is_failure() as u64;
                    }
                    _ => l.ring.push_back((sec, 1, o.is_failure() as u64)),
                }
                while l.ring.front().is_some_and(|e| e.0 + rule.window_secs.max(1) < sec) {
                    l.ring.pop_front();
                }
            }
        }
        if measured {
            sh.metrics.record(o);
        }
        self.with_bucket(&mut sh, now, |b| {
            b.completed += (o.terminal == Terminal::Completed) as u64;
            b.failures += o.is_failure() as u64;
            if o.is_success() {
                add_hist(&mut b.success, o.latency_us);
            }
        });
    }

    fn end_iteration(&self, measured: bool, terminal: Terminal, app: bool, assertion: bool) {
        let mut l = self.ledger.lock();
        let s = l.side(measured);
        s.iter_in_flight -= 1;
        let c = &mut s.counts;
        match terminal {
            Terminal::Completed => {
                c.completed += 1;
                c.application_failures += app as u64;
                c.assertion_failures += assertion as u64;
            }
            Terminal::TransportFailure => c.transport_failures += 1,
            Terminal::Timeout => c.timeouts += 1,
            Terminal::Canceled => c.canceled += 1,
        }
    }

    fn abort_triggered(&self) -> Option<String> {
        let rule = self.plan.abort.as_ref()?;
        let window = rule.window_secs.max(1);
        let now_sec = self.t0.elapsed().as_secs();
        let l = self.ledger.lock();
        let (fin, fail) = l.ring.iter().filter(|e| e.0 + window > now_sec).fold((0u64, 0u64), |(f, x), e| (f + e.1, x + e.2));
        (fin >= ABORT_MIN_SENDS && fail * 1000 > rule.max_failure_permille as u64 * fin).then(|| {
            format!(
                "Aborted by rule at {:.1} s: {fail} of {fin} sends failed ({:.1} %) in the last {window} s, above the {:.1} % limit.",
                self.t0.elapsed().as_secs_f64(),
                fail as f64 * 100.0 / fin as f64,
                rule.max_failure_permille as f64 / 10.0
            )
        })
    }

    /// Finalize timeline buckets with index `< upto`.
    fn flush(&self, tl: &mut Vec<TimeBucket>, upto: u64) {
        let upto = upto.min(MAX_TIMELINE_BUCKETS);
        let mut merged: BTreeMap<u64, BucketAccum> = BTreeMap::new();
        for s in &self.shards {
            let taken = {
                let mut g = s.lock();
                let keep = g.pending.split_off(&upto);
                std::mem::replace(&mut g.pending, keep)
            };
            for (k, v) in taken {
                merged.entry(k).or_default().merge(v);
            }
        }
        let peaks = {
            let mut l = self.ledger.lock();
            let keep = l.peaks.split_off(&upto);
            std::mem::replace(&mut l.peaks, keep)
        };
        let q = |h: &Option<Histogram<u64>>, p: f64| h.as_ref().map(|h| h.value_at_quantile(p)).unwrap_or(0);
        // Rare late records for already-finalized buckets: counts only.
        let next = tl.len() as u64;
        for (k, acc) in merged.range(..next) {
            let b = &mut tl[*k as usize];
            b.started += acc.started;
            b.completed += acc.completed;
            b.failures += acc.failures;
            b.dropped += acc.dropped;
        }
        for idx in next..upto {
            let acc = merged.remove(&idx).unwrap_or_default();
            let second = idx * self.bucket_width_secs;
            tl.push(TimeBucket {
                second,
                started: acc.started,
                completed: acc.completed,
                failures: acc.failures,
                dropped: acc.dropped,
                p50_us: q(&acc.success, 0.5),
                p99_us: q(&acc.success, 0.99),
                in_flight: peaks.get(&idx).copied().unwrap_or(0),
                warmup: Duration::from_secs(second) < self.warmup,
                p99_schedule_lag_us: q(&acc.lag, 0.99),
            });
        }
    }

    fn snapshot(&self, until: Instant, sampler: &HealthSampler) -> MetricsSnapshot {
        // Every shard, then the ledger (see `end_send`): one consistent cut.
        let guards: Vec<_> = self.shards.iter().map(|s| s.lock()).collect();
        let (measured, warmup) = {
            let l = self.ledger.lock();
            (l.measured.clone(), l.warmup.clone())
        };
        let mut m = Metrics::new();
        for g in &guards {
            m.merge(&g.metrics);
        }
        drop(guards);
        let (counts, requests) = measured.balanced();
        let dur = until.saturating_duration_since(self.t0 + self.warmup).as_secs_f64();
        let rate = |n: u64| if dur > 0.0 { n as f64 / dur } else { 0.0 };
        let open = matches!(self.plan.workload, Workload::OpenArrivalRate { .. });
        let lag = m.lag.summary();
        let censored = m.censored.summary();
        MetricsSnapshot {
            achieved_rate_per_sec: rate(counts.started),
            offered_rate_per_sec: open.then(|| rate(counts.scheduled)),
            counts,
            requests,
            warmup_iterations_excluded: warmup.counts.started,
            warmup_sends_excluded: warmup.requests.started,
            measured_duration_secs: dur,
            latency_success: m.success.summary(),
            latency_failure: m.failure.summary(),
            latency_setup: m.setup.summary(),
            histogram_success_b64: m.success.to_b64(),
            histogram_failure_b64: m.failure.to_b64(),
            timeouts_censored: CensoredTimeouts {
                count: censored.count,
                deadline_ms_min: m.deadline_ms_min,
                deadline_ms_max: m.deadline_ms_max,
                elapsed_at_timeout: censored,
                label: report::CENSORED_LABEL.into(),
            },
            status_distribution: m.status.iter().map(|(k, v)| (*k, *v)).collect(),
            failure_categories: m.failure_samples(),
            bytes_sent: m.bytes_sent,
            bytes_received: m.bytes_received,
            protocols: m.protocols.iter().map(|(k, v)| (k.clone(), *v)).collect(),
            destinations: m.destinations.iter().cloned().collect(),
            protocol: Some(m.proto.summary(self.unit, self.plan.connection_mode, &self.units)),
            generator: GeneratorHealth {
                peak_cpu_percent: sampler.peak_cpu_percent,
                peak_rss_bytes: sampler.peak_rss_bytes,
                peak_open_fds: sampler.peak_open_fds,
                max_schedule_lag_us: lag.max_us,
                p99_schedule_lag_us: lag.p99_us,
                target_not_achieved: false,
                notes: vec![],
            },
        }
    }

    fn in_flight(&self) -> u64 {
        let l = self.ledger.lock();
        l.measured.send_in_flight + l.warmup.send_in_flight
    }
}

struct SlotGuard {
    free: Arc<Mutex<Vec<usize>>>,
    slot: usize,
}

impl Drop for SlotGuard {
    fn drop(&mut self) {
        self.free.lock().push(self.slot);
    }
}

async fn run_iteration(sh: &Arc<Shared>, slot: usize, measured: bool) {
    let iter = sh.iteration_seq.fetch_add(1, Ordering::Relaxed);
    let engine = sh.engine(slot);
    let steps: Vec<usize> = if sh.mix_cumulative.is_empty() {
        (0..sh.steps.len()).collect()
    } else {
        vec![pick_weighted(sh.plan.seed, &sh.mix_cumulative, iter)]
    };
    let load = VarLayer {
        label: "load".into(),
        vars: vec![
            VarEntry { name: "anvil.iteration".into(), value: iter.to_string(), secret: false },
            VarEntry { name: "anvil.vu".into(), value: slot.to_string(), secret: false },
        ],
    };
    let row = sh.dataset.as_ref().map(|d| d.row_layer(iter));
    // Values extracted this iteration, each with the scope of the step that
    // extracted it (`ExecutionContext::scope`).
    let mut extracted: Vec<(Option<Id>, VarEntry)> = Vec::new();
    let (mut terminal, mut app, mut assertion) = (Terminal::Completed, false, false);
    for (pos, &si) in steps.iter().enumerate() {
        if pos > 0 && sh.halt.is_cancelled() {
            terminal = Terminal::Canceled;
            break;
        }
        let base = &sh.steps[si];
        let mut ctx = ExecutionContext::clone(base);
        ctx.var_layers.push(load.clone());
        // A step under a sealed import root sees only values extracted under
        // that root, and no dataset row (the dataset is the workspace's); a
        // step outside it never sees what it extracted.
        let scope = base.scope;
        if scope.is_none()
            && let Some(l) = &row
        {
            ctx.var_layers.push(l.clone());
        }
        let visible: Vec<VarEntry> = extracted.iter().filter(|(s, _)| *s == scope).map(|(_, e)| e.clone()).collect();
        if !visible.is_empty() {
            ctx.var_layers.push(VarLayer { label: "iteration (extracted)".into(), vars: visible });
        }
        ctx.seed = Some(derive_seed(sh.plan.seed, base.seed.unwrap_or(0), iter, pos as u64));
        sh.begin_send(slot, measured);
        let t = Instant::now();
        let out = engine.execute(&ctx, EventCtx::none(), sh.hard.clone()).await;
        let obs = metrics::observe(&out, t.elapsed().as_micros() as u64, &sh.units[si]);
        sh.end_send(slot, measured, &obs);
        app |= obs.application_failure;
        assertion |= obs.assertion_failure;
        if obs.terminal != Terminal::Completed {
            terminal = obs.terminal;
            break;
        }
        for (name, value, secret) in out.extracted {
            extracted.retain(|(s, e)| *s != scope || e.name != name);
            extracted.push((scope, VarEntry { name, value, secret }));
        }
    }
    sh.end_iteration(measured, terminal, app, assertion);
}

async fn sleep_or_stop(sh: &Shared, d: Duration) -> bool {
    tokio::select! {
        _ = tokio::time::sleep(d) => true,
        _ = sh.stop.cancelled() => false,
    }
}

/// Returns (time scheduling stopped, still-running tasks).
async fn drive_closed(sh: Arc<Shared>, stages: Vec<Stage>, think: Duration, total_secs: u64) -> (Instant, JoinSet<()>) {
    let end = sh.t0 + Duration::from_secs(total_secs);
    let max_vus = stages.iter().map(|s| s.target).max().unwrap_or(0) as usize;
    let stages = Arc::new(stages);
    let mut set = JoinSet::new();
    for vu in 0..max_vus {
        let (sh, stages) = (sh.clone(), stages.clone());
        set.spawn(async move {
            loop {
                let now = Instant::now();
                if sh.stop.is_cancelled() || now >= end {
                    break;
                }
                let t = now.duration_since(sh.t0).as_secs_f64();
                if schedule::vus_at(&stages, t) as usize <= vu {
                    // Inactive: sleep until the ramp reaches this VU (computed,
                    // not polled, so thousands of idle VUs cost nothing).
                    let Some(next) = schedule::next_time_at_or_above(&stages, t, (vu + 1) as f64) else { break };
                    let wake = (sh.t0 + Duration::from_secs_f64(next)).max(now + Duration::from_millis(1));
                    if wake >= end || !sleep_or_stop(&sh, wake - now).await {
                        break;
                    }
                    continue;
                }
                let measured = sh.measured_at(now);
                sh.begin_iteration(measured);
                run_iteration(&sh, vu, measured).await;
                if !think.is_zero() && !sleep_or_stop(&sh, think).await {
                    break;
                }
            }
        });
    }
    tokio::select! {
        _ = tokio::time::sleep_until(end.into()) => sh.set_reason(StopReason::ScheduleEnd),
        _ = sh.stop.cancelled() => {}
    }
    let at = Instant::now();
    sh.stop.cancel();
    (at, set)
}

async fn drive_open(sh: Arc<Shared>, stages: Vec<Stage>, max_in_flight: usize, total_secs: u64) -> (Instant, JoinSet<()>) {
    let end = sh.t0 + Duration::from_secs(total_secs);
    let free: Arc<Mutex<Vec<usize>>> = Arc::new(Mutex::new((0..max_in_flight).rev().collect()));
    let mut set = JoinSet::new();
    for offset in schedule::Arrivals::new(&stages) {
        let at = sh.t0 + Duration::from_secs_f64(offset);
        if at >= end {
            break;
        }
        tokio::select! {
            biased;
            _ = sh.stop.cancelled() => break,
            _ = tokio::time::sleep_until(at.into()) => {}
        }
        while set.try_join_next().is_some() {}
        let measured = sh.measured_at(at);
        let slot = free.lock().pop();
        match slot {
            None => sh.arrival_dropped(measured),
            Some(slot) => {
                sh.begin_iteration(measured);
                let (sh2, guard) = (sh.clone(), SlotGuard { free: free.clone(), slot });
                set.spawn(async move {
                    let _guard = guard;
                    sh2.record_lag(slot, measured, Instant::now().saturating_duration_since(at));
                    run_iteration(&sh2, slot, measured).await;
                });
            }
        }
    }
    tokio::select! {
        _ = tokio::time::sleep_until(end.into()) => sh.set_reason(StopReason::ScheduleEnd),
        _ = sh.stop.cancelled() => {}
    }
    let at = Instant::now();
    sh.stop.cancel();
    (at, set)
}

/// `lanes` = min(concurrency, iterations): one engine slot per lane.
async fn drive_iterations(sh: Arc<Shared>, iterations: u64, lanes: usize) -> (Instant, JoinSet<()>) {
    let claimed = Arc::new(AtomicU64::new(0));
    let mut set = JoinSet::new();
    for lane in 0..lanes {
        let (sh, claimed) = (sh.clone(), claimed.clone());
        set.spawn(async move {
            while !sh.stop.is_cancelled() && claimed.fetch_add(1, Ordering::Relaxed) < iterations {
                let measured = sh.measured_at(Instant::now());
                sh.begin_iteration(measured);
                run_iteration(&sh, lane, measured).await;
            }
        });
    }
    loop {
        tokio::select! {
            r = set.join_next() => if r.is_none() {
                sh.set_reason(StopReason::ScheduleEnd);
                break;
            },
            _ = sh.stop.cancelled() => break,
        }
    }
    let at = Instant::now();
    sh.stop.cancel();
    (at, set)
}

/// True when every task finished within `d`.
async fn join_all_within(set: &mut JoinSet<()>, d: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + d;
    loop {
        tokio::select! {
            r = set.join_next() => if r.is_none() { return true },
            _ = tokio::time::sleep_until(deadline) => return false,
        }
    }
}

/// Wait for in-flight work: first `first_wait`, then cancel in-flight sends
/// and wait [`HARD_CANCEL_GRACE`]; tasks still running after that are
/// aborted (their work is reported as in flight at end). Returns the number
/// of aborted tasks.
async fn drain(sh: &Shared, set: &mut JoinSet<()>, first_wait: Duration) -> usize {
    if join_all_within(set, first_wait).await {
        return 0;
    }
    sh.halt.cancel();
    sh.hard.cancel();
    if join_all_within(set, HARD_CANCEL_GRACE).await {
        return 0;
    }
    let n = set.len();
    set.abort_all();
    while set.join_next().await.is_some() {}
    n
}

/// A validated, ready-to-execute run.
pub struct LoadRun {
    meta: RunMeta,
    opts: RunOptions,
    steps: Vec<Arc<ExecutionContext>>,
    units: Vec<StepUnit>,
    mix_cumulative: Vec<u64>,
    dataset: Option<Dataset>,
    slots: usize,
    /// Idle connections each slot's engine keeps per pool ([`slot_idle_cap`]).
    slot_idle: usize,
    /// Validated total schedule length in seconds; 0 for fixed-iteration runs.
    /// Every deadline in [`LoadRun::execute_lockable`] derives from this value.
    planned_secs: u64,
}

/// Bounds resolved from a plan's workload: the slot count and, for
/// stage-based workloads, the validated total schedule length.
struct WorkloadLimits {
    slots: usize,
    planned_secs: u64,
}

/// Workload, warmup and abort-rule checks (returns the resolved limits).
/// Public so callers can reject a plan when it is saved, not only when it runs.
fn validate_workload(plan: &LoadPlan) -> Result<WorkloadLimits, LoadError> {
    let (slots, planned_secs) = match &plan.workload {
        Workload::ClosedVirtualUsers { stages, think_time_ms } => {
            let total = validate_stages(stages, MAX_VUS, "virtual users")?;
            if *think_time_ms > 3_600_000 {
                return Err(LoadError::Invalid("think time exceeds one hour".into()));
            }
            (stages.iter().map(|s| s.target).max().unwrap_or(0), total)
        }
        Workload::OpenArrivalRate { stages, max_in_flight } => {
            let total = validate_stages(stages, MAX_RATE_PER_SEC, "arrivals/s")?;
            if *max_in_flight == 0 || *max_in_flight > MAX_IN_FLIGHT {
                return Err(LoadError::Invalid(format!("max_in_flight must be 1..={MAX_IN_FLIGHT}")));
            }
            (*max_in_flight, total)
        }
        Workload::Iterations { iterations, concurrency } => {
            if *iterations == 0 || *iterations > MAX_ITERATIONS {
                return Err(LoadError::Invalid(format!("iterations must be 1..={MAX_ITERATIONS}")));
            }
            if *concurrency == 0 || *concurrency > MAX_CONCURRENCY {
                return Err(LoadError::Invalid(format!("concurrency must be 1..={MAX_CONCURRENCY}")));
            }
            ((*concurrency).min(*iterations), 0)
        }
    };
    match &plan.workload {
        Workload::ClosedVirtualUsers { .. } | Workload::OpenArrivalRate { .. } if plan.warmup_secs >= planned_secs => {
            return Err(LoadError::Invalid("the warmup covers the whole schedule; nothing would be measured".into()));
        }
        _ => {}
    }
    if let Some(a) = &plan.abort
        && (a.max_failure_permille > 1000 || a.window_secs == 0 || a.window_secs > 3600)
    {
        return Err(LoadError::Invalid("abort rule needs max_failure_permille ≤ 1000 and a 1–3600 s window".into()));
    }
    Ok(WorkloadLimits { slots: slots as usize, planned_secs })
}

/// Validate a plan's shape without resolving its requests: a chain or mix is
/// present and the workload, warmup and abort rule are within limits.
pub fn validate_plan(plan: &LoadPlan) -> Result<(), LoadError> {
    if plan.chain.is_empty() && plan.mix.is_empty() {
        return Err(LoadError::Invalid("the plan has neither a request chain nor a weighted mix".into()));
    }
    if !plan.mix.is_empty() && plan.mix.iter().all(|m| m.weight == 0) {
        return Err(LoadError::Invalid("every weighted-mix weight is zero".into()));
    }
    validate_workload(plan).map(|_| ())
}

/// Validate the stage shape and durations, returning the total schedule
/// length. Overflow of the sum is refused with a typed validation error
/// rather than panicking or wrapping.
fn validate_stages(stages: &[Stage], cap: u64, what: &str) -> Result<u64, LoadError> {
    if stages.is_empty() {
        return Err(LoadError::Invalid("the workload has no stages".into()));
    }
    let total =
        schedule::total_secs(stages).ok_or_else(|| LoadError::Invalid("the stage durations overflow; shorten the schedule".into()))?;
    if total == 0 {
        return Err(LoadError::Invalid("the stages have zero total duration".into()));
    }
    if total > MAX_DURATION_SECS {
        return Err(LoadError::Invalid(format!("the stages last {total} s; the limit is {MAX_DURATION_SECS} s")));
    }
    if let Some(s) = stages.iter().find(|s| s.target > cap) {
        return Err(LoadError::Invalid(format!("stage target {} {what} exceeds the limit of {cap}", s.target)));
    }
    if stages.iter().all(|s| s.target == 0) {
        return Err(LoadError::Invalid("every stage target is zero; nothing would be sent".into()));
    }
    Ok(total)
}

impl LoadRun {
    /// Validate the plan and job and freeze the per-step contexts. Nothing is
    /// sent until [`LoadRun::execute`].
    pub fn prepare(plan: LoadPlan, mut job: LoadJob, opts: RunOptions) -> Result<LoadRun, LoadError> {
        if !opts.acknowledged {
            return Err(LoadError::NotAcknowledged);
        }
        let (ids, mix_cumulative): (Vec<Id>, Vec<u64>) = if !plan.mix.is_empty() {
            let mut acc = 0u64;
            let cum = plan
                .mix
                .iter()
                .map(|m| {
                    acc += m.weight as u64;
                    acc
                })
                .collect();
            if acc == 0 {
                return Err(LoadError::Invalid("every weighted-mix weight is zero".into()));
            }
            (plan.mix.iter().map(|m| m.request_id).collect(), cum)
        } else {
            (plan.chain.clone(), vec![])
        };
        if ids.is_empty() {
            return Err(LoadError::Invalid("the plan has neither a request chain nor a weighted mix".into()));
        }
        if plan.mix.is_empty() && ids.len() > MAX_CHAIN_STEPS {
            return Err(LoadError::Invalid(format!("the chain has {} steps; the limit is {MAX_CHAIN_STEPS}", ids.len())));
        }
        let slot_idle = slot_idle_cap(&ids);
        let limits = validate_workload(&plan)?;
        let slots = limits.slots;
        let planned_secs = limits.planned_secs;
        if plan.dataset_id.is_some() && job.dataset.is_none() {
            return Err(LoadError::Invalid("the plan references a dataset but none was provided".into()));
        }

        let mut resolved = Vec::with_capacity(ids.len());
        for id in &ids {
            let ctx = job
                .requests
                .get(id)
                .ok_or_else(|| LoadError::Invalid(format!("request {id} referenced by the plan was not resolved into the job")))?;
            resolved.push((*id, ctx));
        }
        // One unit kind per plan; unsupported combinations are refused here,
        // before any traffic (LOAD-013).
        let (unit, units) =
            protocol::classify_plan(resolved.iter().map(|(id, c)| (*id, *c)), plan.connection_mode).map_err(LoadError::Refused)?;
        let mut steps = Vec::with_capacity(ids.len());
        let mut revisions = Vec::new();
        for (_, ctx) in resolved {
            let mut ctx = ctx.clone();
            // Run-level override layer (highest precedence): the plan's
            // connection mode and a bounded per-send capture.
            let effective = anvil_engine::settings::resolve(&ctx.settings_layers);
            let capture = effective.limits.capture_bytes.min(opts.response_capture_bytes.max(1));
            ctx.settings_layers.push((
                "run:load".into(),
                SettingsOverrides {
                    keepalive: Some(plan.connection_mode == ConnectionMode::Persistent),
                    limits: Some(Limits { capture_bytes: capture, ..effective.limits }),
                    ..Default::default()
                },
            ));
            if let Some(r) = ctx.revision_id.or(ctx.request_id)
                && !revisions.contains(&r)
            {
                revisions.push(r);
            }
            steps.push(Arc::new(ctx));
        }
        let dataset = job.dataset.take();
        let meta = RunMeta {
            run_id: Id::new(),
            engine: crate::ENGINE_NAME.into(),
            engine_version: crate::engine_version(),
            plan,
            request_revisions: revisions,
            dataset_sha256: dataset.as_ref().map(|d| d.sha256.clone()),
            started_at: Utc::now(),
            unit,
        };
        Ok(LoadRun { meta, opts, steps, units, mix_cumulative, dataset, slots: slots.max(1), slot_idle, planned_secs })
    }

    pub fn meta(&self) -> &RunMeta {
        &self.meta
    }

    /// Run to completion, cancellation or abort. Always returns a report;
    /// anything but a normal completion is marked partial.
    pub async fn execute(self, cancel: CancellationToken, progress: Option<ProgressSink>) -> LoadReport {
        self.execute_lockable(cancel, CancellationToken::new(), progress).await
    }

    /// Like [`LoadRun::execute`], with a second token for the lock policy:
    /// cancelling `lock` stops the run like a user cancel but records
    /// `stopped_by_lock`.
    pub async fn execute_lockable(self, cancel: CancellationToken, lock: CancellationToken, progress: Option<ProgressSink>) -> LoadReport {
        let LoadRun { mut meta, opts, steps, units, mix_cumulative, dataset, slots, slot_idle, planned_secs } = self;
        let plan = meta.plan.clone();
        let proto = Engine::new();
        let shard_count = slots.clamp(1, MAX_SHARDS);
        meta.started_at = Utc::now();
        let sh = Arc::new(Shared {
            run_id: meta.run_id,
            steps,
            units,
            unit: meta.unit,
            mix_cumulative,
            dataset,
            t0: Instant::now(),
            warmup: Duration::from_secs(plan.warmup_secs),
            bucket_width_secs: planned_secs.div_ceil(MAX_TIMELINE_BUCKETS).max(1),
            engines: (0..slots).map(|_| OnceLock::new()).collect(),
            slot_idle,
            tokens: proto.tokens.clone(),
            ledger: Mutex::new(LedgerState::default()),
            shards: (0..shard_count).map(|_| Mutex::new(Shard { metrics: Metrics::new(), pending: BTreeMap::new() })).collect(),
            iteration_seq: AtomicU64::new(0),
            stop: CancellationToken::new(),
            halt: CancellationToken::new(),
            hard: CancellationToken::new(),
            reason: Mutex::new(None),
            timeline_truncated: AtomicBool::new(false),
            plan: plan.clone(),
        });
        drop(proto);

        // User cancel → stop scheduling and stop chains.
        let link = {
            let (c, sh, lock) = (cancel.clone(), sh.clone(), lock.clone());
            tokio::spawn(async move {
                tokio::select! {
                    _ = c.cancelled() => {
                        sh.set_reason(StopReason::UserCancel);
                        sh.halt.cancel();
                        sh.stop.cancel();
                    }
                    _ = lock.cancelled() => {
                        sh.set_reason(StopReason::Lock);
                        sh.halt.cancel();
                        sh.stop.cancel();
                    }
                    _ = sh.stop.cancelled() => {}
                }
            })
        };

        // Ticker: timeline flush, abort rule, generator health, progress.
        let done = CancellationToken::new();
        let sched_end: Arc<Mutex<Option<Instant>>> = Arc::new(Mutex::new(None));
        let ticker = {
            let (sh, done, sched_end) = (sh.clone(), done.clone(), sched_end.clone());
            let period = Duration::from_millis(opts.progress_interval_ms.max(MIN_PROGRESS_INTERVAL_MS));
            tokio::spawn(async move {
                let mut tl: Vec<TimeBucket> = Vec::new();
                let mut delivered = 0usize;
                let mut sampler = HealthSampler::new();
                let mut interval = tokio::time::interval(period);
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                interval.tick().await;
                loop {
                    tokio::select! {
                        _ = interval.tick() => {}
                        _ = done.cancelled() => break,
                    }
                    sampler.sample();
                    let now = Instant::now();
                    sh.flush(&mut tl, sh.bucket_of(now).saturating_sub(1));
                    if !sh.stop.is_cancelled()
                        && let Some(note) = sh.abort_triggered()
                    {
                        sh.set_reason(StopReason::Abort(note));
                        sh.halt.cancel();
                        sh.stop.cancel();
                    }
                    if let Some(sink) = &progress {
                        let until = sched_end.lock().unwrap_or(now);
                        let elapsed = now.saturating_duration_since(sh.t0);
                        let phase = if sh.stop.is_cancelled() {
                            RunPhase::Draining
                        } else if elapsed < sh.warmup {
                            RunPhase::Warmup
                        } else {
                            RunPhase::Measuring
                        };
                        let p = Progress {
                            run_id: sh.run_id,
                            elapsed_secs: elapsed.as_secs_f64(),
                            phase,
                            in_flight: sh.in_flight(),
                            snapshot: sh.snapshot(until, &sampler),
                            timeline_from: delivered,
                            timeline_delta: tl[delivered..].to_vec(),
                        };
                        if sink(&p) {
                            delivered = tl.len();
                        }
                    }
                }
                sampler.sample();
                (tl, sampler)
            })
        };

        let (ended_at, mut set) = match plan.workload.clone() {
            Workload::ClosedVirtualUsers { stages, think_time_ms } => {
                drive_closed(sh.clone(), stages, Duration::from_millis(think_time_ms), planned_secs).await
            }
            Workload::OpenArrivalRate { stages, max_in_flight } => {
                drive_open(sh.clone(), stages, max_in_flight as usize, planned_secs).await
            }
            Workload::Iterations { iterations, .. } => drive_iterations(sh.clone(), iterations, slots).await,
        };
        *sched_end.lock() = Some(ended_at);
        let reason = sh.reason.lock().clone().unwrap_or(StopReason::ScheduleEnd);
        let first_wait = match reason {
            StopReason::ScheduleEnd => Duration::from_millis(opts.graceful_stop_ms),
            _ => Duration::from_millis(opts.cancel_drain_ms),
        };
        let pre_hard = sh.hard.is_cancelled();
        let aborted_tasks = drain(&sh, &mut set, first_wait).await;
        let hard_canceled = !pre_hard && sh.hard.is_cancelled();
        link.abort();
        done.cancel();
        let (mut timeline, sampler) = ticker.await.unwrap_or_else(|_| (Vec::new(), HealthSampler::new()));
        sh.flush(&mut timeline, sh.bucket_of(Instant::now()) + 1);

        let mut snap = sh.snapshot(ended_at, &sampler);
        let mut notes = Vec::new();
        let completion = match &reason {
            StopReason::ScheduleEnd => RunCompletion::Completed,
            StopReason::UserCancel => {
                notes.push("Canceled by the user: scheduling stopped, in-flight sends were given the drain window, and the rest were canceled. Metrics cover the run up to the cancel.".into());
                RunCompletion::CanceledByUser
            }
            StopReason::Lock => {
                notes.push("Stopped because the vault locked (stop-runs-on-lock policy): scheduling stopped, in-flight sends were given the drain window, and the rest were canceled.".into());
                RunCompletion::StoppedByLock
            }
            StopReason::Abort(note) => {
                notes.push(note.clone());
                RunCompletion::AbortedByRule
            }
        };
        if hard_canceled && reason == StopReason::ScheduleEnd {
            notes.push(format!(
                "{} iteration(s) were still running {} ms after the schedule ended and were canceled; they are counted as canceled, not as completed.",
                snap.counts.canceled, opts.graceful_stop_ms
            ));
        }
        if aborted_tasks > 0 {
            notes.push(format!(
                "{aborted_tasks} task(s) did not stop after cancellation within {} s and were abandoned; their sends are reported as in flight at end with unknown outcome.",
                HARD_CANCEL_GRACE.as_secs()
            ));
        }
        if sh.timeline_truncated.load(Ordering::Relaxed) {
            notes.push(format!("The timeline covers the first {MAX_TIMELINE_BUCKETS} buckets only; summary metrics cover the whole run."));
        }
        if let Some(d) = &sh.dataset {
            notes.push(format!(
                "Dataset: {} row(s) used in order and cycled per iteration (sha256 {}).",
                d.rows.len(),
                &d.sha256[..16.min(d.sha256.len())]
            ));
            if sh.steps.iter().any(|s| s.scope.is_some()) {
                notes.push(DATASET_SKIPPED_UNDER_IMPORT_ROOT.into());
            }
        }
        if health::sample().is_none() {
            snap.generator.notes.push("Generator CPU and memory measurement is unavailable on this platform.".into());
        } else {
            snap.generator.notes.push(health::METHOD_NOTE.into());
            if let Some(mean) = sampler.mean_cpu_percent() {
                snap.generator.notes.push(format!("Mean generator CPU over the run: {mean:.0} % of one core."));
            }
        }
        report::assemble(&meta, snap, timeline, completion, Utc::now(), notes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slot_engines_keep_small_connection_pools() {
        let e = slot_engine(Arc::new(anvil_auth::oauth::TokenCache::new()), 6);
        let http = e.http.pool.limits();
        assert_eq!((http.max_idle_per_key, http.max_idle_total), (2, 6));
        assert_eq!(http.idle_ttl, anvil_transport::http::PoolLimits::default().idle_ttl);
        assert_eq!(e.h3.pool_limits().max_idle_total, 6);
        assert!(e.grpc_channels.is_some());
    }

    #[test]
    fn slot_idle_cap_follows_the_distinct_requests_of_the_plan() {
        let ids: Vec<Id> = (0..100).map(|_| Id::new()).collect();
        assert_eq!(slot_idle_cap(&ids[..1]), SLOT_MIN_IDLE);
        assert_eq!(slot_idle_cap(&ids[..6]), 6);
        // A request used by several steps is one destination.
        let repeated = [ids[0], ids[1], ids[0], ids[2], ids[1], ids[3], ids[4]];
        assert_eq!(slot_idle_cap(&repeated), 5);
        assert_eq!(slot_idle_cap(&ids[..MAX_CHAIN_STEPS]), MAX_CHAIN_STEPS);
        assert_eq!(slot_idle_cap(&ids), SLOT_MAX_IDLE);
        assert!(SLOT_MAX_IDLE <= anvil_transport::http::PoolLimits::default().max_idle_total);
        assert!(SLOT_MAX_IDLE <= anvil_transport::h3::PoolLimits::default().max_idle_total);
    }

    #[test]
    fn weighted_pick_is_seeded_and_proportional() {
        let cum = [3u64, 4];
        let a: Vec<usize> = (0..4000).map(|i| pick_weighted(7, &cum, i)).collect();
        let b: Vec<usize> = (0..4000).map(|i| pick_weighted(7, &cum, i)).collect();
        assert_eq!(a, b, "same seed, same sequence");
        let c: Vec<usize> = (0..4000).map(|i| pick_weighted(8, &cum, i)).collect();
        assert_ne!(a, c, "different seed, different sequence");
        let first = a.iter().filter(|x| **x == 0).count() as f64 / a.len() as f64;
        assert!((first - 0.75).abs() < 0.03, "3:1 weights → {first}");
    }

    #[test]
    fn unacknowledged_runs_never_start() {
        let plan = LoadPlan {
            id: Id::new(),
            workspace_id: Id::new(),
            name: "x".into(),
            workload: Workload::Iterations { iterations: 1, concurrency: 1 },
            chain: vec![],
            mix: vec![],
            dataset_id: None,
            environment_id: None,
            connection_mode: ConnectionMode::Persistent,
            warmup_secs: 0,
            abort: None,
            seed: 0,
            trusted: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let job = || LoadJob { requests: HashMap::new(), dataset: None };
        assert!(matches!(LoadRun::prepare(plan.clone(), job(), RunOptions::default()), Err(LoadError::NotAcknowledged)));
        let ack = RunOptions { acknowledged: true, ..Default::default() };
        assert!(matches!(LoadRun::prepare(plan, job(), ack), Err(LoadError::Invalid(_))));
    }
}
