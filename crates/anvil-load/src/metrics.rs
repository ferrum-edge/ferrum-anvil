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
//! (LOAD-010).

use anvil_domain::diagnostics::Severity;
use anvil_domain::execution::{ExecutionRecord, FailureKind};
use anvil_domain::load::{FailureSample, LatencySummary};
use anvil_domain::outcome::{ApplicationState, AssertionState, TransportState};
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
}

impl SendObservation {
    pub fn is_success(&self) -> bool {
        self.terminal == Terminal::Completed && !self.application_failure && !self.assertion_failure
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

/// Classify one engine execution. Uses only the engine's typed outcome and
/// its (already redacted) record; never re-parses message text.
pub fn observe(rec: &ExecutionRecord, wall_us: u64) -> SendObservation {
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
    let latency_us: u64 = rec.attempts.iter().map(|a| a.duration_us).sum();
    let mut obs = SendObservation {
        terminal,
        application_failure,
        assertion_failure,
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
    if obs.is_failure() {
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
        if assertion_failure && let Some(r) = rec.assertion_results.iter().find(|r| !r.passed) {
            example.push_str(&format!(" [assertion: {}]", r.message));
        }
        obs.example = Some(truncate_chars(&example, MAX_EXAMPLE_CHARS));
    }
    obs
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
            _ => self.failure.record(o.latency_us),
        }
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
