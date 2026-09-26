//! Run comparison. Lists every semantic difference between two reports and
//! only presents latency deltas when the measurement semantics are
//! compatible (same engine build, workload model, warmup handling, protocol,
//! connection mode, dataset and request set). Incompatible runs get the
//! reasons instead of numbers that look equivalent but are not (LOAD-014).
//! Runs of different load units (HTTP requests vs WebSocket sessions vs UDP
//! exchanges, ...) are refused outright (LOAD-013).

use anvil_domain::Id;
use anvil_domain::load::{ConnectionMode, LoadReport, LoadUnitKind, Workload};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Impact {
    /// Measurements are not comparable; latency deltas are withheld.
    Blocking,
    /// Comparable, but the difference must be kept in mind.
    Caution,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticDifference {
    pub aspect: String,
    pub a: String,
    pub b: String,
    pub impact: Impact,
    pub explanation: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MetricDelta {
    pub metric: String,
    pub a: f64,
    pub b: f64,
    /// `b - a`.
    pub delta: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delta_percent: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum LatencyComparison {
    Comparable { deltas: Vec<MetricDelta> },
    NotComparable { reasons: Vec<String> },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Comparison {
    pub run_a: Id,
    pub run_b: Id,
    pub compatible: bool,
    pub differences: Vec<SemanticDifference>,
    pub latency: LatencyComparison,
    pub summary: String,
}

fn model(w: &Workload) -> &'static str {
    match w {
        Workload::ClosedVirtualUsers { .. } => "closed (virtual users)",
        Workload::OpenArrivalRate { .. } => "open (arrival rate)",
        Workload::Iterations { .. } => "iterations",
    }
}

fn level(w: &Workload) -> String {
    match w {
        Workload::ClosedVirtualUsers { stages, think_time_ms } => {
            format!("stages {:?}, think {think_time_ms} ms", stages.iter().map(|s| (s.duration_secs, s.target)).collect::<Vec<_>>())
        }
        Workload::OpenArrivalRate { stages, max_in_flight } => {
            format!("stages {:?}, max in flight {max_in_flight}", stages.iter().map(|s| (s.duration_secs, s.target)).collect::<Vec<_>>())
        }
        Workload::Iterations { iterations, concurrency } => format!("{iterations} iterations × {concurrency} concurrency"),
    }
}

fn protocols(r: &LoadReport) -> String {
    let mut p: Vec<&str> = r.protocols.iter().map(|(p, _)| p.as_str()).collect();
    p.sort_unstable();
    if p.is_empty() { "none observed".into() } else { p.join(", ") }
}

fn failure_ratio(r: &LoadReport) -> f64 {
    let q = &r.requests;
    let finished = q.completed + q.transport_failures + q.timeouts;
    let failed = q.transport_failures + q.timeouts + q.application_failures.max(q.assertion_failures);
    if finished == 0 { 0.0 } else { failed as f64 / finished as f64 }
}

fn unit(r: &LoadReport) -> LoadUnitKind {
    r.protocol_metrics.as_ref().map(|p| p.unit).unwrap_or_default()
}

/// Protocol denominators that are comparable between two runs of the same
/// unit kind (rates per unit, never raw totals of different run lengths).
fn protocol_deltas(a: &LoadReport, b: &LoadReport, mk: &dyn Fn(&str, f64, f64) -> MetricDelta) -> Vec<MetricDelta> {
    let (Some(pa), Some(pb)) = (&a.protocol_metrics, &b.protocol_metrics) else { return vec![] };
    let per = |n: u64, d: u64| if d == 0 { 0.0 } else { n as f64 / d as f64 };
    let mut out = Vec::new();
    if let (Some(x), Some(y)) = (&pa.grpc, &pb.grpc) {
        out.push(mk("non-OK status ratio", per(x.non_ok, x.ok + x.non_ok), per(y.non_ok, y.ok + y.non_ok)));
        out.push(mk("missing-status ratio", per(x.missing_status, a.requests.started), per(y.missing_status, b.requests.started)));
    }
    if let (Some(x), Some(y)) = (&pa.stream, &pb.stream) {
        out.push(mk("messages per opened stream", per(x.messages_received, x.opened), per(y.messages_received, y.opened)));
        if x.time_to_first_message.count > 0 && y.time_to_first_message.count > 0 {
            out.push(mk("time to first message p50 (µs)", x.time_to_first_message.p50_us as f64, y.time_to_first_message.p50_us as f64));
            out.push(mk("time to first message p99 (µs)", x.time_to_first_message.p99_us as f64, y.time_to_first_message.p99_us as f64));
        }
    }
    if let (Some(x), Some(y)) = (&pa.websocket, &pb.websocket) {
        out.push(mk("sessions opened ratio", per(x.opened, a.requests.started), per(y.opened, b.requests.started)));
        out.push(mk("messages received per opened session", per(x.messages_received, x.opened), per(y.messages_received, y.opened)));
        if x.rtt.count > 0 && y.rtt.count > 0 {
            out.push(mk("round trip p50 (µs)", x.rtt.p50_us as f64, y.rtt.p50_us as f64));
            out.push(mk("round trip p99 (µs)", x.rtt.p99_us as f64, y.rtt.p99_us as f64));
        }
    }
    if let (Some(x), Some(y)) = (&pa.tcp, &pb.tcp) {
        out.push(mk(
            "frames received per exchange",
            per(x.frames_received, a.requests.completed),
            per(y.frames_received, b.requests.completed),
        ));
    }
    if let (Some(x), Some(y)) = (&pa.datagram, &pb.datagram) {
        // An observed ratio, never a delivery rate.
        out.push(mk(
            "datagrams received per sent (observed)",
            per(x.datagrams_received, x.datagrams_sent),
            per(y.datagrams_received, y.datagrams_sent),
        ));
        out.push(mk(
            "exchanges with no response observed (ratio)",
            per(x.exchanges_silent, a.requests.completed),
            per(y.exchanges_silent, b.requests.completed),
        ));
    }
    out
}

pub fn compare(a: &LoadReport, b: &LoadReport) -> Comparison {
    // Two runs of different protocols measure different units: the comparison
    // is refused outright, not merely flagged (LOAD-013).
    let (ua, ub) = (unit(a), unit(b));
    if ua != ub {
        let reason = format!(
            "load unit differs ({} vs {}): the runs count different things (e.g. requests vs sessions vs datagram exchanges), so no count, rate or latency is comparable",
            crate::protocol::label(ua),
            crate::protocol::label(ub)
        );
        return Comparison {
            run_a: a.run_id,
            run_b: b.run_id,
            compatible: false,
            differences: vec![SemanticDifference {
                aspect: "load unit".into(),
                a: crate::protocol::label(ua).into(),
                b: crate::protocol::label(ub).into(),
                impact: Impact::Blocking,
                explanation: "Runs of different protocols are never compared.".into(),
            }],
            latency: LatencyComparison::NotComparable { reasons: vec![reason] },
            summary: "Refused: these runs load different protocols. Compare two runs of the same protocol.".into(),
        };
    }
    let mut d = Vec::new();
    let mut diff = |aspect: &str, va: String, vb: String, impact: Impact, why: &str| {
        if va != vb {
            d.push(SemanticDifference { aspect: aspect.into(), a: va, b: vb, impact, explanation: why.into() });
        }
    };
    use Impact::*;
    diff("engine", a.engine.clone(), b.engine.clone(), Blocking, "Different load engines measure and classify differently.");
    diff(
        "engine version",
        a.engine_version.clone(),
        b.engine_version.clone(),
        Blocking,
        "Engine/transport builds can change timing boundaries and classification.",
    );
    diff(
        "workload model",
        model(&a.plan.workload).into(),
        model(&b.plan.workload).into(),
        Blocking,
        "Closed-workload latency is throttled by the target itself; open-workload latency is not. The numbers answer different questions.",
    );
    diff(
        "warmup",
        format!("{} s, included in metrics: {}", a.plan.warmup_secs, a.warmup_included_in_metrics),
        format!("{} s, included in metrics: {}", b.plan.warmup_secs, b.warmup_included_in_metrics),
        Blocking,
        "Different warmup handling changes which samples (cold connections, caches, JIT) are in the distributions.",
    );
    diff("protocol", protocols(a), protocols(b), Blocking, "HTTP/1.1, HTTP/2 and HTTP/3 have different connection and multiplexing costs.");
    let mode_applies = crate::protocol::connection_mode_applies(ua);
    diff(
        "connection mode",
        format!("{:?}", a.plan.connection_mode),
        format!("{:?}", b.plan.connection_mode),
        if mode_applies { Blocking } else { Caution },
        if !mode_applies {
            "This unit opens its own connection in either mode, so the setting did not change how it connected."
        } else if a.plan.connection_mode == ConnectionMode::Fresh || b.plan.connection_mode == ConnectionMode::Fresh {
            "Fresh mode pays a connection (and TLS handshake) per unit; persistent mode reuses connections."
        } else {
            "Connection handling differs."
        },
    );
    diff(
        "dataset",
        a.dataset_sha256.clone().unwrap_or_else(|| "none".into()),
        b.dataset_sha256.clone().unwrap_or_else(|| "none".into()),
        Blocking,
        "Different input data exercises different code paths and payload sizes.",
    );
    let set = |r: &LoadReport| {
        let mut ids: Vec<String> = if r.plan.mix.is_empty() {
            r.plan.chain.iter().map(|i| i.to_string()).collect()
        } else {
            r.plan.mix.iter().map(|m| format!("{}×{}", m.request_id, m.weight)).collect()
        };
        if !r.plan.mix.is_empty() {
            ids.sort();
        }
        ids.join(" → ")
    };
    diff("request set", set(a), set(b), Blocking, "The runs sent different requests or a different weighted mix.");
    diff(
        "request revisions",
        format!("{:?}", a.request_revisions),
        format!("{:?}", b.request_revisions),
        Caution,
        "The same requests were edited between runs; that may be the change under test, but confirm it.",
    );
    diff("load level", level(&a.plan.workload), level(&b.plan.workload), Caution, "Different load levels are expected to change latency.");
    diff(
        "completeness",
        format!("{:?}{}", a.completion, if a.partial { " (partial)" } else { "" }),
        format!("{:?}{}", b.completion, if b.partial { " (partial)" } else { "" }),
        Caution,
        "A partial run covers less time and may stop in a different phase.",
    );
    diff(
        "generator saturation",
        a.generator.target_not_achieved.to_string(),
        b.generator.target_not_achieved.to_string(),
        Caution,
        "A run whose generator could not sustain the target measures the generator as much as the system under test.",
    );
    if a.schema_version != b.schema_version {
        diff(
            "report schema",
            a.schema_version.to_string(),
            b.schema_version.to_string(),
            Caution,
            "Reports were written by different schema versions.",
        );
    }

    let blocking: Vec<String> = d
        .iter()
        .filter(|x| x.impact == Blocking)
        .map(|x| format!("{} differs ({} vs {}): {}", x.aspect, x.a, x.b, x.explanation))
        .collect();
    let compatible = blocking.is_empty();
    let latency = if compatible {
        let pct = |a: f64, b: f64| (a != 0.0).then(|| (b - a) / a * 100.0);
        let mk = |m: &str, va: f64, vb: f64| MetricDelta { metric: m.into(), a: va, b: vb, delta: vb - va, delta_percent: pct(va, vb) };
        let (la, lb) = (&a.latency_success, &b.latency_success);
        let mut deltas = Vec::new();
        // Percentiles exist only over successful units; with none on either
        // side there is nothing to compare (never "0 µs").
        if la.count > 0 && lb.count > 0 {
            deltas.extend([
                mk("success p50 (µs)", la.p50_us as f64, lb.p50_us as f64),
                mk("success p90 (µs)", la.p90_us as f64, lb.p90_us as f64),
                mk("success p95 (µs)", la.p95_us as f64, lb.p95_us as f64),
                mk("success p99 (µs)", la.p99_us as f64, lb.p99_us as f64),
                mk("success mean (µs)", la.mean_us as f64, lb.mean_us as f64),
            ]);
        }
        deltas.extend([
            mk("achieved rate (/s)", a.achieved_rate_per_sec, b.achieved_rate_per_sec),
            mk("failed-unit ratio", failure_ratio(a), failure_ratio(b)),
            mk("timeouts (censored)", a.timeouts_censored.count as f64, b.timeouts_censored.count as f64),
            mk("dropped arrivals", a.counts.dropped as f64, b.counts.dropped as f64),
        ]);
        deltas.extend(protocol_deltas(a, b, &mk));
        LatencyComparison::Comparable { deltas }
    } else {
        LatencyComparison::NotComparable { reasons: blocking.clone() }
    };
    let cautions = d.iter().filter(|x| x.impact == Caution).count();
    let summary = if compatible {
        format!("Comparable runs ({cautions} caution(s)). Latency deltas are computed from each run's merged histograms.")
    } else {
        format!(
            "Not comparable: {} blocking difference(s). Latency deltas are withheld because the runs measured different things; align the test parameters first.",
            blocking.len()
        )
    };
    Comparison { run_a: a.run_id, run_b: b.run_id, compatible, differences: d, latency, summary }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::tests::sample_report;
    use anvil_domain::load::Stage;

    #[test]
    fn load_014_incompatible_runs_withhold_latency_deltas() {
        let a = sample_report();
        let mut b = a.clone();
        b.run_id = Id::new();
        b.plan.warmup_secs = 30;
        b.plan.workload = Workload::ClosedVirtualUsers { stages: vec![Stage { duration_secs: 5, target: 4 }], think_time_ms: 0 };
        b.engine_version = "anvil-load/9.9.9+anvil-transport/9.9.9".into();
        b.protocols = vec![("h2".into(), 10)];
        b.plan.connection_mode = ConnectionMode::Fresh;
        b.dataset_sha256 = Some("cd".repeat(32));
        b.latency_success.p99_us = 1;
        let c = compare(&a, &b);
        assert!(!c.compatible);
        let aspects: Vec<&str> = c.differences.iter().filter(|x| x.impact == Impact::Blocking).map(|x| x.aspect.as_str()).collect();
        for want in ["engine version", "workload model", "warmup", "protocol", "connection mode", "dataset"] {
            assert!(aspects.contains(&want), "missing {want}: {aspects:?}");
        }
        match &c.latency {
            LatencyComparison::NotComparable { reasons } => assert_eq!(reasons.len(), aspects.len()),
            other => panic!("latency must not be compared: {other:?}"),
        }
        assert!(c.summary.contains("Not comparable"));
    }

    #[test]
    fn compatible_runs_get_deltas_and_cautions() {
        let a = sample_report();
        let mut b = a.clone();
        b.run_id = Id::new();
        b.latency_success.p99_us = a.latency_success.p99_us * 2;
        b.plan.workload = Workload::OpenArrivalRate {
            stages: vec![Stage { duration_secs: 0, target: 20 }, Stage { duration_secs: 5, target: 20 }],
            max_in_flight: 4,
        };
        b.request_revisions = vec![Id::new()];
        let c = compare(&a, &b);
        assert!(c.compatible, "{:?}", c.differences);
        assert!(c.differences.iter().all(|x| x.impact == Impact::Caution));
        assert!(c.differences.iter().any(|x| x.aspect == "load level"));
        let LatencyComparison::Comparable { deltas } = &c.latency else { panic!() };
        let p99 = deltas.iter().find(|x| x.metric.starts_with("success p99")).unwrap();
        assert_eq!(p99.delta_percent, Some(100.0));
    }
}
