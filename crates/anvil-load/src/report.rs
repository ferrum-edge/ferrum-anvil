//! Report assembly and serialization: JSON ([`LoadReport`], sealed with an
//! integrity hash that is verified on reopen), CSV (summary + timeline) and —
//! in [`crate::html`] — a standalone offline HTML summary.

use crate::LoadError;
use crate::executor::MetricsSnapshot;
use anvil_domain::Id;
use anvil_domain::load::*;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const REPORT_SCHEMA_VERSION: u32 = anvil_domain::SCHEMA_VERSION;

pub const CENSORED_LABEL: &str = "Censored at the deadline: each value is the time at which the send was abandoned, a lower bound on the latency the target would have produced. Excluded from the success and failure latency distributions.";

/// Achieved/offered below this ratio means the target rate was not achieved.
pub const TARGET_RATIO: f64 = 0.9;
/// Late-run lag must exceed this (µs) and twice the early-run lag to count as growing.
pub const LAG_GROWTH_FLOOR_US: u64 = 50_000;
/// A p99 start lag above this (µs) means the open schedule was not kept.
pub const LATE_START_P99_US: u64 = 50_000;
/// Diagnostic finding code for local port/address exhaustion (generator-side).
pub const LOCAL_ADDRESS_EXHAUSTION_CODE: &str = "client.connect.address_unavailable";

/// Immutable identity of a run, known before any traffic starts.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunMeta {
    pub run_id: Id,
    pub engine: String,
    pub engine_version: String,
    pub plan: LoadPlan,
    pub request_revisions: Vec<Id>,
    pub dataset_sha256: Option<String>,
    pub started_at: DateTime<Utc>,
}

pub fn workload_label(w: &Workload) -> String {
    match w {
        Workload::ClosedVirtualUsers { .. } => "Closed workload (fixed virtual users): each virtual user waits for its response before its next iteration, so slowing responses reduce the offered rate. Not equivalent to a sustained arrival rate.".into(),
        Workload::OpenArrivalRate { max_in_flight, .. } => format!(
            "Open workload (arrival rate): arrivals are scheduled independently of response time; arrivals that find {max_in_flight} requests already in flight are dropped and counted, never queued."
        ),
        Workload::Iterations { .. } => "Fixed iterations with bounded concurrency (closed): slowing responses lengthen the run rather than dropping work; no target rate.".into(),
    }
}

/// `scheduled = started + dropped` and
/// `started = completed + transport_failures + timeouts + canceled + in_flight_at_end`.
pub fn check_balance(c: &LoadCounts) -> Result<(), String> {
    if c.scheduled != c.started + c.dropped {
        return Err(format!("scheduled {} ≠ started {} + dropped {}", c.scheduled, c.started, c.dropped));
    }
    let terminal = c.completed + c.transport_failures + c.timeouts + c.canceled + c.in_flight_at_end;
    if c.started != terminal {
        return Err(format!(
            "started {} ≠ completed {} + transport failures {} + timeouts {} + canceled {} + in flight {}",
            c.started, c.completed, c.transport_failures, c.timeouts, c.canceled, c.in_flight_at_end
        ));
    }
    if c.application_failures > c.completed || c.assertion_failures > c.completed {
        return Err("application/assertion failures must be subsets of completed".into());
    }
    Ok(())
}

pub fn check_request_balance(r: &RequestCounts) -> Result<(), String> {
    let terminal = r.completed + r.transport_failures + r.timeouts + r.canceled + r.in_flight_at_end;
    if r.started != terminal {
        return Err(format!(
            "sends started {} ≠ completed {} + transport failures {} + timeouts {} + canceled {} + in flight {}",
            r.started, r.completed, r.transport_failures, r.timeouts, r.canceled, r.in_flight_at_end
        ));
    }
    if r.application_failures > r.completed || r.assertion_failures > r.completed {
        return Err("application/assertion failures must be subsets of completed sends".into());
    }
    Ok(())
}

fn mean(v: impl Iterator<Item = u64>) -> Option<f64> {
    let (n, s) = v.fold((0u64, 0u128), |(n, s), x| (n + 1, s + x as u128));
    (n > 0).then(|| s as f64 / n as f64)
}

/// Whether start lag grows over the measured window: the mean per-bucket p99
/// lag of the last quarter exceeds [`LAG_GROWTH_FLOOR_US`] and twice that of
/// the first quarter.
pub fn lag_grows(timeline: &[TimeBucket]) -> bool {
    let measured: Vec<&TimeBucket> = timeline.iter().filter(|b| !b.warmup && b.started > 0).collect();
    if measured.len() < 4 {
        return false;
    }
    let q = measured.len() / 4;
    let early = mean(measured[..q].iter().map(|b| b.p99_schedule_lag_us)).unwrap_or(0.0);
    let late = mean(measured[measured.len() - q..].iter().map(|b| b.p99_schedule_lag_us)).unwrap_or(0.0);
    late > LAG_GROWTH_FLOOR_US as f64 && late > 2.0 * early
}

/// Build the final (or partial) report from a snapshot and timeline.
pub fn assemble(
    meta: &RunMeta,
    snap: MetricsSnapshot,
    timeline: Vec<TimeBucket>,
    completion: RunCompletion,
    finished_at: DateTime<Utc>,
    extra_notes: Vec<String>,
) -> LoadReport {
    let plan = &meta.plan;
    let mut generator = snap.generator.clone();
    let mut notes = vec![workload_label(&plan.workload)];
    match &plan.workload {
        Workload::OpenArrivalRate { max_in_flight, .. } => {
            let offered = snap.offered_rate_per_sec.unwrap_or(0.0);
            let ratio = if offered > 0.0 { snap.achieved_rate_per_sec / offered } else { 1.0 };
            let growing = lag_grows(&timeline);
            if snap.counts.dropped > 0 {
                generator.notes.push(format!(
                    "{} of {} scheduled arrivals were dropped because {max_in_flight} requests were already in flight; dropped arrivals are not successes and have no latency.",
                    snap.counts.dropped, snap.counts.scheduled
                ));
            }
            let late = generator.p99_schedule_lag_us > LATE_START_P99_US;
            let mut reasons = Vec::new();
            if ratio < TARGET_RATIO {
                reasons.push(format!("started {:.1}/s of {:.1}/s offered ({:.0} %)", snap.achieved_rate_per_sec, offered, ratio * 100.0));
            }
            if growing {
                reasons.push("start lag grew over the run (the generator fell further behind the schedule)".into());
            }
            if late {
                reasons.push(format!(
                    "arrivals started late (p99 start lag {:.1} ms, max {:.1} ms), so the offered arrival process was not honoured and catch-up bursts raised concurrency",
                    generator.p99_schedule_lag_us as f64 / 1e3,
                    generator.max_schedule_lag_us as f64 / 1e3
                ));
            }
            if !reasons.is_empty() {
                generator.target_not_achieved = true;
                generator.notes.push(format!(
                    "Target not achieved: {}. This run does not establish the target's capacity — the limit may be the generator or its host (in-flight cap, CPU, scheduling, sockets) rather than the system under test. Use a separate, adequately sized generator host or lower the rate.",
                    reasons.join("; ")
                ));
            }
        }
        Workload::ClosedVirtualUsers { think_time_ms, .. } => {
            generator.notes.push(format!(
                "Closed workload: no target rate exists, so 'target not achieved' does not apply; schedule lag is not measured (think time {think_time_ms} ms)."
            ));
        }
        Workload::Iterations { .. } => {
            generator.notes.push("Iteration workload: no target rate exists; schedule lag is not measured.".into());
        }
    }
    if plan.warmup_secs > 0 {
        notes.push(format!(
            "Warmup: the first {} s ({} iteration(s), {} send(s)) are excluded from every summary metric; the timeline shows them flagged.",
            plan.warmup_secs, snap.warmup_iterations_excluded, snap.warmup_sends_excluded
        ));
    }
    notes.push(match plan.connection_mode {
        ConnectionMode::Persistent => {
            "Connection mode persistent: each virtual user / slot keeps its own pooled connections (keep-alive forced on for this run)."
                .into()
        }
        ConnectionMode::Fresh => {
            "Connection mode fresh: keep-alive is disabled for this run, so every send opens a new connection (and TLS handshake).".into()
        }
    });
    notes.push("Latency is the sum of attempt durations (connect … last body byte) measured by the shared engine; local preparation and token acquisition are reported separately as setup time. Bytes are logical request/response header+body sizes (HTTP/2 header sizes are estimates), not wire bytes.".into());
    if snap.timeouts_censored.count > 0 {
        notes.push(format!("{} send(s) timed out. {}", snap.timeouts_censored.count, CENSORED_LABEL));
    }
    if snap.counts.started == 0 && snap.warmup_iterations_excluded > 0 {
        notes.push(format!(
            "Nothing was measured: all {} iteration(s) started during the {} s warmup. Shorten the warmup or lengthen the run.",
            snap.warmup_iterations_excluded, plan.warmup_secs
        ));
    }
    let port_exhaustion: u64 =
        snap.failure_categories.iter().filter(|c| c.category.contains(LOCAL_ADDRESS_EXHAUSTION_CODE)).map(|c| c.count).sum();
    if port_exhaustion > 0 {
        generator.notes.push(format!(
            "{port_exhaustion} send(s) failed because this machine ran out of local ports or addresses. This is a generator-side limit, not a failure of the target: every closed connection holds its client port in TIME_WAIT (tens of seconds), so fresh-connection runs exhaust the ephemeral range quickly. Use persistent connections, more source addresses or a lower connection rate."
        ));
    }
    notes.extend(extra_notes);

    let mut report = LoadReport {
        run_id: meta.run_id,
        schema_version: REPORT_SCHEMA_VERSION,
        engine: meta.engine.clone(),
        engine_version: meta.engine_version.clone(),
        plan: plan.clone(),
        request_revisions: meta.request_revisions.clone(),
        dataset_sha256: meta.dataset_sha256.clone(),
        started_at: meta.started_at,
        finished_at,
        completion,
        partial: completion != RunCompletion::Completed,
        warmup_included_in_metrics: false,
        destination_summary: snap.destinations,
        counts: snap.counts,
        achieved_rate_per_sec: snap.achieved_rate_per_sec,
        latency_success: snap.latency_success,
        latency_failure: snap.latency_failure,
        histogram_success_b64: snap.histogram_success_b64,
        status_distribution: snap.status_distribution,
        failure_categories: snap.failure_categories,
        timeline,
        bytes_sent: snap.bytes_sent,
        bytes_received: snap.bytes_received,
        generator,
        notes,
        requests: snap.requests,
        workload_label: workload_label(&plan.workload),
        offered_rate_per_sec: snap.offered_rate_per_sec,
        measured_duration_secs: snap.measured_duration_secs,
        timeouts_censored: snap.timeouts_censored,
        latency_setup: snap.latency_setup,
        histogram_failure_b64: snap.histogram_failure_b64,
        protocols: snap.protocols,
        warmup_iterations_excluded: snap.warmup_iterations_excluded,
        warmup_sends_excluded: snap.warmup_sends_excluded,
        integrity_sha256: None,
    };
    seal(&mut report);
    report
}

// -------------------------------------------------------------------- JSON

pub fn integrity_digest(r: &LoadReport) -> String {
    let mut c = r.clone();
    c.integrity_sha256 = None;
    hex::encode(Sha256::digest(serde_json::to_vec(&c).expect("reports serialize")))
}

pub fn seal(r: &mut LoadReport) {
    r.integrity_sha256 = Some(integrity_digest(r));
}

pub fn to_json(r: &LoadReport) -> String {
    let mut c = r.clone();
    seal(&mut c);
    serde_json::to_string_pretty(&c).expect("reports serialize")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Integrity {
    /// The stored hash matches the content.
    Verified,
    /// The report carries no hash (e.g. produced by an older version).
    Unsealed,
}

/// Reopen a saved JSON report, verifying its integrity hash.
pub fn open_json(s: &str) -> Result<(LoadReport, Integrity), LoadError> {
    let r: LoadReport = serde_json::from_str(s).map_err(|e| LoadError::Report(format!("not a load report: {e}")))?;
    match &r.integrity_sha256 {
        None => Ok((r, Integrity::Unsealed)),
        Some(h) if *h == integrity_digest(&r) => Ok((r, Integrity::Verified)),
        Some(_) => Err(LoadError::Report("integrity check failed: the report content does not match its recorded hash".into())),
    }
}

// --------------------------------------------------------------------- CSV

/// Neutralize spreadsheet formula injection in text cells.
fn cell(s: &str) -> String {
    match s.chars().next() {
        Some('=' | '+' | '-' | '@' | '\t' | '\r') => format!("'{s}"),
        _ => s.to_string(),
    }
}

fn csv_string(rows: Vec<Vec<String>>) -> String {
    let mut w = csv::Writer::from_writer(Vec::new());
    for r in rows {
        w.write_record(r.iter().map(|c| cell(c))).expect("in-memory CSV");
    }
    String::from_utf8(w.into_inner().expect("in-memory CSV")).expect("UTF-8 input")
}

fn opt<T: ToString>(v: Option<T>) -> String {
    v.map(|v| v.to_string()).unwrap_or_default()
}

/// Summary CSV: `section,metric,value` rows.
pub fn summary_csv(r: &LoadReport) -> String {
    let mut rows: Vec<Vec<String>> = vec![vec!["section".into(), "metric".into(), "value".into()]];
    let mut add = |s: &str, m: &str, v: String| rows.push(vec![s.into(), m.into(), v]);
    add("run", "run_id", r.run_id.to_string());
    add("run", "plan", r.plan.name.clone());
    add("run", "engine", format!("{} {}", r.engine, r.engine_version));
    add("run", "started_at", r.started_at.to_rfc3339());
    add("run", "finished_at", r.finished_at.to_rfc3339());
    add("run", "completion", format!("{:?}", r.completion));
    add("run", "partial", r.partial.to_string());
    add("run", "workload", r.workload_label.clone());
    add("run", "connection_mode", format!("{:?}", r.plan.connection_mode));
    add("run", "warmup_secs", r.plan.warmup_secs.to_string());
    add("run", "seed", r.plan.seed.to_string());
    add("run", "dataset_sha256", opt(r.dataset_sha256.clone()));
    add("run", "measured_duration_secs", format!("{:.3}", r.measured_duration_secs));
    let c = &r.counts;
    for (k, v) in [
        ("scheduled", c.scheduled),
        ("started", c.started),
        ("dropped", c.dropped),
        ("completed", c.completed),
        ("transport_failures", c.transport_failures),
        ("timeouts", c.timeouts),
        ("canceled", c.canceled),
        ("in_flight_at_end", c.in_flight_at_end),
        ("application_failures", c.application_failures),
        ("assertion_failures", c.assertion_failures),
    ] {
        add("iterations", k, v.to_string());
    }
    let q = &r.requests;
    for (k, v) in [
        ("started", q.started),
        ("completed", q.completed),
        ("transport_failures", q.transport_failures),
        ("timeouts", q.timeouts),
        ("canceled", q.canceled),
        ("in_flight_at_end", q.in_flight_at_end),
        ("application_failures", q.application_failures),
        ("assertion_failures", q.assertion_failures),
        ("connections_opened", q.connections_opened),
        ("connections_reused", q.connections_reused),
    ] {
        add("sends", k, v.to_string());
    }
    add("rate", "achieved_iterations_per_sec", format!("{:.3}", r.achieved_rate_per_sec));
    add("rate", "offered_arrivals_per_sec", opt(r.offered_rate_per_sec.map(|v| format!("{v:.3}"))));
    for (name, l) in
        [("latency_success_us", &r.latency_success), ("latency_failure_us", &r.latency_failure), ("setup_us", &r.latency_setup)]
    {
        for (k, v) in [
            ("count", l.count),
            ("min", l.min_us),
            ("mean", l.mean_us),
            ("p50", l.p50_us),
            ("p90", l.p90_us),
            ("p95", l.p95_us),
            ("p99", l.p99_us),
            ("max", l.max_us),
        ] {
            add(name, k, v.to_string());
        }
    }
    let t = &r.timeouts_censored;
    add("timeouts_censored", "count", t.count.to_string());
    add("timeouts_censored", "deadline_ms_min", opt(t.deadline_ms_min));
    add("timeouts_censored", "deadline_ms_max", opt(t.deadline_ms_max));
    add("timeouts_censored", "elapsed_max_us", t.elapsed_at_timeout.max_us.to_string());
    add("timeouts_censored", "label", t.label.clone());
    for (s, n) in &r.status_distribution {
        add("status", &s.to_string(), n.to_string());
    }
    for f in &r.failure_categories {
        add("failure_category", &f.category, f.count.to_string());
    }
    add("bytes", "sent", r.bytes_sent.to_string());
    add("bytes", "received", r.bytes_received.to_string());
    let g = &r.generator;
    add("generator", "peak_cpu_percent", opt(g.peak_cpu_percent.map(|v| format!("{v:.1}"))));
    add("generator", "peak_rss_bytes", opt(g.peak_rss_bytes));
    add("generator", "peak_open_fds", opt(g.peak_open_fds));
    add("generator", "p99_schedule_lag_us", g.p99_schedule_lag_us.to_string());
    add("generator", "max_schedule_lag_us", g.max_schedule_lag_us.to_string());
    add("generator", "target_not_achieved", g.target_not_achieved.to_string());
    add("integrity", "sha256", opt(r.integrity_sha256.clone()));
    csv_string(rows)
}

/// Per-bucket timeline CSV.
pub fn timeline_csv(r: &LoadReport) -> String {
    let mut rows = vec![
        [
            "second",
            "warmup",
            "sends_started",
            "sends_completed",
            "failures",
            "arrivals_dropped",
            "peak_in_flight",
            "success_p50_us",
            "success_p99_us",
            "p99_schedule_lag_us",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect::<Vec<_>>(),
    ];
    for b in &r.timeline {
        rows.push(vec![
            b.second.to_string(),
            b.warmup.to_string(),
            b.started.to_string(),
            b.completed.to_string(),
            b.failures.to_string(),
            b.dropped.to_string(),
            b.in_flight.to_string(),
            b.p50_us.to_string(),
            b.p99_us.to_string(),
            b.p99_schedule_lag_us.to_string(),
        ]);
    }
    csv_string(rows)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub fn sample_report() -> LoadReport {
        let (meta, snap, timeline) = sample_parts();
        assemble(&meta, snap, timeline, RunCompletion::Completed, Utc::now(), vec![])
    }

    pub fn sample_parts() -> (RunMeta, MetricsSnapshot, Vec<TimeBucket>) {
        let plan = LoadPlan {
            id: Id::new(),
            workspace_id: Id::new(),
            name: "checkout".into(),
            workload: Workload::OpenArrivalRate {
                stages: vec![Stage { duration_secs: 0, target: 10 }, Stage { duration_secs: 5, target: 10 }],
                max_in_flight: 4,
            },
            chain: vec![Id::new()],
            mix: vec![],
            dataset_id: None,
            environment_id: None,
            connection_mode: ConnectionMode::Persistent,
            warmup_secs: 0,
            abort: None,
            seed: 42,
            trusted: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let meta = RunMeta {
            run_id: Id::new(),
            engine: crate::ENGINE_NAME.into(),
            engine_version: crate::engine_version(),
            plan,
            request_revisions: vec![Id::new()],
            dataset_sha256: Some("ab".repeat(32)),
            started_at: Utc::now(),
        };
        let mut m = crate::metrics::Metrics::new();
        for v in [1_000u64, 2_000, 3_000] {
            m.success.record(v);
        }
        let snap = MetricsSnapshot {
            counts: LoadCounts {
                scheduled: 50,
                started: 48,
                dropped: 2,
                completed: 45,
                transport_failures: 1,
                timeouts: 1,
                canceled: 1,
                in_flight_at_end: 0,
                application_failures: 3,
                assertion_failures: 0,
            },
            requests: RequestCounts {
                started: 48,
                completed: 45,
                transport_failures: 1,
                timeouts: 1,
                canceled: 1,
                application_failures: 3,
                ..Default::default()
            },
            measured_duration_secs: 5.0,
            achieved_rate_per_sec: 9.6,
            offered_rate_per_sec: Some(10.0),
            latency_success: m.success.summary(),
            histogram_success_b64: m.success.to_b64(),
            histogram_failure_b64: m.failure.to_b64(),
            status_distribution: vec![(200, 42), (500, 3)],
            failure_categories: vec![FailureSample {
                category: "application_failure: http.server_error".into(),
                count: 3,
                examples: vec!["GET http://127.0.0.1:1/status/500 → HTTP 500".into()],
            }],
            bytes_sent: 1234,
            bytes_received: 5678,
            protocols: vec![("http/1.1".into(), 48)],
            destinations: vec!["http://127.0.0.1:1".into()],
            ..Default::default()
        };
        let timeline = (0..5)
            .map(|s| TimeBucket {
                second: s,
                started: 10,
                completed: 9,
                failures: 1,
                dropped: 0,
                p50_us: 1_500,
                p99_us: 3_000,
                in_flight: 2,
                warmup: false,
                p99_schedule_lag_us: 300,
            })
            .collect();
        (meta, snap, timeline)
    }

    #[test]
    fn generator_side_limits_and_empty_measurement_are_called_out() {
        let (meta, mut snap, timeline) = sample_parts();
        snap.failure_categories.push(FailureSample {
            category: format!("transport_failure: {LOCAL_ADDRESS_EXHAUSTION_CODE}"),
            count: 7,
            examples: vec![],
        });
        let r = assemble(&meta, snap, timeline.clone(), RunCompletion::Completed, Utc::now(), vec![]);
        assert!(r.generator.notes.iter().any(|n| n.starts_with("7 send(s) failed because this machine ran out of local ports")));

        let (mut meta, mut snap, _) = sample_parts();
        meta.plan.warmup_secs = 1;
        snap.counts = LoadCounts::default();
        snap.warmup_iterations_excluded = 30;
        let r = assemble(&meta, snap, vec![], RunCompletion::Completed, Utc::now(), vec![]);
        assert!(r.notes.iter().any(|n| n.starts_with("Nothing was measured: all 30 iteration(s)")), "{:?}", r.notes);
    }

    #[test]
    fn load_007_late_starts_mean_target_not_achieved_even_when_every_arrival_started() {
        let (meta, mut snap, timeline) = sample_parts();
        snap.counts.dropped = 0;
        snap.counts.scheduled = snap.counts.started;
        snap.achieved_rate_per_sec = 10.0;
        let ok = assemble(&meta, snap.clone(), timeline.clone(), RunCompletion::Completed, Utc::now(), vec![]);
        assert!(!ok.generator.target_not_achieved);
        snap.generator.p99_schedule_lag_us = 221_000;
        snap.generator.max_schedule_lag_us = 268_000;
        let late = assemble(&meta, snap, timeline, RunCompletion::Completed, Utc::now(), vec![]);
        assert!(late.generator.target_not_achieved);
        assert!(
            late.generator.notes.iter().any(|n| n.contains("arrivals started late (p99 start lag 221.0 ms")),
            "{:?}",
            late.generator.notes
        );
    }

    #[test]
    fn load_011_json_reopen_preserves_metadata_and_verifies_integrity() {
        let r = sample_report();
        let json = to_json(&r);
        let (back, integrity) = open_json(&json).unwrap();
        assert_eq!(integrity, Integrity::Verified);
        assert_eq!(back, r, "every field, including metrics, config, version and dataset hash, survives the round trip");
        assert_eq!(back.engine_version, crate::engine_version());
        assert_eq!(back.dataset_sha256, r.dataset_sha256);
        assert!(check_balance(&back.counts).is_ok());
        // Tampering is detected.
        let tampered = json.replace("\"p99_us\": 3000", "\"p99_us\": 1");
        assert_ne!(tampered, json);
        assert!(open_json(&tampered).is_err());
        // Histograms reopen and merge.
        let h = crate::metrics::histogram_from_b64(&back.histogram_success_b64).unwrap();
        assert_eq!(h.len(), 3);
    }

    #[test]
    fn csv_exports_neutralize_formulas() {
        let mut r = sample_report();
        r.plan.name = "=HYPERLINK(\"http://evil\")".into();
        let s = summary_csv(&r);
        assert!(s.contains("'=HYPERLINK"), "{s}");
        assert!(s.lines().any(|l| l.starts_with("iterations,dropped,2")));
        let t = timeline_csv(&r);
        assert_eq!(t.lines().count(), 6);
    }

    #[test]
    fn open_workload_below_target_is_flagged() {
        let r = sample_report();
        assert!(!r.generator.target_not_achieved, "96 % of offered is within the 90 % bar");
        let mut tl = r.timeline.clone();
        for (i, b) in tl.iter_mut().enumerate() {
            b.p99_schedule_lag_us = if i < 2 { 1_000 } else { 200_000 };
        }
        assert!(lag_grows(&tl));
    }

    #[test]
    fn balance_checks_catch_inconsistency() {
        let mut c = LoadCounts { scheduled: 3, started: 2, dropped: 1, completed: 2, ..Default::default() };
        assert!(check_balance(&c).is_ok());
        c.completed = 1;
        assert!(check_balance(&c).is_err());
    }
}
