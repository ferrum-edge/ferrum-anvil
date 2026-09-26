//! Loopback measurement harness for `docs/load.md`.
//!
//! Starts the HTTP fixture in this process and runs short workloads through a
//! separate `anvil-load-worker` process (so generator CPU/RSS are the
//! worker's own), then prints one line per scenario. Loopback only; each
//! scenario lasts a few seconds.
//!
//! ```text
//! cargo build --release -p anvil-load --bins --examples
//! target/release/examples/loopback_bench
//! ```

use anvil_domain::Id;
use anvil_domain::load::*;
use anvil_domain::request::RequestSpec;
use anvil_engine::ExecutionContext;
use anvil_load::{LoadController, LoadJob, RunOptions, WorkerJob};
use chrono::Utc;
use std::collections::HashMap;
use std::path::PathBuf;

fn plan(workload: Workload, id: Id, mode: ConnectionMode) -> LoadPlan {
    // Timed workloads exclude a 1 s warmup; a fixed iteration count is
    // measured from the first send.
    let warmup_secs = if matches!(workload, Workload::Iterations { .. }) { 0 } else { 1 };
    LoadPlan {
        id: Id::new(),
        workspace_id: Id::new(),
        name: "loopback bench".into(),
        workload,
        chain: vec![id],
        mix: vec![],
        dataset_id: None,
        environment_id: None,
        connection_mode: mode,
        warmup_secs,
        abort: None,
        seed: 1,
        trusted: true,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn worker_path() -> PathBuf {
    let exe = std::env::current_exe().expect("current exe");
    exe.parent().and_then(|p| p.parent()).expect("target dir").join("anvil-load-worker")
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    anvil_transport::init();
    anvil_fixtures::init();
    let f = anvil_fixtures::http::serve("127.0.0.1:0", None).await.expect("fixture");
    let hold = |r: u64, s: u64| vec![Stage { duration_secs: 0, target: r }, Stage { duration_secs: s, target: r }];
    let scenarios: Vec<(&str, Workload, ConnectionMode, &str)> = vec![
        (
            "closed 32 VUs, persistent, GET /",
            Workload::ClosedVirtualUsers { stages: hold(32, 6), think_time_ms: 0 },
            ConnectionMode::Persistent,
            "/",
        ),
        (
            "open 2000/s, max 256 in flight, GET /",
            Workload::OpenArrivalRate { stages: hold(2000, 6), max_in_flight: 256 },
            ConnectionMode::Persistent,
            "/",
        ),
        (
            "open 500/s, max 256 in flight, 20 ms backend",
            Workload::OpenArrivalRate { stages: hold(500, 6), max_in_flight: 256 },
            ConnectionMode::Persistent,
            "/delay-headers/20",
        ),
        // Last and bounded: every fresh connection leaves a client-side
        // TIME_WAIT socket, which exhausts ephemeral ports within seconds.
        (
            "3000 iterations × 8, fresh connections, GET /",
            Workload::Iterations { iterations: 3000, concurrency: 8 },
            ConnectionMode::Fresh,
            "/",
        ),
    ];
    println!("cpus available: {}", std::thread::available_parallelism().map(|n| n.get()).unwrap_or(0));
    for (name, workload, mode, path) in scenarios {
        let id = Id::new();
        let mut ctx = ExecutionContext::standalone(RequestSpec::http("GET", &f.url(path)));
        ctx.isolation = "bench".into();
        let p = plan(workload, id, mode);
        let opts = RunOptions { acknowledged: true, ..Default::default() };
        let job = WorkerJob::from_load_job(&p, &LoadJob { requests: HashMap::from([(id, ctx)]), dataset: None }, opts).expect("job");
        let c = LoadController::spawn(&worker_path(), &job).await.expect("worker");
        let r = c.wait().await.expect("report");
        let q = &r.requests;
        println!(
            "{name}: achieved {:.0} it/s{} | sends {} ok {} fail {} dropped {} | success p50 {} µs p99 {} µs | lag p99 {} µs max {} µs | worker peak CPU {} | peak RSS {} | peak fds {} | conns opened {} reused {} | target_not_achieved {}",
            r.achieved_rate_per_sec,
            r.offered_rate_per_sec.map(|o| format!(" of {o:.0} offered")).unwrap_or_default(),
            q.started,
            r.latency_success.count,
            r.latency_failure.count + q.timeouts,
            r.counts.dropped,
            r.latency_success.p50_us,
            r.latency_success.p99_us,
            r.generator.p99_schedule_lag_us,
            r.generator.max_schedule_lag_us,
            r.generator.peak_cpu_percent.map(|c| format!("{c:.0}%")).unwrap_or_else(|| "n/a".into()),
            r.generator.peak_rss_bytes.map(|b| format!("{:.0} MiB", b as f64 / 1048576.0)).unwrap_or_else(|| "n/a".into()),
            r.generator.peak_open_fds.map(|n| n.to_string()).unwrap_or_else(|| "n/a".into()),
            q.connections_opened,
            q.connections_reused,
            r.generator.target_not_achieved,
        );
        if let Some(mean) = r.generator.notes.iter().find(|n| n.starts_with("Mean generator CPU")) {
            println!("    {mean}");
        }
        for c in r.failure_categories.iter().take(3) {
            println!("    failure {} ×{}: {}", c.category, c.count, c.examples.first().map(String::as_str).unwrap_or(""));
        }
    }
}
