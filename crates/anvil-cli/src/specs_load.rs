//! `anvil import-spec` and `anvil load …`.

use anvil_app::App;
use anvil_app::specs::SpecTarget;
use anvil_domain::Id;
use anvil_domain::load::{AbortRule, ConnectionMode, LoadPlan, RunCompletion, Stage, Workload};
use anvil_import::{GroupBy, ImportOptions, SampleMode};
use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Subcommand, ValueEnum};
use std::io::Read;
use std::path::PathBuf;

/// Fixed, non-secret mode flag: `anvil` re-launches itself as the load
/// worker; the job travels on stdin only.
pub const LOAD_WORKER_FLAG: &str = "--anvil-load-worker";

#[derive(Clone, Copy, ValueEnum)]
pub enum BodyMode {
    Sample,
    Blank,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum Grouping {
    Tags,
    Paths,
}

#[derive(Args)]
pub struct ImportSpecArgs {
    /// Target workspace (id or name). Omit with `--new-workspace`.
    #[arg(required_unless_present = "new_workspace")]
    workspace: Option<String>,
    /// OpenAPI/Swagger, WSDL, Postman, Insomnia, HAR or a file with a cURL command; `-` reads stdin.
    #[arg(long)]
    file: PathBuf,
    /// Create a new workspace named after the source instead.
    #[arg(long)]
    new_workspace: bool,
    #[arg(long, value_enum, default_value = "sample")]
    bodies: BodyMode,
    #[arg(long, value_enum, default_value = "tags")]
    group_by: Grouping,
    /// Include optional parameters/fields.
    #[arg(long)]
    include_optional: bool,
    /// Keep literal credentials found in HAR/cURL/Postman/Insomnia (default: placeholders).
    #[arg(long)]
    include_credentials: bool,
    /// Which OpenAPI server / Swagger scheme becomes the environment.
    #[arg(long, default_value_t = 0)]
    server: usize,
    /// Print the preview report and stop.
    #[arg(long)]
    dry_run: bool,
}

pub fn import_spec(app: &App, a: &ImportSpecArgs) -> Result<i32> {
    let (bytes, name) = if a.file.as_os_str() == "-" {
        let mut v = Vec::new();
        std::io::stdin().take(32 * 1024 * 1024 + 1).read_to_end(&mut v)?;
        (v, "stdin".to_string())
    } else {
        let meta = std::fs::metadata(&a.file).with_context(|| format!("reading {}", a.file.display()))?;
        if meta.len() > 32 * 1024 * 1024 {
            bail!("the source is larger than 32 MiB");
        }
        (std::fs::read(&a.file)?, a.file.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "source".into()))
    };
    let opts = ImportOptions {
        mode: match a.bodies {
            BodyMode::Sample => SampleMode::Sample,
            BodyMode::Blank => SampleMode::Blank,
        },
        group_by: match a.group_by {
            Grouping::Tags => GroupBy::Tags,
            Grouping::Paths => GroupBy::Paths,
        },
        include_optional: a.include_optional,
        include_credentials: a.include_credentials,
        server_index: a.server,
        ..ImportOptions::default()
    };
    if a.dry_run {
        let p = app.spec_preview(&bytes, &opts)?;
        println!("{}", serde_json::to_string_pretty(&p)?);
        return Ok(0);
    }
    let target = if a.new_workspace {
        SpecTarget::NewWorkspace
    } else {
        let ws = a.workspace.as_deref().ok_or_else(|| anyhow!("name a workspace or pass --new-workspace"))?;
        SpecTarget::Workspace { workspace_id: app.find_workspace(ws)?.meta.id }
    };
    let r = app.spec_import(&bytes, &name, &opts, target)?;
    println!("imported {} request(s) into workspace {} (import {}); nothing was sent", r.requests, r.workspace_id, r.import_id);
    for v in &r.report.required_variables {
        println!("  fill in {{{{{}}}}}{} — {}", v.name, if v.secret { " (secret)" } else { "" }, v.reason);
    }
    for w in r.report.unsupported.iter().take(20) {
        println!("  not imported: {} ({})", w.message, w.pointer);
    }
    Ok(0)
}

#[derive(Subcommand)]
pub enum LoadCmd {
    /// Create a load plan over saved requests (a chain executed per iteration).
    /// Every request must produce the same load unit (HTTP requests, unary gRPC
    /// calls, gRPC or SSE streams, WebSocket sessions, TCP or UDP/DTLS
    /// exchanges); unsupported combinations are refused before any traffic.
    Create {
        workspace: String,
        name: String,
        /// Saved request (id, name or Folder/Path/Name); repeat for a chain.
        #[arg(long = "request", required = true)]
        requests: Vec<String>,
        /// Closed workload: virtual users (held for --duration).
        #[arg(long, conflicts_with_all = ["rate", "iterations"])]
        vus: Option<u64>,
        /// Open workload: arrivals per second (held for --duration).
        #[arg(long, conflicts_with_all = ["vus", "iterations"])]
        rate: Option<u64>,
        /// Fixed iteration count (with --concurrency).
        #[arg(long, conflicts_with_all = ["vus", "rate"])]
        iterations: Option<u64>,
        #[arg(long, default_value_t = 30)]
        duration: u64,
        #[arg(long, default_value_t = 10)]
        concurrency: u64,
        #[arg(long, default_value_t = 1000)]
        max_in_flight: u64,
        #[arg(long, default_value_t = 0)]
        warmup: u64,
        /// Abort when failures exceed this percentage over a 10 s window.
        #[arg(long)]
        abort_failure_pct: Option<u32>,
        /// Open a new connection for every unit (default: reuse per virtual
        /// user where the protocol allows it — HTTP and gRPC).
        #[arg(long)]
        fresh: bool,
    },
    /// Show what a plan measures (its load unit) or why it is refused; nothing is sent.
    Check { workspace: String, plan: String },
    /// List load plans.
    List { workspace: String },
    /// Show the destinations and planned load (nothing is sent).
    Preflight { workspace: String, plan: String },
    /// Run a plan in a worker process. Requires --i-am-authorized.
    Run {
        workspace: String,
        plan: String,
        /// Confirms you own the destinations or are authorized to load-test them.
        #[arg(long)]
        i_am_authorized: bool,
        #[arg(long)]
        json: Option<PathBuf>,
        #[arg(long)]
        html: Option<PathBuf>,
        #[arg(long)]
        csv: Option<PathBuf>,
    },
    /// List saved load reports.
    Reports { workspace: String },
}

fn find_plan(app: &App, ws: &Id, key: &str) -> Result<LoadPlan> {
    app.load_plans(ws)?
        .into_iter()
        .find(|p| p.name.eq_ignore_ascii_case(key) || p.id.to_string() == key)
        .ok_or_else(|| anyhow!("load plan '{key}' not found"))
}

pub async fn load_cmd(app: &App, cmd: &LoadCmd) -> Result<i32> {
    match cmd {
        LoadCmd::Create {
            workspace,
            name,
            requests,
            vus,
            rate,
            iterations,
            duration,
            concurrency,
            max_in_flight,
            warmup,
            abort_failure_pct,
            fresh,
        } => {
            let ws = app.find_workspace(workspace)?.meta.id;
            let mut chain = Vec::new();
            for r in requests {
                chain.push(app.find_request(&ws, r)?.meta.id);
            }
            let stage = |target: u64| vec![Stage { duration_secs: *duration, target }];
            let workload = match (vus, rate, iterations) {
                (Some(v), _, _) => Workload::ClosedVirtualUsers { stages: stage(*v), think_time_ms: 0 },
                (_, Some(r), _) => Workload::OpenArrivalRate { stages: stage(*r), max_in_flight: *max_in_flight },
                (_, _, Some(n)) => Workload::Iterations { iterations: *n, concurrency: *concurrency },
                _ => bail!("choose --vus, --rate or --iterations"),
            };
            let now = chrono::Utc::now();
            let p = LoadPlan {
                id: Id::new(),
                workspace_id: ws,
                name: name.clone(),
                workload,
                chain,
                mix: vec![],
                dataset_id: None,
                environment_id: None,
                connection_mode: if *fresh { ConnectionMode::Fresh } else { ConnectionMode::Persistent },
                warmup_secs: *warmup,
                abort: abort_failure_pct.map(|p| AbortRule { max_failure_permille: p * 10, window_secs: 10 }),
                seed: 1,
                trusted: true,
                created_at: now,
                updated_at: now,
            };
            let p = app.save_load_plan(p)?;
            println!("created load plan {} ({})", p.name, p.id);
            let check = app.load_plan_check(&p)?;
            match (&check.unit_label, &check.refusal) {
                (_, Some(r)) => println!("  refused for load: {r}"),
                (Some(label), None) => println!("  load unit: {label}"),
                _ => {}
            }
            Ok(0)
        }
        LoadCmd::Check { workspace, plan } => {
            let ws = app.find_workspace(workspace)?.meta.id;
            let p = find_plan(app, &ws, plan)?;
            let check = app.load_plan_check(&p)?;
            println!("{}", serde_json::to_string_pretty(&check)?);
            Ok(if check.refusal.is_some() { 3 } else { 0 })
        }
        LoadCmd::List { workspace } => {
            let ws = app.find_workspace(workspace)?.meta.id;
            for p in app.load_plans(&ws)? {
                println!("{}  {}{}", p.id, p.name, if p.trusted { "" } else { "  (imported — review before running)" });
            }
            Ok(0)
        }
        LoadCmd::Preflight { workspace, plan } => {
            let ws = app.find_workspace(workspace)?.meta.id;
            let p = find_plan(app, &ws, plan)?;
            println!("{}", serde_json::to_string_pretty(&app.load_preflight(&p)?)?);
            Ok(0)
        }
        LoadCmd::Run { workspace, plan, i_am_authorized, json, html, csv } => {
            let ws = app.find_workspace(workspace)?.meta.id;
            let p = find_plan(app, &ws, plan)?;
            let pre = app.load_preflight(&p)?;
            eprintln!("destinations: {}", pre.destinations.join(", "));
            eprintln!("workload: {}", pre.workload);
            eprintln!("load unit: {} — {}", pre.unit_label, pre.semantics.completed_means);
            for w in &pre.warnings {
                eprintln!("warning: {w}");
            }
            if !i_am_authorized {
                eprintln!(
                    "refusing to start: pass --i-am-authorized to confirm you own these destinations or are authorized to load-test them"
                );
                return Ok(3);
            }
            let job = app.worker_job(&p, true)?;
            let exe = std::env::current_exe()?;
            let mut c = anvil_load::LoadController::spawn_mode(&exe, Some(LOAD_WORKER_FLAG), &job).await?;
            let cancel = tokio_util::sync::CancellationToken::new();
            let c2 = cancel.clone();
            tokio::spawn(async move {
                if tokio::signal::ctrl_c().await.is_ok() {
                    c2.cancel();
                }
            });
            let mut stopping = false;
            let units = pre.semantics.unit_plural.clone();
            loop {
                tokio::select! {
                    p = c.next_progress() => match p {
                        Some(p) => {
                            let k = &p.snapshot.requests;
                            eprintln!(
                                "{:>5.0}s {units}: {:>9} started {:>9} completed {:>6} failed {:>8.1} iterations/s p95 {}",
                                p.elapsed_secs,
                                k.started,
                                k.completed,
                                k.transport_failures + k.timeouts + k.application_failures,
                                p.snapshot.achieved_rate_per_sec,
                                us_or_none(p.snapshot.latency_success.count, p.snapshot.latency_success.p95_us)
                            );
                        }
                        None => break,
                    },
                    _ = cancel.cancelled(), if !stopping => {
                        stopping = true;
                        eprintln!("stopping (draining in-flight requests)…");
                        c.cancel().await;
                    }
                }
            }
            let report = c.wait().await?;
            app.save_load_report(&report)?;
            if let Some(f) = json {
                std::fs::write(f, anvil_load::report::to_json(&report))?;
            }
            if let Some(f) = html {
                std::fs::write(f, anvil_load::html::to_html(&report))?;
            }
            if let Some(f) = csv {
                std::fs::write(f, anvil_load::report::summary_csv(&report))?;
            }
            let k = &report.counts;
            println!(
                "{:?}{}: {} started, {} completed, {} transport failures, {} timeouts, {} application failures, {} assertion failures, {} dropped; {:.1}/s; success p50 {} p95 {} p99 {}",
                report.completion,
                if report.partial { " (partial)" } else { "" },
                k.started,
                k.completed,
                k.transport_failures,
                k.timeouts,
                k.application_failures,
                k.assertion_failures,
                k.dropped,
                report.achieved_rate_per_sec,
                us_or_none(report.latency_success.count, report.latency_success.p50_us),
                us_or_none(report.latency_success.count, report.latency_success.p95_us),
                us_or_none(report.latency_success.count, report.latency_success.p99_us)
            );
            if let Some(m) = &report.protocol_metrics {
                for l in anvil_load::report::protocol_lines(m) {
                    println!("  {l}");
                }
            }
            for n in &report.notes {
                println!("  note: {n}");
            }
            let failed = k.transport_failures + k.timeouts + k.application_failures > 0;
            Ok(if report.completion != RunCompletion::Completed || report.partial || failed {
                1
            } else if k.assertion_failures > 0 {
                2
            } else {
                0
            })
        }
        LoadCmd::Reports { workspace } => {
            let ws = app.find_workspace(workspace)?.meta.id;
            for r in app.load_reports(&ws)? {
                println!(
                    "{}  {}  {}  {}  {:?}{}  {:.1}/s  p95 {}  {} failed",
                    r.run_id,
                    r.started_at.format("%Y-%m-%d %H:%M:%S"),
                    r.plan_name,
                    anvil_load::protocol::label(r.unit),
                    r.completion,
                    if r.partial { " (partial)" } else { "" },
                    r.achieved_rate_per_sec,
                    r.p95_us.map(|v| format!("{v} µs")).unwrap_or_else(|| "— (no successful units)".into()),
                    r.failures
                );
            }
            Ok(0)
        }
    }
}

/// A success-latency value, or "—" when no send succeeded (never "0 µs").
fn us_or_none(count: u64, us: u64) -> String {
    if count == 0 { "—".into() } else { format!("{us} µs") }
}
