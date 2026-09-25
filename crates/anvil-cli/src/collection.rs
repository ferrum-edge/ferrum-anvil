//! `anvil run` and `anvil scenario`: the collection runner from the command line.

use super::{Dimension, DsFormat, RunArgs, ScenarioCmd};
use anvil_app::App;
use anvil_app::runner::RunSettings;
use anvil_domain::Id;
use anvil_domain::runner::{FailOn, RunEvent, RunReport, RunStepStatus, RunnerCompletion};
use anvil_domain::workspace::{DatasetFormat, ScenarioStep};
use anvil_runner::RunDataset;
use anyhow::{Context, Result, anyhow, bail};
use std::path::Path;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

fn environment_id(app: &App, ws: &Id, name: Option<&str>) -> Result<Option<Id>> {
    let Some(name) = name else { return Ok(None) };
    Ok(Some(
        app.environments(ws)?
            .into_iter()
            .find(|e| e.name.eq_ignore_ascii_case(name) || e.meta.id.to_string() == name)
            .ok_or_else(|| anyhow!("environment '{name}' not found"))?
            .meta
            .id,
    ))
}

fn dataset_format(path: &Path, explicit: Option<DsFormat>) -> Result<DatasetFormat> {
    match explicit {
        Some(DsFormat::Csv) => Ok(DatasetFormat::Csv),
        Some(DsFormat::Json) => Ok(DatasetFormat::Json),
        None => RunDataset::format_for_path(&path.to_string_lossy())
            .ok_or_else(|| anyhow!("cannot tell the format of '{}': use --dataset-format csv|json", path.display())),
    }
}

/// Read a dataset file with the size bound checked before reading.
fn read_dataset_file(path: &Path) -> Result<Vec<u8>> {
    let meta = std::fs::metadata(path).with_context(|| format!("dataset '{}'", path.display()))?;
    if meta.len() > anvil_runner::dataset::MAX_DATASET_BYTES as u64 {
        bail!(
            "dataset '{}' is {} bytes; the collection runner accepts at most {}",
            path.display(),
            meta.len(),
            anvil_runner::dataset::MAX_DATASET_BYTES
        );
    }
    std::fs::read(path).with_context(|| format!("dataset '{}'", path.display()))
}

fn file_name(path: &Path) -> String {
    path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "dataset".into())
}

fn fail_on(dims: &[Dimension]) -> FailOn {
    if dims.is_empty() {
        return FailOn::default();
    }
    FailOn {
        transport: dims.contains(&Dimension::Transport),
        application: dims.contains(&Dimension::Application),
        assertions: dims.contains(&Dimension::Assertions),
    }
}

/// Exit code of a finished run (see the crate docs).
pub fn exit_code(r: &RunReport) -> i32 {
    // With assertions counted, every executed step whose assertion dimension
    // failed is a failed step (totals count omitted summaries too).
    if r.fail_on.assertions && r.totals.assertion_failures > 0 {
        2
    } else if r.totals.steps_failed > 0 || r.totals.steps_errored > 0 || r.completion != RunnerCompletion::Completed {
        1
    } else {
        0
    }
}

fn status_word(s: RunStepStatus) -> &'static str {
    match s {
        RunStepStatus::Passed => "passed",
        RunStepStatus::Failed => "FAILED",
        RunStepStatus::Error => "NOT SENT",
        RunStepStatus::Skipped => "skipped",
        RunStepStatus::Canceled => "canceled",
    }
}

fn print_report(r: &RunReport) {
    let t = &r.totals;
    println!(
        "{} — {} in {} ms{}",
        r.name,
        match r.completion {
            RunnerCompletion::Completed => "completed",
            RunnerCompletion::Canceled => "CANCELED (partial report)",
            RunnerCompletion::Aborted => "ABORTED (partial report)",
        },
        r.duration_ms,
        r.environment_name.as_deref().map(|e| format!(" · environment {e}")).unwrap_or_default()
    );
    if let Some(a) = &r.abort_reason {
        println!("  aborted: {a}");
    }
    println!(
        "  iterations: {} passed, {} failed, {} incomplete of {} planned",
        t.iterations_passed, t.iterations_failed, t.iterations_incomplete, t.iterations_planned
    );
    println!(
        "  steps: {} passed, {} failed, {} not sent, {} skipped, {} canceled",
        t.steps_passed,
        t.steps_failed,
        t.steps_errored,
        t.steps_skipped,
        t.steps_canceled + t.steps_canceled_in_flight
    );
    println!(
        "  failed dimensions: transport {} · application {} · assertions {} (assertion results: {} passed, {} failed)",
        t.transport_failures, t.application_failures, t.assertion_failures, t.assertions_passed, t.assertions_failed
    );
    let mut shown = 0;
    for it in &r.iterations {
        for s in it.steps.iter().filter(|s| matches!(s.status, RunStepStatus::Failed | RunStepStatus::Error)) {
            if shown == 50 {
                println!("  … more failures in the report");
                break;
            }
            shown += 1;
            let row = it.dataset_row.map(|x| format!(" (row {x})")).unwrap_or_default();
            println!("\n  ✗ iteration {}{row} · step {} {} — {}", it.index + 1, s.index + 1, s.name, status_word(s.status));
            if !s.url.is_empty() {
                println!("    {} {}", s.method, s.url);
            }
            if !s.summary.is_empty() {
                println!("    {}", s.summary);
            }
            if let Some(m) = &s.message {
                println!("    {m}");
            }
            for a in s.assertion_results.iter().filter(|a| !a.passed) {
                println!("    ✗ {} — {}", a.label, a.message);
            }
            for f in s.findings.iter().take(2) {
                println!("    {} [{:?}]", f.title, f.confidence);
            }
        }
    }
    for n in &r.notes {
        println!("  ! {n}");
    }
    println!("  run id: {}", r.run_id);
}

fn write_out(path: &Path, text: &str, what: &str) -> Result<()> {
    std::fs::write(path, text).with_context(|| format!("writing the {what} report to {}", path.display()))?;
    eprintln!("wrote {what} report to {}", path.display());
    Ok(())
}

pub async fn run_collection(app: &App, a: &RunArgs) -> Result<i32> {
    let ws = app.find_workspace(&a.workspace)?;
    let dataset = match &a.dataset {
        Some(p) => {
            let format = dataset_format(p, a.dataset_format)?;
            let bytes = read_dataset_file(p)?;
            let d = RunDataset::parse(&file_name(p), format, &bytes, &a.sensitive_columns)?;
            if !d.missing_sensitive_columns.is_empty() {
                bail!("--sensitive-column {} is not a column of '{}'", d.missing_sensitive_columns.join(", "), p.display());
            }
            Some(d)
        }
        None if !a.sensitive_columns.is_empty() => bail!("--sensitive-column needs --dataset"),
        None => None,
    };
    let cancel = CancellationToken::new();
    let c2 = cancel.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            eprintln!("canceling… (in-flight requests are not retried; a partial report follows)");
            c2.cancel();
        }
    });
    let events: Option<anvil_runner::RunEventSink> = if a.quiet {
        None
    } else {
        Some(Arc::new(|e: RunEvent| match e {
            RunEvent::RunStarted { name, iterations, steps, .. } => {
                eprintln!("running {name}: {iterations} iteration(s) × {steps} step(s)")
            }
            RunEvent::StepStarted { iteration, step, name, .. } => eprintln!("  [{}] {} {name} …", iteration + 1, step + 1),
            RunEvent::StepFinished { iteration, step, status, http_status, duration_ms, .. } => eprintln!(
                "  [{}] {} {}{}{}",
                iteration + 1,
                step + 1,
                status_word(status),
                http_status.map(|s| format!(" · HTTP {s}")).unwrap_or_default(),
                duration_ms.map(|d| format!(" · {d} ms")).unwrap_or_default()
            ),
            RunEvent::RunFinished { dropped_events, .. } if dropped_events > 0 => {
                eprintln!("  ({dropped_events} progress lines were coalesced)")
            }
            _ => {}
        }))
    };
    let settings = RunSettings {
        environment: environment_id(app, &ws.meta.id, a.env.as_deref())?,
        iterations: a.iterations,
        stop_on_failure: if a.stop_on_failure {
            Some(true)
        } else if a.continue_on_failure {
            Some(false)
        } else {
            None
        },
        fail_on: fail_on(&a.fail_on),
        allow_untrusted: a.allow_untrusted,
        dataset,
        record_history: !a.no_history,
        persist_report: true,
        seed: None,
        events,
        run_id: None,
    };
    let report = match (&a.scenario, &a.folder) {
        (Some(s), _) => {
            let sc = app.find_scenario(&ws.meta.id, s)?;
            app.run_scenario(&sc.meta.id, settings, cancel).await?
        }
        (None, Some(f)) => {
            let folder = app.find_folder(&ws.meta.id, f)?;
            app.run_folder(&ws.meta.id, folder, settings, cancel).await?
        }
        (None, None) => bail!("give --scenario or --folder"),
    };
    print_report(&report);
    if let Some(p) = &a.json {
        write_out(p, &anvil_runner::to_json(&report), "JSON")?;
    }
    if let Some(p) = &a.junit {
        write_out(p, &anvil_runner::to_junit(&report), "JUnit")?;
    }
    if let Some(p) = &a.html {
        write_out(p, &anvil_runner::to_html(&report), "HTML")?;
    }
    Ok(exit_code(&report))
}

pub fn scenario_cmd(app: &App, cmd: &ScenarioCmd) -> Result<i32> {
    match cmd {
        ScenarioCmd::Create {
            workspace,
            name,
            steps,
            iterations,
            stop_on_failure,
            delay_ms,
            dataset,
            dataset_format: fmt,
            sensitive_columns,
        } => {
            let ws = app.find_workspace(workspace)?;
            let mut out = Vec::new();
            for (i, key) in steps.iter().enumerate() {
                let r = app.find_request(&ws.meta.id, key)?;
                out.push(ScenarioStep { request_id: r.meta.id, enabled: true, delay_ms: if i == 0 { 0 } else { *delay_ms } });
            }
            let mut sc = app.create_scenario(&ws.meta.id, name, out)?;
            sc.iterations = iterations.unwrap_or(0);
            sc.stop_on_failure = *stop_on_failure;
            if let Some(p) = dataset {
                let format = dataset_format(p, *fmt)?;
                let bytes = read_dataset_file(p)?;
                let d = app.create_dataset(&ws.meta.id, &file_name(p), format, &bytes, sensitive_columns.clone())?;
                sc.dataset_id = Some(d.meta.id);
            } else if !sensitive_columns.is_empty() {
                bail!("--sensitive-column needs --dataset");
            }
            let sc = app.update_scenario(sc)?;
            println!("{}", sc.meta.id);
            Ok(0)
        }
        ScenarioCmd::List { workspace } => {
            let ws = app.find_workspace(workspace)?;
            for s in app.scenarios(&ws.meta.id)? {
                println!("{}  {}  {} step(s)  {}", s.meta.id, if s.trusted { "trusted  " } else { "UNTRUSTED" }, s.steps.len(), s.name);
            }
            Ok(0)
        }
        ScenarioCmd::Show { workspace, scenario } => {
            let ws = app.find_workspace(workspace)?;
            let s = app.find_scenario(&ws.meta.id, scenario)?;
            println!("{}  ({})", s.name, s.meta.id);
            if !s.trusted {
                println!("  UNTRUSTED: imported or not yet reviewed. Review the steps, then `anvil scenario trust`.");
            }
            println!(
                "  iterations: {} · stop on failure: {}",
                if s.iterations == 0 { "auto (dataset rows, else 1)".to_string() } else { s.iterations.to_string() },
                s.stop_on_failure
            );
            if let Some(d) = s.dataset_id {
                match app.dataset(&d) {
                    Ok(d) => println!("  dataset: {} ({:?}; sensitive columns: {})", d.name, d.format, d.sensitive_columns.join(", ")),
                    Err(_) => println!("  dataset: {d} (missing)"),
                }
            }
            for (i, st) in s.steps.iter().enumerate() {
                let desc = match app.request(&st.request_id) {
                    Ok(r) => format!("{} {} {}", r.name, r.spec.method, r.spec.url),
                    Err(_) => format!("missing request {}", st.request_id),
                };
                println!(
                    "  {:>2}. {desc}{}{}",
                    i + 1,
                    if st.enabled { "" } else { "  (disabled)" },
                    if st.delay_ms > 0 { format!("  (wait {} ms)", st.delay_ms) } else { String::new() }
                );
            }
            let runs: Vec<RunReport> = app
                .run_reports(&ws.meta.id)?
                .into_iter()
                .filter(|r| matches!(&r.source, anvil_domain::runner::RunSource::Scenario { scenario_id, .. } if *scenario_id == s.meta.id))
                .take(5)
                .collect();
            for r in runs {
                println!(
                    "  run {} {}: {:?}, {} passed / {} failed steps",
                    r.started_at.format("%Y-%m-%d %H:%M:%S"),
                    r.run_id,
                    r.completion,
                    r.totals.steps_passed,
                    r.totals.steps_failed + r.totals.steps_errored
                );
            }
            Ok(0)
        }
        ScenarioCmd::Trust { workspace, scenario } => {
            let ws = app.find_workspace(workspace)?;
            let s = app.find_scenario(&ws.meta.id, scenario)?;
            app.trust_scenario(&s.meta.id)?;
            println!("scenario '{}' is now trusted", s.name);
            Ok(0)
        }
    }
}
