//! Standalone, offline HTML run summary.
//!
//! * Inline CSS only — no scripts, stylesheets, fonts, images or any other
//!   external request; an embedded Content-Security-Policy (`default-src
//!   'none'`) makes a viewer block them even if something slipped through.
//! * Every dynamic value (names, URLs, summaries, assertion values, finding
//!   titles, notes — several are response-derived and therefore untrusted)
//!   goes through [`esc`], shared with the load report.
//! * Iterations are `<details>` elements (no JavaScript); failed iterations
//!   start open.

use anvil_domain::runner::*;
use anvil_load::html::{esc, fmt_n};
use std::fmt::Write as _;

const CSS: &str = r#"
:root{color-scheme:light dark;--page:#f9f9f7;--surface:#fcfcfb;--text:#0b0b0b;--muted:#52514e;--border:rgba(11,11,11,.12);--pass:#0a7f0a;--fail:#c42b2b;--skip:#8a6d00;--info:#2a68b8}
@media (prefers-color-scheme:dark){:root{--page:#0d0d0d;--surface:#1a1a19;--text:#f4f4f2;--muted:#b8b7ae;--border:rgba(255,255,255,.14);--pass:#3cc15a;--fail:#ff6b6b;--skip:#e0b43a;--info:#6aa5f0}}
*{box-sizing:border-box}
body{margin:0;background:var(--page);color:var(--text);font:14px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:1100px;margin:0 auto;padding:24px 16px 48px}
h1{font-size:22px;margin:0 0 4px;font-weight:600}
h2{font-size:16px;margin:28px 0 8px;font-weight:600}
.sub{color:var(--muted);margin:0}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px;word-break:break-all}
.banner{border-left:4px solid var(--fail);background:var(--surface);border-radius:6px;padding:10px 14px;margin:14px 0}
.banner.warn{border-left-color:var(--skip)}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px;margin:16px 0}
.tile{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:10px 12px}
.tile .label{color:var(--muted);font-size:12px}
.tile .value{font-size:20px;font-weight:600}
details{background:var(--surface);border:1px solid var(--border);border-radius:8px;margin:10px 0;padding:6px 12px}
summary{cursor:pointer;font-weight:600;padding:4px 0}
.table-wrap{overflow-x:auto}
table{border-collapse:collapse;width:100%;margin:8px 0}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--border);vertical-align:top}
th{color:var(--muted);font-weight:600;font-size:12px}
.st{font-weight:600;white-space:nowrap}
.passed{color:var(--pass)}.failed,.error{color:var(--fail)}.skipped,.canceled,.incomplete{color:var(--skip)}
ul.plain{margin:4px 0;padding-left:18px}
footer{color:var(--muted);font-size:12px;margin-top:32px}
"#;

fn step_status(s: RunStepStatus) -> (&'static str, &'static str) {
    match s {
        RunStepStatus::Passed => ("passed", "passed"),
        RunStepStatus::Failed => ("failed", "failed"),
        RunStepStatus::Error => ("error", "not sent"),
        RunStepStatus::Skipped => ("skipped", "skipped"),
        RunStepStatus::Canceled => ("canceled", "canceled"),
    }
}

fn iter_status(s: RunIterationStatus) -> &'static str {
    match s {
        RunIterationStatus::Passed => "passed",
        RunIterationStatus::Failed => "failed",
        RunIterationStatus::Incomplete => "incomplete",
    }
}

fn snake<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_value(v).ok().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default()
}

fn tile(out: &mut String, label: &str, value: String) {
    let _ = write!(out, "<div class=\"tile\"><div class=\"label\">{}</div><div class=\"value\">{}</div></div>", esc(label), esc(&value));
}

/// Render the report as a standalone HTML document.
pub fn to_html(r: &RunReport) -> String {
    let t = &r.totals;
    let mut o = String::with_capacity(16 * 1024);
    o.push_str("<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">");
    o.push_str("<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; form-action 'none'; base-uri 'none'\">");
    o.push_str("<meta name=\"referrer\" content=\"no-referrer\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">");
    let _ = write!(o, "<title>{}</title><style>{CSS}</style></head><body><main>", esc(&format!("Anvil run — {}", r.name)));

    let source = match &r.source {
        RunSource::Scenario { .. } => "Scenario".to_string(),
        RunSource::Folder { path, .. } => format!("Folder {path}"),
    };
    let _ = write!(o, "<h1>{}</h1>", esc(&r.name));
    let _ = write!(
        o,
        "<p class=\"sub\">{} · {} · started {} · {} ms · <span class=\"st {}\">{}</span></p>",
        esc(&source),
        esc(r.environment_name.as_deref().map(|e| format!("environment {e}")).as_deref().unwrap_or("no environment")),
        esc(&r.started_at.format("%Y-%m-%d %H:%M:%S UTC").to_string()),
        fmt_n(r.duration_ms),
        if r.passed() { "passed" } else { "failed" },
        esc(&if r.passed() { "passed".to_string() } else { format!("{} · not passed", snake(&r.completion)) })
    );

    if r.completion != RunnerCompletion::Completed {
        let why = match r.completion {
            RunnerCompletion::Canceled => {
                "The run was canceled. This report is partial: only the iterations and steps shown were run.".to_string()
            }
            _ => format!(
                "The run was aborted{}. This report is partial.",
                r.abort_reason.as_deref().map(|a| format!(": {a}")).unwrap_or_default()
            ),
        };
        let _ = write!(o, "<div class=\"banner\"><strong>Partial report.</strong> {}</div>", esc(&why));
    }
    if let RunSource::Scenario { untrusted_override: true, .. } = &r.source {
        o.push_str(
            "<div class=\"banner warn\"><strong>Untrusted scenario.</strong> It ran only because this run explicitly allowed it.</div>",
        );
    }

    o.push_str("<div class=\"tiles\">");
    tile(&mut o, "Iterations passed", format!("{} / {}", fmt_n(t.iterations_passed as u64), fmt_n(t.iterations_planned as u64)));
    tile(&mut o, "Iterations failed", fmt_n(t.iterations_failed as u64));
    tile(&mut o, "Steps passed", fmt_n(t.steps_passed));
    tile(&mut o, "Steps failed", fmt_n(t.steps_failed));
    tile(&mut o, "Not sent (error)", fmt_n(t.steps_errored));
    tile(&mut o, "Skipped / canceled", fmt_n(t.steps_skipped + t.steps_canceled + t.steps_canceled_in_flight));
    tile(&mut o, "Transport failures", fmt_n(t.transport_failures));
    tile(&mut o, "Application failures", fmt_n(t.application_failures));
    tile(&mut o, "Assertion failures", fmt_n(t.assertion_failures));
    o.push_str("</div>");
    let _ = write!(
        o,
        "<p class=\"sub\">A step fails on: {}. Transport, application and assertion results are separate dimensions; a step can fail on more than one.</p>",
        esc(&[("transport", r.fail_on.transport), ("application status", r.fail_on.application), ("assertions", r.fail_on.assertions)]
            .iter()
            .filter(|(_, on)| *on)
            .map(|(n, _)| *n)
            .collect::<Vec<_>>()
            .join(", "))
    );
    if let Some(d) = &r.dataset {
        let _ = write!(
            o,
            "<p class=\"sub\">Dataset {} ({}, {} rows, columns: {}{}) · sha256 <span class=\"mono\">{}</span></p>",
            esc(&d.name),
            esc(&snake(&d.format)),
            fmt_n(d.rows as u64),
            esc(&d.columns.join(", ")),
            if d.sensitive_columns.is_empty() { String::new() } else { format!("; sensitive: {}", esc(&d.sensitive_columns.join(", "))) },
            esc(&d.sha256)
        );
    }

    if !r.notes.is_empty() {
        o.push_str("<h2>Notes</h2><ul class=\"plain\">");
        for n in &r.notes {
            let _ = write!(o, "<li>{}</li>", esc(n));
        }
        o.push_str("</ul>");
    }

    o.push_str("<h2>Iterations</h2>");
    for it in &r.iterations {
        let open = it.status != RunIterationStatus::Passed || r.iterations.len() == 1;
        let row = it.dataset_row.map(|x| format!(" · dataset row {x}")).unwrap_or_default();
        let _ = write!(
            o,
            "<details{}><summary>Iteration {}{} — <span class=\"st {}\">{}</span> · {} ms</summary>",
            if open { " open" } else { "" },
            it.index + 1,
            esc(&row),
            iter_status(it.status),
            iter_status(it.status),
            fmt_n(it.duration_ms)
        );
        o.push_str("<div class=\"table-wrap\"><table><thead><tr><th>#</th><th>Request</th><th>Status</th><th>Transport</th><th>Application</th><th>Assertions</th><th>HTTP</th><th>Time</th><th>Details</th></tr></thead><tbody>");
        for s in &it.steps {
            let (cls, label) = step_status(s.status);
            let name = if s.name.is_empty() { s.request_id.to_string() } else { s.name.clone() };
            let _ = write!(o, "<tr><td>{}</td><td>{}", s.index + 1, esc(&name));
            if !s.url.is_empty() {
                let _ = write!(o, "<div class=\"mono\">{} {}</div>", esc(&s.method), esc(&s.url));
            }
            let _ = write!(
                o,
                "</td><td class=\"st {cls}\">{label}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>",
                esc(&s.transport.map(|x| snake(&x)).unwrap_or_default()),
                esc(&s.application.map(|x| snake(&x)).unwrap_or_default()),
                esc(&s.assertions.map(|x| snake(&x)).unwrap_or_default()),
                s.http_status.map(|x| x.to_string()).unwrap_or_default(),
                s.duration_ms.map(|x| format!("{} ms", fmt_n(x))).unwrap_or_default()
            );
            if !s.summary.is_empty() {
                let _ = write!(o, "<div>{}</div>", esc(&s.summary));
            }
            if let Some(m) = &s.message {
                let _ = write!(o, "<div>{}</div>", esc(m));
            }
            let failed: Vec<_> = s.assertion_results.iter().filter(|a| !a.passed).collect();
            if !failed.is_empty() {
                o.push_str("<ul class=\"plain\">");
                for a in failed {
                    let _ = write!(o, "<li>✗ {} — {}</li>", esc(&a.label), esc(&a.message));
                }
                o.push_str("</ul>");
            }
            let passed = s.assertion_results.iter().filter(|a| a.passed).count();
            if passed > 0 {
                let _ = write!(o, "<div class=\"sub\">{passed} assertion(s) passed</div>");
            }
            if !s.findings.is_empty() {
                o.push_str("<ul class=\"plain\">");
                for f in &s.findings {
                    let _ = write!(
                        o,
                        "<li>{} <span class=\"sub\">[{}; {}]</span> <span class=\"mono\">{}</span></li>",
                        esc(&f.title),
                        esc(&snake(&f.confidence)),
                        esc(&snake(&f.severity)),
                        esc(&f.code)
                    );
                }
                o.push_str("</ul>");
            }
            if let Some(id) = s.execution_id {
                let _ = write!(o, "<div class=\"sub mono\">record {}</div>", esc(&id.to_string()));
            }
            o.push_str("</td></tr>");
        }
        o.push_str("</tbody></table></div>");
        if it.steps_omitted > 0 {
            let _ = write!(o, "<p class=\"sub\">{} step summaries omitted by the report size bound.</p>", fmt_n(it.steps_omitted as u64));
        }
        o.push_str("</details>");
    }
    if r.iterations.is_empty() {
        o.push_str("<p class=\"sub\">No iteration started.</p>");
    }

    let _ = write!(
        o,
        "<footer>Run {} · {} · report v{} · Generated offline by Ferrum Anvil. Values are redacted; response bodies are not included. This page contains no scripts and makes no network requests.</footer>",
        esc(&r.run_id.to_string()),
        esc(&r.runner_version),
        r.report_version
    );
    o.push_str("</main></body></html>\n");
    o
}
