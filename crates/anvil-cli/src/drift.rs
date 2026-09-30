//! `anvil spec-drift`: compare observed traffic with an OpenAPI
//! description and suggest revisions.
//!
//! Two sources: a HAR capture (`--har`, with the spec file; no profile
//! needed) or the history of an imported spec's collection (`--import`,
//! opens the profile). Exit codes: 0 no finding at or above `--fail-on` ·
//! 2 findings at or above it · 3 local error.

use crate::lint::FailOn;
use anvil_app::App;
use anvil_contract::drift::SuggestionKind;
use anvil_contract::{DriftOptions, DriftReport, Spec, terminal_safe as t};
use anvil_domain::Id;
use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, ValueEnum};
use std::io::Read;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, ValueEnum)]
pub enum Format {
    Text,
    Json,
}

#[derive(Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum Apply {
    /// Additions only (the suggestions marked recommended).
    Recommended,
    /// Additions and relaxations.
    All,
}

#[derive(Args)]
pub struct SpecDriftArgs {
    /// The OpenAPI/Swagger description (with `--har`); `-` reads stdin.
    #[arg(required_unless_present = "import", conflicts_with = "import")]
    spec: Option<PathBuf>,
    /// A HAR 1.2 capture of the traffic (browser dev tools, a proxy).
    #[arg(long, requires = "spec")]
    har: Option<PathBuf>,
    /// Instead: an imported spec (its import id, see the desktop's Contract
    /// view or `--json` of `import-spec`) and its collection's history.
    #[arg(long, conflicts_with = "har")]
    import: Option<String>,
    /// Newest history records read (with `--import`).
    #[arg(long, default_value_t = 500)]
    limit: usize,
    #[arg(long, value_enum, default_value = "text")]
    format: Format,
    /// Write the description revised with the chosen suggestions here (in
    /// the description's syntax; YAML is written anew, without comments).
    #[arg(long, value_name = "FILE")]
    revised: Option<PathBuf>,
    /// Write the chosen suggestions as an RFC 6902 JSON Patch here.
    #[arg(long, value_name = "FILE")]
    patch: Option<PathBuf>,
    /// Which suggestions go into --revised and --patch.
    #[arg(long, value_enum, default_value = "recommended")]
    apply: Apply,
    /// Exit with 2 when a finding is at least this severe.
    #[arg(long, value_enum, default_value = "error")]
    fail_on: FailOn,
}

impl SpecDriftArgs {
    pub fn needs_profile(&self) -> bool {
        self.import.is_some()
    }
}

fn read(path: &Path, what: &str, max: u64) -> Result<Vec<u8>> {
    let mut v = Vec::new();
    if path.as_os_str() == "-" {
        std::io::stdin().take(max + 1).read_to_end(&mut v)?;
    } else {
        std::fs::File::open(path).with_context(|| format!("cannot read {what} {}", path.display()))?.take(max + 1).read_to_end(&mut v)?;
    }
    if v.len() as u64 > max {
        bail!("{what} {} is larger than {max} bytes", path.display());
    }
    Ok(v)
}

/// HAR mode: no profile.
pub fn spec_drift_files(a: &SpecDriftArgs) -> Result<i32> {
    let spec_path = a.spec.as_ref().ok_or_else(|| anyhow!("a spec file is required"))?;
    let har_path = a.har.as_ref().ok_or_else(|| anyhow!("pass the traffic with --har FILE, or use --import for history"))?;
    let spec = Spec::parse(&read(spec_path, "spec", 32 << 20)?).map_err(|e| anyhow!("{}: {}", spec_path.display(), t(&e.to_string())))?;
    let obs = anvil_contract::observe::from_har(&read(har_path, "HAR file", anvil_contract::observe::MAX_HAR_BYTES as u64)?)
        .map_err(|e| anyhow!("{}: {}", har_path.display(), t(&e)))?;
    let report = anvil_contract::analyze(&spec, &obs, &DriftOptions::default());
    finish(a, &spec, &report, &spec_path.display().to_string())
}

/// History mode: an import of the open profile.
pub fn spec_drift_import(app: &App, a: &SpecDriftArgs) -> Result<i32> {
    let id: Id = a.import.as_deref().unwrap_or_default().parse().map_err(|_| anyhow!("--import takes an import id"))?;
    let report = app.drift_report(&id, a.limit)?;
    let bytes = app.spec_original(&id)?;
    let spec = Spec::parse(&bytes).map_err(|e| anyhow!("{e}"))?;
    let name = app.spec_source_any(&id)?.file_name;
    finish(a, &spec, &report, &name)
}

fn finish(a: &SpecDriftArgs, spec: &Spec, report: &DriftReport, name: &str) -> Result<i32> {
    let chosen: Vec<String> = report.suggestions.iter().filter(|s| a.apply == Apply::All || s.recommended).map(|s| s.id.clone()).collect();
    if a.revised.is_some() || a.patch.is_some() {
        let rev = anvil_contract::revise(spec, report, &chosen);
        if let Some(p) = &a.revised {
            std::fs::write(p, &rev.text).with_context(|| format!("cannot write {}", p.display()))?;
            eprintln!("wrote the revised description to {} ({} suggestion(s) applied)", p.display(), rev.applied.len());
        }
        if let Some(p) = &a.patch {
            std::fs::write(p, anvil_contract::json_safe(&serde_json::to_string_pretty(&rev.json_patch)?) + "\n")
                .with_context(|| format!("cannot write {}", p.display()))?;
            eprintln!("wrote {} JSON Patch operation(s) to {}", rev.json_patch.len(), p.display());
        }
    }
    match a.format {
        Format::Json => println!("{}", anvil_contract::json_safe(&serde_json::to_string_pretty(report)?)),
        Format::Text => print!("{}", text(report, name, &chosen)),
    }
    let threshold = a.fail_on.threshold();
    Ok(if threshold.is_some_and(|t| report.findings.iter().any(|f| f.severity >= t)) { 2 } else { 0 })
}

fn text(r: &DriftReport, name: &str, chosen: &[String]) -> String {
    let mut s = String::new();
    // Everything from the spec or the traffic goes through `terminal_safe`.
    let name = t(name);
    let title = t(r.spec.title.as_deref().unwrap_or("untitled"));
    s.push_str(&format!(
        "{name} — {title} ({}) · {} exchange(s), {} matched, {} without response, {} ignored\n\n",
        r.spec.dialect, r.observations, r.matched, r.without_response, r.ignored
    ));
    if r.findings.is_empty() {
        s.push_str("No drift: every exchange matches the description.\n\n");
    }
    for f in &r.findings {
        s.push_str(&format!("{:<5} ×{:<3} {}\n", f.severity.label(), f.count, t(&f.message)));
        for id in &f.suggestions {
            if let Some(sug) = r.suggestions.iter().find(|x| &x.id == id) {
                s.push_str(&format!("            → {} {}\n", sug.id, t(&sug.title)));
            }
        }
    }
    let called = r.operations.iter().filter(|o| o.calls > 0).count();
    s.push_str(&format!("\ncoverage: {called} of {} operation(s) called\n", r.operations.len()));
    for o in &r.operations {
        let statuses = o.statuses.iter().map(|(k, v)| format!("{k}×{v}")).collect::<Vec<_>>().join(" ");
        let p95 = o.latency_ms.map(|l| format!("p95 {:.0} ms", l.p95)).unwrap_or_default();
        s.push_str(&format!("  {:<40} {:>4} call(s)  {statuses}  {p95}\n", t(&o.operation), o.calls));
    }
    if !r.undeclared.is_empty() {
        s.push_str("\nnot in the description:\n");
        for u in &r.undeclared {
            s.push_str(&format!("  {} {}  {} call(s)\n", t(&u.method), t(&u.path), u.calls));
        }
    }
    if !r.suggestions.is_empty() {
        s.push_str("\nsuggestions ([x] = used by --revised/--patch):\n");
        for sug in &r.suggestions {
            let mark = if chosen.contains(&sug.id) { "x" } else { " " };
            let kind = match sug.kind {
                SuggestionKind::Addition => "",
                SuggestionKind::Relaxation => " (relaxation)",
            };
            s.push_str(&format!("  [{mark}] {} {}{kind}\n", sug.id, t(&sug.title)));
        }
    }
    for n in &r.notes {
        s.push_str(&format!("note: {}\n", t(n)));
    }
    s
}
