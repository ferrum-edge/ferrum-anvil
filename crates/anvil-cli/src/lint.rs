//! `anvil lint-spec`: check an OpenAPI description against API standards.
//!
//! Needs no profile: the spec and the rulesets are files, so it runs in CI.
//! Exit codes: 0 no finding at or above `--fail-on` · 2 findings at or
//! above it · 3 local error (unreadable file, invalid spec or ruleset).

use anvil_contract::{LintOptions, LintReport, RuleSet, Severity, Spec, terminal_safe as t};
use anyhow::{Context, Result, anyhow};
use clap::{Args, ValueEnum};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

const MAX_SPEC_BYTES: u64 = 32 * 1024 * 1024;

#[derive(Clone, Copy, ValueEnum)]
pub enum Format {
    Text,
    Json,
    Sarif,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum FailOn {
    Error,
    Warn,
    Info,
    Hint,
    Never,
}

impl FailOn {
    fn threshold(self) -> Option<Severity> {
        match self {
            FailOn::Error => Some(Severity::Error),
            FailOn::Warn => Some(Severity::Warn),
            FailOn::Info => Some(Severity::Info),
            FailOn::Hint => Some(Severity::Hint),
            FailOn::Never => None,
        }
    }
}

#[derive(Args)]
pub struct LintSpecArgs {
    /// OpenAPI 3.0/3.1/3.2 or Swagger 2.0 description (JSON or YAML); `-` reads stdin.
    #[arg(required_unless_present = "list_rules")]
    spec: Option<PathBuf>,
    /// A ruleset file (YAML or JSON). Repeat to layer rulesets in order
    /// (a company base, then a team overlay). Without one, Anvil's
    /// recommended rules apply.
    #[arg(long = "ruleset", value_name = "FILE")]
    rulesets: Vec<PathBuf>,
    #[arg(long, value_enum, default_value = "text")]
    format: Format,
    /// Write the report here instead of stdout.
    #[arg(long, value_name = "FILE")]
    output: Option<PathBuf>,
    /// Exit with 2 when a finding is at least this severe.
    #[arg(long, value_enum, default_value = "error")]
    fail_on: FailOn,
    /// Do not check examples against their schemas.
    #[arg(long)]
    no_examples: bool,
    /// Print the rules in effect and exit.
    #[arg(long)]
    list_rules: bool,
    /// Accept a description too large to lint completely (some operations
    /// left out, see `skipped_operations`) instead of exiting with 3.
    #[arg(long)]
    allow_incomplete: bool,
}

fn read_limited(path: &Path, what: &str) -> Result<Vec<u8>> {
    let mut v = Vec::new();
    if path.as_os_str() == "-" {
        std::io::stdin().take(MAX_SPEC_BYTES + 1).read_to_end(&mut v)?;
    } else {
        std::fs::File::open(path)
            .with_context(|| format!("cannot read {what} {}", path.display()))?
            .take(MAX_SPEC_BYTES + 1)
            .read_to_end(&mut v)?;
    }
    if v.len() as u64 > MAX_SPEC_BYTES {
        return Err(anyhow!("{what} {} is larger than {MAX_SPEC_BYTES} bytes", path.display()));
    }
    Ok(v)
}

pub fn lint_spec(a: &LintSpecArgs) -> Result<i32> {
    let rules = if a.rulesets.is_empty() {
        RuleSet::recommended()
    } else {
        let mut files = vec![];
        for p in &a.rulesets {
            let name = p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| p.display().to_string());
            files.push((name, read_limited(p, "ruleset")?));
        }
        RuleSet::load(&files).map_err(|e| anyhow!("{}", t(&e.to_string())))?
    };
    if a.list_rules {
        print_rules(&rules);
        return Ok(0);
    }
    let path = a.spec.as_ref().ok_or_else(|| anyhow!("a spec file is required"))?;
    let bytes = read_limited(path, "spec")?;
    let spec = Spec::parse(&bytes).map_err(|e| anyhow!("{}: {}", t(&path.display().to_string()), t(&e.to_string())))?;
    let report = anvil_contract::lint(&spec, &rules, &LintOptions { validate_examples: !a.no_examples, ..LintOptions::default() });
    let display_name = path.display().to_string();
    let out = match a.format {
        Format::Text => text(&report, &display_name, a.fail_on),
        Format::Json => anvil_contract::json_safe(&serde_json::to_string_pretty(&report)?) + "\n",
        Format::Sarif => {
            anvil_contract::json_safe(&serde_json::to_string_pretty(&anvil_contract::sarif::to_sarif(&report, &display_name))?) + "\n"
        }
    };
    match &a.output {
        Some(p) => {
            std::fs::write(p, out).with_context(|| format!("cannot write {}", p.display()))?;
            eprintln!("{}", summary(&report, a.fail_on));
        }
        None => std::io::stdout().write_all(out.as_bytes())?,
    }
    if report.skipped_operations > 0 && !a.allow_incomplete {
        eprintln!(
            "error: the description is too large to lint completely ({} operation(s) not checked); pass --allow-incomplete to accept that",
            report.skipped_operations
        );
        return Ok(3);
    }
    Ok(if report.passes(a.fail_on.threshold()) { 0 } else { 2 })
}

fn print_rules(rules: &RuleSet) {
    for s in &rules.sources {
        println!("# {}{} ({})", t(&s.name), s.version.as_ref().map(|v| format!(" {}", t(v))).unwrap_or_default(), t(&s.source));
    }
    for r in rules.list() {
        let formats = if r.formats.is_empty() { String::new() } else { format!(" [{}]", r.formats.join(", ")) };
        println!("{:<5}  {:<34} {:<16} {}{formats}", r.severity.label(), r.id, t(&r.given), t(&r.description.unwrap_or_default()));
    }
    for d in &rules.disabled {
        println!("off    {d}");
    }
}

fn summary(r: &LintReport, fail_on: FailOn) -> String {
    let c = &r.counts;
    let plural = |n: usize, w: &str| format!("{n} {w}{}", if n == 1 { "" } else { "s" });
    let verdict = if r.passes(fail_on.threshold()) { "passed" } else { "failed" };
    let threshold = match fail_on.threshold() {
        Some(s) => format!("fails on {}", s.label()),
        None => "never fails".into(),
    };
    format!(
        "{verdict}: {}, {}, {} info, {} ({threshold})",
        plural(c.error, "error"),
        plural(c.warn, "warning"),
        c.info,
        plural(c.hint, "hint")
    )
}

/// Everything from the spec or a ruleset goes through `terminal_safe`: a
/// newline in a message must not start a line a CI runner would read as a
/// workflow command, and escape sequences must not reach the terminal.
fn text(r: &LintReport, name: &str, fail_on: FailOn) -> String {
    let mut s = String::new();
    let name = t(name);
    let title = t(r.spec.title.as_deref().unwrap_or("untitled"));
    let version = r.spec.version.as_ref().map(|v| format!(" {}", t(v))).unwrap_or_default();
    s.push_str(&format!("{name} — {title}{version} ({}), {} operations\n", r.spec.dialect, r.spec.operations));
    let rulesets: Vec<String> = r
        .rulesets
        .iter()
        .map(|x| format!("{}{}", t(&x.name), x.version.as_ref().map(|v| format!(" {}", t(v))).unwrap_or_default()))
        .collect();
    s.push_str(&format!("rulesets: {} · {} rules run\n\n", rulesets.join(", "), r.rules_run));
    for f in &r.findings {
        let at = match (f.line, f.column) {
            (Some(l), Some(c)) => format!("{name}:{l}:{c}"),
            _ => format!("{name}#{}", t(&f.pointer)),
        };
        s.push_str(&format!("{at}  {}  {}\n    {}\n", f.severity.label(), f.rule, t(&f.message)));
        if let Some(h) = &f.how_to_fix {
            s.push_str(&format!("    fix: {}\n", t(h)));
        }
    }
    if r.dropped > 0 {
        s.push_str(&format!("… {} more findings not shown\n", r.dropped));
    }
    if r.examples_not_checked > 0 {
        s.push_str(&format!(
            "note: {} example(s) were not checked: their schema uses an external reference or an unsupported pattern, refers to itself, or expands too far\n",
            r.examples_not_checked
        ));
    }
    if r.skipped_operations > 0 {
        s.push_str(&format!(
            "note: the description is too large to lint completely: {} operation(s) were not checked\n",
            r.skipped_operations
        ));
    }
    if r.unresolved_ref_count > 0 {
        let first: Vec<String> = r.unresolved_refs.iter().take(5).map(|p| t(p)).collect();
        s.push_str(&format!(
            "note: {} $ref(s) could not be followed (external, dangling or cyclic); the objects behind them were not checked: {}{}\n",
            r.unresolved_ref_count,
            first.join(", "),
            if r.unresolved_ref_count > first.len() { ", …" } else { "" }
        ));
    }
    if !r.findings.is_empty() {
        s.push('\n');
    }
    s.push_str(&summary(r, fail_on));
    s.push('\n');
    s
}
