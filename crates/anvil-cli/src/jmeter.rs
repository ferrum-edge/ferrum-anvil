//! `anvil load export-jmx` and `anvil load import-jtl` (the Apache JMeter
//! adapter, LOAD-012).

use anvil_app::App;
use anvil_contract::{json_safe, terminal_safe as t};
use anvil_domain::Id;
use anvil_domain::load::LoadPlan;
use anvil_jmeter::{ExportOptions, JtlLimits, JtlOptions};
use anyhow::{Context, Result, anyhow, bail};
use std::io::Write;
use std::path::{Path, PathBuf};

/// The dataset CSV written next to `out`: `<stem>.dataset.csv`.
pub fn dataset_path(out: &Path) -> PathBuf {
    let stem = out.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_else(|| "plan".into());
    out.with_file_name(format!("{stem}.dataset.csv"))
}

/// Create `path` for secret material: owner-only (0600 on Unix) and never
/// over an existing file or link.
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let mut f = o.open(path).with_context(|| format!("creating {} (it must not exist yet)", path.display()))?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}

/// Export `plan` to `out` (and its dataset next to it). Exit code 3 when
/// the plan is refused; nothing is written then.
pub fn export_jmx(app: &App, plan: &LoadPlan, out: &Path, secrets_file: Option<&Path>, report_file: Option<&Path>) -> Result<i32> {
    let dataset = dataset_path(out);
    let dataset_name = dataset.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "dataset.csv".into());
    let opts = ExportOptions { include_secrets: secrets_file.is_some(), dataset_file: dataset_name };
    let export = match app.load_export_jmx(plan, &opts)? {
        Ok(e) => e,
        Err(refused) => {
            eprintln!("refused: load plan '{}' cannot be exported to JMeter; nothing was written:", t(&plan.name));
            for r in &refused.reasons {
                match &r.request {
                    Some(q) => eprintln!("  - request '{}': {} ({})", t(q), t(&r.message), r.code),
                    None => eprintln!("  - {} ({})", t(&r.message), r.code),
                }
            }
            return Ok(3);
        }
    };
    if let Some(p) = secrets_file
        && p.exists()
    {
        bail!("{} already exists; the secrets file is never written over an existing file", p.display());
    }
    std::fs::write(out, &export.jmx).with_context(|| format!("writing {}", out.display()))?;
    if let Some(csv) = &export.dataset_csv {
        if export.report.dataset.as_ref().is_some_and(|d| !d.sensitive_columns.is_empty()) {
            let _ = std::fs::remove_file(&dataset);
            write_private(&dataset, csv)?;
        } else {
            std::fs::write(&dataset, csv).with_context(|| format!("writing {}", dataset.display()))?;
        }
    }
    if let (Some(p), Some(props)) = (secrets_file, &export.secrets_properties) {
        write_private(p, props.as_bytes())?;
    }
    if let Some(p) = report_file {
        std::fs::write(p, json_safe(&serde_json::to_string_pretty(&export.report)?) + "\n")
            .with_context(|| format!("writing {}", p.display()))?;
    }
    let r = &export.report;
    println!(
        "exported load plan {} to {} ({} thread group(s), Apache JMeter {})",
        t(&plan.name),
        out.display(),
        r.thread_groups,
        r.jmeter_version
    );
    if let Some(d) = &r.dataset {
        println!("  dataset: {} ({} rows), next to the plan", dataset.display(), d.rows);
    }
    for m in &r.mapping {
        println!("  {} → {}", t(&m.anvil), t(&m.jmeter));
    }
    for d in &r.differences {
        println!("  difference: {}", t(d));
    }
    if !r.secret_properties.is_empty() {
        match (secrets_file, r.secrets_written) {
            (Some(p), true) => println!("  secrets: written to {} (owner-only); delete it after the run", p.display()),
            _ => println!(
                "  secrets: not written; set these properties (for example in a file passed with -q), or the plan stops before any traffic:"
            ),
        }
        for s in &r.secret_properties {
            println!("    {}  ({})", s.name, t(&s.purpose));
        }
    }
    let mut cmd = format!("jmeter -n -t {} -l results.jtl", out.display());
    if let Some(p) = secrets_file.filter(|_| r.secrets_written) {
        cmd.push_str(&format!(" -q {}", p.display()));
    }
    for (k, v) in &r.jmeter_properties {
        cmd.push_str(&format!(" -J{k}={v}"));
    }
    println!("  run: {cmd}");
    println!("  then: anvil load import-jtl <workspace> --file results.jtl --plan {}", plan.id);
    Ok(0)
}

pub struct ImportArgs<'a> {
    pub ws: Id,
    pub file: &'a Path,
    pub plan: Option<LoadPlan>,
    pub jmeter_version: Option<String>,
    pub warmup: Option<u64>,
    pub json: Option<&'a Path>,
    pub html: Option<&'a Path>,
}

/// Import a JMeter result file as a saved load report.
pub fn import_jtl(app: &App, a: ImportArgs<'_>) -> Result<i32> {
    let (file, _) = anvil_app::file_grants::open_regular_file(a.file)
        .with_context(|| format!("opening {}", a.file.display()))?
        .ok_or_else(|| anyhow!("{} is not a regular file; nothing was imported", a.file.display()))?;
    let opts = JtlOptions {
        workspace_id: a.ws,
        plan: a.plan,
        source_name: a.file.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "results.jtl".into()),
        jmeter_version: a.jmeter_version,
        warmup_secs: a.warmup,
        limits: JtlLimits::default(),
    };
    let report = app.import_jtl(&a.ws, file, opts)?;
    if let Some(f) = a.json {
        std::fs::write(f, anvil_load::report::to_json(&report))?;
    }
    if let Some(f) = a.html {
        std::fs::write(f, anvil_load::html::to_html(&report))?;
    }
    let q = &report.requests;
    println!(
        "imported {} JMeter sample(s) as load report {} ({}): {} completed, {} transport failures, {} timeouts, {} application failures, {} assertion failures",
        q.started,
        report.run_id,
        t(&report.engine_version),
        q.completed,
        q.transport_failures,
        q.timeouts,
        q.application_failures,
        q.assertion_failures
    );
    for n in &report.notes {
        println!("  note: {}", t(n));
    }
    Ok(0)
}
