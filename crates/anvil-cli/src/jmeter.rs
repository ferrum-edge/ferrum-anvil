//! `anvil load export-jmx` and `anvil load import-jtl` (the Apache JMeter
//! adapter, LOAD-012).

use anvil_app::App;
use anvil_contract::{json_safe, terminal_safe as t};
use anvil_domain::Id;
use anvil_domain::load::LoadPlan;
use anvil_jmeter::{ExportOptions, JtlLimits, JtlOptions};
use anyhow::{Context, Result, anyhow, bail};
use std::path::{Path, PathBuf};

/// The dataset CSV written next to `out`: `<stem>.dataset.csv`.
pub fn dataset_path(out: &Path) -> PathBuf {
    let stem = out.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_else(|| "plan".into());
    out.with_file_name(format!("{stem}.dataset.csv"))
}

/// Create `path` for secret material: owner-only (0600) and never over an
/// existing file or link. Unix only: elsewhere no owner-only file can be
/// created here, so secret output is refused (see [`secret_output_supported`]).
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("creating {} (it must not exist yet)", path.display()))?;
        f.write_all(bytes)?;
        f.sync_all()?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = bytes;
        bail!("{}: secret output is written only where an owner-only file can be created (macOS and Linux)", path.display())
    }
}

/// Whether this platform writes owner-only secret files (on Windows a new
/// file inherits its folder's access list, which may let others read it).
pub fn secret_output_supported() -> bool {
    cfg!(unix)
}

/// A destination as a comparable path: its folder resolved (links
/// followed), case folded where file systems usually ignore case.
fn destination_key(p: &Path) -> PathBuf {
    let abs = std::path::absolute(p).unwrap_or_else(|_| p.to_path_buf());
    let parent = abs.parent().map(|d| std::fs::canonicalize(d).unwrap_or_else(|_| d.to_path_buf()));
    let joined = match (parent, abs.file_name()) {
        (Some(d), Some(n)) => d.join(n),
        _ => abs,
    };
    if cfg!(any(windows, target_os = "macos")) { PathBuf::from(joined.to_string_lossy().to_lowercase()) } else { joined }
}

/// `s` quoted for the shell a user runs the printed command in.
pub fn shell_quote(s: &str) -> String {
    if !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || "_./:-+=@%,".contains(c)) {
        return s.to_string();
    }
    if cfg!(windows) { format!("\"{}\"", s.replace('"', "\\\"")) } else { format!("'{}'", s.replace('\'', "'\\''")) }
}

/// Export `plan` to `out` (and its dataset next to it). Exit code 3 when
/// the plan is refused; nothing is written then. An existing dataset file
/// beside `out` is replaced only with `force`.
pub fn export_jmx(
    app: &App,
    plan: &LoadPlan,
    out: &Path,
    secrets_file: Option<&Path>,
    report_file: Option<&Path>,
    force: bool,
) -> Result<i32> {
    if secrets_file.is_some() && !secret_output_supported() {
        bail!(
            "--secrets-file is refused on this platform: a new file inherits its folder's access list here, so the secrets could be readable by others. Export without it and set the properties another way"
        );
    }
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
    let sensitive_dataset = export.report.dataset.as_ref().is_some_and(|d| !d.sensitive_columns.is_empty());
    if sensitive_dataset && !secret_output_supported() {
        bail!("the dataset has sensitive columns, and an owner-only file cannot be created on this platform; nothing was written");
    }
    // Every destination is distinct, checked before anything is written.
    let mut destinations: Vec<(&str, &Path)> = vec![("--out", out)];
    if export.dataset_csv.is_some() {
        destinations.push(("the dataset file", dataset.as_path()));
    }
    if let Some(p) = secrets_file {
        destinations.push(("--secrets-file", p));
    }
    if let Some(p) = report_file {
        destinations.push(("--report", p));
    }
    for (i, (a, pa)) in destinations.iter().enumerate() {
        for (b, pb) in &destinations[i + 1..] {
            if destination_key(pa) == destination_key(pb) {
                bail!("{a} and {b} name the same file; nothing was written");
            }
        }
    }
    if export.dataset_csv.is_some() && dataset.exists() && !force {
        bail!(
            "{} already exists beside the plan; pass --force to replace it, or choose another --out. Nothing was written",
            dataset.display()
        );
    }
    if let Some(p) = secrets_file
        && p.exists()
    {
        bail!("the secrets file already exists; it is never written over an existing file. Nothing was written");
    }
    std::fs::write(out, &export.jmx).with_context(|| format!("writing {}", out.display()))?;
    if let Some(csv) = &export.dataset_csv {
        if sensitive_dataset {
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
    let needed = r.secret_properties.len();
    let written = r.secrets_written;
    if needed > 0 {
        // Names and purposes are in the test plan and the --report file.
        if written {
            println!("  {needed} JMeter propert(ies) for secrets: written to the --secrets-file (owner-only); delete it after the run");
        } else {
            println!(
                "  {needed} JMeter propert(ies) for secrets are required (see --report or the test plan's setUp check); without them the plan stops before any traffic"
            );
        }
    }
    let mut cmd = format!("jmeter -n -t {} -l results.jtl", shell_quote(&out.display().to_string()));
    if written {
        cmd.push_str(" -q <the --secrets-file you chose>");
    }
    for (k, v) in &r.jmeter_properties {
        cmd.push_str(&format!(" {}", shell_quote(&format!("-J{k}={v}"))));
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
