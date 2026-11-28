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

/// A temporary file staged beside its final destination, ready to publish
/// atomically once every output has been staged without error.
struct StagedFile<'a> {
    label: &'a str,
    dest: &'a Path,
    tmp: PathBuf,
    no_clobber: bool,
}

impl Drop for StagedFile<'_> {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.tmp);
    }
}

/// Stage `bytes` into a new temporary file beside `dest`, writing and syncing
/// before any destination is published.
fn stage_file<'a>(label: &'a str, dest: &'a Path, bytes: &[u8], owner_only: bool, no_clobber: bool) -> Result<StagedFile<'a>> {
    if owner_only && !secret_output_supported() {
        bail!("{}: secret output is written only where an owner-only file can be created (macOS and Linux)", dest.display());
    }
    let parent = dest.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
    let tmp_name = format!(".anvil-{}.partial", Id::new());
    let tmp = parent.join(tmp_name);
    let write_tmp = || -> Result<()> {
        use std::io::Write;
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        if owner_only {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp).with_context(|| format!("staging {label} ({})", dest.display()))?;
        f.write_all(bytes)?;
        f.sync_all()?;
        Ok(())
    };
    if let Err(e) = write_tmp() {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(StagedFile { label, dest, tmp, no_clobber })
}

impl StagedFile<'_> {
    /// Publish the staged temp file atomically to `self.dest`:
    /// - `no_clobber == true`: `hard_link` + `remove_file`, failing with
    ///   `AlreadyExists` if `dest` (file, folder, or symlink, even dangling) exists.
    /// - `no_clobber == false`: `rename`, replacing `dest` atomically without
    ///   following a symlink or truncating an existing inode.
    fn publish(self) -> Result<()> {
        let res = if self.no_clobber {
            std::fs::hard_link(&self.tmp, self.dest).map(|()| {
                let _ = std::fs::remove_file(&self.tmp);
            })
        } else {
            std::fs::rename(&self.tmp, self.dest)
        };
        res.with_context(|| format!("publishing {} ({})", self.label, self.dest.display()))
    }
}

/// Whether this platform writes owner-only secret files (on Windows a new
/// file inherits its folder's access list, which may let others read it).
pub fn secret_output_supported() -> bool {
    cfg!(unix)
}

/// Refuse any destination that is already a symbolic link (target or dangling)
/// so CLI exports never follow links or silently alias another destination.
fn refuse_symlink(label: &str, p: &Path) -> Result<()> {
    if let Ok(meta) = std::fs::symlink_metadata(p)
        && meta.file_type().is_symlink()
    {
        bail!("{label} ({}) is a symbolic link; refusing to write through or replace a symlink. Nothing was written", p.display());
    }
    Ok(())
}

/// A destination as a comparable path: canonicalized when it exists, else its
/// canonicalized parent joined with its filename (case-folded on case-insensitive
/// filesystems).
fn destination_key(p: &Path) -> PathBuf {
    let resolved = std::fs::canonicalize(p).unwrap_or_else(|_| {
        let abs = std::path::absolute(p).unwrap_or_else(|_| p.to_path_buf());
        let parent = abs.parent().map(|d| std::fs::canonicalize(d).unwrap_or_else(|_| d.to_path_buf()));
        match (parent, abs.file_name()) {
            (Some(d), Some(n)) => d.join(n),
            _ => abs,
        }
    });
    if cfg!(any(windows, target_os = "macos")) { PathBuf::from(resolved.to_string_lossy().to_lowercase()) } else { resolved }
}

/// `s` quoted for POSIX `sh` (`'...'`, where no `$`, `` ` ``, or `\` expansion
/// occurs; embedded single quotes become `'\''`).
pub fn shell_quote_posix(s: &str) -> String {
    if !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || "_./:-+=@,".contains(c)) {
        return s.to_string();
    }
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// `s` quoted for Windows PowerShell (`'...'`, verbatim single-quoted string
/// where `$`, `` ` ``, and `"` are never expanded; ASCII and Unicode
/// typographic apostrophes PowerShell treats as single-quote delimiters are
/// doubled).
pub fn shell_quote_powershell(s: &str) -> String {
    if !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || "_./:-+=\\".contains(c)) {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for c in s.chars() {
        out.push(c);
        if matches!(c, '\'' | '\u{2018}' | '\u{2019}' | '\u{201a}' | '\u{201b}') {
            out.push(c);
        }
    }
    out.push('\'');
    out
}

/// `s` quoted for the current platform's labeled shell (PowerShell on Windows,
/// POSIX `sh` on macOS/Linux).
pub fn shell_quote(s: &str) -> String {
    if cfg!(windows) { shell_quote_powershell(s) } else { shell_quote_posix(s) }
}

/// A fresh result filename per export so repeated JMeter runs do not append
/// into the same JTL file. Uses a full UUIDv7 (timestamp + counter + random
/// bits) so exports never collide.
fn fresh_results_name(out: &Path) -> String {
    let stem: String = out
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "results".into())
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '-' })
        .take(32)
        .collect();
    let stem = if stem.is_empty() { "results" } else { stem.as_str() };
    let id = Id::new().to_string();
    format!("{stem}-results-{id}.jtl")
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
    for (label, p) in &destinations {
        refuse_symlink(label, p)?;
        if let Ok(meta) = std::fs::symlink_metadata(p)
            && meta.is_dir()
        {
            bail!("{label} ({}) is a directory; nothing was written", p.display());
        }
    }
    for (i, (a, pa)) in destinations.iter().enumerate() {
        for (b, pb) in &destinations[i + 1..] {
            if destination_key(pa) == destination_key(pb) {
                bail!("{a} and {b} name the same file; nothing was written");
            }
        }
    }
    if export.dataset_csv.is_some() && std::fs::symlink_metadata(&dataset).is_ok() && !force {
        bail!(
            "{} already exists beside the plan; pass --force to replace it, or choose another --out. Nothing was written",
            dataset.display()
        );
    }
    if let Some(p) = secrets_file
        && std::fs::symlink_metadata(p).is_ok()
    {
        bail!("the secrets file already exists; it is never written over an existing file. Nothing was written");
    }
    // Stage every output before publishing any destination so a staging error
    // (bad directory, permission error, disk full) leaves nothing behind.
    let report_json = report_file.map(|_| json_safe(&serde_json::to_string_pretty(&export.report).unwrap_or_default()) + "\n");
    let mut staged: Vec<StagedFile<'_>> = Vec::with_capacity(4);
    if let (Some(p), Some(props)) = (secrets_file, &export.secrets_properties) {
        staged.push(stage_file("--secrets-file", p, props.as_bytes(), true, true)?);
    }
    if let Some(csv) = &export.dataset_csv {
        staged.push(stage_file("the dataset file", &dataset, csv, sensitive_dataset, !force)?);
    }
    staged.push(stage_file("--out", out, export.jmx.as_bytes(), false, false)?);
    if let (Some(p), Some(json)) = (report_file, &report_json) {
        staged.push(stage_file("--report", p, json.as_bytes(), false, false)?);
    }
    // Publish no-clobber sidecars first, then the plan and optional report.
    // Remaining staged files are cleaned up on Drop if any publish fails.
    let mut published: Vec<String> = Vec::new();
    for item in staged {
        let note = format!("{} ({})", item.label, item.dest.display());
        if let Err(err) = item.publish() {
            if published.is_empty() {
                return Err(err.context("nothing was written"));
            }
            return Err(err.context(format!("already written: {}", published.join(", "))));
        }
        published.push(note);
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
    let has_secrets = !r.secret_properties.is_empty();
    let written = r.secrets_written;
    if has_secrets {
        // Names and purposes are in the test plan and the --report file.
        if written {
            println!("  JMeter secret properties written to the --secrets-file (owner-only); delete it after the run");
        } else {
            println!(
                "  JMeter secret properties are required (see --report or the test plan's setUp check); without them the plan stops before any traffic"
            );
        }
    }
    let results_file = fresh_results_name(out);
    let shell_label = if cfg!(windows) { "PowerShell" } else { "sh" };
    let mut cmd = format!("jmeter -n -t {} -l {}", shell_quote(&out.display().to_string()), shell_quote(&results_file));
    if written {
        cmd.push_str(&format!(" -q {}", shell_quote("<the --secrets-file you chose>")));
    }
    for (k, v) in &r.jmeter_properties {
        cmd.push_str(&format!(" {}", shell_quote(&format!("-J{k}={v}"))));
    }
    println!("  run ({shell_label}): {cmd}");
    println!("  then: anvil load import-jtl <workspace> --file {} --plan {}", shell_quote(&results_file), plan.id);
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
    let (file, meta) = anvil_app::file_grants::open_regular_file(a.file)
        .with_context(|| format!("opening {}", a.file.display()))?
        .ok_or_else(|| anyhow!("{} is not a regular file; nothing was imported", a.file.display()))?;
    // Pin output parent directories BEFORE import so retargeting a parent
    // symlink while parsing cannot redirect the final rename onto the source JTL.
    let json_out = match a.json {
        Some(p) => Some((p, anvil_app::file_grants::PinnedOutput::open(p).with_context(|| format!("preparing --json ({})", p.display()))?)),
        None => None,
    };
    let html_out = match a.html {
        Some(p) => Some((p, anvil_app::file_grants::PinnedOutput::open(p).with_context(|| format!("preparing --html ({})", p.display()))?)),
        None => None,
    };
    for (label, out) in [("--json", &json_out), ("--html", &html_out)] {
        if let Some((p, pinned)) = out
            && pinned.aliases_file(&file, &meta, a.file)?
        {
            bail!(
                "{label} ({}) resolves to the same path as --file ({}); refusing to overwrite the source JTL. Nothing was imported",
                p.display(),
                a.file.display()
            );
        }
    }
    if let (Some((jp, j)), Some((_, h))) = (&json_out, &html_out)
        && j.aliases_output(h)
    {
        bail!("--json and --html resolve to the same path ({}); nothing was imported", jp.display());
    }
    let opts = JtlOptions {
        workspace_id: a.ws,
        plan: a.plan,
        source_name: a.file.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "results.jtl".into()),
        jmeter_version: a.jmeter_version,
        warmup_secs: a.warmup,
        limits: JtlLimits::default(),
    };
    let source_id = anvil_app::file_grants::opened_file_id(&file, &meta).with_context(|| format!("inspecting {}", a.file.display()))?;
    let report = app.import_jtl(&a.ws, file, opts)?;
    let mut protected = vec![source_id];
    if let Some((p, pinned)) = &json_out {
        let json_id = pinned
            .write_atomic_guarded(anvil_load::report::to_json(&report).as_bytes(), &protected)
            .with_context(|| format!("writing --json ({})", p.display()))?;
        protected.push(json_id);
    }
    if let Some((p, pinned)) = &html_out {
        pinned
            .write_atomic_guarded(anvil_load::html::to_html(&report).as_bytes(), &protected)
            .with_context(|| format!("writing --html ({})", p.display()))?;
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
