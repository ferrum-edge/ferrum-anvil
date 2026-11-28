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
    // Pin every destination directory and verify none is a symlink, directory,
    // or alias before staging anything.
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
    let mut pinned_dests: Vec<(&str, &Path, anvil_app::file_grants::PinnedOutput)> = Vec::with_capacity(destinations.len());
    for (label, p) in &destinations {
        refuse_symlink(label, p)?;
        if let Ok(meta) = std::fs::symlink_metadata(p)
            && meta.is_dir()
        {
            bail!("{label} ({}) is a directory; nothing was written", p.display());
        }
        let pinned = anvil_app::file_grants::PinnedOutput::open(p).with_context(|| format!("preparing {label} ({})", p.display()))?;
        pinned_dests.push((label, p, pinned));
    }
    for i in 0..pinned_dests.len() {
        let (a, pa, pin_a) = &pinned_dests[i];
        for (b, pb, pin_b) in &pinned_dests[i + 1..] {
            if destination_key(pa) == destination_key(pb) || pin_a.aliases_output(pin_b)? {
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
    // Stage every output inside its pinned directory before publishing any
    // destination so a staging error leaves nothing behind.
    let report_json = report_file.map(|_| json_safe(&serde_json::to_string_pretty(&export.report).unwrap_or_default()) + "\n");
    let find_pinned =
        |label: &str| pinned_dests.iter().find(|(l, _, _)| *l == label).map(|(_, p, pin)| (*p, pin)).expect("destination was pinned above");
    let dataset_reliable_id = if export.dataset_csv.is_some() {
        let (p, pin) = find_pinned("the dataset file");
        let reliable =
            pin.supports_reliable_identity().with_context(|| format!("checking filesystem identity support for {}", p.display()))?;
        if force && !reliable {
            anyhow::bail!(
                "cannot safely replace an existing dataset file ({}) on a filesystem without reliable file identity or atomic exclusive rename; nothing was written",
                p.display()
            );
        }
        reliable
    } else {
        false
    };
    let mut staged: Vec<(&str, &Path, anvil_app::file_grants::StagedPinnedOutput<'_>, bool)> = Vec::with_capacity(4);
    if let (Some(_), Some(props)) = (secrets_file, &export.secrets_properties) {
        let (p, pin) = find_pinned("--secrets-file");
        staged.push((
            "--secrets-file",
            p,
            pin.stage(props.as_bytes(), true).with_context(|| format!("staging --secrets-file ({})", p.display()))?,
            true,
        ));
    }
    if let Some(csv) = &export.dataset_csv {
        let (p, pin) = find_pinned("the dataset file");
        staged.push((
            "the dataset file",
            p,
            pin.stage_owned(csv, sensitive_dataset).with_context(|| format!("staging the dataset file ({})", p.display()))?,
            !force,
        ));
    }
    {
        let (p, pin) = find_pinned("--out");
        staged.push((
            "--out",
            p,
            pin.stage(export.jmx.as_bytes(), false).with_context(|| format!("staging --out ({})", p.display()))?,
            false,
        ));
    }
    if let (Some(_), Some(json)) = (report_file, &report_json) {
        let (p, pin) = find_pinned("--report");
        staged.push((
            "--report",
            p,
            pin.stage(json.as_bytes(), false).with_context(|| format!("staging --report ({})", p.display()))?,
            false,
        ));
    }
    // Serialize concurrent exports that publish a dataset sidecar alongside
    // the plan in the same directory so two `--force` runs can never leave one
    // export's JMX paired with the other's dataset. Protect the lock file's OS
    // identity so no filesystem-equivalent spelling or link can overwrite it.
    let mut protected: Vec<anvil_app::file_grants::PinnedFileId> = Vec::new();
    let _dir_lock = if export.dataset_csv.is_some() {
        let (_, out_pin) = find_pinned("--out");
        let (lock, lock_id) = out_pin.lock_dir().with_context(|| format!("locking export directory for {}", out.display()))?;
        protected.push(lock_id);
        Some(lock)
    } else {
        None
    };
    // Publish no-clobber sidecars first, then the plan and optional report,
    // tracking every published OS file identity so Unicode-normalization
    // aliases (e.g. APFS NFC/NFD) can never replace a newly written sibling.
    // Back up any pre-existing dataset sidecar before overwriting it, keep the
    // staged dataset handle open through JMX settlement, and verify the live
    // object before committing the JMX or deleting a quarantined entry.
    let mut published: Vec<String> = Vec::new();
    let mut dataset_backup: Option<anvil_app::file_grants::PinnedBackup<'_>> = None;
    let mut dataset_published_note: Option<String> = None;
    let mut dataset_live_handle: Option<std::fs::File> = None;
    for (label, dest, item, no_clobber) in staged {
        let note = format!("{label} ({})", dest.display());
        if label == "the dataset file" && !no_clobber {
            let (_, ds_pin) = find_pinned("the dataset file");
            match ds_pin.backup_existing_regular_guarded(&protected) {
                Ok(backup) => dataset_backup = backup,
                Err(err) => {
                    let err = anyhow::Error::new(err).context(format!("backing up {label} ({})", dest.display()));
                    if published.is_empty() {
                        return Err(err.context("nothing was written"));
                    }
                    return Err(err.context(format!("already written: {}", published.join(", "))));
                }
            }
        }
        if label == "--out" && dataset_published_note.is_some() && dataset_reliable_id {
            let (ds_path, ds_pin) = find_pinned("the dataset file");
            let still_owned = dataset_live_handle.as_ref().is_some_and(|h| ds_pin.verify_live_entry(h).unwrap_or(false));
            if !still_owned {
                drop(item);
                drop(dataset_live_handle);
                let mut recovery = String::new();
                if let Some(backup) = dataset_backup.take()
                    && let Some(name) = backup.preserve()
                {
                    let backup_path = ds_path.parent().map(|p| p.join(&name)).unwrap_or_else(|| PathBuf::from(&name));
                    recovery = format!("; previous dataset backup preserved at {}", backup_path.display());
                }
                return Err(anyhow::anyhow!(
                    "published dataset entry changed concurrently before publishing {label} ({}) (already written: {}{recovery})",
                    dest.display(),
                    published.join(", ")
                ));
            }
        }
        let effective_no_clobber = if label == "the dataset file" {
            // If backup moved the original aside (or no original existed),
            // publish with no-clobber so a file installed in the vacated slot
            // is never overwritten.
            no_clobber || dataset_backup.as_ref().is_none_or(|b| b.is_moved())
        } else {
            no_clobber
        };
        let pub_res = if label == "the dataset file" {
            item.publish_guarded_owned(effective_no_clobber, &protected)
        } else {
            item.publish_guarded(effective_no_clobber, &protected).map(|id| (id, None))
        };
        match pub_res {
            Ok((id, live_opt)) => {
                if label == "the dataset file" {
                    if let Some(backup) = dataset_backup.as_mut() {
                        backup.mark_replaced();
                    }
                    dataset_published_note = Some(note.clone());
                    dataset_live_handle = live_opt;
                } else if label == "--out" {
                    if let Some(backup) = dataset_backup.take() {
                        backup.discard();
                    }
                    drop(dataset_live_handle.take());
                }
                protected.push(id);
                published.push(note);
            }
            Err(err) => {
                let mut recovery = String::new();
                if err.published {
                    if label == "the dataset file" {
                        if let Some(backup) = dataset_backup.as_mut() {
                            backup.mark_replaced();
                        }
                        // Post-publish identity verification failed, so ownership
                        // cannot be established; preserve any backup instead of
                        // modifying the dataset entry.
                        if let Some(backup) = dataset_backup.take()
                            && let Some(name) = backup.preserve()
                        {
                            let backup_path = dest.parent().map(|p| p.join(&name)).unwrap_or_else(|| PathBuf::from(&name));
                            recovery = format!("; previous dataset backup preserved at {}", backup_path.display());
                        }
                    } else if label == "--out" {
                        if let Some(backup) = dataset_backup.take() {
                            // JMX already landed; keep the paired replacement dataset
                            // and discard the backup.
                            backup.discard();
                        }
                        drop(dataset_live_handle.take());
                    }
                    published.push(note);
                } else if label == "--out"
                    && let Some(ds_note) = dataset_published_note.take()
                {
                    let (ds_path, ds_pin) = find_pinned("the dataset file");
                    if let Some(live_handle) = dataset_live_handle.take() {
                        match ds_pin.rollback_owned(live_handle, dataset_backup.take()) {
                            anvil_app::file_grants::PinnedRollback::Restored => {
                                published.retain(|p| p != &ds_note);
                            }
                            anvil_app::file_grants::PinnedRollback::Skipped { backup_name, quarantine_left } => {
                                if let Some(name) = backup_name {
                                    let backup_path = ds_path.parent().map(|p| p.join(&name)).unwrap_or_else(|| PathBuf::from(&name));
                                    recovery.push_str(&format!(
                                        "; dataset entry changed concurrently so rollback was skipped, previous dataset backup preserved at {}",
                                        backup_path.display()
                                    ));
                                }
                                if let Some((q_name, q_err)) = quarantine_left {
                                    let q_path = ds_path.parent().map(|p| p.join(&q_name)).unwrap_or_else(|| PathBuf::from(&q_name));
                                    recovery.push_str(&format!(
                                        "; concurrent dataset entry could not be returned from quarantine ({q_err}), preserved at {}",
                                        q_path.display()
                                    ));
                                }
                            }
                            anvil_app::file_grants::PinnedRollback::Failed { backup_name, err: restore_err } => {
                                let backup_path =
                                    ds_path.parent().map(|p| p.join(&backup_name)).unwrap_or_else(|| PathBuf::from(&backup_name));
                                recovery = format!(
                                    "; dataset rollback failed ({restore_err}), previous dataset backup preserved at {}",
                                    backup_path.display()
                                );
                            }
                        }
                    } else if let Some(backup) = dataset_backup.take()
                        && let Some(name) = backup.preserve()
                    {
                        let backup_path = ds_path.parent().map(|p| p.join(&name)).unwrap_or_else(|| PathBuf::from(&name));
                        recovery = format!(
                            "; published dataset ownership could not be verified against the live staged file so rollback was skipped, previous dataset backup preserved at {}",
                            backup_path.display()
                        );
                    }
                } else if label == "the dataset file"
                    && let Some(backup) = dataset_backup.take()
                    && let Err((name, restore_err)) = backup.abort()
                {
                    let backup_path = dest.parent().map(|p| p.join(&name)).unwrap_or_else(|| PathBuf::from(&name));
                    recovery = format!(
                        "; could not restore or safely discard dataset backup ({restore_err}), previous dataset backup preserved at {}",
                        backup_path.display()
                    );
                }
                let err = anyhow::Error::new(err).context(format!("publishing {label} ({})", dest.display()));
                if published.is_empty() && recovery.is_empty() {
                    return Err(err.context("nothing was written"));
                }
                if published.is_empty() {
                    return Err(err.context(format!("nothing was written{recovery}")));
                }
                return Err(err.context(format!("already written: {}{recovery}", published.join(", "))));
            }
        }
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
    // When the exported plan carries a relative sidecar CSV dataset, launch
    // JMeter from the JMX's absolute directory (in a subshell on POSIX so
    // CDPATH cannot interfere, or a guarded Set-Location try/finally block on
    // PowerShell without any `\\?\` verbatim prefix). On Windows, invoke
    // `java` with `ApacheJMeter.jar` directly so `jmeter.bat` never re-parses
    // filenames through `cmd.exe`.
    let abs_out = std::path::absolute(out).unwrap_or_else(|_| out.to_path_buf());
    let strip_win_verbatim = |p: &Path| -> String {
        let s = p.display().to_string();
        if cfg!(windows) {
            if let Some(unc) = s.strip_prefix(r"\\?\UNC\") {
                return format!(r"\\{unc}");
            }
            if let Some(plain) = s.strip_prefix(r"\\?\") {
                return plain.to_string();
            }
        }
        s
    };
    let jmeter_bin = if cfg!(windows) {
        "& java -jar $(if ($env:JMETER_HOME) { Join-Path $env:JMETER_HOME 'bin\\ApacheJMeter.jar' } else { Join-Path (Split-Path -Parent (Get-Command jmeter -ErrorAction Stop).Source) 'ApacheJMeter.jar' })"
    } else {
        "jmeter"
    };
    let (jmx_arg, prefix, suffix, import_results_file, secrets_placeholder) = if r.dataset.is_some() {
        let raw_dir = abs_out.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
        let canon_dir = std::fs::canonicalize(raw_dir).unwrap_or_else(|_| raw_dir.to_path_buf());
        let dir_str = strip_win_verbatim(&canon_dir);
        let name = abs_out.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| abs_out.display().to_string());
        let import_path = strip_win_verbatim(&canon_dir.join(&results_file));
        if cfg!(windows) {
            (
                name,
                format!("$__p = Get-Location; try {{ Set-Location -LiteralPath {} -ErrorAction Stop; ", shell_quote(&dir_str)),
                " } finally { Set-Location -LiteralPath $__p.Path }".to_string(),
                import_path,
                "<absolute path to the --secrets-file you chose>",
            )
        } else {
            (
                name,
                format!("(cd -- {} && ", shell_quote(&dir_str)),
                ")".to_string(),
                import_path,
                "<absolute path to the --secrets-file you chose>",
            )
        }
    } else {
        (strip_win_verbatim(out), String::new(), String::new(), results_file.clone(), "<the --secrets-file you chose>")
    };
    let mut cmd = format!("{prefix}{jmeter_bin} -n -t {} -l {}", shell_quote(&jmx_arg), shell_quote(&results_file));
    if written {
        cmd.push_str(&format!(" -q {}", shell_quote(secrets_placeholder)));
    }
    for (k, v) in &r.jmeter_properties {
        cmd.push_str(&format!(" {}", shell_quote(&format!("-J{k}={v}"))));
    }
    cmd.push_str(&suffix);
    println!("  run ({shell_label}): {cmd}");
    println!("  then: anvil load import-jtl <workspace> --file {} --plan {}", shell_quote(&import_results_file), plan.id);
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
        if let Some((p, pinned)) = out {
            if let Ok(m) = std::fs::symlink_metadata(p)
                && m.is_dir()
            {
                bail!("{label} ({}) is a directory; nothing was imported", p.display());
            }
            if pinned.aliases_file(&file, &meta, a.file)? {
                bail!(
                    "{label} ({}) resolves to the same path as --file ({}); refusing to overwrite the source JTL. Nothing was imported",
                    p.display(),
                    a.file.display()
                );
            }
        }
    }
    if let (Some((jp, j)), Some((_, h))) = (&json_out, &html_out)
        && j.aliases_output(h)?
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
    // Parse and stage optional output files BEFORE persisting the load report
    // so output-directory or staging errors fail cleanly without saving a
    // duplicate report; if final publication fails after save, report the saved
    // run_id so callers do not re-import blindly.
    let report = app.parse_jtl(&a.ws, file, opts)?;
    let staged_json = match &json_out {
        Some((p, pinned)) => Some((
            *p,
            pinned
                .stage(anvil_load::report::to_json(&report).as_bytes(), false)
                .with_context(|| format!("staging --json ({}); nothing was imported", p.display()))?,
        )),
        None => None,
    };
    let staged_html = match &html_out {
        Some((p, pinned)) => Some((
            *p,
            pinned
                .stage(anvil_load::html::to_html(&report).as_bytes(), false)
                .with_context(|| format!("staging --html ({}); nothing was imported", p.display()))?,
        )),
        None => None,
    };
    app.save_load_report(&report)?;
    let mut protected = vec![source_id];
    if let Some((p, staged)) = staged_json {
        let json_id = staged.publish_guarded(false, &protected).map_err(anyhow::Error::new).with_context(|| {
            format!("writing --json ({}); load report {} was already saved in the workspace", p.display(), report.run_id)
        })?;
        protected.push(json_id);
    }
    if let Some((p, staged)) = staged_html {
        staged.publish_guarded(false, &protected).map_err(anyhow::Error::new).with_context(|| {
            format!("writing --html ({}); load report {} was already saved in the workspace", p.display(), report.run_id)
        })?;
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
