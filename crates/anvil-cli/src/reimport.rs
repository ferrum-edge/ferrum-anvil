//! `anvil reimport-spec`: reimport a changed spec or collection file into the
//! import it came from, through the same reviewed plan/apply path as the
//! desktop (`App::spec_reimport_review`, then
//! `App::prepare_spec_reimport_reviewed` and
//! `App::apply_prepared_spec_reimport`).
//!
//! What changed only in the source is updated. A request or configuration
//! unit edited here that changed in the source too (a conflict), and what the
//! source no longer has, are kept unless named with `--overwrite…` or
//! `--delete…`. `--dry-run` prints the plan and its `plan_sha256`; an apply
//! needs `--plan-sha256` (refused unless the reimport still plans exactly
//! that) or `--yes`. Nothing is sent or run. Exit codes: 0 done or planned ·
//! 3 refused or local error (nothing written).

use crate::specs_load::read_spec_source;
use anvil_app::App;
use anvil_app::specs::SpecSourceRecord;
use anvil_contract::{json_safe, terminal_safe as t};
use anvil_domain::Id;
use anvil_domain::workspace::Workspace;
use anvil_import::{ReimportApproval, ReimportChange, ReimportPlan, ScopeChange};
use anyhow::{Result, anyhow, bail};
use clap::Args;
use std::collections::HashMap;
use std::fmt::Write as _;
use std::path::PathBuf;

/// Entries listed per kind of change in the text output before the rest is
/// counted; conflicts and removals, which take decisions, are always listed.
const LIST_LIMIT: usize = 200;

#[derive(Args)]
pub struct ReimportSpecArgs {
    /// The workspace the import is in (id or name).
    workspace: String,
    /// The new version of the source; `-` reads stdin.
    #[arg(long)]
    file: PathBuf,
    /// The import to update: its id (`import-spec` prints it; an earlier id of
    /// the same import works too). Needed when the workspace has more than one.
    #[arg(long = "import", value_name = "IMPORT_ID")]
    import: Option<String>,
    /// Print what would change and the plan's `plan_sha256`, and stop.
    #[arg(long)]
    dry_run: bool,
    /// Apply only if the reimport still plans exactly what the dry run with
    /// this `plan_sha256` showed (the file and the stored import unchanged).
    #[arg(long = "plan-sha256", value_name = "SHA256")]
    plan_sha256: Option<String>,
    /// Apply the plan this run computes, without a reviewed `plan_sha256`.
    #[arg(long, conflicts_with = "dry_run")]
    yes: bool,
    /// Replace your edits to this request with the source's version (a
    /// request id the plan lists as edited here and in the source; repeatable).
    #[arg(long = "overwrite", value_name = "REQUEST_ID")]
    overwrite: Vec<String>,
    /// Delete this request the source no longer has (a request id the plan
    /// lists as no longer in the source; repeatable).
    #[arg(long = "delete", value_name = "REQUEST_ID")]
    delete: Vec<String>,
    /// Replace your edits to this configuration unit (a key the plan lists as
    /// edited here and in the source; repeatable).
    #[arg(long = "overwrite-scope", value_name = "KEY")]
    overwrite_scope: Vec<String>,
    /// Delete this configuration unit the source no longer has (a key the
    /// plan lists; repeatable).
    #[arg(long = "delete-scope", value_name = "KEY")]
    delete_scope: Vec<String>,
    /// Every request and configuration unit edited here and in the source
    /// takes the source's version.
    #[arg(long, conflicts_with_all = ["overwrite", "overwrite_scope"])]
    overwrite_all: bool,
    /// Everything the source no longer has is deleted.
    #[arg(long, conflicts_with_all = ["delete", "delete_scope"])]
    delete_all: bool,
    /// Print the plan (and, after applying, the result) as JSON.
    #[arg(long)]
    json: bool,
}

pub fn reimport_spec(app: &App, a: &ReimportSpecArgs) -> Result<i32> {
    let ws = app.find_workspace(&a.workspace)?;
    let rec = pick_import(app, &ws, a.import.as_deref())?;
    let import_id = rec.source.import_id;
    let (bytes, file_name) = read_spec_source(&a.file)?;
    let review = app.spec_reimport_review(&import_id, &bytes)?;
    let decisions = decisions_for(&review.plan, a)?;
    if let Some(want) = &a.plan_sha256
        && !want.trim().eq_ignore_ascii_case(&review.binding.plan_sha256)
    {
        bail!(
            "the reimport no longer plans what was reviewed (its plan_sha256 is {}): the file or the stored import changed since; nothing was changed, run --dry-run again",
            review.binding.plan_sha256
        );
    }
    let names: HashMap<Id, String> = app.requests(&ws.meta.id)?.into_iter().map(|q| (q.meta.id, q.name)).collect();
    let plan = &review.plan;
    if a.dry_run {
        if a.json {
            let out = serde_json::json!({
                "workspace_id": ws.meta.id,
                "import_id": import_id,
                "file_name": file_name,
                "source_sha256": review.binding.source_sha256,
                "plan_sha256": review.binding.plan_sha256,
                "plan": plan_json(plan, &names),
                "decisions": decisions,
            });
            println!("{}", json_safe(&serde_json::to_string_pretty(&out)?));
        } else {
            print!("{}", plan_text(&ws, &rec, &file_name, plan, &names, &decisions));
            println!("plan_sha256: {}", review.binding.plan_sha256);
        }
        return Ok(0);
    }
    if !a.yes && a.plan_sha256.is_none() {
        bail!(
            "nothing was changed: review the plan with --dry-run, then apply it with --plan-sha256 <the digest it prints> (or --yes to apply the plan this run computes)"
        );
    }
    let prepared = app.prepare_spec_reimport_reviewed(&import_id, bytes, file_name.clone(), &review.binding)?;
    let requests = app.apply_prepared_spec_reimport(prepared, &decisions)?;
    if a.json {
        let out = serde_json::json!({
            "workspace_id": ws.meta.id,
            "import_id": plan.import_id,
            "previous_import_id": import_id,
            "file_name": file_name,
            "plan_sha256": review.binding.plan_sha256,
            "requests": requests,
            "plan": plan_json(plan, &names),
            "decisions": decisions,
        });
        println!("{}", json_safe(&serde_json::to_string_pretty(&out)?));
    } else {
        print!("{}", plan_text(&ws, &rec, &file_name, plan, &names, &decisions));
        println!(
            "reimported {} into workspace '{}' (import {}, was {}): the import has {requests} request(s) now; nothing was sent",
            t(&file_name),
            t(&ws.name),
            plan.import_id,
            import_id
        );
    }
    Ok(0)
}

/// The import of `ws` that `wanted` names (its current id or an earlier one),
/// or its only import.
fn pick_import(app: &App, ws: &Workspace, wanted: Option<&str>) -> Result<SpecSourceRecord> {
    let mut all = app.spec_sources(&ws.meta.id)?;
    all.sort_by_key(|r| r.source.imported_at);
    let listing = |all: &[SpecSourceRecord]| {
        all.iter()
            .map(|r| format!("\n  {}  {}  {}", r.source.import_id, t(&r.file_name), t(r.source.title.as_deref().unwrap_or(""))))
            .collect::<String>()
    };
    if let Some(raw) = wanted {
        let id: Id = raw.trim().parse().map_err(|_| anyhow!("--import takes an import id: '{}'", t(raw)))?;
        let found = all.iter().position(|r| r.source.import_id == id || r.previous_import_ids.contains(&id));
        return match found {
            Some(i) => Ok(all.swap_remove(i)),
            None => bail!("workspace '{}' has no import {id}; its imports:{}", t(&ws.name), listing(&all)),
        };
    }
    match all.len() {
        0 => bail!("workspace '{}' has no imported spec or collection; `anvil import-spec` imports one", t(&ws.name)),
        1 => Ok(all.remove(0)),
        n => bail!("workspace '{}' has {n} imports; name the one to update with --import:{}", t(&ws.name), listing(&all)),
    }
}

/// The decisions the flags ask for, each checked against the plan: an id or
/// key the plan does not offer for that decision is refused, not ignored.
fn decisions_for(plan: &ReimportPlan, a: &ReimportSpecArgs) -> Result<ReimportApproval> {
    let conflicts: Vec<Id> = plan.conflicts.iter().map(|c| c.existing_id).collect();
    let removed: Vec<Id> = plan.removed.iter().map(|r| r.existing_id).collect();
    let scope_conflicts: Vec<String> = plan.scope_conflicts.iter().map(|c| c.key.clone()).collect();
    let scope_removed: Vec<String> = plan.scope_removed.iter().map(|c| c.key.clone()).collect();
    let ids = |given: &[String], all: bool, offered: &[Id], flag: &str, what: &str| -> Result<Vec<Id>> {
        if all {
            return Ok(offered.to_vec());
        }
        let mut out = Vec::new();
        for raw in given {
            let id: Id = raw.trim().parse().map_err(|_| anyhow!("{flag} takes a request id: '{}'", t(raw)))?;
            if !offered.contains(&id) {
                bail!("{flag} {id}: the plan does not list that request as {what}; nothing was changed (--dry-run lists them)");
            }
            if !out.contains(&id) {
                out.push(id);
            }
        }
        Ok(out)
    };
    let keys = |given: &[String], all: bool, offered: &[String], flag: &str, what: &str| -> Result<Vec<String>> {
        if all {
            return Ok(offered.to_vec());
        }
        let mut out: Vec<String> = Vec::new();
        for key in given {
            if !offered.contains(key) {
                bail!(
                    "{flag} '{}': the plan does not list that configuration as {what}; nothing was changed (--dry-run lists them)",
                    t(key)
                );
            }
            if !out.contains(key) {
                out.push(key.clone());
            }
        }
        Ok(out)
    };
    const CONFLICT: &str = "edited here and in the source";
    const GONE: &str = "no longer in the source";
    Ok(ReimportApproval {
        overwrite: ids(&a.overwrite, a.overwrite_all, &conflicts, "--overwrite", CONFLICT)?,
        delete: ids(&a.delete, a.delete_all, &removed, "--delete", GONE)?,
        overwrite_scope: keys(&a.overwrite_scope, a.overwrite_all, &scope_conflicts, "--overwrite-scope", CONFLICT)?,
        delete_scope: keys(&a.delete_scope, a.delete_all, &scope_removed, "--delete-scope", GONE)?,
    })
}

/// The plan for `--json`: what changes and what the decisions apply to, by
/// id, operation key and name. Generated request contents and configuration
/// values (which can hold credentials) are left out.
fn plan_json(p: &ReimportPlan, names: &HashMap<Id, String>) -> serde_json::Value {
    let name = |id: &Id, fallback: &str| names.get(id).cloned().unwrap_or_else(|| fallback.to_string());
    let change = |c: &ReimportChange| {
        serde_json::json!({
            "request_id": c.existing_id,
            "operation_key": c.operation_key,
            "name": name(&c.existing_id, &c.fresh.name),
            "user_edited": c.user_edited,
            "changed_fields": c.changed_fields,
            "upstream_fields": c.upstream_fields,
            "conflicting_fields": c.conflicting_fields,
        })
    };
    let scope = |c: &ScopeChange| serde_json::json!({ "key": c.key, "label": c.label, "user_edited": c.user_edited, "whole_environment": c.whole_environment });
    serde_json::json!({
        "added": p.added.iter().map(|q| serde_json::json!({
            "request_id": q.meta.id,
            "operation_key": q.spec.source.as_ref().map(|s| s.operation_key.clone()),
            "method": q.spec.method,
            "name": q.name,
        })).collect::<Vec<_>>(),
        "updated": p.updated.iter().map(change).collect::<Vec<_>>(),
        "conflicts": p.conflicts.iter().map(change).collect::<Vec<_>>(),
        "removed": p.removed.iter().map(|r| serde_json::json!({
            "request_id": r.existing_id,
            "operation_key": r.operation_key,
            "name": name(&r.existing_id, &r.operation_key),
            "user_edited": r.user_edited,
        })).collect::<Vec<_>>(),
        "preserved_edits": p.preserved_edits,
        "unchanged": p.unchanged.len(),
        "unlinked": p.unlinked.len(),
        "scope_updated": p.scope_updated.iter().map(scope).collect::<Vec<_>>(),
        "scope_conflicts": p.scope_conflicts.iter().map(scope).collect::<Vec<_>>(),
        "scope_preserved_edits": p.scope_preserved_edits,
        "scope_removed": p.scope_removed.iter().map(scope).collect::<Vec<_>>(),
    })
}

/// The plan for the terminal. Everything from the source or the workspace
/// goes through `terminal_safe`. `[x]` marks a conflict or removal the
/// decisions apply to.
fn plan_text(
    ws: &Workspace,
    rec: &SpecSourceRecord,
    file_name: &str,
    p: &ReimportPlan,
    names: &HashMap<Id, String>,
    d: &ReimportApproval,
) -> String {
    let name = |id: &Id, fallback: &str| t(names.get(id).map_or(fallback, String::as_str));
    let mark = |on: bool| if on { "[x]" } else { "[ ]" };
    let fields = |f: &[String]| f.iter().map(|x| if x == "spec" { "request".to_string() } else { t(x) }).collect::<Vec<_>>().join(", ");
    let mut s = String::new();
    let title = rec.source.title.as_deref().unwrap_or(&rec.file_name);
    let _ = writeln!(
        s,
        "reimport of '{}' (import {}, last from {}) in workspace '{}' from {}:",
        t(title),
        rec.source.import_id,
        t(&rec.file_name),
        t(&ws.name),
        t(file_name)
    );
    let _ = writeln!(s, "  new requests: {}", p.added.len());
    for q in p.added.iter().take(LIST_LIMIT) {
        let _ = writeln!(s, "    + {} {}", t(&q.spec.method), t(&q.name));
    }
    more(&mut s, p.added.len());
    let _ = writeln!(s, "  updated (not edited here): {}", p.updated.len());
    for c in p.updated.iter().take(LIST_LIMIT) {
        let f = if c.upstream_fields.is_empty() { &c.changed_fields } else { &c.upstream_fields };
        let _ = writeln!(s, "    ~ {}  ({})", name(&c.existing_id, &c.fresh.name), fields(f));
    }
    more(&mut s, p.updated.len());
    if !p.conflicts.is_empty() {
        let _ = writeln!(s, "  edited here and in the source: {} (kept as you left them unless --overwrite)", p.conflicts.len());
        for c in &p.conflicts {
            let f = if c.conflicting_fields.is_empty() { &c.changed_fields } else { &c.conflicting_fields };
            let on = d.overwrite.contains(&c.existing_id);
            let _ = writeln!(s, "    {} {}  {}  both changed: {}", mark(on), c.existing_id, name(&c.existing_id, &c.fresh.name), fields(f));
        }
    }
    if !p.removed.is_empty() {
        let _ = writeln!(s, "  no longer in the source: {} (kept unless --delete)", p.removed.len());
        for r in &p.removed {
            let edited = if r.user_edited { "  (edited here)" } else { "" };
            let on = d.delete.contains(&r.existing_id);
            let _ = writeln!(s, "    {} {}  {}{edited}", mark(on), r.existing_id, name(&r.existing_id, &r.operation_key));
        }
    }
    if !p.scope_updated.is_empty() {
        let _ = writeln!(s, "  configuration updated: {}", p.scope_updated.len());
        for c in p.scope_updated.iter().take(LIST_LIMIT) {
            let _ = writeln!(s, "    ~ {}", t(&c.label));
        }
        more(&mut s, p.scope_updated.len());
    }
    if !p.scope_conflicts.is_empty() {
        let _ = writeln!(s, "  configuration edited here and in the source: {} (kept unless --overwrite-scope)", p.scope_conflicts.len());
        for c in &p.scope_conflicts {
            let _ = writeln!(s, "    {} {}  {}", mark(d.overwrite_scope.contains(&c.key)), t(&c.key), t(&c.label));
        }
    }
    if !p.scope_removed.is_empty() {
        let _ = writeln!(s, "  configuration no longer in the source: {} (kept unless --delete-scope)", p.scope_removed.len());
        for c in &p.scope_removed {
            let edited = if c.user_edited { "  (edited here)" } else { "" };
            let _ = writeln!(s, "    {} {}  {}{edited}", mark(d.delete_scope.contains(&c.key)), t(&c.key), t(&c.label));
        }
    }
    let _ = writeln!(
        s,
        "  unchanged: {} · your edits kept: {} · not from the import: {}",
        p.unchanged.len(),
        p.preserved_edits.len() + p.scope_preserved_edits.len(),
        p.unlinked.len()
    );
    s
}

fn more(s: &mut String, total: usize) {
    if total > LIST_LIMIT {
        let _ = writeln!(s, "    … and {} more", total - LIST_LIMIT);
    }
}
