//! Export/import between the encrypted store and portable bundles.

use crate::linked_files::LinkedFileBinding;
use crate::workspace::attachment_index_id;
use crate::{App, AppError, Result};
use anvil_domain::Id;
use anvil_domain::execution::ExecutionRecord;
use anvil_domain::workspace::Workspace;
use anvil_portability::bundle::{self, BundleKind, ExportMode, ExportOptions, ExportPreview};
use anvil_portability::plan::{self, ConflictPolicy, Existing, ImportPlan};
use anvil_portability::validate::{self, UncarriedAttachment};
use anvil_portability::{PortableGraph, SecretValue};
use anvil_storage::{KdfParams, StoreRead, kind};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Serialize)]
pub struct ImportReport {
    pub plan: ImportPlan,
    pub warnings: Vec<String>,
    pub secrets_restored: bool,
    pub missing_secrets: Vec<String>,
    /// Linked local files the bundle's requests and datasets name
    /// (`request 'Upload': /path`). Each stays unused until the user
    /// chooses it on this device for that request or dataset.
    pub linked_files: Vec<String>,
    pub checkpoint: Option<String>,
    /// Workspace names as they will appear (or appear) after import.
    pub workspaces: Vec<String>,
    /// Ids of the imported workspaces (after any duplicate remap); empty for a preview.
    pub workspace_ids: Vec<String>,
    /// Whether the file is a full backup (restored) rather than a bundle.
    pub full_backup: bool,
    /// SHA-256 (lowercase hex) of the file as read. An approval given after
    /// the preview names it ([`ImportApproval::bundle_sha256`]), so it holds
    /// only for the file that was previewed.
    pub bundle_sha256: String,
}

/// What the user confirmed after reading an import preview.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ImportApproval {
    /// Workspaces stored here that the bundle claims (the preview's
    /// `plan.existing_workspaces`) and that the user agreed to write into.
    /// Any claimed workspace missing from this list refuses the import.
    #[serde(default)]
    pub existing_workspaces: Vec<Id>,
    /// The preview's `bundle_sha256`: the file this approval was given for.
    /// Required while `existing_workspaces` names any workspace; a file with
    /// any other digest is refused before anything is read from it.
    #[serde(default)]
    pub bundle_sha256: Option<String>,
}

impl ImportApproval {
    /// Approval to write the previewed `file` into `existing_workspaces`.
    pub fn for_file(file: &[u8], existing_workspaces: Vec<Id>) -> Self {
        ImportApproval { existing_workspaces, bundle_sha256: Some(file_sha256(file)) }
    }

    /// Refuse to apply `file` unless it is the file this approval was given
    /// for. An approval that names no workspace and no digest approves
    /// nothing, so it holds for any file.
    pub(crate) fn check_file(&self, file: &[u8], done: &str) -> Result<()> {
        match &self.bundle_sha256 {
            Some(d) if !d.eq_ignore_ascii_case(&file_sha256(file)) => Err(AppError::Invalid(format!(
                "the file is not the one that was previewed (it changed or was replaced since); nothing was {done}. Preview it again."
            ))),
            None if !self.existing_workspaces.is_empty() => Err(AppError::Invalid(format!(
                "an approval to write into an existing workspace must name the previewed file's bundle_sha256; nothing was {done}."
            ))),
            _ => Ok(()),
        }
    }
}

/// SHA-256 (lowercase hex) of an import file, as [`ImportReport::bundle_sha256`].
pub fn file_sha256(file: &[u8]) -> String {
    hex::encode(Sha256::digest(file))
}

impl App {
    /// Build the portable graph for one workspace (or all when `None`).
    pub fn graph(&self, ws: Option<&Id>, include_secrets: bool, include_history: bool) -> Result<PortableGraph> {
        let wss = match ws {
            Some(w) => vec![self.workspace(w)?],
            None => self.workspaces()?,
        };
        let mut g = PortableGraph::default();
        for w in &wss {
            let id = w.meta.id;
            g.folders.extend(self.folders(&id)?);
            let reqs = self.requests(&id)?;
            for r in &reqs {
                if let Some(rid) = r.revision_id
                    && let Ok(rev) = self.revision(&rid)
                    && rev.request_id == r.meta.id
                {
                    g.revisions.push(rev);
                }
            }
            g.requests.extend(reqs);
            g.environments.extend(self.environments(&id)?);
            g.tls_profiles.extend(self.tls_profiles(&id)?);
            g.proxy_profiles.extend(self.proxy_profiles(&id)?);
            g.integrations.extend(self.integrations(&id)?);
            g.datasets.extend(self.datasets(&id)?);
            g.scenarios.extend(self.scenarios(&id)?);
            if include_secrets {
                for sid in self.store.list_secret_ids(Some(&id))? {
                    if let Ok(parsed) = sid.parse::<Id>()
                        && let Some((label, value)) = self.store.get_secret(&parsed)?
                    {
                        g.secrets.insert(sid, SecretValue { label, value: value.to_string(), workspace_id: Some(id.to_string()) });
                    }
                }
            }
            if include_history {
                for h in self.store.list_history(Some(&id), None, 1000)? {
                    if let Some((rec, _)) = self.store.get_history::<serde_json::Value>(&h.id)? {
                        g.history.push(rec);
                    }
                }
            }
        }
        // A load plan travels with the requests, dataset and environment it
        // names. One that still names one deleted since is left out: an
        // import refuses a plan whose objects are not in the bundle.
        for w in &wss {
            let id = w.meta.id;
            let requests: HashSet<Id> = g.requests.iter().filter(|r| r.workspace_id == id).map(|r| r.meta.id).collect();
            let datasets: HashSet<Id> = g.datasets.iter().filter(|d| d.workspace_id == id).map(|d| d.meta.id).collect();
            let environments: HashSet<Id> = g.environments.iter().filter(|e| e.workspace_id == id).map(|e| e.meta.id).collect();
            for p in self.load_plans(&id)? {
                let runs = p.chain.iter().chain(p.mix.iter().map(|m| &m.request_id)).all(|r| requests.contains(r));
                let dataset = p.dataset_id.is_none_or(|d| datasets.contains(&d));
                let environment = p.environment_id.is_none_or(|e| environments.contains(&e));
                if runs && dataset && environment {
                    g.load_plans.push(p);
                }
            }
        }
        g.workspaces = wss;
        // Attachments referenced anywhere in the graph. One whose content
        // cannot be read here travels without it, and the export lists it
        // among its excluded items.
        let text = serde_json::to_string(&g.requests)? + &serde_json::to_string(&g.datasets)?;
        for cap in text.split("\"sha256\":\"").skip(1) {
            let sha: String = cap.chars().take(64).collect();
            if sha.len() == 64
                && let Some(b) = self.get_attachment(&sha)?
            {
                g.attachments.insert(sha, b);
            }
        }
        Ok(g)
    }

    /// What [`App::export`] would write. A full backup is not a bundle: see
    /// [`App::backup_preview`].
    pub fn export_preview(&self, ws: Option<&Id>, mode: ExportMode, include_history: bool) -> Result<ExportPreview> {
        refuse_full_backup(mode)?;
        let g = self.graph(ws, !matches!(mode, ExportMode::ShareSafely), include_history)?;
        let opts = ExportOptions {
            kind: BundleKind::Workspace,
            mode,
            passphrase: Some("preview-only-passphrase"),
            include_history,
            kdf: KdfParams::testing(),
            app_version: env!("CARGO_PKG_VERSION"),
        };
        Ok(bundle::preview(&g, &opts)?)
    }

    /// Write a bundle of one workspace, or of every workspace when `ws` is
    /// `None`. A full backup is not a bundle: see [`App::export_backup`].
    pub fn export(
        &self,
        ws: Option<&Id>,
        mode: ExportMode,
        passphrase: Option<&str>,
        include_history: bool,
    ) -> Result<(Vec<u8>, ExportPreview)> {
        refuse_full_backup(mode)?;
        let g = self.graph(ws, !matches!(mode, ExportMode::ShareSafely), include_history)?;
        let opts = ExportOptions {
            kind: BundleKind::Workspace,
            mode,
            passphrase,
            include_history,
            kdf: KdfParams::interactive(),
            app_version: env!("CARGO_PKG_VERSION"),
        };
        Ok(bundle::write(&g, &opts)?)
    }

    /// Dry run: validate and plan without mutating anything. Bundles that
    /// describe a full backup are refused; full backups are restored with
    /// [`App::restore`].
    pub fn import_preview(&self, bytes: &[u8], passphrase: Option<&str>, policy: ConflictPolicy) -> Result<ImportReport> {
        let bundle_sha256 = file_sha256(bytes);
        let opened = bundle::open(bytes, passphrase)?;
        let uncarried = validate::uncarried_attachments(&opened.graph)?;
        let (existing, stored) = self.store.read_consistently(|r| Ok((existing(r)?, stored_among(r, &uncarried)?)))?;
        let mut warnings = opened.warnings;
        warnings.extend(uncarried_warnings(&uncarried, &stored, "bundle", "imported")?);
        let plan = plan::plan(&opened.graph, &existing, policy);
        Ok(ImportReport {
            plan,
            warnings,
            secrets_restored: opened.secrets_restored,
            missing_secrets: missing_secrets(&opened.graph),
            linked_files: opened.graph.linked_files(),
            checkpoint: None,
            workspaces: opened.graph.workspaces.iter().map(|w| w.name.clone()).collect(),
            workspace_ids: vec![],
            full_backup: false,
            bundle_sha256,
        })
    }

    /// [`App::import_approved`] with nothing approved: a bundle that claims
    /// a workspace stored here is refused under Merge and Replace.
    pub fn import(&self, bytes: &[u8], passphrase: Option<&str>, policy: ConflictPolicy) -> Result<ImportReport> {
        self.import_approved(bytes, passphrase, policy, &ImportApproval::default())
    }

    /// Apply after taking a restore checkpoint. Objects and secrets are
    /// written in one transaction, which any failure before its commit rolls
    /// back. Attachments are stored after the commit and stay stored if that
    /// step fails. Bundles that describe a full backup are refused before
    /// anything is written.
    ///
    /// The whole import is refused, before anything is written, when:
    /// - `approval` was given for another file (its `bundle_sha256`), or
    ///   names an existing workspace without naming a file;
    /// - a request or dataset names a stored attachment by content hash that
    ///   the bundle does not carry, and content with that hash is stored
    ///   here: it would resolve to bytes the bundle never carried. One whose
    ///   content is not stored here is accepted with a warning;
    /// - under Merge or Replace, the bundle claims a workspace stored here
    ///   that `approval` does not name: what it writes there could use that
    ///   workspace's vault secrets, and a bundle's encryption says nothing
    ///   about who wrote it;
    /// - under Replace, a bundle secret's id is stored here under a workspace
    ///   outside the bundle (or under none), or a bundle object's kind and id
    ///   are stored here in another workspace: an object or secret is never
    ///   overwritten or moved out of its workspace.
    pub fn import_approved(
        &self,
        bytes: &[u8],
        passphrase: Option<&str>,
        policy: ConflictPolicy,
        approval: &ImportApproval,
    ) -> Result<ImportReport> {
        approval.check_file(bytes, "imported")?;
        let opened = bundle::open(bytes, passphrase)?;
        let mut g = opened.graph;
        let uncarried = validate::uncarried_attachments(&g)?;
        let checkpoint = self.store.checkpoint("before-import")?;
        // A failure rolls back this import's own transaction and nothing else.
        // The checkpoint is never restored automatically: that would also
        // erase whatever other callers saved since it was taken.
        let (plan, notes) = self.store.atomically(|s| {
            // Read inside the transaction, so merge and naming decisions see
            // exactly what the writes below land on.
            let existing = existing(&s.as_read())?;
            let stored = stored_among(&s.as_read(), &uncarried)?;
            let notes = match uncarried_warnings(&uncarried, &stored, "bundle", "imported") {
                Ok(notes) => notes,
                Err(e) => return Ok(Err(e)),
            };
            let plan = plan::plan(&g, &existing, policy);
            let unapproved: Vec<String> = plan
                .existing_workspaces
                .iter()
                .filter(|w| !approval.existing_workspaces.contains(&w.id))
                .map(|w| format!("'{}' ({})", w.name, w.id))
                .collect();
            if !unapproved.is_empty() {
                return Ok(Err(AppError::Invalid(format!(
                    "this bundle writes into your existing workspace {}, and what it imports there can use that workspace's vault secrets; nothing was imported. Import as copies, or confirm writing into it after the preview.",
                    unapproved.join(", ")
                ))));
            }
            if policy == ConflictPolicy::Replace && !plan.foreign_objects.is_empty() {
                return Ok(Err(AppError::Invalid(format!(
                    "Replace cannot overwrite objects that belong to another workspace ({}); nothing was imported. Import as copies instead.",
                    plan.foreign_objects.join(", ")
                ))));
            }
            if policy == ConflictPolicy::Replace && !plan.foreign_secrets.is_empty() {
                return Ok(Err(AppError::Invalid(format!(
                    "Replace cannot overwrite secrets that belong to a workspace outside the bundle ({}); nothing was imported. Import as copies instead.",
                    plan.foreign_secrets.join(", ")
                ))));
            }
            if policy == ConflictPolicy::Duplicate {
                // Fresh ids for every object, revision and secret: the copy
                // can never overwrite or share anything with its source.
                plan::remap_all(&mut g)?;
            }
            // A different workspace with the same name would be
            // indistinguishable in the UI; label the incoming copy.
            for w in &mut g.workspaces {
                if existing.workspaces.iter().any(|(id, name)| *name == w.name && *id != w.meta.id) {
                    w.name = format!("{} (imported)", w.name);
                }
            }
            let skip = |id: &Id| policy == ConflictPolicy::Merge && existing.objects.contains(id);
            for w in &g.workspaces {
                if !skip(&w.meta.id) {
                    s.put(kind::WORKSPACE, &w.meta.id, None, None, 0.0, w)?;
                }
            }
            for f in &g.folders {
                if !skip(&f.meta.id) {
                    s.put(kind::FOLDER, &f.meta.id, Some(&f.workspace_id), f.parent_id.as_ref(), f.sort_key, f)?;
                }
            }
            for r in &g.requests {
                if !skip(&r.meta.id) {
                    s.put(kind::REQUEST, &r.meta.id, Some(&r.workspace_id), r.folder_id.as_ref(), r.sort_key, r)?;
                }
            }
            // Validation guarantees each revision's request is in the bundle.
            let request_ws: HashMap<Id, Id> = g.requests.iter().map(|q| (q.meta.id, q.workspace_id)).collect();
            for r in &g.revisions {
                if !skip(&r.id) {
                    s.put(kind::REVISION, &r.id, request_ws.get(&r.request_id), Some(&r.request_id), 0.0, r)?;
                }
            }
            for e in &g.environments {
                if !skip(&e.meta.id) {
                    s.put(kind::ENVIRONMENT, &e.meta.id, Some(&e.workspace_id), None, 0.0, e)?;
                }
            }
            for p in &g.tls_profiles {
                if !skip(&p.id) {
                    s.put(kind::TLS_PROFILE, &p.id, Some(&p.workspace_id), None, 0.0, p)?;
                }
            }
            for p in &g.proxy_profiles {
                if !skip(&p.id) {
                    s.put(kind::PROXY_PROFILE, &p.id, Some(&p.workspace_id), None, 0.0, p)?;
                }
            }
            for p in &g.integrations {
                if !skip(&p.id) {
                    s.put(kind::INTEGRATION, &p.id, Some(&p.workspace_id), None, 0.0, p)?;
                }
            }
            for d in &g.datasets {
                if !skip(&d.meta.id) {
                    s.put(kind::DATASET, &d.meta.id, Some(&d.workspace_id), None, 0.0, d)?;
                }
            }
            for sc in &g.scenarios {
                if !skip(&sc.meta.id) {
                    s.put(kind::SCENARIO, &sc.meta.id, Some(&sc.workspace_id), None, 0.0, sc)?;
                }
            }
            for p in &g.load_plans {
                if !skip(&p.id) {
                    s.put(kind::LOAD_PLAN, &p.id, Some(&p.workspace_id), None, 0.0, p)?;
                }
            }
            // Validation keeps only records of a workspace in the bundle, as
            // valid execution records; the bundle carries no response bodies.
            for h in &g.history {
                let rec: ExecutionRecord = serde_json::from_value(h.clone())?;
                if policy == ConflictPolicy::Merge && existing.history.contains_key(&rec.id) {
                    continue;
                }
                let started_at = rec.started_at.timestamp_millis();
                s.add_history(&rec.id, rec.workspace_id.as_ref(), rec.request_id.as_ref(), started_at, &rec, None)?;
            }
            // A linked-file binding was chosen for the request or dataset it
            // names; one this import overwrites is not that object any more.
            let written: HashSet<Id> =
                g.requests.iter().map(|r| r.meta.id).chain(g.datasets.iter().map(|d| d.meta.id)).filter(|id| !skip(id)).collect();
            let bindings: Vec<LinkedFileBinding> = s.list(kind::LINKED_FILE, None)?;
            for b in bindings.iter().filter(|b| written.contains(&b.referrer.id())) {
                s.delete(kind::LINKED_FILE, &b.id)?;
            }
            for (id, v) in &g.secrets {
                if let Ok(sid) = id.parse::<Id>() {
                    if policy == ConflictPolicy::Merge && existing.secrets.contains_key(&sid) {
                        continue;
                    }
                    // Owned by a workspace of this import (remapped for Duplicate).
                    let ws = v.workspace_id.as_deref().and_then(|w| w.parse::<Id>().ok());
                    s.put_secret(&sid, ws.as_ref(), &v.label, &v.value)?;
                }
            }
            Ok(Ok((plan, notes)))
        })??;
        for (sha, bytes) in &g.attachments {
            let r = self.put_attachment(sha, bytes, None)?;
            if let anvil_domain::request::AttachmentRef::Stored { sha256, .. } = r
                && sha256 != *sha
            {
                return Err(AppError::Invalid(format!("attachment {sha} failed its integrity check")));
            }
        }
        let mut warnings = opened.warnings;
        warnings.extend(notes);
        Ok(ImportReport {
            plan,
            warnings,
            secrets_restored: opened.secrets_restored,
            missing_secrets: missing_secrets(&g),
            linked_files: g.linked_files(),
            checkpoint: Some(checkpoint.display().to_string()),
            workspaces: g.workspaces.iter().map(|w| w.name.clone()).collect(),
            workspace_ids: g.workspaces.iter().map(|w| w.meta.id.to_string()).collect(),
            full_backup: false,
            bundle_sha256: file_sha256(bytes),
        })
    }
}

/// Full backups are ANVILBAK files written by [`App::export_backup`], never
/// bundles.
fn refuse_full_backup(mode: ExportMode) -> Result<()> {
    if mode == ExportMode::FullBackup {
        return Err(bundle::BundleError::FullBackupNotABundle.into());
    }
    Ok(())
}

/// Every stored object, secret and history record with its owner, and every
/// stored workspace with its name, read through `s`.
pub(crate) fn existing(s: &StoreRead<'_>) -> anvil_storage::store::Result<Existing> {
    let mut e = Existing::default();
    for k in kind::ALL {
        for m in s.object_meta(k)? {
            if let Ok(id) = m.id.parse() {
                e.objects.insert(id);
                e.owners.insert((m.kind, id), m.workspace_id.and_then(|w| w.parse().ok()));
            }
        }
    }
    for w in s.list::<Workspace>(kind::WORKSPACE, None)? {
        e.workspaces.insert(w.meta.id, w.name);
    }
    for (id, owner) in s.secret_owners()? {
        if let Ok(id) = id.parse() {
            e.secrets.insert(id, owner.and_then(|w| w.parse().ok()));
        }
    }
    for h in s.history_entries()? {
        if let Ok(id) = h.id.parse() {
            e.history.insert(id, h.workspace_id.and_then(|w| w.parse().ok()));
        }
    }
    Ok(e)
}

/// The content hashes among `uncarried` whose content is stored here, read
/// through `r`: each resolves, as a stored attachment of any request or
/// dataset would.
pub(crate) fn stored_among(r: &StoreRead<'_>, uncarried: &[UncarriedAttachment]) -> anvil_storage::store::Result<HashSet<String>> {
    let mut out = HashSet::new();
    for u in uncarried {
        if out.contains(&u.sha256) {
            continue;
        }
        let index: Option<serde_json::Value> = r.get(kind::IMPORT_SOURCE, &attachment_index_id(&u.sha256))?;
        let blob = index.as_ref().and_then(|i| i.get("blob")).and_then(|b| b.as_str());
        if let Some(blob) = blob
            && r.get_blob(blob)?.is_some()
        {
            out.insert(u.sha256.clone());
        }
    }
    Ok(out)
}

/// Check the stored attachments a bundle or backup (`file`) names without
/// their bytes against `stored`, the hashes whose content is stored here.
/// One that is stored refuses the whole file, since the reference would
/// resolve to bytes the file never carried, possibly another workspace's.
/// Otherwise returns one warning per item that names any of them.
pub(crate) fn uncarried_warnings(
    uncarried: &[UncarriedAttachment],
    stored: &HashSet<String>,
    file: &str,
    done: &str,
) -> Result<Vec<String>> {
    if let Some(u) = uncarried.iter().find(|u| stored.contains(&u.sha256)) {
        return Err(AppError::Invalid(format!(
            "{} uses a stored attachment that the {file} does not carry, and content with that hash is already stored on this device; nothing was {done}.",
            u.item
        )));
    }
    let mut warnings: Vec<String> = Vec::new();
    for u in uncarried {
        let warning =
            format!("{} uses a stored file that the {file} does not include; it will fail until the file is attached again.", u.item);
        if !warnings.contains(&warning) {
            warnings.push(warning);
        }
    }
    Ok(warnings)
}

/// Secret references in the graph whose values were not included.
fn missing_secrets(g: &PortableGraph) -> Vec<String> {
    let text = serde_json::to_string(&(&g.requests, &g.environments, &g.tls_profiles, &g.workspaces, &g.folders)).unwrap_or_default();
    let mut out = Vec::new();
    for part in text.split("\"kind\":\"secret\",\"secret\":{\"id\":\"").skip(1) {
        let id: String = part.chars().take(36).collect();
        if !g.secrets.contains_key(&id) {
            let label = part.split("\"label\":\"").nth(1).map(|l| l.split('"').next().unwrap_or("").to_string()).unwrap_or_default();
            out.push(format!("{label} ({id})"));
        }
    }
    out.sort();
    out.dedup();
    out
}
