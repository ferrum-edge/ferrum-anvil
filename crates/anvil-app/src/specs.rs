//! Spec and collection imports (OpenAPI 2.0–3.2, WSDL 1.1, Postman,
//! Insomnia, cURL, HAR). Parsing happens in `anvil-import`; this module
//! previews, persists with provenance, and plans reimports. Nothing imported
//! is ever sent or run as part of importing.

use crate::workspace::{put_attachment_in, spec_hash};
use crate::{App, AppError, Result};
use anvil_domain::Id;
use anvil_domain::auth::AuthConfig;
use anvil_domain::request::AttachmentRef;
use anvil_domain::workspace::{Environment, Folder, Meta, RequestDefinition, RequestRevision, Workspace};
use anvil_import::{
    Detected, ImportOptions, ImportReport, ImportResult, ImportedScope, ImportedSource, ReimportApproval, ReimportPlan, ScopeDiff,
};
use anvil_storage::store::{StoreRead, kind};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};

/// Where an import lands.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SpecTarget {
    /// A new workspace named after the source.
    NewWorkspace,
    /// Inside an existing workspace, under a new top-level folder.
    Workspace { workspace_id: Id },
}

#[derive(Debug, Clone, Serialize)]
pub struct SpecPreview {
    pub detected: Detected,
    pub title: Option<String>,
    pub report: ImportReport,
    pub folders: usize,
    pub requests: usize,
    pub environments: usize,
    /// Up to 200 `METHOD name` lines for a quick look.
    pub sample: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SpecImported {
    pub workspace_id: Id,
    pub root_folder_id: Option<Id>,
    pub import_id: Id,
    pub requests: usize,
    pub report: ImportReport,
}

/// Stored provenance: the source description plus where it was imported.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpecSourceRecord {
    pub source: ImportedSource,
    pub workspace_id: Id,
    pub root_folder_id: Option<Id>,
    /// Content-addressed attachment holding the original bytes.
    pub original_sha256: String,
    pub file_name: String,
    /// Import ids of earlier versions; requests keep the id of the import
    /// that last wrote them.
    #[serde(default)]
    pub previous_import_ids: Vec<Id>,
    /// [`ImportedScope::unit_hashes`] of the scoped configuration (the
    /// workspace's or import root's scope, and the environments) the import
    /// last generated, so a reimport tells user edits from upstream
    /// changes. Missing on records written before it was kept.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generated_scope: Option<BTreeMap<String, String>>,
}

const ROOT_DELETED: &str = "the import's root folder was deleted; import the source again";

/// A reimport compared with what is stored.
struct Reimport {
    rec: SpecSourceRecord,
    previous: Vec<RequestDefinition>,
    current: ImportedScope,
    generated: Option<BTreeMap<String, String>>,
    fresh: ImportedScope,
    /// The environment the fresh import makes active.
    fresh_active: Option<Id>,
    plan: ReimportPlan,
}

fn run(bytes: &[u8], opts: &ImportOptions) -> Result<ImportResult> {
    anvil_import::import(bytes, opts).map_err(|e| AppError::Invalid(e.to_string()))
}

impl App {
    pub fn spec_detect(&self, bytes: &[u8]) -> Detected {
        anvil_import::detect(bytes)
    }

    pub fn spec_preview(&self, bytes: &[u8], opts: &ImportOptions) -> Result<SpecPreview> {
        let detected = anvil_import::detect(bytes);
        let r = run(bytes, opts)?;
        let sample = r.requests.iter().take(200).map(|q| format!("{} {}", q.spec.method, q.name)).collect();
        Ok(SpecPreview {
            detected,
            title: r.source.title.clone(),
            folders: r.folders.len(),
            requests: r.requests.len(),
            environments: r.environments.len(),
            sample,
            report: r.report,
        })
    }

    /// Persist an import as one operation. A restore checkpoint is taken
    /// before anything is written; the new workspace or root folder, the
    /// stored original file, folders, requests, environments and the source
    /// record are then written in one transaction, so a failure leaves the
    /// profile as it was.
    ///
    /// Every import gets a fresh id namespace (kept in the source record,
    /// and reused only by a reimport of this import), so importing the same
    /// source again, into this or another workspace, creates independent
    /// objects and never takes over an earlier import's. Inside an existing
    /// workspace, the source's own auth, variables and settings are kept on
    /// a new import root folder, and imported requests resolve nothing from
    /// the destination workspace. Imported requests are ordinary saved
    /// requests (with an import link for reimport diffs); nothing is sent.
    pub fn spec_import(&self, bytes: &[u8], file_name: &str, opts: &ImportOptions, target: SpecTarget) -> Result<SpecImported> {
        let opts = ImportOptions { id_namespace: Some(Id::new()), ..opts.clone() };
        let mut r = run(bytes, &opts)?;
        let root = match &target {
            SpecTarget::NewWorkspace => None,
            SpecTarget::Workspace { workspace_id } => {
                self.workspace(workspace_id)?;
                let title = r.source.title.clone().unwrap_or_else(|| file_name.to_string());
                let environments = r.environments.iter().map(|e| e.meta.id).collect();
                let root = root_folder(&r.workspace, *workspace_id, &title, environments);
                rehome(&mut r, *workspace_id, root.meta.id);
                Some(root)
            }
        };
        let scope_hashes = generated_scope(&r, root.is_some()).unit_hashes();
        // Kept for a manual restore only; see `App::import`.
        self.store.checkpoint("before-spec-import")?;
        let workspace_id = self.store.atomically(|s| {
            if let Some(clash) = existing_object(&s.as_read(), &r, root.as_ref())? {
                return Ok(Err(AppError::Invalid(format!("the import would overwrite an existing {clash}; nothing was imported"))));
            }
            let workspace_id = match &root {
                None => {
                    let mut w = r.workspace.clone();
                    let local: Vec<Workspace> = s.list(kind::WORKSPACE, None)?;
                    if local.iter().any(|x| x.name == w.name) {
                        w.name = format!("{} (imported)", w.name);
                    }
                    s.put(kind::WORKSPACE, &w.meta.id, None, None, 0.0, &w)?;
                    w.meta.id
                }
                Some(root) => {
                    if s.get::<Workspace>(kind::WORKSPACE, &root.workspace_id)?.is_none() {
                        return Ok(Err(AppError::NotFound("workspace".into())));
                    }
                    let folders: Vec<Folder> = s.list(kind::FOLDER, Some(&root.workspace_id))?;
                    let siblings = folders.iter().filter(|f| f.parent_id.is_none()).count();
                    let root = Folder { sort_key: siblings as f64 + 1.0, ..root.clone() };
                    s.put(kind::FOLDER, &root.meta.id, Some(&root.workspace_id), None, root.sort_key, &root)?;
                    root.workspace_id
                }
            };
            let original_sha256 = match put_attachment_in(s, file_name, bytes, None)? {
                AttachmentRef::Stored { sha256, .. } => sha256,
                AttachmentRef::LinkedFile { .. } => String::new(),
            };
            for f in &r.folders {
                s.put(kind::FOLDER, &f.meta.id, Some(&f.workspace_id), f.parent_id.as_ref(), f.sort_key, f)?;
            }
            for q in &r.requests {
                s.put(kind::REQUEST, &q.meta.id, Some(&q.workspace_id), q.folder_id.as_ref(), q.sort_key, q)?;
            }
            for e in &r.environments {
                s.put(kind::ENVIRONMENT, &e.meta.id, Some(&e.workspace_id), None, 0.0, e)?;
            }
            let rec = SpecSourceRecord {
                source: r.source.clone(),
                workspace_id,
                root_folder_id: root.as_ref().map(|f| f.meta.id),
                original_sha256,
                file_name: file_name.to_string(),
                previous_import_ids: vec![],
                generated_scope: Some(scope_hashes.clone()),
            };
            s.put(kind::SPEC_SOURCE, &r.source.import_id, Some(&workspace_id), None, 0.0, &rec)?;
            Ok(Ok(workspace_id))
        })??;
        Ok(SpecImported {
            workspace_id,
            root_folder_id: root.map(|f| f.meta.id),
            import_id: r.source.import_id,
            requests: r.requests.len(),
            report: r.report,
        })
    }

    pub fn spec_sources(&self, ws: &Id) -> Result<Vec<SpecSourceRecord>> {
        Ok(self.store.list(kind::SPEC_SOURCE, Some(ws))?)
    }

    fn spec_source(&self, import_id: &Id) -> Result<SpecSourceRecord> {
        self.store.get(kind::SPEC_SOURCE, import_id)?.ok_or_else(|| AppError::NotFound(format!("import {import_id}")))
    }

    fn linked_requests(&self, rec: &SpecSourceRecord) -> Result<Vec<RequestDefinition>> {
        Ok(self
            .requests(&rec.workspace_id)?
            .into_iter()
            .filter(|q| {
                q.spec
                    .source
                    .as_ref()
                    .is_some_and(|s| s.import_id == rec.source.import_id || rec.previous_import_ids.contains(&s.import_id))
            })
            .collect())
    }

    /// The import's scoped configuration as stored now: the scope of its
    /// workspace or import root, and those of `environments` (plus the
    /// import root's own) that still exist.
    fn stored_scope(&self, rec: &SpecSourceRecord, mut environments: HashSet<Id>) -> Result<ImportedScope> {
        let (description, settings, variables, auth) = match rec.root_folder_id {
            None => {
                let w = self.workspace(&rec.workspace_id)?;
                (w.description, w.settings, w.variables, w.auth)
            }
            Some(id) => {
                let f = match self.folder(&id) {
                    Err(AppError::NotFound(_)) => return Err(AppError::Invalid(ROOT_DELETED.into())),
                    f => f?,
                };
                environments.extend(f.import_environment_ids.iter().copied());
                (f.description, f.settings, f.variables, f.auth)
            }
        };
        let environments = self.environments(&rec.workspace_id)?.into_iter().filter(|e| environments.contains(&e.meta.id)).collect();
        Ok(ImportedScope { description, settings, variables, auth, environments })
    }

    /// What the import last generated for its scoped configuration. A record
    /// from before that was kept gets it by importing its stored original
    /// again, unless it was reimported since; otherwise it is unknown.
    fn scope_baseline(&self, rec: &SpecSourceRecord) -> Result<Option<BTreeMap<String, String>>> {
        if rec.generated_scope.is_some() || !rec.previous_import_ids.is_empty() {
            return Ok(rec.generated_scope.clone());
        }
        let Some(bytes) = self.get_attachment(&rec.original_sha256)? else { return Ok(None) };
        let mut opts = rec.source.options.clone();
        opts.id_namespace = Some(rec.source.id_namespace);
        Ok(anvil_import::import(&bytes, &opts).ok().map(|r| generated_scope(&r, rec.root_folder_id.is_some()).unit_hashes()))
    }

    /// Import a newer version of the source in the original id namespace
    /// (so unchanged operations and environments keep ids) and compare it
    /// with the linked requests and the scoped configuration.
    fn reimport(&self, import_id: &Id, bytes: &[u8]) -> Result<Reimport> {
        let rec = self.spec_source(import_id)?;
        let mut opts = rec.source.options.clone();
        opts.id_namespace = Some(rec.source.id_namespace);
        let r = run(bytes, &opts)?;
        let previous = self.linked_requests(&rec)?;
        let generated = self.scope_baseline(&rec)?;
        let fresh = generated_scope(&r, rec.root_folder_id.is_some());
        let mut environments: HashSet<Id> = fresh.environments.iter().map(|e| e.meta.id).collect();
        let earlier = generated.iter().flat_map(|g| g.keys()).filter_map(|k| k.strip_prefix("environments/")?.parse::<Id>().ok());
        environments.extend(earlier);
        let current = self.stored_scope(&rec, environments)?;
        let scope = ScopeDiff { current: &current, generated: generated.as_ref(), fresh: &fresh };
        let plan = anvil_import::reimport_diff(&previous, &r, scope);
        Ok(Reimport { rec, previous, current, generated, fresh, fresh_active: r.workspace.active_environment_id, plan })
    }

    /// Compare a newer version of an imported source with what is saved:
    /// its requests and its scoped configuration (the source's own
    /// variables, auth, settings and description, and its environments,
    /// where a changed server shows up as a changed `baseUrl`).
    pub fn spec_reimport_plan(&self, import_id: &Id, bytes: &[u8]) -> Result<ReimportPlan> {
        Ok(self.reimport(import_id, bytes)?.plan)
    }

    /// Apply a reimport. User edits are overwritten and removed operations,
    /// variables and environments deleted only when listed in `approval`.
    /// A request whose spec changes gets a new revision, written in the same
    /// transaction; an unchanged one keeps its revision.
    pub fn spec_reimport_apply(&self, import_id: &Id, bytes: &[u8], approval: &ReimportApproval) -> Result<usize> {
        let Reimport { rec, previous, current, generated, fresh, fresh_active, plan } = self.reimport(import_id, bytes)?;
        let next = plan.apply(&previous, approval);
        let scope = plan.apply_scope(&current, &fresh, approval);
        let baseline = plan.next_generated_scope(&fresh, generated.as_ref(), approval);
        let existing_folders: Vec<Id> = self.folders(&rec.workspace_id)?.iter().map(|f| f.meta.id).collect();
        let new_folders: Vec<Folder> = plan
            .added_folders
            .iter()
            .filter(|f| !existing_folders.contains(&f.meta.id))
            .cloned()
            .map(|mut f| {
                f.workspace_id = rec.workspace_id;
                if f.parent_id.is_none() {
                    f.parent_id = rec.root_folder_id;
                }
                f
            })
            .collect();
        let keep: Vec<Id> = next.iter().map(|q| q.meta.id).collect();
        let deleted: Vec<Id> = previous.iter().map(|q| q.meta.id).filter(|id| !keep.contains(id)).collect();
        let now = chrono::Utc::now();
        let environments: Vec<Environment> = scope
            .environments
            .iter()
            .filter(|e| !current.environments.contains(e))
            .cloned()
            .map(|mut e| {
                e.workspace_id = rec.workspace_id;
                e.meta.updated_at = now;
                e
            })
            .collect();
        let deleted_environments: Vec<Id> =
            current.environments.iter().map(|e| e.meta.id).filter(|id| !scope.environments.iter().any(|e| e.meta.id == *id)).collect();
        let scope_changed = scope.description != current.description
            || scope.settings != current.settings
            || scope.variables != current.variables
            || scope.auth != current.auth;
        // Kept for a manual restore only; see `App::import`.
        self.store.checkpoint("before-spec-reimport")?;
        self.store.atomically(|s| {
            for f in &new_folders {
                s.put(kind::FOLDER, &f.meta.id, Some(&f.workspace_id), f.parent_id.as_ref(), f.sort_key, f)?;
            }
            for q in &next {
                let mut q = q.clone();
                q.workspace_id = rec.workspace_id;
                if q.folder_id.is_none() {
                    q.folder_id = rec.root_folder_id;
                }
                // The revision a changed request pointed at holds its old
                // spec; record the new one, as `App::save_request` does.
                let hash = spec_hash(&q.spec);
                if previous.iter().any(|p| p.meta.id == q.meta.id && spec_hash(&p.spec) != hash) {
                    let rev = RequestRevision {
                        id: Id::new(),
                        request_id: q.meta.id,
                        created_at: now,
                        spec_sha256: hash,
                        spec: q.spec.clone(),
                    };
                    s.put(kind::REVISION, &rev.id, Some(&q.workspace_id), Some(&q.meta.id), 0.0, &rev)?;
                    q.revision_id = Some(rev.id);
                }
                s.put(kind::REQUEST, &q.meta.id, Some(&q.workspace_id), q.folder_id.as_ref(), q.sort_key, &q)?;
            }
            for id in &deleted {
                s.delete(kind::REQUEST, id)?;
            }
            for e in &environments {
                s.put(kind::ENVIRONMENT, &e.meta.id, Some(&e.workspace_id), None, 0.0, e)?;
            }
            for id in &deleted_environments {
                s.delete(kind::ENVIRONMENT, id)?;
            }
            if let Some(mut w) = s.get::<Workspace>(kind::WORKSPACE, &rec.workspace_id)? {
                let before = w.clone();
                if rec.root_folder_id.is_none() && scope_changed {
                    w.description = scope.description.clone();
                    w.settings = scope.settings.clone();
                    w.variables = scope.variables.clone();
                    w.auth = scope.auth.clone();
                }
                // A deleted environment is not the active one any more; a
                // workspace of the import's own falls back to the one the
                // source makes active.
                if w.active_environment_id.is_some_and(|a| deleted_environments.contains(&a)) {
                    let own = fresh_active.filter(|a| rec.root_folder_id.is_none() && scope.environments.iter().any(|e| e.meta.id == *a));
                    w.active_environment_id = own;
                }
                if w != before {
                    w.meta.updated_at = now;
                    s.put(kind::WORKSPACE, &w.meta.id, None, None, 0.0, &w)?;
                }
            }
            if let Some(id) = rec.root_folder_id
                && let Some(mut f) = s.get::<Folder>(kind::FOLDER, &id)?
            {
                let before = f.clone();
                if scope_changed {
                    f.description = scope.description.clone();
                    f.settings = scope.settings.clone();
                    f.variables = scope.variables.clone();
                    f.auth = scope.auth.clone();
                }
                f.import_environment_ids.retain(|e| !deleted_environments.contains(e));
                for e in &scope.environments {
                    if !f.import_environment_ids.contains(&e.meta.id) {
                        f.import_environment_ids.push(e.meta.id);
                    }
                }
                if f != before {
                    f.meta.updated_at = now;
                    s.put(kind::FOLDER, &f.meta.id, Some(&f.workspace_id), f.parent_id.as_ref(), f.sort_key, &f)?;
                }
            }
            let mut rec = rec.clone();
            rec.previous_import_ids.push(rec.source.import_id);
            rec.source.import_id = plan.import_id;
            rec.generated_scope = Some(baseline.clone());
            s.delete(kind::SPEC_SOURCE, &rec.previous_import_ids[rec.previous_import_ids.len() - 1])?;
            s.put(kind::SPEC_SOURCE, &rec.source.import_id, Some(&rec.workspace_id), None, 0.0, &rec)?;
            Ok(())
        })?;
        Ok(next.len())
    }
}

/// The scoped configuration `r` generates, as the import stores it. On an
/// import root in an existing workspace (`rooted`), a source without auth
/// of its own gets an explicit "no auth" (see [`root_folder`]).
fn generated_scope(r: &ImportResult, rooted: bool) -> ImportedScope {
    let mut scope = ImportedScope::generated(r);
    if rooted {
        scope.auth = root_auth(&scope.auth);
    }
    scope
}

fn root_auth(auth: &AuthConfig) -> AuthConfig {
    match auth {
        AuthConfig::Inherit => AuthConfig::None,
        auth => auth.clone(),
    }
}

/// The top-level folder an import into an existing workspace lands in. It
/// keeps the source's workspace-level scope (description, settings,
/// variables and auth), so the imported objects resolve as they would in a
/// workspace of their own. A source without auth of its own gets an
/// explicit "no auth" here. It is an import root: requests under it resolve
/// nothing from the destination workspace (see `App::build_context`) until
/// the user allows that on this device.
fn root_folder(source: &Workspace, workspace_id: Id, name: &str, environments: Vec<Id>) -> Folder {
    Folder {
        meta: Meta::new(),
        workspace_id,
        parent_id: None,
        name: name.trim().into(),
        description: source.description.clone(),
        sort_key: 0.0,
        settings: source.settings.clone(),
        variables: source.variables.clone(),
        auth: root_auth(&source.auth),
        tags: vec![],
        import_root: true,
        import_environment_ids: environments,
        use_workspace_scope: false,
    }
}

/// Move imported objects into `workspace_id`; top-level folders and
/// requests go under the root folder `root`.
fn rehome(r: &mut ImportResult, workspace_id: Id, root: Id) {
    for f in &mut r.folders {
        f.workspace_id = workspace_id;
        if f.parent_id.is_none() {
            f.parent_id = Some(root);
        }
    }
    for q in &mut r.requests {
        q.workspace_id = workspace_id;
        if q.folder_id.is_none() {
            q.folder_id = Some(root);
        }
    }
    for e in &mut r.environments {
        e.workspace_id = workspace_id;
    }
}

/// The kind of the first stored object an import would overwrite, if any.
/// Ids come from a fresh namespace, so this only guards against a clash.
fn existing_object(s: &StoreRead<'_>, r: &ImportResult, root: Option<&Folder>) -> anvil_storage::store::Result<Option<&'static str>> {
    let mut ids = vec![(kind::SPEC_SOURCE, r.source.import_id)];
    match root {
        None => ids.push((kind::WORKSPACE, r.workspace.meta.id)),
        Some(f) => ids.push((kind::FOLDER, f.meta.id)),
    }
    ids.extend(r.folders.iter().map(|f| (kind::FOLDER, f.meta.id)));
    ids.extend(r.requests.iter().map(|q| (kind::REQUEST, q.meta.id)));
    ids.extend(r.environments.iter().map(|e| (kind::ENVIRONMENT, e.meta.id)));
    for (k, id) in ids {
        if s.get::<serde_json::Value>(k, &id)?.is_some() {
            return Ok(Some(k));
        }
    }
    Ok(None)
}
