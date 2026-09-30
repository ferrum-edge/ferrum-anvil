//! Spec and collection imports (OpenAPI 2.0–3.2, WSDL 1.1, Postman,
//! Insomnia, cURL, HAR). Parsing happens in `anvil-import`; this module
//! previews, persists with provenance, and plans reimports. Nothing imported
//! is ever sent or run as part of importing.

use crate::workspace::{put_attachment_in, release_attachment_in, spec_hash};
use crate::{App, AppError, Result};
use anvil_domain::Id;
use anvil_domain::auth::AuthConfig;
use anvil_domain::request::AttachmentRef;
use anvil_domain::workspace::{Environment, Folder, Meta, RequestDefinition, RequestRevision, Workspace};
use anvil_import::{
    Detected, ImportOptions, ImportReport, ImportResult, ImportedScope, ImportedSource, ReimportApproval, ReimportPlan, ScopeDiff,
    request_unit_hashes,
};
use anvil_storage::store::{StoreRead, StoreTx, kind};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};

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
/// A reimport refreshes it: `source`, `original_sha256` and `file_name` then
/// describe the version it applied.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpecSourceRecord {
    pub source: ImportedSource,
    pub workspace_id: Id,
    pub root_folder_id: Option<Id>,
    /// Content-addressed attachment holding the original bytes of the
    /// version last imported.
    pub original_sha256: String,
    pub file_name: String,
    /// Import ids of earlier versions; requests keep the id of the import
    /// that last wrote them.
    #[serde(default)]
    pub previous_import_ids: Vec<Id>,
    /// [`ImportedScope::unit_hashes`] of the scoped configuration (the
    /// workspace's or import root's scope, the environments and the
    /// folders) and [`request_unit_hashes`] of the requests' names,
    /// descriptions and tags the import last generated, so a reimport tells
    /// user edits from upstream changes. Missing on records written before
    /// it was kept; without folder and request units on records written
    /// before those were.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generated_scope: Option<BTreeMap<String, String>>,
}

const ROOT_DELETED: &str = "the import's root folder was deleted; import the source again";
const ROOT_INVALID: &str = "the import's root folder is invalid; import the source again";
const CHANGED: &str = "the import's requests or configuration changed since the diff; re-run the reimport diff";

/// A reimport compared with what is stored.
struct Reimport {
    rec: SpecSourceRecord,
    /// The environments and folders [`stored`] was asked for.
    ids: HashSet<Id>,
    previous: Vec<RequestDefinition>,
    current: ImportedScope,
    generated: Option<BTreeMap<String, String>>,
    /// The fresh import.
    result: ImportResult,
    fresh: ImportedScope,
    plan: ReimportPlan,
}

/// What a reimport compares with, as [`stored`] reads it.
#[derive(PartialEq)]
struct Stored {
    /// The requests linked to the import.
    requests: Vec<RequestDefinition>,
    /// The import's scoped configuration as stored now.
    scope: ImportedScope,
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
        let scope_hashes = baseline(&r, root.is_some());
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

    /// What the import last generated for its scoped configuration and its
    /// requests' names. A record from before that was kept gets it by
    /// importing its stored original again, unless it was reimported since;
    /// otherwise, or when that original cannot be read, it is unknown. A
    /// record from before folder and request units were kept gets those the
    /// same way.
    fn scope_baseline(&self, rec: &SpecSourceRecord) -> Option<BTreeMap<String, String>> {
        let reimported = !rec.previous_import_ids.is_empty();
        let details = |k: &String| k.starts_with("folders/") || k.starts_with("requests/");
        match &rec.generated_scope {
            Some(g) if reimported || g.keys().any(details) => Some(g.clone()),
            None if reimported => None,
            None => self.original_baseline(rec),
            Some(g) => {
                let mut g = g.clone();
                g.extend(self.original_baseline(rec).into_iter().flatten().filter(|(k, _)| details(k)));
                Some(g)
            }
        }
    }

    /// What importing the record's stored original generates, if it can be
    /// read.
    fn original_baseline(&self, rec: &SpecSourceRecord) -> Option<BTreeMap<String, String>> {
        let Ok(Some(bytes)) = self.get_attachment(&rec.original_sha256) else { return None };
        let mut opts = rec.source.options.clone();
        opts.id_namespace = Some(rec.source.id_namespace);
        anvil_import::import(&bytes, &opts).ok().map(|r| baseline(&r, rec.root_folder_id.is_some()))
    }

    /// Import a newer version of the source in the original id namespace
    /// (so unchanged operations and environments keep ids) and compare it
    /// with the linked requests and the scoped configuration.
    fn reimport(&self, import_id: &Id, bytes: &[u8]) -> Result<Reimport> {
        let rec = self.spec_source(import_id)?;
        match self.store.read_consistently(|s| valid_root(s, &rec))? {
            RootStatus::Valid => {}
            RootStatus::Missing => return Err(AppError::Invalid(ROOT_DELETED.into())),
            RootStatus::Invalid => return Err(AppError::Invalid(ROOT_INVALID.into())),
        }
        let mut opts = rec.source.options.clone();
        opts.id_namespace = Some(rec.source.id_namespace);
        let r = run(bytes, &opts)?;
        let generated = self.scope_baseline(&rec);
        let fresh = generated_scope(&r, rec.root_folder_id.is_some());
        let mut ids: HashSet<Id> = fresh.environments.iter().map(|e| e.meta.id).collect();
        let earlier = generated.iter().flat_map(|g| g.keys()).filter_map(|k| k.strip_prefix("environments/")?.parse::<Id>().ok());
        ids.extend(earlier);
        // Only a folder both sides have is compared.
        ids.extend(fresh.folders.iter().map(|f| f.meta.id));
        let Stored { requests: previous, scope: current } = self.store.read_consistently(|s| stored(s, &rec, &ids))??;
        let scope = ScopeDiff { current: &current, generated: generated.as_ref(), fresh: &fresh };
        let plan = anvil_import::reimport_diff(&previous, &r, scope);
        Ok(Reimport { rec, ids, previous, current, generated, result: r, fresh, plan })
    }

    /// Compare a newer version of an imported source with what is saved:
    /// its requests (their specs, names, descriptions and tags) and its
    /// scoped configuration (the source's own variables, auth, settings and
    /// description, its environments, where a changed server shows up as a
    /// changed `baseUrl`, and its folders' own settings).
    pub fn spec_reimport_plan(&self, import_id: &Id, bytes: &[u8]) -> Result<ReimportPlan> {
        Ok(self.reimport(import_id, bytes)?.plan)
    }

    /// Apply a reimport of `bytes`, read from `file_name`. User edits
    /// (renames included) are overwritten and removed operations,
    /// variables and environments deleted only when listed in `approval`.
    /// A request whose spec changes gets a new revision, written in the same
    /// transaction; an unchanged one keeps its revision. The source record
    /// is refreshed in that transaction too: it then holds `bytes` as the
    /// stored original, their hash and `file_name`, and the original it held
    /// before is released unless something else references it.
    pub fn spec_reimport_apply(&self, import_id: &Id, bytes: &[u8], file_name: &str, approval: &ReimportApproval) -> Result<usize> {
        let r = self.reimport(import_id, bytes)?;
        self.apply_reimport(r, bytes, file_name, approval)
    }

    /// Write `r`, a reimport of `bytes` read from `file_name`, with
    /// `approval`. It is refused, and nothing is written, when what `r` was
    /// compared with changed before the write transaction began.
    fn apply_reimport(&self, r: Reimport, bytes: &[u8], file_name: &str, approval: &ReimportApproval) -> Result<usize> {
        let Reimport { rec, ids, previous, current, generated, result, fresh, plan } = r;
        let next = plan.apply(&previous, approval);
        let scope = plan.apply_scope(&current, &fresh, approval);
        let baseline = plan.next_generated_scope(&fresh, &result.requests, generated.as_ref(), approval);
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
        let changed_folders: Vec<Folder> = scope
            .folders
            .iter()
            .filter(|f| !current.folders.contains(f))
            .cloned()
            .map(|mut f| {
                f.meta.updated_at = now;
                f
            })
            .collect();
        let scope_changed = scope.description != current.description
            || scope.settings != current.settings
            || scope.variables != current.variables
            || scope.auth != current.auth;
        // Kept for a manual restore only; see `App::import`.
        self.store.checkpoint("before-spec-reimport")?;
        self.store.atomically(|s| {
            // Everything below is written from copies read before this
            // transaction; a change made since would be overwritten.
            let unchanged = Stored { requests: previous.clone(), scope: current.clone() };
            let source = s.get::<SpecSourceRecord>(kind::SPEC_SOURCE, &rec.source.import_id)?;
            if source.is_none()
                || valid_root(&s.as_read(), &rec)? != RootStatus::Valid
                || stored(&s.as_read(), &rec, &ids)?.ok() != Some(unchanged)
            {
                return Ok(Err(AppError::Invalid(CHANGED.into())));
            }
            let mut foreign_owners = HashMap::new();
            for object_kind in [kind::FOLDER, kind::REQUEST, kind::ENVIRONMENT, kind::REVISION, kind::SPEC_SOURCE] {
                let owners = s.object_meta(object_kind)?.into_iter().map(|row| (row.id, row.workspace_id)).collect();
                foreign_owners.insert(object_kind, owners);
            }
            let mut collisions = false;
            for f in new_folders.iter().chain(&changed_folders) {
                collisions |= foreign_workspace_owns(&foreign_owners, kind::FOLDER, &f.meta.id, &rec.workspace_id);
            }
            for q in &next {
                collisions |= foreign_workspace_owns(&foreign_owners, kind::REQUEST, &q.meta.id, &rec.workspace_id);
            }
            for e in &environments {
                collisions |= foreign_workspace_owns(&foreign_owners, kind::ENVIRONMENT, &e.meta.id, &rec.workspace_id);
            }
            let revisions: Vec<RequestRevision> = next
                .iter()
                .filter_map(|q| {
                    previous.iter().find(|p| p.meta.id == q.meta.id && spec_hash(&p.spec) != spec_hash(&q.spec)).map(|_| RequestRevision {
                        id: Id::new(),
                        request_id: q.meta.id,
                        created_at: now,
                        spec_sha256: spec_hash(&q.spec),
                        spec: q.spec.clone(),
                    })
                })
                .collect();
            for rev in &revisions {
                collisions |= foreign_workspace_owns(&foreign_owners, kind::REVISION, &rev.id, &rec.workspace_id);
            }
            collisions |= foreign_workspace_owns(&foreign_owners, kind::SPEC_SOURCE, &result.source.import_id, &rec.workspace_id);
            if collisions {
                return Ok(Err(foreign_reimport_collision()));
            }
            for f in new_folders.iter().chain(&changed_folders) {
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
                if let Some(rev) = revisions.iter().find(|rev| rev.request_id == q.meta.id) {
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
                // A deleted environment is not the active one any more, as
                // when the user deletes it.
                if w.active_environment_id.is_some_and(|a| deleted_environments.contains(&a)) {
                    w.active_environment_id = None;
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
            // The record describes the version just applied, so anything that
            // reads the stored original reads this one.
            let original_sha256 = match put_attachment_in(s, file_name, bytes, None)? {
                AttachmentRef::Stored { sha256, .. } => sha256,
                AttachmentRef::LinkedFile { .. } => String::new(),
            };
            let mut rec = rec.clone();
            let replaced = std::mem::replace(&mut rec.original_sha256, original_sha256);
            rec.previous_import_ids.push(rec.source.import_id);
            rec.source = result.source.clone();
            rec.file_name = file_name.to_string();
            rec.generated_scope = Some(baseline.clone());
            s.delete(kind::SPEC_SOURCE, &rec.previous_import_ids[rec.previous_import_ids.len() - 1])?;
            s.put(kind::SPEC_SOURCE, &rec.source.import_id, Some(&rec.workspace_id), None, 0.0, &rec)?;
            // The version it replaces is released, unless something else
            // still references it (another import of the same bytes, a saved
            // request body or dataset) or a user attached the same file,
            // which an item not saved yet may hold.
            if !replaced.is_empty() && replaced != rec.original_sha256 {
                release_attachment_in(s, &replaced)?;
            }
            Ok(Ok(()))
        })??;
        Ok(next.len())
    }
}

/// What a reimport of `rec` compares with, read from `s`: the requests linked
/// to the import, and its scoped configuration (the scope of its workspace or
/// import root, and those of the environments and folders in `ids`, plus the
/// import root's own environments, that still exist).
fn stored(s: &StoreRead<'_>, rec: &SpecSourceRecord, ids: &HashSet<Id>) -> anvil_storage::store::Result<Result<Stored>> {
    let mut ids = ids.clone();
    match valid_root(s, rec)? {
        RootStatus::Valid => {}
        RootStatus::Missing => return Ok(Err(AppError::Invalid(ROOT_DELETED.into()))),
        RootStatus::Invalid => return Ok(Err(AppError::Invalid(ROOT_INVALID.into()))),
    }
    let (description, settings, variables, auth) = match rec.root_folder_id {
        None => {
            let Some(w) = s.get::<Workspace>(kind::WORKSPACE, &rec.workspace_id)? else {
                return Ok(Err(AppError::NotFound("workspace".into())));
            };
            (w.description, w.settings, w.variables, w.auth)
        }
        Some(id) => {
            let Some(f) = s.get::<Folder>(kind::FOLDER, &id)? else { return Ok(Err(AppError::Invalid(ROOT_DELETED.into()))) };
            ids.extend(f.import_environment_ids.iter().copied());
            (f.description, f.settings, f.variables, f.auth)
        }
    };
    let linked = |q: &RequestDefinition| {
        q.spec.source.as_ref().is_some_and(|src| src.import_id == rec.source.import_id || rec.previous_import_ids.contains(&src.import_id))
    };
    let requests = s.list::<RequestDefinition>(kind::REQUEST, Some(&rec.workspace_id))?.into_iter().filter(linked).collect();
    let environments =
        s.list::<Environment>(kind::ENVIRONMENT, Some(&rec.workspace_id))?.into_iter().filter(|e| ids.contains(&e.meta.id)).collect();
    let folders = s.list::<Folder>(kind::FOLDER, Some(&rec.workspace_id))?.into_iter().filter(|f| ids.contains(&f.meta.id)).collect();
    Ok(Ok(Stored { requests, scope: ImportedScope { description, settings, variables, auth, environments, folders } }))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RootStatus {
    Valid,
    Missing,
    Invalid,
}

/// A reimport root is provenance, so accept it only when it is still an
/// import root in the source record's workspace. Users may move it within
/// that workspace.
fn valid_root(s: &StoreRead<'_>, rec: &SpecSourceRecord) -> anvil_storage::store::Result<RootStatus> {
    let Some(id) = rec.root_folder_id else { return Ok(RootStatus::Valid) };
    let Some(folder) = s.get::<Folder>(kind::FOLDER, &id)? else { return Ok(RootStatus::Missing) };
    Ok(if folder.workspace_id == rec.workspace_id && folder.import_root { RootStatus::Valid } else { RootStatus::Invalid })
}

fn foreign_workspace_owns(owners: &HashMap<&str, HashMap<String, Option<String>>>, object_kind: &str, id: &Id, workspace_id: &Id) -> bool {
    let expected = workspace_id.to_string();
    owners
        .get(object_kind)
        .and_then(|kind_owners| kind_owners.get(&id.to_string()))
        .is_some_and(|owner| owner.as_deref() != Some(expected.as_str()))
}

fn foreign_reimport_collision() -> AppError {
    AppError::Invalid("reimport would overwrite an object in another workspace; nothing was changed".into())
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

/// The baseline to keep for what `r` generated: its scope's unit hashes and
/// its requests' ([`request_unit_hashes`]).
fn baseline(r: &ImportResult, rooted: bool) -> BTreeMap<String, String> {
    let mut hashes = generated_scope(r, rooted).unit_hashes();
    hashes.extend(request_unit_hashes(&r.requests));
    hashes
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profiles::ProfileManager;
    use anvil_domain::request::SensitiveValue;
    use anvil_domain::workspace::Variable;
    use anvil_storage::KdfParams;

    const SERVER: &str = r#"{"openapi":"3.0.3","info":{"title":"Audit","version":"1"},"servers":[{"url":"https://old.example.test"}],"paths":{"/health":{"get":{"operationId":"health","responses":{"200":{"description":"ok"}}}}}}"#;

    #[test]
    fn a_reimport_is_refused_when_what_it_compared_changed_before_it_was_written() {
        let root = tempfile::tempdir().unwrap();
        let pm = ProfileManager::new(root.path());
        let (s, dek, _recovery) = pm.create_passphrase("t", "correct horse battery", KdfParams::testing()).unwrap();
        let h = anvil_storage::vault::read_header(&s.dir).unwrap();
        let app = App::open(s.dir, h, dek).unwrap();
        let done = app.spec_import(SERVER.as_bytes(), "audit.json", &ImportOptions::default(), SpecTarget::NewWorkspace).unwrap();
        let ws = done.workspace_id;
        let newer = SERVER.replace("https://old.example.test", "https://new.example.test");
        let r = app.reimport(&done.import_id, newer.as_bytes()).unwrap();
        assert!(!r.plan.scope_updated.is_empty());

        // The user edits the environment after the diff was made, before it
        // is written.
        let mut env = app.environments(&ws).unwrap().pop().unwrap();
        env.variables.push(Variable::plain("token", "mine"));
        let env = app.save_environment(env).unwrap();
        let err = app.apply_reimport(r, newer.as_bytes(), "audit-v2.json", &ReimportApproval::default()).unwrap_err();
        assert!(err.to_string().contains("re-run the reimport diff"), "{err}");
        assert_eq!(app.environments(&ws).unwrap(), vec![env], "nothing was written");
        let rec = app.spec_sources(&ws).unwrap().pop().unwrap();
        assert_eq!(rec.source.import_id, done.import_id);
        assert_eq!(rec.file_name, "audit.json", "the source record is not refreshed");
        assert_eq!(app.get_attachment(&rec.original_sha256).unwrap().as_deref(), Some(SERVER.as_bytes()));

        // Diffed again, it applies and keeps the edit.
        app.spec_reimport_apply(&done.import_id, newer.as_bytes(), "audit-v2.json", &ReimportApproval::default()).unwrap();
        let env = app.environments(&ws).unwrap().pop().unwrap();
        assert!(env.variables.iter().any(|v| v.name == "token"), "the user's variable is kept");
        let rec = app.spec_sources(&ws).unwrap().pop().unwrap();
        assert_ne!(rec.source.import_id, done.import_id);
        assert_eq!(rec.file_name, "audit-v2.json");
        assert_eq!(app.get_attachment(&rec.original_sha256).unwrap().as_deref(), Some(newer.as_bytes()));
    }

    #[test]
    fn a_reimport_refuses_a_root_in_another_workspace() {
        let root = tempfile::tempdir().unwrap();
        let pm = ProfileManager::new(root.path());
        let (s, dek, _recovery) = pm.create_passphrase("t", "correct horse battery", KdfParams::testing()).unwrap();
        let h = anvil_storage::vault::read_header(&s.dir).unwrap();
        let app = App::open(s.dir, h, dek).unwrap();
        let victim = app.create_workspace("Victim").unwrap();
        let folder = app.create_folder(&victim.meta.id, None, "Private").unwrap();
        let imported = app.spec_import(ADMIN.as_bytes(), "admin.json", &ImportOptions::default(), SpecTarget::NewWorkspace).unwrap();
        let mut rec = app.spec_source(&imported.import_id).unwrap();
        rec.root_folder_id = Some(folder.meta.id);
        app.store.put(kind::SPEC_SOURCE, &rec.source.import_id, Some(&rec.workspace_id), None, 0.0, &rec).unwrap();
        let changed = ADMIN.replace(r#""value": "read""#, r#""value": "write""#);

        assert!(app.spec_reimport_plan(&imported.import_id, changed.as_bytes()).is_err());
        assert!(app.spec_reimport_apply(&imported.import_id, changed.as_bytes(), "admin-v2.json", &ReimportApproval::default()).is_err());
        assert_eq!(app.folder(&folder.meta.id).unwrap(), folder);
    }

    #[test]
    fn a_moved_import_root_can_be_reimported() {
        let root = tempfile::tempdir().unwrap();
        let pm = ProfileManager::new(root.path());
        let (s, dek, _recovery) = pm.create_passphrase("t", "correct horse battery", KdfParams::testing()).unwrap();
        let h = anvil_storage::vault::read_header(&s.dir).unwrap();
        let app = App::open(s.dir, h, dek).unwrap();
        let ws = app.create_workspace("Workspace").unwrap();
        let parent = app.create_folder(&ws.meta.id, None, "Parent").unwrap();
        let imported = app
            .spec_import(ADMIN.as_bytes(), "admin.json", &ImportOptions::default(), SpecTarget::Workspace { workspace_id: ws.meta.id })
            .unwrap();
        let root_id = imported.root_folder_id.unwrap();
        app.move_folder(&root_id, Some(parent.meta.id), 1.0).unwrap();
        let changed = ADMIN.replace(r#""value": "read""#, r#""value": "write""#);

        app.spec_reimport_plan(&imported.import_id, changed.as_bytes()).unwrap();
        app.spec_reimport_apply(&imported.import_id, changed.as_bytes(), "admin-v2.json", &ReimportApproval::default()).unwrap();

        let folder = app.folders(&ws.meta.id).unwrap().into_iter().find(|f| f.name == "Admin").unwrap();
        assert!(folder.variables.iter().any(|v| v.name == "scope" && v.value == SensitiveValue::template("write")));
        assert_eq!(app.folder(&root_id).unwrap().parent_id, Some(parent.meta.id));
    }

    #[test]
    fn a_missing_import_root_reports_that_it_was_deleted() {
        let root = tempfile::tempdir().unwrap();
        let pm = ProfileManager::new(root.path());
        let (s, dek, _recovery) = pm.create_passphrase("t", "correct horse battery", KdfParams::testing()).unwrap();
        let h = anvil_storage::vault::read_header(&s.dir).unwrap();
        let app = App::open(s.dir, h, dek).unwrap();
        let ws = app.create_workspace("Workspace").unwrap();
        let imported = app
            .spec_import(ADMIN.as_bytes(), "admin.json", &ImportOptions::default(), SpecTarget::Workspace { workspace_id: ws.meta.id })
            .unwrap();
        app.delete_folder(&imported.root_folder_id.unwrap()).unwrap();

        let err = app.spec_reimport_plan(&imported.import_id, ADMIN.as_bytes()).unwrap_err();
        assert!(err.to_string().contains("root folder was deleted"), "{err}");
    }

    #[test]
    fn reimport_cannot_reuse_another_workspaces_namespace() {
        let root = tempfile::tempdir().unwrap();
        let pm = ProfileManager::new(root.path());
        let (s, dek, _recovery) = pm.create_passphrase("t", "correct horse battery", KdfParams::testing()).unwrap();
        let h = anvil_storage::vault::read_header(&s.dir).unwrap();
        let app = App::open(s.dir, h, dek).unwrap();
        let a = app.spec_import(ADMIN.as_bytes(), "a.json", &ImportOptions::default(), SpecTarget::NewWorkspace).unwrap();
        let b = app.spec_import(ADMIN.as_bytes(), "b.json", &ImportOptions::default(), SpecTarget::NewWorkspace).unwrap();
        let b_namespace = app.spec_source(&b.import_id).unwrap().source.id_namespace;
        let mut source_a = app.spec_source(&a.import_id).unwrap();
        source_a.source.id_namespace = b_namespace;
        app.store.put(kind::SPEC_SOURCE, &source_a.source.import_id, Some(&source_a.workspace_id), None, 0.0, &source_a).unwrap();
        let before_folders = app.folders(&b.workspace_id).unwrap();
        let before_requests = app.requests(&b.workspace_id).unwrap();
        let changed = ADMIN.replace(r#""value": "read""#, r#""value": "write""#);

        let err = app.spec_reimport_apply(&a.import_id, changed.as_bytes(), "a-v2.json", &ReimportApproval::default()).unwrap_err();

        assert!(err.to_string().contains("overwrite an object in another workspace"), "{err}");
        assert_eq!(app.folders(&b.workspace_id).unwrap(), before_folders);
        assert_eq!(app.requests(&b.workspace_id).unwrap(), before_requests);
    }

    /// A Postman collection whose folder has a variable of its own.
    const ADMIN: &str = r#"{
  "info": { "name": "Admin API", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json" },
  "item": [
    { "name": "Admin", "variable": [{ "key": "scope", "value": "read" }], "item": [
      { "name": "Users", "request": { "method": "GET", "url": { "raw": "https://api.example.invalid/users/{{scope}}" } } }
    ] }
  ]
}"#;

    #[test]
    fn a_reimport_is_refused_when_a_folder_it_compared_changed_before_it_was_written() {
        let root = tempfile::tempdir().unwrap();
        let pm = ProfileManager::new(root.path());
        let (s, dek, _recovery) = pm.create_passphrase("t", "correct horse battery", KdfParams::testing()).unwrap();
        let h = anvil_storage::vault::read_header(&s.dir).unwrap();
        let app = App::open(s.dir, h, dek).unwrap();
        let done = app.spec_import(ADMIN.as_bytes(), "admin.json", &ImportOptions::default(), SpecTarget::NewWorkspace).unwrap();
        let ws = done.workspace_id;
        let folder = app.folders(&ws).unwrap().into_iter().find(|f| f.name == "Admin").unwrap().meta.id;
        let newer = ADMIN.replace(r#""value": "read""#, r#""value": "write""#);
        for edit in ["rename", "variable"] {
            let r = app.reimport(&done.import_id, newer.as_bytes()).unwrap();
            let key = format!("folders/{folder}/variables/scope");
            assert!(r.plan.scope_updated.iter().any(|c| c.key == key), "{edit}: {:?}", r.plan);

            // The user edits the folder after the diff was made, before it is
            // written.
            let mut f = app.folder(&folder).unwrap();
            if edit == "rename" {
                f.name = "Mine".into();
            } else {
                f.variables.push(Variable::plain("token", "mine"));
            }
            let f = app.save_folder(f).unwrap();
            let requests = app.requests(&ws).unwrap();
            let err = app.apply_reimport(r, newer.as_bytes(), "admin-v2.json", &ReimportApproval::default()).unwrap_err();
            assert!(err.to_string().contains("re-run the reimport diff"), "{edit}: {err}");
            assert_eq!(app.folder(&folder).unwrap(), f, "{edit}: the folder is as the user left it");
            assert_eq!(app.requests(&ws).unwrap(), requests, "{edit}: no request was written");
            let rec = app.spec_sources(&ws).unwrap().pop().unwrap();
            assert_eq!(rec.source.import_id, done.import_id, "{edit}");
            assert_eq!(rec.file_name, "admin.json", "{edit}: the source record is not refreshed");
            assert_eq!(app.get_attachment(&rec.original_sha256).unwrap().as_deref(), Some(ADMIN.as_bytes()), "{edit}");
        }
    }
}
