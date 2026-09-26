//! Spec and collection imports (OpenAPI 2.0–3.2, WSDL 1.1, Postman,
//! Insomnia, cURL, HAR). Parsing happens in `anvil-import`; this module
//! previews, persists with provenance, and plans reimports. Nothing imported
//! is ever sent or run as part of importing.

use crate::workspace::put_attachment_in;
use crate::{App, AppError, Result};
use anvil_domain::Id;
use anvil_domain::auth::AuthConfig;
use anvil_domain::request::AttachmentRef;
use anvil_domain::workspace::{Folder, Meta, RequestDefinition, Workspace};
use anvil_import::{Detected, ImportOptions, ImportReport, ImportResult, ImportedSource, ReimportApproval, ReimportPlan};
use anvil_storage::store::{StoreRead, kind};
use serde::{Deserialize, Serialize};

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
    /// the new root folder, so imported requests never pick up the
    /// destination workspace's auth. Imported requests are ordinary saved
    /// requests (with an import link for reimport diffs); nothing is sent.
    pub fn spec_import(&self, bytes: &[u8], file_name: &str, opts: &ImportOptions, target: SpecTarget) -> Result<SpecImported> {
        let opts = ImportOptions { id_namespace: Some(Id::new()), ..opts.clone() };
        let mut r = run(bytes, &opts)?;
        let root = match &target {
            SpecTarget::NewWorkspace => None,
            SpecTarget::Workspace { workspace_id } => {
                self.workspace(workspace_id)?;
                let title = r.source.title.clone().unwrap_or_else(|| file_name.to_string());
                let root = root_folder(&r.workspace, *workspace_id, &title);
                rehome(&mut r, *workspace_id, root.meta.id);
                Some(root)
            }
        };
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

    /// Compare a newer version of an imported source with what is saved.
    /// Uses the original id namespace so unchanged operations keep ids.
    pub fn spec_reimport_plan(&self, import_id: &Id, bytes: &[u8]) -> Result<ReimportPlan> {
        let rec = self.spec_source(import_id)?;
        let mut opts = rec.source.options.clone();
        opts.id_namespace = Some(rec.source.id_namespace);
        let fresh = run(bytes, &opts)?;
        let previous = self.linked_requests(&rec)?;
        Ok(anvil_import::reimport_diff(&previous, &fresh))
    }

    /// Apply a reimport. User edits are overwritten and removed operations
    /// deleted only when listed in `approval`.
    pub fn spec_reimport_apply(&self, import_id: &Id, bytes: &[u8], approval: &ReimportApproval) -> Result<usize> {
        let rec = self.spec_source(import_id)?;
        let plan = self.spec_reimport_plan(import_id, bytes)?;
        let previous = self.linked_requests(&rec)?;
        let next = plan.apply(&previous, approval);
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
                s.put(kind::REQUEST, &q.meta.id, Some(&q.workspace_id), q.folder_id.as_ref(), q.sort_key, &q)?;
            }
            for id in &deleted {
                s.delete(kind::REQUEST, id)?;
            }
            let mut rec = rec.clone();
            rec.previous_import_ids.push(rec.source.import_id);
            rec.source.import_id = plan.import_id;
            s.delete(kind::SPEC_SOURCE, &rec.previous_import_ids[rec.previous_import_ids.len() - 1])?;
            s.put(kind::SPEC_SOURCE, &rec.source.import_id, Some(&rec.workspace_id), None, 0.0, &rec)?;
            Ok(())
        })?;
        Ok(next.len())
    }
}

/// The top-level folder an import into an existing workspace lands in. It
/// keeps the source's workspace-level scope (description, settings,
/// variables and auth), so the imported objects resolve as they would in a
/// workspace of their own. A source without auth of its own gets an
/// explicit "no auth" here: nothing above it was ever inherited, so the
/// destination workspace's auth must not be either.
fn root_folder(source: &Workspace, workspace_id: Id, name: &str) -> Folder {
    Folder {
        meta: Meta::new(),
        workspace_id,
        parent_id: None,
        name: name.trim().into(),
        description: source.description.clone(),
        sort_key: 0.0,
        settings: source.settings.clone(),
        variables: source.variables.clone(),
        auth: match &source.auth {
            AuthConfig::Inherit => AuthConfig::None,
            auth => auth.clone(),
        },
        tags: vec![],
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
