//! Workspace tree operations: workspaces, nested folders, requests with
//! immutable revisions, environments, profiles and secrets.

use crate::{App, AppError, Result};
use anvil_domain::Id;
use anvil_domain::auth::AuthConfig;
use anvil_domain::integration::IntegrationProfile;
use anvil_domain::request::RequestSpec;
use anvil_domain::secret::SecretRef;
use anvil_domain::tls::{ProxyProfile, TlsProfile};
use anvil_domain::workspace::*;
use anvil_storage::{StoreTx, kind};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::HashSet;

#[derive(Debug, Clone, Serialize)]
pub struct TreeNode {
    pub id: Id,
    pub kind: &'static str,
    pub name: String,
    pub method: Option<String>,
    pub url: Option<String>,
    pub favorite: bool,
    pub children: Vec<TreeNode>,
}

pub fn spec_hash(spec: &RequestSpec) -> String {
    hex::encode(Sha256::digest(serde_json::to_vec(spec).unwrap_or_default()))
}

impl App {
    // ------------------------------------------------------------ workspaces

    pub fn create_workspace(&self, name: &str) -> Result<Workspace> {
        let name = name.trim();
        if name.is_empty() {
            return Err(AppError::Invalid("workspace name is empty".into()));
        }
        let w = Workspace {
            meta: Meta::new(),
            name: name.into(),
            description: String::new(),
            settings: Default::default(),
            variables: vec![],
            auth: AuthConfig::None,
            active_environment_id: None,
        };
        self.store.put(kind::WORKSPACE, &w.meta.id, None, None, 0.0, &w)?;
        Ok(w)
    }

    pub fn workspaces(&self) -> Result<Vec<Workspace>> {
        let mut v: Vec<Workspace> = self.store.list(kind::WORKSPACE, None)?;
        v.sort_by_key(|a| a.name.to_lowercase());
        Ok(v)
    }

    pub fn workspace(&self, id: &Id) -> Result<Workspace> {
        self.store.get(kind::WORKSPACE, id)?.ok_or_else(|| AppError::NotFound("workspace".into()))
    }

    pub fn find_workspace(&self, id_or_name: &str) -> Result<Workspace> {
        self.workspaces()?
            .into_iter()
            .find(|w| w.meta.id.to_string() == id_or_name || w.name.eq_ignore_ascii_case(id_or_name))
            .ok_or_else(|| AppError::NotFound(format!("workspace '{id_or_name}'")))
    }

    pub fn save_workspace(&self, mut w: Workspace) -> Result<Workspace> {
        w.meta.updated_at = chrono::Utc::now();
        self.store.put(kind::WORKSPACE, &w.meta.id, None, None, 0.0, &w)?;
        Ok(w)
    }

    pub fn delete_workspace(&self, id: &Id) -> Result<()> {
        self.store.delete_workspace(id)?;
        self.engine.clear_isolation(&id.to_string());
        Ok(())
    }

    // ------------------------------------------------------------ folders

    pub fn folders(&self, ws: &Id) -> Result<Vec<Folder>> {
        Ok(self.store.list(kind::FOLDER, Some(ws))?)
    }

    pub fn folder(&self, id: &Id) -> Result<Folder> {
        self.store.get(kind::FOLDER, id)?.ok_or_else(|| AppError::NotFound("folder".into()))
    }

    pub fn create_folder(&self, ws: &Id, parent: Option<Id>, name: &str) -> Result<Folder> {
        self.workspace(ws)?;
        if let Some(p) = parent {
            let pf = self.folder(&p)?;
            if pf.workspace_id != *ws {
                return Err(AppError::Invalid("parent folder belongs to another workspace".into()));
            }
        }
        let siblings = self.folders(ws)?.into_iter().filter(|f| f.parent_id == parent).count();
        let f = Folder {
            meta: Meta::new(),
            workspace_id: *ws,
            parent_id: parent,
            name: name.trim().into(),
            description: String::new(),
            sort_key: siblings as f64 + 1.0,
            settings: Default::default(),
            variables: vec![],
            auth: AuthConfig::Inherit,
            tags: vec![],
            import_root: false,
            import_environment_ids: vec![],
            use_workspace_scope: false,
        };
        self.store.put(kind::FOLDER, &f.meta.id, Some(ws), parent.as_ref(), f.sort_key, &f)?;
        Ok(f)
    }

    /// Save a folder. Whether it is an import root, and whether that root is
    /// open to the workspace, are kept as stored: only a spec import makes
    /// an import root, and only [`App::set_import_root_workspace_scope`]
    /// opens one.
    pub fn save_folder(&self, mut f: Folder) -> Result<Folder> {
        let stored: Option<Folder> = self.store.get(kind::FOLDER, &f.meta.id)?;
        f.import_root = stored.as_ref().is_some_and(|s| s.import_root);
        f.import_environment_ids = stored.as_ref().map(|s| s.import_environment_ids.clone()).unwrap_or_default();
        f.use_workspace_scope = stored.as_ref().is_some_and(|s| s.use_workspace_scope);
        f.meta.updated_at = chrono::Utc::now();
        self.store.put(kind::FOLDER, &f.meta.id, Some(&f.workspace_id), f.parent_id.as_ref(), f.sort_key, &f)?;
        Ok(f)
    }

    /// The user's explicit choice on this device to let requests under an
    /// import root also resolve the workspace's variables, active
    /// environment and auth, and this device's workload identity and token
    /// files (`Folder::use_workspace_scope`). An import never sets this.
    pub fn set_import_root_workspace_scope(&self, id: &Id, allow: bool) -> Result<Folder> {
        let mut f = self.folder(id)?;
        if !f.import_root {
            return Err(AppError::Invalid("only the root folder of an imported collection has a scope of its own".into()));
        }
        f.use_workspace_scope = allow;
        f.meta.updated_at = chrono::Utc::now();
        self.store.put(kind::FOLDER, &f.meta.id, Some(&f.workspace_id), f.parent_id.as_ref(), f.sort_key, &f)?;
        Ok(f)
    }

    /// Move a folder under a new parent (None = root) at `sort_key`,
    /// refusing moves that would create an ancestry cycle.
    pub fn move_folder(&self, id: &Id, new_parent: Option<Id>, sort_key: f64) -> Result<Folder> {
        let mut f = self.folder(id)?;
        if let Some(p) = new_parent {
            let mut cur = Some(p);
            while let Some(c) = cur {
                if c == *id {
                    return Err(AppError::Invalid("a folder cannot be moved into itself or one of its subfolders".into()));
                }
                cur = self.folder(&c)?.parent_id;
            }
            if self.folder(&p)?.workspace_id != f.workspace_id {
                return Err(AppError::Invalid("cannot move a folder to another workspace".into()));
            }
        }
        f.parent_id = new_parent;
        f.sort_key = sort_key;
        self.save_folder(f)
    }

    /// Ancestor chain root → leaf (inclusive).
    pub fn folder_chain(&self, id: Option<Id>) -> Result<Vec<Folder>> {
        let mut chain = Vec::new();
        let mut cur = id;
        let mut guard = 0;
        while let Some(c) = cur {
            let f = self.folder(&c)?;
            cur = f.parent_id;
            chain.push(f);
            guard += 1;
            if guard > 256 {
                return Err(AppError::Invalid("folder ancestry is too deep or cyclic".into()));
            }
        }
        chain.reverse();
        Ok(chain)
    }

    /// Delete a folder, its subfolders and their requests.
    pub fn delete_folder(&self, id: &Id) -> Result<()> {
        // Read the folder and its tree inside the transaction, so a folder or
        // request created under a doomed folder meanwhile is deleted with it,
        // not orphaned.
        let deleted = self.store.atomically(|s| {
            let Some(f) = s.get::<Folder>(kind::FOLDER, id)? else { return Ok(false) };
            let all: Vec<Folder> = s.list(kind::FOLDER, Some(&f.workspace_id))?;
            // `seen` stops the walk at a parent cycle (possible in saved or
            // imported data) instead of looping forever.
            let mut seen = HashSet::from([*id]);
            let mut doomed = vec![*id];
            let mut i = 0;
            while i < doomed.len() {
                let cur = doomed[i];
                doomed.extend(all.iter().filter(|x| x.parent_id == Some(cur) && seen.insert(x.meta.id)).map(|x| x.meta.id));
                i += 1;
            }
            let reqs: Vec<RequestDefinition> = s.list(kind::REQUEST, Some(&f.workspace_id))?;
            for r in reqs.iter().filter(|r| r.folder_id.is_some_and(|fid| seen.contains(&fid))) {
                s.delete(kind::REQUEST, &r.meta.id)?;
            }
            for d in &doomed {
                s.delete(kind::FOLDER, d)?;
            }
            Ok(true)
        })?;
        if !deleted {
            return Err(AppError::NotFound("folder".into()));
        }
        Ok(())
    }

    // ------------------------------------------------------------ requests

    pub fn requests(&self, ws: &Id) -> Result<Vec<RequestDefinition>> {
        Ok(self.store.list(kind::REQUEST, Some(ws))?)
    }

    pub fn request(&self, id: &Id) -> Result<RequestDefinition> {
        self.store.get(kind::REQUEST, id)?.ok_or_else(|| AppError::NotFound("request".into()))
    }

    pub fn create_request(&self, ws: &Id, folder: Option<Id>, name: &str, spec: RequestSpec) -> Result<RequestDefinition> {
        self.workspace(ws)?;
        if let Some(f) = folder
            && self.folder(&f)?.workspace_id != *ws
        {
            return Err(AppError::Invalid("folder belongs to another workspace".into()));
        }
        let n = self.requests(ws)?.into_iter().filter(|r| r.folder_id == folder).count();
        let r = RequestDefinition {
            meta: Meta::new(),
            workspace_id: *ws,
            folder_id: folder,
            name: name.trim().into(),
            description: String::new(),
            tags: vec![],
            favorite: false,
            sort_key: n as f64 + 1.0,
            spec,
            revision_id: None,
        };
        self.save_request(r)
    }

    /// Explicit save: persists the definition and appends an immutable revision
    /// when the spec changed.
    pub fn save_request(&self, mut r: RequestDefinition) -> Result<RequestDefinition> {
        let hash = spec_hash(&r.spec);
        let prev: Option<RequestRevision> = match r.revision_id {
            Some(rid) => self.store.get(kind::REVISION, &rid)?,
            None => None,
        };
        if prev.as_ref().map(|p| p.spec_sha256 != hash).unwrap_or(true) {
            let rev = RequestRevision {
                id: Id::new(),
                request_id: r.meta.id,
                created_at: chrono::Utc::now(),
                spec_sha256: hash,
                spec: r.spec.clone(),
            };
            self.store.put(kind::REVISION, &rev.id, Some(&r.workspace_id), Some(&r.meta.id), 0.0, &rev)?;
            r.revision_id = Some(rev.id);
        }
        r.meta.updated_at = chrono::Utc::now();
        self.store.put(kind::REQUEST, &r.meta.id, Some(&r.workspace_id), r.folder_id.as_ref(), r.sort_key, &r)?;
        Ok(r)
    }

    pub fn revision(&self, id: &Id) -> Result<RequestRevision> {
        self.store.get(kind::REVISION, id)?.ok_or_else(|| AppError::NotFound("revision".into()))
    }

    pub fn move_request(&self, id: &Id, folder: Option<Id>, sort_key: f64) -> Result<RequestDefinition> {
        let mut r = self.request(id)?;
        if let Some(f) = folder
            && self.folder(&f)?.workspace_id != r.workspace_id
        {
            return Err(AppError::Invalid("cannot move a request to another workspace".into()));
        }
        r.folder_id = folder;
        r.sort_key = sort_key;
        self.save_request(r)
    }

    pub fn duplicate_request(&self, id: &Id) -> Result<RequestDefinition> {
        let r = self.request(id)?;
        self.create_request(&r.workspace_id, r.folder_id, &format!("{} (copy)", r.name), r.spec.clone())
    }

    pub fn delete_request(&self, id: &Id) -> Result<()> {
        self.store.delete(kind::REQUEST, id)?;
        Ok(())
    }

    /// Find a request by id, name or `Folder/Sub/Name` path.
    pub fn find_request(&self, ws: &Id, key: &str) -> Result<RequestDefinition> {
        let reqs = self.requests(ws)?;
        if let Some(r) = reqs.iter().find(|r| r.meta.id.to_string() == key) {
            return Ok(r.clone());
        }
        let folders = self.folders(ws)?;
        let path_of = |r: &RequestDefinition| -> String {
            let mut parts = vec![r.name.clone()];
            let mut cur = r.folder_id;
            while let Some(c) = cur {
                match folders.iter().find(|f| f.meta.id == c) {
                    Some(f) => {
                        parts.push(f.name.clone());
                        cur = f.parent_id;
                    }
                    None => break,
                }
            }
            parts.reverse();
            parts.join("/")
        };
        let matches: Vec<&RequestDefinition> =
            reqs.iter().filter(|r| r.name.eq_ignore_ascii_case(key) || path_of(r).eq_ignore_ascii_case(key)).collect();
        match matches.as_slice() {
            [one] => Ok((*one).clone()),
            [] => Err(AppError::NotFound(format!("request '{key}'"))),
            _ => Err(AppError::Invalid(format!("'{key}' matches several requests; use the folder path or id"))),
        }
    }

    pub fn search(&self, ws: &Id, query: &str) -> Result<Vec<RequestDefinition>> {
        let q = query.to_lowercase();
        Ok(self
            .requests(ws)?
            .into_iter()
            .filter(|r| {
                r.name.to_lowercase().contains(&q)
                    || r.spec.url.to_lowercase().contains(&q)
                    || r.tags.iter().any(|t| t.to_lowercase().contains(&q))
            })
            .collect())
    }

    pub fn tree(&self, ws: &Id) -> Result<Vec<TreeNode>> {
        let folders = self.folders(ws)?;
        let reqs = self.requests(ws)?;
        fn build(parent: Option<Id>, folders: &[Folder], reqs: &[RequestDefinition], depth: usize) -> Vec<TreeNode> {
            if depth > 64 {
                return vec![];
            }
            let mut fs: Vec<&Folder> = folders.iter().filter(|f| f.parent_id == parent).collect();
            fs.sort_by(|a, b| a.sort_key.partial_cmp(&b.sort_key).unwrap_or(std::cmp::Ordering::Equal));
            let mut out: Vec<TreeNode> = fs
                .iter()
                .map(|f| TreeNode {
                    id: f.meta.id,
                    kind: "folder",
                    name: f.name.clone(),
                    method: None,
                    url: None,
                    favorite: false,
                    children: build(Some(f.meta.id), folders, reqs, depth + 1),
                })
                .collect();
            let mut rs: Vec<&RequestDefinition> = reqs.iter().filter(|r| r.folder_id == parent).collect();
            rs.sort_by(|a, b| a.sort_key.partial_cmp(&b.sort_key).unwrap_or(std::cmp::Ordering::Equal));
            out.extend(rs.iter().map(|r| TreeNode {
                id: r.meta.id,
                kind: "request",
                name: r.name.clone(),
                method: Some(r.spec.method.clone()),
                url: Some(r.spec.url.clone()),
                favorite: r.favorite,
                children: vec![],
            }));
            out
        }
        Ok(build(None, &folders, &reqs, 0))
    }

    // ------------------------------------------------------------ environments

    pub fn environments(&self, ws: &Id) -> Result<Vec<Environment>> {
        Ok(self.store.list(kind::ENVIRONMENT, Some(ws))?)
    }

    pub fn save_environment(&self, mut e: Environment) -> Result<Environment> {
        e.meta.updated_at = chrono::Utc::now();
        self.store.put(kind::ENVIRONMENT, &e.meta.id, Some(&e.workspace_id), None, 0.0, &e)?;
        Ok(e)
    }

    pub fn create_environment(&self, ws: &Id, name: &str, vars: Vec<Variable>) -> Result<Environment> {
        self.save_environment(Environment { meta: Meta::new(), workspace_id: *ws, name: name.into(), variables: vars })
    }

    pub fn delete_environment(&self, id: &Id) -> Result<()> {
        self.store.delete(kind::ENVIRONMENT, id)?;
        Ok(())
    }

    // ------------------------------------------------------------ secrets

    pub fn set_secret(&self, ws: Option<&Id>, label: &str, value: &str) -> Result<SecretRef> {
        let id = Id::new();
        self.store.put_secret(&id, ws, label, value)?;
        Ok(SecretRef { id, label: label.into() })
    }

    pub fn update_secret(&self, r: &SecretRef, ws: Option<&Id>, value: &str) -> Result<()> {
        self.store.put_secret(&r.id, ws, &r.label, value)?;
        Ok(())
    }

    // ------------------------------------------------------------ profiles

    pub fn tls_profiles(&self, ws: &Id) -> Result<Vec<TlsProfile>> {
        Ok(self.store.list(kind::TLS_PROFILE, Some(ws))?)
    }

    pub fn save_tls_profile(&self, mut p: TlsProfile) -> Result<TlsProfile> {
        p.updated_at = chrono::Utc::now();
        self.store.put(kind::TLS_PROFILE, &p.id, Some(&p.workspace_id), None, 0.0, &p)?;
        Ok(p)
    }

    pub fn proxy_profiles(&self, ws: &Id) -> Result<Vec<ProxyProfile>> {
        Ok(self.store.list(kind::PROXY_PROFILE, Some(ws))?)
    }

    pub fn save_proxy_profile(&self, mut p: ProxyProfile) -> Result<ProxyProfile> {
        p.updated_at = chrono::Utc::now();
        self.store.put(kind::PROXY_PROFILE, &p.id, Some(&p.workspace_id), None, 0.0, &p)?;
        Ok(p)
    }

    pub fn integrations(&self, ws: &Id) -> Result<Vec<IntegrationProfile>> {
        Ok(self.store.list(kind::INTEGRATION, Some(ws))?)
    }

    pub fn save_integration(&self, mut p: IntegrationProfile) -> Result<IntegrationProfile> {
        p.updated_at = chrono::Utc::now();
        self.store.put(kind::INTEGRATION, &p.id, Some(&p.workspace_id), None, 0.0, &p)?;
        Ok(p)
    }

    pub fn scenarios(&self, ws: &Id) -> Result<Vec<Scenario>> {
        Ok(self.store.list(kind::SCENARIO, Some(ws))?)
    }

    pub fn save_scenario(&self, s: Scenario) -> Result<Scenario> {
        self.store.put(kind::SCENARIO, &s.meta.id, Some(&s.workspace_id), None, 0.0, &s)?;
        Ok(s)
    }

    pub fn datasets(&self, ws: &Id) -> Result<Vec<Dataset>> {
        Ok(self.store.list(kind::DATASET, Some(ws))?)
    }

    pub fn save_dataset(&self, d: Dataset) -> Result<Dataset> {
        self.store.put(kind::DATASET, &d.meta.id, Some(&d.workspace_id), None, 0.0, &d)?;
        Ok(d)
    }

    /// Store an attachment (content-addressed by sha256). The blob, its pin
    /// and its index entry are written together or not at all.
    pub fn put_attachment(
        &self,
        file_name: &str,
        bytes: &[u8],
        media_type: Option<String>,
    ) -> Result<anvil_domain::request::AttachmentRef> {
        Ok(self.store.atomically(|s| put_attachment_in(s, file_name, bytes, media_type))?)
    }

    /// Pin the blob of every stored attachment (idempotent). Profiles created
    /// before blobs were pinned could lose attachments to history retention;
    /// this protects whatever is still there.
    pub(crate) fn pin_attachment_blobs(&self) -> Result<()> {
        let idx: Vec<serde_json::Value> = self.store.list(kind::IMPORT_SOURCE, None)?;
        for i in idx {
            if let (Some(_), Some(blob)) = (i.get("attachment"), i.get("blob").and_then(|b| b.as_str())) {
                self.store.pin_blob(blob)?;
            }
        }
        Ok(())
    }

    /// Delete a stored attachment once nothing references it any more.
    /// Content addressing means several requests, revisions, datasets or spec
    /// sources can share one attachment, so every object that can hold one is
    /// checked first. Returns whether it was deleted.
    pub fn release_attachment(&self, sha256: &str) -> Result<bool> {
        for k in [kind::REQUEST, kind::REVISION, kind::DATASET, kind::SPEC_SOURCE, kind::SCENARIO, kind::LOAD_PLAN] {
            let objects: Vec<serde_json::Value> = self.store.list(k, None)?;
            if objects.iter().any(|o| o.to_string().contains(sha256)) {
                return Ok(false);
            }
        }
        let id = attachment_index_id(sha256);
        let idx: Option<serde_json::Value> = self.store.get(kind::IMPORT_SOURCE, &id)?;
        let Some(idx) = idx else { return Ok(false) };
        if let Some(blob) = idx.get("blob").and_then(|b| b.as_str()) {
            self.store.release_blob(blob)?;
        }
        self.store.delete(kind::IMPORT_SOURCE, &id)?;
        Ok(true)
    }

    pub fn get_attachment(&self, sha256: &str) -> Result<Option<Vec<u8>>> {
        let idx: Option<serde_json::Value> = self.store.get(kind::IMPORT_SOURCE, &attachment_index_id(sha256))?;
        let Some(idx) = idx else { return Ok(None) };
        let blob = idx.get("blob").and_then(|b| b.as_str()).unwrap_or_default().to_string();
        Ok(self.store.get_blob(&blob)?.map(|z| z.to_vec()))
    }
}

/// [`App::put_attachment`] inside the caller's transaction, so the stored
/// attachment is rolled back with everything else the caller writes.
pub(crate) fn put_attachment_in(
    s: &StoreTx<'_>,
    file_name: &str,
    bytes: &[u8],
    media_type: Option<String>,
) -> anvil_storage::store::Result<anvil_domain::request::AttachmentRef> {
    let sha = hex::encode(Sha256::digest(bytes));
    let blob = s.put_blob(bytes)?;
    s.pin_blob(&blob)?;
    s.put(kind::IMPORT_SOURCE, &attachment_index_id(&sha), None, None, 0.0, &serde_json::json!({"attachment": sha, "blob": blob}))?;
    Ok(anvil_domain::request::AttachmentRef::Stored { sha256: sha, size: bytes.len() as u64, file_name: file_name.into(), media_type })
}

/// Deterministic object id for the attachment index entry of a content hash.
fn attachment_index_id(sha: &str) -> Id {
    let d = Sha256::digest(format!("anvil-attachment-index:{sha}").as_bytes());
    let mut b = [0u8; 16];
    b.copy_from_slice(&d[..16]);
    Id(uuid::Builder::from_custom_bytes(b).into_uuid())
}
