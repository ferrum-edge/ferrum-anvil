//! Workspace tree operations: workspaces, nested folders, requests with
//! immutable revisions, environments, profiles and secrets.

use crate::cleanup::{ATTACHMENT_GRACE, UndecodableObject};
use crate::{App, AppError, Result};
use anvil_domain::Id;
use anvil_domain::auth::AuthConfig;
use anvil_domain::integration::IntegrationProfile;
use anvil_domain::request::{AttachmentRef, Protocol, RequestSpec};
use anvil_domain::secret::SecretRef;
use anvil_domain::tls::{ProxyProfile, TlsProfile};
use anvil_domain::workspace::*;
use anvil_storage::{StoreError, StoreRead, StoreTx, kind};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

#[derive(Debug, Clone, Serialize)]
pub struct TreeNode {
    pub id: Id,
    pub kind: &'static str,
    pub name: String,
    pub method: Option<String>,
    /// Wire protocol of a request (none for a folder), so a tree can label a
    /// WebSocket, gRPC, SSE, TCP or UDP request instead of showing its method.
    pub protocol: Option<Protocol>,
    pub url: Option<String>,
    pub favorite: bool,
    pub children: Vec<TreeNode>,
}

/// What a move checked against import isolation did.
#[derive(Debug)]
pub enum Move<T> {
    Moved(T),
    /// Refused, with nothing written: the move would take what it moves out
    /// of this import root, which is not open to its workspace, and the
    /// caller did not confirm leaving it. Out of it, a request resolves the
    /// workspace's variables, environment and auth, as opening the root does
    /// ([`App::set_import_root_workspace_scope`]).
    LeavesImport(Box<Folder>),
}

impl<T> Move<T> {
    /// What a move that could leave every import root moved.
    fn moved(self) -> T {
        match self {
            Move::Moved(t) => t,
            Move::LeavesImport(_) => unreachable!("every import root may be left"),
        }
    }
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

    /// Delete a workspace with everything in it, and release the stored
    /// files its items held that no item of another workspace references,
    /// in one write transaction. A file a user attached within
    /// [`ATTACHMENT_GRACE`] is kept: a request or dataset of another
    /// workspace not saved yet may hold it, and the cleanup of files attached
    /// and never saved decides it once the period is over. Its load runs are
    /// then stopped, and the engine drops its connections, sessions, OAuth
    /// tokens and other cached state.
    pub fn delete_workspace(&self, id: &Id) -> Result<()> {
        let cutoff = grace_cutoff();
        self.store.atomically(|s| {
            let entries = attachment_entries_in(&s.as_read())?;
            let stored = entries.into_iter().filter(|e| !attached_recently(e, cutoff)).map(|e| e.attachment).collect();
            let held = workspace_attachments_in(s, id, stored)?;
            s.delete_workspace(id)?;
            for sha in unreferenced_in(s, held)? {
                drop_attachment_in(s, &sha)?;
            }
            Ok(())
        })?;
        // Only after the storage delete is committed. A context built for the
        // workspace takes its epoch before it reads the workspace from
        // storage (`App::build_context`), and the engine keeps nothing for
        // an epoch taken before `clear_isolation`: a build that still read
        // the workspace then keeps nothing either. Cleared first, a build
        // between the clear and the commit would take a post-delete epoch
        // and keep cookies, tokens and connections for the deleted workspace
        // that a workspace restored with the same id would pick up. A delete
        // that fails leaves the engine as it was.
        self.stop_load_runs_of(id);
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
        let mut f = Folder {
            meta: Meta::new(),
            workspace_id: *ws,
            parent_id: parent,
            name: name.trim().into(),
            description: String::new(),
            sort_key: 0.0,
            settings: Default::default(),
            variables: vec![],
            auth: AuthConfig::Inherit,
            tags: vec![],
            import_root: false,
            import_environment_ids: vec![],
            use_workspace_scope: false,
        };
        self.store.atomically(|s| {
            validate_folder_parent_in(s, ws, parent)?;
            let siblings: Vec<Folder> = s.list(kind::FOLDER, Some(ws))?;
            f.sort_key = siblings.iter().filter(|f| f.parent_id == parent).count() as f64 + 1.0;
            s.put(kind::FOLDER, &f.meta.id, Some(ws), parent.as_ref(), f.sort_key, &f)
        })?;
        Ok(f)
    }

    /// Save a folder. Whether it is an import root, and whether that root is
    /// open to the workspace, are kept as stored: only a spec import makes
    /// an import root, and only [`App::set_import_root_workspace_scope`]
    /// opens one.
    pub fn save_folder(&self, f: Folder) -> Result<Folder> {
        self.save_folder_with(f, false)
    }

    /// [`App::save_folder`] that keeps a stored folder under its stored
    /// parent: it moves only through [`App::move_folder_keeping_isolation`],
    /// which checks what the move takes out of an import root.
    pub fn save_folder_in_place(&self, f: Folder) -> Result<Folder> {
        self.save_folder_with(f, true)
    }

    fn save_folder_with(&self, mut f: Folder, in_place: bool) -> Result<Folder> {
        self.store.atomically(|s| {
            let stored: Option<Folder> = s.get(kind::FOLDER, &f.meta.id)?;
            if in_place && let Some(stored) = &stored {
                f.parent_id = stored.parent_id;
            }
            validate_folder_parent_in(s, &f.workspace_id, f.parent_id)?;
            f.import_root = stored.as_ref().is_some_and(|s| s.import_root);
            f.import_environment_ids = stored.as_ref().map(|s| s.import_environment_ids.clone()).unwrap_or_default();
            f.use_workspace_scope = stored.as_ref().is_some_and(|s| s.use_workspace_scope);
            f.meta.updated_at = chrono::Utc::now();
            s.put(kind::FOLDER, &f.meta.id, Some(&f.workspace_id), f.parent_id.as_ref(), f.sort_key, &f)
        })?;
        Ok(f)
    }

    /// The user's explicit choice on this device to let requests under an
    /// import root also resolve the workspace's variables, active
    /// environment and auth, and this device's workload identity and token
    /// files (`Folder::use_workspace_scope`). An import never sets this.
    pub fn set_import_root_workspace_scope(&self, id: &Id, allow: bool) -> Result<Folder> {
        self.store.atomically(|s| {
            let Some(mut f) = s.get::<Folder>(kind::FOLDER, id)? else {
                return Ok(Err(AppError::NotFound("folder".into())));
            };
            if !f.import_root {
                return Ok(Err(AppError::Invalid("only the root folder of an imported collection has a scope of its own".into())));
            }
            f.use_workspace_scope = allow;
            f.meta.updated_at = chrono::Utc::now();
            s.put(kind::FOLDER, &f.meta.id, Some(&f.workspace_id), f.parent_id.as_ref(), f.sort_key, &f)?;
            Ok(Ok(f))
        })?
    }

    /// Move a folder under a new parent (None = root) at `sort_key`,
    /// refusing moves that would create an ancestry cycle.
    pub fn move_folder(&self, id: &Id, new_parent: Option<Id>, sort_key: f64) -> Result<Folder> {
        self.move_folder_guarded(id, new_parent, sort_key, |_| true).map(Move::moved)
    }

    /// [`App::move_folder`], refused with [`Move::LeavesImport`] when it
    /// would take the folder's contents out of an import root that is not
    /// open to its workspace, unless that root is `may_leave`. Moving an
    /// import root itself takes nothing out of it.
    pub fn move_folder_keeping_isolation(
        &self,
        id: &Id,
        new_parent: Option<Id>,
        sort_key: f64,
        may_leave: Option<Id>,
    ) -> Result<Move<Folder>> {
        self.move_folder_guarded(id, new_parent, sort_key, |root| Some(root.meta.id) == may_leave)
    }

    fn move_folder_guarded(
        &self,
        id: &Id,
        new_parent: Option<Id>,
        sort_key: f64,
        may_leave: impl Fn(&Folder) -> bool,
    ) -> Result<Move<Folder>> {
        // Check the ancestry and save in one transaction, so two concurrent
        // moves (a under b and b under a) cannot both pass the check.
        self.store.atomically(|s| {
            let Some(mut f) = s.get::<Folder>(kind::FOLDER, id)? else { return Ok(Err(AppError::NotFound("folder".into()))) };
            if let Some(p) = new_parent {
                // `seen` stops the walk at a parent cycle already in saved or
                // imported data instead of looping forever.
                let mut seen = HashSet::new();
                let mut cur = Some(p);
                while let Some(c) = cur {
                    if c == *id {
                        return Ok(Err(AppError::Invalid("a folder cannot be moved into itself or one of its subfolders".into())));
                    }
                    if !seen.insert(c) {
                        return Ok(Err(AppError::Invalid("the target folder's ancestry is cyclic".into())));
                    }
                    let Some(a) = s.get::<Folder>(kind::FOLDER, &c)? else { return Ok(Err(AppError::NotFound("folder".into()))) };
                    if a.workspace_id != f.workspace_id {
                        return Ok(Err(AppError::Invalid("cannot move a folder to another workspace".into())));
                    }
                    cur = a.parent_id;
                }
            }
            if !f.import_root
                && let Some(root) = leaves_import_in(s, f.parent_id, new_parent)?.filter(|root| !may_leave(root))
            {
                return Ok(Ok(Move::LeavesImport(Box::new(root))));
            }
            f.parent_id = new_parent;
            f.sort_key = sort_key;
            f.meta.updated_at = chrono::Utc::now();
            s.put(kind::FOLDER, &f.meta.id, Some(&f.workspace_id), f.parent_id.as_ref(), f.sort_key, &f)?;
            Ok(Ok(Move::Moved(f)))
        })?
    }

    /// Ancestor chain root → leaf (inclusive); every folder must be in `ws`.
    pub fn folder_chain(&self, ws: &Id, id: Option<Id>) -> Result<Vec<Folder>> {
        let mut chain = Vec::new();
        let mut cur = id;
        let mut guard = 0;
        while let Some(c) = cur {
            let f = self.folder(&c)?;
            // Folder settings, auth and variables apply only inside their own
            // workspace; a parent id that names another workspace's folder
            // is refused rather than followed.
            if f.workspace_id != *ws {
                return Err(AppError::Invalid(format!("folder '{}' is not in this workspace", f.name)));
            }
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

    /// Delete a folder, its subfolders and their requests, and release the
    /// stored files those requests held as [`App::delete_request`] does.
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
            let reqs: Vec<RequestDefinition> = reqs.into_iter().filter(|r| r.folder_id.is_some_and(|fid| seen.contains(&fid))).collect();
            delete_requests_in(s, &reqs)?;
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

    /// Create a request in `folder` of workspace `ws`, after the requests
    /// already there. That the workspace and the folder exist and belong
    /// together is checked in the write transaction that stores the request,
    /// so a delete of either that commits first refuses the create and one
    /// that commits later deletes the request with them: a request is never
    /// left under a deleted workspace or folder.
    pub fn create_request(&self, ws: &Id, folder: Option<Id>, name: &str, spec: RequestSpec) -> Result<RequestDefinition> {
        self.create_request_between_phases(ws, folder, name, spec, || {})
    }

    /// [`App::create_request`], calling `between` before its write
    /// transaction, so a test can write where another connection could. Not
    /// for other callers.
    #[doc(hidden)]
    pub fn create_request_between_phases(
        &self,
        ws: &Id,
        folder: Option<Id>,
        name: &str,
        spec: RequestSpec,
        between: impl FnOnce(),
    ) -> Result<RequestDefinition> {
        between();
        self.create_request_holding(ws, folder, name, spec, None)
    }

    /// [`App::create_request`], where the stored files `also` names count as
    /// held already (see [`App::save_request`]). The request is placed in
    /// [`App::save_request_holding`], in its write transaction.
    fn create_request_holding(
        &self,
        ws: &Id,
        folder: Option<Id>,
        name: &str,
        spec: RequestSpec,
        also: Option<&RequestSpec>,
    ) -> Result<RequestDefinition> {
        let r = RequestDefinition {
            meta: Meta::new(),
            workspace_id: *ws,
            folder_id: folder,
            name: name.trim().into(),
            description: String::new(),
            tags: vec![],
            favorite: false,
            sort_key: 0.0,
            spec,
            revision_id: None,
        };
        self.save_request_holding(r, also, true)
    }

    /// Explicit save: persists the definition and appends an immutable revision
    /// when the spec changed. A stored attachment the saved request did not
    /// hold yet must still be stored: a file released between being attached
    /// and this save is refused, so the request never names content that is
    /// gone. The check and the save run in one write transaction.
    ///
    /// A save never places a request that is already stored: it keeps the
    /// folder and position the store holds, read in the same transaction.
    /// A changed workspace is refused. The editor's copy may predate a move
    /// ([`App::move_request`]), which writing back its placement would undo.
    /// A new request is placed where `r` puts it.
    ///
    /// Only a stored request is saved: one that is not stored is refused, not
    /// recreated. The editor's copy may outlive the request, its folder or
    /// its workspace, and recreating it could file it under a deleted folder
    /// or another workspace's. New requests come from [`App::create_request`]
    /// and [`App::duplicate_request`].
    pub fn save_request(&self, r: RequestDefinition) -> Result<RequestDefinition> {
        self.save_request_holding(r, None, false)
    }

    /// [`App::save_request`], where the stored files `also` names count as
    /// held already: those of the request a duplicate copies, which it may
    /// name even when one of them is no longer stored. With `new`, `r` is a
    /// request [`App::create_request`] made, stored here for the first time:
    /// its workspace and folder are checked and it is placed after the
    /// requests already there, in the same transaction.
    fn save_request_holding(&self, mut r: RequestDefinition, also: Option<&RequestSpec>, new: bool) -> Result<RequestDefinition> {
        let hash = spec_hash(&r.spec);
        let spec = serde_json::to_value(&r.spec)?;
        let also = also.map(serde_json::to_value).transpose()?;
        self.store.atomically(|s| {
            let held: Option<RequestDefinition> = s.get(kind::REQUEST, &r.meta.id)?;
            match &held {
                Some(h) => {
                    if r.workspace_id != h.workspace_id {
                        return Err(StoreError::Ownership);
                    }
                    (r.folder_id, r.sort_key) = (h.folder_id, h.sort_key);
                }
                None if !new => return Ok(Err(AppError::NotFound("request (it was deleted)".into()))),
                None => {
                    if s.get::<Workspace>(kind::WORKSPACE, &r.workspace_id)?.is_none() {
                        return Ok(Err(AppError::NotFound("workspace".into())));
                    }
                    if let Some(f) = r.folder_id {
                        let Some(f) = s.get::<Folder>(kind::FOLDER, &f)? else { return Ok(Err(AppError::NotFound("folder".into()))) };
                        if f.workspace_id != r.workspace_id {
                            return Ok(Err(AppError::Invalid("folder belongs to another workspace".into())));
                        }
                    }
                    let siblings: Vec<RequestDefinition> = s.list(kind::REQUEST, Some(&r.workspace_id))?;
                    r.sort_key = siblings.iter().filter(|q| q.folder_id == r.folder_id).count() as f64 + 1.0;
                }
            }
            let mut held: Vec<serde_json::Value> = held.map(|h| serde_json::to_value(&h.spec)).transpose()?.into_iter().collect();
            held.extend(also);
            if let Some(gone) = first_unstored_attachment_in(s, &spec, &held)? {
                return Ok(Err(unstored(&gone)));
            }
            let prev: Option<RequestRevision> = match r.revision_id {
                Some(rid) => s.get(kind::REVISION, &rid)?,
                None => None,
            };
            if prev.as_ref().is_some_and(|p| p.request_id != r.meta.id) {
                return Err(StoreError::Ownership);
            }
            if prev.as_ref().map(|p| p.spec_sha256 != hash).unwrap_or(true) {
                // Revisions authenticate ownership through the sealed parent
                // request. Create that parent first, in this same transaction.
                // Any later failure rolls both rows back.
                if new {
                    s.put(kind::REQUEST, &r.meta.id, Some(&r.workspace_id), r.folder_id.as_ref(), r.sort_key, &r)?;
                }
                let rev = RequestRevision {
                    id: Id::new(),
                    request_id: r.meta.id,
                    created_at: chrono::Utc::now(),
                    spec_sha256: hash,
                    spec: r.spec.clone(),
                };
                s.put(kind::REVISION, &rev.id, Some(&r.workspace_id), Some(&r.meta.id), 0.0, &rev)?;
                r.revision_id = Some(rev.id);
            }
            r.meta.updated_at = chrono::Utc::now();
            s.put(kind::REQUEST, &r.meta.id, Some(&r.workspace_id), r.folder_id.as_ref(), r.sort_key, &r)?;
            Ok(Ok(()))
        })??;
        Ok(r)
    }

    pub fn revision(&self, id: &Id) -> Result<RequestRevision> {
        self.store.get(kind::REVISION, id)?.ok_or_else(|| AppError::NotFound("revision".into()))
    }

    /// Move a request to `folder` of its own workspace at `sort_key`. Only
    /// the placement changes: the request is read and written back in one
    /// write transaction, so a save or a linked-file relocation of it that
    /// lands meanwhile is kept, never replaced by an older copy.
    pub fn move_request(&self, id: &Id, folder: Option<Id>, sort_key: f64) -> Result<RequestDefinition> {
        self.move_request_guarded(id, folder, sort_key, |_| true).map(Move::moved)
    }

    /// [`App::move_request`], refused with [`Move::LeavesImport`] when it
    /// would take the request out of an import root that is not open to its
    /// workspace, unless that root is `may_leave`.
    pub fn move_request_keeping_isolation(
        &self,
        id: &Id,
        folder: Option<Id>,
        sort_key: f64,
        may_leave: Option<Id>,
    ) -> Result<Move<RequestDefinition>> {
        self.move_request_guarded(id, folder, sort_key, |root| Some(root.meta.id) == may_leave)
    }

    fn move_request_guarded(
        &self,
        id: &Id,
        folder: Option<Id>,
        sort_key: f64,
        may_leave: impl Fn(&Folder) -> bool,
    ) -> Result<Move<RequestDefinition>> {
        self.store.atomically(|s| {
            let Some(mut r) = s.get::<RequestDefinition>(kind::REQUEST, id)? else {
                return Ok(Err(AppError::NotFound("request".into())));
            };
            if let Some(f) = folder {
                let Some(f) = s.get::<Folder>(kind::FOLDER, &f)? else { return Ok(Err(AppError::NotFound("folder".into()))) };
                if f.workspace_id != r.workspace_id {
                    return Ok(Err(AppError::Invalid("cannot move a request to another workspace".into())));
                }
            }
            if let Some(root) = leaves_import_in(s, r.folder_id, folder)?.filter(|root| !may_leave(root)) {
                return Ok(Ok(Move::LeavesImport(Box::new(root))));
            }
            r.folder_id = folder;
            r.sort_key = sort_key;
            r.meta.updated_at = chrono::Utc::now();
            s.put(kind::REQUEST, &r.meta.id, Some(&r.workspace_id), r.folder_id.as_ref(), r.sort_key, &r)?;
            Ok(Ok(Move::Moved(r)))
        })?
    }

    /// Save a copy of a request. The copy names the stored files the request
    /// holds, stored or not.
    pub fn duplicate_request(&self, id: &Id) -> Result<RequestDefinition> {
        self.duplicate_request_between_phases(id, || {})
    }

    /// [`App::duplicate_request`], calling `between` after it reads the
    /// request and before its write transaction, so a test can write where
    /// another connection could. Not for other callers.
    #[doc(hidden)]
    pub fn duplicate_request_between_phases(&self, id: &Id, between: impl FnOnce()) -> Result<RequestDefinition> {
        let r = self.request(id)?;
        between();
        self.create_request_holding(&r.workspace_id, r.folder_id, &format!("{} (copy)", r.name), r.spec.clone(), Some(&r.spec))
    }

    /// Delete a request with its revisions, and release the stored
    /// attachments it held that nothing else references any more, in one
    /// write transaction. A file a user attached within [`ATTACHMENT_GRACE`]
    /// is kept: a request or dataset not saved yet may hold it, and the
    /// cleanup of files attached and never saved decides it once the period
    /// is over.
    pub fn delete_request(&self, id: &Id) -> Result<()> {
        self.store.atomically(|s| match s.get::<RequestDefinition>(kind::REQUEST, id)? {
            Some(r) => delete_requests_in(s, &[r]),
            None => Ok(()),
        })?;
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
            // `seen` stops the walk at a parent cycle (possible in saved or
            // imported data) instead of looping forever.
            let mut seen = HashSet::new();
            while let Some(c) = cur
                && seen.insert(c)
            {
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
                    protocol: None,
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
                protocol: Some(r.spec.protocol),
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
        self.store.atomically(|s| {
            let Some(env) = s.get::<Environment>(kind::ENVIRONMENT, id)? else { return Ok(()) };
            s.delete(kind::ENVIRONMENT, id)?;
            if let Some(mut ws) = s.get::<Workspace>(kind::WORKSPACE, &env.workspace_id)?
                && ws.active_environment_id == Some(*id)
            {
                ws.active_environment_id = None;
                ws.meta.updated_at = chrono::Utc::now();
                s.put(kind::WORKSPACE, &ws.meta.id, None, None, 0.0, &ws)?;
            }
            Ok(())
        })?;
        Ok(())
    }

    // ------------------------------------------------------------ secrets

    /// Store a new secret owned by workspace `ws`, which must exist: a
    /// request resolves only secrets its own workspace owns.
    pub fn set_secret(&self, ws: &Id, label: &str, value: &str) -> Result<SecretRef> {
        self.workspace(ws)?;
        let id = Id::new();
        self.store.put_secret(&id, Some(ws), label, value)?;
        Ok(SecretRef { id, label: label.into() })
    }

    /// Validate ownership and write in one transaction. Acquire the caller's
    /// lifecycle guard only once the store transaction has begun, and retain
    /// it through commit/rollback so revocation cannot cross the write.
    pub(crate) fn set_secret_guarded<G>(&self, ws: &Id, label: &str, value: &str, gate: impl FnOnce() -> Option<G>) -> Result<SecretRef> {
        let id = Id::new();
        let mut guard = None;
        let result = self.store.atomically(|tx| {
            guard = gate();
            if guard.is_none() {
                return Err(StoreError::Locked);
            }
            let _: Workspace = tx.get(kind::WORKSPACE, ws)?.ok_or_else(|| StoreError::NotFound(ws.to_string()))?;
            tx.put_secret(&id, Some(ws), label, value)?;
            Ok(SecretRef { id, label: label.into() })
        });
        drop(guard);
        Ok(result?)
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

    /// Save a dataset. A stored file the saved dataset did not hold yet must
    /// still be stored (see [`App::save_request`]), and the stored file it
    /// replaces is released unless something else references it or a user
    /// attached it within [`ATTACHMENT_GRACE`]. Both run in the write
    /// transaction that saves it.
    pub fn save_dataset(&self, d: Dataset) -> Result<Dataset> {
        let attachment = serde_json::to_value(&d.attachment)?;
        self.store.atomically(|s| {
            let held: Option<Dataset> = s.get(kind::DATASET, &d.meta.id)?;
            let before = held.as_ref().map(|h| serde_json::to_value(&h.attachment)).transpose()?;
            if let Some(gone) = first_unstored_attachment_in(s, &attachment, before.as_slice())? {
                return Ok(Err(unstored(&gone)));
            }
            s.put(kind::DATASET, &d.meta.id, Some(&d.workspace_id), None, 0.0, &d)?;
            if let Some(AttachmentRef::Stored { sha256, .. }) = held.map(|h| h.attachment)
                && !matches!(&d.attachment, AttachmentRef::Stored { sha256: kept, .. } if *kept == sha256)
            {
                release_held_attachment_in(s, &sha256)?;
            }
            Ok(Ok(()))
        })??;
        Ok(d)
    }

    /// Store an attachment a user adds (content-addressed by sha256): a
    /// request body or multipart file, a gRPC schema file or a dataset. The
    /// blob, its pin and its index entry are written together or not at all.
    /// The item that will hold it is saved later, in another call, so the
    /// entry is marked as added by a user: no automatic cleanup (such as a
    /// reimport releasing the source file it replaces) releases it, only
    /// deleting or replacing an item that held it, once nothing references
    /// it any more. A file larger than one bundle entry
    /// ([`anvil_portability::bundle::MAX_ENTRY_BYTES`], 128 MiB) is refused:
    /// it could be sent, but its workspace could never be exported.
    pub fn put_attachment(
        &self,
        file_name: &str,
        bytes: &[u8],
        media_type: Option<String>,
    ) -> Result<anvil_domain::request::AttachmentRef> {
        let (size, max) = (bytes.len() as u64, anvil_portability::bundle::MAX_ENTRY_BYTES);
        if size > max {
            let why = format!("'{file_name}' is {size} bytes; an attached file can be at most {max} bytes (128 MiB)");
            return Err(AppError::Invalid(format!("{why}, the most a bundle can carry. Link the file instead; nothing was attached.")));
        }
        Ok(self.store.atomically(|s| store_attachment_in(s, file_name, bytes, media_type, true))?)
    }

    /// Pin the blob of every stored attachment (idempotent). Profiles created
    /// before blobs were pinned could lose attachments to history retention;
    /// this protects whatever is still there. The index is read and every pin
    /// written in one write transaction, so retention on any connection runs
    /// before or after all of it, never between the read and a pin.
    pub(crate) fn pin_attachment_blobs(&self) -> Result<()> {
        Ok(self.store.atomically(|s| {
            let idx: Vec<serde_json::Value> = s.list(kind::IMPORT_SOURCE, None)?;
            for i in idx {
                if let (Some(_), Some(blob)) = (i.get("attachment"), i.get("blob").and_then(|b| b.as_str())) {
                    s.pin_blob(blob)?;
                }
            }
            Ok(())
        })?)
    }

    /// Delete a stored attachment once nothing references it any more.
    /// Content addressing means several requests, revisions, datasets or spec
    /// sources can share one attachment, so every object that can hold one is
    /// checked first. The check and the release run in one write transaction,
    /// so nothing can reference the attachment between them. One a user added
    /// ([`App::put_attachment`]) is kept: an item not saved yet may hold it.
    /// Returns whether it was deleted.
    pub fn release_attachment(&self, sha256: &str) -> Result<bool> {
        Ok(self.store.atomically(|s| release_attachment_in(s, sha256))?)
    }

    pub fn get_attachment(&self, sha256: &str) -> Result<Option<Vec<u8>>> {
        let idx: Option<serde_json::Value> = self.store.get(kind::IMPORT_SOURCE, &attachment_index_id(sha256))?;
        let Some(idx) = idx else { return Ok(None) };
        let blob = idx.get("blob").and_then(|b| b.as_str()).unwrap_or_default().to_string();
        Ok(self.store.get_blob(&blob)?.map(|z| z.to_vec()))
    }
}

/// Validate placement under the same write lock as a folder create/save.
/// A concurrent delete cannot leave the new row under a deleted owner or
/// parent; a foreign parent cannot supply another workspace's inherited scope.
/// The import root a request in `folder` resolves under when it is not open
/// to its workspace, as [`App::build_context`] decides it: the innermost
/// import root of the folder's ancestry, unless the user opened it.
fn sealed_root_in(s: &StoreTx<'_>, folder: Option<Id>) -> anvil_storage::store::Result<Option<Folder>> {
    // `seen` stops the walk at a parent cycle (a context is never built there).
    let mut seen = HashSet::new();
    let mut cur = folder;
    while let Some(c) = cur.filter(|c| seen.insert(*c)) {
        let Some(f) = s.get::<Folder>(kind::FOLDER, &c)? else { return Ok(None) };
        if f.import_root {
            return Ok((!f.use_workspace_scope).then_some(f));
        }
        cur = f.parent_id;
    }
    Ok(None)
}

/// The import root, not open to its workspace, that a move from under
/// `from` to under `to` takes what it moves out of, if any.
fn leaves_import_in(s: &StoreTx<'_>, from: Option<Id>, to: Option<Id>) -> anvil_storage::store::Result<Option<Folder>> {
    let Some(root) = sealed_root_in(s, from)? else { return Ok(None) };
    let stays = sealed_root_in(s, to)?.is_some_and(|r| r.meta.id == root.meta.id);
    Ok((!stays).then_some(root))
}

fn validate_folder_parent_in(s: &StoreTx<'_>, ws: &Id, parent: Option<Id>) -> anvil_storage::store::Result<()> {
    if s.get::<Workspace>(kind::WORKSPACE, ws)?.is_none() {
        return Err(StoreError::NotFound("workspace".into()));
    }
    if let Some(id) = parent {
        let folder: Folder = s.get(kind::FOLDER, &id)?.ok_or_else(|| StoreError::NotFound("folder".into()))?;
        if folder.workspace_id != *ws {
            return Err(StoreError::ForeignFolderParent);
        }
    }
    Ok(())
}

/// Store an attachment inside the caller's transaction, so it is rolled
/// back with everything else the caller writes. Unlike [`App::put_attachment`]
/// it does not mark the attachment as added by a user (an entry already
/// marked stays marked): what the caller stores is referenced by what it
/// writes in the same transaction.
pub(crate) fn put_attachment_in(
    s: &StoreTx<'_>,
    file_name: &str,
    bytes: &[u8],
    media_type: Option<String>,
) -> anvil_storage::store::Result<AttachmentRef> {
    store_attachment_in(s, file_name, bytes, media_type, false)
}

fn store_attachment_in(
    s: &StoreTx<'_>,
    file_name: &str,
    bytes: &[u8],
    media_type: Option<String>,
    user: bool,
) -> anvil_storage::store::Result<AttachmentRef> {
    let sha = hex::encode(Sha256::digest(bytes));
    let blob = s.put_blob(bytes)?;
    s.pin_blob(&blob)?;
    index_attachment_in(s, &sha, &blob, user)?;
    Ok(AttachmentRef::Stored { sha256: sha, size: bytes.len() as u64, file_name: file_name.into(), media_type })
}

/// The index entry of a stored attachment. Entries written before the mark
/// existed have neither `user` nor `attached_at`, and read as not marked.
#[derive(Serialize, Deserialize)]
pub(crate) struct AttachmentIndex {
    pub(crate) attachment: String,
    pub(crate) blob: String,
    /// Added by a user (see [`App::put_attachment`]).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(crate) user: bool,
    /// When a user last added it, in unix milliseconds: what the cleanup of
    /// files attached and never saved ages them by (see
    /// [`crate::cleanup::ATTACHMENT_GRACE`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) attached_at: Option<i64>,
}

/// The time, in unix milliseconds, before which a file a user attached has
/// waited [`ATTACHMENT_GRACE`].
pub(crate) fn grace_cutoff() -> i64 {
    chrono::Utc::now().timestamp_millis().saturating_sub(ATTACHMENT_GRACE.as_millis() as i64)
}

/// Whether a user attached `entry` at `cutoff` ([`grace_cutoff`]) or later:
/// a request or dataset not saved yet may hold it, so no release other than
/// deleting or replacing a saved item that held it takes it before the
/// period is over. A mark without a time (entries written before the time
/// was recorded) counts as recent: its age is unknown. The cleanup at
/// profile open records the time it first sees one, so it ages from then.
pub(crate) fn attached_recently(entry: &AttachmentIndex, cutoff: i64) -> bool {
    entry.user && entry.attached_at.is_none_or(|t| t >= cutoff)
}

/// Every attachment index entry that decodes. One that does not is skipped:
/// its file stays stored.
pub(crate) fn attachment_entries_in(s: &StoreRead<'_>) -> anvil_storage::store::Result<Vec<AttachmentIndex>> {
    let mut entries = Vec::new();
    for m in s.object_meta(kind::IMPORT_SOURCE)? {
        let Ok(id) = m.id.parse::<Id>() else { continue };
        match s.get::<AttachmentIndex>(kind::IMPORT_SOURCE, &id) {
            Ok(Some(entry)) => entries.push(entry),
            Ok(None) | Err(StoreError::Integrity | StoreError::Serde(_)) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(entries)
}

/// Whether deleting or replacing an item that held attachment `sha` leaves
/// it stored: a user attached it at `cutoff` ([`grace_cutoff`]) or later
/// ([`attached_recently`]), so a request or dataset not saved yet may hold
/// it, and the cleanup of files attached and never saved decides it once
/// the period is over.
fn held_release_waits_in(s: &StoreTx<'_>, sha: &str, cutoff: i64) -> anvil_storage::store::Result<bool> {
    Ok(attachment_entry_in(&s.as_read(), sha)?.is_some_and(|e| attached_recently(&e, cutoff)))
}

/// The index entry of attachment `sha`, if it has one that decodes.
fn attachment_entry_in(s: &StoreRead<'_>, sha: &str) -> anvil_storage::store::Result<Option<AttachmentIndex>> {
    match s.get::<AttachmentIndex>(kind::IMPORT_SOURCE, &attachment_index_id(sha)) {
        Ok(entry) => Ok(entry),
        Err(StoreError::Integrity | StoreError::Serde(_)) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Write the index entry of attachment `sha` stored in `blob`. `user` marks
/// one a user added (see [`App::put_attachment`]) and records when; an entry
/// already marked stays marked, with the time it was marked.
pub(crate) fn index_attachment_in(s: &StoreTx<'_>, sha: &str, blob: &str, user: bool) -> anvil_storage::store::Result<()> {
    let id = attachment_index_id(sha);
    let held: Option<serde_json::Value> = s.get(kind::IMPORT_SOURCE, &id)?;
    let held = held.and_then(|h| serde_json::from_value::<AttachmentIndex>(h).ok());
    let (user, attached_at) = match held {
        _ if user => (true, Some(chrono::Utc::now().timestamp_millis())),
        Some(h) if h.user => (true, h.attached_at),
        _ => (false, None),
    };
    let index = AttachmentIndex { attachment: sha.into(), blob: blob.into(), user, attached_at };
    s.put(kind::IMPORT_SOURCE, &id, None, None, 0.0, &index)?;
    Ok(())
}

/// Whether an attachment index entry is marked as added by a user. Entries
/// written before the mark existed are not.
fn user_added(index: &serde_json::Value) -> bool {
    index.get("user").and_then(|u| u.as_bool()).unwrap_or(false)
}

/// [`App::release_attachment`] inside the caller's transaction: what the
/// caller wrote before it is checked as a reference too, and the release is
/// rolled back with everything else the caller writes. An attachment a user
/// added is kept.
pub(crate) fn release_attachment_in(s: &StoreTx<'_>, sha256: &str) -> anvil_storage::store::Result<bool> {
    release_in(s, sha256, false)
}

/// Release attachment `sha256` after the caller deleted or replaced, in this
/// transaction, an item that held it: unlike [`release_attachment_in`], one a
/// user added is released too, once nothing references it any more, unless
/// a user attached it within [`ATTACHMENT_GRACE`] ([`held_release_waits_in`]).
pub(crate) fn release_held_attachment_in(s: &StoreTx<'_>, sha256: &str) -> anvil_storage::store::Result<bool> {
    release_in(s, sha256, true)
}

fn release_in(s: &StoreTx<'_>, sha256: &str, held: bool) -> anvil_storage::store::Result<bool> {
    let kept = if held {
        held_release_waits_in(s, sha256, grace_cutoff())?
    } else {
        let idx: Option<serde_json::Value> = s.get(kind::IMPORT_SOURCE, &attachment_index_id(sha256))?;
        idx.as_ref().is_none_or(user_added)
    };
    if kept {
        return Ok(false);
    }
    if unreferenced_in(s, HashSet::from([sha256.to_string()]))?.is_empty() {
        return Ok(false);
    }
    drop_attachment_in(s, sha256)
}

/// Delete the index entry of attachment `sha256` and release its blob,
/// without any check. Returns whether it had an entry.
pub(crate) fn drop_attachment_in(s: &StoreTx<'_>, sha256: &str) -> anvil_storage::store::Result<bool> {
    let id = attachment_index_id(sha256);
    let idx: Option<serde_json::Value> = s.get(kind::IMPORT_SOURCE, &id)?;
    let Some(idx) = idx else { return Ok(false) };
    if let Some(blob) = idx.get("blob").and_then(|b| b.as_str()) {
        s.release_blob(blob)?;
    }
    s.delete(kind::IMPORT_SOURCE, &id)?;
    Ok(true)
}

/// The kinds of object that can reference a stored attachment.
pub(crate) const REFERRERS: [&str; 6] = [kind::REQUEST, kind::REVISION, kind::DATASET, kind::SPEC_SOURCE, kind::SCENARIO, kind::LOAD_PLAN];

/// Of `candidates`, the attachments that no object of a [`REFERRERS`] kind
/// references, in one pass over those objects. The match is on each
/// object's JSON text, so a spec source's `original_sha256` counts too. An
/// object that does not decode could reference any of them, so then none is
/// returned: a file is kept rather than deleted while something may use it.
/// Each such object is logged as a warning (see [`reference_scan_in`]).
pub(crate) fn unreferenced_in(s: &StoreTx<'_>, candidates: HashSet<String>) -> anvil_storage::store::Result<HashSet<String>> {
    Ok(reference_scan_in(&s.as_read(), candidates, &HashSet::new())?.0)
}

/// [`unreferenced_in`], with the objects that did not decode, and without
/// the revisions `revisions` names by id (ones about to be removed). Once
/// one object keeps every candidate, the scan goes on only to name the
/// others, and each is logged as a warning by kind and id, never content, so
/// a damaged row that stops every release can be found and repaired or
/// deleted.
pub(crate) fn reference_scan_in(
    s: &StoreRead<'_>,
    mut candidates: HashSet<String>,
    revisions: &HashSet<String>,
) -> anvil_storage::store::Result<(HashSet<String>, Vec<UndecodableObject>)> {
    let mut undecodable = Vec::new();
    for k in REFERRERS {
        for m in s.object_meta(k)? {
            if candidates.is_empty() && undecodable.is_empty() {
                return Ok((candidates, undecodable));
            }
            if k == kind::REVISION && revisions.contains(&m.id) {
                continue;
            }
            let decoded = match m.id.parse::<Id>() {
                Ok(id) => match (|| {
                    if k == kind::REVISION
                        && let Some(refs) = s.orphan_revision_attachment_refs_for_retention(&id)?
                    {
                        candidates.retain(|sha| !refs.contains(sha));
                        return Ok(None);
                    }
                    s.get::<serde_json::Value>(k, &id)
                })() {
                    Ok(Some(o)) => Some(o.to_string()),
                    Ok(None) => continue,
                    Err(StoreError::Integrity | StoreError::Serde(_)) => None,
                    Err(e) => return Err(e),
                },
                Err(_) => None,
            };
            match decoded {
                Some(text) => candidates.retain(|sha| !text.contains(sha.as_str())),
                None => {
                    tracing::warn!(kind = k, id = %m.id, "a stored object does not decode; stored files are kept until it is repaired");
                    undecodable.push(UndecodableObject { kind: k.to_string(), id: m.id });
                }
            }
        }
    }
    if !undecodable.is_empty() {
        candidates.clear();
    }
    Ok((candidates, undecodable))
}

/// Of the stored attachments `stored`, those the items of workspace `ws`
/// name: each whose hash appears in the JSON text of one of them, matched as
/// [`unreferenced_in`] matches. An item that does not decode names none, so
/// the files it may hold are kept.
fn workspace_attachments_in(s: &StoreTx<'_>, ws: &Id, stored: Vec<String>) -> anvil_storage::store::Result<HashSet<String>> {
    let ws = ws.to_string();
    let mut held = HashSet::new();
    if stored.is_empty() {
        return Ok(held);
    }
    for k in REFERRERS {
        for m in s.object_meta(k)? {
            if m.workspace_id.as_deref() != Some(ws.as_str()) {
                continue;
            }
            let Ok(id) = m.id.parse::<Id>() else { continue };
            let text = match s.get::<serde_json::Value>(k, &id) {
                Ok(Some(o)) => o.to_string(),
                Ok(None) | Err(StoreError::Integrity | StoreError::Serde(_)) => continue,
                Err(e) => return Err(e),
            };
            held.extend(stored.iter().filter(|sha| text.contains(sha.as_str())).cloned());
        }
    }
    Ok(held)
}

/// The first stored attachment `value` names that none of `held` (what the
/// item held when last saved, if it was) names, and that is not stored:
/// added since that save and released, or never stored here.
fn first_unstored_attachment_in(
    s: &StoreTx<'_>,
    value: &serde_json::Value,
    held: &[serde_json::Value],
) -> anvil_storage::store::Result<Option<String>> {
    let mut kept = HashSet::new();
    for held in held {
        crate::exec::collect_attachments(held, &mut |sha| {
            kept.insert(sha.to_string());
        });
    }
    let mut added = Vec::new();
    crate::exec::collect_attachments(value, &mut |sha| {
        if !kept.contains(sha) {
            added.push(sha.to_string());
        }
    });
    for sha in added {
        if !attachment_stored_in(s, &sha)? {
            return Ok(Some(sha));
        }
    }
    Ok(None)
}

/// Whether attachment `sha256` is stored: its index entry and its content.
fn attachment_stored_in(s: &StoreTx<'_>, sha256: &str) -> anvil_storage::store::Result<bool> {
    let idx: Option<serde_json::Value> = s.get(kind::IMPORT_SOURCE, &attachment_index_id(sha256))?;
    match idx.as_ref().and_then(|i| i.get("blob")).and_then(|b| b.as_str()) {
        Some(blob) => s.has_blob(blob),
        None => Ok(false),
    }
}

/// The refusal of a save naming stored attachment `sha256`, which is not
/// stored.
fn unstored(sha256: &str) -> AppError {
    let short = sha256.get(..12).unwrap_or(sha256);
    AppError::Invalid(format!("an attached file (sha256 {short}...) is no longer stored; attach it again, then save"))
}

/// Delete `requests` with their revisions, then release the stored
/// attachments they held that nothing else references any more, including
/// ones a user added, unless a user attached it within [`ATTACHMENT_GRACE`]
/// ([`held_release_waits_in`]), as [`release_held_attachment_in`] does, in
/// one pass over the referrers.
pub(crate) fn delete_requests_in(s: &StoreTx<'_>, requests: &[RequestDefinition]) -> anvil_storage::store::Result<()> {
    let mut specs = Vec::new();
    for r in requests {
        specs.push(serde_json::to_value(&r.spec)?);
    }
    // Every writer files a revision under its request (`parent_id`), so only
    // these requests' revisions are decrypted.
    let ids: HashSet<String> = requests.iter().map(|r| r.meta.id.to_string()).collect();
    for m in s.object_meta(kind::REVISION)? {
        if !m.parent_id.as_ref().is_some_and(|p| ids.contains(p)) {
            continue;
        }
        let Ok(id) = m.id.parse::<Id>() else { continue };
        // Preserve an undecodable revision as an orphan: dropping its row
        // would lose the only record of the files it may still name.
        match s.get::<RequestRevision>(kind::REVISION, &id) {
            Ok(Some(rev)) => specs.push(serde_json::to_value(&rev.spec)?),
            Ok(None) | Err(StoreError::Integrity | StoreError::Serde(_)) => continue,
            Err(e) => return Err(e),
        }
        s.delete(kind::REVISION, &id)?;
    }
    // Keep the parents until their revisions have authenticated their owners.
    // Both kinds disappear in this same transaction before attachment release.
    for r in requests {
        s.delete(kind::REQUEST, &r.meta.id)?;
    }
    let mut held = HashSet::new();
    for spec in &specs {
        crate::exec::collect_attachments(spec, &mut |sha| {
            held.insert(sha.to_string());
        });
    }
    let cutoff = grace_cutoff();
    let mut candidates = HashSet::new();
    for sha in held {
        if !held_release_waits_in(s, &sha, cutoff)? {
            candidates.insert(sha);
        }
    }
    for sha in unreferenced_in(s, candidates)? {
        drop_attachment_in(s, &sha)?;
    }
    Ok(())
}

/// Deterministic object id for the attachment index entry of a content hash.
pub(crate) fn attachment_index_id(sha: &str) -> Id {
    let d = Sha256::digest(format!("anvil-attachment-index:{sha}").as_bytes());
    let mut b = [0u8; 16];
    b.copy_from_slice(&d[..16]);
    Id(uuid::Builder::from_custom_bytes(b).into_uuid())
}
