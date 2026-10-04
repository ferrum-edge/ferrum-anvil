//! Linked local files (`AttachmentRef::LinkedFile`) the user chose in the
//! desktop's native open dialog.
//!
//! A linked file is a path on one machine. A reference that arrives any other
//! way, for example in an imported bundle, was never chosen on this device,
//! so it stays inert: a request, gRPC schema or dataset that names it is
//! refused before anything is read or sent. It becomes usable only once the
//! user picks that same file in the native dialog for that request or
//! dataset (`file_choose` with purpose `linked_file` and the referrer),
//! which binds the referrer and the file's canonical path in the vault. A
//! binding made for one request or dataset never lets another one read the
//! file, and a bundle import drops the bindings of every request and dataset
//! it writes. Bindings are device-specific: they are not exported, and an
//! import cannot create one. This draft also requires a retained native
//! selection in the current opened session. Restart or lock requires choosing
//! the file again. The CLI has no chooser and cannot reconstruct that handle
//! from a persisted path. This compatibility decision needs owner approval;
//! see docs/security/file-handle-safety.md before integrating this draft.
//!
//! A reference whose file lives at another path on this device (often one
//! imported from another machine) is repointed the same way: the user picks
//! the file at its new location in the native dialog for that request or
//! dataset and the reference it replaces (`file_choose` with purpose
//! `linked_file_relocate`, [`App::relocate_linked_file`]). That rewrites the
//! saved request or dataset to name the new path and binds it for that
//! referrer only. It is the one way the desktop writes a linked path into a
//! saved request or dataset: a spec from the webview still never names one.
//!
//! The desktop shows, beside each linked file, whether it is bound
//! ([`App::linked_file_status`]). That query looks only at files already
//! bound for that referrer, and only at their metadata: it never reads a
//! file, and never touches a path that was not chosen.

use crate::file_handles::SelectedFile;
use crate::{App, AppError, Result};
use anvil_domain::Id;
use anvil_domain::request::{AttachmentRef, RequestSpec};
use anvil_domain::workspace::{Dataset, RequestDefinition, RequestRevision};
use anvil_storage::StoreTx;
use anvil_storage::store::kind;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Read;
use std::path::Path;
use std::sync::Arc;

/// What names a linked file: a saved request (its body or gRPC schema) or a
/// dataset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LinkedFileReferrer {
    Request { id: Id },
    Dataset { id: Id },
}

impl LinkedFileReferrer {
    /// The id of the request or dataset.
    pub fn id(self) -> Id {
        match self {
            LinkedFileReferrer::Request { id } | LinkedFileReferrer::Dataset { id } => id,
        }
    }

    fn noun(self) -> &'static str {
        match self {
            LinkedFileReferrer::Request { .. } => "request",
            LinkedFileReferrer::Dataset { .. } => "dataset",
        }
    }
}

/// A linked file bound through the native dialog for one request or dataset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkedFileBinding {
    pub id: Id,
    pub referrer: LinkedFileReferrer,
    /// Canonical absolute path of the chosen file.
    pub path: String,
    pub bound_at: DateTime<Utc>,
}

/// Whether a linked file a request or dataset names can be used on this device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkedFileState {
    /// Chosen in this session for the referrer, with the same regular file
    /// in the retained directory. The size limit is not checked here: it
    /// depends on what reads the file, and is enforced when it is read.
    Bound,
    /// Not chosen on this device for the referrer, so it is refused. The
    /// path is not looked at.
    Unbound,
    /// A binding exists, but needs reselection in this session, or its leaf
    /// was moved, deleted or replaced. Ancestor renames cannot redirect it.
    Invalid,
}

/// The binding state of one linked file a request or dataset names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkedFileStatus {
    /// The path the request or dataset names.
    pub path: String,
    pub state: LinkedFileState,
    /// Why a bound file cannot be used (only for `invalid`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub problem: Option<String>,
}

impl App {
    /// Bind the linked file the user picked in the native open dialog for
    /// `referrer`, which must name that file. Only the desktop's
    /// `file_choose` calls this, with the dialog's result.
    pub fn bind_linked_file(&self, referrer: LinkedFileReferrer, picked: &Path) -> Result<LinkedFileBinding> {
        let generation = self.linked_file_handles.lock().generation;
        let canonical = crate::token_files::chosen_path(picked, "linked file")?;
        let selected = Arc::new(SelectedFile::open_canonical(canonical.into())?);
        let path = linked_path(&selected)?;
        if !self.named_linked_files(referrer)?.contains(&path) {
            return Err(AppError::Invalid(format!(
                "the chosen file '{path}' is not the linked file this {} names; attach the file instead",
                referrer.noun()
            )));
        }
        if let Some(b) = self.linked_file_bindings()?.into_iter().find(|b| b.referrer == referrer && b.path == path) {
            self.remember_linked_selection(&b, selected, generation)?;
            return Ok(b);
        }
        let b = LinkedFileBinding { id: Id::new(), referrer, path, bound_at: Utc::now() };
        self.store.put(kind::LINKED_FILE, &b.id, None, None, 0.0, &b)?;
        self.remember_linked_selection(&b, selected, generation)?;
        Ok(b)
    }

    /// Repoint the linked file `old_path` that the saved request or dataset
    /// `referrer` names to the file the user picked in the native open
    /// dialog at its new location, and bind that file for `referrer`. Only
    /// the desktop's `file_choose` (purpose `linked_file_relocate`) calls
    /// this, with the dialog's result.
    ///
    /// `old_path` only identifies the reference: it must be a linked file
    /// `referrer` names, and it is never looked at on disk. The picked file
    /// must be a regular file and is named by its canonical path. One write
    /// transaction checks that `referrer` still names `old_path`, rewrites
    /// every reference to it in that request (filing a new revision) or
    /// dataset, drops that referrer's binding of the old path and binds the
    /// new one. Another request or dataset that names the old path is left
    /// as it is, and stays unbound until the file is chosen for it.
    pub fn relocate_linked_file(&self, referrer: LinkedFileReferrer, old_path: &str, picked: &Path) -> Result<LinkedFileBinding> {
        if !self.named_linked_files(referrer)?.iter().any(|p| p == old_path) {
            return Err(not_named(old_path, referrer));
        }
        let generation = self.linked_file_handles.lock().generation;
        let canonical = crate::token_files::chosen_path(picked, "linked file")?;
        let selected = Arc::new(SelectedFile::open_canonical(canonical.into())?);
        let path = linked_path(&selected)?;
        let fresh = LinkedFileBinding { id: Id::new(), referrer, path: path.clone(), bound_at: Utc::now() };
        let binding = self.store.atomically(|s| {
            // The request or dataset may have changed since the check above.
            if let Err(e) = repoint_in(s, referrer, old_path, &path)? {
                return Ok(Err(e));
            }
            let mut kept = None;
            for b in s.list::<LinkedFileBinding>(kind::LINKED_FILE, None)?.into_iter().filter(|b| b.referrer == referrer) {
                if b.path == path {
                    kept = kept.or(Some(b));
                } else if b.path == old_path {
                    s.delete(kind::LINKED_FILE, &b.id)?;
                }
            }
            if let Some(b) = kept {
                return Ok(Ok(b));
            }
            s.put(kind::LINKED_FILE, &fresh.id, None, None, 0.0, &fresh)?;
            Ok(Ok(fresh))
        })??;
        self.remember_linked_selection(&binding, selected, generation)?;
        Ok(binding)
    }

    fn remember_linked_selection(&self, binding: &LinkedFileBinding, selected: Arc<SelectedFile>, generation: u64) -> Result<()> {
        let previous = {
            let mut state = self.linked_file_handles.lock();
            if state.generation != generation {
                return Err(AppError::Locked);
            }
            state.handles.insert(binding.id, selected)
        };
        if let Some(previous) = previous {
            previous.revoke();
        }
        Ok(())
    }

    /// Snapshot only selections whose binding still belongs to this referrer.
    /// No filesystem I/O or callback runs under the selection mutex.
    pub(crate) fn linked_handles_for(
        &self,
        referrer: Option<LinkedFileReferrer>,
        paths: &[String],
    ) -> Result<HashMap<String, Arc<SelectedFile>>> {
        let Some(referrer) = referrer else { return Ok(HashMap::new()) };
        let bound = self.linked_file_bindings()?;
        let state = self.linked_file_handles.lock();
        Ok(bound
            .iter()
            .filter(|b| b.referrer == referrer && paths.contains(&b.path))
            .filter_map(|b| state.handles.get(&b.id).map(|selected| (b.path.clone(), selected.clone())))
            .collect())
    }

    pub fn linked_file_bindings(&self) -> Result<Vec<LinkedFileBinding>> {
        Ok(self.store.list(kind::LINKED_FILE, None)?)
    }

    /// The binding state of each linked file the saved request or dataset
    /// `referrer` names, in the order it names them. Read-only: only a file
    /// bound for `referrer` on this device is looked at, and only its
    /// metadata; an unbound path is never touched. The size limit is checked
    /// when the file is read, since it depends on what reads it.
    pub fn linked_file_status(&self, referrer: LinkedFileReferrer) -> Result<Vec<LinkedFileStatus>> {
        let bound = self.linked_file_bindings()?;
        let mut status = Vec::new();
        for path in self.named_linked_files(referrer)? {
            let binding = bound.iter().find(|b| b.referrer == referrer && b.path == path);
            let chosen = binding.is_some();
            let selected = binding.and_then(|b| self.linked_file_handles.lock().handles.get(&b.id).cloned());
            let problem = if chosen { bound_file_problem(selected.as_deref()) } else { None };
            let state = match (chosen, &problem) {
                (false, _) => LinkedFileState::Unbound,
                (true, None) => LinkedFileState::Bound,
                (true, Some(_)) => LinkedFileState::Invalid,
            };
            status.push(LinkedFileStatus { path, state, problem });
        }
        Ok(status)
    }

    /// The paths of the linked files the saved request (its body or gRPC
    /// schema) or dataset `referrer` names.
    fn named_linked_files(&self, referrer: LinkedFileReferrer) -> Result<Vec<String>> {
        Ok(match referrer {
            LinkedFileReferrer::Request { id } => {
                let mut paths = Vec::new();
                linked_paths(&serde_json::to_value(&self.request(&id)?.spec)?, &mut paths);
                paths
            }
            LinkedFileReferrer::Dataset { id } => match self.dataset(&id)?.attachment {
                AttachmentRef::LinkedFile { path } => vec![path],
                AttachmentRef::Stored { .. } => vec![],
            },
        })
    }

    /// The linked files `spec` names, refusing any that was not chosen on
    /// this device for `referrer` (always, without one).
    pub(crate) fn bound_linked_files(&self, referrer: Option<LinkedFileReferrer>, spec: &RequestSpec) -> Result<Vec<String>> {
        let mut paths = Vec::new();
        linked_paths(&serde_json::to_value(spec)?, &mut paths);
        if let Some(p) = paths.first() {
            let Some(referrer) = referrer else {
                return Err(unbound(p, "request"));
            };
            let bound = self.linked_file_bindings()?;
            for p in &paths {
                refuse_unbound(&bound, referrer, p)?;
            }
        }
        Ok(paths)
    }

    /// Read the linked file of a dataset, refusing it unless it was chosen
    /// on this device for that dataset.
    pub(crate) fn read_linked_dataset(&self, id: Id, path: &str, max: u64) -> Result<Vec<u8>> {
        let referrer = LinkedFileReferrer::Dataset { id };
        let bound = self.linked_file_bindings()?;
        refuse_unbound(&bound, referrer, path)?;
        let binding = bound.iter().find(|b| b.referrer == referrer && b.path == path).expect("checked binding");
        let selected = self.linked_file_handles.lock().handles.get(&binding.id).cloned().ok_or_else(reselect)?;
        read_bound_file(&selected, max, "dataset")
    }
}

/// Rewrite every linked file `referrer` names at `old` to name `new`, in
/// the transaction `s`: a request's spec (with a new revision, as a save
/// files one) or a dataset's file. Refused if `referrer` is gone or no longer
/// names `old`.
fn repoint_in(s: &StoreTx<'_>, referrer: LinkedFileReferrer, old: &str, new: &str) -> anvil_storage::store::Result<Result<()>> {
    let now = Utc::now();
    match referrer {
        LinkedFileReferrer::Request { id } => {
            let Some(mut r) = s.get::<RequestDefinition>(kind::REQUEST, &id)? else {
                return Ok(Err(AppError::NotFound("request".into())));
            };
            let mut spec = serde_json::to_value(&r.spec)?;
            if !repoint(&mut spec, old, new) {
                return Ok(Err(not_named(old, referrer)));
            }
            r.spec = serde_json::from_value(spec)?;
            let hash = crate::workspace::spec_hash(&r.spec);
            let prev: Option<RequestRevision> = match r.revision_id {
                Some(rid) => s.get(kind::REVISION, &rid)?,
                None => None,
            };
            if prev.map(|p| p.spec_sha256 != hash).unwrap_or(true) {
                let rev =
                    RequestRevision { id: Id::new(), request_id: r.meta.id, created_at: now, spec_sha256: hash, spec: r.spec.clone() };
                s.put(kind::REVISION, &rev.id, Some(&r.workspace_id), Some(&r.meta.id), 0.0, &rev)?;
                r.revision_id = Some(rev.id);
            }
            r.meta.updated_at = now;
            s.put(kind::REQUEST, &r.meta.id, Some(&r.workspace_id), r.folder_id.as_ref(), r.sort_key, &r)?;
        }
        LinkedFileReferrer::Dataset { id } => {
            let Some(mut d) = s.get::<Dataset>(kind::DATASET, &id)? else {
                return Ok(Err(AppError::NotFound("dataset".into())));
            };
            match &mut d.attachment {
                AttachmentRef::LinkedFile { path } if path.as_str() == old => *path = new.to_string(),
                _ => return Ok(Err(not_named(old, referrer))),
            }
            d.meta.updated_at = now;
            s.put(kind::DATASET, &d.meta.id, Some(&d.workspace_id), None, 0.0, &d)?;
        }
    }
    Ok(Ok(()))
}

/// Point every linked file at `old` in a serialized spec to `new`; whether
/// there was one.
fn repoint(v: &mut serde_json::Value, old: &str, new: &str) -> bool {
    match v {
        serde_json::Value::Object(o) => {
            let mut found = false;
            if o.get("kind").and_then(|k| k.as_str()) == Some("linked_file") && o.get("path").and_then(|p| p.as_str()) == Some(old) {
                o.insert("path".into(), new.into());
                found = true;
            }
            for x in o.values_mut() {
                found |= repoint(x, old, new);
            }
            found
        }
        serde_json::Value::Array(a) => {
            let mut found = false;
            for x in a {
                found |= repoint(x, old, new);
            }
            found
        }
        _ => false,
    }
}

fn not_named(path: &str, referrer: LinkedFileReferrer) -> AppError {
    AppError::Invalid(format!("the {} does not name the linked file '{path}', so it cannot be relocated", referrer.noun()))
}

fn refuse_unbound(bound: &[LinkedFileBinding], referrer: LinkedFileReferrer, path: &str) -> Result<()> {
    if bound.iter().any(|b| b.referrer == referrer && b.path == path) {
        return Ok(());
    }
    Err(unbound(path, referrer.noun()))
}

fn unbound(path: &str, noun: &str) -> AppError {
    AppError::Invalid(format!(
        "the linked local file '{path}' was not chosen on this device for this {noun}; choose it in the desktop with Choose file… beside the {noun}'s linked file, or attach the file instead (Anvil stores a copy)"
    ))
}

fn linked_path(selected: &SelectedFile) -> Result<String> {
    let path = selected.path.to_str().ok_or_else(|| AppError::Invalid("the linked file's path is not valid UTF-8".into()))?;
    if path.contains("{{") {
        return Err(AppError::Invalid("the linked file's path contains '{{', which Anvil reads as a variable".into()));
    }
    Ok(path.to_owned())
}

fn reselect() -> AppError {
    AppError::Invalid("the linked local file needs a fresh native selection in this session; choose it again".into())
}

/// Inspect the actual opened object, without reading bytes. A persisted path
/// alone is insufficient after restart/lock; it never creates new authority.
fn bound_file_problem(selected: Option<&SelectedFile>) -> Option<String> {
    let Some(selected) = selected else { return Some(reselect().to_string()) };
    match selected.open() {
        Ok(Some(_)) => None,
        Ok(None) => Some("the path no longer leads to the chosen regular file; choose it again".into()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Some("the file is no longer at this path".into()),
        Err(err) => Some(format!("the file cannot be reached ({err}); choose it again")),
    }
}

/// Read through the retained native selection, bounded even during growth.
/// Ancestor names are never resolved here. The reopened leaf's descriptor is
/// compared with the still-open original before its bytes are read.
pub(crate) fn read_bound_file(selected: &SelectedFile, max: u64, what: &str) -> Result<Vec<u8>> {
    let too_large = || AppError::Invalid(format!("the linked {what} is larger than {} MiB", max >> 20));
    let not_regular = || AppError::Invalid(format!("the linked {what} is not a regular file or was replaced; choose it again"));
    #[cfg(test)]
    crate::file_handles::test_checkpoint("linked_read_selected");
    let Some((file, meta)) = selected.open()? else {
        return Err(not_regular());
    };
    if meta.len() > max {
        return Err(too_large());
    }
    let mut bytes = Vec::new();
    file.take(max.saturating_add(1)).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max {
        return Err(too_large());
    }
    Ok(bytes)
}

/// Paths of every linked file referenced anywhere in a serialized spec.
fn linked_paths(v: &serde_json::Value, out: &mut Vec<String>) {
    match v {
        serde_json::Value::Object(o) => {
            if o.get("kind").and_then(|k| k.as_str()) == Some("linked_file") {
                let path = o.get("path").and_then(|p| p.as_str()).unwrap_or_default();
                if !out.iter().any(|p| p == path) {
                    out.push(path.to_string());
                }
            }
            o.values().for_each(|x| linked_paths(x, out));
        }
        serde_json::Value::Array(a) => a.iter().for_each(|x| linked_paths(x, out)),
        _ => {}
    }
}
