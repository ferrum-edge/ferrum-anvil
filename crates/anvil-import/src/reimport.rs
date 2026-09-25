//! Reimport diffs (build plan §11, failure case DATA-012).
//!
//! Previous requests are linked to fresh operations by
//! `ImportSource::operation_key` (operationId when present, else
//! `METHOD path`; `{service}/{port}/{operation}` for WSDL). A request is
//! *user-edited* when the hash of its current spec differs from the
//! `generated_hash` recorded at import time. The plan never loses work:
//!
//! * operations changed upstream on requests the user did not edit are
//!   safe updates;
//! * operations changed upstream on requests the user edited are
//!   conflicts, preserved unless explicitly approved;
//! * operations removed upstream are listed, never deleted automatically;
//! * requests without an import link are left alone.

use crate::ImportResult;
use crate::util::spec_hash;
use anvil_domain::Id;
use anvil_domain::request::RequestSpec;
use anvil_domain::workspace::{Folder, RequestDefinition};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ReimportChange {
    pub existing_id: Id,
    pub operation_key: String,
    /// The existing request's spec no longer matches what was generated.
    pub user_edited: bool,
    /// Top-level spec fields that differ between the existing request and
    /// the fresh import (`url`, `headers`, `body`, …).
    pub changed_fields: Vec<String>,
    /// The freshly generated request (its id is the fresh import's id; the
    /// applied update keeps `existing_id`).
    pub fresh: RequestDefinition,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ReimportRemoval {
    pub existing_id: Id,
    pub operation_key: String,
    pub user_edited: bool,
}

/// Result of [`reimport_diff`]. Nothing is applied until [`ReimportPlan::apply`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ReimportPlan {
    /// Import id of the fresh import.
    pub import_id: Id,
    /// Operations new in the source.
    pub added: Vec<RequestDefinition>,
    /// Fresh folders referenced by `added` requests (callers skip ids they
    /// already have — ids match when the same id namespace was used).
    pub added_folders: Vec<Folder>,
    /// Changed upstream, not edited by the user: safe to apply.
    pub updated: Vec<ReimportChange>,
    /// Changed upstream *and* edited by the user: kept as the user left
    /// them unless their id is in [`ReimportApproval::overwrite`].
    pub conflicts: Vec<ReimportChange>,
    /// Edited by the user, unchanged upstream: kept.
    pub preserved_edits: Vec<Id>,
    pub unchanged: Vec<Id>,
    /// Gone from the source: kept unless their id is in
    /// [`ReimportApproval::delete`].
    pub removed: Vec<ReimportRemoval>,
    /// Existing requests with no import link: untouched.
    pub unlinked: Vec<Id>,
}

/// Explicit user decisions for [`ReimportPlan::apply`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ReimportApproval {
    /// Conflicting (user-edited) requests to overwrite with the fresh spec.
    pub overwrite: Vec<Id>,
    /// Removed-upstream requests to delete.
    pub delete: Vec<Id>,
}

fn changed_fields(a: &RequestSpec, b: &RequestSpec) -> Vec<String> {
    let strip = |s: &RequestSpec| {
        let mut s = s.clone();
        s.source = None;
        serde_json::to_value(s).unwrap_or_default()
    };
    let (va, vb) = (strip(a), strip(b));
    let (Some(ma), Some(mb)) = (va.as_object(), vb.as_object()) else { return vec![] };
    let mut keys: Vec<&String> = ma.keys().chain(mb.keys()).collect();
    keys.sort();
    keys.dedup();
    keys.into_iter().filter(|k| ma.get(*k) != mb.get(*k)).cloned().collect()
}

/// Compare previously imported (and possibly edited) requests with a fresh
/// import of the same source.
pub fn reimport_diff(previous: &[RequestDefinition], fresh: &ImportResult) -> ReimportPlan {
    let mut plan = ReimportPlan {
        import_id: fresh.source.import_id,
        added: vec![],
        added_folders: vec![],
        updated: vec![],
        conflicts: vec![],
        preserved_edits: vec![],
        unchanged: vec![],
        removed: vec![],
        unlinked: vec![],
    };
    let mut matched: HashSet<&str> = HashSet::new();
    for prev in previous {
        let Some(src) = &prev.spec.source else {
            plan.unlinked.push(prev.meta.id);
            continue;
        };
        let user_edited = spec_hash(&prev.spec) != src.generated_hash;
        let found = fresh.requests.iter().find(|f| f.spec.source.as_ref().is_some_and(|s| s.operation_key == src.operation_key));
        let Some(f) = found else {
            plan.removed.push(ReimportRemoval { existing_id: prev.meta.id, operation_key: src.operation_key.clone(), user_edited });
            continue;
        };
        matched.insert(src.operation_key.as_str());
        let fsrc = f.spec.source.as_ref().expect("filtered on source");
        let upstream_changed = fsrc.generated_hash != src.generated_hash;
        let fields = changed_fields(&prev.spec, &f.spec);
        if fields.is_empty() {
            plan.unchanged.push(prev.meta.id);
            continue;
        }
        match (upstream_changed, user_edited) {
            (false, false) => plan.unchanged.push(prev.meta.id),
            (false, true) => plan.preserved_edits.push(prev.meta.id),
            (true, edited) => {
                let change = ReimportChange {
                    existing_id: prev.meta.id,
                    operation_key: src.operation_key.clone(),
                    user_edited: edited,
                    changed_fields: fields,
                    fresh: f.clone(),
                };
                if edited {
                    plan.conflicts.push(change);
                } else {
                    plan.updated.push(change);
                }
            }
        }
    }
    let mut needed: HashSet<Id> = HashSet::new();
    for f in &fresh.requests {
        let key = f.spec.source.as_ref().map(|s| s.operation_key.as_str()).unwrap_or("");
        if !matched.contains(key) {
            plan.added.push(f.clone());
            let mut cur = f.folder_id;
            while let Some(id) = cur {
                if !needed.insert(id) {
                    break;
                }
                cur = fresh.folders.iter().find(|x| x.meta.id == id).and_then(|x| x.parent_id);
            }
        }
    }
    plan.added_folders = fresh.folders.iter().filter(|f| needed.contains(&f.meta.id)).cloned().collect();
    plan
}

impl ReimportPlan {
    /// Apply the plan to `previous`: safe updates always, conflicts and
    /// deletions only when approved, additions appended. Existing ids,
    /// folders, ordering and favorites are kept; added requests are moved
    /// into the previous requests' workspace.
    pub fn apply(&self, previous: &[RequestDefinition], approval: &ReimportApproval) -> Vec<RequestDefinition> {
        let mut out = Vec::with_capacity(previous.len() + self.added.len());
        for prev in previous {
            if self.removed.iter().any(|r| r.existing_id == prev.meta.id) && approval.delete.contains(&prev.meta.id) {
                continue;
            }
            let change =
                self.updated.iter().find(|c| c.existing_id == prev.meta.id).or_else(|| {
                    self.conflicts.iter().find(|c| c.existing_id == prev.meta.id && approval.overwrite.contains(&c.existing_id))
                });
            match change {
                Some(c) => {
                    let mut r = prev.clone();
                    r.spec = c.fresh.spec.clone();
                    r.name = c.fresh.name.clone();
                    r.description = c.fresh.description.clone();
                    r.tags = c.fresh.tags.clone();
                    r.meta.updated_at = c.fresh.meta.updated_at;
                    out.push(r);
                }
                None => out.push(prev.clone()),
            }
        }
        let ws = previous.first().map(|p| p.workspace_id);
        for a in &self.added {
            let mut r = a.clone();
            if let Some(ws) = ws {
                r.workspace_id = ws;
            }
            out.push(r);
        }
        out
    }
}
