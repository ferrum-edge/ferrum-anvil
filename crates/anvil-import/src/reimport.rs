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
//!
//! A request's name, description and tags are not part of its spec hash.
//! Each is compared on its own, by the same rules: a request the user
//! renamed keeps the user's name when only its spec changed upstream, and a
//! rename upstream of a request the user also renamed is a conflict.
//!
//! The same rules apply to the import's scoped configuration
//! ([`ImportedScope`]: the source's own variables, auth, settings and
//! description, its environments, where a server URL lives as `baseUrl`,
//! and the settings of its folders). There is no hash on those objects, nor
//! on a request's name, so the caller keeps [`ImportedScope::unit_hashes`]
//! and [`request_unit_hashes`] of what was generated and passes them back
//! in [`ScopeDiff::generated`].

use crate::ImportResult;
use crate::util::{canonical_json, sha256_hex, spec_hash};
use anvil_domain::Id;
use anvil_domain::auth::AuthConfig;
use anvil_domain::request::{ImportSource, RequestSpec};
use anvil_domain::settings::SettingsOverrides;
use anvil_domain::workspace::{Environment, Folder, RequestDefinition, Variable};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap, HashSet};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ReimportChange {
    pub existing_id: Id,
    pub operation_key: String,
    /// The existing request's spec no longer matches what was generated.
    pub user_edited: bool,
    /// Top-level spec fields that differ between the existing request and
    /// the fresh import (`url`, `headers`, `body`, …), then `name`,
    /// `description` and `tags` when they differ.
    pub changed_fields: Vec<String>,
    /// What changed upstream, and so what applying this change writes:
    /// `spec`, `name`, `description` and/or `tags`. The rest stays as it
    /// is, so a request the user renamed keeps its name when only its spec
    /// changed upstream.
    #[serde(default)]
    pub upstream_fields: Vec<String>,
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

/// What an import configures besides requests: the source's own scope
/// (description, settings, variables and auth of a new workspace, or of the
/// import root in an existing one), its environments and its folders. An
/// OpenAPI server is an environment with a `baseUrl`, so a changed server is
/// a change here, not in the requests that use `{{baseUrl}}`.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize, JsonSchema)]
pub struct ImportedScope {
    pub description: String,
    pub settings: SettingsOverrides,
    pub variables: Vec<Variable>,
    pub auth: AuthConfig,
    pub environments: Vec<Environment>,
    /// The import's folders. Their name, description, settings, variables
    /// and auth are compared for a folder both sides have; one only the
    /// source has arrives with the requests added in it
    /// ([`ReimportPlan::added_folders`]), and one only the store has is left
    /// alone.
    #[serde(default)]
    pub folders: Vec<Folder>,
}

impl ImportedScope {
    /// The scope `result` generated, as a new workspace stores it.
    pub fn generated(result: &ImportResult) -> Self {
        let w = &result.workspace;
        ImportedScope {
            description: w.description.clone(),
            settings: w.settings.clone(),
            variables: w.variables.clone(),
            auth: w.auth.clone(),
            environments: result.environments.clone(),
            folders: result.folders.clone(),
        }
    }

    /// SHA-256 of the canonical JSON of every unit, keyed as
    /// [`ScopeChange::key`]. Keep it, with [`request_unit_hashes`], for what
    /// an import generated and pass it to the next [`reimport_diff`] in
    /// [`ScopeDiff::generated`].
    pub fn unit_hashes(&self) -> BTreeMap<String, String> {
        scope_units(self).into_iter().map(|(k, v)| (k, unit_hash(&v))).collect()
    }
}

/// SHA-256 of the name, description and tags of every linked request in
/// `requests`, keyed `requests/<operation key>/name` (`…/description`,
/// `…/tags`). Keep it with [`ImportedScope::unit_hashes`] of what an import
/// generated, in the same map, so the next [`reimport_diff`] tells a user's
/// rename from one upstream.
pub fn request_unit_hashes(requests: &[RequestDefinition]) -> BTreeMap<String, String> {
    requests.iter().flat_map(request_units).map(|(k, v)| (k, unit_hash(&v))).collect()
}

/// A request's own fields that are not part of its spec hash.
const DETAILS: [&str; 3] = ["name", "description", "tags"];

fn request_key(operation_key: &str, part: &str) -> String {
    format!("requests/{operation_key}/{part}")
}

fn detail(q: &RequestDefinition, part: &str) -> Value {
    match part {
        "name" => Value::String(q.name.clone()),
        "description" => Value::String(q.description.clone()),
        _ => to_json(&q.tags),
    }
}

fn request_units(q: &RequestDefinition) -> Vec<(String, Value)> {
    let Some(src) = &q.spec.source else { return vec![] };
    DETAILS.iter().map(|part| (request_key(&src.operation_key, part), detail(q, part))).collect()
}

/// One unit of imported scoped configuration that differs between what is
/// stored and the fresh import.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ScopeChange {
    /// `description`, `settings`, `auth`, `variables/<name>`,
    /// `environments/<id>` (the environment itself: its name, or all of it
    /// when it is added or removed), `environments/<id>/variables/<name>`,
    /// `folders/<id>` (the folder's name), `folders/<id>/description`,
    /// `folders/<id>/settings`, `folders/<id>/auth` or
    /// `folders/<id>/variables/<name>`. A repeated variable name gets a `#n`
    /// suffix.
    pub key: String,
    /// What the unit is, for a preview (`environment "Production": variable
    /// baseUrl`).
    pub label: String,
    /// The stored value differs from what the last import generated, or
    /// that is not known.
    pub user_edited: bool,
    /// An `environments/<id>` key for an environment only one side has
    /// (added or removed, upstream or by the user): the change covers it
    /// whole, with its variables, and `user_edited` and the upstream change
    /// are judged on all of it.
    #[serde(default)]
    pub whole_environment: bool,
    /// The freshly generated value (the whole environment for an
    /// `environments/<id>` key); `None` when the source no longer has it.
    pub fresh: Option<Value>,
}

/// Imported scoped configuration for [`reimport_diff`].
#[derive(Debug, Clone, Copy)]
pub struct ScopeDiff<'a> {
    /// As stored now, possibly edited by the user.
    pub current: &'a ImportedScope,
    /// [`ImportedScope::unit_hashes`] and [`request_unit_hashes`] of what
    /// the last import generated (after a reimport,
    /// [`ReimportPlan::next_generated_scope`]). `None` when unknown: every
    /// difference is then a conflict or a removal awaiting approval. A unit
    /// missing from it is unknown in the same way.
    pub generated: Option<&'a BTreeMap<String, String>>,
    /// What the fresh import generates, as it would be stored.
    pub fresh: &'a ImportedScope,
}

/// Stands in for a declined conflict's earlier hash when there was none; it
/// matches no value, so the conflict is offered again.
const DECLINED: &str = "declined";

/// Result of [`reimport_diff`]. Nothing is applied until [`ReimportPlan::apply`]
/// and [`ReimportPlan::apply_scope`].
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
    /// Edited by the user (its spec, name, description or tags), unchanged
    /// upstream: kept.
    pub preserved_edits: Vec<Id>,
    pub unchanged: Vec<Id>,
    /// Gone from the source: kept unless their id is in
    /// [`ReimportApproval::delete`].
    pub removed: Vec<ReimportRemoval>,
    /// Existing requests with no import link: untouched.
    pub unlinked: Vec<Id>,
    /// Scoped configuration changed upstream, not edited by the user: safe
    /// to apply. A changed server shows up here as its environment's
    /// `baseUrl` (and name).
    #[serde(default)]
    pub scope_updated: Vec<ScopeChange>,
    /// Scoped configuration changed upstream *and* edited by the user: kept
    /// as the user left it unless its key is in
    /// [`ReimportApproval::overwrite_scope`].
    #[serde(default)]
    pub scope_conflicts: Vec<ScopeChange>,
    /// Keys of scoped configuration edited by the user, unchanged upstream:
    /// kept.
    #[serde(default)]
    pub scope_preserved_edits: Vec<String>,
    /// Scoped configuration gone from the source: kept unless its key is in
    /// [`ReimportApproval::delete_scope`].
    #[serde(default)]
    pub scope_removed: Vec<ScopeChange>,
}

/// Explicit user decisions for [`ReimportPlan::apply`] and
/// [`ReimportPlan::apply_scope`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ReimportApproval {
    /// Conflicting (user-edited) requests to overwrite with the fresh spec.
    pub overwrite: Vec<Id>,
    /// Removed-upstream requests to delete.
    pub delete: Vec<Id>,
    /// Conflicting scope keys ([`ScopeChange::key`]) to overwrite with the
    /// fresh value.
    #[serde(default)]
    pub overwrite_scope: Vec<String>,
    /// Removed-upstream scope keys to delete.
    #[serde(default)]
    pub delete_scope: Vec<String>,
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

/// Compare previously imported (and possibly edited) requests and scoped
/// configuration with a fresh import of the same source.
pub fn reimport_diff(previous: &[RequestDefinition], fresh: &ImportResult, scope: ScopeDiff<'_>) -> ReimportPlan {
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
        scope_updated: vec![],
        scope_conflicts: vec![],
        scope_preserved_edits: vec![],
        scope_removed: vec![],
    };
    let mut matched: HashSet<&str> = HashSet::new();
    for prev in previous {
        let Some(src) = &prev.spec.source else {
            plan.unlinked.push(prev.meta.id);
            continue;
        };
        let spec_edited = spec_hash(&prev.spec) != src.generated_hash;
        let found = fresh.requests.iter().find(|f| f.spec.source.as_ref().is_some_and(|s| s.operation_key == src.operation_key));
        let Some(f) = found else {
            let details_edited = DETAILS.iter().any(|part| detail_diff(prev, prev, src, part, scope.generated).1);
            let user_edited = spec_edited || details_edited;
            plan.removed.push(ReimportRemoval { existing_id: prev.meta.id, operation_key: src.operation_key.clone(), user_edited });
            continue;
        };
        matched.insert(src.operation_key.as_str());
        let fsrc = f.spec.source.as_ref().expect("filtered on source");
        // Each part as (name, differs, changed upstream, edited by the user).
        let spec_fields = changed_fields(&prev.spec, &f.spec);
        let mut parts = vec![("spec", !spec_fields.is_empty(), fsrc.generated_hash != src.generated_hash, spec_edited)];
        for part in DETAILS {
            let (upstream, edited) = detail_diff(prev, f, src, part, scope.generated);
            parts.push((part, detail(prev, part) != detail(f, part), upstream, edited));
        }
        let differing: Vec<_> = parts.into_iter().filter(|(_, differs, _, _)| *differs).collect();
        let upstream: Vec<String> = differing.iter().filter(|(_, _, up, _)| *up).map(|(p, ..)| p.to_string()).collect();
        if upstream.is_empty() {
            if differing.iter().any(|(_, _, _, edited)| *edited) {
                plan.preserved_edits.push(prev.meta.id);
            } else {
                plan.unchanged.push(prev.meta.id);
            }
            continue;
        }
        let user_edited = differing.iter().any(|(_, _, up, edited)| *up && *edited);
        let mut changed = spec_fields;
        changed.extend(differing.iter().map(|(p, ..)| *p).filter(|p| *p != "spec").map(String::from));
        let change = ReimportChange {
            existing_id: prev.meta.id,
            operation_key: src.operation_key.clone(),
            user_edited,
            changed_fields: changed,
            upstream_fields: upstream,
            fresh: f.clone(),
        };
        if user_edited {
            plan.conflicts.push(change);
        } else {
            plan.updated.push(change);
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
    diff_scope(&mut plan, scope);
    plan
}

/// Whether `part` of the request `prev` (linked by `src`) changed upstream,
/// in `fresh`, and whether the user edited it, judged on the hash `generated`
/// holds for it; both when that is unknown.
fn detail_diff(
    prev: &RequestDefinition,
    fresh: &RequestDefinition,
    src: &ImportSource,
    part: &str,
    generated: Option<&BTreeMap<String, String>>,
) -> (bool, bool) {
    let Some(g) = generated.and_then(|g| g.get(&request_key(&src.operation_key, part))) else { return (true, true) };
    (*g != unit_hash(&detail(fresh, part)), *g != unit_hash(&detail(prev, part)))
}

/// Three-way comparison of every scope unit: as stored, as generated last
/// time and as generated now.
fn diff_scope(plan: &mut ReimportPlan, scope: ScopeDiff<'_>) {
    let current_units = scope_units(scope.current);
    let fresh_units = scope_units(scope.fresh);
    let current: BTreeMap<String, String> = current_units.iter().map(|(k, v)| (k.clone(), unit_hash(v))).collect();
    let fresh: BTreeMap<String, String> = fresh_units.iter().map(|(k, v)| (k.clone(), unit_hash(v))).collect();
    // An environment only one side has (added or removed, upstream or by
    // the user) is one unit; its variables go with it.
    let one_sided: HashSet<String> = scope
        .current
        .environments
        .iter()
        .chain(&scope.fresh.environments)
        .map(|e| environment_key(e.meta.id))
        .filter(|k| !(current.contains_key(k) && fresh.contains_key(k)))
        .collect();
    // A folder only one side has is not compared: an added one arrives with
    // the requests added in it, and a removed one is left alone.
    let lone_folders: HashSet<String> = scope
        .current
        .folders
        .iter()
        .chain(&scope.fresh.folders)
        .map(|f| folder_key(f.meta.id))
        .filter(|k| !(current.contains_key(k) && fresh.contains_key(k)))
        .collect();
    let current_only = current_units.iter().map(|(k, _)| k).filter(|k| !fresh.contains_key(*k));
    for key in fresh_units.iter().map(|(k, _)| k).chain(current_only) {
        if one_sided.iter().any(|e| key.starts_with(&format!("{e}/"))) {
            continue;
        }
        if lone_folders.iter().any(|lone| key == lone || key.starts_with(&format!("{lone}/"))) {
            continue;
        }
        let whole = one_sided.contains(key);
        let (c, f) = (hash_at(&current, key, whole), hash_at(&fresh, key, whole));
        if c == f {
            continue;
        }
        let generated = scope.generated.map(|g| hash_at(g, key, whole));
        let upstream_changed = generated.as_ref().is_none_or(|g| *g != f);
        let user_edited = generated.as_ref().is_none_or(|g| *g != c);
        if !upstream_changed {
            plan.scope_preserved_edits.push(key.clone());
            continue;
        }
        let fresh_value = match scope.fresh.environments.iter().find(|e| environment_key(e.meta.id) == *key) {
            Some(e) => Some(to_json(e)),
            None => fresh_units.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone()),
        };
        let label = scope_label(key, scope);
        let change = ScopeChange { key: key.clone(), label, user_edited, whole_environment: whole, fresh: fresh_value };
        if f.is_none() {
            plan.scope_removed.push(change);
        } else if user_edited {
            plan.scope_conflicts.push(change);
        } else {
            plan.scope_updated.push(change);
        }
    }
}

/// The hash `hashes` (unit key to hash) hold for `key`. For a `whole`
/// environment it is one hash over the environment and all its variables;
/// `None` when there is no unit of it.
fn hash_at(hashes: &BTreeMap<String, String>, key: &str, whole: bool) -> Option<String> {
    if !whole {
        return hashes.get(key).cloned();
    }
    let all: serde_json::Map<String, Value> = within(hashes, key).map(|(k, h)| (k.clone(), Value::String(h.clone()))).collect();
    (!all.is_empty()).then(|| unit_hash(&Value::Object(all)))
}

/// The entries of `hashes` for the environment at `key` and its variables.
fn within<'h>(hashes: &'h BTreeMap<String, String>, key: &str) -> impl Iterator<Item = (&'h String, &'h String)> {
    let prefix = format!("{key}/");
    let key = key.to_string();
    hashes.iter().filter(move |(k, _)| **k == key || k.starts_with(&prefix))
}

/// Every comparable unit of `scope`: description, settings, auth, each
/// variable, then each environment (its name) followed by its variables,
/// then each folder (its name) followed by its description, settings, auth
/// and variables.
fn scope_units(scope: &ImportedScope) -> Vec<(String, Value)> {
    let mut out = vec![
        ("description".to_string(), Value::String(scope.description.clone())),
        ("settings".to_string(), to_json(&scope.settings)),
        ("auth".to_string(), to_json(&scope.auth)),
    ];
    out.extend(variable_keys("variables", &scope.variables).into_iter().map(|(k, v)| (k, to_json(v))));
    for e in &scope.environments {
        let at = environment_key(e.meta.id);
        let variables = variable_keys(&format!("{at}/variables"), &e.variables);
        out.push((at, Value::String(e.name.clone())));
        out.extend(variables.into_iter().map(|(k, v)| (k, to_json(v))));
    }
    for f in &scope.folders {
        let at = folder_key(f.meta.id);
        let variables = variable_keys(&format!("{at}/variables"), &f.variables);
        out.push((at.clone(), Value::String(f.name.clone())));
        out.push((format!("{at}/description"), Value::String(f.description.clone())));
        out.push((format!("{at}/settings"), to_json(&f.settings)));
        out.push((format!("{at}/auth"), to_json(&f.auth)));
        out.extend(variables.into_iter().map(|(k, v)| (k, to_json(v))));
    }
    out
}

/// `<prefix>/<name>` for each variable; a repeated name gets `#n`.
fn variable_keys<'v>(prefix: &str, variables: &'v [Variable]) -> Vec<(String, &'v Variable)> {
    let mut seen: HashMap<&str, usize> = HashMap::new();
    variables
        .iter()
        .map(|v| {
            let n = seen.entry(v.name.as_str()).or_insert(0);
            *n += 1;
            let key = if *n == 1 { format!("{prefix}/{}", v.name) } else { format!("{prefix}/{}#{n}", v.name) };
            (key, v)
        })
        .collect()
}

fn environment_key(id: Id) -> String {
    format!("environments/{id}")
}

fn folder_key(id: Id) -> String {
    format!("folders/{id}")
}

fn scope_label(key: &str, scope: ScopeDiff<'_>) -> String {
    for e in scope.fresh.environments.iter().chain(&scope.current.environments) {
        let at = environment_key(e.meta.id);
        if key == at {
            return format!("environment \"{}\"", e.name);
        }
        if let Some(name) = key.strip_prefix(format!("{at}/variables/").as_str()) {
            return format!("environment \"{}\": variable {name}", e.name);
        }
    }
    for f in scope.fresh.folders.iter().chain(&scope.current.folders) {
        let at = folder_key(f.meta.id);
        if key == at {
            return format!("folder \"{}\"", f.name);
        }
        if let Some(unit) = key.strip_prefix(format!("{at}/").as_str()) {
            return format!("folder \"{}\": {}", f.name, unit_label(unit));
        }
    }
    unit_label(key)
}

fn unit_label(unit: &str) -> String {
    match unit.strip_prefix("variables/") {
        Some(name) => format!("variable {name}"),
        None => unit.to_string(),
    }
}

fn to_json<T: Serialize>(v: &T) -> Value {
    serde_json::to_value(v).unwrap_or(Value::Null)
}

fn unit_hash(v: &Value) -> String {
    sha256_hex(canonical_json(v).as_bytes())
}

/// `current` with the taken units of `fresh` applied: replaced in place,
/// removed, or appended in source order.
fn merge_variables(prefix: &str, current: &[Variable], fresh: &[Variable], take: &HashSet<&str>) -> Vec<Variable> {
    let current = variable_keys(prefix, current);
    let fresh = variable_keys(prefix, fresh);
    let mut out = vec![];
    for (k, v) in &current {
        if !take.contains(k.as_str()) {
            out.push((*v).clone());
        } else if let Some((_, f)) = fresh.iter().find(|(f, _)| f == k) {
            out.push((*f).clone());
        }
    }
    for (k, f) in &fresh {
        if take.contains(k.as_str()) && !current.iter().any(|(c, _)| c == k) {
            out.push((*f).clone());
        }
    }
    out
}

impl ReimportPlan {
    /// Apply the plan to `previous`: safe updates always, conflicts and
    /// deletions only when approved, additions appended. An update writes
    /// only its [`ReimportChange::upstream_fields`]. Existing ids, folders,
    /// ordering and favorites are kept; added requests are moved into the
    /// previous requests' workspace. A request whose spec is updated loses
    /// its `revision_id`: that revision holds the old spec, so the caller
    /// records a new one when it persists the update.
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
                    let takes = |part: &str| c.upstream_fields.iter().any(|f| f == part);
                    let mut r = prev.clone();
                    if takes("spec") {
                        r.spec = c.fresh.spec.clone();
                        r.revision_id = None;
                    }
                    if takes("name") {
                        r.name = c.fresh.name.clone();
                    }
                    if takes("description") {
                        r.description = c.fresh.description.clone();
                    }
                    if takes("tags") {
                        r.tags = c.fresh.tags.clone();
                    }
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

    /// Apply the scope part of the plan to `current`: safe updates always,
    /// conflicts and removals only when approved. `fresh` is the
    /// [`ScopeDiff::fresh`] the plan was made from. An environment the
    /// source added comes whole, and one approved for deletion goes whole.
    /// A folder keeps its place; only its compared units change.
    pub fn apply_scope(&self, current: &ImportedScope, fresh: &ImportedScope, approval: &ReimportApproval) -> ImportedScope {
        let take: HashSet<&str> = self
            .scope_updated
            .iter()
            .chain(self.scope_conflicts.iter().filter(|c| approval.overwrite_scope.contains(&c.key)))
            .chain(self.scope_removed.iter().filter(|c| approval.delete_scope.contains(&c.key)))
            .map(|c| c.key.as_str())
            .collect();
        let mut out = current.clone();
        if take.contains("description") {
            out.description = fresh.description.clone();
        }
        if take.contains("settings") {
            out.settings = fresh.settings.clone();
        }
        if take.contains("auth") {
            out.auth = fresh.auth.clone();
        }
        out.variables = merge_variables("variables", &current.variables, &fresh.variables, &take);
        out.environments = vec![];
        for e in &current.environments {
            let at = environment_key(e.meta.id);
            let taken = take.contains(at.as_str());
            match fresh.environments.iter().find(|f| f.meta.id == e.meta.id) {
                // Approved for deletion.
                None if taken => {}
                None => out.environments.push(e.clone()),
                Some(f) => {
                    let mut e = e.clone();
                    if taken {
                        e.name = f.name.clone();
                    }
                    e.variables = merge_variables(&format!("{at}/variables"), &e.variables, &f.variables, &take);
                    out.environments.push(e);
                }
            }
        }
        let added = fresh.environments.iter().filter(|f| !current.environments.iter().any(|e| e.meta.id == f.meta.id));
        out.environments.extend(added.filter(|f| take.contains(environment_key(f.meta.id).as_str())).cloned());
        for c in &mut out.folders {
            let Some(f) = fresh.folders.iter().find(|f| f.meta.id == c.meta.id) else { continue };
            let at = folder_key(c.meta.id);
            let taken = |unit: &str| take.contains(format!("{at}{unit}").as_str());
            if taken("") {
                c.name = f.name.clone();
            }
            if taken("/description") {
                c.description = f.description.clone();
            }
            if taken("/settings") {
                c.settings = f.settings.clone();
            }
            if taken("/auth") {
                c.auth = f.auth.clone();
            }
            c.variables = merge_variables(&format!("{at}/variables"), &c.variables, &f.variables, &take);
        }
        out
    }

    /// The unit hashes to keep for the next reimport once this plan is
    /// applied with `approval`: the fresh import's (`fresh` and
    /// `fresh_requests`, the fresh import's requests), except that a
    /// declined conflict or removal keeps its earlier hash (for a whole
    /// environment, those of it and its variables), so it is offered again.
    /// A declined conflict with no earlier hash gets one that matches
    /// nothing; a declined removal with none is left out, so the next
    /// reimport keeps it as the user's own instead of offering to delete it
    /// again. A declined request conflict, or a kept removed request, keeps
    /// the earlier hashes of its name, description and tags.
    pub fn next_generated_scope(
        &self,
        fresh: &ImportedScope,
        fresh_requests: &[RequestDefinition],
        generated: Option<&BTreeMap<String, String>>,
        approval: &ReimportApproval,
    ) -> BTreeMap<String, String> {
        let mut out = fresh.unit_hashes();
        out.extend(request_unit_hashes(fresh_requests));
        let declined = self.conflicts.iter().filter(|c| !approval.overwrite.contains(&c.existing_id)).map(|c| (&c.operation_key, false));
        let kept = self.removed.iter().filter(|r| !approval.delete.contains(&r.existing_id)).map(|r| (&r.operation_key, true));
        for (operation_key, removal) in declined.chain(kept) {
            for part in DETAILS {
                let key = request_key(operation_key, part);
                match generated.and_then(|g| g.get(&key)) {
                    Some(h) => out.insert(key, h.clone()),
                    None if removal => out.remove(&key),
                    None => out.insert(key, DECLINED.to_string()),
                };
            }
        }
        let conflicts = self.scope_conflicts.iter().filter(|c| !approval.overwrite_scope.contains(&c.key)).map(|c| (c, false));
        let removals = self.scope_removed.iter().filter(|c| !approval.delete_scope.contains(&c.key)).map(|c| (c, true));
        for (c, removal) in conflicts.chain(removals) {
            let earlier: Vec<(String, String)> = match (generated, c.whole_environment) {
                (None, _) => vec![],
                (Some(g), false) => g.get_key_value(&c.key).map(|(k, h)| (k.clone(), h.clone())).into_iter().collect(),
                (Some(g), true) => within(g, &c.key).map(|(k, h)| (k.clone(), h.clone())).collect(),
            };
            let prefix = format!("{}/", c.key);
            out.retain(|k, _| *k != c.key && !(c.whole_environment && k.starts_with(&prefix)));
            if !earlier.is_empty() {
                out.extend(earlier);
            } else if !removal {
                out.insert(c.key.clone(), DECLINED.to_string());
            }
        }
        out
    }
}
