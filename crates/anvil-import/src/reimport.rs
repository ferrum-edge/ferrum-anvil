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
//! * requests without an import link are left alone;
//! * a credential reference never moves to another request (#584). See
//!   [`Continuity`] for the invariants and where each is enforced.
//!
//! A request's name, description and tags are not part of its spec hash.
//! Each is compared on its own, by the same rules: a request the user
//! renamed keeps the user's name when only its spec changed upstream, and a
//! rename upstream of a request the user also renamed is a conflict. A
//! declined conflict keeps only the parts the user edited: the rest of what
//! changed upstream is applied as a safe update would be.
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
    /// The parts of `upstream_fields` the user edited too: what makes this
    /// change a conflict. A declined conflict keeps these as the user left
    /// them and still takes the rest of `upstream_fields`.
    #[serde(default)]
    pub conflicting_fields: Vec<String>,
    /// Held for review although the user may not have edited it: it carries
    /// credentials the import allocated (its own, or inherited from a
    /// folder) and is matched only by its position in the source, or a
    /// placeholder it holds could be kept only by an ambiguous match, so
    /// applying the source's version could point it at variables filled for
    /// another request (`Continuity`). Every part that changed upstream is
    /// then in `conflicting_fields`: declined, nothing of it is applied.
    #[serde(default)]
    pub credential_review: bool,
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

impl ReimportChange {
    /// Whether declining this change keeps `part` as the user left it: a
    /// part in `conflicting_fields`, or any part when that is empty (a plan
    /// from before it was kept).
    fn keeps(&self, part: &str) -> bool {
        self.conflicting_fields.is_empty() || self.conflicting_fields.iter().any(|f| f == part)
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
    /// Held for review although the user may not have edited it: a unit of
    /// a folder known only by its position that holds or feeds credentials
    /// the import allocated, or an auth unit whose fresh version puts such a
    /// placeholder where the stored one has another reference
    /// (`Continuity`).
    #[serde(default)]
    pub credential_review: bool,
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
    // The first fresh request of each operation key, as a search in order
    // finds it, and each fresh folder by id: looked up once per request.
    let mut by_key: HashMap<&str, &RequestDefinition> = HashMap::new();
    for f in &fresh.requests {
        if let Some(s) = &f.spec.source {
            by_key.entry(s.operation_key.as_str()).or_insert(f);
        }
    }
    let mut folders: HashMap<Id, &Folder> = HashMap::new();
    for f in &fresh.folders {
        folders.entry(f.meta.id).or_insert(f);
    }
    let continuity = Continuity::new(previous, fresh, scope);
    let mut taken = continuity.names_in_use(previous);
    for prev in previous {
        let Some(src) = &prev.spec.source else {
            plan.unlinked.push(prev.meta.id);
            continue;
        };
        let spec_edited = spec_hash(&prev.spec) != src.generated_hash;
        let found = by_key.get(src.operation_key.as_str()).copied();
        let Some(f) = found else {
            let details_edited = DETAILS.iter().any(|part| detail_diff(prev, prev, src, part, scope.generated).1);
            let user_edited = spec_edited || details_edited;
            plan.removed.push(ReimportRemoval { existing_id: prev.meta.id, operation_key: src.operation_key.clone(), user_edited });
            continue;
        };
        matched.insert(src.operation_key.as_str());
        let guard = continuity.matched(prev, f, &src.operation_key);
        let f = guard.fresh.as_ref().unwrap_or(f);
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
        let mut conflicting: Vec<String> =
            differing.iter().filter(|(_, _, up, edited)| *up && *edited).map(|(p, ..)| p.to_string()).collect();
        let user_edited = !conflicting.is_empty();
        // Held whole: declined, nothing of it is applied, its name included
        // (a positional request's name says which request now holds the
        // position).
        let credential_review = guard.review;
        if credential_review {
            for part in &upstream {
                if !conflicting.contains(part) {
                    conflicting.push(part.clone());
                }
            }
        }
        let mut changed = spec_fields;
        changed.extend(differing.iter().map(|(p, ..)| *p).filter(|p| *p != "spec").map(String::from));
        let change = ReimportChange {
            existing_id: prev.meta.id,
            operation_key: src.operation_key.clone(),
            user_edited,
            changed_fields: changed,
            upstream_fields: upstream,
            conflicting_fields: conflicting,
            credential_review,
            fresh: f.clone(),
        };
        if user_edited || credential_review {
            plan.conflicts.push(change);
        } else {
            plan.updated.push(change);
        }
    }
    let mut needed: HashSet<Id> = HashSet::new();
    for f in &fresh.requests {
        let key = f.spec.source.as_ref().map(|s| s.operation_key.as_str()).unwrap_or("");
        if !matched.contains(key) {
            plan.added.push(continuity.added(f, &mut taken));
            let mut cur = f.folder_id;
            while let Some(id) = cur {
                if !needed.insert(id) {
                    break;
                }
                cur = folders.get(&id).and_then(|x| x.parent_id);
            }
        }
    }
    plan.added_folders =
        fresh.folders.iter().filter(|f| needed.contains(&f.meta.id)).map(|f| continuity.added_folder(f, &mut taken)).collect();
    diff_scope(&mut plan, scope, &continuity);
    plan
}

/// A string that is exactly one `{{name}}` reference.
fn pure_reference(s: &str) -> bool {
    s.len() > 4 && s.starts_with("{{") && s.ends_with("}}") && !s[2..s.len() - 2].contains(['{', '}'])
}

/// The name inside a pure reference.
fn reference_name(r: &str) -> &str {
    r.get(2..r.len().saturating_sub(2)).unwrap_or("").trim()
}

/// One RFC 6901 reference token.
fn pointer_token(k: &str) -> String {
    k.replace('~', "~0").replace('/', "~1")
}

/// Every pure reference in `v`, by JSON pointer under `at`.
fn collect_references(v: &Value, at: &str, out: &mut BTreeMap<String, String>) {
    match v {
        Value::String(s) if pure_reference(s) => {
            out.insert(at.to_string(), s.clone());
        }
        Value::Array(items) => {
            for (i, x) in items.iter().enumerate() {
                collect_references(x, &format!("{at}/{i}"), out);
            }
        }
        Value::Object(m) => {
            for (k, x) in m {
                collect_references(x, &format!("{at}/{}", pointer_token(k)), out);
            }
        }
        _ => {}
    }
}

/// Where an auth config holds a reference: JSON pointer to reference.
fn auth_slots(auth: &AuthConfig) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    collect_references(&to_json(auth), "", &mut out);
    out
}

/// A request spec as JSON, without its `source`.
fn spec_json(spec: &RequestSpec) -> Value {
    let mut spec = spec.clone();
    spec.source = None;
    to_json(&spec)
}

/// Where a request can hold a credential placeholder the import allocates:
/// every pure reference in its auth, and its URL when that is one pure
/// reference (a quarantined URL). JSON pointer (into [`spec_json`]) to
/// reference. Header, query and form placeholders are named after their
/// field and shared by every request with that field: they never move.
fn credential_slots(spec: &Value) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    if let Some(auth) = spec.get("auth") {
        collect_references(auth, "/auth", &mut out);
    }
    if let Some(Value::String(url)) = spec.get("url")
        && pure_reference(url)
    {
        out.insert("/url".to_string(), url.clone());
    }
    out
}

/// Whether a JSON pointer names a field by its name only, with no array
/// index in it.
fn semantic_pointer(path: &str) -> bool {
    !path.split('/').any(|seg| !seg.is_empty() && seg.bytes().all(|b| b.is_ascii_digit()))
}

/// Whether `name` has the shape of a placeholder an import allocates
/// (`auth_<16 hex>_<field>`, `url-needs-review-<16 hex>`), for references
/// stored by an earlier import, whose allocations are not at hand.
fn allocated_shape(name: &str) -> bool {
    let hex16 = |s: &str| s.len() >= 16 && s.as_bytes()[..16].iter().all(u8::is_ascii_hexdigit);
    name.strip_prefix("auth_").is_some_and(|rest| hex16(rest) && rest.as_bytes().get(16) == Some(&b'_'))
        || name.strip_prefix("url-needs-review-").is_some_and(hex16)
}

/// A repeated operation key's `#n` suffix (`postman:dup#2`).
fn repeated_key(key: &str) -> bool {
    key.rsplit_once('#').is_some_and(|(_, n)| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}

/// What [`Continuity::matched`] decided for a matched request.
struct Guarded {
    /// The fresh request with the existing request's references kept.
    fresh: Option<RequestDefinition>,
    /// Hold the request whole for review if anything changed upstream.
    review: bool,
}

/// Credential continuity on reimport (#584): a reference the user filled
/// never ends up used by another request. Each invariant has one place:
///
/// 1. *Only what the import allocated is handled.* The fresh import records
///    the placeholders it allocated ([`ImportResult::credential_names`]);
///    only those are kept or renamed. Every other reference, one the source
///    wrote or names (an OpenAPI security scheme's variable, a Postman
///    `{{token}}`), follows the source like any other change. ([`Continuity::allocated`])
/// 2. *Names follow identity.* An allocated name derives from its owner's
///    operation key as made unique (or folder key) and the field
///    (`crate::common::auth_secret_name`), never an index or a constant; an
///    empty id is no id, and a repeated one is positional
///    ([`ImportResult::positional_keys`]; [`Continuity::positional`]).
/// 3. *Added requests fail safe.* An added request (or folder) that would
///    reference an allocated name a stored variable already defines gets a
///    fresh, unused name instead, which the user fills: nothing resolves to
///    a value filled for another request. ([`Continuity::added`],
///    [`Continuity::added_folder`])
/// 4. *Positional continuity fails closed, for the whole chain.* A request
///    with allocated credentials (its own, or inherited from a folder) that
///    is matched only by its position is held whole for review when anything
///    of it changed upstream ([`Continuity::matched`]); every changed unit of a folder known only
///    by its position whose subtree holds such credentials (its auth, and
///    the variables that feed its requests' destinations, such as a host) is
///    held for review together ([`diff_scope`]), even when the requests'
///    specs are unchanged.
/// 5. *Kept only by semantic field.* A matched request with a stable
///    identity keeps its stored reference only where the fresh import put
///    an allocated placeholder of the same owner in the same named field
///    (no array index), each name used once; anything ambiguous is held for
///    review. ([`Continuity::matched`])
struct Continuity<'a> {
    fresh: &'a ImportResult,
    /// Operation keys of both sides, to recognize a repeated key.
    keys: HashSet<String>,
    /// Folders known only by their position.
    positional_folders: HashSet<Id>,
    /// Every folder's parent, fresh first.
    parents: HashMap<Id, Option<Id>>,
    /// Folders whose auth (stored or fresh) holds an allocated placeholder.
    credentialed_folders: HashSet<Id>,
    /// Positional folders whose subtree holds allocated credentials: their
    /// changed units are held for review together (invariant 4).
    guarded_folders: HashSet<String>,
    /// Variable names the stored scope defines: values the user may have
    /// filled.
    filled: HashSet<String>,
}

impl<'a> Continuity<'a> {
    fn new(previous: &[RequestDefinition], fresh: &'a ImportResult, scope: ScopeDiff<'_>) -> Self {
        let mut c = Continuity {
            fresh,
            keys: previous.iter().chain(&fresh.requests).filter_map(|q| q.spec.source.as_ref().map(|s| s.operation_key.clone())).collect(),
            positional_folders: fresh.positional_folders.iter().copied().collect(),
            parents: HashMap::new(),
            credentialed_folders: HashSet::new(),
            guarded_folders: HashSet::new(),
            filled: HashSet::new(),
        };
        for f in fresh.folders.iter().chain(&scope.current.folders) {
            c.parents.entry(f.meta.id).or_insert(f.parent_id);
        }
        for f in fresh.folders.iter().chain(&scope.current.folders) {
            if auth_slots(&f.auth).values().any(|r| c.looks_allocated(r)) {
                c.credentialed_folders.insert(f.meta.id);
            }
        }
        // The subtrees that hold allocated credentials: each credentialed
        // folder and each folder holding a request with its own, in either
        // placement, with their ancestors.
        let mut relevant: HashSet<Id> = HashSet::new();
        let own = |q: &RequestDefinition| credential_slots(&spec_json(&q.spec)).values().any(|r| c.looks_allocated(r));
        let mut starts: Vec<Option<Id>> = c.credentialed_folders.iter().map(|id| Some(*id)).collect();
        starts.extend(previous.iter().chain(&fresh.requests).filter(|q| own(q)).map(|q| q.folder_id));
        for start in starts {
            relevant.extend(c.chain(start));
        }
        c.guarded_folders = relevant.into_iter().filter(|id| c.positional_folders.contains(id)).map(folder_key).collect();
        c.filled = scope
            .current
            .variables
            .iter()
            .chain(scope.current.environments.iter().flat_map(|e| &e.variables))
            .chain(scope.current.folders.iter().flat_map(|f| &f.variables))
            .map(|v| v.name.clone())
            .collect();
        c
    }

    /// The folder `start` and its ancestors (a cycle or a chain over 256
    /// levels is cut).
    fn chain(&self, start: Option<Id>) -> Vec<Id> {
        let mut out = vec![];
        let mut cur = start;
        while let Some(id) = cur {
            if out.contains(&id) || out.len() >= 256 {
                break;
            }
            out.push(id);
            cur = self.parents.get(&id).copied().flatten();
        }
        out
    }

    /// The allocation record of the fresh import's placeholder `reference`
    /// (invariant 1).
    fn allocated(&self, reference: &str) -> Option<&'a crate::CredentialName> {
        self.fresh.credential_names.get(reference_name(reference))
    }

    /// Whether `reference` is a placeholder this import or, by its shape, an
    /// earlier one allocated.
    fn looks_allocated(&self, reference: &str) -> bool {
        self.allocated(reference).is_some() || allocated_shape(reference_name(reference))
    }

    /// Whether `key` names a position rather than an identity (invariant 2).
    fn positional(&self, key: &str) -> bool {
        self.fresh.positional_keys.contains(key) || repeated_key(key) || self.keys.contains(&format!("{key}#2"))
    }

    /// Whether a request inherits credentials from a folder with allocated
    /// ones, in its stored or its fresh placement.
    fn inherits_credentials(&self, q: &RequestDefinition) -> bool {
        matches!(q.spec.auth, AuthConfig::Inherit) && self.chain(q.folder_id).iter().any(|id| self.credentialed_folders.contains(id))
    }

    /// Every name a fresh name must not take: stored variables, allocated
    /// names, and every credential reference of both sides.
    fn names_in_use(&self, previous: &[RequestDefinition]) -> HashSet<String> {
        let mut taken = self.filled.clone();
        taken.extend(self.fresh.credential_names.keys().cloned());
        for q in previous.iter().chain(&self.fresh.requests) {
            taken.extend(credential_slots(&spec_json(&q.spec)).values().map(|r| reference_name(r).to_string()));
        }
        taken
    }

    /// A name for `name` no variable or reference uses, now taken.
    fn unused(name: &str, taken: &mut HashSet<String>) -> String {
        let mut n = 1;
        loop {
            let candidate = if n == 1 { format!("{name}_new") } else { format!("{name}_new_{n}") };
            n += 1;
            if taken.insert(candidate.clone()) {
                return candidate;
            }
        }
    }

    /// Invariants 4 and 5 for a request matched by its operation key.
    fn matched(&self, prev: &RequestDefinition, fresh: &RequestDefinition, key: &str) -> Guarded {
        let keep = Guarded { fresh: None, review: false };
        let (before_spec, mut after_spec) = (spec_json(&prev.spec), spec_json(&fresh.spec));
        let (before, after) = (credential_slots(&before_spec), credential_slots(&after_spec));
        if self.positional(key) {
            let own = before.values().chain(after.values()).any(|r| self.looks_allocated(r));
            let inherited = self.inherits_credentials(prev) || self.inherits_credentials(fresh);
            return Guarded { fresh: None, review: own || inherited };
        }
        let mut kept = false;
        for (path, new) in &after {
            let Some(name) = self.allocated(new) else { continue };
            let Some(old) = before.get(path) else { continue };
            if old == new || name.owner != key {
                continue;
            }
            let once = before.values().filter(|r| *r == old).count() == 1 && after.values().filter(|r| *r == new).count() == 1;
            if !semantic_pointer(path) || !once {
                return Guarded { fresh: None, review: true };
            }
            if let Some(slot) = after_spec.pointer_mut(path) {
                *slot = Value::String(old.clone());
                kept = true;
            }
        }
        if !kept {
            return keep;
        }
        let Ok(mut spec) = serde_json::from_value::<RequestSpec>(after_spec) else { return Guarded { fresh: None, review: true } };
        let Some(mut source) = fresh.spec.source.clone() else { return keep };
        source.generated_hash = spec_hash(&spec);
        spec.source = Some(source);
        let mut out = fresh.clone();
        out.spec = spec;
        Guarded { fresh: Some(out), review: false }
    }

    /// Invariant 3 for an added request: each allocated placeholder a stored
    /// variable defines becomes a fresh, unused name.
    fn added(&self, fresh: &RequestDefinition, taken: &mut HashSet<String>) -> RequestDefinition {
        let mut v = spec_json(&fresh.spec);
        let mut renamed = false;
        for (path, r) in credential_slots(&v) {
            let name = reference_name(&r);
            if self.allocated(&r).is_some()
                && self.filled.contains(name)
                && let Some(slot) = v.pointer_mut(&path)
            {
                *slot = Value::String(format!("{{{{{}}}}}", Self::unused(name, taken)));
                renamed = true;
            }
        }
        let mut out = fresh.clone();
        if renamed && let Ok(mut spec) = serde_json::from_value::<RequestSpec>(v) {
            if let Some(mut source) = fresh.spec.source.clone() {
                source.generated_hash = spec_hash(&spec);
                spec.source = Some(source);
            }
            out.spec = spec;
        }
        out
    }

    /// Invariant 3 for a folder added with the requests in it.
    fn added_folder(&self, fresh: &Folder, taken: &mut HashSet<String>) -> Folder {
        let mut v = to_json(&fresh.auth);
        let mut renamed = false;
        for (path, r) in auth_slots(&fresh.auth) {
            let name = reference_name(&r);
            if self.allocated(&r).is_some()
                && self.filled.contains(name)
                && let Some(slot) = v.pointer_mut(&path)
            {
                *slot = Value::String(format!("{{{{{}}}}}", Self::unused(name, taken)));
                renamed = true;
            }
        }
        let mut out = fresh.clone();
        if renamed && let Ok(auth) = serde_json::from_value::<AuthConfig>(v) {
            out.auth = auth;
        }
        out
    }
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
/// time and as generated now. `continuity` holds a guarded folder's changed
/// units and an auth unit that would move an allocated placeholder for
/// review ([`Continuity`], invariant 4).
fn diff_scope(plan: &mut ReimportPlan, scope: ScopeDiff<'_>, continuity: &Continuity<'_>) {
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
    // Looked up by key; reversed so that the first of equal keys wins.
    let fresh_values: HashMap<&str, &Value> = fresh_units.iter().rev().map(|(k, v)| (k.as_str(), v)).collect();
    let current_values: HashMap<&str, &Value> = current_units.iter().rev().map(|(k, v)| (k.as_str(), v)).collect();
    let references = |v: Option<&&Value>| {
        let mut out = BTreeMap::new();
        if let Some(v) = v {
            collect_references(v, "", &mut out);
        }
        out
    };
    let fresh_environments: HashMap<String, &Environment> =
        scope.fresh.environments.iter().rev().map(|e| (environment_key(e.meta.id), e)).collect();
    // Every unit that differs, as (key, whole environment, removed upstream,
    // changed upstream, edited by the user); decided below, once it is known
    // which folders changed upstream.
    let mut differing: Vec<(&String, bool, bool, bool, bool)> = vec![];
    let current_only = current_units.iter().map(|(k, _)| k).filter(|k| !fresh.contains_key(*k));
    for key in fresh_units.iter().map(|(k, _)| k).chain(current_only) {
        let owner = unit_owner(key);
        // A variable of a one-sided environment goes with it.
        if owner.is_some_and(|o| o.len() < key.len() && one_sided.contains(o)) {
            continue;
        }
        if owner.is_some_and(|o| lone_folders.contains(o)) {
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
        differing.push((key, whole, f.is_none(), upstream_changed, user_edited));
    }
    // Guarded folders (positional, holding or feeding allocated credentials)
    // with any unit changed upstream: all their changed units are held.
    let held: HashSet<&str> = differing
        .iter()
        .filter(|(_, _, _, upstream, _)| *upstream)
        .filter_map(|&(key, ..)| unit_owner(key).filter(|o| continuity.guarded_folders.contains(*o)))
        .collect();
    for (key, whole, removed, upstream_changed, user_edited) in differing {
        if !upstream_changed {
            plan.scope_preserved_edits.push(key.clone());
            continue;
        }
        let fresh_value = match fresh_environments.get(key.as_str()) {
            Some(e) => Some(to_json(e)),
            None => fresh_values.get(key.as_str()).copied().cloned(),
        };
        // An auth unit whose fresh version puts an allocated placeholder
        // where the stored one has another reference: it cannot be kept
        // here, so it is held.
        let moves_credentials = (key == "auth" || key.ends_with("/auth")) && {
            let (stored, fresh_refs) = (references(current_values.get(key.as_str())), references(fresh_values.get(key.as_str())));
            fresh_refs.iter().any(|(path, new)| continuity.allocated(new).is_some() && stored.get(path) != Some(new))
        };
        let credential_review = moves_credentials || unit_owner(key).is_some_and(|o| held.contains(o));
        let label = scope_label(key, scope);
        let change = ScopeChange { key: key.clone(), label, user_edited, whole_environment: whole, credential_review, fresh: fresh_value };
        if removed {
            plan.scope_removed.push(change);
        } else if user_edited || credential_review {
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

/// The environment or folder unit `key` is or belongs to: its first two
/// segments (`environments/<id>`, `folders/<id>`). `None` for a key with one
/// segment (`description`, `settings`, `auth`).
fn unit_owner(key: &str) -> Option<&str> {
    let first = key.find('/')?;
    Some(key[first + 1..].find('/').map_or(key, |second| &key[..first + 1 + second]))
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
    // Reversed so that the first of equal keys wins.
    let fresh_by_key: HashMap<&str, &Variable> = fresh.iter().rev().map(|(k, v)| (k.as_str(), *v)).collect();
    let current_keys: HashSet<&str> = current.iter().map(|(k, _)| k.as_str()).collect();
    let mut out = vec![];
    for (k, v) in &current {
        if !take.contains(k.as_str()) {
            out.push((*v).clone());
        } else if let Some(f) = fresh_by_key.get(k.as_str()) {
            out.push((*f).clone());
        }
    }
    for (k, f) in &fresh {
        if take.contains(k.as_str()) && !current_keys.contains(k.as_str()) {
            out.push((*f).clone());
        }
    }
    out
}

impl ReimportPlan {
    /// Apply the plan to `previous`: safe updates always, conflicts and
    /// deletions only when approved, additions appended. An update writes
    /// only its [`ReimportChange::upstream_fields`]; a declined conflict
    /// writes those not in its [`ReimportChange::conflicting_fields`], so the
    /// parts the user edited stay as they are. Existing ids, folders,
    /// ordering and favorites are kept; added requests are moved into the
    /// previous requests' workspace. A request whose spec is updated loses
    /// its `revision_id`: that revision holds the old spec, so the caller
    /// records a new one when it persists the update.
    pub fn apply(&self, previous: &[RequestDefinition], approval: &ReimportApproval) -> Vec<RequestDefinition> {
        let mut out = Vec::with_capacity(previous.len() + self.added.len());
        let removed: HashSet<Id> = self.removed.iter().map(|r| r.existing_id).collect();
        // The first change for each request, as a search in order finds it.
        let mut changes: HashMap<Id, &ReimportChange> = HashMap::new();
        for c in self.updated.iter().chain(&self.conflicts) {
            changes.entry(c.existing_id).or_insert(c);
        }
        for prev in previous {
            if removed.contains(&prev.meta.id) && approval.delete.contains(&prev.meta.id) {
                continue;
            }
            let change = changes.get(&prev.meta.id).copied();
            let taken = change.map(|c| self.taken_fields(c, approval)).unwrap_or_default();
            match change {
                Some(c) if !taken.is_empty() => {
                    let takes = |part: &str| taken.contains(&part);
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
                _ => out.push(prev.clone()),
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

    /// The parts of `c` that applying it with `approval` writes: all of its
    /// upstream fields for a safe update or an approved conflict, only those
    /// the user did not edit for a declined conflict.
    fn taken_fields<'c>(&self, c: &'c ReimportChange, approval: &ReimportApproval) -> Vec<&'c str> {
        let declined = self.conflicts.iter().any(|x| x.existing_id == c.existing_id) && !approval.overwrite.contains(&c.existing_id);
        c.upstream_fields.iter().map(String::as_str).filter(|part| !(declined && c.keeps(part))).collect()
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
        // By id; reversed so that the first of equal ids wins.
        let fresh_environments: HashMap<Id, &Environment> = fresh.environments.iter().rev().map(|f| (f.meta.id, f)).collect();
        let fresh_folders: HashMap<Id, &Folder> = fresh.folders.iter().rev().map(|f| (f.meta.id, f)).collect();
        let current_environments: HashSet<Id> = current.environments.iter().map(|e| e.meta.id).collect();
        out.environments = vec![];
        for e in &current.environments {
            let at = environment_key(e.meta.id);
            let taken = take.contains(at.as_str());
            match fresh_environments.get(&e.meta.id) {
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
        let added = fresh.environments.iter().filter(|f| !current_environments.contains(&f.meta.id));
        out.environments.extend(added.filter(|f| take.contains(environment_key(f.meta.id).as_str())).cloned());
        for c in &mut out.folders {
            let Some(f) = fresh_folders.get(&c.meta.id) else { continue };
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
    /// again. A kept removed request keeps the earlier hashes of its name,
    /// description and tags; a declined request conflict keeps those of the
    /// parts in its [`ReimportChange::conflicting_fields`].
    pub fn next_generated_scope(
        &self,
        fresh: &ImportedScope,
        fresh_requests: &[RequestDefinition],
        generated: Option<&BTreeMap<String, String>>,
        approval: &ReimportApproval,
    ) -> BTreeMap<String, String> {
        let mut out = fresh.unit_hashes();
        out.extend(request_unit_hashes(fresh_requests));
        // A declined conflict applied the parts the user did not edit; only
        // the others keep their earlier hashes.
        let mut earlier: Vec<(&String, &str, bool)> = vec![];
        for c in self.conflicts.iter().filter(|c| !approval.overwrite.contains(&c.existing_id)) {
            earlier.extend(DETAILS.into_iter().filter(|part| c.keeps(part)).map(|part| (&c.operation_key, part, false)));
        }
        for r in self.removed.iter().filter(|r| !approval.delete.contains(&r.existing_id)) {
            earlier.extend(DETAILS.into_iter().map(|part| (&r.operation_key, part, true)));
        }
        for (operation_key, part, removal) in earlier {
            let key = request_key(operation_key, part);
            match generated.and_then(|g| g.get(&key)) {
                Some(h) => out.insert(key, h.clone()),
                None if removal => out.remove(&key),
                None => out.insert(key, DECLINED.to_string()),
            };
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

#[cfg(test)]
mod tests {
    use super::unit_owner;

    #[test]
    fn a_units_owner_is_its_environment_or_folder() {
        let id = "0190f1c2-0000-7000-8000-000000000001";
        assert_eq!(unit_owner(&format!("environments/{id}")), Some(format!("environments/{id}").as_str()));
        assert_eq!(unit_owner(&format!("environments/{id}/variables/a/b")), Some(format!("environments/{id}").as_str()));
        assert_eq!(unit_owner(&format!("folders/{id}/auth")), Some(format!("folders/{id}").as_str()));
        assert_eq!(unit_owner("variables/token"), Some("variables/token"));
        assert_eq!(unit_owner("description"), None);
    }
}
