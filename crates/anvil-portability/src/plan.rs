//! Import planning: conflict detection and id remapping per policy.

use crate::graph::{PortableGraph, SecretValue};
use anvil_domain::Id;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConflictPolicy {
    /// Keep existing objects that share an id; add only new ones.
    Merge,
    /// Overwrite existing objects that share an id.
    Replace,
    /// Import everything under fresh ids (references remapped).
    Duplicate,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ImportPlan {
    pub policy: ConflictPolicy,
    /// Objects and secrets (counted together).
    pub to_create: usize,
    pub to_replace: usize,
    pub skipped_existing: usize,
    /// Objects and secrets that share an id with one already stored.
    pub conflicts: Vec<String>,
    /// Secrets that share an id with one stored here that a workspace outside
    /// the bundle (or no workspace) owns. Replace never overwrites or
    /// re-owns such a secret, so a Replace import is refused while any is
    /// listed; Merge keeps the stored secret and Duplicate never touches it.
    pub foreign_secrets: Vec<String>,
}

/// What the store already holds, as far as an import can collide with it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Existing {
    /// Ids of every stored object.
    pub objects: HashSet<Id>,
    /// Every stored secret, with the workspace that owns it (`None`: none does).
    pub secrets: HashMap<Id, Option<Id>>,
}

pub(crate) fn all_ids(g: &PortableGraph) -> Vec<(String, Id, String)> {
    let mut v = Vec::new();
    v.extend(g.workspaces.iter().map(|x| ("workspace".to_string(), x.meta.id, x.name.clone())));
    v.extend(g.folders.iter().map(|x| ("folder".to_string(), x.meta.id, x.name.clone())));
    v.extend(g.requests.iter().map(|x| ("request".to_string(), x.meta.id, x.name.clone())));
    v.extend(g.environments.iter().map(|x| ("environment".to_string(), x.meta.id, x.name.clone())));
    v.extend(g.tls_profiles.iter().map(|x| ("tls_profile".to_string(), x.id, x.name.clone())));
    v.extend(g.proxy_profiles.iter().map(|x| ("proxy_profile".to_string(), x.id, x.name.clone())));
    v.extend(g.integrations.iter().map(|x| ("integration".to_string(), x.id, x.name.clone())));
    v.extend(g.datasets.iter().map(|x| ("dataset".to_string(), x.meta.id, x.name.clone())));
    v.extend(g.scenarios.iter().map(|x| ("scenario".to_string(), x.meta.id, x.name.clone())));
    v.extend(g.load_plans.iter().map(|x| ("load_plan".to_string(), x.id, x.name.clone())));
    v
}

/// Compute what applying `g` would do given what already exists.
pub fn plan(g: &PortableGraph, existing: &Existing, policy: ConflictPolicy) -> ImportPlan {
    let mut ids = all_ids(g);
    ids.extend(secret_ids(g).map(|(id, v)| ("secret".to_string(), id, v.label.clone())));
    let conflicts: Vec<String> = ids
        .iter()
        .filter(|(_, id, _)| existing.objects.contains(id) || existing.secrets.contains_key(id))
        .map(|(k, id, n)| format!("{k} '{n}' ({id})"))
        .collect();
    let foreign_secrets = foreign_secrets(g, existing);
    let n = ids.len();
    let c = conflicts.len();
    let (to_create, to_replace, skipped_existing) = match policy {
        ConflictPolicy::Merge => (n - c, 0, c),
        ConflictPolicy::Replace => (n - c, c, 0),
        ConflictPolicy::Duplicate => (n, 0, 0),
    };
    ImportPlan { policy, to_create, to_replace, skipped_existing, conflicts, foreign_secrets }
}

/// The bundle's secrets, by id (validation refuses any other key).
fn secret_ids(g: &PortableGraph) -> impl Iterator<Item = (Id, &SecretValue)> {
    g.secrets.iter().filter_map(|(k, v)| Some((k.parse::<Id>().ok()?, v)))
}

/// Bundle secrets whose id is stored here under an owner that is not a
/// workspace in the bundle, as `secret 'label' (id)`.
pub fn foreign_secrets(g: &PortableGraph, existing: &Existing) -> Vec<String> {
    let ws: HashSet<Id> = g.workspaces.iter().map(|w| w.meta.id).collect();
    secret_ids(g)
        .filter(|(id, _)| existing.secrets.get(id).is_some_and(|owner| owner.is_none_or(|w| !ws.contains(&w))))
        .map(|(id, v)| format!("secret '{}' ({id})", v.label))
        .collect()
}

/// Fields that hold the id of an object in the graph (a string, a list of
/// strings, or an object such as a proxy selection whose own `id` is one).
/// Domain types have no free-form maps, so every JSON key in a serialized
/// graph is a field name from those types; user text is never a key.
const REFERENCE_FIELDS: &[&str] = &[
    "id",
    "workspace_id",
    "parent_id",
    "folder_id",
    "request_id",
    "revision_id",
    "dataset_id",
    "environment_id",
    "active_environment_id",
    "tls_profile_id",
    "proxy_profile_id",
    "integration_profile_id",
    "scenario_id",
    "chain",
    "import_environment_ids",
];

/// Give every object, revision and secret a fresh id and rewrite every
/// reference to them (Duplicate policy). The copy shares no identity with the
/// source: writing it can never overwrite a source object, and each copied
/// secret is owned by the copied workspace.
///
/// Only reference fields are rewritten, and only when they name an object or
/// secret in this graph; text that merely looks like an id is left alone.
pub fn remap_all(g: &mut PortableGraph) -> Result<HashMap<Id, Id>, serde_json::Error> {
    let mut map: HashMap<Id, Id> = HashMap::new();
    for (_, id, _) in all_ids(g) {
        map.insert(id, Id::new());
    }
    for r in &g.revisions {
        map.insert(r.id, Id::new());
    }
    let mut secret_map: HashMap<Id, Id> = HashMap::new();
    for k in g.secrets.keys() {
        if let Ok(id) = k.parse::<Id>() {
            secret_map.insert(id, Id::new());
        }
    }
    let mut v = serde_json::to_value(&*g)?;
    rewrite(&mut v, &map, &secret_map);
    let mut ng: PortableGraph = serde_json::from_value(v)?;
    ng.attachments = std::mem::take(&mut g.attachments);
    ng.history = std::mem::take(&mut g.history);
    // Execution records can hold captured user data, so only their own
    // top-level links are followed.
    for h in &mut ng.history {
        for field in ["workspace_id", "request_id", "revision_id", "environment_id"] {
            if let Some(serde_json::Value::String(s)) = h.get_mut(field) {
                remap(s, &map);
            }
        }
    }
    ng.secrets = std::mem::take(&mut g.secrets)
        .into_iter()
        .map(|(k, mut secret)| {
            // Owned by the copied workspace; validation rejects any other owner.
            let owner = secret.workspace_id.as_deref().and_then(|w| w.parse::<Id>().ok()).and_then(|w| map.get(&w));
            secret.workspace_id = owner.map(|w| w.to_string());
            let id = k.parse::<Id>().ok().and_then(|id| secret_map.get(&id)).map(|id| id.to_string()).unwrap_or(k);
            (id, secret)
        })
        .collect();
    *g = ng;
    Ok(map)
}

fn remap(s: &mut String, map: &HashMap<Id, Id>) {
    if let Some(n) = s.parse::<Id>().ok().and_then(|id| map.get(&id)) {
        *s = n.to_string();
    }
}

fn rewrite(v: &mut serde_json::Value, ids: &HashMap<Id, Id>, secrets: &HashMap<Id, Id>) {
    use serde_json::Value;
    match v {
        Value::Object(o) => {
            // A vault reference: `{"kind":"secret","secret":{"id":…,"label":…}}`.
            if o.get("kind").and_then(Value::as_str) == Some("secret")
                && let Some(Value::Object(r)) = o.get_mut("secret")
            {
                if let Some(Value::String(s)) = r.get_mut("id") {
                    remap(s, secrets);
                }
                return;
            }
            for (k, x) in o.iter_mut() {
                match x {
                    Value::String(s) if REFERENCE_FIELDS.contains(&k.as_str()) => remap(s, ids),
                    Value::Array(a) if REFERENCE_FIELDS.contains(&k.as_str()) => {
                        for e in a {
                            match e {
                                Value::String(s) => remap(s, ids),
                                other => rewrite(other, ids, secrets),
                            }
                        }
                    }
                    other => rewrite(other, ids, secrets),
                }
            }
        }
        Value::Array(a) => a.iter_mut().for_each(|x| rewrite(x, ids, secrets)),
        _ => {}
    }
}
