//! Import planning: conflict detection and id remapping per policy.

use crate::graph::PortableGraph;
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
    pub to_create: usize,
    pub to_replace: usize,
    pub skipped_existing: usize,
    pub conflicts: Vec<String>,
}

fn all_ids(g: &PortableGraph) -> Vec<(String, Id, String)> {
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

/// Compute what applying `g` would do given the ids that already exist.
pub fn plan(g: &PortableGraph, existing: &HashSet<Id>, policy: ConflictPolicy) -> ImportPlan {
    let ids = all_ids(g);
    let conflicts: Vec<String> =
        ids.iter().filter(|(_, id, _)| existing.contains(id)).map(|(k, id, n)| format!("{k} '{n}' ({id})")).collect();
    let n = ids.len();
    let c = conflicts.len();
    match policy {
        ConflictPolicy::Merge => ImportPlan { policy, to_create: n - c, to_replace: 0, skipped_existing: c, conflicts },
        ConflictPolicy::Replace => ImportPlan { policy, to_create: n - c, to_replace: c, skipped_existing: 0, conflicts },
        ConflictPolicy::Duplicate => ImportPlan { policy, to_create: n, to_replace: 0, skipped_existing: 0, conflicts },
    }
}

/// Give every object a fresh id and rewrite all references (Duplicate policy).
/// Secret ids are remapped too, so duplicated workspaces never share vault entries.
pub fn remap_all(g: &mut PortableGraph) -> HashMap<Id, Id> {
    let mut map: HashMap<Id, Id> = HashMap::new();
    for (_, id, _) in all_ids(g) {
        map.insert(id, Id::new());
    }
    let mut secret_map: HashMap<String, String> = HashMap::new();
    for k in g.secrets.keys() {
        secret_map.insert(k.clone(), Id::new().to_string());
    }
    // Rewrite via JSON so every reference field is covered uniformly.
    let mut v = serde_json::to_value(&*g).expect("graph serializes");
    rewrite(&mut v, &map, &secret_map);
    let mut ng: PortableGraph = serde_json::from_value(v).expect("remapped graph deserializes");
    ng.attachments = std::mem::take(&mut g.attachments);
    ng.history = std::mem::take(&mut g.history);
    ng.secrets = std::mem::take(&mut g.secrets).into_iter().map(|(k, v)| (secret_map.get(&k).cloned().unwrap_or(k), v)).collect();
    *g = ng;
    map
}

fn rewrite(v: &mut serde_json::Value, map: &HashMap<Id, Id>, secrets: &HashMap<String, String>) {
    match v {
        serde_json::Value::String(s) => {
            if let Ok(id) = s.parse::<Id>() {
                if let Some(n) = map.get(&id) {
                    *s = n.to_string();
                } else if let Some(n) = secrets.get(s.as_str()) {
                    *s = n.clone();
                }
            }
        }
        serde_json::Value::Array(a) => a.iter_mut().for_each(|x| rewrite(x, map, secrets)),
        serde_json::Value::Object(o) => o.values_mut().for_each(|x| rewrite(x, map, secrets)),
        _ => {}
    }
}
