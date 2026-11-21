//! The portable object graph carried by bundles.

use anvil_domain::Id;
use anvil_domain::auth::AuthConfig;
use anvil_domain::integration::IntegrationProfile;
use anvil_domain::load::LoadPlan;
use anvil_domain::request::AttachmentRef;
use anvil_domain::settings::{AppSettings, StoredRuleset};
use anvil_domain::tls::{ProxyProfile, TlsProfile};
use anvil_domain::workload::JwtSvidSource;
use anvil_domain::workspace::{Dataset, Environment, Folder, RequestDefinition, RequestRevision, Scenario, Workspace};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};

/// Entries [`PortableGraph::token_files`] and [`PortableGraph::revision_files`]
/// list at most (the import warnings); past it the last entry counts the
/// rest, since a crafted file could otherwise name millions of paths. An
/// export preview ([`PortableGraph::local_files`]) lists every path.
pub const MAX_LISTED_PATHS: usize = 200;

/// `entries` cut to [`MAX_LISTED_PATHS`], with a last entry counting the rest.
fn capped(mut entries: Vec<String>, total: usize) -> Vec<String> {
    if total > entries.len() {
        entries.push(format!("… and {} more", total - entries.len()));
    }
    entries
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct PortableGraph {
    #[serde(default)]
    pub workspaces: Vec<Workspace>,
    #[serde(default)]
    pub folders: Vec<Folder>,
    #[serde(default)]
    pub requests: Vec<RequestDefinition>,
    #[serde(default)]
    pub revisions: Vec<RequestRevision>,
    #[serde(default)]
    pub environments: Vec<Environment>,
    #[serde(default)]
    pub tls_profiles: Vec<TlsProfile>,
    #[serde(default)]
    pub proxy_profiles: Vec<ProxyProfile>,
    #[serde(default)]
    pub integrations: Vec<IntegrationProfile>,
    #[serde(default)]
    pub datasets: Vec<Dataset>,
    #[serde(default)]
    pub scenarios: Vec<Scenario>,
    #[serde(default)]
    pub load_plans: Vec<LoadPlan>,
    /// Profile-level API standards rulesets, carried with workspace bundles.
    #[serde(default)]
    pub rulesets: Vec<StoredRuleset>,
    /// App settings, carried only by full backups (ANVILBAK files). Never
    /// written to or read from a bundle.
    #[serde(skip)]
    pub app_settings: Option<AppSettings>,
    /// Stored attachments by content sha256 (plaintext inside the bundle).
    #[serde(skip)]
    pub attachments: BTreeMap<String, Vec<u8>>,
    /// Secret values by secret id (only in encrypted bundles; never in objects.json).
    #[serde(skip)]
    pub secrets: BTreeMap<String, SecretValue>,
    /// Optional run history (execution records, already redacted).
    #[serde(skip)]
    pub history: Vec<serde_json::Value>,
    /// Items the exporter left out of this graph (labels only), listed among
    /// the bundle's excluded items. Never written as an object.
    #[serde(skip)]
    pub omitted: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecretValue {
    pub label: String,
    pub value: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_id: Option<String>,
}

impl PortableGraph {
    pub fn object_count(&self) -> usize {
        self.workspaces.len()
            + self.folders.len()
            + self.requests.len()
            + self.revisions.len()
            + self.environments.len()
            + self.tls_profiles.len()
            + self.proxy_profiles.len()
            + self.integrations.len()
            + self.datasets.len()
            + self.scenarios.len()
            + self.load_plans.len()
            + self.rulesets.len()
    }

    /// Every linked local file the graph's requests and datasets name, as
    /// `request 'Upload': /path/to/file`. Each names a file on the machine
    /// that made the bundle, and stays unused on this one until the user
    /// chooses it here for that request or dataset.
    pub fn linked_files(&self) -> Vec<String> {
        let mut out = Vec::new();
        for r in &self.requests {
            let mut paths = Vec::new();
            linked_paths(&serde_json::to_value(&r.spec).unwrap_or_default(), &mut paths);
            out.extend(paths.into_iter().map(|p| format!("request '{}': {p}", r.name)));
        }
        for d in &self.datasets {
            if let AttachmentRef::LinkedFile { path } = &d.attachment {
                out.push(format!("dataset '{}': {path}", d.name));
            }
        }
        out
    }

    /// Every JWT-SVID token file the graph's workspaces, folders and requests
    /// name (a `file` source, inside multi-auth sets too), as
    /// `request 'Orders' token file: /run/spire/jwt.token`. Each names a file
    /// by its path on the machine that made the bundle. The desktop reads a
    /// token file only once it is chosen on the device, and that choice is
    /// never exported.
    /// At most [`MAX_LISTED_PATHS`] are listed (see [`capped`]).
    pub fn token_files(&self) -> Vec<String> {
        self.token_files_up_to(MAX_LISTED_PATHS)
    }

    fn token_files_up_to(&self, limit: usize) -> Vec<String> {
        let (mut out, mut total) = (Vec::new(), 0);
        let owners = self
            .workspaces
            .iter()
            .map(|w| ("workspace", &w.name, &w.auth))
            .chain(self.folders.iter().map(|f| ("folder", &f.name, &f.auth)))
            .chain(self.requests.iter().map(|r| ("request", &r.name, &r.spec.auth)));
        for (kind, name, auth) in owners {
            for p in token_file_paths([auth]) {
                total += 1;
                if out.len() < limit {
                    out.push(format!("{kind} '{name}' token file: {p}"));
                }
            }
        }
        capped(out, total)
    }

    /// Whether a workspace, folder or request names a JWT-SVID token file
    /// ([`Self::token_files`] is not empty), without listing them.
    pub fn has_token_files(&self) -> bool {
        self.workspaces
            .iter()
            .map(|w| &w.auth)
            .chain(self.folders.iter().map(|f| &f.auth))
            .chain(self.requests.iter().map(|r| &r.spec.auth))
            .any(names_token_file)
    }

    /// The linked-file and token-file paths only saved revisions name: the
    /// paths of each revision that neither its request's current spec nor an
    /// earlier revision of it names, as
    /// `saved revision of request 'Upload': /path/to/file` or
    /// `saved revision of request 'Orders' token file: /run/spire/jwt.token`
    /// (`saved revision <id>` when the graph lacks its request). Revisions
    /// are never sent, so nothing needs choosing for them, but they travel in
    /// the bundle like any object.
    /// At most [`MAX_LISTED_PATHS`] are listed (see [`capped`]).
    pub fn revision_files(&self) -> Vec<String> {
        self.revision_files_up_to(MAX_LISTED_PATHS)
    }

    fn revision_files_up_to(&self, limit: usize) -> Vec<String> {
        let current: HashMap<_, _> = self.requests.iter().map(|r| (r.meta.id, r)).collect();
        // Per request: the linked and token paths seen so far, starting with
        // those of its current spec (read once).
        // Keyed by request id, or by revision id (`false`) for a revision whose
        // request the graph lacks, so the two never share an entry.
        let mut seen: HashMap<(bool, Id), (HashSet<String>, HashSet<String>)> = HashMap::new();
        let (mut out, mut total) = (Vec::new(), 0);
        for v in &self.revisions {
            let owner = current.get(&v.request_id);
            let (linked_seen, tokens_seen) =
                seen.entry(owner.map_or((false, v.id), |r| (true, r.meta.id))).or_insert_with(|| match owner {
                    Some(r) => {
                        let mut linked = HashSet::new();
                        linked_paths_into(&serde_json::to_value(&r.spec).unwrap_or_default(), &mut linked, &mut Vec::new());
                        (linked, token_file_paths([&r.spec.auth]).into_iter().collect())
                    }
                    None => (HashSet::new(), HashSet::new()),
                });
            let mut fresh = Vec::new();
            linked_paths_into(&serde_json::to_value(&v.spec).unwrap_or_default(), linked_seen, &mut fresh);
            let tokens: Vec<String> = token_file_paths([&v.spec.auth]).into_iter().filter(|p| tokens_seen.insert(p.clone())).collect();
            let label = |suffix: &str, p: &str| match owner {
                Some(r) => format!("saved revision of request '{}'{suffix}: {p}", r.name),
                None => format!("saved revision {}{suffix}: {p}", v.id),
            };
            for (suffix, paths) in [("", fresh), (" token file", tokens)] {
                for p in paths {
                    total += 1;
                    if out.len() < limit {
                        out.push(label(suffix, &p));
                    }
                }
            }
        }
        capped(out, total)
    }

    /// Whether a saved revision names a path its request's current spec does
    /// not ([`Self::revision_files`] is not empty).
    pub fn has_revision_files(&self) -> bool {
        !self.revisions.is_empty() && !self.revision_files_up_to(0).is_empty()
    }

    /// Every local file path the graph carries: [`Self::linked_files`], then
    /// [`Self::token_files`], then [`Self::revision_files`], each in full.
    /// This is what an export preview lists.
    pub fn local_files(&self) -> Vec<String> {
        let mut out = self.linked_files();
        out.extend(self.token_files_up_to(usize::MAX));
        out.extend(self.revision_files_up_to(usize::MAX));
        out
    }
}

/// The token-file paths of the JWT-SVID `file` sources in `auths`, nested
/// multi-auth sets included, each listed once, in first-seen order.
fn token_file_paths<'a>(auths: impl IntoIterator<Item = &'a AuthConfig>) -> Vec<String> {
    fn walk<'a>(auth: &'a AuthConfig, seen: &mut HashSet<&'a str>, out: &mut Vec<String>) {
        match auth {
            AuthConfig::JwtSvid { config } => {
                if let JwtSvidSource::File { path } = &config.source
                    && seen.insert(path)
                {
                    out.push(path.clone());
                }
            }
            AuthConfig::Multi { profiles } => profiles.iter().for_each(|p| walk(p, seen, out)),
            _ => {}
        }
    }
    let (mut seen, mut out) = (HashSet::new(), Vec::new());
    auths.into_iter().for_each(|auth| walk(auth, &mut seen, &mut out));
    out
}

/// Whether `auth` (nested multi-auth sets included) reads a JWT-SVID token file.
fn names_token_file(auth: &AuthConfig) -> bool {
    match auth {
        AuthConfig::JwtSvid { config } => matches!(config.source, JwtSvidSource::File { .. }),
        AuthConfig::Multi { profiles } => profiles.iter().any(names_token_file),
        _ => false,
    }
}

/// [`linked_paths`] for paths not yet in `seen`: each is added to `seen` and,
/// in traversal order, to `fresh`.
fn linked_paths_into(v: &serde_json::Value, seen: &mut HashSet<String>, fresh: &mut Vec<String>) {
    match v {
        serde_json::Value::Object(o) => {
            if o.get("kind").and_then(|k| k.as_str()) == Some("linked_file") {
                let path = o.get("path").and_then(|p| p.as_str()).unwrap_or_default();
                if seen.insert(path.to_string()) {
                    fresh.push(path.to_string());
                }
            }
            o.values().for_each(|x| linked_paths_into(x, seen, fresh));
        }
        serde_json::Value::Array(a) => a.iter().for_each(|x| linked_paths_into(x, seen, fresh)),
        _ => {}
    }
}

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
