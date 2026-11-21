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
    pub fn token_files(&self) -> Vec<String> {
        let mut out = Vec::new();
        let mut push = |owner: String, paths: Vec<String>| out.extend(paths.into_iter().map(|p| format!("{owner} token file: {p}")));
        for w in &self.workspaces {
            push(format!("workspace '{}'", w.name), token_file_paths([&w.auth]));
        }
        for f in &self.folders {
            push(format!("folder '{}'", f.name), token_file_paths([&f.auth]));
        }
        for r in &self.requests {
            push(format!("request '{}'", r.name), token_file_paths([&r.spec.auth]));
        }
        out
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
    pub fn revision_files(&self) -> Vec<String> {
        let current: HashMap<_, _> = self.requests.iter().map(|r| (r.meta.id, r)).collect();
        // Per request: its label and the linked and token paths listed so far,
        // starting with those of its current spec (read once).
        let mut seen: HashMap<Id, (String, HashSet<String>, HashSet<String>)> = HashMap::new();
        let mut out = Vec::new();
        for v in &self.revisions {
            let (owner, linked_seen, tokens_seen) = match current.get(&v.request_id) {
                Some(r) => seen.entry(r.meta.id).or_insert_with(|| {
                    let mut linked = Vec::new();
                    linked_paths(&serde_json::to_value(&r.spec).unwrap_or_default(), &mut linked);
                    let tokens = token_file_paths([&r.spec.auth]);
                    (format!("saved revision of request '{}'", r.name), linked.into_iter().collect(), tokens.into_iter().collect())
                }),
                None => seen.entry(v.id).or_insert_with(|| (format!("saved revision {}", v.id), HashSet::new(), HashSet::new())),
            };
            let mut linked = Vec::new();
            linked_paths(&serde_json::to_value(&v.spec).unwrap_or_default(), &mut linked);
            for p in linked {
                if linked_seen.insert(p.clone()) {
                    out.push(format!("{owner}: {p}"));
                }
            }
            for p in token_file_paths([&v.spec.auth]) {
                if tokens_seen.insert(p.clone()) {
                    out.push(format!("{owner} token file: {p}"));
                }
            }
        }
        out
    }

    /// Every local file path the graph carries: [`Self::linked_files`], then
    /// [`Self::token_files`], then [`Self::revision_files`]. This is what an
    /// export preview lists.
    pub fn local_files(&self) -> Vec<String> {
        let mut out = self.linked_files();
        out.extend(self.token_files());
        out.extend(self.revision_files());
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
