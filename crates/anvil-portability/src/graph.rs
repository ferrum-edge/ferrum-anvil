//! The portable object graph carried by bundles.

use anvil_domain::integration::IntegrationProfile;
use anvil_domain::load::LoadPlan;
use anvil_domain::request::AttachmentRef;
use anvil_domain::settings::AppSettings;
use anvil_domain::tls::{ProxyProfile, TlsProfile};
use anvil_domain::workspace::{Dataset, Environment, Folder, RequestDefinition, RequestRevision, Scenario, Workspace};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

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
