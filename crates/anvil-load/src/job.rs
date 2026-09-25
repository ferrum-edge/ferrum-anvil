//! The serializable job handed to the `anvil-load-worker` process.
//!
//! [`anvil_engine::ExecutionContext`] holds trait objects (secret and
//! attachment resolvers), so the parent resolves exactly the secrets the
//! plan's requests reference (effective auth, the selected TLS profile's
//! client identity, the selected proxy's password) into a scoped map, and the
//! worker rebuilds contexts over [`MemorySecrets`] / [`MemoryAttachments`].
//!
//! The job travels over the worker's **stdin** only — never argv or the
//! environment, which other local users can read from the process table.
//! Secret values are held in zeroizing buffers and never appear in `Debug`.

use crate::LoadError;
use crate::dataset::{Dataset, DatasetFormat};
use crate::executor::{LoadJob, RunOptions};
use anvil_domain::Id;
use anvil_domain::auth::AuthConfig;
use anvil_domain::integration::{IntegrationKind, IntegrationProfile};
use anvil_domain::load::LoadPlan;
use anvil_domain::request::{AttachmentRef, Body, MultipartContent, RequestSpec};
use anvil_domain::secret::{SecretRef, SensitiveValue};
use anvil_domain::settings::SettingsOverrides;
use anvil_domain::tls::{ClientIdentity, ProxyProfile, TlsProfile};
use anvil_engine::ExecutionContext;
use anvil_engine::context::{MemoryAttachments, MemorySecrets};
use anvil_engine::vars::{VarEntry, VarLayer};
use base64::Engine as _;
use bytes::Bytes;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use zeroize::Zeroizing;

pub const WORKER_PROTOCOL_VERSION: u32 = 1;

/// A sensitive string: zeroized on drop, redacted in `Debug`.
#[derive(Clone, Default)]
pub struct SecretString(pub Zeroizing<String>);

impl SecretString {
    pub fn new(s: impl Into<String>) -> Self {
        SecretString(Zeroizing::new(s.into()))
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for SecretString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(anvil_domain::secret::REDACTED)
    }
}

impl Serialize for SecretString {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SecretString {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(SecretString(Zeroizing::new(String::deserialize(d)?)))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireVar {
    pub name: String,
    pub value: SecretString,
    #[serde(default)]
    pub secret: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireVarLayer {
    pub label: String,
    pub vars: Vec<WireVar>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct WorkerRequest {
    pub request_id: Id,
    #[serde(default)]
    pub workspace_id: Option<Id>,
    #[serde(default)]
    pub revision_id: Option<Id>,
    #[serde(default)]
    pub environment_id: Option<Id>,
    pub spec: RequestSpec,
    pub settings_layers: Vec<(String, SettingsOverrides)>,
    pub auth_layers: Vec<(String, AuthConfig)>,
    pub var_layers: Vec<WireVarLayer>,
    /// Only the TLS profile the request's effective settings select.
    #[serde(default)]
    pub tls_profiles: Vec<TlsProfile>,
    /// Only the proxy profile the request's effective settings select.
    #[serde(default)]
    pub proxy_profiles: Vec<ProxyProfile>,
    /// Ferrum trust profiles, without their diagnostic-detail credentials.
    #[serde(default)]
    pub integrations: Vec<IntegrationProfile>,
    pub isolation: String,
    #[serde(default)]
    pub send_anyway: bool,
    #[serde(default)]
    pub seed: Option<u64>,
    #[serde(default)]
    pub redaction_names: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopedSecret {
    pub id: Id,
    pub value: SecretString,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireAttachment {
    pub sha256: String,
    pub data_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireDataset {
    pub format: DatasetFormat,
    pub data_b64: String,
    #[serde(default)]
    pub sensitive_columns: Vec<String>,
}

/// Complete, bounded description of one load run for the worker.
#[derive(Clone, Serialize, Deserialize)]
pub struct WorkerJob {
    pub protocol_version: u32,
    pub plan: LoadPlan,
    pub options: RunOptions,
    pub requests: Vec<WorkerRequest>,
    pub secrets: Vec<ScopedSecret>,
    #[serde(default)]
    pub attachments: Vec<WireAttachment>,
    #[serde(default)]
    pub dataset: Option<WireDataset>,
}

impl std::fmt::Debug for WorkerJob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WorkerJob")
            .field("plan", &self.plan.name)
            .field("requests", &self.requests.len())
            .field("secrets", &self.secrets.len())
            .field("attachments", &self.attachments.len())
            .field("dataset", &self.dataset.is_some())
            .finish()
    }
}

fn push_secret(v: &SensitiveValue, out: &mut Vec<SecretRef>) {
    if let SensitiveValue::Secret { secret } = v
        && !out.iter().any(|r| r.id == secret.id)
    {
        out.push(secret.clone());
    }
}

fn walk_auth(a: &AuthConfig, out: &mut Vec<SecretRef>) {
    match a {
        AuthConfig::Inherit | AuthConfig::None => {}
        AuthConfig::ApiKey { value, .. } => push_secret(value, out),
        AuthConfig::Basic { password, .. } => push_secret(password, out),
        AuthConfig::Bearer { token, .. } => push_secret(token, out),
        AuthConfig::Jwt { signing_key, .. } => push_secret(signing_key, out),
        AuthConfig::OAuth2 { config } => push_secret(&config.client_secret, out),
        AuthConfig::Hmac { config } => push_secret(&config.secret, out),
        AuthConfig::Dpop { config } => {
            push_secret(&config.access_token, out);
            push_secret(&config.private_key_pem, out);
        }
        AuthConfig::Wsse { config } => {
            push_secret(&config.password, out);
            if let Some(s) = &config.saml_assertion {
                push_secret(s, out);
            }
        }
        AuthConfig::Multi { profiles } => profiles.iter().for_each(|p| walk_auth(p, out)),
    }
}

/// The TLS / proxy profiles a context's effective settings select.
fn selected_profiles(ctx: &ExecutionContext) -> (Option<&TlsProfile>, Option<&ProxyProfile>) {
    let eff = anvil_engine::settings::resolve(&ctx.settings_layers);
    let tls = eff.tls_profile_id.and_then(|id| ctx.tls_profiles.iter().find(|p| p.id == id));
    let proxy = eff.proxy_profile_id.and_then(|id| ctx.proxy_profiles.iter().find(|p| p.id == id));
    (tls, proxy)
}

/// Vault references a context actually needs to execute (scoping).
pub fn secret_refs(ctx: &ExecutionContext) -> Vec<SecretRef> {
    let mut out = Vec::new();
    walk_auth(&ctx.effective_auth().1, &mut out);
    let (tls, proxy) = selected_profiles(ctx);
    match tls.and_then(|p| p.client_identity.as_ref()) {
        Some(ClientIdentity::Pem { private_key_pem, .. }) => push_secret(private_key_pem, &mut out),
        Some(ClientIdentity::Pkcs12 { bundle_b64, password }) => {
            push_secret(bundle_b64, &mut out);
            push_secret(password, &mut out);
        }
        None => {}
    }
    if let Some(pw) = proxy.and_then(|p| p.password.as_ref()) {
        push_secret(pw, &mut out);
    }
    out
}

/// Stored attachments a request body references.
pub fn attachment_refs(spec: &RequestSpec) -> Vec<AttachmentRef> {
    let mut out = Vec::new();
    match &spec.body {
        Body::Binary { attachment, .. } => out.push(attachment.clone()),
        Body::Multipart { parts } => {
            for p in parts.iter().filter(|p| p.enabled) {
                if let MultipartContent::File { attachment, .. } = &p.content {
                    out.push(attachment.clone());
                }
            }
        }
        _ => {}
    }
    out.retain(|a| matches!(a, AttachmentRef::Stored { .. }));
    out
}

fn plan_request_ids(plan: &LoadPlan) -> Vec<Id> {
    let mut ids: Vec<Id> = if plan.mix.is_empty() { plan.chain.clone() } else { plan.mix.iter().map(|m| m.request_id).collect() };
    let mut seen = Vec::new();
    ids.retain(|i| {
        let new = !seen.contains(i);
        seen.push(*i);
        new
    });
    ids
}

impl WorkerJob {
    /// Build the wire job from resolved in-process contexts, resolving only
    /// the secrets and attachments the plan's requests reference.
    pub fn from_load_job(plan: &LoadPlan, job: &LoadJob, options: RunOptions) -> Result<WorkerJob, LoadError> {
        let mut requests = Vec::new();
        let mut secrets: Vec<ScopedSecret> = Vec::new();
        let mut attachments: Vec<WireAttachment> = Vec::new();
        for id in plan_request_ids(plan) {
            let ctx =
                job.requests.get(&id).ok_or_else(|| LoadError::Invalid(format!("request {id} referenced by the plan was not resolved")))?;
            for r in secret_refs(ctx) {
                if secrets.iter().any(|s| s.id == r.id) {
                    continue;
                }
                let v = ctx.secrets.resolve(&r).map_err(|e| LoadError::Invalid(format!("secret '{}': {e}", r.label)))?;
                secrets.push(ScopedSecret { id: r.id, value: SecretString(v) });
            }
            for a in attachment_refs(&ctx.spec) {
                let AttachmentRef::Stored { sha256, .. } = &a else { continue };
                if attachments.iter().any(|x| &x.sha256 == sha256) {
                    continue;
                }
                let bytes = ctx.attachments.load(&a).map_err(LoadError::Invalid)?;
                attachments
                    .push(WireAttachment { sha256: sha256.clone(), data_b64: base64::engine::general_purpose::STANDARD.encode(&bytes) });
            }
            let (tls, proxy) = selected_profiles(ctx);
            requests.push(WorkerRequest {
                request_id: id,
                workspace_id: ctx.workspace_id,
                revision_id: ctx.revision_id,
                environment_id: ctx.environment_id,
                spec: ctx.spec.clone(),
                settings_layers: ctx.settings_layers.clone(),
                auth_layers: vec![ctx.effective_auth()],
                var_layers: ctx
                    .var_layers
                    .iter()
                    .map(|l| WireVarLayer {
                        label: l.label.clone(),
                        vars: l
                            .vars
                            .iter()
                            .map(|v| WireVar { name: v.name.clone(), value: SecretString::new(v.value.clone()), secret: v.secret })
                            .collect(),
                    })
                    .collect(),
                tls_profiles: tls.cloned().into_iter().collect(),
                proxy_profiles: proxy.cloned().into_iter().collect(),
                integrations: ctx
                    .integrations
                    .iter()
                    .cloned()
                    .map(|mut i| {
                        let IntegrationKind::FerrumGateway { detail, .. } = &mut i.kind;
                        *detail = None;
                        i
                    })
                    .collect(),
                isolation: ctx.isolation.clone(),
                send_anyway: ctx.send_anyway,
                seed: ctx.seed,
                redaction_names: ctx.redaction_names.clone(),
            });
        }
        let dataset = job.dataset.as_ref().map(|d| WireDataset {
            format: d.format,
            data_b64: base64::engine::general_purpose::STANDARD.encode(d.raw()),
            sensitive_columns: d.sensitive_columns.clone(),
        });
        Ok(WorkerJob { protocol_version: WORKER_PROTOCOL_VERSION, plan: plan.clone(), options, requests, secrets, attachments, dataset })
    }

    /// Rebuild in-process contexts inside the worker.
    pub fn into_load_job(self) -> Result<(LoadPlan, LoadJob, RunOptions), LoadError> {
        if self.protocol_version != WORKER_PROTOCOL_VERSION {
            return Err(LoadError::Protocol(format!(
                "job protocol {} is not supported by this worker (expects {WORKER_PROTOCOL_VERSION})",
                self.protocol_version
            )));
        }
        let secrets = Arc::new(MemorySecrets(self.secrets.into_iter().map(|s| (s.id, s.value.0)).collect::<HashMap<_, _>>()));
        let mut files = HashMap::new();
        for a in self.attachments {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(&a.data_b64)
                .map_err(|e| LoadError::Invalid(format!("attachment {}: {e}", a.sha256)))?;
            let is_hex_digest = a.sha256.len() == 64 && a.sha256.bytes().all(|b| b.is_ascii_hexdigit());
            if is_hex_digest && !hex::encode(Sha256::digest(&bytes)).eq_ignore_ascii_case(&a.sha256) {
                return Err(LoadError::Invalid(format!("attachment {} does not match its digest", a.sha256)));
            }
            files.insert(a.sha256, Bytes::from(bytes));
        }
        let attachments = Arc::new(MemoryAttachments(files));
        let mut requests = HashMap::new();
        for r in self.requests {
            let mut ctx = ExecutionContext::standalone(r.spec);
            ctx.workspace_id = r.workspace_id;
            ctx.request_id = Some(r.request_id);
            ctx.revision_id = r.revision_id;
            ctx.environment_id = r.environment_id;
            ctx.settings_layers = r.settings_layers;
            ctx.auth_layers = r.auth_layers;
            ctx.var_layers = r
                .var_layers
                .into_iter()
                .map(|l| VarLayer {
                    label: l.label,
                    vars: l
                        .vars
                        .into_iter()
                        .map(|v| VarEntry { name: v.name, value: v.value.expose().to_string(), secret: v.secret })
                        .collect(),
                })
                .collect();
            ctx.tls_profiles = r.tls_profiles;
            ctx.proxy_profiles = r.proxy_profiles;
            ctx.integrations = r.integrations;
            ctx.secrets = secrets.clone();
            ctx.attachments = attachments.clone();
            ctx.isolation = r.isolation;
            ctx.send_anyway = r.send_anyway;
            ctx.seed = r.seed;
            ctx.redaction_names = r.redaction_names;
            requests.insert(r.request_id, ctx);
        }
        let dataset = match self.dataset {
            Some(d) => {
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(&d.data_b64)
                    .map_err(|e| LoadError::Invalid(format!("dataset: {e}")))?;
                Some(Dataset::parse(d.format, bytes)?.with_sensitive_columns(d.sensitive_columns)?)
            }
            None => None,
        };
        Ok((self.plan, LoadJob { requests, dataset }, self.options))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anvil_domain::load::{ConnectionMode, Stage, Workload};
    use chrono::Utc;

    fn plan(ids: Vec<Id>) -> LoadPlan {
        LoadPlan {
            id: Id::new(),
            workspace_id: Id::new(),
            name: "p".into(),
            workload: Workload::OpenArrivalRate { stages: vec![Stage { duration_secs: 1, target: 1 }], max_in_flight: 1 },
            chain: ids,
            mix: vec![],
            dataset_id: None,
            environment_id: None,
            connection_mode: ConnectionMode::Persistent,
            warmup_secs: 0,
            abort: None,
            seed: 0,
            trusted: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn only_referenced_secrets_are_scoped_into_the_job_and_debug_is_redacted() {
        let used = SecretRef { id: Id::new(), label: "api key".into() };
        let unused = Id::new();
        let mut ctx = ExecutionContext::standalone(RequestSpec::http("GET", "http://127.0.0.1:9/x"));
        ctx.auth_layers = vec![
            (
                "workspace".into(),
                AuthConfig::Bearer {
                    token: SensitiveValue::Secret { secret: SecretRef { id: unused, label: "old".into() } },
                    prefix: "Bearer".into(),
                },
            ),
            (
                "request".into(),
                AuthConfig::ApiKey {
                    name: "x-api-key".into(),
                    value: SensitiveValue::Secret { secret: used.clone() },
                    location: Default::default(),
                },
            ),
        ];
        ctx.var_layers = vec![VarLayer {
            label: "env".into(),
            vars: vec![VarEntry { name: "tok".into(), value: "var-secret-value".into(), secret: true }],
        }];
        let mut vault = HashMap::new();
        vault.insert(used.id, Zeroizing::new("sk-live-TOPSECRET".to_string()));
        vault.insert(unused, Zeroizing::new("must-not-leave".to_string()));
        ctx.secrets = Arc::new(MemorySecrets(vault));
        let rid = Id::new();
        let job = LoadJob { requests: HashMap::from([(rid, ctx)]), dataset: None };
        let wj = WorkerJob::from_load_job(&plan(vec![rid]), &job, RunOptions::default()).unwrap();
        assert_eq!(wj.secrets.len(), 1, "only the effective auth's secret is scoped in");
        let json = serde_json::to_string(&wj).unwrap();
        assert!(json.contains("sk-live-TOPSECRET"));
        assert!(!json.contains("must-not-leave"));
        let dbg = format!("{wj:?} {:?} {:?}", wj.secrets, wj.requests[0].var_layers);
        assert!(!dbg.contains("sk-live-TOPSECRET") && !dbg.contains("var-secret-value"), "{dbg}");

        let back: WorkerJob = serde_json::from_str(&json).unwrap();
        let (_, lj, _) = back.into_load_job().unwrap();
        let c = &lj.requests[&rid];
        assert_eq!(c.secrets.resolve(&used).unwrap().as_str(), "sk-live-TOPSECRET");
        assert!(c.secrets.resolve(&SecretRef { id: unused, label: "old".into() }).is_err());
        assert_eq!(c.var_layers[0].vars[0].value, "var-secret-value");
        assert!(c.var_layers[0].vars[0].secret);
    }

    #[test]
    fn attachment_digest_is_verified() {
        let data = b"payload".to_vec();
        let digest = hex::encode(Sha256::digest(&data));
        let mut wj = WorkerJob {
            protocol_version: WORKER_PROTOCOL_VERSION,
            plan: plan(vec![]),
            options: RunOptions::default(),
            requests: vec![],
            secrets: vec![],
            attachments: vec![WireAttachment { sha256: digest, data_b64: base64::engine::general_purpose::STANDARD.encode(&data) }],
            dataset: None,
        };
        assert!(wj.clone().into_load_job().is_ok());
        wj.attachments[0].data_b64 = base64::engine::general_purpose::STANDARD.encode(b"tampered");
        assert!(wj.into_load_job().is_err());
    }
}
