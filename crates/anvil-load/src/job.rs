//! The serializable job handed to the `anvil-load-worker` process.
//!
//! [`anvil_engine::ExecutionContext`] holds trait objects (secret and
//! attachment resolvers), so the parent resolves exactly the secrets the
//! plan's requests reference (effective auth, the selected TLS profile's
//! client identity, the selected proxy's password) into a scoped map, and the
//! worker rebuilds contexts over [`MemorySecrets`] / [`MemoryAttachments`].
//! A linked local file is read once, by the parent through the request's own
//! resolver (and its checks), and travels as stored bytes: the worker never
//! opens a local path, and the body cannot change during the run.
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
use anvil_domain::request::{AttachmentRef, Body, GrpcSchemaSource, MultipartContent, RequestSpec};
use anvil_domain::secret::{SecretRef, SensitiveValue};
use anvil_domain::settings::SettingsOverrides;
use anvil_domain::tls::{ClientIdentity, ProxyProfile, TlsProfile};
use anvil_engine::ExecutionContext;
use anvil_engine::context::{AttachmentResolver, MemoryAttachments, MemorySecrets};
use anvil_engine::vars::{VarEntry, VarLayer};
use base64::Engine as _;
use bytes::Bytes;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use zeroize::Zeroizing;

/// Version of the job wire format. Bump on any field a worker must honour:
/// an older worker would otherwise ignore it and run the job without it.
/// 2 added `WorkerRequest::scope` (the sealed import root).
pub const WORKER_PROTOCOL_VERSION: u32 = 2;

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
    /// The sealed import root the request was prepared under
    /// (`ExecutionContext::scope`).
    #[serde(default)]
    pub scope: Option<Id>,
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
        AuthConfig::JwtSvid { config } => {
            if let anvil_domain::workload::JwtSvidSource::Value { token } = &config.source {
                push_secret(token, out);
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
        // Fetched by the worker from the Workload API; no vault secret.
        Some(ClientIdentity::WorkloadApi { .. }) | None => {}
    }
    if let Some(pw) = proxy.and_then(|p| p.password.as_ref()) {
        push_secret(pw, &mut out);
    }
    out
}

/// Every attachment a request uses, stored or linked: its body files and,
/// for gRPC, the `.proto` files or descriptor set of its schema.
fn attachment_refs_mut(spec: &mut RequestSpec) -> Vec<&mut AttachmentRef> {
    let mut out = Vec::new();
    match &mut spec.body {
        Body::Binary { attachment, .. } => out.push(attachment),
        Body::Multipart { parts } => {
            for p in parts.iter_mut().filter(|p| p.enabled) {
                if let MultipartContent::File { attachment, .. } = &mut p.content {
                    out.push(attachment);
                }
            }
        }
        _ => {}
    }
    if let Some(g) = &mut spec.grpc {
        match &mut g.schema {
            GrpcSchemaSource::ProtoFiles { files } => out.extend(files.iter_mut()),
            GrpcSchemaSource::DescriptorSet { attachment } => out.push(attachment),
            GrpcSchemaSource::Reflection => {}
        }
    }
    out
}

/// The worker's attachments: only the bytes the parent sent. A linked local
/// file arrives as stored bytes, so a linked reference is refused here and
/// the worker never opens a path.
struct WorkerAttachments(MemoryAttachments);

impl AttachmentResolver for WorkerAttachments {
    fn load(&self, a: &AttachmentRef) -> Result<Bytes, String> {
        match a {
            AttachmentRef::Stored { .. } => self.0.load(a),
            AttachmentRef::LinkedFile { path } => Err(format!("the linked local file '{path}' was not sent to the load worker")),
        }
    }
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
            let mut spec = ctx.spec.clone();
            for a in attachment_refs_mut(&mut spec) {
                if let AttachmentRef::Stored { sha256, .. } = &*a
                    && attachments.iter().any(|x| &x.sha256 == sha256)
                {
                    continue;
                }
                let bytes = ctx.attachments.load(a).map_err(LoadError::Invalid)?;
                // Read once, here, through the parent's checks; the worker
                // gets the bytes as a stored attachment.
                if let AttachmentRef::LinkedFile { path } = &*a {
                    let name = std::path::Path::new(path).file_name();
                    let file_name = name.map_or_else(|| "file".into(), |f| f.to_string_lossy().into_owned());
                    let sha256 = hex::encode(Sha256::digest(&bytes));
                    *a = AttachmentRef::Stored { sha256, size: bytes.len() as u64, file_name, media_type: None };
                }
                let AttachmentRef::Stored { sha256, .. } = &*a else { continue };
                if !attachments.iter().any(|x| &x.sha256 == sha256) {
                    let data_b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
                    attachments.push(WireAttachment { sha256: sha256.clone(), data_b64 });
                }
            }
            let (tls, proxy) = selected_profiles(ctx);
            requests.push(WorkerRequest {
                request_id: id,
                workspace_id: ctx.workspace_id,
                revision_id: ctx.revision_id,
                environment_id: ctx.environment_id,
                spec,
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
                scope: ctx.scope,
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
        let attachments = Arc::new(WorkerAttachments(MemoryAttachments(files)));
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
            ctx.scope = r.scope;
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

    /// The parent's resolver for one linked file, as `anvil_app` builds it
    /// after its checks.
    struct Linked(String);

    impl AttachmentResolver for Linked {
        fn load(&self, a: &AttachmentRef) -> Result<Bytes, String> {
            match a {
                AttachmentRef::LinkedFile { path } if *path == self.0 => Ok(Bytes::from_static(b"read-by-the-parent")),
                _ => Err("not available".into()),
            }
        }
    }

    #[test]
    fn a_linked_file_is_read_by_the_parent_and_never_by_the_worker() {
        // A file that exists, so a worker reading the path would succeed.
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml").to_string();
        let linked = AttachmentRef::LinkedFile { path: path.clone() };
        let mut spec = RequestSpec::http("POST", "http://127.0.0.1:9/x");
        spec.body = Body::Binary { attachment: linked.clone(), content_type: None };
        let mut ctx = ExecutionContext::standalone(spec);
        ctx.attachments = Arc::new(Linked(path.clone()));
        let rid = Id::new();
        let job = LoadJob { requests: HashMap::from([(rid, ctx)]), dataset: None };
        let wj = WorkerJob::from_load_job(&plan(vec![rid]), &job, RunOptions::default()).unwrap();
        let Body::Binary { attachment: AttachmentRef::Stored { sha256, file_name, .. }, .. } = &wj.requests[0].spec.body else {
            panic!("the worker's request names a stored attachment");
        };
        assert_eq!(*sha256, hex::encode(Sha256::digest(b"read-by-the-parent")));
        assert_eq!(file_name, "Cargo.toml");
        assert_eq!(wj.attachments.len(), 1);
        assert!(!serde_json::to_string(&wj).unwrap().contains(&path), "the worker job names no local path");

        let (_, lj, _) = wj.clone().into_load_job().unwrap();
        let c = &lj.requests[&rid];
        let Body::Binary { attachment, .. } = &c.spec.body else { panic!("binary body") };
        assert_eq!(c.attachments.load(attachment).unwrap().as_ref(), b"read-by-the-parent");
        assert!(c.attachments.load(&linked).is_err(), "the worker never opens a linked path");

        // Nor does it for a job that names one directly.
        let mut crafted = wj;
        crafted.requests[0].spec.body = Body::Binary { attachment: linked.clone(), content_type: None };
        let (_, lj, _) = crafted.into_load_job().unwrap();
        assert!(lj.requests[&rid].attachments.load(&linked).is_err());
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

    #[test]
    fn a_job_from_before_import_root_scope_is_refused() {
        let wj = WorkerJob {
            protocol_version: 1,
            plan: plan(vec![]),
            options: RunOptions::default(),
            requests: vec![],
            secrets: vec![],
            attachments: vec![],
            dataset: None,
        };
        assert!(matches!(wj.into_load_job(), Err(LoadError::Protocol(_))));
    }
}
