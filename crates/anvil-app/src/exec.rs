//! Build frozen execution contexts from storage and run them through the
//! shared engine, recording redacted history.

use crate::device_identity::uses_device_identity;
use crate::file_grants::FilePurpose;
use crate::linked_files::{LinkedFileReferrer, read_bound_file};
use crate::{App, AppError, Result};
use anvil_domain::Id;
use anvil_domain::auth::AuthConfig;
use anvil_domain::request::{AttachmentRef, RequestSpec};
use anvil_domain::secret::{SecretRef, SensitiveValue};
use anvil_domain::settings::SettingsOverrides;
use anvil_domain::workspace::Variable;
use anvil_engine::ExecutionOutput;
use anvil_engine::context::{AttachmentResolver, ExecutionContext, SecretResolver};
use anvil_engine::vars::{VarEntry, VarLayer};
use anvil_storage::Store;
use anvil_transport::recorder::EventCtx;
use bytes::Bytes;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

/// Vault-backed secret resolution for one workspace (fails closed while
/// locked). Only secrets that workspace owns resolve: a reference to any
/// other secret, whoever owns it, fails as if the secret were not stored.
pub struct StoreSecrets {
    pub store: Arc<Store>,
    pub workspace: Id,
}

impl SecretResolver for StoreSecrets {
    fn resolve(&self, r: &SecretRef) -> std::result::Result<Zeroizing<String>, String> {
        match self.store.get_workspace_secret(&r.id, &self.workspace) {
            Ok(Some((_, v))) => Ok(v),
            Ok(None) => Err(format!(
                "secret '{}' is not in this workspace's vault (it may belong to another workspace or not have been imported)",
                r.label
            )),
            Err(anvil_storage::StoreError::Locked) => Err("Anvil is locked".into()),
            Err(e) => Err(e.to_string()),
        }
    }
}

pub struct StoreAttachments {
    pub app_store: Arc<Store>,
    pub index: std::collections::HashMap<String, Vec<u8>>,
    /// Linked files chosen on this device (see `anvil_app::linked_files`);
    /// any other linked file is refused, never read.
    pub linked: Vec<String>,
}

impl AttachmentResolver for StoreAttachments {
    fn load(&self, a: &AttachmentRef) -> std::result::Result<Bytes, String> {
        match a {
            AttachmentRef::Stored { sha256, file_name, .. } => self
                .index
                .get(sha256)
                .map(|b| Bytes::from(b.clone()))
                .ok_or_else(|| format!("attachment '{file_name}' is missing from this workspace")),
            AttachmentRef::LinkedFile { path } if self.linked.contains(path) => {
                read_bound_file(path, FilePurpose::Attachment.max_read_bytes(), "file").map(Bytes::from).map_err(|e| e.to_string())
            }
            AttachmentRef::LinkedFile { path } => Err(format!("the linked local file '{path}' was not chosen on this device")),
        }
    }
}

fn layer(label: String, vars: &[Variable], secrets: &dyn SecretResolver) -> std::result::Result<VarLayer, AppError> {
    let mut out = Vec::new();
    for v in vars.iter().filter(|v| v.enabled) {
        let value = match &v.value {
            SensitiveValue::Template { value } => value.clone(),
            SensitiveValue::Secret { secret } => {
                secrets.resolve(secret).map(|z| z.to_string()).map_err(|e| AppError::Invalid(format!("variable '{}': {e}", v.name)))?
            }
        };
        out.push(VarEntry { name: v.name.clone(), value, secret: v.secret || matches!(v.value, SensitiveValue::Secret { .. }) });
    }
    Ok(VarLayer { label, vars: out })
}

/// Options for one send.
#[derive(Default, Clone)]
pub struct SendOptions {
    pub environment: Option<Id>,
    pub run_override: Option<SettingsOverrides>,
    pub send_anyway: bool,
    pub record_history: bool,
    pub seed: Option<u64>,
}

impl App {
    /// Build the frozen context for a saved request (optionally with an
    /// unsaved draft spec) — settings, auth and variable layers resolved
    /// from workspace → folders → request. A draft never names a linked
    /// local file, a saved request only ones chosen for it in the native
    /// dialog on this device, and (when confined) a JWT-SVID token file is
    /// read only if it was bound in the native dialog. In a workspace a
    /// bundle import or backup restore wrote into, this device's workload
    /// identity is refused until the user allows it on this device
    /// (`crate::device_identity`): a JWT-SVID from its Workload API or a
    /// token file, and a TLS profile, the request's own or its proxy's, that
    /// presents its X.509-SVID.
    ///
    /// Under an import root (`Folder::import_root`) only the imported
    /// collection's own scope resolves: the root and the folders under it,
    /// and an environment the import brought. The workspace's variables and
    /// auth, outer folders and any other environment are left out, and a
    /// JWT-SVID from this device's Workload API or a token file is refused,
    /// until the user opens the root to the workspace on this device
    /// (`use_workspace_scope`). Settings still apply from the workspace
    /// down, but a selected TLS profile whose client identity is bound to no
    /// host is refused (a proxy's own TLS profile still applies to the
    /// connection to the proxy). The context is tagged with the sealed root
    /// (`ExecutionContext::scope`) so a run or load chain keeps values
    /// extracted outside it, and its dataset, away from it.
    pub fn build_context(
        &self,
        request_id: Option<Id>,
        ws_id: &Id,
        draft: Option<RequestSpec>,
        opts: &SendOptions,
    ) -> Result<ExecutionContext> {
        if let Some(d) = &draft {
            refuse_linked_files(d)?;
        }
        let ws = self.workspace(ws_id)?;
        let (req, spec) = match (request_id, draft) {
            (Some(id), Some(d)) => (Some(self.request(&id)?), d),
            (Some(id), None) => {
                let r = self.request(&id)?;
                let s = r.spec.clone();
                (Some(r), s)
            }
            (None, Some(d)) => (None, d),
            (None, None) => return Err(AppError::Invalid("nothing to send".into())),
        };
        // Secrets, variables and profiles below all come from `ws_id`, so a
        // saved request resolves only in its own workspace.
        if let Some(r) = &req
            && r.workspace_id != *ws_id
        {
            return Err(AppError::Invalid(format!("request '{}' is not in this workspace", r.name)));
        }
        let referrer = req.as_ref().map(|r| LinkedFileReferrer::Request { id: r.meta.id });
        let linked = self.bound_linked_files(referrer, &spec)?;
        let chain = self.folder_chain(ws_id, req.as_ref().and_then(|r| r.folder_id))?;
        // The innermost import root; unless the user opened it to the
        // workspace, nothing outside it resolves under it.
        let root = chain.iter().rposition(|f| f.import_root);
        let sealed = root.filter(|&i| !chain[i].use_workspace_scope);
        let inner = &chain[sealed.unwrap_or(0)..];
        let settings = self.settings()?;
        let secrets = StoreSecrets { store: self.store.clone(), workspace: *ws_id };
        let mut settings_layers = vec![("app".to_string(), settings.defaults.clone()), ("workspace".to_string(), ws.settings.clone())];
        for f in &chain {
            settings_layers.push((format!("folder:{}", f.name), f.settings.clone()));
        }
        settings_layers.push(("request".into(), spec.settings.clone()));
        if let Some(o) = &opts.run_override {
            settings_layers.push(("run".into(), o.clone()));
        }
        // Each OAuth profile caches its token under the id of the workspace,
        // folder or request that defines it (unless it names its own).
        let owned = |auth: &AuthConfig, owner: Option<Id>| {
            let mut auth = auth.clone();
            if let Some(owner) = owner {
                auth.bind_token_cache(owner);
            }
            auth
        };
        let mut auth_layers = Vec::new();
        if sealed.is_none() {
            auth_layers.push(("workspace".to_string(), owned(&ws.auth, Some(ws.meta.id))));
        }
        for f in inner {
            auth_layers.push((format!("folder:{}", f.name), owned(&f.auth, Some(f.meta.id))));
        }
        auth_layers.push(("request".into(), owned(&spec.auth, req.as_ref().map(|r| r.meta.id))));
        let mut var_layers = Vec::new();
        if sealed.is_none() {
            var_layers.push(layer("workspace".into(), &ws.variables, &secrets)?);
        }
        // An import root's variables were the source's workspace variables,
        // so they rank where those would in a workspace of its own: below
        // the environment.
        let (base, nested) = inner.split_at(root.map_or(0, |i| i + 1) - sealed.unwrap_or(0));
        for f in base {
            var_layers.push(layer(format!("folder:{}", f.name), &f.variables, &secrets)?);
        }
        let env_id = opts.environment.or(ws.active_environment_id);
        let env_id = env_id.filter(|eid| sealed.is_none_or(|i| chain[i].import_environment_ids.contains(eid)));
        if let Some(eid) = env_id {
            let env =
                self.environments(ws_id)?.into_iter().find(|e| e.meta.id == eid).ok_or_else(|| AppError::NotFound("environment".into()))?;
            var_layers.push(layer(format!("environment:{}", env.name), &env.variables, &secrets)?);
        }
        for f in nested {
            var_layers.push(layer(format!("folder:{}", f.name), &f.variables, &secrets)?);
        }
        // Attachments referenced by the spec.
        let mut index = std::collections::HashMap::new();
        let spec_json = serde_json::to_value(&spec)?;
        collect_attachments(&spec_json, &mut |sha| {
            if let Ok(Some(b)) = self.get_attachment(sha) {
                index.insert(sha.to_string(), b);
            }
        });
        let settings_app = self.settings()?;
        let ctx = ExecutionContext {
            workspace_id: Some(*ws_id),
            request_id: req.as_ref().map(|r| r.meta.id),
            revision_id: req.as_ref().and_then(|r| r.revision_id),
            environment_id: env_id,
            spec,
            settings_layers,
            auth_layers,
            var_layers,
            tls_profiles: self.tls_profiles(ws_id)?,
            proxy_profiles: self.proxy_profiles(ws_id)?,
            integrations: self.integrations(ws_id)?,
            secrets: Arc::new(secrets),
            attachments: Arc::new(StoreAttachments { app_store: self.store.clone(), index, linked }),
            isolation: ws_id.to_string(),
            send_anyway: opts.send_anyway,
            seed: opts.seed,
            redaction_names: settings_app.redaction_names.clone(),
            scope: sealed.map(|i| chain[i].meta.id),
        };
        if sealed.is_some() {
            refuse_device_identity(&ctx.effective_auth().1)?;
            refuse_unbound_client_identity(&ctx)?;
        }
        self.check_device_identity(&ws, &ctx)?;
        self.check_token_files(&ctx.effective_auth().1)?;
        Ok(ctx)
    }

    /// Execute and (optionally) record history per the retention policy.
    pub async fn send(
        &self,
        request_id: Option<Id>,
        ws: &Id,
        draft: Option<RequestSpec>,
        opts: SendOptions,
        events: EventCtx,
        cancel: CancellationToken,
    ) -> Result<ExecutionOutput> {
        if self.is_locked() {
            return Err(AppError::Locked);
        }
        let ctx = self.build_context(request_id, ws, draft, &opts)?;
        let out = self.engine.execute(&ctx, events, cancel).await;
        if opts.record_history {
            self.record(&out)?;
        }
        Ok(out)
    }

    pub fn record(&self, out: &ExecutionOutput) -> Result<()> {
        let policy = self.settings()?.history;
        if !policy.enabled {
            return Ok(());
        }
        let body = if policy.keep_response_bodies { Some(out.body.as_ref()) } else { None };
        self.store.add_history(
            &out.record.id,
            out.record.workspace_id.as_ref(),
            out.record.request_id.as_ref(),
            out.record.started_at.timestamp_millis(),
            &out.record,
            body,
        )?;
        self.store.prune_history(policy.max_age_days, policy.max_total_bytes)?;
        Ok(())
    }
}

/// Refuse auth that would present this device's own workload identity (a
/// JWT-SVID from the Workload API or a token file) for a request under an
/// import root that the user has not opened to the workspace.
fn refuse_device_identity(auth: &AuthConfig) -> Result<()> {
    if uses_device_identity(auth) {
        return Err(AppError::Invalid(
            "an imported collection does not use this device's workload identity or token files until opened to the workspace".into(),
        ));
    }
    Ok(())
}

/// Refuse a TLS profile with a client identity (a certificate or this
/// device's X.509-SVID) and no host bindings, which would present it to any
/// destination, for a request under an import root that the user has not
/// opened to the workspace. A bound profile presents it only to the hosts
/// it names.
fn refuse_unbound_client_identity(ctx: &ExecutionContext) -> Result<()> {
    let settings = anvil_engine::settings::resolve(&ctx.settings_layers);
    let profile = settings.tls_profile_id.and_then(|id| ctx.tls_profiles.iter().find(|p| p.id == id));
    if let Some(p) = profile
        && p.client_identity.is_some()
        && p.bindings.is_empty()
    {
        return Err(AppError::Invalid(format!(
            "an imported collection does not use TLS profile '{}' (a client identity bound to no host) until opened to the workspace",
            p.name
        )));
    }
    Ok(())
}

/// Refuse a spec that names a linked local file (`AttachmentRef::LinkedFile`,
/// an arbitrary path). Unsaved drafts and every spec the desktop webview
/// supplies may reference only attachments stored in Anvil.
pub fn refuse_linked_files(spec: &RequestSpec) -> Result<()> {
    if has_linked_file(&serde_json::to_value(spec)?) {
        return Err(AppError::Invalid("this request names a linked local file; attach the file instead (Anvil stores a copy)".into()));
    }
    Ok(())
}

fn has_linked_file(v: &serde_json::Value) -> bool {
    match v {
        serde_json::Value::Object(o) => o.get("kind").and_then(|k| k.as_str()) == Some("linked_file") || o.values().any(has_linked_file),
        serde_json::Value::Array(a) => a.iter().any(has_linked_file),
        _ => false,
    }
}

fn collect_attachments(v: &serde_json::Value, f: &mut dyn FnMut(&str)) {
    match v {
        serde_json::Value::Object(o) => {
            if o.get("kind").and_then(|k| k.as_str()) == Some("stored")
                && let Some(s) = o.get("sha256").and_then(|s| s.as_str())
            {
                f(s);
            }
            o.values().for_each(|x| collect_attachments(x, f));
        }
        serde_json::Value::Array(a) => a.iter().for_each(|x| collect_attachments(x, f)),
        _ => {}
    }
}
