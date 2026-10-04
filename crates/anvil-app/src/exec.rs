//! Build frozen execution contexts from storage and run them through the
//! shared engine, recording redacted history.

use crate::device_identity::{selected_tls_profiles, uses_device_identity};
use crate::file_grants::FilePurpose;
use crate::linked_files::{LinkedFileReferrer, read_bound_file};
use crate::{App, AppError, Result};
use anvil_domain::Id;
use anvil_domain::auth::AuthConfig;
use anvil_domain::integration::IntegrationKind;
use anvil_domain::request::{AttachmentRef, RequestSpec};
use anvil_domain::secret::{SecretRef, SensitiveValue};
use anvil_domain::settings::SettingsOverrides;
use anvil_domain::workspace::Variable;
use anvil_engine::ExecutionOutput;
use anvil_engine::context::{AttachmentResolver, ExecutionContext, SecretResolver};
use anvil_engine::oauth_http::require_secure_token_endpoint;
use anvil_engine::vars::{VarEntry, VarLayer};
use anvil_storage::Store;
use anvil_transport::recorder::EventCtx;
use bytes::Bytes;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
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

/// The vault secrets an execution context names, looked up through
/// [`StoreSecrets`] when the context is built, which [`App::send`] and the
/// other async paths do on a blocking thread. OAuth credentials are only
/// prefetched after a fixed token endpoint passes its policy check; credentials
/// for templated endpoints resolve on demand after acquisition validates the
/// expanded endpoint. Each prefetched lookup keeps its outcome, so a secret
/// that is missing, owned by another workspace or unreadable still fails where
/// it is used. Fails closed once the store is locked.
pub struct ResolvedSecrets {
    resolved: HashMap<SecretRef, std::result::Result<Zeroizing<String>, String>>,
    /// Looks up a reference not prefetched, including deferred OAuth credentials.
    store: StoreSecrets,
}

impl ResolvedSecrets {
    /// Look up every secret named in `parts` (see [`secret_parts`]).
    fn lookup(store: StoreSecrets, parts: &[serde_json::Value]) -> ResolvedSecrets {
        let mut refs = HashSet::new();
        parts.iter().for_each(|p| collect_secret_refs(p, &mut refs));
        let mut resolved = HashMap::new();
        for r in refs {
            let v = store.resolve(&r);
            resolved.insert(r, v);
        }
        ResolvedSecrets { resolved, store }
    }
}

impl SecretResolver for ResolvedSecrets {
    fn resolve(&self, r: &SecretRef) -> std::result::Result<Zeroizing<String>, String> {
        if self.store.store.is_locked() {
            return Err("Anvil is locked".into());
        }
        match self.resolved.get(r) {
            Some(v) => v.clone(),
            None => crate::blocking_in_place(|| self.store.resolve(r)),
        }
    }
}

/// Where the engine reads the secrets of `ctx` from when it executes it: the
/// spec, the effective auth, and the TLS, proxy and integration profiles its
/// settings select (with the selected proxy's own TLS profile), as JSON.
/// Any other profile's secrets are looked up only if they are used.
fn secret_parts(ctx: &ExecutionContext) -> Result<Vec<serde_json::Value>> {
    let settings = anvil_engine::settings::resolve(&ctx.settings_layers);
    let proxy = settings.proxy_profile_id.and_then(|id| ctx.proxy_profiles.iter().find(|p| p.id == id));
    let tls: Vec<_> = selected_tls_profiles(ctx).collect();
    let integration = settings.integration_profile_id.and_then(|id| ctx.integrations.iter().find(|i| i.id == id));
    let mut spec = ctx.spec.clone();
    // Only effective auth is used. Inactive request auth must not cause an
    // OAuth credential to be fetched through the spec's duplicate reference.
    spec.auth = AuthConfig::None;
    let mut auth = ctx.effective_auth().1;
    let conflicting = auth.oauth_profile().is_err();
    defer_unvalidated_oauth_secrets(&mut auth, conflicting);
    Ok(vec![
        serde_json::to_value(spec)?,
        serde_json::to_value(auth)?,
        serde_json::to_value(tls)?,
        serde_json::to_value(proxy)?,
        serde_json::to_value(integration)?,
    ])
}

/// A fixed endpoint can be checked before freezing its vault credential.
/// Templated endpoints may depend on a later dataset row or dynamic helper:
/// their credentials resolve on demand, after the acquisition sink checks
/// the actual expanded endpoint. No unvalidated OAuth credential is prefetched.
fn defer_unvalidated_oauth_secrets(auth: &mut AuthConfig, conflicting: bool) {
    match auth {
        AuthConfig::OAuth2 { config } => {
            if conflicting || config.token_url.contains("{{") || require_secure_token_endpoint(&config.token_url).is_err() {
                config.client_secret = SensitiveValue::default();
            }
        }
        AuthConfig::Multi { profiles } => {
            for profile in profiles {
                defer_unvalidated_oauth_secrets(profile, conflicting);
            }
        }
        _ => {}
    }
}

/// Every vault reference (`SensitiveValue::Secret`) in `v`.
fn collect_secret_refs(v: &serde_json::Value, out: &mut HashSet<SecretRef>) {
    match v {
        serde_json::Value::Object(o) => {
            if o.get("kind").and_then(|k| k.as_str()) == Some("secret")
                && let Some(r) = o.get("secret").and_then(|s| SecretRef::deserialize(s).ok())
            {
                out.insert(r);
            }
            o.values().for_each(|x| collect_secret_refs(x, out));
        }
        serde_json::Value::Array(a) => a.iter().for_each(|x| collect_secret_refs(x, out)),
        _ => {}
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
    /// down, but an unbound client identity in the request's own TLS
    /// profile or its proxy's is refused. The context is tagged with the
    /// sealed root (`ExecutionContext::scope`) so a run or load chain keeps
    /// values extracted outside it, and its dataset, away from it.
    ///
    /// The context carries the engine's execution epoch for the workspace,
    /// taken when the build starts (`ExecutionContext::epoch`): an execution
    /// of it keeps nothing for the workspace (cookies, OAuth tokens,
    /// prepared TLS configurations, pooled connections, session tickets)
    /// once the workspace is deleted, even when it starts after the delete.
    pub fn build_context(
        &self,
        request_id: Option<Id>,
        ws_id: &Id,
        draft: Option<RequestSpec>,
        opts: &SendOptions,
    ) -> Result<ExecutionContext> {
        // Taken before anything is read for the workspace: a delete of it
        // from here on (or a lock) fences an execution of this context, even
        // one that starts after it, while a delete before this point leaves
        // nothing to read. A workspace restored with the same id afterwards
        // is not affected: its contexts are built after the delete.
        let epoch = self.engine.context_epoch(&ws_id.to_string());
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
        let selected_env = opts.environment.or(ws.active_environment_id);
        let environments = self.environments(ws_id)?;
        let env_id = match selected_env {
            Some(eid) if environments.iter().any(|env| env.meta.id == eid) => Some(eid),
            Some(eid) if opts.environment == Some(eid) => {
                return Err(AppError::NotFound("environment".into()));
            }
            // A deleted workspace default can remain in older profiles. Treat
            // it as unset; an explicit selection above remains an error.
            Some(_) => None,
            None => None,
        };
        let env_id = env_id.filter(|eid| sealed.is_none_or(|i| chain[i].import_environment_ids.contains(eid)));
        if let Some(eid) = env_id {
            let env = environments.into_iter().find(|e| e.meta.id == eid).ok_or_else(|| AppError::NotFound("environment".into()))?;
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
        let mut ctx = ExecutionContext {
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
            // Replaced below, once the context has passed its checks.
            secrets: Arc::new(StoreSecrets { store: self.store.clone(), workspace: *ws_id }),
            attachments: Arc::new(StoreAttachments { app_store: self.store.clone(), index, linked }),
            isolation: ws_id.to_string(),
            send_anyway: opts.send_anyway,
            seed: opts.seed,
            redaction_names: settings_app.redaction_names.clone(),
            scope: sealed.map(|i| chain[i].meta.id),
            epoch: Some(epoch),
            notes: vec![],
        };
        // A gateway profile's diagnostic reference lookup in a workspace a
        // bundle import or backup restore wrote into would send this device's
        // token where the import or restore said: a passphrase proves nothing
        // about who made a backup. It is paused under the same seal as this
        // device's workload identity, until the user allows the workspace.
        if self.device_identity_sealed(ws_id)? {
            let mut paused = false;
            for i in &mut ctx.integrations {
                let IntegrationKind::FerrumGateway { detail, .. } = &mut i.kind;
                paused |= detail.take().is_some();
            }
            if paused {
                ctx.notes.push(crate::device_identity::LOOKUP_PAUSED_NOTE.to_string());
            }
        }
        if sealed.is_some() {
            refuse_device_identity(&ctx.effective_auth().1)?;
            refuse_unbound_client_identity(&ctx)?;
        }
        self.check_device_identity(&ws, &ctx)?;
        self.check_token_files(&ctx.effective_auth().1)?;
        let parts = secret_parts(&ctx)?;
        ctx.secrets = Arc::new(ResolvedSecrets::lookup(secrets, &parts));
        Ok(ctx)
    }

    /// Execute and (optionally) record history per the retention policy.
    /// The context is built, and the execution recorded, on a blocking
    /// thread (see [`crate::off_runtime`]). A cancel while the context is
    /// being built returns `Canceled` at once: nothing is sent or recorded.
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
        let record_history = opts.record_history;
        let ctx = self.build_context_off_runtime(request_id, *ws, draft, opts, &cancel).await?;
        let out = self.engine.execute(&ctx, events, cancel).await;
        if !record_history {
            return Ok(out);
        }
        let (out, recorded) = self.record_off_runtime(out).await;
        recorded?;
        Ok(out)
    }

    /// [`App::build_context`] on a blocking thread (see
    /// [`crate::off_runtime`]). A cancel returns `Canceled` at once; the
    /// context still being built is dropped when it is done.
    pub async fn build_context_off_runtime(
        &self,
        request_id: Option<Id>,
        ws: Id,
        draft: Option<RequestSpec>,
        opts: SendOptions,
        cancel: &CancellationToken,
    ) -> Result<ExecutionContext> {
        let app = self.shared();
        let built = crate::off_runtime(move || app.build_context(request_id, &ws, draft, &opts));
        tokio::select! {
            biased;
            () = cancel.cancelled() => Err(AppError::Canceled),
            ctx = built => ctx,
        }
    }

    /// [`App::record`] on a blocking thread (see [`crate::off_runtime`]),
    /// handing `out` back with the outcome.
    pub async fn record_off_runtime(&self, out: ExecutionOutput) -> (ExecutionOutput, Result<()>) {
        let (app, out) = (self.shared(), Arc::new(out));
        let recording = out.clone();
        let recorded = crate::off_runtime(move || app.record(&recording)).await;
        // The blocking closure, and its handle on `out`, has ended by now;
        // should it not have, `out` is copied.
        (Arc::unwrap_or_clone(out), recorded)
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
/// opened to the workspace. Both selected profiles count: the request's own
/// and its proxy's. A bound profile presents it only to the hosts it names.
fn refuse_unbound_client_identity(ctx: &ExecutionContext) -> Result<()> {
    let settings = anvil_engine::settings::resolve(&ctx.settings_layers);
    let proxy = settings.proxy_profile_id.and_then(|id| ctx.proxy_profiles.iter().find(|p| p.id == id));
    if let Some(p) = selected_tls_profiles(ctx).find(|p| p.client_identity.is_some() && p.bindings.is_empty()) {
        if settings.tls_profile_id != Some(p.id)
            && let Some(proxy) = proxy.filter(|proxy| proxy.tls_profile_id == Some(p.id))
        {
            return Err(AppError::Invalid(format!(
                "an imported collection does not use TLS profile '{}' of proxy '{}' (a client identity bound to no host) until opened to the workspace",
                p.name, proxy.name
            )));
        }
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

pub(crate) fn collect_attachments(v: &serde_json::Value, f: &mut dyn FnMut(&str)) {
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
