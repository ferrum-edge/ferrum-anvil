//! Build frozen execution contexts from storage and run them through the
//! shared engine, recording redacted history.

use crate::{App, AppError, Result};
use anvil_domain::Id;
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

/// Vault-backed secret resolution (fails closed while locked).
pub struct StoreSecrets(pub Arc<Store>);

impl SecretResolver for StoreSecrets {
    fn resolve(&self, r: &SecretRef) -> std::result::Result<Zeroizing<String>, String> {
        match self.0.get_secret(&r.id) {
            Ok(Some((_, v))) => Ok(v),
            Ok(None) => Err(format!("secret '{}' is not in this vault (it may not have been imported)", r.label)),
            Err(anvil_storage::StoreError::Locked) => Err("Anvil is locked".into()),
            Err(e) => Err(e.to_string()),
        }
    }
}

pub struct StoreAttachments {
    pub app_store: Arc<Store>,
    pub index: std::collections::HashMap<String, Vec<u8>>,
}

impl AttachmentResolver for StoreAttachments {
    fn load(&self, a: &AttachmentRef) -> std::result::Result<Bytes, String> {
        match a {
            AttachmentRef::Stored { sha256, file_name, .. } => self
                .index
                .get(sha256)
                .map(|b| Bytes::from(b.clone()))
                .ok_or_else(|| format!("attachment '{file_name}' is missing from this workspace")),
            AttachmentRef::LinkedFile { .. } => anvil_engine::context::MemoryAttachments::default().load(a),
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
    /// Extra highest-precedence variables (dataset row / extracted values).
    pub iteration_vars: Vec<VarEntry>,
    pub send_anyway: bool,
    pub record_history: bool,
    pub seed: Option<u64>,
}

impl App {
    /// Build the frozen context for a saved request (optionally with an
    /// unsaved draft spec) — settings, auth and variable layers resolved
    /// from workspace → folders → request.
    pub fn build_context(
        &self,
        request_id: Option<Id>,
        ws_id: &Id,
        draft: Option<RequestSpec>,
        opts: &SendOptions,
    ) -> Result<ExecutionContext> {
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
        let chain = self.folder_chain(req.as_ref().and_then(|r| r.folder_id))?;
        let settings = self.settings()?;
        let secrets = StoreSecrets(self.store.clone());
        let mut settings_layers = vec![("app".to_string(), settings.defaults.clone()), ("workspace".to_string(), ws.settings.clone())];
        for f in &chain {
            settings_layers.push((format!("folder:{}", f.name), f.settings.clone()));
        }
        settings_layers.push(("request".into(), spec.settings.clone()));
        if let Some(o) = &opts.run_override {
            settings_layers.push(("run".into(), o.clone()));
        }
        let mut auth_layers = vec![("workspace".to_string(), ws.auth.clone())];
        for f in &chain {
            auth_layers.push((format!("folder:{}", f.name), f.auth.clone()));
        }
        auth_layers.push(("request".into(), spec.auth.clone()));
        let mut var_layers = vec![layer("workspace".into(), &ws.variables, &secrets)?];
        let env_id = opts.environment.or(ws.active_environment_id);
        if let Some(eid) = env_id {
            let env =
                self.environments(ws_id)?.into_iter().find(|e| e.meta.id == eid).ok_or_else(|| AppError::NotFound("environment".into()))?;
            var_layers.push(layer(format!("environment:{}", env.name), &env.variables, &secrets)?);
        }
        for f in &chain {
            var_layers.push(layer(format!("folder:{}", f.name), &f.variables, &secrets)?);
        }
        if !opts.iteration_vars.is_empty() {
            var_layers.push(VarLayer { label: "iteration".into(), vars: opts.iteration_vars.clone() });
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
        Ok(ExecutionContext {
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
            secrets: Arc::new(StoreSecrets(self.store.clone())),
            attachments: Arc::new(StoreAttachments { app_store: self.store.clone(), index }),
            isolation: ws_id.to_string(),
            send_anyway: opts.send_anyway,
            seed: opts.seed,
            redaction_names: settings_app.redaction_names.clone(),
        })
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
