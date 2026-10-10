//! Everything an execution needs, resolved by the caller (desktop core, CLI,
//! runner or load worker) from storage. The engine itself never reads the
//! database or the UI; it receives a frozen snapshot.

use crate::ContextEpoch;
use crate::vars::{VarEntry, VarLayer};
use anvil_domain::Id;
use anvil_domain::auth::AuthConfig;
use anvil_domain::integration::IntegrationProfile;
use anvil_domain::request::{AttachmentRef, RequestSpec};
use anvil_domain::secret::{SecretRef, SensitiveValue};
use anvil_domain::settings::SettingsOverrides;
use anvil_domain::tls::{ProxyProfile, TlsProfile};
use bytes::Bytes;
use std::collections::HashMap;
use std::sync::Arc;
use zeroize::Zeroizing;

pub trait SecretResolver: Send + Sync {
    fn resolve(&self, r: &SecretRef) -> Result<Zeroizing<String>, String>;

    /// A vault variable retained by the context builder until endpoint validation.
    /// Indices identify the original layers and entries; later run layers still win.
    fn variable_secret(&self, _layer: usize, _variable: usize) -> Option<SecretRef> {
        None
    }
}

/// Translate filtered entries back to the immediate source resolver's indices.
/// Keeping the source resolver also preserves its lock, ownership and snapshot checks.
struct RetainedVariableSecrets {
    source: Arc<dyn SecretResolver>,
    variables: Vec<Vec<usize>>,
}

impl SecretResolver for RetainedVariableSecrets {
    fn resolve(&self, reference: &SecretRef) -> Result<Zeroizing<String>, String> {
        self.source.resolve(reference)
    }

    fn variable_secret(&self, layer: usize, variable: usize) -> Option<SecretRef> {
        let original = *self.variables.get(layer)?.get(variable)?;
        self.source.variable_secret(layer, original)
    }
}

pub trait AttachmentResolver: Send + Sync {
    fn load(&self, a: &AttachmentRef) -> Result<Bytes, String>;
}

/// In-memory secrets (CLI, tests, load workers receiving scoped secrets).
#[derive(Default, Clone)]
pub struct MemorySecrets(pub HashMap<Id, Zeroizing<String>>);

impl SecretResolver for MemorySecrets {
    fn resolve(&self, r: &SecretRef) -> Result<Zeroizing<String>, String> {
        self.0.get(&r.id).cloned().ok_or_else(|| format!("secret '{}' is not available in this vault", r.label))
    }
}

/// Attachments from memory, falling back to linked files on disk.
#[derive(Default, Clone)]
pub struct MemoryAttachments(pub HashMap<String, Bytes>);

impl AttachmentResolver for MemoryAttachments {
    fn load(&self, a: &AttachmentRef) -> Result<Bytes, String> {
        match a {
            AttachmentRef::Stored { sha256, file_name, .. } => {
                self.0.get(sha256).cloned().ok_or_else(|| format!("attachment '{file_name}' ({sha256}) is missing from this workspace"))
            }
            AttachmentRef::LinkedFile { path } => {
                let meta = std::fs::metadata(path).map_err(|e| format!("linked file '{path}' is not readable: {e}"))?;
                if meta.len() > 512 * 1024 * 1024 {
                    return Err(format!("linked file '{path}' exceeds 512 MiB"));
                }
                std::fs::read(path).map(Bytes::from).map_err(|e| format!("linked file '{path}' is not readable: {e}"))
            }
        }
    }
}

pub fn resolve_sensitive(v: &SensitiveValue, secrets: &dyn SecretResolver) -> Result<(Zeroizing<String>, bool), String> {
    match v {
        SensitiveValue::Template { value } => Ok((Zeroizing::new(value.clone()), !v.is_pure_reference())),
        SensitiveValue::Secret { secret } => secrets.resolve(secret).map(|s| (s, true)),
    }
}

/// Run and load-test note for a dataset whose rows a step under a sealed
/// import root (`ExecutionContext::scope`) did not receive.
pub const DATASET_SKIPPED_UNDER_IMPORT_ROOT: &str =
    "Dataset rows were not applied to steps of an imported collection not opened to this workspace; open its import root to use them.";

#[derive(Clone)]
pub struct ExecutionContext {
    pub workspace_id: Option<Id>,
    pub request_id: Option<Id>,
    pub revision_id: Option<Id>,
    pub environment_id: Option<Id>,
    pub spec: RequestSpec,
    /// Ordered low → high precedence: ("app", ..), ("workspace", ..), ("folder:<name>", ..), ("request", spec.settings), ("run", ..).
    pub settings_layers: Vec<(String, SettingsOverrides)>,
    /// Ordered outer → inner: workspace, folders…, request. The innermost non-`Inherit` wins.
    pub auth_layers: Vec<(String, AuthConfig)>,
    /// Use [`Self::retain_variables`] to remove entries without changing their vault bindings.
    pub var_layers: Vec<VarLayer>,
    pub tls_profiles: Vec<TlsProfile>,
    pub proxy_profiles: Vec<ProxyProfile>,
    pub integrations: Vec<IntegrationProfile>,
    pub secrets: Arc<dyn SecretResolver>,
    pub attachments: Arc<dyn AttachmentResolver>,
    /// Connection/cookie isolation key (workspace id).
    pub isolation: String,
    /// The user explicitly chose "send anyway" for a body failing lint.
    pub send_anyway: bool,
    pub seed: Option<u64>,
    /// Extra names always treated as secrets by the redactor.
    pub redaction_names: Vec<String>,
    /// The sealed import root this context was built under (an imported
    /// collection's root folder not opened to its workspace), `None` for the
    /// workspace's own scope. A run or load chain hands a step only the
    /// run-local values of the same scope: values extracted by steps of that
    /// scope and, for the workspace scope only, the dataset row.
    pub scope: Option<Id>,
    /// The engine's execution epoch for `isolation`, taken when the context
    /// was built ([`crate::Engine::context_epoch`]): a lock or a delete of
    /// the workspace after that point fences an execution of this context,
    /// even one that starts later. `None` (a standalone context): the
    /// epoch is taken when the execution starts.
    pub epoch: Option<ContextEpoch>,
    /// Notes the context's builder adds to every HTTP record's inferred list
    /// (for example, that a gateway profile's diagnostic lookup is paused).
    pub notes: Vec<String>,
}

impl ExecutionContext {
    /// Remove variables while preserving each retained entry's deferred vault identity.
    /// Layers (including empty ones) keep their positions. Repeated filtering composes
    /// with the previous mapping; entries appended afterward have no retained binding.
    pub fn retain_variables(&mut self, mut keep: impl FnMut(&VarEntry) -> bool) {
        let mut variables = Vec::with_capacity(self.var_layers.len());
        let mut changed = false;
        for layer in &mut self.var_layers {
            let mut retained = Vec::with_capacity(layer.vars.len());
            let mut original = 0;
            layer.vars.retain(|entry| {
                let index = original;
                original += 1;
                if keep(entry) {
                    retained.push(index);
                    true
                } else {
                    changed = true;
                    false
                }
            });
            variables.push(retained);
        }
        if changed {
            self.secrets = Arc::new(RetainedVariableSecrets { source: self.secrets.clone(), variables });
        }
    }

    /// Minimal context for a standalone request (CLI / tests).
    pub fn standalone(spec: RequestSpec) -> Self {
        let settings = spec.settings.clone();
        let auth = spec.auth.clone();
        ExecutionContext {
            workspace_id: None,
            request_id: None,
            revision_id: None,
            environment_id: None,
            spec,
            settings_layers: vec![("request".into(), settings)],
            auth_layers: vec![("request".into(), auth)],
            var_layers: vec![],
            tls_profiles: vec![],
            proxy_profiles: vec![],
            integrations: vec![],
            secrets: Arc::new(MemorySecrets::default()),
            attachments: Arc::new(MemoryAttachments::default()),
            isolation: "standalone".into(),
            send_anyway: false,
            seed: None,
            redaction_names: vec![],
            scope: None,
            epoch: None,
            notes: vec![],
        }
    }

    pub fn effective_auth(&self) -> (String, AuthConfig) {
        for (label, a) in self.auth_layers.iter().rev() {
            if !matches!(a, AuthConfig::Inherit) {
                return (label.clone(), a.clone());
            }
        }
        ("none".into(), AuthConfig::None)
    }
}
