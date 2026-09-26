//! IPC commands. Every data command goes through `DesktopState::app()`, which
//! refuses while locked; secrets never cross into the webview except where
//! the user explicitly typed them (they are stored and only references return).

use crate::state::DesktopState;
use anvil_app::exec::{SendOptions, refuse_linked_files};
use anvil_app::file_grants::FilePurpose;
use anvil_app::profiles::Unlock;
use anvil_app::{App, AppError};
use anvil_domain::Id;
use anvil_domain::events::ExecutionEvent;
use anvil_domain::execution::ExecutionRecord;
use anvil_domain::integration::IntegrationProfile;
use anvil_domain::request::RequestSpec;
use anvil_domain::secret::SecretRef;
use anvil_domain::settings::{AppSettings, SettingsOverrides};
use anvil_domain::tls::{ProxyProfile, TlsProfile};
use anvil_domain::workspace::{Environment, Folder, RequestDefinition, Workspace};
use anvil_portability::ExportMode;
use anvil_portability::plan::ConflictPolicy;
use anvil_storage::KdfParams;
use anvil_transport::recorder::EventCtx;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tauri::{AppHandle, Emitter, State};
use tokio_util::sync::CancellationToken;

pub(crate) type R<T> = Result<T, String>;

pub(crate) fn e(err: AppError) -> String {
    match err {
        AppError::Locked => "LOCKED".into(),
        other => other.to_string(),
    }
}

pub(crate) fn id(s: &str) -> R<Id> {
    s.parse().map_err(|_| format!("invalid id '{s}'"))
}

// ------------------------------------------------------------------ status

#[derive(Serialize)]
pub struct Status {
    pub state: &'static str,
    pub profile: Option<String>,
    pub protection: Option<anvil_domain::workspace::ProtectionMode>,
    pub version: &'static str,
}

#[tauri::command]
pub fn app_status(st: State<'_, DesktopState>) -> Status {
    let g = st.app.read();
    match g.as_ref() {
        Some(a) => Status {
            state: if a.is_locked() { "locked" } else { "unlocked" },
            profile: Some(a.header.display_name.clone()),
            // From disk: a keychain profile converted to a passphrase
            // changes mode while it is open.
            protection: Some(anvil_storage::vault::read_header(&a.dir).map(|h| h.protection).unwrap_or(a.header.protection)),
            version: env!("CARGO_PKG_VERSION"),
        },
        None => Status { state: "no_profile", profile: None, protection: None, version: env!("CARGO_PKG_VERSION") },
    }
}

#[tauri::command]
pub fn profiles_list(st: State<'_, DesktopState>) -> Vec<anvil_app::profiles::ProfileSummary> {
    st.profiles.list()
}

#[derive(Serialize)]
pub struct Created {
    pub profile_id: String,
    /// Shown once; never stored.
    pub recovery_key: Option<String>,
}

#[tauri::command]
pub fn profile_create(st: State<'_, DesktopState>, name: String, passphrase: Option<String>, keychain: bool) -> R<Created> {
    let (summary, key, recovery) = if keychain {
        let (s, k) = st.profiles.create_keychain(&name).map_err(e)?;
        (s, k, None)
    } else {
        let p = passphrase.ok_or("a passphrase is required")?;
        let (s, k, r) = st.profiles.create_passphrase(&name, &p, KdfParams::interactive()).map_err(e)?;
        (s, k, Some(r.to_string()))
    };
    let header = anvil_storage::vault::read_header(&summary.dir).map_err(|x| x.to_string())?;
    let app = App::open(summary.dir.clone(), header, key).map_err(e)?;
    st.set_app(app);
    st.touch();
    Ok(Created { profile_id: summary.profile_id, recovery_key: recovery })
}

#[tauri::command]
pub fn profile_unlock(st: State<'_, DesktopState>, profile_id: String, passphrase: Option<String>, recovery_key: Option<String>) -> R<()> {
    let p = st.profiles.find(&profile_id).map_err(e)?;
    let how = match (&passphrase, &recovery_key) {
        (Some(pw), _) => Unlock::Passphrase(pw),
        (None, Some(rk)) => Unlock::RecoveryKey(rk),
        (None, None) => Unlock::Keychain,
    };
    let (header, key) = anvil_app::profiles::ProfileManager::unlock(&p.dir, how).map_err(e)?;
    {
        let g = st.app.read();
        if let Some(a) = g.as_ref()
            && a.header.profile_id == header.profile_id
        {
            a.unlock(key).map_err(e)?;
            st.touch();
            drop(g);
            st.flush_pending_reports();
            return Ok(());
        }
    }
    let app = App::open(p.dir, header, key).map_err(e)?;
    st.set_app(app);
    st.touch();
    st.flush_pending_reports();
    Ok(())
}

/// Re-wrap the data key under a new passphrase (the app must be unlocked;
/// passphrase profiles only).
#[tauri::command]
pub fn profile_change_passphrase(st: State<'_, DesktopState>, new_passphrase: String) -> R<()> {
    st.app()?.change_passphrase(&new_passphrase, KdfParams::interactive()).map_err(e)
}

#[derive(Serialize)]
pub struct Converted {
    /// Shown once; never stored.
    pub recovery_key: String,
    /// False if the OS credential store kept the old entry; it no longer
    /// unlocks the profile and removal is retried at the next unlock.
    pub keychain_entry_removed: bool,
}

/// Protect an OS-keychain profile with a passphrase instead (the app must be
/// unlocked). Afterwards the keychain no longer opens it.
#[tauri::command]
pub fn profile_convert_to_passphrase(st: State<'_, DesktopState>, new_passphrase: String) -> R<Converted> {
    let c = st.app()?.convert_to_passphrase(&new_passphrase, KdfParams::interactive()).map_err(e)?;
    Ok(Converted { recovery_key: c.recovery_key.to_string(), keychain_entry_removed: c.keychain_entry_removed })
}

#[tauri::command]
pub fn app_lock(st: State<'_, DesktopState>, app: AppHandle) {
    st.lock();
    let _ = app.emit("locked", ());
}

#[tauri::command]
pub fn touch(st: State<'_, DesktopState>) {
    st.touch();
}

#[derive(Serialize)]
pub struct SystemInfo {
    pub version: &'static str,
    pub engine: &'static str,
    pub catalog: String,
    pub system_roots: usize,
    pub data_dir: String,
    pub platform: String,
}

#[tauri::command]
pub fn system_info(st: State<'_, DesktopState>) -> SystemInfo {
    let (roots, _) = anvil_transport::tls::system_root_status();
    SystemInfo {
        version: env!("CARGO_PKG_VERSION"),
        engine: anvil_transport::ADAPTER_VERSION,
        catalog: anvil_diagnostics::catalog_version(),
        system_roots: roots,
        data_dir: st.profiles.root.display().to_string(),
        platform: format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
    }
}

// ------------------------------------------------------------------ workspaces

#[tauri::command]
pub fn workspaces_list(st: State<'_, DesktopState>) -> R<Vec<Workspace>> {
    st.app()?.workspaces().map_err(e)
}

#[tauri::command]
pub fn workspace_create(st: State<'_, DesktopState>, name: String) -> R<Workspace> {
    st.app()?.create_workspace(&name).map_err(e)
}

#[tauri::command]
pub fn workspace_save(st: State<'_, DesktopState>, workspace: Workspace) -> R<Workspace> {
    st.app()?.save_workspace(workspace).map_err(e)
}

#[tauri::command]
pub fn workspace_delete(st: State<'_, DesktopState>, workspace_id: String) -> R<()> {
    st.app()?.delete_workspace(&id(&workspace_id)?).map_err(e)
}

#[tauri::command]
pub fn tree_get(st: State<'_, DesktopState>, workspace_id: String) -> R<Vec<anvil_app::workspace::TreeNode>> {
    st.app()?.tree(&id(&workspace_id)?).map_err(e)
}

#[tauri::command]
pub fn folder_create(st: State<'_, DesktopState>, workspace_id: String, parent_id: Option<String>, name: String) -> R<Folder> {
    let parent = parent_id.map(|p| id(&p)).transpose()?;
    st.app()?.create_folder(&id(&workspace_id)?, parent, &name).map_err(e)
}

#[tauri::command]
pub fn folder_get(st: State<'_, DesktopState>, folder_id: String) -> R<Folder> {
    st.app()?.folder(&id(&folder_id)?).map_err(e)
}

#[tauri::command]
pub fn folder_save(st: State<'_, DesktopState>, folder: Folder) -> R<Folder> {
    st.app()?.save_folder(folder).map_err(e)
}

/// The user's explicit choice to let an imported collection's requests also
/// resolve the workspace's variables, active environment and auth, and this
/// device's workload identity (see `App::build_context`).
#[tauri::command]
pub fn folder_set_workspace_scope(st: State<'_, DesktopState>, folder_id: String, allow: bool) -> R<Folder> {
    st.app()?.set_import_root_workspace_scope(&id(&folder_id)?, allow).map_err(e)
}

#[tauri::command]
pub fn folder_move(st: State<'_, DesktopState>, folder_id: String, parent_id: Option<String>, sort_key: f64) -> R<Folder> {
    let parent = parent_id.map(|p| id(&p)).transpose()?;
    st.app()?.move_folder(&id(&folder_id)?, parent, sort_key).map_err(e)
}

#[tauri::command]
pub fn folder_delete(st: State<'_, DesktopState>, folder_id: String) -> R<()> {
    st.app()?.delete_folder(&id(&folder_id)?).map_err(e)
}

/// A spec from the webview references only stored attachments, never a
/// linked local file (a path).
#[tauri::command]
pub fn request_create(
    st: State<'_, DesktopState>,
    workspace_id: String,
    folder_id: Option<String>,
    name: String,
    spec: Option<RequestSpec>,
) -> R<RequestDefinition> {
    let app = st.app()?;
    let folder = folder_id.map(|p| id(&p)).transpose()?;
    let spec = spec.unwrap_or_else(|| RequestSpec::http("GET", "https://"));
    refuse_linked_files(&spec).map_err(e)?;
    app.create_request(&id(&workspace_id)?, folder, &name, spec).map_err(e)
}

#[tauri::command]
pub fn request_get(st: State<'_, DesktopState>, request_id: String) -> R<RequestDefinition> {
    st.app()?.request(&id(&request_id)?).map_err(e)
}

#[tauri::command]
pub fn request_save(st: State<'_, DesktopState>, request: RequestDefinition) -> R<RequestDefinition> {
    let app = st.app()?;
    refuse_linked_files(&request.spec).map_err(e)?;
    app.save_request(request).map_err(e)
}

#[tauri::command]
pub fn request_move(st: State<'_, DesktopState>, request_id: String, folder_id: Option<String>, sort_key: f64) -> R<RequestDefinition> {
    let folder = folder_id.map(|p| id(&p)).transpose()?;
    st.app()?.move_request(&id(&request_id)?, folder, sort_key).map_err(e)
}

#[tauri::command]
pub fn request_duplicate(st: State<'_, DesktopState>, request_id: String) -> R<RequestDefinition> {
    st.app()?.duplicate_request(&id(&request_id)?).map_err(e)
}

#[tauri::command]
pub fn request_delete(st: State<'_, DesktopState>, request_id: String) -> R<()> {
    st.app()?.delete_request(&id(&request_id)?).map_err(e)
}

#[tauri::command]
pub fn search(st: State<'_, DesktopState>, workspace_id: String, query: String) -> R<Vec<RequestDefinition>> {
    st.app()?.search(&id(&workspace_id)?, &query).map_err(e)
}

// ------------------------------------------------------------------ environments & secrets

#[tauri::command]
pub fn environments_list(st: State<'_, DesktopState>, workspace_id: String) -> R<Vec<Environment>> {
    st.app()?.environments(&id(&workspace_id)?).map_err(e)
}

#[tauri::command]
pub fn environment_save(st: State<'_, DesktopState>, environment: Environment) -> R<Environment> {
    st.app()?.save_environment(environment).map_err(e)
}

#[tauri::command]
pub fn environment_delete(st: State<'_, DesktopState>, environment_id: String) -> R<()> {
    st.app()?.delete_environment(&id(&environment_id)?).map_err(e)
}

/// Store a secret; only the reference comes back to the UI.
#[tauri::command]
pub fn secret_create(st: State<'_, DesktopState>, workspace_id: String, label: String, value: String) -> R<SecretRef> {
    st.app()?.set_secret(&id(&workspace_id)?, &label, &value).map_err(e)
}

/// Generate a DPoP P-256 key inside the vault; returns only its reference and public thumbprint.
#[derive(Serialize)]
pub struct GeneratedKey {
    pub secret: SecretRef,
    pub jkt: String,
}

#[tauri::command]
pub fn dpop_generate_key(st: State<'_, DesktopState>, workspace_id: String, label: String) -> R<GeneratedKey> {
    let ws = id(&workspace_id)?;
    let pem = anvil_auth::dpop::generate_key_pem().map_err(|x| x.to_string())?;
    let (x, y) = anvil_auth::dpop::public_jwk(&pem).map_err(|x| x.to_string())?;
    let secret = st.app()?.set_secret(&ws, &label, &pem).map_err(e)?;
    Ok(GeneratedKey { secret, jkt: anvil_auth::dpop::thumbprint(&x, &y) })
}

// ------------------------------------------------------------------ profiles (TLS/proxy/integration)

#[tauri::command]
pub fn tls_profiles_list(st: State<'_, DesktopState>, workspace_id: String) -> R<Vec<TlsProfile>> {
    st.app()?.tls_profiles(&id(&workspace_id)?).map_err(e)
}

#[tauri::command]
pub fn tls_profile_save(st: State<'_, DesktopState>, profile: TlsProfile) -> R<TlsProfile> {
    st.app()?.save_tls_profile(profile).map_err(e)
}

#[tauri::command]
pub fn proxy_profiles_list(st: State<'_, DesktopState>, workspace_id: String) -> R<Vec<ProxyProfile>> {
    st.app()?.proxy_profiles(&id(&workspace_id)?).map_err(e)
}

#[tauri::command]
pub fn proxy_profile_save(st: State<'_, DesktopState>, profile: ProxyProfile) -> R<ProxyProfile> {
    st.app()?.save_proxy_profile(profile).map_err(e)
}

#[tauri::command]
pub fn integrations_list(st: State<'_, DesktopState>, workspace_id: String) -> R<Vec<IntegrationProfile>> {
    st.app()?.integrations(&id(&workspace_id)?).map_err(e)
}

#[tauri::command]
pub fn integration_save(st: State<'_, DesktopState>, profile: IntegrationProfile) -> R<IntegrationProfile> {
    st.app()?.save_integration(profile).map_err(e)
}

#[tauri::command]
pub fn settings_get(st: State<'_, DesktopState>) -> R<AppSettings> {
    st.app()?.settings().map_err(e)
}

#[tauri::command]
pub fn settings_save(st: State<'_, DesktopState>, settings: AppSettings) -> R<()> {
    st.app()?.save_settings(&settings).map_err(e)
}

// ------------------------------------------------------------------ execution

#[derive(Deserialize)]
pub struct SendInput {
    pub workspace_id: String,
    pub request_id: Option<String>,
    pub spec: Option<RequestSpec>,
    pub environment_id: Option<String>,
    pub send_anyway: bool,
    pub run_override: Option<SettingsOverrides>,
}

#[derive(Serialize, Clone)]
pub struct BodyView {
    pub text: Option<String>,
    pub pretty: Option<String>,
    pub hex: Option<String>,
    pub is_binary: bool,
    pub decoded: bool,
    pub shown_bytes: usize,
    pub captured_bytes: usize,
}

#[derive(Serialize, Clone)]
pub struct ExecutionView {
    pub record: ExecutionRecord,
    pub body: BodyView,
}

const MAX_TEXT: usize = 2 * 1024 * 1024;

pub fn body_view(raw: &[u8], decoded: Option<&[u8]>, content_type: Option<&str>) -> BodyView {
    let bytes = decoded.unwrap_or(raw);
    let shown = &bytes[..bytes.len().min(MAX_TEXT)];
    let text = std::str::from_utf8(shown).ok().map(|s| s.to_string()).or_else(|| {
        // Allow a truncated UTF-8 tail at the display cap.
        std::str::from_utf8(&shown[..shown.len().saturating_sub(3)]).ok().map(|s| s.to_string())
    });
    let is_binary = text.is_none() || shown.iter().take(4096).any(|b| *b == 0);
    let ct = content_type.unwrap_or("").to_ascii_lowercase();
    let pretty = match &text {
        Some(t) if !is_binary && (ct.contains("json") || t.trim_start().starts_with('{') || t.trim_start().starts_with('[')) => {
            serde_json::from_str::<serde_json::Value>(t).ok().and_then(|v| serde_json::to_string_pretty(&v).ok())
        }
        _ => None,
    };
    let hex = if is_binary {
        Some(
            shown
                .iter()
                .take(4096)
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .chunks(16)
                .map(|c| c.join(" "))
                .collect::<Vec<_>>()
                .join("\n"),
        )
    } else {
        None
    };
    BodyView {
        text: if is_binary { None } else { text },
        pretty,
        hex,
        is_binary,
        decoded: decoded.is_some(),
        shown_bytes: shown.len(),
        captured_bytes: raw.len(),
    }
}

#[tauri::command]
pub async fn effective_request(st: State<'_, DesktopState>, input: SendInput) -> R<anvil_engine::preview::EffectiveRequest> {
    let app = st.app()?;
    let ws = id(&input.workspace_id)?;
    let rid = input.request_id.as_deref().map(id).transpose()?;
    let env = input.environment_id.as_deref().map(id).transpose()?;
    let ctx = app
        .build_context(
            rid,
            &ws,
            input.spec,
            &SendOptions { environment: env, run_override: input.run_override, send_anyway: input.send_anyway, ..Default::default() },
        )
        .map_err(e)?;
    app.engine.preview(&ctx).map_err(|f| format!("{:?}: {}", f.kind, f.message))
}

#[tauri::command]
pub async fn send_request(st: State<'_, DesktopState>, handle: AppHandle, input: SendInput, execution_id: String) -> R<ExecutionView> {
    let app = st.app()?;
    let exec_id = id(&execution_id)?;
    let ws = id(&input.workspace_id)?;
    let rid = input.request_id.as_deref().map(id).transpose()?;
    let env = input.environment_id.as_deref().map(id).transpose()?;
    let cancel = CancellationToken::new();
    st.running.lock().insert(exec_id, cancel.clone());
    let h2 = handle.clone();
    let last_progress = parking_lot::Mutex::new(std::time::Instant::now());
    let sink: anvil_transport::EventFn = Arc::new(move |ev: ExecutionEvent| {
        if matches!(ev, ExecutionEvent::BodyProgress { .. }) {
            let mut l = last_progress.lock();
            if l.elapsed() < std::time::Duration::from_millis(100) {
                return;
            }
            *l = std::time::Instant::now();
        }
        let _ = h2.emit("execution-event", &ev);
    });
    let events = EventCtx { execution_id: exec_id, sink: Some(sink) };
    let opts = SendOptions {
        environment: env,
        run_override: input.run_override,
        send_anyway: input.send_anyway,
        record_history: true,
        ..Default::default()
    };
    let res = app.send(rid, &ws, input.spec, opts, events, cancel).await;
    st.running.lock().remove(&exec_id);
    let out = res.map_err(e)?;
    let ct = out.record.response.as_ref().and_then(|r| r.body.content_type.clone());
    let body = body_view(&out.body, out.decoded_body.as_deref(), ct.as_deref());
    Ok(ExecutionView { record: out.record, body })
}

#[tauri::command]
pub fn cancel_execution(st: State<'_, DesktopState>, execution_id: String) -> R<bool> {
    let exec_id = id(&execution_id)?;
    Ok(match st.running.lock().get(&exec_id) {
        Some(t) => {
            t.cancel();
            true
        }
        None => false,
    })
}

#[derive(Serialize)]
pub struct HistoryItem {
    pub id: String,
    pub started_at: i64,
    pub method: String,
    pub url: String,
    pub summary: String,
    pub status: Option<u16>,
    pub request_id: Option<String>,
}

#[tauri::command]
pub fn history_list(st: State<'_, DesktopState>, workspace_id: String, request_id: Option<String>, limit: usize) -> R<Vec<HistoryItem>> {
    let app = st.app()?;
    let ws = id(&workspace_id)?;
    let rid = request_id.as_deref().map(id).transpose()?;
    let mut out = Vec::new();
    for h in app.store.list_history(Some(&ws), rid.as_ref(), limit.min(500)).map_err(|x| x.to_string())? {
        if let Ok(Some((rec, _))) = app.store.get_history::<ExecutionRecord>(&h.id) {
            out.push(HistoryItem {
                id: h.id,
                started_at: h.started_at,
                method: rec.prepared.method.clone(),
                url: rec.prepared.url.clone(),
                summary: rec.outcome.summary.clone(),
                status: rec.response.as_ref().map(|r| r.status),
                request_id: rec.request_id.map(|r| r.to_string()),
            });
        }
    }
    Ok(out)
}

#[tauri::command]
pub fn history_get(st: State<'_, DesktopState>, history_id: String) -> R<ExecutionView> {
    let app = st.app()?;
    let (rec, body): (ExecutionRecord, _) =
        app.store.get_history(&history_id).map_err(|x| x.to_string())?.ok_or("history entry not found")?;
    let raw = body.map(|b| b.to_vec()).unwrap_or_default();
    let ct = rec.response.as_ref().and_then(|r| r.body.content_type.clone());
    let enc = rec.response.as_ref().and_then(|r| r.body.content_encoding.clone());
    // The recorded limit, so the viewer shows what assertions saw.
    let limit = rec.prepared.settings.limits.max_decoded_bytes;
    let decoded = match anvil_transport::decode::decode(enc.as_deref(), &raw, limit) {
        anvil_transport::decode::DecodeOutcome::Decoded { bytes, .. } => Some(bytes),
        _ => None,
    };
    let body = body_view(&raw, decoded.as_deref(), ct.as_deref());
    Ok(ExecutionView { record: rec, body })
}

#[tauri::command]
pub fn history_clear(st: State<'_, DesktopState>, workspace_id: Option<String>) -> R<()> {
    let ws = workspace_id.map(|w| id(&w)).transpose()?;
    st.app()?.store.clear_history(ws.as_ref()).map_err(|x| x.to_string())
}

#[tauri::command]
pub fn lint_body(kind: String, text: String) -> anvil_engine::lint::LintResult {
    match kind.as_str() {
        "xml" | "soap" => anvil_engine::lint::xml(&text),
        _ => anvil_engine::lint::json(&text),
    }
}

#[tauri::command]
pub fn jwt_inspect(token: String) -> R<anvil_auth::jwt::Inspection> {
    anvil_auth::jwt::inspect(&token, chrono::Utc::now(), 0).map_err(|x| x.to_string())
}

/// What a SPIFFE Workload API endpoint issues to this process (public data
/// only: SPIFFE IDs, expiry, bundle key ids, JWT-SVID checks). Keys and
/// tokens stay in the backend and are dropped. Refused while locked.
#[tauri::command]
pub async fn workload_probe(
    st: State<'_, DesktopState>,
    endpoint: String,
    audience: Option<String>,
) -> R<anvil_engine::workload::WorkloadProbe> {
    st.app()?;
    Ok(anvil_engine::workload::probe(&endpoint, audience.as_deref(), std::time::Duration::from_secs(5)).await)
}

// ------------------------------------------------------------------ portability

fn mode(m: &str) -> R<ExportMode> {
    Ok(match m {
        "share_safely" => ExportMode::ShareSafely,
        "encrypted_transfer" => ExportMode::EncryptedTransfer,
        "full_backup" => ExportMode::FullBackup,
        _ => return Err(format!("unknown export mode {m}")),
    })
}

fn policy(p: &str) -> R<ConflictPolicy> {
    Ok(match p {
        "merge" => ConflictPolicy::Merge,
        "replace" => ConflictPolicy::Replace,
        "duplicate" => ConflictPolicy::Duplicate,
        _ => return Err(format!("unknown policy {p}")),
    })
}

/// A bundle preview, or a full-backup preview (same shape for the renderer).
#[derive(Serialize)]
#[serde(untagged)]
pub enum ExportPreview {
    Bundle(anvil_portability::bundle::ExportPreview),
    Backup(anvil_app::backup::BackupPreview),
}

/// A full backup always covers the whole profile.
fn full_backup(ws: Option<&Id>, m: ExportMode) -> R<bool> {
    match (m, ws) {
        (ExportMode::FullBackup, Some(_)) => Err("a full backup covers every workspace; export a workspace with another mode".into()),
        (ExportMode::FullBackup, None) => Ok(true),
        _ => Ok(false),
    }
}

#[tauri::command]
pub fn export_preview(st: State<'_, DesktopState>, workspace_id: Option<String>, export_mode: String) -> R<ExportPreview> {
    let ws = workspace_id.map(|w| id(&w)).transpose()?;
    let m = mode(&export_mode)?;
    let app = st.app()?;
    if full_backup(ws.as_ref(), m)? {
        return app.backup_preview().map(ExportPreview::Backup).map_err(e);
    }
    app.export_preview(ws.as_ref(), m, false).map(ExportPreview::Bundle).map_err(e)
}

/// Run `f` on a blocking worker thread. Writing or opening an encrypted
/// bundle derives its vault key (Argon2id), which must not stall the UI
/// thread that runs synchronous commands.
async fn off_ui_thread<T: Send + 'static>(f: impl FnOnce() -> anvil_app::Result<T> + Send + 'static) -> R<T> {
    tauri::async_runtime::spawn_blocking(f).await.map_err(|x| x.to_string())?.map_err(e)
}

/// Write to the destination the user picked in the native save dialog
/// (`file_choose` with purpose `bundle_export`); `grant` is that selection.
#[tauri::command]
pub async fn export_to_path(
    st: State<'_, DesktopState>,
    workspace_id: Option<String>,
    export_mode: String,
    passphrase: Option<String>,
    grant: String,
) -> R<usize> {
    let app = st.app()?;
    let ws = workspace_id.map(|w| id(&w)).transpose()?;
    let m = mode(&export_mode)?;
    let bytes = if full_backup(ws.as_ref(), m)? {
        let pass = passphrase.ok_or("a full backup needs a passphrase")?;
        off_ui_thread(move || app.export_backup(&pass)).await?.0
    } else {
        off_ui_thread(move || app.export(ws.as_ref(), m, passphrase.as_deref(), false)).await?.0
    };
    st.file_grants.write(&grant, FilePurpose::BundleExport, &bytes).map_err(|x| x.to_string())
}

/// The bundle the user picked in the native open dialog (purpose
/// `bundle_import`).
fn read_bundle(st: &DesktopState, grant: &str) -> R<Vec<u8>> {
    Ok(st.file_grants.read(grant, FilePurpose::BundleImport).map_err(|x| x.to_string())?.bytes)
}

/// A full backup is restored; anything else is imported as a bundle.
#[tauri::command]
pub async fn import_preview(
    st: State<'_, DesktopState>,
    grant: String,
    passphrase: Option<String>,
    conflict_policy: String,
) -> R<anvil_app::port::ImportReport> {
    let app = st.app()?;
    let bytes = read_bundle(&st, &grant)?;
    let policy = policy(&conflict_policy)?;
    if anvil_app::backup::is_backup(&bytes) {
        // A full backup restores every item under its own id, so "copies" is
        // previewed as Merge; the report's policy tells the dialog to switch.
        let policy = if policy == ConflictPolicy::Duplicate { ConflictPolicy::Merge } else { policy };
        return off_ui_thread(move || app.restore_preview(&bytes, passphrase.as_deref(), policy)).await;
    }
    off_ui_thread(move || app.import_preview(&bytes, passphrase.as_deref(), policy)).await
}

#[tauri::command]
pub async fn import_apply(
    st: State<'_, DesktopState>,
    grant: String,
    passphrase: Option<String>,
    conflict_policy: String,
    approval: Option<anvil_app::port::ImportApproval>,
) -> R<anvil_app::port::ImportReport> {
    let app = st.app()?;
    let bytes = read_bundle(&st, &grant)?;
    let policy = policy(&conflict_policy)?;
    // Only the workspaces the user confirmed after the preview's warning,
    // for a full backup as for a bundle.
    let approval = approval.unwrap_or_default();
    if anvil_app::backup::is_backup(&bytes) {
        return off_ui_thread(move || app.restore_approved(&bytes, passphrase.as_deref(), policy, &approval)).await;
    }
    off_ui_thread(move || app.import_approved(&bytes, passphrase.as_deref(), policy, &approval)).await
}

// ------------------------------------------------------------- attachments

/// Store a file the user picked in the native open dialog (purpose
/// `attachment`) as a portable, content-addressed attachment (bounded size).
#[tauri::command]
pub fn attachment_add(st: State<'_, DesktopState>, grant: String, media_type: Option<String>) -> R<anvil_domain::request::AttachmentRef> {
    let app = st.app()?;
    let file = st.file_grants.read(&grant, FilePurpose::Attachment).map_err(|x| x.to_string())?;
    app.put_attachment(&file.file_name, &file.bytes, media_type).map_err(e)
}

/// Read a small file the user picked in the native open dialog: a PEM
/// certificate/key (purpose `pem_file`) or, with `base64`, a PKCS#12
/// keystore (purpose `pkcs12_file`, which must be stored). The content goes
/// straight into the vault when `store_as_secret` is set, so a private key
/// never round-trips through the webview.
#[tauri::command]
pub fn read_text_file(
    st: State<'_, DesktopState>,
    grant: String,
    workspace_id: Option<String>,
    store_as_secret: Option<String>,
    base64: Option<bool>,
) -> R<TextFile> {
    use base64::Engine as _;
    let app = st.app()?;
    let binary = base64.unwrap_or(false);
    if binary && store_as_secret.is_none() {
        return Err("a PKCS#12 keystore is only read into the vault; give it a label".into());
    }
    let purpose = if binary { FilePurpose::Pkcs12File } else { FilePurpose::PemFile };
    let file = st.file_grants.read(&grant, purpose).map_err(|x| x.to_string())?;
    // Binary keystores (PKCS#12) are carried as base64 text in the vault.
    let text = if binary {
        base64::engine::general_purpose::STANDARD.encode(&file.bytes)
    } else {
        String::from_utf8(file.bytes).map_err(|_| "the file is not UTF-8 text".to_string())?
    };
    if let Some(label) = store_as_secret {
        let ws = workspace_id.ok_or_else(|| "a secret must belong to a workspace; open one first".to_string())?;
        let r = app.set_secret(&id(&ws)?, &label, &text).map_err(e)?;
        return Ok(TextFile { text: None, secret: Some(r) });
    }
    Ok(TextFile { text: Some(text), secret: None })
}

#[derive(Serialize)]
pub struct TextFile {
    pub text: Option<String>,
    pub secret: Option<SecretRef>,
}
