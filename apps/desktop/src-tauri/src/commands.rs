//! IPC commands. Every data command goes through `DesktopState::app()`, which
//! refuses while locked; secrets never cross into the webview except where
//! the user explicitly typed them (they are stored and only references return).

use crate::state::{DesktopState, ImportGate, PendingEntry, cancel_pending};
use anvil_app::cleanup::StorageCleanupRecord;
use anvil_app::exec::{SendOptions, refuse_linked_files};
use anvil_app::file_grants::{FileGrants, FilePurpose};
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
use anvil_storage::{KdfParams, StoreError};
use anvil_transport::recorder::EventCtx;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tauri::{AppHandle, Emitter, Manager, State};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

pub(crate) type R<T> = Result<T, String>;

/// What a command returns when its work was canceled before it wrote anything.
pub(crate) const CANCELED: &str = "CANCELED";

/// What an import or preview returns while an earlier one's worker is still
/// running, including one that was canceled and is still deriving its key.
/// A code, like `LOCKED` and `CANCELED`: the import dialog words it.
pub(crate) const IMPORT_BUSY: &str = "IMPORT_BUSY";

pub(crate) fn e(err: AppError) -> String {
    match err {
        AppError::Locked => "LOCKED".into(),
        AppError::Canceled => CANCELED.into(),
        other => other.to_string(),
    }
}

pub(crate) fn id(s: &str) -> R<Id> {
    s.parse().map_err(|_| format!("invalid id '{s}'"))
}

/// Run a command's work with the desktop state on a blocking worker thread.
/// A synchronous command runs on the UI thread, an async one on an async
/// runtime worker; neither should derive a key (Argon2id) or wait on the
/// store, which another command's long transaction (an import, a folder
/// delete) can hold for a while. A lock or a profile switch that lands while
/// the work runs makes the result `LOCKED`, so nothing the work read from the
/// store reaches the webview after the lock.
pub(crate) async fn blocking<T: Send + 'static>(handle: &AppHandle, f: impl FnOnce(&DesktopState) -> R<T> + Send + 'static) -> R<T> {
    let seen = handle.state::<DesktopState>().epoch();
    blocking_unchecked(handle, move |st| {
        let out = f(st)?;
        if st.epoch() != seen {
            return Err("LOCKED".into());
        }
        Ok(out)
    })
    .await
}

/// [`blocking`] without the check for a lock that landed meanwhile: for
/// profile create and unlock, which check it themselves (see
/// [`DesktopState::set_app_since`]), for work whose result stays the user's
/// to see after a lock, and for writes that return no decrypted or
/// workspace data, so a write committed before the lock is not reported as
/// `LOCKED`. Anything that returns what it read from the store uses
/// [`blocking`].
pub(crate) async fn blocking_unchecked<T: Send + 'static>(
    handle: &AppHandle,
    f: impl FnOnce(&DesktopState) -> R<T> + Send + 'static,
) -> R<T> {
    let handle = handle.clone();
    tauri::async_runtime::spawn_blocking(move || f(&handle.state::<DesktopState>())).await.map_err(|x| x.to_string())?
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

/// The key derivation, and opening and migrating the store, run on a
/// blocking thread (see [`blocking_unchecked`]), as for every command below
/// that derives a key. A lock that lands meanwhile leaves the new profile
/// closed; it is still created, and its recovery key is still returned, since
/// it is shown only here.
#[tauri::command]
pub async fn profile_create(handle: AppHandle, name: String, passphrase: Option<String>, keychain: bool) -> R<Created> {
    // Taken before the key derivation: a lock from now on wins over this.
    let seen = handle.state::<DesktopState>().epoch();
    blocking_unchecked(&handle, move |st| {
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
        if st.set_app_since(app, seen).is_ok() {
            st.touch();
        }
        Ok(Created { profile_id: summary.profile_id, recovery_key: recovery })
    })
    .await
}

#[tauri::command]
pub async fn profile_unlock(handle: AppHandle, profile_id: String, passphrase: Option<String>, recovery_key: Option<String>) -> R<()> {
    // Taken before the key derivation: a lock from now on wins over this
    // unlock (see `DesktopState::set_app_since` and `unlock_since`).
    let seen = handle.state::<DesktopState>().epoch();
    blocking_unchecked(&handle, move |st| {
        let p = st.profiles.find(&profile_id).map_err(e)?;
        let how = match (&passphrase, &recovery_key) {
            (Some(pw), _) => Unlock::Passphrase(pw),
            (None, Some(rk)) => Unlock::RecoveryKey(rk),
            (None, None) => Unlock::Keychain,
        };
        let (header, key) = anvil_app::profiles::ProfileManager::unlock(&p.dir, how).map_err(e)?;
        // Not held across the unlock: a lock waits on no store work of this one.
        let open = st.app.read().clone();
        if let Some(a) = open
            && a.header.profile_id == header.profile_id
        {
            st.unlock_since(&a, key, seen)?;
            st.touch();
            st.flush_pending_reports();
            return Ok(());
        }
        let app = App::open(p.dir, header, key).map_err(e)?;
        st.set_app_since(app, seen)?;
        st.touch();
        st.flush_pending_reports();
        Ok(())
    })
    .await
}

/// Re-wrap the data key under a new passphrase (the app must be unlocked;
/// passphrase profiles only). Its outcome is reported even after a lock that
/// landed meanwhile: it says which passphrase opens the profile now.
#[tauri::command]
pub async fn profile_change_passphrase(handle: AppHandle, new_passphrase: String) -> R<()> {
    blocking_unchecked(&handle, move |st| st.app()?.change_passphrase(&new_passphrase, KdfParams::interactive()).map_err(e)).await
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
/// unlocked). Afterwards the keychain no longer opens it. The outcome is
/// returned even after a lock that landed meanwhile, but the UI has then
/// switched to the lock screen and drops it: the new recovery key is never
/// shown and is lost, which exposes nothing, and the new passphrase still
/// opens the profile.
#[tauri::command]
pub async fn profile_convert_to_passphrase(handle: AppHandle, new_passphrase: String) -> R<Converted> {
    blocking_unchecked(&handle, move |st| {
        let c = st.app()?.convert_to_passphrase(&new_passphrase, KdfParams::interactive()).map_err(e)?;
        Ok(Converted { recovery_key: c.recovery_key.to_string(), keychain_entry_removed: c.keychain_entry_removed })
    })
    .await
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

/// One transaction over the whole workspace, on a blocking thread (see
/// [`blocking_unchecked`]: it returns no data, so a delete committed before a
/// lock is not reported as `LOCKED`).
#[tauri::command]
pub async fn workspace_delete(handle: AppHandle, workspace_id: String) -> R<()> {
    blocking_unchecked(&handle, move |st| st.app()?.delete_workspace(&id(&workspace_id)?).map_err(e)).await
}

/// Whether a bundle import or backup restore sealed the workspace from this
/// device's workload identity (see `anvil_app::device_identity`).
#[tauri::command]
pub fn workspace_device_identity_sealed(st: State<'_, DesktopState>, workspace_id: String) -> R<bool> {
    st.app()?.device_identity_sealed(&id(&workspace_id)?).map_err(e)
}

/// The user's explicit choice on this device to let the workspace's requests
/// use this device's workload identity (JWT-SVID or X.509-SVID) again.
/// Returns whether it was sealed.
#[tauri::command]
pub fn workspace_allow_device_identity(st: State<'_, DesktopState>, workspace_id: String) -> R<bool> {
    st.app()?.allow_device_identity(&id(&workspace_id)?).map_err(e)
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

/// One transaction over the whole subtree, on a blocking thread (see
/// [`blocking_unchecked`], as for `workspace_delete`).
#[tauri::command]
pub async fn folder_delete(handle: AppHandle, folder_id: String) -> R<()> {
    blocking_unchecked(&handle, move |st| st.app()?.delete_folder(&id(&folder_id)?).map_err(e)).await
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

/// API standards change only through their own commands (`cmd_standards`),
/// so a settings dialog opened earlier never undoes them.
#[tauri::command]
pub fn settings_save(st: State<'_, DesktopState>, settings: AppSettings) -> R<()> {
    st.app()?.save_settings_keeping_standards(&settings).map_err(e)
}

/// The last storage cleanup of the open profile (`None` before the first):
/// when it ran, what it removed, and the stored objects that do not decode,
/// which keep every stored file until they are repaired or deleted.
#[tauri::command]
pub fn storage_cleanup_last(st: State<'_, DesktopState>) -> R<Option<StorageCleanupRecord>> {
    st.app()?.last_storage_cleanup().map_err(e)
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
    // Taken before the app is read: a preview built across a lock or a
    // profile switch is not returned (as in `blocking`).
    let seen = st.epoch();
    let app = st.app()?;
    let ws = id(&input.workspace_id)?;
    let rid = input.request_id.as_deref().map(id).transpose()?;
    let env = input.environment_id.as_deref().map(id).transpose()?;
    let opts = SendOptions { environment: env, run_override: input.run_override, send_anyway: input.send_anyway, ..Default::default() };
    let builder = app.clone();
    let ctx = anvil_app::off_runtime(move || builder.build_context(rid, &ws, input.spec, &opts)).await.map_err(e)?;
    let preview = app.engine.preview(&ctx).map_err(|f| format!("{:?}: {}", f.kind, f.message))?;
    if st.epoch() != seen {
        return Err("LOCKED".into());
    }
    Ok(preview)
}

#[tauri::command]
pub async fn send_request(st: State<'_, DesktopState>, handle: AppHandle, input: SendInput, execution_id: String) -> R<ExecutionView> {
    let exec_id = id(&execution_id)?;
    // Registered before the app is read, so a lock from now on either refuses
    // `app()` or cancels this token. Retired when dropped, also if the send
    // fails early or panics.
    let pending = crate::state::PendingEntry::register(&st.running, exec_id)?;
    let app = st.app()?;
    let ws = id(&input.workspace_id)?;
    let rid = input.request_id.as_deref().map(id).transpose()?;
    let env = input.environment_id.as_deref().map(id).transpose()?;
    let h2 = handle.clone();
    let owner = app.clone();
    let last_progress = parking_lot::Mutex::new(std::time::Instant::now());
    let sink: anvil_transport::EventFn = Arc::new(move |ev: ExecutionEvent| {
        // Only to the window of the profile the send started under.
        if !h2.state::<DesktopState>().is_current(&owner) {
            return;
        }
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
    let res = app.send(rid, &ws, input.spec, opts, events, pending.token().clone()).await;
    drop(pending);
    let out = res.map_err(e)?;
    let ct = out.record.response.as_ref().and_then(|r| r.body.content_type.clone());
    let body = body_view(&out.body, out.decoded_body.as_deref(), ct.as_deref());
    Ok(ExecutionView { record: out.record, body })
}

#[tauri::command]
pub fn cancel_execution(st: State<'_, DesktopState>, execution_id: String) -> R<bool> {
    Ok(crate::state::cancel_pending(&st.running, &id(&execution_id)?))
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

/// Decrypts up to 500 records, on a blocking thread (see [`blocking`]).
#[tauri::command]
pub async fn history_list(handle: AppHandle, workspace_id: String, request_id: Option<String>, limit: usize) -> R<Vec<HistoryItem>> {
    blocking(&handle, move |st| {
        let app = st.app()?;
        let ws = id(&workspace_id)?;
        let rid = request_id.as_deref().map(id).transpose()?;
        let mut out = Vec::new();
        for h in app.store.list_history(Some(&ws), rid.as_ref(), limit.min(500)).map_err(|x| x.to_string())? {
            let rec = match app.store.get_history::<ExecutionRecord>(&h.id) {
                Ok(Some((rec, _))) => rec,
                // Locked midway: no partial list.
                Err(StoreError::Locked) => return Err("LOCKED".into()),
                // Removed meanwhile, or unreadable: left out.
                Ok(None) | Err(_) => continue,
            };
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
        Ok(out)
    })
    .await
}

#[tauri::command]
pub async fn history_get(handle: AppHandle, history_id: String) -> R<ExecutionView> {
    blocking(&handle, move |st| {
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
    })
    .await
}

/// On a blocking thread (see [`blocking_unchecked`], as for
/// `workspace_delete`).
#[tauri::command]
pub async fn history_clear(handle: AppHandle, workspace_id: Option<String>) -> R<()> {
    let ws = workspace_id.map(|w| id(&w)).transpose()?;
    blocking_unchecked(&handle, move |st| st.app()?.store.clear_history(ws.as_ref()).map_err(|x| x.to_string())).await
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

/// Reads every exported item, on a blocking thread (see [`blocking`]).
#[tauri::command]
pub async fn export_preview(
    handle: AppHandle,
    workspace_id: Option<String>,
    export_mode: String,
    include_standards: bool,
) -> R<ExportPreview> {
    let ws = workspace_id.map(|w| id(&w)).transpose()?;
    let m = mode(&export_mode)?;
    blocking(&handle, move |st| {
        let app = st.app()?;
        if full_backup(ws.as_ref(), m)? {
            return app.backup_preview().map(ExportPreview::Backup).map_err(e);
        }
        app.export_preview_with_standards(ws.as_ref(), m, false, include_standards).map(ExportPreview::Bundle).map_err(e)
    })
    .await
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
    include_standards: bool,
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
        off_ui_thread(move || app.export_with_standards(ws.as_ref(), m, passphrase.as_deref(), false, include_standards)).await?.0
    };
    st.file_grants.write(&grant, FilePurpose::BundleExport, &bytes).map_err(|x| x.to_string())
}

/// The bundle the user picked in the native open dialog (purpose
/// `bundle_import`).
fn read_bundle(grants: &FileGrants, grant: &str) -> R<Vec<u8>> {
    Ok(grants.read(grant, FilePurpose::BundleImport).map_err(|x| x.to_string())?.bytes)
}

/// Register `attempt` so `import_cancel`, or a lock, can reach the import.
/// Done before the app is read (see `DesktopState::lock`).
fn register_import(st: &DesktopState, attempt: Option<&str>) -> R<Option<PendingEntry>> {
    attempt.map(|a| PendingEntry::register(&st.imports, id(a)?)).transpose()
}

/// Claim the one import worker (`DesktopState::import_worker`). Refused with
/// [`IMPORT_BUSY`] while another import's worker, canceled or not, runs.
fn claim_import_worker(slot: &Arc<Semaphore>) -> R<OwnedSemaphorePermit> {
    slot.clone().try_acquire_owned().map_err(|_| IMPORT_BUSY.to_string())
}

/// Run import work on a blocking worker thread: reading the chosen file and
/// deriving an encrypted bundle's or backup's vault key (Argon2id, within
/// the header bounds) must not stall the async runtime.
///
/// The derivation cannot be interrupted, so a cancel of `pending` abandons
/// the worker instead: the command returns `CANCELED` at once, and the
/// worker drops the key and the contents when the derivation ends. For an
/// apply, `gate` settles the race with the writes: a cancel that finds them
/// begun waits for their result instead. The worker holds `worker` until it
/// has ended, also once abandoned, so abandoned workers never pile up.
///
/// The key a preview derives is not kept for the apply that follows. The
/// user can leave the preview open for any length of time, and holding the
/// key would keep material that opens the bundle in memory for all of it;
/// the apply derives it again, bounded by the same header limits.
async fn import_work<T: Send + 'static>(
    worker: OwnedSemaphorePermit,
    pending: Option<PendingEntry>,
    gate: Option<&ImportGate>,
    f: impl FnOnce() -> R<T> + Send + 'static,
) -> R<T> {
    let mut work = std::pin::pin!(tauri::async_runtime::spawn_blocking(move || {
        let r = f();
        drop(worker);
        r
    }));
    if let Some(pending) = &pending {
        tokio::select! {
            r = &mut work => return r.map_err(|x| x.to_string())?,
            _ = pending.token().cancelled() => {
                if gate.is_none_or(ImportGate::abandon) {
                    return Err(CANCELED.into());
                }
            }
        }
    }
    work.await.map_err(|x| x.to_string())?
}

/// Import `bytes` as a bundle, or restore it when it is a full backup.
/// `proceed` is asked once the file is open (its key derived and its
/// contents checked) and before anything is written; `false` ends the
/// import with `CANCELED`, and nothing is written (see
/// [`App::import_approved_if`] and [`App::restore_approved_if`]).
fn apply(
    app: &App,
    bytes: &[u8],
    passphrase: Option<&str>,
    policy: ConflictPolicy,
    approval: &anvil_app::port::ImportApproval,
    proceed: &dyn Fn() -> bool,
) -> R<anvil_app::port::ImportReport> {
    if anvil_app::backup::is_backup(bytes) {
        return app.restore_approved_if(bytes, passphrase, policy, approval, proceed).map_err(e);
    }
    app.import_approved_if(bytes, passphrase, policy, approval, proceed).map_err(e)
}

/// Whether an import's writes may begin, and if so claim them (see
/// [`ImportGate`]): not once the import was abandoned, nor once a lock or a
/// profile switch has landed since the epoch `seen` was taken, even if the
/// profile was unlocked again meanwhile.
fn writes_may_begin(st: &DesktopState, seen: u64, gate: &ImportGate) -> bool {
    st.epoch() == seen && gate.begin_writes()
}

fn import_result_error(st: &DesktopState, seen: u64, error: String) -> String {
    if error == CANCELED && st.epoch() != seen { "LOCKED".into() } else { error }
}

/// A full backup is restored; anything else is imported as a bundle. With
/// an `attempt` id, `import_cancel` (or a lock) ends the preview at once. A
/// preview that a lock or a profile switch overlaps returns `LOCKED`: it
/// reports what it read from the store.
#[tauri::command]
pub async fn import_preview(
    st: State<'_, DesktopState>,
    grant: String,
    passphrase: Option<String>,
    conflict_policy: String,
    attempt: Option<String>,
) -> R<anvil_app::port::ImportReport> {
    let worker = claim_import_worker(&st.import_worker)?;
    let pending = register_import(&st, attempt.as_deref())?;
    let seen = st.epoch();
    let app = st.app()?;
    let policy = policy(&conflict_policy)?;
    let grants = st.file_grants.clone();
    // A preview writes nothing, so it needs no gate.
    let report = import_work(worker, pending, None, move || {
        let bytes = read_bundle(&grants, &grant)?;
        if anvil_app::backup::is_backup(&bytes) {
            // A full backup restores every item under its own id, so "copies" is
            // previewed as Merge; the report's policy tells the dialog to switch.
            let policy = if policy == ConflictPolicy::Duplicate { ConflictPolicy::Merge } else { policy };
            return app.restore_preview(&bytes, passphrase.as_deref(), policy).map_err(e);
        }
        app.import_preview(&bytes, passphrase.as_deref(), policy).map_err(e)
    })
    .await
    .map_err(|error| import_result_error(&st, seen, error))?;
    if st.epoch() != seen {
        return Err("LOCKED".into());
    }
    Ok(report)
}

/// With an `attempt` id, `import_cancel` (or a lock) ends the import at once
/// unless it has begun writing; a canceled import writes nothing. A bundle
/// import, and a full-backup restore, can be canceled until its key is
/// derived and its contents checked. A lock or a profile switch that lands
/// before then also ends it without writing, with or without an `attempt` id.
#[tauri::command]
pub async fn import_apply(
    handle: AppHandle,
    st: State<'_, DesktopState>,
    grant: String,
    passphrase: Option<String>,
    conflict_policy: String,
    approval: Option<anvil_app::port::ImportApproval>,
    attempt: Option<String>,
) -> R<anvil_app::port::ImportReport> {
    let worker = claim_import_worker(&st.import_worker)?;
    let pending = register_import(&st, attempt.as_deref())?;
    // Taken before the app is read: a lock from now on ends the import
    // before it writes (see `writes_may_begin`).
    let seen = st.epoch();
    let app = st.app()?;
    let policy = policy(&conflict_policy)?;
    // Only the workspaces the user confirmed after the preview's warning,
    // for a full backup as for a bundle.
    let approval = approval.unwrap_or_default();
    let grants = st.file_grants.clone();
    let gate = Arc::new(ImportGate::default());
    let worker_gate = gate.clone();
    import_work(worker, pending, Some(&*gate), move || {
        let bytes = read_bundle(&grants, &grant)?;
        let proceed = || writes_may_begin(&handle.state::<DesktopState>(), seen, &worker_gate);
        apply(&app, &bytes, passphrase.as_deref(), policy, &approval, &proceed)
    })
    .await
    .map_err(|error| import_result_error(&st, seen, error))
}

/// Cancel the bundle import, backup restore or preview started with
/// `attempt`; never an execution or a sign-in. Returns whether it was still
/// running; the import itself reports whether it was canceled or had already
/// begun writing.
#[tauri::command]
pub fn import_cancel(st: State<'_, DesktopState>, attempt: String) -> R<bool> {
    Ok(cancel_pending(&st.imports, &id(&attempt)?))
}

// ------------------------------------------------------------- attachments

/// Store a file the user picked in the native open dialog (purpose
/// `attachment`) as a portable, content-addressed attachment (bounded size).
/// Read and stored on a blocking thread (see [`blocking_unchecked`]: it
/// returns only a reference, so a stored attachment is not reported as
/// `LOCKED` after a lock).
#[tauri::command]
pub async fn attachment_add(handle: AppHandle, grant: String, media_type: Option<String>) -> R<anvil_domain::request::AttachmentRef> {
    blocking_unchecked(&handle, move |st| {
        let app = st.app()?;
        let file = st.file_grants.read(&grant, FilePurpose::Attachment).map_err(|x| x.to_string())?;
        app.put_attachment(&file.file_name, &file.bytes, media_type).map_err(e)
    })
    .await
}

/// Read a small file the user picked in the native open dialog: a PEM
/// certificate/key (purpose `pem_file`) or, with `base64`, a PKCS#12
/// keystore (purpose `pkcs12_file`, which must be stored). The content goes
/// straight into the vault when `store_as_secret` is set, so a private key
/// never round-trips through the webview. Read and stored on a blocking
/// thread (see [`blocking`]).
#[tauri::command]
pub async fn read_text_file(
    handle: AppHandle,
    grant: String,
    workspace_id: Option<String>,
    store_as_secret: Option<String>,
    base64: Option<bool>,
) -> R<TextFile> {
    use base64::Engine as _;
    blocking(&handle, move |st| {
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
    })
    .await
}

#[derive(Serialize)]
pub struct TextFile {
    pub text: Option<String>,
    pub secret: Option<SecretRef>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::Running;
    use crate::state::tests::{PASSPHRASE, TempRoot, create};
    use std::sync::mpsc;
    use tokio::sync::oneshot;

    /// A registered attempt, and the gate of its writes.
    fn registered() -> (Arc<Running>, Id, PendingEntry, Arc<ImportGate>) {
        let imports = Arc::new(Running::default());
        let id = Id::new();
        let pending = PendingEntry::register(&imports, id).unwrap();
        (imports, id, pending, Arc::new(ImportGate::default()))
    }

    #[tokio::test]
    async fn a_cancel_before_the_writes_begin_abandons_the_import() {
        let slot = Arc::new(Semaphore::new(1));
        let (imports, attempt, pending, gate) = registered();
        let (started_tx, started_rx) = oneshot::channel();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let (wrote_tx, wrote_rx) = oneshot::channel();
        let worker_gate = gate.clone();
        let worker = claim_import_worker(&slot).unwrap();
        // Stands in for the key derivation: blocks until released, then claims the writes.
        let work = import_work(worker, Some(pending), Some(&*gate), move || {
            started_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            let wrote = worker_gate.begin_writes();
            wrote_tx.send(wrote).unwrap();
            if wrote { Ok("written") } else { Err(CANCELED.to_string()) }
        });
        let cancel = async {
            started_rx.await.unwrap();
            assert!(cancel_pending(&imports, &attempt));
        };
        let (r, ()) = tokio::join!(work, cancel);
        assert_eq!(r, Err(CANCELED.to_string()));
        assert!(imports.lock().is_empty());
        // The abandoned worker still runs, so another import is refused.
        assert_eq!(claim_import_worker(&slot).map(|_| ()), Err(IMPORT_BUSY.to_string()));
        release_tx.send(()).unwrap();
        assert!(!wrote_rx.await.unwrap(), "an abandoned import never begins its writes");
        // Once the worker has ended, the next import can start.
        drop(slot.acquire().await.unwrap());
        assert!(claim_import_worker(&slot).is_ok());
    }

    #[tokio::test]
    async fn a_cancel_after_the_writes_begin_waits_for_the_import() {
        let slot = Arc::new(Semaphore::new(1));
        let (imports, attempt, pending, gate) = registered();
        let (writing_tx, writing_rx) = oneshot::channel();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let worker_gate = gate.clone();
        let worker = claim_import_worker(&slot).unwrap();
        let work = import_work(worker, Some(pending), Some(&*gate), move || {
            assert!(worker_gate.begin_writes());
            writing_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            Ok("written")
        });
        let cancel = async {
            writing_rx.await.unwrap();
            assert!(cancel_pending(&imports, &attempt));
            release_tx.send(()).unwrap();
        };
        let (r, ()) = tokio::join!(work, cancel);
        assert_eq!(r, Ok("written"), "an import whose writes began reports their result");
        assert!(!gate.abandon());
        assert!(imports.lock().is_empty());
        // The worker released its slot before its result was returned.
        assert!(claim_import_worker(&slot).is_ok());
    }

    #[tokio::test]
    async fn an_import_that_is_not_canceled_completes() {
        let slot = Arc::new(Semaphore::new(1));
        let (imports, _, pending, gate) = registered();
        let worker_gate = gate.clone();
        let worker = claim_import_worker(&slot).unwrap();
        let r = import_work(worker, Some(pending), Some(&*gate), move || Ok(worker_gate.begin_writes())).await;
        assert_eq!(r, Ok(true), "the import claimed its writes");
        assert!(!gate.abandon());
        assert!(imports.lock().is_empty());
        assert!(claim_import_worker(&slot).is_ok());
    }

    const BACKUP_PASS: &str = "backup passphrase 1";

    /// A desktop state whose open profile is empty, and a full backup of
    /// another profile that holds one workspace.
    fn with_backup() -> (TempRoot, Arc<DesktopState>, Vec<u8>) {
        let root = TempRoot::new();
        let st = Arc::new(DesktopState::new(root.0.clone()));
        let (source, _) = create(&st, "source");
        source.create_workspace("W").unwrap();
        let bytes = source.export_backup_with(BACKUP_PASS, KdfParams::testing()).unwrap().0;
        let (target, _) = create(&st, "target");
        st.set_app_since(target, st.epoch()).unwrap();
        (root, st, bytes)
    }

    /// Nothing was restored into `app`, not even a checkpoint.
    fn assert_untouched(app: &App) {
        assert!(app.workspaces().unwrap().is_empty());
        assert!(!app.dir.join("checkpoints").exists(), "no checkpoint was taken");
    }

    #[tokio::test]
    async fn a_restore_canceled_before_its_writes_begin_writes_nothing() {
        let (_root, st, bytes) = with_backup();
        let slot = Arc::new(Semaphore::new(1));
        let attempt = Id::new();
        let pending = PendingEntry::register(&st.imports, attempt).unwrap();
        let gate = Arc::new(ImportGate::default());
        let seen = st.epoch();
        let app = st.app().unwrap();
        let (opened_tx, mut opened_rx) = tokio::sync::mpsc::unbounded_channel();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let (done_tx, done_rx) = oneshot::channel();
        let (worker_st, worker_gate, worker_app) = (st.clone(), gate.clone(), app.clone());
        let worker = claim_import_worker(&slot).unwrap();
        let work = import_work(worker, Some(pending), Some(&*gate), move || {
            // Asked once the backup is open; waiting here stands in for a
            // longer key derivation.
            let proceed = || {
                opened_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                writes_may_begin(&worker_st, seen, &worker_gate)
            };
            let r = apply(&worker_app, &bytes, Some(BACKUP_PASS), ConflictPolicy::Merge, &Default::default(), &proceed);
            done_tx.send(r.as_ref().map(|_| ()).map_err(String::clone)).unwrap();
            r
        });
        let cancel = async {
            opened_rx.recv().await.unwrap();
            assert!(cancel_pending(&st.imports, &attempt));
        };
        let (r, ()) = tokio::join!(work, cancel);
        assert_eq!(r.map(|_| ()), Err(CANCELED.to_string()));
        release_tx.send(()).unwrap();
        assert_eq!(done_rx.await.unwrap(), Err(CANCELED.to_string()), "an abandoned restore never begins its writes");
        assert_untouched(&app);
        assert!(st.imports.lock().is_empty());
    }

    #[tokio::test]
    async fn a_restore_canceled_after_its_writes_begin_is_written() {
        let (_root, st, bytes) = with_backup();
        let slot = Arc::new(Semaphore::new(1));
        let attempt = Id::new();
        let pending = PendingEntry::register(&st.imports, attempt).unwrap();
        let gate = Arc::new(ImportGate::default());
        let seen = st.epoch();
        let app = st.app().unwrap();
        let (writing_tx, mut writing_rx) = tokio::sync::mpsc::unbounded_channel();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let (worker_st, worker_gate, worker_app) = (st.clone(), gate.clone(), app.clone());
        let worker = claim_import_worker(&slot).unwrap();
        let work = import_work(worker, Some(pending), Some(&*gate), move || {
            let proceed = || {
                let claimed = writes_may_begin(&worker_st, seen, &worker_gate);
                writing_tx.send(claimed).unwrap();
                release_rx.recv().unwrap();
                claimed
            };
            apply(&worker_app, &bytes, Some(BACKUP_PASS), ConflictPolicy::Merge, &Default::default(), &proceed)
        });
        let cancel = async {
            assert!(writing_rx.recv().await.unwrap(), "the writes were claimed");
            assert!(cancel_pending(&st.imports, &attempt));
            release_tx.send(()).unwrap();
        };
        let (r, ()) = tokio::join!(work, cancel);
        let report = r.expect("a restore whose writes began reports their result");
        assert_eq!(report.workspace_ids.len(), 1);
        assert_eq!(app.workspaces().unwrap().len(), 1);
        assert!(report.checkpoint.is_some());
        assert!(st.imports.lock().is_empty());
    }

    #[tokio::test]
    async fn a_lock_during_a_restores_key_derivation_ends_it_even_once_unlocked_again() {
        let (_root, st, bytes) = with_backup();
        let gate = ImportGate::default();
        // No attempt id: the lock is seen through the epoch alone.
        let seen = st.epoch();
        let app = st.app().unwrap();
        let proceed = || {
            // A lock, and an unlock of the same profile, land while the key is derived.
            st.lock();
            let (_, key) = anvil_app::profiles::ProfileManager::unlock(&app.dir, Unlock::Passphrase(PASSPHRASE)).unwrap();
            st.unlock_since(&app, key, st.epoch()).unwrap();
            writes_may_begin(&st, seen, &gate)
        };
        let r = apply(&app, &bytes, Some(BACKUP_PASS), ConflictPolicy::Merge, &Default::default(), &proceed);
        let result = r.map(|_| ()).map_err(|error| import_result_error(&st, seen, error));
        assert_eq!(result, Err("LOCKED".into()));
        assert!(st.app().is_ok(), "the profile is unlocked again");
        assert_untouched(&app);
        assert!(gate.abandon(), "the writes were never claimed");
    }
}
