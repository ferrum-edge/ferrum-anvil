//! Target-API OAuth sign-in (system browser + loopback, RFC 8252) and the
//! app-login provider catalogue. Provider identities are never keys.

use crate::commands::{CANCELED, R, SendInput, e, id};
use crate::presence::NativePresence;
use crate::state::{DesktopState, PendingEntry, cancel_pending};
use anvil_identity::{FlowEvent, FlowOptions};
use serde::Serialize;
use tauri::{AppHandle, Emitter, State, Window};

fn opts(input: &SendInput) -> R<anvil_app::exec::SendOptions> {
    input.options(false)
}

/// Only http(s) URLs are handed to the OS opener.
fn open_in_browser(url: &str) -> Result<(), String> {
    let parsed = url::Url::parse(url).map_err(|x| x.to_string())?;
    if !matches!(parsed.scheme(), "https" | "http") {
        return Err(format!("refusing to open a {} URL", parsed.scheme()));
    }
    tauri_plugin_opener::open_url(url, None::<&str>).map_err(|x| x.to_string())
}

#[derive(Serialize, Clone)]
pub struct SignInEvent {
    pub attempt: String,
    pub event: FlowEvent,
}

/// Run the sign-in for the OAuth profile the request uses. Progress is
/// emitted as `oauth-flow` events; the token itself never leaves the backend.
/// A draft in `input` uses the workspace's vault only where its saved
/// request would, or once the user confirmed it natively (see
/// `crate::draft_authority`).
#[tauri::command]
pub async fn oauth_sign_in(
    st: State<'_, DesktopState>,
    handle: AppHandle,
    window: Window,
    input: SendInput,
    attempt: String,
) -> R<anvil_identity::api_oauth::ApiAuthorization> {
    // Registered before the app is read (see `DesktopState::lock`); retired
    // when dropped, on every path. Apart from executions, so `oauth_cancel`
    // never cancels an execution, nor `cancel_execution` a sign-in.
    let pending = PendingEntry::register(&st.sign_ins, id(&attempt)?)?;
    let app = st.app()?;
    let ws = id(&input.workspace_id)?;
    let rid = input.request_id.as_deref().map(id).transpose()?;
    let o = opts(&input)?;
    // Built once: the sign-in runs exactly the context a draft was
    // authorized with, never one built again after the dialog.
    let draft = input.spec.is_some();
    let ctx = app.build_context_off_runtime(rid, ws, input.spec, o.clone(), pending.token()).await.map_err(e)?;
    if draft {
        crate::draft_authority::authorize(&st, &NativePresence(window), &app, rid, ws, &ctx, &o).await?;
        if pending.token().is_cancelled() {
            return Err(CANCELED.into());
        }
    }
    let h2 = handle.clone();
    let a2 = attempt.clone();
    let observer = move |event: FlowEvent| {
        let _ = h2.emit("oauth-flow", SignInEvent { attempt: a2.clone(), event });
    };
    let opener = |url: &str| open_in_browser(url);
    st.check_context_authority(&app, ctx.secrets.as_ref())?;
    let res = app.oauth_sign_in_with(&ctx, &opener, &observer, &FlowOptions::default(), pending.token()).await;
    drop(pending);
    res.map_err(e)
}

/// Cancel the sign-in started with `attempt`; never an execution or an
/// import. Returns whether it was still running.
#[tauri::command]
pub fn oauth_cancel(st: State<'_, DesktopState>, attempt: String) -> R<bool> {
    Ok(cancel_pending(&st.sign_ins, &id(&attempt)?))
}

#[tauri::command]
pub fn oauth_token_status(st: State<'_, DesktopState>, input: SendInput) -> R<Option<anvil_engine::oauth_http::TokenSummary>> {
    let app = st.app()?;
    let o = opts(&input)?;
    app.oauth_token_status(input.request_id.as_deref().map(id).transpose()?, &id(&input.workspace_id)?, input.spec, &o).map_err(e)
}

#[tauri::command]
pub fn oauth_sign_out(st: State<'_, DesktopState>, input: SendInput) -> R<bool> {
    let app = st.app()?;
    let o = opts(&input)?;
    app.oauth_sign_out(input.request_id.as_deref().map(id).transpose()?, &id(&input.workspace_id)?, input.spec, &o).map_err(e)
}

/// App-login providers and their availability in this build (Google,
/// GitHub, Facebook stay unavailable until the owner registers them).
#[tauri::command]
pub fn login_providers() -> Vec<anvil_identity::ProviderInfo> {
    anvil_app::identity::login_providers()
}
