//! Target-API OAuth sign-in (system browser + loopback, RFC 8252) and the
//! app-login provider catalogue. Provider identities are never keys.

use crate::commands::{R, SendInput, e, id};
use crate::state::DesktopState;
use anvil_app::exec::SendOptions;
use anvil_identity::{FlowEvent, FlowOptions};
use serde::Serialize;
use tauri::{AppHandle, Emitter, State};
use tokio_util::sync::CancellationToken;

fn opts(input: &SendInput) -> R<SendOptions> {
    Ok(SendOptions { environment: input.environment_id.as_deref().map(id).transpose()?, ..Default::default() })
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
#[tauri::command]
pub async fn oauth_sign_in(
    st: State<'_, DesktopState>,
    handle: AppHandle,
    input: SendInput,
    attempt: String,
) -> R<anvil_identity::api_oauth::ApiAuthorization> {
    let app = st.app()?;
    let ws = id(&input.workspace_id)?;
    let rid = input.request_id.as_deref().map(id).transpose()?;
    let o = opts(&input)?;
    let cancel = CancellationToken::new();
    let key = id(&attempt)?;
    st.running.lock().insert(key, cancel.clone());
    let h2 = handle.clone();
    let a2 = attempt.clone();
    let observer = move |event: FlowEvent| {
        let _ = h2.emit("oauth-flow", SignInEvent { attempt: a2.clone(), event });
    };
    let opener = |url: &str| open_in_browser(url);
    let res = app.oauth_sign_in(rid, &ws, input.spec, &o, &opener, &observer, &FlowOptions::default(), &cancel).await;
    st.running.lock().remove(&key);
    res.map_err(e)
}

#[tauri::command]
pub fn oauth_cancel(st: State<'_, DesktopState>, attempt: String) -> R<bool> {
    Ok(match st.running.lock().get(&id(&attempt)?) {
        Some(t) => {
            t.cancel();
            true
        }
        None => false,
    })
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
