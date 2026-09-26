//! Interactive sessions (WebSocket, TCP/TLS, UDP/DTLS, streaming gRPC, SSE).
//! Messages stream to the webview as `execution-event`s; when the session
//! ends its record is stored in history like any other execution.

use crate::commands::{ExecutionView, R, SendInput, body_view, e, id};
use crate::state::DesktopState;
use anvil_app::exec::SendOptions;
use anvil_domain::events::{ExecutionEvent, SessionCommand};
use anvil_engine::sessions::SessionHandle;
use anvil_transport::recorder::EventCtx;
use serde::Serialize;
use std::sync::Arc;
use std::time::Duration;
use tauri::{AppHandle, Emitter, Manager, State};
use tokio_util::sync::CancellationToken;

pub type SessionSlot = Arc<tokio::sync::Mutex<Option<SessionHandle>>>;

#[derive(Serialize, Clone)]
pub struct SessionEnded {
    pub execution_id: String,
    pub view: Option<ExecutionView>,
    pub error: Option<String>,
}

/// Open a session. Returns the execution id used by message events.
#[tauri::command]
pub async fn session_open(st: State<'_, DesktopState>, handle: AppHandle, input: SendInput, execution_id: String) -> R<String> {
    let app = st.app()?;
    let exec_id = id(&execution_id)?;
    let ws = id(&input.workspace_id)?;
    let rid = input.request_id.as_deref().map(id).transpose()?;
    let env = input.environment_id.as_deref().map(id).transpose()?;
    let opts = SendOptions {
        environment: env,
        run_override: input.run_override,
        send_anyway: input.send_anyway,
        record_history: true,
        ..Default::default()
    };
    let ctx = app.build_context(rid, &ws, input.spec, &opts).map_err(e)?;
    let h2 = handle.clone();
    let sink: anvil_transport::EventFn = Arc::new(move |ev: ExecutionEvent| {
        let _ = h2.emit("execution-event", &ev);
    });
    // Registered before connecting, so `session_cancel` (and locking) can stop an
    // open that has not finished yet: the tab that started it may already be gone.
    let pending = CancellationToken::new();
    st.running.lock().insert(exec_id, pending.clone());
    let opened = tokio::select! {
        s = app.engine.open_session(ctx, EventCtx { execution_id: exec_id, sink: Some(sink) }) => Some(s),
        _ = pending.cancelled() => None,
    };
    let Some(session) = opened else {
        st.running.lock().remove(&exec_id);
        return Err("the session was canceled before it opened".into());
    };
    let slot: SessionSlot = Arc::new(tokio::sync::Mutex::new(Some(session)));
    // Publish the session before retiring the pending token: a concurrent cancel
    // always finds one of the two.
    st.sessions.lock().insert(execution_id.clone(), slot.clone());
    st.running.lock().remove(&exec_id);
    if pending.is_cancelled()
        && let Some(s) = slot.lock().await.as_ref()
    {
        s.cancel();
    }
    // Watch for the end (peer close, local close, cancel, lock) and publish the record.
    let key = execution_id.clone();
    tauri::async_runtime::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_millis(150)).await;
            let finished = match slot.lock().await.as_ref() {
                Some(s) => s.is_finished(),
                None => true,
            };
            if finished {
                break;
            }
        }
        let taken = slot.lock().await.take();
        let st = handle.state::<DesktopState>();
        st.sessions.lock().remove(&key);
        let ev = match taken {
            Some(s) => {
                let out = s.finish().await;
                let recorded = st.app().and_then(|a| a.record(&out).map_err(e));
                let ct = out.record.response.as_ref().and_then(|r| r.body.content_type.clone());
                let view = ExecutionView { body: body_view(&out.body, out.decoded_body.as_deref(), ct.as_deref()), record: out.record };
                SessionEnded { execution_id: key.clone(), view: Some(view), error: recorded.err() }
            }
            None => SessionEnded { execution_id: key.clone(), view: None, error: Some("the session was already finished".into()) },
        };
        let _ = handle.emit("session-ended", ev);
    });
    Ok(execution_id)
}

async fn with_session<F>(st: &DesktopState, execution_id: &str, f: F) -> R<()>
where
    F: for<'a> FnOnce(&'a SessionHandle) -> std::pin::Pin<Box<dyn std::future::Future<Output = R<()>> + Send + 'a>>,
{
    st.app()?;
    let slot = st.sessions.lock().get(execution_id).cloned().ok_or_else(|| "the session is no longer open".to_string())?;
    let guard = slot.lock().await;
    match guard.as_ref() {
        Some(s) => f(s).await,
        None => Err("the session is no longer open".into()),
    }
}

#[tauri::command]
pub async fn session_send(st: State<'_, DesktopState>, execution_id: String, command: SessionCommand) -> R<()> {
    with_session(&st, &execution_id, |s| Box::pin(async move { s.send(command).await.map_err(|x| x.to_string()) })).await
}

/// Abort without a graceful close handshake. An open still connecting is
/// abandoned: `session_open` then fails and no session is left behind.
#[tauri::command]
pub async fn session_cancel(st: State<'_, DesktopState>, execution_id: String) -> R<()> {
    // Checked before the open sessions: an open moves from one to the other.
    let exec_id = id(&execution_id)?;
    if let Some(pending) = st.running.lock().get(&exec_id) {
        pending.cancel();
        return Ok(());
    }
    with_session(&st, &execution_id, |s| {
        Box::pin(async move {
            s.cancel();
            Ok(())
        })
    })
    .await
}
