//! Interactive sessions (WebSocket, TCP/TLS, UDP/DTLS, streaming gRPC, SSE).
//! Messages stream to the webview as `execution-event`s; when the session
//! ends its record is stored in history like any other execution.

use crate::commands::{ExecutionView, R, SendInput, body_view, e, id};
use crate::state::{DesktopState, PendingEntry, cancel_pending};
use anvil_app::AppError;
use anvil_app::exec::SendOptions;
use anvil_domain::events::{ExecutionEvent, SessionCommand};
use anvil_engine::sessions::SessionHandle;
use anvil_transport::recorder::EventCtx;
use serde::Serialize;
use std::sync::Arc;
use std::time::Duration;
use tauri::{AppHandle, Emitter, Manager};

pub type SessionSlot = Arc<OpenSession>;

pub struct OpenSession {
    pub session: tokio::sync::Mutex<Option<SessionHandle>>,
    /// Interrupts a send waiting on the bounded command queue BEFORE any
    /// canceler tries to take `session`. It cannot be trapped by that wait.
    pub cancel: tokio_util::sync::CancellationToken,
}

impl OpenSession {
    pub async fn abort(&self) {
        self.cancel.cancel();
        if let Some(session) = self.session.lock().await.as_ref() {
            session.cancel();
        }
    }
}

const CANCELED_BEFORE_OPEN: &str = "the session was canceled before it opened";

#[derive(Serialize, Clone)]
pub struct SessionEnded {
    pub execution_id: String,
    pub view: Option<ExecutionView>,
    pub error: Option<String>,
}

/// Open a session. Returns the execution id used by message events.
pub(crate) async fn session_open(
    handle: AppHandle,
    fence: crate::state::PayloadFence,
    input: SendInput,
    execution_id: String,
) -> R<String> {
    let st = handle.state::<DesktopState>();
    let exec_id = id(&execution_id)?;
    // Registered first, so `session_cancel` (and locking) can stop an open that
    // has not finished yet: the tab that started it may already be gone. Every
    // early return below retires it.
    let pending = PendingEntry::register(&st.running, exec_id)?;
    // A session already open under this id is not replaced. Checked after
    // registering: only a registered open publishes a session, so none can
    // appear under this id before this one does.
    if st.sessions.lock().contains_key(&execution_id) {
        return Err(format!("attempt {execution_id} is already running"));
    }
    st.check_payload(&fence)?;
    let app = fence.app.clone();
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
    // Built on a blocking thread; a cancel meanwhile ends the open at once.
    let ctx = match app.build_context_off_runtime(rid, ws, input.spec, opts, pending.token()).await {
        Err(AppError::Canceled) => return Err(CANCELED_BEFORE_OPEN.into()),
        built => built.map_err(e)?,
    };
    let h2 = handle.clone();
    let owner = fence.clone();
    let sink: anvil_transport::EventFn = Arc::new(move |ev: ExecutionEvent| {
        let _ = h2.state::<DesktopState>().try_deliver_payload(&owner, || {
            let _ = h2.emit("execution-event", &ev);
        });
    });
    let open = app.engine.open_session(ctx, EventCtx { execution_id: exec_id, sink: Some(sink) });
    let publish = |session| {
        let slot = Arc::new(OpenSession {
            session: tokio::sync::Mutex::new(Some(session)),
            cancel: tokio_util::sync::CancellationToken::new(),
        });
        st.sessions.lock().insert(execution_id.clone(), (fence.clone(), slot.clone()));
        slot
    };
    let Some((slot, canceled)) = pending.open(open, publish).await else {
        return Err(CANCELED_BEFORE_OPEN.into());
    };
    if canceled {
        slot.abort().await;
    }
    // Watch for the end (peer close, local close, cancel, lock, another
    // profile opening) and publish the record.
    let key = execution_id.clone();
    let watch_handle = handle.clone();
    tauri::async_runtime::spawn(async move {
        let handle = watch_handle;
        loop {
            tokio::time::sleep(Duration::from_millis(150)).await;
            let finished = match slot.session.lock().await.as_ref() {
                Some(s) => s.is_finished(),
                None => true,
            };
            if finished {
                break;
            }
        }
        let taken = slot.session.lock().await.take();
        let st = handle.state::<DesktopState>();
        st.sessions.lock().remove(&key);
        let ev = match taken {
            Some(s) => {
                let out = s.finish().await;
                // Into the profile the session was opened under, never the
                // one open now; refused while that profile is locked.
                let (out, recorded) = app.record_off_runtime(out).await;
                let recorded = recorded.map_err(e);
                let ct = out.record.response.as_ref().and_then(|r| r.body.content_type.clone());
                let body = body_view(&out.body, out.decoded_body.as_deref(), ct.as_deref());
                let view = ExecutionView { body, record: out.record };
                SessionEnded { execution_id: key.clone(), view: Some(view), error: recorded.err() }
            }
            None => SessionEnded { execution_id: key.clone(), view: None, error: Some("the session was already finished".into()) },
        };
        // History finalization stays outside the delivery gate. Both the
        // view and any payload-bearing recording error are dropped together.
        tauri::async_runtime::spawn_blocking(move || {
            let st = handle.state::<DesktopState>();
            emit_ended(st.inner(), &fence, ev, |ev| {
                let _ = handle.emit("session-ended", ev);
            });
        });
    });
    Ok(execution_id)
}

/// A refused final payload still retires the UI's session with scalar status.
fn emit_ended(
    st: &DesktopState,
    fence: &crate::state::PayloadFence,
    ev: SessionEnded,
    emit: impl Fn(SessionEnded),
) {
    let execution_id = ev.execution_id.clone();
    if st.deliver_payload(fence, || emit(ev)).is_err() {
        emit(SessionEnded {
            execution_id,
            view: None,
            error: Some("LOCKED".into()),
        });
    }
}

async fn with_session<F>(st: &DesktopState, execution_id: &str, f: F) -> R<()>
where
    F: for<'a> FnOnce(&'a SessionHandle) -> std::pin::Pin<Box<dyn std::future::Future<Output = R<()>> + Send + 'a>>,
{
    st.app()?;
    let closed = || "the session is no longer open".to_string();
    let (owner, slot) = st.sessions.lock().get(execution_id).cloned().ok_or_else(closed)?;
    // A session of a profile that is no longer open is not driven from another.
    st.check_payload(&owner).map_err(|_| closed())?;
    let guard = until_canceled(&slot.cancel, slot.session.lock()).await?;
    match guard.as_ref() {
        Some(s) => until_canceled(&slot.cancel, f(s)).await?,
        None => Err(closed()),
    }
}

async fn until_canceled<T>(
    cancel: &tokio_util::sync::CancellationToken,
    work: impl Future<Output = T>,
) -> R<T> {
    tokio::select! {
        biased;
        () = cancel.cancelled() => Err(crate::commands::CANCELED.into()),
        out = work => Ok(out),
    }
}

pub(crate) async fn session_send(
    st: &DesktopState,
    execution_id: String,
    command: SessionCommand,
) -> R<()> {
    with_session(st, &execution_id, |s| {
        Box::pin(async move { s.send(command).await.map_err(|x| x.to_string()) })
    })
    .await
}

/// Abort without a graceful close handshake. An open still connecting is
/// abandoned: `session_open` then fails and no session is left behind.
pub(crate) async fn session_cancel(st: &DesktopState, execution_id: String) -> R<()> {
    // Checked before the open sessions: an open moves from one to the other.
    if cancel_pending(&st.running, &id(&execution_id)?) {
        return Ok(());
    }
    let closed = || "the session is no longer open".to_string();
    let (owner, slot) = st.sessions.lock().get(&execution_id).cloned().ok_or_else(closed)?;
    st.check_payload(&owner).map_err(|_| closed())?;
    slot.abort().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::tests::payload_view;
    use crate::state::tests::{PASSPHRASE, TempRoot, create};
    use anvil_app::profiles::{ProfileManager, Unlock};
    use tokio::sync::oneshot;

    #[tokio::test]
    async fn cancellation_interrupts_a_queue_wait_and_releases_the_session_mutex() {
        let slot = Arc::new(OpenSession {
            session: tokio::sync::Mutex::new(None),
            cancel: tokio_util::sync::CancellationToken::new(),
        });
        let (waiting_tx, waiting_rx) = oneshot::channel();
        let sender = async {
            let _guard = slot.session.lock().await;
            let queue_wait = async {
                waiting_tx.send(()).unwrap();
                std::future::pending::<()>().await;
            };
            assert_eq!(until_canceled(&slot.cancel, queue_wait).await, Err("CANCELED".into()));
        };
        let canceler = async {
            waiting_rx.await.unwrap();
            // The actual abort signals before trying to acquire the mutex.
            slot.abort().await;
            assert!(slot.session.try_lock().is_ok());
        };
        tokio::time::timeout(Duration::from_secs(10), async {
            tokio::join!(sender, canceler);
        }).await.expect("cancellation must release the slot");
    }

    #[tokio::test]
    async fn paused_session_finalization_never_returns_payload_across_a_fence_change() {
        for transition in ["lock", "lock-unlock", "profile", "unchanged"] {
            let root = TempRoot::new();
            let st = DesktopState::new(root.0.clone());
            let (app, dir) = create(&st, "session");
            let (other, _) = create(&st, "other");
            st.set_app_since(app, st.epoch()).unwrap();
            let fence = st.admit_payload().unwrap();
            let (ready_tx, ready_rx) = oneshot::channel();
            let (release_tx, release_rx) = oneshot::channel();
            let finalizing = async {
                let view = payload_view();
                let output = anvil_engine::ExecutionOutput {
                    record: view.record,
                    body: b"payload-canary".to_vec().into(),
                    decoded_body: None,
                    extracted: vec![],
                    session_facts: None,
                };
                // Barrier at the watcher's finish/history boundary; a lock
                // can make recording fail, but must never authorize a view.
                ready_tx.send(()).unwrap();
                release_rx.await.unwrap();
                let (output, recorded) = fence.app.record_off_runtime(output).await;
                if transition == "lock" {
                    assert!(matches!(recorded, Err(AppError::Locked)));
                }
                let ended = SessionEnded {
                    execution_id: output.record.id.to_string(),
                    view: Some(ExecutionView {
                        record: output.record,
                        body: body_view(&output.body, None, None),
                    }),
                    error: Some("payload-canary recording error".into()),
                };
                let received = parking_lot::Mutex::new(Vec::new());
                emit_ended(&st, &fence, ended, |ev| received.lock().push(ev));
                let received = received.into_inner();
                assert_eq!(received.len(), 1);
                if transition == "unchanged" {
                    assert_eq!(
                        received[0].view.as_ref().unwrap().body.text.as_deref(),
                        Some("payload-canary"),
                    );
                } else {
                    assert!(received[0].view.is_none(), "{transition}");
                    assert_eq!(received[0].error.as_deref(), Some("LOCKED"));
                }
            };
            let locking = async {
                ready_rx.await.unwrap();
                match transition {
                    "lock" => st.lock(),
                    "lock-unlock" => {
                        st.lock();
                        let (_, key) = ProfileManager::unlock(
                            &dir,
                            Unlock::Passphrase(PASSPHRASE),
                        ).unwrap();
                        st.unlock_since(&fence.app, key, st.epoch()).unwrap();
                    }
                    "profile" => st.set_app_since(other, st.epoch()).unwrap(),
                    "unchanged" => {}
                    _ => unreachable!(),
                }
                release_tx.send(()).unwrap();
            };
            tokio::time::timeout(Duration::from_secs(10), async {
                tokio::join!(finalizing, locking);
            }).await.expect("session finalization must settle");
        }
    }
}
