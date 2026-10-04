//! Interactive sessions (WebSocket, TCP/TLS, UDP/DTLS, streaming gRPC, SSE).
//! Messages stream to the webview as `execution-event`s; when the session
//! ends its record is stored in history like any other execution.

use crate::commands::{ExecutionView, R, SendInput, body_view, e, execution_sink, id};
use crate::state::{DesktopState, PayloadFence, PendingEntry};
use anvil_app::AppError;
use anvil_app::exec::SendOptions;
use anvil_domain::events::SessionCommand;
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

/// Owns the exact slot from registration through opening. A failed/canceled
/// open removes only its slot, even if a transition allowed this id's reuse.
struct SessionRegistration<'a> {
    st: &'a DesktopState,
    execution_id: String,
    slot: SessionSlot,
    published: bool,
}

impl Drop for SessionRegistration<'_> {
    fn drop(&mut self) {
        if !self.published {
            remove_slot(self.st, &self.execution_id, &self.slot);
        }
    }
}

fn remove_slot(st: &DesktopState, execution_id: &str, slot: &SessionSlot) {
    let mut sessions = st.sessions.lock();
    if sessions.get(execution_id).is_some_and(|(_, current)| Arc::ptr_eq(current, slot)) {
        sessions.remove(execution_id);
    }
}

fn register_session<'a>(st: &'a DesktopState, fence: &PayloadFence, execution_id: &str) -> R<(PendingEntry, SessionRegistration<'a>)> {
    let exec_id = id(execution_id)?;
    st.deliver_payload(fence, || {
        let mut sessions = st.sessions.lock();
        if sessions.contains_key(execution_id) {
            return Err(format!("attempt {execution_id} is already running"));
        }
        let pending = PendingEntry::register(&st.running, exec_id)?;
        let slot = Arc::new(OpenSession { session: tokio::sync::Mutex::new(None), cancel: pending.token().clone() });
        sessions.insert(execution_id.into(), (fence.clone(), slot.clone()));
        Ok((pending, SessionRegistration { st, execution_id: execution_id.into(), slot, published: false }))
    })?
}

/// The invocation owns this exact pending/open slot, not just a renderer id.
/// Capture it at IPC admission, before spawning the control future.
pub(crate) struct SessionControl {
    fence: PayloadFence,
    execution_id: String,
    slot: SessionSlot,
}

pub(crate) fn admit_control(st: &DesktopState, fence: PayloadFence, execution_id: &str) -> R<SessionControl> {
    st.deliver_payload(&fence, || {
        let (owner, slot) = st.sessions.lock().get(execution_id).cloned().ok_or("the session is no longer open")?;
        if !owner.same_owner(&fence) {
            return Err("the session is no longer open".into());
        }
        Ok(SessionControl { fence: fence.clone(), execution_id: execution_id.into(), slot })
    })?
}

impl SessionControl {
    /// Called only with shared delivery access held, immediately before a
    /// cancellation signal or a poll that can enqueue an engine command.
    fn check_slot(&self, st: &DesktopState) -> R<()> {
        if !st
            .sessions
            .lock()
            .get(&self.execution_id)
            .is_some_and(|(owner, slot)| owner.same_owner(&self.fence) && Arc::ptr_eq(slot, &self.slot))
        {
            return Err("the session is no longer open".into());
        }
        Ok(())
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
    // Publish a pending slot under the admitted epoch. Controls bind that
    // slot and its token now; the handle later fills the same slot.
    let (pending, mut registration) = register_session(st.inner(), &fence, &execution_id)?;
    let slot = registration.slot.clone();
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
    let sink = execution_sink(handle.clone(), fence.clone(), false, move |ev| {
        let _ = h2.emit("execution-event", ev);
    });
    let open = app.engine.open_session(ctx, EventCtx { execution_id: exec_id, sink: Some(sink) });
    let Some((session, canceled)) = pending.open(open, |session| session).await else {
        return Err(CANCELED_BEFORE_OPEN.into());
    };
    publish_handle(st.inner(), &fence, &slot, session, canceled).await;
    registration.published = true;
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
        remove_slot(st.inner(), &key, &slot);
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

async fn publish_handle(st: &DesktopState, fence: &PayloadFence, slot: &SessionSlot, session: SessionHandle, canceled: bool) {
    let mut guard = slot.session.lock().await;
    let mut session = Some(session);
    if st.deliver_payload(fence, || *guard = session.take()).is_err() {
        // This exact old slot may already be retired from the map. Retain
        // the completed handle only for abort/history finalization, never
        // publish it under a reused id or return an unfenced payload.
        *guard = session.take();
        slot.cancel.cancel();
    }
    drop(guard);
    if canceled || slot.cancel.is_cancelled() {
        slot.abort().await;
    }
}

/// A refused final payload still retires the UI's session with scalar status.
fn emit_ended(st: &DesktopState, fence: &crate::state::PayloadFence, ev: SessionEnded, emit: impl Fn(SessionEnded)) {
    let execution_id = ev.execution_id.clone();
    if st.deliver_payload(fence, || emit(ev)).is_err() {
        emit(SessionEnded { execution_id, view: None, error: Some("LOCKED".into()) });
    }
}

async fn until_canceled<T>(cancel: &tokio_util::sync::CancellationToken, work: impl Future<Output = T>) -> R<T> {
    tokio::select! {
        biased;
        () = cancel.cancelled() => Err(crate::commands::CANCELED.into()),
        out = work => Ok(out),
    }
}

pub(crate) async fn session_send(st: &DesktopState, control: SessionControl, command: SessionCommand) -> R<()> {
    st.deliver_payload(&control.fence, || control.check_slot(st))??;
    let guard = until_canceled(&control.slot.cancel, control.slot.session.lock()).await?;
    let session = guard.as_ref().ok_or("the session is no longer open")?;
    let mut send = std::pin::pin!(async { session.send(command).await.map_err(|err| err.to_string()) });
    until_canceled(
        &control.slot.cancel,
        std::future::poll_fn(|cx| {
            // SessionHandle::send inserts into its bounded queue during a
            // poll. Revalidate each poll, including one after a queue wait;
            // pending polls release the synchronous gate before awaiting.
            match st.deliver_payload(&control.fence, || {
                control.check_slot(st)?;
                Ok(send.as_mut().poll(cx))
            }) {
                Ok(Ok(polled)) => polled,
                Ok(Err(err)) | Err(err) => std::task::Poll::Ready(Err(err)),
            }
        }),
    )
    .await?
}

/// Signal the admitted slot/token synchronously under the epoch gate, then
/// release all synchronous guards before acquiring the async engine handle.
pub(crate) async fn session_cancel(st: &DesktopState, control: SessionControl) -> R<()> {
    st.deliver_payload(&control.fence, || {
        control.check_slot(st)?;
        control.slot.cancel.cancel();
        Ok::<_, String>(())
    })??;
    control.slot.abort().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::tests::payload_view;
    use crate::state::tests::{PASSPHRASE, TempRoot, create};
    use anvil_app::profiles::{ProfileManager, Unlock};
    use anvil_domain::events::ExecutionEvent;
    use anvil_domain::request::{Protocol, RequestSpec, TcpFraming, TcpSpec};
    use anvil_engine::context::ExecutionContext;
    use std::sync::mpsc;
    use tokio::sync::oneshot;

    const BOUND: Duration = Duration::from_secs(10);

    // A real engine handle and its real 256-entry command queue. The peer
    // remains listening until cleanup, without an artificial queue or handle.
    async fn open_tcp(
        st: &DesktopState,
        fence: &PayloadFence,
        execution_id: &str,
        sink: Option<anvil_transport::EventFn>,
    ) -> (SessionSlot, tokio::net::TcpListener) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut spec = RequestSpec::http("GET", &format!("tcp://{}", listener.local_addr().unwrap()));
        spec.protocol = Protocol::Tcp;
        spec.tcp = Some(TcpSpec {
            tls: false,
            framing: TcpFraming::NewlineDelimited,
            payloads: vec![],
            half_close_after_send: false,
            read_idle_ms: 1000,
            max_read_bytes: 4096,
            expect_frames: 0,
            proxy_protocol: None,
        });
        let (pending, mut registration) = register_session(st, fence, execution_id).unwrap();
        let slot = registration.slot.clone();
        let open =
            fence.app.engine.open_session(ExecutionContext::standalone(spec), EventCtx { execution_id: id(execution_id).unwrap(), sink });
        let (session, canceled) = pending.open(open, |session| session).await.unwrap();
        publish_handle(st, fence, &slot, session, canceled).await;
        registration.published = true;
        (slot, listener)
    }

    async fn finish_slot(slot: &SessionSlot) {
        slot.abort().await;
        let session = slot.session.lock().await.take();
        if let Some(session) = session {
            tokio::time::timeout(BOUND, session.finish()).await.expect("engine cancellation must finish");
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn actual_full_engine_queue_is_interrupted_by_cancel_and_lock() {
        for how in ["cancel", "lock"] {
            let root = TempRoot::new();
            let st = Arc::new(DesktopState::new(root.0.clone()));
            let (app, _) = create(&st, "queue");
            st.set_app_since(app, st.epoch()).unwrap();
            let fence = st.admit_payload().unwrap();
            let execution_id = Id::new().to_string();
            let (entered_tx, entered_rx) = mpsc::channel();
            let (release_tx, release_rx) = mpsc::channel();
            let release = parking_lot::Mutex::new(release_rx);
            let sink: anvil_transport::EventFn = Arc::new(move |ev| {
                if matches!(ev, ExecutionEvent::AttemptStarted { .. }) {
                    // Stall the real consumer before it can take a command.
                    entered_tx.send(()).unwrap();
                    release.lock().recv_timeout(BOUND).unwrap();
                }
            });
            let (slot, _peer) = open_tcp(&st, &fence, &execution_id, Some(sink)).await;
            entered_rx.recv_timeout(BOUND).unwrap();
            for _ in 0..256 {
                let control = admit_control(&st, fence.clone(), &execution_id).unwrap();
                tokio::time::timeout(BOUND, session_send(&st, control, SessionCommand::SendText { text: "queued".into() }))
                    .await
                    .expect("the real queue's existing capacity")
                    .unwrap();
            }
            let control = admit_control(&st, fence.clone(), &execution_id).unwrap();
            let cancel = admit_control(&st, fence.clone(), &execution_id).unwrap();
            let (waiting_tx, waiting_rx) = oneshot::channel();
            let sending = async {
                let mut send = std::pin::pin!(session_send(&st, control, SessionCommand::SendText { text: "blocked".into() }));
                let mut waiting_tx = Some(waiting_tx);
                let result = std::future::poll_fn(|cx| {
                    let polled = send.as_mut().poll(cx);
                    if polled.is_pending()
                        && let Some(waiting_tx) = waiting_tx.take()
                    {
                        waiting_tx.send(()).unwrap();
                    }
                    polled
                })
                .await;
                assert_eq!(result, Err("CANCELED".into()));
            };
            let canceling = async {
                waiting_rx.await.unwrap();
                // The first Pending is observed on the actual production
                // send. It still owns the async slot mutex at this barrier.
                assert!(slot.session.try_lock().is_err());
                if how == "cancel" {
                    session_cancel(&st, cancel).await.unwrap();
                } else {
                    st.lock();
                    slot.abort().await;
                }
                assert!(slot.session.try_lock().is_ok());
            };
            let settled = tokio::time::timeout(BOUND, async { tokio::join!(sending, canceling) }).await;
            release_tx.send(()).unwrap();
            settled.expect("cancel must release a send waiting on the real bounded queue");
            finish_slot(&slot).await;
            remove_slot(&st, &execution_id, &slot);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn paused_controls_cannot_drive_reused_ids_in_pending_or_live_slots() {
        for how in ["lock-unlock", "profile", "same-epoch-reuse"] {
            for live in [false, true] {
                let root = TempRoot::new();
                let st = Arc::new(DesktopState::new(root.0.clone()));
                let (app, dir) = create(&st, "A");
                st.set_app_since(app, st.epoch()).unwrap();
                let old_fence = st.admit_payload().unwrap();
                let execution_id = Id::new().to_string();
                let (old_pending, old_registration) = register_session(&st, &old_fence, &execution_id).unwrap();
                let old_slot = old_registration.slot.clone();
                let send = admit_control(&st, old_fence.clone(), &execution_id).unwrap();
                let cancel = admit_control(&st, old_fence.clone(), &execution_id).unwrap();
                let (ready_tx, ready_rx) = oneshot::channel();
                let (release_tx, release_rx) = oneshot::channel();
                let controls = async {
                    // Same admission path as IPC, then pause before either
                    // actual command can begin its synchronous effects.
                    ready_tx.send(()).unwrap();
                    release_rx.await.unwrap();
                    let sent = session_send(&st, send, SessionCommand::SendText { text: "stale-canary".into() }).await;
                    let canceled = session_cancel(&st, cancel).await;
                    assert!(sent.is_err(), "{how}, live={live}");
                    assert!(canceled.is_err(), "{how}, live={live}");
                };
                let replacing = async {
                    ready_rx.await.unwrap();
                    match how {
                        "lock-unlock" => {
                            st.lock();
                            let (_, key) = ProfileManager::unlock(&dir, Unlock::Passphrase(PASSPHRASE)).unwrap();
                            st.unlock_since(&old_fence.app, key, st.epoch()).unwrap();
                        }
                        "profile" => {
                            let (other, _) = create(&st, "B");
                            st.set_app_since(other, st.epoch()).unwrap();
                        }
                        "same-epoch-reuse" => {
                            old_slot.cancel.cancel();
                            remove_slot(&st, &execution_id, &old_slot);
                        }
                        _ => unreachable!(),
                    }
                    drop(old_pending);
                    let fresh = st.admit_payload().unwrap();
                    let (slot, peer, pending) = if live {
                        let (slot, peer) = open_tcp(&st, &fresh, &execution_id, None).await;
                        (slot, Some(peer), None)
                    } else {
                        let (pending, mut registration) = register_session(&st, &fresh, &execution_id).unwrap();
                        registration.published = true;
                        (registration.slot.clone(), None, Some(pending))
                    };
                    // An old opener/finalizer cannot retire the reused id.
                    drop(old_registration);
                    assert!(st.sessions.lock().get(&execution_id).is_some_and(|(_, current)| Arc::ptr_eq(current, &slot)));
                    release_tx.send(()).unwrap();
                    // Await the controls in the other joined branch before
                    // checking the new token or sending its positive control.
                    (fresh, slot, peer, pending)
                };
                let (_, (fresh, slot, _peer, pending)) =
                    tokio::time::timeout(BOUND, async { tokio::join!(controls, replacing) }).await.expect("paused controls must settle");
                assert!(!slot.cancel.is_cancelled(), "stale cancel reached replacement: {how}, live={live}");
                if let Some(pending) = pending.as_ref() {
                    assert!(!pending.token().is_cancelled());
                }
                if live {
                    let control = admit_control(&st, fresh.clone(), &execution_id).unwrap();
                    session_send(&st, control, SessionCommand::SendText { text: "fresh".into() }).await.unwrap();
                }
                let control = admit_control(&st, fresh, &execution_id).unwrap();
                session_cancel(&st, control).await.unwrap();
                assert!(slot.cancel.is_cancelled());
                if let Some(pending) = pending.as_ref() {
                    assert!(pending.token().is_cancelled());
                }
                finish_slot(&slot).await;
                remove_slot(&st, &execution_id, &slot);
            }
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn ordinary_same_epoch_controls_use_the_same_live_slot() {
        let root = TempRoot::new();
        let st = DesktopState::new(root.0.clone());
        let (app, _) = create(&st, "positive");
        st.set_app_since(app, st.epoch()).unwrap();
        let fence = st.admit_payload().unwrap();
        let execution_id = Id::new().to_string();
        let (slot, _peer) = open_tcp(&st, &fence, &execution_id, None).await;
        let send = admit_control(&st, fence.clone(), &execution_id).unwrap();
        session_send(&st, send, SessionCommand::SendText { text: "ordinary".into() }).await.unwrap();
        assert!(!slot.cancel.is_cancelled());
        let cancel = admit_control(&st, fence.clone(), &execution_id).unwrap();
        session_cancel(&st, cancel).await.unwrap();
        assert!(slot.cancel.is_cancelled());
        let session = slot.session.lock().await.take().unwrap();
        let output = tokio::time::timeout(BOUND, session.finish()).await.unwrap();
        let (output, recorded) = fence.app.record_off_runtime(output).await;
        recorded.unwrap();
        assert!(fence.app.store.get_history::<anvil_domain::execution::ExecutionRecord>(&output.record.id.to_string()).unwrap().is_some());
        remove_slot(&st, &execution_id, &slot);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_completed_handle_in_a_retired_slot_still_finalizes_without_replacing_the_new_slot() {
        let root = TempRoot::new();
        let st = DesktopState::new(root.0.clone());
        let (app, dir) = create(&st, "history");
        st.set_app_since(app, st.epoch()).unwrap();
        let fence = st.admit_payload().unwrap();
        let execution_id = Id::new().to_string();
        let (old_slot, _peer) = open_tcp(&st, &fence, &execution_id, None).await;
        // Pause between an engine open completing and its handle becoming
        // reachable to the watcher; lock/unlock permits the same id's reuse.
        let session = old_slot.session.lock().await.take().unwrap();
        st.lock();
        let (_, key) = ProfileManager::unlock(&dir, Unlock::Passphrase(PASSPHRASE)).unwrap();
        st.unlock_since(&fence.app, key, st.epoch()).unwrap();
        let fresh = st.admit_payload().unwrap();
        let (pending, registration) = register_session(&st, &fresh, &execution_id).unwrap();
        publish_handle(&st, &fence, &old_slot, session, true).await;
        let session = old_slot.session.lock().await.take().expect("completed handle retained for finalization");
        let output = tokio::time::timeout(BOUND, session.finish()).await.unwrap();
        let (output, recorded) = fence.app.record_off_runtime(output).await;
        recorded.unwrap();
        assert!(fence.app.store.get_history::<anvil_domain::execution::ExecutionRecord>(&output.record.id.to_string()).unwrap().is_some());
        remove_slot(&st, &execution_id, &old_slot);
        assert!(!pending.token().is_cancelled());
        assert!(st.sessions.lock().get(&execution_id).is_some_and(|(_, slot)| Arc::ptr_eq(slot, &registration.slot)));
        let ct = output.record.response.as_ref().and_then(|r| r.body.content_type.as_deref());
        let view = ExecutionView { body: body_view(&output.body, output.decoded_body.as_deref(), ct), record: output.record };
        let ended = SessionEnded { execution_id: execution_id.clone(), view: Some(view), error: None };
        emit_ended(&st, &fence, ended, |ev| {
            assert!(ev.view.is_none());
            assert_eq!(ev.error.as_deref(), Some("LOCKED"));
        });
        let cancel = admit_control(&st, fresh, &execution_id).unwrap();
        session_cancel(&st, cancel).await.unwrap();
        assert!(pending.token().is_cancelled());
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
                    view: Some(ExecutionView { record: output.record, body: body_view(&output.body, None, None) }),
                    error: Some("payload-canary recording error".into()),
                };
                let received = parking_lot::Mutex::new(Vec::new());
                emit_ended(&st, &fence, ended, |ev| received.lock().push(ev));
                let received = received.into_inner();
                assert_eq!(received.len(), 1);
                if transition == "unchanged" {
                    assert_eq!(received[0].view.as_ref().unwrap().body.text.as_deref(), Some("payload-canary"),);
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
                        let (_, key) = ProfileManager::unlock(&dir, Unlock::Passphrase(PASSPHRASE)).unwrap();
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
            })
            .await
            .expect("session finalization must settle");
        }
    }
}
