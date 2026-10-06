//! Interactive sessions (WebSocket, TCP/TLS, UDP/DTLS, streaming gRPC, SSE).
//! Messages stream to the webview as `execution-event`s; when the session
//! ends its record is stored in history like any other execution.

use crate::commands::{ExecutionView, R, SendInput, body_view, e, execution_sink, id};
use crate::state::{DesktopState, PayloadFence, PayloadState, PendingEntry};
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
    /// The explicit renderer attempt admitted with this slot, never its reused id.
    pub attempt_id: String,
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

const NIL_ATTEMPT: &str = "attemptId must be a fresh UUID, not the nil UUID";

fn register_session<'a>(
    st: &'a DesktopState,
    fence: &PayloadFence,
    execution_id: &str,
    attempt_id: &str,
) -> R<(PendingEntry, SessionRegistration<'a>)> {
    let exec_id = id(execution_id)?;
    // Freshness is the caller's obligation (Workbench uses a new random UUID
    // per OPEN); the nil UUID is a fixed value and never a fresh attempt.
    if id(attempt_id)?.is_nil() {
        return Err(NIL_ATTEMPT.into());
    }
    st.deliver_payload(fence, || {
        let mut sessions = st.sessions.lock();
        if sessions.contains_key(execution_id) {
            return Err(format!("attempt {execution_id} is already running"));
        }
        let pending = PendingEntry::register(&st.running, exec_id)?;
        let slot = Arc::new(OpenSession {
            attempt_id: attempt_id.into(),
            session: tokio::sync::Mutex::new(None),
            cancel: pending.token().clone(),
        });
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

/// Send and cancel may arrive after an execution id has been reused. Resolve
/// the required expected attempt at IPC admission, before capturing its slot.
pub(crate) fn admit_control(st: &DesktopState, fence: PayloadFence, execution_id: &str, attempt_id: &str) -> R<SessionControl> {
    st.deliver_payload(&fence, || {
        let (owner, slot) = st.sessions.lock().get(execution_id).cloned().ok_or("the session is no longer open")?;
        if !owner.same_owner(&fence) || attempt_id != slot.attempt_id {
            return Err("the session is no longer open".into());
        }
        Ok(SessionControl { fence: fence.clone(), execution_id: execution_id.into(), slot })
    })?
}

pub(crate) fn admit_cancel(st: &DesktopState, fence: PayloadFence, execution_id: &str, attempt_id: &str) -> R<SessionControl> {
    admit_control(st, fence, execution_id, attempt_id)
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
    /// Renderer generation, distinct from a possibly reused execution id.
    pub attempt_id: String,
    pub view: Option<ExecutionView>,
    pub error: Option<String>,
}

/// Desktop-only envelope: domain/CLI events retain their existing shape.
#[derive(Serialize, Clone)]
pub struct SessionEvent {
    pub attempt_id: String,
    #[serde(flatten)]
    pub event: ExecutionEvent,
}

/// Tag every real transport callback with its immutable registered attempt.
/// The shared payload gate and exact-slot mutex stay held through enqueue.
fn session_sink<S: PayloadState>(
    source: S,
    fence: PayloadFence,
    execution_id: String,
    slot: SessionSlot,
    emit: impl Fn(SessionEvent) + Send + Sync + 'static,
) -> anvil_transport::EventFn {
    execution_sink(source.clone(), fence, false, move |event| {
        source.with_state(|st| {
            let sessions = st.sessions.lock();
            if !sessions.get(&execution_id).is_some_and(|(_, current)| Arc::ptr_eq(current, &slot)) {
                return;
            }
            emit(SessionEvent { attempt_id: slot.attempt_id.clone(), event: event.clone() });
        });
    })
}

/// Open a session. Returns the execution id used by message events.
pub(crate) async fn session_open(
    handle: AppHandle,
    fence: crate::state::PayloadFence,
    input: SendInput,
    execution_id: String,
    attempt_id: String,
) -> R<String> {
    let st = handle.state::<DesktopState>();
    let exec_id = id(&execution_id)?;
    // Publish a pending slot under the admitted epoch. Controls bind that
    // slot and its token now; the handle later fills the same slot.
    let (pending, mut registration) = register_session(st.inner(), &fence, &execution_id, &attempt_id)?;
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
    let sink = session_sink(handle.clone(), fence.clone(), execution_id.clone(), slot.clone(), move |ev| {
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
        let ev = finish_session(&app, key, attempt_id, taken).await;
        // History finalization stays outside the delivery gate. Both the
        // view and any payload-bearing recording error are dropped together.
        tauri::async_runtime::spawn_blocking(move || {
            let st = handle.state::<DesktopState>();
            let st = st.inner();
            emit_ended(st, &fence, &slot, ev, |ev| {
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

async fn finish_session(app: &anvil_app::App, execution_id: String, attempt_id: String, session: Option<SessionHandle>) -> SessionEnded {
    match session {
        Some(session) => {
            let out = session.finish().await;
            // Into the profile the session was opened under, never the one
            // open now; refused while that profile is locked.
            let (out, recorded) = app.record_off_runtime(out).await;
            let ct = out.record.response.as_ref().and_then(|r| r.body.content_type.clone());
            let raw = &out.body;
            let decoded = out.decoded_body.as_deref();
            let content_type = ct.as_deref();
            let body = body_view(raw, decoded, content_type);
            let view = ExecutionView { body, record: out.record };
            let error = recorded.map_err(e).err();
            SessionEnded { execution_id, attempt_id, view: Some(view), error }
        }
        None => SessionEnded { execution_id, attempt_id, view: None, error: Some("the session was already finished".into()) },
    }
}

/// Check the exact native slot and enqueue atomically against registration.
/// A retired, unreplaced attempt still sends completion (scalar if fenced).
/// The renderer generation also rejects packets queued before replacement.
fn emit_ended(st: &DesktopState, fence: &PayloadFence, slot: &SessionSlot, ev: SessionEnded, emit: impl Fn(SessionEnded)) {
    let execution_id = ev.execution_id.clone();
    let attempt_id = ev.attempt_id.clone();
    let deliver = |ev: SessionEnded| {
        let sessions = st.sessions.lock();
        if sessions.get(&ev.execution_id).is_some_and(|(_, current)| !Arc::ptr_eq(current, slot)) {
            return;
        }
        // Keep the registry guard through enqueue, including scalar fallback.
        // This synchronous sink must not reenter the session registry.
        emit(ev);
    };
    if st.deliver_payload(fence, || deliver(ev)).is_err() {
        let error = Some("LOCKED".into());
        let ended = SessionEnded { execution_id, attempt_id, view: None, error };
        deliver(ended);
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
    use anvil_domain::Id;
    use anvil_domain::events::ExecutionEvent;
    use anvil_domain::execution::{Direction, ExecutionRecord};
    use anvil_domain::outcome::{ClosedBy, ProtocolStatus, TransportState};
    use anvil_domain::request::{Protocol, RequestSpec, TcpFraming, TcpSpec};
    use anvil_engine::context::ExecutionContext;
    use std::sync::mpsc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::oneshot;

    const BOUND: Duration = Duration::from_secs(10);

    fn history_contains(app: &anvil_app::App, record_id: &str) -> bool {
        app.store.get_history::<ExecutionRecord>(record_id).unwrap().is_some()
    }

    // A real engine handle and its real 256-entry command queue. The peer
    // remains listening until cleanup, without an artificial queue or handle.
    async fn open_tcp(
        st: &DesktopState,
        fence: &PayloadFence,
        execution_id: &str,
        sink: Option<anvil_transport::EventFn>,
    ) -> (SessionSlot, tokio::net::TcpListener) {
        let (pending, mut registration) = register_session(st, fence, execution_id, &Id::new().to_string()).unwrap();
        let slot = registration.slot.clone();
        let listener = open_registered_tcp(st, fence, execution_id, pending, &slot, sink).await;
        registration.published = true;
        (slot, listener)
    }

    async fn open_registered_tcp(
        st: &DesktopState,
        fence: &PayloadFence,
        execution_id: &str,
        pending: PendingEntry,
        slot: &SessionSlot,
        sink: Option<anvil_transport::EventFn>,
    ) -> tokio::net::TcpListener {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut spec = RequestSpec::http("GET", &format!("tcp://{}", listener.local_addr().unwrap()));
        spec.protocol = Protocol::Tcp;
        spec.tcp = Some(TcpSpec {
            tls: false,
            framing: TcpFraming::NewlineDelimited,
            payloads: vec![],
            half_close_after_send: false,
            read_idle_ms: 10_000,
            max_read_bytes: 4096,
            expect_frames: 0,
            proxy_protocol: None,
        });
        let open =
            fence.app.engine.open_session(ExecutionContext::standalone(spec), EventCtx { execution_id: id(execution_id).unwrap(), sink });
        let (session, canceled) = pending.open(open, |session| session).await.unwrap();
        publish_handle(st, fence, slot, session, canceled).await;
        listener
    }

    async fn finish_slot(slot: &SessionSlot) {
        slot.abort().await;
        let session = slot.session.lock().await.take();
        if let Some(session) = session {
            tokio::time::timeout(BOUND, session.finish()).await.expect("engine cancellation must finish");
        }
    }

    #[test]
    fn nil_attempt_is_rejected_before_registration() {
        let root = TempRoot::new();
        let st = DesktopState::new(root.0.clone());
        let (app, _) = create(&st, "nil");
        st.set_app_since(app, st.epoch()).unwrap();
        let fence = st.admit_payload().unwrap();
        let execution_id = Id::new().to_string();
        let rejected = register_session(&st, &fence, &execution_id, &Id::nil().to_string());
        assert_eq!(rejected.err(), Some(NIL_ATTEMPT.to_string()));
        assert!(st.sessions.lock().is_empty());
        assert!(register_session(&st, &fence, &execution_id, &Id::new().to_string()).is_ok());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn rejected_duplicate_preserves_the_original_slot_and_full_or_scalar_completion() {
        for scalar in [false, true] {
            let root = TempRoot::new();
            let st = DesktopState::new(root.0.clone());
            let (app, _) = create(&st, "duplicate");
            st.set_app_since(app, st.epoch()).unwrap();
            let fence = st.admit_payload().unwrap();
            let execution_id = Id::new().to_string();
            let (slot, _peer) = open_tcp(&st, &fence, &execution_id, None).await;
            let duplicate = Id::new().to_string();
            let rejected = register_session(&st, &fence, &execution_id, &duplicate);
            assert_eq!(rejected.err(), Some(format!("attempt {execution_id} is already running")));
            assert!(st.sessions.lock().get(&execution_id).is_some_and(|(_, current)| Arc::ptr_eq(current, &slot)));
            assert!(!slot.cancel.is_cancelled());
            let attempt_id = slot.attempt_id.clone();
            let control = admit_cancel(&st, fence.clone(), &execution_id, &attempt_id).unwrap();
            session_cancel(&st, control).await.unwrap();
            let taken = slot.session.lock().await.take();
            assert!(taken.is_some());
            let app = &fence.app;
            let key = execution_id.clone();
            let attempt = attempt_id.clone();
            let finish = finish_session(app, key, attempt, taken);
            let ended = tokio::time::timeout(BOUND, finish).await.unwrap();
            assert!(ended.error.is_none());
            let record_id = ended.view.as_ref().unwrap().record.id.to_string();
            assert!(history_contains(app, &record_id));
            remove_slot(&st, &execution_id, &slot);
            if scalar {
                st.lock();
            }
            let received = parking_lot::Mutex::new(Vec::new());
            emit_ended(&st, &fence, &slot, ended, |event| {
                assert!(st.sessions.try_lock().is_none(), "enqueue must exclude registration");
                received.lock().push(serde_json::to_value(event).unwrap());
            });
            let received = received.into_inner();
            assert_eq!(received.len(), 1);
            assert_eq!(received[0]["execution_id"], execution_id);
            assert_eq!(received[0]["attempt_id"], attempt_id);
            if scalar {
                assert!(received[0]["view"].is_null());
                assert_eq!(received[0]["error"], "LOCKED");
            } else {
                assert_eq!(received[0]["view"]["record"]["id"], record_id);
                assert!(received[0]["error"].is_null());
            }
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn late_cancel_admission_cannot_capture_a_replacement_attempt() {
        for transition in ["same-epoch", "lock-unlock", "profile"] {
            for live in [false, true] {
                let root = TempRoot::new();
                let st = DesktopState::new(root.0.clone());
                let (app, dir) = create(&st, "old");
                st.set_app_since(app, st.epoch()).unwrap();
                let fence = st.admit_payload().unwrap();
                let execution_id = Id::new().to_string();
                let old_attempt = Id::new().to_string();
                let (old_pending, old_registration) = register_session(&st, &fence, &execution_id, &old_attempt).unwrap();
                match transition {
                    "same-epoch" => {
                        remove_slot(&st, &execution_id, &old_registration.slot);
                    }
                    "lock-unlock" => {
                        st.lock();
                        let unlock = Unlock::Passphrase(PASSPHRASE);
                        let (_, key) = ProfileManager::unlock(&dir, unlock).unwrap();
                        st.unlock_since(&fence.app, key, st.epoch()).unwrap();
                    }
                    "profile" => {
                        let (other, _) = create(&st, "new");
                        st.set_app_since(other, st.epoch()).unwrap();
                    }
                    _ => unreachable!(),
                }
                drop(old_pending);
                let fresh = st.admit_payload().unwrap();
                let new_attempt = Id::new().to_string();
                let (slot, peer, pending, registration) = if live {
                    let (slot, peer) = open_tcp(&st, &fresh, &execution_id, None).await;
                    (slot, Some(peer), None, None)
                } else {
                    let (pending, registration) = register_session(&st, &fresh, &execution_id, &new_attempt).unwrap();
                    (registration.slot.clone(), None, Some(pending), Some(registration))
                };
                drop(old_registration);
                // This admission is new: a delayed renderer continuation may
                // carry today's authorized epoch while expecting yesterday's slot.
                let stale = admit_cancel(&st, fresh.clone(), &execution_id, &old_attempt);
                assert_eq!(stale.err(), Some("the session is no longer open".into()));
                assert!(!slot.cancel.is_cancelled(), "{transition}, live={live}");
                if let Some(pending) = pending.as_ref() {
                    assert!(!pending.token().is_cancelled());
                }
                if transition != "same-epoch" {
                    let old_epoch = admit_cancel(&st, fence, &execution_id, &slot.attempt_id);
                    assert_eq!(old_epoch.err(), Some("LOCKED".into()));
                }
                if live {
                    let send = admit_control(&st, fresh.clone(), &execution_id, &slot.attempt_id).unwrap();
                    let command = SessionCommand::SendText { text: "replacement".into() };
                    session_send(&st, send, command).await.unwrap();
                }
                let cancel = admit_cancel(&st, fresh, &execution_id, &slot.attempt_id).unwrap();
                session_cancel(&st, cancel).await.unwrap();
                assert!(slot.cancel.is_cancelled());
                if let Some(pending) = pending.as_ref() {
                    assert!(pending.token().is_cancelled());
                }
                finish_slot(&slot).await;
                remove_slot(&st, &execution_id, &slot);
                drop((peer, pending, registration));
            }
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn sends_delayed_before_admission_cannot_drive_pending_or_live_replacements() {
        for transition in ["same-epoch", "lock-unlock", "profile"] {
            for live in [false, true] {
                let root = TempRoot::new();
                let st = DesktopState::new(root.0.clone());
                let (app, dir) = create(&st, "old send");
                st.set_app_since(app, st.epoch()).unwrap();
                let old_fence = st.admit_payload().unwrap();
                let execution_id = Id::new().to_string();
                let (old_slot, _old_peer) = open_tcp(&st, &old_fence, &execution_id, None).await;
                let old_attempt = old_slot.attempt_id.clone();
                let commands = [
                    SessionCommand::SendText { text: "stale-canary".into() },
                    SessionCommand::Close { code: 1000, reason: String::new() },
                    SessionCommand::HalfClose,
                ];
                let (ready_tx, ready_rx) = oneshot::channel();
                let (release_tx, release_rx) = oneshot::channel();
                let (message_tx, mut message_rx) = tokio::sync::mpsc::unbounded_channel();
                let sink: anvil_transport::EventFn = Arc::new(move |event| {
                    if let ExecutionEvent::Message { message, .. } = event
                        && message.direction == Direction::Received
                    {
                        let _ = message_tx.send(message);
                    }
                });
                let invoking = async {
                    // Renderer commands already own E/A, but have NOT reached
                    // native admission. Today's fence must not bind them to B.
                    ready_tx.send(()).unwrap();
                    release_rx.await.unwrap();
                    let fence = st.admit_payload().unwrap();
                    for command in commands {
                        let sent = match admit_control(&st, fence.clone(), &execution_id, &old_attempt) {
                            Ok(control) => session_send(&st, control, command).await,
                            Err(err) => Err(err),
                        };
                        assert_eq!(sent, Err("the session is no longer open".into()), "{transition}, live={live}");
                    }
                    let canceled = admit_cancel(&st, fence, &execution_id, &old_attempt);
                    assert_eq!(canceled.err(), Some("the session is no longer open".into()));
                };
                let replacing = async {
                    ready_rx.await.unwrap();
                    match transition {
                        "same-epoch" => {
                            // The real old handle ends and its slot retires
                            // before history/completion can retire its console.
                            finish_slot(&old_slot).await;
                            remove_slot(&st, &execution_id, &old_slot);
                        }
                        "lock-unlock" => {
                            st.lock();
                            let (_, key) = ProfileManager::unlock(&dir, Unlock::Passphrase(PASSPHRASE)).unwrap();
                            st.unlock_since(&old_fence.app, key, st.epoch()).unwrap();
                        }
                        "profile" => {
                            let (other, _) = create(&st, "new send");
                            st.set_app_since(other, st.epoch()).unwrap();
                        }
                        _ => unreachable!(),
                    }
                    finish_slot(&old_slot).await;
                    let fresh = st.admit_payload().unwrap();
                    let attempt = Id::new().to_string();
                    let (pending, mut registration) = register_session(&st, &fresh, &execution_id, &attempt).unwrap();
                    let slot = registration.slot.clone();
                    let (pending, listener) = if live {
                        let listener = open_registered_tcp(&st, &fresh, &execution_id, pending, &slot, Some(sink.clone())).await;
                        registration.published = true;
                        (None, Some(listener))
                    } else {
                        (Some(pending), None)
                    };
                    release_tx.send(()).unwrap();
                    (fresh, registration, pending, listener)
                };
                let work = async { tokio::join!(invoking, replacing) };
                let (_, (fresh, mut registration, pending, listener)) = tokio::time::timeout(BOUND, work).await.unwrap();
                let slot = registration.slot.clone();
                assert_ne!(slot.attempt_id, old_attempt);
                assert!(!slot.cancel.is_cancelled());
                if let Some(pending) = &pending {
                    assert!(!pending.token().is_cancelled());
                    assert!(slot.session.lock().await.is_none());
                }
                if transition != "same-epoch" {
                    let stale_epoch = admit_control(&st, old_fence, &execution_id, &slot.attempt_id);
                    assert_eq!(stale_epoch.err(), Some("LOCKED".into()));
                }
                // Matching controls can also be admitted while B is pending;
                // publishing its real handle keeps the same captured slot.
                let send = admit_control(&st, fresh.clone(), &execution_id, &slot.attempt_id).unwrap();
                let half_close = admit_control(&st, fresh.clone(), &execution_id, &slot.attempt_id).unwrap();
                let close = admit_control(&st, fresh.clone(), &execution_id, &slot.attempt_id).unwrap();
                let listener = match pending {
                    Some(pending) => {
                        let peer = open_registered_tcp(&st, &fresh, &execution_id, pending, &slot, Some(sink)).await;
                        registration.published = true;
                        peer
                    }
                    None => listener.unwrap(),
                };
                let (mut peer, _) = tokio::time::timeout(BOUND, listener.accept()).await.unwrap().unwrap();
                let command = SessionCommand::SendText { text: "fresh".into() };
                session_send(&st, send, command).await.unwrap();
                let mut bytes = [0; 6];
                tokio::time::timeout(BOUND, peer.read_exact(&mut bytes)).await.unwrap().unwrap();
                assert_eq!(&bytes, b"fresh\n", "stale SendText/Close/HalfClose must leave B usable");
                session_send(&st, half_close, SessionCommand::HalfClose).await.unwrap();
                let mut extra = [0; 1];
                let eof = tokio::time::timeout(BOUND, peer.read(&mut extra)).await.unwrap().unwrap();
                assert_eq!(eof, 0, "matching HalfClose must send FIN with no stale payload queued");
                peer.write_all(b"still reading\n").await.unwrap();
                let message = tokio::time::timeout(BOUND, message_rx.recv()).await.unwrap().unwrap();
                assert!(message.preview.contains("still reading"), "matching HalfClose preserves reads");
                assert!(!slot.session.lock().await.as_ref().unwrap().is_finished());
                let command = SessionCommand::Close { code: 1000, reason: String::new() };
                session_send(&st, close, command).await.unwrap();
                let session = slot.session.lock().await.take().unwrap();
                let out = tokio::time::timeout(BOUND, session.finish()).await.unwrap();
                assert_eq!(out.record.outcome.transport, TransportState::Completed);
                assert!(matches!(
                    out.record.outcome.protocol_status,
                    ProtocolStatus::Tcp { bytes_sent: 6, half_closed: true, closed_by: ClosedBy::Client, .. }
                ));
                assert!(!slot.cancel.is_cancelled(), "matching Close finishes without cancellation");
                remove_slot(&st, &execution_id, &slot);
            }
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn real_session_callbacks_carry_attempts_and_retired_sinks_cannot_enqueue() {
        let root = TempRoot::new();
        let st = Arc::new(DesktopState::new(root.0.clone()));
        let (app, _) = create(&st, "packets");
        st.set_app_since(app, st.epoch()).unwrap();
        let fence = st.admit_payload().unwrap();
        let execution_id = Id::new().to_string();
        let old_attempt = Id::new().to_string();
        let (pending, mut registration) = register_session(&st, &fence, &execution_id, &old_attempt).unwrap();
        let slot = registration.slot.clone();
        let received = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let log = received.clone();
        let state = st.clone();
        let (message_tx, mut message_rx) = tokio::sync::mpsc::unbounded_channel();
        let sink = session_sink(st.clone(), fence.clone(), execution_id.clone(), slot.clone(), move |packet| {
            assert!(state.sessions.try_lock().is_none(), "enqueue must exclude registration");
            let message = matches!(&packet.event, ExecutionEvent::Message { .. });
            let value = serde_json::to_value(packet).unwrap();
            log.lock().push(value.clone());
            if message {
                message_tx.send(value).unwrap();
            }
        });
        let peer = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("tcp://{}", peer.local_addr().unwrap());
        let mut spec = RequestSpec::http("GET", &url);
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
        let events = EventCtx { execution_id: id(&execution_id).unwrap(), sink: Some(sink.clone()) };
        let open = fence.app.engine.open_session(ExecutionContext::standalone(spec), events);
        let (session, canceled) = pending.open(open, |session| session).await.unwrap();
        publish_handle(&st, &fence, &slot, session, canceled).await;
        registration.published = true;
        let send = admit_control(&st, fence.clone(), &execution_id, &slot.attempt_id).unwrap();
        let command = SessionCommand::SendText { text: "real packet payload".into() };
        session_send(&st, send, command).await.unwrap();
        let packet = tokio::time::timeout(BOUND, message_rx.recv()).await.unwrap().unwrap();
        assert_eq!(packet["event"], "message");
        assert_eq!(packet["execution_id"], execution_id);
        assert_eq!(packet["attempt_id"], old_attempt);
        assert!(packet["message"]["preview"].as_str().unwrap().contains("real packet payload"));
        finish_slot(&slot).await;
        remove_slot(&st, &execution_id, &slot);
        let new_attempt = Id::new().to_string();
        let (_pending, replacement) = register_session(&st, &fence, &execution_id, &new_attempt).unwrap();
        let count = received.lock().len();
        let message = anvil_domain::execution::StreamMessage {
            direction: anvil_domain::execution::Direction::Received,
            offset_us: 1,
            kind: "text".into(),
            size: 5,
            preview: "stale".into(),
            preview_is_hex: false,
            preview_truncated: false,
            event_id: None,
            event_type: None,
        };
        sink(ExecutionEvent::Message { execution_id: id(&execution_id).unwrap(), message });
        sink(ExecutionEvent::BodyProgress { execution_id: id(&execution_id).unwrap(), bytes: 999 });
        assert_eq!(received.lock().len(), count, "retired callbacks cannot enqueue under the same epoch");
        let log = received.clone();
        let fresh = session_sink(st.clone(), fence, execution_id.clone(), replacement.slot.clone(), move |packet| {
            log.lock().push(serde_json::to_value(packet).unwrap())
        });
        fresh(ExecutionEvent::BodyProgress { execution_id: id(&execution_id).unwrap(), bytes: 64 });
        {
            let received = received.lock();
            assert_eq!(received.len(), count + 1);
            assert_eq!(received[count]["event"], "body_progress");
            assert_eq!(received[count]["execution_id"], execution_id);
            assert_eq!(received[count]["attempt_id"], new_attempt);
            assert_eq!(received[count]["bytes"], 64);
            for packet in &received[..count] {
                assert_eq!(packet["attempt_id"], old_attempt);
            }
        }
        st.lock();
        fresh(ExecutionEvent::BodyProgress { execution_id: id(&execution_id).unwrap(), bytes: 128 });
        assert_eq!(received.lock().len(), count + 1, "the shared epoch gate still fences packets");
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
            let consumer_release = Arc::new(parking_lot::Mutex::new(None));
            let observed_release = consumer_release.clone();
            let sink: anvil_transport::EventFn = Arc::new(move |ev| {
                if matches!(ev, ExecutionEvent::AttemptStarted { .. }) {
                    // Stall the real consumer before it can take a command.
                    let _ = entered_tx.send(());
                    *observed_release.lock() = Some(release.lock().recv_timeout(BOUND));
                }
            });
            let (slot, _peer) = open_tcp(&st, &fence, &execution_id, Some(sink)).await;
            let proof = async {
                entered_rx.recv_timeout(BOUND).map_err(|err| format!("the real consumer must enter its barrier: {err}"))?;
                for _ in 0..256 {
                    let control = admit_control(&st, fence.clone(), &execution_id, &slot.attempt_id)?;
                    tokio::time::timeout(BOUND, session_send(&st, control, SessionCommand::SendText { text: "queued".into() }))
                        .await
                        .map_err(|err| format!("the real queue's existing capacity must be available: {err}"))??;
                }
                let control = admit_control(&st, fence.clone(), &execution_id, &slot.attempt_id)?;
                let cancel = admit_control(&st, fence.clone(), &execution_id, &slot.attempt_id)?;
                let (waiting_tx, waiting_rx) = oneshot::channel();
                let sending = async {
                    let mut send = std::pin::pin!(session_send(&st, control, SessionCommand::SendText { text: "blocked".into() }));
                    let mut waiting_tx = Some(waiting_tx);
                    let sent = std::future::poll_fn(|cx| {
                        let polled = send.as_mut().poll(cx);
                        if polled.is_pending()
                            && let Some(waiting_tx) = waiting_tx.take()
                        {
                            let _ = waiting_tx.send(());
                        }
                        polled
                    })
                    .await;
                    if sent != Err(crate::commands::CANCELED.into()) {
                        return Err(format!("the blocked send must settle as CANCELED, got {sent:?}"));
                    }
                    Ok::<_, String>(())
                };
                let canceling = async {
                    waiting_rx.await.map_err(|err| format!("the actual send must become Pending before cancellation: {err}"))?;
                    // The first Pending is observed on the actual production
                    // send. It still owns the async slot mutex at this barrier.
                    if slot.session.try_lock().is_ok() {
                        return Err("the Pending send must still own the slot mutex".into());
                    }
                    if how == "cancel" {
                        session_cancel(&st, cancel).await?;
                    } else {
                        st.lock();
                        slot.abort().await;
                    }
                    // Lock also spawns an aborter. Tokio's fair mutex may
                    // reserve the next guard for it after our abort returns.
                    // Await our turn and release it so all aborters can settle.
                    drop(slot.session.lock().await);
                    Ok::<_, String>(())
                };
                tokio::try_join!(sending, canceling)?;
                Ok::<_, String>(())
            };
            let settled = tokio::time::timeout(BOUND, proof).await;
            // Preserve a failed proof until the blocked consumer is released
            // and its real engine task has been joined, including on timeout.
            let released = release_tx.send(());
            finish_slot(&slot).await;
            remove_slot(&st, &execution_id, &slot);
            settled.expect("cancel must release a send waiting on the real bounded queue").expect("the cancellation proof must hold");
            released.expect("release the stalled real consumer");
            assert_eq!(*consumer_release.lock(), Some(Ok(())), "the consumer must stay blocked until the proof settles: {how}");
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
                let (old_pending, old_registration) = register_session(&st, &old_fence, &execution_id, &Id::new().to_string()).unwrap();
                let old_slot = old_registration.slot.clone();
                let send = admit_control(&st, old_fence.clone(), &execution_id, &old_slot.attempt_id).unwrap();
                let cancel = admit_control(&st, old_fence.clone(), &execution_id, &old_slot.attempt_id).unwrap();
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
                        let (pending, mut registration) = register_session(&st, &fresh, &execution_id, &Id::new().to_string()).unwrap();
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
                    let control = admit_control(&st, fresh.clone(), &execution_id, &slot.attempt_id).unwrap();
                    session_send(&st, control, SessionCommand::SendText { text: "fresh".into() }).await.unwrap();
                }
                let control = admit_control(&st, fresh, &execution_id, &slot.attempt_id).unwrap();
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
        let send = admit_control(&st, fence.clone(), &execution_id, &slot.attempt_id).unwrap();
        session_send(&st, send, SessionCommand::SendText { text: "ordinary".into() }).await.unwrap();
        assert!(!slot.cancel.is_cancelled());
        let cancel = admit_control(&st, fence.clone(), &execution_id, &slot.attempt_id).unwrap();
        session_cancel(&st, cancel).await.unwrap();
        assert!(slot.cancel.is_cancelled());
        let session = slot.session.lock().await.take();
        let app = &fence.app;
        let key = execution_id.clone();
        let attempt_id = Id::new().to_string();
        let finish = finish_session(app, key, attempt_id.clone(), session);
        let ended = tokio::time::timeout(BOUND, finish).await.unwrap();
        assert!(ended.error.is_none());
        let record_id = ended.view.as_ref().unwrap().record.id.to_string();
        assert!(history_contains(app, &record_id));
        remove_slot(&st, &execution_id, &slot);
        let received = parking_lot::Mutex::new(Vec::new());
        emit_ended(&st, &fence, &slot, ended, |ev| {
            assert!(st.sessions.try_lock().is_none(), "enqueue must exclude registration");
            received.lock().push(serde_json::to_value(ev).unwrap());
        });
        let received = received.into_inner();
        assert_eq!(received.len(), 1);
        assert_eq!(received[0]["execution_id"], execution_id);
        assert_eq!(received[0]["attempt_id"], attempt_id);
        assert_eq!(received[0]["view"]["record"]["id"], record_id);
        assert!(received[0]["error"].is_null());
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
        let (pending, registration) = register_session(&st, &fresh, &execution_id, &Id::new().to_string()).unwrap();
        publish_handle(&st, &fence, &old_slot, session, true).await;
        let session = old_slot.session.lock().await.take();
        assert!(session.is_some(), "completed handle retained for finalization");
        let app = &fence.app;
        let key = execution_id.clone();
        let attempt_id = Id::new().to_string();
        let finish = finish_session(app, key, attempt_id, session);
        let ended = tokio::time::timeout(BOUND, finish).await.unwrap();
        assert!(ended.error.is_none());
        let record_id = ended.view.as_ref().unwrap().record.id.to_string();
        assert!(history_contains(app, &record_id));
        remove_slot(&st, &execution_id, &old_slot);
        assert!(!pending.token().is_cancelled());
        assert!(st.sessions.lock().get(&execution_id).is_some_and(|(_, slot)| Arc::ptr_eq(slot, &registration.slot)));
        let received = parking_lot::Mutex::new(Vec::new());
        emit_ended(&st, &fence, &old_slot, ended, |ev| received.lock().push(ev));
        assert!(received.lock().is_empty(), "old scalar completion must not retire replacement");
        let attempt = &registration.slot.attempt_id;
        let cancel = admit_control(&st, fresh, &execution_id, attempt).unwrap();
        session_cancel(&st, cancel).await.unwrap();
        assert!(pending.token().is_cancelled());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn history_barrier_completion_cannot_retire_a_reused_id_slot() {
        for transition in ["same-epoch", "lock-unlock", "locked-profile"] {
            for live in [false, true] {
                let root = TempRoot::new();
                let st = DesktopState::new(root.0.clone());
                let (app, dir) = create(&st, "old");
                let (other, _) = create(&st, "other");
                st.set_app_since(app, st.epoch()).unwrap();
                let fence = st.admit_payload().unwrap();
                let execution_id = Id::new().to_string();
                let attempt_id = Id::new().to_string();
                let (old_slot, _old_peer) = open_tcp(&st, &fence, &execution_id, None).await;
                old_slot.abort().await;
                let session = old_slot.session.lock().await.take();
                assert!(session.is_some());
                // The production watcher retires the slot before awaiting
                // finish/history. Pause there, then install a replacement.
                remove_slot(&st, &execution_id, &old_slot);
                let (ready_tx, ready_rx) = oneshot::channel();
                let (release_tx, release_rx) = oneshot::channel();
                let finalizing = async {
                    ready_tx.send(()).unwrap();
                    release_rx.await.unwrap();
                    let app = &fence.app;
                    let key = execution_id.clone();
                    let ended = finish_session(app, key, attempt_id, session).await;
                    let record_id = ended.view.as_ref().unwrap().record.id.to_string();
                    if transition == "locked-profile" {
                        assert!(app.is_locked());
                        assert!(ended.error.is_some());
                    } else {
                        assert!(ended.error.is_none());
                        assert!(history_contains(app, &record_id));
                    }
                    let received = parking_lot::Mutex::new(Vec::new());
                    emit_ended(&st, &fence, &old_slot, ended, |ev| received.lock().push(ev));
                    assert!(received.lock().is_empty(), "{transition}, live={live}");
                };
                let replacing = async {
                    ready_rx.await.unwrap();
                    match transition {
                        "same-epoch" => {}
                        "lock-unlock" => {
                            st.lock();
                            let unlock = Unlock::Passphrase(PASSPHRASE);
                            let (_, key) = ProfileManager::unlock(&dir, unlock).unwrap();
                            st.unlock_since(&fence.app, key, st.epoch()).unwrap();
                        }
                        "locked-profile" => {
                            st.lock();
                            st.set_app_since(other, st.epoch()).unwrap();
                        }
                        _ => unreachable!(),
                    }
                    let fresh = st.admit_payload().unwrap();
                    let (pending, registration, slot, peer) = if live {
                        let (slot, peer) = open_tcp(&st, &fresh, &execution_id, None).await;
                        (None, None, slot, Some(peer))
                    } else {
                        let (pending, reg) = register_session(&st, &fresh, &execution_id, &Id::new().to_string()).unwrap();
                        let slot = reg.slot.clone();
                        (Some(pending), Some(reg), slot, None)
                    };
                    release_tx.send(()).unwrap();
                    (fresh, pending, registration, slot, peer)
                };
                let work = async { tokio::join!(finalizing, replacing) };
                let completed = tokio::time::timeout(BOUND, work).await.unwrap();
                let (_, (fresh, pending, _registration, slot, _peer)) = completed;
                let current = st.sessions.lock().get(&execution_id).cloned();
                assert!(current.is_some_and(|(_, current)| Arc::ptr_eq(&current, &slot)));
                assert!(!slot.cancel.is_cancelled());
                if let Some(pending) = pending.as_ref() {
                    assert!(!pending.token().is_cancelled());
                }
                // Its production controls still reach the replacement.
                if live {
                    let send = admit_control(&st, fresh.clone(), &execution_id, &slot.attempt_id).unwrap();
                    let command = SessionCommand::SendText { text: "replacement".into() };
                    session_send(&st, send, command).await.unwrap();
                }
                let cancel = admit_control(&st, fresh, &execution_id, &slot.attempt_id).unwrap();
                session_cancel(&st, cancel).await.unwrap();
                assert!(slot.cancel.is_cancelled());
                finish_slot(&slot).await;
                remove_slot(&st, &execution_id, &slot);
            }
        }
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
            let view = payload_view();
            let execution_id = view.record.id.to_string();
            let attempt_id = Id::new().to_string();
            let (pending, registration) = register_session(&st, &fence, &execution_id, &attempt_id).unwrap();
            let slot = registration.slot.clone();
            drop(pending);
            drop(registration);
            let (ready_tx, ready_rx) = oneshot::channel();
            let (release_tx, release_rx) = oneshot::channel();
            let finalizing = async {
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
                    attempt_id: attempt_id.clone(),
                    view: Some(ExecutionView { record: output.record, body: body_view(&output.body, None, None) }),
                    error: Some("payload-canary recording error".into()),
                };
                let received = parking_lot::Mutex::new(Vec::new());
                emit_ended(&st, &fence, &slot, ended, |ev| {
                    assert!(st.sessions.try_lock().is_none(), "enqueue must exclude registration");
                    received.lock().push(serde_json::to_value(ev).unwrap());
                });
                let received = received.into_inner();
                assert_eq!(received.len(), 1);
                assert_eq!(received[0]["execution_id"], execution_id);
                assert_eq!(received[0]["attempt_id"], attempt_id);
                if transition == "unchanged" {
                    assert_eq!(received[0]["view"]["body"]["text"], "payload-canary");
                    assert_eq!(received[0]["error"], "payload-canary recording error");
                } else {
                    assert!(received[0]["view"].is_null(), "{transition}");
                    assert_eq!(received[0]["error"], "LOCKED");
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
