//! Barriers around the production transport/runner sinks and IPC dispatcher.

use crate::cmd_runner::{RunFinished, emit_finished, run_event_sink};
use crate::commands::{dispatch_payload_reply, execution_sink};
use crate::state::tests::{PASSPHRASE, TempRoot, create};
use crate::state::{DesktopState, PayloadFence};
use anvil_app::profiles::{ProfileManager, Unlock};
use anvil_domain::Id;
use anvil_domain::events::ExecutionEvent;
use anvil_domain::execution::{Direction, StreamMessage};
use anvil_domain::runner::{RunEvent, RunProgress, RunStepStatus, RunnerCompletion};
use parking_lot::Mutex;
use serde::{Serialize, Serializer};
use std::sync::{Arc, mpsc};
use std::time::Duration;
use tauri::ipc::InvokeResponse;

const BOUND: Duration = Duration::from_secs(10);

fn message() -> ExecutionEvent {
    ExecutionEvent::Message {
        execution_id: Id::new(),
        message: StreamMessage {
            direction: Direction::Received,
            offset_us: 1,
            kind: "text".into(),
            size: 14,
            preview: "payload-canary".into(),
            preview_is_hex: false,
            preview_truncated: false,
            event_id: None,
            event_type: None,
        },
    }
}

fn run_events() -> Vec<RunEvent> {
    let run_id = Id::new();
    vec![
        RunEvent::RunStarted { run_id, name: "payload-canary".into(), iterations: 1, steps: 1 },
        RunEvent::StepFinished {
            run_id,
            iteration: 0,
            step: 0,
            status: RunStepStatus::Failed,
            execution_id: Some(Id::new()),
            http_status: Some(500),
            duration_ms: Some(1),
            progress: RunProgress::default(),
        },
        RunEvent::RunFinished { run_id, completion: RunnerCompletion::Completed, progress: RunProgress::default(), dropped_events: 0 },
    ]
}

fn transition(st: &DesktopState, fence: &PayloadFence, dir: &std::path::Path, how: &str) {
    match how {
        "lock" => st.lock(),
        "lock-unlock" => {
            st.lock();
            let (_, key) = ProfileManager::unlock(dir, Unlock::Passphrase(PASSPHRASE)).unwrap();
            st.unlock_since(&fence.app, key, st.epoch()).unwrap();
        }
        "profile" => {
            let (other, _) = create(st, "B");
            st.set_app_since(other, st.epoch()).unwrap();
        }
        "unchanged" => {}
        _ => unreachable!(),
    }
}

#[test]
fn paused_production_callbacks_and_ipc_responses_revalidate_at_enqueue() {
    for how in ["lock", "lock-unlock", "profile", "unchanged"] {
        let root = TempRoot::new();
        let st = Arc::new(DesktopState::new(root.0.clone()));
        let (app, dir) = create(&st, "A");
        st.set_app_since(app, st.epoch()).unwrap();
        let fence = st.admit_payload().unwrap();
        let received = Arc::new(Mutex::new(Vec::new()));
        // These are the exact callback constructors used by session_open,
        // send_request and run_start, with the same native state access.
        let session_log = received.clone();
        let session = execution_sink(st.clone(), fence.clone(), false, move |ev| {
            session_log.lock().push(serde_json::to_value(ev).unwrap());
        });
        let send_log = received.clone();
        let send = execution_sink(st.clone(), fence.clone(), true, move |ev| {
            send_log.lock().push(serde_json::to_value(ev).unwrap());
        });
        let run_log = received.clone();
        let run = run_event_sink(st.clone(), fence.clone(), move |ev| {
            run_log.lock().push(serde_json::to_value(ev).unwrap());
        });
        let (ready_tx, ready_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let callbacks = std::thread::spawn(move || {
            let event = message();
            let events = run_events();
            ready_tx.send(()).unwrap();
            release_rx.recv_timeout(BOUND).unwrap();
            session(event.clone());
            send(event);
            for event in events {
                run(event);
            }
        });
        // Pause the real async reply pipeline after materializing both a
        // full view and a detailed failure, before Tauri serialization.
        let mut replies = Vec::new();
        let mut releases = Vec::new();
        for out in [Ok(crate::commands::tests::payload_view()), Err("payload-canary error".into())] {
            let (built_tx, built_rx) = mpsc::channel();
            let (go_tx, go_rx) = tokio::sync::oneshot::channel();
            let (reply_tx, reply_rx) = mpsc::channel();
            dispatch_payload_reply(
                st.clone(),
                fence.clone(),
                async move {
                    built_tx.send(()).unwrap();
                    go_rx.await.unwrap();
                    out
                },
                move |response| reply_tx.send(response).unwrap(),
            );
            built_rx.recv_timeout(BOUND).unwrap();
            replies.push(reply_rx);
            releases.push(go_tx);
        }
        ready_rx.recv_timeout(BOUND).unwrap();
        transition(&st, &fence, &dir, how);
        release_tx.send(()).unwrap();
        for release in releases {
            release.send(()).unwrap();
        }
        callbacks.join().unwrap();
        assert_eq!(received.lock().len(), if how == "unchanged" { 5 } else { 0 }, "{how}");
        for (index, reply) in replies.into_iter().enumerate() {
            match reply.recv_timeout(BOUND).unwrap() {
                InvokeResponse::Ok(body) if how == "unchanged" && index == 0 => {
                    let view = body.deserialize::<serde_json::Value>().unwrap();
                    assert_eq!(view["body"]["text"], "payload-canary");
                }
                InvokeResponse::Err(err) if how != "unchanged" || index == 1 => {
                    let expected = if how == "unchanged" { "payload-canary error" } else { "LOCKED" };
                    assert_eq!(err.0, serde_json::json!(expected));
                }
                _ => panic!("unexpected response after {how}"),
            }
        }
        let finished = Mutex::new(Vec::new());
        emit_finished(&st, &fence, RunFinished { run_id: "run".into(), error: Some("payload-canary error".into()) }, |ev| {
            finished.lock().push(ev);
        });
        let finished = finished.into_inner();
        assert_eq!(finished.len(), 1);
        assert_eq!(finished[0].error.as_deref(), Some(if how == "unchanged" { "payload-canary error" } else { "LOCKED" }));
    }
}

struct PausedSerialization {
    entered: mpsc::Sender<()>,
    release: mpsc::Receiver<()>,
}

impl Serialize for PausedSerialization {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.entered.send(()).unwrap();
        self.release.recv_timeout(BOUND).unwrap();
        "payload-canary".serialize(serializer)
    }
}

#[test]
fn unlocked_reply_contention_preserves_session_messages_and_critical_run_events() {
    let root = TempRoot::new();
    let st = Arc::new(DesktopState::new(root.0.clone()));
    let (app, _) = create(&st, "shared");
    st.set_app_since(app, st.epoch()).unwrap();
    let fence = st.admit_payload().unwrap();
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let (reply_tx, reply_rx) = mpsc::channel();
    dispatch_payload_reply(
        st.clone(),
        fence.clone(),
        async move { Ok(PausedSerialization { entered: entered_tx, release: release_rx }) },
        move |response| reply_tx.send(response).unwrap(),
    );
    entered_rx.recv_timeout(BOUND).unwrap();
    let received = Arc::new(Mutex::new(Vec::new()));
    let log = received.clone();
    let session = execution_sink(st.clone(), fence.clone(), false, move |ev| log.lock().push(serde_json::to_value(ev).unwrap()));
    let log = received.clone();
    let run = run_event_sink(st.clone(), fence.clone(), move |ev| log.lock().push(serde_json::to_value(ev).unwrap()));
    let (done_tx, done_rx) = mpsc::channel();
    let callback = std::thread::spawn(move || {
        session(message());
        for event in run_events() {
            run(event);
        }
        done_tx.send(()).unwrap();
    });
    // Completion while serialization is STILL paused proves shared delivery,
    // rather than silently dropping callbacks or deferring them unboundedly.
    let completed = done_rx.recv_timeout(BOUND);
    release_tx.send(()).unwrap();
    callback.join().unwrap();
    completed.expect("live callbacks must complete beside an unlocked reply");
    let log = received.lock();
    assert_eq!(log.len(), 4);
    assert_eq!(log[0]["message"]["preview"], "payload-canary");
    assert_eq!(log[1]["event"], "run_started");
    assert_eq!(log[2]["status"], "failed");
    assert_eq!(log[3]["event"], "run_finished");
    assert_eq!(log[3]["dropped_events"], 0);
    assert!(matches!(reply_rx.recv_timeout(BOUND).unwrap(), InvokeResponse::Ok(_)));
}

#[test]
fn an_actual_callback_enqueue_completes_before_lock_and_cannot_be_retracted() {
    let root = TempRoot::new();
    let st = Arc::new(DesktopState::new(root.0.clone()));
    let (app, _) = create(&st, "enqueue");
    st.set_app_since(app, st.epoch()).unwrap();
    let fence = st.admit_payload().unwrap();
    let received = Arc::new(Mutex::new(Vec::new()));
    let log = received.clone();
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let release = Mutex::new(release_rx);
    let sink = execution_sink(st.clone(), fence.clone(), false, move |ev| {
        entered_tx.send(()).unwrap();
        release.lock().recv_timeout(BOUND).unwrap();
        log.lock().push(ev.clone());
    });
    let emitting = std::thread::spawn(move || sink(message()));
    entered_rx.recv_timeout(BOUND).unwrap();
    let admitted = st.epoch();
    let locking_st = st.clone();
    let (locked_tx, locked_rx) = mpsc::channel();
    let locking = std::thread::spawn(move || {
        locking_st.lock();
        locked_tx.send(()).unwrap();
    });
    // The actual lock is blocked on the gate the paused enqueue still holds.
    st.await_gate_writer(BOUND);
    assert_eq!(st.epoch(), admitted);
    assert!(locked_rx.try_recv().is_err());
    assert!(received.lock().is_empty());
    release_tx.send(()).unwrap();
    emitting.join().unwrap();
    locked_rx.recv_timeout(BOUND).unwrap();
    locking.join().unwrap();
    assert_eq!(received.lock().len(), 1);
    let late = execution_sink(st.clone(), fence, false, |_| panic!("post-lock enqueue"));
    late(message());
}
