//! Library side of the managed worker: spawns `anvil-load-worker` (path
//! supplied by the host app — never taken from an imported plan), writes the
//! job to its stdin, forwards cancel, relays throttled progress and always
//! produces a report — the worker's own, or, if the worker dies, a partial
//! `WorkerCrashed` report rebuilt from the last progress snapshot (LOAD-009).

use crate::LoadError;
use crate::executor::{HARD_CANCEL_GRACE, Progress};
use crate::job::WorkerJob;
use crate::report::{self, RunMeta};
use crate::worker::{MAX_MESSAGE_BYTES, WorkerMessage};
use anvil_domain::Id;
use anvil_domain::load::{LoadPlan, LoadReport, RunCompletion, TimeBucket};
use chrono::Utc;
use std::path::Path;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

/// Extra time allowed after the worker's own drain before it is killed.
const KILL_MARGIN: Duration = Duration::from_secs(5);
const PROGRESS_QUEUE: usize = 16;

pub struct LoadController {
    pid: Option<u32>,
    stdin: Arc<tokio::sync::Mutex<Option<ChildStdin>>>,
    progress: mpsc::Receiver<Progress>,
    result: Option<oneshot::Receiver<Result<LoadReport, LoadError>>>,
    kill: CancellationToken,
    cancel_deadline: Duration,
}

impl LoadController {
    /// Spawn the worker at `worker` and hand it `job` over stdin. The
    /// command line carries no arguments, so nothing secret is visible in
    /// the process table.
    pub async fn spawn(worker: &Path, job: &WorkerJob) -> Result<LoadController, LoadError> {
        let mut child = tokio::process::Command::new(worker)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| LoadError::Io(format!("starting the load worker {}: {e}", worker.display())))?;
        let pid = child.id();
        let mut stdin = child.stdin.take().ok_or_else(|| LoadError::Io("worker stdin unavailable".into()))?;
        let stdout = child.stdout.take().ok_or_else(|| LoadError::Io("worker stdout unavailable".into()))?;
        let mut payload = Zeroizing::new(serde_json::to_vec(job).map_err(|e| LoadError::Protocol(e.to_string()))?);
        payload.push(b'\n');
        if let Err(e) = async {
            stdin.write_all(&payload).await?;
            stdin.flush().await
        }
        .await
        {
            let _ = child.start_kill();
            return Err(LoadError::Io(format!("sending the job to the worker: {e}")));
        }
        drop(payload);
        let (ptx, prx) = mpsc::channel(PROGRESS_QUEUE);
        let (rtx, rrx) = oneshot::channel();
        let kill = CancellationToken::new();
        tokio::spawn(supervise(child, stdout, job.plan.clone(), ptx, rtx, kill.clone()));
        let cancel_deadline = Duration::from_millis(job.options.cancel_drain_ms) + HARD_CANCEL_GRACE + KILL_MARGIN;
        Ok(LoadController {
            pid,
            stdin: Arc::new(tokio::sync::Mutex::new(Some(stdin))),
            progress: prx,
            result: Some(rrx),
            kill,
            cancel_deadline,
        })
    }

    pub fn pid(&self) -> Option<u32> {
        self.pid
    }

    /// Ask the worker to stop: sends `{"cancel":true}` and closes stdin. If
    /// the worker has not finished within its drain window plus a margin, it
    /// is killed and the report is rebuilt from the last progress.
    pub async fn cancel(&self) {
        if let Some(mut s) = self.stdin.lock().await.take() {
            let _ = s.write_all(b"{\"cancel\":true}\n").await;
            let _ = s.flush().await;
        }
        let (kill, deadline) = (self.kill.clone(), self.cancel_deadline);
        tokio::spawn(async move {
            tokio::time::sleep(deadline).await;
            kill.cancel();
        });
    }

    /// Hard-stop the worker immediately (SIGKILL on Unix).
    pub fn kill(&self) {
        self.kill.cancel();
    }

    /// Next throttled progress snapshot; `None` once the worker has exited.
    /// Progress is lossy: a slow consumer misses intermediate snapshots.
    pub async fn next_progress(&mut self) -> Option<Progress> {
        self.progress.recv().await
    }

    /// The final report. `Err` only when the worker refused the job before
    /// sending any traffic.
    pub async fn wait(mut self) -> Result<LoadReport, LoadError> {
        let rx = self.result.take().expect("wait is called once");
        rx.await.unwrap_or_else(|_| Err(LoadError::Io("the worker supervisor stopped unexpectedly".into())))
    }
}

impl Drop for LoadController {
    fn drop(&mut self) {
        // Close stdin (EOF = graceful cancel in the worker), then make sure
        // the process does not outlive a bounded window.
        if let Ok(mut g) = self.stdin.try_lock() {
            g.take();
        }
        if self.result.is_some() {
            let (kill, deadline) = (self.kill.clone(), self.cancel_deadline);
            if let Ok(h) = tokio::runtime::Handle::try_current() {
                h.spawn(async move {
                    tokio::time::sleep(deadline).await;
                    kill.cancel();
                });
            } else {
                kill.cancel();
            }
        }
    }
}

fn crash_report(
    plan: &LoadPlan,
    meta: Option<RunMeta>,
    last: Option<Progress>,
    timeline: Vec<TimeBucket>,
    status: String,
    killed_by_controller: bool,
) -> LoadReport {
    let meta = meta.unwrap_or_else(|| RunMeta {
        run_id: Id::new(),
        engine: crate::ENGINE_NAME.into(),
        engine_version: crate::engine_version(),
        plan: plan.clone(),
        request_revisions: vec![],
        dataset_sha256: None,
        started_at: Utc::now(),
    });
    let (snap, at) = match last {
        Some(p) => (p.snapshot, format!("{:.1} s", p.elapsed_secs)),
        None => (Default::default(), "none (no progress was received)".into()),
    };
    let in_flight = snap.requests.in_flight_at_end;
    let mut notes = vec![format!(
        "The load worker exited without a final report ({status}){}. Metrics come from the last progress snapshot ({at}); sends after that snapshot are not included, and the outcome of the {in_flight} send(s) in flight at that moment is unknown (reported as in flight at end).",
        if killed_by_controller { " after it was stopped by the controller" } else { "" }
    )];
    notes.push("This is an incomplete report: do not read it as a full-duration result.".into());
    report::assemble(&meta, snap, timeline, RunCompletion::WorkerCrashed, Utc::now(), notes)
}

async fn supervise(
    mut child: Child,
    stdout: ChildStdout,
    plan: LoadPlan,
    ptx: mpsc::Sender<Progress>,
    rtx: oneshot::Sender<Result<LoadReport, LoadError>>,
    kill: CancellationToken,
) {
    let mut reader = BufReader::new(stdout);
    let mut meta: Option<RunMeta> = None;
    let mut last: Option<Progress> = None;
    let mut timeline: Vec<TimeBucket> = Vec::new();
    let mut final_report: Option<LoadReport> = None;
    let mut refused: Option<String> = None;
    let mut killed = false;
    let mut buf = Vec::new();
    loop {
        buf.clear();
        let mut limited = (&mut reader).take(MAX_MESSAGE_BYTES as u64);
        let read = tokio::select! {
            r = limited.read_until(b'\n', &mut buf) => r,
            _ = kill.cancelled(), if !killed => {
                killed = true;
                let _ = child.start_kill();
                continue;
            }
        };
        match read {
            Ok(0) | Err(_) => break,
            Ok(n) if n >= MAX_MESSAGE_BYTES && !buf.ends_with(b"\n") => {
                // Protocol violation: stop the worker rather than buffer without bound.
                killed = true;
                let _ = child.start_kill();
                break;
            }
            Ok(_) => {}
        }
        match serde_json::from_slice::<WorkerMessage>(buf.trim_ascii()) {
            Ok(WorkerMessage::Started { meta: m, .. }) => meta = Some(*m),
            Ok(WorkerMessage::Progress { progress }) => {
                if progress.timeline_from <= timeline.len() {
                    timeline.truncate(progress.timeline_from);
                    timeline.extend(progress.timeline_delta.iter().cloned());
                }
                let _ = ptx.try_send((*progress).clone());
                last = Some(*progress);
            }
            Ok(WorkerMessage::Report { report }) => final_report = Some(*report),
            Ok(WorkerMessage::Error { message }) => refused = Some(message),
            Err(_) => {}
        }
    }
    let status = match child.wait().await {
        Ok(s) => s.to_string(),
        Err(e) => format!("wait failed: {e}"),
    };
    drop(ptx);
    let result = match (final_report, refused, meta.is_some()) {
        (Some(r), _, _) => Ok(r),
        (None, Some(msg), false) => Err(LoadError::Invalid(msg)),
        _ => Ok(crash_report(&plan, meta, last, timeline, status, killed)),
    };
    let _ = rtx.send(result);
}
