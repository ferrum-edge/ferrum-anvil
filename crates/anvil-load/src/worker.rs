//! `anvil-load-worker` process protocol.
//!
//! **stdin**: line 1 is one JSON [`WorkerJob`] (bounded size). Afterwards the
//! worker watches stdin: a `{"cancel":true}` line **or EOF** (the parent went
//! away) cancels the run — scheduling stops, in-flight sends get the bounded
//! drain window, and a partial report is emitted. Secrets are never read from
//! argv or the environment.
//!
//! **stdout**: newline-delimited JSON [`WorkerMessage`]s — `started`,
//! throttled `progress` (≤ 4/s, lossy under backpressure), and exactly one
//! final `report` (or `error` if the job was refused before any traffic).

use crate::LoadError;
use crate::executor::{LoadRun, Progress, ProgressSink};
use crate::job::WorkerJob;
use crate::report::RunMeta;
use anvil_domain::load::LoadReport;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

/// Upper bound on the job line (plan, contexts, attachments, dataset).
pub const MAX_JOB_BYTES: usize = 256 * 1024 * 1024;
/// Upper bound on one stdout message line read by the controller.
pub const MAX_MESSAGE_BYTES: usize = 64 * 1024 * 1024;
const MAX_CONTROL_LINE: u64 = 4096;
const STDOUT_QUEUE: usize = 8;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WorkerMessage {
    Started {
        meta: Box<RunMeta>,
        pid: u32,
    },
    Progress {
        progress: Box<Progress>,
    },
    Report {
        report: Box<LoadReport>,
    },
    /// The job was refused; nothing was sent.
    Error {
        message: String,
    },
}

#[derive(Deserialize)]
struct ControlLine {
    #[serde(default)]
    cancel: bool,
}

fn line(m: &WorkerMessage) -> String {
    serde_json::to_string(m).expect("worker messages serialize")
}

/// Parse the job without echoing any of its content in errors (serde error
/// text can quote values, which may be secrets).
pub fn parse_job(bytes: &[u8]) -> Result<WorkerJob, LoadError> {
    serde_json::from_slice(bytes).map_err(|e| {
        LoadError::Protocol(format!("the job on stdin is not valid JSON for this worker (line {}, column {})", e.line(), e.column()))
    })
}

/// Run one job over arbitrary streams (the binary passes stdin/stdout).
/// Returns the process exit code.
pub async fn serve<R, W>(input: R, output: W) -> i32
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(STDOUT_QUEUE);
    let writer = tokio::spawn(async move {
        let mut out = output;
        while let Some(l) = rx.recv().await {
            if out.write_all(l.as_bytes()).await.is_err() || out.write_all(b"\n").await.is_err() || out.flush().await.is_err() {
                // Parent gone; keep draining so senders never block.
                while rx.recv().await.is_some() {}
                break;
            }
        }
    });
    let code = run(input, tx).await;
    let _ = writer.await;
    code
}

async fn run<R: AsyncRead + Unpin + Send + 'static>(input: R, tx: tokio::sync::mpsc::Sender<String>) -> i32 {
    let mut reader = BufReader::new(input);
    let mut buf = Zeroizing::new(Vec::new());
    let read = (&mut reader).take(MAX_JOB_BYTES as u64 + 1).read_until(b'\n', &mut buf).await;
    let refuse = |msg: String| {
        let tx = tx.clone();
        async move {
            let _ = tx.send(line(&WorkerMessage::Error { message: msg })).await;
            2
        }
    };
    match read {
        Ok(0) => return refuse("no job was provided on stdin".into()).await,
        Err(e) => return refuse(format!("reading the job from stdin failed: {e}")).await,
        Ok(_) if buf.len() > MAX_JOB_BYTES => return refuse(format!("the job exceeds {MAX_JOB_BYTES} bytes")).await,
        Ok(_) => {}
    }
    let job = match parse_job(&buf) {
        Ok(j) => j,
        Err(e) => return refuse(e.to_string()).await,
    };
    drop(buf);
    let prepared = job.into_load_job().and_then(|(plan, lj, opts)| LoadRun::prepare(plan, lj, opts));
    let run = match prepared {
        Ok(r) => r,
        Err(e) => return refuse(e.to_string()).await,
    };

    // Cancel on a {"cancel":true} line or on EOF (parent gone).
    let cancel = CancellationToken::new();
    {
        let cancel = cancel.clone();
        tokio::spawn(async move {
            let mut l = Vec::new();
            loop {
                l.clear();
                match (&mut reader).take(MAX_CONTROL_LINE).read_until(b'\n', &mut l).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {
                        if serde_json::from_slice::<ControlLine>(l.trim_ascii()).is_ok_and(|c| c.cancel) {
                            break;
                        }
                    }
                }
            }
            cancel.cancel();
        });
    }
    let _ = tx.send(line(&WorkerMessage::Started { meta: Box::new(run.meta().clone()), pid: std::process::id() })).await;
    let ptx = tx.clone();
    let sink: ProgressSink =
        Arc::new(move |p: &Progress| ptx.try_send(line(&WorkerMessage::Progress { progress: Box::new(p.clone()) })).is_ok());
    let report = run.execute(cancel, Some(sink)).await;
    let _ = tx.send(line(&WorkerMessage::Report { report: Box::new(report) })).await;
    0
}

/// Entry point used by the `anvil-load-worker` binary.
pub async fn run_stdio() -> i32 {
    serve(tokio::io::stdin(), tokio::io::stdout()).await
}
