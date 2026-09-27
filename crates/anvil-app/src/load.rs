//! Load plans and runs. The expensive work happens in a separate worker
//! process (`anvil-load`); this module freezes each referenced request into
//! the same `ExecutionContext` a manual Send uses, resolves the dataset, and
//! stores plans and reports in the encrypted store.

use crate::exec::SendOptions;
use crate::file_grants::FilePurpose;
use crate::{App, AppError, Result};
use anvil_domain::Id;
use anvil_domain::load::{LoadPlan, LoadReport, LoadUnitKind, UnitSemantics};
use anvil_domain::request::{AttachmentRef, Protocol};
use anvil_domain::workspace::DatasetFormat as DomainDatasetFormat;
use anvil_domain::workspace::Workspace;
use anvil_load::{Dataset, DatasetFormat, LoadJob, Refusal, RunOptions, WorkerJob};
use anvil_storage::StoreError;
use anvil_storage::store::kind;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio_util::sync::CancellationToken;

/// The load runs of an opened profile, by workspace: a lock stops every
/// one, and deleting a workspace stops that workspace's. Shared by every
/// [`App::shared`] handle.
#[derive(Default)]
pub(crate) struct LoadRuns {
    next: AtomicU64,
    runs: Mutex<HashMap<u64, (Id, LoadRunStops)>>,
}

#[derive(Clone, Default)]
struct LoadRunStops {
    locked: CancellationToken,
    workspace_deleted: CancellationToken,
}

impl LoadRuns {
    fn stop_all_for_lock(&self) {
        for (_, stops) in self.runs.lock().values() {
            stops.locked.cancel();
        }
    }

    fn stop_workspace(&self, ws: &Id) {
        for (_, stops) in self.runs.lock().values().filter(|(w, _)| w == ws) {
            stops.workspace_deleted.cancel();
        }
    }
}

/// A load run's registration with its profile ([`App::register_load_run`]),
/// removed when this is dropped. Whoever drives the run (the desktop, a
/// worker controller, an in-process run) stops it when a token is canceled:
/// its engines, connection pools, sessions and secrets end with it.
pub struct LoadRunGuard {
    runs: Arc<LoadRuns>,
    key: u64,
    stops: LoadRunStops,
}

impl LoadRunGuard {
    /// Canceled when the profile locks (and so when another profile opens).
    pub fn locked(&self) -> &CancellationToken {
        &self.stops.locked
    }

    /// Canceled when the run's workspace is deleted. Its report is not kept:
    /// [`App::save_load_report`] refuses a report of a workspace that is gone.
    pub fn workspace_deleted(&self) -> &CancellationToken {
        &self.stops.workspace_deleted
    }

    /// Whether the run must stop, for either reason.
    pub fn is_stopped(&self) -> bool {
        self.stops.locked.is_cancelled() || self.stops.workspace_deleted.is_cancelled()
    }
}

impl Drop for LoadRunGuard {
    fn drop(&mut self) {
        self.runs.runs.lock().remove(&self.key);
    }
}

/// Summary row for report lists (the full report is fetched on demand).
#[derive(Debug, Clone, serde::Serialize)]
pub struct LoadReportSummary {
    pub run_id: Id,
    pub plan_id: Id,
    pub plan_name: String,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub completion: anvil_domain::load::RunCompletion,
    pub partial: bool,
    pub achieved_rate_per_sec: f64,
    pub started: u64,
    pub failures: u64,
    /// p95 of successful units; `None` when no unit succeeded.
    pub p95_us: Option<u64>,
    /// What one unit of the run was (requests, sessions, exchanges, ...).
    pub unit: LoadUnitKind,
}

/// What a plan would measure, or why it cannot run (checked without sending
/// anything; the editor shows it while the plan is being built).
#[derive(Debug, Clone, serde::Serialize)]
pub struct LoadPlanCheck {
    /// `None` when the plan is refused or has no requests yet.
    pub unit: Option<LoadUnitKind>,
    pub unit_label: Option<String>,
    pub semantics: Option<UnitSemantics>,
    /// A typed refusal (LOAD-013), raised before any traffic.
    pub refusal: Option<Refusal>,
    /// The protocol of each request the plan references, in plan order.
    pub protocols: Vec<(Id, Protocol)>,
}

/// What the user must see and acknowledge before a run starts.
#[derive(Debug, Clone, serde::Serialize)]
pub struct LoadPreflight {
    /// `METHOD scheme://host[:port]` of every request in the plan (redacted
    /// URLs, no query values).
    pub destinations: Vec<String>,
    pub workload: String,
    pub max_duration_secs: u64,
    pub peak_target: u64,
    pub dataset_rows: Option<usize>,
    pub trusted: bool,
    pub warnings: Vec<String>,
    /// The unit every count in the report will be per, and its definitions.
    pub unit: LoadUnitKind,
    pub unit_label: String,
    pub semantics: UnitSemantics,
}

impl App {
    /// Register a load run of workspace `ws` before its job is prepared, so a
    /// lock or a delete of `ws` from now on reaches it (see [`LoadRunGuard`]).
    /// One that landed before the registration is seen here: the guard is then
    /// stopped already. Fails, registering nothing, when whether `ws` still
    /// exists cannot be read (a busy database, a row that does not decode,
    /// an I/O error).
    pub fn register_load_run(&self, ws: &Id) -> Result<LoadRunGuard> {
        let stops = LoadRunStops::default();
        let key = self.load_runs.next.fetch_add(1, Ordering::Relaxed);
        self.load_runs.runs.lock().insert(key, (*ws, stops.clone()));
        let guard = LoadRunGuard { runs: self.load_runs.clone(), key, stops };
        // A lock locks the store before it stops the registered runs, and a
        // delete commits before it does: either that stop sees this entry,
        // or this read sees the lock or the delete.
        match self.store.get::<Workspace>(kind::WORKSPACE, ws) {
            Ok(Some(_)) => {}
            Ok(None) => guard.stops.workspace_deleted.cancel(),
            Err(StoreError::Locked) => guard.stops.locked.cancel(),
            // The guard is dropped, and with it the registration.
            Err(e) => return Err(e.into()),
        }
        Ok(guard)
    }

    /// Stop every registered load run (see [`App::lock`]).
    pub(crate) fn stop_load_runs(&self) {
        self.load_runs.stop_all_for_lock();
    }

    /// Stop the registered load runs of workspace `ws` (see
    /// [`App::delete_workspace`]).
    pub(crate) fn stop_load_runs_of(&self, ws: &Id) {
        self.load_runs.stop_workspace(ws);
    }

    pub fn load_plans(&self, ws: &Id) -> Result<Vec<LoadPlan>> {
        Ok(self.store.list(kind::LOAD_PLAN, Some(ws))?)
    }

    pub fn load_plan(&self, id: &Id) -> Result<LoadPlan> {
        self.store.get(kind::LOAD_PLAN, id)?.ok_or_else(|| AppError::NotFound(format!("load plan {id}")))
    }

    /// Saving from the UI marks a plan trusted: the user authored or reviewed
    /// it. Imported plans keep `trusted = false` until saved deliberately.
    pub fn save_load_plan(&self, mut p: LoadPlan) -> Result<LoadPlan> {
        validate_plan(&p)?;
        self.check_plan_requests(&p)?;
        p.updated_at = chrono::Utc::now();
        self.store.put(kind::LOAD_PLAN, &p.id, Some(&p.workspace_id), None, 0.0, &p)?;
        Ok(p)
    }

    pub fn delete_load_plan(&self, id: &Id) -> Result<()> {
        self.store.delete(kind::LOAD_PLAN, id)?;
        Ok(())
    }

    fn plan_requests(p: &LoadPlan) -> Vec<Id> {
        let mut ids: Vec<Id> = p.chain.clone();
        for s in &p.mix {
            if !ids.contains(&s.request_id) {
                ids.push(s.request_id);
            }
        }
        ids
    }

    /// Every request a plan runs must be saved in the plan's own workspace:
    /// it is prepared with that workspace's variables, profiles and secrets.
    fn check_plan_requests(&self, p: &LoadPlan) -> Result<()> {
        for id in Self::plan_requests(p) {
            let r = self.request(&id)?;
            if r.workspace_id != p.workspace_id {
                return Err(AppError::Invalid(format!("request '{}' in this load plan belongs to another workspace", r.name)));
            }
        }
        Ok(())
    }

    /// Freeze every request the plan references (same preparation as Send)
    /// and resolve the dataset.
    pub fn load_job(&self, p: &LoadPlan) -> Result<LoadJob> {
        self.check_plan_requests(p)?;
        let opts = SendOptions { environment: p.environment_id, ..Default::default() };
        let mut requests = HashMap::new();
        for id in Self::plan_requests(p) {
            let ctx = self.build_context(Some(id), &p.workspace_id, None, &opts)?;
            requests.insert(id, ctx);
        }
        let dataset = match p.dataset_id {
            Some(did) => Some(self.load_dataset(&p.workspace_id, &did)?),
            None => None,
        };
        Ok(LoadJob { requests, dataset })
    }

    fn load_dataset(&self, ws: &Id, id: &Id) -> Result<Dataset> {
        let d = self.datasets(ws)?.into_iter().find(|d| d.meta.id == *id).ok_or_else(|| AppError::NotFound(format!("dataset {id}")))?;
        let bytes = match &d.attachment {
            AttachmentRef::Stored { sha256, .. } => {
                self.get_attachment(sha256)?.ok_or_else(|| AppError::NotFound(format!("dataset attachment {sha256}")))?
            }
            AttachmentRef::LinkedFile { path } => self.read_linked_dataset(d.meta.id, path, FilePurpose::Dataset.max_read_bytes())?,
        };
        let fmt = match d.format {
            DomainDatasetFormat::Csv => DatasetFormat::Csv,
            DomainDatasetFormat::Json => DatasetFormat::Json,
        };
        Dataset::parse(fmt, bytes)
            .and_then(|ds| ds.with_sensitive_columns(d.sensitive_columns.clone()))
            .map_err(|e| AppError::Invalid(e.to_string()))
    }

    /// Classify the plan's requests into one load unit (LOAD-013) without
    /// sending anything. Refusals are typed and returned, not raised.
    pub fn load_plan_check(&self, p: &LoadPlan) -> Result<LoadPlanCheck> {
        let job = self.load_job(p)?;
        let ids = Self::plan_requests(p);
        let protocols = ids.iter().map(|id| (*id, job.requests[id].spec.protocol)).collect();
        if ids.is_empty() {
            return Ok(LoadPlanCheck { unit: None, unit_label: None, semantics: None, refusal: None, protocols });
        }
        Ok(match anvil_load::protocol::classify_plan(ids.iter().map(|id| (*id, &job.requests[id])), p.connection_mode) {
            Ok((unit, _)) => LoadPlanCheck {
                unit: Some(unit),
                unit_label: Some(anvil_load::protocol::label(unit).into()),
                semantics: Some(anvil_load::protocol::semantics(unit, p.connection_mode)),
                refusal: None,
                protocols,
            },
            Err(r) => LoadPlanCheck { unit: None, unit_label: None, semantics: None, refusal: Some(r), protocols },
        })
    }

    pub fn load_preflight(&self, p: &LoadPlan) -> Result<LoadPreflight> {
        validate_plan(p)?;
        let job = self.load_job(p)?;
        let ids = Self::plan_requests(p);
        // Refused combinations stop here, before the user can start traffic.
        let (unit, _) = anvil_load::protocol::classify_plan(ids.iter().map(|id| (*id, &job.requests[id])), p.connection_mode)
            .map_err(|r| AppError::Invalid(format!("this plan cannot be load tested: {r}")))?;
        let mut destinations = Vec::new();
        for id in ids {
            let ctx = &job.requests[&id];
            destinations.push(match ctx.spec.protocol {
                Protocol::Http => {
                    let preview = self.engine.preview(ctx).map_err(|f| AppError::Invalid(format!("{:?}: {}", f.kind, f.message)))?;
                    format!("{} {}", preview.method, url_origin(&preview.url))
                }
                other => session_destination(ctx, other),
            });
        }
        destinations.dedup();
        let (workload, max_duration_secs, peak_target) = describe(p);
        let mut warnings = Vec::new();
        if !p.trusted {
            warnings.push("This plan was imported and has not been reviewed; saving it marks it as yours.".into());
        }
        if destinations.iter().any(|d| !d.contains("127.0.0.1") && !d.contains("localhost") && !d.contains("[::1]")) {
            warnings.push("Traffic leaves this machine. Only load-test systems you own or are authorized to test.".into());
        }
        if !anvil_load::protocol::connection_mode_applies(unit) {
            warnings.push(format!(
                "Each {} opens its own connection, so the plan's connection mode does not apply.",
                anvil_load::protocol::semantics(unit, p.connection_mode).unit_singular
            ));
        }
        Ok(LoadPreflight {
            destinations,
            workload,
            max_duration_secs,
            peak_target,
            dataset_rows: job.dataset.as_ref().map(|d| d.rows.len()),
            trusted: p.trusted,
            warnings,
            unit,
            unit_label: anvil_load::protocol::label(unit).into(),
            semantics: anvil_load::protocol::semantics(unit, p.connection_mode),
        })
    }

    /// The job handed to the worker process over stdin (secrets scoped to the
    /// referenced requests only). `acknowledged` must come from an explicit
    /// user confirmation of the preflight.
    pub fn worker_job(&self, p: &LoadPlan, acknowledged: bool) -> Result<WorkerJob> {
        if !acknowledged {
            return Err(AppError::Invalid("a load run needs explicit confirmation of its destination and planned load".into()));
        }
        if !p.trusted {
            return Err(AppError::Invalid("imported load plans must be reviewed and saved before they can run".into()));
        }
        let job = self.load_job(p)?;
        let options = RunOptions { acknowledged, ..RunOptions::default() };
        WorkerJob::from_load_job(p, &job, options).map_err(|e| AppError::Invalid(e.to_string()))
    }

    /// Save a report into its plan's workspace. Refused once that workspace
    /// is deleted: the check and the write run in one write transaction.
    pub fn save_load_report(&self, r: &LoadReport) -> Result<()> {
        let ws = r.plan.workspace_id;
        self.store.atomically(|s| {
            if s.get::<Workspace>(kind::WORKSPACE, &ws)?.is_none() {
                return Ok(Err(AppError::NotFound("the load run's workspace".into())));
            }
            s.put_load_report(&r.run_id, Some(&ws), r.started_at.timestamp_millis(), r)?;
            Ok(Ok(()))
        })?
    }

    pub fn load_reports(&self, ws: &Id) -> Result<Vec<LoadReportSummary>> {
        let v: Vec<LoadReport> = self.store.list_load_reports(Some(ws))?;
        Ok(v.into_iter()
            .map(|r| LoadReportSummary {
                run_id: r.run_id,
                plan_id: r.plan.id,
                plan_name: r.plan.name.clone(),
                started_at: r.started_at,
                completion: r.completion,
                partial: r.partial,
                achieved_rate_per_sec: r.achieved_rate_per_sec,
                started: r.counts.started,
                failures: r.counts.transport_failures + r.counts.timeouts + r.counts.application_failures,
                p95_us: (r.latency_success.count > 0).then_some(r.latency_success.p95_us),
                unit: r.protocol_metrics.as_ref().map(|m| m.unit).unwrap_or_default(),
            })
            .collect())
    }

    pub fn load_report(&self, run_id: &Id) -> Result<LoadReport> {
        let all: Vec<LoadReport> = self.store.list_load_reports(None)?;
        all.into_iter().find(|r| r.run_id == *run_id).ok_or_else(|| AppError::NotFound(format!("load report {run_id}")))
    }

    pub fn delete_load_report(&self, run_id: &Id) -> Result<()> {
        self.store.delete_load_report(run_id)?;
        Ok(())
    }
}

fn validate_plan(p: &LoadPlan) -> Result<()> {
    if p.chain.is_empty() && p.mix.is_empty() {
        return Err(AppError::Invalid("add at least one saved request to the plan".into()));
    }
    anvil_load::validate_plan(p).map_err(|e| AppError::Invalid(e.to_string()))
}

/// `WS ws://host:port`-style destination of a session request, from its URL
/// with the context's variables resolved (nothing is sent).
fn session_destination(ctx: &anvil_engine::ExecutionContext, protocol: Protocol) -> String {
    let url = anvil_engine::vars::Resolver::new(ctx.var_layers.clone(), None)
        .resolve(&ctx.spec.url, "url")
        .unwrap_or_else(|_| ctx.spec.url.clone());
    let label = match protocol {
        Protocol::WebSocket => "WebSocket",
        Protocol::Grpc => "gRPC",
        Protocol::Sse => "SSE",
        Protocol::Tcp => "TCP",
        Protocol::Udp => "UDP",
        Protocol::Http => "HTTP",
    };
    format!("{label} {}", url_origin(&url))
}

fn url_origin(url: &str) -> String {
    match url::Url::parse(url) {
        Ok(u) => {
            let host = u.host_str().unwrap_or("?");
            match u.port() {
                Some(port) => format!("{}://{host}:{port}", u.scheme()),
                None => format!("{}://{host}", u.scheme()),
            }
        }
        Err(_) => "(unparsed URL)".into(),
    }
}

fn describe(p: &LoadPlan) -> (String, u64, u64) {
    use anvil_domain::load::Workload::*;
    match &p.workload {
        ClosedVirtualUsers { stages, think_time_ms } => (
            format!("closed: up to {} virtual users, think time {think_time_ms} ms", stages.iter().map(|s| s.target).max().unwrap_or(0)),
            stages.iter().map(|s| s.duration_secs).sum::<u64>() + p.warmup_secs,
            stages.iter().map(|s| s.target).max().unwrap_or(0),
        ),
        OpenArrivalRate { stages, max_in_flight } => (
            format!("open: up to {}/s arrivals, at most {max_in_flight} in flight", stages.iter().map(|s| s.target).max().unwrap_or(0)),
            stages.iter().map(|s| s.duration_secs).sum::<u64>() + p.warmup_secs,
            stages.iter().map(|s| s.target).max().unwrap_or(0),
        ),
        Iterations { iterations, concurrency } => (format!("{iterations} iterations, concurrency {concurrency}"), 0, *concurrency),
    }
}
