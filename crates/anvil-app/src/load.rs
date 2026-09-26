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
use anvil_load::{Dataset, DatasetFormat, LoadJob, Refusal, RunOptions, WorkerJob};
use anvil_storage::store::kind;
use std::collections::HashMap;

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

    /// Freeze every request the plan references (same preparation as Send)
    /// and resolve the dataset.
    pub fn load_job(&self, p: &LoadPlan) -> Result<LoadJob> {
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
            AttachmentRef::LinkedFile { path } => self.read_linked_file(path, FilePurpose::Dataset.max_read_bytes(), "dataset")?,
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

    pub fn save_load_report(&self, r: &LoadReport) -> Result<()> {
        self.store.put_load_report(&r.run_id, Some(&r.plan.workspace_id), r.started_at.timestamp_millis(), r)?;
        Ok(())
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
