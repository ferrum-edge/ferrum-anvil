//! Load plans and runs. The expensive work happens in a separate worker
//! process (`anvil-load`); this module freezes each referenced request into
//! the same `ExecutionContext` a manual Send uses, resolves the dataset, and
//! stores plans and reports in the encrypted store.

use crate::exec::SendOptions;
use crate::file_grants::FilePurpose;
use crate::{App, AppError, Result};
use anvil_domain::Id;
use anvil_domain::auth::OAuthGrant;
use anvil_domain::load::{LoadPlan, LoadReport, LoadUnitKind, UnitSemantics};
use anvil_domain::request::{AttachmentRef, Protocol};
use anvil_domain::settings::ResolverMode;
use anvil_domain::tls::{ProxyKind, ProxyProfile};
use anvil_domain::workspace::DatasetFormat as DomainDatasetFormat;
use anvil_domain::workspace::Workspace;
use anvil_engine::vars::{Resolver, VarEntry, VarLayer};
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
        self.load_job_with_authority(p).map(|(job, _)| job)
    }

    /// A stored plan and its authenticated observation, before registration.
    pub fn load_plan_with_authority(&self, id: &Id) -> Result<(LoadPlan, crate::exec::AppContextAuthority)> {
        self.read_context(|read| {
            let plan = read.get(kind::LOAD_PLAN, id)?.ok_or_else(|| AppError::NotFound(format!("load plan {id}")))?;
            Ok((plan, self.context_authority(read)))
        })
    }

    fn load_job_with_authority(&self, p: &LoadPlan) -> Result<(LoadJob, crate::exec::AppContextAuthority)> {
        let (mut requests, source, stored, authority) = self.read_context(|read| {
            // A caller may provide an explicitly acknowledged draft plan.
            // Native saved-plan callers retain their earlier exact observation.
            read.depend_object(kind::LOAD_PLAN, &p.id);
            let opts = SendOptions { environment: p.environment_id, ..Default::default() };
            let mut requests = HashMap::new();
            for id in Self::plan_requests(p) {
                requests.insert(id, self.build_context_in(read, Some(id), &p.workspace_id, None, &opts)?);
            }
            let (source, stored) = match p.dataset_id {
                Some(id) => {
                    let d: anvil_domain::workspace::Dataset = read
                        .get(kind::DATASET, &id)?
                        .filter(|d: &anvil_domain::workspace::Dataset| d.workspace_id == p.workspace_id)
                        .ok_or_else(|| AppError::NotFound(format!("dataset {id}")))?;
                    let bytes = match &d.attachment {
                        AttachmentRef::Stored { sha256, .. } => Some(
                            crate::exec::attachment_for(read, sha256)?
                                .ok_or_else(|| AppError::NotFound(format!("dataset attachment {sha256}")))?,
                        ),
                        AttachmentRef::LinkedFile { path } => {
                            crate::exec::linked_permission(read, crate::linked_files::LinkedFileReferrer::Dataset { id }, path)?;
                            None
                        }
                    };
                    (Some(d), bytes)
                }
                None => (None, None),
            };
            Ok((requests, source, stored, self.context_authority(read)))
        })?;
        authority.check()?;
        let dataset = match source {
            Some(d) => {
                let bytes = match (stored, &d.attachment) {
                    (Some(bytes), _) => bytes,
                    (None, AttachmentRef::LinkedFile { path }) => {
                        crate::linked_files::read_bound_file(path, FilePurpose::Dataset.max_read_bytes(), "dataset")?
                    }
                    _ => return Err(AppError::NotFound("dataset attachment".into())),
                };
                let format = match d.format {
                    DomainDatasetFormat::Csv => DatasetFormat::Csv,
                    DomainDatasetFormat::Json => DatasetFormat::Json,
                };
                Some(
                    Dataset::parse(format, bytes)
                        .and_then(|ds| ds.with_sensitive_columns(d.sensitive_columns))
                        .map_err(|e| AppError::Invalid(e.to_string()))?,
                )
            }
            None => None,
        };
        authority.check()?;
        for ctx in requests.values_mut() {
            crate::exec::guard_context(ctx, &authority);
        }
        Ok((LoadJob { requests, dataset }, authority))
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
            Ok((unit, steps)) => LoadPlanCheck {
                unit: Some(unit),
                unit_label: Some(anvil_load::protocol::label(unit).into()),
                semantics: Some(anvil_load::protocol::plan_semantics(unit, p.connection_mode, &steps)),
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
        let (unit, steps) = anvil_load::protocol::classify_plan(ids.iter().map(|id| (*id, &job.requests[id])), p.connection_mode)
            .map_err(|r| AppError::Invalid(format!("this plan cannot be load tested: {r}")))?;
        let mut destinations = Vec::new();
        // Whether a unit's target, or the proxy its traffic reaches first
        // (a MASQUE proxy, or the selected proxy profile unless its NO_PROXY
        // list bypasses the target), is off this machine; each host is
        // judged on its own.
        let mut leaves = false;
        for id in ids {
            let ctx = &job.requests[&id];
            // Dataset cells, extracted values, iteration variables and dynamic
            // helpers stand in as markers, so each origin is judged from the
            // URL alone, without any per-run value.
            let resolver = preflight_resolver(ctx, &id, p, &job);
            let refuse = |what: &str, origin: PerRunOrigin| {
                let request = self.request(&id).map(|r| r.name).unwrap_or_default();
                per_run_origin_refusal(&request, what, &origin)
            };
            let (_, auth) = ctx.effective_auth();
            let oauth = auth.oauth_profile().map_err(|message| AppError::Invalid(message.into()))?;
            if let Some(oauth) = oauth {
                // Check before resolving the API URL, headers or mixed auth:
                // those fields may alias a deferred credential variable.
                let proven = match prove_url(&resolver, &oauth.token_url, "auth.token_url") {
                    Ok(proven) => proven,
                    Err(UrlProblem::Unresolved(_)) => {
                        return Err(AppError::Invalid("could not resolve OAuth token URL; check the vault and active variables".into()));
                    }
                    Err(UrlProblem::PerRun(origin)) => return Err(refuse("OAuth token URL", origin)),
                };
                // Literal-loopback cleartext only on a direct route, as the
                // acquisition sink requires (every port for a per-run port).
                let settings = anvil_engine::settings::resolve(&ctx.settings_layers);
                anvil_engine::oauth_http::require_token_endpoint_route(&proven.probe, ctx, &settings, proven.port_varies)
                    .map_err(AppError::Invalid)?;
            }
            let (destination, local) = match ctx.spec.protocol {
                Protocol::Http => {
                    // Resolve the URL first; a forward proxy also routes by
                    // the effective Host after header interpolation and auth.
                    let proven = match prove_url(&resolver, &ctx.spec.url, "url") {
                        Ok(proven) => proven,
                        Err(UrlProblem::Unresolved(message)) => return Err(AppError::Invalid(message)),
                        Err(UrlProblem::PerRun(origin)) => return Err(refuse("URL", origin)),
                    };
                    let schemes = anvil_load::protocol::send_schemes(Protocol::Http);
                    let target = anvil_engine::prepare::parse_target(&proven.probe, schemes, &mut Vec::new())
                        .map_err(|f| AppError::Invalid(format!("{:?}: {}", f.kind, f.message)))?;
                    let method = match resolver.resolve(&mask_dynamic_expressions(ctx.spec.method.trim()), "method") {
                        Ok(method) if per_run_sources(&method).is_empty() => method.to_ascii_uppercase(),
                        // A per-run method (or a dynamic helper) is shown as written.
                        _ => ctx.spec.method.trim().to_string(),
                    };
                    let mut d = format!("{method} {}", origin_label(&target.url(), proven.port_varies));
                    let proxy = proven.proxy(ctx, Protocol::Http);
                    let mut local = target_is_loopback(ctx, &target, proxy.is_some());
                    if let Some(proxy) = proxy {
                        d.push_str(&proxy_label(proxy));
                        local &= address_is_loopback(ctx, &proxy.address);
                        local &= forward_authority_is_loopback(ctx, &target, proxy, &resolver, &mut d);
                    }
                    (d, local)
                }
                other => session_destination(ctx, other, &resolver).map_err(|(what, origin)| refuse(what, origin))?,
            };
            leaves |= !local;
            destinations.push(destination);

            if let Some(oauth) = oauth {
                let mut auth_urls = vec![("OAuth token URL", oauth.token_url.as_str())];
                let authorization_url_required = matches!(oauth.grant, OAuthGrant::AuthorizationCodePkce | OAuthGrant::RefreshToken);
                if authorization_url_required && !oauth.authorization_url.is_empty() {
                    auth_urls.push(("OAuth authorization URL", oauth.authorization_url.as_str()));
                }
                for (label, template) in auth_urls {
                    let proven = match prove_url(&resolver, template, "auth URL") {
                        Ok(proven) => proven,
                        Err(UrlProblem::Unresolved(_)) => {
                            return Err(AppError::Invalid(format!("could not resolve {label}; check the vault and active variables")));
                        }
                        Err(UrlProblem::PerRun(origin)) => return Err(refuse(label, origin)),
                    };
                    if label == "OAuth token URL" {
                        // Eligibility is the acquisition sink's policy: literal
                        // loopback on a direct route, whatever the DNS overrides.
                        let settings = anvil_engine::settings::resolve(&ctx.settings_layers);
                        anvil_engine::oauth_http::require_token_endpoint_route(&proven.probe, ctx, &settings, proven.port_varies)
                            .map_err(AppError::Invalid)?;
                    }
                    let target = anvil_engine::prepare::parse_target(
                        &proven.probe,
                        anvil_load::protocol::send_schemes(Protocol::Http),
                        &mut Vec::new(),
                    )
                    .map_err(|f| AppError::Invalid(format!("{:?}: {}", f.kind, f.message)))?;
                    // Authorization opens in the external browser: client
                    // DNS overrides cannot pin the browser's resolution.
                    let browser = label == "OAuth authorization URL";
                    let proxy = if browser { None } else { proven.proxy(ctx, Protocol::Http) };
                    let mut auth_local = target_is_loopback(ctx, &target, browser || proxy.is_some());
                    let mut auth_destination = format!("{label} {}", origin_label(&target.url(), proven.port_varies));
                    if let Some(proxy) = proxy {
                        auth_destination.push_str(&proxy_label(proxy));
                        auth_local &= address_is_loopback(ctx, &proxy.address);
                    }
                    leaves |= !auth_local;
                    destinations.push(auth_destination);
                }
            }
        }
        destinations.dedup();
        let (workload, max_duration_secs, peak_target) = describe(p);
        let mut warnings = Vec::new();
        if !p.trusted {
            warnings.push("This plan was imported and has not been reviewed; saving it marks it as yours.".into());
        }
        if leaves {
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
            semantics: anvil_load::protocol::plan_semantics(unit, p.connection_mode, &steps),
        })
    }

    /// The job handed to the worker process over stdin (secrets scoped to the
    /// referenced requests only). `acknowledged` must come from an explicit
    /// user confirmation of the preflight.
    pub fn worker_job(&self, p: &LoadPlan, acknowledged: bool) -> Result<WorkerJob> {
        self.worker_job_with_authority(p, acknowledged).map(|(worker, _)| worker)
    }

    /// Producer proof remains local; it is never serialized into a detached worker.
    pub fn worker_job_with_authority(&self, p: &LoadPlan, acknowledged: bool) -> Result<(WorkerJob, crate::exec::AppContextAuthority)> {
        if !acknowledged {
            return Err(AppError::Invalid("a load run needs explicit confirmation of its destination and planned load".into()));
        }
        if !p.trusted {
            return Err(AppError::Invalid("imported load plans must be reviewed and saved before they can run".into()));
        }
        let (job, authority) = self.load_job_with_authority(p)?;
        let options = RunOptions { acknowledged, ..RunOptions::default() };
        let worker = WorkerJob::from_load_job(p, &job, options).map_err(|e| AppError::Invalid(e.to_string()))?;
        authority.check()?;
        Ok((worker, authority))
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
        // Reports are stored under their run id; only this one is decrypted.
        let report: Option<LoadReport> = self.store.get_load_report(run_id)?;
        report.filter(|r| r.run_id == *run_id).ok_or_else(|| AppError::NotFound(format!("load report {run_id}")))
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

// Stand-ins for the values a load worker supplies on each iteration
// (`run_iteration`), one per source so a refusal can say where a value comes
// from without showing it. They hold no URL delimiter (`:`, `/`, `?`, `#`,
// `@`, `[`, `]`), so each stays inside the URL part it reaches.
const DATASET_VALUE: &str = "anvil-preflight-dataset-column";
const EXTRACTED_VALUE: &str = "anvil-preflight-extracted-value";
const ITERATION_VALUE: &str = "anvil-preflight-iteration-variable";
const HELPER_VALUE: &str = "anvil-preflight-dynamic-helper";
const PER_RUN_VALUES: [(&str, &str); 4] = [
    (DATASET_VALUE, "a dataset column"),
    (EXTRACTED_VALUE, "a value extracted by a chain step"),
    (ITERATION_VALUE, "an iteration variable (anvil.iteration or anvil.vu)"),
    (HELPER_VALUE, "a dynamic helper ({{$...}})"),
];

/// Where the per-run stand-ins in `text` come from.
fn per_run_sources(text: &str) -> Vec<&'static str> {
    PER_RUN_VALUES.iter().filter(|(stand_in, _)| text.contains(stand_in)).map(|(_, source)| *source).collect()
}

fn replace_stand_ins(text: &str, with: &str) -> String {
    PER_RUN_VALUES.iter().fold(text.to_string(), |text, (stand_in, _)| text.replace(stand_in, with))
}

/// Dynamic helpers may produce a loopback-looking value in one preview and
/// a remote value on a send. Mask them so they cannot authorize an origin.
fn mask_dynamic_expressions(input: &str) -> String {
    anvil_engine::vars::mask_dynamic(input, HELPER_VALUE)
}

/// A resolver for what a load step sends on every iteration: the step's own
/// variable layers with every dynamic helper masked (also one reached through
/// a variable's value), then a stand-in for each value the worker adds per
/// iteration, layered as `run_iteration` layers the real values. A stand-in
/// therefore wins over a workspace, environment or folder variable of the
/// same name exactly as the real value does.
fn preflight_resolver(ctx: &anvil_engine::ExecutionContext, id: &Id, p: &LoadPlan, job: &LoadJob) -> Resolver {
    let mut layers = ctx.var_layers.clone();
    for variable in layers.iter_mut().flat_map(|layer| layer.vars.iter_mut()) {
        variable.value = mask_dynamic_expressions(&variable.value);
    }
    let stand_in = |name: &str, value: &str| VarEntry { name: name.into(), value: value.into(), secret: false, literal: false };
    let iteration = vec![stand_in("anvil.iteration", ITERATION_VALUE), stand_in("anvil.vu", ITERATION_VALUE)];
    layers.push(VarLayer { label: "load".into(), vars: iteration });
    // Only a step outside a sealed import root sees the dataset row.
    if ctx.scope.is_none()
        && let Some(dataset) = &job.dataset
    {
        let vars: Vec<VarEntry> = dataset.columns.iter().map(|column| stand_in(column.as_str(), DATASET_VALUE)).collect();
        layers.push(VarLayer { label: "dataset".into(), vars });
    }
    // A chain step sees what every earlier position of the iteration
    // extracted under its own scope, including an earlier position of the
    // same request: judge each request at its last position.
    let earlier = p.chain.iter().rposition(|step| step == id).map_or(&[][..], |last| &p.chain[..last]);
    let mut extracted: Vec<VarEntry> = Vec::new();
    for step in earlier.iter().filter_map(|step| job.requests.get(step)).filter(|step| step.scope == ctx.scope) {
        for extraction in &step.spec.extractions {
            if !extracted.iter().any(|entry| entry.name == extraction.variable) {
                extracted.push(stand_in(extraction.variable.as_str(), EXTRACTED_VALUE));
            }
        }
    }
    if !extracted.is_empty() {
        layers.push(VarLayer { label: "iteration (extracted)".into(), vars: extracted });
    }
    Resolver::new(layers, None).with_secrets(ctx.secrets.clone()).with_value_transform(mask_dynamic_expressions)
}

/// The part of a URL's origin a per-run value reaches, and where those values
/// come from.
struct PerRunOrigin {
    part: &'static str,
    sources: Vec<&'static str>,
    /// The rule a per-run port broke, when `part` is the port.
    rule: Option<&'static str>,
}

enum UrlProblem {
    /// The URL does not resolve (an undefined variable, a cycle): every send
    /// fails on it.
    Unresolved(String),
    /// A per-run value can change the URL's origin.
    PerRun(PerRunOrigin),
}

/// A URL whose origin the preflight proved: per-run values reach at most its
/// path, query and fragment, or its port after a fixed loopback host.
struct ProvenUrl {
    /// The resolved URL with a per-run port (with any fixed digits beside the
    /// value) replaced by `1`, and every other per-run value by `1`, to parse
    /// and route. It is never sent.
    probe: String,
    /// The port comes from a per-run value.
    port_varies: bool,
}

impl ProvenUrl {
    fn label(&self, protocol: Protocol) -> String {
        match anvil_engine::prepare::parse_target(&self.probe, anvil_load::protocol::send_schemes(protocol), &mut Vec::new()) {
            Ok(target) => origin_label(&target.url(), self.port_varies),
            Err(_) => url_origin(&self.probe),
        }
    }

    /// The proxy profile the engine routes this URL through. With a per-run
    /// port, only a `NO_PROXY` entry without a port bypasses every port, so
    /// the selected profile is assumed to carry the traffic unless one of
    /// those matches the host.
    fn proxy<'a>(&self, ctx: &'a anvil_engine::ExecutionContext, protocol: Protocol) -> Option<&'a ProxyProfile> {
        let (target, proxy) = anvil_load::protocol::route(ctx, &self.probe, protocol)?;
        if !self.port_varies {
            return proxy;
        }
        let selected = anvil_engine::settings::resolve(&ctx.settings_layers).proxy_profile_id;
        let selected = selected.and_then(|id| ctx.proxy_profiles.iter().find(|proxy| proxy.id == id));
        selected.filter(|proxy| !anvil_transport::net::no_proxy_matches_every_port(&proxy.no_proxy, &target.host))
    }
}

/// Resolve a URL template as every iteration sends it and prove its origin.
fn prove_url(resolver: &Resolver, template: &str, field: &str) -> std::result::Result<ProvenUrl, UrlProblem> {
    let mut resolved = match resolver.resolve(&mask_dynamic_expressions(template), field) {
        Ok(resolved) => resolved.trim().to_string(),
        Err(f) => return Err(UrlProblem::Unresolved(replace_stand_ins(&format!("{:?}: {}", f.kind, f.message), "<per-iteration value>"))),
    };
    let port = per_run_origin(&resolved).map_err(UrlProblem::PerRun)?;
    let port_varies = port.is_some();
    // The whole per-run port becomes one valid port, never fixed digits
    // followed by a placeholder (`9999{{p}}` must not become `99991`).
    if let Some(port) = port {
        resolved.replace_range(port, "1");
    }
    Ok(ProvenUrl { probe: replace_stand_ins(&resolved, "1"), port_varies })
}

/// The byte range of the port of `resolved` (a trimmed URL resolved with the
/// per-run stand-ins) when a per-run value reaches it, or which part of its
/// origin a per-run value reaches when that cannot be proven local. The URL
/// is split as `parse_target` splits it: the scheme ends at the first `://`
/// (with none, a fixed one is inferred), the authority at the first `/`, `?`
/// or `#`, and the host at the `:` before the port (after the `]` of an IPv6
/// literal). A per-run port is accepted only after a fixed loopback host,
/// and with nothing but fixed digits beside it: the value then starts after
/// that `:`, so it can change the port (or make the URL invalid: the engine
/// refuses an `@` in the authority and a port that is not 0-65535 in ASCII
/// digits) but never the host.
fn per_run_origin(resolved: &str) -> std::result::Result<Option<std::ops::Range<usize>>, PerRunOrigin> {
    let (scheme, rest) = resolved.split_once("://").unwrap_or(("", resolved));
    let sources = per_run_sources(scheme);
    if !sources.is_empty() {
        return Err(PerRunOrigin { part: "scheme", sources, rule: None });
    }
    let authority = &rest[..rest.find(['/', '?', '#']).unwrap_or(rest.len())];
    let sources = per_run_sources(authority);
    if sources.is_empty() {
        return Ok(None);
    }
    let host_end = if authority.starts_with('[') { authority.find(']').map(|end| end + 1) } else { authority.find(':') };
    let (host, port) = authority.split_at(host_end.unwrap_or(authority.len()));
    let Some(port) = port.strip_prefix(':').filter(|_| per_run_sources(host).is_empty()) else {
        return Err(PerRunOrigin { part: "host", sources, rule: None });
    };
    if !host_is_loopback(host) {
        return Err(PerRunOrigin { part: "port", sources, rule: Some("a per-iteration port is allowed only after a fixed loopback host") });
    }
    if !replace_stand_ins(port, "").bytes().all(|b| b.is_ascii_digit()) {
        return Err(PerRunOrigin { part: "port", sources, rule: Some("only fixed digits may share the port with a per-iteration value") });
    }
    let start = resolved.len() - rest.len() + host.len() + 1;
    Ok(Some(start..resolved.len() - rest.len() + authority.len()))
}

/// The refusal of a load step whose `what` (its URL or MASQUE proxy URL) has
/// an origin a per-run value can change. It names where the value comes from,
/// never the value.
fn per_run_origin_refusal(request: &str, what: &str, origin: &PerRunOrigin) -> AppError {
    let (part, sources) = (origin.part, origin.sources.join(" and "));
    let mut message = format!("load preflight cannot prove that a variable URL origin stays on loopback: the {part} of the {what}");
    message.push_str(&format!(" of request '{request}' comes from {sources}, which can change on every iteration"));
    if let Some(rule) = origin.rule {
        message.push_str(&format!("; {rule}"));
    }
    AppError::Invalid(message)
}

/// `WS ws://host:port`-style destination of a session request, from its URL
/// resolved as every iteration resolves it (nothing is sent), and whether
/// all of its traffic stays on this machine: the target and the proxy it
/// reaches first (a MASQUE proxy, or the proxy profile the engine routes it
/// through) are judged separately, so either one off this machine counts.
/// `Err` names the URL whose origin a per-run value can change.
fn session_destination(
    ctx: &anvil_engine::ExecutionContext,
    protocol: Protocol,
    resolver: &Resolver,
) -> std::result::Result<(String, bool), (&'static str, PerRunOrigin)> {
    // A URL that does not resolve is never judged local; every send fails on it.
    let target = match prove_url(resolver, &ctx.spec.url, "url") {
        Ok(target) => Some(target),
        Err(UrlProblem::Unresolved(_)) => None,
        Err(UrlProblem::PerRun(origin)) => return Err(("URL", origin)),
    };
    let label = match protocol {
        Protocol::WebSocket => "WebSocket",
        Protocol::Grpc => "gRPC",
        Protocol::Sse => "SSE",
        Protocol::Tcp => "TCP",
        Protocol::Udp => "UDP",
        Protocol::Http => "HTTP",
        Protocol::Mcp => "MCP",
    };
    let parsed = target.as_ref().and_then(|target| anvil_load::protocol::route(ctx, &target.probe, protocol).map(|(target, _)| target));
    let proxy = target.as_ref().and_then(|target| target.proxy(ctx, protocol));
    let masque = ctx.spec.udp.as_ref().and_then(|u| u.masque.as_ref()).filter(|_| protocol == Protocol::Udp);
    let mut d = format!("{label} {}", target.as_ref().map_or_else(|| url_origin(&ctx.spec.url), |target| target.label(protocol)),);
    let mut local = parsed.as_ref().is_some_and(|target| target_is_loopback(ctx, target, proxy.is_some() || masque.is_some()));
    // A datagram tunnel sends every exchange's traffic to the proxy first.
    // (The plan check refuses a MASQUE request a proxy profile also routes.)
    if let Some(m) = masque {
        let proxy = match prove_url(resolver, &m.proxy_url, "udp.masque.proxy_url") {
            Ok(proxy) => Some(proxy),
            Err(UrlProblem::Unresolved(_)) => None,
            Err(UrlProblem::PerRun(origin)) => return Err(("MASQUE proxy URL", origin)),
        };
        d.push_str(&format!(
            " via MASQUE proxy {}",
            proxy.as_ref().map_or_else(|| url_origin(&m.proxy_url), |proxy| proxy.label(Protocol::Http)),
        ));
        local &= proxy.as_ref().is_some_and(|proxy| {
            anvil_load::protocol::route(ctx, &proxy.probe, Protocol::Http)
                .is_some_and(|(target, _)| target_is_loopback(ctx, &target, false))
        });
        // The proxy routes by the expanded CONNECT-UDP path, not the UDP
        // URL. Only the canonical template proves that its routing host is
        // the already checked target. A custom template may put that host
        // in a query while routing to an unrelated host in the path.
        let canonical = resolver
            .resolve(&mask_dynamic_expressions(&m.uri_template), "udp.masque.uri_template")
            .is_ok_and(|template| template == anvil_domain::request::MASQUE_DEFAULT_TEMPLATE);
        if !canonical {
            local = false;
            // Templates can contain secrets; describe the uncertainty only.
            d.push_str(" (MASQUE routing template is unproven)");
        }
    } else if let Some(proxy) = proxy {
        d.push_str(&proxy_label(proxy));
        local &= address_is_loopback(ctx, &proxy.address);
        if let Some(target) = &parsed {
            local &= forward_authority_is_loopback(ctx, target, proxy, resolver, &mut d);
        }
    }
    Ok((d, local))
}

/// ` via HTTP proxy host:port`-style suffix of a destination.
fn proxy_label(proxy: &ProxyProfile) -> String {
    let kind = match proxy.kind {
        ProxyKind::Http => "HTTP",
        ProxyKind::Https => "HTTPS",
        ProxyKind::Socks5 => "SOCKS5",
        ProxyKind::Hbone => "HBONE",
    };
    format!(" via {kind} proxy {}", proxy.address)
}

/// Proof uses exactly the connector's fixed addresses. Never look up a
/// name here: resolver results can change before send, and a synchronous
/// preflight must not wait for the OS resolver's blocking task to finish.
fn fixed_host_is_loopback(ctx: &anvil_engine::ExecutionContext, host: &str, port: u16) -> bool {
    let settings = anvil_engine::settings::resolve(&ctx.settings_layers);
    let system_resolver = matches!(&settings.resolver, ResolverMode::System);
    let dns = anvil_transport::dns::DnsConfig {
        resolver: settings.resolver,
        overrides: settings.dns_overrides,
        ip_preference: settings.ip_preference,
    };
    match anvil_transport::dns::fixed_resolution(host, port, &dns) {
        Some(Ok(resolution)) => {
            !resolution.addrs.is_empty() && resolution.addrs.iter().all(|addr| anvil_transport::dns::is_loopback(addr.ip()))
        }
        Some(Err(_)) => false,
        // System transport resolution enforces this same localhost loopback rule in dns.rs.
        None => system_resolver && anvil_transport::dns::is_localhost_name(host),
    }
}

fn literal_is_loopback(host: &str) -> bool {
    anvil_transport::dns::parse_literal(host).is_some_and(anvil_transport::dns::is_loopback)
}

fn target_is_loopback(ctx: &anvil_engine::ExecutionContext, target: &anvil_engine::prepare::Target, proxy_resolved: bool) -> bool {
    if proxy_resolved {
        // The proxy receives this name unchanged and ignores client overrides.
        literal_is_loopback(&target.host)
    } else {
        fixed_host_is_loopback(ctx, &target.host, target.port)
    }
}

fn address_is_loopback(ctx: &anvil_engine::ExecutionContext, address: &str) -> bool {
    anvil_transport::net::parse_proxy_address(address).is_ok_and(|(host, port)| fixed_host_is_loopback(ctx, &host, port))
}

/// A forward proxy routes the absolute URI or h2c `:authority` using the
/// effective Host. Check the same first-header/auth-replacement semantics
/// as execution, without preparing the method or body or acquiring
/// credentials. Dynamic header
/// names and Host values are unproven, so they always require remote consent.
fn forward_authority_is_loopback(
    ctx: &anvil_engine::ExecutionContext,
    target: &anvil_engine::prepare::Target,
    proxy: &ProxyProfile,
    resolver: &Resolver,
    destination: &mut String,
) -> bool {
    // Session transports (SSE, WebSocket, native gRPC and gRPC-Web) always
    // CONNECT to the URL target, even for cleartext HTTP/1.1 or h2c. Only
    // HttpTransport skips CONNECT, independently of its version policy.
    let forward = anvil_transport::http::forward_proxy_routes_authority(target.scheme == "https", Some(proxy.kind));
    if ctx.spec.protocol != Protocol::Http || !forward {
        return true;
    }
    let authority = anvil_engine::prepare::preflight_authority(ctx, target, |template, field| {
        let resolved = resolver.resolve(&mask_dynamic_expressions(template), field).ok()?;
        per_run_sources(&resolved).is_empty().then_some(resolved)
    });
    let local = authority.as_deref().and_then(anvil_transport::http::authority_host).is_some_and(|host| literal_is_loopback(&host));
    if !local {
        // Host can be an auth credential or secret variable: never display it.
        destination.push_str(" (forward-proxy Host authority is remote or unproven)");
    }
    local
}

/// A host as a URL carries it: an IP literal (IPv6 in brackets) or a name.
/// Only the whole host is compared, so `localhost.example.com` or an
/// address merely containing `127.0.0.1` is not this machine.
fn host_is_loopback(host: &str) -> bool {
    let h = host.trim_start_matches('[').trim_end_matches(']');
    match h.parse::<std::net::IpAddr>() {
        Ok(ip) => anvil_transport::dns::is_loopback(ip),
        Err(_) => anvil_transport::dns::is_localhost_name(h),
    }
}

/// [`url_origin`], with a per-run port shown as `<per-iteration port>`
/// instead of the probe's placeholder.
fn origin_label(url: &str, port_varies: bool) -> String {
    match url::Url::parse(url) {
        Ok(u) if port_varies => format!("{}://{}:<per-iteration port>", u.scheme(), u.host_str().unwrap_or("?")),
        _ => url_origin(url),
    }
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
