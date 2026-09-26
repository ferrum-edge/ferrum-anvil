//! Collection runs over the encrypted store: scenarios, ad-hoc folder runs,
//! datasets and saved run reports.
//!
//! Each step goes through the same [`App::build_context`] as a manual Send
//! (snapshotted once at run start, so a run uses a frozen environment), is
//! executed by the shared engine and recorded in history like a normal send.
//! The finished [`RunReport`] is stored encrypted (`run_report` objects,
//! newest [`MAX_RUN_REPORTS`] per workspace kept).

use crate::exec::SendOptions;
use crate::{App, AppError, Result};
use anvil_domain::Id;
use anvil_domain::runner::{FailOn, RunReport};
use anvil_domain::workspace::{Dataset, DatasetFormat, Meta, Scenario, ScenarioStep};
use anvil_engine::{ExecutionContext, ExecutionOutput};
use anvil_runner::{ProvidedStep, RunDataset, RunEventSink, RunOptions, RunPlan, StepError, StepProvider};
use anvil_storage::kind;
use std::collections::HashMap;
use tokio_util::sync::CancellationToken;

/// Saved run reports kept per workspace (oldest removed first).
pub const MAX_RUN_REPORTS: usize = 100;

/// Caller choices for a collection run.
#[derive(Clone)]
pub struct RunSettings {
    /// Environment (defaults to the workspace's active environment).
    pub environment: Option<Id>,
    /// Override the scenario's iteration count.
    pub iterations: Option<u32>,
    /// Override the scenario's `stop_on_failure` (folder runs default to false).
    pub stop_on_failure: Option<bool>,
    pub fail_on: FailOn,
    /// Run an untrusted (imported) scenario. Set only after the user
    /// confirmed it for this run; recorded in the report.
    pub allow_untrusted: bool,
    /// Dataset for this run, replacing the scenario's own dataset.
    pub dataset: Option<RunDataset>,
    /// Record each executed step in history (per the history policy).
    pub record_history: bool,
    /// Save the report in the encrypted store.
    pub persist_report: bool,
    pub seed: Option<u64>,
    pub events: Option<RunEventSink>,
    /// Pre-assigned run id (correlate live events with the saved report).
    pub run_id: Option<Id>,
}

impl Default for RunSettings {
    fn default() -> Self {
        RunSettings {
            environment: None,
            iterations: None,
            stop_on_failure: None,
            fail_on: FailOn::default(),
            allow_untrusted: false,
            dataset: None,
            record_history: true,
            persist_report: true,
            seed: None,
            events: None,
            run_id: None,
        }
    }
}

/// Frozen per-run contexts built from the store at run start.
struct AppProvider<'a> {
    app: &'a App,
    steps: HashMap<Id, std::result::Result<(String, ExecutionContext), String>>,
    record_history: bool,
}

impl StepProvider for AppProvider<'_> {
    fn step(&self, request_id: &Id) -> std::result::Result<ProvidedStep, StepError> {
        if self.app.is_locked() {
            return Err(StepError::Fatal("Anvil was locked; the run stopped (runs stop on lock)".into()));
        }
        match self.steps.get(request_id) {
            Some(Ok((name, ctx))) => Ok(ProvidedStep { name: name.clone(), context: ctx.clone() }),
            Some(Err(e)) => Err(StepError::Step(e.clone())),
            None => Err(StepError::Step(format!("request {request_id} is not part of this run"))),
        }
    }

    fn record(&self, out: &ExecutionOutput) -> std::result::Result<(), StepError> {
        if !self.record_history {
            return Ok(());
        }
        self.app.record(out).map_err(|e| match e {
            AppError::Locked => StepError::Fatal("Anvil was locked; the run stopped (runs stop on lock)".into()),
            other => StepError::Step(other.to_string()),
        })
    }
}

fn run_error(e: anvil_runner::RunError) -> AppError {
    AppError::Invalid(e.to_string())
}

impl App {
    // ------------------------------------------------------------ runs

    /// Run a saved scenario. Untrusted (imported) scenarios are refused
    /// unless `settings.allow_untrusted` is set after user confirmation.
    pub async fn run_scenario(&self, scenario_id: &Id, settings: RunSettings, cancel: CancellationToken) -> Result<RunReport> {
        if self.is_locked() {
            return Err(AppError::Locked);
        }
        let s = self.scenario(scenario_id)?;
        let dataset = match (&settings.dataset, s.dataset_id) {
            (Some(d), _) => Some(d.clone()),
            (None, Some(did)) => Some(self.run_dataset(&self.dataset(&did)?)?),
            (None, None) => None,
        };
        let names = self.request_names(&s.workspace_id)?;
        let plan = RunPlan::from_scenario(&s, &|id| names.get(id).cloned().unwrap_or_else(|| format!("missing request {id}")), dataset);
        self.run_plan(plan, settings, cancel).await
    }

    /// Ad-hoc run of every request in a folder subtree (`None` = the whole
    /// workspace), in tree order (subfolders first, then requests, as shown
    /// in the sidebar).
    pub async fn run_folder(&self, ws: &Id, folder: Option<Id>, settings: RunSettings, cancel: CancellationToken) -> Result<RunReport> {
        if self.is_locked() {
            return Err(AppError::Locked);
        }
        let requests = self.folder_run_requests(ws, folder)?;
        if requests.is_empty() {
            return Err(AppError::Invalid(format!("folder '{}' contains no requests", self.folder_path(ws, folder)?)));
        }
        let mut plan = RunPlan::folder(*ws, folder, &self.folder_path(ws, folder)?, requests);
        plan.dataset = settings.dataset.clone();
        self.run_plan(plan, settings, cancel).await
    }

    /// Run a prepared plan against this workspace's store.
    pub async fn run_plan(&self, mut plan: RunPlan, settings: RunSettings, cancel: CancellationToken) -> Result<RunReport> {
        let ws = self.workspace(&plan.workspace_id)?;
        let env_id = settings.environment.or(ws.active_environment_id);
        if let Some(eid) = env_id {
            let env = self
                .environments(&ws.meta.id)?
                .into_iter()
                .find(|e| e.meta.id == eid)
                .ok_or_else(|| AppError::NotFound("environment".into()))?;
            plan.environment_id = Some(eid);
            plan.environment_name = Some(env.name);
        }
        // Snapshot every request once: the run uses a frozen environment and
        // request state even if they are edited while it runs.
        let opts = SendOptions { environment: env_id, seed: settings.seed, ..Default::default() };
        let mut steps = HashMap::new();
        for st in plan.steps.iter().filter(|s| s.enabled) {
            if steps.contains_key(&st.request_id) {
                continue;
            }
            let built = match self.request(&st.request_id) {
                Ok(r) if r.workspace_id != ws.meta.id => Err(format!("request '{}' belongs to another workspace", r.name)),
                Ok(r) => match self.build_context(Some(r.meta.id), &ws.meta.id, None, &opts) {
                    Ok(ctx) => Ok((r.name.clone(), ctx)),
                    Err(AppError::Locked) => return Err(AppError::Locked),
                    Err(e) => Err(format!("request '{}' cannot be prepared: {e}", r.name)),
                },
                Err(AppError::Locked) => return Err(AppError::Locked),
                Err(AppError::NotFound(_)) => Err(format!("request {} no longer exists", st.request_id)),
                Err(e) => Err(e.to_string()),
            };
            steps.insert(st.request_id, built);
        }
        let provider = AppProvider { app: self, steps, record_history: settings.record_history };
        let run_opts = RunOptions {
            iterations: settings.iterations,
            stop_on_failure: settings.stop_on_failure,
            fail_on: settings.fail_on,
            allow_untrusted: settings.allow_untrusted,
            events: settings.events.clone(),
            run_id: settings.run_id,
            max_report_steps: None,
        };
        let mut report = anvil_runner::run(&self.engine, &provider, plan, run_opts, cancel).await.map_err(run_error)?;
        if settings.persist_report {
            match self.save_run_report(&report) {
                Ok(()) => {}
                // A run aborted by a lock still returns its partial report.
                Err(AppError::Locked) => report.notes.push("This report was not saved: Anvil is locked.".into()),
                Err(e) => return Err(e),
            }
        }
        Ok(report)
    }

    /// Requests of a folder subtree in tree order, as `(id, name)`.
    pub fn folder_run_requests(&self, ws: &Id, folder: Option<Id>) -> Result<Vec<(Id, String)>> {
        fn find(nodes: &[crate::workspace::TreeNode], id: Id) -> Option<&crate::workspace::TreeNode> {
            for n in nodes {
                if n.id == id && n.kind == "folder" {
                    return Some(n);
                }
                if let Some(x) = find(&n.children, id) {
                    return Some(x);
                }
            }
            None
        }
        fn flatten(nodes: &[crate::workspace::TreeNode], out: &mut Vec<(Id, String)>) {
            for n in nodes {
                match n.kind {
                    "request" => out.push((n.id, n.name.clone())),
                    _ => flatten(&n.children, out),
                }
            }
        }
        let tree = self.tree(ws)?;
        let mut out = Vec::new();
        match folder {
            None => flatten(&tree, &mut out),
            Some(f) => {
                let node = find(&tree, f).ok_or_else(|| AppError::NotFound("folder".into()))?;
                flatten(&node.children, &mut out);
            }
        }
        Ok(out)
    }

    /// `Orders/Refunds` style path of a folder (`/` for the workspace root).
    pub fn folder_path(&self, ws: &Id, folder: Option<Id>) -> Result<String> {
        if folder.is_none() {
            return Ok("/".into());
        }
        Ok(self.folder_chain(ws, folder)?.iter().map(|f| f.name.clone()).collect::<Vec<_>>().join("/"))
    }

    /// Resolve a folder by id or `Parent/Child` path (`/` or empty = root).
    pub fn find_folder(&self, ws: &Id, key: &str) -> Result<Option<Id>> {
        let key = key.trim();
        if key.is_empty() || key == "/" {
            return Ok(None);
        }
        let folders = self.folders(ws)?;
        if let Some(f) = folders.iter().find(|f| f.meta.id.to_string() == key) {
            return Ok(Some(f.meta.id));
        }
        let mut parent: Option<Id> = None;
        for seg in key.trim_matches('/').split('/').filter(|s| !s.is_empty()) {
            let children: Vec<&anvil_domain::workspace::Folder> = folders.iter().filter(|f| f.parent_id == parent).collect();
            let exact: Vec<_> = children.iter().filter(|f| f.name == seg).collect();
            let loose: Vec<_> = children.iter().filter(|f| f.name.eq_ignore_ascii_case(seg)).collect();
            let found = match (exact.as_slice(), loose.as_slice()) {
                ([one], _) | ([], [one]) => one.meta.id,
                ([], []) => return Err(AppError::NotFound(format!("folder '{key}'"))),
                _ => return Err(AppError::Invalid(format!("folder path '{key}' is ambiguous at '{seg}'; use the folder id"))),
            };
            parent = Some(found);
        }
        Ok(parent)
    }

    fn request_names(&self, ws: &Id) -> Result<HashMap<Id, String>> {
        Ok(self.requests(ws)?.into_iter().map(|r| (r.meta.id, r.name)).collect())
    }

    // ------------------------------------------------------------ reports

    /// Save (encrypted) and keep the newest [`MAX_RUN_REPORTS`] per workspace.
    pub fn save_run_report(&self, r: &RunReport) -> Result<()> {
        self.store.put(kind::RUN_REPORT, &r.run_id, Some(&r.workspace_id), None, r.started_at.timestamp_millis() as f64, r)?;
        let ws = r.workspace_id.to_string();
        let mut mine: Vec<_> =
            self.store.object_meta(kind::RUN_REPORT)?.into_iter().filter(|m| m.workspace_id.as_deref() == Some(&ws)).collect();
        if mine.len() > MAX_RUN_REPORTS {
            mine.sort_by(|a, b| b.sort_key.partial_cmp(&a.sort_key).unwrap_or(std::cmp::Ordering::Equal));
            for old in &mine[MAX_RUN_REPORTS..] {
                if let Ok(id) = old.id.parse::<Id>() {
                    self.store.delete(kind::RUN_REPORT, &id)?;
                }
            }
        }
        Ok(())
    }

    /// Saved run reports of a workspace, newest first.
    pub fn run_reports(&self, ws: &Id) -> Result<Vec<RunReport>> {
        let mut v: Vec<RunReport> = self.store.list(kind::RUN_REPORT, Some(ws))?;
        v.sort_by_key(|r| std::cmp::Reverse(r.started_at));
        Ok(v)
    }

    pub fn run_report(&self, id: &Id) -> Result<RunReport> {
        self.store.get(kind::RUN_REPORT, id)?.ok_or_else(|| AppError::NotFound("run report".into()))
    }

    pub fn delete_run_report(&self, id: &Id) -> Result<()> {
        self.store.delete(kind::RUN_REPORT, id)?;
        Ok(())
    }

    // ------------------------------------------------------------ scenarios

    pub fn scenario(&self, id: &Id) -> Result<Scenario> {
        self.store.get(kind::SCENARIO, id)?.ok_or_else(|| AppError::NotFound("scenario".into()))
    }

    /// Find a scenario by id or (case-insensitive) name.
    pub fn find_scenario(&self, ws: &Id, key: &str) -> Result<Scenario> {
        let all = self.scenarios(ws)?;
        if let Some(s) = all.iter().find(|s| s.meta.id.to_string() == key) {
            return Ok(s.clone());
        }
        let matches: Vec<&Scenario> = all.iter().filter(|s| s.name.eq_ignore_ascii_case(key.trim())).collect();
        match matches.as_slice() {
            [one] => Ok((*one).clone()),
            [] => Err(AppError::NotFound(format!("scenario '{key}'"))),
            _ => Err(AppError::Invalid(format!("'{key}' matches several scenarios; use the id"))),
        }
    }

    /// Create a scenario authored by the local user (trusted). Every step
    /// must reference a request of the same workspace.
    pub fn create_scenario(&self, ws: &Id, name: &str, steps: Vec<ScenarioStep>) -> Result<Scenario> {
        self.workspace(ws)?;
        let name = name.trim();
        if name.is_empty() {
            return Err(AppError::Invalid("scenario name is empty".into()));
        }
        let s = Scenario {
            meta: Meta::new(),
            workspace_id: *ws,
            name: name.into(),
            description: String::new(),
            steps,
            dataset_id: None,
            iterations: 0,
            stop_on_failure: false,
            trusted: true,
        };
        self.update_scenario(s)
    }

    /// Validate and save a scenario (steps and dataset in this workspace,
    /// within the runner's bounds). Does not change `trusted`.
    pub fn update_scenario(&self, mut s: Scenario) -> Result<Scenario> {
        if s.steps.len() > anvil_runner::MAX_STEPS {
            return Err(AppError::Invalid(format!("a scenario has at most {} steps", anvil_runner::MAX_STEPS)));
        }
        if s.iterations > anvil_runner::MAX_ITERATIONS {
            return Err(AppError::Invalid(format!("a scenario runs at most {} iterations", anvil_runner::MAX_ITERATIONS)));
        }
        for (i, st) in s.steps.iter().enumerate() {
            let r = self
                .request(&st.request_id)
                .map_err(|_| AppError::Invalid(format!("step {}: request {} does not exist", i + 1, st.request_id)))?;
            if r.workspace_id != s.workspace_id {
                return Err(AppError::Invalid(format!("step {}: request '{}' belongs to another workspace", i + 1, r.name)));
            }
            if st.delay_ms > anvil_runner::MAX_DELAY_MS {
                return Err(AppError::Invalid(format!("step {}: think time is limited to {} ms", i + 1, anvil_runner::MAX_DELAY_MS)));
            }
        }
        if let Some(d) = s.dataset_id
            && self.dataset(&d)?.workspace_id != s.workspace_id
        {
            return Err(AppError::Invalid("the dataset belongs to another workspace".into()));
        }
        s.meta.updated_at = chrono::Utc::now();
        self.save_scenario(s)
    }

    /// Mark a reviewed scenario as trusted (explicit user action).
    pub fn trust_scenario(&self, id: &Id) -> Result<Scenario> {
        let mut s = self.scenario(id)?;
        s.trusted = true;
        s.meta.updated_at = chrono::Utc::now();
        self.save_scenario(s)
    }

    pub fn delete_scenario(&self, id: &Id) -> Result<()> {
        self.store.delete(kind::SCENARIO, id)?;
        Ok(())
    }

    // ------------------------------------------------------------ datasets

    pub fn dataset(&self, id: &Id) -> Result<Dataset> {
        self.store.get(kind::DATASET, id)?.ok_or_else(|| AppError::NotFound("dataset".into()))
    }

    /// Validate (parse with the runner's bounds), store the bytes as a
    /// content-addressed attachment and save the dataset.
    pub fn create_dataset(
        &self,
        ws: &Id,
        name: &str,
        format: DatasetFormat,
        bytes: &[u8],
        sensitive_columns: Vec<String>,
    ) -> Result<Dataset> {
        self.workspace(ws)?;
        let name = name.trim();
        if name.is_empty() {
            return Err(AppError::Invalid("dataset name is empty".into()));
        }
        let parsed = RunDataset::parse(name, format, bytes, &sensitive_columns).map_err(|e| AppError::Invalid(e.to_string()))?;
        if !parsed.missing_sensitive_columns.is_empty() {
            return Err(AppError::Invalid(format!(
                "sensitive column(s) {} are not in dataset '{name}'",
                parsed.missing_sensitive_columns.join(", ")
            )));
        }
        let media = match format {
            DatasetFormat::Csv => "text/csv",
            DatasetFormat::Json => "application/json",
        };
        let attachment = self.put_attachment(name, bytes, Some(media.into()))?;
        self.save_dataset(Dataset {
            meta: Meta::new(),
            workspace_id: *ws,
            name: name.into(),
            format,
            attachment,
            sensitive_columns: parsed.sensitive_columns,
        })
    }

    /// Load and parse a saved dataset for a run.
    pub fn run_dataset(&self, d: &Dataset) -> Result<RunDataset> {
        let bytes = match &d.attachment {
            anvil_domain::request::AttachmentRef::Stored { sha256, .. } => {
                self.get_attachment(sha256)?.ok_or_else(|| AppError::NotFound(format!("the data of dataset '{}'", d.name)))?
            }
            anvil_domain::request::AttachmentRef::LinkedFile { path } => {
                let max = crate::file_grants::FilePurpose::Dataset.max_read_bytes();
                self.read_linked_dataset(d.meta.id, path, max).map_err(|e| AppError::Invalid(format!("dataset '{}': {e}", d.name)))?
            }
        };
        RunDataset::parse(&d.name, d.format, &bytes, &d.sensitive_columns).map_err(|e| AppError::Invalid(e.to_string()))
    }

    pub fn delete_dataset(&self, id: &Id) -> Result<()> {
        let d = self.dataset(id).ok();
        self.store.delete(kind::DATASET, id)?;
        if let Some(anvil_domain::request::AttachmentRef::Stored { sha256, .. }) = d.map(|d| d.attachment) {
            self.release_attachment(&sha256)?;
        }
        Ok(())
    }
}
