//! What to run and how.

use crate::dataset::RunDataset;
use crate::{MAX_DELAY_MS, MAX_ITERATIONS, MAX_STEPS, RunError, RunEventSink};
use anvil_domain::Id;
use anvil_domain::runner::{FailOn, RunSource};
use anvil_domain::workspace::Scenario;

/// One step of a run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedStep {
    pub request_id: Id,
    /// Display name used when the step is not executed (skipped / canceled).
    pub name: String,
    pub enabled: bool,
    /// Think time before the step.
    pub delay_ms: u64,
}

/// A validated-on-start description of a run.
#[derive(Debug, Clone)]
pub struct RunPlan {
    pub workspace_id: Id,
    pub name: String,
    pub source: RunSource,
    pub steps: Vec<PlannedStep>,
    /// Iterations requested by the source (`0` = derive: dataset rows, else 1).
    pub iterations: u32,
    pub stop_on_failure: bool,
    /// Whether the source is trusted. Imported scenarios are untrusted until
    /// the user reviews them; ad-hoc folder runs of the user's saved requests
    /// are an explicit user action.
    pub trusted: bool,
    pub dataset: Option<RunDataset>,
    pub environment_id: Option<Id>,
    pub environment_name: Option<String>,
}

impl RunPlan {
    /// Plan for a saved scenario. `names` gives display names for request ids.
    pub fn from_scenario(s: &Scenario, names: &dyn Fn(&Id) -> String, dataset: Option<RunDataset>) -> RunPlan {
        RunPlan {
            workspace_id: s.workspace_id,
            name: s.name.clone(),
            source: RunSource::Scenario { scenario_id: s.meta.id, name: s.name.clone(), untrusted_override: false },
            steps: s
                .steps
                .iter()
                .map(|st| PlannedStep {
                    request_id: st.request_id,
                    name: names(&st.request_id),
                    enabled: st.enabled,
                    delay_ms: st.delay_ms,
                })
                .collect(),
            iterations: s.iterations,
            stop_on_failure: s.stop_on_failure,
            trusted: s.trusted,
            dataset,
            environment_id: None,
            environment_name: None,
        }
    }

    /// Ad-hoc plan for requests of a folder subtree (already in tree order).
    pub fn folder(workspace_id: Id, folder_id: Option<Id>, path: &str, requests: Vec<(Id, String)>) -> RunPlan {
        RunPlan {
            workspace_id,
            name: if path.is_empty() || path == "/" { "Workspace".into() } else { path.to_string() },
            source: RunSource::Folder { folder_id, path: if path.is_empty() { "/".into() } else { path.to_string() } },
            steps: requests.into_iter().map(|(request_id, name)| PlannedStep { request_id, name, enabled: true, delay_ms: 0 }).collect(),
            iterations: 0,
            stop_on_failure: false,
            trusted: true,
            dataset: None,
            environment_id: None,
            environment_name: None,
        }
    }

    /// Validate against the bounds and the options; returns the iteration count.
    pub(crate) fn check(&self, opts: &RunOptions) -> Result<u32, RunError> {
        if !self.trusted && !opts.allow_untrusted {
            return Err(RunError::Untrusted(self.name.clone()));
        }
        if self.steps.is_empty() {
            return Err(RunError::Invalid(format!("'{}' has no steps", self.name)));
        }
        if !self.steps.iter().any(|s| s.enabled) {
            return Err(RunError::Invalid(format!("'{}' has no enabled steps", self.name)));
        }
        if self.steps.len() > MAX_STEPS {
            return Err(RunError::Invalid(format!("'{}' has {} steps; the limit is {MAX_STEPS}", self.name, self.steps.len())));
        }
        if let Some((i, s)) = self.steps.iter().enumerate().find(|(_, s)| s.delay_ms > MAX_DELAY_MS) {
            return Err(RunError::Invalid(format!(
                "step {} ('{}') waits {} ms; the think-time limit is {MAX_DELAY_MS} ms",
                i + 1,
                s.name,
                s.delay_ms
            )));
        }
        let iterations = match opts.iterations {
            Some(0) => return Err(RunError::Invalid("iterations must be at least 1".into())),
            Some(n) => n,
            None if self.iterations > 0 => self.iterations,
            None => self.dataset.as_ref().map(|d| d.row_count().min(u32::MAX as usize) as u32).unwrap_or(1),
        };
        if iterations > MAX_ITERATIONS {
            return Err(RunError::Invalid(format!("{iterations} iterations requested; the limit is {MAX_ITERATIONS}")));
        }
        Ok(iterations)
    }
}

/// Caller choices for one run.
#[derive(Clone, Default)]
pub struct RunOptions {
    /// Override the plan's iteration count.
    pub iterations: Option<u32>,
    /// Override the plan's `stop_on_failure`.
    pub stop_on_failure: Option<bool>,
    /// What counts as a failed step (default: all three dimensions).
    pub fail_on: FailOn,
    /// Run an untrusted (imported) scenario anyway. UIs set this only after
    /// the user confirmed it for this run; it is recorded in the report.
    pub allow_untrusted: bool,
    /// Live progress (throttled, bounded).
    pub events: Option<RunEventSink>,
    /// Pre-assigned run id (so a UI can correlate events before the report).
    pub run_id: Option<Id>,
    /// Override of [`crate::MAX_REPORT_STEPS`] (tests, constrained callers).
    pub max_report_steps: Option<usize>,
}

impl std::fmt::Debug for RunOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RunOptions")
            .field("iterations", &self.iterations)
            .field("stop_on_failure", &self.stop_on_failure)
            .field("fail_on", &self.fail_on)
            .field("allow_untrusted", &self.allow_untrusted)
            .field("events", &self.events.is_some())
            .field("run_id", &self.run_id)
            .finish()
    }
}
