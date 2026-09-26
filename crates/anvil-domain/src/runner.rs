//! Collection-runner contracts: the saved [`RunReport`] and the live
//! [`RunEvent`] stream.
//!
//! A collection run executes an ordered chain of saved requests through the
//! same engine as a manual Send. The report keeps the three outcome
//! dimensions of every step distinct — transport completion, application
//! status and assertion results — and records which of them the run's
//! [`FailOn`] policy counted as a failure. It holds bounded per-step
//! summaries only (never response bodies); every string that could carry a
//! secret is redacted before it is stored here.

use crate::Id;
use crate::assertions::AssertionResult;
use crate::diagnostics::{Confidence, Severity};
use crate::execution::DispatchState;
use crate::outcome::{ApplicationState, AssertionState, TransportState};
use crate::request::Protocol;
use crate::workspace::DatasetFormat;
use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Version of the [`RunReport`] layout. Bump on any breaking change.
pub const RUN_REPORT_VERSION: u32 = 1;

/// Which outcome dimensions make a step count as *failed* (for the step
/// status, `stop_on_failure`, totals and exit codes).
///
/// The default counts all three: a step fails when its transport did not
/// complete, its application status is a failure (HTTP 4xx/5xx, gRPC
/// non-OK, SOAP fault, GraphQL errors) or any enabled assertion failed. A
/// step the runner could not even prepare (`error`) always counts as failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct FailOn {
    #[serde(default = "yes")]
    pub transport: bool,
    #[serde(default = "yes")]
    pub application: bool,
    #[serde(default = "yes")]
    pub assertions: bool,
}

fn yes() -> bool {
    true
}

impl Default for FailOn {
    fn default() -> Self {
        FailOn { transport: true, application: true, assertions: true }
    }
}

/// One of the three independent outcome dimensions of a step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeDimension {
    /// The exchange did not complete (failed before a response, incomplete
    /// response, local preparation failure).
    Transport,
    /// A response arrived but reports an application failure.
    Application,
    /// At least one enabled assertion failed (or could not be evaluated).
    Assertions,
}

/// What was run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RunSource {
    /// A saved scenario.
    Scenario {
        scenario_id: Id,
        name: String,
        /// The scenario was not trusted (e.g. imported) and ran only because
        /// the user explicitly allowed it for this run.
        #[serde(default)]
        untrusted_override: bool,
    },
    /// An ad-hoc run of every request in a folder subtree, in tree order.
    Folder {
        /// `None` = the workspace root.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        folder_id: Option<Id>,
        /// Display path (`Orders/Refunds`, or `/` for the root).
        path: String,
    },
}

/// How the run ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RunnerCompletion {
    /// Every planned iteration ran to its end (steps may still have failed).
    Completed,
    /// The user (or app shutdown / lock policy) canceled the run.
    Canceled,
    /// The run could not continue (e.g. the vault locked, the workspace
    /// disappeared); the report is partial.
    Aborted,
}

/// Status of one step in one iteration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RunStepStatus {
    /// Executed; no dimension counted by [`FailOn`] failed.
    Passed,
    /// Executed; at least one dimension counted by [`FailOn`] failed.
    Failed,
    /// Not executed: the runner could not obtain the request (deleted,
    /// unreadable secret, ...). Nothing was sent. Always counts as failed.
    Error,
    /// Not executed: disabled in the scenario, or the iteration stopped at an
    /// earlier failed step (`stop_on_failure`).
    Skipped,
    /// Canceled while in flight (the request may or may not have reached the
    /// peer — see `dispatch`), or not started because the run was canceled.
    Canceled,
}

/// Status of one iteration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RunIterationStatus {
    /// Every executed step passed (skipped disabled steps do not count).
    Passed,
    /// At least one step failed or errored.
    Failed,
    /// The run was canceled or aborted during this iteration.
    Incomplete,
}

/// A diagnostic finding reduced to what a run report needs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RunFindingSummary {
    pub code: String,
    pub title: String,
    pub confidence: Confidence,
    pub severity: Severity,
}

/// Bounded summary of one step execution. Never contains a response body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RunStep {
    /// Position in the scenario / folder order (0-based).
    pub index: u32,
    pub request_id: Id,
    /// Exact request revision executed (when the request has been saved).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision_id: Option<Id>,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<Protocol>,
    #[serde(default)]
    pub method: String,
    /// Redacted URL as prepared (or the template when the step never ran).
    #[serde(default)]
    pub url: String,
    pub status: RunStepStatus,
    /// Dimensions that failed, whether or not [`FailOn`] counts them.
    #[serde(default)]
    pub failed_dimensions: Vec<OutcomeDimension>,
    /// Id of the step's `ExecutionRecord` (history), when it was executed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_id: Option<Id>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<TransportState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application: Option<ApplicationState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assertions: Option<AssertionState>,
    /// Whether the request may have been processed by the peer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dispatch: Option<DispatchState>,
    /// HTTP status (or handshake status) when a response head arrived.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_status: Option<u16>,
    /// gRPC terminal status when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grpc_status: Option<i32>,
    /// Redacted one-line summary.
    #[serde(default)]
    pub summary: String,
    /// Redacted reason for `error` / `skipped` / `canceled`, or the typed
    /// transport failure message.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Wall-clock time of the step (preparation, auth, exchange, diagnosis).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    /// Sum of the network attempt durations (the same exchange time latency
    /// assertions evaluate).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exchange_ms: Option<u64>,
    /// Think time waited before the step.
    #[serde(default)]
    pub delay_ms: u64,
    /// Assertion results (redacted, bounded).
    #[serde(default)]
    pub assertion_results: Vec<AssertionResult>,
    /// Assertion results dropped by the per-step bound.
    #[serde(default)]
    pub assertion_results_omitted: u32,
    /// Highest-severity findings first (bounded).
    #[serde(default)]
    pub findings: Vec<RunFindingSummary>,
    /// Names of variables this step extracted (values are never reported).
    #[serde(default)]
    pub extracted: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RunIteration {
    /// 0-based iteration number (the `anvil.iteration` variable).
    pub index: u32,
    /// 1-based dataset row used by this iteration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dataset_row: Option<u32>,
    pub started_at: DateTime<Utc>,
    pub duration_ms: u64,
    pub status: RunIterationStatus,
    /// Set when `stop_on_failure` ended the iteration early: the index of the
    /// step that failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stopped_at_step: Option<u32>,
    pub steps: Vec<RunStep>,
    /// Passing/skipped step summaries dropped by the report-size bound (the
    /// totals still count them; failed steps are kept preferentially).
    #[serde(default)]
    pub steps_omitted: u32,
}

/// Counts over the whole run. The step ledger balances:
/// * `steps_executed = steps_passed + steps_failed + steps_canceled_in_flight`;
/// * every planned step of a started iteration is exactly one of executed,
///   `steps_errored`, `steps_skipped` or `steps_canceled` (not started).
///
/// The per-dimension counters (`transport_failures`, `application_failures`,
/// `assertion_failures`) count executed steps whose dimension failed,
/// regardless of [`FailOn`]; they are independent and may overlap.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
pub struct RunTotals {
    pub iterations_planned: u32,
    pub iterations_started: u32,
    pub iterations_passed: u32,
    pub iterations_failed: u32,
    pub iterations_incomplete: u32,
    /// Engine executions (one `ExecutionRecord` each).
    pub steps_executed: u64,
    pub steps_passed: u64,
    pub steps_failed: u64,
    pub steps_errored: u64,
    pub steps_skipped: u64,
    /// Steps not started because the run was canceled or aborted.
    pub steps_canceled: u64,
    /// Executed steps that were canceled mid-flight.
    pub steps_canceled_in_flight: u64,
    /// Executed steps whose transport did not complete.
    pub transport_failures: u64,
    /// Executed steps whose application status was a failure.
    pub application_failures: u64,
    /// Executed steps with at least one failed assertion.
    pub assertion_failures: u64,
    /// Individual assertion results.
    pub assertions_passed: u64,
    pub assertions_failed: u64,
    /// Sum of step wall-clock durations.
    pub step_time_ms: u64,
}

/// Dataset identity recorded with the run (never its values).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RunDatasetSummary {
    pub name: String,
    pub format: DatasetFormat,
    /// SHA-256 of the exact dataset bytes.
    pub sha256: String,
    pub rows: u32,
    pub columns: Vec<String>,
    /// Columns whose values were treated as secrets.
    pub sensitive_columns: Vec<String>,
}

/// Saved, self-describing collection-run report. Viewable offline; exported
/// as JSON, JUnit XML and a standalone HTML summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RunReport {
    pub run_id: Id,
    /// [`RUN_REPORT_VERSION`].
    pub report_version: u32,
    /// Persisted object schema version ([`crate::SCHEMA_VERSION`]).
    pub schema_version: u32,
    /// Runner build identity (runner crate version + transport adapter version).
    pub runner_version: String,
    pub workspace_id: Id,
    /// Display name of the run (scenario name or folder path).
    pub name: String,
    pub source: RunSource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment_id: Option<Id>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dataset: Option<RunDatasetSummary>,
    pub fail_on: FailOn,
    pub stop_on_failure: bool,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    pub duration_ms: u64,
    pub completion: RunnerCompletion,
    /// True unless every planned iteration ran (cancel / abort).
    pub partial: bool,
    /// Redacted reason when the run was aborted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub abort_reason: Option<String>,
    pub totals: RunTotals,
    pub iterations: Vec<RunIteration>,
    /// Redacted notes (bounds applied, history recording problems, possibly
    /// processed canceled requests, dataset remarks, ...).
    #[serde(default)]
    pub notes: Vec<String>,
}

impl RunReport {
    /// True when no step counted as failed and the run completed.
    pub fn passed(&self) -> bool {
        self.completion == RunnerCompletion::Completed && self.totals.steps_failed == 0 && self.totals.steps_errored == 0
    }
}

/// Live progress snapshot carried by run events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
pub struct RunProgress {
    /// Steps finished so far (executed, errored, skipped or canceled).
    pub steps_done: u64,
    /// Planned steps (iterations × steps).
    pub steps_total: u64,
    pub steps_failed: u64,
    pub iterations_done: u32,
    pub iterations_total: u32,
}

/// Bounded, throttled live events of a collection run. The final
/// [`RunReport`] is authoritative; events may be coalesced under load
/// (failure events are preferred, `run_started` / `run_finished` are never
/// dropped).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum RunEvent {
    RunStarted {
        run_id: Id,
        name: String,
        iterations: u32,
        steps: u32,
    },
    IterationStarted {
        run_id: Id,
        iteration: u32,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        dataset_row: Option<u32>,
    },
    StepStarted {
        run_id: Id,
        iteration: u32,
        step: u32,
        request_id: Id,
        name: String,
    },
    StepFinished {
        run_id: Id,
        iteration: u32,
        step: u32,
        status: RunStepStatus,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        execution_id: Option<Id>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        http_status: Option<u16>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        duration_ms: Option<u64>,
        progress: RunProgress,
    },
    IterationFinished {
        run_id: Id,
        iteration: u32,
        status: RunIterationStatus,
        progress: RunProgress,
    },
    RunFinished {
        run_id: Id,
        completion: RunnerCompletion,
        progress: RunProgress,
        /// Events dropped by throttling.
        dropped_events: u64,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fail_on_defaults_to_all_dimensions() {
        assert_eq!(FailOn::default(), FailOn { transport: true, application: true, assertions: true });
        let parsed: FailOn = serde_json::from_str(r#"{"application":false}"#).unwrap();
        assert_eq!(parsed, FailOn { transport: true, application: false, assertions: true });
    }

    #[test]
    fn events_are_tagged() {
        let e = RunEvent::RunStarted { run_id: Id::nil(), name: "x".into(), iterations: 1, steps: 2 };
        let v = serde_json::to_value(&e).unwrap();
        assert_eq!(v["event"], "run_started");
    }
}
