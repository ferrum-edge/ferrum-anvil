//! Anvil's collection runner.
//!
//! Executes an ordered chain of saved requests — a [`Scenario`] or every
//! request of a folder subtree — through [`anvil_engine::Engine::execute`],
//! exactly like a manual Send: the same preparation, per-send auth, TLS
//! policy, transport, redaction and diagnostics. The runner adds only:
//!
//! * **run-local variables** layered at the highest precedence (plan §5.3):
//!   `{{anvil.iteration}}` / `{{anvil.step}}`, the iteration's dataset row,
//!   then values extracted by earlier steps of the same iteration;
//! * **datasets** ([`RunDataset`]): CSV or a JSON array of objects, bounded,
//!   rows cycled per iteration, sensitive columns treated as secrets;
//! * **semantics**: `stop_on_failure` with a configurable [`FailOn`]
//!   definition of "failed", think time, trust gating of imported
//!   scenarios, cancellation with a partial report, throttled progress events;
//! * **reports**: [`RunReport`] (versioned contract in `anvil-domain`) with
//!   JSON, JUnit XML and standalone offline HTML exports.
//!
//! The runner never retries a step: retries stay the engine's decision, and
//! the engine never replays a possibly processed non-idempotent request.
//!
//! The runner does not read storage. A [`StepProvider`] (implemented by
//! `anvil-app`) yields the frozen [`anvil_engine::ExecutionContext`] of each
//! saved request and records executed steps in history.
//!
//! See `docs/runner.md`.
//!
//! [`Scenario`]: anvil_domain::workspace::Scenario
//! [`FailOn`]: anvil_domain::runner::FailOn
//! [`RunReport`]: anvil_domain::runner::RunReport

pub mod dataset;
mod emit;
pub mod html;
pub mod junit;
pub mod plan;
pub mod provider;
pub mod redact;
mod run;

pub use anvil_domain::runner::{FailOn, RunEvent, RunReport};
pub use dataset::RunDataset;
pub use html::to_html;
pub use junit::to_junit;
pub use plan::{PlannedStep, RunOptions, RunPlan};
pub use provider::{ProvidedStep, StepError, StepProvider};
pub use run::run;

use std::sync::Arc;

/// Maximum iterations of one run.
pub const MAX_ITERATIONS: u32 = 10_000;
/// Maximum steps in one scenario / folder run.
pub const MAX_STEPS: usize = 1_000;
/// Maximum think time before one step.
pub const MAX_DELAY_MS: u64 = 10 * 60 * 1000;
/// Step summaries retained in a report before passing steps are omitted
/// (failed, errored and canceled steps get [`MAX_EXTRA_FAILED_STEPS`] more).
pub const MAX_REPORT_STEPS: usize = 10_000;
pub const MAX_EXTRA_FAILED_STEPS: usize = 2_000;
/// Assertion results kept per step summary.
pub const MAX_ASSERTIONS_PER_STEP: usize = 50;
/// Findings kept per step summary.
pub const MAX_FINDINGS_PER_STEP: usize = 5;
/// Notes kept in a report.
pub const MAX_NOTES: usize = 50;

/// Callback receiving live run events. It must not block: forward into a
/// bounded channel with `try_send` (the runner already throttles).
pub type RunEventSink = Arc<dyn Fn(RunEvent) + Send + Sync>;

/// Runner build identity recorded in every report.
pub fn runner_version() -> String {
    format!("anvil-runner/{}+{}", env!("CARGO_PKG_VERSION"), anvil_transport::ADAPTER_VERSION)
}

/// Errors that prevent a run from starting. Once a run starts it always
/// produces a report (possibly partial), never an error.
#[derive(Debug, thiserror::Error)]
pub enum RunError {
    /// The scenario is not trusted (e.g. imported) and the caller did not pass
    /// the explicit, user-confirmed override. Nothing was sent.
    #[error(
        "scenario '{0}' is not trusted (it was imported or not yet reviewed); review it and mark it trusted, or explicitly allow this run. Nothing was sent."
    )]
    Untrusted(String),
    /// The plan or options are invalid. Nothing was sent.
    #[error("invalid run: {0}")]
    Invalid(String),
    /// The dataset could not be used. Nothing was sent.
    #[error("dataset: {0}")]
    Dataset(String),
}

/// JSON export of a report (pretty-printed, trailing newline).
pub fn to_json(report: &RunReport) -> String {
    let mut s = serde_json::to_string_pretty(report).unwrap_or_else(|_| "{}".into());
    s.push('\n');
    s
}

/// Truncate to at most `max` bytes on a char boundary, marking the cut.
pub(crate) fn clip(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &s[..end])
}
