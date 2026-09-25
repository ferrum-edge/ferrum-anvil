//! The boundary between the runner and storage.

use anvil_domain::Id;
use anvil_engine::{ExecutionContext, ExecutionOutput};

/// A saved request resolved for execution.
pub struct ProvidedStep {
    /// Display name of the request.
    pub name: String,
    /// Frozen context exactly as a manual Send of this request would use it
    /// (settings, auth and variable layers resolved from workspace → folders
    /// → request, environment selected, secrets resolver, attachments).
    ///
    /// The runner appends the run-local variable layers (iteration builtins,
    /// dataset row, extracted values) **after** the provider's layers, so they
    /// always take the highest precedence; the provider must not add them.
    pub context: ExecutionContext,
}

/// Why a step could not be provided or recorded.
#[derive(Debug, Clone)]
pub enum StepError {
    /// This step cannot run (request deleted, a referenced secret is missing,
    /// ...). The step is reported as `error`; the run continues.
    Step(String),
    /// The run cannot continue (the vault locked, the workspace was removed).
    /// The run ends as `aborted` with a partial report.
    Fatal(String),
}

impl std::fmt::Display for StepError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StepError::Step(m) | StepError::Fatal(m) => f.write_str(m),
        }
    }
}

/// Supplies execution contexts for saved requests and records executed
/// steps. Implemented by `anvil-app` over the encrypted store; tests
/// implement it over in-memory contexts.
pub trait StepProvider: Send + Sync {
    /// The frozen context of saved request `request_id`. Called once per
    /// executed step (implementations should snapshot at run start so a run
    /// uses a frozen environment, plan §5.3).
    fn step(&self, request_id: &Id) -> Result<ProvidedStep, StepError>;

    /// Record an executed step (history), after the runner has scrubbed the
    /// run's sensitive values from it. Default: not recorded.
    fn record(&self, _output: &ExecutionOutput) -> Result<(), StepError> {
        Ok(())
    }
}

/// A provider over prepared contexts (CLI one-offs, tests, embedding).
#[derive(Default, Clone)]
pub struct MemoryProvider {
    pub steps: std::collections::HashMap<Id, (String, ExecutionContext)>,
}

impl MemoryProvider {
    pub fn insert(&mut self, id: Id, name: &str, ctx: ExecutionContext) {
        self.steps.insert(id, (name.to_string(), ctx));
    }
}

impl StepProvider for MemoryProvider {
    fn step(&self, request_id: &Id) -> Result<ProvidedStep, StepError> {
        match self.steps.get(request_id) {
            Some((name, ctx)) => Ok(ProvidedStep { name: name.clone(), context: ctx.clone() }),
            None => Err(StepError::Step(format!("request {request_id} is not available to this run"))),
        }
    }
}
