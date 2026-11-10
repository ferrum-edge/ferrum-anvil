//! Read a saved dataset the way a run reads it: through a one-step scenario
//! that names it, so its stored data or linked file goes through the same
//! checks (`App::run_scenario`, the linked-file permission query) as a run
//! the user starts.

// Each integration-test binary uses only the variant it needs.
#![allow(dead_code)]

use anvil_app::runner::RunSettings;
use anvil_app::{App, AppError};
use anvil_domain::request::RequestSpec;
use anvil_domain::workspace::{Dataset, ScenarioStep};
use tokio_util::sync::CancellationToken;

/// The number of rows a run of `dataset` iterates over, or why the run is
/// refused. Adds a request and a scenario that names `dataset` to its
/// workspace; the step targets the discard port, and neither history nor
/// the report is kept.
pub async fn dataset_rows(app: &App, dataset: &Dataset) -> Result<u32, AppError> {
    let ws = dataset.workspace_id;
    let request = app.create_request(&ws, None, "dataset row", RequestSpec::http("GET", "http://127.0.0.1:9/row")).unwrap();
    let mut scenario =
        app.new_scenario(&ws, "dataset rows", vec![ScenarioStep { request_id: request.meta.id, enabled: true, delay_ms: 0 }]).unwrap();
    scenario.dataset_id = Some(dataset.meta.id);
    let scenario = app.update_scenario(scenario).unwrap();
    let settings = RunSettings { record_history: false, persist_report: false, ..Default::default() };
    let report = app.run_scenario(&scenario.meta.id, settings, CancellationToken::new()).await?;
    Ok(report.totals.iterations_planned)
}

/// [`dataset_rows`] from a test that is not async.
pub fn dataset_rows_blocking(app: &App, dataset: &Dataset) -> Result<u32, AppError> {
    tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(dataset_rows(app, dataset))
}
