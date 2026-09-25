//! Collection-runner commands: scenarios, folder runs, reports.

use crate::commands::{R, e, id};
use crate::state::DesktopState;
use anvil_app::runner::RunSettings;
use anvil_domain::Id;
use anvil_domain::runner::{RunEvent, RunReport};
use anvil_domain::workspace::{Scenario, ScenarioStep};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tauri::{AppHandle, Emitter, State};
use tokio_util::sync::CancellationToken;

#[tauri::command]
pub fn scenarios_list(st: State<'_, DesktopState>, workspace_id: String) -> R<Vec<Scenario>> {
    st.app()?.scenarios(&id(&workspace_id)?).map_err(e)
}

#[tauri::command]
pub fn scenario_create(st: State<'_, DesktopState>, workspace_id: String, name: String, request_ids: Vec<String>) -> R<Scenario> {
    let steps = request_ids.iter().map(|r| Ok(ScenarioStep { request_id: id(r)?, enabled: true, delay_ms: 0 })).collect::<R<Vec<_>>>()?;
    st.app()?.create_scenario(&id(&workspace_id)?, &name, steps).map_err(e)
}

#[tauri::command]
pub fn scenario_save(st: State<'_, DesktopState>, scenario: Scenario) -> R<Scenario> {
    st.app()?.update_scenario(scenario).map_err(e)
}

/// Mark an imported scenario as reviewed so it can run.
#[tauri::command]
pub fn scenario_trust(st: State<'_, DesktopState>, scenario_id: String) -> R<Scenario> {
    st.app()?.trust_scenario(&id(&scenario_id)?).map_err(e)
}

#[tauri::command]
pub fn scenario_delete(st: State<'_, DesktopState>, scenario_id: String) -> R<()> {
    st.app()?.delete_scenario(&id(&scenario_id)?).map_err(e)
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RunTarget {
    Scenario { scenario_id: String },
    Folder { workspace_id: String, folder_id: Option<String> },
}

#[derive(Deserialize, Default)]
pub struct RunInput {
    pub environment_id: Option<String>,
    pub iterations: Option<u32>,
    pub stop_on_failure: Option<bool>,
    #[serde(default)]
    pub allow_untrusted: bool,
}

#[derive(Serialize, Clone)]
pub struct RunFinished {
    pub run_id: String,
    pub error: Option<String>,
}

/// Start a run; progress arrives as `run-event`, the end as `run-finished`.
#[tauri::command]
pub async fn run_start(st: State<'_, DesktopState>, handle: AppHandle, target: RunTarget, input: RunInput) -> R<String> {
    let app = st.app()?;
    let run_id = Id::new();
    let cancel = CancellationToken::new();
    st.running.lock().insert(run_id, cancel.clone());
    let h2 = handle.clone();
    let sink: anvil_runner::RunEventSink = Arc::new(move |ev: RunEvent| {
        let _ = h2.emit("run-event", &ev);
    });
    let settings = RunSettings {
        environment: input.environment_id.as_deref().map(id).transpose()?,
        iterations: input.iterations,
        stop_on_failure: input.stop_on_failure,
        allow_untrusted: input.allow_untrusted,
        events: Some(sink),
        run_id: Some(run_id),
        ..Default::default()
    };
    let key = run_id.to_string();
    let target_scenario = match &target {
        RunTarget::Scenario { scenario_id } => Some(id(scenario_id)?),
        RunTarget::Folder { .. } => None,
    };
    let folder = match &target {
        RunTarget::Folder { workspace_id, folder_id } => Some((id(workspace_id)?, folder_id.as_deref().map(id).transpose()?)),
        RunTarget::Scenario { .. } => None,
    };
    let st_running = handle.clone();
    tauri::async_runtime::spawn(async move {
        let res = match (target_scenario, folder) {
            (Some(sid), _) => app.run_scenario(&sid, settings, cancel).await,
            (None, Some((ws, f))) => app.run_folder(&ws, f, settings, cancel).await,
            _ => unreachable!(),
        };
        {
            use tauri::Manager;
            st_running.state::<DesktopState>().running.lock().remove(&run_id);
        }
        let ev = match res {
            Ok(r) => RunFinished { run_id: r.run_id.to_string(), error: None },
            Err(err) => RunFinished { run_id: run_id.to_string(), error: Some(e(err)) },
        };
        let _ = handle.emit("run-finished", ev);
    });
    Ok(key)
}

#[tauri::command]
pub fn run_cancel(st: State<'_, DesktopState>, run_id: String) -> R<bool> {
    Ok(match st.running.lock().get(&id(&run_id)?) {
        Some(t) => {
            t.cancel();
            true
        }
        None => false,
    })
}

#[tauri::command]
pub fn run_reports(st: State<'_, DesktopState>, workspace_id: String) -> R<Vec<RunReport>> {
    st.app()?.run_reports(&id(&workspace_id)?).map_err(e)
}

#[tauri::command]
pub fn run_report(st: State<'_, DesktopState>, run_id: String) -> R<RunReport> {
    st.app()?.run_report(&id(&run_id)?).map_err(e)
}

#[tauri::command]
pub fn run_report_delete(st: State<'_, DesktopState>, run_id: String) -> R<()> {
    st.app()?.delete_run_report(&id(&run_id)?).map_err(e)
}

/// Export to a path chosen in the native save dialog: `json`, `junit`, `html`.
#[tauri::command]
pub fn run_report_export(st: State<'_, DesktopState>, run_id: String, format: String, path: String) -> R<usize> {
    let r = st.app()?.run_report(&id(&run_id)?).map_err(e)?;
    let text = match format.as_str() {
        "json" => anvil_runner::to_json(&r),
        "junit" => anvil_runner::to_junit(&r),
        "html" => anvil_runner::to_html(&r),
        other => return Err(format!("unknown export format {other}")),
    };
    std::fs::write(&path, text.as_bytes()).map_err(|x| x.to_string())?;
    Ok(text.len())
}
