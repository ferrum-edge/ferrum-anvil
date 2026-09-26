//! Load-test commands. Runs execute in a separate worker process (this same
//! executable re-launched with a fixed mode flag); the UI process only
//! relays throttled progress and stores the final report.

use crate::commands::{R, e, id};
use crate::state::DesktopState;
use anvil_app::load::{LoadPlanCheck, LoadPreflight, LoadReportSummary};
use anvil_domain::Id;
use anvil_domain::load::{LoadPlan, LoadReport};
use anvil_domain::workspace::{Dataset, DatasetFormat};
use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, State};

pub const LOAD_WORKER_FLAG: &str = "--anvil-load-worker";

#[tauri::command]
pub fn load_plans(st: State<'_, DesktopState>, workspace_id: String) -> R<Vec<LoadPlan>> {
    st.app()?.load_plans(&id(&workspace_id)?).map_err(e)
}

/// Saving from the editor is the user's review: the plan becomes trusted.
#[tauri::command]
pub fn load_plan_save(st: State<'_, DesktopState>, mut plan: LoadPlan) -> R<LoadPlan> {
    plan.trusted = true;
    st.app()?.save_load_plan(plan).map_err(e)
}

#[tauri::command]
pub fn load_plan_delete(st: State<'_, DesktopState>, plan_id: String) -> R<()> {
    st.app()?.delete_load_plan(&id(&plan_id)?).map_err(e)
}

#[tauri::command]
pub fn load_preflight(st: State<'_, DesktopState>, plan_id: String) -> R<LoadPreflight> {
    let app = st.app()?;
    let p = app.load_plan(&id(&plan_id)?).map_err(e)?;
    app.load_preflight(&p).map_err(e)
}

/// What an edited (possibly unsaved) plan would measure, or its typed
/// refusal (LOAD-013). Nothing is sent.
#[tauri::command]
pub fn load_plan_check(st: State<'_, DesktopState>, plan: LoadPlan) -> R<LoadPlanCheck> {
    st.app()?.load_plan_check(&plan).map_err(e)
}

#[derive(Serialize, Clone)]
pub struct LoadProgressEvent {
    pub run_key: String,
    pub progress: anvil_load::Progress,
}

#[derive(Serialize, Clone)]
pub struct LoadFinishedEvent {
    pub run_key: String,
    pub run_id: Option<Id>,
    pub error: Option<String>,
}

/// Start a run after the user confirmed the preflight. Returns a run key
/// for progress events and cancellation.
#[tauri::command]
pub async fn load_run_start(st: State<'_, DesktopState>, handle: AppHandle, plan_id: String, acknowledged: bool) -> R<String> {
    let app = st.app()?;
    let plan = app.load_plan(&id(&plan_id)?).map_err(e)?;
    let job = app.worker_job(&plan, acknowledged).map_err(e)?;
    let exe = std::env::current_exe().map_err(|x| x.to_string())?;
    let mut controller = anvil_load::LoadController::spawn_mode(&exe, Some(LOAD_WORKER_FLAG), &job).await.map_err(|x| x.to_string())?;
    let run_key = Id::new().to_string();
    let cancel = tokio_util::sync::CancellationToken::new();
    let lock = tokio_util::sync::CancellationToken::new();
    st.load_runs.lock().insert(run_key.clone(), (cancel.clone(), lock.clone()));
    let key = run_key.clone();
    tauri::async_runtime::spawn(async move {
        let mut canceled = false;
        loop {
            tokio::select! {
                p = controller.next_progress() => match p {
                    Some(progress) => {
                        let _ = handle.emit("load-progress", LoadProgressEvent { run_key: key.clone(), progress });
                    }
                    None => break,
                },
                _ = cancel.cancelled(), if !canceled => {
                    canceled = true;
                    controller.cancel().await;
                }
                _ = lock.cancelled(), if !canceled => {
                    canceled = true;
                    controller.cancel_for_lock().await;
                }
            }
        }
        let result = controller.wait().await;
        let st = handle.state::<DesktopState>();
        st.load_runs.lock().remove(&key);
        let ev = match result {
            Ok(report) => {
                let run_id = report.run_id;
                match st.app() {
                    Ok(a) => match a.save_load_report(&report) {
                        Ok(()) => LoadFinishedEvent { run_key: key.clone(), run_id: Some(run_id), error: None },
                        Err(err) => LoadFinishedEvent {
                            run_key: key.clone(),
                            run_id: None,
                            error: Some(format!("the run finished but its report could not be saved: {}", e(err))),
                        },
                    },
                    // Locked mid-run: keep the (redacted) partial report and
                    // store it at the next unlock.
                    Err(_) => {
                        st.pending_load_reports.lock().push(report);
                        LoadFinishedEvent { run_key: key.clone(), run_id: Some(run_id), error: None }
                    }
                }
            }
            Err(err) => LoadFinishedEvent { run_key: key.clone(), run_id: None, error: Some(err.to_string()) },
        };
        let _ = handle.emit("load-finished", ev);
    });
    Ok(run_key)
}

#[tauri::command]
pub fn load_run_cancel(st: State<'_, DesktopState>, run_key: String) -> bool {
    match st.load_runs.lock().get(&run_key) {
        Some((user, _)) => {
            user.cancel();
            true
        }
        None => false,
    }
}

#[tauri::command]
pub fn load_reports(st: State<'_, DesktopState>, workspace_id: String) -> R<Vec<LoadReportSummary>> {
    st.app()?.load_reports(&id(&workspace_id)?).map_err(e)
}

#[tauri::command]
pub fn load_report(st: State<'_, DesktopState>, run_id: String) -> R<LoadReport> {
    st.app()?.load_report(&id(&run_id)?).map_err(e)
}

#[tauri::command]
pub fn load_report_delete(st: State<'_, DesktopState>, run_id: String) -> R<()> {
    st.app()?.delete_load_report(&id(&run_id)?).map_err(e)
}

/// Export to a path chosen in the native save dialog: `json` (integrity-
/// hashed, re-openable), `csv` (summary), `timeline_csv`, or `html` (offline,
/// no scripts).
#[tauri::command]
pub fn load_report_export(st: State<'_, DesktopState>, run_id: String, format: String, path: String) -> R<usize> {
    let r = st.app()?.load_report(&id(&run_id)?).map_err(e)?;
    let text = match format.as_str() {
        "json" => anvil_load::report::to_json(&r),
        "csv" => anvil_load::report::summary_csv(&r),
        "timeline_csv" => anvil_load::report::timeline_csv(&r),
        "html" => anvil_load::html::to_html(&r),
        other => return Err(format!("unknown export format {other}")),
    };
    std::fs::write(&path, text.as_bytes()).map_err(|x| x.to_string())?;
    Ok(text.len())
}

#[tauri::command]
pub fn load_compare(st: State<'_, DesktopState>, a: String, b: String) -> R<anvil_load::Comparison> {
    let app = st.app()?;
    let ra = app.load_report(&id(&a)?).map_err(e)?;
    let rb = app.load_report(&id(&b)?).map_err(e)?;
    Ok(anvil_load::compare(&ra, &rb))
}

#[tauri::command]
pub fn datasets_list(st: State<'_, DesktopState>, workspace_id: String) -> R<Vec<Dataset>> {
    st.app()?.datasets(&id(&workspace_id)?).map_err(e)
}

/// Copy a CSV/JSON file into encrypted storage as a dataset after checking
/// that it parses.
#[tauri::command]
pub fn dataset_add(
    st: State<'_, DesktopState>,
    workspace_id: String,
    path: String,
    name: String,
    sensitive_columns: Vec<String>,
) -> R<Dataset> {
    const MAX: u64 = 64 * 1024 * 1024;
    let meta = std::fs::metadata(&path).map_err(|x| x.to_string())?;
    if meta.len() > MAX {
        return Err("datasets are limited to 64 MiB".into());
    }
    let bytes = std::fs::read(&path).map_err(|x| x.to_string())?;
    let lower = path.to_ascii_lowercase();
    let (format, load_fmt) = if lower.ends_with(".json") {
        (DatasetFormat::Json, anvil_load::DatasetFormat::Json)
    } else {
        (DatasetFormat::Csv, anvil_load::DatasetFormat::Csv)
    };
    let parsed = anvil_load::Dataset::parse(load_fmt, bytes.clone()).map_err(|x| x.to_string())?;
    if let Some(missing) = sensitive_columns.iter().find(|c| !parsed.columns.contains(c)) {
        return Err(format!("the dataset has no column named '{missing}'"));
    }
    let app = st.app()?;
    let file_name = std::path::Path::new(&path).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "dataset".into());
    let attachment = app.put_attachment(&file_name, &bytes, None).map_err(e)?;
    let d = Dataset {
        meta: anvil_domain::workspace::Meta::new(),
        workspace_id: id(&workspace_id)?,
        name,
        format,
        attachment,
        sensitive_columns,
    };
    app.save_dataset(d).map_err(e)
}
