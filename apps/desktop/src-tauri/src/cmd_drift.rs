//! Contract drift of imported OpenAPI descriptions (`anvil_app::drift`):
//! the import's collection history compared with its description, one send
//! checked on its own, and revising the import with chosen suggestions
//! (saved to a file through a save-dialog grant, or reimported). Everything
//! runs on a blocking thread (see `commands::blocking`).

use crate::commands::{R, blocking, blocking_unchecked, e, id};
use anvil_app::file_grants::FilePurpose;
use anvil_contract::{DriftReport, Revision};
use serde::Serialize;
use tauri::AppHandle;

/// History records a desktop report reads.
const LIMIT: usize = 500;

#[tauri::command]
pub async fn drift_report(handle: AppHandle, import_id: String) -> R<DriftReport> {
    blocking(&handle, move |st| st.app()?.drift_report(&id(&import_id)?, LIMIT).map_err(e)).await
}

/// One send checked against the description of the import it belongs to.
#[derive(Serialize)]
pub struct ExecutionDrift {
    pub import_id: String,
    pub file_name: String,
    pub title: Option<String>,
    pub report: DriftReport,
}

/// `None` when the send's request belongs to no OpenAPI import.
#[tauri::command]
pub async fn drift_check_execution(handle: AppHandle, execution_id: String) -> R<Option<ExecutionDrift>> {
    blocking(&handle, move |st| {
        let found = st.app()?.drift_check_execution(&id(&execution_id)?).map_err(e)?;
        Ok(found.map(|(rec, report)| ExecutionDrift {
            import_id: rec.source.import_id.to_string(),
            file_name: rec.file_name,
            title: rec.source.title,
            report,
        }))
    })
    .await
}

#[tauri::command]
pub async fn drift_revise(handle: AppHandle, import_id: String, suggestion_ids: Vec<String>) -> R<Revision> {
    blocking(&handle, move |st| st.app()?.drift_revise(&id(&import_id)?, &suggestion_ids, LIMIT).map_err(e)).await
}

/// What reimporting the revision would do to the collection.
#[derive(Serialize)]
pub struct DriftPlan {
    pub revision: Revision,
    pub added: Vec<String>,
    pub updated: usize,
    pub conflicts: usize,
    pub removed: usize,
    pub unchanged: usize,
}

#[tauri::command]
pub async fn drift_reimport_plan(handle: AppHandle, import_id: String, suggestion_ids: Vec<String>) -> R<DriftPlan> {
    blocking(&handle, move |st| {
        let (revision, plan) = st.app()?.drift_reimport_plan(&id(&import_id)?, &suggestion_ids, LIMIT).map_err(e)?;
        Ok(DriftPlan {
            revision,
            added: plan.added.iter().map(|r| r.name.clone()).collect(),
            updated: plan.updated.len() + plan.scope_updated.len(),
            conflicts: plan.conflicts.len() + plan.scope_conflicts.len(),
            removed: plan.removed.len(),
            unchanged: plan.unchanged.len(),
        })
    })
    .await
}

/// Reimport the revision previewed with `digest`; returns only a count
/// (see `spec_reimport_apply`).
#[tauri::command]
pub async fn drift_reimport_apply(handle: AppHandle, import_id: String, suggestion_ids: Vec<String>, digest: String) -> R<usize> {
    blocking_unchecked(&handle, move |st| {
        st.app()?.drift_reimport_apply(&id(&import_id)?, &suggestion_ids, LIMIT, &digest).map(|(_, n)| n).map_err(e)
    })
    .await
}

/// Write the revised description (`spec`) or its JSON Patch (`patch`) to the
/// destination chosen in the native save dialog (purpose
/// `spec_revision_export`).
#[tauri::command]
pub async fn drift_export(handle: AppHandle, import_id: String, suggestion_ids: Vec<String>, format: String, grant: String) -> R<usize> {
    blocking(&handle, move |st| {
        let rev = st.app()?.drift_revise_exact(&id(&import_id)?, &suggestion_ids, LIMIT).map_err(e)?;
        let text = match format.as_str() {
            "spec" => rev.text,
            "patch" => serde_json::to_string_pretty(&rev.json_patch).map_err(|x| x.to_string())? + "\n",
            other => return Err(format!("unknown export format {other}")),
        };
        st.file_grants.write(&grant, FilePurpose::SpecRevisionExport, text.as_bytes()).map_err(|x| x.to_string())
    })
    .await
}
