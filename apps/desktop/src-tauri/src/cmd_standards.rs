//! API standards: the rulesets kept in the profile, and linting of imported
//! specs or spec files against them (`anvil_app::standards`). Ruleset and
//! spec files are read through grants from the native open dialog; reports
//! are written through a save-dialog grant. Linting runs on a blocking
//! thread (see `commands::blocking`).

use crate::cmd_specs::SpecInput;
use crate::commands::{R, blocking, e, id};
use crate::state::DesktopState;
use anvil_app::file_grants::FilePurpose;
use anvil_app::standards::StandardsView;
use anvil_contract::LintReport;
use anvil_domain::settings::{ApiStandards, StoredRuleset};
use serde::Deserialize;
use tauri::AppHandle;

/// What to lint.
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LintTarget {
    /// The stored original of an import.
    Import { import_id: String },
    /// A spec file chosen in the native dialog (purpose `spec_source`).
    Spec { input: SpecInput },
}

fn lint(st: &DesktopState, target: &LintTarget) -> R<LintReport> {
    let app = st.app()?;
    match target {
        LintTarget::Import { import_id } => app.lint_imported_spec(&id(import_id)?).map_err(e),
        LintTarget::Spec { input } => {
            let (bytes, _) = input.load(&st.file_grants)?;
            app.lint_spec(&bytes).map_err(e)
        }
    }
}

#[tauri::command]
pub async fn standards_view(handle: AppHandle) -> R<StandardsView> {
    blocking(&handle, |st| st.app()?.standards_view().map_err(e)).await
}

/// Add the ruleset file chosen in the native dialog (purpose `ruleset`).
#[tauri::command]
pub async fn standards_add(handle: AppHandle, grant: String) -> R<StoredRuleset> {
    blocking(&handle, move |st| {
        let file = st.file_grants.read(&grant, FilePurpose::Ruleset).map_err(|x| x.to_string())?;
        st.app()?.add_api_ruleset(&file.file_name, &file.bytes).map_err(e)
    })
    .await
}

/// Replace a stored ruleset with a newer file (purpose `ruleset`).
#[tauri::command]
pub async fn standards_replace(handle: AppHandle, ruleset_id: String, grant: String) -> R<StoredRuleset> {
    blocking(&handle, move |st| {
        let file = st.file_grants.read(&grant, FilePurpose::Ruleset).map_err(|x| x.to_string())?;
        st.app()?.replace_api_ruleset(&id(&ruleset_id)?, &file.file_name, &file.bytes).map_err(e)
    })
    .await
}

#[tauri::command]
pub async fn standards_remove(handle: AppHandle, ruleset_id: String) -> R<ApiStandards> {
    blocking(&handle, move |st| st.app()?.remove_api_ruleset(&id(&ruleset_id)?).map_err(e)).await
}

#[tauri::command]
pub async fn standards_set_enabled(handle: AppHandle, ruleset_id: String, enabled: bool) -> R<ApiStandards> {
    blocking(&handle, move |st| st.app()?.set_api_ruleset_enabled(&id(&ruleset_id)?, enabled).map_err(e)).await
}

#[tauri::command]
pub async fn standards_set_recommended(handle: AppHandle, include: bool) -> R<ApiStandards> {
    blocking(&handle, move |st| st.app()?.set_api_standards_recommended(include).map_err(e)).await
}

#[tauri::command]
pub async fn standards_lint(handle: AppHandle, target: LintTarget) -> R<LintReport> {
    blocking(&handle, move |st| lint(st, &target)).await
}

/// Lint `target` again and write the report to the destination chosen in the
/// native save dialog (`grant`, purpose `lint_report_export`): `json` or
/// `sarif`. `artifact` names the spec in a SARIF report.
#[tauri::command]
pub async fn standards_report_export(handle: AppHandle, target: LintTarget, format: String, artifact: String, grant: String) -> R<usize> {
    blocking(&handle, move |st| {
        let report = lint(st, &target)?;
        let value = match format.as_str() {
            "json" => serde_json::to_value(&report).map_err(|x| x.to_string())?,
            "sarif" => anvil_contract::sarif::to_sarif(&report, &artifact),
            other => return Err(format!("unknown export format {other}")),
        };
        let mut text = serde_json::to_string_pretty(&value).map_err(|x| x.to_string())?;
        text.push('\n');
        st.file_grants.write(&grant, FilePurpose::LintReportExport, text.as_bytes()).map_err(|x| x.to_string())
    })
    .await
}
