//! Spec and collection import commands. Sources are read from a path the
//! user picked in the native dialog, or from pasted text (cURL); nothing
//! imported is sent or run.

use crate::commands::{R, e, id};
use crate::state::DesktopState;
use anvil_app::specs::{SpecImported, SpecPreview, SpecSourceRecord, SpecTarget};
use anvil_import::{ImportOptions, ReimportApproval, ReimportPlan};
use serde::Deserialize;
use tauri::State;

const MAX_SOURCE: u64 = 32 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SpecInput {
    Path { path: String },
    Text { text: String, name: String },
}

impl SpecInput {
    fn load(&self) -> R<(Vec<u8>, String)> {
        match self {
            SpecInput::Path { path } => {
                let meta = std::fs::metadata(path).map_err(|x| x.to_string())?;
                if meta.len() > MAX_SOURCE {
                    return Err("the source is larger than 32 MiB".into());
                }
                let name =
                    std::path::Path::new(path).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "source".into());
                Ok((std::fs::read(path).map_err(|x| x.to_string())?, name))
            }
            SpecInput::Text { text, name } => {
                if text.len() as u64 > MAX_SOURCE {
                    return Err("the pasted source is larger than 32 MiB".into());
                }
                Ok((text.as_bytes().to_vec(), name.clone()))
            }
        }
    }
}

#[tauri::command]
pub fn spec_preview(st: State<'_, DesktopState>, input: SpecInput, options: ImportOptions) -> R<SpecPreview> {
    let (bytes, _) = input.load()?;
    st.app()?.spec_preview(&bytes, &options).map_err(e)
}

#[tauri::command]
pub fn spec_import(st: State<'_, DesktopState>, input: SpecInput, options: ImportOptions, target: SpecTarget) -> R<SpecImported> {
    let (bytes, name) = input.load()?;
    st.app()?.spec_import(&bytes, &name, &options, target).map_err(e)
}

#[tauri::command]
pub fn spec_sources(st: State<'_, DesktopState>, workspace_id: String) -> R<Vec<SpecSourceRecord>> {
    st.app()?.spec_sources(&id(&workspace_id)?).map_err(e)
}

#[tauri::command]
pub fn spec_reimport_plan(st: State<'_, DesktopState>, import_id: String, input: SpecInput) -> R<ReimportPlan> {
    let (bytes, _) = input.load()?;
    st.app()?.spec_reimport_plan(&id(&import_id)?, &bytes).map_err(e)
}

#[tauri::command]
pub fn spec_reimport_apply(st: State<'_, DesktopState>, import_id: String, input: SpecInput, approval: ReimportApproval) -> R<usize> {
    let (bytes, _) = input.load()?;
    st.app()?.spec_reimport_apply(&id(&import_id)?, &bytes, &approval).map_err(e)
}
