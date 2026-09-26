//! Spec and collection import commands. Sources are read from a file the
//! user picked in the native dialog (by its grant, never by a path), or from
//! pasted text (cURL); nothing imported is sent or run.

use crate::commands::{R, e, id};
use crate::state::DesktopState;
use anvil_app::file_grants::{FileGrants, FilePurpose};
use anvil_app::specs::{SpecImported, SpecPreview, SpecSourceRecord, SpecTarget};
use anvil_import::{ImportOptions, ReimportApproval, ReimportPlan};
use serde::Deserialize;
use tauri::State;

const MAX_SOURCE: u64 = 32 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SpecInput {
    /// A file chosen in the native open dialog (purpose `spec_source`).
    File {
        grant: String,
    },
    Text {
        text: String,
        name: String,
    },
}

impl SpecInput {
    fn load(&self, grants: &FileGrants) -> R<(Vec<u8>, String)> {
        match self {
            SpecInput::File { grant } => {
                let file = grants.read(grant, FilePurpose::SpecSource).map_err(|x| x.to_string())?;
                Ok((file.bytes, file.file_name))
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
    let app = st.app()?;
    let (bytes, _) = input.load(&st.file_grants)?;
    app.spec_preview(&bytes, &options).map_err(e)
}

#[tauri::command]
pub fn spec_import(st: State<'_, DesktopState>, input: SpecInput, options: ImportOptions, target: SpecTarget) -> R<SpecImported> {
    let app = st.app()?;
    let (bytes, name) = input.load(&st.file_grants)?;
    app.spec_import(&bytes, &name, &options, target).map_err(e)
}

#[tauri::command]
pub fn spec_sources(st: State<'_, DesktopState>, workspace_id: String) -> R<Vec<SpecSourceRecord>> {
    st.app()?.spec_sources(&id(&workspace_id)?).map_err(e)
}

#[tauri::command]
pub fn spec_reimport_plan(st: State<'_, DesktopState>, import_id: String, input: SpecInput) -> R<ReimportPlan> {
    let app = st.app()?;
    let (bytes, _) = input.load(&st.file_grants)?;
    app.spec_reimport_plan(&id(&import_id)?, &bytes).map_err(e)
}

#[tauri::command]
pub fn spec_reimport_apply(st: State<'_, DesktopState>, import_id: String, input: SpecInput, approval: ReimportApproval) -> R<usize> {
    let app = st.app()?;
    let (bytes, _) = input.load(&st.file_grants)?;
    app.spec_reimport_apply(&id(&import_id)?, &bytes, &approval).map_err(e)
}
