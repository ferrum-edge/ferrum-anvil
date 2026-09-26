//! Native file dialogs. The backend shows the dialog and keeps the chosen
//! path; the webview receives only an opaque grant bound to one purpose (see
//! `anvil_app::file_grants`), which the file commands accept in place of a
//! path. No command takes a file path from the webview. A JWT-SVID token
//! file or a linked local file is bound in the vault instead
//! (`anvil_app::token_files`, `anvil_app::linked_files`), and only a bound
//! path is read at send time.

use crate::commands::{R, e};
use crate::state::DesktopState;
use anvil_app::file_grants::{Access, FileGrant, FilePurpose, GrantError};
use serde::Deserialize;
use tauri::{State, Window};
use tauri_plugin_dialog::{DialogExt, FilePath};

#[derive(Deserialize)]
pub struct DialogFilter {
    pub name: String,
    pub extensions: Vec<String>,
}

/// Most files one open dialog may grant at once.
const MAX_PICKED: usize = 16;

/// Presentation only: none of this widens what a grant allows. The dialog
/// title comes from the purpose, not from the webview.
#[derive(Deserialize, Default)]
#[serde(default)]
pub struct DialogOptions {
    /// Suggested name for a save dialog; any folder part is ignored.
    pub file_name: Option<String>,
    pub filters: Vec<DialogFilter>,
    /// Let the open dialog select several files (read purposes only).
    pub multiple: bool,
}

/// Show the native open dialog (read and bind purposes) or save dialog
/// (write purposes) and return a grant for each chosen file; empty if the
/// user cancelled. Refused while locked; a lock while the dialog is open
/// grants nothing.
#[tauri::command]
pub async fn file_choose(
    window: Window,
    st: State<'_, DesktopState>,
    purpose: FilePurpose,
    options: Option<DialogOptions>,
) -> R<Vec<FileGrant>> {
    // Read before the lock check, so a lock after it always moves the
    // generation past this value.
    let generation = st.file_grants.generation();
    st.app()?;
    let options = options.unwrap_or_default();
    match purpose.access() {
        Access::Write if options.multiple => return Err("a save dialog chooses one file".into()),
        Access::Bind if options.multiple => return Err("choose one token file".into()),
        _ => {}
    }
    let mut dialog = window.dialog().file();
    #[cfg(any(windows, target_os = "macos"))]
    {
        dialog = dialog.set_parent(&window);
    }
    dialog = dialog.set_title(title(purpose));
    for f in &options.filters {
        let extensions: Vec<&str> = f.extensions.iter().map(String::as_str).collect();
        dialog = dialog.add_filter(f.name.clone(), &extensions);
    }
    let (tx, rx) = tokio::sync::oneshot::channel::<Option<Vec<FilePath>>>();
    match purpose.access() {
        Access::Read if options.multiple => dialog.pick_files(move |p| {
            let _ = tx.send(p);
        }),
        Access::Read | Access::Bind => dialog.pick_file(move |p| {
            let _ = tx.send(p.map(|f| vec![f]));
        }),
        Access::Write => {
            if let Some(name) = options.file_name.as_deref().and_then(|n| std::path::Path::new(n).file_name()) {
                dialog = dialog.set_file_name(name.to_string_lossy());
            }
            dialog.save_file(move |p| {
                let _ = tx.send(p.map(|f| vec![f]));
            })
        }
    }
    let picked = rx.await.map_err(|_| "the file dialog closed unexpectedly".to_string())?.unwrap_or_default();
    if picked.len() > MAX_PICKED {
        return Err(format!("choose at most {MAX_PICKED} files at once"));
    }
    // The app may have locked while the dialog was open: grant nothing then.
    let app = st.app()?;
    let mut grants = Vec::with_capacity(picked.len());
    for file in picked {
        let path = file.into_path().map_err(|x| x.to_string())?;
        let grant = match purpose.access() {
            Access::Read => st.file_grants.grant_read_at(purpose, &path, generation),
            Access::Write => st.file_grants.grant_write_at(purpose, &path, generation),
            Access::Bind => {
                if st.file_grants.generation() != generation {
                    return Err(GrantError::Revoked.to_string());
                }
                let (id, bound) = match purpose {
                    FilePurpose::LinkedFile => app.bind_linked_file(&path).map(|b| (b.id, b.path)),
                    _ => app.bind_token_file(&path).map(|b| (b.id, b.path)),
                }
                .map_err(e)?;
                // A lock during the bind returns nothing to the webview. The
                // binding is kept: it names only a file the user chose in the
                // native dialog, lets nothing read it without a request that
                // names it, and may predate this choice, so removing it here
                // could drop a binding the user made earlier.
                if st.file_grants.generation() != generation {
                    return Err(GrantError::Revoked.to_string());
                }
                let file_name = std::path::Path::new(&bound).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
                Ok(FileGrant { token: id.to_string(), file_name, path: Some(bound) })
            }
        };
        grants.push(grant.map_err(|x| x.to_string())?);
    }
    Ok(grants)
}

fn title(purpose: FilePurpose) -> &'static str {
    match purpose {
        FilePurpose::BundleImport => "Import an Anvil bundle or backup",
        FilePurpose::Attachment => "Attach a file",
        FilePurpose::PemFile => "Choose a PEM certificate or key",
        FilePurpose::Pkcs12File => "Choose a PKCS#12 keystore for the vault",
        FilePurpose::SpecSource => "Import an API spec or collection",
        FilePurpose::Dataset => "Choose a CSV or JSON dataset",
        FilePurpose::BundleExport => "Export an Anvil bundle",
        FilePurpose::LoadReportExport => "Export the load report",
        FilePurpose::RunReportExport => "Export the run report",
        FilePurpose::JwtSvidFile => "Choose the JWT-SVID token file",
        FilePurpose::LinkedFile => "Choose the linked file on this device",
    }
}
