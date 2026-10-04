//! Native file dialogs. The backend shows the dialog and keeps the chosen
//! path; the webview receives only an opaque grant bound to one purpose (see
//! `anvil_app::file_grants`), which the file commands accept in place of a
//! path. No command takes a file path from the webview. A JWT-SVID token
//! file or a linked local file is bound in the vault instead
//! (`anvil_app::token_files`, `anvil_app::linked_files`), and only a bound
//! path is read at send time. The user lists the bound token files and
//! removes one that should no longer be read, and sees beside each linked
//! file whether it is bound. A linked file found at a new location is
//! repointed the same way: the dialog is shown for the request or dataset
//! and the reference, and only the file picked there is written into it.

use crate::commands::{R, blocking, e, id};
use crate::state::DesktopState;
use anvil_app::App;
use anvil_app::file_grants::{Access, FileGrant, FilePurpose, GrantError};
use anvil_app::linked_files::{LinkedFileEpoch, LinkedFileReferrer, LinkedFileStatus};
use anvil_app::token_files::TokenFileBinding;
use serde::Deserialize;
use std::path::Path;
use std::sync::{Arc, Weak};
use tauri::{AppHandle, State, Window};
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
/// grants nothing. A linked file is bound for the saved request or dataset
/// `referrer` names, and only if that referrer names the chosen file. To
/// relocate one (purpose `linked_file_relocate`), `old_path` names the
/// reference to repoint: it must be a linked file `referrer` names, and is
/// never looked at on disk. The new path is the one picked in the dialog.
#[tauri::command]
pub async fn file_choose(
    window: Window,
    st: State<'_, DesktopState>,
    purpose: FilePurpose,
    options: Option<DialogOptions>,
    referrer: Option<LinkedFileReferrer>,
    old_path: Option<String>,
) -> R<Vec<FileGrant>> {
    st.app()?;
    general_purpose(purpose)?;
    choose_native(window, st, purpose, options, referrer, old_path).await
}

/// The native title and grant purpose are fixed by this command. The
/// renderer cannot select a role or override the security-related title.
#[tauri::command]
pub async fn certificate_file_choose(window: Window, st: State<'_, DesktopState>) -> R<Vec<FileGrant>> {
    choose_native(window, st, FilePurpose::PemCertificate, None, None, None).await
}

/// Choose a private key for one-shot vault ingestion, with native wording
/// that makes the disposition visible at the existing file selection.
#[tauri::command]
pub async fn private_key_file_choose(window: Window, st: State<'_, DesktopState>) -> R<Vec<FileGrant>> {
    choose_native(window, st, FilePurpose::PemPrivateKey, None, None, None).await
}

fn general_purpose(purpose: FilePurpose) -> R<()> {
    if matches!(purpose, FilePurpose::PemCertificate | FilePurpose::PemPrivateKey) {
        return Err("PEM files require their dedicated native chooser".into());
    }
    Ok(())
}

async fn choose_native(
    window: Window,
    st: State<'_, DesktopState>,
    purpose: FilePurpose,
    options: Option<DialogOptions>,
    referrer: Option<LinkedFileReferrer>,
    old_path: Option<String>,
) -> R<Vec<FileGrant>> {
    // Read before the lock check, so a lock after it always moves the
    // generation past this value.
    let generation = st.file_grants.generation();
    // The profile the dialog is shown for. Held weakly: an open dialog does
    // not keep a profile that has since been closed in memory.
    let shown_app = st.app()?;
    let linked_epoch = shown_app.linked_file_epoch();
    let shown_for = Arc::downgrade(&shown_app);
    drop(shown_app);
    let options = options.unwrap_or_default();
    match purpose.access() {
        Access::Write if options.multiple => return Err("a save dialog chooses one file".into()),
        Access::Bind if options.multiple => return Err("choose one file".into()),
        _ => {}
    }
    let bind = bind_target(purpose, referrer, old_path)?;
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
    // Grant and bind only for the profile the dialog was shown for, in
    // addition to checking the revocation generation when recording it.
    if !Weak::ptr_eq(&shown_for, &Arc::downgrade(&app)) {
        return Err(GrantError::Revoked.to_string());
    }
    let mut grants = Vec::with_capacity(picked.len());
    for file in picked {
        let path = file.into_path().map_err(|x| x.to_string())?;
        let grant = match (&bind, purpose.access()) {
            (Some(bind), _) => bind_picked(&st, &app, generation, linked_epoch, bind, &path)?,
            (None, _) if purpose == FilePurpose::PemPrivateKey => {
                st.file_grants.grant_private_key_at(&app, &path, generation).map_err(|x| x.to_string())?
            }
            (None, Access::Write) => st.file_grants.grant_write_at(purpose, &path, generation).map_err(|x| x.to_string())?,
            (None, _) => st.file_grants.grant_read_at(purpose, &path, generation).map_err(|x| x.to_string())?,
        };
        grants.push(grant);
    }
    Ok(grants)
}

/// What a bind-purpose dialog binds the picked file for.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Bind {
    /// A JWT-SVID token file.
    TokenFile,
    /// A linked file the saved request or dataset names, at that path.
    Linked(LinkedFileReferrer),
    /// A new location for the linked file (the path) that the saved request
    /// or dataset names.
    Relocate(LinkedFileReferrer, String),
}

/// What the dialog for `purpose` binds its file for (none for a read or
/// write purpose), refusing a request or dataset, or a reference to
/// relocate, that does not belong to the purpose. Checked before anything is
/// shown.
fn bind_target(purpose: FilePurpose, referrer: Option<LinkedFileReferrer>, old_path: Option<String>) -> Result<Option<Bind>, String> {
    match (purpose, referrer, old_path) {
        (FilePurpose::LinkedFile | FilePurpose::LinkedFileRelocate, None, _) => {
            Err("choose the request or dataset the linked file is for".into())
        }
        (FilePurpose::LinkedFile, Some(referrer), None) => Ok(Some(Bind::Linked(referrer))),
        (FilePurpose::LinkedFile, Some(_), Some(_)) => Err("a linked file is relocated only with purpose linked_file_relocate".into()),
        (FilePurpose::LinkedFileRelocate, Some(referrer), Some(old)) => Ok(Some(Bind::Relocate(referrer, old))),
        (FilePurpose::LinkedFileRelocate, Some(_), None) => Err("choose the linked file to relocate".into()),
        (_, Some(_), _) => Err("only a linked file is chosen for a request or dataset".into()),
        (_, None, Some(_)) => Err("only a linked file is relocated".into()),
        (FilePurpose::JwtSvidFile, None, None) => Ok(Some(Bind::TokenFile)),
        (_, None, None) => Ok(None),
    }
}

/// Bind the file picked in a dialog shown in `generation` for `app`, as
/// `bind` says. Nothing is bound or written once a lock or another profile
/// has intervened since the dialog was shown.
fn bind_picked(
    st: &DesktopState,
    app: &Arc<App>,
    generation: u64,
    linked_epoch: LinkedFileEpoch,
    bind: &Bind,
    path: &Path,
) -> Result<FileGrant, String> {
    bind_picked_at_checkpoints(st, app, (generation, linked_epoch), bind, path, |_| {})
}

fn bind_picked_at_checkpoints(
    st: &DesktopState,
    app: &Arc<App>,
    epochs: (u64, LinkedFileEpoch),
    bind: &Bind,
    path: &Path,
    mut checkpoint: impl FnMut(&str),
) -> Result<FileGrant, String> {
    let (generation, linked_epoch) = epochs;
    let unchanged = || st.file_grants.generation() == generation && st.is_current(app);
    if !unchanged() {
        return Err(GrantError::Revoked.to_string());
    }
    checkpoint("prechecked");
    let choice = match bind {
        Bind::TokenFile => Ok(None),
        Bind::Linked(referrer) => app.bind_linked_file_at(*referrer, path, linked_epoch).map(Some),
        Bind::Relocate(referrer, old) => {
            app.relocate_linked_file_at(*referrer, old, path, linked_epoch).map(Some)
        }
    }
    .map_err(|err| if unchanged() { e(err) } else { GrantError::Revoked.to_string() })?;
    let (id, bound) = if let Some(choice) = &choice {
        (choice.binding.id, choice.binding.path.clone())
    } else {
        let binding = app.bind_token_file(path).map_err(e)?;
        (binding.id, binding.path)
    };
    checkpoint("bound");
    if !unchanged() {
        if let Some(choice) = &choice {
            app.revoke_linked_file_choice(choice);
        }
        return Err(GrantError::Revoked.to_string());
    }
    let file_name = Path::new(&bound).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    Ok(FileGrant { token: id.to_string(), file_name, path: Some(bound) })
}

/// The JWT-SVID token files bound on this device (`file_choose` with purpose
/// `jwt_svid_file`), oldest first. Refused while locked.
#[tauri::command]
pub fn token_files_list(st: State<'_, DesktopState>) -> R<Vec<TokenFileBinding>> {
    st.app()?.token_file_bindings().map_err(e)
}

/// Remove a token-file binding: an auth setting that names the file is
/// refused from the next send on, until the user chooses the file again.
/// Refused while locked.
#[tauri::command]
pub fn token_file_remove(st: State<'_, DesktopState>, binding_id: String) -> R<()> {
    let binding = id(&binding_id)?;
    st.app()?.remove_token_file_binding(&binding).map_err(e)
}

/// The binding state of each linked file the saved request or dataset
/// `referrer` names (see `App::linked_file_status`). Read-only: it binds
/// nothing, and looks only at the metadata of files already bound for that
/// referrer. Refused while locked. On a blocking thread (see [`blocking`]):
/// it waits on the store and looks up paths on this device, which a slow
/// network mount or a sleeping disk can hold for a while.
#[tauri::command]
pub async fn linked_file_status(handle: AppHandle, referrer: LinkedFileReferrer) -> R<Vec<LinkedFileStatus>> {
    blocking(&handle, move |st| st.app()?.linked_file_status(referrer).map_err(e)).await
}

fn title(purpose: FilePurpose) -> &'static str {
    match purpose {
        FilePurpose::BundleImport => "Import an Anvil bundle or backup",
        FilePurpose::Attachment => "Attach a file",
        FilePurpose::PemCertificate => "Choose PEM certificates to display in Anvil",
        FilePurpose::PemPrivateKey => "Choose a PEM private key for the vault",
        FilePurpose::Pkcs12File => "Choose a PKCS#12 keystore for the vault",
        FilePurpose::SpecSource => "Import an API spec or collection",
        FilePurpose::Dataset => "Choose a CSV or JSON dataset",
        FilePurpose::Ruleset => "Add an API standards ruleset",
        FilePurpose::BundleExport => "Export an Anvil bundle",
        FilePurpose::LoadReportExport => "Export the load report",
        FilePurpose::RunReportExport => "Export the run report",
        FilePurpose::LintReportExport => "Export the standards report",
        FilePurpose::SpecRevisionExport => "Save the revised description",
        FilePurpose::JwtSvidFile => "Choose the JWT-SVID token file",
        FilePurpose::LinkedFile => "Choose the linked file on this device",
        FilePurpose::LinkedFileRelocate => "Choose the linked file's new location on this device",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::tests::{PASSPHRASE, TempRoot, create};
    use anvil_app::profiles::{ProfileManager, Unlock};
    use anvil_domain::request::{AttachmentRef, Body, RequestSpec};

    #[test]
    fn pem_roles_are_fixed_by_dedicated_native_choosers() {
        for purpose in [FilePurpose::PemCertificate, FilePurpose::PemPrivateKey] {
            assert!(general_purpose(purpose).is_err());
        }
        assert!(general_purpose(FilePurpose::Pkcs12File).is_ok());
        assert!(general_purpose(FilePurpose::Attachment).is_ok());
        assert!(title(FilePurpose::PemCertificate).contains("display"));
        assert!(title(FilePurpose::PemPrivateKey).contains("vault"));
    }

    #[test]
    fn a_relocation_names_its_request_or_dataset_and_its_reference() {
        let referrer = LinkedFileReferrer::Request { id: anvil_domain::Id::new() };
        let old = || Some("/elsewhere/upload.bin".to_string());
        assert_eq!(bind_target(FilePurpose::LinkedFileRelocate, Some(referrer), old()), Ok(Some(Bind::Relocate(referrer, old().unwrap()))));
        assert_eq!(bind_target(FilePurpose::LinkedFile, Some(referrer), None), Ok(Some(Bind::Linked(referrer))));
        assert_eq!(bind_target(FilePurpose::JwtSvidFile, None, None), Ok(Some(Bind::TokenFile)));
        assert_eq!(bind_target(FilePurpose::Attachment, None, None), Ok(None));
        let refused = |purpose, referrer, old_path| bind_target(purpose, referrer, old_path).unwrap_err();
        assert!(refused(FilePurpose::LinkedFileRelocate, None, old()).contains("choose the request or dataset"));
        assert!(refused(FilePurpose::LinkedFileRelocate, Some(referrer), None).contains("choose the linked file to relocate"));
        assert!(refused(FilePurpose::LinkedFile, Some(referrer), old()).contains("only with purpose linked_file_relocate"));
        assert!(refused(FilePurpose::Attachment, None, old()).contains("only a linked file is relocated"));
        assert!(refused(FilePurpose::JwtSvidFile, None, old()).contains("only a linked file is relocated"));
        assert!(refused(FilePurpose::Attachment, Some(referrer), old()).contains("only a linked file is chosen"));
    }

    #[tokio::test]
    async fn a_lock_while_the_relocation_dialog_is_open_relocates_nothing() {
        let root = TempRoot::new();
        let st = DesktopState::new(root.0.clone());
        let (app, dir) = create(&st, "A");
        st.set_app_since(app, st.epoch()).unwrap();
        let app = st.app().unwrap();
        let files = root.0.join("files");
        std::fs::create_dir_all(&files).unwrap();
        let picked = files.join("upload.bin");
        std::fs::write(&picked, "payload").unwrap();
        let picked_path = std::fs::canonicalize(&picked).unwrap().to_str().unwrap().to_string();
        // The path the request names, from another machine: nothing is there.
        let old = files.join("gone").join("upload.bin").display().to_string();
        let ws = app.create_workspace("W").unwrap();
        let mut spec = RequestSpec::http("POST", "http://127.0.0.1:9/x");
        spec.body = Body::Binary { attachment: AttachmentRef::LinkedFile { path: old.clone() }, content_type: None };
        let r = app.create_request(&ws.meta.id, None, "upload", spec.clone()).unwrap();
        let referrer = LinkedFileReferrer::Request { id: r.meta.id };
        let relocate = Bind::Relocate(referrer, old.clone());

        // The dialog is shown, then the app locks and is unlocked again
        // before the user picks the file.
        let generation = st.file_grants.generation();
        let linked_epoch = app.linked_file_epoch();
        st.lock();
        let seen = st.epoch();
        let (_, key) = ProfileManager::unlock(&dir, Unlock::Passphrase(PASSPHRASE)).unwrap();
        st.unlock_since(&app, key, seen).unwrap();
        assert_eq!(bind_picked(&st, &app, generation, linked_epoch, &relocate, &picked), Err(GrantError::Revoked.to_string()));
        assert_eq!(app.request(&r.meta.id).unwrap().spec, spec, "the request is not rewritten");
        assert!(app.linked_file_bindings().unwrap().is_empty(), "nothing is bound");

        // Still locked when the file is picked: nothing is written either.
        let generation = st.file_grants.generation();
        let linked_epoch = app.linked_file_epoch();
        st.lock();
        assert_eq!(bind_picked(&st, &app, generation, linked_epoch, &relocate, &picked), Err(GrantError::Revoked.to_string()));
        let seen = st.epoch();
        let (_, key) = ProfileManager::unlock(&dir, Unlock::Passphrase(PASSPHRASE)).unwrap();
        st.unlock_since(&app, key, seen).unwrap();
        assert_eq!(app.request(&r.meta.id).unwrap().spec, spec);

        // A dialog shown after the unlock relocates the reference.
        let generation = st.file_grants.generation();
        let linked_epoch = app.linked_file_epoch();
        let grant = bind_picked(&st, &app, generation, linked_epoch, &relocate, &picked).unwrap();
        assert_eq!(grant.path.as_deref(), Some(picked_path.as_str()));
        assert_eq!(grant.file_name, "upload.bin");
        let Body::Binary { attachment, .. } = app.request(&r.meta.id).unwrap().spec.body else { panic!("binary body") };
        assert_eq!(attachment, AttachmentRef::LinkedFile { path: picked_path.clone() });
        let bound: Vec<_> = app.linked_file_bindings().unwrap().into_iter().map(|b| (b.referrer, b.path)).collect();
        assert_eq!(bound, vec![(referrer, picked_path)]);
    }

    #[tokio::test]
    async fn linked_dialog_authority_cannot_cross_the_bind_precheck_or_postcheck() {
        for relocate in [false, true] {
            for barrier in ["prechecked", "bound"] {
                let root = TempRoot::new();
                let st = DesktopState::new(root.0.clone());
                let (app, dir) = create(&st, "A");
                st.set_app_since(app, st.epoch()).unwrap();
                let app = st.app().unwrap();
                let picked = root.0.join("upload.bin");
                std::fs::write(&picked, "chosen payload").unwrap();
                let canonical = std::fs::canonicalize(&picked).unwrap().to_str().unwrap().to_string();
                let old = if relocate { root.0.join("gone.bin").display().to_string() } else { canonical.clone() };
                let workspace = app.create_workspace("W").unwrap();
                let mut spec = RequestSpec::http("POST", "http://127.0.0.1:9/x");
                spec.body = Body::Binary {
                    attachment: AttachmentRef::LinkedFile { path: old.clone() },
                    content_type: None,
                };
                let request = app.create_request(&workspace.meta.id, None, "upload", spec.clone()).unwrap();
                let referrer = LinkedFileReferrer::Request { id: request.meta.id };
                let bind = if relocate { Bind::Relocate(referrer, old) } else { Bind::Linked(referrer) };
                let epochs = (st.file_grants.generation(), app.linked_file_epoch());
                // The real desktop path pauses after its optimistic check,
                // then lock/unlock completes before the issuer can capture
                // any new generation. It must use the dialog's old epoch.
                let result = bind_picked_at_checkpoints(&st, &app, epochs, &bind, &picked, |point| {
                    if point == barrier {
                        st.lock();
                        let seen = st.epoch();
                        let (_, key) = ProfileManager::unlock(&dir, Unlock::Passphrase(PASSPHRASE)).unwrap();
                        st.unlock_since(&app, key, seen).unwrap();
                    }
                });
                assert_eq!(result, Err(GrantError::Revoked.to_string()));
                let status = app.linked_file_status(referrer).unwrap();
                assert!(status.iter().all(|s| s.state != anvil_app::linked_files::LinkedFileState::Bound));
                let saved = app.request(&request.meta.id).unwrap();
                let Body::Binary { attachment, .. } = saved.spec.body else { panic!("binary body") };
                let load = app
                    .build_context(Some(request.meta.id), &workspace.meta.id, None, &Default::default())
                    .and_then(|context| context.attachments.load(&attachment).map_err(anvil_app::AppError::Invalid));
                assert!(load.is_err());
                if barrier == "prechecked" {
                    assert!(app.linked_file_bindings().unwrap().is_empty());
                    assert_eq!(app.request(&request.meta.id).unwrap().spec, spec);
                }
                // A new dialog still establishes usable authority.
                let epochs = (st.file_grants.generation(), app.linked_file_epoch());
                let fresh = Bind::Linked(referrer);
                let target = if barrier == "prechecked" && relocate { &bind } else { &fresh };
                let grant = bind_picked(&st, &app, epochs.0, epochs.1, target, &picked).unwrap();
                assert_eq!(grant.path, Some(canonical));
                assert_eq!(app.linked_file_status(referrer).unwrap()[0].state, anvil_app::linked_files::LinkedFileState::Bound);
            }
        }
    }
}
