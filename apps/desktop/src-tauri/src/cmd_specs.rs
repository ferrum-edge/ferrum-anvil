//! Spec and collection import commands. Sources are read from a file the
//! user picked in the native dialog (by its grant, never by a path), or from
//! pasted text (cURL); nothing imported is sent or run. A source is read,
//! parsed and written on a blocking thread (see `commands::blocking`).

use crate::commands::{R, blocking, blocking_unchecked, e, id};
use crate::state::DesktopState;
use anvil_app::file_grants::{FileGrants, FilePurpose};
use anvil_app::specs::{SpecBinding, SpecImported, SpecPreview, SpecSourceRecord, SpecTarget};
use anvil_import::{ImportOptions, ReimportApproval, ReimportPlan};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, State};

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
    pub(crate) fn load(&self, grants: &FileGrants) -> R<(Vec<u8>, String)> {
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

/// Stateless approval: native bytes/plan plus desktop process, unlocked epoch,
/// profile, source grant/name and destination. No preview cache or token pool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpecApproval {
    pub binding: SpecBinding,
    pub scope: String,
}

#[derive(Serialize)]
pub struct ReviewedPreview {
    #[serde(flatten)]
    pub preview: SpecPreview,
    pub approval: SpecApproval,
}

#[derive(Serialize)]
pub struct ReviewedReimport {
    pub plan: ReimportPlan,
    pub approval: SpecApproval,
}

fn approval_scope(
    st: &DesktopState,
    fence: &crate::state::PayloadFence,
    input: &SpecInput,
    destination: &impl Serialize,
    binding: &SpecBinding,
) -> R<String> {
    let source = match input {
        SpecInput::File { grant } => ("file", grant.as_str()),
        SpecInput::Text { name, .. } => ("text", name.as_str()),
    };
    binding.scoped_digest(&(st.review_session, st.epoch(), &fence.app.header.profile_id, source, destination)).map_err(e)
}

fn preview(st: &DesktopState, input: &SpecInput, options: &ImportOptions, target: &SpecTarget) -> R<ReviewedPreview> {
    let fence = st.admit_payload()?;
    let (bytes, _) = input.load(&st.file_grants)?;
    let preview = fence.app.spec_preview(&bytes, options).map_err(e)?;
    // Never return a binding stamped with an epoch newer than its admission.
    st.deliver_payload(&fence, || {
        let scope = approval_scope(st, &fence, input, &("import", target), &preview.binding)?;
        let approval = SpecApproval { binding: preview.binding.clone(), scope };
        Ok(ReviewedPreview { preview, approval })
    })?
}

fn import(st: &DesktopState, input: &SpecInput, options: &ImportOptions, target: SpecTarget, approval: &SpecApproval) -> R<SpecImported> {
    import_with(st, input, options, target, approval, || {})
}

fn import_with(
    st: &DesktopState,
    input: &SpecInput,
    options: &ImportOptions,
    target: SpecTarget,
    approval: &SpecApproval,
    before_commit: impl FnOnce(),
) -> R<SpecImported> {
    let fence = st.admit_payload()?;
    let (bytes, name) = input.load(&st.file_grants)?;
    let prepared = fence.app.prepare_spec_import_reviewed(bytes, name, options, target.clone(), &approval.binding).map_err(e)?;
    before_commit();
    // Parsing and I/O are already finished. Lock either wins this commit
    // boundary (no writes), or follows the completed transaction.
    st.deliver_payload(&fence, || {
        let scope = approval_scope(st, &fence, input, &("import", &target), &approval.binding)?;
        if scope != approval.scope {
            return Err("the review expired or its scope changed; preview it again".into());
        }
        fence.app.apply_prepared_spec_import(prepared).map_err(e)
    })?
}

fn reimport_plan(st: &DesktopState, import_id: &str, input: &SpecInput) -> R<ReviewedReimport> {
    let fence = st.admit_payload()?;
    let (bytes, _) = input.load(&st.file_grants)?;
    let review = fence.app.spec_reimport_review(&id(import_id)?, &bytes).map_err(e)?;
    st.deliver_payload(&fence, || {
        let scope = approval_scope(st, &fence, input, &("reimport", import_id), &review.binding)?;
        let approval = SpecApproval { binding: review.binding, scope };
        Ok(ReviewedReimport { plan: review.plan, approval })
    })?
}

fn reimport_apply(
    st: &DesktopState,
    import_id: &str,
    input: &SpecInput,
    decisions: &ReimportApproval,
    approval: &SpecApproval,
) -> R<usize> {
    reimport_apply_with(st, import_id, input, decisions, approval, || {})
}

fn reimport_apply_with(
    st: &DesktopState,
    import_id: &str,
    input: &SpecInput,
    decisions: &ReimportApproval,
    approval: &SpecApproval,
    before_commit: impl FnOnce(),
) -> R<usize> {
    let fence = st.admit_payload()?;
    let (bytes, name) = input.load(&st.file_grants)?;
    let prepared = fence.app.prepare_spec_reimport_reviewed(&id(import_id)?, bytes, name, &approval.binding).map_err(e)?;
    before_commit();
    st.deliver_payload(&fence, || {
        let scope = approval_scope(st, &fence, input, &("reimport", import_id), &approval.binding)?;
        if scope != approval.scope {
            return Err("the review expired or its scope changed; preview it again".into());
        }
        fence.app.apply_prepared_spec_reimport(prepared, decisions).map_err(e)
    })?
}

#[tauri::command]
pub async fn spec_preview(handle: AppHandle, input: SpecInput, options: ImportOptions, target: SpecTarget) -> R<ReviewedPreview> {
    blocking(&handle, move |st| preview(st, &input, &options, &target)).await
}

/// Committed imports still return their report, as before. The reviewed
/// source and destination are checked before any mutation, under the fence.
#[tauri::command]
pub async fn spec_import(
    handle: AppHandle,
    input: SpecInput,
    options: ImportOptions,
    target: SpecTarget,
    approval: SpecApproval,
) -> R<SpecImported> {
    blocking_unchecked(&handle, move |st| import(st, &input, &options, target, &approval)).await
}

#[tauri::command]
pub fn spec_sources(st: State<'_, DesktopState>, workspace_id: String) -> R<Vec<SpecSourceRecord>> {
    st.app()?.spec_sources(&id(&workspace_id)?).map_err(e)
}

#[tauri::command]
pub async fn spec_reimport_plan(handle: AppHandle, import_id: String, input: SpecInput) -> R<ReviewedReimport> {
    blocking(&handle, move |st| reimport_plan(st, &import_id, &input)).await
}

/// Decisions always name the bound plan; stable operation ids alone never
/// authorize content from a different source or a different stored baseline.
#[tauri::command]
pub async fn spec_reimport_apply(
    handle: AppHandle,
    import_id: String,
    input: SpecInput,
    decisions: ReimportApproval,
    approval: SpecApproval,
) -> R<usize> {
    blocking_unchecked(&handle, move |st| reimport_apply(st, &import_id, &input, &decisions, &approval)).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::tests::{PASSPHRASE, TempRoot, create};
    use anvil_app::profiles::{ProfileManager, Unlock};
    use anvil_domain::Id;

    const V1: &str = r#"{"openapi":"3.1.0","info":{"title":"Review","version":"1"},
        "paths":{"/safe":{"get":{"operationId":"stable",
        "responses":{"200":{"description":"ok"}}}}}}"#;

    fn selected(st: &DesktopState, root: &TempRoot, text: &str) -> (SpecInput, std::path::PathBuf) {
        let path = root.0.join("review.json");
        std::fs::write(&path, text).unwrap();
        let grant = st.file_grants.grant_read(FilePurpose::SpecSource, &path).unwrap();
        (SpecInput::File { grant: grant.token }, path)
    }

    fn replace_in_place(path: &std::path::Path, text: &str) {
        #[cfg(unix)]
        let before = {
            use std::os::unix::fs::MetadataExt;
            std::fs::metadata(path).unwrap().ino()
        };
        // Truncates and writes the SAME inode, not a rename/replacement.
        std::fs::write(path, text).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            assert_eq!(std::fs::metadata(path).unwrap().ino(), before);
        }
    }

    #[test]
    fn native_apply_persists_its_verified_buffer_without_a_second_file_read() {
        let root = TempRoot::new();
        let st = DesktopState::new(root.0.clone());
        let (app, _) = create(&st, "A");
        st.set_app_since(app, st.epoch()).unwrap();
        let (input, path) = selected(&st, &root, V1);
        let opts = ImportOptions::default();
        let review = preview(&st, &input, &opts, &SpecTarget::NewWorkspace).unwrap();
        let done = import_with(&st, &input, &opts, SpecTarget::NewWorkspace, &review.approval, || {
            replace_in_place(&path, &V1.replace("/safe", "/changed-after-verify"));
        })
        .unwrap();
        let app = st.app().unwrap();
        assert_eq!(app.spec_original(&done.import_id).unwrap(), V1.as_bytes());
        let reviewed = V1.replace("/safe", "/reviewed");
        replace_in_place(&path, &reviewed);
        let key = done.import_id.to_string();
        let plan = reimport_plan(&st, &key, &input).unwrap();
        reimport_apply_with(&st, &key, &input, &ReimportApproval::default(), &plan.approval, || {
            replace_in_place(&path, &V1.replace("/safe", "/changed-after-verify"));
        })
        .unwrap();
        assert_eq!(app.spec_original(&done.import_id).unwrap(), reviewed.as_bytes());
    }

    #[test]
    fn lock_unlock_between_verification_and_commit_refuses_both_native_writes() {
        let root = TempRoot::new();
        let st = DesktopState::new(root.0.clone());
        let (app, dir) = create(&st, "A");
        st.set_app_since(app, st.epoch()).unwrap();
        let app = st.app().unwrap();
        let (input, path) = selected(&st, &root, V1);
        let opts = ImportOptions::default();
        let review = preview(&st, &input, &opts, &SpecTarget::NewWorkspace).unwrap();
        let before = app.backup_contents().unwrap();
        let invalidate = || {
            st.lock();
            let (_, key) = ProfileManager::unlock(&dir, Unlock::Passphrase(PASSPHRASE)).unwrap();
            st.unlock_since(&app, key, st.epoch()).unwrap();
        };
        assert!(import_with(&st, &input, &opts, SpecTarget::NewWorkspace, &review.approval, invalidate,).is_err());
        assert_eq!(app.backup_contents().unwrap(), before);
        let grant = st.file_grants.grant_read(FilePurpose::SpecSource, &path).unwrap();
        let input = SpecInput::File { grant: grant.token };
        let review = preview(&st, &input, &opts, &SpecTarget::NewWorkspace).unwrap();
        let done = import(&st, &input, &opts, SpecTarget::NewWorkspace, &review.approval).unwrap();
        replace_in_place(&path, &V1.replace("/safe", "/reviewed"));
        let key = done.import_id.to_string();
        let plan = reimport_plan(&st, &key, &input).unwrap();
        let before = app.backup_contents().unwrap();
        assert!(reimport_apply_with(&st, &key, &input, &ReimportApproval::default(), &plan.approval, invalidate,).is_err());
        assert_eq!(app.backup_contents().unwrap(), before);
    }

    #[test]
    fn same_inode_mutation_refuses_import_and_unchanged_bytes_persist() {
        let root = TempRoot::new();
        let st = DesktopState::new(root.0.clone());
        let (app, _) = create(&st, "A");
        st.set_app_since(app, st.epoch()).unwrap();
        let app = st.app().unwrap();
        let (input, path) = selected(&st, &root, V1);
        let options = ImportOptions::default();
        let review = preview(&st, &input, &options, &SpecTarget::NewWorkspace).unwrap();
        let before = app.backup_contents().unwrap();
        replace_in_place(&path, &V1.replace("/safe", "/unexpected"));
        // The ordinary reusable grant still accepts the changed inode.
        assert!(input.load(&st.file_grants).is_ok());
        let err = import(&st, &input, &options, SpecTarget::NewWorkspace, &review.approval).unwrap_err();
        assert!(err.contains("source or plan changed"), "{err}");
        assert_eq!(app.backup_contents().unwrap(), before);
        replace_in_place(&path, V1);
        let done = import(&st, &input, &options, SpecTarget::NewWorkspace, &review.approval).unwrap();
        assert_eq!(app.spec_original(&done.import_id).unwrap(), V1.as_bytes());
        assert_eq!(app.requests(&done.workspace_id).unwrap().len(), 1);
    }

    #[test]
    fn same_inode_reimport_change_with_stable_operation_ids_refuses_old_approval() {
        let root = TempRoot::new();
        let st = DesktopState::new(root.0.clone());
        let (app, _) = create(&st, "A");
        st.set_app_since(app, st.epoch()).unwrap();
        let app = st.app().unwrap();
        let (input, path) = selected(&st, &root, V1);
        let options = ImportOptions::default();
        let first = preview(&st, &input, &options, &SpecTarget::NewWorkspace).unwrap();
        let done = import(&st, &input, &options, SpecTarget::NewWorkspace, &first.approval).unwrap();
        let request = app.requests(&done.workspace_id).unwrap().pop().unwrap();
        let reviewed = V1.replace("/safe", "/reviewed");
        replace_in_place(&path, &reviewed);
        let key = done.import_id.to_string();
        let plan = reimport_plan(&st, &key, &input).unwrap();
        assert_eq!(plan.plan.updated[0].existing_id, request.meta.id);
        let decisions = ReimportApproval { overwrite: vec![request.meta.id], ..Default::default() };
        let before = app.backup_contents().unwrap();
        replace_in_place(&path, &V1.replace("/safe", "/unreviewed"));
        let changed = reimport_plan(&st, &key, &input).unwrap();
        assert_eq!(changed.plan.updated[0].existing_id, request.meta.id);
        let err = reimport_apply(&st, &key, &input, &decisions, &plan.approval).unwrap_err();
        assert!(err.contains("source or plan changed"), "{err}");
        assert_eq!(app.backup_contents().unwrap(), before);
        replace_in_place(&path, &reviewed);
        reimport_apply(&st, &key, &input, &decisions, &plan.approval).unwrap();
        assert_eq!(app.spec_original(&done.import_id).unwrap(), reviewed.as_bytes());
        // The source baseline changed on commit, even if ids/content remain.
        assert!(reimport_apply(&st, &key, &input, &decisions, &plan.approval).is_err());
    }

    #[test]
    fn old_plan_refuses_stored_edits_even_when_source_bytes_are_unchanged() {
        let root = TempRoot::new();
        let st = DesktopState::new(root.0.clone());
        let (app, _) = create(&st, "A");
        st.set_app_since(app, st.epoch()).unwrap();
        let app = st.app().unwrap();
        let (input, path) = selected(&st, &root, V1);
        let opts = ImportOptions::default();
        let review = preview(&st, &input, &opts, &SpecTarget::NewWorkspace).unwrap();
        let done = import(&st, &input, &opts, SpecTarget::NewWorkspace, &review.approval).unwrap();
        replace_in_place(&path, &V1.replace("/safe", "/reviewed"));
        let key = done.import_id.to_string();
        let plan = reimport_plan(&st, &key, &input).unwrap();
        let mut request = app.requests(&done.workspace_id).unwrap().pop().unwrap();
        request.name = "local edit after review".into();
        let rid = request.meta.id;
        app.save_request(request).unwrap();
        let before = app.backup_contents().unwrap();
        let decisions = ReimportApproval { overwrite: vec![rid], ..Default::default() };
        assert!(reimport_apply(&st, &key, &input, &decisions, &plan.approval).is_err());
        assert_eq!(app.backup_contents().unwrap(), before);
        let fresh = reimport_plan(&st, &key, &input).unwrap();
        reimport_apply(&st, &key, &input, &decisions, &fresh.approval).unwrap();
    }

    #[test]
    fn lock_unlock_profile_switch_and_desktop_restart_invalidate_both_reviews() {
        let root = TempRoot::new();
        let st = DesktopState::new(root.0.clone());
        let (app, dir) = create(&st, "A");
        let (other, _) = create(&st, "B");
        st.set_app_since(app, st.epoch()).unwrap();
        // Text deliberately bypasses grant revocation: epoch/profile scope
        // itself must reject these approvals, including after unlock.
        let input = SpecInput::Text { text: V1.into(), name: "review.json".into() };
        let opts = ImportOptions::default();
        let review = preview(&st, &input, &opts, &SpecTarget::NewWorkspace).unwrap();
        let done = import(&st, &input, &opts, SpecTarget::NewWorkspace, &review.approval).unwrap();
        let key = done.import_id.to_string();
        let plan = reimport_plan(&st, &key, &input).unwrap();
        let decisions = ReimportApproval::default();
        let refused = || {
            assert!(import(&st, &input, &opts, SpecTarget::NewWorkspace, &review.approval,).is_err());
            assert!(reimport_apply(&st, &key, &input, &decisions, &plan.approval).is_err());
        };
        st.lock();
        refused();
        let app = st.app.read().clone().unwrap();
        let (_, key_material) = ProfileManager::unlock(&dir, Unlock::Passphrase(PASSPHRASE)).unwrap();
        st.unlock_since(&app, key_material, st.epoch()).unwrap();
        refused();
        st.set_app_since(other, st.epoch()).unwrap();
        refused();
        let (header, key_material) = ProfileManager::unlock(&dir, Unlock::Passphrase(PASSPHRASE)).unwrap();
        let reopened = anvil_app::App::open(dir, header, key_material).unwrap();
        let restarted = DesktopState::new(root.0.clone());
        restarted.set_app_since(reopened, restarted.epoch()).unwrap();
        assert!(import(&restarted, &input, &opts, SpecTarget::NewWorkspace, &review.approval,).is_err());
        assert!(reimport_apply(&restarted, &key, &input, &decisions, &plan.approval).is_err());
    }

    #[test]
    fn changed_options_destination_grant_and_forged_digest_are_refused() {
        let root = TempRoot::new();
        let st = DesktopState::new(root.0.clone());
        let (app, _) = create(&st, "A");
        st.set_app_since(app, st.epoch()).unwrap();
        let (input, path) = selected(&st, &root, V1);
        let opts = ImportOptions::default();
        let review = preview(&st, &input, &opts, &SpecTarget::NewWorkspace).unwrap();
        let workspace = st.app().unwrap().create_workspace("destination").unwrap().meta.id;
        let before = st.app().unwrap().backup_contents().unwrap();
        let changed = ImportOptions { include_credentials: true, ..opts.clone() };
        assert!(import(&st, &input, &changed, SpecTarget::NewWorkspace, &review.approval).is_err());
        assert!(import(&st, &input, &opts, SpecTarget::Workspace { workspace_id: workspace }, &review.approval,).is_err());
        let replacement = st.file_grants.grant_read(FilePurpose::SpecSource, &path).unwrap();
        let replacement = SpecInput::File { grant: replacement.token };
        assert!(import(&st, &replacement, &opts, SpecTarget::NewWorkspace, &review.approval,).is_err());
        let mut forged = review.approval;
        forged.binding.source_sha256 = Id::new().to_string();
        // Even with a correctly recomputed context digest, native bytes win.
        let fence = st.admit_payload().unwrap();
        forged.scope = approval_scope(&st, &fence, &input, &("import", SpecTarget::NewWorkspace), &forged.binding).unwrap();
        assert!(import(&st, &input, &opts, SpecTarget::NewWorkspace, &forged).is_err());
        assert_eq!(st.app().unwrap().backup_contents().unwrap(), before);
    }
}
