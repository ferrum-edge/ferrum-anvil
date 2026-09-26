//! `anvil import` of a full backup and of a bundle: the real binary and a
//! real profile on disk. A backup that claims a workspace stored here is
//! restored only when `--into-existing` names that workspace, and only from
//! the file `--bundle-sha256` names when given. A bundle without a vault is
//! imported without an export passphrase.

use anvil_app::App;
use anvil_app::profiles::{ProfileManager, Unlock};
use anvil_domain::Id;
use anvil_domain::request::RequestSpec;
use anvil_portability::ExportMode;
use anvil_storage::KdfParams;
use std::path::Path;
use std::process::{Command, Output};

const PASS: &str = "cli-import-passphrase-1";
const EXPORT_PASS: &str = "cli-backup-passphrase-1";

/// A profile whose workspace `W` holds the request `Kept`, and a full backup
/// of it written to `backup` while `W` also held `Restored` (deleted since).
/// Returns the id of `W`.
fn setup(root: &Path, backup: &Path) -> Id {
    let pm = ProfileManager::new(root);
    let (s, dek, _) = pm.create_passphrase("ci", PASS, KdfParams::testing()).unwrap();
    let h = anvil_storage::vault::read_header(&s.dir).unwrap();
    let app = App::open(s.dir, h, dek).unwrap();
    let ws = app.create_workspace("W").unwrap();
    app.create_request(&ws.meta.id, None, "Kept", RequestSpec::http("GET", "https://kept.example.invalid/")).unwrap();
    let gone = app.create_request(&ws.meta.id, None, "Restored", RequestSpec::http("GET", "https://restored.example.invalid/")).unwrap();
    let (bytes, _) = app.export_backup_with(EXPORT_PASS, KdfParams::testing()).unwrap();
    std::fs::write(backup, bytes).unwrap();
    app.delete_request(&gone.meta.id).unwrap();
    ws.meta.id
}

fn anvil(data: &Path, args: &[&str]) -> Output {
    anvil_with_export_pass(data, EXPORT_PASS, args)
}

/// `anvil` with `ANVIL_EXPORT_PASSPHRASE` set to `export_pass`.
fn anvil_with_export_pass(data: &Path, export_pass: &str, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_anvil"))
        .arg("--data-dir")
        .arg(data)
        .args(args)
        .env("ANVIL_PASSPHRASE", PASS)
        .env("ANVIL_EXPORT_PASSPHRASE", export_pass)
        .env_remove("ANVIL_PROFILE")
        .env_remove("ANVIL_DATA_DIR")
        .output()
        .unwrap()
}

fn text(o: &Output) -> String {
    format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr))
}

/// The names of the requests stored in `ws`, sorted.
fn requests(root: &Path, ws: &Id) -> Vec<String> {
    let s = ProfileManager::new(root).list().into_iter().next().unwrap();
    let (h, key) = ProfileManager::unlock(&s.dir, Unlock::Passphrase(PASS)).unwrap();
    let app = App::open(s.dir, h, key).unwrap();
    let mut names: Vec<String> = app.requests(ws).unwrap().into_iter().map(|r| r.name).collect();
    names.sort();
    names
}

#[test]
fn a_backup_restores_into_a_stored_workspace_only_with_into_existing() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let backup = dir.path().join("profile.anvilbak");
    let ws = setup(&data, &backup);
    let file = backup.to_str().unwrap();
    let id = ws.to_string();

    // The dry run names the stored workspace the backup claims.
    let o = anvil(&data, &["import", file, "--dry-run"]);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    let report: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(report["full_backup"], serde_json::json!(true), "{report}");
    assert_eq!(report["plan"]["existing_workspaces"], serde_json::json!([{ "id": id, "name": "W" }]), "{report}");
    let digest = report["bundle_sha256"].as_str().unwrap().to_string();
    assert_eq!(digest.len(), 64, "{report}");

    // Without approving it, or approving another workspace, nothing is restored.
    let other = Id::new().to_string();
    for policy in ["merge", "replace"] {
        let o = anvil(&data, &["import", file, "--policy", policy]);
        assert_eq!(o.status.code(), Some(3), "{policy}: {}", text(&o));
        assert!(text(&o).contains("existing workspace 'W'"), "{policy}: {}", text(&o));
        let o = anvil(&data, &["import", file, "--policy", policy, "--into-existing", &other]);
        assert_eq!(o.status.code(), Some(3), "{policy}: {}", text(&o));
        assert!(text(&o).contains("existing workspace 'W'"), "{policy}: {}", text(&o));
    }
    // Approved for another file, it is refused too.
    let other_file = "0".repeat(64);
    let o = anvil(&data, &["import", file, "--policy", "merge", "--into-existing", &id, "--bundle-sha256", &other_file]);
    assert_eq!(o.status.code(), Some(3), "{}", text(&o));
    assert!(text(&o).contains("not the one that was previewed"), "{}", text(&o));
    assert_eq!(requests(&data, &ws), vec!["Kept"], "a refused restore writes nothing");

    // Naming it, for the file the dry run showed, restores the backup there.
    let o = anvil(&data, &["import", file, "--policy", "merge", "--into-existing", &id, "--bundle-sha256", &digest]);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    let report: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(report["workspace_ids"], serde_json::json!([id]), "{report}");
    assert_eq!(requests(&data, &ws), vec!["Kept", "Restored"]);
}

/// A profile and a share-safe bundle of its workspace `Shared` (holding the
/// request `Probe`), written to `bundle`; the workspace is deleted since.
/// Returns its id.
fn shared_bundle(root: &Path, bundle: &Path) -> Id {
    let pm = ProfileManager::new(root);
    let (s, dek, _) = pm.create_passphrase("ci", PASS, KdfParams::testing()).unwrap();
    let h = anvil_storage::vault::read_header(&s.dir).unwrap();
    let app = App::open(s.dir, h, dek).unwrap();
    let ws = app.create_workspace("Shared").unwrap();
    app.create_request(&ws.meta.id, None, "Probe", RequestSpec::http("GET", "https://probe.example.invalid/")).unwrap();
    let (bytes, _) = app.export(Some(&ws.meta.id), ExportMode::ShareSafely, None, false).unwrap();
    std::fs::write(bundle, bytes).unwrap();
    app.delete_workspace(&ws.meta.id).unwrap();
    ws.meta.id
}

#[test]
fn a_bundle_without_a_vault_is_imported_without_an_export_passphrase() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let bundle = dir.path().join("shared.anvil-workspace");
    let ws = shared_bundle(&data, &bundle);
    let file = bundle.to_str().unwrap();

    // With ANVIL_EXPORT_PASSPHRASE set, the CLI says to unset it.
    for args in [&["import", file, "--dry-run"][..], &["import", file][..]] {
        let o = anvil(&data, args);
        assert_eq!(o.status.code(), Some(3), "{args:?}: {}", text(&o));
        assert!(text(&o).contains("unset ANVIL_EXPORT_PASSPHRASE"), "{args:?}: {}", text(&o));
    }
    assert!(requests(&data, &ws).is_empty(), "nothing was imported");

    // An empty value is no passphrase.
    let o = anvil_with_export_pass(&data, "", &["import", file]);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    assert_eq!(requests(&data, &ws), vec!["Probe"]);
}
