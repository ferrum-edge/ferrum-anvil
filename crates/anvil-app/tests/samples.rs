//! The committed samples (`samples/`, made by `scripts/make-samples.sh`) stay
//! usable: the portable workspace imports into a clean profile, and the saved
//! reports parse with the current report types.

use anvil_app::App;
use anvil_app::profiles::ProfileManager;
use anvil_domain::load::LoadReport;
use anvil_domain::runner::RunReport;
use anvil_portability::plan::ConflictPolicy;
use anvil_storage::KdfParams;
use std::path::PathBuf;

fn samples() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../samples")
}

#[test]
fn sample_workspace_imports_into_a_clean_profile() {
    let bytes = std::fs::read(samples().join("workspaces/anvil-samples.anvil")).unwrap();
    let root = tempfile::tempdir().unwrap();
    let pm = ProfileManager::new(root.path());
    let (s, dek, _recovery) = pm.create_passphrase("clean", "correct horse battery", KdfParams::testing()).unwrap();
    let app = App::open(s.dir.clone(), anvil_storage::vault::read_header(&s.dir).unwrap(), dek).unwrap();
    let preview = app.import_preview(&bytes, None, ConflictPolicy::Merge).unwrap();
    assert!(preview.missing_secrets.is_empty(), "the sample needs no secrets");
    app.import(&bytes, None, ConflictPolicy::Merge).unwrap();
    let ws = app.find_workspace("Anvil samples (lab core)").unwrap();
    assert_eq!(app.requests(&ws.meta.id).unwrap().len(), 6);
    assert!(app.find_request(&ws.meta.id, "Gateway to backend/Backend refuses connections").is_ok());
}

#[test]
fn sample_reports_parse_with_current_types() {
    let run: RunReport = serde_json::from_slice(&std::fs::read(samples().join("reports/collection-run.json")).unwrap()).unwrap();
    assert_eq!(run.totals.steps_executed, 6);
    let load: LoadReport = serde_json::from_slice(&std::fs::read(samples().join("reports/load-report.json")).unwrap()).unwrap();
    assert_eq!(load.counts.completed, 200);
    assert!(!load.partial);
}
