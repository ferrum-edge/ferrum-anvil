//! The committed samples (`samples/`, made by `scripts/make-samples.sh`) stay
//! usable: the portable workspace imports into a clean profile, and the saved
//! reports parse with the current report types.

use anvil_app::App;
use anvil_app::port::ImportApproval;
use anvil_app::profiles::ProfileManager;
use anvil_domain::Timestamp;
use anvil_domain::load::LoadReport;
use anvil_domain::runner::RunReport;
use anvil_portability::plan::ConflictPolicy;
use anvil_storage::KdfParams;
use serde_json::Value;
use std::io::Read;
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
    app.import_approved(&bytes, None, ConflictPolicy::Merge, &ImportApproval::default()).unwrap();
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

/// Every RFC 3339 date-time string in `v`, with its JSON pointer.
fn timestamps(v: &Value, at: &str, out: &mut Vec<(String, String)>) {
    match v {
        Value::String(s) => {
            let b = s.as_bytes();
            let shaped = b.len() >= 20
                && b[..4].iter().all(u8::is_ascii_digit)
                && (b[4], b[7], b[10], b[13], b[16]) == (b'-', b'-', b'T', b':', b':');
            if shaped {
                out.push((at.to_string(), s.clone()));
            }
        }
        Value::Array(a) => a.iter().enumerate().for_each(|(i, x)| timestamps(x, &format!("{at}/{i}"), out)),
        Value::Object(o) => o.iter().for_each(|(k, x)| timestamps(x, &format!("{at}/{}", k.replace('~', "~0").replace('/', "~1")), out)),
        _ => {}
    }
}

fn sample_json(path: &str) -> Value {
    serde_json::from_slice(&std::fs::read(samples().join(path)).unwrap()).unwrap()
}

fn sample_bundle_json(name: &str) -> Value {
    let bytes = std::fs::read(samples().join("workspaces/anvil-samples.anvil")).unwrap();
    let mut z = zip::ZipArchive::new(std::io::Cursor::new(bytes)).unwrap();
    let mut text = String::new();
    z.by_name(name).unwrap().read_to_string(&mut text).unwrap();
    serde_json::from_str(&text).unwrap()
}

/// Stored and exported timestamps written by chrono (before #576) read back
/// and serialize to the same bytes with `Timestamp`.
#[test]
fn sample_timestamps_reserialize_byte_for_byte() {
    let mut found = Vec::new();
    for (name, v) in [
        ("reports/collection-run.json", sample_json("reports/collection-run.json")),
        ("reports/load-report.json", sample_json("reports/load-report.json")),
        ("anvil-samples.anvil manifest.json", sample_bundle_json("manifest.json")),
        ("anvil-samples.anvil workspace/objects.json", sample_bundle_json("workspace/objects.json")),
    ] {
        let before = found.len();
        timestamps(&v, name, &mut found);
        assert!(found.len() > before, "{name} has timestamps");
    }
    for (at, s) in &found {
        let t: Timestamp = serde_json::from_value(Value::String(s.clone())).unwrap_or_else(|e| panic!("{at}: {s:?}: {e}"));
        assert_eq!(serde_json::to_value(t).unwrap(), Value::String(s.clone()), "{at}");
    }
}

/// Through the report types, every timestamp the current type still has is
/// written back unchanged.
#[test]
fn sample_reports_round_trip_their_timestamps() {
    fn check<T: serde::de::DeserializeOwned + serde::Serialize>(path: &str) {
        let original = sample_json(path);
        let typed: T = serde_json::from_value(original.clone()).unwrap();
        let again = serde_json::to_value(&typed).unwrap();
        let mut found = Vec::new();
        timestamps(&original, "", &mut found);
        let mut compared = 0;
        for (at, s) in &found {
            if let Some(v) = again.pointer(at) {
                assert_eq!(v, &Value::String(s.clone()), "{path}{at}");
                compared += 1;
            }
        }
        assert!(compared >= 3, "{path}: only {compared} timestamps compared");
    }
    check::<RunReport>("reports/collection-run.json");
    check::<LoadReport>("reports/load-report.json");
}

/// The text renderings of those timestamps in the CSV, JUnit and HTML samples.
#[test]
fn sample_report_renderings_keep_their_time_text() {
    let load: LoadReport = serde_json::from_value(sample_json("reports/load-report.json")).unwrap();
    let csv = std::fs::read_to_string(samples().join("reports/load-report.csv")).unwrap();
    assert!(csv.lines().any(|l| l == format!("run,started_at,{}", load.started_at.to_rfc3339())), "{csv}");
    assert!(csv.lines().any(|l| l == format!("run,finished_at,{}", load.finished_at.to_rfc3339())), "{csv}");
    let html = std::fs::read_to_string(samples().join("reports/load-report.html")).unwrap();
    assert!(html.contains(&format!("{} UTC → {} UTC", load.started_at.format_date_time(), load.finished_at.format_time())));

    let run: RunReport = serde_json::from_value(sample_json("reports/collection-run.json")).unwrap();
    let junit = std::fs::read_to_string(samples().join("reports/collection-run.junit.xml")).unwrap();
    assert!(junit.contains(&format!("timestamp=\"{}\"", run.started_at.format_iso_seconds())));
    let html = std::fs::read_to_string(samples().join("reports/collection-run.html")).unwrap();
    assert!(html.contains(&format!("started {} UTC", run.started_at.format_date_time())));
}
