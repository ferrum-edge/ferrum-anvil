//! `anvil spec-drift` with a HAR capture: needs no profile, reports drift,
//! writes the revised description and a JSON Patch, exits 0/2/3.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn repo(p: &str) -> String {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").join(p).to_string_lossy().into_owned()
}

fn anvil(data: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_anvil"))
        .arg("--data-dir")
        .arg(data)
        .args(args)
        .env_remove("ANVIL_PASSPHRASE")
        .env_remove("ANVIL_PROFILE")
        .output()
        .unwrap()
}

#[test]
fn spec_drift_from_a_har_capture() {
    let data = tempfile::tempdir().unwrap();
    let (spec, har) = (repo("samples/contract/shop.yaml"), repo("samples/contract/shop-traffic.har"));
    let revised: PathBuf = data.path().join("revised.yaml");
    let patch: PathBuf = data.path().join("patch.json");
    let out = anvil(
        data.path(),
        &["spec-drift", &spec, "--har", &har, "--revised", revised.to_str().unwrap(), "--patch", patch.to_str().unwrap()],
    );
    let text = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(2), "schema mismatches are errors: {text}");
    assert!(text.contains("GET /orders/{id} returned 404, which is not a documented response"), "{text}");
    assert!(text.contains("[x]") && text.contains("Document GET /customers/{customerId}"), "{text}");
    let revised = std::fs::read_to_string(&revised).unwrap();
    assert!(revised.contains("/customers/{customerId}:") && revised.contains("'404':"), "{revised}");
    let ops: serde_json::Value = serde_json::from_slice(&std::fs::read(&patch).unwrap()).unwrap();
    assert!(ops.as_array().unwrap().iter().any(|o| o["op"] == "add" && o["path"] == "/paths/~1orders/get/parameters/-"));

    // The revision (recommended additions) leaves only the relaxations' errors.
    let out = anvil(
        data.path(),
        &["spec-drift", data.path().join("revised.yaml").to_str().unwrap(), "--har", &har, "--format", "json", "--fail-on", "warn"],
    );
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let kinds: Vec<&str> = report["findings"].as_array().unwrap().iter().map(|f| f["kind"].as_str().unwrap()).collect();
    assert!(!kinds.contains(&"undeclared_status") && !kinds.contains(&"undeclared_path"), "{kinds:?}");
    assert_eq!(out.status.code(), Some(2));
    assert!(std::fs::read_dir(data.path()).unwrap().all(|e| e.unwrap().file_type().unwrap().is_file()), "no profile was created");

    let out = anvil(data.path(), &["spec-drift", &spec, "--har", &spec]);
    assert_eq!(out.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&out.stderr).contains("not a HAR archive"));
    let out = anvil(data.path(), &["spec-drift", &spec, "--har", &har, "--fail-on", "never"]);
    assert_eq!(out.status.code(), Some(0));
}
