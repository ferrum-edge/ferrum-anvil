//! `anvil lint-spec`: needs no profile, exits 0/2/3 by `--fail-on`, and
//! writes text, JSON or SARIF.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn repo(p: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").join(p)
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
fn lint_spec_exit_codes_and_formats() {
    let data = tempfile::tempdir().unwrap();
    let spec = repo("crates/anvil-contract/tests/fixtures/orders-3.1.yaml");
    let spec = spec.to_str().unwrap();
    let acme = repo("samples/api-standards/acme-api-standards.yaml");
    let acme = acme.to_str().unwrap();

    // Recommended rules: an error-level finding (undeclared path parameter).
    let out = anvil(data.path(), &["lint-spec", spec]);
    let text = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(2), "{text}");
    assert!(text.contains("orders-3.1.yaml:42:5  error  path-params-declared"), "{text}");
    assert!(text.contains("fix: Add each one to `parameters`"), "{text}");
    assert!(text.contains("failed: 1 error"), "{text}");
    // No profile was created or opened.
    assert!(std::fs::read_dir(data.path()).map(|d| d.count()).unwrap_or(0) == 0);

    let out = anvil(data.path(), &["lint-spec", spec, "--fail-on", "never", "--format", "json", "--ruleset", acme]);
    assert_eq!(out.status.code(), Some(0));
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["rulesets"][1]["name"], "Acme API standards");
    assert!(report["findings"].as_array().unwrap().iter().any(|f| f["rule"] == "acme-property-camel-case"));

    let sarif_path = data.path().join("out.sarif");
    let out = anvil(data.path(), &["lint-spec", spec, "--ruleset", acme, "--format", "sarif", "--output", sarif_path.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("failed:"));
    let sarif: serde_json::Value = serde_json::from_slice(&std::fs::read(&sarif_path).unwrap()).unwrap();
    assert_eq!(sarif["version"], "2.1.0");

    // Local errors: an invalid ruleset, a file that is not a spec.
    let bad = data.path().join("bad.yaml");
    std::fs::write(&bad, "anvil_ruleset: 1\nrules:\n  x: { given: operatoin, then: { function: truthy } }\n").unwrap();
    let out = anvil(data.path(), &["lint-spec", spec, "--ruleset", bad.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&out.stderr).contains("unknown target 'operatoin'"));
    let out = anvil(data.path(), &["lint-spec", bad.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(3));

    let out = anvil(data.path(), &["lint-spec", "--list-rules", "--ruleset", acme]);
    assert_eq!(out.status.code(), Some(0));
    let list = String::from_utf8_lossy(&out.stdout);
    assert!(list.contains("acme-secured") && list.contains("off    operation-description"), "{list}");
}

#[test]
fn text_output_escapes_control_characters_from_the_spec() {
    let data = tempfile::tempdir().unwrap();
    let spec = data.path().join("evil.json");
    std::fs::write(
        &spec,
        r#"{"openapi":"3.1.0","info":{"title":"t\n::error file=x::pwned\u001b[31m","version":"1"},"paths":{"/a\n::stop-commands::x":{"get":{"responses":{"200":{"description":"ok"}}}}}}"#,
    )
    .unwrap();
    let out = anvil(data.path(), &["lint-spec", spec.to_str().unwrap(), "--fail-on", "never"]);
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.lines().all(|l| !l.starts_with("::")), "{text}");
    assert!(!text.contains('\u{1b}'), "{text}");
    assert!(text.contains("\\n::stop-commands::x"), "{text}");
}

#[test]
fn an_incomplete_lint_is_a_local_error_unless_accepted() {
    let data = tempfile::tempdir().unwrap();
    let params: Vec<serde_json::Value> = (0..3_000).map(|i| serde_json::json!({"name": format!("p{i}"), "in": "query"})).collect();
    let ops: serde_json::Map<String, serde_json::Value> =
        (0..3_000).map(|i| (format!("X{i}"), serde_json::json!({"responses": {"200": {"description": "ok"}}}))).collect();
    let doc = serde_json::json!({"openapi": "3.2.0", "info": {"title": "t", "version": "1"}, "paths": {"/w": {"parameters": params, "additionalOperations": ops}}});
    let spec = data.path().join("wide.json");
    std::fs::write(&spec, doc.to_string()).unwrap();
    let out = anvil(data.path(), &["lint-spec", spec.to_str().unwrap(), "--fail-on", "never"]);
    assert_eq!(out.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&out.stderr).contains("--allow-incomplete"));
    let out = anvil(data.path(), &["lint-spec", spec.to_str().unwrap(), "--fail-on", "never", "--allow-incomplete"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&out.stdout).contains("too large to lint completely"));
}
