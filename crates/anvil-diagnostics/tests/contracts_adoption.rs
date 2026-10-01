use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(path).unwrap_or_else(|error| panic!("reading {}: {error}", path.display())))
        .unwrap_or_else(|error| panic!("parsing {}: {error}", path.display()))
}

fn files_under(root: &Path, base: &Path) -> BTreeSet<String> {
    let mut files = BTreeSet::new();
    for entry in std::fs::read_dir(root).unwrap_or_else(|error| panic!("reading {}: {error}", root.display())) {
        let entry = entry.expect("directory entry");
        let path = entry.path();
        if path.is_dir() {
            files.extend(files_under(&path, base));
        } else {
            files.insert(path.strip_prefix(base).unwrap().to_string_lossy().replace('\\', "/"));
        }
    }
    files
}

fn strings(value: &Value) -> BTreeSet<String> {
    value.as_array().expect("contract list").iter().map(|entry| entry.as_str().expect("string entry").to_owned()).collect()
}

fn differences(expected: &BTreeSet<String>, actual: &BTreeSet<String>) -> (Vec<String>, Vec<String>) {
    let missing = expected.difference(actual).cloned().collect();
    let extra = actual.difference(expected).cloned().collect();
    (missing, extra)
}

#[test]
fn pinned_contract_hashes_and_anvil_copies_match() {
    let root = repo_root();
    let vendor = root.join("contracts/ferrum-contracts");
    let pin = std::fs::read_to_string(vendor.join("PIN")).expect("contracts/ferrum-contracts/PIN");
    let mut hashes = BTreeMap::new();
    let mut tag = None;
    let mut commit = None;
    for line in pin.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        match fields.as_slice() {
            ["tag", value] => tag = Some(*value),
            ["commit", value] => commit = Some(*value),
            ["sha256", hash, path] => {
                hashes.insert((*path).to_owned(), (*hash).to_owned());
            }
            _ => panic!("malformed PIN line: {line}"),
        }
    }
    assert_eq!(tag, Some("contracts-edge-0.9.9"));
    assert_eq!(commit, Some("25c4e9e00033d7941a1dd0ab733fa74e735546ae"));
    let expected_files: BTreeSet<String> = [
        "vocabularies/gateway-errors.json",
        "vocabularies/gateway-headers.json",
        "schemas/diagnostic-finding/v1.schema.json",
        "fixtures/diagnostic-finding/valid/ferrum-token-backend-error.json",
        "fixtures/diagnostic-finding/valid/ferrum-token-connection-failure.json",
        "fixtures/diagnostic-finding/invalid/alloy-only-evidence-source.json",
        "fixtures/diagnostic-finding/invalid/missing-does-not-prove.json",
        "fixtures/diagnostic-finding/invalid/probability-confidence.json",
    ]
    .into_iter()
    .map(String::from)
    .collect();
    let actual_files: BTreeSet<String> = hashes.keys().cloned().collect();
    let (missing, extra) = differences(&expected_files, &actual_files);
    assert!(missing.is_empty() && extra.is_empty(), "PIN file list differs; missing: {missing:?}; extra: {extra:?}");
    let vendored_files: BTreeSet<String> = files_under(&vendor, &vendor).into_iter().filter(|path| path != "PIN").collect();
    let (unpinned, stale_pins) = differences(&vendored_files, &actual_files);
    assert!(
        unpinned.is_empty() && stale_pins.is_empty(),
        "vendored files differ from PIN; unpinned: {unpinned:?}; missing: {stale_pins:?}"
    );
    for (path, expected_hash) in hashes {
        let bytes = std::fs::read(vendor.join(&path)).unwrap_or_else(|error| panic!("reading vendored {path}: {error}"));
        let actual_hash = Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect::<String>();
        assert_eq!(actual_hash, expected_hash, "vendored contract changed: {path}");
    }

    let errors = read_json(&vendor.join("vocabularies/gateway-errors.json"));
    let headers = read_json(&vendor.join("vocabularies/gateway-headers.json"));
    let local = read_json(&root.join("catalog/ferrum/ferrum-edge-0.9.9/outcomes.json"));
    let contract_tokens: BTreeSet<String> =
        errors["x_gateway_error_tokens"].as_array().unwrap().iter().map(|entry| entry["token"].as_str().unwrap().to_owned()).collect();
    let local_tokens = strings(&local["public_tokens"]);
    let (missing, extra) = differences(&contract_tokens, &local_tokens);
    assert!(missing.is_empty() && extra.is_empty(), "0.9.9 public_tokens drift; missing: {missing:?}; extra: {extra:?}");

    let diagnostic_tokens: BTreeSet<String> = read_json(&root.join("catalog/diagnostics/findings.en.json"))["findings"]
        .as_object()
        .unwrap()
        .keys()
        .filter_map(|code| code.strip_prefix("ferrum.token.").map(str::to_owned))
        .collect();
    let (missing, extra) = differences(&contract_tokens, &diagnostic_tokens);
    assert!(missing.is_empty() && extra.is_empty(), "ferrum.token.* wording drift; missing: {missing:?}; extra: {extra:?}");

    let contract_classes: BTreeSet<String> =
        errors["error_classes"].as_array().unwrap().iter().map(|entry| entry["value"].as_str().unwrap().to_owned()).collect();
    let local_classes: BTreeSet<String> =
        local["error_class_semantics"].as_array().unwrap().iter().map(|entry| entry["class"].as_str().unwrap().to_owned()).collect();
    let (missing, extra) = differences(&contract_classes, &local_classes);
    assert!(missing.is_empty() && extra.is_empty(), "0.9.9 error_classes drift; missing: {missing:?}; extra: {extra:?}");
    let local_class_meanings: BTreeMap<&str, &str> = local["error_class_semantics"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| (entry["class"].as_str().unwrap(), entry["x_gateway_error_typical"].as_str().unwrap()))
        .collect();
    let mut class_meaning_drift = Vec::new();
    for class in errors["error_classes"].as_array().unwrap() {
        let name = class["value"].as_str().unwrap();
        let token = class["x_gateway_error"].as_str().unwrap();
        let local_meaning = local_class_meanings[name];
        let documented_condition = match (name, token) {
            ("client_disconnect", "backend_error") => local_meaning == "(only if public status >=500)",
            ("request_body_too_large", "backend_error") => local_meaning == "(4xx: none)",
            _ => false,
        };
        let mapped_token = local_meaning.split_once(" (").map_or(local_meaning, |(token, _)| token);
        if mapped_token != token && !documented_condition {
            class_meaning_drift.push(format!("{name}: contract token {token:?}, local meaning {local_meaning:?}"));
        }
    }
    assert!(class_meaning_drift.is_empty(), "error_class token meaning drift: {class_meaning_drift:?}");

    // Compare the headers Anvil's Ferrum rules actually read. A gateway
    // diagnostic header still unreleased on the pin needs an explicit decision
    // when the pin changes, and a released one Anvil does not read yet is
    // listed here and asserted separately.
    let unreleased: Vec<&str> = headers["headers"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|entry| entry["role"] == "gateway_diagnostic" && entry["availability"] == "unreleased")
        .map(|entry| entry["name"].as_str().unwrap())
        .collect();
    assert!(unreleased.is_empty(), "unreleased gateway diagnostic headers need an explicit decision: {unreleased:?}");
    // X-Ferrum-Diagnostic-Ref is released in Ferrum Edge v0.9.9 (#5845). Anvil
    // does not read it until the authenticated lookup is adopted
    // (docs/diagnostics.md, G01), so its rules still read only the two markers.
    let entries = headers["headers"].as_array().unwrap();
    let diagnostic_ref = entries.iter().find(|entry| entry["name"] == "X-Ferrum-Diagnostic-Ref").expect("X-Ferrum-Diagnostic-Ref");
    assert_eq!(diagnostic_ref["availability"], "v0.9.9", "X-Ferrum-Diagnostic-Ref is released in Ferrum Edge v0.9.9");
    assert_eq!(diagnostic_ref["role"], "gateway_diagnostic");
    let not_read_yet: BTreeSet<String> = ["x-ferrum-diagnostic-ref"].into_iter().map(String::from).collect();
    let contract_headers: BTreeSet<String> = headers["headers"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|entry| entry["role"] == "gateway_diagnostic")
        .map(|entry| entry["name"].as_str().unwrap().to_ascii_lowercase())
        .filter(|name| !not_read_yet.contains(name))
        .collect();
    let local_header_names: BTreeSet<String> = ["x-gateway-error", "x-gateway-upstream-status"].into_iter().map(String::from).collect();
    let (missing, extra) = differences(&contract_headers, &local_header_names);
    assert!(missing.is_empty() && extra.is_empty(), "gateway diagnostic header drift; missing: {missing:?}; extra: {extra:?}");
    let local_header_meanings: BTreeMap<String, &str> = local["headers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| (entry["name"].as_str().unwrap().to_ascii_lowercase(), entry["semantics"].as_str().unwrap()))
        .collect();
    let gateway_error_meaning = local_header_meanings.get("x-gateway-error").expect("X-Gateway-Error meaning");
    let missing_header_tokens: Vec<String> =
        contract_tokens.iter().filter(|token| !gateway_error_meaning.contains(token.as_str())).cloned().collect();
    assert!(missing_header_tokens.is_empty(), "X-Gateway-Error meaning omits pinned tokens: {missing_header_tokens:?}");
    let upstream_status_meaning = local_header_meanings.get("x-gateway-upstream-status").expect("X-Gateway-Upstream-Status meaning");
    assert!(upstream_status_meaning.contains("degraded"), "X-Gateway-Upstream-Status meaning drifted: {upstream_status_meaning}");
    let diagnostic_ref_meaning = local_header_meanings.get("x-ferrum-diagnostic-ref").expect("X-Ferrum-Diagnostic-Ref meaning");
    assert!(diagnostic_ref_meaning.contains("v0.9.9"), "X-Ferrum-Diagnostic-Ref meaning drifted: {diagnostic_ref_meaning}");

    let shared_schema = read_json(&vendor.join("schemas/diagnostic-finding/v1.schema.json"));
    let local_schema = read_json(&root.join("contracts/schemas/DiagnosticFinding.schema.json"));
    let without_contract_metadata = |value: Value| {
        let mut object: Map<String, Value> = value.as_object().unwrap().clone();
        object.remove("$id");
        object.remove("x-contract");
        Value::Object(object)
    };
    assert_eq!(
        without_contract_metadata(local_schema.clone()),
        without_contract_metadata(shared_schema.clone()),
        "local DiagnosticFinding schema differs from the pinned schema after removing $id and x-contract"
    );

    let validator = jsonschema::validator_for(&shared_schema).expect("pinned DiagnosticFinding schema compiles");
    for fixture in [
        "fixtures/diagnostic-finding/valid/ferrum-token-backend-error.json",
        "fixtures/diagnostic-finding/valid/ferrum-token-connection-failure.json",
    ] {
        let instance = read_json(&vendor.join(fixture));
        assert!(validator.is_valid(&instance), "pinned valid fixture failed: {fixture}");
    }
    for fixture in [
        "fixtures/diagnostic-finding/invalid/alloy-only-evidence-source.json",
        "fixtures/diagnostic-finding/invalid/missing-does-not-prove.json",
        "fixtures/diagnostic-finding/invalid/probability-confidence.json",
    ] {
        let instance = read_json(&vendor.join(fixture));
        assert!(!validator.is_valid(&instance), "pinned invalid fixture unexpectedly passed: {fixture}");
    }
}
