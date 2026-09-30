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

fn strings(value: &Value) -> BTreeSet<String> {
    value
        .as_array()
        .expect("contract list")
        .iter()
        .map(|entry| entry.as_str().expect("string entry").to_owned())
        .collect()
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
    assert_eq!(tag, Some("contracts-edge-0.9.8"));
    assert_eq!(commit, Some("89ef3917ce6bba142dce50b84f2033d81eb429dd"));
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
    for (path, expected_hash) in hashes {
        let bytes = std::fs::read(vendor.join(&path)).unwrap_or_else(|error| panic!("reading vendored {path}: {error}"));
        let actual_hash = format!("{:x}", Sha256::digest(bytes));
        assert_eq!(actual_hash, expected_hash, "vendored contract changed: {path}");
    }

    let errors = read_json(&vendor.join("vocabularies/gateway-errors.json"));
    let headers = read_json(&vendor.join("vocabularies/gateway-headers.json"));
    let local = read_json(&root.join("catalog/ferrum/ferrum-edge-0.9.8/outcomes.json"));
    let contract_tokens: BTreeSet<String> = errors["x_gateway_error_tokens"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["token"].as_str().unwrap().to_owned())
        .collect();
    let local_tokens = strings(&local["public_tokens"]);
    let (missing, extra) = differences(&contract_tokens, &local_tokens);
    assert!(missing.is_empty() && extra.is_empty(), "0.9.8 public_tokens drift; missing: {missing:?}; extra: {extra:?}");

    let diagnostic_tokens: BTreeSet<String> = read_json(&root.join("catalog/diagnostics/findings.en.json"))["findings"]
        .as_object()
        .unwrap()
        .keys()
        .filter_map(|code| code.strip_prefix("ferrum.token.").map(str::to_owned))
        .collect();
    let (missing, extra) = differences(&contract_tokens, &diagnostic_tokens);
    assert!(missing.is_empty() && extra.is_empty(), "ferrum.token.* wording drift; missing: {missing:?}; extra: {extra:?}");

    let contract_classes: BTreeSet<String> = errors["error_classes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["value"].as_str().unwrap().to_owned())
        .collect();
    let local_classes: BTreeSet<String> = local["error_class_semantics"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["class"].as_str().unwrap().to_owned())
        .collect();
    let (missing, extra) = differences(&contract_classes, &local_classes);
    assert!(missing.is_empty() && extra.is_empty(), "0.9.8 error_classes drift; missing: {missing:?}; extra: {extra:?}");
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
        let documented_condition = match name {
            "client_disconnect" => local_meaning == "(only if public status >=500)",
            "request_body_too_large" => local_meaning == "(4xx: none)",
            _ => false,
        };
        if !local_meaning.contains(token) && !documented_condition {
            class_meaning_drift.push(format!("{name}: contract token {token:?}, local meaning {local_meaning:?}"));
        }
    }
    assert!(class_meaning_drift.is_empty(), "error_class token meaning drift: {class_meaning_drift:?}");

    // This catalog's header inventory is broader than the shared vocabulary.
    // Compare the v0.9.8 gateway diagnostic headers, which are the overlapping contract surface.
    let contract_headers: BTreeSet<String> = headers["headers"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|entry| entry["role"] == "gateway_diagnostic" && entry["availability"] == "v0.9.8")
        .map(|entry| entry["name"].as_str().unwrap().to_ascii_lowercase())
        .collect();
    let local_header_names: BTreeSet<String> = local["headers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["name"].as_str().unwrap().to_ascii_lowercase())
        .filter(|name| contract_headers.contains(name))
        .collect();
    let (missing, extra) = differences(&contract_headers, &local_header_names);
    assert!(missing.is_empty() && extra.is_empty(), "gateway diagnostic header drift; missing: {missing:?}; extra: {extra:?}");
    let local_header_meanings: BTreeMap<String, &str> = local["headers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| (entry["name"].as_str().unwrap().to_ascii_lowercase(), entry["semantics"].as_str().unwrap()))
        .collect();
    let gateway_error_meaning = local_header_meanings.get("x-gateway-error").expect("X-Gateway-Error meaning");
    let missing_header_tokens: Vec<String> = contract_tokens
        .iter()
        .filter(|token| !gateway_error_meaning.contains(token.as_str()))
        .cloned()
        .collect();
    assert!(missing_header_tokens.is_empty(), "X-Gateway-Error meaning omits pinned tokens: {missing_header_tokens:?}");
    let upstream_status_meaning = local_header_meanings
        .get("x-gateway-upstream-status")
        .expect("X-Gateway-Upstream-Status meaning");
    assert!(upstream_status_meaning.contains("degraded"), "X-Gateway-Upstream-Status meaning drifted: {upstream_status_meaning}");

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

#[test]
fn older_gateway_catalogs_keep_their_release_specific_vocabularies() {
    let root = repo_root();
    let timeout = "request_timeout";
    for release in ["0.9.5", "0.9.7"] {
        let catalog = read_json(&root.join(format!("catalog/ferrum/ferrum-edge-{release}/outcomes.json")));
        let tokens = strings(&catalog["public_tokens"]);
        assert!(!tokens.contains(timeout), "ferrum-edge-{release} describes its older release and must not adopt the 0.9.8 token");
    }
}
