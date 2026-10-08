use anvil_diagnostics::gateway_detail;
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

/// The published pin targets Edge v0.9.14. Its v1 vocabularies keep every
/// token and class, so they also match the retained v0.9.9, v0.9.10 and
/// v0.9.11 catalogs; their historical release-to-contract mappings remain
/// contracts-edge-0.9.9(-r2) and contracts-edge-0.9.11.
const PINNED_RELEASES: [&str; 4] = ["ferrum-edge-0.9.9", "ferrum-edge-0.9.10", "ferrum-edge-0.9.11", "ferrum-edge-0.9.14"];

/// A catalog of a release the pin covers agrees with the pinned vocabularies:
/// the same public tokens and error classes, each class with the contract's
/// token, and header meanings that name every token.
fn assert_catalog_matches_pin(root: &Path, compatibility_id: &str, errors: &Value) {
    let local = read_json(&root.join(format!("catalog/ferrum/{compatibility_id}/outcomes.json")));
    let contract_tokens: BTreeSet<String> =
        errors["x_gateway_error_tokens"].as_array().unwrap().iter().map(|entry| entry["token"].as_str().unwrap().to_owned()).collect();
    let local_tokens = strings(&local["public_tokens"]);
    let (missing, extra) = differences(&contract_tokens, &local_tokens);
    assert!(missing.is_empty() && extra.is_empty(), "{compatibility_id} public_tokens drift; missing: {missing:?}; extra: {extra:?}");

    let contract_classes: BTreeSet<String> =
        errors["error_classes"].as_array().unwrap().iter().map(|entry| entry["value"].as_str().unwrap().to_owned()).collect();
    let local_classes: BTreeSet<String> =
        local["error_class_semantics"].as_array().unwrap().iter().map(|entry| entry["class"].as_str().unwrap().to_owned()).collect();
    let (missing, extra) = differences(&contract_classes, &local_classes);
    assert!(missing.is_empty() && extra.is_empty(), "{compatibility_id} error_classes drift; missing: {missing:?}; extra: {extra:?}");
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
    assert!(class_meaning_drift.is_empty(), "{compatibility_id} error_class token meaning drift: {class_meaning_drift:?}");

    let local_header_meanings: BTreeMap<String, &str> = local["headers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| (entry["name"].as_str().unwrap().to_ascii_lowercase(), entry["semantics"].as_str().unwrap()))
        .collect();
    let gateway_error_meaning = local_header_meanings.get("x-gateway-error").expect("X-Gateway-Error meaning");
    let missing_header_tokens: Vec<String> =
        contract_tokens.iter().filter(|token| !gateway_error_meaning.contains(token.as_str())).cloned().collect();
    assert!(missing_header_tokens.is_empty(), "{compatibility_id}: X-Gateway-Error meaning omits {missing_header_tokens:?}");
    let upstream_status_meaning = local_header_meanings.get("x-gateway-upstream-status").expect("X-Gateway-Upstream-Status meaning");
    assert!(
        upstream_status_meaning.contains("degraded"),
        "{compatibility_id}: X-Gateway-Upstream-Status meaning drifted: {upstream_status_meaning}"
    );
    let diagnostic_ref_meaning = local_header_meanings.get("x-ferrum-diagnostic-ref").expect("X-Ferrum-Diagnostic-Ref meaning");
    assert!(
        diagnostic_ref_meaning.contains("v0.9.9"),
        "{compatibility_id}: X-Ferrum-Diagnostic-Ref meaning drifted: {diagnostic_ref_meaning}"
    );
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
    assert_eq!(tag, Some("contracts-edge-0.9.14"));
    assert_eq!(commit, Some("ddbdd845733b7046c4393ac951011dafb774db33"));
    let expected_files: BTreeSet<String> = [
        "vocabularies/gateway-errors.json",
        "vocabularies/gateway-headers.json",
        "schemas/diagnostic-finding/v1.schema.json",
        "fixtures/diagnostic-finding/valid/ferrum-token-backend-error.json",
        "fixtures/diagnostic-finding/valid/ferrum-token-connection-failure.json",
        "fixtures/diagnostic-finding/invalid/alloy-only-evidence-source.json",
        "fixtures/diagnostic-finding/invalid/missing-does-not-prove.json",
        "fixtures/diagnostic-finding/invalid/probability-confidence.json",
        "schemas/diagnostic-ref/v1.schema.json",
        "fixtures/diagnostic-ref/valid/connection-failure.json",
        "fixtures/diagnostic-ref/valid/plugin-rejection.json",
        "fixtures/diagnostic-ref/valid/replica-tagged-reference.json",
        "fixtures/diagnostic-ref/valid/tls-retry.json",
        "fixtures/diagnostic-ref/invalid/created-at-not-rfc3339.json",
        "fixtures/diagnostic-ref/invalid/detail-missing-backend-dispatch.json",
        "fixtures/diagnostic-ref/invalid/granular-class-as-token.json",
        "fixtures/diagnostic-ref/invalid/malformed-ref.json",
        "fixtures/diagnostic-ref/invalid/unknown-schema-version.json",
        "fixtures/diagnostic-ref/invalid/uppercase-replica-id.json",
        "schemas/diagnostic-report/v1.schema.json",
        "fixtures/diagnostic-report/valid/db-operation-after-headers.json",
        "fixtures/diagnostic-report/valid/db-operation-dominates.json",
        "fixtures/diagnostic-report/valid/edge-rejected-before-upstream.json",
        "fixtures/diagnostic-report/valid/forged-verified-claim.json",
        "fixtures/diagnostic-report/valid/gateway-error-token.json",
        "fixtures/diagnostic-report/valid/service-exceeds-gateway.json",
        "fixtures/diagnostic-report/valid/service-span-missing.json",
        "fixtures/diagnostic-report/valid/unattributed-interval.json",
        "fixtures/diagnostic-report/invalid/finding-missing-owner.json",
        "fixtures/diagnostic-report/invalid/missing-collection.json",
        "fixtures/diagnostic-report/invalid/unsupported-major.json",
        "fixtures/diagnostic-report/invalid/uppercase-span-id.json",
        "fixtures/invalid-expectations.json",
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
    assert_eq!(errors["edge_release"], "v0.9.14");
    assert_eq!(headers["edge_release"], "v0.9.14");
    for vocabulary in [&errors, &headers] {
        for source in vocabulary["provenance"].as_array().unwrap() {
            assert_eq!(source["ref"], "v0.9.14");
            assert_eq!(source["commit"], "9bd4d5f9caa4ebe8f0ea13e76d8a6e2172eaca7d");
        }
    }
    for compatibility_id in PINNED_RELEASES {
        assert_catalog_matches_pin(&root, compatibility_id, &errors);
    }
    // The lab's default pin is a release the contract pin covers.
    let lock = std::fs::read_to_string(root.join("lab/gateway/RELEASE.lock")).expect("lab/gateway/RELEASE.lock");
    let lab_release = lock.lines().find_map(|line| line.strip_prefix("release ")).expect("RELEASE.lock names a release");
    let lab_id = format!("ferrum-edge-{}", lab_release.trim().trim_start_matches('v'));
    assert!(PINNED_RELEASES.contains(&lab_id.as_str()), "the lab runs {lab_id}, which {tag:?} does not cover");
    let contract_tokens: BTreeSet<String> =
        errors["x_gateway_error_tokens"].as_array().unwrap().iter().map(|entry| entry["token"].as_str().unwrap().to_owned()).collect();

    let diagnostic_tokens: BTreeSet<String> = read_json(&root.join("catalog/diagnostics/findings.en.json"))["findings"]
        .as_object()
        .unwrap()
        .keys()
        .filter_map(|code| code.strip_prefix("ferrum.token.").map(str::to_owned))
        .collect();
    let (missing, extra) = differences(&contract_tokens, &diagnostic_tokens);
    assert!(missing.is_empty() && extra.is_empty(), "ferrum.token.* wording drift; missing: {missing:?}; extra: {extra:?}");

    // Compare the headers Anvil's Ferrum rules actually read. A gateway
    // diagnostic header still unreleased on the pin needs an explicit decision
    // when the pin changes.
    let unreleased: Vec<&str> = headers["headers"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|entry| entry["role"] == "gateway_diagnostic" && entry["availability"] == "unreleased")
        .map(|entry| entry["name"].as_str().unwrap())
        .collect();
    assert!(unreleased.is_empty(), "unreleased gateway diagnostic headers need an explicit decision: {unreleased:?}");
    // X-Ferrum-Diagnostic-Ref is released in Ferrum Edge v0.9.9 (#5845), and
    // Anvil reads it: a trusted profile's lookup resolves it (G01).
    let entries = headers["headers"].as_array().unwrap();
    let diagnostic_ref = entries.iter().find(|entry| entry["name"] == "X-Ferrum-Diagnostic-Ref").expect("X-Ferrum-Diagnostic-Ref");
    assert_eq!(diagnostic_ref["availability"], "v0.9.9", "X-Ferrum-Diagnostic-Ref is released in Ferrum Edge v0.9.9");
    assert_eq!(diagnostic_ref["role"], "gateway_diagnostic");
    assert_eq!(diagnostic_ref["name"].as_str().map(str::to_ascii_lowercase).as_deref(), Some(gateway_detail::REF_HEADER));
    let contract_headers: BTreeSet<String> = headers["headers"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|entry| entry["role"] == "gateway_diagnostic")
        .map(|entry| entry["name"].as_str().unwrap().to_ascii_lowercase())
        .collect();
    let local_header_names: BTreeSet<String> =
        ["x-gateway-error", "x-gateway-upstream-status", gateway_detail::REF_HEADER].into_iter().map(String::from).collect();
    let (missing, extra) = differences(&contract_headers, &local_header_names);
    assert!(missing.is_empty() && extra.is_empty(), "gateway diagnostic header drift; missing: {missing:?}; extra: {extra:?}");

    let report = read_json(&vendor.join("schemas/diagnostic-report/v1.schema.json"));
    assert_eq!(report["x-contract"]["status"], "implemented");
    let shared_status = report["x-contract"]["shared_status"].as_str().unwrap();
    assert!(shared_status.starts_with("EXISTING shared v1"));
    let owner = &report["x-contract"]["coordinated_release"]["qualified_owner_commit"];
    let owner = owner.as_str().unwrap();
    assert_eq!(owner, "81cbb410d34ff5fba1f3d54cfd2e7ebccaed397e");
    // Descriptions, wire constraints and historical producer parity stay exact;
    // diagnostic_import.rs compares everything except $id / x-contract.

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

fn enum_strings(value: &Value) -> BTreeSet<String> {
    value["enum"].as_array().expect("enum").iter().filter_map(|entry| entry.as_str().map(str::to_owned)).collect()
}

fn local(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|value| value.to_string()).collect()
}

/// The pinned `ferrum.diagnostic_ref.v1` schema (Ferrum Edge v0.9.9) and
/// Anvil's lookup reader agree: the same closed vocabularies, and the pinned
/// fixtures are accepted or refused by both.
#[test]
fn pinned_diagnostic_ref_contract_matches_anvils_reader() {
    let vendor = repo_root().join("contracts/ferrum-contracts");
    let schema = read_json(&vendor.join("schemas/diagnostic-ref/v1.schema.json"));
    assert_eq!(schema["title"], gateway_detail::SCHEMA_VERSION);
    assert_eq!(enum_strings(&schema["properties"]["schema_version"]), local(&[gateway_detail::SCHEMA_VERSION]));
    assert_eq!(schema["properties"]["ref"]["pattern"], "^(fd1_[0-9a-f]{32}|fd2_[0-9a-f]{8}_[0-9a-f]{32})$");
    for reference in ["fd1_3f9c2a7e5b1d4c8a9e0f6b2d7c4a1e5f", "fd2_1a2b3c4d_3f9c2a7e5b1d4c8a9e0f6b2d7c4a1e5f"] {
        assert!(gateway_detail::parse_ref(reference).is_some(), "Anvil must accept a schema reference: {reference}");
    }
    for reference in ["fd1_3F9C2A7E5B1D4C8A9E0F6B2D7C4A1E5F", "fd1_short"] {
        assert!(gateway_detail::parse_ref(reference).is_none(), "Anvil must reject a malformed reference: {reference}");
    }
    let defs = &schema["$defs"];
    let vocabularies = [
        ("protocol", &schema["properties"]["protocol"], &gateway_detail::PROTOCOLS[..]),
        ("gateway_error", &schema["properties"]["gateway_error"], &gateway_detail::TOKENS[..]),
        ("detail.backend_dispatch", &defs["Detail"]["properties"]["backend_dispatch"], &gateway_detail::DISPATCH[..]),
        ("detail.duration_bucket", &defs["Detail"]["properties"]["duration_bucket"], &gateway_detail::DURATION_BUCKETS[..]),
        ("detail.rejection_phase", &defs["Detail"]["properties"]["rejection_phase"], &gateway_detail::REJECTION_PHASES[..]),
        ("detail.route_timeout_phase", &defs["Detail"]["properties"]["route_timeout_phase"], &gateway_detail::ROUTE_TIMEOUT_PHASES[..]),
        ("rejection.source", &defs["Rejection"]["properties"]["source"], &gateway_detail::REJECTION_SOURCES[..]),
        ("attempts.backend_dispatch", &defs["Attempt"]["properties"]["backend_dispatch"], &gateway_detail::ATTEMPT_DISPATCH[..]),
        ("attempts.tls.failure", &defs["TlsDetail"]["properties"]["failure"], &gateway_detail::TLS_FAILURES[..]),
    ];
    for (field, contract, anvil) in vocabularies {
        let (missing, extra) = differences(&enum_strings(contract), &local(anvil));
        assert!(missing.is_empty() && extra.is_empty(), "{field} drift; missing: {missing:?}; extra: {extra:?}");
    }
    assert_eq!(defs["Detail"]["properties"]["attempts"]["maxItems"], gateway_detail::MAX_ATTEMPTS);
    // Anvil requires the keys the schema requires.
    let (missing, extra) = differences(&strings(&schema["required"]), &local(&gateway_detail::REQUIRED_KEYS));
    assert!(missing.is_empty() && extra.is_empty(), "required keys drift; missing: {missing:?}; extra: {extra:?}");
    let (missing, extra) = differences(&strings(&defs["Detail"]["required"]), &local(&gateway_detail::DETAIL_REQUIRED_KEYS));
    assert!(missing.is_empty() && extra.is_empty(), "detail required keys drift; missing: {missing:?}; extra: {extra:?}");
    // A record's error classes are confirmed only within the pinned vocabulary.
    let errors = read_json(&vendor.join("vocabularies/gateway-errors.json"));
    let classes: BTreeSet<String> =
        errors["error_classes"].as_array().unwrap().iter().map(|entry| entry["value"].as_str().unwrap().to_owned()).collect();
    let (missing, extra) = differences(&classes, &local(&gateway_detail::ERROR_CLASSES));
    assert!(missing.is_empty() && extra.is_empty(), "error class drift; missing: {missing:?}; extra: {extra:?}");

    // `created_at` must be an RFC 3339 time: assert formats, as the contract's own checks do.
    let validator = jsonschema::options().should_validate_formats(true).build(&schema).expect("pinned diagnostic-ref schema compiles");
    let fixtures = files_under(&vendor.join("fixtures/diagnostic-ref"), &vendor);
    assert_eq!(fixtures.len(), 10, "{fixtures:?}");
    for fixture in fixtures {
        let bytes = std::fs::read(vendor.join(&fixture)).unwrap();
        let instance: Value = serde_json::from_slice(&bytes).unwrap();
        let anvil = gateway_detail::parse_view(&bytes);
        if fixture.contains("/valid/") {
            assert!(validator.is_valid(&instance), "pinned valid fixture failed: {fixture}");
            assert!(anvil.is_ok(), "Anvil refuses the valid fixture {fixture}: {anvil:?}");
        } else {
            assert!(!validator.is_valid(&instance), "pinned invalid fixture unexpectedly passed: {fixture}");
            assert!(anvil.is_err(), "Anvil accepts the invalid fixture {fixture}");
        }
    }
}
