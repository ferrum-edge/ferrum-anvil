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

/// The published pin targets Edge v0.9.20. Its vocabulary adds the
/// `loop_detected` token (Edge v0.9.17), which the retained v0.9.9 to v0.9.15
/// catalogs do not have, so it covers the v0.9.20 catalog only; their
/// historical release-to-contract mappings remain contracts-edge-0.9.9(-r2),
/// contracts-edge-0.9.11, contracts-edge-0.9.14 and contracts-edge-0.9.15.
const PINNED_RELEASES: [&str; 1] = ["ferrum-edge-0.9.20"];

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
    assert_eq!(tag, Some("contracts-edge-0.9.20"));
    assert_eq!(commit, Some("39da322083044c2e92617209e62983c92387f0ad"));
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
        "fixtures/diagnostic-ref/valid/client-disconnect-upload.json",
        "fixtures/diagnostic-ref/valid/connection-failure.json",
        "fixtures/diagnostic-ref/valid/gateway-closed-h3-upload.json",
        "fixtures/diagnostic-ref/valid/plugin-rejection.json",
        "fixtures/diagnostic-ref/valid/proxy-hop-limit.json",
        "fixtures/diagnostic-ref/valid/proxy-hops-invalid.json",
        "fixtures/diagnostic-ref/valid/query-trigger-admission.json",
        "fixtures/diagnostic-ref/valid/replica-tagged-reference.json",
        "fixtures/diagnostic-ref/valid/route-protocol-admission.json",
        "fixtures/diagnostic-ref/valid/tls-retry.json",
        "fixtures/diagnostic-ref/invalid/client-disconnect-upload-as-detail-phase.json",
        "fixtures/diagnostic-ref/invalid/created-at-not-rfc3339.json",
        "fixtures/diagnostic-ref/invalid/detail-missing-backend-dispatch.json",
        "fixtures/diagnostic-ref/invalid/gateway-closed-h3-upload-as-detail-phase.json",
        "fixtures/diagnostic-ref/invalid/granular-class-as-token.json",
        "fixtures/diagnostic-ref/invalid/malformed-ref.json",
        "fixtures/diagnostic-ref/invalid/proxy-hop-limit-as-detail-phase.json",
        "fixtures/diagnostic-ref/invalid/proxy-hops-invalid-as-detail-phase.json",
        "fixtures/diagnostic-ref/invalid/query-trigger-admission-as-detail-phase.json",
        "fixtures/diagnostic-ref/invalid/route-protocol-admission-as-detail-phase.json",
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
    assert_eq!(errors["edge_release"], "v0.9.20");
    assert_eq!(headers["edge_release"], "v0.9.20");
    for vocabulary in [&errors, &headers] {
        for source in vocabulary["provenance"].as_array().unwrap() {
            assert_eq!(source["ref"], "v0.9.20");
            assert_eq!(source["commit"], "e4a606a00352674daaef08636e3e359e6c48ba18");
        }
    }
    // The lab's default pin is a release the contract pin covers.
    let lock = std::fs::read_to_string(root.join("lab/gateway/RELEASE.lock")).expect("lab/gateway/RELEASE.lock");
    let lab_release = lock.lines().find_map(|line| line.strip_prefix("release ")).expect("RELEASE.lock names a release");
    let lab_id = format!("ferrum-edge-{}", lab_release.trim().trim_start_matches('v'));
    assert!(PINNED_RELEASES.contains(&lab_id.as_str()), "the lab runs {lab_id}, which {tag:?} does not cover");
    assert_vocabularies_match_anvil(&root, &vendor);

    let report = read_json(&vendor.join("schemas/diagnostic-report/v1.schema.json"));
    assert_eq!(report["x-contract"]["status"], "implemented");
    let shared_status = report["x-contract"]["shared_status"].as_str().unwrap();
    assert!(shared_status.starts_with("EXISTING shared v1"));
    let owner = &report["x-contract"]["coordinated_release"]["qualified_owner_commit"];
    let owner = owner.as_str().unwrap();
    assert_eq!(owner, "81cbb410d34ff5fba1f3d54cfd2e7ebccaed397e");
    // Descriptions, wire constraints and historical producer parity stay exact;
    // diagnostic_import.rs compares everything except $id / x-contract.
}

/// What Anvil reads from the error and header vocabularies and the
/// `DiagnosticFinding` schema in `contracts` (the vendored copy, or the same
/// files from ferrum-contracts `main`) agrees with Anvil: the catalog of every
/// release the pin covers, the `ferrum.token.*` wording, the gateway
/// diagnostic headers Anvil's rules read, and the finding schema and fixtures.
fn assert_vocabularies_match_anvil(root: &Path, contracts: &Path) {
    let errors = read_json(&contracts.join("vocabularies/gateway-errors.json"));
    let headers = read_json(&contracts.join("vocabularies/gateway-headers.json"));
    for compatibility_id in PINNED_RELEASES {
        assert_catalog_matches_pin(root, compatibility_id, &errors);
    }
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

    let shared_schema = read_json(&contracts.join("schemas/diagnostic-finding/v1.schema.json"));
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
        "local DiagnosticFinding schema differs from the contract schema after removing $id and x-contract"
    );

    // Every DiagnosticFinding fixture under the directory, so fixtures a newer
    // contracts revision adds are exercised too (the vendored set is fixed by
    // PIN).
    let validator = jsonschema::validator_for(&shared_schema).expect("DiagnosticFinding schema compiles");
    let fixtures = files_under(&contracts.join("fixtures/diagnostic-finding"), contracts);
    assert!(fixtures.iter().any(|fixture| fixture.contains("/valid/")), "no valid DiagnosticFinding fixture under {}", contracts.display());
    assert!(
        fixtures.iter().any(|fixture| fixture.contains("/invalid/")),
        "no invalid DiagnosticFinding fixture under {}",
        contracts.display()
    );
    for fixture in fixtures {
        let instance = read_json(&contracts.join(&fixture));
        if fixture.contains("/valid/") {
            assert!(validator.is_valid(&instance), "valid DiagnosticFinding fixture failed: {fixture}");
        } else {
            assert!(!validator.is_valid(&instance), "invalid DiagnosticFinding fixture unexpectedly passed: {fixture}");
        }
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
    assert_diagnostic_ref_contract_matches_anvils_reader(&repo_root().join("contracts/ferrum-contracts"), Some(22));
}

/// The `ferrum.diagnostic_ref.v1` schema, error classes and fixtures in
/// `contracts` agree with Anvil's lookup reader. `fixture_count` pins the
/// number of fixtures for the vendored copy; ferrum-contracts `main` may add
/// some.
fn assert_diagnostic_ref_contract_matches_anvils_reader(vendor: &Path, fixture_count: Option<usize>) {
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
    let validator = jsonschema::options().should_validate_formats(true).build(&schema).expect("diagnostic-ref schema compiles");
    let fixtures = files_under(&vendor.join("fixtures/diagnostic-ref"), vendor);
    if let Some(count) = fixture_count {
        assert_eq!(fixtures.len(), count, "{fixtures:?}");
    }
    assert!(!fixtures.is_empty(), "no diagnostic-ref fixtures under {}", vendor.display());
    for fixture in fixtures {
        let bytes = std::fs::read(vendor.join(&fixture)).unwrap();
        let instance: Value = serde_json::from_slice(&bytes).unwrap();
        let anvil = gateway_detail::parse_view(&bytes);
        if fixture.contains("/valid/") {
            assert!(validator.is_valid(&instance), "valid fixture failed: {fixture}");
            assert!(anvil.is_ok(), "Anvil refuses the valid fixture {fixture}: {anvil:?}");
        } else {
            assert!(!validator.is_valid(&instance), "invalid fixture unexpectedly passed: {fixture}");
            assert!(anvil.is_err(), "Anvil accepts the invalid fixture {fixture}");
        }
    }
}

/// The directory `.github/workflows/edge-main-drift.yml` fills with the files
/// Anvil vendors, read from ferrum-contracts `main` instead of the pinned tag.
fn contracts_main_dir() -> PathBuf {
    let dir = std::env::var_os("ANVIL_CONTRACTS_MAIN_DIR")
        .map(PathBuf::from)
        .expect("ANVIL_CONTRACTS_MAIN_DIR names a directory holding the ferrum-contracts main files");
    assert!(dir.join("vocabularies/gateway-errors.json").is_file(), "{} holds no ferrum-contracts files", dir.display());
    dir
}

/// Edge main early warning (ferrum-edge/ferrum-contracts#76): the pinned
/// vocabulary parity checks, against ferrum-contracts `main`, whose
/// vocabularies record what Edge `main` changes (`main_branch_delta`). Run
/// weekly by `.github/workflows/edge-main-drift.yml`; never a required check.
#[test]
#[ignore = "needs ANVIL_CONTRACTS_MAIN_DIR; run by .github/workflows/edge-main-drift.yml"]
fn contracts_main_vocabularies_match_anvil() {
    assert_vocabularies_match_anvil(&repo_root(), &contracts_main_dir());
}

/// The diagnostic-ref half of the Edge main early warning.
#[test]
#[ignore = "needs ANVIL_CONTRACTS_MAIN_DIR; run by .github/workflows/edge-main-drift.yml"]
fn contracts_main_diagnostic_ref_matches_anvils_reader() {
    assert_diagnostic_ref_contract_matches_anvils_reader(&contracts_main_dir(), None);
}

/// Every `const NAME: &str = "value";` in a Rust source, by name.
fn rust_str_consts(source: &str) -> BTreeMap<String, String> {
    let mut consts = BTreeMap::new();
    for line in source.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("pub const ").or_else(|| line.strip_prefix("const ")) else { continue };
        let Some((name, rest)) = rest.split_once(':') else { continue };
        let Some(value) = rest.trim().strip_prefix("&str = \"").and_then(|value| value.strip_suffix("\";")) else { continue };
        consts.insert(name.trim().to_owned(), value.to_owned());
    }
    consts
}

/// Edge's closed `X-Gateway-Error` vocabulary, read from `src/retry.rs`:
/// the entries of `HTTP_OBSERVABILITY_ERROR_CLASSES`, each a string literal
/// or an `OBS_*` constant resolved to its value.
fn edge_gateway_error_tokens(retry_rs: &str) -> BTreeSet<String> {
    const DECLARATION: &str = "pub const HTTP_OBSERVABILITY_ERROR_CLASSES: &[&str] = &[";
    let start = retry_rs.find(DECLARATION).expect("HTTP_OBSERVABILITY_ERROR_CLASSES in src/retry.rs") + DECLARATION.len();
    let end = start + retry_rs[start..].find("];").expect("end of HTTP_OBSERVABILITY_ERROR_CLASSES");
    let consts = rust_str_consts(retry_rs);
    let entries: String = retry_rs[start..end].lines().filter(|line| !line.trim_start().starts_with("//")).collect::<Vec<_>>().join("\n");
    entries
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(|entry| match entry.strip_prefix('"').and_then(|literal| literal.strip_suffix('"')) {
            Some(literal) => literal.to_owned(),
            None => consts.get(entry).unwrap_or_else(|| panic!("src/retry.rs: unresolved token constant {entry}")).clone(),
        })
        .collect()
}

/// Edge's `ErrorClass` labels, read from `ErrorClass::as_str` in `src/retry.rs`.
fn edge_error_classes(retry_rs: &str) -> BTreeSet<String> {
    let start = retry_rs.find("impl ErrorClass {").expect("impl ErrorClass in src/retry.rs");
    let body = &retry_rs[start..];
    let body = &body[body.find("fn as_str(").expect("ErrorClass::as_str in src/retry.rs")..];
    let body = &body[..body.find("\n    }\n").expect("end of ErrorClass::as_str")];
    let classes: BTreeSet<String> = body
        .lines()
        .filter_map(|line| line.split_once("=> \"").map(|(_, label)| label.trim_end_matches(',').trim_end_matches('"').to_owned()))
        .collect();
    assert!(!classes.is_empty(), "ErrorClass::as_str in src/retry.rs names no label");
    classes
}

/// Shaped like Edge's `src/retry.rs`, comments included.
const RETRY_RS_EXCERPT: &str = r#"
impl ErrorClass {
    /// Stable snake_case label.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::ConnectionTimeout => "connection_timeout",
            Self::RequestError => "request_error",
        }
    }
}

pub const OBS_CONNECTION_FAILURE: &str = "connection_failure";
/// A comment between constants.
pub const OBS_LOOP_DETECTED: &str = "loop_detected";

pub const HTTP_OBSERVABILITY_ERROR_CLASSES: &[&str] = &[
    OBS_CONNECTION_FAILURE,
    // a comment inside the array
    OBS_LOOP_DETECTED,
    "literal_token",
];
"#;

#[test]
fn edge_retry_rs_vocabularies_parse() {
    assert_eq!(edge_gateway_error_tokens(RETRY_RS_EXCERPT), local(&["connection_failure", "loop_detected", "literal_token"]));
    assert_eq!(edge_error_classes(RETRY_RS_EXCERPT), local(&["connection_timeout", "request_error"]));
}

#[test]
#[should_panic(expected = "unresolved token constant OBS_NEW")]
fn edge_retry_rs_refuses_an_unresolvable_token() {
    edge_gateway_error_tokens(&RETRY_RS_EXCERPT.replace("\"literal_token\",", "OBS_NEW,"));
}

/// Edge main early warning (ferrum-edge/ferrum-contracts#76): the
/// `X-Gateway-Error` tokens and `ErrorClass` labels Edge `main` actually
/// emits, from its `src/retry.rs` at the checked commit, against Anvil's
/// lookup reader and diagnostic wording. ferrum-contracts' vocabularies
/// describe the release and record main's changes only in prose
/// (`main_branch_delta.summary`), so they cannot show a value main adds.
#[test]
#[ignore = "needs ANVIL_EDGE_MAIN_RETRY_RS; run by .github/workflows/edge-main-drift.yml"]
fn edge_main_vocabulary_matches_anvils_reader() {
    let path =
        std::env::var_os("ANVIL_EDGE_MAIN_RETRY_RS").map(PathBuf::from).expect("ANVIL_EDGE_MAIN_RETRY_RS names Edge main's src/retry.rs");
    let retry_rs = std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("reading {}: {error}", path.display()));
    let tokens = edge_gateway_error_tokens(&retry_rs);
    let (missing, extra) = differences(&tokens, &local(&gateway_detail::TOKENS));
    assert!(
        missing.is_empty() && extra.is_empty(),
        "Edge main X-Gateway-Error tokens vs Anvil's reader; missing: {missing:?}; extra: {extra:?}"
    );
    let diagnostic_tokens: BTreeSet<String> = read_json(&repo_root().join("catalog/diagnostics/findings.en.json"))["findings"]
        .as_object()
        .unwrap()
        .keys()
        .filter_map(|code| code.strip_prefix("ferrum.token.").map(str::to_owned))
        .collect();
    let (missing, extra) = differences(&tokens, &diagnostic_tokens);
    assert!(missing.is_empty() && extra.is_empty(), "Edge main tokens vs ferrum.token.* wording; missing: {missing:?}; extra: {extra:?}");
    let classes = edge_error_classes(&retry_rs);
    let (missing, extra) = differences(&classes, &local(&gateway_detail::ERROR_CLASSES));
    assert!(
        missing.is_empty() && extra.is_empty(),
        "Edge main ErrorClass labels vs Anvil's reader; missing: {missing:?}; extra: {extra:?}"
    );
}
