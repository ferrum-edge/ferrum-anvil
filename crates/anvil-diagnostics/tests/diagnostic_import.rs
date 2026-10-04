use anvil_diagnostics::import::{ImportError, MAX_ARRAY_ITEMS, MAX_BYTES, MAX_DEPTH, MAX_OBJECT_MEMBERS, MAX_STRING_BYTES, preview};
use anvil_domain::diagnostic_import::{ImportedDiagnosticKind, ImportedDiagnosticPreview, ImportedDiagnosticTrust};
use anvil_domain::diagnostics::Confidence;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::cell::Cell;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

fn vendor() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../contracts/ferrum-contracts")
}

fn report() -> Value {
    json!({
        "schema": "ferrum.diagnostic_report", "schema_version": "1.0",
        "collection": {
            "collector": {"kind": "alloy", "name": "fixture"},
            "method": "fixture", "verification": "verified"
        }
    })
}

fn finding() -> Value {
    let bytes = std::fs::read(vendor().join("fixtures/diagnostic-finding/valid/ferrum-token-backend-error.json")).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn reported(preview: &ImportedDiagnosticPreview) -> Value {
    serde_json::from_str(&preview.reported_json).unwrap()
}

fn accepts(value: &Value) -> bool {
    preview(value.to_string().as_bytes(), &|_| Ok(())).is_ok()
}

fn files(path: &Path) -> BTreeSet<PathBuf> {
    std::fs::read_dir(path).unwrap().map(|entry| entry.unwrap().path()).filter(|path| path.is_file()).collect()
}

fn expectation_matches(error: &jsonschema::ValidationError<'_>, path: &str, keyword: &str) -> bool {
    if error.instance_path().as_str() == path && error.kind().keyword() == keyword {
        return true;
    }
    match error.kind() {
        jsonschema::error::ValidationErrorKind::AnyOf { context }
        | jsonschema::error::ValidationErrorKind::OneOfNotValid { context }
        | jsonschema::error::ValidationErrorKind::OneOfMultipleValid { context } => {
            context.iter().flatten().any(|child| expectation_matches(child, path, keyword))
        }
        _ => false,
    }
}

#[test]
fn every_canonical_fixture_passes_the_real_parser_and_independent_schema_gate() {
    let expectations: Value = serde_json::from_slice(&std::fs::read(vendor().join("fixtures/invalid-expectations.json")).unwrap()).unwrap();
    let mut tested = BTreeSet::new();
    for (contract, expected_valid, expected_invalid) in
        [("diagnostic-report", 8, 4), ("diagnostic-finding", 2, 3), ("diagnostic-ref", 4, 6)]
    {
        let schema: Value =
            serde_json::from_slice(&std::fs::read(vendor().join(format!("schemas/{contract}/v1.schema.json"))).unwrap()).unwrap();
        let validator = jsonschema::options().should_validate_formats(true).build(&schema).unwrap();
        for (group, expected_count) in [("valid", expected_valid), ("invalid", expected_invalid)] {
            let fixtures = files(&vendor().join(format!("fixtures/{contract}/{group}")));
            assert_eq!(fixtures.len(), expected_count, "fixture presence: {contract}/{group}");
            for path in fixtures {
                let bytes = std::fs::read(&path).unwrap();
                let value: Value = serde_json::from_slice(&bytes).unwrap();
                let result = preview(&bytes, &|_| Ok(()));
                assert_eq!(result.is_ok(), group == "valid", "{}: {result:?}", path.display());
                assert_eq!(validator.is_valid(&value), group == "valid", "{}", path.display());
                if group == "invalid" {
                    let name = format!("{contract}/invalid/{}", path.file_name().unwrap().to_str().unwrap());
                    let expected = &expectations[&name];
                    assert!(expected.is_object(), "missing invalid expectation: {name}");
                    let errors: Vec<_> = validator.iter_errors(&value).collect();
                    assert_eq!(errors.len(), 1, "canonical single failure: {name}");
                    assert!(
                        expectation_matches(&errors[0], expected["instance_path"].as_str().unwrap(), expected["keyword"].as_str().unwrap(),),
                        "canonical failure location/keyword changed: {name}"
                    );
                    if let Some(top) = expected["top_keyword"].as_str() {
                        assert_eq!(errors[0].kind().keyword(), top, "top keyword: {name}");
                    }
                    tested.insert(name);
                }
            }
        }
    }
    let expected: BTreeSet<_> = expectations.as_object().unwrap().keys().filter(|name| name.starts_with("diagnostic-")).cloned().collect();
    assert_eq!(tested, expected, "all diagnostic invalid expectations must be exercised");
}

#[test]
fn known_fields_reject_null_without_losing_schema_permitted_null_or_unknown_members() {
    let mut value = report();
    for field in ["report_id", "generated_at", "subject", "observations", "findings", "extensions"] {
        value[field] = Value::Null;
        assert!(!accepts(&value), "accepted null {field}");
        value.as_object_mut().unwrap().remove(field);
    }
    value["schema_version"] = json!("1.9999");
    value["collection"]["method"] = json!("future_collector_method");
    value["collection"]["verification"] = json!("future_verification");
    value["x-future"] = json!({"authenticated": true, "nested": [null, "claim"]});
    let result = preview(value.to_string().as_bytes(), &|_| Ok(())).unwrap();
    assert_eq!(reported(&result), value);
    assert_eq!(result.trust, ImportedDiagnosticTrust::Unverified);
    assert_eq!(result.confidence, Confidence::Unknown);

    let mut value = finding();
    value["evidence"][0]["attempt"] = Value::Null;
    value["x-additional-field"] = json!("uninterpreted");
    value["schema_version"] = json!("unrelated-claim");
    value["report"] = json!({"unknown": "uninterpreted"});
    assert!(accepts(&value)); // The canonical schema allows additional properties.
    value["confidence"] = json!(0.99);
    assert!(!accepts(&value));
    value["confidence"] = json!("future_confidence");
    assert!(!accepts(&value)); // Standalone finding has a closed vocabulary.
    let mut value = report();
    let mut claim = finding();
    claim["confidence"] = json!("future_confidence");
    claim["evidence"][0]["source"] = json!("gateway_telemetry");
    value["findings"] = json!([claim]);
    assert!(accepts(&value)); // Report findings deliberately have open string vocabularies.
    value["findings"][0]["confidence"] = json!(0.99);
    assert!(!accepts(&value));
}

#[test]
fn strict_attribute_values_and_collection_limits_are_enforced() {
    let mut value = report();
    let observation = json!({
        "id": "one", "producer": {"kind": "alloy", "name": "fixture"},
        "kind": "measurement", "name": "client.total_time", "availability": "measured",
        "value": 1, "unit": "ms", "scope": {"leg": "client_to_gateway"}, "trust": "verified"
    });
    value["observations"] = json!([observation.clone()]);
    assert!(accepts(&value));
    value["observations"][0]["attributes"] = json!({"unknown": true});
    assert!(!accepts(&value));
    value["observations"][0]["attributes"] = json!({"unknown": null});
    assert!(!accepts(&value));
    let attributes: serde_json::Map<String, Value> = (0..33).map(|index| (format!("key{index}"), json!("value"))).collect();
    value["observations"][0]["attributes"] = json!(attributes);
    assert!(!accepts(&value));
    value["observations"] = json!(vec![observation; MAX_ARRAY_ITEMS + 1]);
    assert!(!accepts(&value));
    value["observations"] = json!([]);
    value["findings"] = json!(vec![finding(); 1001]);
    assert!(!accepts(&value));
}

#[test]
fn duplicate_ids_dangling_references_and_invalid_times_do_not_become_facts() {
    let mut value = report();
    value["generated_at"] = json!("2026-10-04T13:00:00Z");
    assert!(accepts(&value));
    for invalid in ["yesterday", "2026-10-04 13:00:00Z", "2026-13-04T13:00:00Z"] {
        value["generated_at"] = json!(invalid);
        assert!(!accepts(&value));
    }
    value.as_object_mut().unwrap().remove("generated_at");
    let mut claim = finding();
    claim["supporting_observations"] = json!(["missing"]);
    value["findings"] = json!([claim]);
    assert!(!accepts(&value));
    value["observations"] = json!([{
        "id": "missing", "producer": {"kind": "edge", "name": "fixture"},
        "kind": "event", "name": "event", "availability": "measured",
        "scope": {"leg": "gateway"}, "trust": "verified"
    }]);
    assert!(accepts(&value));
    let duplicate = value["observations"][0].clone();
    value["observations"].as_array_mut().unwrap().push(duplicate);
    assert!(!accepts(&value));
    value["observations"].as_array_mut().unwrap().pop();
    value["observations"][0]["span"] = json!({
        "trace_id": "00000000000000000000000000000000", "span_id": "0000000000000000"
    });
    assert!(!accepts(&value));
    value["observations"][0].as_object_mut().unwrap().remove("span");
    value["observations"][0]["interval"] = json!({"start_unix_nano": 2, "end_unix_nano": 1});
    assert!(!accepts(&value));
}

#[test]
fn lexical_and_decoded_bounds_apply_before_redaction_or_presentation() {
    let calls = Cell::new(0);
    let redact = |_: &mut Value| {
        calls.set(calls.get() + 1);
        Ok(())
    };
    for bytes in [
        vec![b' '; MAX_BYTES + 1],
        format!("{}0{}", "[".repeat(MAX_DEPTH + 1), "]".repeat(MAX_DEPTH + 1)).into_bytes(),
        vec![0xff],
        br#"{"schema":null,"schema": "ferrum.diagnostic_report"}"#.to_vec(),
        br#"{"schema":null,"\u0073chema":"ferrum.diagnostic_report"}"#.to_vec(),
    ] {
        assert!(preview(&bytes, &redact).is_err());
    }
    let mut value = report();
    value["extensions"] = json!({"note": "é".repeat(MAX_STRING_BYTES / 2 + 1)});
    assert_eq!(preview(value.to_string().as_bytes(), &redact).unwrap_err(), ImportError::Limit);
    value["extensions"] = json!({"note": "é".repeat(MAX_STRING_BYTES / 2)});
    assert!(preview(value.to_string().as_bytes(), &redact).is_ok());
    assert_eq!(calls.get(), 1, "invalid input never reaches redaction/presentation");
    let object: serde_json::Map<String, Value> = (0..=MAX_OBJECT_MEMBERS).map(|index| (format!("key{index}"), json!(index))).collect();
    value["extensions"] = json!(object);
    assert!(!accepts(&value));
    let oversized = format!("{{\"schema\":\"{}\"}}", "\\u0061".repeat(MAX_STRING_BYTES + 1));
    assert!(preview(oversized.as_bytes(), &redact).is_err());
}

#[test]
fn forged_authenticated_flags_and_trusted_sources_remain_unknown_offline_claims() {
    let mut value = report();
    value["authenticated"] = json!(true);
    value["trusted"] = json!(true);
    let mut claim = finding();
    claim["confidence"] = json!("confirmed");
    claim["evidence"][0]["source"] = json!("gateway_detail");
    value["findings"] = json!([claim]);
    let result = preview(value.to_string().as_bytes(), &|_| Ok(())).unwrap();
    assert_eq!(result.confidence, Confidence::Unknown);
    assert_eq!(result.trust, ImportedDiagnosticTrust::Unverified);
    assert_eq!(reported(&result), value);
    assert_eq!(result.finding_count, 1);
    assert_eq!(result.observation_count, 0);
}

#[test]
fn aggregate_depth_and_unicode_caps_include_unknown_extensions() {
    let mut value = report();
    let mut nested = json!("quotes and braces in a string: [ { \\\" } ]");
    for _ in 0..MAX_DEPTH - 2 {
        nested = json!([nested]);
    }
    value["extensions"] = json!({"nested": nested});
    assert!(accepts(&value));
    let nested = value["extensions"]["nested"].clone();
    value["extensions"]["nested"] = json!([nested]);
    assert!(!accepts(&value));
    value["extensions"] = json!({"text": "🦀".repeat(MAX_STRING_BYTES / 4)});
    assert!(accepts(&value));
    value["extensions"]["text"] = json!("🦀".repeat(MAX_STRING_BYTES / 4 + 1));
    assert!(!accepts(&value));
    value["extensions"] = json!({"wide": vec![vec![0; 5000]; 41]});
    assert_eq!(preview(value.to_string().as_bytes(), &|_| Ok(())).unwrap_err(), ImportError::Limit);
    assert!(preview(br#"{"x":"\ud800"}"#, &|_| Ok(())).is_err());
    assert!(preview(b"{} trailing", &|_| Ok(())).is_err());
}

#[test]
fn alloy_cli_envelope_is_distinct_from_the_report_contract() {
    let value = json!({"report": report(), "warnings": [], "claimed_verification": null});
    let result = preview(value.to_string().as_bytes(), &|_| Ok(())).unwrap();
    assert_eq!(result.kind, ImportedDiagnosticKind::AlloyCli);
    assert_eq!(reported(&result), value);
    for patch in [
        json!({"path": "/tmp/file"}),
        json!({"warnings": null}),
        json!({"warnings": [{"path": "", "message": "claim", "authenticated": true}]}),
        json!({"claimed_verification": true}),
        json!({"report": null}),
    ] {
        let mut invalid = value.clone();
        invalid.as_object_mut().unwrap().extend(patch.as_object().unwrap().clone());
        assert!(!accepts(&invalid));
    }
}

#[test]
fn immutable_real_alloy_exporter_golden_preserves_every_reported_fact() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/alloy");
    let pin = std::fs::read_to_string(root.join("PIN")).unwrap();
    assert!(pin.contains("commit 0c260f5379939ff46d681666bfbcd65b8518b08d\n"));
    assert!(pin.contains("run 37208769030\nartifact 11305688717\n"));
    let mut pinned = BTreeSet::new();
    for line in pin.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        if let ["sha256", expected, file] = fields.as_slice() {
            let bytes = std::fs::read(root.join(file)).unwrap();
            let hash = Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect::<String>();
            assert_eq!(hash, *expected, "Alloy immutable fixture changed: {file}");
            pinned.insert(root.join(file));
        }
    }
    let mut actual = files(&root);
    actual.remove(&root.join("PIN"));
    assert_eq!(pinned, actual, "no unpinned producer fixtures");
    assert_eq!(pinned.len(), 3);

    let alloy_schema: Value = serde_json::from_slice(&std::fs::read(root.join("diagnostic-report.v1.schema.json")).unwrap()).unwrap();
    let mut canonical: Value =
        serde_json::from_slice(&std::fs::read(vendor().join("schemas/diagnostic-report/v1.schema.json")).unwrap()).unwrap();
    canonical.as_object_mut().unwrap().remove("x-contract");
    canonical["$id"] = alloy_schema["$id"].clone();
    assert_eq!(canonical, alloy_schema, "exact producer/shared schema parity");

    let bytes = std::fs::read(root.join("diagnosis-edge-0.9.10.json")).unwrap();
    let golden: Value = serde_json::from_slice(&bytes).unwrap();
    let result = preview(&bytes, &|_| Ok(())).unwrap();
    assert_eq!(reported(&result), golden);
    assert_eq!(result.confidence, Confidence::Unknown);
    assert_eq!(result.finding_count, 2);
    assert!(result.observation_count > 0);
    assert_eq!(golden["findings"][0]["code"], "alloy.service.operation_dominates");
    assert_eq!(golden["findings"][0]["evidence"][0]["source"], "service_telemetry");

    // The immutable CLI serializes the same report inside this exact stdout
    // envelope. The report bytes above are real hosted exporter output; this
    // envelope is a source-derived transport test, not a claimed CLI capture.
    let cli = json!({"claimed_verification": "unverified", "warnings": [], "report": golden});
    let result = preview(cli.to_string().as_bytes(), &|_| Ok(())).unwrap();
    assert_eq!(result.kind, ImportedDiagnosticKind::AlloyCli);
    assert_eq!(reported(&result), cli);
}
