//! Malformed and adversarial input never panics; every import is bounded.

mod common;

use anvil_import::{ImportOptions, detect, import};
use common::*;
use proptest::prelude::*;

const FIXTURES: &[&str] = &[
    "openapi/petstore-3.0.yaml",
    "openapi/accounts-3.1.json",
    "openapi/search-3.2.yaml",
    "openapi/files-swagger-2.0.json",
    "wsdl/stockquote.wsdl",
    "postman/shop.postman_collection.json",
    "postman/staging.postman_environment.json",
    "insomnia/insomnia-v4.json",
    "insomnia/insomnia-v5.yaml",
    "har/session.har",
    "curl/create-order.sh",
    "curl/literal-data.sh",
    "curl/literal-form-string.sh",
];

fn small() -> ImportOptions {
    ImportOptions { max_nodes: 50_000, max_sample_nodes: 2_000, max_ref_expansions: 5_000, ..opts() }
}

#[test]
fn every_fixture_imports_and_detects() {
    for f in FIXTURES {
        let d = detect(&fixture(f));
        assert!(d.dialect.is_supported(), "{f}: {d:?}");
        let r = run(f, &opts());
        assert_eq!(r.source.dialect, d.dialect);
        assert_eq!(r.report.counts.requests, r.requests.len());
        assert_eq!(r.source.sha256.len(), 64);
        // Every request carries an import link whose hash matches its spec.
        for q in &r.requests {
            let src = q.spec.source.as_ref().expect("import link");
            assert_eq!(src.generated_hash, anvil_import::spec_hash(&q.spec), "{f}: {}", q.name);
            assert_eq!(q.workspace_id, r.workspace.meta.id);
            if let Some(fid) = q.folder_id {
                assert!(r.folders.iter().any(|x| x.meta.id == fid), "{f}: orphan request {}", q.name);
            }
        }
        // Parents precede children; no ancestry cycles.
        for (i, folder) in r.folders.iter().enumerate() {
            if let Some(p) = folder.parent_id {
                assert!(r.folders[..i].iter().any(|x| x.meta.id == p), "{f}: folder {} before its parent", folder.name);
            }
        }
        // Scripts are never enabled or trusted.
        assert!(r.report.scripts.iter().all(|s| !s.enabled && !s.trusted));
        // External references always require approval.
        assert!(r.report.external_refs.iter().all(|e| e.requires_approval));
    }
}

#[test]
fn garbage_is_an_error_not_a_panic() {
    for input in [
        &b""[..],
        b"   ",
        b"\xff\xfe\x00\x00",
        b"\xef\xbb\xbf{",
        b"{\"openapi\": 3}",
        b"{\"openapi\": \"3.0.0\", \"paths\": []}",
        b"{\"openapi\": \"3.1.0\", \"paths\": {\"/a\": {\"get\": 5, \"post\": {\"requestBody\": 7}}}}",
        b"{\"swagger\": \"2.0\", \"paths\": {\"/a\": {\"get\": {\"parameters\": [1, null, {\"in\": \"body\"}]}}}}",
        b"{\"info\": {\"_postman_id\": \"x\"}, \"item\": {}}",
        b"{\"info\": {\"_postman_id\": \"x\"}, \"item\": [{\"request\": 5}, {\"item\": [7]}]}",
        b"{\"_type\": \"export\", \"resources\": [{\"_type\": \"request\"}, 5]}",
        b"{\"log\": {\"entries\": [{}, {\"request\": {\"url\": 5}}]}}",
        b"type: collection.insomnia.rest/5.0\ncollection: 5\n",
        b"<definitions xmlns=\"http://schemas.xmlsoap.org/wsdl/\"><binding name=\"b\"><operation/></binding></definitions>",
        b"<not-closed",
        b"curl",
        b"curl -H",
        b"curl -u",
        b"curl $'\\x",
        b"- a\n- b\n",
        b"key: [unclosed",
    ] {
        let _ = detect(input);
        let _ = import(input, &small());
    }
}

#[test]
fn deeply_nested_json_is_refused() {
    let deep = format!("{{\"openapi\": \"3.0.0\", \"x\": {}{}}}", "[".repeat(10_000), "]".repeat(10_000));
    assert!(import(deep.as_bytes(), &opts()).is_err());
}

#[test]
fn yaml_alias_bombs_are_bounded() {
    let mut y = String::from("openapi: 3.0.0\ninfo: {title: t, version: '1'}\npaths: {}\na: &a [x,x,x,x,x,x,x,x,x,x]\n");
    let mut prev = "a".to_string();
    for i in 0..12 {
        let n = format!("b{i}");
        y.push_str(&format!("{n}: &{n} [*{prev},*{prev},*{prev},*{prev},*{prev},*{prev},*{prev},*{prev},*{prev},*{prev}]\n"));
        prev = n;
    }
    assert!(import(y.as_bytes(), &opts()).is_err());
}

#[test]
fn self_referencing_schemas_terminate() {
    let doc = serde_json::json!({
        "openapi": "3.1.0", "info": {"title": "t", "version": "1"},
        "paths": {"/a": {"post": {"operationId": "a", "requestBody": {"content": {
            "application/json": {"schema": {"$ref": "#/components/schemas/A"}},
        }}, "responses": {}}}},
        "components": {"schemas": {
            "A": {"type": "object", "required": ["b", "self"], "properties": {"b": {"$ref": "#/components/schemas/B"}, "self": {"$ref": "#/components/schemas/A"}}},
            "B": {"allOf": [{"$ref": "#/components/schemas/A"}, {"$ref": "#/components/schemas/B"}], "oneOf": [{"$ref": "#/components/schemas/B"}]},
            "Loop": {"$ref": "#/components/schemas/Loop"}
        }}
    });
    let r = import(doc.to_string().as_bytes(), &opts()).unwrap();
    assert!(has(&r, "recursive_schema"));
}

#[test]
fn extreme_numeric_constraints_do_not_overflow() {
    let schemas = [
        serde_json::json!({"type": "number", "minimum": -1e308, "maximum": 1e308, "multipleOf": 1e-300}),
        serde_json::json!({"type": "number", "exclusiveMinimum": -1e308, "exclusiveMaximum": 1e308}),
        serde_json::json!({"type": "integer", "minimum": -9.3e18, "maximum": 9.3e18, "multipleOf": 1e300}),
        serde_json::json!({"type": "integer", "minimum": -1e40, "maximum": 1e40, "multipleOf": 3}),
        serde_json::json!({"type": "integer", "minimum": 9223372036854775807u64, "exclusiveMinimum": true}),
        serde_json::json!({"type": "string", "minLength": 18446744073709551615u64}),
        serde_json::json!({"type": "array", "minItems": 18446744073709551615u64, "items": {"type": "integer"}}),
    ];
    for s in schemas {
        let doc = serde_json::json!({
            "openapi": "3.1.0", "info": {"title": "t", "version": "1"},
            "paths": {"/a": {"post": {"operationId": "a", "requestBody": {"content": {"application/json": {"schema": s}}}, "responses": {}}}}
        });
        let _ = import(doc.to_string().as_bytes(), &opts()).unwrap();
    }
}

/// Flip, drop and insert bytes in real fixtures.
fn mutate(bytes: &[u8], ops: &[(u8, usize, u8)]) -> Vec<u8> {
    let mut out = bytes.to_vec();
    for (kind, pos, val) in ops {
        if out.is_empty() {
            out.push(*val);
            continue;
        }
        let p = pos % out.len();
        match kind % 4 {
            0 => out[p] = *val,
            1 => {
                out.remove(p);
            }
            2 => out.insert(p, *val),
            _ => out.truncate(p),
        }
    }
    out
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, .. ProptestConfig::default() })]

    #[test]
    fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        let _ = detect(&bytes);
        let _ = import(&bytes, &small());
    }

    #[test]
    fn mutated_fixtures_never_panic(
        idx in 0..FIXTURES.len(),
        ops in proptest::collection::vec((any::<u8>(), any::<usize>(), any::<u8>()), 1..8),
    ) {
        let bytes = mutate(&fixture(FIXTURES[idx]), &ops);
        let _ = detect(&bytes);
        if let Ok(r) = import(&bytes, &small()) {
            prop_assert_eq!(r.report.counts.requests, r.requests.len());
            prop_assert!(r.report.scripts.iter().all(|s| !s.enabled));
        }
    }

    #[test]
    fn structural_json_fuzz_never_panics(v in json_value(4)) {
        for wrapper in [
            serde_json::json!({"openapi": "3.1.0", "info": {"title": "f", "version": "1"}, "paths": {"/x": {"post": {"requestBody": {"content": {"application/json": {"schema": v.clone()}}}, "parameters": [v.clone()], "responses": {}}}}, "components": {"schemas": {"S": v.clone()}}}),
            serde_json::json!({"swagger": "2.0", "paths": {"/x/{id}": {"get": {"parameters": [v.clone()], "security": v.clone()}}}, "definitions": {"S": v.clone()}}),
            serde_json::json!({"info": {"_postman_id": "p"}, "item": [{"name": "r", "request": v.clone(), "event": v.clone()}], "auth": v.clone()}),
            serde_json::json!({"_type": "export", "resources": [{"_id": "wrk", "_type": "workspace"}, {"_id": "r", "_type": "request", "parentId": "wrk", "body": v.clone(), "authentication": v.clone(), "url": v.clone()}]}),
            serde_json::json!({"log": {"entries": [{"request": {"method": "POST", "url": "https://x/y", "postData": v.clone(), "headers": v.clone()}}]}}),
        ] {
            let _ = import(wrapper.to_string().as_bytes(), &small());
        }
    }
}

fn json_value(depth: u32) -> impl Strategy<Value = serde_json::Value> {
    let leaf = prop_oneof![
        Just(serde_json::Value::Null),
        any::<bool>().prop_map(serde_json::Value::Bool),
        any::<i64>().prop_map(|n| serde_json::json!(n)),
        prop_oneof![
            Just("string".to_string()),
            Just("object".to_string()),
            Just("array".to_string()),
            Just("integer".to_string()),
            Just("#/components/schemas/S".to_string()),
            Just("#/definitions/S".to_string()),
            Just("body".to_string()),
            Just("query".to_string()),
            Just("path".to_string()),
            Just("form".to_string()),
            Just("{{x}}".to_string()),
            Just("multipart/form-data".to_string()),
            Just("application/json".to_string()),
            "[a-z{}$#/]{0,8}".prop_map(|s| s),
        ]
        .prop_map(serde_json::Value::String),
    ];
    leaf.prop_recursive(depth, 64, 6, |inner| {
        let key = prop_oneof![
            Just("$ref"),
            Just("type"),
            Just("properties"),
            Just("items"),
            Just("allOf"),
            Just("oneOf"),
            Just("anyOf"),
            Just("required"),
            Just("in"),
            Just("name"),
            Just("schema"),
            Just("style"),
            Just("explode"),
            Just("minimum"),
            Just("maximum"),
            Just("minItems"),
            Just("maxLength"),
            Just("enum"),
            Just("mode"),
            Just("raw"),
            Just("url"),
            Just("mimeType"),
            Just("text"),
            Just("params"),
            Just("header"),
            Just("type"),
            Just("format"),
            Just("example"),
            Just("default"),
            Just("additionalProperties"),
            Just("prefixItems"),
        ];
        prop_oneof![
            proptest::collection::vec(inner.clone(), 0..4).prop_map(serde_json::Value::Array),
            proptest::collection::vec((key, inner), 0..5)
                .prop_map(|kv| { serde_json::Value::Object(kv.into_iter().map(|(k, v)| (k.to_string(), v)).collect()) }),
        ]
    })
}
