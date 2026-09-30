//! Adversarial descriptions and texts never panic; work stays bounded.

use anvil_contract::locate::Locator;
use anvil_contract::{LintOptions, RuleSet, Spec, lint};
use anvil_import::Syntax;
use proptest::prelude::*;
use serde_json::{Value, json};

fn rules() -> RuleSet {
    let acme = include_str!("../../../samples/api-standards/acme-api-standards.yaml");
    RuleSet::load(&[("acme.yaml".into(), acme.as_bytes().to_vec())]).unwrap()
}

fn lint_value(v: &Value, rules: &RuleSet) {
    if let Ok(spec) = Spec::parse(v.to_string().as_bytes()) {
        let r = lint(&spec, rules, &LintOptions::default());
        assert!(r.findings.len() <= LintOptions::default().max_findings);
    }
}

#[test]
fn malformed_structure_is_linted_without_panics() {
    let rules = rules();
    for doc in [
        json!({"openapi": "3.1.0", "paths": []}),
        json!({"openapi": "3.1.0", "info": 5, "paths": {"/a": {"get": 5, "post": {"requestBody": 7, "responses": []}}}}),
        json!({"openapi": "3.0.0", "paths": {"/a/{b}": {"$ref": "#/paths/~1a~1{b}"}}}),
        json!({"openapi": "3.2.0", "paths": {"/a": {"additionalOperations": {"LINK": 3, "x": {"responses": {"200": {"$ref": "#/nope"}}}}}}}),
        json!({"swagger": "2.0", "paths": {"/a": {"get": {"parameters": [1, null, {"in": "body"}, {"$ref": "#/x"}], "security": 3}}}, "definitions": []}),
        json!({"openapi": "3.1.0", "components": {"schemas": {"A": {"$ref": "#/components/schemas/A"}, "B": {"properties": {"x": {"properties": {"y": 1}}}}}}}),
        json!({"openapi": "3.1.0", "tags": [1, {"name": 2}], "servers": [3, {"url": 4}], "security": [5]}),
    ] {
        lint_value(&doc, &rules);
    }
}

#[test]
fn deep_property_nesting_is_bounded() {
    let mut s = json!({"type": "string"});
    for _ in 0..50 {
        s = json!({"type": "object", "properties": {"a_b": s}});
    }
    let doc = json!({"openapi": "3.1.0", "info": {"title": "t", "version": "1"}, "paths": {}, "components": {"schemas": {"Deep": s}}});
    let spec = Spec::parse(doc.to_string().as_bytes()).unwrap();
    let r = lint(&spec, &rules(), &LintOptions::default());
    let deep = r.findings.iter().filter(|f| f.rule == "acme-property-camel-case").count();
    assert!(deep > 0 && deep <= 30, "{deep}");
}

fn json_value(depth: u32) -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<i64>().prop_map(|n| json!(n)),
        prop_oneof![
            Just("string".to_string()),
            Just("object".to_string()),
            Just("#/components/schemas/S".to_string()),
            Just("#/definitions/S".to_string()),
            Just("#/paths".to_string()),
            Just("query".to_string()),
            Just("path".to_string()),
            Just("body".to_string()),
            Just("application/json".to_string()),
            "[a-z{}$#/_-]{0,8}".prop_map(|s| s),
            "[\\PC\\n\\u{202e}\\u{85}]{0,6}".prop_map(|s| s),
        ]
        .prop_map(Value::String),
    ];
    leaf.prop_recursive(depth, 64, 6, |inner| {
        let key = prop_oneof![
            Just("$ref"),
            Just("type"),
            Just("properties"),
            Just("items"),
            Just("allOf"),
            Just("required"),
            Just("in"),
            Just("name"),
            Just("schema"),
            Just("content"),
            Just("responses"),
            Just("parameters"),
            Just("requestBody"),
            Just("examples"),
            Just("example"),
            Just("nullable"),
            Just("security"),
            Just("tags"),
            Just("get"),
            Just("200"),
        ];
        prop_oneof![
            proptest::collection::vec(inner.clone(), 0..4).prop_map(Value::Array),
            proptest::collection::vec((key, inner), 0..5)
                .prop_map(|kv| Value::Object(kv.into_iter().map(|(k, v)| (k.to_string(), v)).collect())),
        ]
    })
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, .. ProptestConfig::default() })]

    #[test]
    fn structural_fuzz_never_panics(v in json_value(4)) {
        let rules = rules();
        for doc in [
            json!({"openapi": "3.1.0", "info": {"title": "f", "version": "1"}, "paths": {"/x/{id}": {"get": v.clone(), "post": {"requestBody": {"content": {"application/json": {"schema": v.clone(), "example": v.clone()}}}, "parameters": [v.clone()], "responses": {"200": v.clone()}}}}, "components": {"schemas": {"S": v.clone()}}}),
            json!({"openapi": "3.0.3", "info": v.clone(), "paths": {"/x": {"get": {"responses": {"400": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/S"}, "example": v.clone()}}}}}}}, "components": {"schemas": {"S": v.clone()}}}),
            json!({"swagger": "2.0", "paths": {"/x/{id}": {"get": {"parameters": [v.clone()], "security": v.clone(), "responses": {"200": {"schema": v.clone(), "examples": {"application/json": v.clone()}}}}}}, "definitions": {"S": v.clone()}}),
        ] {
            lint_value(&doc, &rules);
        }
    }

    #[test]
    fn locator_never_panics(text in "[ -~\n\t{}\\[\\]:,'\"#|>\\u{e9}\\u{4e2d}\\u{1f600}-]{0,400}") {
        let l = Locator::new(&text, Syntax::Yaml);
        let _ = l.position("/a/0/b");
        let l = Locator::new(&text, Syntax::Json);
        let _ = l.position("/a/0/b");
    }
}
