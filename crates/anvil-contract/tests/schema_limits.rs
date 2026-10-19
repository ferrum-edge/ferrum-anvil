//! Validation-work refusals are checked before invoking the validator on a
//! hostile instance; positive controls still enforce the accepted schemas.

use anvil_contract::model::Direction;
use anvil_contract::{RuleSet, Spec, schema};
use serde_json::{Value, json};

fn spec(schema: &Value) -> Spec {
    Spec::parse(
        &serde_json::to_vec(&json!({
            "openapi":"3.1.0", "info":{"title":"t","version":"1"}, "paths":{},
            "components":{"schemas":{"Checked":schema}}
        }))
        .unwrap(),
    )
    .unwrap()
}

fn ruleset(schema: &Value) -> Result<RuleSet, anvil_contract::RulesetError> {
    let bytes = serde_json::to_vec(&json!({"anvil_ruleset":1,"rules":{"shape":{
        "given":"info", "then":{"function":"schema","options":{"schema":schema}}
    }}}))
    .unwrap();
    RuleSet::load(&[("schema.json".into(), bytes)])
}

fn refused_work(schema: &Value) {
    let err = schema::measure_standalone(schema).unwrap_err();
    assert!(schema::too_large(&err), "{schema}: {err}");
    assert!(ruleset(schema).unwrap_err().message.contains("too large to check"));
}

#[test]
fn recursive_branching_and_nonstructural_applicators_are_refused() {
    for keyword in ["allOf", "anyOf", "oneOf"] {
        refused_work(&json!({(keyword):[
            {"properties":{"child":{"$ref":"#"}}},
            {"properties":{"child":{"$ref":"#"}}}
        ]}));
    }
    for schema in [
        json!({"if":{"properties":{"child":{"$ref":"#"}}},"then":true,"else":false}),
        json!({"properties":{"child":{"$ref":"#"}},"not":{"type":"string"}}),
        json!({"patternProperties":{"^child$":{"$ref":"#"}}}),
        json!({"items":{"$ref":"#"},"contains":true}),
        json!({"dependentSchemas":{"child":{"properties":{"child":{"$ref":"#"}}}}}),
        // Multiple recursive regions compose work even without one SCC
        // containing two back edges.
        json!({"$defs":{
            "a":{"properties":{"child":{"$ref":"#/$defs/a"},"other":{"$ref":"#/$defs/b"}}},
            "b":{"properties":{"child":{"$ref":"#/$defs/b"}}}
        },"$ref":"#/$defs/a"}),
        // Separate aliases must not deduplicate two applications.
        json!({"$defs":{
            "a":{"properties":{"child":{"$ref":"#/$defs/left"}},"patternProperties":{"^child$":{"$ref":"#/$defs/right"}}},
            "left":{"$ref":"#/$defs/a"},"right":{"$ref":"#/$defs/a"}
        },"$ref":"#/$defs/a"}),
        json!({"$defs":{
            "a":{"$ref":"#/$defs/b","properties":{"extra":{"type":"string"}}},
            "b":{"properties":{"child":{"$ref":"#/$defs/a"}}}
        },"$ref":"#/$defs/a"}),
    ] {
        refused_work(&schema);
    }
}

#[test]
fn simple_structural_recursion_and_acyclic_composition_still_validate() {
    for (schema, good, bad) in [
        (
            json!({"$id":"https://example.test/tree","type":"object","properties":{"child":{"$ref":"#"}}}),
            json!({"child":{"child":{}}}),
            json!({"child":7}),
        ),
        (
            json!({"$defs":{
            "a":{"type":"object","properties":{"children":{"type":"array","items":{"$ref":"#/$defs/b"}}}},
            "b":{"$ref":"#/$defs/a"}
        },"$ref":"#/$defs/a"}),
            json!({"children":[{"children":[]}]}),
            json!({"children":[7]}),
        ),
        (json!({"$defs":{"v":{"type":"string"}},"allOf":[{"$ref":"#/$defs/v"},{"$ref":"#/$defs/v"}]}), json!("ok"), json!(7)),
    ] {
        schema::measure_standalone(&schema).unwrap();
        ruleset(&schema).unwrap();
        let validator = jsonschema::options().with_draft(jsonschema::Draft::Draft202012).build(&schema).unwrap();
        assert!(validator.is_valid(&good));
        assert!(!validator.is_valid(&bad));
    }
}

#[test]
fn unevaluated_work_is_refused_even_without_references() {
    let mut properties = json!(true);
    let mut items = json!(false);
    for _ in 0..12 {
        properties = json!({"anyOf":[{"properties":{"child":properties}}],"unevaluatedProperties":false});
        items = json!({"unevaluatedItems":items});
    }
    for schema in [properties, items] {
        refused_work(&schema);
        let spec = spec(&schema);
        let err = schema::compile(&spec, &schema, Direction::Response).unwrap_err();
        assert!(schema::too_large(&err), "{err}");
    }
}

#[test]
fn literals_and_unknown_annotations_do_not_resolve_references_or_change_scope() {
    let schema = json!({
        "type":"object",
        "const":{"$ref":"#/x"},
        "default":{"$schema":"https://example.test/unsupported", "$dynamicRef":"#loop"},
        "x-trace":{"$id":"tracking", "$ref":"https://example.test/not-fetched", "unevaluatedItems":false}
    });
    ruleset(&schema).unwrap();
    let mut doc = json!({"openapi":"3.1.0","info":{"title":"t","version":"1"},"paths":{},
        "x":{"$ref":"https://example.test/not-fetched"}});
    doc["components"] = json!({"schemas":{"Checked":schema}});
    let spec = Spec::parse(&serde_json::to_vec(&doc).unwrap()).unwrap();
    let bundled = schema::bundle(&spec, &schema, Direction::Response).unwrap();
    assert!(bundled.get("x").is_none(), "a literal reference copied an unmeasured target");
    let validator = schema::compile(&spec, &schema, Direction::Response).unwrap();
    assert!(validator.is_valid(&json!({"$ref":"#/x"})));
    assert!(!validator.is_valid(&json!({"$ref":"other"})));
}

#[test]
fn references_into_data_make_the_target_an_active_schema() {
    for schema in [
        json!({"default":{"$id":"https://example.test/resource"},"$ref":"#/default"}),
        json!({"x-trace":{"$dynamicRef":"#loop"},"$ref":"#/x-trace"}),
    ] {
        assert!(schema::measure_standalone(&schema).is_err());
        assert!(ruleset(&schema).is_err());
    }
    refused_work(&json!({"default":{"unevaluatedItems":false},"$ref":"#/default"}));
}

#[test]
fn openapi_scope_changes_and_bundle_collisions_are_refused() {
    for schema in [
        json!({"$id":"https://example.test/scoped", "x":{
            "allOf":[{"properties":{"child":{"$ref":"#/x"}}},{"properties":{"child":{"$ref":"#/x"}}}]
        },"$ref":"#/x"}),
        json!({"$dynamicAnchor":"loop","properties":{"child":{"$dynamicRef":"#loop"}}}),
        json!({"$ref":"#"}),
        json!({"$ref":"#/allOf/0"}),
    ] {
        let doc = json!({"openapi":"3.1.0","info":{"title":"t","version":"1"},"paths":{},
            "x":true,"allOf":[true],"components":{"schemas":{"Checked":schema}}});
        let spec = Spec::parse(&serde_json::to_vec(&doc).unwrap()).unwrap();
        assert!(schema::compile(&spec, &schema, Direction::Response).is_err(), "{schema}");
    }
    // Legacy identifiers are intentionally removed during conversion.
    let schema = json!({"$id":"ignored","type":"string"});
    let doc = json!({"openapi":"3.0.3","info":{"title":"t","version":"1"},"paths":{},
        "components":{"schemas":{"Checked":schema}}});
    let spec = Spec::parse(&serde_json::to_vec(&doc).unwrap()).unwrap();
    assert!(schema::compile(&spec, &schema, Direction::Response).unwrap().is_valid(&json!("ok")));
}

#[test]
fn constraints_at_the_conversion_depth_boundary_are_enforced_or_refused() {
    let mut schema = json!({"type":"string"});
    let mut good = json!("ok");
    let mut bad = json!(7);
    for _ in 0..64 {
        schema = json!({"items":schema});
        good = json!([good]);
        bad = json!([bad]);
    }
    ruleset(&schema).unwrap();
    let document = spec(&schema);
    let validator = schema::compile(&document, &schema, Direction::Response).unwrap();
    assert!(validator.is_valid(&good));
    assert!(!validator.is_valid(&bad));
    // The first object constraint beyond conversion's depth limit must not
    // become an empty (always true) schema.
    let deep = json!({"items":schema});
    refused_work(&deep);
    let document = spec(&deep);
    let err = schema::compile(&document, &deep, Direction::Response).unwrap_err();
    assert!(schema::too_large(&err), "{err}");
    // The same physical depth in annotation data is copied intact, not
    // recursively converted or interpreted as schema keywords.
    let mut data = json!({"$id":"literal-data"});
    for _ in 0..70 {
        data = json!([data]);
    }
    ruleset(&json!({"type":"object","default":data})).unwrap();
}

#[test]
fn completed_bundles_cannot_activate_unmeasured_root_keywords() {
    let schema = json!({"$ref":"#/properties"});
    for child in [
        json!({"allOf":[
            {"properties":{"child":{"$ref":"#/properties/child"}}},
            {"properties":{"child":{"$ref":"#/properties/child"}}}
        ]}),
        json!({"unevaluatedItems":false}),
    ] {
        // `child` is an unknown annotation in the measured target at
        // /properties, but becomes a schema when copied to root properties.
        let doc = json!({"openapi":"3.1.0","info":{"title":"t","version":"1"},"paths":{},
            "properties":{"child":child},"components":{"schemas":{"Checked":schema}}});
        let document = Spec::parse(&serde_json::to_vec(&doc).unwrap()).unwrap();
        let err = schema::compile(&document, &schema, Direction::Response).unwrap_err();
        assert!(schema::too_large(&err), "{err}");
    }
    let doc = json!({"openapi":"3.1.0","info":{"title":"t","version":"1"},"paths":{},
        "properties":{"child":{"$id":"https://example.test/new-scope","type":"string"}},
        "components":{"schemas":{"Checked":schema}}});
    let document = Spec::parse(&serde_json::to_vec(&doc).unwrap()).unwrap();
    let err = schema::compile(&document, &schema, Direction::Response).unwrap_err();
    assert!(err.contains("$id"), "{err}");

    // Even a cheap copied keyword changes meaning: /properties is inert
    // OpenAPI data but would constrain the wrapper's instance at its root.
    for reference in ["#/properties", "#/%70roperties", "#/type"] {
        let chosen = json!({"$ref":reference});
        let doc = json!({"openapi":"3.1.0","info":{"title":"t","version":"1"},"paths":{},
            "properties":{"child":{"type":"string"}},"type":{"type":"string"},
            "components":{"schemas":{"Checked":chosen}}});
        let document = Spec::parse(&serde_json::to_vec(&doc).unwrap()).unwrap();
        let err = schema::compile(&document, &chosen, Direction::Response).unwrap_err();
        assert!(err.contains("bundle root") || err.contains("validation keyword"), "{err}");
    }
    let chosen = json!({"$ref":"#/components/schemas/Plain"});
    let doc = json!({"openapi":"3.1.0","info":{"title":"t","version":"1"},"paths":{},
        "components":{"schemas":{"Checked":chosen,"Plain":{"type":"string"}}}});
    let document = Spec::parse(&serde_json::to_vec(&doc).unwrap()).unwrap();
    assert!(schema::compile(&document, &chosen, Direction::Response).unwrap().is_valid(&json!("ok")));
}

#[test]
fn compiler_location_and_cartesian_work_are_bounded() {
    let long_key = "k".repeat(512 * 1024);
    let mut descendants = serde_json::Map::new();
    for i in 0..1_000 {
        descendants.insert(format!("p{i}"), json!({"type":"string"}));
    }
    refused_work(&json!({"properties":{(long_key.clone()):{"properties":descendants}}}));
    refused_work(&json!({"$id":format!("https://example.test/{long_key}"),"properties":{"x":{"type":"string"}}}));
    // A long member in literal data is copied, but is not a schema location.
    schema::measure_standalone(&json!({"const":{(long_key):1}})).unwrap();

    let properties: serde_json::Map<String, Value> = (0..1_001).map(|i| (format!("p{i}"), json!(true))).collect();
    let patterns: serde_json::Map<String, Value> = (0..1_001).map(|i| (format!("^p{i}$"), json!(true))).collect();
    refused_work(&json!({"properties":properties,"patternProperties":patterns,"additionalProperties":false}));
    let properties: serde_json::Map<String, Value> = (0..10).map(|i| (format!("p{i}"), json!(true))).collect();
    let patterns: serde_json::Map<String, Value> = (0..10).map(|i| (format!("^p{i}$"), json!(true))).collect();
    ruleset(&json!({"properties":properties,"patternProperties":patterns,"additionalProperties":false})).unwrap();

    let required: Vec<String> = (0..1_001).map(|i| format!("p{i}")).collect();
    let all_of: Vec<Value> = (0..1_001).map(|_| json!({"properties":{}})).collect();
    refused_work(&json!({"anyOf":[{"required":required,"allOf":all_of},false]}));

    let patterns: serde_json::Map<String, Value> = (0..129).map(|i| (format!("^p{i}$"), json!(true))).collect();
    refused_work(&json!({"patternProperties":patterns}));
    ruleset(&json!({"patternProperties":{"^p$":true}})).unwrap();
}

#[test]
fn nested_legacy_dependencies_cannot_multiply_metaschema_errors() {
    let mut schema = json!({"description":"x".repeat(1 << 20),"type":"invalid-type"});
    for _ in 0..33 {
        schema = json!({"dependencies":{"x":schema}});
    }
    let err = schema::measure_standalone(&schema).unwrap_err();
    assert!(schema::too_large(&err), "{err}");
    ruleset(&json!({"dependencies":{"x":{"type":"string"}}})).unwrap();
}

#[test]
fn instance_validation_and_error_collection_choose_bounded_modes() {
    use schema::CheckMode;
    let plan = schema::measure_standalone_plan(&json!({"items":{"not":{"type":"object","description":"x".repeat(512 * 1024)}}})).unwrap();
    assert_eq!(plan.mode(&json!(vec![json!({}); 128])), CheckMode::Generic);
    let plan = schema::measure_standalone_plan(&json!({"items":{"const":"x".repeat(512 * 1024)}})).unwrap();
    assert_eq!(plan.mode(&json!(vec![json!(null); 128])), CheckMode::Generic);
    let plan = schema::measure_standalone_plan(&json!({"anyOf":vec![json!({"type":"string"}); 2_000]})).unwrap();
    assert_eq!(plan.mode(&json!({"payload":"x".repeat(512 * 1024)})), CheckMode::Generic);
    let plan = schema::measure_standalone_plan(&json!({"uniqueItems":true})).unwrap();
    assert_eq!(plan.mode(&json!(vec![0; 10_000])), CheckMode::Skip);
    let plan = schema::measure_standalone_plan(&json!({"items":{"type":"string"}})).unwrap();
    assert_eq!(plan.mode(&json!([1, 2, 3])), CheckMode::Detailed);
}

#[test]
fn a_supported_root_dialect_survives_openapi_wrapping() {
    let schema = json!({"$schema":"https://json-schema.org/draft/2020-12/schema","type":"string"});
    let document = spec(&schema);
    let validator = schema::compile(&document, &schema, Direction::Response).unwrap();
    assert!(validator.is_valid(&json!("ok")));
    assert!(!validator.is_valid(&json!(7)));
}

#[test]
fn legacy_dependency_schemas_are_converted_before_internal_references_resolve() {
    let schema = json!({"type":"object","dependencies":{"trigger":{
        "$id":"https://example.test/ignored-legacy-id",
        "properties":{"child":{"$ref":"#/components/schemas/Value"}}
    }}});
    let doc = json!({"openapi":"3.0.3","info":{"title":"t","version":"1"},"paths":{},
        "components":{"schemas":{"Checked":schema,"Value":{"type":"integer"}}}});
    let spec = Spec::parse(&serde_json::to_vec(&doc).unwrap()).unwrap();
    let validator = schema::compile(&spec, &schema, Direction::Response).unwrap();
    assert!(validator.is_valid(&json!({"trigger":true,"child":1})));
    assert!(!validator.is_valid(&json!({"trigger":true,"child":"bad"})));
}

#[test]
fn cached_reference_tails_cannot_hide_longer_paths() {
    for (count, nesting, short) in [(32, 0, 1), (10, 50, 5)] {
        let mut schemas = serde_json::Map::new();
        schemas.insert("S0".into(), json!({"type":"string"}));
        for i in 1..=count {
            let mut value = json!({"$ref":format!("#/components/schemas/S{}", i - 1)});
            for _ in 0..nesting {
                value = json!({"items":value});
            }
            schemas.insert(format!("S{i}"), value);
        }
        let doc = json!({"openapi":"3.1.0","info":{"title":"t","version":"1"},"paths":{},
            "components":{"schemas":schemas}});
        let document = Spec::parse(&serde_json::to_vec(&doc).unwrap()).unwrap();
        let long = json!({"$ref":format!("#/components/schemas/S{count}")});
        let short = json!({"$ref":format!("#/components/schemas/S{short}")});
        for branches in [json!([long, short]), json!([short, long])] {
            let err = schema::compile(&document, &json!({"allOf":branches}), Direction::Response).unwrap_err();
            assert!(schema::too_large(&err) && err.contains("references too deeply"), "{err}");
        }
    }
}

#[test]
fn reference_expansion_charges_error_payload_bytes_and_scalar_members() {
    for (leaf, repetitions) in [
        (json!({"not":{"type":"object","description":"x".repeat(512 << 10)}}), 2_000),
        (json!({"enum":(0..50_000).collect::<Vec<u32>>()}), 32),
    ] {
        let refs: Vec<Value> = (0..repetitions).map(|_| json!({"$ref":"#/$defs/fail"})).collect();
        // Only measure/load the refusal. Eager error collection on the first
        // case would clone about 1 GiB before yielding its first error.
        refused_work(&json!({"$defs":{"fail":leaf},"allOf":refs}));
        let refs: Vec<Value> = (0..repetitions).map(|_| json!({"$ref":"#/components/schemas/Fail"})).collect();
        let schema = json!({"allOf":refs});
        let doc = json!({"openapi":"3.1.0","info":{"title":"t","version":"1"},"paths":{},
            "components":{"schemas":{"Checked":schema,"Fail":leaf}}});
        let document = Spec::parse(&serde_json::to_vec(&doc).unwrap()).unwrap();
        let err = schema::compile(&document, &schema, Direction::Response).unwrap_err();
        assert!(schema::too_large(&err), "{err}");
    }
    let schema = json!({"$defs":{"fail":{"not":{"type":"object","description":"x".repeat(100)}}},
        "allOf":[{"$ref":"#/$defs/fail"},{"$ref":"#/$defs/fail"}]});
    ruleset(&schema).unwrap();
    let validator = jsonschema::options().with_draft(jsonschema::Draft::Draft202012).build(&schema).unwrap();
    assert!(validator.is_valid(&json!("ok")));
    assert!(!validator.is_valid(&json!({})));
}

#[test]
fn inline_not_copies_are_charged_including_literal_payloads() {
    for mut schema in [
        json!({"type":"object","description":"x".repeat(512 << 10)}),
        json!({"type":"object","default":{"description":"x".repeat(512 << 10)}}),
        json!({"enum":(0..20_000).collect::<Vec<u32>>()}),
        json!({"type":"object","default":vec![json!({}); 2_000]}),
    ] {
        for _ in 0..64 {
            schema = json!({"not":schema});
        }
        // Refuse before compilation retains a copy of this payload for
        // each inline not validator, even though no reference is present.
        refused_work(&schema);
        let document = spec(&schema);
        let err = schema::compile(&document, &schema, Direction::Response).unwrap_err();
        assert!(schema::too_large(&err), "{err}");
    }
    // A member named not inside annotation data is never compiled and must
    // not multiply the work estimate.
    let mut data = json!({"description":"x".repeat(512 << 10)});
    for _ in 0..64 {
        data = json!({"not":data});
    }
    ruleset(&json!({"default":data})).unwrap();
    let schema = json!({"not":{"not":{"type":"string","description":"small"}}});
    ruleset(&schema).unwrap();
    let document = spec(&schema);
    let validator = schema::compile(&document, &schema, Direction::Response).unwrap();
    assert!(validator.is_valid(&json!("ok")));
    assert!(!validator.is_valid(&json!(7)));
}

#[test]
fn repeated_entries_charge_a_complete_recursive_lap() {
    for entry in ["a", "b"] {
        let refs: Vec<Value> = (0..40).map(|_| json!({"$ref":format!("#/$defs/{entry}")})).collect();
        let schema = json!({"$defs":{
            "a":{"description":"x".repeat(256 << 10),"properties":{"child":{"$ref":"#/$defs/b"}}},
            "b":{"description":"x".repeat(256 << 10),"properties":{"child":{"$ref":"#/$defs/a"}}}
        },"allOf":refs});
        // Each entry owes both halves of the cycle, even when a previous
        // entry would have cached only part of it in a depth-first walk.
        refused_work(&schema);
    }
}
