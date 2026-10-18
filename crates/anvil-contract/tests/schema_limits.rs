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
