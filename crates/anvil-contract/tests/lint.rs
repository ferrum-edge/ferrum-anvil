//! API-standards linting across dialects, positions, rule forms and outputs.

use anvil_contract::{LintOptions, LintReport, RuleSet, Severity, Spec, lint};
use serde_json::json;
use std::collections::BTreeSet;

const ACME: &str = include_str!("../../../samples/api-standards/acme-api-standards.yaml");

fn fixture(name: &str) -> String {
    std::fs::read_to_string(format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

fn acme() -> RuleSet {
    RuleSet::load(&[("acme-api-standards.yaml".into(), ACME.as_bytes().to_vec())]).unwrap()
}

fn run(text: &str, rules: &RuleSet) -> LintReport {
    lint(&Spec::parse(text.as_bytes()).unwrap(), rules, &LintOptions::default())
}

fn rules_hit(r: &LintReport) -> Vec<&str> {
    r.findings.iter().map(|f| f.rule.as_str()).collect()
}

/// The same API described in Swagger 2.0 and OpenAPI 3.0, 3.1 and 3.2 breaks
/// the same company rules at the same places.
#[test]
fn one_standard_applies_to_every_dialect() {
    let rules = acme();
    let mut seen: Vec<(String, BTreeSet<(String, String)>)> = vec![];
    for f in ["orders-2.0.json", "orders-3.0.yaml", "orders-3.1.yaml", "orders-3.2.yaml"] {
        let r = run(&fixture(f), &rules);
        let set: BTreeSet<(String, String)> = r
            .findings
            .iter()
            // Rules limited to one family of dialects.
            .filter(|f| f.rule != "openapi-version-current" && f.rule != "acme-x-owner-extension")
            .map(|f| (f.rule.clone(), f.message.clone()))
            .collect();
        seen.push((f.to_string(), set));
    }
    for (name, set) in &seen[1..] {
        assert_eq!(set, &seen[0].1, "{name} differs from {}", seen[0].0);
    }
    let expected: BTreeSet<&str> = [
        "server-https",
        "operation-summary",
        "path-params-declared",
        "acme-operation-id-camel-case",
        "acme-property-camel-case",
        "acme-query-param-camel-case",
        "acme-client-errors-documented",
        "acme-problem-json",
        "acme-rate-limit-header",
    ]
    .into();
    assert_eq!(seen[0].1.iter().map(|(r, _)| r.as_str()).collect::<BTreeSet<_>>(), expected);
    // The dialect-specific rules.
    let swagger = run(&fixture("orders-2.0.json"), &rules);
    assert!(rules_hit(&swagger).contains(&"openapi-version-current"));
    assert!(!rules_hit(&swagger).contains(&"acme-x-owner-extension"));
    assert_eq!(swagger.rules_skipped, 1);
    let oas32 = run(&fixture("orders-3.2.yaml"), &rules);
    assert!(rules_hit(&oas32).contains(&"acme-x-owner-extension"));
}

#[test]
fn findings_point_at_the_line_to_edit() {
    let text = fixture("orders-3.1.yaml");
    let r = run(&text, &RuleSet::recommended());
    let line_of = |needle: &str| text.lines().position(|l| l.contains(needle)).unwrap() as u32 + 1;
    let f = r.findings.iter().find(|f| f.rule == "path-params-declared").unwrap();
    assert_eq!(f.pointer, "/paths/~1v1~1orders~1{orderId}/get");
    assert_eq!(f.line, Some(line_of("/v1/orders/{orderId}:") + 1));
    assert_eq!(f.column, Some(5));
    assert_eq!(f.message, "GET /v1/orders/{orderId} uses path parameter(s) orderId that are not declared.");
    assert!(f.how_to_fix.as_deref().unwrap().contains("in: path"));
    let s = r.findings.iter().find(|f| f.rule == "server-https").unwrap();
    assert_eq!((s.pointer.as_str(), s.line), ("/servers/0", Some(line_of("- url: http://"))));
    // JSON sources are located too.
    let json = run(&fixture("orders-2.0.json"), &RuleSet::recommended());
    let f = json.findings.iter().find(|f| f.rule == "path-params-declared").unwrap();
    let text = fixture("orders-2.0.json");
    assert_eq!(f.line, Some(text.lines().position(|l| l.contains("\"/v1/orders/{orderId}\"")).unwrap() as u32 + 2));
}

#[test]
fn a_clean_description_passes_the_recommended_rules() {
    let text = fixture("orders-3.1.yaml")
        .replace("url: http://orders", "url: https://orders")
        .replace(
            "      operationId: get_order\n",
            "      operationId: get_order\n      summary: Get an order\n      parameters:\n        - { name: orderId, in: path, required: true, description: The order., schema: { type: integer } }\n",
        );
    let r = run(&text, &RuleSet::recommended());
    assert!(r.findings.is_empty(), "{:#?}", r.findings);
    assert!(r.passes(Some(Severity::Hint)));
    assert_eq!(r.spec.operations, 2);
    assert_eq!(r.spec.title.as_deref(), Some("Orders"));
}

#[test]
fn examples_are_checked_against_their_schema_in_every_dialect() {
    for (f, from, to) in [
        ("orders-3.1.yaml", "example: [{ id: 1, total_amount: 10 }]", "example: [{ id: one, total_amount: -1 }]"),
        ("orders-3.0.yaml", "example: [{ id: 1, total_amount: 10 }]", "example: [{ total_amount: 10 }]"),
        ("orders-2.0.json", r#"[{ "id": 1, "total_amount": 10 }]"#, r#"[{ "id": "one" }]"#),
    ] {
        let text = fixture(f);
        assert!(text.contains(from), "{f}");
        let ok = run(&text, &RuleSet::recommended());
        assert!(!rules_hit(&ok).contains(&"example-valid"), "{f}: {:?}", ok.findings);
        let bad = run(&text.replace(from, to), &RuleSet::recommended());
        let e = bad.findings.iter().find(|x| x.rule == "example-valid").unwrap_or_else(|| panic!("{f}: {:?}", bad.findings));
        assert!(e.message.contains("does not match its schema"), "{}", e.message);
        assert!(e.pointer.contains("/responses/200"), "{f}: {}", e.pointer);
        let off = lint(
            &Spec::parse(text.replace(from, to).as_bytes()).unwrap(),
            &RuleSet::recommended(),
            &LintOptions { validate_examples: false, ..LintOptions::default() },
        );
        assert!(!rules_hit(&off).contains(&"example-valid"));
    }
}

#[test]
fn jsonpath_and_raw_fields_reach_the_document() {
    let rules = RuleSet::load(&[(
        "t.yaml".into(),
        br#"anvil_ruleset: 1
rules:
  no-integer-ids:
    severity: error
    given: $.components.schemas.*.properties.id
    then: { field: type, function: enumeration, options: { values: [string] } }
    message: "ids are strings, found {{value}} at {{pointer}}"
  scopes-documented:
    given: security_scheme
    then: { field: raw.flows.clientCredentials.scopes, function: length, options: { min: 2 } }
  xor-demo:
    given: info
    then: { function: xor, options: { fields: [summary, description] } }
"#
        .to_vec(),
    )])
    .unwrap();
    let r = run(&fixture("orders-3.1.yaml"), &rules);
    let ids = r.findings.iter().find(|f| f.rule == "no-integer-ids").unwrap();
    assert_eq!(ids.message, "ids are strings, found integer at /components/schemas/Order/properties/id");
    assert_eq!(ids.pointer, "/components/schemas/Order/properties/id/type");
    let scopes = r.findings.iter().find(|f| f.rule == "scopes-documented").unwrap();
    assert_eq!(scopes.pointer, "/components/securitySchemes/oauth/flows/clientCredentials/scopes");
    assert!(scopes.message.contains("the minimum is 2"), "{}", scopes.message);
    assert!(!rules_hit(&r).contains(&"xor-demo"));
}

#[test]
fn reports_are_bounded_counted_and_deterministic() {
    let text = fixture("orders-3.0.yaml");
    let spec = Spec::parse(text.as_bytes()).unwrap();
    let full = lint(&spec, &acme(), &LintOptions::default());
    assert!(full.findings.len() > 5);
    let capped = lint(&spec, &acme(), &LintOptions { max_findings: 3, ..LintOptions::default() });
    assert_eq!(capped.findings.len(), 3);
    assert_eq!(capped.dropped, full.findings.len() - 3);
    assert_eq!(capped.counts, full.counts);
    assert_eq!(capped.findings[..], full.findings[..3]);
    // Most severe first.
    assert!(full.findings.windows(2).all(|w| w[0].severity >= w[1].severity));
    assert_eq!(lint(&spec, &acme(), &LintOptions::default()), full);
    assert!(!full.passes(Some(Severity::Error)));
    assert!(full.passes(None));
}

#[test]
fn sarif_output_names_rules_and_regions() {
    let r = run(&fixture("orders-3.1.yaml"), &acme());
    let sarif = anvil_contract::sarif::to_sarif(&r, "api/orders.yaml");
    assert_eq!(sarif["version"], "2.1.0");
    let run = &sarif["runs"][0];
    let rules = run["tool"]["driver"]["rules"].as_array().unwrap();
    let results = run["results"].as_array().unwrap();
    assert_eq!(results.len(), r.findings.len());
    for res in results {
        let idx = res["ruleIndex"].as_u64().unwrap() as usize;
        assert_eq!(rules[idx]["id"], res["ruleId"]);
        assert_eq!(
            res["locations"][0]["physicalLocation"]["artifactLocation"],
            json!({"uri": "api/orders.yaml", "uriBaseId": "%SRCROOT%"})
        );
        assert!(res["locations"][0]["physicalLocation"]["region"]["startLine"].as_u64().unwrap() > 0);
    }
    let email = rules.iter().find(|r| r["id"] == "acme-problem-json").unwrap();
    assert_eq!(email["defaultConfiguration"]["level"], "error");
}

#[test]
fn shared_objects_are_reported_once_where_defined() {
    let text = r##"openapi: 3.1.0
info: { title: t, version: '1', description: d, contact: { name: n }, license: { name: MIT } }
servers: [{ url: https://x.example }]
paths:
  /a:
    get:
      operationId: a
      summary: a
      tags: [t]
      parameters: [{ $ref: '#/components/parameters/Q' }]
      responses: { '200': { description: ok } }
  /b:
    get:
      operationId: b
      summary: b
      tags: [t]
      parameters: [{ $ref: '#/components/parameters/Q' }]
      responses: { '200': { description: ok } }
tags: [{ name: t, description: t }]
components:
  parameters:
    Q: { name: q, in: query, schema: { type: string } }
"##;
    let r = run(text, &RuleSet::recommended());
    let p: Vec<_> = r.findings.iter().filter(|f| f.rule == "parameter-description").collect();
    assert_eq!(p.len(), 1, "{p:?}");
    assert_eq!(p[0].pointer, "/components/parameters/Q");
    assert_eq!(p[0].line, Some(22));
}

#[test]
fn sarif_locations_are_uris() {
    use anvil_contract::sarif::artifact_location;
    assert_eq!(artifact_location("specs/my api#1.yaml"), json!({"uri": "specs/my%20api%231.yaml", "uriBaseId": "%SRCROOT%"}));
    assert_eq!(artifact_location("/home/me/api.yaml"), json!({"uri": "file:///home/me/api.yaml"}));
    assert_eq!(artifact_location("C:\\work\\api é.yaml"), json!({"uri": "file:///C:/work/api%20%C3%A9.yaml"}));
    assert_eq!(artifact_location("-"), json!({"uri": "stdin"}));
}

#[test]
fn unresolvable_references_are_reported_not_checked() {
    let text = r##"openapi: 3.1.0
info: { title: t, version: '1', description: d, contact: { name: n }, license: { name: MIT } }
servers: [{ url: https://x.example }]
tags: [{ name: t, description: t }]
paths:
  /a:
    get:
      operationId: a
      summary: a
      description: a
      tags: [t]
      parameters:
        - $ref: 'common.yaml#/parameters/Q'
        - $ref: '#/components/parameters/Missing'
      responses:
        '200': { $ref: '#/components/responses/Gone' }
        '201': { description: ok }
"##;
    let r = run(text, &RuleSet::recommended());
    assert!(r.findings.is_empty(), "{:#?}", r.findings);
    assert_eq!(r.unresolved_ref_count, 3);
    assert!(r.unresolved_refs.contains(&"/paths/~1a/get/parameters/0".to_string()));
    let sarif = anvil_contract::sarif::to_sarif(&r, "a.yaml");
    assert!(sarif["runs"][0]["invocations"][0]["toolExecutionNotifications"][0]["message"]["text"].as_str().unwrap().contains("3 $ref"));
}

#[test]
fn wide_documents_lint_in_linear_time() {
    // 100k parameters on one operation, 20k operations, 20k tags and schemas.
    let params: Vec<serde_json::Value> =
        (0..100_000).map(|i| json!({"name": format!("p{i}"), "in": "query", "description": "d"})).collect();
    let mut paths = serde_json::Map::new();
    paths.insert("/wide".into(), json!({"get": {"operationId": "wide", "summary": "s", "tags": ["t0"], "parameters": params, "responses": {"200": {"description": "ok"}}}}));
    for i in 0..20_000 {
        paths.insert(format!("/p{i}"), json!({"get": {"operationId": format!("o{i}"), "summary": "s", "tags": [format!("t{i}")], "responses": {"200": {"description": "ok", "content": {"application/json": {"schema": {"$ref": format!("#/components/schemas/S{i}")}}}}}}}));
    }
    let tags: Vec<serde_json::Value> = (0..20_000).map(|i| json!({"name": format!("t{i}"), "description": "d"})).collect();
    let schemas: serde_json::Map<String, serde_json::Value> =
        (0..20_000).map(|i| (format!("S{i}"), json!({"type": "object", "properties": {"a": {"type": "string"}}}))).collect();
    let doc = json!({"openapi": "3.1.0", "info": {"title": "t", "version": "1", "description": "d", "contact": {"name": "n"}, "license": {"name": "MIT"}},
        "servers": [{"url": "https://x.example"}], "tags": tags, "paths": paths, "components": {"schemas": schemas}});
    let start = std::time::Instant::now();
    let r = run(&doc.to_string(), &RuleSet::recommended());
    assert!(start.elapsed() < std::time::Duration::from_secs(60), "{:?}", start.elapsed());
    assert!(
        r.findings.iter().all(|f| f.rule != "schema-unused" && f.rule != "operation-tag-defined"),
        "{:?}",
        &r.findings[..r.findings.len().min(3)]
    );
    assert_eq!(r.spec.operations, 20_001);
}

#[test]
fn inherited_parameters_are_bounded_and_shared_path_items_are_checked_per_path() {
    // One 3.2 path item with 3,000 operations inheriting 3,000 path-level
    // parameters: 9M parameter visits, past the work budget.
    let params: Vec<serde_json::Value> = (0..3_000).map(|i| json!({"name": format!("p{i}"), "in": "query", "description": "d"})).collect();
    let ops: serde_json::Map<String, serde_json::Value> = (0..3_000)
        .map(|i| (format!("X{i}"), json!({"operationId": format!("x{i}"), "responses": {"200": {"description": "ok"}}})))
        .collect();
    let doc = json!({"openapi": "3.2.0", "info": {"title": "t", "version": "1"}, "paths": {"/wide": {"parameters": params, "additionalOperations": ops}}});
    let start = std::time::Instant::now();
    let r = run(&doc.to_string(), &RuleSet::recommended());
    assert!(start.elapsed() < std::time::Duration::from_secs(60), "{:?}", start.elapsed());
    assert!(r.skipped_operations > 1_000, "{}", r.skipped_operations);

    // Two paths sharing one Path Item: each path's own template is checked.
    let text = r##"openapi: 3.1.0
info: { title: t, version: '1' }
paths:
  /a/{id}: { $ref: '#/components/pathItems/P' }
  /b/{key}: { $ref: '#/components/pathItems/P' }
components:
  pathItems:
    P:
      get:
        operationId: g
        parameters: [{ name: id, in: path, required: true, schema: { type: string } }]
        responses: { '200': { description: ok } }
"##;
    let r = run(text, &RuleSet::recommended());
    let undeclared: Vec<&str> = r.findings.iter().filter(|f| f.rule == "path-params-declared").map(|f| f.message.as_str()).collect();
    assert_eq!(undeclared, ["GET /b/{key} uses path parameter(s) key that are not declared."]);
    assert!(r.findings.iter().any(|f| f.rule == "path-params-used" && f.label == "GET /b/{key}"));
}

#[test]
fn examples_behind_an_exploding_schema_are_counted_not_checked() {
    let mut schemas = serde_json::Map::new();
    for i in 0..25 {
        let next = format!("#/components/schemas/S{}", i + 1);
        schemas.insert(format!("S{i}"), json!({"allOf": [{"$ref": next}, {"$ref": next}]}));
    }
    schemas.insert("S25".into(), json!({"type": "object"}));
    let doc = json!({"openapi": "3.1.0", "info": {"title": "t", "version": "1"}, "components": {"schemas": schemas},
        "paths": {"/a": {"get": {"responses": {"200": {"description": "ok", "content": {"application/json": {
            "schema": {"$ref": "#/components/schemas/S0"}, "examples": {"a": {"value": {}}, "b": {"value": {}}}}}}}}}}});
    let start = std::time::Instant::now();
    let r = run(&doc.to_string(), &RuleSet::recommended());
    assert!(start.elapsed() < std::time::Duration::from_secs(10));
    assert_eq!(r.examples_not_checked, 2);
}

#[test]
fn security_headers_and_shared_examples_count_against_the_budgets() {
    // 20k global security schemes inherited by 3k operations sharing one
    // response with 20k headers and an example behind a refused schema.
    let schemes: serde_json::Map<String, serde_json::Value> =
        (0..20_000).map(|i| (format!("k{i}"), json!({"type": "apiKey", "in": "header", "name": "X"}))).collect();
    let requirement: serde_json::Map<String, serde_json::Value> = (0..20_000).map(|i| (format!("k{i}"), json!([]))).collect();
    let headers: serde_json::Map<String, serde_json::Value> =
        (0..20_000).map(|i| (format!("H{i}"), json!({"schema": {"type": "string"}}))).collect();
    let mut schemas = serde_json::Map::new();
    for i in 0..25 {
        let next = format!("#/components/schemas/S{}", i + 1);
        schemas.insert(format!("S{i}"), json!({"allOf": [{"$ref": next}, {"$ref": next}]}));
    }
    schemas.insert("S25".into(), json!({"type": "object"}));
    let mut paths = serde_json::Map::new();
    for i in 0..3_000 {
        paths.insert(format!("/p{i}"), json!({"get": {"operationId": format!("o{i}"), "responses": {
            "200": {"$ref": "#/components/responses/Shared"},
            "201": {"description": "own", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/S0"}, "example": {}}}}}}}));
    }
    let doc = json!({"openapi": "3.1.0", "info": {"title": "t", "version": "1"}, "security": [requirement], "paths": paths,
        "components": {"securitySchemes": schemes, "schemas": schemas,
            "responses": {"Shared": {"description": "ok", "headers": headers, "content": {"application/json": {"schema": {"type": "object"}, "example": {}}}}}}});
    let start = std::time::Instant::now();
    let r = run(&doc.to_string(), &RuleSet::recommended());
    assert!(start.elapsed() < std::time::Duration::from_secs(60), "{:?}", start.elapsed());
    assert!(r.skipped_operations > 0, "security names and headers are charged");
    // Every example behind the refused schema is counted, with one compile.
    assert!(r.examples_not_checked > 0);
}
