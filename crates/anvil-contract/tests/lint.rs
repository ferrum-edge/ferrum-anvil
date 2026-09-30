//! API-standards linting across dialects, positions, rule forms and outputs.

use anvil_contract::{LintOptions, LintReport, RuleSet, Severity, Spec, lint};
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
        assert_eq!(res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], "api/orders.yaml");
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
