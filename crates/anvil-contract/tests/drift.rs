//! Contract drift across dialects: observed traffic is routed and checked,
//! grouped into findings with suggestions, and applying the suggestions
//! resolves the drift they cover (the loop: observe, revise, check again).

use anvil_contract::drift::{DriftKind, SuggestionKind};
use anvil_contract::observe::{ObservedBody, ObservedResponse};
use anvil_contract::{DriftOptions, DriftReport, Observation, Spec, analyze, revise};
use serde_json::{Value, json};
use std::collections::BTreeSet;

fn fixture(name: &str) -> String {
    std::fs::read_to_string(format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

struct Obs(Observation);

impl Obs {
    fn new(id: &str, method: &str, url: &str) -> Obs {
        Obs(Observation {
            id: id.into(),
            at: None,
            method: method.into(),
            url: url.into(),
            operation_hint: None,
            request_content_type: None,
            request_bytes: 0,
            query: anvil_contract::observe::query_names(url),
            request_headers: vec!["x-tenant".into()],
            response: None,
            latency_ms: Some(20.0),
        })
    }
    fn json(mut self, status: u16, body: Value) -> Obs {
        let bytes = body.to_string().len() as u64;
        self.0.response = Some(ObservedResponse {
            status,
            content_type: Some("application/json".into()),
            headers: vec!["content-type".into(), "etag".into()],
            bytes: Some(bytes),
            body: ObservedBody::Json(body),
        });
        self
    }
    fn typed(mut self, status: u16, ct: &str, body: Value) -> Obs {
        self = self.json(status, body);
        self.0.response.as_mut().unwrap().content_type = Some(ct.into());
        self
    }
    fn empty(mut self, status: u16) -> Obs {
        self.0.response = Some(ObservedResponse { status, content_type: None, headers: vec![], bytes: Some(0), body: ObservedBody::Empty });
        self
    }
    fn other(mut self, status: u16, ct: &str) -> Obs {
        self.0.response = Some(ObservedResponse {
            status,
            content_type: Some(ct.into()),
            headers: vec!["etag".into()],
            bytes: Some(6),
            body: ObservedBody::Other,
        });
        self
    }
    fn latency(mut self, ms: f64) -> Obs {
        self.0.latency_ms = Some(ms);
        self
    }
    fn size(mut self, n: u64) -> Obs {
        self.0.response.as_mut().unwrap().bytes = Some(n);
        self
    }
    fn no_headers(mut self) -> Obs {
        self.0.request_headers.clear();
        if let Some(r) = self.0.response.as_mut() {
            r.headers.retain(|h| h != "etag");
        }
        self
    }
    fn body(mut self, ct: &str, n: u64) -> Obs {
        self.0.request_content_type = Some(ct.into());
        self.0.request_bytes = n;
        self
    }
}

const API: &str = "https://shop.example/api";

fn traffic() -> Vec<Observation> {
    vec![
        Obs::new("1", "GET", &format!("{API}/orders?limit=5&cursor=abc"))
            .json(200, json!([{"id": 1, "total": 10, "status": "open", "discount": 2.5}])),
        Obs::new("2", "GET", &format!("{API}/orders/7"))
            .json(200, json!({"id": 7, "total": 12.5, "status": "refunded", "note": null}))
            .latency(250.0)
            .size(3000),
        Obs::new("3", "GET", &format!("{API}/orders/8"))
            .typed(404, "application/problem+json", json!({"title": "no such order"}))
            .no_headers(),
        Obs::new("4", "GET", &format!("{API}/orders/9")).json(200, json!({"id": 9, "total": 3, "status": "open"})).no_headers(),
        Obs::new("5", "POST", &format!("{API}/orders"))
            .body("application/xml", 30)
            .json(201, json!({"id": 10, "total": 1, "status": "open"})),
        Obs::new("6", "GET", &format!("{API}/orders/10")).other(200, "text/html"),
        Obs::new("7", "GET", &format!("{API}/customers/42")).json(200, json!({"name": "Ada", "since": "2026-09-30"})),
        Obs::new("8", "PATCH", &format!("{API}/orders/3")).json(200, json!({"id": 3, "total": 1, "status": "paid"})),
        Obs::new("9", "DELETE", &format!("{API}/orders/3")).empty(204),
        Obs::new("10", "OPTIONS", &format!("{API}/orders")).empty(204),
        Obs::new("11", "GET", "https://staging.shop.example/api/orders").json(200, json!([])),
        Obs::new("12", "POST", &format!("{API}/orders")).body("application/json", 20).json(201, json!({"id": 11, "status": "open"})),
        Obs::new("13", "GET", &format!("{API}/orders")),
    ]
    .into_iter()
    .map(|o| o.0)
    .collect()
}

fn kinds(r: &DriftReport) -> BTreeSet<DriftKind> {
    r.findings.iter().map(|f| f.kind).collect()
}

fn find<'a>(r: &'a DriftReport, kind: DriftKind, needle: &str) -> &'a anvil_contract::DriftFinding {
    r.findings
        .iter()
        .find(|f| f.kind == kind && f.message.contains(needle))
        .unwrap_or_else(|| panic!("no {kind:?} with {needle:?} in {:#?}", r.findings))
}

#[test]
fn traffic_is_checked_the_same_way_in_every_dialect() {
    for f in ["shop-3.1.yaml", "shop-3.0.yaml", "shop-3.2.yaml", "shop-2.0.json"] {
        let spec = Spec::parse(fixture(f).as_bytes()).unwrap();
        let r = analyze(&spec, &traffic(), &DriftOptions::default());
        let swagger = f.contains("2.0");
        assert_eq!((r.observations, r.ignored, r.without_response), (13, 1, 1), "{f}");
        assert_eq!(r.matched, 10, "{f}: {:#?}", r.findings);

        find(&r, DriftKind::UndeclaredQueryParameter, "`cursor`");
        find(&r, DriftKind::SlowerThanDeclared, "100 ms budget in 1 of");
        find(&r, DriftKind::ResponseLargerThanDeclared, "2000-byte budget");
        find(&r, DriftKind::MissingRequiredParameter, "header parameter `X-Tenant`");
        find(&r, DriftKind::UndeclaredStatus, "GET /orders/{id} returned 404");
        find(&r, DriftKind::UndeclaredRequestContentType, "application/xml");
        find(&r, DriftKind::UndeclaredContentType, "was text/html");
        find(&r, DriftKind::UndeclaredPath, "GET /customers/{customerId}");
        find(&r, DriftKind::UndeclaredMethod, "PATCH is called on /orders/{id}");
        find(&r, DriftKind::DeprecatedOperationCalled, "DELETE /orders/{id}");
        find(&r, DriftKind::UndeclaredServer, "https://staging.shop.example");
        let schema: Vec<&str> =
            r.findings.iter().filter(|x| x.kind == DriftKind::ResponseSchemaMismatch).map(|x| x.message.as_str()).collect();
        for needle in [
            "`/total` is number, expected integer",
            "`/status` is not one of the declared values",
            "`/note` is null",
            "missing required property `total`",
        ] {
            assert!(schema.iter().any(|m| m.contains(needle)), "{f}: {needle} not in {schema:#?}");
        }
        if !swagger {
            find(&r, DriftKind::MissingResponseHeader, "`ETag`");
        }
        // No observed value leaks into a message, except the enum token in its suggestion.
        let text = serde_json::to_string(&r.findings).unwrap();
        for secret in ["no such order", "Ada", "abc"] {
            assert!(!text.contains(secret), "{f}: {secret}");
        }

        // Suggestions: additions are recommended, relaxations are not.
        let titles: Vec<(&str, SuggestionKind, bool)> = r.suggestions.iter().map(|s| (s.title.as_str(), s.kind, s.recommended)).collect();
        for (needle, kind) in [
            ("Document the 404 response of GET /orders/{id}", SuggestionKind::Addition),
            ("Document property `discount` of Order", SuggestionKind::Addition),
            ("Document query parameter `cursor`", SuggestionKind::Addition),
            ("Document GET /customers/{customerId}", SuggestionKind::Addition),
            ("Document PATCH /orders/{id}", SuggestionKind::Addition),
            ("Document text/html for the 200 response", SuggestionKind::Addition),
            ("Document the application/xml request body", SuggestionKind::Addition),
            ("Allow null at Order.note", SuggestionKind::Relaxation),
            ("Allow fractional numbers at Order.total", SuggestionKind::Relaxation),
            ("Add `refunded` to the values of Order.status", SuggestionKind::Relaxation),
            ("Make `total` optional in Order", SuggestionKind::Relaxation),
            ("Raise the latency budget of GET /orders/{id} to 250 ms", SuggestionKind::Relaxation),
        ] {
            let s = titles
                .iter()
                .find(|(t, _, _)| t.contains(needle))
                .unwrap_or_else(|| panic!("{f}: no suggestion {needle:?} in {titles:#?}"));
            assert_eq!((s.1, s.2), (kind, kind == SuggestionKind::Addition), "{f}: {needle}");
        }
        // Findings point at their own suggestions only.
        let null = r.suggestions.iter().find(|s| s.title.starts_with("Allow null")).unwrap();
        let note = r.findings.iter().find(|x| x.kind == DriftKind::ResponseSchemaMismatch && x.message.contains("`/note`")).unwrap();
        assert_eq!(note.suggestions, std::slice::from_ref(&null.id), "{f}");
        let s404 = r.suggestions.iter().find(|s| s.title.starts_with("Document the 404")).unwrap();
        assert!(find(&r, DriftKind::UndeclaredStatus, "404").suggestions.contains(&s404.id));
        // The inferred 404 schema keeps the shape only.
        assert!(s404.snippet.contains("title") && !s404.snippet.contains("no such order"), "{}", s404.snippet);
        if swagger {
            assert!(s404.ops.iter().any(|o| o.path.ends_with("/produces")), "{f}: 2.0 declares media types in produces");
        } else {
            assert!(s404.snippet.contains("application/problem+json"), "{}", s404.snippet);
        }
        // Coverage lists every operation, called or not.
        let get = r.operations.iter().find(|o| o.operation == "GET /orders/{id}").unwrap();
        assert_eq!(get.calls, 4);
        assert_eq!(get.budget.max_latency_ms, Some(100.0));
        assert_eq!(get.statuses.get("404"), Some(&1));
        assert!(
            r.undeclared.iter().any(|u| u.method == "GET" && u.path == "/customers/{customerId}" && u.examples == ["/api/customers/42"])
        );
    }
}

#[test]
fn applying_the_suggestions_resolves_the_drift_they_cover() {
    for f in ["shop-3.1.yaml", "shop-3.0.yaml", "shop-3.2.yaml", "shop-2.0.json"] {
        let spec = Spec::parse(fixture(f).as_bytes()).unwrap();
        let r = analyze(&spec, &traffic(), &DriftOptions::default());
        let all: Vec<String> = r.suggestions.iter().map(|s| s.id.clone()).collect();
        let rev = revise(&spec, &r, &all);
        assert!(rev.skipped.is_empty(), "{f}: {:?}", rev.skipped);
        // The revision parses in the original syntax, and so does its JSON Patch.
        let revised = Spec::parse(rev.text.as_bytes()).unwrap_or_else(|e| panic!("{f}: {e}\n{}", rev.text));
        assert_eq!(revised.syntax, spec.syntax);
        assert!(!rev.json_patch.is_empty());
        // Every declared-contract gap is gone; what is left is the client's or
        // the API's to fix, not the description's.
        let again = analyze(&revised, &traffic(), &DriftOptions::default());
        let mut left = kinds(&again);
        for k in [
            DriftKind::MissingRequiredParameter,
            DriftKind::MissingResponseHeader,
            DriftKind::DeprecatedOperationCalled,
            DriftKind::ResponseLargerThanDeclared,
        ] {
            left.remove(&k);
        }
        if f.contains("2.0") {
            // Swagger 2.0 has one host: another server cannot be declared.
            left.remove(&DriftKind::UndeclaredServer);
        }
        assert!(left.is_empty(), "{f}: still {left:?}\n{:#?}", again.findings);
        // The lint of the revision still loads and runs.
        let lint = anvil_contract::lint(&revised, &anvil_contract::RuleSet::recommended(), &Default::default());
        assert!(lint.spec.operations >= 6, "{f}: {}", lint.spec.operations);
    }
}

#[test]
fn only_recommended_suggestions_leave_relaxations_open() {
    let spec = Spec::parse(fixture("shop-3.1.yaml").as_bytes()).unwrap();
    let r = analyze(&spec, &traffic(), &DriftOptions::default());
    let recommended: Vec<String> = r.suggestions.iter().filter(|s| s.recommended).map(|s| s.id.clone()).collect();
    let rev = revise(&spec, &r, &recommended);
    let again = analyze(&Spec::parse(rev.text.as_bytes()).unwrap(), &traffic(), &DriftOptions::default());
    let k = kinds(&again);
    assert!(k.contains(&DriftKind::ResponseSchemaMismatch) && k.contains(&DriftKind::SlowerThanDeclared));
    assert!(!k.contains(&DriftKind::UndeclaredStatus) && !k.contains(&DriftKind::UndeclaredPath));
    // An unknown id is reported, not applied.
    let rev = revise(&spec, &r, &["nope".to_string()]);
    assert_eq!(rev.skipped, ["nope"]);
    assert_eq!(rev.json_patch, Vec::<Value>::new());
}

#[test]
fn a_description_without_budgets_gets_a_budget_suggestion() {
    let text = fixture("shop-3.1.yaml").replace("x-anvil-expectations:\n  max_latency_ms: 500\n", "");
    let spec = Spec::parse(text.as_bytes()).unwrap();
    let obs: Vec<Observation> = (0..20)
        .map(|i| Obs::new(&i.to_string(), "GET", &format!("{API}/orders")).json(200, json!([])).latency(10.0 + i as f64).0)
        .collect();
    let r = analyze(&spec, &obs, &DriftOptions::default());
    assert!(r.findings.is_empty(), "{:#?}", r.findings);
    let s = r.suggestions.iter().find(|s| s.title.starts_with("Declare a")).unwrap();
    assert_eq!(s.title, "Declare a 50 ms latency budget for GET /orders");
    assert!(!s.recommended);
    let list = r.operations.iter().find(|o| o.operation == "GET /orders").unwrap();
    assert_eq!(list.latency_ms.unwrap().p95, 28.0);
}

#[test]
fn har_captures_are_checked_too() {
    let har = json!({"log": {"version": "1.2", "entries": [
        {"startedDateTime": "2026-09-30T10:00:00Z", "time": 31,
         "request": {"method": "GET", "url": "https://shop.example/api/orders/1", "headers": [{"name": "X-Tenant", "value": "t"}]},
         "response": {"status": 200, "headers": [{"name": "ETag", "value": "x"}], "content": {"size": 40, "mimeType": "application/json", "text": "{\"id\":1,\"total\":2,\"status\":\"open\",\"extra\":true}"}}}
    ]}});
    let obs = anvil_contract::observe::from_har(har.to_string().as_bytes()).unwrap();
    let spec = Spec::parse(fixture("shop-3.1.yaml").as_bytes()).unwrap();
    let r = analyze(&spec, &obs, &DriftOptions::default());
    assert_eq!(r.matched, 1);
    assert!(r.findings.is_empty(), "additional properties are allowed: {:#?}", r.findings);
    assert!(r.suggestions.iter().any(|s| s.title == "Document property `extra` of Order"));
    assert!(r.from.is_some());
}

#[test]
fn many_operations_and_observations_stay_fast() {
    let mut paths = serde_json::Map::new();
    for i in 0..20_000 {
        paths.insert(
            format!("/r{i}/{{id}}"),
            json!({"get": {"operationId": format!("g{i}"), "responses": {"200": {"description": "ok",
            "content": {"application/json": {"schema": {"type": "object", "properties": {"a": {"type": "integer"}}}}}}}}}),
        );
    }
    let doc =
        json!({"openapi": "3.1.0", "info": {"title": "t", "version": "1"}, "servers": [{"url": "https://x.example/v1"}], "paths": paths});
    let spec = Spec::parse(doc.to_string().as_bytes()).unwrap();
    let obs: Vec<Observation> = (0..1_000)
        .map(|i| {
            let items: Vec<Value> = (0..200).map(|k| json!({"a": k, "b": format!("x{k}")})).collect();
            Obs::new(&i.to_string(), "GET", &format!("https://x.example/v1/r{}/{i}", i * 13 % 20_000))
                .json(200, json!({"a": 1.5, "list": items}))
                .0
        })
        .collect();
    let start = std::time::Instant::now();
    let r = analyze(&spec, &obs, &DriftOptions::default());
    assert!(start.elapsed() < std::time::Duration::from_secs(60), "{:?}", start.elapsed());
    assert_eq!(r.matched, 1_000);
    assert!(r.findings.iter().any(|f| f.kind == DriftKind::ResponseSchemaMismatch));
}
