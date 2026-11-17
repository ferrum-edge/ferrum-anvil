mod common;

use anvil_domain::auth::{AuthConfig, KeyLocation, OAuthGrant};
use anvil_domain::request::Body;
use anvil_domain::secret::SensitiveValue;
use anvil_import::{Dialect, ImportError, detect};
use common::*;

const V4: &str = "insomnia/insomnia-v4.json";
const V5: &str = "insomnia/insomnia-v5.yaml";

#[test]
fn detects_both_formats() {
    assert_eq!(detect(&fixture(V4)).dialect, Dialect::InsomniaV4);
    let d5 = detect(&fixture(V5));
    assert_eq!(d5.dialect, Dialect::InsomniaV5);
    assert_eq!(d5.syntax, anvil_import::Syntax::Yaml);
}

#[test]
fn v4_groups_environments_and_templates() {
    let r = run(V4, &opts());
    assert_eq!(r.workspace.name, "Weather");
    let fc = r.folders.iter().find(|f| f.name == "Forecasts").unwrap();
    let hist = r.folders.iter().find(|f| f.name == "History").unwrap();
    assert_eq!(hist.parent_id, Some(fc.meta.id));
    assert!(fc.variables.iter().any(|v| v.name == "units"));
    assert!(matches!(&fc.auth, AuthConfig::Bearer { token, .. } if token == &SensitiveValue::template("{{apiToken}}")));
    // Base environment → workspace variables (nested data flattened); secrets redacted.
    let names: Vec<&str> = r.workspace.variables.iter().map(|v| v.name.as_str()).collect();
    assert_eq!(names, vec!["baseUrl", "api.version"]);
    assert!(r.report.required_variables.iter().any(|v| v.name == "apiToken" && v.secret));
    // Sub-environments → environments.
    let envs: Vec<&str> = r.environments.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(envs, vec!["Dev", "Prod"]);
    assert!(has(&r, "private_environment"));

    let daily = &req(&r, "insomnia:req_daily").spec;
    assert_eq!(daily.url, "{{baseUrl}}/{{api.version}}/forecast/daily");
    assert_eq!(header(daily, "X-Request-Id").unwrap().value, "{{$uuid}}");
    assert_eq!(header(daily, "X-Sent").unwrap().value, "{{$isoTimestamp}}");
    assert!(!param(daily, "days").unwrap().enabled);
    assert_eq!(daily.settings.redirects.map(|p| p.follow), Some(false));
    assert_eq!(daily.auth, AuthConfig::Inherit);

    let hist_req = &req(&r, "insomnia:req_hist").spec;
    assert_eq!(hist_req.url, "{{baseUrl}}/history/OSL-1");
    assert!(matches!(&hist_req.auth, AuthConfig::ApiKey { location: KeyLocation::Header, name, .. } if name == "X-Key"));
    assert!(has_at(&r, "template_tag", "/resources/7/body/text"));
    match &hist_req.body {
        Body::Json { text } => assert!(text.contains("{{$timestampMs}}")),
        other => panic!("{other:?}"),
    }
}

#[test]
fn v4_bodies_auth_and_unsupported_resources() {
    let r = run(V4, &opts());
    match &req(&r, "insomnia:req_gql").spec.body {
        Body::GraphQl { query, variables, .. } => {
            assert_eq!(query, "{ stations { id } }");
            assert_eq!(variables, r#"{"n":1}"#);
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(req(&r, "insomnia:req_gql").spec.auth, AuthConfig::None);
    assert!(has(&r, "auth_unsupported"));
    match &req(&r, "insomnia:req_login").spec.body {
        Body::FormUrlEncoded { fields } => assert_eq!(fields[1].value, "{{password}}"),
        other => panic!("{other:?}"),
    }
    match &req(&r, "insomnia:req_upload").spec.auth {
        AuthConfig::OAuth2 { config } => {
            assert_eq!(config.grant, OAuthGrant::AuthorizationCodePkce);
            assert_eq!(config.client_id, "weather-app");
        }
        other => panic!("{other:?}"),
    }
    assert!(r.report.redactions.iter().any(|x| x.pointer.ends_with("authentication/accessToken")));
    for code in ["cookie_jar", "embedded_spec", "insomnia_resource"] {
        assert!(has(&r, code), "{code}");
    }
    // Scripts (pre-request and unit test) retained, disabled.
    assert_eq!(r.report.scripts.len(), 2);
    assert!(r.report.scripts.iter().any(|s| s.event == "unit_test" && !s.enabled && !s.trusted));
    // Sorting by metaSortKey within the workspace root.
    let top: Vec<&str> = r.requests.iter().filter(|q| q.folder_id.is_none()).map(|q| q.name.as_str()).collect();
    assert_eq!(top, vec!["Login", "GraphQL", "Upload"]);
    assert!(!serde_json::to_string(&(&r.workspace, &r.requests)).unwrap().contains("tok_live_123"));
}

#[test]
fn v5_collection() {
    let r = run(V5, &opts());
    assert_eq!(r.workspace.name, "Tasks");
    assert_eq!(r.workspace.description, "Insomnia v5 fixture");
    let folder = r.folders.iter().find(|f| f.name == "Tasks").unwrap();
    match &folder.auth {
        AuthConfig::Basic { username, password } => {
            assert_eq!(username, "{{user}}");
            assert_eq!(password, &SensitiveValue::template("{{password}}"));
        }
        other => panic!("{other:?}"),
    }
    // Ordered by sortKey.
    let in_folder: Vec<&str> = r.requests.iter().filter(|q| q.folder_id == Some(folder.meta.id)).map(|q| q.name.as_str()).collect();
    assert_eq!(in_folder, vec!["List tasks", "Create task"]);
    let list = &req(&r, "insomnia:req_list").spec;
    assert_eq!(header(list, "Authorization").unwrap().value, "{{Authorization}}", "literal bearer header redacted");
    assert_eq!(list.settings.cookies, Some(false));
    assert_eq!(list.settings.redirects.map(|p| p.follow), Some(true));
    assert!(matches!(req(&r, "insomnia:req_create").spec.body, Body::Xml { .. }));
    assert!(has_at(&r, "encode_url_off", "/collection/1/settings"));
    assert!(has(&r, "cookie_jar"));
    assert_eq!(r.environments[0].name, "Local");
    assert!(r.workspace.variables.iter().any(|v| v.name == "user"));
    assert!(!r.workspace.variables.iter().any(|v| v.name == "password"), "literal password dropped");
    assert_eq!(r.report.scripts.len(), 2);
}

#[test]
fn deterministic() {
    assert_eq!(run(V4, &opts()), run(V4, &opts()));
    assert_eq!(run(V5, &opts()), run(V5, &opts()));
}

fn v4_request(mut request: serde_json::Value) -> anvil_import::ImportResult {
    request["_id"] = "req_1".into();
    request["_type"] = "request".into();
    request["parentId"] = "wrk_1".into();
    request["name"] = "R".into();
    request["method"] = "POST".into();
    let doc = serde_json::json!({
        "_type": "export",
        "__export_format": 4,
        "resources": [{ "_id": "wrk_1", "_type": "workspace", "parentId": null, "name": "W", "scope": "collection" }, request],
    });
    anvil_import::import(doc.to_string().as_bytes(), &opts()).unwrap()
}

fn v5_request(mut request: serde_json::Value) -> anvil_import::ImportResult {
    request["name"] = "R".into();
    request["meta"] = serde_json::json!({ "id": "req_1" });
    request["method"] = "POST".into();
    let doc = serde_json::json!({ "type": "collection.insomnia.rest/5.0", "name": "W", "collection": [request] });
    anvil_import::import(doc.to_string().as_bytes(), &opts()).unwrap()
}

fn content_type(r: &anvil_import::ImportResult) -> Option<&str> {
    header(&r.requests[0].spec, "Content-Type").map(|h| h.value.as_str())
}

#[test]
fn declared_body_media_type_is_kept() {
    for (mime, text, json) in [
        ("application/vnd.api+json", "{}", true),
        ("application/json; charset=utf-8", "{}", true),
        ("text/xml; charset=utf-8", "<root/>", false),
        ("text/xml", "<root/>", false),
        ("application/atom+xml", "<feed/>", false),
    ] {
        let body = serde_json::json!({ "url": "https://example.test/x", "headers": [], "body": { "mimeType": mime, "text": text } });
        for r in [v4_request(body.clone()), v5_request(body)] {
            let s = &r.requests[0].spec;
            assert_eq!(matches!(s.body, Body::Json { .. }), json, "{mime}: {:?}", s.body);
            assert_eq!(matches!(s.body, Body::Xml { .. }), !json, "{mime}: {:?}", s.body);
            assert_eq!(content_type(&r), Some(mime), "{mime}");
        }
    }
    // Canonical types stay inferred from the body variant (no header).
    for (mime, text) in [("application/json", "{}"), ("application/xml", "<root/>")] {
        let r = v4_request(serde_json::json!({ "url": "https://example.test/x", "body": { "mimeType": mime, "text": text } }));
        assert_eq!(content_type(&r), None, "{mime}");
    }
    // An explicit header keeps precedence and is not duplicated.
    let r = v4_request(serde_json::json!({
        "url": "https://example.test/x",
        "headers": [{ "name": "Content-Type", "value": "application/problem+json" }],
        "body": { "mimeType": "application/vnd.api+json", "text": "{}" },
    }));
    let cts: Vec<&str> =
        r.requests[0].spec.headers.iter().filter(|h| h.name.eq_ignore_ascii_case("content-type")).map(|h| h.value.as_str()).collect();
    assert_eq!(cts, vec!["application/problem+json"]);
}

fn url_with(params: serde_json::Value, url: &str) -> (String, String) {
    let request = serde_json::json!({ "url": url, "pathParameters": params });
    (v4_request(request.clone()).requests[0].spec.url.clone(), v5_request(request).requests[0].spec.url.clone())
}

#[test]
fn path_parameters_match_whole_segments_and_are_encoded() {
    let first = serde_json::json!({ "name": "id", "value": "first" });
    let second = serde_json::json!({ "name": "id2", "value": "second" });
    for params in [serde_json::json!([first.clone(), second.clone()]), serde_json::json!([second, first])] {
        let (v4, v5) = url_with(params, "https://example.test/:id/:id2");
        assert_eq!(v4, "https://example.test/first/second");
        assert_eq!(v5, v4);
    }
    // Reserved characters stay data.
    let (v4, v5) = url_with(serde_json::json!([{ "name": "id", "value": "a/b?admin=true#x" }]), "https://example.test/users/:id");
    assert_eq!(v4, "https://example.test/users/a%2Fb%3Fadmin%3Dtrue%23x");
    assert_eq!(v5, v4);
    let (v4, _) = url_with(serde_json::json!([{ "name": "n", "value": "é ok-_.!~*'()" }]), "https://example.test/:n");
    assert_eq!(v4, "https://example.test/%C3%A9%20ok-_.!~*'()");
    // Repeated segments; the query, fragment, host/port and partial matches
    // are left alone; undeclared segments stay literal.
    let (v4, _) = url_with(
        serde_json::json!([{ "name": "id", "value": "7" }, { "name": "q", "value": "nope" }]),
        "http://host:8080/a/:id/b/:id/:idx/c:id/:other?x=:id&q=:q#:id",
    );
    assert_eq!(v4, "http://host:8080/a/7/b/7/:idx/c:id/:other?x=:id&q=:q#:id");
    // Variable references are kept as references; literal parts around them
    // are encoded. An empty value becomes a required variable.
    let (v4, _) = url_with(
        serde_json::json!([{ "name": "id", "value": "{{ _.userId }}/x" }, { "name": "rev", "value": "" }]),
        "{{ _.baseUrl }}/users/:id/:rev",
    );
    assert_eq!(v4, "{{baseUrl}}/users/{{userId}}%2Fx/{{rev}}");
    let r = v4_request(serde_json::json!({ "url": "https://example.test/:rev", "pathParameters": [{ "name": "rev", "value": "" }] }));
    assert!(r.report.required_variables.iter().any(|v| v.name == "rev"));
}

fn v4_export(resources: serde_json::Value) -> Vec<u8> {
    serde_json::json!({ "_type": "export", "__export_format": 4, "resources": resources }).to_string().into_bytes()
}

#[test]
fn v4_duplicate_resource_ids_are_refused() {
    // A repeated group id would import the group's requests under both groups.
    let repeated = v4_export(serde_json::json!([
        { "_id": "wrk", "_type": "workspace", "name": "W" },
        { "_id": "fld", "_type": "request_group", "parentId": "wrk", "name": "A" },
        { "_id": "fld", "_type": "request_group", "parentId": "wrk", "name": "B" },
        { "_id": "req", "_type": "request", "parentId": "fld", "name": "R", "method": "GET", "url": "https://example.com" },
    ]));
    // Groups claiming the workspace's id are their own parents: every level
    // would repeat both subtrees.
    let cyclic = v4_export(serde_json::json!([
        { "_id": "wrk", "_type": "workspace", "name": "W" },
        { "_id": "wrk", "_type": "request_group", "parentId": "wrk", "name": "A" },
        { "_id": "wrk", "_type": "request_group", "parentId": "wrk", "name": "B" },
    ]));
    for (doc, at) in [(repeated, "/resources/2/_id"), (cyclic, "/resources/1/_id")] {
        match anvil_import::import(&doc, &opts()) {
            Err(ImportError::Invalid { dialect: Dialect::InsomniaV4, pointer, .. }) => assert_eq!(pointer, at),
            other => panic!("expected a duplicate-id error at {at}, got {:?}", other.map(|r| r.requests.len())),
        }
    }
}

#[test]
fn v4_duplicate_ids_of_other_resources_skip_the_later_copy() {
    let doc = v4_export(serde_json::json!([
        { "_id": "wrk", "_type": "workspace", "name": "W" },
        { "_id": "req", "_type": "request", "parentId": "wrk", "name": "R1", "method": "GET", "url": "https://example.com/1" },
        { "_id": "req", "_type": "request", "parentId": "wrk", "name": "R2", "method": "GET", "url": "https://example.com/2" },
    ]));
    let r = anvil_import::import(&doc, &opts()).unwrap();
    assert_eq!(r.requests.len(), 1);
    assert_eq!(r.requests[0].name, "R1");
    assert!(has_at(&r, "duplicate_resource_id", "/resources/2"));
    assert!(!has(&r, "orphan_resource"));
}

#[test]
fn v4_base_environments_without_ids_do_not_adopt_parentless_resources() {
    // Every base environment without an id would otherwise list all
    // parentless resources as its sub-environments.
    let doc = v4_export(serde_json::json!([
        { "_id": "wrk", "_type": "workspace", "name": "W" },
        { "_type": "environment", "parentId": "wrk", "name": "E0", "data": {} },
        { "_type": "environment", "parentId": "wrk", "name": "E1", "data": {} },
        { "_type": "environment", "parentId": "wrk", "name": "E2", "data": {} },
        { "_id": "r1", "_type": "request", "name": "R1", "method": "GET", "url": "https://example.com/1" },
        { "_id": "r2", "_type": "request", "name": "R2", "method": "GET", "url": "https://example.com/2" },
    ]));
    let r = anvil_import::import(&doc, &opts()).unwrap();
    let envs: Vec<&str> = r.environments.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(envs, vec!["E1", "E2"]);
    assert!(r.requests.is_empty());
    assert!(has_at(&r, "orphan_resource", "/resources/4") && has_at(&r, "orphan_resource", "/resources/5"));
}

#[test]
fn v4_workspaces_without_ids_have_no_children() {
    let doc = v4_export(serde_json::json!([
        { "_type": "workspace", "name": "W1" },
        { "_type": "workspace", "name": "W2" },
        { "_id": "fld", "_type": "request_group", "name": "G" },
        { "_id": "r1", "_type": "request", "name": "R1", "method": "GET", "url": "https://example.com/1" },
    ]));
    let r = anvil_import::import(&doc, &opts()).unwrap();
    assert!(r.requests.is_empty());
    assert!(!r.folders.iter().any(|f| f.name == "G"));
    assert!(has_at(&r, "orphan_resource", "/resources/2") && has_at(&r, "orphan_resource", "/resources/3"));
}

#[test]
fn v4_groups_without_ids_do_not_adopt_parentless_resources() {
    // Resources without a parent share the empty parent key; a group without
    // an id must not walk them (each would walk the others again).
    let doc = v4_export(serde_json::json!([
        { "_id": "wrk", "_type": "workspace", "name": "W" },
        { "_type": "request_group", "parentId": "wrk", "name": "A" },
        { "_type": "request_group", "name": "B" },
        { "_type": "request_group", "name": "C" },
        { "_id": "req", "_type": "request", "name": "R", "method": "GET", "url": "https://example.com" },
    ]));
    let r = anvil_import::import(&doc, &opts()).unwrap();
    let names: Vec<&str> = r.folders.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(names, vec!["A"]);
    assert!(r.requests.is_empty());
    assert!(has_at(&r, "orphan_resource", "/resources/4"));
}

#[test]
fn v4_sibling_and_nested_groups_still_import() {
    let doc = v4_export(serde_json::json!([
        { "_id": "wrk", "_type": "workspace", "name": "W" },
        { "_id": "fld_a", "_type": "request_group", "parentId": "wrk", "name": "A" },
        { "_id": "fld_b", "_type": "request_group", "parentId": "wrk", "name": "B" },
        { "_id": "fld_c", "_type": "request_group", "parentId": "fld_a", "name": "C" },
        { "_id": "req_1", "_type": "request", "parentId": "fld_c", "name": "R1", "method": "GET", "url": "https://example.com/1" },
        { "_id": "req_2", "_type": "request", "parentId": "fld_b", "name": "R2", "method": "GET", "url": "https://example.com/2" },
    ]));
    let r = anvil_import::import(&doc, &opts()).unwrap();
    let folder = |name: &str| r.folders.iter().find(|f| f.name == name).unwrap_or_else(|| panic!("no folder {name}"));
    assert_eq!(folder("C").parent_id, Some(folder("A").meta.id));
    assert_eq!(req(&r, "insomnia:req_1").folder_id, Some(folder("C").meta.id));
    assert_eq!(req(&r, "insomnia:req_2").folder_id, Some(folder("B").meta.id));
    assert_eq!(r.requests.len(), 2);
    assert!(!has(&r, "orphan_resource"));
}

#[test]
fn raw_json_bodies_and_url_queries_are_redacted() {
    for r in [
        v4_request(serde_json::json!({
            "url": "https://example.test/x?flag&api_key=placeholder-secret",
            "body": { "mimeType": "application/json", "text": r#"{"user":"u","password":"placeholder-secret"}"# },
        })),
        v5_request(serde_json::json!({
            "url": "https://example.test/x?flag&api_key=placeholder-secret",
            "body": { "mimeType": "application/json", "text": r#"{"user":"u","password":"placeholder-secret"}"# },
        })),
    ] {
        let s = &r.requests[0].spec;
        assert_eq!(json_body(s)["password"], "{{password}}");
        assert_eq!(s.url, "https://example.test/x?flag&api_key={{api_key}}");
        assert!(!serde_json::to_string(&r.requests).unwrap().contains("placeholder-secret"));
        assert_eq!(r.report.redactions.len(), 2);
    }
}

#[test]
fn graphql_payloads_are_parsed_under_the_node_budget() {
    let variables = format!("{{\"ids\":[{}]}}", vec!["0"; 200].join(","));
    let text = format!(r#"{{"query":"{{ a }}","variables":{variables}}}"#);
    let request = serde_json::json!({ "url": "https://example.test/g", "body": { "mimeType": "application/graphql", "text": text } });
    let mut request = request;
    request["_id"] = "req_1".into();
    request["_type"] = "request".into();
    request["parentId"] = "wrk_1".into();
    request["name"] = "R".into();
    request["method"] = "POST".into();
    let doc = serde_json::json!({
        "_type": "export",
        "__export_format": 4,
        "resources": [{ "_id": "wrk_1", "_type": "workspace", "parentId": null, "name": "W", "scope": "collection" }, request],
    });
    let o = anvil_import::ImportOptions { max_nodes: 64, ..opts() };
    let r = anvil_import::import(doc.to_string().as_bytes(), &o).unwrap();
    // The envelope is kept as the JSON it is (not re-wrapped as a query).
    match &r.requests[0].spec.body {
        Body::Raw { text: kept, content_type } => {
            assert_eq!(kept, &text);
            assert_eq!(content_type.as_deref(), Some("application/json"));
        }
        other => panic!("{other:?}"),
    }
    assert!(has_at(&r, "body_not_scanned", "/resources/1/body/text"));
    // Within the budget the payload is split as before.
    let r = v4_request(serde_json::json!({
        "url": "https://example.test/g",
        "body": { "mimeType": "application/graphql", "text": r#"{"query":"{ a }","variables":{"n":1}}"# },
    }));
    match &r.requests[0].spec.body {
        Body::GraphQl { query, variables, .. } => {
            assert_eq!(query, "{ a }");
            assert_eq!(variables, r#"{"n":1}"#);
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn graphql_variables_and_numeric_credentials_are_redacted() {
    let gql = r#"{"query":"mutation { login }","variables":{"user":"u","password":"placeholder-secret","pin":123456}}"#;
    for r in [
        v4_request(serde_json::json!({ "url": "https://example.test/g", "body": { "mimeType": "application/graphql", "text": gql } })),
        v5_request(serde_json::json!({ "url": "https://example.test/g", "body": { "mimeType": "application/graphql", "text": gql } })),
    ] {
        match &r.requests[0].spec.body {
            Body::GraphQl { variables, .. } => {
                // The number is a placeholder again once the user supplies it.
                let v = substituted(variables, &[("pin", "123456")]);
                assert_eq!(v["password"], "{{password}}");
                assert_eq!(v["pin"], 123456);
                assert_eq!(v["user"], "u");
            }
            other => panic!("{other:?}"),
        }
        let all = serde_json::to_string(&r.requests).unwrap();
        assert!(!all.contains("placeholder-secret") && !all.contains("123456"), "{all}");
    }
    // Counts under a `token` name are not credentials.
    let r = v4_request(serde_json::json!({
        "url": "https://example.test/x",
        "body": { "mimeType": "application/json", "text": r#"{"max_tokens":100,"otp":654321}"# },
    }));
    let Body::Json { text } = &r.requests[0].spec.body else { panic!("{:?}", r.requests[0].spec.body) };
    assert!(!text.contains("654321"), "{text}");
    let body = substituted(text, &[("otp", "654321")]);
    assert_eq!(body["max_tokens"], 100);
    assert_eq!(body["otp"], 654321);
}

#[test]
fn a_repeated_credential_member_does_not_keep_its_earlier_value() {
    let r = v4_request(serde_json::json!({
        "url": "https://example.test/x",
        "body": { "mimeType": "application/json", "text": r#"{"password":"placeholder-secret","password":"{{password}}"}"# },
    }));
    assert!(!serde_json::to_string(&r.requests).unwrap().contains("placeholder-secret"));
    assert!(has(&r, "json_duplicate_member"));
    assert_eq!(json_body(&r.requests[0].spec)["password"], "{{password}}");
}

#[test]
fn a_repeated_ordinary_member_does_not_keep_an_earlier_nested_credential() {
    let r = v4_request(serde_json::json!({
        "url": "https://example.test/x",
        "body": { "mimeType": "application/json", "text": r#"{"login":{"password":"placeholder-secret"},"login":{}}"# },
    }));
    assert!(!serde_json::to_string(&r.requests).unwrap().contains("placeholder-secret"));
    assert!(has(&r, "json_duplicate_member"));
}

#[test]
fn graphql_json_without_a_query_string_is_sanitized_not_copied_into_the_query() {
    for text in [
        r#"{"variables":{"password":"placeholder-secret"}}"#,
        r#"{"query":null,"variables":{"password":"placeholder-secret"}}"#,
        r#"{"query":7,"variables":{"password":"placeholder-secret"}}"#,
    ] {
        let r =
            v4_request(serde_json::json!({ "url": "https://example.test/g", "body": { "mimeType": "application/graphql", "text": text } }));
        let all = serde_json::to_string(&r.requests).unwrap();
        assert!(!all.contains("placeholder-secret"), "{text}: {all}");
        assert!(matches!(r.requests[0].spec.body, Body::Raw { .. }), "{text}");
        assert!(has(&r, "graphql_envelope_without_query"), "{text}");
    }
}

#[test]
fn a_bare_graphql_query_stays_a_query_when_the_budget_is_spent() {
    // The first request's JSON body spends the embedded-document budget.
    // An array of 63 items is 64 nodes: the whole budget.
    let big = format!("[{}]", vec!["0"; 63].join(","));
    let doc = serde_json::json!({
        "_type": "export",
        "__export_format": 4,
        "resources": [
            { "_id": "wrk_1", "_type": "workspace", "parentId": null, "name": "W", "scope": "collection" },
            { "_id": "req_1", "_type": "request", "parentId": "wrk_1", "name": "A", "method": "POST", "url": "https://example.test/a",
              "body": { "mimeType": "application/json", "text": big } },
            { "_id": "req_2", "_type": "request", "parentId": "wrk_1", "name": "B", "method": "POST", "url": "https://example.test/g",
              "body": { "mimeType": "application/graphql", "text": "{ a }" } },
        ],
    });
    let o = anvil_import::ImportOptions { max_nodes: 64, ..opts() };
    let r = anvil_import::import(doc.to_string().as_bytes(), &o).unwrap();
    match &req(&r, "insomnia:req_2").spec.body {
        Body::GraphQl { query, .. } => assert_eq!(query, "{ a }"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn graphql_json_that_cannot_be_parsed_is_kept_as_raw_json_with_a_warning() {
    let deep = format!("{{\"query\":\"q\",\"variables\":{}{}}}", "[".repeat(150), "]".repeat(150));
    for text in [r#"{"query":"q","variables":{"password":"placeholder-secret",}}"#.to_string(), deep] {
        let r =
            v4_request(serde_json::json!({ "url": "https://example.test/g", "body": { "mimeType": "application/graphql", "text": text } }));
        match &r.requests[0].spec.body {
            Body::Raw { content_type, .. } => assert_eq!(content_type.as_deref(), Some("application/json")),
            other => panic!("{other:?}"),
        }
        assert!(has_at(&r, "body_not_scanned", "/resources/1/body/text"));
    }
    // A shorthand query is still a query.
    let r = v4_request(
        serde_json::json!({ "url": "https://example.test/g", "body": { "mimeType": "application/graphql", "text": "{ a { b } }" } }),
    );
    assert!(matches!(&r.requests[0].spec.body, Body::GraphQl { query, .. } if query == "{ a { b } }"));
}

#[test]
fn unscannable_bodies_are_flagged() {
    let r = v4_request(serde_json::json!({
        "url": "https://example.test/x",
        "body": { "mimeType": "application/xml", "text": "<login><password>placeholder-secret</password></login>" },
    }));
    assert!(has_at(&r, "body_not_scanned", "/resources/1/body"));
    let r = v4_request(serde_json::json!({
        "url": "https://example.test/x",
        "body": { "mimeType": "application/x-www-form-urlencoded", "text": "flag&password=placeholder-secret" },
    }));
    assert!(has_at(&r, "body_not_scanned", "/resources/1/body"));
}

fn v4_with(request: serde_json::Value, env: serde_json::Value, o: &anvil_import::ImportOptions) -> anvil_import::ImportResult {
    let mut request = request;
    for (k, v) in [("_id", "req_1"), ("_type", "request"), ("parentId", "wrk_1"), ("name", "R"), ("method", "GET")] {
        request[k] = v.into();
    }
    let doc = v4_export(serde_json::json!([
        { "_id": "wrk_1", "_type": "workspace", "parentId": null, "name": "W", "scope": "collection" },
        { "_id": "env_base", "_type": "environment", "parentId": "wrk_1", "name": "Base", "data": env },
        request,
    ]));
    anvil_import::import(&doc, o).unwrap()
}

fn v5_with(request: serde_json::Value, env: serde_json::Value, o: &anvil_import::ImportOptions) -> anvil_import::ImportResult {
    let mut request = request;
    request["name"] = "R".into();
    request["meta"] = serde_json::json!({ "id": "req_1" });
    request["method"] = "GET".into();
    let doc = serde_json::json!({
        "type": "collection.insomnia.rest/5.0", "name": "W",
        "environments": { "name": "Base", "data": env },
        "collection": [request],
    });
    anvil_import::import(doc.to_string().as_bytes(), o).unwrap()
}

fn both(request: serde_json::Value, env: serde_json::Value, o: &anvil_import::ImportOptions) -> [anvil_import::ImportResult; 2] {
    [v4_with(request.clone(), env.clone(), o), v5_with(request, env, o)]
}

fn template_text(v: &SensitiveValue) -> String {
    match v {
        SensitiveValue::Template { value } => value.clone(),
        SensitiveValue::Secret { .. } => panic!("expected a template value"),
    }
}

fn keep() -> anvil_import::ImportOptions {
    anvil_import::ImportOptions { include_credentials: true, ..opts() }
}

/// Insomnia keeps a parameter's `%XX` escapes and encodes everything else
/// when it sends it, so parameters are stored decoded: the engine's one
/// encoding then sends `%3A`, not `%253A`, and `+` as `%2B`, as Insomnia
/// does (#563).
#[test]
fn parameters_are_stored_decoded() {
    let request = serde_json::json!({ "url": "https://example.test/cb", "parameters": [
        { "name": "redirect_uri", "value": "https%3A%2F%2Fapp.example.com%2Fdone" },
        { "name": "q", "value": "a+b" },
        { "name": "pct", "value": "50%" },
        { "name": "n", "value": "caf%C3%A9" },
    ]});
    for r in both(request, serde_json::json!({}), &opts()) {
        let s = &r.requests[0].spec;
        assert_eq!(s.url, "https://example.test/cb");
        let values: Vec<&str> = s.params.iter().map(|p| p.value.as_str()).collect();
        assert_eq!(values, ["https://app.example.com/done", "a+b", "50%", "caf\u{e9}"]);
        assert!(!has(&r, "query_value_converted") && !has(&r, "query_param_not_decoded"));
    }
}

/// Every parameter stays a parameter, encoded by the engine after any
/// `{{reference}}` resolves (review sol F4). An escape that is not UTF-8, or
/// escaped braces that would decode to a reference (sol F5), are kept as
/// written and reported, never U+FFFD or a live reference (#563).
#[test]
fn parameters_without_a_decoded_form_are_kept_as_written() {
    let request = serde_json::json!({ "url": "https://example.test/x?keep=1#frag", "parameters": [
        { "name": "n", "value": "caf%E9" },
        { "name": "api_key", "value": "placeholder-secret" },
        { "name": "sp", "value": "a b&c+d" },
        { "name": "ref", "value": "{{ _.region }}" },
        { "name": "t", "value": "%7B%7Bid%7D%7D" },
    ]});
    for r in both(request, serde_json::json!({}), &opts()) {
        let s = &r.requests[0].spec;
        assert_eq!(s.url, "https://example.test/x?keep=1#frag", "nothing moves into the URL");
        let values: Vec<(&str, &str)> = s.params.iter().map(|p| (p.name.as_str(), p.value.as_str())).collect();
        assert_eq!(
            values,
            [("n", "caf%E9"), ("api_key", "{{api_key}}"), ("sp", "a b&c+d"), ("ref", "{{region}}"), ("t", "%7B%7Bid%7D%7D")]
        );
        assert!(has_at(&r, "query_param_not_decoded", "parameters/0") && has_at(&r, "query_param_not_decoded", "parameters/4"));
        assert!(!has_at(&r, "query_param_not_decoded", "parameters/2"));
        let text = serde_json::to_string(&r.requests).unwrap();
        assert!(!text.contains("placeholder-secret") && !text.contains('\u{fffd}'), "a literal or U+FFFD was stored");
    }
}

/// GHSA-c236-7r9g-c9p2: URL userinfo becomes Basic auth with a
/// `{{password}}` placeholder, and the URL loses it.
#[test]
fn url_userinfo_becomes_basic_auth_and_its_password_is_redacted() {
    let request = serde_json::json!({ "url": "https://admin:insomniaPw-literal@api.example.com/v1/status" });
    for r in both(request.clone(), serde_json::json!({}), &opts()) {
        let s = &r.requests[0].spec;
        assert_eq!(s.url, "https://api.example.com/v1/status");
        assert!(
            matches!(&s.auth, AuthConfig::Basic { username, password } if username == "admin" && password == &SensitiveValue::template("{{password}}")),
            "expected Basic auth with a {{{{password}}}} placeholder"
        );
        assert!(!serde_json::to_string(&r.requests).unwrap().contains("insomniaPw-literal"));
        assert_eq!(r.report.redactions.len(), 1);
    }
    for r in both(request, serde_json::json!({}), &keep()) {
        let s = &r.requests[0].spec;
        assert_eq!(s.url, "https://api.example.com/v1/status");
        assert!(matches!(&s.auth, AuthConfig::Basic { password, .. } if password == &SensitiveValue::template("insomniaPw-literal")));
    }
}

/// GHSA-c236-7r9g-c9p2: a credential-named member of an environment array
/// is redacted, as the same member of a nested object is.
#[test]
fn credential_members_of_environment_arrays_are_redacted() {
    let env = serde_json::json!({
        "accounts": [{ "name": "a", "api_key": "envArrayKey-literal" }, { "name": "b", "password": "" }],
        "nested": { "api_key": "envNestedKey-literal" },
        "hosts": ["a.example", "b.example"],
    });
    let request = serde_json::json!({ "url": "https://example.test/x" });
    for r in both(request.clone(), env.clone(), &opts()) {
        let var = |n: &str| r.workspace.variables.iter().find(|v| v.name == n).map(|v| template_text(&v.value));
        let accounts = var("accounts").expect("accounts variable");
        assert!(!accounts.contains("envArrayKey-literal"), "the array member's literal stayed");
        assert!(accounts.contains("{{api_key}}"), "the array member has no placeholder");
        assert_eq!(var("hosts").as_deref(), Some(r#"["a.example","b.example"]"#));
        assert_eq!(var("nested.api_key"), None, "a secret variable's literal is dropped");
        assert!(r.report.redactions.iter().any(|x| x.pointer.contains("accounts")));
        assert!(r.report.required_variables.iter().any(|v| v.name == "api_key" && v.secret));
    }
    for r in both(request, env, &keep()) {
        let accounts = r.workspace.variables.iter().find(|v| v.name == "accounts").unwrap();
        assert!(template_text(&accounts.value).contains("envArrayKey-literal"));
    }
}

/// GHSA-c236-7r9g-c9p2: a credential-named path parameter follows the
/// credential policy.
#[test]
fn credential_named_path_parameters_are_redacted() {
    let request = serde_json::json!({ "url": "https://hooks.example.com/:webhook_token/:id", "pathParameters": [
        { "name": "webhook_token", "value": "whk-literal-5724" }, { "name": "id", "value": "42" },
    ]});
    for r in both(request.clone(), serde_json::json!({}), &opts()) {
        assert_eq!(r.requests[0].spec.url, "https://hooks.example.com/{{webhook_token}}/42");
        assert!(!serde_json::to_string(&r.requests).unwrap().contains("whk-literal-5724"));
        assert_eq!(r.report.redactions.len(), 1);
    }
    for r in both(request, serde_json::json!({}), &keep()) {
        assert_eq!(r.requests[0].spec.url, "https://hooks.example.com/whk-literal-5724/42");
    }
}
