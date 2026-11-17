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
        assert_eq!(s.url, "https://example.test/x?flag");
        assert!(param(s, "api_key").is_some_and(|p| p.value == "{{api_key}}" && p.sensitive));
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
    for (k, v) in [("_id", "req_1"), ("_type", "request"), ("parentId", "wrk_1"), ("name", "R")] {
        request[k] = v.into();
    }
    if request.get("method").is_none() {
        request["method"] = "GET".into();
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
    if request.get("method").is_none() {
        request["method"] = "GET".into();
    }
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

fn keep() -> anvil_import::ImportOptions {
    anvil_import::ImportOptions { include_credentials: true, ..opts() }
}

fn template_text(v: &SensitiveValue) -> String {
    match v {
        SensitiveValue::Template { value } => value.clone(),
        SensitiveValue::Secret { .. } => panic!("expected a template value"),
    }
}

/// #563: a parameter's escapes are stored decoded only when the engine's
/// one encoding sends exactly what Insomnia sends; anything else is kept as
/// written and reported.
#[test]
fn parameters_are_decoded_only_when_exact() {
    let request = serde_json::json!({ "url": "https://example.test/cb", "parameters": [
        { "name": "redirect_uri", "value": "https%3A%2F%2Fapp.example.com%2Fdone" },
        { "name": "n", "value": "caf%E9" },
        { "name": "t", "value": "%7B%7Bid%7D%7D" },
        { "name": "q", "value": "a+b" },
    ]});
    for r in both(request, serde_json::json!({}), &opts()) {
        let values: Vec<&str> = r.requests[0].spec.params.iter().map(|p| p.value.as_str()).collect();
        assert_eq!(values, ["https://app.example.com/done", "caf%E9", "%7B%7Bid%7D%7D", "a+b"]);
        assert!(has_at(&r, "query_value_not_decoded", "parameters/1") && has_at(&r, "query_value_not_decoded", "parameters/2"));
        assert!(!has_at(&r, "query_value_not_decoded", "parameters/0"));
    }
}

/// GHSA-c236-7r9g-c9p2: URL userinfo becomes Basic auth with a
/// `{{password}}` placeholder; disabled auth wins and drops it.
#[test]
fn url_userinfo_becomes_basic_auth_unless_auth_is_disabled() {
    let request = serde_json::json!({ "url": "https://admin:tok-SENSITIVE-in1@api.example.com/v1/status" });
    for r in both(request.clone(), serde_json::json!({}), &opts()) {
        let s = &r.requests[0].spec;
        assert_eq!(s.url, "https://api.example.com/v1/status");
        assert!(
            matches!(&s.auth, AuthConfig::Basic { username, password } if username == "admin" && password == &SensitiveValue::template("{{password}}")),
            "expected Basic auth with a placeholder password"
        );
        assert!(!serde_json::to_string(&r.requests).unwrap().contains("tok-SENSITIVE-in1"));
    }
    let mut disabled = request;
    disabled["authentication"] = serde_json::json!({ "type": "basic", "disabled": true });
    for r in both(disabled, serde_json::json!({}), &opts()) {
        assert!(!matches!(r.requests[0].spec.auth, AuthConfig::Basic { .. }));
        assert!(has(&r, "url_credentials_dropped"));
    }
}

/// GHSA-c236-7r9g-c9p2: every scalar under a credential-named member of an
/// environment array is redacted (strings, numbers, booleans, arrays of
/// them, helper arguments), with distinct placeholders.
#[test]
fn credential_members_of_environment_arrays_are_redacted() {
    let env = serde_json::json!({
        "accounts": [
            { "name": "a", "api_key": "tok-SENSITIVE-in2", "pin": 571571571, "mfa": true },
            { "name": "b", "tokens": ["tok-SENSITIVE-in3", "{{ref}}"], "secret": "{{$randomFrom tok-SENSITIVE-in4 x}}" }
        ],
        "keys": [{ "credentials": { "a-b": "tok-SENSITIVE-in5", "a_b": "tok-SENSITIVE-in6" } }],
        "hosts": ["a.example", "b.example"],
    });
    let request = serde_json::json!({ "url": "https://example.test/x" });
    for r in both(request.clone(), env.clone(), &opts()) {
        let var = |n: &str| r.workspace.variables.iter().find(|v| v.name == n).map(|v| template_text(&v.value));
        let accounts = var("accounts").expect("accounts variable");
        let keys = var("keys").expect("keys variable");
        for text in [&accounts, &keys] {
            assert!(!text.contains("tok-SENSITIVE") && !text.contains("571571571"), "a credential member stayed");
        }
        assert!(accounts.contains("{{ref}}"), "a reference is kept");
        assert_eq!(var("hosts").as_deref(), Some(r#"["a.example","b.example"]"#));
        let names: std::collections::HashSet<&str> = r.report.required_variables.iter().map(|v| v.name.as_str()).collect();
        assert!(names.len() >= 6, "each credential leaf has its own placeholder");
        let parsed: serde_json::Value = serde_json::from_str(&keys).unwrap();
        let creds = &parsed[0]["credentials"];
        assert_ne!(creds["a-b"], creds["a_b"], "different leaves get different placeholders");
    }
    for r in both(request, env, &keep()) {
        let accounts = r.workspace.variables.iter().find(|v| v.name == "accounts").unwrap();
        assert!(template_text(&accounts.value).contains("571571571"));
    }
}

/// GHSA-c236-7r9g-c9p2: a credential-named path parameter follows the
/// credential policy.
#[test]
fn credential_named_path_parameters_are_redacted() {
    let request = serde_json::json!({ "url": "https://hooks.example.com/:webhook_token/:id", "pathParameters": [
        { "name": "webhook_token", "value": "tok-SENSITIVE-in7" }, { "name": "id", "value": "42" },
    ]});
    for r in both(request.clone(), serde_json::json!({}), &opts()) {
        assert_eq!(r.requests[0].spec.url, "https://hooks.example.com/{{webhook_token}}/42");
        assert!(!serde_json::to_string(&r.requests).unwrap().contains("tok-SENSITIVE-in7"));
    }
    for r in both(request, serde_json::json!({}), &keep()) {
        assert_eq!(r.requests[0].spec.url, "https://hooks.example.com/tok-SENSITIVE-in7/42");
    }
}

/// Review of #573, sol F4: environment placeholders never take the name of
/// a variable of the environment (here the 48-byte name of the array
/// itself) or of a placeholder made for another array whose path reads the
/// same (`a-b` and `a_b`).
#[test]
fn environment_placeholders_never_collide() {
    let long = "a".repeat(48);
    let mut env = serde_json::Map::new();
    env.insert(long.clone(), serde_json::json!([{ "api_key": "tok-SENSITIVE-in8" }]));
    env.insert("a-b".into(), serde_json::json!([{ "api_key": "tok-SENSITIVE-in9" }]));
    env.insert("a_b".into(), serde_json::json!([{ "api_key": "tok-SENSITIVE-in10" }]));
    let request = serde_json::json!({ "url": "https://example.test/x" });
    for r in both(request.clone(), serde_json::Value::Object(env.clone()), &opts()) {
        let var = |n: &str| r.workspace.variables.iter().find(|v| v.name == n).map(|v| template_text(&v.value)).unwrap();
        let own = var(&long);
        assert!(!own.contains(&format!("{{{{{long}}}}}")), "a placeholder took its own variable's name");
        let (first, second) = (var("a-b"), var("a_b"));
        assert_ne!(first, second, "two arrays share a placeholder");
        for text in [own, first, second] {
            assert!(!text.contains("tok-SENSITIVE"), "a credential member stayed");
        }
    }
}

/// Review of #573, dsf F2: placeholder names and report pointers for a leaf
/// deep under long member names stay bounded.
#[test]
fn deep_environment_paths_stay_bounded() {
    let key = "k".repeat(60);
    let mut node = serde_json::json!({ "api_key": (0..500).map(|i| format!("tok-SENSITIVE-deep-{i}")).collect::<Vec<_>>() });
    for _ in 0..100 {
        let mut m = serde_json::Map::new();
        m.insert(key.clone(), node);
        node = serde_json::Value::Object(m);
    }
    let env = serde_json::json!({ "deep": [node] });
    let r = v4_with(serde_json::json!({ "url": "https://example.test/x" }), env, &opts());
    let text = r.workspace.variables.iter().find(|v| v.name == "deep").map(|v| template_text(&v.value)).unwrap();
    assert!(!text.contains("tok-SENSITIVE-deep"), "a credential member stayed");
    assert!(r.report.required_variables.iter().all(|v| v.name.len() <= 56), "a placeholder name is unbounded");
    assert!(r.report.redactions.iter().all(|x| x.pointer.len() < 2048), "a report pointer is unbounded");
    let distinct: std::collections::HashSet<&str> = r.report.required_variables.iter().map(|v| v.name.as_str()).collect();
    assert!(distinct.len() >= 500, "each leaf has its own placeholder");
}

/// Review round 2 of #573, sol F2: a Nunjucks expression with a quoted
/// literal (or anything but a plain reference) under a credential name is
/// literal material and is redacted; a plain `{{ _.name }}` reference stays.
#[test]
fn quoted_expressions_in_environment_arrays_are_redacted() {
    let env = serde_json::json!({ "accounts": [
        { "api_key": "{{ 'tok-SENSITIVE-in11' }}", "token": "{{ _.shared }}", "secret": "{{ x | upper }}" }
    ]});
    for r in both(serde_json::json!({ "url": "https://example.test/x" }), env, &opts()) {
        let text = r.workspace.variables.iter().find(|v| v.name == "accounts").map(|v| template_text(&v.value)).unwrap();
        assert!(!text.contains("tok-SENSITIVE-in11"), "a quoted credential stayed");
        assert!(!text.contains("upper"), "a filtered expression stayed");
        assert!(text.contains("{{shared}}"), "a plain reference is kept");
    }
}

/// Review round 2 of #573, dsf F3: a sub-environment placeholder never takes
/// a base-environment variable name (which would shadow it), nor the
/// reverse.
#[test]
fn sub_environment_placeholders_never_take_a_base_variable_name() {
    let doc = serde_json::json!({
        "type": "collection.insomnia.rest/5.0", "name": "W",
        "environments": {
            "name": "Base",
            "data": { "accounts_0_api_key": "base-value", "keys": [{ "api_key": "tok-SENSITIVE-in12" }] },
            "subEnvironments": [{ "name": "Sub", "data": {
                "accounts": [{ "api_key": "tok-SENSITIVE-in13" }],
                "keys_0_api_key": "sub-value"
            } }]
        },
        "collection": [{ "name": "R", "meta": { "id": "req_1" }, "method": "GET", "url": "https://example.test/x" }],
    });
    let r = anvil_import::import(doc.to_string().as_bytes(), &opts()).unwrap();
    let base = r.workspace.variables.iter().find(|v| v.name == "keys").map(|v| template_text(&v.value)).unwrap();
    let sub = r.environments[0].variables.iter().find(|v| v.name == "accounts").map(|v| template_text(&v.value)).unwrap();
    assert!(!sub.contains("{{accounts_0_api_key}}"), "a sub-environment placeholder took a base variable name");
    assert!(!base.contains("{{keys_0_api_key}}"), "a base placeholder took a sub-environment variable name");
    assert!(!sub.contains("tok-SENSITIVE") && !base.contains("tok-SENSITIVE"), "a credential member stayed");
}

/// Review round 4 of #573, sol F1 and F2: in Nunjucks, subtraction and
/// numeric operands are expressions (literal), and a delimiter inside a
/// password expression does not end the URL's authority early.
#[test]
fn nunjucks_expressions_and_delimiters_in_passwords_are_redacted() {
    let request = serde_json::json!({
        "url": "https://admin:{{ 'tok-SENSITIVE-in14/x?y#z' | urlencode }}@api.example.test/v1",
        "headers": [{ "name": "X-Api-Key", "value": "{{ _.zero--571571578 }}" }],
    });
    let env = serde_json::json!({ "zero": 0, "accounts": [{ "pin": "{{ _.zero--571571579 }}" }] });
    for r in both(request, env, &opts()) {
        let s = &r.requests[0].spec;
        assert_eq!(s.url, "https://api.example.test/v1");
        assert!(matches!(&s.auth, AuthConfig::Basic { password, .. } if password == &SensitiveValue::template("{{password}}")));
        assert_eq!(header(s, "X-Api-Key").unwrap().value, "{{X_Api_Key}}");
        let accounts = r.workspace.variables.iter().find(|v| v.name == "accounts").map(|v| template_text(&v.value)).unwrap();
        let text = serde_json::to_string(&r.requests).unwrap();
        assert!(!text.contains("tok-SENSITIVE-in14") && !text.contains("57157157") && !accounts.contains("57157157"), "a literal stayed");
    }
}
