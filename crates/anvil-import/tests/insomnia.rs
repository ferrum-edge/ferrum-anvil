mod common;

use anvil_domain::auth::{AuthConfig, KeyLocation, OAuthGrant};
use anvil_domain::request::Body;
use anvil_domain::secret::SensitiveValue;
use anvil_import::{Dialect, detect};
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
