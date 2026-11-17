mod common;

use anvil_domain::auth::{AuthConfig, KeyLocation, OAuthGrant};
use anvil_domain::request::{Body, MultipartContent};
use anvil_domain::secret::SensitiveValue;
use anvil_import::{Dialect, ImportError, ImportOptions, detect, import};
use common::*;

const COLLECTION: &str = "postman/shop.postman_collection.json";
const ENV: &str = "postman/staging.postman_environment.json";

fn by_name<'a>(r: &'a anvil_import::ImportResult, name: &str) -> &'a anvil_domain::workspace::RequestDefinition {
    r.requests.iter().find(|q| q.name == name).unwrap_or_else(|| panic!("no request {name}"))
}

#[test]
fn detects_collection_and_environment() {
    assert_eq!(detect(&fixture(COLLECTION)).dialect, Dialect::PostmanV21);
    assert_eq!(detect(&fixture(ENV)).dialect, Dialect::PostmanEnvironment);
    let v1 = br#"{"id": "x", "name": "old", "order": [], "requests": []}"#;
    assert!(matches!(import(v1, &opts()), Err(ImportError::UnsupportedDialect { dialect: Dialect::PostmanV1, .. })));
}

#[test]
fn nested_folders_and_requests() {
    let r = run(COLLECTION, &opts());
    assert_eq!(r.workspace.name, "Shop API");
    let catalog = r.folders.iter().find(|f| f.name == "Catalog").unwrap();
    let products = r.folders.iter().find(|f| f.name == "Products").unwrap();
    assert_eq!(products.parent_id, Some(catalog.meta.id));
    assert_eq!(catalog.description, "Catalog endpoints");
    let list = by_name(&r, "List products");
    assert_eq!(list.folder_id, Some(products.meta.id));
    assert_eq!(list.spec.url, "{{baseUrl}}/products");
    // Disabled entries are preserved, not dropped (DATA-001).
    assert!(!param(&list.spec, "sort").unwrap().enabled);
    assert!(!header(&list.spec, "X-Debug").unwrap().enabled);
    assert_eq!(header(&list.spec, "X-Request-Id").unwrap().value, "{{$guid}}", "native dynamic variable kept");
    assert_eq!(list.spec.source.as_ref().unwrap().operation_key, "postman:7b0e1c7e-0001-4000-8000-000000000001");
    // Path variables.
    assert_eq!(by_name(&r, "Get product").spec.url, "{{baseUrl}}/products/42/variants/{{variant}}");
    assert!(r.report.required_variables.iter().any(|v| v.name == "variant"));
    // Unsupported faker variable reported with its location.
    assert!(has_at(&r, "dynamic_variable", "/item/0/item/0/item/0/request/url/raw"));
    assert!(has_at(&r, "saved_responses", "/item/0/item/0/item/0/response"));
}

#[test]
fn bodies() {
    let r = run(COLLECTION, &opts());
    let create = by_name(&r, "Create order");
    match &create.spec.body {
        Body::Json { text } => assert!(text.contains("{{qty}}")),
        other => panic!("{other:?}"),
    }
    assert!(header(&create.spec, "Content-Type").is_none(), "matching Content-Type is inferred by the body");
    match &by_name(&r, "Upload invoice").spec.body {
        Body::Multipart { parts } => {
            assert!(parts[0].enabled);
            assert!(!parts[1].enabled, "file parts are disabled placeholders");
            assert!(matches!(&parts[1].content, MultipartContent::Text { value } if value.is_empty()));
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(r.report.external_refs[0].reference, "/Users/alice/invoices/inv-1.pdf");
    match &by_name(&r, "Login form").spec.body {
        Body::FormUrlEncoded { fields } => {
            assert_eq!(fields[1].value, "{{password}}");
            assert!(fields[1].sensitive);
            assert!(!fields[2].enabled);
        }
        other => panic!("{other:?}"),
    }
    match &by_name(&r, "GraphQL search").spec.body {
        Body::GraphQl { query, variables, .. } => {
            assert!(query.starts_with("query($q"));
            assert_eq!(variables, r#"{"q": "lamp"}"#);
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn auth_placeholders_and_redaction() {
    let r = run(COLLECTION, &opts());
    // Collection bearer references a variable: kept.
    assert!(matches!(&r.workspace.auth, AuthConfig::Bearer { token, .. } if token == &SensitiveValue::template("{{accessToken}}")));
    // The secret collection variable is dropped and listed as required.
    assert!(!r.workspace.variables.iter().any(|v| v.name == "accessToken"));
    assert!(r.report.required_variables.iter().any(|v| v.name == "accessToken" && v.secret));
    // Disabled variable kept disabled.
    assert!(r.workspace.variables.iter().any(|v| v.name == "pageSize" && !v.enabled));
    // Folder API key auth with a literal → placeholder.
    let products = r.folders.iter().find(|f| f.name == "Products").unwrap();
    match &products.auth {
        AuthConfig::ApiKey { name, value, location } => {
            assert_eq!(name, "X-Api-Key");
            assert_eq!(*location, KeyLocation::Header);
            assert!(value.is_pure_reference());
        }
        other => panic!("{other:?}"),
    }
    match &by_name(&r, "Create order").spec.auth {
        AuthConfig::Basic { username, password } => {
            assert_eq!(username, "shop-bot");
            assert!(password.is_pure_reference(), "literal password redacted");
        }
        other => panic!("{other:?}"),
    }
    match &by_name(&r, "GraphQL search").spec.auth {
        AuthConfig::OAuth2 { config } => {
            assert_eq!(config.grant, OAuthGrant::ClientCredentials);
            assert_eq!(config.client_id, "shop-cli");
            assert_eq!(config.client_secret, SensitiveValue::template("{{clientSecret}}"));
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(by_name(&r, "Upload invoice").spec.auth, AuthConfig::None);
    assert!(has_at(&r, "auth_unsupported", "/item/1/item/1/request/auth"));
    assert_eq!(by_name(&r, "Login form").spec.auth, AuthConfig::None);
    assert_eq!(by_name(&r, "List products").spec.auth, AuthConfig::Inherit);
    // Nothing secret leaks into the imported objects.
    let all = serde_json::to_string(&(&r.workspace, &r.folders, &r.requests, &r.environments)).unwrap();
    for secret in ["hunter2", "sk_live_abc123", "eyJhbGciOiJIUzI1NiJ9.literal.token", "cached-token-value", "p@ss"] {
        assert!(!all.contains(secret), "{secret} leaked into imported objects");
    }
}

#[test]
fn include_credentials_keeps_literals() {
    let r = run(COLLECTION, &ImportOptions { include_credentials: true, ..opts() });
    match &by_name(&r, "Create order").spec.auth {
        AuthConfig::Basic { password, .. } => assert_eq!(password, &SensitiveValue::template("hunter2")),
        other => panic!("{other:?}"),
    }
    assert!(r.workspace.variables.iter().any(|v| v.name == "accessToken" && v.secret));
}

#[test]
fn scripts_are_retained_disabled_and_untrusted() {
    let r = run(COLLECTION, &opts());
    assert_eq!(r.report.scripts.len(), 2);
    for s in &r.report.scripts {
        assert!(!s.enabled && !s.trusted);
    }
    let test = r.report.scripts.iter().find(|s| s.event == "test").unwrap();
    assert_eq!(test.owner, "List products");
    assert!(test.source.contains("pm.environment.set('first'"));
    assert_eq!(test.pointer, "/item/0/item/0/item/0/event/0");
    // Scripts never reach request specs.
    let all = serde_json::to_string(&r.requests).unwrap();
    assert!(!all.contains("pm.test"));
}

#[test]
fn tls_bypass_is_inactive_and_redirects_mapped() {
    let r = run(COLLECTION, &opts());
    let get = by_name(&r, "Get product");
    assert_eq!(get.spec.settings.redirects.map(|p| p.follow), Some(false));
    let s = r.report.inactive_settings.iter().find(|s| s.setting == "tls.verify").unwrap();
    assert_eq!(s.pointer, "/item/0/item/0/item/1/protocolProfileBehavior/strictSSL");
    assert!(get.spec.settings.tls_profile_id.is_none());
}

#[test]
fn environment_export() {
    let r = run(ENV, &opts());
    assert_eq!(r.environments.len(), 1);
    let env = &r.environments[0];
    assert_eq!(env.name, "Staging");
    assert_eq!(r.workspace.active_environment_id, Some(env.meta.id));
    let names: Vec<&str> = env.variables.iter().map(|v| v.name.as_str()).collect();
    assert_eq!(names, vec!["baseUrl", "clientSecret", "qty"]);
    assert!(env.variables.iter().find(|v| v.name == "clientSecret").unwrap().secret);
    assert!(!env.variables.iter().find(|v| v.name == "qty").unwrap().enabled);
    assert_eq!(r.report.redactions.len(), 1);
    assert!(!serde_json::to_string(&r.environments).unwrap().contains("staging-secret-token"));
}

#[test]
fn postman_v20_auth_object_form() {
    let doc = serde_json::json!({
        "info": {"name": "v20", "schema": "https://schema.getpostman.com/json/collection/v2.0.0/collection.json"},
        "item": [{"name": "r", "request": {"url": "https://x.example.com/a", "method": "GET",
            "auth": {"type": "basic", "basic": {"username": "u", "password": "{{pw}}"}}}}]
    });
    let r = import(doc.to_string().as_bytes(), &opts()).unwrap();
    assert_eq!(r.source.dialect, Dialect::PostmanV20);
    match &r.requests[0].spec.auth {
        AuthConfig::Basic { username, password } => {
            assert_eq!(username, "u");
            assert_eq!(password, &SensitiveValue::template("{{pw}}"));
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn raw_json_bodies_and_mixed_raw_queries_are_redacted() {
    let doc = serde_json::json!({
        "info": {"name": "c", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
        "item": [{"name": "r", "request": {
            "url": "https://x.example.com/a?flag&api_key=placeholder-secret",
            "method": "POST",
            "body": {"mode": "raw", "raw": "{\"user\":\"u\",\"password\":\"placeholder-secret\"}", "options": {"raw": {"language": "json"}}}
        }}]
    });
    let r = import(doc.to_string().as_bytes(), &opts()).unwrap();
    let s = &r.requests[0].spec;
    assert_eq!(json_body(s)["password"], "{{password}}");
    assert_eq!(s.url, "https://x.example.com/a?flag&api_key={{api_key}}");
    assert!(!serde_json::to_string(&r.requests).unwrap().contains("placeholder-secret"));
    assert_eq!(r.report.redactions.len(), 2);
}

fn postman_body(body: serde_json::Value, o: &ImportOptions) -> anvil_import::ImportResult {
    let doc = serde_json::json!({
        "info": {"name": "c", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
        "item": [{"name": "r", "request": { "url": "https://x.example.com/a", "method": "POST", "body": body }}]
    });
    import(doc.to_string().as_bytes(), o).unwrap()
}

#[test]
fn graphql_variables_numeric_credentials_and_unscannable_bodies() {
    let gql = serde_json::json!({"mode": "graphql", "graphql": {"query": "mutation { login }", "variables": "{\"password\":\"placeholder-secret\",\"pin\":123456}"}});
    let r = postman_body(gql.clone(), &opts());
    match &r.requests[0].spec.body {
        Body::GraphQl { variables, .. } => {
            let v = substituted(variables, &[("pin", "123456")]);
            assert_eq!((v["password"].as_str(), v["pin"].as_u64()), (Some("{{password}}"), Some(123456)));
        }
        other => panic!("{other:?}"),
    }
    assert!(!serde_json::to_string(&r.requests).unwrap().contains("placeholder-secret"));
    // Kept as written with include_credentials.
    let r = postman_body(gql, &ImportOptions { include_credentials: true, ..opts() });
    match &r.requests[0].spec.body {
        Body::GraphQl { variables, .. } => assert!(variables.contains("placeholder-secret")),
        other => panic!("{other:?}"),
    }
    // A repeated credential member keeps only its last value.
    let raw = serde_json::json!({"mode": "raw", "raw": "{\"pin\":1234,\"pin\":\"{{pin}}\"}", "options": {"raw": {"language": "json"}}});
    let r = postman_body(raw, &opts());
    assert!(!serde_json::to_string(&r.requests).unwrap().contains("1234"));
    // XML cannot be scanned.
    let xml = serde_json::json!({"mode": "raw", "raw": "<p>placeholder-secret</p>", "options": {"raw": {"language": "xml"}}});
    assert!(has(&postman_body(xml, &opts()), "body_not_scanned"));
}

fn postman_request(request: serde_json::Value, o: &ImportOptions) -> anvil_import::ImportResult {
    let doc = serde_json::json!({
        "info": {"name": "c", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
        "item": [{"name": "r", "request": request}]
    });
    import(doc.to_string().as_bytes(), o).unwrap()
}

/// Postman sends a query value as written, so `%3A` is stored decoded and the
/// engine's one encoding sends `%3A` again, not `%253A` (#563). Every list
/// entry stays a parameter, so a `&`, `#` or `=` in it stays data, and a
/// retained credential keeps its `sensitive` mark (review sol F1, F2).
#[test]
fn query_list_values_are_decoded_and_stay_parameters() {
    let url = |query: serde_json::Value| serde_json::json!({"method": "GET", "url": {"raw": "https://x.example.com/cb", "host": ["x", "example", "com"], "path": ["cb"], "query": query}});
    let r = postman_request(
        url(serde_json::json!([
            {"key": "redirect_uri", "value": "https%3A%2F%2Fapp.example.com%2Fdone"},
            {"key": "n", "value": "caf%C3%A9", "disabled": true}
        ])),
        &opts(),
    );
    let s = &r.requests[0].spec;
    assert_eq!(s.url, "https://x.example.com/cb");
    assert_eq!(param(s, "redirect_uri").unwrap().value, "https://app.example.com/done");
    assert_eq!(param(s, "n").unwrap().value, "caf\u{e9}");
    assert!(!param(s, "n").unwrap().enabled);
    assert!(!has(&r, "query_value_converted") && !has(&r, "query_param_not_decoded"));

    let list = serde_json::json!([
        {"key": "q", "value": "a+b#tail&x=1"},
        {"key": "a=b", "value": "c"},
        {"key": "api_key", "value": "placeholder-secret"},
        {"key": "pwd", "value": "retained-credential-571"},
        {"key": "flag"},
        {"key": "off", "value": "x+y", "disabled": true}
    ]);
    let r = postman_request(url(list.clone()), &opts());
    let s = &r.requests[0].spec;
    assert_eq!(s.url, "https://x.example.com/cb", "nothing moves into the URL");
    let pairs: Vec<(&str, &str, bool)> = s.params.iter().map(|p| (p.name.as_str(), p.value.as_str(), p.enabled)).collect();
    assert_eq!(
        pairs,
        [
            ("q", "a b#tail&x=1", true),
            ("a=b", "c", true),
            ("api_key", "{{api_key}}", true),
            ("pwd", "{{pwd}}", true),
            ("flag", "", true),
            ("off", "x y", false)
        ]
    );
    assert!(has_at(&r, "query_value_converted", "/url/query/0"));
    let text = serde_json::to_string(&r.requests).unwrap();
    assert!(!text.contains("placeholder-secret") && !text.contains("retained-credential-571"), "{text}");
    assert_eq!(r.report.redactions.len(), 2);

    // Kept credentials stay structured and marked sensitive.
    let r = postman_request(url(list), &ImportOptions { include_credentials: true, ..opts() });
    let s = &r.requests[0].spec;
    assert_eq!(s.url, "https://x.example.com/cb");
    let pwd = param(s, "pwd").unwrap();
    assert!(pwd.value == "retained-credential-571" && pwd.sensitive);
    assert!(param(s, "api_key").unwrap().sensitive);
    assert!(!param(s, "q").unwrap().sensitive);

    // An escape that is not UTF-8, and escaped braces that would decode to a
    // reference, are kept as written (never U+FFFD, never a live `{{id}}`).
    let r = postman_request(
        url(serde_json::json!([{"key": "n", "value": "caf%E9"}, {"key": "t", "value": "%7B%7Bid%7D%7D"}, {"key": "v", "value": "{{id}}"}])),
        &opts(),
    );
    let s = &r.requests[0].spec;
    assert_eq!(param(s, "n").unwrap().value, "caf%E9");
    assert_eq!(param(s, "t").unwrap().value, "%7B%7Bid%7D%7D");
    assert_eq!(param(s, "v").unwrap().value, "{{id}}", "a reference written as one stays one");
    assert!(has_at(&r, "query_param_not_decoded", "/url/query/0") && has_at(&r, "query_param_not_decoded", "/url/query/1"));

    // The raw URL path: decoded pairs, or the query as written.
    let r = postman_request(serde_json::json!({"method": "GET", "url": "https://x.example.com/cb?r=https%3A%2F%2Fa.example&n=1"}), &opts());
    assert_eq!(param(&r.requests[0].spec, "r").unwrap().value, "https://a.example");
    for query in ["q=hello+world", "n=caf%E9", "discount=50%"] {
        let r = postman_request(serde_json::json!({"method": "GET", "url": format!("https://x.example.com/search?{query}")}), &opts());
        assert_eq!(r.requests[0].spec.url, format!("https://x.example.com/search?{query}"));
        assert!(r.requests[0].spec.params.is_empty());
    }
    // Path variables are substituted before a verbatim query.
    let r = postman_request(
        serde_json::json!({"method": "GET", "url": {"raw": "https://x.example.com/items/:id?q=a+b", "variable": [{"key": "id", "value": "7"}]}}),
        &opts(),
    );
    assert_eq!(r.requests[0].spec.url, "https://x.example.com/items/7?q=a+b");
}

/// GHSA-c236-7r9g-c9p2: URL userinfo becomes Basic auth with a
/// `{{password}}` placeholder (the engine never sends it in the URL), as in
/// the cURL and HAR importers, for the string and object URL forms.
#[test]
fn url_userinfo_becomes_basic_auth_and_its_password_is_redacted() {
    for url in [
        serde_json::json!("https://admin:hunter2-literal@api.example.com/v1/status"),
        serde_json::json!({"raw": "https://admin:hunter2-literal@api.example.com/v1/status"}),
        serde_json::json!({"protocol": "https", "host": ["admin:hunter2-literal@api", "example", "com"], "path": ["v1", "status"]}),
    ] {
        let r = postman_request(serde_json::json!({"method": "GET", "url": url.clone()}), &opts());
        let s = &r.requests[0].spec;
        assert_eq!(s.url, "https://api.example.com/v1/status");
        assert!(
            matches!(&s.auth, AuthConfig::Basic { username, password } if username == "admin" && password == &SensitiveValue::template("{{password}}")),
            "{:?}",
            s.auth
        );
        assert!(!serde_json::to_string(&r.requests).unwrap().contains("hunter2-literal"));
        assert_eq!(r.report.redactions.len(), 1);

        let r = postman_request(serde_json::json!({"method": "GET", "url": url}), &ImportOptions { include_credentials: true, ..opts() });
        let s = &r.requests[0].spec;
        assert_eq!(s.url, "https://api.example.com/v1/status");
        assert!(matches!(&s.auth, AuthConfig::Basic { password, .. } if password == &SensitiveValue::template("hunter2-literal")));
        assert!(r.report.redactions.is_empty());
    }
    // The request's own auth is kept; the userinfo is dropped, with a warning.
    let r = postman_request(
        serde_json::json!({"method": "GET", "url": "https://admin:hunter2-literal@api.example.com/x",
            "auth": {"type": "bearer", "bearer": [{"key": "token", "value": "{{tok}}"}]}}),
        &opts(),
    );
    let s = &r.requests[0].spec;
    assert_eq!(s.url, "https://api.example.com/x");
    assert!(matches!(&s.auth, AuthConfig::Bearer { .. }));
    assert!(has(&r, "url_credentials_dropped"));
    assert!(!serde_json::to_string(&r.requests).unwrap().contains("hunter2-literal"));
}

/// GHSA-c236-7r9g-c9p2: a credential-named path variable follows the
/// credential policy; other path variables are substituted as before.
#[test]
fn credential_named_path_variables_are_redacted() {
    let request = serde_json::json!({"method": "POST", "url": {
        "raw": "https://hooks.example.com/:webhook_token/orders/:id",
        "variable": [{"key": "webhook_token", "value": "whk-literal-5724"}, {"key": "id", "value": "42"}]
    }});
    let r = postman_request(request.clone(), &opts());
    assert_eq!(r.requests[0].spec.url, "https://hooks.example.com/{{webhook_token}}/orders/42");
    assert!(!serde_json::to_string(&r.requests).unwrap().contains("whk-literal-5724"));
    assert_eq!(r.report.redactions.len(), 1);
    assert!(r.report.required_variables.iter().any(|v| v.name == "webhook_token" && v.secret));

    let r = postman_request(request, &ImportOptions { include_credentials: true, ..opts() });
    assert_eq!(r.requests[0].spec.url, "https://hooks.example.com/whk-literal-5724/orders/42");
    assert!(r.report.redactions.is_empty());
}
