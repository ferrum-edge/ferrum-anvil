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
            assert!(is_secret_ref(&fields[1].value));
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
    assert_eq!(test.owner, anvil_import::ScriptOwner::Request);
    assert_eq!(test.language, "javascript");
    assert!(test.bytes > 0 && test.lines > 0);
    // #584: the report describes a script by its metadata; the body and the
    // owner's name are not copied into it.
    let report = serde_json::to_string(&r.report).unwrap();
    assert!(!report.contains("pm.environment.set") && !report.contains("List products"));
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
    assert!(json_body(s)["password"].as_str().is_some_and(is_secret_ref));
    assert_eq!(s.url, "https://x.example.com/a?flag");
    assert!(param(s, "api_key").is_some_and(|p| is_secret_ref(&p.value) && p.sensitive));
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
            assert!(v["password"].as_str().is_some_and(is_secret_ref));
            assert_eq!(v["pin"].as_u64(), Some(123456));
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

fn with_query(query: serde_json::Value) -> serde_json::Value {
    serde_json::json!({"method": "GET", "url": {"raw": "https://x.example.com/cb", "query": query}})
}

/// #563: Postman sends a list value's escapes as written. A value is stored
/// decoded only when the engine's one encoding sends exactly the source
/// (`%3A%2F%2F`); anything else is kept as written, as before, and reported.
#[test]
fn query_list_values_are_decoded_only_when_exact() {
    let r = postman_request(
        with_query(serde_json::json!([
            {"key": "redirect_uri", "value": "https%3A%2F%2Fapp.example.com%2Fdone"},
            {"key": "lower", "value": "a%3ab"},
            {"key": "braces", "value": "%7B%7Bid%7D%7D"},
            {"key": "plus", "value": "a+b"},
            {"key": "plain", "value": "v1"},
            {"key": "a+b", "value": "1"}
        ])),
        &opts(),
    );
    let s = &r.requests[0].spec;
    let values: Vec<(&str, &str)> = s.params.iter().map(|p| (p.name.as_str(), p.value.as_str())).collect();
    assert_eq!(
        values,
        [
            ("redirect_uri", "https://app.example.com/done"),
            ("lower", "a%3ab"),
            ("braces", "%7B%7Bid%7D%7D"),
            ("plus", "a+b"),
            ("plain", "v1"),
            ("a+b", "1")
        ]
    );
    assert!(has_at(&r, "query_value_not_decoded", "/url/query/1") && has_at(&r, "query_value_not_decoded", "/url/query/2"));
    assert!(has_at(&r, "query_plus_sent_encoded", "/url/query/3"));
    // A `+` in a name is reported too (review of #573, dsf F3).
    assert!(has_at(&r, "query_plus_sent_encoded", "/url/query/5"));
    assert!(!has_at(&r, "query_value_not_decoded", "/url/query/0"));
}

/// A credential name is recognized decoded too, even when it is kept as
/// written (`%70assword` re-encodes differently).
#[test]
fn an_escaped_credential_name_in_a_query_list_is_redacted() {
    let r = postman_request(with_query(serde_json::json!([{"key": "%70assword", "value": "tok-SENSITIVE-pm1"}])), &opts());
    let p = &r.requests[0].spec.params[0];
    // The placeholder is named after the spelling as written.
    assert!(p.sensitive && is_secret_ref(&p.value));
    assert!(!serde_json::to_string(&r.requests).unwrap().contains("tok-SENSITIVE-pm1"));
}

/// GHSA-c236-7r9g-c9p2: URL userinfo becomes Basic auth with a password
/// placeholder for the string, raw and rebuilt URL forms; the
/// userinfo ends at the last `@` of the authority.
#[test]
fn url_userinfo_becomes_basic_auth_and_its_password_is_redacted() {
    for url in [
        serde_json::json!("https://admin:tok-SENSITIVE-pm2@api.example.com/v1/status"),
        serde_json::json!({"raw": "https://admin:p@tok-SENSITIVE-pm2@api.example.com/v1/status"}),
        serde_json::json!({"protocol": "https", "host": ["admin:tok-SENSITIVE-pm2@api", "example", "com"], "path": ["v1", "status"]}),
    ] {
        let r = postman_request(serde_json::json!({"method": "GET", "url": url.clone()}), &opts());
        let s = &r.requests[0].spec;
        assert_eq!(s.url, "https://api.example.com/v1/status");
        assert!(
            matches!(&s.auth, AuthConfig::Basic { username, password } if is_auth_ref(username, "username") && is_auth_ref(template_of(password), "password")),
            "expected Basic auth with a placeholder password"
        );
        assert!(!serde_json::to_string(&r.requests).unwrap().contains("tok-SENSITIVE-pm2"));
        assert_eq!(r.report.redactions.len(), 1);

        let r = postman_request(serde_json::json!({"method": "GET", "url": url}), &ImportOptions { include_credentials: true, ..opts() });
        let s = &r.requests[0].spec;
        assert_eq!(s.url, "https://api.example.com/v1/status");
        assert!(matches!(&s.auth, AuthConfig::Basic { password, .. } if !password.is_pure_reference()));
    }
}

/// Auth of the request's own, and an explicit "no auth", win over URL
/// userinfo, which is dropped with a warning.
#[test]
fn own_auth_and_noauth_win_over_url_userinfo() {
    for auth in
        [serde_json::json!({"type": "bearer", "bearer": [{"key": "token", "value": "{{tok}}"}]}), serde_json::json!({"type": "noauth"})]
    {
        let r = postman_request(
            serde_json::json!({"method": "GET", "url": "https://admin:tok-SENSITIVE-pm3@api.example.com/x", "auth": auth}),
            &opts(),
        );
        let s = &r.requests[0].spec;
        assert_eq!(s.url, "https://api.example.com/x");
        assert!(!matches!(&s.auth, AuthConfig::Basic { .. }));
        assert!(has(&r, "url_credentials_dropped"));
        assert!(!serde_json::to_string(&r.requests).unwrap().contains("tok-SENSITIVE-pm3"));
    }
}

/// GHSA-c236-7r9g-c9p2: a credential-named path variable follows the
/// credential policy; other path variables are substituted as before.
#[test]
fn credential_named_path_variables_are_redacted() {
    let request = serde_json::json!({"method": "POST", "url": {
        "raw": "https://hooks.example.com/:webhook_token/orders/:id",
        "variable": [{"key": "webhook_token", "value": "tok-SENSITIVE-pm4"}, {"key": "id", "value": "42"}]
    }});
    let r = postman_request(request.clone(), &opts());
    let url = &r.requests[0].spec.url;
    assert!(url.strip_prefix("https://hooks.example.com/").and_then(|u| u.strip_suffix("/orders/42")).is_some_and(is_secret_ref), "{url}");
    assert!(!serde_json::to_string(&r.requests).unwrap().contains("tok-SENSITIVE-pm4"));
    assert!(r.report.required_variables.iter().any(|v| is_secret_ref(&format!("{{{{{}}}}}", v.name)) && v.secret));
    let r = postman_request(request, &ImportOptions { include_credentials: true, ..opts() });
    assert_eq!(r.requests[0].spec.url, "https://hooks.example.com/tok-SENSITIVE-pm4/orders/42");
}

/// Round 2 of #575, sol F2: userinfo placeholders never take the name of a
/// variable the collection defines, so an existing `username` is never sent
/// in place of the redacted token.
#[test]
fn userinfo_placeholders_never_take_a_collection_variable_name() {
    let doc = serde_json::json!({
        "info": {"name": "c", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
        "variable": [{"key": "username", "value": "other-account-value"}, {"key": "password", "value": "other"}],
        "item": [{"name": "r", "request": {"method": "GET", "url": "https://tok-SENSITIVE-pm5@collector.example.test/v1"}}]
    });
    let r = import(doc.to_string().as_bytes(), &opts()).unwrap();
    match &r.requests[0].spec.auth {
        AuthConfig::Basic { username, password } => {
            assert!(is_auth_ref(username, "username"), "the user name is not an auth placeholder");
            // No password in the URL: nothing to bind a placeholder to.
            assert_eq!(template_of(password), "");
        }
        _ => panic!("expected Basic auth"),
    }
    assert!(!serde_json::to_string(&r.requests).unwrap().contains("tok-SENSITIVE-pm5"));
}

/// Final gate of #575: the userinfo placeholders never take the name of a
/// path variable, in the same request or another one, so supplying the path
/// value never fills the credential.
#[test]
fn userinfo_placeholders_never_take_a_path_variable_name() {
    let doc = serde_json::json!({
        "info": {"name": "c", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
        "item": [
            {"name": "a", "request": {"method": "GET", "url": {"raw": "https://admin:tok-SENSITIVE-pm6@api.example.test/items/:username"}}},
            {"name": "b", "request": {"method": "GET", "url": {"raw": "https://api.example.test/accounts/:password", "variable": [{"key": "password"}]}}}
        ]
    });
    let r = import(doc.to_string().as_bytes(), &opts()).unwrap();
    assert_eq!(r.requests[0].spec.url, "https://api.example.test/items/{{username}}");
    assert_eq!(r.requests[1].spec.url, "https://api.example.test/accounts/{{password}}");
    match &r.requests[0].spec.auth {
        AuthConfig::Basic { username, password } => {
            assert!(is_auth_ref(username, "username"), "the user name is not an auth placeholder");
            assert!(is_auth_ref(template_of(password), "password"));
        }
        _ => panic!("expected Basic auth"),
    }
}

/// Review of #586 (sol F3): an auth secret's placeholder never shares a
/// variable with a field placeholder. Field and auth placeholders are bound
/// to different literals and kinds, and a source that names a field like an
/// auth placeholder is refused (#584, round 5).
#[test]
fn auth_placeholders_never_alias_field_placeholders() {
    let doc = |headers: serde_json::Value| {
        serde_json::json!({
            "info": { "name": "c", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json" },
            "auth": { "type": "bearer", "bearer": [{ "key": "token", "value": "tok-SENSITIVE-pm-col" }] },
            "item": [{ "id": "r1", "name": "r", "request": { "method": "GET", "url": "https://api.example.test/", "header": headers,
                "auth": { "type": "basic", "basic": [{ "key": "username", "value": "u" }, { "key": "password", "value": "tok-SENSITIVE-pm-req" }] } } }]
        })
        .to_string()
    };
    let reference = |v: &serde_json::Value, field: &str| v[field]["value"].as_str().unwrap().trim_matches(['{', '}']).to_string();
    // A credential header holding the same literal as the request's auth.
    let headers = serde_json::json!([{ "key": "X-Api-Key", "value": "tok-SENSITIVE-pm-req" }]);
    let r = import(doc(headers).as_bytes(), &opts()).unwrap();
    let spec = &r.requests[0].spec;
    let request_secret = reference(&serde_json::to_value(&spec.auth).unwrap(), "password");
    let collection_secret = reference(&serde_json::to_value(&r.workspace.auth).unwrap(), "token");
    let field = header(spec, "X-Api-Key").unwrap().value.trim_matches(['{', '}']).to_string();
    assert!(request_secret.starts_with("auth_") && collection_secret.starts_with("auth_") && field.starts_with("secret_"));
    assert!(request_secret != collection_secret && request_secret != field, "two credentials share a placeholder");

    // Headers named exactly like both auth secrets are the source's own use of
    // the reserved shape.
    let headers = serde_json::json!([
        { "key": request_secret, "value": "tok-SENSITIVE-pm-h1" },
        { "key": collection_secret, "value": "tok-SENSITIVE-pm-h2" }
    ]);
    assert!(import(doc(headers).as_bytes(), &opts()).is_err(), "a header named like a placeholder was accepted");
}
