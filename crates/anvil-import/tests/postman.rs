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
