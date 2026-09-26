mod common;

use anvil_domain::request::Body;
use anvil_import::{Dialect, ImportOptions, detect};
use common::*;

const HAR: &str = "har/session.har";
const SECRETS: &[&str] =
    &["AKIA1234567890", "eyJhbGciOiJSUzI1NiJ9.payload.signature", "s%3Aabcdef", "live_key_42", "hunter2", "rt-123", "very-secret"];

fn by_name<'a>(r: &'a anvil_import::ImportResult, name: &str) -> &'a anvil_domain::workspace::RequestDefinition {
    r.requests.iter().find(|q| q.name == name).unwrap_or_else(|| panic!("no request {name}"))
}

#[test]
fn detects_har() {
    let d = detect(&fixture(HAR));
    assert_eq!(d.dialect, Dialect::Har);
    assert_eq!(d.declared_version.as_deref(), Some("1.2"));
}

#[test]
fn credentials_are_redacted_by_default() {
    let r = run(HAR, &opts());
    let me = &by_name(&r, "GET /v1/me").spec;
    assert_eq!(me.url, "https://api.example.com/v1/me");
    assert_eq!(param(me, "api_key").unwrap().value, "{{api_key}}");
    assert_eq!(param(me, "lang").unwrap().value, "en");
    assert_eq!(header(me, "Authorization").unwrap().value, "{{Authorization}}");
    assert_eq!(header(me, "Cookie").unwrap().value, "{{Cookie}}");
    assert_eq!(header(me, "X-Api-Key").unwrap().value, "{{X_Api_Key}}");
    assert!(header(me, "Authorization").unwrap().sensitive);
    // HTTP/2 pseudo-headers and connection headers dropped.
    assert!(me.headers.iter().all(|h| !h.name.starts_with(':') && !h.name.eq_ignore_ascii_case("host")));
    assert!(has(&r, "har_headers_dropped"));

    let login = &by_name(&r, "POST /v1/login").spec;
    let body = json_body(login);
    assert_eq!(body["username"], "alice");
    assert_eq!(body["password"], "{{password}}");
    assert_eq!(body["profile"]["refresh_token"], "{{refresh_token}}");
    assert_eq!(body["profile"]["name"], "A");
    assert!(header(login, "Content-Length").is_none());

    match &by_name(&r, "POST /oauth/token").spec.body {
        Body::FormUrlEncoded { fields } => {
            assert_eq!(fields[1].value, "app");
            assert_eq!(fields[2].value, "{{client_secret}}");
        }
        other => panic!("{other:?}"),
    }
    // Every redaction is reported with its location.
    let pointers: Vec<&str> = r.report.redactions.iter().map(|x| x.pointer.as_str()).collect();
    assert!(pointers.contains(&"/log/entries/0/request/headers/3"));
    assert!(pointers.contains(&"/log/entries/1/request/postData/text/password"));
    // No secret value survives anywhere in the imported objects.
    let all = serde_json::to_string(&(&r.workspace, &r.folders, &r.requests, &r.environments)).unwrap();
    for s in SECRETS {
        assert!(!all.contains(s), "{s} leaked");
    }
    // Unscannable bodies are flagged honestly.
    assert!(has_at(&r, "body_not_scanned", "/log/entries/4/request/postData"));
}

#[test]
fn include_credentials_keeps_originals() {
    let r = run(HAR, &ImportOptions { include_credentials: true, ..opts() });
    let me = &by_name(&r, "GET /v1/me").spec;
    assert_eq!(header(me, "Authorization").unwrap().value, "Bearer eyJhbGciOiJSUzI1NiJ9.payload.signature");
    assert!(header(me, "Authorization").unwrap().sensitive, "kept values are still marked sensitive");
    assert_eq!(param(me, "api_key").unwrap().value, "AKIA1234567890");
    assert!(r.report.redactions.is_empty());
    assert_eq!(json_body(&by_name(&r, "POST /v1/login").spec)["password"], "hunter2");
}

#[test]
fn grouping_and_skips() {
    let r = run(HAR, &opts());
    let hosts: Vec<&str> = r.folders.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(hosts, vec!["api.example.com", "auth.example.com"]);
    assert_eq!(r.requests.len(), 4);
    assert!(has_at(&r, "har_non_http", "/log/entries/3/request/url"));
    assert_eq!(r.report.counts.skipped_operations, 1);
    // Recorded responses (Set-Cookie etc.) are not imported.
    assert!(!serde_json::to_string(&r.requests).unwrap().contains("new-session"));
}

#[test]
fn deterministic() {
    assert_eq!(run(HAR, &opts()), run(HAR, &opts()));
}

fn har_post(headers: serde_json::Value, mime: &str, text: &str) -> anvil_import::ImportResult {
    let doc = serde_json::json!({ "log": { "version": "1.2", "entries": [{ "request": {
        "method": "POST",
        "url": "https://example.test/x",
        "headers": headers,
        "postData": { "mimeType": mime, "text": text },
    } }] } });
    anvil_import::import(doc.to_string().as_bytes(), &opts()).unwrap()
}

fn content_types(r: &anvil_import::ImportResult) -> Vec<&str> {
    r.requests[0].spec.headers.iter().filter(|h| h.name.eq_ignore_ascii_case("content-type")).map(|h| h.value.as_str()).collect()
}

#[test]
fn declared_post_data_media_type_is_kept() {
    for (mime, text, json) in [
        ("application/vnd.api+json", "{}", true),
        ("application/json; charset=utf-8", r#"{"a":1}"#, true),
        ("text/xml; charset=utf-8", "<root/>", false),
        ("text/xml", "<root/>", false),
        ("application/xml; charset=utf-8", "<root/>", false),
    ] {
        let r = har_post(serde_json::json!([]), mime, text);
        let s = &r.requests[0].spec;
        assert_eq!(matches!(s.body, Body::Json { .. }), json, "{mime}: {:?}", s.body);
        assert_eq!(matches!(s.body, Body::Xml { .. }), !json, "{mime}: {:?}", s.body);
        assert_eq!(content_types(&r), vec![mime]);
    }
    // Canonical types are inferred from the body variant.
    assert!(content_types(&har_post(serde_json::json!([]), "application/json", "{}")).is_empty());
    assert!(content_types(&har_post(serde_json::json!([]), "application/xml", "<root/>")).is_empty());
    // A recorded header keeps precedence and is not duplicated.
    let r = har_post(serde_json::json!([{ "name": "Content-Type", "value": "text/xml" }]), "text/xml; charset=utf-8", "<root/>");
    assert_eq!(content_types(&r), vec!["text/xml"]);
}
