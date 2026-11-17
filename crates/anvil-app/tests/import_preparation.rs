//! Imported media types survive request preparation with the same effective
//! Content-Type that will be sent.

use anvil_domain::request::RequestSpec;
use anvil_domain::settings::EffectiveSettings;
use anvil_engine::context::MemoryAttachments;
use anvil_engine::prepare::prepare_http;
use anvil_engine::vars::{Resolver, VarEntry, VarLayer};
use anvil_import::{ImportOptions, import};

fn imported_request(source: &[u8]) -> RequestSpec {
    import(source, &ImportOptions::default()).unwrap().requests.remove(0).spec
}

fn prepared_content_type(spec: &RequestSpec) -> Option<String> {
    let resolver = Resolver::new(vec![], None);
    let attachments = MemoryAttachments::default();
    prepare_http(spec, &resolver, &attachments, &EffectiveSettings::default(), false, &["https"]).unwrap().content_type
}

fn har(mime: &str, body: &str) -> Vec<u8> {
    serde_json::json!({
        "log": { "version": "1.2", "entries": [{ "request": {
            "method": "POST",
            "url": "https://example.test/resource",
            "headers": [],
            "postData": { "mimeType": mime, "text": body }
        } }] }
    })
    .to_string()
    .into_bytes()
}

fn insomnia(mime: &str, body: &str) -> Vec<u8> {
    serde_json::json!({
        "_type": "export",
        "__export_format": 4,
        "resources": [
            { "_id": "wrk_1", "_type": "workspace", "parentId": null, "name": "W", "scope": "collection" },
            {
                "_id": "req_1", "_type": "request", "parentId": "wrk_1", "name": "R", "method": "POST",
                "url": "https://example.test/resource", "body": { "mimeType": mime, "text": body }
            }
        ]
    })
    .to_string()
    .into_bytes()
}

#[test]
fn har_and_insomnia_declared_media_types_reach_preparation() {
    for (mime, body, expected) in [
        ("application/vnd.api+json", "{}", "application/vnd.api+json"),
        ("text/xml", "<root/>", "text/xml"),
        ("application/json; charset=utf-8", "{}", "application/json; charset=utf-8"),
        ("application/xml; charset=utf-8", "<root/>", "application/xml; charset=utf-8"),
    ] {
        for source in [har(mime, body), insomnia(mime, body)] {
            let spec = imported_request(&source);
            assert_eq!(prepared_content_type(&spec).as_deref(), Some(expected), "{mime}");
        }
    }

    for (mime, body, expected) in [("application/json", "{}", "application/json"), ("application/xml", "<root/>", "application/xml")] {
        for source in [har(mime, body), insomnia(mime, body)] {
            let spec = imported_request(&source);
            assert_eq!(prepared_content_type(&spec).as_deref(), Some(expected), "{mime}");
        }
    }
}

#[test]
fn curl_soap_content_types_reach_preparation() {
    let quoted_action = imported_request(
        r#"curl -H 'Content-Type: application/soap+xml; charset=utf-8; action="urn:lookup"' -d '<E/>' https://example.test"#.as_bytes(),
    );
    assert_eq!(prepared_content_type(&quoted_action).as_deref(), Some("application/soap+xml; charset=utf-8; action=\"urn:lookup\""));

    let no_action = imported_request(b"curl -H 'Content-Type: application/soap+xml; charset=utf-8' -d '<E/>' https://example.test");
    assert_eq!(prepared_content_type(&no_action).as_deref(), Some("application/soap+xml; charset=utf-8"));

    let bare = imported_request(b"curl -H 'Content-Type: application/soap+xml' -d '<E/>' https://example.test");
    assert_eq!(prepared_content_type(&bare).as_deref(), Some("application/soap+xml"));

    let soap_11 = imported_request(b"curl -H 'Content-Type: text/xml' -H 'SOAPAction: \"urn:lookup\"' -d '<E/>' https://example.test");
    assert_eq!(prepared_content_type(&soap_11).as_deref(), Some("text/xml"));

    let soap_11_non_default_charset = imported_request(
        b"curl -H 'Content-Type: text/xml; charset=iso-8859-1' -H 'SOAPAction: \"urn:lookup\"' -d '<E/>' https://example.test",
    );
    assert_eq!(prepared_content_type(&soap_11_non_default_charset).as_deref(), Some("text/xml; charset=iso-8859-1"));

    let soap_11_default_charset =
        imported_request(b"curl -H 'Content-Type: text/xml; charset=utf-8' -H 'SOAPAction: \"urn:lookup\"' -d '<E/>' https://example.test");
    assert_eq!(prepared_content_type(&soap_11_default_charset).as_deref(), Some("text/xml; charset=utf-8"));
}

fn prepared_query(spec: &RequestSpec) -> String {
    prepared_query_with(spec, &[])
}

/// The query `spec` sends with `vars` defined (plain variables).
fn prepared_query_with(spec: &RequestSpec, vars: &[(&str, &str)]) -> String {
    let vars = vars.iter().map(|(n, v)| VarEntry { name: n.to_string(), value: v.to_string(), secret: false, literal: false }).collect();
    let resolver = Resolver::new(vec![VarLayer { label: "environment".into(), vars }], None);
    let attachments = MemoryAttachments::default();
    prepare_http(spec, &resolver, &attachments, &EffectiveSettings::default(), false, &["https"]).unwrap().target.query
}

fn postman(url: serde_json::Value) -> Vec<u8> {
    serde_json::json!({
        "info": { "name": "c", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json" },
        "item": [{ "name": "r", "request": { "method": "GET", "url": url } }]
    })
    .to_string()
    .into_bytes()
}

fn insomnia_params(url: &str, params: serde_json::Value) -> Vec<u8> {
    serde_json::json!({
        "_type": "export",
        "__export_format": 4,
        "resources": [
            { "_id": "wrk_1", "_type": "workspace", "parentId": null, "name": "W", "scope": "collection" },
            { "_id": "req_1", "_type": "request", "parentId": "wrk_1", "name": "R", "method": "GET", "url": url, "parameters": params }
        ]
    })
    .to_string()
    .into_bytes()
}

fn har_get(url: &str) -> Vec<u8> {
    serde_json::json!({ "log": { "version": "1.2", "entries": [{ "request": { "method": "GET", "url": url, "headers": [] } }] } })
        .to_string()
        .into_bytes()
}

/// An imported request sends the query bytes its source sends: no `%25`
/// from encoding an escape twice, a `+` sent as curl sends it in a URL (or
/// as `%2B`, as Insomnia sends it), and no U+FFFD for an escape that is not
/// UTF-8 (#563).
#[test]
fn imported_queries_send_the_source_query_bytes() {
    let redirect = "redirect_uri=https%3A%2F%2Fapp.example.com%2Fdone";
    // Decodable: stored as decoded parameters, sent with the same escapes.
    let decodable = format!("{redirect}&q=caf%C3%A9");
    // Not decodable: kept in the URL as written.
    let verbatim = format!("{redirect}&q=hello+world&ts=2024-01-01T00:00:00+01:00&n=caf%E9&d=50%");
    for query in [&decodable, &verbatim] {
        let url = format!("https://api.example.com/search?{query}");
        let curl = format!("curl '{url}'");
        assert_eq!(&prepared_query(&imported_request(curl.as_bytes())), query, "cURL");
        assert_eq!(&prepared_query(&imported_request(&har_get(&url))), query, "HAR");
        assert_eq!(&prepared_query(&imported_request(&postman(serde_json::json!(url)))), query, "Postman raw URL");
    }

    // Postman sends its query list as written. List entries stay
    // parameters: a `+` is read as a space, as form-decoding servers read
    // Postman's bare `+`, and sent as `%20`.
    let list = |entries: serde_json::Value| postman(serde_json::json!({ "raw": "https://api.example.com/search", "query": entries }));
    let redirect_entry = serde_json::json!({ "key": "redirect_uri", "value": "https%3A%2F%2Fapp.example.com%2Fdone" });
    let spec = imported_request(&list(serde_json::json!([redirect_entry.clone()])));
    assert_eq!(prepared_query(&spec), redirect);
    let spec = imported_request(&list(serde_json::json!([redirect_entry, { "key": "q", "value": "a+b" }])));
    assert_eq!(prepared_query(&spec), format!("{redirect}&q=a%20b"));

    // Insomnia keeps a parameter's escapes and encodes the rest, `+` too.
    let spec = imported_request(&insomnia_params(
        "https://api.example.com/search",
        serde_json::json!([
            { "name": "redirect_uri", "value": "https%3A%2F%2Fapp.example.com%2Fdone" },
            { "name": "q", "value": "a+b" }
        ]),
    ));
    assert_eq!(prepared_query(&spec), format!("{redirect}&q=a%2Bb"));
}

/// A `{{reference}}` in a listed parameter is encoded after it resolves, so
/// a resolved `&`, `#` or `+` stays data, as Insomnia and Postman send it
/// (review sol F4).
#[test]
fn listed_parameters_encode_resolved_references() {
    let term = [("term", "a&b#c+d")];
    let insomnia = imported_request(&insomnia_params(
        "https://api.example.com/search",
        serde_json::json!([{ "name": "n", "value": "caf%E9" }, { "name": "q", "value": "{{ _.term }}" }, { "name": "z", "value": "1" }]),
    ));
    assert_eq!(prepared_query_with(&insomnia, &term), "n=caf%25E9&q=a%26b%23c%2Bd&z=1");
    let postman_spec = imported_request(&postman(serde_json::json!({ "raw": "https://api.example.com/search", "query": [
        { "key": "n", "value": "a+b" }, { "key": "q", "value": "{{term}}" }, { "key": "z", "value": "1" }
    ] })));
    assert_eq!(prepared_query_with(&postman_spec, &term), "n=a%20b&q=a%26b%23c%2Bd&z=1");
}

/// A redacted credential from an undecodable URL query is a parameter, so
/// the value supplied for its placeholder is percent-encoded when sent: a
/// `&`, `=`, `#` or `+` in it stays data (review dsf F1).
#[test]
fn a_supplied_credential_from_a_url_query_is_encoded() {
    let spec = imported_request(b"curl 'https://api.example.com/search?q=a+b&api_key=key-literal-571'");
    assert_eq!(spec.url, "https://api.example.com/search");
    assert_eq!(prepared_query_with(&spec, &[("api_key", "a&admin=1#x+y")]), "q=a%20b&api_key=a%26admin%3D1%23x%2By");
}

/// Escaped braces stay literal text, never a variable reference, with or
/// without a variable of that name (review sol F5). Escaped text next to a
/// real reference keeps the reference intact (round 2, sol F4).
#[test]
fn escaped_braces_never_become_references() {
    let id = [("id", "42")];
    let none: &[(&str, &str)] = &[];
    let curl = imported_request(b"curl 'https://api.example.com/search?q=%7B%7Bid%7D%7D'");
    for vars in [&id[..], none] {
        assert_eq!(prepared_query_with(&curl, vars), "q=%7B%7Bid%7D%7D");
    }
    let listed = imported_request(&postman(serde_json::json!({ "raw": "https://api.example.com/search", "query": [
        { "key": "q", "value": "%7B%7Bid%7D%7D" }
    ] })));
    for vars in [&id[..], none] {
        let query = prepared_query_with(&listed, vars);
        assert!(!query.contains("42") && query.contains("7B"), "{query}");
    }
    let mixed = imported_request(&postman(serde_json::json!({ "raw": "https://api.example.com/search", "query": [
        { "key": "q", "value": "%7B{{id}}" }
    ] })));
    assert_eq!(prepared_query_with(&mixed, &id), "q=%257B42");
}

/// GHSA-c236-7r9g-c9p2: URL userinfo leaves the URL on import, so the
/// imported request prepares (the engine refuses credentials in the URL).
#[test]
fn imported_url_userinfo_leaves_the_url() {
    let url = "https://admin:hunter2-literal@api.example.com/v1/status";
    for source in [postman(serde_json::json!(url)), insomnia_params(url, serde_json::json!([]))] {
        let spec = imported_request(&source);
        assert_eq!(spec.url, "https://api.example.com/v1/status");
        assert_eq!(prepared_query(&spec), "");
    }
}
