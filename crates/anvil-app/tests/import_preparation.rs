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

/// The variable a redacted query parameter's placeholder names.
fn placeholder_of(spec: &RequestSpec) -> String {
    let p = spec.params.iter().find(|p| p.value.starts_with("{{secret_")).expect("a redacted parameter");
    p.value.trim_start_matches("{{").trim_end_matches("}}").to_string()
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
    let resolver = Resolver::new(vec![], None);
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

/// #563: a Postman query list or Insomnia parameter with escapes the engine
/// re-encodes identically is sent with the source's exact bytes, not with
/// its `%` encoded again (`%253A`).
#[test]
fn listed_query_escapes_are_sent_once() {
    let redirect = "redirect_uri=https%3A%2F%2Fapp.example.com%2Fdone";
    let entry = serde_json::json!({ "key": "redirect_uri", "value": "https%3A%2F%2Fapp.example.com%2Fdone" });
    let spec = imported_request(&postman(serde_json::json!({ "raw": "https://api.example.com/cb", "query": [entry] })));
    assert_eq!(prepared_query(&spec), redirect);
    let spec = imported_request(&insomnia_params(
        "https://api.example.com/cb",
        serde_json::json!([{ "name": "redirect_uri", "value": "https%3A%2F%2Fapp.example.com%2Fdone" }]),
    ));
    assert_eq!(prepared_query(&spec), redirect);
}

/// GHSA-c236-7r9g-c9p2: URL userinfo leaves the URL on import, so the
/// imported request prepares (the engine refuses credentials in the URL).
#[test]
fn imported_url_userinfo_leaves_the_url() {
    let url = "https://admin:tok-SENSITIVE-ap1@api.example.com/v1/status";
    for source in [postman(serde_json::json!(url)), insomnia_params(url, serde_json::json!([]))] {
        let spec = imported_request(&source);
        assert_eq!(spec.url, "https://api.example.com/v1/status");
        assert_eq!(prepared_query(&spec), "");
    }
}

/// Review of #573: a credential in a query kept verbatim (escaped braces) is
/// a parameter, so the value supplied for its placeholder is percent-encoded
/// when sent: a `&` in it adds no parameter.
#[test]
fn a_supplied_credential_beside_a_verbatim_query_is_encoded() {
    let spec = imported_request(b"curl 'https://api.example.test/cb?redirect_uri=%7B%7Bcb%7D%7D&client_secret=tok-SENSITIVE-ap2'");
    assert_eq!(spec.url, "https://api.example.test/cb?redirect_uri=%7B%7Bcb%7D%7D");
    let vars = vec![VarEntry { name: placeholder_of(&spec), value: "s3cr&t=x#y".into(), secret: false, literal: false }];
    let resolver = Resolver::new(vec![VarLayer { label: "environment".into(), vars }], None);
    let attachments = MemoryAttachments::default();
    let query = prepare_http(&spec, &resolver, &attachments, &EffectiveSettings::default(), false, &["https"]).unwrap().target.query;
    assert_eq!(query, "redirect_uri=%7B%7Bcb%7D%7D&client_secret=s3cr%26t%3Dx%23y");
}

/// Review rounds 2 and 3 of #573 (sol F1, dsf F1): an escaped credential
/// name taken out of a verbatim query stays data, and so does its
/// placeholder: a secret variable named inside the escaped braces is never
/// read or sent, through the parameter's name or its value.
#[test]
fn an_escaped_credential_name_never_reads_a_variable() {
    let entry = |name: &str, value: &str| VarEntry { name: name.into(), value: value.into(), secret: false, literal: false };
    let attachments = MemoryAttachments::default();
    for (source, expected) in [
        (
            &b"curl 'https://collector.example/?flag&api_key_%7B%7Bvault_token%7D%7D=tok-SENSITIVE-ap3'"[..],
            "flag&api_key_%257B%257Bvault_token%257D%257D=supplied",
        ),
        (&b"curl 'https://collector.example/?flag&%7B%7Bapi_key%7D%7D=1'"[..], "flag&%257B%257Bapi_key%257D%257D=supplied"),
    ] {
        let spec = imported_request(source);
        // Variables named after the escaped names, in either spelling, and
        // the placeholder's own.
        let vars = vec![
            entry("vault_token", "vault-secret-value"),
            entry("api_key", "workspace-secret-value"),
            entry("api_key_7B_7Bvault_token_7D_7D", "field-secret-value"),
            entry("_7B_7Bapi_key_7D_7D", "field-secret-value"),
            entry(&placeholder_of(&spec), "supplied"),
        ];
        let resolver = Resolver::new(vec![VarLayer { label: "environment".into(), vars }], None);
        let query = prepare_http(&spec, &resolver, &attachments, &EffectiveSettings::default(), false, &["https"]).unwrap().target.query;
        assert!(!query.contains("secret-value"), "a variable named in escaped braces was sent");
        assert_eq!(query, expected);
    }
}

/// The URL an OpenAPI import's first request prepares to, with the active
/// server's environment as the only variable layer.
fn prepared_openapi_url(doc: &serde_json::Value) -> String {
    let result = import(doc.to_string().as_bytes(), &ImportOptions::default()).unwrap();
    let env = &result.environments[0];
    let vars = env
        .variables
        .iter()
        .map(|v| match &v.value {
            anvil_domain::secret::SensitiveValue::Template { value } => {
                VarEntry { name: v.name.clone(), value: value.clone(), secret: false, literal: false }
            }
            other => panic!("{other:?}"),
        })
        .collect();
    let resolver = Resolver::new(vec![VarLayer { label: "environment".into(), vars }], None);
    let spec = &result.requests[0].spec;
    let attachments = MemoryAttachments::default();
    prepare_http(spec, &resolver, &attachments, &EffectiveSettings::default(), false, &["https"]).unwrap().target.url()
}

/// Server variables whose names sanitize alike resolve to their own values
/// once imported and prepared, and a variable used twice resolves the same
/// both times (#580).
#[test]
fn openapi_server_variables_that_sanitize_alike_resolve_to_their_own_values() {
    let doc = |url: &str, vars: serde_json::Value| {
        serde_json::json!({
            "openapi": "3.0.3", "info": { "title": "t", "version": "1" },
            "servers": [{ "url": url, "variables": vars }],
            "paths": { "/items": { "get": { "responses": { "200": { "description": "ok" } } } } }
        })
    };
    let declared = doc(
        "https://example.test/{release-name}/{release_name}",
        serde_json::json!({ "release-name": { "default": "v1" }, "release_name": { "default": "v2" } }),
    );
    assert_eq!(prepared_openapi_url(&declared), "https://example.test/v1/v2/items");
    let reused = doc(
        "https://example.test/{release-name}/{release_name}/{release-name}",
        serde_json::json!({ "release-name": { "default": "v1" }, "release_name": { "default": "v2" } }),
    );
    assert_eq!(prepared_openapi_url(&reused), "https://example.test/v1/v2/v1/items");
    let unique =
        doc("https://{region}.example.test/{base}", serde_json::json!({ "region": { "default": "eu" }, "base": { "default": "v3" } }));
    assert_eq!(prepared_openapi_url(&unique), "https://eu.example.test/v3/items");
}
