//! Imported media types survive request preparation with the same effective
//! Content-Type that will be sent.

use anvil_domain::request::RequestSpec;
use anvil_domain::settings::EffectiveSettings;
use anvil_engine::context::MemoryAttachments;
use anvil_engine::prepare::prepare_http;
use anvil_engine::vars::Resolver;
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
    assert_eq!(prepared_content_type(&soap_11).as_deref(), Some("text/xml; charset=utf-8"));
}
