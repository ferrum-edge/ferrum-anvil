//! One corpus of credential shapes, run through every migration importer
//! (cURL, HAR, Postman, Insomnia) with the default options: no literal
//! credential may survive in the stored objects, nor in the readable
//! `objects.json` the export sanitizer would write. Every literal secret in
//! the corpus carries the marker `zq571` (numbers: `571571571`), so a new
//! shape only needs a new row.

use anvil_import::{ImportOptions, ImportResult, import};
use serde_json::{Value, json};

const MARKER: &str = "zq571";
const NUMBER: &str = "571571571";

/// A request shape every importer can express.
struct Shape {
    name: &'static str,
    url: &'static str,
    headers: &'static [(&'static str, &'static str)],
    json_body: Option<&'static str>,
}

const NESTED_BODY: &str = r#"{"credentials":{"pin":571571571,"v":"zq571-nested"},"tokens":["zq571-array"],"auth":{"otp":571571571,"mfa":"zq571-mfa"},"note":"ok"}"#;

const SHAPES: &[Shape] = &[
    Shape { name: "userinfo password holding @", url: "https://admin:p@zq571-userinfo@api.example.test/v1", headers: &[], json_body: None },
    Shape { name: "escaped @ in a userinfo password", url: "https://u:zq571%40escaped@api.example.test/v1", headers: &[], json_body: None },
    Shape {
        name: "escaped braces as a userinfo password",
        url: "https://u:%7B%7Bzq571%7D%7D@api.example.test/v1",
        headers: &[],
        json_body: None,
    },
    Shape { name: "encoded credential name", url: "https://api.example.test/v1?%70assword=zq571-encoded", headers: &[], json_body: None },
    Shape {
        name: "encoded credential name that is not UTF-8",
        url: "https://api.example.test/v1?%70assword%E9=zq571-undecodable",
        headers: &[],
        json_body: None,
    },
    Shape { name: "credential beside a plus", url: "https://api.example.test/v1?q=a+b&api_key=zq571-plus", headers: &[], json_body: None },
    Shape {
        name: "credential beside a bare flag",
        url: "https://api.example.test/v1?flag&token=zq571-flag",
        headers: &[],
        json_body: None,
    },
    Shape {
        name: "credential header mixing a reference and a literal",
        url: "https://api.example.test/v1",
        headers: &[("X-Api-Key", "{{tenant}}-zq571-header")],
        json_body: None,
    },
    Shape {
        name: "nested credential objects, arrays and numbers",
        url: "https://api.example.test/v1",
        headers: &[],
        json_body: Some(NESTED_BODY),
    },
];

fn curl(s: &Shape) -> Vec<u8> {
    let mut cmd = String::from("curl -X POST");
    for (k, v) in s.headers {
        cmd.push_str(&format!(" -H '{k}: {v}'"));
    }
    if let Some(body) = s.json_body {
        cmd.push_str(&format!(" --json '{body}'"));
    }
    cmd.push_str(&format!(" '{}'", s.url));
    cmd.into_bytes()
}

fn har(s: &Shape) -> Vec<u8> {
    let headers: Vec<Value> = s.headers.iter().map(|(k, v)| json!({ "name": k, "value": v })).collect();
    let mut request = json!({ "method": "POST", "url": s.url, "headers": headers });
    if let Some(body) = s.json_body {
        request["postData"] = json!({ "mimeType": "application/json", "text": body });
    }
    json!({ "log": { "version": "1.2", "entries": [{ "request": request }] } }).to_string().into_bytes()
}

fn postman(s: &Shape) -> Vec<u8> {
    let headers: Vec<Value> = s.headers.iter().map(|(k, v)| json!({ "key": k, "value": v })).collect();
    let mut request = json!({ "method": "POST", "url": s.url, "header": headers });
    if let Some(body) = s.json_body {
        request["body"] = json!({ "mode": "raw", "raw": body, "options": { "raw": { "language": "json" } } });
    }
    json!({
        "info": { "name": "c", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json" },
        "item": [{ "name": "r", "request": request }]
    })
    .to_string()
    .into_bytes()
}

fn insomnia(s: &Shape) -> Vec<u8> {
    let headers: Vec<Value> = s.headers.iter().map(|(k, v)| json!({ "name": k, "value": v })).collect();
    let mut request =
        json!({ "_id": "req_1", "_type": "request", "parentId": "wrk_1", "name": "R", "method": "POST", "url": s.url, "headers": headers });
    if let Some(body) = s.json_body {
        request["body"] = json!({ "mimeType": "application/json", "text": body });
    }
    json!({
        "_type": "export",
        "__export_format": 4,
        "resources": [{ "_id": "wrk_1", "_type": "workspace", "parentId": null, "name": "W", "scope": "collection" }, request]
    })
    .to_string()
    .into_bytes()
}

/// The stored objects of an import, shaped like the export graph.
fn stored(r: &ImportResult) -> Value {
    json!({
        "workspace": serde_json::to_value(&r.workspace).unwrap(),
        "folders": serde_json::to_value(&r.folders).unwrap(),
        "environments": serde_json::to_value(&r.environments).unwrap(),
        "requests": serde_json::to_value(&r.requests).unwrap(),
    })
}

/// No literal secret in the stored objects, nor in the `objects.json` text
/// the export sanitizer leaves readable (share safely and encrypted
/// transfer alike).
fn assert_no_literal(source: &[u8], label: &str) {
    let r = import(source, &ImportOptions::default()).unwrap_or_else(|e| panic!("{label}: import failed: {e}"));
    assert!(!r.requests.is_empty(), "{label}: no request imported");
    let mut objects = stored(&r);
    let text = objects.to_string();
    assert!(!text.contains(MARKER) && !text.contains(NUMBER), "{label}: a literal credential survived the import");
    anvil_portability::sanitize::sanitize(&mut objects, &[]);
    let exported = objects.to_string();
    assert!(!exported.contains(MARKER) && !exported.contains(NUMBER), "{label}: a literal credential survived the export");
}

#[test]
fn no_importer_keeps_a_literal_credential() {
    let importers: [(&str, fn(&Shape) -> Vec<u8>); 4] = [("cURL", curl), ("HAR", har), ("Postman", postman), ("Insomnia", insomnia)];
    for shape in SHAPES {
        for (importer, build) in importers {
            assert_no_literal(&build(shape), &format!("{importer}, {}", shape.name));
        }
    }
}

/// Shapes only cURL has: `-G` data moved into the query, and `-u` beside
/// URL userinfo.
#[test]
fn no_curl_option_keeps_a_literal_credential() {
    for (label, cmd) in [
        ("-G data", "curl -G -d 'api_key=zq571-get' -d 'q=a+b' https://api.example.test/v1"),
        ("-G data with a bare flag", "curl -G -d 'flag&token=zq571-get-flag' https://api.example.test/v1"),
        ("-u beside URL userinfo", "curl -u alice:zq571-user 'https://bob:zq571-url@api.example.test/v1'"),
        ("form data", "curl -d 'user=u&password=zq571-form' https://api.example.test/v1"),
    ] {
        assert_no_literal(cmd.as_bytes(), &format!("cURL, {label}"));
    }
}
