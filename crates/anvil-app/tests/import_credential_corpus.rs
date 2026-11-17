//! One corpus of credential shapes, run through every migration importer
//! (cURL, HAR, Postman, Insomnia) and the export sanitizer.
//!
//! * With the default options no literal credential may survive in the
//!   stored objects or in the readable `objects.json` an export writes.
//! * With `include_credentials` the literals are kept, and the export must
//!   then extract each one kept in a field (so a broken sanitizer fails this
//!   test), or warn about one kept in free text, as documented.
//!
//! Every literal secret carries the allowlisted canary prefix
//! `tok-SENSITIVE-c` (numbers start `57157157`), so a new shape needs only a
//! new row.

use anvil_import::{ImportOptions, ImportResult, import};
use serde_json::{Value, json};

const MARKER: &str = "tok-SENSITIVE-c";
const NUMBER: &str = "57157157";

/// What a share-safely or encrypted-transfer export must do with the
/// literals an import kept under `include_credentials`.
#[derive(Clone, Copy, Debug)]
enum Export {
    /// Kept in a field (an auth secret, a credential-named header, query or
    /// form field): extracted, never left in `objects.json`.
    Extract,
    /// Kept in free text (a JSON body, a variable's JSON text): exported as
    /// written, with a content warning.
    Warn,
    /// Not kept at all, or kept in URL text the export only scans.
    Skip,
}

/// A request shape every importer can express.
struct Shape {
    name: &'static str,
    url: &'static str,
    headers: &'static [(&'static str, &'static str)],
    json_body: Option<&'static str>,
    /// For cURL, HAR, Postman and Insomnia, in that order.
    export: [Export; 4],
}

const NESTED_BODY: &str = r#"{"credentials":{"pin":571571571,"password":"tok-SENSITIVE-c7"},"auth":{"otp":571571572},"note":"ok"}"#;

const ALL: [Export; 4] = [Export::Extract; 4];

const SHAPES: &[Shape] = &[
    Shape {
        name: "userinfo password holding @",
        url: "https://admin:p@tok-SENSITIVE-c1@api.example.test/v1",
        headers: &[],
        json_body: None,
        export: ALL,
    },
    Shape {
        name: "escaped @ in a userinfo password",
        url: "https://u:tok-SENSITIVE-c2%40x@api.example.test/v1",
        headers: &[],
        json_body: None,
        export: ALL,
    },
    Shape {
        name: "escaped braces as a userinfo password",
        url: "https://u:%7B%7Btok-SENSITIVE-c3%7D%7D@api.example.test/v1",
        headers: &[],
        json_body: None,
        export: [Export::Skip; 4],
    },
    Shape {
        name: "credential query parameter",
        url: "https://api.example.test/v1?api_key=tok-SENSITIVE-c4&page=2",
        headers: &[],
        json_body: None,
        export: ALL,
    },
    Shape {
        name: "encoded credential query name",
        url: "https://api.example.test/v1?%70assword=tok-SENSITIVE-c5",
        headers: &[],
        json_body: None,
        export: ALL,
    },
    Shape {
        name: "credential beside a bare flag",
        url: "https://api.example.test/v1?flag&token=tok-SENSITIVE-c14",
        headers: &[],
        json_body: None,
        export: ALL,
    },
    Shape {
        name: "escaped credential name beside a bare flag",
        url: "https://api.example.test/v1?flag&api_key_%7B%7Bvault_token%7D%7D=tok-SENSITIVE-c16",
        headers: &[],
        json_body: None,
        export: ALL,
    },
    Shape {
        name: "credential beside escaped braces",
        url: "https://api.example.test/v1?q=%7B%7Bid%7D%7D&client_secret=tok-SENSITIVE-c15",
        headers: &[],
        json_body: None,
        export: ALL,
    },
    Shape {
        name: "credential header mixing a reference and a literal",
        url: "https://api.example.test/v1",
        headers: &[("X-Api-Key", "{{tenant}}-tok-SENSITIVE-c6")],
        json_body: None,
        export: ALL,
    },
    // A dynamic helper with arguments is literal in every source: Anvil
    // would evaluate it and send its arguments.
    Shape {
        name: "helper expression in a credential header",
        url: "https://api.example.test/v1",
        headers: &[("X-Api-Key", "{{$randomFrom tok-SENSITIVE-c20 x}}")],
        json_body: None,
        export: ALL,
    },
    // A token in the user name, with no password or an empty one: kept with
    // include_credentials as the Basic user name, which the export extracts.
    Shape {
        name: "token alone in the userinfo",
        url: "https://tok-SENSITIVE-c26@api.example.test/v1",
        headers: &[],
        json_body: None,
        export: ALL,
    },
    Shape {
        name: "token with an empty password in the userinfo",
        url: "https://tok-SENSITIVE-c27:@api.example.test/v1",
        headers: &[],
        json_body: None,
        export: ALL,
    },
    // A quoted `}}` and a delimiter inside a password expression do not end
    // the authority early (review of #575, sol F1).
    Shape {
        name: "quoted braces and a slash in a userinfo password expression",
        url: r#"https://admin:{{ "tok-SENSITIVE-c28}}/s" | urlencode }}@api.example.test/v1"#,
        headers: &[],
        json_body: None,
        export: ALL,
    },
    Shape {
        name: "quoted braces and a question mark in a userinfo password expression",
        url: r#"https://admin:{{ "tok-SENSITIVE-c30}}?s" | urlencode }}@api.example.test/v1"#,
        headers: &[],
        json_body: None,
        export: ALL,
    },
    Shape {
        name: "quoted braces and a hash in a userinfo password expression",
        url: r#"https://admin:{{ "tok-SENSITIVE-c31}}#s" | urlencode }}@api.example.test/v1"#,
        headers: &[],
        json_body: None,
        export: ALL,
    },
    // Round 2 of #575: a credential URL inside an expression, and a `:`
    // inside a user name expression.
    Shape {
        name: "credential URL inside an expression",
        url: r#"https://{{ "https://admin:tok-SENSITIVE-c43@api.example.test" | replace("https://", "") }}/v1"#,
        headers: &[],
        json_body: None,
        export: ALL,
    },
    Shape {
        name: "colon inside a user name expression",
        url: r#"https://{{ "tok-SENSITIVE-c44:rest" }}@api.example.test/v1"#,
        headers: &[],
        json_body: None,
        export: ALL,
    },
    // An expression opened in the password and closed only in the query does
    // not hide the userinfo (review of #575, dsf F2).
    Shape {
        name: "unclosed expression in a userinfo password",
        url: "https://user:tok-SENSITIVE-c29{{ss@api.example.test/v1?q={{x}}",
        headers: &[],
        json_body: None,
        export: ALL,
    },
    Shape {
        name: "escaped braces as a credential query name",
        url: "https://api.example.test/v1?flag&%7B%7Bapi_key%7D%7D=tok-SENSITIVE-c23",
        headers: &[],
        json_body: None,
        export: ALL,
    },
    Shape {
        name: "nested credential objects and numbers in a JSON body",
        url: "https://api.example.test/v1",
        headers: &[],
        json_body: Some(NESTED_BODY),
        export: [Export::Warn; 4],
    },
];

type Build = fn(&Shape) -> Vec<u8>;

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

fn postman_doc(request: Value) -> Vec<u8> {
    json!({
        "info": { "name": "c", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json" },
        "item": [{ "name": "r", "request": request }]
    })
    .to_string()
    .into_bytes()
}

fn postman(s: &Shape) -> Vec<u8> {
    let headers: Vec<Value> = s.headers.iter().map(|(k, v)| json!({ "key": k, "value": v })).collect();
    let mut request = json!({ "method": "POST", "url": s.url, "header": headers });
    if let Some(body) = s.json_body {
        request["body"] = json!({ "mode": "raw", "raw": body, "options": { "raw": { "language": "json" } } });
    }
    postman_doc(request)
}

fn insomnia_doc(request: Value, env: Value) -> Vec<u8> {
    json!({
        "_type": "export",
        "__export_format": 4,
        "resources": [
            { "_id": "wrk_1", "_type": "workspace", "parentId": null, "name": "W", "scope": "collection" },
            { "_id": "env_base", "_type": "environment", "parentId": "wrk_1", "name": "Base", "data": env },
            request
        ]
    })
    .to_string()
    .into_bytes()
}

fn insomnia_request(url: &str) -> Value {
    json!({ "_id": "req_1", "_type": "request", "parentId": "wrk_1", "name": "R", "method": "POST", "url": url })
}

fn insomnia(s: &Shape) -> Vec<u8> {
    let headers: Vec<Value> = s.headers.iter().map(|(k, v)| json!({ "name": k, "value": v })).collect();
    let mut request = insomnia_request(s.url);
    request["headers"] = json!(headers);
    if let Some(body) = s.json_body {
        request["body"] = json!({ "mimeType": "application/json", "text": body });
    }
    insomnia_doc(request, json!({}))
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

fn leaks(text: &str) -> bool {
    text.contains(MARKER) || text.contains(NUMBER)
}

/// Import `source` both ways and check the outcome `export` describes.
fn check(source: &[u8], export: Export, label: &str) {
    let redacted = import(source, &ImportOptions::default()).unwrap_or_else(|e| panic!("{label}: import failed: {e}"));
    assert!(!redacted.requests.is_empty(), "{label}: no request imported");
    let mut objects = stored(&redacted);
    assert!(!leaks(&objects.to_string()), "{label}: a literal credential survived the default import");
    anvil_portability::sanitize::sanitize(&mut objects, &[]);
    assert!(!leaks(&objects.to_string()), "{label}: a literal credential survived the export");

    let kept = import(source, &ImportOptions { include_credentials: true, ..ImportOptions::default() })
        .unwrap_or_else(|e| panic!("{label}: import failed: {e}"));
    let mut objects = stored(&kept);
    match export {
        Export::Extract => {
            assert!(leaks(&objects.to_string()), "{label}: include_credentials did not keep the literal");
            let s = anvil_portability::sanitize::sanitize(&mut objects, &[]);
            assert!(!leaks(&objects.to_string()), "{label}: the export left a kept credential readable");
            assert!(s.extracted.iter().any(|e| leaks(&e.value)), "{label}: the export did not extract the kept credential");
        }
        Export::Warn => {
            assert!(leaks(&objects.to_string()), "{label}: include_credentials did not keep the literal");
            let s = anvil_portability::sanitize::sanitize(&mut objects, &[]);
            assert!(!s.warnings.is_empty(), "{label}: the export did not warn about a kept free-text credential");
        }
        Export::Skip => {}
    }
}

#[test]
fn every_importer_redacts_and_every_export_extracts() {
    let importers: [(&str, Build); 4] = [("cURL", curl), ("HAR", har), ("Postman", postman), ("Insomnia", insomnia)];
    // Round 2 of #575: a password expression longer than any scan bound.
    let long: &'static str = Box::leak(
        format!("https://admin:{{{{{}\"tok-SENSITIVE-c45/x\"|urlencode}}}}@api.example.test/v1", " ".repeat(8192)).into_boxed_str(),
    );
    let long_shape = Shape { name: "password expression past 4 KiB", url: long, headers: &[], json_body: None, export: ALL };
    for shape in SHAPES.iter().chain(std::iter::once(&long_shape)) {
        for (i, (importer, build)) in importers.iter().enumerate() {
            check(&build(shape), shape.export[i], &format!("{importer}, {}", shape.name));
        }
    }
}

/// Shapes only some importers have.
#[test]
fn importer_specific_shapes_are_redacted() {
    let path = json!({ "method": "POST", "url": {
        "raw": "https://hooks.example.test/:webhook_token/x",
        "variable": [{ "key": "webhook_token", "value": "tok-SENSITIVE-c8" }]
    }});
    let mut insomnia_path = insomnia_request("https://hooks.example.test/:webhook_token/x");
    insomnia_path["pathParameters"] = json!([{ "name": "webhook_token", "value": "tok-SENSITIVE-c8" }]);
    let env = json!({ "accounts": [{ "api_key": "tok-SENSITIVE-c9", "pin": 571571573, "tokens": ["tok-SENSITIVE-c9b"] }] });
    let quoted = json!({ "accounts": [{ "api_key": "{{ 'tok-SENSITIVE-c17' }}" }] });
    let numeric = json!({ "accounts": [{ "pin": "{{ 571571575 }}" }] });
    let scalar = json!({ "api_key": "{{ 'tok-SENSITIVE-c24' }}" });
    // Insomnia evaluates Nunjucks: a quoted string, a number or an operator
    // inside `{{…}}` is a literal there (Postman, cURL and HAR read the same
    // text as a variable name).
    let insomnia_header = |value: &str| {
        let mut request = insomnia_request("https://api.example.test/v1");
        request["headers"] = json!([{ "name": "X-Api-Key", "value": value }]);
        insomnia_doc(request, json!({}))
    };
    let subtraction = json!({ "zero": 0, "accounts": [{ "api_key": "{{ _.zero--571571576 }}" }] });
    let mut insomnia_quoted_path = insomnia_request("https://hooks.example.test/:api_key/x");
    insomnia_quoted_path["pathParameters"] = json!([{ "name": "api_key", "value": "{{ 'tok-SENSITIVE-c22' }}" }]);
    let sub_env = json!({
        "type": "collection.insomnia.rest/5.0", "name": "W",
        "environments": {
            "name": "Base", "data": { "accounts_0_api_key": "base-value" },
            "subEnvironments": [{ "name": "Sub", "data": { "accounts": [{ "api_key": "tok-SENSITIVE-c18" }] } }]
        },
        "collection": [{ "name": "R", "meta": { "id": "req_1" }, "method": "GET", "url": "https://api.example.test/v1" }],
    })
    .to_string()
    .into_bytes();
    let rows: Vec<(&str, Vec<u8>, Export)> = vec![
        // A path is URL text: redacted on import, only scanned on export.
        ("Postman, credential path variable", postman_doc(path), Export::Skip),
        ("Insomnia, credential path parameter", insomnia_doc(insomnia_path, json!({})), Export::Skip),
        ("Insomnia, environment array", insomnia_doc(insomnia_request("https://api.example.test/v1"), env), Export::Warn),
        (
            "Insomnia, quoted expression in an environment array",
            insomnia_doc(insomnia_request("https://api.example.test/v1"), quoted),
            Export::Warn,
        ),
        ("Insomnia v5, sub-environment array", sub_env, Export::Warn),
        // Kept JSON text with a literal credential member is warned about.
        (
            "Insomnia, numeric expression in an environment array",
            insomnia_doc(insomnia_request("https://api.example.test/v1"), numeric),
            Export::Warn,
        ),
        (
            "Insomnia, subtraction expression in an environment array",
            insomnia_doc(insomnia_request("https://api.example.test/v1"), subtraction),
            Export::Warn,
        ),
        ("Insomnia, quoted expression in a credential header", insomnia_header("{{ 'tok-SENSITIVE-c19' }}"), Export::Extract),
        ("Insomnia, numeric expression in a credential header", insomnia_header("{{ 571571574 }}"), Export::Extract),
        ("Insomnia, subtraction expression in a credential header", insomnia_header("{{ _.zero--571571577 }}"), Export::Extract),
        (
            "Insomnia, quoted expression as a userinfo password",
            insomnia_doc(insomnia_request(r#"https://admin:{{"tok-SENSITIVE-c21"}}@api.example.test/v1"#), json!({})),
            Export::Extract,
        ),
        (
            "Insomnia, delimiter inside a userinfo password expression",
            insomnia_doc(insomnia_request("https://admin:{{ 'tok-SENSITIVE-c25/x?y#z' | urlencode }}@api.example.test/v1"), json!({})),
            Export::Extract,
        ),
        // A secret variable is extracted on export.
        (
            "Insomnia, quoted expression as a credential variable",
            insomnia_doc(insomnia_request("https://api.example.test/v1"), scalar),
            Export::Extract,
        ),
        ("Insomnia, quoted credential path parameter", insomnia_doc(insomnia_quoted_path, json!({})), Export::Skip),
        ("cURL, -G data", b"curl -G -d 'api_key=tok-SENSITIVE-c10' https://api.example.test/v1".to_vec(), Export::Extract),
        (
            "cURL, -u beside URL userinfo",
            b"curl -u alice:tok-SENSITIVE-c11 'https://bob:tok-SENSITIVE-c12@api.example.test/v1'".to_vec(),
            Export::Extract,
        ),
        ("cURL, form data", b"curl -d 'user=u&password=tok-SENSITIVE-c13' https://api.example.test/v1".to_vec(), Export::Extract),
    ];
    for (label, source, export) in rows {
        check(&source, export, label);
    }
}
