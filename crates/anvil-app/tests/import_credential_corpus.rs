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
    // Round 3 of #575: quoted braces on both sides of a delimiter, and an `@`
    // in the user name before an expression.
    Shape {
        name: "quoted brace pairs around a slash in a password expression",
        url: r#"https://admin:{{"tok-SENSITIVE-c46}}/x{{"|urlencode}}@api.example.test/v1"#,
        headers: &[],
        json_body: None,
        export: ALL,
    },
    Shape {
        name: "an at sign in the user name before a password expression",
        url: r#"https://alice@example.test:{{"tok-SENSITIVE-c47/x"|urlencode}}@api.example.test/v1"#,
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
    // The report is shown in the preview and may be logged, in either mode.
    assert!(!leaks(&serde_json::to_string(&redacted.report).unwrap()), "{label}: the default import's report holds a literal credential");
    anvil_portability::sanitize::sanitize(&mut objects, &[]);
    assert!(!leaks(&objects.to_string()), "{label}: a literal credential survived the export");

    let kept = import(source, &ImportOptions { include_credentials: true, ..ImportOptions::default() })
        .unwrap_or_else(|e| panic!("{label}: import failed: {e}"));
    assert!(!leaks(&serde_json::to_string(&kept.report).unwrap()), "{label}: the include_credentials report holds a literal credential");
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

/// Round 3 of #575, dsf F1: a URL is never cut at a path or query `@`, so
/// the request cannot be retargeted at another host. With the whole
/// authority in one reference it is kept as written; with any other
/// template there beside an `@` (here in the query, after a JSON `}}`) it is
/// quarantined: not imported at all (the request uses a placeholder no
/// variable defines and the text is stored nowhere), or kept exactly as
/// written with include_credentials, reported either way.
#[test]
fn an_ambiguous_url_never_changes_host() {
    let importers: [(&str, Build); 4] = [("cURL", curl), ("HAR", har), ("Postman", postman), ("Insomnia", insomnia)];
    let kept_url = r#"https://{{baseUrl}}/items?filter={"a":{"b":1}}&to=user@example.com"#;
    let quarantined_url = r#"https://api.{{region}}.example.test/items?filter={"a":{"b":1}}&to=user@example.com"#;
    for (importer, build) in importers {
        let shape = |url| Shape { name: "ambiguous URL", url, headers: &[], json_body: None, export: [Export::Skip; 4] };
        let r = import(&build(&shape(kept_url)), &ImportOptions::default()).unwrap_or_else(|e| panic!("{importer}: {e}"));
        assert!(r.requests[0].spec.url.starts_with("https://{{baseUrl}}/items"), "{importer}: the host changed");
        assert!(!r.report.has_code("url_quarantined"), "{importer}: a reference authority was quarantined");
        let r = import(&build(&shape(quarantined_url)), &ImportOptions::default()).unwrap_or_else(|e| panic!("{importer}: {e}"));
        assert_eq!(r.requests[0].spec.url, "{{url-needs-review}}", "{importer}: the URL was imported");
        assert!(r.report.has_code("url_quarantined"), "{importer}: no quarantine warning");
        let text = format!("{}{}", stored(&r), serde_json::to_string(&r.report).unwrap());
        assert!(!text.contains("example.test") && !text.contains("user@example.com"), "{importer}: the URL text was stored");
        let kept =
            import(&build(&shape(quarantined_url)), &ImportOptions { include_credentials: true, ..ImportOptions::default() }).unwrap();
        let url = &kept.requests[0].spec.url;
        assert!(
            url.starts_with("https://api.{{region}}.example.test/items?") && url.ends_with("to=user@example.com"),
            "{importer}: the URL was not kept as written"
        );
        assert!(kept.report.has_code("url_quarantined"), "{importer}: no quarantine warning with credentials");
        assert!(kept.workspace.variables.is_empty(), "{importer}: a variable was created");
        // Final gate of #575 (sol F3): names, folders and provenance never
        // come from the kept URL's text, and a sanitized export extracts the
        // URL whole and restores it.
        let request = &kept.requests[0];
        let source = serde_json::to_string(&request.spec.source).unwrap();
        let folders = serde_json::to_string(&kept.folders).unwrap();
        assert!(
            !request.name.contains("example") && !source.contains("example") && !folders.contains("example"),
            "{importer}: a name or the provenance came from the kept URL"
        );
        let mut objects = stored(&kept);
        let before = objects.clone();
        let s = anvil_portability::sanitize::sanitize(&mut objects, &[]);
        let text = objects.to_string();
        assert!(!text.contains("example.test") && !text.contains("user@example.com"), "{importer}: the export kept the URL readable");
        assert!(s.extracted.iter().any(|e| e.pointer == "/requests/0/spec/url"), "{importer}: the URL was not extracted");
        anvil_portability::sanitize::restore(&mut objects, &s.extracted).unwrap();
        assert_eq!(objects, before, "{importer}: the URL was not restored");
    }
}

/// Final gate of #575 (sol F1, dsf F2): cURL diagnostics never echo an
/// ignored URL, a connection option's value or the rest of a command line.
#[test]
fn curl_diagnostics_never_echo_credentials() {
    for cmd in [
        "curl https://safe.example.test/ 'https://admin:tok-SENSITIVE-c60@api.example.test/v1'",
        "curl https://safe.example.test/ 'admin:tok-SENSITIVE-c61@api.example.test/v1'",
        "curl https://safe.example.test/ 'https://api.{{region}}.example.test/v1?to=a:tok-SENSITIVE-c62@b'",
        "curl --proxy 'http://u:tok-SENSITIVE-c63@proxy.example.test' https://safe.example.test/",
        "curl https://safe.example.test/ ; curl 'https://u:tok-SENSITIVE-c64@h.example.test/'",
        "curl https://safe.example.test/ && curl -H 'Authorization: Bearer tok-SENSITIVE-c65' https://h.example.test/",
        "curl --frobnicate=https://u:tok-SENSITIVE-c66@h.example.test/ https://safe.example.test/",
    ] {
        for include_credentials in [false, true] {
            let r = import(cmd.as_bytes(), &ImportOptions { include_credentials, ..ImportOptions::default() }).unwrap();
            assert!(!leaks(&serde_json::to_string(&r.report).unwrap()), "a cURL diagnostic echoed a credential ({include_credentials})");
            assert!(!leaks(&stored(&r).to_string()), "a cURL diagnostic credential was stored ({include_credentials})");
        }
    }
}

/// Final gate of #575 (dsf F4): the quarantine placeholder never takes a
/// name the source references or derives (a path parameter, a cURL shell
/// variable, an explicit reference), so it cannot bind another request's
/// variable.
#[test]
fn the_quarantine_placeholder_never_binds_a_source_name() {
    let quarantined = "https://api.{{region}}.example.test/v1?to=a@b";
    let doc = postman_doc_items(json!([
        { "name": "a", "request": { "method": "GET", "url": { "raw": "https://api.example.test/items/:url_needs_review/:url-needs-review" } } },
        { "name": "b", "request": { "method": "GET", "url": quarantined } },
    ]));
    let r = import(&doc, &ImportOptions::default()).unwrap();
    let a = &r.requests[0].spec.url;
    // The `:url-needs-review` path segment is reserved before any placeholder
    // is allocated, so the quarantine placeholder takes the next free name.
    assert_eq!(r.requests[1].spec.url, "{{url-needs-review_2}}");
    assert!(!a.contains("{{url-needs-review_2}}"), "a path parameter took the quarantine placeholder");
    let doc = postman_doc_items(json!([
        { "name": "a", "request": { "method": "GET", "url": "https://api.example.test/", "header": [{ "key": "X-Id", "value": "{{url-needs-review}}" }] } },
        { "name": "b", "request": { "method": "GET", "url": quarantined } },
    ]));
    let r = import(&doc, &ImportOptions::default()).unwrap();
    assert_eq!(r.requests[1].spec.url, "{{url-needs-review_2}}", "an explicit reference was not reserved");
    let r = import(format!("curl -H \"X-Id: $url_needs_review\" '{quarantined}'").as_bytes(), &ImportOptions::default()).unwrap();
    assert_eq!(r.requests[0].spec.url, "{{url-needs-review}}");
    assert_eq!(header_value(&r, "X-Id"), Some("{{url_needs_review}}"));
}

fn postman_doc_items(items: Value) -> Vec<u8> {
    json!({
        "info": { "name": "c", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json" },
        "item": items
    })
    .to_string()
    .into_bytes()
}

fn header_value<'r>(r: &'r ImportResult, name: &str) -> Option<&'r str> {
    r.requests[0].spec.headers.iter().find(|h| h.name.eq_ignore_ascii_case(name)).map(|h| h.value.as_str())
}

/// Final gate of #575: the userinfo placeholders never take a path
/// parameter's name (Postman path variables, Insomnia path parameters), in
/// the same request or another one, in either mode.
#[test]
fn userinfo_placeholders_never_take_a_path_parameter_name() {
    let userinfo_url = "https://admin:tok-SENSITIVE-c67@api.example.test/items/:username";
    let other_url = "https://api.example.test/accounts/:password";
    let postman_source = postman_doc_items(json!([
        { "name": "a", "request": { "method": "GET", "url": { "raw": userinfo_url } } },
        { "name": "b", "request": { "method": "GET", "url": { "raw": other_url } } },
    ]));
    let mut a = insomnia_request(userinfo_url);
    a["pathParameters"] = json!([{ "name": "username", "value": "" }]);
    let mut other = insomnia_request(other_url);
    other["_id"] = json!("req_2");
    other["name"] = json!("R2");
    other["pathParameters"] = json!([{ "name": "password", "value": "" }]);
    let insomnia_source = json!({
        "_type": "export",
        "__export_format": 4,
        "resources": [
            { "_id": "wrk_1", "_type": "workspace", "parentId": null, "name": "W", "scope": "collection" },
            a,
            other
        ]
    })
    .to_string()
    .into_bytes();
    for (importer, source) in [("Postman", postman_source), ("Insomnia", insomnia_source)] {
        for include_credentials in [false, true] {
            let r = import(&source, &ImportOptions { include_credentials, ..ImportOptions::default() }).unwrap();
            let with_userinfo = r.requests.iter().find(|q| q.spec.url.contains("/items/")).expect("the userinfo request");
            let auth = serde_json::to_string(&with_userinfo.spec.auth).unwrap();
            assert!(with_userinfo.spec.url.ends_with("/items/{{username}}"), "{importer}: the path parameter changed");
            assert!(auth.contains("{{username_2}}"), "{importer}: the user name placeholder took a path parameter's name");
            if !include_credentials {
                assert!(auth.contains("{{password_2}}"), "{importer}: the password placeholder took a path parameter's name");
                assert!(!leaks(&stored(&r).to_string()), "{importer}: a literal credential survived");
            }
            assert!(r.requests.iter().any(|q| q.spec.url.ends_with("/accounts/{{password}}")), "{importer}: the other path changed");
        }
    }
}

/// A URL whose whole authority is one plain reference (`{{baseUrl}}/x`) has
/// no literal userinfo and is kept as written; any other template before
/// the authority's end beside an `@` still quarantines the URL.
#[test]
fn a_reference_authority_keeps_the_url() {
    let importers: [(&str, Build); 4] = [("cURL", curl), ("HAR", har), ("Postman", postman), ("Insomnia", insomnia)];
    let shape = |url: &'static str| Shape { name: "reference authority", url, headers: &[], json_body: None, export: [Export::Skip; 4] };
    let stored =
        |build: Build, url: &'static str| import(&build(&shape(url)), &ImportOptions::default()).unwrap().requests[0].spec.url.clone();
    // Kept: not quarantined and not cut (its query may still become
    // parameters).
    let kept = |stored: &str, url: &str| stored != "{{url-needs-review}}" && stored.starts_with(url.split('?').next().unwrap_or(url));
    for (importer, build) in importers {
        // HAR imports only `http(s)` URLs.
        let schemeless = importer != "HAR";
        for url in ["https://{{host}}/x?email=a@b", "https://{{host}}?q=a@b"] {
            assert!(kept(&stored(build, url), url), "{importer}: {url}");
        }
        if schemeless {
            for url in ["{{baseUrl}}/x?email=a@b", "{{baseUrl}}?q=a@b"] {
                assert!(kept(&stored(build, url), url), "{importer}: {url}");
            }
            for url in ["{{baseUrl}}@evil/x", "{{ base Url }}/x@y", "{{a}}{{b}}/x@y"] {
                assert_eq!(stored(build, url), "{{url-needs-review}}", "{importer}: {url}");
            }
        }
        for url in ["https://{{ base Url }}/x@y", "https://{{a}}{{b}}/x@y", "https://pre{{a}}/x@y"] {
            assert_eq!(stored(build, url), "{{url-needs-review}}", "{importer}: {url}");
        }
    }
}

// Final scope of GHSA-c236: one shared row per remaining credential path.

fn with_credentials(include_credentials: bool) -> ImportOptions {
    ImportOptions { include_credentials, ..ImportOptions::default() }
}

const POSTMAN_SCHEMA: &str = "https://schema.getpostman.com/json/collection/v2.1.0/collection.json";

/// Neither the report nor the stored objects hold a canary, and a sanitized
/// export of the stored objects holds none either, in both modes.
fn assert_nothing_readable(source: &[u8], label: &str) {
    for include_credentials in [false, true] {
        let r = import(source, &with_credentials(include_credentials)).unwrap_or_else(|e| panic!("{label}: {e}"));
        assert!(!leaks(&serde_json::to_string(&r.report).unwrap()), "{label}: the report holds a credential ({include_credentials})");
        let mut objects = stored(&r);
        if !include_credentials {
            assert!(!leaks(&objects.to_string()), "{label}: a credential was stored");
        }
        let before = objects.clone();
        let s = anvil_portability::sanitize::sanitize(&mut objects, &[]);
        assert!(!leaks(&objects.to_string()), "{label}: a sanitized export kept a credential readable ({include_credentials})");
        anvil_portability::sanitize::restore(&mut objects, &s.extracted).unwrap();
        assert_eq!(objects, before, "{label}: the export did not restore ({include_credentials})");
    }
}

/// sol F1: an explicit request, folder or collection name that repeats a
/// credential URL is redacted like report text.
#[test]
fn names_never_keep_a_credential_url() {
    let ambiguous = "https://admin:{{pw}}tok-SENSITIVE-c70@api.example.test/v1";
    let literal = "https://admin:tok-SENSITIVE-c71@api.example.test/v1";
    let postman = json!({
        "info": { "name": literal, "schema": POSTMAN_SCHEMA },
        "item": [{ "name": ambiguous, "item": [{ "name": literal, "request": { "method": "GET", "url": ambiguous } }] }]
    })
    .to_string()
    .into_bytes();
    let mut request = insomnia_request(ambiguous);
    request["name"] = json!(literal);
    assert_nothing_readable(&postman, "Postman names");
    assert_nothing_readable(&insomnia_doc(request, json!({})), "Insomnia names");
}

/// sol F2: a report pointer built from a source key holds no credential.
#[test]
fn report_pointers_never_hold_a_credential() {
    let source = postman_doc_items(json!([{
        "name": "r",
        "protocolProfileBehavior": { "https://admin:tok-SENSITIVE-c72@api.example.test/": true },
        "request": { "method": "GET", "url": "https://api.example.test/" }
    }]));
    let r = import(&source, &ImportOptions::default()).unwrap();
    assert!(r.report.unsupported.iter().any(|f| f.code == "request_setting"), "the setting was not reported");
    assert_nothing_readable(&source, "Postman settings key");
}

/// sol F3: OAuth endpoint URLs get the request URL's userinfo rule on
/// import and whole-URL extraction on export.
#[test]
fn oauth_endpoint_urls_never_keep_a_credential() {
    let token_url = "https://client:tok-SENSITIVE-c73@issuer.example.test/token";
    let auth_url = "https://{{tenant}}.issuer.example.test/authorize?x=a:tok-SENSITIVE-c74@b";
    let postman = postman_doc(json!({
        "method": "GET",
        "url": "https://api.example.test/",
        "auth": { "type": "oauth2", "oauth2": [
            { "key": "grant_type", "value": "authorization_code_with_pkce" },
            { "key": "accessTokenUrl", "value": token_url },
            { "key": "authUrl", "value": auth_url },
            { "key": "clientId", "value": "client" }
        ] }
    }));
    let mut request = insomnia_request("https://api.example.test/");
    request["authentication"] = json!({
        "type": "oauth2", "grantType": "authorization_code", "usePkce": true,
        "accessTokenUrl": token_url, "authorizationUrl": auth_url, "clientId": "client"
    });
    let insomnia = insomnia_doc(request, json!({}));
    for (importer, source) in [("Postman", postman), ("Insomnia", insomnia)] {
        let r = import(&source, &ImportOptions::default()).unwrap();
        let config = &serde_json::to_value(&r.requests[0].spec.auth).unwrap()["config"];
        assert_eq!(config["token_url"], "https://issuer.example.test/token", "{importer}");
        assert_eq!(config["authorization_url"], "{{url-needs-review}}", "{importer}");
        let kept = import(&source, &with_credentials(true)).unwrap();
        assert!(leaks(&stored(&kept).to_string()), "{importer}: include_credentials did not keep the endpoint");
        assert_nothing_readable(&source, importer);
    }
}

/// sol F4: an ordinary credential placeholder never takes a name the source
/// defines (here an alias that would resolve to another account's value).
#[test]
fn credential_placeholders_never_bind_a_source_variable() {
    let postman = json!({
        "info": { "name": "c", "schema": POSTMAN_SCHEMA },
        "variable": [
            { "key": "r_password", "value": "{{selected_value}}" },
            { "key": "selected_value", "value": "other-account-value" }
        ],
        "item": [{ "name": "r", "request": { "method": "GET", "url": "https://api.example.test/",
            "auth": { "type": "basic", "basic": [{ "key": "username", "value": "u" }, { "key": "password", "value": "tok-SENSITIVE-c75" }] } } }]
    })
    .to_string()
    .into_bytes();
    let mut request = insomnia_request("https://api.example.test/");
    request["authentication"] = json!({ "type": "basic", "username": "u", "password": "tok-SENSITIVE-c76" });
    let insomnia = insomnia_doc(request, json!({ "R_password": "{{ _.selected }}", "selected": "other-account-value" }));
    for (importer, source) in [("Postman", postman), ("Insomnia", insomnia)] {
        let r = import(&source, &ImportOptions::default()).unwrap();
        let password = serde_json::to_value(&r.requests[0].spec.auth).unwrap()["password"]["value"].as_str().unwrap().to_string();
        let defined: Vec<String> = r
            .workspace
            .variables
            .iter()
            .chain(r.environments.iter().flat_map(|e| e.variables.iter()))
            .map(|v| format!("{{{{{}}}}}", v.name))
            .collect();
        assert!(password.starts_with("{{") && !defined.contains(&password), "{importer}: the placeholder binds a source variable");
        assert_nothing_readable(&source, importer);
    }
}

/// sol F5: a reference the source escaped (a JSON \u escape, percent-encoding,
/// shell quoting) is reserved by its decoded spelling.
#[test]
fn escaped_references_are_reserved() {
    let quarantined = "https://api.{{region}}.example.test/v1?to=a@b";
    let json_escaped = format!(
        r#"{{"info":{{"name":"c","schema":"{POSTMAN_SCHEMA}"}},"item":[{{"name":"a","request":{{"method":"GET","url":"https://api.example.test/","header":[{{"key":"X-Id","value":"\u007b\u007burl-needs-review\u007d\u007d"}}]}}}},{{"name":"b","request":{{"method":"GET","url":"{quarantined}"}}}}]}}"#
    );
    let percent = postman_doc_items(json!([
        { "name": "a", "request": { "method": "GET", "url": "https://api.example.test/", "header": [{ "key": "X-Id", "value": "{{url%2Dneeds%2Dreview}}" }] } },
        { "name": "b", "request": { "method": "GET", "url": quarantined } },
    ]));
    for (label, source) in [("JSON escape", json_escaped.into_bytes()), ("percent-encoding", percent)] {
        let r = import(&source, &ImportOptions::default()).unwrap();
        assert_eq!(r.requests[1].spec.url, "{{url-needs-review_2}}", "{label}: an escaped reference was not reserved");
    }
    let shell = format!("curl -H 'X-Id: {{{{url-'\"needs-review}}}}\" '{quarantined}'");
    let r = import(shell.as_bytes(), &ImportOptions::default()).unwrap();
    assert_eq!(header_value(&r, "X-Id"), Some("{{url-needs-review}}"));
    assert_eq!(r.requests[0].spec.url, "{{url-needs-review_2}}", "shell quoting hid a reference");
}

/// dsf F1: a path parameter is reserved by its raw spelling as well as the
/// sanitized one its placeholder takes. That is fail-safe: no placeholder
/// can bind the parameter under either spelling, at the cost of a suffix.
#[test]
fn a_path_parameter_reserves_its_raw_spelling() {
    let r = import(
        &postman_doc_items(json!([
            { "name": "a", "request": { "method": "GET", "url": { "raw": "https://api.example.test/items/:url-needs-review" } } },
            { "name": "b", "request": { "method": "GET", "url": "https://api.{{region}}.example.test/v1?to=a@b" } },
        ])),
        &ImportOptions::default(),
    )
    .unwrap();
    assert_eq!(r.requests[0].spec.url, "https://api.example.test/items/{{url_needs_review}}");
    assert_eq!(r.requests[1].spec.url, "{{url-needs-review_2}}");
}

/// #579: a retained script keeps no credential literal in the report.
#[test]
fn retained_scripts_hold_no_credential_literal() {
    let source = postman_doc_items(json!([{ "name": "r",
        "event": [{ "listen": "prerequest", "script": { "type": "text/javascript", "exec": [
            "const password = 'tok-SENSITIVE-c77';",
            "pm.request.headers.add({ key: 'Authorization', value: 'Bearer tok-SENSITIVE-c78abcdef' });",
            "pm.sendRequest('https://admin:tok-SENSITIVE-c79@api.example.test/');"
        ] } }],
        "request": { "method": "GET", "url": "https://api.example.test/" } }]));
    let r = import(&source, &ImportOptions::default()).unwrap();
    assert_eq!(r.report.scripts.len(), 1);
    assert!(r.report.scripts[0].source.contains("pm.request.headers.add"), "the script was not retained");
    assert_nothing_readable(&source, "Postman script");
}

/// #579: an importer message that echoes a source value outside a URL or a
/// template holds no credential literal.
#[test]
fn messages_hold_no_credential_literal() {
    let postman = postman_doc(json!({
        "method": "POST",
        "url": "https://api.example.test/",
        "body": { "mode": "password=tok-SENSITIVE-c80" }
    }));
    let mut request = insomnia_request("https://api.example.test/");
    request["authentication"] = json!({ "type": "Bearer tok-SENSITIVE-c81abcdef" });
    for (label, source) in [("Postman body mode", postman), ("Insomnia auth type", insomnia_doc(request, json!({})))] {
        let r = import(&source, &ImportOptions::default()).unwrap();
        assert!(!r.report.unsupported.is_empty(), "{label}: nothing was reported");
        assert_nothing_readable(&source, label);
    }
}

/// Review of #583 (sol F2 = dsf F2): a retained script's owner (a
/// collection, folder or request name) and its other metadata are redacted
/// like report text.
#[test]
fn retained_script_metadata_is_redacted() {
    let name = "https://admin:tok-SENSITIVE-c84@api.example.test/v1";
    let source = json!({
        "info": { "name": name, "schema": POSTMAN_SCHEMA },
        "event": [{ "listen": "prerequest", "script": { "type": "text/javascript", "exec": ["pm.variables.set('a', 1);"] } }],
        "item": [{ "name": name,
            "event": [{ "listen": "test", "script": { "type": "text/javascript", "exec": ["pm.test('ok', () => {});"] } }],
            "request": { "method": "GET", "url": "https://api.example.test/" } }]
    })
    .to_string()
    .into_bytes();
    let r = import(&source, &ImportOptions::default()).unwrap();
    assert_eq!(r.report.scripts.len(), 2, "the scripts were not retained");
    assert_nothing_readable(&source, "script owner");
}

/// Review of #583 (dsf F3): OpenAPI and Swagger OAuth endpoint URLs get the
/// request URL's userinfo rule on import.
#[test]
fn openapi_oauth_endpoint_urls_never_keep_a_credential() {
    let source = json!({
        "openapi": "3.0.3",
        "info": { "title": "t", "version": "1" },
        "servers": [{ "url": "https://api.example.test" }],
        "components": { "securitySchemes": {
            "cc": { "type": "oauth2", "flows": { "clientCredentials": {
                "tokenUrl": "https://client:tok-SENSITIVE-c85@issuer.example.test/token", "scopes": {} } } },
            "ac": { "type": "oauth2", "flows": { "authorizationCode": {
                "authorizationUrl": "https://user:tok-SENSITIVE-c86@issuer.example.test/authorize",
                "tokenUrl": "https://issuer.example.test/token", "scopes": {} } } }
        } },
        "paths": {
            "/a": { "get": { "security": [{ "cc": [] }], "responses": { "200": { "description": "ok" } } } },
            "/b": { "get": { "security": [{ "ac": [] }], "responses": { "200": { "description": "ok" } } } }
        }
    })
    .to_string()
    .into_bytes();
    let r = import(&source, &ImportOptions::default()).unwrap();
    let text = stored(&r).to_string();
    assert!(text.contains("\"https://issuer.example.test/token\""), "the token URL lost more than its userinfo");
    assert!(text.contains("\"https://issuer.example.test/authorize\""), "the authorization URL lost more than its userinfo");
    assert_nothing_readable(&source, "OpenAPI OAuth endpoints");
}
