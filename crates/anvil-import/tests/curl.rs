mod common;

use anvil_domain::auth::AuthConfig;
use anvil_domain::request::{Body, MultipartContent, SoapVersion};
use anvil_domain::secret::SensitiveValue;
use anvil_domain::settings::HttpVersionPolicy;
use anvil_import::{Dialect, ImportError, ImportOptions, ImportResult, detect, import};
use common::*;

fn curl(cmd: &str) -> ImportResult {
    import(cmd.as_bytes(), &opts()).unwrap_or_else(|e| panic!("{cmd}: {e}"))
}

#[test]
fn fixture_command() {
    assert_eq!(detect(&fixture("curl/create-order.sh")).dialect, Dialect::Curl);
    let r = run("curl/create-order.sh", &opts());
    assert_eq!(r.requests.len(), 1);
    let s = &r.requests[0].spec;
    assert_eq!(s.method, "POST");
    assert_eq!(s.url, "https://shop.example.com/api/orders");
    assert_eq!(param(s, "dry_run").unwrap().value, "true");
    assert_eq!(param(s, "token").unwrap().value, "{{token}}", "credential-like query value redacted");
    // `$SHOP_TOKEN` becomes a variable, which is not a literal secret.
    assert_eq!(header(s, "Authorization").unwrap().value, "Bearer {{SHOP_TOKEN}}");
    assert!(r.report.required_variables.iter().any(|v| v.name == "SHOP_TOKEN" && v.secret));
    match &s.body {
        Body::Json { text } => assert_eq!(text, r#"{"sku":"A-1","qty":2,"note":"it's fine"}"#),
        other => panic!("{other:?}"),
    }
    assert!(header(s, "Content-Type").is_none(), "application/json is inferred from the body");
    match &s.auth {
        AuthConfig::Basic { username, password } => {
            assert_eq!(username, "shop-bot");
            assert_eq!(password, &SensitiveValue::template("{{password}}"));
        }
        other => panic!("{other:?}"),
    }
    // -k is never applied.
    let tls = r.report.inactive_settings.iter().find(|x| x.setting == "tls.verify").unwrap();
    assert_eq!(tls.pointer, "/args/15");
    assert!(s.settings.tls_profile_id.is_none());
    // -sSL cluster, --max-redirs, --compressed, --connect-timeout, --http2.
    let redirects = s.settings.redirects.unwrap();
    assert!(redirects.follow);
    assert_eq!(redirects.max, 5);
    assert!(!redirects.forward_credentials_cross_origin);
    assert_eq!(s.settings.decompress, Some(true));
    assert_eq!(s.settings.timeouts.unwrap().connect_ms, Some(Some(2500)));
    assert_eq!(s.settings.http_version, Some(HttpVersionPolicy::Auto));
    assert!(!serde_json::to_string(&r.requests).unwrap().contains("hunter2"));
}

#[test]
fn literal_parity_fixtures() {
    let data = run("curl/literal-data.sh", &opts());
    match &data.requests[0].spec.body {
        Body::Raw { text, .. } => assert_eq!(text, "line1\nline2\r\n"),
        other => panic!("{other:?}"),
    }

    let form = run("curl/literal-form-string.sh", &opts());
    match &form.requests[0].spec.body {
        Body::Multipart { parts } => {
            assert_eq!(parts[0].name, "x");
            assert!(matches!(&parts[0].content, MultipartContent::Text { value } if value == "a;type=text/html"));
            assert_eq!(parts[0].content_type, None);
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn include_credentials_keeps_literals() {
    let r = import(&fixture("curl/create-order.sh"), &ImportOptions { include_credentials: true, ..opts() }).unwrap();
    let s = &r.requests[0].spec;
    assert!(matches!(&s.auth, AuthConfig::Basic { password, .. } if password == &SensitiveValue::template("hunter2")));
    assert_eq!(param(s, "token").unwrap().value, "abc123");
    assert!(param(s, "token").unwrap().sensitive);
}

#[test]
fn form_data_and_defaults() {
    let r = curl("curl https://api.example.com/login -d 'user=alice' -d 'password=s3cret' --data-urlencode 'q=a b&c'");
    let s = &r.requests[0].spec;
    assert_eq!(s.method, "POST");
    match &s.body {
        Body::FormUrlEncoded { fields } => {
            assert_eq!(fields[0].name, "user");
            assert_eq!(fields[1].value, "{{password}}");
            assert_eq!(fields[2].value, "a b&c");
        }
        other => panic!("{other:?}"),
    }
    // -G moves data to the query.
    let r = curl("curl -G https://api.example.com/search -d q=lamp -d page=2");
    let s = &r.requests[0].spec;
    assert_eq!(s.method, "GET");
    assert_eq!(param(s, "q").unwrap().value, "lamp");
    assert!(matches!(s.body, Body::None));
    // JSON-looking data without a Content-Type stays form-typed and is flagged.
    let r = curl(r#"curl https://api.example.com/x -d '{"a":1}'"#);
    assert!(matches!(&r.requests[0].spec.body, Body::Raw { content_type: Some(ct), .. } if ct == "application/x-www-form-urlencoded"));
    assert!(has(&r, "curl_json_as_form"));
    // --json sets JSON.
    let r = curl(r#"curl --json '{"a":1}' https://api.example.com/x"#);
    assert!(matches!(r.requests[0].spec.body, Body::Json { .. }));
    assert_eq!(header(&r.requests[0].spec, "Accept").unwrap().value, "application/json");
}

#[test]
fn multipart_and_file_references() {
    let r = curl("curl -F 'caption=hi' -F 'file=@/tmp/photo.png;type=image/png' https://api.example.com/upload");
    match &r.requests[0].spec.body {
        Body::Multipart { parts } => {
            assert!(matches!(&parts[0].content, MultipartContent::Text { value } if value == "hi"));
            assert!(!parts[1].enabled);
            assert_eq!(parts[1].content_type.as_deref(), Some("image/png"));
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(r.report.external_refs[0].reference, "/tmp/photo.png");
    let r = curl("curl -d @payload.json https://api.example.com/x");
    assert!(has(&r, "curl_data_file"));
    assert_eq!(r.report.external_refs[0].reference, "payload.json");
}

#[test]
fn methods_head_and_misc_flags() {
    let r = curl("curl -I https://example.com");
    assert_eq!(r.requests[0].spec.method, "HEAD");
    let r = curl("curl -XDELETE 'https://example.com/a?id=1' -A 'agent/1' -e https://ref.example.com -b 'sid=abc'");
    let s = &r.requests[0].spec;
    assert_eq!(s.method, "DELETE");
    assert_eq!(header(s, "User-Agent").unwrap().value, "agent/1");
    assert_eq!(header(s, "Referer").unwrap().value, "https://ref.example.com");
    assert_eq!(header(s, "Cookie").unwrap().value, "{{Cookie}}");
    let r = curl("curl --http3-only --location-trusted --digest -u a:b --proxy http://p:8080 https://example.com");
    let s = &r.requests[0].spec;
    assert_eq!(s.settings.http_version, Some(HttpVersionPolicy::Http3Only));
    assert!(!s.settings.redirects.unwrap().forward_credentials_cross_origin);
    assert!(r.report.inactive_settings.iter().any(|x| x.setting == "redirects.forward_credentials_cross_origin"));
    assert!(has(&r, "curl_auth_scheme"));
    assert!(has(&r, "curl_connection_option"));
    // Unknown flags are reported.
    let r = curl("curl --frobnicate https://example.com");
    assert!(has_at(&r, "curl_option", "/args/1"));
}

#[test]
fn url_credentials_and_scheme_default() {
    let r = curl("curl http://bob:pa%3Ass@example.com/x");
    let s = &r.requests[0].spec;
    assert_eq!(s.url, "http://example.com/x");
    assert!(matches!(&s.auth, AuthConfig::Basic { username, password } if username == "bob" && password.is_pure_reference()));
    let r = curl("curl example.com/x");
    assert_eq!(r.requests[0].spec.url, "http://example.com/x");
    assert!(has(&r, "curl_default_scheme"));
}

#[test]
fn soap_via_curl() {
    let r = curl(r#"curl -H 'Content-Type: text/xml' -H 'SOAPAction: "urn:x/Op"' -d '<Envelope/>' https://soap.example.com"#);
    match &r.requests[0].spec.body {
        Body::Soap { version, action, envelope } => {
            assert_eq!(*version, SoapVersion::Soap11);
            assert_eq!(action.as_deref(), Some("urn:x/Op"));
            assert_eq!(envelope, "<Envelope/>");
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn literal_data_keeps_line_breaks() {
    // cURL strips CR/LF only when it reads `--data @file`; literal data is
    // sent as given, like `--data-binary`.
    for flag in ["-d", "--data", "--data-ascii", "--data-binary"] {
        let r = curl(&format!(r"curl -H 'Content-Type: text/plain' {flag} $'line1\nline2\r\n' https://example.test"));
        match &r.requests[0].spec.body {
            Body::Raw { text, content_type } => {
                assert_eq!(text, "line1\nline2\r\n", "{flag}");
                assert_eq!(content_type.as_deref(), Some("text/plain"));
            }
            other => panic!("{flag}: {other:?}"),
        }
    }
    // File references stay reported, never read.
    let r = curl("curl --data-ascii @body.txt https://example.test");
    assert!(has(&r, "curl_data_file"));
    assert_eq!(r.requests[0].spec.body, Body::None);
}

#[test]
fn form_string_value_is_literal() {
    let r = curl("curl --form-string 'note=alpha;bravo;type=text/html' --form-string 'up=@/etc/passwd' https://example.test");
    match &r.requests[0].spec.body {
        Body::Multipart { parts } => {
            assert_eq!(parts[0].name, "note");
            assert!(matches!(&parts[0].content, MultipartContent::Text { value } if value == "alpha;bravo;type=text/html"));
            assert_eq!(parts[0].content_type, None);
            assert!(parts[1].enabled, "--form-string never reads a file");
            assert!(matches!(&parts[1].content, MultipartContent::Text { value } if value == "@/etc/passwd"));
        }
        other => panic!("{other:?}"),
    }
    assert!(r.report.external_refs.is_empty());
    // -F keeps parsing `;type=` metadata.
    let r = curl("curl -F 'note=alpha;type=text/html' https://example.test");
    match &r.requests[0].spec.body {
        Body::Multipart { parts } => {
            assert!(matches!(&parts[0].content, MultipartContent::Text { value } if value == "alpha"));
            assert_eq!(parts[0].content_type.as_deref(), Some("text/html"));
        }
        other => panic!("{other:?}"),
    }
}

fn soap_body(r: &ImportResult) -> (SoapVersion, Option<String>) {
    match &r.requests[0].spec.body {
        Body::Soap { version, action, .. } => (*version, action.clone()),
        other => panic!("{other:?}"),
    }
}

#[test]
fn soap12_action_parameter_is_kept() {
    // The engine derives exactly this Content-Type from the body, so the
    // header is folded into the SOAP model.
    let r = curl(r#"curl -H 'Content-Type: application/soap+xml; charset=utf-8; action="urn:lookup"' --data-binary '<E/>' https://e.test"#);
    assert_eq!(soap_body(&r), (SoapVersion::Soap12, Some("urn:lookup".into())));
    assert!(header(&r.requests[0].spec, "Content-Type").is_none());
    // Quoted values may contain ';'; parameter names are case-insensitive.
    let r = curl(r#"curl -H 'Content-Type: application/soap+xml;Action="urn:a;b";charset=UTF-8' -d '<Envelope/>' https://example.test"#);
    assert_eq!(soap_body(&r), (SoapVersion::Soap12, Some("urn:a;b".into())));
    assert!(header(&r.requests[0].spec, "Content-Type").is_none());
    // Unquoted action.
    let r = curl("curl -H 'Content-Type: application/soap+xml; charset=utf-8; action=urn:plain' -d '<Envelope/>' https://example.test");
    assert_eq!(soap_body(&r).1.as_deref(), Some("urn:plain"));
    // No action: control.
    let r = curl("curl -H 'Content-Type: application/soap+xml; charset=utf-8' -d '<Envelope/>' https://example.test");
    assert_eq!(soap_body(&r), (SoapVersion::Soap12, None));
    assert!(header(&r.requests[0].spec, "Content-Type").is_none());
    // Parameters the engine would not derive keep the explicit header, which
    // takes precedence when sending.
    for ct in [
        r#"application/soap+xml; action="urn:lookup""#,
        r#"application/soap+xml; charset=iso-8859-1; action="urn:lookup""#,
        r#"application/soap+xml; charset=utf-8; action="urn:lookup"; profile=x"#,
        r#"application/soap+xml; charset=utf-8; action="urn:first"; action="urn:second""#,
    ] {
        let r = curl(&format!("curl -H 'Content-Type: {ct}' -d '<Envelope/>' https://example.test"));
        let expected_action = if ct.contains("urn:first") { "urn:first" } else { "urn:lookup" };
        assert_eq!(soap_body(&r), (SoapVersion::Soap12, Some(expected_action.into())), "{ct}");
        assert_eq!(header(&r.requests[0].spec, "Content-Type").map(|h| h.value.as_str()), Some(ct));
    }
    // A SOAPAction header does not turn a SOAP 1.2 media type into SOAP 1.1.
    let r = curl(r#"curl -H 'Content-Type: application/soap+xml; charset=utf-8; action="urn:x"' -H 'SOAPAction: urn:x' -d '<E/>' e.test"#);
    assert_eq!(soap_body(&r), (SoapVersion::Soap12, Some("urn:x".into())));
    // SOAP 1.1 is unchanged: the action comes from the SOAPAction header.
    let r = curl(r#"curl -H 'Content-Type: text/xml; charset=utf-8' -H 'SOAPAction: "urn:x/Op"' -d '<E/>' https://example.test"#);
    assert_eq!(soap_body(&r), (SoapVersion::Soap11, Some("urn:x/Op".into())));
    assert!(header(&r.requests[0].spec, "SOAPAction").is_none());
}

#[test]
fn shell_edge_cases() {
    // Pipelines: only the first command.
    let r = curl("curl https://example.com | jq .");
    assert!(has(&r, "shell_pipeline"));
    // Prompt prefix and line continuation with CRLF.
    let r = curl("$ curl \\\r\n  https://example.com/a");
    assert_eq!(r.requests[0].spec.url, "https://example.com/a");
    // ANSI-C quoting.
    let r = curl(r#"curl -H $'X-Tab: a\tb' https://example.com"#);
    assert_eq!(header(&r.requests[0].spec, "X-Tab").unwrap().value, "a\tb");
    // Errors, not panics.
    assert!(matches!(import(b"curl 'unterminated", &opts()), Err(ImportError::Syntax { .. })));
    assert!(matches!(import(b"curl -X POST", &opts()), Err(ImportError::Invalid { .. })));
}
