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

/// The value of a value-taking option that is not imported is never read as
/// the URL, whether the importer knows the option or not (#538).
#[test]
fn an_option_value_is_never_taken_for_the_url() {
    for cmd in [
        "curl --unix-socket /var/run/docker.sock http://localhost/v1/info",
        "curl --retry-max-time 30 http://localhost/v1/info",
        "curl --proxy-header 'X-Proxy: y' http://localhost/v1/info",
        "curl --tls-max 1.2 http://localhost/v1/info",
        "curl -K cfg http://localhost/v1/info",
        "curl --config cfg http://localhost/v1/info",
        "curl --noproxy '*' http://localhost/v1/info",
        "curl -sKcfg http://localhost/v1/info",
        // Unknown to the importer: the bare word after it is its value,
        // since a URL follows.
        "curl --frobnicate-with value http://localhost/v1/info",
    ] {
        let r = curl(cmd);
        assert_eq!(r.requests.len(), 1, "{cmd}");
        assert_eq!(r.requests[0].spec.url, "http://localhost/v1/info", "{cmd}");
        assert!(has(&r, "curl_option"), "{cmd}: {:?}", codes(&r));
        assert!(!has(&r, "curl_multiple_urls"), "{cmd}");
    }
    let r = curl("curl -K cfg http://localhost/v1/info");
    assert!(r.report.external_refs.iter().any(|x| x.reference == "cfg"), "{:?}", r.report.external_refs);
    // Without a URL after it, the bare word stays the URL, as before.
    let r = curl("curl --frobnicate example.com");
    assert_eq!(r.requests[0].spec.url, "http://example.com");
    // A URL that is another option's value does not count.
    let r = curl("curl --frobnicate example.com --proxy http://p:8080");
    assert_eq!(r.requests[0].spec.url, "http://example.com");
}

/// `--max-redirs -1` is curl's "unlimited": the most a redirect policy
/// follows, with a warning, never zero (#538).
#[test]
fn unlimited_max_redirs_follows_the_most_redirects() {
    let r = curl("curl -L --max-redirs -1 https://example.com");
    let redirects = r.requests[0].spec.settings.redirects.unwrap();
    assert!(redirects.follow);
    assert_eq!(redirects.max, u8::MAX);
    assert!(has(&r, "curl_unlimited_redirects"));
    let r = curl("curl -L --max-redirs 1000 https://example.com");
    assert_eq!(r.requests[0].spec.settings.redirects.unwrap().max, u8::MAX);
    assert!(!has(&r, "curl_unlimited_redirects"));
}

#[test]
fn url_credentials_and_scheme_default() {
    let r = curl("curl http://bob:pa%3Ass@example.com/x");
    let s = &r.requests[0].spec;
    assert_eq!(s.url, "http://example.com/x");
    // A literal userinfo is replaced by placeholders, user name included.
    assert!(matches!(&s.auth, AuthConfig::Basic { username, password } if username == "{{username}}" && password.is_pure_reference()));
    let r = curl("curl example.com/x");
    assert_eq!(r.requests[0].spec.url, "http://example.com/x");
    assert!(has(&r, "curl_default_scheme"));
}

/// The authority ends at the first `/`, `?` or `#`: an `@` after it is not
/// userinfo, so the host stays and no Basic auth is invented (#511).
#[test]
fn an_at_sign_in_the_query_or_fragment_is_not_userinfo() {
    let r = curl("curl 'https://api.example.com?email=a@b.com'");
    let s = &r.requests[0].spec;
    assert_eq!(s.url, "https://api.example.com");
    assert!(!matches!(s.auth, AuthConfig::Basic { .. }), "no Basic auth is invented from the query or fragment");
    assert_eq!(param(s, "email").unwrap().value, "a@b.com");
    let r = curl("curl 'https://api.example.com#frag@x.test'");
    let s = &r.requests[0].spec;
    assert_eq!(s.url, "https://api.example.com");
    assert!(!matches!(s.auth, AuthConfig::Basic { .. }), "no Basic auth is invented from the query or fragment");
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

#[test]
fn short_option_clusters_count_against_the_argument_limit() {
    // One shell word that expands into more flags than the argument limit.
    let cmd = format!("curl -{} https://example.test", "s".repeat(20_000));
    match import(cmd.as_bytes(), &opts()) {
        Err(ImportError::Syntax { message, .. }) => assert!(message.contains("arguments"), "{message}"),
        other => panic!("expected the argument limit, got {other:?}"),
    }
    // Ordinary clusters still expand.
    let r = curl("curl -sSL -XPOST https://example.test");
    assert_eq!(r.requests[0].spec.method, "POST");
}

#[test]
fn credentials_in_a_verbatim_query_become_sensitive_parameters() {
    // The rest of the query keeps its exact syntax; the credential is never
    // left in URL text, where its placeholder would resolve unencoded and a
    // kept literal would not be extracted on export (review of #573).
    let r = curl("curl 'https://example.test/a?flag&api_key=placeholder-secret&page=2#top'");
    let s = &r.requests[0].spec;
    assert_eq!(s.url, "https://example.test/a?flag&page=2");
    let p = param(s, "api_key").unwrap();
    assert!(p.value == "{{api_key}}" && p.sensitive);
    assert!(!serde_json::to_string(&r.requests).unwrap().contains("placeholder-secret"));
    assert_eq!(r.report.redactions.len(), 1);
    // Kept with include_credentials, decoded and marked sensitive.
    let o = ImportOptions { include_credentials: true, ..opts() };
    let r = import(b"curl 'https://example.test/a?flag&token=a%26b'", &o).unwrap();
    let s = &r.requests[0].spec;
    assert_eq!(s.url, "https://example.test/a?flag");
    let p = param(s, "token").unwrap();
    assert!(p.value == "a&b" && p.sensitive);
    // A query kept verbatim for escaped braces moves its credential out too.
    for options in [opts(), o] {
        let r = import(b"curl 'https://api.example.test/v1?q=%7B%7Bid%7D%7D&api_key=tok-SENSITIVE-cu4'", &options).unwrap();
        let s = &r.requests[0].spec;
        assert_eq!(s.url, "https://api.example.test/v1?q=%7B%7Bid%7D%7D");
        assert!(param(s, "api_key").unwrap().sensitive);
        assert!(!r.requests[0].name.contains("tok-SENSITIVE-cu4"), "a credential reached the request name");
    }
}

#[test]
fn json_data_is_scanned_under_the_node_budget() {
    let o = ImportOptions { max_nodes: 64, ..opts() };
    let big = format!("[{}]", vec!["0"; 200].join(","));
    let cmd = format!("curl -H 'Content-Type: application/json' -d '{big}' https://example.test");
    let r = import(cmd.as_bytes(), &o).unwrap();
    assert!(has_at(&r, "body_not_scanned", "/args#json"));
    // Within the budget, credential members are still redacted.
    let r = import(br#"curl --json '{"password":"placeholder-secret"}' https://example.test"#, &o).unwrap();
    assert_eq!(json_body(&r.requests[0].spec)["password"], "{{password}}");
}

#[test]
fn numeric_credentials_and_unscannable_data() {
    let r = curl(r#"curl --json '{"pin":123456,"max_tokens":5}' https://example.test"#);
    let Body::Json { text } = &r.requests[0].spec.body else { panic!("{:?}", r.requests[0].spec.body) };
    assert!(!text.contains("123456"), "{text}");
    let body = substituted(text, &[("pin", "123456")]);
    assert_eq!((body["pin"].as_u64(), body["max_tokens"].as_u64()), (Some(123456), Some(5)));
    // Unrelated source text mentioning the render marker's tag must not keep
    // the numeric placeholder quoted (which would send the pin as a string),
    // and the mentioning string itself is preserved.
    let r = curl(r#"curl --json '{"pin":123456,"note":"anvil-number"}' https://example.test"#);
    let Body::Json { text } = &r.requests[0].spec.body else { panic!("{:?}", r.requests[0].spec.body) };
    let body = substituted(text, &[("pin", "123456")]);
    assert_eq!(body["pin"].as_u64(), Some(123456), "{text}");
    assert_eq!(body["note"].as_str(), Some("anvil-number"), "{text}");
    // A longer string that begins with the whole serialized marker and then
    // holds multibyte text is not a placeholder: it stays intact, and the
    // rendering must not slice it at a byte offset.
    let note = format!("\u{1}anvil-number\u{1}{}é", "x".repeat(31));
    let cmd = format!(r#"curl --json '{{"pin":123456,"note":{}}}' https://example.test"#, serde_json::to_string(&note).unwrap());
    let r = curl(&cmd);
    let Body::Json { text } = &r.requests[0].spec.body else { panic!("{:?}", r.requests[0].spec.body) };
    let body = substituted(text, &[("pin", "123456")]);
    assert_eq!(body["pin"].as_u64(), Some(123456), "{text}");
    assert_eq!(body["note"].as_str(), Some(note.as_str()), "{text}");
    let r = curl("curl -H 'Content-Type: application/xml' -d '<a>placeholder-secret</a>' https://example.test");
    assert!(has_at(&r, "body_not_scanned", "/args"));
}

#[test]
fn get_data_with_a_bare_flag_keeps_the_credential_policy() {
    let r = curl("curl -G -d 'flag&api_key=placeholder-secret' https://example.test");
    let s = &r.requests[0].spec;
    assert_eq!(param(s, "api_key").map(|p| p.value.as_str()), Some("{{api_key}}"));
    assert!(param(s, "flag").is_some());
    assert!(!serde_json::to_string(&r.requests).unwrap().contains("placeholder-secret"));
}

/// curl sends data by POST whether it is literal or read from a file; the
/// file is not imported, but the method still is (#564). `-G` and `-I`
/// keep precedence, and so does an explicit `-X`.
#[test]
fn data_read_from_a_file_still_defaults_to_post() {
    for cmd in [
        "curl https://api.example.com/orders -H 'Content-Type: application/json' -d @order.json",
        "curl https://api.example.com/orders --json @order.json",
        "curl https://api.example.com/orders --data-urlencode comment@notes.txt",
        "curl https://api.example.com/orders --data-urlencode @notes.txt",
        "curl https://api.example.com/orders --data @order.json",
        "curl https://api.example.com/orders --data-ascii @order.json",
        "curl https://api.example.com/orders --data-binary @order.json",
    ] {
        let r = curl(cmd);
        assert_eq!(r.requests[0].spec.method, "POST", "{cmd}");
        assert!(has(&r, "curl_data_file"), "{cmd}");
    }
    assert_eq!(curl("curl -G -d @query.txt https://api.example.com/orders").requests[0].spec.method, "GET");
    assert_eq!(curl("curl -I -d @query.txt https://api.example.com/orders").requests[0].spec.method, "HEAD");
    assert_eq!(curl("curl -X PUT -d @order.json https://api.example.com/orders").requests[0].spec.method, "PUT");
    assert_eq!(curl("curl https://api.example.com/orders").requests[0].spec.method, "GET");
}

/// GHSA-c236-7r9g-c9p2: the userinfo ends at the last `@` of the authority,
/// so a password holding `@` leaves nothing in the URL. A userinfo that is
/// not exactly references is replaced by fresh placeholders; with
/// include_credentials only the password literal is kept, in the password.
/// Escaped braces never become a `{{reference}}`.
#[test]
fn literal_userinfo_is_replaced_by_placeholders() {
    let r = curl("curl 'https://admin:p@tok-SENSITIVE-cu1@api.example.com/v1?next=a@b'");
    let s = &r.requests[0].spec;
    assert_eq!(s.url, "https://api.example.com/v1");
    assert!(
        matches!(&s.auth, AuthConfig::Basic { username, password } if username == "{{username}}" && password == &SensitiveValue::template("{{password}}"))
    );
    assert!(has(&r, "url_userinfo_replaced"));
    assert!(!serde_json::to_string(&r.requests).unwrap().contains("tok-SENSITIVE-cu1"));
    let keep = ImportOptions { include_credentials: true, ..opts() };
    let r = import(b"curl 'https://admin:p@tok-SENSITIVE-cu1@api.example.com/v1'", &keep).unwrap();
    assert!(
        matches!(&r.requests[0].spec.auth, AuthConfig::Basic { username, password } if username == "{{username}}" && password == &SensitiveValue::template("p@tok-SENSITIVE-cu1"))
    );
    for options in [opts(), keep] {
        let r = import(b"curl 'https://%7B%7Bu%7D%7D:%7B%7Bid%7D%7D@example.test/'", &options).unwrap();
        match &r.requests[0].spec.auth {
            AuthConfig::Basic { username, password } => {
                assert_eq!(username, "{{username}}");
                assert!(!matches!(password, SensitiveValue::Template { value } if value == "{{id}}"), "escaped braces became a reference");
            }
            _ => panic!("expected Basic auth"),
        }
    }
}

/// `-u` wins over URL userinfo, as in curl, and the userinfo is dropped with
/// a warning.
#[test]
fn user_option_wins_over_url_userinfo() {
    let r = curl("curl -u alice:tok-SENSITIVE-cu2 'https://bob:tok-SENSITIVE-cu3@api.example.com/x'");
    let s = &r.requests[0].spec;
    assert_eq!(s.url, "https://api.example.com/x");
    assert!(matches!(&s.auth, AuthConfig::Basic { username, password } if username == "alice" && password.is_pure_reference()));
    assert!(has(&r, "url_credentials_dropped"));
    let text = serde_json::to_string(&r.requests).unwrap();
    assert!(!text.contains("tok-SENSITIVE-cu2") && !text.contains("tok-SENSITIVE-cu3"));
}

/// #563: a URL query's parameters keep main's decoding; what they send
/// differently from curl (a `+`, an escape that is not UTF-8) is reported,
/// and escaped braces never decode to a reference (the query stays as
/// written).
#[test]
fn url_query_conversions_are_reported_and_braces_stay_data() {
    let r = curl("curl 'https://api.example.com/search?q=hello+world'");
    assert_eq!(param(&r.requests[0].spec, "q").unwrap().value, "hello+world");
    assert!(has(&r, "query_plus_sent_encoded"));
    let r = curl("curl 'https://api.example.com/search?n=caf%E9'");
    assert!(has(&r, "query_not_utf8"));
    let r = curl("curl 'https://api.example.com/search?q=%7B%7Bid%7D%7D'");
    let s = &r.requests[0].spec;
    assert_eq!(s.url, "https://api.example.com/search?q=%7B%7Bid%7D%7D");
    assert!(s.params.is_empty());
    let r = curl("curl 'https://api.example.com/search?r=https%3A%2F%2Fa.example'");
    assert_eq!(param(&r.requests[0].spec, "r").unwrap().value, "https://a.example");
    assert!(!has(&r, "query_plus_sent_encoded") && !has(&r, "query_not_utf8"));
}

/// Review round 2 of #573, sol F1 = dsf F2: a credential taken out of a
/// verbatim query keeps an escaped name encoded when decoding it would make
/// a `{{reference}}` (the engine resolves parameter names too). dsf F4: a
/// value that decodes to whitespace only stays in the query, as the pair
/// path keeps it. sol F3 / dsf F1: what the moved credential sends
/// differently is reported.
#[test]
fn credentials_moved_from_a_verbatim_query_keep_escaped_names_and_report_conversions() {
    let r = curl("curl 'https://collector.example/?flag&api_key_%7B%7Bvault_token%7D%7D=tok-SENSITIVE-cu5'");
    let s = &r.requests[0].spec;
    assert_eq!(s.url, "https://collector.example/?flag");
    let p = &s.params[0];
    assert_eq!(p.name, "api_key_%7B%7Bvault_token%7D%7D");
    assert!(p.sensitive && !p.value.contains("tok-SENSITIVE-cu5"));
    let r = curl("curl 'https://api.example.test/v1?flag&%7B%7Bapi%5Fkey%7D%7D=tok-SENSITIVE-cu6'");
    assert_eq!(r.requests[0].spec.params[0].name, "%7B%7Bapi%5Fkey%7D%7D");

    let r = curl("curl 'https://api.example.test/v1?flag&api_key=%20'");
    let s = &r.requests[0].spec;
    assert_eq!(s.url, "https://api.example.test/v1?flag&api_key=%20");
    assert!(s.params.is_empty() && r.report.required_variables.is_empty());

    let keep = ImportOptions { include_credentials: true, ..opts() };
    let r = import(b"curl 'https://api.example.test/v1?flag&token=a+b'", &keep).unwrap();
    assert!(has(&r, "query_plus_sent_encoded"));
    let r = import(b"curl 'https://api.example.test/v1?flag&api_key=caf%E9'", &keep).unwrap();
    assert!(has(&r, "query_not_utf8"));
}

/// Review round 4 of #573 (dsf F1) and of #575: a token alone in the
/// userinfo, or one beside an empty password or inside an expression with a
/// `:`, is never kept as a user name; the placeholders never take the name
/// of a variable the source defines or references.
#[test]
fn a_token_in_the_userinfo_is_a_credential() {
    for url in ["https://tok-SENSITIVE-cu7@api.example.test/v1", "https://tok-SENSITIVE-cu7:@api.example.test/v1"] {
        let r = curl(&format!("curl '{url}'"));
        let s = &r.requests[0].spec;
        assert_eq!(s.url, "https://api.example.test/v1", "{url}");
        assert!(matches!(&s.auth, AuthConfig::Basic { username, .. } if username == "{{username}}"), "{url}");
        assert!(has(&r, "url_userinfo_replaced"), "{url}");
        assert!(!serde_json::to_string(&r.requests).unwrap().contains("tok-SENSITIVE-cu7"), "{url}");
    }
    // A template in the authority beside an `@` makes the URL ambiguous: it
    // is quarantined, not imported and stored nowhere (review of #575).
    let r = curl(r#"curl 'https://{{ "tok-SENSITIVE-cu7:rest" }}@api.example.test/v1'"#);
    let s = &r.requests[0].spec;
    assert_eq!(s.url, "{{url-needs-review}}");
    assert!(has(&r, "url_quarantined") && matches!(s.auth, AuthConfig::Inherit));
    assert!(r.workspace.variables.is_empty());
    assert!(!serde_json::to_string(&r.requests).unwrap().contains("tok-SENSITIVE-cu7"));
    assert!(!serde_json::to_string(&r.report).unwrap().contains("tok-SENSITIVE-cu7"));
    // References stay references, without a warning.
    let r = curl("curl 'https://{{api_token}}@api.example.test/v1'");
    assert!(matches!(&r.requests[0].spec.auth, AuthConfig::Basic { username, .. } if username == "{{api_token}}"));
    assert!(!has(&r, "url_userinfo_replaced"));
    // A source that already references `username` and `password` gets other
    // placeholder names.
    let r = curl("curl -H 'X-User: {{username}}' -H 'X-Pass: {{password}}' 'https://tok-SENSITIVE-cu8:pw@api.example.test/v1'");
    match &r.requests[0].spec.auth {
        AuthConfig::Basic { username, password } => {
            assert_eq!(username, "{{username_2}}");
            assert_eq!(password, &SensitiveValue::template("{{password_2}}"));
        }
        _ => panic!("expected Basic auth"),
    }
}

/// Postman, cURL and HAR never evaluate `{{…}}`: an expression-looking name
/// is a variable name, kept as a reference.
#[test]
fn expression_looking_names_are_references_outside_insomnia() {
    let r = curl("curl -H 'X-Api-Key: {{api-key}}' -H 'X-Auth-Token: {{ x-1 }}' https://api.example.test/v1");
    let s = &r.requests[0].spec;
    assert_eq!(header(s, "X-Api-Key").unwrap().value, "{{api-key}}");
    assert_eq!(header(s, "X-Auth-Token").unwrap().value, "{{ x-1 }}");
    assert!(r.report.redactions.is_empty());
}
