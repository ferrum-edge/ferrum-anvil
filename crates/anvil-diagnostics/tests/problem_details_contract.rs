//! RFC 9457 problem reports in error responses. The generic `http.*` finding
//! quotes the report's type, title and detail as evidence and in its
//! explanation, because they often separate causes the status cannot: Ferrum
//! Alloy answers both a handler deadline and a full admission limit with 503.
//! The report never changes a finding's code, confidence, scope or owner:
//! any server on the path can send `application/problem+json`, with or
//! without a trusted Ferrum profile.

use anvil_diagnostics::{Diagnosis, DiagnosticInput, FerrumTrust, diagnose};
use anvil_domain::diagnostics::{DiagnosticFinding, EvidenceSource, Owner};
use anvil_domain::execution::{BodyCapture, BodyCompleteness, HeaderEntry, ResponseRecord};
use anvil_domain::outcome::ProtocolStatus;
use anvil_domain::request::Protocol;

/// Ferrum Alloy (ferrum-edge/ferrum-alloy@cd5edac, `limits.rs`): the handler
/// did not produce response headers within `server.request_timeout_ms`.
/// Bytes as served by a real Alloy service.
const ALLOY_REQUEST_TIMEOUT: &str = r#"{"type":"tag:ferrumedge.com,2026:alloy/problem/request-timeout","title":"Request timed out","status":503,"detail":"The service did not produce a response in time."}"#;
/// Ferrum Alloy: `server.max_in_flight_requests` was reached.
const ALLOY_OVERLOADED: &str = r#"{"type":"tag:ferrumedge.com,2026:alloy/problem/overloaded","title":"Service overloaded","status":503,"detail":"The service is at its concurrent request limit."}"#;
/// Ferrum Edge `openapi_validator` (catalog
/// `plugin.openapi_validator.unknown_operation`, lab GW-015).
const EDGE_UNKNOWN_OPERATION: &str = r#"{"type":"about:blank","title":"Unknown OpenAPI operation","status":400,"detail":"No OpenAPI operation matched this request","operation":null}"#;

const PROBLEM_JSON: &str = "application/problem+json";

fn response(status: u16, content_type: &str, body: &[u8]) -> ResponseRecord {
    ResponseRecord {
        status,
        reason: None,
        http_version: "HTTP/1.1".into(),
        headers: vec![HeaderEntry { name: "Content-Type".into(), value: content_type.into() }],
        trailers: vec![],
        trailers_received: false,
        body: BodyCapture {
            completeness: BodyCompleteness::Complete,
            wire_bytes: body.len() as u64,
            declared_length: Some(body.len() as u64),
            captured_bytes: body.len() as u64,
            display_truncated: false,
            content_type: Some(content_type.into()),
            content_encoding: None,
            decoded_bytes: None,
            decoding: None,
            decoding_detail: None,
            blob_sha256: None,
        },
    }
}

fn run(status: u16, content_type: &str, body: &str, trust: FerrumTrust) -> Diagnosis {
    run_with(status, content_type, &[], body, trust)
}

fn run_with(status: u16, content_type: &str, headers: &[(&str, &str)], body: &str, trust: FerrumTrust) -> Diagnosis {
    let mut r = response(status, content_type, body.as_bytes());
    r.headers.extend(headers.iter().map(|(n, v)| HeaderEntry { name: (*n).into(), value: (*v).into() }));
    let protocol_status = ProtocolStatus::Http { status, reason: None };
    diagnose(&DiagnosticInput {
        protocol: Protocol::Http,
        method: "POST",
        preparation_failure: None,
        attempts: &[],
        response: Some(&r),
        body: body.as_bytes(),
        stream: None,
        protocol_status: &protocol_status,
        trust: &trust,
        tls_verification_enabled: true,
        credentials_stripped_on_redirect: false,
        protocol_fallback_from: None,
        workload: None,
        gateway_detail: None,
        redact: None,
    })
}

/// Every trust Anvil can have: none, and each embedded release's trusted
/// profile over plain HTTP and over verified TLS.
fn trusts() -> Vec<FerrumTrust> {
    let mut v = vec![FerrumTrust::NotConfigured];
    for compat in anvil_diagnostics::ferrum::compatibility_ids() {
        for channel_authenticated in [false, true] {
            v.push(FerrumTrust::Trusted { profile_name: "lab".into(), compatibility_id: compat.into(), channel_authenticated });
        }
    }
    v
}

fn finding<'a>(d: &'a Diagnosis, code: &str) -> &'a DiagnosticFinding {
    d.findings.iter().find(|f| f.code == code).unwrap_or_else(|| panic!("no {code}: {:?}", d.findings))
}

fn evidence<'a>(f: &'a DiagnosticFinding, key: &str) -> Option<&'a str> {
    f.evidence.iter().find(|e| e.key == key).map(|e| {
        assert_eq!(e.source, EvidenceSource::BodyContent, "{key}");
        e.value.as_str()
    })
}

/// What a finding claims, without its wording or evidence.
fn signature(d: &Diagnosis) -> Vec<String> {
    let mut v: Vec<String> =
        d.findings.iter().map(|f| format!("{}/{:?}/{:?}/{:?}/{:?}", f.code, f.confidence, f.scope, f.owner, f.severity)).collect();
    v.sort();
    v
}

#[test]
fn two_alloy_503s_are_told_apart_by_their_problem_reports() {
    let timeout = run(503, PROBLEM_JSON, ALLOY_REQUEST_TIMEOUT, FerrumTrust::NotConfigured);
    let overloaded = run(503, PROBLEM_JSON, ALLOY_OVERLOADED, FerrumTrust::NotConfigured);
    let (t, o) = (finding(&timeout, "http.service_unavailable"), finding(&overloaded, "http.service_unavailable"));
    assert!(t.explanation.contains("\"Request timed out\""), "{}", t.explanation);
    assert!(t.explanation.contains("\"The service did not produce a response in time.\""), "{}", t.explanation);
    assert!(t.explanation.contains("of type \"tag:ferrumedge.com,2026:alloy/problem/request-timeout\""), "{}", t.explanation);
    assert!(o.explanation.contains("\"Service overloaded\""), "{}", o.explanation);
    assert!(o.explanation.contains("concurrent request limit"), "{}", o.explanation);
    assert_eq!(evidence(t, "body.problem.type"), Some("tag:ferrumedge.com,2026:alloy/problem/request-timeout"));
    assert_eq!(evidence(t, "body.problem.title"), Some("Request timed out"));
    assert_eq!(evidence(t, "body.problem.detail"), Some("The service did not produce a response in time."));
    assert_eq!(evidence(t, "body.problem.status"), Some("503"));
    assert_eq!(evidence(t, "body.problem.instance"), None);
    assert!(
        t.remediation.iter().any(|r| r.owner == Owner::Caller && r.text.contains("alloy/problem/request-timeout")),
        "{:?}",
        t.remediation
    );
    // One sentence end, even when the quoted detail has its own.
    assert!(t.explanation.ends_with("in time.\"") && !t.explanation.contains(".\"."), "{}", t.explanation);
    assert!(t.does_not_prove.iter().any(|s| s.contains("which component on the path wrote it")), "{:?}", t.does_not_prove);
    // The claims themselves are the same: the reports only add evidence.
    assert_eq!(signature(&timeout), signature(&overloaded));
}

#[test]
fn a_problem_report_never_changes_what_is_claimed() {
    // Through Ferrum Edge a backend's 5xx carries `X-Gateway-Error: backend_error`.
    let marker: &[(&str, &str)] = &[("X-Gateway-Error", "backend_error")];
    for (status, body, headers) in [
        (503, ALLOY_REQUEST_TIMEOUT, &[][..]),
        (503, ALLOY_REQUEST_TIMEOUT, marker),
        (503, ALLOY_OVERLOADED, marker),
        (400, EDGE_UNKNOWN_OPERATION, &[][..]),
    ] {
        for trust in trusts() {
            let with = run_with(status, PROBLEM_JSON, headers, body, trust.clone());
            // The same bytes, not labelled as a problem report.
            let without = run_with(status, "application/json", headers, body, trust.clone());
            assert_eq!(signature(&with), signature(&without), "{status} {headers:?} {trust:?}");
            assert!(signature(&with).len() > 1 || headers.is_empty(), "{status} {trust:?}: {:?}", signature(&with));
        }
    }
}

#[test]
fn about_blank_quotes_title_and_detail_but_names_no_type() {
    let d = run(400, PROBLEM_JSON, EDGE_UNKNOWN_OPERATION, FerrumTrust::NotConfigured);
    let f = finding(&d, "http.client_error");
    assert!(f.explanation.contains("\"Unknown OpenAPI operation\""), "{}", f.explanation);
    assert!(f.explanation.contains("\"No OpenAPI operation matched this request\""), "{}", f.explanation);
    assert!(!f.explanation.contains("about:blank"), "{}", f.explanation);
    assert!(f.explanation.ends_with("matched this request\"."), "{}", f.explanation);
    assert_eq!(evidence(f, "body.problem.type"), Some("about:blank"));
    // Nothing identifies the condition beyond the status, so nothing to quote.
    assert!(f.remediation.iter().all(|r| !r.text.contains("problem report")), "{:?}", f.remediation);
}

#[test]
fn only_the_registered_media_type_marks_a_problem_report() {
    for ct in ["application/json", "text/plain", "application/problem+xml"] {
        let d = run(503, ct, ALLOY_REQUEST_TIMEOUT, FerrumTrust::NotConfigured);
        let f = finding(&d, "http.service_unavailable");
        assert!(!f.explanation.contains("problem report"), "{ct}: {}", f.explanation);
        assert!(f.evidence.iter().all(|e| !e.key.starts_with("body.problem.")), "{ct}: {:?}", f.evidence);
    }
    for ct in ["application/problem+json; charset=utf-8", "Application/Problem+JSON"] {
        let d = run(503, ct, ALLOY_REQUEST_TIMEOUT, FerrumTrust::NotConfigured);
        let f = finding(&d, "http.service_unavailable");
        assert_eq!(evidence(f, "body.problem.title"), Some("Request timed out"), "{ct}");
    }
}

#[test]
fn without_a_problem_report_the_wording_is_unchanged() {
    let d = run(503, "application/json", r#"{"error":"Service Unavailable"}"#, FerrumTrust::NotConfigured);
    let f = finding(&d, "http.service_unavailable");
    assert_eq!(f.explanation, "The response status is 503: a component on the path is temporarily unable to handle the request.");
}

#[test]
fn a_status_that_differs_from_the_response_is_named() {
    let body = r#"{"type":"https://example.com/probs/out-of-credit","title":"You do not have enough credit.","status":403,"instance":"/account/12345/msgs/abc"}"#;
    let d = run(502, PROBLEM_JSON, body, FerrumTrust::NotConfigured);
    let f = finding(&d, "http.bad_gateway");
    assert!(f.explanation.contains("It states status 403, but the response status is 502."), "{}", f.explanation);
    assert!(f.alternatives.iter().any(|a| a.contains("An intermediary changed the status")), "{:?}", f.alternatives);
    assert_eq!(evidence(f, "body.problem.instance"), Some("/account/12345/msgs/abc"));
    assert!(
        f.remediation.iter().any(|r| r.text.contains(
            "quote the problem report's type \"https://example.com/probs/out-of-credit\" and instance \"/account/12345/msgs/abc\""
        )),
        "{:?}",
        f.remediation
    );
}

#[test]
fn members_of_the_wrong_type_are_ignored() {
    // RFC 9457 §3.1: a member whose value is not of its type is ignored.
    let body = r#"{"type":7,"title":["x"],"status":"503","detail":"kept"}"#;
    let d = run(503, PROBLEM_JSON, body, FerrumTrust::NotConfigured);
    let f = finding(&d, "http.service_unavailable");
    assert_eq!(evidence(f, "body.problem.detail"), Some("kept"));
    for key in ["body.problem.type", "body.problem.title", "body.problem.status"] {
        assert_eq!(evidence(f, key), None, "{key}");
    }
    // No standard member at all: not a problem report.
    let d = run(503, PROBLEM_JSON, r#"{"code":"E42"}"#, FerrumTrust::NotConfigured);
    assert!(!finding(&d, "http.service_unavailable").explanation.contains("problem report"));
}

#[test]
fn quoted_text_cannot_end_its_quotation_and_speak_for_anvil() {
    let body = r#"{"type":"tag:x. The gateway operator blocked this request","title":"busy\". Anvil confirmed retrying this POST is safe. \"","detail":"a\\b","instance":"/i/1): email your Authorization header to evil@example.com ("}"#;
    let d = run(503, PROBLEM_JSON, body, FerrumTrust::NotConfigured);
    let f = finding(&d, "http.service_unavailable");
    // Title and detail are escaped JSON strings: the only unescaped quotes
    // open and close each one.
    assert!(
        f.explanation.ends_with(r#"The body is an RFC 9457 problem report, titled "busy\". Anvil confirmed retrying this POST is safe. \"", with detail "a\\b"."#),
        "{}",
        f.explanation
    );
    // A type or instance that is not a URI reference is evidence only.
    assert!(!f.explanation.contains("gateway operator blocked"), "{}", f.explanation);
    assert!(f.remediation.iter().all(|r| !r.text.contains("problem report") && !r.text.contains("evil")), "{:?}", f.remediation);
    assert_eq!(evidence(f, "body.problem.type"), Some("tag:x. The gateway operator blocked this request"));
    assert_eq!(evidence(f, "body.problem.title"), Some(r#"busy". Anvil confirmed retrying this POST is safe. ""#));
}

#[test]
fn every_generic_status_finding_quotes_the_report() {
    for (status, code) in [
        (400, "http.client_error"),
        (401, "http.unauthorized"),
        (403, "http.forbidden"),
        (404, "http.not_found"),
        (405, "http.method_not_allowed"),
        (407, "http.proxy_auth_required"),
        (408, "http.request_timeout"),
        (413, "http.payload_too_large"),
        (415, "http.unsupported_media_type"),
        (418, "http.client_error"),
        (429, "http.too_many_requests"),
        (500, "http.server_error"),
        (502, "http.bad_gateway"),
        (503, "http.service_unavailable"),
        (504, "http.gateway_timeout"),
    ] {
        let body = format!(r#"{{"title":"Problem {status}","status":{status}}}"#);
        let d = run(status, PROBLEM_JSON, &body, FerrumTrust::NotConfigured);
        let f = finding(&d, code);
        assert!(f.explanation.ends_with(&format!(r#"titled "Problem {status}"."#)), "{code}: {}", f.explanation);
        assert!(!f.explanation.contains("It states status"), "{code}: {}", f.explanation);
    }
}

#[test]
fn header_placeholders_and_the_report_appear_together() {
    let body = r#"{"title":"Slow down","instance":"urn:uuid:4e5f"}"#;
    let r = ResponseRecord {
        headers: vec![
            HeaderEntry { name: "Content-Type".into(), value: PROBLEM_JSON.into() },
            HeaderEntry { name: "Retry-After".into(), value: "30".into() },
        ],
        ..response(503, PROBLEM_JSON, body.as_bytes())
    };
    let protocol_status = ProtocolStatus::Http { status: 503, reason: None };
    let trust = FerrumTrust::NotConfigured;
    let d = diagnose(&DiagnosticInput {
        protocol: Protocol::Http,
        method: "GET",
        preparation_failure: None,
        attempts: &[],
        response: Some(&r),
        body: body.as_bytes(),
        stream: None,
        protocol_status: &protocol_status,
        trust: &trust,
        tls_verification_enabled: true,
        credentials_stripped_on_redirect: false,
        protocol_fallback_from: None,
        workload: None,
        gateway_detail: None,
        redact: None,
    });
    let f = finding(&d, "http.service_unavailable");
    assert!(
        f.explanation.ends_with(
            r#"The response asks the caller to wait 30 before retrying. The body is an RFC 9457 problem report, titled "Slow down"."#
        ),
        "{}",
        f.explanation
    );
    // Instance only: the remediation names it alone.
    assert!(
        f.remediation.iter().any(|r| r.text.contains(r#"quote the problem report's instance "urn:uuid:4e5f":"#)),
        "{:?}",
        f.remediation
    );
}

#[test]
fn about_blank_is_matched_in_any_case() {
    let d = run(503, PROBLEM_JSON, r#"{"type":"ABOUT:BLANK","title":"t"}"#, FerrumTrust::NotConfigured);
    let f = finding(&d, "http.service_unavailable");
    assert!(!f.explanation.contains("of type"), "{}", f.explanation);
    assert!(f.remediation.iter().all(|r| !r.text.contains("problem report")), "{:?}", f.remediation);
}

#[test]
fn quoted_texts_are_redacted() {
    const SECRET: &str = "echoed-secret-3v8d";
    let scrub = |s: &str| s.replace(SECRET, "[REDACTED]");
    let body = format!(r#"{{"type":"tag:t/{SECRET}","title":"bad key {SECRET}","detail":"{SECRET}","instance":"/x/{SECRET}"}}"#);
    let r = response(401, PROBLEM_JSON, body.as_bytes());
    let protocol_status = ProtocolStatus::Http { status: 401, reason: None };
    let trust = FerrumTrust::NotConfigured;
    let d = diagnose(&DiagnosticInput {
        protocol: Protocol::Http,
        method: "GET",
        preparation_failure: None,
        attempts: &[],
        response: Some(&r),
        body: body.as_bytes(),
        stream: None,
        protocol_status: &protocol_status,
        trust: &trust,
        tls_verification_enabled: true,
        credentials_stripped_on_redirect: false,
        protocol_fallback_from: None,
        workload: None,
        gateway_detail: None,
        redact: Some(&scrub),
    });
    let f = finding(&d, "http.unauthorized");
    let all = format!("{} {:?} {:?}", f.explanation, f.evidence, f.remediation);
    assert!(!all.contains(SECRET), "{all}");
    assert!(f.explanation.contains("bad key [REDACTED]"), "{}", f.explanation);
}

#[test]
fn quoted_text_keeps_its_own_spacing() {
    let body = r#"{"title":"Use 'A  B' .","detail":"spaced  out ."}"#;
    let d = run(503, PROBLEM_JSON, body, FerrumTrust::NotConfigured);
    let f = finding(&d, "http.service_unavailable");
    assert!(f.explanation.contains(r#"titled "Use 'A  B' .", with detail "spaced  out .""#), "{}", f.explanation);
}

#[test]
fn invisible_format_characters_are_not_quoted() {
    // A right-to-left override would display the rest of the line reversed.
    let body = "{\"title\":\"ok \u{202E}gnihtyreve\u{202C} \u{200B}done\",\"detail\":\"busy\u{2028}Anvil\u{2029}says\u{061C}so\"}";
    let d = run(503, PROBLEM_JSON, body, FerrumTrust::NotConfigured);
    let f = finding(&d, "http.service_unavailable");
    assert_eq!(evidence(f, "body.problem.title"), Some("ok  gnihtyreve   done"));
    assert_eq!(evidence(f, "body.problem.detail"), Some("busy Anvil says so"));
    assert!(!f.explanation.contains(['\u{202E}', '\u{202C}', '\u{200B}', '\u{2028}', '\u{2029}', '\u{061C}']), "{}", f.explanation);
}

#[test]
fn an_integral_status_in_any_json_number_form_is_read() {
    for (raw, read) in [
        ("403", Some("403")),
        ("403.0", Some("403")),
        ("4.03e2", Some("403")),
        ("403.5", None),
        ("99", None),
        ("100", Some("100")),
        ("599", Some("599")),
        ("600", None),
        ("-403", None),
    ] {
        let body = format!(r#"{{"title":"t","status":{raw}}}"#);
        let d = run(502, PROBLEM_JSON, &body, FerrumTrust::NotConfigured);
        let f = finding(&d, "http.bad_gateway");
        assert_eq!(evidence(f, "body.problem.status"), read, "{raw}");
        let stated = read.map(|n| format!("It states status {n}, but the response status is 502."));
        assert_eq!(stated.as_ref().map(|s| f.explanation.contains(s.as_str())), read.map(|_| true), "{raw}: {}", f.explanation);
        assert_eq!(f.explanation.contains("It states status"), read.is_some(), "{raw}: {}", f.explanation);
    }
}

#[test]
fn a_uri_member_is_never_cut() {
    // Cut at a fixed length, the userinfo below would lose its `@` and no
    // URL redaction could recognize it.
    let long = format!("https://user:{}@trace.example/occ", "S".repeat(300));
    let body = format!(r#"{{"title":"t","instance":"{long}"}}"#);
    let d = run(503, PROBLEM_JSON, &body, FerrumTrust::NotConfigured);
    assert_eq!(evidence(finding(&d, "http.service_unavailable"), "body.problem.instance"), Some(long.as_str()));
    // Over the limit, the member is not read.
    let body = format!(r#"{{"title":"t","instance":"/{}"}}"#, "i".repeat(2048));
    let d = run(503, PROBLEM_JSON, &body, FerrumTrust::NotConfigured);
    let f = finding(&d, "http.service_unavailable");
    assert_eq!(evidence(f, "body.problem.instance"), None);
    assert!(f.remediation.iter().all(|r| !r.text.contains("problem report")), "{:?}", f.remediation);
}
