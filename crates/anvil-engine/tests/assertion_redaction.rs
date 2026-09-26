//! Assertion results are persisted in the execution record and printed by the
//! CLI, so a secret known to the execution must not reach them through a
//! label, an observed value, a validator diagnostic or an evaluation error.
//! Comparisons still see the original values. Real loopback sockets for the
//! engine-level cases, no mocks.

use anvil_domain::assertions::{Assertion, AssertionKind, AssertionResult, Comparison};
use anvil_domain::outcome::{AssertionState, ProtocolStatus, TransportState};
use anvil_domain::request::{KeyValue, RequestSpec};
use anvil_domain::secret::REDACTED;
use anvil_engine::assertions::{Observed, evaluate};
use anvil_engine::redact::Redactor;
use anvil_engine::{Engine, ExecutionContext, ExecutionOutput};
use anvil_transport::recorder::EventCtx;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

const SECRET: &str = "AUDIT-ONLY-FAKE-SECRET-29a7";

fn init() {
    anvil_transport::init();
    anvil_fixtures::init();
}

fn assertion(label: &str, kind: AssertionKind) -> Assertion {
    Assertion { enabled: true, label: label.into(), kind }
}

/// A loopback HTTP/1.1 server answering every connection with a chunked JSON
/// body `{"token":SECRET}`, the secret in an `x-api-key` response header and
/// in an `x-api-key` trailer.
async fn secret_echo_server() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = listener.accept().await else { return };
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut buf = [0u8; 1024];
                while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => head.extend_from_slice(&buf[..n]),
                    }
                }
                let body = format!(r#"{{"token":"{SECRET}"}}"#);
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nx-api-key: {SECRET}\r\nTrailer: x-api-key\r\n\
                     Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n{body}\r\n0\r\nx-api-key: {SECRET}\r\n\r\n",
                    body.len()
                );
                let _ = s.write_all(response.as_bytes()).await;
                let _ = s.shutdown().await;
            });
        }
    });
    port
}

/// Send with the secret in a request header marked sensitive, so the
/// execution's redactor knows the value.
async fn send(port: u16, assertions: Vec<Assertion>) -> ExecutionOutput {
    let mut spec = RequestSpec::http("GET", &format!("http://127.0.0.1:{port}/"));
    let mut h = KeyValue::new("X-Api-Key", SECRET);
    h.sensitive = true;
    spec.headers.push(h);
    spec.assertions = assertions;
    Engine::new().execute(&ExecutionContext::standalone(spec), EventCtx::none(), CancellationToken::new()).await
}

fn result<'a>(o: &'a ExecutionOutput, label: &str) -> &'a AssertionResult {
    o.record.assertion_results.iter().find(|r| r.label == label).unwrap_or_else(|| panic!("no result labelled {label}"))
}

fn assert_no_secret(r: &AssertionResult) {
    let json = serde_json::to_string(r).unwrap();
    assert!(!json.contains(SECRET), "the secret leaked into an assertion result: {json}");
}

#[tokio::test]
async fn failed_schema_and_trailer_assertions_do_not_copy_the_secret_into_the_record() {
    init();
    let port = secret_echo_server().await;
    let schema = r#"{"type":"object","properties":{"token":{"type":"integer"}}}"#;
    let assertions = vec![
        assertion("schema", AssertionKind::JsonSchema { schema: schema.into() }),
        assertion("trailer", AssertionKind::Trailer { name: "x-api-key".into(), comparison: Comparison::Equals, value: "other".into() }),
        // Controls: the header and JSONPath branches already masked their values.
        assertion("header", AssertionKind::Header { name: "x-api-key".into(), comparison: Comparison::Equals, value: "other".into() }),
        assertion("jsonpath", AssertionKind::JsonPath { path: "$.token".into(), comparison: Comparison::Equals, value: "other".into() }),
    ];
    let o = send(port, assertions).await;
    let response = o.record.response.as_ref().expect("a response");
    assert_eq!(response.status, 200);
    assert!(response.trailers_received, "the chunked trailer was received");
    assert_eq!(response.trailer_values("x-api-key"), vec![REDACTED], "the stored trailer is redacted");

    let schema = result(&o, "schema");
    assert!(!schema.passed);
    let actual = schema.actual.as_deref().expect("schema diagnostics");
    assert!(actual.contains("is not of type") && actual.contains("/token"), "the diagnostic keeps its meaning: {actual}");
    assert!(actual.contains(REDACTED), "{actual}");
    for label in ["trailer", "header", "jsonpath"] {
        let r = result(&o, label);
        assert!(!r.passed, "{label} compared the original value against a different one");
        assert_eq!(r.actual.as_deref(), Some(REDACTED), "{label}");
        assert_eq!(r.message, format!("failed (actual: {REDACTED})"), "{label}");
    }
    for r in &o.record.assertion_results {
        assert_no_secret(r);
    }
    assert_eq!(o.record.outcome.assertions, AssertionState::Fail);
    let record = serde_json::to_string(&o.record).unwrap();
    assert!(!record.contains(SECRET), "the secret leaked into the execution record");
}

#[tokio::test]
async fn comparisons_still_use_the_original_values_and_default_labels_are_redacted() {
    init();
    let port = secret_echo_server().await;
    let schema = r#"{"type":"object","properties":{"token":{"type":"string"}}}"#;
    let assertions = vec![
        assertion("", AssertionKind::Trailer { name: "x-api-key".into(), comparison: Comparison::Equals, value: SECRET.into() }),
        assertion("", AssertionKind::JsonPath { path: "$.token".into(), comparison: Comparison::Equals, value: SECRET.into() }),
        assertion("schema", AssertionKind::JsonSchema { schema: schema.into() }),
    ];
    let o = send(port, assertions).await;
    assert_eq!(o.record.assertion_results.len(), 3);
    for r in &o.record.assertion_results {
        assert!(r.passed, "{} compared against the original value: {}", r.label, r.message);
        assert_no_secret(r);
    }
    assert_eq!(o.record.assertion_results[0].label, format!("trailer x-api-key Equals {REDACTED}"));
    assert_eq!(o.record.assertion_results[1].label, format!("$.token Equals {REDACTED}"));
    assert_eq!(o.record.outcome.assertions, AssertionState::Pass);
}

fn observe(body: &[u8], a: &[Assertion], redactor: &Redactor) -> Vec<AssertionResult> {
    let status = ProtocolStatus::None;
    let o = Observed {
        response: None,
        body,
        body_unavailable: None,
        latency_ms: None,
        protocol_status: &status,
        stream: None,
        findings: &[],
        transport: TransportState::Completed,
    };
    evaluate(a, &o, redactor)
}

#[test]
fn schema_diagnostics_scrub_the_json_escaped_form_of_a_secret() {
    // Validator messages quote instance values as JSON, escaping quotes and
    // backslashes, so the raw value never appears verbatim.
    let secret = r#"quoted"and\slashed-7c1e"#;
    let escaped = r#"quoted\"and\\slashed-7c1e"#;
    let r = Redactor::new(vec![secret.into()], vec![]);
    let body = serde_json::to_vec(&serde_json::json!({ "note": secret })).unwrap();
    let a = assertion("schema", AssertionKind::JsonSchema { schema: r#"{"properties":{"note":{"type":"integer"}}}"#.into() });
    let out = observe(&body, &[a], &r);
    assert!(!out[0].passed);
    let json = serde_json::to_string(&out[0]).unwrap();
    for form in [secret, escaped] {
        assert!(!out[0].message.contains(form) && !out[0].actual.as_deref().unwrap_or("").contains(form), "{json}");
    }
    assert!(out[0].message.contains(REDACTED), "{json}");
}

#[test]
fn evaluation_errors_and_user_labels_do_not_repeat_a_secret() {
    let r = Redactor::new(vec![SECRET.into()], vec![]);
    let body = format!(r#"{{"token":"{SECRET}"}}"#);
    let label = format!("token is {SECRET}");
    let a = [
        // An invalid pattern: the regex error quotes the pattern.
        assertion("", AssertionKind::JsonPath { path: "$.token".into(), comparison: Comparison::Matches, value: format!("{SECRET}(") }),
        assertion(&label, AssertionKind::JsonPath { path: "$.token".into(), comparison: Comparison::Equals, value: "other".into() }),
    ];
    let out = observe(body.as_bytes(), &a, &r);
    assert!(out[0].message.starts_with("could not evaluate: invalid pattern"), "{}", out[0].message);
    assert_eq!(out[1].label, format!("token is {REDACTED}"));
    for x in &out {
        assert!(!x.passed);
        let json = serde_json::to_string(x).unwrap();
        assert!(!json.contains(SECRET), "{json}");
    }
}
