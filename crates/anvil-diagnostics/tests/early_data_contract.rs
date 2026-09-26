//! 0-RTT early data and `425 Too Early` over public evidence: the shapes the
//! engine tests and the `early` lab observe (Ferrum Edge's HTTP/3 listener
//! answers `425 {"error":"Method not allowed in 0-RTT early data"}` to a
//! method outside `FERRUM_TLS_EARLY_DATA_METHODS`). The 425 finding never
//! claims which component answered, even for a trusted gateway, and a request
//! that did not travel as early data is never described as early data.

use anvil_diagnostics::{Diagnosis, DiagnosticInput, FerrumTrust, diagnose};
use anvil_domain::diagnostics::{Confidence, Severity, SourceScope};
use anvil_domain::execution::*;
use anvil_domain::outcome::ProtocolStatus;
use anvil_domain::request::Protocol;

const BODY_425: &[u8] = br#"{"error":"Method not allowed in 0-RTT early data"}"#;

fn early(offered: bool, accepted: Option<bool>, not_used: Option<EarlyDataNotUsed>) -> EarlyDataObservation {
    EarlyDataObservation {
        transport: EarlyDataTransport::Quic,
        method_eligible: not_used != Some(EarlyDataNotUsed::MethodNotEligible),
        resumption_attempted: offered,
        resumption_accepted: offered.then_some(true),
        offered,
        accepted,
        bytes: if offered { 180 } else { 0 },
        bytes_estimated: offered,
        resent_after_handshake: offered && accepted == Some(false),
        not_used,
        tickets_received: 1,
        ticket_max_early_data: Some(u32::MAX),
    }
}

fn attempt(index: u32, reason: AttemptReason, status: u16, e: Option<EarlyDataObservation>) -> AttemptObservation {
    AttemptObservation {
        early_data: e,
        index,
        reason,
        method: "PUT".into(),
        url: "https://127.0.0.1:17243/early/echo".into(),
        started_at: chrono::Utc::now(),
        connection: None,
        phases: vec![],
        dispatch: DispatchState::Sent,
        bytes: ByteCounts::default(),
        response_status: Some(status),
        failure: None,
        duration_us: 1,
    }
}

fn response(status: u16, body: &[u8]) -> ResponseRecord {
    ResponseRecord {
        status,
        reason: None,
        http_version: "HTTP/3".into(),
        headers: vec![HeaderEntry { name: "content-type".into(), value: "application/json".into() }],
        trailers: vec![],
        trailers_received: false,
        body: BodyCapture {
            completeness: BodyCompleteness::Complete,
            wire_bytes: body.len() as u64,
            declared_length: None,
            captured_bytes: body.len() as u64,
            display_truncated: false,
            content_type: Some("application/json".into()),
            content_encoding: None,
            decoded_bytes: None,
            decoding: None,
            decoding_detail: None,
            blob_sha256: None,
        },
    }
}

fn run(attempts: &[AttemptObservation], r: &ResponseRecord, body: &[u8], trusted: bool) -> Diagnosis {
    let status = ProtocolStatus::Http { status: r.status, reason: None };
    let trust = if trusted {
        FerrumTrust::Trusted { profile_name: "lab".into(), compatibility_id: "ferrum-edge-0.9.7".into(), channel_authenticated: true }
    } else {
        FerrumTrust::NotConfigured
    };
    diagnose(&DiagnosticInput {
        protocol: Protocol::Http,
        method: "PUT",
        preparation_failure: None,
        attempts,
        response: Some(r),
        body,
        stream: None,
        protocol_status: &status,
        trust: &trust,
        tls_verification_enabled: true,
        credentials_stripped_on_redirect: false,
        protocol_fallback_from: None,
        workload: None,
    })
}

fn codes(d: &Diagnosis) -> Vec<&str> {
    d.findings.iter().map(|f| f.code.as_str()).collect()
}

#[test]
fn a_425_to_accepted_early_data_then_a_successful_retry() {
    for trusted in [true, false] {
        let attempts = vec![
            attempt(0, AttemptReason::Initial, 425, Some(early(true, Some(true), None))),
            attempt(1, AttemptReason::TooEarlyRetry, 200, Some(early(false, None, Some(EarlyDataNotUsed::RetryAfterTooEarly)))),
        ];
        let d = run(&attempts, &response(200, b"{}"), b"{}", trusted);
        let f = d.findings.iter().find(|f| f.code == "request.too_early").unwrap_or_else(|| panic!("{:?}", codes(&d)));
        assert_eq!(f.confidence, Confidence::Confirmed);
        assert_eq!(f.scope, SourceScope::Unknown, "the 425 never names the component that answered");
        assert_eq!(f.severity, Severity::Info, "the retry succeeded");
        assert!(f.explanation.contains("accepted the early data"), "{}", f.explanation);
        assert!(f.explanation.contains("attempt 1): HTTP 200"), "{}", f.explanation);
        assert!(f.does_not_prove.iter().any(|x| x.contains("Which component")));
        assert!(codes(&d).contains(&"early_data.accepted"));
        assert!(!codes(&d).iter().any(|c| c.starts_with("ferrum.token")), "{:?}", codes(&d));
    }
}

#[test]
fn a_425_to_a_request_not_sent_early_says_so_and_offers_the_alternatives() {
    let attempts = vec![attempt(0, AttemptReason::Initial, 425, Some(early(false, None, Some(EarlyDataNotUsed::NoTicket))))];
    let d = run(&attempts, &response(425, BODY_425), BODY_425, true);
    let f = d.findings.iter().find(|f| f.code == "request.too_early").expect("finding");
    assert_eq!(f.severity, Severity::Warning);
    assert!(f.explanation.contains("did not send this request as early data"), "{}", f.explanation);
    assert!(f.explanation.contains("not retried"), "{}", f.explanation);
    assert!(f.does_not_prove.iter().any(|x| x.contains("travelled as early data")));
    assert!(f.alternatives.iter().any(|a| a.contains("right after its handshake")), "{:?}", f.alternatives);
    assert!(f.alternatives.iter().any(|a| a.contains("Early-Data: 1")));
    assert!(!codes(&d).contains(&"early_data.accepted"));
    assert!(f.evidence.iter().any(|e| e.key == "body.error"), "the public body is evidence, never an instruction");
}

#[test]
fn a_425_without_the_opt_in_is_reported_and_not_retried() {
    let attempts = vec![attempt(0, AttemptReason::Initial, 425, None)];
    let d = run(&attempts, &response(425, BODY_425), BODY_425, false);
    let f = d.findings.iter().find(|f| f.code == "request.too_early").expect("finding");
    assert!(f.explanation.contains("early data is off for this request"), "{}", f.explanation);
    assert!(f.explanation.contains("only for requests covered by the early-data opt-in"), "{}", f.explanation);
}

#[test]
fn rejected_early_data_is_a_transport_resend_not_a_retry() {
    let attempts = vec![attempt(0, AttemptReason::Initial, 200, Some(early(true, Some(false), None)))];
    let d = run(&attempts, &response(200, b"{}"), b"{}", false);
    let f = d.findings.iter().find(|f| f.code == "early_data.rejected").expect("finding");
    assert_eq!(f.severity, Severity::Info);
    assert!(f.explanation.contains("not an application retry"));
    assert!(f.explanation.contains("sent the same request again"));
    assert!(!codes(&d).contains(&"request.too_early"));
}

#[test]
fn quiet_cases_produce_no_early_data_finding() {
    // No opt-in; opt-in with tickets received on a full handshake; a
    // pooled connection. None of these is worth a finding.
    for e in [
        None,
        Some(early(false, None, Some(EarlyDataNotUsed::NoTicket))),
        Some(early(false, None, Some(EarlyDataNotUsed::ConnectionReused))),
        Some(early(false, None, Some(EarlyDataNotUsed::MethodNotEligible))),
    ] {
        let attempts = vec![attempt(0, AttemptReason::Initial, 200, e)];
        let d = run(&attempts, &response(200, b"{}"), b"{}", false);
        assert!(!codes(&d).iter().any(|c| c.starts_with("early_data.") || *c == "request.too_early"), "{:?}", codes(&d));
    }
}
