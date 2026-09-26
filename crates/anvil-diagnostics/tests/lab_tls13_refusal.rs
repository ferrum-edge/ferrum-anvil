//! Regression found by the real-gateway lab (`anvil-lab run tls`, TLS-005,
//! TLS-006, TLS-014): Ferrum Edge 0.9.5 refuses a missing or untrusted client
//! certificate after the client's TLS 1.3 flight. Usually Anvil reads the
//! `certificate_required` / `unknown_ca` alert, but in some runs the gateway's
//! reset discarded the alert and Anvil saw only "connection closed before a
//! response". The tests reproduce that public evidence — never the lab's
//! ground truth — and the lookalikes that must not get the TLS explanation.

use anvil_diagnostics::{Diagnosis, DiagnosticInput, FerrumTrust, diagnose};
use anvil_domain::diagnostics::{Confidence, SourceScope};
use anvil_domain::execution::{
    AttemptObservation, AttemptReason, ByteCounts, CertificateSummary, ConnectionObservation, DispatchState, FailureKind, Phase,
    TlsObservation, TlsVerification, TransportFailure,
};
use anvil_domain::outcome::ProtocolStatus;
use anvil_domain::request::Protocol;

fn cert(subject: &str) -> CertificateSummary {
    CertificateSummary {
        subject: subject.into(),
        issuer: "CN=issuer".into(),
        subject_alt_names: vec![],
        not_before: String::new(),
        not_after: String::new(),
        serial_hex: "01".into(),
        sha256_fingerprint: "00".into(),
        is_ca: false,
        key_algorithm: "ECDSA".into(),
    }
}

struct Shape {
    version: &'static str,
    requested: Option<bool>,
    presented: Option<&'static str>,
    reused: bool,
    kind: FailureKind,
    alert: Option<&'static str>,
}

fn attempt(s: &Shape) -> AttemptObservation {
    let mut failure = TransportFailure::new(Phase::AwaitResponseHeaders, s.kind, "connection closed");
    failure.tls_alert = s.alert.map(|a| a.to_string());
    AttemptObservation {
        index: 0,
        reason: AttemptReason::Initial,
        method: "GET".into(),
        url: "https://localhost:18343/tls/echo".into(),
        started_at: chrono::Utc::now(),
        connection: Some(ConnectionObservation {
            id: 1,
            reused: s.reused,
            protocol: Some("h2".into()),
            local_address: None,
            remote_address: Some("127.0.0.1:18343".into()),
            resolved_addresses: vec!["127.0.0.1".into()],
            resolution_source: Some("override".into()),
            connect_attempts: vec![],
            via_proxy: None,
            tls: Some(TlsObservation {
                server_name: "localhost".into(),
                sni: Some("localhost".into()),
                server_name_overridden: false,
                identity_check: None,
                peer_spiffe_id: None,
                version: Some(s.version.into()),
                cipher_suite: None,
                alpn_offered: vec!["h2".into(), "http/1.1".into()],
                alpn_negotiated: Some("h2".into()),
                verification: TlsVerification::Verified,
                peer_certificates: vec![cert("CN=anvil-lab-gateway")],
                client_certificate_requested: s.requested,
                client_certificate_presented: s.presented.map(cert),
                alert_received: None,
                resumed: Some(false),
            }),
            prior_requests: if s.reused { 3 } else { 0 },
            tunnel: None,
            proxy_header: None,
        }),
        phases: vec![],
        dispatch: DispatchState::NotDispatched,
        bytes: ByteCounts::default(),
        response_status: None,
        failure: Some(failure),
        duration_us: 1,
    }
}

fn diagnose_shape(s: &Shape) -> Diagnosis {
    let attempts = vec![attempt(s)];
    let trust = FerrumTrust::NotConfigured;
    diagnose(&DiagnosticInput {
        protocol: Protocol::Http,
        method: "GET",
        preparation_failure: None,
        attempts: &attempts,
        response: None,
        body: &[],
        stream: None,
        protocol_status: &ProtocolStatus::None,
        trust: &trust,
        tls_verification_enabled: true,
        credentials_stripped_on_redirect: false,
        protocol_fallback_from: None,
    })
}

fn find<'a>(d: &'a Diagnosis, code: &str) -> Option<&'a anvil_domain::diagnostics::DiagnosticFinding> {
    d.findings.iter().find(|f| f.code == code)
}

const CODE: &str = "client.tls.closed_after_certificate_request";

#[test]
fn tls005_lost_alert_after_certificate_request_is_likely_a_missing_certificate() {
    let d = diagnose_shape(&Shape {
        version: "TLSv1_3",
        requested: Some(true),
        presented: None,
        reused: false,
        kind: FailureKind::ClosedBeforeResponse,
        alert: None,
    });
    let f = find(&d, CODE).expect("TLS explanation for the lost alert");
    assert_eq!(f.confidence, Confidence::Likely);
    assert_eq!(f.scope, SourceScope::ClientToPeer);
    assert!(f.explanation.contains("no client certificate") && !f.explanation.contains('{'), "{}", f.explanation);
    assert!(f.does_not_prove.iter().any(|x| x.contains("401")));
    // The observed transport fact stays reported too.
    assert!(find(&d, "exchange.closed_before_response").is_some());
}

#[test]
fn tls006_lost_alert_with_a_presented_certificate_stays_unknown() {
    let d = diagnose_shape(&Shape {
        version: "TLSv1_3",
        requested: Some(true),
        presented: Some("CN=anvil-lab-client-rogue"),
        reused: false,
        kind: FailureKind::RequestWriteFailed,
        alert: None,
    });
    let f = find(&d, CODE).expect("finding");
    assert_eq!(f.confidence, Confidence::Unknown, "without the alert, a rejection of a presented certificate is not established");
    assert!(f.explanation.contains("CN=anvil-lab-client-rogue"));
}

#[test]
fn lookalikes_do_not_get_the_tls_explanation() {
    let base = Shape {
        version: "TLSv1_3",
        requested: Some(true),
        presented: None,
        reused: false,
        kind: FailureKind::ClosedBeforeResponse,
        alert: None,
    };
    // A reused connection's close has nothing to do with its old handshake.
    assert!(find(&diagnose_shape(&Shape { reused: true, ..base }), CODE).is_none());
    // No certificate request was observed.
    assert!(find(&diagnose_shape(&Shape { requested: Some(false), ..base }), CODE).is_none());
    // TLS 1.2 refusals happen inside the handshake, where the alert is reliable.
    assert!(find(&diagnose_shape(&Shape { version: "TLSv1_2", ..base }), CODE).is_none());
    // A readable alert is handled by the alert-specific rules.
    let with_alert = diagnose_shape(&Shape { kind: FailureKind::TlsAlertAfterHandshake, alert: Some("certificate_required"), ..base });
    assert!(find(&with_alert, CODE).is_none());
    assert!(find(&with_alert, "client.tls.client_cert_required").is_some());
}
