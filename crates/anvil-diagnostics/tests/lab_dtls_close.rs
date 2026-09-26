//! Regression found by the real-gateway lab (`anvil-lab run tls`, PROTO-022):
//! Ferrum Edge 0.9.5's DTLS frontend closes the session (close_notify) after
//! refusing a client certificate. The test reproduces only the public
//! evidence the lab observed — never its private ground truth — plus the
//! lookalike (plain UDP silence) that must keep the cautious finding.

use anvil_diagnostics::{Diagnosis, DiagnosticInput, FerrumTrust, diagnose};
use anvil_domain::diagnostics::SourceScope;
use anvil_domain::execution::{Direction, StreamMessage, StreamTranscript};
use anvil_domain::outcome::ProtocolStatus;
use anvil_domain::request::Protocol;

fn message(direction: Direction, kind: &str, size: u64) -> StreamMessage {
    StreamMessage {
        direction,
        offset_us: 0,
        kind: kind.into(),
        size,
        preview: String::new(),
        preview_is_hex: false,
        preview_truncated: false,
        event_id: None,
        event_type: None,
    }
}

fn udp(stream: &StreamTranscript, sent: u64, received: u64) -> Diagnosis {
    let status = ProtocolStatus::Udp { datagrams_sent: sent, datagrams_received: received, window_ms: 1000, masque: None };
    let trust = FerrumTrust::NotConfigured;
    diagnose(&DiagnosticInput {
        protocol: Protocol::Udp,
        method: "DTLS",
        preparation_failure: None,
        attempts: &[],
        response: None,
        body: &[],
        stream: Some(stream),
        protocol_status: &status,
        trust: &trust,
        tls_verification_enabled: true,
        credentials_stripped_on_redirect: false,
        protocol_fallback_from: None,
    })
}

fn codes(d: &Diagnosis) -> Vec<&str> {
    d.findings.iter().map(|f| f.code.as_str()).collect()
}

/// PROTO-022: Ferrum's DTLS 1.3 frontend refuses an unaccepted client
/// certificate after the client's final flight and sends close_notify. The
/// client saw the handshake finish, so "nothing is listening" (the generic
/// silent-UDP alternative) is contradicted by the evidence.
#[test]
fn proto022_dtls_close_notify_without_response_is_not_reported_as_silence() {
    let t = StreamTranscript {
        messages: vec![message(Direction::Sent, "datagram", 16), message(Direction::Received, "close_notify", 0)],
        dropped_messages: 0,
        sent_count: 1,
        received_count: 0,
        sent_bytes: 16,
        received_bytes: 0,
    };
    let d = udp(&t, 1, 0);
    let f = d.findings.iter().find(|f| f.code == "dtls.closed_without_response").expect("peer close is reported");
    assert_eq!(f.scope, SourceScope::ClientToPeer);
    assert!(f.alternatives.iter().any(|a| a.contains("client certificate")), "{:?}", f.alternatives);
    assert!(f.does_not_prove.iter().any(|a| a.contains("Which of these")), "the cause stays open");
    assert!(!codes(&d).contains(&"udp.no_response"), "{:?}", codes(&d));
    assert!(!f.explanation.contains('{'), "every placeholder is filled: {}", f.explanation);
}

/// Lookalike: plain silence (no close_notify) keeps the cautious silent-UDP
/// finding and never claims the peer closed anything.
#[test]
fn proto022_lookalike_plain_silence_stays_udp_no_response() {
    let t = StreamTranscript {
        messages: vec![message(Direction::Sent, "datagram", 16), message(Direction::Sent, "close_notify", 0)],
        dropped_messages: 0,
        sent_count: 1,
        received_count: 0,
        sent_bytes: 16,
        received_bytes: 0,
    };
    let d = udp(&t, 1, 0);
    assert!(codes(&d).contains(&"udp.no_response"), "{:?}", codes(&d));
    assert!(!codes(&d).contains(&"dtls.closed_without_response"), "our own close_notify is not the peer's");
}
