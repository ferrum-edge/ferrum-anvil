//! HBONE tunnel-leg findings over public evidence only (the shapes the real
//! Ferrum Edge 0.9.7 mesh lab produced, plus lookalikes): the tunnel leg is
//! attributed to the configured hop (`forward_proxy`), the mTLS failure is
//! split by who decided, a CONNECT refusal keeps its public body without a
//! precise policy claim, and the inner destination is never blamed.

use anvil_diagnostics::{Diagnosis, DiagnosticInput, FerrumTrust, diagnose};
use anvil_domain::diagnostics::{Confidence, SourceScope};
use anvil_domain::execution::*;
use anvil_domain::outcome::ProtocolStatus;
use anvil_domain::request::Protocol;

const ENDPOINT: &str = "mesh hbone (127.0.0.1:17618)";
const AUTHORITY: &str = "127.0.0.1:17801";

fn svid(uri: &str) -> CertificateSummary {
    CertificateSummary {
        subject: "O=Ferrum Anvil Mesh Lab, CN=x".into(),
        issuer: "CN=mesh root".into(),
        subject_alt_names: vec![format!("URI:{uri}")],
        not_before: String::new(),
        not_after: String::new(),
        serial_hex: "01".into(),
        sha256_fingerprint: "00".into(),
        is_ca: false,
        key_algorithm: "EC-256".into(),
    }
}

fn outer_tls(verification: TlsVerification, presented: bool) -> TlsObservation {
    TlsObservation {
        server_name: "127.0.0.1".into(),
        sni: None,
        server_name_overridden: false,
        identity_check: Some(PeerIdentityCheck::SpiffeId {
            expected: "spiffe://cluster.local/ns/ferrum/sa/anvil-lab-ztunnel".into(),
            trust_domain: "cluster.local".into(),
        }),
        peer_spiffe_id: Some("spiffe://cluster.local/ns/ferrum/sa/anvil-lab-ztunnel".into()),
        version: Some("TLSv1_3".into()),
        cipher_suite: None,
        alpn_offered: vec!["h2".into()],
        alpn_negotiated: Some("h2".into()),
        verification,
        peer_certificates: vec![svid("spiffe://cluster.local/ns/ferrum/sa/anvil-lab-ztunnel")],
        client_certificate_requested: Some(true),
        client_certificate_presented: presented.then(|| svid("spiffe://cluster.local/ns/ferrum/sa/anvil-lab-client")),
        alert_received: None,
        resumed: Some(false),
    }
}

struct Shape {
    kind: FailureKind,
    inner: TransportFailure,
    tls: Option<TlsObservation>,
    status: Option<u16>,
    body: Option<&'static str>,
}

fn attempt(s: &Shape) -> AttemptObservation {
    let mut f = TransportFailure::new(Phase::ProxyTunnel, s.kind, format!("tunnel leg failed: {}", s.inner.message));
    f.tls_alert = s.inner.tls_alert.clone();
    f.status = s.status;
    AttemptObservation {
        index: 0,
        reason: AttemptReason::Initial,
        method: "POST".into(),
        url: format!("http://{AUTHORITY}/orders"),
        started_at: chrono::Utc::now(),
        connection: Some(ConnectionObservation {
            id: 1,
            reused: false,
            protocol: None,
            local_address: None,
            remote_address: None,
            resolved_addresses: vec![],
            resolution_source: None,
            connect_attempts: vec![],
            via_proxy: Some(ENDPOINT.into()),
            tls: None,
            proxy_header: None,
            prior_requests: 0,
            tunnel: Some(TunnelObservation {
                kind: TunnelKind::Hbone,
                endpoint: ENDPOINT.into(),
                authority: AUTHORITY.into(),
                resolved_addresses: vec!["127.0.0.1:17618".into()],
                resolution_source: Some("literal".into()),
                connect_attempts: vec![],
                local_address: None,
                remote_address: Some("127.0.0.1:17618".into()),
                phases: vec![],
                tls: s.tls.clone(),
                connect_headers: vec![HeaderEntry { name: "x-ferrum-mesh-protocol".into(), value: "hbone".into() }],
                connect_status: s.status,
                response_headers: vec![],
                refusal_body: s.body.map(String::from),
                refusal_body_truncated: false,
                failure: Some(s.inner.clone()),
                datagrams: None,
            }),
        }),
        phases: vec![],
        dispatch: DispatchState::NotDispatched,
        bytes: ByteCounts::default(),
        response_status: None,
        failure: Some(f),
        duration_us: 1,
    }
}

fn run(s: &Shape) -> Diagnosis {
    let attempts = vec![attempt(s)];
    let trust = FerrumTrust::NotConfigured;
    diagnose(&DiagnosticInput {
        protocol: Protocol::Http,
        method: "POST",
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
        workload: None,
    })
}

fn find<'a>(d: &'a Diagnosis, code: &str) -> &'a anvil_domain::diagnostics::DiagnosticFinding {
    d.findings
        .iter()
        .find(|f| f.code == code)
        .unwrap_or_else(|| panic!("{code}: {:?}", d.findings.iter().map(|f| &f.code).collect::<Vec<_>>()))
}

fn no_destination_blame(d: &Diagnosis) {
    for f in &d.findings {
        assert!(
            !(f.code.starts_with("http.")
                || f.code.starts_with("client.connect")
                || f.code.starts_with("client.dns")
                || f.code.starts_with("ferrum.")),
            "the inner destination is never blamed: {}",
            f.code
        );
        assert!(!f.explanation.contains('{'), "unfilled placeholder in {}: {}", f.code, f.explanation);
        assert!(f.code != "request.processing_uncertain", "a not-dispatched request is not uncertain");
    }
}

fn inner(phase: Phase, kind: FailureKind, alert: Option<&str>) -> TransportFailure {
    let mut f = TransportFailure::new(phase, kind, "observed failure");
    f.tls_alert = alert.map(String::from);
    f
}

#[test]
fn a_404_relay_synthesis_refusal_quotes_the_body_and_claims_no_policy() {
    // Ferrum Edge 0.9.7: an authority the terminator does not own is refused
    // at relay synthesis with a generic 404 (MESH-009/010/011).
    let d = run(&Shape {
        kind: FailureKind::HboneConnectRefused,
        inner: inner(Phase::ProxyTunnel, FailureKind::HboneConnectRefused, None),
        tls: Some(outer_tls(TlsVerification::Verified, true)),
        status: Some(404),
        body: Some(r#"{"error":"Not Found"}"#),
    });
    let f = find(&d, "hbone.tunnel_refused");
    assert_eq!(f.scope, SourceScope::ForwardProxy);
    assert_eq!(f.confidence, Confidence::Confirmed, "the answer came over the verified mTLS connection");
    assert!(
        f.explanation.contains("HTTP 404") && f.explanation.contains("Not Found") && f.explanation.contains(AUTHORITY),
        "{}",
        f.explanation
    );
    assert!(f.does_not_prove.iter().any(|x| x.contains("Which mesh policy")));
    assert!(f.evidence.iter().any(|e| e.key == "tunnel.connect_headers" && e.value.contains("x-ferrum-mesh-protocol")));
    no_destination_blame(&d);
}

#[test]
fn a_refusal_over_an_unverified_endpoint_is_only_likely_from_it() {
    let d = run(&Shape {
        kind: FailureKind::HboneConnectRefused,
        inner: inner(Phase::ProxyTunnel, FailureKind::HboneConnectRefused, None),
        tls: Some(outer_tls(TlsVerification::Bypassed { would_have_failed: None }, true)),
        status: Some(403),
        body: Some(r#"{"error":"HBONE tunnel requires an authenticated mesh peer"}"#),
    });
    assert_eq!(find(&d, "hbone.tunnel_refused").confidence, Confidence::Likely);
    let b = find(&d, "client.tls.verification_bypassed");
    assert_eq!(b.scope, SourceScope::ForwardProxy);
    assert!(b.explanation.contains("HBONE endpoint"));
    no_destination_blame(&d);
}

#[test]
fn a_5xx_on_connect_makes_no_leg_claim() {
    let d = run(&Shape {
        kind: FailureKind::HboneConnectRefused,
        inner: inner(Phase::ProxyTunnel, FailureKind::HboneConnectRefused, None),
        tls: Some(outer_tls(TlsVerification::Verified, true)),
        status: Some(503),
        body: Some(r#"{"error":"HBONE backend unavailable"}"#),
    });
    let f = find(&d, "hbone.tunnel_unavailable");
    assert!(f.does_not_prove.iter().any(|x| x.contains("which leg")));
    no_destination_blame(&d);
}

#[test]
fn mtls_failures_are_split_by_who_decided() {
    // Anvil rejected the endpoint (local verification decision).
    let mut tls = outer_tls(
        TlsVerification::Failed {
            problem: FailureKind::TlsSpiffeIdMismatch,
            detail: "the server's SPIFFE ID is spiffe://cluster.local/ns/ferrum/sa/anvil-lab-ztunnel, not the expected spiffe://cluster.local/ns/ferrum/sa/anvil-lab-other".into(),
        },
        false,
    );
    tls.client_certificate_requested = None;
    let d = run(&Shape {
        kind: FailureKind::HboneEndpointTlsFailed,
        inner: inner(Phase::TlsHandshake, FailureKind::TlsSpiffeIdMismatch, None),
        tls: Some(tls),
        status: None,
        body: None,
    });
    let f = find(&d, "hbone.endpoint_identity_rejected");
    assert_eq!((f.confidence, f.scope), (Confidence::Confirmed, SourceScope::ForwardProxy));
    assert!(f.explanation.contains("anvil-lab-other"), "{}", f.explanation);
    no_destination_blame(&d);

    // The endpoint required a client SVID (certificate_required, none presented).
    let d = run(&Shape {
        kind: FailureKind::HboneEndpointTlsFailed,
        inner: inner(Phase::TlsHandshake, FailureKind::TlsAlertAfterHandshake, Some("certificate_required")),
        tls: Some(outer_tls(TlsVerification::Verified, false)),
        status: None,
        body: None,
    });
    assert_eq!(find(&d, "hbone.client_svid_required").confidence, Confidence::Confirmed);
    no_destination_blame(&d);

    // Ferrum 0.9.7 answers an untrusted-trust-domain SVID with handshake_failure
    // after the client's TLS 1.3 Finished (MESH-013).
    let d = run(&Shape {
        kind: FailureKind::HboneEndpointTlsFailed,
        inner: inner(Phase::TlsHandshake, FailureKind::TlsAlertAfterHandshake, Some("handshake_failure")),
        tls: Some(outer_tls(TlsVerification::Verified, true)),
        status: None,
        body: None,
    });
    let f = find(&d, "hbone.client_svid_rejected");
    assert_eq!(f.confidence, Confidence::Likely);
    assert!(f.explanation.contains("anvil-lab-client"), "{}", f.explanation);
    no_destination_blame(&d);

    // A handshake_failure *during* the handshake is not attributed to the SVID.
    let d = run(&Shape {
        kind: FailureKind::HboneEndpointTlsFailed,
        inner: inner(Phase::TlsHandshake, FailureKind::TlsAlertReceived, Some("handshake_failure")),
        tls: Some(outer_tls(TlsVerification::NotReached, true)),
        status: None,
        body: None,
    });
    assert_eq!(find(&d, "hbone.endpoint_tls_failed").confidence, Confidence::Unknown);
}

#[test]
fn a_lost_tls13_alert_after_a_certificate_request_is_explained_not_confirmed() {
    let lost = |presented: bool| Shape {
        kind: FailureKind::HboneProtocolError,
        inner: inner(Phase::ProxyTunnel, FailureKind::RequestWriteFailed, None),
        tls: Some(outer_tls(TlsVerification::Verified, presented)),
        status: None,
        body: None,
    };
    let d = run(&lost(false));
    let f = find(&d, "hbone.closed_after_certificate_request");
    assert_eq!(f.confidence, Confidence::Likely);
    no_destination_blame(&d);
    assert_eq!(find(&run(&lost(true)), "hbone.closed_after_certificate_request").confidence, Confidence::Unknown);

    // Lookalike: no certificate request observed → a plain tunnel protocol error.
    let mut s = lost(false);
    if let Some(t) = &mut s.tls {
        t.client_certificate_requested = Some(false);
    }
    let d = run(&s);
    find(&d, "hbone.tunnel_protocol_error");
    assert!(d.findings.iter().all(|f| f.code != "hbone.closed_after_certificate_request"));
}

#[test]
fn an_unreachable_endpoint_is_the_tunnel_hop_not_a_generic_proxy_or_the_destination() {
    let d = run(&Shape {
        kind: FailureKind::ProxyConnectFailed,
        inner: inner(Phase::Connect, FailureKind::ConnectRefused, None),
        tls: None,
        status: None,
        body: None,
    });
    let f = find(&d, "hbone.endpoint_unreachable");
    assert_eq!(f.scope, SourceScope::ForwardProxy);
    assert!(d.findings.iter().all(|f| f.code != "proxy.connect_failed"));
    no_destination_blame(&d);
}

#[test]
fn a_direct_tls13_handshake_failure_after_finished_with_a_presented_certificate_is_a_client_cert_refusal() {
    // MESH-006: the STRICT sidecar answers an untrusted-trust-domain client
    // SVID with `handshake_failure` after the client's TLS 1.3 Finished.
    let direct = |kind: FailureKind, presented: bool| {
        let s =
            Shape { kind, inner: inner(Phase::AwaitResponseHeaders, kind, Some("handshake_failure")), tls: None, status: None, body: None };
        let mut a = attempt(&s);
        let c = a.connection.as_mut().unwrap();
        c.tunnel = None;
        c.via_proxy = None;
        c.tls = Some(outer_tls(TlsVerification::Verified, presented));
        a.failure = Some(s.inner.clone());
        let attempts = vec![a];
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
            workload: None,
        })
    };
    let d = direct(FailureKind::TlsAlertAfterHandshake, true);
    assert_eq!(find(&d, "client.tls.client_cert_rejected").confidence, Confidence::Likely);
    // During the handshake, or without a presented certificate, it stays a generic alert.
    let d = direct(FailureKind::TlsAlertReceived, true);
    assert!(d.findings.iter().all(|f| f.code != "client.tls.client_cert_rejected"));
    let d = direct(FailureKind::TlsAlertAfterHandshake, false);
    assert!(d.findings.iter().all(|f| f.code != "client.tls.client_cert_rejected"));
}

// ------------------------------------------------------ UDP (datagrams) ---

/// A UDP session through an HBONE datagram tunnel: `connect_status`,
/// channel facts, the attempt's failure and the datagram counts.
fn udp(
    status: u16,
    channel: HboneDatagramChannel,
    failure: Option<TransportFailure>,
    sent: u64,
    received: u64,
    tls: TlsObservation,
) -> Diagnosis {
    let s = Shape {
        kind: FailureKind::HboneConnectRefused,
        inner: inner(Phase::ProxyTunnel, FailureKind::HboneConnectRefused, None),
        tls: Some(tls),
        status: Some(status),
        body: (status >= 300).then_some(r#"{"error":"HBONE UDP relay destination not allowed"}"#),
    };
    let mut a = attempt(&s);
    a.method = "UDP".into();
    a.url = format!("udp://{AUTHORITY}");
    a.dispatch = match (sent, received) {
        (0, _) => DispatchState::NotDispatched,
        (_, 0) => DispatchState::MayHaveBeenSent,
        _ => DispatchState::Sent,
    };
    let t = a.connection.as_mut().unwrap().tunnel.as_mut().unwrap();
    t.connect_headers = vec![HeaderEntry { name: "x-ferrum-mesh-protocol".into(), value: "udp".into() }];
    t.datagrams = Some(channel);
    if status < 300 {
        t.failure = None;
        a.failure = failure;
    }
    let attempts = vec![a];
    let trust = FerrumTrust::NotConfigured;
    let ps = ProtocolStatus::Udp { datagrams_sent: sent, datagrams_received: received, window_ms: 1000, masque: None };
    diagnose(&DiagnosticInput {
        protocol: Protocol::Udp,
        method: "UDP",
        preparation_failure: None,
        attempts: &attempts,
        response: None,
        body: &[],
        stream: None,
        protocol_status: &ps,
        trust: &trust,
        tls_verification_enabled: true,
        credentials_stripped_on_redirect: false,
        protocol_fallback_from: None,
        workload: None,
    })
}

fn channel(sent: u64, received: u64, closed_by: anvil_domain::outcome::ClosedBy) -> HboneDatagramChannel {
    HboneDatagramChannel { records_sent: sent, records_received: received, closed_by, ..HboneDatagramChannel::new() }
}

fn codes(d: &Diagnosis) -> Vec<String> {
    d.findings.iter().map(|f| f.code.clone()).collect()
}

fn session_failure(kind: FailureKind, h2: Option<u32>) -> TransportFailure {
    let mut f = TransportFailure::new(Phase::Session, kind, "the datagram tunnel ended abnormally");
    f.h2_error_code = h2;
    f
}

#[test]
fn the_endpoint_ending_a_udp_tunnel_is_its_close_and_never_the_destinations() {
    use anvil_domain::diagnostics::Severity;
    use anvil_domain::outcome::ClosedBy;
    // END_STREAM (Ferrum Edge's relay ends this way: MESH-026/027): a warning, confirmed over a verified endpoint.
    let d = udp(200, channel(2, 1, ClosedBy::Peer), None, 2, 1, outer_tls(TlsVerification::Verified, true));
    let f = find(&d, "hbone.udp_tunnel_ended");
    assert_eq!((f.confidence, f.severity, f.scope), (Confidence::Confirmed, Severity::Warning, SourceScope::ForwardProxy));
    assert!(f.explanation.contains("END_STREAM") && f.explanation.contains(AUTHORITY), "{}", f.explanation);
    assert!(f.does_not_prove.iter().any(|x| x.contains("down")), "{:?}", f.does_not_prove);
    assert!(f.alternatives.iter().any(|x| x.contains("ICMP")), "{:?}", f.alternatives);
    // Over an unverified endpoint, the frame's author is only likely.
    let d = udp(200, channel(2, 1, ClosedBy::Peer), None, 2, 1, outer_tls(TlsVerification::Bypassed { would_have_failed: None }, true));
    assert_eq!(find(&d, "hbone.udp_tunnel_ended").confidence, Confidence::Likely);

    // RST_STREAM: an error with its code, and no exchange finding about the destination.
    let mut ch = channel(1, 1, ClosedBy::Abnormal);
    ch.reset_code = Some("CANCEL".into());
    let d = udp(200, ch, Some(session_failure(FailureKind::H2StreamReset, Some(8))), 1, 1, outer_tls(TlsVerification::Verified, true));
    let f = find(&d, "hbone.udp_tunnel_ended");
    assert_eq!(f.severity, Severity::Error);
    assert!(f.explanation.contains("RST_STREAM CANCEL"), "{}", f.explanation);
    assert!(f.evidence.iter().any(|e| e.key == "h2.error_code" && e.value == "CANCEL"));
    assert!(!codes(&d).iter().any(|c| c.starts_with("exchange.") || c.starts_with("response.")), "{:?}", codes(&d));

    // A lost connection has no author: unknown.
    let d = udp(
        200,
        channel(1, 0, ClosedBy::Abnormal),
        Some(session_failure(FailureKind::BodyIncomplete, None)),
        1,
        0,
        outer_tls(TlsVerification::Verified, true),
    );
    assert_eq!(find(&d, "hbone.udp_tunnel_ended").confidence, Confidence::Unknown);

    // Anvil's own end (window, Close) is not an early end.
    let d = udp(200, channel(1, 1, ClosedBy::Client), None, 1, 1, outer_tls(TlsVerification::Verified, true));
    assert!(!codes(&d).iter().any(|c| c.starts_with("hbone.")), "{:?}", codes(&d));
}

#[test]
fn a_truncated_record_and_oversize_datagrams_have_their_own_findings() {
    use anvil_domain::outcome::ClosedBy;
    let mut ch = channel(1, 1, ClosedBy::Abnormal);
    ch.truncated_tail_bytes = 6;
    let d = udp(200, ch, Some(session_failure(FailureKind::BodyIncomplete, None)), 1, 1, outer_tls(TlsVerification::Verified, true));
    let f = find(&d, "hbone.udp_record_truncated");
    assert!(f.explanation.contains("6 byte(s)"), "{}", f.explanation);
    assert!(!codes(&d).contains(&"hbone.udp_tunnel_ended".to_string()), "one finding per end: {:?}", codes(&d));

    let mut ch = channel(1, 1, ClosedBy::Client);
    ch.oversize_refused = 2;
    let d = udp(200, ch, None, 1, 1, outer_tls(TlsVerification::Verified, true));
    let f = find(&d, "hbone.udp_datagram_too_large");
    assert_eq!((f.scope, f.confidence), (SourceScope::LocalClient, Confidence::Confirmed));
    assert!(f.explanation.contains("65,535"), "{}", f.explanation);
}

#[test]
fn udp_tunnel_refusals_add_datagram_alternatives_without_a_cause() {
    use anvil_domain::outcome::ClosedBy;
    let d = udp(403, channel(0, 0, ClosedBy::NotClosed), None, 0, 0, outer_tls(TlsVerification::Verified, true));
    let f = find(&d, "hbone.tunnel_refused");
    assert!(f.explanation.contains("HBONE UDP relay destination not allowed"), "{}", f.explanation);
    assert!(f.alternatives.iter().any(|a| a.contains("UDP (datagram) tunnel") && a.contains(AUTHORITY)), "{:?}", f.alternatives);
    assert!(f.does_not_prove.iter().any(|x| x.contains("Which mesh policy")));
    assert!(!codes(&d).iter().any(|c| c.starts_with("udp.") || c.starts_with("hbone.udp_")), "{:?}", codes(&d));
    no_destination_blame(&d);

    let d = udp(502, channel(0, 0, ClosedBy::NotClosed), None, 0, 0, outer_tls(TlsVerification::Verified, true));
    let f = find(&d, "hbone.tunnel_unavailable");
    assert!(f.alternatives.iter().any(|a| a.contains("does not show whether anything listens")), "{:?}", f.alternatives);
    no_destination_blame(&d);

    // Lookalike: a byte-stream tunnel refusal gets no datagram alternatives.
    let d = run(&Shape {
        kind: FailureKind::HboneConnectRefused,
        inner: inner(Phase::ProxyTunnel, FailureKind::HboneConnectRefused, None),
        tls: Some(outer_tls(TlsVerification::Verified, true)),
        status: Some(403),
        body: Some(r#"{"error":"HBONE relay destination not allowed"}"#),
    });
    assert!(!find(&d, "hbone.tunnel_refused").alternatives.iter().any(|a| a.contains("datagram")));
}

#[test]
fn silence_through_a_udp_tunnel_is_still_only_no_response_observed() {
    use anvil_domain::outcome::ClosedBy;
    let d = udp(200, channel(1, 0, ClosedBy::Client), None, 1, 0, outer_tls(TlsVerification::Verified, true));
    let f = find(&d, "udp.no_response");
    assert_eq!(f.confidence, Confidence::Confirmed);
    assert!(f.alternatives.iter().any(|a| a.contains("without acknowledgement") && a.contains(AUTHORITY)), "{:?}", f.alternatives);
    assert!(f.does_not_prove.iter().any(|x| x.contains("delivered")));
    assert!(!codes(&d).iter().any(|c| c.starts_with("hbone.")), "the tunnel was fine: {:?}", codes(&d));
}
