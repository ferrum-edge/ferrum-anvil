//! DTLS inside an RFC 9298 CONNECT-UDP (MASQUE) tunnel, end to end through
//! the engine: the `h3server` CONNECT-UDP proxy relays every DTLS record to
//! the dimpl `dtls` echo fixture over real sockets (no mocks). Fixture ground
//! truth only checks that a condition was reached; it is never fed to the
//! diagnostic engine.

use anvil_domain::diagnostics::DiagnosticFinding;
use anvil_domain::events::SessionCommand;
use anvil_domain::execution::*;
use anvil_domain::outcome::*;
use anvil_domain::request::*;
use anvil_domain::settings::{SettingsOverrides, TimeoutOverrides};
use anvil_domain::tls::{ClientIdentity, TlsMinVersion, TlsProfile};
use anvil_domain::{Id, auth::AuthConfig, secret::SensitiveValue};
use anvil_engine::{Engine, ExecutionContext, ExecutionOutput};
use anvil_fixtures::dtls::{self as fxdtls, DtlsServerOptions};
use anvil_fixtures::h3server::{self, H3Fixture, H3Options};
use anvil_fixtures::pki::Pem;
use anvil_fixtures::streams::{self, UdpMode};
use anvil_fixtures::{GroundTruth, LabPki, TlsServerOptions};
use anvil_transport::recorder::EventCtx;
use std::sync::OnceLock;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

fn init() {
    anvil_transport::init();
    anvil_fixtures::init();
}

fn pki() -> &'static LabPki {
    static P: OnceLock<LabPki> = OnceLock::new();
    P.get_or_init(LabPki::generate)
}

async fn proxy(options: H3Options) -> H3Fixture {
    let tls = TlsServerOptions::new(pki().server.chain_with(&pki().ca), pki().server.key.clone());
    h3server::serve_with("127.0.0.1:0", tls, options).await.unwrap()
}

/// A DTLS echo whose certificate is `server` (signed by the lab CA, or by
/// the rogue CA for `server_untrusted`).
async fn dtls_echo(server: &Pem, client_auth: bool) -> fxdtls::DtlsFixture {
    let opts = DtlsServerOptions {
        cert_pem: server.cert.clone(),
        key_pem: server.key.clone(),
        client_ca_pem: client_auth.then(|| pki().client_ca.cert.clone()),
    };
    fxdtls::serve("127.0.0.1:0", opts).await.unwrap()
}

/// One TLS profile (trusting only the lab CA) for the proxy's QUIC handshake
/// and the DTLS handshake with the target.
fn ctx(target: &str, proxy: &H3Fixture, template: &str, mode: MasqueDatagramMode, identity: Option<&Pem>) -> ExecutionContext {
    let mut s = RequestSpec::http("GET", target);
    s.protocol = Protocol::Udp;
    s.udp = Some(UdpSpec {
        dtls: true,
        datagrams: vec![StreamPayload { data: "secure hello".into(), encoding: PayloadEncoding::Text }],
        response_window_ms: 500,
        max_datagrams: 10,
        proxy_protocol: None,
        masque: Some(MasqueSpec {
            proxy_url: format!("https://127.0.0.1:{}", proxy.addr.port()),
            uri_template: template.into(),
            datagrams: mode,
        }),
    });
    let mut c = ExecutionContext::standalone(s);
    let p = TlsProfile {
        id: Id::new(),
        workspace_id: Id::new(),
        name: "lab".into(),
        verify: true,
        use_system_roots: false,
        extra_roots_pem: vec![pki().ca.cert.clone()],
        client_identity: identity
            .map(|p| ClientIdentity::Pem { cert_chain_pem: p.cert.clone(), private_key_pem: SensitiveValue::template(p.key.clone()) }),
        bindings: vec![],
        min_version: TlsMinVersion::Tls12,
        server_name_override: None,
        server_spiffe: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    let id = p.id;
    c.tls_profiles.push(p);
    c.settings_layers.push((
        "run".into(),
        SettingsOverrides {
            tls_profile_id: Some(id),
            timeouts: Some(TimeoutOverrides {
                connect_ms: Some(Some(2_000)),
                tls_handshake_ms: Some(Some(2_000)),
                response_headers_ms: Some(Some(4_000)),
                total_ms: Some(Some(15_000)),
                ..Default::default()
            }),
            ..Default::default()
        },
    ));
    c
}

fn default_ctx(target: &str, proxy: &H3Fixture) -> ExecutionContext {
    ctx(target, proxy, MASQUE_DEFAULT_TEMPLATE, MasqueDatagramMode::Auto, None)
}

async fn run(e: &Engine, c: &ExecutionContext) -> ExecutionOutput {
    e.execute(c, EventCtx::none(), CancellationToken::new()).await
}

fn codes(o: &ExecutionOutput) -> Vec<String> {
    o.record.findings.iter().map(|f| f.code.clone()).collect()
}

fn finding<'a>(o: &'a ExecutionOutput, code: &str) -> &'a DiagnosticFinding {
    o.record.findings.iter().find(|f| f.code == code).unwrap_or_else(|| panic!("missing {code}; have {:?}", codes(o)))
}

fn last(o: &ExecutionOutput) -> &AttemptObservation {
    o.record.attempts.last().expect("attempt")
}

fn tls(o: &ExecutionOutput) -> &TlsObservation {
    last(o).connection.as_ref().and_then(|c| c.tls.as_ref()).expect("DTLS evidence")
}

fn outer(o: &ExecutionOutput) -> &TunnelObservation {
    last(o).connection.as_ref().and_then(|c| c.tunnel.as_ref()).expect("tunnel evidence")
}

fn phase(a: &AttemptObservation, p: Phase) -> Option<PhaseStatus> {
    a.phase(p).map(|x| x.status)
}

fn tunnel(o: &ExecutionOutput) -> (u64, u64, MasqueTunnel) {
    match &o.record.outcome.protocol_status {
        ProtocolStatus::Udp { datagrams_sent, datagrams_received, masque: Some(m), .. } => {
            (*datagrams_sent, *datagrams_received, m.clone())
        }
        other => panic!("{other:?}"),
    }
}

fn previews(o: &ExecutionOutput, dir: Direction, kind: &str) -> Vec<String> {
    o.record
        .stream
        .as_ref()
        .map(|s| s.messages.iter().filter(|m| m.direction == dir && m.kind == kind).map(|m| m.preview.clone()).collect())
        .unwrap_or_default()
}

fn app_datagrams(log: &anvil_fixtures::GroundTruthLog) -> usize {
    log.entries().iter().filter(|e| matches!(e.event, GroundTruth::DatagramReceived { .. })).count()
}

fn relayed(log: &anvil_fixtures::GroundTruthLog, via: &str) -> usize {
    log.entries().iter().filter(|e| matches!(&e.event, GroundTruth::DatagramRelayed { via: v, .. } if v == via)).count()
}

#[tokio::test]
async fn dtls_through_a_masque_tunnel_verifies_the_peer_and_records_both_legs() {
    init();
    let p = proxy(H3Options::default()).await;
    let echo = dtls_echo(&pki().server, false).await;
    let e = Engine::new();
    let mut c = default_ctx(&echo.url(), &p);
    c.auth_layers.push((
        "request".into(),
        AuthConfig::Bearer { token: SensitiveValue::template("dtls-tunnel-secret".to_string()), prefix: "Bearer".into() },
    ));
    let o = run(&e, &c).await;
    let a = last(&o);
    assert!(a.failure.is_none(), "{:?}", a.failure);
    // The attempt is the DTLS session with the target.
    assert_eq!(a.method, "DTLS");
    assert_eq!(a.url, echo.url());
    assert_eq!(phase(a, Phase::Dns), Some(PhaseStatus::NotApplicable), "the proxy resolves the target");
    assert_eq!(phase(a, Phase::ProxyTunnel), Some(PhaseStatus::Completed));
    assert_eq!(phase(a, Phase::DtlsHandshake), Some(PhaseStatus::Completed));
    assert_eq!(phase(a, Phase::QuicHandshake), None, "the QUIC leg is tunnel evidence");
    // DTLS evidence: the target's own certificate, verified against the profile.
    let t = tls(&o);
    assert_eq!(t.version.as_deref(), Some("DTLSv1_2"));
    assert_eq!(t.verification, TlsVerification::Verified);
    assert!(t.peer_certificates[0].subject.contains("anvil-lab-server"));
    assert_eq!(t.client_certificate_requested, Some(false));
    assert_eq!(a.connection.as_ref().unwrap().protocol.as_deref(), Some("dtlsv1_2"));
    // Tunnel evidence: the QUIC connection to the proxy and its CONNECT-UDP answer.
    let out = outer(&o);
    assert_eq!(out.kind, TunnelKind::ConnectUdp);
    assert_eq!(out.connect_status, Some(200));
    assert_eq!(out.authority, echo.addr.to_string());
    assert_eq!(out.tls.as_ref().and_then(|t| t.alpn_negotiated.as_deref()), Some("h3"));
    assert_eq!(out.tls.as_ref().map(|t| t.verification.clone()), Some(TlsVerification::Verified));
    assert!(out.phases.iter().any(|p| p.phase == Phase::QuicHandshake && p.status == PhaseStatus::Completed));
    assert!(out.connect_headers.iter().any(|h| h.name == "capsule-protocol"));
    let auth = out.connect_headers.iter().find(|h| h.name == "authorization").expect("auth goes on the CONNECT");
    assert!(!auth.value.contains("dtls-tunnel-secret"), "{}", auth.value);
    assert!(o.record.response.is_none(), "the proxy's 200 is tunnel evidence, not a response of the target");
    // Datagrams: plaintext in the transcript, DTLS records as capsules in the tunnel.
    assert_eq!(previews(&o, Direction::Received, "datagram"), vec!["secure hello"]);
    let (sent, got, m) = tunnel(&o);
    assert_eq!((sent, got), (1, 1));
    assert_eq!((m.connect_status, m.encoding, m.closed_by), (Some(200), Some(MasqueEncoding::Capsule), ClosedBy::Client));
    assert!(m.sent_capsules >= 3 && m.received_capsules >= 3, "handshake flights and data travel as capsules: {m:?}");
    assert_eq!((m.sent_quic_datagrams, m.received_quic_datagrams), (0, 0));
    assert_eq!(o.record.outcome.transport, TransportState::Completed);
    assert_eq!(o.record.outcome.dispatch, DispatchState::Sent);
    assert!(
        !codes(&o).iter().any(|c| c.starts_with("masque.") || c.starts_with("udp.") || c.starts_with("client.") || c.starts_with("hbone.")),
        "{:?}",
        codes(&o)
    );
    assert!(o.record.prepared.inferred.iter().any(|i| i.contains("DTLS runs inside the tunnel")), "{:?}", o.record.prepared.inferred);
    // Ground truth: the target completed the handshake and got the datagram
    // through the proxy; the token went on the CONNECT and is redacted in the record.
    assert_eq!(echo.completed_handshakes(), vec![None]);
    assert_eq!(app_datagrams(&echo.log), 1);
    assert!(relayed(&p.log, "capsule") >= 3);
    let hdrs = p.log.last_request_headers().unwrap();
    assert!(hdrs.iter().any(|(n, v)| n == "authorization" && v == "Bearer dtls-tunnel-secret"));
    assert!(!serde_json::to_string(&o.record).unwrap().contains("dtls-tunnel-secret"));
}

#[tokio::test]
async fn dtls_through_a_masque_tunnel_over_quic_datagram_frames() {
    init();
    let p = proxy(H3Options { h3_datagrams: true, ..Default::default() }).await;
    let echo = dtls_echo(&pki().server, false).await;
    let e = Engine::new();
    let o = run(&e, &ctx(&echo.url(), &p, MASQUE_DEFAULT_TEMPLATE, MasqueDatagramMode::QuicDatagrams, None)).await;
    assert!(last(&o).failure.is_none(), "{:?}", last(&o).failure);
    let (sent, got, m) = tunnel(&o);
    assert_eq!((sent, got), (1, 1));
    assert_eq!(m.encoding, Some(MasqueEncoding::QuicDatagram));
    assert!(m.sent_quic_datagrams >= 3 && m.received_quic_datagrams >= 3, "{m:?}");
    assert_eq!(m.sent_capsules, 0, "records fit the QUIC DATAGRAM frames: {m:?}");
    assert_eq!(tls(&o).verification, TlsVerification::Verified);
    assert!(relayed(&p.log, "quic_datagram") >= 3);
    assert_eq!(relayed(&p.log, "capsule"), 0);
    assert_eq!(echo.completed_handshakes().len(), 1);
}

#[tokio::test]
async fn dtls_through_a_masque_tunnel_wrong_root_is_a_client_side_verification_failure_about_the_target() {
    init();
    let p = proxy(H3Options::default()).await;
    // The proxy is trusted; the DTLS target's certificate is signed by a root the profile does not trust.
    let echo = dtls_echo(&pki().server_untrusted, false).await;
    let e = Engine::new();
    let o = run(&e, &default_ctx(&echo.url(), &p)).await;
    let f = last(&o).failure.as_ref().unwrap();
    assert_eq!(f.kind, FailureKind::TlsUntrustedIssuer);
    assert_eq!(f.phase, Phase::DtlsHandshake);
    assert!(matches!(tls(&o).verification, TlsVerification::Failed { problem: FailureKind::TlsUntrustedIssuer, .. }));
    assert!(!tls(&o).peer_certificates.is_empty(), "the presented certificate is kept as evidence");
    assert_eq!(outer(&o).tls.as_ref().map(|t| t.verification.clone()), Some(TlsVerification::Verified), "the proxy leg verified");
    let d = finding(&o, "client.tls.untrusted_issuer");
    assert!(d.explanation.contains(&echo.addr.to_string()), "about the DTLS target, not the proxy: {}", d.explanation);
    assert!(!codes(&o).iter().any(|c| c.starts_with("masque.")), "{:?}", codes(&o));
    assert_eq!(o.record.outcome.dispatch, DispatchState::NotDispatched);
    assert!(o.record.stream.is_none());
    assert_eq!(tunnel(&o).2.closed_by, ClosedBy::Client);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(echo.completed_handshakes().is_empty());
    assert_eq!(app_datagrams(&echo.log), 0, "no application data left");
}

#[tokio::test]
async fn dtls_through_a_masque_tunnel_mutual_tls_positive_and_negative() {
    init();
    let p = proxy(H3Options::default()).await;
    let echo = dtls_echo(&pki().server, true).await;
    let e = Engine::new();
    let template = MASQUE_DEFAULT_TEMPLATE;
    let o = run(&e, &ctx(&echo.url(), &p, template, MasqueDatagramMode::Auto, Some(&pki().client_a))).await;
    assert!(last(&o).failure.is_none(), "{:?}", last(&o).failure);
    assert_eq!(tls(&o).client_certificate_requested, Some(true));
    assert!(tls(&o).client_certificate_presented.as_ref().unwrap().subject.contains("anvil-client-a"));
    assert_eq!(echo.completed_handshakes(), vec![Some("anvil-client-a".to_string())]);
    assert_eq!(previews(&o, Direction::Received, "datagram"), vec!["secure hello"]);
    // An identity from an untrusted CA is rejected by the peer, through the tunnel.
    let o = run(&e, &ctx(&echo.url(), &p, template, MasqueDatagramMode::Auto, Some(&pki().client_rogue))).await;
    let f = last(&o).failure.as_ref().unwrap();
    assert_eq!(f.kind, FailureKind::DtlsHandshakeFailed);
    assert_eq!(f.tls_alert.as_deref(), Some("unknown_ca"));
    assert_eq!(tls(&o).verification, TlsVerification::Verified, "our side verified the target; the target rejected us");
    assert!(tls(&o).client_certificate_presented.as_ref().unwrap().subject.contains("anvil-client-rogue"));
    assert!(finding(&o, "client.dtls.handshake_failed").explanation.contains("unknown_ca"));
    assert!(echo.failed_handshakes().iter().any(|e| e.contains("client certificate rejected")));
    assert!(!codes(&o).iter().any(|c| c.starts_with("masque.")), "the tunnel did its part: {:?}", codes(&o));
}

#[tokio::test]
async fn dtls_through_a_masque_tunnel_to_a_silent_target_ends_at_the_handshake_deadline() {
    init();
    let p = proxy(H3Options::default()).await;
    let silent = streams::udp("127.0.0.1:0", UdpMode::Silent).await.unwrap();
    let e = Engine::new();
    let mut c = default_ctx(&format!("dtls://{}", silent.addr), &p);
    c.settings_layers.push((
        "scenario".into(),
        SettingsOverrides {
            timeouts: Some(TimeoutOverrides { tls_handshake_ms: Some(Some(900)), ..Default::default() }),
            ..Default::default()
        },
    ));
    let o = run(&e, &c).await;
    let f = last(&o).failure.as_ref().unwrap();
    assert_eq!(f.kind, FailureKind::DtlsHandshakeTimeout);
    assert_eq!(f.deadline_ms, Some(900));
    assert_eq!(phase(last(&o), Phase::DtlsHandshake), Some(PhaseStatus::TimedOut));
    let (sent, got, m) = tunnel(&o);
    assert_eq!((sent, got), (0, 0), "no application datagram was sent");
    assert_eq!((m.connect_status, m.closed_by, m.received_capsules), (Some(200), ClosedBy::Client, 0));
    assert!(m.sent_capsules >= 1, "the ClientHello (and retransmissions) went through the tunnel: {m:?}");
    finding(&o, "client.dtls.handshake_timeout");
    assert!(!codes(&o).iter().any(|c| c.starts_with("masque.") || c == "udp.no_response"), "{:?}", codes(&o));
    assert_eq!(o.record.outcome.dispatch, DispatchState::NotDispatched);
    assert!(
        silent.log.entries().iter().any(|e| matches!(e.event, GroundTruth::DatagramReceived { .. })),
        "the handshake reached the target"
    );
}

#[tokio::test]
async fn a_refused_tunnel_attempts_no_dtls() {
    init();
    let p = proxy(H3Options::default()).await;
    let echo = dtls_echo(&pki().server, false).await;
    let e = Engine::new();
    let o =
        run(&e, &ctx(&echo.url(), &p, "/.well-known/masque/udp/{target_host}/{target_port}/?refuse=403", MasqueDatagramMode::Auto, None))
            .await;
    let a = last(&o);
    assert_eq!(a.failure.as_ref().map(|f| f.kind), Some(FailureKind::MasqueRefused));
    assert_eq!(a.method, "CONNECT", "the attempt stays the proxy's CONNECT");
    assert_eq!(phase(a, Phase::DtlsHandshake), None, "no DTLS was attempted");
    assert!(a.connection.as_ref().and_then(|c| c.tunnel.as_ref()).is_none());
    assert_eq!(tunnel(&o).2.connect_status, Some(403));
    finding(&o, "masque.proxy_refused");
    assert!(!codes(&o).iter().any(|c| c.starts_with("client.dtls.")), "{:?}", codes(&o));
    assert_eq!(o.record.response.as_ref().map(|r| r.status), Some(403));
    assert!(String::from_utf8_lossy(&o.body).contains("refused"));
    assert_eq!(o.record.outcome.dispatch, DispatchState::NotDispatched);
    assert!(o.record.stream.is_none());
    assert!(echo.log.entries().is_empty(), "the target saw nothing");
}

#[tokio::test]
async fn a_tunnel_ending_mid_session_is_abnormal_or_a_proxy_close() {
    init();
    let p = proxy(H3Options::default()).await;
    let echo = dtls_echo(&pki().server, false).await;
    let e = Engine::new();
    let long_window = |mut c: ExecutionContext| {
        if let Some(u) = c.spec.udp.as_mut() {
            u.response_window_ms = 4_000;
        }
        c
    };
    // The proxy resets the CONNECT stream after the handshake and the echo.
    let reset = "/.well-known/masque/udp/{target_host}/{target_port}/?reset_after_ms=700";
    let o = run(&e, &long_window(ctx(&echo.url(), &p, reset, MasqueDatagramMode::Auto, None))).await;
    let f = last(&o).failure.as_ref().unwrap();
    assert_eq!((f.kind, f.phase), (FailureKind::BodyReset, Phase::Session), "{f:?}");
    assert_eq!(phase(last(&o), Phase::DtlsHandshake), Some(PhaseStatus::Completed));
    assert_eq!(previews(&o, Direction::Received, "datagram"), vec!["secure hello"], "data before the end is kept");
    assert_eq!(tunnel(&o).2.closed_by, ClosedBy::Abnormal);
    finding(&o, "masque.tunnel_ended_abnormally");
    assert_eq!(o.record.outcome.transport, TransportState::Incomplete);
    assert!(p.log.entries().iter().any(|e| e.event == GroundTruth::FaultApplied { fault: "masque_reset".into() }));
    // A clean FIN from the proxy is the proxy closing the tunnel, not a failure.
    let fin = "/.well-known/masque/udp/{target_host}/{target_port}/?fin_after_ms=700";
    let o = run(&e, &long_window(ctx(&echo.url(), &p, fin, MasqueDatagramMode::Auto, None))).await;
    assert!(last(&o).failure.is_none(), "{:?}", last(&o).failure);
    assert_eq!(tunnel(&o).2.closed_by, ClosedBy::Peer);
    assert!(previews(&o, Direction::Received, "datagram") == vec!["secure hello"]);
    assert!(o.record.stream.as_ref().unwrap().messages.iter().any(|m| m.kind == "tunnel_closed"));
    assert!(
        !o.record.stream.as_ref().unwrap().messages.iter().any(|m| m.kind == "close_notify" && m.direction == Direction::Sent),
        "nothing is sent into a closed tunnel"
    );
    assert!(!codes(&o).iter().any(|c| c.starts_with("masque.")), "{:?}", codes(&o));
}

#[tokio::test]
async fn a_tunnel_ending_during_the_handshake_fails_the_handshake_typed() {
    init();
    let p = proxy(H3Options::default()).await;
    let echo = dtls_echo(&pki().server, false).await;
    let e = Engine::new();
    // The proxy resets the stream as soon as the tunnel is open.
    let reset = "/.well-known/masque/udp/{target_host}/{target_port}/?reset_after_ms=0";
    let o = run(&e, &ctx(&echo.url(), &p, reset, MasqueDatagramMode::Auto, None)).await;
    let f = last(&o).failure.as_ref().unwrap();
    assert_eq!((f.kind, f.phase), (FailureKind::BodyReset, Phase::DtlsHandshake), "{f:?}");
    assert_eq!(tunnel(&o).2.closed_by, ClosedBy::Abnormal);
    finding(&o, "masque.tunnel_ended_abnormally");
    assert!(o.record.stream.is_none());
    assert_eq!(o.record.outcome.dispatch, DispatchState::NotDispatched);
    // A clean FIN as soon as the tunnel is open: the handshake cannot finish.
    let fin = "/.well-known/masque/udp/{target_host}/{target_port}/?fin_after_ms=0";
    let o = run(&e, &ctx(&echo.url(), &p, fin, MasqueDatagramMode::Auto, None)).await;
    let f = last(&o).failure.as_ref().unwrap();
    assert_eq!((f.kind, f.phase), (FailureKind::DtlsHandshakeFailed, Phase::DtlsHandshake), "{f:?}");
    assert!(f.message.contains("closed during the DTLS handshake"), "{}", f.message);
    assert_eq!(tunnel(&o).2.closed_by, ClosedBy::Peer);
    assert!(!codes(&o).iter().any(|c| c.starts_with("masque.")), "a proxy close is not an abnormal end: {:?}", codes(&o));
}

#[tokio::test]
async fn interactive_dtls_through_a_masque_tunnel_sends_on_command_until_close() {
    init();
    let p = proxy(H3Options::default()).await;
    let echo = dtls_echo(&pki().server, false).await;
    let e = Engine::new();
    let h = e.open_session(default_ctx(&echo.url(), &p), EventCtx::none()).await;
    h.send(SessionCommand::SendText { text: "live".into() }).await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    h.close().await.unwrap();
    let o = h.finish().await;
    assert_eq!(previews(&o, Direction::Received, "datagram"), vec!["secure hello", "live"]);
    let (sent, got, m) = tunnel(&o);
    assert_eq!((sent, got), (2, 2));
    assert_eq!(m.closed_by, ClosedBy::Client);
    assert_eq!(o.record.outcome.transport, TransportState::Completed);
    assert!(o.record.stream.as_ref().unwrap().messages.iter().any(|m| m.kind == "close_notify" && m.direction == Direction::Sent));
}
