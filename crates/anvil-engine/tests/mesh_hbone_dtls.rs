//! DTLS inside a Ferrum Mesh HBONE datagram tunnel, end to end through the
//! engine: the HBONE fixture's datagram relay (`anvil_fixtures::hbone`, its
//! own `[u16 length][payload]` codec) carries every DTLS record to the dimpl
//! `dtls` echo fixture over real sockets (no mocks). The HBONE leg uses the
//! mesh PKI (client SVID, SPIFFE-verified endpoint) from the proxy profile;
//! the DTLS leg uses the lab PKI from the request's TLS profile. Fixture
//! logs are ground truth only; they are never fed to the diagnostic engine.

use anvil_domain::Id;
use anvil_domain::diagnostics::{Confidence, DiagnosticFinding, Severity, SourceScope};
use anvil_domain::events::SessionCommand;
use anvil_domain::execution::*;
use anvil_domain::outcome::{ClosedBy, ProtocolStatus, TransportState};
use anvil_domain::proxy_protocol::DatagramEnvelopeSpec;
use anvil_domain::request::*;
use anvil_domain::secret::SensitiveValue;
use anvil_domain::settings::{ProxySelection, SettingsOverrides, TimeoutOverrides};
use anvil_domain::tls::{
    ClientIdentity, HboneMarker, HboneOptions, ProxyKind, ProxyProfile, ServerSpiffeIdentity, TlsMinVersion, TlsProfile,
};
use anvil_engine::{Engine, ExecutionContext, ExecutionOutput};
use anvil_fixtures::dtls::{self as fxdtls, DtlsFixture, DtlsServerOptions};
use anvil_fixtures::hbone::{self, HboneFixture, UdpTunnelFault};
use anvil_fixtures::mesh_pki::{self, MeshPki};
use anvil_fixtures::pki::Pem;
use anvil_fixtures::streams::{self, UdpMode};
use anvil_fixtures::{ClientAuth, GroundTruth, GroundTruthLog, LabPki};
use anvil_transport::recorder::EventCtx;
use std::net::SocketAddr;
use std::sync::OnceLock;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

fn init() {
    anvil_transport::init();
    anvil_fixtures::init();
}

fn mesh() -> &'static MeshPki {
    static P: OnceLock<MeshPki> = OnceLock::new();
    P.get_or_init(MeshPki::generate)
}

fn pki() -> &'static LabPki {
    static P: OnceLock<LabPki> = OnceLock::new();
    P.get_or_init(LabPki::generate)
}

async fn run(c: &ExecutionContext) -> ExecutionOutput {
    Engine::new().execute(c, EventCtx::none(), CancellationToken::new()).await
}

fn codes(o: &ExecutionOutput) -> Vec<String> {
    o.record.findings.iter().map(|f| f.code.clone()).collect()
}

fn finding<'a>(o: &'a ExecutionOutput, code: &str) -> &'a DiagnosticFinding {
    o.record.findings.iter().find(|f| f.code == code).unwrap_or_else(|| panic!("{code} missing; findings: {:?}", codes(o)))
}

fn last(o: &ExecutionOutput) -> &AttemptObservation {
    o.record.attempts.last().expect("an attempt")
}

fn dtls_evidence(o: &ExecutionOutput) -> &TlsObservation {
    last(o).connection.as_ref().and_then(|c| c.tls.as_ref()).expect("DTLS evidence")
}

fn tunnel(o: &ExecutionOutput) -> &TunnelObservation {
    last(o).connection.as_ref().and_then(|c| c.tunnel.as_ref()).expect("tunnel evidence")
}

fn channel(o: &ExecutionOutput) -> &HboneDatagramChannel {
    tunnel(o).datagrams.as_ref().expect("datagram channel evidence")
}

fn phase(a: &AttemptObservation, p: Phase) -> Option<PhaseStatus> {
    a.phase(p).map(|x| x.status)
}

/// Application datagrams sent and received (`ProtocolStatus::Udp`, no MASQUE facts).
fn counts(o: &ExecutionOutput) -> (u64, u64) {
    match &o.record.outcome.protocol_status {
        ProtocolStatus::Udp { datagrams_sent, datagrams_received, masque: None, .. } => (*datagrams_sent, *datagrams_received),
        other => panic!("{other:?} {:?}", codes(o)),
    }
}

fn previews(o: &ExecutionOutput, dir: Direction, kind: &str) -> Vec<String> {
    o.record
        .stream
        .as_ref()
        .map(|s| s.messages.iter().filter(|m| m.direction == dir && m.kind == kind).map(|m| m.preview.clone()).collect())
        .unwrap_or_default()
}

fn app_datagrams(log: &GroundTruthLog) -> usize {
    log.entries().iter().filter(|e| matches!(e.event, GroundTruth::DatagramReceived { .. })).count()
}

/// A DTLS echo presenting `server` (lab CA, or the rogue CA for
/// `server_untrusted`), optionally requiring a lab client certificate.
async fn dtls_echo(server: &Pem, client_auth: bool) -> DtlsFixture {
    let opts = DtlsServerOptions {
        cert_pem: server.cert.clone(),
        key_pem: server.key.clone(),
        client_ca_pem: client_auth.then(|| pki().client_ca.cert.clone()),
    };
    fxdtls::serve("127.0.0.1:0", opts).await.unwrap()
}

/// The HBONE endpoint: mTLS with the mesh CA, relaying datagram tunnels to `allowed`.
async fn endpoint(allowed: Vec<String>, faults: Vec<(String, UdpTunnelFault)>) -> HboneFixture {
    hbone::serve("127.0.0.1:0", endpoint_options(allowed, faults)).await.unwrap()
}

fn endpoint_options(allowed: Vec<String>, faults: Vec<(String, UdpTunnelFault)>) -> hbone::HboneOptions {
    hbone::HboneOptions {
        server_cert_chain_pem: mesh().ztunnel.chain_with(&mesh().ca),
        server_key_pem: mesh().ztunnel.key.clone(),
        client_auth: ClientAuth::Required { ca_pem: mesh().ca.cert.clone() },
        alpn: vec!["h2".into()],
        allowed,
        unavailable: vec![],
        udp_faults: faults,
    }
}

/// The proxy profile's TLS: the mesh client SVID, the endpoint verified by SPIFFE ID.
fn svid_profile(with_svid: bool) -> TlsProfile {
    TlsProfile {
        id: Id::new(),
        workspace_id: Id::new(),
        name: "mesh SVID".into(),
        verify: true,
        use_system_roots: false,
        extra_roots_pem: vec![mesh().ca.cert.clone()],
        client_identity: with_svid.then(|| ClientIdentity::Pem {
            cert_chain_pem: mesh().client.chain_with(&mesh().ca),
            private_key_pem: SensitiveValue::template(mesh().client.key.clone()),
        }),
        bindings: vec![],
        min_version: Default::default(),
        server_name_override: None,
        server_spiffe: Some(ServerSpiffeIdentity {
            expected_server_spiffe_id: Some(mesh_pki::ZTUNNEL_SPIFFE_ID.into()),
            trust_domain: None,
        }),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

/// The request's TLS profile, for the DTLS peer: the lab CA and, optionally,
/// a lab client identity.
fn dtls_profile(identity: Option<&Pem>) -> TlsProfile {
    TlsProfile {
        id: Id::new(),
        workspace_id: Id::new(),
        name: "lab DTLS".into(),
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
    }
}

fn udp_spec(datagrams: &[&str], window_ms: u64) -> UdpSpec {
    UdpSpec {
        dtls: false,
        datagrams: datagrams.iter().map(|d| StreamPayload { data: d.to_string(), encoding: PayloadEncoding::Text }).collect(),
        response_window_ms: window_ms,
        max_datagrams: 100,
        masque: None,
        proxy_protocol: None,
    }
}

/// `scheme://target` with `udp` through the HBONE endpoint: the proxy profile
/// carries the mesh SVID (or none), the request's TLS profile the DTLS trust.
fn via_hbone(
    scheme: &str,
    target: SocketAddr,
    udp: UdpSpec,
    ep: &HboneFixture,
    svid: bool,
    dtls_identity: Option<&Pem>,
) -> ExecutionContext {
    let mut s = RequestSpec::http("GET", &format!("{scheme}://{target}"));
    s.protocol = Protocol::Udp;
    s.udp = Some(udp);
    let mut c = ExecutionContext::standalone(s);
    let outer = svid_profile(svid);
    let inner = dtls_profile(dtls_identity);
    let proxy = ProxyProfile {
        id: Id::new(),
        workspace_id: Id::new(),
        name: "mesh hbone".into(),
        kind: ProxyKind::Hbone,
        address: ep.address(),
        username: None,
        password: None,
        no_proxy: String::new(),
        tls_profile_id: Some(outer.id),
        hbone: Some(HboneOptions {
            marker: HboneMarker::None,
            baggage: Some(format!("source.principal={}", mesh_pki::CLIENT_SPIFFE_ID)),
            extra_headers: vec![],
        }),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    c.settings_layers.push((
        "run".into(),
        SettingsOverrides {
            tls_profile_id: Some(inner.id),
            proxy_profile_id: Some(ProxySelection::Profile { id: proxy.id }),
            timeouts: Some(TimeoutOverrides {
                connect_ms: Some(Some(3_000)),
                tls_handshake_ms: Some(Some(3_000)),
                response_headers_ms: Some(Some(5_000)),
                total_ms: Some(Some(20_000)),
                ..Default::default()
            }),
            ..Default::default()
        },
    ));
    c.proxy_profiles.push(proxy);
    c.tls_profiles.push(outer);
    c.tls_profiles.push(inner);
    c
}

fn dtls_via(echo: &DtlsFixture, ep: &HboneFixture) -> ExecutionContext {
    via_hbone("dtls", echo.addr, udp_spec(&["secure hello"], 500), ep, true, None)
}

/// Wait (bounded) until the endpoint recorded `n` tunnel ends.
async fn tunnel_ends(ep: &HboneFixture, n: usize) -> Vec<String> {
    for _ in 0..40 {
        let e = ep.log.udp_tunnel_ends.lock().clone();
        if e.len() >= n {
            return e;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    ep.log.udp_tunnel_ends.lock().clone()
}

fn records_relayed(ep: &HboneFixture) -> usize {
    ep.log.udp_relayed.lock().len()
}

/// No finding describes the DTLS target (or the HBONE hop's own refusal) as
/// something it is not: used where the tunnel did its part.
fn no_hbone_findings(o: &ExecutionOutput) {
    assert!(!codes(o).iter().any(|c| c.starts_with("hbone.")), "the tunnel did its part: {:?}", codes(o));
}

#[tokio::test]
async fn dtls_through_hbone_verifies_the_peer_and_records_both_legs() {
    init();
    let echo = dtls_echo(&pki().server, false).await;
    let ep = endpoint(vec![echo.addr.to_string()], vec![]).await;
    let o = run(&dtls_via(&echo, &ep)).await;
    let a = last(&o);
    assert!(a.failure.is_none(), "{:?} {:?}", a.failure, codes(&o));
    // The attempt is the DTLS session with the target.
    assert_eq!(a.method, "DTLS");
    assert_eq!(a.url, echo.url());
    assert_eq!(phase(a, Phase::Dns), Some(PhaseStatus::NotApplicable), "the endpoint resolves the target");
    assert_eq!(phase(a, Phase::Connect), Some(PhaseStatus::NotApplicable));
    assert_eq!(phase(a, Phase::ProxyTunnel), Some(PhaseStatus::Completed));
    assert_eq!(phase(a, Phase::DtlsHandshake), Some(PhaseStatus::Completed));
    assert_eq!(phase(a, Phase::Session), Some(PhaseStatus::Completed));
    assert_eq!(phase(a, Phase::TlsHandshake), None, "the endpoint's mTLS is tunnel evidence");
    let order: Vec<Phase> = a.phases.iter().map(|p| p.phase).collect();
    let pos = |p: Phase| order.iter().position(|x| *x == p).unwrap();
    assert!(pos(Phase::ProxyTunnel) < pos(Phase::DtlsHandshake) && pos(Phase::DtlsHandshake) < pos(Phase::Session), "{order:?}");
    // DTLS evidence: the target's own certificate, verified against the request's profile.
    let t = dtls_evidence(&o);
    assert_eq!(t.version.as_deref(), Some("DTLSv1_2"));
    assert_eq!(t.verification, TlsVerification::Verified);
    assert!(t.peer_certificates[0].subject.contains("anvil-lab-server"), "{:?}", t.peer_certificates);
    assert_eq!(t.client_certificate_requested, Some(false));
    assert_eq!(a.connection.as_ref().unwrap().protocol.as_deref(), Some("dtlsv1_2"));
    // Tunnel evidence: the HBONE outer leg, exactly as for UDP through HBONE.
    let out = tunnel(&o);
    assert_eq!(out.kind, TunnelKind::Hbone);
    assert_eq!(out.connect_status, Some(200));
    assert_eq!(out.authority, echo.addr.to_string());
    assert!(out.connect_headers.iter().any(|h| h.name == "x-ferrum-mesh-protocol" && h.value == "udp"), "{:?}", out.connect_headers);
    let otls = out.tls.as_ref().unwrap();
    assert_eq!(otls.verification, TlsVerification::Verified);
    assert_eq!(otls.peer_spiffe_id.as_deref(), Some(mesh_pki::ZTUNNEL_SPIFFE_ID));
    assert!(otls.client_certificate_presented.is_some(), "the mesh SVID went to the endpoint");
    assert!(out.phases.iter().any(|p| p.phase == Phase::TlsHandshake && p.status == PhaseStatus::Completed));
    assert!(o.record.response.is_none(), "the endpoint's 200 is tunnel evidence, not a response of the target");
    // The datagram channel counts DTLS records (handshake flights included).
    let ch = channel(&o);
    assert!(ch.records_sent >= 3 && ch.records_received >= 3, "handshake flights and data travel as records: {ch:?}");
    assert_eq!((ch.closed_by, ch.oversize_refused, ch.truncated_tail_bytes, ch.reset_code.clone()), (ClosedBy::Client, 0, 0, None));
    // Application datagrams: plaintext in the transcript, encrypted in the tunnel.
    assert_eq!(counts(&o), (1, 1));
    assert_eq!(previews(&o, Direction::Received, "datagram"), vec!["secure hello"]);
    assert!(previews(&o, Direction::Sent, "close_notify").len() == 1, "Anvil closed the DTLS session");
    assert!(o.record.stream.as_ref().unwrap().messages.iter().any(|m| m.kind == "tunnel" && m.preview.contains("HBONE datagram tunnel")));
    assert_eq!(o.record.outcome.transport, TransportState::Completed);
    assert_eq!(o.record.outcome.dispatch, DispatchState::Sent);
    assert!(!o.record.findings.iter().any(|f| f.severity >= Severity::Warning), "{:?}", codes(&o));
    assert!(
        o.record.prepared.inferred.iter().any(|i| i.contains("DTLS runs inside the HBONE datagram tunnel")),
        "{:?}",
        o.record.prepared.inferred
    );
    let b = a.bytes.connection_bytes_written.unwrap_or(0);
    assert!(b > 0, "the tunnel's connection bytes are recorded");
    // Ground truth: the endpoint saw one udp-marked CONNECT from the mesh
    // client, relayed every record, and saw Anvil end the tunnel; the DTLS
    // target completed a handshake and got the datagram.
    let rec = &ep.connects()[0];
    assert_eq!(rec.authority, echo.addr.to_string());
    assert!(rec.headers.iter().any(|(n, v)| n == "x-ferrum-mesh-protocol" && v == "udp"));
    assert_eq!(rec.peer_spiffe_id.as_deref(), Some(mesh_pki::CLIENT_SPIFFE_ID));
    assert_eq!(records_relayed(&ep) as u64, ch.records_sent, "every record Anvil counted reached the relay");
    assert_eq!(tunnel_ends(&ep, 1).await, vec!["client_end"]);
    assert_eq!(echo.completed_handshakes(), vec![None]);
    assert_eq!(app_datagrams(&echo.log), 1);
    let peers: Vec<String> = echo
        .log
        .entries()
        .into_iter()
        .filter_map(|e| match e.event {
            GroundTruth::ConnectionAccepted { peer } => Some(peer),
            _ => None,
        })
        .collect();
    assert_eq!(peers.len(), 1, "one DTLS association, from the endpoint's relay socket: {peers:?}");
}

#[tokio::test]
async fn dtls_through_hbone_wrong_root_is_a_client_side_verification_failure_about_the_target() {
    init();
    // The endpoint is trusted; the DTLS target's certificate is signed by a root the request's profile does not trust.
    let echo = dtls_echo(&pki().server_untrusted, false).await;
    let ep = endpoint(vec![echo.addr.to_string()], vec![]).await;
    let o = run(&dtls_via(&echo, &ep)).await;
    let f = last(&o).failure.as_ref().unwrap();
    assert_eq!((f.kind, f.phase), (FailureKind::TlsUntrustedIssuer, Phase::DtlsHandshake));
    assert!(matches!(dtls_evidence(&o).verification, TlsVerification::Failed { problem: FailureKind::TlsUntrustedIssuer, .. }));
    assert!(!dtls_evidence(&o).peer_certificates.is_empty(), "the presented certificate is kept as evidence");
    assert_eq!(tunnel(&o).tls.as_ref().map(|t| t.verification.clone()), Some(TlsVerification::Verified), "the endpoint leg verified");
    let d = finding(&o, "client.tls.untrusted_issuer");
    assert!(d.explanation.contains(&echo.addr.to_string()), "about the DTLS target, not the endpoint: {}", d.explanation);
    no_hbone_findings(&o);
    assert_eq!(o.record.outcome.dispatch, DispatchState::NotDispatched);
    assert!(o.record.stream.is_none());
    assert_eq!(counts(&o), (0, 0));
    assert_eq!(channel(&o).closed_by, ClosedBy::Client);
    assert_eq!(tunnel_ends(&ep, 1).await, vec!["client_end"]);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(echo.completed_handshakes().is_empty());
    assert_eq!(app_datagrams(&echo.log), 0, "no application data left");
    assert!(records_relayed(&ep) >= 1, "the handshake did go through the tunnel");
}

#[tokio::test]
async fn dtls_through_hbone_mutual_tls_positive_and_negative_on_the_dtls_leg() {
    init();
    let echo = dtls_echo(&pki().server, true).await;
    let ep = endpoint(vec![echo.addr.to_string()], vec![]).await;
    let spec = || udp_spec(&["secure hello"], 500);
    // The DTLS peer sees the lab client identity; the endpoint sees the mesh SVID.
    let o = run(&via_hbone("dtls", echo.addr, spec(), &ep, true, Some(&pki().client_a))).await;
    assert!(last(&o).failure.is_none(), "{:?}", last(&o).failure);
    assert_eq!(dtls_evidence(&o).client_certificate_requested, Some(true));
    assert!(dtls_evidence(&o).client_certificate_presented.as_ref().unwrap().subject.contains("anvil-client-a"));
    assert!(
        tunnel(&o)
            .tls
            .as_ref()
            .unwrap()
            .client_certificate_presented
            .as_ref()
            .unwrap()
            .subject_alt_names
            .iter()
            .any(|s| s.contains(mesh_pki::CLIENT_SPIFFE_ID))
    );
    assert_eq!(echo.completed_handshakes(), vec![Some("anvil-client-a".to_string())]);
    assert_eq!(ep.connects()[0].peer_spiffe_id.as_deref(), Some(mesh_pki::CLIENT_SPIFFE_ID));
    assert_eq!(previews(&o, Direction::Received, "datagram"), vec!["secure hello"]);
    // An identity from an untrusted CA is rejected by the DTLS peer, through the tunnel.
    let o = run(&via_hbone("dtls", echo.addr, spec(), &ep, true, Some(&pki().client_rogue))).await;
    let f = last(&o).failure.as_ref().unwrap();
    assert_eq!((f.kind, f.phase), (FailureKind::DtlsHandshakeFailed, Phase::DtlsHandshake));
    assert_eq!(f.tls_alert.as_deref(), Some("unknown_ca"));
    assert_eq!(dtls_evidence(&o).verification, TlsVerification::Verified, "our side verified the target; the target rejected us");
    assert!(dtls_evidence(&o).client_certificate_presented.as_ref().unwrap().subject.contains("anvil-client-rogue"));
    let d = finding(&o, "client.dtls.handshake_failed");
    assert!(d.explanation.contains("unknown_ca"), "{}", d.explanation);
    assert!(echo.failed_handshakes().iter().any(|e| e.contains("client certificate rejected")));
    no_hbone_findings(&o);
    assert_eq!(channel(&o).closed_by, ClosedBy::Client);
    assert_eq!(o.record.outcome.dispatch, DispatchState::NotDispatched);
}

#[tokio::test]
async fn dtls_through_hbone_to_a_silent_target_ends_at_the_dtls_handshake_deadline() {
    init();
    let silent = streams::udp("127.0.0.1:0", UdpMode::Silent).await.unwrap();
    let ep = endpoint(vec![silent.addr.to_string()], vec![]).await;
    let mut c = via_hbone("dtls", silent.addr, udp_spec(&["anyone?"], 500), &ep, true, None);
    c.settings_layers.push((
        "scenario".into(),
        SettingsOverrides {
            timeouts: Some(TimeoutOverrides { tls_handshake_ms: Some(Some(900)), ..Default::default() }),
            ..Default::default()
        },
    ));
    let o = run(&c).await;
    let f = last(&o).failure.as_ref().unwrap();
    assert_eq!((f.kind, f.deadline_ms), (FailureKind::DtlsHandshakeTimeout, Some(900)));
    assert_eq!(phase(last(&o), Phase::DtlsHandshake), Some(PhaseStatus::TimedOut));
    assert_eq!(phase(last(&o), Phase::ProxyTunnel), Some(PhaseStatus::Completed), "the tunnel itself opened");
    assert_eq!(counts(&o), (0, 0), "no application datagram was sent");
    let ch = channel(&o);
    assert!(ch.records_sent >= 1 && ch.records_received == 0, "the ClientHello (and retransmissions) went through: {ch:?}");
    assert_eq!(ch.closed_by, ClosedBy::Client);
    let d = finding(&o, "client.dtls.handshake_timeout");
    assert_eq!(d.confidence, Confidence::Confirmed);
    assert!(
        d.alternatives.iter().any(|a| a.contains("without acknowledgement") && a.contains(&silent.addr.to_string())),
        "the relay's silence is an alternative: {:?}",
        d.alternatives
    );
    assert!(d.does_not_prove.iter().any(|x| x.contains("down")), "{:?}", d.does_not_prove);
    no_hbone_findings(&o);
    assert!(!codes(&o).contains(&"udp.no_response".to_string()), "{:?}", codes(&o));
    assert_eq!(o.record.outcome.dispatch, DispatchState::NotDispatched);
    // Ground truth: the handshake reached the target through the relay.
    assert!(silent.log.entries().iter().any(|e| matches!(e.event, GroundTruth::DatagramReceived { .. })));
    assert_eq!(tunnel_ends(&ep, 1).await, vec!["client_end"]);
}

/// Everything about a record except its identifiers and timings.
fn shape(o: &ExecutionOutput) -> String {
    let a = last(o);
    let t = tunnel(o);
    let f = a.failure.as_ref().unwrap();
    format!(
        "{:?} | {:?} {:?} {} | {:?} {:?} {:?} {:?} {:?} {:?} | {:?} {:?} {:?} | {:?} {:?}",
        a.phases.iter().map(|p| (p.phase, p.status)).collect::<Vec<_>>(),
        f.kind,
        f.phase,
        f.message,
        t.kind,
        t.authority,
        t.connect_status,
        t.refusal_body,
        t.datagrams,
        t.failure.as_ref().map(|x| (x.kind, x.phase)),
        a.connection.as_ref().map(|c| (c.protocol.clone(), c.tls.is_some(), c.via_proxy.clone())),
        a.dispatch,
        o.record.outcome.protocol_status,
        codes(o),
        o.record.stream.is_some(),
    )
}

#[tokio::test]
async fn a_tunnel_that_never_opens_is_the_udp_through_hbone_record_with_no_dtls_attempted() {
    init();
    let echo = dtls_echo(&pki().server, false).await;
    // The endpoint does not relay to the DTLS target: 403 with the UDP body.
    let ep = endpoint(vec![], vec![]).await;
    let spec = || udp_spec(&["x"], 300);
    let dtls = run(&via_hbone("dtls", echo.addr, spec(), &ep, true, None)).await;
    let udp = run(&via_hbone("udp", echo.addr, spec(), &ep, true, None)).await;
    let a = last(&dtls);
    assert_eq!(a.failure.as_ref().map(|f| f.kind), Some(FailureKind::HboneConnectRefused));
    assert_eq!((a.method.as_str(), a.url.as_str()), ("DTLS", echo.url().as_str()), "the attempt still addresses the DTLS target");
    assert_eq!(phase(a, Phase::DtlsHandshake), None, "no DTLS was attempted");
    assert!(a.connection.as_ref().unwrap().tls.is_none(), "no DTLS evidence");
    let f = finding(&dtls, "hbone.tunnel_refused");
    assert_eq!((f.scope, f.confidence), (SourceScope::ForwardProxy, Confidence::Confirmed));
    assert!(f.explanation.contains("HBONE UDP relay destination not allowed"), "{}", f.explanation);
    assert!(f.alternatives.iter().any(|x| x.contains("UDP (datagram) tunnel")), "{:?}", f.alternatives);
    assert!(
        !codes(&dtls).iter().any(|c| c.starts_with("client.dtls.") || c.starts_with("udp.") || c.starts_with("client.tls.")),
        "{:?}",
        codes(&dtls)
    );
    assert_eq!((dtls.record.outcome.dispatch, counts(&dtls), dtls.record.response.is_none()), (DispatchState::NotDispatched, (0, 0), true));
    // Exactly the UDP-through-HBONE record, apart from the method and URL.
    assert_eq!(last(&udp).method, "UDP");
    assert_eq!(shape(&dtls), shape(&udp));
    // An mTLS refusal on the endpoint leg: the same, again with no DTLS attempted.
    let no_svid = run(&via_hbone("dtls", echo.addr, spec(), &ep, false, None)).await;
    let c = codes(&no_svid);
    assert!(c.iter().any(|x| x == "hbone.client_svid_required" || x == "hbone.closed_after_certificate_request"), "{c:?}");
    assert!(!c.iter().any(|x| x.starts_with("client.dtls.") || x.starts_with("udp.")), "{c:?}");
    assert_eq!(phase(last(&no_svid), Phase::DtlsHandshake), None);
    assert_eq!(no_svid.record.outcome.dispatch, DispatchState::NotDispatched);
    // Ground truth: nothing reached the DTLS target; the endpoint answered one CONNECT per tunnel run.
    assert!(echo.log.entries().is_empty(), "the target saw nothing");
    assert_eq!(ep.connects().iter().map(|c| c.status).collect::<Vec<_>>(), vec![403, 403]);
    assert!(ep.log.udp_relayed.lock().is_empty());
}

#[tokio::test]
async fn the_endpoint_ending_the_tunnel_mid_session_is_its_close_not_a_dtls_failure() {
    init();
    let echo = dtls_echo(&pki().server, false).await;
    let ep = endpoint(vec![echo.addr.to_string()], vec![(echo.addr.to_string(), UdpTunnelFault::EndAfterMs(700))]).await;
    let t0 = std::time::Instant::now();
    let o = run(&via_hbone("dtls", echo.addr, udp_spec(&["secure hello"], 4_000), &ep, true, None)).await;
    let took = t0.elapsed();
    assert!(last(&o).failure.is_none(), "END_STREAM is the endpoint's clean close: {:?}", last(&o).failure);
    assert_eq!(phase(last(&o), Phase::DtlsHandshake), Some(PhaseStatus::Completed));
    assert_eq!(previews(&o, Direction::Received, "datagram"), vec!["secure hello"], "data before the end is kept");
    assert_eq!(channel(&o).closed_by, ClosedBy::Peer);
    let msgs = &o.record.stream.as_ref().unwrap().messages;
    assert!(msgs.iter().any(|m| m.kind == "tunnel_closed" && m.preview.contains("END_STREAM")), "{msgs:?}");
    assert!(!msgs.iter().any(|m| m.kind == "close_notify" && m.direction == Direction::Sent), "nothing is sent into a closed tunnel");
    let f = finding(&o, "hbone.udp_tunnel_ended");
    assert_eq!((f.confidence, f.severity, f.scope), (Confidence::Confirmed, Severity::Warning, SourceScope::ForwardProxy));
    assert!(
        f.explanation.contains("DTLS record(s)") && f.explanation.contains("application datagrams among them are kept"),
        "{}",
        f.explanation
    );
    assert!(!codes(&o).iter().any(|c| c.starts_with("client.dtls.") || c.starts_with("exchange.")), "{:?}", codes(&o));
    assert!(took < Duration::from_millis(3_500), "the session ended with the tunnel, not at the window: {took:?}");
    assert_eq!(tunnel_ends(&ep, 1).await, vec!["fault:end_stream"]);
    assert_eq!(echo.completed_handshakes().len(), 1);
}

#[tokio::test]
async fn a_tunnel_ending_during_the_dtls_handshake_fails_it_and_is_the_endpoints_end() {
    init();
    let echo = dtls_echo(&pki().server, false).await;
    // END_STREAM right after the first reply of the DTLS server.
    let ep = endpoint(vec![echo.addr.to_string()], vec![(echo.addr.to_string(), UdpTunnelFault::EndAfter(1))]).await;
    let o = run(&dtls_via(&echo, &ep)).await;
    let fl = last(&o).failure.as_ref().unwrap();
    assert_eq!((fl.kind, fl.phase), (FailureKind::DtlsHandshakeFailed, Phase::DtlsHandshake), "{fl:?}");
    assert!(fl.message.contains("closed during the DTLS handshake") && fl.message.contains("END_STREAM"), "{}", fl.message);
    assert_eq!(channel(&o).closed_by, ClosedBy::Peer);
    let f = finding(&o, "hbone.udp_tunnel_ended");
    assert_eq!((f.severity, f.scope), (Severity::Error, SourceScope::ForwardProxy));
    assert!(f.explanation.contains("during the DTLS handshake"), "{}", f.explanation);
    assert!(
        !codes(&o).iter().any(|c| c.starts_with("client.dtls.") || c.starts_with("exchange.")),
        "not the DTLS peer's doing: {:?}",
        codes(&o)
    );
    assert_eq!(o.record.outcome.dispatch, DispatchState::NotDispatched);
    assert!(o.record.stream.is_none());
    assert_eq!(tunnel_ends(&ep, 1).await, vec!["fault:end_stream"]);

    // A reset (raw h2 endpoint) during the handshake: an abnormal end with its code.
    let resetting = hbone::serve_resetting("127.0.0.1:0", endpoint_options(vec![], vec![]), 1).await.unwrap();
    let o = run(&dtls_via(&echo, &resetting)).await;
    let fl = last(&o).failure.as_ref().unwrap();
    assert_eq!((fl.kind, fl.phase), (FailureKind::H2StreamReset, Phase::DtlsHandshake), "{fl:?}");
    let ch = channel(&o);
    assert_eq!((ch.closed_by, ch.reset_code.as_deref()), (ClosedBy::Abnormal, Some("CANCEL")));
    let f = finding(&o, "hbone.udp_tunnel_ended");
    assert_eq!(f.severity, Severity::Error);
    assert!(f.explanation.contains("RST_STREAM CANCEL") && f.explanation.contains("during the DTLS handshake"), "{}", f.explanation);
    assert!(
        !codes(&o).iter().any(|c| c.starts_with("exchange.") || c.starts_with("client.dtls.")),
        "the stream is the endpoint's, not the DTLS peer's: {:?}",
        codes(&o)
    );
    assert_eq!(o.record.outcome.transport, TransportState::Failed);
    assert_eq!(tunnel_ends(&resetting, 1).await, vec!["fault:reset"]);
}

#[tokio::test]
async fn interactive_dtls_through_hbone_sends_on_command_until_close() {
    init();
    let echo = dtls_echo(&pki().server, false).await;
    let ep = endpoint(vec![echo.addr.to_string()], vec![]).await;
    let h = Engine::new().open_session(dtls_via(&echo, &ep), EventCtx::none()).await;
    h.send(SessionCommand::SendText { text: "live".into() }).await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    h.close().await.unwrap();
    let o = h.finish().await;
    assert!(last(&o).failure.is_none(), "{:?}", last(&o).failure);
    assert_eq!(previews(&o, Direction::Received, "datagram"), vec!["secure hello", "live"]);
    assert_eq!(counts(&o), (2, 2));
    assert_eq!(channel(&o).closed_by, ClosedBy::Client);
    assert_eq!(o.record.outcome.transport, TransportState::Completed);
    assert_eq!(previews(&o, Direction::Sent, "close_notify").len(), 1);
    assert_eq!(app_datagrams(&echo.log), 2);
    assert_eq!(tunnel_ends(&ep, 1).await, vec!["client_end"]);
}

#[tokio::test]
async fn dtls_through_hbone_still_refuses_a_proxy_envelope_and_auth_before_traffic() {
    init();
    let echo = dtls_echo(&pki().server, false).await;
    let ep = endpoint(vec![echo.addr.to_string()], vec![]).await;
    let refused = |o: &ExecutionOutput, field: &str, needle: &str| {
        let f = last(o).failure.as_ref().unwrap_or_else(|| panic!("{needle}: not refused: {:?}", codes(o)));
        assert_eq!(f.kind, FailureKind::UnsupportedCombination, "{f:?}");
        assert_eq!(f.field.as_deref(), Some(field));
        assert!(f.message.contains(needle), "{}", f.message);
    };
    let mut spec = udp_spec(&["x"], 300);
    spec.proxy_protocol = Some(DatagramEnvelopeSpec {
        command: Default::default(),
        family: Default::default(),
        source: Some("192.0.2.1:1000".into()),
        destination: Some("192.0.2.2:2000".into()),
        authentication: None,
    });
    refused(&run(&via_hbone("dtls", echo.addr, spec, &ep, true, None)).await, "udp.proxy_protocol", "HBONE tunnel");
    let mut c = dtls_via(&echo, &ep);
    c.auth_layers.push((
        "run".into(),
        anvil_domain::auth::AuthConfig::Bearer { token: SensitiveValue::template("tok-123456"), prefix: "Bearer".into() },
    ));
    refused(&run(&c).await, "auth", "verbatim");
    assert_eq!(*ep.log.connections.lock(), 0, "nothing reached the endpoint");
    assert!(echo.log.entries().is_empty());
}
