//! Engine-level mesh client cases: HBONE proxy profiles and SPIFFE TLS
//! profiles through the shared preparation path, with diagnostics. Fixture
//! ground truth (the HBONE endpoint's CONNECT log, the echo's request log)
//! only checks that a condition was, or was not, reached.

use anvil_domain::Id;
use anvil_domain::diagnostics::{Confidence, Severity, SourceScope};
use anvil_domain::execution::*;
use anvil_domain::outcome::{ApplicationState, ClosedBy, ProtocolStatus, TransportState};
use anvil_domain::request::*;
use anvil_domain::secret::SensitiveValue;
use anvil_domain::settings::{HttpVersionPolicy, ProxySelection, SettingsOverrides, TimeoutOverrides};
use anvil_domain::tls::{ClientIdentity, HboneMarker, HboneOptions, ProxyKind, ProxyProfile, ServerSpiffeIdentity, TlsProfile};
use anvil_engine::{Engine, ExecutionContext, ExecutionOutput};
use anvil_fixtures::hbone::{self, HboneFixture};
use anvil_fixtures::http as fx;
use anvil_fixtures::mesh_pki::{self, MeshPki};
use anvil_fixtures::pki::Pem;
use anvil_fixtures::streams::{self, TcpMode};
use anvil_fixtures::{ClientAuth, TlsServerOptions};
use anvil_transport::recorder::EventCtx;
use std::sync::OnceLock;
use tokio_util::sync::CancellationToken;

fn init() {
    anvil_transport::init();
    anvil_fixtures::init();
}

fn mesh() -> &'static MeshPki {
    static P: OnceLock<MeshPki> = OnceLock::new();
    P.get_or_init(MeshPki::generate)
}

async fn run(c: &ExecutionContext) -> ExecutionOutput {
    Engine::new().execute(c, EventCtx::none(), CancellationToken::new()).await
}

fn codes(o: &ExecutionOutput) -> Vec<String> {
    o.record.findings.iter().map(|f| f.code.clone()).collect()
}

fn finding<'a>(o: &'a ExecutionOutput, code: &str) -> &'a anvil_domain::diagnostics::DiagnosticFinding {
    o.record.findings.iter().find(|f| f.code == code).unwrap_or_else(|| panic!("{code} missing; findings: {:?}", codes(o)))
}

fn last(o: &ExecutionOutput) -> &AttemptObservation {
    o.record.attempts.last().expect("an attempt")
}

fn tunnel(o: &ExecutionOutput) -> &TunnelObservation {
    last(o).connection.as_ref().and_then(|c| c.tunnel.as_ref()).expect("tunnel evidence")
}

fn tls_profile(name: &str, identity: Option<(&Pem, &Pem)>, spiffe: Option<ServerSpiffeIdentity>) -> TlsProfile {
    TlsProfile {
        id: Id::new(),
        workspace_id: Id::new(),
        name: name.into(),
        verify: true,
        use_system_roots: false,
        extra_roots_pem: vec![mesh().ca.cert.clone()],
        client_identity: identity.map(|(leaf, ca)| ClientIdentity::Pem {
            cert_chain_pem: leaf.chain_with(ca),
            private_key_pem: SensitiveValue::template(leaf.key.clone()),
        }),
        bindings: vec![],
        min_version: Default::default(),
        server_name_override: None,
        server_spiffe: spiffe,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

fn expect_id(id: &str) -> Option<ServerSpiffeIdentity> {
    Some(ServerSpiffeIdentity { expected_server_spiffe_id: Some(id.into()), trust_domain: None })
}

fn fast() -> SettingsOverrides {
    SettingsOverrides {
        timeouts: Some(TimeoutOverrides {
            connect_ms: Some(Some(3_000)),
            tls_handshake_ms: Some(Some(3_000)),
            response_headers_ms: Some(Some(5_000)),
            total_ms: Some(Some(20_000)),
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// A context sending `spec` through an HBONE proxy at `endpoint` using `tls`.
fn via_hbone(spec: RequestSpec, endpoint: &str, tls: Option<TlsProfile>, marker: HboneMarker) -> ExecutionContext {
    let mut c = ExecutionContext::standalone(spec);
    let proxy = ProxyProfile {
        id: Id::new(),
        workspace_id: Id::new(),
        name: "mesh hbone".into(),
        kind: ProxyKind::Hbone,
        address: endpoint.into(),
        username: None,
        password: None,
        no_proxy: String::new(),
        tls_profile_id: tls.as_ref().map(|t| t.id),
        hbone: Some(HboneOptions {
            marker,
            baggage: Some(format!("source.principal={}", mesh_pki::CLIENT_SPIFFE_ID)),
            extra_headers: vec![],
        }),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    let mut o = fast();
    o.proxy_profile_id = Some(ProxySelection::Profile { id: proxy.id });
    c.proxy_profiles.push(proxy);
    if let Some(t) = tls {
        c.tls_profiles.push(t);
    }
    c.settings_layers.push(("run".into(), o));
    c
}

fn client_svid_profile() -> TlsProfile {
    tls_profile("client SVID", Some((&mesh().client, &mesh().ca)), expect_id(mesh_pki::ZTUNNEL_SPIFFE_ID))
}

async fn endpoint(auth: ClientAuth, allowed: Vec<String>) -> HboneFixture {
    hbone::serve(
        "127.0.0.1:0",
        hbone::HboneOptions {
            server_cert_chain_pem: mesh().ztunnel.chain_with(&mesh().ca),
            server_key_pem: mesh().ztunnel.key.clone(),
            client_auth: auth,
            alpn: vec!["h2".into()],
            allowed,
            unavailable: vec!["127.0.0.1:9".into()],
        },
    )
    .await
    .unwrap()
}

fn required() -> ClientAuth {
    ClientAuth::Required { ca_pem: mesh().ca.cert.clone() }
}

fn no_destination_blame(o: &ExecutionOutput) {
    let c = codes(o);
    assert!(
        !c.iter()
            .any(|x| x.starts_with("http.") || x.starts_with("ferrum.") || x.starts_with("client.dns") || x.starts_with("client.connect")),
        "the destination must not be blamed: {c:?}"
    );
    assert_eq!(o.record.outcome.dispatch, DispatchState::NotDispatched);
    assert!(o.record.response.is_none());
    assert_eq!(o.record.outcome.transport, TransportState::Failed);
    assert_eq!(o.record.outcome.application, ApplicationState::NotEvaluated);
}

#[tokio::test]
async fn hbone_proxy_profile_reaches_the_destination_with_markers_and_baggage() {
    init();
    let echo = fx::serve("127.0.0.1:0", None).await.unwrap();
    let ep = endpoint(required(), vec![echo.addr.to_string()]).await;
    let c = via_hbone(
        RequestSpec::http("GET", &echo.url("/echo")),
        &ep.address(),
        Some(client_svid_profile()),
        HboneMarker::FerrumMeshProtocol,
    );
    let o = run(&c).await;
    assert!(last(&o).failure.is_none(), "{:?} {:?}", last(&o).failure, codes(&o));
    assert_eq!(o.record.response.as_ref().unwrap().status, 200);
    assert!(!o.record.findings.iter().any(|f| f.severity >= Severity::Warning), "{:?}", codes(&o));
    let t = tunnel(&o);
    assert_eq!(t.connect_status, Some(200));
    assert!(o.record.prepared.proxy.as_deref().unwrap().contains("mesh hbone"));
    let rec = &ep.connects()[0];
    assert!(rec.headers.iter().any(|(n, v)| n == "x-ferrum-mesh-protocol" && v == "hbone"));
    assert!(rec.headers.iter().any(|(n, v)| n == "baggage" && v.contains(mesh_pki::CLIENT_SPIFFE_ID)));
    assert_eq!(echo.log.count_requests(), 1);
}

#[tokio::test]
async fn hbone_refusal_is_a_forward_proxy_finding_with_the_public_body() {
    init();
    let echo = fx::serve("127.0.0.1:0", None).await.unwrap();
    let ep = endpoint(required(), vec![]).await;
    let c = via_hbone(RequestSpec::http("POST", &echo.url("/echo")), &ep.address(), Some(client_svid_profile()), HboneMarker::None);
    let o = run(&c).await;
    assert_eq!(last(&o).failure.as_ref().unwrap().kind, FailureKind::HboneConnectRefused);
    let f = finding(&o, "hbone.tunnel_refused");
    assert_eq!(f.scope, SourceScope::ForwardProxy);
    assert_eq!(f.confidence, Confidence::Confirmed, "the answer came over the verified mTLS connection");
    assert!(f.explanation.contains("HBONE relay destination not allowed"), "{}", f.explanation);
    assert!(f.explanation.contains("403"));
    assert!(f.does_not_prove.iter().any(|d| d.contains("Which mesh policy")));
    no_destination_blame(&o);
    assert!(!codes(&o).iter().any(|c| c == "request.processing_uncertain"), "a refused POST was provably not processed");
    assert_eq!(echo.log.count_requests(), 0);

    // 5xx on CONNECT: the endpoint could not open the tunnel; no leg claim.
    let c = via_hbone(RequestSpec::http("GET", "http://127.0.0.1:9/"), &ep.address(), Some(client_svid_profile()), HboneMarker::None);
    let o = run(&c).await;
    let f = finding(&o, "hbone.tunnel_unavailable");
    assert_eq!(f.scope, SourceScope::ForwardProxy);
    no_destination_blame(&o);
}

#[tokio::test]
async fn unauthenticated_marker_only_connect_is_refused_with_the_endpoint_body() {
    init();
    let echo = fx::serve("127.0.0.1:0", None).await.unwrap();
    let ep = endpoint(ClientAuth::Optional { ca_pem: mesh().ca.cert.clone() }, vec![echo.addr.to_string()]).await;
    let no_svid = tls_profile("no SVID", None, expect_id(mesh_pki::ZTUNNEL_SPIFFE_ID));
    let c = via_hbone(RequestSpec::http("GET", &echo.url("/echo")), &ep.address(), Some(no_svid), HboneMarker::IstioProtocol);
    let o = run(&c).await;
    let f = finding(&o, "hbone.tunnel_refused");
    assert!(f.explanation.contains("HBONE tunnel requires an authenticated mesh peer"), "{}", f.explanation);
    no_destination_blame(&o);
    assert_eq!(ep.connects()[0].peer_spiffe_id, None);
}

#[tokio::test]
async fn hbone_mtls_failures_are_split_by_leg() {
    init();
    let echo = fx::serve("127.0.0.1:0", None).await.unwrap();
    let ep = endpoint(required(), vec![echo.addr.to_string()]).await;
    let spec = || RequestSpec::http("GET", &echo.url("/echo"));

    // Anvil rejects the endpoint's identity (client-side decision).
    let wrong = tls_profile("wrong endpoint id", Some((&mesh().client, &mesh().ca)), expect_id(mesh_pki::OTHER_SPIFFE_ID));
    let o = run(&via_hbone(spec(), &ep.address(), Some(wrong), HboneMarker::None)).await;
    let f = finding(&o, "hbone.endpoint_identity_rejected");
    assert_eq!(f.confidence, Confidence::Confirmed);
    assert!(f.explanation.contains(mesh_pki::ZTUNNEL_SPIFFE_ID) && f.explanation.contains(mesh_pki::OTHER_SPIFFE_ID), "{}", f.explanation);
    assert!(f.evidence.iter().any(|e| e.key == "tunnel.failure.kind" && e.value == "TlsSpiffeIdMismatch"));
    no_destination_blame(&o);

    // The endpoint requires a client SVID that Anvil does not have.
    let none = tls_profile("no client SVID", None, expect_id(mesh_pki::ZTUNNEL_SPIFFE_ID));
    let o = run(&via_hbone(spec(), &ep.address(), Some(none), HboneMarker::None)).await;
    // TLS 1.3 delivers certificate_required after Anvil's side of the
    // handshake; a reset can discard it (then the lost-alert finding applies).
    match o.record.findings.iter().find(|f| f.code == "hbone.client_svid_required") {
        Some(f) => assert_eq!(f.confidence, Confidence::Confirmed),
        None => assert_eq!(finding(&o, "hbone.closed_after_certificate_request").confidence, Confidence::Likely),
    }
    no_destination_blame(&o);

    // The endpoint rejects an SVID from an untrusted trust domain.
    let foreign = tls_profile("partner SVID", Some((&mesh().foreign_client, &mesh().foreign_ca)), expect_id(mesh_pki::ZTUNNEL_SPIFFE_ID));
    let o = run(&via_hbone(spec(), &ep.address(), Some(foreign), HboneMarker::None)).await;
    let codes = codes(&o);
    assert!(
        codes.iter().any(|c| c == "hbone.client_svid_rejected"
            || c == "hbone.endpoint_tls_failed"
            || c == "hbone.closed_after_certificate_request"),
        "{codes:?}"
    );
    assert!(!codes.iter().any(|c| c == "hbone.endpoint_identity_rejected"), "Anvil accepted the endpoint: {codes:?}");
    no_destination_blame(&o);
    assert!(ep.connects().is_empty(), "no CONNECT was ever sent");
    assert_eq!(echo.log.count_requests(), 0);
}

#[tokio::test]
async fn hbone_without_a_tls_profile_is_refused_before_traffic() {
    init();
    let ep = endpoint(required(), vec![]).await;
    let c = via_hbone(RequestSpec::http("GET", "http://127.0.0.1:1/"), &ep.address(), None, HboneMarker::None);
    let o = run(&c).await;
    assert_eq!(last(&o).failure.as_ref().unwrap().kind, FailureKind::ProxyConfigInvalid);
    assert!(codes(&o).contains(&"local.proxy_config_invalid".to_string()), "{:?}", codes(&o));
    assert_eq!(*ep.log.connections.lock(), 0, "nothing was sent");
}

#[tokio::test]
async fn http3_through_an_hbone_proxy_is_an_unsupported_combination() {
    init();
    let ep = endpoint(required(), vec![]).await;
    let mut c = via_hbone(RequestSpec::http("GET", "https://127.0.0.1:1/"), &ep.address(), Some(client_svid_profile()), HboneMarker::None);
    c.settings_layers.push(("h3".into(), SettingsOverrides { http_version: Some(HttpVersionPolicy::Http3Only), ..Default::default() }));
    let o = run(&c).await;
    assert_eq!(last(&o).failure.as_ref().unwrap().kind, FailureKind::UnsupportedCombination);
    assert_eq!(*ep.log.connections.lock(), 0);
}

#[tokio::test]
async fn websocket_and_raw_tcp_run_over_the_hbone_tunnel() {
    init();
    let ws = fx::serve("127.0.0.1:0", None).await.unwrap();
    let tcp = streams::tcp("127.0.0.1:0", TcpMode::Echo, None).await.unwrap();
    let ep = endpoint(required(), vec![ws.addr.to_string(), tcp.addr.to_string()]).await;

    let mut s = RequestSpec::http("GET", &format!("ws://{}/ws?close_after=1", ws.addr));
    s.protocol = Protocol::WebSocket;
    s.websocket = Some(WsSpec {
        bootstrap: WsBootstrap::Http1Upgrade,
        subprotocols: vec![],
        messages: vec![WsMessage::Text { text: "through-hbone".into() }],
        expect_messages: 0,
        max_message_bytes: 1024 * 1024,
        idle_close_ms: 1_500,
    });
    let o = run(&via_hbone(s, &ep.address(), Some(client_svid_profile()), HboneMarker::None)).await;
    match &o.record.outcome.protocol_status {
        ProtocolStatus::WebSocket { handshake_status, close_code, closed_by, .. } => {
            assert_eq!(*handshake_status, Some(101));
            assert_eq!(*close_code, Some(1000));
            assert_eq!(*closed_by, ClosedBy::Peer);
        }
        other => panic!("{other:?} {:?}", codes(&o)),
    }
    assert_eq!(tunnel(&o).connect_status, Some(200));

    let mut s = RequestSpec::http("GET", &format!("tcp://{}", tcp.addr));
    s.protocol = Protocol::Tcp;
    s.tcp = Some(TcpSpec {
        proxy_protocol: None,
        tls: false,
        framing: TcpFraming::None,
        payloads: vec![StreamPayload { data: "ping-through-hbone".into(), encoding: PayloadEncoding::Text }],
        half_close_after_send: false,
        read_idle_ms: 500,
        max_read_bytes: 4096,
        expect_frames: 0,
    });
    let o = run(&via_hbone(s, &ep.address(), Some(client_svid_profile()), HboneMarker::None)).await;
    match &o.record.outcome.protocol_status {
        ProtocolStatus::Tcp { bytes_sent, bytes_received, .. } => {
            assert_eq!(*bytes_sent, 18);
            assert!(*bytes_received >= 18, "echo through the tunnel: {bytes_received}");
        }
        other => panic!("{other:?} {:?}", codes(&o)),
    }
    assert_eq!(tunnel(&o).connect_status, Some(200));
    let authorities: Vec<String> = ep.connects().iter().map(|c| c.authority.clone()).collect();
    assert!(authorities.contains(&ws.addr.to_string()) && authorities.contains(&tcp.addr.to_string()), "{authorities:?}");
}

// ------------------------------------------------ SPIFFE TLS profiles ---

async fn svid_server(cert: &Pem, ca: &Pem) -> fx::Fixture {
    fx::serve("127.0.0.1:0", Some(TlsServerOptions::new(cert.chain_with(ca), cert.key.clone()))).await.unwrap()
}

fn direct(url: &str, p: TlsProfile) -> ExecutionContext {
    let mut c = ExecutionContext::standalone(RequestSpec::http("GET", url));
    let mut o = fast();
    o.tls_profile_id = Some(p.id);
    c.tls_profiles.push(p);
    c.settings_layers.push(("run".into(), o));
    c
}

#[tokio::test]
async fn spiffe_profile_findings_name_the_presented_and_expected_identity() {
    init();
    let svc = svid_server(&mesh().svc, &mesh().ca).await;
    let ok = run(&direct(&svc.url("/echo"), tls_profile("svc", None, expect_id(mesh_pki::SVC_SPIFFE_ID)))).await;
    assert!(last(&ok).failure.is_none(), "{:?}", codes(&ok));
    let tls = last(&ok).connection.as_ref().unwrap().tls.as_ref().unwrap();
    assert_eq!(tls.peer_spiffe_id.as_deref(), Some(mesh_pki::SVC_SPIFFE_ID));

    let o = run(&direct(&svc.url("/echo"), tls_profile("svc", None, expect_id(mesh_pki::OTHER_SPIFFE_ID)))).await;
    let f = finding(&o, "client.tls.spiffe_id_mismatch");
    assert_eq!(f.scope, SourceScope::ClientToPeer);
    assert!(f.explanation.contains(mesh_pki::SVC_SPIFFE_ID) && f.explanation.contains(mesh_pki::OTHER_SPIFFE_ID), "{}", f.explanation);
    assert!(f.evidence.iter().any(|e| e.key == "tls.identity_check" && e.value.contains(mesh_pki::OTHER_SPIFFE_ID)));
    assert_eq!(o.record.outcome.dispatch, DispatchState::NotDispatched);

    let partner = svid_server(&mesh().partner_same_ca, &mesh().ca).await;
    let td = Some(ServerSpiffeIdentity { expected_server_spiffe_id: None, trust_domain: Some("cluster.local".into()) });
    let o = run(&direct(&partner.url("/echo"), tls_profile("td", None, td.clone()))).await;
    assert!(finding(&o, "client.tls.untrusted_trust_domain").explanation.contains("partner.example"));

    let two = svid_server(&mesh().two_uris, &mesh().ca).await;
    let o = run(&direct(&two.url("/echo"), tls_profile("td", None, td))).await;
    assert!(finding(&o, "client.tls.invalid_svid").explanation.contains("URI SAN"));
    assert_eq!(svc.log.count_requests() + partner.log.count_requests() + two.log.count_requests(), 1, "only the positive control was sent");
}

#[tokio::test]
async fn sni_override_is_noted_with_the_identity_that_was_checked() {
    init();
    let svc = svid_server(&mesh().svc, &mesh().ca).await;
    let mut p = tls_profile("svc", None, expect_id(mesh_pki::SVC_SPIFFE_ID));
    p.server_name_override = Some("outbound_.8080_._.svc.ferrum.svc.cluster.local".into());
    let o = run(&direct(&svc.url("/echo"), p)).await;
    assert!(last(&o).failure.is_none(), "{:?}", codes(&o));
    let f = finding(&o, "client.tls.sni_override");
    assert_eq!(f.severity, Severity::Info);
    assert!(f.explanation.contains("outbound_.8080_._.svc.ferrum.svc.cluster.local"), "{}", f.explanation);
    assert!(f.explanation.contains(mesh_pki::SVC_SPIFFE_ID), "{}", f.explanation);
}
