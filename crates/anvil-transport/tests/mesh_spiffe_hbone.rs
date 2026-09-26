//! Mesh client transport: SPIFFE server-identity verification, SNI override
//! evidence and the HBONE tunnel (HTTP/2 CONNECT over mutual TLS), against
//! real local sockets. Ground truth comes from the fixtures' own logs.

use anvil_domain::execution::*;
use anvil_domain::settings::{HttpVersionPolicy, Limits, Timeouts};
use anvil_domain::tls::{ProxyKind, ServerSpiffeIdentity};
use anvil_fixtures::hbone::{self, HboneOptions};
use anvil_fixtures::http as fxhttp;
use anvil_fixtures::mesh_pki::{self, MeshPki};
use anvil_fixtures::pki::Pem;
use anvil_fixtures::{ClientAuth, LabPki, TlsServerOptions};
use anvil_transport::connector::ProxyPlan;
use anvil_transport::dns::DnsConfig;
use anvil_transport::http::{AttemptOutput, HttpPlan, HttpTransport};
use anvil_transport::recorder::EventCtx;
use anvil_transport::tls::{self, ClientIdentityMaterial, TlsSettings};
use bytes::Bytes;
use std::sync::{Arc, OnceLock};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

fn mesh() -> &'static MeshPki {
    static P: OnceLock<MeshPki> = OnceLock::new();
    P.get_or_init(MeshPki::generate)
}

fn lab() -> &'static LabPki {
    static P: OnceLock<LabPki> = OnceLock::new();
    P.get_or_init(LabPki::generate)
}

fn init() {
    anvil_transport::init();
    anvil_fixtures::init();
}

fn timeouts() -> Timeouts {
    Timeouts {
        dns_ms: Some(2000),
        connect_ms: Some(2000),
        tls_handshake_ms: Some(1500),
        request_write_ms: Some(2000),
        response_headers_ms: Some(2000),
        body_idle_ms: Some(1000),
        total_ms: Some(8000),
    }
}

fn spiffe_id(id: &str) -> Option<ServerSpiffeIdentity> {
    Some(ServerSpiffeIdentity { expected_server_spiffe_id: Some(id.into()), trust_domain: None })
}

fn trust_domain(td: &str) -> Option<ServerSpiffeIdentity> {
    Some(ServerSpiffeIdentity { expected_server_spiffe_id: None, trust_domain: Some(td.into()) })
}

/// Trust the mesh root, optionally present `identity`, verify by SPIFFE.
fn mesh_tls(identity: Option<&Pem>, spiffe: Option<ServerSpiffeIdentity>) -> TlsSettings {
    TlsSettings {
        verify: true,
        use_system_roots: false,
        extra_roots_pem: vec![mesh().ca.cert.clone()],
        client_identity: identity
            .map(|p| ClientIdentityMaterial { cert_chain_pem: p.chain_with(&mesh().ca), private_key_pem: Zeroizing::new(p.key.clone()) }),
        server_spiffe: spiffe,
        ..Default::default()
    }
}

fn plan(url: &str, tls: Option<TlsSettings>, proxy: Option<ProxyPlan>) -> HttpPlan {
    let u = url::Url::parse(url).unwrap();
    let https = u.scheme() == "https";
    let host = u.host_str().unwrap().trim_start_matches('[').trim_end_matches(']').to_string();
    let port = u.port_or_known_default().unwrap();
    HttpPlan {
        method: http::Method::GET,
        https,
        host: host.clone(),
        port,
        authority: format!("{host}:{port}"),
        request_target: u.path().to_string(),
        headers: vec![],
        body: Bytes::new(),
        version: HttpVersionPolicy::Auto,
        timeouts: timeouts(),
        limits: Limits::default(),
        keepalive: true,
        dns: DnsConfig::default(),
        proxy,
        tls: tls.map(|t| Arc::new(tls::prepare(&t).expect("tls profile"))),
        isolation: "mesh-test".into(),
        display_url: url.into(),
    }
}

fn hbone_proxy(addr: &str, tls: TlsSettings, headers: &[(&str, &str)]) -> ProxyPlan {
    let (host, port) = addr.rsplit_once(':').unwrap();
    ProxyPlan {
        kind: ProxyKind::Hbone,
        host: host.into(),
        port: port.parse().unwrap(),
        credentials: None,
        tls: Some(Arc::new(tls::prepare(&tls).expect("hbone tls"))),
        label: format!("test hbone ({addr})"),
        connect_headers: headers
            .iter()
            .map(|(n, v)| (http::HeaderName::from_bytes(n.as_bytes()).unwrap(), http::HeaderValue::from_str(v).unwrap()))
            .collect(),
    }
}

async fn run(t: &HttpTransport, p: &HttpPlan) -> AttemptOutput {
    let mut outs = t.execute(p, 0, AttemptReason::Initial, &EventCtx::none(), &CancellationToken::new()).await;
    outs.pop().unwrap()
}

fn tls_obs(o: &AttemptOutput) -> &TlsObservation {
    o.observation.connection.as_ref().and_then(|c| c.tls.as_ref()).expect("tls observation")
}

fn tunnel(o: &AttemptOutput) -> &TunnelObservation {
    o.observation.connection.as_ref().and_then(|c| c.tunnel.as_ref()).expect("tunnel observation")
}

fn failure(o: &AttemptOutput) -> &TransportFailure {
    o.observation.failure.as_ref().unwrap_or_else(|| panic!("expected a failure, got {:?}", o.observation.response_status))
}

async fn svid_server(cert: &Pem, issuer: &Pem) -> fxhttp::Fixture {
    fxhttp::serve("127.0.0.1:0", Some(TlsServerOptions::new(cert.chain_with(issuer), cert.key.clone()))).await.unwrap()
}

// ------------------------------------------------------------ SPIFFE ---

#[tokio::test]
async fn spiffe_id_verifies_a_uri_only_svid_and_records_the_check() {
    init();
    let fx = svid_server(&mesh().svc, &mesh().ca).await;
    let t = HttpTransport::new();
    let o = run(&t, &plan(&fx.url("/echo"), Some(mesh_tls(None, spiffe_id(mesh_pki::SVC_SPIFFE_ID))), None)).await;
    assert!(o.observation.failure.is_none(), "{:?}", o.observation.failure);
    assert_eq!(o.observation.response_status, Some(200));
    let t = tls_obs(&o);
    assert_eq!(t.verification, TlsVerification::Verified);
    assert_eq!(t.peer_spiffe_id.as_deref(), Some(mesh_pki::SVC_SPIFFE_ID));
    assert_eq!(
        t.identity_check,
        Some(PeerIdentityCheck::SpiffeId { expected: mesh_pki::SVC_SPIFFE_ID.into(), trust_domain: "cluster.local".into() })
    );
    assert_eq!(t.sni, None, "an IP literal sends no SNI");
    assert_eq!(fx.log.count_requests(), 1);
}

#[tokio::test]
async fn host_name_verification_stays_on_by_default_and_records_the_peer_spiffe_id() {
    init();
    let fx = svid_server(&mesh().svc, &mesh().ca).await;
    let o = run(&HttpTransport::new(), &plan(&fx.url("/echo"), Some(mesh_tls(None, None)), None)).await;
    assert_eq!(failure(&o).kind, FailureKind::TlsNameMismatch, "a URI-only SVID does not cover an IP/host name");
    let t = tls_obs(&o);
    assert_eq!(t.identity_check, Some(PeerIdentityCheck::HostName { name: "127.0.0.1".into() }));
    assert_eq!(t.peer_spiffe_id.as_deref(), Some(mesh_pki::SVC_SPIFFE_ID), "the SPIFFE ID is evidence even without a SPIFFE check");
    assert_eq!(fx.log.count_requests(), 0);
}

#[tokio::test]
async fn wrong_expected_spiffe_id_is_a_typed_client_side_failure_before_any_request() {
    init();
    let fx = svid_server(&mesh().svc, &mesh().ca).await;
    let o = run(&HttpTransport::new(), &plan(&fx.url("/echo"), Some(mesh_tls(None, spiffe_id(mesh_pki::OTHER_SPIFFE_ID))), None)).await;
    let f = failure(&o);
    assert_eq!(f.kind, FailureKind::TlsSpiffeIdMismatch);
    assert!(f.message.contains(mesh_pki::SVC_SPIFFE_ID) && f.message.contains(mesh_pki::OTHER_SPIFFE_ID), "{}", f.message);
    assert_eq!(o.observation.dispatch, DispatchState::NotDispatched);
    assert_eq!(fx.log.count_requests(), 0, "nothing was sent");
    assert!(matches!(&tls_obs(&o).verification, TlsVerification::Failed { problem: FailureKind::TlsSpiffeIdMismatch, .. }));
}

#[tokio::test]
async fn trust_domain_check_accepts_any_workload_of_the_domain() {
    init();
    let fx = svid_server(&mesh().other, &mesh().ca).await;
    let o = run(&HttpTransport::new(), &plan(&fx.url("/echo"), Some(mesh_tls(None, trust_domain("cluster.local"))), None)).await;
    assert!(o.observation.failure.is_none(), "{:?}", o.observation.failure);
    assert_eq!(tls_obs(&o).identity_check, Some(PeerIdentityCheck::SpiffeTrustDomain { trust_domain: "cluster.local".into() }));
}

#[tokio::test]
async fn svid_of_another_trust_domain_is_untrusted_whether_or_not_its_chain_anchors() {
    init();
    // Same CA, foreign trust domain: the chain verifies, the domain does not.
    let fx = svid_server(&mesh().partner_same_ca, &mesh().ca).await;
    let o = run(&HttpTransport::new(), &plan(&fx.url("/echo"), Some(mesh_tls(None, trust_domain("cluster.local"))), None)).await;
    assert_eq!(failure(&o).kind, FailureKind::TlsUntrustedTrustDomain);
    // A partner root this profile does not trust.
    let fx2 = svid_server(&mesh().foreign_server, &mesh().foreign_ca).await;
    let o2 = run(&HttpTransport::new(), &plan(&fx2.url("/echo"), Some(mesh_tls(None, spiffe_id(mesh_pki::SVC_SPIFFE_ID))), None)).await;
    assert_eq!(failure(&o2).kind, FailureKind::TlsUntrustedTrustDomain, "{}", failure(&o2).message);
    assert!(failure(&o2).message.contains("partner.example"));
    assert_eq!(fx.log.count_requests() + fx2.log.count_requests(), 0);
}

#[tokio::test]
async fn several_uri_sans_or_none_is_not_an_x509_svid() {
    init();
    for cert in [&mesh().two_uris, &mesh().no_uri] {
        let fx = svid_server(cert, &mesh().ca).await;
        let o = run(&HttpTransport::new(), &plan(&fx.url("/echo"), Some(mesh_tls(None, trust_domain("cluster.local"))), None)).await;
        assert_eq!(failure(&o).kind, FailureKind::TlsInvalidSvid, "{}", failure(&o).message);
        assert_eq!(fx.log.count_requests(), 0);
    }
    // Several URI SANs: no single SPIFFE ID is recorded either.
    let fx = svid_server(&mesh().two_uris, &mesh().ca).await;
    let o = run(&HttpTransport::new(), &plan(&fx.url("/echo"), Some(mesh_tls(None, trust_domain("cluster.local"))), None)).await;
    assert!(failure(&o).message.contains("2 URI SANs"), "{}", failure(&o).message);
    assert_eq!(tls_obs(&o).peer_spiffe_id, None);
}

#[tokio::test]
async fn a_bypass_records_what_the_spiffe_check_would_have_concluded() {
    init();
    let fx = svid_server(&mesh().svc, &mesh().ca).await;
    let mut s = mesh_tls(None, spiffe_id(mesh_pki::OTHER_SPIFFE_ID));
    s.verify = false;
    let o = run(&HttpTransport::new(), &plan(&fx.url("/echo"), Some(s), None)).await;
    assert!(o.observation.failure.is_none());
    assert_eq!(tls_obs(&o).verification, TlsVerification::Bypassed { would_have_failed: Some(FailureKind::TlsSpiffeIdMismatch) });
}

#[test]
fn invalid_spiffe_settings_are_refused_before_traffic() {
    init();
    for (id, td) in [
        (Some("https://cluster.local/ns/a"), None),
        (Some("spiffe://cluster.local/ns//a"), None),
        (None, Some("Cluster.Local")),
        (Some("spiffe://cluster.local/ns/a"), Some("partner.example")),
    ] {
        let mut s = mesh_tls(None, None);
        s.server_spiffe =
            Some(ServerSpiffeIdentity { expected_server_spiffe_id: id.map(String::from), trust_domain: td.map(String::from) });
        let e = tls::prepare(&s).err().unwrap_or_else(|| panic!("{id:?} {td:?} accepted"));
        assert_eq!(e.kind, FailureKind::TlsProfileInvalid);
        assert_eq!(e.phase, Phase::Prepare);
    }
}

// ------------------------------------------------------- SNI override ---

#[tokio::test]
async fn sni_override_is_sent_and_verified_against() {
    init();
    let mut o = TlsServerOptions::new(lab().server.chain_with(&lab().ca), lab().server.key.clone());
    o.alpn = vec!["http/1.1".into()];
    let fx = fxhttp::serve("127.0.0.1:0", Some(o)).await.unwrap();
    let lab_tls = |name: &str| TlsSettings {
        verify: true,
        use_system_roots: false,
        extra_roots_pem: vec![lab().ca.cert.clone()],
        server_name_override: Some(name.into()),
        ..Default::default()
    };
    // Covered by the certificate (*.anvil.test): verified against the override.
    let ok = run(&HttpTransport::new(), &plan(&fx.url("/echo"), Some(lab_tls("api.anvil.test")), None)).await;
    assert!(ok.observation.failure.is_none(), "{:?}", ok.observation.failure);
    let t = tls_obs(&ok);
    assert_eq!(t.sni.as_deref(), Some("api.anvil.test"));
    assert!(t.server_name_overridden);
    assert_eq!(t.identity_check, Some(PeerIdentityCheck::HostName { name: "api.anvil.test".into() }));
    // An east-west passthrough name is sent verbatim, and verified against.
    let ew = "outbound_.8080_._.svc.ferrum.svc.cluster.local";
    let bad = run(&HttpTransport::new(), &plan(&fx.url("/echo"), Some(lab_tls(ew)), None)).await;
    assert_eq!(failure(&bad).kind, FailureKind::TlsNameMismatch);
    assert_eq!(tls_obs(&bad).sni.as_deref(), Some(ew));
}

// --------------------------------------------------------------- HBONE ---

struct Hbone {
    endpoint: hbone::HboneFixture,
    echo: fxhttp::Fixture,
}

async fn hbone_endpoint(client_auth: ClientAuth, alpn: &[&str], extra_allowed: &[&str]) -> Hbone {
    let echo = fxhttp::serve("127.0.0.1:0", None).await.unwrap();
    let mut allowed = vec![echo.addr.to_string()];
    allowed.extend(extra_allowed.iter().map(|s| s.to_string()));
    let endpoint = hbone::serve(
        "127.0.0.1:0",
        HboneOptions {
            server_cert_chain_pem: mesh().ztunnel.chain_with(&mesh().ca),
            server_key_pem: mesh().ztunnel.key.clone(),
            client_auth,
            alpn: alpn.iter().map(|s| s.to_string()).collect(),
            allowed,
            unavailable: vec!["127.0.0.1:9".into()],
            udp_faults: vec![],
        },
    )
    .await
    .unwrap();
    Hbone { endpoint, echo }
}

fn required() -> ClientAuth {
    ClientAuth::Required { ca_pem: mesh().ca.cert.clone() }
}

fn client_svid_tls() -> TlsSettings {
    mesh_tls(Some(&mesh().client), spiffe_id(mesh_pki::ZTUNNEL_SPIFFE_ID))
}

#[tokio::test]
async fn hbone_tunnel_carries_an_inner_http1_request_with_separate_outer_evidence() {
    init();
    let h = hbone_endpoint(required(), &["h2"], &[]).await;
    let proxy = hbone_proxy(&h.endpoint.address(), client_svid_tls(), &[("x-istio-protocol", "hbone")]);
    let o = run(&HttpTransport::new(), &plan(&h.echo.url("/echo"), None, Some(proxy))).await;
    assert!(o.observation.failure.is_none(), "{:?}", o.observation.failure);
    assert_eq!(o.observation.response_status, Some(200));
    assert_eq!(o.observation.dispatch, DispatchState::Sent);
    // Inner phases: the endpoint resolves/dials the destination; the tunnel is one phase.
    assert_eq!(o.observation.phase(Phase::Dns).unwrap().status, PhaseStatus::NotApplicable);
    assert_eq!(o.observation.phase(Phase::Connect).unwrap().status, PhaseStatus::NotApplicable);
    assert_eq!(o.observation.phase(Phase::ProxyTunnel).unwrap().status, PhaseStatus::Completed);
    let c = o.observation.connection.as_ref().unwrap();
    assert!(c.tls.is_none(), "cleartext inner connection");
    assert_eq!(c.protocol.as_deref(), Some("http/1.1"));
    // Outer evidence.
    let t = tunnel(&o);
    assert_eq!(t.kind, TunnelKind::Hbone);
    assert_eq!(t.connect_status, Some(200));
    assert_eq!(t.authority, h.echo.addr.to_string());
    let outer = t.tls.as_ref().unwrap();
    assert_eq!(outer.verification, TlsVerification::Verified);
    assert_eq!(outer.peer_spiffe_id.as_deref(), Some(mesh_pki::ZTUNNEL_SPIFFE_ID));
    assert_eq!(outer.alpn_negotiated.as_deref(), Some("h2"));
    assert!(outer.client_certificate_presented.as_ref().unwrap().subject_alt_names.iter().any(|s| s.contains("anvil-lab-client")));
    let phases: Vec<Phase> = t.phases.iter().map(|p| p.phase).collect();
    assert_eq!(phases, vec![Phase::Dns, Phase::Connect, Phase::TlsHandshake, Phase::ProtocolHandshake, Phase::ProxyTunnel]);
    assert!(t.connect_headers.iter().any(|h| h.name == "x-istio-protocol" && h.value == "hbone"));
    // Ground truth: the endpoint saw an authenticated CONNECT; the echo saw the request.
    let rec = h.endpoint.connects();
    assert_eq!(rec.len(), 1);
    assert_eq!(rec[0].peer_spiffe_id.as_deref(), Some(mesh_pki::CLIENT_SPIFFE_ID));
    assert!(rec[0].headers.iter().any(|(n, v)| n == "x-istio-protocol" && v == "hbone"));
    assert_eq!(h.echo.log.count_requests(), 1);
    // Tunnels are never pooled: a second execution opens a fresh HBONE connection.
    let t2 = HttpTransport::new();
    let p = plan(&h.echo.url("/echo"), None, Some(hbone_proxy(&h.endpoint.address(), client_svid_tls(), &[])));
    let a = run(&t2, &p).await;
    let b = run(&t2, &p).await;
    assert!(a.observation.failure.is_none() && b.observation.failure.is_none());
    assert!(!b.observation.connection.as_ref().unwrap().reused);
    assert_eq!(*h.endpoint.log.connections.lock(), 3);
}

#[tokio::test]
async fn hbone_tunnel_carries_inner_tls_and_http2_to_the_destination() {
    init();
    let echo = fxhttp::serve("127.0.0.1:0", Some(TlsServerOptions::new(lab().server.chain_with(&lab().ca), lab().server.key.clone())))
        .await
        .unwrap();
    let endpoint = hbone::serve(
        "127.0.0.1:0",
        HboneOptions {
            server_cert_chain_pem: mesh().ztunnel.chain_with(&mesh().ca),
            server_key_pem: mesh().ztunnel.key.clone(),
            client_auth: required(),
            alpn: vec!["h2".into()],
            allowed: vec![format!("localhost:{}", echo.addr.port())],
            unavailable: vec![],
            udp_faults: vec![],
        },
    )
    .await
    .unwrap();
    let inner = TlsSettings { verify: true, use_system_roots: false, extra_roots_pem: vec![lab().ca.cert.clone()], ..Default::default() };
    let url = format!("https://localhost:{}/echo", echo.addr.port());
    let o = run(&HttpTransport::new(), &plan(&url, Some(inner), Some(hbone_proxy(&endpoint.address(), client_svid_tls(), &[])))).await;
    assert!(o.observation.failure.is_none(), "{:?}", o.observation.failure);
    let c = o.observation.connection.as_ref().unwrap();
    assert_eq!(c.protocol.as_deref(), Some("h2"), "inner ALPN h2 through the tunnel");
    let inner_tls = c.tls.as_ref().unwrap();
    assert_eq!(inner_tls.sni.as_deref(), Some("localhost"));
    assert_eq!(inner_tls.verification, TlsVerification::Verified);
    assert_eq!(tunnel(&o).tls.as_ref().unwrap().peer_spiffe_id.as_deref(), Some(mesh_pki::ZTUNNEL_SPIFFE_ID));
    assert_eq!(endpoint.connects()[0].authority, format!("localhost:{}", echo.addr.port()), "the endpoint resolves the name");
    assert_eq!(echo.log.count_requests(), 1);
}

#[tokio::test]
async fn hbone_refusal_keeps_status_and_body_and_never_blames_the_destination() {
    init();
    let h = hbone_endpoint(required(), &["h2"], &[]).await;
    let denied = "127.0.0.1:1";
    let o = run(
        &HttpTransport::new(),
        &plan(&format!("http://{denied}/echo"), None, Some(hbone_proxy(&h.endpoint.address(), client_svid_tls(), &[]))),
    )
    .await;
    let f = failure(&o);
    assert_eq!(f.kind, FailureKind::HboneConnectRefused);
    assert_eq!(f.phase, Phase::ProxyTunnel);
    assert_eq!(f.status, Some(403));
    assert_eq!(o.observation.dispatch, DispatchState::NotDispatched);
    assert!(o.response.is_none(), "a CONNECT refusal is not a destination response");
    let t = tunnel(&o);
    assert_eq!(t.connect_status, Some(403));
    assert_eq!(t.refusal_body.as_deref(), Some(hbone::DESTINATION_DENIED_BODY));
    assert_eq!(t.failure.as_ref().unwrap().kind, FailureKind::HboneConnectRefused);
    assert_eq!(o.observation.phase(Phase::ProxyTunnel).unwrap().status, PhaseStatus::Failed);
    assert!(o.observation.phase(Phase::RequestWrite).is_none(), "no inner request phase exists");
    // 5xx: the endpoint could not open the tunnel.
    let o = run(
        &HttpTransport::new(),
        &plan("http://127.0.0.1:9/echo", None, Some(hbone_proxy(&h.endpoint.address(), client_svid_tls(), &[]))),
    )
    .await;
    assert_eq!(failure(&o).status, Some(503));
    assert_eq!(h.echo.log.count_requests(), 0);
}

#[tokio::test]
async fn hbone_without_client_svid_is_refused_at_mtls_or_by_the_unauthenticated_gate() {
    init();
    // Required client auth: the handshake itself refuses.
    let h = hbone_endpoint(required(), &["h2"], &[]).await;
    let no_svid = mesh_tls(None, spiffe_id(mesh_pki::ZTUNNEL_SPIFFE_ID));
    let o =
        run(&HttpTransport::new(), &plan(&h.echo.url("/echo"), None, Some(hbone_proxy(&h.endpoint.address(), no_svid.clone(), &[])))).await;
    let f = failure(&o);
    let inner = tunnel(&o).failure.as_ref().unwrap();
    // TLS 1.3: the alert follows Anvil's finished handshake; a reset can
    // discard it, leaving an HTTP/2 failure right after the handshake.
    match f.kind {
        FailureKind::HboneEndpointTlsFailed => assert_eq!(inner.tls_alert.as_deref(), Some("certificate_required"), "{inner:?}"),
        FailureKind::HboneProtocolError => assert_eq!(inner.phase, Phase::ProxyTunnel, "{inner:?}"),
        other => panic!("unexpected {other:?}: {f:?}"),
    }
    assert_eq!(tunnel(&o).tls.as_ref().unwrap().client_certificate_requested, Some(true));
    assert!(h.endpoint.connects().is_empty());
    // Optional client auth + a marker: TLS completes, the CONNECT is refused.
    let h = hbone_endpoint(ClientAuth::Optional { ca_pem: mesh().ca.cert.clone() }, &["h2"], &[]).await;
    let o = run(
        &HttpTransport::new(),
        &plan(&h.echo.url("/echo"), None, Some(hbone_proxy(&h.endpoint.address(), no_svid, &[("x-ferrum-mesh-protocol", "hbone")]))),
    )
    .await;
    assert_eq!(failure(&o).kind, FailureKind::HboneConnectRefused);
    assert_eq!(tunnel(&o).refusal_body.as_deref(), Some(hbone::UNAUTHENTICATED_BODY));
    assert_eq!(h.endpoint.connects()[0].peer_spiffe_id, None);
    assert_eq!(h.echo.log.count_requests(), 0);
}

#[tokio::test]
async fn hbone_client_svid_from_an_untrusted_domain_is_rejected_by_the_endpoint() {
    init();
    let h = hbone_endpoint(required(), &["h2"], &[]).await;
    let mut s = mesh_tls(None, spiffe_id(mesh_pki::ZTUNNEL_SPIFFE_ID));
    s.client_identity = Some(ClientIdentityMaterial {
        cert_chain_pem: mesh().foreign_client.chain_with(&mesh().foreign_ca),
        private_key_pem: Zeroizing::new(mesh().foreign_client.key.clone()),
    });
    let o = run(&HttpTransport::new(), &plan(&h.echo.url("/echo"), None, Some(hbone_proxy(&h.endpoint.address(), s, &[])))).await;
    assert!(matches!(failure(&o).kind, FailureKind::HboneEndpointTlsFailed | FailureKind::HboneProtocolError), "{:?}", failure(&o));
    let t = tunnel(&o);
    assert!(t.tls.as_ref().unwrap().client_certificate_presented.is_some());
    assert!(h.endpoint.connects().is_empty());
}

#[tokio::test]
async fn hbone_endpoint_identity_mismatch_stops_on_the_client_side() {
    init();
    let h = hbone_endpoint(required(), &["h2"], &[]).await;
    let s = mesh_tls(Some(&mesh().client), spiffe_id(mesh_pki::OTHER_SPIFFE_ID));
    let o = run(&HttpTransport::new(), &plan(&h.echo.url("/echo"), None, Some(hbone_proxy(&h.endpoint.address(), s, &[])))).await;
    assert_eq!(failure(&o).kind, FailureKind::HboneEndpointTlsFailed);
    let t = tunnel(&o);
    assert_eq!(t.failure.as_ref().unwrap().kind, FailureKind::TlsSpiffeIdMismatch);
    assert_eq!(t.failure.as_ref().unwrap().phase, Phase::TlsHandshake);
    assert!(h.endpoint.connects().is_empty(), "no CONNECT was sent");
    assert_eq!(o.observation.dispatch, DispatchState::NotDispatched);
}

#[tokio::test]
async fn hbone_sni_override_reaches_the_endpoint_and_spiffe_decides_identity() {
    init();
    let h = hbone_endpoint(required(), &["h2"], &[]).await;
    let mut s = client_svid_tls();
    let name = "outbound_.15008_._.ztunnel.ferrum.svc.cluster.local";
    s.server_name_override = Some(name.into());
    let o = run(&HttpTransport::new(), &plan(&h.echo.url("/echo"), None, Some(hbone_proxy(&h.endpoint.address(), s, &[])))).await;
    assert!(o.observation.failure.is_none(), "{:?}", o.observation.failure);
    let outer = tunnel(&o).tls.as_ref().unwrap();
    assert_eq!(outer.sni.as_deref(), Some(name));
    assert!(outer.server_name_overridden);
    assert!(matches!(outer.identity_check, Some(PeerIdentityCheck::SpiffeId { .. })));
    assert_eq!(h.endpoint.log.snis.lock().last().cloned().flatten().as_deref(), Some(name), "ground truth: the SNI the endpoint received");
}

#[tokio::test]
async fn hbone_endpoint_problems_before_connect_are_tunnel_leg_failures() {
    init();
    // Nothing listening.
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = closed.local_addr().unwrap().to_string();
    drop(closed);
    let o = run(&HttpTransport::new(), &plan("http://127.0.0.1:1/x", None, Some(hbone_proxy(&addr, client_svid_tls(), &[])))).await;
    assert_eq!(failure(&o).kind, FailureKind::ProxyConnectFailed);
    assert_eq!(tunnel(&o).failure.as_ref().unwrap().kind, FailureKind::ConnectRefused);
    // An endpoint that does not negotiate HTTP/2.
    let h = hbone_endpoint(required(), &["http/1.1"], &[]).await;
    let o = run(&HttpTransport::new(), &plan(&h.echo.url("/echo"), None, Some(hbone_proxy(&h.endpoint.address(), client_svid_tls(), &[]))))
        .await;
    assert_eq!(failure(&o).kind, FailureKind::HboneProtocolError);
    assert_eq!(tunnel(&o).failure.as_ref().unwrap().kind, FailureKind::TlsAlpnMismatch);
    assert!(h.endpoint.connects().is_empty());
}
