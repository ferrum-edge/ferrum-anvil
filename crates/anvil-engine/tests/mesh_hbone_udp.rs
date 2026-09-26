//! UDP through an HBONE proxy profile (Ferrum Mesh datagram-over-HBONE):
//! the `udp`-marked CONNECT, `[u16 length][payload]` records in both
//! directions, the tunnel's end, refusals and local limits, over real
//! sockets. Ground truth comes from the HBONE fixture's own log (CONNECT
//! headers, datagrams it relayed, how each tunnel ended) and the UDP
//! fixtures; neither is given to the engine.

use anvil_domain::Id;
use anvil_domain::diagnostics::{Confidence, Severity, SourceScope};
use anvil_domain::events::SessionCommand;
use anvil_domain::execution::*;
use anvil_domain::outcome::{ApplicationState, ClosedBy, ProtocolStatus, TransportState};
use anvil_domain::proxy_protocol::DatagramEnvelopeSpec;
use anvil_domain::request::*;
use anvil_domain::secret::SensitiveValue;
use anvil_domain::settings::{ProxySelection, SettingsOverrides, TimeoutOverrides};
use anvil_domain::tls::{ClientIdentity, HboneMarker, HboneOptions, ProxyKind, ProxyProfile, ServerSpiffeIdentity, TlsProfile};
use anvil_engine::{Engine, ExecutionContext, ExecutionOutput};
use anvil_fixtures::hbone::{self, HboneFixture, UdpTunnelFault};
use anvil_fixtures::mesh_pki::{self, MeshPki};
use anvil_fixtures::pki::Pem;
use anvil_fixtures::streams::{self, StreamFixture, UdpMode};
use anvil_fixtures::{ClientAuth, GroundTruth};
use anvil_transport::recorder::EventCtx;
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

fn channel(o: &ExecutionOutput) -> &HboneDatagramChannel {
    tunnel(o).datagrams.as_ref().expect("datagram channel evidence")
}

fn counts(o: &ExecutionOutput) -> (u64, u64) {
    match &o.record.outcome.protocol_status {
        ProtocolStatus::Udp { datagrams_sent, datagrams_received, masque: None, .. } => (*datagrams_sent, *datagrams_received),
        other => panic!("{other:?} {:?}", codes(o)),
    }
}

fn previews(o: &ExecutionOutput, dir: Direction) -> Vec<String> {
    o.record
        .stream
        .as_ref()
        .expect("transcript")
        .messages
        .iter()
        .filter(|m| m.direction == dir && m.kind == "datagram")
        .map(|m| m.preview.clone())
        .collect()
}

fn tls_profile(name: &str, identity: Option<(&Pem, &Pem)>) -> TlsProfile {
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
        server_spiffe: Some(ServerSpiffeIdentity {
            expected_server_spiffe_id: Some(mesh_pki::ZTUNNEL_SPIFFE_ID.into()),
            trust_domain: None,
        }),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

fn client_svid() -> TlsProfile {
    tls_profile("client SVID", Some((&mesh().client, &mesh().ca)))
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

fn proxy_profile(kind: ProxyKind, address: &str, tls: Option<&TlsProfile>, options: HboneOptions) -> ProxyProfile {
    ProxyProfile {
        id: Id::new(),
        workspace_id: Id::new(),
        name: "mesh hbone".into(),
        kind,
        address: address.into(),
        username: None,
        password: None,
        no_proxy: String::new(),
        tls_profile_id: tls.map(|t| t.id),
        hbone: (kind == ProxyKind::Hbone).then_some(options),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

fn marker(marker: HboneMarker) -> HboneOptions {
    HboneOptions { marker, baggage: Some(format!("source.principal={}", mesh_pki::CLIENT_SPIFFE_ID)), extra_headers: vec![] }
}

/// `url` with `udp` through `proxy`, fast timeouts.
fn with_proxy(url: &str, udp: UdpSpec, proxy: ProxyProfile, tls: Option<TlsProfile>) -> ExecutionContext {
    let mut s = RequestSpec::http("GET", url);
    s.protocol = Protocol::Udp;
    s.udp = Some(udp);
    let mut c = ExecutionContext::standalone(s);
    let o = SettingsOverrides {
        timeouts: Some(TimeoutOverrides {
            connect_ms: Some(Some(3_000)),
            tls_handshake_ms: Some(Some(3_000)),
            response_headers_ms: Some(Some(5_000)),
            total_ms: Some(Some(20_000)),
            ..Default::default()
        }),
        proxy_profile_id: Some(ProxySelection::Profile { id: proxy.id }),
        ..Default::default()
    };
    c.proxy_profiles.push(proxy);
    if let Some(t) = tls {
        c.tls_profiles.push(t);
    }
    c.settings_layers.push(("run".into(), o));
    c
}

fn via_hbone(target: &StreamFixture, udp: UdpSpec, ep: &HboneFixture, tls: Option<TlsProfile>, m: HboneMarker) -> ExecutionContext {
    let p = proxy_profile(ProxyKind::Hbone, &ep.address(), tls.as_ref(), marker(m));
    with_proxy(&format!("udp://{}", target.addr), udp, p, tls)
}

async fn endpoint(auth: ClientAuth, allowed: Vec<String>, unavailable: Vec<String>, faults: Vec<(String, UdpTunnelFault)>) -> HboneFixture {
    hbone::serve(
        "127.0.0.1:0",
        hbone::HboneOptions {
            server_cert_chain_pem: mesh().ztunnel.chain_with(&mesh().ca),
            server_key_pem: mesh().ztunnel.key.clone(),
            client_auth: auth,
            alpn: vec!["h2".into()],
            allowed,
            unavailable,
            udp_faults: faults,
        },
    )
    .await
    .unwrap()
}

fn required() -> ClientAuth {
    ClientAuth::Required { ca_pem: mesh().ca.cert.clone() }
}

fn datagrams_seen(f: &StreamFixture) -> Vec<u64> {
    f.log
        .entries()
        .iter()
        .filter_map(|e| match e.event {
            GroundTruth::DatagramReceived { bytes } => Some(bytes),
            _ => None,
        })
        .collect()
}

/// Wait (bounded) until the fixture recorded `n` tunnel ends.
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

/// A tunnel-leg or CONNECT outcome: the UDP destination is never blamed and nothing was sent.
fn no_destination_blame(o: &ExecutionOutput) {
    let c = codes(o);
    assert!(
        !c.iter().any(|x| x.starts_with("http.")
            || x.starts_with("ferrum.")
            || x.starts_with("client.dns")
            || x.starts_with("client.connect")
            || x.starts_with("udp.")
            || x.starts_with("exchange.")),
        "the destination must not be blamed: {c:?}"
    );
    assert_eq!(o.record.outcome.dispatch, DispatchState::NotDispatched);
    assert!(o.record.response.is_none());
    assert_eq!(counts(o), (0, 0));
}

#[tokio::test]
async fn udp_through_hbone_relays_records_and_keeps_both_legs_apart() {
    init();
    let echo = streams::udp("127.0.0.1:0", UdpMode::Echo).await.unwrap();
    let ep = endpoint(required(), vec![echo.addr.to_string()], vec![], vec![]).await;
    let c = via_hbone(&echo, udp_spec(&["ping-1", "", "ping-3"], 400), &ep, Some(client_svid()), HboneMarker::None);
    let o = run(&c).await;
    assert!(last(&o).failure.is_none(), "{:?} {:?}", last(&o).failure, codes(&o));
    assert_eq!(counts(&o), (3, 3));
    assert_eq!(previews(&o, Direction::Received), vec!["ping-1", "", "ping-3"], "per-datagram boundaries, a zero-length datagram kept");
    assert!(!o.record.findings.iter().any(|f| f.severity >= Severity::Warning), "{:?}", codes(&o));
    assert_eq!(o.record.outcome.transport, TransportState::Completed);
    assert_eq!(last(&o).dispatch, DispatchState::Sent);

    // Outer leg: the verified mTLS and the udp-marked CONNECT; no inner TLS, DNS or connect.
    let t = tunnel(&o);
    assert_eq!(t.connect_status, Some(200));
    assert_eq!(t.authority, echo.addr.to_string());
    let tls = t.tls.as_ref().unwrap();
    assert_eq!(tls.verification, TlsVerification::Verified);
    assert!(tls.client_certificate_presented.is_some());
    assert!(t.phases.iter().any(|p| p.phase == Phase::TlsHandshake && p.status == PhaseStatus::Completed));
    assert!(t.connect_headers.iter().any(|h| h.name == "x-ferrum-mesh-protocol" && h.value == "udp"), "{:?}", t.connect_headers);
    let conn = last(&o).connection.as_ref().unwrap();
    assert!(conn.tls.is_none(), "UDP has no inner TLS");
    assert_eq!(conn.protocol.as_deref(), Some("udp"));
    for p in [Phase::Dns, Phase::Connect] {
        assert_eq!(last(&o).phase(p).map(|x| x.status), Some(PhaseStatus::NotApplicable), "{p:?}");
    }
    assert_eq!(last(&o).phase(Phase::ProxyTunnel).map(|x| x.status), Some(PhaseStatus::Completed));
    let ch = channel(&o);
    assert_eq!((ch.records_sent, ch.records_received, ch.closed_by), (3, 3, ClosedBy::Client));
    assert_eq!((ch.oversize_refused, ch.truncated_tail_bytes, ch.reset_code.clone()), (0, 0, None));
    assert!(o.record.prepared.inferred.iter().any(|i| i.contains("x-ferrum-mesh-protocol: udp")), "{:?}", o.record.prepared.inferred);

    // Ground truth: the endpoint saw a bare CONNECT (the fixture answers 405 to a :protocol)
    // with the udp marker, relayed each datagram intact, and saw Anvil end the tunnel.
    let rec = &ep.connects()[0];
    assert_eq!(rec.authority, echo.addr.to_string());
    assert!(rec.headers.iter().any(|(n, v)| n == "x-ferrum-mesh-protocol" && v == "udp"));
    assert!(rec.headers.iter().any(|(n, v)| n == "baggage" && v.contains(mesh_pki::CLIENT_SPIFFE_ID)));
    assert_eq!(rec.peer_spiffe_id.as_deref(), Some(mesh_pki::CLIENT_SPIFFE_ID));
    assert_eq!(datagrams_seen(&echo), vec![6, 0, 6]);
    assert_eq!(tunnel_ends(&ep, 1).await, vec!["client_end"], "Anvil ended the tunnel itself");
}

#[tokio::test]
async fn the_istio_marker_carries_udp_and_marker_extras_are_refused_before_traffic() {
    init();
    let echo = streams::udp("127.0.0.1:0", UdpMode::Echo).await.unwrap();
    let ep = endpoint(required(), vec![echo.addr.to_string()], vec![], vec![]).await;
    let o = run(&via_hbone(&echo, udp_spec(&["istio"], 300), &ep, Some(client_svid()), HboneMarker::IstioProtocol)).await;
    assert_eq!(counts(&o), (1, 1), "{:?}", codes(&o));
    let h = &ep.connects()[0].headers;
    assert!(h.iter().any(|(n, v)| n == "x-istio-protocol" && v == "udp"), "{h:?}");
    assert!(!h.iter().any(|(n, _)| n == "x-ferrum-mesh-protocol"), "{h:?}");

    // A marker header among the extras would make the datagram selection ambiguous.
    let mut opts = marker(HboneMarker::None);
    opts.extra_headers.push(KeyValue::new("X-Ferrum-Mesh-Protocol", "hbone"));
    let tls = client_svid();
    let p = proxy_profile(ProxyKind::Hbone, &ep.address(), Some(&tls), opts);
    let o = run(&with_proxy(&format!("udp://{}", echo.addr), udp_spec(&["x"], 300), p, Some(tls))).await;
    assert_eq!(last(&o).failure.as_ref().unwrap().kind, FailureKind::ProxyConfigInvalid);
    assert!(codes(&o).contains(&"local.proxy_config_invalid".to_string()), "{:?}", codes(&o));
    assert_eq!(*ep.log.connections.lock(), 1, "only the first run connected");
}

#[tokio::test]
async fn silence_through_the_tunnel_is_only_no_response_observed() {
    init();
    let silent = streams::udp("127.0.0.1:0", UdpMode::Silent).await.unwrap();
    let ep = endpoint(required(), vec![silent.addr.to_string()], vec![], vec![]).await;
    let o = run(&via_hbone(&silent, udp_spec(&["anyone?"], 300), &ep, Some(client_svid()), HboneMarker::None)).await;
    assert_eq!(counts(&o), (1, 0));
    let n = finding(&o, "udp.no_response");
    assert!(n.does_not_prove.iter().any(|d| d.contains("delivered")), "{:?}", n.does_not_prove);
    assert!(
        n.alternatives.iter().any(|a| a.contains("without acknowledgement") && a.contains(&silent.addr.to_string())),
        "{:?}",
        n.alternatives
    );
    assert!(!codes(&o).iter().any(|c| c.starts_with("hbone.")), "the tunnel itself was fine: {:?}", codes(&o));
    assert_eq!(last(&o).dispatch, DispatchState::MayHaveBeenSent);
    assert_eq!(o.record.outcome.transport, TransportState::Completed);
    assert_ne!(o.record.outcome.application, ApplicationState::Success);
    assert_eq!(channel(&o).closed_by, ClosedBy::Client);
    // Independent ground truth: the datagram did arrive; Anvil claims neither way.
    assert_eq!(datagrams_seen(&silent), vec![7]);
}

#[tokio::test]
async fn datagram_connect_refusals_quote_the_public_body_and_send_nothing() {
    init();
    let echo = streams::udp("127.0.0.1:0", UdpMode::Echo).await.unwrap();
    let full = streams::udp("127.0.0.1:0", UdpMode::Echo).await.unwrap();
    let ep =
        endpoint(ClientAuth::Optional { ca_pem: mesh().ca.cert.clone() }, vec![full.addr.to_string()], vec![full.addr.to_string()], vec![])
            .await;

    // No client SVID: the endpoint's UDP-specific authenticated-peer refusal.
    let o = run(&via_hbone(&echo, udp_spec(&["x"], 300), &ep, Some(tls_profile("no SVID", None)), HboneMarker::None)).await;
    assert_eq!(last(&o).failure.as_ref().unwrap().kind, FailureKind::HboneConnectRefused);
    let f = finding(&o, "hbone.tunnel_refused");
    assert_eq!(f.scope, SourceScope::ForwardProxy);
    assert_eq!(f.confidence, Confidence::Confirmed);
    assert!(f.explanation.contains("HBONE UDP tunnel requires an authenticated mesh peer"), "{}", f.explanation);
    assert!(f.alternatives.iter().any(|a| a.contains("UDP (datagram) tunnel")), "{:?}", f.alternatives);
    assert!(f.does_not_prove.iter().any(|d| d.contains("Which mesh policy")));
    assert_eq!(channel(&o).records_sent, 0);
    no_destination_blame(&o);

    // Authenticated, but a destination the endpoint does not relay to.
    let o = run(&via_hbone(&echo, udp_spec(&["x"], 300), &ep, Some(client_svid()), HboneMarker::None)).await;
    let f = finding(&o, "hbone.tunnel_refused");
    assert!(f.explanation.contains("HBONE UDP relay destination not allowed") && f.explanation.contains("403"), "{}", f.explanation);
    no_destination_blame(&o);

    // 5xx: the endpoint could not open the relay (session capacity); no leg claim.
    let o = run(&via_hbone(&full, udp_spec(&["x"], 300), &ep, Some(client_svid()), HboneMarker::None)).await;
    let f = finding(&o, "hbone.tunnel_unavailable");
    assert!(f.explanation.contains("UDP egress relay session capacity exhausted"), "{}", f.explanation);
    assert!(f.alternatives.iter().any(|a| a.contains("does not show whether anything listens")), "{:?}", f.alternatives);
    no_destination_blame(&o);
    assert!(datagrams_seen(&echo).is_empty() && datagrams_seen(&full).is_empty());
    assert!(ep.log.udp_relayed.lock().is_empty());
}

#[tokio::test]
async fn the_endpoint_ending_the_stream_mid_session_is_its_close_not_a_destination_fault() {
    init();
    let echo = streams::udp("127.0.0.1:0", UdpMode::Echo).await.unwrap();
    let ep = endpoint(required(), vec![echo.addr.to_string()], vec![], vec![(echo.addr.to_string(), UdpTunnelFault::EndAfter(1))]).await;
    let t0 = std::time::Instant::now();
    let o = run(&via_hbone(&echo, udp_spec(&["first"], 2_000), &ep, Some(client_svid()), HboneMarker::None)).await;
    let took = t0.elapsed();
    assert_eq!(counts(&o), (1, 1));
    let ch = channel(&o);
    assert_eq!(ch.closed_by, ClosedBy::Peer);
    assert!(last(&o).failure.is_none(), "END_STREAM is the endpoint's clean close: {:?}", last(&o).failure);
    let f = finding(&o, "hbone.udp_tunnel_ended");
    assert_eq!((f.confidence, f.severity, f.scope), (Confidence::Confirmed, Severity::Warning, SourceScope::ForwardProxy));
    assert!(f.explanation.contains("END_STREAM"), "{}", f.explanation);
    assert!(f.does_not_prove.iter().any(|d| d.contains("down")), "{:?}", f.does_not_prove);
    assert!(took < Duration::from_millis(1_900), "the session ended with the tunnel, not at the window: {took:?}");
    assert_eq!(tunnel_ends(&ep, 1).await, vec!["fault:end_stream"]);
}

#[tokio::test]
async fn a_reset_tunnel_is_an_abnormal_end_with_its_code() {
    init();
    let echo = streams::udp("127.0.0.1:0", UdpMode::Echo).await.unwrap();
    let opts = hbone::HboneOptions {
        server_cert_chain_pem: mesh().ztunnel.chain_with(&mesh().ca),
        server_key_pem: mesh().ztunnel.key.clone(),
        client_auth: required(),
        alpn: vec!["h2".into()],
        allowed: vec![],
        unavailable: vec![],
        udp_faults: vec![],
    };
    let ep = hbone::serve_resetting("127.0.0.1:0", opts, 1).await.unwrap();
    let o = run(&via_hbone(&echo, udp_spec(&["one"], 2_000), &ep, Some(client_svid()), HboneMarker::None)).await;
    assert_eq!(counts(&o), (1, 1), "the reply before the reset is kept: {:?}", codes(&o));
    let fl = last(&o).failure.as_ref().expect("an abnormal end is a failure");
    assert_eq!(fl.kind, FailureKind::H2StreamReset);
    assert_eq!(fl.phase, Phase::Session);
    let ch = channel(&o);
    assert_eq!((ch.closed_by, ch.reset_code.as_deref()), (ClosedBy::Abnormal, Some("CANCEL")));
    assert_eq!(o.record.outcome.transport, TransportState::Incomplete);
    let f = finding(&o, "hbone.udp_tunnel_ended");
    assert_eq!(f.severity, Severity::Error);
    assert!(f.explanation.contains("RST_STREAM CANCEL"), "{}", f.explanation);
    assert!(!codes(&o).iter().any(|c| c.starts_with("exchange.")), "the stream is the endpoint's, not the destination's: {:?}", codes(&o));
    assert_eq!(tunnel_ends(&ep, 1).await, vec!["fault:reset"]);
}

#[tokio::test]
async fn a_vanished_endpoint_connection_is_an_abnormal_end_without_an_author() {
    init();
    let echo = streams::udp("127.0.0.1:0", UdpMode::Echo).await.unwrap();
    let ep =
        endpoint(required(), vec![echo.addr.to_string()], vec![], vec![(echo.addr.to_string(), UdpTunnelFault::DropConnectionAfter(1))])
            .await;
    let o = run(&via_hbone(&echo, udp_spec(&["one"], 2_000), &ep, Some(client_svid()), HboneMarker::None)).await;
    assert_eq!(counts(&o), (1, 1), "{:?}", codes(&o));
    let ch = channel(&o);
    assert_eq!((ch.closed_by, ch.reset_code.clone()), (ClosedBy::Abnormal, None));
    assert_eq!(o.record.outcome.transport, TransportState::Incomplete);
    let f = finding(&o, "hbone.udp_tunnel_ended");
    assert_eq!(f.confidence, Confidence::Unknown, "no HTTP/2 frame names who ended it");
    assert!(f.explanation.contains("connection to the endpoint was lost"), "{}", f.explanation);
    assert!(!codes(&o).iter().any(|c| c.starts_with("exchange.") || c.starts_with("response.")), "{:?}", codes(&o));
}

#[tokio::test]
async fn a_record_cut_by_the_end_of_stream_is_discarded_and_reported() {
    init();
    let echo = streams::udp("127.0.0.1:0", UdpMode::Echo).await.unwrap();
    let ep =
        endpoint(required(), vec![echo.addr.to_string()], vec![], vec![(echo.addr.to_string(), UdpTunnelFault::TruncateAfter(1))]).await;
    let o = run(&via_hbone(&echo, udp_spec(&["whole"], 2_000), &ep, Some(client_svid()), HboneMarker::None)).await;
    assert_eq!(counts(&o), (1, 1), "only the complete record is a datagram");
    assert_eq!(previews(&o, Direction::Received), vec!["whole"]);
    let ch = channel(&o);
    assert_eq!((ch.truncated_tail_bytes, ch.closed_by), (6, ClosedBy::Abnormal));
    assert_eq!(last(&o).failure.as_ref().unwrap().kind, FailureKind::BodyIncomplete);
    assert_eq!(o.record.outcome.transport, TransportState::Incomplete);
    let f = finding(&o, "hbone.udp_record_truncated");
    assert!(f.explanation.contains("6 byte(s)"), "{}", f.explanation);
    assert!(!codes(&o).contains(&"hbone.udp_tunnel_ended".to_string()), "one finding per end: {:?}", codes(&o));
}

#[tokio::test]
async fn several_records_in_one_data_frame_and_empty_records_are_datagrams() {
    init();
    let echo = streams::udp("127.0.0.1:0", UdpMode::Echo).await.unwrap();
    let ep = endpoint(required(), vec![echo.addr.to_string()], vec![], vec![(echo.addr.to_string(), UdpTunnelFault::PackWithEmpty)]).await;
    let o = run(&via_hbone(&echo, udp_spec(&["a", "b"], 400), &ep, Some(client_svid()), HboneMarker::None)).await;
    assert_eq!(counts(&o), (2, 4), "{:?}", codes(&o));
    assert_eq!(previews(&o, Direction::Received), vec!["a", "", "b", ""]);
    // The second empty payload repeats the first: an observation, not a duplicate-delivery claim.
    assert!(codes(&o).contains(&"udp.repeated_payloads".to_string()));
}

#[tokio::test]
async fn datagrams_over_the_record_limit_are_refused_locally() {
    init();
    let silent = streams::udp("127.0.0.1:0", UdpMode::Silent).await.unwrap();
    let echo = streams::udp("127.0.0.1:0", UdpMode::Echo).await.unwrap();
    let ep = endpoint(required(), vec![silent.addr.to_string(), echo.addr.to_string()], vec![], vec![]).await;
    let hex = |n: usize| "ab".repeat(n);
    let hex_spec =
        |n: usize| UdpSpec { datagrams: vec![StreamPayload { data: hex(n), encoding: PayloadEncoding::Hex }], ..udp_spec(&[], 300) };

    // Scripted: refused before any traffic.
    let o = run(&via_hbone(&silent, hex_spec(65_536), &ep, Some(client_svid()), HboneMarker::None)).await;
    let fl = last(&o).failure.as_ref().unwrap();
    assert_eq!((fl.kind, fl.field.as_deref()), (FailureKind::RequestTooLargeLocal, Some("udp.datagrams[0]")));
    assert!(codes(&o).contains(&"local.request_too_large".to_string()), "{:?}", codes(&o));
    assert_eq!(*ep.log.connections.lock(), 0);

    // The largest record goes out intact (the endpoint's decoder saw 65,535 payload bytes).
    let o = run(&via_hbone(&silent, hex_spec(65_535), &ep, Some(client_svid()), HboneMarker::None)).await;
    assert_eq!(counts(&o).0, 1, "{:?}", codes(&o));
    assert_eq!(ep.log.udp_relayed.lock().last().map(|(_, n)| *n), Some(65_535));

    // Interactive: an oversize datagram is refused and recorded; the session goes on.
    let c = via_hbone(&echo, udp_spec(&[], 300), &ep, Some(client_svid()), HboneMarker::None);
    let h = Engine::new().open_session(c, EventCtx::none()).await;
    h.send(SessionCommand::SendBinaryHex { hex: hex(65_536) }).await.unwrap();
    h.send(SessionCommand::SendText { text: "fits".into() }).await.unwrap();
    tokio::time::sleep(Duration::from_millis(400)).await;
    h.close().await.unwrap();
    let o = h.finish().await;
    assert_eq!(counts(&o), (1, 1), "{:?}", codes(&o));
    assert_eq!(previews(&o, Direction::Received), vec!["fits"]);
    let ch = channel(&o);
    assert_eq!((ch.oversize_refused, ch.records_sent, ch.closed_by), (1, 1, ClosedBy::Client));
    let f = finding(&o, "hbone.udp_datagram_too_large");
    assert_eq!((f.scope, f.confidence), (SourceScope::LocalClient, Confidence::Confirmed));
    assert!(o.record.stream.as_ref().unwrap().messages.iter().any(|m| m.kind == "not_sent" && m.preview.contains("65536-byte")));
}

#[tokio::test]
async fn unsupported_udp_combinations_are_refused_before_traffic() {
    init();
    let echo = streams::udp("127.0.0.1:0", UdpMode::Echo).await.unwrap();
    let ep = endpoint(required(), vec![echo.addr.to_string()], vec![], vec![]).await;
    let refused = |o: &ExecutionOutput, field: &str, needle: &str| {
        let f = last(o).failure.as_ref().unwrap_or_else(|| panic!("{needle}: not refused: {:?} {:?}", codes(o), o.record.outcome));
        assert_eq!(f.kind, FailureKind::UnsupportedCombination, "{f:?}");
        assert_eq!(f.field.as_deref(), Some(field));
        assert!(f.message.contains(needle), "{}", f.message);
    };

    // (DTLS through HBONE runs inside the tunnel: tests/mesh_hbone_dtls.rs.)
    // A PROXY v2 datagram envelope would reach the destination as payload.
    let mut spec = udp_spec(&["x"], 300);
    spec.proxy_protocol = Some(DatagramEnvelopeSpec {
        command: Default::default(),
        family: Default::default(),
        source: Some("192.0.2.1:1000".into()),
        destination: Some("192.0.2.2:2000".into()),
        authentication: None,
    });
    let o = run(&via_hbone(&echo, spec, &ep, Some(client_svid()), HboneMarker::None)).await;
    refused(&o, "udp.proxy_protocol", "HBONE tunnel");

    // HTTP CONNECT and SOCKS5 proxies still carry TCP only.
    let p = proxy_profile(ProxyKind::Http, "127.0.0.1:9", None, HboneOptions::default());
    let o = run(&with_proxy(&format!("udp://{}", echo.addr), udp_spec(&["x"], 300), p, None)).await;
    refused(&o, "settings.proxy", "HTTP CONNECT and SOCKS5 tunnels carry TCP only");

    // MASQUE's QUIC connection cannot ride an HBONE tunnel.
    let mut spec = udp_spec(&["x"], 300);
    spec.masque = Some(MasqueSpec {
        proxy_url: "https://127.0.0.1:1".into(),
        uri_template: MASQUE_DEFAULT_TEMPLATE.into(),
        datagrams: Default::default(),
    });
    let o = run(&via_hbone(&echo, spec, &ep, Some(client_svid()), HboneMarker::None)).await;
    refused(&o, "settings.proxy", "MASQUE");

    // Payloads are sent verbatim: an auth profile has nowhere to go.
    let mut c = via_hbone(&echo, udp_spec(&["x"], 300), &ep, Some(client_svid()), HboneMarker::None);
    c.auth_layers.push((
        "run".into(),
        anvil_domain::auth::AuthConfig::Bearer { token: SensitiveValue::template("tok-123456"), prefix: "Bearer".into() },
    ));
    let o = run(&c).await;
    refused(&o, "auth", "verbatim");

    assert_eq!(*ep.log.connections.lock(), 0, "nothing reached the endpoint");
    assert!(datagrams_seen(&echo).is_empty());
}

#[tokio::test]
async fn an_endpoint_mtls_refusal_on_the_udp_path_is_a_tunnel_leg_failure() {
    init();
    let echo = streams::udp("127.0.0.1:0", UdpMode::Echo).await.unwrap();
    let ep = endpoint(required(), vec![echo.addr.to_string()], vec![], vec![]).await;
    let o = run(&via_hbone(&echo, udp_spec(&["x"], 300), &ep, Some(tls_profile("no SVID", None)), HboneMarker::None)).await;
    // TLS 1.3 delivers certificate_required after Anvil's side of the handshake;
    // a reset can discard it (then the lost-alert finding applies).
    let c = codes(&o);
    assert!(c.iter().any(|x| x == "hbone.client_svid_required" || x == "hbone.closed_after_certificate_request"), "{c:?}");
    assert!(matches!(last(&o).failure.as_ref().unwrap().kind, FailureKind::HboneEndpointTlsFailed | FailureKind::HboneProtocolError));
    no_destination_blame(&o);
    assert!(ep.connects().is_empty(), "no CONNECT was ever sent");
    assert!(datagrams_seen(&echo).is_empty());
}
