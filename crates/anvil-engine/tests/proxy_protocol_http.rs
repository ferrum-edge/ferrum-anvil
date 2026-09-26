//! PROXY protocol headers on HTTP-family requests (HTTP/1.1, HTTP/2 over TLS
//! and h2c, WebSocket, gRPC, gRPC-Web, SSE) through the engine. The
//! `anvil_fixtures::proxy_protocol::tcp_relay` receiver parses the header
//! independently of Anvil's encoder, then relays the connection unchanged to
//! the HTTP fixture — a load-balanced listener in front of a server. Receiver
//! and fixture logs are ground truth only; they are never fed to the
//! diagnostic engine.

use anvil_domain::Id;
use anvil_domain::diagnostics::{Confidence, DiagnosticFinding};
use anvil_domain::execution::*;
use anvil_domain::outcome::*;
use anvil_domain::proxy_protocol::*;
use anvil_domain::request::*;
use anvil_domain::settings::{HttpVersionPolicy, ProxySelection, SettingsOverrides, TimeoutOverrides};
use anvil_domain::tls::{ProxyKind, ProxyProfile, TlsMinVersion, TlsProfile};
use anvil_engine::context::MemoryAttachments;
use anvil_engine::{Engine, ExecutionContext, ExecutionOutput};
use anvil_fixtures::grpc::ECHO_PROTO;
use anvil_fixtures::http::{self as fx, Fixture};
use anvil_fixtures::proxy_protocol::{self as pp, ProxyEvent, ProxyFixture};
use anvil_fixtures::{LabPki, TlsServerOptions};
use anvil_transport::recorder::EventCtx;
use bytes::Bytes;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, OnceLock};
use tokio_util::sync::CancellationToken;

fn init() {
    anvil_transport::init();
    anvil_fixtures::init();
}

fn pki() -> &'static LabPki {
    static P: OnceLock<LabPki> = OnceLock::new();
    P.get_or_init(LabPki::generate)
}

fn localhost() -> Vec<IpAddr> {
    vec!["127.0.0.1".parse().unwrap()]
}

fn server_tls() -> TlsServerOptions {
    TlsServerOptions::new(pki().server.chain_with(&pki().ca), pki().server.key.clone())
}

/// An HTTP fixture behind a PROXY-header-requiring relay.
async fn behind_relay(tls: bool) -> (Fixture, ProxyFixture) {
    let backend = fx::serve("127.0.0.1:0", tls.then(server_tls)).await.unwrap();
    let relay = pp::tcp_relay("127.0.0.1:0", localhost(), backend.addr).await.unwrap();
    (backend, relay)
}

fn header(version: ProxyHeaderVersion, source: &str) -> ProxyHeaderSpec {
    ProxyHeaderSpec {
        version,
        command: ProxyCommand::Proxy,
        family: ProxyAddressFamily::Auto,
        source: Some(source.into()),
        destination: None,
        authority: None,
        tlvs: vec![],
        raw_hex: None,
    }
}

fn trust_profile() -> TlsProfile {
    TlsProfile {
        server_spiffe: None,
        id: Id::new(),
        workspace_id: Id::new(),
        name: "lab".into(),
        verify: true,
        use_system_roots: false,
        extra_roots_pem: vec![pki().ca.cert.clone()],
        client_identity: None,
        bindings: vec![],
        min_version: TlsMinVersion::Tls12,
        server_name_override: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

fn layer(c: &mut ExecutionContext, s: SettingsOverrides) {
    c.settings_layers.push(("run".into(), s));
}

/// A request context with fast timeouts and (for TLS URLs) the lab trust.
fn ctx(mut spec: RequestSpec, h: Option<ProxyHeaderSpec>, version: Option<HttpVersionPolicy>) -> ExecutionContext {
    spec.proxy_protocol = h;
    let tls = ["https://", "wss://", "grpcs://"].iter().any(|s| spec.url.starts_with(s));
    let mut c = ExecutionContext::standalone(spec);
    let mut s = SettingsOverrides {
        http_version: version,
        timeouts: Some(TimeoutOverrides {
            connect_ms: Some(Some(3_000)),
            tls_handshake_ms: Some(Some(3_000)),
            response_headers_ms: Some(Some(5_000)),
            total_ms: Some(Some(15_000)),
            ..Default::default()
        }),
        ..Default::default()
    };
    if tls {
        let p = trust_profile();
        s.tls_profile_id = Some(p.id);
        c.tls_profiles.push(p);
    }
    layer(&mut c, s);
    c
}

fn get(url: &str, h: Option<ProxyHeaderSpec>) -> ExecutionContext {
    ctx(RequestSpec::http("GET", url), h, None)
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

fn status(o: &ExecutionOutput) -> Option<u16> {
    o.record.response.as_ref().map(|r| r.status)
}

fn header_phase(a: &AttemptObservation) -> Option<&PhaseTiming> {
    a.phase(Phase::ProxyProtocolHeader)
}

fn conn(a: &AttemptObservation) -> &ConnectionObservation {
    a.connection.as_ref().expect("connection")
}

/// Sources of the headers the relay accepted, in order.
fn sources(relay: &ProxyFixture) -> Vec<Option<SocketAddr>> {
    relay
        .log
        .headers()
        .into_iter()
        .filter_map(|e| match e {
            ProxyEvent::Header { source, .. } => Some(source),
            _ => None,
        })
        .collect()
}

fn addr(s: &str) -> Option<SocketAddr> {
    Some(s.parse().unwrap())
}

/// The header was written on this attempt's new connection, before any TLS.
fn assert_sent_fresh(o: &ExecutionOutput, format: ProxyHeaderFormat) {
    let a = last(o);
    let p = header_phase(a).expect("proxy_protocol_header phase");
    assert_eq!(p.status, PhaseStatus::Completed, "{p:?}");
    let c = conn(a);
    assert!(!c.reused);
    let h = c.proxy_header.as_ref().expect("header evidence");
    assert_eq!(h.format, format);
    assert!(h.well_formed);
    assert_eq!(h.source_origin, Some(AddressOrigin::Configured));
    assert_eq!(h.destination_origin, Some(AddressOrigin::Socket));
    if let Some(t) = a.phase(Phase::TlsHandshake).filter(|t| t.status == PhaseStatus::Completed) {
        assert!(p.end_us.unwrap() <= t.start_us.unwrap(), "the header precedes the TLS ClientHello");
    }
}

#[tokio::test]
async fn http1_cleartext_and_over_tls_carry_the_header_before_tls() {
    init();
    let e = Engine::new();
    let (backend, relay) = behind_relay(false).await;
    let url = format!("http://{}/echo", relay.addr);
    let o = run(&e, &get(&url, Some(header(ProxyHeaderVersion::V1, "203.0.113.7:4242")))).await;
    assert_eq!(status(&o), Some(200), "{:?}", last(&o).failure);
    assert_sent_fresh(&o, ProxyHeaderFormat::V1);
    assert_eq!(
        conn(last(&o)).proxy_header.as_ref().unwrap().text.as_deref().map(|t| t.starts_with("PROXY TCP4 203.0.113.7 127.0.0.1 4242 ")),
        Some(true)
    );
    assert_eq!(sources(&relay), vec![addr("203.0.113.7:4242")]);
    assert_eq!(backend.log.count_requests(), 1);
    assert!(
        o.record.prepared.inferred.iter().any(|i| i.starts_with("PROXY protocol v1 header written once on every new connection")),
        "{:?}",
        o.record.prepared.inferred
    );
    assert!(!codes(&o).iter().any(|c| c.contains("proxy")), "{:?}", codes(&o));

    let (tls_backend, tls_relay) = behind_relay(true).await;
    let url = format!("https://127.0.0.1:{}/echo", tls_relay.addr.port());
    let o = run(
        &e,
        &ctx(
            RequestSpec::http("GET", &url),
            Some(header(ProxyHeaderVersion::V2, "198.51.100.23:40002")),
            Some(HttpVersionPolicy::Http1Only),
        ),
    )
    .await;
    assert_eq!(status(&o), Some(200), "{:?}", last(&o).failure);
    assert_sent_fresh(&o, ProxyHeaderFormat::V2);
    let tls = conn(last(&o)).tls.as_ref().unwrap();
    assert_eq!(tls.verification, TlsVerification::Verified, "TLS runs end to end with the server behind the listener");
    assert_eq!(o.record.response.as_ref().unwrap().http_version, "HTTP/1.1");
    assert_eq!(sources(&tls_relay), vec![addr("198.51.100.23:40002")]);
    assert_eq!(tls_backend.log.count_requests(), 1);
}

#[tokio::test]
async fn http2_over_tls_and_h2c_carry_the_header() {
    init();
    let e = Engine::new();
    let (_b, relay) = behind_relay(true).await;
    let url = format!("https://127.0.0.1:{}/echo", relay.addr.port());
    let o = run(
        &e,
        &ctx(RequestSpec::http("GET", &url), Some(header(ProxyHeaderVersion::V2, "203.0.113.20:2020")), Some(HttpVersionPolicy::Http2Only)),
    )
    .await;
    assert_eq!(status(&o), Some(200), "{:?}", last(&o).failure);
    assert_eq!(o.record.response.as_ref().unwrap().http_version, "HTTP/2");
    assert_eq!(conn(last(&o)).tls.as_ref().unwrap().alpn_negotiated.as_deref(), Some("h2"));
    assert_sent_fresh(&o, ProxyHeaderFormat::V2);
    assert_eq!(sources(&relay), vec![addr("203.0.113.20:2020")]);

    let (_b2, relay2) = behind_relay(false).await;
    let url = format!("http://{}/echo", relay2.addr);
    let o = run(
        &e,
        &ctx(RequestSpec::http("GET", &url), Some(header(ProxyHeaderVersion::V2, "203.0.113.21:2121")), Some(HttpVersionPolicy::H2c)),
    )
    .await;
    assert_eq!(status(&o), Some(200), "{:?}", last(&o).failure);
    assert_eq!(o.record.response.as_ref().unwrap().http_version, "HTTP/2");
    assert_sent_fresh(&o, ProxyHeaderFormat::V2);
    assert_eq!(sources(&relay2), vec![addr("203.0.113.21:2121")]);
}

#[tokio::test]
async fn pooled_connections_are_keyed_by_the_header_plan() {
    init();
    let e = Engine::new();
    let (backend, relay) = behind_relay(false).await;
    let url = format!("http://{}/echo", relay.addr);
    let a = || Some(header(ProxyHeaderVersion::V2, "203.0.113.1:1001"));
    let b = || Some(header(ProxyHeaderVersion::V2, "203.0.113.2:1002"));
    let first = run(&e, &get(&url, a())).await;
    assert_sent_fresh(&first, ProxyHeaderFormat::V2);
    // The same plan reuses the connection: the header is not sent again, and
    // the attempt records that it was sent when that connection was opened.
    let second = run(&e, &get(&url, a())).await;
    assert_eq!(status(&second), Some(200));
    let c = conn(last(&second));
    assert!(c.reused, "same plan, same pooled connection");
    assert_eq!(c.id, conn(last(&first)).id);
    let p = header_phase(last(&second)).expect("header phase on the reused attempt");
    assert_eq!(p.status, PhaseStatus::Reused);
    assert!(p.detail.as_deref().unwrap_or("").contains(&format!("sent once when connection #{} was opened", c.id)), "{p:?}");
    assert!(c.proxy_header.is_some(), "the connection's header stays in its evidence");
    assert_eq!(sources(&relay).len(), 1);
    // Another plan never shares that connection.
    let third = run(&e, &get(&url, b())).await;
    assert_eq!(status(&third), Some(200));
    assert!(!conn(last(&third)).reused);
    assert_eq!(sources(&relay), vec![addr("203.0.113.1:1001"), addr("203.0.113.2:1002")]);
    // Back to the first plan: its connection is still pooled.
    let fourth = run(&e, &get(&url, a())).await;
    assert!(conn(last(&fourth)).reused);
    assert_eq!(conn(last(&fourth)).id, conn(last(&first)).id);
    assert_eq!(sources(&relay).len(), 2);
    // No header: never a connection that was opened with one. The relay
    // requires a header, so the new connection is closed without a response.
    let none = run(&e, &get(&url, None)).await;
    assert!(status(&none).is_none());
    assert!(!conn(last(&none)).reused);
    assert!(header_phase(last(&none)).is_none());
    assert_eq!(relay.log.rejections().len(), 1, "{:?}", relay.log.rejections());
    assert_eq!(backend.log.count_requests(), 4, "the header-less request never reached the backend");
    // Diagnosis: a public close; "the listener may require a PROXY header" is only an alternative.
    let f = none.record.findings.iter().find(|f| f.alternatives.iter().any(|a| a.contains("may require a PROXY protocol header")));
    let f = f.unwrap_or_else(|| panic!("no finding offers the PROXY alternative: {:?}", codes(&none)));
    assert!(!f.explanation.contains("PROXY"), "the finding states the public close, not a PROXY cause: {}", f.explanation);
    assert!(!codes(&none).iter().any(|c| c.contains("proxy_header")), "no header was sent: {:?}", codes(&none));

    // HTTP/2 connections are multiplexed and keyed the same way.
    let (_b2, relay2) = behind_relay(false).await;
    let url = format!("http://{}/echo", relay2.addr);
    let h2 = |h| ctx(RequestSpec::http("GET", &url), h, Some(HttpVersionPolicy::H2c));
    let one = run(&e, &h2(a())).await;
    let two = run(&e, &h2(a())).await;
    assert_eq!(conn(last(&two)).id, conn(last(&one)).id);
    assert_eq!(header_phase(last(&two)).map(|p| p.status), Some(PhaseStatus::Reused));
    let other = run(&e, &h2(b())).await;
    assert_ne!(conn(last(&other)).id, conn(last(&one)).id);
    assert_eq!(sources(&relay2), vec![addr("203.0.113.1:1001"), addr("203.0.113.2:1002")]);
}

#[tokio::test]
async fn redirects_carry_the_header_only_to_the_same_listener() {
    init();
    let e = Engine::new();
    let (backend, relay) = behind_relay(false).await;
    // Same listener: the redirected request goes out with the header (here on
    // the same kept-alive connection).
    let url = format!("http://{}/redirect?to=/echo", relay.addr);
    let o = run(&e, &get(&url, Some(header(ProxyHeaderVersion::V2, "203.0.113.30:3030")))).await;
    assert_eq!(o.record.attempts.len(), 2);
    assert_eq!(status(&o), Some(200));
    for a in &o.record.attempts {
        let p = header_phase(a).expect("header phase");
        assert!(matches!(p.status, PhaseStatus::Completed | PhaseStatus::Reused), "{p:?}");
        assert!(conn(a).proxy_header.is_some());
    }
    assert!(relay.log.rejections().is_empty());
    // Another listener (the server itself, which does not expect a header):
    // the redirect is followed without the header, and the attempt says so.
    let direct = format!("http://{}/echo", backend.addr);
    let to: String = url::form_urlencoded::byte_serialize(direct.as_bytes()).collect();
    let url = format!("http://{}/redirect?to={to}", relay.addr);
    let before = sources(&relay).len();
    let o = run(&e, &get(&url, Some(header(ProxyHeaderVersion::V2, "203.0.113.31:3131")))).await;
    assert_eq!(o.record.attempts.len(), 2);
    assert_eq!(status(&o), Some(200), "the server answered a request that did not start with a PROXY header");
    let first = &o.record.attempts[0];
    assert_eq!(header_phase(first).map(|p| p.status), Some(PhaseStatus::Completed));
    let second = last(&o);
    assert!(matches!(second.reason, AttemptReason::Redirect { .. }));
    let p = header_phase(second).expect("withheld header phase");
    assert_eq!(p.status, PhaseStatus::NotApplicable);
    assert!(p.detail.as_deref().unwrap_or("").contains(&format!("configured for {} only", relay.addr)), "{p:?}");
    assert!(conn(second).proxy_header.is_none());
    assert_eq!(sources(&relay).len(), before + 1, "only the first hop carried a header");
    assert!(
        o.record.prepared.inferred.iter().any(|i| i.starts_with("PROXY header withheld on the redirect")),
        "{:?}",
        o.record.prepared.inferred
    );
}

fn echo_attachment() -> (AttachmentRef, MemoryAttachments) {
    let sha = anvil_transport::certs::sha256_hex(ECHO_PROTO.as_bytes());
    let mut m = HashMap::new();
    m.insert(sha.clone(), Bytes::from_static(ECHO_PROTO.as_bytes()));
    (
        AttachmentRef::Stored { sha256: sha, size: ECHO_PROTO.len() as u64, file_name: "echo.proto".into(), media_type: None },
        MemoryAttachments(m),
    )
}

fn grpc(url: &str, wire: GrpcWire, h: Option<ProxyHeaderSpec>) -> ExecutionContext {
    let (att, store) = echo_attachment();
    let mut s = RequestSpec::http("POST", url);
    s.protocol = Protocol::Grpc;
    s.grpc = Some(GrpcSpec {
        service: "anvil.lab.v1.Echo".into(),
        method: "Unary".into(),
        mode: GrpcMode::Unary,
        schema: GrpcSchemaSource::ProtoFiles { files: vec![att] },
        messages: vec![r#"{"message":"through the balancer"}"#.into()],
        metadata: vec![],
        deadline_ms: None,
        plaintext: false,
        wire,
    });
    let mut c = ctx(s, h, None);
    c.attachments = Arc::new(store);
    c
}

#[tokio::test]
async fn websocket_grpc_grpc_web_and_sse_carry_the_header() {
    init();
    let e = Engine::new();
    let (_b, relay) = behind_relay(false).await;
    // WebSocket (HTTP/1.1 Upgrade).
    let mut s = RequestSpec::http("GET", &format!("ws://{}/ws", relay.addr));
    s.protocol = Protocol::WebSocket;
    s.websocket = Some(WsSpec {
        bootstrap: WsBootstrap::Http1Upgrade,
        subprotocols: vec![],
        messages: vec![WsMessage::Text { text: "hello".into() }],
        expect_messages: 1,
        max_message_bytes: 1024 * 1024,
        idle_close_ms: 1_500,
    });
    let o = run(&e, &ctx(s, Some(header(ProxyHeaderVersion::V2, "203.0.113.40:4040")), None)).await;
    assert!(last(&o).failure.is_none(), "{:?}", last(&o).failure);
    assert!(o.record.stream.as_ref().unwrap().received_count >= 1);
    assert_sent_fresh(&o, ProxyHeaderFormat::V2);
    // Native gRPC (h2c) and gRPC-Web (HTTP/1.1).
    let o =
        run(&e, &grpc(&format!("grpc://{}", relay.addr), GrpcWire::Grpc, Some(header(ProxyHeaderVersion::V1, "203.0.113.41:4141")))).await;
    assert!(matches!(o.record.outcome.protocol_status, ProtocolStatus::Grpc { grpc_status: Some(0), .. }), "{:?}", o.record.outcome);
    assert_sent_fresh(&o, ProxyHeaderFormat::V1);
    let o = run(&e, &grpc(&format!("http://{}", relay.addr), GrpcWire::GrpcWeb, Some(header(ProxyHeaderVersion::V2, "203.0.113.42:4242"))))
        .await;
    assert!(matches!(o.record.outcome.protocol_status, ProtocolStatus::Grpc { grpc_status: Some(0), .. }), "{:?}", o.record.outcome);
    assert_sent_fresh(&o, ProxyHeaderFormat::V2);
    // SSE.
    let mut s = RequestSpec::http("GET", &format!("http://{}/sse?count=2&interval=10", relay.addr));
    s.protocol = Protocol::Sse;
    s.sse = Some(SseSpec { max_events: 0, idle_timeout_ms: 3_000, last_event_id: None, reconnect: false });
    let o = run(&e, &ctx(s, Some(header(ProxyHeaderVersion::V2, "203.0.113.43:4343")), None)).await;
    assert!(matches!(o.record.outcome.protocol_status, ProtocolStatus::Sse { events: 2, .. }), "{:?}", o.record.outcome.protocol_status);
    assert_sent_fresh(&o, ProxyHeaderFormat::V2);
    assert_eq!(
        sources(&relay),
        vec![addr("203.0.113.40:4040"), addr("203.0.113.41:4141"), addr("203.0.113.42:4242"), addr("203.0.113.43:4343")]
    );
    assert!(relay.log.rejections().is_empty());
}

fn proxy_profile(kind: ProxyKind, tls_profile_id: Option<Id>) -> ProxyProfile {
    ProxyProfile {
        tls_profile_id,
        hbone: None,
        id: Id::new(),
        workspace_id: Id::new(),
        name: "fwd".into(),
        kind,
        address: "127.0.0.1:9".into(),
        username: None,
        password: None,
        no_proxy: String::new(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

#[tokio::test]
async fn http3_forward_proxies_hbone_and_raw_protocols_are_refused_before_traffic() {
    init();
    let e = Engine::new();
    let (_b, relay) = behind_relay(false).await;
    let h = || Some(header(ProxyHeaderVersion::V2, "203.0.113.50:5050"));
    let url = format!("https://127.0.0.1:{}/echo", relay.addr.port());
    let mut cases: Vec<(&str, ExecutionContext)> = vec![
        ("HTTP/3 only", ctx(RequestSpec::http("GET", &url), h(), Some(HttpVersionPolicy::Http3Only))),
        ("HTTP/3 with fallback", ctx(RequestSpec::http("GET", &url), h(), Some(HttpVersionPolicy::Http3WithFallback))),
    ];
    let mut ws = RequestSpec::http("GET", &format!("wss://127.0.0.1:{}/ws", relay.addr.port()));
    ws.protocol = Protocol::WebSocket;
    ws.websocket = Some(WsSpec {
        bootstrap: WsBootstrap::Http3ExtendedConnect,
        subprotocols: vec![],
        messages: vec![],
        expect_messages: 0,
        max_message_bytes: 1024,
        idle_close_ms: 500,
    });
    cases.push(("WebSocket over HTTP/3", ctx(ws, h(), None)));
    let mut sse = RequestSpec::http("GET", &url);
    sse.protocol = Protocol::Sse;
    cases.push(("SSE with HTTP/3 fallback", ctx(sse, h(), Some(HttpVersionPolicy::Http3WithFallback))));
    for kind in [ProxyKind::Http, ProxyKind::Https, ProxyKind::Socks5, ProxyKind::Hbone] {
        let mut c = get(&format!("http://{}/echo", relay.addr), h());
        let tls = trust_profile();
        let p = proxy_profile(kind, Some(tls.id));
        c.tls_profiles.push(tls);
        layer(&mut c, SettingsOverrides { proxy_profile_id: Some(ProxySelection::Profile { id: p.id }), ..Default::default() });
        c.proxy_profiles.push(p);
        cases.push((
            match kind {
                ProxyKind::Http => "HTTP proxy",
                ProxyKind::Https => "HTTPS proxy",
                ProxyKind::Socks5 => "SOCKS5 proxy",
                ProxyKind::Hbone => "HBONE",
            },
            c,
        ));
    }
    let mut tcp = RequestSpec::http("GET", &format!("tcp://{}", relay.addr));
    tcp.protocol = Protocol::Tcp;
    cases.push(("raw TCP (uses tcp.proxy_protocol)", ctx(tcp, h(), None)));
    let mut udp = RequestSpec::http("GET", "udp://127.0.0.1:9");
    udp.protocol = Protocol::Udp;
    cases.push(("UDP (uses the datagram envelope)", ctx(udp, h(), None)));
    for (what, c) in cases {
        let o = run(&e, &c).await;
        let f = last(&o).failure.as_ref().unwrap_or_else(|| panic!("{what}: not refused"));
        assert_eq!(f.kind, FailureKind::UnsupportedCombination, "{what}: {}", f.message);
        assert_eq!(f.field.as_deref(), Some("proxy_protocol"), "{what}");
        assert_eq!(f.phase, Phase::Prepare, "{what}");
        assert_eq!(o.record.outcome.dispatch, DispatchState::NotDispatched, "{what}");
        assert!(last(&o).phases.iter().all(|p| p.phase == Phase::Prepare), "{what}: nothing was attempted");
        finding(&o, "local.unsupported_combination");
    }
    assert!(relay.log.events().is_empty(), "no refused request reached the listener");
}

#[tokio::test]
async fn a_listener_that_does_not_expect_a_header_is_an_alternative_never_a_cause() {
    init();
    let e = Engine::new();
    let may_not_expect = |o: &ExecutionOutput| {
        o.record
            .findings
            .iter()
            .filter(|f| f.alternatives.iter().any(|a| a.contains("may not expect a PROXY protocol header")))
            .map(|f| (f.code.clone(), f.confidence))
            .collect::<Vec<_>>()
    };
    // The HTTP fixture has no PROXY support: the header is the start of its
    // request line, so it answers 400 (hyper's parse-error response) and
    // closes. When that answer arrives before the client has written its
    // request, the HTTP client reports only the close (a genuine race, seen
    // live with Ferrum Edge); both public outcomes are handled.
    let plain = fx::serve("127.0.0.1:0", None).await.unwrap();
    let o = run(&e, &get(&format!("http://{}/echo", plain.addr), Some(header(ProxyHeaderVersion::V1, "203.0.113.60:6060")))).await;
    assert_sent_fresh(&o, ProxyHeaderFormat::V1);
    assert_eq!(plain.log.count_requests(), 0, "the server never saw a valid request");
    match status(&o) {
        Some(400) => {
            assert_eq!(may_not_expect(&o), vec![("http.client_error".to_string(), Confidence::Confirmed)], "{:?}", codes(&o));
            assert!(finding(&o, "http.client_error").explanation.contains("400"), "the public outcome is stated as observed");
            assert!(!codes(&o).iter().any(|c| c.contains("proxy_header")), "the listener answered: no rejection claim");
        }
        other => {
            assert_eq!(other, None);
            assert_eq!(finding(&o, "tcp.proxy_header_maybe_rejected").confidence, Confidence::Unknown);
            assert!(may_not_expect(&o).iter().any(|(c, _)| c.starts_with("exchange.")), "{:?}", codes(&o));
        }
    }
    assert!(o.record.findings.iter().all(|f| !(f.confidence == Confidence::Confirmed && f.explanation.contains("PROXY"))));
    // Without the header the same server answers normally, and no PROXY alternative appears.
    let ok = run(&e, &get(&format!("http://{}/echo", plain.addr), None)).await;
    assert_eq!(status(&ok), Some(200));
    assert!(may_not_expect(&ok).is_empty());
    // The TLS fixture reads the header as the start of the TLS handshake and
    // answers with a decode_error alert.
    let tls = fx::serve("127.0.0.1:0", Some(server_tls())).await.unwrap();
    let o =
        run(&e, &get(&format!("https://127.0.0.1:{}/echo", tls.addr.port()), Some(header(ProxyHeaderVersion::V2, "203.0.113.61:6161"))))
            .await;
    let f = last(&o).failure.as_ref().expect("the TLS handshake cannot succeed");
    assert_eq!((f.kind, f.phase, f.tls_alert.as_deref()), (FailureKind::TlsAlertReceived, Phase::TlsHandshake, Some("decode_error")));
    assert_eq!(may_not_expect(&o), vec![("client.tls.peer_alert".to_string(), Confidence::Unknown)], "{:?}", codes(&o));
    assert!(tls.log.entries().iter().all(|e| !matches!(e.event, anvil_fixtures::GroundTruth::TlsHandshakeCompleted { .. })));
}
