//! Session-protocol scenarios through the shared engine against real local
//! sockets (no mocks). Matrix IDs (PROTO-006…022) are kept in test names.
//! Fixture ground truth is used only to check that a condition was really
//! reached; it is never fed to the diagnostic engine.

use anvil_domain::assertions::{Assertion, AssertionKind, Comparison};
use anvil_domain::auth::AuthConfig;
use anvil_domain::diagnostics::{Confidence, DiagnosticFinding, Severity};
use anvil_domain::events::{ExecutionEvent, SessionCommand};
use anvil_domain::execution::*;
use anvil_domain::outcome::*;
use anvil_domain::request::*;
use anvil_domain::secret::SensitiveValue;
use anvil_domain::settings::{HttpVersionPolicy, ProxySelection, SettingsOverrides, TimeoutOverrides};
use anvil_domain::tls::{ClientIdentity, ProxyKind, ProxyProfile, TlsMinVersion, TlsProfile};
use anvil_domain::{Id, secret::REDACTED};
use anvil_engine::context::MemoryAttachments;
use anvil_engine::{Engine, ExecutionContext, ExecutionOutput, SessionError};
use anvil_fixtures::dtls::{self as fxdtls, DtlsServerOptions};
use anvil_fixtures::grpc::{ABORT_WITHOUT_STATUS, ECHO_PROTO};
use anvil_fixtures::http as fx;
use anvil_fixtures::pki::Pem;
use anvil_fixtures::streams::{self, TcpMode, UdpMode};
use anvil_fixtures::{GroundTruth, LabPki, TlsServerOptions, h3server};
use anvil_transport::recorder::{EventCtx, EventFn};
use bytes::Bytes;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
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

fn server_tls() -> TlsServerOptions {
    TlsServerOptions::new(pki().server.chain_with(&pki().ca), pki().server.key.clone())
}

fn spec(protocol: Protocol, url: &str) -> RequestSpec {
    let mut s = RequestSpec::http("GET", url);
    s.protocol = protocol;
    s
}

fn ctx(spec: RequestSpec) -> ExecutionContext {
    ExecutionContext::standalone(spec)
}

fn run_layer(c: &mut ExecutionContext, o: SettingsOverrides) {
    c.settings_layers.push(("run".into(), o));
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

fn profile(roots: &[&str], identity: Option<&Pem>, verify: bool) -> TlsProfile {
    TlsProfile {
        id: Id::new(),
        workspace_id: Id::new(),
        name: "lab".into(),
        verify,
        use_system_roots: false,
        extra_roots_pem: roots.iter().map(|s| s.to_string()).collect(),
        client_identity: identity
            .map(|p| ClientIdentity::Pem { cert_chain_pem: p.cert.clone(), private_key_pem: SensitiveValue::template(p.key.clone()) }),
        bindings: vec![],
        min_version: TlsMinVersion::Tls12,
        server_name_override: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

fn with_profile(c: &mut ExecutionContext, p: TlsProfile) {
    let id = p.id;
    c.tls_profiles.push(p);
    run_layer(c, SettingsOverrides { tls_profile_id: Some(id), ..Default::default() });
}

fn lab_trust(c: &mut ExecutionContext) {
    with_profile(c, profile(&[&pki().ca.cert], None, true));
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

fn phase(a: &AttemptObservation, p: Phase) -> Option<&PhaseTiming> {
    a.phase(p)
}

fn stream(o: &ExecutionOutput) -> &StreamTranscript {
    o.record.stream.as_ref().expect("transcript")
}

fn previews(o: &ExecutionOutput, dir: Direction, kind: &str) -> Vec<String> {
    stream(o).messages.iter().filter(|m| m.direction == dir && m.kind == kind).map(|m| m.preview.clone()).collect()
}

fn assertion(kind: AssertionKind) -> Assertion {
    Assertion { enabled: true, label: String::new(), kind }
}

fn events_sink() -> (EventCtx, Arc<Mutex<Vec<ExecutionEvent>>>) {
    let seen: Arc<Mutex<Vec<ExecutionEvent>>> = Arc::new(Mutex::new(vec![]));
    let s2 = seen.clone();
    let sink: EventFn = Arc::new(move |e| s2.lock().push(e));
    (EventCtx { execution_id: Id::new(), sink: Some(sink) }, seen)
}

// ----------------------------------------------------------------- HTTP/3

#[tokio::test]
async fn proto_006_forced_h3_success_measures_quic_not_tcp() {
    init();
    let f = h3server::serve("127.0.0.1:0", server_tls()).await.unwrap();
    let e = Engine::new();
    let mut c = ctx(RequestSpec::http("GET", &f.url("/echo")));
    lab_trust(&mut c);
    run_layer(&mut c, SettingsOverrides { http_version: Some(HttpVersionPolicy::Http3Only), ..fast() });
    let o = run(&e, &c).await;
    assert_eq!(o.record.attempts.len(), 1, "forced H3 is a single attempt");
    let a = last(&o);
    assert!(a.failure.is_none(), "{:?}", a.failure);
    let conn = a.connection.as_ref().unwrap();
    assert_eq!(conn.protocol.as_deref(), Some("h3"));
    let tls = conn.tls.as_ref().unwrap();
    assert_eq!(tls.alpn_negotiated.as_deref(), Some("h3"));
    assert_eq!(tls.verification, TlsVerification::Verified);
    assert_eq!(phase(a, Phase::QuicHandshake).unwrap().status, PhaseStatus::Completed);
    assert_eq!(phase(a, Phase::Connect).unwrap().status, PhaseStatus::NotApplicable, "no TCP handshake is claimed for QUIC");
    assert!(phase(a, Phase::TlsHandshake).is_none(), "TLS is part of the QUIC handshake, not a TCP TLS phase");
    let r = o.record.response.as_ref().unwrap();
    assert_eq!(r.http_version, "HTTP/3");
    assert_eq!(o.record.outcome.transport, TransportState::Completed);
    // Ground truth: the fixture really served this over QUIC.
    assert_eq!(f.connections(), 1);
    assert!(f.log.requests().iter().any(|(m, p)| m == "GET" && p == "/echo"));
    assert!(String::from_utf8_lossy(&o.body).contains("\"protocol\":\"h3\""));
}

#[tokio::test]
async fn proto_007_forced_h3_without_udp_listener_fails_typed_without_tcp() {
    init();
    // TCP-only HTTPS fixture: nothing listens for QUIC on this port.
    let tcp = fx::serve("127.0.0.1:0", Some(server_tls())).await.unwrap();
    let e = Engine::new();
    let mut c = ctx(RequestSpec::http("GET", &format!("https://127.0.0.1:{}/", tcp.addr.port())));
    lab_trust(&mut c);
    let mut o = fast();
    o.http_version = Some(HttpVersionPolicy::Http3Only);
    o.timeouts.as_mut().unwrap().tls_handshake_ms = Some(Some(700));
    run_layer(&mut c, o);
    let out = run(&e, &c).await;
    assert_eq!(out.record.attempts.len(), 1, "forced H3 never adds a TCP attempt");
    let f = last(&out).failure.as_ref().unwrap();
    assert_eq!(f.kind, FailureKind::QuicHandshakeTimeout);
    assert_eq!(f.phase, Phase::QuicHandshake);
    assert_eq!(out.record.outcome.transport, TransportState::Failed);
    assert!(out.record.response.is_none());
    let q = finding(&out, "client.quic.handshake_timeout");
    assert!(q.does_not_prove.iter().any(|d| d.contains("UDP failure is not TCP failure")));
    assert!(!tcp.log.saw_connection(), "no silent TCP request was made");
}

#[tokio::test]
async fn proto_008_h3_auto_fallback_records_both_attempts() {
    init();
    let tcp = fx::serve("127.0.0.1:0", Some(server_tls())).await.unwrap();
    let e = Engine::new();
    let mut c = ctx(RequestSpec::http("GET", &format!("https://127.0.0.1:{}/", tcp.addr.port())));
    lab_trust(&mut c);
    let mut o = fast();
    o.http_version = Some(HttpVersionPolicy::Http3WithFallback);
    o.timeouts.as_mut().unwrap().tls_handshake_ms = Some(Some(700));
    run_layer(&mut c, o);
    let out = run(&e, &c).await;
    assert_eq!(out.record.attempts.len(), 2);
    let h3 = &out.record.attempts[0];
    assert_eq!(h3.failure.as_ref().unwrap().kind, FailureKind::QuicHandshakeTimeout);
    let tcp_attempt = &out.record.attempts[1];
    assert_eq!(tcp_attempt.reason, AttemptReason::ProtocolFallback { from: "h3".into() });
    assert!(tcp_attempt.failure.is_none());
    let proto = tcp_attempt.connection.as_ref().unwrap().protocol.clone().unwrap();
    assert_ne!(proto, "h3");
    assert_ne!(out.record.response.as_ref().unwrap().http_version, "HTTP/3", "must not claim H3 was used");
    let fb = finding(&out, "client.h3.fallback_used");
    assert!(fb.explanation.contains(&proto), "{}", fb.explanation);
    assert!(out.record.outcome.warnings.iter().any(|w| w.code == WarningCode::ProtocolFallback));
    assert_eq!(out.record.outcome.transport, TransportState::Completed);
}

// -------------------------------------------------------------- WebSocket

fn ws_spec(messages: Vec<WsMessage>) -> WsSpec {
    WsSpec {
        bootstrap: WsBootstrap::Http1Upgrade,
        subprotocols: vec![],
        messages,
        expect_messages: 0,
        max_message_bytes: 1024 * 1024,
        idle_close_ms: 1_500,
    }
}

fn text(t: &str) -> WsMessage {
    WsMessage::Text { text: t.into() }
}

#[tokio::test]
async fn proto_009_ws_normal_close_is_not_a_fault() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    let mut s = spec(Protocol::WebSocket, &format!("ws://{}/ws?close_after=2", f.addr));
    s.websocket = Some(ws_spec(vec![text("alpha"), text("beta")]));
    s.assertions = vec![assertion(AssertionKind::MessageCount { comparison: Comparison::Equals, value: 2 })];
    let o = run(&e, &ctx(s)).await;
    match &o.record.outcome.protocol_status {
        ProtocolStatus::WebSocket { handshake_status, close_code, closed_by, .. } => {
            assert_eq!(*handshake_status, Some(101));
            assert_eq!(*close_code, Some(1000));
            assert_eq!(*closed_by, ClosedBy::Peer);
        }
        other => panic!("{other:?}"),
    }
    assert!(last(&o).failure.is_none());
    assert_eq!(o.record.outcome.transport, TransportState::Completed);
    assert_eq!(o.record.outcome.application, ApplicationState::Success);
    assert_eq!(o.record.outcome.assertions, AssertionState::Pass);
    finding(&o, "ws.closed_normally");
    assert!(!codes(&o).iter().any(|c| c.starts_with("exchange.") || c == "ws.closed_abnormally"));
    assert_eq!(previews(&o, Direction::Received, "text"), vec!["alpha", "beta"]);
    assert_eq!(stream(&o).sent_count, 2);
    let a = last(&o);
    assert_eq!(a.method, "GET");
    assert_eq!(phase(a, Phase::Session).unwrap().status, PhaseStatus::Completed);
    assert_eq!(a.connection.as_ref().unwrap().protocol.as_deref(), Some("http/1.1"));
}

#[tokio::test]
async fn proto_010_ws_abnormal_close_is_reported_as_local_1006() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    let mut s = spec(Protocol::WebSocket, &format!("ws://{}/ws?abnormal_after=1", f.addr));
    s.websocket = Some(ws_spec(vec![text("only")]));
    let o = run(&e, &ctx(s)).await;
    assert!(f.log.entries().iter().any(|e| e.event == GroundTruth::FaultApplied { fault: "ws_abnormal_drop".into() }));
    match &o.record.outcome.protocol_status {
        ProtocolStatus::WebSocket { close_code, closed_by, .. } => {
            assert_eq!(*close_code, Some(1006));
            assert_eq!(*closed_by, ClosedBy::Abnormal);
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(o.record.outcome.transport, TransportState::Incomplete);
    assert_ne!(o.record.outcome.application, ApplicationState::Success);
    let ab = finding(&o, "ws.closed_abnormally");
    assert!(ab.explanation.contains("never sent by a peer"));
    assert!(ab.does_not_prove.iter().any(|d| d.contains("peer chose to close")));
    assert!(!codes(&o).contains(&"ws.closed_normally".to_string()));
    let fk = last(&o).failure.as_ref().unwrap().kind;
    assert!(matches!(fk, FailureKind::BodyIncomplete | FailureKind::BodyReset), "{fk:?}");
    assert_eq!(previews(&o, Direction::Received, "text"), vec!["only"], "messages before the drop are kept");
}

#[tokio::test]
async fn proto_011_ws_oversize_local_limit_and_peer_limit() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    let big = "x".repeat(200);
    // (a) Anvil's own inbound ceiling.
    let mut s = spec(Protocol::WebSocket, &format!("ws://{}/ws", f.addr));
    let mut w = ws_spec(vec![text(&big)]);
    w.max_message_bytes = 64;
    s.websocket = Some(w);
    let o = run(&e, &ctx(s)).await;
    match &o.record.outcome.protocol_status {
        ProtocolStatus::WebSocket { close_code, closed_by, .. } => {
            assert_eq!(*close_code, Some(1009));
            assert_eq!(*closed_by, ClosedBy::Client);
        }
        other => panic!("{other:?}"),
    }
    let fl = last(&o).failure.as_ref().unwrap();
    assert_eq!(fl.kind, FailureKind::WsMessageTooLarge);
    assert!(fl.message.contains("local"), "{}", fl.message);
    let tb = finding(&o, "ws.closed_too_big");
    assert!(
        tb.alternatives.iter().any(|a| a.contains("local")) && tb.alternatives.iter().any(|a| a.contains("peer")),
        "source uncertainty kept"
    );
    assert!(tb.does_not_prove.iter().any(|d| d.contains("corrupt")));
    assert!(!codes(&o).iter().any(|c| c.contains("protocol_error")));
    assert_eq!(o.record.outcome.application, ApplicationState::Failure);

    // (b) The peer's ceiling: the server closes with 1009.
    let mut s = spec(Protocol::WebSocket, &format!("ws://{}/ws?max=64", f.addr));
    s.websocket = Some(ws_spec(vec![text(&big)]));
    let o = run(&e, &ctx(s)).await;
    match &o.record.outcome.protocol_status {
        ProtocolStatus::WebSocket { close_code, closed_by, .. } => {
            assert_eq!(*close_code, Some(1009));
            assert_eq!(*closed_by, ClosedBy::Peer);
        }
        other => panic!("{other:?}"),
    }
    assert!(last(&o).failure.is_none(), "a peer size-policy close is a protocol outcome, not a transport fault");
    assert_eq!(o.record.outcome.transport, TransportState::Completed);
    finding(&o, "ws.closed_too_big");
}

#[tokio::test]
async fn proto_012_ws_over_h2_extended_connect_is_its_own_bootstrap() {
    init();
    for tls in [true, false] {
        let f = fx::serve("127.0.0.1:0", if tls { Some(server_tls()) } else { None }).await.unwrap();
        let e = Engine::new();
        let scheme = if tls { "wss" } else { "ws" };
        let mut s = spec(Protocol::WebSocket, &format!("{scheme}://127.0.0.1:{}/ws?close_after=1", f.addr.port()));
        let mut w = ws_spec(vec![text("over-h2")]);
        w.bootstrap = WsBootstrap::Http2ExtendedConnect;
        w.subprotocols = vec!["anvil.v1".into()];
        s.websocket = Some(w);
        let mut c = ctx(s);
        if tls {
            lab_trust(&mut c);
        }
        let o = run(&e, &c).await;
        let a = last(&o);
        assert!(a.failure.is_none(), "{tls}: {:?}", a.failure);
        assert_eq!(a.method, "CONNECT");
        assert_eq!(a.connection.as_ref().unwrap().protocol.as_deref(), Some("h2"));
        assert!(a.phases.iter().any(|p| p.detail.as_deref().map(|d| d.contains("extended CONNECT")).unwrap_or(false)));
        match &o.record.outcome.protocol_status {
            ProtocolStatus::WebSocket { handshake_status, close_code, .. } => {
                assert_eq!(*handshake_status, Some(200), "RFC 8441 success is 200, not 101");
                assert_eq!(*close_code, Some(1000));
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(previews(&o, Direction::Received, "text"), vec!["over-h2"]);
        assert!(o.record.prepared.inferred.iter().any(|i| i.contains("subprotocol negotiated: anvil.v1")));
        // Ground truth: the server saw an extended CONNECT, not an H1 upgrade.
        assert!(f.log.requests().iter().any(|(m, p)| m == "CONNECT" && p.starts_with("/ws")), "{:?}", f.log.requests());
    }
}

fn ws_h3_ctx(url: &str, messages: Vec<WsMessage>) -> ExecutionContext {
    let mut s = spec(Protocol::WebSocket, url);
    let mut w = ws_spec(messages);
    w.bootstrap = WsBootstrap::Http3ExtendedConnect;
    s.websocket = Some(w);
    let mut c = ctx(s);
    lab_trust(&mut c);
    c
}

#[tokio::test]
async fn proto_013_ws_over_h3_extended_connect_echoes_over_quic() {
    init();
    let f = h3server::serve("127.0.0.1:0", server_tls()).await.unwrap();
    let e = Engine::new();
    let mut c = ws_h3_ctx(&format!("wss://127.0.0.1:{}/ws?close_after=1", f.addr.port()), vec![text("over-h3")]);
    if let Some(w) = c.spec.websocket.as_mut() {
        w.subprotocols = vec!["anvil.v1".into()];
    }
    let o = run(&e, &c).await;
    let a = last(&o);
    assert!(a.failure.is_none(), "{:?}", a.failure);
    assert_eq!(a.method, "CONNECT");
    let conn = a.connection.as_ref().unwrap();
    assert_eq!(conn.protocol.as_deref(), Some("h3"));
    assert_eq!(conn.tls.as_ref().unwrap().alpn_negotiated.as_deref(), Some("h3"));
    assert_eq!(phase(a, Phase::QuicHandshake).unwrap().status, PhaseStatus::Completed);
    assert_eq!(phase(a, Phase::Connect).unwrap().status, PhaseStatus::NotApplicable, "no TCP handshake is claimed for QUIC");
    assert!(a.phases.iter().any(|p| p.detail.as_deref().map(|d| d.contains("RFC 9220")).unwrap_or(false)), "{:?}", a.phases);
    assert_eq!(o.record.response.as_ref().unwrap().http_version, "HTTP/3");
    match &o.record.outcome.protocol_status {
        ProtocolStatus::WebSocket { handshake_status, close_code, closed_by, .. } => {
            assert_eq!(*handshake_status, Some(200), "RFC 9220 success is 200, not 101");
            assert_eq!(*close_code, Some(1000));
            assert_eq!(*closed_by, ClosedBy::Peer);
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(o.record.outcome.transport, TransportState::Completed);
    assert_eq!(previews(&o, Direction::Received, "text"), vec!["over-h3"]);
    assert!(o.record.prepared.inferred.iter().any(|i| i.contains("subprotocol negotiated: anvil.v1")));
    assert!(a.bytes.connection_bytes_written.unwrap_or(0) > 0 && a.bytes.connection_bytes_read.unwrap_or(0) > 0);
    // Ground truth: one QUIC connection, and the fixture saw an extended CONNECT.
    assert_eq!(f.connections(), 1);
    assert!(f.log.requests().iter().any(|(m, p)| m == "CONNECT" && p.starts_with("/ws")), "{:?}", f.log.requests());
    assert!(f.log.entries().iter().any(|e| matches!(e.event, GroundTruth::MessageReceived { .. })));
}

#[tokio::test]
async fn ws_over_h3_without_extended_connect_sends_nothing() {
    init();
    let f = h3server::serve_with("127.0.0.1:0", server_tls(), h3server::H3Options { extended_connect: false, ..Default::default() })
        .await
        .unwrap();
    let e = Engine::new();
    let o = run(&e, &ws_h3_ctx(&format!("wss://127.0.0.1:{}/ws", f.addr.port()), vec![text("never sent")])).await;
    let fl = last(&o).failure.as_ref().unwrap();
    assert_eq!(fl.kind, FailureKind::WsHandshakeRejected);
    assert_eq!(fl.phase, Phase::ProtocolHandshake);
    assert!(fl.message.contains("SETTINGS_ENABLE_CONNECT_PROTOCOL"), "{}", fl.message);
    assert_eq!(o.record.outcome.dispatch, DispatchState::NotDispatched);
    assert!(o.record.stream.is_none(), "no success-shaped session");
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(f.connections(), 1, "the QUIC connection was made");
    assert!(f.log.requests().is_empty(), "but no request was sent: {:?}", f.log.requests());
}

#[tokio::test]
async fn ws_over_h3_needs_wss_and_sends_nothing_for_ws() {
    init();
    let f = h3server::serve("127.0.0.1:0", server_tls()).await.unwrap();
    let e = Engine::new();
    let o = run(&e, &ws_h3_ctx(&format!("ws://127.0.0.1:{}/ws", f.addr.port()), vec![text("never sent")])).await;
    let fl = last(&o).failure.as_ref().unwrap();
    assert_eq!(fl.kind, FailureKind::UnsupportedCombination);
    assert_eq!(fl.phase, Phase::Prepare);
    assert!(fl.message.contains("wss://"), "{}", fl.message);
    assert_eq!(o.record.outcome.dispatch, DispatchState::NotDispatched);
    finding(&o, "local.unsupported_combination");
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(f.connections(), 0, "nothing was sent");
}

#[tokio::test]
async fn ws_over_h3_rejected_connect_keeps_http_evidence() {
    init();
    let f = h3server::serve("127.0.0.1:0", server_tls()).await.unwrap();
    let e = Engine::new();
    let o = run(&e, &ws_h3_ctx(&format!("wss://127.0.0.1:{}/nope", f.addr.port()), vec![])).await;
    let fl = last(&o).failure.as_ref().unwrap();
    assert_eq!(fl.kind, FailureKind::WsHandshakeRejected);
    assert_eq!(fl.status, Some(400));
    assert!(fl.message.contains("HTTP/3"), "{}", fl.message);
    finding(&o, "ws.handshake_rejected");
    let r = o.record.response.as_ref().unwrap();
    assert_eq!((r.status, r.http_version.as_str()), (400, "HTTP/3"));
    assert!(String::from_utf8_lossy(&o.body).contains(":protocol websocket"));
}

#[tokio::test]
async fn ws_over_h3_abnormal_end_is_reported_as_local_1006() {
    init();
    let f = h3server::serve("127.0.0.1:0", server_tls()).await.unwrap();
    let e = Engine::new();
    let o = run(&e, &ws_h3_ctx(&format!("wss://127.0.0.1:{}/ws?abnormal_after=1", f.addr.port()), vec![text("only")])).await;
    assert!(f.log.entries().iter().any(|e| e.event == GroundTruth::FaultApplied { fault: "ws_abnormal_drop".into() }));
    match &o.record.outcome.protocol_status {
        ProtocolStatus::WebSocket { close_code, closed_by, .. } => {
            assert_eq!(*close_code, Some(1006));
            assert_eq!(*closed_by, ClosedBy::Abnormal);
        }
        other => panic!("{other:?}"),
    }
    assert_ne!(o.record.outcome.application, ApplicationState::Success);
    finding(&o, "ws.closed_abnormally");
    assert_eq!(previews(&o, Direction::Received, "text"), vec!["only"], "messages before the drop are kept");
}

#[tokio::test]
async fn ws_handshake_rejection_keeps_http_evidence() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    // A plain HTTP route answers the upgrade with 404.
    let mut s = spec(Protocol::WebSocket, &format!("ws://{}/nope", f.addr));
    s.websocket = Some(ws_spec(vec![]));
    let o = run(&e, &ctx(s)).await;
    let fl = last(&o).failure.as_ref().unwrap();
    assert_eq!(fl.kind, FailureKind::WsHandshakeRejected);
    assert_eq!(fl.status, Some(404));
    finding(&o, "ws.handshake_rejected");
    assert_eq!(o.record.outcome.application, ApplicationState::Failure);
    assert_eq!(o.record.response.as_ref().unwrap().status, 404);
    assert!(String::from_utf8_lossy(&o.body).contains("no fixture route"));
    assert!(o.record.stream.is_none());
}

#[tokio::test]
async fn ws_wss_auth_is_applied_and_secrets_are_redacted_everywhere() {
    init();
    let f = fx::serve("127.0.0.1:0", Some(server_tls())).await.unwrap();
    let e = Engine::new();
    let secret = "wss-bearer-secret-7731";
    let mut s = spec(Protocol::WebSocket, &format!("wss://127.0.0.1:{}/ws?close_after=1", f.addr.port()));
    s.auth = AuthConfig::Bearer { token: SensitiveValue::template(secret), prefix: "Bearer".into() };
    s.websocket = Some(ws_spec(vec![text(&format!("my token is {secret}"))]));
    let mut c = ctx(s);
    lab_trust(&mut c);
    let (events, seen) = events_sink();
    let o = e.execute(&c, events, CancellationToken::new()).await;
    assert!(last(&o).failure.is_none(), "{:?}", last(&o).failure);
    // The server really received the credential...
    let hdrs = f.log.last_request_headers().unwrap();
    assert!(hdrs.iter().any(|(n, v)| n == "authorization" && v == &format!("Bearer {secret}")));
    // ...but no record, transcript or live event contains it.
    let json = serde_json::to_string(&o.record).unwrap();
    assert!(!json.contains(secret), "record leaks the secret");
    assert!(o.record.prepared.headers.iter().any(|h| h.name.eq_ignore_ascii_case("authorization") && h.value.contains(REDACTED)));
    assert!(previews(&o, Direction::Sent, "text")[0].contains(REDACTED));
    let live = serde_json::to_string(&*seen.lock()).unwrap();
    assert!(!live.contains(secret), "live events leak the secret");
    assert!(seen.lock().iter().any(|e| matches!(e, ExecutionEvent::Message { .. })), "transcript is emitted live");
    let tls = last(&o).connection.as_ref().unwrap().tls.as_ref().unwrap();
    assert_eq!(tls.alpn_negotiated.as_deref(), Some("http/1.1"), "H1 upgrade offers http/1.1 only");
}

#[tokio::test]
async fn ws_interactive_session_commands_and_final_record() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    let mut s = spec(Protocol::WebSocket, &format!("ws://{}/ws", f.addr));
    s.websocket = Some(ws_spec(vec![text("scripted")]));
    let (events, seen) = events_sink();
    let h = e.open_session(ctx(s), events).await;
    h.send(SessionCommand::SendText { text: "typed".into() }).await.unwrap();
    h.send(SessionCommand::SendBinaryHex { hex: "c0ffee".into() }).await.unwrap();
    h.send(SessionCommand::Ping).await.unwrap();
    assert!(matches!(h.send(SessionCommand::HalfClose).await, Err(SessionError::Unsupported(_))));
    // Interactive sessions do not idle-close: wait longer than idle_close_ms.
    tokio::time::sleep(Duration::from_millis(1_800)).await;
    assert!(!h.is_finished());
    h.close().await.unwrap();
    let o = h.finish().await;
    match &o.record.outcome.protocol_status {
        ProtocolStatus::WebSocket { close_code, closed_by, .. } => {
            assert_eq!(*close_code, Some(1000));
            assert_eq!(*closed_by, ClosedBy::Client);
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(previews(&o, Direction::Received, "text"), vec!["scripted", "typed"]);
    assert_eq!(previews(&o, Direction::Received, "binary"), vec!["c0ffee"]);
    assert!(stream(&o).messages.iter().any(|m| m.kind == "pong" && m.direction == Direction::Received));
    assert_eq!(o.record.outcome.transport, TransportState::Completed);
    let live = seen.lock().iter().filter(|e| matches!(e, ExecutionEvent::Message { .. })).count();
    assert!(live >= 6, "live transcript events: {live}");
}

// ------------------------------------------------------------------- gRPC

fn echo_attachment() -> (AttachmentRef, MemoryAttachments) {
    let sha = anvil_transport::certs::sha256_hex(ECHO_PROTO.as_bytes());
    let mut m = HashMap::new();
    m.insert(sha.clone(), Bytes::from_static(ECHO_PROTO.as_bytes()));
    (
        AttachmentRef::Stored { sha256: sha, size: ECHO_PROTO.len() as u64, file_name: "echo.proto".into(), media_type: None },
        MemoryAttachments(m),
    )
}

fn grpc_ctx(url: &str, method: &str, mode: GrpcMode, messages: &[&str], schema_proto: bool) -> ExecutionContext {
    let (att, store) = echo_attachment();
    let mut s = spec(Protocol::Grpc, url);
    s.grpc = Some(GrpcSpec {
        service: "anvil.lab.v1.Echo".into(),
        method: method.into(),
        mode,
        schema: if schema_proto { GrpcSchemaSource::ProtoFiles { files: vec![att] } } else { GrpcSchemaSource::Reflection },
        messages: messages.iter().map(|m| m.to_string()).collect(),
        metadata: vec![],
        deadline_ms: None,
        plaintext: false,
        wire: GrpcWire::Grpc,
    });
    let mut c = ctx(s);
    c.attachments = Arc::new(store);
    run_layer(&mut c, fast());
    c
}

/// A gRPC call with a wire format and an HTTP version policy (TLS URLs trust the lab root).
fn grpc_wire_ctx(
    url: &str,
    method: &str,
    mode: GrpcMode,
    messages: &[&str],
    wire: GrpcWire,
    version: HttpVersionPolicy,
) -> ExecutionContext {
    let mut c = grpc_ctx(url, method, mode, messages, true);
    c.spec.grpc.as_mut().unwrap().wire = wire;
    run_layer(&mut c, SettingsOverrides { http_version: Some(version), ..Default::default() });
    if url.starts_with("grpcs://") || url.starts_with("https://") {
        lab_trust(&mut c);
    }
    c
}

fn with_metadata(mut c: ExecutionContext, name: &str, value: &str) -> ExecutionContext {
    c.spec.grpc.as_mut().unwrap().metadata.push(KeyValue::new(name, value));
    c
}

/// QUIC evidence for an HTTP/3 call: ALPN h3, a measured QUIC handshake, no TCP phase.
fn assert_quic(o: &ExecutionOutput) {
    let a = last(o);
    let conn = a.connection.as_ref().expect("connection");
    assert_eq!(conn.protocol.as_deref(), Some("h3"));
    assert_eq!(conn.tls.as_ref().unwrap().alpn_negotiated.as_deref(), Some("h3"));
    assert_eq!(conn.tls.as_ref().unwrap().verification, TlsVerification::Verified);
    assert_eq!(phase(a, Phase::QuicHandshake).unwrap().status, PhaseStatus::Completed);
    assert_eq!(phase(a, Phase::Connect).unwrap().status, PhaseStatus::NotApplicable, "no TCP connect is claimed for QUIC");
    assert!(phase(a, Phase::TlsHandshake).is_none(), "TLS is part of the QUIC handshake");
    assert_eq!(o.record.response.as_ref().unwrap().http_version, "HTTP/3");
}

fn fixture_saw(log: &anvil_fixtures::GroundTruthLog, path: &str) -> Option<Vec<(String, String)>> {
    log.entries().into_iter().rev().find_map(|e| match e.event {
        GroundTruth::RequestReceived { path: p, headers, .. } if p == path => Some(headers),
        _ => None,
    })
}

fn header_of<'a>(h: &'a [(String, String)], name: &str) -> Option<&'a str> {
    h.iter().find(|(n, _)| n == name).map(|(_, v)| v.as_str())
}

fn grpc_status(o: &ExecutionOutput) -> (Option<u16>, Option<i32>, GrpcStatusSource) {
    match &o.record.outcome.protocol_status {
        ProtocolStatus::Grpc { http_status, grpc_status, source, .. } => (*http_status, *grpc_status, *source),
        other => panic!("not gRPC: {other:?}"),
    }
}

#[tokio::test]
async fn proto_014_grpc_http_200_with_error_status_is_an_rpc_failure() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    let mut c = grpc_ctx(&format!("grpc://{}", f.addr), "Unary", GrpcMode::Unary, &[r#"{"message":"hi","failWith":7}"#], true);
    c.spec.assertions = vec![
        assertion(AssertionKind::GrpcStatus { code: 7 }),
        assertion(AssertionKind::Status { comparison: Comparison::Equals, value: "200".into() }),
    ];
    let o = run(&e, &c).await;
    assert_eq!(grpc_status(&o), (Some(200), Some(7), GrpcStatusSource::Trailers));
    assert_eq!(o.record.outcome.transport, TransportState::Completed, "the HTTP/2 exchange itself completed");
    assert_eq!(o.record.outcome.application, ApplicationState::Failure, "HTTP 200 is not RPC success");
    assert_eq!(o.record.outcome.assertions, AssertionState::Pass);
    let g = finding(&o, "app.grpc_status");
    assert!(g.title.contains("PERMISSION_DENIED"), "{}", g.title);
    assert!(g.explanation.contains("HTTP 200 does not mean the RPC succeeded"));
    assert!(o.record.response.as_ref().unwrap().trailers_received);
}

#[tokio::test]
async fn proto_015_grpc_missing_terminal_status_is_incomplete_not_success() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    let msg = format!(r#"{{"message":"hi","failWith":{ABORT_WITHOUT_STATUS}}}"#);
    let o = run(&e, &grpc_ctx(&format!("grpc://{}", f.addr), "Unary", GrpcMode::Unary, &[&msg], true)).await;
    assert!(f.log.entries().iter().any(|e| e.event == GroundTruth::FaultApplied { fault: "grpc_abort_before_status".into() }));
    let (http, st, src) = grpc_status(&o);
    assert_eq!((http, st, src), (Some(200), None, GrpcStatusSource::Missing));
    assert_eq!(o.record.outcome.transport, TransportState::Incomplete);
    assert_eq!(o.record.outcome.application, ApplicationState::NotEvaluated, "a missing status is never success");
    finding(&o, "app.grpc_status_missing");
    assert_eq!(stream(&o).received_count, 1, "the message before the reset is kept");
}

#[tokio::test]
async fn proto_016_grpc_four_modes_with_message_boundaries() {
    init();
    let f = fx::serve("127.0.0.1:0", Some(server_tls())).await.unwrap();
    let e = Engine::new();
    let url = format!("grpcs://127.0.0.1:{}", f.addr.port());
    let tls = |mut c: ExecutionContext| {
        lab_trust(&mut c);
        c
    };
    // Unary
    let o = run(&e, &tls(grpc_ctx(&url, "Unary", GrpcMode::Unary, &[r#"{"message":"one"}"#], true))).await;
    assert_eq!(grpc_status(&o), (Some(200), Some(0), GrpcStatusSource::Trailers));
    assert_eq!(o.record.outcome.application, ApplicationState::Success);
    assert_eq!(previews(&o, Direction::Received, "grpc_message"), vec![r#"{"message":"one"}"#]);
    assert_eq!(last(&o).connection.as_ref().unwrap().tls.as_ref().unwrap().alpn_negotiated.as_deref(), Some("h2"));
    // Server streaming: five separate messages, in order.
    let mut c = tls(grpc_ctx(&url, "ServerStream", GrpcMode::ServerStreaming, &[r#"{"message":"s","count":5}"#], true));
    c.spec.assertions = vec![assertion(AssertionKind::MessageCount { comparison: Comparison::Equals, value: 5 })];
    let o = run(&e, &c).await;
    assert_eq!(grpc_status(&o).1, Some(0));
    assert_eq!(o.record.outcome.assertions, AssertionState::Pass);
    let got = previews(&o, Direction::Received, "grpc_message");
    assert_eq!(got.len(), 5);
    assert!(got[4].contains("\"index\":4"), "{got:?}");
    // Client streaming: three requests, one reply after half-close.
    let o = run(
        &e,
        &tls(grpc_ctx(
            &url,
            "ClientStream",
            GrpcMode::ClientStreaming,
            &[r#"{"message":"a"}"#, r#"{"message":"b"}"#, r#"{"message":"c"}"#],
            true,
        )),
    )
    .await;
    assert_eq!(grpc_status(&o).1, Some(0));
    assert_eq!(stream(&o).sent_count, 3);
    assert_eq!(previews(&o, Direction::Received, "grpc_message"), vec![r#"{"message":"3 messages; last=c","index":3}"#]);
    assert!(stream(&o).messages.iter().any(|m| m.kind == "half_close"));
    // Bidirectional
    let o = run(&e, &tls(grpc_ctx(&url, "Bidi", GrpcMode::Bidirectional, &[r#"{"message":"x"}"#, r#"{"message":"y"}"#], true))).await;
    assert_eq!(grpc_status(&o).1, Some(0));
    let got = previews(&o, Direction::Received, "grpc_message");
    assert_eq!(got, vec![r#"{"message":"x"}"#.to_string(), r#"{"message":"y","index":1}"#.to_string()]);
}

#[tokio::test]
async fn proto_016_grpc_deadline_is_sent_and_enforced_without_fabricating_a_status() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    let mut c =
        grpc_ctx(&format!("grpc://{}", f.addr), "ServerStream", GrpcMode::ServerStreaming, &[r#"{"message":"slow","count":1000}"#], true);
    c.spec.grpc.as_mut().unwrap().deadline_ms = Some(250);
    let o = run(&e, &c).await;
    let hdrs = f.log.last_request_headers().unwrap();
    assert!(hdrs.iter().any(|(n, v)| n == "grpc-timeout" && v == "250m"), "{hdrs:?}");
    let fl = last(&o).failure.as_ref().unwrap();
    assert_eq!(fl.kind, FailureKind::TotalTimeout);
    assert_eq!(fl.deadline_ms, Some(250));
    let (_, st, src) = grpc_status(&o);
    assert_eq!((st, src), (None, GrpcStatusSource::Missing), "no DEADLINE_EXCEEDED is invented locally");
    assert_eq!(o.record.outcome.transport, TransportState::Incomplete);
    assert!(stream(&o).received_count > 0 && stream(&o).received_count < 1000);
}

#[tokio::test]
async fn proto_016_grpc_cancellation_and_mode_mismatch() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    let c = grpc_ctx(&format!("grpc://{}", f.addr), "ServerStream", GrpcMode::ServerStreaming, &[r#"{"message":"c","count":1000}"#], true);
    let cancel = CancellationToken::new();
    let c2 = cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(150)).await;
        c2.cancel();
    });
    let o = e.execute(&c, EventCtx::none(), cancel).await;
    assert_eq!(o.record.outcome.transport, TransportState::Canceled);
    assert_eq!(last(&o).failure.as_ref().unwrap().kind, FailureKind::Canceled);
    assert_eq!(grpc_status(&o).2, GrpcStatusSource::Missing);
    // Unary alone never proves streaming: a mode mismatch fails before traffic.
    let before = f.log.count_requests();
    let o = run(&e, &grpc_ctx(&format!("grpc://{}", f.addr), "Unary", GrpcMode::ServerStreaming, &[r#"{"message":"m"}"#], true)).await;
    assert_eq!(last(&o).failure.as_ref().unwrap().kind, FailureKind::UnsupportedCombination);
    finding(&o, "local.unsupported_combination");
    assert_eq!(f.log.count_requests(), before);
}

#[tokio::test]
async fn proto_016_grpc_interactive_bidi_session() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    let c = grpc_ctx(&format!("grpc://{}", f.addr), "Bidi", GrpcMode::Bidirectional, &[r#"{"message":"first"}"#], true);
    let h = e.open_session(c, EventCtx::none()).await;
    h.send(SessionCommand::SendText { text: r#"{"message":"second"}"#.into() }).await.unwrap();
    h.send(SessionCommand::SendText { text: r#"{"nope":true}"#.into() }).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    h.send(SessionCommand::HalfClose).await.unwrap();
    let o = h.finish().await;
    assert_eq!(grpc_status(&o).1, Some(0));
    let got = previews(&o, Direction::Received, "grpc_message");
    assert_eq!(got.len(), 2, "{got:?}");
    assert!(stream(&o).messages.iter().any(|m| m.kind == "error" && m.preview.contains("not sent")), "invalid JSON is reported, not sent");
    // Unary methods are not interactive sessions.
    let c = grpc_ctx(&format!("grpc://{}", f.addr), "Unary", GrpcMode::Unary, &[r#"{"message":"x"}"#], true);
    let o = e.open_session(c, EventCtx::none()).await.finish().await;
    assert_eq!(last(&o).failure.as_ref().unwrap().kind, FailureKind::UnsupportedCombination);
}

#[tokio::test]
async fn proto_017_reflection_denied_but_local_proto_works() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    let url = format!("grpc://{}", f.addr);
    let deny = |mut c: ExecutionContext| {
        c.spec.grpc.as_mut().unwrap().metadata = vec![KeyValue::new("x-fixture-deny-reflection", "1")];
        c
    };
    // (a) Reflection refused: a schema-discovery problem, not "service unavailable".
    let o = run(&e, &deny(grpc_ctx(&url, "Unary", GrpcMode::Unary, &[r#"{"message":"r"}"#], false))).await;
    let r = finding(&o, "grpc.reflection_unavailable");
    assert!(r.explanation.contains("grpc-status 7"), "{}", r.explanation);
    assert!(r.does_not_prove.iter().any(|d| d.contains("service or method itself is unavailable")));
    assert!(!codes(&o).contains(&"app.grpc_status".to_string()), "the method's status is not invented: {:?}", codes(&o));
    assert_eq!(o.record.outcome.application, ApplicationState::NotEvaluated);
    assert_eq!(o.record.outcome.dispatch, DispatchState::NotDispatched, "the method call was not sent");
    assert!(!f.log.requests().iter().any(|(_, p)| p == "/anvil.lab.v1.Echo/Unary"));
    // (b) Same peer, same denial, local .proto: the call works.
    let o = run(&e, &deny(grpc_ctx(&url, "Unary", GrpcMode::Unary, &[r#"{"message":"local"}"#], true))).await;
    assert_eq!(grpc_status(&o).1, Some(0));
    assert_eq!(previews(&o, Direction::Received, "grpc_message"), vec![r#"{"message":"local"}"#]);
    // (c) Reflection allowed: the schema is discovered over the same connection.
    let o = run(&e, &grpc_ctx(&url, "ServerStream", GrpcMode::ServerStreaming, &[r#"{"message":"r","count":2}"#], false)).await;
    assert_eq!(grpc_status(&o).1, Some(0));
    assert!(o.record.prepared.inferred.iter().any(|i| i.contains("server reflection (grpc.reflection.v1)")));
    assert_eq!(stream(&o).received_count, 2);
}

// ------------------------------------------------------------ gRPC over HTTP/3

#[tokio::test]
async fn proto_016_grpc_over_h3_four_modes_with_quic_evidence_and_message_boundaries() {
    init();
    let f = h3server::serve("127.0.0.1:0", server_tls()).await.unwrap();
    let e = Engine::new();
    let url = format!("grpcs://127.0.0.1:{}", f.addr.port());
    let h3 = |m: &str, mode, msgs: &[&str]| grpc_wire_ctx(&url, m, mode, msgs, GrpcWire::Grpc, HttpVersionPolicy::Http3Only);
    let o = run(&e, &h3("Unary", GrpcMode::Unary, &[r#"{"message":"one"}"#])).await;
    assert_eq!(grpc_status(&o), (Some(200), Some(0), GrpcStatusSource::Trailers), "{:?}", last(&o).failure);
    assert_eq!(o.record.attempts.len(), 1, "forced HTTP/3 is a single attempt");
    assert_quic(&o);
    assert!(o.record.response.as_ref().unwrap().trailers_received, "the status came in HTTP/3 trailers");
    assert_eq!(previews(&o, Direction::Received, "grpc_message"), vec![r#"{"message":"one"}"#]);
    assert_eq!(o.record.outcome.application, ApplicationState::Success);
    assert!(o.record.prepared.inferred.iter().any(|i| i.contains("never falls back to TCP")));
    let o = run(&e, &h3("ServerStream", GrpcMode::ServerStreaming, &[r#"{"message":"s","count":4}"#])).await;
    let got = previews(&o, Direction::Received, "grpc_message");
    assert_eq!(got.len(), 4, "{got:?}");
    assert!(got[3].contains("\"index\":3"));
    let o = run(&e, &h3("ClientStream", GrpcMode::ClientStreaming, &[r#"{"message":"a"}"#, r#"{"message":"b"}"#])).await;
    assert_eq!(grpc_status(&o).1, Some(0));
    assert_eq!(previews(&o, Direction::Received, "grpc_message"), vec![r#"{"message":"2 messages; last=b","index":2}"#]);
    assert!(stream(&o).messages.iter().any(|m| m.kind == "half_close"));
    let o = run(&e, &h3("Bidi", GrpcMode::Bidirectional, &[r#"{"message":"x"}"#, r#"{"message":"y"}"#])).await;
    assert_eq!(previews(&o, Direction::Received, "grpc_message"), vec![r#"{"message":"x"}"#, r#"{"message":"y","index":1}"#]);
    assert!(last(&o).bytes.connection_bytes_written.unwrap_or(0) > 0 && last(&o).bytes.connection_bytes_read.unwrap_or(0) > 0);
    // Ground truth: every call arrived over QUIC as native gRPC.
    for m in ["Unary", "ServerStream", "ClientStream", "Bidi"] {
        let h = fixture_saw(&f.log, &format!("/anvil.lab.v1.Echo/{m}")).unwrap_or_else(|| panic!("{m} not seen"));
        assert_eq!(header_of(&h, "content-type"), Some("application/grpc"));
        assert_eq!(header_of(&h, "te"), Some("trailers"));
    }
    assert_eq!(f.connections(), 4, "one fresh QUIC connection per call");
}

#[tokio::test]
async fn proto_014_grpc_over_h3_error_status_and_reset_before_status() {
    init();
    let f = h3server::serve("127.0.0.1:0", server_tls()).await.unwrap();
    let e = Engine::new();
    let url = format!("grpcs://127.0.0.1:{}", f.addr.port());
    // An immediate error: a trailers-only answer (the status in the HTTP/3 response headers).
    let c =
        grpc_wire_ctx(&url, "Unary", GrpcMode::Unary, &[r#"{"message":"x","failWith":7}"#], GrpcWire::Grpc, HttpVersionPolicy::Http3Only);
    let o = run(&e, &c).await;
    assert!(f.log.entries().iter().any(|e| e.event == GroundTruth::FaultApplied { fault: "grpc_h3_trailers_only".into() }));
    assert_eq!(grpc_status(&o), (Some(200), Some(7), GrpcStatusSource::TrailersOnly));
    assert!(!o.record.response.as_ref().unwrap().trailers_received);
    assert_eq!(o.record.outcome.transport, TransportState::Completed, "the HTTP/3 exchange completed");
    assert_eq!(o.record.outcome.application, ApplicationState::Failure, "HTTP 200 is not RPC success");
    let g = finding(&o, "app.grpc_status");
    assert!(g.title.contains("PERMISSION_DENIED"));
    assert!(g.explanation.contains("trailers-only"), "{}", g.explanation);
    // An error after messages: the status in the HTTP/3 trailers, the messages kept.
    let c = grpc_wire_ctx(
        &url,
        "ServerStream",
        GrpcMode::ServerStreaming,
        &[r#"{"message":"m","count":2,"failWith":9}"#],
        GrpcWire::Grpc,
        HttpVersionPolicy::Http3Only,
    );
    let o = run(&e, &c).await;
    assert_eq!(grpc_status(&o), (Some(200), Some(9), GrpcStatusSource::Trailers));
    assert!(o.record.response.as_ref().unwrap().trailers_received);
    assert_eq!(previews(&o, Direction::Received, "grpc_message").len(), 2);
    assert!(finding(&o, "app.grpc_status").title.contains("FAILED_PRECONDITION"));
    // PROTO-015 over HTTP/3: one reply, then the stream is reset before any status.
    let msg = format!(r#"{{"message":"hi","failWith":{ABORT_WITHOUT_STATUS}}}"#);
    let o = run(&e, &grpc_wire_ctx(&url, "Unary", GrpcMode::Unary, &[&msg], GrpcWire::Grpc, HttpVersionPolicy::Http3Only)).await;
    assert!(f.log.entries().iter().any(|e| e.event == GroundTruth::FaultApplied { fault: "grpc_abort_before_status".into() }));
    assert_eq!(grpc_status(&o), (Some(200), None, GrpcStatusSource::Missing));
    assert_eq!(o.record.outcome.transport, TransportState::Incomplete);
    assert_ne!(o.record.outcome.application, ApplicationState::Success);
    assert_eq!(last(&o).failure.as_ref().unwrap().kind, FailureKind::BodyReset, "{:?}", last(&o).failure);
    finding(&o, "app.grpc_status_missing");
    assert_eq!(stream(&o).received_count, 1, "the message before the reset is kept");
}

#[tokio::test]
async fn grpc_over_h3_deadline_cancel_reflection_and_interactive_bidi() {
    init();
    let f = h3server::serve("127.0.0.1:0", server_tls()).await.unwrap();
    let e = Engine::new();
    let url = format!("grpcs://127.0.0.1:{}", f.addr.port());
    // Deadline: enforced locally, no DEADLINE_EXCEEDED is invented.
    let mut c = grpc_wire_ctx(
        &url,
        "ServerStream",
        GrpcMode::ServerStreaming,
        &[r#"{"message":"slow","count":1000}"#],
        GrpcWire::Grpc,
        HttpVersionPolicy::Http3Only,
    );
    c.spec.grpc.as_mut().unwrap().deadline_ms = Some(250);
    let o = run(&e, &c).await;
    let fl = last(&o).failure.as_ref().unwrap();
    assert_eq!((fl.kind, fl.deadline_ms), (FailureKind::TotalTimeout, Some(250)));
    assert_eq!(grpc_status(&o).1, None, "no DEADLINE_EXCEEDED is invented locally");
    assert_eq!(grpc_status(&o).2, GrpcStatusSource::Missing);
    assert!(stream(&o).received_count > 0 && stream(&o).received_count < 1000);
    let h = fixture_saw(&f.log, "/anvil.lab.v1.Echo/ServerStream").unwrap();
    assert_eq!(header_of(&h, "grpc-timeout"), Some("250m"));
    // Server reflection runs over the same QUIC connection as the call.
    let mut c = grpc_wire_ctx(&url, "Unary", GrpcMode::Unary, &[r#"{"message":"r"}"#], GrpcWire::Grpc, HttpVersionPolicy::Http3Only);
    c.spec.grpc.as_mut().unwrap().schema = GrpcSchemaSource::Reflection;
    let before = f.connections();
    let o = run(&e, &c).await;
    assert_eq!(grpc_status(&o).1, Some(0), "{:?}", last(&o).failure);
    assert!(o.record.prepared.inferred.iter().any(|i| i.contains("server reflection (grpc.reflection.v1)")));
    assert_eq!(f.connections(), before + 1);
    // Interactive bidirectional session over HTTP/3.
    let c = grpc_wire_ctx(&url, "Bidi", GrpcMode::Bidirectional, &[r#"{"message":"first"}"#], GrpcWire::Grpc, HttpVersionPolicy::Http3Only);
    let h = e.open_session(c, EventCtx::none()).await;
    h.send(SessionCommand::SendText { text: r#"{"message":"second"}"#.into() }).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    h.send(SessionCommand::HalfClose).await.unwrap();
    let o = h.finish().await;
    assert_eq!(grpc_status(&o).1, Some(0), "{:?}", last(&o).failure);
    assert_eq!(previews(&o, Direction::Received, "grpc_message").len(), 2);
    assert_quic(&o);
    // Cancel mid-stream: canceled, status missing.
    let c = grpc_wire_ctx(
        &url,
        "ServerStream",
        GrpcMode::ServerStreaming,
        &[r#"{"message":"c","count":1000}"#],
        GrpcWire::Grpc,
        HttpVersionPolicy::Http3Only,
    );
    let cancel = CancellationToken::new();
    let c2 = cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(150)).await;
        c2.cancel();
    });
    let o = e.execute(&c, EventCtx::none(), cancel).await;
    assert_eq!(o.record.outcome.transport, TransportState::Canceled);
    assert!(last(&o).failure.as_ref().unwrap().message.contains("H3_REQUEST_CANCELLED"));
    assert_eq!(grpc_status(&o).2, GrpcStatusSource::Missing);
}

#[tokio::test]
async fn grpc_forced_h3_never_uses_tcp_and_fallback_is_a_recorded_second_attempt() {
    init();
    // TCP-only HTTPS gRPC fixture: nothing listens for QUIC on this port.
    let tcp = fx::serve("127.0.0.1:0", Some(server_tls())).await.unwrap();
    let e = Engine::new();
    let url = format!("grpcs://127.0.0.1:{}", tcp.addr.port());
    let short = |mut c: ExecutionContext| {
        let mut t = fast();
        t.timeouts.as_mut().unwrap().tls_handshake_ms = Some(Some(700));
        run_layer(&mut c, t);
        c
    };
    let o = run(
        &e,
        &short(grpc_wire_ctx(&url, "Unary", GrpcMode::Unary, &[r#"{"message":"h3"}"#], GrpcWire::Grpc, HttpVersionPolicy::Http3Only)),
    )
    .await;
    assert_eq!(o.record.attempts.len(), 1, "forced HTTP/3 never adds a TCP attempt");
    let fl = last(&o).failure.as_ref().unwrap();
    assert_eq!((fl.kind, fl.phase), (FailureKind::QuicHandshakeTimeout, Phase::QuicHandshake));
    assert_eq!(o.record.outcome.dispatch, DispatchState::NotDispatched);
    finding(&o, "client.quic.handshake_timeout");
    assert!(!tcp.log.saw_connection(), "no silent TCP call was made");
    // With fallback: the failed HTTP/3 attempt, then the call over HTTP/2, both recorded.
    let o = run(
        &e,
        &short(grpc_wire_ctx(
            &url,
            "Unary",
            GrpcMode::Unary,
            &[r#"{"message":"fb"}"#],
            GrpcWire::Grpc,
            HttpVersionPolicy::Http3WithFallback,
        )),
    )
    .await;
    assert_eq!(o.record.attempts.len(), 2);
    assert_eq!(o.record.attempts[0].failure.as_ref().unwrap().kind, FailureKind::QuicHandshakeTimeout);
    assert_eq!(o.record.attempts[1].reason, AttemptReason::ProtocolFallback { from: "h3".into() });
    assert_eq!(o.record.attempts[1].connection.as_ref().unwrap().protocol.as_deref(), Some("h2"));
    assert_eq!(grpc_status(&o), (Some(200), Some(0), GrpcStatusSource::Trailers));
    assert_eq!(o.record.response.as_ref().unwrap().http_version, "HTTP/2", "HTTP/3 is not claimed");
    let fb = finding(&o, "client.h3.fallback_used");
    assert!(fb.explanation.contains("h2"), "{}", fb.explanation);
    assert!(o.record.outcome.warnings.iter().any(|w| w.code == WarningCode::ProtocolFallback));
    assert_eq!(previews(&o, Direction::Received, "grpc_message"), vec![r#"{"message":"fb"}"#]);
    assert_eq!(tcp.log.requests().iter().filter(|(_, p)| p == "/anvil.lab.v1.Echo/Unary").count(), 1, "called exactly once");
}

#[tokio::test]
async fn grpc_over_h3_refusals_happen_before_traffic() {
    init();
    let f = h3server::serve("127.0.0.1:0", server_tls()).await.unwrap();
    let e = Engine::new();
    // Cleartext URL: QUIC is always encrypted.
    let c = grpc_wire_ctx(
        &format!("grpc://127.0.0.1:{}", f.addr.port()),
        "Unary",
        GrpcMode::Unary,
        &["{}"],
        GrpcWire::Grpc,
        HttpVersionPolicy::Http3Only,
    );
    let o = run(&e, &c).await;
    let fl = last(&o).failure.as_ref().unwrap();
    assert_eq!((fl.kind, fl.phase), (FailureKind::UnsupportedCombination, Phase::Prepare));
    assert!(fl.message.contains("needs TLS"), "{}", fl.message);
    assert_eq!(o.record.outcome.dispatch, DispatchState::NotDispatched);
    finding(&o, "local.unsupported_combination");
    // Native gRPC never runs over HTTP/1.1.
    let c = grpc_wire_ctx(
        &format!("grpcs://127.0.0.1:{}", f.addr.port()),
        "Unary",
        GrpcMode::Unary,
        &["{}"],
        GrpcWire::Grpc,
        HttpVersionPolicy::Http1Only,
    );
    let o = run(&e, &c).await;
    assert!(last(&o).failure.as_ref().unwrap().message.contains("gRPC-Web"), "the refusal points at gRPC-Web for HTTP/1.1");
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(f.connections(), 0, "nothing was sent");
}

// -------------------------------------------------------------------- gRPC-Web

fn web_status(o: &ExecutionOutput) -> (Option<u16>, Option<i32>, GrpcStatusSource) {
    grpc_status(o)
}

#[tokio::test]
async fn grpc_web_binary_and_text_over_h1_h2_and_h3_keep_message_boundaries() {
    init();
    let plain = fx::serve("127.0.0.1:0", None).await.unwrap();
    let tls = fx::serve("127.0.0.1:0", Some(server_tls())).await.unwrap();
    let quic = h3server::serve("127.0.0.1:0", server_tls()).await.unwrap();
    let e = Engine::new();
    let cases: Vec<(String, GrpcWire, HttpVersionPolicy, &str, &anvil_fixtures::GroundTruthLog)> = vec![
        (format!("grpc://{}", plain.addr), GrpcWire::GrpcWeb, HttpVersionPolicy::Auto, "HTTP/1.1", &plain.log),
        (format!("grpc://{}", plain.addr), GrpcWire::GrpcWebText, HttpVersionPolicy::H2c, "HTTP/2", &plain.log),
        (format!("grpcs://127.0.0.1:{}", tls.addr.port()), GrpcWire::GrpcWeb, HttpVersionPolicy::Auto, "HTTP/2", &tls.log),
        (format!("grpcs://127.0.0.1:{}", tls.addr.port()), GrpcWire::GrpcWebText, HttpVersionPolicy::Http1Only, "HTTP/1.1", &tls.log),
        (format!("grpcs://127.0.0.1:{}", quic.addr.port()), GrpcWire::GrpcWeb, HttpVersionPolicy::Http3Only, "HTTP/3", &quic.log),
        (format!("grpcs://127.0.0.1:{}", quic.addr.port()), GrpcWire::GrpcWebText, HttpVersionPolicy::Http3Only, "HTTP/3", &quic.log),
    ];
    for (url, wire, version, http, log) in cases {
        let label = format!("{wire:?} {version:?} {url}");
        let text = wire == GrpcWire::GrpcWebText;
        let ct = if text { "application/grpc-web-text" } else { "application/grpc-web+proto" };
        let o = run(&e, &grpc_wire_ctx(&url, "Unary", GrpcMode::Unary, &[r#"{"message":"web"}"#], wire, version)).await;
        assert_eq!(web_status(&o), (Some(200), Some(0), GrpcStatusSource::TrailerFrame), "{label}: {:?}", last(&o).failure);
        assert_eq!(o.record.outcome.transport, TransportState::Completed, "{label}");
        assert_eq!(o.record.outcome.application, ApplicationState::Success, "{label}");
        let r = o.record.response.as_ref().unwrap();
        assert_eq!(r.http_version, http, "{label}");
        assert!(!r.trailers_received, "{label}: the status came in the body, not in HTTP trailers");
        assert_eq!(r.body.content_type.as_deref(), Some(ct), "{label}");
        assert_eq!(previews(&o, Direction::Received, "grpc_message"), vec![r#"{"message":"web"}"#], "{label}");
        let tf: Vec<String> = stream(&o).messages.iter().filter(|m| m.kind == "trailer_frame").map(|m| m.preview.clone()).collect();
        assert_eq!(tf, vec!["grpc-status: 0".to_string()], "{label}");
        assert_eq!(o.record.prepared.content_type.as_deref(), Some(ct), "{label}");
        assert!(o.record.prepared.inferred.iter().any(|i| i.contains("gRPC-Web")), "{label}");
        assert!(!codes(&o).iter().any(|c| c.starts_with("grpc_web.") || c.starts_with("app.grpc")), "{label}: {:?}", codes(&o));
        // Ground truth: the fixture received gRPC-Web, and text bodies were base64.
        let seen = fixture_saw(log, "/anvil.lab.v1.Echo/Unary").unwrap();
        assert_eq!(header_of(&seen, "content-type"), Some(ct), "{label}");
        assert_eq!(header_of(&seen, "x-grpc-web"), Some("1"), "{label}");
        assert_eq!(header_of(&seen, "accept"), Some(ct), "{label}");
        let body_bytes = log.entries().into_iter().rev().find_map(|e| match e.event {
            GroundTruth::RequestReceived { path, body_bytes, .. } if path == "/anvil.lab.v1.Echo/Unary" => Some(body_bytes),
            _ => None,
        });
        assert_eq!(body_bytes, Some(o.record.prepared.body_bytes), "{label}: the fixture received exactly the prepared body");
        if http == "HTTP/1.1" {
            assert_eq!(header_of(&seen, "content-length"), Some(o.record.prepared.body_bytes.to_string().as_str()), "{label}");
        }
        // Server streaming: each message kept separately; text bodies carry padding mid-body.
        let o = run(&e, &grpc_wire_ctx(&url, "ServerStream", GrpcMode::ServerStreaming, &[r#"{"message":"s","count":3}"#], wire, version))
            .await;
        assert_eq!(web_status(&o).1, Some(0), "{label}: {:?}", last(&o).failure);
        let got = previews(&o, Direction::Received, "grpc_message");
        assert_eq!(got, vec![r#"{"message":"s"}"#, r#"{"message":"s","index":1}"#, r#"{"message":"s","index":2}"#], "{label}");
        if text {
            let raw = String::from_utf8_lossy(&o.body).to_string();
            assert!(raw.trim_end_matches('=').contains('='), "{label}: the fixture pads each frame separately: {raw}");
        }
    }
}

#[tokio::test]
async fn grpc_web_error_status_trailers_only_and_http_trailers_are_distinguished() {
    init();
    let f = fx::serve("127.0.0.1:0", Some(server_tls())).await.unwrap();
    let e = Engine::new();
    let url = format!("grpcs://127.0.0.1:{}", f.addr.port());
    let web = |msg: &str| grpc_wire_ctx(&url, "Unary", GrpcMode::Unary, &[msg], GrpcWire::GrpcWeb, HttpVersionPolicy::Http2Only);
    // Error status in the trailer frame: an RPC failure on a completed exchange.
    let o = run(&e, &web(r#"{"message":"x","failWith":5}"#)).await;
    assert_eq!(web_status(&o), (Some(200), Some(5), GrpcStatusSource::TrailerFrame));
    assert_eq!(o.record.outcome.transport, TransportState::Completed);
    assert_eq!(o.record.outcome.application, ApplicationState::Failure);
    let g = finding(&o, "app.grpc_status");
    assert!(g.title.contains("NOT_FOUND"), "{}", g.title);
    assert!(g.evidence.iter().any(|v| v.key == "status.source" && v.value == "TrailerFrame"));
    // Trailers-only: the status is in the response headers, the body is empty.
    let o = run(&e, &with_metadata(web(r#"{"message":"x","failWith":7}"#), "x-fixture-grpc-web", "trailers-only")).await;
    assert_eq!(web_status(&o), (Some(200), Some(7), GrpcStatusSource::TrailersOnly));
    assert!(!codes(&o).contains(&"grpc_web.no_trailer_frame".to_string()), "trailers-only is complete: {:?}", codes(&o));
    finding(&o, "app.grpc_status");
    // Status only in HTTP trailers: recorded, with a warning that gRPC-Web clients cannot read it.
    let o = run(&e, &with_metadata(web(r#"{"message":"y"}"#), "x-fixture-grpc-web", "http-trailers")).await;
    assert_eq!(web_status(&o), (Some(200), Some(0), GrpcStatusSource::Trailers));
    let w = finding(&o, "grpc_web.no_trailer_frame");
    assert_eq!(w.severity, Severity::Warning);
    assert!(w.explanation.contains("HTTP trailers") && w.explanation.contains("cannot read"), "{}", w.explanation);
    assert!(o.record.prepared.inferred.iter().any(|i| i.contains("not in a gRPC-Web trailer frame")));
}

#[tokio::test]
async fn grpc_web_without_a_trailer_frame_is_incomplete_never_success() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    let url = format!("grpc://{}", f.addr);
    for wire in [GrpcWire::GrpcWeb, GrpcWire::GrpcWebText] {
        let c = with_metadata(
            grpc_wire_ctx(
                &url,
                "ServerStream",
                GrpcMode::ServerStreaming,
                &[r#"{"message":"m","count":2}"#],
                wire,
                HttpVersionPolicy::Auto,
            ),
            "x-fixture-grpc-web",
            "no-trailer-frame",
        );
        let o = run(&e, &c).await;
        assert!(f.log.entries().iter().any(|e| e.event == GroundTruth::FaultApplied { fault: "grpc_web_no_trailer_frame".into() }));
        assert_eq!(web_status(&o), (Some(200), None, GrpcStatusSource::Missing), "{wire:?}");
        assert_eq!(o.record.outcome.transport, TransportState::Incomplete, "{wire:?}");
        assert_eq!(o.record.outcome.application, ApplicationState::NotEvaluated, "{wire:?}: a missing status is never success");
        assert_eq!(previews(&o, Direction::Received, "grpc_message").len(), 2, "the messages are kept");
        finding(&o, "app.grpc_status_missing");
        let n = finding(&o, "grpc_web.no_trailer_frame");
        assert_eq!(n.severity, Severity::Error);
        assert!(n.explanation.contains("0x80") && n.explanation.contains("not a success"), "{}", n.explanation);
        assert!(n.does_not_prove.iter().any(|d| d.contains("gateway")), "no gateway translation claim either way");
        assert!(n.confidence == Confidence::Confirmed);
    }
    // A reset before the status (no clean end) is a transport failure, not a missing frame.
    let msg = format!(r#"{{"message":"hi","failWith":{ABORT_WITHOUT_STATUS}}}"#);
    let o = run(&e, &grpc_wire_ctx(&url, "Unary", GrpcMode::Unary, &[&msg], GrpcWire::GrpcWeb, HttpVersionPolicy::H2c)).await;
    assert_eq!(web_status(&o), (Some(200), None, GrpcStatusSource::Missing));
    assert!(last(&o).failure.is_some());
    assert_eq!(o.record.outcome.transport, TransportState::Incomplete);
    assert!(!codes(&o).contains(&"grpc_web.no_trailer_frame".to_string()), "{:?}", codes(&o));
    finding(&o, "app.grpc_status_missing");
}

#[tokio::test]
async fn grpc_web_appended_trailer_frame_is_invalid_framing_not_success() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    for wire in [GrpcWire::GrpcWeb, GrpcWire::GrpcWebText] {
        let c = with_metadata(
            grpc_wire_ctx(&format!("grpc://{}", f.addr), "Unary", GrpcMode::Unary, &[r#"{"message":"m"}"#], wire, HttpVersionPolicy::Auto),
            "x-fixture-grpc-web",
            "extra-trailer-frame",
        );
        let o = run(&e, &c).await;
        assert!(f.log.entries().iter().any(|e| e.event == GroundTruth::FaultApplied { fault: "grpc_web_extra_trailer_frame".into() }));
        // The first trailer frame ends the call per gRPC-Web; the extra frame makes the response malformed.
        assert_eq!(web_status(&o), (Some(200), Some(0), GrpcStatusSource::TrailerFrame), "{wire:?}");
        assert_eq!(o.record.response.as_ref().unwrap().body.completeness, BodyCompleteness::Complete, "the HTTP body itself completed");
        assert_eq!(o.record.outcome.transport, TransportState::Incomplete, "{wire:?}");
        let fl = last(&o).failure.as_ref().unwrap();
        assert_eq!(fl.kind, FailureKind::HttpProtocolError);
        let g = finding(&o, "grpc.framing_invalid");
        assert!(g.title.contains("gRPC-Web"), "{}", g.title);
        assert!(
            g.explanation.contains("second trailer frame (grpc-status 2)") && g.explanation.contains("not a complete success"),
            "{}",
            g.explanation
        );
        assert!(g.does_not_prove.iter().any(|d| d.contains("Which hop")));
        assert!(!codes(&o).contains(&"response.body_incomplete".to_string()), "the HTTP body did finish: {:?}", codes(&o));
        let frames: Vec<String> = stream(&o).messages.iter().filter(|m| m.kind == "trailer_frame").map(|m| m.preview.clone()).collect();
        assert_eq!(frames, vec!["grpc-status: 0".to_string(), "grpc-status: 2".to_string()], "both frames are kept as evidence");
    }
}

#[tokio::test]
async fn grpc_web_streaming_request_modes_and_reflection_are_refused_before_traffic() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    let url = format!("grpc://{}", f.addr);
    for (method, mode) in [("ClientStream", GrpcMode::ClientStreaming), ("Bidi", GrpcMode::Bidirectional)] {
        let o = run(&e, &grpc_wire_ctx(&url, method, mode, &[r#"{"message":"a"}"#], GrpcWire::GrpcWeb, HttpVersionPolicy::Auto)).await;
        let fl = last(&o).failure.as_ref().unwrap();
        assert_eq!((fl.kind, fl.phase), (FailureKind::UnsupportedCombination, Phase::Prepare));
        assert_eq!(fl.field.as_deref(), Some("grpc.wire"));
        assert!(fl.message.contains("unary and server-streaming"), "{}", fl.message);
        assert_eq!(o.record.outcome.dispatch, DispatchState::NotDispatched);
        // Interactive sessions are refused the same way.
        let c = grpc_wire_ctx(&url, method, mode, &[], GrpcWire::GrpcWebText, HttpVersionPolicy::Auto);
        let o = e.open_session(c, EventCtx::none()).await.finish().await;
        assert_eq!(last(&o).failure.as_ref().unwrap().field.as_deref(), Some("grpc.wire"));
    }
    let mut c = grpc_wire_ctx(&url, "Unary", GrpcMode::Unary, &["{}"], GrpcWire::GrpcWeb, HttpVersionPolicy::Auto);
    c.spec.grpc.as_mut().unwrap().schema = GrpcSchemaSource::Reflection;
    let o = run(&e, &c).await;
    assert_eq!(last(&o).failure.as_ref().unwrap().field.as_deref(), Some("grpc.schema"));
    assert!(!f.log.saw_connection(), "nothing was sent");
}

// -------------------------------------------------------------------- SSE

#[tokio::test]
async fn proto_018_sse_cancel_is_expected_and_keeps_bounded_history() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    let mut s = spec(Protocol::Sse, &format!("http://{}/sse?count=500&interval=20", f.addr));
    s.sse = Some(SseSpec { max_events: 0, idle_timeout_ms: 5_000, last_event_id: Some("41".into()), reconnect: false });
    let cancel = CancellationToken::new();
    let c2 = cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(250)).await;
        c2.cancel();
    });
    let o = e.execute(&ctx(s), EventCtx::none(), cancel).await;
    assert_eq!(o.record.outcome.transport, TransportState::Canceled);
    let n = match &o.record.outcome.protocol_status {
        ProtocolStatus::Sse { http_status, events, closed_by } => {
            assert_eq!(*http_status, 200);
            assert_eq!(*closed_by, ClosedBy::Client);
            *events
        }
        other => panic!("{other:?}"),
    };
    assert!(n >= 3, "events before cancel are kept: {n}");
    finding(&o, "sse.canceled");
    assert!(!codes(&o).iter().any(|c| c.contains("timeout")), "a cancel is not a backend timeout: {:?}", codes(&o));
    let ev = &stream(&o).messages[0];
    assert_eq!((ev.event_id.as_deref(), ev.event_type.as_deref()), (Some("0"), Some("tick")));
    assert_eq!(ev.preview, r#"{"n":0}"#);
    assert!(stream(&o).messages.len() <= 2_000);
    let hdrs = f.log.last_request_headers().unwrap();
    assert!(hdrs.iter().any(|(n, v)| n == "last-event-id" && v == "41"));
    assert!(hdrs.iter().any(|(n, v)| n == "accept" && v == "text/event-stream"));
}

#[tokio::test]
async fn sse_max_events_is_a_planned_client_stop() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    let mut s = spec(Protocol::Sse, &format!("http://{}/sse?count=10&interval=10", f.addr));
    s.sse = Some(SseSpec { max_events: 3, idle_timeout_ms: 5_000, last_event_id: None, reconnect: false });
    s.assertions = vec![assertion(AssertionKind::MessageCount { comparison: Comparison::Equals, value: 3 })];
    let o = run(&e, &ctx(s)).await;
    assert_eq!(o.record.outcome.transport, TransportState::Completed);
    assert_eq!(o.record.outcome.assertions, AssertionState::Pass);
    assert!(matches!(o.record.outcome.protocol_status, ProtocolStatus::Sse { events: 3, closed_by: ClosedBy::Client, .. }));
    // A stream the server ends by itself is a peer close.
    let mut s = spec(Protocol::Sse, &format!("http://{}/sse?count=2&interval=5", f.addr));
    s.sse = Some(SseSpec { max_events: 0, idle_timeout_ms: 5_000, last_event_id: None, reconnect: false });
    let o = run(&e, &ctx(s)).await;
    assert!(matches!(o.record.outcome.protocol_status, ProtocolStatus::Sse { events: 2, closed_by: ClosedBy::Peer, .. }));
    assert_eq!(o.record.outcome.application, ApplicationState::Success);
}

// -------------------------------------------------------------------- TCP

#[tokio::test]
async fn proto_019_tcp_half_close_keeps_the_reply() {
    init();
    let f = streams::tcp("127.0.0.1:0", TcpMode::ReplyAfterHalfClose, None).await.unwrap();
    let e = Engine::new();
    let mut s = spec(Protocol::Tcp, &format!("tcp://{}", f.addr));
    s.tcp = Some(TcpSpec {
        tls: false,
        framing: TcpFraming::None,
        payloads: vec![StreamPayload { data: "hello".into(), encoding: PayloadEncoding::Text }],
        half_close_after_send: true,
        read_idle_ms: 2_000,
        max_read_bytes: 4096,
        expect_frames: 0,
    });
    let o = run(&e, &ctx(s)).await;
    match &o.record.outcome.protocol_status {
        ProtocolStatus::Tcp { bytes_sent, bytes_received, half_closed, closed_by } => {
            assert_eq!(*bytes_sent, 5);
            assert!(*bytes_received > 0);
            assert!(*half_closed);
            assert_eq!(*closed_by, ClosedBy::Peer);
        }
        other => panic!("{other:?}"),
    }
    assert!(previews(&o, Direction::Received, "bytes").concat().contains("received 5 bytes after half-close"));
    finding(&o, "tcp.reply_after_half_close");
    assert_eq!(o.record.outcome.transport, TransportState::Completed);
    assert_eq!(last(&o).dispatch, DispatchState::Sent);
}

#[tokio::test]
async fn tcp_framing_presets_hex_payloads_and_tls_with_client_identity() {
    init();
    // Newline framing over TLS with a required client certificate.
    let mut opts = server_tls();
    opts.client_auth = anvil_fixtures::ClientAuth::Required { ca_pem: pki().client_ca.cert.clone() };
    let f = streams::tcp("127.0.0.1:0", TcpMode::Echo, Some(opts)).await.unwrap();
    let e = Engine::new();
    let mut s = spec(Protocol::Tcp, &format!("tls://127.0.0.1:{}", f.addr.port()));
    s.tcp = Some(TcpSpec {
        tls: true,
        framing: TcpFraming::NewlineDelimited,
        payloads: vec![
            StreamPayload { data: "first".into(), encoding: PayloadEncoding::Text },
            StreamPayload { data: "7365636f6e64".into(), encoding: PayloadEncoding::Hex },
        ],
        half_close_after_send: false,
        read_idle_ms: 3_000,
        max_read_bytes: 4096,
        expect_frames: 2,
    });
    let mut c = ctx(s);
    with_profile(&mut c, profile(&[&pki().ca.cert], Some(&pki().client_a), true));
    let o = run(&e, &c).await;
    assert!(last(&o).failure.is_none(), "{:?}", last(&o).failure);
    assert_eq!(previews(&o, Direction::Received, "frame"), vec!["first", "second"]);
    assert!(
        matches!(o.record.outcome.protocol_status, ProtocolStatus::Tcp { closed_by: ClosedBy::Client, .. }),
        "stopped at expect_frames"
    );
    let tls = last(&o).connection.as_ref().unwrap().tls.as_ref().unwrap();
    assert_eq!(tls.verification, TlsVerification::Verified);
    assert_eq!(tls.client_certificate_requested, Some(true));
    assert!(tls.client_certificate_presented.as_ref().unwrap().subject.contains("anvil-client-a"));
    // Length-prefixed framing that cannot represent a payload fails locally.
    let mut s = spec(Protocol::Tcp, &format!("tcp://{}", f.addr));
    s.tcp = Some(TcpSpec {
        tls: false,
        framing: TcpFraming::LengthPrefixedU16,
        payloads: vec![StreamPayload { data: "a".repeat(70_000), encoding: PayloadEncoding::Text }],
        half_close_after_send: false,
        read_idle_ms: 500,
        max_read_bytes: 4096,
        expect_frames: 0,
    });
    let o = run(&e, &ctx(s)).await;
    assert_eq!(last(&o).failure.as_ref().unwrap().kind, FailureKind::BodySerialization);
    assert_eq!(o.record.outcome.dispatch, DispatchState::NotDispatched);
}

#[tokio::test]
async fn tcp_interactive_session_and_auth_is_rejected_before_traffic() {
    init();
    let f = streams::tcp("127.0.0.1:0", TcpMode::Echo, None).await.unwrap();
    let e = Engine::new();
    let mut s = spec(Protocol::Tcp, &format!("tcp://{}", f.addr));
    s.tcp = Some(TcpSpec {
        tls: false,
        framing: TcpFraming::NewlineDelimited,
        payloads: vec![],
        half_close_after_send: false,
        read_idle_ms: 200,
        max_read_bytes: 4096,
        expect_frames: 0,
    });
    let h = e.open_session(ctx(s.clone()), EventCtx::none()).await;
    h.send(SessionCommand::SendText { text: "ping-1".into() }).await.unwrap();
    tokio::time::sleep(Duration::from_millis(400)).await; // longer than read_idle_ms: interactive keeps going
    h.send(SessionCommand::SendText { text: "ping-2".into() }).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    h.close().await.unwrap();
    let o = h.finish().await;
    assert_eq!(previews(&o, Direction::Received, "frame"), vec!["ping-1", "ping-2"]);
    // Auth cannot be applied to raw bytes: refused before any connection.
    let g = streams::tcp("127.0.0.1:0", TcpMode::Echo, None).await.unwrap();
    let mut s2 = spec(Protocol::Tcp, &format!("tcp://{}", g.addr));
    s2.auth = AuthConfig::Bearer { token: SensitiveValue::template("tok-123456"), prefix: "Bearer".into() };
    let o = run(&e, &ctx(s2)).await;
    assert_eq!(last(&o).failure.as_ref().unwrap().kind, FailureKind::UnsupportedCombination);
    assert!(!g.log.saw_connection());
}

// -------------------------------------------------------------------- UDP

fn udp_spec(datagrams: &[&str], window_ms: u64) -> UdpSpec {
    UdpSpec {
        dtls: false,
        datagrams: datagrams.iter().map(|d| StreamPayload { data: d.to_string(), encoding: PayloadEncoding::Text }).collect(),
        response_window_ms: window_ms,
        max_datagrams: 100,
        masque: None,
    }
}

#[tokio::test]
async fn proto_020_udp_silence_is_only_no_response_observed() {
    init();
    let f = streams::udp("127.0.0.1:0", UdpMode::Silent).await.unwrap();
    let e = Engine::new();
    let mut s = spec(Protocol::Udp, &format!("udp://{}", f.addr));
    s.udp = Some(udp_spec(&["are you there?"], 300));
    let o = run(&e, &ctx(s)).await;
    // Independent ground truth: the fixture did receive it — Anvil must not claim either way.
    assert!(f.log.entries().iter().any(|e| matches!(e.event, GroundTruth::DatagramReceived { .. })));
    assert!(matches!(
        o.record.outcome.protocol_status,
        ProtocolStatus::Udp { datagrams_sent: 1, datagrams_received: 0, window_ms: 300, masque: None }
    ));
    let n = finding(&o, "udp.no_response");
    assert!(n.does_not_prove.iter().any(|d| d.contains("delivered")));
    assert!(n.does_not_prove.iter().any(|d| d.contains("down")));
    assert_eq!(last(&o).dispatch, DispatchState::MayHaveBeenSent);
    assert_eq!(o.record.outcome.transport, TransportState::Completed);
    assert_ne!(o.record.outcome.application, ApplicationState::Success);
    assert_eq!(phase(last(&o), Phase::Connect).unwrap().status, PhaseStatus::NotApplicable);
}

#[tokio::test]
async fn proto_021_udp_loss_and_repeats_are_counted_not_explained() {
    init();
    let e = Engine::new();
    let lossy = streams::udp("127.0.0.1:0", UdpMode::DropEveryOther).await.unwrap();
    let mut s = spec(Protocol::Udp, &format!("udp://{}", lossy.addr));
    s.udp = Some(udp_spec(&["d0", "d1", "d2", "d3"], 300));
    let o = run(&e, &ctx(s)).await;
    assert!(matches!(o.record.outcome.protocol_status, ProtocolStatus::Udp { datagrams_sent: 4, datagrams_received: 2, .. }));
    let p = finding(&o, "udp.partial_responses");
    assert!(p.explanation.contains("Sent is not delivered"));
    assert_eq!(previews(&o, Direction::Received, "datagram"), vec!["d0", "d2"], "per-datagram boundaries");
    let dup = streams::udp("127.0.0.1:0", UdpMode::Duplicate).await.unwrap();
    let mut s = spec(Protocol::Udp, &format!("udp://{}", dup.addr));
    s.udp = Some(udp_spec(&["u0", "u1"], 300));
    let o = run(&e, &ctx(s)).await;
    assert!(matches!(o.record.outcome.protocol_status, ProtocolStatus::Udp { datagrams_sent: 2, datagrams_received: 4, .. }));
    let r = finding(&o, "udp.repeated_payloads");
    assert!(r.explanation.contains("not as proof of duplicate delivery"));
    assert!(r.alternatives.len() >= 2);
    assert!(!codes(&o).contains(&"udp.partial_responses".to_string()));
}

#[tokio::test]
async fn udp_with_a_proxy_fails_before_traffic_and_interactive_udp_works() {
    init();
    let f = streams::udp("127.0.0.1:0", UdpMode::Echo).await.unwrap();
    let e = Engine::new();
    let mut s = spec(Protocol::Udp, &format!("udp://{}", f.addr));
    s.udp = Some(udp_spec(&["x"], 200));
    let mut c = ctx(s.clone());
    let pid = Id::new();
    c.proxy_profiles.push(ProxyProfile {
        id: pid,
        workspace_id: Id::new(),
        name: "corp".into(),
        kind: ProxyKind::Http,
        address: "127.0.0.1:9".into(),
        username: None,
        password: None,
        no_proxy: String::new(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    });
    run_layer(&mut c, SettingsOverrides { proxy_profile_id: Some(ProxySelection::Profile { id: pid }), ..Default::default() });
    let o = run(&e, &c).await;
    assert_eq!(last(&o).failure.as_ref().unwrap().kind, FailureKind::UnsupportedCombination);
    assert!(f.log.entries().is_empty(), "nothing was sent");
    // Interactive UDP: datagrams from commands, replies recorded until Close.
    let h = e.open_session(ctx(s), EventCtx::none()).await;
    h.send(SessionCommand::SendText { text: "live".into() }).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    h.close().await.unwrap();
    let o = h.finish().await;
    assert_eq!(previews(&o, Direction::Received, "datagram"), vec!["x", "live"]);
}

// ------------------------------------------------------------------- DTLS

async fn dtls_fixture(client_ca: bool) -> fxdtls::DtlsFixture {
    fxdtls::serve(
        "127.0.0.1:0",
        DtlsServerOptions {
            cert_pem: pki().server.cert.clone(),
            key_pem: pki().server.key.clone(),
            client_ca_pem: client_ca.then(|| pki().client_ca.cert.clone()),
        },
    )
    .await
    .unwrap()
}

fn dtls_ctx(url: &str, p: TlsProfile) -> ExecutionContext {
    let mut s = spec(Protocol::Udp, url);
    s.udp = Some(UdpSpec {
        dtls: true,
        datagrams: vec![StreamPayload { data: "secure hello".into(), encoding: PayloadEncoding::Text }],
        response_window_ms: 500,
        max_datagrams: 10,
        masque: None,
    });
    let mut c = ctx(s);
    with_profile(&mut c, p);
    run_layer(&mut c, fast());
    c
}

#[tokio::test]
async fn proto_022_dtls_handshake_with_verified_peer() {
    init();
    let f = dtls_fixture(false).await;
    let e = Engine::new();
    let o = run(&e, &dtls_ctx(&f.url(), profile(&[&pki().ca.cert], None, true))).await;
    let a = last(&o);
    assert!(a.failure.is_none(), "{:?}", a.failure);
    assert_eq!(a.method, "DTLS");
    assert_eq!(phase(a, Phase::DtlsHandshake).unwrap().status, PhaseStatus::Completed);
    assert!(phase(a, Phase::TlsHandshake).is_none(), "the TLS adapter was not used");
    let tls = a.connection.as_ref().unwrap().tls.as_ref().unwrap();
    assert_eq!(tls.version.as_deref(), Some("DTLSv1_2"));
    assert_eq!(tls.verification, TlsVerification::Verified);
    assert!(tls.peer_certificates[0].subject.contains("anvil-lab-server"));
    assert_eq!(tls.client_certificate_requested, Some(false));
    assert_eq!(previews(&o, Direction::Received, "datagram"), vec!["secure hello"]);
    assert!(matches!(o.record.outcome.protocol_status, ProtocolStatus::Udp { datagrams_sent: 1, datagrams_received: 1, .. }));
    assert_eq!(f.completed_handshakes(), vec![None]);
}

#[tokio::test]
async fn proto_022_dtls_wrong_root_is_a_typed_client_side_verification_failure() {
    init();
    let f = dtls_fixture(false).await;
    let e = Engine::new();
    let o = run(&e, &dtls_ctx(&f.url(), profile(&[&pki().rogue_ca.cert], None, true))).await;
    let fl = last(&o).failure.as_ref().unwrap();
    assert_eq!(fl.kind, FailureKind::TlsUntrustedIssuer);
    assert_eq!(fl.phase, Phase::DtlsHandshake);
    let tls = last(&o).connection.as_ref().unwrap().tls.as_ref().unwrap();
    assert!(matches!(tls.verification, TlsVerification::Failed { problem: FailureKind::TlsUntrustedIssuer, .. }));
    assert!(!tls.peer_certificates.is_empty(), "the presented certificate is kept as evidence");
    assert_eq!(o.record.outcome.dispatch, DispatchState::NotDispatched);
    assert!(o.record.stream.is_none());
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(f.completed_handshakes().is_empty());
    assert!(!f.log.entries().iter().any(|e| matches!(e.event, GroundTruth::DatagramReceived { .. })), "no application data left");
    // An explicit, scoped bypass keeps encryption and records what strict verification would say.
    let o = run(&e, &dtls_ctx(&f.url(), profile(&[&pki().rogue_ca.cert], None, false))).await;
    assert!(last(&o).failure.is_none());
    let tls = last(&o).connection.as_ref().unwrap().tls.as_ref().unwrap();
    assert_eq!(tls.verification, TlsVerification::Bypassed { would_have_failed: Some(FailureKind::TlsUntrustedIssuer) });
    finding(&o, "client.tls.verification_bypassed");
}

#[tokio::test]
async fn proto_022_dtls_mutual_tls_positive_and_negative() {
    init();
    let f = dtls_fixture(true).await;
    let e = Engine::new();
    // Positive: the configured identity chains to the server's client CA.
    let o = run(&e, &dtls_ctx(&f.url(), profile(&[&pki().ca.cert], Some(&pki().client_a), true))).await;
    let a = last(&o);
    assert!(a.failure.is_none(), "{:?}", a.failure);
    let tls = a.connection.as_ref().unwrap().tls.as_ref().unwrap();
    assert_eq!(tls.client_certificate_requested, Some(true));
    assert!(tls.client_certificate_presented.as_ref().unwrap().subject.contains("anvil-client-a"));
    assert_eq!(f.completed_handshakes(), vec![Some("anvil-client-a".to_string())]);
    assert_eq!(previews(&o, Direction::Received, "datagram"), vec!["secure hello"]);
    // Negative: an identity from an untrusted CA is rejected by the peer.
    let o = run(&e, &dtls_ctx(&f.url(), profile(&[&pki().ca.cert], Some(&pki().client_rogue), true))).await;
    let fl = last(&o).failure.as_ref().unwrap();
    assert_eq!(fl.kind, FailureKind::DtlsHandshakeFailed);
    assert_eq!(fl.tls_alert.as_deref(), Some("unknown_ca"));
    let tls = last(&o).connection.as_ref().unwrap().tls.as_ref().unwrap();
    assert_eq!(tls.verification, TlsVerification::Verified, "our side verified the server; the peer rejected us");
    assert!(tls.client_certificate_presented.as_ref().unwrap().subject.contains("anvil-client-rogue"));
    let d = finding(&o, "client.dtls.handshake_failed");
    assert!(d.explanation.contains("unknown_ca"));
    assert!(f.failed_handshakes().iter().any(|e| e.contains("client certificate rejected")));
    // No identity configured: dimpl's ephemeral certificate is presented and rejected — and the evidence says so.
    let o = run(&e, &dtls_ctx(&f.url(), profile(&[&pki().ca.cert], None, true))).await;
    assert_eq!(last(&o).failure.as_ref().unwrap().tls_alert.as_deref(), Some("unknown_ca"));
    assert!(o.record.prepared.inferred.iter().any(|i| i.contains("ephemeral self-signed")));
}
