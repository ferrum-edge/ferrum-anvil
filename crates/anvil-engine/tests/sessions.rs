//! Session-protocol scenarios through the shared engine against real local
//! sockets (no mocks). Matrix IDs (PROTO-006…022) are kept in test names.
//! Fixture ground truth is used only to check that a condition was really
//! reached; it is never fed to the diagnostic engine.

use anvil_domain::assertions::{Assertion, AssertionKind, Comparison};
use anvil_domain::auth::AuthConfig;
use anvil_domain::diagnostics::DiagnosticFinding;
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

#[tokio::test]
async fn proto_013_ws_over_h3_is_a_typed_unsupported_combination() {
    init();
    let f = h3server::serve("127.0.0.1:0", server_tls()).await.unwrap();
    let e = Engine::new();
    let mut s = spec(Protocol::WebSocket, &format!("wss://127.0.0.1:{}/ws", f.addr.port()));
    let mut w = ws_spec(vec![text("never sent")]);
    w.bootstrap = WsBootstrap::Http3ExtendedConnect;
    s.websocket = Some(w);
    let mut c = ctx(s);
    lab_trust(&mut c);
    let o = run(&e, &c).await;
    let fl = last(&o).failure.as_ref().unwrap();
    assert_eq!(fl.kind, FailureKind::UnsupportedCombination);
    assert_eq!(fl.phase, Phase::Prepare);
    assert!(fl.message.contains("h3 0.0.8") && fl.message.contains(":protocol"), "{}", fl.message);
    assert_eq!(o.record.outcome.transport, TransportState::Failed);
    assert_eq!(o.record.outcome.dispatch, DispatchState::NotDispatched);
    finding(&o, "local.unsupported_combination");
    assert!(o.record.stream.is_none(), "no success-shaped session");
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(f.connections(), 0, "nothing was sent");
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
    });
    let mut c = ctx(s);
    c.attachments = Arc::new(store);
    run_layer(&mut c, fast());
    c
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
    assert!(matches!(o.record.outcome.protocol_status, ProtocolStatus::Udp { datagrams_sent: 1, datagrams_received: 0, window_ms: 300 }));
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
