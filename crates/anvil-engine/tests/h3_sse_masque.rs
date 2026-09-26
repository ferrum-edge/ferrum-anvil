//! Server-sent events over HTTP/3 and UDP through an RFC 9298 CONNECT-UDP
//! (MASQUE) proxy, end to end through the engine against real local QUIC
//! fixtures (no mocks). Fixture ground truth only checks that a condition was
//! reached; it is never fed to the diagnostic engine.

use anvil_domain::diagnostics::{Confidence, DiagnosticFinding, SourceScope};
use anvil_domain::events::SessionCommand;
use anvil_domain::execution::*;
use anvil_domain::outcome::*;
use anvil_domain::request::*;
use anvil_domain::settings::{HttpVersionPolicy, SettingsOverrides, TimeoutOverrides};
use anvil_domain::tls::{TlsMinVersion, TlsProfile};
use anvil_domain::{Id, auth::AuthConfig, secret::SensitiveValue};
use anvil_engine::{Engine, ExecutionContext, ExecutionOutput};
use anvil_fixtures::h3server::{self, H3Options};
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

fn server_tls() -> TlsServerOptions {
    TlsServerOptions::new(pki().server.chain_with(&pki().ca), pki().server.key.clone())
}

fn lab_ctx(spec: RequestSpec, version: Option<HttpVersionPolicy>) -> ExecutionContext {
    let mut c = ExecutionContext::standalone(spec);
    let p = TlsProfile {
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
            http_version: version,
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

fn previews(o: &ExecutionOutput, dir: Direction, kind: &str) -> Vec<String> {
    o.record
        .stream
        .as_ref()
        .map(|s| s.messages.iter().filter(|m| m.direction == dir && m.kind == kind).map(|m| m.preview.clone()).collect())
        .unwrap_or_default()
}

// ---------------------------------------------------------- SSE over H3 ---

fn sse_spec(url: &str, max_events: u32, idle_ms: u64, reconnect: bool) -> RequestSpec {
    let mut s = RequestSpec::http("GET", url);
    s.protocol = Protocol::Sse;
    s.sse = Some(SseSpec { max_events, idle_timeout_ms: idle_ms, last_event_id: None, reconnect });
    s
}

fn sse_status(o: &ExecutionOutput) -> (u16, u64, ClosedBy) {
    match &o.record.outcome.protocol_status {
        ProtocolStatus::Sse { http_status, events, closed_by } => (*http_status, *events, *closed_by),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn proto_018_sse_over_forced_h3_streams_events_and_ends_with_the_peer() {
    init();
    let f = h3server::serve("127.0.0.1:0", server_tls()).await.unwrap();
    let e = Engine::new();
    let url = format!("https://127.0.0.1:{}/sse?count=4&interval=5", f.addr.port());
    let o = run(&e, &lab_ctx(sse_spec(&url, 0, 3_000, false), Some(HttpVersionPolicy::Http3Only))).await;
    assert_eq!(sse_status(&o), (200, 4, ClosedBy::Peer));
    assert_eq!(o.record.outcome.transport, TransportState::Completed);
    assert_eq!(o.record.outcome.application, ApplicationState::Success);
    assert_eq!(o.record.response.as_ref().unwrap().http_version, "HTTP/3");
    let a = last(&o);
    assert_eq!(a.connection.as_ref().unwrap().protocol.as_deref(), Some("h3"));
    assert_eq!(a.phase(Phase::QuicHandshake).unwrap().status, PhaseStatus::Completed);
    assert!(a.phase(Phase::TlsHandshake).is_none());
    assert_eq!(previews(&o, Direction::Received, "event").len(), 4);
    assert_eq!(f.connections(), 1);
}

#[tokio::test]
async fn trust_007_sse_over_h3_abort_is_incomplete_never_success() {
    init();
    let f = h3server::serve("127.0.0.1:0", server_tls()).await.unwrap();
    let e = Engine::new();
    let url = format!("https://127.0.0.1:{}/sse-abort?count=3&interval=20", f.addr.port());
    let o = run(&e, &lab_ctx(sse_spec(&url, 0, 3_000, false), Some(HttpVersionPolicy::Http3Only))).await;
    assert!(f.log.entries().iter().any(|e| e.event == GroundTruth::FaultApplied { fault: "sse_abort_mid_stream".into() }));
    assert_eq!(sse_status(&o), (200, 3, ClosedBy::Abnormal));
    assert_eq!(o.record.outcome.transport, TransportState::Incomplete);
    assert_ne!(o.record.outcome.application, ApplicationState::Success);
    assert!(codes(&o).iter().any(|c| c.starts_with("response.body")), "{:?}", codes(&o));
    assert_eq!(last(&o).failure.as_ref().unwrap().kind, FailureKind::BodyReset);
}

#[tokio::test]
async fn sse_over_h3_reconnect_is_a_new_attempt_with_last_event_id() {
    init();
    let f = h3server::serve("127.0.0.1:0", server_tls()).await.unwrap();
    let e = Engine::new();
    let url = format!("https://127.0.0.1:{}/sse-flaky?interval=10", f.addr.port());
    let o = run(&e, &lab_ctx(sse_spec(&url, 0, 3_000, true), Some(HttpVersionPolicy::Http3Only))).await;
    assert_eq!(o.record.attempts.len(), 2);
    assert!(matches!(o.record.attempts[1].reason, AttemptReason::Retry { .. }));
    assert_eq!(sse_status(&o), (200, 3, ClosedBy::Peer));
    assert_eq!(o.record.outcome.transport, TransportState::Completed);
    let hdrs = f.log.last_request_headers().unwrap();
    assert!(hdrs.iter().any(|(n, v)| n == "last-event-id" && v == "2"), "{hdrs:?}");
    assert!(o.record.prepared.inferred.iter().any(|i| i.contains("reconnecting")), "{:?}", o.record.prepared.inferred);
}

#[tokio::test]
async fn sse_over_h3_idle_and_cancel_are_expected_ends() {
    init();
    let f = h3server::serve("127.0.0.1:0", server_tls()).await.unwrap();
    let e = Engine::new();
    let url = format!("https://127.0.0.1:{}/sse?count=3&interval=3000", f.addr.port());
    let o = run(&e, &lab_ctx(sse_spec(&url, 0, 400, false), Some(HttpVersionPolicy::Http3Only))).await;
    assert_eq!(sse_status(&o), (200, 1, ClosedBy::Timeout));
    finding(&o, "sse.idle_timeout");
    assert!(!codes(&o).contains(&"sse.canceled".to_string()));

    let url = format!("https://127.0.0.1:{}/sse?count=500&interval=20", f.addr.port());
    let cancel = CancellationToken::new();
    let c2 = cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(250)).await;
        c2.cancel();
    });
    let o = e.execute(&lab_ctx(sse_spec(&url, 0, 5_000, false), Some(HttpVersionPolicy::Http3Only)), EventCtx::none(), cancel).await;
    assert_eq!(o.record.outcome.transport, TransportState::Canceled);
    assert_eq!(sse_status(&o).2, ClosedBy::Client);
    finding(&o, "sse.canceled");
    assert!(!codes(&o).iter().any(|c| c.contains("timeout")), "{:?}", codes(&o));

    // Interactive SSE over HTTP/3 stays receive-only.
    let url = format!("https://127.0.0.1:{}/sse?count=500&interval=20", f.addr.port());
    let h = e.open_session(lab_ctx(sse_spec(&url, 0, 5_000, false), Some(HttpVersionPolicy::Http3Only)), EventCtx::none()).await;
    assert!(h.send(SessionCommand::SendText { text: "no".into() }).await.is_err(), "receive-only");
    tokio::time::sleep(Duration::from_millis(200)).await;
    h.close().await.unwrap();
    let o = h.finish().await;
    let (_, n, by) = sse_status(&o);
    assert!(n >= 2 && by == ClosedBy::Client, "{n} {by:?}");
}

#[tokio::test]
async fn sse_h3_policies_fail_before_traffic_or_fall_back_visibly() {
    init();
    let e = Engine::new();
    // Forced HTTP/3 needs https://: refused locally.
    let o = run(&e, &lab_ctx(sse_spec("http://127.0.0.1:9/sse", 0, 1_000, false), Some(HttpVersionPolicy::Http3Only))).await;
    assert_eq!(last(&o).failure.as_ref().unwrap().kind, FailureKind::UnsupportedCombination);
    finding(&o, "local.unsupported_combination");
    // The automatic policy against a TCP-only server records the failed H3 attempt, then TCP.
    let tcp = anvil_fixtures::http::serve("127.0.0.1:0", Some(server_tls())).await.unwrap();
    let mut c = lab_ctx(
        sse_spec(&format!("https://127.0.0.1:{}/sse?count=2&interval=5", tcp.addr.port()), 0, 3_000, false),
        Some(HttpVersionPolicy::Http3WithFallback),
    );
    c.settings_layers.push((
        "scenario".into(),
        SettingsOverrides {
            timeouts: Some(TimeoutOverrides { tls_handshake_ms: Some(Some(400)), ..Default::default() }),
            ..Default::default()
        },
    ));
    let o = run(&e, &c).await;
    assert_eq!(o.record.attempts.len(), 2);
    assert_eq!(o.record.attempts[0].failure.as_ref().unwrap().kind, FailureKind::QuicHandshakeTimeout);
    assert_eq!(sse_status(&o), (200, 2, ClosedBy::Peer));
    finding(&o, "client.h3.fallback_used");
    assert!(o.record.outcome.warnings.iter().any(|w| w.code == WarningCode::ProtocolFallback));
}

// ------------------------------------------------------------ CONNECT-UDP ---

fn masque_spec(target: &str, proxy: &str, template: Option<&str>, mode: MasqueDatagramMode, datagrams: &[&str]) -> RequestSpec {
    let mut s = RequestSpec::http("GET", target);
    s.protocol = Protocol::Udp;
    s.udp = Some(UdpSpec {
        dtls: false,
        datagrams: datagrams.iter().map(|d| StreamPayload { data: d.to_string(), encoding: PayloadEncoding::Text }).collect(),
        response_window_ms: 400,
        max_datagrams: 100,
        proxy_protocol: None,
        masque: Some(MasqueSpec {
            proxy_url: proxy.to_string(),
            uri_template: template.unwrap_or(MASQUE_DEFAULT_TEMPLATE).to_string(),
            datagrams: mode,
        }),
    });
    s
}

fn tunnel(o: &ExecutionOutput) -> (u64, u64, MasqueTunnel) {
    match &o.record.outcome.protocol_status {
        ProtocolStatus::Udp { datagrams_sent, datagrams_received, masque: Some(m), .. } => {
            (*datagrams_sent, *datagrams_received, m.clone())
        }
        other => panic!("{other:?}"),
    }
}

/// No MASQUE finding may claim the UDP target is down or unreachable.
fn no_target_blame(o: &ExecutionOutput) {
    for f in o.record.findings.iter().filter(|f| f.code.starts_with("masque.")) {
        assert_eq!(f.scope, SourceScope::ForwardProxy, "{}", f.code);
        assert!(f.does_not_prove.iter().any(|d| d.contains("127.0.0.1:")), "{}: {:?}", f.code, f.does_not_prove);
        assert!(!f.title.to_lowercase().contains("down"), "{}", f.title);
    }
}

#[tokio::test]
async fn udp_through_a_masque_proxy_echoes_and_records_the_tunnel() {
    init();
    let proxy = h3server::serve("127.0.0.1:0", server_tls()).await.unwrap();
    let echo = streams::udp("127.0.0.1:0", UdpMode::Echo).await.unwrap();
    let e = Engine::new();
    let mut s = masque_spec(
        &format!("udp://{}", echo.addr),
        &format!("https://127.0.0.1:{}", proxy.addr.port()),
        None,
        MasqueDatagramMode::Auto,
        &["one", "two"],
    );
    s.headers.push(KeyValue::new("x-tunnel-tag", "lab"));
    let o = run(&e, &lab_ctx(s, None)).await;
    let (sent, got, m) = tunnel(&o);
    assert_eq!((sent, got), (2, 2));
    assert_eq!((m.connect_status, m.encoding, m.closed_by), (Some(200), Some(MasqueEncoding::Capsule), ClosedBy::Client));
    assert_eq!(previews(&o, Direction::Received, "datagram"), vec!["one", "two"]);
    assert_eq!(o.record.outcome.transport, TransportState::Completed);
    assert!(!codes(&o).iter().any(|c| c.starts_with("masque.") || c.starts_with("udp.")), "{:?}", codes(&o));
    assert_eq!(last(&o).method, "CONNECT");
    assert!(last(&o).url.contains("/.well-known/masque/udp/127.0.0.1/"), "{}", last(&o).url);
    assert!(o.record.prepared.inferred.iter().any(|i| i.contains("MASQUE proxy")), "{:?}", o.record.prepared.inferred);
    assert!(o.record.prepared.inferred.iter().any(|i| i.contains("DATAGRAM capsules")), "{:?}", o.record.prepared.inferred);
    let hdrs = proxy.log.last_request_headers().unwrap();
    assert!(hdrs.iter().any(|(n, v)| n == "x-tunnel-tag" && v == "lab"), "request headers go on the CONNECT: {hdrs:?}");
    assert!(hdrs.iter().any(|(n, _)| n == "user-agent"));
    assert!(!hdrs.iter().any(|(n, _)| n == "content-type" || n == "accept-encoding"), "no HTTP body defaults: {hdrs:?}");
}

#[tokio::test]
async fn masque_refusal_is_the_proxys_answer_not_a_claim_about_the_target() {
    init();
    let proxy = h3server::serve("127.0.0.1:0", server_tls()).await.unwrap();
    let echo = streams::udp("127.0.0.1:0", UdpMode::Echo).await.unwrap();
    let e = Engine::new();
    let o = run(
        &e,
        &lab_ctx(
            masque_spec(
                &format!("udp://{}", echo.addr),
                &format!("https://127.0.0.1:{}", proxy.addr.port()),
                Some("/.well-known/masque/udp/{target_host}/{target_port}/?refuse=403"),
                MasqueDatagramMode::Auto,
                &["never"],
            ),
            None,
        ),
    )
    .await;
    let f = finding(&o, "masque.proxy_refused");
    assert_eq!(f.confidence, Confidence::Confirmed);
    assert!(f.explanation.contains("HTTP 403"), "{}", f.explanation);
    assert!(f.evidence.iter().any(|e| e.key == "body.error"), "the refusal body is kept as evidence: {:?}", f.evidence);
    no_target_blame(&o);
    assert_eq!(o.record.outcome.application, ApplicationState::Failure);
    assert_eq!(o.record.outcome.dispatch, DispatchState::NotDispatched);
    assert!(o.record.stream.is_none());
    assert!(String::from_utf8_lossy(&o.body).contains("refused"));
    assert!(!codes(&o).contains(&"udp.no_response".to_string()), "nothing was sent, so no silence is claimed");
    assert!(echo.log.entries().is_empty());
}

#[tokio::test]
async fn masque_capabilities_missing_fail_before_traffic_with_findings() {
    init();
    let echo = streams::udp("127.0.0.1:0", UdpMode::Echo).await.unwrap();
    let e = Engine::new();
    let no_ext =
        h3server::serve_with("127.0.0.1:0", server_tls(), H3Options { extended_connect: false, ..Default::default() }).await.unwrap();
    let o = run(
        &e,
        &lab_ctx(
            masque_spec(
                &format!("udp://{}", echo.addr),
                &format!("https://127.0.0.1:{}", no_ext.addr.port()),
                None,
                MasqueDatagramMode::Auto,
                &["x"],
            ),
            None,
        ),
    )
    .await;
    finding(&o, "masque.extended_connect_unavailable");
    no_target_blame(&o);
    assert_eq!(o.record.outcome.dispatch, DispatchState::NotDispatched);
    assert!(no_ext.log.requests().is_empty());

    let proxy = h3server::serve("127.0.0.1:0", server_tls()).await.unwrap();
    let o = run(
        &e,
        &lab_ctx(
            masque_spec(
                &format!("udp://{}", echo.addr),
                &format!("https://127.0.0.1:{}", proxy.addr.port()),
                None,
                MasqueDatagramMode::QuicDatagrams,
                &["x"],
            ),
            None,
        ),
    )
    .await;
    let f = finding(&o, "masque.no_datagram_support");
    assert!(f.evidence.iter().any(|e| e.key == "h3.settings.h3_datagram" && e.value == "not enabled"), "{:?}", f.evidence);
    no_target_blame(&o);
    assert!(proxy.log.requests().is_empty());
    assert!(echo.log.entries().is_empty());
}

#[tokio::test]
async fn masque_abnormal_end_is_incomplete_and_silence_is_only_no_response() {
    init();
    let proxy = h3server::serve("127.0.0.1:0", server_tls()).await.unwrap();
    let echo = streams::udp("127.0.0.1:0", UdpMode::Echo).await.unwrap();
    let e = Engine::new();
    let mut s = masque_spec(
        &format!("udp://{}", echo.addr),
        &format!("https://127.0.0.1:{}", proxy.addr.port()),
        Some("/.well-known/masque/udp/{target_host}/{target_port}/?reset_after=1"),
        MasqueDatagramMode::Auto,
        &["a"],
    );
    if let Some(u) = s.udp.as_mut() {
        u.response_window_ms = 2_000;
    }
    let o = run(&e, &lab_ctx(s, None)).await;
    finding(&o, "masque.tunnel_ended_abnormally");
    no_target_blame(&o);
    assert_eq!(o.record.outcome.transport, TransportState::Incomplete);
    assert_ne!(o.record.outcome.application, ApplicationState::Success);
    assert_eq!(previews(&o, Direction::Received, "datagram"), vec!["a"]);

    let silent = streams::udp("127.0.0.1:0", UdpMode::Silent).await.unwrap();
    let o = run(
        &e,
        &lab_ctx(
            masque_spec(
                &format!("udp://{}", silent.addr),
                &format!("https://127.0.0.1:{}", proxy.addr.port()),
                None,
                MasqueDatagramMode::Auto,
                &["?"],
            ),
            None,
        ),
    )
    .await;
    let n = finding(&o, "udp.no_response");
    assert!(n.does_not_prove.iter().any(|d| d.contains("delivered")));
    assert!(!codes(&o).iter().any(|c| c.starts_with("masque.")), "{:?}", codes(&o));
    assert_eq!(o.record.outcome.dispatch, DispatchState::MayHaveBeenSent);
    assert!(silent.log.entries().iter().any(|e| matches!(e.event, GroundTruth::DatagramReceived { .. })));
}

#[tokio::test]
async fn interactive_udp_through_a_masque_proxy_sends_on_command_until_close() {
    init();
    let proxy = h3server::serve_with("127.0.0.1:0", server_tls(), H3Options { h3_datagrams: true, ..Default::default() }).await.unwrap();
    let echo = streams::udp("127.0.0.1:0", UdpMode::Echo).await.unwrap();
    let e = Engine::new();
    let s = masque_spec(
        &format!("udp://{}", echo.addr),
        &format!("https://127.0.0.1:{}", proxy.addr.port()),
        None,
        MasqueDatagramMode::Auto,
        &["scripted"],
    );
    let h = e.open_session(lab_ctx(s, None), EventCtx::none()).await;
    h.send(SessionCommand::SendText { text: "live".into() }).await.unwrap();
    h.send(SessionCommand::SendBinaryHex { hex: "6865780a".into() }).await.unwrap();
    assert!(h.send(SessionCommand::Ping).await.is_err(), "UDP has no ping");
    tokio::time::sleep(Duration::from_millis(400)).await;
    h.close().await.unwrap();
    let o = h.finish().await;
    assert_eq!(previews(&o, Direction::Received, "datagram"), vec!["scripted", "live", "hex\n"]);
    let (sent, got, m) = tunnel(&o);
    assert_eq!((sent, got), (3, 3));
    assert_eq!((m.encoding, m.sent_quic_datagrams, m.received_quic_datagrams), (Some(MasqueEncoding::QuicDatagram), 3, 3));
    assert_eq!(m.closed_by, ClosedBy::Client);
    assert_eq!(o.record.outcome.transport, TransportState::Completed);
}

#[tokio::test]
async fn masque_settings_are_validated_before_traffic() {
    init();
    let e = Engine::new();
    let local = |url: &str, proxy: &str, template: Option<&str>| {
        let s = masque_spec(url, proxy, template, MasqueDatagramMode::Auto, &["x"]);
        lab_ctx(s, None)
    };
    for (c, field) in [
        (local("udp://127.0.0.1:9", "http://127.0.0.1:9", None), "udp.masque.proxy_url"),
        (local("udp://127.0.0.1:9", "https://127.0.0.1:9/prefix", None), "udp.masque.proxy_url"),
        (local("udp://127.0.0.1:9", "https://127.0.0.1:9", Some("/masque/{target_host}/")), "udp.masque.uri_template"),
        (
            local("udp://127.0.0.1:9", "https://127.0.0.1:9", Some("/masque/{target_host}/{target_port}/{other}/")),
            "udp.masque.uri_template",
        ),
    ] {
        let o = run(&e, &c).await;
        let f = last(&o).failure.as_ref().unwrap();
        assert!(f.kind.is_local_preparation(), "{:?}", f.kind);
        assert_eq!(f.field.as_deref(), Some(field), "{}", f.message);
        assert!(last(&o).phases.iter().all(|p| p.phase == Phase::Prepare), "nothing was sent");
    }
    // Auth applies to the CONNECT request (the proxy is the HTTP peer).
    let proxy = h3server::serve("127.0.0.1:0", server_tls()).await.unwrap();
    let echo = streams::udp("127.0.0.1:0", UdpMode::Echo).await.unwrap();
    let mut s = masque_spec(
        &format!("udp://{}", echo.addr),
        &format!("https://127.0.0.1:{}", proxy.addr.port()),
        None,
        MasqueDatagramMode::Auto,
        &["x"],
    );
    s.auth = AuthConfig::Bearer { token: SensitiveValue::template("masque-secret-token".to_string()), prefix: "Bearer".into() };
    let o = run(&e, &lab_ctx(s, None)).await;
    let hdrs = proxy.log.last_request_headers().unwrap();
    assert!(hdrs.iter().any(|(n, v)| n == "authorization" && v == "Bearer masque-secret-token"), "{hdrs:?}");
    let json = serde_json::to_string(&o.record).unwrap();
    assert!(!json.contains("masque-secret-token"), "the token is redacted in the record");
}
