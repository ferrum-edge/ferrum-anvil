//! Server-sent events over HTTP/3 and RFC 9298 CONNECT-UDP (MASQUE) through
//! an HTTP/3 proxy, against real local QUIC fixtures (no mocks). Fixture
//! ground truth only checks that a condition was reached; it is never given
//! to the adapter.

use anvil_domain::execution::*;
use anvil_domain::outcome::{ClosedBy, MasqueEncoding, MasqueTunnel, ProtocolStatus};
use anvil_domain::request::MasqueDatagramMode;
use anvil_domain::settings::{HttpVersionPolicy, Limits, Timeouts};
use anvil_fixtures::h3server::{self, H3Options};
use anvil_fixtures::streams::{self, UdpMode};
use anvil_fixtures::{GroundTruth, LabPki, TlsServerOptions};
use anvil_transport::dns::DnsConfig;
use anvil_transport::recorder::EventCtx;
use anvil_transport::session::{SessionOutput, TranscriptLimits};
use anvil_transport::tls::{self, PreparedTls, TlsSettings};
use anvil_transport::{masque, sse};
use bytes::Bytes;
use std::net::SocketAddr;
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

fn client_tls() -> Arc<PreparedTls> {
    Arc::new(
        tls::prepare(&TlsSettings {
            verify: true,
            use_system_roots: false,
            extra_roots_pem: vec![pki().ca.cert.clone()],
            ..Default::default()
        })
        .unwrap(),
    )
}

fn timeouts() -> Timeouts {
    Timeouts {
        dns_ms: Some(2_000),
        connect_ms: Some(2_000),
        tls_handshake_ms: Some(2_000),
        request_write_ms: Some(2_000),
        response_headers_ms: Some(3_000),
        body_idle_ms: Some(3_000),
        total_ms: Some(15_000),
    }
}

// ---------------------------------------------------------- SSE over H3 ---

fn sse_plan(addr: SocketAddr, target: &str) -> sse::SsePlan {
    sse::SsePlan {
        method: http::Method::GET,
        https: true,
        host: addr.ip().to_string(),
        port: addr.port(),
        authority: addr.to_string(),
        request_target: target.to_string(),
        headers: vec![],
        body: Bytes::new(),
        version: HttpVersionPolicy::Http3Only,
        timeouts: timeouts(),
        limits: Limits::default(),
        dns: DnsConfig::default(),
        proxy: None,
        tls: Some(client_tls()),
        display_url: format!("https://{addr}{target}"),
        max_events: 0,
        idle_timeout_ms: 3_000,
        last_event_id: None,
        reconnect: false,
        max_reconnects: 0,
        transcript: TranscriptLimits::default(),
        redact: None,
    }
}

fn sse_state(out: &SessionOutput) -> (u16, u64, ClosedBy) {
    match &out.status {
        ProtocolStatus::Sse { http_status, events, closed_by } => (*http_status, *events, *closed_by),
        other => panic!("{other:?}"),
    }
}

fn events(out: &SessionOutput) -> Vec<(Option<String>, String)> {
    out.transcript
        .as_ref()
        .map(|t| t.messages.iter().filter(|m| m.kind == "event").map(|m| (m.event_id.clone(), m.preview.clone())).collect())
        .unwrap_or_default()
}

#[tokio::test]
async fn sse_over_h3_parses_events_from_data_frames_and_measures_quic() {
    init();
    let f = h3server::serve("127.0.0.1:0", server_tls()).await.unwrap();
    let out = sse::run(&sse_plan(f.addr, "/sse?count=3&interval=5"), &EventCtx::none(), &CancellationToken::new(), None).await;
    assert_eq!(sse_state(&out), (200, 3, ClosedBy::Peer), "a clean end of stream is the server's close");
    assert_eq!(out.attempts.len(), 1);
    let a = &out.attempts[0];
    assert!(a.observation.failure.is_none(), "{:?}", a.observation.failure);
    let conn = a.observation.connection.as_ref().unwrap();
    assert_eq!(conn.protocol.as_deref(), Some("h3"));
    assert_eq!(a.observation.phase(Phase::QuicHandshake).unwrap().status, PhaseStatus::Completed);
    assert_eq!(a.observation.phase(Phase::Connect).unwrap().status, PhaseStatus::NotApplicable, "no TCP connect is claimed");
    assert!(a.observation.phase(Phase::TlsHandshake).is_none(), "no TCP-TLS phase is claimed");
    let r = a.response.as_ref().unwrap();
    assert_eq!((r.status, r.http_version.as_str()), (200, "HTTP/3"));
    assert_eq!(r.body.completeness, BodyCompleteness::Complete);
    assert_eq!(events(&out)[2], (Some("2".into()), r#"{"n":2}"#.into()));
    assert!(a.observation.bytes.connection_bytes_read.unwrap_or(0) > 0);
    // Ground truth: one QUIC connection; the request asked for an event stream.
    assert_eq!(f.connections(), 1);
    let hdrs = f.log.last_request_headers().unwrap();
    assert!(hdrs.iter().any(|(n, v)| n == "accept" && v == "text/event-stream"), "{hdrs:?}");
}

#[tokio::test]
async fn sse_over_h3_abort_mid_stream_is_incomplete_and_keeps_the_events() {
    init();
    let f = h3server::serve("127.0.0.1:0", server_tls()).await.unwrap();
    let out = sse::run(&sse_plan(f.addr, "/sse-abort?count=2&interval=20"), &EventCtx::none(), &CancellationToken::new(), None).await;
    assert!(f.log.entries().iter().any(|e| e.event == GroundTruth::FaultApplied { fault: "sse_abort_mid_stream".into() }));
    assert_eq!(sse_state(&out), (200, 2, ClosedBy::Abnormal));
    let a = &out.attempts[0];
    let fl = a.observation.failure.as_ref().unwrap();
    assert_eq!((fl.kind, fl.phase), (FailureKind::BodyReset, Phase::Session));
    assert_eq!(fl.quic_error_code, Some(0x102), "the peer's H3_INTERNAL_ERROR is kept as evidence");
    assert_eq!(a.response.as_ref().unwrap().body.completeness, BodyCompleteness::Incomplete);
    assert_eq!(events(&out).len(), 2, "events before the reset are kept");
}

#[tokio::test]
async fn sse_over_h3_reconnects_on_a_new_quic_connection_with_last_event_id() {
    init();
    let f = h3server::serve("127.0.0.1:0", server_tls()).await.unwrap();
    let mut plan = sse_plan(f.addr, "/sse-flaky?interval=10");
    plan.reconnect = true;
    plan.max_reconnects = 3;
    let out = sse::run(&plan, &EventCtx::none(), &CancellationToken::new(), None).await;
    assert_eq!(out.attempts.len(), 2, "one abnormal end, then one reconnection");
    assert_eq!(out.attempts[0].observation.failure.as_ref().unwrap().kind, FailureKind::BodyReset);
    assert!(matches!(out.attempts[1].observation.reason, AttemptReason::Retry { after: FailureKind::BodyReset }));
    assert_eq!(sse_state(&out), (200, 3, ClosedBy::Peer));
    assert_eq!(events(&out).iter().map(|(id, _)| id.clone().unwrap_or_default()).collect::<Vec<_>>(), vec!["1", "2", "3"]);
    assert_eq!(f.connections(), 2, "each attempt is a new QUIC connection");
    let ids: Vec<Option<String>> = f
        .log
        .entries()
        .iter()
        .filter_map(|e| match &e.event {
            GroundTruth::RequestReceived { headers, .. } => {
                Some(headers.iter().find(|(n, _)| n == "last-event-id").map(|(_, v)| v.clone()))
            }
            _ => None,
        })
        .collect();
    assert_eq!(ids, vec![None, Some("2".into())]);
    assert!(out.facts.notes.iter().any(|n| n.contains("Last-Event-ID 2")), "{:?}", out.facts.notes);
    // Without reconnect the same stream ends after the first attempt.
    let out = sse::run(&sse_plan(f.addr, "/sse-flaky?interval=10"), &EventCtx::none(), &CancellationToken::new(), None).await;
    assert_eq!(out.attempts.len(), 1);
    assert_eq!(sse_state(&out).2, ClosedBy::Abnormal);
}

#[tokio::test]
async fn sse_over_h3_idle_max_events_and_cancel_are_client_side_ends() {
    init();
    let f = h3server::serve("127.0.0.1:0", server_tls()).await.unwrap();
    let mut plan = sse_plan(f.addr, "/sse?count=3&interval=2000");
    plan.idle_timeout_ms = 300;
    let out = sse::run(&plan, &EventCtx::none(), &CancellationToken::new(), None).await;
    assert_eq!(sse_state(&out), (200, 1, ClosedBy::Timeout), "one event, then the idle limit");
    assert!(out.attempts[0].observation.failure.is_none(), "an idle stop is not a transport failure");

    let mut plan = sse_plan(f.addr, "/sse?count=50&interval=5");
    plan.max_events = 2;
    let out = sse::run(&plan, &EventCtx::none(), &CancellationToken::new(), None).await;
    assert_eq!(sse_state(&out), (200, 2, ClosedBy::Client));

    let cancel = CancellationToken::new();
    let c2 = cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(200)).await;
        c2.cancel();
    });
    let out = sse::run(&sse_plan(f.addr, "/sse?count=500&interval=20"), &EventCtx::none(), &cancel, None).await;
    let (_, n, by) = sse_state(&out);
    assert!(n >= 2, "events before the cancel are kept: {n}");
    assert_eq!(by, ClosedBy::Client);
    assert_eq!(out.attempts[0].observation.failure.as_ref().unwrap().kind, FailureKind::Canceled);
}

#[tokio::test]
async fn forced_h3_sse_needs_https_and_never_touches_tcp() {
    init();
    let mut plan = sse_plan("127.0.0.1:9".parse().unwrap(), "/sse");
    plan.https = false;
    let out = sse::run(&plan, &EventCtx::none(), &CancellationToken::new(), None).await;
    let f = out.attempts[0].observation.failure.as_ref().unwrap();
    assert_eq!((f.kind, f.phase), (FailureKind::UnsupportedCombination, Phase::Prepare));
    assert!(out.attempts[0].observation.phases.is_empty(), "nothing was attempted");
    // Forced HTTP/3 to a port without a QUIC listener: one failed attempt, no TCP.
    let tcp = anvil_fixtures::http::serve("127.0.0.1:0", Some(server_tls())).await.unwrap();
    let mut plan = sse_plan(tcp.addr, "/sse?count=2&interval=5");
    plan.timeouts.tls_handshake_ms = Some(400);
    let out = sse::run(&plan, &EventCtx::none(), &CancellationToken::new(), None).await;
    assert_eq!(out.attempts.len(), 1);
    assert_eq!(out.attempts[0].observation.failure.as_ref().unwrap().kind, FailureKind::QuicHandshakeTimeout);
    assert!(!tcp.log.saw_connection(), "no silent TCP fallback");
}

#[tokio::test]
async fn automatic_h3_sse_falls_back_to_tcp_as_a_separate_attempt() {
    init();
    let tcp = anvil_fixtures::http::serve("127.0.0.1:0", Some(server_tls())).await.unwrap();
    let mut plan = sse_plan(tcp.addr, "/sse?count=2&interval=5");
    plan.version = HttpVersionPolicy::Http3WithFallback;
    plan.timeouts.tls_handshake_ms = Some(400);
    let out = sse::run(&plan, &EventCtx::none(), &CancellationToken::new(), None).await;
    assert_eq!(out.attempts.len(), 2);
    assert_eq!(out.attempts[0].observation.failure.as_ref().unwrap().kind, FailureKind::QuicHandshakeTimeout);
    assert_eq!(out.attempts[1].observation.reason, AttemptReason::ProtocolFallback { from: "h3".into() });
    assert_ne!(out.attempts[1].response.as_ref().unwrap().http_version, "HTTP/3");
    assert_eq!(sse_state(&out), (200, 2, ClosedBy::Peer));
    assert!(tcp.log.saw_connection());
}

// ------------------------------------------------------------ CONNECT-UDP ---

fn masque_plan(proxy: SocketAddr, target: SocketAddr, query: &str, datagrams: &[&str]) -> masque::MasquePlan {
    masque::MasquePlan {
        proxy_host: proxy.ip().to_string(),
        proxy_port: proxy.port(),
        proxy_authority: proxy.to_string(),
        request_target: format!("/.well-known/masque/udp/{}/{}/{query}", target.ip(), target.port()),
        target: target.to_string(),
        headers: vec![],
        mode: MasqueDatagramMode::Auto,
        tls: client_tls(),
        dns: DnsConfig::default(),
        timeouts: timeouts(),
        limits: Limits::default(),
        datagrams: datagrams.iter().map(|d| Bytes::copy_from_slice(d.as_bytes())).collect(),
        response_window_ms: 400,
        max_datagrams: 100,
        display_url: format!("https://{proxy}/.well-known/masque/udp/{}/{}/", target.ip(), target.port()),
        transcript: TranscriptLimits::default(),
        redact: None,
    }
}

fn udp_state(out: &SessionOutput) -> (u64, u64, MasqueTunnel) {
    match &out.status {
        ProtocolStatus::Udp { datagrams_sent, datagrams_received, masque: Some(m), .. } => {
            (*datagrams_sent, *datagrams_received, m.clone())
        }
        other => panic!("{other:?}"),
    }
}

fn received(out: &SessionOutput) -> Vec<String> {
    out.transcript
        .as_ref()
        .map(|t| {
            t.messages.iter().filter(|m| m.kind == "datagram" && m.direction == Direction::Received).map(|m| m.preview.clone()).collect()
        })
        .unwrap_or_default()
}

fn relayed(f: &h3server::H3Fixture) -> Vec<String> {
    f.log
        .entries()
        .iter()
        .filter_map(|e| match &e.event {
            GroundTruth::DatagramRelayed { via, .. } => Some(via.clone()),
            _ => None,
        })
        .collect()
}

#[tokio::test]
async fn connect_udp_with_capsules_when_the_proxy_does_not_offer_h3_datagrams() {
    init();
    let proxy = h3server::serve("127.0.0.1:0", server_tls()).await.unwrap();
    let echo = streams::udp("127.0.0.1:0", UdpMode::Echo).await.unwrap();
    let out =
        masque::run(&masque_plan(proxy.addr, echo.addr, "", &["ping-1", "ping-2"]), &EventCtx::none(), &CancellationToken::new(), None)
            .await;
    let a = &out.attempts[0];
    assert!(a.observation.failure.is_none(), "{:?}", a.observation.failure);
    assert_eq!(a.observation.method, "CONNECT");
    assert_eq!(a.response.as_ref().unwrap().status, 200);
    assert_eq!(a.observation.connection.as_ref().unwrap().protocol.as_deref(), Some("h3"));
    assert!(
        a.observation.phases.iter().any(|p| p.detail.as_deref().unwrap_or("").contains("DATAGRAM capsules")),
        "{:?}",
        a.observation.phases
    );
    let (sent, got, m) = udp_state(&out);
    assert_eq!((sent, got), (2, 2));
    assert_eq!(m.connect_status, Some(200));
    assert_eq!((m.extended_connect, m.h3_datagrams), (Some(true), Some(false)));
    assert_eq!(m.encoding, Some(MasqueEncoding::Capsule));
    assert_eq!((m.sent_capsules, m.received_capsules, m.sent_quic_datagrams, m.received_quic_datagrams), (2, 2, 0, 0));
    assert_eq!(m.closed_by, ClosedBy::Client, "Anvil ended the tunnel after the response window");
    assert_eq!(received(&out), vec!["ping-1", "ping-2"]);
    assert_eq!(a.observation.dispatch, DispatchState::Sent);
    // Ground truth: the proxy saw an RFC 9298 request and relayed capsules to the target.
    let hdrs = proxy.log.last_request_headers().unwrap();
    assert!(hdrs.iter().any(|(n, v)| n == "capsule-protocol" && v == "?1"), "{hdrs:?}");
    assert_eq!(relayed(&proxy), vec!["capsule", "capsule"]);
    assert_eq!(echo.log.entries().iter().filter(|e| matches!(e.event, GroundTruth::DatagramReceived { .. })).count(), 2);
}

#[tokio::test]
async fn connect_udp_with_quic_datagrams_when_both_sides_enable_them() {
    init();
    let proxy = h3server::serve_with("127.0.0.1:0", server_tls(), H3Options { h3_datagrams: true, ..Default::default() }).await.unwrap();
    let echo = streams::udp("127.0.0.1:0", UdpMode::Echo).await.unwrap();
    let mut plan = masque_plan(proxy.addr, echo.addr, "", &["q1", "q2", "q3"]);
    plan.mode = MasqueDatagramMode::QuicDatagrams;
    let out = masque::run(&plan, &EventCtx::none(), &CancellationToken::new(), None).await;
    let (sent, got, m) = udp_state(&out);
    assert!(out.attempts[0].observation.failure.is_none(), "{:?}", out.attempts[0].observation.failure);
    assert_eq!((sent, got), (3, 3));
    assert_eq!(m.encoding, Some(MasqueEncoding::QuicDatagram));
    assert_eq!((m.sent_quic_datagrams, m.received_quic_datagrams, m.sent_capsules, m.received_capsules), (3, 3, 0, 0));
    assert_eq!(received(&out), vec!["q1", "q2", "q3"]);
    assert_eq!(relayed(&proxy), vec!["quic_datagram"; 3]);
}

#[tokio::test]
async fn connect_udp_refusal_keeps_the_proxy_answer_and_sends_no_datagram() {
    init();
    let proxy = h3server::serve("127.0.0.1:0", server_tls()).await.unwrap();
    let echo = streams::udp("127.0.0.1:0", UdpMode::Echo).await.unwrap();
    let out =
        masque::run(&masque_plan(proxy.addr, echo.addr, "?refuse=403", &["never"]), &EventCtx::none(), &CancellationToken::new(), None)
            .await;
    let a = &out.attempts[0];
    let f = a.observation.failure.as_ref().unwrap();
    assert_eq!((f.kind, f.status), (FailureKind::MasqueRefused, Some(403)));
    assert!(f.message.contains("no datagram was sent"), "{}", f.message);
    assert_eq!(a.observation.dispatch, DispatchState::NotDispatched);
    let r = a.response.as_ref().unwrap();
    assert_eq!((r.status, r.http_version.as_str()), (403, "HTTP/3"));
    assert!(String::from_utf8_lossy(&a.body).contains("refused this CONNECT-UDP"), "the refusal body is kept");
    assert!(out.transcript.is_none(), "no tunnel, no session transcript");
    let (sent, got, m) = udp_state(&out);
    assert_eq!((sent, got, m.connect_status, m.encoding), (0, 0, Some(403), Some(MasqueEncoding::Capsule)));
    assert!(echo.log.entries().is_empty(), "the target saw nothing");
    // A proxy with CONNECT-UDP disabled answers 501: also a refusal, not a transport failure.
    let off = h3server::serve_with("127.0.0.1:0", server_tls(), H3Options { connect_udp: false, ..Default::default() }).await.unwrap();
    let out = masque::run(&masque_plan(off.addr, echo.addr, "", &["never"]), &EventCtx::none(), &CancellationToken::new(), None).await;
    assert_eq!(out.attempts[0].observation.failure.as_ref().unwrap().status, Some(501));
}

#[tokio::test]
async fn connect_udp_fails_before_traffic_without_extended_connect_or_required_datagrams() {
    init();
    let echo = streams::udp("127.0.0.1:0", UdpMode::Echo).await.unwrap();
    let no_ext =
        h3server::serve_with("127.0.0.1:0", server_tls(), H3Options { extended_connect: false, ..Default::default() }).await.unwrap();
    let out = masque::run(&masque_plan(no_ext.addr, echo.addr, "", &["never"]), &EventCtx::none(), &CancellationToken::new(), None).await;
    let f = out.attempts[0].observation.failure.as_ref().unwrap();
    assert_eq!((f.kind, f.phase), (FailureKind::MasqueUnsupported, Phase::ProtocolHandshake));
    assert!(f.message.contains("SETTINGS_ENABLE_CONNECT_PROTOCOL"), "{}", f.message);
    let (_, _, m) = udp_state(&out);
    assert_eq!((m.extended_connect, m.connect_status), (Some(false), None));
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(no_ext.connections(), 1, "the QUIC connection was made");
    assert!(no_ext.log.requests().is_empty(), "but nothing was sent on a request stream");

    let no_dgram = h3server::serve("127.0.0.1:0", server_tls()).await.unwrap();
    let mut plan = masque_plan(no_dgram.addr, echo.addr, "", &["never"]);
    plan.mode = MasqueDatagramMode::QuicDatagrams;
    let out = masque::run(&plan, &EventCtx::none(), &CancellationToken::new(), None).await;
    let f = out.attempts[0].observation.failure.as_ref().unwrap();
    assert_eq!(f.kind, FailureKind::MasqueUnsupported);
    assert!(f.message.contains("SETTINGS_H3_DATAGRAM"), "{}", f.message);
    let (_, _, m) = udp_state(&out);
    assert_eq!((m.extended_connect, m.h3_datagrams), (Some(true), Some(false)));
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(no_dgram.log.requests().is_empty());
    assert!(echo.log.entries().is_empty());
}

#[tokio::test]
async fn connect_udp_silence_reset_and_proxy_close_are_told_apart() {
    init();
    let proxy = h3server::serve("127.0.0.1:0", server_tls()).await.unwrap();
    // Silent target: only "no response observed".
    let silent = streams::udp("127.0.0.1:0", UdpMode::Silent).await.unwrap();
    let out =
        masque::run(&masque_plan(proxy.addr, silent.addr, "", &["anyone?"]), &EventCtx::none(), &CancellationToken::new(), None).await;
    let (sent, got, m) = udp_state(&out);
    assert_eq!((sent, got, m.closed_by), (1, 0, ClosedBy::Client));
    assert!(out.attempts[0].observation.failure.is_none());
    assert_eq!(out.attempts[0].observation.dispatch, DispatchState::MayHaveBeenSent);
    assert!(silent.log.entries().iter().any(|e| matches!(e.event, GroundTruth::DatagramReceived { .. })));

    // The proxy resets the stream after one reply: abnormal, the reply is kept.
    let echo = streams::udp("127.0.0.1:0", UdpMode::Echo).await.unwrap();
    let mut plan = masque_plan(proxy.addr, echo.addr, "?reset_after=1", &["r1"]);
    plan.response_window_ms = 2_000;
    let out = masque::run(&plan, &EventCtx::none(), &CancellationToken::new(), None).await;
    assert!(proxy.log.entries().iter().any(|e| e.event == GroundTruth::FaultApplied { fault: "masque_reset".into() }));
    let (_, got, m) = udp_state(&out);
    assert_eq!((got, m.closed_by), (1, ClosedBy::Abnormal));
    let f = out.attempts[0].observation.failure.as_ref().unwrap();
    assert_eq!((f.kind, f.phase, f.quic_error_code), (FailureKind::BodyReset, Phase::Session, Some(0x102)));
    assert_eq!(received(&out), vec!["r1"]);

    // The proxy finishes the stream after one reply: a proxy close, not a failure.
    let mut plan = masque_plan(proxy.addr, echo.addr, "?fin_after=1", &["f1"]);
    plan.response_window_ms = 2_000;
    let out = masque::run(&plan, &EventCtx::none(), &CancellationToken::new(), None).await;
    let (_, got, m) = udp_state(&out);
    assert_eq!((got, m.closed_by), (1, ClosedBy::Peer));
    assert!(out.attempts[0].observation.failure.is_none());
}

#[tokio::test]
async fn connect_udp_cancel_and_quic_blocked_path() {
    init();
    let proxy = h3server::serve("127.0.0.1:0", server_tls()).await.unwrap();
    let silent = streams::udp("127.0.0.1:0", UdpMode::Silent).await.unwrap();
    let cancel = CancellationToken::new();
    let c2 = cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(300)).await;
        c2.cancel();
    });
    let mut plan = masque_plan(proxy.addr, silent.addr, "", &["x"]);
    plan.response_window_ms = 10_000;
    let out = masque::run(&plan, &EventCtx::none(), &cancel, None).await;
    assert_eq!(out.attempts[0].observation.failure.as_ref().unwrap().kind, FailureKind::Canceled);
    assert_eq!(udp_state(&out).2.closed_by, ClosedBy::Client);

    // No QUIC listener at the proxy address: a QUIC handshake timeout, nothing else.
    let tcp_only = anvil_fixtures::http::serve("127.0.0.1:0", Some(server_tls())).await.unwrap();
    let mut plan = masque_plan(tcp_only.addr, silent.addr, "", &["x"]);
    plan.timeouts.tls_handshake_ms = Some(400);
    let out = masque::run(&plan, &EventCtx::none(), &CancellationToken::new(), None).await;
    assert_eq!(out.attempts[0].observation.failure.as_ref().unwrap().kind, FailureKind::QuicHandshakeTimeout);
    assert!(matches!(out.status, ProtocolStatus::None));
    assert!(!tcp_only.log.saw_connection(), "no TCP fallback");
}
