//! Session adapter evidence against real local sockets (no mocks): SSE
//! reconnection and bounded history, UDP ICMP evidence, DTLS stall, and the
//! gRPC adapter used directly. Matrix IDs are kept in test names.

use anvil_domain::execution::*;
use anvil_domain::outcome::{ClosedBy, GrpcStatusSource, ProtocolStatus};
use anvil_domain::request::GrpcMode;
use anvil_domain::settings::{HttpVersionPolicy, Limits, Timeouts};
use anvil_fixtures::http as fxhttp;
use anvil_fixtures::streams::{self, UdpMode};
use anvil_fixtures::{LabPki, TlsServerOptions};
use anvil_transport::dns::DnsConfig;
use anvil_transport::recorder::EventCtx;
use anvil_transport::session::TranscriptLimits;
use anvil_transport::tls::{self, TlsSettings};
use anvil_transport::{dtls, grpc, sse, udp};
use bytes::Bytes;
use parking_lot::Mutex;
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

fn init() {
    anvil_transport::init();
    anvil_fixtures::init();
}

fn pki() -> &'static LabPki {
    static P: OnceLock<LabPki> = OnceLock::new();
    P.get_or_init(LabPki::generate)
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

fn sse_plan(addr: SocketAddr, target: &str) -> sse::SsePlan {
    sse::SsePlan {
        method: http::Method::GET,
        https: false,
        host: addr.ip().to_string(),
        port: addr.port(),
        authority: addr.to_string(),
        request_target: target.to_string(),
        headers: vec![],
        body: Bytes::new(),
        version: HttpVersionPolicy::Auto,
        timeouts: timeouts(),
        limits: Limits::default(),
        dns: DnsConfig::default(),
        proxy: None,
        tls: None,
        display_url: format!("http://{addr}{target}"),
        max_events: 0,
        idle_timeout_ms: 3_000,
        last_event_id: None,
        reconnect: false,
        max_reconnects: 0,
        transcript: TranscriptLimits::default(),
        redact: None,
    }
}

/// A real TCP server: the first connection sends two events then drops the
/// stream mid-body (no terminating chunk); later connections record the
/// `Last-Event-ID` they carry and end cleanly after one more event.
async fn flaky_sse_server() -> (SocketAddr, Arc<Mutex<Vec<Option<String>>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen: Arc<Mutex<Vec<Option<String>>>> = Arc::new(Mutex::new(vec![]));
    let s2 = seen.clone();
    tokio::spawn(async move {
        let mut n = 0;
        while let Ok((mut sock, _)) = listener.accept().await {
            n += 1;
            let mut head = Vec::new();
            let mut buf = [0u8; 1024];
            while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                match sock.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(k) => head.extend_from_slice(&buf[..k]),
                }
            }
            let text = String::from_utf8_lossy(&head).to_string();
            let last_id = text.lines().find_map(|l| l.to_ascii_lowercase().strip_prefix("last-event-id:").map(|v| v.trim().to_string()));
            s2.lock().push(last_id);
            let chunk = |s: &str| format!("{:x}\r\n{s}\r\n", s.len());
            let _ = sock.write_all(b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ntransfer-encoding: chunked\r\n\r\n").await;
            if n == 1 {
                let _ = sock.write_all(chunk("retry: 50\nid: 1\ndata: one\n\nid: 2\ndata: two\n\ndata: partial-").as_bytes()).await;
                let _ = sock.flush().await;
                tokio::time::sleep(std::time::Duration::from_millis(30)).await;
                drop(sock); // abnormal end: no terminating chunk
            } else {
                let _ = sock.write_all(chunk("id: 3\ndata: three\n\n").as_bytes()).await;
                let _ = sock.write_all(b"0\r\n\r\n").await;
                let _ = sock.flush().await;
            }
        }
    });
    (addr, seen)
}

#[tokio::test]
async fn sse_reconnects_only_when_enabled_with_last_event_id() {
    init();
    let (addr, seen) = flaky_sse_server().await;
    let mut plan = sse_plan(addr, "/events");
    plan.reconnect = true;
    plan.max_reconnects = 3;
    let out = sse::run(&plan, &EventCtx::none(), &CancellationToken::new(), None).await;
    assert_eq!(out.attempts.len(), 2, "one abnormal end, one reconnection");
    let first = &out.attempts[0];
    assert!(matches!(first.observation.failure.as_ref().map(|f| f.kind), Some(FailureKind::BodyIncomplete)));
    assert_eq!(first.response.as_ref().unwrap().body.completeness, BodyCompleteness::Incomplete);
    let second = &out.attempts[1].observation;
    assert_eq!(second.reason, AttemptReason::Retry { after: FailureKind::BodyIncomplete });
    assert!(second.failure.is_none());
    assert_eq!(*seen.lock(), vec![None, Some("2".to_string())], "Last-Event-ID carried the last complete event id");
    let t = out.transcript.unwrap();
    let data: Vec<&str> = t.messages.iter().map(|m| m.preview.as_str()).collect();
    assert_eq!(data, vec!["one", "two", "three"], "the partial event from the broken stream is discarded");
    assert!(matches!(out.status, ProtocolStatus::Sse { events: 3, closed_by: ClosedBy::Peer, .. }));
    assert!(out.facts.notes.iter().any(|n| n.contains("reconnecting after an abnormal end in 50 ms")), "{:?}", out.facts.notes);

    // Reconnection is off by default: the abnormal end is simply recorded.
    let (addr, seen) = flaky_sse_server().await;
    let out = sse::run(&sse_plan(addr, "/events"), &EventCtx::none(), &CancellationToken::new(), None).await;
    assert_eq!(out.attempts.len(), 1);
    assert_eq!(seen.lock().len(), 1);
    assert!(matches!(out.status, ProtocolStatus::Sse { events: 2, closed_by: ClosedBy::Abnormal, .. }));
}

#[tokio::test]
async fn proto_018_sse_history_is_bounded_but_counted() {
    init();
    let f = fxhttp::serve("127.0.0.1:0", None).await.unwrap();
    let mut plan = sse_plan(f.addr, "/sse?count=300&interval=0");
    plan.transcript = TranscriptLimits { max_messages: 10, preview_bytes: 64 };
    let out = sse::run(&plan, &EventCtx::none(), &CancellationToken::new(), None).await;
    let t = out.transcript.unwrap();
    assert_eq!(t.received_count, 300);
    assert_eq!(t.messages.len(), 10);
    assert_eq!(t.dropped_messages, 290);
    assert_eq!(t.messages.first().unwrap().event_id.as_deref(), Some("0"));
    assert_eq!(t.messages.last().unwrap().event_id.as_deref(), Some("299"), "the most recent events are kept");
    let captured = out.attempts[0].response.as_ref().unwrap().body.captured_bytes;
    assert!(captured <= Limits::default().capture_bytes);
}

#[tokio::test]
async fn proto_020_udp_icmp_unreachable_is_recorded_as_such() {
    init();
    // A port that was just released: nothing listens there.
    let port = std::net::UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let plan = udp::UdpPlan {
        host: "127.0.0.1".into(),
        port,
        dns: DnsConfig::default(),
        timeouts: timeouts(),
        datagrams: vec![Bytes::from_static(b"one"), Bytes::from_static(b"two")],
        response_window_ms: 300,
        max_datagrams: 10,
        display_url: format!("udp://127.0.0.1:{port}"),
        transcript: TranscriptLimits::default(),
        redact: None,
    };
    let out = udp::run(&plan, &EventCtx::none(), &CancellationToken::new(), None).await;
    assert!(matches!(out.status, ProtocolStatus::Udp { datagrams_received: 0, .. }));
    let t = out.transcript.unwrap();
    if cfg!(unix) {
        assert!(out.facts.icmp_port_unreachable, "loopback ICMP port-unreachable is reported to a connected socket");
        assert!(t.messages.iter().any(|m| m.kind == "icmp_port_unreachable"));
    }
    assert!(out.attempts[0].observation.failure.is_none(), "silence/ICMP is evidence, not a transport failure");
}

#[tokio::test]
async fn proto_022_dtls_to_a_non_dtls_listener_times_out_with_a_deadline() {
    init();
    let silent = streams::udp("127.0.0.1:0", UdpMode::Silent).await.unwrap();
    let prepared = Arc::new(
        tls::prepare(&TlsSettings {
            verify: true,
            use_system_roots: false,
            extra_roots_pem: vec![pki().ca.cert.clone()],
            ..Default::default()
        })
        .unwrap(),
    );
    let mut t = timeouts();
    t.tls_handshake_ms = Some(600);
    let plan = dtls::DtlsPlan {
        host: "127.0.0.1".into(),
        port: silent.addr.port(),
        dns: DnsConfig::default(),
        timeouts: t,
        tls: prepared,
        identity: None,
        datagrams: vec![Bytes::from_static(b"hi")],
        response_window_ms: 200,
        max_datagrams: 10,
        display_url: format!("dtls://{}", silent.addr),
        transcript: TranscriptLimits::default(),
        redact: None,
    };
    let out = dtls::run(&plan, &EventCtx::none(), &CancellationToken::new(), None).await;
    let f = out.attempts[0].observation.failure.as_ref().unwrap();
    assert_eq!(f.kind, FailureKind::DtlsHandshakeTimeout);
    assert_eq!(f.deadline_ms, Some(600));
    assert_eq!(out.attempts[0].observation.dispatch, DispatchState::NotDispatched, "no application datagram was sent");
    assert!(out.transcript.is_none());
    let p = out.attempts[0].observation.phase(Phase::DtlsHandshake).unwrap();
    assert_eq!(p.status, PhaseStatus::TimedOut);
    // Ground truth: the handshake datagrams did reach the listener.
    assert!(silent.log.entries().iter().any(|e| matches!(e.event, anvil_fixtures::GroundTruth::DatagramReceived { .. })));
}

#[tokio::test]
async fn proto_016_grpc_adapter_with_a_compiled_proto_and_trailers() {
    init();
    let f = fxhttp::serve("127.0.0.1:0", Some(TlsServerOptions::new(pki().server.chain_with(&pki().ca), pki().server.key.clone())))
        .await
        .unwrap();
    let pool = grpc::pool_from_proto_sources(&[("echo.proto".into(), anvil_fixtures::grpc::ECHO_PROTO.into())]).unwrap();
    let prepared = Arc::new(
        tls::prepare(&TlsSettings {
            verify: true,
            use_system_roots: false,
            extra_roots_pem: vec![pki().ca.cert.clone()],
            ..Default::default()
        })
        .unwrap(),
    );
    let plan = grpc::GrpcPlan {
        tls: Some(prepared),
        host: "127.0.0.1".into(),
        port: f.addr.port(),
        authority: format!("127.0.0.1:{}", f.addr.port()),
        path_prefix: String::new(),
        service: "anvil.lab.v1.Echo".into(),
        method: "ServerStream".into(),
        mode: GrpcMode::ServerStreaming,
        schema: grpc::Schema::Pool(pool),
        messages: vec![r#"{"message":"m","count":3,"failWith":5}"#.into()],
        headers: vec![],
        deadline_ms: Some(5_000),
        timeouts: timeouts(),
        limits: Limits::default(),
        dns: DnsConfig::default(),
        proxy: None,
        display_url: "grpcs://fixture/anvil.lab.v1.Echo/ServerStream".into(),
        max_message_bytes: 4 * 1024 * 1024,
        transcript: TranscriptLimits::default(),
        redact: None,
    };
    let out = grpc::run(&plan, &EventCtx::none(), &CancellationToken::new(), None).await;
    match &out.status {
        ProtocolStatus::Grpc { http_status, grpc_status, grpc_message, source } => {
            assert_eq!(*http_status, Some(200));
            assert_eq!(*grpc_status, Some(5), "status after streamed messages");
            assert_eq!(grpc_message.as_deref(), Some("fixture requested failure"));
            assert_eq!(*source, GrpcStatusSource::Trailers);
        }
        other => panic!("{other:?}"),
    }
    let t = out.transcript.unwrap();
    assert_eq!(t.received_count, 3, "three messages with boundaries preserved before the error status");
    assert!(t.messages.iter().any(|m| m.kind == "status" && m.preview.starts_with("grpc-status 5")));
    let r = out.attempts[0].response.as_ref().unwrap();
    assert!(r.trailers_received && r.trailers.iter().any(|h| h.name == "grpc-status" && h.value == "5"));
    let conn = out.attempts[0].observation.connection.as_ref().unwrap();
    assert_eq!(conn.protocol.as_deref(), Some("h2"));
    assert_eq!(conn.tls.as_ref().unwrap().verification, TlsVerification::Verified);
}
