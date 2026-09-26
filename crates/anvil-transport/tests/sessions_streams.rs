//! Session adapter evidence against real local sockets (no mocks): SSE
//! reconnection and bounded history, UDP ICMP evidence, DTLS stall, and the
//! gRPC adapter used directly (native over HTTP/2 and HTTP/3, gRPC-Web binary
//! and text, malformed gRPC-Web bodies). Matrix IDs are kept in test names.

use anvil_domain::execution::*;
use anvil_domain::outcome::{ClosedBy, GrpcStatusSource, ProtocolStatus};
use anvil_domain::request::{GrpcMode, GrpcWire};
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
        envelope: None,
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
        envelope: None,
        masque: None,
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
        wire: GrpcWire::Grpc,
        version: HttpVersionPolicy::Auto,
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

// ------------------------------------------------- gRPC-Web and gRPC over HTTP/3

fn lab_tls() -> Arc<tls::PreparedTls> {
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

fn echo_plan(
    port: u16,
    tls: bool,
    method: &str,
    mode: GrpcMode,
    message: &str,
    wire: GrpcWire,
    version: HttpVersionPolicy,
) -> grpc::GrpcPlan {
    let pool = grpc::pool_from_proto_sources(&[("echo.proto".into(), anvil_fixtures::grpc::ECHO_PROTO.into())]).unwrap();
    grpc::GrpcPlan {
        tls: tls.then(lab_tls),
        host: "127.0.0.1".into(),
        port,
        authority: format!("127.0.0.1:{port}"),
        path_prefix: String::new(),
        service: "anvil.lab.v1.Echo".into(),
        method: method.into(),
        mode,
        schema: grpc::Schema::Pool(pool),
        messages: vec![message.into()],
        headers: vec![],
        deadline_ms: None,
        timeouts: timeouts(),
        limits: Limits::default(),
        dns: DnsConfig::default(),
        proxy: None,
        display_url: format!("fixture/anvil.lab.v1.Echo/{method}"),
        max_message_bytes: 4 * 1024 * 1024,
        transcript: TranscriptLimits::default(),
        redact: None,
        wire,
        version,
    }
}

fn status_of(out: &anvil_transport::session::SessionOutput) -> (Option<i32>, GrpcStatusSource) {
    match &out.status {
        ProtocolStatus::Grpc { grpc_status, source, .. } => (*grpc_status, *source),
        other => panic!("not gRPC: {other:?}"),
    }
}

fn failure_of(out: &anvil_transport::session::SessionOutput) -> Option<TransportFailure> {
    out.attempts.last().and_then(|a| a.observation.failure.clone())
}

#[tokio::test]
async fn grpc_web_text_adapter_decodes_padded_segments_and_records_the_trailer_frame() {
    init();
    let f = fxhttp::serve("127.0.0.1:0", None).await.unwrap();
    let plan = echo_plan(
        f.addr.port(),
        false,
        "ServerStream",
        GrpcMode::ServerStreaming,
        r#"{"message":"t","count":3,"failWith":9}"#,
        GrpcWire::GrpcWebText,
        HttpVersionPolicy::Auto,
    );
    let out = grpc::run(&plan, &EventCtx::none(), &CancellationToken::new(), None).await;
    assert_eq!(status_of(&out), (Some(9), GrpcStatusSource::TrailerFrame), "{:?}", failure_of(&out));
    let t = out.transcript.as_ref().unwrap();
    assert_eq!(t.received_count, 3, "three messages decoded from independently padded base64 segments");
    assert!(t.messages.iter().any(|m| m.kind == "trailer_frame" && m.preview.contains("grpc-status: 9")));
    let web = out.facts.grpc_web.clone().unwrap();
    assert!(web.text && web.trailer_frame && web.body_complete && !web.status_in_http_trailers, "{web:?}");
    assert_eq!(web.response_content_type.as_deref(), Some("application/grpc-web-text"));
    let a = &out.attempts[0];
    assert_eq!(a.observation.connection.as_ref().unwrap().protocol.as_deref(), Some("http/1.1"), "cleartext gRPC-Web is HTTP/1.1");
    assert_eq!(a.response.as_ref().unwrap().http_version, "HTTP/1.1");
    assert!(a.body.iter().all(|b| b.is_ascii_alphanumeric() || b"+/=".contains(b)), "the captured body is the raw base64 text");
}

#[tokio::test]
async fn grpc_h3_adapter_uses_quic_and_reads_status_from_h3_trailers() {
    init();
    let f =
        anvil_fixtures::h3server::serve("127.0.0.1:0", TlsServerOptions::new(pki().server.chain_with(&pki().ca), pki().server.key.clone()))
            .await
            .unwrap();
    let plan = echo_plan(
        f.addr.port(),
        true,
        "ServerStream",
        GrpcMode::ServerStreaming,
        r#"{"message":"q","count":2}"#,
        GrpcWire::Grpc,
        HttpVersionPolicy::Http3Only,
    );
    let out = grpc::run(&plan, &EventCtx::none(), &CancellationToken::new(), None).await;
    assert_eq!(status_of(&out), (Some(0), GrpcStatusSource::Trailers), "{:?}", failure_of(&out));
    assert_eq!(out.transcript.as_ref().unwrap().received_count, 2);
    let a = &out.attempts[0];
    let conn = a.observation.connection.as_ref().unwrap();
    assert_eq!(conn.protocol.as_deref(), Some("h3"));
    assert!(a.observation.phase(Phase::QuicHandshake).is_some() && a.observation.phase(Phase::TlsHandshake).is_none());
    let r = a.response.as_ref().unwrap();
    assert_eq!(r.http_version, "HTTP/3");
    assert!(r.trailers_received && r.trailers.iter().any(|h| h.name == "grpc-status" && h.value == "0"));
    assert!(out.facts.grpc_web.is_none());
    // gRPC-Web over the same HTTP/3 fixture: status from the trailer frame, not trailers.
    let plan =
        echo_plan(f.addr.port(), true, "Unary", GrpcMode::Unary, r#"{"message":"w"}"#, GrpcWire::GrpcWeb, HttpVersionPolicy::Http3Only);
    let out = grpc::run(&plan, &EventCtx::none(), &CancellationToken::new(), None).await;
    assert_eq!(status_of(&out), (Some(0), GrpcStatusSource::TrailerFrame), "{:?}", failure_of(&out));
    assert!(!out.attempts[0].response.as_ref().unwrap().trailers_received);
}

/// One-shot HTTP/1.1 responder: reads a request (headers + Content-Length
/// body) and answers with `response` verbatim, then closes.
async fn raw_h1(response: Vec<u8>) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        let Ok((mut s, _)) = l.accept().await else { return };
        let mut buf = Vec::new();
        let mut tmp = [0u8; 4096];
        loop {
            let n = s.read(&mut tmp).await.unwrap_or(0);
            if n == 0 {
                return;
            }
            buf.extend_from_slice(&tmp[..n]);
            if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&buf[..end]).to_ascii_lowercase();
                let len: usize =
                    head.lines().find_map(|l| l.strip_prefix("content-length:")).and_then(|v| v.trim().parse().ok()).unwrap_or(0);
                if buf.len() >= end + 4 + len {
                    break;
                }
            }
        }
        let _ = s.write_all(&response).await;
        let _ = s.shutdown().await;
    });
    addr
}

fn web_frame(flag: u8, payload: &[u8]) -> Vec<u8> {
    let mut v = vec![flag];
    v.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    v.extend_from_slice(payload);
    v
}

fn h1_response(content_type: &str, status: u16, body: &[u8]) -> Vec<u8> {
    let mut r =
        format!("HTTP/1.1 {status} X\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n", body.len())
            .into_bytes();
    r.extend_from_slice(body);
    r
}

#[tokio::test]
async fn grpc_web_malformed_bodies_fail_typed_and_are_never_success() {
    init();
    // EchoReply { message: "ok" } as protobuf.
    let msg = web_frame(0, &[0x0a, 0x02, b'o', b'k']);
    let ok_trailer = web_frame(0x80, b"grpc-status: 0\r\n");
    let b64 = |b: &[u8]| {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(b).into_bytes()
    };
    let cases: Vec<(&str, GrpcWire, Vec<u8>, FailureKind, &str)> = vec![
        (
            "data after the trailer frame",
            GrpcWire::GrpcWeb,
            h1_response("application/grpc-web+proto", 200, &[ok_trailer.clone(), msg.clone()].concat()),
            FailureKind::HttpProtocolError,
            "a message frame followed the trailer frame",
        ),
        (
            "a second, appended trailer frame",
            GrpcWire::GrpcWeb,
            h1_response(
                "application/grpc-web+proto",
                200,
                &[msg.clone(), ok_trailer.clone(), web_frame(0x80, b"grpc-status: 2\r\n")].concat(),
            ),
            FailureKind::HttpProtocolError,
            "a second trailer frame (grpc-status 2) followed the first (grpc-status 0)",
        ),
        (
            "compressed trailer frame",
            GrpcWire::GrpcWeb,
            h1_response("application/grpc-web+proto", 200, &web_frame(0x81, b"grpc-status: 0\r\n")),
            FailureKind::HttpProtocolError,
            "0x81",
        ),
        (
            "malformed trailer block",
            GrpcWire::GrpcWeb,
            h1_response("application/grpc-web+proto", 200, &web_frame(0x80, b"grpc-status 0\r\n")),
            FailureKind::HttpProtocolError,
            "trailer frame is malformed",
        ),
        (
            "invalid base64",
            GrpcWire::GrpcWebText,
            h1_response("application/grpc-web-text", 200, b"AAAA*AAA"),
            FailureKind::HttpProtocolError,
            "not valid base64",
        ),
        (
            "base64 truncated inside a quantum",
            GrpcWire::GrpcWebText,
            h1_response("application/grpc-web-text", 200, &[b64(&msg), b"AAA".to_vec()].concat()),
            FailureKind::BodyIncomplete,
            "base64 quantum",
        ),
        (
            "body ends inside a frame",
            GrpcWire::GrpcWeb,
            h1_response("application/grpc-web+proto", 200, &msg[..6]),
            FailureKind::BodyIncomplete,
            "inside a gRPC-Web frame",
        ),
    ];
    for (label, wire, response, kind, needle) in cases {
        let addr = raw_h1(response).await;
        let plan = echo_plan(addr.port(), false, "Unary", GrpcMode::Unary, r#"{"message":"x"}"#, wire, HttpVersionPolicy::Http1Only);
        let out = grpc::run(&plan, &EventCtx::none(), &CancellationToken::new(), None).await;
        let f = failure_of(&out).unwrap_or_else(|| panic!("{label}: expected a failure, got {:?}", out.status));
        assert_eq!(f.kind, kind, "{label}: {f:?}");
        assert!(f.message.contains(needle), "{label}: {}", f.message);
        let body_complete = out.facts.grpc_web.as_ref().map(|w| w.body_complete).unwrap_or(false);
        assert!(!body_complete, "{label}: a failed body is not complete");
        let http_body = out.attempts[0].response.as_ref().unwrap().body.completeness;
        if kind == FailureKind::HttpProtocolError {
            // A framing violation: the HTTP body itself was read to its end.
            assert_eq!(http_body, BodyCompleteness::Complete, "{label}");
            assert_eq!(out.facts.grpc_framing_error.as_deref(), Some(f.message.as_str()), "{label}");
        } else {
            assert_eq!(http_body, BodyCompleteness::Incomplete, "{label}");
            assert!(out.facts.grpc_framing_error.is_none(), "{label}");
        }
    }
    // The trailer frame's grpc-message is percent-decoded and grpc-status-details-bin decoded.
    let details = {
        use base64::Engine;
        // google.rpc.Status { code: 3, message: "bad arg" }
        base64::engine::general_purpose::STANDARD.encode([0x08, 0x03, 0x12, 0x07, b'b', b'a', b'd', b' ', b'a', b'r', b'g'])
    };
    let block = format!("grpc-status: 3\r\ngrpc-message: bad%20arg\r\ngrpc-status-details-bin: {details}\r\n");
    let addr = raw_h1(h1_response("application/grpc-web+proto", 200, &web_frame(0x80, block.as_bytes()))).await;
    let plan = echo_plan(addr.port(), false, "Unary", GrpcMode::Unary, r#"{"message":"x"}"#, GrpcWire::GrpcWeb, HttpVersionPolicy::Auto);
    let out = grpc::run(&plan, &EventCtx::none(), &CancellationToken::new(), None).await;
    assert!(failure_of(&out).is_none(), "{:?}", failure_of(&out));
    match &out.status {
        ProtocolStatus::Grpc { http_status, grpc_status, grpc_message, source } => {
            assert_eq!((*http_status, *grpc_status, *source), (Some(200), Some(3), GrpcStatusSource::TrailerFrame));
            assert_eq!(grpc_message.as_deref(), Some("bad arg"));
        }
        other => panic!("{other:?}"),
    }
    let d = out.facts.grpc_status_details.clone().unwrap_or_default();
    assert!(d.contains("code=3") && d.contains("bad arg"), "{d}");
    // A non-gRPC answer (an intermediary's HTML error) is kept as evidence, not parsed.
    let addr = raw_h1(h1_response("text/html", 502, b"<html>bad gateway</html>")).await;
    let plan = echo_plan(addr.port(), false, "Unary", GrpcMode::Unary, r#"{"message":"x"}"#, GrpcWire::GrpcWeb, HttpVersionPolicy::Auto);
    let out = grpc::run(&plan, &EventCtx::none(), &CancellationToken::new(), None).await;
    assert!(failure_of(&out).is_none(), "{:?}", failure_of(&out));
    assert_eq!(status_of(&out), (None, GrpcStatusSource::Missing));
    assert!(out.facts.notes.iter().any(|n| n.contains("text/html") && n.contains("not parsed")), "{:?}", out.facts.notes);
    assert_eq!(out.attempts[0].body.as_ref(), b"<html>bad gateway</html>");
    assert_eq!(out.attempts[0].response.as_ref().unwrap().status, 502);
}
