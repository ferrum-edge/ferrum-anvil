//! Session adapter evidence against real local sockets (no mocks): SSE
//! reconnection, per-send signing and bounded history, UDP ICMP evidence,
//! DTLS stall, and the gRPC adapter used directly (native over HTTP/2 and
//! HTTP/3, gRPC-Web binary and text, malformed gRPC-Web bodies). Matrix IDs
//! are kept in test names.

use anvil_domain::Id;
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
use std::sync::atomic::{AtomicUsize, Ordering};
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
        proxy_header: None,
        method: http::Method::GET,
        https: false,
        host: addr.ip().to_string(),
        port: addr.port(),
        authority: addr.to_string(),
        request_target: target.to_string(),
        headers: vec![],
        sign: None,
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

/// A signer that signs the first `ok` sends (`x-send: <n>`) and refuses
/// every later one, counting the sends it was asked to sign in `calls`.
fn counting_signer(ok: usize, calls: Arc<AtomicUsize>) -> sse::SignFn {
    Arc::new(move || {
        let n = calls.fetch_add(1, Ordering::SeqCst) + 1;
        if n > ok {
            return Err(TransportFailure::new(
                Phase::Prepare,
                FailureKind::AuthPreparationFailed,
                format!("the test signer refused send {n}"),
            ));
        }
        Ok(vec![(http::HeaderName::from_static("x-send"), http::HeaderValue::from(n))])
    })
}

#[tokio::test]
async fn sse_signs_each_send_and_a_send_that_cannot_be_signed_is_not_made() {
    init();
    // Each send is signed: the initial one and the reconnection.
    let (addr, seen) = flaky_sse_server().await;
    let calls = Arc::new(AtomicUsize::new(0));
    let mut plan = sse_plan(addr, "/events");
    plan.reconnect = true;
    plan.max_reconnects = 3;
    plan.sign = Some(counting_signer(usize::MAX, calls.clone()));
    let out = sse::run(&plan, &EventCtx::none(), &CancellationToken::new(), None).await;
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(out.attempts.len(), 2);
    assert_eq!(*seen.lock(), vec![None, Some("2".to_string())], "the reconnection still sends Last-Event-ID");
    assert!(matches!(out.status, ProtocolStatus::Sse { events: 3, closed_by: ClosedBy::Peer, .. }));

    // A reconnection that cannot be signed again is not made, and the
    // session ends as the abnormal end it was, with a note.
    let (addr, seen) = flaky_sse_server().await;
    let calls = Arc::new(AtomicUsize::new(0));
    plan = sse_plan(addr, "/events");
    plan.reconnect = true;
    plan.max_reconnects = 3;
    plan.sign = Some(counting_signer(1, calls.clone()));
    let out = sse::run(&plan, &EventCtx::none(), &CancellationToken::new(), None).await;
    assert_eq!(calls.load(Ordering::SeqCst), 2, "the reconnection was signed before it would be sent");
    assert_eq!(out.attempts.len(), 1, "the reconnection was not made");
    assert_eq!(seen.lock().len(), 1, "the server saw the initial send only");
    assert!(matches!(out.status, ProtocolStatus::Sse { events: 2, closed_by: ClosedBy::Abnormal, .. }));
    let note = "not reconnected: auth could not sign the reconnection again (the test signer refused send 2)";
    assert!(out.facts.notes.iter().any(|n| n == note), "{:?}", out.facts.notes);

    // An initial send that cannot be signed is not made.
    let (addr, seen) = flaky_sse_server().await;
    plan = sse_plan(addr, "/events");
    plan.sign = Some(counting_signer(0, Arc::new(AtomicUsize::new(0))));
    let out = sse::run(&plan, &EventCtx::none(), &CancellationToken::new(), None).await;
    assert_eq!(out.attempts.len(), 1);
    let a = &out.attempts[0];
    assert!(a.response.is_none());
    assert_eq!(a.observation.dispatch, DispatchState::NotDispatched);
    assert_eq!(a.observation.failure.as_ref().map(|f| f.kind), Some(FailureKind::AuthPreparationFailed));
    assert!(seen.lock().is_empty());
    assert!(out.transcript.is_none());

    // The TCP fallback after HTTP/3 is signed, and is not made when it
    // cannot be. Here HTTP/3 is refused before traffic (the URL is http://),
    // so only the fallback is signed.
    for (ok, fell_back) in [(usize::MAX, true), (0, false)] {
        let (addr, seen) = flaky_sse_server().await;
        let calls = Arc::new(AtomicUsize::new(0));
        plan = sse_plan(addr, "/events");
        plan.version = HttpVersionPolicy::Http3WithFallback;
        plan.sign = Some(counting_signer(ok, calls.clone()));
        let out = sse::run(&plan, &EventCtx::none(), &CancellationToken::new(), None).await;
        assert_eq!(calls.load(Ordering::SeqCst), 1, "only the fallback, which could be sent, was signed");
        assert_eq!(out.attempts[0].observation.failure.as_ref().map(|f| f.kind), Some(FailureKind::UnsupportedCombination));
        if fell_back {
            assert_eq!(out.attempts.len(), 2);
            assert_eq!(out.attempts[1].observation.reason, AttemptReason::ProtocolFallback { from: "h3".into() });
            assert_eq!(seen.lock().len(), 1);
        } else {
            assert_eq!(out.attempts.len(), 1, "the fallback was not made");
            assert!(seen.lock().is_empty());
            let note = "; not sent over TCP: auth could not sign it again (the test signer refused send 1)";
            assert!(out.facts.notes.iter().any(|n| n.ends_with(note)), "{:?}", out.facts.notes);
        }
    }
}

#[tokio::test]
async fn sse_a_forced_http3_send_refused_before_traffic_is_not_signed() {
    init();
    // Forced HTTP/3 needs an https:// URL: the loop's version check refuses
    // it before anything is sent, so no signature is made (or recorded).
    let (addr, seen) = flaky_sse_server().await;
    let calls = Arc::new(AtomicUsize::new(0));
    let mut plan = sse_plan(addr, "/events");
    plan.version = HttpVersionPolicy::Http3Only;
    plan.reconnect = true;
    plan.max_reconnects = 3;
    plan.sign = Some(counting_signer(usize::MAX, calls.clone()));
    let out = sse::run(&plan, &EventCtx::none(), &CancellationToken::new(), None).await;
    assert_eq!(calls.load(Ordering::SeqCst), 0, "a send that is refused is not signed");
    assert_eq!(out.attempts.len(), 1);
    let a = &out.attempts[0].observation;
    assert_eq!(a.dispatch, DispatchState::NotDispatched);
    assert_eq!(a.failure.as_ref().map(|f| f.kind), Some(FailureKind::UnsupportedCombination));
    assert!(seen.lock().is_empty());
    assert!(out.transcript.is_none());
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
    let mut clean_attempt = false;
    for _ in 0..5 {
        // A parallel test can claim the released port, so retry any attempt
        // that receives a reply using a fresh port and unique random payload.
        let closed = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = closed.local_addr().unwrap().port();
        let payload = Id::new().to_string();
        let plan = udp::UdpPlan {
            host: "127.0.0.1".into(),
            port,
            dns: DnsConfig::default(),
            timeouts: timeouts(),
            datagrams: vec![Bytes::from(payload.into_bytes())],
            response_window_ms: 300,
            max_datagrams: 10,
            display_url: format!("udp://127.0.0.1:{port}"),
            transcript: TranscriptLimits::default(),
            redact: None,
            envelope: None,
        };
        drop(closed);
        let out = udp::run(&plan, &EventCtx::none(), &CancellationToken::new(), None).await;
        if matches!(&out.status, ProtocolStatus::Udp { datagrams_received, .. } if *datagrams_received > 0) {
            continue;
        }
        assert!(matches!(&out.status, ProtocolStatus::Udp { datagrams_received: 0, .. }), "{:?}", out.status);
        let t = out.transcript.unwrap();
        if cfg!(unix) {
            assert!(out.facts.icmp_port_unreachable, "loopback ICMP port-unreachable is reported to a connected socket");
            assert!(t.messages.iter().any(|m| m.kind == "icmp_port_unreachable"));
        }
        assert!(out.attempts[0].observation.failure.is_none(), "silence/ICMP is evidence, not a transport failure");
        clean_attempt = true;
        break;
    }
    assert!(clean_attempt, "all five released-port attempts received foreign UDP replies");
}

#[tokio::test]
async fn udp_pre_canceled_attempt_sends_nothing() {
    init();
    let echo = streams::udp("127.0.0.1:0", UdpMode::Echo).await.unwrap();
    let plan = |payload: &str| udp::UdpPlan {
        host: "127.0.0.1".into(),
        port: echo.addr.port(),
        dns: DnsConfig::default(),
        timeouts: timeouts(),
        datagrams: vec![Bytes::from(payload.to_string().into_bytes())],
        response_window_ms: 300,
        max_datagrams: 10,
        display_url: format!("udp://{}", echo.addr),
        transcript: TranscriptLimits::default(),
        redact: None,
        envelope: None,
    };
    // Positive control: an uncanceled attempt is sent and echoed.
    let live = Id::new().to_string();
    let out = udp::run(&plan(&live), &EventCtx::none(), &CancellationToken::new(), None).await;
    assert!(matches!(&out.status, ProtocolStatus::Udp { datagrams_received: 1, .. }), "{:?}", out.status);
    // Pre-canceled: setup itself is guarded, so nothing reaches the listener.
    let dead = Id::new().to_string();
    let cancel = CancellationToken::new();
    cancel.cancel();
    let out = udp::run(&plan(&dead), &EventCtx::none(), &cancel, None).await;
    let f = out.attempts[0].observation.failure.as_ref().unwrap();
    assert_eq!(f.kind, FailureKind::Canceled);
    assert_eq!(out.attempts[0].observation.dispatch, DispatchState::NotDispatched);
    let received = echo.log.entries().iter().filter(|e| matches!(e.event, anvil_fixtures::GroundTruth::DatagramReceived { .. })).count();
    assert_eq!(received, 1, "only the uncanceled datagram arrived");
}

/// Cancellation after setup wins over an interactive command that is
/// already queued: the command's datagram is never sent (#366).
#[tokio::test]
async fn udp_cancel_after_setup_beats_a_queued_interactive_send() {
    use anvil_domain::events::{ExecutionEvent, SessionCommand};
    init();
    let echo = streams::udp("127.0.0.1:0", UdpMode::Echo).await.unwrap();
    let plan = udp::UdpPlan {
        host: "127.0.0.1".into(),
        port: echo.addr.port(),
        dns: DnsConfig::default(),
        timeouts: timeouts(),
        datagrams: vec![],
        response_window_ms: 300,
        max_datagrams: 10,
        display_url: format!("udp://{}", echo.addr),
        transcript: TranscriptLimits::default(),
        redact: None,
        envelope: None,
    };
    for _ in 0..20 {
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        tx.send(SessionCommand::SendText { text: Id::new().to_string() }).await.unwrap();
        tx.send(SessionCommand::SendBinaryHex { hex: "00ff".into() }).await.unwrap();
        let cancel = CancellationToken::new();
        let c = cancel.clone();
        // Cancel the moment the exchange phase starts (socket set up, no
        // datagram sent yet), with both commands already queued.
        let events = EventCtx {
            execution_id: Id::new(),
            sink: Some(Arc::new(move |ev: ExecutionEvent| {
                if let ExecutionEvent::Phase { phase: Phase::Session, .. } = ev {
                    c.cancel();
                }
            })),
        };
        let out = udp::run(&plan, &events, &cancel, Some(rx)).await;
        let o = &out.attempts[0].observation;
        assert_eq!(o.failure.as_ref().map(|f| f.kind), Some(FailureKind::Canceled));
        assert_eq!(o.dispatch, DispatchState::NotDispatched);
        assert!(matches!(&out.status, ProtocolStatus::Udp { datagrams_sent: 0, .. }), "{:?}", out.status);
        drop(tx);
    }
    let received = echo.log.entries().iter().filter(|e| matches!(e.event, anvil_fixtures::GroundTruth::DatagramReceived { .. })).count();
    assert_eq!(received, 0, "no queued command was sent after cancellation");
}

fn udp_plan(port: u16, response_window_ms: u64, max_datagrams: u32, datagrams: Vec<Bytes>) -> udp::UdpPlan {
    udp::UdpPlan {
        host: "127.0.0.1".into(),
        port,
        dns: DnsConfig::default(),
        timeouts: timeouts(),
        datagrams,
        response_window_ms,
        max_datagrams,
        display_url: format!("udp://127.0.0.1:{port}"),
        transcript: TranscriptLimits::default(),
        redact: None,
        envelope: None,
    }
}

/// A peer that keeps sending cannot hold the exchange open past its
/// response window: window expiry is checked before another receive.
#[tokio::test]
async fn udp_response_window_ends_a_busy_receiver() {
    init();
    let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = peer.local_addr().unwrap().port();
    let flood = tokio::spawn(async move {
        let mut buf = [0u8; 64];
        let (_, client) = peer.recv_from(&mut buf).await.unwrap();
        loop {
            if peer.send_to(b"flood", client).await.is_err() {
                return;
            }
            tokio::task::yield_now().await;
        }
    });
    let started = std::time::Instant::now();
    let out =
        udp::run(&udp_plan(port, 300, 10_000_000, vec![Bytes::from_static(b"go")]), &EventCtx::none(), &CancellationToken::new(), None)
            .await;
    let elapsed = started.elapsed();
    flood.abort();
    assert!(out.attempts[0].observation.failure.is_none(), "{:?}", out.attempts[0].observation.failure);
    assert!(elapsed < std::time::Duration::from_secs(5), "the window did not end the exchange: {elapsed:?}");
}

/// A command queue that is kept full does not starve reply capture.
#[tokio::test]
async fn udp_sustained_commands_do_not_starve_replies() {
    use anvil_domain::events::SessionCommand;
    init();
    let echo = streams::udp("127.0.0.1:0", UdpMode::Echo).await.unwrap();
    let (tx, rx) = tokio::sync::mpsc::channel(64);
    let producer = tokio::spawn(async move {
        for i in 0..2_000 {
            if tx.send(SessionCommand::SendText { text: format!("m{i}") }).await.is_err() {
                return;
            }
        }
        let _ = tx.send(SessionCommand::Close { code: 1000, reason: String::new() }).await;
    });
    let out = udp::run(&udp_plan(echo.addr.port(), 300, 100_000, vec![]), &EventCtx::none(), &CancellationToken::new(), Some(rx)).await;
    producer.abort();
    match &out.status {
        ProtocolStatus::Udp { datagrams_sent, datagrams_received, .. } => {
            assert!(*datagrams_sent > 0);
            assert!(*datagrams_received > 0, "replies were captured while commands kept arriving");
        }
        s => panic!("{s:?}"),
    }
}

/// After a completed handshake, the total deadline ends the exchange as a
/// TotalTimeout even while the response window is still open, and no
/// close_notify is written after it.
#[tokio::test]
async fn dtls_total_deadline_ends_the_application_exchange() {
    init();
    let f = anvil_fixtures::dtls::serve(
        "127.0.0.1:0",
        anvil_fixtures::dtls::DtlsServerOptions {
            cert_pem: pki().server.cert.clone(),
            key_pem: pki().server.key.clone(),
            client_ca_pem: None,
        },
    )
    .await
    .unwrap();
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
    t.total_ms = Some(1_500);
    let plan = dtls::DtlsPlan {
        host: "127.0.0.1".into(),
        port: f.addr.port(),
        dns: DnsConfig::default(),
        timeouts: t,
        tls: prepared,
        identity: None,
        datagrams: vec![Bytes::from_static(b"hi")],
        response_window_ms: 10_000,
        max_datagrams: 10,
        display_url: format!("dtls://{}", f.addr),
        transcript: TranscriptLimits::default(),
        redact: None,
        envelope: None,
        masque: None,
        hbone: None,
    };
    let started = std::time::Instant::now();
    let out = dtls::run(&plan, &EventCtx::none(), &CancellationToken::new(), None).await;
    let elapsed = started.elapsed();
    let o = &out.attempts[0].observation;
    assert_eq!(o.phase(Phase::DtlsHandshake).unwrap().status, PhaseStatus::Completed);
    let fl = o.failure.as_ref().expect("the total deadline ends the exchange");
    assert_eq!(fl.kind, FailureKind::TotalTimeout);
    assert_eq!(fl.phase, Phase::Session);
    assert_eq!(fl.deadline_ms, Some(1_500));
    assert!(elapsed < std::time::Duration::from_millis(2_500), "{elapsed:?}");
    let transcript = out.transcript.as_ref().unwrap();
    assert!(!transcript.messages.iter().any(|m| m.kind == "close_notify"), "no close_notify after the deadline");
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
        hbone: None,
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

/// The DTLS total deadline bounds the whole attempt: a resolver that never
/// answers and a listener that never completes the handshake both end at
/// `total_ms`, well before their own (longer) phase timeouts (#366).
#[tokio::test]
async fn dtls_total_deadline_bounds_setup_and_handshake() {
    use anvil_domain::settings::ResolverMode;
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
    let plan = |host: &str, dns: DnsConfig| {
        let mut t = timeouts();
        t.dns_ms = Some(5_000);
        t.tls_handshake_ms = Some(5_000);
        t.total_ms = Some(400);
        dtls::DtlsPlan {
            host: host.into(),
            port: silent.addr.port(),
            dns,
            timeouts: t,
            tls: prepared.clone(),
            identity: None,
            datagrams: vec![Bytes::from_static(b"hi")],
            response_window_ms: 200,
            max_datagrams: 10,
            display_url: format!("dtls://{host}:{}", silent.addr.port()),
            transcript: TranscriptLimits::default(),
            redact: None,
            envelope: None,
            masque: None,
            hbone: None,
        }
    };
    // Delayed DNS: the configured nameserver never answers.
    let dns = DnsConfig { resolver: ResolverMode::Custom { nameservers: vec![silent.addr.to_string()] }, ..Default::default() };
    let started = std::time::Instant::now();
    let out = dtls::run(&plan("never-answers.anvil.test", dns), &EventCtx::none(), &CancellationToken::new(), None).await;
    let elapsed = started.elapsed();
    let f = out.attempts[0].observation.failure.as_ref().unwrap();
    assert_eq!(f.phase, Phase::Dns, "{f:?}");
    assert!(matches!(f.kind, FailureKind::TotalTimeout | FailureKind::DnsTimeout), "{f:?}");
    assert!(elapsed < std::time::Duration::from_millis(2_500), "setup ran past the total deadline: {elapsed:?}");
    // Delayed handshake: the listener never answers the handshake.
    let started = std::time::Instant::now();
    let out = dtls::run(&plan("127.0.0.1", DnsConfig::default()), &EventCtx::none(), &CancellationToken::new(), None).await;
    let elapsed = started.elapsed();
    let o = &out.attempts[0].observation;
    let f = o.failure.as_ref().unwrap();
    assert_eq!(f.kind, FailureKind::TotalTimeout, "{f:?}");
    assert_eq!(f.phase, Phase::DtlsHandshake);
    assert_eq!(f.deadline_ms, Some(400));
    assert_eq!(o.dispatch, DispatchState::NotDispatched);
    assert!(elapsed < std::time::Duration::from_millis(2_500), "the handshake ran past the total deadline: {elapsed:?}");
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
        proxy_header: None,
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
        sign: None,
        sign_reflection: None,
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
        channels: None,
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
        proxy_header: None,
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
        sign: None,
        sign_reflection: None,
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
        channels: None,
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

#[tokio::test]
async fn a_reflection_request_auth_cannot_sign_is_not_sent_and_is_reported_as_an_auth_failure() {
    init();
    let f = fxhttp::serve("127.0.0.1:0", None).await.unwrap();
    let mut plan = echo_plan(f.addr.port(), false, "Unary", GrpcMode::Unary, "{}", GrpcWire::Grpc, HttpVersionPolicy::Auto);
    plan.schema = grpc::Schema::Reflection;
    let refuse: grpc::SignFn = Arc::new(|_: &str, _: &Bytes| -> Result<Vec<(http::HeaderName, http::HeaderValue)>, TransportFailure> {
        Err(TransportFailure::new(Phase::Prepare, FailureKind::AuthPreparationFailed, "the signing key is not usable"))
    });
    plan.sign_reflection = Some(refuse);
    let out = grpc::run(&plan, &EventCtx::none(), &CancellationToken::new(), None).await;
    let r = out.facts.grpc_reflection.clone().expect("no reflection outcome");
    assert!(!r.succeeded && r.auth_failed, "{r:?}");
    let problem = r.problem.unwrap_or_default();
    assert!(problem.contains("auth could not be prepared for the reflection request"), "{problem}");
    assert!(problem.contains("the signing key is not usable") && !problem.contains("transport level"), "{problem}");
    assert_eq!(failure_of(&out).map(|f| f.kind), Some(FailureKind::AuthPreparationFailed));
    let sent = f.log.requests();
    assert!(!sent.iter().any(|(_, p)| p.starts_with("/grpc.reflection.") || p.starts_with("/anvil.lab.v1.")), "{sent:?}");
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
