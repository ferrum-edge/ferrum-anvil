//! The WebSocket bootstrap stays within the attempt's total deadline (#389):
//! a peer that withholds the SETTINGS enabling extended CONNECT (HTTP/2 and
//! HTTP/3), and a rejected handshake whose response body is held open or
//! trickled (HTTP/1.1 and HTTP/3), end at `total_ms`, long before the
//! per-phase timeouts (5 s SETTINGS wait, 30 s or reset body idle).

use anvil_domain::execution::*;
use anvil_domain::request::WsBootstrap;
use anvil_domain::settings::{Limits, Timeouts};
use anvil_fixtures::h3raw::{self, Answer, DATA, End, HEADERS};
use anvil_fixtures::{LabPki, TlsServerOptions};
use anvil_transport::dns::DnsConfig;
use anvil_transport::recorder::EventCtx;
use anvil_transport::session::{SessionOutput, TranscriptLimits};
use anvil_transport::tls::{self, PreparedTls, TlsSettings};
use anvil_transport::ws;
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

const TOTAL_MS: u64 = 800;
/// Room for setup, far below the per-phase timeouts the old code waited for.
const WITHIN_BUDGET: Duration = Duration::from_millis(2_500);
const GIVE_UP: Duration = Duration::from_secs(20);

fn init() {
    anvil_transport::init();
    anvil_fixtures::init();
}

fn pki() -> &'static LabPki {
    static P: OnceLock<LabPki> = OnceLock::new();
    P.get_or_init(LabPki::generate)
}

fn client_tls() -> Arc<PreparedTls> {
    let settings =
        TlsSettings { verify: true, use_system_roots: false, extra_roots_pem: vec![pki().ca.cert.clone()], ..Default::default() };
    Arc::new(tls::prepare(&settings).expect("tls profile"))
}

fn server_tls() -> TlsServerOptions {
    TlsServerOptions::new(pki().server.chain_with(&pki().ca), pki().server.key.clone())
}

fn plan(addr: SocketAddr, bootstrap: WsBootstrap, body_idle_ms: u64) -> ws::WsPlan {
    let secure = bootstrap == WsBootstrap::Http3ExtendedConnect;
    ws::WsPlan {
        bootstrap,
        secure,
        host: addr.ip().to_string(),
        port: addr.port(),
        authority: addr.to_string(),
        request_target: "/ws".into(),
        headers: vec![],
        subprotocols: vec![],
        deflate: None,
        script: vec![],
        expect_messages: 0,
        idle_close_ms: 5_000,
        max_message_bytes: 1 << 20,
        timeouts: Timeouts {
            dns_ms: Some(2_000),
            connect_ms: Some(5_000),
            tls_handshake_ms: Some(5_000),
            request_write_ms: Some(5_000),
            response_headers_ms: Some(10_000),
            body_idle_ms: Some(body_idle_ms),
            total_ms: Some(TOTAL_MS),
        },
        limits: Limits::default(),
        dns: DnsConfig::default(),
        proxy: None,
        tls: secure.then(client_tls),
        display_url: format!("{}://{addr}/ws", if secure { "wss" } else { "ws" }),
        transcript: TranscriptLimits::default(),
        redact: None,
        proxy_header: None,
    }
}

async fn timed_run(p: &ws::WsPlan) -> (SessionOutput, Duration) {
    let started = std::time::Instant::now();
    let out = tokio::time::timeout(GIVE_UP, ws::run(p, &EventCtx::none(), &CancellationToken::new(), None))
        .await
        .expect("the WebSocket attempt did not end");
    (out, started.elapsed())
}

/// A plaintext HTTP/2 peer whose SETTINGS never enable extended CONNECT
/// (RFC 8441) and which answers nothing.
async fn h2_without_extended_connect() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                let Ok(mut conn) = h2::server::handshake(sock).await else { return };
                // Drive the connection (SETTINGS, pings) and never answer.
                while let Some(Ok(_)) = conn.accept().await {}
            });
        }
    });
    addr
}

/// A plaintext HTTP/1.1 peer that rejects the upgrade with 403 and one byte
/// of chunked body, then holds the body open (`drip` = None) or sends one
/// more byte every `drip`.
async fn h1_rejecting(drip: Option<Duration>) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                let mut seen = Vec::new();
                while !seen.windows(4).any(|w| w == b"\r\n\r\n") {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => seen.extend_from_slice(&buf[..n]),
                    }
                }
                let head = b"HTTP/1.1 403 Forbidden\r\ncontent-type: text/plain\r\ntransfer-encoding: chunked\r\n\r\n1\r\nx\r\n";
                if sock.write_all(head).await.is_err() {
                    return;
                }
                loop {
                    match drip {
                        Some(every) => {
                            tokio::time::sleep(every).await;
                            if sock.write_all(b"1\r\nx\r\n").await.is_err() {
                                return;
                            }
                        }
                        None => {
                            if sock.read(&mut buf).await.map(|n| n == 0).unwrap_or(true) {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });
    addr
}

fn assert_settings_deadline(out: &SessionOutput, elapsed: Duration) {
    let f = out.attempts[0].observation.failure.as_ref().expect("the bootstrap failed");
    assert_eq!((f.kind, f.phase), (FailureKind::TotalTimeout, Phase::ProtocolHandshake), "{f:?}");
    assert_eq!(f.deadline_ms, Some(TOTAL_MS));
    assert_eq!(out.attempts[0].observation.dispatch, DispatchState::NotDispatched);
    assert!(elapsed < WITHIN_BUDGET, "the SETTINGS wait ran past the total deadline: {elapsed:?}");
}

fn assert_rejection_deadline(out: &SessionOutput, elapsed: Duration, status: u16) {
    let a = &out.attempts[0];
    let o = &a.observation;
    let f = o.failure.as_ref().expect("the handshake was rejected");
    assert_eq!((f.kind, f.phase), (FailureKind::TotalTimeout, Phase::ResponseBody), "{f:?}");
    assert_eq!(f.deadline_ms, Some(TOTAL_MS));
    assert_eq!(f.status, Some(status), "the rejection status is kept");
    let r = a.response.as_ref().expect("the rejection response is kept");
    assert_eq!(r.status, status);
    assert_eq!(r.body.completeness, BodyCompleteness::Incomplete);
    assert!(a.body.starts_with(b"x"), "the captured body is kept: {:?}", a.body);
    assert_eq!(o.phase(Phase::ResponseBody).map(|p| p.status), Some(PhaseStatus::TimedOut));
    assert!(out.facts.notes.iter().any(|n| n.contains("rejected handshake")), "{:?}", out.facts.notes);
    assert!(elapsed < WITHIN_BUDGET, "the rejected body ran past the total deadline: {elapsed:?}");
}

#[tokio::test]
async fn http3_settings_withheld_stop_at_the_total_deadline() {
    init();
    let peer = h3raw::serve_without_settings(server_tls()).await.expect("raw HTTP/3 peer");
    let (out, elapsed) = timed_run(&plan(peer.addr, WsBootstrap::Http3ExtendedConnect, 30_000)).await;
    assert_settings_deadline(&out, elapsed);
}

#[tokio::test]
async fn http2_settings_without_extended_connect_stop_at_the_total_deadline() {
    init();
    let addr = h2_without_extended_connect().await;
    let (out, elapsed) = timed_run(&plan(addr, WsBootstrap::Http2ExtendedConnect, 30_000)).await;
    assert_settings_deadline(&out, elapsed);
}

#[tokio::test]
async fn an_http3_rejection_body_held_open_or_trickled_stops_at_the_total_deadline() {
    init();
    // `:status: 503` (QPACK static entry 28), then one byte of body.
    let rejection = [h3raw::frame(HEADERS, &h3raw::field_section(&[h3raw::indexed(28)])), h3raw::frame(DATA, b"x")].concat();
    let held = h3raw::serve(server_tls(), vec![Answer { bytes: rejection.clone(), end: End::Hold }]).await.unwrap();
    let dripped = h3raw::serve(server_tls(), vec![Answer { bytes: rejection, end: End::Drip(Duration::from_millis(100)) }]).await.unwrap();
    for (addr, idle) in [(held.addr, 30_000), (dripped.addr, 1_000)] {
        let (out, elapsed) = timed_run(&plan(addr, WsBootstrap::Http3ExtendedConnect, idle)).await;
        assert_rejection_deadline(&out, elapsed, 503);
    }
}

#[tokio::test]
async fn an_http1_rejection_body_held_open_or_trickled_stops_at_the_total_deadline() {
    init();
    for (drip, idle) in [(None, 30_000), (Some(Duration::from_millis(100)), 1_000)] {
        let addr = h1_rejecting(drip).await;
        let (out, elapsed) = timed_run(&plan(addr, WsBootstrap::Http1Upgrade, idle)).await;
        assert_rejection_deadline(&out, elapsed, 403);
    }
}
