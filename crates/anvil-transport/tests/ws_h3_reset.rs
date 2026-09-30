//! WebSocket over HTTP/3 (RFC 9220) against a peer that stops reading, from
//! a raw local QUIC origin (`anvil_fixtures::h3raw`) that answers the
//! extended CONNECT and never reads the request stream. A write the cancel
//! interrupts may have left a partial frame, so the client resets the stream
//! (`H3_REQUEST_CANCELLED`) instead of ending it with a FIN, which the peer
//! would take for a clean end after a cut frame.

use anvil_domain::execution::FailureKind;
use anvil_domain::request::{WsBootstrap, WsMessage};
use anvil_domain::settings::{Limits, Timeouts};
use anvil_fixtures::h3raw::{self, Answer, End, HEADERS, RawH3, STATUS_200};
use anvil_fixtures::{LabPki, TlsServerOptions};
use anvil_transport::dns::DnsConfig;
use anvil_transport::recorder::EventCtx;
use anvil_transport::session::TranscriptLimits;
use anvil_transport::tls::{self, PreparedTls, TlsSettings};
use anvil_transport::ws;
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio_util::sync::CancellationToken;

/// `H3_REQUEST_CANCELLED` (RFC 9114 §8.1).
const H3_REQUEST_CANCELLED: u64 = 0x10c;
/// Longer than the session may take once the cancel holds.
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

/// An origin that answers every extended CONNECT with `:status: 200` and
/// never reads what the client sends on the stream.
async fn unread_origin() -> RawH3 {
    let tls = TlsServerOptions::new(pki().server.chain_with(&pki().ca), pki().server.key.clone());
    let ok_head = h3raw::frame(HEADERS, &h3raw::field_section(&[h3raw::indexed(STATUS_200)]));
    h3raw::serve(tls, vec![Answer { bytes: ok_head, end: End::HoldUnread }]).await.expect("raw HTTP/3 origin")
}

fn plan(addr: SocketAddr, script: Vec<WsMessage>) -> ws::WsPlan {
    ws::WsPlan {
        bootstrap: WsBootstrap::Http3ExtendedConnect,
        secure: true,
        host: addr.ip().to_string(),
        port: addr.port(),
        authority: addr.to_string(),
        request_target: "/ws".into(),
        headers: vec![],
        subprotocols: vec![],
        deflate: None,
        script,
        expect_messages: 0,
        idle_close_ms: 5_000,
        max_message_bytes: 1 << 20,
        timeouts: Timeouts {
            dns_ms: Some(2_000),
            connect_ms: Some(5_000),
            tls_handshake_ms: Some(5_000),
            request_write_ms: Some(5_000),
            response_headers_ms: Some(5_000),
            body_idle_ms: Some(30_000),
            total_ms: Some(60_000),
        },
        limits: Limits::default(),
        dns: DnsConfig::default(),
        proxy: None,
        tls: Some(client_tls()),
        display_url: format!("wss://{addr}/ws"),
        transcript: TranscriptLimits::default(),
        redact: None,
        proxy_header: None,
    }
}

#[tokio::test]
async fn an_interrupted_write_resets_the_http3_stream_instead_of_finishing_it() {
    init();
    let origin = unread_origin().await;
    // Far more than QUIC flow control lets through to a peer that does not read.
    let plan = plan(origin.addr, vec![WsMessage::Text { text: "x".repeat(16 << 20) }]);
    let cancel = CancellationToken::new();
    let c = cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(2_000)).await;
        c.cancel();
    });
    let run = ws::run(&plan, &EventCtx::none(), &cancel, None);
    let out = tokio::time::timeout(GIVE_UP, run).await.expect("the session must end although the peer never reads");
    let f = out.attempts[0].observation.failure.as_ref().expect("the session was canceled");
    assert_eq!(f.kind, FailureKind::Canceled);
    assert!(f.message.contains("while a write was pending"), "the cancel must interrupt the stalled write: {}", f.message);
    assert_eq!(out.transcript.as_ref().map(|t| t.sent_count), Some(0), "the stalled message is not recorded as sent");
    // Ground truth: the peer saw the stream reset, never a FIN after a partial frame.
    assert_eq!(origin.first_reset(Duration::from_secs(5)).await, Some(H3_REQUEST_CANCELLED), "the stream was not reset");
}
