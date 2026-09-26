//! WebSocket permessage-deflate (RFC 7692) through the engine, against real
//! sockets, for all three bootstraps (HTTP/1.1 Upgrade, RFC 8441 extended
//! CONNECT over TLS and h2c, RFC 9220 over QUIC). The peer is the fixture's
//! independent RFC 7692 implementation (`anvil_fixtures::ws_deflate`: its
//! own frames and raw DEFLATE); its ground truth (the offer it received, its
//! answer, and each message's RSV1 flag and sizes) checks that the wire
//! really carried what the record claims. It is never given to the engine.

use anvil_domain::auth::AuthConfig;
use anvil_domain::diagnostics::{DiagnosticFinding, Severity};
use anvil_domain::events::SessionCommand;
use anvil_domain::execution::*;
use anvil_domain::outcome::*;
use anvil_domain::request::*;
use anvil_domain::secret::{REDACTED, SensitiveValue};
use anvil_domain::settings::{SettingsOverrides, TimeoutOverrides};
use anvil_domain::tls::{TlsMinVersion, TlsProfile};
use anvil_domain::{Id, request::KeyValue};
use anvil_engine::{Engine, ExecutionContext, ExecutionOutput};
use anvil_fixtures::http as fx;
use anvil_fixtures::{GroundTruth, GroundTruthLog, LabPki, TlsServerOptions, h3server};
use anvil_transport::recorder::EventCtx;
use std::sync::OnceLock;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Boot {
    H1,
    H2Tls,
    H2c,
    H3,
}

const ALL: [Boot; 4] = [Boot::H1, Boot::H2Tls, Boot::H2c, Boot::H3];

/// One peer per transport: cleartext TCP, TCP with TLS, and QUIC.
struct Peers {
    plain: fx::Fixture,
    tls: fx::Fixture,
    h3: h3server::H3Fixture,
}

impl Peers {
    async fn start() -> Peers {
        Peers {
            plain: fx::serve("127.0.0.1:0", None).await.unwrap(),
            tls: fx::serve("127.0.0.1:0", Some(server_tls())).await.unwrap(),
            h3: h3server::serve("127.0.0.1:0", server_tls()).await.unwrap(),
        }
    }

    fn url(&self, b: Boot, query: &str) -> String {
        match b {
            Boot::H1 | Boot::H2c => format!("ws://127.0.0.1:{}/ws?{query}", self.plain.addr.port()),
            Boot::H2Tls => format!("wss://127.0.0.1:{}/ws?{query}", self.tls.addr.port()),
            Boot::H3 => format!("wss://127.0.0.1:{}/ws?{query}", self.h3.addr.port()),
        }
    }

    fn log(&self, b: Boot) -> &GroundTruthLog {
        match b {
            Boot::H1 | Boot::H2c => &self.plain.log,
            Boot::H2Tls => &self.tls.log,
            Boot::H3 => &self.h3.log,
        }
    }
}

fn offer() -> WsDeflateOffer {
    WsDeflateOffer { enabled: true, ..Default::default() }
}

fn ctx(url: &str, b: Boot, messages: &[&str], deflate: WsDeflateOffer) -> ExecutionContext {
    let mut s = RequestSpec::http("GET", url);
    s.protocol = Protocol::WebSocket;
    s.websocket = Some(WsSpec {
        bootstrap: match b {
            Boot::H1 => WsBootstrap::Http1Upgrade,
            Boot::H2Tls | Boot::H2c => WsBootstrap::Http2ExtendedConnect,
            Boot::H3 => WsBootstrap::Http3ExtendedConnect,
        },
        subprotocols: vec![],
        messages: messages.iter().map(|m| WsMessage::Text { text: m.to_string() }).collect(),
        expect_messages: 0,
        max_message_bytes: 1024 * 1024,
        idle_close_ms: 1_500,
        permessage_deflate: deflate,
    });
    let mut c = ExecutionContext::standalone(s);
    let timeouts = TimeoutOverrides {
        connect_ms: Some(Some(3_000)),
        tls_handshake_ms: Some(Some(3_000)),
        response_headers_ms: Some(Some(5_000)),
        total_ms: Some(Some(20_000)),
        ..Default::default()
    };
    let mut run = SettingsOverrides { timeouts: Some(timeouts), ..Default::default() };
    if url.starts_with("wss://") {
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
        run.tls_profile_id = Some(p.id);
        c.tls_profiles.push(p);
    }
    c.settings_layers.push(("run".into(), run));
    c
}

async fn run(c: &ExecutionContext) -> ExecutionOutput {
    Engine::new().execute(c, EventCtx::none(), CancellationToken::new()).await
}

fn codes(o: &ExecutionOutput) -> Vec<String> {
    o.record.findings.iter().map(|f| f.code.clone()).collect()
}

fn finding<'a>(o: &'a ExecutionOutput, code: &str) -> &'a DiagnosticFinding {
    o.record.findings.iter().find(|f| f.code == code).unwrap_or_else(|| panic!("missing {code}; have {:?}", codes(o)))
}

fn ext(o: &ExecutionOutput) -> &WsExtensions {
    match &o.record.outcome.protocol_status {
        ProtocolStatus::WebSocket { extensions: Some(e), .. } => e,
        other => panic!("no extension evidence: {other:?}"),
    }
}

fn close(o: &ExecutionOutput) -> (Option<u16>, ClosedBy) {
    match &o.record.outcome.protocol_status {
        ProtocolStatus::WebSocket { close_code, closed_by, .. } => (*close_code, *closed_by),
        other => panic!("{other:?}"),
    }
}

fn failure(o: &ExecutionOutput) -> Option<&TransportFailure> {
    o.record.attempts.last().and_then(|a| a.failure.as_ref())
}

fn received_messages(o: &ExecutionOutput) -> Vec<&StreamMessage> {
    let s = o.record.stream.as_ref().expect("transcript");
    s.messages.iter().filter(|m| m.direction == Direction::Received && (m.kind == "text" || m.kind == "binary")).collect()
}

/// Previews of the received data messages.
fn received(o: &ExecutionOutput) -> Vec<String> {
    received_messages(o).into_iter().map(|m| m.preview.clone()).collect()
}

/// Decompressed sizes of the received data messages.
fn received_sizes(o: &ExecutionOutput) -> Vec<u64> {
    received_messages(o).into_iter().map(|m| m.size).collect()
}

/// How a message appears as a preview (the first 2 KiB).
fn shown(s: &str) -> String {
    s[..s.len().min(2048)].to_string()
}

/// `(offer, answer)` the peer recorded.
fn gt_negotiation(log: &GroundTruthLog) -> Vec<(Option<String>, Option<String>)> {
    log.entries()
        .into_iter()
        .filter_map(|e| match e.event {
            GroundTruth::WsExtensions { offer, answer } => Some((offer, answer)),
            _ => None,
        })
        .collect()
}

/// `(compressed, wire bytes, decoded bytes)` of every message the peer received.
fn gt_messages(log: &GroundTruthLog) -> Vec<(bool, u64, u64)> {
    log.entries()
        .into_iter()
        .filter_map(|e| match e.event {
            GroundTruth::WsMessage { compressed, wire_bytes, bytes } => Some((compressed, wire_bytes, bytes)),
            _ => None,
        })
        .collect()
}

fn faults(log: &GroundTruthLog) -> Vec<String> {
    log.entries()
        .into_iter()
        .filter_map(|e| match e.event {
            GroundTruth::FaultApplied { fault } => Some(fault),
            _ => None,
        })
        .collect()
}

/// Compressible text (many repeats) of about `n` bytes.
fn text(n: usize) -> String {
    "permessage-deflate shrinks repeated text; ".repeat(n / 42 + 1)[..n].to_string()
}

/// Pseudo-random letters: the only redundancy is a repeat after `n` bytes.
fn repeat_after(n: usize) -> String {
    let mut x: u32 = 0x9e37_79b9;
    let block: String = (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            (b'a' + (x >> 24) as u8 % 26) as char
        })
        .collect();
    format!("{block}{block}")
}

#[tokio::test]
async fn negotiated_deflate_compresses_both_ways_on_every_bootstrap() {
    init();
    let p = Peers::start().await;
    let msg = text(2000);
    for b in ALL {
        let o = run(&ctx(&p.url(b, "close_after=2"), b, &[&msg, &msg], offer())).await;
        assert!(failure(&o).is_none(), "{b:?}: {:?}", failure(&o));
        assert_eq!(close(&o), (Some(1000), ClosedBy::Peer), "{b:?}");
        let e = ext(&o);
        assert_eq!(e.negotiation, WsNegotiation::Negotiated, "{b:?}");
        assert_eq!(e.offered.as_deref(), Some("permessage-deflate; client_max_window_bits"));
        assert_eq!(e.answered.as_deref(), Some("permessage-deflate"));
        let d = e.deflate.as_ref().unwrap();
        assert!(d.client_compresses && !d.server_no_context_takeover && !d.client_no_context_takeover);
        let t = e.traffic.as_ref().unwrap();
        for (dir, x) in [("sent", t.sent), ("received", t.received)] {
            assert_eq!((x.messages, x.compressed_messages), (2, 2), "{b:?} {dir}");
            assert_eq!(x.payload_bytes, 4000, "{b:?} {dir}: uncompressed sizes");
            assert!(x.wire_bytes < 400, "{b:?} {dir}: {} wire bytes for 4000", x.wire_bytes);
        }
        assert_eq!(received(&o), vec![msg.clone(), msg.clone()], "{b:?}: previews show the decompressed payload");
        assert!(o.record.prepared.inferred.iter().any(|i| i.contains("Sec-WebSocket-Extensions: permessage-deflate")), "{b:?}");
        assert!(o.record.prepared.inferred.iter().any(|i| i.contains("permessage-deflate negotiated")), "{b:?}");
        assert!(o.record.stream.as_ref().unwrap().messages.iter().any(|m| m.kind == "extension"), "{b:?}: noted in the transcript");
        assert!(!codes(&o).iter().any(|c| c.starts_with("ws.deflate") || c.starts_with("ws.extension")), "{b:?}: {:?}", codes(&o));
        // Ground truth: the peer got the offer and two compressed messages.
        let log = p.log(b);
        let (offered, answered) = gt_negotiation(log).pop().unwrap();
        assert_eq!(offered.as_deref(), Some("permessage-deflate; client_max_window_bits"));
        assert_eq!(answered.as_deref(), Some("permessage-deflate"));
        let msgs = gt_messages(log);
        let last2 = &msgs[msgs.len() - 2..];
        assert!(last2.iter().all(|(c, wire, n)| *c && *n == 2000 && *wire < 200), "{b:?}: {last2:?}");
        assert!(faults(log).is_empty(), "{b:?}: {:?}", faults(log));
    }
}

#[tokio::test]
async fn deflate_is_off_by_default_and_nothing_is_offered() {
    init();
    let p = Peers::start().await;
    for b in ALL {
        // `pmd=accept`: the deflate-capable peer serves the session and would accept an offer.
        let o = run(&ctx(&p.url(b, "pmd=accept&close_after=1"), b, &["plain"], WsDeflateOffer::default())).await;
        assert!(failure(&o).is_none(), "{b:?}: {:?}", failure(&o));
        match &o.record.outcome.protocol_status {
            ProtocolStatus::WebSocket { extensions, .. } => assert!(extensions.is_none(), "{b:?}"),
            other => panic!("{other:?}"),
        }
        assert_eq!(gt_negotiation(p.log(b)).pop(), Some((None, None)), "{b:?}: no Sec-WebSocket-Extensions reached the peer");
        assert_eq!(gt_messages(p.log(b)).pop().map(|m| m.0), Some(false));
    }
}

#[tokio::test]
async fn an_offer_that_is_not_accepted_is_information_and_the_session_runs_uncompressed() {
    init();
    let p = Peers::start().await;
    for b in ALL {
        let o = run(&ctx(&p.url(b, "pmd=decline&close_after=1"), b, &[&text(500)], offer())).await;
        assert!(failure(&o).is_none(), "{b:?}: {:?}", failure(&o));
        let e = ext(&o);
        assert_eq!((e.negotiation, e.answered.as_deref()), (WsNegotiation::NotNegotiated, None), "{b:?}");
        let t = e.traffic.as_ref().unwrap();
        assert_eq!((t.sent.compressed_messages, t.received.compressed_messages), (0, 0));
        assert_eq!((t.sent.wire_bytes, t.received.wire_bytes), (500, 500), "{b:?}: uncompressed on the wire");
        let f = finding(&o, "ws.deflate_not_negotiated");
        assert_eq!(f.severity, Severity::Info);
        assert!(f.alternatives.iter().any(|a| a.contains("gateway")), "{:?}", f.alternatives);
        assert_eq!(o.record.outcome.application, ApplicationState::Success, "{b:?}: not an error");
        assert!(o.record.prepared.inferred.iter().any(|i| i.contains("offered but not negotiated")));
        assert!(!gt_messages(p.log(b)).pop().unwrap().0, "{b:?}: the peer received an uncompressed message");
    }
}

#[tokio::test]
async fn context_takeover_is_used_by_default_and_dropped_when_negotiated_off() {
    init();
    let p = Peers::start().await;
    let msg = repeat_after(1500);
    let msg = &msg[..1500]; // incompressible on its own, identical each time
    // Context takeover: the second copy is a back-reference into the first.
    let o = run(&ctx(&p.url(Boot::H1, "close_after=2"), Boot::H1, &[msg, msg], offer())).await;
    assert!(failure(&o).is_none(), "{:?}", failure(&o));
    let m = gt_messages(&p.plain.log);
    let (first, second) = (m[m.len() - 2].1, m[m.len() - 1].1);
    assert!(second * 10 < first, "sent: {first} then {second} wire bytes");
    let shared = ext(&o).traffic.as_ref().unwrap().received.wire_bytes;
    // Both directions without context takeover, as Anvil asked: every message stands alone.
    let nct = WsDeflateOffer { server_no_context_takeover: true, client_no_context_takeover: true, ..offer() };
    let o = run(&ctx(&p.url(Boot::H1, "close_after=2"), Boot::H1, &[msg, msg], nct)).await;
    assert!(failure(&o).is_none(), "{:?}", failure(&o));
    let e = ext(&o);
    let d = e.deflate.as_ref().unwrap();
    assert!(d.server_no_context_takeover && d.client_no_context_takeover);
    assert_eq!(e.answered.as_deref(), Some("permessage-deflate; server_no_context_takeover; client_no_context_takeover"));
    let m = gt_messages(&p.plain.log);
    let (first, second) = (m[m.len() - 2].1, m[m.len() - 1].1);
    assert!(second * 10 > first * 9, "sent: {first} then {second} wire bytes");
    let t = e.traffic.as_ref().unwrap();
    assert!(t.received.wire_bytes * 10 > shared * 18, "received {} wire bytes, {shared} with context takeover", t.received.wire_bytes);
    assert_eq!(received(&o), vec![msg.to_string(), msg.to_string()]);
    // The server may impose client_no_context_takeover unasked: the peer
    // resets its decompressor per message and would fail on a back-reference.
    let o = run(&ctx(&p.url(Boot::H2c, "pmd_client_nct=1&close_after=2"), Boot::H2c, &[msg, msg], offer())).await;
    assert!(failure(&o).is_none(), "{:?}", failure(&o));
    assert!(ext(&o).deflate.as_ref().unwrap().client_no_context_takeover);
    assert!(!faults(&p.plain.log).contains(&"ws_client_inflate_failed".to_string()));
}

#[tokio::test]
async fn window_bits_are_offered_answered_and_honoured() {
    init();
    let p = Peers::start().await;
    let msg = repeat_after(2048); // the repeat is 2 KiB back: out of reach of a 2^9 window
    // Anvil asks the server for a small window; the peer compresses within it and Anvil decodes.
    let asked = WsDeflateOffer { server_max_window_bits: Some(10), ..offer() };
    let o = run(&ctx(&p.url(Boot::H3, "close_after=1"), Boot::H3, &[&msg], asked)).await;
    assert!(failure(&o).is_none(), "{:?}", failure(&o));
    assert_eq!(ext(&o).answered.as_deref(), Some("permessage-deflate; server_max_window_bits=10"));
    assert_eq!((received(&o), received_sizes(&o)), (vec![shown(&msg)], vec![4096]));
    let wire = ext(&o).traffic.as_ref().unwrap().received.wire_bytes;
    assert!(wire > 2 * 2048 * 55 / 100, "the peer's 2^10 window cannot reach the repeat: {wire} wire bytes");
    // The server limits Anvil's window: Anvil's message cannot use the repeat either.
    for (query, shrinks) in [("pmd_client_bits=9&close_after=1", false), ("close_after=1", true)] {
        let o = run(&ctx(&p.url(Boot::H1, query), Boot::H1, &[&msg], offer())).await;
        assert!(failure(&o).is_none(), "{query}: {:?}", failure(&o));
        let (c, wire, n) = gt_messages(&p.plain.log).pop().unwrap();
        assert!(c && n == 4096);
        assert_eq!(wire < 2048 * 80 / 100, shrinks, "{query}: {wire} wire bytes for {n}");
    }
    assert_eq!(
        ext(&run(&ctx(&p.url(Boot::H1, "pmd_client_bits=9&close_after=1"), Boot::H1, &["x"], offer())).await)
            .deflate
            .as_ref()
            .unwrap()
            .client_max_window_bits,
        Some(9)
    );
    // A 2^8 client window: Anvil cannot compress that small, so it sends
    // uncompressed messages (RFC 7692 §6) and still decodes the peer's.
    let o = run(&ctx(&p.url(Boot::H2Tls, "pmd_client_bits=8&close_after=1"), Boot::H2Tls, &[&text(800)], offer())).await;
    assert!(failure(&o).is_none(), "{:?}", failure(&o));
    let e = ext(&o);
    assert!(!e.deflate.as_ref().unwrap().client_compresses);
    let t = e.traffic.as_ref().unwrap();
    assert_eq!((t.sent.compressed_messages, t.received.compressed_messages), (0, 1));
    assert!(!gt_messages(&p.tls.log).pop().unwrap().0);
    assert!(o.record.prepared.inferred.iter().any(|i| i.contains("uncompressed because it cannot compress within a 256-byte window")));
    // Anvil's own offered limit is kept when the answer is silent about it.
    let limited = WsDeflateOffer { client_max_window_bits: Some(9), ..offer() };
    let o = run(&ctx(&p.url(Boot::H1, "close_after=1"), Boot::H1, &[&msg], limited)).await;
    assert_eq!(ext(&o).offered.as_deref(), Some("permessage-deflate; client_max_window_bits=9"));
    let (_, wire, _) = gt_messages(&p.plain.log).pop().unwrap();
    assert!(wire > 2048 * 80 / 100, "{wire}");
}

#[tokio::test]
async fn fragmented_compressed_messages_and_empty_messages() {
    init();
    let p = Peers::start().await;
    let msg = text(5000);
    for b in [Boot::H1, Boot::H3] {
        // Replies in 7-byte fragments (RSV1 on the first only), plus an empty compressed message after each echo.
        let o = run(&ctx(&p.url(b, "pmd_fragment=7&pmd_empty=1&close_after=3"), b, &[&msg, "", &msg], offer())).await;
        assert!(failure(&o).is_none(), "{b:?}: {:?}", failure(&o));
        assert_eq!(received_sizes(&o), vec![5000, 0, 0, 0, 5000, 0], "{b:?}");
        assert_eq!(received(&o)[0], shown(&msg), "{b:?}");
        let t = ext(&o).traffic.as_ref().unwrap();
        assert_eq!((t.received.messages, t.received.compressed_messages), (6, 6), "{b:?}");
        // Anvil's empty message (the 0x00 octet) did not disturb the shared
        // window: the peer decoded the next message with the same decompressor.
        let m = gt_messages(p.log(b));
        assert_eq!(m[m.len() - 3..].iter().map(|x| (x.0, x.2)).collect::<Vec<_>>(), vec![(true, 5000), (true, 0), (true, 5000)], "{b:?}");
        assert_eq!(m[m.len() - 2].1, 1, "{b:?}: an empty message is one octet on the wire");
        assert!(faults(p.log(b)).is_empty(), "{b:?}: {:?}", faults(p.log(b)));
    }
    // Uncompressed replies under a negotiated extension are fine too.
    let o = run(&ctx(&p.url(Boot::H2c, "pmd_plain_replies=1&close_after=1"), Boot::H2c, &[&msg], offer())).await;
    assert!(failure(&o).is_none(), "{:?}", failure(&o));
    assert_eq!(ext(&o).traffic.as_ref().unwrap().received.compressed_messages, 0);
    assert_eq!((received(&o), received_sizes(&o)), (vec![shown(&msg)], vec![5000]));
}

#[tokio::test]
async fn a_decompression_bomb_stops_at_the_local_limit_after_decompression() {
    init();
    let p = Peers::start().await;
    for b in [Boot::H1, Boot::H2Tls, Boot::H3] {
        // 32 MiB of zeros compress to about 32 KiB, far below the 1 MiB limit on the wire.
        let o = run(&ctx(&p.url(b, "bomb=33554432"), b, &["hello"], offer())).await;
        assert!(faults(p.log(b)).contains(&"ws_decompression_bomb".to_string()), "{b:?}");
        assert_eq!(close(&o), (Some(1009), ClosedBy::Client), "{b:?}");
        let f = failure(&o).unwrap();
        assert_eq!(f.kind, FailureKind::WsMessageTooLarge);
        assert!(f.message.contains("while it was decompressed"), "{}", f.message);
        let v = ext(&o).violation.as_ref().unwrap();
        assert_eq!((v.kind, v.limit_bytes), (WsViolationKind::TooLargeAfterDecompression, Some(1024 * 1024)));
        assert!(v.compressed_bytes.unwrap() < 64 * 1024, "{v:?}");
        let d = finding(&o, "ws.too_large_after_decompression");
        assert!(d.explanation.contains("1048576") && d.explanation.contains("after decompression"), "{}", d.explanation);
        assert!(!codes(&o).contains(&"ws.closed_too_big".to_string()), "{b:?}: {:?}", codes(&o));
        assert_eq!(received(&o), vec!["hello"], "{b:?}: the echo before the bomb is kept");
    }
}

#[tokio::test]
async fn the_peers_own_limit_is_still_the_peers_1009() {
    init();
    let p = Peers::start().await;
    let o = run(&ctx(&p.url(Boot::H1, "max=1000"), Boot::H1, &[&text(5000)], offer())).await;
    assert!(faults(&p.plain.log).contains(&"ws_client_message_too_big".to_string()));
    assert_eq!(close(&o), (Some(1009), ClosedBy::Peer));
    assert!(failure(&o).is_none(), "a peer size-policy close is not a transport fault");
    finding(&o, "ws.closed_too_big");
    assert!(ext(&o).violation.is_none());
}

#[tokio::test]
async fn compressed_frames_without_negotiation_and_undecodable_ones_are_the_peers_violations() {
    init();
    let p = Peers::start().await;
    for (b, deflate) in [(Boot::H1, WsDeflateOffer::default()), (Boot::H2c, offer()), (Boot::H3, offer())] {
        // The peer answers no extension but compresses its reply anyway.
        let o = run(&ctx(&p.url(b, "pmd=unnegotiated"), b, &[&text(300)], deflate.clone())).await;
        assert_eq!(close(&o), (Some(1002), ClosedBy::Client), "{b:?}");
        let f = failure(&o).unwrap();
        assert_eq!(f.kind, FailureKind::WsProtocolError);
        assert!(f.message.contains("RSV1") && f.message.contains("by the peer"), "{}", f.message);
        let e = ext(&o);
        assert_eq!(e.violation.as_ref().unwrap().kind, WsViolationKind::CompressedWithoutNegotiation);
        assert_eq!(e.traffic.as_ref().unwrap().received.compressed_messages, 1, "{b:?}");
        let d = finding(&o, "ws.compressed_without_negotiation");
        assert_eq!(d.explanation.contains("Anvil had offered permessage-deflate"), deflate.enabled, "{}", d.explanation);
        assert_eq!(e.negotiation, if deflate.enabled { WsNegotiation::NotNegotiated } else { WsNegotiation::NotOffered });
    }
    for b in [Boot::H1, Boot::H3] {
        let o = run(&ctx(&p.url(b, "pmd_corrupt=1"), b, &["hello"], offer())).await;
        assert!(faults(p.log(b)).contains(&"ws_corrupt_deflate".to_string()));
        assert_eq!(close(&o), (Some(1002), ClosedBy::Client), "{b:?}");
        assert_eq!(ext(&o).violation.as_ref().unwrap().kind, WsViolationKind::Undecodable);
        assert!(failure(&o).unwrap().message.contains("could not be decompressed"));
        finding(&o, "ws.decompression_failed");
        assert_eq!(received(&o), vec!["hello"]);
    }
}

#[tokio::test]
async fn answers_that_do_not_fit_the_offer_fail_the_handshake_with_a_reason() {
    init();
    let p = Peers::start().await;
    let strict = WsDeflateOffer { server_no_context_takeover: true, server_max_window_bits: Some(10), ..offer() };
    let cases: Vec<(Boot, &str, WsDeflateOffer, &str)> = vec![
        (Boot::H1, "pmd_answer=permessage-deflate%3B%20mystery", offer(), "mystery is not a permessage-deflate parameter"),
        (Boot::H2Tls, "pmd_answer=permessage-deflate%3B%20client_max_window_bits%3D16", offer(), "not a window size"),
        (Boot::H3, "pmd_answer=permessage-deflate%2C%20permessage-deflate", offer(), "more than once"),
        (Boot::H2c, "pmd_answer=x-webkit-deflate-frame", offer(), "did not offer"),
        (Boot::H1, "pmd_answer=permessage-deflate%3B%20server_max_window_bits%3D10", strict.clone(), "server_no_context_takeover"),
        (Boot::H3, "pmd_answer=permessage-deflate%3B%20server_no_context_takeover", strict, "server_max_window_bits=10"),
        // An extension answer although nothing was offered (RFC 6455 §4.1).
        (Boot::H1, "pmd=unsolicited", WsDeflateOffer::default(), "did not offer"),
    ];
    for (b, query, deflate, want) in cases {
        let o = run(&ctx(&p.url(b, query), b, &["never sent"], deflate)).await;
        let f = failure(&o).unwrap_or_else(|| panic!("{query}: no failure"));
        assert_eq!((f.kind, f.phase), (FailureKind::WsProtocolError, Phase::ProtocolHandshake), "{query}");
        assert!(f.message.contains(want), "{query}: {}", f.message);
        assert!(o.record.stream.is_none(), "{query}: no session");
        let e = ext(&o);
        assert_eq!(e.negotiation, WsNegotiation::Rejected);
        assert!(e.problem.as_deref().unwrap().contains(want));
        let d = finding(&o, "ws.extension_answer_refused");
        assert!(d.explanation.contains(want), "{}", d.explanation);
        assert!(gt_messages(p.log(b)).iter().all(|m| m.2 != 10), "{query}: nothing was sent after the refusal");
    }
}

#[tokio::test]
async fn misconfigurations_are_refused_before_any_traffic() {
    init();
    let p = Peers::start().await;
    let mut c = ctx(&p.url(Boot::H1, ""), Boot::H1, &["x"], offer());
    c.spec.headers.push(KeyValue::new("Sec-WebSocket-Extensions", "permessage-deflate"));
    let o = run(&c).await;
    let f = failure(&o).unwrap();
    assert_eq!((f.kind, f.phase), (FailureKind::UnsupportedCombination, Phase::Prepare));
    assert_eq!(f.field.as_deref(), Some("websocket.permessage_deflate"));
    assert_eq!(o.record.outcome.dispatch, DispatchState::NotDispatched);
    for bits in [7u8, 16] {
        let o = run(&ctx(&p.url(Boot::H1, ""), Boot::H1, &["x"], WsDeflateOffer { server_max_window_bits: Some(bits), ..offer() })).await;
        let f = failure(&o).unwrap();
        assert_eq!(f.kind, FailureKind::UnsupportedCombination);
        assert!(f.message.contains("from 8 to 15"), "{}", f.message);
    }
    assert!(!p.plain.log.saw_connection(), "nothing was sent");
    // With the toggle off, a user-supplied header is sent verbatim, but Anvil
    // runs no codec for it: an accepting answer fails the handshake.
    let mut c = ctx(&p.url(Boot::H1, ""), Boot::H1, &["x"], WsDeflateOffer::default());
    c.spec.headers.push(KeyValue::new("Sec-WebSocket-Extensions", "permessage-deflate"));
    let o = run(&c).await;
    assert!(failure(&o).unwrap().message.contains("custom Sec-WebSocket-Extensions header"), "{}", failure(&o).unwrap().message);
    assert_eq!(gt_negotiation(&p.plain.log).pop().unwrap().0.as_deref(), Some("permessage-deflate"));
}

#[tokio::test]
async fn decompressed_previews_are_redacted_and_interactive_sessions_compress() {
    init();
    let p = Peers::start().await;
    let secret = "deflate-bearer-secret-5519";
    let mut c = ctx(&p.url(Boot::H2Tls, "close_after=1"), Boot::H2Tls, &[&format!("token {secret} {}", text(400))], offer());
    let auth = AuthConfig::Bearer { token: SensitiveValue::template(secret), prefix: "Bearer".into() };
    c.auth_layers = vec![("request".into(), auth.clone())];
    c.spec.auth = auth;
    let o = run(&c).await;
    assert!(failure(&o).is_none(), "{:?}", failure(&o));
    assert!(ext(&o).traffic.as_ref().unwrap().received.compressed_messages == 1);
    let hdrs = p.tls.log.last_request_headers().unwrap();
    assert!(hdrs.iter().any(|(n, v)| n == "authorization" && v == &format!("Bearer {secret}")), "the peer got the credential");
    let json = serde_json::to_string(&o.record).unwrap();
    assert!(!json.contains(secret), "the record leaks the secret");
    assert!(received(&o)[0].contains(REDACTED), "the decompressed echo is redacted: {}", received(&o)[0]);

    let h = Engine::new().open_session(ctx(&p.url(Boot::H3, ""), Boot::H3, &[], offer()), EventCtx::none()).await;
    h.send(SessionCommand::SendText { text: text(1000) }).await.unwrap();
    h.send(SessionCommand::SendBinaryHex { hex: "00".repeat(1000) }).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    h.close().await.unwrap();
    let o = h.finish().await;
    let t = ext(&o).traffic.as_ref().unwrap();
    assert_eq!((t.sent.messages, t.sent.compressed_messages, t.sent.payload_bytes), (2, 2, 2000));
    assert!(t.sent.wire_bytes < 200, "{t:?}");
    assert_eq!(t.received.compressed_messages, 2);
    assert_eq!(close(&o), (Some(1000), ClosedBy::Client));
}
