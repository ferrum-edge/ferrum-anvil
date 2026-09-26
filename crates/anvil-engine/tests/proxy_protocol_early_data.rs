//! A PROXY protocol header together with TLS 1.3 resumption and early data
//! (the 0-RTT opt-in) on HTTP requests, end to end through the engine. The
//! independent PROXY-parsing relay (`anvil_fixtures::proxy_protocol::
//! tcp_relay`, its own parser) sits in front of the TLS 1.3 early-data
//! fixture (`anvil_fixtures::early_data::serve_tls`) and relays everything
//! after the header byte for byte, so the ClientHello, the early data and
//! the rest of the handshake reach the server unchanged. The relay's parse
//! and the fixture's early-data ground truth are compared with Anvil's
//! evidence; neither is fed to the diagnostic engine.
//!
//! The relay reads exactly one header at the head of each connection and
//! closes a connection whose first bytes are not one; the TLS server behind
//! it then sees everything after the header. A header written after the
//! ClientHello, or a second header, would therefore fail the connection
//! rather than pass silently.

use anvil_domain::diagnostics::Confidence;
use anvil_domain::execution::*;
use anvil_domain::proxy_protocol::*;
use anvil_domain::request::*;
use anvil_domain::settings::{EarlyDataPolicy, HttpVersionPolicy, SettingsOverrides, TimeoutOverrides};
use anvil_domain::tls::{TlsMinVersion, TlsProfile};
use anvil_domain::{Id, auth::AuthConfig};
use anvil_engine::{Engine, ExecutionContext, ExecutionOutput};
use anvil_fixtures::early_data::{self, EarlyMode, EarlyTlsFixture};
use anvil_fixtures::proxy_protocol::{self as pp, ProxyEvent, ProxyFixture};
use anvil_fixtures::{GroundTruth, LabPki, TlsServerOptions};
use anvil_transport::recorder::EventCtx;
use std::net::{IpAddr, SocketAddr};
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

const SOURCE: &str = "203.0.113.7:4242";
const DESTINATION: &str = "198.51.100.9:443";

fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

/// The early-data fixture behind a PROXY-header-requiring relay (trusting loopback).
async fn behind_relay() -> (EarlyTlsFixture, ProxyFixture) {
    let tls = TlsServerOptions::new(pki().server.chain_with(&pki().ca), pki().server.key.clone());
    let fx = early_data::serve_tls("127.0.0.1:0", tls, EarlyMode::Accept).await.expect("early-data fixture");
    let relay = pp::tcp_relay("127.0.0.1:0", vec![IpAddr::from([127, 0, 0, 1])], fx.addr).await.expect("relay");
    (fx, relay)
}

fn profile() -> TlsProfile {
    TlsProfile {
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
    }
}

/// `GET url` with a PROXY v2 header whose addresses are both configured,
/// the early-data opt-in, a forced single-protocol `version` (early data
/// needs a fixed ALPN) and connection reuse as given.
fn ctx(url: &str, tls: &TlsProfile, version: HttpVersionPolicy, keepalive: bool) -> ExecutionContext {
    let mut s = RequestSpec::http("GET", url);
    s.auth = AuthConfig::None;
    s.proxy_protocol = Some(ProxyHeaderSpec {
        version: ProxyHeaderVersion::V2,
        command: ProxyCommand::Proxy,
        family: ProxyAddressFamily::Auto,
        source: Some(SOURCE.into()),
        destination: Some(DESTINATION.into()),
        authority: None,
        tlvs: vec![],
        raw_hex: None,
    });
    let mut c = ExecutionContext::standalone(s);
    c.isolation = "ws-pp-early".into();
    c.tls_profiles.push(tls.clone());
    c.settings_layers.push((
        "run".into(),
        SettingsOverrides {
            tls_profile_id: Some(tls.id),
            http_version: Some(version),
            keepalive: Some(keepalive),
            early_data: Some(EarlyDataPolicy { enabled: true, extra_methods: vec![] }),
            timeouts: Some(TimeoutOverrides {
                connect_ms: Some(Some(3_000)),
                tls_handshake_ms: Some(Some(3_000)),
                response_headers_ms: Some(Some(5_000)),
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

fn last(o: &ExecutionOutput) -> &AttemptObservation {
    o.record.attempts.last().expect("attempt")
}

fn status(o: &ExecutionOutput) -> Option<u16> {
    o.record.response.as_ref().map(|r| r.status)
}

fn conn(o: &ExecutionOutput) -> &ConnectionObservation {
    last(o).connection.as_ref().expect("connection")
}

fn early(o: &ExecutionOutput) -> EarlyDataObservation {
    last(o).early_data.clone().unwrap_or_else(|| panic!("no early-data evidence: {:?}", last(o)))
}

/// `(source, destination, v2, local)` of every header the relay parsed, in order.
fn parsed(relay: &ProxyFixture) -> Vec<(Option<SocketAddr>, Option<SocketAddr>, bool, bool)> {
    relay
        .log
        .headers()
        .into_iter()
        .filter_map(|e| match e {
            ProxyEvent::Header { source, destination, v2, local, .. } => Some((source, destination, v2, local)),
            _ => None,
        })
        .collect()
}

/// Connections the TLS server behind the relay accepted.
fn server_connections(fx: &EarlyTlsFixture) -> usize {
    fx.log.entries().iter().filter(|e| matches!(e.event, GroundTruth::ConnectionAccepted { .. })).count()
}

/// The attempt wrote the configured header on its new connection, in its own
/// phase that ended before the TLS handshake (the ClientHello) started.
fn assert_header_before_client_hello(o: &ExecutionOutput) {
    let a = last(o);
    let p = a.phase(Phase::ProxyProtocolHeader).expect("proxy_protocol_header phase");
    assert_eq!(p.status, PhaseStatus::Completed, "{p:?}");
    let t = a.phase(Phase::TlsHandshake).expect("tls_handshake phase");
    assert!(p.end_us.unwrap() <= t.start_us.unwrap(), "the header precedes the ClientHello: {p:?} {t:?}");
    let order: Vec<Phase> = a.phases.iter().map(|x| x.phase).collect();
    let pos = |ph: Phase| order.iter().position(|x| *x == ph).unwrap();
    assert!(
        pos(Phase::Connect) < pos(Phase::ProxyProtocolHeader) && pos(Phase::ProxyProtocolHeader) < pos(Phase::TlsHandshake),
        "{order:?}"
    );
    let c = conn(o);
    assert!(!c.reused);
    let h = c.proxy_header.as_ref().expect("header evidence");
    assert_eq!((h.format, h.well_formed), (ProxyHeaderFormat::V2, true));
    assert_eq!((h.source_origin, h.destination_origin), (Some(AddressOrigin::Configured), Some(AddressOrigin::Configured)));
}

#[tokio::test]
async fn the_header_precedes_the_resuming_client_hello_and_its_early_data() {
    init();
    for version in [HttpVersionPolicy::Http1Only, HttpVersionPolicy::Http2Only] {
        let (fx, relay) = behind_relay().await;
        let e = Engine::new();
        let tls = profile();
        let url = format!("https://{}/echo", relay.addr);
        let want = (Some(addr(SOURCE)), Some(addr(DESTINATION)), true, false);

        // First request: a full handshake on a new connection, which earns a ticket.
        let first = run(&e, &ctx(&url, &tls, version, false)).await;
        assert_eq!(status(&first), Some(200), "{version:?}: {:?} {:?}", last(&first).failure, codes(&first));
        assert_header_before_client_hello(&first);
        let ed = early(&first);
        assert!(!ed.offered && !ed.resumption_attempted, "{ed:?}");
        assert_eq!(ed.not_used, Some(EarlyDataNotUsed::NoTicket));
        assert!(ed.tickets_received >= 1, "{ed:?}");
        assert_eq!(parsed(&relay), vec![want], "{version:?}");

        // Second request: a new connection resumes the ticket and sends GET as
        // early data; the header still goes first, once.
        let second = run(&e, &ctx(&url, &tls, version, false)).await;
        assert_eq!(status(&second), Some(200), "{version:?}: {:?} {:?}", last(&second).failure, codes(&second));
        assert_eq!(second.record.attempts.len(), 1);
        assert_header_before_client_hello(&second);
        assert_ne!(conn(&second).id, conn(&first).id);
        let ed = early(&second);
        assert!(ed.resumption_attempted && ed.offered, "{version:?}: {ed:?}");
        assert_eq!((ed.resumption_accepted, ed.accepted), (Some(true), Some(true)), "{version:?}: {ed:?}");
        assert!(ed.bytes > 0 && !ed.bytes_estimated, "{ed:?}");
        assert!(!ed.resent_after_handshake);
        let t = conn(&second).tls.as_ref().expect("tls evidence");
        assert_eq!((t.resumed, &t.verification), (Some(true), &TlsVerification::Verified));
        let hs = last(&second).phase(Phase::TlsHandshake).unwrap();
        assert!(hs.detail.as_deref().unwrap_or_default().contains("early data accepted"), "{hs:?}");
        let f = second.record.findings.iter().find(|f| f.code == "early_data.accepted").expect("early_data.accepted");
        assert_eq!(f.confidence, Confidence::Confirmed);
        assert!(!codes(&second).iter().any(|c| c.contains("proxy_header")), "{:?}", codes(&second));

        // Ground truth: exactly one header per connection, both with the
        // configured addresses; the server saw the same two connections and
        // the second request (only) in early data it accepted.
        assert_eq!(parsed(&relay), vec![want, want], "{version:?}");
        assert!(relay.log.rejections().is_empty(), "{:?}", relay.log.rejections());
        assert_eq!(server_connections(&fx), 2);
        assert_eq!(fx.requests().iter().map(|r| r.0).collect::<Vec<_>>(), vec![false, true], "{version:?}: {:?}", fx.requests());
    }
}

#[tokio::test]
async fn a_pooled_reuse_of_the_early_data_connection_does_not_resend_the_header() {
    init();
    let (fx, relay) = behind_relay().await;
    let e = Engine::new();
    let tls = profile();
    let url = format!("https://{}/echo", relay.addr);
    // A ticket first (not pooled), then early data on a new, pooled connection.
    let first = run(&e, &ctx(&url, &tls, HttpVersionPolicy::Http1Only, false)).await;
    assert_eq!(status(&first), Some(200));
    let second = run(&e, &ctx(&url, &tls, HttpVersionPolicy::Http1Only, true)).await;
    assert_eq!(status(&second), Some(200), "{:?}", last(&second).failure);
    assert_header_before_client_hello(&second);
    assert_eq!(early(&second).accepted, Some(true), "{:?}", early(&second));

    // The third request reuses that connection: no header, no handshake, no early data.
    let third = run(&e, &ctx(&url, &tls, HttpVersionPolicy::Http1Only, true)).await;
    assert_eq!(status(&third), Some(200), "{:?}", last(&third).failure);
    let c = conn(&third);
    assert!(c.reused, "same header plan, same pooled connection");
    assert_eq!(c.id, conn(&second).id);
    let p = last(&third).phase(Phase::ProxyProtocolHeader).expect("header phase on the reused attempt");
    assert_eq!(p.status, PhaseStatus::Reused);
    assert!(p.detail.as_deref().unwrap_or_default().contains(&format!("sent once when connection #{} was opened", c.id)), "{p:?}");
    assert!(c.proxy_header.is_some(), "the connection's header stays in its evidence");
    assert_eq!(last(&third).phase(Phase::TlsHandshake).map(|t| t.status), Some(PhaseStatus::Reused));
    let ed = early(&third);
    assert!(!ed.offered, "{ed:?}");
    assert_eq!(ed.not_used, Some(EarlyDataNotUsed::ConnectionReused));
    assert!(!codes(&third).iter().any(|c| c.starts_with("early_data.")), "{:?}", codes(&third));

    // Ground truth: two connections, two headers; the reused request was not early data.
    let want = (Some(addr(SOURCE)), Some(addr(DESTINATION)), true, false);
    assert_eq!(parsed(&relay), vec![want, want]);
    assert_eq!(server_connections(&fx), 2);
    assert_eq!(fx.requests().iter().map(|r| r.0).collect::<Vec<_>>(), vec![false, true, false], "{:?}", fx.requests());
}
