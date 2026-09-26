//! UDP through an HBONE tunnel at the transport level: the datagram
//! tunnel's outer leg is recorded exactly like the byte-stream tunnel's,
//! records cross the stream intact, and tunnel-leg failures stay typed as
//! such. Real local sockets; ground truth from the fixtures' own logs.

use anvil_domain::execution::*;
use anvil_domain::outcome::{ClosedBy, ProtocolStatus};
use anvil_domain::settings::Timeouts;
use anvil_domain::tls::{ProxyKind, ServerSpiffeIdentity};
use anvil_fixtures::hbone::{self, HboneOptions};
use anvil_fixtures::mesh_pki::{self, MeshPki};
use anvil_fixtures::streams::{self, UdpMode};
use anvil_fixtures::{ClientAuth, GroundTruth};
use anvil_transport::connector::ProxyPlan;
use anvil_transport::dns::DnsConfig;
use anvil_transport::hbone_udp::{self, HboneUdpPlan};
use anvil_transport::recorder::EventCtx;
use anvil_transport::session::{SessionOutput, TranscriptLimits};
use anvil_transport::tls::{self, ClientIdentityMaterial, TlsSettings};
use bytes::Bytes;
use std::sync::{Arc, OnceLock};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

fn mesh() -> &'static MeshPki {
    static P: OnceLock<MeshPki> = OnceLock::new();
    P.get_or_init(MeshPki::generate)
}

fn init() {
    anvil_transport::init();
    anvil_fixtures::init();
}

fn timeouts() -> Timeouts {
    Timeouts {
        dns_ms: Some(2000),
        connect_ms: Some(2000),
        tls_handshake_ms: Some(1500),
        request_write_ms: Some(2000),
        response_headers_ms: Some(2000),
        body_idle_ms: Some(1000),
        total_ms: Some(8000),
    }
}

fn client_svid_tls() -> TlsSettings {
    TlsSettings {
        verify: true,
        use_system_roots: false,
        extra_roots_pem: vec![mesh().ca.cert.clone()],
        client_identity: Some(ClientIdentityMaterial {
            cert_chain_pem: mesh().client.chain_with(&mesh().ca),
            private_key_pem: Zeroizing::new(mesh().client.key.clone()),
        }),
        server_spiffe: Some(ServerSpiffeIdentity {
            expected_server_spiffe_id: Some(mesh_pki::ZTUNNEL_SPIFFE_ID.into()),
            trust_domain: None,
        }),
        ..Default::default()
    }
}

fn proxy(addr: &str) -> ProxyPlan {
    let (host, port) = addr.rsplit_once(':').unwrap();
    ProxyPlan {
        kind: ProxyKind::Hbone,
        host: host.into(),
        port: port.parse().unwrap(),
        credentials: None,
        tls: Some(Arc::new(tls::prepare(&client_svid_tls()).expect("hbone tls"))),
        label: format!("test hbone ({addr})"),
        connect_headers: vec![(http::HeaderName::from_static("x-ferrum-mesh-protocol"), http::HeaderValue::from_static("udp"))],
    }
}

fn plan(target: std::net::SocketAddr, proxy: ProxyPlan, datagrams: &[&[u8]]) -> HboneUdpPlan {
    HboneUdpPlan {
        host: target.ip().to_string(),
        port: target.port(),
        proxy,
        dns: DnsConfig::default(),
        timeouts: timeouts(),
        datagrams: datagrams.iter().map(|d| Bytes::copy_from_slice(d)).collect(),
        response_window_ms: 300,
        max_datagrams: 100,
        display_url: format!("udp://{target}"),
        transcript: TranscriptLimits::default(),
        redact: None,
    }
}

async fn endpoint(alpn: &[&str], allowed: Vec<String>) -> hbone::HboneFixture {
    hbone::serve(
        "127.0.0.1:0",
        HboneOptions {
            server_cert_chain_pem: mesh().ztunnel.chain_with(&mesh().ca),
            server_key_pem: mesh().ztunnel.key.clone(),
            client_auth: ClientAuth::Required { ca_pem: mesh().ca.cert.clone() },
            alpn: alpn.iter().map(|s| s.to_string()).collect(),
            allowed,
            unavailable: vec![],
            udp_faults: vec![],
        },
    )
    .await
    .unwrap()
}

async fn run(p: &HboneUdpPlan) -> SessionOutput {
    hbone_udp::run(p, &EventCtx::none(), &CancellationToken::new(), None).await
}

fn attempt(o: &SessionOutput) -> &AttemptObservation {
    &o.attempts.last().unwrap().observation
}

fn tunnel(o: &SessionOutput) -> &TunnelObservation {
    attempt(o).connection.as_ref().and_then(|c| c.tunnel.as_ref()).expect("tunnel evidence")
}

#[tokio::test]
async fn the_datagram_tunnel_records_the_same_outer_leg_as_the_byte_stream_tunnel() {
    init();
    let echo = streams::udp("127.0.0.1:0", UdpMode::Echo).await.unwrap();
    let ep = endpoint(&["h2"], vec![echo.addr.to_string()]).await;
    let o = run(&plan(echo.addr, proxy(&ep.address()), &[b"one", b"", b"three"])).await;
    let a = attempt(&o);
    assert!(a.failure.is_none(), "{:?}", a.failure);
    assert!(matches!(o.status, ProtocolStatus::Udp { datagrams_sent: 3, datagrams_received: 3, masque: None, .. }), "{:?}", o.status);
    let t = tunnel(&o);
    let phases: Vec<Phase> = t.phases.iter().map(|p| p.phase).collect();
    assert_eq!(phases, vec![Phase::Dns, Phase::Connect, Phase::TlsHandshake, Phase::ProtocolHandshake, Phase::ProxyTunnel]);
    assert_eq!(t.tls.as_ref().unwrap().alpn_negotiated.as_deref(), Some("h2"));
    assert_eq!(t.tls.as_ref().unwrap().peer_spiffe_id.as_deref(), Some(mesh_pki::ZTUNNEL_SPIFFE_ID));
    assert_eq!(t.connect_status, Some(200));
    let ch = t.datagrams.as_ref().unwrap();
    assert_eq!((ch.records_sent, ch.records_received, ch.closed_by), (3, 3, ClosedBy::Client));
    let received: Vec<&str> = o
        .transcript
        .as_ref()
        .unwrap()
        .messages
        .iter()
        .filter(|m| m.direction == Direction::Received && m.kind == "datagram")
        .map(|m| m.preview.as_str())
        .collect();
    assert_eq!(received, vec!["one", "", "three"]);
    assert!(a.bytes.connection_bytes_written.unwrap_or(0) > 0, "outer TLS bytes are counted");
    // Ground truth: the destination got the three datagrams, sizes intact.
    let sizes: Vec<u64> = echo
        .log
        .entries()
        .iter()
        .filter_map(|e| match e.event {
            GroundTruth::DatagramReceived { bytes } => Some(bytes),
            _ => None,
        })
        .collect();
    assert_eq!(sizes, vec![3, 0, 5]);
}

#[tokio::test]
async fn tunnel_leg_failures_on_the_udp_path_stay_typed_as_the_tunnels() {
    init();
    let echo = streams::udp("127.0.0.1:0", UdpMode::Echo).await.unwrap();

    // An endpoint that does not offer HTTP/2.
    let h1 = endpoint(&["http/1.1"], vec![echo.addr.to_string()]).await;
    let o = run(&plan(echo.addr, proxy(&h1.address()), &[b"x"])).await;
    let f = attempt(&o).failure.as_ref().unwrap();
    assert_eq!(f.kind, FailureKind::HboneProtocolError);
    assert_eq!(tunnel(&o).failure.as_ref().unwrap().kind, FailureKind::TlsAlpnMismatch);
    assert!(tunnel(&o).datagrams.is_some(), "the datagram channel is recorded even when the tunnel never opened");
    assert_eq!(attempt(&o).dispatch, DispatchState::NotDispatched);

    // An endpoint that is not there.
    let o = run(&plan(echo.addr, proxy("127.0.0.1:1"), &[b"x"])).await;
    assert_eq!(attempt(&o).failure.as_ref().unwrap().kind, FailureKind::ProxyConnectFailed);
    assert!(matches!(o.status, ProtocolStatus::Udp { datagrams_sent: 0, datagrams_received: 0, .. }));
    assert!(o.transcript.is_none(), "the session never opened");
    assert!(echo.log.entries().is_empty(), "nothing reached the destination");
}
