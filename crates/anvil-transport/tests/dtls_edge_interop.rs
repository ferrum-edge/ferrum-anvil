//! Anvil's DTLS client against the DTLS stack every supported Ferrum Edge
//! release serves: dimpl 0.6.1 (`dimpl-edge`), whose DTLS 1.3
//! CertificateRequest carries an empty `certificate_authorities` extension
//! when the listener requires client certificates. Unpatched dimpl 0.8.0
//! drops that message without an alert, so the client never presents its
//! identity and the handshake times out. That reached `main` once (the
//! vendored dimpl in vendor/dimpl-0.8.0-empty-ca now accepts the list): Anvil's
//! own fixtures run the same dimpl as the client and passed, and only the
//! nightly lab's PROTO-022 against a real gateway failed. This test keeps the
//! cross-version handshake in the required Rust lane.

use anvil_domain::execution::*;
use anvil_domain::outcome::ProtocolStatus;
use anvil_domain::settings::Timeouts;
use anvil_fixtures::LabPki;
use anvil_transport::dns::DnsConfig;
use anvil_transport::dtls;
use anvil_transport::recorder::EventCtx;
use anvil_transport::session::TranscriptLimits;
use anvil_transport::tls::{self, TlsSettings};
use bytes::Bytes;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

/// What the Edge-side server saw: whether a client certificate arrived, and
/// the error that ended it, if any (so a server-side failure is not mistaken
/// for the client's handshake timeout).
#[derive(Default)]
struct ServerView {
    saw_client_cert: AtomicBool,
    error: Mutex<Option<String>>,
}

impl ServerView {
    fn fail(&self, what: String) {
        self.error.lock().unwrap().get_or_insert(what);
    }
}

/// A one-peer DTLS echo server on Ferrum Edge's dimpl, configured as Edge's
/// frontend DTLS listener is when a client CA is set
/// (`require_client_certificate(true)`).
async fn edge_dtls_echo(view: Arc<ServerView>) -> std::net::SocketAddr {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let config = Arc::new(dimpl_edge::Config::builder().require_client_certificate(true).build().unwrap());
        let cert = dimpl_edge::certificate::generate_self_signed_certificate().unwrap();
        let mut server = dimpl_edge::Dtls::new_auto(config, cert, Instant::now());
        let _ = server.handle_timeout(Instant::now());
        let mut peer = None;
        let mut next: Option<Instant> = None; // set by every drain (it ends at Timeout)
        let mut buf = vec![0u8; 2048];
        let mut out = vec![0u8; 4096];
        loop {
            let wait = next.map(|t| t.saturating_duration_since(Instant::now())).unwrap_or(Duration::from_millis(100));
            tokio::select! {
                r = sock.recv_from(&mut buf) => {
                    let (n, from) = match r {
                        Ok(r) => r,
                        Err(e) => return view.fail(format!("server recv: {e}")),
                    };
                    peer = Some(from);
                    if let Err(e) = server.handle_packet(&buf[..n]) {
                        return view.fail(format!("server handle_packet: {e:?}"));
                    }
                }
                _ = tokio::time::sleep(wait) => {
                    if let Err(e) = server.handle_timeout(Instant::now()) {
                        return view.fail(format!("server handle_timeout: {e:?}"));
                    }
                }
            }
            // Drain to the Timeout that ends every poll cycle, echoing any
            // application data and draining again after each echo.
            loop {
                let mut echo = None;
                loop {
                    match server.poll_output(&mut out) {
                        dimpl_edge::Output::Packet(p) => {
                            if let Some(to) = peer {
                                let _ = sock.send_to(p, to).await;
                            }
                        }
                        dimpl_edge::Output::Timeout(t) => {
                            next = Some(t);
                            break;
                        }
                        dimpl_edge::Output::PeerCert(_) => view.saw_client_cert.store(true, Ordering::SeqCst),
                        dimpl_edge::Output::ApplicationData(d) => echo = Some(d.to_vec()),
                        _ => {}
                    }
                }
                let Some(d) = echo else { break };
                if let Err(e) = server.send_application_data(&d) {
                    return view.fail(format!("server send_application_data: {e:?}"));
                }
            }
        }
    });
    addr
}

/// PROTO-022 without the gateway: a DTLS 1.3 listener that requires client
/// certificates gets Anvil's client identity, and the datagram is echoed.
#[tokio::test]
async fn proto_022_dtls_mtls_handshake_with_ferrum_edge_dimpl_completes() {
    anvil_transport::init();
    anvil_fixtures::init();
    let pki = LabPki::generate();
    let view = Arc::new(ServerView::default());
    let addr = edge_dtls_echo(view.clone()).await;
    let prepared = Arc::new(tls::prepare(&TlsSettings { verify: false, ..Default::default() }).unwrap());
    let plan = dtls::DtlsPlan {
        host: "127.0.0.1".into(),
        port: addr.port(),
        dns: DnsConfig::default(),
        timeouts: Timeouts {
            dns_ms: Some(2_000),
            connect_ms: Some(2_000),
            tls_handshake_ms: Some(3_000),
            request_write_ms: Some(2_000),
            response_headers_ms: Some(3_000),
            body_idle_ms: Some(3_000),
            total_ms: Some(15_000),
        },
        tls: prepared,
        identity: Some(dtls::identity_from_pem(&pki.client_a.cert, &pki.client_a.key).unwrap()),
        datagrams: vec![Bytes::from_static(b"proto-022")],
        response_window_ms: 2_000,
        max_datagrams: 1,
        display_url: format!("dtls://{addr}"),
        transcript: TranscriptLimits::default(),
        redact: None,
        envelope: None,
        masque: None,
        hbone: None,
    };
    let out = dtls::run(&plan, &EventCtx::none(), &CancellationToken::new(), None).await;
    let o = &out.attempts[0].observation;
    let server_error = view.error.lock().unwrap().clone();
    assert_eq!(o.phase(Phase::DtlsHandshake).unwrap().status, PhaseStatus::Completed, "client: {:?}; server: {server_error:?}", o.failure);
    let tls = o.connection.as_ref().and_then(|c| c.tls.as_ref()).expect("TLS evidence");
    assert_eq!(tls.version.as_deref(), Some("DTLSv1_3"), "the case that regressed is DTLS 1.3");
    // DTLS 1.3 encrypts the CertificateRequest, so the client cannot report
    // it (`client_certificate_requested` stays unknown); the server's view is
    // the ground truth.
    assert!(view.saw_client_cert.load(Ordering::SeqCst), "the server received the client certificate");
    assert!(matches!(&out.status, ProtocolStatus::Udp { datagrams_received: 1, .. }), "{:?}", out.status);
}
