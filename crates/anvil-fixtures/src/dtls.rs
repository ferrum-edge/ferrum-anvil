//! DTLS 1.2 echo fixture built on dimpl (Sans-IO, RustCrypto provider).
//!
//! dimpl verifies handshake signatures but performs no PKI validation. When
//! client authentication is configured, this fixture validates the client's
//! leaf certificate itself (rustls `WebPkiClientVerifier` against the
//! configured client CA) and rejects an untrusted identity with a plaintext
//! fatal alert (`unknown_ca`) before it sends its final flight — the same
//! observable behavior as a conventional DTLS server.
//!
//! Every application datagram received after the handshake is echoed back.

use crate::log::{GroundTruth, GroundTruthLog};
use dimpl::{Config, Dtls, DtlsCertificate, Output};
use rustls::server::WebPkiClientVerifier;
use rustls::server::danger::ClientCertVerifier;
use rustls_pki_types::{CertificateDer, UnixTime};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

#[derive(Clone, Debug)]
pub struct DtlsServerOptions {
    /// Server certificate (ECDSA P-256/P-384; dimpl does not support RSA).
    pub cert_pem: String,
    /// PKCS#8 or SEC1 private key PEM.
    pub key_pem: String,
    /// When set, a client certificate chaining to this CA is required.
    pub client_ca_pem: Option<String>,
}

pub struct DtlsFixture {
    pub addr: SocketAddr,
    pub log: GroundTruthLog,
    cancel: CancellationToken,
}

impl DtlsFixture {
    pub fn url(&self) -> String {
        format!("dtls://{}", self.addr)
    }

    pub fn completed_handshakes(&self) -> Vec<Option<String>> {
        self.log
            .entries()
            .into_iter()
            .filter_map(|e| match e.event {
                GroundTruth::TlsHandshakeCompleted { client_cert_cn, .. } => Some(client_cert_cn),
                _ => None,
            })
            .collect()
    }

    pub fn failed_handshakes(&self) -> Vec<String> {
        self.log
            .entries()
            .into_iter()
            .filter_map(|e| match e.event {
                GroundTruth::TlsHandshakeFailed { error } => Some(error),
                _ => None,
            })
            .collect()
    }
}

impl Drop for DtlsFixture {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

struct Session {
    dtls: Dtls,
    next_timeout: Option<Instant>,
    connected: bool,
}

enum Out {
    Packet(Vec<u8>),
    PeerCert(Vec<u8>),
    Connected,
    App(Vec<u8>),
    Close,
}

/// Drain dimpl output until it asks for a timer.
fn drain(s: &mut Session) -> Vec<Out> {
    let mut outs = Vec::new();
    let mut buf = vec![0u8; 2048];
    for _ in 0..1024 {
        match s.dtls.poll_output(&mut buf) {
            Output::Packet(p) => outs.push(Out::Packet(p.to_vec())),
            Output::Timeout(t) => {
                s.next_timeout = Some(t);
                break;
            }
            Output::Connected => outs.push(Out::Connected),
            Output::PeerCert(c) => outs.push(Out::PeerCert(c.to_vec())),
            Output::ApplicationData(d) => outs.push(Out::App(d.to_vec())),
            Output::CloseNotify => outs.push(Out::Close),
            _ => {}
        }
    }
    outs
}

/// Plaintext (epoch 0) DTLS 1.2 fatal alert record.
fn fatal_alert(description: u8) -> Vec<u8> {
    let mut r = vec![21u8, 0xfe, 0xfd, 0, 0];
    r.extend_from_slice(&[0, 0, 0, 0, 0x10, 0x00]); // sequence number (fresh, unauthenticated epoch 0)
    r.extend_from_slice(&[0, 2, 2, description]);
    r
}

/// Common name of a DER certificate (fixture helper, no full X.509 parser).
pub fn cn_from_der(der: &[u8]) -> Option<String> {
    let mut last = None;
    for i in 0..der.len().saturating_sub(5) {
        if der[i] == 0x55 && der[i + 1] == 0x04 && der[i + 2] == 0x03 {
            let len = der[i + 4] as usize;
            if i + 5 + len <= der.len() {
                last = String::from_utf8(der[i + 5..i + 5 + len].to_vec()).ok();
            }
        }
    }
    last
}

pub async fn serve(bind: &str, opts: DtlsServerOptions) -> anyhow::Result<DtlsFixture> {
    let cert_der = crate::tlsserver::certs(&opts.cert_pem).into_iter().next().ok_or_else(|| anyhow::anyhow!("no server certificate"))?;
    let key_der = crate::tlsserver::key(&opts.key_pem).secret_der().to_vec();
    let certificate = DtlsCertificate { certificate: cert_der.as_ref().to_vec(), private_key: key_der };
    let config = Arc::new(
        Config::builder()
            .with_crypto_provider(dimpl::crypto::rust_crypto::default_provider())
            .require_client_certificate(opts.client_ca_pem.is_some())
            .build()
            .map_err(|e| anyhow::anyhow!("dimpl config: {e:?}"))?,
    );
    let verifier: Option<Arc<dyn ClientCertVerifier>> = match &opts.client_ca_pem {
        Some(ca) => {
            let mut roots = rustls::RootCertStore::empty();
            for c in crate::tlsserver::certs(ca) {
                roots.add(c)?;
            }
            Some(WebPkiClientVerifier::builder_with_provider(Arc::new(roots), crate::tlsserver::provider()).build()?)
        }
        None => None,
    };
    let sock = UdpSocket::bind(bind).await?;
    let addr = sock.local_addr()?;
    let log = GroundTruthLog::default();
    let cancel = CancellationToken::new();
    let (l2, c2) = (log.clone(), cancel.clone());
    tokio::spawn(async move {
        let mut sessions: HashMap<SocketAddr, Session> = HashMap::new();
        let mut buf = vec![0u8; 65_535];
        loop {
            let next = sessions.values().filter_map(|s| s.next_timeout).min();
            let sleep = async {
                match next {
                    Some(t) => tokio::time::sleep_until(tokio::time::Instant::from_std(t)).await,
                    None => tokio::time::sleep(Duration::from_secs(3600)).await,
                }
            };
            let mut ready: Vec<SocketAddr> = Vec::new();
            tokio::select! {
                r = sock.recv_from(&mut buf) => {
                    let Ok((n, peer)) = r else { continue };
                    if !sessions.contains_key(&peer) {
                        if sessions.len() >= 64 {
                            continue;
                        }
                        l2.push(GroundTruth::ConnectionAccepted { peer: peer.to_string() });
                        let now = Instant::now();
                        let mut dtls = Dtls::new_12(config.clone(), certificate.clone(), now);
                        // dimpl seeds per-connection state (server random) on the first timeout tick.
                        let _ = dtls.handle_timeout(now);
                        sessions.insert(peer, Session { dtls, next_timeout: None, connected: false });
                    }
                    let s = sessions.get_mut(&peer).expect("session");
                    if let Err(e) = s.dtls.handle_packet(&buf[..n]) {
                        l2.push(GroundTruth::TlsHandshakeFailed { error: format!("{e:?}") });
                        sessions.remove(&peer);
                        continue;
                    }
                    ready.push(peer);
                }
                _ = sleep => {
                    let now = Instant::now();
                    for (peer, s) in sessions.iter_mut() {
                        if s.next_timeout.map(|t| t <= now).unwrap_or(false) {
                            s.next_timeout = None;
                            let _ = s.dtls.handle_timeout(now);
                            ready.push(*peer);
                        }
                    }
                }
                _ = c2.cancelled() => break,
            }
            for peer in ready {
                let mut remove = false;
                let mut rounds = 0;
                loop {
                    rounds += 1;
                    let Some(s) = sessions.get_mut(&peer) else { break };
                    let outs = drain(s);
                    // Validate a presented client identity before releasing this flight.
                    let mut reject = None;
                    let mut client_cn = None;
                    for o in &outs {
                        if let Out::PeerCert(der) = o {
                            client_cn = cn_from_der(der);
                            if let Some(v) = &verifier {
                                let leaf = CertificateDer::from(der.clone());
                                if let Err(e) = v.verify_client_cert(&leaf, &[], UnixTime::now()) {
                                    reject = Some(e.to_string());
                                }
                            }
                        }
                    }
                    if let Some(err) = reject {
                        l2.push(GroundTruth::TlsHandshakeFailed { error: format!("client certificate rejected: {err}") });
                        let _ = sock.send_to(&fatal_alert(48), peer).await; // unknown_ca
                        remove = true;
                        break;
                    }
                    let mut echoed = false;
                    for o in outs {
                        match o {
                            Out::Packet(p) => {
                                let _ = sock.send_to(&p, peer).await;
                            }
                            Out::Connected => {
                                s.connected = true;
                                l2.push(GroundTruth::TlsHandshakeCompleted { alpn: None, client_cert_cn: client_cn.clone() });
                            }
                            Out::App(d) => {
                                l2.push(GroundTruth::DatagramReceived { bytes: d.len() as u64 });
                                if s.connected && s.dtls.send_application_data(&d).is_ok() {
                                    echoed = true;
                                }
                            }
                            Out::Close => {
                                l2.push(GroundTruth::FaultApplied { fault: "dtls_close_notify_received".into() });
                                remove = true;
                            }
                            Out::PeerCert(_) => {}
                        }
                    }
                    if !echoed || remove || rounds > 8 {
                        break;
                    }
                }
                if remove {
                    sessions.remove(&peer);
                }
            }
        }
    });
    Ok(DtlsFixture { addr, log, cancel })
}
