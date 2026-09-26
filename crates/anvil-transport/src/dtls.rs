//! DTLS datagram exchanges (RFC 6347 / RFC 9147) with `dimpl`.
//!
//! This is a dedicated DTLS implementation choice, not the TLS adapter:
//! * dimpl (RustCrypto provider) supports DTLS 1.2 and 1.3 with ECDSA
//!   P-256/P-384 certificates only (no RSA). The client offers both versions
//!   (hybrid ClientHello) and records the negotiated one.
//! * dimpl verifies handshake signatures but performs **no PKI validation**.
//!   Anvil validates the peer's leaf certificate itself with the same
//!   webpki verifier (trust anchors, validity, name) that the TLS profile
//!   builds for TLS, before releasing the next flight; a failure aborts the
//!   handshake and is recorded as typed verification evidence. dimpl surfaces
//!   only the peer's leaf, so a chain that needs an intermediate validates
//!   only when that intermediate is itself a configured trust anchor.
//! * dimpl sends a single client certificate (no chain) and always needs a
//!   key pair; when no client identity is configured and the server asks for
//!   one, an ephemeral self-signed certificate
//!   (`CN=anvil-ephemeral-dtls-client`) is what gets presented, and the
//!   evidence says so.
//! * Retransmission timers are driven from dimpl's `Timeout` outputs; the
//!   handshake deadline is the TLS handshake timeout class.
//! * For DTLS 1.2, whether the server sent a CertificateRequest is observed
//!   from its plaintext flight. For DTLS 1.3 that message is encrypted, so it
//!   is recorded as not observed.

use crate::certs::summarize;
use crate::dns::DnsConfig;
use crate::errors::classify_rustls;
use crate::http::{AttemptOutput, sleep_until_opt};
use crate::recorder::{EventCtx, Recorder};
use crate::session::*;
use crate::tls::PreparedTls;
use anvil_domain::events::{ExecutionEvent, SessionCommand};
use anvil_domain::execution::*;
use anvil_domain::outcome::ProtocolStatus;
use anvil_domain::settings::Timeouts;
use bytes::Bytes;
use dimpl::{Config, Dtls, DtlsCertificate, Output, ProtocolVersion};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, UnixTime};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

/// Client identity in the form dimpl needs (leaf DER + PKCS#8/SEC1 key DER).
#[derive(Clone)]
pub struct DtlsIdentity {
    pub cert_der: Vec<u8>,
    pub key_der: Zeroizing<Vec<u8>>,
    pub summary: CertificateSummary,
    /// Certificates beyond the leaf that dimpl cannot send.
    pub unsent_chain: usize,
}

impl std::fmt::Debug for DtlsIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DtlsIdentity").field("subject", &self.summary.subject).field("key", &"‹redacted›").finish()
    }
}

fn local(kind: FailureKind, msg: impl Into<String>, field: &str) -> TransportFailure {
    TransportFailure::new(Phase::Prepare, kind, msg).with_field(field)
}

/// Convert a PEM client identity for DTLS. Only ECDSA P-256/P-384 keys are
/// usable with dimpl's RustCrypto provider; anything else fails locally.
pub fn identity_from_pem(cert_chain_pem: &str, key_pem: &str) -> Result<DtlsIdentity, TransportFailure> {
    use rustls_pki_types::pem::PemObject;
    let certs: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(cert_chain_pem.as_bytes()).collect::<Result<_, _>>().map_err(|e| {
            local(FailureKind::ClientIdentityInvalid, format!("certificate PEM could not be parsed: {e}"), "tls.client_identity")
        })?;
    let Some(leaf) = certs.first() else {
        return Err(local(FailureKind::ClientIdentityInvalid, "no CERTIFICATE blocks found in PEM", "tls.client_identity"));
    };
    let key = match PrivateKeyDer::from_pem_slice(key_pem.as_bytes()) {
        Ok(PrivateKeyDer::Pkcs8(k)) => k.secret_pkcs8_der().to_vec(),
        Ok(PrivateKeyDer::Sec1(k)) => k.secret_sec1_der().to_vec(),
        Ok(_) => {
            return Err(local(
                FailureKind::ClientIdentityInvalid,
                "RSA client keys cannot be used for DTLS: the DTLS implementation (dimpl) supports ECDSA P-256/P-384 keys only",
                "tls.client_identity.private_key",
            ));
        }
        _ => return Err(local(FailureKind::ClientIdentityInvalid, "no private key found in PEM", "tls.client_identity.private_key")),
    };
    dimpl::crypto::rust_crypto::default_provider().key_provider.load_private_key(&key).map_err(|e| {
        local(
            FailureKind::ClientIdentityInvalid,
            format!("the client key cannot be used for DTLS (ECDSA P-256/P-384 only): {e}"),
            "tls.client_identity.private_key",
        )
    })?;
    Ok(DtlsIdentity {
        cert_der: leaf.as_ref().to_vec(),
        key_der: Zeroizing::new(key),
        summary: summarize(leaf),
        unsent_chain: certs.len() - 1,
    })
}

/// Process-wide ephemeral self-signed identity (dimpl always needs one).
fn ephemeral_identity() -> Result<DtlsIdentity, String> {
    static E: OnceLock<Result<DtlsIdentity, String>> = OnceLock::new();
    E.get_or_init(|| {
        let key = rcgen::KeyPair::generate().map_err(|e| e.to_string())?;
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).map_err(|e| e.to_string())?;
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(rcgen::DnType::CommonName, "anvil-ephemeral-dtls-client");
        params.distinguished_name = dn;
        let cert = params.self_signed(&key).map_err(|e| e.to_string())?;
        let der = cert.der().to_vec();
        Ok(DtlsIdentity {
            summary: summarize(&CertificateDer::from(der.clone())),
            cert_der: der,
            key_der: Zeroizing::new(key.serialize_der()),
            unsent_chain: 0,
        })
    })
    .clone()
}

#[derive(Clone)]
pub struct DtlsPlan {
    pub host: String,
    pub port: u16,
    pub dns: DnsConfig,
    pub timeouts: Timeouts,
    /// Trust/verification settings from the TLS profile.
    pub tls: Arc<PreparedTls>,
    pub identity: Option<DtlsIdentity>,
    pub datagrams: Vec<Bytes>,
    pub response_window_ms: u64,
    pub max_datagrams: u32,
    pub display_url: String,
    pub transcript: TranscriptLimits,
    pub redact: Option<RedactFn>,
    /// PROXY v2 `DGRAM` envelope prepended to every UDP datagram, outside the
    /// DTLS records (handshake flights included).
    pub envelope: Option<crate::proxy_protocol::EnvelopePlan>,
}

async fn next_cmd(rx: &mut Option<CommandRx>) -> Option<SessionCommand> {
    match rx {
        Some(r) => r.recv().await,
        None => std::future::pending().await,
    }
}

enum Out {
    Packet(Vec<u8>),
    PeerCert(Vec<u8>),
    Connected,
    App(Vec<u8>),
    Close,
}

fn drain(dtls: &mut Dtls, next_timeout: &mut Option<Instant>) -> Vec<Out> {
    let mut outs = Vec::new();
    let mut buf = vec![0u8; 2048];
    for _ in 0..4096 {
        match dtls.poll_output(&mut buf) {
            Output::Packet(p) => outs.push(Out::Packet(p.to_vec())),
            Output::Timeout(t) => {
                *next_timeout = Some(t);
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

/// Validate the peer leaf with the profile's verifier (host name, or the
/// SPIFFE X.509-SVID identity when the profile configures one). Returns the
/// verification evidence and the leaf's SPIFFE ID, if it carries one.
fn verify_leaf(prepared: &PreparedTls, host: &str, der: &[u8]) -> (TlsVerification, Option<String>) {
    let leaf = CertificateDer::from(der.to_vec());
    match crate::tls::server_name_for(host, prepared) {
        Err(_) => {
            let e = rustls::Error::General(format!("'{host}' is not a valid verification name"));
            let v = if prepared.verify {
                TlsVerification::Failed { problem: classify_rustls(&e, false).0, detail: e.to_string() }
            } else {
                TlsVerification::Bypassed { would_have_failed: None }
            };
            (v, crate::spiffe::peer_spiffe_id(der))
        }
        Ok(name) => {
            let mut verdict = crate::tls::verify_peer(&prepared.peer_check(), &name, &leaf, &[], UnixTime::now());
            if prepared.verifier.is_none() && !prepared.verify {
                verdict.problem = None;
            }
            (crate::tls::verification_of(prepared.verify, &verdict), verdict.peer_spiffe_id)
        }
    }
}

fn u24(b: &[u8]) -> usize {
    ((b[0] as usize) << 16) | ((b[1] as usize) << 8) | b[2] as usize
}

/// Whether a datagram carries a plaintext (epoch 0) CertificateRequest.
fn has_certificate_request(mut p: &[u8]) -> bool {
    while p.len() >= 13 {
        let content_type = p[0];
        let epoch = u16::from_be_bytes([p[3], p[4]]);
        let len = u16::from_be_bytes([p[11], p[12]]) as usize;
        if p.len() < 13 + len {
            break;
        }
        let frag = &p[13..13 + len];
        if content_type == 22 && epoch == 0 {
            let mut off = 0;
            while off + 12 <= frag.len() {
                let msg_type = frag[off];
                let frag_offset = u24(&frag[off + 6..off + 9]);
                let frag_len = u24(&frag[off + 9..off + 12]);
                if msg_type == 13 && frag_offset == 0 {
                    return true;
                }
                off += 12 + frag_len;
            }
        }
        p = &p[13 + len..];
    }
    false
}

fn alert_name(code: u8) -> String {
    match code {
        0 => "close_notify",
        10 => "unexpected_message",
        20 => "bad_record_mac",
        22 => "record_overflow",
        40 => "handshake_failure",
        42 => "bad_certificate",
        43 => "unsupported_certificate",
        44 => "certificate_revoked",
        45 => "certificate_expired",
        46 => "certificate_unknown",
        47 => "illegal_parameter",
        48 => "unknown_ca",
        49 => "access_denied",
        50 => "decode_error",
        51 => "decrypt_error",
        70 => "protocol_version",
        71 => "insufficient_security",
        80 => "internal_error",
        86 => "inappropriate_fallback",
        90 => "user_canceled",
        109 => "missing_extension",
        110 => "unsupported_extension",
        112 => "unrecognized_name",
        115 => "unknown_psk_identity",
        116 => "certificate_required",
        120 => "no_application_protocol",
        _ => return format!("alert_{code}"),
    }
    .to_string()
}

/// Typed classification of a dimpl error. dimpl reports received alerts only
/// inside its own formatted error (`description=N`); the numeric alert code
/// is extracted from that fixed format — no cause is inferred from wording.
fn classify_dimpl(e: &dimpl::Error, deadline_ms: u64) -> TransportFailure {
    match e {
        dimpl::Error::Timeout(what) => TransportFailure::new(
            Phase::DtlsHandshake,
            FailureKind::DtlsHandshakeTimeout,
            format!("the DTLS handshake did not complete ({what}); retransmissions were exhausted"),
        )
        .with_deadline(Some(deadline_ms)),
        dimpl::Error::SecurityError(msg) => {
            let code =
                msg.split("description=").nth(1).and_then(|s| s.trim().split(|c: char| !c.is_ascii_digit()).next()?.parse::<u8>().ok());
            let mut f = TransportFailure::new(Phase::DtlsHandshake, FailureKind::DtlsHandshakeFailed, "");
            match code {
                Some(c) => {
                    let name = alert_name(c);
                    f.message = format!(
                        "the DTLS peer sent a fatal alert ({name}) during the handshake{}",
                        if matches!(c, 42 | 43 | 44 | 45 | 46 | 48 | 49 | 116) {
                            " — this alert concerns certificates; the peer may have rejected the client identity or the negotiated parameters"
                        } else {
                            ""
                        }
                    );
                    f.tls_alert = Some(name);
                }
                None => f.message = format!("the DTLS handshake failed a security check: {msg}"),
            }
            f
        }
        dimpl::Error::CertificateError(msg) => TransportFailure::new(
            Phase::DtlsHandshake,
            FailureKind::DtlsHandshakeFailed,
            format!("the DTLS certificate exchange failed: {msg}"),
        ),
        other => {
            TransportFailure::new(Phase::DtlsHandshake, FailureKind::DtlsHandshakeFailed, format!("the DTLS handshake failed: {other:?}"))
        }
    }
}

fn version_label(v: Option<ProtocolVersion>) -> Option<String> {
    match v? {
        ProtocolVersion::DTLS1_0 => Some("DTLSv1_0".into()),
        ProtocolVersion::DTLS1_2 => Some("DTLSv1_2".into()),
        ProtocolVersion::DTLS1_3 => Some("DTLSv1_3".into()),
        ProtocolVersion::Unknown(n) => Some(format!("DTLS(0x{n:04x})")),
    }
}

async fn send_all(sock: &UdpSocket, outs: &[Out], env: &mut Option<crate::proxy_protocol::Enveloper>) {
    for o in outs {
        if let Out::Packet(p) = o {
            let _ = sock.send(&crate::udp::wire(env, p)).await;
        }
    }
}

pub async fn run(plan: &DtlsPlan, events: &EventCtx, cancel: &CancellationToken, mut commands: Option<CommandRx>) -> SessionOutput {
    let interactive = commands.is_some();
    let mut rec = Recorder::new(0, events.clone());
    events.emit(ExecutionEvent::AttemptStarted { execution_id: events.execution_id, attempt: 0 });
    let mut obs = new_attempt(0, AttemptReason::Initial, "DTLS", &plan.display_url);
    let mut facts = SessionFacts::default();
    let (identity, ephemeral) = match &plan.identity {
        Some(i) => (i.clone(), false),
        None => match ephemeral_identity() {
            Ok(i) => (i, true),
            Err(e) => {
                let f = TransportFailure::new(Phase::Prepare, FailureKind::Internal, format!("could not create the DTLS key pair: {e}"));
                return SessionOutput::single(
                    fail_attempt(rec, obs, f, DispatchState::NotDispatched, events),
                    None,
                    ProtocolStatus::None,
                    facts,
                );
            }
        },
    };
    if identity.unsent_chain > 0 {
        facts
            .notes
            .push(format!("DTLS sends only the client leaf certificate; {} chain certificate(s) were not sent", identity.unsent_chain));
    }
    let (sock, addr, mut cobs) = match crate::udp::open_socket(&mut rec, &plan.host, plan.port, &plan.dns, &plan.timeouts, "dtls").await {
        Ok(x) => x,
        Err((f, cobs)) => {
            obs.connection = Some(cobs);
            return SessionOutput::single(
                fail_attempt(rec, obs, f, DispatchState::NotDispatched, events),
                None,
                ProtocolStatus::None,
                facts,
            );
        }
    };
    let mut env = match crate::udp::start_envelope(plan.envelope.as_ref(), &sock, addr, plan.redact.clone()) {
        Ok(e) => e,
        Err(f) => {
            obs.connection = Some(cobs);
            return SessionOutput::single(
                fail_attempt(rec, obs, f, DispatchState::NotDispatched, events),
                None,
                ProtocolStatus::None,
                facts,
            );
        }
    };
    if let Some(e) = &env {
        facts.notes.push(e.summary());
    }
    let hs_ms = plan.timeouts.tls_handshake_ms.or(plan.timeouts.connect_ms).unwrap_or(10_000);
    let config = match Config::builder()
        .with_crypto_provider(dimpl::crypto::rust_crypto::default_provider())
        .handshake_timeout(Duration::from_millis(hs_ms + 2_000))
        .flight_retries(8)
        .build()
    {
        Ok(c) => Arc::new(c),
        Err(e) => {
            let f = TransportFailure::new(Phase::Prepare, FailureKind::TlsProfileInvalid, format!("DTLS configuration rejected: {e:?}"));
            obs.connection = Some(cobs);
            return SessionOutput::single(
                fail_attempt(rec, obs, f, DispatchState::NotDispatched, events),
                None,
                ProtocolStatus::None,
                facts,
            );
        }
    };
    let cert = DtlsCertificate { certificate: identity.cert_der.clone(), private_key: identity.key_der.to_vec() };
    let start = Instant::now();
    let mut dtls = Dtls::new_auto(config, cert, start);
    dtls.set_active(true);
    // dimpl initializes per-connection state on the first timeout tick.
    if let Err(e) = dtls.handle_timeout(start) {
        let f = TransportFailure::new(Phase::Prepare, FailureKind::Internal, format!("the DTLS client could not start: {e:?}"));
        obs.connection = Some(cobs);
        return SessionOutput::single(fail_attempt(rec, obs, f, DispatchState::NotDispatched, events), None, ProtocolStatus::None, facts);
    }

    // ---- handshake ----
    let hs_idx = rec.start(Phase::DtlsHandshake);
    let hs_deadline = Instant::now() + Duration::from_millis(hs_ms);
    let mut next_timeout: Option<Instant> = None;
    let mut verification = TlsVerification::NotReached;
    let mut peer_chain: Vec<CertificateSummary> = vec![];
    let mut peer_spiffe_id: Option<String> = None;
    let mut cert_requested = false;
    let mut buf = vec![0u8; 65_535];
    enum HsEv {
        Recv(std::io::Result<usize>),
        Timer,
        Deadline,
        Canceled,
    }
    let hs: Result<(), TransportFailure> = 'hs: loop {
        let outs = drain(&mut dtls, &mut next_timeout);
        for o in &outs {
            if let Out::PeerCert(der) = o {
                peer_chain = vec![summarize(&CertificateDer::from(der.clone()))];
                (verification, peer_spiffe_id) = verify_leaf(&plan.tls, &plan.host, der);
                if let TlsVerification::Failed { problem, detail } = &verification {
                    break 'hs Err(TransportFailure::new(
                        Phase::DtlsHandshake,
                        *problem,
                        format!("the DTLS peer's certificate failed verification: {detail}; the handshake was aborted"),
                    ));
                }
            }
        }
        send_all(&sock, &outs, &mut env).await;
        if outs.iter().any(|o| matches!(o, Out::Connected)) {
            break Ok(());
        }
        let ev = tokio::select! {
            r = sock.recv(&mut buf) => HsEv::Recv(r),
            _ = sleep_until_opt(next_timeout) => HsEv::Timer,
            _ = tokio::time::sleep_until(tokio::time::Instant::from_std(hs_deadline)) => HsEv::Deadline,
            _ = cancel.cancelled() => HsEv::Canceled,
        };
        match ev {
            HsEv::Recv(Ok(n)) => {
                cert_requested |= has_certificate_request(&buf[..n]);
                if let Err(e) = dtls.handle_packet(&buf[..n]) {
                    break Err(classify_dimpl(&e, hs_ms));
                }
            }
            HsEv::Recv(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                facts.icmp_port_unreachable = true;
                let mut f = TransportFailure::new(
                    Phase::DtlsHandshake,
                    FailureKind::DtlsHandshakeFailed,
                    "the OS reported ICMP port unreachable for the destination (often: nothing is listening on that UDP port)",
                );
                f.io_error_kind = Some(format!("{:?}", e.kind()));
                break Err(f);
            }
            HsEv::Recv(Err(e)) => {
                let mut f = TransportFailure::new(
                    Phase::DtlsHandshake,
                    FailureKind::DtlsHandshakeFailed,
                    format!("receiving during the DTLS handshake failed: {e}"),
                );
                f.io_error_kind = Some(format!("{:?}", e.kind()));
                break Err(f);
            }
            HsEv::Timer => {
                next_timeout = None;
                if let Err(e) = dtls.handle_timeout(Instant::now()) {
                    break Err(classify_dimpl(&e, hs_ms));
                }
            }
            HsEv::Deadline => {
                break Err(TransportFailure::new(
                    Phase::DtlsHandshake,
                    FailureKind::DtlsHandshakeTimeout,
                    format!(
                        "no DTLS handshake completed within {hs_ms} ms; UDP gives no signal whether the datagrams reached a DTLS listener"
                    ),
                )
                .with_deadline(Some(hs_ms)));
            }
            HsEv::Canceled => {
                break Err(TransportFailure::new(Phase::DtlsHandshake, FailureKind::Canceled, "canceled during the DTLS handshake"));
            }
        }
    };
    let version = version_label(dtls.protocol_version());
    let is12 = version.as_deref() == Some("DTLSv1_2");
    let completed = hs.is_ok();
    let requested = if is12 && completed {
        Some(cert_requested)
    } else if cert_requested {
        Some(true)
    } else {
        None
    };
    let alert = hs.as_ref().err().and_then(|f| f.tls_alert.clone());
    let presented = if requested == Some(true) { Some(identity.summary.clone()) } else { None };
    if ephemeral && requested == Some(true) {
        facts.notes.push(
            "the DTLS server requested a client certificate but no client identity is configured; dimpl presented an ephemeral self-signed certificate (CN=anvil-ephemeral-dtls-client)"
                .into(),
        );
    }
    let server_name = plan.tls.server_name_override.clone().unwrap_or_else(|| plan.host.clone());
    cobs.tls = Some(TlsObservation {
        // dimpl is not configured with a server name: no SNI is sent; the
        // name is used for verification only.
        sni: None,
        server_name_overridden: plan.tls.server_name_override.is_some(),
        identity_check: Some(crate::tls::identity_check_for(&plan.tls, &server_name)),
        peer_spiffe_id,
        server_name,
        version: version.clone(),
        cipher_suite: None,
        alpn_offered: vec![],
        alpn_negotiated: None,
        verification: verification.clone(),
        peer_certificates: peer_chain,
        client_certificate_requested: requested,
        client_certificate_presented: presented,
        alert_received: alert,
        resumed: if completed { Some(false) } else { None },
    });
    if let Some(v) = &version {
        cobs.protocol = Some(v.to_ascii_lowercase());
    }
    cobs.proxy_header = env.as_ref().map(|e| e.observation());
    obs.connection = Some(cobs);
    if let Err(f) = hs {
        rec.finish(hs_idx, phase_status_for(f.kind));
        // Handshake datagrams only: no application data was dispatched.
        return SessionOutput::single(fail_attempt(rec, obs, f, DispatchState::NotDispatched, events), None, ProtocolStatus::None, facts);
    }
    rec.finish_with(hs_idx, PhaseStatus::Completed, version.clone().unwrap_or_else(|| "DTLS".into()));

    // ---- application datagrams ----
    let s_idx = rec.start(Phase::Session);
    let mut tr = Transcript::new(rec.t0, plan.transcript, events.clone(), plan.redact.clone());
    if let Some(e) = &env {
        tr.note("proxy_protocol_envelope", &e.summary());
    }
    let mut sent = 0u64;
    let mut received = 0u64;
    let mut failure: Option<TransportFailure> = None;
    let mut peer_closed = false;
    let mut seen: HashSet<[u8; 32]> = HashSet::new();
    let mut record_inbound = |outs: &[Out], tr: &mut Transcript, received: &mut u64, peer_closed: &mut bool, facts: &mut SessionFacts| {
        for o in outs {
            match o {
                Out::App(d) => {
                    *received += 1;
                    let mut digest = [0u8; 32];
                    digest.copy_from_slice(&Sha256::digest(d));
                    if !seen.insert(digest) {
                        facts.repeated_datagrams += 1;
                    }
                    tr.data(Direction::Received, "datagram", d);
                }
                Out::Close => {
                    *peer_closed = true;
                    tr.control(Direction::Received, "close_notify", b"");
                }
                _ => {}
            }
        }
    };
    for d in &plan.datagrams {
        if let Err(e) = dtls.send_application_data(d) {
            failure = Some(TransportFailure::new(
                Phase::RequestWrite,
                FailureKind::RequestWriteFailed,
                format!("DTLS could not send a datagram: {e:?}"),
            ));
            break;
        }
        let outs = drain(&mut dtls, &mut next_timeout);
        send_all(&sock, &outs, &mut env).await;
        sent += 1;
        tr.data(Direction::Sent, "datagram", d);
        record_inbound(&outs, &mut tr, &mut received, &mut peer_closed, &mut facts);
    }
    let total_deadline = if interactive { None } else { deadline_from(plan.timeouts.total_ms) };
    let window = Duration::from_millis(plan.response_window_ms);
    let mut window_end = Instant::now() + window;
    enum Ev {
        Recv(std::io::Result<usize>),
        Timer,
        Cmd(Option<SessionCommand>),
        WindowEnd,
        Deadline,
        Canceled,
    }
    while failure.is_none() && !peer_closed && received < plan.max_datagrams as u64 {
        let window_deadline = if interactive { None } else { Some(window_end) };
        let ev = tokio::select! {
            r = sock.recv(&mut buf) => Ev::Recv(r),
            _ = sleep_until_opt(next_timeout) => Ev::Timer,
            c = next_cmd(&mut commands), if interactive => Ev::Cmd(c),
            _ = sleep_until_opt(window_deadline) => Ev::WindowEnd,
            _ = sleep_until_opt(total_deadline) => Ev::Deadline,
            _ = cancel.cancelled() => Ev::Canceled,
        };
        match ev {
            Ev::Recv(Ok(n)) => {
                if let Err(e) = dtls.handle_packet(&buf[..n]) {
                    let mut f = classify_dimpl(&e, hs_ms);
                    f.phase = Phase::Session;
                    failure = Some(f);
                    break;
                }
                let outs = drain(&mut dtls, &mut next_timeout);
                send_all(&sock, &outs, &mut env).await;
                record_inbound(&outs, &mut tr, &mut received, &mut peer_closed, &mut facts);
            }
            Ev::Recv(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                if !facts.icmp_port_unreachable {
                    facts.icmp_port_unreachable = true;
                    tr.note("icmp_port_unreachable", "the OS reported ICMP port unreachable for the destination");
                }
            }
            Ev::Recv(Err(e)) => tr.note("error", &format!("receive error: {e}")),
            Ev::Timer => {
                next_timeout = None;
                if dtls.handle_timeout(Instant::now()).is_ok() {
                    let outs = drain(&mut dtls, &mut next_timeout);
                    send_all(&sock, &outs, &mut env).await;
                    record_inbound(&outs, &mut tr, &mut received, &mut peer_closed, &mut facts);
                }
            }
            Ev::Cmd(c) => {
                let payload: Option<Vec<u8>> = match c {
                    Some(SessionCommand::SendText { text }) => Some(text.into_bytes()),
                    Some(SessionCommand::SendBinaryHex { hex }) => match decode_hex(&hex) {
                        Ok(b) => Some(b),
                        Err(e) => {
                            tr.note("error", &format!("datagram not sent: {e}"));
                            None
                        }
                    },
                    Some(SessionCommand::Ping) | Some(SessionCommand::HalfClose) => {
                        tr.note("unsupported_command", "DTLS datagrams have no ping or half-close; send a datagram or Close");
                        None
                    }
                    Some(SessionCommand::Close { .. }) | None => break,
                };
                if let Some(p) = payload {
                    if dtls.send_application_data(&p).is_ok() {
                        let outs = drain(&mut dtls, &mut next_timeout);
                        send_all(&sock, &outs, &mut env).await;
                        sent += 1;
                        tr.data(Direction::Sent, "datagram", &p);
                        record_inbound(&outs, &mut tr, &mut received, &mut peer_closed, &mut facts);
                    }
                    window_end = Instant::now() + window;
                }
            }
            Ev::WindowEnd => break,
            Ev::Deadline => {
                failure = Some(
                    TransportFailure::new(Phase::Session, FailureKind::TotalTimeout, "the total deadline elapsed during the DTLS exchange")
                        .with_deadline(plan.timeouts.total_ms),
                );
            }
            Ev::Canceled => failure = Some(TransportFailure::new(Phase::Session, FailureKind::Canceled, "the DTLS exchange was canceled")),
        }
    }
    // Graceful close_notify (not retransmitted per RFC 6347 §4.2.7).
    if !peer_closed && dtls.close().is_ok() {
        let outs = drain(&mut dtls, &mut next_timeout);
        send_all(&sock, &outs, &mut env).await;
        tr.control(Direction::Sent, "close_notify", b"");
    }
    if facts.repeated_datagrams > 0 {
        facts.notes.push(format!(
            "{} received datagram(s) were byte-identical to an earlier one (the peer may send identical replies; not proof of duplication)",
            facts.repeated_datagrams
        ));
    }
    rec.finish(
        s_idx,
        match &failure {
            Some(f) => phase_status_for(f.kind),
            None => PhaseStatus::Completed,
        },
    );
    obs.dispatch = if sent == 0 {
        DispatchState::NotDispatched
    } else if received > 0 {
        DispatchState::Sent
    } else {
        DispatchState::MayHaveBeenSent
    };
    obs.failure = failure;
    obs.bytes.request_body = tr.sent_bytes();
    obs.bytes.response_body_wire = Some(tr.received_bytes());
    if let (Some(e), Some(c)) = (&env, obs.connection.as_mut()) {
        c.proxy_header = Some(e.observation());
    }
    let obs = finish_attempt(rec, obs, events);
    let ps = ProtocolStatus::Udp { datagrams_sent: sent, datagrams_received: received, window_ms: plan.response_window_ms, masque: None };
    SessionOutput::single(AttemptOutput { observation: obs, response: None, body: Bytes::new() }, Some(tr.finish()), ps, facts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn certificate_request_is_found_in_a_plaintext_flight() {
        // record header (handshake, DTLS 1.2, epoch 0) + ServerHelloDone-like msg + CertificateRequest header
        let mut hs = vec![14u8, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0];
        hs.extend_from_slice(&[13u8, 0, 0, 1, 0, 3, 0, 0, 0, 0, 0, 1, 0xAA]);
        let mut rec = vec![22u8, 0xfe, 0xfd, 0, 0, 0, 0, 0, 0, 0, 5];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        assert!(has_certificate_request(&rec));
        rec[4] = 1; // epoch 1 = encrypted, not inspected
        assert!(!has_certificate_request(&rec));
    }

    #[test]
    fn rsa_identities_are_refused_before_traffic() {
        let b64 = "MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu";
        let cert = format!("-----BEGIN CERTIFICATE-----\n{b64}\n-----END CERTIFICATE-----\n");
        let key = format!("-----BEGIN RSA PRIVATE KEY-----\n{b64}\n-----END RSA PRIVATE KEY-----\n");
        let e = identity_from_pem(&cert, &key).unwrap_err();
        assert_eq!(e.kind, FailureKind::ClientIdentityInvalid);
        assert!(e.message.contains("ECDSA"), "{}", e.message);
    }

    #[test]
    fn alert_codes_are_extracted() {
        let f = classify_dimpl(&dimpl::Error::SecurityError("Received fatal alert: level=2, description=48".into()), 1000);
        assert_eq!(f.kind, FailureKind::DtlsHandshakeFailed);
        assert_eq!(f.tls_alert.as_deref(), Some("unknown_ca"));
        let t = classify_dimpl(&dimpl::Error::Timeout("handshake"), 1000);
        assert_eq!(t.kind, FailureKind::DtlsHandshakeTimeout);
    }
}
