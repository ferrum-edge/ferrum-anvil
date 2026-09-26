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
//! * The handshake and session run over a [`DatagramChannel`]: a UDP socket
//!   connected to the destination (optionally with a PROXY v2 envelope on
//!   every datagram), or an RFC 9298 CONNECT-UDP tunnel through an HTTP/3
//!   MASQUE proxy, where every DTLS record is one HTTP Datagram. Through a
//!   tunnel, the proxy leg is the connection's `tunnel` evidence and the
//!   DTLS evidence stays the connection's `tls`; a tunnel that never opens
//!   leaves the attempt as the proxy's CONNECT, with no DTLS attempted.

use crate::certs::summarize;
use crate::datagram::{DatagramChannel, Inbound, Sent, SocketChannel};
use crate::dns::DnsConfig;
use crate::errors::classify_rustls;
use crate::http::{AttemptOutput, sleep_until_opt};
use crate::recorder::{EventCtx, Recorder};
use crate::session::*;
use crate::tls::PreparedTls;
use anvil_domain::events::{ExecutionEvent, SessionCommand};
use anvil_domain::execution::*;
use anvil_domain::outcome::{ClosedBy, ProtocolStatus};
use anvil_domain::settings::Timeouts;
use bytes::Bytes;
use dimpl::{Config, Dtls, DtlsCertificate, Output, ProtocolVersion};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, UnixTime};
use std::collections::HashSet;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
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
    /// DTLS records (handshake flights included). Direct sockets only.
    pub envelope: Option<crate::proxy_protocol::EnvelopePlan>,
    /// Run the session inside an RFC 9298 CONNECT-UDP tunnel through this
    /// MASQUE proxy instead of over a direct UDP socket (`host`/`port` are
    /// then the tunnel's target, and `dns` is not used).
    pub masque: Option<crate::masque::MasqueTunnelPlan>,
}

/// dimpl's default record size limit (its MTU).
const DEFAULT_MTU: usize = 1150;
/// The smallest MTU dimpl accepts.
const MIN_MTU: usize = 64;

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

/// Notes from the datagram path, each recorded once.
#[derive(Default)]
struct PathNotes(HashSet<String>);

impl PathNotes {
    fn once(&mut self, facts: &mut SessionFacts, note: String) {
        if self.0.insert(note.clone()) {
            facts.notes.push(note);
        }
    }
}

/// Hand every packet dimpl produced to the path. `Err` means the path
/// itself failed; a datagram the path did not take is noted (DTLS
/// retransmits handshake flights, and application data is not reliable).
async fn send_all<C: DatagramChannel>(
    chan: &mut C,
    outs: &[Out],
    notes: &mut PathNotes,
    facts: &mut SessionFacts,
) -> Result<(), TransportFailure> {
    for o in outs {
        if let Out::Packet(p) = o {
            match chan.send(p).await? {
                Sent::Sent(None) => {}
                Sent::Sent(Some(n)) | Sent::NotSent(n) => notes.once(facts, n),
            }
        }
    }
    Ok(())
}

pub async fn run(plan: &DtlsPlan, events: &EventCtx, cancel: &CancellationToken, commands: Option<CommandRx>) -> SessionOutput {
    let rec = Recorder::new(0, events.clone());
    events.emit(ExecutionEvent::AttemptStarted { execution_id: events.execution_id, attempt: 0 });
    let mut facts = SessionFacts::default();
    let (identity, ephemeral) = match &plan.identity {
        Some(i) => (i.clone(), false),
        None => match ephemeral_identity() {
            Ok(i) => (i, true),
            Err(e) => {
                let obs = new_attempt(0, AttemptReason::Initial, "DTLS", &plan.display_url);
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
    let id = Identity { identity: &identity, ephemeral };
    match &plan.masque {
        None => run_direct(plan, rec, facts, id, events, cancel, commands).await,
        Some(m) => run_tunneled(plan, m, rec, facts, id, events, cancel, commands).await,
    }
}

struct Identity<'a> {
    identity: &'a DtlsIdentity,
    /// dimpl's ephemeral self-signed certificate (no identity configured).
    ephemeral: bool,
}

/// DTLS over a UDP socket connected to the destination (optionally with a
/// PROXY v2 envelope on every datagram).
async fn run_direct(
    plan: &DtlsPlan,
    mut rec: Recorder,
    mut facts: SessionFacts,
    id: Identity<'_>,
    events: &EventCtx,
    cancel: &CancellationToken,
    commands: Option<CommandRx>,
) -> SessionOutput {
    let mut obs = new_attempt(0, AttemptReason::Initial, "DTLS", &plan.display_url);
    let early = |rec: Recorder, obs: AttemptObservation, f: TransportFailure, facts: SessionFacts| {
        SessionOutput::single(fail_attempt(rec, obs, f, DispatchState::NotDispatched, events), None, ProtocolStatus::None, facts)
    };
    let (sock, addr, cobs) = match crate::udp::open_socket(&mut rec, &plan.host, plan.port, &plan.dns, &plan.timeouts, "dtls").await {
        Ok(x) => x,
        Err((f, cobs)) => {
            obs.connection = Some(cobs);
            return early(rec, obs, f, facts);
        }
    };
    obs.connection = Some(cobs);
    let env = match crate::udp::start_envelope(plan.envelope.as_ref(), &sock, addr, plan.redact.clone()) {
        Ok(e) => e,
        Err(f) => return early(rec, obs, f, facts),
    };
    let mut session_notes = vec![];
    if let Some(e) = &env {
        facts.notes.push(e.summary());
        session_notes.push(("proxy_protocol_envelope", e.summary()));
    }
    let mut chan = SocketChannel::new(sock, env);
    let session = exchange(plan, &mut chan, &mut rec, &mut obs, &mut facts, &id, &session_notes, events, cancel, commands).await;
    if let (Some(e), Some(c)) = (chan.envelope(), obs.connection.as_mut()) {
        c.proxy_header = Some(e.observation());
    }
    let obs = finish_attempt(rec, obs, events);
    let (transcript, status) = match session {
        Some(s) => (
            Some(s.transcript),
            ProtocolStatus::Udp {
                datagrams_sent: s.sent,
                datagrams_received: s.received,
                window_ms: plan.response_window_ms,
                masque: None,
            },
        ),
        None => (None, ProtocolStatus::None),
    };
    SessionOutput::single(AttemptOutput { observation: obs, response: None, body: Bytes::new() }, transcript, status, facts)
}

/// DTLS inside an RFC 9298 CONNECT-UDP tunnel. A tunnel that never opens
/// leaves the attempt as the CONNECT to the proxy (no DTLS was attempted);
/// once it opens, the attempt addresses the target and the proxy leg is
/// recorded as the connection's CONNECT-UDP tunnel.
#[allow(clippy::too_many_arguments)]
async fn run_tunneled(
    plan: &DtlsPlan,
    m: &crate::masque::MasqueTunnelPlan,
    mut rec: Recorder,
    mut facts: SessionFacts,
    id: Identity<'_>,
    events: &EventCtx,
    cancel: &CancellationToken,
    commands: Option<CommandRx>,
) -> SessionOutput {
    let mut obs = new_attempt(0, AttemptReason::Initial, "CONNECT", &m.display_url);
    let total_deadline = if commands.is_some() { None } else { deadline_from(plan.timeouts.total_ms) };
    let mut chan = match crate::masque::open(m, &mut rec, &mut obs, &mut facts, events, cancel, total_deadline).await {
        Ok(c) => c,
        Err(n) => return n.into_output(rec, obs, facts, plan.response_window_ms, events),
    };
    chan.into_outer_leg(&mut rec, &mut obs, "DTLS", &plan.display_url);
    let encoding = chan.status().encoding.map(crate::masque::encoding_name).unwrap_or("HTTP Datagrams");
    let note = format!("DTLS with {} inside the CONNECT-UDP tunnel through {} (records as {encoding})", m.target, m.proxy_authority);
    let session = exchange(plan, &mut chan, &mut rec, &mut obs, &mut facts, &id, &[("tunnel", note)], events, cancel, commands).await;
    let failure_kind = obs.failure.as_ref().map(|f| f.kind);
    chan.set_closed_by(if failure_kind == Some(FailureKind::TotalTimeout) { ClosedBy::Timeout } else { ClosedBy::Client });
    let (tunnel, written, read) = chan.close(failure_kind == Some(FailureKind::Canceled)).await;
    crate::masque::note_dropped(&mut facts, &tunnel);
    obs.bytes.connection_bytes_written = Some(written);
    obs.bytes.connection_bytes_read = Some(read);
    let obs = finish_attempt(rec, obs, events);
    let (transcript, sent, received) = match session {
        Some(s) => (Some(s.transcript), s.sent, s.received),
        None => (None, 0, 0),
    };
    let status = ProtocolStatus::Udp {
        datagrams_sent: sent,
        datagrams_received: received,
        window_ms: plan.response_window_ms,
        masque: Some(tunnel),
    };
    SessionOutput::single(AttemptOutput { observation: obs, response: None, body: Bytes::new() }, transcript, status, facts)
}

/// An application-data session after a completed handshake.
struct Session {
    transcript: StreamTranscript,
    sent: u64,
    received: u64,
}

/// Inbound application data after the handshake.
#[derive(Default)]
struct Inbox {
    received: u64,
    peer_closed: bool,
    tally: crate::udp::PayloadTally,
}

impl Inbox {
    /// An application datagram Anvil sent (so an identical reply counts as an echo).
    fn sent(&mut self, d: &[u8]) {
        self.tally.sent(d);
    }

    fn record(&mut self, outs: &[Out], tr: &mut Transcript, facts: &mut SessionFacts) {
        for o in outs {
            match o {
                Out::App(d) => {
                    self.received += 1;
                    self.tally.received(d, facts);
                    tr.data(Direction::Received, "datagram", d);
                }
                Out::Close => {
                    self.peer_closed = true;
                    tr.control(Direction::Received, "close_notify", b"");
                }
                _ => {}
            }
        }
    }
}

/// The DTLS handshake and the application datagrams over any datagram path.
/// Fills the connection's TLS evidence, the phases, `obs.failure` and
/// `obs.dispatch`; returns the session when the handshake completed.
#[allow(clippy::too_many_arguments)]
async fn exchange<C: DatagramChannel>(
    plan: &DtlsPlan,
    chan: &mut C,
    rec: &mut Recorder,
    obs: &mut AttemptObservation,
    facts: &mut SessionFacts,
    id: &Identity<'_>,
    session_notes: &[(&str, String)],
    events: &EventCtx,
    cancel: &CancellationToken,
    mut commands: Option<CommandRx>,
) -> Option<Session> {
    let interactive = commands.is_some();
    let mut notes = PathNotes::default();
    let hs_ms = plan.timeouts.tls_handshake_ms.or(plan.timeouts.connect_ms).unwrap_or(10_000);
    let mut builder = Config::builder()
        .with_crypto_provider(dimpl::crypto::rust_crypto::default_provider())
        .handshake_timeout(Duration::from_millis(hs_ms + 2_000))
        .flight_retries(8);
    // Size records to the path when it carries less than dimpl's default MTU
    // (a QUIC DATAGRAM frame inside a CONNECT-UDP tunnel).
    if let Some(max) = chan.max_datagram().filter(|m| (MIN_MTU..DEFAULT_MTU).contains(m)) {
        builder = builder.mtu(max);
    }
    let config = match builder.build() {
        Ok(c) => Arc::new(c),
        Err(e) => {
            obs.failure =
                Some(TransportFailure::new(Phase::Prepare, FailureKind::TlsProfileInvalid, format!("DTLS configuration rejected: {e:?}")));
            obs.dispatch = DispatchState::NotDispatched;
            return None;
        }
    };
    let cert = DtlsCertificate { certificate: id.identity.cert_der.clone(), private_key: id.identity.key_der.to_vec() };
    let start = Instant::now();
    let mut dtls = Dtls::new_auto(config, cert, start);
    dtls.set_active(true);
    // dimpl initializes per-connection state on the first timeout tick.
    if let Err(e) = dtls.handle_timeout(start) {
        obs.failure = Some(TransportFailure::new(Phase::Prepare, FailureKind::Internal, format!("the DTLS client could not start: {e:?}")));
        obs.dispatch = DispatchState::NotDispatched;
        return None;
    }

    // ---- handshake ----
    let hs_idx = rec.start(Phase::DtlsHandshake);
    let hs_deadline = Instant::now() + Duration::from_millis(hs_ms);
    let mut next_timeout: Option<Instant> = None;
    let mut verification = TlsVerification::NotReached;
    let mut peer_chain: Vec<CertificateSummary> = vec![];
    let mut peer_spiffe_id: Option<String> = None;
    let mut cert_requested = false;
    enum HsEv {
        In(Inbound),
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
        if let Err(mut f) = send_all(chan, &outs, &mut notes, facts).await {
            f.phase = Phase::DtlsHandshake;
            break Err(f);
        }
        if outs.iter().any(|o| matches!(o, Out::Connected)) {
            break Ok(());
        }
        let ev = tokio::select! {
            i = chan.recv() => HsEv::In(i),
            _ = sleep_until_opt(next_timeout) => HsEv::Timer,
            _ = tokio::time::sleep_until(tokio::time::Instant::from_std(hs_deadline)) => HsEv::Deadline,
            _ = cancel.cancelled() => HsEv::Canceled,
        };
        match ev {
            HsEv::In(Inbound::Datagram(d)) => {
                cert_requested |= has_certificate_request(&d);
                if let Err(e) = dtls.handle_packet(&d) {
                    break Err(classify_dimpl(&e, hs_ms));
                }
            }
            HsEv::In(Inbound::PortUnreachable(e)) => {
                facts.icmp_port_unreachable = true;
                let mut f = TransportFailure::new(
                    Phase::DtlsHandshake,
                    FailureKind::DtlsHandshakeFailed,
                    "the OS reported ICMP port unreachable for the destination (often: nothing is listening on that UDP port)",
                );
                f.io_error_kind = Some(format!("{:?}", e.kind()));
                break Err(f);
            }
            HsEv::In(Inbound::Error(e)) => {
                let mut f = TransportFailure::new(
                    Phase::DtlsHandshake,
                    FailureKind::DtlsHandshakeFailed,
                    format!("receiving during the DTLS handshake failed: {e}"),
                );
                f.io_error_kind = Some(format!("{:?}", e.kind()));
                break Err(f);
            }
            HsEv::In(Inbound::Dropped(what)) => notes.once(facts, format!("the datagram path dropped {what}")),
            HsEv::In(Inbound::Ended { failure: Some(mut f), .. }) => {
                f.phase = Phase::DtlsHandshake;
                f.message = format!("{} (during the DTLS handshake)", f.message);
                break Err(f);
            }
            HsEv::In(Inbound::Ended { failure: None, note }) => {
                break Err(TransportFailure::new(
                    Phase::DtlsHandshake,
                    FailureKind::DtlsHandshakeFailed,
                    format!("the datagram path closed during the DTLS handshake: {note}"),
                ));
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
    let presented = if requested == Some(true) { Some(id.identity.summary.clone()) } else { None };
    if id.ephemeral && requested == Some(true) {
        facts.notes.push(
            "the DTLS server requested a client certificate but no client identity is configured; dimpl presented an ephemeral self-signed certificate (CN=anvil-ephemeral-dtls-client)"
                .into(),
        );
    }
    let server_name = plan.tls.server_name_override.clone().unwrap_or_else(|| plan.host.clone());
    if let Some(c) = obs.connection.as_mut() {
        c.tls = Some(TlsObservation {
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
            c.protocol = Some(v.to_ascii_lowercase());
        }
    }
    if let Err(f) = hs {
        rec.finish(hs_idx, phase_status_for(f.kind));
        // Handshake datagrams only: no application data was dispatched.
        obs.failure = Some(f);
        obs.dispatch = DispatchState::NotDispatched;
        return None;
    }
    rec.finish_with(hs_idx, PhaseStatus::Completed, version.clone().unwrap_or_else(|| "DTLS".into()));

    // ---- application datagrams ----
    let s_idx = rec.start(Phase::Session);
    let mut tr = Transcript::new(rec.t0, plan.transcript, events.clone(), plan.redact.clone());
    for (kind, text) in session_notes {
        tr.note(kind, text);
    }
    let mut sent = 0u64;
    let mut failure: Option<TransportFailure> = None;
    let mut inbox = Inbox::default();
    // The path ended: nothing more can be sent through it (no close_notify).
    let mut path_ended = false;
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
        if let Err(f) = send_all(chan, &outs, &mut notes, facts).await {
            failure = Some(f);
            path_ended = true;
            break;
        }
        sent += 1;
        inbox.sent(d);
        tr.data(Direction::Sent, "datagram", d);
        inbox.record(&outs, &mut tr, facts);
    }
    let total_deadline = if interactive { None } else { deadline_from(plan.timeouts.total_ms) };
    let window = Duration::from_millis(plan.response_window_ms);
    let mut window_end = Instant::now() + window;
    enum Ev {
        In(Inbound),
        Timer,
        Cmd(Option<SessionCommand>),
        WindowEnd,
        Deadline,
        Canceled,
    }
    while failure.is_none() && !inbox.peer_closed && !path_ended && inbox.received < plan.max_datagrams as u64 {
        let window_deadline = if interactive { None } else { Some(window_end) };
        let ev = tokio::select! {
            i = chan.recv() => Ev::In(i),
            _ = sleep_until_opt(next_timeout) => Ev::Timer,
            c = next_cmd(&mut commands), if interactive => Ev::Cmd(c),
            _ = sleep_until_opt(window_deadline) => Ev::WindowEnd,
            _ = sleep_until_opt(total_deadline) => Ev::Deadline,
            _ = cancel.cancelled() => Ev::Canceled,
        };
        match ev {
            Ev::In(Inbound::Datagram(d)) => {
                if let Err(e) = dtls.handle_packet(&d) {
                    let mut f = classify_dimpl(&e, hs_ms);
                    f.phase = Phase::Session;
                    failure = Some(f);
                    break;
                }
                let outs = drain(&mut dtls, &mut next_timeout);
                if let Err(f) = send_all(chan, &outs, &mut notes, facts).await {
                    failure = Some(f);
                    path_ended = true;
                }
                inbox.record(&outs, &mut tr, facts);
            }
            Ev::In(Inbound::PortUnreachable(_)) => {
                if !facts.icmp_port_unreachable {
                    facts.icmp_port_unreachable = true;
                    tr.note("icmp_port_unreachable", "the OS reported ICMP port unreachable for the destination");
                }
            }
            Ev::In(Inbound::Error(e)) => tr.note("error", &format!("receive error: {e}")),
            Ev::In(Inbound::Dropped(what)) => notes.once(facts, format!("the datagram path dropped {what}")),
            Ev::In(Inbound::Ended { failure: f, note }) => {
                path_ended = true;
                match f {
                    Some(f) => failure = Some(f),
                    None => tr.note("tunnel_closed", &note),
                }
            }
            Ev::Timer => {
                next_timeout = None;
                if dtls.handle_timeout(Instant::now()).is_ok() {
                    let outs = drain(&mut dtls, &mut next_timeout);
                    if let Err(f) = send_all(chan, &outs, &mut notes, facts).await {
                        failure = Some(f);
                        path_ended = true;
                    }
                    inbox.record(&outs, &mut tr, facts);
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
                        if let Err(f) = send_all(chan, &outs, &mut notes, facts).await {
                            failure = Some(f);
                            path_ended = true;
                        } else {
                            sent += 1;
                            inbox.sent(&p);
                            tr.data(Direction::Sent, "datagram", &p);
                        }
                        inbox.record(&outs, &mut tr, facts);
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
    if !inbox.peer_closed && !path_ended && dtls.close().is_ok() {
        let outs = drain(&mut dtls, &mut next_timeout);
        if send_all(chan, &outs, &mut notes, facts).await.is_ok() {
            tr.control(Direction::Sent, "close_notify", b"");
        }
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
    } else if inbox.received > 0 {
        DispatchState::Sent
    } else {
        DispatchState::MayHaveBeenSent
    };
    obs.failure = failure;
    obs.bytes.request_body = tr.sent_bytes();
    obs.bytes.response_body_wire = Some(tr.received_bytes());
    Some(Session { transcript: tr.finish(), sent, received: inbox.received })
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
