//! Client TLS with observable verification and client-certificate evidence.
//!
//! * Verification uses webpki against system roots (loaded from the OS store
//!   once) and/or profile-scoped extra roots. Extra roots are never installed
//!   into the OS store and never shared across profiles.
//! * An observing verifier records the presented chain and the verification
//!   result even when the handshake fails, so evidence can show *what* failed.
//! * An observing client-certificate resolver records whether the peer sent a
//!   CertificateRequest and which identity (if any) was presented.
//! * `verify = false` keeps encryption, still checks handshake signatures, and
//!   records what strict verification would have concluded.
//! * SPIFFE server identity (opt-in per profile): the chain is verified to
//!   the profile's trust anchors (the trust bundle) and the leaf's single
//!   `spiffe://` URI SAN is matched exactly or by trust domain, per the
//!   X.509-SVID specification. Host-name verification does not apply then.
//!   The peer's SPIFFE ID is recorded for every server that presents one.
//! * The SNI actually sent, whether it came from the profile's override, and
//!   the identity check applied are part of the evidence.

use crate::certs::summarize;
use crate::errors::classify_rustls;
use crate::spiffe;
use anvil_domain::execution::{
    CertificateSummary, FailureKind, PeerIdentityCheck, Phase, TlsObservation, TlsVerification, TransportFailure,
};
use anvil_domain::tls::{ServerSpiffeIdentity, TlsMinVersion};
use parking_lot::Mutex;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{ClientSessionMemoryCache, Resumption, WebPkiServerVerifier};
use rustls::crypto::CryptoProvider;
use rustls::sign::CertifiedKey;
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use sha2::{Digest, Sha256};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use zeroize::Zeroizing;

/// Client identity material resolved by the engine (secrets already unwrapped).
#[derive(Clone)]
pub struct ClientIdentityMaterial {
    pub cert_chain_pem: String,
    pub private_key_pem: Zeroizing<String>,
}

impl std::fmt::Debug for ClientIdentityMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientIdentityMaterial").field("private_key_pem", &"‹redacted›").finish()
    }
}

#[derive(Clone, Debug, Default)]
pub struct TlsSettings {
    pub verify: bool,
    pub use_system_roots: bool,
    pub extra_roots_pem: Vec<String>,
    pub client_identity: Option<ClientIdentityMaterial>,
    pub min_version: TlsMinVersion,
    pub server_name_override: Option<String>,
    /// SPIFFE server identity; replaces host-name verification when set.
    pub server_spiffe: Option<ServerSpiffeIdentity>,
}

impl TlsSettings {
    pub fn strict_system() -> Self {
        TlsSettings { verify: true, use_system_roots: true, ..Default::default() }
    }
}

pub fn provider() -> Arc<CryptoProvider> {
    static P: OnceLock<Arc<CryptoProvider>> = OnceLock::new();
    P.get_or_init(|| Arc::new(rustls::crypto::ring::default_provider())).clone()
}

struct SystemRoots {
    certs: Vec<CertificateDer<'static>>,
    load_errors: Vec<String>,
}

fn system_roots() -> &'static SystemRoots {
    static R: OnceLock<SystemRoots> = OnceLock::new();
    R.get_or_init(|| {
        let res = rustls_native_certs::load_native_certs();
        SystemRoots { certs: res.certs, load_errors: res.errors.iter().map(|e| e.to_string()).collect() }
    })
}

/// Number of system roots loaded and any OS store errors (for diagnostics).
pub fn system_root_status() -> (usize, Vec<String>) {
    let r = system_roots();
    (r.certs.len(), r.load_errors.clone())
}

/// A validated SPIFFE server-identity expectation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpiffeExpectation {
    /// Exact SPIFFE ID, when configured.
    pub expected_id: Option<String>,
    pub trust_domain: String,
}

impl SpiffeExpectation {
    pub fn check(&self) -> PeerIdentityCheck {
        match &self.expected_id {
            Some(id) => PeerIdentityCheck::SpiffeId { expected: id.clone(), trust_domain: self.trust_domain.clone() },
            None => PeerIdentityCheck::SpiffeTrustDomain { trust_domain: self.trust_domain.clone() },
        }
    }
}

/// Validated, reusable TLS material for one profile.
pub struct PreparedTls {
    /// Stable fingerprint of everything that affects the TLS session
    /// (part of the connection-pool isolation key).
    pub fingerprint: String,
    pub(crate) verifier: Option<Arc<WebPkiServerVerifier>>,
    roots: Option<Arc<RootCertStore>>,
    client_key: Option<Arc<CertifiedKey>>,
    pub client_summary: Option<CertificateSummary>,
    pub verify: bool,
    min_version: TlsMinVersion,
    pub server_name_override: Option<String>,
    /// SPIFFE server identity check (replaces host-name verification).
    pub spiffe: Option<SpiffeExpectation>,
    sessions: Arc<ClientSessionMemoryCache>,
    /// Which TLS profile (and revision) this material was prepared from, set
    /// by the caller; part of the session-ticket isolation key, so tickets are
    /// never shared between two profiles even with identical settings.
    pub profile_key: String,
}

fn local(kind: FailureKind, msg: impl Into<String>, field: &str) -> TransportFailure {
    TransportFailure::new(Phase::Prepare, kind, msg).with_field(field)
}

fn parse_certs(pem: &str, field: &str) -> Result<Vec<CertificateDer<'static>>, TransportFailure> {
    use rustls_pki_types::pem::PemObject;
    let certs: Result<Vec<_>, _> = CertificateDer::pem_slice_iter(pem.as_bytes()).collect();
    let certs = certs.map_err(|e| local(FailureKind::TlsProfileInvalid, format!("certificate PEM could not be parsed: {e}"), field))?;
    if certs.is_empty() {
        return Err(local(FailureKind::TlsProfileInvalid, "no CERTIFICATE blocks found in PEM", field));
    }
    Ok(certs)
}

fn parse_key(pem: &str) -> Result<PrivateKeyDer<'static>, TransportFailure> {
    use rustls_pki_types::pem::{self, PemObject};
    match PrivateKeyDer::from_pem_slice(pem.as_bytes()) {
        Ok(k) => Ok(k),
        Err(pem::Error::NoItemsFound) => Err(local(
            FailureKind::ClientIdentityInvalid,
            "no private key found (expected PKCS#8, PKCS#1 or SEC1 PEM; encrypted keys must be decrypted on import)",
            "tls.client_identity.private_key",
        )),
        Err(e) => Err(local(
            FailureKind::ClientIdentityInvalid,
            format!("private key PEM could not be parsed: {e}"),
            "tls.client_identity.private_key",
        )),
    }
}

/// Validate the SPIFFE settings of a profile (nothing is sent on failure).
fn spiffe_expectation(s: &ServerSpiffeIdentity) -> Result<Option<SpiffeExpectation>, TransportFailure> {
    let id = s.expected_server_spiffe_id.as_deref().map(str::trim).filter(|v| !v.is_empty());
    let td = s.trust_domain.as_deref().map(str::trim).filter(|v| !v.is_empty());
    let parsed_id = match id {
        Some(v) => {
            Some(spiffe::parse_id(v).map_err(|e| local(FailureKind::TlsProfileInvalid, e, "tls.server_spiffe.expected_server_spiffe_id"))?)
        }
        None => None,
    };
    let parsed_td = match td {
        Some(v) => {
            Some(spiffe::parse_trust_domain(v).map_err(|e| local(FailureKind::TlsProfileInvalid, e, "tls.server_spiffe.trust_domain"))?)
        }
        None => None,
    };
    match (parsed_id, parsed_td) {
        (None, None) => Ok(None),
        (Some(id), None) => Ok(Some(SpiffeExpectation { expected_id: Some(id.as_uri()), trust_domain: id.trust_domain })),
        (None, Some(td)) => Ok(Some(SpiffeExpectation { expected_id: None, trust_domain: td })),
        (Some(id), Some(td)) => {
            if id.trust_domain != td {
                return Err(local(
                    FailureKind::TlsProfileInvalid,
                    format!("the expected server SPIFFE ID {} is not in the configured trust domain '{td}'", id.as_uri()),
                    "tls.server_spiffe",
                ));
            }
            Ok(Some(SpiffeExpectation { expected_id: Some(id.as_uri()), trust_domain: td }))
        }
    }
}

/// Validate a TLS profile: parse roots, load and key-match the client identity.
/// All failures are local (no network activity happened).
pub fn prepare(settings: &TlsSettings) -> Result<PreparedTls, TransportFailure> {
    let mut hasher = Sha256::new();
    hasher.update([settings.verify as u8, settings.use_system_roots as u8, settings.min_version as u8]);
    hasher.update(settings.server_name_override.as_deref().unwrap_or("").as_bytes());
    let spiffe = match &settings.server_spiffe {
        Some(s) => spiffe_expectation(s)?,
        None => None,
    };
    if let Some(sp) = &spiffe {
        hasher.update(b"spiffe");
        hasher.update(sp.trust_domain.as_bytes());
        hasher.update(sp.expected_id.as_deref().unwrap_or("").as_bytes());
    }
    if let Some(o) = &settings.server_name_override
        && ServerName::try_from(o.clone()).is_err()
    {
        return Err(local(
            FailureKind::TlsProfileInvalid,
            format!("the SNI / verification name override '{o}' is not a valid DNS name or IP address"),
            "tls.server_name_override",
        ));
    }

    let mut roots = RootCertStore::empty();
    if settings.use_system_roots {
        let (added, _ignored) = roots.add_parsable_certificates(system_roots().certs.iter().cloned());
        hasher.update(b"system");
        let _ = added;
    }
    for (i, pem) in settings.extra_roots_pem.iter().enumerate() {
        let certs = parse_certs(pem, &format!("tls.extra_roots[{i}]"))?;
        for c in certs {
            hasher.update(c.as_ref());
            roots.add(c).map_err(|e| {
                local(FailureKind::TlsProfileInvalid, format!("CA certificate rejected: {e}"), &format!("tls.extra_roots[{i}]"))
            })?;
        }
    }
    let (verifier, roots) = if roots.is_empty() {
        if settings.verify {
            return Err(local(
                FailureKind::TlsProfileInvalid,
                if spiffe.is_some() {
                    "SPIFFE verification is enabled but the profile has no trust bundle (add the trust domain's CA certificates)"
                } else {
                    "certificate verification is enabled but the profile has no trust anchors (system roots disabled and no CA configured)"
                },
                "tls.extra_roots",
            ));
        }
        (None, None)
    } else {
        let roots = Arc::new(roots);
        let v = WebPkiServerVerifier::builder_with_provider(roots.clone(), provider())
            .build()
            .map_err(|e| local(FailureKind::TlsProfileInvalid, format!("trust store could not be built: {e}"), "tls.extra_roots"))?;
        (Some(v), Some(roots))
    };

    let (client_key, client_summary) = match &settings.client_identity {
        None => (None, None),
        Some(id) => {
            let chain = parse_certs(&id.cert_chain_pem, "tls.client_identity.cert_chain")?;
            let key = parse_key(&id.private_key_pem)?;
            let signing_key = provider().key_provider.load_private_key(key).map_err(|e| {
                local(
                    FailureKind::ClientIdentityInvalid,
                    format!("private key type is not supported: {e}"),
                    "tls.client_identity.private_key",
                )
            })?;
            let ck = CertifiedKey::new(chain.clone(), signing_key);
            // Public-key consistency check between the leaf and the private key.
            match ck.keys_match() {
                Ok(()) => {}
                Err(rustls::Error::InconsistentKeys(rustls::InconsistentKeys::KeyMismatch)) => {
                    return Err(local(
                        FailureKind::ClientIdentityKeyMismatch,
                        "the private key does not match the client certificate's public key",
                        "tls.client_identity",
                    ));
                }
                // Unknown = the provider could not derive the public key; not a proven mismatch.
                Err(_) => {}
            }
            for c in &chain {
                hasher.update(c.as_ref());
            }
            let summary = summarize(&chain[0]);
            (Some(Arc::new(ck)), Some(summary))
        }
    };

    let fingerprint = hex::encode(&hasher.finalize()[..16]);
    Ok(PreparedTls {
        fingerprint,
        verifier,
        roots,
        client_key,
        client_summary,
        verify: settings.verify,
        min_version: settings.min_version,
        server_name_override: settings.server_name_override.clone(),
        spiffe,
        sessions: Arc::new(ClientSessionMemoryCache::new(64)),
        profile_key: String::new(),
    })
}

/// The outcome of checking a peer certificate against a prepared profile,
/// independent of whether verification is enforced.
pub(crate) struct PeerVerdict {
    /// `Err` aborts the handshake (when verification is enforced).
    pub result: Result<(), rustls::Error>,
    /// Typed problem and plain-language detail when `result` is `Err`.
    pub problem: Option<(FailureKind, String)>,
    /// The leaf's SPIFFE ID, when it carries exactly one valid one.
    pub peer_spiffe_id: Option<String>,
}

fn rustls_problem(e: &rustls::Error) -> (FailureKind, String) {
    let (kind, _) = classify_rustls(e, false);
    (kind, crate::errors::describe_rustls(e).unwrap_or_else(|| e.to_string()))
}

/// What a peer certificate is checked against (borrowed from a profile).
pub(crate) struct PeerCheck<'a> {
    verifier: Option<&'a Arc<WebPkiServerVerifier>>,
    roots: Option<&'a Arc<RootCertStore>>,
    spiffe: Option<&'a SpiffeExpectation>,
}

impl PreparedTls {
    pub(crate) fn peer_check(&self) -> PeerCheck<'_> {
        PeerCheck { verifier: self.verifier.as_ref(), roots: self.roots.as_ref(), spiffe: self.spiffe.as_ref() }
    }
}

/// Verify a peer leaf (and intermediates) against the profile: host-name
/// verification, or SPIFFE X.509-SVID verification when configured.
pub(crate) fn verify_peer(
    check: &PeerCheck<'_>,
    server_name: &ServerName<'_>,
    end_entity: &CertificateDer<'_>,
    intermediates: &[CertificateDer<'_>],
    now: UnixTime,
) -> PeerVerdict {
    let peer_spiffe_id = spiffe::peer_spiffe_id(end_entity.as_ref());
    let Some(exp) = check.spiffe else {
        let result = match check.verifier {
            Some(v) => v.verify_server_cert(end_entity, intermediates, server_name, &[], now).map(|_| ()),
            None => Err(rustls::Error::General("no trust anchors".into())),
        };
        let problem = result.as_ref().err().map(rustls_problem);
        return PeerVerdict { result, problem, peer_spiffe_id };
    };
    let fail = |kind: FailureKind, detail: String| PeerVerdict {
        result: Err(rustls::Error::InvalidCertificate(rustls::CertificateError::ApplicationVerificationFailure)),
        problem: Some((kind, detail)),
        peer_spiffe_id: peer_spiffe_id.clone(),
    };
    let Some(roots) = check.roots else {
        let e = rustls::Error::General("no trust anchors".into());
        return PeerVerdict { problem: Some(rustls_problem(&e)), result: Err(e), peer_spiffe_id };
    };
    // 1. Chain to the trust bundle (serverAuth EKU when present), no name check.
    let chain = rustls::server::ParsedCertificate::try_from(end_entity).and_then(|parsed| {
        rustls::client::verify_server_cert_signed_by_trust_anchor(
            &parsed,
            roots,
            intermediates,
            now,
            provider().signature_verification_algorithms.all,
        )
    });
    if let Err(e) = chain {
        let (kind, detail) = rustls_problem(&e);
        // An unanchored SVID that names another trust domain: the bundle for
        // that domain is simply not configured.
        if kind == FailureKind::TlsUntrustedIssuer
            && let Some(id) = peer_spiffe_id.as_deref().and_then(|s| spiffe::parse_id(s).ok())
            && id.trust_domain != exp.trust_domain
        {
            return PeerVerdict {
                result: Err(e),
                problem: Some((
                    FailureKind::TlsUntrustedTrustDomain,
                    format!(
                        "the server presented an SVID for trust domain '{}' ({}), which no configured trust bundle anchors; this profile trusts trust domain '{}'",
                        id.trust_domain,
                        id.as_uri(),
                        exp.trust_domain
                    ),
                )),
                peer_spiffe_id,
            };
        }
        return PeerVerdict { result: Err(e), problem: Some((kind, detail)), peer_spiffe_id };
    }
    // 2. X.509-SVID shape: exactly one URI SAN that is a SPIFFE ID.
    let id = match spiffe::svid_id(end_entity.as_ref()) {
        Ok(id) => id,
        Err(p) => return fail(FailureKind::TlsInvalidSvid, p.describe()),
    };
    // 3. Identity: trust domain, then (when configured) the exact ID.
    if id.trust_domain != exp.trust_domain {
        return fail(
            FailureKind::TlsUntrustedTrustDomain,
            format!(
                "the server's SPIFFE ID {} is in trust domain '{}', not the trusted '{}'",
                id.as_uri(),
                id.trust_domain,
                exp.trust_domain
            ),
        );
    }
    if let Some(expected) = &exp.expected_id
        && &id.as_uri() != expected
    {
        return fail(FailureKind::TlsSpiffeIdMismatch, format!("the server's SPIFFE ID is {}, not the expected {expected}", id.as_uri()));
    }
    PeerVerdict { result: Ok(()), problem: None, peer_spiffe_id }
}

#[derive(Default)]
struct Slot {
    peer_chain: Vec<CertificateSummary>,
    verification: Option<TlsVerification>,
    peer_spiffe_id: Option<String>,
    client_cert_requested: bool,
    client_cert_presented: bool,
}

#[derive(Debug)]
pub(crate) struct ObservingVerifier {
    prepared: Arc<PreparedView>,
    slot: Arc<SlotCell>,
}

/// The parts of [`PreparedTls`] the verifier needs (cheap to clone into a
/// rustls config, which requires `'static` + `Debug`).
struct PreparedView {
    verifier: Option<Arc<WebPkiServerVerifier>>,
    roots: Option<Arc<RootCertStore>>,
    verify: bool,
    spiffe: Option<SpiffeExpectation>,
}

impl std::fmt::Debug for PreparedView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedView").field("verify", &self.verify).field("spiffe", &self.spiffe).finish()
    }
}

impl PreparedView {
    fn of(p: &PreparedTls) -> Arc<Self> {
        Arc::new(PreparedView { verifier: p.verifier.clone(), roots: p.roots.clone(), verify: p.verify, spiffe: p.spiffe.clone() })
    }

    fn peer_check(&self) -> PeerCheck<'_> {
        PeerCheck { verifier: self.verifier.as_ref(), roots: self.roots.as_ref(), spiffe: self.spiffe.as_ref() }
    }
}

#[derive(Default)]
pub(crate) struct SlotHandle(Slot);
impl std::fmt::Debug for SlotHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TlsObservationSlot")
    }
}

/// Where the observing verifier and client-certificate resolver record a
/// handshake's evidence. A per-connection config owns its slot. A session
/// resumption context ([`crate::tickets`]) keeps one verifier and resolver for
/// all its connections, because rustls resumes a ticket only with the same
/// verifier and resolver instances; it points the cell at the slot of the
/// connection that holds its handshake gate.
pub(crate) struct SlotCell(Mutex<Arc<Mutex<SlotHandle>>>);

impl SlotCell {
    pub(crate) fn new(slot: Arc<Mutex<SlotHandle>>) -> Arc<Self> {
        Arc::new(SlotCell(Mutex::new(slot)))
    }

    fn current(&self) -> Arc<Mutex<SlotHandle>> {
        self.0.lock().clone()
    }

    pub(crate) fn route_to(&self, slot: Arc<Mutex<SlotHandle>>) {
        *self.0.lock() = slot;
    }
}

impl std::fmt::Debug for SlotCell {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TlsObservationSlotCell")
    }
}

/// Record a verdict as evidence and decide whether the handshake continues.
pub(crate) fn verification_of(verify: bool, v: &PeerVerdict) -> TlsVerification {
    if verify {
        match &v.problem {
            None => TlsVerification::Verified,
            Some((kind, detail)) => TlsVerification::Failed { problem: *kind, detail: detail.clone() },
        }
    } else {
        TlsVerification::Bypassed { would_have_failed: v.problem.as_ref().map(|(k, _)| *k) }
    }
}

impl ServerCertVerifier for ObservingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let mut chain = vec![summarize(end_entity)];
        chain.extend(intermediates.iter().map(summarize));
        let mut verdict = verify_peer(&self.prepared.peer_check(), server_name, end_entity, intermediates, now);
        // Without any trust anchors there is nothing strict verification could
        // have concluded (bypass only).
        if self.prepared.verifier.is_none() && !self.prepared.verify {
            verdict.problem = None;
        }
        let slot = self.slot.current();
        let mut slot = slot.lock();
        slot.0.peer_chain = chain;
        slot.0.peer_spiffe_id = verdict.peer_spiffe_id.clone();
        slot.0.verification = Some(verification_of(self.prepared.verify, &verdict));
        if self.prepared.verify { verdict.result.map(|_| ServerCertVerified::assertion()) } else { Ok(ServerCertVerified::assertion()) }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &provider().signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &provider().signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        provider().signature_verification_algorithms.supported_schemes()
    }
}

#[derive(Debug)]
pub(crate) struct ObservingClientCert {
    key: Option<Arc<CertifiedKey>>,
    slot: Arc<SlotCell>,
}

impl rustls::client::ResolvesClientCert for ObservingClientCert {
    fn resolve(&self, _root_hint_subjects: &[&[u8]], _sigschemes: &[SignatureScheme]) -> Option<Arc<CertifiedKey>> {
        let slot = self.slot.current();
        let mut slot = slot.lock();
        slot.0.client_cert_requested = true;
        slot.0.client_cert_presented = self.key.is_some();
        self.key.clone()
    }

    fn has_certs(&self) -> bool {
        self.key.is_some()
    }
}

pub fn server_name_for(host: &str, prepared: &PreparedTls) -> Result<ServerName<'static>, TransportFailure> {
    let name = prepared.server_name_override.clone().unwrap_or_else(|| host.trim_start_matches('[').trim_end_matches(']').to_string());
    ServerName::try_from(name.clone())
        .map_err(|_| local(FailureKind::InvalidUrl, format!("'{name}' is not a valid TLS server name"), "url"))
}

/// The identity check a profile applies for `server_name`.
pub fn identity_check_for(prepared: &PreparedTls, server_name: &str) -> PeerIdentityCheck {
    match &prepared.spiffe {
        Some(s) => s.check(),
        None => PeerIdentityCheck::HostName { name: server_name.to_string() },
    }
}

/// Perform a TLS handshake over `io`, returning the stream and evidence. On
/// failure the evidence gathered so far is returned with the typed failure.
pub async fn connect<S>(
    prepared: &PreparedTls,
    io: S,
    host: &str,
    alpn: &[&str],
    deadline: Option<Duration>,
) -> Result<(TlsStream<S>, TlsObservation), (TransportFailure, TlsObservation)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let server_name = match server_name_for(host, prepared) {
        Ok(n) => n,
        Err(f) => return Err((f, empty_observation(host, alpn))),
    };
    let slot = Arc::new(Mutex::new(SlotHandle::default()));
    let config = match client_config(prepared, alpn, slot.clone()) {
        Ok(c) => c,
        Err(f) => return Err((f, empty_observation(host, alpn))),
    };
    let connector = TlsConnector::from(Arc::new(config));
    let sni = server_name_string(&server_name);
    let sent_sni = matches!(server_name, ServerName::DnsName(_));
    let fut = connector.connect(server_name, io);
    let res = match deadline {
        Some(d) => match tokio::time::timeout(d, fut).await {
            Ok(r) => r,
            Err(_) => {
                let obs = observation_from_slot(&slot, &sni, sent_sni, alpn, prepared, false);
                let f = TransportFailure::new(
                    Phase::TlsHandshake,
                    FailureKind::TlsHandshakeTimeout,
                    format!("TLS handshake did not complete within {} ms", d.as_millis()),
                )
                .with_deadline(Some(d.as_millis() as u64));
                return Err((f, obs));
            }
        },
        None => fut.await,
    };
    match res {
        Ok(stream) => {
            let mut obs = observation_from_slot(&slot, &sni, sent_sni, alpn, prepared, true);
            let (_, conn) = stream.get_ref();
            obs.version = conn.protocol_version().map(|v| format!("{v:?}"));
            obs.cipher_suite = conn.negotiated_cipher_suite().map(|c| format!("{:?}", c.suite()));
            obs.alpn_negotiated = conn.alpn_protocol().map(|p| String::from_utf8_lossy(p).into_owned());
            let resumed = matches!(conn.handshake_kind(), Some(rustls::HandshakeKind::Resumed));
            obs.resumed = Some(resumed);
            if resumed {
                // No certificate exchange happens on resumption.
                obs.client_certificate_requested = None;
                if obs.verification == TlsVerification::NotReached {
                    obs.verification =
                        if prepared.verify { TlsVerification::Verified } else { TlsVerification::Bypassed { would_have_failed: None } };
                }
            }
            Ok((stream, obs))
        }
        Err(e) => {
            let obs = observation_from_slot(&slot, &sni, sent_sni, alpn, prepared, false);
            let mut f = crate::errors::classify_tls_handshake(&e);
            // Prefer the verifier's own typed conclusion when it failed.
            if let TlsVerification::Failed { problem, detail } = &obs.verification {
                f.kind = *problem;
                f.message = detail.clone();
            }
            Err((f, obs))
        }
    }
}

/// A TLS connect over TCP through a session resumption context (the caller
/// holds its handshake gate and routed `handle`). With `early_data` the
/// stream comes back *during* the handshake when the ticket allowed early
/// data (`true` = still handshaking: writes become early data and the
/// handshake completes on the first flush); otherwise after the handshake.
pub(crate) async fn connect_resumable<S>(
    config: ClientConfig,
    io: S,
    server_name: ServerName<'static>,
    early_data: bool,
    deadline: Option<Duration>,
) -> Result<(TlsStream<S>, bool), TransportFailure>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let connector = TlsConnector::from(Arc::new(config)).early_data(early_data);
    let fut = connector.connect(server_name, io);
    let res = match deadline {
        Some(d) => match tokio::time::timeout(d, fut).await {
            Ok(r) => r,
            Err(_) => {
                return Err(TransportFailure::new(
                    Phase::TlsHandshake,
                    FailureKind::TlsHandshakeTimeout,
                    format!("TLS handshake did not complete within {} ms", d.as_millis()),
                )
                .with_deadline(Some(d.as_millis() as u64)));
            }
        },
        None => fut.await,
    };
    match res {
        Ok(stream) => {
            let handshaking = stream.get_ref().1.is_handshaking();
            Ok((stream, handshaking))
        }
        Err(e) => Err(crate::errors::classify_tls_handshake(&e)),
    }
}

/// TLS evidence for a completed handshake of a resumption context's
/// connection: the resumed-session view when rustls resumed, otherwise the
/// full-handshake observation.
pub(crate) fn completed_observation(
    h: &ObservationHandle,
    prepared: &PreparedTls,
    conn: &rustls::ClientConnection,
) -> (TlsObservation, bool) {
    let version = conn.protocol_version().map(|v| format!("{v:?}"));
    let cipher = conn.negotiated_cipher_suite().map(|c| format!("{:?}", c.suite()));
    let alpn = conn.alpn_protocol().map(|p| String::from_utf8_lossy(p).into_owned());
    let resumed = matches!(conn.handshake_kind(), Some(rustls::HandshakeKind::Resumed));
    if resumed {
        let chain: Vec<CertificateDer<'static>> =
            conn.peer_certificates().map(|c| c.iter().map(|x| x.clone().into_owned()).collect()).unwrap_or_default();
        (resumed_observation(h, prepared, &chain, version, cipher, alpn), true)
    } else {
        let mut obs = observe(h, prepared, true);
        obs.version = version;
        obs.cipher_suite = cipher;
        obs.alpn_negotiated = alpn;
        obs.resumed = Some(false);
        (obs, false)
    }
}

fn server_name_string(n: &ServerName<'_>) -> String {
    match n {
        ServerName::DnsName(d) => d.as_ref().to_string(),
        ServerName::IpAddress(ip) => format!("{:?}", std::net::IpAddr::from(*ip)),
        _ => String::from("<unknown>"),
    }
}

fn client_config(prepared: &PreparedTls, alpn: &[&str], slot: Arc<Mutex<SlotHandle>>) -> Result<ClientConfig, TransportFailure> {
    let versions: &[&'static rustls::SupportedProtocolVersion] = match prepared.min_version {
        TlsMinVersion::Tls12 => &[&rustls::version::TLS13, &rustls::version::TLS12],
        TlsMinVersion::Tls13 => &[&rustls::version::TLS13],
    };
    let cell = SlotCell::new(slot);
    let verifier = Arc::new(ObservingVerifier { prepared: PreparedView::of(prepared), slot: cell.clone() });
    let mut cfg = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(versions)
        .map_err(|e| local(FailureKind::TlsProfileInvalid, format!("TLS versions unsupported: {e}"), "tls.min_version"))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_cert_resolver(Arc::new(ObservingClientCert { key: prepared.client_key.clone(), slot: cell }));
    cfg.alpn_protocols = alpn.iter().map(|p| p.as_bytes().to_vec()).collect();
    cfg.resumption = Resumption::store(prepared.sessions.clone());
    Ok(cfg)
}

/// The stable verifier and client-certificate resolver of a session
/// resumption context: every connection of the context shares them (rustls
/// only resumes a ticket with the instances that obtained it), and `cell`
/// routes their evidence to the connection holding the context's gate.
pub(crate) fn stable_identity(prepared: &PreparedTls, cell: Arc<SlotCell>) -> (Arc<ObservingVerifier>, Arc<ObservingClientCert>) {
    (
        Arc::new(ObservingVerifier { prepared: PreparedView::of(prepared), slot: cell.clone() }),
        Arc::new(ObservingClientCert { key: prepared.client_key.clone(), slot: cell }),
    )
}

/// A client config for a session resumption context: the context's stable
/// verifier and resolver, its ticket store, and TLS 1.3 early data when
/// `early_data` (the ClientHello then offers it whenever the ticket allows).
pub(crate) fn resumable_config(
    prepared: &PreparedTls,
    verifier: Arc<ObservingVerifier>,
    resolver: Arc<ObservingClientCert>,
    store: Arc<dyn rustls::client::ClientSessionStore>,
    alpn: &[&str],
    tls13_only: bool,
    early_data: bool,
) -> Result<ClientConfig, TransportFailure> {
    let versions: &[&'static rustls::SupportedProtocolVersion] = if tls13_only || prepared.min_version == TlsMinVersion::Tls13 {
        &[&rustls::version::TLS13]
    } else {
        &[&rustls::version::TLS13, &rustls::version::TLS12]
    };
    let mut cfg = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(versions)
        .map_err(|e| local(FailureKind::TlsProfileInvalid, format!("TLS versions unsupported: {e}"), "tls.min_version"))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_cert_resolver(resolver);
    cfg.alpn_protocols = alpn.iter().map(|p| p.as_bytes().to_vec()).collect();
    cfg.resumption = Resumption::store(store);
    cfg.enable_early_data = early_data;
    Ok(cfg)
}

/// An observation handle whose slot the caller routes a resumption context's
/// verifier to (see [`SlotCell::route_to`]).
pub(crate) fn routed_handle(
    prepared: &PreparedTls,
    host: &str,
    alpn: &[&str],
) -> Result<(ServerName<'static>, ObservationHandle), TransportFailure> {
    let server_name = server_name_for(host, prepared)?;
    let sni = server_name_string(&server_name);
    let sent_sni = matches!(server_name, ServerName::DnsName(_));
    let slot = Arc::new(Mutex::new(SlotHandle::default()));
    Ok((server_name, ObservationHandle { slot, sni, sent_sni, alpn: alpn.iter().map(|s| s.to_string()).collect() }))
}

impl ObservationHandle {
    pub(crate) fn slot(&self) -> Arc<Mutex<SlotHandle>> {
        self.slot.clone()
    }

    /// Whether the verifier saw a certificate on this connection (a full
    /// handshake; a resumed TLS 1.3 session sends none).
    pub(crate) fn certificate_seen(&self) -> bool {
        self.slot.lock().0.verification.is_some()
    }
}

/// TLS evidence for a connection that resumed a session: no certificate was
/// exchanged, so the chain is the one stored with the ticket and the
/// verification is the original handshake's. A ticket of a verifying profile
/// exists only because that handshake passed this profile's verifier; with a
/// bypass the chain is checked again to say what strict verification would
/// conclude.
pub(crate) fn resumed_observation(
    h: &ObservationHandle,
    prepared: &PreparedTls,
    chain: &[CertificateDer<'_>],
    version: Option<String>,
    cipher_suite: Option<String>,
    alpn_negotiated: Option<String>,
) -> TlsObservation {
    let mut obs = observe(h, prepared, true);
    obs.version = version;
    obs.cipher_suite = cipher_suite;
    obs.alpn_negotiated = alpn_negotiated;
    obs.resumed = Some(true);
    obs.client_certificate_requested = None;
    obs.client_certificate_presented = None;
    obs.peer_certificates = chain.iter().map(summarize).collect();
    if let Some(leaf) = chain.first() {
        obs.peer_spiffe_id = spiffe::peer_spiffe_id(leaf.as_ref());
    }
    obs.verification = if prepared.verify {
        TlsVerification::Verified
    } else {
        let would_have_failed = match (chain.first(), ServerName::try_from(h.sni.clone())) {
            (Some(leaf), Ok(name)) if prepared.verifier.is_some() => {
                verify_peer(&prepared.peer_check(), &name, leaf, &chain[1..], UnixTime::now()).problem.map(|(k, _)| k)
            }
            _ => None,
        };
        TlsVerification::Bypassed { would_have_failed }
    };
    obs
}

fn empty_observation(host: &str, alpn: &[&str]) -> TlsObservation {
    TlsObservation {
        server_name: host.to_string(),
        sni: None,
        server_name_overridden: false,
        identity_check: None,
        peer_spiffe_id: None,
        version: None,
        cipher_suite: None,
        alpn_offered: alpn.iter().map(|s| s.to_string()).collect(),
        alpn_negotiated: None,
        verification: TlsVerification::NotReached,
        peer_certificates: vec![],
        client_certificate_requested: None,
        client_certificate_presented: None,
        alert_received: None,
        resumed: None,
    }
}

fn observation_from_slot(
    slot: &Arc<Mutex<SlotHandle>>,
    sni: &str,
    sent_sni: bool,
    alpn: &[&str],
    prepared: &PreparedTls,
    completed: bool,
) -> TlsObservation {
    let s = slot.lock();
    let mut obs = empty_observation(sni, alpn);
    obs.sni = if sent_sni { Some(sni.to_string()) } else { None };
    obs.server_name_overridden = prepared.server_name_override.is_some();
    obs.identity_check = Some(identity_check_for(prepared, sni));
    obs.peer_spiffe_id = s.0.peer_spiffe_id.clone();
    obs.peer_certificates = s.0.peer_chain.clone();
    obs.verification = s.0.verification.clone().unwrap_or(TlsVerification::NotReached);
    // "Not requested" is only asserted for a completed full handshake; a
    // failed handshake may have stopped before the resolver was consulted.
    obs.client_certificate_requested = if s.0.client_cert_requested {
        Some(true)
    } else if completed {
        Some(false)
    } else {
        None
    };
    obs.client_certificate_presented = if s.0.client_cert_presented { prepared.client_summary.clone() } else { None };
    obs
}

/// Handle for reading TLS evidence from a connection built with
/// [`client_config_observed`] (used by QUIC, where the handshake is driven
/// by quinn rather than tokio-rustls).
pub struct ObservationHandle {
    slot: Arc<Mutex<SlotHandle>>,
    sni: String,
    sent_sni: bool,
    alpn: Vec<String>,
}

/// A client config (TLS 1.3 only when `tls13_only`) with observing verifier
/// and client-certificate resolver.
pub fn client_config_observed(
    prepared: &PreparedTls,
    host: &str,
    alpn: &[&str],
    tls13_only: bool,
) -> Result<(ClientConfig, ServerName<'static>, ObservationHandle), TransportFailure> {
    let server_name = server_name_for(host, prepared)?;
    let slot = Arc::new(Mutex::new(SlotHandle::default()));
    let versions: &[&'static rustls::SupportedProtocolVersion] = if tls13_only || prepared.min_version == TlsMinVersion::Tls13 {
        &[&rustls::version::TLS13]
    } else {
        &[&rustls::version::TLS13, &rustls::version::TLS12]
    };
    let cell = SlotCell::new(slot.clone());
    let verifier = Arc::new(ObservingVerifier { prepared: PreparedView::of(prepared), slot: cell.clone() });
    let mut cfg = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(versions)
        .map_err(|e| local(FailureKind::TlsProfileInvalid, format!("TLS versions unsupported: {e}"), "tls.min_version"))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_cert_resolver(Arc::new(ObservingClientCert { key: prepared.client_key.clone(), slot: cell }));
    cfg.alpn_protocols = alpn.iter().map(|p| p.as_bytes().to_vec()).collect();
    cfg.resumption = Resumption::store(prepared.sessions.clone());
    let sni = server_name_string(&server_name);
    let sent_sni = matches!(server_name, ServerName::DnsName(_));
    Ok((cfg, server_name, ObservationHandle { slot, sni, sent_sni, alpn: alpn.iter().map(|s| s.to_string()).collect() }))
}

pub fn observe(h: &ObservationHandle, prepared: &PreparedTls, completed: bool) -> TlsObservation {
    let alpn: Vec<&str> = h.alpn.iter().map(|s| s.as_str()).collect();
    observation_from_slot(&h.slot, &h.sni, h.sent_sni, &alpn, prepared, completed)
}
