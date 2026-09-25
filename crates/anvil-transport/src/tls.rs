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

use crate::certs::summarize;
use crate::errors::classify_rustls;
use anvil_domain::execution::{CertificateSummary, FailureKind, Phase, TlsObservation, TlsVerification, TransportFailure};
use anvil_domain::tls::TlsMinVersion;
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

/// Validated, reusable TLS material for one profile.
pub struct PreparedTls {
    /// Stable fingerprint of everything that affects the TLS session
    /// (part of the connection-pool isolation key).
    pub fingerprint: String,
    verifier: Option<Arc<WebPkiServerVerifier>>,
    client_key: Option<Arc<CertifiedKey>>,
    pub client_summary: Option<CertificateSummary>,
    pub verify: bool,
    min_version: TlsMinVersion,
    pub server_name_override: Option<String>,
    sessions: Arc<ClientSessionMemoryCache>,
}

fn local(kind: FailureKind, msg: impl Into<String>, field: &str) -> TransportFailure {
    TransportFailure::new(Phase::Prepare, kind, msg).with_field(field)
}

fn parse_certs(pem: &str, field: &str) -> Result<Vec<CertificateDer<'static>>, TransportFailure> {
    let mut rd = std::io::BufReader::new(pem.as_bytes());
    let certs: Result<Vec<_>, _> = rustls_pemfile::certs(&mut rd).collect();
    let certs = certs.map_err(|e| local(FailureKind::TlsProfileInvalid, format!("certificate PEM could not be parsed: {e}"), field))?;
    if certs.is_empty() {
        return Err(local(FailureKind::TlsProfileInvalid, "no CERTIFICATE blocks found in PEM", field));
    }
    Ok(certs)
}

fn parse_key(pem: &str) -> Result<PrivateKeyDer<'static>, TransportFailure> {
    let mut rd = std::io::BufReader::new(pem.as_bytes());
    match rustls_pemfile::private_key(&mut rd) {
        Ok(Some(k)) => Ok(k),
        Ok(None) => Err(local(
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

/// Validate a TLS profile: parse roots, load and key-match the client identity.
/// All failures are local (no network activity happened).
pub fn prepare(settings: &TlsSettings) -> Result<PreparedTls, TransportFailure> {
    let mut hasher = Sha256::new();
    hasher.update([settings.verify as u8, settings.use_system_roots as u8, settings.min_version as u8]);
    hasher.update(settings.server_name_override.as_deref().unwrap_or("").as_bytes());

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
    let verifier = if roots.is_empty() {
        if settings.verify {
            return Err(local(
                FailureKind::TlsProfileInvalid,
                "certificate verification is enabled but the profile has no trust anchors (system roots disabled and no CA configured)",
                "tls.extra_roots",
            ));
        }
        None
    } else {
        Some(
            WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider())
                .build()
                .map_err(|e| local(FailureKind::TlsProfileInvalid, format!("trust store could not be built: {e}"), "tls.extra_roots"))?,
        )
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
        client_key,
        client_summary,
        verify: settings.verify,
        min_version: settings.min_version,
        server_name_override: settings.server_name_override.clone(),
        sessions: Arc::new(ClientSessionMemoryCache::new(64)),
    })
}

#[derive(Default)]
struct Slot {
    peer_chain: Vec<CertificateSummary>,
    verification: Option<TlsVerification>,
    client_cert_requested: bool,
    client_cert_presented: bool,
}

#[derive(Debug)]
struct ObservingVerifier {
    inner: Option<Arc<WebPkiServerVerifier>>,
    verify: bool,
    slot: Arc<Mutex<SlotHandle>>,
}

#[derive(Default)]
struct SlotHandle(Slot);
impl std::fmt::Debug for SlotHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TlsObservationSlot")
    }
}

impl ServerCertVerifier for ObservingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let mut chain = vec![summarize(end_entity)];
        chain.extend(intermediates.iter().map(summarize));
        let result = match &self.inner {
            Some(v) => v.verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now),
            None => Err(rustls::Error::General("no trust anchors".into())),
        };
        let mut slot = self.slot.lock();
        slot.0.peer_chain = chain;
        if self.verify {
            match &result {
                Ok(_) => slot.0.verification = Some(TlsVerification::Verified),
                Err(e) => {
                    let (kind, _) = classify_rustls(e, false);
                    slot.0.verification = Some(TlsVerification::Failed { problem: kind, detail: e.to_string() });
                }
            }
            result
        } else {
            let would = match (&self.inner, &result) {
                (Some(_), Err(e)) => Some(classify_rustls(e, false).0),
                _ => None,
            };
            slot.0.verification = Some(TlsVerification::Bypassed { would_have_failed: would });
            Ok(ServerCertVerified::assertion())
        }
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
struct ObservingClientCert {
    key: Option<Arc<CertifiedKey>>,
    slot: Arc<Mutex<SlotHandle>>,
}

impl rustls::client::ResolvesClientCert for ObservingClientCert {
    fn resolve(&self, _root_hint_subjects: &[&[u8]], _sigschemes: &[SignatureScheme]) -> Option<Arc<CertifiedKey>> {
        let mut slot = self.slot.lock();
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
    let fut = connector.connect(server_name, io);
    let res = match deadline {
        Some(d) => match tokio::time::timeout(d, fut).await {
            Ok(r) => r,
            Err(_) => {
                let obs = observation_from_slot(&slot, &sni, alpn, prepared, false);
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
            let mut obs = observation_from_slot(&slot, &sni, alpn, prepared, true);
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
            let obs = observation_from_slot(&slot, &sni, alpn, prepared, false);
            let mut f = crate::errors::classify_tls_handshake(&e);
            // Prefer the verifier's own typed conclusion when it failed.
            if let TlsVerification::Failed { problem, .. } = &obs.verification {
                f.kind = *problem;
            }
            Err((f, obs))
        }
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
    let verifier = Arc::new(ObservingVerifier { inner: prepared.verifier.clone(), verify: prepared.verify, slot: slot.clone() });
    let mut cfg = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(versions)
        .map_err(|e| local(FailureKind::TlsProfileInvalid, format!("TLS versions unsupported: {e}"), "tls.min_version"))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_cert_resolver(Arc::new(ObservingClientCert { key: prepared.client_key.clone(), slot }));
    cfg.alpn_protocols = alpn.iter().map(|p| p.as_bytes().to_vec()).collect();
    cfg.resumption = Resumption::store(prepared.sessions.clone());
    Ok(cfg)
}

fn empty_observation(host: &str, alpn: &[&str]) -> TlsObservation {
    TlsObservation {
        server_name: host.to_string(),
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
    alpn: &[&str],
    prepared: &PreparedTls,
    completed: bool,
) -> TlsObservation {
    let s = slot.lock();
    let mut obs = empty_observation(sni, alpn);
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
