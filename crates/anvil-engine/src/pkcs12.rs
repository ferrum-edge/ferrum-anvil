//! PKCS#12 identity import (pure Rust, p12-keystore), for a TLS client
//! identity and for a WS-Security XML signing key. Converts the first
//! private-key chain to PEM; the bundle and password are secrets and never
//! logged.

use anvil_domain::execution::{FailureKind, Phase, TransportFailure};
use anvil_transport::certs::pem;
use anvil_transport::tls::ClientIdentityMaterial;
use base64::Engine;
use zeroize::Zeroizing;

/// The first private key with its certificate chain in a base64 PKCS#12
/// bundle, as (certificate chain PEM, PKCS#8 key PEM). The error is a
/// sentence that never quotes the bundle or the password.
pub fn decode(bundle_b64: &str, password: &str) -> Result<(String, Zeroizing<String>), String> {
    let data = Zeroizing::new(
        base64::engine::general_purpose::STANDARD
            .decode(bundle_b64.trim())
            .map_err(|_| "the PKCS#12 bundle is not valid base64".to_string())?,
    );
    let ks = p12_keystore::KeyStore::from_pkcs12(&data, password, p12_keystore::Pkcs12ImportPolicy::Relaxed)
        .map_err(|e| format!("the PKCS#12 bundle could not be opened (wrong password or unsupported encryption): {e}"))?;
    for (_, entry) in ks.entries() {
        if let p12_keystore::KeyStoreEntry::PrivateKeyChain(chain) = entry {
            if chain.certs().is_empty() {
                continue;
            }
            let mut certs = String::new();
            for c in chain.certs() {
                certs.push_str(&pem("CERTIFICATE", c.as_der()));
            }
            return Ok((certs, Zeroizing::new(pem("PRIVATE KEY", chain.key().as_der()))));
        }
    }
    Err("the PKCS#12 bundle contains no private key with a certificate".into())
}

pub fn to_pem(bundle_b64: &str, password: &str) -> Result<ClientIdentityMaterial, TransportFailure> {
    let (cert_chain_pem, private_key_pem) = decode(bundle_b64, password).map_err(|m| {
        TransportFailure::new(Phase::Prepare, FailureKind::ClientIdentityInvalid, m).with_field("tls.client_identity.pkcs12")
    })?;
    Ok(ClientIdentityMaterial { cert_chain_pem, private_key_pem })
}
