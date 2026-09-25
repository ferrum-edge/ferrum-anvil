//! PKCS#12 client identity import (pure Rust, p12-keystore). Converts the
//! first private-key chain to PEM for the transport; the bundle and password
//! are secrets and never logged.

use anvil_domain::execution::{FailureKind, Phase, TransportFailure};
use anvil_transport::tls::ClientIdentityMaterial;
use base64::Engine;
use zeroize::Zeroizing;

fn pem(label: &str, der: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut s = format!("-----BEGIN {label}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        s.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        s.push('\n');
    }
    s.push_str(&format!("-----END {label}-----\n"));
    s
}

pub fn to_pem(bundle_b64: &str, password: &str) -> Result<ClientIdentityMaterial, TransportFailure> {
    let fail =
        |m: String| TransportFailure::new(Phase::Prepare, FailureKind::ClientIdentityInvalid, m).with_field("tls.client_identity.pkcs12");
    let data = base64::engine::general_purpose::STANDARD
        .decode(bundle_b64.trim())
        .map_err(|_| fail("the PKCS#12 bundle is not valid base64".into()))?;
    let ks = p12_keystore::KeyStore::from_pkcs12(&data, password, p12_keystore::Pkcs12ImportPolicy::Relaxed)
        .map_err(|e| fail(format!("the PKCS#12 bundle could not be opened (wrong password or unsupported encryption): {e}")))?;
    for (_, entry) in ks.entries() {
        if let p12_keystore::KeyStoreEntry::PrivateKeyChain(chain) = entry {
            if chain.certs().is_empty() {
                continue;
            }
            let mut certs = String::new();
            for c in chain.certs() {
                certs.push_str(&pem("CERTIFICATE", c.as_der()));
            }
            return Ok(ClientIdentityMaterial {
                cert_chain_pem: certs,
                private_key_pem: Zeroizing::new(pem("PRIVATE KEY", chain.key().as_der())),
            });
        }
    }
    Err(fail("the PKCS#12 bundle contains no private key with a certificate".into()))
}
