//! The X.509 signing identity behind WS-Security XML signatures: a private
//! key and the certificate it belongs to, and the XML-DSig signature over a
//! canonical `SignedInfo`.
//!
//! Keys are read from PEM: PKCS#8 (`PRIVATE KEY`, RSA or EC), PKCS#1 (`RSA
//! PRIVATE KEY`) or SEC1 (`EC PRIVATE KEY`). A PKCS#12 bundle is converted to
//! PEM by the engine before it reaches this module. Signing is done by
//! AWS-LC (`aws-lc-rs`, already the workspace's JWT backend): RSA PKCS#1 v1.5
//! with SHA-256 (blinded) and ECDSA P-256 with SHA-256, written as the fixed
//! `r || s` form XML-DSig requires. SHA-1 is never offered, RSA keys shorter
//! than 2048 bits and curves other than P-256 are refused, and the key must
//! belong to one of the certificates given.
//!
//! Nothing here formats key material: errors are fixed sentences, and the
//! identity's `Debug` names only the algorithm and the certificate.

use crate::AuthError;
use anvil_domain::auth::XmlSignatureAlgorithm;
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _, RSA_PKCS1_SHA256, RsaKeyPair};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// `ds:SignatureMethod` for RSA PKCS#1 v1.5 with SHA-256 (RFC 6931 §2.3.2).
pub const RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
/// `ds:SignatureMethod` for ECDSA with SHA-256 (RFC 6931 §2.3.6).
pub const ECDSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";
/// `ds:DigestMethod` SHA-256 (XML Encryption).
pub const DIGEST_SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
/// The XML-DSig namespace.
pub const DS_NS: &str = "http://www.w3.org/2000/09/xmldsig#";
/// Smallest RSA modulus accepted, in bits.
pub const MIN_RSA_BITS: usize = 2048;
/// Largest RSA modulus AWS-LC signs with, in bits.
pub const MAX_RSA_BITS: usize = 8192;

/// The signature algorithm an identity signs with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    RsaSha256,
    EcdsaP256Sha256,
}

impl Algorithm {
    /// The `ds:SignatureMethod` algorithm URI.
    pub fn uri(self) -> &'static str {
        match self {
            Algorithm::RsaSha256 => RSA_SHA256,
            Algorithm::EcdsaP256Sha256 => ECDSA_SHA256,
        }
    }

    /// A short label for evidence (`RSA-SHA256`, `ECDSA-P256-SHA256`).
    pub fn label(self) -> &'static str {
        match self {
            Algorithm::RsaSha256 => "RSA-SHA256",
            Algorithm::EcdsaP256Sha256 => "ECDSA-P256-SHA256",
        }
    }
}

enum Key {
    Rsa(RsaKeyPair),
    Ec(EcdsaKeyPair),
}

/// A private key with its certificate, ready to sign.
pub struct SigningIdentity {
    key: Key,
    algorithm: Algorithm,
    /// DER of the certificate the key belongs to (sent as the token).
    certificate_der: Vec<u8>,
    /// Certificates given after it (not sent; see `docs/wsse-signing.md`).
    extra_certificates: usize,
    subject: String,
    not_after_unix: i64,
}

impl std::fmt::Debug for SigningIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningIdentity")
            .field("algorithm", &self.algorithm)
            .field("certificate_sha256", &self.certificate_sha256())
            .field("key", &"‹redacted›")
            .finish()
    }
}

fn invalid(m: impl Into<String>) -> AuthError {
    AuthError::Invalid(m.into())
}

/// A PEM block's label and DER (zeroized when dropped).
type PemBlock = (String, Zeroizing<Vec<u8>>);

/// Every PEM block in `text` as (label, DER). The DER of a key is zeroized
/// when dropped. Any PEM error is reported without its detail, which could
/// quote a byte of the key.
fn pem_blocks(text: &str, what: &str) -> Result<Vec<PemBlock>, AuthError> {
    let mut out = Vec::new();
    for block in x509_parser::pem::Pem::iter_from_buffer(text.trim().as_bytes()) {
        let block = block.map_err(|_| invalid(format!("the {what} is not valid PEM")))?;
        out.push((block.label, Zeroizing::new(block.contents)));
    }
    if out.is_empty() {
        return Err(invalid(format!("the {what} holds no PEM block")));
    }
    Ok(out)
}

/// Bits in a big-endian unsigned integer.
fn bit_len(be: &[u8]) -> usize {
    let be = &be[be.iter().take_while(|b| **b == 0).count()..];
    match be.first() {
        Some(first) => be.len() * 8 - first.leading_zeros() as usize,
        None => 0,
    }
}

/// The public key a certificate certifies.
enum CertKey {
    Rsa { bits: usize, spki_key: Vec<u8> },
    Ec { point: Vec<u8> },
}

struct Cert {
    der: Vec<u8>,
    key: CertKey,
    subject: String,
    not_after_unix: i64,
}

fn parse_certificate(der: Vec<u8>, index: usize) -> Result<Cert, AuthError> {
    use x509_parser::prelude::*;
    let (_, cert) = X509Certificate::from_der(&der)
        .map_err(|_| invalid(format!("certificate {} of the chain is not a valid X.509 certificate", index + 1)))?;
    let spki = cert.public_key();
    let key = match spki.parsed() {
        Ok(x509_parser::public_key::PublicKey::RSA(rsa)) => {
            CertKey::Rsa { bits: bit_len(rsa.modulus), spki_key: spki.subject_public_key.data.to_vec() }
        }
        Ok(x509_parser::public_key::PublicKey::EC(point)) => CertKey::Ec { point: point.data().to_vec() },
        _ => CertKey::Ec { point: Vec::new() },
    };
    let subject = cert.subject().to_string();
    let not_after_unix = cert.validity().not_after.timestamp();
    drop(cert);
    Ok(Cert { der, key, subject, not_after_unix })
}

impl SigningIdentity {
    /// Build an identity from a PEM certificate chain and a PEM private key.
    /// The key must belong to one of the certificates; that certificate is
    /// the one sent. `algorithm` must suit the key (`Auto` picks it).
    pub fn from_pem(cert_chain_pem: &str, private_key_pem: &str, algorithm: XmlSignatureAlgorithm) -> Result<Self, AuthError> {
        let mut certs = Vec::new();
        for (i, (label, der)) in pem_blocks(cert_chain_pem, "signing certificate chain")?.into_iter().enumerate() {
            if label != "CERTIFICATE" {
                return Err(invalid(format!(
                    "the signing certificate chain holds a '{label}' PEM block; it must hold certificates only (put the private key in its own field)"
                )));
            }
            certs.push(parse_certificate(der.to_vec(), i)?);
        }
        let mut keys = pem_blocks(private_key_pem, "signing private key")?;
        if keys.len() != 1 {
            return Err(invalid("the signing private key must be exactly one PEM block"));
        }
        let (label, key_der) = keys.remove(0);
        let rsa_wanted = match label.as_str() {
            "PRIVATE KEY" => None,
            "RSA PRIVATE KEY" => Some(true),
            "EC PRIVATE KEY" => Some(false),
            "ENCRYPTED PRIVATE KEY" => {
                return Err(invalid(
                    "the signing private key is encrypted; give it unencrypted (kept in the vault) or as a PKCS#12 bundle with its password",
                ));
            }
            _ => return Err(invalid(format!("a '{label}' PEM block is not a private key Anvil can sign with (PKCS#8, PKCS#1 or SEC1)"))),
        };
        // Which kind of key to read follows the certificates when the PEM
        // label does not say.
        let rsa = rsa_wanted.unwrap_or_else(|| certs.iter().any(|c| matches!(c.key, CertKey::Rsa { .. })));
        let (key, public) = if rsa {
            let parsed = if label == "RSA PRIVATE KEY" { RsaKeyPair::from_der(&key_der) } else { RsaKeyPair::from_pkcs8(&key_der) };
            let pair = parsed.map_err(|e| match e.description_() {
                "TooSmall" => {
                    invalid(format!("the signing key is an RSA key shorter than {MIN_RSA_BITS} bits; Anvil refuses weak RSA keys"))
                }
                "TooLarge" => invalid(format!("the signing key is an RSA key longer than {MAX_RSA_BITS} bits, which is not supported")),
                _ => invalid("the signing private key is not a usable RSA or P-256 EC key"),
            })?;
            if pair.public_modulus_len() * 8 < MIN_RSA_BITS {
                return Err(invalid(format!(
                    "the signing key is an RSA key shorter than {MIN_RSA_BITS} bits; Anvil refuses weak RSA keys"
                )));
            }
            let public = pair.public_key().as_ref().to_vec();
            (Key::Rsa(pair), public)
        } else {
            let pair = EcdsaKeyPair::from_private_key_der(&ECDSA_P256_SHA256_FIXED_SIGNING, &key_der)
                .map_err(|_| invalid("the signing private key is not a P-256 EC key (the only curve supported) or a usable RSA key"))?;
            let public = pair.public_key().as_ref().to_vec();
            (Key::Ec(pair), public)
        };
        drop(key_der);
        let found = certs.iter().position(|c| match &c.key {
            CertKey::Rsa { spki_key, .. } => matches!(key, Key::Rsa(_)) && *spki_key == public,
            CertKey::Ec { point } => matches!(key, Key::Ec(_)) && *point == public,
        });
        let Some(index) = found else {
            return Err(invalid("the signing private key does not belong to any certificate in the signing certificate chain"));
        };
        let cert = certs.swap_remove(index);
        if let CertKey::Rsa { bits, .. } = cert.key
            && bits < MIN_RSA_BITS
        {
            return Err(invalid(format!(
                "the signing certificate has a {bits}-bit RSA key; Anvil refuses RSA keys shorter than {MIN_RSA_BITS} bits"
            )));
        }
        let natural = match key {
            Key::Rsa(_) => Algorithm::RsaSha256,
            Key::Ec(_) => Algorithm::EcdsaP256Sha256,
        };
        let algorithm = match (algorithm, natural) {
            (XmlSignatureAlgorithm::Auto, a) => a,
            (XmlSignatureAlgorithm::RsaSha256, Algorithm::RsaSha256) => Algorithm::RsaSha256,
            (XmlSignatureAlgorithm::EcdsaP256Sha256, Algorithm::EcdsaP256Sha256) => Algorithm::EcdsaP256Sha256,
            (chosen, a) => {
                return Err(invalid(format!(
                    "the signature algorithm {chosen:?} does not suit the signing key, which signs {}; choose Auto or {}",
                    a.label(),
                    a.label()
                )));
            }
        };
        Ok(SigningIdentity {
            key,
            algorithm,
            certificate_der: cert.der,
            extra_certificates: certs.len(),
            subject: cert.subject,
            not_after_unix: cert.not_after_unix,
        })
    }

    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// DER of the certificate sent in the `wsse:BinarySecurityToken`.
    pub fn certificate_der(&self) -> &[u8] {
        &self.certificate_der
    }

    /// Hex SHA-256 of the sent certificate (what Ferrum Edge pins).
    pub fn certificate_sha256(&self) -> String {
        hex::encode(Sha256::digest(&self.certificate_der))
    }

    pub fn certificate_subject(&self) -> &str {
        &self.subject
    }

    /// The sent certificate's notAfter, in Unix seconds.
    pub fn certificate_not_after_unix(&self) -> i64 {
        self.not_after_unix
    }

    /// Certificates in the chain besides the one sent.
    pub fn extra_certificates(&self) -> usize {
        self.extra_certificates
    }

    /// The XML-DSig `SignatureValue` bytes over `data` (the canonical
    /// `SignedInfo`): RSA PKCS#1 v1.5 or ECDSA `r || s`, both over SHA-256.
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, AuthError> {
        let failed = || AuthError::Invalid("the XML signature could not be computed".into());
        let rng = SystemRandom::new();
        match &self.key {
            Key::Rsa(pair) => {
                let mut sig = vec![0u8; pair.public_modulus_len()];
                pair.sign(&RSA_PKCS1_SHA256, &rng, data, &mut sig).map_err(|_| failed())?;
                Ok(sig)
            }
            Key::Ec(pair) => Ok(pair.sign(&rng, data).map_err(|_| failed())?.as_ref().to_vec()),
        }
    }

    /// Check `signature` over `data` with this identity's public key (for
    /// tests; CI verifies with xmlsec1 and Ferrum Edge independently).
    pub fn verify(&self, data: &[u8], signature: &[u8]) -> bool {
        use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED, RSA_PKCS1_2048_8192_SHA256, UnparsedPublicKey};
        match &self.key {
            Key::Rsa(pair) => {
                UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, pair.public_key().as_ref()).verify(data, signature).is_ok()
            }
            Key::Ec(pair) => UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, pair.public_key().as_ref()).verify(data, signature).is_ok(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bit_lengths_ignore_leading_zero_bytes() {
        assert_eq!(bit_len(&[0, 0x80, 0]), 16);
        assert_eq!(bit_len(&[0x01, 0]), 9);
        assert_eq!(bit_len(&[0, 0]), 0);
    }

    #[test]
    fn non_pem_input_is_refused_without_quoting_it() {
        let e = SigningIdentity::from_pem("not pem", "tok-SENSITIVE-not-a-key", XmlSignatureAlgorithm::Auto).unwrap_err().to_string();
        assert!(!e.contains("tok-SENSITIVE"), "{e}");
        assert!(e.contains("certificate chain"), "{e}");
    }
}
