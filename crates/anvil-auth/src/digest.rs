//! Body digest headers: RFC 9530 `Content-Digest` and legacy RFC 3230 `Digest`.

use anvil_domain::auth::BodyDigestHeader;
use base64::Engine;
use sha2::{Digest, Sha256, Sha512};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestAlg {
    Sha256,
    Sha512,
}

/// `(header name, header value)` over the final body bytes.
pub fn header(kind: BodyDigestHeader, alg: DigestAlg, body: &[u8]) -> (&'static str, String) {
    let (label, bytes) = match alg {
        DigestAlg::Sha256 => ("sha-256", Sha256::digest(body).to_vec()),
        DigestAlg::Sha512 => ("sha-512", Sha512::digest(body).to_vec()),
    };
    let b64 = base64::engine::general_purpose::STANDARD.encode(bytes);
    match kind {
        BodyDigestHeader::ContentDigest => ("Content-Digest", format!("{label}=:{b64}:")),
        BodyDigestHeader::LegacyDigest => ("Digest", format!("{label}={b64}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_body_matches_audited_vectors() {
        assert_eq!(
            header(BodyDigestHeader::LegacyDigest, DigestAlg::Sha256, b"").1,
            "sha-256=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="
        );
        assert_eq!(
            header(BodyDigestHeader::ContentDigest, DigestAlg::Sha256, br#"{"ping":1}"#).1,
            "sha-256=:ZId/Ft8ue8HkIp/hVZzPZbPIfx9wUS0PscyMwyMul3g=:"
        );
    }
}
