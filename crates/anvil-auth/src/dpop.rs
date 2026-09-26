//! RFC 9449 DPoP proofs, shaped for Ferrum Edge 0.9.5 `jwks_auth`:
//! `typ=dpop+jwt`, ES256, embedded public JWK, integer `iat`, unique `jti`,
//! `htm` = uppercase method, `htu` = scheme://host[:port]/path (lowercase host,
//! default port removed, no query/fragment), and `ath` = b64url(SHA-256(token)).
//! A new proof is generated for every send (proofs are single-use).

use crate::AuthError;
use base64::Engine;
use chrono::{DateTime, Utc};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use sha2::{Digest, Sha256};

pub struct Proof {
    pub jwt: String,
    pub jti: String,
    pub jkt: String,
    pub htu: String,
}

fn b64u(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

/// Canonical `htu` for a request as sent.
pub fn htu(scheme: &str, authority: &str, raw_path: &str) -> Result<String, AuthError> {
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return Err(AuthError::Invalid(format!("DPoP htu requires http or https, got {scheme}")));
    }
    let mut host = authority.trim().to_ascii_lowercase();
    if (scheme == "http" && host.ends_with(":80")) || (scheme == "https" && host.ends_with(":443")) {
        host.truncate(host.rfind(':').unwrap_or(host.len()));
    }
    let path = raw_path.split(['?', '#']).next().unwrap_or("");
    let path = if path.starts_with('/') { path.to_string() } else { format!("/{path}") };
    Ok(format!("{scheme}://{host}{path}"))
}

pub fn ath(access_token: &str) -> String {
    b64u(&Sha256::digest(access_token.as_bytes()))
}

/// Public JWK members (x, y) of a P-256 private key PEM.
pub fn public_jwk(private_key_pem: &str) -> Result<(String, String), AuthError> {
    use p256::pkcs8::DecodePrivateKey;
    let sk = p256::ecdsa::SigningKey::from_pkcs8_pem(private_key_pem)
        .or_else(|_| p256::SecretKey::from_sec1_pem(private_key_pem).map(p256::ecdsa::SigningKey::from).map_err(|e| e.to_string()))
        .map_err(|e| AuthError::Invalid(format!("DPoP key must be a P-256 private key in PKCS#8 or SEC1 PEM: {e}")))?;
    let vk = sk.verifying_key();
    let point = vk.to_sec1_bytes();
    // Uncompressed SEC1: 0x04 || X(32) || Y(32)
    let bytes: &[u8] = point.as_ref();
    if bytes.len() != 65 || bytes[0] != 4 {
        return Err(AuthError::Invalid("unexpected P-256 public key encoding".into()));
    }
    Ok((b64u(&bytes[1..33]), b64u(&bytes[33..65])))
}

/// RFC 7638 thumbprint in the gateway's canonical member order.
pub fn thumbprint(x: &str, y: &str) -> String {
    let canonical = format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#);
    b64u(&Sha256::digest(canonical.as_bytes()))
}

/// Generate a new P-256 key pair; returns PKCS#8 PEM.
pub fn generate_key_pem() -> Result<String, AuthError> {
    use p256::pkcs8::EncodePrivateKey;
    let mut seed = [0u8; 32];
    loop {
        rand::fill(&mut seed);
        if let Ok(sk) = p256::SecretKey::from_slice(&seed) {
            let pem = sk.to_pkcs8_pem(Default::default()).map_err(|e| AuthError::Invalid(e.to_string()))?;
            return Ok(pem.to_string());
        }
    }
}

pub fn proof(
    private_key_pem: &str,
    method: &str,
    htu: &str,
    access_token: Option<&str>,
    nonce: Option<&str>,
    now: DateTime<Utc>,
) -> Result<Proof, AuthError> {
    let (x, y) = public_jwk(private_key_pem)?;
    let jkt = thumbprint(&x, &y);
    let jti = uuid::Uuid::new_v4().to_string();
    let mut claims = serde_json::json!({
        "htm": method.to_ascii_uppercase(),
        "htu": htu,
        "iat": now.timestamp(),
        "jti": jti,
    });
    if let Some(t) = access_token {
        claims["ath"] = ath(t).into();
    }
    if let Some(n) = nonce {
        claims["nonce"] = n.into();
    }
    let mut header = Header::new(Algorithm::ES256);
    header.typ = Some("dpop+jwt".into());
    header.jwk = Some(
        serde_json::from_value(serde_json::json!({"kty": "EC", "crv": "P-256", "x": x, "y": y}))
            .map_err(|e| AuthError::Invalid(format!("JWK construction failed: {e}")))?,
    );
    let key = EncodingKey::from_ec_pem(private_key_pem.as_bytes()).map_err(|e| AuthError::Invalid(format!("DPoP key: {e}")))?;
    let jwt = jsonwebtoken::encode(&header, &claims, &key).map_err(|e| AuthError::Invalid(format!("DPoP signing failed: {e}")))?;
    Ok(Proof { jwt, jti, jkt, htu: htu.to_string() })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc9449_ath_vector() {
        assert_eq!(ath("Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU"), "fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo");
    }

    #[test]
    fn rfc9449_thumbprint_vector() {
        assert_eq!(
            thumbprint("l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs", "9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA"),
            "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"
        );
    }

    #[test]
    fn htu_canonicalization_matches_gateway_table() {
        assert_eq!(htu("HTTPS", "Example.COM:443", "/resource?x=1#frag").unwrap(), "https://example.com/resource");
        assert_eq!(htu("http", "example.com:80", "/x").unwrap(), "http://example.com/x");
        assert_eq!(htu("https", "example.com:8443", "/x").unwrap(), "https://example.com:8443/x");
        assert!(htu("ftp", "example.com", "/").is_err());
    }

    #[test]
    fn proofs_are_fresh_and_bound() {
        let pem = generate_key_pem().unwrap();
        let now = Utc::now();
        let a = proof(&pem, "post", "https://api.anvil.test/orders", Some("tok"), None, now).unwrap();
        let b = proof(&pem, "post", "https://api.anvil.test/orders", Some("tok"), None, now).unwrap();
        assert_ne!(a.jti, b.jti, "each send needs a new jti");
        assert_eq!(a.jkt, b.jkt);
        let payload: serde_json::Value =
            serde_json::from_slice(&base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(a.jwt.split('.').nth(1).unwrap()).unwrap())
                .unwrap();
        assert_eq!(payload["htm"], "POST");
        assert_eq!(payload["ath"], ath("tok"));
        let header: serde_json::Value =
            serde_json::from_slice(&base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(a.jwt.split('.').next().unwrap()).unwrap())
                .unwrap();
        assert_eq!(header["typ"], "dpop+jwt");
        assert!(header["jwk"].get("d").is_none(), "private members must never be embedded");
    }
}
