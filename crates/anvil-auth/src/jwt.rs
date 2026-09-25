//! JWT helper: signs with user-supplied key material only, and inspects
//! tokens. Decoding is NOT verification; inspection reports time-claim status
//! against the local clock and says explicitly that the signature is unverified.

use crate::AuthError;
use anvil_domain::auth::{JwtAlgorithm, JwtClaims};
use base64::Engine;
use chrono::{DateTime, Utc};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::Serialize;

fn alg(a: JwtAlgorithm) -> Algorithm {
    match a {
        JwtAlgorithm::HS256 => Algorithm::HS256,
        JwtAlgorithm::HS384 => Algorithm::HS384,
        JwtAlgorithm::HS512 => Algorithm::HS512,
        JwtAlgorithm::RS256 => Algorithm::RS256,
        JwtAlgorithm::ES256 => Algorithm::ES256,
    }
}

pub fn sign(
    algorithm: JwtAlgorithm,
    key: &str,
    claims: &JwtClaims,
    extra: &serde_json::Value,
    kid: Option<&str>,
    now: DateTime<Utc>,
) -> Result<String, AuthError> {
    let mut body = serde_json::Map::new();
    if let Some(obj) = extra.as_object() {
        for (k, v) in obj {
            body.insert(k.clone(), v.clone());
        }
    } else if !extra.is_null() {
        return Err(AuthError::Invalid("additional JWT claims must be a JSON object".into()));
    }
    let ts = now.timestamp();
    body.insert("iat".into(), ts.into());
    if let Some(v) = &claims.iss {
        body.insert("iss".into(), v.clone().into());
    }
    if let Some(v) = &claims.sub {
        body.insert("sub".into(), v.clone().into());
    }
    if let Some(v) = &claims.aud {
        body.insert("aud".into(), v.clone().into());
    }
    if let Some(e) = claims.expires_in_secs {
        body.insert("exp".into(), (ts + e).into());
    }
    if let Some(n) = claims.not_before_offset_secs {
        body.insert("nbf".into(), (ts + n).into());
    }
    let mut header = Header::new(alg(algorithm));
    header.kid = kid.map(|s| s.to_string());
    let enc =
        match algorithm {
            JwtAlgorithm::HS256 | JwtAlgorithm::HS384 | JwtAlgorithm::HS512 => {
                if key.is_empty() {
                    return Err(AuthError::Invalid("JWT HMAC secret is empty".into()));
                }
                EncodingKey::from_secret(key.as_bytes())
            }
            JwtAlgorithm::RS256 => EncodingKey::from_rsa_pem(key.as_bytes())
                .map_err(|e| AuthError::Invalid(format!("RS256 key is not a valid RSA PEM: {e}")))?,
            JwtAlgorithm::ES256 => EncodingKey::from_ec_pem(key.as_bytes())
                .map_err(|e| AuthError::Invalid(format!("ES256 key is not a valid P-256 PEM: {e}")))?,
        };
    jsonwebtoken::encode(&header, &serde_json::Value::Object(body), &enc)
        .map_err(|e| AuthError::Invalid(format!("JWT signing failed: {e}")))
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TimeStatus {
    Valid,
    Expired,
    NotYetValid,
    NoExpiry,
}

#[derive(Debug, Clone, Serialize)]
pub struct Inspection {
    pub header: serde_json::Value,
    pub claims: serde_json::Value,
    pub time_status: TimeStatus,
    /// Always false: decoding does not verify the signature.
    pub signature_verified: bool,
    pub notes: Vec<String>,
}

/// Decode a JWT for display. Never treats the token as verified.
pub fn inspect(token: &str, now: DateTime<Utc>, leeway_secs: i64) -> Result<Inspection, AuthError> {
    let parts: Vec<&str> = token.trim().split('.').collect();
    if parts.len() != 3 {
        return Err(AuthError::Invalid("not a compact JWS (expected three dot-separated parts)".into()));
    }
    let dec = |s: &str| -> Result<serde_json::Value, AuthError> {
        let b = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(s.trim_end_matches('='))
            .map_err(|_| AuthError::Invalid("JWT segment is not base64url".into()))?;
        serde_json::from_slice(&b).map_err(|_| AuthError::Invalid("JWT segment is not JSON".into()))
    };
    let header = dec(parts[0])?;
    let claims = dec(parts[1])?;
    let ts = now.timestamp();
    let exp = claims.get("exp").and_then(|v| v.as_i64());
    let nbf = claims.get("nbf").and_then(|v| v.as_i64());
    let mut notes = vec!["Decoded only: the signature has not been verified.".to_string()];
    let time_status = if let Some(n) = nbf.filter(|n| ts + leeway_secs < *n) {
        notes
            .push(format!("Not valid until {} (local clock).", DateTime::from_timestamp(n, 0).map(|d| d.to_rfc3339()).unwrap_or_default()));
        TimeStatus::NotYetValid
    } else if let Some(e) = exp {
        if ts - leeway_secs >= e {
            notes.push(format!("Expired at {} (local clock).", DateTime::from_timestamp(e, 0).map(|d| d.to_rfc3339()).unwrap_or_default()));
            TimeStatus::Expired
        } else {
            TimeStatus::Valid
        }
    } else {
        TimeStatus::NoExpiry
    };
    if let Some(a) = header.get("alg").and_then(|a| a.as_str())
        && a.eq_ignore_ascii_case("none")
    {
        notes.push("Header declares alg \"none\": the token is unsigned and must never be accepted as verified.".into());
    }
    Ok(Inspection { header, claims, time_status, signature_verified: false, notes })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hs256_sign_then_inspect_times() {
        let now = DateTime::from_timestamp(1_800_000_000, 0).unwrap();
        let claims = JwtClaims { sub: Some("bob".into()), expires_in_secs: Some(60), ..Default::default() };
        let t = sign(JwtAlgorithm::HS256, "bob-jwt-secret-key-12345678901234", &claims, &serde_json::Value::Null, None, now).unwrap();
        let i = inspect(&t, now, 0).unwrap();
        assert_eq!(i.time_status, TimeStatus::Valid);
        assert!(!i.signature_verified);
        let later = DateTime::from_timestamp(1_800_000_061, 0).unwrap();
        assert_eq!(inspect(&t, later, 0).unwrap().time_status, TimeStatus::Expired);
        // Independent verification with the same secret.
        let mut v = jsonwebtoken::Validation::new(Algorithm::HS256);
        v.validate_exp = false;
        v.required_spec_claims.clear();
        jsonwebtoken::decode::<serde_json::Value>(&t, &jsonwebtoken::DecodingKey::from_secret(b"bob-jwt-secret-key-12345678901234"), &v)
            .unwrap();
    }

    #[test]
    fn unsigned_token_is_flagged() {
        let t = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0.";
        let i = inspect(t, Utc::now(), 0).unwrap();
        assert!(i.notes.iter().any(|n| n.contains("unsigned")));
    }
}
