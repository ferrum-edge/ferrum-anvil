//! JWT-SVID decoding and signature verification against a SPIFFE JWT bundle
//! (the JWKS a Workload API returns from `FetchJWTBundles`).
//!
//! * Decoding is strict: three unpadded base64url segments, JSON objects for
//!   the header and the claims, bounded sizes. Decoding is never verification.
//! * Verification selects the bundle key by `kid` (a token without `kid` is
//!   accepted only when the bundle holds exactly one key), and verifies with
//!   the algorithm family the *key* permits — the JWK's own `alg` when it
//!   declares one — never with the token's word alone. `none` and the HMAC
//!   family are refused before any key is touched: a bundle publishes public
//!   keys, so a symmetric "verification" would let anyone forge a token.
//! * Only the signature is verified here. Time, audience and subject checks
//!   belong to the caller, which reports each one separately.

use base64::Engine;
use jsonwebtoken::jwk::{AlgorithmParameters, EllipticCurve, Jwk};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde_json::{Map, Value};

/// Largest JWT-SVID accepted for checking.
pub const MAX_TOKEN_BYTES: usize = 16 * 1024;
/// Largest decoded header or claims segment.
pub const MAX_SEGMENT_BYTES: usize = 8 * 1024;
/// Algorithms the JWT-SVID specification allows (§3) that Anvil can verify.
pub const ALLOWED_ALGORITHMS: &[&str] = &["RS256", "RS384", "RS512", "ES256", "ES384", "PS256", "PS384", "PS512"];

/// Header and claims of a JWT-SVID (decoded, not verified).
#[derive(Debug, Clone)]
pub struct Decoded {
    pub header: Map<String, Value>,
    pub claims: Map<String, Value>,
}

impl Decoded {
    pub fn alg(&self) -> Option<&str> {
        self.header.get("alg").and_then(Value::as_str)
    }

    pub fn kid(&self) -> Option<&str> {
        self.header.get("kid").and_then(Value::as_str)
    }
}

/// Decode a compact JWS strictly (no verification).
pub fn decode(token: &str) -> Result<Decoded, String> {
    let token = token.trim();
    if token.is_empty() {
        return Err("the token is empty".into());
    }
    if token.len() > MAX_TOKEN_BYTES {
        return Err(format!("the token is larger than {MAX_TOKEN_BYTES} bytes"));
    }
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err("the token is not a compact JWS (three dot-separated segments)".into());
    }
    if parts.iter().any(|p| p.is_empty() || !p.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')) {
        return Err("a token segment is empty or not unpadded base64url".into());
    }
    let seg = |s: &str, what: &str| -> Result<Map<String, Value>, String> {
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s).map_err(|_| format!("the {what} is not base64url"))?;
        if raw.len() > MAX_SEGMENT_BYTES {
            return Err(format!("the {what} is larger than {MAX_SEGMENT_BYTES} bytes"));
        }
        match serde_json::from_slice::<Value>(&raw) {
            Ok(Value::Object(m)) => Ok(m),
            _ => Err(format!("the {what} is not a JSON object")),
        }
    };
    Ok(Decoded { header: seg(parts[0], "header")?, claims: seg(parts[1], "claims segment")? })
}

/// Why `alg` is unacceptable for a JWT-SVID, if it is.
pub fn algorithm_problem(alg: Option<&str>) -> Option<String> {
    match alg {
        None => Some("the header has no alg".into()),
        Some(a) if a.eq_ignore_ascii_case("none") => Some("alg is \"none\": the token is unsigned".into()),
        Some(a) if a.to_ascii_uppercase().starts_with("HS") => {
            Some(format!("alg is {a}, a symmetric (HMAC) algorithm; JWT-SVIDs are signed with asymmetric keys"))
        }
        Some(a) if !ALLOWED_ALGORITHMS.contains(&a) => Some(format!("alg {a} is not an algorithm Anvil can verify for a JWT-SVID")),
        Some(_) => None,
    }
}

fn to_algorithm(a: &str) -> Option<Algorithm> {
    Some(match a {
        "RS256" => Algorithm::RS256,
        "RS384" => Algorithm::RS384,
        "RS512" => Algorithm::RS512,
        "ES256" => Algorithm::ES256,
        "ES384" => Algorithm::ES384,
        "PS256" => Algorithm::PS256,
        "PS384" => Algorithm::PS384,
        "PS512" => Algorithm::PS512,
        _ => return None,
    })
}

/// Whether `alg` is one the key's type can produce.
fn key_permits(jwk: &Jwk, alg: &str) -> bool {
    match &jwk.algorithm {
        AlgorithmParameters::EllipticCurve(ec) => match ec.curve {
            EllipticCurve::P256 => alg == "ES256",
            EllipticCurve::P384 => alg == "ES384",
            _ => false,
        },
        AlgorithmParameters::RSA(_) => matches!(alg, "RS256" | "RS384" | "RS512" | "PS256" | "PS384" | "PS512"),
        _ => false,
    }
}

/// Verify `token`'s signature with the bundle key selected by its `kid`.
/// Returns the key id used (or `-` for an unnamed single key).
pub fn verify_signature(token: &str, jwks: &[u8]) -> Result<String, String> {
    let d = decode(token)?;
    let alg = d.alg().map(str::to_string);
    if let Some(p) = algorithm_problem(alg.as_deref()) {
        return Err(p);
    }
    let alg = alg.unwrap_or_default();
    let doc: Value = serde_json::from_slice(jwks).map_err(|_| "the JWT bundle is not JSON".to_string())?;
    let keys = doc.get("keys").and_then(Value::as_array).ok_or("the JWT bundle has no keys array")?;
    // Keys for signature verification: `use` absent, `sig` or `jwt-svid`.
    let usable: Vec<&Value> = keys
        .iter()
        .filter(|k| match k.get("use") {
            None => true,
            Some(Value::String(u)) => u == "sig" || u == "jwt-svid",
            Some(_) => false,
        })
        .collect();
    let kid = d.kid();
    let candidates: Vec<&Value> = match kid {
        Some(kid) => usable.iter().copied().filter(|k| k.get("kid").and_then(Value::as_str) == Some(kid)).collect(),
        None => usable.clone(),
    };
    let key = match (candidates.as_slice(), kid) {
        ([one], _) => *one,
        ([], Some(k)) => return Err(format!("the JWT bundle has no signing key with kid {k}")),
        ([], None) => return Err("the JWT bundle has no signing key".into()),
        (_, Some(k)) => return Err(format!("the JWT bundle has several keys with kid {k}")),
        (_, None) => return Err("the token has no kid and the JWT bundle holds several keys, so the key is ambiguous".into()),
    };
    let jwk: Jwk = serde_json::from_value(key.clone()).map_err(|e| format!("the bundle key is not a usable JWK: {e}"))?;
    if let Some(declared) = key.get("alg").and_then(Value::as_str)
        && declared != alg
    {
        return Err(format!("the token says alg {alg} but the bundle key is declared for {declared}"));
    }
    if !key_permits(&jwk, &alg) {
        return Err(format!("the bundle key's type cannot produce alg {alg}"));
    }
    let algorithm = to_algorithm(&alg).ok_or_else(|| format!("alg {alg} is not supported"))?;
    let dk = DecodingKey::from_jwk(&jwk).map_err(|e| format!("the bundle key could not be loaded: {e}"))?;
    let mut v = Validation::new(algorithm);
    v.algorithms = vec![algorithm];
    v.validate_exp = false;
    v.validate_nbf = false;
    v.validate_aud = false;
    v.required_spec_claims.clear();
    jsonwebtoken::decode::<Value>(token.trim(), &dk, &v).map_err(|e| format!("the signature does not verify with that key ({e})"))?;
    Ok(kid.unwrap_or("-").to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{EncodingKey, Header};

    struct Key {
        pem: String,
        x: String,
        y: String,
    }

    fn fresh_key() -> Key {
        let pem = crate::dpop::generate_key_pem().unwrap();
        let (x, y) = crate::dpop::public_jwk(&pem).unwrap();
        Key { pem, x, y }
    }

    fn token_with(k: &Key, kid: Option<&str>, alg: Algorithm) -> String {
        let mut h = Header::new(alg);
        h.kid = kid.map(String::from);
        let claims = serde_json::json!({"sub": "spiffe://anvil.test/w", "aud": ["a"], "exp": 4_000_000_000i64});
        jsonwebtoken::encode(&h, &claims, &EncodingKey::from_ec_pem(k.pem.as_bytes()).unwrap()).unwrap()
    }

    fn jwks(keys: serde_json::Value) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({ "keys": keys })).unwrap()
    }

    fn key(k: &Key, kid: &str) -> serde_json::Value {
        serde_json::json!({"kty": "EC", "crv": "P-256", "x": k.x, "y": k.y, "kid": kid, "alg": "ES256", "use": "sig"})
    }

    #[test]
    fn verifies_by_kid_and_refuses_ambiguity_and_wrong_keys() {
        let (k, other) = (fresh_key(), fresh_key());
        let t = token_with(&k, Some("k1"), Algorithm::ES256);
        assert_eq!(verify_signature(&t, &jwks(serde_json::json!([key(&other, "k0"), key(&k, "k1")]))).unwrap(), "k1");
        assert!(verify_signature(&t, &jwks(serde_json::json!([key(&k, "k0")]))).unwrap_err().contains("no signing key with kid k1"));
        let unnamed = token_with(&k, None, Algorithm::ES256);
        assert_eq!(verify_signature(&unnamed, &jwks(serde_json::json!([key(&k, "k0")]))).unwrap(), "-");
        assert!(
            verify_signature(&unnamed, &jwks(serde_json::json!([key(&k, "k0"), key(&other, "k1")]))).unwrap_err().contains("ambiguous")
        );
        // Another key under the same kid: the signature does not verify.
        assert!(verify_signature(&t, &jwks(serde_json::json!([key(&other, "k1")]))).unwrap_err().contains("does not verify"));
        // A key declared for another algorithm is refused.
        let mut rs = key(&k, "k1");
        rs["alg"] = "ES384".into();
        assert!(verify_signature(&t, &jwks(serde_json::json!([rs]))).unwrap_err().contains("declared for ES384"));
        // x509-svid keys are not JWT signing keys.
        let x509 = serde_json::json!({"kty": "EC", "crv": "P-256", "x": k.x, "y": k.y, "kid": "k1", "use": "x509-svid"});
        assert!(verify_signature(&t, &jwks(serde_json::json!([x509]))).is_err());
    }

    #[test]
    fn none_and_hmac_are_refused_before_any_key() {
        let none = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0.c2ln";
        let k = fresh_key();
        assert!(verify_signature(none, &jwks(serde_json::json!([key(&k, "k")]))).unwrap_err().contains("unsigned"));
        let hs = jsonwebtoken::encode(&Header::new(Algorithm::HS256), &serde_json::json!({"sub": "x"}), &EncodingKey::from_secret(b"k"))
            .unwrap();
        assert!(verify_signature(&hs, &jwks(serde_json::json!([key(&k, "k")]))).unwrap_err().contains("HMAC"));
        assert!(algorithm_problem(Some("ES256")).is_none());
    }

    #[test]
    fn decoding_is_strict() {
        assert!(decode("a.b").is_err());
        assert!(decode("e30.e30.x=").is_err(), "padding is not base64url-unpadded");
        assert!(decode("W10.e30.c2ln").is_err(), "header must be an object");
        let d = decode(&token_with(&fresh_key(), Some("k"), Algorithm::ES256)).unwrap();
        assert_eq!((d.alg(), d.kid()), (Some("ES256"), Some("k")));
    }
}
