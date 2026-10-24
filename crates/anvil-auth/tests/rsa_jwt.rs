//! RSA JWT signing and JWT-SVID verification through Anvil's own APIs.
//!
//! jsonwebtoken runs on its AWS-LC backend, which accepts RSA keys of
//! 2048–8192 bits for both signing and verification. These tests pin that
//! window and the key formats Anvil accepts (PKCS#1 and PKCS#8 PEM).
//!
//! Fixtures (`tests/fixtures/rsa-test-*`) are throwaway keys made for these
//! tests with OpenSSL and used nowhere else:
//!
//! ```text
//! openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out rsa-test-2048.pkcs8.pem
//! openssl pkey -in rsa-test-2048.pkcs8.pem -traditional -out rsa-test-2048.pkcs1.pem
//! openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:1024 -out rsa-test-1024.pkcs8.pem
//! ```
//!
//! The `*.public.jwk.json` files hold each key's modulus and exponent.
//! `rsa-test-1024.rs256.jwt` was signed offline with the 1024-bit key
//! (header `{"typ":"JWT","alg":"RS256","kid":"rsa-1024"}`), because AWS-LC
//! refuses to sign with it; its signature was checked with `openssl dgst
//! -verify` against that key.

use anvil_auth::{jwt, jwt_svid};
use anvil_domain::auth::{JwtAlgorithm, JwtClaims};
use chrono::DateTime;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde_json::{Value, json};

const RSA_2048_PKCS8: &str = include_str!("fixtures/rsa-test-2048.pkcs8.pem");
const RSA_2048_PKCS1: &str = include_str!("fixtures/rsa-test-2048.pkcs1.pem");
const RSA_2048_JWK: &str = include_str!("fixtures/rsa-test-2048.public.jwk.json");
const RSA_1024_PKCS8: &str = include_str!("fixtures/rsa-test-1024.pkcs8.pem");
const RSA_1024_JWK: &str = include_str!("fixtures/rsa-test-1024.public.jwk.json");
const RSA_1024_RS256_TOKEN: &str = include_str!("fixtures/rsa-test-1024.rs256.jwt");

fn jwk(public: &str, kid: &str, alg: &str) -> Value {
    let mut key: Value = serde_json::from_str(public).unwrap();
    key["kid"] = kid.into();
    key["alg"] = alg.into();
    key["use"] = "sig".into();
    key
}

fn bundle(keys: Value) -> Vec<u8> {
    serde_json::to_vec(&json!({ "keys": keys })).unwrap()
}

fn claims() -> JwtClaims {
    JwtClaims { sub: Some("spiffe://anvil.test/w".into()), expires_in_secs: Some(300), ..Default::default() }
}

#[test]
fn rs256_signs_with_pkcs1_and_pkcs8_keys_and_verifies_against_the_rsa_jwk() {
    let now = DateTime::from_timestamp(1_800_000_000, 0).unwrap();
    let jwks = bundle(json!([jwk(RSA_2048_JWK, "rsa-2048", "RS256")]));
    let public: Value = serde_json::from_str(RSA_2048_JWK).unwrap();
    let decoding = DecodingKey::from_rsa_components(public["n"].as_str().unwrap(), public["e"].as_str().unwrap()).unwrap();
    for (form, pem) in [("PKCS#8", RSA_2048_PKCS8), ("PKCS#1", RSA_2048_PKCS1)] {
        let token = jwt::sign(JwtAlgorithm::RS256, pem, &claims(), &Value::Null, Some("rsa-2048"), now)
            .unwrap_or_else(|e| panic!("{form} RSA key must sign RS256: {e}"));
        assert_eq!(jwt_svid::verify_signature(&token, &jwks).unwrap(), "rsa-2048", "{form}");
        // Independent check with jsonwebtoken directly.
        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_exp = false;
        validation.required_spec_claims.clear();
        jsonwebtoken::decode::<Value>(&token, &decoding, &validation).unwrap();
    }
}

#[test]
fn ps256_jwt_svid_verifies_against_the_rsa_jwk_and_another_key_does_not() {
    let mut header = Header::new(Algorithm::PS256);
    header.kid = Some("rsa-2048".into());
    let token = jsonwebtoken::encode(
        &header,
        &json!({"sub": "spiffe://anvil.test/w", "exp": 4_000_000_000i64}),
        &EncodingKey::from_rsa_pem(RSA_2048_PKCS8.as_bytes()).unwrap(),
    )
    .unwrap();
    assert_eq!(jwt_svid::verify_signature(&token, &bundle(json!([jwk(RSA_2048_JWK, "rsa-2048", "PS256")]))).unwrap(), "rsa-2048");
    // A different (here also below-floor) RSA key under the same kid: no match.
    let wrong = jwk(RSA_1024_JWK, "rsa-2048", "PS256");
    assert!(jwt_svid::verify_signature(&token, &bundle(json!([wrong]))).unwrap_err().contains("does not verify"));
}

#[test]
fn rsa_keys_below_2048_bits_neither_sign_nor_verify() {
    let now = DateTime::from_timestamp(1_800_000_000, 0).unwrap();
    // Signing: the PEM parses, but AWS-LC refuses the key when signing.
    let err = jwt::sign(JwtAlgorithm::RS256, RSA_1024_PKCS8, &claims(), &Value::Null, None, now).unwrap_err();
    assert!(err.to_string().contains("JWT signing failed"), "unexpected error: {err}");
    // Verification: a genuine RS256 signature from the 1024-bit key is refused.
    let refused =
        jwt_svid::verify_signature(RSA_1024_RS256_TOKEN.trim(), &bundle(json!([jwk(RSA_1024_JWK, "rsa-1024", "RS256")]))).unwrap_err();
    assert!(refused.contains("does not verify"), "unexpected error: {refused}");
}
