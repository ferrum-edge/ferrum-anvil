//! AUTH-018/021/022: byte-exact canonicalization against the audited
//! Ferrum Edge v0.9.5 vectors (fixtures/auth-vectors/hmac-v2.json).

use anvil_auth::hmac_sig::{mac, signing_string};
use anvil_auth::{HmacParams, SignableRequest};
use anvil_domain::auth::{BodyDigestHeader, HmacAlgorithm, HmacProfile};
use base64::Engine;
use zeroize::Zeroizing;

fn vectors(file: &str) -> serde_json::Value {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/auth-vectors").join(file);
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

fn alg(s: &str) -> HmacAlgorithm {
    match s {
        "hmac-sha384" => HmacAlgorithm::HmacSha384,
        "hmac-sha512" => HmacAlgorithm::HmacSha512,
        _ => HmacAlgorithm::HmacSha256,
    }
}

#[test]
fn signing_strings_and_signatures_match_audited_vectors() {
    let mut checked = 0;
    for file in ["hmac-v2.json", "hmac-v1.json"] {
        let v = vectors(file);
        for vec in v["vectors"].as_array().unwrap() {
            let i = &vec["inputs"];
            let e = &vec["expected"];
            let (Some(profile), Some(expected_ss)) = (i["profile"].as_str(), e["signing_string"].as_str()) else { continue };
            let prof = if profile == "ferrum-hmac-v2" { HmacProfile::FerrumV2 } else { HmacProfile::FerrumV1Legacy };
            let ss = signing_string(
                prof,
                i["namespace"].as_str().unwrap_or_default(),
                i["username"].as_str().or(i["username_decoded"].as_str()).unwrap_or_default(),
                i["authority"].as_str().unwrap_or_default(),
                i["method"].as_str().unwrap_or_default(),
                i["raw_path"].as_str().unwrap_or_default(),
                i["raw_query"].as_str().unwrap_or_default(),
                i["date"].as_str().unwrap_or_default(),
                i["digest_header_value"].as_str().unwrap_or_default(),
                i["nonce"].as_str(),
            );
            assert_eq!(ss, expected_ss, "{}", vec["name"]);
            let sig = base64::engine::general_purpose::STANDARD.encode(mac(
                alg(i["algorithm"].as_str().unwrap_or("hmac-sha256")),
                i["secret"].as_str().unwrap_or_default().as_bytes(),
                ss.as_bytes(),
            ));
            assert_eq!(sig, e["signature_base64"].as_str().unwrap(), "{}", vec["name"]);
            checked += 1;
        }
    }
    assert!(checked >= 8, "expected the audited vectors to be exercised, checked {checked}");
}

#[test]
fn quoted_username_is_escaped_in_header_but_not_in_signing_string() {
    let p = HmacParams {
        profile: HmacProfile::FerrumV2,
        username: "ops,\"blue\\team".into(),
        secret: Zeroizing::new("my-hmac-secret-key-at-least-32-bytes".into()),
        algorithm: HmacAlgorithm::HmacSha256,
        digest_header: BodyDigestHeader::LegacyDigest,
        namespace: "ferrum".into(),
        allow_unsafe_legacy: false,
    };
    let req = SignableRequest {
        method: "GET".into(),
        scheme: "https".into(),
        authority: "api.example.com".into(),
        raw_path: "/quoted".into(),
        raw_query: String::new(),
        headers: vec![],
        body: vec![],
    };
    let s = anvil_auth::hmac_sig::sign_with(&p, &req, "Fri, 25 Sep 2026 12:00:00 GMT", "0".repeat(32)).unwrap();
    let auth = &s.headers[0].1;
    assert!(auth.starts_with("hmac username=\"ops,\\\"blue\\\\team\""), "{auth}");
    assert!(s.signing_string.contains("\nops,\"blue\\team\n"));
}

#[test]
fn full_sign_produces_single_digest_and_fresh_nonces() {
    let p = HmacParams {
        profile: HmacProfile::FerrumV2,
        username: "hmacuser".into(),
        secret: Zeroizing::new("my-hmac-secret-key-at-least-32-bytes".into()),
        algorithm: HmacAlgorithm::HmacSha256,
        digest_header: BodyDigestHeader::ContentDigest,
        namespace: "ferrum".into(),
        allow_unsafe_legacy: false,
    };
    let req = SignableRequest {
        method: "post".into(),
        scheme: "https".into(),
        authority: "api.example.com".into(),
        raw_path: "/api/orders".into(),
        raw_query: String::new(),
        headers: vec![],
        body: br#"{"ping":1}"#.to_vec(),
    };
    let a = anvil_auth::hmac_sig::sign_with(&p, &req, "Fri, 25 Sep 2026 12:00:00 GMT", "00000000000000000000000000000f5c".into()).unwrap();
    assert_eq!(a.signature, "5LCS367Dfl/E2+3m5C91yY9sq3K+hjmIwbsH2XnQu2o=", "matches vector v2_post_ping_body_content_digest");
    let names: Vec<_> = a.headers.iter().map(|(n, _)| n.to_ascii_lowercase()).collect();
    assert!(names.contains(&"content-digest".to_string()) && !names.contains(&"digest".to_string()));
    // AUTH-020: every send gets a new nonce.
    let now = chrono::Utc::now();
    let s1 = anvil_auth::hmac_sig::sign(&p, &req, now).unwrap();
    let s2 = anvil_auth::hmac_sig::sign(&p, &req, now).unwrap();
    assert_ne!(s1.nonce, s2.nonce);
    assert_eq!(s1.nonce.as_ref().unwrap().len(), 32);
}

#[test]
fn auth_019_022_023_guards() {
    let mut p = HmacParams {
        profile: HmacProfile::FerrumV1Legacy,
        username: "u".into(),
        secret: Zeroizing::new("s".repeat(32)),
        algorithm: HmacAlgorithm::HmacSha256,
        digest_header: BodyDigestHeader::LegacyDigest,
        namespace: String::new(),
        allow_unsafe_legacy: false,
    };
    let mut req = SignableRequest {
        method: "GET".into(),
        scheme: "http".into(),
        authority: "h".into(),
        raw_path: "/".into(),
        raw_query: String::new(),
        headers: vec![],
        body: vec![],
    };
    assert!(anvil_auth::hmac_sig::sign(&p, &req, chrono::Utc::now()).is_err(), "legacy v1 stays disabled without explicit opt-in");
    p.profile = HmacProfile::FerrumV2;
    req.headers.push(("Digest".into(), "sha-256=abc".into()));
    req.headers.push(("Content-Digest".into(), "sha-256=:abc:".into()));
    assert!(anvil_auth::hmac_sig::sign(&p, &req, chrono::Utc::now()).is_err(), "manual/duplicate digest headers are refused, not guessed");
}
