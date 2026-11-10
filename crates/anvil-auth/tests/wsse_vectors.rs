//! WS-Security UsernameToken PasswordDigest against the audited Ferrum Edge
//! vectors (fixtures/auth-vectors/soap-usernametoken.json). The exclusive
//! C14N vector there is not exercised: Anvil does not produce XML signatures.

use anvil_auth::wsse::{password_digest, security_header};
use anvil_domain::auth::WssePasswordType;
use base64::Engine;
use chrono::{DateTime, Utc};

fn vectors() -> Vec<serde_json::Value> {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/auth-vectors/soap-usernametoken.json");
    let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
    v["vectors"].as_array().unwrap().clone()
}

fn s<'a>(v: &'a serde_json::Value, key: &str) -> &'a str {
    v[key].as_str().unwrap_or_else(|| panic!("missing {key} in {v}"))
}

fn b64(text: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD.decode(text).unwrap()
}

#[test]
fn password_digests_match_audited_vectors() {
    let mut checked = 0;
    for vec in vectors() {
        let (i, e) = (&vec["inputs"], &vec["expected"]);
        let Some(nonce_hex) = i["nonce_bytes_hex"].as_str() else { continue };
        let nonce = hex::decode(nonce_hex).unwrap();
        assert_eq!(b64(s(i, "nonce_base64")), nonce, "{}", vec["name"]);
        let (created, password) = (s(i, "created"), s(i, "password"));
        // The digest input is the decoded nonce, the Created text and the password.
        let input = [&nonce[..], created.as_bytes(), password.as_bytes()].concat();
        assert_eq!(hex::encode(input), s(e, "digest_input_hex"), "{}", vec["name"]);
        assert_eq!(password_digest(&nonce, created, password), s(e, "password_digest_base64"), "{}", vec["name"]);
        checked += 1;
    }
    assert_eq!(checked, 5, "expected the five PasswordDigest vectors to be exercised");
}

#[test]
fn hashing_the_nonce_text_instead_of_its_bytes_gives_the_rejected_digest() {
    let vectors = vectors();
    let negative = vectors.iter().find(|v| v["inputs"]["wrong_nonce_input"].is_string()).expect("negative vector");
    let (i, e) = (&negative["inputs"], &negative["expected"]);
    assert_eq!(e["gateway_accepts"], serde_json::Value::Bool(false));
    let (nonce_text, created, password) = (s(i, "nonce_base64"), s(i, "created"), s(i, "password"));
    // The client bug the vector demonstrates gives exactly its digest...
    assert_eq!(password_digest(nonce_text.as_bytes(), created, password), s(e, "password_digest_base64"));
    // ...and Anvil, hashing the decoded nonce, does not.
    assert_ne!(password_digest(&b64(nonce_text), created, password), s(e, "password_digest_base64"));
}

#[test]
fn the_complete_envelope_carries_the_digest_of_its_inputs() {
    let vectors = vectors();
    let env = vectors.iter().find(|v| v["expected"]["envelope"].is_string()).expect("envelope vector");
    let i = &env["inputs"];
    let digest = password_digest(&b64(s(i, "nonce_base64")), s(i, "created"), s(i, "password"));
    let password_element = format!(">{digest}</wsse:Password>");
    assert!(s(&env["expected"], "envelope").contains(&password_element), "the envelope does not carry the computed digest");
}

/// The header Anvil writes for a whole-second Created (it formats Created
/// with second precision) carries the digest of the matching vector.
#[test]
fn generated_security_header_matches_the_whole_second_vector() {
    let vectors = vectors();
    let vec = vectors
        .iter()
        .find(|v| v["inputs"]["created"] == "2026-01-01T00:00:00Z" && v["inputs"]["nonce_base64"] == "dGVzdC1ub25jZS0xMjM0NQ==");
    let vec = vec.expect("PasswordDigest V2");
    let i = &vec["inputs"];
    let now: DateTime<Utc> = s(i, "created").parse().unwrap();
    let nonce = hex::decode(s(i, "nonce_bytes_hex")).unwrap();
    let header = security_header(s(i, "username"), s(i, "password"), WssePasswordType::PasswordDigest, None, None, now, &nonce);
    assert!(
        header.contains(&format!(">{}</wsse:Password>", s(&vec["expected"], "password_digest_base64"))),
        "the header does not carry the vector's digest"
    );
    assert!(header.contains(&format!(">{}</wsse:Nonce>", s(i, "nonce_base64"))), "the header does not carry the nonce");
    assert!(header.contains(&format!("<wsu:Created>{}</wsu:Created>", s(i, "created"))), "the header does not carry Created");
    assert!(header.contains(&format!("<wsse:Username>{}</wsse:Username>", s(i, "username"))), "the header does not carry the username");
}
