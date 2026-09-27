//! Multi-auth composition: each profile applies to the request as it will be
//! sent after the earlier profiles' changes, so cookie credentials accumulate
//! and an HMAC signature covers the query and body actually sent. Orders that
//! would lose a credential or break a signature are refused before anything
//! is sent.

use anvil_auth::digest::{self, DigestAlg};
use anvil_auth::hmac_sig::{mac, signing_string};
use anvil_auth::{Applied, HmacParams, ResolvedAuth, SignableRequest};
use anvil_domain::auth::{BodyDigestHeader, HmacAlgorithm, HmacProfile, KeyLocation, WssePasswordType};
use base64::Engine;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const ENVELOPE: &str = r#"<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><m:Ping xmlns:m="urn:x">1</m:Ping></soap:Body></soap:Envelope>"#;

fn request(method: &str, query: &str, headers: &[(&str, &str)], body: &[u8]) -> SignableRequest {
    SignableRequest {
        method: method.into(),
        scheme: "https".into(),
        authority: "api.example.com".into(),
        raw_path: "/api/orders".into(),
        raw_query: query.into(),
        headers: headers.iter().map(|(n, v)| (n.to_string(), v.to_string())).collect(),
        body: body.to_vec(),
    }
}

fn key(name: &str, value: &str, location: KeyLocation) -> ResolvedAuth {
    ResolvedAuth::ApiKey { name: name.into(), value: Zeroizing::new(value.into()), location }
}

fn hmac_params(digest_header: BodyDigestHeader) -> HmacParams {
    HmacParams {
        profile: HmacProfile::FerrumV2,
        username: "hmacuser".into(),
        secret: Zeroizing::new("my-hmac-secret-key-at-least-32-bytes".into()),
        algorithm: HmacAlgorithm::HmacSha256,
        digest_header,
        namespace: "ferrum".into(),
        allow_unsafe_legacy: false,
    }
}

fn hmac() -> ResolvedAuth {
    ResolvedAuth::Hmac(hmac_params(BodyDigestHeader::ContentDigest))
}

fn wsse() -> ResolvedAuth {
    ResolvedAuth::Wsse {
        username: "alice".into(),
        password: Zeroizing::new("secret123".into()),
        password_type: WssePasswordType::PasswordText,
        timestamp_ttl_secs: None,
        saml_assertion: None,
    }
}

fn apply(auth: ResolvedAuth, req: &SignableRequest) -> Result<Applied, String> {
    anvil_auth::apply(&auth, req, chrono::Utc::now()).map_err(|e| e.to_string())
}

fn multi(parts: Vec<ResolvedAuth>, req: &SignableRequest) -> Result<Applied, String> {
    apply(ResolvedAuth::Multi(parts), req)
}

fn header<'a>(a: &'a Applied, name: &str) -> Option<&'a str> {
    a.set_headers.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
}

fn fact<'a>(a: &'a Applied, name: &str) -> &'a str {
    a.facts.iter().find(|(n, _)| n == name).map(|(_, v)| v.as_str()).unwrap_or_else(|| panic!("no fact {name}"))
}

/// Rebuild the canonical string from the Date, digest and nonce `apply`
/// returned, over the authority, query and body of the request as sent, and
/// check both the recorded signing-string hash and the signature against it.
fn assert_signed_over(a: &Applied, authority: &str, raw_query: &str, body: &[u8]) {
    let p = hmac_params(BodyDigestHeader::ContentDigest);
    let date = header(a, "Date").expect("Date header");
    let digest_value = header(a, "Content-Digest").expect("Content-Digest header");
    assert_eq!(digest_value, digest::header(BodyDigestHeader::ContentDigest, DigestAlg::Sha256, body).1, "digest covers the body sent");
    let ss = signing_string(
        p.profile,
        "ferrum",
        &p.username,
        authority,
        "POST",
        "/api/orders",
        raw_query,
        date,
        digest_value,
        Some(fact(a, "hmac.nonce")),
    );
    assert_eq!(fact(a, "hmac.signing_string_sha256"), hex::encode(Sha256::digest(ss.as_bytes())), "signed query {raw_query:?}");
    let sig = base64::engine::general_purpose::STANDARD.encode(mac(p.algorithm, p.secret.as_bytes(), ss.as_bytes()));
    let auth = header(a, "Authorization").expect("Authorization header");
    assert!(auth.contains(&format!("signature=\"{sig}\"")), "{auth}");
}

// ------------------------------------------------------------ cookies

#[test]
fn cookie_keys_from_every_profile_accumulate() {
    let req = request("GET", "", &[], b"");
    let a = multi(vec![key("first", "one", KeyLocation::Cookie), key("second", "two", KeyLocation::Cookie)], &req).unwrap();
    assert_eq!(a.set_headers, vec![("Cookie".to_string(), "first=one; second=two".to_string())]);
    assert!(a.secrets.contains(&"one".to_string()) && a.secrets.contains(&"two".to_string()));
}

#[test]
fn cookie_keys_follow_every_cookie_the_request_already_has() {
    // The generated Cookie header replaces all of the request's Cookie
    // headers, so every one of them is carried over.
    let req = request("GET", "", &[("Cookie", "sid=abc"), ("cookie", " theme=dark ;")], b"");
    let a = multi(vec![key("first", "one", KeyLocation::Cookie), key("second", "two", KeyLocation::Cookie)], &req).unwrap();
    assert_eq!(header(&a, "cookie"), Some("sid=abc; theme=dark; first=one; second=two"));
    let single = apply(key("first", "one", KeyLocation::Cookie), &req).unwrap();
    assert_eq!(header(&single, "cookie"), Some("sid=abc; theme=dark; first=one"));
}

#[test]
fn a_profile_cookie_replaces_a_request_cookie_of_the_same_name() {
    let req = request("GET", "", &[("Cookie", "first=stale; sid=abc")], b"");
    let a = multi(vec![key("first", "one", KeyLocation::Cookie), key("second", "two", KeyLocation::Cookie)], &req).unwrap();
    assert_eq!(header(&a, "cookie"), Some("sid=abc; first=one; second=two"));
    // Cookie names are case-sensitive: `First` is another cookie.
    let req = request("GET", "", &[("Cookie", "First=kept")], b"");
    let a = apply(key("first", "one", KeyLocation::Cookie), &req).unwrap();
    assert_eq!(header(&a, "cookie"), Some("First=kept; first=one"));
}

#[test]
fn two_profiles_sending_the_same_cookie_are_refused() {
    let req = request("GET", "", &[], b"");
    let err = multi(vec![key("session", "one", KeyLocation::Cookie), key("session", "two", KeyLocation::Cookie)], &req).unwrap_err();
    assert!(err.contains("cookie 'session'"), "{err}");
}

#[test]
fn a_cookie_header_key_and_a_cookie_key_are_refused_in_either_order() {
    let req = request("GET", "", &[], b"");
    for parts in [
        vec![key("Cookie", "raw=1", KeyLocation::Header), key("first", "one", KeyLocation::Cookie)],
        vec![key("first", "one", KeyLocation::Cookie), key("Cookie", "raw=1", KeyLocation::Header)],
    ] {
        let err = multi(parts, &req).unwrap_err();
        assert!(err.contains("Cookie header"), "{err}");
    }
}

// ------------------------------------------------------------ query + HMAC

#[test]
fn hmac_after_a_query_key_signs_the_query_as_sent() {
    let req = request("POST", "", &[], br#"{"ping":1}"#);
    let a = multi(vec![key("key", "audit-only-key", KeyLocation::Query), hmac()], &req).unwrap();
    assert_eq!(a.append_query, vec![("key".to_string(), "audit-only-key".to_string())]);
    assert_signed_over(&a, "api.example.com", "key=audit-only-key", br#"{"ping":1}"#);
}

#[test]
fn hmac_signs_the_existing_query_with_the_encoded_key_appended() {
    let req = request("POST", "a=1&b=x%2Fy", &[], b"");
    let a = multi(vec![key("api key", "v/1 &2", KeyLocation::Query), hmac()], &req).unwrap();
    assert_signed_over(&a, "api.example.com", "a=1&b=x%2Fy&api%20key=v%2F1%20%262", b"");
}

#[test]
fn hmac_as_a_middle_profile_signs_what_came_before_and_allows_unsigned_headers_after() {
    let req = request("POST", "", &[("Cookie", "sid=abc")], b"{}");
    let parts = vec![
        key("key", "audit-only-key", KeyLocation::Query),
        hmac(),
        key("session", "s3", KeyLocation::Cookie),
        key("X-Tenant", "blue", KeyLocation::Header),
    ];
    let a = multi(parts, &req).unwrap();
    assert_signed_over(&a, "api.example.com", "key=audit-only-key", b"{}");
    assert_eq!(header(&a, "cookie"), Some("sid=abc; session=s3"));
    assert_eq!(header(&a, "x-tenant"), Some("blue"));
}

#[test]
fn hmac_signs_the_authority_an_earlier_host_header_sets() {
    let req = request("POST", "", &[], b"");
    let a = multi(vec![key("Host", "gw.example.com", KeyLocation::Header), hmac()], &req).unwrap();
    assert_signed_over(&a, "gw.example.com", "", b"");
}

#[test]
fn changing_what_hmac_signed_after_it_is_refused() {
    let req = request("POST", "", &[], ENVELOPE.as_bytes());
    let cases = [
        (key("key", "audit-only-key", KeyLocation::Query), "query"),
        (wsse(), "body"),
        (key("Host", "gw.example.com", KeyLocation::Header), "Host header"),
        (key("Date", "Thu, 01 Jan 2026 00:00:00 GMT", KeyLocation::Header), "Date header"),
        (key("Digest", "sha-256=abc", KeyLocation::Header), "Digest header"),
    ];
    for (later, what) in cases {
        let err = multi(vec![hmac(), later], &req).unwrap_err();
        assert!(err.contains(&format!("change the {what} after hmac")), "{what}: {err}");
    }
    // A Content-Digest after a legacy-Digest signature would send both.
    let legacy = ResolvedAuth::Hmac(hmac_params(BodyDigestHeader::LegacyDigest));
    let err = multi(vec![legacy, key("Content-Digest", "sha-256=:abc:", KeyLocation::Header)], &req).unwrap_err();
    assert!(err.contains("Content-Digest header"), "{err}");
}

#[test]
fn a_digest_header_set_before_hmac_is_refused_by_the_signer() {
    let req = request("POST", "", &[], b"{}");
    let err = multi(vec![key("Content-Digest", "sha-256=:abc:", KeyLocation::Header), hmac()], &req).unwrap_err();
    assert!(err.contains("Digest"), "{err}");
}

// ------------------------------------------------------------ WS-Security + HMAC

#[test]
fn hmac_after_ws_security_digests_the_envelope_it_inserted() {
    let req = request("POST", "", &[], ENVELOPE.as_bytes());
    let a = multi(vec![wsse(), hmac()], &req).unwrap();
    let body = a.body.clone().expect("WS-Security rewrites the body");
    assert!(String::from_utf8_lossy(&body).contains("<wsse:Security"));
    assert_signed_over(&a, "api.example.com", "", &body);
}

// ------------------------------------------------------------ other conflicts

#[test]
fn two_profiles_setting_the_same_header_are_refused() {
    let req = request("GET", "", &[], b"");
    let basic = ResolvedAuth::Basic { username: "u".into(), password: Zeroizing::new("p".into()) };
    let bearer = ResolvedAuth::Bearer { token: Zeroizing::new("t".into()), prefix: "Bearer".into() };
    let err = multi(vec![basic, bearer], &req).unwrap_err();
    assert!(err.contains("Authorization header"), "{err}");
    let err = multi(vec![key("X-Api-Key", "a", KeyLocation::Header), key("x-api-key", "b", KeyLocation::Header)], &req).unwrap_err();
    assert!(err.contains("header"), "{err}");
}

#[test]
fn conflicts_inside_nested_multi_sets_are_refused() {
    let req = request("GET", "", &[], b"");
    let inner = ResolvedAuth::Multi(vec![key("session", "two", KeyLocation::Cookie)]);
    let err = multi(vec![key("session", "one", KeyLocation::Cookie), inner], &req).unwrap_err();
    assert!(err.contains("cookie 'session'"), "{err}");
    let inner = ResolvedAuth::Multi(vec![key("first", "one", KeyLocation::Cookie)]);
    let a = multi(vec![inner, key("second", "two", KeyLocation::Cookie)], &req).unwrap();
    assert_eq!(header(&a, "cookie"), Some("first=one; second=two"));
}

#[test]
fn two_profiles_adding_the_same_query_parameter_are_refused() {
    let req = request("GET", "", &[], b"");
    let err = multi(vec![key("key", "one", KeyLocation::Query), key("key", "two", KeyLocation::Query)], &req).unwrap_err();
    assert!(err.contains("query parameter 'key'"), "{err}");
    let a = multi(vec![key("key", "one", KeyLocation::Query), key("other", "two", KeyLocation::Query)], &req).unwrap();
    assert_eq!(a.append_query.len(), 2);
}
