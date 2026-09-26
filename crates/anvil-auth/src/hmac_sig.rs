//! Ferrum Edge HMAC request signing (`ferrum-hmac-v2`; legacy v1 opt-in).
//!
//! Canonical signing string (v0.9.5 `src/plugins/hmac_auth.rs:1902-1943`):
//! `profile \n namespace \n username \n authority \n METHOD \n raw_path \n
//! raw_query \n Date \n digest-header-value \n nonce` (v1 omits the nonce).
//! The digest covers the exact final body bytes. Each call generates a fresh
//! 128-bit nonce, so a signature is never reused across sends.

use crate::digest::{self, DigestAlg};
use crate::{AuthError, HmacParams, SignableRequest};
use anvil_domain::auth::{HmacAlgorithm, HmacProfile};
use base64::Engine;
use chrono::{DateTime, Utc};
use hmac::{KeyInit, Mac};

pub struct Signed {
    pub headers: Vec<(String, String)>,
    pub signing_string: String,
    pub signature: String,
    pub nonce: Option<String>,
}

pub fn profile_name(p: HmacProfile) -> &'static str {
    match p {
        HmacProfile::FerrumV2 => "ferrum-hmac-v2",
        HmacProfile::FerrumV1Legacy => "ferrum-hmac-v1",
    }
}

fn alg_name(a: HmacAlgorithm) -> &'static str {
    match a {
        HmacAlgorithm::HmacSha256 => "hmac-sha256",
        HmacAlgorithm::HmacSha384 => "hmac-sha384",
        HmacAlgorithm::HmacSha512 => "hmac-sha512",
    }
}

/// RFC 9110 quoted-string escaping for auth-param values.
pub fn quote(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

pub fn fresh_nonce() -> String {
    let mut b = [0u8; 16];
    rand::fill(&mut b);
    hex::encode(b)
}

pub fn mac(alg: HmacAlgorithm, secret: &[u8], data: &[u8]) -> Vec<u8> {
    match alg {
        HmacAlgorithm::HmacSha256 => {
            let mut m = hmac::Hmac::<sha2::Sha256>::new_from_slice(secret).expect("hmac accepts any key length");
            m.update(data);
            m.finalize().into_bytes().to_vec()
        }
        HmacAlgorithm::HmacSha384 => {
            let mut m = hmac::Hmac::<sha2::Sha384>::new_from_slice(secret).expect("hmac accepts any key length");
            m.update(data);
            m.finalize().into_bytes().to_vec()
        }
        HmacAlgorithm::HmacSha512 => {
            let mut m = hmac::Hmac::<sha2::Sha512>::new_from_slice(secret).expect("hmac accepts any key length");
            m.update(data);
            m.finalize().into_bytes().to_vec()
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub fn signing_string(
    profile: HmacProfile,
    namespace: &str,
    username: &str,
    authority: &str,
    method: &str,
    raw_path: &str,
    raw_query: &str,
    date: &str,
    digest_value: &str,
    nonce: Option<&str>,
) -> String {
    let mut parts = vec![profile_name(profile), namespace, username, authority, method, raw_path, raw_query, date, digest_value];
    if let Some(n) = nonce {
        parts.push(n);
    }
    parts.join("\n")
}

/// Sign one send. `now` supplies the Date header.
pub fn sign(p: &HmacParams, req: &SignableRequest, now: DateTime<Utc>) -> Result<Signed, AuthError> {
    sign_with(p, req, &httpdate::fmt_http_date(now.into()), fresh_nonce())
}

pub fn sign_with(p: &HmacParams, req: &SignableRequest, date: &str, nonce: String) -> Result<Signed, AuthError> {
    if p.profile == HmacProfile::FerrumV1Legacy && !p.allow_unsafe_legacy {
        return Err(AuthError::Invalid(
            "the legacy ferrum-hmac-v1 profile is replayable and is disabled; enable the unsafe legacy option explicitly or use ferrum-hmac-v2".into(),
        ));
    }
    if p.username.trim().is_empty() {
        return Err(AuthError::Invalid("HMAC username is empty".into()));
    }
    if p.secret.is_empty() {
        return Err(AuthError::Invalid("HMAC secret is empty".into()));
    }
    if req.has_header("digest") || req.has_header("content-digest") {
        return Err(AuthError::Invalid(
            "HMAC signing computes the body digest itself; remove the manual Digest/Content-Digest header (the gateway rejects requests carrying both or a mismatched digest)".into(),
        ));
    }
    let method = req.method.to_ascii_uppercase();
    let (dname, dvalue) = digest::header(p.digest_header, DigestAlg::Sha256, &req.body);
    let namespace = if p.namespace.is_empty() { "ferrum" } else { p.namespace.as_str() };
    let nonce_opt = match p.profile {
        HmacProfile::FerrumV2 => Some(nonce.as_str()),
        HmacProfile::FerrumV1Legacy => None,
    };
    let ss =
        signing_string(p.profile, namespace, &p.username, &req.authority, &method, &req.raw_path, &req.raw_query, date, &dvalue, nonce_opt);
    let sig = base64::engine::general_purpose::STANDARD.encode(mac(p.algorithm, p.secret.as_bytes(), ss.as_bytes()));
    let mut auth = format!("hmac username=\"{}\", algorithm=\"{}\"", quote(&p.username), alg_name(p.algorithm));
    if let Some(n) = nonce_opt {
        auth.push_str(&format!(", nonce=\"{n}\""));
    }
    auth.push_str(&format!(", signature=\"{sig}\""));
    Ok(Signed {
        headers: vec![("Authorization".into(), auth), ("Date".into(), date.to_string()), (dname.to_string(), dvalue)],
        signing_string: ss,
        signature: sig,
        nonce: nonce_opt.map(|s| s.to_string()),
    })
}
