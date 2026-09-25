//! Credential generation for Anvil.
//!
//! Auth is applied to the *final* serialized request (after interpolation,
//! content-type inference and body serialization) and is re-applied for
//! every actual send, so HMAC nonces, DPoP proofs and JWT time claims are
//! fresh per attempt — including under load. Nothing here performs network
//! I/O except OAuth token acquisition through the [`oauth::TokenHttp`] trait,
//! which the engine implements with the same instrumented transport.

pub mod digest;
pub mod dpop;
pub mod hmac_sig;
pub mod jwt;
pub mod oauth;
pub mod wsse;

use anvil_domain::auth::{BodyDigestHeader, HmacAlgorithm, HmacProfile, JwtAlgorithm, JwtClaims, KeyLocation, WssePasswordType};
use base64::Engine;
use chrono::{DateTime, Utc};
use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum AuthError {
    #[error("{0}")]
    Invalid(String),
    #[error("credential acquisition failed: {0}")]
    Acquisition(String),
    #[error("{0}")]
    Unsupported(String),
}

/// The request exactly as it will be written (after serialization).
#[derive(Debug, Clone)]
pub struct SignableRequest {
    pub method: String,
    pub scheme: String,
    /// `Host` / `:authority` value as sent.
    pub authority: String,
    /// Raw path as sent (no normalization).
    pub raw_path: String,
    /// Raw query as sent, without `?`.
    pub raw_query: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl SignableRequest {
    pub fn has_header(&self, name: &str) -> bool {
        self.headers.iter().any(|(n, _)| n.eq_ignore_ascii_case(name))
    }
}

/// Auth with all secret references already resolved by the engine.
/// Built once per send; variant sizes are irrelevant at that rate.
#[derive(Clone)]
#[allow(clippy::large_enum_variant)]
pub enum ResolvedAuth {
    None,
    ApiKey {
        name: String,
        value: Zeroizing<String>,
        location: KeyLocation,
    },
    Basic {
        username: String,
        password: Zeroizing<String>,
    },
    Bearer {
        token: Zeroizing<String>,
        prefix: String,
    },
    Jwt {
        algorithm: JwtAlgorithm,
        signing_key: Zeroizing<String>,
        claims: JwtClaims,
        extra_claims: serde_json::Value,
        kid: Option<String>,
        header_name: String,
        prefix: String,
    },
    /// OAuth2: the engine acquires/refreshes the token first and passes it here.
    OAuth2 {
        access_token: Zeroizing<String>,
        token_type: String,
    },
    Hmac(HmacParams),
    Dpop {
        access_token: Zeroizing<String>,
        private_key_pem: Zeroizing<String>,
        dpop_scheme: bool,
        nonce: Option<String>,
    },
    Wsse {
        username: String,
        password: Zeroizing<String>,
        password_type: WssePasswordType,
        timestamp_ttl_secs: Option<u32>,
        saml_assertion: Option<Zeroizing<String>>,
    },
    Multi(Vec<ResolvedAuth>),
}

impl std::fmt::Debug for ResolvedAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ResolvedAuth({})", self.label())
    }
}

#[derive(Clone)]
pub struct HmacParams {
    pub profile: HmacProfile,
    pub username: String,
    pub secret: Zeroizing<String>,
    pub algorithm: HmacAlgorithm,
    pub digest_header: BodyDigestHeader,
    pub namespace: String,
    pub allow_unsafe_legacy: bool,
}

/// Header/query/body changes produced by applying auth to one send.
#[derive(Debug, Default, Clone)]
pub struct Applied {
    /// Headers to set (replacing any existing header of the same name).
    pub set_headers: Vec<(String, String)>,
    pub append_query: Vec<(String, String)>,
    /// Replacement body (WS-Security header insertion).
    pub body: Option<Vec<u8>>,
    /// Human label for evidence (never contains secret material).
    pub label: String,
    /// Secret values used, for exact-value redaction of evidence and logs.
    pub secrets: Vec<String>,
    /// Non-secret facts about the generated credential (nonce, jti, exp...).
    pub facts: Vec<(String, String)>,
}

impl ResolvedAuth {
    pub fn label(&self) -> String {
        match self {
            ResolvedAuth::None => "none".into(),
            ResolvedAuth::ApiKey { name, location, .. } => format!("api_key({location:?} {name})"),
            ResolvedAuth::Basic { username, .. } => format!("basic(user {username})"),
            ResolvedAuth::Bearer { .. } => "bearer".into(),
            ResolvedAuth::Jwt { algorithm, .. } => format!("jwt({algorithm:?})"),
            ResolvedAuth::OAuth2 { .. } => "oauth2(access token)".into(),
            ResolvedAuth::Hmac(p) => format!("hmac({:?}, user {})", p.profile, p.username),
            ResolvedAuth::Dpop { .. } => "dpop(bound access token)".into(),
            ResolvedAuth::Wsse { username, password_type, .. } => format!("ws-security({password_type:?}, user {username})"),
            ResolvedAuth::Multi(v) => format!("multi[{}]", v.iter().map(|a| a.label()).collect::<Vec<_>>().join(", ")),
        }
    }
}

fn set(applied: &mut Applied, name: &str, value: String) {
    applied.set_headers.retain(|(n, _)| !n.eq_ignore_ascii_case(name));
    applied.set_headers.push((name.to_string(), value));
}

/// Apply auth for one actual send. Every call produces fresh nonces/proofs.
pub fn apply(auth: &ResolvedAuth, req: &SignableRequest, now: DateTime<Utc>) -> Result<Applied, AuthError> {
    let mut applied = Applied { label: auth.label(), ..Default::default() };
    apply_into(auth, req, now, &mut applied)?;
    // Conflicting Authorization from several profiles is an error, not a silent override.
    let mut seen = std::collections::HashSet::new();
    if let ResolvedAuth::Multi(parts) = auth {
        for p in parts {
            let mut tmp = Applied::default();
            apply_into(p, req, now, &mut tmp).ok();
            for (n, _) in tmp.set_headers {
                let key = n.to_ascii_lowercase();
                if key == "authorization" && !seen.insert(key) {
                    return Err(AuthError::Invalid(
                        "several auth profiles would each set the Authorization header; choose one profile for Authorization".into(),
                    ));
                }
            }
        }
    }
    Ok(applied)
}

fn apply_into(auth: &ResolvedAuth, req: &SignableRequest, now: DateTime<Utc>, out: &mut Applied) -> Result<(), AuthError> {
    match auth {
        ResolvedAuth::None => {}
        ResolvedAuth::ApiKey { name, value, location } => {
            if name.trim().is_empty() {
                return Err(AuthError::Invalid("API key name is empty".into()));
            }
            out.secrets.push(value.to_string());
            match location {
                KeyLocation::Header => set(out, name, value.to_string()),
                KeyLocation::Query => out.append_query.push((name.clone(), value.to_string())),
                KeyLocation::Cookie => {
                    let existing = req.headers.iter().find(|(n, _)| n.eq_ignore_ascii_case("cookie")).map(|(_, v)| v.clone());
                    let c = match existing {
                        Some(e) if !e.is_empty() => format!("{e}; {name}={}", value.as_str()),
                        _ => format!("{name}={}", value.as_str()),
                    };
                    set(out, "Cookie", c);
                }
            }
        }
        ResolvedAuth::Basic { username, password } => {
            if username.contains(':') {
                return Err(AuthError::Invalid("Basic auth user names cannot contain ':'".into()));
            }
            let token = base64::engine::general_purpose::STANDARD.encode(format!("{username}:{}", password.as_str()));
            out.secrets.push(password.to_string());
            out.secrets.push(token.clone());
            set(out, "Authorization", format!("Basic {token}"));
        }
        ResolvedAuth::Bearer { token, prefix } => {
            out.secrets.push(token.to_string());
            let v = if prefix.is_empty() { token.to_string() } else { format!("{prefix} {}", token.as_str()) };
            set(out, "Authorization", v);
        }
        ResolvedAuth::Jwt { algorithm, signing_key, claims, extra_claims, kid, header_name, prefix } => {
            let token = jwt::sign(*algorithm, signing_key, claims, extra_claims, kid.as_deref(), now)?;
            out.secrets.push(signing_key.to_string());
            out.secrets.push(token.clone());
            let v = if prefix.is_empty() { token } else { format!("{prefix} {token}") };
            set(out, header_name, v);
        }
        ResolvedAuth::OAuth2 { access_token, token_type } => {
            out.secrets.push(access_token.to_string());
            let scheme = if token_type.eq_ignore_ascii_case("bearer") || token_type.is_empty() { "Bearer" } else { token_type.as_str() };
            set(out, "Authorization", format!("{scheme} {}", access_token.as_str()));
        }
        ResolvedAuth::Hmac(p) => {
            let signed = hmac_sig::sign(p, req, now)?;
            out.secrets.push(p.secret.to_string());
            for (n, v) in signed.headers {
                set(out, &n, v);
            }
            out.facts.push(("hmac.nonce".into(), signed.nonce.unwrap_or_default()));
            out.facts.push((
                "hmac.signing_string_sha256".into(),
                hex::encode(sha2::Digest::finalize(<sha2::Sha256 as sha2::Digest>::new_with_prefix(signed.signing_string.as_bytes()))),
            ));
        }
        ResolvedAuth::Dpop { access_token, private_key_pem, dpop_scheme, nonce } => {
            let proof = dpop::proof(
                private_key_pem,
                &req.method,
                &dpop::htu(&req.scheme, &req.authority, &req.raw_path)?,
                Some(access_token),
                nonce.as_deref(),
                now,
            )?;
            out.secrets.push(access_token.to_string());
            out.secrets.push(private_key_pem.to_string());
            set(out, "Authorization", format!("{} {}", if *dpop_scheme { "DPoP" } else { "Bearer" }, access_token.as_str()));
            set(out, "DPoP", proof.jwt.clone());
            out.facts.push(("dpop.jti".into(), proof.jti));
            out.facts.push(("dpop.jkt".into(), proof.jkt));
            out.facts.push(("dpop.htu".into(), proof.htu));
        }
        ResolvedAuth::Wsse { username, password, password_type, timestamp_ttl_secs, saml_assertion } => {
            let body = wsse::insert_security(
                &req.body,
                username,
                password,
                *password_type,
                *timestamp_ttl_secs,
                saml_assertion.as_deref().map(|s| s.as_str()),
                now,
            )?;
            out.secrets.push(password.to_string());
            out.body = Some(body);
        }
        ResolvedAuth::Multi(parts) => {
            for p in parts {
                apply_into(p, req, now, out)?;
            }
        }
    }
    Ok(())
}
