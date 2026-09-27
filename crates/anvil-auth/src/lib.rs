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
pub mod jwt_svid;
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
    /// No usable token exists and the configured grant needs the user to
    /// sign in interactively (authorization code + PKCE). Never answered by
    /// silently switching to another grant.
    #[error("{0}")]
    InteractionRequired(String),
    /// The acquisition was abandoned: its execution was canceled, or a lock,
    /// a sign-out or a new sign-in superseded it while it was in flight.
    /// Nothing it obtained was cached or used.
    #[error("{0}")]
    Canceled(String),
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
    /// JWT-SVID: the engine fetches/reads and checks the token first and
    /// passes it here (empty until then).
    JwtSvid {
        token: Zeroizing<String>,
        header_name: String,
        prefix: String,
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
            ResolvedAuth::JwtSvid { header_name, .. } => format!("jwt_svid({header_name})"),
            ResolvedAuth::Multi(v) => format!("multi[{}]", v.iter().map(|a| a.label()).collect::<Vec<_>>().join(", ")),
        }
    }
}

fn set(applied: &mut Applied, name: &str, value: String) {
    applied.set_headers.retain(|(n, _)| !n.eq_ignore_ascii_case(name));
    applied.set_headers.push((name.to_string(), value));
}

const QUERY_COMPONENT: &percent_encoding::AsciiSet =
    &percent_encoding::NON_ALPHANUMERIC.remove(b'-').remove(b'_').remove(b'.').remove(b'~');

/// Percent-encode one query name or value: everything except ASCII letters,
/// digits and `-._~`. The engine re-exports this as
/// `prepare::encode_component` and uses it to append [`Applied::append_query`]
/// pairs to the request it sends, so a later multi-auth step signs the query
/// that is actually sent.
pub fn encode_query_component(s: &str) -> String {
    percent_encoding::utf8_percent_encode(s, QUERY_COMPONENT).to_string()
}

/// Apply auth for one actual send. Every call produces fresh nonces/proofs.
///
/// A [`ResolvedAuth::Multi`] applies its profiles in order (nested sets are
/// flattened), each against the request as it will be sent after the
/// earlier profiles' changes, so a signature covers the query, headers and
/// body the earlier profiles produced:
///
/// - Cookie API keys accumulate into one `Cookie` header, after the
///   request's own cookies, in profile order. A profile's cookie replaces a
///   cookie of the same name already in the request (as a header API key
///   replaces a header of the same name); two profiles sending the same
///   cookie name are refused.
/// - Two profiles setting the same header (other than cookie API keys
///   sharing `Cookie`), or adding the same query parameter, are refused.
/// - A profile that would change what an earlier signature covers is
///   refused rather than sent with a signature that cannot match: after
///   HMAC, the query, the body and the `Host`, `Date`, `Digest` and
///   `Content-Digest` headers; after DPoP, the `Host` header. Put such a
///   profile before the signing one.
/// - A set holds at most one HMAC profile and one DPoP profile.
/// - A cookie API key's name must be an RFC 6265 token and its value
///   cookie-octets, so it cannot add or change another cookie.
pub fn apply(auth: &ResolvedAuth, req: &SignableRequest, now: DateTime<Utc>) -> Result<Applied, AuthError> {
    let mut steps = Vec::new();
    flatten(auth, &mut steps);
    let hmac = steps.iter().filter(|s| matches!(s, ResolvedAuth::Hmac(_))).count();
    let dpop = steps.iter().filter(|s| matches!(s, ResolvedAuth::Dpop { .. })).count();
    for (kind, count) in [("HMAC", hmac), ("DPoP", dpop)] {
        if count > 1 {
            return Err(AuthError::Invalid(format!("a multi-auth set can hold one {kind} profile")));
        }
    }
    let mut applied = Applied { label: auth.label(), ..Default::default() };
    let mut effective = std::borrow::Cow::Borrowed(req);
    let mut composed = Composed::default();
    for (i, step) in steps.iter().enumerate() {
        let mut out = Applied::default();
        apply_step(step, &effective, now, &mut out)?;
        composed.check(step, &out)?;
        if i + 1 < steps.len() {
            absorb(effective.to_mut(), &out);
        }
        for (n, v) in out.set_headers {
            set(&mut applied, &n, v);
        }
        applied.append_query.extend(out.append_query);
        if out.body.is_some() {
            applied.body = out.body;
        }
        applied.secrets.extend(out.secrets);
        applied.facts.extend(out.facts);
    }
    Ok(applied)
}

fn flatten<'a>(auth: &'a ResolvedAuth, steps: &mut Vec<&'a ResolvedAuth>) {
    match auth {
        ResolvedAuth::None => {}
        ResolvedAuth::Multi(parts) => parts.iter().for_each(|p| flatten(p, steps)),
        other => steps.push(other),
    }
}

/// Make `req` the request as it will be sent after `step`'s changes, the
/// way the engine applies them.
fn absorb(req: &mut SignableRequest, step: &Applied) {
    for (n, v) in &step.set_headers {
        req.headers.retain(|(h, _)| !h.eq_ignore_ascii_case(n));
        req.headers.push((n.clone(), v.clone()));
        if n.eq_ignore_ascii_case("host") {
            req.authority = v.clone();
        }
    }
    for (k, v) in &step.append_query {
        let pair = format!("{}={}", encode_query_component(k), encode_query_component(v));
        req.raw_query = if req.raw_query.is_empty() { pair } else { format!("{}&{pair}", req.raw_query) };
    }
    if let Some(b) = &step.body {
        req.body = b.clone();
    }
}

/// What a request signature covers besides the method, scheme and path
/// (which no auth profile changes).
struct Signature {
    label: String,
    query: bool,
    body: bool,
    headers: &'static [&'static str],
}

/// What the profiles applied so far set, for refusing conflicts.
#[derive(Default)]
struct Composed {
    /// Lowercased header name, the profile that set it, and whether it is a
    /// cookie API key's `Cookie` (which later cookie keys extend).
    headers: Vec<(String, String, bool)>,
    cookies: Vec<(String, String)>,
    query: Vec<(String, String)>,
    signatures: Vec<Signature>,
}

impl Composed {
    fn check(&mut self, step: &ResolvedAuth, out: &Applied) -> Result<(), AuthError> {
        let label = step.label();
        let cookie_key = match step {
            ResolvedAuth::ApiKey { name, location: KeyLocation::Cookie, .. } => Some(name.as_str()),
            _ => None,
        };
        for sig in &self.signatures {
            let changed = if sig.query && !out.append_query.is_empty() {
                Some("query".to_string())
            } else if sig.body && out.body.is_some() {
                Some("body".to_string())
            } else {
                let signed = |n: &str| sig.headers.iter().any(|h| n.eq_ignore_ascii_case(h));
                out.set_headers.iter().find(|(n, _)| signed(n.as_str())).map(|(n, _)| format!("{n} header"))
            };
            if let Some(what) = changed {
                let signer = &sig.label;
                return Err(AuthError::Invalid(format!(
                    "the auth profile {label} would change the {what} after {signer} signed the request, so the signature would not match what is sent; put {label} before {signer} in the multi-auth list"
                )));
            }
        }
        for (n, _) in &out.set_headers {
            let key = n.to_ascii_lowercase();
            let merge = cookie_key.is_some() && key == "cookie";
            if let Some((_, owner, owner_merge)) = self.headers.iter().find(|(h, _, _)| *h == key) {
                if !(merge && *owner_merge) {
                    return Err(AuthError::Invalid(format!(
                        "several auth profiles would each set the {n} header ({owner} and {label}); choose one profile for {n}"
                    )));
                }
            } else {
                self.headers.push((key, label.clone(), merge));
            }
        }
        if let Some(name) = cookie_key {
            if let Some((_, owner)) = self.cookies.iter().find(|(c, _)| c == name) {
                return Err(AuthError::Invalid(format!(
                    "several auth profiles would each send the cookie '{name}' ({owner} and {label}); give each cookie credential its own name"
                )));
            }
            self.cookies.push((name.to_string(), label.clone()));
        }
        for (k, _) in &out.append_query {
            if let Some((_, owner)) = self.query.iter().find(|(q, _)| q == k) {
                return Err(AuthError::Invalid(format!(
                    "several auth profiles would each add the query parameter '{k}' ({owner} and {label}); give each query credential its own name"
                )));
            }
            self.query.push((k.clone(), label.clone()));
        }
        match step {
            ResolvedAuth::Hmac(_) => {
                self.signatures.push(Signature { label, query: true, body: true, headers: &["host", "date", "digest", "content-digest"] })
            }
            ResolvedAuth::Dpop { .. } => self.signatures.push(Signature { label, query: false, body: false, headers: &["host"] }),
            _ => {}
        }
        Ok(())
    }
}

/// RFC 7230 `tchar`, which an RFC 6265 cookie name is made of.
fn is_token_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// RFC 6265 `cookie-octet`: visible ASCII except `"`, `,`, `;` and `\`.
fn is_cookie_octet(b: u8) -> bool {
    matches!(b, 0x21 | 0x23..=0x2B | 0x2D..=0x3A | 0x3C..=0x5B | 0x5D..=0x7E)
}

/// The request's cookies with `name=value` added, replacing any cookie of
/// that name. Every `Cookie` header is read, since the result replaces them all.
/// A name that is not a token or a value that is not cookie-octets (optionally
/// in double quotes) is refused, so a credential cannot add or change another
/// cookie; the message names the cookie, never its value.
fn with_cookie(req: &SignableRequest, name: &str, value: &str) -> Result<String, AuthError> {
    if !name.bytes().all(is_token_char) {
        return Err(AuthError::Invalid(format!(
            "the cookie API key name {name:?} is not a valid cookie name; use letters, digits and !#$%&'*+-.^_`|~ only"
        )));
    }
    let inner = value.strip_prefix('"').and_then(|v| v.strip_suffix('"')).unwrap_or(value);
    if !inner.bytes().all(is_cookie_octet) {
        return Err(AuthError::Invalid(format!(
            "the cookie API key '{name}' has an invalid cookie value (no whitespace, control or non-ASCII characters, \", ; or \\)"
        )));
    }
    let added = format!("{name}={value}");
    let mut pairs: Vec<&str> = req
        .headers
        .iter()
        .filter(|(n, _)| n.eq_ignore_ascii_case("cookie"))
        .flat_map(|(_, v)| v.split(';'))
        .map(str::trim)
        .filter(|p| !p.is_empty() && p.split_once('=').map_or(*p, |(n, _)| n).trim() != name)
        .collect();
    pairs.push(&added);
    Ok(pairs.join("; "))
}

fn apply_step(auth: &ResolvedAuth, req: &SignableRequest, now: DateTime<Utc>, out: &mut Applied) -> Result<(), AuthError> {
    match auth {
        // `apply` flattens a multi-auth set into its profiles.
        ResolvedAuth::None | ResolvedAuth::Multi(_) => {}
        ResolvedAuth::ApiKey { name, value, location } => {
            if name.trim().is_empty() {
                return Err(AuthError::Invalid("API key name is empty".into()));
            }
            out.secrets.push(value.to_string());
            match location {
                KeyLocation::Header => set(out, name, value.to_string()),
                KeyLocation::Query => out.append_query.push((name.clone(), value.to_string())),
                KeyLocation::Cookie => set(out, "Cookie", with_cookie(req, name, value)?),
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
        ResolvedAuth::JwtSvid { token, header_name, prefix } => {
            if token.is_empty() {
                return Err(AuthError::Invalid("no JWT-SVID is available for this request".into()));
            }
            out.secrets.push(token.to_string());
            let v = if prefix.is_empty() { token.to_string() } else { format!("{prefix} {}", token.as_str()) };
            set(out, header_name, v);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::encode_query_component;

    #[test]
    fn query_components_encode_everything_but_unreserved_ascii() {
        let corpus = [
            ("aZ09-_.~", "aZ09-_.~"),
            (" ", "%20"),
            ("+", "%2B"),
            ("*", "%2A"),
            ("%", "%25"),
            ("/", "%2F"),
            ("a=b&c", "a%3Db%26c"),
            ("?#[]@!$'(),;:", "%3F%23%5B%5D%40%21%24%27%28%29%2C%3B%3A"),
            ("é", "%C3%A9"),
            ("日本", "%E6%97%A5%E6%9C%AC"),
            ("\u{1F600}", "%F0%9F%98%80"),
            ("\t\n\u{7f}", "%09%0A%7F"),
            ("", ""),
        ];
        for (raw, encoded) in corpus {
            assert_eq!(encode_query_component(raw), encoded, "{raw:?}");
        }
    }
}
