//! OAuth 2.0 token acquisition for *target APIs* (not app login).
//!
//! * client credentials and refresh-token grants over the engine's transport;
//! * authorization code + PKCE (S256) with a per-attempt `state` and an exact
//!   loopback redirect binding (RFC 8252); callbacks that do not match are
//!   rejected without any token exchange;
//! * single-flight refresh: concurrent sends that find an expired token share
//!   one token request instead of stampeding the issuer;
//! * interactive grants (authorization code + PKCE, refresh token) never fall
//!   back to client credentials: without a usable access or refresh token the
//!   cache answers [`AuthError::InteractionRequired`] and nothing is sent
//!   until the user signs in.

use crate::AuthError;
use anvil_domain::auth::OAuthGrant;
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use parking_lot::Mutex;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use zeroize::Zeroizing;

pub type BoxFut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Minimal HTTP capability for token endpoints, implemented by the engine.
pub trait TokenHttp: Send + Sync {
    /// POST `application/x-www-form-urlencoded`; returns (status, body).
    fn post_form<'a>(
        &'a self,
        url: &'a str,
        form: Vec<(String, String)>,
        basic: Option<(String, String)>,
    ) -> BoxFut<'a, Result<(u16, Vec<u8>), String>>;
}

#[derive(Clone)]
pub struct OAuthResolved {
    /// The configured grant. Only `ClientCredentials` may obtain a token
    /// without user interaction.
    pub grant: OAuthGrant,
    pub token_url: String,
    pub client_id: String,
    pub client_secret: Zeroizing<String>,
    pub scope: String,
    pub audience: String,
    pub basic_client_auth: bool,
    pub refresh_skew_secs: i64,
}

#[derive(Clone)]
pub struct CachedToken {
    pub access_token: Zeroizing<String>,
    pub token_type: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub refresh_token: Option<Zeroizing<String>>,
}

impl CachedToken {
    pub fn usable(&self, now: DateTime<Utc>, skew: i64) -> bool {
        self.expires_at.map(|e| now + Duration::seconds(skew) < e).unwrap_or(true)
    }
}

#[derive(Default)]
pub struct TokenCache {
    entries: Mutex<HashMap<String, CachedToken>>,
    locks: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    /// Token endpoint requests performed (observability / storm tests).
    pub requests: std::sync::atomic::AtomicU64,
}

impl TokenCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&self, key: &str, t: CachedToken) {
        self.entries.lock().insert(key.to_string(), t);
    }

    pub fn get(&self, key: &str) -> Option<CachedToken> {
        self.entries.lock().get(key).cloned()
    }

    /// Forget one cached token (explicit sign-out, or a refresh token the
    /// issuer rejected). Returns whether an entry existed.
    pub fn remove(&self, key: &str) -> bool {
        self.entries.lock().remove(key).is_some()
    }

    pub fn clear(&self) {
        self.entries.lock().clear();
    }

    fn lock_for(&self, key: &str) -> Arc<tokio::sync::Mutex<()>> {
        self.locks.lock().entry(key.to_string()).or_insert_with(|| Arc::new(tokio::sync::Mutex::new(()))).clone()
    }

    /// Return a usable token, refreshing or acquiring at most once for
    /// concurrent callers.
    ///
    /// * `ClientCredentials`: refresh when a refresh token is cached (falling
    ///   back to a new client-credentials grant), otherwise acquire.
    /// * Interactive grants (`AuthorizationCodePkce`, `RefreshToken`): refresh
    ///   when a refresh token is cached; otherwise — or when the issuer
    ///   rejects the refresh token with `invalid_grant` — fail with
    ///   [`AuthError::InteractionRequired`]. No other grant is ever tried.
    pub async fn get_or_acquire(
        &self,
        key: &str,
        cfg: &OAuthResolved,
        http: &dyn TokenHttp,
        now: DateTime<Utc>,
    ) -> Result<CachedToken, AuthError> {
        if let Some(t) = self.get(key)
            && t.usable(now, cfg.refresh_skew_secs)
        {
            return Ok(t);
        }
        let lock = self.lock_for(key);
        let _g = lock.lock().await;
        // Another caller may have refreshed while we waited.
        if let Some(t) = self.get(key)
            && t.usable(Utc::now(), cfg.refresh_skew_secs)
        {
            return Ok(t);
        }
        let prior_refresh = self.get(key).and_then(|t| t.refresh_token.clone());
        let interactive = cfg.grant != OAuthGrant::ClientCredentials;
        if prior_refresh.is_none() && interactive {
            return Err(AuthError::InteractionRequired(interaction_message(cfg.grant, None)));
        }
        self.requests.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let t = match prior_refresh {
            Some(rt) => match request_token(cfg, refresh_form(&rt), http).await {
                // RFC 6749 §6: when no new refresh token is issued the old one stays valid.
                Ok(mut t) => {
                    if t.refresh_token.is_none() {
                        t.refresh_token = Some(rt);
                    }
                    t
                }
                Err(_) if !interactive => client_credentials(cfg, http).await?,
                Err(TokenFailure::Rejected { error, .. }) if error == "invalid_grant" => {
                    // Expired or revoked refresh token: forget it so the next
                    // send does not retry it, and ask for a new sign-in.
                    self.remove(key);
                    return Err(AuthError::InteractionRequired(interaction_message(cfg.grant, Some(&error))));
                }
                // Issuer unreachable or failing: keep the refresh token for a
                // later attempt and report the dependency failure.
                Err(other) => return Err(other.into()),
            },
            None => client_credentials(cfg, http).await?,
        };
        self.insert(key, t.clone());
        Ok(t)
    }
}

fn interaction_message(grant: OAuthGrant, refresh_error: Option<&str>) -> String {
    let flow = match grant {
        OAuthGrant::RefreshToken => "the refresh-token grant",
        _ => "the authorization-code + PKCE grant",
    };
    match refresh_error {
        Some(e) => format!(
            "The authorization server rejected the cached refresh token ({e}). This auth profile uses {flow}, so a new sign-in in the system browser is required."
        ),
        None => format!(
            "No access token or refresh token is available for this auth profile, which uses {flow}. Sign in through the system browser first; Anvil never substitutes the client-credentials grant."
        ),
    }
}

/// Token-endpoint outcome, typed so an issuer rejection can be told apart
/// from an unreachable issuer.
#[derive(Debug, Clone, PartialEq, Eq)]
enum TokenFailure {
    /// The token request did not complete (DNS, connect, TLS, timeout …).
    Transport(String),
    /// The issuer answered with an OAuth error response.
    Rejected { status: u16, error: String, description: String },
    /// The issuer answered with something that is not a token response.
    Malformed(String),
}

impl From<TokenFailure> for AuthError {
    fn from(f: TokenFailure) -> Self {
        match f {
            TokenFailure::Transport(m) | TokenFailure::Malformed(m) => AuthError::Acquisition(m),
            TokenFailure::Rejected { status, error, description } => {
                AuthError::Acquisition(format!("token endpoint returned HTTP {status}: {error} {description}").trim().to_string())
            }
        }
    }
}

/// Keep remote-supplied OAuth error codes printable and bounded before they
/// reach messages or logs.
pub fn sanitize_error_code(s: &str) -> String {
    let out: String = s.chars().filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.')).take(64).collect();
    if out.is_empty() { "unknown_error".into() } else { out }
}

fn sanitize_text(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).take(200).collect()
}

async fn request_token(cfg: &OAuthResolved, mut form: Vec<(String, String)>, http: &dyn TokenHttp) -> Result<CachedToken, TokenFailure> {
    let basic = client_auth(cfg, &mut form);
    let (status, body) = http.post_form(&cfg.token_url, form, basic).await.map_err(TokenFailure::Transport)?;
    parse_token_response(status, &body)
}

fn refresh_form(refresh_token: &str) -> Vec<(String, String)> {
    vec![("grant_type".to_string(), "refresh_token".to_string()), ("refresh_token".into(), refresh_token.to_string())]
}

fn parse_token_response(status: u16, body: &[u8]) -> Result<CachedToken, TokenFailure> {
    let v: serde_json::Value = serde_json::from_slice(body)
        .map_err(|_| TokenFailure::Malformed(format!("token endpoint returned HTTP {status} with a non-JSON body")))?;
    if !(200..300).contains(&status) {
        let error = v.get("error").and_then(|e| e.as_str()).map(sanitize_error_code).unwrap_or_else(|| "unknown_error".into());
        let description = v.get("error_description").and_then(|e| e.as_str()).map(sanitize_text).unwrap_or_default();
        return Err(TokenFailure::Rejected { status, error, description });
    }
    let access = v
        .get("access_token")
        .and_then(|t| t.as_str())
        .ok_or_else(|| TokenFailure::Malformed("token response has no access_token".into()))?;
    let expires_at = v.get("expires_in").and_then(|e| e.as_i64()).map(|s| Utc::now() + Duration::seconds(s));
    Ok(CachedToken {
        access_token: Zeroizing::new(access.to_string()),
        token_type: v.get("token_type").and_then(|t| t.as_str()).unwrap_or("Bearer").to_string(),
        expires_at,
        refresh_token: v.get("refresh_token").and_then(|t| t.as_str()).map(|s| Zeroizing::new(s.to_string())),
    })
}

fn client_auth(cfg: &OAuthResolved, form: &mut Vec<(String, String)>) -> Option<(String, String)> {
    if cfg.basic_client_auth && !cfg.client_secret.is_empty() {
        Some((cfg.client_id.clone(), cfg.client_secret.to_string()))
    } else {
        form.push(("client_id".into(), cfg.client_id.clone()));
        if !cfg.client_secret.is_empty() {
            form.push(("client_secret".into(), cfg.client_secret.to_string()));
        }
        None
    }
}

pub async fn client_credentials(cfg: &OAuthResolved, http: &dyn TokenHttp) -> Result<CachedToken, AuthError> {
    let mut form = vec![("grant_type".to_string(), "client_credentials".to_string())];
    if !cfg.scope.is_empty() {
        form.push(("scope".into(), cfg.scope.clone()));
    }
    if !cfg.audience.is_empty() {
        form.push(("audience".into(), cfg.audience.clone()));
    }
    Ok(request_token(cfg, form, http).await?)
}

pub async fn refresh(cfg: &OAuthResolved, refresh_token: &str, http: &dyn TokenHttp) -> Result<CachedToken, AuthError> {
    Ok(request_token(cfg, refresh_form(refresh_token), http).await?)
}

/// Redeem an authorization code (RFC 6749 §4.1.3 with the RFC 7636 verifier).
pub async fn exchange_code(
    cfg: &OAuthResolved,
    code: &str,
    verifier: &str,
    redirect_uri: &str,
    http: &dyn TokenHttp,
) -> Result<CachedToken, AuthError> {
    let form = vec![
        ("grant_type".to_string(), "authorization_code".to_string()),
        ("code".into(), code.to_string()),
        ("code_verifier".into(), verifier.to_string()),
        ("redirect_uri".into(), redirect_uri.to_string()),
    ];
    Ok(request_token(cfg, form, http).await?)
}

/// One authorization-code attempt: PKCE verifier, state and the exact
/// redirect URI it is bound to.
#[derive(Clone)]
pub struct PkceAttempt {
    pub verifier: Zeroizing<String>,
    pub challenge: String,
    pub state: String,
    pub redirect_uri: String,
}

impl PkceAttempt {
    /// A copy carrying only what callback validation needs (state and
    /// redirect binding) — never the verifier.
    pub fn binding_only(&self) -> PkceAttempt {
        PkceAttempt {
            verifier: Zeroizing::new(String::new()),
            challenge: self.challenge.clone(),
            state: self.state.clone(),
            redirect_uri: self.redirect_uri.clone(),
        }
    }
}

fn random_b64u(n: usize) -> String {
    let mut b = vec![0u8; n];
    rand::fill(&mut b[..]);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

pub fn new_attempt(redirect_uri: &str) -> PkceAttempt {
    let verifier = random_b64u(48);
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    PkceAttempt { verifier: Zeroizing::new(verifier), challenge, state: random_b64u(24), redirect_uri: redirect_uri.to_string() }
}

pub fn authorization_url(authorization_endpoint: &str, client_id: &str, scope: &str, attempt: &PkceAttempt) -> Result<String, AuthError> {
    let mut u = url::Url::parse(authorization_endpoint).map_err(|e| AuthError::Invalid(format!("authorization URL: {e}")))?;
    if !matches!(u.scheme(), "https" | "http") {
        return Err(AuthError::Invalid("authorization URL must use https (or http for a local test issuer)".into()));
    }
    {
        let mut q = u.query_pairs_mut();
        q.append_pair("response_type", "code");
        q.append_pair("client_id", client_id);
        q.append_pair("redirect_uri", &attempt.redirect_uri);
        q.append_pair("state", &attempt.state);
        q.append_pair("code_challenge", &attempt.challenge);
        q.append_pair("code_challenge_method", "S256");
        if !scope.is_empty() {
            q.append_pair("scope", scope);
        }
    }
    Ok(u.to_string())
}

/// Validate a redirect callback against the attempt it must belong to.
/// Returns the authorization code only when origin, path and state match.
pub fn validate_callback(attempt: &PkceAttempt, callback_url: &str) -> Result<Zeroizing<String>, AuthError> {
    let expected = url::Url::parse(&attempt.redirect_uri).map_err(|e| AuthError::Invalid(format!("redirect URI: {e}")))?;
    let got = url::Url::parse(callback_url).map_err(|_| AuthError::Invalid("callback is not a URL".into()))?;
    if got.scheme() != expected.scheme()
        || got.host_str() != expected.host_str()
        || got.port_or_known_default() != expected.port_or_known_default()
        || got.path() != expected.path()
    {
        return Err(AuthError::Invalid("callback arrived on a different origin/path than this authorization attempt; ignored".into()));
    }
    let mut q: HashMap<String, Zeroizing<String>> = HashMap::new();
    for (k, v) in got.query_pairs() {
        if matches!(k.as_ref(), "code" | "state" | "error") && q.contains_key(k.as_ref()) {
            return Err(AuthError::Invalid(format!("callback repeats the '{k}' parameter; no token exchange was performed")));
        }
        q.insert(k.into_owned(), Zeroizing::new(v.into_owned()));
    }
    // State is checked first so an unbound callback cannot even report an error.
    match q.get("state") {
        Some(s) if constant_time_eq(s.as_bytes(), attempt.state.as_bytes()) => {}
        _ => {
            return Err(AuthError::Invalid(
                "callback state does not match this authorization attempt; no token exchange was performed".into(),
            ));
        }
    }
    if let Some(e) = q.get("error") {
        return Err(AuthError::Acquisition(format!("authorization server returned error: {}", sanitize_error_code(e))));
    }
    q.remove("code").filter(|c| !c.is_empty()).ok_or_else(|| AuthError::Invalid("callback has no authorization code".into()))
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Scriptable issuer: answers per grant type and counts every request.
    struct FakeIssuer {
        calls: AtomicU64,
        grants: Mutex<Vec<String>>,
        /// (status, body) for refresh_token requests; `None` = transport failure.
        refresh_reply: Mutex<Option<(u16, String)>>,
    }

    impl FakeIssuer {
        fn new() -> Self {
            FakeIssuer { calls: AtomicU64::new(0), grants: Mutex::new(vec![]), refresh_reply: Mutex::new(None) }
        }
    }

    impl TokenHttp for FakeIssuer {
        fn post_form<'a>(
            &'a self,
            _url: &'a str,
            form: Vec<(String, String)>,
            _basic: Option<(String, String)>,
        ) -> BoxFut<'a, Result<(u16, Vec<u8>), String>> {
            Box::pin(async move {
                let n = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
                let grant = form.iter().find(|(k, _)| k == "grant_type").map(|(_, v)| v.clone()).unwrap_or_default();
                self.grants.lock().push(grant.clone());
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                if grant == "refresh_token" {
                    return match self.refresh_reply.lock().clone() {
                        Some((status, body)) => Ok((status, body.into_bytes())),
                        None => Err("connect refused".into()),
                    };
                }
                Ok((200, format!(r#"{{"access_token":"t{n}","token_type":"Bearer","expires_in":3600}}"#).into_bytes()))
            })
        }
    }

    fn cfg() -> OAuthResolved {
        OAuthResolved {
            grant: OAuthGrant::ClientCredentials,
            token_url: "http://issuer/token".into(),
            client_id: "c".into(),
            client_secret: Zeroizing::new("s".into()),
            scope: String::new(),
            audience: String::new(),
            basic_client_auth: true,
            refresh_skew_secs: 30,
        }
    }

    fn pkce_cfg() -> OAuthResolved {
        OAuthResolved { grant: OAuthGrant::AuthorizationCodePkce, client_secret: Zeroizing::new(String::new()), ..cfg() }
    }

    fn expired_with_refresh(rt: &str) -> CachedToken {
        CachedToken {
            access_token: Zeroizing::new("old".into()),
            token_type: "Bearer".into(),
            expires_at: Some(Utc::now() - Duration::seconds(10)),
            refresh_token: Some(Zeroizing::new(rt.into())),
        }
    }

    #[tokio::test]
    async fn auth_014_single_flight_refresh() {
        let issuer = Arc::new(FakeIssuer::new());
        let cache = Arc::new(TokenCache::new());
        let mut handles = Vec::new();
        for _ in 0..50 {
            let (c, i) = (cache.clone(), issuer.clone());
            handles.push(tokio::spawn(async move {
                c.get_or_acquire("k", &cfg(), i.as_ref(), Utc::now()).await.map(|t| t.access_token.to_string())
            }));
        }
        let mut tokens = Vec::new();
        for h in handles {
            tokens.push(h.await.unwrap().unwrap());
        }
        assert_eq!(issuer.calls.load(Ordering::SeqCst), 1, "concurrent expiry must trigger exactly one token request");
        assert!(tokens.iter().all(|t| t == "t1"));
    }

    #[tokio::test]
    async fn pkce_without_token_requires_interaction_and_never_uses_client_credentials() {
        for grant in [OAuthGrant::AuthorizationCodePkce, OAuthGrant::RefreshToken] {
            let issuer = FakeIssuer::new();
            let cache = TokenCache::new();
            let c = OAuthResolved { grant, ..pkce_cfg() };
            let e = cache.get_or_acquire("k", &c, &issuer, Utc::now()).await.err().expect("must not acquire");
            assert!(matches!(e, AuthError::InteractionRequired(_)), "{e:?}");
            assert_eq!(issuer.calls.load(Ordering::SeqCst), 0, "no token request of any grant");
        }
    }

    #[tokio::test]
    async fn pkce_uses_cached_token_then_refreshes_and_keeps_refresh_token() {
        let issuer = FakeIssuer::new();
        *issuer.refresh_reply.lock() = Some((200, r#"{"access_token":"fresh","token_type":"Bearer","expires_in":60}"#.into()));
        let cache = TokenCache::new();
        cache.insert("k", expired_with_refresh("rt-1"));
        let t = cache.get_or_acquire("k", &pkce_cfg(), &issuer, Utc::now()).await.unwrap();
        assert_eq!(t.access_token.as_str(), "fresh");
        assert_eq!(t.refresh_token.as_deref().map(|s| s.as_str()), Some("rt-1"), "old refresh token stays valid when none is re-issued");
        assert_eq!(*issuer.grants.lock(), vec!["refresh_token".to_string()]);
        // Usable now: no further request.
        cache.get_or_acquire("k", &pkce_cfg(), &issuer, Utc::now()).await.unwrap();
        assert_eq!(issuer.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn pkce_rejected_refresh_requires_interaction_and_forgets_it() {
        let issuer = FakeIssuer::new();
        *issuer.refresh_reply.lock() = Some((400, r#"{"error":"invalid_grant"}"#.into()));
        let cache = TokenCache::new();
        cache.insert("k", expired_with_refresh("rt-revoked"));
        let e = cache.get_or_acquire("k", &pkce_cfg(), &issuer, Utc::now()).await.err().unwrap();
        assert!(matches!(&e, AuthError::InteractionRequired(m) if m.contains("invalid_grant")), "{e:?}");
        assert!(cache.get("k").is_none(), "a rejected refresh token is not retried");
        assert_eq!(*issuer.grants.lock(), vec!["refresh_token".to_string()], "never falls back to client credentials");
    }

    #[tokio::test]
    async fn auth_015_issuer_outage_on_refresh_is_a_dependency_failure() {
        let issuer = FakeIssuer::new(); // refresh → transport failure
        let cache = TokenCache::new();
        cache.insert("k", expired_with_refresh("rt-1"));
        let e = cache.get_or_acquire("k", &pkce_cfg(), &issuer, Utc::now()).await.err().unwrap();
        assert!(matches!(e, AuthError::Acquisition(_)), "{e:?}");
        assert!(cache.get("k").is_some(), "refresh token kept for a later attempt");
        *issuer.refresh_reply.lock() = Some((503, r#"{"error":"temporarily_unavailable"}"#.into()));
        let e = cache.get_or_acquire("k", &pkce_cfg(), &issuer, Utc::now()).await.err().unwrap();
        assert!(matches!(e, AuthError::Acquisition(_)), "{e:?}");
        assert!(issuer.grants.lock().iter().all(|g| g == "refresh_token"));
    }

    #[tokio::test]
    async fn client_credentials_refresh_failure_still_falls_back() {
        let issuer = FakeIssuer::new(); // refresh fails
        let cache = TokenCache::new();
        cache.insert("k", expired_with_refresh("rt-1"));
        let t = cache.get_or_acquire("k", &cfg(), &issuer, Utc::now()).await.unwrap();
        assert!(t.access_token.starts_with('t'));
        assert_eq!(*issuer.grants.lock(), vec!["refresh_token".to_string(), "client_credentials".to_string()]);
    }

    #[test]
    fn auth_012_013_callback_binding() {
        let a = new_attempt("http://127.0.0.1:53123/callback");
        let ok = format!("http://127.0.0.1:53123/callback?code=abc&state={}", a.state);
        assert_eq!(validate_callback(&a, &ok).unwrap().as_str(), "abc");
        assert!(validate_callback(&a, "http://127.0.0.1:53123/callback?code=abc&state=forged").is_err());
        let wrong_port = format!("http://127.0.0.1:9999/callback?code=abc&state={}", a.state);
        assert!(validate_callback(&a, &wrong_port).is_err());
        let wrong_path = format!("http://127.0.0.1:53123/other?code=abc&state={}", a.state);
        assert!(validate_callback(&a, &wrong_path).is_err());
        // The binding-only copy validates identically and carries no verifier.
        let b = a.binding_only();
        assert!(b.verifier.is_empty());
        assert_eq!(validate_callback(&b, &ok).unwrap().as_str(), "abc");
    }

    #[test]
    fn callback_duplicates_and_errors_are_bounded() {
        let a = new_attempt("http://127.0.0.1:1/cb");
        let dup = format!("http://127.0.0.1:1/cb?code=a&code=b&state={}", a.state);
        assert!(matches!(validate_callback(&a, &dup), Err(AuthError::Invalid(_))));
        let err = format!("http://127.0.0.1:1/cb?error=access_denied%0A%3Cscript%3E&state={}", a.state);
        match validate_callback(&a, &err) {
            Err(AuthError::Acquisition(m)) => {
                assert!(m.contains("access_denied") && !m.contains('<') && !m.contains('\n'), "{m}")
            }
            other => panic!("{:?}", other.map(|z| z.to_string())),
        }
        // An error without the right state is an unbound callback, not a provider answer.
        assert!(matches!(validate_callback(&a, "http://127.0.0.1:1/cb?error=access_denied&state=x"), Err(AuthError::Invalid(_))));
        let empty = format!("http://127.0.0.1:1/cb?code=&state={}", a.state);
        assert!(validate_callback(&a, &empty).is_err());
    }

    #[test]
    fn pkce_challenge_is_s256_of_verifier() {
        let a = new_attempt("http://127.0.0.1:1/cb");
        let expect = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(a.verifier.as_bytes()));
        assert_eq!(a.challenge, expect);
        assert!(a.verifier.len() >= 43);
    }

    #[test]
    fn authorization_url_rejects_non_http_schemes() {
        let a = new_attempt("http://127.0.0.1:1/cb");
        assert!(authorization_url("javascript:alert(1)", "c", "", &a).is_err());
        assert!(authorization_url("file:///etc/passwd", "c", "", &a).is_err());
        let u = authorization_url("https://issuer.example/authorize?x=1", "c", "openid", &a).unwrap();
        assert!(u.contains("code_challenge_method=S256") && u.contains("x=1"));
    }
}
