//! OAuth 2.0 token acquisition for *target APIs* (not app login).
//!
//! * client credentials and refresh-token grants over the engine's transport;
//! * authorization code + PKCE (S256) with a per-attempt `state` and an exact
//!   loopback redirect binding (RFC 8252); callbacks that do not match are
//!   rejected without any token exchange;
//! * single-flight refresh: concurrent sends that find an expired token share
//!   one token request instead of stampeding the issuer.

use crate::AuthError;
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

    pub fn clear(&self) {
        self.entries.lock().clear();
    }

    fn lock_for(&self, key: &str) -> Arc<tokio::sync::Mutex<()>> {
        self.locks.lock().entry(key.to_string()).or_insert_with(|| Arc::new(tokio::sync::Mutex::new(()))).clone()
    }

    /// Return a usable token, refreshing or acquiring at most once for
    /// concurrent callers.
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
        self.requests.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let t = match prior_refresh {
            Some(rt) => match refresh(cfg, &rt, http).await {
                Ok(t) => t,
                Err(_) => client_credentials(cfg, http).await?,
            },
            None => client_credentials(cfg, http).await?,
        };
        self.insert(key, t.clone());
        Ok(t)
    }
}

fn parse_token_response(status: u16, body: &[u8]) -> Result<CachedToken, AuthError> {
    let v: serde_json::Value = serde_json::from_slice(body)
        .map_err(|_| AuthError::Acquisition(format!("token endpoint returned HTTP {status} with a non-JSON body")))?;
    if !(200..300).contains(&status) {
        let err = v.get("error").and_then(|e| e.as_str()).unwrap_or("unknown_error");
        let desc = v.get("error_description").and_then(|e| e.as_str()).unwrap_or("");
        return Err(AuthError::Acquisition(format!("token endpoint returned HTTP {status}: {err} {desc}").trim().to_string()));
    }
    let access = v
        .get("access_token")
        .and_then(|t| t.as_str())
        .ok_or_else(|| AuthError::Acquisition("token response has no access_token".into()))?;
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
    let basic = client_auth(cfg, &mut form);
    let (status, body) = http.post_form(&cfg.token_url, form, basic).await.map_err(AuthError::Acquisition)?;
    parse_token_response(status, &body)
}

pub async fn refresh(cfg: &OAuthResolved, refresh_token: &str, http: &dyn TokenHttp) -> Result<CachedToken, AuthError> {
    let mut form = vec![("grant_type".to_string(), "refresh_token".to_string()), ("refresh_token".into(), refresh_token.to_string())];
    let basic = client_auth(cfg, &mut form);
    let (status, body) = http.post_form(&cfg.token_url, form, basic).await.map_err(AuthError::Acquisition)?;
    parse_token_response(status, &body)
}

pub async fn exchange_code(
    cfg: &OAuthResolved,
    code: &str,
    verifier: &str,
    redirect_uri: &str,
    http: &dyn TokenHttp,
) -> Result<CachedToken, AuthError> {
    let mut form = vec![
        ("grant_type".to_string(), "authorization_code".to_string()),
        ("code".into(), code.to_string()),
        ("code_verifier".into(), verifier.to_string()),
        ("redirect_uri".into(), redirect_uri.to_string()),
    ];
    let basic = client_auth(cfg, &mut form);
    let (status, body) = http.post_form(&cfg.token_url, form, basic).await.map_err(AuthError::Acquisition)?;
    parse_token_response(status, &body)
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
pub fn validate_callback(attempt: &PkceAttempt, callback_url: &str) -> Result<String, AuthError> {
    let expected = url::Url::parse(&attempt.redirect_uri).map_err(|e| AuthError::Invalid(format!("redirect URI: {e}")))?;
    let got = url::Url::parse(callback_url).map_err(|_| AuthError::Invalid("callback is not a URL".into()))?;
    if got.scheme() != expected.scheme()
        || got.host_str() != expected.host_str()
        || got.port_or_known_default() != expected.port_or_known_default()
        || got.path() != expected.path()
    {
        return Err(AuthError::Invalid("callback arrived on a different origin/path than this authorization attempt; ignored".into()));
    }
    let q: HashMap<String, String> = got.query_pairs().into_owned().collect();
    if let Some(e) = q.get("error") {
        return Err(AuthError::Acquisition(format!("authorization server returned error: {e}")));
    }
    match q.get("state") {
        Some(s) if constant_time_eq(s.as_bytes(), attempt.state.as_bytes()) => {}
        _ => {
            return Err(AuthError::Invalid(
                "callback state does not match this authorization attempt; no token exchange was performed".into(),
            ));
        }
    }
    q.get("code").cloned().ok_or_else(|| AuthError::Invalid("callback has no authorization code".into()))
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

    struct FakeIssuer {
        calls: AtomicU64,
    }

    impl TokenHttp for FakeIssuer {
        fn post_form<'a>(
            &'a self,
            _url: &'a str,
            _form: Vec<(String, String)>,
            _basic: Option<(String, String)>,
        ) -> BoxFut<'a, Result<(u16, Vec<u8>), String>> {
            Box::pin(async move {
                let n = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                Ok((200, format!(r#"{{"access_token":"t{n}","token_type":"Bearer","expires_in":3600}}"#).into_bytes()))
            })
        }
    }

    fn cfg() -> OAuthResolved {
        OAuthResolved {
            token_url: "http://issuer/token".into(),
            client_id: "c".into(),
            client_secret: Zeroizing::new("s".into()),
            scope: String::new(),
            audience: String::new(),
            basic_client_auth: true,
            refresh_skew_secs: 30,
        }
    }

    #[tokio::test]
    async fn auth_014_single_flight_refresh() {
        let issuer = Arc::new(FakeIssuer { calls: AtomicU64::new(0) });
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

    #[test]
    fn auth_012_013_callback_binding() {
        let a = new_attempt("http://127.0.0.1:53123/callback");
        let ok = format!("http://127.0.0.1:53123/callback?code=abc&state={}", a.state);
        assert_eq!(validate_callback(&a, &ok).unwrap(), "abc");
        assert!(validate_callback(&a, "http://127.0.0.1:53123/callback?code=abc&state=forged").is_err());
        let wrong_port = format!("http://127.0.0.1:9999/callback?code=abc&state={}", a.state);
        assert!(validate_callback(&a, &wrong_port).is_err());
        let wrong_path = format!("http://127.0.0.1:53123/other?code=abc&state={}", a.state);
        assert!(validate_callback(&a, &wrong_path).is_err());
    }

    #[test]
    fn pkce_challenge_is_s256_of_verifier() {
        let a = new_attempt("http://127.0.0.1:1/cb");
        let expect = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(a.verifier.as_bytes()));
        assert_eq!(a.challenge, expect);
        assert!(a.verifier.len() >= 43);
    }
}
