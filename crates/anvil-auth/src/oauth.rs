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
//!   until the user signs in;
//! * tokens are cached under a [`TokenKey`] made of every input that decides
//!   what the token authorizes, so a profile never reuses a token issued for
//!   another grant, audience, client, scope, issuer, authorization URL or
//!   token-cache identity;
//! * clearing the cache (lock), forgetting a token (sign-out) or storing a
//!   new sign-in starts a new generation: an acquisition, refresh or code
//!   redemption that began before it can no longer store or return its token.
//!   When a newer sign-in is all that happened, the send is served with that
//!   sign-in's token instead of failing;
//! * a refresh runs to completion on a task of its own, so a caller that
//!   stops waiting never abandons a refresh token the issuer may already have
//!   rotated. A lock or a sign-out of its key aborts it;
//! * every cached token expires: a response without `expires_in` is given
//!   [`DEFAULT_EXPIRES_IN_SECS`], and an `expires_in` that is not a whole
//!   number of seconds up to [`MAX_EXPIRES_IN_SECS`] fails the acquisition.

use crate::AuthError;
use anvil_domain::Id;
use anvil_domain::auth::OAuthGrant;
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use parking_lot::Mutex;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::OwnedMutexGuard;
use tokio::task::AbortHandle;
use zeroize::Zeroizing;

pub type BoxFut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Lifetime given to a token whose response has no `expires_in` (RFC 6749
/// §5.1 makes it optional): the token is refreshed or acquired again after
/// an hour instead of being reused for the rest of the session.
pub const DEFAULT_EXPIRES_IN_SECS: u64 = 3600;

/// Longest `expires_in` accepted (ten years). A token response claiming a
/// longer lifetime is rejected as malformed.
pub const MAX_EXPIRES_IN_SECS: u64 = 10 * 365 * 24 * 60 * 60;

/// Minimal HTTP capability for token endpoints, implemented by the engine.
pub trait TokenHttp: Send + Sync {
    /// POST `application/x-www-form-urlencoded`; returns (status, body).
    ///
    /// The returned future borrows nothing, so the cache can finish it on a
    /// task of its own after the caller stops waiting (a refresh). Dropping
    /// it abandons the request.
    fn post_form(
        &self,
        url: &str,
        form: Vec<(String, String)>,
        basic: Option<(String, String)>,
    ) -> BoxFut<'static, Result<(u16, Vec<u8>), String>>;
}

#[derive(Clone)]
pub struct OAuthResolved {
    /// The configured grant. Only `ClientCredentials` may obtain a token
    /// without user interaction.
    pub grant: OAuthGrant,
    pub token_url: String,
    /// Authorization endpoint of an interactive grant, query included (an
    /// organization, connection or identity-provider hint decides whose
    /// token the sign-in yields). Empty for client credentials.
    pub authorization_url: String,
    pub client_id: String,
    pub client_secret: Zeroizing<String>,
    pub scope: String,
    pub audience: String,
    pub basic_client_auth: bool,
    /// Token-cache identity of the profile: profiles with different ids
    /// never share a token, even with otherwise identical settings.
    pub token_cache_id: Option<Id>,
    pub refresh_skew_secs: i64,
}

/// Identity of a cached token: every input that changes what the token
/// authorizes or whom it was issued to. Two sends share a token only when
/// all of them are equal. Holds no secret.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TokenKey {
    /// Cache partition chosen by the caller (the engine uses the workspace
    /// isolation key).
    pub partition: String,
    pub token_url: String,
    /// Empty for client credentials, which never visit it.
    pub authorization_url: String,
    pub client_id: String,
    pub basic_client_auth: bool,
    pub grant: OAuthGrant,
    pub audience: String,
    pub scope: String,
    pub token_cache_id: Option<Id>,
}

impl TokenKey {
    pub fn new(partition: &str, cfg: &OAuthResolved) -> Self {
        let interactive = cfg.grant != OAuthGrant::ClientCredentials;
        TokenKey {
            partition: partition.to_string(),
            token_url: cfg.token_url.clone(),
            authorization_url: if interactive { cfg.authorization_url.clone() } else { String::new() },
            client_id: cfg.client_id.clone(),
            basic_client_auth: cfg.basic_client_auth,
            grant: cfg.grant,
            audience: cfg.audience.clone(),
            scope: cfg.scope.clone(),
            token_cache_id: cfg.token_cache_id,
        }
    }
}

#[derive(Clone)]
pub struct CachedToken {
    pub access_token: Zeroizing<String>,
    pub token_type: String,
    /// Always set for a token-endpoint response (see
    /// [`DEFAULT_EXPIRES_IN_SECS`]). A token without one is never reused.
    pub expires_at: Option<DateTime<Utc>>,
    pub refresh_token: Option<Zeroizing<String>>,
}

impl CachedToken {
    /// Whether the token is still valid `skew` seconds from `now`. A token
    /// without an expiry, or whose expiry cannot be compared, is not.
    pub fn usable(&self, now: DateTime<Utc>, skew: i64) -> bool {
        let horizon = Duration::try_seconds(skew).and_then(|skew| now.checked_add_signed(skew));
        matches!((horizon, self.expires_at), (Some(h), Some(e)) if h < e)
    }
}

/// The cache generation an acquisition started in, for one key. A token
/// obtained under it may be stored only while it is still current, i.e. no
/// [`TokenCache::clear`], [`TokenCache::remove`] or
/// [`TokenCache::store_sign_in`] of that key happened since.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Generation {
    cache: u64,
    removal: u64,
    sign_in: u64,
}

#[derive(Default)]
struct CacheState {
    entries: HashMap<TokenKey, CachedToken>,
    /// Bumped by [`TokenCache::clear`].
    generation: u64,
    /// Bumped per key by [`TokenCache::remove`].
    removals: HashMap<TokenKey, u64>,
    /// Bumped per key by [`TokenCache::store_sign_in`]. Counted apart from
    /// removals: a send overtaken only by a sign-in can use its token.
    sign_ins: HashMap<TokenKey, u64>,
    /// The refresh in flight per key (with its sequence number), aborted by
    /// [`TokenCache::clear`] and [`TokenCache::remove`].
    refreshes: HashMap<TokenKey, (u64, AbortHandle)>,
    next_refresh: u64,
}

impl CacheState {
    fn generation(&self, key: &TokenKey) -> Generation {
        let of = |counts: &HashMap<TokenKey, u64>| counts.get(key).copied().unwrap_or(0);
        Generation { cache: self.generation, removal: of(&self.removals), sign_in: of(&self.sign_ins) }
    }

    fn bump(counts: &mut HashMap<TokenKey, u64>, key: &TokenKey) {
        let g = counts.entry(key.clone()).or_insert(0);
        *g = g.wrapping_add(1);
    }

    /// The answer of an acquisition that started in `generation` and can no
    /// longer store its own token. When a newer sign-in is all that happened
    /// since, a valid token is cached and the caller gets it; after a lock or
    /// a sign-out it gets [`superseded`].
    fn superseded_answer(&self, key: &TokenKey, generation: Generation, skew: i64) -> Result<CachedToken, AuthError> {
        let current = self.generation(key);
        let only_signed_in = current.cache == generation.cache && current.removal == generation.removal;
        match self.entries.get(key) {
            Some(t) if only_signed_in && t.usable(Utc::now(), skew) => Ok(t.clone()),
            _ => Err(superseded()),
        }
    }

    /// Forget the registration of refresh `id` once it is over.
    fn refresh_finished(&mut self, key: &TokenKey, id: u64) {
        if self.refreshes.get(key).is_some_and(|(current, _)| *current == id) {
            self.refreshes.remove(key);
        }
    }

    fn insert_if_current(&mut self, key: &TokenKey, generation: Generation, t: CachedToken) -> bool {
        if self.generation(key) != generation {
            return false;
        }
        self.entries.insert(key.clone(), t);
        true
    }

    /// Drop the entry holding a refresh token the issuer rejected, unless
    /// the entry was replaced (a new sign-in) or the generation moved on.
    fn forget_rejected_refresh(&mut self, key: &TokenKey, generation: Generation, rejected: &str) {
        if self.generation(key) != generation {
            return;
        }
        if self.entries.get(key).and_then(|t| t.refresh_token.as_ref()).is_some_and(|rt| rt.as_str() == rejected) {
            self.entries.remove(key);
        }
    }
}

/// What a refresh task hands back to the caller that started it.
enum Refreshed {
    /// Finished: the token (already stored) or the failure to report.
    Done(Result<CachedToken, AuthError>),
    /// Client credentials only: the refresh failed and the caller falls back
    /// to a new grant, still holding the single-flight lock.
    Fallback(OwnedMutexGuard<()>),
}

#[derive(Default)]
pub struct TokenCache {
    /// Shared with refresh tasks, which store their result themselves.
    state: Arc<Mutex<CacheState>>,
    locks: Mutex<HashMap<TokenKey, Arc<tokio::sync::Mutex<()>>>>,
    /// Token endpoint requests performed (observability / storm tests).
    pub requests: std::sync::atomic::AtomicU64,
}

impl TokenCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Store a token unconditionally (unit tests). Token-endpoint results go
    /// through [`insert_if_current`](Self::insert_if_current) or
    /// [`store_sign_in`](Self::store_sign_in).
    #[cfg(test)]
    pub(crate) fn insert(&self, key: &TokenKey, t: CachedToken) {
        self.state.lock().entries.insert(key.clone(), t);
    }

    pub fn get(&self, key: &TokenKey) -> Option<CachedToken> {
        self.state.lock().entries.get(key).cloned()
    }

    /// The current generation for `key`. Take it before starting a token
    /// request whose result is to be cached.
    pub fn generation(&self, key: &TokenKey) -> Generation {
        self.state.lock().generation(key)
    }

    /// The generation and the entry for `key`, read together.
    fn snapshot(&self, key: &TokenKey) -> (Generation, Option<CachedToken>) {
        let st = self.state.lock();
        (st.generation(key), st.entries.get(key).cloned())
    }

    /// Store `t` only if `generation` is still current for `key`; returns
    /// whether it was stored. The check and the insert are atomic with
    /// respect to [`clear`](Self::clear), [`remove`](Self::remove) and
    /// [`store_sign_in`](Self::store_sign_in), so a token acquired before a
    /// lock, sign-out or new sign-in can never overwrite what came after.
    pub fn insert_if_current(&self, key: &TokenKey, generation: Generation, t: CachedToken) -> bool {
        self.state.lock().insert_if_current(key, generation, t)
    }

    /// Store the token of a completed sign-in (a redeemed authorization
    /// code) if `generation` is still current for `key`, and start a new
    /// generation for `key` in the same step: an acquisition or refresh that
    /// began before the sign-in can no longer overwrite it. Returns whether
    /// it was stored.
    pub fn store_sign_in(&self, key: &TokenKey, generation: Generation, t: CachedToken) -> bool {
        let mut st = self.state.lock();
        if st.generation(key) != generation {
            return false;
        }
        CacheState::bump(&mut st.sign_ins, key);
        st.entries.insert(key.clone(), t);
        true
    }

    /// Forget one cached token (explicit sign-out), invalidate every
    /// acquisition of that key still in flight and abort its refresh.
    /// Returns whether an entry existed.
    pub fn remove(&self, key: &TokenKey) -> bool {
        let mut st = self.state.lock();
        CacheState::bump(&mut st.removals, key);
        if let Some((_, refresh)) = st.refreshes.remove(key) {
            refresh.abort();
        }
        st.entries.remove(key).is_some()
    }

    /// Forget every cached token (lock), invalidate every acquisition still
    /// in flight and abort every refresh.
    pub fn clear(&self) {
        let mut st = self.state.lock();
        st.entries.clear();
        st.removals.clear();
        st.sign_ins.clear();
        for (_, (_, refresh)) in st.refreshes.drain() {
            refresh.abort();
        }
        st.generation = st.generation.wrapping_add(1);
    }

    fn lock_for(&self, key: &TokenKey) -> Arc<tokio::sync::Mutex<()>> {
        self.locks.lock().entry(key.clone()).or_insert_with(|| Arc::new(tokio::sync::Mutex::new(()))).clone()
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
    ///
    /// The call belongs to the cache generation current when it starts. If
    /// the cache is cleared or `key` is forgotten before it finishes, it
    /// fails with [`AuthError::Canceled`] and caches nothing. If a new
    /// sign-in is stored meanwhile, what it obtained is discarded as well,
    /// and it answers with the sign-in's token while that is usable.
    ///
    /// Dropping the future abandons a client-credentials request. A refresh
    /// runs on a task of its own that keeps the single-flight lock until the
    /// issuer answers and stores the result (under the same generation
    /// rule), so a caller that stops waiting cannot lose a refresh token the
    /// issuer rotated, and nobody retries the old one meanwhile. A lock or a
    /// sign-out of `key` aborts that task.
    pub async fn get_or_acquire(
        &self,
        key: &TokenKey,
        cfg: &OAuthResolved,
        http: &dyn TokenHttp,
        now: DateTime<Utc>,
    ) -> Result<CachedToken, AuthError> {
        let (generation, cached) = self.snapshot(key);
        if let Some(t) = cached
            && t.usable(now, cfg.refresh_skew_secs)
        {
            return Ok(t);
        }
        let single_flight = self.lock_for(key).lock_owned().await;
        // One read: the generation check and the entry it guards.
        let (current, cached) = self.snapshot(key);
        if current != generation {
            return self.state.lock().superseded_answer(key, generation, cfg.refresh_skew_secs);
        }
        // Another caller may have refreshed while we waited.
        if let Some(t) = &cached
            && t.usable(Utc::now(), cfg.refresh_skew_secs)
        {
            return Ok(t.clone());
        }
        let prior_refresh = cached.and_then(|t| t.refresh_token);
        let interactive = cfg.grant != OAuthGrant::ClientCredentials;
        if prior_refresh.is_none() && interactive {
            return Err(AuthError::InteractionRequired(interaction_message(cfg.grant, None)));
        }
        self.requests.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let _single_flight = match prior_refresh {
            Some(rt) => match self.refresh_detached(key, generation, cfg, rt, http, single_flight).await {
                Refreshed::Done(r) => return r,
                Refreshed::Fallback(single_flight) => single_flight,
            },
            None => single_flight,
        };
        let t = client_credentials(cfg, http).await?;
        let mut st = self.state.lock();
        if !st.insert_if_current(key, generation, t.clone()) {
            return st.superseded_answer(key, generation, cfg.refresh_skew_secs);
        }
        Ok(t)
    }

    /// Run a refresh on its own task, which holds `single_flight` and stores
    /// the refreshed token (or forgets a rejected refresh token) itself. The
    /// task is registered under `key` so a lock or a sign-out aborts it.
    async fn refresh_detached(
        &self,
        key: &TokenKey,
        generation: Generation,
        cfg: &OAuthResolved,
        rt: Zeroizing<String>,
        http: &dyn TokenHttp,
        single_flight: OwnedMutexGuard<()>,
    ) -> Refreshed {
        let mut form = refresh_form(&rt);
        let basic = client_auth(cfg, &mut form);
        let request = http.post_form(&cfg.token_url, form, basic);
        let (state, task_key, grant, skew) = (self.state.clone(), key.clone(), cfg.grant, cfg.refresh_skew_secs);
        // The generation check and registration share the state lock, so a
        // sign-in cannot slip between them. A refresh that was superseded
        // before registration does not spawn: it answers like
        // `superseded_answer`, with the newer sign-in's token when only a
        // sign-in happened since, and `Canceled` after a lock or a sign-out.
        let task = {
            let mut st = self.state.lock();
            if st.generation(key) != generation {
                return Refreshed::Done(st.superseded_answer(key, generation, cfg.refresh_skew_secs));
            }
            st.next_refresh = st.next_refresh.wrapping_add(1);
            let id = st.next_refresh;
            let task = tokio::spawn(async move {
                let key = task_key;
                let answer = match request.await {
                    Ok((status, body)) => parse_token_response(status, &body),
                    Err(e) => Err(TokenFailure::Transport(e)),
                };
                state.lock().refresh_finished(&key, id);
                // `single_flight` is released only when this task ends, after the
                // outcome is stored: a waiter never refreshes with the old token.
                match answer {
                    // RFC 6749 §6: when no new refresh token is issued the old one stays valid.
                    Ok(mut t) => {
                        if t.refresh_token.is_none() {
                            t.refresh_token = Some(rt);
                        }
                        let mut st = state.lock();
                        let stored = st.insert_if_current(&key, generation, t.clone());
                        Refreshed::Done(if stored { Ok(t) } else { st.superseded_answer(&key, generation, skew) })
                    }
                    Err(_) if grant == OAuthGrant::ClientCredentials => Refreshed::Fallback(single_flight),
                    Err(TokenFailure::Rejected { error, .. }) if error == "invalid_grant" => {
                        // Expired or revoked refresh token: forget it so the next
                        // send does not retry it, and ask for a new sign-in.
                        state.lock().forget_rejected_refresh(&key, generation, &rt);
                        Refreshed::Done(Err(AuthError::InteractionRequired(interaction_message(grant, Some(&error)))))
                    }
                    // Issuer unreachable or failing: keep the refresh token for a
                    // later attempt and report the dependency failure.
                    Err(other) => Refreshed::Done(Err(other.into())),
                }
            });
            st.refreshes.insert(key.clone(), (id, task.abort_handle()));
            task
        };
        match task.await {
            Ok(r) => r,
            // Aborted by a lock or a sign-out of this key.
            Err(e) if e.is_cancelled() => Refreshed::Done(Err(superseded())),
            Err(e) => Refreshed::Done(Err(AuthError::Acquisition(format!("the token refresh ended unexpectedly: {e}")))),
        }
    }
}

fn superseded() -> AuthError {
    AuthError::Canceled(
        "a lock, a sign-out or a new sign-in superseded this OAuth token while it was being acquired; the token was discarded".into(),
    )
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
    let expires_at = expiry(v.get("expires_in"), Utc::now())?;
    Ok(CachedToken {
        access_token: Zeroizing::new(access.to_string()),
        token_type: v.get("token_type").and_then(|t| t.as_str()).unwrap_or("Bearer").to_string(),
        expires_at: Some(expires_at),
        refresh_token: v.get("refresh_token").and_then(|t| t.as_str()).map(|s| Zeroizing::new(s.to_string())),
    })
}

/// When a token issued at `now` expires. An omitted (or null) `expires_in`
/// gets [`DEFAULT_EXPIRES_IN_SECS`]; a present one must be a whole number of
/// seconds up to [`MAX_EXPIRES_IN_SECS`], as a JSON number or a decimal
/// string (some issuers send `"3600"`). Anything else is malformed, never a
/// token without an expiry.
fn expiry(expires_in: Option<&serde_json::Value>, now: DateTime<Utc>) -> Result<DateTime<Utc>, TokenFailure> {
    let secs = match expires_in {
        None | Some(serde_json::Value::Null) => Some(DEFAULT_EXPIRES_IN_SECS),
        Some(serde_json::Value::Number(n)) => n.as_u64(),
        Some(serde_json::Value::String(s)) if s.bytes().all(|b| b.is_ascii_digit()) => s.parse().ok(),
        Some(_) => None,
    };
    secs.filter(|s| *s <= MAX_EXPIRES_IN_SECS)
        .and_then(|s| Duration::try_seconds(s as i64))
        .and_then(|d| now.checked_add_signed(d))
        .ok_or_else(|| TokenFailure::Malformed("token response has an invalid expires_in (whole seconds, up to ten years)".into()))
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
    /// A handle: token requests share its state and borrow nothing.
    #[derive(Clone)]
    struct FakeIssuer(Arc<FakeState>);

    struct FakeState {
        calls: AtomicU64,
        grants: Mutex<Vec<String>>,
        /// (status, body) for refresh_token requests; `None` = transport failure.
        refresh_reply: Mutex<Option<(u16, String)>>,
    }

    impl FakeIssuer {
        fn new() -> Self {
            FakeIssuer(Arc::new(FakeState { calls: AtomicU64::new(0), grants: Mutex::new(vec![]), refresh_reply: Mutex::new(None) }))
        }
    }

    impl std::ops::Deref for FakeIssuer {
        type Target = FakeState;

        fn deref(&self) -> &FakeState {
            &self.0
        }
    }

    impl TokenHttp for FakeIssuer {
        fn post_form(
            &self,
            _url: &str,
            form: Vec<(String, String)>,
            _basic: Option<(String, String)>,
        ) -> BoxFut<'static, Result<(u16, Vec<u8>), String>> {
            let state = self.0.clone();
            Box::pin(async move {
                let n = state.calls.fetch_add(1, Ordering::SeqCst) + 1;
                let grant = form.iter().find(|(k, _)| k == "grant_type").map(|(_, v)| v.clone()).unwrap_or_default();
                state.grants.lock().push(grant.clone());
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                if grant == "refresh_token" {
                    return match state.refresh_reply.lock().clone() {
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
            authorization_url: String::new(),
            client_id: "c".into(),
            client_secret: Zeroizing::new("s".into()),
            scope: String::new(),
            audience: String::new(),
            basic_client_auth: true,
            token_cache_id: None,
            refresh_skew_secs: 30,
        }
    }

    fn pkce_cfg() -> OAuthResolved {
        OAuthResolved { grant: OAuthGrant::AuthorizationCodePkce, client_secret: Zeroizing::new(String::new()), ..cfg() }
    }

    fn key(c: &OAuthResolved) -> TokenKey {
        TokenKey::new("p", c)
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
                c.get_or_acquire(&key(&cfg()), &cfg(), i.as_ref(), Utc::now()).await.map(|t| t.access_token.to_string())
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
            let e = cache.get_or_acquire(&key(&c), &c, &issuer, Utc::now()).await.err().expect("must not acquire");
            assert!(matches!(e, AuthError::InteractionRequired(_)), "{e:?}");
            assert_eq!(issuer.calls.load(Ordering::SeqCst), 0, "no token request of any grant");
        }
    }

    #[tokio::test]
    async fn pkce_uses_cached_token_then_refreshes_and_keeps_refresh_token() {
        let issuer = FakeIssuer::new();
        *issuer.refresh_reply.lock() = Some((200, r#"{"access_token":"fresh","token_type":"Bearer","expires_in":60}"#.into()));
        let cache = TokenCache::new();
        cache.insert(&key(&pkce_cfg()), expired_with_refresh("rt-1"));
        let t = cache.get_or_acquire(&key(&pkce_cfg()), &pkce_cfg(), &issuer, Utc::now()).await.unwrap();
        assert_eq!(t.access_token.as_str(), "fresh");
        assert_eq!(t.refresh_token.as_deref().map(|s| s.as_str()), Some("rt-1"), "old refresh token stays valid when none is re-issued");
        assert_eq!(*issuer.grants.lock(), vec!["refresh_token".to_string()]);
        // Usable now: no further request.
        cache.get_or_acquire(&key(&pkce_cfg()), &pkce_cfg(), &issuer, Utc::now()).await.unwrap();
        assert_eq!(issuer.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn pkce_rejected_refresh_requires_interaction_and_forgets_it() {
        let issuer = FakeIssuer::new();
        *issuer.refresh_reply.lock() = Some((400, r#"{"error":"invalid_grant"}"#.into()));
        let cache = TokenCache::new();
        cache.insert(&key(&pkce_cfg()), expired_with_refresh("rt-revoked"));
        let e = cache.get_or_acquire(&key(&pkce_cfg()), &pkce_cfg(), &issuer, Utc::now()).await.err().unwrap();
        assert!(matches!(&e, AuthError::InteractionRequired(m) if m.contains("invalid_grant")), "{e:?}");
        assert!(cache.get(&key(&pkce_cfg())).is_none(), "a rejected refresh token is not retried");
        assert_eq!(*issuer.grants.lock(), vec!["refresh_token".to_string()], "never falls back to client credentials");
    }

    #[tokio::test]
    async fn auth_015_issuer_outage_on_refresh_is_a_dependency_failure() {
        let issuer = FakeIssuer::new(); // refresh → transport failure
        let cache = TokenCache::new();
        cache.insert(&key(&pkce_cfg()), expired_with_refresh("rt-1"));
        let e = cache.get_or_acquire(&key(&pkce_cfg()), &pkce_cfg(), &issuer, Utc::now()).await.err().unwrap();
        assert!(matches!(e, AuthError::Acquisition(_)), "{e:?}");
        assert!(cache.get(&key(&pkce_cfg())).is_some(), "refresh token kept for a later attempt");
        *issuer.refresh_reply.lock() = Some((503, r#"{"error":"temporarily_unavailable"}"#.into()));
        let e = cache.get_or_acquire(&key(&pkce_cfg()), &pkce_cfg(), &issuer, Utc::now()).await.err().unwrap();
        assert!(matches!(e, AuthError::Acquisition(_)), "{e:?}");
        assert!(issuer.grants.lock().iter().all(|g| g == "refresh_token"));
    }

    #[tokio::test]
    async fn client_credentials_refresh_failure_still_falls_back() {
        let issuer = FakeIssuer::new(); // refresh fails
        let cache = TokenCache::new();
        cache.insert(&key(&cfg()), expired_with_refresh("rt-1"));
        let t = cache.get_or_acquire(&key(&cfg()), &cfg(), &issuer, Utc::now()).await.unwrap();
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
