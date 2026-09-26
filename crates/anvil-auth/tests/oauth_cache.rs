//! Token-cache identity and generations: a cached token is only ever reused
//! for the exact grant, audience, client, scope, issuer, authorization URL
//! and token-cache identity it was issued for; a clear (lock), a forget
//! (sign-out) or a new sign-in wins over every acquisition still in flight,
//! and a send overtaken only by a sign-in is served with its token; a refresh
//! finishes even when its caller stops waiting, unless a lock or a sign-out
//! aborts it.

use anvil_auth::AuthError;
use anvil_auth::oauth::{BoxFut, CachedToken, OAuthResolved, TokenCache, TokenHttp, TokenKey};
use anvil_domain::Id;
use anvil_domain::auth::OAuthGrant;
use chrono::{Duration, Utc};
use std::ops::Deref;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::Notify;
use zeroize::Zeroizing;

/// Scriptable issuer. With a gate, every token request reports that it
/// arrived and then waits until the test releases it. A handle: token
/// requests share its state and borrow nothing.
#[derive(Clone, Default)]
struct Issuer(Arc<IssuerState>);

#[derive(Default)]
struct IssuerState {
    calls: AtomicU64,
    completed: AtomicU64,
    forms: Mutex<Vec<Vec<(String, String)>>>,
    gated: AtomicBool,
    received: Notify,
    release: Notify,
    down: AtomicBool,
    /// Answer with a new refresh token (`rt-<n>`), as a rotating issuer does.
    rotate: AtomicBool,
}

impl Deref for Issuer {
    type Target = IssuerState;

    fn deref(&self) -> &IssuerState {
        &self.0
    }
}

impl Issuer {
    fn gated() -> Self {
        let issuer = Issuer::default();
        issuer.gated.store(true, Ordering::SeqCst);
        issuer
    }

    fn down() -> Self {
        let issuer = Issuer::default();
        issuer.down.store(true, Ordering::SeqCst);
        issuer
    }

    fn form_value(&self, request: usize, name: &str) -> Option<String> {
        self.forms.lock().unwrap().get(request)?.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone())
    }
}

impl TokenHttp for Issuer {
    fn post_form(
        &self,
        _url: &str,
        form: Vec<(String, String)>,
        _basic: Option<(String, String)>,
    ) -> BoxFut<'static, Result<(u16, Vec<u8>), String>> {
        let state = self.0.clone();
        Box::pin(async move {
            let n = state.calls.fetch_add(1, Ordering::SeqCst) + 1;
            state.forms.lock().unwrap().push(form);
            if state.gated.load(Ordering::SeqCst) {
                state.received.notify_one();
                state.release.notified().await;
            }
            state.completed.fetch_add(1, Ordering::SeqCst);
            if state.down.load(Ordering::SeqCst) {
                return Err("connect refused".into());
            }
            let refresh = if state.rotate.load(Ordering::SeqCst) { format!(r#","refresh_token":"rt-{n}""#) } else { String::new() };
            Ok((200, format!(r#"{{"access_token":"t{n}","token_type":"Bearer","expires_in":3600{refresh}}}"#).into_bytes()))
        })
    }
}

fn client_credentials(audience: &str) -> OAuthResolved {
    OAuthResolved {
        grant: OAuthGrant::ClientCredentials,
        token_url: "http://issuer.test/token".into(),
        authorization_url: "http://issuer.test/authorize".into(),
        client_id: "client".into(),
        client_secret: Zeroizing::new("secret".into()),
        scope: "api.read".into(),
        audience: audience.into(),
        basic_client_auth: true,
        token_cache_id: None,
        refresh_skew_secs: 30,
    }
}

fn pkce(audience: &str) -> OAuthResolved {
    OAuthResolved { grant: OAuthGrant::AuthorizationCodePkce, client_secret: Zeroizing::new(String::new()), ..client_credentials(audience) }
}

fn key(cfg: &OAuthResolved) -> TokenKey {
    TokenKey::new("workspace", cfg)
}

fn signed_in(access: &str, refresh: &str, expired: bool) -> CachedToken {
    let offset = if expired { -10 } else { 3600 };
    CachedToken {
        access_token: Zeroizing::new(access.into()),
        token_type: "Bearer".into(),
        expires_at: Some(Utc::now() + Duration::seconds(offset)),
        refresh_token: Some(Zeroizing::new(refresh.into())),
    }
}

/// Store a completed sign-in, as the authorization-code redemption does.
fn sign_in(cache: &TokenCache, cfg: &OAuthResolved, t: CachedToken) {
    let k = key(cfg);
    assert!(cache.store_sign_in(&k, cache.generation(&k), t), "nothing superseded this sign-in");
}

async fn acquire(cache: &TokenCache, cfg: &OAuthResolved, issuer: &Issuer) -> Result<String, AuthError> {
    cache.get_or_acquire(&key(cfg), cfg, issuer, Utc::now()).await.map(|t| t.access_token.to_string())
}

/// Let spawned tasks on this (current-thread) runtime run until they block.
async fn settle() {
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
}

// ---------------------------------------------------------------- identity ---

#[test]
fn key_changes_with_every_input_that_decides_the_token() {
    let base = pkce("api-a");
    let variants: Vec<(&str, OAuthResolved)> = vec![
        ("grant", OAuthResolved { grant: OAuthGrant::ClientCredentials, ..base.clone() }),
        ("grant", OAuthResolved { grant: OAuthGrant::RefreshToken, ..base.clone() }),
        ("audience", OAuthResolved { audience: "api-b".into(), ..base.clone() }),
        ("scope", OAuthResolved { scope: "api.write".into(), ..base.clone() }),
        ("token URL", OAuthResolved { token_url: "http://other-issuer.test/token".into(), ..base.clone() }),
        ("client id", OAuthResolved { client_id: "other".into(), ..base.clone() }),
        ("client auth", OAuthResolved { basic_client_auth: false, ..base.clone() }),
        ("token cache id", OAuthResolved { token_cache_id: Some(Id::new()), ..base.clone() }),
        ("authorization URL", OAuthResolved { authorization_url: "http://issuer.test/authorize?org=b".into(), ..base.clone() }),
    ];
    for (what, v) in &variants {
        assert_ne!(key(&base), key(v), "a different {what} must not share the cached token");
    }
    assert_ne!(TokenKey::new("workspace-a", &base), TokenKey::new("workspace-b", &base), "partitions are separate");
    // Refresh timing does not change what the token authorizes.
    assert_eq!(key(&base), key(&OAuthResolved { refresh_skew_secs: 120, ..base.clone() }));
    // Client credentials never visit the authorization endpoint.
    let cc = client_credentials("api-a");
    assert_eq!(key(&cc), key(&OAuthResolved { authorization_url: "http://elsewhere.test/authorize".into(), ..cc.clone() }));
}

#[tokio::test]
async fn profiles_that_differ_only_in_authorization_url_do_not_share_a_sign_in() {
    let issuer = Issuer::default();
    let cache = TokenCache::new();
    // Same issuer, client, scope and audience; the authorization URL picks
    // the organization (Auth0 `organization`, Keycloak `kc_idp_hint`, …).
    let org_a = OAuthResolved { authorization_url: "http://issuer.test/authorize?organization=org-a".into(), ..pkce("api-a") };
    let org_b = OAuthResolved { authorization_url: "http://issuer.test/authorize?organization=org-b".into(), ..pkce("api-a") };
    sign_in(&cache, &org_a, signed_in("org-a-token", "org-a-rt", false));
    assert_eq!(acquire(&cache, &org_a, &issuer).await.unwrap(), "org-a-token");
    let e = acquire(&cache, &org_b, &issuer).await.expect_err("nobody signed in through org-b");
    assert!(matches!(e, AuthError::InteractionRequired(_)), "{e:?}");
    assert_eq!(issuer.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn client_credentials_token_is_never_reused_for_an_interactive_profile() {
    let issuer = Issuer::default();
    let cache = TokenCache::new();
    assert_eq!(acquire(&cache, &client_credentials("api-a"), &issuer).await.unwrap(), "t1");

    // Same issuer, client, scope and partition; only grant (and audience) differ.
    for cfg in [pkce("api-a"), pkce("api-b")] {
        let e = acquire(&cache, &cfg, &issuer).await.expect_err("an interactive profile needs its own sign-in");
        assert!(matches!(e, AuthError::InteractionRequired(_)), "{e:?}");
    }
    assert_eq!(issuer.calls.load(Ordering::SeqCst), 1, "no token request for the interactive profile");
}

#[tokio::test]
async fn audience_switch_acquires_a_separate_token() {
    let issuer = Issuer::default();
    let cache = TokenCache::new();
    assert_eq!(acquire(&cache, &client_credentials("api-a"), &issuer).await.unwrap(), "t1");
    assert_eq!(acquire(&cache, &client_credentials("api-b"), &issuer).await.unwrap(), "t2");
    assert_eq!(issuer.form_value(1, "audience").as_deref(), Some("api-b"), "the second token was requested for api-b");
    // Both stay cached, each under its own audience.
    assert_eq!(acquire(&cache, &client_credentials("api-a"), &issuer).await.unwrap(), "t1");
    assert_eq!(acquire(&cache, &client_credentials("api-b"), &issuer).await.unwrap(), "t2");
    assert_eq!(issuer.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn profiles_with_different_token_cache_ids_do_not_share_a_sign_in() {
    let issuer = Issuer::default();
    let cache = TokenCache::new();
    let alice = OAuthResolved { token_cache_id: Some(Id::new()), ..pkce("api-a") };
    let bob = OAuthResolved { token_cache_id: Some(Id::new()), ..pkce("api-a") };
    sign_in(&cache, &alice, signed_in("alice-token", "alice-rt", false));
    assert_eq!(acquire(&cache, &alice, &issuer).await.unwrap(), "alice-token");
    let e = acquire(&cache, &bob, &issuer).await.expect_err("bob has not signed in");
    assert!(matches!(e, AuthError::InteractionRequired(_)), "{e:?}");
    assert_eq!(issuer.calls.load(Ordering::SeqCst), 0);
}

// ------------------------------------------------------------- generations ---

#[tokio::test]
async fn clear_during_acquisition_discards_the_late_token() {
    let issuer = Arc::new(Issuer::gated());
    let cache = Arc::new(TokenCache::new());
    let cfg = client_credentials("api-a");
    let task = {
        let (cache, issuer, cfg) = (cache.clone(), issuer.clone(), cfg.clone());
        tokio::spawn(async move { acquire(&cache, &cfg, &issuer).await })
    };
    issuer.received.notified().await;
    cache.clear(); // lock
    issuer.release.notify_one();
    let e = task.await.unwrap().expect_err("an acquisition that straddles a clear must not succeed");
    assert!(matches!(e, AuthError::Canceled(_)), "{e:?}");
    assert_eq!(issuer.completed.load(Ordering::SeqCst), 1, "the issuer did answer");
    assert!(cache.get(&key(&cfg)).is_none(), "the late token did not repopulate the cleared cache");

    // With the issuer gone, nothing cached can be sent.
    let down = Issuer::down();
    let e = acquire(&cache, &cfg, &down).await.expect_err("no cached token after the clear");
    assert!(matches!(e, AuthError::Acquisition(_)), "{e:?}");
}

#[tokio::test]
async fn sign_out_during_refresh_discards_the_late_token() {
    let issuer = Arc::new(Issuer::gated());
    let cache = Arc::new(TokenCache::new());
    let cfg = pkce("api-a");
    sign_in(&cache, &cfg, signed_in("old", "rt-1", true));
    let task = {
        let (cache, issuer, cfg) = (cache.clone(), issuer.clone(), cfg.clone());
        tokio::spawn(async move { acquire(&cache, &cfg, &issuer).await })
    };
    issuer.received.notified().await;
    assert_eq!(issuer.form_value(0, "grant_type").as_deref(), Some("refresh_token"));
    assert!(cache.remove(&key(&cfg)), "sign-out forgets the cached token");
    issuer.release.notify_one();
    let e = task.await.unwrap().expect_err("a refresh that straddles a sign-out must not succeed");
    assert!(matches!(e, AuthError::Canceled(_)), "{e:?}");
    assert!(cache.get(&key(&cfg)).is_none(), "the refreshed token was not stored after sign-out");
    let e = acquire(&cache, &cfg, &issuer).await.expect_err("signed out");
    assert!(matches!(e, AuthError::InteractionRequired(_)), "{e:?}");
}

#[tokio::test]
async fn waiters_that_started_before_a_clear_are_not_served_after_it() {
    let issuer = Arc::new(Issuer::gated());
    let cache = Arc::new(TokenCache::new());
    let cfg = client_credentials("api-a");
    let spawn = || {
        let (cache, issuer, cfg) = (cache.clone(), issuer.clone(), cfg.clone());
        tokio::spawn(async move { acquire(&cache, &cfg, &issuer).await })
    };
    let holder = spawn();
    issuer.received.notified().await;
    let waiters: Vec<_> = (0..5).map(|_| spawn()).collect();
    settle().await; // the waiters are queued on the single-flight lock
    cache.clear();
    issuer.release.notify_one();
    assert!(matches!(holder.await.unwrap(), Err(AuthError::Canceled(_))));
    for w in waiters {
        let r = w.await.unwrap();
        assert!(matches!(r, Err(AuthError::Canceled(_))), "{r:?}");
    }
    assert_eq!(issuer.calls.load(Ordering::SeqCst), 1, "waiters did not start their own request after the clear");
    assert!(cache.get(&key(&cfg)).is_none());
}

#[tokio::test]
async fn sign_out_of_one_profile_leaves_other_acquisitions_alone() {
    let issuer = Arc::new(Issuer::gated());
    let cache = Arc::new(TokenCache::new());
    let cfg = client_credentials("api-a");
    let other = pkce("api-b");
    sign_in(&cache, &other, signed_in("other", "rt", false));
    let task = {
        let (cache, issuer, cfg) = (cache.clone(), issuer.clone(), cfg.clone());
        tokio::spawn(async move { acquire(&cache, &cfg, &issuer).await })
    };
    issuer.received.notified().await;
    assert!(cache.remove(&key(&other)));
    issuer.release.notify_one();
    assert_eq!(task.await.unwrap().unwrap(), "t1");
    assert!(cache.get(&key(&cfg)).is_some());
}

#[tokio::test]
async fn dropping_an_acquisition_abandons_the_request_and_caches_nothing() {
    let issuer = Arc::new(Issuer::gated());
    let cache = Arc::new(TokenCache::new());
    let cfg = client_credentials("api-a");
    tokio::select! {
        r = acquire(&cache, &cfg, &issuer) => panic!("the gated issuer never answered: {r:?}"),
        _ = issuer.received.notified() => {} // cancel as soon as the request is out
    }
    issuer.release.notify_one();
    settle().await;
    assert_eq!(issuer.completed.load(Ordering::SeqCst), 0, "the abandoned request was not awaited to completion");
    assert!(cache.get(&key(&cfg)).is_none());

    // The single-flight lock was released with the dropped call.
    let fresh = Issuer::default();
    assert_eq!(acquire(&cache, &cfg, &fresh).await.unwrap(), "t1");
}

#[test]
fn insert_if_current_refuses_results_from_an_older_generation() {
    let cache = TokenCache::new();
    let (a, b) = (key(&pkce("api-a")), key(&pkce("api-b")));

    let g = cache.generation(&a);
    cache.clear();
    assert!(!cache.insert_if_current(&a, g, signed_in("late", "rt", false)), "a lock in between wins");
    assert!(cache.get(&a).is_none());

    let g = cache.generation(&a);
    cache.remove(&a);
    assert!(!cache.insert_if_current(&a, g, signed_in("late", "rt", false)), "a sign-out in between wins");
    assert!(cache.get(&a).is_none());

    let g = cache.generation(&a);
    cache.remove(&b);
    assert!(cache.insert_if_current(&a, g, signed_in("fresh", "rt", false)), "another profile's sign-out is unrelated");
    assert_eq!(cache.get(&a).unwrap().access_token.as_str(), "fresh");
}

// ---------------------------------------------------------------- sign-ins ---

#[test]
fn a_sign_in_that_straddles_a_lock_or_sign_out_is_discarded() {
    let cache = TokenCache::new();
    let k = key(&pkce("api-a"));

    let g = cache.generation(&k);
    cache.clear();
    assert!(!cache.store_sign_in(&k, g, signed_in("late", "rt", false)), "a lock during the sign-in wins");
    assert!(cache.get(&k).is_none());

    let g = cache.generation(&k);
    cache.remove(&k);
    assert!(!cache.store_sign_in(&k, g, signed_in("late", "rt", false)), "a sign-out during the sign-in wins");
    assert!(cache.get(&k).is_none());

    let g = cache.generation(&k);
    assert!(cache.store_sign_in(&k, g, signed_in("fresh", "rt", false)));
    assert_eq!(cache.get(&k).unwrap().access_token.as_str(), "fresh");
    assert_ne!(cache.generation(&k), g, "storing a sign-in starts a new generation");
    assert!(!cache.insert_if_current(&k, g, signed_in("older", "rt", false)), "work from before the sign-in cannot overwrite it");
    assert_eq!(cache.get(&k).unwrap().access_token.as_str(), "fresh");
}

#[tokio::test]
async fn an_older_refresh_never_overwrites_a_newer_sign_in() {
    let issuer = Arc::new(Issuer::gated());
    issuer.rotate.store(true, Ordering::SeqCst);
    let cache = Arc::new(TokenCache::new());
    let cfg = pkce("api-a");
    sign_in(&cache, &cfg, signed_in("old", "rt-0", true));
    let task = {
        let (cache, issuer, cfg) = (cache.clone(), issuer.clone(), cfg.clone());
        tokio::spawn(async move { acquire(&cache, &cfg, &issuer).await })
    };
    issuer.received.notified().await;
    // The user signs in again while the refresh is in flight.
    sign_in(&cache, &cfg, signed_in("new-sign-in", "rt-new", false));
    issuer.release.notify_one();
    // The refreshed token is discarded; the send is served by the sign-in.
    assert_eq!(task.await.unwrap().unwrap(), "new-sign-in");
    assert_eq!(issuer.completed.load(Ordering::SeqCst), 1, "the issuer did answer");
    let stored = cache.get(&key(&cfg)).unwrap();
    assert_eq!(stored.access_token.as_str(), "new-sign-in", "the late refresh did not overwrite the sign-in");
    assert_eq!(stored.refresh_token.as_ref().map(|rt| rt.as_str()), Some("rt-new"));
    assert_eq!(acquire(&cache, &cfg, &issuer).await.unwrap(), "new-sign-in");
    assert_eq!(issuer.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_send_that_waited_through_a_sign_in_is_served_by_it() {
    let issuer = Arc::new(Issuer::gated());
    issuer.rotate.store(true, Ordering::SeqCst);
    let cache = Arc::new(TokenCache::new());
    let cfg = pkce("api-a");
    sign_in(&cache, &cfg, signed_in("old", "rt-0", true));
    let spawn = || {
        let (cache, issuer, cfg) = (cache.clone(), issuer.clone(), cfg.clone());
        tokio::spawn(async move { acquire(&cache, &cfg, &issuer).await })
    };
    let refreshing = spawn();
    issuer.received.notified().await;
    let waiter = spawn();
    settle().await; // the waiter found the expired token and queued on the single-flight lock
    sign_in(&cache, &cfg, signed_in("new-sign-in", "rt-new", false));
    issuer.release.notify_one();
    assert_eq!(refreshing.await.unwrap().unwrap(), "new-sign-in");
    assert_eq!(waiter.await.unwrap().unwrap(), "new-sign-in", "a sign-in alone does not cancel a waiting send");
    assert_eq!(issuer.calls.load(Ordering::SeqCst), 1, "the waiter did not refresh again");
    assert_eq!(cache.get(&key(&cfg)).unwrap().access_token.as_str(), "new-sign-in");
}

#[tokio::test]
async fn a_send_that_waited_through_a_sign_in_and_a_sign_out_is_canceled() {
    let issuer = Arc::new(Issuer::gated());
    let cache = Arc::new(TokenCache::new());
    let cfg = client_credentials("api-a");
    let spawn = || {
        let (cache, issuer, cfg) = (cache.clone(), issuer.clone(), cfg.clone());
        tokio::spawn(async move { acquire(&cache, &cfg, &issuer).await })
    };
    let holder = spawn();
    issuer.received.notified().await;
    let waiter = spawn();
    settle().await;
    assert!(!cache.remove(&key(&cfg)));
    sign_in(&cache, &cfg, signed_in("after-sign-out", "rt", false));
    issuer.release.notify_one();
    for task in [holder, waiter] {
        let r = task.await.unwrap();
        assert!(matches!(r, Err(AuthError::Canceled(_))), "a sign-out in between still wins: {r:?}");
    }
    assert_eq!(issuer.calls.load(Ordering::SeqCst), 1);
}

// ------------------------------------------------------ abandoned refresh ---

#[tokio::test]
async fn a_refresh_whose_caller_stops_waiting_still_stores_the_rotated_token() {
    let issuer = Arc::new(Issuer::gated());
    issuer.rotate.store(true, Ordering::SeqCst);
    let cache = Arc::new(TokenCache::new());
    let cfg = pkce("api-a");
    sign_in(&cache, &cfg, signed_in("old", "rt-0", true));
    tokio::select! {
        r = acquire(&cache, &cfg, &issuer) => panic!("the gated issuer never answered: {r:?}"),
        _ = issuer.received.notified() => {} // the caller stops waiting once the refresh is out
    }
    assert_eq!(issuer.form_value(0, "refresh_token").as_deref(), Some("rt-0"));

    // A send that arrives meanwhile waits for that refresh instead of
    // presenting the refresh token the issuer is rotating a second time.
    let waiter = {
        let (cache, issuer, cfg) = (cache.clone(), issuer.clone(), cfg.clone());
        tokio::spawn(async move { acquire(&cache, &cfg, &issuer).await })
    };
    settle().await;
    issuer.release.notify_one();
    assert_eq!(waiter.await.unwrap().unwrap(), "t1");
    assert_eq!(issuer.calls.load(Ordering::SeqCst), 1, "rt-0 was presented once");
    let stored = cache.get(&key(&cfg)).expect("the abandoned refresh stored its token");
    assert_eq!(stored.access_token.as_str(), "t1");
    assert_eq!(stored.refresh_token.as_ref().map(|rt| rt.as_str()), Some("rt-1"), "the rotated refresh token was kept");
}

#[tokio::test]
async fn a_refresh_whose_caller_stopped_waiting_loses_to_a_lock() {
    let issuer = Arc::new(Issuer::gated());
    issuer.rotate.store(true, Ordering::SeqCst);
    let cache = Arc::new(TokenCache::new());
    let cfg = pkce("api-a");
    sign_in(&cache, &cfg, signed_in("old", "rt-0", true));
    tokio::select! {
        r = acquire(&cache, &cfg, &issuer) => panic!("the gated issuer never answered: {r:?}"),
        _ = issuer.received.notified() => {}
    }
    cache.clear(); // lock
    settle().await;
    issuer.release.notify_one();
    settle().await;
    assert_eq!(issuer.completed.load(Ordering::SeqCst), 0, "the lock aborted the refresh before the issuer answered");
    assert!(cache.get(&key(&cfg)).is_none(), "the late refresh did not repopulate the cleared cache");
    let e = acquire(&cache, &cfg, &issuer).await.expect_err("locked: a new sign-in is needed");
    assert!(matches!(e, AuthError::InteractionRequired(_)), "{e:?}");
    assert_eq!(issuer.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn sign_out_aborts_a_detached_refresh_and_frees_its_lock() {
    let issuer = Arc::new(Issuer::gated());
    let cache = Arc::new(TokenCache::new());
    let cfg = pkce("api-a");
    sign_in(&cache, &cfg, signed_in("old", "rt-0", true));
    tokio::select! {
        r = acquire(&cache, &cfg, &issuer) => panic!("the gated issuer never answered: {r:?}"),
        _ = issuer.received.notified() => {} // the caller stops waiting; the refresh is detached
    }
    assert!(cache.remove(&key(&cfg)), "sign-out");
    settle().await;
    issuer.release.notify_one();
    settle().await;
    assert_eq!(issuer.completed.load(Ordering::SeqCst), 0, "the sign-out aborted the refresh before the issuer answered");
    assert!(cache.get(&key(&cfg)).is_none());

    // The aborted refresh released the single-flight lock: a new sign-in
    // refreshes at once with its own refresh token.
    issuer.gated.store(false, Ordering::SeqCst);
    sign_in(&cache, &cfg, signed_in("expired-again", "rt-new", true));
    assert_eq!(acquire(&cache, &cfg, &issuer).await.unwrap(), "t2");
    assert_eq!(issuer.form_value(1, "refresh_token").as_deref(), Some("rt-new"));
}

#[tokio::test]
async fn a_lock_aborts_a_refresh_its_caller_is_waiting_for() {
    let issuer = Arc::new(Issuer::gated());
    let cache = Arc::new(TokenCache::new());
    let cfg = pkce("api-a");
    sign_in(&cache, &cfg, signed_in("old", "rt-0", true));
    let task = {
        let (cache, issuer, cfg) = (cache.clone(), issuer.clone(), cfg.clone());
        tokio::spawn(async move { acquire(&cache, &cfg, &issuer).await })
    };
    issuer.received.notified().await;
    cache.clear();
    // Ends without the issuer ever answering.
    let e = task.await.unwrap().expect_err("a lock aborts the refresh");
    assert!(matches!(e, AuthError::Canceled(_)), "{e:?}");
    assert_eq!(issuer.completed.load(Ordering::SeqCst), 0);
}
