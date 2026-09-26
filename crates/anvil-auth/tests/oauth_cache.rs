//! Token-cache identity and generations: a cached token is only ever reused
//! for the exact grant, audience, client, scope, issuer and token-cache
//! identity it was issued for, and a clear (lock) or forget (sign-out) wins
//! over every acquisition still in flight.

use anvil_auth::AuthError;
use anvil_auth::oauth::{BoxFut, CachedToken, OAuthResolved, TokenCache, TokenHttp, TokenKey};
use anvil_domain::Id;
use anvil_domain::auth::OAuthGrant;
use chrono::{Duration, Utc};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::Notify;
use zeroize::Zeroizing;

/// Scriptable issuer. With a gate, every token request reports that it
/// arrived and then waits until the test releases it.
#[derive(Default)]
struct Issuer {
    calls: AtomicU64,
    completed: AtomicU64,
    forms: Mutex<Vec<Vec<(String, String)>>>,
    gated: bool,
    received: Notify,
    release: Notify,
    down: AtomicBool,
}

impl Issuer {
    fn gated() -> Self {
        Issuer { gated: true, ..Issuer::default() }
    }

    fn form_value(&self, request: usize, name: &str) -> Option<String> {
        self.forms.lock().unwrap().get(request)?.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone())
    }
}

impl TokenHttp for Issuer {
    fn post_form<'a>(
        &'a self,
        _url: &'a str,
        form: Vec<(String, String)>,
        _basic: Option<(String, String)>,
    ) -> BoxFut<'a, Result<(u16, Vec<u8>), String>> {
        Box::pin(async move {
            let n = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
            self.forms.lock().unwrap().push(form);
            if self.gated {
                self.received.notify_one();
                self.release.notified().await;
            }
            self.completed.fetch_add(1, Ordering::SeqCst);
            if self.down.load(Ordering::SeqCst) {
                return Err("connect refused".into());
            }
            Ok((200, format!(r#"{{"access_token":"t{n}","token_type":"Bearer","expires_in":3600}}"#).into_bytes()))
        })
    }
}

fn client_credentials(audience: &str) -> OAuthResolved {
    OAuthResolved {
        grant: OAuthGrant::ClientCredentials,
        token_url: "http://issuer.test/token".into(),
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
    ];
    for (what, v) in &variants {
        assert_ne!(key(&base), key(v), "a different {what} must not share the cached token");
    }
    assert_ne!(TokenKey::new("workspace-a", &base), TokenKey::new("workspace-b", &base), "partitions are separate");
    // Refresh timing does not change what the token authorizes.
    assert_eq!(key(&base), key(&OAuthResolved { refresh_skew_secs: 120, ..base.clone() }));
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
    cache.insert(&key(&alice), signed_in("alice-token", "alice-rt", false));
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
    let down = Issuer { down: AtomicBool::new(true), ..Issuer::default() };
    let e = acquire(&cache, &cfg, &down).await.expect_err("no cached token after the clear");
    assert!(matches!(e, AuthError::Acquisition(_)), "{e:?}");
}

#[tokio::test]
async fn sign_out_during_refresh_discards_the_late_token() {
    let issuer = Arc::new(Issuer::gated());
    let cache = Arc::new(TokenCache::new());
    let cfg = pkce("api-a");
    cache.insert(&key(&cfg), signed_in("old", "rt-1", true));
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
    cache.insert(&key(&other), signed_in("other", "rt", false));
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
