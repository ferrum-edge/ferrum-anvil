//! Token lifetimes from the token endpoint: an `expires_in` the issuer sends
//! is checked before any date arithmetic, so an unrepresentable or malformed
//! value is a typed acquisition failure (never a panic, never a token that
//! does not expire), and a response without one gets a bounded default.

use anvil_auth::AuthError;
use anvil_auth::oauth::{
    BoxFut, CachedToken, DEFAULT_EXPIRES_IN_SECS, MAX_EXPIRES_IN_SECS, OAuthResolved, TokenCache, TokenHttp, TokenKey,
    client_credentials, exchange_code, refresh,
};
use anvil_domain::auth::OAuthGrant;
use chrono::{DateTime, Duration, Utc};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use zeroize::Zeroizing;

/// Answers every token request with HTTP 200 and `body`.
#[derive(Clone)]
struct FixedIssuer {
    body: String,
    calls: Arc<AtomicU64>,
}

impl FixedIssuer {
    fn new(body: impl Into<String>) -> Self {
        FixedIssuer { body: body.into(), calls: Arc::default() }
    }

    /// A token response whose `expires_in` member is `expires_in` (raw JSON),
    /// or has no `expires_in` at all.
    fn expiring(expires_in: Option<&str>) -> Self {
        let expires_in = expires_in.map(|e| format!(r#","expires_in":{e}"#)).unwrap_or_default();
        Self::new(format!(r#"{{"access_token":"at","token_type":"Bearer","refresh_token":"rt-next"{expires_in}}}"#))
    }
}

impl TokenHttp for FixedIssuer {
    fn post_form(
        &self,
        _url: &str,
        _form: Vec<(String, String)>,
        _basic: Option<(String, String)>,
    ) -> BoxFut<'static, Result<(u16, Vec<u8>), String>> {
        let (body, calls) = (self.body.clone(), self.calls.clone());
        Box::pin(async move {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok((200, body.into_bytes()))
        })
    }
}

fn cfg(grant: OAuthGrant) -> OAuthResolved {
    OAuthResolved {
        grant,
        token_url: "http://issuer.test/token".into(),
        authorization_url: "http://issuer.test/authorize".into(),
        client_id: "client".into(),
        client_secret: Zeroizing::new("secret".into()),
        scope: String::new(),
        audience: String::new(),
        basic_client_auth: true,
        token_cache_id: None,
        refresh_skew_secs: 30,
    }
}

/// Every public way a token response is acquired, each on a task of its own
/// so a panic shows up as a join error instead of ending the test.
async fn acquire_all_ways(issuer: &FixedIssuer) -> Vec<(&'static str, Result<CachedToken, AuthError>)> {
    let mut out = vec![];
    for way in ["client_credentials", "refresh", "exchange_code"] {
        let issuer = issuer.clone();
        let joined = tokio::spawn(async move {
            match way {
                "client_credentials" => client_credentials(&cfg(OAuthGrant::ClientCredentials), &issuer).await,
                "refresh" => refresh(&cfg(OAuthGrant::AuthorizationCodePkce), "rt", &issuer).await,
                _ => exchange_code(&cfg(OAuthGrant::AuthorizationCodePkce), "code", "verifier", "http://127.0.0.1:1/cb", &issuer).await,
            }
        })
        .await;
        match joined {
            Ok(r) => out.push((way, r)),
            Err(e) => panic!("{way}: acquiring the token panicked: {e}"),
        }
    }
    out
}

fn assert_expires_in(t: &CachedToken, before: DateTime<Utc>, after: DateTime<Utc>, secs: i64) {
    let e = t.expires_at.expect("every acquired token has an expiry");
    assert!(before + Duration::seconds(secs) <= e && e <= after + Duration::seconds(secs), "expires_at {e} is not issue time + {secs}s");
}

#[tokio::test]
async fn unrepresentable_or_malformed_expires_in_is_a_typed_acquisition_error() {
    let over = (MAX_EXPIRES_IN_SECS + 1).to_string();
    let over_str = format!("\"{over}\"");
    let cases = [
        // i64::MAX: out of range for a duration.
        "9223372036854775807",
        // A duration, but past the last representable date.
        "10000000000000",
        // u64::MAX, then a number that does not fit u64.
        "18446744073709551615",
        "18446744073709551616",
        over.as_str(),
        over_str.as_str(),
        "-1",
        "-9223372036854775808",
        "3600.5",
        "1e3",
        "true",
        "{}",
        "[]",
        "\"\"",
        "\"soon\"",
        "\"-60\"",
        "\"+60\"",
        "\" 60\"",
    ];
    for raw in cases {
        let issuer = FixedIssuer::expiring(Some(raw));
        for (way, r) in acquire_all_ways(&issuer).await {
            match r {
                Err(AuthError::Acquisition(m)) => assert!(m.contains("expires_in"), "{way} with expires_in {raw}: {m}"),
                Err(e) => panic!("{way} with expires_in {raw}: expected an acquisition error, got {e:?}"),
                Ok(t) => panic!("{way} with expires_in {raw}: accepted, expires_at {:?}", t.expires_at),
            }
        }
    }
}

#[tokio::test]
async fn omitted_or_null_expires_in_gets_the_bounded_default() {
    let default = DEFAULT_EXPIRES_IN_SECS as i64;
    for raw in [None, Some("null")] {
        let before = Utc::now();
        let results = acquire_all_ways(&FixedIssuer::expiring(raw)).await;
        let after = Utc::now();
        for (way, r) in results {
            let t = r.unwrap_or_else(|e| panic!("{way} with expires_in {raw:?}: {e:?}"));
            assert_expires_in(&t, before, after, default);
            assert!(t.usable(after, 0), "{way}: usable right after it was issued");
            assert!(!t.usable(after + Duration::seconds(default + 1), 0), "{way}: not usable forever");
            assert_eq!(t.refresh_token.as_ref().map(|rt| rt.as_str()), Some("rt-next"));
        }
    }
}

#[tokio::test]
async fn whole_seconds_as_a_number_or_a_decimal_string_are_accepted() {
    let max = MAX_EXPIRES_IN_SECS.to_string();
    for (raw, secs) in [("3600", 3600), ("\"3600\"", 3600), ("0", 0), (max.as_str(), MAX_EXPIRES_IN_SECS as i64)] {
        let before = Utc::now();
        let results = acquire_all_ways(&FixedIssuer::expiring(Some(raw))).await;
        let after = Utc::now();
        for (way, r) in results {
            let t = r.unwrap_or_else(|e| panic!("{way} with expires_in {raw}: {e:?}"));
            assert_expires_in(&t, before, after, secs);
            assert!(!t.usable(after + Duration::seconds(secs + 1), 0), "{way} with expires_in {raw}: expires");
        }
    }
}

#[test]
fn a_token_without_a_usable_expiry_is_never_reused() {
    let now = Utc::now();
    let t = |expires_at| CachedToken {
        access_token: Zeroizing::new("at".into()),
        token_type: "Bearer".into(),
        expires_at,
        refresh_token: None,
    };
    assert!(!t(None).usable(now, 0), "no expiry is not a token that never expires");
    let valid = t(Some(now + Duration::seconds(3600)));
    assert!(valid.usable(now, 30));
    assert!(!valid.usable(now, 3600));
    // A skew no date can represent does not panic; the token is refreshed.
    assert!(!valid.usable(now, i64::MAX));
    assert!(!t(Some(DateTime::<Utc>::MAX_UTC)).usable(DateTime::<Utc>::MAX_UTC, 1));
}

#[tokio::test]
async fn the_cache_never_stores_a_non_expiring_or_malformed_token() {
    let cc = cfg(OAuthGrant::ClientCredentials);
    let key = TokenKey::new("workspace", &cc);

    let cache = TokenCache::new();
    let e = cache.get_or_acquire(&key, &cc, &FixedIssuer::expiring(Some("18446744073709551615")), Utc::now()).await;
    assert!(matches!(e, Err(AuthError::Acquisition(_))), "{:?}", e.map(|t| t.expires_at));
    assert!(cache.get(&key).is_none(), "the malformed token was not cached");

    let issuer = FixedIssuer::expiring(None);
    let before = Utc::now();
    cache.get_or_acquire(&key, &cc, &issuer, Utc::now()).await.unwrap();
    let after = Utc::now();
    let cached = cache.get(&key).expect("cached");
    assert_expires_in(&cached, before, after, DEFAULT_EXPIRES_IN_SECS as i64);
    // Reused while fresh.
    cache.get_or_acquire(&key, &cc, &issuer, Utc::now()).await.unwrap();
    assert_eq!(issuer.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_refresh_answered_with_a_malformed_expiry_keeps_the_refresh_token() {
    let pkce = cfg(OAuthGrant::AuthorizationCodePkce);
    let key = TokenKey::new("workspace", &pkce);
    let cache = TokenCache::new();
    let expired = CachedToken {
        access_token: Zeroizing::new("old".into()),
        token_type: "Bearer".into(),
        expires_at: Some(Utc::now() - Duration::seconds(10)),
        refresh_token: Some(Zeroizing::new("rt-0".into())),
    };
    assert!(cache.store_sign_in(&key, cache.generation(&key), expired));

    let issuer = FixedIssuer::expiring(Some("9223372036854775807"));
    let e = cache.get_or_acquire(&key, &pkce, &issuer, Utc::now()).await;
    assert!(matches!(e, Err(AuthError::Acquisition(_))), "a malformed answer is an issuer failure: {:?}", e.map(|t| t.expires_at));
    let kept = cache.get(&key).expect("the entry is kept for a later attempt");
    assert_eq!(kept.access_token.as_str(), "old");
    assert_eq!(kept.refresh_token.as_ref().map(|rt| rt.as_str()), Some("rt-0"));

    // A well-formed answer then refreshes normally.
    let fixed = FixedIssuer::expiring(Some("600"));
    let t = cache.get_or_acquire(&key, &pkce, &fixed, Utc::now()).await.unwrap();
    assert_eq!(t.access_token.as_str(), "at");
    assert_eq!(t.refresh_token.as_ref().map(|rt| rt.as_str()), Some("rt-next"));
}

#[tokio::test]
async fn client_credentials_falls_back_when_a_refresh_answer_is_malformed() {
    let cc = cfg(OAuthGrant::ClientCredentials);
    let key = TokenKey::new("workspace", &cc);
    let cache = TokenCache::new();
    let expired = CachedToken {
        access_token: Zeroizing::new("old".into()),
        token_type: "Bearer".into(),
        expires_at: Some(Utc::now() - Duration::seconds(10)),
        refresh_token: Some(Zeroizing::new("rt-0".into())),
    };
    assert!(cache.store_sign_in(&key, cache.generation(&key), expired));
    // Both the refresh and the fallback grant see the same malformed answer.
    let issuer = FixedIssuer::expiring(Some("10000000000000"));
    let e = cache.get_or_acquire(&key, &cc, &issuer, Utc::now()).await;
    assert!(matches!(e, Err(AuthError::Acquisition(_))), "{:?}", e.map(|t| t.expires_at));
    assert_eq!(issuer.calls.load(Ordering::SeqCst), 2, "refresh, then a client-credentials grant");
}
