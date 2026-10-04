//! Application identity (DATA-018/019, plan §13) and target-API sign-in
//! through the app services. The CI mock provider runs a real loopback PKCE
//! flow against the fixture issuer; nothing here fabricates a
//! `VerifiedIdentity`.

use anvil_app::exec::SendOptions;
use anvil_app::identity::{IDENTITY_FILE, IdentityPolicyError, login_providers};
use anvil_app::profiles::{ProfileManager, Unlock};
use anvil_app::{App, AppError};
use anvil_domain::auth::{AuthConfig, OAuth2Config, OAuthClientAuth, OAuthGrant};
use anvil_domain::execution::FailureKind;
use anvil_domain::request::RequestSpec;
use anvil_domain::secret::SensitiveValue;
use anvil_domain::workspace::Folder;
use anvil_fixtures::idp::{IdpFixture, IdpOptions, simulate_browser};
use anvil_identity::mock::{MockProvider, MockProviderConfig};
use anvil_identity::{Availability, FlowErrorKind, FlowEvent, FlowOptions, IdentityProvider, NoEvents, VerifiedIdentity};
use anvil_portability::plan::ConflictPolicy;
use anvil_storage::KdfParams;
use anvil_storage::vault::VaultError;
use anvil_transport::recorder::EventCtx;
use std::path::{Path, PathBuf};
use tokio_util::sync::CancellationToken;

const PASS: &str = "correct horse battery";

fn browser(url: &str) -> Result<(), String> {
    let url = url.to_string();
    tokio::spawn(async move {
        let _ = simulate_browser(&url, None).await;
    });
    Ok(())
}

async fn send(app: &App, ws: &anvil_domain::Id, rid: Option<anvil_domain::Id>) -> anvil_engine::ExecutionOutput {
    app.send(rid, ws, None, SendOptions::default(), EventCtx::none(), CancellationToken::new()).await.unwrap()
}

fn provider(idp: &IdpFixture) -> MockProvider {
    MockProvider::new(MockProviderConfig {
        authorization_endpoint: idp.authorization_endpoint(),
        token_endpoint: idp.token_endpoint(),
        userinfo_endpoint: idp.userinfo_endpoint(),
        client_id: idp.client_id(),
        scope: "openid email".into(),
    })
    .unwrap()
}

async fn sign_in(p: &MockProvider) -> VerifiedIdentity {
    p.authenticate(&browser, &NoEvents, &FlowOptions::default(), &CancellationToken::new()).await.expect("mock sign-in")
}

/// Passphrase profile; returns (dir, recovery key).
fn profile(root: &Path, name: &str) -> (PathBuf, String) {
    let (s, _dek, rk) = ProfileManager::new(root).create_passphrase(name, PASS, KdfParams::testing()).unwrap();
    (s.dir, rk.to_string())
}

fn policy_err(r: Result<impl Sized, AppError>) -> IdentityPolicyError {
    match r {
        Err(AppError::Identity(e)) => e,
        Err(e) => panic!("expected an identity policy error, got {e}"),
        Ok(_) => panic!("expected an identity policy error, got success"),
    }
}

#[tokio::test]
async fn link_with_mock_provider_keeps_the_key_wraps_untouched() {
    anvil_fixtures::init();
    let idp = IdpFixture::start(IdpOptions::default()).await.unwrap();
    let p = provider(&idp);
    let root = tempfile::tempdir().unwrap();
    let (dir, _rk) = profile(root.path(), "alice");
    let header_before = std::fs::read(dir.join("profile.json")).unwrap();

    let linked = ProfileManager::link_identity(&dir, Unlock::Passphrase(PASS), sign_in(&p).await, false).unwrap();
    assert_eq!((linked.provider.as_str(), linked.subject.as_str()), ("mock", "fixture-user-1"));
    assert_eq!(linked.email.as_deref(), Some("fixture-user-1@idp.anvil.test"));
    assert!(!linked.require_fresh_login);

    // Identity is not a key: the wrapped data key and its check value are unchanged.
    assert_eq!(std::fs::read(dir.join("profile.json")).unwrap(), header_before);
    // The plaintext hint carries no e-mail and no key material.
    let raw = std::fs::read_to_string(dir.join(IDENTITY_FILE)).unwrap();
    assert!(!raw.contains("idp.anvil.test"), "{raw}");
    let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
    keys.sort();
    assert_eq!(keys, ["format", "linked_at", "provider", "require_fresh_login", "sealed", "subject", "version"]);

    let req = ProfileManager::unlock_requirements(&dir).unwrap();
    assert_eq!(req.linked.as_ref().map(|l| l.subject.as_str()), Some("fixture-user-1"));
    assert!(!req.fresh_login_required && req.recovery_key_available);

    // Unlocked view (verified against the sealed copy) includes the e-mail.
    let (_, key) = ProfileManager::unlock(&dir, Unlock::Passphrase(PASS)).unwrap();
    let full = ProfileManager::linked_identity(&dir, &key).unwrap().unwrap();
    assert_eq!(full, linked);
}

#[tokio::test]
async fn data_018_fresh_login_policy_is_enforced_in_the_backend() {
    anvil_fixtures::init();
    let idp = IdpFixture::start(IdpOptions::default()).await.unwrap();
    let p = provider(&idp);
    let root = tempfile::tempdir().unwrap();
    let (dir, rk) = profile(root.path(), "alice");
    ProfileManager::link_identity(&dir, Unlock::Passphrase(PASS), sign_in(&p).await, true).unwrap();
    assert!(ProfileManager::unlock_requirements(&dir).unwrap().fresh_login_required);

    // The passphrase alone is refused before any key is unwrapped.
    let e = policy_err(ProfileManager::unlock(&dir, Unlock::Passphrase(PASS)));
    assert_eq!(e, IdentityPolicyError::FreshLoginRequired { provider: "mock".into() });

    // Passphrase + fresh sign-in of the linked account unlocks the real data.
    let (h, key) = ProfileManager::unlock_with_fresh_login(&dir, Unlock::Passphrase(PASS), sign_in(&p).await).unwrap();
    let app = App::open(dir.clone(), h, key).unwrap();
    app.create_workspace("after fresh login").unwrap();
    drop(app);

    // A sign-in does not replace the passphrase: wrong passphrase + valid proof fails.
    let r = ProfileManager::unlock_with_fresh_login(&dir, Unlock::Passphrase("wrong passphrase"), sign_in(&p).await);
    assert!(matches!(r, Err(AppError::Vault(VaultError::WrongSecret))), "{:?}", r.err());

    // A stale sign-in does not count.
    let stale = sign_in(&p).await;
    let later = stale.authenticated_at() + chrono::Duration::minutes(10);
    let e = policy_err(ProfileManager::unlock_with_fresh_login_at(&dir, Unlock::Passphrase(PASS), stale, later));
    assert!(matches!(e, IdentityPolicyError::StaleProof { .. }));

    // A different account at the same provider does not count.
    idp.set_subject("fixture-user-2", Some("other@idp.anvil.test"));
    let e = policy_err(ProfileManager::unlock_with_fresh_login(&dir, Unlock::Passphrase(PASS), sign_in(&p).await));
    assert_eq!(e, IdentityPolicyError::IdentityMismatch { provider: "mock".into() });

    // DATA-019: provider unavailable/offline — the recovery key still unlocks.
    drop(idp);
    let (h, key) = ProfileManager::unlock(&dir, Unlock::RecoveryKey(&rk)).unwrap();
    let app = App::open(dir.clone(), h, key).unwrap();
    assert!(app.find_workspace("after fresh login").is_ok());
}

#[tokio::test]
async fn identity_alone_never_unlocks() {
    anvil_fixtures::init();
    let idp = IdpFixture::start(IdpOptions::default()).await.unwrap();
    let p = provider(&idp);
    let root = tempfile::tempdir().unwrap();
    let (dir, _) = profile(root.path(), "alice");
    let linked = ProfileManager::link_identity(&dir, Unlock::Passphrase(PASS), sign_in(&p).await, false).unwrap();
    // Neither the subject nor the e-mail is a passphrase or recovery key.
    for guess in [linked.subject.as_str(), linked.email.as_deref().unwrap(), "mock"] {
        assert!(matches!(ProfileManager::unlock(&dir, Unlock::Passphrase(guess)), Err(AppError::Vault(VaultError::WrongSecret))));
        assert!(matches!(ProfileManager::unlock(&dir, Unlock::RecoveryKey(guess)), Err(AppError::Vault(VaultError::WrongSecret))));
        let r = ProfileManager::unlock_with_fresh_login(&dir, Unlock::Passphrase(guess), sign_in(&p).await);
        assert!(matches!(r, Err(AppError::Vault(VaultError::WrongSecret))));
    }
    // A proof for a profile with no linked identity is refused, not ignored.
    let (other, _) = profile(root.path(), "bob");
    let e = policy_err(ProfileManager::unlock_with_fresh_login(&other, Unlock::Passphrase(PASS), sign_in(&p).await));
    assert_eq!(e, IdentityPolicyError::NotLinked);
}

#[tokio::test]
async fn edited_hint_cannot_switch_the_policy_off() {
    anvil_fixtures::init();
    let idp = IdpFixture::start(IdpOptions::default()).await.unwrap();
    let p = provider(&idp);
    let root = tempfile::tempdir().unwrap();
    let (dir, rk) = profile(root.path(), "alice");
    ProfileManager::link_identity(&dir, Unlock::Passphrase(PASS), sign_in(&p).await, true).unwrap();
    let path = dir.join(IDENTITY_FILE);
    let edited = std::fs::read_to_string(&path).unwrap().replace("\"require_fresh_login\": true", "\"require_fresh_login\": false");
    std::fs::write(&path, edited).unwrap();

    let e = policy_err(ProfileManager::unlock(&dir, Unlock::Passphrase(PASS)));
    assert_eq!(e, IdentityPolicyError::BindingTampered);
    // Corrupt JSON is tampering too, not "not linked".
    std::fs::write(&path, b"{ not json").unwrap();
    assert_eq!(policy_err(ProfileManager::unlock(&dir, Unlock::Passphrase(PASS))), IdentityPolicyError::BindingTampered);

    // The recovery key still works and can clean up the binding.
    assert!(ProfileManager::unlock(&dir, Unlock::RecoveryKey(&rk)).is_ok());
    ProfileManager::unlink_identity(&dir, Unlock::RecoveryKey(&rk), None).unwrap();
    assert!(!path.exists());
    assert!(ProfileManager::unlock(&dir, Unlock::Passphrase(PASS)).is_ok());
}

#[tokio::test]
async fn relinking_and_unlinking_follow_the_policy() {
    anvil_fixtures::init();
    let idp = IdpFixture::start(IdpOptions::default()).await.unwrap();
    let p = provider(&idp);
    let root = tempfile::tempdir().unwrap();
    let (dir, rk) = profile(root.path(), "alice");
    ProfileManager::link_identity(&dir, Unlock::Passphrase(PASS), sign_in(&p).await, true).unwrap();

    // Unlinking needs the fresh proof (or the recovery key).
    let e = policy_err(ProfileManager::unlink_identity(&dir, Unlock::Passphrase(PASS), None));
    assert!(matches!(e, IdentityPolicyError::FreshLoginRequired { .. }));

    // Replacing the account with a passphrase alone is refused …
    idp.set_subject("fixture-user-2", None);
    let other = sign_in(&p).await;
    let e = policy_err(ProfileManager::link_identity(&dir, Unlock::Passphrase(PASS), other, false));
    assert!(matches!(e, IdentityPolicyError::FreshLoginRequired { .. }));
    // … the same account may switch its own policy off with a fresh proof.
    idp.set_subject("fixture-user-1", None);
    let relinked = ProfileManager::link_identity(&dir, Unlock::Passphrase(PASS), sign_in(&p).await, false).unwrap();
    assert!(!relinked.require_fresh_login);
    assert!(ProfileManager::unlock(&dir, Unlock::Passphrase(PASS)).is_ok());

    // The recovery key may replace the account.
    idp.set_subject("fixture-user-2", None);
    let replaced = ProfileManager::link_identity(&dir, Unlock::RecoveryKey(&rk), sign_in(&p).await, true).unwrap();
    assert_eq!(replaced.subject, "fixture-user-2");
    ProfileManager::unlink_identity(&dir, Unlock::Passphrase(PASS), Some(sign_in(&p).await)).unwrap();
    assert!(ProfileManager::unlock_requirements(&dir).unwrap().linked.is_none());
    assert_eq!(policy_err(ProfileManager::unlink_identity(&dir, Unlock::Passphrase(PASS), None)), IdentityPolicyError::NotLinked);
}

#[tokio::test]
async fn restoring_someone_elses_backup_keeps_the_local_identity() {
    anvil_fixtures::init();
    let idp = IdpFixture::start(IdpOptions::default()).await.unwrap();
    let p = provider(&idp);
    let root = tempfile::tempdir().unwrap();

    // Alice links her account and makes a full backup.
    let (a_dir, _) = profile(root.path(), "alice");
    ProfileManager::link_identity(&a_dir, Unlock::Passphrase(PASS), sign_in(&p).await, false).unwrap();
    let (h, key) = ProfileManager::unlock(&a_dir, Unlock::Passphrase(PASS)).unwrap();
    let alice = App::open(a_dir.clone(), h, key).unwrap();
    alice.create_workspace("Alice's work").unwrap();
    let (backup, _) = alice.export_backup_with("backup passphrase", KdfParams::testing()).unwrap();

    // Bob has his own account linked with the fresh-login policy.
    idp.set_subject("fixture-user-bob", None);
    let (b_dir, _) = profile(root.path(), "bob");
    ProfileManager::link_identity(&b_dir, Unlock::Passphrase(PASS), sign_in(&p).await, true).unwrap();
    let before = std::fs::read(b_dir.join(IDENTITY_FILE)).unwrap();
    let (h, key) = ProfileManager::unlock_with_fresh_login(&b_dir, Unlock::Passphrase(PASS), sign_in(&p).await).unwrap();
    let bob = App::open(b_dir.clone(), h, key).unwrap();
    bob.restore(&backup, Some("backup passphrase"), ConflictPolicy::Merge).unwrap();
    assert!(bob.find_workspace("Alice's work").is_ok(), "the backup's data was restored");

    // Bob's binding and policy are untouched; Alice's account gained nothing.
    assert_eq!(std::fs::read(b_dir.join(IDENTITY_FILE)).unwrap(), before);
    let req = ProfileManager::unlock_requirements(&b_dir).unwrap();
    assert_eq!(req.linked.unwrap().subject, "fixture-user-bob");
    assert!(req.fresh_login_required);
    idp.set_subject("fixture-user-1", None);
    let e = policy_err(ProfileManager::unlock_with_fresh_login(&b_dir, Unlock::Passphrase(PASS), sign_in(&p).await));
    assert!(matches!(e, IdentityPolicyError::IdentityMismatch { .. }));
}

#[test]
fn real_login_providers_are_listed_as_unavailable() {
    let providers = login_providers();
    let ids: Vec<&str> = providers.iter().map(|p| p.id).collect();
    assert_eq!(ids, ["google", "github", "facebook"]);
    for p in providers {
        assert!(matches!(p.availability, Availability::Unavailable { ref reason } if reason.contains("owner action")), "{p:?}");
    }
}

#[tokio::test]
async fn target_api_sign_in_through_the_app_is_session_only() {
    anvil_fixtures::init();
    let idp = IdpFixture::start(IdpOptions::default()).await.unwrap();
    let root = tempfile::tempdir().unwrap();
    let (dir, _) = profile(root.path(), "alice");
    let (h, key) = ProfileManager::unlock(&dir, Unlock::Passphrase(PASS)).unwrap();
    let app = App::open(dir.clone(), h, key).unwrap();
    let ws = app.create_workspace("Orders API").unwrap();
    let mut spec = RequestSpec::http("GET", &idp.api_url());
    spec.auth = AuthConfig::OAuth2 {
        config: OAuth2Config {
            grant: OAuthGrant::AuthorizationCodePkce,
            token_url: idp.token_endpoint(),
            authorization_url: idp.authorization_endpoint(),
            client_id: idp.client_id(),
            client_secret: SensitiveValue::default(),
            scope: "orders.read".into(),
            audience: String::new(),
            client_auth: OAuthClientAuth::RequestBody,
            token_cache_id: None,
            refresh_skew_secs: 30,
        },
    };
    let req = app.create_request(&ws.meta.id, None, "List orders", spec).unwrap();
    let rid = Some(req.meta.id);
    let opts = SendOptions::default();
    let kind = |o: &anvil_engine::ExecutionOutput| o.record.attempts.last().and_then(|a| a.failure.as_ref()).map(|f| f.kind);

    assert_eq!(kind(&send(&app, &ws.meta.id, rid).await), Some(FailureKind::OAuthInteractionRequired));
    assert!(app.oauth_token_status(rid, &ws.meta.id, None, &opts).unwrap().is_none());
    let auth = app
        .oauth_sign_in(rid, &ws.meta.id, None, &opts, &browser, &NoEvents, &FlowOptions::default(), &CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(auth.profile_scope, "request");
    assert!(app.oauth_token_status(rid, &ws.meta.id, None, &opts).unwrap().is_some());
    let o = send(&app, &ws.meta.id, rid).await;
    assert_eq!(o.record.response.as_ref().map(|r| r.status), Some(200));

    // Tokens live in memory only and are dropped on lock.
    app.lock();
    assert!(matches!(
        app.oauth_sign_in(rid, &ws.meta.id, None, &opts, &browser, &NoEvents, &FlowOptions::default(), &CancellationToken::new()).await,
        Err(AppError::Locked)
    ));
    let (_, key) = ProfileManager::unlock(&dir, Unlock::Passphrase(PASS)).unwrap();
    app.unlock(key).unwrap();
    assert_eq!(kind(&send(&app, &ws.meta.id, rid).await), Some(FailureKind::OAuthInteractionRequired));
    assert_eq!(idp.api_requests(), (1, 1));
    assert!(!idp.grants_seen().iter().any(|g| g == "client_credentials"));
}

#[tokio::test]
async fn ineligible_token_urls_surface_the_same_failure_to_status_and_browser_observers() {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    anvil_fixtures::init();
    let idp = IdpFixture::start(IdpOptions::default()).await.unwrap();
    let root = tempfile::tempdir().unwrap();
    let (dir, _) = profile(root.path(), "issuer policy");
    let (header, key) = ProfileManager::unlock(&dir, Unlock::Passphrase(PASS)).unwrap();
    let app = App::open(dir, header, key).unwrap();
    let ws = app.create_workspace("Issuer policy").unwrap();
    let credential = app.set_secret(&ws.meta.id, "OAuth credential", "{{vault-canary}}").unwrap();
    let opened = AtomicUsize::new(0);
    let opener = |_: &str| {
        opened.fetch_add(1, Ordering::SeqCst);
        Ok(())
    };
    let expected = "the OAuth token endpoint requires HTTPS or literal-loopback HTTP";
    for endpoint in [
        "http://localhost:8080/token?hidden=endpoint-material",
        "http://issuer.example.test/token?hidden=endpoint-material",
        "http://[::ffff:192.168.1.1]/token?hidden=endpoint-material",
    ] {
        let mut spec = RequestSpec::http("GET", &idp.api_url());
        spec.auth = AuthConfig::OAuth2 {
            config: OAuth2Config {
                grant: OAuthGrant::AuthorizationCodePkce,
                token_url: endpoint.into(),
                authorization_url: idp.authorization_endpoint(),
                client_id: "{{missing_client_id}}".into(),
                client_secret: SensitiveValue::Secret { secret: credential.clone() },
                scope: String::new(),
                audience: String::new(),
                client_auth: OAuthClientAuth::BasicHeader,
                token_cache_id: None,
                refresh_skew_secs: 30,
            },
        };
        let req = app.create_request(&ws.meta.id, None, "Refused issuer", spec).unwrap();
        let rid = Some(req.meta.id);
        let opts = SendOptions::default();
        assert_eq!(app.oauth_token_status(rid, &ws.meta.id, None, &opts).unwrap_err().to_string(), expected);
        let events = Mutex::new(Vec::new());
        let observer = |event| events.lock().unwrap().push(event);
        let error = app
            .oauth_sign_in(rid, &ws.meta.id, None, &opts, &opener, &observer, &FlowOptions::default(), &CancellationToken::new())
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), expected);
        assert_eq!(*events.lock().unwrap(), vec![FlowEvent::Failed { kind: FlowErrorKind::Configuration, message: expected.into() }]);
    }
    assert_eq!(opened.load(Ordering::SeqCst), 0, "no browser opened for an ineligible issuer");
    assert!(idp.grants_seen().is_empty(), "no credentials reached the issuer");
    assert_eq!(idp.api_requests(), (0, 0));
}

#[tokio::test]
async fn mapped_loopback_token_endpoint_can_complete_app_browser_sign_in() {
    anvil_fixtures::init();
    let idp = IdpFixture::start(IdpOptions::default()).await.unwrap();
    let root = tempfile::tempdir().unwrap();
    let (dir, _) = profile(root.path(), "mapped issuer");
    let (header, key) = ProfileManager::unlock(&dir, Unlock::Passphrase(PASS)).unwrap();
    let app = App::open(dir, header, key).unwrap();
    let ws = app.create_workspace("Mapped issuer").unwrap();
    let credential = app.set_secret(&ws.meta.id, "OAuth credential", "eligible-vault-credential").unwrap();
    let mut spec = RequestSpec::http("GET", &idp.api_url());
    spec.auth = AuthConfig::OAuth2 {
        config: OAuth2Config {
            grant: OAuthGrant::AuthorizationCodePkce,
            token_url: idp.token_endpoint().replace("127.0.0.1", "[::ffff:127.0.0.1]"),
            authorization_url: idp.authorization_endpoint(),
            client_id: idp.client_id(),
            client_secret: SensitiveValue::Secret { secret: credential },
            scope: "orders.read".into(),
            audience: String::new(),
            client_auth: OAuthClientAuth::RequestBody,
            token_cache_id: None,
            refresh_skew_secs: 30,
        },
    };
    let req = app.create_request(&ws.meta.id, None, "Mapped loopback", spec).unwrap();
    let rid = Some(req.meta.id);
    let opts = SendOptions::default();
    assert!(app.oauth_token_status(rid, &ws.meta.id, None, &opts).unwrap().is_none());
    app.oauth_sign_in(rid, &ws.meta.id, None, &opts, &browser, &NoEvents, &FlowOptions::default(), &CancellationToken::new())
        .await
        .unwrap();
    assert!(app.oauth_token_status(rid, &ws.meta.id, None, &opts).unwrap().is_some());
    assert_eq!(send(&app, &ws.meta.id, rid).await.record.response.unwrap().status, 200);
    assert_eq!(idp.api_requests(), (1, 1));
}

#[tokio::test]
async fn vault_expansion_failures_are_sanitized_before_status_browser_events_and_history() {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    anvil_fixtures::init();
    let idp = IdpFixture::start(IdpOptions::default()).await.unwrap();
    let root = tempfile::tempdir().unwrap();
    let (dir, _) = profile(root.path(), "vault errors");
    let (header, key) = ProfileManager::unlock(&dir, Unlock::Passphrase(PASS)).unwrap();
    let app = App::open(dir, header, key).unwrap();
    let mut ws = app.create_workspace("Vault errors").unwrap();
    let credential = app.set_secret(&ws.meta.id, "OAuth credential", "{{vault-canary}}").unwrap();
    ws.variables.push(anvil_domain::workspace::Variable::plain("issuer", &idp.token_endpoint()));
    app.save_workspace(ws.clone()).unwrap();
    let opened = AtomicUsize::new(0);
    let opener = |_: &str| {
        opened.fetch_add(1, Ordering::SeqCst);
        Ok(())
    };
    let expected = "could not resolve auth.client_secret; check the vault and active variables";
    for (endpoint, missing) in
        [(idp.token_endpoint(), false), ("{{issuer}}".into(), false), (idp.token_endpoint(), true), ("{{issuer}}".into(), true)]
    {
        if missing {
            app.store.delete_secret(&credential.id).unwrap();
        }
        let mut spec = RequestSpec::http("GET", &idp.api_url());
        spec.auth = AuthConfig::OAuth2 {
            config: OAuth2Config {
                grant: OAuthGrant::AuthorizationCodePkce,
                token_url: endpoint,
                authorization_url: idp.authorization_endpoint(),
                client_id: idp.client_id(),
                client_secret: SensitiveValue::Secret { secret: credential.clone() },
                scope: "orders.read".into(),
                audience: String::new(),
                client_auth: OAuthClientAuth::RequestBody,
                token_cache_id: None,
                refresh_skew_secs: 30,
            },
        };
        let req = app.create_request(&ws.meta.id, None, "Vault-backed issuer", spec).unwrap();
        let rid = Some(req.meta.id);
        let opts = SendOptions::default();
        assert_eq!(app.oauth_token_status(rid, &ws.meta.id, None, &opts).unwrap_err().to_string(), expected);
        let events = Mutex::new(Vec::new());
        let observer = |event| events.lock().unwrap().push(event);
        let error = app
            .oauth_sign_in(rid, &ws.meta.id, None, &opts, &opener, &observer, &FlowOptions::default(), &CancellationToken::new())
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), expected);
        assert_eq!(*events.lock().unwrap(), vec![FlowEvent::Failed { kind: FlowErrorKind::Configuration, message: expected.into() }]);
        assert!(!serde_json::to_string(&*events.lock().unwrap()).unwrap().contains("vault-canary"));
        let out = send(&app, &ws.meta.id, rid).await;
        assert_eq!(out.record.outcome.dispatch, anvil_domain::execution::DispatchState::NotDispatched);
        assert_eq!(out.record.attempts.last().unwrap().failure.as_ref().unwrap().message, expected);
        assert!(!serde_json::to_string(&out.record).unwrap().contains("vault-canary"));
    }
    assert_eq!(opened.load(Ordering::SeqCst), 0);
    assert!(idp.grants_seen().is_empty());
    assert_eq!(idp.api_requests(), (0, 0));
}

#[tokio::test]
async fn credential_variable_failures_keep_endpoint_policy_and_never_disclose_vault_errors() {
    use anvil_domain::workspace::Variable;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    anvil_fixtures::init();
    let idp = IdpFixture::start(IdpOptions::default()).await.unwrap();
    let root = tempfile::tempdir().unwrap();
    let (dir, _) = profile(root.path(), "credential variable errors");
    let (header, key) = ProfileManager::unlock(&dir, Unlock::Passphrase(PASS)).unwrap();
    let app = App::open(dir, header, key).unwrap();
    let mut ws = app.create_workspace("Credential variable errors").unwrap();
    let opened = AtomicUsize::new(0);
    let opener = |_: &str| {
        opened.fetch_add(1, Ordering::SeqCst);
        Ok(())
    };
    for endpoint in ["http://issuer.example.test/token".to_string(), idp.token_endpoint(), "{{issuer}}".into()] {
        for (value, missing) in [("{{missing-variable-canary}}", false), ("{{credential}}", false), ("canary", true)] {
            let credential = app.set_secret(&ws.meta.id, "missing-reference-label-canary", value).unwrap();
            ws.variables = vec![
                Variable::plain("issuer", &idp.token_endpoint()),
                Variable {
                    name: "credential".into(),
                    value: SensitiveValue::Secret { secret: credential.clone() },
                    secret: true,
                    enabled: true,
                    description: String::new(),
                },
                Variable::plain("nested_credential", "{{credential}}"),
            ];
            app.save_workspace(ws.clone()).unwrap();
            if missing {
                app.store.delete_secret(&credential.id).unwrap();
            }
            let mut spec = RequestSpec::http("GET", &idp.api_url());
            spec.auth = AuthConfig::OAuth2 {
                config: OAuth2Config {
                    grant: OAuthGrant::AuthorizationCodePkce,
                    token_url: endpoint.clone(),
                    authorization_url: idp.authorization_endpoint(),
                    client_id: idp.client_id(),
                    client_secret: SensitiveValue::template("{{nested_credential}}"),
                    scope: "orders.read".into(),
                    audience: String::new(),
                    client_auth: OAuthClientAuth::RequestBody,
                    token_cache_id: None,
                    refresh_skew_secs: 30,
                },
            };
            let request = app.create_request(&ws.meta.id, None, "Credential variable", spec).unwrap();
            let rid = Some(request.meta.id);
            let opts = SendOptions::default();
            let expected = if endpoint.starts_with("http://issuer") {
                "the OAuth token endpoint requires HTTPS or literal-loopback HTTP"
            } else {
                "could not resolve auth.client_secret; check the vault and active variables"
            };
            assert_eq!(app.oauth_token_status(rid, &ws.meta.id, None, &opts).unwrap_err().to_string(), expected);
            let events = Mutex::new(Vec::new());
            let observer = |event| events.lock().unwrap().push(event);
            let error = app
                .oauth_sign_in(rid, &ws.meta.id, None, &opts, &opener, &observer, &FlowOptions::default(), &CancellationToken::new())
                .await
                .unwrap_err();
            assert_eq!(error.to_string(), expected);
            assert_eq!(*events.lock().unwrap(), vec![FlowEvent::Failed { kind: FlowErrorKind::Configuration, message: expected.into() }]);
            assert!(!serde_json::to_string(&*events.lock().unwrap()).unwrap().contains("canary"));
            let output = send(&app, &ws.meta.id, rid).await;
            assert_eq!(output.record.outcome.dispatch, anvil_domain::execution::DispatchState::NotDispatched);
            assert_eq!(output.record.attempts[0].failure.as_ref().unwrap().message, expected);
            assert!(!serde_json::to_string(&output.record).unwrap().contains("canary"));
        }
    }
    assert_eq!(opened.load(Ordering::SeqCst), 0);
    assert!(idp.grants_seen().is_empty());
    assert_eq!(idp.api_requests(), (0, 0));
}

#[tokio::test]
async fn oauth_tokens_are_cached_per_workspace_folder_or_request_that_defines_the_profile() {
    let root = tempfile::tempdir().unwrap();
    let (dir, _) = profile(root.path(), "bob");
    let (h, key) = ProfileManager::unlock(&dir, Unlock::Passphrase(PASS)).unwrap();
    let app = App::open(dir, h, key).unwrap();
    let ws = app.create_workspace("Tenants").unwrap();
    let oauth = AuthConfig::OAuth2 {
        config: OAuth2Config {
            grant: OAuthGrant::AuthorizationCodePkce,
            token_url: "https://issuer.test/token".into(),
            authorization_url: "https://issuer.test/authorize".into(),
            client_id: "client".into(),
            client_secret: SensitiveValue::default(),
            scope: "orders.read".into(),
            audience: String::new(),
            client_auth: OAuthClientAuth::RequestBody,
            token_cache_id: None,
            refresh_skew_secs: 30,
        },
    };
    // Two folders carry the same OAuth profile.
    let mut folders: Vec<Folder> = vec![];
    for name in ["tenant-a", "tenant-b"] {
        let mut f = app.create_folder(&ws.meta.id, None, name).unwrap();
        f.auth = oauth.clone();
        folders.push(app.save_folder(f).unwrap());
    }
    let key_of = |folder: Option<&Folder>, auth: AuthConfig| {
        let mut spec = RequestSpec::http("GET", "https://api.test/orders");
        spec.auth = auth;
        let req = app.create_request(&ws.meta.id, folder.map(|f| f.meta.id), "List orders", spec).unwrap();
        let ctx = app.build_context(Some(req.meta.id), &ws.meta.id, None, &SendOptions::default()).unwrap();
        anvil_engine::oauth_http::interactive_oauth(&ctx).unwrap().cache_key().clone()
    };

    let a1 = key_of(Some(&folders[0]), AuthConfig::Inherit);
    let a2 = key_of(Some(&folders[0]), AuthConfig::Inherit);
    let b1 = key_of(Some(&folders[1]), AuthConfig::Inherit);
    assert_eq!(a1, a2, "requests that inherit one folder's profile share its sign-in");
    assert_eq!(a1.token_cache_id, Some(folders[0].meta.id));
    assert_ne!(a1, b1, "the same settings defined in another folder need their own sign-in");

    // A profile defined on a request belongs to that request.
    let r1 = key_of(None, oauth.clone());
    let r2 = key_of(None, oauth.clone());
    assert_ne!(r1, r2);
    assert_ne!(r1, a1);
}
