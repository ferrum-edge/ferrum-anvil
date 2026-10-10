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
use anvil_storage::vault::VaultError;
use anvil_storage::{KdfParams, vault};
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

fn link(
    dir: &Path,
    how: Unlock<'_>,
    proof: VerifiedIdentity,
    fresh: bool,
    passphrase: &str,
) -> Result<(anvil_domain::workspace::LinkedIdentity, String), AppError> {
    let recovery = vault::RotationRecoveryKey::generate();
    let linked = ProfileManager::link_identity(
        dir,
        how,
        proof,
        fresh,
        anvil_app::profiles::PolicyRotation { new_passphrase: passphrase, recovery: &recovery, kdf: KdfParams::testing() },
    )?;
    Ok((linked, recovery.as_str().to_string()))
}
fn unlink(dir: &Path, how: Unlock<'_>, proof: Option<VerifiedIdentity>, passphrase: &str) -> Result<String, AppError> {
    let recovery = vault::RotationRecoveryKey::generate();
    ProfileManager::unlink_identity(
        dir,
        how,
        proof,
        anvil_app::profiles::PolicyRotation { new_passphrase: passphrase, recovery: &recovery, kdf: KdfParams::testing() },
    )?;
    Ok(recovery.as_str().to_string())
}
fn state(dir: &Path) -> serde_json::Value {
    let conn = rusqlite::Connection::open(dir.join("anvil.db")).unwrap();
    let raw: String = conn.query_row("SELECT value FROM meta WHERE key='local_key_state_v1'", [], |r| r.get(0)).unwrap();
    serde_json::from_str(&raw).unwrap()
}
fn replace_state(dir: &Path, state: &serde_json::Value) {
    rusqlite::Connection::open(dir.join("anvil.db"))
        .unwrap()
        .execute("UPDATE meta SET value=?1 WHERE key='local_key_state_v1'", [state.to_string()])
        .unwrap();
}

#[tokio::test]
async fn linking_rotates_the_key_and_authenticates_policy_presence() {
    anvil_fixtures::init();
    let idp = IdpFixture::start(IdpOptions::default()).await.unwrap();
    let p = provider(&idp);
    let root = tempfile::tempdir().unwrap();
    let (dir, old_recovery) = profile(root.path(), "alice");
    let before = vault::read_header(&dir).unwrap();
    let (linked, recovery) = link(&dir, Unlock::Passphrase(PASS), sign_in(&p).await, false, PASS).unwrap();
    assert_eq!((linked.provider.as_str(), linked.subject.as_str()), ("mock", "fixture-user-1"));
    assert_eq!(linked.email.as_deref(), Some("fixture-user-1@idp.anvil.test"));
    assert_ne!(vault::read_header(&dir).unwrap().key_check, before.key_check);
    assert!(ProfileManager::unlock(&dir, Unlock::RecoveryKey(&old_recovery)).is_err());
    assert!(ProfileManager::unlock(&dir, Unlock::RecoveryKey(&recovery)).is_ok());
    assert!(!dir.join(IDENTITY_FILE).exists());
    assert!(!state(&dir)["binding"].to_string().contains("idp.anvil.test"));
    let (_, key) = ProfileManager::unlock(&dir, Unlock::Passphrase(PASS)).unwrap();
    assert_eq!(ProfileManager::linked_identity(&dir, &key).unwrap().unwrap(), linked);
}

#[tokio::test]
async fn data_018_fresh_login_policy_is_enforced_in_the_backend() {
    anvil_fixtures::init();
    let idp = IdpFixture::start(IdpOptions::default()).await.unwrap();
    let p = provider(&idp);
    let root = tempfile::tempdir().unwrap();
    let (dir, _) = profile(root.path(), "alice");
    let (_, rk) = link(&dir, Unlock::Passphrase(PASS), sign_in(&p).await, true, PASS).unwrap();
    assert!(ProfileManager::unlock_requirements(&dir).unwrap().fresh_login_required);
    assert!(matches!(policy_err(ProfileManager::unlock(&dir, Unlock::Passphrase(PASS))), IdentityPolicyError::FreshLoginRequired { .. }));
    let (h, key) = ProfileManager::unlock_with_fresh_login(&dir, Unlock::Passphrase(PASS), sign_in(&p).await).unwrap();
    App::open(dir.clone(), h, key).unwrap().create_workspace("after fresh login").unwrap();
    assert!(matches!(
        ProfileManager::unlock_with_fresh_login(&dir, Unlock::Passphrase("wrong passphrase"), sign_in(&p).await),
        Err(AppError::Vault(VaultError::WrongSecret))
    ));
    let stale = sign_in(&p).await;
    let later = stale.authenticated_at() + chrono::Duration::minutes(10);
    assert!(matches!(
        policy_err(ProfileManager::unlock_with_fresh_login_at(&dir, Unlock::Passphrase(PASS), stale, later)),
        IdentityPolicyError::StaleProof { .. }
    ));
    idp.set_subject("fixture-user-2", Some("other@idp.anvil.test"));
    assert!(matches!(
        policy_err(ProfileManager::unlock_with_fresh_login(&dir, Unlock::Passphrase(PASS), sign_in(&p).await)),
        IdentityPolicyError::IdentityMismatch { .. }
    ));
    drop(idp);
    let (h, key) = ProfileManager::unlock(&dir, Unlock::RecoveryKey(&rk)).unwrap();
    assert!(App::open(dir, h, key).unwrap().find_workspace("after fresh login").is_ok());
}

#[tokio::test]
async fn identity_alone_never_unlocks() {
    anvil_fixtures::init();
    let idp = IdpFixture::start(IdpOptions::default()).await.unwrap();
    let p = provider(&idp);
    let root = tempfile::tempdir().unwrap();
    let (dir, _) = profile(root.path(), "alice");
    let (linked, _) = link(&dir, Unlock::Passphrase(PASS), sign_in(&p).await, false, PASS).unwrap();
    for guess in [linked.subject.as_str(), linked.email.as_deref().unwrap(), "mock"] {
        assert!(ProfileManager::unlock(&dir, Unlock::Passphrase(guess)).is_err());
        assert!(ProfileManager::unlock(&dir, Unlock::RecoveryKey(guess)).is_err());
        assert!(ProfileManager::unlock_with_fresh_login(&dir, Unlock::Passphrase(guess), sign_in(&p).await).is_err());
    }
    let (other, _) = profile(root.path(), "bob");
    assert_eq!(
        policy_err(ProfileManager::unlock_with_fresh_login(&other, Unlock::Passphrase(PASS), sign_in(&p).await)),
        IdentityPolicyError::NotLinked
    );
}

#[tokio::test]
async fn edited_hint_cannot_switch_the_policy_off_and_recovery_repairs_it_by_rotation() {
    anvil_fixtures::init();
    let idp = IdpFixture::start(IdpOptions::default()).await.unwrap();
    let p = provider(&idp);
    let root = tempfile::tempdir().unwrap();
    let (dir, _) = profile(root.path(), "alice");
    let (_, rk) = link(&dir, Unlock::Passphrase(PASS), sign_in(&p).await, true, PASS).unwrap();
    let mut edited = state(&dir);
    edited["binding"]["require_fresh_login"] = false.into();
    replace_state(&dir, &edited);
    assert_eq!(policy_err(ProfileManager::unlock(&dir, Unlock::Passphrase(PASS))), IdentityPolicyError::BindingTampered);
    edited["binding"] = serde_json::Value::Null;
    replace_state(&dir, &edited);
    assert!(ProfileManager::unlock(&dir, Unlock::Passphrase(PASS)).is_err());
    assert!(ProfileManager::unlock(&dir, Unlock::RecoveryKey(&rk)).is_ok());
    let (h, key) = ProfileManager::unlock(&dir, Unlock::RecoveryKey(&rk)).unwrap();
    let app = App::open(dir.clone(), h, key).unwrap();
    assert!(
        app.rotate_data_key(PASS, &vault::RotationRecoveryKey::generate(), KdfParams::testing()).is_err(),
        "implicit rotation cannot legitimize missing authenticated policy"
    );
    let replacement = unlink(&dir, Unlock::RecoveryKey(&rk), None, PASS).unwrap();
    assert!(ProfileManager::unlock(&dir, Unlock::RecoveryKey(&rk)).is_err());
    assert!(ProfileManager::unlock(&dir, Unlock::RecoveryKey(&replacement)).is_ok());
    assert!(ProfileManager::unlock(&dir, Unlock::Passphrase(PASS)).is_ok());
}

#[tokio::test]
async fn relinking_and_unlinking_follow_the_policy_and_rotate_every_epoch() {
    anvil_fixtures::init();
    let idp = IdpFixture::start(IdpOptions::default()).await.unwrap();
    let p = provider(&idp);
    let root = tempfile::tempdir().unwrap();
    let (dir, _) = profile(root.path(), "alice");
    let (_, first) = link(&dir, Unlock::Passphrase(PASS), sign_in(&p).await, true, PASS).unwrap();
    assert!(matches!(policy_err(unlink(&dir, Unlock::Passphrase(PASS), None, PASS)), IdentityPolicyError::FreshLoginRequired { .. }));
    idp.set_subject("fixture-user-2", None);
    assert!(matches!(
        policy_err(link(&dir, Unlock::Passphrase(PASS), sign_in(&p).await, false, PASS)),
        IdentityPolicyError::FreshLoginRequired { .. }
    ));
    idp.set_subject("fixture-user-1", None);
    let (linked, second) = link(&dir, Unlock::Passphrase(PASS), sign_in(&p).await, false, PASS).unwrap();
    assert!(!linked.require_fresh_login);
    assert!(ProfileManager::unlock(&dir, Unlock::RecoveryKey(&first)).is_err());
    idp.set_subject("fixture-user-2", None);
    let (linked, third) = link(&dir, Unlock::RecoveryKey(&second), sign_in(&p).await, true, PASS).unwrap();
    assert_eq!(linked.subject, "fixture-user-2");
    assert!(ProfileManager::unlock(&dir, Unlock::RecoveryKey(&second)).is_err());
    unlink(&dir, Unlock::Passphrase(PASS), Some(sign_in(&p).await), PASS).unwrap();
    assert!(ProfileManager::unlock(&dir, Unlock::RecoveryKey(&third)).is_err());
    assert_eq!(policy_err(unlink(&dir, Unlock::Passphrase(PASS), None, PASS)), IdentityPolicyError::NotLinked);
}

#[tokio::test]
async fn restoring_someone_elses_backup_keeps_the_local_identity() {
    anvil_fixtures::init();
    let idp = IdpFixture::start(IdpOptions::default()).await.unwrap();
    let p = provider(&idp);
    let root = tempfile::tempdir().unwrap();
    let (a_dir, _) = profile(root.path(), "alice");
    link(&a_dir, Unlock::Passphrase(PASS), sign_in(&p).await, false, PASS).unwrap();
    let (h, key) = ProfileManager::unlock(&a_dir, Unlock::Passphrase(PASS)).unwrap();
    let alice = App::open(a_dir, h, key).unwrap();
    alice.create_workspace("Alice's work").unwrap();
    let (backup, _) = alice.export_backup_with("backup passphrase", KdfParams::testing()).unwrap();
    idp.set_subject("fixture-user-bob", None);
    let (b_dir, _) = profile(root.path(), "bob");
    link(&b_dir, Unlock::Passphrase(PASS), sign_in(&p).await, true, PASS).unwrap();
    let before = state(&b_dir);
    let (h, key) = ProfileManager::unlock_with_fresh_login(&b_dir, Unlock::Passphrase(PASS), sign_in(&p).await).unwrap();
    let bob = App::open(b_dir.clone(), h, key).unwrap();
    bob.restore(&backup, Some("backup passphrase"), ConflictPolicy::Merge).unwrap();
    assert!(bob.find_workspace("Alice's work").is_ok());
    assert_eq!(state(&b_dir), before);
    assert_eq!(ProfileManager::unlock_requirements(&b_dir).unwrap().linked.unwrap().subject, "fixture-user-bob");
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
            } else if missing {
                "could not resolve a secret variable; check the vault and active variables"
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

#[tokio::test]
async fn authentic_old_policy_replay_cannot_open_current_ciphertext() {
    anvil_fixtures::init();
    let idp = IdpFixture::start(IdpOptions::default()).await.unwrap();
    let p = provider(&idp);
    let root = tempfile::tempdir().unwrap();
    let (dir, original_recovery) = profile(root.path(), "replay");
    let (h, key) = ProfileManager::unlock(&dir, Unlock::Passphrase(PASS)).unwrap();
    let stale = App::open(dir.clone(), h, key).unwrap();
    stale.create_workspace("before").unwrap();
    let unlinked = state(&dir);
    let (_, replacement) = link(&dir, Unlock::Passphrase(PASS), sign_in(&p).await, true, PASS).unwrap();
    let committed = state(&dir);
    let (h, key) = ProfileManager::unlock_with_fresh_login(&dir, Unlock::Passphrase(PASS), sign_in(&p).await).unwrap();
    let current = App::open(dir.clone(), h, key).unwrap();
    current.create_workspace("after").unwrap();
    assert!(stale.create_workspace("stale writer").is_err());
    replace_state(&dir, &unlinked);
    assert!(
        ProfileManager::unlock(&dir, Unlock::Passphrase(PASS)).is_err(),
        "authentic old unlinked metadata has the wrong ciphertext key"
    );
    assert!(ProfileManager::unlock(&dir, Unlock::RecoveryKey(&original_recovery)).is_err());
    replace_state(&dir, &committed);
    let (h, key) = ProfileManager::unlock(&dir, Unlock::RecoveryKey(&replacement)).unwrap();
    assert!(App::open(dir, h, key).unwrap().find_workspace("after").is_ok());
}

#[tokio::test]
async fn stale_authorized_policy_cannot_unlink_or_replace_a_newer_binding() {
    anvil_fixtures::init();
    let idp = IdpFixture::start(IdpOptions::default()).await.unwrap();
    let p = provider(&idp);
    let root = tempfile::tempdir().unwrap();
    let (dir, _) = profile(root.path(), "concurrency");
    link(&dir, Unlock::Passphrase(PASS), sign_in(&p).await, false, PASS).unwrap();
    let (authorized, key) = ProfileManager::unlock(&dir, Unlock::Passphrase(PASS)).unwrap();
    let old_binding = anvil_storage::rotation::binding(&dir).unwrap().unwrap();
    let (_, recovery) = link(&dir, Unlock::Passphrase(PASS), sign_in(&p).await, true, PASS).unwrap();
    let committed = state(&dir);
    for replacement in [None, old_binding] {
        assert!(anvil_storage::rotation::set_binding(&dir, &authorized, &key, replacement).is_err());
        assert_eq!(state(&dir), committed);
    }
    unlink(&dir, Unlock::RecoveryKey(&recovery), None, PASS).unwrap();
    assert!(ProfileManager::unlock(&dir, Unlock::Passphrase(PASS)).is_ok());
}

#[tokio::test]
async fn deleting_header_mac_cannot_legitimize_an_unlinked_policy() {
    use sha2::Digest;
    anvil_fixtures::init();
    let idp = IdpFixture::start(IdpOptions::default()).await.unwrap();
    let p = provider(&idp);
    let root = tempfile::tempdir().unwrap();
    let (dir, _) = profile(root.path(), "unsigned policy");
    link(&dir, Unlock::Passphrase(PASS), sign_in(&p).await, true, PASS).unwrap();
    let mut edited = state(&dir);
    edited["binding"] = serde_json::Value::Null;
    edited["header"]["rotation"]["binding_digest"] = hex::encode(sha2::Sha256::digest(b"null")).into();
    edited["header"]["protection_mac"] = serde_json::Value::Null;
    replace_state(&dir, &edited);
    assert!(ProfileManager::unlock(&dir, Unlock::Passphrase(PASS)).is_err());
}
