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
use anvil_identity::{Availability, FlowOptions, IdentityProvider, NoEvents, VerifiedIdentity};
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
    let (s, _dek, rk) = ProfileManager::new(root)
        .create_passphrase_with_identity_expectation(name, PASS, KdfParams::testing())
        .unwrap();
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
    let before: serde_json::Value = serde_json::from_slice(&header_before).unwrap();
    let after: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("profile.json")).unwrap()).unwrap();
    for field in ["passphrase_wrap", "recovery_wrap", "key_check"] {
        assert_eq!(before[field], after[field]);
    }
    assert_ne!(before["protection_mac"], after["protection_mac"]);
    assert!(after["identity_binding"]["binding"].is_object());
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

/// Exercise the production unlock-to-install sequence and prove the installer
/// never runs on refusal. The existing database/workspace bytes stay untouched.
fn rejected_install(dir: &Path) -> AppError {
    let before = std::fs::read(dir.join(anvil_storage::store::DB_FILE)).ok();
    let mut installed = false;
    let result = ProfileManager::unlock(dir, Unlock::Passphrase(PASS)).and_then(|(h, key)| {
        installed = true;
        let app = App::open(dir.to_path_buf(), h, key)?;
        app.create_workspace("must never be created")?;
        Ok(app)
    });
    assert!(!installed, "ordinary unlock returned a key to the installer");
    assert_eq!(std::fs::read(dir.join(anvil_storage::store::DB_FILE)).ok(), before);
    result.err().expect("unlock must refuse")
}

#[tokio::test]
async fn deleted_truncated_replaced_and_replayed_required_bindings_refuse_install() {
    anvil_fixtures::init();
    let idp = IdpFixture::start(IdpOptions::default()).await.unwrap();
    let p = provider(&idp);
    let root = tempfile::tempdir().unwrap();
    let (dir, rk) = profile(root.path(), "alice");
    let (h, key) = ProfileManager::unlock(&dir, Unlock::Passphrase(PASS)).unwrap();
    let app = App::open(dir.clone(), h, key).unwrap();
    app.create_workspace("existing workspace").unwrap();
    drop(app);
    ProfileManager::link_identity(&dir, Unlock::Passphrase(PASS), sign_in(&p).await, false)
        .unwrap();
    let path = dir.join(IDENTITY_FILE);
    let older = std::fs::read(&path).unwrap();
    ProfileManager::link_identity(&dir, Unlock::Passphrase(PASS), sign_in(&p).await, true)
        .unwrap();
    let current = std::fs::read(&path).unwrap();
    let header = std::fs::read(dir.join("profile.json")).unwrap();
    let (other, _) = profile(root.path(), "bob");
    ProfileManager::link_identity(&other, Unlock::Passphrase(PASS), sign_in(&p).await, false)
        .unwrap();
    let other_binding = std::fs::read(other.join(IDENTITY_FILE)).unwrap();

    for replacement in [
        None,
        Some(b"".to_vec()),
        Some(b"{".to_vec()),
        Some(older),
        Some(other_binding),
    ] {
        match replacement {
            Some(bytes) => std::fs::write(&path, bytes).unwrap(),
            None => std::fs::remove_file(&path).unwrap(),
        }
        assert!(matches!(
            rejected_install(&dir),
            AppError::Identity(IdentityPolicyError::BindingTampered),
        ));
        assert_eq!(std::fs::read(dir.join("profile.json")).unwrap(), header);
        assert!(ProfileManager::unlock(&dir, Unlock::RecoveryKey(&rk)).is_ok());
        // Even a valid proof does not repair a missing/replaced required file.
        assert_eq!(
            policy_err(ProfileManager::unlock_with_fresh_login(
                &dir,
                Unlock::Passphrase(PASS),
                sign_in(&p).await,
            )),
            IdentityPolicyError::BindingTampered,
        );
        std::fs::write(&path, &current).unwrap();
    }
    ProfileManager::unlink_identity(&dir, Unlock::RecoveryKey(&rk), None).unwrap();
    let (h, key) = ProfileManager::unlock(&dir, Unlock::Passphrase(PASS)).unwrap();
    let app = App::open(dir, h, key).unwrap();
    assert!(app.find_workspace("existing workspace").is_ok());
    assert!(app.find_workspace("must never be created").is_err());
}

#[tokio::test]
async fn required_digest_version_and_header_fields_cannot_be_weakened() {
    anvil_fixtures::init();
    let idp = IdpFixture::start(IdpOptions::default()).await.unwrap();
    let p = provider(&idp);
    let root = tempfile::tempdir().unwrap();
    let (dir, rk) = profile(root.path(), "alice");
    ProfileManager::link_identity(&dir, Unlock::Passphrase(PASS), sign_in(&p).await, false)
        .unwrap();
    let original = anvil_storage::vault::read_header(&dir).unwrap();
    let binding_path = dir.join(IDENTITY_FILE);
    let binding = std::fs::read(&binding_path).unwrap();
    let mut bad_binding: serde_json::Value = serde_json::from_slice(&binding).unwrap();
    bad_binding["version"] = 2.into();
    std::fs::write(&binding_path, serde_json::to_vec(&bad_binding).unwrap()).unwrap();
    assert!(matches!(
        rejected_install(&dir),
        AppError::Identity(IdentityPolicyError::BindingTampered),
    ));
    std::fs::write(&binding_path, &binding).unwrap();

    for mutation in 0..6 {
        let mut h = original.clone();
        let e = h.identity_binding.as_mut().unwrap();
        match mutation {
            0 => e.binding = None,
            1 => e.binding.as_mut().unwrap().version = 2,
            2 => e.binding.as_mut().unwrap().sha256 = "00".repeat(32),
            3 => e.version = 2,
            4 => h.identity_binding = None,
            5 => h.protection_mac = None,
            _ => unreachable!(),
        }
        anvil_storage::vault::write_header(&dir, &h).unwrap();
        rejected_install(&dir);
        // Recovery bypasses provider policy, never a bad protection MAC/format.
        assert!(ProfileManager::unlock(&dir, Unlock::RecoveryKey(&rk)).is_err());
    }
    let mut h = original.clone();
    h.identity_binding.as_mut().unwrap().binding = None;
    anvil_storage::vault::write_header(&dir, &h).unwrap();
    std::fs::remove_file(&binding_path).unwrap();
    assert!(matches!(rejected_install(&dir), AppError::Vault(VaultError::HeaderTampered)));
    assert!(ProfileManager::unlink_identity(&dir, Unlock::RecoveryKey(&rk), None).is_err());
    anvil_storage::vault::write_header(&dir, &original).unwrap();
    // A valid required header + missing binding is recoverable only explicitly.
    ProfileManager::unlink_identity(&dir, Unlock::RecoveryKey(&rk), None).unwrap();
    assert!(ProfileManager::unlock(&dir, Unlock::Passphrase(PASS)).is_ok());
}

#[tokio::test]
async fn a_matching_file_digest_does_not_replace_profile_specific_binding_authentication() {
    use anvil_storage::{crypto, vault};
    use vault::IdentityBindingPublication;

    anvil_fixtures::init();
    let idp = IdpFixture::start(IdpOptions::default()).await.unwrap();
    let p = provider(&idp);
    let root = tempfile::tempdir().unwrap();
    let (dir, rk) = profile(root.path(), "draft");
    let linked = ProfileManager::link_identity(
        &dir,
        Unlock::Passphrase(PASS),
        sign_in(&p).await,
        false,
    )
    .unwrap();
    let h = vault::read_header(&dir).unwrap();
    let key = vault::unlock_with_recovery(&h, &rk).unwrap();
    let bytes = std::fs::read(dir.join(IDENTITY_FILE)).unwrap();
    let mut file: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    file["sealed"] = hex::encode(crypto::seal(
        &key,
        b"anvil-identity-binding-v1/a-different-profile",
        &serde_json::to_vec(&linked).unwrap(),
    ))
    .into();
    let contents = serde_json::to_string_pretty(&file).unwrap();
    let publication = IdentityBindingPublication {
        binding: Some(vault::identity_binding_digest(contents.as_bytes(), 1)),
        contents: Some(contents),
    };
    // Test-only authenticated malformed state: even with a matching digest,
    // the production verifier must reject the wrong-profile AEAD envelope.
    let guard = vault::lock_identity_header(&dir).unwrap();
    guard.begin_identity_publication(&h, &key, publication).unwrap();
    guard.finish_identity_publication(&key).unwrap();
    drop(guard);
    assert!(matches!(
        rejected_install(&dir),
        AppError::Identity(IdentityPolicyError::BindingTampered),
    ));
    ProfileManager::unlink_identity(&dir, Unlock::RecoveryKey(&rk), None).unwrap();
}

#[tokio::test]
async fn interrupted_link_and_unlink_require_explicit_authenticated_journal_recovery() {
    use anvil_storage::vault::{self, IdentityBindingPublication};

    anvil_fixtures::init();
    let idp = IdpFixture::start(IdpOptions::default()).await.unwrap();
    let p = provider(&idp);
    let root = tempfile::tempdir().unwrap();
    let (dir, rk) = profile(root.path(), "alice");
    let unlinked = vault::read_header(&dir).unwrap();
    let key = vault::unlock_with_recovery(&unlinked, &rk).unwrap();
    ProfileManager::link_identity(&dir, Unlock::Passphrase(PASS), sign_in(&p).await, true)
        .unwrap();
    let linked = vault::read_header(&dir).unwrap();
    let contents = std::fs::read_to_string(dir.join(IDENTITY_FILE)).unwrap();
    let publication = IdentityBindingPublication {
        binding: linked.identity_binding.as_ref().unwrap().binding.clone(),
        contents: Some(contents.clone()),
    };

    // Replay a test snapshot to exercise each actual publication boundary:
    // after pending header, after next file, and after final header. Only the
    // header journal supplies recovery bytes; the disk binding may be garbage.
    for file_published in [false, true] {
        vault::write_header(&dir, &unlinked).unwrap();
        std::fs::remove_file(dir.join(IDENTITY_FILE)).unwrap();
        let guard = vault::lock_identity_header(&dir).unwrap();
        guard.begin_identity_publication(&unlinked, &key, publication.clone()).unwrap();
        drop(guard);
        if file_published {
            std::fs::write(dir.join(IDENTITY_FILE), &contents).unwrap();
        }
        assert!(matches!(
            rejected_install(&dir),
            AppError::Identity(IdentityPolicyError::PublicationPending),
        ));
        // Wrong credentials cannot finalize a journal or write the binding.
        let before = std::fs::read(dir.join("profile.json")).unwrap();
        assert!(
            ProfileManager::recover_identity_publication(&dir, Unlock::Passphrase("wrong")).is_err()
        );
        assert_eq!(std::fs::read(dir.join("profile.json")).unwrap(), before);
        assert!(ProfileManager::unlock(&dir, Unlock::RecoveryKey(&rk)).is_ok());
        assert_eq!(
            std::fs::read(dir.join("profile.json")).unwrap(),
            before,
            "unlock did not repair",
        );
        std::fs::write(dir.join(IDENTITY_FILE), b"attacker hint").unwrap();
        ProfileManager::recover_identity_publication(&dir, Unlock::RecoveryKey(&rk)).unwrap();
        assert_eq!(std::fs::read_to_string(dir.join(IDENTITY_FILE)).unwrap(), contents);
        assert!(matches!(
            rejected_install(&dir),
            AppError::Identity(IdentityPolicyError::FreshLoginRequired { .. }),
        ));
        assert!(ProfileManager::unlock_with_fresh_login(
            &dir,
            Unlock::Passphrase(PASS),
            sign_in(&p).await,
        )
        .is_ok());
        assert!(
            ProfileManager::recover_identity_publication(&dir, Unlock::RecoveryKey(&rk)).is_err()
        );
    }

    for file_removed in [false, true] {
        vault::write_header(&dir, &linked).unwrap();
        std::fs::write(dir.join(IDENTITY_FILE), &contents).unwrap();
        let guard = vault::lock_identity_header(&dir).unwrap();
        guard
            .begin_identity_publication(
                &linked,
                &key,
                IdentityBindingPublication { binding: None, contents: None },
            )
            .unwrap();
        drop(guard);
        if file_removed {
            std::fs::remove_file(dir.join(IDENTITY_FILE)).unwrap();
        }
        assert!(matches!(
            rejected_install(&dir),
            AppError::Identity(IdentityPolicyError::PublicationPending),
        ));
        ProfileManager::recover_identity_publication(&dir, Unlock::Passphrase(PASS)).unwrap();
        assert!(!dir.join(IDENTITY_FILE).exists());
        assert!(ProfileManager::unlock(&dir, Unlock::Passphrase(PASS)).is_ok());
        assert!(ProfileManager::linked_identity(&dir, &key).unwrap().is_none());
    }
}

#[tokio::test]
async fn tampered_journal_cannot_resume_or_weaken_a_pending_change() {
    use anvil_storage::vault::{self, IdentityBindingPublication};

    anvil_fixtures::init();
    let idp = IdpFixture::start(IdpOptions::default()).await.unwrap();
    let p = provider(&idp);
    let root = tempfile::tempdir().unwrap();
    let (dir, rk) = profile(root.path(), "alice");
    ProfileManager::link_identity(&dir, Unlock::Passphrase(PASS), sign_in(&p).await, true)
        .unwrap();
    let h = vault::read_header(&dir).unwrap();
    let key = vault::unlock_with_recovery(&h, &rk).unwrap();
    let guard = vault::lock_identity_header(&dir).unwrap();
    let pending = guard
        .begin_identity_publication(
            &h,
            &key,
            IdentityBindingPublication { binding: None, contents: None },
        )
        .unwrap();
    drop(guard);
    let binding = std::fs::read(dir.join(IDENTITY_FILE)).unwrap();
    for remove_pending in [false, true] {
        let mut edited = pending.clone();
        let e = edited.identity_binding.as_mut().unwrap();
        if remove_pending {
            e.pending = None;
            e.binding = None;
            std::fs::remove_file(dir.join(IDENTITY_FILE)).unwrap();
        } else {
            e.pending.as_mut().unwrap().contents = Some("{}".into());
        }
        vault::write_header(&dir, &edited).unwrap();
        assert!(
            ProfileManager::recover_identity_publication(&dir, Unlock::RecoveryKey(&rk)).is_err()
        );
        rejected_install(&dir);
        std::fs::write(dir.join(IDENTITY_FILE), &binding).unwrap();
    }
    vault::write_header(&dir, &pending).unwrap();
    ProfileManager::recover_identity_publication(&dir, Unlock::RecoveryKey(&rk)).unwrap();
}

#[tokio::test]
async fn never_linked_profiles_work_and_legacy_enrollment_is_not_silent() {
    let root = tempfile::tempdir().unwrap();
    let (dir, rk) = profile(root.path(), "new draft profile");
    assert!(ProfileManager::unlock(&dir, Unlock::Passphrase(PASS)).is_ok());
    assert!(ProfileManager::unlock(&dir, Unlock::RecoveryKey(&rk)).is_ok());
    assert!(ProfileManager::unlock_requirements(&dir).unwrap().linked.is_none());
    assert!(ProfileManager::recover_identity_publication(&dir, Unlock::RecoveryKey(&rk)).is_err());
    let (legacy, _, _) = ProfileManager::new(root.path())
        .create_passphrase("legacy", PASS, KdfParams::testing())
        .unwrap();
    let before = std::fs::read(legacy.dir.join("profile.json")).unwrap();
    assert!(ProfileManager::unlock(&legacy.dir, Unlock::Passphrase(PASS)).is_ok());
    assert_eq!(std::fs::read(legacy.dir.join("profile.json")).unwrap(), before);
    anvil_fixtures::init();
    let idp = IdpFixture::start(IdpOptions::default()).await.unwrap();
    let e = policy_err(ProfileManager::link_identity(
        &legacy.dir,
        Unlock::Passphrase(PASS),
        sign_in(&provider(&idp)).await,
        true,
    ));
    assert_eq!(e, IdentityPolicyError::LegacyEnrollmentRequired);
    assert_eq!(std::fs::read(legacy.dir.join("profile.json")).unwrap(), before);
    assert!(!legacy.dir.join(IDENTITY_FILE).exists());
}

#[test]
fn an_open_draft_profile_cannot_reseal_a_field_stripped_legacy_header() {
    use anvil_storage::vault;

    let root = tempfile::tempdir().unwrap();
    let (dir, _) = profile(root.path(), "draft");
    let (h, key) = ProfileManager::unlock(&dir, Unlock::Passphrase(PASS)).unwrap();
    let app = App::open(dir.clone(), h.clone(), key).unwrap();
    let mut edited = h;
    edited.format = "anvil-profile".into();
    edited.identity_binding = None;
    edited.protection_mac = None;
    vault::write_header(&dir, &edited).unwrap();
    let before = std::fs::read(dir.join("profile.json")).unwrap();
    assert!(matches!(
        app.change_passphrase("replacement passphrase", KdfParams::testing()),
        Err(AppError::Vault(VaultError::HeaderTampered)),
    ));
    assert_eq!(std::fs::read(dir.join("profile.json")).unwrap(), before);
}

#[tokio::test]
async fn a_consistent_old_profile_snapshot_remains_replayable_in_this_partial_candidate() {
    anvil_fixtures::init();
    let idp = IdpFixture::start(IdpOptions::default()).await.unwrap();
    let p = provider(&idp);
    let root = tempfile::tempdir().unwrap();
    let (dir, _) = profile(root.path(), "draft");
    let (h, key) = ProfileManager::unlock(&dir, Unlock::Passphrase(PASS)).unwrap();
    let app = App::open(dir.clone(), h, key).unwrap();
    app.create_workspace("retained snapshot").unwrap();
    drop(app);
    let header = std::fs::read(dir.join("profile.json")).unwrap();
    let database = std::fs::read(dir.join(anvil_storage::store::DB_FILE)).unwrap();
    ProfileManager::link_identity(&dir, Unlock::Passphrase(PASS), sign_in(&p).await, true)
        .unwrap();
    std::fs::remove_file(dir.join(IDENTITY_FILE)).unwrap();
    assert!(ProfileManager::unlock(&dir, Unlock::Passphrase(PASS)).is_err());
    // Restoring the matching old header/database and old absence of a binding
    // restores an authentic unlinked state. This is an unresolved advisory
    // limit, explicitly a positive control against a false antirollback claim.
    std::fs::write(dir.join("profile.json"), header).unwrap();
    std::fs::write(dir.join(anvil_storage::store::DB_FILE), database).unwrap();
    let (h, key) = ProfileManager::unlock(&dir, Unlock::Passphrase(PASS)).unwrap();
    let app = App::open(dir, h, key).unwrap();
    assert!(app.find_workspace("retained snapshot").is_ok());
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
    async fn send(app: &App, ws: &anvil_domain::Id, rid: Option<anvil_domain::Id>) -> anvil_engine::ExecutionOutput {
        app.send(rid, ws, None, SendOptions::default(), EventCtx::none(), CancellationToken::new()).await.unwrap()
    }
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
