//! Legacy ambiguity is explicit; historical owner restore remains possible.
use anvil_app::identity::IdentityPolicyError;
use anvil_app::profiles::{PolicyRotation, ProfileManager, Unlock};
use anvil_app::{App, AppError};
use anvil_storage::{KdfParams, Key, Store, vault};
const OLD: &str = "old legacy passphrase";
const NEW: &str = "replacement passphrase";

#[test]
fn missing_legacy_policy_blocks_normal_unlock_and_implicit_rotation() {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("legacy");
    let legacy = vault::create_passphrase_profile(&dir, "legacy", OLD, KdfParams::testing()).unwrap();
    let historical_key = Key::from_bytes(legacy.dek.as_bytes()).unwrap();
    let app = App::open(dir.clone(), legacy.header, legacy.dek).unwrap();
    let ws = app.create_workspace("kept").unwrap();
    assert!(matches!(
        ProfileManager::unlock(&dir, Unlock::Passphrase(OLD)),
        Err(AppError::Identity(IdentityPolicyError::PolicyEnrollmentRequired))
    ));
    let replacement = vault::RotationRecoveryKey::generate();
    assert!(app.rotate_data_key(NEW, &replacement, KdfParams::testing()).is_err());
    assert!(vault::read_header(&dir).unwrap().rotation.is_none());
    let refusal = ProfileManager::enroll_unlinked_policy(
        &dir,
        Unlock::Passphrase(OLD),
        PolicyRotation { new_passphrase: OLD, recovery: &replacement, kdf: KdfParams::testing() },
    )
    .unwrap_err();
    assert!(refusal.to_string().contains("different from the current"));
    assert!(vault::read_header(&dir).unwrap().rotation.is_none());
    assert_eq!(app.workspace(&ws.meta.id).unwrap().name, "kept");
    ProfileManager::enroll_unlinked_policy(
        &dir,
        Unlock::Passphrase(OLD),
        PolicyRotation { new_passphrase: NEW, recovery: &replacement, kdf: KdfParams::testing() },
    )
    .unwrap();
    assert!(Store::open(&dir, historical_key).is_err());
    assert!(ProfileManager::unlock(&dir, Unlock::Passphrase(OLD)).is_err());
    assert!(ProfileManager::unlock(&dir, Unlock::RecoveryKey(legacy.recovery_key.as_ref().unwrap())).is_err());
    let (h, key) = ProfileManager::unlock(&dir, Unlock::RecoveryKey(replacement.as_str())).unwrap();
    assert!(h.rotation.is_some());
    assert_eq!(App::open(dir, h, key).unwrap().workspace(&ws.meta.id).unwrap().name, "kept");
}

#[test]
fn new_profiles_cannot_silently_lose_authenticated_policy() {
    let root = tempfile::tempdir().unwrap();
    let (s, _, _) = ProfileManager::new(root.path()).create_passphrase("new", OLD, KdfParams::testing()).unwrap();
    assert!(vault::read_header(&s.dir).unwrap().rotation.is_some());
    let conn = rusqlite::Connection::open(s.dir.join("anvil.db")).unwrap();
    conn.execute("DELETE FROM meta WHERE key='local_key_state_v1'", []).unwrap();
    assert!(ProfileManager::unlock(&s.dir, Unlock::Passphrase(OLD)).is_err());
    assert!(
        ProfileManager::enroll_unlinked_policy(
            &s.dir,
            Unlock::Passphrase(OLD),
            PolicyRotation { new_passphrase: NEW, recovery: &vault::RotationRecoveryKey::generate(), kdf: KdfParams::testing() }
        )
        .is_err(),
        "missing enrolled state must not reenroll silently"
    );
}

#[test]
fn a_replacement_recovery_credential_cannot_be_reused_for_another_rotation() {
    let root = tempfile::tempdir().unwrap();
    let (s, key, _) = ProfileManager::new(root.path()).create_passphrase("recovery", OLD, KdfParams::testing()).unwrap();
    let app = App::open(s.dir.clone(), vault::read_header(&s.dir).unwrap(), key).unwrap();
    let replacement = vault::RotationRecoveryKey::generate();
    app.change_passphrase(NEW, &replacement, KdfParams::testing()).unwrap();
    let (h, key) = ProfileManager::unlock(&s.dir, Unlock::Passphrase(NEW)).unwrap();
    let app = App::open(s.dir.clone(), h, key).unwrap();
    assert!(app.change_passphrase("yet another passphrase", &replacement, KdfParams::testing()).is_err());
    assert!(ProfileManager::unlock(&s.dir, Unlock::Passphrase(NEW)).is_ok());
}

#[test]
fn complete_authentic_local_snapshot_restore_is_an_explicit_offline_boundary() {
    let root = tempfile::tempdir().unwrap();
    let (s, key, recovery) = ProfileManager::new(root.path()).create_passphrase("historical", OLD, KdfParams::testing()).unwrap();
    let app = App::open(s.dir.clone(), vault::read_header(&s.dir).unwrap(), key).unwrap();
    app.create_workspace("historical").unwrap();
    let snapshot = app.store.checkpoint("owner historical snapshot").unwrap();
    app.change_passphrase(NEW, &vault::RotationRecoveryKey::generate(), KdfParams::testing()).unwrap();
    drop(app);
    // Deliberate external replacement restores *all* trusted profile state,
    // including the authentic canonical header/policy and its canary.
    std::fs::copy(snapshot, s.dir.join("anvil.db")).unwrap();
    let (h, key) = ProfileManager::unlock(&s.dir, Unlock::RecoveryKey(&recovery)).unwrap();
    assert!(App::open(s.dir, h, key).unwrap().find_workspace("historical").is_ok());
}
