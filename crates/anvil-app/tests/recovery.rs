//! LOCK/recovery: forgotten passphrase → recovery key → new passphrase.

use anvil_app::App;
use anvil_app::profiles::{ProfileManager, Unlock};
use anvil_storage::KdfParams;

#[test]
fn recovery_key_then_new_passphrase_keeps_data() {
    let root = tempfile::tempdir().unwrap();
    let pm = ProfileManager::new(root.path());
    let (s, dek, recovery) = pm.create_passphrase("r", "old passphrase 1", KdfParams::testing()).unwrap();
    let h = anvil_storage::vault::read_header(&s.dir).unwrap();
    let app = App::open(s.dir.clone(), h, dek).unwrap();
    let ws = app.create_workspace("kept").unwrap();
    app.lock();
    drop(app);

    // Forgot the passphrase: unlock with the recovery key.
    assert!(ProfileManager::unlock(&s.dir, Unlock::Passphrase("wrong guess 12")).is_err());
    let (h, dek) = ProfileManager::unlock(&s.dir, Unlock::RecoveryKey(&recovery)).unwrap();
    let app = App::open(s.dir.clone(), h, dek).unwrap();
    assert_eq!(app.workspace(&ws.meta.id).unwrap().name, "kept");
    assert!(app.change_passphrase("short", KdfParams::testing()).is_err());
    app.change_passphrase("brand new passphrase", KdfParams::testing()).unwrap();
    drop(app);

    assert!(ProfileManager::unlock(&s.dir, Unlock::Passphrase("old passphrase 1")).is_err(), "old passphrase no longer unlocks");
    let (h, dek) = ProfileManager::unlock(&s.dir, Unlock::Passphrase("brand new passphrase")).unwrap();
    let app = App::open(s.dir.clone(), h, dek).unwrap();
    assert_eq!(app.workspace(&ws.meta.id).unwrap().name, "kept");
    // The recovery key still works after the change.
    assert!(ProfileManager::unlock(&s.dir, Unlock::RecoveryKey(&recovery)).is_ok());
}
