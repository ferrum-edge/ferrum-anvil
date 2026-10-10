use anvil_app::{App, exec::SendOptions, profiles::ProfileManager, settings_id};
use anvil_domain::{auth::AuthConfig, request::RequestSpec, secret::SensitiveValue};
use anvil_storage::{KdfParams, kind, store::DB_FILE, vault};
use rusqlite::{Connection, params};

fn app() -> (tempfile::TempDir, App) {
    let root = tempfile::tempdir().unwrap();
    let (s, k, _) = ProfileManager::new(root.path()).create_passphrase("test", "correct horse battery", KdfParams::testing()).unwrap();
    let h = vault::read_header(&s.dir).unwrap();
    let a = App::open(s.dir, h, k).unwrap();
    (root, a)
}

#[test]
fn settings_replay_and_removal_do_not_apply_weaker_defaults() {
    let (_root, app) = app();
    let raw = Connection::open(app.dir.join(DB_FILE)).unwrap();
    let old: Vec<u8> = raw
        .query_row("SELECT payload FROM objects WHERE kind=?1 AND id=?2", params![kind::APP_SETTINGS, settings_id().to_string()], |r| {
            r.get(0)
        })
        .unwrap();
    let mut settings = app.settings().unwrap();
    settings.lock.idle_minutes = 1;
    app.save_settings(&settings).unwrap();
    raw.execute("UPDATE objects SET payload=?1 WHERE kind=?2 AND id=?3", params![old, kind::APP_SETTINGS, settings_id().to_string()])
        .unwrap();
    assert!(app.settings().is_err());
    raw.execute("DELETE FROM objects WHERE kind=?1 AND id=?2", params![kind::APP_SETTINGS, settings_id().to_string()]).unwrap();
    assert!(app.settings().is_err());
}

#[test]
fn cached_secrets_are_refused_after_edit_or_external_replay() {
    let (_root, app) = app();
    let ws = app.create_workspace("workspace").unwrap();
    let secret = app.set_secret(&ws.meta.id, "credential", "original").unwrap();
    let mut spec = RequestSpec::http("GET", "https://example.invalid/");
    spec.auth = AuthConfig::Bearer { token: SensitiveValue::Secret { secret: secret.clone() }, prefix: "Bearer".into() };
    let request = app.create_request(&ws.meta.id, None, "request", spec).unwrap();
    let ctx = app.build_context(Some(request.meta.id), &ws.meta.id, None, &SendOptions::default()).unwrap();
    assert_eq!(ctx.secrets.resolve(&secret).unwrap().as_str(), "original");
    // Legitimate unrelated edits stale existing contexts, without relocking.
    app.create_workspace("other workspace").unwrap();
    assert!(ctx.secrets.validate_context().unwrap_err().contains("configuration changed"));
    assert!(!app.is_locked());
    let fresh = app.build_context(Some(request.meta.id), &ws.meta.id, None, &SendOptions::default()).unwrap();
    let raw = Connection::open(app.dir.join(DB_FILE)).unwrap();
    raw.execute("DELETE FROM secrets WHERE id=?1", [secret.id.to_string()]).unwrap();
    assert!(fresh.secrets.resolve(&secret).is_err(), "the cached value must not bypass authenticated presence");
    assert!(app.is_locked(), "authority preflight locks after integrity failure");
}

#[test]
fn deleted_device_deny_record_is_not_treated_as_permission() {
    let (_root, app) = app();
    let ws = app.create_workspace("workspace").unwrap();
    app.store
        .put(
            kind::DEVICE_IDENTITY_SEAL,
            &ws.meta.id,
            Some(&ws.meta.id),
            None,
            0.0,
            &serde_json::json!({"workspace_id":ws.meta.id,"sealed_at":chrono::Utc::now()}),
        )
        .unwrap();
    assert!(app.device_identity_sealed(&ws.meta.id).unwrap());
    let raw = Connection::open(app.dir.join(DB_FILE)).unwrap();
    raw.execute("DELETE FROM objects WHERE kind=?1 AND id=?2", params![kind::DEVICE_IDENTITY_SEAL, ws.meta.id.to_string()]).unwrap();
    assert!(app.device_identity_sealed(&ws.meta.id).is_err());
    assert!(
        app.build_context(None, &ws.meta.id, Some(RequestSpec::http("GET", "https://example.invalid/")), &SendOptions::default()).is_err()
    );
    assert!(app.is_locked());
}
