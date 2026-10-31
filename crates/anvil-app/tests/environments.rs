use anvil_app::App;
use anvil_app::exec::SendOptions;
use anvil_app::profiles::{ProfileManager, Unlock};
use anvil_app::runner::RunSettings;
use anvil_domain::request::RequestSpec;
use anvil_domain::workspace::ScenarioStep;
use anvil_storage::KdfParams;
use tokio_util::sync::CancellationToken;

const PASSPHRASE: &str = "correct horse battery";

fn new_app(root: &std::path::Path, name: &str) -> App {
    let pm = ProfileManager::new(root);
    let (store, dek, _recovery) = pm.create_passphrase(name, PASSPHRASE, KdfParams::testing()).unwrap();
    let header = anvil_storage::vault::read_header(&store.dir).unwrap();
    App::open(store.dir, header, dek).unwrap()
}

#[test]
fn deleting_active_environment_clears_selection_atomically_and_survives_reopen() {
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path(), "environment-delete");
    let workspace = app.create_workspace("Workspace").unwrap();
    let request = app.create_request(&workspace.meta.id, None, "Literal", RequestSpec::http("GET", "http://127.0.0.1/")).unwrap();
    let active = app.create_environment(&workspace.meta.id, "active", vec![]).unwrap();
    let inactive = app.create_environment(&workspace.meta.id, "inactive", vec![]).unwrap();
    let mut saved = app.workspace(&workspace.meta.id).unwrap();
    saved.active_environment_id = Some(active.meta.id);
    app.save_workspace(saved).unwrap();

    app.delete_environment(&inactive.meta.id).unwrap();
    assert_eq!(app.workspace(&workspace.meta.id).unwrap().active_environment_id, Some(active.meta.id));

    let profile_dir = app.dir.clone();
    app.delete_environment(&active.meta.id).unwrap();
    assert_eq!(app.workspace(&workspace.meta.id).unwrap().active_environment_id, None);
    drop(app);

    let (header, dek) = ProfileManager::unlock(&profile_dir, Unlock::Passphrase(PASSPHRASE)).unwrap();
    let reopened = App::open(profile_dir, header, dek).unwrap();
    assert_eq!(reopened.workspace(&workspace.meta.id).unwrap().active_environment_id, None);
    assert!(reopened.environments(&workspace.meta.id).unwrap().is_empty());
    let context = reopened.build_context(Some(request.meta.id), &workspace.meta.id, None, &SendOptions::default()).unwrap();
    assert_eq!(context.environment_id, None);
}

#[test]
fn missing_workspace_default_falls_back_but_explicit_missing_environment_errors() {
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path(), "environment-fallback");
    let workspace = app.create_workspace("Workspace").unwrap();
    let request = app.create_request(&workspace.meta.id, None, "Literal", RequestSpec::http("GET", "http://127.0.0.1/")).unwrap();
    let missing = anvil_domain::Id::new();
    let mut saved = app.workspace(&workspace.meta.id).unwrap();
    saved.active_environment_id = Some(missing);
    app.save_workspace(saved).unwrap();

    let context = app.build_context(Some(request.meta.id), &workspace.meta.id, None, &SendOptions::default()).unwrap();
    assert_eq!(context.environment_id, None);

    let explicit = SendOptions { environment: Some(missing), ..Default::default() };
    let error = app.build_context(Some(request.meta.id), &workspace.meta.id, None, &explicit).err().unwrap();
    assert!(error.to_string().contains("environment"), "unexpected error: {error}");
}

#[tokio::test]
async fn collection_run_reports_when_a_dangling_default_is_ignored() {
    anvil_fixtures::init();
    let fixture = anvil_fixtures::http::serve("127.0.0.1:0", None).await.unwrap();
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path(), "environment-run-fallback");
    let workspace = app.create_workspace("Workspace").unwrap();
    let request = app.create_request(&workspace.meta.id, None, "Literal", RequestSpec::http("GET", &fixture.url("/status/200"))).unwrap();
    let scenario = app
        .create_scenario(&workspace.meta.id, "Scenario", vec![ScenarioStep { request_id: request.meta.id, enabled: true, delay_ms: 0 }])
        .unwrap();
    let missing = anvil_domain::Id::new();
    let mut saved = app.workspace(&workspace.meta.id).unwrap();
    saved.active_environment_id = Some(missing);
    app.save_workspace(saved).unwrap();

    let report = app
        .run_scenario(&scenario.meta.id, RunSettings { persist_report: false, ..Default::default() }, CancellationToken::new())
        .await
        .unwrap();
    assert!(report.passed(), "{report:#?}");
    assert!(report.notes.iter().any(|note| note.contains("no environment was used")), "{:?}", report.notes);
}

#[test]
fn setting_a_variable_keeps_secrets_in_the_vault_and_one_value_per_name() {
    use anvil_domain::secret::SensitiveValue;
    use anvil_domain::workspace::Variable;
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path(), "environment-set");
    let ws = app.create_workspace("Workspace").unwrap();
    let dup = |v: &str| Variable { enabled: false, ..Variable::plain("token", v) };
    let env = app.create_environment(&ws.meta.id, "dev", vec![Variable::plain("base", "http://x"), dup("a"), dup("b")]).unwrap();

    // A plain value replaces the first variable of the name, enabled, and
    // drops the others; the other variables stay as they were.
    let e = app.set_environment_variable(&env.meta.id, "token", "plain", false).unwrap();
    let names: Vec<_> = e.variables.iter().map(|v| v.name.as_str()).collect();
    assert_eq!(names, ["base", "token"]);
    assert_eq!(e.variables[1].value, SensitiveValue::template("plain"));
    assert!(e.variables[1].enabled && !e.variables[1].secret);

    // Made secret: the environment holds only a reference to a vault entry
    // the workspace owns.
    let e = app.set_environment_variable(&env.meta.id, "token", "s3cret-value", true).unwrap();
    let v = e.variables.iter().find(|v| v.name == "token").unwrap();
    assert!(v.secret);
    let SensitiveValue::Secret { secret } = &v.value else { panic!("not in the vault: {v:?}") };
    let (_, stored) = app.store.get_workspace_secret(&secret.id, &ws.meta.id).unwrap().unwrap();
    assert_eq!(stored.as_str(), "s3cret-value");
    let raw = serde_json::to_string(&app.environments(&ws.meta.id).unwrap()).unwrap();
    assert!(!raw.contains("s3cret-value"), "{raw}");

    // A secret stays secret when set again without asking for it.
    let e = app.set_environment_variable(&env.meta.id, "token", "next-value", false).unwrap();
    let v = e.variables.iter().find(|v| v.name == "token").unwrap();
    assert!(v.secret && matches!(v.value, SensitiveValue::Secret { .. }), "{v:?}");

    // Names that cannot be referenced are refused, with nothing written.
    for bad in ["", " token", "{{token}}"] {
        assert!(app.set_environment_variable(&env.meta.id, bad, "x", false).is_err(), "{bad:?}");
    }
    assert_eq!(app.environments(&ws.meta.id).unwrap()[0].variables.len(), 2);

    // Unset removes it, and reports a name that is not there.
    let (e, removed) = app.unset_environment_variable(&env.meta.id, "token").unwrap();
    assert!(removed && e.variables.iter().all(|v| v.name != "token"));
    assert!(!app.unset_environment_variable(&env.meta.id, "token").unwrap().1);
}

#[test]
fn the_active_environment_must_belong_to_the_workspace() {
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path(), "environment-use");
    let ws = app.create_workspace("Workspace").unwrap();
    let other = app.create_workspace("Other").unwrap();
    let mine = app.create_environment(&ws.meta.id, "mine", vec![]).unwrap();
    let theirs = app.create_environment(&other.meta.id, "theirs", vec![]).unwrap();

    assert_eq!(app.set_active_environment(&ws.meta.id, Some(&mine.meta.id)).unwrap().active_environment_id, Some(mine.meta.id));
    assert!(app.set_active_environment(&ws.meta.id, Some(&theirs.meta.id)).is_err());
    assert!(app.set_active_environment(&ws.meta.id, Some(&anvil_domain::Id::new())).is_err());
    assert_eq!(app.workspace(&ws.meta.id).unwrap().active_environment_id, Some(mine.meta.id));
    assert_eq!(app.set_active_environment(&ws.meta.id, None).unwrap().active_environment_id, None);
}

#[test]
fn a_secret_is_never_made_plain_and_displaced_vault_entries_are_released() {
    use anvil_domain::secret::{SecretRef, SensitiveValue};
    use anvil_domain::workspace::Variable;
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path(), "environment-secret-release");
    let ws = app.create_workspace("Workspace").unwrap();
    let vault = |v: &str| {
        let r = app.set_secret(&ws.meta.id, "token", v).unwrap();
        (r.clone(), SensitiveValue::Secret { secret: r })
    };
    let secret_ref = |e: &anvil_domain::workspace::Environment| match &e.variables.iter().find(|v| v.name == "token").unwrap().value {
        SensitiveValue::Secret { secret } => secret.clone(),
        v => panic!("not in the vault: {v:?}"),
    };
    let stored = |r: &SecretRef| app.store.get_workspace_secret(&r.id, &ws.meta.id).unwrap().map(|(_, v)| v.to_string());

    // A plain duplicate before a secret one, and a vault value whose flag
    // is off: either way the value set goes to the vault.
    let (old_a, held_a) = vault("old-a");
    let plain_then_secret =
        vec![Variable::plain("token", "plain"), Variable { secret: true, value: held_a, ..Variable::plain("token", "") }];
    let a = app.create_environment(&ws.meta.id, "a", plain_then_secret).unwrap();
    let (old_b, held_b) = vault("old-b");
    let b =
        app.create_environment(&ws.meta.id, "b", vec![Variable { secret: false, value: held_b, ..Variable::plain("token", "") }]).unwrap();
    for (env, old) in [(&a, &old_a), (&b, &old_b)] {
        let e = app.set_environment_variable(&env.meta.id, "token", "new", false).unwrap();
        assert_eq!(e.variables.iter().filter(|v| v.name == "token").count(), 1);
        let now = secret_ref(&e);
        assert!(e.variables.iter().all(|v| v.name != "token" || v.secret));
        assert_eq!(stored(&now).as_deref(), Some("new"));
        // Nothing else referenced the old entry: it is gone.
        assert_eq!(stored(old), None);
    }

    // An entry another object still references is kept; unset releases
    // the last reference.
    let shared = secret_ref(&app.environments(&ws.meta.id).unwrap().into_iter().find(|e| e.name == "a").unwrap());
    let copy = app
        .create_environment(
            &ws.meta.id,
            "copy",
            vec![Variable { secret: true, value: SensitiveValue::Secret { secret: shared.clone() }, ..Variable::plain("token", "") }],
        )
        .unwrap();
    app.set_environment_variable(&a.meta.id, "token", "rotated", true).unwrap();
    assert_eq!(stored(&shared).as_deref(), Some("new"), "still referenced by 'copy'");
    let (_, removed) = app.unset_environment_variable(&copy.meta.id, "token").unwrap();
    assert!(removed);
    assert_eq!(stored(&shared), None);
}

#[test]
fn a_named_environment_is_created_once_and_optionally_made_active() {
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path(), "environment-create");
    let ws = app.create_workspace("Workspace").unwrap();
    let dev = app.create_named_environment(&ws.meta.id, "  dev ", false).unwrap();
    assert_eq!(dev.name, "dev");
    assert_eq!(app.workspace(&ws.meta.id).unwrap().active_environment_id, None);
    assert!(app.create_named_environment(&ws.meta.id, "DEV", true).is_err());
    assert!(app.create_named_environment(&ws.meta.id, "  ", false).is_err());
    let prod = app.create_named_environment(&ws.meta.id, "prod", true).unwrap();
    assert_eq!(app.workspace(&ws.meta.id).unwrap().active_environment_id, Some(prod.meta.id));
    assert_eq!(app.environments(&ws.meta.id).unwrap().len(), 2);
}
