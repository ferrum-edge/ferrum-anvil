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
