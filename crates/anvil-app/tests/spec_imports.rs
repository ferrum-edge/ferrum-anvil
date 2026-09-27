//! Spec/collection imports persisted by the app: every import is an
//! independent copy, an import is written all at once or not at all, and an
//! import into an existing workspace keeps the source's own scope instead of
//! picking up the destination workspace's auth.

use anvil_app::exec::SendOptions;
use anvil_app::profiles::ProfileManager;
use anvil_app::runner::RunSettings;
use anvil_app::specs::{SpecSourceRecord, SpecTarget};
use anvil_app::{App, AppError};
use anvil_domain::Id;
use anvil_domain::assertions::{Extraction, ExtractionSource};
use anvil_domain::auth::AuthConfig;
use anvil_domain::execution::ExecutionRecord;
use anvil_domain::load::{LoadPlan, Workload};
use anvil_domain::request::{Body, KeyValue, RequestSpec};
use anvil_domain::runner::RunStepStatus;
use anvil_domain::secret::SensitiveValue;
use anvil_domain::settings::ProxySelection;
use anvil_domain::tls::{ClientIdentity, HostBinding, ProxyKind, ProxyProfile, TlsProfile};
use anvil_domain::workload::{JwtSvidConfig, JwtSvidSource};
use anvil_domain::workspace::{Environment, RequestRevision, Variable, Workspace};
use anvil_engine::ExecutionContext;
use anvil_fixtures::GroundTruth;
use anvil_import::{ImportOptions, ReimportApproval};
use anvil_portability::ExportMode;
use anvil_portability::plan::ConflictPolicy;
use anvil_storage::KdfParams;
use anvil_storage::store::{DB_FILE, kind};
use anvil_transport::recorder::EventCtx;
use std::collections::HashSet;
use std::path::Path;
use tokio_util::sync::CancellationToken;

fn new_app(root: &Path) -> App {
    let pm = ProfileManager::new(root);
    let (s, dek, _recovery) = pm.create_passphrase("t", "correct horse battery", KdfParams::testing()).unwrap();
    let h = anvil_storage::vault::read_header(&s.dir).unwrap();
    App::open(s.dir, h, dek).unwrap()
}

const CURL: &[u8] = b"curl https://example.invalid/health";

const COLLECTION: &str = r#"{
  "info": { "name": "Echo", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json" },
  "auth": { "type": "noauth" },
  "variable": [{ "key": "base", "value": "https://api.example.invalid" }],
  "item": [
    { "name": "Health", "request": { "method": "GET", "url": { "raw": "{{base}}/health" } } },
    { "name": "Concrete", "request": { "method": "GET", "url": { "raw": "https://api.example.invalid/concrete" } } },
    { "name": "Nested", "item": [
      { "name": "Deep", "request": { "method": "GET", "url": { "raw": "{{base}}/deep" } } }
    ] }
  ]
}"#;

fn into(ws: &Id) -> SpecTarget {
    SpecTarget::Workspace { workspace_id: *ws }
}

fn import(app: &App, bytes: &[u8], target: SpecTarget) -> anvil_app::specs::SpecImported {
    app.spec_import(bytes, "source.txt", &ImportOptions::default(), target).unwrap()
}

fn request_ids(app: &App, ws: &Id) -> HashSet<Id> {
    app.requests(ws).unwrap().into_iter().map(|q| q.meta.id).collect()
}

// ---------------------------------------------------------------- identity

#[test]
fn the_same_source_imported_into_two_workspaces_creates_independent_copies() {
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let one = app.create_workspace("One").unwrap();
    let two = app.create_workspace("Two").unwrap();
    let first = import(&app, CURL, into(&one.meta.id));
    // The user edits the first copy.
    let mut edited = app.requests(&one.meta.id).unwrap().pop().unwrap();
    edited.name = "Mine".into();
    app.save_request(edited.clone()).unwrap();

    let second = import(&app, CURL, into(&two.meta.id));
    assert_ne!(first.import_id, second.import_id);
    assert_eq!(app.requests(&one.meta.id).unwrap().len(), 1, "the first import keeps its request");
    assert_eq!(app.requests(&two.meta.id).unwrap().len(), 1);
    let kept = app.request(&edited.meta.id).unwrap();
    assert_eq!((kept.workspace_id, kept.folder_id, kept.name.as_str()), (one.meta.id, first.root_folder_id, "Mine"));
    assert!(request_ids(&app, &one.meta.id).is_disjoint(&request_ids(&app, &two.meta.id)));
    assert_eq!(app.spec_sources(&one.meta.id).unwrap().len(), 1);
    assert_eq!(app.spec_sources(&two.meta.id).unwrap().len(), 1);
}

#[test]
fn the_same_source_imported_twice_into_one_workspace_creates_two_copies() {
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let ws = app.create_workspace("One").unwrap();
    let first = import(&app, CURL, into(&ws.meta.id));
    let second = import(&app, CURL, into(&ws.meta.id));
    assert_ne!(first.root_folder_id, second.root_folder_id);
    let requests = app.requests(&ws.meta.id).unwrap();
    assert_eq!(requests.len(), 2);
    let homes: HashSet<Option<Id>> = requests.iter().map(|q| q.folder_id).collect();
    assert_eq!(homes, HashSet::from([first.root_folder_id, second.root_folder_id]), "each copy stays under its own root folder");
    let sources = app.spec_sources(&ws.meta.id).unwrap();
    assert_eq!(sources.len(), 2);
    assert_ne!(sources[0].source.id_namespace, sources[1].source.id_namespace);

    // Two new workspaces from the same source are independent as well.
    let a = import(&app, CURL, SpecTarget::NewWorkspace);
    let b = import(&app, CURL, SpecTarget::NewWorkspace);
    assert_ne!(a.workspace_id, b.workspace_id);
    assert_eq!(app.requests(&a.workspace_id).unwrap().len(), 1);
    assert_eq!(app.requests(&b.workspace_id).unwrap().len(), 1);
}

#[test]
fn a_caller_supplied_id_namespace_never_reuses_an_earlier_imports_ids() {
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let one = app.create_workspace("One").unwrap();
    let two = app.create_workspace("Two").unwrap();
    let first = import(&app, CURL, into(&one.meta.id));
    let namespace = app.spec_sources(&one.meta.id).unwrap()[0].source.id_namespace;
    let opts = ImportOptions { id_namespace: Some(namespace), ..Default::default() };
    app.spec_import(CURL, "source.txt", &opts, into(&two.meta.id)).unwrap();
    assert_eq!(app.requests(&one.meta.id).unwrap().len(), 1);
    assert_eq!(app.requests(&two.meta.id).unwrap().len(), 1);
    assert!(request_ids(&app, &one.meta.id).is_disjoint(&request_ids(&app, &two.meta.id)));
    // The first import's reimport still finds exactly its own request.
    let plan = app.spec_reimport_plan(&first.import_id, CURL).unwrap();
    assert_eq!((plan.unchanged.len(), plan.added.len(), plan.removed.len()), (1, 0, 0));
}

#[test]
fn a_reimport_updates_only_its_own_copy() {
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let one = app.create_workspace("One").unwrap();
    let two = app.create_workspace("Two").unwrap();
    let first = import(&app, CURL, into(&one.meta.id));
    import(&app, CURL, into(&two.meta.id));
    let before_two = app.requests(&two.meta.id).unwrap();
    let newer = b"curl -H 'X-Version: 2' https://example.invalid/health";
    app.spec_reimport_apply(&first.import_id, newer, "source.txt", &ReimportApproval::default()).unwrap();
    let one_after = app.requests(&one.meta.id).unwrap();
    assert_eq!(one_after.len(), 1);
    assert!(one_after[0].spec.headers.iter().any(|h| h.name == "X-Version"), "the reimport updated its own copy");
    assert_eq!(app.requests(&two.meta.id).unwrap(), before_two, "the other copy is untouched");
}

// ---------------------------------------------------------------- atomicity

/// Every row the profile holds, so a failed import can be compared with
/// the state before it.
fn inventory(app: &App) -> Vec<String> {
    let db = rusqlite::Connection::open(app.dir.join(DB_FILE)).unwrap();
    let mut out = Vec::new();
    for sql in [
        "SELECT 'object:' || kind || ':' || id FROM objects",
        "SELECT 'blob:' || id FROM blobs",
        "SELECT 'meta:' || key FROM meta WHERE key LIKE 'pin:%'",
        "SELECT 'secret:' || id FROM secrets",
    ] {
        let mut st = db.prepare(sql).unwrap();
        out.extend(st.query_map([], |r| r.get::<_, String>(0)).unwrap().map(Result::unwrap));
    }
    out.sort();
    out
}

/// Make the next write that matches `when` fail inside SQLite.
fn fail_writes(app: &App, table: &str, when: &str) {
    let db = rusqlite::Connection::open(app.dir.join(DB_FILE)).unwrap();
    let trigger = format!("CREATE TRIGGER injected_failure BEFORE INSERT ON {table} WHEN {when}");
    db.execute_batch(&format!("{trigger} BEGIN SELECT RAISE(ABORT, 'injected failure'); END;")).unwrap();
}

fn allow_writes(app: &App) {
    let db = rusqlite::Connection::open(app.dir.join(DB_FILE)).unwrap();
    db.execute_batch("DROP TRIGGER IF EXISTS injected_failure;").unwrap();
}

fn targets(app: &App) -> Vec<(&'static str, SpecTarget)> {
    let ws = app.create_workspace("Existing").unwrap();
    vec![("existing workspace", into(&ws.meta.id)), ("new workspace", SpecTarget::NewWorkspace)]
}

#[test]
fn an_import_that_cannot_take_its_checkpoint_writes_nothing() {
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let checkpoints = app.dir.join("checkpoints");
    for (label, target) in targets(&app) {
        let before = inventory(&app);
        // A regular file where the checkpoint folder goes.
        if checkpoints.is_dir() {
            std::fs::remove_dir_all(&checkpoints).unwrap();
        }
        std::fs::write(&checkpoints, b"not a folder").unwrap();
        assert!(app.spec_import(CURL, "source.txt", &ImportOptions::default(), target.clone()).is_err(), "{label}");
        assert_eq!(inventory(&app), before, "{label}: nothing was written");
        std::fs::remove_file(&checkpoints).unwrap();
        import(&app, CURL, target);
        assert_ne!(inventory(&app), before, "{label}: the same import succeeds once the checkpoint can be taken");
    }
}

#[test]
fn an_import_that_fails_storing_its_source_file_writes_nothing() {
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    for (i, (label, target)) in targets(&app).into_iter().enumerate() {
        // New bytes each time, so the source file is a new blob.
        let bytes = format!("curl https://example.invalid/health/{i}").into_bytes();
        let before = inventory(&app);
        fail_writes(&app, "blobs", "1");
        assert!(app.spec_import(&bytes, "source.txt", &ImportOptions::default(), target.clone()).is_err(), "{label}");
        allow_writes(&app);
        assert_eq!(inventory(&app), before, "{label}: no folder, workspace, attachment index or blob is left behind");
        let done = import(&app, &bytes, target);
        assert_eq!(app.requests(&done.workspace_id).unwrap().len(), 1, "{label}");
    }
}

#[test]
fn an_import_that_fails_writing_its_objects_writes_nothing() {
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    for (label, target) in targets(&app) {
        let before = inventory(&app);
        // The source record is the last object written.
        fail_writes(&app, "objects", "NEW.kind = 'spec_source'");
        let bytes = COLLECTION.as_bytes();
        assert!(app.spec_import(bytes, "echo.json", &ImportOptions::default(), target.clone()).is_err(), "{label}");
        allow_writes(&app);
        assert_eq!(inventory(&app), before, "{label}: every write of the import was rolled back");
        let done = app.spec_import(bytes, "echo.json", &ImportOptions::default(), target).unwrap();
        assert_eq!(app.requests(&done.workspace_id).unwrap().len(), 3, "{label}");
        assert!(app.get_attachment(&app.spec_sources(&done.workspace_id).unwrap()[0].original_sha256).unwrap().is_some());
    }
}

// ---------------------------------------------------------------- scope

fn destination_with_credentials(app: &App) -> Workspace {
    let mut ws = app.create_workspace("Destination").unwrap();
    ws.auth = AuthConfig::Bearer { token: SensitiveValue::Template { value: "destination-dummy".into() }, prefix: "Bearer".into() };
    ws.variables.push(Variable::plain("base", "https://destination.example.invalid"));
    app.save_workspace(ws).unwrap()
}

/// (url, auth, authorization header present) as the request would be sent.
fn prepared(app: &App, ws: &Id, name: &str) -> (String, AuthConfig, bool) {
    let q = app.requests(ws).unwrap().into_iter().find(|q| q.name == name).unwrap_or_else(|| panic!("no request {name}"));
    let ctx = app.build_context(Some(q.meta.id), ws, None, &SendOptions::default()).unwrap();
    let preview = app.engine.preview(&ctx).unwrap_or_else(|e| panic!("{name}: {e:?}"));
    let authorization = preview.headers.iter().any(|h| h.name.eq_ignore_ascii_case("authorization"));
    (preview.url, ctx.effective_auth().1, authorization)
}

#[test]
fn an_import_into_an_existing_workspace_keeps_the_sources_no_auth_and_variables() {
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let own = import(&app, COLLECTION.as_bytes(), SpecTarget::NewWorkspace);
    let dest = destination_with_credentials(&app);
    let nested = import(&app, COLLECTION.as_bytes(), into(&dest.meta.id));

    let root_folder = app.folder(&nested.root_folder_id.unwrap()).unwrap();
    assert_eq!(root_folder.auth, AuthConfig::None, "the explicit no-auth boundary is kept");
    assert!(root_folder.variables.iter().any(|v| v.name == "base"), "collection variables are kept");

    for name in ["Health", "Concrete", "Deep"] {
        let expected = prepared(&app, &own.workspace_id, name);
        let got = prepared(&app, &dest.meta.id, name);
        assert_eq!(got, expected, "{name}: prepared as in a workspace of its own");
        assert_eq!(got.1, AuthConfig::None, "{name}");
        assert!(!got.2, "{name}: no destination credentials");
        assert!(got.0.starts_with("https://api.example.invalid/"), "{name}: {}", got.0);
    }
}

#[test]
fn a_source_without_auth_of_its_own_gets_no_auth_in_an_existing_workspace() {
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let dest = destination_with_credentials(&app);
    // A Postman environment export has no auth at all.
    let env = br#"{
      "name": "Staging",
      "_postman_variable_scope": "environment",
      "values": [{ "key": "k", "value": "v", "enabled": true }]
    }"#;
    let done = import(&app, env, into(&dest.meta.id));
    assert_eq!(app.folder(&done.root_folder_id.unwrap()).unwrap().auth, AuthConfig::None);
    let done = import(&app, CURL, into(&dest.meta.id));
    let root_folder = done.root_folder_id.unwrap();
    assert_eq!(app.folder(&root_folder).unwrap().auth, AuthConfig::None);
    let q = app.requests(&dest.meta.id).unwrap().into_iter().find(|q| q.folder_id == Some(root_folder)).unwrap();
    let ctx = app.build_context(Some(q.meta.id), &dest.meta.id, None, &SendOptions::default()).unwrap();
    assert_eq!(ctx.effective_auth().1, AuthConfig::None);
}

const API_KEY_AUTH: &str = r#""auth": { "type": "apikey", "apikey": [
  { "key": "key", "value": "X-Key" }, { "key": "value", "value": "{{api_key}}" }, { "key": "in", "value": "header" }
] }"#;

/// The collection with an API key taken from `{{api_key}}`.
fn api_key_collection() -> String {
    COLLECTION.replace(r#""auth": { "type": "noauth" }"#, API_KEY_AUTH)
}

/// A destination whose workspace and active environment hold vault-backed
/// values, including an `api_key` the imported collection's auth names.
fn destination_with_environment(app: &App) -> (Workspace, Environment) {
    let mut ws = destination_with_credentials(app);
    let secret = app.set_secret(&ws.meta.id, "api key", "destination-secret").unwrap();
    let from_vault = |name: &str| Variable {
        name: name.into(),
        value: SensitiveValue::Secret { secret: secret.clone() },
        secret: true,
        enabled: true,
        description: String::new(),
    };
    ws.variables.push(from_vault("workspace_key"));
    let vars = vec![from_vault("api_key"), Variable::plain("region", "destination-region")];
    let env = app.create_environment(&ws.meta.id, "Production", vars).unwrap();
    ws.active_environment_id = Some(env.meta.id);
    (app.save_workspace(ws).unwrap(), env)
}

/// Every `name=value` an execution could resolve.
fn resolvable(ctx: &ExecutionContext) -> Vec<String> {
    ctx.var_layers.iter().flat_map(|l| l.vars.iter().map(|v| format!("{}={}", v.name, v.value))).collect()
}

fn nothing_from_the_destination(ctx: &ExecutionContext) {
    let values = resolvable(ctx);
    assert!(values.iter().all(|v| !v.contains("destination")), "{values:?}");
}

/// The error of a refused call (an `ExecutionContext` is not `Debug`).
fn refused<T>(r: Result<T, AppError>, label: &str) -> String {
    match r {
        Ok(_) => panic!("{label}: expected a refusal"),
        Err(e) => e.to_string(),
    }
}

#[test]
fn a_sources_own_auth_applies_and_the_destinations_values_never_fill_it() {
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let (dest, env) = destination_with_environment(&app);
    let done = import(&app, api_key_collection().as_bytes(), into(&dest.meta.id));
    let root_folder = app.folder(&done.root_folder_id.unwrap()).unwrap();
    assert!(matches!(root_folder.auth, AuthConfig::ApiKey { .. }), "{:?}", root_folder.auth);
    assert!(root_folder.import_root && !root_folder.use_workspace_scope);
    let q = app.requests(&dest.meta.id).unwrap().into_iter().find(|q| q.name == "Deep").unwrap();
    // Neither the destination's active environment nor one chosen for the send.
    for opts in [SendOptions::default(), SendOptions { environment: Some(env.meta.id), ..Default::default() }] {
        let ctx = app.build_context(Some(q.meta.id), &dest.meta.id, None, &opts).unwrap();
        assert_eq!(ctx.effective_auth().1, root_folder.auth, "nested requests inherit the source's auth, not the destination's");
        nothing_from_the_destination(&ctx);
        assert_eq!(ctx.environment_id, None);
        // `{{api_key}}` has nothing to resolve from, so nothing can be sent.
        assert!(app.engine.preview(&ctx).is_err());
    }
}

#[test]
fn only_the_user_opens_an_import_root_to_the_destination_on_this_device() {
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let (dest, env) = destination_with_environment(&app);
    let done = import(&app, api_key_collection().as_bytes(), into(&dest.meta.id));
    let root_id = done.root_folder_id.unwrap();
    let deep = app.requests(&dest.meta.id).unwrap().into_iter().find(|q| q.name == "Deep").unwrap();
    let build = || app.build_context(Some(deep.meta.id), &dest.meta.id, None, &SendOptions::default()).unwrap();

    // Saving the folder neither opens it nor stops it being an import root.
    let mut edited = app.folder(&root_id).unwrap();
    edited.use_workspace_scope = true;
    edited.import_root = false;
    let saved = app.save_folder(edited).unwrap();
    assert!(saved.import_root && !saved.use_workspace_scope);
    nothing_from_the_destination(&build());

    // The explicit choice does.
    app.set_import_root_workspace_scope(&root_id, true).unwrap();
    let ctx = build();
    let values = resolvable(&ctx);
    assert!(values.contains(&"api_key=destination-secret".to_string()), "{values:?}");
    assert!(values.contains(&"workspace_key=destination-secret".to_string()), "{values:?}");
    assert_eq!(ctx.environment_id, Some(env.meta.id));
    // The source's own auth and variables still take precedence.
    assert!(matches!(ctx.effective_auth().1, AuthConfig::ApiKey { .. }));
    let preview = app.engine.preview(&ctx).unwrap_or_else(|e| panic!("{e:?}"));
    assert!(preview.url.starts_with("https://api.example.invalid/"), "{}", preview.url);
    // And it can be taken back.
    app.set_import_root_workspace_scope(&root_id, false).unwrap();
    nothing_from_the_destination(&build());
    app.set_import_root_workspace_scope(&root_id, true).unwrap();

    // Only an import root has a scope of its own.
    let plain = app.create_folder(&dest.meta.id, None, "Mine").unwrap();
    assert!(app.set_import_root_workspace_scope(&plain.meta.id, true).is_err());

    // A bundle keeps the import root but never carries the choice.
    let (bytes, _) = app.export(Some(&dest.meta.id), ExportMode::EncryptedTransfer, Some("export passphrase 1"), false).unwrap();
    let other = tempfile::tempdir().unwrap();
    let b = new_app(other.path());
    let report = b.import(&bytes, Some("export passphrase 1"), ConflictPolicy::Duplicate).unwrap();
    assert!(report.warnings.iter().any(|w| w.contains("imported collection")), "{:?}", report.warnings);
    let ws_b: Id = report.workspace_ids[0].parse().unwrap();
    let root_b = b.folders(&ws_b).unwrap().into_iter().find(|f| f.import_root).expect("the import root is kept");
    assert!(!root_b.use_workspace_scope);
    let deep_b = b.requests(&ws_b).unwrap().into_iter().find(|q| q.name == "Deep").unwrap();
    nothing_from_the_destination(&b.build_context(Some(deep_b.meta.id), &ws_b, None, &SendOptions::default()).unwrap());

    // Nor does a full backup restored elsewhere.
    let (bytes, _) = app.export_backup_with("export passphrase 1", KdfParams::testing()).unwrap();
    let other = tempfile::tempdir().unwrap();
    let c = new_app(other.path());
    let report = c.restore(&bytes, Some("export passphrase 1"), ConflictPolicy::Replace).unwrap();
    assert!(report.warnings.iter().any(|w| w.contains("imported collection")), "{:?}", report.warnings);
    let root_c = c.folder(&root_id).unwrap();
    assert!(root_c.import_root && !root_c.use_workspace_scope);
    let deep_c = c.requests(&dest.meta.id).unwrap().into_iter().find(|q| q.name == "Deep").unwrap();
    nothing_from_the_destination(&c.build_context(Some(deep_c.meta.id), &dest.meta.id, None, &SendOptions::default()).unwrap());
}

#[test]
fn an_import_roots_own_environment_resolves_and_the_destinations_does_not() {
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let (dest, env) = destination_with_environment(&app);
    // A Postman environment export: its environment lands in the destination.
    let staging = br#"{
      "name": "Staging",
      "_postman_variable_scope": "environment",
      "values": [{ "key": "k", "value": "v", "enabled": true }]
    }"#;
    let done = import(&app, staging, into(&dest.meta.id));
    let root_folder = app.folder(&done.root_folder_id.unwrap()).unwrap();
    assert_eq!(root_folder.import_environment_ids.len(), 1);
    let staging = root_folder.import_environment_ids[0];
    assert!(app.environments(&dest.meta.id).unwrap().iter().any(|e| e.meta.id == staging));
    let spec = RequestSpec::http("GET", "https://api.example.invalid/{{k}}");
    let q = app.create_request(&dest.meta.id, Some(root_folder.meta.id), "mine", spec).unwrap();
    let build = |environment| {
        let opts = SendOptions { environment, ..Default::default() };
        app.build_context(Some(q.meta.id), &dest.meta.id, None, &opts).unwrap()
    };
    for environment in [None, Some(env.meta.id)] {
        let ctx = build(environment);
        assert_eq!(ctx.environment_id, None);
        nothing_from_the_destination(&ctx);
    }
    let ctx = build(Some(staging));
    assert_eq!(ctx.environment_id, Some(staging));
    assert!(resolvable(&ctx).contains(&"k=v".to_string()));
}

fn jwt_svid(source: JwtSvidSource) -> AuthConfig {
    let config = JwtSvidConfig {
        source,
        audiences: vec!["spiffe://example.org/api".into()],
        endpoint: String::new(),
        spiffe_id: None,
        verify_with_bundles: false,
        send_despite_failed_checks: false,
        header_name: "Authorization".into(),
        prefix: "Bearer".into(),
    };
    AuthConfig::JwtSvid { config }
}

#[test]
fn an_imported_collection_does_not_use_this_devices_workload_identity_by_default() {
    let root = tempfile::tempdir().unwrap();
    let files = tempfile::tempdir().unwrap();
    let token = files.path().join("jwt_svid.token");
    std::fs::write(&token, "header.claims.signature").unwrap();
    let app = new_app(root.path());
    let dest = destination_with_credentials(&app);
    let done = import(&app, COLLECTION.as_bytes(), into(&dest.meta.id));
    let root_id = done.root_folder_id.unwrap();
    let mut requests = Vec::new();
    let sources = [JwtSvidSource::WorkloadApi, JwtSvidSource::File { path: token.display().to_string() }];
    for (i, source) in sources.into_iter().enumerate() {
        let mut spec = RequestSpec::http("GET", "https://api.example.invalid/svid");
        spec.auth = jwt_svid(source);
        requests.push(app.create_request(&dest.meta.id, Some(root_id), &format!("svid {i}"), spec).unwrap());
    }
    // Inherited from the root folder too, inside a multi-auth profile.
    let mut root_folder = app.folder(&root_id).unwrap();
    root_folder.auth = AuthConfig::Multi { profiles: vec![jwt_svid(JwtSvidSource::WorkloadApi)] };
    app.save_folder(root_folder).unwrap();
    requests.push(app.requests(&dest.meta.id).unwrap().into_iter().find(|q| q.name == "Deep").unwrap());

    for q in &requests {
        let err = refused(app.build_context(Some(q.meta.id), &dest.meta.id, None, &SendOptions::default()), &q.name);
        assert!(err.contains("workload identity"), "{}: {err}", q.name);
    }
    app.set_import_root_workspace_scope(&root_id, true).unwrap();
    for q in &requests {
        app.build_context(Some(q.meta.id), &dest.meta.id, None, &SendOptions::default()).expect(&q.name);
    }
}

#[test]
fn an_imported_collection_does_not_use_a_client_identity_bound_to_no_host() {
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let mut dest = destination_with_credentials(&app);
    let done = import(&app, COLLECTION.as_bytes(), into(&dest.meta.id));
    let root_id = done.root_folder_id.unwrap();
    // The destination selects a TLS profile whose client certificate goes to
    // any host (no bindings).
    let tls = unbound_client_certificate(&app, &dest.meta.id, "device cert");
    dest.settings.tls_profile_id = Some(tls.id);
    let dest = app.save_workspace(dest).unwrap();
    let deep = app.requests(&dest.meta.id).unwrap().into_iter().find(|q| q.name == "Deep").unwrap();
    let build = || app.build_context(Some(deep.meta.id), &dest.meta.id, None, &SendOptions::default());
    let plan = load_plan(dest.meta.id, deep.meta.id);

    let err = refused(build(), "a client identity bound to no host");
    assert!(err.contains("TLS profile 'device cert'"), "{err}");
    let err = refused(app.load_job(&plan), "load: a client identity bound to no host");
    assert!(err.contains("TLS profile 'device cert'"), "{err}");
    // Bound to hosts, it is presented only to them.
    let mut bound = tls.clone();
    bound.bindings = vec![HostBinding { host: "internal.example.invalid".into(), port: None }];
    app.save_tls_profile(bound).unwrap();
    build().expect("a bound client identity");
    app.load_job(&plan).expect("load: a bound client identity");
    app.save_tls_profile(tls).unwrap();
    refused(build(), "unbound again");
    // The workspace's own requests, and the import root once the user opens
    // it, use the profile as before.
    let spec = RequestSpec::http("GET", "https://api.example.invalid/mine");
    let mine = app.create_request(&dest.meta.id, None, "mine", spec).unwrap();
    app.build_context(Some(mine.meta.id), &dest.meta.id, None, &SendOptions::default()).expect("a workspace request");
    app.set_import_root_workspace_scope(&root_id, true).unwrap();
    build().expect("an opened import root");
}

#[tokio::test]
async fn an_imported_collection_does_not_use_a_proxys_client_identity_bound_to_no_host() {
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let mut dest = destination_with_credentials(&app);
    let done = import(&app, COLLECTION.as_bytes(), into(&dest.meta.id));
    let root_id = done.root_folder_id.unwrap();
    // The destination selects no TLS profile of its own, but an HTTPS proxy
    // whose own TLS profile presents a client certificate to any host.
    let tls = unbound_client_certificate(&app, &dest.meta.id, "proxy cert");
    let now = chrono::Utc::now();
    let proxy = app
        .save_proxy_profile(ProxyProfile {
            id: Id::new(),
            workspace_id: dest.meta.id,
            name: "egress".into(),
            kind: ProxyKind::Https,
            address: "proxy.example.invalid:3128".into(),
            username: None,
            password: None,
            // The request targets this host, so the engine bypasses the
            // proxy; its selected unbound TLS profile is still refused.
            no_proxy: "api.example.invalid".into(),
            tls_profile_id: Some(tls.id),
            hbone: None,
            created_at: now,
            updated_at: now,
        })
        .unwrap();
    dest.settings.proxy_profile_id = Some(ProxySelection::Profile { id: proxy.id });
    let dest = app.save_workspace(dest).unwrap();
    let deep = app.requests(&dest.meta.id).unwrap().into_iter().find(|q| q.name == "Deep").unwrap();
    let build = || app.build_context(Some(deep.meta.id), &dest.meta.id, None, &SendOptions::default());
    let plan = load_plan(dest.meta.id, deep.meta.id);

    let sent = app.send(Some(deep.meta.id), &dest.meta.id, None, SendOptions::default(), EventCtx::none(), CancellationToken::new()).await;
    let refusals = [
        ("send", refused(sent, "send")),
        ("build_context", refused(build(), "build_context")),
        ("load_job", refused(app.load_job(&plan), "load_job")),
        ("load_preflight", refused(app.load_preflight(&plan), "load_preflight")),
    ];
    for (call, err) in refusals {
        assert!(err.contains("TLS profile 'proxy cert'") && err.contains("bound to no host"), "{call}: {err}");
        assert!(err.contains("proxy 'egress'"), "{call}: {err}");
    }
    // Bound to the proxy's host, it is presented only there.
    let mut bound = tls.clone();
    bound.bindings = vec![HostBinding { host: "proxy.example.invalid".into(), port: None }];
    app.save_tls_profile(bound).unwrap();
    build().expect("a bound client identity");
    app.load_job(&plan).expect("load: a bound client identity");
    app.save_tls_profile(tls).unwrap();
    refused(build(), "unbound again");
    refused(app.load_job(&plan), "load: unbound again");
    // The workspace's own requests, and the import root once the user opens
    // it, use the proxy as before.
    let spec = RequestSpec::http("GET", "https://api.example.invalid/mine");
    let mine = app.create_request(&dest.meta.id, None, "mine", spec).unwrap();
    app.build_context(Some(mine.meta.id), &dest.meta.id, None, &SendOptions::default()).expect("a workspace request");
    app.set_import_root_workspace_scope(&root_id, true).unwrap();
    build().expect("an opened import root");
    app.load_job(&plan).expect("load: an opened import root");
}

/// A TLS profile whose client certificate goes to any host (no bindings).
fn unbound_client_certificate(app: &App, ws: &Id, name: &str) -> TlsProfile {
    let identity = ClientIdentity::Pem {
        cert_chain_pem: "-----BEGIN CERTIFICATE-----".into(),
        private_key_pem: SensitiveValue::Template { value: "destination-key".into() },
    };
    let now = chrono::Utc::now();
    app.save_tls_profile(TlsProfile {
        id: Id::new(),
        workspace_id: *ws,
        name: name.into(),
        verify: true,
        use_system_roots: true,
        extra_roots_pem: vec![],
        client_identity: Some(identity),
        bindings: vec![],
        min_version: Default::default(),
        server_name_override: None,
        server_spiffe: None,
        created_at: now,
        updated_at: now,
    })
    .unwrap()
}

fn load_plan(ws: Id, request: Id) -> LoadPlan {
    let now = chrono::Utc::now();
    LoadPlan {
        id: Id::new(),
        workspace_id: ws,
        name: "smoke".into(),
        workload: Workload::Iterations { iterations: 2, concurrency: 1 },
        chain: vec![request],
        mix: vec![],
        dataset_id: None,
        environment_id: None,
        connection_mode: Default::default(),
        warmup_secs: 0,
        abort: None,
        seed: 1,
        trusted: true,
        created_at: now,
        updated_at: now,
    }
}

fn token_login(url: &str, token: &str) -> RequestSpec {
    let mut s = RequestSpec::http("POST", url);
    s.params.push(KeyValue::new("body", format!(r#"{{"token":"{token}"}}"#)));
    s.extractions.push(Extraction {
        variable: "token".into(),
        source: ExtractionSource::JsonPath { path: "$.token".into() },
        sensitive: true,
    });
    s
}

fn token_echo(url: &str, step: &str) -> RequestSpec {
    let mut s = RequestSpec::http("GET", url);
    s.headers.push(KeyValue::new("X-Step", step));
    s.headers.push(KeyValue::new("X-Token", "{{token}}"));
    s
}

/// `(X-Step, X-Token)` of every request the fixture received.
fn received_tokens(f: &anvil_fixtures::http::Fixture) -> Vec<(String, String)> {
    f.log
        .entries()
        .into_iter()
        .filter_map(|e| match e.event {
            GroundTruth::RequestReceived { headers, .. } => {
                let get = |n: &str| headers.iter().find(|(h, _)| h.eq_ignore_ascii_case(n)).map(|(_, v)| v.clone());
                Some((get("x-step")?, get("x-token")?))
            }
            _ => None,
        })
        .collect()
}

#[tokio::test]
async fn a_workspace_run_keeps_extracted_values_on_their_side_of_an_import_root() {
    anvil_fixtures::init();
    let f = anvil_fixtures::http::serve("127.0.0.1:0", None).await.unwrap();
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let ws = app.create_workspace("Destination").unwrap().meta.id;
    let (login, echo) = (f.url("/status/200"), f.url("/echo"));
    let auth = app.create_folder(&ws, None, "Auth").unwrap().meta.id;
    app.create_request(&ws, Some(auth), "Login", token_login(&login, "user-session-0001")).unwrap();
    app.create_request(&ws, Some(auth), "Me", token_echo(&echo, "me")).unwrap();
    let staging = br#"{
      "name": "Staging",
      "_postman_variable_scope": "environment",
      "values": [{ "key": "k", "value": "v", "enabled": true }]
    }"#;
    let import_root = import(&app, staging, into(&ws)).root_folder_id.unwrap();
    app.create_request(&ws, Some(import_root), "Leak", token_echo(&echo, "leak")).unwrap();
    app.create_request(&ws, Some(import_root), "Imported login", token_login(&login, "imported-0002")).unwrap();
    app.create_request(&ws, Some(import_root), "Imported", token_echo(&echo, "imported")).unwrap();
    app.create_request(&ws, None, "After", token_echo(&echo, "after")).unwrap();

    // "Run workspace": the user's folder, then the import root, then the
    // workspace's own requests.
    let r = app.run_folder(&ws, None, RunSettings::default(), CancellationToken::new()).await.unwrap();
    let steps = &r.iterations[0].steps;
    let order: Vec<&str> = steps.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(order, ["Login", "Me", "Leak", "Imported login", "Imported", "After"]);
    assert_ne!(steps[2].status, RunStepStatus::Passed, "the user's token is not there to send");
    // Ground truth: what reached the peer.
    let sent = received_tokens(&f);
    let expected = [("me", "user-session-0001"), ("imported", "imported-0002"), ("after", "user-session-0001")];
    assert_eq!(sent, expected.map(|(s, t)| (s.to_string(), t.to_string())));
}

// ---------------------------------------------------------------- reimport

const SERVER_V1: &str = r#"{"openapi":"3.0.3","info":{"title":"Audit","version":"1"},"servers":[{"url":"https://old.example.test"}],"paths":{"/health":{"get":{"operationId":"health","responses":{"200":{"description":"ok"}}}}}}"#;

fn server(url: &str) -> Vec<u8> {
    SERVER_V1.replace("https://old.example.test", url).into_bytes()
}

/// The URL `request` would be sent to.
fn sent_to(app: &App, ws: &Id, request: &Id, environment: Option<Id>) -> String {
    let opts = SendOptions { environment, ..Default::default() };
    let ctx = app.build_context(Some(*request), ws, None, &opts).unwrap();
    app.engine.preview(&ctx).unwrap_or_else(|e| panic!("{e:?}")).url
}

/// The import id a reimport of the workspace's only source uses now.
fn current_import(app: &App, ws: &Id) -> Id {
    app.spec_sources(ws).unwrap()[0].source.import_id
}

#[test]
fn a_reimport_with_a_changed_server_sends_to_the_new_server() {
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let existing = app.create_workspace("Existing").unwrap().meta.id;
    for (label, target) in [("new workspace", SpecTarget::NewWorkspace), ("import root", into(&existing))] {
        let done = app.spec_import(SERVER_V1.as_bytes(), "audit.json", &ImportOptions::default(), target).unwrap();
        let ws = done.workspace_id;
        let health = app.requests(&ws).unwrap().pop().unwrap();
        // Under an import root only an environment the import brought
        // resolves, and only when it is chosen.
        let environment = done.root_folder_id.map(|f| app.folder(&f).unwrap().import_environment_ids[0]);
        let url = sent_to(&app, &ws, &health.meta.id, environment);
        assert!(url.starts_with("https://old.example.test/"), "{label}: {url}");

        let newer = server("https://new.example.test");
        let plan = app.spec_reimport_plan(&done.import_id, &newer).unwrap();
        assert_eq!(plan.unchanged, vec![health.meta.id], "{label}: the request itself says `{{{{baseUrl}}}}/health`");
        assert!(plan.scope_updated.iter().any(|c| c.key.ends_with("/variables/baseUrl")), "{label}: {:?}", plan.scope_updated);
        assert!(plan.scope_conflicts.is_empty(), "{label}: {:?}", plan.scope_conflicts);
        app.spec_reimport_apply(&done.import_id, &newer, "source.txt", &ReimportApproval::default()).unwrap();
        let url = sent_to(&app, &ws, &health.meta.id, environment);
        assert!(url.starts_with("https://new.example.test/"), "{label}: {url}");
        assert_eq!(app.request(&health.meta.id).unwrap(), health, "{label}: the request is untouched");

        // Applied, it is what was generated: nothing is offered again.
        let again = app.spec_reimport_plan(&current_import(&app, &ws), &newer).unwrap();
        assert!(again.scope_updated.is_empty() && again.scope_conflicts.is_empty(), "{label}: {again:?}");
    }
}

#[test]
fn a_server_the_user_changed_is_kept_until_the_user_approves_the_new_one() {
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let done = import(&app, SERVER_V1.as_bytes(), SpecTarget::NewWorkspace);
    let ws = done.workspace_id;
    let health = app.requests(&ws).unwrap().pop().unwrap().meta.id;
    let mut env = app.environments(&ws).unwrap().pop().unwrap();
    env.variables.iter_mut().find(|v| v.name == "baseUrl").unwrap().value = SensitiveValue::template("https://mine.example.test");
    env.variables.push(Variable::plain("token", "mine"));
    app.save_environment(env.clone()).unwrap();

    let newer = server("https://new.example.test");
    let key = format!("environments/{}/variables/baseUrl", env.meta.id);
    let plan = app.spec_reimport_plan(&done.import_id, &newer).unwrap();
    assert_eq!(plan.scope_conflicts.iter().map(|c| c.key.as_str()).collect::<Vec<_>>(), vec![key.as_str()]);
    assert!(plan.scope_conflicts[0].user_edited);
    app.spec_reimport_apply(&done.import_id, &newer, "source.txt", &ReimportApproval::default()).unwrap();
    assert!(sent_to(&app, &ws, &health, None).starts_with("https://mine.example.test/"), "the user's server is kept");

    // Declined once, it is offered again; approved, it replaces the user's.
    let plan = app.spec_reimport_plan(&current_import(&app, &ws), &newer).unwrap();
    assert_eq!(plan.scope_conflicts.iter().map(|c| c.key.as_str()).collect::<Vec<_>>(), vec![key.as_str()]);
    let approval = ReimportApproval { overwrite_scope: vec![key], ..Default::default() };
    app.spec_reimport_apply(&current_import(&app, &ws), &newer, "source.txt", &approval).unwrap();
    assert!(sent_to(&app, &ws, &health, None).starts_with("https://new.example.test/"));
    let env = app.environments(&ws).unwrap().pop().unwrap();
    assert!(env.variables.iter().any(|v| v.name == "token"), "a variable of the user's own is kept");
}

#[test]
fn a_reimport_updates_an_import_roots_own_variables_and_leaves_the_destinations_alone() {
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let dest = destination_with_credentials(&app);
    let done = import(&app, COLLECTION.as_bytes(), into(&dest.meta.id));
    assert!(prepared(&app, &dest.meta.id, "Health").0.starts_with("https://api.example.invalid/"));

    let newer = COLLECTION.replace(r#""value": "https://api.example.invalid""#, r#""value": "https://api2.example.invalid""#);
    let plan = app.spec_reimport_plan(&done.import_id, newer.as_bytes()).unwrap();
    assert!(plan.scope_updated.iter().any(|c| c.key == "variables/base"), "{:?}", plan.scope_updated);
    app.spec_reimport_apply(&done.import_id, newer.as_bytes(), "source.txt", &ReimportApproval::default()).unwrap();
    let (url, auth, authorization) = prepared(&app, &dest.meta.id, "Health");
    assert!(url.starts_with("https://api2.example.invalid/"), "{url}");
    assert_eq!((auth, authorization), (AuthConfig::None, false), "still the source's own no-auth");
    let root_folder = app.folder(&done.root_folder_id.unwrap()).unwrap();
    assert!(root_folder.import_root && !root_folder.use_workspace_scope);
    assert_eq!(app.workspace(&dest.meta.id).unwrap(), dest, "the destination's own scope is untouched");
}

fn revisions(app: &App, ws: &Id) -> usize {
    app.store.list::<RequestRevision>(kind::REVISION, Some(ws)).unwrap().len()
}

#[test]
fn a_reimport_that_changes_a_request_points_it_at_a_new_revision() {
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let done = import(&app, CURL, SpecTarget::NewWorkspace);
    let ws = done.workspace_id;
    let mut q = app.requests(&ws).unwrap().pop().unwrap();
    q.name = "Mine".into();
    let saved = app.save_request(q).unwrap();
    let old = saved.revision_id.expect("saving records a revision");
    assert_eq!(revisions(&app, &ws), 1);

    let newer = b"curl -H 'X-Version: 2' https://example.invalid/health";
    let plan = app.spec_reimport_plan(&done.import_id, newer).unwrap();
    assert_eq!(plan.updated.len(), 1, "not edited by the user: a safe update");
    app.spec_reimport_apply(&done.import_id, newer, "source.txt", &ReimportApproval::default()).unwrap();
    let after = app.request(&saved.meta.id).unwrap();
    assert!(after.spec.headers.iter().any(|h| h.name == "X-Version"));
    let new = after.revision_id.expect("the updated request has a revision");
    assert_ne!(new, old);
    let revision = app.revision(&new).unwrap();
    assert_eq!((revision.request_id, &revision.spec), (after.meta.id, &after.spec));
    assert_eq!(app.revision(&old).unwrap().spec, saved.spec, "the old revision keeps the old spec");
    let ctx = app.build_context(Some(after.meta.id), &ws, None, &SendOptions::default()).unwrap();
    assert_eq!(ctx.revision_id, Some(new));
    assert_eq!(revisions(&app, &ws), 2);

    // Unchanged by a reimport, it keeps its revision and gains none.
    app.spec_reimport_apply(&current_import(&app, &ws), newer, "source.txt", &ReimportApproval::default()).unwrap();
    assert_eq!(app.request(&saved.meta.id).unwrap(), after);
    assert_eq!(revisions(&app, &ws), 2);
}

#[tokio::test]
async fn an_approved_conflict_runs_and_is_recorded_as_its_new_revision() {
    anvil_fixtures::init();
    let f = anvil_fixtures::http::serve("127.0.0.1:0", None).await.unwrap();
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let url = f.url("/echo");
    let done = import(&app, format!("curl {url}").as_bytes(), SpecTarget::NewWorkspace);
    let ws = done.workspace_id;
    // Edited by the user and changed upstream: a conflict.
    let mut q = app.requests(&ws).unwrap().pop().unwrap();
    q.spec.headers.push(KeyValue::new("X-Mine", "1"));
    let edited = app.save_request(q).unwrap();
    let newer = format!("curl -H 'X-Version: 2' {url}");
    let plan = app.spec_reimport_plan(&done.import_id, newer.as_bytes()).unwrap();
    assert_eq!(plan.conflicts.len(), 1);

    // Declined, the user's request and its revision stay as they were.
    app.spec_reimport_apply(&done.import_id, newer.as_bytes(), "source.txt", &ReimportApproval::default()).unwrap();
    assert_eq!(app.request(&edited.meta.id).unwrap().revision_id, edited.revision_id);

    let approval = ReimportApproval { overwrite: vec![edited.meta.id], ..Default::default() };
    app.spec_reimport_apply(&current_import(&app, &ws), newer.as_bytes(), "source.txt", &approval).unwrap();
    let after = app.request(&edited.meta.id).unwrap();
    assert!(!after.spec.headers.iter().any(|h| h.name == "X-Mine"));
    let rev = after.revision_id.expect("the overwritten request has a revision");
    assert_ne!(Some(rev), edited.revision_id);
    assert_eq!(app.revision(&rev).unwrap().spec, after.spec);

    let r = app.run_folder(&ws, None, RunSettings::default(), CancellationToken::new()).await.unwrap();
    let step = &r.iterations[0].steps[0];
    assert_eq!(step.revision_id, Some(rev), "the run names the revision it sent");
    let seen = f.log.last_request_headers().unwrap();
    assert!(seen.iter().any(|(n, v)| n == "x-version" && v == "2"), "and that is what reached the peer: {seen:?}");
    let (record, _) = app.store.get_history::<ExecutionRecord>(&step.execution_id.unwrap().to_string()).unwrap().unwrap();
    assert_eq!(record.revision_id, Some(rev));
}

#[test]
fn an_active_environment_a_reimport_deletes_leaves_none_active() {
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let two_servers = SERVER_V1.replace(
        r#"[{"url":"https://old.example.test"}]"#,
        r#"[{"url":"https://old.example.test"},{"url":"https://staging.example.test","description":"Staging"}]"#,
    );
    let done = import(&app, two_servers.as_bytes(), SpecTarget::NewWorkspace);
    let ws = done.workspace_id;
    let staging = app.environments(&ws).unwrap().into_iter().find(|e| e.name == "Staging").unwrap().meta.id;
    let mut w = app.workspace(&ws).unwrap();
    assert_ne!(w.active_environment_id, Some(staging), "the source makes its first server active");
    w.active_environment_id = Some(staging);
    app.save_workspace(w).unwrap();

    let key = format!("environments/{staging}");
    let plan = app.spec_reimport_plan(&done.import_id, SERVER_V1.as_bytes()).unwrap();
    assert_eq!(plan.scope_removed.iter().map(|c| c.key.as_str()).collect::<Vec<_>>(), vec![key.as_str()]);
    let approval = ReimportApproval { delete_scope: vec![key], ..Default::default() };
    app.spec_reimport_apply(&done.import_id, SERVER_V1.as_bytes(), "source.txt", &approval).unwrap();
    assert_eq!(app.environments(&ws).unwrap().len(), 1);
    // As when the user deletes it: none is active, not the one the source
    // makes active.
    assert_eq!(app.workspace(&ws).unwrap().active_environment_id, None);
}

#[test]
fn an_earlier_import_whose_original_cannot_be_read_can_still_be_reimported() {
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let done = import(&app, SERVER_V1.as_bytes(), SpecTarget::NewWorkspace);
    let ws = done.workspace_id;
    // As an earlier build stored it: no record of the scope it generated.
    let mut rec = app.spec_sources(&ws).unwrap().pop().unwrap();
    rec.generated_scope = None;
    app.store.put(kind::SPEC_SOURCE, &done.import_id, Some(&ws), None, 0.0, &rec).unwrap();
    // And its stored original no longer opens.
    let db = rusqlite::Connection::open(app.dir.join(DB_FILE)).unwrap();
    db.execute_batch("UPDATE blobs SET payload = x'00';").unwrap();
    assert!(app.get_attachment(&rec.original_sha256).is_err());

    let newer = server("https://new.example.test");
    let plan = app.spec_reimport_plan(&done.import_id, &newer).unwrap();
    // Nothing is known of what was generated: every difference needs approval.
    assert!(plan.scope_updated.is_empty(), "{:?}", plan.scope_updated);
    assert!(plan.scope_conflicts.iter().any(|c| c.key.ends_with("/variables/baseUrl") && c.user_edited), "{:?}", plan.scope_conflicts);
    app.spec_reimport_apply(&done.import_id, &newer, "source.txt", &ReimportApproval::default()).unwrap();
    assert!(sent_to(&app, &ws, &app.requests(&ws).unwrap()[0].meta.id, None).starts_with("https://old.example.test/"), "declined: kept");
}

// ---------------------------------------------------------------- reimport follow-ups

/// The source record of the import in `ws` whose root folder is `root`.
fn record(app: &App, ws: &Id, root: Option<Id>) -> SpecSourceRecord {
    app.spec_sources(ws).unwrap().into_iter().find(|r| r.root_folder_id == root).expect("the import's source record")
}

#[test]
fn a_reimport_refreshes_the_source_record_with_the_version_it_applied() {
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let existing = app.create_workspace("Existing").unwrap().meta.id;
    let newer_collection = COLLECTION.replace("https://api.example.invalid", "https://api2.example.invalid").into_bytes();
    let sources =
        [("openapi", SERVER_V1.as_bytes(), server("https://new.example.test")), ("postman", COLLECTION.as_bytes(), newer_collection)];
    for (source, v1, v2) in sources {
        for (target_label, target) in [("new workspace", SpecTarget::NewWorkspace), ("import root", into(&existing))] {
            let label = format!("{source}, {target_label}");
            let done = app.spec_import(v1, "v1.json", &ImportOptions::default(), target).unwrap();
            let ws = done.workspace_id;
            let before = record(&app, &ws, done.root_folder_id);
            assert_eq!((before.file_name.as_str(), before.source.import_id), ("v1.json", done.import_id), "{label}");

            app.spec_reimport_apply(&done.import_id, &v2, "v2.json", &ReimportApproval::default()).unwrap();
            let after = record(&app, &ws, done.root_folder_id);
            assert_ne!(after.source.import_id, done.import_id, "{label}");
            assert_eq!(after.previous_import_ids, vec![done.import_id], "{label}");
            assert_eq!(after.source.id_namespace, before.source.id_namespace, "{label}: the same objects");
            assert_eq!(after.file_name, "v2.json", "{label}");
            assert_eq!(app.get_attachment(&after.original_sha256).unwrap(), Some(v2.clone()), "{label}: the stored original is v2");
            assert_eq!(after.source.sha256, after.original_sha256, "{label}");
            assert_ne!(after.source.sha256, before.source.sha256, "{label}");
            assert_eq!(after.source.size_bytes, v2.len() as u64, "{label}");
            assert_eq!(app.get_attachment(&before.original_sha256).unwrap(), None, "{label}: nothing else references v1: released");

            // Compared with the version it holds now, v2 changes nothing.
            let plan = app.spec_reimport_plan(&after.source.import_id, &v2).unwrap();
            assert!(plan.updated.is_empty() && plan.conflicts.is_empty() && plan.added.is_empty(), "{label}: {plan:?}");
            assert!(plan.scope_updated.is_empty() && plan.scope_conflicts.is_empty(), "{label}: {plan:?}");
        }
    }
}

#[test]
fn a_reimport_keeps_the_version_it_replaces_while_something_else_references_it() {
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let newer = server("https://new.example.test");
    // Another import of the same file holds v1.
    let one = import(&app, SERVER_V1.as_bytes(), SpecTarget::NewWorkspace);
    let two = import(&app, SERVER_V1.as_bytes(), SpecTarget::NewWorkspace);
    let v1 = record(&app, &one.workspace_id, None).original_sha256;
    assert_eq!(record(&app, &two.workspace_id, None).original_sha256, v1);
    app.spec_reimport_apply(&one.import_id, &newer, "v2.json", &ReimportApproval::default()).unwrap();
    assert_eq!(app.get_attachment(&v1).unwrap().as_deref(), Some(SERVER_V1.as_bytes()), "the other import still holds v1");

    // Once that one moves on too, a request that sends v1 as its body holds it.
    let file = app.put_attachment("audit.json", SERVER_V1.as_bytes(), None).unwrap();
    let upload = RequestSpec {
        body: Body::Binary { attachment: file, content_type: None },
        ..RequestSpec::http("POST", "https://upload.example.invalid/")
    };
    app.create_request(&one.workspace_id, None, "Upload", upload).unwrap();
    app.spec_reimport_apply(&two.import_id, &newer, "v2.json", &ReimportApproval::default()).unwrap();
    assert_eq!(app.get_attachment(&v1).unwrap().as_deref(), Some(SERVER_V1.as_bytes()), "the request body still holds v1");
    // Both records now hold v2, which stays.
    let v2 = record(&app, &one.workspace_id, None).original_sha256;
    assert_eq!(record(&app, &two.workspace_id, None).original_sha256, v2);
    assert_eq!(app.get_attachment(&v2).unwrap(), Some(newer));
}

#[test]
fn a_file_attached_before_a_reimport_is_still_stored_when_the_request_is_saved() {
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let done = import(&app, SERVER_V1.as_bytes(), SpecTarget::NewWorkspace);
    let v1 = record(&app, &done.workspace_id, None).original_sha256;
    // The user attaches the imported file as a request body; the request is
    // saved later, in another call.
    let file = app.put_attachment("audit.json", SERVER_V1.as_bytes(), None).unwrap();
    // Before that save, a reimport replaces the stored original, v1.
    let newer = server("https://new.example.test");
    app.spec_reimport_apply(&done.import_id, &newer, "v2.json", &ReimportApproval::default()).unwrap();
    assert_eq!(app.get_attachment(&v1).unwrap().as_deref(), Some(SERVER_V1.as_bytes()), "an attached file is never released by a reimport");

    // The save that follows keeps the body intact.
    let upload = RequestSpec {
        body: Body::Binary { attachment: file.clone(), content_type: None },
        ..RequestSpec::http("POST", "https://upload.example.invalid/")
    };
    let q = app.create_request(&done.workspace_id, None, "Upload", upload).unwrap();
    assert_eq!(app.request(&q.meta.id).unwrap().spec.body, Body::Binary { attachment: file, content_type: None });
    assert_eq!(app.get_attachment(&v1).unwrap().as_deref(), Some(SERVER_V1.as_bytes()));
    // Deleting the request that holds it releases it: nothing else does.
    app.delete_request(&q.meta.id).unwrap();
    assert_eq!(app.get_attachment(&v1).unwrap(), None, "released with its request");
    let v2 = record(&app, &done.workspace_id, None).original_sha256;
    assert_eq!(app.get_attachment(&v2).unwrap(), Some(newer), "the import's own original stays");
}

#[test]
fn deleting_a_request_that_sends_the_current_original_keeps_it() {
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let done = import(&app, SERVER_V1.as_bytes(), SpecTarget::NewWorkspace);
    let v1 = record(&app, &done.workspace_id, None).original_sha256;
    let file = app.put_attachment("audit.json", SERVER_V1.as_bytes(), None).unwrap();
    let upload = RequestSpec {
        body: Body::Binary { attachment: file, content_type: None },
        ..RequestSpec::http("POST", "https://upload.example.invalid/")
    };
    let q = app.create_request(&done.workspace_id, None, "Upload", upload).unwrap();
    app.delete_request(&q.meta.id).unwrap();
    // The import's record still names it as its original.
    assert_eq!(app.get_attachment(&v1).unwrap().as_deref(), Some(SERVER_V1.as_bytes()), "the import still holds v1");
}

#[test]
fn a_reimport_still_releases_a_replaced_original_nothing_else_holds() {
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let done = import(&app, SERVER_V1.as_bytes(), SpecTarget::NewWorkspace);
    let v1 = record(&app, &done.workspace_id, None).original_sha256;
    // A file attached and then held by nothing else does not keep another
    // version alive: only the one attached is marked.
    app.put_attachment("other.json", b"{}", None).unwrap();
    app.spec_reimport_apply(&done.import_id, &server("https://new.example.test"), "v2.json", &ReimportApproval::default()).unwrap();
    assert_eq!(app.get_attachment(&v1).unwrap(), None, "the original an import stored itself is released");
}

/// A Postman collection whose folder has a variable of its own that the
/// request uses.
const ADMIN: &str = r#"{
  "info": { "name": "Admin API", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json" },
  "variable": [{ "key": "base", "value": "https://api.example.invalid" }, { "key": "admin", "value": "k1" }],
  "item": [
    { "name": "Admin", "variable": [{ "key": "scope", "value": "read" }], "item": [
      { "name": "Users", "request": { "method": "GET", "url": { "raw": "{{base}}/users/{{scope}}" } } }
    ] }
  ]
}"#;

/// The folder of [`ADMIN`] with an API key of its own.
const ADMIN_KEY: &str = r#"{ "name": "Admin", "auth": {
      "type": "apikey", "apikey": [{ "key": "key", "value": "X-Admin" }, { "key": "value", "value": "{{admin}}" }] }, "#;

/// [`ADMIN`] with the folder's `scope` set to `scope`, and with its API key.
fn admin(scope: &str) -> Vec<u8> {
    let scope = format!(r#""value": "{scope}""#);
    ADMIN.replace(r#""value": "read""#, &scope).replace(r#"{ "name": "Admin", "#, ADMIN_KEY).into_bytes()
}

#[test]
fn a_reimport_applies_a_folders_own_settings_and_keeps_the_users_until_approved() {
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let existing = app.create_workspace("Existing").unwrap().meta.id;
    for (label, target) in [("new workspace", SpecTarget::NewWorkspace), ("import root", into(&existing))] {
        let done = app.spec_import(ADMIN.as_bytes(), "admin.json", &ImportOptions::default(), target).unwrap();
        let ws = done.workspace_id;
        let latest = |app: &App| record(app, &ws, done.root_folder_id).source.import_id;
        let folder = app.folders(&ws).unwrap().into_iter().find(|f| f.name == "Admin").unwrap().meta.id;
        let (url, auth, _) = prepared(&app, &ws, "Users");
        assert!(url.ends_with("/users/read"), "{label}: {url}");
        assert!(!matches!(auth, AuthConfig::ApiKey { .. }), "{label}: {auth:?}");

        // Changed upstream, not by the user: applied.
        let v2 = admin("write");
        let plan = app.spec_reimport_plan(&done.import_id, &v2).unwrap();
        let keys: Vec<&str> = plan.scope_updated.iter().map(|c| c.key.as_str()).collect();
        assert!(keys.contains(&format!("folders/{folder}/variables/scope").as_str()), "{label}: {keys:?}");
        assert!(keys.contains(&format!("folders/{folder}/auth").as_str()), "{label}: {keys:?}");
        assert!(plan.scope_conflicts.is_empty(), "{label}: {:?}", plan.scope_conflicts);
        app.spec_reimport_apply(&done.import_id, &v2, "admin.json", &ReimportApproval::default()).unwrap();
        let (url, auth, _) = prepared(&app, &ws, "Users");
        assert!(url.ends_with("/users/write"), "{label}: {url}");
        assert!(matches!(&auth, AuthConfig::ApiKey { name, .. } if name == "X-Admin"), "{label}: {auth:?}");
        let again = app.spec_reimport_plan(&latest(&app), &v2).unwrap();
        assert!(again.scope_updated.is_empty() && again.scope_conflicts.is_empty(), "{label}: {again:?}");

        // Changed by the user and upstream: kept until approved.
        let mut f = app.folder(&folder).unwrap();
        f.variables.iter_mut().find(|v| v.name == "scope").unwrap().value = SensitiveValue::template("mine");
        app.save_folder(f).unwrap();
        let v3 = admin("admin");
        let key = format!("folders/{folder}/variables/scope");
        let plan = app.spec_reimport_plan(&latest(&app), &v3).unwrap();
        assert_eq!(plan.scope_conflicts.iter().map(|c| c.key.as_str()).collect::<Vec<_>>(), vec![key.as_str()], "{label}");
        app.spec_reimport_apply(&latest(&app), &v3, "admin.json", &ReimportApproval::default()).unwrap();
        assert!(prepared(&app, &ws, "Users").0.ends_with("/users/mine"), "{label}: the user's value is kept");
        let plan = app.spec_reimport_plan(&latest(&app), &v3).unwrap();
        assert_eq!(plan.scope_conflicts.iter().map(|c| c.key.as_str()).collect::<Vec<_>>(), vec![key.as_str()], "{label}: offered again");
        let approval = ReimportApproval { overwrite_scope: vec![key], ..Default::default() };
        app.spec_reimport_apply(&latest(&app), &v3, "admin.json", &approval).unwrap();
        assert!(prepared(&app, &ws, "Users").0.ends_with("/users/admin"), "{label}");
    }
}

#[test]
fn a_reimport_keeps_a_users_rename_until_the_user_approves_the_sources() {
    let summarized = SERVER_V1.replace(r#""operationId":"health","#, r#""operationId":"health","summary":"Health","#);
    let postman_moved = COLLECTION.replace("{{base}}/health", "{{base}}/healthz");
    let openapi_moved = summarized.replace(r#""/health""#, r#""/healthz""#);
    let sources = [
        ("postman", COLLECTION.to_string(), postman_moved, r#""name": "Health""#, r#""name": "Health check""#),
        ("openapi", summarized, openapi_moved, r#""summary":"Health""#, r#""summary":"Health check""#),
    ];
    for (label, v1, moved, name, new_name) in sources {
        let root = tempfile::tempdir().unwrap();
        let app = new_app(root.path());
        let done = import(&app, v1.as_bytes(), SpecTarget::NewWorkspace);
        let ws = done.workspace_id;
        let mut q = app.requests(&ws).unwrap().into_iter().find(|q| q.name == "Health").unwrap_or_else(|| panic!("{label}"));
        q.name = "Ping".into();
        let q = app.save_request(q).unwrap();

        // Only its spec changed upstream: updated, and still called "Ping".
        let plan = app.spec_reimport_plan(&done.import_id, moved.as_bytes()).unwrap();
        let change = plan.updated.iter().find(|c| c.existing_id == q.meta.id).unwrap_or_else(|| panic!("{label}: {plan:?}"));
        assert_eq!(change.upstream_fields, vec!["spec".to_string()], "{label}");
        app.spec_reimport_apply(&done.import_id, moved.as_bytes(), "source.txt", &ReimportApproval::default()).unwrap();
        let after = app.request(&q.meta.id).unwrap();
        assert_eq!(after.name, "Ping", "{label}: the user's name is kept");
        assert!(after.spec.url.ends_with("/healthz"), "{label}: {}", after.spec.url);

        // Renamed upstream too: a conflict, kept until approved.
        let renamed = moved.replace(name, new_name);
        let plan = app.spec_reimport_plan(&current_import(&app, &ws), renamed.as_bytes()).unwrap();
        assert_eq!(plan.conflicts.iter().map(|c| c.existing_id).collect::<Vec<_>>(), vec![q.meta.id], "{label}: {plan:?}");
        app.spec_reimport_apply(&current_import(&app, &ws), renamed.as_bytes(), "source.txt", &ReimportApproval::default()).unwrap();
        assert_eq!(app.request(&q.meta.id).unwrap().name, "Ping", "{label}");
        let plan = app.spec_reimport_plan(&current_import(&app, &ws), renamed.as_bytes()).unwrap();
        assert_eq!(plan.conflicts.iter().map(|c| c.existing_id).collect::<Vec<_>>(), vec![q.meta.id], "{label}: offered again");
        let approval = ReimportApproval { overwrite: vec![q.meta.id], ..Default::default() };
        app.spec_reimport_apply(&current_import(&app, &ws), renamed.as_bytes(), "source.txt", &approval).unwrap();
        assert_eq!(app.request(&q.meta.id).unwrap().name, "Health check", "{label}");
    }
}

#[test]
fn a_declined_rename_conflict_still_takes_the_sources_new_spec() {
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let done = import(&app, COLLECTION.as_bytes(), SpecTarget::NewWorkspace);
    let ws = done.workspace_id;
    let mut q = app.requests(&ws).unwrap().into_iter().find(|q| q.name == "Health").unwrap();
    q.name = "Ping".into();
    let q = app.save_request(q).unwrap();

    // Moved and renamed upstream: the name conflicts, the spec does not.
    let v2 = COLLECTION.replace("{{base}}/health", "{{base}}/healthz").replace(r#""name": "Health""#, r#""name": "Health check""#);
    let plan = app.spec_reimport_plan(&done.import_id, v2.as_bytes()).unwrap();
    let conflict = plan.conflicts.iter().find(|c| c.existing_id == q.meta.id).unwrap_or_else(|| panic!("{plan:?}"));
    assert_eq!(conflict.upstream_fields, vec!["spec".to_string(), "name".to_string()]);
    assert_eq!(conflict.conflicting_fields, vec!["name".to_string()]);
    app.spec_reimport_apply(&done.import_id, v2.as_bytes(), "source.txt", &ReimportApproval::default()).unwrap();
    let after = app.request(&q.meta.id).unwrap();
    assert_eq!(after.name, "Ping", "declined: the user's name is kept");
    assert!(after.spec.url.ends_with("/healthz"), "the spec the user did not edit is updated: {}", after.spec.url);
    assert_ne!(after.revision_id, q.revision_id, "and recorded as a new revision");

    // Only the name is offered again; approved, it is applied.
    let plan = app.spec_reimport_plan(&current_import(&app, &ws), v2.as_bytes()).unwrap();
    let conflict = plan.conflicts.iter().find(|c| c.existing_id == q.meta.id).unwrap_or_else(|| panic!("{plan:?}"));
    assert_eq!(conflict.upstream_fields, vec!["name".to_string()], "{plan:?}");
    let approval = ReimportApproval { overwrite: vec![q.meta.id], ..Default::default() };
    app.spec_reimport_apply(&current_import(&app, &ws), v2.as_bytes(), "source.txt", &approval).unwrap();
    let after = app.request(&q.meta.id).unwrap();
    assert_eq!(after.name, "Health check");
    assert!(after.spec.url.ends_with("/healthz"), "{}", after.spec.url);
}

/// Store `rec` as a build that kept only the scope's hashes wrote it: no
/// `folders/…` or `requests/…` units.
fn legacy(app: &App, mut rec: SpecSourceRecord) {
    let generated = rec.generated_scope.as_mut().expect("a record of what was generated");
    generated.retain(|k, _| !k.starts_with("folders/") && !k.starts_with("requests/"));
    app.store.put(kind::SPEC_SOURCE, &rec.source.import_id, Some(&rec.workspace_id), None, 0.0, &rec).unwrap();
}

#[test]
fn a_record_from_before_folder_and_request_units_gets_them_from_its_stored_original() {
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let done = app.spec_import(ADMIN.as_bytes(), "admin.json", &ImportOptions::default(), SpecTarget::NewWorkspace).unwrap();
    let ws = done.workspace_id;
    let folder = app.folders(&ws).unwrap().into_iter().find(|f| f.name == "Admin").unwrap().meta.id;
    let mut q = app.requests(&ws).unwrap().pop().unwrap();
    q.name = "Mine".into();
    let q = app.save_request(q).unwrap();
    let rec = record(&app, &ws, None);
    assert!(rec.previous_import_ids.is_empty(), "never reimported");
    legacy(&app, rec);

    // The same version: the rename is the user's own.
    let plan = app.spec_reimport_plan(&done.import_id, ADMIN.as_bytes()).unwrap();
    assert_eq!(plan.preserved_edits, vec![q.meta.id], "{plan:?}");
    assert!(plan.updated.is_empty() && plan.conflicts.is_empty(), "{plan:?}");
    assert!(plan.scope_updated.is_empty() && plan.scope_conflicts.is_empty(), "{plan:?}");

    // A newer one: the folder's changes are safe updates, and the rename is kept.
    let v2 = admin("write");
    let plan = app.spec_reimport_plan(&done.import_id, &v2).unwrap();
    let scope = format!("folders/{folder}/variables/scope");
    assert!(plan.scope_updated.iter().any(|c| c.key == scope), "{plan:?}");
    assert!(plan.scope_conflicts.is_empty(), "{plan:?}");
    assert_eq!(plan.preserved_edits, vec![q.meta.id], "{plan:?}");
    app.spec_reimport_apply(&done.import_id, &v2, "admin.json", &ReimportApproval::default()).unwrap();
    let (url, auth, _) = prepared(&app, &ws, "Mine");
    assert!(url.ends_with("/users/write"), "{url}");
    assert!(matches!(&auth, AuthConfig::ApiKey { name, .. } if name == "X-Admin"), "{auth:?}");
}

#[test]
fn a_reimported_record_from_before_folder_and_request_units_asks_before_changing_them() {
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let done = app.spec_import(ADMIN.as_bytes(), "admin.json", &ImportOptions::default(), SpecTarget::NewWorkspace).unwrap();
    let ws = done.workspace_id;
    let folder = app.folders(&ws).unwrap().into_iter().find(|f| f.name == "Admin").unwrap().meta.id;
    app.spec_reimport_apply(&done.import_id, ADMIN.as_bytes(), "admin.json", &ReimportApproval::default()).unwrap();
    let mut q = app.requests(&ws).unwrap().pop().unwrap();
    q.name = "Mine".into();
    let q = app.save_request(q).unwrap();
    let rec = record(&app, &ws, None);
    assert_eq!(rec.previous_import_ids, vec![done.import_id], "reimported once");
    let latest = rec.source.import_id;
    legacy(&app, rec);

    // What was generated for the folder and the name is unknown: every
    // difference awaits approval.
    let v2 = admin("write");
    let plan = app.spec_reimport_plan(&latest, &v2).unwrap();
    assert_eq!(plan.conflicts.iter().map(|c| c.existing_id).collect::<Vec<_>>(), vec![q.meta.id], "{plan:?}");
    assert_eq!(plan.conflicts[0].conflicting_fields, vec!["name".to_string()]);
    let scope = format!("folders/{folder}/variables/scope");
    assert!(plan.scope_conflicts.iter().any(|c| c.key == scope && c.user_edited), "{plan:?}");
    assert!(!plan.scope_updated.iter().any(|c| c.key.starts_with("folders/")), "{plan:?}");
    app.spec_reimport_apply(&latest, &v2, "admin.json", &ReimportApproval::default()).unwrap();
    let (url, auth, _) = prepared(&app, &ws, "Mine");
    assert!(url.ends_with("/users/read"), "declined: the folder is kept: {url}");
    assert!(!matches!(auth, AuthConfig::ApiKey { .. }), "{auth:?}");
}
