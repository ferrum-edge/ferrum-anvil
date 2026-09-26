//! Spec/collection imports persisted by the app: every import is an
//! independent copy, an import is written all at once or not at all, and an
//! import into an existing workspace keeps the source's own scope instead of
//! picking up the destination workspace's auth.

use anvil_app::exec::SendOptions;
use anvil_app::profiles::ProfileManager;
use anvil_app::runner::RunSettings;
use anvil_app::specs::SpecTarget;
use anvil_app::{App, AppError};
use anvil_domain::Id;
use anvil_domain::assertions::{Extraction, ExtractionSource};
use anvil_domain::auth::AuthConfig;
use anvil_domain::request::{KeyValue, RequestSpec};
use anvil_domain::runner::RunStepStatus;
use anvil_domain::secret::SensitiveValue;
use anvil_domain::tls::{ClientIdentity, HostBinding, TlsProfile};
use anvil_domain::workload::{JwtSvidConfig, JwtSvidSource};
use anvil_domain::workspace::{Environment, Variable, Workspace};
use anvil_engine::ExecutionContext;
use anvil_fixtures::GroundTruth;
use anvil_import::{ImportOptions, ReimportApproval};
use anvil_portability::ExportMode;
use anvil_portability::plan::ConflictPolicy;
use anvil_storage::KdfParams;
use anvil_storage::store::DB_FILE;
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
    app.spec_reimport_apply(&first.import_id, newer, &ReimportApproval::default()).unwrap();
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
    let (bytes, _) = app.export(Some(&dest.meta.id), ExportMode::FullBackup, Some("export passphrase 1"), false).unwrap();
    let other = tempfile::tempdir().unwrap();
    let b = new_app(other.path());
    let report = b.import(&bytes, Some("export passphrase 1"), ConflictPolicy::Duplicate).unwrap();
    assert!(report.warnings.iter().any(|w| w.contains("imported collection")), "{:?}", report.warnings);
    let ws_b: Id = report.workspace_ids[0].parse().unwrap();
    let root_b = b.folders(&ws_b).unwrap().into_iter().find(|f| f.import_root).expect("the import root is kept");
    assert!(!root_b.use_workspace_scope);
    let deep_b = b.requests(&ws_b).unwrap().into_iter().find(|q| q.name == "Deep").unwrap();
    nothing_from_the_destination(&b.build_context(Some(deep_b.meta.id), &ws_b, None, &SendOptions::default()).unwrap());
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
    let identity = ClientIdentity::Pem {
        cert_chain_pem: "-----BEGIN CERTIFICATE-----".into(),
        private_key_pem: SensitiveValue::Template { value: "destination-key".into() },
    };
    let tls = app
        .save_tls_profile(TlsProfile {
            id: Id::new(),
            workspace_id: dest.meta.id,
            name: "device cert".into(),
            verify: true,
            use_system_roots: true,
            extra_roots_pem: vec![],
            client_identity: Some(identity),
            bindings: vec![],
            min_version: Default::default(),
            server_name_override: None,
            server_spiffe: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        })
        .unwrap();
    dest.settings.tls_profile_id = Some(tls.id);
    let dest = app.save_workspace(dest).unwrap();
    let deep = app.requests(&dest.meta.id).unwrap().into_iter().find(|q| q.name == "Deep").unwrap();
    let build = || app.build_context(Some(deep.meta.id), &dest.meta.id, None, &SendOptions::default());

    let err = refused(build(), "a client identity bound to no host");
    assert!(err.contains("TLS profile 'device cert'"), "{err}");
    // Bound to hosts, it is presented only to them.
    let mut bound = tls.clone();
    bound.bindings = vec![HostBinding { host: "internal.example.invalid".into(), port: None }];
    app.save_tls_profile(bound).unwrap();
    build().expect("a bound client identity");
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
