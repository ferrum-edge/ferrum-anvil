//! Spec/collection imports persisted by the app: every import is an
//! independent copy, an import is written all at once or not at all, and an
//! import into an existing workspace keeps the source's own scope instead of
//! picking up the destination workspace's auth.

use anvil_app::App;
use anvil_app::exec::SendOptions;
use anvil_app::profiles::ProfileManager;
use anvil_app::specs::SpecTarget;
use anvil_domain::Id;
use anvil_domain::auth::AuthConfig;
use anvil_domain::secret::SensitiveValue;
use anvil_domain::workspace::{Variable, Workspace};
use anvil_import::{ImportOptions, ReimportApproval};
use anvil_storage::KdfParams;
use anvil_storage::store::DB_FILE;
use std::collections::HashSet;
use std::path::Path;

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

#[test]
fn a_sources_own_auth_applies_instead_of_the_destinations() {
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let dest = destination_with_credentials(&app);
    let api_key = r#""auth": { "type": "apikey", "apikey": [
      { "key": "key", "value": "X-Key" }, { "key": "value", "value": "{{api_key}}" }, { "key": "in", "value": "header" }
    ] }"#;
    let collection = COLLECTION.replace(r#""auth": { "type": "noauth" }"#, api_key);
    let done = import(&app, collection.as_bytes(), into(&dest.meta.id));
    let root_folder = app.folder(&done.root_folder_id.unwrap()).unwrap();
    assert!(matches!(root_folder.auth, AuthConfig::ApiKey { .. }), "{:?}", root_folder.auth);
    let q = app.requests(&dest.meta.id).unwrap().into_iter().find(|q| q.name == "Deep").unwrap();
    let ctx = app.build_context(Some(q.meta.id), &dest.meta.id, None, &SendOptions::default()).unwrap();
    assert_eq!(ctx.effective_auth().1, root_folder.auth, "nested requests inherit the source's auth, not the destination's");
}
