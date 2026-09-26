//! App-level spec import / reimport and load-plan services.

use anvil_app::App;
use anvil_app::profiles::ProfileManager;
use anvil_app::specs::SpecTarget;
use anvil_domain::Id;
use anvil_domain::load::{LoadPlan, Workload};
use anvil_domain::request::RequestSpec;
use anvil_import::{ImportOptions, ReimportApproval};
use anvil_storage::KdfParams;
use tokio_util::sync::CancellationToken;

fn new_app(root: &std::path::Path) -> App {
    let pm = ProfileManager::new(root);
    let (s, dek, _recovery) = pm.create_passphrase("t", "correct horse battery", KdfParams::testing()).unwrap();
    let h = anvil_storage::vault::read_header(&s.dir).unwrap();
    App::open(s.dir, h, dek).unwrap()
}

const SPEC_V1: &str = r#"
openapi: 3.1.0
info: { title: Orders API, version: "1" }
servers: [{ url: "https://orders.example.com/v1" }]
paths:
  /orders:
    get:
      operationId: listOrders
      tags: [orders]
      responses: { "200": { description: ok } }
  /orders/{id}:
    get:
      operationId: getOrder
      tags: [orders]
      parameters: [{ name: id, in: path, required: true, schema: { type: integer } }]
      responses: { "200": { description: ok } }
"#;

const SPEC_V2: &str = r#"
openapi: 3.1.0
info: { title: Orders API, version: "2" }
servers: [{ url: "https://orders.example.com/v1" }]
paths:
  /orders:
    get:
      operationId: listOrders
      tags: [orders]
      parameters: [{ name: limit, in: query, required: true, schema: { type: integer } }]
      responses: { "200": { description: ok } }
  /orders/{id}:
    get:
      operationId: getOrder
      tags: [orders]
      parameters: [{ name: id, in: path, required: true, schema: { type: integer } }]
      responses: { "200": { description: ok } }
  /refunds:
    post:
      operationId: createRefund
      tags: [refunds]
      responses: { "201": { description: created } }
"#;

#[test]
fn spec_import_new_workspace_records_provenance_and_nothing_runs() {
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let preview = app.spec_preview(SPEC_V1.as_bytes(), &ImportOptions::default()).unwrap();
    assert_eq!(preview.requests, 2);
    let done = app.spec_import(SPEC_V1.as_bytes(), "orders.yaml", &ImportOptions::default(), SpecTarget::NewWorkspace).unwrap();
    assert_eq!(done.requests, 2);
    assert_eq!(app.requests(&done.workspace_id).unwrap().len(), 2);
    let sources = app.spec_sources(&done.workspace_id).unwrap();
    assert_eq!(sources.len(), 1);
    assert_eq!(sources[0].file_name, "orders.yaml");
    // Original bytes are retained as a content-addressed attachment.
    assert!(app.get_attachment(&sources[0].original_sha256).unwrap().is_some());
    // Importing sends nothing: history stays empty.
    assert!(app.store.list_history(Some(&done.workspace_id), None, 10).unwrap().is_empty());
}

#[test]
fn spec_import_into_existing_workspace_nests_under_a_new_folder() {
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let ws = app.create_workspace("Mine").unwrap();
    let done = app
        .spec_import(SPEC_V1.as_bytes(), "orders.yaml", &ImportOptions::default(), SpecTarget::Workspace { workspace_id: ws.meta.id })
        .unwrap();
    let rootf = done.root_folder_id.unwrap();
    let tree = app.tree(&ws.meta.id).unwrap();
    assert_eq!(tree.len(), 1, "one new top-level folder");
    assert_eq!(tree[0].id, rootf);
    assert_eq!(app.requests(&ws.meta.id).unwrap().len(), 2);
}

#[test]
fn data_012_spec_reimport_adds_new_operations_and_preserves_user_edits() {
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let done = app.spec_import(SPEC_V1.as_bytes(), "orders.yaml", &ImportOptions::default(), SpecTarget::NewWorkspace).unwrap();
    // The user edits listOrders.
    let mut edited = app
        .requests(&done.workspace_id)
        .unwrap()
        .into_iter()
        .find(|r| r.name.contains("listOrders") || r.spec.url.ends_with("/orders"))
        .unwrap();
    edited.spec.headers.push(anvil_domain::request::KeyValue::new("X-Mine", "1"));
    app.save_request(edited.clone()).unwrap();

    let plan = app.spec_reimport_plan(&done.import_id, SPEC_V2.as_bytes()).unwrap();
    assert_eq!(plan.added.len(), 1, "createRefund is new");
    assert_eq!(plan.conflicts.len(), 1, "listOrders changed upstream and was edited locally");
    let n = app.spec_reimport_apply(&done.import_id, SPEC_V2.as_bytes(), &ReimportApproval::default()).unwrap();
    assert_eq!(n, 3);
    let after = app.requests(&done.workspace_id).unwrap();
    assert_eq!(after.len(), 3);
    let kept = after.iter().find(|r| r.meta.id == edited.meta.id).unwrap();
    assert!(kept.spec.headers.iter().any(|h| h.name == "X-Mine"), "user edit kept without explicit overwrite approval");
    // A second reimport still finds the linked requests.
    let again = app.spec_reimport_plan(&app.spec_sources(&done.workspace_id).unwrap()[0].source.import_id, SPEC_V2.as_bytes()).unwrap();
    assert!(again.added.is_empty());
}

fn plan(ws: Id, req: Id) -> LoadPlan {
    LoadPlan {
        id: Id::new(),
        workspace_id: ws,
        name: "smoke".into(),
        workload: Workload::Iterations { iterations: 20, concurrency: 4 },
        chain: vec![req],
        mix: vec![],
        dataset_id: None,
        environment_id: None,
        connection_mode: Default::default(),
        warmup_secs: 0,
        abort: None,
        seed: 1,
        trusted: true,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

#[tokio::test]
async fn load_plan_requires_acknowledgement_runs_and_stores_report() {
    anvil_fixtures::init();
    let fx = anvil_fixtures::http::serve("127.0.0.1:0", None).await.unwrap();
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let ws = app.create_workspace("Load").unwrap();
    let req = app.create_request(&ws.meta.id, None, "echo", RequestSpec::http("GET", &fx.url("/echo"))).unwrap();

    let empty = LoadPlan { chain: vec![], ..plan(ws.meta.id, req.meta.id) };
    assert!(app.save_load_plan(empty).is_err(), "a plan without requests is rejected at save time");
    let p = app.save_load_plan(plan(ws.meta.id, req.meta.id)).unwrap();

    let pre = app.load_preflight(&p).unwrap();
    assert_eq!(pre.destinations.len(), 1);
    assert!(pre.destinations[0].starts_with("GET http://127.0.0.1:"), "{:?}", pre.destinations);
    assert!(app.worker_job(&p, false).is_err(), "never runs without explicit acknowledgement");
    let untrusted = LoadPlan { trusted: false, ..p.clone() };
    assert!(app.worker_job(&untrusted, true).is_err(), "imported plans must be reviewed first");

    // Run in-process (the desktop/CLI use the worker process; semantics are identical).
    let job = app.load_job(&p).unwrap();
    let run = anvil_load::LoadRun::prepare(p.clone(), job, anvil_load::RunOptions { acknowledged: true, ..Default::default() }).unwrap();
    let report = run.execute(CancellationToken::new(), None).await;
    assert_eq!(report.counts.started, 20);
    assert_eq!(report.counts.completed, 20);
    app.save_load_report(&report).unwrap();
    let list = app.load_reports(&ws.meta.id).unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(app.load_report(&report.run_id).unwrap().counts.started, 20);
    app.delete_load_report(&report.run_id).unwrap();
    assert!(app.load_reports(&ws.meta.id).unwrap().is_empty());
}

/// LOAD-013 at the app boundary: the editor's plan check names the unit (or
/// the typed refusal) and the preflight shows protocol destinations and
/// refuses unsupported plans before the user can start traffic.
#[tokio::test]
async fn load_plan_check_names_the_unit_and_preflight_refuses_mixed_protocols() {
    anvil_fixtures::init();
    let fx = anvil_fixtures::http::serve("127.0.0.1:0", None).await.unwrap();
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let ws = app.create_workspace("Load").unwrap();
    let mut s = RequestSpec::http("GET", &format!("ws://{}/ws", fx.addr));
    s.protocol = anvil_domain::request::Protocol::WebSocket;
    let wsreq = app.create_request(&ws.meta.id, None, "socket", s).unwrap();
    let http = app.create_request(&ws.meta.id, None, "echo", RequestSpec::http("GET", &fx.url("/echo"))).unwrap();

    let p = app.save_load_plan(plan(ws.meta.id, wsreq.meta.id)).unwrap();
    let check = app.load_plan_check(&p).unwrap();
    assert_eq!(check.unit, Some(anvil_domain::load::LoadUnitKind::WebsocketSession));
    assert!(check.refusal.is_none());
    assert_eq!(check.semantics.unwrap().unit_plural, "sessions");
    let pre = app.load_preflight(&p).unwrap();
    assert_eq!(pre.destinations, vec![format!("WebSocket ws://{}", fx.addr)]);
    assert_eq!(pre.unit_label, "WebSocket sessions");
    assert!(pre.warnings.iter().any(|w| w.contains("connection mode does not apply")), "{:?}", pre.warnings);

    let mixed = app.save_load_plan(LoadPlan { chain: vec![http.meta.id, wsreq.meta.id], ..plan(ws.meta.id, http.meta.id) }).unwrap();
    let check = app.load_plan_check(&mixed).unwrap();
    assert_eq!(check.unit, None);
    assert_eq!(check.refusal.as_ref().unwrap().code, anvil_load::RefusalCode::MixedUnitKinds);
    assert_eq!(check.protocols.len(), 2);
    let err = app.load_preflight(&mixed).unwrap_err().to_string();
    assert!(err.contains("LOAD-013"), "{err}");
    assert!(fx.log.entries().is_empty(), "checks and preflights send nothing");
}
