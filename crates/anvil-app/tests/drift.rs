//! Contract drift from history: real sends of an imported collection are
//! compared with the import's description, one send is checked on its own,
//! and reimporting the revised description resolves what it documents.

use anvil_app::App;
use anvil_app::exec::SendOptions;
use anvil_app::profiles::ProfileManager;
use anvil_app::specs::SpecTarget;
use anvil_contract::DriftKind;
use anvil_domain::Id;
use anvil_domain::request::RequestSpec;
use anvil_import::ImportOptions;
use anvil_storage::KdfParams;
use anvil_transport::recorder::EventCtx;
use std::path::Path;
use tokio_util::sync::CancellationToken;

fn new_app(root: &Path) -> App {
    let pm = ProfileManager::new(root);
    let (s, dek, _recovery) = pm.create_passphrase("t", "correct horse battery", KdfParams::testing()).unwrap();
    let h = anvil_storage::vault::read_header(&s.dir).unwrap();
    App::open(s.dir, h, dek).unwrap()
}

/// The fixture's `/status/{code}` answers `{"status": code, "source": …}`.
fn spec(base: &str) -> String {
    r#"{"openapi":"3.1.0","info":{"title":"Fixture","version":"1"},"servers":[{"url":"BASE"}],
      "paths":{"/status/{code}":{"get":{"operationId":"status",
        "parameters":[{"name":"code","in":"path","required":true,"schema":{"type":"integer"},"example":200}],
        "responses":{"200":{"description":"ok","content":{"application/json":{"schema":
          {"type":"object","required":["status"],"properties":{"status":{"type":"integer"}}}}}}}}}}}"#
        .replace("BASE", base)
}

async fn send(app: &App, ws: &Id, request: &Id, env: Option<Id>) -> Id {
    let opts = SendOptions { environment: env, record_history: true, ..Default::default() };
    let out = app.send(Some(*request), ws, None, opts, EventCtx::none(), CancellationToken::new()).await.unwrap();
    out.record.id
}

#[tokio::test(flavor = "multi_thread")]
async fn history_drift_is_found_and_a_reimport_of_the_revision_resolves_it() {
    anvil_fixtures::init();
    let f = anvil_fixtures::http::serve("127.0.0.1:0", None).await.unwrap();
    let base = f.url("").trim_end_matches('/').to_string();
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let done = app.spec_import(spec(&base).as_bytes(), "fixture.json", &ImportOptions::default(), SpecTarget::NewWorkspace).unwrap();
    let ws = done.workspace_id;
    let env = app.workspace(&ws).unwrap().active_environment_id;
    let imported = app.requests(&ws).unwrap().pop().unwrap();
    // Requests the user added to the imported workspace are its collection too.
    let not_found = app.create_request(&ws, None, "Missing", RequestSpec::http("GET", &f.url("/status/404"))).unwrap();
    let echo = app.create_request(&ws, None, "Echo", RequestSpec::http("GET", &f.url("/echo"))).unwrap();

    send(&app, &ws, &imported.meta.id, env).await;
    let missing = send(&app, &ws, &not_found.meta.id, env).await;
    send(&app, &ws, &echo.meta.id, env).await;

    let r = app.drift_report(&done.import_id, 100).unwrap();
    assert_eq!((r.observations, r.matched), (3, 2), "{:#?}", r.findings);
    let kinds: Vec<DriftKind> = r.findings.iter().map(|x| x.kind).collect();
    assert!(kinds.contains(&DriftKind::UndeclaredStatus), "{:#?}", r.findings);
    assert!(kinds.contains(&DriftKind::UndeclaredPath), "{:#?}", r.findings);
    let status = r.operations.iter().find(|o| o.operation == "GET /status/{code}").unwrap();
    assert_eq!(status.calls, 2);
    assert!(status.latency_ms.is_some());
    assert!(
        r.suggestions.iter().any(|s| s.title == "Document property `source` of the 200 response of GET /status/{code}"),
        "{:#?}",
        r.suggestions
    );

    // One send on its own, as the response panel shows it.
    let (rec, one) = app.drift_check_execution(&missing).unwrap().expect("linked to the import");
    assert_eq!(rec.source.import_id, done.import_id);
    assert_eq!(one.observations, 1);
    assert_eq!(one.findings[0].kind, DriftKind::UndeclaredStatus);
    assert!(one.findings[0].message.contains("returned 404"));

    // Reimport the description revised with the recommended suggestions.
    let ids: Vec<String> = r.suggestions.iter().filter(|s| s.recommended).map(|s| s.id.clone()).collect();
    let (rev, plan) = app.drift_reimport_plan(&done.import_id, &ids, 100).unwrap();
    assert_eq!(rev.applied.len(), ids.len());
    assert_eq!(plan.added.len(), 1, "GET /echo becomes a request");
    let (_, changed) = app.drift_reimport_apply(&done.import_id, &ids, 100).unwrap();
    assert!(changed >= 1);
    // The stored original is the revision now, under the earlier id too.
    let revised = String::from_utf8(app.spec_original(&done.import_id).unwrap()).unwrap();
    assert!(revised.contains("\"404\"") && revised.contains("/echo"), "{revised}");
    let again = app.drift_report(&done.import_id, 100).unwrap();
    let left: Vec<DriftKind> = again.findings.iter().map(|x| x.kind).collect();
    assert!(!left.contains(&DriftKind::UndeclaredStatus) && !left.contains(&DriftKind::UndeclaredPath), "{:#?}", again.findings);
    assert_eq!(again.matched, 3);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_send_outside_any_import_has_no_drift_check() {
    anvil_fixtures::init();
    let f = anvil_fixtures::http::serve("127.0.0.1:0", None).await.unwrap();
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let ws = app.create_workspace("Plain").unwrap().meta.id;
    let r = app.create_request(&ws, None, "Echo", RequestSpec::http("GET", &f.url("/echo"))).unwrap();
    let id = send(&app, &ws, &r.meta.id, None).await;
    assert!(app.drift_check_execution(&id).unwrap().is_none());
    assert!(app.drift_check_execution(&Id::new()).is_err());
}
