//! Renderer-reachable App saves and explicit moves exercise the production
//! storage guards. No desktop command/state changes are needed for this gate.

use anvil_app::profiles::ProfileManager;
use anvil_app::{App, AppError};
use anvil_domain::Id;
use anvil_domain::request::RequestSpec;
use anvil_domain::workspace::{DatasetFormat, RequestDefinition, ScenarioStep};
use anvil_storage::store::DB_FILE;
use anvil_storage::{KdfParams, StoreError, kind};
use rusqlite::{Connection, params};
use serde_json::{Value, json};

fn open() -> (tempfile::TempDir, App) {
    let root = tempfile::tempdir().unwrap();
    let pm = ProfileManager::new(root.path());
    let (profile, key, _) = pm.create_passphrase("owner binding", "test passphrase", KdfParams::testing()).unwrap();
    let header = anvil_storage::vault::read_header(&profile.dir).unwrap();
    let app = App::open(profile.dir, header, key).unwrap();
    (root, app)
}

fn db(app: &App) -> Connection {
    Connection::open(app.dir.join(DB_FILE)).unwrap()
}

#[derive(Debug, PartialEq)]
struct RawObject {
    kind: String,
    id: String,
    owner: Option<String>,
    parent: Option<String>,
    sort_key: f64,
    updated_at: i64,
    payload: Vec<u8>,
}

fn snapshot(app: &App) -> Vec<RawObject> {
    let conn = db(app);
    let mut st = conn
        .prepare(
            "SELECT kind,id,workspace_id,parent_id,sort_key,updated_at,payload
             FROM objects ORDER BY kind,id",
        )
        .unwrap();
    st.query_map([], |r| {
        Ok(RawObject {
            kind: r.get(0)?,
            id: r.get(1)?,
            owner: r.get(2)?,
            parent: r.get(3)?,
            sort_key: r.get(4)?,
            updated_at: r.get(5)?,
            payload: r.get(6)?,
        })
    })
    .unwrap()
    .collect::<Result<_, _>>()
    .unwrap()
}

fn save(app: &App, k: &str, value: Value) -> anvil_app::Result<()> {
    match k {
        kind::FOLDER => app.save_folder(serde_json::from_value(value)?).map(|_| ()),
        kind::REQUEST => app.save_request(serde_json::from_value(value)?).map(|_| ()),
        kind::ENVIRONMENT => app.save_environment(serde_json::from_value(value)?).map(|_| ()),
        kind::TLS_PROFILE => app.save_tls_profile(serde_json::from_value(value)?).map(|_| ()),
        kind::PROXY_PROFILE => app.save_proxy_profile(serde_json::from_value(value)?).map(|_| ()),
        kind::INTEGRATION => app.save_integration(serde_json::from_value(value)?).map(|_| ()),
        kind::SCENARIO => app.update_scenario(serde_json::from_value(value)?).map(|_| ()),
        kind::DATASET => app.save_dataset(serde_json::from_value(value)?).map(|_| ()),
        kind::LOAD_PLAN => app.save_load_plan(serde_json::from_value(value)?).map(|_| ()),
        _ => panic!("uncovered App save {k}"),
    }
}

fn list(app: &App, k: &str, ws: &Id) -> anvil_app::Result<Value> {
    Ok(match k {
        kind::FOLDER => json!(app.folders(ws)?),
        kind::REQUEST => json!(app.requests(ws)?),
        kind::ENVIRONMENT => json!(app.environments(ws)?),
        kind::TLS_PROFILE => json!(app.tls_profiles(ws)?),
        kind::PROXY_PROFILE => json!(app.proxy_profiles(ws)?),
        kind::INTEGRATION => json!(app.integrations(ws)?),
        kind::SCENARIO => json!(app.scenarios(ws)?),
        kind::DATASET => json!(app.datasets(ws)?),
        kind::LOAD_PLAN => json!(app.load_plans(ws)?),
        _ => panic!("uncovered App list {k}"),
    })
}

fn objects(app: &App, ws: Id) -> Vec<(&'static str, Id, Value)> {
    let folder = app.create_folder(&ws, None, "folder").unwrap();
    let request = app.create_request(&ws, Some(folder.meta.id), "request", RequestSpec::http("GET", "https://original.invalid/")).unwrap();
    let environment = app.create_environment(&ws, "environment", vec![]).unwrap();
    let scenario =
        app.create_scenario(&ws, "scenario", vec![ScenarioStep { request_id: request.meta.id, enabled: true, delay_ms: 0 }]).unwrap();
    let dataset = app.create_dataset(&ws, "dataset", DatasetFormat::Csv, b"column\nvalue\n", vec![]).unwrap();
    let mut out = vec![
        (kind::FOLDER, folder.meta.id, json!(folder)),
        (kind::REQUEST, request.meta.id, json!(request)),
        (kind::ENVIRONMENT, environment.meta.id, json!(environment)),
        (kind::SCENARIO, scenario.meta.id, json!(scenario)),
        (kind::DATASET, dataset.meta.id, json!(dataset)),
    ];
    for k in [kind::TLS_PROFILE, kind::PROXY_PROFILE, kind::INTEGRATION, kind::LOAD_PLAN] {
        let id = Id::new();
        let now = chrono::Utc::now();
        let mut value = json!({
            "id": id, "workspace_id": ws, "name": k, "created_at": now, "updated_at": now
        });
        match k {
            kind::TLS_PROFILE => {}
            kind::PROXY_PROFILE => {
                value["kind"] = json!("http");
                value["address"] = json!("127.0.0.1:8080");
            }
            kind::INTEGRATION => {
                value["kind"] = json!("ferrum_gateway");
                value["hosts"] = json!([]);
                value["compatibility_id"] = json!("ferrum-edge-0.9.10");
            }
            kind::LOAD_PLAN => {
                value["workload"] = json!({
                    "model": "iterations", "iterations": 1, "concurrency": 1
                });
                value["chain"] = json!([request.meta.id]);
                value["trusted"] = json!(true);
            }
            _ => unreachable!(),
        }
        save(app, k, value.clone()).unwrap();
        out.push((k, id, value));
    }
    out
}

#[test]
fn ipc_reachable_saves_reject_existing_ids_under_a_different_workspace() {
    let (_root, app) = open();
    let a = app.create_workspace("A").unwrap().meta.id;
    let b = app.create_workspace("B").unwrap().meta.id;
    let target = app.create_request(&b, None, "target", RequestSpec::http("GET", "https://target.invalid/")).unwrap();
    for (k, _id, mut value) in objects(&app, a) {
        save(&app, k, value.clone()).unwrap();
        let original = snapshot(&app);
        value["workspace_id"] = json!(b);
        value["name"] = json!("substitution");
        if k == kind::FOLDER {
            value["parent_id"] = Value::Null;
        }
        if k == kind::SCENARIO {
            value["steps"] = json!([{"request_id": target.meta.id}]);
        }
        if k == kind::LOAD_PLAN {
            value["chain"] = json!([target.meta.id]);
        }
        let result = save(&app, k, value);
        assert!(matches!(result, Err(AppError::Store(StoreError::Ownership))), "{k}: {result:?}");
        assert_eq!(snapshot(&app), original, "{k} changed rows or attachment indexes on refusal");
        assert!(list(&app, k, &a).unwrap().as_array().is_some_and(|v| !v.is_empty()));
    }
}

#[test]
fn app_lists_and_saves_refuse_offline_owner_edits_without_adopting_them() {
    let (_root, app) = open();
    let a = app.create_workspace("A").unwrap().meta.id;
    let b = app.create_workspace("B").unwrap().meta.id;
    for (k, id, mut value) in objects(&app, a) {
        // SQLite-only attacker: no DEK and no change to the encrypted bytes.
        db(&app).execute("UPDATE objects SET workspace_id=?1 WHERE kind=?2 AND id=?3", params![b.to_string(), k, id.to_string()]).unwrap();
        assert!(matches!(list(&app, k, &b), Err(AppError::Store(StoreError::Integrity))), "{k}");
        let tampered = snapshot(&app);
        value["workspace_id"] = json!(b);
        // Remove references so scenario/plan validation cannot mask the
        // actual storage gate with an unrelated cross-workspace reference.
        if k == kind::SCENARIO {
            value["steps"] = json!([]);
        }
        if k == kind::LOAD_PLAN {
            let target = app.create_request(&b, None, "target", RequestSpec::http("GET", "https://target.invalid/")).unwrap();
            value["chain"] = json!([target.meta.id]);
        }
        let before_save = snapshot(&app);
        let result = save(&app, k, value);
        assert!(matches!(result, Err(AppError::Store(StoreError::Integrity))), "{k}: {result:?}");
        assert_eq!(snapshot(&app), before_save, "{k} adopted tampered metadata");
        if k != kind::LOAD_PLAN {
            assert_eq!(before_save, tampered);
        }
        db(&app).execute("UPDATE objects SET workspace_id=?1 WHERE kind=?2 AND id=?3", params![a.to_string(), k, id.to_string()]).unwrap();
    }
}

#[test]
fn explicit_folder_and_request_moves_keep_owner_revisions_and_referential_integrity() {
    let (_root, app) = open();
    let a = app.create_workspace("A").unwrap().meta.id;
    let b = app.create_workspace("B").unwrap().meta.id;
    let left = app.create_folder(&a, None, "left").unwrap();
    let right = app.create_folder(&a, None, "right").unwrap();
    let foreign = app.create_folder(&b, None, "foreign").unwrap();
    let child = app.create_folder(&a, Some(left.meta.id), "child").unwrap();
    let request = app.create_request(&a, Some(child.meta.id), "request", RequestSpec::http("GET", "https://original.invalid/")).unwrap();
    let moved = app.move_folder(&child.meta.id, Some(right.meta.id), 3.0).unwrap();
    assert_eq!(moved.workspace_id, a);
    assert_eq!(moved.parent_id, Some(right.meta.id));
    let moved = app.move_request(&request.meta.id, Some(left.meta.id), 4.0).unwrap();
    assert_eq!(moved.workspace_id, a);
    assert_eq!(moved.folder_id, Some(left.meta.id));
    assert_eq!(moved.revision_id, request.revision_id);
    assert_eq!(app.revision(&moved.revision_id.unwrap()).unwrap().request_id, request.meta.id);
    // A stale editor save retains the placement of the explicit move.
    let saved = app.save_request(request.clone()).unwrap();
    assert_eq!(saved.folder_id, Some(left.meta.id));
    assert_eq!(saved.sort_key, 4.0);

    let original = snapshot(&app);
    assert!(app.move_folder(&child.meta.id, Some(foreign.meta.id), 0.0).is_err());
    assert!(app.move_request(&request.meta.id, Some(foreign.meta.id), 0.0).is_err());
    assert!(app.move_folder(&right.meta.id, Some(child.meta.id), 0.0).is_err());
    assert!(app.move_request(&request.meta.id, Some(Id::new()), 0.0).is_err());
    assert!(app.create_folder(&a, Some(foreign.meta.id), "refused").is_err());
    let mut invalid = app.folder(&child.meta.id).unwrap();
    invalid.parent_id = Some(foreign.meta.id);
    assert!(app.save_folder(invalid).is_err());
    assert_eq!(snapshot(&app), original, "refused placements must mutate no row");
    app.delete_request(&request.meta.id).unwrap();
    assert!(app.revision(&request.revision_id.unwrap()).is_err());
}

#[test]
fn request_save_cannot_use_another_requests_revision_and_failure_rolls_back_new_revision() {
    let (_root, app) = open();
    let ws = app.create_workspace("A").unwrap().meta.id;
    let spec = RequestSpec::http("GET", "https://original.invalid/");
    let first = app.create_request(&ws, None, "first", spec.clone()).unwrap();
    let second = app.create_request(&ws, None, "second", spec).unwrap();
    let original = snapshot(&app);
    let mut substituted = first.clone();
    substituted.revision_id = second.revision_id;
    assert!(matches!(app.save_request(substituted), Err(AppError::Store(StoreError::Ownership))));
    assert_eq!(snapshot(&app), original);

    db(&app)
        .execute_batch(
            "CREATE TRIGGER refuse_request_write BEFORE UPDATE ON objects
             WHEN NEW.kind='request' BEGIN SELECT RAISE(ABORT, 'injected failure'); END;",
        )
        .unwrap();
    let changed = RequestDefinition { spec: RequestSpec::http("POST", "https://changed.invalid/"), ..first };
    assert!(matches!(app.save_request(changed), Err(AppError::Store(StoreError::Db(_)))));
    assert_eq!(snapshot(&app), original, "new revision and parent update must roll back together");
}
