//! `anvil reimport-spec`: the real binary and a real profile on disk. A dry
//! run prints the plan and its `plan_sha256`; an apply needs that digest (or
//! `--yes`) and is refused, writing nothing, when the plan changed since. A
//! request edited here that changed in the source too is kept, and one the
//! source no longer has is kept, unless named; an id the plan does not offer
//! is refused.

use anvil_app::App;
use anvil_app::profiles::{ProfileManager, Unlock};
use anvil_app::specs::SpecTarget;
use anvil_domain::Id;
use anvil_import::ImportOptions;
use anvil_storage::KdfParams;
use std::path::Path;
use std::process::{Command, Output};

const PASS: &str = "cli-reimport-passphrase-1";

const V1: &str = r#"{"openapi":"3.1.0","info":{"title":"Shop","version":"1"},
  "servers":[{"url":"https://shop.example.invalid"}],
  "paths":{
    "/orders":{"get":{"operationId":"listOrders","summary":"List orders","responses":{"200":{"description":"ok"}}}},
    "/orders/{id}":{
      "parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}}],
      "get":{"operationId":"getOrder","summary":"Get order","responses":{"200":{"description":"ok"}}},
      "delete":{"operationId":"deleteOrder","summary":"Delete order","responses":{"204":{"description":"gone"}}}}}}"#;

/// `listOrders` renamed upstream, `getOrder` renamed upstream (and, in the
/// profile, by the user), `deleteOrder` gone and `createOrder` new.
const V2: &str = r#"{"openapi":"3.1.0","info":{"title":"Shop","version":"2"},
  "servers":[{"url":"https://shop.example.invalid"}],
  "paths":{
    "/orders":{
      "get":{"operationId":"listOrders","summary":"List all orders","responses":{"200":{"description":"ok"}}},
      "post":{"operationId":"createOrder","summary":"Create order","responses":{"201":{"description":"made"}}}},
    "/orders/{id}":{
      "parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}}],
      "get":{"operationId":"getOrder","summary":"Fetch order","responses":{"200":{"description":"ok"}}}}}}"#;

fn create(root: &Path) -> App {
    let pm = ProfileManager::new(root);
    let (s, dek, _) = pm.create_passphrase("ci", PASS, KdfParams::testing()).unwrap();
    let h = anvil_storage::vault::read_header(&s.dir).unwrap();
    App::open(s.dir, h, dek).unwrap()
}

fn open(root: &Path) -> App {
    let s = ProfileManager::new(root).list().into_iter().next().unwrap();
    let (h, key) = ProfileManager::unlock(&s.dir, Unlock::Passphrase(PASS)).unwrap();
    App::open(s.dir, h, key).unwrap()
}

/// A profile with the workspace `Shop 1` imported from `V1`, whose `Get order`
/// the user renamed to `My order`. Returns the workspace and import ids.
fn setup(root: &Path) -> (Id, Id) {
    let app = create(root);
    let done = app.spec_import(V1.as_bytes(), "shop.json", &ImportOptions::default(), SpecTarget::NewWorkspace).unwrap();
    let mut get = app.requests(&done.workspace_id).unwrap().into_iter().find(|q| q.name == "Get order").unwrap();
    get.name = "My order".into();
    app.save_request(get).unwrap();
    (done.workspace_id, done.import_id)
}

fn anvil(data: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_anvil"))
        .arg("--data-dir")
        .arg(data)
        .args(args)
        .env("ANVIL_PASSPHRASE", PASS)
        .env_remove("ANVIL_PROFILE")
        .env_remove("ANVIL_DATA_DIR")
        .output()
        .unwrap()
}

fn text(o: &Output) -> String {
    format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr))
}

fn names(data: &Path, ws: &Id) -> Vec<String> {
    let mut names: Vec<String> = open(data).requests(ws).unwrap().into_iter().map(|q| q.name).collect();
    names.sort();
    names
}

fn request_id(data: &Path, ws: &Id, name: &str) -> String {
    open(data).requests(ws).unwrap().into_iter().find(|q| q.name == name).unwrap().meta.id.to_string()
}

#[test]
fn a_reviewed_reimport_applies_only_its_plan_and_keeps_edits_unless_named() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let (ws, first_import) = setup(&data);
    let v2 = dir.path().join("shop-v2.json");
    std::fs::write(&v2, V2).unwrap();
    let file = v2.to_str().unwrap();
    // OpenAPI names the workspace after its title and version ("Shop 1").
    let shop_id = ws.to_string();
    let shop = shop_id.as_str();
    let before = ["Delete order", "List orders", "My order"];
    let mine = request_id(&data, &ws, "My order");
    let gone = request_id(&data, &ws, "Delete order");

    // Neither reviewed nor confirmed: nothing is written.
    let o = anvil(&data, &["reimport-spec", shop, "--file", file]);
    assert_eq!(o.status.code(), Some(3), "{}", text(&o));
    assert!(text(&o).contains("--dry-run") && text(&o).contains("--plan-sha256"), "{}", text(&o));
    assert_eq!(names(&data, &ws), before);

    // The dry run: what changes, by id and stored name, and the digest.
    let o = anvil(&data, &["reimport-spec", shop, "--file", file, "--dry-run", "--json"]);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    let plan: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(plan["import_id"], serde_json::json!(first_import.to_string()), "{plan}");
    assert_eq!(plan["file_name"], serde_json::json!("shop-v2.json"), "{plan}");
    let p = &plan["plan"];
    assert_eq!(p["added"][0]["name"], serde_json::json!("Create order"), "{plan}");
    assert_eq!(p["updated"][0]["name"], serde_json::json!("List orders"), "{plan}");
    assert_eq!(p["conflicts"][0]["request_id"], serde_json::json!(mine), "{plan}");
    assert_eq!(p["conflicts"][0]["name"], serde_json::json!("My order"), "{plan}");
    assert_eq!(p["conflicts"][0]["conflicting_fields"], serde_json::json!(["name"]), "{plan}");
    assert_eq!(p["removed"][0]["request_id"], serde_json::json!(gone), "{plan}");
    assert!(p["conflicts"][0].get("fresh").is_none(), "generated contents stay out of the JSON: {plan}");
    let digest = plan["plan_sha256"].as_str().unwrap().to_string();
    assert_eq!(digest.len(), 64, "{plan}");

    let o = anvil(&data, &["reimport-spec", shop, "--file", file, "--dry-run", "--delete", &gone]);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    let out = text(&o);
    assert!(out.contains("edited here and in the source: 1"), "{out}");
    assert!(out.contains(&format!("[ ] {mine}  My order  both changed: name")), "{out}");
    assert!(out.contains(&format!("[x] {gone}  Delete order")), "{out}");
    assert!(out.contains("+ POST Create order"), "{out}");
    assert!(out.contains(&format!("plan_sha256: {digest}")), "{out}");
    assert_eq!(names(&data, &ws), before, "a dry run writes nothing");

    // A request the plan does not offer for a decision is refused.
    for args in [["--overwrite", gone.as_str()], ["--delete", mine.as_str()], ["--delete-scope", "variables/nope"]] {
        let o = anvil(&data, &[&["reimport-spec", shop, "--file", file, "--yes"][..], &args[..]].concat());
        assert_eq!(o.status.code(), Some(3), "{args:?}: {}", text(&o));
        assert!(text(&o).contains("the plan does not list that"), "{args:?}: {}", text(&o));
    }
    // A digest of another plan is refused. A dry run with it is refused too
    // (it checks the plan, as `import --dry-run --bundle-sha256` checks a
    // bundle) and says how to see the new plan; with the reviewed one it runs.
    let other = "0".repeat(64);
    let o = anvil(&data, &["reimport-spec", shop, "--file", file, "--dry-run", "--plan-sha256", &other]);
    assert_eq!(o.status.code(), Some(3), "{}", text(&o));
    assert!(text(&o).contains(&format!("its plan_sha256 is {digest}")), "{}", text(&o));
    assert!(text(&o).contains("run the dry run without --plan-sha256 to see the new plan"), "{}", text(&o));
    assert!(!text(&o).contains("run --dry-run again"), "{}", text(&o));
    let o = anvil(&data, &["reimport-spec", shop, "--file", file, "--dry-run", "--plan-sha256", &digest]);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    assert!(text(&o).contains(&format!("plan_sha256: {digest}")), "{}", text(&o));
    let o = anvil(&data, &["reimport-spec", shop, "--file", file, "--plan-sha256", &other]);
    assert_eq!(o.status.code(), Some(3), "{}", text(&o));
    assert!(text(&o).contains("no longer plans what was reviewed"), "{}", text(&o));
    assert_eq!(names(&data, &ws), before);

    // The reviewed plan, deleting the request the source no longer has: the
    // user's rename is kept, the upstream rename applied, the new one added.
    let o = anvil(&data, &["reimport-spec", shop, "--file", file, "--plan-sha256", &digest.to_uppercase(), "--delete", &gone]);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    assert!(text(&o).contains("reimported shop-v2.json into workspace 'Shop 1'"), "{}", text(&o));
    assert!(text(&o).contains("nothing was sent"), "{}", text(&o));
    assert_eq!(names(&data, &ws), ["Create order", "List all orders", "My order"]);
    let rec = open(&data).spec_sources(&ws).unwrap().pop().unwrap();
    assert_eq!(rec.file_name, "shop-v2.json");
    assert_eq!(rec.previous_import_ids, vec![first_import]);

    // The stored import changed: the old review no longer applies.
    let o = anvil(&data, &["reimport-spec", shop, "--file", file, "--plan-sha256", &digest]);
    assert_eq!(o.status.code(), Some(3), "{}", text(&o));
    assert_eq!(names(&data, &ws), ["Create order", "List all orders", "My order"]);

    // The declined rename is offered again by the next version of the file;
    // --yes --overwrite-all takes the source's name. The import's earlier id
    // still names it.
    let v3 = dir.path().join("shop-v3.json");
    std::fs::write(&v3, format!("{V2}\n")).unwrap();
    let file = v3.to_str().unwrap();
    let o =
        anvil(&data, &["reimport-spec", shop, "--file", file, "--import", &first_import.to_string(), "--yes", "--overwrite-all", "--json"]);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    let done: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(done["requests"], serde_json::json!(3), "{done}");
    assert_eq!(done["decisions"]["overwrite"], serde_json::json!([mine]), "{done}");
    assert_eq!(names(&data, &ws), ["Create order", "Fetch order", "List all orders"]);
}

#[test]
fn the_import_to_update_is_named_when_the_workspace_has_several() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let app = create(&data);
    let ws = app.create_workspace("Two").unwrap().meta.id;
    let target = SpecTarget::Workspace { workspace_id: ws };
    let first = app.spec_import(V1.as_bytes(), "a.json", &ImportOptions::default(), target.clone()).unwrap().import_id;
    let second = app.spec_import(V1.as_bytes(), "b.json", &ImportOptions::default(), target).unwrap().import_id;
    drop(app);
    let v2 = dir.path().join("v2.json");
    std::fs::write(&v2, V2).unwrap();
    let file = v2.to_str().unwrap();

    let o = anvil(&data, &["reimport-spec", "Two", "--file", file, "--dry-run"]);
    assert_eq!(o.status.code(), Some(3), "{}", text(&o));
    let out = text(&o);
    assert!(out.contains("has 2 imports; name the one to update with --import"), "{out}");
    assert!(out.contains(&first.to_string()) && out.contains(&second.to_string()), "{out}");

    let o = anvil(&data, &["reimport-spec", "Two", "--file", file, "--dry-run", "--import", &Id::new().to_string()]);
    assert_eq!(o.status.code(), Some(3), "{}", text(&o));
    assert!(text(&o).contains("has no import"), "{}", text(&o));

    let o = anvil(&data, &["reimport-spec", "Two", "--file", file, "--dry-run", "--json", "--import", &second.to_string()]);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    let plan: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(plan["import_id"], serde_json::json!(second.to_string()), "{plan}");

    // A workspace without an import says so.
    let app = open(&data);
    app.create_workspace("Empty").unwrap();
    drop(app);
    let o = anvil(&data, &["reimport-spec", "Empty", "--file", file, "--dry-run"]);
    assert_eq!(o.status.code(), Some(3), "{}", text(&o));
    assert!(text(&o).contains("has no imported spec or collection"), "{}", text(&o));
}
