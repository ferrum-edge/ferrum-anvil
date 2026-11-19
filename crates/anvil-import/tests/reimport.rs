mod common;

use anvil_domain::Id;
use anvil_domain::auth::AuthConfig;
use anvil_domain::request::KeyValue;
use anvil_domain::secret::SensitiveValue;
use anvil_domain::workspace::{RequestDefinition, Variable};
use anvil_import::{
    ImportOptions, ImportResult, ImportedScope, ReimportApproval, ReimportPlan, ScopeChange, ScopeDiff, import, reimport_diff,
    request_unit_hashes,
};
use common::*;
use std::collections::{BTreeMap, BTreeSet};

const V1: &str = r#"
openapi: 3.0.3
info: { title: Orders, version: '1' }
servers: [{ url: https://orders.example.com }]
tags: [{ name: orders }]
paths:
  /orders:
    get:
      tags: [orders]
      operationId: listOrders
      parameters:
        - { name: limit, in: query, required: true, schema: { type: integer, example: 10 } }
      responses: { '200': { description: ok } }
    post:
      tags: [orders]
      operationId: createOrder
      requestBody:
        content:
          application/json:
            schema: { type: object, required: [sku], properties: { sku: { type: string, example: A-1 } } }
      responses: { '201': { description: ok } }
  /orders/{id}:
    get:
      tags: [orders]
      operationId: getOrder
      parameters:
        - { name: id, in: path, required: true, schema: { type: integer, example: 7 } }
      responses: { '200': { description: ok } }
    delete:
      tags: [orders]
      operationId: deleteOrder
      parameters:
        - { name: id, in: path, required: true, schema: { type: integer, example: 7 } }
      responses: { '204': { description: ok } }
"#;

/// What `r` generated, as the app keeps it: the scope's unit hashes and the
/// requests' names, descriptions and tags.
fn baseline(r: &ImportResult) -> BTreeMap<String, String> {
    let mut generated = ImportedScope::generated(r).unit_hashes();
    generated.extend(request_unit_hashes(&r.requests));
    generated
}

/// Diff `previous` against `fresh`, with the scoped configuration as `first`
/// generated it and left untouched.
fn diff(first: &ImportResult, previous: &[RequestDefinition], fresh: &ImportResult) -> ReimportPlan {
    let (current, fresh_scope) = (ImportedScope::generated(first), ImportedScope::generated(fresh));
    let generated = baseline(first);
    reimport_diff(previous, fresh, ScopeDiff { current: &current, generated: Some(&generated), fresh: &fresh_scope })
}

/// v2: listOrders changes (new required param), createOrder changes (new
/// body member), getOrder unchanged, deleteOrder removed, cancelOrder added
/// in a new tag.
fn v2() -> String {
    V1.replace(
        "        - { name: limit, in: query, required: true, schema: { type: integer, example: 10 } }\n",
        "        - { name: limit, in: query, required: true, schema: { type: integer, example: 10 } }\n        - { name: status, in: query, required: true, schema: { type: string, example: open } }\n",
    )
    .replace(
        "schema: { type: object, required: [sku], properties: { sku: { type: string, example: A-1 } } }",
        "schema: { type: object, required: [sku, qty], properties: { sku: { type: string, example: A-1 }, qty: { type: integer, example: 1 } } }",
    )
    .replace(
        "    delete:\n      tags: [orders]\n      operationId: deleteOrder\n      parameters:\n        - { name: id, in: path, required: true, schema: { type: integer, example: 7 } }\n      responses: { '204': { description: ok } }\n",
        "",
    ) + "  /orders/{id}/cancel:\n    post:\n      tags: [admin]\n      operationId: cancelOrder\n      responses: { '200': { description: ok } }\n"
}

#[test]
fn data_012_reimport_preserves_edits_and_never_deletes() {
    let first = import(V1.as_bytes(), &opts()).unwrap();
    let mut previous = first.requests.clone();
    // The user edits createOrder (adds a header).
    let create = previous.iter_mut().find(|q| q.name == "createOrder").unwrap();
    create.spec.headers.push(KeyValue::new("X-Team", "payments"));
    let create_id = create.meta.id;

    // Reimport the newer spec in the same id namespace.
    let o = ImportOptions { id_namespace: Some(first.source.id_namespace), ..opts() };
    let fresh = import(v2().as_bytes(), &o).unwrap();
    assert_ne!(fresh.source.import_id, first.source.import_id);
    let plan = diff(&first, &previous, &fresh);

    let list_id = req(&first, "listOrders").meta.id;
    let get_id = req(&first, "getOrder").meta.id;
    let del_id = req(&first, "deleteOrder").meta.id;
    assert_eq!(plan.updated.len(), 1);
    assert_eq!(plan.updated[0].existing_id, list_id);
    assert_eq!(plan.updated[0].changed_fields, vec!["params".to_string()]);
    assert_eq!(plan.conflicts.len(), 1);
    assert_eq!(plan.conflicts[0].existing_id, create_id);
    assert!(plan.conflicts[0].user_edited);
    assert!(plan.conflicts[0].changed_fields.contains(&"body".to_string()));
    assert!(plan.conflicts[0].changed_fields.contains(&"headers".to_string()));
    assert_eq!(plan.unchanged, vec![get_id]);
    assert_eq!(plan.removed.len(), 1);
    assert_eq!(plan.removed[0].existing_id, del_id);
    assert!(!plan.removed[0].user_edited);
    assert_eq!(plan.added.len(), 1);
    assert_eq!(plan.added[0].name, "cancelOrder");
    assert_eq!(plan.added_folders.len(), 1);
    assert_eq!(plan.added_folders[0].name, "admin");
    // The new folder arrives with its request, not as a change of scope.
    assert!(plan.scope_updated.is_empty() && plan.scope_conflicts.is_empty(), "{:?}", plan.scope_updated);

    // Default apply: safe update applied, edit preserved, nothing deleted.
    let applied = plan.apply(&previous, &ReimportApproval::default());
    assert_eq!(applied.len(), 5);
    let list = applied.iter().find(|q| q.meta.id == list_id).unwrap();
    assert!(list.spec.params.iter().any(|p| p.name == "status"), "safe update applied");
    assert_eq!(list.folder_id, req(&first, "listOrders").folder_id, "placement kept");
    let create = applied.iter().find(|q| q.meta.id == create_id).unwrap();
    assert!(create.spec.headers.iter().any(|h| h.name == "X-Team"), "user edit preserved");
    assert!(applied.iter().any(|q| q.meta.id == del_id), "removed operation kept");
    let added = applied.iter().find(|q| q.name == "cancelOrder").unwrap();
    assert_eq!(added.workspace_id, first.workspace.meta.id);
    // Same namespace → unchanged folders keep their ids.
    assert_eq!(fresh.folders.iter().find(|f| f.name == "orders").unwrap().meta.id, first.folders[0].meta.id);

    // Explicit approval overwrites the conflict and deletes the removed op.
    let approval = ReimportApproval { overwrite: vec![create_id], delete: vec![del_id], ..Default::default() };
    let applied = plan.apply(&previous, &approval);
    assert_eq!(applied.len(), 4);
    let create = applied.iter().find(|q| q.meta.id == create_id).unwrap();
    assert!(!create.spec.headers.iter().any(|h| h.name == "X-Team"));
    assert!(json_body(&create.spec).get("qty").is_some());
    assert!(!applied.iter().any(|q| q.meta.id == del_id));
}

#[test]
fn user_edit_without_upstream_change_is_preserved() {
    let first = import(V1.as_bytes(), &opts()).unwrap();
    let mut previous = first.requests.clone();
    previous[0].spec.url.push_str("?debug=1");
    let again = import(V1.as_bytes(), &ImportOptions { id_namespace: Some(first.source.id_namespace), ..opts() }).unwrap();
    let plan = diff(&first, &previous, &again);
    assert_eq!(plan.preserved_edits, vec![previous[0].meta.id]);
    assert_eq!(plan.unchanged.len(), 3);
    assert!(plan.updated.is_empty() && plan.conflicts.is_empty() && plan.added.is_empty() && plan.removed.is_empty());
    assert_eq!(plan.apply(&previous, &ReimportApproval::default()), previous);
}

#[test]
fn unlinked_requests_are_untouched() {
    let first = import(V1.as_bytes(), &opts()).unwrap();
    let mut previous = first.requests.clone();
    previous[1].spec.source = None;
    let plan = diff(&first, &previous, &first);
    assert_eq!(plan.unlinked, vec![previous[1].meta.id]);
    // The op that lost its link reappears as added (never merged silently).
    assert_eq!(plan.added.len(), 1);
}

#[test]
fn an_updated_request_drops_the_revision_of_its_old_spec() {
    let first = import(V1.as_bytes(), &opts()).unwrap();
    let mut previous = first.requests.clone();
    let revisions: Vec<Id> = previous.iter_mut().map(|q| *q.revision_id.insert(Id::new())).collect();
    let o = ImportOptions { id_namespace: Some(first.source.id_namespace), ..opts() };
    let fresh = import(v2().as_bytes(), &o).unwrap();
    let plan = diff(&first, &previous, &fresh);
    let applied = plan.apply(&previous, &ReimportApproval::default());
    for (q, revision) in previous.iter().zip(&revisions) {
        let after = applied.iter().find(|a| a.meta.id == q.meta.id).unwrap();
        if after.spec == q.spec {
            assert_eq!(after.revision_id, Some(*revision), "{}: unchanged, so its revision still describes it", q.name);
        } else {
            assert_eq!(after.revision_id, None, "{}: the old revision no longer describes it", q.name);
        }
    }
    let list_id = req(&first, "listOrders").meta.id;
    assert_eq!(applied.iter().find(|a| a.meta.id == list_id).unwrap().revision_id, None);
}

// ---------------------------------------------------------------- scope

const SERVER_V1: &str = r#"{"openapi":"3.0.3","info":{"title":"Audit","version":"1"},"servers":[{"url":"https://old.example.test"}],"paths":{"/health":{"get":{"operationId":"health","responses":{"200":{"description":"ok"}}}}}}"#;

fn server(url: &str) -> String {
    SERVER_V1.replace("https://old.example.test", url)
}

fn reimport(first: &ImportResult, bytes: &str) -> ImportResult {
    import(bytes.as_bytes(), &ImportOptions { id_namespace: Some(first.source.id_namespace), ..opts() }).unwrap()
}

fn base_url(scope: &ImportedScope, environment: Id) -> SensitiveValue {
    let e = scope.environments.iter().find(|e| e.meta.id == environment).expect("the environment");
    e.variables.iter().find(|v| v.name == "baseUrl").expect("a baseUrl").value.clone()
}

#[test]
fn a_changed_server_is_an_update_although_no_request_changed() {
    let first = import(SERVER_V1.as_bytes(), &opts()).unwrap();
    let fresh = reimport(&first, &server("https://new.example.test"));
    let plan = diff(&first, &first.requests, &fresh);
    // The request only says `{{baseUrl}}/health`.
    assert_eq!(plan.unchanged, vec![first.requests[0].meta.id]);
    let env = first.environments[0].meta.id;
    let key = format!("environments/{env}/variables/baseUrl");
    let change = plan.scope_updated.iter().find(|c| c.key == key).unwrap_or_else(|| panic!("{:?}", plan.scope_updated));
    assert!(!change.user_edited);
    assert_eq!(change.fresh.as_ref().unwrap()["value"]["value"], "https://new.example.test");
    assert!(change.label.contains("baseUrl"), "{}", change.label);
    assert!(plan.scope_conflicts.is_empty() && plan.scope_removed.is_empty() && plan.scope_preserved_edits.is_empty());

    let current = ImportedScope::generated(&first);
    let applied = plan.apply_scope(&current, &ImportedScope::generated(&fresh), &ReimportApproval::default());
    assert_eq!(base_url(&applied, env), SensitiveValue::template("https://new.example.test"));
    assert_eq!(applied.environments.len(), 1, "the same environment, updated");
    assert_eq!(applied.environments[0].name, "https://new.example.test");

    // The same source again changes nothing.
    let again = reimport(&first, &server("https://old.example.test"));
    let plan = diff(&first, &first.requests, &again);
    assert!(plan.scope_updated.is_empty() && plan.scope_conflicts.is_empty() && plan.scope_removed.is_empty());
}

#[test]
fn a_server_the_user_changed_is_a_conflict_kept_unless_approved() {
    let first = import(SERVER_V1.as_bytes(), &opts()).unwrap();
    let generated = ImportedScope::generated(&first).unit_hashes();
    let env = first.environments[0].meta.id;
    let mut current = ImportedScope::generated(&first);
    let variables = &mut current.environments[0].variables;
    variables.iter_mut().find(|v| v.name == "baseUrl").unwrap().value = SensitiveValue::template("http://localhost:8080");
    variables.push(Variable::plain("token", "mine"));
    let fresh_result = reimport(&first, &server("https://new.example.test"));
    let fresh = ImportedScope::generated(&fresh_result);
    let scope = ScopeDiff { current: &current, generated: Some(&generated), fresh: &fresh };
    let plan = reimport_diff(&first.requests, &fresh_result, scope);

    let key = format!("environments/{env}/variables/baseUrl");
    assert_eq!(plan.scope_conflicts.len(), 1, "{:?}", plan.scope_conflicts);
    assert_eq!(plan.scope_conflicts[0].key, key);
    assert!(plan.scope_conflicts[0].user_edited);
    assert_eq!(plan.scope_preserved_edits, vec![format!("environments/{env}/variables/token")], "a variable of the user's own");
    assert!(plan.scope_removed.is_empty());

    // Declined: the user's server and variable stay, and the conflict is
    // offered again next time.
    let kept = plan.apply_scope(&current, &fresh, &ReimportApproval::default());
    assert_eq!(base_url(&kept, env), SensitiveValue::template("http://localhost:8080"));
    assert!(kept.environments[0].variables.iter().any(|v| v.name == "token"));
    let next = plan.next_generated_scope(&fresh, &fresh_result.requests, Some(&generated), &ReimportApproval::default());
    let again = reimport_diff(&first.requests, &fresh_result, ScopeDiff { current: &kept, generated: Some(&next), fresh: &fresh });
    assert_eq!(again.scope_conflicts.iter().map(|c| c.key.as_str()).collect::<Vec<_>>(), vec![key.as_str()]);

    // Approved: the fresh server replaces it; the user's own variable stays.
    let approval = ReimportApproval { overwrite_scope: vec![key.clone()], ..Default::default() };
    let applied = plan.apply_scope(&current, &fresh, &approval);
    assert_eq!(base_url(&applied, env), SensitiveValue::template("https://new.example.test"));
    assert!(applied.environments[0].variables.iter().any(|v| v.name == "token"));
    let next = plan.next_generated_scope(&fresh, &fresh_result.requests, Some(&generated), &approval);
    let again = reimport_diff(&first.requests, &fresh_result, ScopeDiff { current: &applied, generated: Some(&next), fresh: &fresh });
    assert!(again.scope_conflicts.is_empty() && again.scope_updated.is_empty());
}

#[test]
fn without_a_record_of_what_was_generated_every_difference_needs_approval() {
    let first = import(SERVER_V1.as_bytes(), &opts()).unwrap();
    let current = ImportedScope::generated(&first);
    let fresh_result = reimport(&first, &server("https://new.example.test"));
    let fresh = ImportedScope::generated(&fresh_result);
    let plan = reimport_diff(&first.requests, &fresh_result, ScopeDiff { current: &current, generated: None, fresh: &fresh });
    assert!(plan.scope_updated.is_empty());
    assert!(plan.scope_conflicts.iter().any(|c| c.key.ends_with("/variables/baseUrl") && c.user_edited));
    assert_eq!(plan.apply_scope(&current, &fresh, &ReimportApproval::default()), current);
}

#[test]
fn a_new_server_arrives_whole_and_a_removed_one_goes_only_when_approved() {
    let one = import(SERVER_V1.as_bytes(), &opts()).unwrap();
    let two_servers = SERVER_V1.replace(
        r#"[{"url":"https://old.example.test"}]"#,
        r#"[{"url":"https://old.example.test"},{"url":"https://staging.example.test","description":"Staging"}]"#,
    );
    let two = reimport(&one, &two_servers);
    assert_eq!(two.environments.len(), 2);
    let staging = two.environments[1].meta.id;
    let key = format!("environments/{staging}");

    // Added upstream: one update carrying the whole environment.
    let plan = diff(&one, &one.requests, &two);
    assert_eq!(plan.scope_updated.iter().map(|c| c.key.as_str()).collect::<Vec<_>>(), vec![key.as_str()]);
    assert_eq!(plan.scope_updated[0].fresh.as_ref().unwrap()["name"], "Staging");
    let applied = plan.apply_scope(&ImportedScope::generated(&one), &ImportedScope::generated(&two), &ReimportApproval::default());
    assert_eq!(applied.environments.len(), 2);
    assert_eq!(base_url(&applied, staging), SensitiveValue::template("https://staging.example.test"));

    // Removed upstream: listed, kept unless approved.
    let back = reimport(&one, SERVER_V1);
    let plan = diff(&two, &two.requests, &back);
    assert_eq!(plan.scope_removed.iter().map(|c| c.key.as_str()).collect::<Vec<_>>(), vec![key.as_str()]);
    assert!(!plan.scope_removed[0].user_edited && plan.scope_removed[0].fresh.is_none());
    let (current, fresh) = (ImportedScope::generated(&two), ImportedScope::generated(&back));
    assert_eq!(plan.apply_scope(&current, &fresh, &ReimportApproval::default()).environments.len(), 2);
    let approval = ReimportApproval { delete_scope: vec![key.clone()], ..Default::default() };
    let applied = plan.apply_scope(&current, &fresh, &approval);
    assert_eq!(applied.environments.iter().map(|e| e.meta.id).collect::<Vec<_>>(), vec![one.environments[0].meta.id]);
}

#[test]
fn source_level_variables_auth_and_description_are_compared_too() {
    let v1 = r#"{
      "info": { "name": "Echo", "description": "first", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json" },
      "auth": { "type": "noauth" },
      "variable": [{ "key": "base", "value": "https://api.example.invalid" }],
      "item": [{ "name": "Health", "request": { "method": "GET", "url": { "raw": "{{base}}/health" } } }]
    }"#;
    let first = import(v1.as_bytes(), &opts()).unwrap();
    let v2 = v1.replace("https://api.example.invalid", "https://api2.example.invalid").replace("first", "second");
    let fresh = reimport(&first, &v2);
    let plan = diff(&first, &first.requests, &fresh);
    assert_eq!(plan.unchanged.len(), 1, "the request only says `{{{{base}}}}/health`");
    let keys: Vec<&str> = plan.scope_updated.iter().map(|c| c.key.as_str()).collect();
    assert!(keys.contains(&"variables/base"), "{keys:?}");
    assert!(keys.contains(&"description"), "{keys:?}");
    let applied = plan.apply_scope(&ImportedScope::generated(&first), &ImportedScope::generated(&fresh), &ReimportApproval::default());
    let base = applied.variables.iter().find(|v| v.name == "base").unwrap();
    assert_eq!(base.value, SensitiveValue::template("https://api2.example.invalid"));
    assert_eq!(applied, ImportedScope::generated(&fresh));
}

fn keys(changes: &[ScopeChange]) -> Vec<&str> {
    changes.iter().map(|c| c.key.as_str()).collect()
}

/// [`server`] with a server description, so the environment keeps its name
/// ("Production") when the URL changes.
fn named_server(url: &str) -> String {
    server(url).replace(r#"[{"url":"#, r#"[{"description":"Production","url":"#)
}

#[test]
fn an_environment_the_user_deleted_is_a_conflict_when_its_server_changed_upstream() {
    let first = import(named_server("https://old.example.test").as_bytes(), &opts()).unwrap();
    assert_eq!(first.environments[0].name, "Production");
    let generated = ImportedScope::generated(&first).unit_hashes();
    let env = first.environments[0].meta.id;
    let key = format!("environments/{env}");
    let mut current = ImportedScope::generated(&first);
    current.environments.clear();

    // Unchanged upstream, the deletion is the user's to keep.
    let same = reimport(&first, &named_server("https://old.example.test"));
    let fresh = ImportedScope::generated(&same);
    let plan = reimport_diff(&first.requests, &same, ScopeDiff { current: &current, generated: Some(&generated), fresh: &fresh });
    assert_eq!(plan.scope_preserved_edits, vec![key.clone()]);
    assert!(plan.scope_conflicts.is_empty() && plan.scope_updated.is_empty());

    // Its server changed upstream, under the same name: a conflict on the
    // whole environment, not a kept edit.
    let fresh_result = reimport(&first, &named_server("https://new.example.test"));
    let fresh = ImportedScope::generated(&fresh_result);
    let plan = reimport_diff(&first.requests, &fresh_result, ScopeDiff { current: &current, generated: Some(&generated), fresh: &fresh });
    assert!(plan.scope_preserved_edits.is_empty(), "{:?}", plan.scope_preserved_edits);
    assert_eq!(keys(&plan.scope_conflicts), vec![key.as_str()]);
    assert!(plan.scope_conflicts[0].user_edited && plan.scope_conflicts[0].whole_environment);
    assert!(plan.scope_updated.is_empty() && plan.scope_removed.is_empty());

    // Declined: still deleted, and offered again next time.
    assert!(plan.apply_scope(&current, &fresh, &ReimportApproval::default()).environments.is_empty());
    let next = plan.next_generated_scope(&fresh, &fresh_result.requests, Some(&generated), &ReimportApproval::default());
    let again = reimport_diff(&first.requests, &fresh_result, ScopeDiff { current: &current, generated: Some(&next), fresh: &fresh });
    assert_eq!(keys(&again.scope_conflicts), vec![key.as_str()]);

    // Approved: it comes back with the new server.
    let approval = ReimportApproval { overwrite_scope: vec![key], ..Default::default() };
    let applied = plan.apply_scope(&current, &fresh, &approval);
    assert_eq!(base_url(&applied, env), SensitiveValue::template("https://new.example.test"));
}

#[test]
fn an_environment_removed_upstream_is_user_edited_when_its_variables_were() {
    let two_servers = SERVER_V1.replace(
        r#"[{"url":"https://old.example.test"}]"#,
        r#"[{"url":"https://old.example.test"},{"url":"https://staging.example.test","description":"Staging"}]"#,
    );
    let two = import(two_servers.as_bytes(), &opts()).unwrap();
    let staging = two.environments[1].meta.id;
    let key = format!("environments/{staging}");
    let generated = ImportedScope::generated(&two).unit_hashes();
    let back = reimport(&two, SERVER_V1);
    let fresh = ImportedScope::generated(&back);

    let untouched = ImportedScope::generated(&two);
    let plan = reimport_diff(&two.requests, &back, ScopeDiff { current: &untouched, generated: Some(&generated), fresh: &fresh });
    assert_eq!(keys(&plan.scope_removed), vec![key.as_str()]);
    assert!(!plan.scope_removed[0].user_edited);

    let mut edited = ImportedScope::generated(&two);
    let variables = &mut edited.environments[1].variables;
    variables.iter_mut().find(|v| v.name == "baseUrl").unwrap().value = SensitiveValue::template("http://localhost:8080");
    let plan = reimport_diff(&two.requests, &back, ScopeDiff { current: &edited, generated: Some(&generated), fresh: &fresh });
    assert_eq!(keys(&plan.scope_removed), vec![key.as_str()]);
    assert!(plan.scope_removed[0].user_edited, "the user changed its baseUrl");
    assert!(plan.scope_removed[0].whole_environment);

    // Declined: kept as the user left it, and offered again next time.
    let kept = plan.apply_scope(&edited, &fresh, &ReimportApproval::default());
    assert_eq!(base_url(&kept, staging), SensitiveValue::template("http://localhost:8080"));
    let next = plan.next_generated_scope(&fresh, &back.requests, Some(&generated), &ReimportApproval::default());
    let again = reimport_diff(&two.requests, &back, ScopeDiff { current: &kept, generated: Some(&next), fresh: &fresh });
    assert_eq!(keys(&again.scope_removed), vec![key.as_str()]);
    assert!(again.scope_removed[0].user_edited);
}

#[test]
fn a_declined_removal_with_no_record_of_what_was_generated_is_kept_as_the_users_own() {
    let first = import(SERVER_V1.as_bytes(), &opts()).unwrap();
    let key = format!("environments/{}/variables/token", first.environments[0].meta.id);
    let mut current = ImportedScope::generated(&first);
    current.environments[0].variables.push(Variable::plain("token", "mine"));
    let again = reimport(&first, SERVER_V1);
    let fresh = ImportedScope::generated(&again);

    // Not knowing what was generated, it may be the source's own: listed.
    let plan = reimport_diff(&first.requests, &again, ScopeDiff { current: &current, generated: None, fresh: &fresh });
    assert_eq!(keys(&plan.scope_removed), vec![key.as_str()]);
    let next = plan.next_generated_scope(&fresh, &again.requests, None, &ReimportApproval::default());
    assert!(!next.contains_key(&key), "{next:?}");

    // Declined, it is the user's own from then on.
    let plan = reimport_diff(&first.requests, &again, ScopeDiff { current: &current, generated: Some(&next), fresh: &fresh });
    assert!(plan.scope_removed.is_empty(), "{:?}", plan.scope_removed);
    assert_eq!(plan.scope_preserved_edits, vec![key]);
}

// ---------------------------------------------------------------- folders

/// A Postman folder with its own description, variables and (in newer
/// versions) auth.
const ADMIN_V1: &str = r#"{
  "info": { "name": "Admin API", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json" },
  "variable": [{ "key": "base", "value": "https://api.example.invalid" }],
  "item": [
    { "name": "Admin", "description": "first", "variable": [{ "key": "scope", "value": "read" }], "item": [
      { "name": "Users", "request": { "method": "GET", "url": { "raw": "{{base}}/users/{{scope}}" } } }
    ] }
  ]
}"#;

/// The folder in [`admin_v2`]: renamed, described again and given an API key.
const ADMIN_V2_FOLDER: &str = r#""name": "Administration", "description": "second", "auth": {
      "type": "apikey", "apikey": [{ "key": "key", "value": "X-Admin" }, { "key": "value", "value": "{{admin}}" }] },"#;

/// [`ADMIN_V1`] with [`ADMIN_V2_FOLDER`] and `scope` set to `scope`.
fn admin_v2(scope: &str) -> String {
    let scope = format!(r#""value": "{scope}""#);
    ADMIN_V1.replace(r#""value": "read""#, &scope).replace(r#""name": "Admin", "description": "first","#, ADMIN_V2_FOLDER)
}

#[test]
fn a_postman_folders_own_settings_changed_upstream_are_applied() {
    let first = import(ADMIN_V1.as_bytes(), &opts()).unwrap();
    let folder = first.folders[0].meta.id;
    let fresh = reimport(&first, &admin_v2("write"));
    assert_eq!(fresh.folders[0].meta.id, folder, "the same folder");
    let plan = diff(&first, &first.requests, &fresh);
    assert_eq!(plan.unchanged, vec![first.requests[0].meta.id], "the request only says `{{{{scope}}}}`");
    let at = format!("folders/{folder}");
    let expected = [at.clone(), format!("{at}/description"), format!("{at}/auth"), format!("{at}/variables/scope")];
    let mut got = keys(&plan.scope_updated);
    got.sort();
    let mut want: Vec<&str> = expected.iter().map(String::as_str).collect();
    want.sort();
    assert_eq!(got, want);
    assert!(plan.scope_updated.iter().all(|c| !c.user_edited && c.label.starts_with("folder \"Administration\"")), "{plan:?}");
    assert!(plan.scope_conflicts.is_empty() && plan.scope_removed.is_empty() && plan.scope_preserved_edits.is_empty());

    let current = ImportedScope::generated(&first);
    let applied = plan.apply_scope(&current, &ImportedScope::generated(&fresh), &ReimportApproval::default());
    assert_eq!(applied.folders, fresh.folders, "the folder now has the source's name, description, auth and variables");
    assert!(matches!(&applied.folders[0].auth, AuthConfig::ApiKey { name, .. } if name == "X-Admin"), "{:?}", applied.folders[0].auth);

    // The same source again changes nothing.
    let plan = diff(&first, &first.requests, &reimport(&first, ADMIN_V1));
    assert!(plan.scope_updated.is_empty() && plan.scope_conflicts.is_empty() && plan.scope_removed.is_empty());
}

#[test]
fn a_postman_folder_setting_the_user_changed_is_a_conflict_kept_unless_approved() {
    let first = import(ADMIN_V1.as_bytes(), &opts()).unwrap();
    let generated = baseline(&first);
    let key = format!("folders/{}/variables/scope", first.folders[0].meta.id);
    let mut current = ImportedScope::generated(&first);
    current.folders[0].variables[0].value = SensitiveValue::template("mine");
    let fresh_result = reimport(&first, &admin_v2("write"));
    let fresh = ImportedScope::generated(&fresh_result);
    let plan = reimport_diff(&first.requests, &fresh_result, ScopeDiff { current: &current, generated: Some(&generated), fresh: &fresh });
    assert_eq!(keys(&plan.scope_conflicts), vec![key.as_str()]);
    assert!(plan.scope_conflicts[0].user_edited);
    assert!(plan.scope_conflicts[0].label.ends_with("variable scope"), "{}", plan.scope_conflicts[0].label);
    assert_eq!(plan.scope_updated.len(), 3, "its name, description and auth are the source's to change: {:?}", plan.scope_updated);

    // Declined: the user's value stays, the rest is applied, and the
    // conflict is offered again next time.
    let kept = plan.apply_scope(&current, &fresh, &ReimportApproval::default());
    assert_eq!(kept.folders[0].variables[0].value, SensitiveValue::template("mine"));
    assert_eq!(kept.folders[0].name, "Administration");
    let next = plan.next_generated_scope(&fresh, &fresh_result.requests, Some(&generated), &ReimportApproval::default());
    let again = reimport_diff(&first.requests, &fresh_result, ScopeDiff { current: &kept, generated: Some(&next), fresh: &fresh });
    assert_eq!(keys(&again.scope_conflicts), vec![key.as_str()]);
    assert!(again.scope_updated.is_empty(), "{:?}", again.scope_updated);

    // Approved: the source's value replaces it.
    let approval = ReimportApproval { overwrite_scope: vec![key], ..Default::default() };
    let applied = plan.apply_scope(&current, &fresh, &approval);
    assert_eq!(applied.folders, fresh.folders);

    // Unchanged upstream, the user's value is a kept edit.
    let same = reimport(&first, ADMIN_V1);
    let same_scope = ImportedScope::generated(&same);
    let plan = reimport_diff(&first.requests, &same, ScopeDiff { current: &current, generated: Some(&generated), fresh: &same_scope });
    assert_eq!(plan.scope_preserved_edits.len(), 1);
    assert!(plan.scope_conflicts.is_empty() && plan.scope_updated.is_empty());
}

#[test]
fn an_openapi_tag_description_is_its_folders_and_is_compared() {
    let first = import(V1.as_bytes(), &opts()).unwrap();
    let orders = first.folders.iter().find(|f| f.name == "orders").unwrap().meta.id;
    let described = V1.replace("tags: [{ name: orders }]", "tags: [{ name: orders, description: Order operations }]");
    let fresh = reimport(&first, &described);
    let key = format!("folders/{orders}/description");
    let plan = diff(&first, &first.requests, &fresh);
    assert_eq!(keys(&plan.scope_updated), vec![key.as_str()]);
    assert_eq!(plan.scope_updated[0].label, "folder \"orders\": description");
    let applied = plan.apply_scope(&ImportedScope::generated(&first), &ImportedScope::generated(&fresh), &ReimportApproval::default());
    assert_eq!(applied.folders.iter().find(|f| f.meta.id == orders).unwrap().description, "Order operations");

    // One the user described differently is a conflict.
    let generated = baseline(&first);
    let mut current = ImportedScope::generated(&first);
    current.folders[0].description = "Mine".into();
    let fresh_scope = ImportedScope::generated(&fresh);
    let plan = reimport_diff(&first.requests, &fresh, ScopeDiff { current: &current, generated: Some(&generated), fresh: &fresh_scope });
    assert_eq!(keys(&plan.scope_conflicts), vec![key.as_str()]);
    assert_eq!(plan.apply_scope(&current, &fresh_scope, &ReimportApproval::default()).folders[0].description, "Mine");

    // A folder the user deleted is not brought back as a change of scope.
    current.folders.clear();
    let plan = reimport_diff(&first.requests, &fresh, ScopeDiff { current: &current, generated: Some(&generated), fresh: &fresh_scope });
    assert!(plan.scope_updated.is_empty() && plan.scope_conflicts.is_empty() && plan.scope_removed.is_empty(), "{plan:?}");
}

// ---------------------------------------------------------------- renames

fn named(requests: &[RequestDefinition], id: Id) -> &RequestDefinition {
    requests.iter().find(|q| q.meta.id == id).expect("the request")
}

#[test]
fn an_openapi_request_the_user_renamed_keeps_its_name_unless_the_user_approves_the_sources() {
    let first = import(V1.as_bytes(), &opts()).unwrap();
    let list = req(&first, "listOrders").meta.id;
    let mut previous = first.requests.clone();
    previous.iter_mut().find(|q| q.meta.id == list).unwrap().name = "My orders".into();

    // Only its spec changed upstream: the spec is updated, the name kept.
    let fresh = reimport(&first, &v2());
    let plan = diff(&first, &previous, &fresh);
    let change = plan.updated.iter().find(|c| c.existing_id == list).expect("a safe update");
    assert_eq!(change.upstream_fields, vec!["spec".to_string()]);
    assert!(change.changed_fields.contains(&"params".to_string()) && change.changed_fields.contains(&"name".to_string()));
    let applied = plan.apply(&previous, &ReimportApproval::default());
    let after = named(&applied, list);
    assert_eq!(after.name, "My orders", "the user's name is kept");
    assert!(after.spec.params.iter().any(|p| p.name == "status"), "the spec is updated");

    // Unchanged upstream, the rename is a kept edit.
    let plan = diff(&first, &previous, &reimport(&first, V1));
    assert_eq!(plan.preserved_edits, vec![list]);

    // Renamed upstream too: a conflict, kept until approved.
    let summarized = V1.replace("      operationId: listOrders\n", "      operationId: listOrders\n      summary: List orders\n");
    let fresh = reimport(&first, &summarized);
    assert_eq!(req(&fresh, "listOrders").name, "List orders");
    let generated = baseline(&first);
    let plan = diff(&first, &previous, &fresh);
    assert_eq!(plan.conflicts.len(), 1, "{plan:?}");
    assert_eq!((plan.conflicts[0].existing_id, plan.conflicts[0].user_edited), (list, true));
    assert_eq!(plan.conflicts[0].upstream_fields, vec!["name".to_string()]);
    let kept = plan.apply(&previous, &ReimportApproval::default());
    assert_eq!(named(&kept, list).name, "My orders");
    let fresh_scope = ImportedScope::generated(&fresh);
    let next = plan.next_generated_scope(&fresh_scope, &fresh.requests, Some(&generated), &ReimportApproval::default());
    let current = ImportedScope::generated(&first);
    let again = reimport_diff(&kept, &fresh, ScopeDiff { current: &current, generated: Some(&next), fresh: &fresh_scope });
    assert_eq!(again.conflicts.iter().map(|c| c.existing_id).collect::<Vec<_>>(), vec![list], "declined, it is offered again");
    let approval = ReimportApproval { overwrite: vec![list], ..Default::default() };
    let applied = plan.apply(&previous, &approval);
    assert_eq!(named(&applied, list).name, "List orders");
    assert_eq!(named(&applied, list).spec, named(&previous, list).spec, "only the name changed upstream");

    // Not renamed by the user, the source's new name is a safe update.
    let plan = diff(&first, &first.requests, &fresh);
    assert_eq!(plan.updated.len(), 1);
    assert_eq!(plan.updated[0].upstream_fields, vec!["name".to_string()]);
    assert_eq!(named(&plan.apply(&first.requests, &ReimportApproval::default()), list).name, "List orders");
}

const HEALTH_V1: &str = r#"{
  "info": { "name": "Echo", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json" },
  "item": [{ "name": "Health", "request": { "method": "GET", "url": { "raw": "https://api.example.invalid/health" } } }]
}"#;

#[test]
fn a_postman_request_the_user_renamed_keeps_its_name_unless_the_user_approves_the_sources() {
    let first = import(HEALTH_V1.as_bytes(), &opts()).unwrap();
    let health = first.requests[0].meta.id;
    let mut previous = first.requests.clone();
    previous[0].name = "Ping".into();

    // Its URL changed upstream: updated, still called "Ping".
    let moved = reimport(&first, &HEALTH_V1.replace("/health", "/healthz"));
    let plan = diff(&first, &previous, &moved);
    assert_eq!(plan.updated.iter().map(|c| c.existing_id).collect::<Vec<_>>(), vec![health]);
    let applied = plan.apply(&previous, &ReimportApproval::default());
    assert_eq!(applied[0].name, "Ping");
    assert!(applied[0].spec.url.ends_with("/healthz"), "{}", applied[0].spec.url);

    // Renamed upstream as well: a conflict on the name.
    let renamed = reimport(&first, &HEALTH_V1.replace(r#""name": "Health""#, r#""name": "Health check""#));
    let plan = diff(&first, &previous, &renamed);
    assert_eq!(plan.conflicts.iter().map(|c| c.existing_id).collect::<Vec<_>>(), vec![health]);
    assert_eq!(plan.apply(&previous, &ReimportApproval::default())[0].name, "Ping");
    let approval = ReimportApproval { overwrite: vec![health], ..Default::default() };
    assert_eq!(plan.apply(&previous, &approval)[0].name, "Health check");

    // Not knowing what was generated, a different name needs approval.
    let current = ImportedScope::generated(&first);
    let fresh = ImportedScope::generated(&moved);
    let plan = reimport_diff(&previous, &moved, ScopeDiff { current: &current, generated: None, fresh: &fresh });
    assert_eq!(plan.conflicts.iter().map(|c| c.existing_id).collect::<Vec<_>>(), vec![health]);
    assert!(plan.updated.is_empty());
}

#[test]
fn a_declined_conflict_still_takes_the_parts_the_user_did_not_edit() {
    let first = import(HEALTH_V1.as_bytes(), &opts()).unwrap();
    let health = first.requests[0].meta.id;
    let mut previous = first.requests.clone();
    previous[0].name = "Ping".into();

    // Moved and renamed upstream: only the name conflicts.
    let v2 = HEALTH_V1.replace("/health", "/healthz").replace(r#""name": "Health""#, r#""name": "Health check""#);
    let fresh = reimport(&first, &v2);
    let plan = diff(&first, &previous, &fresh);
    assert_eq!(plan.conflicts.iter().map(|c| c.existing_id).collect::<Vec<_>>(), vec![health], "{plan:?}");
    assert_eq!(plan.conflicts[0].upstream_fields, vec!["spec".to_string(), "name".to_string()]);
    assert_eq!(plan.conflicts[0].conflicting_fields, vec!["name".to_string()]);
    let kept = plan.apply(&previous, &ReimportApproval::default());
    assert_eq!(named(&kept, health).name, "Ping", "declined: the user's name is kept");
    assert_eq!(named(&kept, health).spec, fresh.requests[0].spec, "the spec the user did not edit is updated");
    assert_eq!(named(&kept, health).revision_id, None);

    // Only the name is offered again.
    let generated = baseline(&first);
    let fresh_scope = ImportedScope::generated(&fresh);
    let next = plan.next_generated_scope(&fresh_scope, &fresh.requests, Some(&generated), &ReimportApproval::default());
    let current = ImportedScope::generated(&first);
    let again = reimport_diff(&kept, &fresh, ScopeDiff { current: &current, generated: Some(&next), fresh: &fresh_scope });
    assert_eq!(again.conflicts.iter().map(|c| c.existing_id).collect::<Vec<_>>(), vec![health], "{again:?}");
    assert_eq!(again.conflicts[0].upstream_fields, vec!["name".to_string()]);
    assert!(again.updated.is_empty(), "{again:?}");

    // The user's spec edit conflicts instead: the source's new name arrives.
    let mut edited = first.requests.clone();
    edited[0].spec.headers.push(KeyValue::new("X-Mine", "1"));
    let plan = diff(&first, &edited, &fresh);
    assert_eq!(plan.conflicts.iter().map(|c| c.existing_id).collect::<Vec<_>>(), vec![health], "{plan:?}");
    assert_eq!(plan.conflicts[0].conflicting_fields, vec!["spec".to_string()]);
    let kept = plan.apply(&edited, &ReimportApproval::default());
    assert_eq!(named(&kept, health).name, "Health check", "the source's rename is applied");
    assert_eq!(named(&kept, health).spec, edited[0].spec, "the user's spec is kept");
    let approval = ReimportApproval { overwrite: vec![health], ..Default::default() };
    assert_eq!(named(&plan.apply(&edited, &approval), health).spec, fresh.requests[0].spec);
}

// ------------------------------------------------------- auth placeholders

/// The placeholder an auth config's secret `field` refers to, as stored.
fn auth_reference(r: &RequestDefinition, field: &str) -> String {
    serde_json::to_value(&r.spec.auth).unwrap()[field]["value"].as_str().unwrap_or_default().to_string()
}

/// Review of #586 (sol F1): an auth config's placeholders are bound to the
/// literal they replaced, not to the order the source lists items in, so
/// reordering the source keeps every request on the variable the user filled
/// for it, and never hands one host another's secret.
#[test]
fn reordering_items_keeps_each_auth_config_on_its_own_variables() {
    let postman_item = |id: &str| {
        serde_json::json!({ "id": id, "name": id, "request": { "method": "GET", "url": format!("https://{id}.example.invalid/v1"),
            "auth": { "type": "bearer", "bearer": [{ "key": "token", "value": format!("tok-SENSITIVE-{id}") }] } } })
    };
    let postman = |items: [&str; 2]| {
        serde_json::json!({
            "info": { "name": "Two", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json" },
            "item": items.map(postman_item)
        })
        .to_string()
    };
    let insomnia_request = |id: &str, sort: f64| {
        serde_json::json!({ "_id": id, "_type": "request", "parentId": "wrk_1", "name": id, "method": "GET", "metaSortKey": sort,
            "url": format!("https://{id}.example.invalid/v1"),
            "authentication": { "type": "basic", "username": "u", "password": format!("tok-SENSITIVE-{id}") } })
    };
    let insomnia = |a: f64, b: f64| {
        serde_json::json!({ "_type": "export", "__export_format": 4, "resources": [
            { "_id": "wrk_1", "_type": "workspace", "parentId": null, "name": "W", "scope": "collection" },
            insomnia_request("req_a", a), insomnia_request("req_b", b)
        ] })
        .to_string()
    };
    // Review of #586, round 2: these two ids collided under the 32-bit digest
    // (sol F2); URL userinfo is literal-bound too (dsf F1).
    let userinfo_item = |id: &str| {
        serde_json::json!({ "id": id, "name": id, "request": { "method": "GET",
            "url": format!("https://user-{id}:tok-SENSITIVE-{id}@{id}.example.invalid/v1") } })
    };
    let userinfo = |items: [&str; 2]| {
        serde_json::json!({
            "info": { "name": "Two", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json" },
            "item": items.map(userinfo_item)
        })
        .to_string()
    };
    let cases = [
        ("Postman", postman(["req-a", "req-b"]), postman(["req-b", "req-a"]), ["postman:req-a", "postman:req-b"], "token"),
        (
            "Postman, ids that collided",
            postman(["req-137081", "req-723190"]),
            postman(["req-723190", "req-137081"]),
            ["postman:req-137081", "postman:req-723190"],
            "token",
        ),
        ("Postman, URL userinfo", userinfo(["ui-a", "ui-b"]), userinfo(["ui-b", "ui-a"]), ["postman:ui-a", "postman:ui-b"], "password"),
        ("Insomnia", insomnia(1.0, 2.0), insomnia(2.0, 1.0), ["insomnia:req_a", "insomnia:req_b"], "password"),
    ];
    for (importer, before, after, keys, field) in cases {
        let first = import(before.as_bytes(), &opts()).unwrap();
        // The variables the user filled after the first import: each
        // request's own secret under the placeholder it was given.
        let filled: BTreeMap<String, String> =
            keys.iter().map(|k| (auth_reference(req(&first, k), field), format!("secret for {k}"))).collect();
        assert_eq!(filled.len(), 2, "{importer}: the two auth configs share a placeholder");
        assert!(filled.keys().all(|p| is_auth_ref(p, field)), "{importer}: {filled:?}");

        let fresh = reimport(&first, &after);
        for k in keys {
            assert_eq!(auth_reference(req(&fresh, k), field), auth_reference(req(&first, k), field), "{importer}: {k} changed placeholder");
        }
        assert_credentials_stay(importer, &first, &fresh);
        let plan = diff(&first, &first.requests, &fresh);
        assert!(plan.conflicts.is_empty(), "{importer}: {:?}", plan.conflicts);
        let applied = plan.apply(&first.requests, &ReimportApproval::default());
        for k in keys {
            let request = applied.iter().find(|q| q.spec.source.as_ref().is_some_and(|s| s.operation_key == k)).expect("the request");
            assert_eq!(
                filled.get(&auth_reference(request, field)),
                Some(&format!("secret for {k}")),
                "{importer}: {k} took another's secret"
            );
        }
    }
}

/// Review of #586, round 2 (sol F1, dsf F1): requests matched only by their
/// position (Postman items without ids) carrying credentials, their own,
/// from URL userinfo or inherited from their folder, and reordered: each
/// position takes the other request's URL together with that request's
/// literal-bound names, so applying the plan as by default sends every
/// filled credential only to the host it was filled for.
#[test]
fn reordered_items_without_ids_keep_each_credential_with_its_host() {
    let folder = |n: &str| {
        serde_json::json!({ "name": format!("Folder {n}"),
            "auth": { "type": "bearer", "bearer": [{ "key": "token", "value": format!("tok-SENSITIVE-folder-{n}") }] },
            "item": [{ "name": format!("Inherits {n}"), "request": { "method": "GET", "url": format!("https://inherit-{n}.example.invalid/v1") } }] })
    };
    let own = |n: &str| {
        serde_json::json!({ "name": format!("Own {n}"), "request": { "method": "GET", "url": format!("https://own-{n}.example.invalid/v1"),
            "auth": { "type": "bearer", "bearer": [{ "key": "token", "value": format!("tok-SENSITIVE-own-{n}") }] } } })
    };
    let userinfo = |n: &str| {
        serde_json::json!({ "name": format!("Userinfo {n}"), "request": { "method": "GET",
            "url": format!("https://user-{n}:tok-SENSITIVE-ui-{n}@userinfo-{n}.example.invalid/v1") } })
    };
    let doc = |order: [&str; 2]| {
        let makers: [fn(&str) -> serde_json::Value; 3] = [folder, own, userinfo];
        let items: Vec<serde_json::Value> = makers.iter().flat_map(|make| order.map(make)).collect();
        serde_json::json!({
            "info": { "name": "No ids", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json" },
            "item": items
        })
        .to_string()
    };
    let first = import(doc(["a", "b"]).as_bytes(), &opts()).unwrap();
    let fresh = reimport(&first, &doc(["b", "a"]));
    let plan = assert_credentials_stay("items without ids", &first, &fresh);
    assert!(plan.conflicts.is_empty(), "{:?}", plan.conflicts.iter().map(|c| &c.operation_key).collect::<Vec<_>>());
}

/// Round 4: a request imported under an older naming (here `{{r_token}}`)
/// moves to the literal-bound name on reimport: a new, unfilled variable the
/// user is asked for, never one filled for another literal.
#[test]
fn a_request_under_an_older_naming_is_asked_for_again() {
    let doc = serde_json::json!({
        "info": { "name": "One", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json" },
        "item": [{ "id": "r1", "name": "r", "request": { "method": "GET", "url": "https://r.example.invalid/v1",
            "auth": { "type": "bearer", "bearer": [{ "key": "token", "value": "tok-SENSITIVE-legacy" }] } } }]
    })
    .to_string();
    let mut first = import(doc.as_bytes(), &opts()).unwrap();
    let legacy = &mut first.requests[0];
    legacy.spec.auth = AuthConfig::Bearer { token: SensitiveValue::template("{{r_token}}"), prefix: "Bearer".into() };
    let hash = anvil_import::spec_hash(&legacy.spec);
    legacy.spec.source.as_mut().unwrap().generated_hash = hash;
    let fresh = reimport(&first, &doc);
    let plan = diff(&first, &first.requests, &fresh);
    assert_eq!(plan.updated.len(), 1, "{plan:?}");
    let applied = plan.apply(&first.requests, &ReimportApproval::default());
    let reference = auth_reference(&applied[0], "token");
    assert!(is_auth_ref(&reference, "token"), "the reference was not renamed");
    let name = reference.trim_start_matches("{{").trim_end_matches("}}");
    assert!(fresh.credential_names.contains_key(name));
    assert!(fresh.report.required_variables.iter().any(|v| v.name == name && v.secret), "the new name is not asked for");
}

// ------------------------------------- credential continuity (#584, round 3)

const PM: &str = "https://schema.getpostman.com/json/collection/v2.1.0/collection.json";

fn template_value(v: &SensitiveValue) -> String {
    match v {
        SensitiveValue::Template { value } => value.clone(),
        SensitiveValue::Secret { .. } => String::new(),
    }
}

/// Every pure `{{reference}}` name in `v`.
fn references_in(v: &serde_json::Value, out: &mut Vec<String>) {
    match v {
        serde_json::Value::String(s)
            if s.len() > 4 && s.starts_with("{{") && s.ends_with("}}") && !s[2..s.len() - 2].contains(['{', '}']) =>
        {
            out.push(s[2..s.len() - 2].trim().to_string());
        }
        serde_json::Value::Array(items) => items.iter().for_each(|x| references_in(x, out)),
        serde_json::Value::Object(m) => m.values().for_each(|x| references_in(x, out)),
        _ => {}
    }
}

/// Where each request sends its credentials under `scope`: (destination,
/// references). The destination is the host of its URL, with every variable
/// but a filled credential resolved through its folders and then the scope;
/// a URL left as one reference (quarantined) is the request itself, by name.
/// The references are those of its auth, or of the nearest folder (or the
/// scope) it inherits auth from, and of a quarantined URL.
fn destinations(requests: &[RequestDefinition], scope: &ImportedScope, filled: &BTreeSet<String>) -> Vec<(String, Vec<String>)> {
    requests
        .iter()
        .map(|q| {
            let mut vars: Vec<&Variable> = vec![];
            let mut inherited: Option<&AuthConfig> = None;
            let mut cur = q.folder_id;
            for _ in 0..64 {
                let Some(f) = cur.and_then(|id| scope.folders.iter().find(|f| f.meta.id == id)) else { break };
                vars.extend(&f.variables);
                if inherited.is_none() && !matches!(f.auth, AuthConfig::Inherit) {
                    inherited = Some(&f.auth);
                }
                cur = f.parent_id;
            }
            vars.extend(&scope.variables);
            let mut url = q.spec.url.clone();
            for _ in 0..4 {
                for v in vars.iter().filter(|v| !filled.contains(&v.name)) {
                    url = url.replace(&format!("{{{{{}}}}}", v.name), &template_value(&v.value));
                }
            }
            let auth = if matches!(q.spec.auth, AuthConfig::Inherit) { inherited.unwrap_or(&scope.auth) } else { &q.spec.auth };
            let mut refs = vec![];
            references_in(&serde_json::to_value(auth).unwrap(), &mut refs);
            let destination = match url.split_once("://") {
                Some((_, rest)) => rest.split(['/', '?']).next().unwrap_or("").to_string(),
                None => {
                    references_in(&serde_json::Value::String(url.clone()), &mut refs);
                    format!("request {}", q.name)
                }
            };
            (destination, refs)
        })
        .collect()
}

/// Reimport `fresh` over `first` with every credential placeholder the first
/// import allocated filled in by the user, apply the request and the scope
/// plans as by default, and check that each filled credential still goes
/// only to the destination it was filled for.
fn assert_credentials_stay(label: &str, first: &ImportResult, fresh: &ImportResult) -> ReimportPlan {
    let mut current = ImportedScope::generated(first);
    let mut owners: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (destination, refs) in destinations(&first.requests, &current, &BTreeSet::new()) {
        for r in refs {
            owners.entry(r).or_default().insert(destination.clone());
        }
    }
    let filled: BTreeMap<String, String> = owners
        .into_iter()
        .filter(|(r, d)| d.len() == 1 && first.credential_names.contains_key(r))
        .filter_map(|(r, d)| d.into_iter().next().map(|d| (r, d)))
        .collect();
    assert!(!filled.is_empty(), "{label}: the first import allocated no credential to fill");
    current.variables.extend(filled.keys().map(|name| Variable::plain(name, "filled by the user")));
    let names: BTreeSet<String> = filled.keys().cloned().collect();
    let generated = baseline(first);
    let fresh_scope = ImportedScope::generated(fresh);
    let plan = reimport_diff(&first.requests, fresh, ScopeDiff { current: &current, generated: Some(&generated), fresh: &fresh_scope });
    let requests = plan.apply(&first.requests, &ReimportApproval::default());
    let mut scope = plan.apply_scope(&current, &fresh_scope, &ReimportApproval::default());
    for f in &plan.added_folders {
        if !scope.folders.iter().any(|x| x.meta.id == f.meta.id) {
            scope.folders.push(f.clone());
        }
    }
    for (destination, refs) in destinations(&requests, &scope, &names) {
        for r in refs {
            if let Some(owner) = filled.get(&r) {
                assert_eq!(owner, &destination, "{label}: a credential filled for {owner} goes to {destination}");
            }
        }
    }
    plan
}

fn postman_items(items: Vec<serde_json::Value>) -> String {
    serde_json::json!({ "info": { "name": "C", "schema": PM }, "item": items }).to_string()
}

/// A Postman request to `host` with a literal bearer token; `id` when given.
fn bearer_item(id: Option<&str>, host: &str) -> serde_json::Value {
    let mut item = serde_json::json!({ "name": format!("to {host}"), "request": { "method": "GET", "url": format!("https://{host}/v1"),
        "auth": { "type": "bearer", "bearer": [{ "key": "token", "value": format!("tok-SENSITIVE-{host}") }] } } });
    if let Some(id) = id {
        item["id"] = serde_json::json!(id);
    }
    item
}

/// Round 3, sol F1 and dsf F1: a reordered or inserted HAR entry has a new
/// key, so it is added; its userinfo placeholders are named from that key
/// and never resolve the credentials filled for another host.
#[test]
fn har_reorders_and_insertions_never_reuse_another_hosts_userinfo() {
    let har = |entries: &[(&str, &str)]| {
        let entries: Vec<serde_json::Value> = entries
            .iter()
            .map(|(userinfo, host)| serde_json::json!({ "request": { "method": "GET", "url": format!("https://{userinfo}@{host}/v1") } }))
            .collect();
        serde_json::json!({ "log": { "version": "1.2", "entries": entries } }).to_string()
    };
    let (a, b, c) = (
        ("alice:tok-SENSITIVE-1", "a.example.test"),
        ("bob:tok-SENSITIVE-2", "b.example.test"),
        ("carol:tok-SENSITIVE-3", "c.example.test"),
    );
    let first = import(har(&[a, b]).as_bytes(), &opts()).unwrap();
    for (label, after) in [("reordered", har(&[b, a])), ("inserted", har(&[c, a, b]))] {
        let fresh = reimport(&first, &after);
        assert_credentials_stay(&format!("HAR {label}"), &first, &fresh);
    }
}

/// Round 3, dsf F1: a cURL command for another URL is a new request; neither
/// its userinfo nor a quarantined URL resolves what was filled for the old
/// one.
#[test]
fn a_curl_command_for_another_url_never_reuses_the_filled_credentials() {
    let first = import(b"curl 'https://alice:tok-SENSITIVE-1@a.example.test/v1'", &opts()).unwrap();
    let fresh = reimport(&first, "curl 'https://bob:tok-SENSITIVE-2@b.example.test/v1'");
    let plan = assert_credentials_stay("cURL userinfo", &first, &fresh);
    assert_eq!((plan.added.len(), plan.removed.len()), (1, 1));
    let first = import(b"curl 'https://a.{{region}}.example.test/v1?to=a@b'", &opts()).unwrap();
    assert!(is_quarantined(&first.requests[0].spec.url));
    let fresh = reimport(&first, "curl -X POST 'https://b.{{region}}.example.test/v1?to=a@b'");
    assert_credentials_stay("cURL quarantined URL", &first, &fresh);
}

/// Round 4: a name is bound to its literal, not to a destination. The source
/// sending the same literal to a new host (a request that moved, a new
/// request holding that secret) keeps the name, and the variable filled for
/// it follows: the source itself sends that secret there. Allowed.
#[test]
fn the_same_literal_for_a_new_host_keeps_its_name() {
    let item = |id: &str, host: &str| {
        serde_json::json!({ "id": id, "name": id, "request": { "method": "GET", "url": format!("https://{host}/v1"),
            "auth": { "type": "bearer", "bearer": [{ "key": "token", "value": "tok-SENSITIVE-shared" }] } } })
    };
    let first = import(postman_items(vec![item("r1", "a.example.test")]).as_bytes(), &opts()).unwrap();
    let name = auth_reference(req(&first, "postman:r1"), "token");
    assert!(first.credential_names.contains_key(name.trim_start_matches("{{").trim_end_matches("}}")));
    let fresh = reimport(&first, &postman_items(vec![item("r1", "b.example.test"), item("r2", "c.example.test")]));
    let plan = diff(&first, &first.requests, &fresh);
    let applied = plan.apply(&first.requests, &ReimportApproval::default());
    let moved = applied.iter().find(|q| q.meta.id == first.requests[0].meta.id).expect("the request");
    assert!(moved.spec.url.contains("b.example.test"), "the move was not applied");
    assert_eq!(auth_reference(moved, "token"), name);
    assert_eq!(plan.added.len(), 1, "{plan:?}");
    assert_eq!(auth_reference(&plan.added[0], "token"), name, "the same literal got another name");
}

/// Round 4: without the key that named the first import's placeholders (a
/// fresh clone, another profile: here `None`, a random key) every name is
/// new, so nothing the user filled resolves and every credential is asked
/// for again.
#[test]
fn a_missing_credential_key_asks_for_every_credential_again() {
    let source = postman_items(vec![
        bearer_item(Some("r1"), "a.example.test"),
        bearer_item(None, "b.example.test"),
        serde_json::json!({ "name": "ui", "request": { "method": "GET", "url": "https://u:tok-SENSITIVE-ui@c.example.test/v1" } }),
        serde_json::json!({ "name": "q", "request": { "method": "GET", "url": "https://api.{{region}}.d.example.test/v1?to=a@b" } }),
    ]);
    let first = import(source.as_bytes(), &opts()).unwrap();
    let fresh = import(source.as_bytes(), &ImportOptions { id_namespace: Some(first.source.id_namespace), credential_key: None, ..opts() })
        .unwrap();
    assert!(!fresh.credential_names.is_empty());
    assert!(fresh.credential_names.keys().all(|n| !first.credential_names.contains_key(n)), "a name survived without the key");
    let plan = assert_credentials_stay("missing key", &first, &fresh);
    let applied = plan.apply(&first.requests, &ReimportApproval::default());
    for q in &applied {
        let mut refs = vec![];
        references_in(&serde_json::to_value(&q.spec).unwrap(), &mut refs);
        assert!(refs.iter().all(|r| !first.credential_names.contains_key(r)), "{}: kept a name filled under the old key", q.name);
        assert!(refs.iter().any(|r| fresh.credential_names.contains_key(r)), "{}: no new placeholder", q.name);
    }
    // A quarantined URL's placeholder is listed with its redaction instead.
    let required = |n: &String| fresh.report.required_variables.iter().any(|v| &v.name == n);
    assert!(fresh.credential_names.iter().filter(|(_, c)| c.kind != "url").all(|(n, _)| required(n)), "a new placeholder is not asked for");
}

/// Round 4: a source that names a variable or reference in the shape of a
/// literal-bound placeholder (as written, percent-encoded, as a path
/// parameter, a collection variable, an Insomnia or a cURL reference) is
/// refused, so a source can never point a request at a variable filled for
/// one of them. Names merely like it are accepted.
#[test]
fn a_source_name_in_the_reserved_shape_is_refused() {
    let with_header = |value: &str| {
        postman_items(vec![serde_json::json!({ "name": "r", "request": { "method": "GET", "url": "https://api.example.test/v1",
            "header": [{ "key": "X-Id", "value": value }] } })])
    };
    let insomnia = |value: &str| {
        serde_json::json!({ "_type": "export", "__export_format": 4, "resources": [
            { "_id": "wrk_1", "_type": "workspace", "parentId": null, "name": "W", "scope": "collection" },
            { "_id": "req_1", "_type": "request", "parentId": "wrk_1", "name": "r", "method": "GET", "url": "https://api.example.test/v1",
              "headers": [{ "name": "X-Id", "value": value }] }
        ] })
        .to_string()
    };
    // Built at run time: digits after a word like `secret_` read as a key
    // to the secret scanner.
    let digits = ["0123", "4567", "89ab", "cdef"].concat();
    let reserved = [format!("auth_{digits}_token"), format!("secret_{digits}"), format!("url_{}", digits.to_uppercase())];
    for name in &reserved {
        let cases = [
            ("reference", with_header(&format!("{{{{{name}}}}}"))),
            ("percent-encoded", with_header(&format!("{{{{{}}}}}", name.replacen('_', "%5F", 1)))),
            (
                "path parameter",
                postman_items(vec![serde_json::json!({ "name": "r", "request": { "method": "GET",
                    "url": { "raw": format!("https://api.example.test/items/:{name}") } } })]),
            ),
            (
                "collection variable",
                serde_json::json!({ "info": { "name": "C", "schema": PM }, "variable": [{ "key": name, "value": "x" }],
                    "item": [{ "name": "r", "request": { "method": "GET", "url": "https://api.example.test/v1" } }] })
                .to_string(),
            ),
            ("Insomnia", insomnia(&format!("{{{{ _.{name} }}}}"))),
            (
                "object key",
                postman_items(vec![serde_json::json!({ "name": "r", "protocolProfileBehavior": { (name.as_str()): true },
                    "request": { "method": "GET", "url": "https://api.example.test/v1" } })]),
            ),
            (
                "percent-encoded URL",
                postman_items(vec![serde_json::json!({ "name": "r", "request": { "method": "GET",
                    "url": format!("https://api.example.test/%7B%7B{}%7D%7D", name.replacen('_', "%5F", 1)) } })]),
            ),
            ("cURL", format!("curl -H 'X-Id: {{{{{name}}}}}' https://api.example.test/v1")),
        ];
        for (label, source) in cases {
            match import(source.as_bytes(), &opts()) {
                Err(e) => assert!(e.to_string().contains("reserves"), "{label} {name}: {e}"),
                Ok(_) => panic!("{label} {name}: a reserved name was accepted"),
            }
        }
    }
    let alike = [
        "auth_token".to_string(),
        "secret_0123".to_string(),
        format!("url_{digits}g"),
        format!("auth_{}g_token", &digits[..15]),
        format!("api_{digits}"),
    ];
    for name in &alike {
        assert!(import(with_header(&format!("{{{{{name}}}}}")).as_bytes(), &opts()).is_ok(), "{name} was refused");
    }
}

/// Round 3, sol F2: folders known only by their position whose requests'
/// specs stay identical (`{{host}}/v1`, inherited auth) while their `host`
/// variables move: each folder's auth names move with the literals, so
/// applying both plans as by default sends no token to the other folder's
/// host.
#[test]
fn positional_folders_keep_their_auth_with_their_hosts() {
    let folder = |n: &str| {
        serde_json::json!({ "name": format!("Folder {n}"),
            "variable": [{ "key": "host", "value": format!("https://{n}.example.test") }],
            "auth": { "type": "bearer", "bearer": [{ "key": "token", "value": format!("tok-SENSITIVE-folder-{n}") }] },
            "item": [{ "name": "Ping", "request": { "method": "GET", "url": "{{host}}/v1" } }] })
    };
    let first = import(postman_items(vec![folder("a"), folder("b")]).as_bytes(), &opts()).unwrap();
    let fresh = reimport(&first, &postman_items(vec![folder("b"), folder("a")]));
    let plan = assert_credentials_stay("positional folders", &first, &fresh);
    assert!(plan.scope_conflicts.iter().all(|c| !c.key.starts_with("folders/")), "{:?}", keys(&plan.scope_conflicts));
}

/// Round 3, sol F3: reordering a stable request's sensitive headers keeps
/// each header on its own placeholder (bound to its literal, never kept by
/// position).
#[test]
fn reordered_sensitive_headers_keep_their_own_placeholders() {
    let item = |headers: [(&str, &str); 2]| {
        serde_json::json!({ "id": "r1", "name": "r", "request": { "method": "GET", "url": "https://api.example.test/v1",
            "header": headers.map(|(k, v)| serde_json::json!({ "key": k, "value": v })) } })
    };
    let first = import(
        postman_items(vec![item([("X-Api-Key", "tok-SENSITIVE-alpha"), ("X-Auth-Token", "tok-SENSITIVE-beta")])]).as_bytes(),
        &opts(),
    )
    .unwrap();
    let fresh =
        reimport(&first, &postman_items(vec![item([("X-Auth-Token", "tok-SENSITIVE-beta"), ("X-Api-Key", "tok-SENSITIVE-alpha")])]));
    let plan = diff(&first, &first.requests, &fresh);
    let applied = plan.apply(&first.requests, &ReimportApproval::default());
    let (spec, before) = (&applied[0].spec, &first.requests[0].spec);
    for h in ["X-Api-Key", "X-Auth-Token"] {
        assert!(is_secret_ref(&header(before, h).unwrap().value), "{h}");
        assert_eq!(header(spec, h).unwrap().value, header(before, h).unwrap().value, "{h} changed placeholder");
    }
}

/// Round 3, dsf F2: repeated or empty item ids identify nothing; such items
/// are positional, and a reorder never swaps their filled credentials.
#[test]
fn repeated_and_empty_ids_are_positional() {
    for id in ["dup", ""] {
        let items = |hosts: [&str; 2]| postman_items(hosts.iter().map(|h| bearer_item(Some(id), h)).collect());
        let first = import(items(["a.example.test", "b.example.test"]).as_bytes(), &opts()).unwrap();
        let fresh = reimport(&first, &items(["b.example.test", "a.example.test"]));
        assert_credentials_stay(&format!("id {id:?}"), &first, &fresh);
    }
}

/// Round 3, dsf F3: a reference the source designates is the source's to
/// change: an OpenAPI operation switching security scheme, or a Postman
/// bearer token switching variable, applies.
#[test]
fn source_designated_references_follow_the_source() {
    let openapi = |scheme: &str| {
        serde_json::json!({ "openapi": "3.0.3", "info": { "title": "t", "version": "1" }, "servers": [{ "url": "https://api.example.test" }],
            "components": { "securitySchemes": { "A": { "type": "http", "scheme": "bearer" }, "B": { "type": "http", "scheme": "bearer" } } },
            "paths": { "/users": { "get": { "operationId": "getUsers", "security": [{ scheme: [] }], "responses": { "200": { "description": "ok" } } } } } })
        .to_string()
    };
    let first = import(openapi("A").as_bytes(), &opts()).unwrap();
    let fresh = reimport(&first, &openapi("B"));
    let applied = diff(&first, &first.requests, &fresh).apply(&first.requests, &ReimportApproval::default());
    assert_eq!(auth_reference(&applied[0], "token"), "{{B}}", "the scheme switch was not applied");
    let postman = |token: &str| {
        postman_items(vec![
            serde_json::json!({ "id": "r1", "name": "r", "request": { "method": "GET", "url": "https://api.example.test/v1",
            "auth": { "type": "bearer", "bearer": [{ "key": "token", "value": token }] } } }),
        ])
    };
    let first = import(postman("{{tokenA}}").as_bytes(), &opts()).unwrap();
    let fresh = reimport(&first, &postman("{{tokenB}}"));
    let applied = diff(&first, &first.requests, &fresh).apply(&first.requests, &ReimportApproval::default());
    assert_eq!(auth_reference(&applied[0], "token"), "{{tokenB}}", "the variable switch was not applied");
}

/// Quarantined URLs: bound to the URL they replaced, so a reorder, with or
/// without ids, keeps each with its own request.
#[test]
fn quarantined_urls_stay_with_their_requests() {
    let item = |id: Option<&str>, host: &str| {
        let mut item = serde_json::json!({ "name": host, "request": { "method": "GET", "url": format!("https://api.{{{{region}}}}.{host}/v1?to=a@b") } });
        if let Some(id) = id {
            item["id"] = serde_json::json!(id);
        }
        item
    };
    for ids in [[Some("q1"), Some("q2")], [None, None]] {
        let first =
            import(postman_items(vec![item(ids[0], "a.example.test"), item(ids[1], "b.example.test")]).as_bytes(), &opts()).unwrap();
        assert!(first.requests.iter().all(|q| is_quarantined(&q.spec.url)));
        let fresh = reimport(&first, &postman_items(vec![item(ids[1], "b.example.test"), item(ids[0], "a.example.test")]));
        assert_credentials_stay(&format!("quarantined, ids {ids:?}"), &first, &fresh);
    }
}

// ---------------------------------------------------------- round 5 (#586)

/// Sol F1: a name the source designates (here an OpenAPI security scheme's
/// key) equal to a placeholder the import also makes is refused, in a new
/// import and a reimport. So the request it names can never resolve the
/// value filled for that placeholder.
#[test]
fn a_designated_name_equal_to_a_made_placeholder_is_refused() {
    let doc = |evil: Option<&str>, alternatives: bool| {
        let mut schemes = serde_json::json!({ "cc": { "type": "oauth2", "flows": { "clientCredentials": {
            "tokenUrl": "https://{{tenant}}.issuer.example.test/token?to=a@b", "scopes": {} } } },
            "mtls": { "type": "mutualTLS" } });
        let mut paths =
            serde_json::json!({ "/a": { "get": { "security": [{ "cc": [] }], "responses": { "200": { "description": "ok" } } } } });
        if let Some(name) = evil {
            schemes[name] = serde_json::json!({ "type": "http", "scheme": "bearer" });
            // Round 6 (sol F1): an incomplete first alternative whose
            // allocation is discarded, then the scheme named N.
            let security =
                if alternatives { serde_json::json!([{ "cc": [], "mtls": [] }, { name: [] }]) } else { serde_json::json!([{ name: [] }]) };
            paths["/evil"] = serde_json::json!({ "get": { "security": security, "servers": [{ "url": "https://evil.example.test" }],
                "responses": { "200": { "description": "ok" } } } });
        }
        serde_json::json!({ "openapi": "3.0.3", "info": { "title": "t", "version": "1" }, "servers": [{ "url": "https://api.example.test" }],
            "components": { "securitySchemes": schemes }, "paths": paths })
        .to_string()
    };
    let first = import(doc(None, false).as_bytes(), &opts()).unwrap();
    let name = first.credential_names.iter().find(|(_, c)| c.kind == "url").map(|(n, _)| n.clone()).expect("the token URL is quarantined");
    for (label, o, alternatives) in [
        ("import", opts(), false),
        ("reimport", ImportOptions { id_namespace: Some(first.source.id_namespace), ..opts() }, false),
        ("reimport, discarded alternative", ImportOptions { id_namespace: Some(first.source.id_namespace), ..opts() }, true),
    ] {
        let evil = doc(Some(&name), alternatives);
        match import(evil.as_bytes(), &o) {
            Err(e) => assert!(e.to_string().contains("reserves"), "{label}: {e}"),
            Ok(_) => panic!("{label}: a scheme named like the quarantine placeholder was accepted"),
        }
    }
}

/// Sol F2: an Insomnia quarantined URL is bound to its own text: two URLs
/// get two placeholders, and a changed URL a new one, so a value filled for
/// one never resolves for another.
#[test]
fn insomnia_quarantined_urls_are_bound_to_their_text() {
    let doc = |requests: &[(&str, &str)]| {
        let mut resources =
            vec![serde_json::json!({ "_id": "wrk_1", "_type": "workspace", "parentId": null, "name": "W", "scope": "collection" })];
        resources.extend(requests.iter().map(
            |(id, url)| serde_json::json!({ "_id": id, "_type": "request", "parentId": "wrk_1", "name": id, "method": "GET", "url": url }),
        ));
        serde_json::json!({ "_type": "export", "__export_format": 4, "resources": resources }).to_string()
    };
    let (a, b) = ("https://a.{{ region }}.example.test/v1?to=a@b", "https://b.{{ region }}.example.test/v1?to=c@d");
    let both = import(doc(&[("req_a", a), ("req_b", b)]).as_bytes(), &opts()).unwrap();
    let urls: Vec<&str> = both.requests.iter().map(|q| q.spec.url.as_str()).collect();
    assert!(urls.iter().all(|u| is_quarantined(u)), "{urls:?}");
    assert_ne!(urls[0], urls[1], "two URLs share a placeholder");
    let first = import(doc(&[("req_a", a)]).as_bytes(), &opts()).unwrap();
    let fresh = reimport(&first, &doc(&[("req_a", b)]));
    assert_ne!(fresh.requests[0].spec.url, first.requests[0].spec.url, "a changed URL kept its placeholder");
    assert_credentials_stay("Insomnia quarantined URL changed", &first, &fresh);
}

/// Sol F3: the HMAC input is length-prefixed, so a field and literal that
/// would join to the same text (`password\0a` = `b`, `password` = `a\0b`)
/// get different names.
#[test]
fn field_and_literal_never_run_together() {
    let body = |raw: &str| {
        postman_items(vec![
            serde_json::json!({ "id": "r1", "name": "r", "request": { "method": "POST", "url": "https://api.example.test/v1",
            "header": [{ "key": "Content-Type", "value": "application/json" }],
            "body": { "mode": "raw", "raw": raw, "options": { "raw": { "language": "json" } } } } }),
        ])
    };
    let placeholder = |r: &ImportResult| {
        let v = json_body(&r.requests[0].spec);
        v.as_object()
            .and_then(|m| m.values().find_map(|x| x.as_str().filter(|s| is_secret_ref(s)).map(str::to_string)))
            .expect("a placeholder")
    };
    let one = import(body(r#"{"password\u0000a":"b"}"#).as_bytes(), &opts()).unwrap();
    let two = import(body(r#"{"password":"a\u0000b"}"#).as_bytes(), &opts()).unwrap();
    assert_ne!(placeholder(&one), placeholder(&two), "two different literals share a placeholder");
}

/// Sol F4: a name whose 17th byte falls inside a character is not of the
/// reserved shape, and checking it does not panic.
#[test]
fn a_name_with_a_multibyte_character_at_byte_sixteen_imports() {
    for name in ["auth_aaaaaaaaaaaaaaaé", "secret_0123456789abcdeé", "url_é"] {
        let doc = serde_json::json!({ "info": { "name": name, "schema": PM },
            "variable": [{ "key": name, "value": "x" }],
            "item": [{ "name": name, "request": { "method": "GET", "url": format!("https://api.example.test/{{{{{name}}}}}") } }] });
        assert!(import(doc.to_string().as_bytes(), &opts()).is_ok(), "a multibyte name was refused");
    }
}
