mod common;

use anvil_domain::Id;
use anvil_domain::request::KeyValue;
use anvil_domain::secret::SensitiveValue;
use anvil_domain::workspace::{RequestDefinition, Variable};
use anvil_import::{ImportOptions, ImportResult, ImportedScope, ReimportApproval, ReimportPlan, ScopeDiff, import, reimport_diff};
use common::*;

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

/// Diff `previous` against `fresh`, with the scoped configuration as `first`
/// generated it and left untouched.
fn diff(first: &ImportResult, previous: &[RequestDefinition], fresh: &ImportResult) -> ReimportPlan {
    let (current, fresh_scope) = (ImportedScope::generated(first), ImportedScope::generated(fresh));
    let generated = current.unit_hashes();
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
    assert_eq!(plan.added.len(), 1);
    assert_eq!(plan.added[0].name, "cancelOrder");
    assert_eq!(plan.added_folders.len(), 1);
    assert_eq!(plan.added_folders[0].name, "admin");

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
    let next = plan.next_generated_scope(&fresh, Some(&generated), &ReimportApproval::default());
    let again = reimport_diff(&first.requests, &fresh_result, ScopeDiff { current: &kept, generated: Some(&next), fresh: &fresh });
    assert_eq!(again.scope_conflicts.iter().map(|c| c.key.as_str()).collect::<Vec<_>>(), vec![key.as_str()]);

    // Approved: the fresh server replaces it; the user's own variable stays.
    let approval = ReimportApproval { overwrite_scope: vec![key.clone()], ..Default::default() };
    let applied = plan.apply_scope(&current, &fresh, &approval);
    assert_eq!(base_url(&applied, env), SensitiveValue::template("https://new.example.test"));
    assert!(applied.environments[0].variables.iter().any(|v| v.name == "token"));
    let next = plan.next_generated_scope(&fresh, Some(&generated), &approval);
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
