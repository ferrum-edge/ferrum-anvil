mod common;

use anvil_domain::request::KeyValue;
use anvil_import::{ImportOptions, ReimportApproval, import, reimport_diff};
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
fn reimport_preserves_edits_and_never_deletes() {
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
    let plan = reimport_diff(&previous, &fresh);

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
    let approval = ReimportApproval { overwrite: vec![create_id], delete: vec![del_id] };
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
    let plan = reimport_diff(&previous, &again);
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
    let plan = reimport_diff(&previous, &first);
    assert_eq!(plan.unlinked, vec![previous[1].meta.id]);
    // The op that lost its link reappears as added (never merged silently).
    assert_eq!(plan.added.len(), 1);
}
