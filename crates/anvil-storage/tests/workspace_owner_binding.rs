//! Production Store tests for the released v1 object envelope. Metadata-only
//! attackers below receive a SQLite connection, never the data encryption key.

use anvil_domain::Id;
use anvil_domain::request::RequestSpec;
use anvil_domain::runner::{FailOn, RunTotals};
use anvil_domain::settings::AppSettings;
use anvil_storage::store::DB_FILE;
use anvil_storage::{Key, Store, StoreError, crypto, kind};
use rusqlite::{Connection, params};
use serde_json::{Value, json};

struct Object {
    kind: &'static str,
    id: Id,
    owner: Option<Id>,
    parent: Option<Id>,
    value: Value,
}

impl Object {
    fn put(&self, store: &Store) -> Result<(), StoreError> {
        store.put(self.kind, &self.id, self.owner.as_ref(), self.parent.as_ref(), 1.0, &self.value)
    }
}

fn fixture(k: &'static str, ws: Id, request: Id) -> Object {
    let id = if k == kind::DEVICE_IDENTITY_SEAL { ws } else { Id::new() };
    let now = chrono::Utc::now();
    let mut value = json!({
        "id": id,
        "workspace_id": ws,
        "schema_version": anvil_domain::SCHEMA_VERSION,
        "created_at": now,
        "updated_at": now,
        "name": "binding fixture",
    });
    let mut owner = Some(ws);
    let mut parent = None;
    match k {
        kind::WORKSPACE => {
            value.as_object_mut().unwrap().remove("workspace_id");
            owner = None;
        }
        kind::FOLDER => value["sort_key"] = json!(1.0),
        kind::REQUEST => {
            value["sort_key"] = json!(1.0);
            value["spec"] = json!(RequestSpec::http("GET", "https://original.invalid/"));
        }
        kind::REVISION => {
            value.as_object_mut().unwrap().remove("workspace_id");
            value["request_id"] = json!(request);
            value["spec_sha256"] = json!("fixture hash");
            value["spec"] = json!(RequestSpec::http("GET", "https://original.invalid/"));
            parent = Some(request);
        }
        kind::ENVIRONMENT | kind::TLS_PROFILE => {}
        kind::PROXY_PROFILE => {
            value["kind"] = json!("http");
            value["address"] = json!("127.0.0.1:8080");
        }
        kind::INTEGRATION => {
            value["kind"] = json!("ferrum_gateway");
            value["hosts"] = json!([]);
            value["compatibility_id"] = json!("ferrum-edge-0.9.10");
        }
        kind::DATASET => {
            value["format"] = json!("csv");
            value["attachment"] = json!({
                "kind": "stored", "sha256": "fixture", "size": 0, "file_name": "rows.csv"
            });
        }
        kind::SCENARIO => value["steps"] = json!([]),
        kind::LOAD_PLAN => {
            value["workload"] = json!({"model": "iterations", "iterations": 1, "concurrency": 1});
        }
        kind::USER_PROFILE => {
            value["display_name"] = json!("profile");
            value["protection"] = json!("passphrase");
            owner = None;
        }
        kind::APP_SETTINGS => {
            value = json!(AppSettings::default());
            owner = None;
        }
        kind::API_RULESET => {
            value["file_name"] = json!("rules.yaml");
            value["text"] = json!("rules: []");
            value["sha256"] = json!("fixture");
            value["added_at"] = json!(now);
            owner = None;
        }
        kind::IMPORT_SOURCE => {
            value = json!({"attachment": "fixture", "blob": "fixture blob"});
            owner = None;
        }
        kind::SPEC_SOURCE => {
            value = json!({
                "source": {"import_id": id}, "workspace_id": ws,
                "root_folder_id": null, "original_sha256": "fixture", "file_name": "spec.json"
            });
        }
        kind::RUN_REPORT => {
            value = json!({
                "run_id": id, "report_version": 1,
                "schema_version": anvil_domain::SCHEMA_VERSION, "runner_version": "fixture",
                "workspace_id": ws, "name": "fixture",
                "source": {"kind": "folder", "path": "/"},
                "fail_on": FailOn::default(), "stop_on_failure": false,
                "started_at": now, "finished_at": now, "duration_ms": 0,
                "completion": "completed", "partial": false,
                "totals": RunTotals::default(), "iterations": []
            });
        }
        kind::TOKEN_FILE | kind::LINKED_FILE => {
            value = json!({"id": id, "path": "/fixture", "bound_at": now});
            if k == kind::LINKED_FILE {
                value["referrer"] = json!({"kind": "request", "id": request});
            }
            owner = None;
        }
        kind::DEVICE_IDENTITY_SEAL => {
            value = json!({"workspace_id": ws, "sealed_at": now});
        }
        _ => panic!("uncovered kind {k}"),
    }
    Object { kind: k, id, owner, parent, value }
}

fn kinds() -> Vec<&'static str> {
    let mut kinds = kind::ALL.to_vec();
    kinds.extend([kind::TOKEN_FILE, kind::LINKED_FILE, kind::DEVICE_IDENTITY_SEAL]);
    kinds
}

fn open() -> (tempfile::TempDir, Store, Key, Id, Id, Id) {
    let dir = tempfile::tempdir().unwrap();
    let key = Key::random();
    let store = Store::open(dir.path(), key.clone()).unwrap();
    let (a, b) = (Id::new(), Id::new());
    for id in [a, b] {
        let mut ws = fixture(kind::WORKSPACE, a, Id::nil());
        ws.id = id;
        ws.value["id"] = json!(id);
        ws.put(&store).unwrap();
    }
    let request = fixture(kind::REQUEST, a, Id::nil());
    request.put(&store).unwrap();
    (dir, store, key, a, b, request.id)
}

#[derive(Debug, PartialEq)]
struct StoredRow {
    owner: Option<String>,
    parent: Option<String>,
    sort_key: f64,
    updated_at: i64,
    payload: Vec<u8>,
}

fn row(db: &Connection, object: &Object) -> StoredRow {
    db.query_row(
        "SELECT workspace_id,parent_id,sort_key,updated_at,payload FROM objects
         WHERE kind=?1 AND id=?2",
        params![object.kind, object.id.to_string()],
        |r| Ok(StoredRow { owner: r.get(0)?, parent: r.get(1)?, sort_key: r.get(2)?, updated_at: r.get(3)?, payload: r.get(4)? }),
    )
    .unwrap()
}

// This attacker has no key. Change only the plaintext routing column.
fn change_owner(db: &Connection, object: &Object, owner: Option<Id>) {
    db.execute(
        "UPDATE objects SET workspace_id=?1 WHERE kind=?2 AND id=?3",
        params![owner.map(|w| w.to_string()), object.kind, object.id.to_string()],
    )
    .unwrap();
}

#[test]
fn every_kind_rejects_metadata_only_owner_tampering_and_resave() {
    let (dir, store, _key, a, b, request) = open();
    let db = Connection::open(dir.path().join(DB_FILE)).unwrap();
    for k in kinds() {
        let mut object = fixture(k, a, request);
        object.put(&store).unwrap();
        assert_eq!(store.get::<Value>(k, &object.id).unwrap(), Some(object.value.clone()));
        assert!(store.list::<Value>(k, object.owner.as_ref()).unwrap().contains(&object.value));
        // Supported updates of the same identity continue to work.
        object.put(&store).unwrap();
        let original = row(&db, &object);

        change_owner(&db, &object, Some(b));
        assert_eq!(row(&db, &object).payload, original.payload, "attacker resealed {k}");
        assert!(matches!(store.get::<Value>(k, &object.id), Err(StoreError::Integrity)), "{k}");
        assert!(matches!(store.list::<Value>(k, Some(&b)), Err(StoreError::Integrity)), "{k}");
        assert!(matches!(store.list::<Value>(k, None), Err(StoreError::Integrity)), "{k}");
        store
            .read_consistently(|read| {
                assert!(matches!(read.get::<Value>(k, &object.id), Err(StoreError::Integrity)));
                assert!(matches!(read.list::<Value>(k, Some(&b)), Err(StoreError::Integrity)));
                Ok(())
            })
            .unwrap();

        // Resubmitting under the forged index must never adopt it as truth.
        let tampered = row(&db, &object);
        object.owner = Some(b);
        if object.value.get("workspace_id").is_some() {
            object.value["workspace_id"] = json!(b);
        }
        assert!(object.put(&store).is_err(), "{k} adopted an edited owner");
        assert_eq!(row(&db, &object), tampered, "{k} partially updated a refused row");
        change_owner(&db, &object, original.owner.as_ref().map(|s| s.parse().unwrap()));
        store.delete(k, &object.id).unwrap();
    }
}

#[test]
fn every_kind_preserves_existing_owner_in_direct_and_transactional_updates() {
    let (dir, store, _key, a, b, request) = open();
    let db = Connection::open(dir.path().join(DB_FILE)).unwrap();
    for k in kinds() {
        let mut object = fixture(k, a, request);
        object.put(&store).unwrap();
        let original = row(&db, &object);
        object.owner = Some(b);
        if object.value.get("workspace_id").is_some() {
            object.value["workspace_id"] = json!(b);
        }
        assert!(object.put(&store).is_err(), "{k} moved on direct put");
        let result = store.atomically(|tx| tx.put(k, &object.id, object.owner.as_ref(), object.parent.as_ref(), 999.0, &object.value));
        assert!(result.is_err(), "{k} moved on transactional put");
        assert_eq!(row(&db, &object), original, "{k} changed a refused row");
        store.delete(k, &object.id).unwrap();
    }
}

#[test]
fn every_kind_checks_id_kind_and_parent_metadata_before_returning_payloads() {
    let (dir, store, _key, a, _b, request) = open();
    let db = Connection::open(dir.path().join(DB_FILE)).unwrap();
    for k in kinds() {
        let object = fixture(k, a, request);
        object.put(&store).unwrap();
        let other = Id::new();
        db.execute("UPDATE objects SET id=?1 WHERE kind=?2 AND id=?3", params![other.to_string(), k, object.id.to_string()]).unwrap();
        assert!(matches!(store.get::<Value>(k, &other), Err(StoreError::Integrity)), "{k}");
        assert!(matches!(store.list::<Value>(k, None), Err(StoreError::Integrity)), "{k}");
        db.execute("UPDATE objects SET id=?1 WHERE kind=?2 AND id=?3", params![object.id.to_string(), k, other.to_string()]).unwrap();

        db.execute("UPDATE objects SET parent_id=?1 WHERE kind=?2 AND id=?3", params![other.to_string(), k, object.id.to_string()])
            .unwrap();
        assert!(matches!(store.get::<Value>(k, &object.id), Err(StoreError::Integrity)), "{k}");
        assert!(matches!(store.list::<Value>(k, None), Err(StoreError::Integrity)), "{k}");
        assert!(object.put(&store).is_err(), "{k} repaired an untrusted parent on save");
        db.execute(
            "UPDATE objects SET parent_id=?1,kind='unrecognized' WHERE kind=?2 AND id=?3",
            params![object.parent.map(|p| p.to_string()), k, object.id.to_string()],
        )
        .unwrap();
        assert!(matches!(store.get::<Value>("unrecognized", &object.id), Err(StoreError::Integrity)));
        assert!(matches!(store.list::<Value>("unrecognized", None), Err(StoreError::Integrity)));
        db.execute("DELETE FROM objects WHERE kind='unrecognized' AND id=?1", params![object.id.to_string()]).unwrap();
    }
}

#[test]
fn already_sealed_wrong_id_owner_type_and_parent_are_refused_without_resealing() {
    let (dir, store, key, a, b, request) = open();
    let db = Connection::open(dir.path().join(DB_FILE)).unwrap();
    let object = fixture(kind::ENVIRONMENT, a, request);
    object.put(&store).unwrap();
    let valid = row(&db, &object);
    let mut wrong_id = object.value.clone();
    wrong_id["id"] = json!(Id::new());
    let mut wrong_owner = object.value.clone();
    wrong_owner["workspace_id"] = json!(b);
    for value in [wrong_id, wrong_owner, json!({"id": object.id, "workspace_id": a})] {
        // A fixture of an older writer's malformed sealed record, not the
        // metadata-only attacker above. Keep the released AAD exactly.
        let aad = format!("anvil/v1/objects/{}/{}", object.kind, object.id);
        let payload = crypto::seal(&key, aad.as_bytes(), &serde_json::to_vec(&value).unwrap());
        db.execute("UPDATE objects SET payload=?1 WHERE kind=?2 AND id=?3", params![payload, object.kind, object.id.to_string()]).unwrap();
        let invalid = row(&db, &object);
        assert!(matches!(store.get::<Value>(object.kind, &object.id), Err(StoreError::Integrity)));
        assert!(matches!(store.list::<Value>(object.kind, Some(&a)), Err(StoreError::Integrity)));
        assert!(object.put(&store).is_err());
        assert_eq!(row(&db, &object), invalid);
    }
    db.execute("UPDATE objects SET payload=?1 WHERE kind=?2 AND id=?3", params![valid.payload, object.kind, object.id.to_string()])
        .unwrap();

    let revision = fixture(kind::REVISION, a, request);
    revision.put(&store).unwrap();
    let mut wrong_parent = revision.value.clone();
    wrong_parent["request_id"] = json!(Id::new());
    let aad = format!("anvil/v1/objects/revision/{}", revision.id);
    let payload = crypto::seal(&key, aad.as_bytes(), &serde_json::to_vec(&wrong_parent).unwrap());
    db.execute("UPDATE objects SET payload=?1 WHERE kind='revision' AND id=?2", params![payload, revision.id.to_string()]).unwrap();
    assert!(matches!(store.get::<Value>(kind::REVISION, &revision.id), Err(StoreError::Integrity)));
}

#[test]
fn failed_owner_change_rolls_back_earlier_writes_and_revisions_follow_sealed_request_owner() {
    let (dir, store, _key, a, b, request) = open();
    let db = Connection::open(dir.path().join(DB_FILE)).unwrap();
    let env = fixture(kind::ENVIRONMENT, a, request);
    let revision = fixture(kind::REVISION, a, request);
    env.put(&store).unwrap();
    revision.put(&store).unwrap();
    let original = row(&db, &env);
    let mut changed = env.value.clone();
    changed["name"] = json!("must roll back");
    let result = store.atomically(|tx| {
        tx.put(kind::ENVIRONMENT, &env.id, Some(&a), None, 55.0, &changed)?;
        tx.put(kind::REVISION, &revision.id, Some(&b), Some(&request), 0.0, &revision.value)
    });
    assert!(matches!(result, Err(StoreError::Ownership)));
    assert_eq!(row(&db, &env), original);
    // Editing the parent request's owner cannot validate a revision's owner.
    db.execute("UPDATE objects SET workspace_id=?1 WHERE kind='request' AND id=?2", params![b.to_string(), request.to_string()]).unwrap();
    assert!(matches!(store.get::<Value>(kind::REVISION, &revision.id), Err(StoreError::Integrity)));
}

#[test]
fn new_objects_require_consistent_identity_and_an_existing_workspace() {
    let (dir, store, _key, a, _b, request) = open();
    let db = Connection::open(dir.path().join(DB_FILE)).unwrap();
    for k in kinds() {
        let mut object = fixture(k, a, request);
        let value = object.value.clone();
        object.value = json!([]);
        assert!(object.put(&store).is_err(), "{k} accepted a wrong payload type");
        object.value = value;
        object.parent = Some(Id::new());
        assert!(object.put(&store).is_err(), "{k} accepted a mismatched parent");
        let count: i64 =
            db.query_row("SELECT count(*) FROM objects WHERE kind=?1 AND id=?2", params![k, object.id.to_string()], |r| r.get(0)).unwrap();
        assert_eq!(count, 0, "{k} partially created a rejected object");
    }
    for k in kinds() {
        let absent = fixture(k, Id::new(), request);
        if absent.owner.is_some() {
            assert!(matches!(absent.put(&store), Err(StoreError::NotFound(_))), "{k}");
        }
    }
}

#[test]
fn orphan_inspection_returns_only_hashes_and_never_bypasses_a_present_parent() {
    let (dir, store, _key, a, b, request) = open();
    let db = Connection::open(dir.path().join(DB_FILE)).unwrap();
    let mut revision = fixture(kind::REVISION, a, request);
    let hash = "a".repeat(64);
    revision.value["spec"]["body"] = json!({
        "type": "binary",
        "attachment": {
            "kind": "stored", "sha256": hash, "size": 3,
            "file_name": "private-route-name", "media_type": "private-media-type"
        }
    });
    revision.put(&store).unwrap();
    db.execute(
        "UPDATE objects SET workspace_id=?1,parent_id=NULL WHERE kind='revision' AND id=?2",
        params![b.to_string(), revision.id.to_string()],
    )
    .unwrap();
    let forged = row(&db, &revision);
    // Even a corrupt parent remains present, so this cannot become an
    // alternative reader for live revision data or reference authorization.
    db.execute(
        "UPDATE objects SET payload=x'00' WHERE kind='request' AND id=?1",
        params![request.to_string()],
    )
    .unwrap();
    let refs = store
        .read_consistently(|r| r.orphan_revision_attachment_refs_for_retention(&revision.id))
        .unwrap();
    assert_eq!(refs, None);
    assert!(matches!(
        store.get::<Value>(kind::REVISION, &revision.id),
        Err(StoreError::Integrity)
    ));
    store.delete(kind::REQUEST, &request).unwrap();
    let refs = store
        .read_consistently(|r| r.orphan_revision_attachment_refs_for_retention(&revision.id))
        .unwrap();
    assert_eq!(refs, Some(std::collections::HashSet::from([hash])));
    assert!(matches!(
        store.get::<Value>(kind::REVISION, &revision.id),
        Err(StoreError::Integrity)
    ));
    assert!(store.list::<Value>(kind::REVISION, Some(&b)).is_err());
    assert!(revision.put(&store).is_err(), "reference inspection cannot reseal or adopt it");
    assert_eq!(row(&db, &revision), forged);
    store.lock();
    assert!(matches!(
        store.read_consistently(|r| r.orphan_revision_attachment_refs_for_retention(&revision.id)),
        Err(StoreError::Locked)
    ));
}

#[test]
fn orphan_inspection_refuses_ciphertext_wrong_ids_and_non_hash_attachment_data() {
    let (dir, store, key, a, _b, request) = open();
    let db = Connection::open(dir.path().join(DB_FILE)).unwrap();
    let revision = fixture(kind::REVISION, a, request);
    revision.put(&store).unwrap();
    store.delete(kind::REQUEST, &request).unwrap();
    let mut wrong_id = revision.value.clone();
    wrong_id["id"] = json!(Id::new());
    let mut invalid_hash = revision.value.clone();
    invalid_hash["spec"]["body"] = json!({
        "type": "binary",
        "attachment": {
            "kind": "stored", "sha256": "https://private-route.invalid/",
            "size": 0, "file_name": "private"
        }
    });
    let aad = format!("anvil/v1/objects/revision/{}", revision.id);
    for payload in [
        vec![0],
        crypto::seal(&key, aad.as_bytes(), &serde_json::to_vec(&wrong_id).unwrap()),
        crypto::seal(&key, aad.as_bytes(), &serde_json::to_vec(&invalid_hash).unwrap()),
    ] {
        db.execute(
            "UPDATE objects SET payload=?1 WHERE kind='revision' AND id=?2",
            params![payload, revision.id.to_string()],
        )
        .unwrap();
        let before = row(&db, &revision);
        assert!(matches!(
            store.read_consistently(|r| {
                r.orphan_revision_attachment_refs_for_retention(&revision.id)
            }),
            Err(StoreError::Integrity)
        ));
        assert_eq!(row(&db, &revision), before);
    }
}
