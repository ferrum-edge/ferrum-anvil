//! `Store::list_history_with`: the history listing decodes each record's
//! listed fields from the one decryption that authenticates it, never reads
//! a response body, and fails on a record that does not authenticate exactly
//! as `Store::list_history` does.

use anvil_domain::Id;
use anvil_domain::execution::{ExecutionListing, ExecutionRecord};
use anvil_storage::store::{DB_FILE, HistoryEntry};
use anvil_storage::{Key, Store, StoreError};
use rusqlite::{Connection, params};
use serde_json::{Value, json};

/// The listed fields of an `ExecutionRecord` and some bulk the listing skips,
/// without the record's other required fields: a full `ExecutionRecord` does
/// not decode from it.
fn record(id: Id, ws: Id, request: Id, status: Option<u16>) -> Value {
    let mut v = json!({
        "id": id,
        "workspace_id": ws,
        "request_id": request,
        "started_at": "2026-11-06T10:00:00Z",
        "prepared": {"protocol": "http", "method": "POST", "url": format!("https://api.invalid/{id}"), "headers": [{"name": "a", "value": "b"}]},
        "attempts": [{"transcript": "x".repeat(4096)}],
        "outcome": {"summary": format!("summary of {id}"), "warnings": []},
        "findings": [],
    });
    if let Some(status) = status {
        v["response"] = json!({"status": status, "headers": [], "body": {"bytes": 4}});
    }
    v
}

/// `(id, started_at, size, workspace, request)` of an entry.
type EntryKey = (String, i64, i64, Option<String>, Option<String>);

/// A row's `(workspace_id, request_id, body_blob)` columns.
type Indexes = (Option<String>, Option<String>, Option<String>);

/// The [`EntryKey`] of each entry, in order.
fn keys(entries: impl IntoIterator<Item = HistoryEntry>) -> Vec<EntryKey> {
    entries.into_iter().map(|h| (h.id, h.started_at, h.size, h.workspace_id, h.request_id)).collect()
}

fn names<T>(result: Result<T, StoreError>, id: &Id) -> bool {
    matches!(result, Err(StoreError::ObjectIntegrity { kind, id: named }) if kind == "history record" && named == id.to_string())
}

struct Fixture {
    _dir: tempfile::TempDir,
    store: Store,
    db: Connection,
    ws: Id,
    request: Id,
    /// Newest first: two with a stored response body, one without a response.
    ids: [Id; 3],
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path(), Key::random()).unwrap();
    let db = Connection::open(dir.path().join(DB_FILE)).unwrap();
    let (ws, request) = (Id::new(), Id::new());
    let ids = [Id::new(), Id::new(), Id::new()];
    store.add_history(&ids[2], Some(&ws), Some(&request), 1, &record(ids[2], ws, request, None), None).unwrap();
    store.add_history(&ids[1], Some(&ws), Some(&request), 2, &record(ids[1], ws, request, Some(404)), Some(b"gone".as_slice())).unwrap();
    store.add_history(&ids[0], Some(&ws), Some(&request), 3, &record(ids[0], ws, request, Some(200)), Some(b"body".as_slice())).unwrap();
    Fixture { _dir: dir, store, db, ws, request, ids }
}

#[test]
fn the_listing_decodes_the_same_fields_as_reading_each_record() {
    let f = fixture();
    let listed = f.store.list_history_with::<ExecutionListing>(Some(&f.ws), None, 10).unwrap();
    let (entries, recs): (Vec<_>, Vec<_>) = listed.into_iter().unzip();
    assert_eq!(keys(entries.clone()), keys(f.store.list_history(Some(&f.ws), None, 10).unwrap()), "the same entries, in the same order");
    assert_eq!(entries.iter().map(|h| h.id.clone()).collect::<Vec<_>>(), f.ids.map(|i| i.to_string()));
    for (h, rec) in entries.iter().zip(recs) {
        let rec = rec.unwrap();
        let (full, _) = f.store.get_history::<Value>(&h.id).unwrap().unwrap();
        assert_eq!(rec.prepared.method, full["prepared"]["method"].as_str().unwrap());
        assert_eq!(rec.prepared.url, full["prepared"]["url"].as_str().unwrap());
        assert_eq!(rec.outcome.summary, full["outcome"]["summary"].as_str().unwrap());
        assert_eq!(rec.response.map(|r| u64::from(r.status)), full["response"]["status"].as_u64());
        assert_eq!(rec.request_id.map(|r| r.to_string()), h.request_id);
        assert_eq!(rec.started_at, serde_json::from_value::<chrono::DateTime<chrono::Utc>>(full["started_at"].clone()).unwrap());
    }
    // Filters and limit as in `list_history`.
    let one = f.store.list_history_with::<ExecutionListing>(Some(&f.ws), Some(&f.request), 1).unwrap();
    assert_eq!(keys(one.into_iter().map(|(h, _)| h)), keys(f.store.list_history(Some(&f.ws), Some(&f.request), 1).unwrap()));
    assert!(f.store.list_history_with::<ExecutionListing>(Some(&Id::new()), None, 10).unwrap().is_empty());
}

#[test]
fn the_listing_never_reads_a_response_body() {
    let f = fixture();
    // Every stored body no longer opens: reading a record with its body
    // fails, the listing does not notice.
    f.db.execute("UPDATE blobs SET payload=x'00'", []).unwrap();
    for id in &f.ids[..2] {
        assert!(matches!(f.store.get_history::<Value>(&id.to_string()), Err(StoreError::Integrity)), "{id}");
    }
    let listed = f.store.list_history_with::<ExecutionListing>(Some(&f.ws), None, 10).unwrap();
    let statuses: Vec<_> = listed.into_iter().map(|(_, rec)| rec.unwrap().response.map(|r| r.status)).collect();
    assert_eq!(statuses, vec![Some(200), Some(404), None]);
    // Nor are the bodies needed at all.
    f.db.execute("DELETE FROM blobs", []).unwrap();
    assert_eq!(f.store.list_history_with::<ExecutionListing>(Some(&f.ws), None, 10).unwrap().len(), 3);
}

#[test]
fn a_record_that_fails_its_integrity_check_still_fails_the_listing() {
    let f = fixture();
    let target = f.ids[1].to_string();
    // Filed under another workspace, under no request, or with its body
    // reference cleared.
    let edits = [
        ("UPDATE history SET workspace_id=?1 WHERE id=?2", Some(Id::new().to_string())),
        ("UPDATE history SET request_id=?1 WHERE id=?2", None),
        ("UPDATE history SET body_blob=?1 WHERE id=?2", None),
    ];
    for (edit, value) in edits {
        let before: Indexes =
            f.db.query_row("SELECT workspace_id, request_id, body_blob FROM history WHERE id=?1", params![target], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })
            .unwrap();
        f.db.execute(edit, params![value, target]).unwrap();
        assert!(names(f.store.list_history(None, None, 10), &f.ids[1]), "{edit}");
        assert!(names(f.store.list_history_with::<ExecutionListing>(None, None, 10), &f.ids[1]), "{edit}: no partial list, no skip");
        let restore = "UPDATE history SET workspace_id=?1, request_id=?2, body_blob=?3 WHERE id=?4";
        f.db.execute(restore, params![before.0, before.1, before.2, target]).unwrap();
    }
    // A sealed record that does not open.
    let sealed: Vec<u8> = f.db.query_row("SELECT payload FROM history WHERE id=?1", params![target], |r| r.get(0)).unwrap();
    let mut tampered = sealed.clone();
    *tampered.last_mut().unwrap() ^= 1;
    f.db.execute("UPDATE history SET payload=?1 WHERE id=?2", params![tampered, target]).unwrap();
    assert!(names(f.store.list_history_with::<ExecutionListing>(Some(&f.ws), None, 10), &f.ids[1]));
    f.db.execute("UPDATE history SET payload=?1 WHERE id=?2", params![sealed, target]).unwrap();
    assert_eq!(f.store.list_history_with::<ExecutionListing>(Some(&f.ws), None, 10).unwrap().len(), 3);
}

#[test]
fn an_authentic_record_that_does_not_decode_is_reported_with_its_entry() {
    let f = fixture();
    let odd = Id::new();
    let partial = json!({"id": odd, "workspace_id": f.ws, "request_id": f.request, "status": 200});
    f.store.add_history(&odd, Some(&f.ws), Some(&f.request), 4, &partial, None).unwrap();
    let listed = f.store.list_history_with::<ExecutionListing>(Some(&f.ws), None, 10).unwrap();
    assert_eq!(listed.len(), 4);
    assert_eq!(listed[0].0.id, odd.to_string());
    assert!(matches!(listed[0].1, Err(StoreError::Serde(_))));
    assert!(listed[1..].iter().all(|(_, rec)| rec.is_ok()));
}

#[test]
fn a_record_the_full_record_type_rejects_is_listed_from_its_listed_fields() {
    let f = fixture();
    // The listing decodes only what it shows, so a record it can show is
    // listed even when opening it as a full record fails.
    let listed = f.store.list_history_with::<ExecutionListing>(Some(&f.ws), None, 10).unwrap();
    assert_eq!(listed.len(), 3);
    for (h, rec) in listed {
        assert!(rec.is_ok(), "{}", h.id);
        assert!(matches!(f.store.get_history::<ExecutionRecord>(&h.id), Err(StoreError::Serde(_))), "{}", h.id);
    }
}

#[test]
fn the_listing_is_refused_while_locked() {
    let f = fixture();
    f.store.lock();
    assert!(matches!(f.store.list_history_with::<ExecutionListing>(None, None, 10), Err(StoreError::Locked)));
}
