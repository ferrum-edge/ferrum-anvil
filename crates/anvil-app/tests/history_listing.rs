//! The history listing (`Store::list_history_with::<ExecutionListing>`, as
//! the desktop History panel and `anvil history` read it) shows the same
//! fields for real recorded sends as reading each full `ExecutionRecord`,
//! and does so without their response bodies. It decodes only those fields,
//! so an authentic record a full `ExecutionRecord` does not decode from is
//! listed, and fails only when opened.

use anvil_app::App;
use anvil_app::exec::SendOptions;
use anvil_app::profiles::ProfileManager;
use anvil_domain::execution::{ExecutionListing, ExecutionRecord};
use anvil_domain::request::{Body, RequestSpec};
use anvil_storage::store::DB_FILE;
use anvil_storage::{KdfParams, StoreError};
use anvil_transport::recorder::EventCtx;
use tokio_util::sync::CancellationToken;

fn new_app(root: &std::path::Path) -> App {
    let pm = ProfileManager::new(root);
    let (s, dek, _recovery) = pm.create_passphrase("t", "correct horse battery", KdfParams::testing()).unwrap();
    let h = anvil_storage::vault::read_header(&s.dir).unwrap();
    App::open(s.dir, h, dek).unwrap()
}

/// What a History row shows: id, start, method, url, summary, status, request.
type Listed = (String, i64, String, String, String, Option<u16>, Option<String>, chrono::DateTime<chrono::Utc>);

/// The listing as the desktop built it before: each entry's full record.
fn read_each_record(app: &App, ws: &anvil_domain::Id) -> Vec<Listed> {
    let mut out = Vec::new();
    for h in app.store.list_history(Some(ws), None, 500).unwrap() {
        let (rec, _) = app.store.get_history::<ExecutionRecord>(&h.id).unwrap().unwrap();
        let status = rec.response.as_ref().map(|r| r.status);
        out.push((
            h.id,
            h.started_at,
            rec.prepared.method,
            rec.prepared.url,
            rec.outcome.summary,
            status,
            rec.request_id.map(|r| r.to_string()),
            rec.started_at,
        ));
    }
    out
}

fn listing(app: &App, ws: &anvil_domain::Id) -> Vec<Listed> {
    let rows = app.store.list_history_with::<ExecutionListing>(Some(ws), None, 500).unwrap();
    rows.into_iter()
        .map(|(h, rec)| {
            let rec = rec.unwrap();
            (
                h.id,
                h.started_at,
                rec.prepared.method,
                rec.prepared.url,
                rec.outcome.summary,
                rec.response.map(|r| r.status),
                rec.request_id.map(|r| r.to_string()),
                rec.started_at,
            )
        })
        .collect()
}

#[tokio::test]
async fn the_history_listing_matches_the_full_records_without_reading_their_bodies() {
    anvil_fixtures::init();
    let fx = anvil_fixtures::http::serve("127.0.0.1:0", None).await.unwrap();
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let ws = app.create_workspace("History").unwrap().meta.id;
    let mut echo = RequestSpec::http("POST", &fx.url("/echo"));
    echo.body = Body::Json { text: r#"{"note":"listed"}"#.into() };
    let echo = app.create_request(&ws, None, "Echo", echo).unwrap();
    let missing = app.create_request(&ws, None, "Missing", RequestSpec::http("GET", &fx.url("/status/404"))).unwrap();
    let opts = SendOptions { record_history: true, ..Default::default() };
    for request in [echo.meta.id, missing.meta.id] {
        app.send(Some(request), &ws, None, opts.clone(), EventCtx::none(), CancellationToken::new()).await.unwrap();
    }
    // A draft: no request.
    let draft = RequestSpec::http("GET", &fx.url("/status/200"));
    app.send(None, &ws, Some(draft), opts, EventCtx::none(), CancellationToken::new()).await.unwrap();

    let before = read_each_record(&app, &ws);
    assert_eq!(before.len(), 3);
    assert!(before.iter().any(|r| r.6.is_none()), "the draft has no request");
    assert_eq!(listing(&app, &ws), before, "the same rows, fields and order as reading each record");

    // Every stored response body no longer opens: reading a record with its
    // body fails, the listing shows the same as before.
    let db = rusqlite::Connection::open(app.dir.join(DB_FILE)).unwrap();
    let with_body: i64 = db.query_row("SELECT COUNT(*) FROM history WHERE body_blob IS NOT NULL", [], |r| r.get(0)).unwrap();
    assert!(with_body > 0, "the sends stored their response bodies");
    db.execute("UPDATE blobs SET payload=x'00' WHERE id IN (SELECT body_blob FROM history)", []).unwrap();
    let unreadable = before.iter().filter(|r| matches!(app.store.get_history::<ExecutionRecord>(&r.0), Err(StoreError::Integrity))).count();
    assert_eq!(i64::try_from(unreadable).unwrap(), with_body);
    assert_eq!(listing(&app, &ws), before);
}

#[tokio::test]
async fn a_record_only_the_listed_fields_decode_from_is_listed_but_does_not_open() {
    anvil_fixtures::init();
    let fx = anvil_fixtures::http::serve("127.0.0.1:0", None).await.unwrap();
    let root = tempfile::tempdir().unwrap();
    let app = new_app(root.path());
    let ws = app.create_workspace("History").unwrap().meta.id;
    let opts = SendOptions { record_history: true, ..Default::default() };
    let draft = RequestSpec::http("GET", &fx.url("/status/200"));
    let sent = app.send(None, &ws, Some(draft), opts, EventCtx::none(), CancellationToken::new()).await.unwrap();
    // The same record under another id, without a field only the full
    // record requires.
    let (mut partial, _) = app.store.get_history::<serde_json::Value>(&sent.record.id.to_string()).unwrap().unwrap();
    let id = anvil_domain::Id::new();
    partial["id"] = serde_json::json!(id);
    assert!(partial.as_object_mut().unwrap().remove("finished_at").is_some());
    app.store.add_history(&id, Some(&ws), None, sent.record.started_at.timestamp_millis() + 1, &partial, None).unwrap();

    assert!(matches!(app.store.get_history::<ExecutionRecord>(&id.to_string()), Err(StoreError::Serde(_))), "it does not open");
    let listed = listing(&app, &ws);
    assert_eq!(listed.len(), 2);
    assert_eq!(listed[0].0, id.to_string(), "it is listed, newest");
    assert_eq!(listed[1].0, sent.record.id.to_string());
    let shown = |r: &Listed| (r.2.clone(), r.3.clone(), r.4.clone(), r.5, r.6.clone(), r.7);
    assert_eq!(shown(&listed[0]), shown(&listed[1]), "with the fields it seals");
}
