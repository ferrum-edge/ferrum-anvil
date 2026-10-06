//! Warnings reach a log: the desktop shell's is a bounded file. A stored
//! object that does not decode while the storage cleanup runs is named there
//! by kind and id.

use anvil_app::App;
use anvil_app::logging::{LOG_FILE, LevelFilter, LogFile, log_to_file};
use anvil_app::profiles::ProfileManager;
use anvil_domain::request::{AttachmentRef, Body, RequestSpec};
use anvil_storage::store::DB_FILE;
use anvil_storage::{KdfParams, kind};
use std::io::Write;

#[test]
fn a_stored_object_that_does_not_decode_is_named_in_the_log_file() {
    let root = tempfile::tempdir().unwrap();
    let logs = root.path().join("logs");
    // The one logger of this test binary.
    log_to_file(&logs, LevelFilter::INFO).unwrap();
    let pm = ProfileManager::new(root.path());
    let (s, dek, _recovery) = pm.create_passphrase("logging", "correct horse battery", KdfParams::testing()).unwrap();
    let h = anvil_storage::vault::read_header(&s.dir).unwrap();
    let app = App::open(s.dir, h, dek).unwrap();
    let ws = app.create_workspace("W").unwrap().meta.id;
    let attachment = app.put_attachment("private-payload.bin", b"LOG-SECRET-4821", None).unwrap();
    let AttachmentRef::Stored { sha256, .. } = &attachment else { panic!("stored attachment") };
    let sha256 = sha256.clone();
    let mut spec = RequestSpec::http("GET", "http://127.0.0.1:9/");
    spec.body = Body::Binary { attachment, content_type: None };
    let damaged = app.create_request(&ws, None, "damaged", spec).unwrap();
    let revision = damaged.revision_id.unwrap();
    let db = rusqlite::Connection::open(app.dir.join(DB_FILE)).unwrap();
    let id = damaged.meta.id.to_string();
    db.execute("UPDATE objects SET payload=x'00' WHERE kind=?1 AND id=?2", rusqlite::params![kind::REQUEST, id]).unwrap();
    let past = (chrono::Utc::now() - chrono::Duration::days(31)).timestamp_millis();
    drop(db);
    // Attached past the grace period.
    for entry in app.store.object_meta(kind::IMPORT_SOURCE).unwrap() {
        let row = entry.id.parse().unwrap();
        let mut index: serde_json::Value = app.store.get(kind::IMPORT_SOURCE, &row).unwrap().unwrap();
        index["attached_at"] = past.into();
        app.store.put(kind::IMPORT_SOURCE, &row, None, None, 0.0, &index).unwrap();
    }

    let done = app.clean_up_storage().unwrap();
    assert_eq!(done.undecodable.len(), 2, "the damaged request and its revision are blocked");
    assert!(done.undecodable.contains(&anvil_app::cleanup::UndecodableObject { kind: kind::REQUEST.into(), id: id.clone() }));
    assert!(done.undecodable.contains(&anvil_app::cleanup::UndecodableObject { kind: kind::REVISION.into(), id: revision.to_string() }));
    assert!(app.store.object_meta(kind::REQUEST).unwrap().iter().any(|row| row.id == id));
    assert!(app.store.object_meta(kind::REVISION).unwrap().iter().any(|row| row.id == revision.to_string()));
    assert!(app.get_attachment(&sha256).unwrap().unwrap().as_slice() == b"LOG-SECRET-4821", "attachment data was not retained");
    let attachment_index: serde_json::Value = app.store.list(kind::IMPORT_SOURCE, None).unwrap().remove(0);
    let blob = attachment_index["blob"].as_str().unwrap();
    let db = rusqlite::Connection::open(app.dir.join(DB_FILE)).unwrap();
    let pinned: bool = db
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM meta WHERE key=?1 AND value=?2) AND EXISTS(SELECT 1 FROM blobs WHERE id=?2)",
            rusqlite::params![format!("pin:{blob}"), blob],
            |row| row.get(0),
        )
        .unwrap();
    assert!(pinned, "cleanup released or unpinned the blocked request attachment");
    let log = std::fs::read_to_string(logs.join(LOG_FILE)).unwrap();
    let has_warning = |kind: &str, id: &str| {
        log.lines().any(|line| {
            line.contains(" WARN anvil_app::")
                && line.contains("a stored object does not decode")
                && line.contains(&format!("kind=\"{kind}\""))
                && line.ends_with(&format!("id={id}"))
        })
    };
    assert!(has_warning(kind::REQUEST, &id), "request warning was not logged");
    assert!(has_warning(kind::REVISION, &revision.to_string()), "revision warning was not logged");
    assert!(!log.contains("LOG-SECRET-4821") && !log.contains("private-payload.bin"), "log contains attachment data");
}

#[test]
fn a_log_file_is_rotated_once_it_reaches_its_limit() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bounded.log");
    let mut file = LogFile::open(path.clone(), 64).unwrap();
    let line = [b'a'; 40];
    for _ in 0..5 {
        file.write_all(&line).unwrap();
        file.write_all(b"\n").unwrap();
    }
    file.flush().unwrap();
    let rotated = file.rotated_path();
    assert_eq!(rotated, dir.path().join("bounded.log.1"));
    assert!(std::fs::metadata(&path).unwrap().len() <= 64, "the current file stays within its limit");
    assert!(std::fs::metadata(&rotated).unwrap().len() <= 64, "and so does the one before it");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for f in [&path, &rotated] {
            assert_eq!(std::fs::metadata(f).unwrap().permissions().mode() & 0o777, 0o600, "{}: owner only", f.display());
        }
    }
    // Reopened, it goes on from where it was.
    let len = std::fs::metadata(&path).unwrap().len();
    let mut again = LogFile::open(path.clone(), 64).unwrap();
    again.write_all(b"x").unwrap();
    assert_eq!(std::fs::metadata(&path).unwrap().len(), len + 1);
}
