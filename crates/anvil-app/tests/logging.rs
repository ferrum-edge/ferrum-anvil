//! Warnings reach a log: the desktop shell's is a bounded file. A stored
//! object that does not decode while the storage cleanup runs is named there
//! by kind and id.

use anvil_app::App;
use anvil_app::logging::{LOG_FILE, LevelFilter, LogFile, log_to_file};
use anvil_app::profiles::ProfileManager;
use anvil_domain::request::RequestSpec;
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
    let damaged = app.create_request(&ws, None, "damaged", RequestSpec::http("GET", "http://127.0.0.1:9/")).unwrap();
    // A pass decodes the referrers only when there is a file to release.
    app.put_attachment("abandoned.bin", b"attached to a draft never saved", None).unwrap();
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
    assert_eq!(done.undecodable.len(), 1);
    let log = std::fs::read_to_string(logs.join(LOG_FILE)).unwrap();
    let line = log.lines().find(|l| l.contains("does not decode")).unwrap_or_else(|| panic!("no warning in the log: {log}"));
    assert!(line.contains(" WARN anvil_app::"), "{line}");
    assert!(line.contains(&format!("kind=\"{}\"", kind::REQUEST)) && line.contains(&format!("id={id}")), "{line}");
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
