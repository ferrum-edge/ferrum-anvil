//! Operational failures keep the key; integrity evidence locks the store.
use super::*;
use crate::{KdfParams, vault};
use std::path::Path;

fn profile(dir: &Path) -> (Store, Key) {
    let c = vault::create_enrolled_passphrase_profile(dir, "availability", "a passphrase 123", KdfParams::testing()).unwrap();
    (Store::open(dir, c.dek.clone()).unwrap(), c.dek)
}

thread_local! {
    /// Failures the next key checks of [`Store::conn`] report, last first.
    pub(super) static PREFLIGHT_FAULT: std::cell::RefCell<Vec<StoreError>> = const { std::cell::RefCell::new(Vec::new()) };
}

fn sqlite(code: i32) -> StoreError {
    StoreError::from(rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(code), None))
}

#[test]
fn operational_failures_of_the_key_check_keep_the_key() {
    let dir = tempfile::tempdir().unwrap();
    let (store, _) = profile(dir.path());
    let blob = store.put_blob(b"kept").unwrap();
    for (fault, retryable) in [
        (sqlite(rusqlite::ffi::SQLITE_IOERR), true),
        (sqlite(rusqlite::ffi::SQLITE_FULL), true),
        (StoreError::Io(std::io::Error::other("transient")), true),
        (sqlite(rusqlite::ffi::SQLITE_ERROR), false),
    ] {
        let shown = fault.to_string();
        PREFLIGHT_FAULT.set(vec![fault]);
        let e = store.get_blob(&blob).unwrap_err();
        assert_eq!(e.to_string(), shown);
        assert_eq!(e.is_retryable(), retryable, "{e}");
        assert!(!store.is_locked(), "{e} is no evidence against the key");
        assert_eq!(store.get_blob(&blob).unwrap().unwrap().as_slice(), b"kept");
    }
}

#[test]
fn contention_in_the_key_check_is_retried_a_bounded_number_of_times() {
    let dir = tempfile::tempdir().unwrap();
    let (store, _) = profile(dir.path());
    let blob = store.put_blob(b"kept").unwrap();
    // Contention that clears within the retries is not seen by the caller.
    PREFLIGHT_FAULT.set((0..PREFLIGHT_RETRIES).map(|_| sqlite(rusqlite::ffi::SQLITE_BUSY)).collect());
    assert_eq!(store.get_blob(&blob).unwrap().unwrap().as_slice(), b"kept");
    // Contention that outlasts them is reported as busy, and the key is kept.
    PREFLIGHT_FAULT.set((0..=PREFLIGHT_RETRIES).map(|_| sqlite(rusqlite::ffi::SQLITE_BUSY)).collect());
    let e = store.get_blob(&blob).unwrap_err();
    assert!(matches!(e, StoreError::Busy(_)), "{e}");
    assert!(PREFLIGHT_FAULT.with_borrow(Vec::is_empty));
    assert!(!store.is_locked());
}

#[test]
fn an_authentication_failure_of_the_key_check_locks() {
    let dir = tempfile::tempdir().unwrap();
    let (store, _) = profile(dir.path());
    let blob = store.put_blob(b"kept").unwrap();
    PREFLIGHT_FAULT.set(vec![StoreError::Integrity]);
    assert!(matches!(store.get_blob(&blob), Err(StoreError::Locked)));
    assert!(store.is_locked());
}

#[test]
fn a_write_meeting_another_writer_is_busy_and_keeps_the_key() {
    let dir = tempfile::tempdir().unwrap();
    let (store, _) = profile(dir.path());
    let blob = store.put_blob(b"kept").unwrap();
    store.conn.lock().busy_timeout(Duration::from_millis(20)).unwrap();
    let other = Connection::open(dir.path().join(DB_FILE)).unwrap();
    other.execute_batch("BEGIN IMMEDIATE; INSERT INTO meta(key,value) VALUES('held','1');").unwrap();
    let e = store.put_blob(b"waits").unwrap_err();
    assert!(matches!(e, StoreError::Busy(_)), "{e}");
    assert!(e.is_retryable());
    assert!(!store.is_locked(), "contention is no evidence against the key");
    // Readers are not blocked by the writer.
    assert_eq!(store.get_blob(&blob).unwrap().unwrap().as_slice(), b"kept");
    other.execute_batch("ROLLBACK").unwrap();
    store.put_blob(b"accepted").unwrap();
}

#[test]
fn a_held_key_change_fence_keeps_the_key_and_fails_busy_within_the_bound() {
    let dir = tempfile::tempdir().unwrap();
    let (store, _) = profile(dir.path());
    let blob = store.put_blob(b"kept").unwrap();
    crate::profile_lock::TEST_LOCK_WAIT.set(Some(Duration::from_millis(100)));
    let fence = crate::profile_lock::exclusive(dir.path()).unwrap();
    let started = std::time::Instant::now();
    let e = store.get_blob(&blob).unwrap_err();
    assert!(matches!(&e, StoreError::Busy(m) if m.contains("profile is busy")), "{e}");
    assert!(e.is_retryable());
    assert!(started.elapsed() < Duration::from_secs(5), "the wait is bounded");
    assert!(!store.is_locked());
    drop(fence);
    crate::profile_lock::TEST_LOCK_WAIT.set(None);
    assert_eq!(store.get_blob(&blob).unwrap().unwrap().as_slice(), b"kept");
}

#[test]
fn integrity_evidence_locks_the_store() {
    for attack in [
        // The canary no longer opens under the held key.
        "UPDATE meta SET value='rotated-v1:00' WHERE key='key_canary'",
        // The catalogue the handle requires disappeared.
        "DELETE FROM meta WHERE key='protected_records_v1'",
        // The canary was removed.
        "DELETE FROM meta WHERE key='key_canary'",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let (store, _) = profile(dir.path());
        let blob = store.put_blob(b"kept").unwrap();
        Connection::open(dir.path().join(DB_FILE)).unwrap().execute_batch(attack).unwrap();
        assert!(matches!(store.get_blob(&blob), Err(StoreError::Locked)), "{attack}");
        assert!(store.is_locked(), "{attack}");
    }
}
