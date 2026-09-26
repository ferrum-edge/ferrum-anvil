//! Transaction isolation: a `Store::atomically` transaction belongs to its
//! caller alone. Other callers wait for it to end instead of writing into it,
//! reading its uncommitted rows, or being committed or rolled back with it.

use anvil_domain::Id;
use anvil_storage::store::{DB_FILE, StoreError};
use anvil_storage::{KdfParams, Key, Store, kind, vault};
use serde_json::{Value, json};
use std::path::Path;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

/// How long a transaction holds out for a concurrent caller to finish inside
/// it. A caller that could join the transaction finishes well within this;
/// an isolated one cannot finish until the transaction ends.
const WINDOW: Duration = Duration::from_millis(500);

fn open() -> (tempfile::TempDir, Store, Key) {
    let dir = tempfile::tempdir().unwrap();
    let created = vault::create_passphrase_profile(dir.path(), "t", "pw", KdfParams::testing()).unwrap();
    let store = Store::open(dir.path(), created.dek.clone()).unwrap();
    (dir, store, created.dek)
}

fn name(store: &Store, id: &Id) -> Option<String> {
    store.get::<Value>(kind::WORKSPACE, id).unwrap().map(|v| v["name"].as_str().unwrap().to_string())
}

fn injected() -> StoreError {
    StoreError::NotFound("injected failure".into())
}

/// The store's connection holds no transaction: another connection can take
/// the database write lock at once.
fn assert_no_open_transaction(dir: &Path) {
    let other = rusqlite::Connection::open(dir.join(DB_FILE)).unwrap();
    other.busy_timeout(Duration::ZERO).unwrap();
    other.execute_batch("BEGIN IMMEDIATE; ROLLBACK;").expect("the store's connection was left inside a transaction");
}

#[test]
fn failed_transaction_never_rolls_back_a_concurrent_save() {
    let (dir, store, dek) = open();
    let store = &store;
    let (ws, doomed) = (Id::new(), Id::new());
    store.put(kind::WORKSPACE, &ws, None, None, 0.0, &json!({"name": "old"})).unwrap();

    let (began, began_rx) = mpsc::channel();
    let (saved, saved_rx) = mpsc::channel();
    let saved_inside = thread::scope(|sc| {
        // Caller A: opens a transaction, writes, then fails.
        let a = sc.spawn(move || {
            let mut saved_inside = false;
            let r: Result<(), StoreError> = store.atomically(|tx| {
                tx.put(kind::WORKSPACE, &doomed, None, None, 0.0, &json!({"name": "doomed"}))?;
                began.send(()).unwrap();
                saved_inside = saved_rx.recv_timeout(WINDOW).is_ok();
                Err(injected())
            });
            assert!(r.is_err());
            saved_inside
        });
        // Caller B: an unrelated save while A's transaction is open.
        began_rx.recv().unwrap();
        store.put(kind::WORKSPACE, &ws, None, None, 0.0, &json!({"name": "renamed"})).unwrap();
        let _ = saved.send(());
        a.join().unwrap()
    });

    assert!(!saved_inside, "a save completed inside another caller's open transaction");
    assert_eq!(name(store, &ws).as_deref(), Some("renamed"), "the other caller's rollback erased an acknowledged save");
    assert_eq!(name(store, &doomed), None, "the failed transaction's own write was rolled back");
    // Durable, not just visible on this connection.
    let reopened = Store::open(dir.path(), dek).unwrap();
    assert_eq!(name(&reopened, &ws).as_deref(), Some("renamed"));
    assert_eq!(name(&reopened, &doomed), None);
}

#[test]
fn readers_never_see_another_callers_uncommitted_writes() {
    let (_dir, store, _dek) = open();
    let store = &store;
    let ws = Id::new();
    store.put(kind::WORKSPACE, &ws, None, None, 0.0, &json!({"name": "committed"})).unwrap();

    let (began, began_rx) = mpsc::channel();
    let (read, read_rx) = mpsc::channel();
    let read_inside = thread::scope(|sc| {
        let a = sc.spawn(move || {
            let mut read_inside = None;
            let r: Result<(), StoreError> = store.atomically(|tx| {
                tx.put(kind::WORKSPACE, &ws, None, None, 0.0, &json!({"name": "uncommitted"}))?;
                // The transaction sees its own write.
                assert_eq!(tx.get::<Value>(kind::WORKSPACE, &ws)?.unwrap()["name"], "uncommitted");
                began.send(()).unwrap();
                read_inside = read_rx.recv_timeout(WINDOW).ok();
                Err(injected())
            });
            assert!(r.is_err());
            read_inside
        });
        began_rx.recv().unwrap();
        let seen = name(store, &ws);
        let _ = read.send(seen.clone());
        assert_eq!(seen.as_deref(), Some("committed"), "a reader saw another caller's uncommitted write");
        a.join().unwrap()
    });

    assert_eq!(read_inside, None, "a read completed inside another caller's open transaction");
    assert_eq!(name(store, &ws).as_deref(), Some("committed"));
}

#[test]
fn concurrent_transactions_commit_or_roll_back_independently() {
    let (dir, store, dek) = open();
    let store = &store;
    let (a_id, b_id) = (Id::new(), Id::new());

    let (began, began_rx) = mpsc::channel();
    let (b_done, b_done_rx) = mpsc::channel();
    let b_inside = thread::scope(|sc| {
        // Transaction A fails.
        let a = sc.spawn(move || {
            let mut b_inside = false;
            let r: Result<(), StoreError> = store.atomically(|tx| {
                tx.put(kind::WORKSPACE, &a_id, None, None, 0.0, &json!({"name": "a"}))?;
                began.send(()).unwrap();
                b_inside = b_done_rx.recv_timeout(WINDOW).is_ok();
                Err(injected())
            });
            assert!(r.is_err());
            b_inside
        });
        // Transaction B, started while A is open, commits.
        began_rx.recv().unwrap();
        let r: Result<(), StoreError> = store.atomically(|tx| {
            tx.put(kind::WORKSPACE, &b_id, None, None, 0.0, &json!({"name": "b"}))?;
            assert!(tx.get::<Value>(kind::WORKSPACE, &a_id)?.is_none(), "B saw A's uncommitted write");
            Ok(())
        });
        r.unwrap();
        let _ = b_done.send(());
        a.join().unwrap()
    });

    assert!(!b_inside, "transaction B ran inside transaction A");
    assert_eq!(name(store, &a_id), None);
    assert_eq!(name(store, &b_id).as_deref(), Some("b"));
    let reopened = Store::open(dir.path(), dek).unwrap();
    assert_eq!(name(&reopened, &a_id), None);
    assert_eq!(name(&reopened, &b_id).as_deref(), Some("b"));
}

#[test]
fn store_calls_inside_its_own_transaction_are_rejected_not_deadlocked() {
    let (_dir, store, _dek) = open();
    let (kept, stray) = (Id::new(), Id::new());
    let r: Result<(), StoreError> = store.atomically(|tx| {
        tx.put(kind::WORKSPACE, &kept, None, None, 0.0, &json!({"name": "kept"}))?;
        let direct = store.put(kind::WORKSPACE, &stray, None, None, 0.0, &json!({"name": "stray"}));
        assert!(matches!(direct, Err(StoreError::TransactionActive)));
        assert!(matches!(store.get::<Value>(kind::WORKSPACE, &kept), Err(StoreError::TransactionActive)));
        assert!(matches!(store.atomically(|_| Ok(())), Err(StoreError::TransactionActive)), "nested transactions are rejected");
        Ok(())
    });
    r.unwrap();
    assert_eq!(name(&store, &kept).as_deref(), Some("kept"), "the rejected calls did not disturb the transaction");
    assert_eq!(name(&store, &stray), None);

    // A panic inside the closure rolls back and releases the store.
    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        store.atomically(|tx| -> Result<(), StoreError> {
            tx.put(kind::WORKSPACE, &stray, None, None, 0.0, &json!({"name": "stray"}))?;
            panic!("injected panic");
        })
    }));
    assert!(panicked.is_err());
    assert_eq!(name(&store, &stray), None);
    store.put(kind::WORKSPACE, &stray, None, None, 0.0, &json!({"name": "after"})).unwrap();
    assert_eq!(name(&store, &stray).as_deref(), Some("after"));
}

#[test]
fn locking_mid_transaction_fails_its_remaining_writes() {
    let (_dir, store, dek) = open();
    let id = Id::new();
    let r: Result<(), StoreError> = store.atomically(|tx| {
        tx.put(kind::WORKSPACE, &id, None, None, 0.0, &json!({"name": "w"}))?;
        store.lock();
        tx.put(kind::WORKSPACE, &Id::new(), None, None, 0.0, &json!({"name": "x"}))
    });
    assert!(matches!(r, Err(StoreError::Locked)));
    store.unlock(dek).unwrap();
    assert_eq!(name(&store, &id), None, "the locked transaction rolled back");
}

#[test]
fn every_transaction_ends_before_the_connection_is_released() {
    let (dir, store, _dek) = open();
    let id = Id::new();

    let r: Result<(), StoreError> = store.atomically(|tx| {
        tx.put(kind::WORKSPACE, &id, None, None, 0.0, &json!({"name": "failed"}))?;
        Err(injected())
    });
    assert!(matches!(r, Err(StoreError::NotFound(_))), "the closure's own error is returned");
    assert_no_open_transaction(dir.path());

    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        store.atomically(|tx| -> Result<(), StoreError> {
            tx.put(kind::WORKSPACE, &id, None, None, 0.0, &json!({"name": "panicked"}))?;
            panic!("injected panic");
        })
    }));
    assert!(panicked.is_err());
    assert_no_open_transaction(dir.path());
    assert_eq!(name(&store, &id), None);

    store.atomically(|tx| tx.put(kind::WORKSPACE, &id, None, None, 0.0, &json!({"name": "committed"}))).unwrap();
    assert_no_open_transaction(dir.path());
    assert_eq!(name(&store, &id).as_deref(), Some("committed"));
}

#[test]
fn consistent_reads_take_no_write_lock() {
    let (dir, store, _dek) = open();
    let id = Id::new();
    store.put(kind::WORKSPACE, &id, None, None, 0.0, &json!({"name": "kept"})).unwrap();

    let r: Result<Option<Value>, StoreError> = store.read_consistently(|tx| {
        let seen = tx.get(kind::WORKSPACE, &id)?;
        let other = rusqlite::Connection::open(dir.path().join(DB_FILE)).unwrap();
        other.busy_timeout(Duration::ZERO).unwrap();
        other.execute_batch("BEGIN IMMEDIATE; ROLLBACK;").expect("a consistent read took the write lock");
        Ok(seen)
    });
    assert_eq!(r.unwrap().unwrap()["name"], "kept");
    assert_no_open_transaction(dir.path());
}
