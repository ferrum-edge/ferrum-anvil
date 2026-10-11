//! SQLite failures that remain effective with triggers and foreign keys disabled.

// Each integration-test binary uses only the helpers needed for its fault paths.
#![allow(dead_code)]

use rusqlite::Connection;

/// Keep existing matching payloads readable, but reject a new or changed one.
/// The table and predicate are fixed SQL supplied by these test fixtures.
pub fn deny_payload_writes(db: &Connection, table: &str, predicate: &str) {
    let mut statement = db.prepare(&format!("SELECT quote(hex(payload)) FROM {table} WHERE {predicate}")).unwrap();
    let values = statement.query_map([], |row| row.get::<_, String>(0)).unwrap().collect::<Result<Vec<_>, _>>().unwrap();
    let unchanged = if values.is_empty() { "0".to_owned() } else { format!("hex(payload) IN ({})", values.join(",")) };
    db.execute_batch(&format!(
        "ALTER TABLE {table} ADD COLUMN injected_write_guard INTEGER GENERATED ALWAYS AS (1) VIRTUAL \
         CHECK (NOT ({predicate}) OR ({unchanged}));"
    ))
    .unwrap();
}

pub fn allow_payload_writes(db: &Connection, table: &str) {
    db.execute_batch(&format!("ALTER TABLE {table} DROP COLUMN injected_write_guard;")).unwrap();
}

/// Preserve reads and all rows while making SQL writes fail on a read-only view.
pub fn deny_object_deletes(db: &Connection) {
    db.execute_batch("ALTER TABLE objects RENAME TO injected_objects; CREATE VIEW objects AS SELECT * FROM injected_objects;").unwrap();
}

pub fn allow_object_deletes(db: &Connection) {
    db.execute_batch("DROP VIEW objects; ALTER TABLE injected_objects RENAME TO objects;").unwrap();
}

/// Fail publication after the transaction closure's row deletes have completed.
pub fn deny_authority_publication(db: &Connection) {
    let canary: String = db.query_row("SELECT quote(value) FROM meta WHERE key='key_canary'", [], |row| row.get(0)).unwrap();
    db.execute_batch(&format!(
        "ALTER TABLE meta ADD COLUMN injected_publication_guard INTEGER GENERATED ALWAYS AS (1) VIRTUAL \
         CHECK (key <> 'key_canary' OR value = {canary});"
    ))
    .unwrap();
}

pub fn allow_authority_publication(db: &Connection) {
    db.execute_batch("ALTER TABLE meta DROP COLUMN injected_publication_guard;").unwrap();
}
