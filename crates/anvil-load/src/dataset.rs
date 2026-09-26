//! CSV / JSON datasets: one row per iteration (cycling), injected as an
//! iteration-scoped variable layer. The SHA-256 of the exact dataset bytes is
//! recorded in the report so runs over different data are never compared as
//! equivalent.

use crate::LoadError;
use anvil_engine::vars::{VarEntry, VarLayer};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;

pub const MAX_DATASET_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_ROWS: usize = 1_000_000;
pub const MAX_COLUMNS: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DatasetFormat {
    /// Header row followed by records.
    Csv,
    /// An array of flat objects. Strings are used as-is; other scalars use
    /// their JSON text; nested values use their compact JSON text.
    Json,
}

#[derive(Debug, Clone)]
pub struct Dataset {
    pub format: DatasetFormat,
    pub columns: Vec<String>,
    /// Row cells aligned with `columns`; `None` = key absent in that JSON row
    /// (the variable is then not defined by the dataset for that row).
    pub rows: Vec<Vec<Option<String>>>,
    pub sha256: String,
    /// Columns whose values are secrets: marked secret in each row's
    /// variable layer, so the engine redacts their exact values everywhere.
    pub sensitive_columns: Vec<String>,
    raw: Arc<[u8]>,
}

impl Dataset {
    pub fn parse(format: DatasetFormat, bytes: impl Into<Arc<[u8]>>) -> Result<Dataset, LoadError> {
        let raw: Arc<[u8]> = bytes.into();
        if raw.len() > MAX_DATASET_BYTES {
            return Err(LoadError::Invalid(format!("dataset is {} bytes; the limit is {MAX_DATASET_BYTES}", raw.len())));
        }
        let (columns, rows) = match format {
            DatasetFormat::Csv => parse_csv(&raw)?,
            DatasetFormat::Json => parse_json(&raw)?,
        };
        if rows.is_empty() {
            return Err(LoadError::Invalid("dataset has no rows".into()));
        }
        let sha256 = hex::encode(Sha256::digest(&raw));
        Ok(Dataset { format, columns, rows, sha256, sensitive_columns: vec![], raw })
    }

    /// Mark columns as sensitive. Unknown names are rejected so a typo never
    /// silently leaves a secret column unredacted.
    pub fn with_sensitive_columns(mut self, cols: Vec<String>) -> Result<Dataset, LoadError> {
        if let Some(c) = cols.iter().find(|c| !self.columns.contains(c)) {
            return Err(LoadError::Invalid(format!("dataset has no column named '{c}' (listed as sensitive)")));
        }
        self.sensitive_columns = cols;
        Ok(self)
    }

    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    /// Row used by iteration `iteration` (rows cycle in order).
    pub fn row_index(&self, iteration: u64) -> usize {
        (iteration % self.rows.len() as u64) as usize
    }

    pub fn row_layer(&self, iteration: u64) -> VarLayer {
        let i = self.row_index(iteration);
        let vars = self
            .columns
            .iter()
            .zip(&self.rows[i])
            .filter_map(|(c, v)| {
                v.as_ref().map(|v| VarEntry { name: c.clone(), value: v.clone(), secret: self.sensitive_columns.contains(c) })
            })
            .collect();
        VarLayer { label: format!("dataset row {}", i + 1), vars }
    }
}

type Parsed = (Vec<String>, Vec<Vec<Option<String>>>);

fn check_columns(cols: &[String]) -> Result<(), LoadError> {
    if cols.len() > MAX_COLUMNS {
        return Err(LoadError::Invalid(format!("dataset has {} columns; the limit is {MAX_COLUMNS}", cols.len())));
    }
    for (i, c) in cols.iter().enumerate() {
        if c.is_empty() {
            return Err(LoadError::Invalid(format!("dataset column {} has an empty name", i + 1)));
        }
        if c.contains("{{") || c.contains("}}") {
            return Err(LoadError::Invalid(format!("dataset column '{c}' contains template braces")));
        }
        if cols[..i].contains(c) {
            return Err(LoadError::Invalid(format!("dataset column '{c}' is duplicated")));
        }
    }
    Ok(())
}

fn parse_csv(raw: &[u8]) -> Result<Parsed, LoadError> {
    let mut rdr = csv::ReaderBuilder::new().has_headers(true).flexible(false).from_reader(raw);
    let headers = rdr.headers().map_err(|e| LoadError::Invalid(format!("dataset CSV header: {e}")))?;
    let columns: Vec<String> = headers.iter().map(|h| h.trim().to_string()).collect();
    check_columns(&columns)?;
    let mut rows = Vec::new();
    for (i, rec) in rdr.records().enumerate() {
        let rec = rec.map_err(|e| LoadError::Invalid(format!("dataset CSV row {}: {e}", i + 1)))?;
        if rows.len() >= MAX_ROWS {
            return Err(LoadError::Invalid(format!("dataset has more than {MAX_ROWS} rows")));
        }
        rows.push(rec.iter().map(|v| Some(v.to_string())).collect());
    }
    Ok((columns, rows))
}

fn parse_json(raw: &[u8]) -> Result<Parsed, LoadError> {
    let v: serde_json::Value = serde_json::from_slice(raw).map_err(|e| LoadError::Invalid(format!("dataset JSON: {e}")))?;
    let arr = v.as_array().ok_or_else(|| LoadError::Invalid("dataset JSON must be an array of objects".into()))?;
    if arr.len() > MAX_ROWS {
        return Err(LoadError::Invalid(format!("dataset has more than {MAX_ROWS} rows")));
    }
    let mut columns: Vec<String> = Vec::new();
    for (i, row) in arr.iter().enumerate() {
        let obj = row.as_object().ok_or_else(|| LoadError::Invalid(format!("dataset JSON row {} is not an object", i + 1)))?;
        for k in obj.keys() {
            if !columns.contains(k) {
                columns.push(k.clone());
                if columns.len() > MAX_COLUMNS {
                    return Err(LoadError::Invalid(format!("dataset has more than {MAX_COLUMNS} distinct keys")));
                }
            }
        }
    }
    check_columns(&columns)?;
    let rows = arr
        .iter()
        .map(|row| {
            let obj = row.as_object().expect("checked above");
            columns
                .iter()
                .map(|c| {
                    obj.get(c).map(|v| match v {
                        serde_json::Value::String(s) => s.clone(),
                        serde_json::Value::Null => String::new(),
                        other => other.to_string(),
                    })
                })
                .collect()
        })
        .collect();
    Ok((columns, rows))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_rows_cycle_and_hash_is_of_exact_bytes() {
        let d = Dataset::parse(DatasetFormat::Csv, b"user,token\nalice,a1\nbob,b2\n".to_vec()).unwrap();
        assert_eq!(d.columns, vec!["user", "token"]);
        assert_eq!(d.rows.len(), 2);
        let l = d.row_layer(3);
        assert_eq!(l.vars[0].value, "bob");
        assert_eq!(d.sha256, hex::encode(Sha256::digest(b"user,token\nalice,a1\nbob,b2\n")));
    }

    #[test]
    fn json_rows_stringify_scalars_and_keep_missing_keys_undefined() {
        let d = Dataset::parse(DatasetFormat::Json, br#"[{"id":1,"name":"x","ok":true},{"id":2}]"#.to_vec()).unwrap();
        assert_eq!(d.columns, vec!["id", "name", "ok"]);
        let l0 = d.row_layer(0);
        assert_eq!(l0.vars.iter().map(|v| v.value.as_str()).collect::<Vec<_>>(), vec!["1", "x", "true"]);
        let l1 = d.row_layer(1);
        assert_eq!(l1.vars.len(), 1, "absent keys are not defined as empty strings");
    }

    #[test]
    fn invalid_datasets_are_rejected() {
        assert!(Dataset::parse(DatasetFormat::Csv, b"a,a\n1,2\n".to_vec()).is_err());
        assert!(Dataset::parse(DatasetFormat::Csv, b"a,b\n".to_vec()).is_err());
        assert!(Dataset::parse(DatasetFormat::Csv, b"a,b\n1\n".to_vec()).is_err());
        assert!(Dataset::parse(DatasetFormat::Json, br#"{"a":1}"#.to_vec()).is_err());
        assert!(Dataset::parse(DatasetFormat::Json, br#"[1,2]"#.to_vec()).is_err());
    }

    #[test]
    fn sensitive_columns_are_secret_in_row_layers() {
        let d = Dataset::parse(DatasetFormat::Csv, b"user,token\nann,t-111\nbob,t-222\n".to_vec())
            .unwrap()
            .with_sensitive_columns(vec!["token".into()])
            .unwrap();
        let l = d.row_layer(1);
        assert!(l.vars.iter().any(|v| v.name == "token" && v.secret && v.value == "t-222"));
        assert!(l.vars.iter().any(|v| v.name == "user" && !v.secret));
        let bad = Dataset::parse(DatasetFormat::Csv, b"user\nann\n".to_vec()).unwrap().with_sensitive_columns(vec!["tokn".into()]);
        assert!(bad.is_err(), "a misspelled sensitive column is refused");
    }
}
