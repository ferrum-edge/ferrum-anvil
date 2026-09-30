//! CSV / JSON datasets: one row per iteration (cycling), injected as an
//! iteration-scoped variable layer. The SHA-256 of the exact dataset bytes is
//! recorded in the report so runs over different data are never compared as
//! equivalent.

use crate::LoadError;
use anvil_engine::vars::{VarEntry, VarLayer};
use serde::{Deserialize, Serialize, de::DeserializeSeed};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;

pub const MAX_DATASET_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_ROWS: usize = 1_000_000;
pub const MAX_COLUMNS: usize = 256;
pub const MAX_CELL_BYTES: usize = 1024 * 1024;
/// Most cells (rows × columns) a parsed dataset may hold. Every row keeps a
/// slot for every column, present or not, so the row and column limits alone
/// would let a few megabytes of mostly empty JSON objects (or of empty CSV
/// fields) expand into gigabytes. Checked before the stored matrix grows past it.
pub const MAX_CELLS: usize = 4 * 1024 * 1024;

/// Bounds a caller applies while a dataset is parsed, before rows are added
/// to the stored dataset. Each is capped at this module's global limit, so a
/// caller can only tighten them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DatasetLimits {
    pub max_rows: usize,
    pub max_cells: usize,
}

impl Default for DatasetLimits {
    fn default() -> Self {
        DatasetLimits { max_rows: MAX_ROWS, max_cells: MAX_CELLS }
    }
}

impl DatasetLimits {
    fn capped(self) -> DatasetLimits {
        DatasetLimits { max_rows: self.max_rows.min(MAX_ROWS), max_cells: self.max_cells.min(MAX_CELLS) }
    }
}

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
        Dataset::parse_with_limits(format, bytes, DatasetLimits::default())
    }

    /// Parse under a caller's own bounds (the collection runner's tighter row
    /// limit, say). They are enforced while parsing, before rows are built.
    pub fn parse_with_limits(format: DatasetFormat, bytes: impl Into<Arc<[u8]>>, limits: DatasetLimits) -> Result<Dataset, LoadError> {
        let limits = limits.capped();
        let raw: Arc<[u8]> = bytes.into();
        if raw.len() > MAX_DATASET_BYTES {
            return Err(LoadError::Invalid(format!("dataset is {} bytes; the limit is {MAX_DATASET_BYTES}", raw.len())));
        }
        let (columns, rows) = match format {
            DatasetFormat::Csv => parse_csv(&raw, limits)?,
            DatasetFormat::Json => parse_json(&raw, limits)?,
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

fn check_column_name(column: &str, index: usize) -> Result<(), LoadError> {
    if column.is_empty() {
        return Err(LoadError::Invalid(format!("dataset column {} has an empty name", index + 1)));
    }
    if column.contains("{{") || column.contains("}}") {
        return Err(LoadError::Invalid(format!("dataset column '{column}' contains template braces")));
    }
    Ok(())
}

fn check_columns(cols: &[String]) -> Result<(), LoadError> {
    if cols.len() > MAX_COLUMNS {
        return Err(LoadError::Invalid(format!("dataset has {} columns; the limit is {MAX_COLUMNS}", cols.len())));
    }
    let mut indexes = HashMap::with_capacity(cols.len());
    for (index, column) in cols.iter().enumerate() {
        check_column_name(column, index)?;
        if indexes.insert(column.as_str(), index).is_some() {
            return Err(LoadError::Invalid(format!("dataset column '{column}' is duplicated")));
        }
    }
    Ok(())
}

fn load_error_message(error: LoadError) -> String {
    match error {
        LoadError::Invalid(message) => message,
        error => error.to_string(),
    }
}

/// Refuse a matrix of `rows` × `columns` cells over the budget. Error text
/// carries only counts, never cell values.
fn check_cells(rows: usize, columns: usize, limits: DatasetLimits) -> Result<(), LoadError> {
    match rows.checked_mul(columns) {
        Some(cells) if cells <= limits.max_cells => Ok(()),
        _ => Err(LoadError::Invalid(format!(
            "dataset has {rows} rows of {columns} columns; the limit is {} cells (rows × columns)",
            limits.max_cells
        ))),
    }
}

fn parse_csv(raw: &[u8], limits: DatasetLimits) -> Result<Parsed, LoadError> {
    let mut rdr = csv::ReaderBuilder::new().has_headers(true).flexible(false).from_reader(raw);
    let headers = rdr.headers().map_err(|e| LoadError::Invalid(format!("dataset CSV header: {e}")))?;
    let columns: Vec<String> = headers.iter().map(|h| h.trim().to_string()).collect();
    check_columns(&columns)?;
    let mut rows = Vec::new();
    for (i, rec) in rdr.records().enumerate() {
        let rec = rec.map_err(|e| LoadError::Invalid(format!("dataset CSV row {}: {e}", i + 1)))?;
        if rows.len() >= limits.max_rows {
            return Err(LoadError::Invalid(format!("dataset has more than {} rows", limits.max_rows)));
        }
        check_cells(rows.len() + 1, columns.len(), limits)?;
        rows.push(rec.iter().map(|v| Some(v.to_string())).collect());
    }
    Ok((columns, rows))
}

fn parse_json(raw: &[u8], limits: DatasetLimits) -> Result<Parsed, LoadError> {
    let mut columns = Vec::new();
    let mut column_indexes: HashMap<String, usize> = HashMap::new();
    let mut rows = Vec::new();
    let mut deserializer = serde_json::Deserializer::from_slice(raw);
    JsonDatasetSeed { limits, columns: &mut columns, column_indexes: &mut column_indexes, rows: &mut rows }
        .deserialize(&mut deserializer)
        .map_err(|e| LoadError::Invalid(format!("dataset JSON: {e}")))?;
    deserializer.end().map_err(|e| LoadError::Invalid(format!("dataset JSON: {e}")))?;
    Ok((columns, rows))
}

struct JsonDatasetSeed<'a> {
    limits: DatasetLimits,
    columns: &'a mut Vec<String>,
    column_indexes: &'a mut HashMap<String, usize>,
    rows: &'a mut Vec<Vec<Option<String>>>,
}

impl<'de> serde::de::DeserializeSeed<'de> for JsonDatasetSeed<'_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_seq(JsonDatasetVisitor {
            limits: self.limits,
            columns: self.columns,
            column_indexes: self.column_indexes,
            rows: self.rows,
        })
    }
}

struct JsonDatasetVisitor<'a> {
    limits: DatasetLimits,
    columns: &'a mut Vec<String>,
    column_indexes: &'a mut HashMap<String, usize>,
    rows: &'a mut Vec<Vec<Option<String>>>,
}

impl<'de> serde::de::Visitor<'de> for JsonDatasetVisitor<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("an array of objects")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        use serde::de::Error;
        while let Some(row) = seq.next_element_seed(JsonRowSeed {
            row_number: self.rows.len() + 1,
            reject: self.rows.len() >= self.limits.max_rows,
            max_rows: self.limits.max_rows,
        })? {
            let row_index = self.rows.len() + 1;
            for (key, _) in &row {
                if self.column_indexes.contains_key(key) {
                    continue;
                }
                if self.columns.len() >= MAX_COLUMNS {
                    return Err(serde::de::Error::custom(format!("dataset has more than {MAX_COLUMNS} distinct keys")));
                }
                check_column_name(key, self.columns.len()).map_err(|e| A::Error::custom(load_error_message(e)))?;
                check_cells(row_index, self.columns.len() + 1, self.limits).map_err(|e| A::Error::custom(load_error_message(e)))?;
                let index = self.columns.len();
                self.columns.push(key.clone());
                self.column_indexes.insert(key.clone(), index);
                for previous in self.rows.iter_mut() {
                    previous.push(None);
                }
            }
            check_cells(row_index, self.columns.len(), self.limits).map_err(|e| A::Error::custom(load_error_message(e)))?;
            let mut values = vec![None; self.columns.len()];
            for (key, value) in row {
                let index = *self.column_indexes.get(&key).expect("row key was added as a column");
                values[index] = Some(value);
            }
            self.rows.push(values);
        }
        Ok(())
    }
}

struct JsonRowSeed {
    row_number: usize,
    reject: bool,
    max_rows: usize,
}

impl<'de> serde::de::DeserializeSeed<'de> for JsonRowSeed {
    type Value = Vec<(String, String)>;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if self.reject {
            return Err(serde::de::Error::custom(format!("dataset has more than {} rows", self.max_rows)));
        }
        deserializer.deserialize_map(JsonRowVisitor { row_number: self.row_number })
    }
}

struct JsonRowVisitor {
    row_number: usize,
}

impl<'de> serde::de::Visitor<'de> for JsonRowVisitor {
    type Value = Vec<(String, String)>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "an object at row {}", self.row_number)
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        use serde::de::Error;
        let mut values: Vec<(String, String)> = Vec::new();
        let mut value_indexes: HashMap<String, usize> = HashMap::new();
        while let Some(key) = map.next_key::<String>()? {
            let raw = map.next_value::<&serde_json::value::RawValue>()?;
            if raw.get().len() > MAX_CELL_BYTES {
                return Err(A::Error::custom(format!("dataset JSON cell exceeds the 1 MiB limit ({MAX_CELL_BYTES} bytes)")));
            }
            let text = cell_text(raw.get()).map_err(A::Error::custom)?;
            if let Some(index) = value_indexes.get(&key) {
                values[*index].1 = text;
            } else {
                if values.len() >= MAX_COLUMNS {
                    return Err(A::Error::custom(format!("dataset has more than {MAX_COLUMNS} distinct keys")));
                }
                let index = values.len();
                value_indexes.insert(key.clone(), index);
                values.push((key, text));
            }
        }
        Ok(values)
    }
}

fn cell_text(raw: &str) -> Result<String, &'static str> {
    if raw == "null" {
        Ok(String::new())
    } else if raw.starts_with('"') {
        serde_json::from_str(raw).map_err(|_| "dataset JSON contains an invalid string cell")
    } else {
        Ok(compact_json(raw))
    }
}

/// Remove insignificant JSON whitespace without materializing a nested Value tree.
fn compact_json(raw: &str) -> String {
    let mut compact = String::with_capacity(raw.len());
    let mut in_string = false;
    let mut escaped = false;
    for ch in raw.chars() {
        if in_string {
            compact.push(ch);
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
        } else if ch == '"' {
            in_string = true;
            compact.push(ch);
        } else if !ch.is_ascii_whitespace() {
            compact.push(ch);
        }
    }
    compact
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

    /// One object with every column, then empty objects: a small file whose
    /// rows would each still get a slot for every column.
    fn sparse_wide_json(rows: usize) -> Vec<u8> {
        let wide: Vec<String> = (0..MAX_COLUMNS).map(|i| format!("\"c{i}\":1")).collect();
        let mut s = format!("[{{{}}}", wide.join(","));
        for _ in 1..rows {
            s.push_str(",{}");
        }
        s.push(']');
        s.into_bytes()
    }

    #[test]
    fn sparse_json_is_refused_before_it_expands_into_a_dense_matrix() {
        let bytes = sparse_wide_json(MAX_CELLS / MAX_COLUMNS + 1);
        assert!(bytes.len() < 1024 * 1024, "the input stays small: {} bytes", bytes.len());
        let e = Dataset::parse(DatasetFormat::Json, bytes.clone()).unwrap_err().to_string();
        assert!(e.contains("cells"), "{e}");
        // A caller can only tighten the bounds, never loosen them.
        let loose = DatasetLimits { max_rows: usize::MAX, max_cells: usize::MAX };
        let e = Dataset::parse_with_limits(DatasetFormat::Json, bytes, loose).unwrap_err().to_string();
        assert!(e.contains("cells"), "{e}");
    }

    #[test]
    fn large_object_array_stops_at_the_row_limit() {
        let bytes = format!("[{{}}{}]", ",{}".repeat(MAX_ROWS)).into_bytes();
        let e = Dataset::parse(DatasetFormat::Json, bytes).unwrap_err().to_string();
        assert!(e.contains("more than 1000000 rows"), "{e}");
    }

    #[test]
    fn scalar_json_rows_are_refused_with_the_row_number() {
        let e = Dataset::parse(DatasetFormat::Json, b"[0]".to_vec()).unwrap_err().to_string();
        assert!(e.contains("row 1"), "{e}");
        assert!(e.contains("an object"), "{e}");
    }

    #[test]
    fn json_cells_have_a_clear_size_limit() {
        let oversized = "x".repeat(MAX_CELL_BYTES);
        let bytes = serde_json::to_vec(&vec![serde_json::json!({"cell": oversized})]).unwrap();
        let e = Dataset::parse(DatasetFormat::Json, bytes).unwrap_err().to_string();
        assert!(e.contains("cell exceeds the 1 MiB limit"), "{e}");
    }

    /// Parse under a caller's bounds of 3 rows and 6 cells.
    fn limited(format: DatasetFormat, bytes: &[u8]) -> Result<Dataset, LoadError> {
        Dataset::parse_with_limits(format, bytes.to_vec(), DatasetLimits { max_rows: 3, max_cells: 6 })
    }

    #[test]
    fn caller_limits_apply_while_parsing() {
        let s = |v: &str| Some(v.to_string());
        // Within both bounds: a key missing from a row stays undefined.
        let d = limited(DatasetFormat::Json, br#"[{"a":1,"b":2},{},{"b":"x"}]"#).unwrap();
        assert_eq!(d.rows, vec![vec![s("1"), s("2")], vec![None, None], vec![None, s("x")]]);
        assert_eq!(limited(DatasetFormat::Csv, b"a,b\n1,2\n3,4\n5,6\n").unwrap().rows.len(), 3);
        // More rows than this caller accepts.
        let e = limited(DatasetFormat::Json, br#"[{},{},{},{}]"#).unwrap_err().to_string();
        assert!(e.contains("more than 3 rows"), "{e}");
        let e = limited(DatasetFormat::Csv, b"a\n1\n2\n3\n4\n").unwrap_err().to_string();
        assert!(e.contains("more than 3 rows"), "{e}");
        // Within the row bound, over the cell budget.
        let e = limited(DatasetFormat::Json, br#"[{"a":1,"b":2,"c":3},{},{}]"#).unwrap_err().to_string();
        assert!(e.contains("cells"), "{e}");
        let e = limited(DatasetFormat::Csv, b"a,b,c\n1,2,3\n4,5,6\n7,8,9\n").unwrap_err().to_string();
        assert!(e.contains("cells"), "{e}");
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
