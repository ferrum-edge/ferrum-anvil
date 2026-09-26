//! Run datasets: CSV (header row + records) or a JSON array of flat objects.
//!
//! Parsing is shared with the load engine (`anvil_load::dataset`); the runner
//! applies tighter bounds (a collection run keeps a summary per step) and
//! treats `sensitive_columns` as secrets: their values are marked secret in
//! the variable layer (so the engine redacts them from the record), scrubbed
//! from the report, and never written to the report themselves.

use crate::RunError;
use anvil_domain::runner::RunDatasetSummary;
use anvil_domain::workspace::DatasetFormat;
use anvil_engine::vars::{VarEntry, VarLayer};

/// Largest dataset accepted by the runner.
pub const MAX_DATASET_BYTES: usize = 16 * 1024 * 1024;
/// Most rows accepted by the runner (iterations are capped separately).
pub const MAX_DATASET_ROWS: usize = 100_000;

#[derive(Debug, Clone)]
pub struct RunDataset {
    pub name: String,
    pub format: DatasetFormat,
    pub columns: Vec<String>,
    /// Row cells aligned with `columns`; `None` = key absent in that JSON row
    /// (the variable is then not defined by the dataset for that row).
    pub rows: Vec<Vec<Option<String>>>,
    pub sha256: String,
    /// Sensitive columns that exist in the dataset.
    pub sensitive_columns: Vec<String>,
    /// Sensitive columns that were requested but do not exist.
    pub missing_sensitive_columns: Vec<String>,
}

impl RunDataset {
    /// Parse and bound a dataset. Errors are user-facing and never include
    /// cell values.
    pub fn parse(name: &str, format: DatasetFormat, bytes: &[u8], sensitive_columns: &[String]) -> Result<RunDataset, RunError> {
        if bytes.len() > MAX_DATASET_BYTES {
            return Err(RunError::Dataset(format!(
                "'{name}' is {} bytes; the collection runner accepts at most {MAX_DATASET_BYTES} bytes",
                bytes.len()
            )));
        }
        let lf = match format {
            DatasetFormat::Csv => anvil_load::DatasetFormat::Csv,
            DatasetFormat::Json => anvil_load::DatasetFormat::Json,
        };
        let parsed = anvil_load::Dataset::parse(lf, bytes.to_vec()).map_err(|e| {
            let msg = e.to_string();
            RunError::Dataset(format!("'{name}': {}", msg.strip_prefix("invalid load plan: ").unwrap_or(&msg)))
        })?;
        if parsed.rows.len() > MAX_DATASET_ROWS {
            return Err(RunError::Dataset(format!(
                "'{name}' has {} rows; the collection runner accepts at most {MAX_DATASET_ROWS}",
                parsed.rows.len()
            )));
        }
        let mut sensitive = Vec::new();
        let mut missing = Vec::new();
        for c in sensitive_columns {
            let c = c.trim();
            if c.is_empty() {
                continue;
            }
            match parsed.columns.iter().find(|x| x.as_str() == c) {
                Some(x) if !sensitive.contains(x) => sensitive.push(x.clone()),
                Some(_) => {}
                None => missing.push(c.to_string()),
            }
        }
        Ok(RunDataset {
            name: name.to_string(),
            format,
            columns: parsed.columns.clone(),
            rows: parsed.rows.clone(),
            sha256: parsed.sha256.clone(),
            sensitive_columns: sensitive,
            missing_sensitive_columns: missing,
        })
    }

    /// Infer the format from a file name (`.csv` / `.json`).
    pub fn format_for_path(path: &str) -> Option<DatasetFormat> {
        let lower = path.to_ascii_lowercase();
        if lower.ends_with(".csv") {
            Some(DatasetFormat::Csv)
        } else if lower.ends_with(".json") {
            Some(DatasetFormat::Json)
        } else {
            None
        }
    }

    pub fn row_count(&self) -> usize {
        self.rows.len()
    }

    /// 0-based row used by iteration `iteration` (rows cycle in order).
    pub fn row_index(&self, iteration: u32) -> usize {
        iteration as usize % self.rows.len().max(1)
    }

    pub fn is_sensitive(&self, column: &str) -> bool {
        self.sensitive_columns.iter().any(|c| c == column)
    }

    /// Variable layer for an iteration: sensitive columns are secret entries.
    pub fn row_layer(&self, iteration: u32) -> VarLayer {
        let i = self.row_index(iteration);
        let vars = self
            .columns
            .iter()
            .zip(&self.rows[i])
            .filter_map(|(c, v)| v.as_ref().map(|v| VarEntry { name: c.clone(), value: v.clone(), secret: self.is_sensitive(c) }))
            .collect();
        VarLayer { label: format!("dataset '{}' row {}", self.name, i + 1), vars }
    }

    /// Sensitive values of a row (for exact-value redaction).
    pub fn sensitive_values(&self, iteration: u32) -> Vec<String> {
        let i = self.row_index(iteration);
        self.columns
            .iter()
            .zip(&self.rows[i])
            .filter(|(c, _)| self.is_sensitive(c))
            .filter_map(|(_, v)| v.clone())
            .filter(|v| !v.is_empty())
            .collect()
    }

    pub fn summary(&self) -> RunDatasetSummary {
        RunDatasetSummary {
            name: self.name.clone(),
            format: self.format,
            sha256: self.sha256.clone(),
            rows: self.rows.len() as u32,
            columns: self.columns.clone(),
            sensitive_columns: self.sensitive_columns.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_sensitive_columns_become_secret_entries() {
        let d = RunDataset::parse("users", DatasetFormat::Csv, b"user,password\nalice,pw-alice-1\nbob,pw-bob-22\n", &["password".into()])
            .unwrap();
        let l = d.row_layer(1);
        assert_eq!(l.vars.len(), 2);
        assert!(!l.vars[0].secret && l.vars[1].secret);
        assert_eq!(l.vars[1].value, "pw-bob-22");
        assert_eq!(d.sensitive_values(2), vec!["pw-alice-1".to_string()], "rows cycle");
        assert!(l.label.contains("row 2"));
    }

    #[test]
    fn missing_sensitive_column_is_reported_not_ignored() {
        let d = RunDataset::parse("x", DatasetFormat::Json, br#"[{"a":1}]"#, &["secret_col".into()]).unwrap();
        assert!(d.sensitive_columns.is_empty());
        assert_eq!(d.missing_sensitive_columns, vec!["secret_col".to_string()]);
    }

    #[test]
    fn invalid_and_oversized_datasets_have_clear_errors() {
        let e = RunDataset::parse("bad", DatasetFormat::Json, br#"{"a":1}"#, &[]).unwrap_err().to_string();
        assert!(e.contains("bad") && e.contains("array of objects"), "{e}");
        let e = RunDataset::parse("empty", DatasetFormat::Csv, b"a,b\n", &[]).unwrap_err().to_string();
        assert!(e.contains("no rows"), "{e}");
        let big = vec![b'a'; MAX_DATASET_BYTES + 1];
        let e = RunDataset::parse("big", DatasetFormat::Csv, &big, &[]).unwrap_err().to_string();
        assert!(e.contains("at most"), "{e}");
        assert_eq!(RunDataset::format_for_path("rows.CSV"), Some(DatasetFormat::Csv));
        assert_eq!(RunDataset::format_for_path("rows.txt"), None);
    }
}
