//! Linked local files (`AttachmentRef::LinkedFile`) the user chose in the
//! desktop's native open dialog.
//!
//! A linked file is a path on one machine. A reference that arrives any other
//! way, for example in an imported bundle, was never chosen on this device,
//! so it stays inert: a request, gRPC schema or dataset that names it is
//! refused before anything is read or sent. It becomes usable only once the
//! user picks that same file in the native dialog (`file_choose` with purpose
//! `linked_file`), which binds its canonical path in the vault. Bindings are
//! device-specific: they are not exported, and an import cannot create one.
//! The CLI has no dialog, so it never reads a linked file.

use crate::{App, AppError, Result};
use anvil_domain::Id;
use anvil_domain::request::RequestSpec;
use anvil_storage::store::kind;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::path::Path;

/// A linked file bound through the native dialog.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkedFileBinding {
    pub id: Id,
    /// Canonical absolute path of the chosen file.
    pub path: String,
    pub bound_at: DateTime<Utc>,
}

impl App {
    /// Bind the linked file the user picked in the native open dialog. Only
    /// the desktop's `file_choose` calls this, with the dialog's result.
    pub fn bind_linked_file(&self, picked: &Path) -> Result<LinkedFileBinding> {
        let path = crate::token_files::chosen_path(picked, "linked file")?;
        if let Some(b) = self.linked_file_bindings()?.into_iter().find(|b| b.path == path) {
            return Ok(b);
        }
        let b = LinkedFileBinding { id: Id::new(), path, bound_at: Utc::now() };
        self.store.put(kind::LINKED_FILE, &b.id, None, None, 0.0, &b)?;
        Ok(b)
    }

    pub fn linked_file_bindings(&self) -> Result<Vec<LinkedFileBinding>> {
        Ok(self.store.list(kind::LINKED_FILE, None)?)
    }

    /// The linked files `spec` names, refusing any that was not chosen on
    /// this device.
    pub(crate) fn bound_linked_files(&self, spec: &RequestSpec) -> Result<Vec<String>> {
        let mut paths = Vec::new();
        linked_paths(&serde_json::to_value(spec)?, &mut paths);
        if !paths.is_empty() {
            let bound = self.linked_file_bindings()?;
            for p in &paths {
                refuse_unbound(&bound, p)?;
            }
        }
        Ok(paths)
    }

    /// Read a linked file, refusing it unless it was chosen on this device.
    /// `what` names it in errors ("dataset").
    pub(crate) fn read_linked_file(&self, path: &str, max: u64, what: &str) -> Result<Vec<u8>> {
        refuse_unbound(&self.linked_file_bindings()?, path)?;
        read_bound_file(path, max, what)
    }
}

fn refuse_unbound(bound: &[LinkedFileBinding], path: &str) -> Result<()> {
    if bound.iter().any(|b| b.path == path) {
        return Ok(());
    }
    Err(AppError::Invalid(format!(
        "the linked local file '{path}' was not chosen on this device; choose that file on this device, or attach it instead"
    )))
}

/// Read a bound linked file, bounded to `max` bytes. Only a regular file is
/// opened, and only while its path still resolves to itself, so a file or
/// folder on the path replaced by a link is refused.
pub(crate) fn read_bound_file(path: &str, max: u64, what: &str) -> Result<Vec<u8>> {
    let too_large = || AppError::Invalid(format!("the linked {what} is larger than {} MiB", max >> 20));
    let not_regular = || AppError::Invalid(format!("the linked {what} is not a regular file"));
    if std::fs::canonicalize(path)?.to_str() != Some(path) {
        return Err(AppError::Invalid(format!("the linked {what} changed after it was chosen; choose it again")));
    }
    // Checked before opening, so a FIFO or device is never opened.
    if !std::fs::metadata(path)?.is_file() {
        return Err(not_regular());
    }
    let file = std::fs::File::open(path)?;
    // The checks that count are on the opened handle, not on the path.
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(not_regular());
    }
    if meta.len() > max {
        return Err(too_large());
    }
    let mut bytes = Vec::new();
    file.take(max + 1).read_to_end(&mut bytes)?;
    // Bounded even if the file grows while it is read.
    if bytes.len() as u64 > max {
        return Err(too_large());
    }
    Ok(bytes)
}

/// Paths of every linked file referenced anywhere in a serialized spec.
fn linked_paths(v: &serde_json::Value, out: &mut Vec<String>) {
    match v {
        serde_json::Value::Object(o) => {
            if o.get("kind").and_then(|k| k.as_str()) == Some("linked_file") {
                let path = o.get("path").and_then(|p| p.as_str()).unwrap_or_default();
                if !out.iter().any(|p| p == path) {
                    out.push(path.to_string());
                }
            }
            o.values().for_each(|x| linked_paths(x, out));
        }
        serde_json::Value::Array(a) => a.iter().for_each(|x| linked_paths(x, out)),
        _ => {}
    }
}
