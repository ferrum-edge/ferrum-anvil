//! A parsed OpenAPI description: the document, its dialect and source
//! positions, plus bounded internal `$ref` resolution.

use crate::locate::{Locator, Position};
use anvil_import::{Dialect, ImportError, ImportOptions, Syntax};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::sync::{Mutex, OnceLock};

/// Longest `$ref` chain followed from one location. Every walk over the
/// document is itself bounded (by its targets and nesting), so each
/// resolution is bounded work and a parsed spec can serve many analyses.
pub const MAX_REF_DEPTH: usize = 32;
/// Longest member name accepted.
pub const MAX_KEY_BYTES: usize = 4 * 1024;
/// The JSON Pointers of all members together, at most. Positions, targets
/// and labels keep one pointer (or a label of similar length) per member,
/// so this bounds them whatever the shape of the document.
pub const MAX_POINTER_BYTES: usize = 64 * 1024 * 1024;
/// Unresolvable references remembered for the report.
const MAX_UNRESOLVED: usize = 1_000;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SpecError {
    #[error("{0}")]
    Parse(#[from] ImportError),
    #[error("{0}")]
    TooComplex(String),
}

/// An OpenAPI 3.0/3.1/3.2 or Swagger 2.0 document.
#[derive(Debug)]
pub struct Spec {
    pub dialect: Dialect,
    pub declared_version: Option<String>,
    pub syntax: Syntax,
    pub root: Value,
    /// SHA-256 (hex) of the exact bytes parsed.
    pub sha256: String,
    pub size_bytes: u64,
    text: String,
    locator: OnceLock<Locator>,
    /// Locations of `$ref`s that could not be resolved (see [`Spec::unresolved`]).
    unresolved: Mutex<(BTreeSet<String>, usize)>,
}

impl Spec {
    /// Parse `bytes` under the importer's bounds (size, nodes, depth).
    /// Performs no I/O: external references are never fetched.
    pub fn parse(bytes: &[u8]) -> Result<Spec, SpecError> {
        let (detected, root) = anvil_import::parse_openapi(bytes, &ImportOptions::default())?;
        check_pointer_budget(&root)?;
        let text = String::from_utf8_lossy(bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes)).into_owned();
        Ok(Spec {
            dialect: detected.dialect,
            declared_version: detected.declared_version,
            syntax: detected.syntax,
            root,
            sha256: hex::encode(Sha256::digest(bytes)),
            size_bytes: bytes.len() as u64,
            text,
            locator: OnceLock::new(),
            unresolved: Mutex::new((BTreeSet::new(), 0)),
        })
    }

    pub fn is_swagger2(&self) -> bool {
        self.dialect == Dialect::Swagger20
    }

    pub fn title(&self) -> Option<&str> {
        self.root.pointer("/info/title").and_then(Value::as_str)
    }

    pub fn version(&self) -> Option<String> {
        self.root.pointer("/info/version").map(|v| match v {
            Value::String(s) => s.clone(),
            other => other.to_string(),
        })
    }

    /// Line and column of `pointer` (or its nearest ancestor) in the source.
    pub fn position(&self, pointer: &str) -> Option<Position> {
        self.locator.get_or_init(|| Locator::new(&self.text, self.syntax)).position(pointer)
    }

    /// The source text as parsed (UTF-8, byte-order mark removed).
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Follow internal `$ref` chains from `v` (at `at`). Returns the first
    /// non-reference value and its pointer, or `None` for an external,
    /// dangling, cyclic or too deep reference (remembered in
    /// [`Spec::unresolved`]).
    pub fn resolve<'a>(&'a self, v: &'a Value, at: &str) -> Option<(&'a Value, String)> {
        let found = self.follow(v, at);
        if found.is_none() {
            self.note_unresolved(at);
        }
        found
    }

    fn follow<'a>(&'a self, v: &'a Value, at: &str) -> Option<(&'a Value, String)> {
        let mut cur = v;
        let mut cur_ptr = at.to_string();
        for _ in 0..MAX_REF_DEPTH {
            let Some(r) = cur.get("$ref").and_then(Value::as_str) else {
                return Some((cur, cur_ptr));
            };
            let target = internal_pointer(r)?;
            cur = self.root.pointer(&target)?;
            cur_ptr = target;
        }
        None
    }

    fn note_unresolved(&self, at: &str) {
        let Ok(mut u) = self.unresolved.lock() else { return };
        if u.0.len() < MAX_UNRESOLVED {
            if u.0.insert(at.to_string()) {
                u.1 += 1;
            }
        } else if !u.0.contains(at) {
            u.1 += 1;
        }
    }

    /// Resolve `v` and return the resolved value, or `v` itself when it is not
    /// a resolvable reference (then still a `{"$ref": …}` object: callers
    /// that need the referenced object skip it, see [`Spec::usable`]).
    pub fn deref<'a>(&'a self, v: &'a Value, at: &str) -> (&'a Value, String) {
        self.resolve(v, at).unwrap_or((v, at.to_string()))
    }

    /// `v` resolved, or `None` when it is a reference that cannot be.
    pub fn usable<'a>(&'a self, v: &'a Value, at: &str) -> Option<(&'a Value, String)> {
        self.resolve(v, at)
    }

    /// Locations of `$ref`s that could not be followed so far (at most
    /// 1,000), and how many distinct ones there were. Objects behind them
    /// are left out of every analysis instead of being checked as `$ref`s.
    pub fn unresolved(&self) -> (Vec<String>, usize) {
        match self.unresolved.lock() {
            Ok(u) => (u.0.iter().cloned().collect(), u.1),
            Err(_) => (vec![], 0),
        }
    }
}

/// Refuse a document whose member names, as JSON Pointers, would take more
/// than [`MAX_POINTER_BYTES`] (or that has a name over [`MAX_KEY_BYTES`]).
fn check_pointer_budget(root: &Value) -> Result<(), SpecError> {
    let mut total = 0usize;
    // (value, length of its pointer)
    let mut stack: Vec<(&Value, usize)> = vec![(root, 0)];
    while let Some((v, len)) = stack.pop() {
        match v {
            Value::Object(o) => {
                for (k, child) in o {
                    if k.len() > MAX_KEY_BYTES {
                        return Err(SpecError::TooComplex(format!(
                            "a member name is {} bytes long; the limit is {MAX_KEY_BYTES}",
                            k.len()
                        )));
                    }
                    let child_len = len + 1 + k.len();
                    total += child_len;
                    if total > MAX_POINTER_BYTES {
                        return Err(SpecError::TooComplex(format!(
                            "the document's member names are too long for how deeply they nest (more than {} MiB of paths)",
                            MAX_POINTER_BYTES >> 20
                        )));
                    }
                    stack.push((child, child_len));
                }
            }
            Value::Array(a) => {
                for (i, child) in a.iter().enumerate() {
                    let child_len = len + 1 + i.to_string().len();
                    total += child_len;
                    if total > MAX_POINTER_BYTES {
                        return Err(SpecError::TooComplex(format!(
                            "the document's member names are too long for how deeply they nest (more than {} MiB of paths)",
                            MAX_POINTER_BYTES >> 20
                        )));
                    }
                    stack.push((child, child_len));
                }
            }
            _ => {}
        }
    }
    Ok(())
}

/// The JSON pointer of an internal reference (`#/a/b`), percent-decoded.
pub fn internal_pointer(r: &str) -> Option<String> {
    let frag = r.strip_prefix('#')?;
    if !(frag.is_empty() || frag.starts_with('/')) {
        return None;
    }
    Some(percent_decode(frag))
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(h), Some(l)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2]))
        {
            out.push(h * 16 + l);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    (b as char).to_digit(16).map(|d| d as u8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_internal_chains_and_refuses_the_rest() {
        let spec = Spec::parse(
            br##"{"openapi":"3.1.0","info":{"title":"t","version":"1"},"paths":{},
            "components":{"schemas":{"A":{"$ref":"#/components/schemas/B"},"B":{"type":"string"},
            "C":{"$ref":"#/components/schemas/C"},"D":{"$ref":"other.yaml#/X"},"E%20":{"type":"integer"},
            "F":{"$ref":"#/components/schemas/E%2520"}}}}"##,
        )
        .unwrap();
        let a = spec.root.pointer("/components/schemas/A").unwrap();
        let (v, p) = spec.resolve(a, "/components/schemas/A").unwrap();
        assert_eq!(v["type"], "string");
        assert_eq!(p, "/components/schemas/B");
        let c = spec.root.pointer("/components/schemas/C").unwrap();
        assert!(spec.resolve(c, "/components/schemas/C").is_none());
        let d = spec.root.pointer("/components/schemas/D").unwrap();
        assert!(spec.resolve(d, "/components/schemas/D").is_none());
        assert_eq!(spec.unresolved(), (vec!["/components/schemas/C".to_string(), "/components/schemas/D".to_string()], 2));
        let f = spec.root.pointer("/components/schemas/F").unwrap();
        assert_eq!(spec.resolve(f, "/components/schemas/F").unwrap().0["type"], "integer");
    }

    #[test]
    fn long_names_and_deep_long_paths_are_refused() {
        let long = format!(
            r#"{{"openapi":"3.1.0","info":{{"title":"t","version":"1"}},"paths":{{}},"x":{{"{}":1}}}}"#,
            "k".repeat(MAX_KEY_BYTES + 1)
        );
        assert!(matches!(Spec::parse(long.as_bytes()), Err(SpecError::TooComplex(_))));
        // Keys within the limit, nested so the paths add up past the budget.
        let key = "k".repeat(4000);
        let mut v = serde_json::json!(1);
        for _ in 0..100 {
            let wide: serde_json::Map<String, Value> =
                (0..200).map(|i| (format!("{key}{i}"), v.clone())).take(if v.is_object() { 1 } else { 200 }).collect();
            v = Value::Object(wide);
        }
        let doc = serde_json::json!({"openapi": "3.1.0", "info": {"title": "t", "version": "1"}, "paths": {}, "x": v});
        let text = doc.to_string();
        assert!(text.len() < 32 << 20);
        assert!(matches!(Spec::parse(text.as_bytes()), Err(SpecError::TooComplex(_))), "{} bytes", text.len());
    }

    #[test]
    fn refuses_other_formats() {
        assert!(
            Spec::parse(br#"{"info":{"_postman_id":"x","schema":"https://schema.getpostman.com/json/collection/v2.1.0/"},"item":[]}"#)
                .is_err()
        );
        assert!(Spec::parse(b"openapi: 4.0.0\ninfo: {}\n").is_err());
    }
}
