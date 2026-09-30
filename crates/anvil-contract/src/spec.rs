//! A parsed OpenAPI description: the document, its dialect and source
//! positions, plus bounded internal `$ref` resolution.

use crate::locate::{Locator, Position};
use anvil_import::{Dialect, ImportError, ImportOptions, Syntax};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Longest `$ref` chain followed from one location.
pub const MAX_REF_DEPTH: usize = 32;
/// `$ref` resolutions allowed per [`Spec`] (every analysis shares it).
pub const MAX_REF_RESOLUTIONS: usize = 250_000;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SpecError {
    #[error("{0}")]
    Parse(#[from] ImportError),
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
    refs_used: AtomicUsize,
}

impl Spec {
    /// Parse `bytes` under the importer's bounds (size, nodes, depth).
    /// Performs no I/O: external references are never fetched.
    pub fn parse(bytes: &[u8]) -> Result<Spec, SpecError> {
        let (detected, root) = anvil_import::parse_openapi(bytes, &ImportOptions::default())?;
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
            refs_used: AtomicUsize::new(0),
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
    /// dangling, cyclic or over-budget reference.
    pub fn resolve<'a>(&'a self, v: &'a Value, at: &str) -> Option<(&'a Value, String)> {
        let mut cur = v;
        let mut cur_ptr = at.to_string();
        for _ in 0..MAX_REF_DEPTH {
            let Some(r) = cur.get("$ref").and_then(Value::as_str) else {
                return Some((cur, cur_ptr));
            };
            if self.refs_used.fetch_add(1, Ordering::Relaxed) >= MAX_REF_RESOLUTIONS {
                return None;
            }
            let target = internal_pointer(r)?;
            cur = self.root.pointer(&target)?;
            cur_ptr = target;
        }
        None
    }

    /// Resolve `v` and return the resolved value, or `v` itself when it is not
    /// a resolvable reference.
    pub fn deref<'a>(&'a self, v: &'a Value, at: &str) -> (&'a Value, String) {
        self.resolve(v, at).unwrap_or((v, at.to_string()))
    }
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
        let f = spec.root.pointer("/components/schemas/F").unwrap();
        assert_eq!(spec.resolve(f, "/components/schemas/F").unwrap().0["type"], "integer");
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
