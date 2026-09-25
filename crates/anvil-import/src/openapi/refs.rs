//! Bounded, internal-only `$ref` resolution.
//!
//! * `#/json/pointer` references are resolved inside the document, following
//!   chains up to `max_ref_depth` with cycle detection.
//! * Anything else (relative files, `http(s):` URLs, `urn:`/`$id` based
//!   URIs) is **never fetched**; it is recorded in the report as an external
//!   reference that requires explicit approval (DATA-009).
//! * Plain-name fragments (`#foo`, JSON Schema `$anchor`) are reported as
//!   unsupported.
//! * Every resolution is charged against `max_ref_expansions` for the whole
//!   import.

use crate::report::ImportReport;
use serde_json::Value;

#[derive(Clone, Copy)]
pub(crate) struct Refs<'a> {
    pub root: &'a Value,
    pub max_depth: usize,
    pub max_expansions: usize,
}

enum Target {
    Internal(String),
    External,
    Anchor,
}

fn classify(r: &str) -> Target {
    if r == "#" {
        return Target::Internal(String::new());
    }
    if let Some(frag) = r.strip_prefix('#') {
        if frag.starts_with('/') {
            let decoded = percent_encoding::percent_decode_str(frag).decode_utf8_lossy().into_owned();
            return Target::Internal(decoded);
        }
        return Target::Anchor;
    }
    Target::External
}

impl<'a> Refs<'a> {
    /// The `$ref` string of `v`, if it is a reference object.
    pub fn ref_of(v: &Value) -> Option<&str> {
        v.get("$ref").and_then(Value::as_str)
    }

    /// Follow `$ref` chains from `v` (located at `at`). Returns the first
    /// non-reference value and its pointer, or `None` (already reported)
    /// when the reference is external, dangling, cyclic or over budget.
    pub fn resolve<'v>(&self, v: &'v Value, at: &str, report: &mut ImportReport) -> Option<(&'v Value, String)>
    where
        'a: 'v,
    {
        let mut cur: &'v Value = v;
        let mut cur_ptr = at.to_string();
        let mut chain: Vec<String> = Vec::new();
        loop {
            let Some(r) = Self::ref_of(cur) else {
                return Some((cur, cur_ptr));
            };
            if chain.len() >= self.max_depth {
                report.warn("ref_depth_limit", at, format!("$ref chain longer than {} was not followed", self.max_depth));
                return None;
            }
            if report.counts.refs_resolved >= self.max_expansions {
                report.warn(
                    "ref_budget_exhausted",
                    at,
                    format!(
                        "the import reached its limit of {} $ref resolutions; remaining references were not expanded",
                        self.max_expansions
                    ),
                );
                return None;
            }
            report.counts.refs_resolved += 1;
            match classify(r) {
                Target::Internal(p) => {
                    if chain.contains(&p) {
                        report.warn("ref_cycle", &cur_ptr, format!("$ref '{r}' forms a reference-only cycle"));
                        return None;
                    }
                    let Some(target) = self.root.pointer(&p) else {
                        report.warn("dangling_ref", &cur_ptr, format!("$ref '{r}' does not point to anything in the document"));
                        return None;
                    };
                    chain.push(p.clone());
                    cur = target;
                    cur_ptr = p;
                }
                Target::External => {
                    report.external_ref(r, &cur_ptr);
                    return None;
                }
                Target::Anchor => {
                    report.unsupported(
                        "ref_anchor",
                        &cur_ptr,
                        format!("$ref '{r}' uses a plain-name fragment ($anchor/$id resolution is not supported)"),
                    );
                    return None;
                }
            }
        }
    }

    /// Like [`Self::resolve`] but tolerates a non-reference value and never
    /// fails: returns `v` itself when resolution is impossible.
    pub fn resolve_or_self<'v>(&self, v: &'v Value, at: &str, report: &mut ImportReport) -> (&'v Value, String)
    where
        'a: 'v,
    {
        match self.resolve(v, at, report) {
            Some(x) => x,
            None => (v, at.to_string()),
        }
    }
}

/// Last path segment of an internal reference (`#/components/schemas/Pet` → `Pet`).
pub(crate) fn ref_name(r: &str) -> Option<String> {
    let frag = r.split('#').nth(1)?;
    let last = frag.rsplit('/').next()?;
    if last.is_empty() {
        return None;
    }
    Some(last.replace("~1", "/").replace("~0", "~"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn resolves_chains_and_reports_external() {
        let root = json!({
            "a": {"$ref": "#/b"},
            "b": {"$ref": "#/c"},
            "c": {"type": "string"},
            "loop1": {"$ref": "#/loop2"},
            "loop2": {"$ref": "#/loop1"},
            "ext": {"$ref": "other.yaml#/X"},
            "sp": {"$ref": "#/with%20space"},
            "with space": {"type": "integer"}
        });
        let refs = Refs { root: &root, max_depth: 8, max_expansions: 100 };
        let mut rep = ImportReport::default();
        let (v, p) = refs.resolve(&root["a"], "/a", &mut rep).unwrap();
        assert_eq!(v["type"], "string");
        assert_eq!(p, "/c");
        assert!(refs.resolve(&root["loop1"], "/loop1", &mut rep).is_none());
        assert!(rep.has_code("ref_cycle"));
        assert!(refs.resolve(&root["ext"], "/ext", &mut rep).is_none());
        assert_eq!(rep.external_refs.len(), 1);
        assert_eq!(refs.resolve(&root["sp"], "/sp", &mut rep).unwrap().0["type"], "integer");
    }

    #[test]
    fn names() {
        assert_eq!(ref_name("#/components/schemas/Pet").as_deref(), Some("Pet"));
        assert_eq!(ref_name("#/definitions/a~1b").as_deref(), Some("a/b"));
    }
}
