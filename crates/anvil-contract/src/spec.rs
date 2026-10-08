//! A parsed OpenAPI description: the document, its dialect and source
//! positions, plus bounded internal `$ref` resolution. Each `$ref` string
//! is followed once per document and remembered.

use crate::locate::{Locator, Position};
use anvil_import::{Dialect, ImportError, ImportOptions, Syntax};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap, HashSet};
#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

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
    /// Where each `$ref` string leads, found once (see [`Spec::reach`]).
    refs: Mutex<RefCache>,
    /// Pointers walked to follow references.
    #[cfg(test)]
    pub(crate) walks: AtomicUsize,
}

/// Where a `$ref` chain ends.
#[derive(Debug, Clone)]
pub struct RefTarget {
    /// The same for every reference of the document that ends there.
    pub id: usize,
    pub pointer: Arc<str>,
}

/// What a value leads to ([`Spec::reach`]).
#[derive(Debug, Clone)]
pub enum Reach<'a> {
    /// Not a reference: the value itself.
    Inline(&'a Value),
    /// The end of an internal `$ref` chain.
    Target(RefTarget),
    /// An external, dangling, cyclic or too deep reference.
    Unresolved,
}

/// The `$ref`s followed so far.
#[derive(Debug, Default)]
struct RefCache {
    /// A `$ref` string → where its chain ends (an index into `ends`) and how
    /// many references the chain passes through; `None` when it cannot be
    /// followed (external, dangling or cyclic).
    by_ref: HashMap<String, Option<(usize, usize)>>,
    /// Where chains end, each once.
    ends: Vec<Arc<str>>,
    end_ids: HashMap<Arc<str>, usize>,
}

impl RefCache {
    /// The index of `pointer` in `ends`.
    fn intern(&mut self, pointer: String) -> usize {
        if let Some(id) = self.end_ids.get(pointer.as_str()) {
            return *id;
        }
        let pointer: Arc<str> = pointer.into();
        self.end_ids.insert(Arc::clone(&pointer), self.ends.len());
        self.ends.push(pointer);
        self.ends.len() - 1
    }
}

/// A byte budget for work and copies, each charged before it is done. Once
/// a charge does not fit, it and every later one are refused.
#[derive(Debug, Clone)]
pub struct Meter {
    left: usize,
    spent: usize,
    exhausted: bool,
}

impl Meter {
    pub fn new(bytes: usize) -> Meter {
        Meter { left: bytes, spent: 0, exhausted: false }
    }

    /// Charge `bytes`; `false` when they do not fit (or an earlier charge
    /// did not).
    pub fn charge(&mut self, bytes: usize) -> bool {
        if self.exhausted || bytes > self.left {
            self.exhausted = true;
            return false;
        }
        self.left -= bytes;
        self.spent += bytes;
        true
    }

    /// Whether a charge was refused.
    pub fn exhausted(&self) -> bool {
        self.exhausted
    }

    /// What the accepted charges add up to.
    pub fn spent(&self) -> usize {
        self.spent
    }
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
            refs: Mutex::new(RefCache::default()),
            #[cfg(test)]
            walks: AtomicUsize::new(0),
        })
    }

    /// `root` as a document, without the parser's bounds: tests check that an
    /// analysis bounds itself on inputs those limits would refuse.
    #[cfg(test)]
    pub(crate) fn unchecked(dialect: Dialect, root: Value) -> Spec {
        Spec {
            dialect,
            declared_version: None,
            syntax: Syntax::Json,
            root,
            sha256: String::new(),
            size_bytes: 0,
            text: String::new(),
            locator: OnceLock::new(),
            unresolved: Mutex::new((BTreeSet::new(), 0)),
            refs: Mutex::new(RefCache::default()),
            walks: AtomicUsize::new(0),
        }
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
        match self.reach(v, at) {
            Reach::Inline(v) => Some((v, at.to_string())),
            Reach::Target(t) => Some((self.target_value(&t)?, t.pointer.to_string())),
            Reach::Unresolved => None,
        }
    }

    /// [`Spec::resolve`], charged to `meter` before each step: `at` and the
    /// `$ref` before the reference is looked up, then the pointer it ends at
    /// before that is walked and copied. So however many references lead to
    /// one long pointer, what they cost together stays within the meter.
    /// `None` too once a charge is refused (see [`Meter::exhausted`]).
    pub fn resolve_within<'a>(&'a self, v: &'a Value, at: &str, meter: &mut Meter) -> Option<(&'a Value, String)> {
        let r = v.get("$ref").and_then(Value::as_str).map_or(0, str::len);
        if !meter.charge(at.len() + r) {
            return None;
        }
        match self.reach(v, at) {
            Reach::Inline(v) => Some((v, at.to_string())),
            Reach::Target(t) => {
                if !meter.charge(t.pointer.len()) {
                    return None;
                }
                Some((self.target_value(&t)?, t.pointer.to_string()))
            }
            Reach::Unresolved => None,
        }
    }

    /// Where `v` (at `at`) leads, without walking there: itself, or where its
    /// `$ref` chain ends. Each `$ref` string is followed once per document,
    /// so many references sharing a chain cost one walk of the chain (each
    /// use still walks and copies the pointer it ends at: see
    /// [`Spec::resolve_within`]). An unresolvable reference is remembered in
    /// [`Spec::unresolved`].
    pub fn reach<'a>(&self, v: &'a Value, at: &str) -> Reach<'a> {
        let Some(r) = v.get("$ref").and_then(Value::as_str) else { return Reach::Inline(v) };
        let mut cache = self.refs.lock().unwrap_or_else(PoisonError::into_inner);
        let end = self.end_of(&mut cache, r);
        match end {
            Some((id, hops)) if hops < MAX_REF_DEPTH => Reach::Target(RefTarget { id, pointer: Arc::clone(&cache.ends[id]) }),
            _ => {
                drop(cache);
                self.note_unresolved(at);
                Reach::Unresolved
            }
        }
    }

    /// The value a [`RefTarget`] of this document points at.
    pub fn target_value(&self, t: &RefTarget) -> Option<&Value> {
        self.walk(&t.pointer)
    }

    /// Where the chain from the `$ref` string `r` ends and how many
    /// references it passes through. Follows `r` and the references after it
    /// until the chain ends, comes back on itself or meets one already
    /// followed, and remembers each.
    fn end_of(&self, cache: &mut RefCache, r: &str) -> Option<(usize, usize)> {
        if let Some(found) = cache.by_ref.get(r) {
            return *found;
        }
        let mut chain: Vec<&str> = vec![r];
        let mut on_chain: HashSet<&str> = HashSet::from([r]);
        // Where the last reference of `chain` leads: the end and how many
        // references come after it.
        let end = loop {
            let Some(target) = internal_pointer(chain[chain.len() - 1]) else { break None };
            let Some(v) = self.walk(&target) else { break None };
            let Some(next) = v.get("$ref").and_then(Value::as_str) else { break Some((cache.intern(target), 0)) };
            if let Some(found) = cache.by_ref.get(next) {
                break *found;
            }
            if !on_chain.insert(next) {
                break None;
            }
            chain.push(next);
        };
        let n = chain.len();
        for (i, r) in chain.into_iter().enumerate() {
            cache.by_ref.insert(r.to_string(), end.map(|(id, after)| (id, after + n - i)));
        }
        end.map(|(id, after)| (id, after + n))
    }

    /// The value at `pointer`.
    fn walk(&self, pointer: &str) -> Option<&Value> {
        #[cfg(test)]
        {
            self.walks.fetch_add(1, Ordering::Relaxed);
        }
        self.root.pointer(pointer)
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
    use serde_json::{Map, json};

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
    fn chain_depth_is_counted_from_where_resolution_starts() {
        // S0 → S1 → … → S40, a string.
        let mut schemas = Map::new();
        for i in 0..40 {
            schemas.insert(format!("S{i}"), json!({"$ref": format!("#/components/schemas/S{}", i + 1)}));
        }
        schemas.insert("S40".into(), json!({"type": "string"}));
        let doc = json!({"openapi": "3.1.0", "info": {"title": "t", "version": "1"}, "paths": {}, "components": {"schemas": schemas}});
        let spec = Spec::parse(doc.to_string().as_bytes()).unwrap();
        let at = |i: usize| format!("/components/schemas/S{i}");
        let resolves = |i: usize| spec.resolve(spec.root.pointer(&at(i)).unwrap(), &at(i)).is_some();
        // Part of the chain is already followed from further along; the
        // references before it still count.
        assert!(resolves(20));
        assert!(!resolves(0));
        assert!(resolves(9), "31 references");
        assert!(!resolves(8), "32 references");
        assert_eq!(spec.resolve(spec.root.pointer(&at(39)).unwrap(), &at(39)).unwrap().1, at(40));
    }

    #[test]
    fn many_references_to_one_deep_target_follow_it_once() {
        // A target with a pointer of about 400 KB, behind one alias that
        // 1,000 others refer to.
        let key = "k".repeat(4_000);
        let mut deep = json!({"type": "string"});
        for _ in 0..100 {
            let mut level = Map::new();
            level.insert(key.clone(), deep);
            deep = Value::Object(level);
        }
        let mut aliases = Map::new();
        aliases.insert("end".into(), json!({"$ref": format!("#/x{}", format!("/{key}").repeat(100))}));
        for i in 0..1_000 {
            aliases.insert(format!("a{i}"), json!({"$ref": "#/aliases/end"}));
        }
        let doc = json!({"openapi": "3.1.0", "info": {"title": "t", "version": "1"}, "paths": {}, "x": deep, "aliases": aliases});
        let spec = Spec::parse(doc.to_string().as_bytes()).unwrap();
        let refs: Vec<Value> = (0..1_000).map(|i| json!({"$ref": format!("#/aliases/a{i}")})).collect();
        let mut end = None;
        for n in 0..1_000_000 {
            let Reach::Target(t) = spec.reach(&refs[n % refs.len()], "/r") else { panic!("not followed") };
            assert_eq!(t.id, *end.get_or_insert(t.id));
        }
        // Each alias once, then `end` and the target once.
        assert_eq!(spec.walks.load(Ordering::Relaxed), refs.len() + 2);
        let (v, pointer) = spec.resolve(&refs[7], "/r").unwrap();
        assert_eq!((v["type"].as_str(), pointer.len()), (Some("string"), 100 * 4_001 + 2));
    }

    #[test]
    fn metered_resolution_charges_every_use_of_a_long_pointer() {
        // A target with a pointer of about 200 KB behind one alias.
        let key = "k".repeat(4_000);
        let mut deep = json!({"type": "string"});
        for _ in 0..50 {
            let mut level = Map::new();
            level.insert(key.clone(), deep);
            deep = Value::Object(level);
        }
        let target = format!("/x{}", format!("/{key}").repeat(50));
        let doc = json!({"openapi": "3.1.0", "info": {"title": "t", "version": "1"}, "paths": {}, "x": deep,
            "a": {"$ref": format!("#{target}")}});
        let spec = Spec::parse(doc.to_string().as_bytes()).unwrap();
        // Each use is charged its location (`/r`), its `$ref` (`#/a`) and
        // the pointer it ends at: room for ten uses, not eleven.
        let r = json!({"$ref": "#/a"});
        let mut meter = Meter::new(10 * (2 + 3 + target.len()) + 4);
        let mut found = 0;
        while spec.resolve_within(&r, "/r", &mut meter).is_some() {
            found += 1;
        }
        assert_eq!(found, 10);
        assert!(meter.exhausted());
        assert_eq!(meter.spent(), 10 * (2 + 3 + target.len()));
        // The alias and the target once to follow the chain, then the target
        // once per use; a refused use walks nothing.
        assert_eq!(spec.walks.load(Ordering::Relaxed), 2 + 10);
        assert!(spec.resolve_within(&r, "/r", &mut meter).is_none());
        assert_eq!(spec.walks.load(Ordering::Relaxed), 2 + 10);
        // A refusal is not an unresolvable reference.
        assert_eq!(spec.unresolved().1, 0);
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
