//! Schema-driven sample generation (request direction).
//!
//! Precedence in [`SampleMode::Sample`]: explicit example → `default` →
//! `const` → first `enum` value → seeded generator. [`SampleMode::Blank`]
//! produces type-correct empty values (`""`, `0`, `false`, `[]`, objects
//! with required members) and never uses examples, defaults or enums.
//!
//! The generator honors required members, `readOnly` (omitted in requests),
//! `writeOnly`, nullable/type arrays, length/range/multipleOf/item-count
//! constraints and common formats. Composition: `allOf` is merged, the first
//! viable `oneOf`/`anyOf` branch is used (with a warning). Recursion is cut
//! at the first repeated `$ref` and reported. Anything the generator cannot
//! guarantee (patterns, `not`, conditionals, contradictions) is reported as
//! a warning — a sample is never claimed to be valid.

use super::refs::{Refs, ref_name};
use crate::report::ImportReport;
use crate::util::{SplitMix64, clip, is_credential_name, json_type, ptr};
use crate::{Dialect, ImportOptions, SampleMode};
use base64::Engine as _;
use serde_json::{Map, Number, Value, json};
use std::borrow::Cow;
use std::cell::Cell;
use std::collections::HashSet;

const MAX_NESTING: usize = 48;
/// Sample bytes (generated values, copied examples, defaults and merged
/// schemas) allowed across one import, per input byte limit.
pub(crate) const SAMPLE_BYTES_PER_INPUT_BYTE: usize = 4;
/// Bytes charged per generated or copied value, roughly what one
/// `serde_json::Value` occupies.
const VALUE_BYTES: usize = 32;
const MAX_ARRAY_ITEMS: usize = 32;

/// Keywords whose constraints the generator does not enforce.
const UNENFORCED: &[(&str, &str)] = &[
    ("not", "`not` is not enforced"),
    ("if", "`if`/`then`/`else` conditionals are not evaluated"),
    ("dependentSchemas", "`dependentSchemas` is not evaluated"),
    ("dependentRequired", "`dependentRequired` is not evaluated"),
    ("dependencies", "`dependencies` is not evaluated"),
    ("patternProperties", "`patternProperties` members are not generated"),
    ("unevaluatedProperties", "`unevaluatedProperties` is not evaluated"),
    ("unevaluatedItems", "`unevaluatedItems` is not evaluated"),
    ("propertyNames", "`propertyNames` is not enforced"),
    ("contains", "`contains` is not enforced"),
];

pub(crate) struct SampleGen<'a, 'r> {
    pub refs: Refs<'a>,
    pub report: &'r mut ImportReport,
    pub dialect: Dialect,
    pub mode: SampleMode,
    pub include_optional: bool,
    rng: SplitMix64,
    stack: Vec<String>,
    nodes: usize,
    max_nodes: usize,
    max_ref_depth: usize,
    budget_warned: bool,
    /// Node budget of the payload's structural lookups (`flatten`), kept
    /// apart from the payload's own and reset with it.
    flat_budget: (usize, bool),
    /// Bytes the rest of the import may still generate or copy.
    bytes: &'r Cell<usize>,
    bytes_warned: bool,
}

pub(crate) fn is_31_plus(d: Dialect) -> bool {
    matches!(d, Dialect::OpenApi31 | Dialect::OpenApi32)
}

impl<'a, 'r> SampleGen<'a, 'r> {
    pub fn new(
        refs: Refs<'a>,
        report: &'r mut ImportReport,
        dialect: Dialect,
        opts: &ImportOptions,
        seed: u64,
        bytes: &'r Cell<usize>,
    ) -> Self {
        SampleGen {
            refs,
            report,
            dialect,
            mode: opts.mode,
            include_optional: opts.include_optional,
            rng: SplitMix64::new(seed),
            stack: vec![],
            nodes: 0,
            max_nodes: opts.max_sample_nodes,
            max_ref_depth: opts.max_ref_depth,
            budget_warned: false,
            flat_budget: (0, false),
            bytes,
            bytes_warned: false,
        }
    }

    /// Reset the per-payload node budget (one budget per payload).
    pub fn reset_budget(&mut self) {
        self.nodes = 0;
        self.budget_warned = false;
        self.flat_budget = (0, false);
    }

    pub fn generate(&mut self, schema: &Value, at: &str, name: Option<&str>) -> Option<Value> {
        self.gen_value(schema, at, 0, name)
    }

    /// Resolve a (possibly `$ref`) schema to an `allOf`-merged object for
    /// structural inspection (XML names, multipart part kinds). All the calls
    /// for one payload share a node budget of their own, so they never spend
    /// the payload's. Only a merge copies (charged to the import's byte
    /// budget); with nothing to merge the resolved schema is borrowed.
    pub fn flatten<'v>(&mut self, schema: &'v Value, at: &str) -> (Cow<'v, Value>, String)
    where
        'a: 'v,
    {
        let (s, p) = match self.resolve(schema, at) {
            Some(x) => x,
            None => (schema, at.to_string()),
        };
        let payload = (self.nodes, self.budget_warned);
        (self.nodes, self.budget_warned) = self.flat_budget;
        let merged = if s.get("allOf").is_some_and(Value::is_array) { self.merge_all_of(s, &p) } else { None };
        self.flat_budget = (self.nodes, self.budget_warned);
        (self.nodes, self.budget_warned) = payload;
        match merged {
            Some(m) => (Cow::Owned(m), p),
            None => (Cow::Borrowed(s), p),
        }
    }

    /// A copy of `v` (an example, a default or part of a merged schema),
    /// charged against the import's sample byte budget before it is made.
    /// Once the budget is spent nothing more is copied or generated.
    pub fn copy(&mut self, at: &str, v: &Value) -> Option<Value> {
        if charge_copy(self.bytes, v) {
            Some(v.clone())
        } else {
            self.bytes_spent(at);
            None
        }
    }

    /// [`copy`](Self::copy) for text.
    pub fn copy_str(&mut self, at: &str, s: &str) -> Option<String> {
        self.take_bytes(at, s.len().saturating_add(VALUE_BYTES)).then(|| s.to_string())
    }

    /// Charge `n` generated bytes against the import's byte budget.
    fn take_bytes(&mut self, at: &str, n: usize) -> bool {
        let left = self.bytes.get();
        if n >= left {
            self.bytes_spent(at);
            return false;
        }
        self.bytes.set(left - n);
        true
    }

    /// Copy `obj` without the `skip` member.
    fn copy_map_except(&mut self, at: &str, obj: &Map<String, Value>, skip: &str) -> Option<Map<String, Value>> {
        let mut out = Map::new();
        for (k, v) in obj {
            if k != skip {
                let v = self.copy(at, v)?;
                out.insert(k.clone(), v);
            }
        }
        Some(out)
    }

    /// Charge looking at `n` bytes of the schema (member names, `required`
    /// names, `enum` values). Nothing is generated, but the work repeats on
    /// every visit of the schema, so it draws on the import's byte budget
    /// like generated output: the total stays proportional to the input.
    fn charge_scan(&mut self, at: &str, n: usize) -> bool {
        self.take_bytes(at, n)
    }

    /// [`Refs::resolve`], with the pointer it copies and the `$ref` it
    /// decodes charged first, and the target's pointer after.
    fn resolve<'v>(&mut self, v: &'v Value, at: &str) -> Option<(&'v Value, String)>
    where
        'a: 'v,
    {
        let r = Refs::ref_of(v).map_or(0, str::len);
        if !self.charge_scan(at, at.len().saturating_add(r)) {
            return None;
        }
        let (t, tp) = self.refs.resolve(v, at, self.report)?;
        self.charge_scan(at, tp.len()).then_some((t, tp))
    }

    /// Charge checking `p` against the `$ref`s being expanded (and keeping a copy).
    fn charge_stack(&mut self, at: &str, p: &str) -> bool {
        self.charge_scan(at, p.len().saturating_mul(self.stack.len() + 1))
    }

    fn bytes_spent(&mut self, at: &str) {
        self.bytes.set(0);
        if !self.bytes_warned {
            self.bytes_warned = true;
            self.report.warn("sample_size_limit", at, "generated samples reached the import's byte budget; the rest was omitted");
        }
    }

    /// Whether a property schema (following `$ref`) carries a boolean flag.
    pub fn flag(&mut self, schema: &Value, at: &str, key: &str) -> bool {
        if schema.get(key).and_then(Value::as_bool) == Some(true) {
            return true;
        }
        if Refs::ref_of(schema).is_some()
            && let Some((t, _)) = self.resolve(schema, at)
        {
            return t.get(key).and_then(Value::as_bool) == Some(true);
        }
        false
    }

    /// Charge one generated value: a node of the payload's budget and its
    /// bytes in the import's.
    fn charge(&mut self, at: &str) -> bool {
        if self.nodes >= self.max_nodes {
            if !self.budget_warned {
                self.budget_warned = true;
                self.report.warn(
                    "sample_size_limit",
                    at,
                    format!("generated payload reached {} values (max_sample_nodes); the rest was omitted", self.max_nodes),
                );
            }
            return false;
        }
        if !self.take_bytes(at, VALUE_BYTES) {
            return false;
        }
        self.nodes += 1;
        true
    }

    fn gen_value(&mut self, schema: &Value, at: &str, depth: usize, name: Option<&str>) -> Option<Value> {
        // Every visit is charged a value and the length of its pointer, which
        // the visit copies into child pointers and findings.
        if !self.charge(at) || !self.charge_scan(at, at.len()) {
            return None;
        }
        if depth > MAX_NESTING {
            self.report.warn("schema_depth_limit", at, format!("schema nesting deeper than {MAX_NESTING} levels was not expanded"));
            return None;
        }
        let obj = match schema {
            Value::Bool(true) => return Some(Value::Null),
            Value::Bool(false) => {
                self.report.warn("unsatisfiable_schema", at, "schema `false` accepts no value; member omitted");
                return None;
            }
            Value::Object(o) => o,
            _ => {
                self.report.warn("invalid_schema", at, format!("expected a schema object, found {}", json_type(schema)));
                return None;
            }
        };

        if let Some(r) = obj.get("$ref").and_then(Value::as_str) {
            return self.gen_ref(schema, obj, r, at, depth, name);
        }
        for k in ["$dynamicRef", "$recursiveRef"] {
            if obj.contains_key(k) {
                self.report.unsupported("dynamic_ref", at, format!("`{k}` resolution is not supported; value omitted"));
                return None;
            }
        }
        for (k, why) in UNENFORCED {
            if obj.contains_key(*k) {
                self.report.warn("schema_keyword_not_enforced", &ptr(at, k), format!("{why}; the sample may not satisfy it"));
            }
        }
        if obj.contains_key("$schema") {
            self.report.warn("schema_dialect", &ptr(at, "$schema"), "schema-level `$schema` is ignored; OpenAPI base semantics are used");
        }

        let types = self.types(obj, at);
        if self.mode == SampleMode::Sample
            && let Some(v) = self.explicit_value(obj, at, &types)
        {
            return Some(v);
        }
        if self.bytes.get() == 0 {
            return None;
        }

        if obj.get("allOf").is_some_and(Value::is_array) {
            let merged = self.merge_all_of(schema, at)?;
            return self.gen_value(&merged, at, depth + 1, name);
        }
        for key in ["oneOf", "anyOf"] {
            if let Some(alts) = obj.get(key).and_then(Value::as_array) {
                return self.gen_alternative(obj, key, alts, at, depth, name);
            }
        }

        let nullable = types.iter().any(|t| t == "null")
            || obj.get("nullable").and_then(Value::as_bool) == Some(true)
            || obj.get("x-nullable").and_then(Value::as_bool) == Some(true);
        let non_null: Vec<&String> = types.iter().filter(|t| *t != "null").collect();
        if non_null.len() > 1 {
            // The message lists every type, on every visit: charged.
            if !self.charge_scan(at, non_null.iter().fold(0usize, |n, t| n.saturating_add(t.len() + 2))) {
                return None;
            }
            self.report.warn(
                "multiple_types",
                &ptr(at, "type"),
                format!(
                    "schema allows {}; the sample uses '{}'",
                    non_null.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", "),
                    non_null[0]
                ),
            );
        }
        let t = match non_null.first() {
            Some(t) => Some(t.as_str().to_string()),
            None if !types.is_empty() => return Some(Value::Null), // only "null"
            None => infer_type(obj).map(str::to_string),
        };
        let _ = nullable;
        match t.as_deref() {
            Some("object") => self.gen_object(obj, at, depth),
            Some("array") => self.gen_array(obj, at, depth, name),
            Some("string") => Some(self.gen_string(obj, at, name)),
            Some("integer") => Some(self.gen_integer(obj, at)),
            Some("number") => Some(self.gen_number(obj, at)),
            Some("boolean") => Some(Value::Bool(self.mode == SampleMode::Sample && self.rng.bool())),
            Some("file") => {
                self.report.warn("binary_placeholder", at, "file content cannot be generated; left empty");
                Some(Value::String(String::new()))
            }
            Some(other) => {
                self.report.warn("unknown_type", &ptr(at, "type"), format!("unknown type '{other}'; null used"));
                Some(Value::Null)
            }
            None => Some(Value::Object(Map::new())),
        }
    }

    fn gen_ref(&mut self, schema: &Value, obj: &Map<String, Value>, r: &str, at: &str, depth: usize, name: Option<&str>) -> Option<Value> {
        const ANNOTATIONS: &[&str] = &[
            "$ref",
            "description",
            "summary",
            "title",
            "$comment",
            "deprecated",
            "readOnly",
            "writeOnly",
            "example",
            "examples",
            "default",
        ];
        // Every key may be looked at (all of them when they are annotations).
        if !self.charge_scan(at, obj.len()) {
            return None;
        }
        let has_siblings = obj.keys().any(|k| !ANNOTATIONS.contains(&k.as_str()) && !k.starts_with("x-"));
        let modern = is_31_plus(self.dialect);
        if modern && self.mode == SampleMode::Sample {
            // 3.1+: sibling example/default apply to the referencing site.
            if let Some(v) = example_of(obj, self.dialect) {
                return self.copy(at, v);
            }
            if let Some(d) = obj.get("default") {
                return self.copy(at, d);
            }
        }
        let (target, tptr) = self.resolve(schema, at)?;
        if !self.charge_stack(at, &tptr) {
            return None;
        }
        if self.stack.contains(&tptr) {
            self.report.warn(
                "recursive_schema",
                &tptr,
                format!("recursive schema ({}): expansion stops at the first repetition", ref_name(r).unwrap_or_else(|| r.to_string())),
            );
            return None;
        }
        if self.stack.len() >= self.max_ref_depth {
            self.report.warn("ref_depth_limit", at, format!("more than {} nested $ref levels were not expanded", self.max_ref_depth));
            return None;
        }
        self.stack.push(tptr.clone());
        let out = if has_siblings && modern {
            match (self.copy(at, target), self.copy_map_except(at, obj, "$ref")) {
                (Some(t), Some(sib)) => {
                    let merged = json!({ "allOf": [t, Value::Object(sib)] });
                    self.gen_value(&merged, at, depth + 1, name)
                }
                _ => None,
            }
        } else {
            if has_siblings {
                self.report.warn(
                    "ref_siblings_ignored",
                    at,
                    format!("{} ignores keywords next to $ref; only the referenced schema is used", self.dialect.label()),
                );
            }
            self.gen_value(target, &tptr, depth + 1, name)
        };
        self.stack.pop();
        out
    }

    fn types(&mut self, obj: &Map<String, Value>, at: &str) -> Vec<String> {
        match obj.get("type") {
            Some(Value::String(s)) => vec![s.clone()],
            Some(Value::Array(a)) => {
                // Every entry is read (and copied) on every visit.
                if !self.charge_scan(at, a.iter().fold(a.len(), |n, t| n.saturating_add(t.as_str().map_or(0, str::len)))) {
                    return vec![];
                }
                if !is_31_plus(self.dialect) {
                    self.report.warn(
                        "type_array_in_legacy_dialect",
                        &ptr(at, "type"),
                        format!("type arrays are an OpenAPI 3.1+ construct; interpreted anyway in a {} document", self.dialect.label()),
                    );
                }
                a.iter().filter_map(Value::as_str).map(str::to_string).collect()
            }
            _ => vec![],
        }
    }

    /// Example → default → const → enum (Sample mode only).
    fn explicit_value(&mut self, obj: &Map<String, Value>, at: &str, types: &[String]) -> Option<Value> {
        let (v, what) = if let Some(v) = example_of(obj, self.dialect) {
            (v, "example")
        } else if let Some(v) = obj.get("default") {
            (v, "default")
        } else if let Some(v) = obj.get("const") {
            (v, "const")
        } else {
            let e = obj.get("enum").and_then(Value::as_array).filter(|e| !e.is_empty())?;
            let first = e.iter().position(|x| !x.is_null());
            // Every value looked at is charged.
            if !self.charge_scan(at, first.map_or(e.len(), |i| i + 1)) {
                return None;
            }
            (&e[first.unwrap_or(0)], "enum")
        };
        if !types.is_empty() && !value_matches_types(v, types, obj) {
            self.report.warn(
                "example_type_mismatch",
                &ptr(at, what),
                format!("{what} value is {} but the schema type is {}; used as written", json_type(v), types.join("|")),
            );
        }
        if let (Some(c), Some(e)) = (obj.get("const"), obj.get("enum").and_then(Value::as_array)) {
            // An empty `enum` contains nothing: `const` is not walked at all.
            // Otherwise each comparison may walk all of `const`: its size is
            // charged once per `enum` value before any comparison is made.
            let contained = if e.is_empty() {
                false
            } else {
                let cost = size_within(c, self.bytes.get()).and_then(|n| n.checked_mul(e.len()));
                if !cost.is_some_and(|n| self.charge_scan(at, n)) {
                    self.bytes_spent(at);
                    return None;
                }
                e.contains(c)
            };
            if !contained {
                self.report.warn("contradictory_schema", at, "`const` is not one of the `enum` values");
            }
        }
        self.copy(&ptr(at, what), v)
    }

    fn gen_alternative(
        &mut self,
        obj: &Map<String, Value>,
        key: &str,
        alts: &[Value],
        at: &str,
        depth: usize,
        name: Option<&str>,
    ) -> Option<Value> {
        let kptr = ptr(at, key);
        if alts.is_empty() {
            self.report.warn("contradictory_schema", &kptr, format!("empty `{key}` accepts no value"));
            return None;
        }
        // Every alternative looked at is charged, with the check of its
        // `$ref` against the ones being expanded.
        let viable = |this: &mut Self, a: &Value| -> Option<bool> {
            let r = Refs::ref_of(a).and_then(|r| r.strip_prefix('#'));
            if !this.charge_scan(at, r.map_or(0, str::len).saturating_mul(this.stack.len()).saturating_add(1)) {
                return None;
            }
            if a == &Value::Bool(false) || r.is_some_and(|frag| this.stack.iter().any(|s| s == frag)) {
                return Some(false);
            }
            Some(a.get("type").and_then(Value::as_str) != Some("null"))
        };
        let mut idx = 0;
        for (i, a) in alts.iter().enumerate() {
            if viable(self, a)? {
                idx = i;
                break;
            }
        }
        if alts.len() > 1 {
            let label = Refs::ref_of(&alts[idx]).and_then(ref_name).unwrap_or_else(|| format!("#{idx}"));
            self.report.warn(
                "composition_first_branch",
                &kptr,
                format!(
                    "`{key}` has {} alternatives; the sample uses the first viable one ({label}) and does not prove it is the intended one",
                    alts.len()
                ),
            );
        }
        let alt = &alts[idx];
        let mut base = self.copy_map_except(&kptr, obj, key)?;
        let discriminator = base.remove("discriminator");
        let structural = base.keys().any(|k| matches!(k.as_str(), "properties" | "required" | "type" | "allOf" | "items"));
        let mut v = if structural {
            let alt = self.copy(&kptr, alt)?;
            let schema = json!({ "allOf": [Value::Object(base), alt] });
            self.gen_value(&schema, &ptr_i(&kptr, idx), depth + 1, name)?
        } else {
            self.gen_value(alt, &ptr_i(&kptr, idx), depth + 1, name)?
        };
        if let (Some(d), Value::Object(m)) = (discriminator, &mut v)
            && let Some(prop) = d.get("propertyName").and_then(Value::as_str)
        {
            let r = Refs::ref_of(alt).map(str::to_string);
            // Every mapping entry may be compared with the chosen `$ref`.
            let entries = d.get("mapping").and_then(Value::as_object).map_or(0, Map::len);
            if !self.charge_scan(at, entries.saturating_mul(r.as_ref().map_or(1, String::len))) {
                return None;
            }
            let mapped = d.get("mapping").and_then(Value::as_object).and_then(|mp| {
                mp.iter().find(|(_, target)| r.as_deref().is_some_and(|r| target.as_str() == Some(r))).map(|(k, _)| k.clone())
            });
            if let Some(tag) = mapped.or_else(|| r.as_deref().and_then(ref_name)) {
                m.insert(prop.to_string(), Value::String(tag));
            }
        }
        Some(v)
    }

    /// Merge `allOf` branches (following `$ref`s) into one schema object.
    ///
    /// Every branch is charged against the payload budget before it is
    /// resolved or copied, and a followed `$ref` counts toward the active
    /// `$ref` depth like a direct one, so a long or branching composition
    /// graph stops at the same limits as the rest of the generator.
    pub fn merge_all_of(&mut self, schema: &Value, at: &str) -> Option<Value> {
        self.merge_all_of_at(schema, at, 0)
    }

    fn merge_all_of_at(&mut self, schema: &Value, at: &str, nesting: usize) -> Option<Value> {
        let obj = schema.as_object()?;
        let mut acc = self.copy_map_except(at, obj, "allOf")?;
        let branches = obj.get("allOf").and_then(Value::as_array).map(Vec::as_slice).unwrap_or_default();
        for (i, br) in branches.iter().enumerate() {
            // A branch is charged a value, its pointer and its keys.
            let keys = br.as_object().map_or(0, Map::len);
            if !self.charge_scan(at, at.len().saturating_add(keys)) {
                return None;
            }
            let bptr = ptr_i(&ptr(at, "allOf"), i);
            if !self.charge(&bptr) {
                return None;
            }
            let mut pushed = false;
            let mut with_siblings = None;
            let target = if Refs::ref_of(br).is_some() {
                let (t, tp) = self.resolve(br, &bptr)?;
                if !self.charge_stack(&bptr, &tp) {
                    return None;
                }
                if self.stack.contains(&tp) {
                    self.report.warn("recursive_schema", &tp, "recursive allOf composition: expansion stops at the first repetition");
                    continue;
                }
                if self.stack.len() >= self.max_ref_depth {
                    self.report.warn(
                        "ref_depth_limit",
                        &bptr,
                        format!("more than {} nested $ref levels were not expanded", self.max_ref_depth),
                    );
                    continue;
                }
                self.stack.push(tp);
                pushed = true;
                // Keywords next to the `$ref` fill in what the target lacks.
                if let (Some(tm), Some(bm)) = (t.as_object(), br.as_object())
                    && bm.keys().any(|k| k != "$ref" && !tm.contains_key(k))
                {
                    let Some(Value::Object(mut m)) = self.copy(&bptr, t) else {
                        self.stack.pop();
                        return None;
                    };
                    for (k, v) in bm {
                        if k != "$ref" && !m.contains_key(k) {
                            let Some(v) = self.copy(&bptr, v) else {
                                self.stack.pop();
                                return None;
                            };
                            m.insert(k.clone(), v);
                        }
                    }
                    with_siblings = Some(Value::Object(m));
                }
                t
            } else {
                br
            };
            let cur = with_siblings.as_ref().unwrap_or(target);
            let nested = if !cur.get("allOf").is_some_and(Value::is_array) {
                None
            } else if nesting >= MAX_NESTING {
                let msg = format!("allOf nesting deeper than {MAX_NESTING} levels was not expanded");
                self.report.warn("schema_depth_limit", &bptr, msg);
                None
            } else {
                let m = self.merge_all_of_at(cur, &bptr, nesting + 1);
                if m.is_none() {
                    if pushed {
                        self.stack.pop();
                    }
                    return None;
                }
                m
            };
            if pushed {
                self.stack.pop();
            }
            let kept = match nested.as_ref().unwrap_or(cur) {
                Value::Object(m) => self.merge_into(&mut acc, m, at),
                Value::Bool(false) => {
                    self.report.warn("unsatisfiable_schema", &bptr, "allOf contains `false`: no value can satisfy it");
                    true
                }
                _ => true,
            };
            if !kept {
                return None;
            }
        }
        Some(Value::Object(acc))
    }

    /// Merge `src` into `acc`. Only what is kept is copied, and each copy is
    /// charged first; `false` once the byte budget is spent. `allOf` members
    /// were merged (or cut) by the caller. The lookups and comparisons a merge
    /// makes are charged too: each key, each property name and the size of a
    /// property compared with one already merged, the `required` names, and
    /// the pairs of `type` and `enum` values compared.
    fn merge_into(&mut self, acc: &mut Map<String, Value>, src: &Map<String, Value>, at: &str) -> bool {
        if !self.charge_scan(at, src.keys().fold(0usize, |n, k| n.saturating_add(k.len() + 1))) {
            return false;
        }
        for (k, v) in src {
            match k.as_str() {
                "allOf" => {}
                "properties" => {
                    let dst = acc.entry("properties").or_insert_with(|| Value::Object(Map::new()));
                    if let (Value::Object(d), Value::Object(s)) = (dst, v) {
                        for (pk, pv) in s {
                            if !self.charge_scan(at, pk.len().saturating_add(1)) {
                                return false;
                            }
                            match d.get_mut(pk) {
                                Some(existing) => {
                                    // The comparison walks at most `pv`.
                                    let Some(n) = size_within(pv, self.bytes.get()) else {
                                        self.bytes_spent(at);
                                        return false;
                                    };
                                    if !self.charge_scan(at, n) {
                                        return false;
                                    }
                                    if *existing != *pv {
                                        let Some(pv) = self.copy(at, pv) else { return false };
                                        let prev = std::mem::take(existing);
                                        *existing = json!({ "allOf": [prev, pv] });
                                    }
                                }
                                None => {
                                    let Some(pv) = self.copy(at, pv) else { return false };
                                    d.insert(pk.clone(), pv);
                                }
                            }
                        }
                    }
                }
                "required" => {
                    let dst = acc.entry("required").or_insert_with(|| Value::Array(vec![]));
                    if let (Value::Array(d), Value::Array(s)) = (dst, v) {
                        // The names merged so far go into a set, and each new
                        // one is looked up in it: all charged first.
                        if !self.charge_scan(at, names_cost(d.iter().chain(s))) {
                            return false;
                        }
                        let mut names: HashSet<String> = d.iter().filter_map(Value::as_str).map(str::to_string).collect();
                        let mut ignored = false;
                        for x in s {
                            let Some(n) = x.as_str() else {
                                ignored = true;
                                continue;
                            };
                            if names.insert(n.to_string()) {
                                let Some(x) = self.copy(at, x) else { return false };
                                d.push(x);
                            }
                        }
                        if ignored {
                            self.report.warn(
                                "invalid_required",
                                &ptr(at, "allOf"),
                                "`required` lists values that are not names; they are ignored",
                            );
                        }
                    }
                }
                "type" => match acc.get("type") {
                    None => {
                        let Some(v) = self.copy(at, v) else { return false };
                        acc.insert(k.clone(), v);
                    }
                    Some(existing) => {
                        // Every pair of types may be compared.
                        let ((na, la), (nb, lb)) = (type_size(existing), type_size(v));
                        if !self.charge_scan(at, na.saturating_mul(nb).saturating_add(la).saturating_add(lb)) {
                            return false;
                        }
                        let a = type_set(existing);
                        let b = type_set(v);
                        let inter: Vec<String> = a
                            .iter()
                            .filter(|t| b.contains(t) || (*t == "integer" && b.iter().any(|x| x == "number")))
                            .cloned()
                            .chain(b.iter().filter(|t| *t == "integer" && a.iter().any(|x| x == "number")).cloned())
                            .collect();
                        if inter.is_empty() {
                            self.report.warn(
                                "contradictory_schema",
                                &ptr(at, "allOf"),
                                format!(
                                    "allOf branches require incompatible types ({} vs {}); no value can satisfy both",
                                    a.join("|"),
                                    b.join("|")
                                ),
                            );
                        } else {
                            // The generator uses the first type; keep a plain string so
                            // merged schemas never look like 3.1 type arrays.
                            acc.insert(k.clone(), Value::String(inter[0].clone()));
                        }
                    }
                },
                "minimum" | "minLength" | "minItems" | "minProperties" => merge_num(acc, k, v, f64::max),
                "maximum" | "maxLength" | "maxItems" | "maxProperties" => merge_num(acc, k, v, f64::min),
                "exclusiveMinimum" if v.is_number() => merge_num(acc, k, v, f64::max),
                "exclusiveMaximum" if v.is_number() => merge_num(acc, k, v, f64::min),
                "enum" if acc.get("enum").is_some_and(Value::is_array) && v.is_array() => {
                    if let (Some(Value::Array(a)), Value::Array(b)) = (acc.get_mut("enum"), v) {
                        // Each kept value is compared with every value of `b`
                        // (twice: to test, then to keep): each comparison walks
                        // at most the kept value, so its size is charged per
                        // value of `b`.
                        let cost = size_of_all(a, self.bytes.get()).and_then(|n| n.checked_mul(b.len())).and_then(|n| n.checked_mul(2));
                        if !cost.is_some_and(|n| self.charge_scan(at, n)) {
                            self.bytes_spent(at);
                            return false;
                        }
                        if a.iter().any(|x| b.contains(x)) {
                            a.retain(|x| b.contains(x));
                        } else {
                            self.report.warn("contradictory_schema", &ptr(at, "allOf"), "allOf branches have disjoint `enum` values");
                        }
                    }
                }
                _ => {
                    if !acc.contains_key(k) {
                        let Some(v) = self.copy(at, v) else { return false };
                        acc.insert(k.clone(), v);
                    }
                }
            }
        }
        true
    }

    fn gen_object(&mut self, obj: &Map<String, Value>, at: &str, depth: usize) -> Option<Value> {
        let empty = Map::new();
        let props = obj.get("properties").and_then(Value::as_object).unwrap_or(&empty);
        let listed = obj.get("required").and_then(Value::as_array).map(Vec::as_slice).unwrap_or_default();
        // Reading the `required` names (into a set, and later against the
        // members) is charged up front: a byte per name plus its length.
        if !self.charge_scan(at, names_cost(listed)) {
            return None;
        }
        let required: Vec<&str> = listed.iter().filter_map(Value::as_str).collect();
        let required_set: HashSet<&str> = required.iter().copied().collect();
        let mut out = Map::new();
        let pbase = ptr(at, "properties");
        for (k, ps) in props {
            // Every member looked at is charged, generated or not.
            if !self.charge_scan(at, k.len().saturating_add(1)) {
                break;
            }
            let req = required_set.contains(k.as_str());
            if !req && !self.include_optional {
                continue;
            }
            // Its pointer is built (and copied into findings) only now: charged.
            if !self.charge_scan(at, pbase.len().saturating_add(k.len())) {
                break;
            }
            let pp = ptr(&pbase, k);
            if self.flag(ps, &pp, "readOnly") {
                continue;
            }
            match self.gen_value(ps, &pp, depth + 1, Some(k)) {
                Some(v) => {
                    out.insert(k.clone(), v);
                }
                None if req => {
                    // The null stands in for a value and is charged like one;
                    // once a budget is spent the member is left out instead.
                    if !self.charge(&pp) {
                        break;
                    }
                    self.report.warn(
                        "required_member_unsatisfied",
                        &pp,
                        format!("required member '{k}' could not be generated (recursive or unsatisfiable); null used"),
                    );
                    out.insert(k.clone(), Value::Null);
                }
                None => {}
            }
        }
        let ap = obj.get("additionalProperties");
        let rptr = ptr(at, "required");
        for r in &required {
            if props.contains_key(*r) {
                continue;
            }
            // As above: each null is charged to both budgets before it is inserted.
            if !self.charge(&rptr) {
                break;
            }
            if ap == Some(&Value::Bool(false)) {
                self.report.warn(
                    "contradictory_schema",
                    &rptr,
                    format!("'{r}' is required but not allowed by additionalProperties: false"),
                );
            } else {
                self.report.warn("required_member_undeclared", &rptr, format!("'{r}' is required but has no schema; null used"));
            }
            out.insert((*r).to_string(), Value::Null);
        }
        let min_props = obj.get("minProperties").and_then(Value::as_u64).unwrap_or(0) as usize;
        if props.is_empty() && out.is_empty() && (self.include_optional || min_props > 0) {
            match ap {
                Some(s @ Value::Object(_)) => {
                    let wanted = min_props.clamp(1, 3);
                    for i in 1..=wanted {
                        if let Some(v) = self.gen_value(s, &ptr(at, "additionalProperties"), depth + 1, None) {
                            out.insert(format!("property{i}"), v);
                        }
                    }
                }
                Some(Value::Bool(true)) | None if min_props > 0 => {
                    for i in 1..=min_props.min(3) {
                        out.insert(format!("property{i}"), Value::String(String::new()));
                    }
                }
                _ => {}
            }
        }
        if out.len() < min_props {
            self.report.warn(
                "min_properties_unsatisfied",
                &ptr(at, "minProperties"),
                format!("minProperties is {min_props} but only {} members were generated", out.len()),
            );
        }
        if let Some(max) = obj.get("maxProperties").and_then(Value::as_u64)
            && out.len() as u64 > max
        {
            self.report.warn(
                "contradictory_schema",
                &ptr(at, "maxProperties"),
                format!("maxProperties is {max} but {} members are required or included", out.len()),
            );
        }
        Some(Value::Object(out))
    }

    fn gen_array(&mut self, obj: &Map<String, Value>, at: &str, depth: usize, name: Option<&str>) -> Option<Value> {
        let min = obj.get("minItems").and_then(Value::as_u64).unwrap_or(0) as usize;
        let max = obj.get("maxItems").and_then(Value::as_u64).map(|m| m as usize);
        if let Some(m) = max
            && m < min
        {
            self.report.warn("contradictory_schema", at, format!("minItems {min} is greater than maxItems {m}"));
        }
        let mut count = match self.mode {
            SampleMode::Blank => min,
            SampleMode::Sample => min.max(1),
        };
        if let Some(m) = max {
            count = count.min(m.max(min));
        }
        if count > MAX_ARRAY_ITEMS {
            self.report.warn(
                "sample_size_limit",
                at,
                format!("minItems {count} exceeds the sample cap; {MAX_ARRAY_ITEMS} items generated"),
            );
            count = MAX_ARRAY_ITEMS;
        }
        let prefix: &[Value] = match (obj.get("prefixItems"), obj.get("items")) {
            (Some(Value::Array(p)), _) => p.as_slice(),
            (_, Some(Value::Array(p))) => p.as_slice(), // draft-4 tuple form
            _ => &[],
        };
        let items = match obj.get("items") {
            Some(v @ (Value::Object(_) | Value::Bool(_))) => Some(v),
            _ => None,
        };
        let count = count.max(if self.mode == SampleMode::Sample { prefix.len() } else { 0 });
        let mut out = Vec::new();
        for i in 0..count {
            let (s, p) = if i < prefix.len() {
                (&prefix[i], ptr_i(&ptr(at, if obj.contains_key("prefixItems") { "prefixItems" } else { "items" }), i))
            } else if let Some(it) = items {
                (it, ptr(at, "items"))
            } else {
                break;
            };
            match self.gen_value(s, &p, depth + 1, name) {
                Some(v) => out.push(v),
                None => break,
            }
        }
        if obj.get("uniqueItems").and_then(Value::as_bool) == Some(true) && out.len() > 1 {
            let mut uniq: Vec<Value> = Vec::new();
            for v in out {
                if !uniq.contains(&v) {
                    uniq.push(v);
                }
            }
            out = uniq;
        }
        if out.len() < min {
            self.report.warn("min_items_unsatisfied", at, format!("minItems is {min} but only {} items could be generated", out.len()));
        }
        Some(Value::Array(out))
    }

    fn gen_string(&mut self, obj: &Map<String, Value>, at: &str, name: Option<&str>) -> Value {
        let min = obj.get("minLength").and_then(Value::as_u64).map(|v| v as usize);
        let max = obj.get("maxLength").and_then(Value::as_u64).map(|v| v as usize);
        if let (Some(a), Some(b)) = (min, max)
            && a > b
        {
            self.report.warn("contradictory_schema", at, format!("minLength {a} is greater than maxLength {b}"));
        }
        if self.mode == SampleMode::Blank {
            return Value::String(String::new());
        }
        let format = obj.get("format").and_then(Value::as_str).unwrap_or("");
        let encoding = obj.get("contentEncoding").and_then(Value::as_str).unwrap_or("");
        if format == "binary" || (obj.contains_key("contentMediaType") && encoding.is_empty() && format.is_empty()) {
            self.report.warn("binary_placeholder", at, "binary content cannot be generated; left empty");
            return Value::String(String::new());
        }
        if format == "password" || name.is_some_and(is_credential_name) {
            self.report.warn("credential_left_blank", at, "credential-like value is never generated; left empty for you to supply");
            return Value::String(String::new());
        }
        if let Some(p) = obj.get("pattern").and_then(Value::as_str) {
            let msg = format!("the sample is not guaranteed to match pattern `{}`", clip(p, 200));
            self.report.warn("pattern_not_enforced", &ptr(at, "pattern"), msg);
        }
        let fixed = |s: String| (s, true);
        let (s, fixed_shape) = match format {
            "date-time" => fixed(self.date_time()),
            "date" => fixed(self.date_time()[..10].to_string()),
            "time" => fixed(format!("{}Z", &self.date_time()[11..19])),
            "duration" => fixed(format!("P{}D", self.rng.range_i128(1, 30))),
            "uuid" => fixed(self.uuid()),
            "email" | "idn-email" => fixed(format!("user{}@example.com", self.rng.range_i128(1, 9999))),
            "hostname" | "idn-hostname" => fixed(format!("host{}.example.com", self.rng.range_i128(1, 999))),
            "ipv4" => fixed(format!("192.0.2.{}", self.rng.range_i128(1, 254))),
            "ipv6" => fixed(format!("2001:db8::{:x}", self.rng.range_i128(1, 0xffff))),
            "uri" | "url" | "iri" => fixed(format!("https://example.com/resource/{}", self.rng.range_i128(1, 9999))),
            "uri-reference" | "iri-reference" => fixed(format!("/resource/{}", self.rng.range_i128(1, 9999))),
            "uri-template" => fixed("https://example.com/{id}".to_string()),
            "json-pointer" => fixed("/example/0".to_string()),
            "relative-json-pointer" => fixed("1/example".to_string()),
            "regex" => fixed("^[a-z]+$".to_string()),
            "byte" => fixed(self.base64()),
            "int32" | "int64" => fixed(self.rng.range_i128(1, 100_000).to_string()),
            _ if encoding == "base64" || encoding == "base64url" => fixed(self.base64()),
            _ => {
                let stem = name.map(|n| n.chars().filter(|c| c.is_ascii_alphanumeric()).take(24).collect::<String>()).unwrap_or_default();
                let stem = if stem.is_empty() { "string".to_string() } else { stem };
                (format!("{stem}-{}", self.rng.hex(4)), false)
            }
        };
        let len = s.chars().count();
        if fixed_shape {
            if min.is_some_and(|m| len < m) || max.is_some_and(|m| len > m) {
                self.report.warn(
                    "contradictory_schema",
                    at,
                    format!("format '{format}' produces {len} characters, outside the length limits; the sample violates them"),
                );
            }
            return Value::String(s);
        }
        let mut s = s;
        if let Some(m) = min
            && len < m
        {
            let pad = m.min(4096) - len.min(m.min(4096));
            // The padding is generated output: charged before it is made.
            if self.take_bytes(at, pad) {
                s.push_str(&"x".repeat(pad));
            }
        }
        if let Some(m) = max
            && s.chars().count() > m
        {
            s = s.chars().take(m).collect();
        }
        Value::String(s)
    }

    fn gen_integer(&mut self, obj: &Map<String, Value>, at: &str) -> Value {
        if self.mode == SampleMode::Blank {
            return Value::Number(0.into());
        }
        let (fmin, fmax) = match obj.get("format").and_then(Value::as_str) {
            Some("int32") => (i128::from(i32::MIN), i128::from(i32::MAX)),
            Some("uint32") => (0, i128::from(u32::MAX)),
            _ => (i128::from(i64::MIN), i128::from(i64::MAX)),
        };
        let (lo_f, lo_ex) = bound(obj, "minimum", "exclusiveMinimum");
        let (hi_f, hi_ex) = bound(obj, "maximum", "exclusiveMaximum");
        let mut lo = lo_f.map(|v| {
            let c = v.ceil();
            let c = if lo_ex && c == v { c + 1.0 } else { c };
            clamp_i128(c, fmin, fmax)
        });
        let mut hi = hi_f.map(|v| {
            let f = v.floor();
            let f = if hi_ex && f == v { f - 1.0 } else { f };
            clamp_i128(f, fmin, fmax)
        });
        match (lo, hi) {
            (None, None) => {
                lo = Some(1.max(fmin));
                hi = Some(1000.min(fmax));
            }
            (Some(l), None) => hi = Some(l.saturating_add(1000).min(fmax)),
            (None, Some(h)) => lo = Some(h.saturating_sub(1000).max(fmin)),
            _ => {}
        }
        let (lo, hi) = (lo.unwrap_or(0), hi.unwrap_or(0));
        if lo > hi {
            self.report.warn("contradictory_schema", at, format!("no integer satisfies minimum {lo} and maximum {hi}; minimum used"));
            return Value::Number((lo as i64).into());
        }
        let v = match obj.get("multipleOf").and_then(Value::as_f64).filter(|m| *m > 0.0 && m.fract() == 0.0) {
            Some(m) => {
                let m = m as i128;
                let kmin = div_ceil(lo, m);
                let kmax = div_floor(hi, m);
                if kmin > kmax {
                    self.report.warn("contradictory_schema", at, format!("no multiple of {m} lies within [{lo}, {hi}]; minimum used"));
                    lo
                } else {
                    self.rng.range_i128(kmin, kmax).saturating_mul(m)
                }
            }
            None => self.rng.range_i128(lo, hi),
        };
        Value::Number((v.clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64).into())
    }

    fn gen_number(&mut self, obj: &Map<String, Value>, at: &str) -> Value {
        if self.mode == SampleMode::Blank {
            return Value::Number(0.into());
        }
        let (lo_f, lo_ex) = bound(obj, "minimum", "exclusiveMinimum");
        let (hi_f, hi_ex) = bound(obj, "maximum", "exclusiveMaximum");
        let (lo, hi) = match (lo_f, hi_f) {
            (None, None) => (1.0, 1000.0),
            (Some(l), None) => (l, l + 1000.0),
            (None, Some(h)) => (h - 1000.0, h),
            (Some(l), Some(h)) => (l, h),
        };
        if lo > hi || (lo == hi && (lo_ex || hi_ex)) {
            self.report.warn("contradictory_schema", at, format!("no number satisfies the range [{lo}, {hi}]; minimum used"));
            return Number::from_f64(lo).map(Value::Number).unwrap_or(Value::Null);
        }
        let v = match obj.get("multipleOf").and_then(Value::as_f64).filter(|m| *m > 0.0) {
            Some(m) => {
                let kmin = ((lo / m).ceil() as i128).saturating_add(i128::from(lo_ex && (lo / m).fract() == 0.0));
                let kmax = ((hi / m).floor() as i128).saturating_sub(i128::from(hi_ex && (hi / m).fract() == 0.0));
                if kmin > kmax {
                    self.report.warn("contradictory_schema", at, format!("no multiple of {m} lies within the range; minimum used"));
                    lo
                } else {
                    self.rng.range_i128(kmin, kmax) as f64 * m
                }
            }
            None => {
                let raw = lo + self.rng.unit_f64() * (hi - lo);
                let mut v = (raw * 100.0).round() / 100.0;
                if v < lo || (lo_ex && v <= lo) {
                    v = if lo_ex { lo + (hi - lo) / 2.0 } else { lo };
                }
                if v > hi || (hi_ex && v >= hi) {
                    v = if hi_ex { lo + (hi - lo) / 2.0 } else { hi };
                }
                v
            }
        };
        Number::from_f64(v).map(Value::Number).unwrap_or(Value::Null)
    }

    fn date_time(&mut self) -> String {
        // 2020-01-01T00:00:00Z .. ~2029-12-31
        let secs = self.rng.range_i128(1_577_836_800, 1_893_455_999) as i64;
        chrono::DateTime::from_timestamp(secs, 0)
            .map(|d| d.format("%Y-%m-%dT%H:%M:%SZ").to_string())
            .unwrap_or_else(|| "2024-01-01T00:00:00Z".into())
    }

    fn uuid(&mut self) -> String {
        let hi = self.rng.next_u64();
        let lo = self.rng.next_u64();
        let bytes: [u8; 16] = ((u128::from(hi) << 64) | u128::from(lo)).to_be_bytes();
        uuid::Builder::from_random_bytes(bytes).into_uuid().to_string()
    }

    fn base64(&mut self) -> String {
        let bytes: Vec<u8> = self.rng.next_u64().to_be_bytes().to_vec();
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }
}

fn ptr_i(base: &str, i: usize) -> String {
    format!("{base}/{i}")
}

/// Explicit example of a schema object: 3.1+ `examples` array (first), then
/// `example`, then the widespread `x-example` extension.
pub(crate) fn example_of(obj: &Map<String, Value>, dialect: Dialect) -> Option<&Value> {
    if is_31_plus(dialect)
        && let Some(first) = obj.get("examples").and_then(Value::as_array).and_then(|a| a.first())
    {
        return Some(first);
    }
    obj.get("example").or_else(|| obj.get("x-example"))
}

/// Charge a copy of `v` against an import's sample byte budget; `false` (and
/// the budget is spent) when it does not fit.
pub(crate) fn charge_copy(bytes: &Cell<usize>, v: &Value) -> bool {
    let left = bytes.get();
    match size_within(v, left) {
        Some(n) => {
            bytes.set(left - n);
            true
        }
        None => {
            bytes.set(0);
            false
        }
    }
}

/// Charge `n` bytes against an import's sample byte budget; `false` (and
/// the budget is spent) when they do not fit.
pub(crate) fn charge_len(bytes: &Cell<usize>, n: usize) -> bool {
    let left = bytes.get();
    if n < left {
        bytes.set(left - n);
        true
    } else {
        bytes.set(0);
        false
    }
}

/// Size estimate of a copy of `v` (its JSON text, roughly), or `None` when it
/// exceeds `limit`. The walk stops as soon as the limit is passed, so it costs
/// at most `limit`.
fn size_within(v: &Value, limit: usize) -> Option<usize> {
    fn walk(v: &Value, left: &mut usize) -> bool {
        let own = match v {
            Value::String(s) => s.len() + VALUE_BYTES,
            _ => VALUE_BYTES,
        };
        if own > *left {
            return false;
        }
        *left -= own;
        match v {
            Value::Array(a) => a.iter().all(|x| walk(x, left)),
            Value::Object(o) => o.iter().all(|(k, x)| {
                if k.len() + VALUE_BYTES > *left {
                    return false;
                }
                *left -= k.len() + VALUE_BYTES;
                walk(x, left)
            }),
            _ => true,
        }
    }
    let mut left = limit;
    let fits = walk(v, &mut left);
    fits.then_some(limit - left)
}

fn infer_type(obj: &Map<String, Value>) -> Option<&'static str> {
    let has = |k: &str| obj.contains_key(k);
    if has("properties") || has("additionalProperties") || has("minProperties") || has("maxProperties") || has("patternProperties") {
        Some("object")
    } else if has("items") || has("prefixItems") || has("minItems") || has("maxItems") {
        Some("array")
    } else if has("minLength") || has("maxLength") || has("pattern") || has("format") {
        Some("string")
    } else if has("minimum") || has("maximum") || has("multipleOf") || has("exclusiveMinimum") || has("exclusiveMaximum") {
        Some("number")
    } else {
        None
    }
}

/// Bytes charged for reading a `required` list: one per entry plus the
/// length of each name.
fn names_cost<'v>(vals: impl IntoIterator<Item = &'v Value>) -> usize {
    vals.into_iter().fold(0usize, |n, x| n.saturating_add(x.as_str().map_or(0, str::len)).saturating_add(1))
}

/// (entries, bytes) of a `type` value, for charging a comparison of two.
fn type_size(v: &Value) -> (usize, usize) {
    match v {
        Value::String(s) => (1, s.len()),
        Value::Array(a) => (a.len(), a.iter().fold(0usize, |n, t| n.saturating_add(t.as_str().map_or(1, str::len)))),
        _ => (0, 0),
    }
}

/// The summed [`size_within`] of `vals`, or `None` past `limit`.
fn size_of_all(vals: &[Value], limit: usize) -> Option<usize> {
    let mut total = 0usize;
    for v in vals {
        total += size_within(v, limit.checked_sub(total)?)?;
    }
    Some(total)
}

fn type_set(v: &Value) -> Vec<String> {
    match v {
        Value::String(s) => vec![s.clone()],
        Value::Array(a) => a.iter().filter_map(Value::as_str).map(str::to_string).collect(),
        _ => vec![],
    }
}

fn merge_num(acc: &mut Map<String, Value>, k: &str, v: &Value, pick: fn(f64, f64) -> f64) {
    let Some(new) = v.as_f64() else { return };
    let merged = match acc.get(k).and_then(Value::as_f64) {
        Some(old) => pick(old, new),
        None => new,
    };
    let num = if merged.fract() == 0.0 && merged.abs() < 9.0e15 { Value::Number((merged as i64).into()) } else { json!(merged) };
    acc.insert(k.to_string(), num);
}

/// (bound, exclusive) from either the 3.0 boolean form or the 3.1 numeric form.
fn bound(obj: &Map<String, Value>, inclusive: &str, exclusive: &str) -> (Option<f64>, bool) {
    let inc = obj.get(inclusive).and_then(Value::as_f64);
    match obj.get(exclusive) {
        Some(Value::Bool(b)) => (inc, *b),
        Some(Value::Number(n)) => {
            let e = n.as_f64();
            match (inc, e) {
                (Some(i), Some(e)) if i > e && inclusive == "minimum" => (Some(i), false),
                (Some(i), Some(e)) if i < e && inclusive == "maximum" => (Some(i), false),
                (_, e) => (e, true),
            }
        }
        _ => (inc, false),
    }
}

fn clamp_i128(v: f64, lo: i128, hi: i128) -> i128 {
    if v.is_nan() {
        return 0;
    }
    if v <= lo as f64 {
        lo
    } else if v >= hi as f64 {
        hi
    } else {
        v as i128
    }
}

fn div_floor(a: i128, b: i128) -> i128 {
    let d = a / b;
    if (a % b != 0) && ((a < 0) != (b < 0)) { d - 1 } else { d }
}

fn div_ceil(a: i128, b: i128) -> i128 {
    let d = a / b;
    if (a % b != 0) && ((a < 0) == (b < 0)) { d + 1 } else { d }
}

fn value_matches_types(v: &Value, types: &[String], obj: &Map<String, Value>) -> bool {
    let nullable = obj.get("nullable").and_then(Value::as_bool) == Some(true);
    types.iter().any(|t| match (t.as_str(), v) {
        ("null", Value::Null) => true,
        (_, Value::Null) => nullable,
        ("string", Value::String(_)) => true,
        ("integer", Value::Number(n)) => n.is_i64() || n.is_u64() || n.as_f64().is_some_and(|f| f.fract() == 0.0),
        ("number", Value::Number(_)) => true,
        ("boolean", Value::Bool(_)) => true,
        ("array", Value::Array(_)) => true,
        ("object", Value::Object(_)) => true,
        _ => false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gen_with(root: &Value, schema: &Value, mode: SampleMode, include_optional: bool) -> (Option<Value>, ImportReport) {
        let refs = Refs { root, max_depth: 16, max_expansions: 10_000 };
        let mut rep = ImportReport::default();
        let opts = ImportOptions { mode, include_optional, ..Default::default() };
        let bytes = Cell::new(1 << 20);
        let v = SampleGen::new(refs, &mut rep, Dialect::OpenApi31, &opts, 7, &bytes).generate(schema, "/s", None);
        (v, rep)
    }

    #[test]
    fn flatten_has_one_budget_per_payload() {
        let root = json!({"components": {"schemas": {"A": {"type": "object", "properties": {"a": {"type": "string"}}}}}});
        let refs = Refs { root: &root, max_depth: 16, max_expansions: 10_000 };
        let mut rep = ImportReport::default();
        let opts = ImportOptions { max_sample_nodes: 2, ..Default::default() };
        let bytes = Cell::new(1 << 20);
        let mut sg = SampleGen::new(refs, &mut rep, Dialect::OpenApi31, &opts, 7, &bytes);
        let schema = json!({"allOf": [{"$ref": "#/components/schemas/A"}, {"required": ["a"]}]});
        let (flat, _) = sg.flatten(&schema, "/s");
        assert!(flat["properties"]["a"].is_object(), "{flat}");
        assert_eq!(flat["required"], json!(["a"]));
        // The payload's own two nodes are still there.
        let v = sg.generate(&json!({"type": "array", "items": {"type": "string"}}), "/t", None);
        assert_eq!(v.map(|v| v.as_array().map(Vec::len)), Some(Some(1)));
        // Lookups share one budget per payload: this one is not merged ...
        let (flat, _) = sg.flatten(&schema, "/s");
        assert!(flat.get("allOf").is_some(), "{flat}");
        // ... and the next payload starts afresh.
        sg.reset_budget();
        let (flat, _) = sg.flatten(&schema, "/s");
        assert!(flat["properties"]["a"].is_object(), "{flat}");
    }

    #[test]
    fn flatten_borrows_when_nothing_is_merged() {
        let root = json!({"components": {"schemas": {"A": {"type": "string", "description": "x".repeat(4_000)}}}});
        let refs = Refs { root: &root, max_depth: 16, max_expansions: 10_000 };
        let mut rep = ImportReport::default();
        let opts = ImportOptions::default();
        let bytes = Cell::new(1_000);
        let mut sg = SampleGen::new(refs, &mut rep, Dialect::OpenApi31, &opts, 7, &bytes);
        let schema = json!({"$ref": "#/components/schemas/A"});
        let (flat, at) = sg.flatten(&schema, "/s");
        // The resolved schema is borrowed: it is bigger than the whole budget,
        // yet it is not replaced by `null`, and only the pointers are charged.
        assert!(matches!(flat, Cow::Borrowed(_)));
        assert_eq!(flat["type"], json!("string"));
        assert_eq!(at, "/components/schemas/A");
        assert!(bytes.get() > 900, "{} bytes left", bytes.get());
    }

    #[test]
    fn copies_stop_at_the_import_byte_budget() {
        let root = json!({});
        let refs = Refs { root: &root, max_depth: 16, max_expansions: 10_000 };
        let mut rep = ImportReport::default();
        let opts = ImportOptions::default();
        let bytes = Cell::new(10_000);
        let mut sg = SampleGen::new(refs, &mut rep, Dialect::OpenApi31, &opts, 7, &bytes);
        let schema = json!({"type": "string", "example": "x".repeat(4_000)});
        assert!(sg.generate(&schema, "/a", None).is_some());
        assert!(sg.generate(&schema, "/b", None).is_some());
        // The third copy does not fit: nothing more is copied or generated.
        assert!(sg.generate(&schema, "/c", None).is_none());
        assert!(sg.generate(&json!({"type": "string"}), "/d", None).is_none());
        assert_eq!(bytes.get(), 0);
        assert!(rep.has_code("sample_size_limit"));
    }

    #[test]
    fn recursion_is_cut_and_reported() {
        let root = json!({"components": {"schemas": {"Node": {
            "type": "object", "required": ["name", "child"],
            "properties": {"name": {"type": "string"}, "child": {"$ref": "#/components/schemas/Node"}}
        }}}});
        let (v, rep) = gen_with(&root, &json!({"$ref": "#/components/schemas/Node"}), SampleMode::Sample, false);
        let v = v.unwrap();
        assert!(v["name"].is_string());
        assert!(v["child"].is_null());
        assert!(rep.has_code("recursive_schema"));
    }

    #[test]
    fn integer_bounds_and_multiple() {
        let root = json!({});
        for seed_schema in [
            json!({"type": "integer", "minimum": 10, "maximum": 20, "multipleOf": 5}),
            json!({"type": "integer", "exclusiveMinimum": 10, "exclusiveMaximum": 12}),
        ] {
            let (v, _) = gen_with(&root, &seed_schema, SampleMode::Sample, false);
            let n = v.unwrap().as_i64().unwrap();
            if seed_schema.get("multipleOf").is_some() {
                assert!([10, 15, 20].contains(&n), "{n}");
            } else {
                assert_eq!(n, 11);
            }
        }
        let (v, rep) = gen_with(&root, &json!({"type": "integer", "minimum": 5, "maximum": 1}), SampleMode::Sample, false);
        assert_eq!(v.unwrap(), json!(5));
        assert!(rep.has_code("contradictory_schema"));
    }

    #[test]
    fn blank_mode_is_structural() {
        let root = json!({});
        let s = json!({"type": "object", "required": ["a", "b", "c"], "properties": {
            "a": {"type": "string", "example": "x"}, "b": {"type": "integer", "default": 4}, "c": {"type": "array", "items": {"type": "string"}},
            "d": {"type": "boolean"}
        }});
        let (v, _) = gen_with(&root, &s, SampleMode::Blank, false);
        assert_eq!(v.unwrap(), json!({"a": "", "b": 0, "c": []}));
        let (v, _) = gen_with(&root, &s, SampleMode::Blank, true);
        assert_eq!(v.unwrap(), json!({"a": "", "b": 0, "c": [], "d": false}));
    }

    #[test]
    fn read_only_omitted_and_write_only_kept() {
        let root = json!({});
        let s = json!({"type": "object", "required": ["id", "secretCode"], "properties": {
            "id": {"type": "integer", "readOnly": true}, "secretCode": {"type": "string", "writeOnly": true, "example": "abc"}
        }});
        let (v, _) = gen_with(&root, &s, SampleMode::Sample, false);
        assert_eq!(v.unwrap(), json!({"secretCode": "abc"}));
    }

    #[test]
    fn one_of_first_branch_warns() {
        let root = json!({});
        let s = json!({"oneOf": [{"type": "string", "enum": ["a"]}, {"type": "integer"}]});
        let (v, rep) = gen_with(&root, &s, SampleMode::Sample, false);
        assert_eq!(v.unwrap(), json!("a"));
        assert!(rep.has_code("composition_first_branch"));
    }

    #[test]
    fn all_of_merges_and_detects_conflict() {
        let root = json!({});
        let s = json!({"allOf": [{"type": "string"}, {"type": "integer"}]});
        let (_, rep) = gen_with(&root, &s, SampleMode::Sample, false);
        assert!(rep.has_code("contradictory_schema"));
        let s = json!({"allOf": [
            {"type": "object", "required": ["a"], "properties": {"a": {"type": "string", "enum": ["x"]}}},
            {"type": "object", "required": ["b"], "properties": {"b": {"type": "integer", "minimum": 3, "maximum": 3}}}
        ]});
        let (v, _) = gen_with(&root, &s, SampleMode::Sample, false);
        assert_eq!(v.unwrap(), json!({"a": "x", "b": 3}));
    }

    #[test]
    fn all_of_required_ignores_values_that_are_not_names() {
        let root = json!({});
        let s = json!({"allOf": [
            {"type": "object", "required": ["a"], "properties": {"a": {"type": "string", "enum": ["x"]}}},
            {"required": [1, 2, "a", "b", {"c": 3}], "properties": {"b": {"type": "integer", "enum": [4]}}}
        ]});
        let (v, rep) = gen_with(&root, &s, SampleMode::Sample, false);
        assert_eq!(v.unwrap(), json!({"a": "x", "b": 4}));
        assert!(rep.has_code("invalid_required"));
    }

    #[test]
    fn strings_respect_lengths_and_formats() {
        let root = json!({});
        let (v, _) = gen_with(&root, &json!({"type": "string", "minLength": 20, "maxLength": 25}), SampleMode::Sample, false);
        let s = v.unwrap();
        let n = s.as_str().unwrap().len();
        assert!((20..=25).contains(&n), "{s}");
        let (v, _) = gen_with(&root, &json!({"type": "string", "format": "uuid"}), SampleMode::Sample, false);
        assert!(uuid::Uuid::parse_str(v.unwrap().as_str().unwrap()).is_ok());
        let (v, _) = gen_with(&root, &json!({"type": "string", "format": "date-time"}), SampleMode::Sample, false);
        assert!(chrono::DateTime::parse_from_rfc3339(v.unwrap().as_str().unwrap()).is_ok());
        let (v, rep) = gen_with(&root, &json!({"type": "string", "format": "password"}), SampleMode::Sample, false);
        assert_eq!(v.unwrap(), json!(""));
        assert!(rep.has_code("credential_left_blank"));
    }

    #[test]
    fn nullable_type_arrays() {
        let root = json!({});
        let (v, _) = gen_with(&root, &json!({"type": ["string", "null"], "maxLength": 3}), SampleMode::Sample, false);
        assert!(v.unwrap().as_str().unwrap().len() <= 3);
        let (v, _) = gen_with(&root, &json!({"type": "null"}), SampleMode::Sample, false);
        assert_eq!(v.unwrap(), Value::Null);
    }
}
