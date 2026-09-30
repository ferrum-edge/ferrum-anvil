//! Schemas inferred from observed JSON, for suggested spec revisions.
//!
//! Only the shape is kept: types, properties, which properties were always
//! present, array items and a few string formats recognized in every
//! sample. Observed values are never copied into a schema (no examples,
//! enums or defaults), so a suggestion cannot leak a response's data. An
//! object whose keys look like data (an email, an id, more than 50 names)
//! is a map: it becomes `additionalProperties` with the merged value shape,
//! and its keys are not kept.

use anvil_import::Dialect;
use serde_json::{Map, Value, json};
use std::collections::BTreeSet;

/// Nesting followed when inferring.
const MAX_DEPTH: usize = 16;
/// Properties kept per object.
const MAX_PROPERTIES: usize = 200;
/// Array items sampled per array.
const MAX_ITEMS: usize = 50;
/// Distinct names past which an object is taken to be a map.
const MAX_NAMED_PROPERTIES: usize = 50;

/// A member or parameter name from traffic that may appear in a message or a
/// suggested description: ASCII letters, digits and `_ - . $ [ ]`, not
/// starting with a digit, at most 64 characters and fewer than four digits.
/// Anything else (an email, a token, an id) is data, not a name.
pub fn safe_name(n: &str) -> bool {
    let b = n.as_bytes();
    !b.is_empty()
        && b.len() <= 64
        && !b[0].is_ascii_digit()
        && b.iter().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.' | b'$' | b'[' | b']'))
        && b.iter().filter(|c| c.is_ascii_digit()).count() < 4
}

/// An accumulating shape: merge samples in, then render for a dialect.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Shape {
    samples: usize,
    nulls: usize,
    booleans: usize,
    integers: usize,
    numbers: usize,
    strings: usize,
    formats: Option<BTreeSet<&'static str>>,
    arrays: usize,
    items: Option<Box<Shape>>,
    objects: usize,
    /// Property name → (times present, shape).
    properties: Vec<(String, usize, Shape)>,
    /// Some key looked like data: the object is a map.
    map_like: bool,
    truncated: bool,
}

impl Shape {
    pub fn of(v: &Value) -> Shape {
        let mut s = Shape::default();
        s.add(v);
        s
    }

    pub fn add(&mut self, v: &Value) {
        self.add_at(v, 0);
    }

    fn add_at(&mut self, v: &Value, depth: usize) {
        self.samples += 1;
        if depth > MAX_DEPTH {
            self.truncated = true;
            return;
        }
        match v {
            Value::Null => self.nulls += 1,
            Value::Bool(_) => self.booleans += 1,
            Value::Number(n) if n.is_i64() || n.is_u64() => self.integers += 1,
            Value::Number(_) => self.numbers += 1,
            Value::String(s) => {
                self.strings += 1;
                let found = string_formats(s);
                self.formats = Some(match self.formats.take() {
                    None => found,
                    Some(prev) => prev.intersection(&found).copied().collect(),
                });
            }
            Value::Array(a) => {
                self.arrays += 1;
                let items = self.items.get_or_insert_with(Box::default);
                for x in a.iter().take(MAX_ITEMS) {
                    items.add_at(x, depth + 1);
                }
            }
            Value::Object(o) => {
                self.objects += 1;
                if o.keys().any(|k| !safe_name(k)) || o.len() > MAX_NAMED_PROPERTIES {
                    self.map_like = true;
                }
                for (k, x) in o {
                    match self.properties.iter().position(|(n, _, _)| n == k) {
                        Some(i) => {
                            let (_, seen, shape) = &mut self.properties[i];
                            *seen += 1;
                            shape.add_at(x, depth + 1);
                        }
                        None if self.properties.len() < MAX_PROPERTIES => {
                            let mut shape = Shape::default();
                            shape.add_at(x, depth + 1);
                            self.properties.push((k.clone(), 1, shape));
                        }
                        None => self.truncated = true,
                    }
                }
            }
        }
    }

    /// Fold `other` into this shape (samples of the same place).
    fn merge(&mut self, other: &Shape) {
        self.samples += other.samples;
        self.nulls += other.nulls;
        self.booleans += other.booleans;
        self.integers += other.integers;
        self.numbers += other.numbers;
        self.strings += other.strings;
        self.formats = match (self.formats.take(), &other.formats) {
            (None, f) => f.clone(),
            (f, None) => f,
            (Some(a), Some(b)) => Some(a.intersection(b).copied().collect()),
        };
        self.arrays += other.arrays;
        if let Some(oi) = &other.items {
            self.items.get_or_insert_with(Box::default).merge(oi);
        }
        self.objects += other.objects;
        self.map_like |= other.map_like;
        self.truncated |= other.truncated;
        for (k, seen, shape) in &other.properties {
            match self.properties.iter().position(|(n, _, _)| n == k) {
                Some(i) => {
                    self.properties[i].1 += seen;
                    self.properties[i].2.merge(shape);
                }
                None if self.properties.len() < MAX_PROPERTIES => self.properties.push((k.clone(), *seen, shape.clone())),
                None => self.truncated = true,
            }
        }
    }

    /// Render as a Schema Object of `dialect`.
    pub fn schema(&self, dialect: Dialect) -> Value {
        let mut types: Vec<&str> = vec![];
        if self.objects > 0 {
            types.push("object");
        }
        if self.arrays > 0 {
            types.push("array");
        }
        if self.strings > 0 {
            types.push("string");
        }
        if self.numbers > 0 {
            types.push("number");
        } else if self.integers > 0 {
            types.push("integer");
        }
        if self.booleans > 0 {
            types.push("boolean");
        }
        let nullable = self.nulls > 0;
        let mut out = Map::new();
        match (types.as_slice(), dialect) {
            ([], _) if nullable => return null_schema(dialect),
            ([], _) => return json!({}),
            ([one], _) => {
                out.insert("type".into(), json!(one));
            }
            (many, Dialect::OpenApi31 | Dialect::OpenApi32) => {
                out.insert("type".into(), json!(many));
            }
            (_, Dialect::Swagger20) => {
                // 2.0 has neither type lists nor `oneOf`: any type.
                return if nullable { json!({"x-nullable": true}) } else { json!({}) };
            }
            (many, _) => {
                // 3.0 has no type lists.
                let branches: Vec<Value> = many.iter().map(|t| self.only(t).schema(dialect)).collect();
                let mut s = json!({ "oneOf": branches });
                if nullable {
                    mark_nullable(&mut s, dialect);
                }
                return s;
            }
        }
        if types.contains(&"string")
            && let Some(f) = self.formats.as_ref().and_then(|f| f.iter().next())
        {
            out.insert("format".into(), json!(f));
        }
        if self.objects > 0 && (self.map_like || self.properties.len() > MAX_NAMED_PROPERTIES) {
            // A map: one shape for every value, no names.
            let mut values = Shape::default();
            for (_, _, shape) in &self.properties {
                values.merge(shape);
            }
            out.insert("additionalProperties".into(), if shape_is_empty(&values) { json!({}) } else { values.schema(dialect) });
        } else if self.objects > 0 {
            let mut props = Map::new();
            let mut required = vec![];
            for (name, seen, shape) in &self.properties {
                props.insert(name.clone(), shape.schema(dialect));
                if *seen == self.objects {
                    required.push(json!(name));
                }
            }
            out.insert("properties".into(), Value::Object(props));
            if !required.is_empty() {
                out.insert("required".into(), Value::Array(required));
            }
        }
        if self.arrays > 0 {
            let items = self.items.as_ref().map(|i| i.schema(dialect)).unwrap_or_else(|| json!({}));
            out.insert("items".into(), items);
        }
        let mut s = Value::Object(out);
        if nullable {
            mark_nullable(&mut s, dialect);
        }
        s
    }

    /// The part of this shape of one JSON type.
    fn only(&self, t: &str) -> Shape {
        let mut s = self.clone();
        s.nulls = 0;
        if t != "object" {
            s.objects = 0;
            s.properties.clear();
        }
        if t != "array" {
            s.arrays = 0;
            s.items = None;
        }
        if t != "string" {
            s.strings = 0;
        }
        if t != "number" && t != "integer" {
            s.numbers = 0;
            s.integers = 0;
        }
        if t != "boolean" {
            s.booleans = 0;
        }
        s
    }
}

fn shape_is_empty(s: &Shape) -> bool {
    s.samples == 0
}

/// The JSON Schema type name of a value.
pub fn json_type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(n) if n.is_i64() || n.is_u64() => "integer",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// Allow `null` on a rendered schema, in the dialect's own way. An `enum`
/// gets `null` among its values (every dialect requires it there), and a
/// 3.1/3.2 `const` becomes `anyOf` the constant or `null`.
pub fn mark_nullable(s: &mut Value, dialect: Dialect) {
    let Some(o) = s.as_object_mut() else { return };
    if let Some(Value::Array(e)) = o.get_mut("enum")
        && !e.contains(&Value::Null)
    {
        e.push(Value::Null);
    }
    if matches!(dialect, Dialect::OpenApi31 | Dialect::OpenApi32) && o.contains_key("const") {
        let inner = Value::Object(std::mem::take(o));
        o.insert("anyOf".into(), json!([inner, { "type": "null" }]));
        return;
    }
    match dialect {
        Dialect::OpenApi31 | Dialect::OpenApi32 => match o.get("type").cloned() {
            Some(Value::String(t)) => {
                o.insert("type".into(), json!([t, "null"]));
            }
            Some(Value::Array(mut a)) => {
                if !a.contains(&json!("null")) {
                    a.push(json!("null"));
                }
                o.insert("type".into(), Value::Array(a));
            }
            _ => {
                let inner = Value::Object(std::mem::take(o));
                o.insert("anyOf".into(), json!([inner, { "type": "null" }]));
            }
        },
        Dialect::Swagger20 => {
            o.insert("x-nullable".into(), json!(true));
        }
        _ => {
            o.insert("nullable".into(), json!(true));
        }
    }
}

fn null_schema(dialect: Dialect) -> Value {
    match dialect {
        Dialect::OpenApi31 | Dialect::OpenApi32 => json!({ "type": "null" }),
        Dialect::Swagger20 => json!({ "x-nullable": true }),
        _ => json!({ "nullable": true }),
    }
}

/// Formats a string is valid for (only the unambiguous ones).
fn string_formats(s: &str) -> BTreeSet<&'static str> {
    let mut out = BTreeSet::new();
    let b = s.as_bytes();
    let digits = |r: std::ops::Range<usize>| b.get(r).is_some_and(|x| x.iter().all(u8::is_ascii_digit));
    let is_date = b.len() >= 10 && digits(0..4) && b[4] == b'-' && digits(5..7) && b[7] == b'-' && digits(8..10);
    if is_date && b.len() == 10 {
        out.insert("date");
    }
    if is_date
        && b.len() > 19
        && (b[10] == b'T' || b[10] == b't')
        && digits(11..13)
        && b[13] == b':'
        && digits(14..16)
        && b[16] == b':'
        && digits(17..19)
    {
        let tz = &s[19..];
        let tz = tz.strip_prefix('.').map(|r| r.trim_start_matches(|c: char| c.is_ascii_digit())).unwrap_or(tz);
        if tz == "Z" || tz == "z" || (tz.len() == 6 && (tz.starts_with('+') || tz.starts_with('-')) && tz.as_bytes()[3] == b':') {
            out.insert("date-time");
        }
    }
    if b.len() == 36 && s.char_indices().all(|(i, c)| if matches!(i, 8 | 13 | 18 | 23) { c == '-' } else { c.is_ascii_hexdigit() }) {
        out.insert("uuid");
    }
    if let Some((local, domain)) = s.split_once('@')
        && !local.is_empty()
        && domain.contains('.')
        && !s.contains(char::is_whitespace)
        && !domain.contains('@')
    {
        out.insert("email");
    }
    if (s.starts_with("https://") || s.starts_with("http://")) && !s.contains(char::is_whitespace) && s.len() > 8 {
        out.insert("uri");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn infer(samples: &[Value], d: Dialect) -> Value {
        let mut s = Shape::default();
        for v in samples {
            s.add(v);
        }
        s.schema(d)
    }

    #[test]
    fn objects_merge_and_required_means_always_present() {
        let s = infer(
            &[
                json!({"id": 1, "name": "a", "tags": ["x"], "at": "2026-09-30T10:00:00Z"}),
                json!({"id": 2, "tags": [], "at": "2026-09-30T10:00:00.123+02:00", "owner": {"email": "a@b.example"}}),
            ],
            Dialect::OpenApi31,
        );
        assert_eq!(s["type"], "object");
        assert_eq!(s["required"], json!(["id", "tags", "at"]));
        assert_eq!(s["properties"]["id"], json!({"type": "integer"}));
        assert_eq!(s["properties"]["tags"], json!({"type": "array", "items": {"type": "string"}}));
        assert_eq!(s["properties"]["at"]["format"], "date-time");
        assert_eq!(s["properties"]["owner"]["properties"]["email"]["format"], "email");
        // No observed value is copied into the schema.
        assert!(!s.to_string().contains("a@b.example"));
        assert!(!s.to_string().contains("2026"));
    }

    #[test]
    fn numbers_widen_and_nulls_follow_the_dialect() {
        let samples = [json!(1), json!(2.5), json!(null)];
        assert_eq!(infer(&samples, Dialect::OpenApi31), json!({"type": ["number", "null"]}));
        assert_eq!(infer(&samples, Dialect::OpenApi30), json!({"type": "number", "nullable": true}));
        assert_eq!(infer(&samples, Dialect::Swagger20), json!({"type": "number", "x-nullable": true}));
        assert_eq!(infer(&[json!(null)], Dialect::OpenApi32), json!({"type": "null"}));
    }

    #[test]
    fn mixed_types_use_one_of_where_type_lists_do_not_exist() {
        let samples = [json!("a"), json!(3)];
        assert_eq!(infer(&samples, Dialect::OpenApi31), json!({"type": ["string", "integer"]}));
        assert_eq!(infer(&samples, Dialect::OpenApi30), json!({"oneOf": [{"type": "string"}, {"type": "integer"}]}));
        assert_eq!(infer(&samples, Dialect::Swagger20), json!({}), "2.0 has no oneOf");
        assert_eq!(infer(&[json!("a"), json!(3), json!(null)], Dialect::Swagger20), json!({"x-nullable": true}));
    }

    #[test]
    fn map_shaped_objects_keep_no_keys() {
        let s = infer(&[json!({"alice@x.example": {"n": 1}, "bob@y.example": {"n": 2}})], Dialect::OpenApi31);
        assert_eq!(
            s,
            json!({"type": "object", "additionalProperties": {"type": "object", "properties": {"n": {"type": "integer"}}, "required": ["n"]}})
        );
        assert!(!s.to_string().contains("alice"));
        let wide: Map<String, Value> = (0..60).map(|i| (format!("k{i}"), json!(true))).collect();
        assert_eq!(
            infer(&[Value::Object(wide)], Dialect::OpenApi30),
            json!({"type": "object", "additionalProperties": {"type": "boolean"}})
        );
        assert!(safe_name("createdAt") && safe_name("items[]") && !safe_name("user_12345") && !safe_name("a@b") && !safe_name("9lives"));
    }

    #[test]
    fn nullable_enums_and_consts_accept_null() {
        let mut e = json!({"type": "string", "enum": ["a"]});
        mark_nullable(&mut e, Dialect::OpenApi31);
        assert_eq!(e, json!({"type": ["string", "null"], "enum": ["a", null]}));
        let mut c = json!({"const": "a"});
        mark_nullable(&mut c, Dialect::OpenApi32);
        assert_eq!(c, json!({"anyOf": [{"const": "a"}, {"type": "null"}]}));
        let mut e30 = json!({"type": "string", "enum": ["a"]});
        mark_nullable(&mut e30, Dialect::OpenApi30);
        assert_eq!(e30, json!({"type": "string", "enum": ["a", null], "nullable": true}));
    }

    #[test]
    fn formats_need_every_sample() {
        let uuid = "3f2504e0-4f89-11d3-9a0c-0305e82c3301";
        assert_eq!(infer(&[json!(uuid)], Dialect::OpenApi31)["format"], "uuid");
        assert!(infer(&[json!(uuid), json!("x")], Dialect::OpenApi31).get("format").is_none());
        assert_eq!(infer(&[json!("2026-09-30")], Dialect::OpenApi31)["format"], "date");
    }

    #[test]
    fn depth_and_width_are_bounded() {
        let mut v = json!(1);
        for _ in 0..40 {
            v = json!({ "a": v });
        }
        let _ = infer(&[v], Dialect::OpenApi31);
        let wide: Map<String, Value> = (0..500).map(|i| (format!("k{i}"), json!(i))).collect();
        let s = infer(&[Value::Object(wide)], Dialect::OpenApi31);
        assert!(s.get("properties").is_none(), "500 names is a map");
        assert_eq!(s["additionalProperties"], json!({"type": "integer"}));
    }
}
