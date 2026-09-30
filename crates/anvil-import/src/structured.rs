//! Bounded JSON/YAML parsing into `serde_json::Value`.
//!
//! Both parsers feed a custom visitor that charges every node (scalars, map
//! keys, sequence items) against a budget and aborts as soon as it is spent.
//! A second budget covers the bytes of every string kept in the tree (string
//! scalars and map keys): each one is charged before it is copied, so a long
//! scalar that many YAML aliases repeat cannot grow the tree far beyond the
//! input size either. Both bounds apply *during* deserialization, so YAML
//! alias expansion ("billion laughs") cannot materialize an oversized tree
//! first. Nesting depth is bounded as well (serde_json and serde_norway also
//! enforce their own recursion limits).

use crate::ImportError;
use crate::detect::Syntax;
use serde::de::{self, DeserializeSeed, Deserializer, EnumAccess, MapAccess, SeqAccess, VariantAccess, Visitor};
use serde_json::{Map, Number, Value};
use std::cell::Cell;
use std::fmt;

pub const MAX_DEPTH: usize = 200;
/// Materialized string bytes allowed per input byte limit. Without aliases a
/// document never keeps more string bytes than its own size; the headroom is
/// for ordinary YAML anchors and merge keys.
const BYTES_PER_INPUT_BYTE: usize = 2;
const BUDGET_MSG: &str = "anvil-import: node budget exhausted";
const BYTES_MSG: &str = "anvil-import: document byte budget exhausted";
const DEPTH_MSG: &str = "anvil-import: nesting depth exceeded";

/// Limits for one parse: parsed nodes and materialized string bytes.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub max_nodes: usize,
    pub max_bytes: usize,
}

impl Limits {
    /// The limits derived from the import options' node and input-size caps.
    pub fn for_input(max_nodes: usize, max_input_bytes: usize) -> Self {
        Limits { max_nodes, max_bytes: max_input_bytes.saturating_mul(BYTES_PER_INPUT_BYTE) }
    }
}

struct Budget {
    remaining: Cell<usize>,
    bytes_remaining: Cell<usize>,
    exhausted: Cell<bool>,
    bytes_exhausted: Cell<bool>,
    too_deep: Cell<bool>,
}

impl Budget {
    fn charge<E: de::Error>(&self) -> Result<(), E> {
        let r = self.remaining.get();
        if r == 0 {
            self.exhausted.set(true);
            return Err(E::custom(BUDGET_MSG));
        }
        self.remaining.set(r - 1);
        Ok(())
    }

    /// Charge `len` string bytes before they are copied into the tree.
    fn charge_bytes<E: de::Error>(&self, len: usize) -> Result<(), E> {
        let r = self.bytes_remaining.get();
        if len > r {
            self.bytes_exhausted.set(true);
            return Err(E::custom(BYTES_MSG));
        }
        self.bytes_remaining.set(r - len);
        Ok(())
    }

    /// One string node of `len` bytes.
    fn charge_str<E: de::Error>(&self, len: usize) -> Result<(), E> {
        self.charge()?;
        self.charge_bytes(len)
    }

    /// Charge an already formatted, short string (numbers kept as text).
    fn keep<E: de::Error>(&self, s: String) -> Result<String, E> {
        self.charge_bytes(s.len())?;
        Ok(s)
    }
}

#[derive(Clone, Copy)]
struct Bounded<'b> {
    budget: &'b Budget,
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for Bounded<'_> {
    type Value = Value;
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Value, D::Error> {
        d.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Bounded<'_> {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("any JSON/YAML value")
    }

    fn visit_bool<E: de::Error>(self, v: bool) -> Result<Value, E> {
        self.budget.charge()?;
        Ok(Value::Bool(v))
    }
    fn visit_i64<E: de::Error>(self, v: i64) -> Result<Value, E> {
        self.budget.charge()?;
        Ok(Value::Number(v.into()))
    }
    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Value, E> {
        self.budget.charge()?;
        Ok(Value::Number(v.into()))
    }
    fn visit_i128<E: de::Error>(self, v: i128) -> Result<Value, E> {
        self.budget.charge()?;
        Ok(match i64::try_from(v) {
            Ok(i) => Value::Number(i.into()),
            Err(_) => Value::String(self.budget.keep(v.to_string())?),
        })
    }
    fn visit_u128<E: de::Error>(self, v: u128) -> Result<Value, E> {
        self.budget.charge()?;
        Ok(match u64::try_from(v) {
            Ok(i) => Value::Number(i.into()),
            Err(_) => Value::String(self.budget.keep(v.to_string())?),
        })
    }
    fn visit_f64<E: de::Error>(self, v: f64) -> Result<Value, E> {
        self.budget.charge()?;
        // YAML allows .inf/.nan, which JSON cannot represent: keep the text.
        match Number::from_f64(v) {
            Some(n) => Ok(Value::Number(n)),
            None => Ok(Value::String(self.budget.keep(v.to_string())?)),
        }
    }
    fn visit_str<E: de::Error>(self, v: &str) -> Result<Value, E> {
        self.budget.charge_str(v.len())?;
        Ok(Value::String(v.to_string()))
    }
    fn visit_string<E: de::Error>(self, v: String) -> Result<Value, E> {
        self.budget.charge_str(v.len())?;
        Ok(Value::String(v))
    }
    fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Value, E> {
        self.budget.charge_str(v.len())?;
        let s = String::from_utf8_lossy(v).into_owned();
        // Replacement characters can make the text longer than the bytes.
        self.budget.charge_bytes(s.len().saturating_sub(v.len()))?;
        Ok(Value::String(s))
    }
    fn visit_none<E: de::Error>(self) -> Result<Value, E> {
        self.budget.charge()?;
        Ok(Value::Null)
    }
    fn visit_unit<E: de::Error>(self) -> Result<Value, E> {
        self.budget.charge()?;
        Ok(Value::Null)
    }
    fn visit_some<D: Deserializer<'de>>(self, d: D) -> Result<Value, D::Error> {
        d.deserialize_any(self)
    }
    fn visit_newtype_struct<D: Deserializer<'de>>(self, d: D) -> Result<Value, D::Error> {
        d.deserialize_any(self)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        self.budget.charge()?;
        let child = self.child()?;
        let mut out = Vec::new();
        while let Some(v) = seq.next_element_seed(child)? {
            out.push(v);
        }
        Ok(Value::Array(out))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        self.budget.charge()?;
        let child = self.child()?;
        let mut out = Map::new();
        while let Some(k) = map.next_key_seed(KeySeed(self.budget))? {
            let v = map.next_value_seed(child)?;
            out.insert(k, v);
        }
        Ok(Value::Object(out))
    }

    /// YAML tagged values (`!Tag value`) arrive as enums; the tag is dropped.
    fn visit_enum<A: EnumAccess<'de>>(self, data: A) -> Result<Value, A::Error> {
        let (_tag, variant): (String, _) = data.variant_seed(KeySeed(self.budget))?;
        variant.newtype_variant_seed(self)
    }
}

impl Bounded<'_> {
    fn child<E: de::Error>(&self) -> Result<Self, E> {
        if self.depth + 1 > MAX_DEPTH {
            self.budget.too_deep.set(true);
            return Err(E::custom(DEPTH_MSG));
        }
        Ok(Bounded { budget: self.budget, depth: self.depth + 1 })
    }
}

/// Map keys: YAML allows non-string scalars (`200:` response codes, `true:`),
/// which are converted to their text.
#[derive(Clone, Copy)]
struct KeySeed<'b>(&'b Budget);

impl<'de> DeserializeSeed<'de> for KeySeed<'_> {
    type Value = String;
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<String, D::Error> {
        d.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for KeySeed<'_> {
    type Value = String;
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a scalar map key")
    }
    fn visit_str<E: de::Error>(self, v: &str) -> Result<String, E> {
        self.0.charge_str(v.len())?;
        Ok(v.to_string())
    }
    fn visit_string<E: de::Error>(self, v: String) -> Result<String, E> {
        self.0.charge_str(v.len())?;
        Ok(v)
    }
    fn visit_bool<E: de::Error>(self, v: bool) -> Result<String, E> {
        self.0.charge()?;
        self.0.keep(v.to_string())
    }
    fn visit_i64<E: de::Error>(self, v: i64) -> Result<String, E> {
        self.0.charge()?;
        self.0.keep(v.to_string())
    }
    fn visit_u64<E: de::Error>(self, v: u64) -> Result<String, E> {
        self.0.charge()?;
        self.0.keep(v.to_string())
    }
    fn visit_f64<E: de::Error>(self, v: f64) -> Result<String, E> {
        self.0.charge()?;
        self.0.keep(v.to_string())
    }
    fn visit_unit<E: de::Error>(self) -> Result<String, E> {
        self.0.charge_str(4)?;
        Ok("null".into())
    }
    fn visit_none<E: de::Error>(self) -> Result<String, E> {
        self.0.charge_str(4)?;
        Ok("null".into())
    }
}

fn limit_error(b: &Budget, limits: Limits) -> Option<ImportError> {
    if b.exhausted.get() {
        Some(ImportError::LimitExceeded { what: "document nodes".into(), limit: limits.max_nodes })
    } else if b.bytes_exhausted.get() {
        Some(ImportError::LimitExceeded { what: "document string bytes".into(), limit: limits.max_bytes })
    } else if b.too_deep.get() {
        Some(ImportError::LimitExceeded { what: "nesting depth".into(), limit: MAX_DEPTH })
    } else {
        None
    }
}

fn new_budget(limits: Limits) -> Budget {
    Budget {
        remaining: Cell::new(limits.max_nodes),
        bytes_remaining: Cell::new(limits.max_bytes),
        exhausted: Cell::new(false),
        bytes_exhausted: Cell::new(false),
        too_deep: Cell::new(false),
    }
}

pub fn parse_json(text: &str, limits: Limits) -> Result<Value, ImportError> {
    let budget = new_budget(limits);
    let mut de = serde_json::Deserializer::from_str(text);
    let res = Bounded { budget: &budget, depth: 0 }.deserialize(&mut de).and_then(|v| de.end().map(|_| v));
    res.map_err(|e| {
        limit_error(&budget, limits).unwrap_or_else(|| ImportError::Syntax {
            syntax: "JSON".into(),
            message: e.to_string(),
            line: Some(e.line()),
            column: Some(e.column()),
        })
    })
}

pub fn parse_yaml(text: &str, limits: Limits) -> Result<Value, ImportError> {
    let budget = new_budget(limits);
    let de = serde_norway::Deserializer::from_str(text);
    let res = Bounded { budget: &budget, depth: 0 }.deserialize(de);
    res.map_err(|e| {
        limit_error(&budget, limits).unwrap_or_else(|| {
            let loc = e.location();
            ImportError::Syntax {
                syntax: "YAML".into(),
                message: e.to_string(),
                line: loc.as_ref().map(|l| l.line()),
                column: loc.as_ref().map(|l| l.column()),
            }
        })
    })
}

/// Parse JSON (when the text looks like JSON) or YAML. JSON-looking text that
/// fails as JSON is retried as YAML (a superset); the JSON error is reported
/// if both fail.
pub fn parse(text: &str, limits: Limits) -> Result<(Value, Syntax), ImportError> {
    let t = text.trim_start();
    if t.starts_with('{') || t.starts_with('[') {
        match parse_json(text, limits) {
            Ok(v) => Ok((v, Syntax::Json)),
            Err(e @ ImportError::LimitExceeded { .. }) => Err(e),
            Err(json_err) => match parse_yaml(text, limits) {
                Ok(v) => Ok((v, Syntax::Yaml)),
                Err(e @ ImportError::LimitExceeded { .. }) => Err(e),
                Err(_) => Err(json_err),
            },
        }
    } else {
        parse_yaml(text, limits).map(|v| (v, Syntax::Yaml))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nodes(max_nodes: usize) -> Limits {
        Limits { max_nodes, max_bytes: 1 << 20 }
    }

    #[test]
    fn yaml_non_string_keys() {
        let v = parse_yaml("responses:\n  200:\n    description: ok\n  true: x\n", nodes(1000)).unwrap();
        assert_eq!(v["responses"]["200"]["description"], "ok");
        assert_eq!(v["responses"]["true"], "x");
    }

    #[test]
    fn json_budget() {
        let big = format!("[{}]", vec!["1"; 5000].join(","));
        assert!(matches!(parse_json(&big, nodes(100)), Err(ImportError::LimitExceeded { .. })));
        assert!(parse_json(&big, nodes(10_000)).is_ok());
    }

    #[test]
    fn yaml_billion_laughs_is_bounded() {
        let mut y = String::from("a: &a [\"lol\",\"lol\",\"lol\",\"lol\",\"lol\",\"lol\",\"lol\",\"lol\",\"lol\"]\n");
        let names = ["b", "c", "d", "e", "f", "g", "h", "i"];
        let mut prev = "a";
        for n in names {
            y.push_str(&format!("{n}: &{n} [*{prev},*{prev},*{prev},*{prev},*{prev},*{prev},*{prev},*{prev},*{prev}]\n"));
            prev = n;
        }
        let r = parse_yaml(&y, nodes(100_000));
        assert!(r.is_err(), "expansion must be refused");
    }

    #[test]
    fn deep_nesting_is_an_error_not_a_crash() {
        let deep = format!("{}{}", "[".repeat(5000), "]".repeat(5000));
        assert!(parse_json(&deep, nodes(1_000_000)).is_err());
        let deep_yaml = format!("{}1{}", "[".repeat(5000), "]".repeat(5000));
        assert!(parse_yaml(&deep_yaml, nodes(1_000_000)).is_err());
    }

    /// A long anchored scalar repeated by many flat aliases stays shallow and
    /// uses few nodes; the string-byte budget refuses it.
    fn flat_aliases(scalar_len: usize, aliases: usize) -> String {
        let mut y = format!("a: &a {}\nb:\n", "x".repeat(scalar_len));
        for _ in 0..aliases {
            y.push_str("  - *a\n");
        }
        y
    }

    #[test]
    fn yaml_flat_aliases_to_a_long_scalar_are_bounded() {
        let y = flat_aliases(64 * 1024, 1_000);
        let limits = Limits::for_input(2_000_000, y.len());
        match parse_yaml(&y, limits) {
            Err(ImportError::LimitExceeded { what, limit }) => {
                assert_eq!(what, "document string bytes");
                assert_eq!(limit, limits.max_bytes);
            }
            other => panic!("expected the string-byte limit, got {:?}", other.map(|_| ())),
        }
        // Through `parse` as well (YAML is not retried as anything else).
        assert!(matches!(parse(&y, limits), Err(ImportError::LimitExceeded { .. })));
    }

    #[test]
    fn map_keys_share_the_byte_budget() {
        // YAML implicit keys are at most 1024 characters long.
        let long = "k".repeat(1000);
        let y = format!("a: &a {{{long}: 1}}\nb: [*a, *a, *a, *a, *a, *a, *a, *a]\n");
        let r = parse_yaml(&y, Limits { max_nodes: 1_000, max_bytes: 4 * 1000 });
        assert!(matches!(r, Err(ImportError::LimitExceeded { .. })));
    }

    #[test]
    fn ordinary_aliases_and_long_scalars_still_parse() {
        // A few aliases to a long scalar fit the default headroom.
        let y = flat_aliases(64 * 1024, 1);
        let v = parse_yaml(&y, Limits::for_input(2_000_000, y.len())).unwrap();
        assert_eq!(v["b"][0].as_str().map(str::len), Some(64 * 1024));
        // Without aliases every string fits: the tree never holds more string
        // bytes than the input.
        let j = format!("{{\"k{}\": \"{}\"}}", "k".repeat(1000), "v".repeat(100_000));
        assert!(parse_json(&j, Limits::for_input(1_000, j.len())).is_ok());
        let y = format!("k{}: {}\n", "k".repeat(1000), "v".repeat(100_000));
        assert!(parse_yaml(&y, Limits::for_input(1_000, y.len())).is_ok());
    }
}
