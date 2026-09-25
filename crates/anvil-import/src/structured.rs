//! Bounded JSON/YAML parsing into `serde_json::Value`.
//!
//! Both parsers feed a custom visitor that charges every node (scalars, map
//! keys, sequence items) against a budget and aborts as soon as it is spent.
//! That bound applies *during* deserialization, so YAML alias expansion
//! ("billion laughs") cannot materialize an oversized tree first. Nesting
//! depth is bounded as well (serde_json and serde_norway also enforce their
//! own recursion limits).

use crate::ImportError;
use crate::detect::Syntax;
use serde::de::{self, DeserializeSeed, Deserializer, EnumAccess, MapAccess, SeqAccess, VariantAccess, Visitor};
use serde_json::{Map, Number, Value};
use std::cell::Cell;
use std::fmt;

pub const MAX_DEPTH: usize = 200;
const BUDGET_MSG: &str = "anvil-import: node budget exhausted";
const DEPTH_MSG: &str = "anvil-import: nesting depth exceeded";

struct Budget {
    remaining: Cell<usize>,
    exhausted: Cell<bool>,
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
            Err(_) => Value::String(v.to_string()),
        })
    }
    fn visit_u128<E: de::Error>(self, v: u128) -> Result<Value, E> {
        self.budget.charge()?;
        Ok(match u64::try_from(v) {
            Ok(i) => Value::Number(i.into()),
            Err(_) => Value::String(v.to_string()),
        })
    }
    fn visit_f64<E: de::Error>(self, v: f64) -> Result<Value, E> {
        self.budget.charge()?;
        // YAML allows .inf/.nan, which JSON cannot represent: keep the text.
        Ok(Number::from_f64(v).map(Value::Number).unwrap_or_else(|| Value::String(v.to_string())))
    }
    fn visit_str<E: de::Error>(self, v: &str) -> Result<Value, E> {
        self.budget.charge()?;
        Ok(Value::String(v.to_string()))
    }
    fn visit_string<E: de::Error>(self, v: String) -> Result<Value, E> {
        self.budget.charge()?;
        Ok(Value::String(v))
    }
    fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Value, E> {
        self.budget.charge()?;
        Ok(Value::String(String::from_utf8_lossy(v).into_owned()))
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
        self.0.charge()?;
        Ok(v.to_string())
    }
    fn visit_string<E: de::Error>(self, v: String) -> Result<String, E> {
        self.0.charge()?;
        Ok(v)
    }
    fn visit_bool<E: de::Error>(self, v: bool) -> Result<String, E> {
        self.0.charge()?;
        Ok(v.to_string())
    }
    fn visit_i64<E: de::Error>(self, v: i64) -> Result<String, E> {
        self.0.charge()?;
        Ok(v.to_string())
    }
    fn visit_u64<E: de::Error>(self, v: u64) -> Result<String, E> {
        self.0.charge()?;
        Ok(v.to_string())
    }
    fn visit_f64<E: de::Error>(self, v: f64) -> Result<String, E> {
        self.0.charge()?;
        Ok(v.to_string())
    }
    fn visit_unit<E: de::Error>(self) -> Result<String, E> {
        self.0.charge()?;
        Ok("null".into())
    }
    fn visit_none<E: de::Error>(self) -> Result<String, E> {
        self.0.charge()?;
        Ok("null".into())
    }
}

fn limit_error(b: &Budget, max_nodes: usize) -> Option<ImportError> {
    if b.exhausted.get() {
        Some(ImportError::LimitExceeded { what: "document nodes".into(), limit: max_nodes })
    } else if b.too_deep.get() {
        Some(ImportError::LimitExceeded { what: "nesting depth".into(), limit: MAX_DEPTH })
    } else {
        None
    }
}

fn new_budget(max_nodes: usize) -> Budget {
    Budget { remaining: Cell::new(max_nodes), exhausted: Cell::new(false), too_deep: Cell::new(false) }
}

pub fn parse_json(text: &str, max_nodes: usize) -> Result<Value, ImportError> {
    let budget = new_budget(max_nodes);
    let mut de = serde_json::Deserializer::from_str(text);
    let res = Bounded { budget: &budget, depth: 0 }.deserialize(&mut de).and_then(|v| de.end().map(|_| v));
    res.map_err(|e| {
        limit_error(&budget, max_nodes).unwrap_or_else(|| ImportError::Syntax {
            syntax: "JSON".into(),
            message: e.to_string(),
            line: Some(e.line()),
            column: Some(e.column()),
        })
    })
}

pub fn parse_yaml(text: &str, max_nodes: usize) -> Result<Value, ImportError> {
    let budget = new_budget(max_nodes);
    let de = serde_norway::Deserializer::from_str(text);
    let res = Bounded { budget: &budget, depth: 0 }.deserialize(de);
    res.map_err(|e| {
        limit_error(&budget, max_nodes).unwrap_or_else(|| {
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
pub fn parse(text: &str, max_nodes: usize) -> Result<(Value, Syntax), ImportError> {
    let t = text.trim_start();
    if t.starts_with('{') || t.starts_with('[') {
        match parse_json(text, max_nodes) {
            Ok(v) => Ok((v, Syntax::Json)),
            Err(e @ ImportError::LimitExceeded { .. }) => Err(e),
            Err(json_err) => match parse_yaml(text, max_nodes) {
                Ok(v) => Ok((v, Syntax::Yaml)),
                Err(e @ ImportError::LimitExceeded { .. }) => Err(e),
                Err(_) => Err(json_err),
            },
        }
    } else {
        parse_yaml(text, max_nodes).map(|v| (v, Syntax::Yaml))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn yaml_non_string_keys() {
        let v = parse_yaml("responses:\n  200:\n    description: ok\n  true: x\n", 1000).unwrap();
        assert_eq!(v["responses"]["200"]["description"], "ok");
        assert_eq!(v["responses"]["true"], "x");
    }

    #[test]
    fn json_budget() {
        let big = format!("[{}]", vec!["1"; 5000].join(","));
        assert!(matches!(parse_json(&big, 100), Err(ImportError::LimitExceeded { .. })));
        assert!(parse_json(&big, 10_000).is_ok());
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
        let r = parse_yaml(&y, 100_000);
        assert!(r.is_err(), "expansion must be refused");
    }

    #[test]
    fn deep_nesting_is_an_error_not_a_crash() {
        let deep = format!("{}{}", "[".repeat(5000), "]".repeat(5000));
        assert!(parse_json(&deep, 1_000_000).is_err());
        let deep_yaml = format!("{}1{}", "[".repeat(5000), "]".repeat(5000));
        assert!(parse_yaml(&deep_yaml, 1_000_000).is_err());
    }
}
