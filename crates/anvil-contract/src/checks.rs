//! The functions a rule applies to a field: `defined`, `pattern`,
//! `casing`, `schema`, … Options are checked when the ruleset is loaded, so
//! a typo in a company ruleset fails loudly instead of passing silently.

use regex::Regex;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Map, Value};

/// Function names, for listings and error messages.
pub const FUNCTIONS: &[&str] = &[
    "defined",
    "undefined",
    "truthy",
    "falsy",
    "pattern",
    "casing",
    "enumeration",
    "length",
    "alphabetical",
    "includes",
    "unique",
    "xor",
    "schema",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Casing {
    Camel,
    Pascal,
    Kebab,
    Snake,
    Cobol,
    Macro,
    Flat,
}

impl Casing {
    fn label(self) -> &'static str {
        match self {
            Casing::Camel => "camelCase",
            Casing::Pascal => "PascalCase",
            Casing::Kebab => "kebab-case",
            Casing::Snake => "snake_case",
            Casing::Cobol => "COBOL-CASE",
            Casing::Macro => "MACRO_CASE",
            Casing::Flat => "flatcase",
        }
    }

    fn regex(self, digits: bool) -> String {
        let (lower, upper, any) = if digits { ("[a-z0-9]", "[A-Z0-9]", "[a-zA-Z0-9]") } else { ("[a-z]", "[A-Z]", "[a-zA-Z]") };
        match self {
            Casing::Camel => format!("^[a-z]{any}*$"),
            Casing::Pascal => format!("^[A-Z]{any}*$"),
            Casing::Kebab => format!("^[a-z]{lower}*(-{lower}+)*$"),
            Casing::Snake => format!("^[a-z]{lower}*(_{lower}+)*$"),
            Casing::Cobol => format!("^[A-Z]{upper}*(-{upper}+)*$"),
            Casing::Macro => format!("^[A-Z]{upper}*(_{upper}+)*$"),
            Casing::Flat => format!("^[a-z]{lower}*$"),
        }
    }
}

#[derive(Debug)]
pub enum Function {
    Defined,
    Undefined,
    Truthy,
    Falsy,
    Pattern { matches: Option<Regex>, not_match: Option<Regex> },
    Casing { casing: Casing, regex: Regex },
    Enumeration { values: Vec<Value> },
    Length { min: Option<f64>, max: Option<f64> },
    Alphabetical { key: Option<String> },
    Includes { values: Vec<Value>, pattern: Option<Regex> },
    Unique,
    Xor { fields: Vec<String> },
    Schema { validator: Box<jsonschema::Validator> },
}

fn options<T: DeserializeOwned>(name: &str, v: &Value) -> Result<T, String> {
    let v = if v.is_null() { Value::Object(Map::new()) } else { v.clone() };
    serde_json::from_value(v).map_err(|e| format!("invalid options for `{name}`: {e}"))
}

fn regex(name: &str, pattern: &str) -> Result<Regex, String> {
    regex::RegexBuilder::new(pattern).size_limit(1 << 20).build().map_err(|e| format!("invalid regular expression for `{name}`: {e}"))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NoOptions {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PatternOpts {
    #[serde(rename = "match")]
    matches: Option<String>,
    #[serde(alias = "notMatch")]
    not_match: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CasingOpts {
    #[serde(rename = "type")]
    casing: Casing,
    #[serde(default, alias = "disallowDigits")]
    disallow_digits: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ValuesOpts {
    values: Vec<Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LengthOpts {
    min: Option<f64>,
    max: Option<f64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AlphaOpts {
    #[serde(alias = "keyedBy")]
    key: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IncludesOpts {
    #[serde(default)]
    values: Vec<Value>,
    pattern: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct XorOpts {
    fields: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SchemaOpts {
    schema: Value,
}

impl Function {
    pub fn compile(name: &str, opts: &Value) -> Result<Function, String> {
        Ok(match name {
            "defined" | "undefined" | "truthy" | "falsy" | "unique" => {
                options::<NoOptions>(name, opts)?;
                match name {
                    "defined" => Function::Defined,
                    "undefined" => Function::Undefined,
                    "truthy" => Function::Truthy,
                    "falsy" => Function::Falsy,
                    _ => Function::Unique,
                }
            }
            "pattern" => {
                let o: PatternOpts = options(name, opts)?;
                if o.matches.is_none() && o.not_match.is_none() {
                    return Err("`pattern` needs `match` or `not_match`".into());
                }
                Function::Pattern {
                    matches: o.matches.as_deref().map(|p| regex(name, p)).transpose()?,
                    not_match: o.not_match.as_deref().map(|p| regex(name, p)).transpose()?,
                }
            }
            "casing" => {
                let o: CasingOpts = options(name, opts)?;
                Function::Casing { casing: o.casing, regex: regex(name, &o.casing.regex(!o.disallow_digits))? }
            }
            "enumeration" => Function::Enumeration { values: options::<ValuesOpts>(name, opts)?.values },
            "length" => {
                let o: LengthOpts = options(name, opts)?;
                if o.min.is_none() && o.max.is_none() {
                    return Err("`length` needs `min` or `max`".into());
                }
                Function::Length { min: o.min, max: o.max }
            }
            "alphabetical" => Function::Alphabetical { key: options::<AlphaOpts>(name, opts)?.key },
            "includes" => {
                let o: IncludesOpts = options(name, opts)?;
                if o.values.is_empty() && o.pattern.is_none() {
                    return Err("`includes` needs `values` or `pattern`".into());
                }
                Function::Includes { values: o.values, pattern: o.pattern.as_deref().map(|p| regex(name, p)).transpose()? }
            }
            "xor" => {
                let o: XorOpts = options(name, opts)?;
                if o.fields.len() < 2 {
                    return Err("`xor` needs at least two `fields`".into());
                }
                Function::Xor { fields: o.fields }
            }
            "schema" => {
                let o: SchemaOpts = options(name, opts)?;
                let validator = jsonschema::options()
                    .with_draft(jsonschema::Draft::Draft202012)
                    .with_pattern_options(crate::schema::linear_patterns())
                    .build(&o.schema)
                    .map_err(|e| format!("invalid JSON Schema for `schema`: {e}"))?;
                Function::Schema { validator: Box::new(validator) }
            }
            other => return Err(format!("unknown function `{other}` (known: {})", FUNCTIONS.join(", "))),
        })
    }

    /// Whether the function reads a field (every function except `xor`).
    pub fn uses_field(&self) -> bool {
        !matches!(self, Function::Xor { .. })
    }

    /// `None` when `value` passes; otherwise why it fails. `sibling` reads
    /// another field of the same target (for `xor`).
    pub fn evaluate(&self, value: Option<&Value>, sibling: &dyn Fn(&str) -> Option<Value>) -> Option<String> {
        let value = value.filter(|v| !v.is_null());
        match self {
            Function::Defined => value.is_none().then(|| "is missing".into()),
            Function::Undefined => value.map(|v| format!("must not be set (is {})", show(v))),
            Function::Truthy => (!truthy(value)).then(|| "is missing or empty".into()),
            Function::Falsy => value.filter(|v| truthy(Some(v))).map(|v| format!("must be empty (is {})", show(v))),
            Function::Pattern { matches, not_match } => {
                let v = value?;
                let Some(text) = scalar(v) else { return Some(format!("is not a text value ({})", show(v))) };
                if let Some(re) = matches
                    && !re.is_match(&text)
                {
                    return Some(format!("{} does not match /{}/", show(v), re.as_str()));
                }
                if let Some(re) = not_match
                    && re.is_match(&text)
                {
                    return Some(format!("{} must not match /{}/", show(v), re.as_str()));
                }
                None
            }
            Function::Casing { casing, regex } => {
                let v = value?;
                let Some(text) = scalar(v) else { return Some(format!("is not a text value ({})", show(v))) };
                (!regex.is_match(&text)).then(|| format!("{} is not {}", show(v), casing.label()))
            }
            Function::Enumeration { values } => {
                let v = value?;
                (!values.contains(v))
                    .then(|| format!("{} is not one of: {}", show(v), values.iter().map(show).collect::<Vec<_>>().join(", ")))
            }
            Function::Length { min, max } => {
                let v = value?;
                let len = match v {
                    Value::String(s) => s.chars().count() as f64,
                    Value::Array(a) => a.len() as f64,
                    Value::Object(o) => o.len() as f64,
                    Value::Number(n) => n.as_f64().unwrap_or(0.0),
                    _ => return Some(format!("has no length ({})", show(v))),
                };
                let unit = if v.is_number() { "" } else { " long" };
                if let Some(m) = min
                    && len < *m
                {
                    return Some(format!("is {len}{unit}; the minimum is {m}"));
                }
                if let Some(m) = max
                    && len > *m
                {
                    return Some(format!("is {len}{unit}; the maximum is {m}"));
                }
                None
            }
            Function::Alphabetical { key } => {
                let v = value?;
                let items: Vec<String> = match (v, key) {
                    (Value::Array(a), None) => a.iter().map(|x| scalar(x).unwrap_or_else(|| x.to_string())).collect(),
                    (Value::Array(a), Some(k)) => a.iter().map(|x| x.get(k).and_then(scalar).unwrap_or_default()).collect(),
                    (Value::Object(o), _) => o.keys().cloned().collect(),
                    _ => return Some(format!("is not a list ({})", show(v))),
                };
                items
                    .windows(2)
                    .find(|w| w[0].to_lowercase() > w[1].to_lowercase())
                    .map(|w| format!("is not in alphabetical order (\"{}\" comes before \"{}\")", w[0], w[1]))
            }
            Function::Includes { values, pattern } => {
                let Some(Value::Array(items)) = value else {
                    return Some(match value {
                        Some(v) => format!("is not a list ({})", show(v)),
                        None => "is missing".into(),
                    });
                };
                if let Some(missing) = values.iter().find(|x| !items.contains(x)) {
                    return Some(format!("does not include {}", show(missing)));
                }
                if let Some(re) = pattern
                    && !items.iter().any(|x| scalar(x).is_some_and(|t| re.is_match(&t)))
                {
                    return Some(format!("has no item matching /{}/", re.as_str()));
                }
                None
            }
            Function::Unique => {
                let Some(Value::Array(items)) = value else { return None };
                // Serialized items in a set: linear, whatever the list's length.
                let mut seen = std::collections::HashSet::new();
                items.iter().find(|x| !seen.insert(x.to_string())).map(|x| format!("has duplicate item {}", show(x)))
            }
            Function::Xor { fields } => {
                let set: Vec<&String> = fields.iter().filter(|f| sibling(f).is_some_and(|v| !v.is_null())).collect();
                match set.len() {
                    1 => None,
                    0 => Some(format!("needs exactly one of {} (none is set)", fields.join(", "))),
                    _ => Some(format!(
                        "needs exactly one of {} (found {})",
                        fields.join(", "),
                        set.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
                    )),
                }
            }
            Function::Schema { validator } => {
                let v = value?;
                let errors: Vec<String> = validator
                    .iter_errors(v)
                    .take(3)
                    .map(|e| {
                        let at = e.instance_path().to_string();
                        if at.is_empty() { e.to_string() } else { format!("{e} at {at}") }
                    })
                    .collect();
                (!errors.is_empty()).then(|| format!("does not match the schema: {}", errors.join("; ")))
            }
        }
    }
}

fn truthy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) | Some(Value::Bool(false)) => false,
        Some(Value::String(s)) => !s.trim().is_empty(),
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Object(o)) => !o.is_empty(),
        Some(Value::Number(n)) => n.as_f64() != Some(0.0),
        Some(Value::Bool(true)) => true,
    }
}

fn scalar(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// A short rendering of a value for messages.
pub fn show(v: &Value) -> String {
    let s = match v {
        Value::Array(a) if a.iter().all(|x| x.is_string()) && !a.is_empty() => {
            a.iter().filter_map(Value::as_str).map(|x| format!("\"{x}\"")).collect::<Vec<_>>().join(", ")
        }
        other => other.to_string(),
    };
    if s.chars().count() > 120 { format!("{}…", s.chars().take(120).collect::<String>()) } else { s }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn eval(name: &str, opts: Value, v: Value) -> Option<String> {
        Function::compile(name, &opts).unwrap().evaluate(Some(&v), &|_| None)
    }

    #[test]
    fn casing() {
        let c = |t: &str, v: &str| eval("casing", json!({"type": t}), json!(v));
        assert_eq!(c("camel", "listPets"), None);
        assert!(c("camel", "ListPets").unwrap().contains("camelCase"));
        assert!(c("camel", "list_pets").is_some());
        assert_eq!(c("kebab", "pet-owners"), None);
        assert!(c("kebab", "petOwners").is_some());
        assert!(c("kebab", "pet--owners").is_some());
        assert_eq!(c("snake", "pet_owner2"), None);
        assert_eq!(c("pascal", "PetOwner"), None);
        assert_eq!(c("macro", "PET_OWNER"), None);
        assert_eq!(c("cobol", "PET-OWNER"), None);
        assert_eq!(c("flat", "petowner"), None);
        assert!(eval("casing", json!({"type": "camel", "disallow_digits": true}), json!("pet2")).is_some());
    }

    #[test]
    fn truthiness_and_presence() {
        let f = |n: &str, v: Option<Value>| Function::compile(n, &Value::Null).unwrap().evaluate(v.as_ref(), &|_| None);
        assert!(f("defined", None).is_some());
        assert!(f("defined", Some(Value::Null)).is_some());
        assert!(f("defined", Some(json!(""))).is_none());
        assert!(f("truthy", Some(json!(""))).is_some());
        assert!(f("truthy", Some(json!([]))).is_some());
        assert!(f("truthy", Some(json!(["a"]))).is_none());
        assert!(f("falsy", Some(json!(["id"]))).unwrap().contains("\"id\""));
        assert!(f("falsy", None).is_none());
        assert!(f("undefined", Some(json!(1))).is_some());
    }

    #[test]
    fn values_and_lists() {
        assert!(eval("pattern", json!({"match": "^/v[0-9]+/"}), json!("/pets")).is_some());
        assert!(eval("pattern", json!({"notMatch": "/$"}), json!("/pets/")).is_some());
        assert!(eval("pattern", json!({"match": "x"}), json!(["x"])).unwrap().contains("not a text value"));
        assert!(eval("enumeration", json!({"values": ["a", "b"]}), json!("c")).is_some());
        assert!(eval("length", json!({"max": 3}), json!("abcd")).is_some());
        assert!(eval("length", json!({"min": 1}), json!([])).is_some());
        assert!(eval("alphabetical", Value::Null, json!(["b", "a"])).is_some());
        assert!(eval("alphabetical", json!({"key": "name"}), json!([{"name": "a"}, {"name": "B"}])).is_none());
        assert!(eval("includes", json!({"pattern": "^4"}), json!(["200", "500"])).is_some());
        assert!(eval("includes", json!({"values": ["401"]}), json!(["200", "401"])).is_none());
        assert!(eval("unique", Value::Null, json!(["a", "a"])).is_some());
        assert!(eval("schema", json!({"schema": {"type": "string", "maxLength": 2}}), json!("abc")).is_some());
    }

    #[test]
    fn xor_reads_siblings() {
        let f = Function::compile("xor", &json!({"fields": ["a", "b"]})).unwrap();
        assert!(f.evaluate(None, &|n| (n == "a").then(|| json!(1))).is_none());
        assert!(f.evaluate(None, &|_| Some(json!(1))).is_some());
        assert!(f.evaluate(None, &|_| None).is_some());
    }

    #[test]
    fn bad_options_are_refused() {
        assert!(Function::compile("pattern", &json!({"matches": "x"})).is_err());
        assert!(Function::compile("pattern", &json!({"match": "("})).is_err());
        assert!(Function::compile("casing", &json!({"type": "train"})).is_err());
        assert!(Function::compile("length", &json!({})).is_err());
        assert!(Function::compile("nope", &Value::Null).is_err());
        assert!(Function::compile("defined", &json!({"x": 1})).is_err());
        assert!(Function::compile("schema", &json!({"schema": {"type": 3}})).is_err());
    }
}
