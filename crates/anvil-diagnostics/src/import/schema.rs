//! Small, fail-closed interpreter for the assertions in the three pinned schemas.
//! No remote references or runtime schema input. Independent jsonschema parity tests
//! cover every canonical fixture; compilation asserts the supported keyword set.

use super::ImportError;
use anvil_domain::diagnostic_import::ImportedDiagnosticKind;
use regex::Regex;
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::OnceLock;

const REPORT: &str = include_str!("../../../../contracts/ferrum-contracts/schemas/diagnostic-report/v1.schema.json");
const FINDING: &str = include_str!("../../../../contracts/ferrum-contracts/schemas/diagnostic-finding/v1.schema.json");
const REFERENCE: &str = include_str!("../../../../contracts/ferrum-contracts/schemas/diagnostic-ref/v1.schema.json");

#[derive(Default)]
struct Node {
    types: Vec<String>,
    constant: Option<Value>,
    choices: Option<Vec<Value>>,
    any: Vec<Node>,
    one: Vec<Node>,
    required: Vec<String>,
    properties: BTreeMap<String, Node>,
    additional: Option<Box<Node>>,
    allow_additional: bool,
    items: Option<Box<Node>>,
    pattern: Option<Regex>,
    format: Option<String>,
    min: Option<f64>,
    max: Option<f64>,
    max_length: Option<u64>,
    max_items: Option<u64>,
    max_properties: Option<u64>,
}

fn compile(schema: &Value, root: &Value) -> Node {
    if let Some(reference) = schema["$ref"].as_str() {
        assert!(reference.starts_with("#/$defs/"), "only local pinned references");
        assert!(schema.as_object().expect("reference schema").keys().all(|key| matches!(key.as_str(), "$ref" | "description" | "title")));
        return compile(root.pointer(&reference[1..]).expect("pinned definition"), root);
    }
    // A pin update cannot silently add an assertion this consumer does not enforce.
    for key in schema.as_object().expect("schema object").keys() {
        assert!(matches!(
            key.as_str(),
            "$schema"
                | "$id"
                | "$defs"
                | "x-contract"
                | "title"
                | "description"
                | "type"
                | "const"
                | "enum"
                | "anyOf"
                | "oneOf"
                | "required"
                | "properties"
                | "additionalProperties"
                | "items"
                | "pattern"
                | "format"
                | "minimum"
                | "maximum"
                | "maxLength"
                | "maxItems"
                | "maxProperties"
        ));
    }
    let list =
        |key: &str| schema[key].as_array().map(|values| values.iter().map(|value| compile(value, root)).collect()).unwrap_or_default();
    let types = match &schema["type"] {
        Value::String(value) => vec![value.clone()],
        Value::Array(values) => values.iter().map(|value| value.as_str().expect("type").into()).collect(),
        Value::Null => Vec::new(),
        _ => panic!("pinned schema type"),
    };
    assert!(
        types.iter().all(|kind| { matches!(kind.as_str(), "object" | "array" | "string" | "number" | "integer" | "boolean" | "null") })
    );
    assert!(schema["format"].as_str().is_none_or(|format| matches!(format, "uint32" | "date-time")));
    Node {
        types,
        constant: schema.get("const").cloned(),
        choices: schema["enum"].as_array().cloned(),
        any: list("anyOf"),
        one: list("oneOf"),
        required: schema["required"]
            .as_array()
            .map(|keys| keys.iter().map(|key| key.as_str().expect("required").into()).collect())
            .unwrap_or_default(),
        properties: schema["properties"]
            .as_object()
            .map(|map| map.iter().map(|(key, value)| (key.clone(), compile(value, root))).collect())
            .unwrap_or_default(),
        additional: schema["additionalProperties"].as_object().map(|_| Box::new(compile(&schema["additionalProperties"], root))),
        allow_additional: schema["additionalProperties"] != false,
        items: schema.get("items").map(|value| Box::new(compile(value, root))),
        pattern: schema["pattern"].as_str().map(|p| Regex::new(p).expect("pinned pattern")),
        format: schema["format"].as_str().map(str::to_owned),
        min: schema["minimum"].as_f64(),
        max: schema["maximum"].as_f64(),
        max_length: schema["maxLength"].as_u64(),
        max_items: schema["maxItems"].as_u64(),
        max_properties: schema["maxProperties"].as_u64(),
    }
}

impl Node {
    fn accepts(&self, value: &Value) -> bool {
        if (!self.types.is_empty() && !self.types.iter().any(|kind| has_type(value, kind)))
            || self.constant.as_ref().is_some_and(|v| v != value)
            || self.choices.as_ref().is_some_and(|values| !values.contains(value))
            || (!self.any.is_empty() && !self.any.iter().any(|node| node.accepts(value)))
            || (!self.one.is_empty() && self.one.iter().filter(|node| node.accepts(value)).count() != 1)
        {
            return false;
        }
        if let Some(number) = value.as_f64()
            && (self.min.is_some_and(|min| number < min) || self.max.is_some_and(|max| number > max))
        {
            return false;
        }
        if let Some(text) = value.as_str()
            && (self.max_length.is_some_and(|max| text.chars().count() as u64 > max)
                || self.pattern.as_ref().is_some_and(|pattern| !pattern.is_match(text))
                || (self.format.as_deref() == Some("date-time") && !rfc3339(text)))
        {
            return false;
        }
        if let Some(array) = value.as_array() {
            if self.max_items.is_some_and(|max| array.len() as u64 > max) {
                return false;
            }
            if let Some(items) = &self.items
                && !array.iter().all(|value| items.accepts(value))
            {
                return false;
            }
        }
        if let Some(object) = value.as_object() {
            if self.max_properties.is_some_and(|max| object.len() as u64 > max) || !self.required.iter().all(|key| object.contains_key(key))
            {
                return false;
            }
            for (key, value) in object {
                match self.properties.get(key).or(self.additional.as_deref()) {
                    Some(node) if !node.accepts(value) => return false,
                    None if !self.allow_additional => return false,
                    _ => {}
                }
            }
        }
        true
    }
}

fn has_type(value: &Value, kind: &str) -> bool {
    match kind {
        "object" => value.is_object(),
        "array" => value.is_array(),
        "string" => value.is_string(),
        "number" => value.is_number(),
        "integer" => value.as_f64().is_some_and(|number| number.fract() == 0.0),
        "boolean" => value.is_boolean(),
        "null" => value.is_null(),
        _ => panic!("unsupported pinned type"),
    }
}

pub(super) fn rfc3339(text: &str) -> bool {
    static RFC3339: OnceLock<Regex> = OnceLock::new();
    let syntax = RFC3339.get_or_init(|| {
        Regex::new(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt][0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?([Zz]|[+-][0-9]{2}:[0-9]{2})$")
            .expect("RFC 3339 pattern")
    });
    syntax.is_match(text) && chrono::DateTime::parse_from_rfc3339(text).is_ok()
}

pub(super) fn validate(value: &Value, kind: ImportedDiagnosticKind) -> Result<(), ImportError> {
    static SCHEMAS: OnceLock<[Node; 3]> = OnceLock::new();
    let schemas = SCHEMAS.get_or_init(|| {
        [REPORT, FINDING, REFERENCE].map(|text| {
            let root = serde_json::from_str(text).expect("immutable schema JSON");
            compile(&root, &root)
        })
    });
    let index = match kind {
        ImportedDiagnosticKind::Report | ImportedDiagnosticKind::AlloyCli => 0,
        ImportedDiagnosticKind::Finding => 1,
        ImportedDiagnosticKind::Reference => 2,
    };
    if schemas[index].accepts(value) { Ok(()) } else { Err(ImportError::Contract) }
}
