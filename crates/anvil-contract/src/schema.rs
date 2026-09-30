//! OpenAPI Schema Objects as JSON Schema 2020-12 validators.
//!
//! OpenAPI 3.1 and 3.2 schemas are JSON Schema 2020-12 already. Swagger 2.0
//! and OpenAPI 3.0 use an extended subset of draft 4/5, converted here:
//! `nullable` / `x-nullable` become a `null` type (or `anyOf` with `null`),
//! boolean `exclusiveMinimum`/`exclusiveMaximum` become the numeric form,
//! siblings of `$ref` are dropped (they are ignored in those versions) and
//! the 2.0 `file` type accepts anything. In every version a `required`
//! property that is `readOnly` is not required in a request, and one that
//! is `writeOnly` is not required in a response.
//!
//! A validator is built from the schema plus only the component schemas it
//! reaches through internal `$ref`s, copied at their original pointers, so
//! references resolve as in the document. External references are never
//! fetched: a schema that uses one cannot be compiled.

use crate::model::Direction;
use crate::spec::{Spec, internal_pointer};
use anvil_import::Dialect;
use serde_json::{Map, Value, json};
use std::collections::{HashMap, HashSet};

const MAX_DEPTH: usize = 64;
/// References followed inside one another, and nesting summed along such a
/// chain: the validator compiles and checks schemas recursively.
const MAX_REF_CHAIN: usize = 32;
const MAX_CHAIN_DEPTH: usize = 512;
/// Schema nodes a check may visit for one value with every `$ref` expanded
/// (repeated references count each time): beyond this a schema is not used.
pub const MAX_EXPANDED_NODES: usize = 100_000;
/// Distinct `$ref` targets copied into one validator.
const MAX_REF_TARGETS: usize = 4_096;

/// Build a validator for `schema` (located at `pointer`), as it applies in
/// `direction`.
pub fn compile(spec: &Spec, schema: &Value, direction: Direction) -> Result<jsonschema::Validator, String> {
    // Validation walks the schema with references expanded: a schema that
    // fans out through repeated `$ref`s (each level twice, forty levels
    // deep) compiles cheaply and then validates for ever.
    measure(spec, schema)?;
    let wrapper = bundle(spec, schema, direction)?;
    jsonschema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .should_validate_formats(true)
        .with_pattern_options(linear_patterns())
        .build(&wrapper)
        .map_err(|e| format!("the schema cannot be compiled: {e}"))
}

/// `pattern` and `patternProperties` use the linear-time `regex` engine (not
/// the backtracking default), size-limited: a hostile pattern cannot stall a
/// check. Patterns that need look-around or back-references do not compile,
/// and a schema using one is not checked.
pub fn linear_patterns() -> jsonschema::PatternOptions<jsonschema::Regex> {
    jsonschema::PatternOptions::regex().size_limit(1 << 20).dfa_size_limit(1 << 20)
}

/// The converted schema with the `$ref` targets it reaches, as one document.
pub fn bundle(spec: &Spec, schema: &Value, direction: Direction) -> Result<Value, String> {
    let root = convert(spec, schema, direction, 0);
    let mut doc = Value::Object(Map::new());
    let mut pending: Vec<String> = vec![];
    collect_refs(&root, &mut pending)?;
    let mut queued: HashSet<String> = pending.iter().cloned().collect();
    // Copied targets; a target inside one of them is already present.
    let mut copied: HashSet<String> = HashSet::new();
    while let Some(target) = pending.pop() {
        let inside =
            std::iter::once(target.as_str()).chain(target.match_indices('/').map(|(i, _)| &target[..i])).any(|p| copied.contains(p));
        if inside {
            continue;
        }
        copied.insert(target.clone());
        if copied.len() > MAX_REF_TARGETS {
            return Err(format!("the schema reaches more than {MAX_REF_TARGETS} referenced schemas"));
        }
        let Some(raw) = spec.root.pointer(&target) else {
            return Err(format!("unresolved reference #{target}"));
        };
        let converted = convert(spec, raw, direction, 0);
        let mut found = vec![];
        collect_refs(&converted, &mut found)?;
        pending.extend(found.into_iter().filter(|t| queued.insert(t.clone())));
        insert_at(&mut doc, &target, converted);
    }
    let Value::Object(mut map) = doc else { unreachable!("the bundle is an object") };
    // Keywords at the root would apply to the bundle; nest the schema.
    map.insert("$schema".into(), json!("https://json-schema.org/draft/2020-12/schema"));
    map.insert("allOf".into(), json!([root]));
    Ok(Value::Object(map))
}

/// Keywords whose subschemas apply to a part of the value (a property, an
/// item, a property name): a reference cycle through one of them ends with
/// the value. (`dependentSchemas` applies to the same value, so it does not.)
fn descends(keyword: &str) -> bool {
    matches!(
        keyword,
        "properties"
            | "patternProperties"
            | "additionalProperties"
            | "items"
            | "prefixItems"
            | "additionalItems"
            | "contains"
            | "propertyNames"
            | "unevaluatedProperties"
            | "unevaluatedItems"
    )
}

/// One schema (the root, or a `$ref` target): how many objects and lists
/// it has, and its internal references, each with whether it sits under a
/// keyword that descends into the value.
struct Part {
    nodes: usize,
    /// Deepest nesting of objects and lists.
    depth: usize,
    refs: Vec<(String, bool)>,
}

fn scan(v: &Value) -> Part {
    let mut part = Part { nodes: 0, depth: 0, refs: vec![] };
    let mut stack: Vec<(&Value, bool, usize)> = vec![(v, false, 1)];
    while let Some((v, down, d)) = stack.pop() {
        part.depth = part.depth.max(d);
        match v {
            Value::Object(o) => {
                part.nodes += 1;
                if let Some(t) = o.get("$ref").and_then(Value::as_str).and_then(internal_pointer) {
                    part.refs.push((t, down));
                }
                for (k, child) in o {
                    if k != "$ref" && (child.is_object() || child.is_array()) {
                        stack.push((child, down || descends(k), d + 1));
                    }
                }
            }
            Value::Array(a) => {
                part.nodes += 1;
                stack.extend(a.iter().filter(|c| c.is_object() || c.is_array()).map(|c| (c, down, d + 1)));
            }
            _ => {}
        }
    }
    part
}

const ROOT: &str = "#root";

/// Check a schema before it is compiled: refuse a reference cycle that
/// does not descend into the value (validation would never end), and a
/// schema that expands to more than [`MAX_EXPANDED_NODES`] nodes with every
/// `$ref` expanded (repeated references count each time). Both passes are
/// iterative, so neither nesting nor reference chains use the call stack.
fn measure(spec: &Spec, schema: &Value) -> Result<usize, String> {
    let mut parts: HashMap<String, Part> = HashMap::from([(ROOT.to_string(), scan(schema))]);
    let part_of = |parts: &mut HashMap<String, Part>, key: &str| -> Result<bool, String> {
        if parts.contains_key(key) {
            return Ok(true);
        }
        if parts.len() >= MAX_REF_TARGETS {
            return Err(format!("the schema reaches more than {MAX_REF_TARGETS} referenced schemas"));
        }
        match spec.root.pointer(key) {
            Some(v) => {
                parts.insert(key.to_string(), scan(v));
                Ok(true)
            }
            None => Ok(false),
        }
    };

    // 1. Every schema the root reaches, over all references.
    let mut queue: Vec<String> = vec![ROOT.to_string()];
    let mut reached: Vec<String> = vec![ROOT.to_string()];
    let mut queued: HashSet<String> = HashSet::from([ROOT.to_string()]);
    while let Some(key) = queue.pop() {
        let targets: Vec<String> = parts[key.as_str()].refs.iter().map(|(t, _)| t.clone()).collect();
        for t in targets {
            if queued.insert(t.clone()) && part_of(&mut parts, &t)? {
                reached.push(t.clone());
                queue.push(t);
            }
        }
    }

    // 2. Cycles along references that do not descend, searched from every
    //    reached schema (one reached only through a descending reference
    //    can still loop on itself): three colours, iterative.
    let mut colour: HashMap<String, u8> = HashMap::new();
    for start in &reached {
        if colour.contains_key(start) {
            continue;
        }
        colour.insert(start.clone(), 1);
        let mut stack: Vec<(String, usize)> = vec![(start.clone(), 0)];
        while let Some((key, i)) = stack.last_mut() {
            let next = parts
                .get(key.as_str())
                .and_then(|p| p.refs.iter().enumerate().skip(*i).find(|(_, (_, down))| !down).map(|(j, (t, _))| (j, t.clone())));
            let Some((j, target)) = next else {
                colour.insert(key.clone(), 2);
                stack.pop();
                continue;
            };
            *i = j + 1;
            match colour.get(&target).copied() {
                Some(1) => return Err("the schema refers to itself without descending into the value".into()),
                Some(_) => {}
                None if parts.contains_key(target.as_str()) => {
                    colour.insert(target.clone(), 1);
                    stack.push((target, 0));
                }
                None => {}
            }
        }
    }

    // 3. Sizes, memoized per target; a reference back to a schema being
    //    measured (a cycle through the value) adds nothing more.
    let too_big = || format!("the schema expands to more than {MAX_EXPANDED_NODES} nodes through its references");
    let mut size: HashMap<String, usize> = HashMap::new();
    let mut open: HashSet<String> = HashSet::from([ROOT.to_string()]);
    let mut stack: Vec<(String, usize, usize)> = vec![(ROOT.to_string(), 0, 0)];
    let mut chain_depth = parts[ROOT].depth;
    loop {
        let Some((key, i, acc)) = stack.last_mut() else { unreachable!("the root is popped last") };
        if let Some((target, _)) = parts[key.as_str()].refs.get(*i).cloned() {
            *i += 1;
            if let Some(n) = size.get(&target) {
                *acc = acc.saturating_add(*n);
            } else if !open.contains(&target) && part_of(&mut parts, &target)? {
                if stack.len() >= MAX_REF_CHAIN || chain_depth + parts[target.as_str()].depth > MAX_CHAIN_DEPTH {
                    return Err("the schema nests references too deeply".into());
                }
                chain_depth += parts[target.as_str()].depth;
                open.insert(target.clone());
                stack.push((target, 0, 0));
            }
            continue;
        }
        let total = parts[key.as_str()].nodes.saturating_add(*acc);
        if total > MAX_EXPANDED_NODES {
            return Err(too_big());
        }
        let done = key.clone();
        stack.pop();
        chain_depth -= parts[done.as_str()].depth;
        open.remove(&done);
        size.insert(done, total);
        match stack.last_mut() {
            Some((_, _, parent)) => *parent = parent.saturating_add(total),
            None => return Ok(total),
        }
    }
}

fn collect_refs(v: &Value, out: &mut Vec<String>) -> Result<(), String> {
    let mut stack = vec![v];
    while let Some(v) = stack.pop() {
        match v {
            Value::Object(o) => {
                if let Some(r) = o.get("$ref").and_then(Value::as_str) {
                    match internal_pointer(r) {
                        Some(p) => out.push(p),
                        None => return Err(format!("external reference '{r}' is not resolved")),
                    }
                }
                stack.extend(o.values());
            }
            Value::Array(a) => stack.extend(a),
            _ => {}
        }
    }
    Ok(())
}

fn unescape(token: &str) -> String {
    token.replace("~1", "/").replace("~0", "~")
}

fn insert_at(doc: &mut Value, pointer: &str, value: Value) {
    let tokens: Vec<String> = pointer.split('/').skip(1).map(unescape).collect();
    let Some((last, parents)) = tokens.split_last() else { return };
    let mut cur = doc;
    for t in parents {
        if !cur.is_object() {
            return;
        }
        cur = cur.as_object_mut().expect("checked").entry(t.clone()).or_insert_with(|| Value::Object(Map::new()));
    }
    if let Some(o) = cur.as_object_mut() {
        o.insert(last.clone(), value);
    }
}

fn legacy(d: Dialect) -> bool {
    matches!(d, Dialect::Swagger20 | Dialect::OpenApi30)
}

/// Convert one schema (not following `$ref`s) for `direction`.
pub fn convert(spec: &Spec, schema: &Value, direction: Direction, depth: usize) -> Value {
    let Value::Object(src) = schema else {
        // `true`/`false` schemas (3.1+) and anything malformed pass through.
        return schema.clone();
    };
    if depth > MAX_DEPTH {
        return json!({});
    }
    let old = legacy(spec.dialect);
    if old && let Some(r) = src.get("$ref") {
        let nullable = src.get("x-nullable").and_then(Value::as_bool).unwrap_or(false);
        return if nullable { json!({"anyOf": [{"$ref": r}, {"type": "null"}]}) } else { json!({"$ref": r}) };
    }
    let mut out = Map::new();
    for (k, v) in src {
        let converted = match k.as_str() {
            "properties" | "patternProperties" | "$defs" | "definitions" | "dependentSchemas" => match v {
                Value::Object(m) => Value::Object(m.iter().map(|(n, s)| (n.clone(), convert(spec, s, direction, depth + 1))).collect()),
                other => other.clone(),
            },
            "items"
            | "additionalProperties"
            | "not"
            | "contains"
            | "if"
            | "then"
            | "else"
            | "propertyNames"
            | "unevaluatedProperties"
            | "unevaluatedItems"
            | "additionalItems" => match v {
                Value::Array(a) => Value::Array(a.iter().map(|s| convert(spec, s, direction, depth + 1)).collect()),
                s => convert(spec, s, direction, depth + 1),
            },
            "allOf" | "anyOf" | "oneOf" | "prefixItems" => match v {
                Value::Array(a) => Value::Array(a.iter().map(|s| convert(spec, s, direction, depth + 1)).collect()),
                other => other.clone(),
            },
            "required" => match v {
                Value::Array(names) => Value::Array(names.iter().filter(|n| !excluded(spec, src, n, direction)).cloned().collect()),
                other => other.clone(),
            },
            // Annotations of OpenAPI with no validation meaning.
            "discriminator" | "xml" | "externalDocs" | "example" if old => continue,
            "nullable" | "x-nullable" if old => continue,
            "$id" | "id" if old => continue,
            "exclusiveMinimum" | "exclusiveMaximum" if old && v.is_boolean() => continue,
            "type" if old && v.as_str() == Some("file") => continue,
            _ => v.clone(),
        };
        out.insert(k.clone(), converted);
    }
    if old {
        for (flag, bound) in [("exclusiveMinimum", "minimum"), ("exclusiveMaximum", "maximum")] {
            if src.get(flag).and_then(Value::as_bool) == Some(true)
                && let Some(b) = src.get(bound)
            {
                out.remove(bound);
                out.insert(flag.into(), b.clone());
            }
        }
        let nullable = src.get("nullable").or_else(|| src.get("x-nullable")).and_then(Value::as_bool).unwrap_or(false);
        if nullable {
            match out.get("type").cloned() {
                Some(Value::String(t)) => {
                    out.insert("type".into(), json!([t, "null"]));
                    if let Some(Value::Array(e)) = out.get_mut("enum")
                        && !e.contains(&Value::Null)
                    {
                        e.push(Value::Null);
                    }
                }
                Some(_) => {}
                None => return json!({"anyOf": [Value::Object(out), {"type": "null"}]}),
            }
        }
    }
    Value::Object(out)
}

/// Whether required property `name` of `parent` does not apply in `direction`.
fn excluded(spec: &Spec, parent: &Map<String, Value>, name: &Value, direction: Direction) -> bool {
    let Some(name) = name.as_str() else { return false };
    let Some(prop) = parent.get("properties").and_then(|p| p.get(name)) else { return false };
    let (prop, _) = spec.deref(prop, "");
    let flag = match direction {
        Direction::Request => "readOnly",
        Direction::Response => "writeOnly",
    };
    prop.get(flag).and_then(Value::as_bool).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(text: &str) -> Spec {
        Spec::parse(text.as_bytes()).unwrap()
    }

    #[test]
    fn openapi30_nullable_and_exclusive_bounds() {
        let s = spec(
            r##"{"openapi":"3.0.3","info":{"title":"t","version":"1"},"paths":{},"components":{"schemas":{
              "Pet":{"type":"object","required":["id","name","secret"],"properties":{
                "id":{"type":"integer","readOnly":true},
                "name":{"type":"string","nullable":true,"enum":["a","b"]},
                "age":{"type":"number","minimum":0,"exclusiveMinimum":true},
                "secret":{"type":"string","writeOnly":true},
                "owner":{"$ref":"#/components/schemas/Owner","description":"ignored sibling"}}},
              "Owner":{"type":"object","required":["email"],"properties":{"email":{"type":"string","format":"email"}}}}}}"##,
        );
        let pet = s.root.pointer("/components/schemas/Pet").unwrap();
        let v = compile(&s, pet, Direction::Response).unwrap();
        assert!(v.is_valid(&json!({"id": 1, "name": null})));
        assert!(v.is_valid(&json!({"id": 1, "name": "a", "age": 1})));
        assert!(!v.is_valid(&json!({"id": 1, "name": "a", "age": 0})), "exclusive minimum");
        assert!(!v.is_valid(&json!({"name": "a"})), "id is required in a response");
        assert!(!v.is_valid(&json!({"id": 1, "name": "c"})), "enum");
        assert!(!v.is_valid(&json!({"id": 1, "name": "a", "owner": {"email": "not-an-email"}})), "format via $ref");
        let r = compile(&s, pet, Direction::Request).unwrap();
        assert!(!r.is_valid(&json!({"name": "a"})), "secret is required in a request");
        assert!(r.is_valid(&json!({"name": "a", "secret": "x"})), "id is read-only");
    }

    #[test]
    fn openapi31_is_used_as_is_and_recursion_resolves() {
        let s = spec(
            r##"{"openapi":"3.1.0","info":{"title":"t","version":"1"},"paths":{},"components":{"schemas":{
              "Node":{"type":["object","null"],"properties":{"next":{"$ref":"#/components/schemas/Node"},"v":{"type":"integer","exclusiveMinimum":0}}}}}}"##,
        );
        let node = s.root.pointer("/components/schemas/Node").unwrap();
        let v = compile(&s, node, Direction::Response).unwrap();
        assert!(v.is_valid(&json!({"v": 1, "next": {"v": 2, "next": null}})));
        assert!(!v.is_valid(&json!({"v": 1, "next": {"v": 0}})));
    }

    #[test]
    fn swagger2_definitions_and_file() {
        let s = spec(
            r##"{"swagger":"2.0","info":{"title":"t","version":"1"},"paths":{},"definitions":{
              "Err":{"type":"object","properties":{"code":{"type":"integer","x-nullable":true},"f":{"type":"file"}}}}}"##,
        );
        let v = compile(&s, &json!({"$ref": "#/definitions/Err"}), Direction::Response).unwrap();
        assert!(v.is_valid(&json!({"code": null, "f": 3})));
        assert!(!v.is_valid(&json!({"code": "x"})));
    }

    #[test]
    fn formats_are_asserted_and_unknown_ones_ignored() {
        let s = spec(r##"{"openapi":"3.0.3","info":{"title":"t","version":"1"},"paths":{}}"##);
        let v = compile(&s, &json!({"type": "object", "properties": {"at": {"type": "string", "format": "date-time"}, "n": {"type": "integer", "format": "int64"}}}), Direction::Response).unwrap();
        assert!(v.is_valid(&json!({"at": "2026-09-30T10:00:00Z", "n": 5})));
        assert!(!v.is_valid(&json!({"at": "yesterday"})));
    }

    #[test]
    fn patterns_are_linear_and_cycles_terminate() {
        let s = spec(
            r##"{"openapi":"3.1.0","info":{"title":"t","version":"1"},"paths":{},"components":{"schemas":{
              "A":{"allOf":[{"$ref":"#/components/schemas/B"}],"properties":{"x":{"type":"string","pattern":"^(a*)*b$"}}},
              "B":{"allOf":[{"$ref":"#/components/schemas/A"}]},
              "P":{"type":"object","properties":{"x":{"type":"string","pattern":"^(a*)*b$"}}}}}}"##,
        );
        // A cycle through `allOf` alone would never end: refused.
        let a = s.root.pointer("/components/schemas/A").unwrap();
        let e = compile(&s, a, Direction::Response).unwrap_err();
        assert!(e.contains("refers to itself"), "{e}");
        // The pattern runs on the linear engine.
        let v = compile(&s, s.root.pointer("/components/schemas/P").unwrap(), Direction::Response).unwrap();
        let start = std::time::Instant::now();
        assert!(!v.is_valid(&json!({"x": "a".repeat(10_000)})));
        assert!(start.elapsed() < std::time::Duration::from_secs(2));
        // A back-reference needs a backtracking engine: the schema is not compiled.
        assert!(compile(&s, &json!({"type": "string", "pattern": "(a)\\1"}), Direction::Response).is_err());
    }

    #[test]
    fn fan_out_through_repeated_references_is_refused() {
        let mut schemas = serde_json::Map::new();
        for i in 0..25 {
            let next = format!("#/components/schemas/S{}", i + 1);
            schemas.insert(format!("S{i}"), json!({"allOf": [{"$ref": next}, {"$ref": next}]}));
        }
        schemas.insert("S25".into(), json!({"type": "object"}));
        let doc = json!({"openapi": "3.1.0", "info": {"title": "t", "version": "1"}, "paths": {}, "components": {"schemas": schemas}});
        let s = spec(&doc.to_string());
        let start = std::time::Instant::now();
        let e = compile(&s, &json!({"$ref": "#/components/schemas/S0"}), Direction::Response).unwrap_err();
        assert!(e.contains("expands to more than"), "{e}");
        assert!(start.elapsed() < std::time::Duration::from_secs(2));
        // A shallow chain is fine.
        assert!(compile(&s, &json!({"$ref": "#/components/schemas/S20"}), Direction::Response).is_ok());
    }

    #[test]
    fn a_cycle_is_found_whatever_path_reaches_it_first() {
        // U is first reached through `additionalProperties` (descending), but
        // V → X → U → V does not descend.
        let s = spec(
            r##"{"openapi":"3.1.0","info":{"title":"t","version":"1"},"paths":{},"components":{"schemas":{
              "V":{"additionalProperties":{"$ref":"#/components/schemas/U"},"allOf":[{"$ref":"#/components/schemas/X"}]},
              "X":{"allOf":[{"$ref":"#/components/schemas/U"}]},
              "U":{"allOf":[{"$ref":"#/components/schemas/V"}]},
              "D":{"dependentSchemas":{"x":{"$ref":"#/components/schemas/D"}}},
              "A":{"allOf":[{"$ref":"#/components/schemas/B"}]},
              "B":{"allOf":[{"$ref":"#/components/schemas/A"}]},
              "InProps":{"properties":{"x":{"$ref":"#/components/schemas/A"}}},
              "VInProps":{"properties":{"x":{"$ref":"#/components/schemas/V"}}},
              "Tree":{"type":"object","properties":{"children":{"type":"array","items":{"$ref":"#/components/schemas/Tree"}}}}}}}"##,
        );
        for name in ["V", "D", "InProps", "VInProps"] {
            let e = compile(&s, &json!({"$ref": format!("#/components/schemas/{name}")}), Direction::Response).unwrap_err();
            assert!(e.contains("refers to itself"), "{name}: {e}");
        }
        // Recursion through the value is fine.
        let tree = compile(&s, &json!({"$ref": "#/components/schemas/Tree"}), Direction::Response).unwrap();
        assert!(tree.is_valid(&json!({"children": [{"children": []}]})));
    }

    #[test]
    fn long_reference_chains_use_no_call_stack() {
        let mut schemas = serde_json::Map::new();
        for i in 0..3_000 {
            schemas.insert(format!("C{i}"), json!({"properties": {"n": {"$ref": format!("#/components/schemas/C{}", i + 1)}}}));
        }
        schemas.insert("C3000".into(), json!({"type": "string"}));
        let doc = json!({"openapi": "3.1.0", "info": {"title": "t", "version": "1"}, "paths": {}, "components": {"schemas": schemas}});
        let s = spec(&doc.to_string());
        // Measured without recursion, and refused: the validator would recurse
        // as deep as the chain.
        let e = compile(&s, &json!({"$ref": "#/components/schemas/C0"}), Direction::Response).unwrap_err();
        assert!(e.contains("too deeply"), "{e}");
        // Up to the limit it compiles and validates, even on a small stack.
        let ok = compile(&s, &json!({"$ref": "#/components/schemas/C2970"}), Direction::Response).unwrap();
        let mut v = json!("x");
        for _ in 0..30 {
            v = json!({ "n": v });
        }
        assert!(ok.is_valid(&v));
    }

    #[test]
    fn external_references_are_refused() {
        let s = spec(r##"{"openapi":"3.1.0","info":{"title":"t","version":"1"},"paths":{}}"##);
        assert!(compile(&s, &json!({"$ref": "https://example.com/x.json"}), Direction::Response).is_err());
        assert!(compile(&s, &json!({"$ref": "#/components/schemas/Missing"}), Direction::Response).is_err());
    }
}
