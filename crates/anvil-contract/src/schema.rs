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
use crate::spec::{Reach, Spec, internal_pointer};
use anvil_import::Dialect;
use serde_json::{Map, Value, json};
use std::collections::{HashMap, HashSet};

const MAX_DEPTH: usize = 64;
/// References followed inside one another, and nesting summed along such a
/// chain: the validator compiles and checks schemas recursively.
const MAX_REF_CHAIN: usize = 32;
const MAX_CHAIN_DEPTH: usize = 512;
/// Members and items (scalars included) looked at while measuring a schema
/// and the schemas it references: a large `enum` passes, a pathological
/// one does not stall every compile. Also caps reference-expanded members
/// and items, since error collection may copy them once per application.
pub const MAX_SCAN_STEPS: usize = 10 * MAX_EXPANDED_NODES;
/// Bytes of member names and strings in a schema and the schemas it
/// references: a compile copies them (converting and bundling the schema,
/// and the validator keeps some), however few members hold them. About 16
/// bytes per member of [`MAX_SCAN_STEPS`], so an ordinary schema meets both
/// limits at about the same size, and only text this long (a description
/// of several megabytes, say) meets this one first. Also caps text with each
/// reference expanded, bounding repeated subschema copies in errors.
pub const MAX_SCAN_BYTES: usize = 16 * 1024 * 1024;
/// Schema nodes a check may visit for one value with every `$ref` expanded
/// (repeated references count each time): beyond this a schema is not used.
pub const MAX_EXPANDED_NODES: usize = 100_000;
/// Distinct `$ref` targets copied into one validator.
const MAX_REF_TARGETS: usize = 4_096;
const MAX_COMPILE_LOCATIONS: usize = 64 * 1024 * 1024;
const MAX_PATTERN_PAIRS: usize = 1_000_000;
const MAX_PATTERN_NAME_WORK: usize = 32 * 1024 * 1024;
const MAX_UNION_ANALYSIS: usize = 1_000_000;
/// Union discriminator inference hashes each required name against property
/// maps, including names that none of those maps contains.
const MAX_UNION_NAME_WORK: usize = 32 * 1024 * 1024;
const MAX_DISTINCT_PATTERNS: usize = 128;
const MAX_DEPENDENCY_COPY_BYTES: usize = 32 * 1024 * 1024;
const MAX_VALIDATION_WORK: usize = 50_000_000;
const MAX_TEXT_INSTANCE_WORK: usize = 256 * 1024 * 1024;
const MAX_ERROR_BYTES: usize = 8 * 1024 * 1024;
const MAX_UNIQUE_WORK: usize = 4_000_000;
/// What every refusal of a schema for its size or nesting starts with (see
/// [`too_large`]).
const TOO_LARGE: &str = "too large to check: ";

/// What schema compiles have scanned, or may scan: members and items, and
/// bytes of member names and strings. Members bound the work of scanning
/// and measuring a schema, bytes what compiling it copies; neither bounds
/// the other (a large `enum` of numbers, a long `description`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Scanned {
    /// Members and items, scalars included.
    pub steps: usize,
    /// Bytes of member names and strings.
    pub bytes: usize,
}

impl Scanned {
    /// No limit.
    pub const UNLIMITED: Scanned = Scanned { steps: usize::MAX, bytes: usize::MAX };

    /// Whether either count is over its limit in `budget`.
    pub fn exceeds(self, budget: Scanned) -> bool {
        self.steps > budget.steps || self.bytes > budget.bytes
    }
}

/// Whether `error`, from [`compile`] or [`compile_within`], refused the
/// schema for its size or nesting (past one of the limits above) rather
/// than for an external, broken or cyclic reference or what the validator
/// rejects.
pub fn too_large(error: &str) -> bool {
    error.starts_with(TOO_LARGE)
}

/// Build a validator for `schema` (located at `pointer`), as it applies in
/// `direction`.
pub fn compile(spec: &Spec, schema: &Value, direction: Direction) -> Result<jsonschema::Validator, String> {
    compile_within(spec, schema, direction, &mut Scanned::default(), Scanned::UNLIMITED)
}

/// [`compile`], adding what it scans to `scanned` and refusing once that
/// exceeds `budget` (shared by many compiles, e.g. every example of a lint):
/// each compile scans its input and completed bundle before building.
pub fn compile_within(
    spec: &Spec,
    schema: &Value,
    direction: Direction,
    scanned: &mut Scanned,
    budget: Scanned,
) -> Result<jsonschema::Validator, String> {
    compile_within_checked(spec, schema, direction, scanned, budget).map(|checked| checked.validator)
}

/// A validator and the bound used before checking each instance. Eager error
/// collection retains copies of both schema payloads and instance values.
pub struct CheckedValidator {
    pub validator: jsonschema::Validator,
    pub plan: ValidationPlan,
}

pub fn compile_within_checked(
    spec: &Spec,
    schema: &Value,
    direction: Direction,
    scanned: &mut Scanned,
    budget: Scanned,
) -> Result<CheckedValidator, String> {
    if scanned.exceeds(budget) {
        return Err("the checks' scanning budget is spent".into());
    }
    // Validation walks the schema with references expanded: a schema that
    // fans out through repeated `$ref`s (each level twice, forty levels
    // deep) compiles cheaply and then validates for ever.
    measure_counted(spec, schema, scanned)?;
    if scanned.exceeds(budget) {
        return Err("the checks' scanning budget is spent".into());
    }
    let wrapper = bundle(spec, schema, direction)?;
    // A copied target can activate a keyword at the document root (for
    // example a target copied to `/properties`). Check the exact document
    // given to the compiler, not just the schema in its original position.
    // Wrapping the selected schema in allOf adds one subschema level.
    let work = measure_in(&wrapper, &wrapper, scanned, MAX_DEPTH + 1)?;
    if scanned.exceeds(budget) {
        return Err("the checks' scanning budget is spent".into());
    }
    check_keywords(&wrapper, &wrapper, false, false)?;
    let risk = check_compile_work(&wrapper, work, false)?;
    let validator = jsonschema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .should_validate_formats(true)
        .with_pattern_options(linear_patterns())
        .build(&wrapper)
        .map_err(|e| format!("the schema cannot be compiled: {e}"))?;
    Ok(CheckedValidator {
        validator,
        plan: ValidationPlan {
            work,
            unique_uses: work.unique_uses.max(usize::from(risk.unique)),
            text_scans: work.pattern_uses.saturating_add(work.string_scans).saturating_add(work.name_lookups),
        },
    })
}

/// `pattern` and `patternProperties` use the linear-time `regex` engine (not
/// the backtracking default), size-limited: a hostile pattern cannot stall a
/// check. Patterns that need look-around or back-references do not compile,
/// and a schema using one is not checked.
pub fn linear_patterns() -> jsonschema::PatternOptions<jsonschema::Regex> {
    // At most 128 distinct patterns are accepted per validator. Together
    // with the per-pattern cap this bounds retained automata to about 16 MiB.
    jsonschema::PatternOptions::regex().size_limit(1 << 17).dfa_size_limit(1 << 17)
}

/// The converted schema with the `$ref` targets it reaches, as one document.
pub fn bundle(spec: &Spec, schema: &Value, direction: Direction) -> Result<Value, String> {
    let mut flags = Flags::new();
    let mut root = convert_in(spec, schema, direction, 0, &mut flags);
    // The wrapper declares this same dialect. Preserve a supported root
    // declaration without moving it into a nested resource during wrapping.
    if let Value::Object(o) = &mut root
        && o.get("$schema").and_then(Value::as_str).is_some_and(is_draft_202012)
    {
        o.remove("$schema");
    }
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
            return Err(format!("{TOO_LARGE}the schema reaches more than {MAX_REF_TARGETS} referenced schemas"));
        }
        let Some(raw) = spec.root.pointer(&target) else {
            return Err(format!("unresolved reference #{target}"));
        };
        let converted = convert_in(spec, raw, direction, 0, &mut flags);
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

/// Validation/compilation work, including data retained by inline `not`
/// validators. Kept separate from physical scans charged to a shared budget.
#[derive(Clone, Copy, Default, Debug)]
struct Work {
    nodes: usize,
    steps: usize,
    bytes: usize,
    pattern_pairs: usize,
    pattern_name_work: usize,
    pattern_uses: usize,
    string_scans: usize,
    regex_format_uses: usize,
    name_lookups: usize,
    name_bytes: usize,
    unique_uses: usize,
    required_names: usize,
    required_name_bytes: usize,
    property_maps: usize,
    union: bool,
    max_ref_chain: usize,
}

/// Whether checking an instance can report detailed errors within a bounded
/// allocation, or only its validity. `Skip` is reported as unchecked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckMode {
    Detailed,
    Generic,
    Skip,
}

#[derive(Clone, Copy, Debug)]
pub struct ValidationPlan {
    work: Work,
    unique_uses: usize,
    text_scans: usize,
}

impl ValidationPlan {
    pub fn mode(self, instance: &Value) -> CheckMode {
        let mut values = 0usize;
        let mut objects = 0usize;
        let mut bytes = 0usize;
        let mut string_bytes = 0usize;
        let mut longest_string = 0usize;
        let mut longest_array = 0usize;
        let mut max_value_depth = 0usize;
        // jsonschema owns an instance path for each retained error. A long
        // ancestor property name is repeated for every failing descendant.
        let mut error_path_bytes = 0usize;
        let mut stack = vec![(instance, 0usize, 0usize)];
        while let Some((value, path_len, depth)) = stack.pop() {
            values = values.saturating_add(1);
            max_value_depth = max_value_depth.max(depth);
            error_path_bytes = error_path_bytes.saturating_add(path_len);
            match value {
                Value::Object(map) => {
                    objects = objects.saturating_add(1);
                    for (name, child) in map {
                        bytes = bytes.saturating_add(name.len());
                        let escaped_len = name.len().saturating_add(name.bytes().filter(|b| matches!(b, b'~' | b'/')).count());
                        stack.push((child, path_len.saturating_add(1).saturating_add(escaped_len), depth.saturating_add(1)));
                    }
                }
                Value::Array(items) => {
                    longest_array = longest_array.max(items.len());
                    stack.extend(items.iter().enumerate().map(|(index, child)| {
                        let mut digits = 1;
                        let mut remaining = index;
                        while remaining >= 10 {
                            remaining /= 10;
                            digits += 1;
                        }
                        (child, path_len.saturating_add(1 + digits), depth.saturating_add(1))
                    }));
                }
                Value::String(s) => {
                    bytes = bytes.saturating_add(s.len());
                    string_bytes = string_bytes.saturating_add(s.len());
                    longest_string = longest_string.max(s.len());
                }
                _ => {}
            }
            if values.saturating_mul(self.work.steps.max(1)) > MAX_VALIDATION_WORK
                || bytes.saturating_mul(self.text_scans) > MAX_TEXT_INSTANCE_WORK
                // The ECMA `regex` format parser can compare every named
                // group with earlier groups in the same string.
                || self
                    .work
                    .regex_format_uses
                    .saturating_mul(longest_string)
                    .saturating_mul(string_bytes)
                    > MAX_TEXT_INSTANCE_WORK
                || objects.saturating_mul(self.work.name_bytes) > MAX_TEXT_INSTANCE_WORK
                || self.unique_uses.saturating_mul(longest_array).saturating_mul(values.saturating_add(bytes)) > MAX_UNIQUE_WORK
            {
                return CheckMode::Skip;
            }
        }
        if self.unique_uses.saturating_mul(longest_array).saturating_mul(values.saturating_add(bytes)) > MAX_UNIQUE_WORK {
            return CheckMode::Skip;
        }
        // A failed anyOf/oneOf may own one full instance per branch even in
        // validate(); iter_errors can additionally own one const/enum/not
        // payload for each failed application. Avoid both paths when either
        // product exceeds the retained-error allowance.
        let instance_heap = bytes.saturating_add(values.saturating_mul(64));
        let schema_heap = self.work.bytes.saturating_add(self.work.steps.saturating_mul(64));
        // A captured error makes jsonschema cache every active `$ref`
        // evaluation prefix. In a structural reference cycle, one full
        // reference chain can be active for each instance level, and each
        // cached prefix can contain every earlier schema-location suffix.
        let active_refs = max_value_depth.saturating_add(1).saturating_mul(self.work.max_ref_chain);
        let schema_path_bound = self.work.bytes.saturating_mul(2).saturating_add(self.work.steps.saturating_mul(8));
        if error_path_bytes.saturating_mul(self.work.steps.max(1)) > MAX_ERROR_BYTES
            || instance_heap.saturating_mul(self.work.steps.max(1)) > MAX_ERROR_BYTES
            || schema_heap.saturating_mul(values) > MAX_ERROR_BYTES
            || active_refs.saturating_mul(active_refs).saturating_mul(schema_path_bound) > MAX_ERROR_BYTES
        {
            CheckMode::Generic
        } else {
            CheckMode::Detailed
        }
    }
}

impl Work {
    fn add(&mut self, other: Self) {
        self.nodes = self.nodes.saturating_add(other.nodes);
        self.steps = self.steps.saturating_add(other.steps);
        self.bytes = self.bytes.saturating_add(other.bytes);
        self.pattern_pairs = self.pattern_pairs.saturating_add(other.pattern_pairs);
        self.pattern_name_work = self.pattern_name_work.saturating_add(other.pattern_name_work);
        self.pattern_uses = self.pattern_uses.saturating_add(other.pattern_uses);
        self.string_scans = self.string_scans.saturating_add(other.string_scans);
        self.regex_format_uses = self.regex_format_uses.saturating_add(other.regex_format_uses);
        self.name_lookups = self.name_lookups.saturating_add(other.name_lookups);
        self.name_bytes = self.name_bytes.saturating_add(other.name_bytes);
        self.unique_uses = self.unique_uses.saturating_add(other.unique_uses);
        self.required_names = self.required_names.saturating_add(other.required_names);
        self.required_name_bytes = self.required_name_bytes.saturating_add(other.required_name_bytes);
        self.property_maps = self.property_maps.saturating_add(other.property_maps);
        self.union |= other.union;
        self.max_ref_chain = self.max_ref_chain.max(other.max_ref_chain);
    }

    fn check(self) -> Result<(), String> {
        if self.nodes > MAX_EXPANDED_NODES {
            return Err(format!(
                "{TOO_LARGE}the schema expands to more than {MAX_EXPANDED_NODES} nodes through references or schema copies"
            ));
        }
        if self.steps > MAX_SCAN_STEPS {
            return Err(format!(
                "{TOO_LARGE}the schema expands to more than {MAX_SCAN_STEPS} members and items through references or schema copies"
            ));
        }
        if self.bytes > MAX_SCAN_BYTES {
            return Err(format!(
                "{TOO_LARGE}the schema expands to more than {} MiB of names and strings through references or schema copies",
                MAX_SCAN_BYTES >> 20
            ));
        }
        if self.pattern_pairs > MAX_PATTERN_PAIRS || self.pattern_name_work > MAX_PATTERN_NAME_WORK {
            return Err(format!("{TOO_LARGE}property-pattern precomputation exceeds its comparison budget"));
        }
        if self.union && self.required_names.saturating_mul(self.property_maps) > MAX_UNION_ANALYSIS {
            return Err(format!("{TOO_LARGE}union discriminator analysis exceeds {MAX_UNION_ANALYSIS} comparisons"));
        }
        if self.union && self.required_name_bytes.saturating_mul(self.property_maps) > MAX_UNION_NAME_WORK {
            return Err(format!("{TOO_LARGE}union discriminator analysis exceeds {MAX_UNION_NAME_WORK} bytes of name comparisons"));
        }
        Ok(())
    }
}

/// One schema (the root, or a `$ref` target): how many objects and lists
/// it has, and its internal references, each with whether it sits under a
/// keyword that descends into the value.
struct Part {
    nodes: usize,
    /// Members and items looked at, scalars included.
    steps: usize,
    /// Bytes of the member names and strings among them.
    bytes: usize,
    /// Cost including inline subschema copies retained by the validator.
    work: Work,
    /// Deepest nesting of objects and lists.
    depth: usize,
    /// Schema nesting as conversion follows it; literal data does not add
    /// conversion depth. Never silently truncate a checked constraint.
    schema_depth: usize,
    refs: Vec<(String, bool)>,
    /// Applicators whose work is not one structural traversal of the value.
    complex: bool,
}

/// Where a scanned value sits: a schema, a map of named schemas
/// (`properties`, `$defs`, …), or literal data (`const`, `enum`, …).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pos {
    Schema,
    Map,
    Literal,
}

/// Scan until more than `node_limit` objects and lists, more than
/// `step_limit` members and items (scalars included), or more than
/// `byte_limit` bytes of member names and strings have been seen.
fn scan(v: &Value, node_limit: usize, step_limit: usize, byte_limit: usize, schema_depth_limit: usize) -> Part {
    let mut part = Part {
        nodes: 0,
        steps: 0,
        bytes: text_bytes(v),
        work: Work { bytes: text_bytes(v), ..Work::default() },
        depth: 0,
        schema_depth: 0,
        refs: vec![],
        complex: false,
    };
    let mut stack: Vec<(&Value, bool, usize, Pos, usize, usize)> = vec![(v, false, 1, Pos::Schema, 0, 1)];
    'scan: while let Some((v, down, d, pos, schema_depth, copies)) = stack.pop() {
        if part.nodes > node_limit || part.steps > step_limit || part.bytes > byte_limit {
            break;
        }
        part.depth = part.depth.max(d);
        if pos == Pos::Schema && v.is_object() {
            part.schema_depth = part.schema_depth.max(schema_depth);
            if schema_depth > schema_depth_limit {
                break;
            }
        }
        match v {
            Value::Object(o) => {
                part.nodes += 1;
                part.work.nodes = part.work.nodes.saturating_add(copies);
                if pos == Pos::Schema {
                    let properties = o.get("properties").and_then(Value::as_object);
                    let patterns = o.get("patternProperties").and_then(Value::as_object);
                    if let Some(properties) = properties {
                        part.work.property_maps = part.work.property_maps.saturating_add(copies);
                        if let Some(patterns) = patterns {
                            part.work.pattern_pairs = part
                                .work
                                .pattern_pairs
                                .saturating_add(copies.saturating_mul(properties.len()).saturating_mul(patterns.len()));
                            let name_bytes = properties.keys().fold(0usize, |sum, name| sum.saturating_add(name.len().max(1)));
                            part.work.pattern_name_work = part
                                .work
                                .pattern_name_work
                                .saturating_add(copies.saturating_mul(name_bytes).saturating_mul(patterns.len()));
                        }
                    }
                    part.work.pattern_uses =
                        part.work
                            .pattern_uses
                            .saturating_add(copies.saturating_mul(
                                usize::from(o.get("pattern").is_some_and(Value::is_string)) + patterns.map_or(0, Map::len),
                            ));
                    part.work.string_scans = part.work.string_scans.saturating_add(
                        copies.saturating_mul(
                            ["minLength", "maxLength", "format", "contentEncoding", "contentMediaType"]
                                .into_iter()
                                .filter(|keyword| o.contains_key(*keyword))
                                .count()
                                .saturating_add(usize::from(o.contains_key("const")))
                                .saturating_add(o.get("enum").and_then(Value::as_array).map_or(0, Vec::len)),
                        ),
                    );
                    if o.get("format").and_then(Value::as_str) == Some("regex") {
                        part.work.regex_format_uses = part.work.regex_format_uses.saturating_add(copies);
                    }
                    // Required/property/dependency validators can hash or
                    // compare instance member names once per application.
                    // Charge long names for every reference-expanded use.
                    let dependent_lookups = |keyword: &str| {
                        o.get(keyword).and_then(Value::as_object).map_or(0, |entries| {
                            entries.len().saturating_add(
                                entries.values().map(|v| v.as_array().map_or(0, Vec::len)).fold(0usize, |sum, len| sum.saturating_add(len)),
                            )
                        })
                    };
                    let lookups = o
                        .get("required")
                        .and_then(Value::as_array)
                        .map_or(0, Vec::len)
                        .saturating_add(properties.map_or(0, Map::len))
                        .saturating_add(dependent_lookups("dependentRequired"))
                        .saturating_add(dependent_lookups("dependencies"))
                        .saturating_add(o.get("dependentSchemas").and_then(Value::as_object).map_or(0, Map::len))
                        .saturating_add(usize::from(o.contains_key("additionalProperties")))
                        .saturating_add(usize::from(o.contains_key("propertyNames")));
                    part.work.name_lookups = part.work.name_lookups.saturating_add(copies.saturating_mul(lookups));
                    // Some validators hash a schema-side name even when the
                    // instance has only short, unrelated member names.
                    let array_name_bytes = |value: Option<&Value>| {
                        value.and_then(Value::as_array).map_or(0, |names| {
                            names.iter().filter_map(Value::as_str).fold(0usize, |sum, name| sum.saturating_add(name.len().max(1)))
                        })
                    };
                    let dependent_name_bytes = |keyword: &str| {
                        o.get(keyword).and_then(Value::as_object).map_or(0, |entries| {
                            entries.iter().fold(0usize, |sum, (name, value)| {
                                sum.saturating_add(name.len().max(1)).saturating_add(array_name_bytes(Some(value)))
                            })
                        })
                    };
                    let required_name_bytes = array_name_bytes(o.get("required"));
                    let name_bytes = required_name_bytes
                        .saturating_add(
                            properties.map_or(0, |entries| entries.keys().fold(0usize, |sum, name| sum.saturating_add(name.len().max(1)))),
                        )
                        .saturating_add(dependent_name_bytes("dependentRequired"))
                        .saturating_add(dependent_name_bytes("dependencies"))
                        .saturating_add(
                            o.get("dependentSchemas")
                                .and_then(Value::as_object)
                                .map_or(0, |entries| entries.keys().fold(0usize, |sum, name| sum.saturating_add(name.len().max(1)))),
                        );
                    part.work.name_bytes = part.work.name_bytes.saturating_add(copies.saturating_mul(name_bytes));
                    part.work.required_name_bytes =
                        part.work.required_name_bytes.saturating_add(copies.saturating_mul(required_name_bytes));
                    part.work.required_names = part
                        .work
                        .required_names
                        .saturating_add(copies.saturating_mul(o.get("required").and_then(Value::as_array).map_or(0, Vec::len)));
                    part.work.union |= o.contains_key("anyOf") || o.contains_key("oneOf");
                    if o.get("uniqueItems") == Some(&Value::Bool(true)) {
                        part.work.unique_uses = part.work.unique_uses.saturating_add(copies);
                    }
                }
                if pos == Pos::Schema
                    && (o.keys().any(|k| complex_applicator(k))
                        || (o.contains_key("$ref")
                            && o.keys().any(|k| schema_child_keyword(k) || matches!(k.as_str(), "properties" | "additionalProperties"))))
                {
                    part.complex = true;
                }
                // Literal data is counted but holds no references; in a map
                // of named schemas, `$ref` is a name.
                if pos == Pos::Schema
                    && let Some(t) = o.get("$ref").and_then(Value::as_str).and_then(internal_pointer)
                {
                    part.refs.push((t, down));
                }
                for (k, child) in o {
                    part.steps += 1;
                    part.bytes += k.len() + text_bytes(child);
                    // NotValidator keeps a clone of its whole child schema,
                    // including literal data; nested nots retain overlapping
                    // copies. Unknown/literal `not` members are just data.
                    let child_copies = copies + usize::from(pos == Pos::Schema && k == "not");
                    part.work.steps = part.work.steps.saturating_add(copies);
                    part.work.bytes = part.work.bytes.saturating_add(copies * k.len() + child_copies * text_bytes(child));
                    if part.steps > step_limit || part.bytes > byte_limit {
                        break 'scan;
                    }
                    let child_pos = child_position(pos, k);
                    let child_depth = schema_depth + usize::from(child_pos == Pos::Schema && pos != Pos::Literal);
                    // A `$ref` that is not a string is still copied by
                    // conversion and bundling: scanned like any member.
                    if child.is_object() || child.is_array() {
                        stack.push((child, down || (pos == Pos::Schema && descends(k)), d + 1, child_pos, child_depth, child_copies));
                    }
                }
            }
            Value::Array(a) => {
                part.nodes += 1;
                part.work.nodes = part.work.nodes.saturating_add(copies);
                for child in a {
                    part.steps += 1;
                    part.bytes += text_bytes(child);
                    part.work.steps = part.work.steps.saturating_add(copies);
                    part.work.bytes = part.work.bytes.saturating_add(copies * text_bytes(child));
                    if part.steps > step_limit || part.bytes > byte_limit {
                        break 'scan;
                    }
                    if child.is_object() || child.is_array() {
                        stack.push((child, down, d + 1, pos, schema_depth, copies));
                    }
                }
            }
            _ => {}
        }
    }
    part
}

/// The bytes of `v` if it is a string (its members are counted where they
/// are scanned).
fn text_bytes(v: &Value) -> usize {
    v.as_str().map_or(0, str::len)
}

const ROOT: &str = "#root";

/// Check a schema before it is compiled: refuse a reference cycle that
/// does not descend into the value (validation would never end), and a
/// schema that expands to more than [`MAX_EXPANDED_NODES`] nodes with every
/// `$ref` expanded (repeated references count each time). Both passes are
/// iterative, so neither nesting nor reference chains use the call stack.
/// [`measure`], adding the members and items it looked at, and the bytes of
/// their names and strings, to `total`.
fn measure_counted(spec: &Spec, schema: &Value, total: &mut Scanned) -> Result<usize, String> {
    let size = measure_in(&spec.root, schema, total, MAX_DEPTH)?;
    check_keywords(&spec.root, schema, false, legacy(spec.dialect))?;
    Ok(size.nodes)
}

/// Check a standalone JSON Schema (a custom ruleset's `schema` function)
/// before it is compiled, with the same limits as an OpenAPI schema: its
/// references resolve within the schema itself. Only plain `#`/`#/…`
/// references are accepted, and nothing may change how they resolve: no
/// `$id` or `$schema` below the root, a root `$schema` only for draft
/// 2020-12, and no `$anchor`, `$dynamicRef` or `$recursiveRef`. Every
/// reference the validator follows is then one the measurement counts.
///
/// Keywords are read only where a schema is: literal data (`const`, `enum`,
/// `default`, `examples`) is not interpreted, unless a reference points into
/// it (the validator then compiles it as a schema too).
pub fn measure_standalone(schema: &Value) -> Result<usize, String> {
    measure_standalone_plan(schema).map(|plan| plan.work.nodes)
}

pub fn measure_standalone_plan(schema: &Value) -> Result<ValidationPlan, String> {
    let mut work = measure_in(schema, schema, &mut Scanned::default(), MAX_DEPTH)?;
    check_keywords(schema, schema, true, false)?;
    let risk = check_compile_work(schema, work, true)?;
    // Custom rules use the draft's format-annotation default, unlike the
    // OpenAPI checks that explicitly assert formats.
    work.regex_format_uses = 0;
    Ok(ValidationPlan {
        work,
        unique_uses: work.unique_uses.max(usize::from(risk.unique)),
        text_scans: work.pattern_uses.saturating_add(work.string_scans).saturating_add(work.name_lookups),
    })
}

/// Only schema-valued keywords change position. Assertions, annotations and
/// unknown extensions hold data, unless a reference explicitly targets it.
fn child_position(pos: Pos, k: &str) -> Pos {
    match pos {
        Pos::Literal => Pos::Literal,
        Pos::Map => Pos::Schema,
        Pos::Schema if schema_map_keyword(k) => Pos::Map,
        Pos::Schema if schema_child_keyword(k) => Pos::Schema,
        Pos::Schema => Pos::Literal,
    }
}

fn schema_child_keyword(k: &str) -> bool {
    matches!(
        k,
        "allOf"
            | "anyOf"
            | "oneOf"
            | "not"
            | "if"
            | "then"
            | "else"
            | "items"
            | "prefixItems"
            | "additionalItems"
            | "additionalProperties"
            | "contains"
            | "propertyNames"
            | "unevaluatedProperties"
            | "unevaluatedItems"
            | "contentSchema"
    )
}

fn complex_applicator(k: &str) -> bool {
    matches!(
        k,
        "allOf"
            | "anyOf"
            | "oneOf"
            | "not"
            | "if"
            | "then"
            | "else"
            | "dependentSchemas"
            | "dependencies"
            | "contains"
            | "propertyNames"
            | "patternProperties"
            | "contentSchema"
            | "unevaluatedProperties"
            | "unevaluatedItems"
    )
}

/// Keywords whose value maps names to schemas.
fn schema_map_keyword(k: &str) -> bool {
    matches!(k, "properties" | "patternProperties" | "$defs" | "definitions" | "dependentSchemas" | "dependencies")
}

/// A copied pointer target at one of these document-root names would become
/// an assertion on the wrapper, even if it was inert OpenAPI data before.
fn root_assertion_keyword(k: &str) -> bool {
    schema_child_keyword(k)
        || matches!(
            k,
            "$ref"
                | "properties"
                | "patternProperties"
                | "dependentSchemas"
                | "dependencies"
                | "type"
                | "const"
                | "enum"
                | "required"
                | "dependentRequired"
                | "minimum"
                | "maximum"
                | "exclusiveMinimum"
                | "exclusiveMaximum"
                | "multipleOf"
                | "minLength"
                | "maxLength"
                | "pattern"
                | "format"
                | "minItems"
                | "maxItems"
                | "uniqueItems"
                | "minContains"
                | "maxContains"
                | "minProperties"
                | "maxProperties"
                | "contentEncoding"
                | "contentMediaType"
        )
}

/// Bound work the jsonschema compiler does in addition to walking nodes.
/// Only schema positions are visited; a `const` object is data, while a
/// referenced target in otherwise literal data is promoted to a schema.
struct CompileRisk {
    unique: bool,
}

fn check_compile_work(root: &Value, work: Work, standalone: bool) -> Result<CompileRisk, String> {
    let uri_len = if standalone { root.get("$id").and_then(Value::as_str).map_or(0, str::len) } else { 0 };
    if uri_len > crate::spec::MAX_KEY_BYTES {
        return Err(format!("{TOO_LARGE}the schema's root URI exceeds the compiler location limit"));
    }
    let mut locations = 0usize;
    let mut pattern_pairs = 0usize;
    let mut pattern_name_work = 0usize;
    let mut required_names = 0usize;
    let mut required_name_bytes = 0usize;
    let mut property_maps = 0usize;
    let mut has_union = false;
    let mut unique = false;
    let mut deepest_dependency = 0usize;
    let mut patterns: HashSet<String> = HashSet::new();
    let mut followed: HashSet<String> = HashSet::new();
    let mut stack = vec![(root, Pos::Schema, 0usize, 0usize, false)];
    while let Some((value, pos, path, dependency_depth, dependency_map)) = stack.pop() {
        if pos == Pos::Literal {
            continue;
        }
        if pos == Pos::Schema {
            locations = locations.saturating_add(2usize.saturating_mul(path.saturating_add(uri_len).saturating_mul(3).saturating_add(64)));
        }
        if locations > MAX_COMPILE_LOCATIONS {
            return Err(format!("{TOO_LARGE}compiled schema locations exceed {} MiB", MAX_COMPILE_LOCATIONS >> 20));
        }
        match value {
            Value::Object(map) => {
                if pos == Pos::Schema {
                    let properties = map.get("properties").and_then(Value::as_object);
                    let pattern_properties = map.get("patternProperties").and_then(Value::as_object);
                    // Metaschema validation checks array uniqueness before
                    // item types for these keywords. Numeric members can
                    // collide through f64 hashing, making a malformed
                    // string array quadratic before keyword compilation.
                    for keyword in ["required", "type"] {
                        if let Some(Value::Array(names)) = map.get(keyword)
                            && names.iter().any(|name| !name.is_string())
                        {
                            return Err(format!("`{keyword}` arrays must contain only strings"));
                        }
                    }
                    if let Some(Value::Object(entries)) = map.get("dependencies") {
                        for value in entries.values() {
                            if let Value::Array(names) = value
                                && names.iter().any(|name| !name.is_string())
                            {
                                return Err("`dependencies` arrays must contain only strings".into());
                            }
                        }
                    }
                    if let Some(dependencies) = map.get("dependentRequired") {
                        let Some(entries) = dependencies.as_object() else {
                            return Err("`dependentRequired` must be an object of string arrays".into());
                        };
                        for names in entries.values() {
                            let Some(names) = names.as_array() else {
                                return Err("`dependentRequired` must be an object of string arrays".into());
                            };
                            if names.iter().any(|name| !name.is_string()) {
                                return Err("`dependentRequired` must be an object of string arrays".into());
                            }
                        }
                    }
                    if let Some(properties) = properties {
                        property_maps = property_maps.saturating_add(1);
                        if let Some(pattern_properties) = pattern_properties {
                            pattern_pairs = pattern_pairs.saturating_add(properties.len().saturating_mul(pattern_properties.len()));
                            let names = properties.keys().fold(0usize, |sum, name| sum.saturating_add(name.len().max(1)));
                            pattern_name_work = pattern_name_work.saturating_add(names.saturating_mul(pattern_properties.len()));
                        }
                    }
                    if let Some(Value::Array(names)) = map.get("required") {
                        required_names = required_names.saturating_add(names.len());
                        required_name_bytes = required_name_bytes.saturating_add(
                            names.iter().filter_map(Value::as_str).fold(0usize, |sum, name| sum.saturating_add(name.len().max(1))),
                        );
                    }
                    has_union |= map.contains_key("anyOf") || map.contains_key("oneOf");
                    unique |= map.get("uniqueItems") == Some(&Value::Bool(true));
                    if let Some(pattern) = map.get("pattern").and_then(Value::as_str) {
                        patterns.insert(pattern.to_owned());
                    }
                    if let Some(property_patterns) = pattern_properties {
                        patterns.extend(property_patterns.keys().cloned());
                    }
                    if let Some(reference) = map.get("$ref").and_then(Value::as_str).and_then(internal_pointer)
                        && followed.insert(reference.clone())
                        && let Some(target) = root.pointer(&reference)
                    {
                        stack.push((target, Pos::Schema, reference.len(), dependency_depth, false));
                    }
                }
                for (name, child) in map {
                    if name.len() > crate::spec::MAX_KEY_BYTES {
                        return Err(format!("{TOO_LARGE}a schema member name exceeds {} bytes", crate::spec::MAX_KEY_BYTES));
                    }
                    let next = child_position(pos, name);
                    if next == Pos::Literal {
                        continue;
                    }
                    let escaped = name.len().saturating_add(name.bytes().filter(|b| *b == b'~' || *b == b'/').count());
                    let child_path = path.saturating_add(escaped.saturating_add(1));
                    if pos == Pos::Schema {
                        locations = locations.saturating_add(child_path.saturating_add(uri_len).saturating_mul(3).saturating_add(64));
                    }
                    // Only children of a legacy `dependencies` map add a
                    // metaschema copy layer, not ordinary properties/$defs.
                    let child_dependency_depth = dependency_depth.saturating_add(usize::from(pos == Pos::Map && dependency_map));
                    stack.push((child, next, child_path, child_dependency_depth, pos == Pos::Schema && name == "dependencies"));
                }
            }
            Value::Array(items) => {
                for (index, child) in items.iter().enumerate() {
                    stack.push((child, pos, path.saturating_add(1 + index.to_string().len()), dependency_depth, false));
                }
            }
            _ => {}
        }
        deepest_dependency = deepest_dependency.max(dependency_depth);
        if locations > MAX_COMPILE_LOCATIONS
            || pattern_pairs > MAX_PATTERN_PAIRS
            || pattern_name_work > MAX_PATTERN_NAME_WORK
            || patterns.len() > MAX_DISTINCT_PATTERNS
        {
            return Err(format!("{TOO_LARGE}schema compiler locations, property-pattern comparisons or regexes exceed their limits"));
        }
    }
    if has_union && required_names.saturating_mul(property_maps) > MAX_UNION_ANALYSIS {
        return Err(format!("{TOO_LARGE}union discriminator analysis exceeds {MAX_UNION_ANALYSIS} comparisons"));
    }
    if has_union && required_name_bytes.saturating_mul(property_maps) > MAX_UNION_NAME_WORK {
        return Err(format!("{TOO_LARGE}union discriminator analysis exceeds {MAX_UNION_NAME_WORK} bytes of name comparisons"));
    }
    if deepest_dependency.saturating_mul(work.bytes.saturating_add(work.steps.saturating_mul(64))) > MAX_DEPENDENCY_COPY_BYTES {
        return Err(format!("{TOO_LARGE}legacy dependency validation may copy too much schema data"));
    }
    Ok(CompileRisk { unique })
}

fn is_draft_202012(dialect: &str) -> bool {
    matches!(dialect.trim_end_matches('#'), "https://json-schema.org/draft/2020-12/schema" | "http://json-schema.org/draft/2020-12/schema")
}

fn check_keywords(root_doc: &Value, schema: &Value, root_id: bool, legacy_ids: bool) -> Result<(), String> {
    let mut stack: Vec<(&Value, bool, Pos)> = vec![(schema, true, Pos::Schema)];
    let mut followed: HashSet<String> = HashSet::new();
    // A reference target is walked again from its own position, so the walk
    // is bounded like the measurement's scan.
    let mut steps = 0usize;
    while let Some((v, root, pos)) = stack.pop() {
        if pos == Pos::Literal {
            continue;
        }
        if let Value::Array(a) = v {
            steps += a.len();
            if steps > MAX_SCAN_STEPS {
                return Err(format!("{TOO_LARGE}the schema keyword scan exceeds {MAX_SCAN_STEPS} members and items"));
            }
            stack.extend(a.iter().filter(|c| c.is_object() || c.is_array()).map(|c| (c, false, pos)));
            continue;
        }
        let Value::Object(o) = v else { continue };
        for (k, child) in o {
            steps += 1;
            if steps > MAX_SCAN_STEPS {
                return Err(format!(
                    "{TOO_LARGE}the schema and the schemas it references have more than {MAX_SCAN_STEPS} members and items"
                ));
            }
            if pos != Pos::Schema {
                stack.push((child, false, child_position(pos, k)));
                continue;
            }
            match k.as_str() {
                "$ref" if child.is_string() => match internal_pointer(child.as_str().unwrap_or_default()) {
                    // The target is compiled as a schema wherever it is.
                    Some(p) => {
                        let root_name = p.split('/').nth(1).map(unescape);
                        if !root_id
                            && (p.is_empty()
                                || root_name.as_deref() == Some("$schema")
                                || root_name.as_deref().is_some_and(root_assertion_keyword))
                        {
                            return Err(
                                "references to the OpenAPI bundle root or a validation keyword at that root are not supported".into()
                            );
                        }
                        if followed.insert(p.clone())
                            && let Some(t) = root_doc.pointer(&p)
                        {
                            stack.push((t, root_id && p.is_empty(), Pos::Schema));
                        }
                    }
                    None => return Err("only references within the schema (`#/…`) are supported".into()),
                },
                "$id" if !legacy_ids && !(root_id && root) => return Err("`$id` is only supported at a standalone schema's root".into()),
                "$schema" if child.is_string() => {
                    if !root || !is_draft_202012(child.as_str().unwrap_or_default()) {
                        return Err("`$schema` is only supported at the root of the schema, for draft 2020-12".into());
                    }
                }
                "$anchor" | "$dynamicAnchor" | "$dynamicRef" | "$recursiveRef" | "$recursiveAnchor" => {
                    return Err(format!("`{k}` is not supported; use a `#/…` reference"));
                }
                "unevaluatedProperties" | "unevaluatedItems" => {
                    return Err(format!("{TOO_LARGE}`{k}` can re-evaluate schemas and cannot be checked within the work bound"));
                }
                _ => {}
            }
            stack.push((child, false, child_position(pos, k)));
        }
    }
    Ok(())
}

/// [`measure_counted`] with references resolved in `root`.
fn measure_in(root_doc: &Value, schema: &Value, total: &mut Scanned, schema_depth_limit: usize) -> Result<Work, String> {
    let too_big = || format!("{TOO_LARGE}the schema expands to more than {MAX_EXPANDED_NODES} nodes through its references");
    let too_wide = || format!("{TOO_LARGE}the schema and the schemas it references have more than {MAX_SCAN_STEPS} members and items");
    let mib = MAX_SCAN_BYTES >> 20;
    let too_long = || format!("{TOO_LARGE}the schema and the schemas it references have more than {mib} MiB of names and strings");
    let too_nested = || format!("{TOO_LARGE}the schema nests subschemas more than {schema_depth_limit} levels");
    // Every reached schema counts at least once in the expanded size, so
    // scanning stops as soon as the schemas scanned so far exceed the limit
    // (targets nested in one another are scanned once each, not more), or
    // their members and items (scalars too: a huge `enum`) or the bytes of
    // their names and strings (a huge `description`) exceed theirs.
    let root = scan(schema, MAX_EXPANDED_NODES, MAX_SCAN_STEPS, MAX_SCAN_BYTES, schema_depth_limit);
    let mut scanned = root.nodes;
    total.steps += root.steps;
    total.bytes += root.bytes;
    if scanned > MAX_EXPANDED_NODES {
        return Err(too_big());
    }
    if root.steps > MAX_SCAN_STEPS {
        return Err(too_wide());
    }
    if root.bytes > MAX_SCAN_BYTES {
        return Err(too_long());
    }
    if root.schema_depth > schema_depth_limit {
        return Err(too_nested());
    }
    let mut stepped = root.steps;
    let mut bytes = root.bytes;
    let mut parts: HashMap<String, Part> = HashMap::from([(ROOT.to_string(), root)]);
    let mut part_of = |parts: &mut HashMap<String, Part>, key: &str| -> Result<(), String> {
        if parts.contains_key(key) {
            return Ok(());
        }
        if parts.len() >= MAX_REF_TARGETS {
            return Err(format!("{TOO_LARGE}the schema reaches more than {MAX_REF_TARGETS} referenced schemas"));
        }
        match root_doc.pointer(key) {
            Some(v) => {
                let part = scan(v, MAX_EXPANDED_NODES - scanned, MAX_SCAN_STEPS - stepped, MAX_SCAN_BYTES - bytes, schema_depth_limit);
                scanned += part.nodes;
                stepped += part.steps;
                bytes += part.bytes;
                total.steps += part.steps;
                total.bytes += part.bytes;
                if scanned > MAX_EXPANDED_NODES {
                    return Err(too_big());
                }
                if stepped > MAX_SCAN_STEPS {
                    return Err(too_wide());
                }
                if bytes > MAX_SCAN_BYTES {
                    return Err(too_long());
                }
                if part.schema_depth > schema_depth_limit {
                    return Err(too_nested());
                }
                parts.insert(key.to_string(), part);
                Ok(())
            }
            // The validator's resolver accepts some array-index spellings
            // that serde_json::Value::pointer does not. An unmeasured target
            // must never reach validator construction, even if that resolver
            // could follow it at validation time.
            None => Err(format!("unresolved reference #{key}")),
        }
    };

    // 1. Every schema the root reaches, over all references.
    let mut queue: Vec<String> = vec![ROOT.to_string()];
    let mut reached: Vec<String> = vec![ROOT.to_string()];
    let mut queued: HashSet<String> = HashSet::from([ROOT.to_string()]);
    while let Some(key) = queue.pop() {
        let targets: Vec<String> = parts[key.as_str()].refs.iter().map(|(t, _)| t.clone()).collect();
        for t in targets {
            if queued.insert(t.clone()) {
                part_of(&mut parts, &t)?;
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

    measure_parts(&parts, &reached)
}

/// Iterative strongly connected components over all reference occurrences.
/// A cyclic part must have exactly one outgoing reference and only ordinary
/// structural applicators. This deliberately refuses some legitimate trees:
/// the validator's eager error collection has no runtime work budget, and a
/// second route (even through aliases or another recursive component) can
/// multiply work on the same nested value. Duplicate references count twice.
/// The condensed graph bounds longest depth and reference-expanded nodes,
/// members/items and text bytes, then returns the expanded node count.
fn measure_parts(parts: &HashMap<String, Part>, reached: &[String]) -> Result<Work, String> {
    let ids: HashMap<&str, usize> = reached.iter().enumerate().map(|(i, key)| (key.as_str(), i)).collect();
    let edges: Vec<Vec<usize>> = reached
        .iter()
        .map(|key| parts[key.as_str()].refs.iter().filter_map(|(target, _)| ids.get(target.as_str()).copied()).collect())
        .collect();
    let mut reverse = vec![vec![]; reached.len()];
    for (from, targets) in edges.iter().enumerate() {
        for &to in targets {
            reverse[to].push(from);
        }
    }
    let mut seen = vec![false; reached.len()];
    let mut finish = Vec::with_capacity(reached.len());
    for start in 0..reached.len() {
        if seen[start] {
            continue;
        }
        seen[start] = true;
        let mut stack = vec![(start, 0)];
        while let Some((node, next)) = stack.last_mut() {
            if let Some(&target) = edges[*node].get(*next) {
                *next += 1;
                if !seen[target] {
                    seen[target] = true;
                    stack.push((target, 0));
                }
            } else {
                finish.push(*node);
                stack.pop();
            }
        }
    }
    seen.fill(false);
    let mut component_of = vec![0; reached.len()];
    let mut components = vec![];
    while let Some(start) = finish.pop() {
        if seen[start] {
            continue;
        }
        let mut component = vec![];
        let mut stack = vec![start];
        seen[start] = true;
        while let Some(node) = stack.pop() {
            component.push(node);
            for &target in &reverse[node] {
                if !seen[target] {
                    seen[target] = true;
                    stack.push(target);
                }
            }
        }
        let cyclic = component.len() > 1 || edges[start].contains(&start);
        if cyclic
            && component.iter().any(|&node| {
                let part = &parts[reached[node].as_str()];
                part.refs.len() != 1 || part.complex
            })
        {
            return Err(format!("{TOO_LARGE}recursive schemas with branching or non-structural applicators are not checked"));
        }
        for &node in &component {
            component_of[node] = components.len();
        }
        components.push(component);
    }
    // Size memoization alone cannot enforce depth: a target first reached
    // by a short route may later complete a longer route from the cache.
    // Condense cycles, then measure the longest path in the resulting DAG.
    // Accepted cyclic components are simple terminal cycles; charge one
    // full lap, stopping before a repeated member, whichever entry is used.
    let weights: Vec<(usize, usize)> =
        components.iter().map(|nodes| (nodes.len(), nodes.iter().map(|&node| parts[reached[node].as_str()].depth).sum())).collect();
    let mut longest = weights.clone();
    // Error collection can clone subschema data for every application.
    // Count expanded text and scalar members too, not only containers.
    // A complete lap gives every entry to a permitted cycle the same cost.
    let mut work: Vec<Work> = components
        .iter()
        .map(|nodes| {
            nodes.iter().fold(Work::default(), |mut work, &node| {
                work.add(parts[reached[node].as_str()].work);
                work
            })
        })
        .collect();
    for cost in &work {
        cost.check()?;
    }
    let mut parents = vec![vec![]; components.len()];
    let mut remaining = vec![0; components.len()];
    for (from, targets) in edges.iter().enumerate() {
        for &to in targets {
            let (parent, child) = (component_of[from], component_of[to]);
            if parent != child {
                parents[child].push(parent);
                remaining[parent] += 1;
            }
        }
    }
    let mut ready: Vec<usize> = remaining.iter().enumerate().filter_map(|(i, &count)| (count == 0).then_some(i)).collect();
    while let Some(child) = ready.pop() {
        for &parent in &parents[child] {
            let child_work = work[child];
            work[parent].add(child_work);
            work[parent].check()?;
            longest[parent].0 = longest[parent].0.max(weights[parent].0.saturating_add(longest[child].0));
            longest[parent].1 = longest[parent].1.max(weights[parent].1.saturating_add(longest[child].1));
            remaining[parent] -= 1;
            if remaining[parent] == 0 {
                ready.push(parent);
            }
        }
    }
    let (references, depth) = longest[component_of[0]];
    if references > MAX_REF_CHAIN || depth > MAX_CHAIN_DEPTH {
        return Err(format!("{TOO_LARGE}the schema nests references too deeply"));
    }
    let mut result = work[component_of[0]];
    if reached.iter().any(|key| !parts[key.as_str()].refs.is_empty()) {
        result.max_ref_chain = references;
    }
    Ok(result)
}

fn collect_refs(v: &Value, out: &mut Vec<String>) -> Result<(), String> {
    let mut stack = vec![(v, Pos::Schema)];
    while let Some((v, pos)) = stack.pop() {
        if pos == Pos::Literal {
            continue;
        }
        match v {
            Value::Object(o) => {
                if pos == Pos::Schema
                    && let Some(r) = o.get("$ref").and_then(Value::as_str)
                {
                    match internal_pointer(r) {
                        Some(p) => out.push(p),
                        None => return Err(format!("external reference '{r}' is not resolved")),
                    }
                }
                stack.extend(o.iter().map(|(k, v)| (v, child_position(pos, k))));
            }
            Value::Array(a) => stack.extend(a.iter().map(|v| (v, pos))),
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

/// The `readOnly` or `writeOnly` flag of each `$ref` target read so far,
/// by [`crate::spec::RefTarget::id`] (`None`: the target is missing): a
/// bundle reads each target once, however many required properties lead
/// there.
type Flags = HashMap<usize, Option<bool>>;

/// Convert one schema (not following `$ref`s) for `direction`.
pub fn convert(spec: &Spec, schema: &Value, direction: Direction, depth: usize) -> Value {
    convert_in(spec, schema, direction, depth, &mut Flags::new())
}

/// [`convert`], reading the flags of `$ref` targets through `flags`.
fn convert_in(spec: &Spec, schema: &Value, direction: Direction, depth: usize, flags: &mut Flags) -> Value {
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
            "properties" | "patternProperties" | "$defs" | "definitions" | "dependentSchemas" | "dependencies" => match v {
                Value::Object(m) => {
                    Value::Object(m.iter().map(|(n, s)| (n.clone(), convert_in(spec, s, direction, depth + 1, flags))).collect())
                }
                other => other.clone(),
            },
            "items"
            | "additionalProperties"
            | "not"
            | "contains"
            | "contentSchema"
            | "if"
            | "then"
            | "else"
            | "propertyNames"
            | "unevaluatedProperties"
            | "unevaluatedItems"
            | "additionalItems" => match v {
                Value::Array(a) => Value::Array(a.iter().map(|s| convert_in(spec, s, direction, depth + 1, flags)).collect()),
                s => convert_in(spec, s, direction, depth + 1, flags),
            },
            "allOf" | "anyOf" | "oneOf" | "prefixItems" => match v {
                Value::Array(a) => Value::Array(a.iter().map(|s| convert_in(spec, s, direction, depth + 1, flags)).collect()),
                other => other.clone(),
            },
            "required" => match v {
                Value::Array(names) => {
                    // Each name is looked up once, however often it is listed.
                    let mut dropped: HashMap<&str, bool> = HashMap::new();
                    let mut kept = vec![];
                    for n in names {
                        if let Some(name) = n.as_str()
                            && *dropped.entry(name).or_insert_with(|| excluded(spec, src, name, direction, flags))
                        {
                            continue;
                        }
                        kept.push(n.clone());
                    }
                    Value::Array(kept)
                }
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

/// Whether required property `name` of `parent` does not apply in
/// `direction`. A referenced property's target is read once (`flags`).
fn excluded(spec: &Spec, parent: &Map<String, Value>, name: &str, direction: Direction, flags: &mut Flags) -> bool {
    let Some(prop) = parent.get("properties").and_then(|p| p.get(name)) else { return false };
    let flag = match direction {
        Direction::Request => "readOnly",
        Direction::Response => "writeOnly",
    };
    let read = |v: &Value| v.get(flag).and_then(Value::as_bool).unwrap_or(false);
    match spec.reach(prop, "") {
        Reach::Inline(v) => read(v),
        Reach::Target(t) => {
            let found = *flags.entry(t.id).or_insert_with(|| spec.target_value(&t).map(read));
            // A missing target leaves the reference itself, as `Spec::deref`.
            found.unwrap_or_else(|| read(prop))
        }
        Reach::Unresolved => read(prop),
    }
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
    fn nested_targets_are_not_rescanned() {
        // /x, /x/a, /x/a/a … each referenced, over a large subtree of objects,
        // then over a huge `enum` of scalars.
        // (The deep version of the enum case is refused by the spec's pointer
        // budget already; ten levels fit in it.)
        for (leaf, depth) in [
            (
                {
                    let wide: serde_json::Map<String, Value> = (0..60_000).map(|i| (format!("k{i}"), json!({"type": "string"}))).collect();
                    json!({"type": "object", "properties": wide})
                },
                100,
            ),
            (json!({"type": "integer", "enum": (0..1_200_000).collect::<Vec<u32>>()}), 10),
        ] {
            let mut v = leaf;
            for _ in 0..depth {
                v = json!({"a": v});
            }
            let refs: Vec<Value> = (0..depth).map(|d| json!({"$ref": format!("#/x{}", "/a".repeat(d))})).collect();
            let doc = json!({"openapi": "3.1.0", "info": {"title": "t", "version": "1"}, "paths": {}, "x": v});
            let s = spec(&doc.to_string());
            let mut scanned = Scanned::default();
            let e = measure_counted(&s, &json!({"anyOf": refs}), &mut scanned).unwrap_err();
            assert!(e.contains("more than"), "{e}");
            // Bounded by the limits, not by `depth` × the subtree.
            assert!(scanned.steps <= MAX_SCAN_STEPS + depth, "{scanned:?}");
        }
        // A large legitimate enum is fine.
        let s = spec(&json!({"openapi": "3.1.0", "info": {"title": "t", "version": "1"}, "paths": {}}).to_string());
        assert!(compile(&s, &json!({"enum": (0..200_000).collect::<Vec<u32>>()}), Direction::Response).is_ok());
    }

    #[test]
    fn text_is_charged_however_few_members_hold_it() {
        // Two members, one a description past the limit: few members, but
        // every compile would copy it.
        let s = spec(&json!({"openapi": "3.1.0", "info": {"title": "t", "version": "1"}, "paths": {}}).to_string());
        let long = json!({"type": "string", "description": "d".repeat(MAX_SCAN_BYTES)});
        let mut scanned = Scanned::default();
        let e = compile_within(&s, &long, Direction::Response, &mut scanned, Scanned::UNLIMITED).unwrap_err();
        assert!(e.contains("MiB of names and strings"), "{e}");
        assert!(scanned.steps <= 2, "{scanned:?}");
        assert!(scanned.bytes > MAX_SCAN_BYTES, "{scanned:?}");
        // The same through a reference.
        let doc = json!({"openapi": "3.1.0", "info": {"title": "t", "version": "1"}, "paths": {}, "x": long});
        let s = spec(&doc.to_string());
        let e = compile(&s, &json!({"$ref": "#/x"}), Direction::Response).unwrap_err();
        assert!(e.contains("MiB of names and strings"), "{e}");
        // A shared budget is spent by bytes too.
        let short = json!({"type": "string", "description": "d".repeat(1_000)});
        let mut scanned = Scanned::default();
        let budget = Scanned { steps: usize::MAX, bytes: 5_000 };
        assert!(compile_within(&s, &short, Direction::Response, &mut scanned, budget).is_ok());
        assert!(compile_within(&s, &short, Direction::Response, &mut scanned, budget).is_ok());
        let e = compile_within(&s, &short, Direction::Response, &mut scanned, budget).unwrap_err();
        assert!(e.contains("budget is spent"), "{e}");
        assert!(scanned.bytes > budget.bytes, "{scanned:?}");
    }

    #[test]
    fn a_reference_that_is_not_a_string_is_charged_for_its_text() {
        // Conversion and bundling copy a `$ref` whatever it holds: an object
        // of text there is scanned like any other member.
        let s = spec(&json!({"openapi": "3.1.0", "info": {"title": "t", "version": "1"}, "paths": {}}).to_string());
        let e = compile(&s, &json!({"$ref": {"d": "d".repeat(MAX_SCAN_BYTES)}}), Direction::Response).unwrap_err();
        assert!(e.contains("MiB of names and strings"), "{e}");
        assert!(too_large(&e), "{e}");
        // A component holding 1 MiB of it, reached by many schemas: each
        // compile is charged for both the input and completed bundle, so a
        // shared budget of 10 MiB is spent before ten compiles.
        let big = json!({"type": "string", "$ref": {"blob": "x".repeat(1 << 20)}});
        let doc = json!({"openapi": "3.1.0", "info": {"title": "t", "version": "1"}, "paths": {}, "components": {"schemas": {"Big": big}}});
        let s = spec(&doc.to_string());
        let schema = json!({"allOf": [{"$ref": "#/components/schemas/Big"}]});
        let mut scanned = Scanned::default();
        let budget = Scanned { steps: usize::MAX, bytes: 10 << 20 };
        let mut refused = None;
        for i in 0..100 {
            if compile_within(&s, &schema, Direction::Response, &mut scanned, budget).is_err_and(|e| e.contains("budget is spent")) {
                refused = Some(i);
                break;
            }
        }
        assert!(refused.is_some_and(|i| i > 0 && i < 10), "{scanned:?}");
        assert!(scanned.bytes > 10 << 20, "{scanned:?}");
    }

    #[test]
    fn refusals_for_size_are_told_apart() {
        let s = spec(&json!({"openapi": "3.1.0", "info": {"title": "t", "version": "1"}, "paths": {}}).to_string());
        let e = compile(&s, &json!({"enum": (0..1_200_000).collect::<Vec<u32>>()}), Direction::Response).unwrap_err();
        assert!(too_large(&e), "{e}");
        for schema in [json!({"$ref": "#/nowhere"}), json!({"$ref": "https://example.com/s.json"})] {
            let e = compile(&s, &schema, Direction::Response).unwrap_err();
            assert!(!too_large(&e), "{e}");
        }
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

    #[test]
    fn a_bundle_reads_each_referenced_target_once() {
        // 1,000 required properties, each a reference to one alias of a
        // write-only schema at a pointer of about 200 KB.
        let key = "k".repeat(4_000);
        let mut target = json!({"type": "string", "writeOnly": true});
        for _ in 0..50 {
            let mut level = Map::new();
            level.insert(key.clone(), target);
            target = Value::Object(level);
        }
        let deep = format!("#/x{}", format!("/{key}").repeat(50));
        let names: Vec<String> = (0..1_000).map(|i| format!("n{i}")).collect();
        let properties: Map<String, Value> = names.iter().map(|n| (n.clone(), json!({"$ref": "#/p"}))).collect();
        let doc = json!({"openapi": "3.1.0", "info": {"title": "t", "version": "1"}, "paths": {}, "x": target, "p": {"$ref": deep}});
        let s = spec(&doc.to_string());
        let schema = json!({"type": "object", "required": names, "properties": properties});
        let walks = || s.walks.load(std::sync::atomic::Ordering::Relaxed);
        // The first bundle also follows the chain, once for the document.
        bundle(&s, &schema, Direction::Response).unwrap();
        let before = walks();
        let response = bundle(&s, &schema, Direction::Response).unwrap();
        assert_eq!(walks() - before, 1);
        assert_eq!(response["allOf"][0]["required"], json!([]), "write-only in a response");
        let before = walks();
        let request = bundle(&s, &schema, Direction::Request).unwrap();
        assert_eq!(walks() - before, 1);
        assert_eq!(request["allOf"][0]["required"].as_array().map(Vec::len), Some(1_000));
    }
}
