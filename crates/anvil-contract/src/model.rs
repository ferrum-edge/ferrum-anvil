//! A version-neutral view of an OpenAPI description.
//!
//! Swagger 2.0 and OpenAPI 3.0/3.1/3.2 describe the same things in
//! different shapes (`host`/`basePath` vs `servers`, `in: body` vs
//! `requestBody`, `produces` vs `content`, `definitions` vs
//! `components/schemas`). Rules are written against *targets* (operation,
//! parameter, response, schema, …) whose fields are the same in every
//! dialect, so one company standard applies to every version. Each target
//! keeps the JSON Pointer of the object it came from (after `$ref`
//! resolution, so a finding points where the fix belongs), and `raw.*`
//! fields reach the original object for dialect-specific rules.

use crate::locate::ptr;
use crate::spec::{Spec, internal_pointer};
use anvil_import::Dialect;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::rc::Rc;

/// What a rule applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TargetKind {
    Document,
    Info,
    Server,
    Tag,
    Path,
    Operation,
    Parameter,
    RequestBody,
    Response,
    Header,
    MediaType,
    Schema,
    Property,
    SecurityScheme,
    /// A node selected by a rule's JSONPath.
    Node,
}

impl TargetKind {
    pub const ALL: [TargetKind; 14] = [
        TargetKind::Document,
        TargetKind::Info,
        TargetKind::Server,
        TargetKind::Tag,
        TargetKind::Path,
        TargetKind::Operation,
        TargetKind::Parameter,
        TargetKind::RequestBody,
        TargetKind::Response,
        TargetKind::Header,
        TargetKind::MediaType,
        TargetKind::Schema,
        TargetKind::Property,
        TargetKind::SecurityScheme,
    ];

    pub fn name(self) -> &'static str {
        match self {
            TargetKind::Document => "document",
            TargetKind::Info => "info",
            TargetKind::Server => "server",
            TargetKind::Tag => "tag",
            TargetKind::Path => "path",
            TargetKind::Operation => "operation",
            TargetKind::Parameter => "parameter",
            TargetKind::RequestBody => "request_body",
            TargetKind::Response => "response",
            TargetKind::Header => "header",
            TargetKind::MediaType => "media_type",
            TargetKind::Schema => "schema",
            TargetKind::Property => "property",
            TargetKind::SecurityScheme => "security_scheme",
            TargetKind::Node => "node",
        }
    }

    pub fn parse(s: &str) -> Option<TargetKind> {
        TargetKind::ALL.into_iter().find(|k| k.name() == s)
    }
}

/// One target: its normalized fields, where it is, and a readable label.
#[derive(Debug, Clone)]
pub struct Target {
    pub kind: TargetKind,
    /// Where the object is defined (after `$ref` resolution).
    pub pointer: String,
    /// `GET /pets`, `schema Pet`, `property Pet.name`, …
    pub label: String,
    pub view: Map<String, Value>,
}

/// The HTTP methods of a Path Item, in document order of the fixed fields.
pub const METHODS: &[&str] = &["get", "put", "post", "delete", "options", "head", "patch", "trace"];

/// An operation with its path item context.
#[derive(Debug, Clone)]
pub struct OperationRef<'a> {
    /// Lower-case method (`get`, `query`, or an `additionalOperations` name).
    pub method: String,
    pub path: String,
    pub pointer: String,
    pub op: &'a Value,
    /// The Path Item (after `$ref` resolution) and its pointer.
    pub item: &'a Value,
    pub item_pointer: String,
}

impl OperationRef<'_> {
    pub fn label(&self) -> String {
        format!("{} {}", self.method.to_ascii_uppercase(), self.path)
    }

    pub fn operation_id(&self) -> Option<&str> {
        self.op.get("operationId").and_then(Value::as_str)
    }
}

/// Every operation of the document (3.2 `query` and `additionalOperations`
/// included; in older dialects those fields are not operations).
pub fn operations(spec: &Spec) -> Vec<OperationRef<'_>> {
    let mut out = vec![];
    let Some(paths) = spec.root.get("paths").and_then(Value::as_object) else { return out };
    for (path, raw_item) in paths {
        if path.starts_with("x-") {
            continue;
        }
        let pptr = ptr("/paths", path);
        let Some((item, item_pointer)) = spec.usable(raw_item, &pptr) else { continue };
        for (method, pointer, op) in item_operations(spec, item, &item_pointer) {
            out.push(OperationRef { method, path: path.clone(), pointer, op, item, item_pointer: item_pointer.clone() });
        }
    }
    out
}

/// The operations of a Path Item: lower-case method, pointer and object.
fn item_operations<'v>(spec: &Spec, item: &'v Value, item_pointer: &str) -> Vec<(String, String, &'v Value)> {
    let mut out = vec![];
    for m in METHODS {
        if let Some(op) = item.get(*m).filter(|o| o.is_object()) {
            out.push((m.to_string(), ptr(item_pointer, m), op));
        }
    }
    if spec.dialect == Dialect::OpenApi32 {
        if let Some(op) = item.get("query").filter(|o| o.is_object()) {
            out.push(("query".into(), ptr(item_pointer, "query"), op));
        }
        if let Some(extra) = item.get("additionalOperations").and_then(Value::as_object) {
            let base = ptr(item_pointer, "additionalOperations");
            for (m, op) in extra.iter().filter(|(_, o)| o.is_object()) {
                out.push((m.to_ascii_lowercase(), ptr(&base, m), op));
            }
        }
    }
    out
}

/// A resolved parameter of an operation.
#[derive(Debug, Clone)]
pub struct Param<'a> {
    pub name: String,
    pub location: String,
    pub value: &'a Value,
    pub pointer: String,
}

/// Path-level parameters merged with the operation's (the operation wins on
/// the same name and location).
pub fn parameters<'a>(spec: &'a Spec, op: &OperationRef<'a>) -> Vec<Param<'a>> {
    let mut out: Vec<Option<Param<'a>>> = vec![];
    // (name, in) → index in `out`: a later entry replaces an earlier one.
    let mut index: HashMap<(String, String), usize> = HashMap::new();
    let lists =
        [(op.item.get("parameters"), ptr(&op.item_pointer, "parameters")), (op.op.get("parameters"), ptr(&op.pointer, "parameters"))];
    for (list, base) in lists {
        let Some(list) = list.and_then(Value::as_array) else { continue };
        for (i, raw) in list.iter().enumerate() {
            let Some((p, pointer)) = spec.usable(raw, &ptr(&base, &i.to_string())) else { continue };
            let name = p.get("name").and_then(Value::as_str).unwrap_or("").to_string();
            let location = p.get("in").and_then(Value::as_str).unwrap_or("").to_string();
            if let Some(prev) = index.insert((name.clone(), location.clone()), out.len()) {
                out[prev] = None;
            }
            out.push(Some(Param { name, location, value: p, pointer }));
        }
    }
    out.into_iter().flatten().collect()
}

/// Names inside `{…}` in a path template.
pub fn template_params(path: &str) -> Vec<String> {
    let mut out = vec![];
    let mut rest = path;
    while let Some(open) = rest.find('{') {
        let after = &rest[open + 1..];
        let Some(close) = after.find('}') else { break };
        out.push(after[..close].to_string());
        rest = &after[close + 1..];
    }
    out
}

/// A media type of a request body or response, with its schema.
#[derive(Debug, Clone)]
pub struct Media<'a> {
    pub media_type: String,
    pub pointer: String,
    /// The media type object (3.x) or the response/body parameter (2.0).
    pub object: Option<&'a Value>,
    pub schema: Option<&'a Value>,
    pub schema_pointer: String,
}

/// A resolved request body.
#[derive(Debug, Clone)]
pub struct RequestBody<'a> {
    pub pointer: String,
    pub value: &'a Value,
    pub required: bool,
    pub media: Vec<Media<'a>>,
}

/// A resolved response of an operation.
#[derive(Debug, Clone)]
pub struct Response<'a> {
    pub code: String,
    pub pointer: String,
    pub value: &'a Value,
    pub media: Vec<Media<'a>>,
}

fn list_of_strings(v: Option<&Value>) -> Option<Vec<String>> {
    v.and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect())
}

/// Swagger 2.0 `consumes`/`produces` of an operation (falling back to the
/// document's).
pub fn swagger_media(spec: &Spec, op: &Value, field: &str) -> Option<Vec<String>> {
    list_of_strings(op.get(field)).or_else(|| list_of_strings(spec.root.get(field)))
}

fn content_media<'a>(spec: &'a Spec, owner: &'a Value, owner_ptr: &str) -> Vec<Media<'a>> {
    let mut out = vec![];
    let Some(content) = owner.get("content").and_then(Value::as_object) else { return out };
    let cptr = ptr(owner_ptr, "content");
    for (mt, obj) in content {
        let mptr = ptr(&cptr, mt);
        let Some((obj, mptr)) = spec.usable(obj, &mptr) else { continue };
        let schema = obj.get("schema");
        out.push(Media { media_type: mt.clone(), pointer: mptr.clone(), object: Some(obj), schema, schema_pointer: ptr(&mptr, "schema") });
    }
    out
}

pub fn request_body<'a>(spec: &'a Spec, op: &OperationRef<'a>) -> Option<RequestBody<'a>> {
    if spec.is_swagger2() {
        let params = parameters(spec, op);
        if let Some(body) = params.iter().find(|p| p.location == "body") {
            let types = swagger_media(spec, op.op, "consumes").unwrap_or_else(|| vec!["application/json".into()]);
            let media = types
                .into_iter()
                .map(|mt| Media {
                    media_type: mt,
                    pointer: body.pointer.clone(),
                    object: Some(body.value),
                    schema: body.value.get("schema"),
                    schema_pointer: ptr(&body.pointer, "schema"),
                })
                .collect();
            return Some(RequestBody {
                pointer: body.pointer.clone(),
                value: body.value,
                required: body.value.get("required").and_then(Value::as_bool).unwrap_or(false),
                media,
            });
        }
        let form: Vec<&Param> = params.iter().filter(|p| p.location == "formData").collect();
        if let Some(first) = form.first() {
            let has_file = form.iter().any(|p| p.value.get("type").and_then(Value::as_str) == Some("file"));
            let default = if has_file { "multipart/form-data" } else { "application/x-www-form-urlencoded" };
            let types = swagger_media(spec, op.op, "consumes").unwrap_or_else(|| vec![default.into()]);
            let media = types
                .into_iter()
                .map(|mt| Media {
                    media_type: mt,
                    pointer: first.pointer.clone(),
                    object: None,
                    schema: None,
                    schema_pointer: String::new(),
                })
                .collect();
            return Some(RequestBody {
                pointer: first.pointer.clone(),
                value: first.value,
                required: form.iter().any(|p| p.value.get("required").and_then(Value::as_bool).unwrap_or(false)),
                media,
            });
        }
        return None;
    }
    let raw = op.op.get("requestBody")?;
    let (value, pointer) = spec.usable(raw, &ptr(&op.pointer, "requestBody"))?;
    Some(RequestBody {
        required: value.get("required").and_then(Value::as_bool).unwrap_or(false),
        media: content_media(spec, value, &pointer),
        pointer,
        value,
    })
}

pub fn responses<'a>(spec: &'a Spec, op: &OperationRef<'a>) -> Vec<Response<'a>> {
    let mut out = vec![];
    let Some(map) = op.op.get("responses").and_then(Value::as_object) else { return out };
    let base = ptr(&op.pointer, "responses");
    for (code, raw) in map {
        if code.starts_with("x-") {
            continue;
        }
        let Some((value, pointer)) = spec.usable(raw, &ptr(&base, code)) else { continue };
        let media = if spec.is_swagger2() {
            match value.get("schema") {
                Some(schema) => swagger_media(spec, op.op, "produces")
                    .unwrap_or_else(|| vec!["application/json".into()])
                    .into_iter()
                    .map(|mt| Media {
                        media_type: mt,
                        pointer: pointer.clone(),
                        object: Some(value),
                        schema: Some(schema),
                        schema_pointer: ptr(&pointer, "schema"),
                    })
                    .collect(),
                None => vec![],
            }
        } else {
            content_media(spec, value, &pointer)
        };
        out.push(Response { code: code.clone(), pointer, value, media });
    }
    out
}

fn requirement_names(reqs: Option<&Vec<Value>>) -> Vec<String> {
    let mut names = BTreeSet::new();
    for r in reqs.into_iter().flatten() {
        if let Some(o) = r.as_object() {
            names.extend(o.keys().cloned());
        }
    }
    names.into_iter().collect()
}

pub fn security_schemes(spec: &Spec) -> Option<(&Map<String, Value>, String)> {
    if spec.is_swagger2() {
        spec.root.get("securityDefinitions").and_then(Value::as_object).map(|m| (m, "/securityDefinitions".to_string()))
    } else {
        spec.root.pointer("/components/securitySchemes").and_then(Value::as_object).map(|m| (m, "/components/securitySchemes".to_string()))
    }
}

pub fn component_schemas(spec: &Spec) -> Option<(&Map<String, Value>, String)> {
    if spec.is_swagger2() {
        spec.root.get("definitions").and_then(Value::as_object).map(|m| (m, "/definitions".to_string()))
    } else {
        spec.root.pointer("/components/schemas").and_then(Value::as_object).map(|m| (m, "/components/schemas".to_string()))
    }
}

fn extensions(v: &Value) -> Value {
    let mut m = Map::new();
    if let Some(o) = v.as_object() {
        for (k, x) in o {
            if k.starts_with("x-") {
                m.insert(k.clone(), x.clone());
            }
        }
    }
    Value::Object(m)
}

fn opt_str(v: &Value, key: &str) -> Value {
    v.get(key).and_then(Value::as_str).map(|s| Value::String(s.to_string())).unwrap_or(Value::Null)
}

fn opt_bool(v: &Value, key: &str) -> bool {
    v.get(key).and_then(Value::as_bool).unwrap_or(false)
}

/// `type` as one name (the first non-null one), every name, and whether
/// `null` is allowed (3.0 `nullable`, 2.0 `x-nullable`, 3.1 type arrays).
pub fn schema_types(schema: &Value) -> (Value, Vec<String>, bool) {
    let mut types: Vec<String> = match schema.get("type") {
        Some(Value::String(s)) => vec![s.clone()],
        Some(Value::Array(a)) => a.iter().filter_map(Value::as_str).map(str::to_string).collect(),
        _ => vec![],
    };
    let nullable = opt_bool(schema, "nullable") || opt_bool(schema, "x-nullable") || types.iter().any(|t| t == "null");
    types.retain(|t| t != "null");
    let first = types.first().cloned().map(Value::String).unwrap_or(Value::Null);
    (first, types, nullable)
}

/// Names of the component schemas (Swagger `definitions`, under `base`)
/// that an internal `$ref` points at or into. Linear in the document.
fn referenced_schemas(root: &Value, base: &str) -> HashSet<String> {
    let prefix = format!("{base}/");
    let mut out = HashSet::new();
    let mut stack = vec![root];
    while let Some(v) = stack.pop() {
        match v {
            Value::Object(o) => {
                if let Some(t) = o.get("$ref").and_then(Value::as_str).and_then(internal_pointer)
                    && let Some(rest) = t.strip_prefix(&prefix)
                {
                    let token = rest.split('/').next().unwrap_or(rest);
                    out.insert(token.replace("~1", "/").replace("~0", "~"));
                }
                stack.extend(o.values());
            }
            Value::Array(a) => stack.extend(a),
            _ => {}
        }
    }
    out
}

/// Builds every target of a document.
pub struct Model<'a> {
    pub spec: &'a Spec,
    pub targets: Vec<Target>,
    /// Operations left out because the work or view budget ran out.
    pub skipped_operations: usize,
}

/// Parameters, responses and media types looked at across all operations
/// (path-level ones count again for every operation that inherits them).
/// Past this, the remaining operations are left out and counted.
pub const MAX_MODEL_WORK: usize = 2_000_000;
/// Bytes the targets copy out of the document: their views, labels and
/// pointers, and what an operation copies again for every path that reaches
/// it. Counted separately from the object-work budget so ordinary long
/// descriptions do not consume that budget. Every copy is charged before it is
/// made; once one does not fit, nothing more is built and the remaining
/// operations are counted as left out.
pub const MAX_MODEL_VIEW_BYTES: usize = 256 * 1024 * 1024;
/// Charged for every JSON value a view copies, besides its text, so values
/// without text (numbers, nulls, nesting) count too.
const VALUE_BYTES: usize = 8;
/// Charged for the fixed member names and flags of a view.
const VIEW_BYTES: usize = 256;
/// The same for an operation view, which has about four times as many.
const OPERATION_VIEW_BYTES: usize = 1024;

impl<'a> Model<'a> {
    pub fn build(spec: &'a Spec, examples: &mut dyn FnMut(&Media<'a>, Direction) -> Vec<String>) -> Model<'a> {
        let mut b = ModelBuilder::new(spec, MAX_MODEL_VIEW_BYTES);
        b.build(examples);
        Model { spec, targets: b.targets, skipped_operations: b.skipped_operations }
    }

    pub fn of_kind(&self, kind: TargetKind) -> impl Iterator<Item = &Target> {
        self.targets.iter().filter(move |t| t.kind == kind)
    }
}

/// Whether a schema describes something sent to the API or returned by it
/// (OpenAPI `readOnly`/`writeOnly` apply to one direction each).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Request,
    Response,
}

struct ModelBuilder<'a> {
    spec: &'a Spec,
    targets: Vec<Target>,
    /// (kind, pointer) of targets already emitted: a parameter or response
    /// shared through `$ref` is one target.
    seen: HashSet<(TargetKind, String)>,
    /// Schemas whose properties were visited (the Swagger 2.0 media types of
    /// a body or response share its schema).
    property_roots: HashSet<String>,
    /// Operations already resolved, by pointer: one in a Path Item that
    /// several paths `$ref` is resolved and sized once.
    shared: HashMap<String, Rc<SharedOperation<'a>>>,
    work: usize,
    view_bytes: usize,
    view_byte_limit: usize,
    /// A copy did not fit the view budget: nothing more is built.
    exhausted: bool,
    skipped_operations: usize,
    /// JSON values visited to size copies.
    #[cfg(test)]
    walked: usize,
    /// Copies charged or refused.
    #[cfg(test)]
    reservations: usize,
}

/// What the paths that reach one operation share: its resolved parameters,
/// body and responses, the work they count and what a copy of its view costs
/// (both counted again for every path).
struct SharedOperation<'a> {
    params: Vec<Param<'a>>,
    body: Option<RequestBody<'a>>,
    resps: Vec<Response<'a>>,
    security_names: Vec<String>,
    duplicate_params: BTreeSet<String>,
    work: usize,
    view_cost: usize,
}

/// A Path Item and its operations, read once however many paths `$ref` it.
struct PathItem<'a> {
    value: &'a Value,
    pointer: String,
    operations: Vec<(String, String, &'a Value)>,
}

impl<'a> ModelBuilder<'a> {
    fn new(spec: &'a Spec, view_byte_limit: usize) -> ModelBuilder<'a> {
        ModelBuilder {
            spec,
            targets: vec![],
            seen: HashSet::new(),
            property_roots: HashSet::new(),
            shared: HashMap::new(),
            work: 0,
            view_bytes: 0,
            view_byte_limit,
            exhausted: false,
            skipped_operations: 0,
            #[cfg(test)]
            walked: 0,
            #[cfg(test)]
            reservations: 0,
        }
    }

    fn push(&mut self, kind: TargetKind, pointer: String, label: String, view: Value) {
        // An operation reached through several paths (one Path Item `$ref`'d
        // by each) is a target per path: its path template differs.
        let key = if kind == TargetKind::Operation { format!("{pointer}#{label}") } else { pointer.clone() };
        if !self.seen.insert((kind, key)) {
            return;
        }
        let Value::Object(view) = view else { return };
        self.targets.push(Target { kind, pointer, label, view });
    }

    fn is_seen(&self, kind: TargetKind, pointer: &str) -> bool {
        self.seen.contains(&(kind, pointer.to_string()))
    }

    /// Charge `bytes` of copies before making them. Once a charge does not
    /// fit, nothing more is built.
    fn reserve(&mut self, bytes: usize) -> bool {
        #[cfg(test)]
        {
            self.reservations += 1;
        }
        if self.exhausted || bytes > self.view_byte_limit.saturating_sub(self.view_bytes) {
            self.exhausted = true;
            return false;
        }
        self.view_bytes += bytes;
        true
    }

    /// What copying `v` into a view costs: its text and member names, plus
    /// [`VALUE_BYTES`] per value. Counting stops past what is left of the
    /// budget (that copy is never made).
    fn value_cost(&mut self, v: &Value) -> usize {
        let left = self.view_byte_limit.saturating_sub(self.view_bytes);
        let mut total = VALUE_BYTES;
        let mut stack = vec![v];
        while let Some(v) = stack.pop() {
            if total > left {
                break;
            }
            #[cfg(test)]
            {
                self.walked += 1;
            }
            match v {
                Value::String(s) => total = total.saturating_add(s.len()),
                Value::Array(a) => {
                    total = total.saturating_add(a.len().saturating_mul(VALUE_BYTES));
                    if total <= left {
                        stack.extend(a);
                    }
                }
                Value::Object(o) => {
                    total = total.saturating_add(o.len().saturating_mul(VALUE_BYTES));
                    if total <= left {
                        for (k, x) in o {
                            total = total.saturating_add(k.len());
                            stack.push(x);
                        }
                    }
                }
                _ => {}
            }
        }
        total
    }

    /// [`Self::value_cost`] of `v[key]`, when present.
    fn field_cost(&mut self, v: &Value, key: &str) -> usize {
        match v.get(key) {
            Some(x) => self.value_cost(x),
            None => 0,
        }
    }

    /// What copying the `x-` members of `v` costs.
    fn extensions_cost(&mut self, v: &Value) -> usize {
        let mut total = VALUE_BYTES;
        for (k, x) in v.as_object().into_iter().flatten().filter(|(k, _)| k.starts_with("x-")) {
            total = total.saturating_add(k.len()).saturating_add(self.value_cost(x));
        }
        total
    }

    fn build(&mut self, examples: &mut dyn FnMut(&Media<'a>, Direction) -> Vec<String>) {
        let spec = self.spec;
        let root = &spec.root;
        let schema_base = if spec.is_swagger2() { "/definitions" } else { "/components/schemas" };
        let referenced = referenced_schemas(root, schema_base);
        let declared_tags: Vec<String> = root
            .get("tags")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(|t| t.get("name").and_then(Value::as_str)).map(str::to_string).collect())
            .unwrap_or_default();
        let scheme_names: HashSet<String> = security_schemes(spec).map(|(m, _)| m.keys().cloned().collect()).unwrap_or_default();
        // Each path with its Path Item (an index into `items`): a Path Item
        // `$ref`'d by several paths is resolved and listed once.
        let mut items: Vec<PathItem<'a>> = vec![];
        let mut path_items: Vec<(&'a str, usize)> = vec![];
        let mut item_index: HashMap<String, usize> = HashMap::new();
        if let Some(paths) = root.get("paths").and_then(Value::as_object) {
            for (path, raw) in paths.iter().filter(|(k, _)| !k.starts_with("x-")) {
                let Some((value, pointer)) = spec.usable(raw, &ptr("/paths", path)) else { continue };
                let i = match item_index.get(&pointer) {
                    Some(i) => *i,
                    None => {
                        item_index.insert(pointer.clone(), items.len());
                        items.push(PathItem { value, operations: item_operations(spec, value, &pointer), pointer });
                        items.len() - 1
                    }
                };
                path_items.push((path.as_str(), i));
            }
        }
        let mut id_counts: HashMap<&str, usize> = HashMap::new();
        let mut used_tags: HashSet<&str> = HashSet::new();
        let mut used_schemes: HashSet<String> = HashSet::new();
        // The document's requirements once; each operation adds only its own.
        let global_security_names = requirement_names(root.get("security").and_then(Value::as_array));
        used_schemes.extend(global_security_names.iter().cloned());
        // Each operation once, its id counted for every path that reaches it.
        let mut uses = vec![0usize; items.len()];
        for (_, i) in &path_items {
            uses[*i] += 1;
        }
        for (item, n) in items.iter().zip(uses) {
            for (_, _, op) in &item.operations {
                let op = *op;
                if let Some(id) = op.get("operationId").and_then(Value::as_str) {
                    *id_counts.entry(id).or_default() += n;
                }
                used_tags.extend(op.get("tags").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str));
                used_schemes.extend(requirement_names(op.get("security").and_then(Value::as_array)));
            }
        }
        let operation_count: usize = path_items.iter().map(|(_, i)| items[*i].operations.len()).sum();
        let declared_tag_set: HashSet<String> = declared_tags.iter().cloned().collect();

        // Servers (document level; 2.0 from schemes × host + basePath).
        let mut server_urls = vec![];
        if spec.is_swagger2() {
            if let Some(host) = root.get("host").and_then(Value::as_str) {
                let base = root.get("basePath").and_then(Value::as_str).unwrap_or("");
                let schemes = list_of_strings(root.get("schemes")).filter(|s| !s.is_empty()).unwrap_or_else(|| vec!["https".into()]);
                for s in schemes {
                    // The URL is copied into the list, the label and the view.
                    let url_bytes = s.len() + 3 + host.len() + base.len();
                    if !self.reserve(VIEW_BYTES + 2 * (s.len() + 6) + 4 * url_bytes) {
                        break;
                    }
                    let url = format!("{s}://{host}{base}");
                    server_urls.push(url.clone());
                    self.push(
                        TargetKind::Server,
                        format!("/host#{s}"),
                        format!("server {url}"),
                        json!({"url": url, "description": null, "name": null, "variables": [], "level": "document", "extensions": {}}),
                    );
                }
            }
        } else {
            self.servers(root.get("servers"), "/servers", "document", &mut server_urls);
        }

        // Document and info.
        let path_count =
            root.get("paths").and_then(Value::as_object).map(|p| p.keys().filter(|k| !k.starts_with("x-")).count()).unwrap_or(0);
        let global_security = root.get("security").and_then(Value::as_array);
        let document_cost = VIEW_BYTES
            + spec.declared_version.as_ref().map_or(0, |v| v.len() + VALUE_BYTES)
            + spec.title().map_or(0, |t| t.len() + VALUE_BYTES)
            + 6 * root.pointer("/info/version").map_or(0, |v| self.value_cost(v))
            + names_cost(server_urls.iter().map(String::as_str))
            + names_cost(declared_tags.iter().map(String::as_str))
            + names_cost(global_security_names.iter().map(String::as_str))
            + self.field_cost(root, "consumes")
            + self.field_cost(root, "produces")
            + str_cost(root, "jsonSchemaDialect")
            + self.extensions_cost(root);
        if self.reserve(document_cost) {
            self.push(
                TargetKind::Document,
                String::new(),
                "document".into(),
                json!({
                    "dialect": spec.dialect.label(),
                    "openapi_version": spec.declared_version,
                    "title": spec.title(),
                    "version": spec.version(),
                    "has_servers": !server_urls.is_empty(),
                    "server_urls": server_urls,
                    "tags": declared_tags,
                    "security": global_security_names,
                    "has_global_security": global_security.is_some_and(|s| !s.is_empty()),
                    "path_count": path_count,
                    "operation_count": operation_count,
                    "schema_count": component_schemas(spec).map(|(m, _)| m.len()).unwrap_or(0),
                    "security_scheme_count": scheme_names.len(),
                    "json_schema_dialect": opt_str(root, "jsonSchemaDialect"),
                    "has_webhooks": root.get("webhooks").and_then(Value::as_object).is_some_and(|w| !w.is_empty()),
                    "consumes": list_of_strings(root.get("consumes")),
                    "produces": list_of_strings(root.get("produces")),
                    "extensions": extensions(root),
                }),
            );
        }
        if let Some(info) = root.get("info") {
            let info_cost = VIEW_BYTES
                + strs_cost(info, &["title", "summary", "description", "termsOfService"])
                + 6 * self.field_cost(info, "version")
                + info.get("contact").map_or(0, |c| strs_cost(c, &["name", "url", "email"]) + VALUE_BYTES)
                + info.get("license").map_or(0, |l| strs_cost(l, &["name", "url", "identifier"]) + VALUE_BYTES)
                + self.extensions_cost(info);
            if self.reserve(info_cost) {
                let contact = info
                    .get("contact")
                    .map(|c| json!({"name": opt_str(c, "name"), "url": opt_str(c, "url"), "email": opt_str(c, "email")}));
                let license = info
                    .get("license")
                    .map(|l| json!({"name": opt_str(l, "name"), "url": opt_str(l, "url"), "identifier": opt_str(l, "identifier")}));
                self.push(
                    TargetKind::Info,
                    "/info".into(),
                    "info".into(),
                    json!({
                        "title": opt_str(info, "title"),
                        "version": info.get("version").map(|v| match v { Value::String(s) => s.clone(), o => o.to_string() }),
                        "summary": opt_str(info, "summary"),
                        "description": opt_str(info, "description"),
                        "terms_of_service": opt_str(info, "termsOfService"),
                        "contact": contact,
                        "license": license,
                        "extensions": extensions(info),
                    }),
                );
            }
        }

        // Tags.
        if let Some(tags) = root.get("tags").and_then(Value::as_array) {
            for (i, t) in tags.iter().enumerate() {
                let name = t.get("name").and_then(Value::as_str).unwrap_or("");
                let cost =
                    VIEW_BYTES + 3 * name.len() + strs_cost(t, &["summary", "description", "parent", "kind"]) + self.extensions_cost(t);
                if !self.reserve(cost) {
                    break;
                }
                self.push(
                    TargetKind::Tag,
                    format!("/tags/{i}"),
                    format!("tag {name}"),
                    json!({
                        "name": name,
                        "summary": opt_str(t, "summary"),
                        "description": opt_str(t, "description"),
                        "parent": opt_str(t, "parent"),
                        "kind": opt_str(t, "kind"),
                        "has_external_docs": t.get("externalDocs").is_some(),
                        "used": used_tags.contains(name),
                        "extensions": extensions(t),
                    }),
                );
            }
        }

        // Paths.
        for (path, i) in &path_items {
            let item = &items[*i];
            if !self.is_seen(TargetKind::Path, &item.pointer) {
                let methods: Vec<&str> = item.operations.iter().map(|(m, _, _)| m.as_str()).collect();
                let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
                let static_segments: Vec<&str> = segments.iter().copied().filter(|s| !s.contains('{')).collect();
                // The path is copied into the label and the view, and again
                // as its segments and template parameters.
                let cost = VIEW_BYTES
                    + 2 * item.pointer.len()
                    + 6 * path.len()
                    + VALUE_BYTES * (2 * segments.len() + path.matches('{').count())
                    + names_cost(methods.iter().copied())
                    + self.extensions_cost(item.value);
                if !self.reserve(cost) {
                    break;
                }
                self.push(
                    TargetKind::Path,
                    item.pointer.clone(),
                    format!("path {path}"),
                    json!({
                        "path": path,
                        "operations": methods,
                        "segments": segments,
                        "static_segments": static_segments,
                        "template_params": template_params(path),
                        "extensions": extensions(item.value),
                    }),
                );
            }
            self.servers(item.value.get("servers"), &ptr(&ptr("/paths", path), "servers"), "path", &mut vec![]);
        }

        // Operations and everything under them.
        for (path, i) in &path_items {
            let item = &items[*i];
            for (k, (method, pointer, value)) in item.operations.iter().enumerate() {
                // The operation's own copies of its method, path and pointers:
                // its reference, label, key and view.
                let copies = 8 * method.len() + 6 * path.len() + 3 * pointer.len() + item.pointer.len() + 8 * VALUE_BYTES;
                if self.work > MAX_MODEL_WORK || !self.reserve(copies) {
                    self.skipped_operations += item.operations.len() - k;
                    break;
                }
                let op = OperationRef {
                    method: method.clone(),
                    path: path.to_string(),
                    pointer: pointer.clone(),
                    op: *value,
                    item: item.value,
                    item_pointer: item.pointer.clone(),
                };
                self.operation(&op, &declared_tag_set, &global_security_names, &scheme_names, &id_counts, examples);
            }
        }

        // Security schemes.
        if let Some((schemes, base)) = security_schemes(spec) {
            for (name, raw) in schemes {
                let Some((s, pointer)) = spec.usable(raw, &ptr(&base, name)) else { continue };
                let flows_cost = match s.get("flows").and_then(Value::as_object) {
                    Some(f) => names_cost(f.keys().map(String::as_str)),
                    None => str_cost(s, "flow"),
                };
                let cost = VIEW_BYTES
                    + 2 * pointer.len()
                    + 3 * name.len()
                    + strs_cost(s, &["type", "scheme", "in", "name", "bearerFormat", "openIdConnectUrl", "description"])
                    + flows_cost
                    + self.extensions_cost(s);
                if !self.reserve(cost) {
                    break;
                }
                let flows: Vec<String> = match s.get("flows").and_then(Value::as_object) {
                    Some(f) => f.keys().cloned().collect(),
                    None => s.get("flow").and_then(Value::as_str).map(|f| vec![f.to_string()]).unwrap_or_default(),
                };
                self.push(
                    TargetKind::SecurityScheme,
                    pointer,
                    format!("security scheme {name}"),
                    json!({
                        "name": name,
                        "type": opt_str(s, "type"),
                        "scheme": opt_str(s, "scheme"),
                        "in": opt_str(s, "in"),
                        "param_name": opt_str(s, "name"),
                        "bearer_format": opt_str(s, "bearerFormat"),
                        "flows": flows,
                        "openid_connect_url": opt_str(s, "openIdConnectUrl"),
                        "description": opt_str(s, "description"),
                        "deprecated": opt_bool(s, "deprecated"),
                        "used": used_schemes.contains(name),
                        "extensions": extensions(s),
                    }),
                );
            }
        }

        // Component schemas and their properties.
        if let Some((schemas, base)) = component_schemas(spec) {
            for (name, raw) in schemas {
                let pointer = ptr(&base, name);
                let is_referenced = referenced.contains(name);
                let property_names = raw.get("properties").and_then(Value::as_object);
                let cost = VIEW_BYTES
                    + 2 * pointer.len()
                    + 3 * name.len()
                    + 2 * self.field_cost(raw, "type")
                    + strs_cost(raw, &["format", "title", "description"])
                    + property_names.map_or(0, |p| names_cost(p.keys().map(String::as_str)))
                    + self.field_cost(raw, "required")
                    + self.field_cost(raw, "enum")
                    + self.extensions_cost(raw);
                if !self.reserve(cost) {
                    break;
                }
                let (ty, types, nullable) = schema_types(raw);
                let properties: Vec<String> = property_names.map(|p| p.keys().cloned().collect()).unwrap_or_default();
                self.push(
                    TargetKind::Schema,
                    pointer.clone(),
                    format!("schema {name}"),
                    json!({
                        "name": name,
                        "type": ty,
                        "types": types,
                        "nullable": nullable,
                        "format": opt_str(raw, "format"),
                        "title": opt_str(raw, "title"),
                        "description": opt_str(raw, "description"),
                        "properties": properties,
                        "required": raw.get("required").cloned().unwrap_or(json!([])),
                        "enum": raw.get("enum").cloned(),
                        "has_example": raw.get("example").is_some() || raw.get("examples").is_some(),
                        "deprecated": opt_bool(raw, "deprecated"),
                        "is_ref": raw.get("$ref").is_some(),
                        "referenced": is_referenced,
                        "extensions": extensions(raw),
                    }),
                );
                self.properties(raw, &pointer, name, 0);
            }
        }
    }

    fn servers(&mut self, servers: Option<&Value>, base: &str, level: &str, urls: &mut Vec<String>) {
        let Some(list) = servers.and_then(Value::as_array) else { return };
        for (i, s) in list.iter().enumerate() {
            let url = s.get("url").and_then(Value::as_str).unwrap_or("");
            let variables = s.get("variables").and_then(Value::as_object);
            // The URL is copied into the list, the label and the view.
            let cost = VIEW_BYTES
                + 2 * (base.len() + 21)
                + 4 * url.len()
                + strs_cost(s, &["description", "name"])
                + variables.map_or(0, |v| names_cost(v.keys().map(String::as_str)))
                + self.extensions_cost(s);
            if !self.reserve(cost) {
                return;
            }
            let url = url.to_string();
            urls.push(url.clone());
            let variables: Vec<String> = variables.map(|v| v.keys().cloned().collect()).unwrap_or_default();
            self.push(
                TargetKind::Server,
                ptr(base, &i.to_string()),
                format!("server {url}"),
                json!({
                    "url": url,
                    "description": opt_str(s, "description"),
                    "name": opt_str(s, "name"),
                    "variables": variables,
                    "level": level,
                    "extensions": extensions(s),
                }),
            );
        }
    }

    /// Resolve and size an operation the first time a path reaches it.
    /// `None` when its work does not fit.
    fn share(&mut self, op: &OperationRef<'a>, global_security_names: &[String]) -> Option<Rc<SharedOperation<'a>>> {
        let spec = self.spec;
        let own_security = op.op.get("security").and_then(Value::as_array);
        // Part of the work below, known before anything is resolved.
        let listed = 1
            + own_security.map_or(0, Vec::len)
            + op.item.get("parameters").and_then(Value::as_array).map_or(0, Vec::len)
            + op.op.get("parameters").and_then(Value::as_array).map_or(0, Vec::len);
        if self.work.saturating_add(listed) > MAX_MODEL_WORK {
            self.work = self.work.saturating_add(listed);
            return None;
        }
        let params = parameters(spec, op);
        let body = request_body(spec, op);
        let resps = responses(spec, op);
        // Inheriting operations reuse the document's names (gathered once).
        let security_names = match own_security {
            Some(reqs) => requirement_names(Some(reqs)),
            None => global_security_names.to_vec(),
        };
        // Everything below is proportional to these (inherited parameters and
        // the document's security count for every operation).
        let work = 1
            + params.len()
            + security_names.len()
            + own_security.map_or(0, Vec::len)
            + resps
                .iter()
                .map(|r| 1 + r.media.len() + r.value.get("headers").and_then(Value::as_object).map_or(0, |h| h.len()))
                .sum::<usize>()
            + body.as_ref().map_or(0, |b| b.media.len())
            + op.item.get("parameters").and_then(Value::as_array).map_or(0, Vec::len)
            + op.op.get("parameters").and_then(Value::as_array).map_or(0, Vec::len);
        self.work += work;
        if self.work > MAX_MODEL_WORK {
            return None;
        }
        // The same name and location twice in one parameter list.
        let mut duplicate_params = BTreeSet::new();
        let levels =
            [(op.item.get("parameters"), ptr(&op.item_pointer, "parameters")), (op.op.get("parameters"), ptr(&op.pointer, "parameters"))];
        for (list, base) in levels {
            let mut this_level = HashSet::new();
            for (i, raw) in list.and_then(Value::as_array).into_iter().flatten().enumerate() {
                let Some((p, _)) = spec.usable(raw, &ptr(&base, &i.to_string())) else { continue };
                let name = p.get("name").and_then(Value::as_str).unwrap_or("");
                let location = p.get("in").and_then(Value::as_str).unwrap_or("");
                if !this_level.insert((name, location)) {
                    duplicate_params.insert(format!("{name} ({location})"));
                }
            }
        }
        // What a copy of its view costs, but for what depends on the path.
        let media_cost = |m: &Media<'_>| 2 * m.media_type.len() + VALUE_BYTES + m.pointer.len() + m.schema_pointer.len();
        let mut view_cost = OPERATION_VIEW_BYTES
            + strs_cost(op.op, &["operationId", "summary", "description"])
            + 3 * self.field_cost(op.op, "tags")
            + 3 * names_cost(security_names.iter().map(String::as_str))
            + op.op.get("callbacks").and_then(Value::as_object).map_or(0, |c| names_cost(c.keys().map(String::as_str)))
            + names_cost(duplicate_params.iter().map(String::as_str))
            + self.extensions_cost(op.op);
        for p in &params {
            view_cost += 5 * (p.name.len() + p.location.len()) + 10 * VALUE_BYTES + p.pointer.len();
        }
        if let Some(b) = &body {
            view_cost += b.pointer.len() + b.media.iter().map(media_cost).sum::<usize>();
        }
        for r in &resps {
            view_cost += 3 * (r.code.len() + VALUE_BYTES) + r.pointer.len() + r.media.iter().map(media_cost).sum::<usize>();
        }
        let shared = Rc::new(SharedOperation { params, body, resps, security_names, duplicate_params, work, view_cost });
        self.shared.insert(op.pointer.clone(), Rc::clone(&shared));
        Some(shared)
    }

    fn operation(
        &mut self,
        op: &OperationRef<'a>,
        declared_tags: &HashSet<String>,
        global_security_names: &[String],
        scheme_names: &HashSet<String>,
        id_counts: &HashMap<&str, usize>,
        examples: &mut dyn FnMut(&Media<'a>, Direction) -> Vec<String>,
    ) {
        let spec = self.spec;
        // An operation reached through several paths is resolved and sized
        // once, and what is under it is a target once.
        let (shared, first) = match self.shared.get(&op.pointer) {
            Some(s) => {
                let s = Rc::clone(s);
                self.work += s.work;
                (s, false)
            }
            None => match self.share(op, global_security_names) {
                Some(s) => (s, true),
                None => {
                    self.skipped_operations += 1;
                    return;
                }
            },
        };
        if self.work > MAX_MODEL_WORK {
            self.skipped_operations += 1;
            return;
        }
        let label = op.label();
        let template = template_params(&op.path);
        let path_params: Vec<&str> = shared.params.iter().filter(|p| p.location == "path").map(|p| p.name.as_str()).collect();
        let declared: HashSet<&str> = path_params.iter().copied().collect();
        let templated: HashSet<&str> = template.iter().map(String::as_str).collect();
        let undeclared: Vec<&String> = template.iter().filter(|t| !declared.contains(t.as_str())).collect();
        let unused: Vec<&&str> = path_params.iter().filter(|p| !templated.contains(**p)).collect();
        let path_cost = names_cost(undeclared.iter().map(|t| t.as_str())) + names_cost(unused.iter().map(|p| **p));
        if !self.reserve(shared.view_cost + path_cost) {
            self.skipped_operations += 1;
            return;
        }
        let params = &shared.params;
        let tags = list_of_strings(op.op.get("tags")).unwrap_or_default();
        let codes: Vec<&str> = shared.resps.iter().map(|r| r.code.as_str()).collect();
        let class = |c: &str, first: char| c.starts_with(first);
        let operation_id = op.operation_id();
        let operation_view = json!({
                "method": op.method,
                "method_upper": op.method.to_ascii_uppercase(),
                "path": op.path,
                "operation_id": operation_id,
                "summary": opt_str(op.op, "summary"),
                "description": opt_str(op.op, "description"),
                "tags": tags,
                "deprecated": opt_bool(op.op, "deprecated"),
                "parameters": params.iter().map(|p| json!({"name": p.name, "in": p.location, "required": opt_bool(p.value, "required")})).collect::<Vec<_>>(),
                "parameter_names": params.iter().map(|p| p.name.clone()).collect::<Vec<_>>(),
                "query_params": params.iter().filter(|p| p.location == "query").map(|p| p.name.clone()).collect::<Vec<_>>(),
                "header_params": params.iter().filter(|p| p.location == "header").map(|p| p.name.clone()).collect::<Vec<_>>(),
                "path_params": path_params,
                "cookie_params": params.iter().filter(|p| p.location == "cookie").map(|p| p.name.clone()).collect::<Vec<_>>(),
                "has_request_body": shared.body.is_some(),
                "request_content_types": shared.body.as_ref().map(|b| b.media.iter().map(|m| m.media_type.clone()).collect::<Vec<_>>()).unwrap_or_default(),
                "response_codes": codes,
                "success_codes": codes.iter().filter(|c| class(c, '2') || class(c, '3')).collect::<Vec<_>>(),
                "error_codes": codes.iter().filter(|c| class(c, '4') || class(c, '5')).collect::<Vec<_>>(),
                "client_error_codes": codes.iter().filter(|c| class(c, '4')).collect::<Vec<_>>(),
                "server_error_codes": codes.iter().filter(|c| class(c, '5')).collect::<Vec<_>>(),
                "has_default_response": codes.contains(&"default"),
                "response_content_types": shared.resps.iter().flat_map(|r| r.media.iter().map(|m| m.media_type.clone())).collect::<BTreeSet<_>>(),
                "security": shared.security_names,
                // A requirement naming no scheme (`{}`) makes security optional.
                "has_security": !shared.security_names.is_empty(),
                "has_explicit_security": op.op.get("security").is_some(),
                "callbacks": op.op.get("callbacks").and_then(Value::as_object).map(|c| c.keys().cloned().collect::<Vec<_>>()).unwrap_or_default(),
                "operation_id_duplicate": operation_id.is_some_and(|id| id_counts.get(id).copied().unwrap_or(0) > 1),
                "undeclared_path_params": undeclared,
                "unused_path_params": unused,
                "undeclared_tags": tags.iter().filter(|t| !declared_tags.contains(*t)).collect::<Vec<_>>(),
                "undefined_security_schemes": shared.security_names.iter().filter(|n| !scheme_names.contains(*n)).collect::<Vec<_>>(),
                "duplicate_parameters": shared.duplicate_params,
                "extensions": extensions(op.op),
        });
        self.push(TargetKind::Operation, op.pointer.clone(), label.clone(), operation_view);
        if !first {
            return;
        }
        // Copied into every view below, as each label repeats the operation's.
        let ctx_cost = 96 + 2 * op.method.len() + op.path.len() + operation_id.map_or(0, str::len);
        if !self.reserve(ctx_cost) {
            return;
        }
        let ctx = json!({
            "method": op.method,
            "method_upper": op.method.to_ascii_uppercase(),
            "path": op.path,
            "operation_id": operation_id
        });

        for p in params {
            // A Swagger 2.0 body parameter is the request body target; a
            // shared (inherited or `$ref`'d) parameter is one target.
            if p.location == "body" || self.is_seen(TargetKind::Parameter, &p.pointer) {
                continue;
            }
            let schema = p.value.get("schema").unwrap_or(p.value);
            let label_bytes = p.location.len() + p.name.len() + label.len() + 15;
            let cost = VIEW_BYTES
                + ctx_cost
                + 2 * p.pointer.len()
                + label_bytes
                + p.name.len()
                + p.location.len()
                + strs_cost(p.value, &["description", "style"])
                + str_cost(schema, "format")
                + 2 * self.field_cost(schema, "type")
                + self.field_cost(schema, "enum")
                + self.field_cost(p.value, "explode")
                + self.extensions_cost(p.value);
            if !self.reserve(cost) {
                return;
            }
            let (ty, types, nullable) = schema_types(schema);
            let mut view = json!({
                "name": p.name,
                "in": p.location,
                "required": opt_bool(p.value, "required"),
                "description": opt_str(p.value, "description"),
                "deprecated": opt_bool(p.value, "deprecated"),
                "type": ty,
                "types": types,
                "nullable": nullable,
                "format": opt_str(schema, "format"),
                "enum": schema.get("enum").cloned(),
                "style": opt_str(p.value, "style"),
                "explode": p.value.get("explode").cloned(),
                "allow_empty_value": opt_bool(p.value, "allowEmptyValue"),
                "has_schema": p.value.get("schema").is_some() || p.value.get("content").is_some() || p.value.get("type").is_some(),
                "has_example": p.value.get("example").is_some() || p.value.get("examples").is_some() || schema.get("example").is_some() || p.value.get("x-example").is_some(),
                "extensions": extensions(p.value),
            });
            merge(&mut view, &ctx);
            self.push(TargetKind::Parameter, p.pointer.clone(), format!("{} parameter {} of {label}", p.location, p.name), view);
            if let Some(s) = p.value.get("schema") {
                // The owner of its properties repeats the label.
                if !self.reserve(label_bytes + p.pointer.len() + 7) {
                    return;
                }
                self.properties(s, &ptr(&p.pointer, "schema"), &format!("{label} {} parameter {}", p.location, p.name), 0);
            }
        }

        // A shared (`$ref`'d) body or response is one target: built once.
        if let Some(body) = shared.body.as_ref().filter(|b| !self.is_seen(TargetKind::RequestBody, &b.pointer)) {
            let cost = VIEW_BYTES
                + ctx_cost
                + 2 * body.pointer.len()
                + label.len()
                + str_cost(body.value, "description")
                + names_cost(body.media.iter().map(|m| m.media_type.as_str()))
                + self.extensions_cost(body.value);
            if !self.reserve(cost) {
                return;
            }
            let mut view = json!({
                "required": body.required,
                "description": opt_str(body.value, "description"),
                "content_types": body.media.iter().map(|m| m.media_type.clone()).collect::<Vec<_>>(),
                "extensions": extensions(body.value),
            });
            merge(&mut view, &ctx);
            self.push(TargetKind::RequestBody, body.pointer.clone(), format!("request body of {label}"), view);
            for m in &body.media {
                self.media(m, Direction::Request, None, &ctx, &label, examples);
            }
        }

        for r in &shared.resps {
            if self.exhausted {
                return;
            }
            if self.is_seen(TargetKind::Response, &r.pointer) {
                continue;
            }
            let header_map = r.value.get("headers").and_then(Value::as_object);
            let cost = VIEW_BYTES
                + ctx_cost
                + 2 * r.pointer.len()
                + label.len()
                + 2 * r.code.len()
                + str_cost(r.value, "description")
                + names_cost(r.media.iter().map(|m| m.media_type.as_str()))
                + header_map.map_or(0, |h| names_cost(h.keys().map(String::as_str)))
                + self.extensions_cost(r.value);
            if !self.reserve(cost) {
                return;
            }
            let headers: Vec<String> = header_map.map(|h| h.keys().cloned().collect()).unwrap_or_default();
            let mut view = json!({
                "code": r.code,
                "description": opt_str(r.value, "description"),
                "content_types": r.media.iter().map(|m| m.media_type.clone()).collect::<Vec<_>>(),
                "headers": headers,
                "has_content": !r.media.is_empty(),
                "is_success": r.code.starts_with('2') || r.code.starts_with('3'),
                "is_error": r.code.starts_with('4') || r.code.starts_with('5'),
                "is_default": r.code == "default",
                "extensions": extensions(r.value),
            });
            merge(&mut view, &ctx);
            self.push(TargetKind::Response, r.pointer.clone(), format!("{} response of {label}", r.code), view);
            if let Some(h) = header_map {
                let base = ptr(&r.pointer, "headers");
                for (name, raw) in h {
                    let Some((hv, hptr)) = spec.usable(raw, &ptr(&base, name)) else { continue };
                    if self.is_seen(TargetKind::Header, &hptr) {
                        continue;
                    }
                    let schema = hv.get("schema").unwrap_or(hv);
                    let cost = VIEW_BYTES
                        + ctx_cost
                        + 2 * hptr.len()
                        + label.len()
                        + 2 * (name.len() + r.code.len())
                        + str_cost(hv, "description")
                        + str_cost(schema, "format")
                        + self.field_cost(schema, "type")
                        + self.extensions_cost(hv);
                    if !self.reserve(cost) {
                        return;
                    }
                    let (ty, _, _) = schema_types(schema);
                    let mut view = json!({
                        "name": name,
                        "code": r.code,
                        "description": opt_str(hv, "description"),
                        "required": opt_bool(hv, "required"),
                        "deprecated": opt_bool(hv, "deprecated"),
                        "type": ty,
                        "format": opt_str(schema, "format"),
                        "extensions": extensions(hv),
                    });
                    merge(&mut view, &ctx);
                    self.push(TargetKind::Header, hptr, format!("header {name} of the {} response of {label}", r.code), view);
                }
            }
            for m in &r.media {
                self.media(m, Direction::Response, Some(&r.code), &ctx, &label, examples);
            }
        }
    }

    fn media(
        &mut self,
        m: &Media<'a>,
        direction: Direction,
        code: Option<&str>,
        ctx: &Value,
        label: &str,
        examples: &mut dyn FnMut(&Media<'a>, Direction) -> Vec<String>,
    ) {
        let spec = self.spec;
        // A Swagger 2.0 media type shares its pointer with its response; key
        // the target by media type too.
        let pointer = if spec.is_swagger2() { format!("{}#{}", m.pointer, m.media_type) } else { m.pointer.clone() };
        if self.exhausted || self.is_seen(TargetKind::MediaType, &pointer) {
            return;
        }
        let obj = m.object.unwrap_or(&Value::Null);
        let has_example = if spec.is_swagger2() {
            obj.pointer(&format!("/examples/{}", m.media_type.replace('~', "~0").replace('/', "~1"))).is_some()
                || m.schema.is_some_and(|s| s.get("example").is_some())
        } else {
            obj.get("example").is_some()
                || obj.get("examples").and_then(Value::as_object).is_some_and(|e| !e.is_empty())
                || m.schema.is_some_and(|s| s.get("example").is_some() || s.get("examples").is_some())
        };
        let schema = m.schema.map(|s| spec.deref(s, &m.schema_pointer).0);
        let example_errors = examples(m, direction);
        // The label and the owner of its properties repeat the operation's.
        let where_bytes = code.map_or(16, |c| c.len() + 13) + label.len();
        let cost = VIEW_BYTES
            + self.value_cost(ctx)
            + 2 * pointer.len()
            + where_bytes
            + 2 * m.media_type.len()
            + code.map_or(0, |c| c.len() + VALUE_BYTES)
            + schema.map_or(0, |s| self.field_cost(s, "type"))
            + names_cost(example_errors.iter().map(String::as_str))
            + self.extensions_cost(obj);
        if !self.reserve(cost) {
            return;
        }
        let where_ = match code {
            Some(c) => format!("{c} response of {label}"),
            None => format!("request body of {label}"),
        };
        let (ty, _, _) = schema.map(schema_types).unwrap_or((Value::Null, vec![], false));
        let mut view = json!({
            "media_type": m.media_type,
            "direction": match direction { Direction::Request => "request", Direction::Response => "response" },
            "code": code,
            "has_schema": m.schema.is_some(),
            "schema_type": ty,
            "schema_is_ref": m.schema.is_some_and(|s| s.get("$ref").is_some()),
            "has_example": has_example,
            "example_errors": example_errors,
            "extensions": extensions(obj),
        });
        merge(&mut view, ctx);
        self.push(TargetKind::MediaType, pointer, format!("{} in the {where_}", m.media_type), view);
        if let Some(s) = m.schema
            && !self.property_roots.contains(&m.schema_pointer)
        {
            if !self.reserve(where_bytes + m.media_type.len() + 2 * m.schema_pointer.len() + 3) {
                return;
            }
            self.property_roots.insert(m.schema_pointer.clone());
            self.properties(s, &m.schema_pointer, &format!("{where_} ({})", m.media_type), 0);
        }
    }

    /// Properties of an inline schema (not following `$ref`: referenced
    /// schemas are visited as components), through `items`, compositions and
    /// `additionalProperties`. Every pointer and owner label is charged
    /// before it is built, and the walk ends once the budget is spent.
    fn properties(&mut self, schema: &Value, pointer: &str, owner: &str, depth: usize) {
        if self.exhausted || depth > 24 || schema.get("$ref").is_some() {
            return;
        }
        if let Some(props) = schema.get("properties").and_then(Value::as_object) {
            let required: HashSet<&str> =
                schema.get("required").and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_str).collect()).unwrap_or_default();
            if !self.reserve(pointer.len() + 11) {
                return;
            }
            let base = ptr(pointer, "properties");
            for (name, p) in props {
                // Its pointer, label and parent, and the owner of what it
                // nests, repeat `pointer` or `owner`.
                let cost = VIEW_BYTES
                    + 3 * (base.len() + 1 + 2 * name.len())
                    + 3 * (owner.len() + name.len())
                    + 2 * self.field_cost(p, "type")
                    + strs_cost(p, &["format", "description"])
                    + self.field_cost(p, "enum")
                    + self.extensions_cost(p);
                if !self.reserve(cost) {
                    return;
                }
                let pptr = ptr(&base, name);
                let (ty, types, nullable) = schema_types(p);
                self.push(
                    TargetKind::Property,
                    pptr.clone(),
                    format!("property {name} of {owner}"),
                    json!({
                        "name": name,
                        "parent": owner,
                        "required": required.contains(name.as_str()),
                        "type": ty,
                        "types": types,
                        "nullable": nullable,
                        "format": opt_str(p, "format"),
                        "description": opt_str(p, "description"),
                        "is_ref": p.get("$ref").is_some(),
                        "deprecated": opt_bool(p, "deprecated"),
                        "read_only": opt_bool(p, "readOnly"),
                        "write_only": opt_bool(p, "writeOnly"),
                        "enum": p.get("enum").cloned(),
                        "has_example": p.get("example").is_some() || p.get("examples").is_some(),
                        "extensions": extensions(p),
                    }),
                );
                self.properties(p, &pptr, &format!("{owner}.{name}"), depth + 1);
            }
        }
        if let Some(items) = schema.get("items") {
            if !self.reserve(pointer.len() + owner.len() + 8) {
                return;
            }
            self.properties(items, &ptr(pointer, "items"), &format!("{owner}[]"), depth + 1);
        }
        for key in ["allOf", "oneOf", "anyOf"] {
            if let Some(list) = schema.get(key).and_then(Value::as_array) {
                if !self.reserve(pointer.len() + 6) {
                    return;
                }
                let base = ptr(pointer, key);
                for (i, s) in list.iter().enumerate() {
                    if !self.reserve(base.len() + 21) {
                        return;
                    }
                    self.properties(s, &ptr(&base, &i.to_string()), owner, depth + 1);
                }
            }
        }
        if let Some(ap) = schema.get("additionalProperties").filter(|a| a.is_object()) {
            if !self.reserve(pointer.len() + owner.len() + 24) {
                return;
            }
            self.properties(ap, &ptr(pointer, "additionalProperties"), &format!("{owner}{{*}}"), depth + 1);
        }
    }
}

fn merge(view: &mut Value, ctx: &Value) {
    if let (Value::Object(v), Value::Object(c)) = (view, ctx) {
        for (k, x) in c {
            v.entry(k.clone()).or_insert_with(|| x.clone());
        }
    }
}

/// What copying the string `v[key]` into a view costs (other values are not
/// copied).
fn str_cost(v: &Value, key: &str) -> usize {
    v.get(key).and_then(Value::as_str).map_or(0, |s| s.len() + VALUE_BYTES)
}

/// [`str_cost`] of each of `keys`.
fn strs_cost(v: &Value, keys: &[&str]) -> usize {
    keys.iter().map(|k| str_cost(v, k)).sum()
}

/// What copying a list of names into a view costs.
fn names_cost<'s>(names: impl IntoIterator<Item = &'s str>) -> usize {
    names.into_iter().fold(0, |sum, n| sum.saturating_add(n.len()).saturating_add(VALUE_BYTES))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build(spec: &Spec, view_byte_limit: usize) -> ModelBuilder<'_> {
        let mut builder = ModelBuilder::new(spec, view_byte_limit);
        builder.build(&mut |_, _| vec![]);
        builder
    }

    #[test]
    fn shared_operation_extensions_are_charged_to_the_view_byte_budget() {
        let extension = "x".repeat(128 * 1024);
        let mut paths = serde_json::Map::new();
        for i in 0..12 {
            paths.insert(format!("/shared-{i}"), json!({"$ref": "#/components/pathItems/Shared"}));
        }
        let document = json!({
            "openapi": "3.1.0",
            "info": {"title": "test", "version": "1"},
            "paths": paths,
            "components": {"pathItems": {"Shared": {"get": {"x-doc": extension}}}}
        });
        let spec = Spec::parse(document.to_string().as_bytes()).unwrap();
        let builder = build(&spec, 1024 * 1024);

        assert!(builder.skipped_operations > 0);
        assert!(builder.view_bytes <= builder.view_byte_limit);
        assert!(builder.targets.iter().any(|t| t.kind == TargetKind::Operation));
    }

    #[test]
    fn child_views_with_large_operation_ids_are_charged_to_the_view_byte_budget() {
        let operation_id = "x".repeat(1024 * 1024);
        let parameters: Vec<Value> =
            (0..300).map(|i| json!({"name": format!("parameter-{i}"), "in": "query", "schema": {"type": "string"}})).collect();
        let document = json!({
            "openapi": "3.1.0",
            "info": {"title": "test", "version": "1"},
            "paths": {"/large": {"get": {"operationId": operation_id, "parameters": parameters}}}
        });
        let spec = Spec::parse(document.to_string().as_bytes()).unwrap();
        let builder = build(&spec, MAX_MODEL_VIEW_BYTES);

        assert!(builder.view_bytes <= builder.view_byte_limit);
        let parameter_count = builder.targets.iter().filter(|t| t.kind == TargetKind::Parameter).count();
        assert!(parameter_count < 300);
        assert!(parameter_count <= MAX_MODEL_VIEW_BYTES / operation_id.len());
    }

    #[test]
    fn long_path_keys_stop_property_copies_at_the_view_byte_budget() {
        // Every property's pointer, label and parent repeat the path.
        let properties: Map<String, Value> = (0..10_000).map(|i| (format!("p{i}"), json!({"type": "string"}))).collect();
        let parameter = json!({"name": "q", "in": "query", "schema": {"type": "object", "properties": properties}});
        for (path_bytes, limit) in [(40 << 20, MAX_MODEL_VIEW_BYTES), (1 << 20, 40 << 20)] {
            let mut document = json!({"openapi": "3.1.0", "paths": {}});
            document["paths"][format!("/{}", "a".repeat(path_bytes))] = json!({"get": {"parameters": [parameter]}});
            // Past the parser's member-name limit: the model bounds itself.
            let spec = Spec::unchecked(Dialect::OpenApi31, document);
            let builder = build(&spec, limit);

            assert!(builder.exhausted);
            assert!(builder.view_bytes <= limit);
            let copied = builder.targets.iter().filter(|t| t.kind == TargetKind::Property).count();
            assert!(copied <= limit / path_bytes, "{copied}");
            // Nothing is attempted once the budget is spent.
            assert!(builder.reservations < 100, "{}", builder.reservations);
        }
    }

    #[test]
    fn shared_path_items_are_resolved_and_sized_once() {
        let values: Vec<u32> = (0..100_000).collect();
        let paths: Map<String, Value> = (0..2_000).map(|i| (format!("/p{i}"), json!({"$ref": "#/components/pathItems/Shared"}))).collect();
        let header = json!({"schema": {"type": "integer"}, "x-values": values});
        let shared = json!({"get": {
            "parameters": [{"name": "q", "in": "query", "schema": {"type": "integer", "enum": values}}],
            "responses": {"200": {"description": "ok", "x-values": values, "headers": {"X-Values": header}}}
        }});
        let document = json!({
            "openapi": "3.1.0",
            "info": {"title": "test", "version": "1"},
            "paths": paths,
            "components": {"pathItems": {"Shared": shared}}
        });
        let spec = Spec::parse(document.to_string().as_bytes()).unwrap();
        let builder = build(&spec, MAX_MODEL_VIEW_BYTES);

        assert_eq!(builder.skipped_operations, 0);
        assert_eq!(builder.targets.iter().filter(|t| t.kind == TargetKind::Operation).count(), 2_000);
        assert_eq!(builder.targets.iter().filter(|t| t.kind == TargetKind::Response).count(), 1);
        // The shared parameter, response and header are sized once, not once
        // per path.
        assert!(builder.walked < 4 * values.len(), "{}", builder.walked);
    }
}
