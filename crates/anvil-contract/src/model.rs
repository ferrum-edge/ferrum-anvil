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
        for m in METHODS {
            if let Some(op) = item.get(*m).filter(|o| o.is_object()) {
                out.push(OperationRef {
                    method: m.to_string(),
                    path: path.clone(),
                    pointer: ptr(&item_pointer, m),
                    op,
                    item,
                    item_pointer: item_pointer.clone(),
                });
            }
        }
        if spec.dialect == Dialect::OpenApi32 {
            if let Some(op) = item.get("query").filter(|o| o.is_object()) {
                out.push(OperationRef {
                    method: "query".into(),
                    path: path.clone(),
                    pointer: ptr(&item_pointer, "query"),
                    op,
                    item,
                    item_pointer: item_pointer.clone(),
                });
            }
            if let Some(extra) = item.get("additionalOperations").and_then(Value::as_object) {
                let base = ptr(&item_pointer, "additionalOperations");
                for (m, op) in extra.iter().filter(|(_, o)| o.is_object()) {
                    out.push(OperationRef {
                        method: m.to_ascii_lowercase(),
                        path: path.clone(),
                        pointer: ptr(&base, m),
                        op,
                        item,
                        item_pointer: item_pointer.clone(),
                    });
                }
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
    /// Operations left out because the work budget ran out.
    pub skipped_operations: usize,
}

/// Parameters, responses and media types looked at across all operations
/// (path-level ones count again for every operation that inherits them).
/// Past this, the remaining operations are left out and counted.
pub const MAX_MODEL_WORK: usize = 2_000_000;
/// Bytes copied into per-path operation views, counted separately from the
/// object-work budget so ordinary long descriptions do not consume that budget.
pub const MAX_MODEL_VIEW_BYTES: usize = 256 * 1024 * 1024;

impl<'a> Model<'a> {
    pub fn build(spec: &'a Spec, examples: &mut dyn FnMut(&Media<'a>, Direction) -> Vec<String>) -> Model<'a> {
        let mut b = ModelBuilder {
            spec,
            targets: vec![],
            seen: HashSet::new(),
            work: 0,
            view_bytes: 0,
            view_byte_limit: MAX_MODEL_VIEW_BYTES,
            skipped_operations: 0,
        };
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
    work: usize,
    view_bytes: usize,
    view_byte_limit: usize,
    skipped_operations: usize,
}

impl<'a> ModelBuilder<'a> {
    fn push(&mut self, kind: TargetKind, pointer: String, label: String, view: Value) {
        // An operation reached through several paths (one Path Item `$ref`'d
        // by each) is a target per path: its path template differs.
        let key = if kind == TargetKind::Operation { format!("{pointer}#{label}") } else { pointer.clone() };
        if !self.seen.insert((kind, key)) {
            return;
        }
        if kind != TargetKind::Operation {
            let copied_bytes = pointer.len().saturating_add(label.len()).saturating_add(copied_string_bytes(&view));
            if self.view_bytes.saturating_add(copied_bytes) > self.view_byte_limit {
                return;
            }
            self.view_bytes += copied_bytes;
        }
        let Value::Object(view) = view else { return };
        self.targets.push(Target { kind, pointer, label, view });
    }

    fn build(&mut self, examples: &mut dyn FnMut(&Media<'a>, Direction) -> Vec<String>) {
        let spec = self.spec;
        let root = &spec.root;
        let ops = operations(spec);
        let schema_base = if spec.is_swagger2() { "/definitions" } else { "/components/schemas" };
        let referenced = referenced_schemas(root, schema_base);
        let declared_tags: Vec<String> = root
            .get("tags")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(|t| t.get("name").and_then(Value::as_str)).map(str::to_string).collect())
            .unwrap_or_default();
        let scheme_names: HashSet<String> = security_schemes(spec).map(|(m, _)| m.keys().cloned().collect()).unwrap_or_default();
        let mut id_counts: HashMap<&str, usize> = HashMap::new();
        let mut used_tags: HashSet<&str> = HashSet::new();
        let mut used_schemes: HashSet<String> = HashSet::new();
        let mut methods_by_path: HashMap<&str, Vec<&str>> = HashMap::new();
        // The document's requirements once; each operation adds only its own.
        let global_security_names = requirement_names(root.get("security").and_then(Value::as_array));
        used_schemes.extend(global_security_names.iter().cloned());
        for op in &ops {
            if let Some(id) = op.operation_id() {
                *id_counts.entry(id).or_default() += 1;
            }
            used_tags.extend(op.op.get("tags").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str));
            used_schemes.extend(requirement_names(op.op.get("security").and_then(Value::as_array)));
            methods_by_path.entry(op.path.as_str()).or_default().push(op.method.as_str());
        }
        let declared_tag_set: HashSet<String> = declared_tags.iter().cloned().collect();

        // Servers (document level; 2.0 from schemes × host + basePath).
        let mut server_urls = vec![];
        if spec.is_swagger2() {
            if let Some(host) = root.get("host").and_then(Value::as_str) {
                let base = root.get("basePath").and_then(Value::as_str).unwrap_or("");
                let schemes = list_of_strings(root.get("schemes")).filter(|s| !s.is_empty()).unwrap_or_else(|| vec!["https".into()]);
                for s in schemes {
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
                "security": requirement_names(global_security),
                "has_global_security": global_security.is_some_and(|s| !s.is_empty()),
                "path_count": path_count,
                "operation_count": ops.len(),
                "schema_count": component_schemas(spec).map(|(m, _)| m.len()).unwrap_or(0),
                "security_scheme_count": scheme_names.len(),
                "json_schema_dialect": opt_str(root, "jsonSchemaDialect"),
                "has_webhooks": root.get("webhooks").and_then(Value::as_object).is_some_and(|w| !w.is_empty()),
                "consumes": list_of_strings(root.get("consumes")),
                "produces": list_of_strings(root.get("produces")),
                "extensions": extensions(root),
            }),
        );
        if let Some(info) = root.get("info") {
            let contact =
                info.get("contact").map(|c| json!({"name": opt_str(c, "name"), "url": opt_str(c, "url"), "email": opt_str(c, "email")}));
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

        // Tags.
        if let Some(tags) = root.get("tags").and_then(Value::as_array) {
            for (i, t) in tags.iter().enumerate() {
                let name = t.get("name").and_then(Value::as_str).unwrap_or("");
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
        if let Some(paths) = root.get("paths").and_then(Value::as_object) {
            for (path, raw) in paths.iter().filter(|(k, _)| !k.starts_with("x-")) {
                let Some((item, pointer)) = spec.usable(raw, &ptr("/paths", path)) else { continue };
                let methods: Vec<&str> = methods_by_path.get(path.as_str()).cloned().unwrap_or_default();
                let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
                let static_segments: Vec<&str> = segments.iter().copied().filter(|s| !s.contains('{')).collect();
                self.push(
                    TargetKind::Path,
                    pointer,
                    format!("path {path}"),
                    json!({
                        "path": path,
                        "operations": methods,
                        "segments": segments,
                        "static_segments": static_segments,
                        "template_params": template_params(path),
                        "extensions": extensions(item),
                    }),
                );
                self.servers(item.get("servers"), &ptr(&ptr("/paths", path), "servers"), "path", &mut vec![]);
            }
        }

        // Operations and everything under them.
        for op in &ops {
            if self.work > MAX_MODEL_WORK {
                self.skipped_operations += 1;
                continue;
            }
            self.operation(op, &declared_tag_set, &global_security_names, &scheme_names, &id_counts, examples);
        }

        // Security schemes.
        if let Some((schemes, base)) = security_schemes(spec) {
            for (name, raw) in schemes {
                let Some((s, pointer)) = spec.usable(raw, &ptr(&base, name)) else { continue };
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
                let (ty, types, nullable) = schema_types(raw);
                let properties: Vec<String> =
                    raw.get("properties").and_then(Value::as_object).map(|p| p.keys().cloned().collect()).unwrap_or_default();
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
            let url = s.get("url").and_then(Value::as_str).unwrap_or("").to_string();
            urls.push(url.clone());
            let variables: Vec<String> =
                s.get("variables").and_then(Value::as_object).map(|v| v.keys().cloned().collect()).unwrap_or_default();
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
        let label = op.label();
        let params = parameters(spec, op);
        let body = request_body(spec, op);
        let resps = responses(spec, op);
        // Inheriting operations reuse the document's names (gathered once).
        let own_security = op.op.get("security").and_then(Value::as_array);
        let security_names = match own_security {
            Some(reqs) => requirement_names(Some(reqs)),
            None => global_security_names.to_vec(),
        };
        // Everything below is proportional to these (inherited parameters and
        // the document's security count for every operation).
        self.work += 1
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
        if self.work > MAX_MODEL_WORK {
            self.skipped_operations += 1;
            return;
        }
        let tags = list_of_strings(op.op.get("tags")).unwrap_or_default();
        let template = template_params(&op.path);
        let path_params: Vec<&str> = params.iter().filter(|p| p.location == "path").map(|p| p.name.as_str()).collect();
        let codes: Vec<&str> = resps.iter().map(|r| r.code.as_str()).collect();
        let class = |c: &str, first: char| c.starts_with(first);
        // The same name and location twice in one parameter list.
        let mut dup_params = BTreeSet::new();
        let levels =
            [(op.item.get("parameters"), ptr(&op.item_pointer, "parameters")), (op.op.get("parameters"), ptr(&op.pointer, "parameters"))];
        for (list, base) in levels {
            let mut this_level = HashSet::new();
            for (i, raw) in list.and_then(Value::as_array).into_iter().flatten().enumerate() {
                let Some((p, _)) = spec.usable(raw, &ptr(&base, &i.to_string())) else { continue };
                let name = p.get("name").and_then(Value::as_str).unwrap_or("");
                let location = p.get("in").and_then(Value::as_str).unwrap_or("");
                if !this_level.insert((name, location)) {
                    dup_params.insert(format!("{name} ({location})"));
                }
            }
        }
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
                "has_request_body": body.is_some(),
                "request_content_types": body.as_ref().map(|b| b.media.iter().map(|m| m.media_type.clone()).collect::<Vec<_>>()).unwrap_or_default(),
                "response_codes": codes,
                "success_codes": codes.iter().filter(|c| class(c, '2') || class(c, '3')).collect::<Vec<_>>(),
                "error_codes": codes.iter().filter(|c| class(c, '4') || class(c, '5')).collect::<Vec<_>>(),
                "client_error_codes": codes.iter().filter(|c| class(c, '4')).collect::<Vec<_>>(),
                "server_error_codes": codes.iter().filter(|c| class(c, '5')).collect::<Vec<_>>(),
                "has_default_response": codes.contains(&"default"),
                "response_content_types": resps.iter().flat_map(|r| r.media.iter().map(|m| m.media_type.clone())).collect::<BTreeSet<_>>(),
                "security": security_names,
                // A requirement naming no scheme (`{}`) makes security optional.
                "has_security": !security_names.is_empty(),
                "has_explicit_security": op.op.get("security").is_some(),
                "callbacks": op.op.get("callbacks").and_then(Value::as_object).map(|c| c.keys().cloned().collect::<Vec<_>>()).unwrap_or_default(),
                "operation_id_duplicate": operation_id.is_some_and(|id| id_counts.get(id).copied().unwrap_or(0) > 1),
                "undeclared_path_params": template.iter().filter(|t| !path_params.contains(&t.as_str())).collect::<Vec<_>>(),
                "unused_path_params": path_params.iter().filter(|p| !template.iter().any(|t| t == *p)).collect::<Vec<_>>(),
                "undeclared_tags": list_of_strings(op.op.get("tags")).unwrap_or_default().into_iter().filter(|t| !declared_tags.contains(t)).collect::<Vec<_>>(),
                "undefined_security_schemes": security_names.iter().filter(|n| !scheme_names.contains(*n)).collect::<Vec<_>>(),
                "duplicate_parameters": dup_params,
                "extensions": extensions(op.op),
        });
        let copied_bytes = op.pointer.len().saturating_add(label.len()).saturating_add(copied_string_bytes(&operation_view));
        if self.view_bytes.saturating_add(copied_bytes) > self.view_byte_limit {
            self.skipped_operations += 1;
            return;
        }
        self.view_bytes += copied_bytes;
        self.push(TargetKind::Operation, op.pointer.clone(), label.clone(), operation_view);
        let ctx =
            json!({"method": op.method, "method_upper": op.method.to_ascii_uppercase(), "path": op.path, "operation_id": operation_id});

        for p in &params {
            // A Swagger 2.0 body parameter is the request body target; a
            // shared (inherited or `$ref`'d) parameter is one target.
            if p.location == "body" || self.seen.contains(&(TargetKind::Parameter, p.pointer.clone())) {
                continue;
            }
            let schema = p.value.get("schema").unwrap_or(p.value);
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
                self.properties(s, &ptr(&p.pointer, "schema"), &format!("{label} {} parameter {}", p.location, p.name), 0);
            }
        }

        // A shared (`$ref`'d) body or response is one target: built once.
        if let Some(body) = body.as_ref().filter(|b| !self.seen.contains(&(TargetKind::RequestBody, b.pointer.clone()))) {
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

        for r in &resps {
            if self.seen.contains(&(TargetKind::Response, r.pointer.clone())) {
                continue;
            }
            let headers: Vec<String> =
                r.value.get("headers").and_then(Value::as_object).map(|h| h.keys().cloned().collect()).unwrap_or_default();
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
            if let Some(h) = r.value.get("headers").and_then(Value::as_object) {
                for (name, raw) in h {
                    let Some((hv, hptr)) = spec.usable(raw, &ptr(&ptr(&r.pointer, "headers"), name)) else { continue };
                    let schema = hv.get("schema").unwrap_or(hv);
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
        // A Swagger 2.0 media type shares its pointer with its response; key
        // the target by media type too.
        let pointer = if self.spec.is_swagger2() { format!("{}#{}", m.pointer, m.media_type) } else { m.pointer.clone() };
        if self.seen.contains(&(TargetKind::MediaType, pointer.clone())) {
            return;
        }
        let obj = m.object.unwrap_or(&Value::Null);
        let has_example = if self.spec.is_swagger2() {
            obj.pointer(&format!("/examples/{}", m.media_type.replace('~', "~0").replace('/', "~1"))).is_some()
                || m.schema.is_some_and(|s| s.get("example").is_some())
        } else {
            obj.get("example").is_some()
                || obj.get("examples").and_then(Value::as_object).is_some_and(|e| !e.is_empty())
                || m.schema.is_some_and(|s| s.get("example").is_some() || s.get("examples").is_some())
        };
        let where_ = match code {
            Some(c) => format!("{c} response of {label}"),
            None => format!("request body of {label}"),
        };
        let (ty, _, _) = m.schema.map(|s| schema_types(self.spec.deref(s, &m.schema_pointer).0)).unwrap_or((Value::Null, vec![], false));
        let mut view = json!({
            "media_type": m.media_type,
            "direction": match direction { Direction::Request => "request", Direction::Response => "response" },
            "code": code,
            "has_schema": m.schema.is_some(),
            "schema_type": ty,
            "schema_is_ref": m.schema.is_some_and(|s| s.get("$ref").is_some()),
            "has_example": has_example,
            "example_errors": examples(m, direction),
            "extensions": extensions(obj),
        });
        merge(&mut view, ctx);
        self.push(TargetKind::MediaType, pointer, format!("{} in the {where_}", m.media_type), view);
        if let Some(s) = m.schema {
            self.properties(s, &m.schema_pointer, &format!("{where_} ({})", m.media_type), 0);
        }
    }

    /// Properties of an inline schema (not following `$ref`: referenced
    /// schemas are visited as components), through `items`, compositions and
    /// `additionalProperties`.
    fn properties(&mut self, schema: &Value, pointer: &str, owner: &str, depth: usize) {
        if depth > 24 || schema.get("$ref").is_some() {
            return;
        }
        if let Some(props) = schema.get("properties").and_then(Value::as_object) {
            let required: Vec<&str> =
                schema.get("required").and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_str).collect()).unwrap_or_default();
            for (name, p) in props {
                let pptr = ptr(&ptr(pointer, "properties"), name);
                let (ty, types, nullable) = schema_types(p);
                self.push(
                    TargetKind::Property,
                    pptr.clone(),
                    format!("property {name} of {owner}"),
                    json!({
                        "name": name,
                        "parent": owner,
                        "required": required.contains(&name.as_str()),
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
            self.properties(items, &ptr(pointer, "items"), &format!("{owner}[]"), depth + 1);
        }
        for key in ["allOf", "oneOf", "anyOf"] {
            if let Some(list) = schema.get(key).and_then(Value::as_array) {
                for (i, s) in list.iter().enumerate() {
                    self.properties(s, &ptr(&ptr(pointer, key), &i.to_string()), owner, depth + 1);
                }
            }
        }
        if let Some(ap) = schema.get("additionalProperties").filter(|a| a.is_object()) {
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

fn copied_string_bytes(value: &Value) -> usize {
    match value {
        Value::String(s) => s.len(),
        Value::Array(values) => values.iter().fold(0usize, |sum, value| sum.saturating_add(copied_string_bytes(value))),
        Value::Object(values) => values
            .iter()
            .fold(0usize, |sum, (key, value)| sum.saturating_add(key.len()).saturating_add(copied_string_bytes(value))),
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let mut builder = ModelBuilder {
            spec: &spec,
            targets: vec![],
            seen: HashSet::new(),
            work: 0,
            view_bytes: 0,
            view_byte_limit: 1024 * 1024,
            skipped_operations: 0,
        };
        builder.build(&mut |_, _| vec![]);

        assert!(builder.skipped_operations > 0);
        assert!(builder.view_bytes <= builder.view_byte_limit);
        assert!(builder.targets.iter().any(|t| t.kind == TargetKind::Operation));
    }

    #[test]
    fn child_views_with_large_operation_ids_are_charged_to_the_view_byte_budget() {
        let operation_id = "x".repeat(1024 * 1024);
        let parameters: Vec<Value> = (0..300)
            .map(|i| json!({"name": format!("parameter-{i}"), "in": "query", "schema": {"type": "string"}}))
            .collect();
        let document = json!({
            "openapi": "3.1.0",
            "info": {"title": "test", "version": "1"},
            "paths": {"/large": {"get": {"operationId": operation_id, "parameters": parameters}}}
        });
        let spec = Spec::parse(document.to_string().as_bytes()).unwrap();
        let mut builder = ModelBuilder {
            spec: &spec,
            targets: vec![],
            seen: HashSet::new(),
            work: 0,
            view_bytes: 0,
            view_byte_limit: MAX_MODEL_VIEW_BYTES,
            skipped_operations: 0,
        };
        builder.build(&mut |_, _| vec![]);

        assert!(builder.view_bytes <= builder.view_byte_limit);
        assert!(builder.targets.iter().filter(|t| t.kind == TargetKind::Parameter).count() < 300);
    }
}
