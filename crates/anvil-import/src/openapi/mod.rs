//! OpenAPI 3.0 / 3.1 / 3.2 and Swagger 2.0 import.
//!
//! Each dialect is handled explicitly. Constructs introduced in OpenAPI 3.2
//! (`query` operations, `additionalOperations`, `in: querystring`, the
//! `cookie` style, hierarchical tags, example `dataValue`/`serializedValue`,
//! XML `nodeType`, server `name`) are only honored in 3.2 documents; found
//! in older documents they are reported. 3.2 constructs this importer does
//! not implement (`itemSchema` streams, `prefixEncoding`/`itemEncoding`,
//! `$self` base URIs, `oauth2MetadataUrl` discovery, the device
//! authorization flow, URI-valued security requirements pointing outside
//! the document) are reported as unsupported.

mod body;
mod params;
mod refs;
mod schema;
mod security;

use crate::builder::Builder;
use crate::util::{fnv1a64, is_credential_name, ptr, sanitize_var, scalar_text, str_of};
use crate::{Dialect, GroupBy, ImportError, SampleMode};
use anvil_domain::Id;
use anvil_domain::auth::AuthConfig;
use anvil_domain::request::{Body, KeyValue, RequestSpec};
use anvil_domain::workspace::Variable;
use params::Location;
use refs::Refs;
use schema::SampleGen;
use serde_json::{Map, Value, json};
use std::collections::HashMap;

pub(crate) struct Ctx<'a> {
    pub root: &'a Value,
    pub dialect: Dialect,
    pub refs: Refs<'a>,
}

const METHODS: &[&str] = &["get", "put", "post", "delete", "options", "head", "patch", "trace"];

fn is_32(d: Dialect) -> bool {
    d == Dialect::OpenApi32
}

fn only_32(ctx: &Ctx, b: &mut Builder, at: &str, what: &str) {
    b.report.warn(
        "openapi32_construct",
        at,
        format!("{what} is an OpenAPI 3.2 construct; it is ignored in a {} document", ctx.dialect.label()),
    );
}

pub(crate) fn import(root: &Value, dialect: Dialect, b: &mut Builder) -> Result<(), ImportError> {
    if !root.is_object() {
        return Err(ImportError::Invalid { dialect, pointer: String::new(), message: "the document is not an object".into() });
    }
    let ctx = Ctx { root, dialect, refs: Refs { root, max_depth: b.opts.max_ref_depth, max_expansions: b.opts.max_ref_expansions } };

    // Info.
    let info = root.get("info").cloned().unwrap_or(Value::Null);
    let title = str_of(&info, "title").unwrap_or("").trim().to_string();
    let version = info.get("version").map(scalar_text).unwrap_or_default();
    if !title.is_empty() {
        b.title = Some(title.clone());
        b.workspace.name = if version.is_empty() { title } else { format!("{title} {version}") };
    }
    let mut desc = vec![];
    for k in ["summary", "description"] {
        if let Some(s) = str_of(&info, k) {
            desc.push(s.to_string());
        }
    }
    b.workspace.description = desc.join("\n\n");

    dialect_checks(&ctx, b);
    import_servers(&ctx, b);

    // Global security → workspace auth (operations without their own
    // `security` inherit it).
    let global_sec = root.get("security").cloned();
    b.workspace.auth = match &global_sec {
        Some(req) => security::requirement_auth(&ctx, b, req, "/security"),
        None => AuthConfig::None,
    };

    let tags = TagIndex::new(&ctx, b);
    let mut folder_order: Vec<(Id, usize)> = vec![];
    match root.get("paths") {
        Some(Value::Object(paths)) => {
            for (path, item) in paths {
                let pptr = ptr("/paths", path);
                if path.starts_with("x-") {
                    continue;
                }
                if !path.starts_with('/') {
                    b.report.warn("path_not_absolute", &pptr, format!("path '{path}' does not start with '/'; used as written"));
                }
                import_path_item(&ctx, b, path, item, &pptr, global_sec.as_ref(), &tags, &mut folder_order);
            }
        }
        Some(_) => b.report.warn("invalid_paths", "/paths", "`paths` is not an object; no operations imported"),
        None if matches!(dialect, Dialect::Swagger20 | Dialect::OpenApi30) => {
            b.report.warn("missing_paths", "/paths", format!("{} requires `paths`; no operations imported", dialect.label()))
        }
        None => {}
    }
    // Declared tag order first, then first appearance.
    folder_order.sort_by_key(|(_, rank)| *rank);
    for (i, (id, _)) in folder_order.iter().enumerate() {
        if let Some(f) = b.folder_mut(*id) {
            f.sort_key = (i + 1) as f64;
        }
    }
    if let Some(Value::Object(w)) = root.get("webhooks") {
        for name in w.keys() {
            b.report.unsupported(
                "webhook_not_imported",
                &ptr("/webhooks", name),
                "webhooks describe requests the API sends to you; they are not imported as requests",
            );
        }
    }
    Ok(())
}

fn dialect_checks(ctx: &Ctx, b: &mut Builder) {
    let root = ctx.root;
    if let Some(d) = str_of(root, "jsonSchemaDialect")
        && !d.starts_with("https://spec.openapis.org/oas/3.")
    {
        b.report.warn(
            "json_schema_dialect",
            "/jsonSchemaDialect",
            format!("custom JSON Schema dialect '{d}' is not implemented; schemas are interpreted with OpenAPI base semantics"),
        );
    }
    if root.get("$self").is_some() {
        if is_32(ctx.dialect) {
            b.report.unsupported(
                "self_base_uri",
                "/$self",
                "`$self` only affects resolution of external references, which are never fetched during import",
            );
        } else {
            only_32(ctx, b, "/$self", "`$self`");
        }
    }
    if ctx.dialect == Dialect::OpenApi30 && root.get("webhooks").is_some() {
        b.report.warn("openapi31_construct", "/webhooks", "`webhooks` is an OpenAPI 3.1+ construct in a 3.0 document");
    }
}

/// Servers → one environment each with `baseUrl` and the server variables.
fn import_servers(ctx: &Ctx, b: &mut Builder) {
    let mut envs: Vec<(String, String, Vec<Variable>)> = vec![];
    if ctx.dialect == Dialect::Swagger20 {
        let host = str_of(ctx.root, "host").map(str::to_string);
        let base_path = str_of(ctx.root, "basePath").unwrap_or("").trim_end_matches('/').to_string();
        let schemes: Vec<String> = ctx
            .root
            .get("schemes")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect())
            .filter(|v: &Vec<String>| !v.is_empty())
            .unwrap_or_else(|| vec!["https".into()]);
        if ctx.root.get("schemes").is_none() {
            b.report.warn(
                "swagger_default_scheme",
                "/schemes",
                "no `schemes`: https is assumed (Swagger 2.0 defaults to the scheme used to fetch the spec)",
            );
        }
        for s in schemes {
            let url = match &host {
                Some(h) => format!("{s}://{h}{base_path}"),
                None => {
                    b.report.require_var("origin", false, "the spec has no `host`; set scheme://host of the API", "/host");
                    format!("{{{{origin}}}}{base_path}")
                }
            };
            envs.push((url.clone(), url.clone(), vec![Variable::plain("baseUrl", &url)]));
        }
    } else {
        let servers = ctx
            .root
            .get("servers")
            .and_then(Value::as_array)
            .cloned()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| vec![json!({"url": "/"})]);
        for (i, s) in servers.iter().enumerate() {
            let sptr = format!("/servers/{i}");
            let (url, vars) = server_url(b, s, &sptr, false);
            let name = str_of(s, "name")
                .filter(|_| is_32(ctx.dialect))
                .or_else(|| str_of(s, "description"))
                .or_else(|| str_of(s, "url"))
                .unwrap_or("/")
                .to_string();
            if s.get("name").is_some() && !is_32(ctx.dialect) {
                only_32(ctx, b, &ptr(&sptr, "name"), "server `name`");
            }
            let mut all = vec![Variable::plain("baseUrl", &url)];
            all.extend(vars);
            envs.push((name, url, all));
        }
    }
    let mut ids = vec![];
    for (i, (name, _, vars)) in envs.into_iter().enumerate() {
        ids.push(b.add_environment(&format!("server:{i}"), &name, vars));
    }
    if !ids.is_empty() {
        let idx = if b.opts.server_index < ids.len() {
            b.opts.server_index
        } else {
            b.report.warn(
                "server_index_out_of_range",
                "/servers",
                format!("server_index {} is out of range ({} servers); the first server is active", b.opts.server_index, ids.len()),
            );
            0
        };
        b.workspace.active_environment_id = Some(ids[idx]);
    }
}

/// Convert an OpenAPI 3 server object into a base URL. With `inline`,
/// server variables are replaced by their defaults (operation/path-level
/// overrides); otherwise they become `{{variables}}` defined in the
/// environment.
fn server_url(b: &mut Builder, s: &Value, sptr: &str, inline: bool) -> (String, Vec<Variable>) {
    let raw = str_of(s, "url").unwrap_or("/").trim().to_string();
    let decl = s.get("variables").and_then(Value::as_object).cloned().unwrap_or_default();
    let mut vars = vec![];
    let mut out = String::new();
    let mut rest = raw.as_str();
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        let Some(close) = after.find('}') else {
            out.push_str(&rest[open..]);
            rest = "";
            break;
        };
        let name = &after[..close];
        rest = &after[close + 1..];
        let vptr = ptr(&ptr(sptr, "variables"), name);
        let def = decl.get(name).and_then(|d| d.get("default")).map(scalar_text);
        if decl.get(name).is_none() {
            b.report.warn("undeclared_server_variable", sptr, format!("server URL uses '{{{name}}}' but does not declare it"));
        }
        if let Some(e) = decl.get(name).and_then(|d| d.get("enum")).and_then(Value::as_array)
            && let Some(d) = &def
            && !e.iter().any(|x| scalar_text(x) == *d)
        {
            b.report.warn("contradictory_schema", &vptr, format!("default '{d}' is not one of the server variable's enum values"));
        }
        match (inline, def) {
            (true, Some(d)) => out.push_str(&d),
            (_, d) => {
                let v = sanitize_var(name);
                out.push_str(&format!("{{{{{v}}}}}"));
                match d {
                    Some(d) => {
                        let mut var = Variable::plain(&v, &d);
                        if let Some(e) = decl.get(name).and_then(|x| x.get("enum")).and_then(Value::as_array) {
                            var.description = format!("one of: {}", e.iter().map(scalar_text).collect::<Vec<_>>().join(", "));
                        }
                        if let Some(dsc) = decl.get(name).and_then(|x| str_of(x, "description")) {
                            var.description =
                                if var.description.is_empty() { dsc.to_string() } else { format!("{dsc} ({})", var.description) };
                        }
                        vars.push(var);
                    }
                    None => b.report.require_var(&v, false, "server variable without a default", &vptr),
                }
            }
        }
    }
    out.push_str(rest);
    let mut url = out.trim_end_matches('/').to_string();
    if !url.contains("://") && !url.starts_with("{{") {
        let origin = if let Some(p) = url.strip_prefix('/') { format!("{{{{origin}}}}/{p}") } else { format!("{{{{origin}}}}{url}") };
        b.report.require_var(
            "origin",
            false,
            "server URL is relative to the document location; set scheme://host of the API",
            &ptr(sptr, "url"),
        );
        b.report.warn(
            "relative_server_url",
            &ptr(sptr, "url"),
            format!("server URL '{raw}' is relative; it is prefixed with {{{{origin}}}}"),
        );
        url = origin.trim_end_matches('/').to_string();
    }
    (url, vars)
}

struct TagIndex {
    order: HashMap<String, usize>,
    parent: HashMap<String, String>,
    description: HashMap<String, String>,
}

impl TagIndex {
    fn new(ctx: &Ctx, b: &mut Builder) -> Self {
        let mut t = TagIndex { order: HashMap::new(), parent: HashMap::new(), description: HashMap::new() };
        if let Some(tags) = ctx.root.get("tags").and_then(Value::as_array) {
            for (i, tag) in tags.iter().enumerate() {
                let Some(name) = str_of(tag, "name") else { continue };
                t.order.entry(name.to_string()).or_insert(i);
                let mut d = vec![];
                if let Some(s) = str_of(tag, "summary") {
                    if is_32(ctx.dialect) {
                        d.push(s.to_string());
                    } else {
                        only_32(ctx, b, &format!("/tags/{i}/summary"), "tag `summary`");
                    }
                }
                if let Some(s) = str_of(tag, "description") {
                    d.push(s.to_string());
                }
                t.description.insert(name.to_string(), d.join("\n\n"));
                if let Some(p) = str_of(tag, "parent") {
                    if is_32(ctx.dialect) {
                        t.parent.insert(name.to_string(), p.to_string());
                    } else {
                        only_32(ctx, b, &format!("/tags/{i}/parent"), "tag `parent`");
                    }
                }
                if tag.get("kind").is_some() && !is_32(ctx.dialect) {
                    only_32(ctx, b, &format!("/tags/{i}/kind"), "tag `kind`");
                }
            }
        }
        t
    }

    /// Folder for a tag, creating parent-tag folders first (3.2).
    fn folder(&self, b: &mut Builder, tag: &str, order: &mut Vec<(Id, usize)>, depth: usize) -> Id {
        let parent = match self.parent.get(tag) {
            Some(p) if depth < 16 && p != tag => Some(self.folder(b, p, order, depth + 1)),
            Some(_) => {
                b.report.warn("tag_parent_cycle", "/tags", format!("tag '{tag}' has a cyclic or too deep `parent` chain"));
                None
            }
            None => None,
        };
        let key = format!("tag:{tag}");
        let before = b.folders.len();
        let id = b.folder(parent, &key, tag);
        if b.folders.len() > before {
            if let Some(d) = self.description.get(tag)
                && let Some(f) = b.folder_mut(id)
            {
                f.description = d.clone();
            }
            // Declared tags keep their declaration order; undeclared ones
            // follow in order of first use.
            let rank = self.order.get(tag).copied().unwrap_or(1_000_000 + order.len());
            order.push((id, rank));
        }
        id
    }
}

#[allow(clippy::too_many_arguments)]
fn import_path_item(
    ctx: &Ctx,
    b: &mut Builder,
    path: &str,
    item: &Value,
    pptr: &str,
    global_sec: Option<&Value>,
    tags: &TagIndex,
    order: &mut Vec<(Id, usize)>,
) {
    // Path Item `$ref` (local fields win over the referenced ones).
    let mut merged: Map<String, Value> = match ctx.refs.resolve(item, pptr, &mut b.report) {
        Some((t, _)) => t.as_object().cloned().unwrap_or_default(),
        None => {
            b.skipped();
            return;
        }
    };
    if let Some(local) = item.as_object() {
        for (k, v) in local {
            if k != "$ref" {
                merged.insert(k.clone(), v.clone());
            }
        }
    }
    let item = Value::Object(merged);
    let mut ops: Vec<(String, &Value, String)> = vec![];
    for m in METHODS {
        if let Some(op) = item.get(*m) {
            ops.push((m.to_uppercase(), op, ptr(pptr, m)));
        }
    }
    if let Some(op) = item.get("query") {
        if is_32(ctx.dialect) {
            ops.push(("QUERY".into(), op, ptr(pptr, "query")));
        } else {
            only_32(ctx, b, &ptr(pptr, "query"), "the `query` operation");
        }
    }
    if let Some(Value::Object(extra)) = item.get("additionalOperations") {
        if is_32(ctx.dialect) {
            for (m, op) in extra {
                let upper = m.to_ascii_uppercase();
                let aptr = ptr(&ptr(pptr, "additionalOperations"), m);
                if !upper.bytes().all(|c| c.is_ascii_alphabetic() || c == b'-' || c == b'_') {
                    b.report.warn("invalid_method", &aptr, format!("'{m}' is not a valid HTTP method token; skipped"));
                    continue;
                }
                if METHODS.contains(&m.to_ascii_lowercase().as_str()) || upper == "QUERY" {
                    b.report.warn("invalid_method", &aptr, format!("'{m}' must use its fixed Path Item field; skipped"));
                    continue;
                }
                ops.push((upper, op, aptr));
            }
        } else {
            only_32(ctx, b, &ptr(pptr, "additionalOperations"), "`additionalOperations`");
        }
    }
    let path_params = item.get("parameters").cloned().unwrap_or(Value::Array(vec![]));
    let path_servers = item.get("servers").cloned();
    for (method, op, optr) in ops {
        if !b.admit(&optr) {
            continue;
        }
        import_operation(ctx, b, path, &method, op, &optr, &path_params, pptr, path_servers.as_ref(), global_sec, tags, order);
    }
}

struct ParamOut {
    query: Vec<KeyValue>,
    headers: Vec<KeyValue>,
    cookies_required: Vec<String>,
    cookies_all: Vec<String>,
    path_values: HashMap<String, String>,
    body_params: Option<(Value, String)>,
    form_params: Vec<(Value, String)>,
}

/// Merge path-level and operation-level parameters (operation wins on the
/// same name + location). Returns (param, pointer) pairs.
fn merged_params(ctx: &Ctx, b: &mut Builder, path_params: &Value, pptr: &str, op: &Value, optr: &str) -> Vec<(Value, String)> {
    let mut out: Vec<(Value, String)> = vec![];
    let mut add = |b: &mut Builder, list: &Value, base: &str| {
        let Some(a) = list.as_array() else { return };
        for (i, p) in a.iter().enumerate() {
            let at = format!("{base}/{i}");
            let Some((p, pp)) = ctx.refs.resolve(p, &at, &mut b.report) else { continue };
            let name = str_of(p, "name").unwrap_or("").to_string();
            let loc = str_of(p, "in").unwrap_or("").to_string();
            let norm = |n: &str| if loc == "header" { n.to_ascii_lowercase() } else { n.to_string() };
            if let Some(slot) =
                out.iter_mut().find(|(q, _)| str_of(q, "in") == Some(loc.as_str()) && norm(str_of(q, "name").unwrap_or("")) == norm(&name))
            {
                *slot = (p.clone(), pp);
            } else {
                out.push((p.clone(), pp));
            }
        }
    };
    add(b, path_params, &ptr(pptr, "parameters"));
    if let Some(ps) = op.get("parameters") {
        add(b, ps, &ptr(optr, "parameters"));
    }
    out
}

fn param_value(sg: &mut SampleGen, p: &Value, pp: &str) -> Option<Value> {
    if sg.mode == SampleMode::Sample {
        match body::explicit_example(sg, p, pp) {
            Some(body::Explicit::Value(v)) => return Some(v),
            Some(body::Explicit::Serialized(s)) => return Some(Value::String(s)),
            None => {}
        }
        if let Some(v) = p.get("x-example") {
            return Some(v.clone());
        }
    }
    if let Some(s) = p.get("schema") {
        return sg.generate(s, &ptr(pp, "schema"), str_of(p, "name"));
    }
    if let Some((mt, media)) = p.get("content").and_then(Value::as_object).and_then(|m| m.iter().next()) {
        let mptr = ptr(&ptr(pp, "content"), mt);
        if sg.mode == SampleMode::Sample
            && let Some(body::Explicit::Value(v)) = body::explicit_example(sg, media, &mptr)
        {
            return Some(v);
        }
        return media.get("schema").and_then(|s| sg.generate(s, &ptr(&mptr, "schema"), str_of(p, "name")));
    }
    // Swagger 2.0 non-body parameters are schema-like themselves.
    if p.get("type").is_some() {
        let mut s = p.clone();
        if let Some(o) = s.as_object_mut() {
            for k in ["name", "in", "required", "description", "collectionFormat", "allowEmptyValue"] {
                o.remove(k);
            }
        }
        return sg.generate(&s, pp, str_of(p, "name"));
    }
    None
}

fn process_params(ctx: &Ctx, sg: &mut SampleGen, params: &[(Value, String)], blank_vars: &mut Vec<(String, String)>) -> ParamOut {
    let mut out = ParamOut {
        query: vec![],
        headers: vec![],
        cookies_required: vec![],
        cookies_all: vec![],
        path_values: HashMap::new(),
        body_params: None,
        form_params: vec![],
    };
    for (p, pp) in params {
        sg.reset_budget();
        let name = str_of(p, "name").unwrap_or("").to_string();
        let raw_loc = str_of(p, "in").unwrap_or("");
        if ctx.dialect == Dialect::Swagger20 {
            match raw_loc {
                "body" => {
                    out.body_params = Some((p.clone(), pp.clone()));
                    continue;
                }
                "formData" => {
                    out.form_params.push((p.clone(), pp.clone()));
                    continue;
                }
                _ => {}
            }
        }
        let Some(loc) = Location::parse(raw_loc) else {
            sg.report.warn("invalid_parameter_location", pp, format!("parameter location '{raw_loc}' is not valid; parameter skipped"));
            continue;
        };
        if loc == Location::QueryString && !is_32(ctx.dialect) {
            sg.report.warn(
                "openapi32_construct",
                pp,
                format!("`in: querystring` is an OpenAPI 3.2 construct; ignored in a {} document", ctx.dialect.label()),
            );
            continue;
        }
        let required = p.get("required").and_then(Value::as_bool).unwrap_or(false) || loc == Location::Path;
        let enabled = required || sg.include_optional;
        let mut description = str_of(p, "description").unwrap_or("").to_string();
        if p.get("deprecated").and_then(Value::as_bool) == Some(true) {
            description = format!("[deprecated] {description}").trim().to_string();
        }
        if p.get("allowReserved").and_then(Value::as_bool) == Some(true) {
            sg.report.warn(
                "allow_reserved_not_preserved",
                pp,
                "allowReserved is not preserved: reserved characters in the value are percent-encoded when sent",
            );
        }
        let (mut style, mut explode) = {
            let s = str_of(p, "style").unwrap_or(loc.default_style()).to_string();
            let e = p.get("explode").and_then(Value::as_bool).unwrap_or(s == "form" || s == "cookie");
            (s, e)
        };
        if style == "cookie" && !is_32(ctx.dialect) {
            sg.report.warn("openapi32_construct", &ptr(pp, "style"), "the `cookie` style is an OpenAPI 3.2 construct; `form` used");
            style = "form".into();
        }
        let mut tab = false;
        if ctx.dialect == Dialect::Swagger20 && p.get("type").and_then(Value::as_str) == Some("array") {
            let (s, e) = params::collection_format(str_of(p, "collectionFormat").unwrap_or("csv"), loc);
            tab = s == "tabDelimited";
            style = s.to_string();
            explode = e;
        }
        let credential = is_credential_name(&name) && loc != Location::Path;
        // Header names the OpenAPI spec says to ignore.
        if loc == Location::Header && ["accept", "content-type", "authorization"].contains(&name.to_ascii_lowercase().as_str()) {
            sg.report.warn(
                "ignored_header_parameter",
                pp,
                format!("header parameter '{name}' is ignored per the OpenAPI specification (use media types / security schemes)"),
            );
            continue;
        }

        let value = if credential {
            let v = sanitize_var(&name);
            sg.report.require_var(&v, true, &format!("credential-like {raw_loc} parameter '{name}'"), pp);
            Some(Value::String(format!("{{{{{v}}}}}")))
        } else if sg.mode == SampleMode::Blank {
            None
        } else {
            param_value(sg, p, pp)
        };

        match loc {
            Location::Path => {
                let text = match &value {
                    Some(v) => {
                        let (t, w) = params::path_value(&name, &style, explode, v);
                        if let Some(w) = w {
                            sg.report.warn("parameter_style", pp, w);
                        }
                        t
                    }
                    None => {
                        let v = sanitize_var(&name);
                        blank_vars.push((v.clone(), pp.clone()));
                        format!("{{{{{v}}}}}")
                    }
                };
                out.path_values.insert(name.clone(), text);
            }
            Location::Query | Location::QueryString => {
                let pairs = match &value {
                    None => vec![(name.clone(), String::new())],
                    Some(v) if loc == Location::QueryString => match v {
                        Value::Object(m) => m.iter().map(|(k, x)| (k.clone(), scalar_text(x))).collect(),
                        other => {
                            sg.report.unsupported(
                                "querystring_parameter",
                                pp,
                                "only object-valued form-encoded `querystring` parameters are generated",
                            );
                            vec![(name.clone(), scalar_text(other))]
                        }
                    },
                    Some(v) if p.get("content").is_some() => vec![(name.clone(), v.to_string())],
                    Some(v) if tab => params::tab_delimited(&name, v),
                    Some(v) => {
                        let (pairs, w) = params::query_pairs(&name, &style, explode, v);
                        if let Some(w) = w {
                            sg.report.warn("parameter_style", pp, w);
                        }
                        pairs
                    }
                };
                for (k, v) in pairs {
                    out.query.push(KeyValue { name: k, value: v, enabled, description: description.clone(), sensitive: credential });
                }
            }
            Location::Header => {
                let text = match &value {
                    None => String::new(),
                    Some(v) if p.get("content").is_some() => v.to_string(),
                    Some(v) => params::header_value(explode, v),
                };
                out.headers.push(KeyValue { name: name.clone(), value: text, enabled, description, sensitive: credential });
            }
            Location::Cookie => {
                let pairs = match &value {
                    None => vec![(name.clone(), String::new())],
                    Some(v) => params::query_pairs(&name, &style, explode, v).0,
                };
                for (k, v) in pairs {
                    let c = format!("{k}={v}");
                    if required {
                        out.cookies_required.push(c.clone());
                    }
                    out.cookies_all.push(c);
                }
            }
        }
    }
    out
}

/// Substitute `{name}` templates; unknown names become `{{name}}` placeholders.
fn fill_path(path: &str, values: &HashMap<String, String>, b: &mut Builder, optr: &str, blank_vars: &mut Vec<(String, String)>) -> String {
    let mut out = String::new();
    let mut rest = path;
    let mut used = vec![];
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        let Some(close) = after.find('}') else {
            out.push_str(&rest[open..]);
            rest = "";
            break;
        };
        let name = &after[..close];
        rest = &after[close + 1..];
        used.push(name.to_string());
        match values.get(name) {
            Some(v) => out.push_str(v),
            None => {
                b.report.warn("undeclared_path_parameter", optr, format!("path template '{{{name}}}' has no parameter definition"));
                let v = sanitize_var(name);
                blank_vars.push((v.clone(), optr.to_string()));
                out.push_str(&format!("{{{{{v}}}}}"));
            }
        }
    }
    out.push_str(rest);
    let mut unused: Vec<&String> = values.keys().filter(|k| !used.contains(k)).collect();
    unused.sort();
    if !unused.is_empty() {
        let names = unused.iter().map(|k| format!("'{k}'")).collect::<Vec<_>>().join(", ");
        b.report.warn("unused_path_parameter", optr, format!("path parameter(s) {names} do not appear in the path template"));
    }
    out
}

#[allow(clippy::too_many_arguments)]
fn import_operation(
    ctx: &Ctx,
    b: &mut Builder,
    path: &str,
    method: &str,
    op: &Value,
    optr: &str,
    path_params: &Value,
    pptr: &str,
    path_servers: Option<&Value>,
    global_sec: Option<&Value>,
    tags: &TagIndex,
    order: &mut Vec<(Id, usize)>,
) {
    let Some(op) = op.as_object().map(|_| op) else {
        b.report.warn("invalid_operation", optr, "operation is not an object; skipped");
        b.skipped();
        return;
    };
    let op_id = str_of(op, "operationId").map(str::to_string).filter(|s| !s.trim().is_empty());
    let key = op_id.clone().unwrap_or_else(|| format!("{method} {path}"));
    let seed = b.opts.seed ^ fnv1a64(&key);
    let params = merged_params(ctx, b, path_params, pptr, op, optr);

    // ---- generation (borrows the report) ----
    let mut blank_vars: Vec<(String, String)> = vec![];
    let (pout, body) = {
        let mut sg = SampleGen::new(ctx.refs, &mut b.report, ctx.dialect, b.opts, seed);
        let pout = process_params(ctx, &mut sg, &params, &mut blank_vars);
        let body = request_body(ctx, &mut sg, op, optr, &pout);
        (pout, body)
    };

    // ---- URL ----
    let filled = fill_path(path, &pout.path_values, b, optr, &mut blank_vars);
    for (v, at) in &blank_vars {
        b.report.require_var(v, false, "path parameter value (blank mode or undeclared)", at);
    }
    let override_servers = op.get("servers").map(|s| (s, ptr(optr, "servers"))).or_else(|| path_servers.map(|s| (s, ptr(pptr, "servers"))));
    let base = match override_servers.as_ref().and_then(|(s, p)| s.as_array().and_then(|a| a.first()).map(|s0| (s0, p.clone()))) {
        Some((s0, p)) => {
            b.report.warn(
                "server_override",
                &p,
                "operation/path-level server overrides the environment baseUrl (variables use their defaults)",
            );
            server_url(b, s0, &format!("{p}/0"), true).0
        }
        None => "{{baseUrl}}".to_string(),
    };
    if ctx.dialect == Dialect::Swagger20 && op.get("schemes").is_some() {
        b.report.warn(
            "operation_schemes_ignored",
            &ptr(optr, "schemes"),
            "operation-level `schemes` are not applied; the environment's baseUrl scheme is used",
        );
    }
    let url = format!("{base}{filled}");

    // ---- headers ----
    let mut headers = pout.headers;
    if let Some(accept) = accept_type(ctx, b, op, optr) {
        headers.insert(0, KeyValue::new("Accept", accept));
    }
    if let Some(ct) = &body.content_type {
        headers.push(KeyValue::new("Content-Type", ct.clone()));
    }
    if !pout.cookies_all.is_empty() {
        if !pout.cookies_required.is_empty() || b.opts.include_optional {
            let list = if b.opts.include_optional { &pout.cookies_all } else { &pout.cookies_required };
            headers.push(KeyValue::new("Cookie", list.join("; ")));
        }
        if !b.opts.include_optional && pout.cookies_all.len() > pout.cookies_required.len() {
            let mut kv = KeyValue::new("Cookie", pout.cookies_all.join("; "));
            kv.enabled = false;
            kv.description = "includes optional cookies".into();
            headers.push(kv);
        }
    }

    // ---- auth ----
    let auth = match op.get("security") {
        None => AuthConfig::Inherit,
        Some(s) if Some(s) == global_sec => AuthConfig::Inherit,
        Some(s) => security::requirement_auth(ctx, b, s, &ptr(optr, "security")),
    };

    // ---- callbacks (never registered) ----
    if let Some(Value::Object(cbs)) = op.get("callbacks") {
        for (name, cb) in cbs {
            let exprs = cb.as_object().map(|m| m.keys().cloned().collect::<Vec<_>>().join(", ")).unwrap_or_default();
            b.report.inactive(
                &ptr(&ptr(optr, "callbacks"), name),
                "callback",
                &exprs,
                "callback URLs are server-initiated; they are represented in the report only and never registered or called",
            );
        }
    }

    // ---- folder ----
    let op_tags: Vec<String> = op
        .get("tags")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect())
        .unwrap_or_default();
    let folder = match b.opts.group_by {
        GroupBy::Tags => op_tags.first().map(|t| tags.folder(b, t, order, 0)),
        GroupBy::Paths => {
            let seg = path.trim_start_matches('/').split('/').next().unwrap_or("");
            if seg.is_empty() {
                None
            } else {
                let key = format!("path:{seg}");
                let before = b.folders.len();
                let id = b.folder(None, &key, seg);
                if b.folders.len() > before {
                    order.push((id, order.len()));
                }
                Some(id)
            }
        }
    };

    let mut spec = RequestSpec::http(method, &url);
    spec.params = pout.query;
    spec.headers = headers;
    spec.body = body.body;
    spec.auth = auth;
    let name = str_of(op, "summary")
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .or(op_id)
        .unwrap_or_else(|| format!("{method} {path}"));
    let deprecated = op.get("deprecated").and_then(Value::as_bool) == Some(true);
    let mut description = str_of(op, "description").unwrap_or("").to_string();
    if deprecated {
        description = format!("[deprecated] {description}").trim().to_string();
    }
    let req = b.add_request(folder, &name, &key, spec, optr);
    req.description = description;
    req.tags = op_tags;
    if deprecated {
        req.tags.push("deprecated".into());
    }
}

fn accept_type(ctx: &Ctx, b: &mut Builder, op: &Value, optr: &str) -> Option<String> {
    if ctx.dialect == Dialect::Swagger20 {
        let produces = op.get("produces").or_else(|| ctx.root.get("produces"))?;
        return produces.as_array()?.iter().filter_map(Value::as_str).find(|m| *m != "*/*").map(str::to_string);
    }
    let responses = op.get("responses")?.as_object()?;
    for (code, resp) in responses {
        if !(code.starts_with('2') || code == "default") {
            continue;
        }
        let rptr = ptr(&ptr(optr, "responses"), code);
        let (resp, _) = ctx.refs.resolve(resp, &rptr, &mut b.report)?;
        if let Some(m) = resp.get("content").and_then(Value::as_object)
            && let Some(mt) = m.keys().find(|k| k.as_str() != "*/*")
        {
            return Some(mt.clone());
        }
    }
    None
}

fn request_body(ctx: &Ctx, sg: &mut SampleGen, op: &Value, optr: &str, pout: &ParamOut) -> body::GeneratedBody {
    let none = body::GeneratedBody { body: Body::None, content_type: None };
    if ctx.dialect == Dialect::Swagger20 {
        return swagger2_body(ctx, sg, op, optr, pout);
    }
    let Some(rb) = op.get("requestBody") else { return none };
    let rptr = ptr(optr, "requestBody");
    let Some((rb, rptr)) = sg.refs.resolve(rb, &rptr, sg.report) else { return none };
    let Some(content) = rb.get("content").and_then(Value::as_object) else {
        sg.report.warn("request_body_without_content", &rptr, "requestBody has no `content`; no body generated");
        return none;
    };
    let keys: Vec<&str> = content.keys().map(String::as_str).collect();
    let Some(i) = body::choose_media(&keys) else { return none };
    if keys.len() > 1 {
        let others: Vec<&str> = keys.iter().enumerate().filter(|(j, _)| *j != i).map(|(_, k)| *k).collect();
        sg.report.warn(
            "alternative_media_types",
            &ptr(&rptr, "content"),
            format!("request body also accepts [{}]; only '{}' was generated", others.join(", "), keys[i]),
        );
    }
    let mt = keys[i];
    body::from_media(sg, mt, &content[mt], &ptr(&ptr(&rptr, "content"), mt))
}

fn swagger2_body(ctx: &Ctx, sg: &mut SampleGen, op: &Value, optr: &str, pout: &ParamOut) -> body::GeneratedBody {
    let consumes: Vec<String> = op
        .get("consumes")
        .or_else(|| ctx.root.get("consumes"))
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect())
        .unwrap_or_default();
    if let Some((p, pp)) = &pout.body_params {
        let keys: Vec<&str> = consumes.iter().map(String::as_str).filter(|m| !m.contains("form")).collect();
        let mt = body::choose_media(&keys).map(|i| keys[i].to_string()).unwrap_or_else(|| "application/json".into());
        let media = json!({ "schema": p.get("schema").cloned().unwrap_or(json!({})) });
        return body::from_media(sg, &mt, &media, pp);
    }
    if pout.form_params.is_empty() {
        return body::GeneratedBody { body: Body::None, content_type: None };
    }
    let has_file = pout.form_params.iter().any(|(p, _)| str_of(p, "type") == Some("file"));
    let multipart = has_file || consumes.iter().any(|c| c.starts_with("multipart/form-data"));
    let mut props = Map::new();
    let mut required = vec![];
    let mut encoding = Map::new();
    for (p, _) in &pout.form_params {
        let name = str_of(p, "name").unwrap_or("").to_string();
        let mut s = p.clone();
        if let Some(o) = s.as_object_mut() {
            for k in ["name", "in", "required", "description", "collectionFormat", "allowEmptyValue"] {
                o.remove(k);
            }
            if o.get("type").and_then(Value::as_str) == Some("file") {
                o.insert("type".into(), json!("string"));
                o.insert("format".into(), json!("binary"));
            }
        }
        if p.get("required").and_then(Value::as_bool) == Some(true) {
            required.push(Value::String(name.clone()));
        }
        if str_of(p, "type") == Some("array") {
            let (style, explode) = params::collection_format(str_of(p, "collectionFormat").unwrap_or("csv"), Location::Query);
            encoding.insert(name.clone(), json!({ "style": if style == "tabDelimited" { "form" } else { style }, "explode": explode }));
        }
        props.insert(name, s);
    }
    let media = json!({
        "schema": { "type": "object", "properties": props, "required": required },
        "encoding": encoding,
    });
    let mt = if multipart { "multipart/form-data" } else { "application/x-www-form-urlencoded" };
    let synthetic = ptr(optr, "parameters");
    let (w0, u0) = (sg.report.warnings.len(), sg.report.unsupported.len());
    let out = body::from_media(sg, mt, &media, &synthetic);
    // Findings refer to the synthesized schema: point them at the real
    // formData parameter instead.
    let prefix = format!("{synthetic}/schema/properties/");
    let fix = |f: &mut crate::report::Finding| {
        if let Some(rest) = f.pointer.strip_prefix(&prefix) {
            let name = rest.split('/').next().unwrap_or("").replace("~1", "/").replace("~0", "~");
            if let Some((_, pp)) = pout.form_params.iter().find(|(p, _)| str_of(p, "name") == Some(name.as_str())) {
                f.pointer = pp.clone();
            }
        }
    };
    sg.report.warnings[w0..].iter_mut().for_each(fix);
    sg.report.unsupported[u0..].iter_mut().for_each(fix);
    out
}
