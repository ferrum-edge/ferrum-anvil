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
use crate::report::Message;
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
use std::cell::Cell;
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};

pub(crate) struct Ctx<'a> {
    pub root: &'a Value,
    pub dialect: Dialect,
    pub refs: Refs<'a>,
    /// Bytes sample generation may still copy from the document (whole import).
    pub sample_bytes: Cell<usize>,
    /// Swagger 2.0 document-level `produces` and `consumes`, read once rather
    /// than by every operation that inherits them.
    pub swagger_defaults: SwaggerDefaults,
    /// [`request_variable_names`], read only once a server variable needs a
    /// suffix ([`Ctx::taken_by_requests`]).
    request_variable_names: std::cell::OnceCell<HashSet<String>>,
}

/// What an operation without its own `produces`/`consumes` inherits.
#[derive(Default)]
pub(crate) struct SwaggerDefaults {
    /// The first `produces` type other than `*/*`.
    accept: Option<String>,
    /// The body media type chosen from `consumes`.
    body_media: String,
    /// `consumes` lists `multipart/form-data`.
    multipart: bool,
}

impl SwaggerDefaults {
    fn new(produces: Option<&Value>, consumes: Option<&Value>) -> Self {
        let consumes: Vec<&str> =
            consumes.and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_str).collect()).unwrap_or_default();
        SwaggerDefaults {
            accept: first_produced(produces),
            body_media: body_media(&consumes),
            multipart: consumes.iter().any(|c| c.starts_with("multipart/form-data")),
        }
    }
}

/// The first type of a `produces` list other than `*/*`.
fn first_produced(produces: Option<&Value>) -> Option<String> {
    produces?.as_array()?.iter().filter_map(Value::as_str).find(|m| *m != "*/*").map(str::to_string)
}

/// The Swagger 2.0 `in: body` media type chosen from a `consumes` list.
fn body_media(consumes: &[&str]) -> String {
    let keys: Vec<&str> = consumes.iter().copied().filter(|m| !m.contains("form")).collect();
    body::choose_media(&keys).map(|i| keys[i].to_string()).unwrap_or_else(|| "application/json".into())
}

const METHODS: &[&str] = &["get", "put", "post", "delete", "options", "head", "patch", "trace"];

fn is_32(d: Dialect) -> bool {
    d == Dialect::OpenApi32
}

impl Ctx<'_> {
    /// Whether a request of the document can use `name` besides its server
    /// variables ([`request_variable_names`]); read on first use.
    fn taken_by_requests(&self, name: &str) -> bool {
        self.request_variable_names.get_or_init(|| request_variable_names(self.root, self.refs.max_depth)).contains(name)
    }
}

/// The `{{name}}`s a request of the document can use besides its server
/// variables: the `{…}` segments of every path template, every declared
/// parameter's name (path item, its local fields beside a `$ref`, operation
/// and component level, 3.2 `additionalOperations` included), each security
/// scheme's credential names (by scheme and requirement key), and the
/// default-less variables of path- and operation-level servers, all
/// sanitized as the importer names them. Local `$ref`s are followed as the
/// importer follows them (percent-decoded, at most `max_depth` hops, at most
/// [`refs::MAX_REF_LEN`] bytes), with no report and no budget charged, and
/// each referenced object is read once however many paths share it.
fn request_variable_names(root: &Value, max_depth: usize) -> HashSet<String> {
    fn local<'a>(root: &'a Value, mut v: &'a Value, max_depth: usize) -> Option<&'a Value> {
        for _ in 0..=max_depth {
            let Some(r) = v.get("$ref").and_then(Value::as_str) else { return Some(v) };
            let frag = r.strip_prefix('#').filter(|f| r.len() <= refs::MAX_REF_LEN && (f.is_empty() || f.starts_with('/')))?;
            let decoded = percent_encoding::percent_decode_str(frag).decode_utf8_lossy();
            v = root.pointer(&decoded)?;
        }
        None
    }
    fn template_names(text: &str, out: &mut HashSet<String>, keep: impl Fn(&str) -> bool) {
        let mut rest = text;
        while let Some(open) = rest.find('{') {
            let after = &rest[open + 1..];
            let Some(close) = after.find('}') else { break };
            if keep(&after[..close]) {
                out.insert(sanitize_var(&after[..close]));
            }
            rest = &after[close + 1..];
        }
    }
    struct Scan<'a> {
        root: &'a Value,
        max_depth: usize,
        out: HashSet<String>,
        /// Objects already read (by address): a shared one is read once.
        seen: HashSet<*const Value>,
        schemes: Vec<&'a str>,
    }
    impl<'a> Scan<'a> {
        fn first(&mut self, v: &'a Value) -> bool {
            self.seen.insert(v as *const Value)
        }
        fn parameters(&mut self, list: Option<&'a Value>) {
            for p in list.and_then(Value::as_array).into_iter().flatten() {
                let Some(p) = local(self.root, p, self.max_depth) else { continue };
                if self.first(p)
                    && let Some(name) = p.get("name").and_then(Value::as_str)
                {
                    self.out.insert(sanitize_var(name));
                }
            }
        }
        fn servers(&mut self, list: Option<&'a Value>) {
            for server in list.and_then(Value::as_array).into_iter().flatten() {
                let (Some(url), decl) = (server.get("url").and_then(Value::as_str), server.get("variables")) else { continue };
                template_names(url, &mut self.out, |name| decl.and_then(|d| d.get(name)).and_then(|d| d.get("default")).is_none());
            }
        }
        fn security(&mut self, list: Option<&'a Value>) {
            for requirement in list.and_then(Value::as_array).into_iter().flatten() {
                self.schemes.extend(requirement.as_object().into_iter().flat_map(|r| r.keys()).map(String::as_str));
            }
        }
        fn operation(&mut self, op: &'a Value) {
            if self.first(op) {
                self.parameters(op.get("parameters"));
                self.servers(op.get("servers"));
                self.security(op.get("security"));
            }
        }
        /// A Path Item's own fields: parameters, servers and operations.
        fn item_fields(&mut self, item: &'a Value) {
            self.parameters(item.get("parameters"));
            self.servers(item.get("servers"));
            let Some(o) = item.as_object() else { return };
            for (key, op) in o {
                if key == "additionalOperations" {
                    for op in op.as_object().into_iter().flat_map(|a| a.values()) {
                        self.operation(op);
                    }
                } else if !matches!(key.as_str(), "parameters" | "servers" | "$ref") && op.is_object() {
                    self.operation(op);
                }
            }
        }
    }
    let mut scan = Scan { root, max_depth, out: HashSet::new(), seen: HashSet::new(), schemes: vec![] };
    for (path, item) in root.get("paths").and_then(Value::as_object).into_iter().flatten() {
        template_names(path, &mut scan.out, |_| true);
        // Local fields beside a `$ref`, then the shared target, once.
        scan.item_fields(item);
        if item.get("$ref").is_some()
            && let Some(target) = local(root, item, max_depth)
            && scan.first(target)
        {
            scan.item_fields(target);
        }
    }
    let components = root.pointer("/components/parameters").or_else(|| root.get("parameters")).and_then(Value::as_object);
    for p in components.into_iter().flat_map(|c| c.values()) {
        if let Some(name) = local(root, p, max_depth).and_then(|p| p.get("name")).and_then(Value::as_str) {
            scan.out.insert(sanitize_var(name));
        }
    }
    scan.security(root.get("security"));
    let defined = root.pointer("/components/securitySchemes").or_else(|| root.get("securityDefinitions")).and_then(Value::as_object);
    let mut schemes: HashSet<&str> = scan.schemes.drain(..).collect();
    schemes.extend(defined.into_iter().flat_map(|s| s.keys()).map(String::as_str));
    for key in schemes {
        let v = sanitize_var(key);
        for suffix in ["", "_username", "_password", "_client_id", "_client_secret"] {
            scan.out.insert(format!("{v}{suffix}"));
        }
    }
    // Every `{{name}}` a decoded string of the document writes (JSON or YAML
    // escapes can hide one from the raw-text reservation), as written and
    // as a placeholder would spell it.
    let references = |text: &str, out: &mut HashSet<String>| {
        let mut rest = text;
        while let Some(open) = rest.find("{{") {
            let after = &rest[open + 2..];
            let Some(close) = after.find("}}") else { break };
            let expr = after[..close].trim();
            let name = expr.strip_prefix("_.").unwrap_or(expr);
            if !name.is_empty() && name.len() <= 256 {
                out.insert(name.to_string());
                out.insert(sanitize_var(name));
            }
            rest = &after[close + 2..];
        }
    };
    let mut stack = vec![root];
    while let Some(v) = stack.pop() {
        match v {
            Value::String(text) => references(text, &mut scan.out),
            Value::Array(a) => stack.extend(a.iter()),
            // Member names too: an example's keys are sent as written.
            Value::Object(o) => {
                o.keys().for_each(|k| references(k, &mut scan.out));
                stack.extend(o.values());
            }
            _ => {}
        }
    }
    scan.out
}

fn only_32(ctx: &Ctx, b: &mut Builder, at: &str, what: &'static str) {
    b.report.warn(
        "openapi32_construct",
        at,
        Message::new(what).text(" is an OpenAPI 3.2 construct; it is ignored in a ").text(ctx.dialect.label()).text(" document"),
    );
}

pub(crate) fn import(root: &Value, dialect: Dialect, b: &mut Builder) -> Result<(), ImportError> {
    if !root.is_object() {
        return Err(ImportError::Invalid { dialect, pointer: String::new(), message: "the document is not an object".into() });
    }
    let ctx = Ctx {
        root,
        dialect,
        refs: Refs { root, max_depth: b.opts.max_ref_depth, max_expansions: b.opts.max_ref_expansions },
        sample_bytes: Cell::new(b.opts.max_bytes.saturating_mul(schema::SAMPLE_BYTES_PER_INPUT_BYTE)),
        swagger_defaults: if dialect == Dialect::Swagger20 {
            SwaggerDefaults::new(root.get("produces"), root.get("consumes"))
        } else {
            SwaggerDefaults::default()
        },
        request_variable_names: std::cell::OnceCell::new(),
    };

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
                    b.report.warn("path_not_absolute", &pptr, "the path does not start with '/'; used as written");
                }
                import_path_item(&ctx, b, path, item, &pptr, global_sec.as_ref(), &tags, &mut folder_order);
            }
        }
        Some(_) => b.report.warn("invalid_paths", "/paths", "`paths` is not an object; no operations imported"),
        None if matches!(dialect, Dialect::Swagger20 | Dialect::OpenApi30) => {
            b.report.warn("missing_paths", "/paths", Message::new(dialect.label()).text(" requires `paths`; no operations imported"))
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
    if str_of(root, "jsonSchemaDialect").is_some_and(|d| !d.starts_with("https://spec.openapis.org/oas/3.")) {
        b.report.warn(
            "json_schema_dialect",
            "/jsonSchemaDialect",
            "a custom JSON Schema dialect is not implemented; schemas are interpreted with OpenAPI base semantics",
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
            let (url, vars) = server_url(b, s, &sptr, false, &|n: &str| ctx.taken_by_requests(n));
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
                Message::new("server_index ")
                    .num(b.opts.server_index)
                    .text(" is out of range (")
                    .num(ids.len())
                    .text(" servers); the first server is active"),
            );
            0
        };
        b.workspace.active_environment_id = Some(ids[idx]);
    }
}

/// Convert an OpenAPI 3 server object into a base URL. With `inline`,
/// server variables are replaced by their defaults (operation/path-level
/// overrides); otherwise they become `{{variables}}` defined in the
/// environment. Each variable is rendered once however often the URL uses it
/// (its default, the check against its `enum`, its description), under its
/// own `{{variable}}` name ([`server_aliases`]), and the text read and
/// written is charged to the import's text budget: an operation-level server
/// is converted for every operation that uses it.
fn server_url(b: &mut Builder, s: &Value, sptr: &str, inline: bool, avoid: &dyn Fn(&str) -> bool) -> (String, Vec<Variable>) {
    let raw = str_of(s, "url").unwrap_or("/").trim();
    let empty = Map::new();
    let decl = s.get("variables").and_then(Value::as_object).unwrap_or(&empty);
    let mut vars = vec![];
    let mut out = String::new();
    let mut rendered: HashMap<&str, String> = HashMap::new();
    let mut rest = if b.charge_text(sptr, raw.len()) { raw } else { "" };
    // An operation-level server's placeholders sit beside the document's
    // server environment, so its names are avoided too.
    // ... and a name the source itself writes as `{{name}}`.
    let taken = |n: &str| avoid(n) || (inline && b.server_variable_names.contains(n)) || b.env_names.is_used(n);
    let aliases = server_aliases(rest, decl, inline, b.text_left(), &taken);
    if !inline {
        // Every name a document-level server gives, required ones included.
        b.server_variable_names.extend(aliases.values().cloned());
    }
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
        let text = match rendered.entry(name) {
            Entry::Occupied(e) => e.into_mut(),
            Entry::Vacant(e) => {
                // An inlined default needs no name of its own; a variable
                // without one keeps its plain sanitized name if free.
                let alias = aliases.get(name).cloned().unwrap_or_else(|| sanitize_var(name));
                e.insert(server_variable(b, decl, name, &alias, sptr, inline, &mut vars))
            }
        };
        if !b.charge_text(sptr, text.len()) {
            rest = "";
            break;
        }
        out.push_str(text);
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
        b.report.warn("relative_server_url", &ptr(sptr, "url"), "the server URL is relative; it is prefixed with {{origin}}");
        url = origin.trim_end_matches('/').to_string();
    }
    (url, vars)
}

/// The variables `url` uses, in first-use order, each with whether it is
/// written as a `{{variable}}` (rather than its default inlined), as
/// [`server_url`] reads them.
fn server_url_names<'a>(url: &'a str, decl: &Map<String, Value>, inline: bool) -> Vec<(&'a str, bool)> {
    let mut names = vec![];
    let mut seen: HashSet<&str> = HashSet::new();
    let mut rest = url;
    while let Some(open) = rest.find('{') {
        let after = &rest[open + 1..];
        let Some(close) = after.find('}') else { break };
        let name = &after[..close];
        if seen.insert(name) {
            let has_default = decl.get(name).and_then(|d| d.get("default")).is_some();
            names.push((name, !(inline && has_default)));
        }
        rest = &after[close + 1..];
    }
    names
}

/// Whether [`server_url`] renders `url` as a relative URL (prefixed with
/// `{{origin}}`): the same check (no `://` once trailing `/` are trimmed, and
/// not starting with `{{`) on the text it renders, with each inlined default
/// in place and every other variable as a `{{…}}` placeholder, inserted only
/// while they fit `budget` bytes, as the renderer charges them. Nothing is
/// built: the text is read once, character by character.
fn renders_relative(url: &str, decl: &Map<String, Value>, inline: bool, budget: usize) -> bool {
    struct Scan {
        head: String,
        last: [char; 2],
        /// A `://` was read; `confirmed` once a character other than `/`
        /// follows it, which trimming the trailing `/` keeps.
        scheme: bool,
        confirmed: bool,
    }
    impl Scan {
        fn feed(&mut self, text: &str) {
            for c in text.chars() {
                if self.head.len() < 2 {
                    self.head.push(c);
                }
                if self.scheme && c != '/' {
                    self.confirmed = true;
                }
                if self.last == [':', '/'] && c == '/' {
                    self.scheme = true;
                }
                self.last = [self.last[1], c];
            }
        }
    }
    let mut scan = Scan { head: String::new(), last: ['\0', '\0'], scheme: false, confirmed: false };
    let mut defaults: HashMap<&str, Option<String>> = HashMap::new();
    let (mut rest, mut left) = (url, budget);
    while let Some(open) = rest.find('{') {
        scan.feed(&rest[..open]);
        let after = &rest[open + 1..];
        let Some(close) = after.find('}') else {
            scan.feed(&rest[open..]);
            rest = "";
            break;
        };
        let name = &after[..close];
        rest = &after[close + 1..];
        let text =
            defaults.entry(name).or_insert_with(|| decl.get(name).and_then(|d| d.get("default")).filter(|_| inline).map(scalar_text));
        let text = text.as_deref().unwrap_or("{{v}}");
        if text.len() >= left {
            rest = "";
            break;
        }
        left -= text.len();
        scan.feed(text);
    }
    scan.feed(rest);
    !scan.confirmed && !scan.head.starts_with("{{")
}

/// A distinct `{{variable}}` name for each variable a server URL writes as
/// one, so each keeps its own value: its sanitized name ([`sanitize_var`]),
/// or, when another variable holds that name, the next free `_2`, `_3`, …
/// suffix. Every variable that can have its own sanitized name gets it
/// (`{release_name}` keeps `release_name`, the spelling that is already
/// sanitized winning, then the first used) before any suffix is given, so
/// `{release-name}` beside them becomes `release_name_2` only when no
/// `{release-name-2}` claims that name. The environment's own names are
/// never given: `baseUrl`, and `origin` when the URL renders relative, nor
/// is a name in `avoid` (other variables a request can use) a suffixed one. A variable whose
/// default is inlined needs no name. The same URL always gets the same names.
fn server_aliases<'a>(
    url: &'a str,
    decl: &Map<String, Value>,
    inline: bool,
    budget: usize,
    avoid: &dyn Fn(&str) -> bool,
) -> HashMap<&'a str, String> {
    let names: Vec<&str> = server_url_names(url, decl, inline).into_iter().filter(|(_, named)| *named).map(|(n, _)| n).collect();
    let mut used = crate::common::PlaceholderNames::default();
    // A document-level server's environment holds `baseUrl`; an operation-
    // level server may refer to it, as `{baseUrl}`, and keeps that name.
    if !inline {
        used.reserve("baseUrl");
    }
    if renders_relative(url, decl, inline, budget) {
        used.reserve("origin");
    }
    let mut aliases: HashMap<&str, String> = HashMap::with_capacity(names.len());
    // Natural names: the already-sanitized spellings first, then the rest
    // in first-use order; then suffixes for the variables left without one.
    for exact in [true, false] {
        for &name in &names {
            let base = sanitize_var(name);
            if (base == name) == exact && !aliases.contains_key(name) && used.claim(&base) {
                aliases.insert(name, base);
            }
        }
    }
    // A suffixed name is never one this server holds or one in `avoid`
    // (looked up there, never copied).
    let mut next: HashMap<String, usize> = HashMap::new();
    for &name in &names {
        if !aliases.contains_key(name) {
            let base = sanitize_var(name);
            let n = next.entry(base.clone()).or_insert(2);
            let alias = loop {
                let candidate = format!("{base}_{n}");
                *n += 1;
                if !avoid(&candidate) && used.claim(&candidate) {
                    break candidate;
                }
            };
            aliases.insert(name, alias);
        }
    }
    aliases
}

/// Render server variable `name` of `decl` once, as `{{alias}}`: the text
/// the URL gets for it, with its `Variable` (or required variable) recorded.
/// Every `enum` value read is charged.
fn server_variable(
    b: &mut Builder,
    decl: &Map<String, Value>,
    name: &str,
    alias: &str,
    sptr: &str,
    inline: bool,
    vars: &mut Vec<Variable>,
) -> String {
    let vptr = ptr(&ptr(sptr, "variables"), name);
    let d = decl.get(name);
    if d.is_none() {
        b.report.warn("undeclared_server_variable", sptr, "the server URL uses a variable it does not declare");
    }
    let def = d.and_then(|d| d.get("default")).map(scalar_text);
    let def = def.filter(|t| b.charge_text(&vptr, t.len()));
    let values = d.and_then(|d| d.get("enum")).and_then(Value::as_array);
    if let (Some(e), Some(dv)) = (values, &def) {
        let mut found = Some(false);
        for x in e {
            let t = scalar_text(x);
            if !b.charge_text(&vptr, t.len().saturating_add(1)) {
                found = None;
                break;
            }
            if t == *dv {
                found = Some(true);
                break;
            }
        }
        if found == Some(false) {
            b.report.warn("contradictory_schema", &vptr, "the default is not one of the server variable's enum values");
        }
    }
    if inline && let Some(dv) = def {
        return dv;
    }
    let v = alias;
    match def {
        Some(dv) => {
            let mut var = Variable::plain(v, &dv);
            if let Some(e) = values {
                let mut listed = vec![];
                for x in e {
                    let t = scalar_text(x);
                    if !b.charge_text(&vptr, t.len().saturating_add(2)) {
                        break;
                    }
                    listed.push(t);
                }
                var.description = format!("one of: {}", listed.join(", "));
            }
            if let Some(dsc) = d.and_then(|x| str_of(x, "description")) {
                let dsc = b.text(&vptr, dsc);
                var.description = if var.description.is_empty() { dsc } else { format!("{dsc} ({})", var.description) };
            }
            vars.push(var);
        }
        None => b.report.require_var(v, false, "server variable without a default", &vptr),
    }
    format!("{{{{{v}}}}}")
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
                b.report.warn("tag_parent_cycle", "/tags", "a tag has a cyclic or too deep `parent` chain");
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
    // Path Item `$ref` (local fields win over the referenced ones). The
    // referenced item is read in place, never copied: many paths may share it.
    let Some((target, _)) = ctx.refs.resolve(item, pptr, &mut b.report) else {
        b.skipped();
        return;
    };
    let local = item.as_object();
    let field = |k: &str| path_field(local, target, k);
    let mut ops: Vec<(String, &Value, String)> = vec![];
    for m in METHODS {
        if let Some(op) = field(m) {
            ops.push((m.to_uppercase(), op, ptr(pptr, m)));
        }
    }
    if let Some(op) = field("query") {
        if is_32(ctx.dialect) {
            ops.push(("QUERY".into(), op, ptr(pptr, "query")));
        } else {
            only_32(ctx, b, &ptr(pptr, "query"), "the `query` operation");
        }
    }
    if let Some(Value::Object(extra)) = field("additionalOperations") {
        if is_32(ctx.dialect) {
            let abase = ptr(pptr, "additionalOperations");
            for (m, op) in extra {
                // Every entry's pointer copies the path (a long path times many
                // entries): charged before it is built.
                if !b.charge_text(&abase, abase.len().saturating_add(m.len()).saturating_add(1)) {
                    break;
                }
                let upper = m.to_ascii_uppercase();
                let aptr = ptr(&abase, m);
                if !upper.bytes().all(|c| c.is_ascii_alphabetic() || c == b'-' || c == b'_') {
                    b.report.warn("invalid_method", &aptr, "this is not a valid HTTP method token; skipped");
                    continue;
                }
                if METHODS.contains(&m.to_ascii_lowercase().as_str()) || upper == "QUERY" {
                    b.report.warn("invalid_method", &aptr, "this method must use its fixed Path Item field; skipped");
                    continue;
                }
                ops.push((upper, op, aptr));
            }
        } else {
            only_32(ctx, b, &ptr(pptr, "additionalOperations"), "`additionalOperations`");
        }
    }
    let no_params = Value::Array(vec![]);
    let path_params = field("parameters").unwrap_or(&no_params);
    let path_servers = field("servers");
    for (method, op, optr) in ops {
        if !b.admit(&optr) {
            continue;
        }
        // An operation is walked, and parts of it copied, each time it is
        // imported (a shared Path Item imports it once per path): charged.
        if !b.charge_value(&optr, op) {
            b.skipped();
            continue;
        }
        import_operation(ctx, b, path, &method, op, &optr, path_params, pptr, path_servers, global_sec, tags, order);
    }
}

/// A Path Item field: the item's own (other than `$ref`), else the referenced item's.
fn path_field<'v>(local: Option<&'v Map<String, Value>>, target: &'v Value, k: &str) -> Option<&'v Value> {
    local.and_then(|l| l.get(k)).filter(|_| k != "$ref").or_else(|| target.get(k))
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
    // (location, name as compared) → position in `out`.
    let mut index: HashMap<(String, String), usize> = HashMap::new();
    let mut add = |b: &mut Builder, list: &Value, base: &str| {
        let Some(a) = list.as_array() else { return };
        for (i, p) in a.iter().enumerate() {
            // Parameters are copied per operation, with their pointers; the
            // copies share the import's sample byte budget.
            if !schema::charge_len(&ctx.sample_bytes, base.len().saturating_add(24)) {
                b.report.warn("sample_size_limit", base, "generated samples reached the import's byte budget; parameter skipped");
                return;
            }
            let at = format!("{base}/{i}");
            let Some((p, pp)) = ctx.refs.resolve(p, &at, &mut b.report) else { continue };
            if !schema::charge_len(&ctx.sample_bytes, pp.len()) || !schema::charge_copy(&ctx.sample_bytes, p) {
                b.report.warn("sample_size_limit", &pp, "generated samples reached the import's byte budget; parameter skipped");
                continue;
            }
            let name = str_of(p, "name").unwrap_or("");
            let loc = str_of(p, "in").unwrap_or("");
            let name = if loc == "header" { name.to_ascii_lowercase() } else { name.to_string() };
            match index.entry((loc.to_string(), name)) {
                Entry::Occupied(slot) => out[*slot.get()] = (p.clone(), pp),
                Entry::Vacant(slot) => {
                    slot.insert(out.len());
                    out.push((p.clone(), pp));
                }
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
            return sg.copy(&ptr(pp, "x-example"), v);
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
        let mut s = sg.copy(pp, p)?;
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
                    out.body_params = sg.copy(pp, p).map(|c| (c, pp.clone()));
                    continue;
                }
                "formData" => {
                    if let Some(c) = sg.copy(pp, p) {
                        out.form_params.push((c, pp.clone()));
                    }
                    continue;
                }
                _ => {}
            }
        }
        let Some(loc) = Location::parse(raw_loc) else {
            sg.report.warn("invalid_parameter_location", pp, "the parameter location is not valid; parameter skipped");
            continue;
        };
        if loc == Location::QueryString && !is_32(ctx.dialect) {
            sg.report.warn(
                "openapi32_construct",
                pp,
                Message::new("`in: querystring` is an OpenAPI 3.2 construct; ignored in a ").text(ctx.dialect.label()).text(" document"),
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
        let ignored = match name.to_ascii_lowercase().as_str() {
            "accept" => Some("Accept"),
            "content-type" => Some("Content-Type"),
            "authorization" => Some("Authorization"),
            _ => None,
        };
        if loc == Location::Header
            && let Some(header) = ignored
        {
            sg.report.warn(
                "ignored_header_parameter",
                pp,
                Message::new("header parameter '")
                    .text(header)
                    .text("' is ignored per the OpenAPI specification (use media types / security schemes)"),
            );
            continue;
        }

        let value = if credential {
            let v = sanitize_var(&name);
            sg.report.require_var(&v, true, "credential-like parameter", pp);
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
                b.report.warn("undeclared_path_parameter", optr, "a path template variable has no parameter definition");
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
        b.report.warn(
            "unused_path_parameter",
            optr,
            Message::new("").num(unused.len()).text(" path parameter(s) do not appear in the path template"),
        );
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
        let mut sg = SampleGen::new(ctx.refs, &mut b.report, ctx.dialect, b.opts, seed, &ctx.sample_bytes);
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
            server_url(b, s0, &format!("{p}/0"), true, &|n: &str| ctx.taken_by_requests(n)).0
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
            // The callback URL expressions are counted, not quoted.
            let exprs = cb.as_object().map_or(0, Map::len);
            b.report.inactive(
                &ptr(&ptr(optr, "callbacks"), name),
                "callback",
                Message::new("").num(exprs).text(" callback URL expression(s)"),
                "callback URLs are server-initiated; they are represented in the report only and never registered or called",
            );
        }
    }

    // ---- folder ----
    let tag_list = op.get("tags").and_then(Value::as_array).map(Vec::as_slice).unwrap_or_default();
    let tag_bytes = tag_list.iter().fold(0usize, |n, t| n.saturating_add(t.as_str().map_or(0, str::len)));
    let op_tags: Vec<String> =
        if b.charge_text(optr, tag_bytes) { tag_list.iter().filter_map(Value::as_str).map(str::to_string).collect() } else { vec![] };
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
    let desc = str_of(op, "description").unwrap_or("");
    let description = if !b.charge_text(optr, desc.len()) {
        String::new()
    } else if deprecated {
        format!("[deprecated] {desc}").trim().to_string()
    } else {
        desc.to_string()
    };
    let req = b.add_request(folder, &name, &key, spec, optr);
    req.description = description;
    req.tags = op_tags;
    if deprecated {
        req.tags.push("deprecated".into());
    }
}

fn accept_type(ctx: &Ctx, b: &mut Builder, op: &Value, optr: &str) -> Option<String> {
    if ctx.dialect == Dialect::Swagger20 {
        return match op.get("produces") {
            Some(p) => first_produced(Some(p)),
            None => ctx.swagger_defaults.accept.as_deref().map(|a| b.text(optr, a)).filter(|a| !a.is_empty()),
        };
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
        sg.report.warn(
            "alternative_media_types",
            &ptr(&rptr, "content"),
            Message::new("the request body also accepts ")
                .num(keys.len() - 1)
                .text(" other media type(s); only the preferred one was generated"),
        );
    }
    let mt = keys[i];
    body::from_media(sg, mt, &content[mt], &ptr(&ptr(&rptr, "content"), mt))
}

fn swagger2_body(ctx: &Ctx, sg: &mut SampleGen, op: &Value, optr: &str, pout: &ParamOut) -> body::GeneratedBody {
    // An operation's own `consumes` (charged with the operation), else the
    // document's, read once.
    let own = op.get("consumes").map(|c| SwaggerDefaults::new(None, Some(c)));
    let consumes = own.as_ref().unwrap_or(&ctx.swagger_defaults);
    if let Some((p, pp)) = &pout.body_params {
        // Copied per operation: charged.
        let Some(mt) = sg.copy_str(pp, &consumes.body_media) else {
            return body::GeneratedBody { body: Body::None, content_type: None };
        };
        let schema = match p.get("schema") {
            Some(s) => sg.copy(pp, s).unwrap_or(Value::Null),
            None => json!({}),
        };
        let media = json!({ "schema": schema });
        return body::from_media(sg, &mt, &media, pp);
    }
    if pout.form_params.is_empty() {
        return body::GeneratedBody { body: Body::None, content_type: None };
    }
    let has_file = pout.form_params.iter().any(|(p, _)| str_of(p, "type") == Some("file"));
    let multipart = has_file || consumes.multipart;
    let mut props = Map::new();
    let mut required = vec![];
    let mut encoding = Map::new();
    for (p, pp) in &pout.form_params {
        let name = str_of(p, "name").unwrap_or("").to_string();
        let Some(mut s) = sg.copy(pp, p) else { continue };
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
    let mut by_name: HashMap<&str, &String> = HashMap::new();
    for (p, pp) in &pout.form_params {
        if let Some(n) = str_of(p, "name") {
            by_name.entry(n).or_insert(pp);
        }
    }
    let fix = |f: &mut crate::report::Finding| {
        if let Some(rest) = f.pointer.strip_prefix(&prefix) {
            let name = rest.split('/').next().unwrap_or("").replace("~1", "/").replace("~0", "~");
            if let Some(pp) = by_name.get(name.as_str()) {
                f.pointer = (*pp).clone();
            }
        }
    };
    sg.report.warnings[w0..].iter_mut().for_each(fix);
    sg.report.unsupported[u0..].iter_mut().for_each(fix);
    out
}
