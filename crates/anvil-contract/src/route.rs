//! Which operation of a description an observed request is.
//!
//! The observed path is matched against the path templates after removing
//! a server's base path (`servers[*].url`, Swagger `basePath`, path- and
//! operation-level servers; server variables match any segment). When no
//! declared base path fits, up to three leading segments are tried as an
//! unknown prefix (a gateway mounting the API under `/api`, say), alone or
//! in front of a declared base path. Among matching templates the one with
//! the most literal segments wins (a segment mixing text and a parameter
//! counts half), then the longest base path, then the operation the request
//! was imported from.
//!
//! A Path Item that many paths `$ref` is read once and its operations are
//! shared by those paths; each (path, operation) the router lists is charged
//! to [`MAX_ROUTE_BYTES`].

use crate::locate::ptr;
use crate::model::{OperationRef, PathItem, read_paths};
use crate::observe::{percent_decode, split_url};
use crate::spec::Spec;
use regex::Regex;
use serde_json::Value;
use std::collections::{HashMap, HashSet};

/// Distinct server base paths kept (after the ones differing only in
/// variable names are merged).
const MAX_BASES: usize = 64;
/// Declared values kept per server variable segment of a base path.
const MAX_CHOICES: usize = 64;
/// What the operations a router lists may cost, in bytes. Each (path,
/// operation) is charged its method, path, pointers and declared statuses
/// for the copies an analysis keeps per operation (its record, label and
/// coverage entry), so paths that `$ref` one Path Item cost like distinct
/// ones. Past this, the remaining operations are left out and counted.
pub const MAX_ROUTE_BYTES: usize = crate::model::MAX_MODEL_VIEW_BYTES;
/// Charged per listed operation besides its text.
const ROUTE_OPERATION_BYTES: usize = 512;

#[derive(Debug, Clone)]
enum Seg {
    Lit(String),
    Param,
    /// A segment mixing text and parameters (`{id}.json`, `label{fmt}`).
    Mixed(Regex),
    /// A server variable limited to its `enum` and `default`.
    Choice(Vec<String>),
}

impl Seg {
    fn matches(&self, s: &str) -> bool {
        match self {
            Seg::Lit(l) => l == s,
            Seg::Param => !s.is_empty(),
            Seg::Mixed(re) => re.is_match(s),
            Seg::Choice(values) => values.iter().any(|v| v == s),
        }
    }

    /// How specific a matching segment is: literal, mixed, parameter.
    fn score(&self) -> usize {
        match self {
            Seg::Lit(_) | Seg::Choice(_) => 2,
            Seg::Mixed(_) => 1,
            Seg::Param => 0,
        }
    }

    /// The same for every spelling of the variable names (`{a}` = `{b}`).
    fn canonical(&self) -> String {
        match self {
            Seg::Lit(l) => format!("l:{l}"),
            Seg::Param => "p".into(),
            Seg::Mixed(re) => format!("m:{}", re.as_str()),
            Seg::Choice(v) => format!("c:{}", v.join("\u{0}")),
        }
    }
}

/// A server base path: segments that match any variable value (to route),
/// and segments that match only a variable's `enum` or `default` (to name
/// the base of a path nothing declares). Servers whose base paths differ
/// only in variables share one `Base`; their declared values are merged.
struct Base {
    loose: Vec<Seg>,
    strict: Vec<Seg>,
}

fn parse_segments(path: &str) -> Vec<Seg> {
    path.split('/')
        .filter(|s| !s.is_empty())
        .map(|s| {
            if !s.contains('{') {
                return Seg::Lit(percent_decode(s));
            }
            if s.starts_with('{') && s.ends_with('}') && s.matches('{').count() == 1 {
                return Seg::Param;
            }
            let mut re = String::from("^");
            let mut rest = s;
            while let Some(open) = rest.find('{') {
                re.push_str(&regex::escape(&rest[..open]));
                match rest[open..].find('}') {
                    Some(close) => {
                        re.push_str("[^/]+");
                        rest = &rest[open + close + 1..];
                    }
                    None => {
                        re.push_str(&regex::escape(&rest[open..]));
                        rest = "";
                    }
                }
            }
            re.push_str(&regex::escape(rest));
            re.push('$');
            Regex::new(&re).map(Seg::Mixed).unwrap_or_else(|_| Seg::Lit(s.to_string()))
        })
        .collect()
}

/// The path part of a server URL (`https://x/api/{v}` → `/api/{v}`).
fn server_base(url: &str) -> String {
    let path = match url.split_once("://") {
        Some((_, rest)) => rest.find('/').map(|i| &rest[i..]).unwrap_or(""),
        None => url,
    };
    path.split(['?', '#']).next().unwrap_or("").trim_end_matches('/').to_string()
}

struct Template {
    path: String,
    segs: Vec<Seg>,
    /// Sum of [`Seg::score`].
    score: usize,
    ops: Vec<usize>,
}

impl Template {
    fn new(path: &str, ops: Vec<usize>) -> Template {
        let segs = parse_segments(path);
        Template { path: path.to_string(), score: segs.iter().map(Seg::score).sum(), segs, ops }
    }
}

/// A declared server: its URL and whether an origin matches it.
#[derive(Debug, Clone)]
pub struct Server {
    pub url: String,
    origin: Option<Regex>,
}

/// One operation of one path: the path, its Path Item (an index into
/// [`Router::items`]) and the operation's index in that item.
#[derive(Debug, Clone, Copy)]
struct Entry<'a> {
    path: &'a str,
    item: usize,
    op: usize,
}

pub struct Router<'a> {
    /// Path Items, each once however many paths `$ref` it.
    items: Vec<PathItem<'a>>,
    /// Each listed operation of each path, in document order.
    entries: Vec<Entry<'a>>,
    templates: Vec<Template>,
    /// Template indexes by path.
    by_path: HashMap<&'a str, usize>,
    /// Template indexes by segment count.
    by_len: HashMap<usize, Vec<usize>>,
    bases: Vec<Base>,
    pub servers: Vec<Server>,
    /// Server URLs whose base path was not kept ([`MAX_BASES`]).
    pub dropped_servers: usize,
    /// Operations not listed because they did not fit [`MAX_ROUTE_BYTES`].
    pub skipped_operations: usize,
}

/// Where an observed request lands.
#[derive(Debug, Clone)]
pub enum Route {
    /// A declared operation (see [`Router::operation`]).
    Operation { op: usize, template: String, base: String },
    /// A declared path without this method.
    Method { template: String, base: String },
    /// No declared path; `base` is the base path that was assumed.
    Path { base: String },
}

impl<'a> Router<'a> {
    pub fn new(spec: &'a Spec) -> Router<'a> {
        let (items, path_items) = read_paths(spec);
        // What a copy of each operation's declared statuses costs, once per
        // Path Item.
        let status_bytes: Vec<Vec<usize>> =
            items.iter().map(|item| item.operations.iter().map(|(_, _, op)| statuses_cost(op)).collect()).collect();
        // Each path's operations, charged before they are listed; once one
        // does not fit, the rest are counted instead.
        let mut entries: Vec<Entry<'a>> = vec![];
        let mut left = MAX_ROUTE_BYTES;
        let mut skipped_operations = 0;
        for &(path, i) in &path_items {
            let item = &items[i];
            for (k, (method, pointer, _)) in item.operations.iter().enumerate() {
                let cost =
                    ROUTE_OPERATION_BYTES + 3 * (method.len() + path.len() + pointer.len()) + item.pointer.len() + status_bytes[i][k];
                if skipped_operations > 0 || cost > left {
                    skipped_operations += item.operations.len() - k;
                    break;
                }
                left -= cost;
                entries.push(Entry { path, item: i, op: k });
            }
        }
        let mut templates: Vec<Template> = vec![];
        let mut by_path: HashMap<&'a str, usize> = HashMap::new();
        for (i, e) in entries.iter().enumerate() {
            match by_path.get(e.path) {
                Some(t) => templates[*t].ops.push(i),
                None => {
                    by_path.insert(e.path, templates.len());
                    templates.push(Template::new(e.path, vec![i]));
                }
            }
        }
        // Paths without operations still count as declared paths.
        if let Some(paths) = spec.root.get("paths").and_then(Value::as_object) {
            for p in paths.keys().filter(|k| !k.starts_with("x-")) {
                if !by_path.contains_key(p.as_str()) {
                    by_path.insert(p.as_str(), templates.len());
                    templates.push(Template::new(p, vec![]));
                }
            }
        }
        let mut by_len: HashMap<usize, Vec<usize>> = HashMap::new();
        for (i, t) in templates.iter().enumerate() {
            by_len.entry(t.segs.len()).or_default().push(i);
        }
        // Server URLs with their variables.
        let mut urls: Vec<(String, Option<&Value>)> = vec![];
        let mut seen_urls: HashSet<String> = HashSet::new();
        // Every server object's URL and variables, for the base paths (the
        // same URL may declare other variable values elsewhere).
        let mut variants: Vec<(&str, Option<&Value>)> = vec![];
        if spec.is_swagger2() {
            let base = spec.root.get("basePath").and_then(Value::as_str).unwrap_or("");
            if let Some(host) = spec.root.get("host").and_then(Value::as_str) {
                let schemes: Vec<&str> = spec
                    .root
                    .get("schemes")
                    .and_then(Value::as_array)
                    .map(|a| a.iter().filter_map(Value::as_str).collect())
                    .unwrap_or_default();
                for s in if schemes.is_empty() { vec!["https"] } else { schemes } {
                    urls.push((format!("{s}://{host}{base}"), None));
                }
            } else {
                urls.push((base.to_string(), None));
            }
        } else {
            let mut lists = vec![spec.root.get("servers")];
            // Each Path Item's servers and its operations' once, in the order
            // the paths first reach them.
            let mut listed = vec![false; items.len()];
            for &(_, i) in &path_items {
                if std::mem::replace(&mut listed[i], true) {
                    continue;
                }
                lists.push(items[i].value.get("servers"));
                lists.extend(items[i].operations.iter().map(|(_, _, op)| op.get("servers")));
            }
            for list in lists.into_iter().flatten().filter_map(Value::as_array) {
                for s in list {
                    let Some(u) = s.get("url").and_then(Value::as_str) else { continue };
                    if seen_urls.insert(u.to_string()) {
                        urls.push((u.to_string(), s.get("variables")));
                    } else if s.get("variables").is_some() {
                        variants.push((u, s.get("variables")));
                    }
                }
            }
        }
        let mut bases: Vec<Base> = vec![Base { loose: vec![], strict: vec![] }];
        // Routing form (`/{v}` and `/{w}` route alike) → index in `bases`.
        let mut seen_bases: HashMap<String, usize> = HashMap::from([(String::new(), 0)]);
        // Distinct server URLs whose base path was not kept.
        let mut dropped: HashSet<&str> = HashSet::new();
        let all = urls.iter().map(|(u, v)| (u.as_str(), *v)).chain(variants);
        for (u, vars) in all {
            let b = server_base(u);
            let loose = parse_segments(&b);
            let strict = strict_segments(&b, vars);
            let key = loose.iter().map(Seg::canonical).collect::<Vec<_>>().join("/");
            match seen_bases.get(&key) {
                Some(&i) => {
                    for (have, add) in bases[i].strict.iter_mut().zip(strict) {
                        if let (Seg::Choice(values), Seg::Choice(more)) = (have, add) {
                            for v in more {
                                if values.len() < MAX_CHOICES && !values.contains(&v) {
                                    values.push(v);
                                }
                            }
                        }
                    }
                }
                None if bases.len() < MAX_BASES => {
                    seen_bases.insert(key, bases.len());
                    bases.push(Base { loose, strict });
                }
                None => {
                    dropped.insert(u);
                }
            }
        }
        // Longest base first.
        bases.sort_by_key(|b| std::cmp::Reverse(b.loose.len()));
        let servers = urls
            .iter()
            .map(|(u, _)| {
                let origin = u.split_once("://").map(|(scheme, rest)| {
                    let host = rest.split('/').next().unwrap_or("");
                    let mut re = format!("^{}://", regex::escape(&scheme.to_ascii_lowercase()));
                    let mut r = host;
                    while let Some(open) = r.find('{') {
                        re.push_str(&regex::escape(&r[..open].to_ascii_lowercase()));
                        let close = r[open..].find('}').map(|c| open + c + 1).unwrap_or(r.len());
                        // A server variable stands for one host label (or port).
                        re.push_str("[^/.:]+");
                        r = &r[close..];
                    }
                    re.push_str(&regex::escape(&r.to_ascii_lowercase()));
                    re.push('$');
                    Regex::new(&re).ok()
                });
                Server { url: u.clone(), origin: origin.flatten() }
            })
            .collect();
        let dropped_servers = dropped.len();
        Router { items, entries, templates, by_path, by_len, bases, servers, dropped_servers, skipped_operations }
    }

    /// How many operations are listed (the indexes of [`Route::Operation`]).
    pub fn operation_count(&self) -> usize {
        self.entries.len()
    }

    /// Listed operation `i`.
    pub fn operation(&self, i: usize) -> OperationRef<'a> {
        let e = self.entries[i];
        let item = &self.items[e.item];
        let (method, pointer, _) = &item.operations[e.op];
        OperationRef {
            method: method.clone(),
            path: e.path.to_string(),
            pointer: pointer.clone(),
            op: item.operations[e.op].2,
            item: item.value,
            item_pointer: item.pointer.clone(),
        }
    }

    /// The operation object of listed operation `i`: the same for every
    /// path that reaches it through one Path Item.
    pub fn operation_object(&self, i: usize) -> (usize, usize) {
        (self.entries[i].item, self.entries[i].op)
    }

    /// The methods (upper case) listed for the declared path `path`.
    pub fn methods_of(&self, path: &str) -> Vec<String> {
        let ops = self.by_path.get(path).map(|t| self.templates[*t].ops.as_slice()).unwrap_or_default();
        ops.iter().map(|o| self.method(*o).to_ascii_uppercase()).collect()
    }

    /// The lower-case method of listed operation `i`.
    fn method(&self, i: usize) -> &str {
        let e = &self.entries[i];
        &self.items[e.item].operations[e.op].0
    }

    /// [`op_key`] of listed operation `i`.
    fn key(&self, i: usize) -> String {
        let e = &self.entries[i];
        let (method, _, op) = &self.items[e.item].operations[e.op];
        operation_key(op.get("operationId").and_then(Value::as_str), method, e.path)
    }

    /// Whether `base` (observed segments) is a declared server base path.
    pub fn base_declared(&self, base: &str) -> bool {
        let segs: Vec<String> = base.split('/').filter(|s| !s.is_empty()).map(percent_decode).collect();
        self.bases.iter().any(|b| b.strict.len() == segs.len() && b.strict.iter().zip(&segs).all(|(s, r)| s.matches(r)))
    }

    /// Whether `origin` (`scheme://host[:port]`) is one of the declared
    /// absolute servers; `None` when the description declares none.
    pub fn origin_declared(&self, origin: &str) -> Option<bool> {
        let absolute: Vec<&Regex> = self.servers.iter().filter_map(|s| s.origin.as_ref()).collect();
        if absolute.is_empty() {
            return None;
        }
        Some(absolute.iter().any(|re| re.is_match(origin)))
    }

    pub fn route(&self, method: &str, url: &str, hint: Option<&str>) -> Route {
        let (_, path) = split_url(url);
        let segs: Vec<String> = path.split('/').filter(|s| !s.is_empty()).map(percent_decode).collect();
        let method = method.to_ascii_lowercase();
        // (template score, base length, template index, base).
        let mut best: Option<(usize, usize, usize, String)> = None;
        let consider = |base_len: usize, base: String, rest: &[String], best: &mut Option<(usize, usize, usize, String)>| {
            for &ti in self.by_len.get(&rest.len()).into_iter().flatten() {
                let t = &self.templates[ti];
                if !t.segs.iter().zip(rest).all(|(s, r)| s.matches(r)) {
                    continue;
                }
                let lits = t.score;
                let better = match best {
                    None => true,
                    Some((bl, bb, bt, _)) => {
                        let hinted = |i: usize| hint.is_some_and(|h| self.templates[i].ops.iter().any(|o| self.key(*o) == strip_dup(h)));
                        (lits, base_len) > (*bl, *bb) || ((lits, base_len) == (*bl, *bb) && hinted(ti) && !hinted(*bt))
                    }
                };
                if better {
                    *best = Some((lits, base_len, ti, base.clone()));
                }
            }
        };
        // An unknown prefix of `k` segments (a gateway mount), then a
        // declared base path; the prefix is tried only when nothing matches
        // without it.
        for k in 0..=3.min(segs.len().saturating_sub(1)) {
            for b in &self.bases {
                let bsegs = &b.loose;
                let rest = &segs[k..];
                if bsegs.len() <= rest.len() && bsegs.iter().zip(rest).all(|(s, r)| s.matches(r)) {
                    let n = k + bsegs.len();
                    let base = if n == 0 { String::new() } else { format!("/{}", segs[..n].join("/")) };
                    consider(bsegs.len(), base, &segs[n..], &mut best);
                }
            }
            if best.is_some() {
                break;
            }
        }
        let Some((_, _, ti, base)) = best else {
            // Only a base whose variables have their declared values names
            // the base of an undeclared path.
            // (An unknown prefix may come first, as above.)
            let base = (0..=3.min(segs.len()))
                .find_map(|k| {
                    let rest = &segs[k..];
                    self.bases
                        .iter()
                        .map(|b| &b.strict)
                        .find(|b| !b.is_empty() && b.len() <= rest.len() && b.iter().zip(rest).all(|(s, r)| s.matches(r)))
                        .map(|b| format!("/{}", segs[..k + b.len()].join("/")))
                })
                .unwrap_or_default();
            return Route::Path { base };
        };
        let t = &self.templates[ti];
        let find = |m: &str| t.ops.iter().copied().find(|o| self.method(*o) == m);
        // Servers commonly answer HEAD for GET routes.
        match find(&method).or_else(|| if method == "head" { find("get") } else { None }) {
            Some(op) => Route::Operation { op, template: t.path.clone(), base },
            None => Route::Method { template: t.path.clone(), base },
        }
    }

    /// The pointer of a declared path item.
    pub fn path_pointer(path: &str) -> String {
        ptr("/paths", path)
    }
}

/// The segments of a server base path with each whole-segment variable
/// limited to its `enum` and `default` (none: it matches nothing).
fn strict_segments(base: &str, vars: Option<&Value>) -> Vec<Seg> {
    base.split('/')
        .filter(|s| !s.is_empty())
        .zip(parse_segments(base))
        .map(|(raw, seg)| match seg {
            Seg::Param => {
                let name = raw.trim_start_matches('{').trim_end_matches('}');
                let v = vars.and_then(|v| v.get(name));
                let mut values: Vec<String> = v
                    .and_then(|v| v.get("enum"))
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect();
                if let Some(d) = v.and_then(|v| v.get("default")).and_then(Value::as_str) {
                    values.push(d.to_string());
                }
                Seg::Choice(values)
            }
            other => other,
        })
        .collect()
}

/// The importer's operation key: the operationId, else `METHOD path`.
pub fn op_key(op: &OperationRef<'_>) -> String {
    operation_key(op.operation_id(), &op.method, &op.path)
}

fn operation_key(operation_id: Option<&str>, method: &str, path: &str) -> String {
    operation_id.map(str::to_string).unwrap_or_else(|| format!("{} {}", method.to_ascii_uppercase(), path))
}

/// What a copy of an operation's declared statuses costs.
fn statuses_cost(op: &Value) -> usize {
    op.get("responses").and_then(Value::as_object).map_or(0, |m| m.keys().map(|k| k.len() + 24).sum())
}

/// Drop the importer's `#n` suffix for duplicate keys.
fn strip_dup(k: &str) -> &str {
    match k.rsplit_once('#') {
        Some((base, n)) if n.chars().all(|c| c.is_ascii_digit()) && !n.is_empty() => base,
        _ => k,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Map, json};
    use std::sync::atomic::Ordering;

    fn spec(text: &str) -> Spec {
        Spec::parse(text.as_bytes()).unwrap()
    }

    const DOC: &str = r#"{"openapi":"3.1.0","info":{"title":"t","version":"1"},
      "servers":[{"url":"https://api.example/v1"},{"url":"https://{region}.example/{base}","variables":{"region":{"default":"eu"},"base":{"default":"v2"}}}],
      "paths":{
        "/pets":{"get":{"operationId":"listPets"},"post":{}},
        "/pets/{id}":{"get":{"operationId":"getPet"},"delete":{}},
        "/pets/mine":{"get":{"operationId":"myPets"}},
        "/files/{name}.json":{"get":{}},
        "/declared-only":{}
      }}"#;

    fn op_of(r: &Router, route: Route) -> String {
        match route {
            Route::Operation { op, base, .. } => format!("{} @{base}", r.key(op)),
            Route::Method { template, base } => format!("method {template} @{base}"),
            Route::Path { base } => format!("path @{base}"),
        }
    }

    #[test]
    fn routes_through_server_bases_and_prefers_literals() {
        let s = spec(DOC);
        let r = Router::new(&s);
        assert_eq!(op_of(&r, r.route("GET", "https://api.example/v1/pets?limit=3", None)), "listPets @/v1");
        assert_eq!(op_of(&r, r.route("GET", "https://api.example/v1/pets/42", None)), "getPet @/v1");
        assert_eq!(op_of(&r, r.route("GET", "https://api.example/v1/pets/mine", None)), "myPets @/v1");
        assert_eq!(op_of(&r, r.route("GET", "https://eu.example/v2/pets/7", None)), "getPet @/v2");
        assert_eq!(op_of(&r, r.route("POST", "http://localhost:8080/pets", None)), "POST /pets @");
        assert_eq!(op_of(&r, r.route("GET", "https://api.example/v1/files/report.json", None)), "GET /files/{name}.json @/v1");
        assert_eq!(op_of(&r, r.route("HEAD", "https://api.example/v1/pets", None)), "listPets @/v1");
        assert_eq!(op_of(&r, r.route("PATCH", "https://api.example/v1/pets/1", None)), "method /pets/{id} @/v1");
        assert_eq!(op_of(&r, r.route("GET", "https://api.example/v1/declared-only", None)), "method /declared-only @/v1");
        assert_eq!(op_of(&r, r.route("GET", "https://api.example/v1/owners/1", None)), "path @/v1");
        // A gateway prefix nobody declared.
        assert_eq!(op_of(&r, r.route("GET", "https://gw.example/api/v1/pets/9", None)), "getPet @/api/v1");
        assert_eq!(op_of(&r, r.route("GET", "https://gw.example/a/b/c/v1/pets/9", None)), "getPet @/a/b/c/v1");
        // A variable base names an undeclared path's base only with its declared value.
        assert_eq!(op_of(&r, r.route("GET", "https://eu.example/v2/owners/1", None)), "path @/v2");
        assert_eq!(op_of(&r, r.route("GET", "https://eu.example/owners/1", None)), "path @");
        assert!(r.base_declared("/v2") && r.base_declared("/v1") && !r.base_declared("/owners"));
    }

    #[test]
    fn mixed_segments_rank_between_literals_and_parameters() {
        let s = spec(
            r#"{"openapi":"3.0.3","info":{"title":"t","version":"1"},"paths":{
              "/r/{a}/{b}":{"get":{"operationId":"params"}},
              "/r/{id}.json/{b}":{"get":{"operationId":"mixed"}},
              "/r/x.json/{b}":{"get":{"operationId":"literal"}}}}"#,
        );
        let r = Router::new(&s);
        assert_eq!(op_of(&r, r.route("GET", "/r/1.json/2", None)), "mixed @");
        assert_eq!(op_of(&r, r.route("GET", "/r/x.json/2", None)), "literal @");
        assert_eq!(op_of(&r, r.route("GET", "/r/1/2", None)), "params @");
    }

    #[test]
    fn variable_bases_with_different_defaults_are_one_base() {
        let servers: Vec<serde_json::Value> = (0..100)
            .map(|i| serde_json::json!({"url": "https://h.example/{v}", "variables": {"v": {"default": format!("t{i}")}}}))
            .collect();
        let doc = serde_json::json!({"openapi": "3.1.0", "info": {"title": "t", "version": "1"}, "servers": servers,
            "paths": {"/a": {"get": {}}}});
        let s = spec(&doc.to_string());
        let r = Router::new(&s);
        assert_eq!(r.bases.len(), 2, "the empty base and /{{v}}");
        assert_eq!(r.dropped_servers, 0);
        assert_eq!(op_of(&r, r.route("GET", "https://h.example/t7/a", None)), "GET /a @/t7");
        // Declared values name an undeclared path's base; the first 64 are kept.
        assert_eq!(op_of(&r, r.route("GET", "https://h.example/t42/zzz", None)), "path @/t42");
        assert_eq!(op_of(&r, r.route("GET", "https://h.example/t99/zzz", None)), "path @");
        let many: Vec<serde_json::Value> = (0..100).map(|i| serde_json::json!({"url": format!("https://h.example/b{i}")})).collect();
        let doc = serde_json::json!({"openapi": "3.1.0", "info": {"title": "t", "version": "1"}, "servers": many, "paths": {}});
        let s = spec(&doc.to_string());
        let r = Router::new(&s);
        assert_eq!((r.bases.len(), r.dropped_servers), (MAX_BASES, 100 - (MAX_BASES - 1)));
        // A dropped server with variables, declared twice, counts once.
        let many: Vec<serde_json::Value> = (0..100)
            .flat_map(|i| {
                let s = serde_json::json!({"url": format!("https://h.example/b{i}/{{v}}"), "variables": {"v": {"default": "x"}}});
                [s.clone(), s]
            })
            .collect();
        let doc = serde_json::json!({"openapi": "3.1.0", "info": {"title": "t", "version": "1"}, "servers": many, "paths": {}});
        let s = spec(&doc.to_string());
        assert_eq!(Router::new(&s).dropped_servers, 100 - (MAX_BASES - 1));
    }

    #[test]
    fn many_variable_servers_route_quickly() {
        // Every operation declares its own server with a differently named
        // variable: they are one base path.
        let mut paths = serde_json::Map::new();
        for i in 0..5_000 {
            paths.insert(
                format!("/r{i}/{{id}}"),
                serde_json::json!({"get": {"servers": [{"url": format!("https://h{i}.example/{{v{i}}}/{{w{i}}}"), "variables": {}}]}}),
            );
        }
        let doc = serde_json::json!({"openapi": "3.1.0", "info": {"title": "t", "version": "1"}, "paths": paths});
        let s = spec(&doc.to_string());
        let started = std::time::Instant::now();
        let r = Router::new(&s);
        assert!(r.bases.len() <= 3, "{} bases", r.bases.len());
        for i in 0..2_000 {
            let _ = r.route("GET", &format!("https://h.example/a/b/r{i}/7"), None);
            let _ = r.route("GET", &format!("https://h.example/nothing/{i}/x/y/z"), None);
        }
        assert!(started.elapsed() < std::time::Duration::from_secs(20), "{:?}", started.elapsed());
    }

    #[test]
    fn origins_are_checked_against_absolute_servers() {
        let s = spec(DOC);
        let r = Router::new(&s);
        assert_eq!(r.origin_declared("https://api.example"), Some(true));
        assert_eq!(r.origin_declared("https://us.example"), Some(true));
        assert_eq!(r.origin_declared("https://staging.api.example"), Some(false));
        let rel = spec(r#"{"openapi":"3.0.3","info":{"title":"t","version":"1"},"servers":[{"url":"/v1"}],"paths":{}}"#);
        assert_eq!(Router::new(&rel).origin_declared("https://x"), None);
    }

    #[test]
    fn swagger_base_path() {
        let s = spec(
            r#"{"swagger":"2.0","info":{"title":"t","version":"1"},"host":"api.example","basePath":"/v2","schemes":["https"],"paths":{"/items/{id}":{"get":{"operationId":"getItem"}}}}"#,
        );
        let r = Router::new(&s);
        assert_eq!(op_of(&r, r.route("GET", "https://api.example/v2/items/1", None)), "getItem @/v2");
        assert_eq!(r.origin_declared("https://api.example"), Some(true));
    }

    #[test]
    fn paths_sharing_a_path_item_share_its_operations() {
        let paths: Map<String, Value> =
            (0..20_000).map(|i| (format!("/p{i}/{{id}}"), json!({"$ref": "#/components/pathItems/Shared"}))).collect();
        let doc = json!({"openapi": "3.1.0", "info": {"title": "t", "version": "1"}, "paths": paths,
            "components": {"pathItems": {"Shared": {"get": {"operationId": "shared"}, "post": {}}}}});
        let s = spec(&doc.to_string());
        let r = Router::new(&s);
        assert_eq!((r.items.len(), r.operation_count(), r.skipped_operations), (1, 40_000, 0));
        assert_eq!(op_of(&r, r.route("GET", "/p19999/7", None)), "shared @");
        assert_eq!(op_of(&r, r.route("POST", "/p42/7", None)), "POST /p42/{id} @");
        let Route::Operation { op, .. } = r.route("POST", "/p42/7", None) else { panic!("not routed") };
        let op = r.operation(op);
        assert_eq!(
            (op.path.as_str(), op.pointer.as_str(), op.item_pointer.as_str()),
            ("/p42/{id}", "/components/pathItems/Shared/post", "/components/pathItems/Shared")
        );
        assert_eq!(r.methods_of("/p42/{id}"), ["GET", "POST"]);
    }

    #[test]
    fn a_deep_shared_path_item_is_read_once_and_its_paths_are_bounded() {
        // A Path Item at a pointer of about 200 KB, which 20,000 paths reach
        // through 100 aliases of one more reference.
        let key = "k".repeat(4_000);
        let mut item = json!({"get": {"operationId": "shared"}, "post": {}});
        for _ in 0..50 {
            let mut level = Map::new();
            level.insert(key.clone(), item);
            item = Value::Object(level);
        }
        let mut aliases: Map<String, Value> = (0..100).map(|i| (format!("A{i}"), json!({"$ref": "#/components/pathItems/B"}))).collect();
        aliases.insert("B".into(), json!({"$ref": format!("#/x{}", format!("/{key}").repeat(50))}));
        let paths: Map<String, Value> =
            (0..20_000).map(|i| (format!("/p{i}/{{id}}"), json!({"$ref": format!("#/components/pathItems/A{}", i % 100)}))).collect();
        let doc = json!({"openapi": "3.1.0", "info": {"title": "t", "version": "1"}, "paths": paths, "x": item,
            "components": {"pathItems": aliases}});
        let s = spec(&doc.to_string());
        let r = Router::new(&s);
        // Each alias once, then `B` and the Path Item once, and the Path Item
        // once more to read it.
        assert_eq!(s.walks.load(Ordering::Relaxed), 100 + 3);
        assert_eq!(r.items.len(), 1);
        // Every listed operation is charged its pointer: the rest are counted.
        assert!(r.operation_count() > 0 && r.operation_count() < 1_000, "{}", r.operation_count());
        assert_eq!(r.operation_count() + r.skipped_operations, 40_000);
        assert_eq!(op_of(&r, r.route("GET", "/p0/7", None)), "shared @");
    }
}
