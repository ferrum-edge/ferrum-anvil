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

use crate::locate::ptr;
use crate::model::{OperationRef, operations};
use crate::observe::{percent_decode, split_url};
use crate::spec::Spec;
use regex::Regex;
use serde_json::Value;
use std::collections::{HashMap, HashSet};

/// Distinct server base paths kept (after the ones differing only in
/// variable names are merged).
const MAX_BASES: usize = 64;

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
/// the base of a path nothing declares).
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

pub struct Router<'a> {
    pub ops: Vec<OperationRef<'a>>,
    templates: Vec<Template>,
    /// Template indexes by segment count.
    by_len: HashMap<usize, Vec<usize>>,
    bases: Vec<Base>,
    pub servers: Vec<Server>,
}

/// Where an observed request lands.
#[derive(Debug, Clone)]
pub enum Route {
    /// A declared operation (index into [`Router::ops`]).
    Operation { op: usize, template: String, base: String },
    /// A declared path without this method.
    Method { template: String, base: String },
    /// No declared path; `base` is the base path that was assumed.
    Path { base: String },
}

impl<'a> Router<'a> {
    pub fn new(spec: &'a Spec) -> Router<'a> {
        let ops = operations(spec);
        let mut templates: Vec<Template> = vec![];
        let mut by_path: HashMap<String, usize> = HashMap::new();
        for (i, op) in ops.iter().enumerate() {
            match by_path.get(&op.path) {
                Some(t) => templates[*t].ops.push(i),
                None => {
                    by_path.insert(op.path.clone(), templates.len());
                    templates.push(Template::new(&op.path, vec![i]));
                }
            }
        }
        // Paths without operations still count as declared paths.
        if let Some(paths) = spec.root.get("paths").and_then(Value::as_object) {
            for p in paths.keys().filter(|k| !k.starts_with("x-")) {
                if !by_path.contains_key(p) {
                    by_path.insert(p.clone(), templates.len());
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
            for op in &ops {
                lists.push(op.item.get("servers"));
                lists.push(op.op.get("servers"));
            }
            for list in lists.into_iter().flatten().filter_map(Value::as_array) {
                for s in list {
                    if let Some(u) = s.get("url").and_then(Value::as_str)
                        && seen_urls.insert(u.to_string())
                    {
                        urls.push((u.to_string(), s.get("variables")));
                    }
                }
            }
        }
        let mut bases: Vec<Base> = vec![Base { loose: vec![], strict: vec![] }];
        let mut seen_bases: HashSet<String> = HashSet::from([String::new()]);
        for (u, vars) in &urls {
            if bases.len() >= MAX_BASES {
                break;
            }
            let b = server_base(u);
            let strict = strict_segments(&b, *vars);
            // `/{v}` and `/{w}` route alike: keep one of them.
            let key: Vec<String> = parse_segments(&b).iter().chain(&strict).map(Seg::canonical).collect();
            if seen_bases.insert(key.join("/")) {
                bases.push(Base { loose: parse_segments(&b), strict });
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
        Router { ops, templates, by_len, bases, servers }
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
                        let hinted =
                            |i: usize| hint.is_some_and(|h| self.templates[i].ops.iter().any(|o| op_key(&self.ops[*o]) == strip_dup(h)));
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
        let find = |m: &str| t.ops.iter().copied().find(|o| self.ops[*o].method == m);
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
    op.operation_id().map(str::to_string).unwrap_or_else(|| format!("{} {}", op.method.to_ascii_uppercase(), op.path))
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
            Route::Operation { op, base, .. } => format!("{} @{base}", op_key(&r.ops[op])),
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
}
