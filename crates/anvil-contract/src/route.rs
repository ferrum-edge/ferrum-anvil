//! Which operation of a description an observed request is.
//!
//! The observed path is matched against the path templates after removing
//! a server's base path (`servers[*].url`, Swagger `basePath`, path- and
//! operation-level servers; server variables match any segment). When no
//! declared base path fits, up to three leading segments are tried as an
//! unknown prefix (a gateway mounting the API under `/api`, say). Among
//! matching templates the one with the most literal segments wins, then the
//! longest base path, then the operation the request was imported from.

use crate::locate::ptr;
use crate::model::{OperationRef, operations};
use crate::observe::{percent_decode, split_url};
use crate::spec::Spec;
use regex::Regex;
use serde_json::Value;
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone)]
enum Seg {
    Lit(String),
    Param,
    /// A segment mixing text and parameters (`{id}.json`, `label{fmt}`).
    Mixed(Regex),
}

impl Seg {
    fn matches(&self, s: &str) -> bool {
        match self {
            Seg::Lit(l) => l == s,
            Seg::Param => !s.is_empty(),
            Seg::Mixed(re) => re.is_match(s),
        }
    }
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
    ops: Vec<usize>,
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
    bases: Vec<(String, Vec<Seg>)>,
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
                    templates.push(Template { path: op.path.clone(), segs: parse_segments(&op.path), ops: vec![i] });
                }
            }
        }
        // Paths without operations still count as declared paths.
        if let Some(paths) = spec.root.get("paths").and_then(Value::as_object) {
            for p in paths.keys().filter(|k| !k.starts_with("x-")) {
                if !by_path.contains_key(p) {
                    by_path.insert(p.clone(), templates.len());
                    templates.push(Template { path: p.clone(), segs: parse_segments(p), ops: vec![] });
                }
            }
        }
        let mut urls: Vec<String> = vec![];
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
                    urls.push(format!("{s}://{host}{base}"));
                }
            } else {
                urls.push(base.to_string());
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
                        urls.push(u.to_string());
                    }
                }
            }
        }
        let mut bases: Vec<(String, Vec<Seg>)> = vec![(String::new(), vec![])];
        let mut seen_bases: HashSet<String> = HashSet::from([String::new()]);
        for u in &urls {
            let b = server_base(u);
            if seen_bases.insert(b.clone()) {
                bases.push((b.clone(), parse_segments(&b)));
            }
        }
        // Longest base first.
        bases.sort_by_key(|(_, segs)| std::cmp::Reverse(segs.len()));
        let servers = urls
            .iter()
            .map(|u| {
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
        Router { ops, templates, bases, servers }
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
        // (literal segments, base length, template index, base).
        let mut best: Option<(usize, usize, usize, String)> = None;
        let consider = |base_len: usize, base: String, rest: &[String], best: &mut Option<(usize, usize, usize, String)>| {
            for (ti, t) in self.templates.iter().enumerate() {
                if t.segs.len() != rest.len() || !t.segs.iter().zip(rest).all(|(s, r)| s.matches(r)) {
                    continue;
                }
                let lits = t.segs.iter().filter(|s| matches!(s, Seg::Lit(_))).count();
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
        for (_, bsegs) in &self.bases {
            if bsegs.len() <= segs.len() && bsegs.iter().zip(&segs).all(|(s, r)| s.matches(r)) {
                let base = if bsegs.is_empty() { String::new() } else { format!("/{}", segs[..bsegs.len()].join("/")) };
                consider(bsegs.len(), base, &segs[bsegs.len()..], &mut best);
            }
        }
        if best.is_none() {
            // An unknown prefix in front of the API (a gateway mount).
            for k in 1..=3.min(segs.len().saturating_sub(1)) {
                consider(0, format!("/{}", segs[..k].join("/")), &segs[k..], &mut best);
                if best.is_some() {
                    break;
                }
            }
        }
        let Some((_, _, ti, base)) = best else {
            let base = self
                .bases
                .iter()
                .find(|(_, b)| !b.is_empty() && b.len() <= segs.len() && b.iter().zip(&segs).all(|(s, r)| s.matches(r)))
                .map(|(_, b)| format!("/{}", segs[..b.len()].join("/")))
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
