//! Request bodies: media-type choice, example precedence and serialization
//! to JSON, XML (schema `xml` hints, including OpenAPI 3.2 `nodeType`),
//! form-urlencoded (with `encoding` style/explode) and multipart.

use super::params;
use super::refs::{Refs, ref_name};
use super::schema::SampleGen;
use crate::SampleMode;
use crate::util::{is_json_media, is_xml_media, media_essence, ptr, scalar_text, str_of};
use anvil_domain::request::{Body, KeyValue, MultipartContent, MultipartPart};
use serde_json::{Map, Value};

pub(crate) struct GeneratedBody {
    pub body: Body,
    /// Explicit `Content-Type` to keep when the body variant would infer a
    /// different one (`application/vnd.api+json`, `text/xml`, …).
    pub content_type: Option<String>,
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
enum Rank {
    Json,
    Form,
    Multipart,
    Xml,
    Text,
    Any,
    Other,
}

fn rank(mt: &str) -> Rank {
    let e = media_essence(mt);
    if is_json_media(mt) {
        Rank::Json
    } else if e == "application/x-www-form-urlencoded" {
        Rank::Form
    } else if e == "multipart/form-data" {
        Rank::Multipart
    } else if is_xml_media(mt) {
        Rank::Xml
    } else if e.starts_with("text/") && e != "text/event-stream" {
        Rank::Text
    } else if e == "*/*" {
        Rank::Any
    } else {
        Rank::Other
    }
}

/// Pick the media type to generate (JSON > form > multipart > XML > text >
/// `*/*` > other; ties keep document order).
pub(crate) fn choose_media(keys: &[&str]) -> Option<usize> {
    (0..keys.len()).min_by_key(|i| (rank(keys[*i]), *i))
}

/// Explicit example of a Media Type / Parameter object (Sample mode):
/// `example`, then the first `examples` entry (`value`, 3.2 `dataValue`,
/// 3.2 `serializedValue` as raw text). `externalValue` is reported, not
/// fetched.
pub(crate) enum Explicit {
    Value(Value),
    Serialized(String),
}

pub(crate) fn explicit_example(sg: &mut SampleGen, holder: &Value, at: &str) -> Option<Explicit> {
    if let Some(v) = holder.get("example") {
        return Some(Explicit::Value(v.clone()));
    }
    let (name, ex) = holder.get("examples").and_then(Value::as_object).and_then(|m| m.iter().next())?;
    let eptr = ptr(&ptr(at, "examples"), name);
    let (ex, eptr) = sg.refs.resolve(ex, &eptr, sg.report)?;
    if let Some(v) = ex.get("value").or_else(|| ex.get("dataValue")) {
        return Some(Explicit::Value(v.clone()));
    }
    if let Some(s) = ex.get("serializedValue").and_then(Value::as_str) {
        return Some(Explicit::Serialized(s.to_string()));
    }
    if let Some(u) = ex.get("externalValue").and_then(Value::as_str) {
        sg.report.external_ref(u, &ptr(&eptr, "externalValue"));
    }
    None
}

/// Generate a body for one media type of an OpenAPI 3 `content` map (or a
/// synthesized Swagger 2.0 equivalent).
pub(crate) fn from_media(sg: &mut SampleGen, mt: &str, media: &Value, mptr: &str) -> GeneratedBody {
    sg.reset_budget();
    let (media, mptr) = sg.refs.resolve_or_self(media, mptr, sg.report);
    let media = media.clone();
    for k in ["prefixEncoding", "itemEncoding"] {
        if media.get(k).is_some() {
            sg.report.unsupported("sequential_encoding", &ptr(&mptr, k), format!("OpenAPI 3.2 `{k}` is not supported; parts use defaults"));
        }
    }
    let schema = media.get("schema").cloned();
    let sptr = ptr(&mptr, "schema");
    if schema.is_none()
        && let Some(item) = media.get("itemSchema")
    {
        sg.report.unsupported(
            "item_schema_stream",
            &ptr(&mptr, "itemSchema"),
            "OpenAPI 3.2 sequential media (`itemSchema`) is not generated as a stream; a single item is emitted",
        );
        let v = sg.generate(item, &ptr(&mptr, "itemSchema"), None).unwrap_or(Value::Null);
        return GeneratedBody { body: Body::Raw { text: format!("{v}\n"), content_type: Some(mt.to_string()) }, content_type: None };
    }
    let explicit = if sg.mode == SampleMode::Sample { explicit_example(sg, &media, &mptr) } else { None };
    if let Some(Explicit::Serialized(text)) = &explicit {
        return GeneratedBody { body: Body::Raw { text: text.clone(), content_type: Some(mt.to_string()) }, content_type: None };
    }
    let mut value = || -> Value {
        match &explicit {
            Some(Explicit::Value(v)) => v.clone(),
            _ => match &schema {
                Some(s) => gen_root(sg, s, &sptr),
                None => Value::Null,
            },
        }
    };
    let e = media_essence(mt);
    match rank(mt) {
        Rank::Json | Rank::Any => {
            let v = value();
            let text = match &v {
                Value::String(s) if matches!(&explicit, Some(Explicit::Value(_))) && looks_like_json_doc(s) => s.clone(),
                _ => serde_json::to_string_pretty(&v).unwrap_or_default(),
            };
            let explicit_ct = (e != "application/json").then(|| mt.to_string());
            GeneratedBody { body: Body::Json { text }, content_type: explicit_ct }
        }
        Rank::Xml => {
            let v = value();
            let text = match (&v, &schema) {
                (Value::String(s), _) if matches!(&explicit, Some(Explicit::Value(_))) => s.clone(),
                (_, Some(s)) => {
                    let root = root_name(s);
                    let mut out = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
                    xml_element(sg, s, &sptr, &v, &root, &mut out, 0, 0);
                    out
                }
                (_, None) => String::new(),
            };
            let explicit_ct = (e != "application/xml").then(|| mt.to_string());
            GeneratedBody { body: Body::Xml { text }, content_type: explicit_ct }
        }
        Rank::Form => {
            let v = value();
            let enc = media.get("encoding").and_then(Value::as_object).cloned();
            let fields = form_fields(sg, &v, enc.as_ref(), &mptr);
            GeneratedBody { body: Body::FormUrlEncoded { fields }, content_type: None }
        }
        Rank::Multipart => {
            let v = value();
            let enc = media.get("encoding").and_then(Value::as_object).cloned();
            let parts = match &schema {
                Some(s) => multipart_parts(sg, s, &sptr, &v, enc.as_ref()),
                None => vec![],
            };
            GeneratedBody { body: Body::Multipart { parts }, content_type: None }
        }
        Rank::Text => {
            let v = value();
            let text = match v {
                Value::String(s) => s,
                Value::Null => String::new(),
                other @ (Value::Array(_) | Value::Object(_)) => other.to_string(),
                other => scalar_text(&other),
            };
            GeneratedBody { body: Body::Raw { text, content_type: Some(mt.to_string()) }, content_type: None }
        }
        Rank::Other => {
            sg.report.unsupported(
                "binary_body",
                &mptr,
                format!("'{mt}' request bodies need a file attachment; the request is imported without a body"),
            );
            GeneratedBody { body: Body::None, content_type: Some(mt.to_string()) }
        }
    }
}

fn looks_like_json_doc(s: &str) -> bool {
    let t = s.trim_start();
    (t.starts_with('{') || t.starts_with('[')) && serde_json::from_str::<Value>(s).is_ok()
}

/// Generate the top-level value; an unexpandable root yields a type-correct
/// empty value rather than nothing.
fn gen_root(sg: &mut SampleGen, schema: &Value, sptr: &str) -> Value {
    match sg.generate(schema, sptr, None) {
        Some(v) => v,
        None => {
            let (flat, _) = sg.flatten(schema, sptr);
            match flat.get("type").and_then(Value::as_str) {
                Some("array") => Value::Array(vec![]),
                Some("string") => Value::String(String::new()),
                _ => Value::Object(Map::new()),
            }
        }
    }
}

fn root_name(schema: &Value) -> String {
    if let Some(n) = schema.get("xml").and_then(|x| str_of(x, "name")) {
        return n.to_string();
    }
    Refs::ref_of(schema).and_then(ref_name).unwrap_or_else(|| "root".to_string())
}

fn xml_name(s: &str) -> String {
    let mut out: String = s.chars().map(|c| if c.is_alphanumeric() || matches!(c, '_' | '-' | '.') { c } else { '_' }).collect();
    if out.is_empty() || !out.chars().next().is_some_and(|c| c.is_alphabetic() || c == '_') {
        out.insert(0, '_');
    }
    out
}

pub(crate) fn xml_escape(s: &str, attr: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' if attr => out.push_str("&quot;"),
            c => out.push(c),
        }
    }
    out
}

struct XmlHints {
    name: Option<String>,
    prefix: Option<String>,
    namespace: Option<String>,
    node_type: Option<String>,
    wrapped: bool,
}

fn hints(schema: &Value) -> XmlHints {
    let x = schema.get("xml");
    let get = |k: &str| x.and_then(|x| str_of(x, k)).map(str::to_string);
    let mut node_type = get("nodeType");
    if node_type.is_none() && x.and_then(|x| x.get("attribute")).and_then(Value::as_bool) == Some(true) {
        node_type = Some("attribute".into());
    }
    XmlHints {
        name: get("name"),
        prefix: get("prefix"),
        namespace: get("namespace"),
        wrapped: x.and_then(|x| x.get("wrapped")).and_then(Value::as_bool) == Some(true) || node_type.as_deref() == Some("element"),
        node_type,
    }
}

#[allow(clippy::too_many_arguments)]
fn xml_element(
    sg: &mut SampleGen,
    schema: &Value,
    sptr: &str,
    value: &Value,
    default_name: &str,
    out: &mut String,
    indent: usize,
    depth: usize,
) {
    if depth > 64 {
        return;
    }
    let (flat, fp) = sg.flatten(schema, sptr);
    // Hints on the referencing schema override the target's.
    let mut h = hints(&flat);
    let local = hints(schema);
    if local.name.is_some() {
        h.name = local.name;
    }
    let name = xml_name(h.name.as_deref().unwrap_or(default_name));
    let qname = match &h.prefix {
        Some(p) => format!("{p}:{name}"),
        None => name.clone(),
    };
    let ns_attr = match (&h.namespace, &h.prefix) {
        (Some(ns), Some(p)) => format!(" xmlns:{p}=\"{}\"", xml_escape(ns, true)),
        (Some(ns), None) => format!(" xmlns=\"{}\"", xml_escape(ns, true)),
        _ => String::new(),
    };
    let pad = "  ".repeat(indent);
    match value {
        Value::Object(m) => {
            let props = flat.get("properties").and_then(Value::as_object).cloned().unwrap_or_default();
            let mut attrs = String::new();
            let mut text: Option<String> = None;
            let mut children = String::new();
            let unwrap = h.node_type.as_deref() == Some("none");
            let child_indent = if unwrap { indent } else { indent + 1 };
            for (k, v) in m {
                let ps = props.get(k).cloned().unwrap_or(Value::Object(Map::new()));
                let pptr = ptr(&ptr(&fp, "properties"), k);
                let (pflat, _) = sg.flatten(&ps, &pptr);
                let ph = hints(&ps);
                let ph2 = hints(&pflat);
                let nt = ph.node_type.clone().or(ph2.node_type.clone());
                let pname = xml_name(ph.name.as_deref().or(ph2.name.as_deref()).unwrap_or(k));
                match nt.as_deref() {
                    Some("attribute") => {
                        let an = match ph.prefix.as_ref().or(ph2.prefix.as_ref()) {
                            Some(p) => format!("{p}:{pname}"),
                            None => pname,
                        };
                        attrs.push_str(&format!(" {an}=\"{}\"", xml_escape(&scalar_text(v), true)));
                    }
                    Some("text") => text = Some(xml_escape(&scalar_text(v), false)),
                    Some("cdata") => text = Some(format!("<![CDATA[{}]]>", scalar_text(v).replace("]]>", "]]]]><![CDATA[>"))),
                    _ => xml_element(sg, &ps, &pptr, v, k, &mut children, child_indent, depth + 1),
                }
            }
            if unwrap {
                out.push_str(&children);
                return;
            }
            match (text, children.is_empty()) {
                (Some(t), true) => out.push_str(&format!("{pad}<{qname}{ns_attr}{attrs}>{t}</{qname}>\n")),
                (Some(t), false) => out.push_str(&format!("{pad}<{qname}{ns_attr}{attrs}>{t}\n{children}{pad}</{qname}>\n")),
                (None, true) => out.push_str(&format!("{pad}<{qname}{ns_attr}{attrs}/>\n")),
                (None, false) => out.push_str(&format!("{pad}<{qname}{ns_attr}{attrs}>\n{children}{pad}</{qname}>\n")),
            }
        }
        Value::Array(items) => {
            let item_schema = flat.get("items").cloned().unwrap_or(Value::Object(Map::new()));
            let iptr = ptr(&fp, "items");
            let (iflat, _) = sg.flatten(&item_schema, &iptr);
            let item_name = hints(&item_schema).name.or(hints(&iflat).name).unwrap_or_else(|| name.clone());
            if h.wrapped {
                out.push_str(&format!("{pad}<{qname}{ns_attr}>\n"));
                for it in items {
                    xml_element(sg, &item_schema, &iptr, it, &item_name, out, indent + 1, depth + 1);
                }
                out.push_str(&format!("{pad}</{qname}>\n"));
            } else {
                for it in items {
                    xml_element(sg, &item_schema, &iptr, it, &item_name, out, indent, depth + 1);
                }
            }
        }
        other => {
            let t = scalar_text(other);
            match h.node_type.as_deref() {
                Some("cdata") => {
                    out.push_str(&format!("{pad}<{qname}{ns_attr}><![CDATA[{}]]></{qname}>\n", t.replace("]]>", "]]]]><![CDATA[>")))
                }
                _ => out.push_str(&format!("{pad}<{qname}{ns_attr}>{}</{qname}>\n", xml_escape(&t, false))),
            }
        }
    }
}

fn form_fields(sg: &mut SampleGen, v: &Value, enc: Option<&Map<String, Value>>, mptr: &str) -> Vec<KeyValue> {
    let Value::Object(m) = v else {
        if !v.is_null() {
            sg.report.warn("form_body_not_object", mptr, "form-urlencoded body schema is not an object; no fields generated");
        }
        return vec![];
    };
    let mut out = vec![];
    for (k, x) in m {
        let e = enc.and_then(|e| e.get(k));
        let style = e.and_then(|e| str_of(e, "style"));
        let explode = e.and_then(|e| e.get("explode")).and_then(Value::as_bool).unwrap_or(style.is_none_or(|s| s == "form"));
        let pairs: Vec<(String, String)> = match (x, style) {
            (Value::Object(_), None) => vec![(k.clone(), x.to_string())],
            (_, s) => params::query_pairs(k, s.unwrap_or("form"), explode, x).0,
        };
        out.extend(pairs.into_iter().map(|(n, val)| KeyValue::new(n, val)));
    }
    out
}

fn is_binary(s: &Value) -> bool {
    let fmt = str_of(s, "format");
    fmt == Some("binary")
        || str_of(s, "type") == Some("file")
        || (s.get("contentMediaType").is_some() && s.get("contentEncoding").is_none() && fmt.is_none())
}

fn multipart_parts(sg: &mut SampleGen, schema: &Value, sptr: &str, v: &Value, enc: Option<&Map<String, Value>>) -> Vec<MultipartPart> {
    let (flat, fp) = sg.flatten(schema, sptr);
    let props = flat.get("properties").and_then(Value::as_object).cloned().unwrap_or_default();
    let Value::Object(m) = v else { return vec![] };
    let mut parts = vec![];
    for (k, x) in m {
        let pptr = ptr(&ptr(&fp, "properties"), k);
        let (ps, _) = sg.flatten(props.get(k).unwrap_or(&Value::Null), &pptr);
        let e = enc.and_then(|e| e.get(k));
        if e.is_some_and(|e| e.get("headers").is_some()) {
            sg.report.unsupported("multipart_part_headers", &pptr, "per-part headers from `encoding` are not generated");
        }
        let ct = e.and_then(|e| str_of(e, "contentType")).map(str::to_string);
        let item = ps.get("items").map(|i| sg.flatten(i, &ptr(&pptr, "items")).0);
        let binary = is_binary(&ps) || item.as_ref().is_some_and(is_binary);
        if binary {
            sg.report.warn(
                "file_part_requires_attachment",
                &pptr,
                format!("multipart part '{k}' is a file: attach one before sending (imported as a disabled placeholder)"),
            );
            let media = ct.clone().or_else(|| str_of(&ps, "contentMediaType").map(str::to_string));
            parts.push(MultipartPart {
                name: k.clone(),
                enabled: false,
                content: MultipartContent::Text { value: String::new() },
                content_type: media,
            });
            continue;
        }
        match x {
            Value::Array(items) => {
                for it in items {
                    let text = match it {
                        Value::Object(_) | Value::Array(_) => it.to_string(),
                        o => scalar_text(o),
                    };
                    parts.push(MultipartPart {
                        name: k.clone(),
                        enabled: true,
                        content: MultipartContent::Text { value: text },
                        content_type: ct.clone(),
                    });
                }
            }
            Value::Object(_) => parts.push(MultipartPart {
                name: k.clone(),
                enabled: true,
                content: MultipartContent::Text { value: x.to_string() },
                content_type: Some(ct.clone().unwrap_or_else(|| "application/json".into())),
            }),
            o => parts.push(MultipartPart {
                name: k.clone(),
                enabled: true,
                content: MultipartContent::Text { value: scalar_text(o) },
                content_type: ct.clone(),
            }),
        }
    }
    parts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn media_preference() {
        assert_eq!(choose_media(&["application/xml", "application/json"]), Some(1));
        assert_eq!(choose_media(&["text/plain", "multipart/form-data"]), Some(1));
        assert_eq!(choose_media(&["application/octet-stream", "text/plain"]), Some(1));
        assert_eq!(choose_media(&[]), None);
    }
}
