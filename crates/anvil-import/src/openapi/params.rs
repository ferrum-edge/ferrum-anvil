//! Parameter serialization by OpenAPI style and explode (RFC 6570 derived).
//!
//! Query parameters are produced as *decoded* name/value pairs; the engine
//! percent-encodes them when the request is prepared, which also encodes
//! the delimiters of non-exploded styles (`,` → `%2C`, `|` → `%7C`,
//! space → `%20`). Form-decoding servers see identical values. Path values
//! are percent-encoded here (the URL is used as written), with the style's
//! own delimiters (`.`, `;`, `=`, `,`) left literal.

use crate::util::scalar_text;
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use serde_json::Value;

const UNRESERVED: &AsciiSet = &NON_ALPHANUMERIC.remove(b'-').remove(b'_').remove(b'.').remove(b'~');

fn enc(s: &str) -> String {
    utf8_percent_encode(s, UNRESERVED).to_string()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Location {
    Path,
    Query,
    Header,
    Cookie,
    /// OpenAPI 3.2 `in: querystring` (the whole query string).
    QueryString,
}

impl Location {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "path" => Location::Path,
            "query" => Location::Query,
            "header" => Location::Header,
            "cookie" => Location::Cookie,
            "querystring" => Location::QueryString,
            _ => return None,
        })
    }

    pub fn default_style(self) -> &'static str {
        match self {
            Location::Path | Location::Header => "simple",
            Location::Query | Location::Cookie | Location::QueryString => "form",
        }
    }
}

fn prims(v: &Value) -> Vec<String> {
    match v {
        Value::Array(a) => a.iter().map(scalar_text).collect(),
        other => vec![scalar_text(other)],
    }
}

fn obj_pairs(v: &Value) -> Vec<(String, String)> {
    v.as_object().map(|m| m.iter().map(|(k, v)| (k.clone(), compact(v))).collect()).unwrap_or_default()
}

/// Primitive text, or compact JSON for nested structures.
fn compact(v: &Value) -> String {
    match v {
        Value::Array(_) | Value::Object(_) => v.to_string(),
        other => scalar_text(other),
    }
}

/// Serialize a path parameter value. Returns the text to substitute for
/// `{name}` and an optional warning.
pub(crate) fn path_value(name: &str, style: &str, explode: bool, v: &Value) -> (String, Option<String>) {
    let join_obj = |pairs: Vec<(String, String)>, kv: &str, sep: &str| -> String {
        pairs
            .iter()
            .map(|(k, v)| if explode { format!("{}{kv}{}", enc(k), enc(v)) } else { format!("{},{}", enc(k), enc(v)) })
            .collect::<Vec<_>>()
            .join(sep)
    };
    match style {
        "simple" => (
            match v {
                Value::Object(_) => join_obj(obj_pairs(v), "=", ","),
                _ => prims(v).iter().map(|s| enc(s)).collect::<Vec<_>>().join(","),
            },
            None,
        ),
        "label" => {
            let sep = if explode { "." } else { "," };
            let body = match v {
                Value::Object(_) => join_obj(obj_pairs(v), "=", sep),
                _ => prims(v).iter().map(|s| enc(s)).collect::<Vec<_>>().join(sep),
            };
            (format!(".{body}"), None)
        }
        "matrix" => {
            let n = enc(name);
            let s = match v {
                Value::Array(_) if explode => prims(v).iter().map(|x| format!(";{n}={}", enc(x))).collect::<String>(),
                Value::Array(_) => format!(";{n}={}", prims(v).iter().map(|s| enc(s)).collect::<Vec<_>>().join(",")),
                Value::Object(_) if explode => obj_pairs(v).iter().map(|(k, x)| format!(";{}={}", enc(k), enc(x))).collect::<String>(),
                Value::Object(_) => format!(";{n}={}", join_obj(obj_pairs(v), "=", ",")),
                other => format!(";{n}={}", enc(&scalar_text(other))),
            };
            (s, None)
        }
        other => {
            let (s, _) = path_value(name, "simple", explode, v);
            (s, Some(format!("style '{other}' is not valid for path parameters; 'simple' used")))
        }
    }
}

/// Serialize a query (or cookie) parameter into decoded name/value pairs.
pub(crate) fn query_pairs(name: &str, style: &str, explode: bool, v: &Value) -> (Vec<(String, String)>, Option<String>) {
    let arr_join = |sep: &str| prims(v).join(sep);
    match (style, v) {
        ("form" | "cookie", Value::Array(_)) if explode => (prims(v).into_iter().map(|x| (name.to_string(), x)).collect(), None),
        ("form" | "cookie", Value::Array(_)) => (vec![(name.to_string(), arr_join(","))], None),
        ("form" | "cookie", Value::Object(_)) if explode => (obj_pairs(v), None),
        ("form" | "cookie", Value::Object(_)) => {
            (vec![(name.to_string(), obj_pairs(v).into_iter().flat_map(|(k, x)| [k, x]).collect::<Vec<_>>().join(","))], None)
        }
        ("form" | "cookie", other) => (vec![(name.to_string(), scalar_text(other))], None),
        ("spaceDelimited" | "pipeDelimited", Value::Array(_)) if explode => {
            (prims(v).into_iter().map(|x| (name.to_string(), x)).collect(), None)
        }
        ("spaceDelimited", Value::Array(_)) => (vec![(name.to_string(), arr_join(" "))], None),
        ("pipeDelimited", Value::Array(_)) => (vec![(name.to_string(), arr_join("|"))], None),
        ("spaceDelimited" | "pipeDelimited", Value::Object(_)) => {
            let sep = if style == "spaceDelimited" { " " } else { "|" };
            (vec![(name.to_string(), obj_pairs(v).into_iter().flat_map(|(k, x)| [k, x]).collect::<Vec<_>>().join(sep))], None)
        }
        ("deepObject", Value::Object(m)) => {
            let mut out = vec![];
            let mut nested = false;
            for (k, x) in m {
                match x {
                    Value::Object(inner) => {
                        nested = true;
                        for (k2, x2) in inner {
                            out.push((format!("{name}[{k}][{k2}]"), compact(x2)));
                        }
                    }
                    Value::Array(items) => {
                        nested = true;
                        for it in items {
                            out.push((format!("{name}[{k}]"), compact(it)));
                        }
                    }
                    other => out.push((format!("{name}[{k}]"), scalar_text(other))),
                }
            }
            let warn = nested
                .then(|| "deepObject serialization of nested objects/arrays is undefined by OpenAPI; bracket nesting used".to_string());
            (out, warn)
        }
        (s @ ("spaceDelimited" | "pipeDelimited" | "deepObject"), other) => (
            vec![(name.to_string(), compact(other))],
            Some(format!("style '{s}' does not apply to a {} value; 'form' used", crate::util::json_type(other))),
        ),
        (other, val) => {
            let (p, _) = query_pairs(name, "form", explode, val);
            (p, Some(format!("style '{other}' is not valid for query parameters; 'form' used")))
        }
    }
}

/// `simple` serialization for header values (no percent-encoding).
pub(crate) fn header_value(explode: bool, v: &Value) -> String {
    match v {
        Value::Object(_) => obj_pairs(v)
            .into_iter()
            .map(|(k, x)| if explode { format!("{k}={x}") } else { format!("{k},{x}") })
            .collect::<Vec<_>>()
            .join(","),
        _ => prims(v).join(","),
    }
}

/// Swagger 2.0 `collectionFormat` → OpenAPI 3 (style, explode).
pub(crate) fn collection_format(fmt: &str, loc: Location) -> (&'static str, bool) {
    match (fmt, loc) {
        ("multi", _) => ("form", true),
        ("ssv", _) => ("spaceDelimited", false),
        ("pipes", _) => ("pipeDelimited", false),
        ("tsv", _) => ("tabDelimited", false),
        (_, Location::Path | Location::Header) => ("simple", false),
        _ => ("form", false),
    }
}

/// Swagger 2.0 `tsv` has no OpenAPI 3 style; join with a tab.
pub(crate) fn tab_delimited(name: &str, v: &Value) -> Vec<(String, String)> {
    vec![(name.to_string(), prims(v).join("\t"))]
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn path_styles() {
        let arr = json!(["3", 4, 5]);
        let obj = json!({"role": "admin", "firstName": "Alex"});
        assert_eq!(path_value("id", "simple", false, &json!(5)).0, "5");
        assert_eq!(path_value("id", "simple", false, &arr).0, "3,4,5");
        assert_eq!(path_value("id", "simple", false, &obj).0, "role,admin,firstName,Alex");
        assert_eq!(path_value("id", "simple", true, &obj).0, "role=admin,firstName=Alex");
        assert_eq!(path_value("id", "label", false, &arr).0, ".3,4,5");
        assert_eq!(path_value("id", "label", true, &arr).0, ".3.4.5");
        assert_eq!(path_value("id", "matrix", false, &json!(5)).0, ";id=5");
        assert_eq!(path_value("id", "matrix", true, &arr).0, ";id=3;id=4;id=5");
        assert_eq!(path_value("id", "matrix", false, &arr).0, ";id=3,4,5");
        assert_eq!(path_value("id", "matrix", true, &obj).0, ";role=admin;firstName=Alex");
        assert_eq!(path_value("id", "simple", false, &json!("a b/c")).0, "a%20b%2Fc");
    }

    #[test]
    fn query_styles() {
        let arr = json!(["blue", "black"]);
        let obj = json!({"R": 100, "G": 200});
        let p = |v: Vec<(String, String)>| v.into_iter().map(|(a, b)| format!("{a}={b}")).collect::<Vec<_>>().join("&");
        assert_eq!(p(query_pairs("color", "form", true, &arr).0), "color=blue&color=black");
        assert_eq!(p(query_pairs("color", "form", false, &arr).0), "color=blue,black");
        assert_eq!(p(query_pairs("color", "form", true, &obj).0), "R=100&G=200");
        assert_eq!(p(query_pairs("color", "form", false, &obj).0), "color=R,100,G,200");
        assert_eq!(p(query_pairs("color", "spaceDelimited", false, &arr).0), "color=blue black");
        assert_eq!(p(query_pairs("color", "pipeDelimited", false, &arr).0), "color=blue|black");
        assert_eq!(p(query_pairs("color", "deepObject", true, &obj).0), "color[R]=100&color[G]=200");
        assert!(query_pairs("color", "deepObject", true, &json!(1)).1.is_some());
    }
}
