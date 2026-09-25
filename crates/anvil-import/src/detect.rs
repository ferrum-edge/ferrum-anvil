//! Source format and dialect detection.

use crate::structured;
use crate::util::str_of;
use crate::{ImportError, ImportOptions};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt;

/// Family of the imported artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    /// OpenAPI 3.x or Swagger 2.0.
    OpenApi,
    Wsdl,
    PostmanCollection,
    PostmanEnvironment,
    Insomnia,
    Curl,
    Har,
    Unknown,
}

/// Exact dialect. Every OpenAPI minor version is its own dialect: 3.2 is
/// never treated as 3.1, and an unknown future version is refused rather
/// than guessed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Dialect {
    Swagger20,
    OpenApi30,
    OpenApi31,
    OpenApi32,
    /// An `openapi`/`swagger` version this importer does not implement.
    OpenApiUnsupported,
    Wsdl11,
    /// WSDL 2.0 (`http://www.w3.org/ns/wsdl`): recognized, not supported.
    Wsdl20,
    /// Postman collection format v1: recognized, not supported.
    PostmanV1,
    PostmanV20,
    PostmanV21,
    PostmanEnvironment,
    PostmanGlobals,
    InsomniaV4,
    InsomniaV5,
    Curl,
    Har,
    Unknown,
}

impl Dialect {
    pub fn kind(self) -> SourceKind {
        match self {
            Dialect::Swagger20 | Dialect::OpenApi30 | Dialect::OpenApi31 | Dialect::OpenApi32 | Dialect::OpenApiUnsupported => {
                SourceKind::OpenApi
            }
            Dialect::Wsdl11 | Dialect::Wsdl20 => SourceKind::Wsdl,
            Dialect::PostmanV1 | Dialect::PostmanV20 | Dialect::PostmanV21 => SourceKind::PostmanCollection,
            Dialect::PostmanEnvironment | Dialect::PostmanGlobals => SourceKind::PostmanEnvironment,
            Dialect::InsomniaV4 | Dialect::InsomniaV5 => SourceKind::Insomnia,
            Dialect::Curl => SourceKind::Curl,
            Dialect::Har => SourceKind::Har,
            Dialect::Unknown => SourceKind::Unknown,
        }
    }

    /// Whether [`crate::import`] implements this dialect.
    pub fn is_supported(self) -> bool {
        !matches!(self, Dialect::OpenApiUnsupported | Dialect::Wsdl20 | Dialect::PostmanV1 | Dialect::Unknown)
    }

    pub fn label(self) -> &'static str {
        match self {
            Dialect::Swagger20 => "swagger-2.0",
            Dialect::OpenApi30 => "openapi-3.0",
            Dialect::OpenApi31 => "openapi-3.1",
            Dialect::OpenApi32 => "openapi-3.2",
            Dialect::OpenApiUnsupported => "openapi-unsupported",
            Dialect::Wsdl11 => "wsdl-1.1",
            Dialect::Wsdl20 => "wsdl-2.0",
            Dialect::PostmanV1 => "postman-collection-1",
            Dialect::PostmanV20 => "postman-collection-2.0",
            Dialect::PostmanV21 => "postman-collection-2.1",
            Dialect::PostmanEnvironment => "postman-environment",
            Dialect::PostmanGlobals => "postman-globals",
            Dialect::InsomniaV4 => "insomnia-4",
            Dialect::InsomniaV5 => "insomnia-5",
            Dialect::Curl => "curl",
            Dialect::Har => "har",
            Dialect::Unknown => "unknown",
        }
    }
}

impl fmt::Display for Dialect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Syntax {
    Json,
    Yaml,
    Xml,
    Shell,
    Unknown,
}

/// Result of [`detect`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Detected {
    pub kind: SourceKind,
    pub dialect: Dialect,
    pub syntax: Syntax,
    /// Version string declared by the source (`3.1.0`, `2.0`, `1.2`, …).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declared_version: Option<String>,
    /// Why detection failed or what was recognized but is unsupported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl Detected {
    fn unknown(syntax: Syntax, note: impl Into<String>) -> Self {
        Detected { kind: SourceKind::Unknown, dialect: Dialect::Unknown, syntax, declared_version: None, note: Some(note.into()) }
    }

    fn of(dialect: Dialect, syntax: Syntax, version: Option<String>) -> Self {
        Detected { kind: dialect.kind(), dialect, syntax, declared_version: version, note: None }
    }
}

/// Parsed input, kept so `import` does not parse twice.
pub(crate) enum Parsed {
    Structured(Value),
    Xml(String),
    Text(String),
}

/// Identify the format and dialect of `bytes` without importing it.
/// Uses the default resource bounds; never performs I/O.
pub fn detect(bytes: &[u8]) -> Detected {
    match detect_parsed(bytes, &ImportOptions::default()) {
        Ok((d, _)) => d,
        Err(e) => Detected::unknown(Syntax::Unknown, e.to_string()),
    }
}

pub(crate) fn decode_text(bytes: &[u8]) -> Result<&str, String> {
    if bytes.starts_with(&[0xFF, 0xFE]) || bytes.starts_with(&[0xFE, 0xFF]) {
        return Err("UTF-16 input is not supported; save the file as UTF-8".into());
    }
    let bytes = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes);
    std::str::from_utf8(bytes).map_err(|e| format!("input is not valid UTF-8: {e}"))
}

fn looks_like_curl(t: &str) -> bool {
    let t = t.trim_start();
    let t = t.strip_prefix("$ ").unwrap_or(t).trim_start();
    let first: String = t.chars().take_while(|c| !c.is_whitespace()).collect();
    first == "curl" || first.ends_with("/curl") || first == "curl.exe"
}

fn looks_like_xml(t: &str) -> bool {
    t.trim_start().starts_with('<')
}

pub(crate) fn detect_parsed(bytes: &[u8], opts: &ImportOptions) -> Result<(Detected, Parsed), ImportError> {
    if bytes.len() > opts.max_bytes {
        return Err(ImportError::TooLarge { size: bytes.len(), max: opts.max_bytes });
    }
    let text = decode_text(bytes).map_err(|message| ImportError::Unrecognized { message })?;
    if text.trim().is_empty() {
        return Err(ImportError::Unrecognized { message: "input is empty".into() });
    }
    if looks_like_curl(text) {
        return Ok((Detected::of(Dialect::Curl, Syntax::Shell, None), Parsed::Text(text.to_string())));
    }
    if looks_like_xml(text) {
        return Ok((detect_xml(text), Parsed::Xml(text.to_string())));
    }
    let (v, syntax) = structured::parse(text, opts.max_nodes)?;
    Ok((detect_value(&v, syntax), Parsed::Structured(v)))
}

const WSDL11_NS: &str = "http://schemas.xmlsoap.org/wsdl/";
const WSDL20_NS: &str = "http://www.w3.org/ns/wsdl";

/// Cheap root-element sniffing (no DTD processing, no parsing of the body).
fn detect_xml(text: &str) -> Detected {
    let Some((root, ns)) = sniff_root(text) else {
        return Detected::unknown(Syntax::Xml, "XML without a recognizable root element");
    };
    let local = root.rsplit(':').next().unwrap_or(&root);
    match (local, ns.as_deref()) {
        ("definitions", Some(WSDL11_NS)) => Detected::of(Dialect::Wsdl11, Syntax::Xml, Some("1.1".into())),
        ("description", Some(WSDL20_NS)) => {
            let mut d = Detected::of(Dialect::Wsdl20, Syntax::Xml, Some("2.0".into()));
            d.note = Some("WSDL 2.0 is recognized but not supported; only WSDL 1.1 is imported".into());
            d
        }
        _ => Detected::unknown(Syntax::Xml, format!("XML root <{root}> is not a WSDL 1.1 definitions element")),
    }
}

/// Return the root element's qualified name and its namespace URI, looking
/// only at the start tag (skipping the XML declaration, comments and PIs).
fn sniff_root(text: &str) -> Option<(String, Option<String>)> {
    let mut rest = text;
    loop {
        let start = rest.find('<')?;
        rest = &rest[start..];
        if rest.starts_with("<?") {
            rest = &rest[rest.find("?>")? + 2..];
        } else if rest.starts_with("<!--") {
            rest = &rest[rest.find("-->")? + 3..];
        } else if rest.starts_with("<!") {
            // DOCTYPE: skip for sniffing; the real parse refuses DTDs.
            rest = &rest[rest.find('>')? + 1..];
        } else {
            break;
        }
    }
    let end = rest.find('>')?;
    let tag = &rest[1..end];
    let name: String = tag.chars().take_while(|c| !c.is_whitespace() && *c != '/').collect();
    let prefix = name.split_once(':').map(|(p, _)| p.to_string());
    let attr = match &prefix {
        Some(p) => format!("xmlns:{p}"),
        None => "xmlns".to_string(),
    };
    let ns = find_attr(tag, &attr);
    Some((name, ns))
}

fn find_attr(tag: &str, name: &str) -> Option<String> {
    let mut search = tag;
    while let Some(i) = search.find(name) {
        let before_ok = i == 0 || search.as_bytes()[i - 1].is_ascii_whitespace();
        let after = search[i + name.len()..].trim_start();
        if before_ok && let Some(after) = after.strip_prefix('=') {
            let after = after.trim_start();
            let q = after.chars().next()?;
            if q == '"' || q == '\'' {
                let body = &after[1..];
                return body.find(q).map(|e| body[..e].to_string());
            }
        }
        search = &search[i + name.len()..];
    }
    None
}

pub(crate) fn detect_value(v: &Value, syntax: Syntax) -> Detected {
    let Some(obj) = v.as_object() else {
        return Detected::unknown(syntax, "top-level value is not an object");
    };
    // OpenAPI / Swagger
    if let Some(ver) = obj.get("openapi") {
        let ver = crate::util::scalar_text(ver);
        let dialect = if ver.starts_with("3.0.") || ver == "3.0" {
            Dialect::OpenApi30
        } else if ver.starts_with("3.1.") || ver == "3.1" {
            Dialect::OpenApi31
        } else if ver.starts_with("3.2.") || ver == "3.2" {
            Dialect::OpenApi32
        } else {
            Dialect::OpenApiUnsupported
        };
        let mut d = Detected::of(dialect, syntax, Some(ver.clone()));
        if dialect == Dialect::OpenApiUnsupported {
            d.note = Some(format!("OpenAPI version '{ver}' is not supported (supported: 2.0, 3.0.x, 3.1.x, 3.2.x)"));
        }
        return d;
    }
    if let Some(ver) = obj.get("swagger") {
        let ver = crate::util::scalar_text(ver);
        let dialect = if ver == "2.0" { Dialect::Swagger20 } else { Dialect::OpenApiUnsupported };
        let mut d = Detected::of(dialect, syntax, Some(ver.clone()));
        if dialect == Dialect::OpenApiUnsupported {
            d.note = Some(format!("Swagger version '{ver}' is not supported (only 2.0)"));
        }
        return d;
    }
    // HAR
    if let Some(log) = obj.get("log").and_then(Value::as_object)
        && log.get("entries").is_some_and(Value::is_array)
    {
        let ver = log.get("version").map(crate::util::scalar_text);
        return Detected::of(Dialect::Har, syntax, ver);
    }
    // Insomnia v4 export
    if str_of(v, "_type") == Some("export") && obj.get("resources").is_some_and(Value::is_array) {
        let ver = obj.get("__export_format").map(crate::util::scalar_text);
        return Detected::of(Dialect::InsomniaV4, syntax, ver);
    }
    // Insomnia v5
    if let Some(t) = str_of(v, "type")
        && t.contains(".insomnia.rest/")
    {
        let ver = t.rsplit('/').next().map(str::to_string);
        if ver.as_deref().is_some_and(|x| x.starts_with("5.")) {
            return Detected::of(Dialect::InsomniaV5, syntax, ver);
        }
        let mut d = Detected::unknown(syntax, format!("Insomnia document type '{t}' is not supported"));
        d.kind = SourceKind::Insomnia;
        return d;
    }
    // Postman collection
    if let Some(info) = obj.get("info").and_then(Value::as_object)
        && (info.contains_key("_postman_id") || info.get("schema").and_then(Value::as_str).is_some_and(|s| s.contains("getpostman.com")))
    {
        let schema = info.get("schema").and_then(Value::as_str).unwrap_or("");
        let (dialect, ver) = if schema.contains("v2.1") {
            (Dialect::PostmanV21, "2.1.0")
        } else if schema.contains("v2.0") {
            (Dialect::PostmanV20, "2.0.0")
        } else if schema.contains("v1") {
            (Dialect::PostmanV1, "1.0.0")
        } else {
            (Dialect::PostmanV21, "2.1.0")
        };
        let mut d = Detected::of(dialect, syntax, Some(ver.into()));
        if dialect == Dialect::PostmanV1 {
            d.note = Some("Postman collection v1 is not supported; re-export as v2.1".into());
        }
        return d;
    }
    if obj.contains_key("requests") && obj.contains_key("order") && obj.contains_key("name") {
        let mut d = Detected::of(Dialect::PostmanV1, syntax, Some("1.0.0".into()));
        d.note = Some("Postman collection v1 is not supported; re-export as v2.1".into());
        return d;
    }
    // Postman environment / globals
    match str_of(v, "_postman_variable_scope") {
        Some("environment") => return Detected::of(Dialect::PostmanEnvironment, syntax, None),
        Some("globals") => return Detected::of(Dialect::PostmanGlobals, syntax, None),
        _ => {}
    }
    if obj.contains_key("values")
        && obj.get("values").is_some_and(Value::is_array)
        && obj.contains_key("name")
        && (obj.contains_key("_postman_exported_using") || obj.contains_key("id"))
    {
        return Detected::of(Dialect::PostmanEnvironment, syntax, None);
    }
    Detected::unknown(syntax, "no OpenAPI, Swagger, Postman, Insomnia or HAR markers found")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sniff_wsdl() {
        let x = r#"<?xml version="1.0"?><!-- c --><wsdl:definitions xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/" name="x">"#;
        assert_eq!(detect_xml(x).dialect, Dialect::Wsdl11);
        let x2 = r#"<description xmlns="http://www.w3.org/ns/wsdl">"#;
        assert_eq!(detect_xml(x2).dialect, Dialect::Wsdl20);
    }

    #[test]
    fn curl_prompt() {
        assert!(looks_like_curl("$ curl https://x"));
        assert!(looks_like_curl("  /usr/bin/curl -X GET x"));
        assert!(!looks_like_curl("curling"));
    }
}
