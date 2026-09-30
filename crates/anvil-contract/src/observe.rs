//! What was seen on the wire, independent of where it was recorded (Anvil's
//! history, a HAR capture).

use base64::Engine as _;
use chrono::{DateTime, Utc};
use serde_json::Value;

/// Response bodies larger than this are not parsed for schema checks.
pub const MAX_BODY_CHECKED: usize = 1024 * 1024;
/// HAR entries read at most.
pub const MAX_HAR_ENTRIES: usize = 10_000;
/// Largest HAR file read.
pub const MAX_HAR_BYTES: usize = 128 * 1024 * 1024;

/// One exchange.
#[derive(Debug, Clone, PartialEq)]
pub struct Observation {
    /// Where it came from: a history record id, `har:<index>`.
    pub id: String,
    pub at: Option<DateTime<Utc>>,
    /// Upper case.
    pub method: String,
    /// As sent (credentials already redacted by the recorder).
    pub url: String,
    /// The operation the request was imported from (`operationId`, or
    /// `METHOD path`), used only to choose between equally good matches.
    pub operation_hint: Option<String>,
    pub request_content_type: Option<String>,
    pub request_bytes: u64,
    /// Query parameter names, in order, without values.
    pub query: Vec<String>,
    /// Request header names, lower case.
    pub request_headers: Vec<String>,
    /// `None` when no response arrived (a transport failure).
    pub response: Option<ObservedResponse>,
    /// Time from the start of the exchange to the end of the response.
    pub latency_ms: Option<f64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ObservedResponse {
    pub status: u16,
    pub content_type: Option<String>,
    /// Header names, lower case.
    pub headers: Vec<String>,
    /// Decoded body size, when known.
    pub bytes: Option<u64>,
    pub body: ObservedBody,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ObservedBody {
    /// A complete JSON body.
    Json(Value),
    Empty,
    /// A body that is not JSON (or not checked as JSON).
    Other,
    /// The body is not available for checks, and why.
    Unavailable(String),
}

/// The lower-case media type without parameters.
pub fn essence(ct: &str) -> String {
    ct.split(';').next().unwrap_or("").trim().to_ascii_lowercase()
}

pub fn is_json(ct: &str) -> bool {
    let e = essence(ct);
    e == "application/json" || e.ends_with("+json") || e == "text/json"
}

/// Parse a response body for checks: JSON when the media type says so and
/// the body is small enough.
pub fn body_of(content_type: Option<&str>, bytes: &[u8], complete: bool) -> ObservedBody {
    if bytes.is_empty() {
        return ObservedBody::Empty;
    }
    if !content_type.is_some_and(is_json) {
        return ObservedBody::Other;
    }
    if !complete {
        return ObservedBody::Unavailable("only part of the body was captured".into());
    }
    if bytes.len() > MAX_BODY_CHECKED {
        return ObservedBody::Unavailable(format!("the body is larger than {} KiB", MAX_BODY_CHECKED / 1024));
    }
    // Bounded by the size check and serde_json's nesting limit.
    match serde_json::from_slice(bytes) {
        Ok(v) => ObservedBody::Json(v),
        Err(_) => ObservedBody::Unavailable("the body is not valid JSON".into()),
    }
}

/// Query parameter names of a URL, in order.
pub fn query_names(url: &str) -> Vec<String> {
    let Some((_, q)) = url.split_once('?') else { return vec![] };
    let q = q.split('#').next().unwrap_or("");
    q.split('&').filter(|p| !p.is_empty()).map(|p| percent_decode(p.split('=').next().unwrap_or(""))).filter(|n| !n.is_empty()).collect()
}

/// `scheme://authority` and the path of a URL (the path starts with `/`).
pub fn split_url(url: &str) -> (Option<String>, String) {
    let no_frag = url.split('#').next().unwrap_or("");
    let no_query = no_frag.split('?').next().unwrap_or("");
    match no_query.split_once("://") {
        Some((scheme, rest)) => {
            let (auth, path) = match rest.find('/') {
                Some(i) => (&rest[..i], &rest[i..]),
                None => (rest, "/"),
            };
            // Drop any userinfo.
            let auth = auth.rsplit('@').next().unwrap_or(auth);
            (Some(format!("{}://{}", scheme.to_ascii_lowercase(), auth.to_ascii_lowercase())), path.to_string())
        }
        None => (None, if no_query.starts_with('/') { no_query.to_string() } else { format!("/{no_query}") }),
    }
}

pub fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && i + 2 < b.len()
            && let (Some(h), Some(l)) = ((b[i + 1] as char).to_digit(16), (b[i + 2] as char).to_digit(16))
        {
            out.push((h * 16 + l) as u8);
            i += 3;
            continue;
        }
        out.push(if b[i] == b'+' { b' ' } else { b[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn header_names(v: Option<&Value>) -> Vec<String> {
    v.and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|h| h.get("name").and_then(Value::as_str)).map(|n| n.to_ascii_lowercase()).collect())
        .unwrap_or_default()
}

fn header_value<'a>(v: Option<&'a Value>, name: &str) -> Option<&'a str> {
    v.and_then(Value::as_array)?
        .iter()
        .find(|h| h.get("name").and_then(Value::as_str).is_some_and(|n| n.eq_ignore_ascii_case(name)))
        .and_then(|h| h.get("value").and_then(Value::as_str))
}

/// Read the exchanges of a HAR 1.2 archive (browser dev tools, proxies).
/// Performs no I/O; bounded like an import.
pub fn from_har(bytes: &[u8]) -> Result<Vec<Observation>, String> {
    let opts = anvil_import::ImportOptions { max_bytes: MAX_HAR_BYTES, max_nodes: 5_000_000, ..anvil_import::ImportOptions::default() };
    let (doc, _) = anvil_import::parse_document(bytes, &opts).map_err(|e| e.to_string())?;
    let entries = doc.pointer("/log/entries").and_then(Value::as_array).ok_or("not a HAR archive (no log.entries)")?;
    let mut out = vec![];
    for (i, e) in entries.iter().take(MAX_HAR_ENTRIES).enumerate() {
        let req = e.get("request");
        let Some(method) = req.and_then(|r| r.get("method")).and_then(Value::as_str) else { continue };
        let Some(url) = req.and_then(|r| r.get("url")).and_then(Value::as_str) else { continue };
        let mut query: Vec<String> = req
            .and_then(|r| r.get("queryString"))
            .and_then(Value::as_array)
            .map(|q| q.iter().filter_map(|p| p.get("name").and_then(Value::as_str)).map(str::to_string).collect())
            .unwrap_or_default();
        if query.is_empty() {
            query = query_names(url);
        }
        let post = req.and_then(|r| r.get("postData"));
        let request_bytes = req
            .and_then(|r| r.get("bodySize"))
            .and_then(Value::as_i64)
            .filter(|n| *n >= 0)
            .map(|n| n as u64)
            .or_else(|| post.and_then(|p| p.get("text")).and_then(Value::as_str).map(|t| t.len() as u64))
            .unwrap_or(0);
        let request_content_type = post
            .and_then(|p| p.get("mimeType"))
            .and_then(Value::as_str)
            .map(str::to_string)
            .or_else(|| header_value(req.and_then(|r| r.get("headers")), "content-type").map(str::to_string))
            .filter(|c| !c.is_empty());
        let resp = e.get("response");
        let status = resp.and_then(|r| r.get("status")).and_then(Value::as_u64).filter(|s| (100..1000).contains(s));
        let response = status.map(|status| {
            let content = resp.and_then(|r| r.get("content"));
            let ct = content
                .and_then(|c| c.get("mimeType"))
                .and_then(Value::as_str)
                .map(str::to_string)
                .or_else(|| header_value(resp.and_then(|r| r.get("headers")), "content-type").map(str::to_string))
                .filter(|c| !c.is_empty());
            let text = content.and_then(|c| c.get("text")).and_then(Value::as_str);
            let raw: Option<Vec<u8>> = match (text, content.and_then(|c| c.get("encoding")).and_then(Value::as_str)) {
                (Some(t), Some("base64")) => base64::engine::general_purpose::STANDARD.decode(t.trim()).ok(),
                (Some(t), _) => Some(t.as_bytes().to_vec()),
                (None, _) => None,
            };
            let size = content.and_then(|c| c.get("size")).and_then(Value::as_i64).filter(|n| *n >= 0).map(|n| n as u64);
            let body = match &raw {
                Some(b) => body_of(ct.as_deref(), b, true),
                None if size == Some(0) => ObservedBody::Empty,
                None => ObservedBody::Unavailable("the archive does not include the body".into()),
            };
            ObservedResponse {
                status: status as u16,
                headers: header_names(resp.and_then(|r| r.get("headers"))),
                bytes: size.or(raw.as_ref().map(|b| b.len() as u64)),
                content_type: ct,
                body,
            }
        });
        out.push(Observation {
            id: format!("har:{i}"),
            at: e
                .get("startedDateTime")
                .and_then(Value::as_str)
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                .map(|d| d.with_timezone(&Utc)),
            method: method.to_ascii_uppercase(),
            url: url.to_string(),
            operation_hint: None,
            request_content_type,
            request_bytes,
            query,
            request_headers: header_names(req.and_then(|r| r.get("headers"))),
            response,
            latency_ms: e.get("time").and_then(Value::as_f64).filter(|t| *t >= 0.0),
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn urls_split_and_queries_are_named() {
        assert_eq!(
            split_url("HTTPS://User:pw@API.example:8443/v1/pets?limit=5#x"),
            (Some("https://api.example:8443".into()), "/v1/pets".into())
        );
        assert_eq!(split_url("https://api.example"), (Some("https://api.example".into()), "/".into()));
        assert_eq!(query_names("https://x/p?a=1&b&c%5B0%5D=2&=3"), ["a", "b", "c[0]"]);
    }

    #[test]
    fn har_entries_become_observations() {
        let body = base64::engine::general_purpose::STANDARD.encode(br#"{"id": 1}"#);
        let har = json!({"log": {"version": "1.2", "entries": [
            {"startedDateTime": "2026-09-30T10:00:00.000Z", "time": 42.5,
             "request": {"method": "post", "url": "https://api.example/v1/pets?dry_run=1", "headers": [{"name": "Content-Type", "value": "application/json"}],
                         "queryString": [{"name": "dry_run", "value": "1"}], "bodySize": 12, "postData": {"mimeType": "application/json", "text": "{\"name\":\"x\"}"}},
             "response": {"status": 201, "headers": [{"name": "Content-Type", "value": "application/json"}],
                          "content": {"size": 9, "mimeType": "application/json", "text": body, "encoding": "base64"}}},
            {"request": {"method": "GET", "url": "https://api.example/v1/pets"}, "response": {"status": 0}},
            {"request": 5}
        ]}});
        let obs = from_har(har.to_string().as_bytes()).unwrap();
        assert_eq!(obs.len(), 2);
        assert_eq!(obs[0].method, "POST");
        assert_eq!(obs[0].query, ["dry_run"]);
        assert_eq!(obs[0].request_bytes, 12);
        assert_eq!(obs[0].latency_ms, Some(42.5));
        let r = obs[0].response.as_ref().unwrap();
        assert_eq!((r.status, r.bytes), (201, Some(9)));
        assert_eq!(r.body, ObservedBody::Json(json!({"id": 1})));
        assert!(obs[1].response.is_none(), "status 0 is no response");
        assert!(from_har(b"{\"log\": {}}").is_err());
    }

    #[test]
    fn bodies_are_parsed_only_when_useful() {
        assert_eq!(body_of(Some("application/problem+json"), b"{\"a\":1}", true), ObservedBody::Json(json!({"a": 1})));
        assert_eq!(body_of(Some("text/plain"), b"hi", true), ObservedBody::Other);
        assert!(matches!(body_of(Some("application/json"), b"{\"a\":", true), ObservedBody::Unavailable(_)));
        assert!(matches!(body_of(Some("application/json"), b"{}", false), ObservedBody::Unavailable(_)));
        assert_eq!(body_of(Some("application/json"), b"", true), ObservedBody::Empty);
    }
}
