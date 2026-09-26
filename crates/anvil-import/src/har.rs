//! HAR 1.1/1.2 archives: each entry's request becomes a request (grouped by
//! host). Recorded responses and timings are not imported.
//!
//! Credentials are redacted by default: `Authorization`, `Cookie`,
//! API-key/token-like headers, credential-looking query parameters, form
//! fields and JSON body members are replaced by `{{placeholder}}`
//! variables and listed in [`crate::ImportReport::redactions`]. With
//! `include_credentials` the originals are kept (and marked sensitive).
//! Arbitrary text/XML bodies cannot be scanned reliably; they are reported.

use crate::builder::Builder;
use crate::common::{body_from_text, credential, dedupe_content_type, maybe_redact, parse_form, query_decode, scrub_json, split_query};
use crate::util::{is_credential_name, is_json_media, media_essence, ptr, scalar_text, str_of};
use crate::{Dialect, ImportError};
use anvil_domain::auth::AuthConfig;
use anvil_domain::request::{Body, KeyValue, MultipartContent, MultipartPart, RequestSpec};
use serde_json::Value;
use std::collections::BTreeSet;

/// Headers computed by the transport or meaningless outside the recorded
/// connection. Dropped (and reported once).
const DROPPED_HEADERS: &[&str] =
    &["content-length", "host", "connection", "transfer-encoding", "keep-alive", "upgrade", "te", "proxy-connection"];

pub(crate) fn import(root: &Value, b: &mut Builder) -> Result<(), ImportError> {
    let log = root.get("log").ok_or_else(|| ImportError::Invalid {
        dialect: Dialect::Har,
        pointer: "/log".into(),
        message: "missing `log`".into(),
    })?;
    let version = log.get("version").map(scalar_text).unwrap_or_default();
    if !version.is_empty() && version != "1.2" && version != "1.1" {
        b.report.warn("har_version", "/log/version", format!("HAR version '{version}' is not 1.1/1.2; imported with the 1.2 mapping"));
    }
    let creator = log.pointer("/creator/name").and_then(Value::as_str).unwrap_or("");
    b.workspace.name = if creator.is_empty() { "HAR import".into() } else { format!("HAR import ({creator})") };
    b.title = Some(b.workspace.name.clone());
    b.workspace.auth = AuthConfig::None;
    let entries = log.get("entries").and_then(Value::as_array).cloned().unwrap_or_default();
    let mut dropped: BTreeSet<String> = BTreeSet::new();
    for (i, e) in entries.iter().enumerate() {
        let at = format!("/log/entries/{i}");
        let Some(req) = e.get("request") else {
            b.report.warn("har_entry_without_request", &at, "entry has no request; skipped");
            continue;
        };
        let rptr = ptr(&at, "request");
        let method = str_of(req, "method").unwrap_or("GET").to_ascii_uppercase();
        let raw_url = str_of(req, "url").unwrap_or("").to_string();
        let lower = raw_url.to_ascii_lowercase();
        if !(lower.starts_with("http://") || lower.starts_with("https://")) {
            b.report.counts.operations_found += 1;
            b.skipped();
            let scheme = raw_url.split(':').next().unwrap_or("");
            b.report.unsupported(
                "har_non_http",
                &ptr(&rptr, "url"),
                format!("'{scheme}:' entries are not imported (only http/https requests)"),
            );
            continue;
        }
        if !b.admit(&at) {
            continue;
        }
        entry(b, req, &rptr, &method, &raw_url, i, &mut dropped);
    }
    if !dropped.is_empty() {
        b.report.warn(
            "har_headers_dropped",
            "/log/entries",
            format!(
                "connection-specific headers are recomputed when sending and were not imported: {}",
                dropped.into_iter().collect::<Vec<_>>().join(", ")
            ),
        );
    }
    Ok(())
}

fn entry(b: &mut Builder, req: &Value, rptr: &str, method: &str, raw_url: &str, index: usize, dropped: &mut BTreeSet<String>) {
    let uptr = ptr(rptr, "url");
    let mut auth = AuthConfig::Inherit;
    let mut url = crate::common::strip_fragment(raw_url).to_string();
    // Userinfo is never kept in the URL (the engine refuses it).
    if let Some((scheme, rest)) = url.split_once("://").map(|(a, c)| (a.to_string(), c.to_string()))
        && let Some(p) = rest.find('@').filter(|p| !rest[..*p].contains('/'))
    {
        let userinfo = &rest[..p];
        let (user, pass) = userinfo.split_once(':').unwrap_or((userinfo, ""));
        auth = AuthConfig::Basic {
            username: query_decode(user),
            password: credential(b, &query_decode(pass), "password", &uptr, "password in the URL"),
        };
        url = format!("{scheme}://{}", &rest[p + 1..]);
    }
    let (base, pairs) = split_query(&url);
    let base = if pairs.is_empty() && base.contains('?') { redact_raw_query(b, &base, &uptr) } else { base };
    let params: Vec<KeyValue> = pairs
        .into_iter()
        .enumerate()
        .map(|(n, (k, v))| {
            let (value, sensitive) = maybe_redact(b, &k, &v, &format!("{}/{n}", ptr(rptr, "queryString")), "query parameter");
            KeyValue { name: k, value, enabled: true, description: String::new(), sensitive }
        })
        .collect();

    let mut headers = vec![];
    let mut has_cookie = false;
    for (n, h) in req.get("headers").and_then(Value::as_array).into_iter().flatten().enumerate() {
        let hp = format!("{}/{n}", ptr(rptr, "headers"));
        let name = str_of(h, "name").unwrap_or("").to_string();
        if name.is_empty() || name.starts_with(':') {
            continue;
        }
        let lower = name.to_ascii_lowercase();
        if DROPPED_HEADERS.contains(&lower.as_str()) {
            dropped.insert(lower);
            continue;
        }
        has_cookie |= lower == "cookie";
        let raw = h.get("value").map(scalar_text).unwrap_or_default();
        let (value, sensitive) = maybe_redact(b, &name, &raw, &hp, "header");
        headers.push(KeyValue { name, value, enabled: true, description: String::new(), sensitive });
    }
    if !has_cookie && let Some(cookies) = req.get("cookies").and_then(Value::as_array).filter(|c| !c.is_empty()) {
        let joined = cookies
            .iter()
            .filter_map(|c| Some(format!("{}={}", str_of(c, "name")?, c.get("value").map(scalar_text).unwrap_or_default())))
            .collect::<Vec<_>>()
            .join("; ");
        let (value, sensitive) = maybe_redact(b, "Cookie", &joined, &ptr(rptr, "cookies"), "header");
        headers.push(KeyValue { name: "Cookie".into(), value, enabled: true, description: String::new(), sensitive });
    }

    let body = match req.get("postData") {
        Some(pd) => post_data(b, pd, &ptr(rptr, "postData")),
        None => Body::None,
    };
    dedupe_content_type(&mut headers, &body);

    let mut spec = RequestSpec::http(method, &base);
    spec.params = params;
    spec.headers = headers;
    spec.body = body;
    spec.auth = auth;
    let host = base.split("://").nth(1).and_then(|r| r.split(['/', '?']).next()).unwrap_or("").to_string();
    let path = base.split("://").nth(1).and_then(|r| r.find('/').map(|p| r[p..].to_string())).unwrap_or_else(|| "/".into());
    let folder = if host.is_empty() { None } else { Some(b.folder(None, &format!("har:{host}"), &host)) };
    let name = format!("{method} {}", path.split('?').next().unwrap_or(&path));
    let key = format!("har:{index}:{method} {}", base.split('?').next().unwrap_or(&base));
    b.add_request(folder, &name, &key, spec, rptr);
}

/// A query kept verbatim (not a plain list of pairs): redact the values of
/// credential-named segments in place.
fn redact_raw_query(b: &mut Builder, url: &str, at: &str) -> String {
    let Some((base, q)) = url.split_once('?') else { return url.to_string() };
    let segs: Vec<String> = q
        .split('&')
        .map(|seg| match seg.split_once('=') {
            Some((k, v)) if is_credential_name(&query_decode(k)) && !v.is_empty() => {
                let (nv, _) = maybe_redact(b, &query_decode(k), &query_decode(v), at, "query parameter");
                format!("{k}={nv}")
            }
            _ => seg.to_string(),
        })
        .collect();
    format!("{base}?{}", segs.join("&"))
}

fn post_data(b: &mut Builder, pd: &Value, at: &str) -> Body {
    let mime = str_of(pd, "mimeType").unwrap_or("").to_string();
    let text = str_of(pd, "text").unwrap_or("").to_string();
    if str_of(pd, "encoding").is_some_and(|e| e.eq_ignore_ascii_case("base64")) {
        b.report.unsupported(
            "har_binary_body",
            at,
            "base64-encoded (binary) request bodies are not imported; attach the file as a binary body",
        );
        return Body::None;
    }
    let essence = media_essence(&mime);
    let params = pd.get("params").and_then(Value::as_array).cloned().unwrap_or_default();
    if essence == "multipart/form-data" {
        if params.is_empty() && !text.is_empty() {
            b.report.unsupported(
                "har_multipart_text",
                at,
                "multipart body recorded without params is not split into parts; imported as raw text (not scanned for credentials)",
            );
            return Body::Raw { text, content_type: Some(mime) };
        }
        let mut parts = vec![];
        for (n, p) in params.iter().enumerate() {
            let pp = format!("{}/{n}", ptr(at, "params"));
            let name = str_of(p, "name").unwrap_or("").to_string();
            let ct = str_of(p, "contentType").map(str::to_string);
            if let Some(f) = str_of(p, "fileName") {
                b.report.warn(
                    "file_part_requires_attachment",
                    &pp,
                    format!("file part '{name}' ({f}) was not captured: attach the file before sending (imported disabled)"),
                );
                parts.push(MultipartPart {
                    name,
                    enabled: false,
                    content: MultipartContent::Text { value: String::new() },
                    content_type: ct,
                });
                continue;
            }
            let raw = p.get("value").map(scalar_text).unwrap_or_default();
            let (value, _) = maybe_redact(b, &name, &raw, &pp, "form field");
            parts.push(MultipartPart { name, enabled: true, content: MultipartContent::Text { value }, content_type: ct });
        }
        return Body::Multipart { parts };
    }
    if essence == "application/x-www-form-urlencoded" {
        let fields = if !text.is_empty() {
            parse_form(&text)
        } else {
            Some(
                params
                    .iter()
                    .map(|p| KeyValue::new(str_of(p, "name").unwrap_or(""), p.get("value").map(scalar_text).unwrap_or_default()))
                    .collect(),
            )
        };
        if let Some(mut fields) = fields {
            for (n, f) in fields.iter_mut().enumerate() {
                let (value, sensitive) = maybe_redact(b, &f.name, &f.value, &format!("{at}/params/{n}"), "form field");
                f.value = value;
                f.sensitive = sensitive;
            }
            return Body::FormUrlEncoded { fields };
        }
    }
    if text.is_empty() {
        return Body::None;
    }
    if is_json_media(&mime) || (mime.is_empty() && text.trim_start().starts_with(['{', '['])) {
        if let Ok(mut v) = serde_json::from_str::<Value>(&text) {
            let before = b.report.redactions.len();
            scrub_json(b, &mut v, &ptr(at, "text"));
            let text = if b.report.redactions.len() > before { serde_json::to_string_pretty(&v).unwrap_or(text) } else { text };
            return body_from_text(Some(if mime.is_empty() { "application/json" } else { &mime }), text).0;
        }
        b.report.warn("body_not_scanned", at, "JSON body could not be parsed; it was not scanned for credentials");
        return Body::Raw { text, content_type: Some(mime) };
    }
    if !b.opts.include_credentials {
        b.report.warn(
            "body_not_scanned",
            at,
            format!("'{mime}' body is imported verbatim; it was not scanned for credentials (review before sharing)"),
        );
    }
    body_from_text(if mime.is_empty() { None } else { Some(&mime) }, text).0
}
