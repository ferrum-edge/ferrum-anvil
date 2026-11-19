#![allow(dead_code)]

use anvil_domain::request::{Body, KeyValue, RequestSpec};
use anvil_domain::workspace::RequestDefinition;
use anvil_import::{ImportOptions, ImportResult, import};
use chrono::{TimeZone, Utc};

pub fn fixture(path: &str) -> Vec<u8> {
    let p = format!("{}/tests/fixtures/{path}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&p).unwrap_or_else(|e| panic!("read {p}: {e}"))
}

pub fn opts() -> ImportOptions {
    ImportOptions { imported_at: Some(Utc.with_ymd_and_hms(2026, 1, 2, 3, 4, 5).unwrap()), ..Default::default() }
}

pub fn run(path: &str, o: &ImportOptions) -> ImportResult {
    import(&fixture(path), o).unwrap_or_else(|e| panic!("import {path}: {e}"))
}

pub fn req<'a>(r: &'a ImportResult, key: &str) -> &'a RequestDefinition {
    r.requests
        .iter()
        .find(|q| q.spec.source.as_ref().is_some_and(|s| s.operation_key == key))
        .unwrap_or_else(|| panic!("no request with key {key}; have {:?}", keys(r)))
}

pub fn keys(r: &ImportResult) -> Vec<String> {
    r.requests.iter().filter_map(|q| q.spec.source.as_ref().map(|s| s.operation_key.clone())).collect()
}

pub fn header<'a>(s: &'a RequestSpec, name: &str) -> Option<&'a KeyValue> {
    s.headers.iter().find(|h| h.name.eq_ignore_ascii_case(name))
}

pub fn param<'a>(s: &'a RequestSpec, name: &str) -> Option<&'a KeyValue> {
    s.params.iter().find(|h| h.name == name)
}

pub fn json_body(s: &RequestSpec) -> serde_json::Value {
    match &s.body {
        Body::Json { text } => serde_json::from_str(text).unwrap_or_else(|e| panic!("body is not JSON ({e}): {text}")),
        other => panic!("expected a JSON body, got {other:?}"),
    }
}

pub fn codes(r: &ImportResult) -> Vec<String> {
    r.report.warnings.iter().chain(r.report.unsupported.iter()).map(|f| f.code.clone()).collect()
}

pub fn has(r: &ImportResult, code: &str) -> bool {
    codes(r).iter().any(|c| c == code)
}

pub fn has_at(r: &ImportResult, code: &str, pointer_part: &str) -> bool {
    r.report.warnings.iter().chain(r.report.unsupported.iter()).any(|f| f.code == code && f.pointer.contains(pointer_part))
}

/// `text` with `{{name}}` placeholders replaced by the given values, as the
/// engine's resolver substitutes them, parsed as JSON.
pub fn substituted(text: &str, vars: &[(&str, &str)]) -> serde_json::Value {
    let mut t = text.to_string();
    for (n, v) in vars {
        t = t.replace(&format!("{{{{{n}}}}}"), v);
    }
    serde_json::from_str(&t).unwrap_or_else(|e| panic!("not JSON after substitution ({e}): {t}"))
}

/// Whether `text` is exactly the placeholder an auth secret `field` gets:
/// `{{auth_<16 hex digits>_<field>}}`, possibly with a `_n` suffix.
pub fn is_auth_ref(text: &str, field: &str) -> bool {
    let Some(inner) = text.strip_prefix("{{auth_").and_then(|t| t.strip_suffix("}}")) else { return false };
    let Some((digest, rest)) = inner.split_at_checked(16) else { return false };
    digest.bytes().all(|b| b.is_ascii_hexdigit())
        && rest.strip_prefix('_').and_then(|r| r.strip_prefix(field)).is_some_and(|tail| {
            tail.is_empty() || tail.strip_prefix('_').is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
        })
}

/// The text of a template value.
pub fn template_of(v: &anvil_domain::secret::SensitiveValue) -> &str {
    match v {
        anvil_domain::secret::SensitiveValue::Template { value } => value,
        anvil_domain::secret::SensitiveValue::Secret { .. } => "",
    }
}

/// Whether `text` is a quarantined URL's placeholder,
/// `{{url-needs-review-<16 hex digits>}}`.
pub fn is_quarantined(text: &str) -> bool {
    text.strip_prefix("{{url-needs-review-")
        .and_then(|t| t.strip_suffix("}}"))
        .is_some_and(|h| h.len() == 16 && h.bytes().all(|b| b.is_ascii_hexdigit()))
}
