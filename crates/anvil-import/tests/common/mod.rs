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

pub fn dump(r: &ImportResult) -> String {
    serde_json::to_string_pretty(&serde_json::json!({
        "requests": r.requests.iter().map(|q| serde_json::json!({"name": q.name, "folder": q.folder_id, "spec": q.spec})).collect::<Vec<_>>(),
        "folders": r.folders.iter().map(|f| (f.name.clone(), f.meta.id, f.parent_id)).collect::<Vec<_>>(),
        "envs": r.environments,
        "report": r.report,
        "ws": r.workspace,
    }))
    .unwrap()
}
