//! SARIF 2.1.0 output, for code-scanning dashboards and CI annotations.

use crate::lint::LintReport;
use crate::ruleset::Severity;
use serde_json::{Value, json};
use std::collections::BTreeMap;

/// Percent-encode everything but unreserved characters and `/`.
fn encode_path(p: &str) -> String {
    let mut out = String::new();
    for b in p.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~' | b'/') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// A SARIF artifact location for a file path: a `file:` URI when absolute,
/// else relative to `%SRCROOT%` (the repository, for code scanning).
pub fn artifact_location(path: &str) -> Value {
    if path == "-" {
        return json!({"uri": "stdin"});
    }
    let p = path.replace('\\', "/");
    let drive = p.len() > 2 && p.as_bytes()[1] == b':' && p.as_bytes()[0].is_ascii_alphabetic();
    if drive {
        // `file:///C:/…`: the drive's colon stays as it is.
        json!({"uri": format!("file:///{}:{}", &p[..1], encode_path(&p[2..]))})
    } else if p.starts_with('/') {
        json!({"uri": format!("file://{}", encode_path(&p))})
    } else {
        json!({"uri": encode_path(p.trim_start_matches("./")), "uriBaseId": "%SRCROOT%"})
    }
}

fn level(s: Severity) -> &'static str {
    match s {
        Severity::Error => "error",
        Severity::Warn => "warning",
        Severity::Info | Severity::Hint => "note",
    }
}

/// A SARIF log with one run. `artifact_uri` names the linted file as the
/// consumer should see it (a repository-relative path, typically).
pub fn to_sarif(report: &LintReport, artifact_uri: &str) -> Value {
    let mut rules: BTreeMap<&str, Value> = BTreeMap::new();
    for f in &report.findings {
        rules.entry(&f.rule).or_insert_with(|| {
            let mut r = json!({
                "id": f.rule,
                "defaultConfiguration": {"level": level(f.severity)},
                "properties": {"ruleset": f.ruleset},
            });
            if let Some(h) = &f.how_to_fix {
                r["help"] = json!({"text": h});
            }
            if let Some(u) = f.docs_url.as_ref().filter(|u| u.starts_with("https://") || u.starts_with("http://")) {
                r["helpUri"] = json!(u);
            }
            r
        });
    }
    let index: BTreeMap<&str, usize> = rules.keys().enumerate().map(|(i, k)| (*k, i)).collect();
    let results: Vec<Value> = report
        .findings
        .iter()
        .map(|f| {
            let mut region = json!({});
            if let Some(l) = f.line {
                region["startLine"] = json!(l);
            }
            if let Some(c) = f.column {
                region["startColumn"] = json!(c);
            }
            let mut physical = json!({"artifactLocation": artifact_location(artifact_uri)});
            if f.line.is_some() {
                physical["region"] = region;
            }
            json!({
                "ruleId": f.rule,
                "ruleIndex": index[f.rule.as_str()],
                "level": level(f.severity),
                "message": {"text": f.message},
                "locations": [{
                    "physicalLocation": physical,
                    "logicalLocations": [{"fullyQualifiedName": f.pointer, "name": f.label}],
                }],
                "properties": {"severity": f.severity.label(), "target": f.target.name()},
            })
        })
        .collect();
    let mut notes = vec![];
    if report.dropped > 0 {
        notes.push(
            json!({"level": "warning", "message": {"text": format!("{} more findings were counted but not listed", report.dropped)}}),
        );
    }
    if report.examples_not_checked > 0 {
        notes.push(json!({"level": "note", "message": {"text": format!(
            "{} example(s) were not checked: their schema uses an external reference or an unsupported pattern, refers to itself, or expands too far",
            report.examples_not_checked
        )}}));
    }
    if report.skipped_operations > 0 {
        notes.push(json!({"level": "warning", "message": {"text": format!(
            "the description is too large to lint completely: {} operation(s) were not checked",
            report.skipped_operations
        )}}));
    }
    if report.unresolved_ref_count > 0 {
        notes.push(json!({"level": "warning", "message": {"text": format!(
            "{} $ref(s) could not be followed (external, dangling or cyclic); the objects behind them were not checked",
            report.unresolved_ref_count
        )}}));
    }
    json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "Ferrum Anvil",
                "informationUri": "https://github.com/ferrum-edge/ferrum-anvil",
                "rules": rules.into_values().collect::<Vec<_>>(),
            }},
            "columnKind": "unicodeCodePoints",
            "invocations": [{"executionSuccessful": true, "toolExecutionNotifications": notes}],
            "results": results,
            "properties": {"counts": report.counts, "dropped": report.dropped, "unresolvedRefs": report.unresolved_refs},
        }],
    })
}
