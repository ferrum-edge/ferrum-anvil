//! SARIF 2.1.0 output, for code-scanning dashboards and CI annotations.

use crate::lint::LintReport;
use crate::ruleset::Severity;
use serde_json::{Value, json};
use std::collections::BTreeMap;

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
            if let Some(u) = &f.docs_url {
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
            let mut physical = json!({"artifactLocation": {"uri": artifact_uri}});
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
    json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "Ferrum Anvil",
                "informationUri": "https://github.com/ferrum-edge/ferrum-anvil",
                "rules": rules.into_values().collect::<Vec<_>>(),
            }},
            "results": results,
        }],
    })
}
