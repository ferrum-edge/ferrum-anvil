//! Applies the versioned wording catalog to rule drafts.

use crate::Draft;
use anvil_domain::diagnostics::{DiagnosticFinding, Owner, Remediation};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::OnceLock;

const RAW: &str = include_str!("../../../catalog/diagnostics/findings.en.json");

#[derive(Debug, Deserialize)]
pub struct FindingsCatalog {
    pub version: String,
    pub locale: String,
    pub findings: HashMap<String, Template>,
    /// Shared wording that rules attach to findings by evidence
    /// ([`crate::Draft::alt_fragment`]).
    #[serde(default)]
    pub fragments: HashMap<String, String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Template {
    pub title: String,
    pub explanation: String,
    #[serde(default)]
    pub alternatives: Vec<String>,
    #[serde(default)]
    pub does_not_prove: Vec<String>,
    #[serde(default)]
    pub remediation: Vec<RemediationTemplate>,
    #[serde(default)]
    pub confirm_with: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct RemediationTemplate {
    pub text: String,
    pub owner: String,
}

pub fn catalog() -> &'static FindingsCatalog {
    static C: OnceLock<FindingsCatalog> = OnceLock::new();
    C.get_or_init(|| serde_json::from_str(RAW).expect("embedded findings catalog is valid JSON"))
}

fn owner(s: &str) -> Owner {
    match s {
        "caller" => Owner::Caller,
        "gateway_operator" => Owner::GatewayOperator,
        "api_owner" => Owner::ApiOwner,
        "network_administrator" => Owner::NetworkAdministrator,
        "identity_provider" => Owner::IdentityProvider,
        _ => Owner::Unknown,
    }
}

/// Substitute `{name}` placeholders. Unknown placeholders are removed so a
/// missing value never leaks template syntax; tests assert every placeholder
/// used by a rule is supplied.
pub fn fill(t: &str, vars: &[(&'static str, String)]) -> String {
    let mut out = String::with_capacity(t.len() + 32);
    let mut rest = t;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        match after.find('}') {
            Some(close) if after[..close].chars().all(|c| c.is_ascii_alphanumeric() || c == '_') => {
                let key = &after[..close];
                if let Some((_, v)) = vars.iter().rev().find(|(k, _)| *k == key) {
                    out.push_str(v);
                }
                rest = &after[close + 1..];
            }
            _ => {
                out.push('{');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    // Collapse doubled spaces left by empty optional placeholders.
    let mut collapsed = String::with_capacity(out.len());
    let mut prev_space = false;
    for ch in out.chars() {
        if ch == ' ' {
            if !prev_space {
                collapsed.push(ch);
            }
            prev_space = true;
        } else {
            prev_space = false;
            collapsed.push(ch);
        }
    }
    collapsed.trim().replace(" .", ".")
}

pub fn render(d: Draft) -> DiagnosticFinding {
    let cat = catalog();
    let tpl = cat.findings.get(&d.code).cloned().unwrap_or_else(|| Template {
        title: d.code.clone(),
        explanation: String::from("No wording is available for this finding code."),
        alternatives: vec![],
        does_not_prove: vec![],
        remediation: vec![],
        confirm_with: vec![],
    });
    let (title, explanation) = match &d.catalog_text {
        Some((t, e)) => (t.clone(), e.clone()),
        None => (fill(&tpl.title, &d.vars), fill(&tpl.explanation, &d.vars)),
    };
    let mut alternatives: Vec<String> = tpl.alternatives.iter().map(|a| fill(a, &d.vars)).collect();
    alternatives.extend(d.extra_alternatives);
    alternatives.extend(d.alt_fragments.iter().filter_map(|k| cat.fragments.get(*k)).map(|t| fill(t, &d.vars)));
    let mut does_not_prove: Vec<String> = tpl.does_not_prove.iter().map(|a| fill(a, &d.vars)).collect();
    does_not_prove.extend(d.extra_does_not_prove);
    let mut remediation: Vec<Remediation> =
        tpl.remediation.iter().map(|r| Remediation { text: fill(&r.text, &d.vars), owner: owner(&r.owner) }).collect();
    remediation.extend(d.extra_remediation);
    let mut confirm_with: Vec<String> = tpl.confirm_with.iter().map(|a| fill(a, &d.vars)).collect();
    confirm_with.extend(d.extra_confirm_with);
    DiagnosticFinding {
        code: d.code,
        rule_id: d.rule_id.to_string(),
        rule_version: d.rule_version,
        title,
        explanation,
        scope: d.scope,
        confidence: d.confidence,
        severity: d.severity,
        evidence: d.evidence,
        alternatives,
        does_not_prove,
        remediation,
        owner: d.owner,
        confirm_with,
    }
}
