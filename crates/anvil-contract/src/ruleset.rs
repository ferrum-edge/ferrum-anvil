//! Rulesets: a team's API standards as data.
//!
//! ```yaml
//! anvil_ruleset: 1
//! name: Acme API standards
//! extends: [anvil:recommended]
//! rules:
//!   info-license: error            # change an inherited rule's severity
//!   operation-description: off     # or turn it off
//!   acme-property-camel-case:
//!     description: Property names are camelCase.
//!     severity: error
//!     given: property
//!     then:
//!       field: name
//!       function: casing
//!       options: { type: camel }
//!     how_to_fix: Rename the property, e.g. `created_at` → `createdAt`.
//! ```
//!
//! Loading never reads files or the network: `extends` names built-in
//! rulesets only, and several rulesets (a company base plus a team overlay)
//! are layered by the caller in order. Every rule, target, function and
//! option is checked on load; unknown keys are errors.

use crate::checks::Function;
use crate::model::TargetKind;
use anvil_import::{Dialect, ImportOptions, Syntax};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

/// Largest ruleset file accepted.
pub const MAX_RULESET_BYTES: usize = 1024 * 1024;
/// Most rules in one merged rule set.
pub const MAX_RULES: usize = 2_000;

pub const RECOMMENDED: &str = "anvil:recommended";
const RECOMMENDED_YAML: &str = include_str!("../rulesets/recommended.yaml");

/// Names of the built-in rulesets.
pub const BUILTIN: &[&str] = &[RECOMMENDED];

/// How serious a lint finding is (`off` in a ruleset turns a rule off).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[schemars(rename = "LintSeverity")]
pub enum Severity {
    Hint,
    Info,
    Warn,
    Error,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Severity::Hint => "hint",
            Severity::Info => "info",
            Severity::Warn => "warn",
            Severity::Error => "error",
        }
    }

    /// `off` is `Ok(None)`.
    pub fn parse(s: &str) -> Result<Option<Severity>, String> {
        Ok(Some(match s {
            "error" => Severity::Error,
            "warn" | "warning" => Severity::Warn,
            "info" | "information" => Severity::Info,
            "hint" => Severity::Hint,
            "off" => return Ok(None),
            other => return Err(format!("unknown severity '{other}' (use error, warn, info, hint or off)")),
        }))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize, JsonSchema)]
#[error("{source_name}: {message}")]
pub struct RulesetError {
    /// The ruleset (file name or built-in name) the problem is in.
    pub source_name: String,
    /// The rule, when the problem is in one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    pub message: String,
}

impl RulesetError {
    fn new(source: &str, rule: Option<&str>, message: impl Into<String>) -> Self {
        let message = message.into();
        RulesetError {
            source_name: source.to_string(),
            rule: rule.map(str::to_string),
            message: match rule {
                Some(r) => format!("rule '{r}': {message}"),
                None => message,
            },
        }
    }
}

/// Which parts of the document a rule looks at.
#[derive(Debug)]
pub enum Given {
    Targets(Vec<TargetKind>),
    JsonPath { path: Box<serde_json_path::JsonPath>, source: String },
}

/// A field path: dot-separated names, `*` for every item of a list or map,
/// and a leading `raw.` for the original OpenAPI object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldPath {
    pub raw: bool,
    pub tokens: Vec<FieldToken>,
    pub source: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldToken {
    Key(String),
    Each,
}

impl FieldPath {
    pub fn parse(s: &str) -> Result<FieldPath, String> {
        let s = s.trim();
        if s.is_empty() {
            return Err("empty field".into());
        }
        let mut parts: Vec<&str> = s.split('.').collect();
        let raw = parts.first() == Some(&"raw");
        if raw {
            parts.remove(0);
        }
        let mut tokens = vec![];
        for p in parts {
            match p {
                "" => return Err(format!("field '{s}' has an empty segment")),
                "*" => tokens.push(FieldToken::Each),
                k => tokens.push(FieldToken::Key(k.to_string())),
            }
        }
        Ok(FieldPath { raw, tokens, source: s.to_string() })
    }
}

/// One `then`/`where` entry.
#[derive(Debug)]
pub struct Assertion {
    pub field: Option<FieldPath>,
    pub function: Function,
}

/// A compiled rule.
#[derive(Debug)]
pub struct Rule {
    pub id: String,
    pub description: Option<String>,
    pub message: Option<String>,
    pub severity: Severity,
    pub given: Given,
    pub conditions: Vec<Assertion>,
    pub then: Vec<Assertion>,
    /// Dialects the rule applies to; empty = all.
    pub formats: Vec<Dialect>,
    pub how_to_fix: Option<String>,
    pub docs_url: Option<String>,
    /// The ruleset that defined the rule.
    pub ruleset: String,
}

impl Rule {
    pub fn applies_to(&self, d: Dialect) -> bool {
        self.formats.is_empty() || self.formats.contains(&d)
    }

    pub fn given_label(&self) -> String {
        match &self.given {
            Given::Targets(t) => t.iter().map(|k| k.name()).collect::<Vec<_>>().join(", "),
            Given::JsonPath { source, .. } => source.clone(),
        }
    }
}

/// A ruleset that took part in a [`RuleSet`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RulesetSummary {
    pub name: String,
    /// File name, or the built-in name.
    pub source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub builtin: bool,
    /// SHA-256 (hex) of the ruleset text.
    pub sha256: String,
}

/// A rule as listed to users.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RuleInfo {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub severity: Severity,
    pub given: String,
    /// Dialect labels the rule is limited to; empty = every dialect.
    pub formats: Vec<String>,
    pub ruleset: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub how_to_fix: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub docs_url: Option<String>,
}

/// Rules merged from one or more rulesets, ready to run.
#[derive(Debug, Default)]
pub struct RuleSet {
    pub rules: Vec<Rule>,
    pub sources: Vec<RulesetSummary>,
    /// Rules turned off by a later ruleset (listed, not run).
    pub disabled: Vec<String>,
}

impl RuleSet {
    /// A built-in ruleset by name (`anvil:recommended`).
    pub fn builtin(name: &str) -> Result<RuleSet, RulesetError> {
        let mut set = RuleSet::default();
        set.add_builtin(name, name)?;
        Ok(set)
    }

    /// The recommended rules alone.
    pub fn recommended() -> RuleSet {
        RuleSet::builtin(RECOMMENDED).expect("the built-in ruleset is valid")
    }

    /// Layer rulesets in order: each may extend built-ins, add rules,
    /// replace a rule of the same id, or change an earlier rule's severity.
    pub fn load(files: &[(String, Vec<u8>)]) -> Result<RuleSet, RulesetError> {
        let mut set = RuleSet::default();
        for (name, bytes) in files {
            set.add(name, bytes, false)?;
        }
        Ok(set)
    }

    /// Add a built-in ruleset once: extending it again (from a second
    /// ruleset) keeps the severities earlier rulesets gave its rules.
    fn add_builtin(&mut self, name: &str, requested_by: &str) -> Result<(), RulesetError> {
        if self.sources.iter().any(|s| s.builtin && s.source == name) {
            return Ok(());
        }
        match name {
            RECOMMENDED => self.add(RECOMMENDED, RECOMMENDED_YAML.as_bytes(), true),
            other => Err(RulesetError::new(
                requested_by,
                None,
                format!(
                    "unknown ruleset '{other}' in `extends` (built-in: {}); layer your own rulesets by passing several instead",
                    BUILTIN.join(", ")
                ),
            )),
        }
    }

    /// Add one ruleset's text.
    pub fn add(&mut self, source: &str, bytes: &[u8], builtin: bool) -> Result<(), RulesetError> {
        let err = |rule: Option<&str>, m: String| RulesetError::new(source, rule, m);
        let (top, summary) = header(source, bytes, builtin)?;
        let name = summary.name.clone();
        match top.get("extends") {
            None | Some(Value::Null) => {}
            Some(Value::String(s)) => self.add_builtin(s, source)?,
            Some(Value::Array(list)) => {
                for e in list {
                    let Some(s) = e.as_str() else { return Err(err(None, "`extends` lists ruleset names".into())) };
                    self.add_builtin(s, source)?;
                }
            }
            Some(_) => return Err(err(None, "`extends` is a ruleset name or a list of them".into())),
        }
        self.sources.push(summary);
        let rules = match top.get("rules") {
            None | Some(Value::Null) => Map::new(),
            Some(Value::Object(m)) => m.clone(),
            Some(_) => return Err(err(None, "`rules` is a mapping of rule ids".into())),
        };
        for (id, entry) in rules {
            if !valid_id(&id) {
                return Err(err(Some(&id), "rule ids use letters, digits, '.', '_' and '-'".into()));
            }
            match entry {
                Value::String(s) => self.set_severity(source, &id, &s)?,
                Value::Object(o) if o.len() == 1 && o.contains_key("severity") => {
                    let Some(s) = o["severity"].as_str() else { return Err(err(Some(&id), "`severity` must be text".into())) };
                    self.set_severity(source, &id, s)?;
                }
                Value::Object(o) => {
                    let rule = compile_rule(source, &name, &id, &o)?;
                    self.rules.retain(|r| r.id != id);
                    self.disabled.retain(|d| d != &id);
                    match rule {
                        Some(r) => self.rules.push(r),
                        None => self.disabled.push(id.clone()),
                    }
                    if self.rules.len() > MAX_RULES {
                        return Err(err(None, format!("more than {MAX_RULES} rules")));
                    }
                }
                _ => return Err(err(Some(&id), "a rule is a mapping, or a severity for an inherited rule".into())),
            }
        }
        Ok(())
    }

    fn set_severity(&mut self, source: &str, id: &str, s: &str) -> Result<(), RulesetError> {
        let sev = Severity::parse(s).map_err(|m| RulesetError::new(source, Some(id), m))?;
        if let Some(pos) = self.rules.iter().position(|r| r.id == id) {
            match sev {
                Some(sev) => self.rules[pos].severity = sev,
                None => {
                    self.rules.remove(pos);
                    self.disabled.push(id.to_string());
                }
            }
            Ok(())
        } else if self.disabled.iter().any(|d| d == id) {
            if sev.is_some() {
                return Err(RulesetError::new(source, Some(id), "the rule was turned off earlier; define it again to turn it back on"));
            }
            Ok(())
        } else {
            Err(RulesetError::new(source, Some(id), "no inherited rule has this id; a new rule needs `given` and `then`"))
        }
    }

    pub fn list(&self) -> Vec<RuleInfo> {
        self.rules
            .iter()
            .map(|r| RuleInfo {
                id: r.id.clone(),
                description: r.description.clone(),
                severity: r.severity,
                given: r.given_label(),
                formats: r.formats.iter().map(|d| d.label().to_string()).collect(),
                ruleset: r.ruleset.clone(),
                how_to_fix: r.how_to_fix.clone(),
                docs_url: r.docs_url.clone(),
            })
            .collect()
    }
}

/// Read a ruleset's top level (format version, name, version,
/// description) without compiling its rules.
pub fn describe(source: &str, bytes: &[u8]) -> Result<RulesetSummary, RulesetError> {
    header(source, bytes, false).map(|(_, s)| s)
}

fn header(source: &str, bytes: &[u8], builtin: bool) -> Result<(Map<String, Value>, RulesetSummary), RulesetError> {
    let err = |m: String| RulesetError::new(source, None, m);
    if bytes.len() > MAX_RULESET_BYTES {
        return Err(err(format!("the ruleset is {} bytes; the limit is {MAX_RULESET_BYTES}", bytes.len())));
    }
    let opts = ImportOptions { max_nodes: 200_000, ..ImportOptions::default() };
    let (doc, _syntax): (Value, Syntax) = anvil_import::parse_document(bytes, &opts).map_err(|e| err(e.to_string()))?;
    let Value::Object(top) = doc else { return Err(err("a ruleset is a mapping".into())) };
    for k in top.keys() {
        if !matches!(k.as_str(), "anvil_ruleset" | "name" | "description" | "version" | "extends" | "rules") {
            return Err(err(format!("unknown key '{k}' (expected anvil_ruleset, name, description, version, extends, rules)")));
        }
    }
    match top.get("anvil_ruleset") {
        Some(v) if v.as_u64() == Some(1) || v.as_str() == Some("1") => {}
        Some(v) => return Err(err(format!("unsupported anvil_ruleset version {v}; this build reads version 1"))),
        None => return Err(err("missing `anvil_ruleset: 1` (the ruleset format version)".into())),
    }
    let text_field = |k: &str| -> Result<Option<String>, RulesetError> {
        match top.get(k) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(s)) => Ok(Some(s.clone())),
            Some(Value::Number(n)) => Ok(Some(n.to_string())),
            Some(_) => Err(err(format!("`{k}` must be text"))),
        }
    };
    let summary = RulesetSummary {
        name: text_field("name")?.unwrap_or_else(|| source.to_string()),
        source: source.to_string(),
        version: text_field("version")?,
        description: text_field("description")?,
        builtin,
        sha256: hex::encode(Sha256::digest(bytes)),
    };
    Ok((top, summary))
}

fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 128 && id.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// Dialects named by a `formats` entry.
fn formats_of(name: &str) -> Option<Vec<Dialect>> {
    Some(match name {
        "swagger-2.0" | "oas2" | "swagger2" => vec![Dialect::Swagger20],
        "openapi-3.0" | "oas3_0" | "oas3.0" => vec![Dialect::OpenApi30],
        "openapi-3.1" | "oas3_1" | "oas3.1" => vec![Dialect::OpenApi31],
        "openapi-3.2" | "oas3_2" | "oas3.2" => vec![Dialect::OpenApi32],
        "oas3" | "openapi-3" => vec![Dialect::OpenApi30, Dialect::OpenApi31, Dialect::OpenApi32],
        _ => return None,
    })
}

const RULE_KEYS: &[&str] =
    &["description", "message", "severity", "given", "where", "then", "formats", "how_to_fix", "docs_url", "recommended"];

fn compile_rule(source: &str, ruleset: &str, id: &str, o: &Map<String, Value>) -> Result<Option<Rule>, RulesetError> {
    let err = |m: String| RulesetError::new(source, Some(id), m);
    for k in o.keys() {
        if !RULE_KEYS.contains(&k.as_str()) {
            return Err(err(format!("unknown key '{k}' (expected {})", RULE_KEYS.join(", "))));
        }
    }
    let text = |k: &str| -> Result<Option<String>, RulesetError> {
        match o.get(k) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(s)) => Ok(Some(s.clone())),
            Some(_) => Err(err(format!("`{k}` must be text"))),
        }
    };
    let severity = match o.get("severity") {
        None | Some(Value::Null) => Some(Severity::Warn),
        Some(Value::String(s)) => Severity::parse(s).map_err(err)?,
        Some(_) => return Err(err("`severity` must be text".into())),
    };
    let given = match o.get("given") {
        Some(Value::String(s)) => given_of(s).map_err(err)?,
        Some(Value::Array(list)) => {
            let mut kinds = vec![];
            for g in list {
                let Some(s) = g.as_str() else { return Err(err("`given` lists target names".into())) };
                match given_of(s).map_err(err)? {
                    Given::Targets(t) => kinds.extend(t),
                    Given::JsonPath { .. } => return Err(err("a JSONPath `given` cannot be combined with targets".into())),
                }
            }
            if kinds.is_empty() {
                return Err(err("`given` is empty".into()));
            }
            Given::Targets(kinds)
        }
        Some(Value::Object(g)) => match (g.get("jsonpath").and_then(Value::as_str), g.len()) {
            (Some(p), 1) => jsonpath(p).map_err(err)?,
            _ => return Err(err("`given` object form is `{ jsonpath: \"$…\" }`".into())),
        },
        _ => return Err(err(format!("`given` is required: one of {} or {{ jsonpath: … }}", target_names()))),
    };
    let then = assertions(o.get("then")).map_err(|m| err(format!("then: {m}")))?;
    if then.is_empty() {
        return Err(err("`then` is required".into()));
    }
    let conditions = assertions(o.get("where")).map_err(|m| err(format!("where: {m}")))?;
    let mut formats = vec![];
    match o.get("formats") {
        None | Some(Value::Null) => {}
        Some(Value::Array(list)) => {
            for f in list {
                let name = f.as_str().unwrap_or_default();
                let Some(d) = formats_of(name) else {
                    return Err(err(format!(
                        "unknown format '{name}' (use swagger-2.0, openapi-3.0, openapi-3.1, openapi-3.2, oas2, oas3)"
                    )));
                };
                formats.extend(d);
            }
        }
        Some(_) => return Err(err("`formats` is a list".into())),
    }
    if let Some(v) = o.get("recommended")
        && !v.is_boolean()
    {
        return Err(err("`recommended` is true or false".into()));
    }
    let Some(severity) = severity else { return Ok(None) };
    Ok(Some(Rule {
        id: id.to_string(),
        description: text("description")?,
        message: text("message")?,
        severity,
        given,
        conditions,
        then,
        formats,
        how_to_fix: text("how_to_fix")?,
        docs_url: text("docs_url")?,
        ruleset: ruleset.to_string(),
    }))
}

fn target_names() -> String {
    TargetKind::ALL.iter().map(|k| k.name()).collect::<Vec<_>>().join(", ")
}

fn given_of(s: &str) -> Result<Given, String> {
    if s.starts_with('$') {
        return jsonpath(s);
    }
    TargetKind::parse(s)
        .map(|k| Given::Targets(vec![k]))
        .ok_or_else(|| format!("unknown target '{s}' (use {} or a JSONPath)", target_names()))
}

fn jsonpath(s: &str) -> Result<Given, String> {
    let path = serde_json_path::JsonPath::parse(s).map_err(|e| format!("invalid JSONPath '{s}': {e}"))?;
    Ok(Given::JsonPath { path: Box::new(path), source: s.to_string() })
}

fn assertions(v: Option<&Value>) -> Result<Vec<Assertion>, String> {
    let list = match v {
        None | Some(Value::Null) => return Ok(vec![]),
        Some(Value::Array(a)) => a.clone(),
        Some(o @ Value::Object(_)) => vec![o.clone()],
        Some(_) => return Err("expected a mapping or a list of mappings".into()),
    };
    let mut out = vec![];
    for a in list {
        let Value::Object(m) = a else { return Err("each entry is a mapping with `function`".into()) };
        for k in m.keys() {
            if !matches!(k.as_str(), "field" | "function" | "options") {
                return Err(format!("unknown key '{k}' (expected field, function, options)"));
            }
        }
        let Some(name) = m.get("function").and_then(Value::as_str) else { return Err("`function` is required".into()) };
        let function = Function::compile(name, m.get("options").unwrap_or(&Value::Null))?;
        let field = match m.get("field") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) => Some(FieldPath::parse(s)?),
            Some(_) => return Err("`field` must be text".into()),
        };
        if field.is_some() && !function.uses_field() {
            return Err(format!("`{name}` reads `options.fields`, not `field`"));
        }
        out.push(Assertion { field, function });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load(text: &str) -> Result<RuleSet, RulesetError> {
        RuleSet::load(&[("team.yaml".into(), text.as_bytes().to_vec())])
    }

    #[test]
    fn recommended_loads() {
        let set = RuleSet::recommended();
        assert!(set.rules.len() > 15);
        assert_eq!(set.sources[0].name, "Anvil recommended");
    }

    #[test]
    fn extends_overrides_and_new_rules() {
        let set = load(
            "anvil_ruleset: 1\nname: Team\nextends: anvil:recommended\nrules:\n  info-contact: error\n  operation-description: off\n  team-x:\n    given: [operation, tag]\n    then: { field: description, function: truthy }\n",
        )
        .unwrap();
        assert_eq!(set.rules.iter().find(|r| r.id == "info-contact").unwrap().severity, Severity::Error);
        assert!(set.rules.iter().all(|r| r.id != "operation-description"));
        assert!(set.disabled.contains(&"operation-description".to_string()));
        let x = set.rules.iter().find(|r| r.id == "team-x").unwrap();
        assert_eq!(x.severity, Severity::Warn);
        assert_eq!(x.ruleset, "Team");
        assert_eq!(set.sources.len(), 2);
    }

    #[test]
    fn a_builtin_is_added_once() {
        let a = "anvil_ruleset: 1\nname: A\nextends: [anvil:recommended]\nrules:\n  info-contact: error\n";
        let b = "anvil_ruleset: 1\nname: B\nextends: [anvil:recommended]\n";
        let set = RuleSet::load(&[("a.yaml".into(), a.into()), ("b.yaml".into(), b.into())]).unwrap();
        assert_eq!(set.rules.iter().find(|r| r.id == "info-contact").unwrap().severity, Severity::Error);
        assert_eq!(set.sources.iter().filter(|s| s.builtin).count(), 1);
    }

    #[test]
    fn layering_rulesets() {
        let base = "anvil_ruleset: 1\nname: Base\nrules:\n  a:\n    given: operation\n    then: { field: summary, function: truthy }\n";
        let overlay = "anvil_ruleset: 1\nname: Overlay\nrules:\n  a: off\n";
        let set = RuleSet::load(&[("b.yaml".into(), base.into()), ("o.yaml".into(), overlay.into())]).unwrap();
        assert!(set.rules.is_empty());
        let bad = "anvil_ruleset: 1\nrules:\n  a: error\n";
        let e =
            RuleSet::load(&[("b.yaml".into(), base.into()), ("o.yaml".into(), overlay.into()), ("x.yaml".into(), bad.into())]).unwrap_err();
        assert!(e.message.contains("turned off earlier"), "{e}");
    }

    #[test]
    fn errors_name_the_problem() {
        let cases = [
            ("rules: {}\n", "anvil_ruleset"),
            ("anvil_ruleset: 2\n", "version 2"),
            ("anvil_ruleset: 1\nextends: ./base.yaml\n", "unknown ruleset './base.yaml'"),
            ("anvil_ruleset: 1\nrulez: {}\n", "unknown key 'rulez'"),
            ("anvil_ruleset: 1\nrules:\n  x: warn\n", "no inherited rule"),
            (
                "anvil_ruleset: 1\nrules:\n  x:\n    given: operatoin\n    then: {function: truthy, field: a}\n",
                "unknown target 'operatoin'",
            ),
            (
                "anvil_ruleset: 1\nrules:\n  x:\n    given: operation\n    then: {function: pattern, field: a, options: {match: '('}}\n",
                "invalid regular expression",
            ),
            ("anvil_ruleset: 1\nrules:\n  x:\n    given: operation\n    then: {function: truthy, feild: a}\n", "unknown key 'feild'"),
            (
                "anvil_ruleset: 1\nrules:\n  x:\n    given: operation\n    severity: fatal\n    then: {function: truthy, field: a}\n",
                "unknown severity",
            ),
            ("anvil_ruleset: 1\nrules:\n  x:\n    given: $..[?(\n    then: {function: truthy}\n", "invalid JSONPath"),
            (
                "anvil_ruleset: 1\nrules:\n  x:\n    given: operation\n    formats: [oas4]\n    then: {function: truthy, field: a}\n",
                "unknown format",
            ),
            ("anvil_ruleset: 1\nrules:\n  'bad id':\n    given: operation\n    then: {function: truthy, field: a}\n", "rule ids"),
        ];
        for (text, needle) in cases {
            let e = load(text).unwrap_err();
            assert!(e.to_string().contains(needle), "{text:?}: {e}");
        }
    }
}
