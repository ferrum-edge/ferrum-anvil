//! Running a [`RuleSet`] over a [`Spec`].

use crate::checks::show;
use crate::locate::ptr;
use crate::model::{Direction, Media, Model, Target, TargetKind};
use crate::ruleset::{Assertion, FieldToken, Given, Rule, RuleSet, RulesetSummary, Severity};
use crate::schema;
use crate::spec::Spec;
use anvil_import::Dialect;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::HashSet;

/// Examples validated per lint (each compiles a validator).
pub const MAX_EXAMPLE_CHECKS: usize = 1_000;
/// Findings collected before sorting; later ones are only counted.
const MAX_COLLECTED: usize = 100_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct LintOptions {
    /// Findings kept; the rest are counted but dropped.
    pub max_findings: usize,
    /// Check `example`/`examples` of bodies against their schemas (the
    /// `example_errors` field). Off, that field is always empty.
    pub validate_examples: bool,
}

impl Default for LintOptions {
    fn default() -> Self {
        LintOptions { max_findings: 5_000, validate_examples: true }
    }
}

/// Where a finding is, in the document and in its source text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct LintFinding {
    pub rule: String,
    pub severity: Severity,
    pub message: String,
    /// RFC 6901 JSON Pointer of the object to change.
    pub pointer: String,
    /// 1-based line and column in the source, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub column: Option<u32>,
    pub target: TargetKind,
    /// What the finding is about: `GET /pets`, `schema Pet`, …
    pub label: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub how_to_fix: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub docs_url: Option<String>,
    /// Name of the ruleset that defined the rule.
    pub ruleset: String,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SeverityCounts {
    pub error: usize,
    pub warn: usize,
    pub info: usize,
    pub hint: usize,
}

impl SeverityCounts {
    fn add(&mut self, s: Severity) {
        match s {
            Severity::Error => self.error += 1,
            Severity::Warn => self.warn += 1,
            Severity::Info => self.info += 1,
            Severity::Hint => self.hint += 1,
        }
    }

    /// Findings at `threshold` or above.
    pub fn at_least(&self, threshold: Severity) -> usize {
        [(Severity::Error, self.error), (Severity::Warn, self.warn), (Severity::Info, self.info), (Severity::Hint, self.hint)]
            .iter()
            .filter(|(s, _)| *s >= threshold)
            .map(|(_, n)| n)
            .sum()
    }
}

/// The linted document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SpecSummary {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub dialect: Dialect,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declared_version: Option<String>,
    pub sha256: String,
    pub size_bytes: u64,
    pub operations: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct LintReport {
    pub spec: SpecSummary,
    pub rulesets: Vec<RulesetSummary>,
    /// Rules that applied to this dialect and ran.
    pub rules_run: usize,
    /// Rules skipped because of their `formats`.
    pub rules_skipped: usize,
    /// Counts of every finding, including any dropped past the limit.
    pub counts: SeverityCounts,
    /// Most severe first, then in document order.
    pub findings: Vec<LintFinding>,
    /// Findings dropped past [`LintOptions::max_findings`].
    pub dropped: usize,
    /// Locations of `$ref`s that could not be followed (external, dangling,
    /// cyclic or too deep; at most 1,000). The objects behind them were not
    /// checked.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unresolved_refs: Vec<String>,
    #[serde(default)]
    pub unresolved_ref_count: usize,
}

impl LintReport {
    /// Whether no finding reaches `threshold` (`None`: always passes).
    pub fn passes(&self, threshold: Option<Severity>) -> bool {
        threshold.is_none_or(|t| self.counts.at_least(t) == 0)
    }
}

/// Lint `spec` with `rules`.
pub fn lint(spec: &Spec, rules: &RuleSet, opts: &LintOptions) -> LintReport {
    let mut example_budget = if opts.validate_examples { MAX_EXAMPLE_CHECKS } else { 0 };
    let mut examples = |m: &Media<'_>, dir: Direction| example_errors(spec, m, dir, &mut example_budget);
    let model = Model::build(spec, &mut examples);
    let mut out = Collector { spec, findings: vec![], counts: SeverityCounts::default(), seen: HashSet::new(), dropped: 0 };
    let (mut run, mut skipped) = (0, 0);
    for rule in &rules.rules {
        if !rule.applies_to(spec.dialect) {
            skipped += 1;
            continue;
        }
        run += 1;
        match &rule.given {
            Given::Targets(kinds) => {
                for kind in kinds {
                    for t in model.of_kind(*kind) {
                        apply(spec, rule, t, &mut out);
                    }
                }
            }
            Given::JsonPath { path, .. } => {
                for node in path.query_located(&spec.root).all() {
                    let pointer = node.location().to_json_pointer();
                    let view = match node.node() {
                        Value::Object(o) => o.clone(),
                        other => {
                            let mut m = Map::new();
                            m.insert("value".into(), other.clone());
                            m
                        }
                    };
                    let t = Target { kind: TargetKind::Node, label: pointer_label(&pointer), pointer, view };
                    apply(spec, rule, &t, &mut out);
                }
            }
        }
    }
    let mut findings = out.findings;
    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then(a.line.unwrap_or(u32::MAX).cmp(&b.line.unwrap_or(u32::MAX)))
            .then(a.column.cmp(&b.column))
            .then(a.rule.cmp(&b.rule))
            .then(a.message.cmp(&b.message))
    });
    let (unresolved_refs, unresolved_ref_count) = spec.unresolved();
    let mut dropped = out.dropped;
    if findings.len() > opts.max_findings {
        dropped += findings.len() - opts.max_findings;
        findings.truncate(opts.max_findings);
    }
    LintReport {
        spec: SpecSummary {
            title: spec.title().map(str::to_string),
            version: spec.version(),
            dialect: spec.dialect,
            declared_version: spec.declared_version.clone(),
            sha256: spec.sha256.clone(),
            size_bytes: spec.size_bytes,
            operations: model.of_kind(TargetKind::Operation).count(),
        },
        rulesets: rules.sources.clone(),
        rules_run: run,
        rules_skipped: skipped,
        counts: out.counts,
        findings,
        dropped,
        unresolved_refs,
        unresolved_ref_count,
    }
}

fn pointer_label(pointer: &str) -> String {
    if pointer.is_empty() { "document".into() } else { pointer.to_string() }
}

struct Collector<'a> {
    spec: &'a Spec,
    findings: Vec<LintFinding>,
    counts: SeverityCounts,
    seen: HashSet<(String, String, String)>,
    dropped: usize,
}

/// A selected field value and the pointer it came from, when known.
struct Selected {
    value: Option<Value>,
    pointer: Option<String>,
}

fn apply(spec: &Spec, rule: &Rule, t: &Target, out: &mut Collector<'_>) {
    let sibling = |name: &str| -> Option<Value> { t.view.get(name).cloned() };
    for c in &rule.conditions {
        let selected = select(spec, t, c);
        if selected.iter().any(|s| c.function.evaluate(s.value.as_ref(), &sibling).is_some()) {
            return;
        }
    }
    for a in &rule.then {
        for s in select(spec, t, a) {
            let Some(reason) = a.function.evaluate(s.value.as_ref(), &sibling) else { continue };
            let pointer = s.pointer.unwrap_or_else(|| t.pointer.clone());
            // A Swagger 2.0 synthetic target keys itself `…#suffix`.
            let pointer = pointer.split('#').next().unwrap_or("").to_string();
            let field = a.field.as_ref().map(|f| f.source.clone()).unwrap_or_default();
            let message = match &rule.message {
                Some(m) => render(m, rule, t, &field, s.value.as_ref(), &reason),
                None if field.is_empty() => format!("{}: {reason}", t.label),
                None => format!("{}: {field} {reason}", t.label),
            };
            out.push(rule, t, pointer, message);
        }
    }
}

impl Collector<'_> {
    fn push(&mut self, rule: &Rule, t: &Target, pointer: String, message: String) {
        // One finding per rule and place: a shared (`$ref`) object is
        // reported once, where it is defined.
        if !self.seen.insert((rule.id.clone(), pointer.clone(), message.clone())) {
            return;
        }
        self.counts.add(rule.severity);
        if self.findings.len() >= MAX_COLLECTED {
            self.dropped += 1;
            return;
        }
        let pos = self.spec.position(&pointer);
        self.findings.push(LintFinding {
            rule: rule.id.clone(),
            severity: rule.severity,
            message,
            pointer,
            line: pos.map(|p| p.line),
            column: pos.map(|p| p.column),
            target: t.kind,
            label: t.label.clone(),
            how_to_fix: rule.how_to_fix.clone(),
            docs_url: rule.docs_url.clone(),
            ruleset: rule.ruleset.clone(),
        });
    }
}

/// The values a field path selects on a target.
fn select(spec: &Spec, t: &Target, a: &Assertion) -> Vec<Selected> {
    let Some(field) = &a.field else {
        // No field: the function looks at the whole target.
        return vec![Selected { value: Some(Value::Object(t.view.clone())), pointer: None }];
    };
    let (start, base): (Option<Value>, Option<String>) = if field.raw || t.kind == TargetKind::Node {
        let at = t.pointer.split('#').next().unwrap_or("");
        let raw = spec.root.pointer(at).map(|v| spec.deref(v, at).0.clone());
        let raw = if t.kind == TargetKind::Node && !field.raw { Some(Value::Object(t.view.clone())) } else { raw };
        (raw, Some(at.to_string()))
    } else {
        (Some(Value::Object(t.view.clone())), None)
    };
    let mut cur = vec![Selected { value: start, pointer: base }];
    for tok in &field.tokens {
        let mut next = vec![];
        for s in cur {
            match tok {
                FieldToken::Key(k) => {
                    let value = s.value.as_ref().and_then(|v| v.get(k)).cloned();
                    next.push(Selected { value, pointer: s.pointer.map(|p| ptr(&p, k)) });
                }
                FieldToken::Each => match s.value {
                    Some(Value::Array(items)) => {
                        for (i, v) in items.into_iter().enumerate() {
                            next.push(Selected { value: Some(v), pointer: s.pointer.as_ref().map(|p| ptr(p, &i.to_string())) });
                        }
                    }
                    Some(Value::Object(m)) => {
                        for (k, v) in m {
                            next.push(Selected { value: Some(v), pointer: s.pointer.as_ref().map(|p| ptr(p, &k)) });
                        }
                    }
                    // Nothing to iterate: nothing to check.
                    _ => {}
                },
            }
        }
        cur = next;
    }
    // A pointer into the raw document is only useful where the value exists.
    for s in &mut cur {
        if let Some(p) = &s.pointer
            && spec.root.pointer(p).is_none()
        {
            s.pointer = None;
        }
    }
    cur
}

/// Fill `{{placeholders}}`: `value`, `field`, `reason`, `label`, `rule`,
/// `pointer`, and any scalar or list field of the target.
fn render(template: &str, rule: &Rule, t: &Target, field: &str, value: Option<&Value>, reason: &str) -> String {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(open) = rest.find("{{") {
        out.push_str(&rest[..open]);
        let after = &rest[open + 2..];
        let Some(close) = after.find("}}") else {
            out.push_str(&rest[open..]);
            return out;
        };
        let name = after[..close].trim();
        let text = match name {
            "value" => value.filter(|v| !v.is_null()).map(show_plain).unwrap_or_default(),
            "field" => field.to_string(),
            "reason" => reason.to_string(),
            "label" => t.label.clone(),
            "rule" => rule.id.clone(),
            "pointer" => t.pointer.clone(),
            other => t.view.get(other).filter(|v| !v.is_null()).map(show_plain).unwrap_or_default(),
        };
        out.push_str(&text);
        rest = &after[close + 2..];
    }
    out.push_str(rest);
    out
}

/// A value as message text: strings unquoted, lists of strings joined.
fn show_plain(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Array(a) if !a.is_empty() && a.iter().all(Value::is_string) => {
            let items: Vec<&str> = a.iter().filter_map(Value::as_str).collect();
            items.join(if items.iter().any(|i| i.contains(' ')) { "; " } else { ", " })
        }
        other => show(other),
    }
}

/// Validate a media type's examples against its schema.
fn example_errors(spec: &Spec, m: &Media<'_>, dir: Direction, budget: &mut usize) -> Vec<String> {
    let (Some(schema), Some(obj)) = (m.schema, m.object) else { return vec![] };
    let json_media = {
        let e = m.media_type.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
        e == "application/json" || e.ends_with("+json") || e == "*/*"
    };
    let mut examples: Vec<(String, &Value)> = vec![];
    if spec.is_swagger2() {
        if let Some(v) = obj.get("examples").and_then(|e| e.get(&m.media_type)) {
            examples.push((format!("examples/{}", m.media_type), v));
        }
    } else {
        if let Some(v) = obj.get("example") {
            examples.push(("example".into(), v));
        }
        if let Some(map) = obj.get("examples").and_then(Value::as_object) {
            for (name, ex) in map {
                let (ex, _) = spec.deref(ex, "");
                if let Some(v) = ex.get("value").or_else(|| ex.get("dataValue")) {
                    examples.push((format!("examples/{name}"), v));
                }
            }
        }
    }
    // A string example of a non-JSON media type is the serialized body.
    examples.retain(|(_, v)| json_media || !v.is_string());
    if examples.is_empty() || *budget == 0 {
        return vec![];
    }
    let Ok(validator) = schema::compile(spec, schema, dir) else { return vec![] };
    let mut out = vec![];
    for (name, v) in examples {
        if *budget == 0 {
            break;
        }
        *budget -= 1;
        for e in validator.iter_errors(v).take(3) {
            let at = e.instance_path().to_string();
            out.push(if at.is_empty() { format!("{name}: {e}") } else { format!("{name}: {e} at {at}") });
        }
    }
    out
}
