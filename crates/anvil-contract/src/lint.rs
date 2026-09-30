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
use std::collections::{HashMap, HashSet};

/// Examples validated per lint (each compiles a validator).
pub const MAX_EXAMPLE_CHECKS: usize = 1_000;
/// Schema members and items scanned by all the example checks of a lint
/// together (each compile scans, bundles and builds its schema).
pub const MAX_EXAMPLE_SCAN_STEPS: usize = 20 * schema::MAX_SCAN_STEPS;
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
    /// Body examples not checked: their schema uses an external reference
    /// or an unsupported pattern, refers to itself without descending into
    /// the value, or expands too far through its references.
    #[serde(default)]
    pub examples_not_checked: usize,
    /// Operations left out because the description is too large to lint
    /// completely (see `model::MAX_MODEL_WORK`).
    #[serde(default)]
    pub skipped_operations: usize,
}

impl LintReport {
    /// Whether no finding reaches `threshold` (`None`: always passes).
    /// Operations left out (`skipped_operations`) are not considered: the
    /// CLI refuses such a report unless told to accept it.
    pub fn passes(&self, threshold: Option<Severity>) -> bool {
        threshold.is_none_or(|t| self.counts.at_least(t) == 0)
    }
}

/// Lint `spec` with `rules`.
pub fn lint(spec: &Spec, rules: &RuleSet, opts: &LintOptions) -> LintReport {
    let mut checker = ExampleChecker {
        budget: if opts.validate_examples { MAX_EXAMPLE_CHECKS } else { 0 },
        not_checked: 0,
        compiled: HashMap::new(),
        compiles: 0,
        scan_steps: 0,
        scan_budget: MAX_EXAMPLE_SCAN_STEPS,
    };
    let mut examples = |m: &Media<'_>, dir: Direction| checker.check(spec, m, dir);
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
    let skipped_operations = model.skipped_operations;
    let examples_not_checked = checker.not_checked;
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
        examples_not_checked,
        skipped_operations,
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

/// Validates body examples against their schemas. Each validation and each
/// compile attempt spends one unit of [`MAX_EXAMPLE_CHECKS`]; a schema is
/// compiled once per direction however many media types share it.
struct ExampleChecker {
    budget: usize,
    not_checked: usize,
    compiled: HashMap<(String, bool), Option<jsonschema::Validator>>,
    /// Compiles attempted.
    compiles: usize,
    /// Members and items scanned by those compiles, and the limit.
    scan_steps: usize,
    scan_budget: usize,
}

impl ExampleChecker {
    fn check(&mut self, spec: &Spec, m: &Media<'_>, dir: Direction) -> Vec<String> {
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
                    let at = crate::locate::ptr(&crate::locate::ptr(&m.pointer, "examples"), name);
                    let Some((ex, _)) = spec.usable(ex, &at) else { continue };
                    if let Some(v) = ex.get("value").or_else(|| ex.get("dataValue")) {
                        examples.push((format!("examples/{name}"), v));
                    }
                }
            }
        }
        // A string example of a non-JSON media type is the serialized body.
        examples.retain(|(_, v)| json_media || !v.is_string());
        if examples.is_empty() {
            return vec![];
        }
        if self.budget == 0 {
            self.not_checked += examples.len();
            return vec![];
        }
        // Media types whose schema is only a `$ref` to the same target share
        // its validator. The key is the first hop, not the end of the chain:
        // in 3.1 and 3.2 an object with `$ref` and other keywords along the
        // way constrains the value too.
        let target = match schema.as_object() {
            Some(o) if o.len() == 1 => o.get("$ref").and_then(Value::as_str).and_then(crate::spec::internal_pointer),
            _ => None,
        };
        let key = (target.unwrap_or_else(|| m.schema_pointer.clone()), dir == Direction::Request);
        if !self.compiled.contains_key(&key) {
            self.budget -= 1;
            self.compiles += 1;
            let v = schema::compile_within(spec, schema, dir, &mut self.scan_steps, self.scan_budget).ok();
            self.compiled.insert(key.clone(), v);
        }
        let Some(validator) = self.compiled.get(&key).and_then(Option::as_ref) else {
            self.not_checked += examples.len();
            return vec![];
        };
        let mut out = vec![];
        for (name, v) in examples {
            if self.budget == 0 {
                self.not_checked += 1;
                continue;
            }
            self.budget -= 1;
            for e in validator.iter_errors(v).take(3) {
                let at = e.instance_path().to_string();
                out.push(if at.is_empty() { format!("{name}: {e}") } else { format!("{name}: {e} at {at}") });
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn checker(scan_budget: usize) -> ExampleChecker {
        ExampleChecker { budget: MAX_EXAMPLE_CHECKS, not_checked: 0, compiled: HashMap::new(), compiles: 0, scan_steps: 0, scan_budget }
    }

    #[test]
    fn a_ref_with_constraining_siblings_is_its_own_validator() {
        // 3.1: X1 = Y plus `maximum: 5`. A refers to X1, B to Y.
        let doc = json!({"openapi": "3.1.0", "info": {"title": "t", "version": "1"},
        "components": {"schemas": {"Y": {"type": "integer"}, "X1": {"$ref": "#/components/schemas/Y", "maximum": 5}}},
        "paths": {
            "/a": {"get": {"responses": {"200": {"description": "ok", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/X1"}, "example": 7}}}}}},
            "/b": {"get": {"responses": {"200": {"description": "ok", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Y"}, "example": 7}}}}}}
        }});
        let spec = Spec::parse(doc.to_string().as_bytes()).unwrap();
        let r = lint(&spec, &RuleSet::recommended(), &LintOptions::default());
        let bad: Vec<&str> = r.findings.iter().filter(|f| f.rule == "example-valid").map(|f| f.label.as_str()).collect();
        assert_eq!(bad, ["application/json in the 200 response of GET /a"], "{:#?}", r.findings);
    }

    #[test]
    fn compiles_share_one_scanning_budget() {
        // Each media type wraps the big schema, so none shares a validator.
        let mut paths = Map::new();
        for i in 0..100 {
            paths.insert(
                format!("/p{i}"),
                json!({"get": {"responses": {"200": {"description": "ok", "content": {"application/json": {
                    "schema": {"allOf": [{"$ref": "#/components/schemas/Big"}]}, "example": 3}}}}}}),
            );
        }
        let doc = json!({"openapi": "3.1.0", "info": {"title": "t", "version": "1"}, "paths": paths,
            "components": {"schemas": {"Big": {"type": "integer", "enum": (0..50_000).collect::<Vec<u32>>()}}}});
        let spec = Spec::parse(doc.to_string().as_bytes()).unwrap();
        let mut checker = checker(200_000);
        let mut examples = |m: &Media<'_>, dir: Direction| checker.check(&spec, m, dir);
        drop(Model::build(&spec, &mut examples));
        assert_eq!(checker.compiles, 100);
        assert!(checker.scan_steps <= 200_000 + 50_010, "{}", checker.scan_steps);
        assert!(checker.not_checked >= 95, "{}", checker.not_checked);
    }

    #[test]
    fn media_types_sharing_a_schema_compile_it_once() {
        let mut paths = Map::new();
        for i in 0..1_000 {
            paths.insert(
                format!("/p{i}"),
                json!({"get": {"responses": {"200": {"description": "ok", "content": {"application/json": {
                    "schema": {"$ref": "#/components/schemas/Big"}, "example": 3}}}}}}),
            );
        }
        let doc = json!({"openapi": "3.1.0", "info": {"title": "t", "version": "1"}, "paths": paths,
            "components": {"schemas": {"Big": {"type": "integer", "enum": (0..50_000).collect::<Vec<u32>>()}}}});
        let spec = Spec::parse(doc.to_string().as_bytes()).unwrap();
        let mut checker = checker(MAX_EXAMPLE_SCAN_STEPS);
        let mut examples = |m: &Media<'_>, dir: Direction| checker.check(&spec, m, dir);
        let model = Model::build(&spec, &mut examples);
        assert_eq!(model.of_kind(TargetKind::MediaType).count(), 1_000);
        drop(model);
        assert_eq!(checker.compiles, 1);
        // The one compile spent a unit of the budget: the last example is
        // counted as not checked.
        assert_eq!(checker.not_checked, 1);
    }
}
