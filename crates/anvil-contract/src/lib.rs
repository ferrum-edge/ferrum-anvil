//! OpenAPI contract tooling (see `docs/contract.md`).
//!
//! **API standards (linting).** A team writes what its API descriptions
//! must look like as a [`RuleSet`] (YAML or JSON, see [`ruleset`]), and
//! [`lint`] checks an OpenAPI 3.0/3.1/3.2 or Swagger 2.0 description
//! against it. Rules target version-neutral objects (operations,
//! parameters, responses, schemas, …; see [`model`]), so one standard
//! applies to every dialect. Each finding names the rule, the JSON Pointer
//! and the line and column to edit, and how to fix it; [`sarif::to_sarif`]
//! feeds CI code scanning.
//!
//! Guarantees:
//! * **No I/O.** Specs and rulesets are parsed from bytes the caller
//!   supplies, under the importer's bounds. External `$ref`s are never
//!   fetched; `extends` names built-in rulesets only.
//! * **Bounded.** Input size, node count, nesting, `$ref` chains and
//!   resolutions, rules, example validations and findings are capped.
//! * **Deterministic.** The same spec and rules give the same report.

pub mod checks;
pub mod lint;
pub mod locate;
pub mod model;
pub mod ruleset;
pub mod sarif;
pub mod schema;
pub mod spec;

pub use lint::{LintFinding, LintOptions, LintReport, SeverityCounts, SpecSummary, lint};
pub use locate::Position;
pub use model::TargetKind;
pub use ruleset::{RuleInfo, RuleSet, RulesetError, RulesetSummary, Severity};
pub use spec::{Spec, SpecError};

/// Text from a spec, a ruleset or traffic, made safe to print to a terminal
/// or a CI log: control characters (C0, C1, including newlines, which would
/// let a line start a CI workflow command) and bidirectional overrides are
/// escaped.
pub fn terminal_safe(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_control() || matches!(c, '\u{2028}' | '\u{2029}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}') {
            out.extend(c.escape_default());
        } else {
            out.push(c);
        }
    }
    out
}

/// JSON text made safe to print: C1 controls, line/paragraph separators and
/// bidirectional overrides (which serde_json leaves as they are) become
/// `\uXXXX` escapes. The JSON value is unchanged.
pub fn json_safe(json: &str) -> String {
    let mut out = String::with_capacity(json.len());
    for c in json.chars() {
        if matches!(c, '\u{80}'..='\u{9f}' | '\u{2028}' | '\u{2029}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}') {
            out.push_str(&format!("\\u{:04x}", c as u32));
        } else {
            out.push(c);
        }
    }
    out
}

/// JSON Schemas of the contracts the desktop renderer reads (written by
/// `anvil schema` next to `anvil_domain::schema::all()`).
pub fn contract_schemas() -> Vec<(&'static str, serde_json::Value)> {
    fn s<T: schemars::JsonSchema>() -> serde_json::Value {
        serde_json::to_value(schemars::schema_for!(T)).expect("schema serializes")
    }
    vec![("LintReport", s::<LintReport>()), ("RuleInfo", s::<RuleInfo>()), ("RulesetSummary", s::<RulesetSummary>())]
}

#[cfg(test)]
mod tests {
    #[test]
    fn output_escaping() {
        assert_eq!(super::terminal_safe("a\n::error::x\u{1b}[31m\u{202e}"), "a\\n::error::x\\u{1b}[31m\\u{202e}");
        let json = serde_json::to_string(&serde_json::json!({"m": "a\u{85}b\u{202e}c"})).unwrap();
        let safe = super::json_safe(&json);
        assert_eq!(safe, r#"{"m":"a\u0085b\u202ec"}"#);
        assert_eq!(serde_json::from_str::<serde_json::Value>(&safe).unwrap()["m"], "a\u{85}b\u{202e}c");
    }
}
