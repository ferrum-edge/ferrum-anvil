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
pub mod drift;
pub mod infer;
pub mod lint;
pub mod locate;
pub mod model;
pub mod observe;
pub mod patch;
pub mod route;
pub mod ruleset;
pub mod sarif;
pub mod schema;
pub mod spec;

pub use drift::{DriftFinding, DriftKind, DriftOptions, DriftReport, Revision, Suggestion, SuggestionKind, analyze, revise};
pub use lint::{LintFinding, LintOptions, LintReport, SeverityCounts, SpecSummary, lint};
pub use locate::Position;
pub use model::TargetKind;
pub use observe::{Observation, ObservedBody, ObservedResponse};
pub use ruleset::{RuleInfo, RuleSet, RulesetError, RulesetSummary, Severity};
pub use spec::{Spec, SpecError};

/// Text from a spec, a ruleset or traffic, made safe to print to a terminal
/// or a CI log:
/// * control characters (C0, C1, including newlines, which would let a line
///   start a CI workflow command) and bidirectional overrides are escaped
///   (`\n`, `\u{1b}`, `\u{202e}`);
/// * the GitHub Actions workflow-command introducers get a visible
///   backslash: `::` prints as `:\:` and `##[` as `#\#[`. A runner reads
///   `::command::` at the start of a line, which a value printed first on
///   a line would be, and the legacy `##[command]` anywhere in a line.
///
/// Text with none of these prints unchanged, and escaping escaped text
/// changes nothing.
pub fn terminal_safe(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_control() || matches!(c, '\u{2028}' | '\u{2029}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}') {
            out.extend(c.escape_default());
        } else if c == ':' && out.ends_with(':') {
            out.push_str("\\:");
        } else if c == '[' && out.ends_with("##") {
            out.pop();
            out.push_str("\\#[");
        } else {
            out.push(c);
        }
    }
    out
}

/// JSON text made safe to print: C1 controls, line/paragraph separators and
/// bidirectional overrides (which serde_json leaves as they are) become
/// `\uXXXX` escapes, and so does the `[` of a legacy GitHub Actions
/// workflow command (`##[`), which a runner reads anywhere in a line. JSON
/// syntax has no `#` outside strings, so that `[` is always in a string.
/// The JSON value is unchanged.
pub fn json_safe(json: &str) -> String {
    let mut out = String::with_capacity(json.len());
    for c in json.chars() {
        if matches!(c, '\u{80}'..='\u{9f}' | '\u{2028}' | '\u{2029}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
            || (c == '[' && out.ends_with("##"))
        {
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
    vec![
        ("LintReport", s::<LintReport>()),
        ("RuleInfo", s::<RuleInfo>()),
        ("RulesetSummary", s::<RulesetSummary>()),
        ("DriftReport", s::<DriftReport>()),
        ("Revision", s::<Revision>()),
    ]
}

#[cfg(test)]
mod tests {
    #[test]
    fn output_escaping() {
        assert_eq!(super::terminal_safe("a\n::error::x\u{1b}[31m\u{202e}"), r"a\n:\:error:\:x\u{1b}[31m\u{202e}");
        let json = serde_json::to_string(&serde_json::json!({"m": "a\u{85}b\u{202e}c"})).unwrap();
        let safe = super::json_safe(&json);
        assert_eq!(safe, r#"{"m":"a\u0085b\u202ec"}"#);
        assert_eq!(serde_json::from_str::<serde_json::Value>(&safe).unwrap()["m"], "a\u{85}b\u{202e}c");
    }

    #[test]
    fn workflow_command_introducers_are_broken_visibly() {
        use super::terminal_safe as t;
        assert_eq!(t("::error title=x::forged"), r":\:error title=x:\:forged");
        assert_eq!(t("failed (actual: ##[error]forged)"), r"failed (actual: #\#[error]forged)");
        assert_eq!(t(":::"), r":\:\:");
        assert_eq!(t("###[x"), r"##\#[x");
        assert_eq!(t("http://[::1]:8080/"), r"http://[:\:1]:8080/");
        // Text with neither sequence (nor a control character) is unchanged.
        for plain in ["", "GET https://api.example/v1?q=a:b#frag", "## Heading", "a: b", "#[derive]", "[x]#", "✓ status — 200 · ok"] {
            assert_eq!(t(plain), plain);
        }
        // Escaping escaped text changes nothing.
        for s in ["a\n::error::x\u{1b}[2K", "##[warning]w", ":::", "###[", "#\\#[", r":\:", "\u{202e}::##[\r"] {
            assert_eq!(t(&t(s)), t(s), "{s:?}");
            let out = t(s);
            assert!(!out.contains("::") && !out.contains("##[") && !out.chars().any(char::is_control), "{out:?}");
        }
    }

    #[test]
    fn json_safe_breaks_a_legacy_workflow_command_and_keeps_the_value() {
        let v = serde_json::json!({"v": "x ##[error]forged ##[", "a": [["##"], "#"], "k::": "::e::"});
        for json in [serde_json::to_string(&v).unwrap(), serde_json::to_string_pretty(&v).unwrap()] {
            let safe = super::json_safe(&json);
            assert!(!safe.contains("##["), "{safe}");
            assert!(safe.contains(r"x ##\u005berror]forged ##\u005b"), "{safe}");
            assert_eq!(serde_json::from_str::<serde_json::Value>(&safe).unwrap(), v);
            assert_eq!(super::json_safe(&safe), safe);
        }
        // JSON without these characters is unchanged.
        let plain = serde_json::to_string_pretty(&serde_json::json!({"a": [1, "b:c", {"d": "#"}]})).unwrap();
        assert_eq!(super::json_safe(&plain), plain);
    }
}
