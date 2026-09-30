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

/// JSON Schemas of the contracts the desktop renderer reads (written by
/// `anvil schema` next to `anvil_domain::schema::all()`).
pub fn contract_schemas() -> Vec<(&'static str, serde_json::Value)> {
    fn s<T: schemars::JsonSchema>() -> serde_json::Value {
        serde_json::to_value(schemars::schema_for!(T)).expect("schema serializes")
    }
    vec![("LintReport", s::<LintReport>()), ("RuleInfo", s::<RuleInfo>()), ("RulesetSummary", s::<RulesetSummary>())]
}
