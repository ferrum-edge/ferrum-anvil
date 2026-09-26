# ADR 0003: Deterministic, catalog-worded diagnostics

## Context
The defining feature is evidence-based diagnosis with explicit uncertainty.
No cloud service or LLM may be required, and remote text must never steer
the app.

## Decision
- Pure Rust rules (`anvil-diagnostics/src/rules/*`) map typed facts to
  findings. Each finding carries a confidence (`confirmed | likely | unknown |
  conflicting_evidence`), a scope (leg or owner), an owner, evidence items,
  alternatives, "does not prove" statements, remediation and confirm-with
  steps.
- The wording lives in `catalog/diagnostics/findings.en.json`, keyed by
  finding code and versioned. Rules never build prose from response content.
- Ferrum markers (`X-Gateway-Error`, upstream status) count as gateway
  evidence only when the destination matches an explicit integration
  profile. They are capped at `likely` because v0.9.5 markers are
  backend-spoofable, and plain-HTTP trust is capped as well. The seven coarse
  tokens are never refined into precise causes, and shared signals yield
  ambiguity rather than a guess.
- Findings are ordered by severity, then specificity (hop- or phase-specific
  before the generic status explanation), then confidence. Order is only
  presentation; each finding keeps its own confidence.

## Consequences
- Answers are reproducible and testable against lab ground truth, which is
  never fed into the engine.
- "Unknown" is a first-class answer. `Confirmed` gateway attribution becomes
  possible only with a gateway-owned diagnostic contract (G01).
