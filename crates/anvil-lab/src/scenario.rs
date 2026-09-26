//! Scenario execution records (plan §15.2) and check helpers.
//!
//! Checks assert Anvil's *diagnostic invariants* — required findings,
//! confidence ceilings, scopes and forbidden claims — and separately verify
//! with independent ground truth (fixture logs, gateway operator log) that
//! the intended condition was actually reached. Ground truth is never passed
//! to the engine.

use anvil_domain::diagnostics::{Confidence, DiagnosticFinding, SourceScope};
use anvil_engine::ExecutionOutput;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct Check {
    pub name: String,
    pub kind: CheckKind,
    pub passed: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CheckKind {
    /// Assertion about Anvil's conclusions (public evidence only).
    Diagnosis,
    /// Independent verification that the fault condition was reached.
    GroundTruth,
    /// Positive-control / recovery request after removing or bypassing the fault.
    Recovery,
}

#[derive(Debug, Clone, Serialize)]
pub struct ObservedSummary {
    pub status: Option<u16>,
    pub x_gateway_error: Vec<String>,
    pub body_preview: String,
    pub transport: String,
    pub application: String,
    pub dispatch: String,
    pub attempts: usize,
    pub failure: Option<String>,
    pub findings: Vec<FindingSummary>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FindingSummary {
    pub code: String,
    pub confidence: Confidence,
    pub scope: SourceScope,
    pub title: String,
}

pub fn summarize(o: &ExecutionOutput) -> ObservedSummary {
    let r = o.record.response.as_ref();
    let body = o.decoded_body.as_ref().unwrap_or(&o.body);
    ObservedSummary {
        status: r.map(|x| x.status),
        x_gateway_error: r.map(|x| x.header_values("x-gateway-error").iter().map(|s| s.to_string()).collect()).unwrap_or_default(),
        body_preview: String::from_utf8_lossy(&body[..body.len().min(300)]).into_owned(),
        transport: format!("{:?}", o.record.outcome.transport),
        application: format!("{:?}", o.record.outcome.application),
        dispatch: format!("{:?}", o.record.outcome.dispatch),
        attempts: o.record.attempts.len(),
        failure: o.record.attempts.last().and_then(|a| a.failure.as_ref()).map(|f| format!("{:?} @ {:?}", f.kind, f.phase)),
        findings: o
            .record
            .findings
            .iter()
            .map(|f| FindingSummary { code: f.code.clone(), confidence: f.confidence, scope: f.scope, title: f.title.clone() })
            .collect(),
        warnings: o.record.outcome.warnings.iter().map(|w| format!("{:?}", w.code)).collect(),
    }
}

pub struct Checks {
    pub items: Vec<Check>,
}

impl Checks {
    pub fn new() -> Self {
        Checks { items: vec![] }
    }

    pub fn add(&mut self, kind: CheckKind, name: impl Into<String>, passed: bool, detail: impl Into<String>) {
        self.items.push(Check { name: name.into(), kind, passed, detail: detail.into() });
    }

    fn find<'a>(o: &'a ExecutionOutput, code: &str) -> Option<&'a DiagnosticFinding> {
        o.record.findings.iter().find(|f| f.code == code)
    }

    pub fn has(&mut self, o: &ExecutionOutput, code: &str) {
        let f = Self::find(o, code);
        self.add(
            CheckKind::Diagnosis,
            format!("finding {code} present"),
            f.is_some(),
            format!("findings: {:?}", o.record.findings.iter().map(|f| &f.code).collect::<Vec<_>>()),
        );
    }

    pub fn has_any(&mut self, o: &ExecutionOutput, codes: &[&str]) {
        let found: Vec<&str> = codes.iter().copied().filter(|c| Self::find(o, c).is_some()).collect();
        self.add(
            CheckKind::Diagnosis,
            format!("one of {codes:?} present"),
            !found.is_empty(),
            format!("found {found:?}; all findings: {:?}", o.record.findings.iter().map(|f| &f.code).collect::<Vec<_>>()),
        );
    }

    pub fn absent_prefix(&mut self, o: &ExecutionOutput, prefix: &str) {
        let hits: Vec<&String> = o.record.findings.iter().map(|f| &f.code).filter(|c| c.starts_with(prefix)).collect();
        self.add(CheckKind::Diagnosis, format!("no finding starting with {prefix}"), hits.is_empty(), format!("{hits:?}"));
    }

    pub fn max_confidence(&mut self, o: &ExecutionOutput, code: &str, max: Confidence) {
        if let Some(f) = Self::find(o, code) {
            self.add(CheckKind::Diagnosis, format!("{code} confidence ≤ {max:?}"), f.confidence <= max, format!("{:?}", f.confidence));
        }
    }

    pub fn scope(&mut self, o: &ExecutionOutput, code: &str, scope: SourceScope) {
        if let Some(f) = Self::find(o, code) {
            self.add(CheckKind::Diagnosis, format!("{code} scope {scope:?}"), f.scope == scope, format!("{:?}", f.scope));
        }
    }

    /// No finding may be *confirmed* while mentioning a forbidden term in its title/explanation.
    pub fn no_confirmed_claim(&mut self, o: &ExecutionOutput, term: &str) {
        let bad: Vec<String> = o
            .record
            .findings
            .iter()
            .filter(|f| f.confidence == Confidence::Confirmed && (f.title.to_lowercase().contains(term) || f.code.contains(term)))
            .map(|f| f.code.clone())
            .collect();
        self.add(CheckKind::Diagnosis, format!("no confirmed '{term}' claim"), bad.is_empty(), format!("{bad:?}"));
    }

    pub fn not_success(&mut self, o: &ExecutionOutput) {
        let ok = !(matches!(o.record.outcome.transport, anvil_domain::outcome::TransportState::Completed)
            && matches!(o.record.outcome.application, anvil_domain::outcome::ApplicationState::Success));
        self.add(CheckKind::Diagnosis, "not reported as a complete success", ok, o.record.outcome.summary.clone());
    }

    pub fn success(&mut self, kind: CheckKind, o: &ExecutionOutput) {
        let ok = matches!(o.record.outcome.transport, anvil_domain::outcome::TransportState::Completed)
            && matches!(o.record.outcome.application, anvil_domain::outcome::ApplicationState::Success);
        self.add(kind, "complete successful exchange", ok, o.record.outcome.summary.clone());
    }

    pub fn status_in(&mut self, o: &ExecutionOutput, allowed: &[u16]) {
        let s = o.record.response.as_ref().map(|r| r.status);
        self.add(
            CheckKind::GroundTruth,
            format!("gateway status in {allowed:?}"),
            s.map(|s| allowed.contains(&s)).unwrap_or(false),
            format!("{s:?}"),
        );
    }

    /// Trust-aware marker expectation: with a trusted profile the token
    /// finding must exist; without one only an "unverified marker" may appear.
    pub fn token(&mut self, o: &ExecutionOutput, code: &str, trusted: bool) {
        if trusted {
            self.has(o, code);
        } else {
            let has_marker = o.record.response.as_ref().map(|r| !r.header_values("x-gateway-error").is_empty()).unwrap_or(false);
            if has_marker {
                self.has(o, "ferrum.marker.unverified");
            }
            self.absent_prefix(o, "ferrum.token");
        }
    }

    pub fn token_any(&mut self, o: &ExecutionOutput, codes: &[&str], trusted: bool) {
        if trusted {
            self.has_any(o, codes);
        } else {
            self.absent_prefix(o, "ferrum.token");
        }
    }

    /// Operator-side ground truth: the gateway's own transaction log
    /// `error_class` for the proxy (never shown to the diagnostic engine).
    pub fn operator_class(&mut self, lines: &[String], proxy_id: &str, allowed: &[&str]) {
        let classes: Vec<String> = lines
            .iter()
            .filter(|l| l.contains(&format!("\"proxy_id\":\"{proxy_id}\"")))
            .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            .filter_map(|v| v.get("error_class").and_then(|c| c.as_str()).map(|s| s.to_string()))
            .collect();
        let ok = classes.iter().any(|c| allowed.contains(&c.as_str()));
        self.add(CheckKind::GroundTruth, format!("gateway operator log error_class in {allowed:?}"), ok, format!("{classes:?}"));
    }

    pub fn all_passed(&self) -> bool {
        self.items.iter().all(|c| c.passed)
    }
}

impl Default for Checks {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ScenarioResult {
    pub id: String,
    pub title: String,
    pub profile: String,
    pub evidence_mode: String,
    pub trusted_destination: bool,
    pub gateway_release: String,
    pub gateway_source_sha: String,
    pub gateway_binary_sha256: String,
    pub platform: String,
    pub observed: Option<ObservedSummary>,
    pub recovery: Option<ObservedSummary>,
    pub operator_log_evidence: Vec<String>,
    pub checks: Vec<Check>,
    pub status: String,
    pub skip_reason: Option<String>,
    pub duration_ms: u128,
}
