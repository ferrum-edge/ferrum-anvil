//! Anvil's evidence-based diagnostic engine.
//!
//! * Rules are deterministic Rust predicates over typed evidence (never over
//!   message text) and are separate from the user-facing wording, which lives
//!   in the versioned catalog `catalog/diagnostics/findings.en.json`.
//! * Ferrum-specific knowledge comes from the source-linked compatibility
//!   catalog `catalog/ferrum/<compat-id>/outcomes.json`.
//! * Confidence is per claim: `confirmed`, `likely`, `unknown`,
//!   `conflicting_evidence`. "Unknown" is a correct answer when the evidence
//!   cannot distinguish causes; rules never guess a precise cause.
//! * Response bodies are untrusted data: they are parsed for structure only
//!   and never interpreted as instructions.

pub mod facts;
pub mod ferrum;
pub mod render;
pub mod rules;

use anvil_domain::diagnostics::{Confidence, DiagnosticFinding, Evidence, EvidenceSource, Owner, Remediation, Severity, SourceScope};
use anvil_domain::outcome::{ApplicationState, OutcomeWarning, ProtocolStatus, WarningCode};
use anvil_domain::request::Protocol;
pub use facts::{BodyFacts, DiagnosticInput, FerrumTrust};

/// Catalog version string recorded in every execution record.
pub fn catalog_version() -> String {
    format!("findings:{} ferrum:{}", render::catalog().version, ferrum::catalog().compatibility_id)
}

/// A rule's claim before wording is applied.
#[derive(Debug, Clone)]
pub struct Draft {
    pub code: String,
    pub rule_id: &'static str,
    pub rule_version: u32,
    pub confidence: Confidence,
    pub scope: SourceScope,
    pub owner: Owner,
    pub severity: Severity,
    pub evidence: Vec<Evidence>,
    pub vars: Vec<(&'static str, String)>,
    pub extra_alternatives: Vec<String>,
    pub extra_does_not_prove: Vec<String>,
    pub extra_remediation: Vec<Remediation>,
    pub extra_confirm_with: Vec<String>,
    /// Title/explanation supplied by the Ferrum catalog (source-audited text).
    pub catalog_text: Option<(String, String)>,
}

impl Draft {
    pub fn new(
        code: impl Into<String>,
        rule_id: &'static str,
        confidence: Confidence,
        scope: SourceScope,
        owner: Owner,
        severity: Severity,
    ) -> Self {
        Draft {
            code: code.into(),
            rule_id,
            rule_version: 1,
            confidence,
            scope,
            owner,
            severity,
            evidence: vec![],
            vars: vec![],
            extra_alternatives: vec![],
            extra_does_not_prove: vec![],
            extra_remediation: vec![],
            extra_confirm_with: vec![],
            catalog_text: None,
        }
    }

    pub fn ev(mut self, source: EvidenceSource, key: &str, value: impl Into<String>) -> Self {
        self.evidence.push(Evidence { source, key: key.into(), value: value.into(), attempt: None });
        self
    }

    pub fn ev_at(mut self, source: EvidenceSource, key: &str, value: impl Into<String>, attempt: u32) -> Self {
        self.evidence.push(Evidence { source, key: key.into(), value: value.into(), attempt: Some(attempt) });
        self
    }

    pub fn var(mut self, k: &'static str, v: impl Into<String>) -> Self {
        self.vars.push((k, v.into()));
        self
    }

    pub fn alt(mut self, s: impl Into<String>) -> Self {
        self.extra_alternatives.push(s.into());
        self
    }

    pub fn not_proven(mut self, s: impl Into<String>) -> Self {
        self.extra_does_not_prove.push(s.into());
        self
    }
}

/// Result of diagnosing one execution.
#[derive(Debug, Clone, Default)]
pub struct Diagnosis {
    pub findings: Vec<DiagnosticFinding>,
    pub warnings: Vec<OutcomeWarning>,
    pub body: BodyFacts,
}

/// Run every rule over the input and render findings.
pub fn diagnose(input: &DiagnosticInput<'_>) -> Diagnosis {
    let body = input.response.map(|r| facts::body_facts(r.body.content_type.as_deref(), input.body)).unwrap_or_default();
    let mut drafts: Vec<Draft> = Vec::new();
    let mut warnings: Vec<OutcomeWarning> = Vec::new();
    let ctx = rules::Ctx { input, body: &body };
    rules::run_all(&ctx, &mut drafts, &mut warnings);
    // Cap confidence when the only provenance is an unauthenticated channel.
    let findings = drafts.into_iter().map(render::render).collect::<Vec<_>>();
    let mut findings = dedupe(findings);
    findings.sort_by(|a, b| b.severity.cmp(&a.severity).then(b.confidence.cmp(&a.confidence)));
    warnings.dedup_by(|a, b| a.code == b.code);
    Diagnosis { findings, warnings, body }
}

fn dedupe(v: Vec<DiagnosticFinding>) -> Vec<DiagnosticFinding> {
    let mut out: Vec<DiagnosticFinding> = Vec::new();
    for f in v {
        if !out.iter().any(|o| o.code == f.code && o.scope == f.scope) {
            out.push(f);
        }
    }
    out
}

/// Application-level assessment (independent of transport completion).
pub fn assess_application(protocol: Protocol, status: &ProtocolStatus, body: &BodyFacts, body_complete: bool) -> ApplicationState {
    match status {
        ProtocolStatus::Http { status, .. } | ProtocolStatus::Sse { http_status: status, .. } => {
            if *status >= 400 {
                ApplicationState::Failure
            } else if !body_complete {
                ApplicationState::NotEvaluated
            } else if body.soap_fault.is_some() || body.graphql.is_some() {
                ApplicationState::Failure
            } else {
                ApplicationState::Success
            }
        }
        ProtocolStatus::Grpc { grpc_status, .. } => match grpc_status {
            Some(0) => ApplicationState::Success,
            Some(_) => ApplicationState::Failure,
            None => ApplicationState::NotEvaluated,
        },
        ProtocolStatus::WebSocket { handshake_status, close_code, .. } => match handshake_status {
            Some(101) | Some(200) => match close_code {
                None | Some(1000) | Some(1001) => ApplicationState::Success,
                Some(1006) => ApplicationState::NotEvaluated,
                Some(_) => ApplicationState::Failure,
            },
            Some(_) => ApplicationState::Failure,
            None => ApplicationState::NotEvaluated,
        },
        _ => {
            let _ = protocol;
            ApplicationState::NotEvaluated
        }
    }
}

pub(crate) fn warn(ws: &mut Vec<OutcomeWarning>, code: WarningCode, message: impl Into<String>) {
    ws.push(OutcomeWarning { code, message: message.into() });
}
