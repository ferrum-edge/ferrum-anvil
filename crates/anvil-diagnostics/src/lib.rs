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

/// Catalog versions this build embeds: the findings wording catalog and every
/// Ferrum compatibility catalog (e.g. `findings:V ferrum:ferrum-edge-0.9.5,ferrum-edge-0.9.7`).
pub fn catalog_version() -> String {
    format!("findings:{} ferrum:{}", render::catalog().version, ferrum::compatibility_ids().collect::<Vec<_>>().join(","))
}

/// Catalog version string recorded in an execution record: the findings
/// catalog plus the Ferrum catalog the diagnosis actually used — the trusted
/// profile's compatibility id, `<id>(no-catalog)` when this build has no
/// catalog for it, or `none` without a trusted Ferrum profile.
pub fn catalog_version_for(trust: &FerrumTrust) -> String {
    let ferrum = match trust {
        FerrumTrust::Trusted { compatibility_id, .. } => match ferrum::catalog_for(compatibility_id) {
            Some(c) => c.compatibility_id.clone(),
            None => format!("{}(no-catalog)", compatibility_id.trim()),
        },
        FerrumTrust::NotConfigured => "none".to_string(),
    };
    format!("findings:{} ferrum:{ferrum}", render::catalog().version)
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
    /// Keys of catalog `fragments` appended to the alternatives (wording
    /// shared by several findings, selected by evidence).
    pub alt_fragments: Vec<&'static str>,
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
            alt_fragments: vec![],
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

    /// Append the catalog fragment `key` to the alternatives.
    pub fn alt_fragment(mut self, key: &'static str) -> Self {
        if !self.alt_fragments.contains(&key) {
            self.alt_fragments.push(key);
        }
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
    /// The exchange ended at an interactive login step (a redirect to an
    /// OAuth 2.0 / OIDC authorization endpoint), not at the requested API:
    /// whatever the final status, the application was not evaluated.
    pub stopped_at_login: bool,
}

/// Run every rule over the input and render findings.
pub fn diagnose(input: &DiagnosticInput<'_>) -> Diagnosis {
    let body = input.response.map(|r| facts::body_facts(r.body.content_type.as_deref(), input.body)).unwrap_or_default();
    let mut drafts: Vec<Draft> = Vec::new();
    let mut warnings: Vec<OutcomeWarning> = Vec::new();
    let ctx = rules::Ctx { input, body: &body };
    rules::run_all(&ctx, &mut drafts, &mut warnings);
    let stopped_at_login = rules::stopped_at_login(&ctx);
    // Cap confidence when the only provenance is an unauthenticated channel.
    let findings = drafts.into_iter().map(render::render).collect::<Vec<_>>();
    let mut findings = dedupe(findings);
    findings.sort_by(|a, b| b.severity.cmp(&a.severity).then(specificity(b).cmp(&specificity(a))).then(b.confidence.cmp(&a.confidence)));
    warnings.dedup_by(|a, b| a.code == b.code);
    Diagnosis { findings, warnings, body, stopped_at_login }
}

/// Presentation order only (each finding keeps its own confidence): evidence
/// about a specific hop or phase is more actionable than the generic
/// status-code explanation, which stays listed as the fallback.
fn specificity(f: &DiagnosticFinding) -> u8 {
    if f.code.starts_with("http.") {
        0
    } else if f.scope == anvil_domain::diagnostics::SourceScope::Unknown {
        1
    } else {
        2
    }
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
        // A CONNECT-UDP proxy that refused the tunnel is an application-level
        // answer (of the proxy). An open tunnel is never judged: UDP has no
        // application status.
        ProtocolStatus::Udp { masque: Some(m), .. } if m.connect_status.map(|s| !(200..300).contains(&s)).unwrap_or(false) => {
            ApplicationState::Failure
        }
        _ => {
            let _ = protocol;
            ApplicationState::NotEvaluated
        }
    }
}

pub(crate) fn warn(ws: &mut Vec<OutcomeWarning>, code: WarningCode, message: impl Into<String>) {
    ws.push(OutcomeWarning { code, message: message.into() });
}
