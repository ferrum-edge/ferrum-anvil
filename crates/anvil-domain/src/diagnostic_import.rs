//! Ephemeral, read-only IPC preview. Never an execution record or trusted evidence.

use crate::diagnostics::Confidence;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticImportInput {
    pub text: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportedDiagnosticKind {
    Report,
    AlloyCli,
    Finding,
    Reference,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportedDiagnosticTrust {
    Unverified,
}

/// `reported` preserves producer claims, after credential redaction. Its confidence,
/// verification, trust and authenticated fields never determine Anvil's assessment.
/// This DTO is private IPC, with dedicated frontend bindings; it is not persisted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportedDiagnosticPreview {
    pub kind: ImportedDiagnosticKind,
    pub trust: ImportedDiagnosticTrust,
    pub confidence: Confidence,
    pub observation_count: usize,
    pub finding_count: usize,
    pub reported: Value,
    pub warnings: Vec<String>,
}
