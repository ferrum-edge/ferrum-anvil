//! Ephemeral, read-only IPC preview. Never an execution record or trusted evidence.

use crate::diagnostics::Confidence;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticImportInput {
    pub text: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ImportedDiagnosticKind {
    Report,
    AlloyCli,
    Finding,
    Reference,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ImportedDiagnosticTrust {
    Unverified,
}

/// `reported_json` preserves producer claims, after credential redaction. Its confidence,
/// verification, trust and authenticated fields never determine Anvil's assessment.
/// Rust serializes the JSON text so native IPC never rounds producer integers in JavaScript.
/// This DTO is ephemeral IPC and is not persisted.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ImportedDiagnosticPreview {
    pub kind: ImportedDiagnosticKind,
    pub trust: ImportedDiagnosticTrust,
    pub confidence: Confidence,
    pub observation_count: usize,
    pub finding_count: usize,
    pub reported_json: String,
    pub warnings: Vec<String>,
}
