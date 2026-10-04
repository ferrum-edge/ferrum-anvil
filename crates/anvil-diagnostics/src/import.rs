//! Bounded offline consumer of the immutable Ferrum diagnostic contracts.
//! No execution inputs, GatewayDetail, transport, storage, paths or URLs enter this API.

mod bounds;
mod schema;

use anvil_domain::diagnostic_import::{ImportedDiagnosticKind, ImportedDiagnosticPreview, ImportedDiagnosticTrust};
use anvil_domain::diagnostics::Confidence;
use serde_json::Value;
use std::collections::BTreeSet;

pub const MAX_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_DEPTH: usize = 32;
pub const MAX_STRING_BYTES: usize = 2048;
pub const MAX_ARRAY_ITEMS: usize = 5000;
pub const MAX_OBJECT_MEMBERS: usize = 128;
pub const MAX_NODES: usize = 200_000;

/// Errors deliberately contain no input values, keys, paths or parser excerpts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ImportError {
    #[error("Diagnostic JSON exceeds a byte, depth, string or collection limit.")]
    Limit,
    #[error("Diagnostic input must be valid UTF-8 JSON with unique object keys.")]
    Json,
    #[error("Diagnostic input does not match a supported v1 contract.")]
    Contract,
    #[error("Diagnostic report contains invalid identifiers, references or measurements.")]
    Semantics,
}

/// Redaction is mandatory at the boundary, before any producer value is returned.
/// Supplied findings are retained only as claims; no diagnosis is computed from them.
pub fn preview(input: &[u8], redact: &dyn Fn(&mut Value) -> Result<(), ImportError>) -> Result<ImportedDiagnosticPreview, ImportError> {
    let mut value = bounds::parse(input)?;
    let kind = if value["schema"] == "ferrum.diagnostic_report" {
        ImportedDiagnosticKind::Report
    } else if value["schema_version"] == "ferrum.diagnostic_ref.v1" {
        ImportedDiagnosticKind::Reference
    } else if value.get("report").is_some() && value.get("code").is_none() {
        validate_cli(&value)?;
        ImportedDiagnosticKind::AlloyCli
    } else if value.get("ref").is_some() && value.get("code").is_none() {
        ImportedDiagnosticKind::Reference
    } else {
        ImportedDiagnosticKind::Finding
    };
    let reported = if kind == ImportedDiagnosticKind::AlloyCli { &value["report"] } else { &value };
    schema::validate(reported, kind)?;
    let (observation_count, finding_count) = match kind {
        ImportedDiagnosticKind::Report | ImportedDiagnosticKind::AlloyCli => {
            validate_report(reported)?;
            (array_len(reported, "observations"), array_len(reported, "findings"))
        }
        ImportedDiagnosticKind::Finding => (0, 1),
        ImportedDiagnosticKind::Reference => (0, 0),
    };
    redact(&mut value)?;
    Ok(ImportedDiagnosticPreview {
        kind,
        trust: ImportedDiagnosticTrust::Unverified,
        confidence: Confidence::Unknown,
        observation_count,
        finding_count,
        reported_json: serde_json::to_string_pretty(&value).map_err(|_| ImportError::Json)?,
        warnings: vec![
            "Read-only offline preview: reported facts and authentication claims are unverified.".into(),
            "Supplied findings are conclusions, never evidence for an Anvil diagnosis.".into(),
            "Unknown members are uninterpreted claims. Review free text before sharing.".into(),
            "Short or unrecognized free-text secrets can remain after credential redaction.".into(),
        ],
    })
}

fn array_len(value: &Value, key: &str) -> usize {
    value.get(key).and_then(Value::as_array).map_or(0, Vec::len)
}

fn validate_cli(value: &Value) -> Result<(), ImportError> {
    let object = value.as_object().ok_or(ImportError::Contract)?;
    // Exact stdout envelope from immutable Alloy CLI diagnose.rs, not a report schema.
    if object.len() != 3
        || !object.contains_key("report")
        || !object.contains_key("warnings")
        || !object.contains_key("claimed_verification")
    {
        return Err(ImportError::Contract);
    }
    let claim = &object["claimed_verification"];
    if !claim.is_null() && !claim.is_string() {
        return Err(ImportError::Contract);
    }
    let warnings = object["warnings"].as_array().ok_or(ImportError::Contract)?;
    for warning in warnings {
        let warning = warning.as_object().ok_or(ImportError::Contract)?;
        if warning.len() != 2 || !warning.get("path").is_some_and(Value::is_string) || !warning.get("message").is_some_and(Value::is_string)
        {
            return Err(ImportError::Contract);
        }
    }
    Ok(())
}

fn validate_report(report: &Value) -> Result<(), ImportError> {
    if report.get("generated_at").is_some_and(|v| !v.as_str().is_some_and(schema::rfc3339)) {
        return Err(ImportError::Semantics);
    }
    let mut ids = BTreeSet::new();
    if let Some(observations) = report["observations"].as_array() {
        for observation in observations {
            let id = observation["id"].as_str().ok_or(ImportError::Contract)?;
            if !ids.insert(id) {
                return Err(ImportError::Semantics);
            }
            if observation["kind"] == "measurement"
                && observation["availability"] == "measured"
                && !observation.get("value").is_some_and(Value::is_number)
            {
                return Err(ImportError::Semantics);
            }
            if observation.get("value").is_some()
                && observation["availability"] == "measured"
                && !observation.get("unit").is_some_and(Value::is_string)
            {
                return Err(ImportError::Semantics);
            }
            if let Some(interval) = observation.get("interval") {
                let start = interval["start_unix_nano"].as_u64();
                let end = interval["end_unix_nano"].as_u64();
                if !matches!((start, end), (Some(start), Some(end)) if start <= end) {
                    return Err(ImportError::Semantics);
                }
            }
            if let Some(span) = observation.get("span") {
                for field in ["trace_id", "span_id", "parent_span_id"] {
                    if span[field].as_str().is_some_and(|s| s.bytes().all(|b| b == b'0')) {
                        return Err(ImportError::Semantics);
                    }
                }
            }
        }
    }
    if report["subject"]["trace_id"].as_str().is_some_and(|s| s.bytes().all(|b| b == b'0')) {
        return Err(ImportError::Semantics);
    }
    if let Some(findings) = report["findings"].as_array() {
        for finding in findings {
            if let Some(references) = finding["supporting_observations"].as_array() {
                for reference in references {
                    if !reference.as_str().is_some_and(|id| ids.contains(id)) {
                        return Err(ImportError::Semantics);
                    }
                }
            }
        }
    }
    Ok(())
}
