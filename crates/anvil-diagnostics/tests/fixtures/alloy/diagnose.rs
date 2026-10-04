//! `ferrum-alloy diagnose`: explains supplied evidence.
//!
//! Deterministic rules only, and no external AI service. The only network
//! access is `--url` (a service report) and `--edge-admin-url` (one G01
//! record). Reports are always read with `parse_offline`. Only an admin
//! record bound to a separate explicit client observation can authenticate
//! a gateway record finding (ADR 0009).
//!
//! An OTLP export is held to the same report limits, with or without
//! `--write-report`: rules only ever run on reports the parser accepts, so
//! a trace the parser would refuse fails instead of being analyzed.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use clap::Args;
use ferrum_alloy_diagnostics::edge_record;
use ferrum_alloy_diagnostics::model::{
    Collection, CollectionMethod, DiagnosticReport, Producer, ProducerKind, Verification,
};
use ferrum_alloy_diagnostics::otlp::{self, ImportLimits};
use ferrum_alloy_diagnostics::parse::{Limits, parse_offline};
use ferrum_alloy_diagnostics::render::render_text;
use ferrum_alloy_diagnostics::rules::{Thresholds, analyze};

use crate::Format;
use crate::edge_lookup::CredentialRedactor;
use crate::error::CliError;
use crate::input::{invalid, read_regular_file_bounded};
use crate::output::printable;

/// Arguments for `diagnose`.
#[derive(Debug, Args)]
#[command(group = clap::ArgGroup::new("source").args(["input", "otlp", "url"]))]
#[command(group = clap::ArgGroup::new("evidence").required(true).multiple(true).args(["input", "otlp", "url", "edge_observation"]))]
pub(crate) struct DiagnoseArgs {
    /// A `ferrum.diagnostic_report` v1 JSON file.
    #[arg(long)]
    input: Option<PathBuf>,
    /// An OTLP/JSON trace export (OpenTelemetry Collector `file` exporter).
    #[arg(long)]
    otlp: Option<PathBuf>,
    /// Trace to analyze in an OTLP export with several traces.
    #[arg(long, requires = "otlp")]
    trace_id: Option<String>,
    /// List the traces in an OTLP export and exit.
    #[arg(long, requires = "otlp")]
    list_traces: bool,
    /// Fetch the live report of one request from a running service: the base
    /// URL of its management listener, for example `http://127.0.0.1:9090`.
    /// The credential comes from `FERRUM_ALLOY_DIAGNOSTICS_TOKEN` or
    /// `--token-file`, never from an argument.
    #[arg(long, requires = "request_id")]
    url: Option<String>,
    /// The request id to fetch with `--url`.
    #[arg(long, requires = "url")]
    request_id: Option<String>,
    /// A file holding the credential for `--url`, instead of
    /// `FERRUM_ALLOY_DIAGNOSTICS_TOKEN`.
    #[arg(long, requires = "url")]
    token_file: Option<PathBuf>,
    /// Edge admin base URL for an authenticated G01 lookup. Uses only
    /// FERRUM_ALLOY_EDGE_DIAGNOSTICS_TOKEN (diagnostics:read plus ns).
    #[arg(long, requires = "edge_observation", conflicts_with = "list_traces")]
    edge_admin_url: Option<String>,
    /// Explicit trusted client capture JSON, separate from any service report:
    /// reference, namespace, status, gateway_error (null if absent), protocol,
    /// request_started_at and response_received_at (RFC 3339, at most 300s apart).
    #[arg(long, requires = "edge_admin_url")]
    edge_observation: Option<PathBuf>,
    /// Whole-request timeout in milliseconds (1 to 120000). Edge lookups
    /// additionally cap it at 5000 and connection setup at 2000.
    #[arg(long, default_value_t = 10_000)]
    timeout_ms: u64,
    /// Write the assembled report (with findings) to this file, pretty-printed,
    /// or compact when only compact JSON fits the report size limit. Nothing
    /// is written when `diagnose --input` would reject it.
    #[arg(long)]
    write_report: Option<PathBuf>,
    /// Output format.
    #[arg(long, value_enum, default_value_t)]
    format: Format,
}

fn read(path: &Path, max: usize) -> Result<Vec<u8>, CliError> {
    let max = u64::try_from(max).unwrap_or(u64::MAX);
    read_regular_file_bounded(path, max).map_err(|e| invalid(path, e))
}

/// The bytes `--write-report` writes: pretty-printed JSON, or compact JSON
/// when the pretty form would not fit within `limits.max_bytes`.
fn report_bytes(report: &impl serde::Serialize, limits: &Limits) -> Result<Vec<u8>, CliError> {
    let encode = |e: serde_json::Error| CliError::Io(e.to_string());
    let mut json = serde_json::to_vec_pretty(report).map_err(encode)?;
    if json.len() >= limits.max_bytes {
        json = serde_json::to_vec(report).map_err(encode)?;
    }
    json.push(b'\n');
    Ok(json)
}

/// Runs `diagnose`.
pub(crate) fn run(args: DiagnoseArgs) -> Result<ExitCode, CliError> {
    let redactor = CredentialRedactor::from_env();
    run_redacted(args, &redactor).map_err(|error| redactor.redact_error(error))
}

fn run_redacted(args: DiagnoseArgs, redactor: &CredentialRedactor) -> Result<ExitCode, CliError> {
    let limits = Limits::default();
    if !(1..=120_000).contains(&args.timeout_ms) {
        return Err(CliError::Invalid(
            "--timeout-ms must be within 1..=120000".into(),
        ));
    }
    let observation = args
        .edge_observation
        .as_deref()
        .map(|path| {
            let bytes = read(path, edge_record::MAX_RECORD_BYTES)?;
            edge_record::parse_observation(&bytes).map_err(|e| CliError::Invalid(e.to_string()))
        })
        .transpose()?;
    let (mut report, warnings, claimed) = if let Some(path) = &args.input {
        let bytes = read(path, limits.max_bytes)?;
        let parsed = parse_offline(&bytes, &limits)
            .map_err(|e| CliError::Invalid(format!("{}: {e}", path.display())))?;
        (
            parsed.report,
            parsed.warnings,
            Some(parsed.claimed_verification),
        )
    } else if let Some(path) = &args.otlp {
        let import_limits = ImportLimits::default();
        let bytes = read(path, import_limits.max_bytes)?;
        let text = String::from_utf8(bytes)
            .map_err(|_| CliError::Invalid(format!("{} is not UTF-8", path.display())))?;
        if args.list_traces {
            let ids = otlp::trace_ids(&text, &import_limits)
                .map_err(|e| CliError::Invalid(e.to_string()))?;
            let out = match args.format {
                Format::Json => {
                    let mut value = serde_json::json!({ "trace_ids": ids });
                    redactor.redact_json(&mut value);
                    format!("{value:#}\n")
                }
                Format::Human => ids
                    .iter()
                    .map(|id| format!("{}\n", redactor.redact(id)))
                    .collect(),
            };
            crate::print(&out)?;
            return Ok(ExitCode::SUCCESS);
        }
        let collector = Producer {
            kind: ProducerKind::Collector,
            name: "ferrum-alloy-cli".into(),
            version: Some(env!("CARGO_PKG_VERSION").into()),
            instance: None,
        };
        // Strict even without --write-report; see the module documentation.
        let report = otlp::import(&text, args.trace_id.as_deref(), collector, &import_limits)
            .map_err(|e| CliError::Invalid(e.to_string()))?;
        (report, Vec::new(), None)
    } else if let Some(base) = &args.url {
        let Some(request_id) = args.request_id.as_deref() else {
            return Err(CliError::Invalid("--url requires --request-id".into()));
        };
        let token = crate::live::token(args.token_file.as_deref())?;
        let url = crate::live::report_url(base, request_id, token.is_some())?;
        let timeout = Duration::from_millis(args.timeout_ms);
        let bytes = crate::live::fetch(url, token.as_deref(), timeout, limits.max_bytes)?;
        let parsed = parse_offline(&bytes, &limits)
            .map_err(|e| CliError::Invalid(format!("the live report: {e}")))?;
        (
            parsed.report,
            parsed.warnings,
            Some(parsed.claimed_verification),
        )
    } else if observation.is_some() {
        let report = DiagnosticReport::new(Collection {
            collector: Producer {
                kind: ProducerKind::Collector,
                name: "ferrum-alloy-cli".into(),
                version: Some(env!("CARGO_PKG_VERSION").into()),
                instance: None,
            },
            method: CollectionMethod::OfflineImport,
            verification: Verification::Unverified,
            notes: Vec::new(),
        });
        (report, Vec::new(), None)
    } else {
        return Err(CliError::Invalid("pass --input, --otlp, or --url".into()));
    };

    let lookup = match (args.edge_admin_url.as_deref(), observation.as_ref()) {
        (Some(base), Some(observation)) => Some(crate::edge_lookup::fetch(
            base,
            observation,
            Duration::from_millis(args.timeout_ms),
        )?),
        _ => None,
    };
    let mut findings = analyze(&report, &Thresholds::default());
    if let Some(lookup) = &lookup {
        findings.push(lookup.finding());
        ferrum_alloy_diagnostics::rules::sort_findings(&mut findings);
    }
    report.findings.clone_from(&findings);
    if let Some(path) = &args.write_report {
        let json = if redactor.is_empty() {
            report_bytes(&report, &limits)?
        } else {
            let mut value =
                serde_json::to_value(&report).map_err(|e| CliError::Io(e.to_string()))?;
            redactor.redact_json(&mut value);
            report_bytes(&value, &limits)?
        };
        // Findings and pretty printing add bytes after the report was
        // checked: never write a file that `diagnose --input` would reject.
        if let Err(e) = parse_offline(&json, &limits) {
            return Err(CliError::Invalid(format!(
                "not writing {}: `diagnose --input` would reject the report: {e}",
                path.display()
            )));
        }
        crate::fsout::write_atomically(path, &json, crate::fsout::NewFileMode::Private)?;
    }
    match args.format {
        Format::Human => {
            let text = render_text(&report, &findings, &warnings);
            let text = redactor.redact(&text);
            crate::print(&printable(&text))?;
        }
        Format::Json => {
            let mut value = serde_json::json!({
                "claimed_verification": claimed.map(|v| v.as_str().to_owned()),
                "warnings": warnings.iter().map(|w| serde_json::json!({ "path": w.path, "message": w.message })).collect::<Vec<_>>(),
                "report": report,
            });
            redactor.redact_json(&mut value);
            crate::print(&format!("{value:#}\n"))?;
        }
    }
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use ferrum_alloy_diagnostics::model::{Collection, CollectionMethod, Verification};

    use super::*;

    #[test]
    fn written_reports_fall_back_to_compact_json_to_fit_the_limit() {
        let report = DiagnosticReport::new(Collection {
            collector: Producer {
                kind: ProducerKind::Collector,
                name: "ferrum-alloy-cli".into(),
                version: None,
                instance: None,
            },
            method: CollectionMethod::OtlpFileImport,
            verification: Verification::Unverified,
            notes: vec!["compact when pretty does not fit".into()],
        });
        let pretty = serde_json::to_vec_pretty(&report).unwrap();
        let compact = serde_json::to_vec(&report).unwrap();
        assert!(compact.len() < pretty.len());
        // The pretty form plus its newline fits exactly, then by one byte less.
        for (max_bytes, form) in [(pretty.len() + 1, &pretty), (pretty.len(), &compact)] {
            let limits = Limits {
                max_bytes,
                ..Limits::default()
            };
            let mut expected = form.clone();
            expected.push(b'\n');
            assert_eq!(report_bytes(&report, &limits).unwrap(), expected);
        }
    }
}
