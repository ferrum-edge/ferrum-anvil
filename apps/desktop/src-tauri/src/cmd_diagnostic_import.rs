//! Stateless offline preview: no DesktopState, grants, paths, vault or request effects.

use anvil_diagnostics::import::{ImportError, preview};
use anvil_domain::diagnostic_import::{DiagnosticImportInput, ImportedDiagnosticPreview};
use anvil_domain::secret::REDACTED;
use anvil_engine::redact::{Redactor, is_credential_name};
use serde_json::Value;

#[tauri::command]
pub fn diagnostic_import_preview(
    input: DiagnosticImportInput,
) -> Result<ImportedDiagnosticPreview, String> {
    preview(input.text.as_bytes(), &redact).map_err(|error| error.to_string())
}

const MAX_CREDENTIALS: usize = 128;
const MAX_CREDENTIAL_BYTES: usize = 64 * 1024;

fn sensitive(name: &str) -> bool {
    // Imported evidence keys may contain arbitrarily long namespace prefixes.
    is_credential_name(name, &[]) || name.to_ascii_lowercase().contains("cookie")
}

fn collect(
    value: &Value,
    hidden: bool,
    secrets: &mut Vec<String>,
    bytes: &mut usize,
) -> Result<(), ImportError> {
    match value {
        Value::String(text) => {
            let credential = hidden
                || text.contains("-----BEGIN ") && text.contains("PRIVATE KEY-----")
                || text.split_whitespace().any(|word| {
                    word.eq_ignore_ascii_case("bearer") || word.eq_ignore_ascii_case("basic")
                });
            if credential && !text.is_empty() {
                *bytes += text.len();
                if secrets.len() == MAX_CREDENTIALS || *bytes > MAX_CREDENTIAL_BYTES {
                    return Err(ImportError::Limit);
                }
                secrets.push(text.clone());
                let mut words = text.split_whitespace();
                while let Some(word) = words.next() {
                    if (word.eq_ignore_ascii_case("bearer") || word.eq_ignore_ascii_case("basic"))
                        && let Some(token) = words.next()
                    {
                        *bytes += token.len();
                        if secrets.len() == MAX_CREDENTIALS || *bytes > MAX_CREDENTIAL_BYTES {
                            return Err(ImportError::Limit);
                        }
                        secrets.push(token.into());
                    }
                }
            }
        }
        Value::Array(values) => {
            for value in values {
                collect(value, hidden, secrets, bytes)?;
            }
        }
        Value::Object(object) => {
            let pair = ["key", "name", "header"]
                .iter()
                .any(|key| object.get(*key).and_then(Value::as_str).is_some_and(sensitive));
            for (key, value) in object {
                collect(
                    value,
                    hidden || sensitive(key) || pair && key == "value",
                    secrets,
                    bytes,
                )?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn redact(value: &mut Value) -> Result<(), ImportError> {
    let mut secrets = Vec::new();
    let mut credential_bytes = 0;
    collect(value, false, &mut secrets, &mut credential_bytes)?;
    // Use Anvil's existing exact-value and encoded-value scrubber. No vault values
    // are resolved: only credential-bearing strings inside this bounded input.
    let redactor = Redactor::new(secrets, Vec::new());
    scrub(value, false, &redactor);
    Ok(())
}

fn scrub(value: &mut Value, hidden: bool, redactor: &Redactor) {
    if hidden {
        *value = Value::String(REDACTED.into());
        return;
    }
    match value {
        Value::String(text) => *text = redactor.url(&redactor.text(text)),
        Value::Array(values) => {
            for value in values {
                scrub(value, false, redactor);
            }
        }
        Value::Object(object) => {
            let pair = ["key", "name", "header"]
                .iter()
                .any(|key| object.get(*key).and_then(Value::as_str).is_some_and(sensitive));
            let original = std::mem::take(object);
            for (key, mut value) in original {
                // Keep booleans such as authenticated:true as original claims.
                let hidden = sensitive(&key) && !value.is_boolean() || pair && key == "value";
                scrub(&mut value, hidden, redactor);
                object.insert(redactor.text(&key), value);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anvil_domain::diagnostic_import::ImportedDiagnosticTrust;
    use anvil_domain::diagnostics::Confidence;
    use serde_json::json;

    const REPORT: &str = include_str!(
        "../../../../contracts/ferrum-contracts/fixtures/diagnostic-report/valid/forged-verified-claim.json"
    );

    #[test]
    fn ipc_returns_unverified_claims_and_redacts_credentials_everywhere() {
        let mut report: Value = serde_json::from_str(REPORT).unwrap();
        report["authenticated"] = json!(true);
        report["extensions"] = json!({
            "authorization": "Bearer credential-12345",
            "nested": {"password": "secret-12345"},
            "echo": "credential-12345 secret-12345",
            "url": "https://user:pass@example.test/?access_token=hidden",
            "binary": {"cookie": ["cookie-secret"]},
            "key": "header.x-api-key",
            "value": "api-secret",
        });
        let result = diagnostic_import_preview(DiagnosticImportInput {
            text: report.to_string(),
        })
        .unwrap();
        assert_eq!(result.trust, ImportedDiagnosticTrust::Unverified);
        assert_eq!(result.confidence, Confidence::Unknown);
        assert_eq!(result.reported["authenticated"], true);
        assert_eq!(result.reported["collection"]["verification"], "verified");
        let text = result.reported.to_string();
        for secret in [
            "credential-12345",
            "secret-12345",
            "user:pass",
            "hidden",
            "cookie-secret",
            "api-secret",
        ] {
            assert!(!text.contains(secret), "credential leaked");
        }
        assert!(text.contains(REDACTED));
    }

    #[test]
    fn ipc_rejects_hostile_input_without_echoing_it() {
        for text in [
            "secret-input-not-json".to_string(),
            REPORT.replace("1.0", "2.0"),
            " ".repeat(anvil_diagnostics::import::MAX_BYTES + 1),
        ] {
            let error = diagnostic_import_preview(DiagnosticImportInput { text }).unwrap_err();
            assert!(!error.contains("secret-input"));
        }
    }

    #[test]
    fn ipc_credential_work_is_bounded() {
        let mut report: Value = serde_json::from_str(REPORT).unwrap();
        report["extensions"] = json!({"passwords": vec!["secret"; MAX_CREDENTIALS + 1]});
        assert!(
            diagnostic_import_preview(DiagnosticImportInput {
                text: report.to_string(),
            })
            .is_err()
        );
    }

    #[test]
    fn production_ipc_dto_refuses_paths_urls_nulls_and_extra_capabilities() {
        for value in [
            json!({"text": REPORT, "path": "/tmp/diagnostic.json"}),
            json!({"text": REPORT, "url": "https://example.test/report"}),
            json!({"text": REPORT, "grant": "forged"}),
            json!({"text": null}),
            json!({"text": {"report": REPORT}}),
            json!({}),
        ] {
            assert!(serde_json::from_value::<DiagnosticImportInput>(value).is_err());
        }
        let input: DiagnosticImportInput = serde_json::from_value(json!({"text": REPORT})).unwrap();
        let result = diagnostic_import_preview(input).unwrap();
        let serialized = serde_json::to_value(result).unwrap();
        assert_eq!(serialized["trust"], "unverified");
        assert_eq!(serialized["confidence"], "unknown");
    }

    #[test]
    fn every_canonical_fixture_crosses_the_production_command_boundary() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../contracts/ferrum-contracts/fixtures");
        let mut count = 0;
        for contract in ["diagnostic-report", "diagnostic-finding", "diagnostic-ref"] {
            for group in ["valid", "invalid"] {
                for entry in std::fs::read_dir(root.join(contract).join(group)).unwrap() {
                    let text = std::fs::read_to_string(entry.unwrap().path()).unwrap();
                    let input: DiagnosticImportInput =
                        serde_json::from_value(json!({"text": text})).unwrap();
                    assert_eq!(diagnostic_import_preview(input).is_ok(), group == "valid");
                    count += 1;
                }
            }
        }
        assert_eq!(
            count,
            27,
            "all canonical diagnostic fixtures through IPC DTO and command"
        );
    }

    #[test]
    fn real_hosted_producer_golden_crosses_the_ipc_boundary() {
        let text = include_str!(
            "../../../../crates/anvil-diagnostics/tests/fixtures/alloy/diagnosis-edge-0.9.10.json"
        );
        let input: DiagnosticImportInput = serde_json::from_value(json!({"text": text})).unwrap();
        let result = diagnostic_import_preview(input).unwrap();
        assert_eq!(result.finding_count, 2);
        assert_eq!(result.confidence, Confidence::Unknown);
        assert_eq!(result.trust, ImportedDiagnosticTrust::Unverified);
        let golden: Value = serde_json::from_str(text).unwrap();
        assert_eq!(result.reported, golden);
    }
}
