//! Stateless offline preview: no DesktopState, grants, paths, vault or request effects.

use anvil_diagnostics::import::{ImportError, preview};
use anvil_domain::diagnostic_import::{DiagnosticImportInput, ImportedDiagnosticPreview};
use anvil_domain::secret::REDACTED;
use anvil_engine::redact::{Redactor, is_credential_name};
use serde_json::Value;

#[tauri::command]
pub async fn diagnostic_import_preview(input: DiagnosticImportInput) -> Result<ImportedDiagnosticPreview, String> {
    tokio::task::spawn_blocking(move || preview_import(&input.text))
        .await
        .map_err(|error| error.to_string())?
}

fn preview_import(text: &str) -> Result<ImportedDiagnosticPreview, String> {
    preview(text.as_bytes(), &redact).map_err(|error| error.to_string())
}

const MAX_CREDENTIALS: usize = 128;
const MAX_CREDENTIAL_BYTES: usize = 64 * 1024;
const MAX_DECODE_ROUNDS: usize = 3;

#[derive(Default)]
struct Credentials {
    secrets: Vec<String>,
    discoveries: usize,
    bytes: usize,
}

impl Credentials {
    fn register(&mut self, text: &str) -> Result<(), ImportError> {
        if text.is_empty() {
            return Ok(());
        }
        // Charge even duplicate and tiny values: deduplication bounds the scrubber,
        // while the discovery budget also bounds redundant attacker-controlled work.
        self.discoveries += 1;
        self.bytes += text.len();
        if self.discoveries > MAX_CREDENTIALS || self.bytes > MAX_CREDENTIAL_BYTES {
            return Err(ImportError::Limit);
        }
        if !self.secrets.iter().any(|secret| secret == text) {
            self.secrets.push(text.into());
        }
        Ok(())
    }

    fn component(&mut self, text: &str) -> Result<(), ImportError> {
        self.register(text)?;
        let mut layer = text.to_owned();
        for _ in 0..MAX_DECODE_ROUNDS {
            let Some(decoded) = percent_decoded(&layer) else {
                break;
            };
            if decoded == layer {
                break;
            }
            self.register(&decoded)?;
            layer = decoded;
        }
        Ok(())
    }
}

// Strict, shrinking, UTF-8 percent decoding. No lossy or unbounded decoding,
// and `+` stays literal in userinfo and cookies.
fn percent_decoded(text: &str) -> Option<String> {
    let mut bytes = Vec::with_capacity(text.len());
    let mut input = text.bytes();
    while let Some(byte) = input.next() {
        if byte == b'%' {
            let high = char::from(input.next()?).to_digit(16)?;
            let low = char::from(input.next()?).to_digit(16)?;
            bytes.push((high * 16 + low) as u8);
        } else {
            bytes.push(byte);
        }
    }
    String::from_utf8(bytes).ok()
}

#[derive(Clone, Copy)]
enum CookieKind {
    Cookie,
    SetCookie,
}

fn cookie_kind(name: &str) -> Option<CookieKind> {
    let name = name.to_ascii_lowercase();
    if name.contains("set-cookie") || name.contains("set_cookie") {
        Some(CookieKind::SetCookie)
    } else if name.contains("cookie") {
        Some(CookieKind::Cookie)
    } else {
        None
    }
}

fn collect_cookie(text: &str, kind: CookieKind, credentials: &mut Credentials) -> Result<(), ImportError> {
    // A Set-Cookie value is the first pair; Path/Domain/Expires are attributes,
    // not additional cookies. Multiple Set-Cookie headers can be array entries.
    for pair in text.split(';') {
        if let Some((_, value)) = pair.split_once('=') {
            let value = value.trim();
            let value = value.strip_prefix('"').and_then(|v| v.strip_suffix('"')).unwrap_or(value);
            credentials.component(value)?;
        }
        if matches!(kind, CookieKind::SetCookie) {
            break;
        }
    }
    Ok(())
}

fn collect_urls(text: &str, credentials: &mut Credentials) -> Result<(), ImportError> {
    // Whole URL fields and whitespace-delimited URLs in text. URL parsing is
    // structural only: it never resolves, fetches or authenticates a destination.
    for word in text.split_whitespace() {
        let word = word.trim_matches(['<', '>', '"', '\'', '(', ')', '[', ']']);
        let Ok(url) = url::Url::parse(word) else {
            continue;
        };
        credentials.component(url.username())?;
        if let Some(password) = url.password() {
            credentials.component(password)?;
        }
        for query in [url.query(), url.fragment()].into_iter().flatten() {
            for pair in query.split('&') {
                if let Some((name, value)) = pair.split_once('=') {
                    let name = name.replace('+', " ");
                    if percent_decoded(&name).is_some_and(|name| sensitive(&name)) {
                        credentials.component(value)?;
                        if value.contains('+') {
                            credentials.component(&value.replace('+', " "))?;
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

fn sensitive(name: &str) -> bool {
    // Imported evidence keys may contain arbitrarily long namespace prefixes.
    is_credential_name(name, &[]) || name.to_ascii_lowercase().contains("cookie")
}

fn collect(value: &Value, hidden: bool, cookie: Option<CookieKind>, credentials: &mut Credentials) -> Result<(), ImportError> {
    match value {
        Value::String(text) => {
            let credential = hidden
                || text.contains("-----BEGIN ") && text.contains("PRIVATE KEY-----")
                || text.split_whitespace().any(|word| word.eq_ignore_ascii_case("bearer") || word.eq_ignore_ascii_case("basic"));
            if credential && !text.is_empty() {
                credentials.component(text)?;
                let mut words = text.split_whitespace();
                while let Some(word) = words.next() {
                    if (word.eq_ignore_ascii_case("bearer") || word.eq_ignore_ascii_case("basic"))
                        && let Some(token) = words.next()
                    {
                        credentials.component(token)?;
                    }
                }
            }
            if let Some(kind) = cookie {
                collect_cookie(text, kind, credentials)?;
            }
            collect_urls(text, credentials)?;
        }
        Value::Array(values) => {
            for value in values {
                collect(value, hidden, cookie, credentials)?;
            }
        }
        Value::Object(object) => {
            let pair = ["key", "name", "header"].iter().any(|key| object.get(*key).and_then(Value::as_str).is_some_and(sensitive));
            let pair_cookie =
                ["key", "name", "header"].iter().find_map(|key| object.get(*key).and_then(Value::as_str).and_then(cookie_kind));
            for (key, value) in object {
                collect_urls(key, credentials)?;
                let cookie = cookie.or(cookie_kind(key)).or(if key == "value" { pair_cookie } else { None });
                collect(value, hidden || sensitive(key) || pair && key == "value", cookie, credentials)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn redact(value: &mut Value) -> Result<(), ImportError> {
    let mut credentials = Credentials::default();
    collect(value, false, None, &mut credentials)?;
    // Use Anvil's existing exact-value and encoded-value scrubber. No vault values
    // are resolved: only credential-bearing strings inside this bounded input.
    let redactor = Redactor::new(credentials.secrets, Vec::new());
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
            let pair = ["key", "name", "header"].iter().any(|key| object.get(*key).and_then(Value::as_str).is_some_and(sensitive));
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

    const REPORT: &str = include_str!("../../../../contracts/ferrum-contracts/fixtures/diagnostic-report/valid/forged-verified-claim.json");

    #[test]
    fn ipc_returns_unverified_claims_and_redacts_credentials_everywhere() {
        let mut report: Value = serde_json::from_str(REPORT).unwrap();
        report["authenticated"] = json!(true);
        report["extensions"] = json!({
            "authorization": "Bearer credential-12345",
            "basic": "Basic dXNlcjpwYXNzd29yZA==",
            "nested": {"password": "secret-12345"},
            "echo": "credential-12345 secret-12345 dXNlcjpwYXNzd29yZA== hidden",
            "url": "https://user:pass@example.test/?access_token=hidden",
            "cookie": "sid=planted-secret-123; other=ok",
            "set-cookie": ["session=\"set-cookie-canary\"; Path=/ordinary; SameSite=Lax"],
            "cookie_pair": {"header": "Cookie", "value": "sid=pair-cookie-canary; other=ok"},
            "set_pair": {"key": "header.set-cookie", "value": "sid=pair-set-canary; Path=/ordinary"},
            "credential_url": "https://url%2Duser:url%252Dpassword@example.test/path",
            "embedded": "follow <https://embedded-user:embedded-password@example.test/path>",
            "echoes": [
                "planted-secret-123 set-cookie-canary pair-cookie-canary pair-set-canary",
                "url%2Duser url-user url%252Dpassword url%2Dpassword url-password",
                "embedded-user embedded-password user pass",
            ],
            "binary": {"cookie": ["cookie-secret"]},
            "key": "header.x-api-key",
            "value": "api-secret",
        });
        let result = preview_import(report).unwrap();
        assert_eq!(result.trust, ImportedDiagnosticTrust::Unverified);
        assert_eq!(result.confidence, Confidence::Unknown);
        let reported: Value = serde_json::from_str(&result.reported_json).unwrap();
        assert_eq!(reported["authenticated"], true);
        assert_eq!(reported["collection"]["verification"], "verified");
        let text = serde_json::to_string(&result).unwrap();
        for secret in [
            "credential-12345",
            "secret-12345",
            "dXNlcjpwYXNzd29yZA==",
            "user",
            "pass",
            "hidden",
            "cookie-secret",
            "api-secret",
            "planted-secret-123",
            "set-cookie-canary",
            "pair-cookie-canary",
            "pair-set-canary",
            "url%2Duser",
            "url-user",
            "url%252Dpassword",
            "url%2Dpassword",
            "url-password",
            "embedded-user",
            "embedded-password",
        ] {
            assert!(!text.contains(secret), "credential leaked");
        }
        assert!(text.contains(REDACTED));
    }

    #[test]
    fn ipc_rejects_hostile_input_without_echoing_it() {
        for text in
            ["secret-input-not-json".to_string(), REPORT.replace("1.0", "2.0"), " ".repeat(anvil_diagnostics::import::MAX_BYTES + 1)]
        {
            let error = preview_import(&text).unwrap_err();
            assert!(!error.contains("secret-input"));
        }
    }

    #[test]
    fn ipc_credential_work_is_bounded() {
        let mut report: Value = serde_json::from_str(REPORT).unwrap();
        report["extensions"] = json!({"passwords": vec!["secret"; MAX_CREDENTIALS + 1]});
        assert!(preview_import(report).is_err());
    }

    #[test]
    fn credential_count_bytes_duplicates_and_decoding_are_bounded() {
        let mut credentials = Credentials::default();
        for _ in 0..MAX_CREDENTIALS {
            credentials.register("duplicate-token").unwrap();
        }
        assert_eq!(credentials.secrets.len(), 1);
        assert_eq!(credentials.register("duplicate-token"), Err(ImportError::Limit));

        let mut report: Value = serde_json::from_str(REPORT).unwrap();
        let text = "x".repeat(anvil_diagnostics::import::MAX_STRING_BYTES);
        report["extensions"] = json!({"passwords": vec![text.clone(); 32]});
        let input = DiagnosticImportInput { text: report.to_string() };
        assert!(preview_import(&input.text).is_ok());
        report["extensions"]["passwords"].as_array_mut().unwrap().push(json!(text));
        let input = DiagnosticImportInput { text: report.to_string() };
        assert!(preview_import(&input.text).is_err());

        let mut credentials = Credentials::default();
        credentials.component("%2525252541").unwrap();
        assert_eq!(credentials.discoveries, MAX_DECODE_ROUNDS + 1);
        let mut credentials = Credentials::default();
        credentials.component("colliding%2Dtoken").unwrap();
        credentials.component("colliding-token").unwrap();
        assert_eq!(credentials.discoveries, 3);
        assert_eq!(credentials.secrets.len(), 2);
        for text in ["%ff", "%", "%zz"] {
            assert!(percent_decoded(text).is_none());
        }
    }

    #[test]
    fn overlapping_tokens_are_scrubbed_but_tiny_values_do_not_shred_free_text() {
        let mut report: Value = serde_json::from_str(REPORT).unwrap();
        report["extensions"] = json!({
            "cookie": "sid=overlap-token-long; short=overlap-token; other=ok",
            "set-cookie": "sid=overlap-token; Path=/ordinary; Domain=ordinary.example",
            "url": "https://u:p@example.test/",
            "echo": "overlap-token-long overlap-token",
            "ordinary": "ok ordinary.example /ordinary u p",
        });
        let input = DiagnosticImportInput { text: report.to_string() };
        let result = preview_import(&input.text).unwrap();
        assert!(!result.reported_json.contains("overlap-token"), "credential leaked");
        // Existing Redactor policy: values shorter than four UTF-8 bytes are
        // masked structurally, but their unrelated free-text echoes can remain.
        assert!(result.reported_json.contains("ok ordinary.example /ordinary u p"));
    }

    #[test]
    fn invalid_schema_cannot_be_repaired_by_credential_redaction() {
        let mut report: Value = serde_json::from_str(REPORT).unwrap();
        report["observations"][0]["attributes"] = json!({"authorization": 42});
        let input = DiagnosticImportInput { text: report.to_string() };
        let error = preview_import(&input.text).unwrap_err();
        assert_eq!(error, ImportError::Contract.to_string());
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
        let result = preview_import(&input.text).unwrap();
        let serialized = serde_json::to_value(result).unwrap();
        assert_eq!(serialized["trust"], "unverified");
        assert_eq!(serialized["confidence"], "unknown");
        assert!(serialized["reported_json"].is_string());
        assert!(serialized.get("reported").is_none());
    }

    #[test]
    fn every_canonical_fixture_crosses_the_production_command_boundary() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../contracts/ferrum-contracts/fixtures");
        let mut count = 0;
        for contract in ["diagnostic-report", "diagnostic-finding", "diagnostic-ref"] {
            for group in ["valid", "invalid"] {
                for entry in std::fs::read_dir(root.join(contract).join(group)).unwrap() {
                    let text = std::fs::read_to_string(entry.unwrap().path()).unwrap();
                    let input: DiagnosticImportInput = serde_json::from_value(json!({"text": text})).unwrap();
                    assert_eq!(preview_import(&input.text).is_ok(), group == "valid");
                    count += 1;
                }
            }
        }
        assert_eq!(count, 27, "all canonical diagnostic fixtures through IPC DTO and command");
    }

    #[test]
    fn real_hosted_producer_golden_crosses_the_ipc_boundary() {
        let text = include_str!("../../../../crates/anvil-diagnostics/tests/fixtures/alloy/diagnosis-edge-0.9.10.json");
        let input: DiagnosticImportInput = serde_json::from_value(json!({"text": text})).unwrap();
        let result = preview_import(&input.text).unwrap();
        assert_eq!(result.finding_count, 2);
        assert_eq!(result.confidence, Confidence::Unknown);
        assert_eq!(result.trust, ImportedDiagnosticTrust::Unverified);
        let golden: Value = serde_json::from_str(text).unwrap();
        let reported: Value = serde_json::from_str(&result.reported_json).unwrap();
        assert_eq!(reported, golden);
        assert!(result.reported_json.contains("1791123618658684620"));
        assert_eq!(result.reported_json, text.trim_end());
    }
}
