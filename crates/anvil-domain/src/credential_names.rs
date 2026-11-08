//! Field names Anvil treats as credentials: one source for the engine's
//! redactor and redirect rule (`anvil_engine::redact`), the importer
//! (`anvil_import::util`) and the bundle export sanitizer
//! (`anvil_portability::sanitize`).
//!
//! Each consumer keeps its own rule over these lists (the redactor caps
//! substring matches by length, the importer leaves pagination tokens out),
//! but the export sanitizer's rule, [`is_export_secret_name`], is the union of
//! all of them: a literal under any name another part of Anvil would treat as
//! a credential never stays in a bundle's readable `objects.json`.

/// Header names the engine always treats as secrets (redaction, and
/// credentials a cross-origin redirect does not carry).
pub const ENGINE_SENSITIVE_HEADERS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "api-key",
    "apikey",
    "x-auth-token",
    "x-access-token",
    "x-amz-security-token",
    "x-csrf-token",
    "dpop",
    "x-functions-key",
    "ocp-apim-subscription-key",
];

/// Name fragments the engine treats as secrets.
pub const ENGINE_SENSITIVE_NAME_PARTS: &[&str] = &[
    "password",
    "passwd",
    "secret",
    "token",
    "apikey",
    "api_key",
    "api-key",
    "access_key",
    "private_key",
    "signature",
    "sig",
    "session",
    "credential",
    "auth",
];

/// Header names the importer treats as carrying credentials or session state.
pub const IMPORT_CREDENTIAL_HEADERS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "api-key",
    "apikey",
    "x-auth-token",
    "x-access-token",
    "x-amz-security-token",
    "x-csrf-token",
    "x-xsrf-token",
    "x-goog-api-key",
    "dpop",
    "x-functions-key",
    "ocp-apim-subscription-key",
    "x-session-token",
    "x-refresh-token",
];

/// Name fragments the importer treats as credential-like.
pub const IMPORT_CREDENTIAL_PARTS: &[&str] = &[
    "password",
    "passwd",
    "passphrase",
    "secret",
    "token",
    "apikey",
    "api_key",
    "api-key",
    "access_key",
    "accesskey",
    "private_key",
    "privatekey",
    "client_secret",
    "credential",
    "session",
    "signature",
    "authorization",
];

/// Exact names (after lowercasing) the importer treats as credential-like
/// even though they are short (`sig`, `key`, `pwd`, `auth`, `code`-style
/// OAuth values).
pub const IMPORT_CREDENTIAL_EXACT: &[&str] = &["sig", "key", "pwd", "pass", "auth", "otp", "pin", "jwt", "sid", "code_verifier"];

/// Name fragments only the export sanitizer had: they stay in its rule.
const EXPORT_NAME_PARTS: &[&str] = &["cookie", "private", "x-api-key"];

/// Whether a header, query parameter, form field or variable named `name`
/// holds a secret for a workspace export: the union of every rule above, the
/// `-key` / `_key` suffix of the engine's redirect-credential rule
/// (`X-Master-Key`, `Subscription-Key`, `tenant_key`), and the user's extra
/// redaction names (`AppSettings::redaction_names`), compared ignoring ASCII
/// case and surrounding whitespace.
///
/// It deliberately errs towards extraction: an extracted value travels in
/// the encrypted vault (encrypted transfer) or becomes a `{{placeholder}}`
/// the recipient fills in (share safely), so a name matched by mistake costs
/// a placeholder, while a credential missed is disclosed. Pagination tokens,
/// which the importer leaves out, are therefore extracted too.
pub fn is_export_secret_name(name: &str, extra: &[String]) -> bool {
    let n = name.trim().to_ascii_lowercase();
    if n.is_empty() {
        return false;
    }
    if extra.iter().any(|e| e.trim().eq_ignore_ascii_case(&n)) {
        return true;
    }
    let listed = |list: &[&str]| list.contains(&n.as_str());
    if listed(ENGINE_SENSITIVE_HEADERS) || listed(IMPORT_CREDENTIAL_HEADERS) || listed(IMPORT_CREDENTIAL_EXACT) {
        return true;
    }
    let part = |list: &[&str]| list.iter().any(|p| n.contains(p));
    part(ENGINE_SENSITIVE_NAME_PARTS)
        || part(IMPORT_CREDENTIAL_PARTS)
        || part(EXPORT_NAME_PARTS)
        || n.ends_with("-key")
        || n.ends_with("_key")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_listed_name_is_an_export_secret() {
        for list in [
            ENGINE_SENSITIVE_HEADERS,
            ENGINE_SENSITIVE_NAME_PARTS,
            IMPORT_CREDENTIAL_HEADERS,
            IMPORT_CREDENTIAL_PARTS,
            IMPORT_CREDENTIAL_EXACT,
            EXPORT_NAME_PARTS,
        ] {
            for n in list {
                assert!(is_export_secret_name(n, &[]), "{n}");
                assert!(is_export_secret_name(&n.to_ascii_uppercase(), &[]), "{n}");
            }
        }
    }

    #[test]
    fn the_names_the_advisory_lists_are_export_secrets() {
        for n in [
            "Ocp-Apim-Subscription-Key",
            "X-Functions-Key",
            "DPoP",
            "X-Master-Key",
            "Subscription-Key",
            "X-Auth-Key",
            "DD-Application-Key",
            "tenant_key",
            "aws_access_key_id",
            "X-Auth-User",
            "key",
            "sig",
            "pwd",
            "pass",
            "otp",
            "pin",
            " Key ",
        ] {
            assert!(is_export_secret_name(n, &[]), "{n}");
        }
    }

    #[test]
    fn extra_redaction_names_are_export_secrets() {
        let extra = vec!["X-Customer-Ssn".to_string(), " tenant ".to_string()];
        assert!(is_export_secret_name("x-customer-ssn", &extra));
        assert!(is_export_secret_name("Tenant", &extra));
        assert!(!is_export_secret_name("x-customer-ssn", &[]));
    }

    #[test]
    fn ordinary_names_are_not() {
        for n in ["Accept", "Content-Type", "X-Request-Id", "page", "limit", "X-Keyboard", "keyword", "monkey", "", "  "] {
            assert!(!is_export_secret_name(n, &[]), "{n:?}");
        }
    }
}
