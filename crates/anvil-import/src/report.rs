//! The import report: everything the importer did not (or must not) turn
//! into active workspace objects, each with a location in the source.
//!
//! Locations (`pointer`) are RFC 6901 JSON Pointers into the parsed
//! JSON/YAML document. For WSDL they are element paths such as
//! `/definitions/binding[@name='QuoteSoap']/operation[@name='GetQuote']`;
//! for cURL they point into the argument vector (`/args/3`).

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// A located observation about the source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Finding {
    /// Stable machine code (`recursive_schema`, `external_ref`, …).
    pub code: String,
    pub pointer: String,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExternalRefKind {
    /// Relative or absolute file path (including `file:` URIs).
    File,
    /// `http:`/`https:` URL.
    Url,
    /// Any other URI scheme or an unresolvable identifier (`$id`, `urn:`).
    Other,
}

/// A reference to content outside the imported document. Never fetched or
/// read by this crate; resolving it requires an explicit, per-reference user
/// approval (build plan §11, failure case DATA-009).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ExternalRef {
    /// The reference exactly as written (`common.yaml#/Pet`, `https://…/types.xsd`).
    pub reference: String,
    pub kind: ExternalRefKind,
    /// Every location that uses the reference.
    pub pointers: Vec<String>,
    /// Always `true`: background resolution is a different trust boundary.
    pub requires_approval: bool,
}

/// A script found in the source. Retained verbatim for review; never
/// executed, and not attached to any request as runnable code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RetainedScript {
    pub pointer: String,
    /// Name of the collection/folder/request that owned the script.
    pub owner: String,
    /// `prerequest`, `test`, `after_response`, `unit_test`, …
    pub event: String,
    pub language: String,
    pub source: String,
    /// Always `false`: imported scripts are disabled until trusted.
    pub enabled: bool,
    /// Always `false`: trust is a separate, explicit user decision.
    pub trusted: bool,
}

/// An imported setting that would weaken safety or cause automatic traffic
/// (TLS verification bypass, auto-run scripts, load plans, callback URLs,
/// cross-origin credential forwarding). Represented here only — never
/// applied to the imported objects (failure case DATA-008).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct InactiveSetting {
    pub pointer: String,
    /// e.g. `tls.verify`, `callback`, `redirects.forward_credentials_cross_origin`.
    pub setting: String,
    /// The value found in the source (credentials are never copied here).
    pub value: String,
    pub reason: String,
}

/// A credential that was replaced by a `{{placeholder}}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Redaction {
    pub pointer: String,
    /// Human description of the field (`header Authorization`, `query api_key`).
    pub field: String,
    /// The variable reference that replaced the value (`{{authorization}}`).
    pub placeholder: String,
}

/// A variable the imported requests reference but the import deliberately
/// does not define (credentials, path parameters in blank mode, hosts that
/// the source leaves relative). Unresolved variables fail request validation
/// until the user supplies them, so nothing is sent with an invented value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RequiredVariable {
    pub name: String,
    pub secret: bool,
    pub reason: String,
    pub pointers: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ImportCounts {
    /// Operations/requests/entries found in the source.
    pub operations_found: usize,
    pub requests: usize,
    pub folders: usize,
    pub environments: usize,
    /// Operations not imported because of `max_operations` or because they
    /// are unsupported (see `unsupported`).
    pub skipped_operations: usize,
    pub refs_resolved: usize,
    pub warnings: usize,
    pub unsupported: usize,
    pub external_refs: usize,
    pub scripts: usize,
    pub inactive_settings: usize,
    pub redactions: usize,
    pub required_variables: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ImportReport {
    /// Imported with a caveat (recursion cut, composition branch chosen,
    /// constraint not guaranteed, alternative ignored, …).
    pub warnings: Vec<Finding>,
    /// Present in the source but not imported or not represented.
    pub unsupported: Vec<Finding>,
    pub external_refs: Vec<ExternalRef>,
    pub scripts: Vec<RetainedScript>,
    pub inactive_settings: Vec<InactiveSetting>,
    pub redactions: Vec<Redaction>,
    pub required_variables: Vec<RequiredVariable>,
    pub counts: ImportCounts,
    #[serde(skip)]
    #[schemars(skip)]
    seen: Seen,
}

/// De-duplication index for findings. Not part of the report's value:
/// always compares equal and is never serialized.
#[derive(Debug, Clone, Default)]
struct Seen(HashSet<(String, String)>);

impl PartialEq for Seen {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}

impl Eq for Seen {}

impl Seen {
    fn insert(&mut self, k: (String, String)) -> bool {
        self.0.insert(k)
    }
}

impl ImportReport {
    /// Record a warning once per (code, pointer).
    pub fn warn(&mut self, code: &str, pointer: &str, message: impl Into<String>) {
        if self.seen.insert((code.to_string(), pointer.to_string())) {
            self.warnings.push(Finding { code: code.into(), pointer: pointer.into(), message: message.into() });
        }
    }

    /// Record an unsupported construct once per (code, pointer).
    pub fn unsupported(&mut self, code: &str, pointer: &str, message: impl Into<String>) {
        if self.seen.insert((format!("u:{code}"), pointer.to_string())) {
            self.unsupported.push(Finding { code: code.into(), pointer: pointer.into(), message: message.into() });
        }
    }

    pub fn external_ref(&mut self, reference: &str, pointer: &str) {
        if let Some(e) = self.external_refs.iter_mut().find(|e| e.reference == reference) {
            if !e.pointers.iter().any(|p| p == pointer) {
                e.pointers.push(pointer.to_string());
            }
            return;
        }
        let lower = reference.to_ascii_lowercase();
        let kind = if lower.starts_with("http://") || lower.starts_with("https://") {
            ExternalRefKind::Url
        } else if lower.starts_with("file:") || !lower.contains(':') || lower.starts_with("./") || lower.starts_with("../") {
            ExternalRefKind::File
        } else {
            ExternalRefKind::Other
        };
        self.external_refs.push(ExternalRef {
            reference: reference.to_string(),
            kind,
            pointers: vec![pointer.to_string()],
            requires_approval: true,
        });
    }

    pub fn script(&mut self, pointer: &str, owner: &str, event: &str, language: &str, source: String) {
        self.scripts.push(RetainedScript {
            pointer: pointer.into(),
            owner: owner.into(),
            event: event.into(),
            language: language.into(),
            source,
            enabled: false,
            trusted: false,
        });
    }

    pub fn inactive(&mut self, pointer: &str, setting: &str, value: &str, reason: impl Into<String>) {
        self.inactive_settings.push(InactiveSetting {
            pointer: pointer.into(),
            setting: setting.into(),
            value: value.into(),
            reason: reason.into(),
        });
    }

    pub fn redacted(&mut self, pointer: &str, field: impl Into<String>, placeholder: &str) {
        self.redactions.push(Redaction { pointer: pointer.into(), field: field.into(), placeholder: placeholder.into() });
    }

    /// Declare a variable that must be supplied by the user.
    pub fn require_var(&mut self, name: &str, secret: bool, reason: &str, pointer: &str) {
        if let Some(v) = self.required_variables.iter_mut().find(|v| v.name == name) {
            v.secret |= secret;
            if !v.pointers.iter().any(|p| p == pointer) {
                v.pointers.push(pointer.to_string());
            }
            return;
        }
        self.required_variables.push(RequiredVariable {
            name: name.into(),
            secret,
            reason: reason.into(),
            pointers: vec![pointer.to_string()],
        });
    }

    pub fn has_code(&self, code: &str) -> bool {
        self.warnings.iter().chain(self.unsupported.iter()).any(|f| f.code == code)
    }

    pub(crate) fn finalize_counts(&mut self) {
        let c = &mut self.counts;
        c.warnings = self.warnings.len();
        c.unsupported = self.unsupported.len();
        c.external_refs = self.external_refs.len();
        c.scripts = self.scripts.len();
        c.inactive_settings = self.inactive_settings.len();
        c.redactions = self.redactions.len();
        c.required_variables = self.required_variables.len();
    }
}
