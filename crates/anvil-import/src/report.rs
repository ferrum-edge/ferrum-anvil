//! The import report: everything the importer did not (or must not) turn
//! into active workspace objects, each with a location in the source.
//!
//! Locations (`pointer`) are RFC 6901 JSON Pointers into the parsed
//! JSON/YAML document. For WSDL they are element paths such as
//! `/definitions/binding[@name='QuoteSoap']/operation[@name='GetQuote']`;
//! for cURL they point into the argument vector (`/args/3`).

use crate::util::{clip, fnv1a64};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Findings of one code kept in a report; the rest are counted in a single
/// `report_truncated` warning. Pointers and messages are clipped, so the
/// report stays bounded however many locations an input repeats.
const MAX_FINDINGS_PER_CODE: usize = 1_000;
/// Locations kept per external reference or required variable.
const MAX_POINTERS_PER_ENTRY: usize = 1_000;
/// Inactive settings, redactions and retained scripts kept per report.
const MAX_ENTRIES: usize = 10_000;
/// Characters kept of a stored pointer.
const MAX_POINTER_CHARS: usize = 512;
/// Characters kept of a stored message or value.
const MAX_TEXT_CHARS: usize = 2_048;

/// `s` as stored in a report: whole when short, clipped otherwise (the
/// clip looks at no more than `max` characters).
fn bounded(s: &str, max: usize) -> String {
    if s.len() <= max { s.to_string() } else { clip(s, max) }
}

/// A pointer as stored in a report: whole when short; otherwise clipped and
/// suffixed with a hash of the whole pointer, so distinct long pointers stay
/// distinct (for de-duplication too).
fn bounded_pointer(p: &str) -> String {
    if p.len() <= MAX_POINTER_CHARS { p.to_string() } else { format!("{}#{:016x}", clip(p, MAX_POINTER_CHARS), fnv1a64(p)) }
}

/// [`bounded`] for text that is already owned.
fn bounded_owned(s: String, max: usize) -> String {
    if s.len() <= max { s } else { clip(&s, max) }
}

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

/// De-duplication and lookup indexes. Not part of the report's value:
/// always compares equal and is never serialized.
#[derive(Debug, Clone, Default)]
struct Seen {
    /// (code, clipped pointer) of every finding kept.
    findings: HashSet<(String, String)>,
    /// Findings kept per code (`u:` prefix for unsupported ones).
    per_code: HashMap<String, usize>,
    /// External reference → its index in `external_refs` and its pointers.
    refs: HashMap<String, (usize, HashSet<String>)>,
    /// Required variable name → its index in `required_variables` and its pointers.
    vars: HashMap<String, (usize, HashSet<String>)>,
    /// Redactions made, including those past the list's limit.
    redactions: usize,
}

impl PartialEq for Seen {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}

impl Eq for Seen {}

impl Seen {
    /// Whether a finding of `key` (its code) at `pointer` is new, and
    /// whether its code still has room for it.
    fn admit(&mut self, key: &str, pointer: &str) -> Admit {
        if self.findings.contains(&(key.to_string(), pointer.to_string())) {
            return Admit::Known;
        }
        let n = self.per_code.entry(key.to_string()).or_insert(0);
        *n += 1;
        if *n > MAX_FINDINGS_PER_CODE {
            return if *n == MAX_FINDINGS_PER_CODE + 1 { Admit::Truncate } else { Admit::Dropped };
        }
        self.findings.insert((key.to_string(), pointer.to_string()));
        Admit::Keep
    }
}

enum Admit {
    Keep,
    Known,
    /// The first finding over the code's limit: note the truncation.
    Truncate,
    Dropped,
}

impl ImportReport {
    /// Record a warning once per (code, pointer).
    pub fn warn(&mut self, code: &str, pointer: &str, message: impl Into<String>) {
        let pointer = bounded_pointer(pointer);
        match self.seen.admit(code, &pointer) {
            Admit::Keep => {
                let message = bounded_owned(message.into(), MAX_TEXT_CHARS);
                self.warnings.push(Finding { code: code.into(), pointer, message });
            }
            Admit::Truncate => self.truncated(code),
            Admit::Known | Admit::Dropped => {}
        }
    }

    /// Record an unsupported construct once per (code, pointer).
    pub fn unsupported(&mut self, code: &str, pointer: &str, message: impl Into<String>) {
        let pointer = bounded_pointer(pointer);
        match self.seen.admit(&format!("u:{code}"), &pointer) {
            Admit::Keep => {
                let message = bounded_owned(message.into(), MAX_TEXT_CHARS);
                self.unsupported.push(Finding { code: code.into(), pointer, message });
            }
            Admit::Truncate => self.truncated(code),
            Admit::Known | Admit::Dropped => {}
        }
    }

    /// Note, once per kind, that entries of that kind were left out.
    fn truncated(&mut self, code: &str) {
        if !self.seen.findings.insert(("report_truncated".into(), code.to_string())) {
            return;
        }
        self.warnings.push(Finding {
            code: "report_truncated".into(),
            pointer: "/".into(),
            message: format!("more than {MAX_FINDINGS_PER_CODE} '{}' findings; the rest are not listed", clip(code, 64)),
        });
    }

    pub fn external_ref(&mut self, reference: &str, pointer: &str) {
        let pointer = bounded_pointer(pointer);
        if let Some((i, seen)) = self.seen.refs.get_mut(reference) {
            let e = &mut self.external_refs[*i];
            if e.pointers.len() < MAX_POINTERS_PER_ENTRY && seen.insert(pointer.clone()) {
                e.pointers.push(pointer);
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
        self.seen.refs.insert(reference.to_string(), (self.external_refs.len(), HashSet::from([pointer.clone()])));
        self.external_refs.push(ExternalRef { reference: reference.to_string(), kind, pointers: vec![pointer], requires_approval: true });
    }

    pub fn script(&mut self, pointer: &str, owner: &str, event: &str, language: &str, source: String) {
        if self.scripts.len() >= MAX_ENTRIES {
            return self.truncated("script");
        }
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
        if self.inactive_settings.len() >= MAX_ENTRIES {
            return self.truncated("inactive_setting");
        }
        self.inactive_settings.push(InactiveSetting {
            pointer: bounded_pointer(pointer),
            setting: bounded(setting, MAX_TEXT_CHARS),
            value: bounded(value, MAX_TEXT_CHARS),
            reason: bounded_owned(reason.into(), MAX_TEXT_CHARS),
        });
    }

    pub fn redacted(&mut self, pointer: &str, field: impl Into<String>, placeholder: &str) {
        self.seen.redactions += 1;
        if self.redactions.len() >= MAX_ENTRIES {
            return self.truncated("redaction");
        }
        self.redactions.push(Redaction { pointer: bounded_pointer(pointer), field: field.into(), placeholder: placeholder.into() });
    }

    /// Declare a variable that must be supplied by the user.
    pub fn require_var(&mut self, name: &str, secret: bool, reason: &str, pointer: &str) {
        let pointer = bounded_pointer(pointer);
        if let Some((i, seen)) = self.seen.vars.get_mut(name) {
            let v = &mut self.required_variables[*i];
            v.secret |= secret;
            if v.pointers.len() < MAX_POINTERS_PER_ENTRY && seen.insert(pointer.clone()) {
                v.pointers.push(pointer);
            }
            return;
        }
        self.seen.vars.insert(name.to_string(), (self.required_variables.len(), HashSet::from([pointer.clone()])));
        self.required_variables.push(RequiredVariable { name: name.into(), secret, reason: reason.into(), pointers: vec![pointer] });
    }

    /// Redactions made so far, however many the list keeps: what an importer
    /// compares to learn whether a value it scrubbed changed.
    pub(crate) fn redactions_made(&self) -> usize {
        self.seen.redactions
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
        c.redactions = self.seen.redactions;
        c.required_variables = self.required_variables.len();
    }
}
