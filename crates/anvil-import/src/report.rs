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

/// A pointer as stored in a report: whole when short; otherwise clipped and
/// suffixed with a hash of the whole pointer, so distinct long pointers stay
/// distinct (for de-duplication too).
fn bounded_pointer(p: &str) -> String {
    let redacted = redact_pointer(p);
    let p = redacted.as_str();
    if p.len() <= MAX_POINTER_CHARS { p.to_string() } else { format!("{}#{:016x}", clip(p, MAX_POINTER_CHARS), fnv1a64(p)) }
}

/// A pointer with each reference token ([RFC 6901]: `~1` is `/`, `~0` is
/// `~`) redacted like report text ([`redact_for_report`]): a source key
/// (a header name, a settings key) can hold a credential URL or literal. A
/// token that changes keeps a digest of the original, so distinct
/// locations stay distinct.
///
/// [RFC 6901]: https://www.rfc-editor.org/rfc/rfc6901
fn redact_pointer(p: &str) -> String {
    if !p.contains(['~', '{', '@', ':', '=', ' ']) {
        return p.to_string();
    }
    p.split('/')
        .map(|token| {
            let decoded = token.replace("~1", "/").replace("~0", "~");
            let redacted = redact_for_report(&decoded);
            if redacted == decoded {
                token.to_string()
            } else {
                format!("{}#{:08x}", redacted.replace('~', "~0").replace('/', "~1"), fnv1a64(token) as u32)
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// `s` as stored in a report: whole when short, clipped otherwise (the
/// clip looks at no more than `max` characters).
fn bounded_owned(s: String, max: usize) -> String {
    if s.len() <= max { s } else { clip(&s, max) }
}

/// Text as it may appear in a report: every string an importer puts in a
/// finding, inactive setting, redaction, required variable or external
/// reference goes through this first (the report is shown in the preview
/// and may be logged, whatever `include_credentials` says).
///
/// - URL userinfo, by the importers' rule
///   ([`anvil_domain::secret::url_userinfo`], strict syntax), at every
///   `://`: a userinfo that is not exactly references becomes `<redacted>`,
///   and an ambiguous URL (a template before the end of its authority and an
///   `@` after it) is replaced, through the word holding the text's last
///   `@`, by `<url redacted>`.
/// - Template expressions: a `{{…}}` that is not a plain name (an
///   identifier or dotted path, or an argument-free `$helper`) is literal
///   text, possibly a credential, and is replaced, through the text's last
///   `}}` (a quoted `}}` cannot end it early), by `{{…}}`; an unterminated
///   `{{` hides the rest of the text.
///
/// Over-redaction is preferred: the finding's pointer locates the source.
/// Linear in the text.
pub fn redact_for_report(text: &str) -> String {
    redact_credential_text(&redact_expressions(&redact_urls(text)))
}

/// The credential-name heuristics of [`redact_for_report`], for text that is
/// not a URL or a template: the value of a `name=value` or `name: value`
/// pair whose name is a credential name ([`crate::util::is_credential_name`]),
/// quoted (`"password": "…"`) or not, the token after an auth scheme word
/// (`Bearer …`, `Basic …`) when it looks like one (16 characters, or 8 with
/// both letters and digits), and a JWT, each become `<redacted>`. A value
/// that is a `{{…}}` reference (or one already redacted) or a plain word
/// (`none`, `true`, …) is kept. When a credential-named pair's value is an
/// auth scheme word (`Authorization: Bearer …`), the token after it is part
/// of the value.
///
/// Strictly linear: a name is looked for at most 128 bytes back, every
/// inspected value is skipped once inspected, and a word, token or JWT span
/// is scanned a bounded number of times.
fn redact_credential_text(text: &str) -> String {
    let bytes = text.as_bytes();
    let name_byte = |c: u8| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.');
    let token_byte = |c: u8| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.' | b'~' | b'+' | b'/' | b'=');
    // Where the next value terminator is at or after a position: one cache
    // per terminator kind, so values that start inside a span already
    // searched reuse the answer and no byte is searched twice.
    let unquoted_end = |c: char| c.is_whitespace() || matches!(c, '&' | ',' | ';' | '"' | '\'' | '}' | ']' | ')' | '>' | '`');
    let mut cached: [Option<(usize, usize)>; 3] = [None; 3];
    let mut next_end = |kind: usize, from: usize| -> usize {
        if let Some((searched, found)) = cached[kind]
            && searched <= from
            && from <= found
        {
            return found;
        }
        let rest = &text[from..];
        let found = from
            + match kind {
                0 => rest.find(unquoted_end),
                1 => rest.find('"'),
                _ => rest.find('\''),
            }
            .unwrap_or(rest.len());
        cached[kind] = Some((from, found));
        found
    };
    let scheme = |word: &str| word.len() <= 6 && matches!(word.to_ascii_lowercase().as_str(), "bearer" | "basic" | "token" | "digest");
    let mut cuts: Vec<(usize, usize)> = vec![];
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        // `name=value` / `name: value` (not the `:` of a `scheme://`).
        if (c == b'=' || c == b':') && !bytes[i..].starts_with(b"://") {
            let mut end = i;
            while end > 0 && i - end < 8 && bytes[end - 1] == b' ' {
                end -= 1;
            }
            if end > 0 && matches!(bytes[end - 1], b'"' | b'\'') {
                end -= 1;
            }
            let floor = end.saturating_sub(128);
            let mut start = end;
            while start > floor && name_byte(bytes[start - 1]) {
                start -= 1;
            }
            let mut v = i + 1;
            while v < bytes.len() && v - i <= 8 && bytes[v] == b' ' {
                v += 1;
            }
            if start < end && v < bytes.len() && crate::util::is_credential_name(&text[start..end]) {
                let (from, mut to) = match bytes[v] {
                    b'"' => (v + 1, next_end(1, v + 1)),
                    b'\'' => (v + 1, next_end(2, v + 1)),
                    _ => (v, next_end(0, v)),
                };
                let value = &text[from..to];
                let word = value.len() <= 7
                    && matches!(value.to_ascii_lowercase().as_str(), "none" | "null" | "true" | "false" | "inherit" | "off" | "on");
                // `Authorization: Bearer <token>`: the token after the scheme
                // is part of the value.
                if scheme(value) && to < bytes.len() && bytes[to] == b' ' {
                    let t = to + 1;
                    let t_end = (t..bytes.len()).find(|&k| !token_byte(bytes[k])).unwrap_or(bytes.len());
                    if t_end > t {
                        to = t_end;
                    }
                }
                if !value.is_empty() && !word && !value.starts_with("{{") && !value.starts_with('<') {
                    cuts.push((from, to));
                }
                // Past the value either way: nothing inspected is scanned
                // again.
                i = to.max(i + 1);
                continue;
            }
        }
        // `Bearer <token>` and a JWT, at the start of a word.
        if c.is_ascii_alphabetic() && (i == 0 || !name_byte(bytes[i - 1])) {
            let word_end = (i..bytes.len()).find(|&k| !bytes[k].is_ascii_alphabetic()).unwrap_or(bytes.len());
            if scheme(&text[i..word_end]) && word_end < bytes.len() && bytes[word_end] == b' ' {
                let t = word_end + 1;
                let t_end = (t..bytes.len()).find(|&k| !token_byte(bytes[k])).unwrap_or(bytes.len());
                let token = &text[t..t_end];
                let digits = token.bytes().any(|b| b.is_ascii_digit());
                let letters = token.bytes().any(|b| b.is_ascii_alphabetic());
                if token.len() >= 16 || (token.len() >= 8 && digits && letters) {
                    cuts.push((t, t_end));
                    i = t_end;
                    continue;
                }
            }
            if text[i..].starts_with("eyJ") {
                // The JWT alphabet (base64url and dots) is all name bytes, so
                // no later word starts inside a span scanned here.
                let t_end = (i..bytes.len())
                    .find(|&k| !(bytes[k].is_ascii_alphanumeric() || matches!(bytes[k], b'_' | b'-' | b'.')))
                    .unwrap_or(bytes.len());
                if t_end - i >= 20 && text[i..t_end].matches('.').count() >= 2 {
                    cuts.push((i, t_end));
                    i = t_end;
                    continue;
                }
            }
            i = word_end.max(i + 1);
            continue;
        }
        i += 1;
    }
    if cuts.is_empty() {
        return text.to_string();
    }
    let mut out = String::with_capacity(text.len());
    let mut copied = 0;
    for (from, to) in cuts {
        debug_assert!(from >= copied);
        out.push_str(&text[copied..from]);
        out.push_str("<redacted>");
        copied = to;
    }
    out.push_str(&text[copied..]);
    out
}

fn redact_urls(text: &str) -> String {
    use anvil_domain::secret::{TemplateSyntax, UrlUserinfo, is_plain_userinfo, url_userinfo};
    let Some(last_at) = text.rfind('@') else { return text.to_string() };
    let word_end =
        |from: usize| text[from..].find(|c: char| c.is_whitespace() || matches!(c, '\'' | '"' | '`')).map_or(text.len(), |e| from + e);
    let scheme_char = |c: char| c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '-' | '_' | '{' | '}' | '$');
    let mut out = String::with_capacity(text.len());
    let mut copied = 0;
    let mut from = 0;
    while let Some(found) = text[from..].find("://") {
        let sep = from + found;
        if sep >= last_at {
            break;
        }
        let start = text[copied..sep].char_indices().rev().take_while(|&(_, c)| scheme_char(c)).last().map_or(sep, |(i, _)| copied + i);
        let url = &text[start..];
        match url_userinfo(url, TemplateSyntax::Nunjucks) {
            UrlUserinfo::None => from = sep + 3,
            UrlUserinfo::Userinfo { start: u, at } => {
                let userinfo = &url[u..at];
                if !userinfo.trim().is_empty() && !is_plain_userinfo(userinfo, TemplateSyntax::Nunjucks) {
                    out.push_str(&text[copied..start + u]);
                    out.push_str("<redacted>");
                    copied = start + at;
                }
                from = start + at + 1;
            }
            UrlUserinfo::Ambiguous => {
                out.push_str(&text[copied..start]);
                out.push_str("<url redacted>");
                copied = word_end(last_at + 1);
                break;
            }
        }
    }
    out.push_str(&text[copied..]);
    out
}

fn redact_expressions(text: &str) -> String {
    let plain = |inner: &str| {
        let e = inner.trim();
        let e = e.strip_prefix("_.").or_else(|| e.strip_prefix('$')).unwrap_or(e);
        let mut chars = e.chars();
        chars.next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            && chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
    };
    if !text.contains("{{") {
        return text.to_string();
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(open) = rest.find("{{") {
        out.push_str(&rest[..open]);
        let after = &rest[open + 2..];
        match after.find("}}") {
            Some(close) if plain(&after[..close]) => {
                out.push_str(&rest[open..open + 2 + close + 2]);
                rest = &after[close + 2..];
            }
            Some(_) => {
                out.push_str("{{…}}");
                // Through the last `}}`: a quoted `}}` inside the expression
                // cannot end the redaction early.
                let last = after.rfind("}}").unwrap_or(0);
                rest = &after[last + 2..];
            }
            None => {
                out.push_str("{{…");
                rest = "";
            }
        }
    }
    out.push_str(rest);
    out
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
                let message = bounded_owned(redact_for_report(&Into::<String>::into(message)), MAX_TEXT_CHARS);
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
                let message = bounded_owned(redact_for_report(&Into::<String>::into(message)), MAX_TEXT_CHARS);
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
        let reference = &redact_for_report(reference);
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
            // Every field comes from the source (a request name, an event
            // or type string) and is redacted like report text.
            pointer: bounded_pointer(pointer),
            owner: bounded_owned(redact_for_report(owner), MAX_TEXT_CHARS),
            event: bounded_owned(redact_for_report(event), MAX_TEXT_CHARS),
            language: bounded_owned(redact_for_report(language), MAX_TEXT_CHARS),
            // Retained for review, never run: credential literals in it are
            // redacted like report text, the rest is kept as written.
            source: redact_for_report(&source),
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
            setting: bounded_owned(redact_for_report(setting), MAX_TEXT_CHARS),
            value: bounded_owned(redact_for_report(value), MAX_TEXT_CHARS),
            reason: bounded_owned(redact_for_report(&Into::<String>::into(reason)), MAX_TEXT_CHARS),
        });
    }

    pub fn redacted(&mut self, pointer: &str, field: impl Into<String>, placeholder: &str) {
        self.seen.redactions += 1;
        if self.redactions.len() >= MAX_ENTRIES {
            return self.truncated("redaction");
        }
        let field = bounded_owned(redact_for_report(&Into::<String>::into(field)), MAX_TEXT_CHARS);
        self.redactions.push(Redaction { pointer: bounded_pointer(pointer), field, placeholder: placeholder.into() });
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
        self.required_variables.push(RequiredVariable {
            name: name.into(),
            secret,
            reason: redact_for_report(reason),
            pointers: vec![pointer],
        });
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

#[cfg(test)]
mod tests {
    use super::redact_for_report;

    #[test]
    fn report_text_never_holds_url_credentials_or_literal_expressions() {
        for (text, expected) in [
            ("ignored 'https://admin:tok-SENSITIVE-r1@api.example.test/v1'", "ignored 'https://<redacted>@api.example.test/v1'"),
            ("proxy http://{{u}}:{{p}}@proxy.example.test", "proxy http://{{u}}:{{p}}@proxy.example.test"),
            ("see https://api.example.test/x?email=a@b", "see https://api.example.test/x?email=a@b"),
            ("see https://{{host}}/x?email=a@b ok", "see https://{{host}}/x?email=a@b ok"),
            ("url https://api.{{region}}.example.test/v1?to=a:tok-SENSITIVE-r2@b ignored", "url <url redacted> ignored"),
            ("url https://admin:{{ 'tok-SENSITIVE-r3 x' }}@api.example.test/ ignored", "url <url redacted> ignored"),
            ("url https://o'brien:tok-SENSITIVE-r4@api.example.test/", "url https://<redacted>@api.example.test/"),
            (
                "Nunjucks expression `{{ 'tok-SENSITIVE-r5}}x' | urlencode }}` is not supported",
                "Nunjucks expression `{{…}}` is not supported",
            ),
            (
                "dynamic variable '{{$guid}}' and {{ _.base }} and {{origin}}",
                "dynamic variable '{{$guid}}' and {{ _.base }} and {{origin}}",
            ),
            ("value {{ _.zero--571571570 }} here", "value {{…}} here"),
            ("unterminated {{ tok-SENSITIVE-r6", "unterminated {{…"),
            ("no credentials here", "no credentials here"),
        ] {
            assert_eq!(redact_for_report(text), expected, "{expected:?}");
        }
    }

    /// Final scope of GHSA-c236 (#579): literals outside a URL or a template,
    /// by the credential-name heuristics.
    #[test]
    fn report_text_never_holds_credential_literals() {
        for (text, expected) in [
            ("Postman body mode 'password=tok-SENSITIVE-r7' is not supported", "Postman body mode 'password=<redacted>' is not supported"),
            ("const password = 'tok-SENSITIVE-r8';", "const password = '<redacted>';"),
            (r#"{"api_key": "tok-SENSITIVE-r9", "note": "ok"}"#, r#"{"api_key": "<redacted>", "note": "ok"}"#),
            ("Insomnia auth type 'Bearer tok-SENSITIVE-r10' is not supported", "Insomnia auth type 'Bearer <redacted>' is not supported"),
            ("token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl here", "token <redacted> here"),
            ("password: {{password}} and token={{ _.token }}", "password: {{password}} and token={{ _.token }}"),
            ("see email=a@b and Basic authentication", "see email=a@b and Basic authentication"),
            ("Postman setting `strictSSL` is not imported", "Postman setting `strictSSL` is not imported"),
            ("imported without credentials (auth: none)", "imported without credentials (auth: none)"),
            // Review of #583 (dsf F1): a scheme word as a pair's value.
            ("Authorization: Bearer opaque-tok-SENSITIVE-r12", "Authorization: <redacted>"),
            ("header Authorization=Basic dXNlcjpwYXNz ok", "header Authorization=<redacted> ok"),
        ] {
            assert_eq!(redact_for_report(text), expected, "{expected:?}");
        }
    }

    /// Final scope of GHSA-c236 (sol F2): a pointer token (a source key) is
    /// redacted too, and keeps a digest so locations stay distinct.
    #[test]
    fn report_pointers_never_hold_credentials() {
        let mut report = super::ImportReport::default();
        let key = "https:~1~1admin:tok-SENSITIVE-r11@api.example.test~1";
        report.unsupported("request_setting", &format!("/item/0/protocolProfileBehavior/{key}"), "x");
        report.unsupported("request_setting", "/item/0/protocolProfileBehavior/strictSSL", "x");
        let pointer = &report.unsupported[0].pointer;
        assert!(!pointer.contains("tok-SENSITIVE"), "a pointer kept a credential");
        assert!(pointer.starts_with("/item/0/protocolProfileBehavior/https:~1~1<redacted>@api.example.test~1#"));
        assert_eq!(report.unsupported[1].pointer, "/item/0/protocolProfileBehavior/strictSSL");
    }

    #[test]
    fn report_redaction_is_linear() {
        // Over-redaction is fine: without a `/` the authority runs on.
        let text = "a://b ".repeat(1 << 16) + "x@y";
        assert!(redact_for_report(&text).ends_with("a://<redacted>@y"));
        let text = format!("{}@", "https://{{a}}/ ".repeat(1 << 16));
        assert_eq!(redact_for_report(&text), text, "a reference authority holds no userinfo");
        let text = format!("{}@", "https://x{{a}}/ ".repeat(1 << 16));
        assert_eq!(redact_for_report(&text), "<url redacted>");
        let text = "{{a}} {{".repeat(1 << 16);
        assert!(redact_for_report(&text).ends_with("{{…"));
        let text = "password= ".repeat(1 << 16) + "token=x";
        assert!(redact_for_report(&text).ends_with("<redacted>"));
        // Review of #583 (sol F7): exempt and unterminated values, scheme
        // words and JWT prefixes, each about 1 MiB; a rescan would take
        // minutes here.
        for unit in [
            "password=<",
            "password=\"",
            "password='",
            "password={{",
            "eyJ~",
            "bearer bearer ",
            "token: none ",
            "a=b:c=",
            "Authorization: Bearer ",
        ] {
            let text = unit.repeat((1 << 20) / unit.len());
            let started = std::time::Instant::now();
            let _ = redact_for_report(&text);
            assert!(started.elapsed() < std::time::Duration::from_secs(20), "{unit:?} took too long");
        }
    }
}
