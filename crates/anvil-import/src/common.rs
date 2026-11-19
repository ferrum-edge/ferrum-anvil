//! Helpers shared by the migration importers (Postman, Insomnia, cURL, HAR):
//! the credential placeholder policy, body mapping by media type, URL/query
//! splitting and dynamic-variable checks.

use crate::builder::Builder;
use crate::report::Message;
use crate::util::{
    has_literal_secret, is_credential_name, is_json_media, is_numeric_credential_name, is_xml_media, media_essence, sanitize_var,
};
use anvil_domain::auth::AuthConfig;
use anvil_domain::request::{Body, KeyValue};
use anvil_domain::secret::SensitiveValue;
use anvil_domain::workspace::Variable;
use serde_json::Value;

/// Credential placeholders are bound to the literal they replace (#584): a
/// literal of a field becomes `{{<kind>_<16 hex>}}` (`{{auth_<16 hex>_<field>}}`
/// for an auth secret), the digits from
/// HMAC-SHA256(this import's key, kind | field | literal), each part
/// length-prefixed so no two tuples encode alike ([`crate::CredentialKey`]). Equal names therefore mean the same source
/// literal: a variable the user filled resolves only where the source holds
/// exactly the secret it replaced, whatever moved, was inserted, repeated or
/// rotated, and a different literal gets a new, unfilled name. No owner, no
/// position and no raw source field name is part of a name. The name is
/// recorded in [`crate::ImportResult::credential_names`].
///
/// What is returned, and written into the imported objects, is not the name
/// but this import's sentinel for it ([`sentinel`]). [`finalize`] replaces
/// each sentinel with its name only after refusing any reserved-shape name
/// in the output. At that point every such name came from the source,
/// however the import derived it.
pub fn literal_name(b: &mut Builder, kind: &'static str, field: &str, suffix: Option<&'static str>, literal: &str) -> String {
    let field = field.to_ascii_lowercase();
    let mac = hex::encode(crate::util::hmac_sha256(&b.credential_key, &hmac_input(&[kind, &field, literal])));
    if let Some(token) = b.literal_names.get(&mac) {
        return token.clone();
    }
    let base = match suffix {
        Some(f) => format!("{kind}_{}_{f}", &mac[..16]),
        None => format!("{kind}_{}", &mac[..16]),
    };
    // Taken only by another literal whose digest shares 64 bits with this
    // one: the next free suffix.
    let name = b.env_names.name_verbatim(&base);
    let token = sentinel(&b.sentinel_nonce, b.placeholder_names.len());
    b.placeholder_names.push(name.clone());
    b.literal_names.insert(mac, token.clone());
    b.credential_names.insert(name, crate::CredentialName { kind: kind.to_string(), field });
    token
}

/// The sentinel for placeholder `index` of an import with `nonce` (32 hex
/// digits, 128 random bits drawn per import): `anvil<nonce>n<index>e`.
/// It is a plain identifier, so every path a name takes (percent-encoding,
/// sanitizing, a template or credential classifier, a renderer) keeps it as
/// it keeps a name. The source cannot write one, because it cannot know the
/// nonce.
pub fn sentinel(nonce: &str, index: usize) -> String {
    format!("anvil{nonce}n{index}e")
}

/// Finalize an import's objects (#584), in one pass over each:
///
/// 1. Refuse any string or object key that is, or holds as a `{{…}}`
///    reference (also percent-decoded), a name of [`generated_shape`].
///    The import has written only sentinels so far, so every such name came
///    from the source, however the import derived it: decoded, embedded,
///    concatenated or copied from an XML namespace.
/// 2. Refuse any sentinel-shaped text that is not one of this import's own:
///    another nonce, or an index it never issued.
/// 3. Replace each sentinel with its name, then recompute each request's
///    generated hash, which was computed over the sentinel.
///
/// Objects without a sentinel are left untouched.
pub fn finalize(result: &mut crate::ImportResult, nonce: &str, names: &[String]) -> Result<(), crate::ImportError> {
    let dialect = result.source.dialect;
    let refused = || reserved_name_error(dialect);
    let check = |v: &Value| walk_strings(v, &mut |s: &str| holds_reserved_name(s) || foreign_sentinel(s, nonce, names.len()));
    let to_json = |v: serde_json::Result<Value>| v.unwrap_or(Value::Null);
    let workspace = to_json(serde_json::to_value(&result.workspace));
    let folders: Vec<Value> = result.folders.iter().map(|f| to_json(serde_json::to_value(f))).collect();
    let requests: Vec<Value> = result.requests.iter().map(|q| to_json(serde_json::to_value(q))).collect();
    let environments: Vec<Value> = result.environments.iter().map(|e| to_json(serde_json::to_value(e))).collect();
    let report = to_json(serde_json::to_value(&result.report));
    if check(&workspace) || folders.iter().any(&check) || requests.iter().any(&check) || environments.iter().any(&check) || check(&report) {
        return Err(refused());
    }
    if names.is_empty() {
        return Ok(());
    }
    let prefix = format!("anvil{nonce}n");
    let replace = |v: Value| -> Option<Value> { contains_text(&v, &prefix).then(|| substitute(v, &prefix, names)) };
    let invalid = |what: &str| crate::ImportError::Invalid {
        dialect,
        pointer: "/".into(),
        message: format!("the imported {what} could not be finalized"),
    };
    if let Some(v) = replace(workspace) {
        result.workspace = serde_json::from_value(v).map_err(|_| invalid("workspace"))?;
    }
    for (f, v) in result.folders.iter_mut().zip(folders) {
        if let Some(v) = replace(v) {
            *f = serde_json::from_value(v).map_err(|_| invalid("folder"))?;
        }
    }
    for (q, v) in result.requests.iter_mut().zip(requests) {
        if let Some(v) = replace(v) {
            *q = serde_json::from_value(v).map_err(|_| invalid("request"))?;
            let source = q.spec.source.take();
            let hash = crate::spec_hash(&q.spec);
            q.spec.source = source.map(|s| anvil_domain::request::ImportSource { generated_hash: hash, ..s });
        }
    }
    for (e, v) in result.environments.iter_mut().zip(environments) {
        if let Some(v) = replace(v) {
            *e = serde_json::from_value(v).map_err(|_| invalid("environment"))?;
        }
    }
    for r in &mut result.report.redactions {
        r.placeholder = substitute_text(&r.placeholder, &prefix, names);
    }
    for v in &mut result.report.required_variables {
        v.name = substitute_text(&v.name, &prefix, names);
    }
    Ok(())
}

/// Call `f` on every string and object key of `v` until it returns true.
/// One pass, without recursion.
fn walk_strings(v: &Value, f: &mut dyn FnMut(&str) -> bool) -> bool {
    let mut stack = vec![v];
    while let Some(v) = stack.pop() {
        match v {
            Value::String(s) if f(s) => return true,
            Value::Array(items) => stack.extend(items),
            Value::Object(m) => {
                for (k, x) in m {
                    if f(k) {
                        return true;
                    }
                    stack.push(x);
                }
            }
            _ => {}
        }
    }
    false
}

fn contains_text(v: &Value, needle: &str) -> bool {
    walk_strings(v, &mut |s: &str| s.contains(needle))
}

/// Whether `s` is a name of [`generated_shape`], or holds one as a `{{…}}`
/// reference (Insomnia's `{{ _.name }}` too), as written or percent-decoded.
fn holds_reserved_name(s: &str) -> bool {
    let shaped = |n: &str| {
        generated_shape(n) || (n.contains('%') && percent_encoding::percent_decode_str(n).decode_utf8().is_ok_and(|d| generated_shape(&d)))
    };
    if shaped(s.trim()) {
        return true;
    }
    let mut rest = s;
    while let Some(open) = rest.find("{{") {
        let after = &rest[open + 2..];
        let Some(close) = after.find("}}") else { break };
        let inner = after[..close].trim();
        if shaped(inner.strip_prefix("_.").unwrap_or(inner)) {
            return true;
        }
        rest = &after[close + 2..];
    }
    false
}

/// Whether `s` holds sentinel-shaped text (`anvil<32 hex>n<digits>e`) that is
/// not one of this import's: another nonce, or an index past `issued`.
fn foreign_sentinel(s: &str, nonce: &str, issued: usize) -> bool {
    let mut rest = s;
    while let Some(at) = rest.find("anvil") {
        let tail = &rest[at + 5..];
        rest = tail;
        let b = tail.as_bytes();
        if b.len() < 34 || !b[..32].iter().all(u8::is_ascii_hexdigit) || b[32] != b'n' {
            continue;
        }
        let digits = b[33..].iter().take_while(|c| c.is_ascii_digit()).count();
        if digits == 0 || b.get(33 + digits) != Some(&b'e') {
            continue;
        }
        let index = std::str::from_utf8(&b[33..33 + digits]).ok().and_then(|d| d.parse::<usize>().ok());
        if &tail[..32] != nonce || index.is_none_or(|i| i >= issued) {
            return true;
        }
    }
    false
}

/// `s` with each of this import's sentinels replaced by its name.
fn substitute_text(s: &str, prefix: &str, names: &[String]) -> String {
    if !s.contains(prefix) {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(at) = rest.find(prefix) {
        out.push_str(&rest[..at]);
        let tail = &rest[at + prefix.len()..];
        let digits = tail.bytes().take_while(u8::is_ascii_digit).count();
        let name = tail[..digits].parse::<usize>().ok().and_then(|i| names.get(i)).filter(|_| tail.as_bytes().get(digits) == Some(&b'e'));
        match name {
            Some(name) => {
                out.push_str(name);
                rest = &tail[digits + 1..];
            }
            // Not a sentinel after all (checked before): kept as written.
            None => {
                out.push_str(prefix);
                rest = tail;
            }
        }
    }
    out.push_str(rest);
    out
}

/// `v` with every string and object key passed through [`substitute_text`].
fn substitute(v: Value, prefix: &str, names: &[String]) -> Value {
    match v {
        Value::String(s) => Value::String(substitute_text(&s, prefix, names)),
        Value::Array(items) => Value::Array(items.into_iter().map(|x| substitute(x, prefix, names)).collect()),
        Value::Object(m) => {
            Value::Object(m.into_iter().map(|(k, x)| (substitute_text(&k, prefix, names), substitute(x, prefix, names))).collect())
        }
        other => other,
    }
}

/// The HMAC input for `parts`: each part's byte length (8 bytes, big
/// endian), then its bytes. Unambiguous whatever the parts hold (a NUL
/// included), unlike joining them with a separator.
pub fn hmac_input(parts: &[&str]) -> Vec<u8> {
    let mut out = Vec::with_capacity(parts.iter().map(|p| p.len() + 8).sum());
    for part in parts {
        out.extend_from_slice(&(part.len() as u64).to_be_bytes());
        out.extend_from_slice(part.as_bytes());
    }
    out
}

/// Whether `name` has the shape of a placeholder [`literal_name`] makes
/// (`auth_<16 hex>…`, `secret_<16 hex>…`, `url_<16 hex>…`). A source that
/// uses such a name itself is refused ([`finalize`]), so a source can never
/// point a request at a variable filled for one of these.
pub fn generated_shape(name: &str) -> bool {
    let Some((kind, rest)) = name.split_once('_') else { return false };
    // Bytes, not a string split: byte 16 may fall inside a character.
    let rest = rest.as_bytes();
    matches!(kind, "auth" | "secret" | "url")
        && rest.len() >= 16
        && rest[..16].iter().all(u8::is_ascii_hexdigit)
        && rest.get(16).is_none_or(|&c| c == b'_')
}

/// The refusal for a source that uses a reserved-shape name ([`finalize`]).
pub fn reserved_name_error(dialect: crate::Dialect) -> crate::ImportError {
    crate::ImportError::Invalid {
        dialect,
        pointer: "/".into(),
        message: "the source uses a variable name in the shape Anvil reserves for credential placeholders \
                  (`auth_`, `secret_` or `url_` followed by 16 hex digits): rename it"
            .into(),
    }
}

/// The policy for a credential `value` of field `field`:
///
/// * a value that is not literal material (a reference) is kept;
/// * an empty value is kept: there is no literal to bind a placeholder to
///   (fill it in on the request);
/// * a literal is kept only with `include_credentials`; otherwise it is
///   replaced by its literal-bound placeholder ([`literal_name`]), recorded
///   as a redaction and listed as a required variable.
fn credential_placeholder(
    b: &mut Builder,
    value: &str,
    literal: bool,
    (kind, field, suffix): (&'static str, &str, Option<&'static str>),
    pointer: &str,
    label: &str,
) -> String {
    let t = value.trim();
    if t.is_empty() || !literal || b.opts.include_credentials {
        return value.to_string();
    }
    let var = literal_name(b, kind, field, suffix, value);
    let placeholder = format!("{{{{{var}}}}}");
    b.report.redacted(pointer, label, &placeholder);
    b.report.require_var(&var, true, "the credential was redacted on import", pointer);
    placeholder
}

/// [`credential_placeholder`] for a value stored as plain text (a header,
/// query, form, body, path or environment value) of the field named
/// `field`.
pub fn credential_text(b: &mut Builder, value: &str, field: &str, pointer: &str, label: &str) -> String {
    let literal = has_literal_secret(value.trim(), b.template_syntax);
    credential_placeholder(b, value, literal, ("secret", field, None), pointer, label)
}

/// [`credential_placeholder`] for secret `field` of an auth config
/// (`password`, `token`, `api_key`, `client_secret`).
pub fn auth_credential(b: &mut Builder, value: &str, field: &'static str, pointer: &str, label: &str) -> SensitiveValue {
    let literal = has_literal_secret(value.trim(), b.template_syntax);
    SensitiveValue::template(credential_placeholder(b, value, literal, ("auth", field, Some(field)), pointer, label))
}

/// Apply the credential policy to a variable definition. A secret literal
/// is dropped (without `include_credentials`) and listed as a required
/// variable, so references to it fail validation until the user supplies it.
pub fn env_var(b: &mut Builder, key: &str, value: &str, secret: bool, enabled: bool, at: &str) -> Option<Variable> {
    let literal = has_literal_secret(value, b.template_syntax);
    if secret && literal && !b.opts.include_credentials {
        b.report.redacted(at, format!("variable {key}"), &format!("{{{{{key}}}}}"));
        b.report.require_var(key, true, "secret variable value was redacted on import", at);
        return None;
    }
    Some(Variable { name: key.to_string(), value: SensitiveValue::template(value), secret, enabled, description: String::new() })
}

/// Redact a header/query value when its name is credential-like. Returns
/// the value to store and whether the entry should be marked sensitive.
pub fn maybe_redact(b: &mut Builder, name: &str, value: &str, pointer: &str, what: &str) -> (String, bool) {
    if !is_credential_name(name) || value.trim().is_empty() {
        return (value.to_string(), false);
    }
    (credential_text(b, value, name, pointer, &format!("{what} {name}")), true)
}

/// [`maybe_redact`] for a path parameter's value. A valueless parameter
/// keeps its own name (`:api_key` becomes `{{api_key}}`, the source's own
/// variable); a literal value becomes a literal-bound placeholder like any
/// other ([`literal_name`]).
pub fn maybe_redact_path(b: &mut Builder, name: &str, value: &str, pointer: &str, what: &str) -> (String, bool) {
    if !is_credential_name(name) || value.trim().is_empty() {
        return (value.to_string(), false);
    }
    (credential_text(b, value, name, pointer, &format!("{what} {name}")), true)
}

/// Replace credential-looking string members of a JSON body (recursively),
/// and numbers under names that hold numeric credentials (a `pin`, an `otp`).
pub fn scrub_json(b: &mut Builder, v: &mut Value, pointer: &str) {
    scrub_json_at(b, v, pointer, &mut Vec::new());
}

/// Marks a placeholder that replaced a number, so [`render_json`] writes it
/// without quotes (`"pin": {{pin}}`). A control character the source text
/// cannot hold unescaped, plus a tag.
const NUMERIC_PLACEHOLDER: &str = "\u{1}anvil-number\u{1}";

/// Serialize a scrubbed JSON body, writing the placeholders that replaced
/// numbers unquoted.
///
/// Only the exact strings [`scrub_json_at`] produced are unquoted: they are
/// collected from the tree into a lookup keyed by their whole serialized
/// form, then the rendered text and the source are each scanned once for
/// that form, so unrelated source text that merely mentions the marker tag
/// cannot keep a numeric placeholder quoted, source strings are never
/// rewritten, and the work stays linear in the body however many distinct
/// numeric placeholders it holds. The one indistinguishable case, a source
/// string already equal to a whole marked placeholder, stays a quoted
/// string with the markers stripped.
pub fn render_json(v: &Value, pretty: bool, source: &str) -> Option<String> {
    let text = if pretty { serde_json::to_string_pretty(v).ok()? } else { serde_json::to_string(v).ok()? };
    let mut numeric = Vec::new();
    collect_numeric_placeholders(v, &mut numeric);
    if numeric.is_empty() {
        return Some(text);
    }
    numeric.sort();
    numeric.dedup();
    // Serialized marked string -> what replaces it. Built once; its total
    // size is bounded by the placeholders themselves, not the body.
    let mut replacements = std::collections::HashMap::with_capacity(numeric.len());
    for marked in &numeric {
        let serialized = serde_json::to_string(&Value::String(marked.clone())).ok()?;
        let inner = &marked[NUMERIC_PLACEHOLDER.len()..marked.len() - NUMERIC_PLACEHOLDER.len()];
        replacements.insert(serialized, inner.to_string());
    }
    // The marker as it appears inside a serialized JSON string.
    let marker_json = serde_json::to_string(NUMERIC_PLACEHOLDER).ok()?;
    let marker_json = &marker_json[1..marker_json.len() - 1];
    let prefix = format!("\"{marker_json}");
    // Marked strings the source itself already held stay quoted.
    let mut collisions = std::collections::HashSet::new();
    scan_marked(source, &prefix, |candidate| {
        if replacements.contains_key(candidate) {
            collisions.insert(candidate.to_string());
            Some(candidate)
        } else {
            None
        }
    });
    for serialized in &collisions {
        let inner = replacements.get(serialized)?;
        let quoted = serde_json::to_string(inner).ok()?;
        replacements.insert(serialized.clone(), quoted);
    }
    Some(scan_marked(&text, &prefix, |candidate| replacements.get(candidate).map(String::as_str)))
}

/// One pass over JSON `text`, replacing every whole string token that
/// starts with `prefix` and for which `replace` returns a replacement.
///
/// String tokens are walked with their escapes, so each byte is visited
/// once and slices land only on ASCII quote boundaries: a longer string
/// that merely begins with the marker is one token, never rescanned, and
/// cannot swallow a marked string that follows it.
fn scan_marked<'t, 'r>(text: &'t str, prefix: &str, mut replace: impl FnMut(&'t str) -> Option<&'r str>) -> String
where
    't: 'r,
{
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut copied = 0usize;
    let mut at = 0usize;
    while at < bytes.len() {
        if bytes[at] != b'"' {
            at += 1;
            continue;
        }
        // The string token from `at`: its closing quote, escapes skipped.
        let mut end = at + 1;
        while end < bytes.len() && bytes[end] != b'"' {
            end += if bytes[end] == b'\\' { 2 } else { 1 };
        }
        if end >= bytes.len() {
            break; // unterminated: the rest is copied verbatim below
        }
        let token = &text[at..=end];
        if token.starts_with(prefix)
            && let Some(replacement) = replace(token)
        {
            out.push_str(&text[copied..at]);
            out.push_str(replacement);
            copied = end + 1;
        }
        at = end + 1;
    }
    out.push_str(&text[copied..]);
    out
}

/// Every string in `v` that is a whole numeric placeholder (marker, value,
/// marker), as written by [`scrub_json_at`].
fn collect_numeric_placeholders(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::String(s) => {
            if s.len() > NUMERIC_PLACEHOLDER.len() * 2 && s.starts_with(NUMERIC_PLACEHOLDER) && s.ends_with(NUMERIC_PLACEHOLDER) {
                out.push(s.clone());
            }
        }
        Value::Array(a) => a.iter().for_each(|c| collect_numeric_placeholders(c, out)),
        Value::Object(m) => m.values().for_each(|c| collect_numeric_placeholders(c, out)),
        _ => {}
    }
}

/// Bytes of a member name kept per path segment while walking a body; a
/// report pointer is built from the segments only for a member that is
/// redacted, and is itself bounded, so walking a wide array under a long
/// name costs no more than the body.
const SEGMENT_BYTES: usize = 64;
const POINTER_BYTES: usize = 1024;

fn segment(name: &str) -> String {
    crate::util::clip(name, SEGMENT_BYTES)
}

fn pointer_at(base: &str, path: &[String], last: &str) -> String {
    let mut p = base.to_string();
    for seg in path.iter().map(String::as_str).chain(std::iter::once(last)) {
        if p.len() > POINTER_BYTES {
            p.push_str("/…");
            break;
        }
        p = crate::util::ptr(&p, seg);
    }
    p
}

fn scrub_json_at(b: &mut Builder, v: &mut Value, pointer: &str, path: &mut Vec<String>) {
    match v {
        Value::Object(m) => {
            for (k, child) in m.iter_mut() {
                if is_credential_name(k)
                    && let Value::String(s) = child
                {
                    let p = pointer_at(pointer, path, &segment(k));
                    let new = credential_text(b, s, k, &p, &format!("body field {k}"));
                    *s = new;
                    continue;
                }
                if is_numeric_credential_name(k)
                    && let Value::Number(n) = child
                {
                    let p = pointer_at(pointer, path, &segment(k));
                    let literal = n.to_string();
                    let new = credential_text(b, &literal, k, &p, &format!("body field {k}"));
                    if new != literal {
                        // Rendered unquoted ([`render_json`]): the value the
                        // user supplies is substituted as a number again.
                        *child = Value::String(format!("{NUMERIC_PLACEHOLDER}{new}{NUMERIC_PLACEHOLDER}"));
                    }
                    continue;
                }
                if child.is_object() || child.is_array() {
                    path.push(segment(k));
                    scrub_json_at(b, child, pointer, path);
                    path.pop();
                }
            }
        }
        Value::Array(a) => {
            for (i, child) in a.iter_mut().enumerate() {
                if child.is_object() || child.is_array() {
                    path.push(i.to_string());
                    scrub_json_at(b, child, pointer, path);
                    path.pop();
                }
            }
        }
        _ => {}
    }
}

/// The names in use in an import's scope: every name the source defines,
/// references or derives, reserved first, and every placeholder the import
/// made ([`literal_name`]), so a placeholder never takes one of the
/// source's names (a name already taken gets the next free `_2`, `_3`, …
/// suffix, found in amortized constant time).
#[derive(Default)]
pub struct PlaceholderNames {
    used: std::collections::HashSet<String>,
    next: std::collections::HashMap<String, usize>,
}

impl PlaceholderNames {
    /// Reserve a name that exists in the scope (a variable name), as written
    /// and as a placeholder would spell it, and by its percent-decoded
    /// spelling too (`{{a%2Db}}` may be read as `a-b`).
    pub fn reserve(&mut self, name: &str) {
        self.used.insert(name.to_string());
        self.used.insert(sanitize_var(name));
        if name.contains('%')
            && let Ok(decoded) = percent_encoding::percent_decode_str(name).decode_utf8()
            && decoded != name
        {
            self.used.insert(sanitize_var(&decoded));
            self.used.insert(decoded.into_owned());
        }
    }

    /// A free name for `base` as written (not sanitized), now reserved: for
    /// a name that must not be one an import derives from the source, since
    /// every derived name is sanitized ([`sanitize_var`]: letters, digits
    /// and `_`) and every explicit one is reserved.
    pub fn name_verbatim(&mut self, base: &str) -> String {
        if self.used.insert(base.to_string()) {
            return base.to_string();
        }
        let mut n = self.next.get(base).copied().unwrap_or(2);
        loop {
            let candidate = format!("{base}_{n}");
            n += 1;
            if self.used.insert(candidate.clone()) {
                self.next.insert(base.to_string(), n);
                return candidate;
            }
        }
    }
}

/// Reserve every name the source references as `{{name}}` (Insomnia's
/// `{{ _.name }}` too), so a placeholder the import makes never names a
/// variable the source already uses. One pass over the input.
pub fn reserve_source_references(b: &mut Builder, text: &str) {
    let mut rest = text;
    while let Some(open) = rest.find("{{") {
        let after = &rest[open + 2..];
        let Some(close) = after.find("}}") else { break };
        let expr = after[..close].trim();
        let name = expr.strip_prefix("_.").unwrap_or(expr);
        if !name.is_empty() && name.len() <= 256 {
            b.env_names.reserve(name);
        }
        rest = &after[close + 2..];
    }
}

/// Reserve every name a request can define implicitly, before any
/// placeholder is made, so a fresh placeholder (an auth secret, a
/// credential field, a path-named environment leaf) never names one:
/// - every path parameter, written as a `:name` segment at the start of a
///   string or after a `/` (a Postman or Insomnia URL, a Postman `path`
///   element), up to the next `/`, `?` or `#`; a valueless one becomes
///   `{{name}}` (sanitized);
/// - every `key` (or `id`) of a `variable` list (Postman collection, folder
///   and `url.variable`) and every `name` of an Insomnia `pathParameters`
///   list;
/// - every `{{name}}` reference in a decoded string, which escapes can hide
///   from the raw-text pass ([`reserve_string_references`]).
///
/// A path parameter is reserved by its raw spelling too (`:a-b` reserves
/// `a-b` as well as `a_b`); that is fail-safe: a placeholder then takes a
/// suffix.
///
/// Over-reserving only makes a placeholder take a suffix. One pass over the
/// parsed document, without recursion.
pub fn reserve_implicit_names(b: &mut Builder, root: &Value) {
    let mut stack = vec![root];
    while let Some(v) = stack.pop() {
        match v {
            Value::String(s) => {
                reserve_path_segments(b, s);
                reserve_string_references(b, s);
            }
            Value::Array(a) => stack.extend(a.iter()),
            Value::Object(m) => {
                for (list, field) in [("variable", "key"), ("variable", "id"), ("pathParameters", "name")] {
                    for entry in m.get(list).and_then(Value::as_array).into_iter().flatten() {
                        if let Some(name) = entry.get(field).and_then(Value::as_str).filter(|n| !n.is_empty() && n.len() <= 256) {
                            b.env_names.reserve(name);
                        }
                    }
                }
                stack.extend(m.values());
            }
            _ => {}
        }
    }
}

/// Reserve the `{{name}}` references of one decoded string (a parsed JSON or
/// YAML value, a tokenized cURL word), which the raw-text pass
/// ([`reserve_source_references`]) cannot see when the source escaped them
/// (`\u007b\u007bname\u007d\u007d`, shell quoting).
pub fn reserve_string_references(b: &mut Builder, s: &str) {
    if s.contains("{{") {
        reserve_source_references(b, s);
    }
}

/// [`reserve_implicit_names`] for the `:name` segments of one string.
fn reserve_path_segments(b: &mut Builder, s: &str) {
    let mut from = 0;
    while let Some(found) = s[from..].find(':') {
        let colon = from + found;
        from = colon + 1;
        if colon > 0 && s.as_bytes()[colon - 1] != b'/' {
            continue;
        }
        let rest = &s[colon + 1..];
        let name = &rest[..rest.find(['/', '?', '#']).unwrap_or(rest.len())];
        if !name.is_empty() && name.len() <= 256 {
            b.env_names.reserve(name);
        }
    }
}

/// Apply the credential policy to a JSON value that is stored as text (an
/// Insomnia environment value named `name` that is an array): every scalar
/// under a credential-named member, whatever it is called and whatever its
/// type (string, number or boolean), becomes a literal-bound placeholder
/// ([`literal_name`], the field being the nearest member name). Numbers and
/// booleans keep an unquoted placeholder
/// ([`render_json`]). As in [`scrub_json`], a node's report pointer and name
/// are built, bounded, only for a leaf that is redacted, so the walk costs no
/// more than the value. Returns whether anything was redacted.
pub fn scrub_stored_json(b: &mut Builder, v: &mut Value, name: &str, pointer: &str) -> bool {
    let before = b.report.redactions_made();
    scrub_stored_at(b, v, name, pointer, &mut Vec::new(), false);
    b.report.redactions_made() > before
}

fn scrub_stored_at(b: &mut Builder, v: &mut Value, root: &str, pointer: &str, path: &mut Vec<String>, credential: bool) {
    match v {
        Value::Object(m) => {
            for (k, child) in m.iter_mut() {
                let under = credential || is_credential_name(k);
                if under || child.is_object() || child.is_array() {
                    path.push(segment(k));
                    scrub_stored_at(b, child, root, pointer, path, under);
                    path.pop();
                }
            }
        }
        Value::Array(a) => {
            for (i, child) in a.iter_mut().enumerate() {
                if credential || child.is_object() || child.is_array() {
                    path.push(i.to_string());
                    scrub_stored_at(b, child, root, pointer, path, credential);
                    path.pop();
                }
            }
        }
        Value::String(s) if credential => {
            let (field, p) = leaf_names(root, pointer, path);
            let literal = has_literal_secret(s.trim(), b.template_syntax);
            *s = credential_placeholder(b, s, literal, ("secret", field, None), &p, &format!("environment value {root}"));
        }
        Value::Number(_) | Value::Bool(_) if credential => {
            let (field, p) = leaf_names(root, pointer, path);
            let literal = v.to_string();
            let new = credential_placeholder(b, &literal, true, ("secret", field, None), &p, &format!("environment value {root}"));
            if new != literal {
                *v = Value::String(format!("{NUMERIC_PLACEHOLDER}{new}{NUMERIC_PLACEHOLDER}"));
            }
        }
        _ => {}
    }
}

/// The field name a leaf at `path` under the value named `root` fills (its
/// nearest member name), and its report pointer, built with bounded work.
fn leaf_names<'p>(root: &'p str, pointer: &str, path: &'p [String]) -> (&'p str, String) {
    let field = path.iter().rev().find(|seg| !seg.bytes().all(|c| c.is_ascii_digit())).map_or(root, String::as_str);
    let p = match path.split_last() {
        Some((last, parents)) => pointer_at(pointer, parents, last),
        None => pointer.to_string(),
    };
    (field, p)
}

/// Parse a JSON document embedded in a string field of the source (a request
/// body, a GraphQL payload) under the import bounds. Its nodes are charged to
/// one budget shared by every embedded document of the import, so many small
/// outer strings cannot expand into far more nodes than
/// [`ImportOptions::max_nodes`](crate::ImportOptions::max_nodes) allows.
pub fn parse_embedded_json(b: &mut Builder, text: &str) -> Result<crate::structured::CountedJson, crate::ImportError> {
    let limits = crate::structured::Limits::for_input(b.embedded_nodes_left, b.opts.max_bytes);
    let (res, used) = crate::structured::parse_json_counted(text, limits);
    b.embedded_nodes_left = b.embedded_nodes_left.saturating_sub(used);
    res
}

/// Scan a JSON body's text for credential-like members and replace their
/// literal values ([`scrub_json`]). The text is rewritten only when something
/// was redacted, or (without `include_credentials`) when an object repeats a
/// member: the parsed tree keeps only its last value, and the text would
/// still hold the earlier ones, which were never scanned. A body that cannot be parsed (or
/// exceeds the import's embedded-document budget) is kept verbatim with a
/// `body_not_scanned` warning. Returns whether the body was scanned.
pub fn scrub_json_text(b: &mut Builder, text: &mut String, pointer: &str) -> bool {
    match parse_embedded_json(b, text) {
        Ok(parsed) => {
            let mut v = parsed.value;
            // Counted apart from the (capped) list, so a body is rewritten
            // whenever it was scrubbed.
            let before = b.report.redactions_made();
            scrub_json(b, &mut v, pointer);
            let collapse = parsed.duplicate_keys && !b.opts.include_credentials;
            if collapse {
                b.report.warn(
                    "json_duplicate_member",
                    pointer,
                    "the JSON body repeats a member name; it was rewritten keeping the last value of each repeated member, as most parsers read it",
                );
            }
            if (b.report.redactions_made() > before || collapse)
                && let Some(t) = render_json(&v, true, text)
            {
                *text = t;
            }
            true
        }
        Err(e) => {
            let message = match e {
                crate::ImportError::LimitExceeded { limit, .. } => {
                    Message::new("the JSON body was not scanned for credentials: it exceeds an import limit (")
                        .num(limit)
                        .text("); review it before sharing")
                }
                _ => Message::new("the JSON body was not scanned for credentials: it could not be parsed; review it before sharing"),
            };
            b.report.warn("body_not_scanned", pointer, message);
            false
        }
    }
}

/// Apply the credential policy to a mapped text body: credential-like JSON
/// members (unless `include_credentials` is set) and URL-encoded form fields.
/// A non-empty XML, SOAP or other text body cannot be scanned and gets a
/// `body_not_scanned` warning ([`warn_unscanned`]).
pub fn scrub_body(b: &mut Builder, body: &mut Body, pointer: &str) {
    match body {
        Body::Json { text } if !text.trim().is_empty() && !b.opts.include_credentials => {
            scrub_json_text(b, text, pointer);
        }
        Body::FormUrlEncoded { fields } => {
            for (n, f) in fields.iter_mut().enumerate() {
                let (value, sensitive) = maybe_redact(b, &f.name, &f.value, &format!("{pointer}#field{n}"), "form field");
                f.value = value;
                f.sensitive |= sensitive;
            }
        }
        _ => warn_unscanned(b, body, pointer),
    }
}

/// `body_not_scanned` for a non-empty body whose kind the credential policy
/// cannot read (XML, a SOAP envelope, other text), unless credentials are
/// kept anyway.
pub fn warn_unscanned(b: &mut Builder, body: &Body, pointer: &str) {
    if b.opts.include_credentials {
        return;
    }
    let text = match body {
        Body::Raw { text, .. } | Body::Xml { text } | Body::Soap { envelope: text, .. } => text,
        _ => return,
    };
    if !text.trim().is_empty() {
        b.report.warn(
            "body_not_scanned",
            pointer,
            "the body is imported verbatim; it was not scanned for credentials (review it before sharing)",
        );
    }
}

/// Apply the credential policy to GraphQL variables (unless
/// `include_credentials` is set): a JSON object, or a string holding one,
/// parsed under the embedded-document budget. Returns the variables text.
pub fn scrub_graphql_variables(b: &mut Builder, variables: Option<Value>, pointer: &str) -> String {
    match variables {
        Some(Value::Null) | None => String::new(),
        Some(Value::String(mut s)) => {
            if !b.opts.include_credentials && !s.trim().is_empty() {
                scrub_json_text(b, &mut s, pointer);
            }
            s
        }
        Some(mut v) => {
            if b.opts.include_credentials {
                return v.to_string();
            }
            let source = v.to_string();
            scrub_json(b, &mut v, pointer);
            render_json(&v, false, &source).unwrap_or(source)
        }
    }
}

/// Take the credential-named `name=value` segments out of a query that
/// [`split_query`] keeps in the URL verbatim (a bare `flag` segment, or
/// escapes that would decode into a `{{reference}}`), and return them as
/// sensitive parameters with the credential policy applied. The rest of the
/// query keeps its exact syntax, and the fragment is kept.
///
/// A credential is never left in URL text: there a placeholder would resolve
/// without percent-encoding (a supplied `a&b` would add a parameter) and a
/// kept literal would be neither marked sensitive nor extracted on export.
/// As a parameter the engine encodes its value after resolution. A value
/// whose decoding would make or change a reference is treated as literal.
pub fn redact_raw_query(b: &mut Builder, url: &str, pointer: &str, what: &str) -> (String, Vec<KeyValue>) {
    let no_frag = strip_fragment(url);
    let fragment = &url[no_frag.len()..];
    let Some((base, q)) = no_frag.split_once('?') else { return (url.to_string(), vec![]) };
    let mut kept = vec![];
    let mut params = vec![];
    for seg in q.split('&') {
        let credential = match seg.split_once('=') {
            Some((k, v)) if !query_decode(v).trim().is_empty() && is_credential_name(&query_decode(k)) => Some((k, v)),
            _ => None,
        };
        let Some((k, v)) = credential else {
            kept.push(seg);
            continue;
        };
        // Matched by its decoded spelling, but stored decoded only when that
        // makes or changes no `{{reference}}`: the engine resolves names
        // too. The placeholder is bound to the literal ([`literal_name`]),
        // never named after the name, so decoded escaped braces
        // (`%7B%7Bapi_key%7D%7D`) cannot name an existing variable
        // (`{{api_key}}`) the source never read.
        let var = k.to_string();
        let name = decode_keeping_references(k).unwrap_or_else(|| k.to_string());
        let decoded = query_decode(v);
        let value = if same_references(v, &decoded) {
            credential_text(b, &decoded, &var, pointer, &format!("{what} {var}"))
        } else {
            credential_placeholder(b, v, true, ("secret", &var, None), pointer, &format!("{what} {var}"))
        };
        if seg.contains('+') {
            b.report.warn(
                "query_plus_sent_encoded",
                pointer,
                "a '+' in a credential query parameter is kept as a plus and sent as %2B, where the source sends it as is",
            );
        }
        if percent_encoding::percent_decode_str(k).decode_utf8().is_err() || percent_encoding::percent_decode_str(v).decode_utf8().is_err()
        {
            b.report.warn(
                "query_not_utf8",
                pointer,
                "a credential query parameter has an escape that is not UTF-8; it was replaced by U+FFFD: edit it before sending",
            );
        }
        params.push(KeyValue { name, value, enabled: true, description: String::new(), sensitive: true });
    }
    let url = if kept.is_empty() { format!("{base}{fragment}") } else { format!("{base}?{}{fragment}", kept.join("&")) };
    (url, params)
}

/// Map a text body to the matching [`Body`] variant by media type. Returns
/// the body and, when the variant's inferred content type would differ from
/// `mime`, the explicit `Content-Type` header to keep.
pub fn body_from_text(mime: Option<&str>, text: String) -> (Body, Option<String>) {
    let Some(m) = mime.filter(|m| !m.trim().is_empty()) else {
        return (Body::Raw { text, content_type: None }, None);
    };
    let e = media_essence(m);
    if is_json_media(m) {
        let explicit = (e != "application/json" || m.contains(';')).then(|| m.to_string());
        (Body::Json { text }, explicit)
    } else if is_xml_media(m) {
        let explicit = (e != "application/xml" || m.contains(';')).then(|| m.to_string());
        (Body::Xml { text }, explicit)
    } else if e == "application/x-www-form-urlencoded" {
        match parse_form(&text) {
            Some(fields) => (Body::FormUrlEncoded { fields }, None),
            None => (Body::Raw { text, content_type: Some(m.to_string()) }, None),
        }
    } else {
        (Body::Raw { text, content_type: Some(m.to_string()) }, None)
    }
}

/// Parse `a=1&b=2` into fields. `None` when any pair lacks `=` (kept raw to
/// preserve the exact bytes).
pub fn parse_form(text: &str) -> Option<Vec<KeyValue>> {
    if text.is_empty() {
        return Some(vec![]);
    }
    let mut out = vec![];
    for pair in text.split('&') {
        let (k, v) = pair.split_once('=')?;
        out.push(KeyValue::new(form_decode(k), form_decode(v)));
    }
    Some(out)
}

pub fn form_decode(s: &str) -> String {
    let plus = s.replace('+', " ");
    percent_encoding::percent_decode_str(&plus).decode_utf8_lossy().into_owned()
}

pub fn query_decode(s: &str) -> String {
    percent_encoding::percent_decode_str(s).decode_utf8_lossy().into_owned()
}

/// Split a URL into base (without query/fragment) and decoded query pairs.
/// When some pair has no `=` (or the query is otherwise not a plain list of
/// pairs), or decoding a name or value would make or change a
/// `{{reference}}` (`%7B%7Bid%7D%7D`, which the source sends as literal
/// text), the query stays in the URL verbatim and no pairs are returned.
pub fn split_query(url: &str) -> (String, Vec<(String, String)>) {
    let no_frag = strip_fragment(url);
    let Some((base, q)) = no_frag.split_once('?') else {
        return (no_frag.to_string(), vec![]);
    };
    if q.is_empty() {
        return (base.to_string(), vec![]);
    }
    let mut pairs = vec![];
    for p in q.split('&') {
        match p.split_once('=') {
            Some((k, v)) if !k.is_empty() => {
                let (name, value) = (query_decode(k), query_decode(v));
                if !same_references(k, &name) || !same_references(v, &value) {
                    return (no_frag.to_string(), vec![]);
                }
                pairs.push((name, value));
            }
            _ => return (no_frag.to_string(), vec![]),
        }
    }
    (base.to_string(), pairs)
}

/// Report what a URL query's decoded parameters ([`split_query`]) send
/// differently from the source, which sends the query as written: a `+`
/// (sent as `%2B`, where form-decoding servers read the source's `+` as a
/// space) and escapes that are not UTF-8 (replaced by U+FFFD).
pub fn warn_query_conversions(b: &mut Builder, pairs_found: bool, url: &str, pointer: &str) {
    let Some((_, q)) = strip_fragment(url).split_once('?') else { return };
    if !pairs_found {
        return;
    }
    if q.contains('+') {
        b.report.warn(
            "query_plus_sent_encoded",
            pointer,
            "a '+' in the query is kept as a plus and sent as %2B; servers that read '+' as a space would see a plus: edit the \
             parameter if a space was meant",
        );
    }
    if q.split(['&', '=']).any(|part| percent_encoding::percent_decode_str(part).decode_utf8().is_err()) {
        b.report.warn(
            "query_not_utf8",
            pointer,
            "a query escape is not UTF-8 and was replaced by U+FFFD in the parameter; edit it before sending",
        );
    }
}

/// The `{{…}}` references in `s` as the resolver reads them: each `{{` up to
/// the first `}}` after it.
fn template_tokens(s: &str) -> Vec<&str> {
    let mut out = vec![];
    let mut rest = s;
    while let Some(open) = rest.find("{{") {
        let after = &rest[open + 2..];
        let Some(close) = after.find("}}") else { break };
        out.push(&after[..close]);
        rest = &after[close + 2..];
    }
    out
}

/// Whether `decoded` has exactly the `{{references}}` of the source text
/// `source`: the same tokens in the same order, and no new `{{` or `}}`.
/// Escaped text (`%7B%7Bid%7D%7D`, `%7B{{id}}`, `{{i%64}}`) is data in the
/// source and must never become, or change, a reference the engine
/// resolves.
fn same_references(source: &str, decoded: &str) -> bool {
    template_tokens(source) == template_tokens(decoded)
        && source.matches("{{").count() == decoded.matches("{{").count()
        && source.matches("}}").count() == decoded.matches("}}").count()
}

/// `s` percent-decoded, when it decodes to UTF-8 and keeps its references
/// ([`same_references`]).
fn decode_keeping_references(s: &str) -> Option<String> {
    let decoded = percent_encoding::percent_decode_str(s).decode_utf8().ok()?;
    same_references(s, &decoded).then(|| decoded.into_owned())
}

/// What the engine sends for a stored query parameter name or value: every
/// byte outside `A-Za-z0-9-._~` percent-encoded (`anvil_auth::encode_query_component`).
fn engine_query_encode(s: &str) -> String {
    const QUERY_COMPONENT: &percent_encoding::AsciiSet =
        &percent_encoding::NON_ALPHANUMERIC.remove(b'-').remove(b'_').remove(b'.').remove(b'~');
    percent_encoding::utf8_percent_encode(s, QUERY_COMPONENT).to_string()
}

/// The text to store for a name or value of a source's query parameter list
/// (Postman `url.query`, Insomnia `parameters`), which the source sends with
/// its `%XX` escapes as written. Stored text is encoded once by the engine,
/// so a value with escapes is stored decoded when, and only when, encoding
/// that decoded text gives back exactly the source (`%3A%2F%2F` is stored as
/// `://`) and decoding makes or changes no `{{reference}}`. Anything else is
/// stored as written, as before, and reported (`query_value_not_decoded`)
/// when it holds an escape the engine would encode again.
pub fn listed_query_text(b: &mut Builder, s: &str, pointer: &str) -> String {
    if !s.contains('%') {
        return s.to_string();
    }
    if let Some(decoded) = decode_keeping_references(s)
        && engine_query_encode(&decoded) == s
    {
        return decoded;
    }
    if s.as_bytes().windows(3).any(|w| w[0] == b'%' && w[1].is_ascii_hexdigit() && w[2].is_ascii_hexdigit()) {
        b.report.warn(
            "query_value_not_decoded",
            pointer,
            "this query value has percent escapes that cannot be stored decoded without changing what is sent; it is kept as \
             written, so its '%' is sent as %25: check it before sending",
        );
    }
    s.to_string()
}

/// One entry of a source's query parameter list as stored: its name and
/// value ([`listed_query_text`]), with the credential policy applied by the
/// name as stored or percent-decoded (`%70assword` is a credential name even
/// when it is kept as written). Returns the name, the value and whether the
/// entry is sensitive.
pub fn listed_query_param(b: &mut Builder, raw_name: &str, raw_value: &str, pointer: &str) -> (String, String, bool) {
    let name = listed_query_text(b, raw_name, pointer);
    let value = listed_query_text(b, raw_value, pointer);
    let decoded_name = query_decode(raw_name);
    if !(is_credential_name(&name) || is_credential_name(&decoded_name)) || value.trim().is_empty() {
        return (name, value, false);
    }
    // The placeholder is named after the source spelling as written, never
    // after a decoded name (see [`redact_raw_query`]).
    let value = credential_text(b, &value, raw_name, pointer, &format!("query {name}"));
    (name, value, true)
}

/// What [`take_userinfo`] found in a URL.
pub enum TakenUrl {
    /// No userinfo: the URL as it was.
    Plain(String),
    /// Userinfo taken off: the URL without it, and the userinfo as written.
    Userinfo(String, Userinfo),
    /// The authority holds a `{{…}}` and the URL has an `@`: where the
    /// userinfo ends cannot be told without parsing the template, so the URL
    /// is not cut at all ([`quarantine_url`]).
    Ambiguous,
}

/// Find URL userinfo without parsing templates, by the shared rule
/// ([`anvil_domain::secret::url_userinfo`]): the authority ends at the first
/// `/`, `?` or `#` after `scheme://` (RFC 3986) and the userinfo is
/// everything before its last `@`; a template before that end beside an `@`
/// anywhere makes the URL ambiguous, so it is not cut at all.
pub fn take_userinfo(url: &str, syntax: anvil_domain::secret::TemplateSyntax) -> TakenUrl {
    use anvil_domain::secret::UrlUserinfo;
    match anvil_domain::secret::url_userinfo(url, syntax) {
        UrlUserinfo::None => TakenUrl::Plain(url.to_string()),
        UrlUserinfo::Ambiguous => TakenUrl::Ambiguous,
        UrlUserinfo::Userinfo { start, at } => {
            let stripped = format!("{}{}", &url[..start], &url[at + 1..]);
            if url[start..at].trim().is_empty() {
                TakenUrl::Plain(stripped)
            } else {
                TakenUrl::Userinfo(stripped, url[start..at].to_string())
            }
        }
    }
}

/// An endpoint URL other than the request's (an OAuth token or
/// authorization URL), by the request URL's rule
/// ([`anvil_domain::secret::url_userinfo`]): a userinfo that is not exactly
/// references is taken off and reported (it cannot become Basic auth here),
/// and an ambiguous URL is quarantined ([`quarantine_url`]). With
/// `include_credentials` a literal userinfo is kept, and a sanitized export
/// extracts the whole URL.
pub fn endpoint_url(b: &mut Builder, url: &str, pointer: &str, field: &'static str) -> String {
    use anvil_domain::secret::{UrlUserinfo, is_plain_userinfo, url_userinfo};
    match url_userinfo(url, b.template_syntax) {
        UrlUserinfo::None => url.to_string(),
        UrlUserinfo::Ambiguous => quarantine_url(b, url, pointer),
        UrlUserinfo::Userinfo { start, at } => {
            let userinfo = &url[start..at];
            if userinfo.trim().is_empty() || is_plain_userinfo(userinfo, b.template_syntax) || b.opts.include_credentials {
                return url.to_string();
            }
            b.report.redacted(pointer, format!("credentials in the {field}"), "(removed)");
            b.report.warn(
                "url_credentials_removed",
                pointer,
                Message::new("the ")
                    .text(field)
                    .text(" held credentials in its userinfo; they were not imported (supply them as the client credentials)"),
            );
            format!("{}{}", &url[..start], &url[at + 1..])
        }
    }
}

/// What a name, folder or operation key derived from a quarantined URL
/// shows instead of its text ([`quarantine_url`]).
pub const QUARANTINED_URL_NAME: &str = "<url redacted>";

/// An ambiguous request URL ([`TakenUrl::Ambiguous`]): a template before the
/// end of its authority and an `@`, so where a credential in it ends cannot
/// be told. Nothing in it is parsed or cut, so the request's host cannot
/// change. Unless `include_credentials`, the URL is not imported at all: the
/// request gets a reference bound to the URL's text (`url_<16 hex digits>`,
/// [`literal_name`]), and the original text is stored nowhere. With
/// `include_credentials`, the URL is kept exactly as written. Either way the request is reported
/// (`url_quarantined`).
pub fn quarantine_url(b: &mut Builder, url: &str, pointer: &str) -> String {
    const WHY: &str = "this URL mixes a template with a possible credential in its authority";
    if b.opts.include_credentials {
        b.report.warn(
            "url_quarantined",
            pointer,
            Message::new(WHY).text("; it was kept as written because credentials are included, and may contain a credential"),
        );
        return url.to_string();
    }
    let name = literal_name(b, "url", "url", None, url);
    let reference = format!("{{{{{name}}}}}");
    b.report.redacted(pointer, "request URL", &reference);
    // The placeholder is the import's own name, listed with the redaction.
    b.report.warn(
        "url_quarantined",
        pointer,
        Message::new(WHY).text("; it was not imported (the request uses the placeholder listed in the redactions): re-enter it"),
    );
    reference
}

/// Basic auth from URL userinfo as written ([`take_userinfo`]); the engine
/// never sends credentials in the URL.
///
/// A userinfo that is exactly variable references (`{{user}}`,
/// `{{user}}:`, `{{user}}:{{password}}`, in the source's syntax;
/// [`anvil_domain::secret::is_plain_userinfo`]) keeps them. Anything else is
/// credential material, and no part of it is kept as a user name or in the
/// URL: the user name becomes a placeholder bound to it, and the password
/// one too (with a redaction; an empty password stays empty), or, with
/// `include_credentials`, the literal after the first `:` (the whole
/// userinfo when there is none), kept only in the password, a secret field
/// (`url_userinfo_replaced`).
pub fn userinfo_auth(b: &mut Builder, userinfo: &str, pointer: &str) -> AuthConfig {
    let (user, pass) = userinfo.split_once(':').unwrap_or((userinfo, ""));
    if anvil_domain::secret::is_plain_userinfo(userinfo, b.template_syntax) {
        return AuthConfig::Basic { username: user.to_string(), password: SensitiveValue::template(pass) };
    }
    // Each part is bound to its literal ([`literal_name`]), as an auth
    // secret is.
    let username = if user.is_empty() {
        String::new()
    } else {
        let user_var = literal_name(b, "auth", "username", Some("username"), user);
        b.report.require_var(&user_var, true, "the user name in the URL is not imported", pointer);
        format!("{{{{{user_var}}}}}")
    };
    let password = if b.opts.include_credentials {
        // The password part, or the whole userinfo when it holds an
        // expression or has no (or an empty) password: no part is dropped.
        let literal = match userinfo.split_once(':') {
            Some((_, p)) if !p.trim().is_empty() && !userinfo.contains("{{") => p,
            _ => userinfo,
        };
        SensitiveValue::template(decode_keeping_references(literal).unwrap_or_else(|| literal.to_string()))
    } else if pass.is_empty() {
        // Nothing to bind a placeholder to.
        SensitiveValue::default()
    } else {
        let pass_var = literal_name(b, "auth", "password", Some("password"), pass);
        let placeholder = format!("{{{{{pass_var}}}}}");
        b.report.redacted(pointer, "credentials in the URL", &placeholder);
        b.report.require_var(&pass_var, true, "the credentials in the URL were redacted on import", pointer);
        SensitiveValue::template(placeholder)
    };
    b.report.warn(
        "url_userinfo_replaced",
        pointer,
        "the URL's user name and password are not exactly variable references, so they were taken off the URL and replaced \
         by placeholders to supply (with included credentials, only the password literal is kept, in the auth password)",
    );
    AuthConfig::Basic { username, password }
}

/// Apply URL userinfo to a request whose own auth is `auth`. It becomes
/// Basic auth only when the request inherits its auth. Auth of its own (a
/// cURL `-u`, a Postman or Insomnia auth helper) and an explicit "no auth"
/// win, as curl prefers `-u`; the userinfo, already removed from the URL,
/// is then dropped with a `url_credentials_dropped` warning.
pub fn apply_userinfo(b: &mut Builder, auth: &mut AuthConfig, userinfo: Option<Userinfo>, pointer: &str) {
    let Some(userinfo) = userinfo else { return };
    if matches!(auth, AuthConfig::Inherit) {
        *auth = userinfo_auth(b, &userinfo, pointer);
    } else {
        b.report.warn(
            "url_credentials_dropped",
            pointer,
            "the user name and password in the URL were removed and not imported: the request has auth of its own (or none), \
             which is kept",
        );
    }
}

/// A URL's userinfo as written (`user:password`).
pub type Userinfo = String;

/// Remove a `#fragment`, ignoring `#` inside `{{…}}` references.
pub fn strip_fragment(url: &str) -> &str {
    let bytes = url.as_bytes();
    let mut depth = 0usize;
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i..].starts_with(b"{{") {
            depth += 1;
            i += 2;
            continue;
        }
        if bytes[i..].starts_with(b"}}") && depth > 0 {
            depth -= 1;
            i += 2;
            continue;
        }
        if bytes[i] == b'#' && depth == 0 {
            return &url[..i];
        }
        i += 1;
    }
    url
}

/// Anvil's native dynamic variables (see anvil-engine `vars.rs`).
const NATIVE_DYNAMIC: &[&str] =
    &["uuid", "randomUUID", "guid", "timestamp", "timestampMs", "isoTimestamp", "counter", "randomInt", "randomFrom"];

/// Report `{{$name}}` dynamic variables Anvil does not implement (Postman's
/// faker `$random*` family and others). They are left in place, so the
/// request fails validation visibly instead of sending a wrong value.
pub fn check_dynamic_vars(b: &mut Builder, s: &str, pointer: &str) {
    let mut rest = s;
    while let Some(i) = rest.find("{{$") {
        let after = &rest[i + 3..];
        let Some(end) = after.find("}}") else { break };
        let name = after[..end].split_whitespace().next().unwrap_or("");
        if !NATIVE_DYNAMIC.contains(&name) {
            b.report.unsupported("dynamic_variable", pointer, "a dynamic variable has no Anvil equivalent; replace it before sending");
        }
        rest = &after[end + 2..];
    }
}

/// `Content-Type` value from a header list (last one wins, enabled only).
pub fn header_content_type(headers: &[KeyValue]) -> Option<String> {
    headers.iter().rev().find(|h| h.enabled && h.name.eq_ignore_ascii_case("content-type")).map(|h| h.value.clone())
}

/// Keep the media type a body mapping could not express in its variant (the
/// second value of [`body_from_text`]) as an explicit `Content-Type` header,
/// unless the source already sets one: an explicit header takes precedence.
pub fn keep_declared_content_type(headers: &mut Vec<KeyValue>, declared: Option<String>) {
    if let Some(ct) = declared
        && header_content_type(headers).is_none()
    {
        headers.push(KeyValue::new("Content-Type", ct));
    }
}

/// Drop an explicit `Content-Type` header when the body variant infers the
/// same type, so the engine's inference and the header never disagree.
pub fn dedupe_content_type(headers: &mut Vec<KeyValue>, body: &Body) {
    let inferred = match body {
        Body::Json { .. } => Some("application/json"),
        Body::Xml { .. } => Some("application/xml"),
        Body::FormUrlEncoded { .. } => Some("application/x-www-form-urlencoded"),
        _ => None,
    };
    if let Some(inf) = inferred {
        headers.retain(|h| !(h.name.eq_ignore_ascii_case("content-type") && media_essence(&h.value) == inf && !h.value.contains(';')));
    }
    // Multipart boundaries are computed by the engine; a copied header would
    // carry a stale boundary.
    if matches!(body, Body::Multipart { .. }) {
        headers.retain(|h| !(h.name.eq_ignore_ascii_case("content-type") && media_essence(&h.value) == "multipart/form-data"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_query_pairs() {
        let (b, p) = split_query("https://x/a?b=1&c=%20d#frag");
        assert_eq!(b, "https://x/a");
        assert_eq!(p, vec![("b".into(), "1".into()), ("c".into(), " d".into())]);
        let (b, p) = split_query("https://x/a?flag&b=1");
        assert_eq!(b, "https://x/a?flag&b=1");
        assert!(p.is_empty());
        assert_eq!(strip_fragment("{{base}}/x#y"), "{{base}}/x");
    }
}
