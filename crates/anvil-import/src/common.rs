//! Helpers shared by the migration importers (Postman, Insomnia, cURL, HAR):
//! the credential placeholder policy, body mapping by media type, URL/query
//! splitting and dynamic-variable checks.

use crate::builder::Builder;
use crate::util::{
    has_literal_secret, is_credential_name, is_json_media, is_numeric_credential_name, is_xml_media, media_essence, sanitize_var,
};
use anvil_domain::auth::AuthConfig;
use anvil_domain::request::{Body, KeyValue};
use anvil_domain::secret::SensitiveValue;
use anvil_domain::workspace::Variable;
use serde_json::Value;

/// Apply the credential policy to a sensitive auth field.
///
/// * a pure `{{variable}}` reference is kept as-is;
/// * an empty value becomes a `{{var}}` placeholder the user must supply;
/// * a literal is kept only with `include_credentials`; otherwise it is
///   replaced by `{{var}}` and recorded as a redaction.
pub fn credential(b: &mut Builder, value: &str, var: &str, pointer: &str, field: &str) -> SensitiveValue {
    SensitiveValue::template(credential_text(b, value, var, pointer, field))
}

/// Same policy as [`credential`] for values stored as plain text (header,
/// query and body fields).
pub fn credential_text(b: &mut Builder, value: &str, var: &str, pointer: &str, field: &str) -> String {
    let t = value.trim();
    if !t.is_empty() && !has_literal_secret(t) {
        return value.to_string();
    }
    let var = sanitize_var(var);
    let placeholder = format!("{{{{{var}}}}}");
    if t.is_empty() {
        b.report.require_var(&var, true, &format!("{field} has no value in the source"), pointer);
        return placeholder;
    }
    if b.opts.include_credentials {
        return value.to_string();
    }
    b.report.redacted(pointer, field, &placeholder);
    b.report.require_var(&var, true, &format!("{field} was redacted on import"), pointer);
    placeholder
}

/// Apply the credential policy to a variable definition. A secret literal
/// is dropped (without `include_credentials`) and listed as a required
/// variable, so references to it fail validation until the user supplies it.
pub fn env_var(b: &mut Builder, key: &str, value: &str, secret: bool, enabled: bool, at: &str) -> Option<Variable> {
    let literal = has_literal_secret(value);
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
                    if is_credential_name(k) {
                        // Everything under a credential name is credential
                        // material, whatever its own members are called
                        // (`"tokens": ["…"]`, `"credentials": {"v": "…"}`).
                        let var = sanitize_var(k);
                        scrub_credential_subtree(b, child, pointer, path, &var);
                    } else {
                        scrub_json_at(b, child, pointer, path);
                    }
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

/// Apply the credential policy to every string leaf under a credential-named
/// member, whatever the leaves are called. Each leaf's placeholder names its
/// place (`tokens_0`, `credentials_v`), so different values stay apart.
fn scrub_credential_subtree(b: &mut Builder, v: &mut Value, pointer: &str, path: &mut Vec<String>, var: &str) {
    match v {
        Value::Object(m) => {
            for (k, child) in m.iter_mut() {
                path.push(segment(k));
                scrub_credential_subtree(b, child, pointer, path, &format!("{var}_{}", sanitize_var(k)));
                path.pop();
            }
        }
        Value::Array(a) => {
            for (i, child) in a.iter_mut().enumerate() {
                path.push(i.to_string());
                scrub_credential_subtree(b, child, pointer, path, &format!("{var}_{i}"));
                path.pop();
            }
        }
        Value::String(s) => {
            let last = path.pop().unwrap_or_default();
            let p = pointer_at(pointer, path, &last);
            path.push(last);
            *s = credential_text(b, s, var, &p, &format!("body field {var}"));
        }
        _ => {}
    }
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
            let why = match e {
                crate::ImportError::LimitExceeded { what, limit } => format!("it exceeds the import limit for {what} ({limit})"),
                _ => "it could not be parsed".to_string(),
            };
            b.report.warn(
                "body_not_scanned",
                pointer,
                format!("JSON body was not scanned for credentials: {why}; review it before sharing"),
            );
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

/// How a source writes the query names and values it holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryForm {
    /// As sent (cURL, HAR, Postman): `%XX` escapes stand for their bytes, and
    /// a `+` or a `%` that starts no escape is sent as it is.
    Wire,
    /// Encoded when sent, its `%XX` escapes kept (Insomnia): `+` and a `%`
    /// that starts no escape are literal characters, encoded as `%2B` and
    /// `%25`.
    Insomnia,
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

/// Percent-decode `s` only when that changes no `{{reference}}`: the same
/// references, in the same order, and no new `{{` or `}}`. Escaped text
/// (`%7B%7Bid%7D%7D`, `%7B{{id}}`, `{{i%64}}`) is data in the source and
/// must never become, or change, a reference the engine resolves. `None`
/// also for escapes that do not decode to UTF-8.
fn decode_keeping_references(s: &str) -> Option<String> {
    let decoded = percent_encoding::percent_decode_str(s).decode_utf8().ok()?;
    let same = template_tokens(s) == template_tokens(&decoded)
        && s.matches("{{").count() == decoded.matches("{{").count()
        && s.matches("}}").count() == decoded.matches("}}").count();
    same.then(|| decoded.into_owned())
}

/// The decoded text Anvil stores for a query name or value the source wrote
/// in `form`. The engine percent-encodes a stored parameter once when it
/// sends it (every byte outside `A-Za-z0-9-._~`), so the request carries
/// what the source sent.
///
/// `None` when no stored text does that: a wire `+` (curl sends it as is,
/// and a form-decoding server reads a space, while a stored `+` is sent as
/// `%2B`), a wire `%` that starts no escape (sent bare, while a stored `%` is
/// sent as `%25`), or decoding [`decode_keeping_references`] refuses.
pub fn decode_query_text(s: &str, form: QueryForm) -> Option<String> {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' if form == QueryForm::Wire => return None,
            b'%' => {
                let escape = bytes.get(i + 1..i + 3).is_some_and(|h| h.iter().all(u8::is_ascii_hexdigit));
                if !escape && form == QueryForm::Wire {
                    return None;
                }
                i += if escape { 3 } else { 1 };
            }
            _ => i += 1,
        }
    }
    decode_keeping_references(s)
}

/// The text to store for a query name or value that must be a parameter,
/// reporting when it does not send exactly what the source sent
/// ([`decode_query_text`] gives `None`):
///
/// * a wire `+` is read as a space, as form-decoding servers read it, and
///   sent as `%20`; a wire `%` that starts no escape is kept and sent as
///   `%25` (`query_value_converted`);
/// * escapes that do not decode to UTF-8, or decoding that would make or
///   change a `{{reference}}`, keep the text as written
///   (`query_param_not_decoded`): it never becomes U+FFFD or a reference.
fn stored_query_text(b: &mut Builder, s: &str, form: QueryForm, pointer: &str) -> String {
    if let Some(decoded) = decode_query_text(s, form) {
        return decoded;
    }
    let spaced = if form == QueryForm::Wire { s.replace('+', " ") } else { s.to_string() };
    if let Some(decoded) = decode_keeping_references(&spaced) {
        b.report.warn(
            "query_value_converted",
            pointer,
            "a query '+' was read as a space, as form-decoding servers read it, and is sent as %20; a '%' that starts no escape \
             is sent as %25",
        );
        return decoded;
    }
    b.report.warn(
        "query_param_not_decoded",
        pointer,
        "this query value is kept as written: it has an escape that is not UTF-8, or decoding it would make or change a \
         {{reference}}; Anvil encodes a parameter when it sends it, so check it before sending",
    );
    s.to_string()
}

/// Whether a query name is a credential name, read as the source tool reads
/// it: as stored, and percent-decoded (with `+` as a space too) whatever is
/// kept, so an escaped spelling (`%70assword`, `api%5Fkey`) is still one.
fn query_credential_name(raw: &str, stored: &str) -> bool {
    is_credential_name(stored) || is_credential_name(&query_decode(raw)) || is_credential_name(&query_decode(&raw.replace('+', " ")))
}

/// [`maybe_redact`] for a query parameter whose credential classification
/// was made from its source spelling ([`query_credential_name`]). The
/// placeholder is named after the decoded source name `raw`.
fn redact_query_value(b: &mut Builder, credential: bool, raw: &str, value: &str, pointer: &str, what: &str) -> (String, bool) {
    if !credential || value.trim().is_empty() {
        return (value.to_string(), false);
    }
    let name = query_decode(raw);
    (credential_text(b, value, &name, pointer, &format!("{what} {name}")), true)
}

/// The non-empty `&` segments of a query, split at the first `=` (`None`
/// for a segment without one, such as a bare `flag`).
fn query_segments(q: &str) -> Vec<(&str, Option<&str>)> {
    q.split('&').filter(|seg| !seg.is_empty()).map(|seg| seg.split_once('=').map_or((seg, None), |(k, v)| (k, Some(v)))).collect()
}

/// Whether a query has a credential-named segment with a value.
fn query_has_credential(q: &str) -> bool {
    query_segments(q).into_iter().any(|(k, v)| v.is_some_and(|v| !v.trim().is_empty()) && query_credential_name(k, k))
}

/// Every segment of `q` as a parameter ([`stored_query_text`]), with the
/// credential policy applied by the source spelling of each name. A bare
/// `flag` becomes a parameter with an empty value, sent as `flag=`
/// (`query_flag_as_param`).
fn structured_query(b: &mut Builder, q: &str, form: QueryForm, pointer_of: impl Fn(usize) -> String, what: &str) -> Vec<KeyValue> {
    let mut out = vec![];
    for (n, (k, v)) in query_segments(q).into_iter().enumerate() {
        let p = pointer_of(n);
        let name = stored_query_text(b, k, form, &p);
        let value = match v {
            Some(v) => stored_query_text(b, v, form, &p),
            None => {
                b.report.warn(
                    "query_flag_as_param",
                    &p,
                    "a query segment without '=' became a parameter with an empty value, sent as 'name='",
                );
                String::new()
            }
        };
        let credential = query_credential_name(k, &name);
        let (value, sensitive) = redact_query_value(b, credential, k, &value, &p, what);
        out.push(KeyValue { name, value, enabled: true, description: String::new(), sensitive });
    }
    out
}

/// Split a URL into base (without query/fragment) and decoded query pairs
/// ([`decode_query_text`], wire form). When some pair has no `=`, or some
/// name or value has no decoded form, no pairs are returned and the base
/// keeps the query as written.
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
        let decoded = match p.split_once('=') {
            Some((k, v)) if !k.is_empty() => decode_query_text(k, QueryForm::Wire).zip(decode_query_text(v, QueryForm::Wire)),
            _ => None,
        };
        match decoded {
            Some(pair) => pairs.push(pair),
            None => return (no_frag.to_string(), vec![]),
        }
    }
    (base.to_string(), pairs)
}

/// The query parameters of a URL's own query (cURL, HAR, a Postman raw URL)
/// and the URL to store (its fragment dropped):
///
/// * decoded pairs ([`split_query`]) when every pair decodes exactly;
/// * otherwise, when a segment has a credential name, every segment as a
///   parameter ([`structured_query`]): a credential in the URL text would be
///   neither marked `sensitive` nor percent-encoded when its placeholder
///   resolves;
/// * otherwise the query stays in the URL exactly as the source sends it
///   (nothing in it needs the credential policy).
///
/// `pointer_of(n)` locates segment `n`.
pub fn url_query_params(b: &mut Builder, url: &str, pointer_of: impl Fn(usize) -> String, what: &str) -> (String, Vec<KeyValue>) {
    let (base, pairs) = split_query(url);
    if !pairs.is_empty() || !base.contains('?') {
        let params = pairs
            .into_iter()
            .enumerate()
            .map(|(n, (k, v))| {
                let (value, sensitive) = maybe_redact(b, &k, &v, &pointer_of(n), what);
                KeyValue { name: k, value, enabled: true, description: String::new(), sensitive }
            })
            .collect();
        return (base, params);
    }
    let (path, query) = base.split_once('?').unwrap_or((base.as_str(), ""));
    if query_has_credential(query) {
        return (path.to_string(), structured_query(b, query, QueryForm::Wire, pointer_of, what));
    }
    (base, vec![])
}

/// For a URL whose query is otherwise kept as written (Insomnia): when the
/// query has a credential-named segment, the URL without its query and that
/// query's segments as parameters ([`structured_query`]), for the reasons
/// [`url_query_params`] gives. Otherwise the URL unchanged.
pub fn credential_query_params(
    b: &mut Builder,
    url: &str,
    form: QueryForm,
    pointer_of: impl Fn(usize) -> String,
    what: &str,
) -> (String, Vec<KeyValue>) {
    let no_frag = strip_fragment(url);
    match no_frag.split_once('?') {
        Some((path, query)) if query_has_credential(query) => (path.to_string(), structured_query(b, query, form, pointer_of, what)),
        _ => (url.to_string(), vec![]),
    }
}

/// One entry of a source's query parameter list (Postman `url.query`,
/// Insomnia `parameters`), as the source wrote it.
pub struct ListedParam {
    pub name: String,
    /// `None` for an entry without a value (`?flag`).
    pub value: Option<String>,
    pub enabled: bool,
    pub description: String,
    pub pointer: String,
}

/// Map a source's query parameter list to request parameters holding decoded
/// text ([`stored_query_text`]), applying the credential policy by the
/// source spelling of each name ([`query_credential_name`]). Every entry
/// stays a parameter: the engine encodes its name and value after resolving
/// any `{{reference}}`, so a `&`, `#` or `=` in them (literal or resolved)
/// never becomes query structure, and a credential keeps its `sensitive`
/// mark.
pub fn listed_query_params(b: &mut Builder, list: Vec<ListedParam>, form: QueryForm) -> Vec<KeyValue> {
    let mut out = vec![];
    for p in list {
        let name = stored_query_text(b, &p.name, form, &p.pointer);
        let value = match &p.value {
            Some(v) => stored_query_text(b, v, form, &p.pointer),
            None => String::new(),
        };
        let credential = query_credential_name(&p.name, &name);
        let (value, sensitive) = redact_query_value(b, credential, &p.name, &value, &p.pointer, "query");
        out.push(KeyValue { name, value, enabled: p.enabled, description: p.description, sensitive });
    }
    out
}

/// Split URL userinfo (`user:password@`) off `url`: the URL without it, and
/// the user name and password as written (percent-encoded). A URL without a
/// scheme is read from its start (Postman and Insomnia accept
/// `user:pw@host/path`). The userinfo ends at the last `@` of the authority
/// ([`userinfo_end`]).
pub fn take_userinfo(url: &str) -> (String, Option<(String, String)>) {
    let (prefix, rest) = match url.split_once("://") {
        Some((scheme, rest)) if !scheme.is_empty() && !scheme.contains(['/', '?', '#', '@']) => (&url[..scheme.len() + 3], rest),
        _ => ("", url),
    };
    let Some(at) = userinfo_end(rest) else { return (url.to_string(), None) };
    let userinfo = &rest[..at];
    let (user, pass) = userinfo.split_once(':').unwrap_or((userinfo, ""));
    (format!("{prefix}{}", &rest[at + 1..]), Some((user.to_string(), pass.to_string())))
}

/// Basic auth from URL userinfo as written ([`take_userinfo`]): the engine
/// never sends credentials in the URL, and the password follows the
/// credential policy (a `{{password}}` placeholder and a redaction unless
/// `include_credentials`).
///
/// Each part is percent-decoded only when that keeps its `{{references}}`
/// ([`decode_keeping_references`]): escaped text never becomes a reference
/// the engine resolves. A user name that cannot be decoded so is kept as
/// written (`url_user_not_decoded`); such a password cannot be stored at
/// all, so it becomes a required `{{password}}` in either credential mode
/// (`url_password_not_decoded`).
pub fn userinfo_auth(b: &mut Builder, user: &str, pass: &str, pointer: &str) -> AuthConfig {
    let username = decode_keeping_references(user).unwrap_or_else(|| {
        b.report.warn(
            "url_user_not_decoded",
            pointer,
            "the user name in the URL is kept percent-encoded: decoding it would make or change a {{reference}}, or it is not UTF-8",
        );
        user.to_string()
    });
    let password = match decode_keeping_references(pass) {
        Some(pass) => credential(b, &pass, "password", pointer, "password in the URL"),
        None => {
            b.report.warn(
                "url_password_not_decoded",
                pointer,
                "the password in the URL was not imported: decoding it would make or change a {{reference}}, or it is not UTF-8; \
                 supply it as the variable 'password'",
            );
            b.report.redacted(pointer, "password in the URL", "{{password}}");
            b.report.require_var("password", true, "password in the URL could not be imported", pointer);
            SensitiveValue::template("{{password}}")
        }
    };
    AuthConfig::Basic { username, password }
}

/// Apply URL userinfo to a request whose own auth is `auth`: it becomes
/// Basic auth when the request has none of its own (`inherit` or none);
/// otherwise the request's auth is kept, and the userinfo, already removed
/// from the URL, is dropped with a `url_credentials_dropped` warning.
pub fn apply_userinfo(b: &mut Builder, auth: &mut AuthConfig, userinfo: Option<(String, String)>, pointer: &str) {
    let Some((user, pass)) = userinfo else { return };
    if matches!(auth, AuthConfig::Inherit | AuthConfig::None) {
        *auth = userinfo_auth(b, &user, &pass, pointer);
    } else {
        b.report.warn(
            "url_credentials_dropped",
            pointer,
            "the user name and password in the URL were removed and not imported: the request has its own auth, which is kept",
        );
    }
}

/// The byte offset of the `@` that ends the userinfo in `after_scheme` (a
/// URL with its `scheme://` removed), if it has userinfo. The authority ends
/// at the first `/`, `?` or `#` (RFC 3986 section 3.2), so an `@` in the
/// path, query or fragment is not one; within the authority the last `@`
/// ends the userinfo, as URL parsers (and Postman's) read a password that
/// holds an `@`.
pub fn userinfo_end(after_scheme: &str) -> Option<usize> {
    let authority_end = after_scheme.find(['/', '?', '#']).unwrap_or(after_scheme.len());
    after_scheme[..authority_end].rfind('@')
}

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
            b.report.unsupported(
                "dynamic_variable",
                pointer,
                format!("dynamic variable '{{{{${name}}}}}' has no Anvil equivalent; replace it before sending"),
            );
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
