//! Helpers shared by the migration importers (Postman, Insomnia, cURL, HAR):
//! the credential placeholder policy, body mapping by media type, URL/query
//! splitting and dynamic-variable checks.

use crate::builder::Builder;
use crate::util::{has_literal_secret, is_credential_name, is_json_media, is_xml_media, media_essence, sanitize_var};
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

/// Replace credential-looking string members of a JSON body (recursively).
pub fn scrub_json(b: &mut Builder, v: &mut Value, pointer: &str) {
    match v {
        Value::Object(m) => {
            for (k, child) in m.iter_mut() {
                let p = crate::util::ptr(pointer, k);
                if is_credential_name(k)
                    && let Value::String(s) = child
                {
                    let new = credential_text(b, s, k, &p, &format!("body field {k}"));
                    *s = new;
                    continue;
                }
                scrub_json(b, child, &p);
            }
        }
        Value::Array(a) => {
            for (i, child) in a.iter_mut().enumerate() {
                scrub_json(b, child, &format!("{pointer}/{i}"));
            }
        }
        _ => {}
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

/// Split a URL into base (without query/fragment) and decoded query pairs.
/// When some pair has no `=` (or the query is otherwise not a plain list of
/// pairs), the query stays in the URL verbatim and no pairs are returned.
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
            Some((k, v)) if !k.is_empty() => pairs.push((query_decode(k), query_decode(v))),
            _ => return (no_frag.to_string(), vec![]),
        }
    }
    (base.to_string(), pairs)
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
