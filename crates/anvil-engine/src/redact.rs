//! Redaction for evidence, history, logs and safe-share exports.
//!
//! Two layers: (1) known-sensitive names (headers, query parameters, cookie
//! and JSON field names, plus any request field the user marked sensitive)
//! and (2) exact-value scrubbing of every secret value resolved during the
//! execution, including its canonical percent-encoded forms. URL components
//! are percent-decoded before they are compared, so an encoded secret is
//! replaced whole rather than left in a reversible form. Arbitrary content
//! can still contain secrets Anvil cannot recognize; exports show a preview
//! for that reason.

use crate::vars::Resolver;
use anvil_domain::execution::HeaderEntry;
use anvil_domain::secret::REDACTED;

/// Shorter values are not exact-value scrubbed: they would shred ordinary
/// text. Name-based redaction still applies to them.
const MIN_SECRET_LEN: usize = 4;

/// Percent-decoding rounds applied to one URL component (covers values that
/// were encoded more than once).
const MAX_DECODE_ROUNDS: usize = 3;

/// Headers whose values are URLs (and so may carry encoded query values).
const URL_HEADERS: &[&str] = &["location", "content-location", "referer"];

const SENSITIVE_HEADERS: &[&str] = &[
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

const SENSITIVE_NAME_PARTS: &[&str] = &[
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

pub fn is_sensitive_name(name: &str, extra: &[String]) -> bool {
    let n = name.to_ascii_lowercase();
    if SENSITIVE_HEADERS.contains(&n.as_str()) || extra.iter().any(|e| e.eq_ignore_ascii_case(&n)) {
        return true;
    }
    SENSITIVE_NAME_PARTS.iter().any(|p| n == *p || n.contains(p) && n.len() <= 48)
}

#[derive(Clone, Default)]
pub struct Redactor {
    /// Secret values, longest first (compared against decoded URL components).
    secrets: Vec<String>,
    /// Secret values and their canonical percent-encoded forms, longest first
    /// (scrubbed from arbitrary text).
    patterns: Vec<String>,
    extra_names: Vec<String>,
}

impl Redactor {
    pub fn new(secrets: Vec<String>, extra_names: Vec<String>) -> Self {
        let mut r = Redactor { secrets, patterns: vec![], extra_names };
        r.secrets.retain(|s| s.len() >= MIN_SECRET_LEN);
        r.reindex();
        r
    }

    /// The redactor for one execution: every secret value the resolver
    /// substituted or saw in a sensitive field, the configured names, and the
    /// names of the request fields marked sensitive.
    pub fn for_execution(r: &Resolver, names: &[String]) -> Self {
        let mut all = names.to_vec();
        for n in r.sensitive_names.lock().iter() {
            if !all.iter().any(|x| x.eq_ignore_ascii_case(n)) {
                all.push(n.clone());
            }
        }
        Redactor::new(r.used_secrets.lock().clone(), all)
    }

    /// Longest first so overlapping values are fully covered.
    fn reindex(&mut self) {
        sort_longest_first(&mut self.secrets);
        let mut patterns = Vec::with_capacity(self.secrets.len() * 4);
        for s in &self.secrets {
            patterns.push(s.clone());
            patterns.extend(encoded_forms(s));
        }
        sort_longest_first(&mut patterns);
        self.patterns = patterns;
    }

    pub fn add_secret(&mut self, s: &str) {
        if s.len() >= MIN_SECRET_LEN && !self.secrets.iter().any(|x| x == s) {
            self.secrets.push(s.to_string());
            self.reindex();
        }
    }

    /// Scrub exact secret values (and their canonical encoded forms) from
    /// arbitrary text.
    pub fn text(&self, s: &str) -> String {
        let mut out = s.to_string();
        for v in &self.patterns {
            if out.contains(v.as_str()) {
                out = out.replace(v.as_str(), REDACTED);
            }
        }
        out
    }

    /// True when a URL component, once percent-decoded (and with `+` read as
    /// a space), contains a secret value. Raw occurrences are scrubbed by
    /// [`Redactor::text`] before components are examined.
    fn hides_secret(&self, component: &str) -> bool {
        if self.secrets.is_empty() || !component.contains(['%', '+']) {
            return false;
        }
        let mut layer: Vec<u8> = component.as_bytes().to_vec();
        for _ in 0..MAX_DECODE_ROUNDS {
            let decoded: Vec<u8> = percent_encoding::percent_decode(&layer).collect();
            let plus: Vec<u8> = layer.iter().map(|&b| if b == b'+' { b' ' } else { b }).collect();
            let form: Vec<u8> = percent_encoding::percent_decode(&plus).collect();
            if self.secrets.iter().any(|s| contains_bytes(&decoded, s.as_bytes()) || contains_bytes(&form, s.as_bytes())) {
                return true;
            }
            if decoded == layer {
                break;
            }
            layer = decoded;
        }
        false
    }

    pub fn header(&self, name: &str, value: &str) -> String {
        if is_sensitive_name(name, &self.extra_names) {
            // Keep the scheme word for Authorization-like headers (e.g. "Bearer").
            let lower = name.to_ascii_lowercase();
            if (lower == "authorization" || lower == "proxy-authorization")
                && let Some((scheme, _)) = value.split_once(' ')
            {
                return format!("{scheme} {REDACTED}");
            }
            if lower == "cookie" {
                return value
                    .split(';')
                    .map(|c| match c.split_once('=') {
                        Some((k, _)) => format!("{}={REDACTED}", k.trim()),
                        None => REDACTED.to_string(),
                    })
                    .collect::<Vec<_>>()
                    .join("; ");
            }
            if lower == "set-cookie" {
                return match value.split_once('=') {
                    Some((k, rest)) => {
                        let attrs = rest.split_once(';').map(|(_, a)| format!(";{a}")).unwrap_or_default();
                        format!("{}={REDACTED}{attrs}", k.trim())
                    }
                    None => REDACTED.to_string(),
                };
            }
            return REDACTED.to_string();
        }
        if URL_HEADERS.iter().any(|h| name.eq_ignore_ascii_case(h)) {
            return self.url(value);
        }
        self.text(value)
    }

    pub fn headers(&self, h: &[HeaderEntry]) -> Vec<HeaderEntry> {
        h.iter().map(|e| HeaderEntry { name: e.name.clone(), value: self.header(&e.name, &e.value) }).collect()
    }

    /// Redact sensitive query parameter values and secret values in a URL.
    /// Path segments, query names and values and the fragment are compared
    /// after percent-decoding; a component that hides a secret is replaced
    /// whole, so no reversible encoding of it survives.
    pub fn url(&self, u: &str) -> String {
        let u = self.text(u);
        let (base, frag) = match u.split_once('#') {
            Some((b, f)) => (b, Some(f)),
            None => (u.as_str(), None),
        };
        let (before_query, query) = match base.split_once('?') {
            Some((p, q)) => (p, Some(q)),
            None => (base, None),
        };
        let mut out = self.url_path(before_query);
        if let Some(q) = query {
            let parts: Vec<String> = q
                .split('&')
                .map(|kv| match kv.split_once('=') {
                    Some((k, v)) => {
                        let dk = percent_encoding::percent_decode_str(k).decode_utf8_lossy();
                        let k = if self.hides_secret(k) { REDACTED } else { k };
                        if is_sensitive_name(&dk, &self.extra_names) || self.hides_secret(v) {
                            format!("{k}={REDACTED}")
                        } else {
                            format!("{k}={v}")
                        }
                    }
                    None if self.hides_secret(kv) => REDACTED.to_string(),
                    None => kv.to_string(),
                })
                .collect();
            out = format!("{out}?{}", parts.join("&"));
        }
        // Userinfo in the authority is always sensitive.
        let out = redact_userinfo(&out);
        match frag {
            Some(f) if self.hides_secret(f) => format!("{out}#{REDACTED}"),
            Some(f) => format!("{out}#{f}"),
            None => out,
        }
    }

    /// `scheme://authority/path` (or a bare path) with every path segment that
    /// hides a secret replaced.
    fn url_path(&self, s: &str) -> String {
        let (prefix, path) = match s.split_once("://") {
            Some((scheme, rest)) => {
                let end = rest.find('/').unwrap_or(rest.len());
                (format!("{scheme}://{}", &rest[..end]), &rest[end..])
            }
            None => (String::new(), s),
        };
        let path: Vec<&str> = path.split('/').map(|seg| if self.hides_secret(seg) { REDACTED } else { seg }).collect();
        format!("{prefix}{}", path.join("/"))
    }

    /// Redact sensitive JSON fields (by name) and secret values in a JSON body.
    pub fn json_text(&self, body: &str) -> String {
        match serde_json::from_str::<serde_json::Value>(body) {
            Ok(mut v) => {
                self.json_value(&mut v, 0);
                self.text(&serde_json::to_string(&v).unwrap_or_default())
            }
            Err(_) => self.text(body),
        }
    }

    fn json_value(&self, v: &mut serde_json::Value, depth: usize) {
        if depth > 64 {
            return;
        }
        match v {
            serde_json::Value::Object(m) => {
                for (k, val) in m.iter_mut() {
                    if is_sensitive_name(k, &self.extra_names) && (val.is_string() || val.is_number()) {
                        *val = serde_json::Value::String(REDACTED.into());
                    } else {
                        self.json_value(val, depth + 1);
                    }
                }
            }
            serde_json::Value::Array(a) => a.iter_mut().for_each(|x| self.json_value(x, depth + 1)),
            _ => {}
        }
    }
}

/// Longest first; equal lengths in a stable order so duplicates are adjacent.
fn sort_longest_first(v: &mut Vec<String>) {
    v.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
    v.dedup();
}

/// The encodings Anvil and common clients produce for a value placed in a
/// URL: RFC 3986 component encoding (upper- and lower-case hex) and
/// `application/x-www-form-urlencoded`.
fn encoded_forms(s: &str) -> Vec<String> {
    let upper = crate::prepare::encode_component(s);
    let lower = lower_hex(&upper);
    let form: String = url::form_urlencoded::byte_serialize(s.as_bytes()).collect();
    [upper, lower, form].into_iter().filter(|f| f != s).collect()
}

fn lower_hex(encoded: &str) -> String {
    let mut out = String::with_capacity(encoded.len());
    let mut hex_left = 0;
    for c in encoded.chars() {
        if hex_left > 0 {
            out.push(c.to_ascii_lowercase());
            hex_left -= 1;
        } else {
            if c == '%' {
                hex_left = 2;
            }
            out.push(c);
        }
    }
    out
}

fn contains_bytes(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.len() >= needle.len() && hay.windows(needle.len()).any(|w| w == needle)
}

fn redact_userinfo(u: &str) -> String {
    if let Some((scheme, rest)) = u.split_once("://") {
        let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let authority = &rest[..authority_end];
        if let Some(at) = authority.rfind('@') {
            return format!("{scheme}://{REDACTED}@{}{}", &authority[at + 1..], &rest[authority_end..]);
        }
    }
    u.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_002_query_and_header_redaction() {
        let r = Redactor::new(vec!["planted-secret-123".into()], vec![]);
        assert_eq!(r.url("https://h/x?api_key=planted-secret-123&page=2"), format!("https://h/x?api_key={REDACTED}&page=2"));
        assert_eq!(r.header("Authorization", "Bearer abc.def"), format!("Bearer {REDACTED}"));
        assert_eq!(r.header("X-Custom", "v=planted-secret-123"), format!("v={REDACTED}"));
        assert_eq!(r.header("Cookie", "a=1; session=zzz"), format!("a={REDACTED}; session={REDACTED}"));
        assert_eq!(r.url("https://user:pw@h/p"), format!("https://{REDACTED}@h/p"));
    }

    #[test]
    fn data_020_json_body_fields_and_values() {
        let r = Redactor::new(vec!["value-in-body-xyz".into()], vec!["customer_ssn".into()]);
        let out = r.json_text(r#"{"password":"hunter2","nested":{"customer_ssn":"123"},"note":"value-in-body-xyz","ok":"fine"}"#);
        assert!(!out.contains("hunter2") && !out.contains("123\"") && !out.contains("value-in-body-xyz"));
        assert!(out.contains("fine"));
    }
}
