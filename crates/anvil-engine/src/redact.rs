//! Redaction for evidence, history, logs and safe-share exports.
//!
//! Two layers: (1) known-sensitive names (headers, query parameters, cookie
//! and JSON field names) and (2) exact-value scrubbing of every secret value
//! resolved during the execution. Arbitrary content can still contain
//! secrets Anvil cannot recognize; exports show a preview for that reason.

use anvil_domain::execution::HeaderEntry;
use anvil_domain::secret::REDACTED;

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
    secrets: Vec<String>,
    extra_names: Vec<String>,
}

impl Redactor {
    pub fn new(mut secrets: Vec<String>, extra_names: Vec<String>) -> Self {
        // Longest first so overlapping values are fully covered; ignore
        // trivially short values that would shred ordinary text.
        secrets.retain(|s| s.len() >= 4);
        secrets.sort_by_key(|s| std::cmp::Reverse(s.len()));
        secrets.dedup();
        Redactor { secrets, extra_names }
    }

    pub fn add_secret(&mut self, s: &str) {
        if s.len() >= 4 && !self.secrets.iter().any(|x| x == s) {
            self.secrets.push(s.to_string());
            self.secrets.sort_by_key(|s| std::cmp::Reverse(s.len()));
        }
    }

    /// Scrub exact secret values from arbitrary text.
    pub fn text(&self, s: &str) -> String {
        let mut out = s.to_string();
        for v in &self.secrets {
            if out.contains(v.as_str()) {
                out = out.replace(v.as_str(), REDACTED);
            }
        }
        out
    }

    pub fn header(&self, name: &str, value: &str) -> String {
        if is_sensitive_name(name, &self.extra_names) {
            // Keep the scheme word for Authorization-like headers (e.g. "Bearer").
            let lower = name.to_ascii_lowercase();
            if lower == "authorization" || lower == "proxy-authorization" {
                if let Some((scheme, _)) = value.split_once(' ') {
                    return format!("{scheme} {REDACTED}");
                }
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
        self.text(value)
    }

    pub fn headers(&self, h: &[HeaderEntry]) -> Vec<HeaderEntry> {
        h.iter().map(|e| HeaderEntry { name: e.name.clone(), value: self.header(&e.name, &e.value) }).collect()
    }

    /// Redact sensitive query parameter values (and secret values) in a URL.
    pub fn url(&self, u: &str) -> String {
        let (base, frag) = match u.split_once('#') {
            Some((b, f)) => (b, Some(f)),
            None => (u, None),
        };
        let out = match base.split_once('?') {
            Some((path, q)) => {
                let parts: Vec<String> = q
                    .split('&')
                    .map(|kv| match kv.split_once('=') {
                        Some((k, v)) => {
                            let dk = percent_encoding::percent_decode_str(k).decode_utf8_lossy();
                            if is_sensitive_name(&dk, &self.extra_names) {
                                format!("{k}={REDACTED}")
                            } else {
                                format!("{k}={}", self.text(v))
                            }
                        }
                        None => kv.to_string(),
                    })
                    .collect();
                format!("{}?{}", self.text(path), parts.join("&"))
            }
            None => self.text(base),
        };
        // Userinfo in the authority is always sensitive.
        let out = redact_userinfo(&out);
        match frag {
            Some(f) => format!("{out}#{}", self.text(f)),
            None => out,
        }
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
