//! Moves sensitive literals out of the object graph before export.
//!
//! Every `SensitiveValue::Template` literal (auth passwords, tokens, private
//! keys…), every *secret* variable value, and every sensitive-named header,
//! query or form field with a literal value is replaced by a `{{placeholder}}`
//! reference. The originals are returned so encrypted bundles can carry them
//! in the authenticated vault and restore them on import. `objects.json`
//! therefore never contains secret material, in any export mode.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Extracted {
    /// JSON Pointer into `objects.json`.
    pub pointer: String,
    /// Placeholder variable name written in place of the value.
    pub placeholder: String,
    pub value: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContentWarning {
    pub pointer: String,
    pub reason: String,
}

const SENSITIVE_PARTS: &[&str] = &[
    "password",
    "passwd",
    "secret",
    "token",
    "apikey",
    "api_key",
    "api-key",
    "authorization",
    "cookie",
    "session",
    "private",
    "credential",
    "signature",
    "x-api-key",
];

pub fn sensitive_name(n: &str) -> bool {
    let l = n.to_ascii_lowercase();
    SENSITIVE_PARTS.iter().any(|p| l.contains(p))
}

fn is_pure_reference(s: &str) -> bool {
    let t = s.trim();
    t.is_empty() || (t.starts_with("{{") && t.ends_with("}}") && t.matches("{{").count() == 1)
}

fn escape_ptr(s: &str) -> String {
    s.replace('~', "~0").replace('/', "~1")
}

fn placeholder_name(hint: &str) -> String {
    let mut out: String = hint.chars().map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_lowercase() } else { '_' }).collect();
    while out.contains("__") {
        out = out.replace("__", "_");
    }
    let out = out.trim_matches('_').to_string();
    if out.is_empty() { "secret_value".into() } else { format!("secret_{out}") }
}

/// Patterns that suggest credentials inside free text (bodies, URLs).
fn looks_like_credential(s: &str) -> Option<&'static str> {
    use std::sync::OnceLock;
    static RE: OnceLock<Vec<(regex::Regex, &'static str)>> = OnceLock::new();
    let res = RE.get_or_init(|| {
        vec![
            (regex::Regex::new(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}").unwrap(), "looks like a JWT"),
            (regex::Regex::new(r"(?i)bearer\s+[A-Za-z0-9._~+/-]{16,}").unwrap(), "contains a bearer token"),
            (regex::Regex::new(r"AKIA[0-9A-Z]{16}").unwrap(), "looks like an AWS access key id"),
            (regex::Regex::new(r"-----BEGIN [A-Z ]*PRIVATE KEY-----").unwrap(), "contains a private key"),
            (
                regex::Regex::new(r#"(?i)"(password|passwd|secret|token|api_?key)"\s*:\s*"[^"{]{3,}""#).unwrap(),
                "contains a credential-named JSON field",
            ),
        ]
    });
    res.iter().find(|(r, _)| r.is_match(s)).map(|(_, why)| *why)
}

pub struct Sanitized {
    pub extracted: Vec<Extracted>,
    pub warnings: Vec<ContentWarning>,
}

/// Walk `objects.json` and replace sensitive literals in place.
pub fn sanitize(v: &mut serde_json::Value) -> Sanitized {
    let mut s = Sanitized { extracted: vec![], warnings: vec![] };
    walk(v, String::new(), "", &mut s);
    s
}

fn walk(v: &mut serde_json::Value, ptr: String, key: &str, s: &mut Sanitized) {
    match v {
        serde_json::Value::Object(map) => {
            // SensitiveValue::Template  => {"kind":"template","value": "..."}
            let is_template = map.get("kind").and_then(|k| k.as_str()) == Some("template")
                && map.len() == 2
                && map.get("value").map(|x| x.is_string()).unwrap_or(false);
            if is_template {
                let val = map["value"].as_str().unwrap_or("").to_string();
                if !is_pure_reference(&val) {
                    let ph = placeholder_name(key);
                    s.extracted.push(Extracted { pointer: format!("{ptr}/value"), placeholder: ph.clone(), value: val });
                    map.insert("value".into(), serde_json::Value::String(format!("{{{{{ph}}}}}")));
                }
                return;
            }
            // Variable => {"name", "value": SensitiveValue, "secret": bool, ...}
            let is_variable =
                map.contains_key("name") && map.contains_key("secret") && map.get("value").map(|x| x.is_object()).unwrap_or(false);
            if is_variable {
                let secret = map.get("secret").and_then(|b| b.as_bool()).unwrap_or(false);
                let name = map.get("name").and_then(|n| n.as_str()).unwrap_or("").to_string();
                if let Some(val) = map.get_mut("value") {
                    let is_tpl = val.get("kind").and_then(|k| k.as_str()) == Some("template");
                    let text = val.get("value").and_then(|x| x.as_str()).unwrap_or("").to_string();
                    if secret && is_tpl && !is_pure_reference(&text) {
                        s.extracted.push(Extracted { pointer: format!("{ptr}/value/value"), placeholder: String::new(), value: text });
                        val["value"] = serde_json::Value::String(String::new());
                    } else if !secret
                        && is_tpl
                        && (sensitive_name(&name) || looks_like_credential(&text).is_some())
                        && !text.is_empty()
                        && !is_pure_reference(&text)
                    {
                        s.warnings.push(ContentWarning {
                            pointer: ptr.clone(),
                            reason: format!("variable '{name}' looks sensitive but is not marked secret; it is exported as-is"),
                        });
                    }
                }
                return;
            }
            // KeyValue => {"name": .., "value": "<string>", "enabled": ..}
            let is_kv = map.contains_key("name") && map.get("value").map(|x| x.is_string()).unwrap_or(false) && map.contains_key("enabled");
            if is_kv {
                let name = map.get("name").and_then(|n| n.as_str()).unwrap_or("").to_string();
                let flagged = map.get("sensitive").and_then(|b| b.as_bool()).unwrap_or(false);
                let val = map["value"].as_str().unwrap_or("").to_string();
                if (flagged || sensitive_name(&name)) && !is_pure_reference(&val) {
                    let ph = placeholder_name(&name);
                    s.extracted.push(Extracted { pointer: format!("{ptr}/value"), placeholder: ph.clone(), value: val });
                    map.insert("value".into(), serde_json::Value::String(format!("{{{{{ph}}}}}")));
                } else if let Some(why) = looks_like_credential(&val) {
                    s.warnings.push(ContentWarning { pointer: ptr.clone(), reason: format!("'{name}' {why}") });
                }
                return;
            }
            let keys: Vec<String> = map.keys().cloned().collect();
            for k in keys {
                let child_ptr = format!("{ptr}/{}", escape_ptr(&k));
                // Free-text fields are scanned, not modified.
                if let Some(serde_json::Value::String(text)) = map.get(&k) {
                    if matches!(k.as_str(), "text" | "url" | "query" | "envelope" | "variables" | "extra_json")
                        && let Some(why) = looks_like_credential(text)
                    {
                        s.warnings.push(ContentWarning {
                            pointer: child_ptr.clone(),
                            reason: format!("{k} {why}; it is exported as written — review it or use encrypted transfer"),
                        });
                    }
                    continue;
                }
                if let Some(child) = map.get_mut(&k) {
                    walk(child, child_ptr, &k, s);
                }
            }
        }
        serde_json::Value::Array(a) => {
            for (i, x) in a.iter_mut().enumerate() {
                walk(x, format!("{ptr}/{i}"), key, s);
            }
        }
        _ => {}
    }
}

/// Text [`sanitize`] writes in place of an extracted value: `{{placeholder}}`,
/// or an empty string for a secret variable.
fn placeholder_text(placeholder: &str) -> String {
    if placeholder.is_empty() { String::new() } else { format!("{{{{{placeholder}}}}}") }
}

/// Put extracted values back (after decrypting an encrypted bundle).
///
/// Each value goes back only to the exact pointer it was taken from, and
/// only while that field still holds the text [`sanitize`] wrote there. A
/// pointer that is missing, or whose field holds anything else (as a field
/// already restored by an earlier value usually does), refuses the whole
/// restore and leaves `v` unchanged.
pub fn restore(v: &mut serde_json::Value, extracted: &[Extracted]) -> Result<(), String> {
    let mut restored = v.clone();
    for e in extracted {
        match restored.pointer_mut(&e.pointer) {
            Some(serde_json::Value::String(slot)) if *slot == placeholder_text(&e.placeholder) => *slot = e.value.clone(),
            Some(_) => return Err(format!("encrypted vault refers to {}, which does not hold its placeholder", e.pointer)),
            None => return Err(format!("encrypted vault refers to {} which does not exist in the bundle", e.pointer)),
        }
    }
    *v = restored;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaces_literals_keeps_references_and_restores() {
        let mut v = serde_json::json!({
            "requests": [{
                "spec": {
                    "auth": {"type": "basic", "username": "bob", "password": {"kind": "template", "value": "hunter2"}},
                    "headers": [
                        {"name": "X-API-Key", "value": "k-123", "enabled": true},
                        {"name": "Authorization", "value": "{{token}}", "enabled": true},
                        {"name": "Accept", "value": "application/json", "enabled": true}
                    ]
                }
            }],
            "environments": [{"variables": [
                {"name": "host", "value": {"kind": "template", "value": "api.example.com"}, "secret": false, "enabled": true},
                {"name": "db_pw", "value": {"kind": "template", "value": "s3cr3t"}, "secret": true, "enabled": true}
            ]}]
        });
        let original = v.clone();
        let s = sanitize(&mut v);
        let text = v.to_string();
        for leaked in ["hunter2", "k-123", "s3cr3t"] {
            assert!(!text.contains(leaked), "{leaked} leaked");
        }
        assert!(text.contains("{{token}}"), "pure references stay");
        assert!(text.contains("api.example.com"), "non-secret variables stay");
        assert_eq!(s.extracted.len(), 3);
        restore(&mut v, &s.extracted).unwrap();
        assert_eq!(v, original);
    }

    #[test]
    fn values_are_restored_only_over_their_placeholders() {
        let mut v = serde_json::json!({
            "requests": [{
                "spec": {
                    "url": "https://api.example.com/",
                    "auth": {"type": "basic", "username": "bob", "password": {"kind": "template", "value": "hunter2"}}
                }
            }],
            "environments": [{"variables": [
                {"name": "db_pw", "value": {"kind": "template", "value": "s3cr3t"}, "secret": true, "enabled": true}
            ]}]
        });
        let s = sanitize(&mut v);
        assert_eq!(s.extracted.len(), 2);
        let sanitized = v.clone();
        let pw = s.extracted.iter().position(|e| e.placeholder == "secret_password").unwrap();
        let with = |pointer: &str, placeholder: &str| {
            let mut e = s.extracted.clone();
            e[pw] = Extracted { pointer: pointer.into(), placeholder: placeholder.into(), value: "hunter2".into() };
            e
        };
        let refused = [
            // Another field, whatever placeholder is claimed for it.
            with("/requests/0/spec/url", "secret_password"),
            with("/requests/0/spec/auth/username", ""),
            // Not a string, or not there at all.
            with("/requests/0/spec/auth", "secret_password"),
            with("", ""),
            with("/requests/1/spec/auth/password/value", "secret_password"),
            // The right field under another placeholder.
            with("/requests/0/spec/auth/password/value", "secret_other"),
            with("/requests/0/spec/auth/password/value", ""),
            // The same field twice.
            vec![s.extracted[pw].clone(), s.extracted[pw].clone()],
        ];
        for extracted in refused {
            let mut target = sanitized.clone();
            assert!(restore(&mut target, &extracted).is_err(), "{extracted:?}");
            assert_eq!(target, sanitized, "a refused restore changed nothing: {extracted:?}");
        }
        restore(&mut v, &s.extracted).unwrap();
        assert!(v.to_string().contains("hunter2") && v.to_string().contains("s3cr3t"));
    }

    #[test]
    fn free_text_credentials_are_warned_not_modified() {
        let mut v = serde_json::json!({"requests": [{"spec": {"body": {"type": "json", "text": "{\"password\":\"abc123\"}"}}}]});
        let s = sanitize(&mut v);
        assert_eq!(s.warnings.len(), 1);
        assert!(v.to_string().contains("abc123"));
    }
}
