//! Moves sensitive literals out of the object graph before export.
//!
//! Every `SensitiveValue::Template` literal (auth passwords, tokens, private
//! keys…), every *secret* variable value, and every header, query or form
//! field with a literal value that is flagged `sensitive` or whose name is a
//! credential name ([`sensitive_name`]) is replaced by a `{{placeholder}}`
//! reference. The originals are returned so encrypted bundles can carry them
//! in the authenticated vault and restore them on import. `objects.json`
//! therefore never contains secret material, in any export mode.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

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

/// Whether a field or variable named `name` holds a secret for export:
/// any name the engine, the importer or the user's extra redaction names
/// (`extra`) treat as a credential
/// ([`anvil_domain::credential_names::is_export_secret_name`]).
pub fn sensitive_name(name: &str, extra: &[String]) -> bool {
    anvil_domain::credential_names::is_export_secret_name(name, extra)
}

/// Whether `s` carries no literal text: empty, or exactly one `{{name}}`
/// reference spanning the whole (trimmed) value, as the resolver reads it
/// (the first `}}` closes it). A dynamic helper counts only without
/// arguments (`{{$guid}}`): an argument such as `{{$randomFrom a|b}}` is
/// literal text that is sent.
fn is_pure_reference(s: &str) -> bool {
    let t = s.trim();
    if t.is_empty() {
        return true;
    }
    let Some(inner) = t.strip_prefix("{{") else { return false };
    let Some(close) = inner.find("}}") else { return false };
    if close + 2 != inner.len() {
        return false;
    }
    let expr = inner[..close].trim();
    match expr.strip_prefix('$') {
        Some(helper) => !helper.is_empty() && !helper.contains(char::is_whitespace),
        None => !expr.is_empty(),
    }
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
    /// Names a new placeholder must not take: the graph's variable names and
    /// `{{references}}`, and the placeholders already allocated.
    reserved: HashSet<String>,
    /// The placeholder allocated for each (base name, value).
    by_value: HashMap<(String, String), String>,
    /// The next numeric suffix to try for each base name.
    next: HashMap<String, usize>,
}

impl Sanitized {
    /// A placeholder name for `value` under `hint`: the same name for the
    /// same value (one variable fills them all), another (`_2`, `_3`, ...)
    /// for a different value, so a share-safely recipient can supply each,
    /// and never a name the graph already uses for a variable or reference.
    fn placeholder_for(&mut self, hint: &str, value: &str) -> String {
        let base = placeholder_name(hint);
        let key = (base, value.to_string());
        if let Some(name) = self.by_value.get(&key) {
            return name.clone();
        }
        let base = &key.0;
        let mut n = self.next.get(base).copied().unwrap_or(1);
        let name = loop {
            let candidate = if n == 1 { base.clone() } else { format!("{base}_{n}") };
            n += 1;
            if self.reserved.insert(candidate.clone()) {
                break candidate;
            }
        };
        self.next.insert(base.clone(), n);
        self.by_value.insert(key, name.clone());
        name
    }
}

/// The names `v` already uses: every variable's name, every response
/// extraction's variable, every sensitive dataset column, and every
/// `{{name}}` reference (as the resolver reads it: the first `}}` closes
/// it). A dataset's other columns live only in its attachment and are not
/// seen here.
fn used_names(v: &serde_json::Value, out: &mut HashSet<String>) {
    match v {
        serde_json::Value::Object(map) => {
            if map.contains_key("secret")
                && let Some(n) = map.get("name").and_then(|n| n.as_str())
            {
                out.insert(n.trim().to_string());
            }
            if let Some(n) = map.get("variable").and_then(|n| n.as_str()) {
                out.insert(n.trim().to_string());
            }
            if let Some(columns) = map.get("sensitive_columns").and_then(|c| c.as_array()) {
                out.extend(columns.iter().filter_map(|c| c.as_str()).map(|c| c.trim().to_string()));
            }
            for child in map.values() {
                used_names(child, out);
            }
        }
        serde_json::Value::Array(a) => a.iter().for_each(|x| used_names(x, out)),
        serde_json::Value::String(text) => {
            let mut rest = text.as_str();
            while let Some(open) = rest.find("{{") {
                let after = &rest[open + 2..];
                let Some(close) = after.find("}}") else { break };
                out.insert(after[..close].trim().to_string());
                rest = &after[close + 2..];
            }
        }
        _ => {}
    }
}

/// Walk `objects.json` and replace sensitive literals in place. `extra` is
/// the user's extra redaction names (`AppSettings::redaction_names`), always
/// treated as credential names.
pub fn sanitize(v: &mut serde_json::Value, extra: &[String]) -> Sanitized {
    let mut reserved = HashSet::new();
    used_names(v, &mut reserved);
    let mut s = Sanitized { extracted: vec![], warnings: vec![], reserved, by_value: HashMap::new(), next: HashMap::new() };
    walk(v, String::new(), "", extra, &mut s);
    s
}

fn walk(v: &mut serde_json::Value, ptr: String, key: &str, extra: &[String], s: &mut Sanitized) {
    match v {
        serde_json::Value::Object(map) => {
            // SensitiveValue::Template  => {"kind":"template","value": "..."}
            let is_template = map.get("kind").and_then(|k| k.as_str()) == Some("template")
                && map.len() == 2
                && map.get("value").map(|x| x.is_string()).unwrap_or(false);
            if is_template {
                let val = map["value"].as_str().unwrap_or("").to_string();
                if !is_pure_reference(&val) {
                    let ph = s.placeholder_for(key, &val);
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
                        && (sensitive_name(&name, extra) || looks_like_credential(&text).is_some())
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
                // A templated name may resolve to a credential name in some
                // scope: its literal value is extracted too.
                let templated = name.contains("{{");
                if (flagged || templated || sensitive_name(&name, extra)) && !is_pure_reference(&val) {
                    let ph = s.placeholder_for(&name, &val);
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
                        s.warnings
                            .push(ContentWarning { pointer: child_ptr.clone(), reason: format!("{k} {why}; {FREE_TEXT_REMEDIATION}") });
                    }
                    continue;
                }
                if let Some(child) = map.get_mut(&k) {
                    walk(child, child_ptr, &k, extra, s);
                }
            }
        }
        serde_json::Value::Array(a) => {
            for (i, x) in a.iter_mut().enumerate() {
                walk(x, format!("{ptr}/{i}"), key, extra, s);
            }
        }
        _ => {}
    }
}

/// What a free-text credential warning advises. Free text is never
/// extracted, so it stays readable in every bundle mode: encrypted transfer
/// seals only the vault (secrets and extracted values), not the objects.
const FREE_TEXT_REMEDIATION: &str = "it is exported as written and stays readable in share-safely and encrypted-transfer \
     bundles alike (encrypted transfer seals only vault secrets and extracted fields) — remove it, or move it into a secret \
     variable or a sensitive header/parameter; only a full backup encrypts it";

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
        let s = sanitize(&mut v, &[]);
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
        let s = sanitize(&mut v, &[]);
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

    /// GHSA-8fmc-h49v-mh7f: every name the engine or the importer treats as
    /// a credential, and the user's extra redaction names, is extracted from
    /// headers, query parameters and form fields; ordinary names are not.
    #[test]
    fn every_credential_name_anvil_knows_is_extracted() {
        use anvil_domain::credential_names as cn;
        let extra = vec!["X-Customer-Ssn".to_string()];
        let mut names: Vec<String> = [
            cn::ENGINE_SENSITIVE_HEADERS,
            cn::ENGINE_SENSITIVE_NAME_PARTS,
            cn::IMPORT_CREDENTIAL_HEADERS,
            cn::IMPORT_CREDENTIAL_PARTS,
            cn::IMPORT_CREDENTIAL_EXACT,
            cn::OAUTH_SECRET_FORM_FIELDS,
        ]
        .concat()
        .iter()
        .map(|n| n.to_string())
        .collect();
        names.extend(
            [
                "Ocp-Apim-Subscription-Key",
                "X-Functions-Key",
                "DPoP",
                "X-Master-Key",
                "Subscription-Key",
                "X-Auth-Key",
                "DD-Application-Key",
            ]
            .map(String::from),
        );
        names.extend(
            ["tenant_key", "aws_access_key_id", "X-Auth-User", "key", "sig", "pwd", "pass", "otp", "pin", "x-customer-ssn"]
                .map(String::from),
        );
        let kv = |n: &str, i: usize, place: &str| serde_json::json!({"name": n, "value": format!("lit-{place}-{i}-zq"), "enabled": true});
        let fields = |place: &str| names.iter().enumerate().map(|(i, n)| kv(n, i, place)).collect::<Vec<_>>();
        let ordinary = ["Accept", "Content-Type", "X-Request-Id", "page", "limit"];
        let kept = |place: &str| {
            ordinary
                .iter()
                .map(|n| serde_json::json!({"name": n, "value": format!("plain-{place}-{n}"), "enabled": true}))
                .collect::<Vec<_>>()
        };
        let mut headers = fields("h");
        headers.extend(kept("h"));
        let mut query = fields("q");
        query.extend(kept("q"));
        let mut form = fields("f");
        form.extend(kept("f"));
        let mut v = serde_json::json!({"requests": [{"spec": {
            "headers": headers,
            "query": query,
            "body": {"type": "form", "fields": form}
        }}]});
        let original = v.clone();
        let s = sanitize(&mut v, &extra);
        let text = v.to_string();
        assert!(!text.contains("lit-"), "a credential-named literal stayed: {text}");
        assert_eq!(s.extracted.len(), names.len() * 3);
        for place in ["h", "q", "f"] {
            for n in ordinary {
                assert!(text.contains(&format!("plain-{place}-{n}")), "{n} was extracted");
            }
        }
        // Without the extra name, its literal stays (it is no built-in name).
        let mut without = original.clone();
        let s_without = sanitize(&mut without, &[]);
        assert_eq!(s_without.extracted.len(), (names.len() - 1) * 3, "x-customer-ssn is only an extra name");
        restore(&mut v, &s.extracted).unwrap();
        assert_eq!(v, original);
    }

    #[test]
    fn only_a_whole_value_reference_is_left_in_place() {
        for pure in ["", "  ", "{{token}}", " {{ token }} ", "{{$guid}}", "{{api key}}"] {
            assert!(is_pure_reference(pure), "{pure:?}");
        }
        for literal in [
            "{{tenant}}-live-key-123456}}",
            "{{tenant}}-live-key",
            "live-{{tenant}}",
            "{{a}}{{b}}",
            "{{$randomFrom live-key-a|live-key-b}}",
            "{{}}",
            "{{$}}",
            "{{unterminated",
        ] {
            assert!(!is_pure_reference(literal), "{literal:?}");
        }
        let mut v = serde_json::json!({"headers": [
            {"name": "X-Functions-Key", "value": "{{tenant}}-live-key-123456}}", "enabled": true},
            {"name": "X-Functions-Key", "value": "{{$randomFrom live-key-a|live-key-b}}", "enabled": true},
            {"name": "{{header_name}}", "value": "templated-name-literal", "enabled": true},
            {"name": "{{header_name}}", "value": "{{header_value}}", "enabled": true},
            {"name": "X-Functions-Key", "value": "{{function_key}}", "enabled": true}
        ]});
        let original = v.clone();
        let s = sanitize(&mut v, &[]);
        let text = v.to_string();
        for leaked in ["live-key", "templated-name-literal"] {
            assert!(!text.contains(leaked), "{leaked}: {text}");
        }
        assert!(text.contains("{{header_value}}") && text.contains("{{function_key}}"), "whole references stay: {text}");
        assert_eq!(s.extracted.len(), 3);
        restore(&mut v, &s.extracted).unwrap();
        assert_eq!(v, original);
    }

    #[test]
    fn different_values_under_one_name_get_their_own_placeholders() {
        let kv = |n: &str, v: &str| serde_json::json!({"name": n, "value": v, "enabled": true});
        let mut v = serde_json::json!({"requests": [
            {"headers": [kv("X-Master-Key", "tenant-a"), kv("x_master_key", "tenant-b")]},
            {"headers": [kv("X-Master-Key", "tenant-a")], "params": [kv("sig", "s1"), kv("sig", "s2")]}
        ]});
        let original = v.clone();
        let s = sanitize(&mut v, &[]);
        let names: Vec<&str> = s.extracted.iter().map(|e| e.placeholder.as_str()).collect();
        assert_eq!(names, ["secret_x_master_key", "secret_x_master_key_2", "secret_x_master_key", "secret_sig", "secret_sig_2"]);
        restore(&mut v, &s.extracted).unwrap();
        assert_eq!(v, original);
    }

    #[test]
    fn placeholders_never_take_a_name_the_graph_already_uses() {
        let kv = |n: &str, v: &str| serde_json::json!({"name": n, "value": v, "enabled": true});
        let mut v = serde_json::json!({
            "environments": [{"variables": [
                {"name": "secret_x_master_key_2", "value": {"kind": "template", "value": "catalog-filter"}, "secret": false, "enabled": true}
            ]}],
            "datasets": [{"sensitive_columns": ["secret_x_master_key_5"]}],
            "extractions": [{"variable": "secret_x_master_key_4", "from": {"kind": "status"}}],
            "requests": [
                {"headers": [kv("X-Label", "{{secret_x_master_key_2}}"), kv("X-Other", "{{ secret_x_master_key_3 }}")]},
                {"headers": [kv("X-Master-Key", "tenant-a"), kv("X-Master-Key", "tenant-b"), kv("X-Master-Key", "tenant-c")]}
            ]
        });
        let original = v.clone();
        let s = sanitize(&mut v, &[]);
        let names: Vec<&str> = s.extracted.iter().map(|e| e.placeholder.as_str()).collect();
        assert_eq!(names, ["secret_x_master_key", "secret_x_master_key_6", "secret_x_master_key_7"]);
        restore(&mut v, &s.extracted).unwrap();
        assert_eq!(v, original);
    }

    #[test]
    fn many_distinct_values_under_one_name_are_allocated_in_linear_time() {
        let fields: Vec<serde_json::Value> =
            (0..20_000).map(|i| serde_json::json!({"name": "X-Master-Key", "value": format!("v{i}"), "enabled": true})).collect();
        let mut v = serde_json::json!({"headers": fields});
        let s = sanitize(&mut v, &[]);
        assert_eq!(s.extracted.len(), 20_000);
        assert_eq!(s.extracted.last().unwrap().placeholder, "secret_x_master_key_20000");
    }

    #[test]
    fn free_text_credentials_are_warned_not_modified() {
        let mut v = serde_json::json!({"requests": [{"spec": {"body": {"type": "json", "text": "{\"password\":\"abc123\"}"}}}]});
        let s = sanitize(&mut v, &[]);
        assert_eq!(s.warnings.len(), 1);
        assert!(!s.warnings[0].reason.contains("use encrypted transfer"), "{}", s.warnings[0].reason);
        assert!(s.warnings[0].reason.contains("encrypted-transfer"), "{}", s.warnings[0].reason);
        assert!(v.to_string().contains("abc123"));
    }
}
