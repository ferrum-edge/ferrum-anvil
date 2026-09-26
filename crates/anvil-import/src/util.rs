//! Small shared helpers: hashing, canonical JSON, a stable seeded PRNG,
//! JSON-pointer building, variable-name sanitizing and credential-name
//! detection.

use anvil_domain::request::RequestSpec;
use serde_json::Value;
use sha2::{Digest, Sha256};

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Canonical JSON: object keys sorted (byte order), no insignificant
/// whitespace, numbers as serde_json prints them. Stable across runs and
/// independent of the `preserve_order` feature.
pub fn canonical_json(v: &Value) -> String {
    let mut out = String::new();
    write_canonical(v, &mut out);
    out
}

fn write_canonical(v: &Value, out: &mut String) {
    match v {
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&Value::String((*k).clone()).to_string());
                out.push(':');
                write_canonical(&m[k.as_str()], out);
            }
            out.push('}');
        }
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(x, out);
            }
            out.push(']');
        }
        other => out.push_str(&other.to_string()),
    }
}

/// SHA-256 (hex) of the canonical JSON of a request spec with its `source`
/// link removed. This is the value stored in `ImportSource::generated_hash`
/// at import time; a later mismatch means the user edited the request.
pub fn spec_hash(spec: &RequestSpec) -> String {
    let mut s = spec.clone();
    s.source = None;
    let v = serde_json::to_value(&s).unwrap_or(Value::Null);
    sha256_hex(canonical_json(&v).as_bytes())
}

/// FNV-1a 64-bit, used only to derive per-operation PRNG seeds.
pub fn fnv1a64(s: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.as_bytes() {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}

/// SplitMix64: tiny, fast and — unlike external RNG crates — guaranteed to
/// produce the same sequence forever, so samples stay stable across releases
/// (reimport diffs depend on it).
#[derive(Debug, Clone)]
pub struct SplitMix64(u64);

impl SplitMix64 {
    pub fn new(seed: u64) -> Self {
        SplitMix64(seed)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// Uniform in `[lo, hi]` (inclusive); returns `lo` when `lo >= hi`.
    /// Overflow-free for the whole `i128` range.
    pub fn range_i128(&mut self, lo: i128, hi: i128) -> i128 {
        if lo >= hi {
            return lo;
        }
        // Two's-complement difference is exact for hi > lo.
        let span = (hi as u128).wrapping_sub(lo as u128);
        let r = u128::from(self.next_u64()) << 64 | u128::from(self.next_u64());
        let off = match span.checked_add(1) {
            Some(n) => r % n,
            None => r,
        };
        (lo as u128).wrapping_add(off) as i128
    }

    pub fn unit_f64(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }

    pub fn bool(&mut self) -> bool {
        self.next_u64() & 1 == 1
    }

    pub fn hex(&mut self, n: usize) -> String {
        let mut s = String::with_capacity(n);
        while s.len() < n {
            s.push_str(&format!("{:016x}", self.next_u64()));
        }
        s.truncate(n);
        s
    }
}

/// Append one reference token to a JSON pointer (RFC 6901 escaping).
pub fn ptr(base: &str, token: &str) -> String {
    let mut out = String::with_capacity(base.len() + token.len() + 1);
    out.push_str(base);
    out.push('/');
    for c in token.chars() {
        match c {
            '~' => out.push_str("~0"),
            '/' => out.push_str("~1"),
            c => out.push(c),
        }
    }
    out
}

/// Turn an arbitrary label into a `{{variable}}`-safe name: ASCII letters,
/// digits and `_` only; never empty.
pub fn sanitize_var(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut last_us = false;
    for c in name.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c);
            last_us = false;
        } else if !last_us && !out.is_empty() {
            out.push('_');
            last_us = true;
        }
    }
    while out.ends_with('_') {
        out.pop();
    }
    if out.is_empty() {
        out.push_str("value");
    }
    if out.as_bytes()[0].is_ascii_digit() {
        out.insert(0, '_');
    }
    out
}

/// Header names that always carry credentials or session state.
const CREDENTIAL_HEADERS: &[&str] = &[
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
    "x-xsrf-token",
    "x-goog-api-key",
    "dpop",
    "x-functions-key",
    "ocp-apim-subscription-key",
    "x-session-token",
    "x-refresh-token",
];

/// Name fragments that mark a header/query/body field as credential-like.
const CREDENTIAL_PARTS: &[&str] = &[
    "password",
    "passwd",
    "passphrase",
    "secret",
    "token",
    "apikey",
    "api_key",
    "api-key",
    "access_key",
    "accesskey",
    "private_key",
    "privatekey",
    "client_secret",
    "credential",
    "session",
    "signature",
    "authorization",
];

/// Exact names (after lowercasing) that are credential-like even though they
/// are short (`sig`, `key`, `pwd`, `auth`, `code`-style OAuth values).
const CREDENTIAL_EXACT: &[&str] = &["sig", "key", "pwd", "pass", "auth", "otp", "pin", "jwt", "sid", "code_verifier"];

/// Best-effort detector for credential-looking names. Deliberately errs on
/// the side of redaction; arbitrary content can still hide secrets it does
/// not recognize (documented limitation).
pub fn is_credential_name(name: &str) -> bool {
    let n = name.trim().to_ascii_lowercase();
    if n.is_empty() {
        return false;
    }
    if CREDENTIAL_HEADERS.contains(&n.as_str()) || CREDENTIAL_EXACT.contains(&n.as_str()) {
        return true;
    }
    // Pagination/continuation tokens are not credentials.
    if n.contains("page_token") || n.contains("pagetoken") || n.contains("next_token") || n.contains("continuation") {
        return false;
    }
    CREDENTIAL_PARTS.iter().any(|p| n.contains(p))
}

/// True when `v` contains literal text that could be secret material, i.e.
/// anything besides `{{variable}}` references and an auth-scheme word
/// (`Bearer {{token}}` carries no literal secret).
pub fn has_literal_secret(v: &str) -> bool {
    let mut rest = v;
    let mut literal = String::new();
    while let Some(i) = rest.find("{{") {
        literal.push_str(&rest[..i]);
        match rest[i..].find("}}") {
            Some(j) => rest = &rest[i + j + 2..],
            None => {
                literal.push_str(&rest[i..]);
                rest = "";
            }
        }
    }
    literal.push_str(rest);
    let t = literal.trim();
    const SCHEMES: &[&str] = &["bearer", "basic", "token", "digest", "apikey", "dpop", "hmac", "negotiate", "jwt"];
    !(t.is_empty() || SCHEMES.contains(&t.to_ascii_lowercase().as_str()))
}

/// Lower-cased media type without parameters.
pub fn media_essence(ct: &str) -> String {
    ct.split(';').next().unwrap_or("").trim().to_ascii_lowercase()
}

/// Parameters of a media type (`type/sub; a=b; c="d;e"`) in order, with
/// lowercased names and quoted-string values unquoted (RFC 9110 §5.6.6).
/// Parameters without a name or `=` are skipped.
pub fn media_params(ct: &str) -> Vec<(String, String)> {
    let Some((_, rest)) = ct.split_once(';') else { return vec![] };
    let mut out = vec![];
    let mut chars = rest.chars().peekable();
    loop {
        while chars.next_if(|c| *c == ';' || c.is_whitespace()).is_some() {}
        if chars.peek().is_none() {
            break;
        }
        let mut name = String::new();
        while let Some(c) = chars.next_if(|c| *c != '=' && *c != ';') {
            name.push(c);
        }
        if chars.next_if_eq(&'=').is_none() {
            continue;
        }
        let mut value = String::new();
        if chars.next_if_eq(&'"').is_some() {
            while let Some(c) = chars.next() {
                match c {
                    '"' => break,
                    '\\' => value.extend(chars.next()),
                    c => value.push(c),
                }
            }
            // Anything between the closing quote and the next ';' is ignored.
            while chars.next_if(|c| *c != ';').is_some() {}
        } else {
            while let Some(c) = chars.next_if(|c| *c != ';') {
                value.push(c);
            }
            value.truncate(value.trim_end().len());
        }
        let name = name.trim().to_ascii_lowercase();
        if !name.is_empty() {
            out.push((name, value));
        }
    }
    out
}

pub fn is_json_media(ct: &str) -> bool {
    let e = media_essence(ct);
    e == "application/json" || e == "text/json" || e.ends_with("+json") || e == "application/x-json"
}

pub fn is_xml_media(ct: &str) -> bool {
    let e = media_essence(ct);
    e == "application/xml" || e == "text/xml" || e.ends_with("+xml")
}

/// Truncate a string for inclusion in a report message.
pub fn clip(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max).collect();
        out.push('…');
        out
    }
}

/// Short, stable description of a JSON value's type.
pub fn json_type(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(n) if n.is_i64() || n.is_u64() => "integer",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

pub fn str_of<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(Value::as_str)
}

/// Render a primitive JSON value as the text a user would type.
pub fn scalar_text(v: &Value) -> String {
    match v {
        Value::Null => String::new(),
        Value::String(s) => s.clone(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn media_type_parameters() {
        let p = |ct: &str| media_params(ct).into_iter().map(|(n, v)| format!("{n}={v}")).collect::<Vec<_>>();
        assert!(p("application/soap+xml").is_empty());
        assert_eq!(p(r#"application/soap+xml; charset=utf-8; action="urn:lookup""#), vec!["charset=utf-8", "action=urn:lookup"]);
        assert_eq!(p(r#"a/b;Action="x;y\"z" ;q=1 ; bare; =v;"#), vec![r#"action=x;y"z"#, "q=1"]);
        assert_eq!(p(r#"a/b; action="unterminated"#), vec!["action=unterminated"]);
    }

    #[test]
    fn canonical_sorts_keys() {
        let a = json!({"b": 1, "a": {"d": [1, 2], "c": null}});
        assert_eq!(canonical_json(&a), r#"{"a":{"c":null,"d":[1,2]},"b":1}"#);
    }

    #[test]
    fn splitmix_is_stable() {
        let mut r = SplitMix64::new(42);
        let first = r.next_u64();
        assert_eq!(first, SplitMix64::new(42).next_u64());
        assert_ne!(first, r.next_u64());
        for _ in 0..100 {
            let v = r.range_i128(-3, 3);
            assert!((-3..=3).contains(&v));
        }
    }

    #[test]
    fn sanitize() {
        assert_eq!(sanitize_var("api key"), "api_key");
        assert_eq!(sanitize_var("x-api-key"), "x_api_key");
        assert_eq!(sanitize_var("1st"), "_1st");
        assert_eq!(sanitize_var("---"), "value");
    }

    #[test]
    fn credential_names() {
        for n in ["Authorization", "X-API-Key", "access_token", "client_secret", "password", "sig", "Cookie"] {
            assert!(is_credential_name(n), "{n}");
        }
        for n in ["Accept", "page_token", "limit", "Content-Type", "user_id", "keyword"] {
            assert!(!is_credential_name(n), "{n}");
        }
    }

    #[test]
    fn literal_secrets() {
        assert!(!has_literal_secret("{{token}}"));
        assert!(!has_literal_secret("Bearer {{token}}"));
        assert!(!has_literal_secret(""));
        assert!(has_literal_secret("Bearer abc"));
        assert!(has_literal_secret("{{user}}:hunter2"));
    }

    #[test]
    fn pointers_escape() {
        assert_eq!(ptr("/paths", "/pets/{id}"), "/paths/~1pets~1{id}");
        assert_eq!(ptr("", "a~b"), "/a~0b");
    }
}
