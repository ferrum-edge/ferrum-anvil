//! Redaction for evidence, history, logs and safe-share exports.
//!
//! Two layers: (1) known-sensitive names (headers, query parameters, cookie
//! and JSON field names, plus any request field the user marked sensitive)
//! and (2) exact-value scrubbing of every secret value resolved during the
//! execution, including its canonical percent-encoded forms, its lowercase
//! hex (as a session transcript's hex preview shows it) and, for a secret
//! substituted into a hex- or base64-encoded session payload, the bytes it
//! decodes to. URL components are percent-decoded before they are compared,
//! so an encoded secret is replaced whole rather than left in a reversible
//! form, and a finished URL that still reveals a secret once decoded (a
//! secret split across components) keeps only its scheme and authority.
//! Arbitrary content can still contain secrets Anvil cannot recognize;
//! exports show a preview for that reason.

use crate::vars::Resolver;
use anvil_domain::diagnostics::DiagnosticFinding;
use anvil_domain::execution::HeaderEntry;
use anvil_domain::request::PayloadEncoding;
use anvil_domain::secret::REDACTED;
use base64::Engine as _;

/// Shorter values (and shorter forms of what a secret decodes to) are not
/// exact-value scrubbed: they would shred ordinary text. Name-based
/// redaction still applies to them.
const MIN_SECRET_LEN: usize = 4;

/// Occurrences of one secret registered per decoded field (the first ones,
/// which a transcript preview shows).
const MAX_DECODED_WINDOWS: usize = 64;

/// Percent-decoding rounds applied to one URL component (covers values that
/// were encoded more than once).
const MAX_DECODE_ROUNDS: usize = 3;

/// Headers whose values are URLs (and so may carry encoded query values).
/// `Link` and `Refresh` embed URLs in a larger value and are handled apart.
const URL_HEADERS: &[&str] = &["location", "content-location", "referer"];

/// Diagnostic evidence keys whose values are URLs, or `host/path` without a
/// scheme.
const URL_EVIDENCE: &[&str] = &["redirect.authorization_endpoint"];

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

/// Whether a configured header name marks a credential that must not follow
/// a redirect to another origin. Broader than [`is_sensitive_name`], which
/// decides redaction: no length limit, and names ending in `-key` / `_key`
/// (`X-Master-Key`, `Subscription-Key`, ...) count too.
pub fn is_credential_name(name: &str, extra: &[String]) -> bool {
    let n = name.to_ascii_lowercase();
    SENSITIVE_HEADERS.contains(&n.as_str())
        || extra.iter().any(|e| e.eq_ignore_ascii_case(&n))
        || SENSITIVE_NAME_PARTS.iter().any(|p| n.contains(p))
        || n.ends_with("-key")
        || n.ends_with("_key")
}

#[derive(Clone, Default)]
pub struct Redactor {
    /// Secret values, longest first (compared against decoded URL components).
    secrets: Vec<String>,
    /// Secret values, their canonical percent-encoded forms and their JSON
    /// string escaping, longest first (scrubbed from arbitrary text).
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
        let mut secrets = r.used_secrets.lock().clone();
        secrets.extend(r.decoded_secrets.lock().iter().cloned());
        Redactor::new(secrets, all)
    }

    /// Take in what the resolver has seen since this redactor was built:
    /// secret values substituted by templates resolved later (a session's
    /// messages, metadata or payloads), what those in an encoded payload
    /// decode to, and request fields marked sensitive.
    pub fn refresh_used_secrets(&mut self, r: &Resolver) {
        let before = self.secrets.len();
        let decoded = r.decoded_secrets.lock().clone();
        for s in r.used_secrets.lock().iter().chain(decoded.iter()) {
            if s.len() >= MIN_SECRET_LEN && !self.secrets.contains(s) {
                self.secrets.push(s.clone());
            }
        }
        if self.secrets.len() != before {
            self.reindex();
        }
        for n in r.sensitive_names.lock().iter() {
            if !self.extra_names.iter().any(|x| x.eq_ignore_ascii_case(n)) {
                self.extra_names.push(n.clone());
            }
        }
    }

    /// Longest first so overlapping values are fully covered.
    fn reindex(&mut self) {
        sort_longest_first(&mut self.secrets);
        let mut patterns = Vec::with_capacity(self.secrets.len() * 5);
        for s in &self.secrets {
            patterns.push(s.clone());
            // A session transcript shows bytes that are not printable text as hex.
            patterns.push(hex::encode(s));
            patterns.extend(encoded_forms(s));
            patterns.extend(json_escaped(s));
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

    /// Scrub raw secret values, their canonical percent encodings and JSON
    /// string escapes from arbitrary text.
    ///
    /// Limits: only the raw value, the encodings in [`encoded_forms`], its
    /// lowercase hex and the value's JSON string escaping (as rendered in
    /// JSON diagnostics) are recognized. A secret encoded any other way
    /// (partly or doubly percent-encoded, base64, HTML-escaped), split by other
    /// content, or shorter than 4 characters passes through, and names are
    /// not consulted. Use [`Redactor::url`], [`Redactor::header`] or
    /// [`Redactor::json_text`] where the structure is known.
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

    /// True when a secret can be read from `s` directly or after undoing up to
    /// [`MAX_DECODE_ROUNDS`] layers of percent-encoding, with `+` read either
    /// way at every layer.
    fn reveals_secret(&self, s: &str) -> bool {
        if self.secrets.is_empty() {
            return false;
        }
        // Nothing to decode: only a raw occurrence can reveal a secret.
        if !s.contains(['%', '+']) {
            return self.secrets.iter().any(|x| s.contains(x.as_str()));
        }
        let mut layers: Vec<Vec<u8>> = vec![s.as_bytes().to_vec()];
        for round in 0..=MAX_DECODE_ROUNDS {
            if layers.iter().any(|l| self.secrets.iter().any(|x| contains_bytes(l, x.as_bytes()))) {
                return true;
            }
            if round == MAX_DECODE_ROUNDS {
                break;
            }
            let mut next: Vec<Vec<u8>> = Vec::new();
            for l in &layers {
                let plus: Vec<u8> = l.iter().map(|&b| if b == b'+' { b' ' } else { b }).collect();
                let plain: Vec<u8> = percent_encoding::percent_decode(l).collect();
                let form: Vec<u8> = percent_encoding::percent_decode(&plus).collect();
                for d in [plain, form] {
                    if !next.contains(&d) {
                        next.push(d);
                    }
                }
            }
            layers = next;
        }
        false
    }

    /// A header value with its credential redacted. A header with a
    /// sensitive name keeps only the parts that describe its credential (the
    /// scheme word of an `Authorization`-like header, cookie names and
    /// `Set-Cookie` attributes), and those are scrubbed of every known secret
    /// value first: a server can echo a credential it received into any of
    /// them. Scrubbing the whole value before it is split also replaces a
    /// secret that spans a `;`, `=` or space whole.
    pub fn header(&self, name: &str, value: &str) -> String {
        if is_sensitive_name(name, &self.extra_names) {
            let value = self.text(value);
            let value = value.as_str();
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
                        let attrs = rest.split_once(';').map(|(_, a)| format!(";{}", self.set_cookie_attrs(a))).unwrap_or_default();
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
        if name.eq_ignore_ascii_case("link") {
            return self.link(value);
        }
        if name.eq_ignore_ascii_case("refresh") {
            return self.refresh(value);
        }
        self.text(value)
    }

    fn set_cookie_attrs(&self, attrs: &str) -> String {
        attrs
            .split(';')
            .map(|attr| match attr.split_once('=') {
                Some((name, value))
                    if matches!(name.trim().to_ascii_lowercase().as_str(), "path" | "domain") && self.hides_secret(value.trim()) =>
                {
                    format!("{name}={REDACTED}")
                }
                _ => attr.to_string(),
            })
            .collect::<Vec<_>>()
            .join(";")
    }

    /// `Link` (RFC 8288): every `<URI-reference>` is redacted as a URL, and so
    /// is the value of an `anchor` parameter, which is a URI reference too.
    fn link(&self, value: &str) -> String {
        let value = self.text(value);
        let mut out = String::with_capacity(value.len());
        let mut rest = value.as_str();
        while let Some(start) = rest.find('<') {
            let Some(len) = rest[start + 1..].find('>') else { break };
            out.push_str(&self.link_params(&rest[..start]));
            out.push('<');
            out.push_str(&self.url(&rest[start + 1..start + 1 + len]));
            out.push('>');
            rest = &rest[start + 2 + len..];
        }
        out.push_str(&self.link_params(rest));
        out
    }

    /// The parameters between `Link` URI references with every `anchor`
    /// value (quoted or not) redacted as a URL.
    fn link_params(&self, params: &str) -> String {
        let mut out = String::with_capacity(params.len());
        let mut rest = params;
        while let Some(at) = anchor_value_start(rest) {
            out.push_str(&rest[..at]);
            let value = &rest[at..];
            let (redacted, after) = match value.strip_prefix('"') {
                Some(quoted) => match quoted.find('"') {
                    Some(end) => (format!("\"{}\"", self.url(&quoted[..end])), &quoted[end + 1..]),
                    None => (format!("\"{}", self.url(quoted)), ""),
                },
                None => {
                    let end = value.find([';', ',']).unwrap_or(value.len());
                    (self.url(&value[..end]), &value[end..])
                }
            };
            out.push_str(&redacted);
            rest = after;
        }
        out.push_str(rest);
        out
    }

    /// `Refresh` (`5; url=https://…`): the target after `url=` is redacted as
    /// a URL, keeping surrounding quotes.
    fn refresh(&self, value: &str) -> String {
        let value = self.text(value);
        let Some(at) = value.to_ascii_lowercase().find("url=") else { return self.url(&value) };
        let (head, target) = value.split_at(at + 4);
        let quote = target.chars().next().filter(|c| matches!(*c, '"' | '\'') && target.len() > 1 && target.ends_with(*c));
        if let Some(q) = quote {
            return format!("{head}{q}{}{q}", self.url(&target[1..target.len() - 1]));
        }
        format!("{head}{}", self.url(target))
    }

    /// An inferred note of a prepared request with its values redacted. An
    /// auth fact's `htu` (the DPoP target URI) is a URL whose path can carry a
    /// secret, so it is redacted as a URL.
    pub fn inferred(&self, line: &str) -> String {
        match line.strip_prefix("auth ").and_then(|l| l.split_once(": ")) {
            Some((k, v)) if k.ends_with(".htu") => format!("auth {k}: {}", self.url(v)),
            _ => self.text(line),
        }
    }

    /// A diagnostic finding with its values redacted. URL-valued evidence is
    /// redacted as a URL, and so is its copy in the explanation.
    pub fn finding(&self, f: &mut DiagnosticFinding) {
        f.title = self.text(&f.title);
        let mut explanation = f.explanation.clone();
        for e in &mut f.evidence {
            if !URL_EVIDENCE.contains(&e.key.as_str()) {
                e.value = self.text(&e.value);
                continue;
            }
            let redacted = self.url(&e.value);
            if !e.value.is_empty() && redacted != e.value {
                explanation = explanation.replace(e.value.as_str(), &redacted);
            }
            e.value = redacted;
        }
        f.explanation = self.text(&explanation);
        for a in &mut f.alternatives {
            *a = self.text(a);
        }
    }

    pub fn headers(&self, h: &[HeaderEntry]) -> Vec<HeaderEntry> {
        h.iter().map(|e| HeaderEntry { name: e.name.clone(), value: self.header(&e.name, &e.value) }).collect()
    }

    /// Redact sensitive query parameter values and secret values in a URL.
    /// Path segments, query names and values and the fragment are compared
    /// after percent-decoding; a component that hides a secret is replaced
    /// whole, so no reversible encoding of it survives. The fragment is read
    /// as `k=v` pairs too (e.g. `#access_token=…`). If the finished URL still
    /// reveals a secret once decoded (a secret split across components by a
    /// raw `/` or `&`), everything after the authority is replaced.
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
            out = format!("{out}?{}", self.pairs(q));
        }
        // Userinfo in the authority is always sensitive.
        let out = redact_userinfo(&out);
        let out = match frag {
            Some(f) => format!("{out}#{}", self.pairs(f)),
            None => out,
        };
        self.seal(out)
    }

    /// `k=v&k=v` (a query or a fragment) with sensitive names' values and
    /// every name, value or bare part that hides a secret replaced.
    fn pairs(&self, q: &str) -> String {
        q.split('&')
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
            .collect::<Vec<_>>()
            .join("&")
    }

    /// Final whole-URL check: components are examined one at a time, so a
    /// secret containing a delimiter that was left raw is split across them.
    /// If the finished URL still reveals a secret, only its scheme and
    /// authority are kept (nothing at all if even that reveals one).
    fn seal(&self, u: String) -> String {
        if !self.reveals_secret(&u) {
            return u;
        }
        let sealed = match u.split_once("://").filter(|(scheme, _)| is_scheme(scheme)) {
            Some((scheme, rest)) => {
                let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
                format!("{scheme}://{}/{REDACTED}", &rest[..end])
            }
            None => REDACTED.to_string(),
        };
        if self.reveals_secret(&sealed) { REDACTED.to_string() } else { sealed }
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

/// Registers what the secrets the resolver substituted since `since` (an
/// index into its secrets) into one hex- or base64-encoded field become once
/// the field is `decoded`: the bytes are sent, and shown in a transcript, as
/// text when they are UTF-8 and as lowercase hex otherwise. Each secret is
/// found in the field's canonical encoding and registered as the window of
/// decoded bytes it covers, widened to whole bytes (hex) or whole 4-character
/// groups (base64), so a secret split across the encoding's alignment by what
/// precedes it is covered along with the neighbouring bits it shares bytes
/// with. A secret that cannot be found there makes the field's first
/// preview's worth of bytes secret. Forms shorter than [`MIN_SECRET_LEN`]
/// are not registered.
pub(crate) fn note_decoded_secrets(r: &Resolver, since: usize, encoding: PayloadEncoding, decoded: &[u8]) {
    let canonical = match encoding {
        PayloadEncoding::Text => return,
        PayloadEncoding::Hex => hex::encode(decoded),
        PayloadEncoding::Base64 => base64::engine::general_purpose::STANDARD.encode(decoded),
    };
    let fresh: Vec<String> = r.used_secrets.lock().iter().skip(since).filter(|s| s.len() >= MIN_SECRET_LEN).cloned().collect();
    let mut forms = Vec::new();
    for s in fresh {
        let windows = secret_windows(&s, encoding, &canonical, decoded.len());
        if windows.is_empty() {
            preview_forms(decoded, &mut forms);
        }
        for (start, end) in windows {
            window_forms(decoded, start, end, &mut forms);
        }
    }
    let mut known = r.decoded_secrets.lock();
    for f in forms {
        if f.len() >= MIN_SECRET_LEN && !known.contains(&f) {
            known.push(f);
        }
    }
}

/// Byte ranges of a decoded field (of `len` bytes, `canonical` once encoded
/// again) that hold secret `s`, the first [`MAX_DECODED_WINDOWS`] of them.
/// The secret is cleaned as the field's decoder cleans it (hex: whitespace,
/// `:` and a `0x` prefix dropped, case ignored; base64: surrounding
/// whitespace dropped).
fn secret_windows(s: &str, encoding: PayloadEncoding, canonical: &str, len: usize) -> Vec<(usize, usize)> {
    let (needle, chars, bytes) = match encoding {
        PayloadEncoding::Text => return vec![],
        PayloadEncoding::Hex => {
            let cleaned: String = s.trim().trim_start_matches("0x").chars().filter(|c| !c.is_whitespace() && *c != ':').collect();
            (cleaned.to_ascii_lowercase(), 2, 1)
        }
        PayloadEncoding::Base64 => (s.trim().to_string(), 4, 3),
    };
    if needle.is_empty() {
        return vec![];
    }
    let mut windows = Vec::new();
    for (i, m) in canonical.match_indices(needle.as_str()) {
        let start = i / chars * bytes;
        let end = ((i + m.len()).div_ceil(chars) * bytes).min(len);
        windows.push((start, end));
        if windows.len() == MAX_DECODED_WINDOWS {
            break;
        }
    }
    windows
}

/// The window `start..end` of a decoded field as hex and, as text, widened to
/// whole characters when the field is UTF-8 (or as it is when only the
/// window is).
fn window_forms(decoded: &[u8], start: usize, end: usize, forms: &mut Vec<String>) {
    let window = &decoded[start..end];
    forms.push(hex::encode(window));
    if let Ok(text) = std::str::from_utf8(decoded) {
        let (mut start, mut end) = (start, end);
        while !text.is_char_boundary(start) {
            start -= 1;
        }
        while !text.is_char_boundary(end) {
            end += 1;
        }
        forms.push(text[start..end].to_string());
    } else if let Ok(text) = std::str::from_utf8(window) {
        forms.push(text.to_string());
    }
}

/// The head of a decoded field that a transcript preview shows: its hex, and
/// its text when the field is UTF-8. Every session plan uses the default
/// transcript limits; if a plan ever gets custom limits, pass them here.
fn preview_forms(decoded: &[u8], forms: &mut Vec<String>) {
    let limit = anvil_transport::session::TranscriptLimits::default().preview_bytes;
    forms.push(hex::encode(&decoded[..decoded.len().min(limit / 2)]));
    if let Ok(text) = std::str::from_utf8(decoded) {
        let mut end = text.len().min(limit);
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        forms.push(text[..end].to_string());
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

/// The value as it appears inside a serialized JSON string, when escaping
/// changes it (quotes, backslashes, control characters).
fn json_escaped(s: &str) -> Option<String> {
    let quoted = serde_json::to_string(s).ok()?;
    let inner = &quoted[1..quoted.len() - 1];
    (inner != s).then(|| inner.to_string())
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

fn is_scheme(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
}

fn contains_bytes(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.len() >= needle.len() && hay.windows(needle.len()).any(|w| w == needle)
}

/// `scheme://user:pw@host/...` and the scheme-relative `//user:pw@host/...`
/// with the userinfo replaced.
fn redact_userinfo(u: &str) -> String {
    let (head, rest) = match u.strip_prefix("//") {
        Some(rest) => ("//".to_string(), rest),
        None => match u.split_once("://") {
            Some((scheme, rest)) => (format!("{scheme}://"), rest),
            None => return u.to_string(),
        },
    };
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    match authority.rfind('@') {
        Some(at) => format!("{head}{REDACTED}@{}{}", &authority[at + 1..], &rest[authority_end..]),
        None => u.to_string(),
    }
}

/// Byte offset of the value of the first `anchor` parameter in `s` (a
/// parameter name follows a `;`).
fn anchor_value_start(s: &str) -> Option<usize> {
    let lower = s.to_ascii_lowercase();
    lower.match_indices("anchor").find_map(|(i, name)| {
        let after_name = s[i + name.len()..].trim_start();
        let value = after_name.strip_prefix('=')?.trim_start();
        if s[..i].trim_end().ends_with(';') { Some(s.len() - value.len()) } else { None }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b64(bytes: &[u8]) -> String {
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, bytes)
    }

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
    fn known_secrets_are_scrubbed_from_the_parts_of_a_credential_header_that_are_kept() {
        let secret = "reflected-known-secret-7q2m";
        // Sent percent-encoded in a URL path as `tok%2Fen%3Dvalue`.
        let reserved = "tok/en=value";
        let r = Redactor::new(vec![secret.into(), reserved.into()], vec![]);
        let cases = [
            ("Set-Cookie", format!("ordinary=x; Path=/{secret}; HttpOnly"), format!("ordinary={REDACTED}; Path=/{REDACTED}; HttpOnly")),
            ("Set-Cookie", format!("{secret}=x; Path=/"), format!("{REDACTED}={REDACTED}; Path=/")),
            ("Set-Cookie", format!("sid=x; Domain={secret}.example"), format!("sid={REDACTED}; Domain={REDACTED}.example")),
            ("Set-Cookie", "sid=x; Path=/tok%2Fen%3Dvalue".into(), format!("sid={REDACTED}; Path=/{REDACTED}")),
            ("Cookie", format!("a=1; {secret}=2"), format!("a={REDACTED}; {REDACTED}={REDACTED}")),
            ("Authorization", format!("{secret} opaque"), format!("{REDACTED} {REDACTED}")),
            ("Proxy-Authorization", format!("X-{secret} opaque"), format!("X-{REDACTED} {REDACTED}")),
        ];
        for (i, (name, value, expected)) in cases.iter().enumerate() {
            let out = r.header(name, value);
            assert!(!out.contains(secret) && !out.contains("tok%2Fen%3Dvalue"), "case {i} ({name}): a known secret is kept");
            assert_eq!(&out, expected, "case {i} ({name})");
        }
        // A secret that spans the delimiters the value is split on is replaced whole.
        let r = Redactor::new(vec!["span;Path=/secret".into(), "name-part=value-part".into(), "Bearer whole-value".into()], vec![]);
        assert_eq!(r.header("Set-Cookie", "sid=span;Path=/secret; Secure"), format!("sid={REDACTED}; Secure"));
        assert_eq!(r.header("Cookie", "name-part=value-part; b=2"), format!("{REDACTED}; b={REDACTED}"));
        // A secret that holds the scheme word too (a whole header value marked sensitive) leaves nothing of it.
        assert_eq!(r.header("Authorization", "Bearer whole-value"), REDACTED);
        // Without a known secret in them, the kept parts are unchanged.
        let r = Redactor::new(vec![], vec![]);
        assert_eq!(r.header("Set-Cookie", "sid=abc; Path=/app; HttpOnly"), format!("sid={REDACTED}; Path=/app; HttpOnly"));
        assert_eq!(r.header("Cookie", "a=1; b=2"), format!("a={REDACTED}; b={REDACTED}"));
        assert_eq!(r.header("Authorization", "Bearer abc.def"), format!("Bearer {REDACTED}"));

        let r = Redactor::new(vec!["encoded-cookie-secret-7q2m".into()], vec![]);
        assert_eq!(
            r.header("Set-Cookie", "sid=x; Path=/mixed/encoded%2dcookie-secret-7q2m; HttpOnly"),
            format!("sid={REDACTED}; Path={REDACTED}; HttpOnly")
        );
        assert_eq!(
            r.header("Set-Cookie", "sid=x; Domain=encoded%252dcookie-secret-7q2m.example; Secure"),
            format!("sid={REDACTED}; Domain={REDACTED}; Secure")
        );
    }

    #[test]
    fn data_020_json_body_fields_and_values() {
        let r = Redactor::new(vec!["value-in-body-xyz".into()], vec!["customer_ssn".into()]);
        let out = r.json_text(r#"{"password":"hunter2","nested":{"customer_ssn":"123"},"note":"value-in-body-xyz","ok":"fine"}"#);
        assert!(!out.contains("hunter2") && !out.contains("123\"") && !out.contains("value-in-body-xyz"));
        assert!(out.contains("fine"));
    }

    #[test]
    fn secrets_in_encoded_payloads_are_redacted_as_the_bytes_they_decode_to() {
        let r = Resolver::new(vec![], None);
        r.used_secrets.lock().push("DEADBEEF00C0FFEE".into());
        note_decoded_secrets(&r, 0, PayloadEncoding::Hex, &[0xde, 0xad, 0xbe, 0xef, 0x00, 0xc0, 0xff, 0xee]);
        r.used_secrets.lock().push("c2VjcmV0LXZhbHVl".into());
        note_decoded_secrets(&r, 1, PayloadEncoding::Base64, b"secret-value");
        let red = Redactor::for_execution(&r, &[]);
        assert_eq!(red.text("sent deadbeef00c0ffee"), format!("sent {REDACTED}"));
        assert_eq!(red.text("sent secret-value"), format!("sent {REDACTED}"));
        assert_eq!(red.text(&hex::encode("secret-value")), REDACTED);
        // A secret that does not decode on its own where it sits: the bytes it shares are secret.
        let r = Resolver::new(vec![], None);
        r.used_secrets.lock().push("taXNhbGl".into());
        let field = b"\x01\x02misaligned";
        assert_eq!(b64(field), "AQJtaXNhbGlnbmVk");
        note_decoded_secrets(&r, 0, PayloadEncoding::Base64, field);
        // Characters 3..11 lie in the groups of bytes 0..9.
        assert_eq!(*r.decoded_secrets.lock(), vec![hex::encode(&field[..9]), "\x01\x02misalig".to_string()]);
        assert_eq!(Redactor::for_execution(&r, &[]).text("got 01026d6973616c69676e6564"), format!("got {REDACTED}6e6564"));
    }

    #[test]
    fn short_decoded_secrets_are_redacted_by_the_length_of_each_form() {
        // Two and three decoded bytes: their lowercase hex is 4 and 6 characters.
        let r = Resolver::new(vec![], None);
        r.used_secrets.lock().push("AbCd".into());
        note_decoded_secrets(&r, 0, PayloadEncoding::Hex, &[0xab, 0xcd]);
        r.used_secrets.lock().push("c2Vj".into());
        note_decoded_secrets(&r, 1, PayloadEncoding::Base64, b"sec");
        assert_eq!(*r.decoded_secrets.lock(), vec!["abcd".to_string(), "736563".to_string()]);
        let red = Redactor::for_execution(&r, &[]);
        assert_eq!(red.text("sent abcd"), format!("sent {REDACTED}"));
        assert_eq!(red.text("sent 736563"), format!("sent {REDACTED}"));
        // Three characters of text are too few to scrub.
        assert_eq!(red.text("sec"), "sec");
        // Neither is a secret shorter than 4 characters.
        let r = Resolver::new(vec![], None);
        r.used_secrets.lock().push("abc".into());
        note_decoded_secrets(&r, 0, PayloadEncoding::Hex, &[0x0a, 0xbc]);
        assert!(r.decoded_secrets.lock().is_empty());
    }

    #[test]
    fn decoded_secrets_in_a_field_longer_than_the_preview_are_bounded_windows() {
        let limit = anvil_transport::session::TranscriptLimits::default().preview_bytes;
        let field: Vec<u8> = (0..3_000u32).map(|i| (i % 256) as u8).collect();
        assert!(field.len() > limit);
        // A transcript shows a binary payload's first `limit / 2` bytes as hex.
        let preview = hex::encode(&field[..limit / 2]);

        // Hex: characters 21..37 start and end mid-byte, so bytes 10..19 are secret.
        let r = Resolver::new(vec![], None);
        let secret = hex::encode(&field)[21..37].to_ascii_uppercase();
        assert_eq!(secret, "A0B0C0D0E0F10111");
        r.used_secrets.lock().push(secret);
        note_decoded_secrets(&r, 0, PayloadEncoding::Hex, &field);
        let window = hex::encode(&field[10..19]);
        assert!(r.decoded_secrets.lock().iter().all(|f| f.len() <= window.len()), "{:?}", r.decoded_secrets.lock());
        let out = Redactor::for_execution(&r, &[]).text(&preview);
        assert!(!out.contains(&window) && !out.contains("a0b0c0d0e0f10111"));
        assert_eq!(out, preview.replace(&window, REDACTED));
        assert_eq!(out.matches(REDACTED).count(), 4, "once in every 256 bytes shown");

        // Base64: characters 10..30 are groups 2..8, bytes 6..24.
        let r = Resolver::new(vec![], None);
        let secret = b64(&field)[10..30].to_string();
        r.used_secrets.lock().push(secret);
        note_decoded_secrets(&r, 0, PayloadEncoding::Base64, &field);
        let window = hex::encode(&field[6..24]);
        assert!(r.decoded_secrets.lock().iter().all(|f| f.len() <= window.len()), "{:?}", r.decoded_secrets.lock());
        let out = Redactor::for_execution(&r, &[]).text(&preview);
        assert!(!out.contains(&window));
        assert_eq!(out, preview.replace(&window, REDACTED));

        // A secret the field does not show verbatim: what the preview shows of the field is secret.
        let r = Resolver::new(vec![], None);
        r.used_secrets.lock().push("not-in-the-field".into());
        note_decoded_secrets(&r, 0, PayloadEncoding::Hex, &field);
        assert_eq!(*r.decoded_secrets.lock(), vec![preview.clone()]);
        assert_eq!(Redactor::for_execution(&r, &[]).text(&preview), REDACTED);
    }

    #[test]
    fn credential_names_for_redirect_stripping() {
        assert!(is_credential_name("X-Master-Key", &[]));
        assert!(is_credential_name("X-Client-Key", &[]));
        assert!(is_credential_name("Subscription-Key", &[]));
        assert!(is_credential_name("tenant_key", &[]));
        assert!(is_credential_name("X-API-Key", &[]) && is_credential_name("Cookie", &[]));
        let long = "X-Vendor-Specific-Upstream-Gateway-Routing-Session-Token";
        assert!(long.len() > 48);
        assert!(is_credential_name(long, &[]));
        assert!(is_credential_name("X-Customer-Ssn", &["x-customer-ssn".into()]));
        for n in ["X-Plain", "Accept", "Content-Type", "X-Keyboard"] {
            assert!(!is_credential_name(n, &[]), "{n}");
        }
        // Redaction keeps its own rules.
        assert!(!is_sensitive_name("X-Master-Key", &[]));
        assert!(!is_sensitive_name(long, &[]));
    }
}
