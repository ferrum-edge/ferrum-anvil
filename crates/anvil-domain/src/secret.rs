use crate::Id;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Reference to a value held in the encrypted vault. The value itself never
/// appears in ordinary object graphs, logs or safe-share exports.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct SecretRef {
    pub id: Id,
    /// Human label shown in the UI and in export previews ("prod API key").
    pub label: String,
}

/// A field that may carry sensitive material (password, token, key).
///
/// * `Template` — text that may contain `{{variable}}` references. A literal
///   (non-variable) template in a sensitive field is itself treated as
///   sensitive: it is masked in the UI, redacted in history, and replaced by a
///   placeholder in safe-share exports.
/// * `Secret` — a vault reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SensitiveValue {
    Template { value: String },
    Secret { secret: SecretRef },
}

impl Default for SensitiveValue {
    fn default() -> Self {
        SensitiveValue::Template { value: String::new() }
    }
}

impl SensitiveValue {
    pub fn template(value: impl Into<String>) -> Self {
        SensitiveValue::Template { value: value.into() }
    }

    /// True when the value is only variable references (no literal secret
    /// material embedded in the object graph).
    pub fn is_pure_reference(&self) -> bool {
        match self {
            SensitiveValue::Secret { .. } => true,
            SensitiveValue::Template { value } => {
                let t = value.trim();
                t.is_empty() || (t.starts_with("{{") && t.ends_with("}}") && t.matches("{{").count() == 1)
            }
        }
    }
}

/// What a template value (a header, query, form, auth or variable value)
/// holds, as the importers and the export sanitizer judge credentials
/// ([`classify_template_value`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TemplateKind {
    /// Nothing but whitespace.
    Empty,
    /// Exactly one variable reference and nothing else.
    Reference,
    /// Only variable references, with nothing between them but whitespace or
    /// one auth-scheme word (`Bearer {{token}}`).
    References,
    /// Anything else: literal text, an expression that is not a reference in
    /// the source's syntax ([`TemplateSyntax`]), a dynamic helper with
    /// arguments, an unterminated `{{`, or text mixed with references. Under a
    /// credential name, this is credential material.
    Literal,
}

/// How the source of a template value reads `{{…}}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TemplateSyntax {
    /// Postman, cURL (shell variables) and HAR: `{{…}}` names a variable and
    /// is never evaluated, so any text without braces is a variable name.
    /// Only a dynamic helper with arguments (`{{$randomFrom a|b}}`), which
    /// Anvil would evaluate with its literal arguments, is literal.
    #[default]
    Name,
    /// Insomnia (Nunjucks) and the export sanitizer, which cannot tell where a
    /// value came from: a reference is only an identifier
    /// `[A-Za-z_][A-Za-z0-9_]*` or a dotted path of them, optionally after
    /// `_.`. Anything else (a quoted string, a number, `-` or another
    /// operator, a filter, a helper) is an expression whose text is literal.
    Nunjucks,
}

/// Auth-scheme words that carry no secret next to a reference.
const SCHEME_WORDS: &[&str] = &["bearer", "basic", "token", "digest", "apikey", "dpop", "hmac", "negotiate", "jwt"];

/// Whether a `{{…}}` expression is a variable reference in `syntax`
/// ([`TemplateSyntax`]).
pub fn is_plain_reference_expr(expr: &str, syntax: TemplateSyntax) -> bool {
    let e = expr.trim();
    match syntax {
        TemplateSyntax::Name => {
            !e.is_empty() && !e.contains(['{', '}']) && !e.strip_prefix('$').is_some_and(|helper| helper.contains(char::is_whitespace))
        }
        TemplateSyntax::Nunjucks => {
            let path = e.strip_prefix("_.").unwrap_or(e);
            !path.is_empty()
                && path.split('.').all(|ident| {
                    let mut chars = ident.chars();
                    chars.next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
                        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
                })
        }
    }
}

/// Classify a template value ([`TemplateKind`]) read in `syntax`. One rule for
/// every place that decides whether a credential-named value is a reference
/// to keep or a literal to redact or extract.
pub fn classify_template_value(value: &str, syntax: TemplateSyntax) -> TemplateKind {
    let t = value.trim();
    if t.is_empty() {
        return TemplateKind::Empty;
    }
    let mut rest = t;
    let mut literal = String::new();
    let mut references = 0usize;
    while let Some(open) = rest.find("{{") {
        literal.push_str(&rest[..open]);
        let after = &rest[open + 2..];
        let Some(close) = after.find("}}") else { return TemplateKind::Literal };
        if !is_plain_reference_expr(&after[..close], syntax) {
            return TemplateKind::Literal;
        }
        references += 1;
        rest = &after[close + 2..];
    }
    literal.push_str(rest);
    let lit = literal.trim();
    match (references, lit.is_empty()) {
        (0, _) => TemplateKind::Literal,
        (1, true) => TemplateKind::Reference,
        (_, true) => TemplateKind::References,
        _ if SCHEME_WORDS.contains(&lit.to_ascii_lowercase().as_str()) => TemplateKind::References,
        _ => TemplateKind::Literal,
    }
}

/// The byte offset of the `@` that ends the userinfo in `after_scheme` (a
/// URL with its `scheme://` removed), if it has one. `{{…}}` expressions are
/// not parsed; the rule fails closed instead:
///
/// * When no `{{` comes before the first `@`, RFC 3986 applies: the
///   authority ends at the first `/`, `?` or `#`, and its last `@` ends the
///   userinfo.
/// * Otherwise a delimiter only ends the authority when it is unambiguous:
///   outside every `{{` seen so far (counting `{{` and `}}`), and not
///   followed by a stray `}}` that shows it was inside an expression after
///   all (`{{ 'a}}/b' | f }}`). The userinfo then ends at the last `@` before
///   the first unambiguous delimiter, or before the end when there is none,
///   so an ambiguous userinfo is taken off whole rather than left in the URL.
///
/// One pass, linear in the input.
pub fn userinfo_end(after_scheme: &str) -> Option<usize> {
    let bytes = after_scheme.as_bytes();
    let first_at = after_scheme.find('@')?;
    if !after_scheme[..first_at].contains("{{") {
        let end = after_scheme.find(['/', '?', '#']).unwrap_or(after_scheme.len());
        return after_scheme[..end].rfind('@');
    }
    let mut depth = 0usize;
    let mut boundary = None;
    let mut ats = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i..].starts_with(b"{{") {
            depth += 1;
            i += 2;
            continue;
        }
        if bytes[i..].starts_with(b"}}") {
            if depth > 0 {
                depth -= 1;
            } else {
                // A stray `}}`: the delimiter taken as the boundary was inside
                // an expression.
                boundary = None;
            }
            i += 2;
            continue;
        }
        match bytes[i] {
            b'/' | b'?' | b'#' if depth == 0 && boundary.is_none() => boundary = Some(i),
            b'@' => ats.push(i),
            _ => {}
        }
        i += 1;
    }
    let end = boundary.unwrap_or(bytes.len());
    ats.into_iter().rev().find(|&at| at < end)
}

/// Whether a URL userinfo is exactly variable references in `syntax`:
/// `{{user}}`, `{{user}}:` or `{{user}}:{{password}}`. Anything else (a
/// literal user name or password, an expression, a token) is credential
/// material.
pub fn is_plain_userinfo(userinfo: &str, syntax: TemplateSyntax) -> bool {
    let (user, pass) = match userinfo.split_once(':') {
        Some((u, p)) => (u, p),
        None => (userinfo, ""),
    };
    classify_template_value(user, syntax) == TemplateKind::Reference
        && matches!(classify_template_value(pass, syntax), TemplateKind::Empty | TemplateKind::Reference)
}

/// Marker text substituted wherever a secret would otherwise be displayed or
/// written.
pub const REDACTED: &str = "‹redacted›";

/// How far past a cut the redactor looks: a secret (in any form the redactor
/// knows) that starts before the cut and is at most this long is recognized
/// whole before the text is cut. Only this much past the cut is redacted,
/// whatever the text's size.
pub const REDACT_LOOKAHEAD_BYTES: usize = 64 * 1024;

/// The largest char boundary of `s` at or below byte `i` (`s.len()` when `i`
/// is past the end).
pub fn floor_char_boundary(s: &str, i: usize) -> usize {
    let mut end = i.min(s.len());
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    end
}

/// `window` redacted, then cut at `cut` bytes (a char boundary of `window`).
///
/// Redaction runs before the cut, so a secret that crosses the cut is
/// replaced whole instead of leaving its prefix. `window` must hold the text
/// past the cut that the redactor needs to see (up to
/// [`REDACT_LOOKAHEAD_BYTES`]). The result shows nothing from past the cut:
/// when a secret crosses it, the result ends with [`REDACTED`] where that
/// secret starts.
pub fn redact_then_cut<F: Fn(&str) -> String + ?Sized>(redact: &F, window: &str, cut: usize) -> String {
    if cut >= window.len() {
        return redact(window);
    }
    let whole = redact(window);
    if whole == window {
        // Nothing in the window is secret, so nothing before the cut is.
        return window[..cut].to_string();
    }
    let head = redact(&window[..cut]);
    let tail = redact(&window[cut..]);
    if whole.len() == head.len() + tail.len() && whole.starts_with(&head) && whole.ends_with(&tail) {
        // Redacting either side alone finds the same secrets: none crosses the cut.
        return head;
    }
    // A secret crosses the cut. What precedes it is the same in both forms;
    // from where they differ on, the head holds that secret's prefix.
    let same = whole.bytes().zip(head.bytes()).take_while(|(a, b)| a == b).count();
    let mut out = head[..floor_char_boundary(&head, same)].to_string();
    out.push_str(REDACTED);
    out
}

/// At most `max_chars` characters of `s`, redacted before the cut when a
/// redactor is given ([`redact_then_cut`], over up to
/// [`REDACT_LOOKAHEAD_BYTES`] past the cut): a secret that crosses the cut
/// is replaced whole instead of leaving its prefix. Without a redactor, `s`
/// is only cut.
pub fn redacted_excerpt<F: Fn(&str) -> String + ?Sized>(redact: Option<&F>, s: &str, max_chars: usize) -> String {
    let cut = s.char_indices().nth(max_chars).map_or(s.len(), |(i, _)| i);
    match redact {
        Some(r) => redact_then_cut(r, &s[..floor_char_boundary(s, cut.saturating_add(REDACT_LOOKAHEAD_BYTES))], cut),
        None => s[..cut].to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "s3cr3t-t0k3n-value";

    fn scrub(s: &str) -> String {
        s.replace(SECRET, REDACTED)
    }

    #[test]
    fn floor_char_boundary_never_splits_a_character() {
        let s = "aé€";
        assert_eq!(floor_char_boundary(s, 0), 0);
        assert_eq!(floor_char_boundary(s, 2), 1, "inside `é`");
        assert_eq!(floor_char_boundary(s, 3), 3);
        assert_eq!(floor_char_boundary(s, 5), 3, "inside `€`");
        assert_eq!(floor_char_boundary(s, 6), 6);
        assert_eq!(floor_char_boundary(s, usize::MAX), s.len(), "past the end");
    }

    #[test]
    fn redact_then_cut_never_shows_what_is_past_the_cut() {
        let r = |s: &str| s.replace("abcdef", "#");
        // The secret crosses the cut: the result stops where it starts.
        assert_eq!(redact_then_cut(&r, "xxabcdefyy", 4), format!("xx{REDACTED}"));
        // Wholly before the cut; wholly after it; none.
        assert_eq!(redact_then_cut(&r, "abcdefxxyy", 8), "#xx");
        assert_eq!(redact_then_cut(&r, "xxyyabcdef", 4), "xxyy");
        assert_eq!(redact_then_cut(&r, "xxyyzz", 3), "xxy");
        // A cut at or past the end redacts the whole text.
        assert_eq!(redact_then_cut(&r, "xxabcdef", 8), "xx#");
    }

    #[test]
    fn excerpts_are_redacted_before_they_are_cut() {
        let redact = Some(&scrub as &dyn Fn(&str) -> String);
        // The cut (20 characters) falls after the secret's first 4 characters, then after all but its last.
        for keep in [4, SECRET.len() - 1] {
            let pad = "p".repeat(20 - keep);
            assert_eq!(redacted_excerpt(redact, &format!("{pad}{SECRET} and more"), 20), format!("{pad}{REDACTED}"), "keep {keep}");
        }
        // Positive controls: a secret wholly before the cut, wholly after it, a multi-byte cut, a short text.
        assert_eq!(redacted_excerpt(redact, &format!("{SECRET} and more text after it"), 30), format!("{REDACTED} and more te"));
        assert_eq!(redacted_excerpt(redact, &format!("{} {SECRET}", "a".repeat(30)), 20), "a".repeat(20));
        assert_eq!(redacted_excerpt(redact, &"é".repeat(25), 20), "é".repeat(20), "the cut counts characters");
        assert_eq!(redacted_excerpt(redact, "short", 20), "short");
        // Without a redactor the text is only cut, so a crossing secret leaves its prefix.
        let none: Option<&dyn Fn(&str) -> String> = None;
        assert_eq!(redacted_excerpt(none, &format!("{}{SECRET}", "p".repeat(16)), 20), format!("{}{}", "p".repeat(16), &SECRET[..4]));
    }

    #[test]
    fn the_redactor_sees_only_the_lookahead_past_the_cut() {
        // Cut after 3 characters; the window then ends `REDACT_LOOKAHEAD_BYTES` past the cut.
        // A secret starting at byte 2 that ends inside the window is recognized whole ...
        let fits = "L".repeat(REDACT_LOOKAHEAD_BYTES + 1);
        let r = |s: &str| s.replace(&fits, "#");
        assert_eq!(redacted_excerpt(Some(&r), &format!("ab{fits}zz"), 3), format!("ab{REDACTED}"));
        // ... one byte longer, it is not: the redactor never sees past the window.
        let too_long = "L".repeat(REDACT_LOOKAHEAD_BYTES + 2);
        let r = |s: &str| s.replace(&too_long, "#");
        assert_eq!(redacted_excerpt(Some(&r), &format!("ab{too_long}zz"), 3), "abL");
    }
}

#[cfg(test)]
mod template_kind_tests {
    use super::*;

    #[test]
    fn userinfo_ends_at_the_last_at_before_an_unambiguous_delimiter() {
        for (after, userinfo) in [
            ("admin:pw@host/x", Some("admin:pw")),
            ("admin:p@ss@host/x@y", Some("admin:p@ss")),
            ("host/x@y", None),
            ("host?email=a@b", None),
            ("admin:pw@{{host}}/x", Some("admin:pw")),
            ("{{host}}/x?e=a@b&k={{key}}&m=c@d", None),
            ("{{baseUrl}}/users/me@x", None),
            // A delimiter, or a quoted `}}`, inside an expression.
            ("admin:{{ 'a/b?c#d' | urlencode }}@host/x", Some("admin:{{ 'a/b?c#d' | urlencode }}")),
            ("admin:{{ 'tok}}/suffix' | urlencode }}@host/x", Some("admin:{{ 'tok}}/suffix' | urlencode }}")),
            ("admin:{{ \"q}}?x\" }}@host", Some("admin:{{ \"q}}?x\" }}")),
            // An expression that closes only in the query.
            ("user:pa{{ss@host/v1?q={{x}}", Some("user:pa{{ss")),
            // A credential URL inside an expression is taken off up to its `@`.
            ("{{ 'https://admin:tok@api.example.test' | replace('https://', '') }}/v1", Some("{{ 'https://admin:tok")),
        ] {
            assert_eq!(userinfo_end(after).map(|at| &after[..at]), userinfo, "{after:?}");
        }
        let long = format!("admin:{{{{{}'tok/x'|urlencode}}}}@api.example.test/v1", " ".repeat(8192));
        assert_eq!(userinfo_end(&long), long.find("}}@").map(|i| i + 2));
        let unterminated = format!("u:{}@host", "{".repeat(1 << 20));
        assert!(userinfo_end(&unterminated).is_some());
    }

    #[test]
    fn only_references_make_a_plain_userinfo() {
        use TemplateSyntax::Nunjucks;
        for plain in ["{{user}}", "{{user}}:", "{{user}}:{{pass}}", "{{ _.user }}:{{ _.pass }}"] {
            assert!(is_plain_userinfo(plain, Nunjucks), "{plain:?}");
        }
        for literal in ["admin", "admin:pw", "admin:{{pw}}", "{{user}}:pw", ":{{pw}}", "{{ 'tok:rest' }}", "", "tok"] {
            assert!(!is_plain_userinfo(literal, Nunjucks), "{literal:?}");
        }
    }

    #[test]
    fn references_follow_the_source_syntax() {
        use TemplateKind::*;
        use TemplateSyntax::*;
        for (v, name, nunjucks) in [
            ("", Empty, Empty),
            ("  ", Empty, Empty),
            ("{{token}}", Reference, Reference),
            (" {{ token }} ", Reference, Reference),
            ("{{ _.api.version }}", Reference, Reference),
            ("Bearer {{token}}", References, References),
            ("{{a}}{{b}}", References, References),
            ("{{user}}:{{pass}}", Literal, Literal),
            // Never evaluated by Postman, cURL or HAR: a variable name.
            ("{{a-b}}", Reference, Literal),
            ("{{ _.zero--571571575 }}", Reference, Literal),
            ("{{ 'tok-SENSITIVE-k1' }}", Reference, Literal),
            ("{{ 571571571 }}", Reference, Literal),
            ("{{ x | upper }}", Reference, Literal),
            ("{{api key}}", Reference, Literal),
            ("{{$guid}}", Reference, Literal),
            // Evaluated by Anvil with literal arguments.
            ("{{$randomFrom a|b}}", Literal, Literal),
            ("{{tenant}}-live", Literal, Literal),
            ("{{unterminated", Literal, Literal),
            ("{{}}", Literal, Literal),
            ("literal", Literal, Literal),
        ] {
            assert_eq!(classify_template_value(v, Name), name, "Name: {v:?}");
            assert_eq!(classify_template_value(v, Nunjucks), nunjucks, "Nunjucks: {v:?}");
        }
    }
}
