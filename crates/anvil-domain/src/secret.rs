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
