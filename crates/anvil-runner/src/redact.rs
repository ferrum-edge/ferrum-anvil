//! Run-level redaction.
//!
//! The engine already redacts what it knows per execution: sensitive header /
//! parameter / field names and every secret *variable value* it substituted.
//! Run-local values add two sources the engine cannot know about on its own:
//!
//! * dataset `sensitive_columns` (passed to the engine as secret variables,
//!   so a step that uses them is redacted by the engine too), and
//! * values extracted with `sensitive: true` — which first appear in the
//!   *response* of the step that extracts them, before any variable carries
//!   them.
//!
//! [`RunSecrets`] collects both and scrubs every executed record (before it
//! is recorded in history) and every report string with the engine's
//! [`Redactor`] (exact-value redaction plus the sensitive names). Values
//! shorter than 4 characters are not exact-value scrubbed (the engine's rule:
//! they would shred ordinary text); name-based redaction still applies.

use anvil_domain::execution::ExecutionRecord;
use anvil_domain::secret::REDACTED;
use anvil_engine::ExecutionOutput;
use anvil_engine::redact::Redactor;
use bytes::Bytes;
use std::collections::VecDeque;

/// Bound on remembered run secrets (oldest evicted first). Current-iteration
/// values are always present because they are added last.
pub const MAX_RUN_SECRETS: usize = 4_096;

#[derive(Clone, Default)]
pub struct RunSecrets {
    values: VecDeque<String>,
    names: Vec<String>,
    redactor: Redactor,
}

impl RunSecrets {
    pub fn new(names: Vec<String>) -> Self {
        let mut s = RunSecrets { values: VecDeque::new(), names, redactor: Redactor::default() };
        s.rebuild();
        s
    }

    fn rebuild(&mut self) {
        self.redactor = Redactor::new(self.values.iter().cloned().collect(), self.names.clone());
    }

    /// Add values; returns true if anything new was added.
    pub fn add_values<I: IntoIterator<Item = String>>(&mut self, it: I) -> bool {
        let mut changed = false;
        for v in it {
            if v.len() < 4 {
                continue;
            }
            if let Some(pos) = self.values.iter().position(|x| *x == v) {
                // Refresh recency so current-iteration values are not evicted.
                let x = self.values.remove(pos).expect("position is valid");
                self.values.push_back(x);
                continue;
            }
            self.values.push_back(v);
            while self.values.len() > MAX_RUN_SECRETS {
                self.values.pop_front();
            }
            changed = true;
        }
        if changed {
            self.rebuild();
        }
        changed
    }

    pub fn add_name(&mut self, name: &str) {
        if !self.names.iter().any(|n| n.eq_ignore_ascii_case(name)) {
            self.names.push(name.to_string());
            self.rebuild();
        }
    }

    pub fn names(&self) -> &[String] {
        &self.names
    }

    pub fn redactor(&self) -> &Redactor {
        &self.redactor
    }

    pub fn text(&self, s: &str) -> String {
        self.redactor.text(s)
    }

    pub fn url(&self, s: &str) -> String {
        self.redactor.url(s)
    }

    pub fn has_values(&self) -> bool {
        !self.values.is_empty()
    }

    /// Scrub every string of an execution record that can carry a value.
    pub fn scrub_record(&self, r: &mut ExecutionRecord) {
        let red = &self.redactor;
        r.prepared.url = red.url(&r.prepared.url);
        r.prepared.headers = red.headers(&r.prepared.headers);
        for s in &mut r.prepared.inferred {
            *s = red.text(s);
        }
        for a in &mut r.attempts {
            a.url = red.url(&a.url);
            if let Some(f) = &mut a.failure {
                f.message = red.text(&f.message);
            }
            for p in &mut a.phases {
                if let Some(d) = &mut p.detail {
                    *d = red.text(d);
                }
            }
        }
        if let Some(resp) = &mut r.response {
            resp.headers = red.headers(&resp.headers);
            resp.trailers = red.headers(&resp.trailers);
            if let Some(reason) = &mut resp.reason {
                *reason = red.text(reason);
            }
        }
        if let Some(st) = &mut r.stream {
            for m in &mut st.messages {
                if !m.preview_is_hex {
                    m.preview = red.text(&m.preview);
                }
            }
        }
        r.outcome.summary = red.text(&r.outcome.summary);
        for w in &mut r.outcome.warnings {
            w.message = red.text(&w.message);
        }
        for a in &mut r.assertion_results {
            a.label = red.text(&a.label);
            a.message = red.text(&a.message);
            if let Some(x) = &mut a.actual {
                *x = red.text(x);
            }
        }
        for f in &mut r.findings {
            f.title = red.text(&f.title);
            f.explanation = red.text(&f.explanation);
            for e in &mut f.evidence {
                e.value = red.text(&e.value);
            }
            for a in &mut f.alternatives {
                *a = red.text(a);
            }
        }
    }

    /// Scrub run secrets from the captured body before it is recorded in
    /// history. A content-encoded body that contains a secret once decoded
    /// cannot be scrubbed in place, so it is not kept (returns a note).
    pub fn scrub_body(&self, out: &mut ExecutionOutput) -> Option<String> {
        if !self.has_values() || out.body.is_empty() {
            return None;
        }
        let secrets: Vec<&[u8]> = self.values.iter().map(|v| v.as_bytes()).collect();
        if let Some(decoded) = &out.decoded_body {
            if secrets.iter().any(|s| contains(decoded, s)) {
                out.body = Bytes::new();
                out.decoded_body = None;
                return Some("a content-encoded response body contained a sensitive run value; it was not kept in history".into());
            }
            return None;
        }
        let mut body = out.body.to_vec();
        let mut changed = false;
        for s in &secrets {
            if contains(&body, s) {
                body = replace(&body, s, REDACTED.as_bytes());
                changed = true;
            }
        }
        if changed {
            out.body = Bytes::from(body);
        }
        None
    }
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}

fn replace(hay: &[u8], needle: &[u8], with: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(hay.len());
    let mut i = 0;
    while i < hay.len() {
        if hay.len() - i >= needle.len() && &hay[i..i + needle.len()] == needle {
            out.extend_from_slice(with);
            i += needle.len();
        } else {
            out.push(hay[i]);
            i += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_are_bounded_and_short_values_ignored() {
        let mut s = RunSecrets::new(vec![]);
        assert!(!s.add_values(vec!["abc".to_string()]));
        assert!(s.add_values((0..MAX_RUN_SECRETS + 10).map(|i| format!("secret-{i:05}"))));
        assert_eq!(s.values.len(), MAX_RUN_SECRETS);
        assert_eq!(s.text("x secret-04105 y"), format!("x {REDACTED} y"));
        assert_eq!(s.text("secret-00000"), "secret-00000", "oldest evicted");
    }

    #[test]
    fn byte_replace() {
        assert_eq!(replace(b"a-tok-b-tok", b"tok", b"X"), b"a-X-b-X".to_vec());
        assert!(contains(b"hello world", b"o w"));
    }
}
