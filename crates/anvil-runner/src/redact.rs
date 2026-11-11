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

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, AhoCorasickKind, MatchKind};
use anvil_domain::execution::{ContentDecoding, ExecutionRecord};
use anvil_domain::secret::REDACTED;
use anvil_engine::ExecutionOutput;
use anvil_engine::redact::Redactor;
use bytes::Bytes;
use std::collections::VecDeque;
use std::ops::Range;

/// Bound on remembered run secrets (oldest evicted first). Current-iteration
/// values are always present because they are added last.
pub const MAX_RUN_SECRETS: usize = 4_096;

/// Bound on the run-value matches scrubbed from one body; a body with more
/// is withheld whole rather than scanned on.
const MAX_BODY_MATCHES: usize = 1 << 20;

#[derive(Clone, Default)]
pub struct RunSecrets {
    values: VecDeque<String>,
    names: Vec<String>,
    redactor: Redactor,
    /// Every remembered value, matched in one pass over a body.
    body: BodyMatcher,
}

/// Finds run values in a captured body: one automaton over all of them, so a
/// body is read once however many values the run remembers.
#[derive(Clone, Default)]
enum BodyMatcher {
    #[default]
    Empty,
    Automaton(AhoCorasick),
    /// The values, when no automaton could be built for them: each is
    /// searched for in turn.
    Values(Vec<Vec<u8>>),
}

impl BodyMatcher {
    fn new<'a>(values: impl IntoIterator<Item = &'a String>) -> Self {
        let values: Vec<&[u8]> = values.into_iter().map(|v| v.as_bytes()).filter(|v| !v.is_empty()).collect();
        if values.is_empty() {
            return BodyMatcher::Empty;
        }
        match AhoCorasickBuilder::new().kind(Some(AhoCorasickKind::ContiguousNFA)).match_kind(MatchKind::Standard).build(&values) {
            Ok(automaton) => BodyMatcher::Automaton(automaton),
            Err(_) => BodyMatcher::Values(values.into_iter().map(<[u8]>::to_vec).collect()),
        }
    }

    fn is_match(&self, hay: &[u8]) -> bool {
        match self {
            BodyMatcher::Empty => false,
            BodyMatcher::Automaton(a) => a.is_match(hay),
            BodyMatcher::Values(values) => values.iter().any(|v| hay.windows(v.len()).any(|w| w == v.as_slice())),
        }
    }

    /// The spans of `hay` any value covers, in order, overlapping matches
    /// merged into one; `None` past [`MAX_BODY_MATCHES`] matches.
    fn spans(&self, hay: &[u8]) -> Option<Vec<Range<usize>>> {
        let mut spans: Vec<Range<usize>> = Vec::new();
        let mut add = |found: Range<usize>| {
            // Matches arrive in end order, so one can reach back over several
            // earlier spans.
            let mut start = found.start;
            while spans.last().is_some_and(|last| last.end > start) {
                if let Some(last) = spans.pop() {
                    start = start.min(last.start);
                }
            }
            spans.push(start..found.end);
        };
        match self {
            BodyMatcher::Empty => {}
            BodyMatcher::Automaton(a) => {
                for (index, m) in a.find_overlapping_iter(hay).enumerate() {
                    if index == MAX_BODY_MATCHES {
                        return None;
                    }
                    add(m.range());
                }
            }
            BodyMatcher::Values(values) => {
                // Every match, ordered by where it ends.
                let mut found: Vec<Range<usize>> = Vec::new();
                for v in values {
                    for at in (0..=hay.len().saturating_sub(v.len())).filter(|&at| hay[at..].starts_with(v)) {
                        if found.len() == MAX_BODY_MATCHES {
                            return None;
                        }
                        found.push(at..at + v.len());
                    }
                }
                found.sort_by_key(|r| (r.end, r.start));
                found.into_iter().for_each(&mut add);
            }
        }
        Some(spans)
    }
}

impl RunSecrets {
    pub fn new(names: Vec<String>) -> Self {
        let mut s = RunSecrets { values: VecDeque::new(), names, redactor: Redactor::default(), body: BodyMatcher::Empty };
        s.rebuild();
        s
    }

    /// Rebuild the matchers from the values and names: once per change of
    /// either (an `add_values` call adds every value of an iteration at once).
    fn rebuild(&mut self) {
        self.redactor = Redactor::new(self.values.iter().cloned().collect(), self.names.clone());
        self.body = BodyMatcher::new(&self.values);
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
        red.record_metadata(r);
        if let Some(st) = &mut r.stream {
            // Hex previews too: the redactor knows secrets' hex forms.
            for m in &mut st.messages {
                m.preview = red.text(&m.preview);
                for s in [&mut m.event_id, &mut m.event_type].into_iter().flatten() {
                    *s = red.text(s);
                }
            }
        }
    }

    /// Scrub run secrets from the captured body before it is recorded in
    /// history. A content-encoded body cannot be scrubbed in place: it is
    /// kept only when it was decoded completely and the decoded content holds
    /// no run secret. Otherwise (a secret found, decoding truncated, failed or
    /// unsupported, or decompression off) neither the raw nor the decoded
    /// body is kept, and the returned note says so.
    pub fn scrub_body(&self, out: &mut ExecutionOutput) -> Option<String> {
        if !self.has_values() || out.body.is_empty() {
            return None;
        }
        let capture = out.record.response.as_ref().map(|r| &r.body);
        let coded = out.decoded_body.is_some()
            || out.response_metadata.as_ref().map_or_else(
                || capture.is_some_and(|b| has_content_coding(b.content_encoding.as_deref())),
                anvil_engine::ResponseMetadata::has_content_coding,
            );
        if coded {
            let complete = capture.and_then(|b| b.decoding) == Some(ContentDecoding::Complete);
            let reason = match out.decoded_body.as_ref().filter(|_| complete) {
                None => Some("it was not fully decoded, so it could not be checked for sensitive run values"),
                Some(d) if self.body.is_match(d) || self.body.is_match(&out.body) => Some("it contained a sensitive run value"),
                Some(_) => None,
            };
            let reason = reason?;
            out.body = Bytes::new();
            out.decoded_body = None;
            return Some(format!("A content-encoded response body was not kept in history: {reason}."));
        }
        match self.body.spans(&out.body) {
            Some(spans) => {
                if !spans.is_empty() {
                    out.body = Bytes::from(replace_spans(&out.body, &spans));
                }
            }
            // So many matches that the body is mostly run values.
            None => out.body = Bytes::from_static(REDACTED.as_bytes()),
        }
        None
    }
}

/// `hay` with each span (in order, not overlapping) replaced by one marker.
fn replace_spans(hay: &[u8], spans: &[Range<usize>]) -> Vec<u8> {
    let mut out = Vec::with_capacity(hay.len());
    let mut at = 0;
    for span in spans {
        out.extend_from_slice(&hay[at..span.start]);
        out.extend_from_slice(REDACTED.as_bytes());
        at = span.end;
    }
    out.extend_from_slice(&hay[at..]);
    out
}

/// True when a `Content-Encoding` value names any coding other than
/// `identity`, including ones Anvil cannot decode (e.g. `none`).
fn has_content_coding(ce: Option<&str>) -> bool {
    ce.is_some_and(|ce| ce.split(',').map(str::trim).any(|c| !c.is_empty() && !c.eq_ignore_ascii_case("identity")))
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
    fn records_redact_url_values_as_urls() {
        use anvil_domain::diagnostics::{Confidence, DiagnosticFinding, Evidence, EvidenceSource, Owner, Severity, SourceScope};
        use anvil_domain::execution::{FailureKind, Phase, TransportFailure};

        let ctx = anvil_engine::ExecutionContext::standalone(anvil_domain::request::RequestSpec::http("GET", "https://example.test/"));
        let resolver = anvil_engine::vars::Resolver::new(vec![], None);
        let failure = TransportFailure::new(Phase::Prepare, FailureKind::InvalidUrl, "not sent");
        let mut record = anvil_engine::record::local_failure(&ctx, &resolver, chrono::Utc::now(), failure).record;
        // `%2D` is not a canonical encoding: exact-value scrubbing misses it,
        // URL redaction does not.
        record.prepared.inferred.push("auth dpop.htu: https://h/u/run%2Dvalue-5e6f/x".into());
        let endpoint = "idp.test/t/run%2Dvalue-5e6f/authorize";
        record.findings.push(DiagnosticFinding {
            code: "auth.browser_session_required".into(),
            rule_id: "auth.session".into(),
            rule_version: 1,
            title: "login".into(),
            explanation: format!("example.test redirected this request ({endpoint})."),
            scope: SourceScope::Unknown,
            confidence: Confidence::Likely,
            severity: Severity::Error,
            evidence: vec![Evidence {
                source: EvidenceSource::HttpHeader,
                key: "redirect.authorization_endpoint".into(),
                value: endpoint.into(),
                attempt: Some(1),
            }],
            alternatives: vec![],
            does_not_prove: vec![],
            remediation: vec![],
            owner: Owner::Caller,
            confirm_with: vec![],
        });

        let mut s = RunSecrets::new(vec![]);
        s.add_values(vec!["run-value-5e6f".to_string()]);
        s.scrub_record(&mut record);
        assert!(record.prepared.inferred.contains(&format!("auth dpop.htu: https://h/u/{REDACTED}/x")), "{:?}", record.prepared.inferred);
        let f = record.findings.last().unwrap();
        assert_eq!(f.evidence[0].value, format!("idp.test/t/{REDACTED}/authorize"));
        assert_eq!(f.explanation, format!("example.test redirected this request (idp.test/t/{REDACTED}/authorize)."));
    }

    #[test]
    fn body_spans_cover_every_value_and_merge_overlaps() {
        let values: Vec<String> = ["tok-1", "abcd", "bcde", "aaaa"].into_iter().map(String::from).collect();
        let matchers = [BodyMatcher::new(&values), BodyMatcher::Values(values.iter().map(|v| v.as_bytes().to_vec()).collect())];
        for m in &matchers {
            let scrub = |hay: &[u8]| String::from_utf8(replace_spans(hay, &m.spans(hay).unwrap())).unwrap();
            assert_eq!(scrub(b"a-tok-1-b-tok-1"), format!("a-{REDACTED}-b-{REDACTED}"));
            // Overlapping values are covered whole, not one with a residue.
            assert_eq!(scrub(b"<abcde>"), format!("<{REDACTED}>"));
            assert_eq!(scrub(b"xaaaaaay"), format!("x{REDACTED}y"));
            assert_eq!(scrub(b"nothing here"), "nothing here");
            assert!(m.is_match(b"..bcde..") && !m.is_match(b"bcd"));
        }
        assert!(!BodyMatcher::new(&Vec::<String>::new()).is_match(b"anything"));
        assert_eq!(BodyMatcher::Empty.spans(b"anything"), Some(vec![]));
    }

    #[test]
    fn a_body_with_too_many_matches_is_withheld_whole() {
        let values = vec!["xxxx".to_string()];
        let hay = vec![b'x'; MAX_BODY_MATCHES + 4];
        assert_eq!(BodyMatcher::new(&values).spans(&hay), None);
    }

    #[test]
    fn content_coding_detection() {
        for ce in [Some("gzip"), Some("identity, br"), Some("none"), Some(" GZIP ")] {
            assert!(has_content_coding(ce), "{ce:?}");
        }
        for ce in [None, Some(""), Some("identity"), Some(" Identity , ")] {
            assert!(!has_content_coding(ce), "{ce:?}");
        }
    }
}
