//! Ferrum Edge compatibility catalogs: the source-audited outcome inventory
//! of each supported release (`catalog/ferrum/<compat-id>/outcomes.json`)
//! and public-signal matching.
//!
//! Every catalog is keyed by the `compatibility_id` an integration profile
//! declares. A profile whose id has no embedded catalog gets no catalog at
//! all — never another release's — so rules fall back to the
//! version-independent token vocabulary ([`shared_tokens`]).
//!
//! Matching compares *observable* signals only (status, `X-Gateway-Error`,
//! body text, gRPC status). Outcomes that share an identical public signal
//! are returned together; the rules then report them as indistinguishable
//! rather than choosing one.

use crate::facts::BodyFacts;
use regex::Regex;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::OnceLock;

/// The compatibility id new integration profiles default to: the newest
/// audited release.
pub const DEFAULT_COMPATIBILITY_ID: &str = "ferrum-edge-0.9.7";

/// Every embedded catalog, oldest release first: (compatibility id, outcomes.json).
const EMBEDDED: &[(&str, &str)] = &[
    ("ferrum-edge-0.9.5", include_str!("../../../catalog/ferrum/ferrum-edge-0.9.5/outcomes.json")),
    ("ferrum-edge-0.9.7", include_str!("../../../catalog/ferrum/ferrum-edge-0.9.7/outcomes.json")),
];

#[derive(Debug, Deserialize)]
struct RawCatalog {
    compatibility_id: String,
    #[serde(default)]
    public_tokens: Vec<String>,
    #[serde(default)]
    headers: Vec<RawHeader>,
    #[serde(default)]
    outcomes: Vec<RawOutcome>,
    #[serde(default)]
    gateway: serde_json::Value,
    #[serde(default)]
    marker_semantics: RawMarkerSemantics,
}

/// Release-specific sentences a catalog adds to the release-neutral wording
/// of the marker findings (`ferrum.token.<t>`, `ferrum.marker.absent`).
#[derive(Debug, Default, Clone, Deserialize)]
pub struct ReleaseNotes {
    #[serde(default)]
    pub explanation: String,
    #[serde(default)]
    pub alternatives: Vec<String>,
    #[serde(default)]
    pub does_not_prove: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
struct RawMarkerSemantics {
    #[serde(default)]
    tokens: HashMap<String, ReleaseNotes>,
    #[serde(default)]
    absent: ReleaseNotes,
}

#[derive(Debug, Deserialize)]
struct RawHeader {
    name: String,
    #[serde(default)]
    spoofable_by_backend: serde_json::Value,
}

#[derive(Debug, Deserialize, Clone)]
struct RawOutcome {
    id: String,
    #[serde(default)]
    family: String,
    #[serde(default)]
    public_signal: serde_json::Value,
    #[serde(default)]
    evidence_visibility: String,
    #[serde(default)]
    shared_signal_with: Vec<String>,
    #[serde(default)]
    minimum_truthful_diagnosis: String,
    #[serde(default)]
    must_not_claim: serde_json::Value,
    #[serde(default)]
    remediation: serde_json::Value,
    #[serde(default)]
    owner: String,
    #[serde(default)]
    fixture_ids: Vec<String>,
}

#[derive(Debug, Clone)]
pub enum BodyPattern {
    Json(serde_json::Value),
    Regex(Regex),
}

#[derive(Debug, Clone)]
pub struct Outcome {
    pub id: String,
    pub family: String,
    pub statuses: Vec<u16>,
    /// `None` = no constraint could be parsed; `Some(vec![])` = no token expected.
    pub tokens: Option<Vec<String>>,
    pub body_patterns: Vec<BodyPattern>,
    /// True when the body is the backend's own (pass-through) body.
    pub body_passthrough: bool,
    pub grpc_status: Option<i32>,
    pub evidence_visibility: String,
    pub shared_signal_with: Vec<String>,
    pub minimum_truthful_diagnosis: String,
    pub must_not_claim: Vec<String>,
    pub remediation: Vec<String>,
    pub owner: String,
    pub fixture_ids: Vec<String>,
}

#[derive(Debug)]
pub struct FerrumCatalog {
    pub compatibility_id: String,
    /// Gateway release tag the catalog was audited at (e.g. `v0.9.7`).
    pub release_tag: String,
    pub source_sha: String,
    pub tokens: Vec<String>,
    pub outcomes: Vec<Outcome>,
    /// Whether a backend can make `X-Gateway-Error` appear on a response:
    /// `Some(false)` only when the audit established the gateway strips/overrides it.
    pub marker_spoofable: Option<bool>,
    /// Release-specific notes per public token.
    pub token_notes: HashMap<String, ReleaseNotes>,
    /// Release-specific notes for a 5xx that carries no marker.
    pub absent_notes: ReleaseNotes,
}

fn strings(v: &serde_json::Value) -> Vec<String> {
    match v {
        serde_json::Value::String(s) if !s.is_empty() => vec![s.clone()],
        serde_json::Value::Array(a) => a.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect(),
        _ => vec![],
    }
}

fn parse_statuses(v: &serde_json::Value) -> Vec<u16> {
    match v {
        serde_json::Value::Number(n) => n.as_u64().map(|n| vec![n as u16]).unwrap_or_default(),
        serde_json::Value::String(s) => {
            let parts: Vec<&str> = s.split('|').map(|p| p.trim()).collect();
            if parts.iter().all(|p| p.parse::<u16>().is_ok()) { parts.iter().filter_map(|p| p.parse().ok()).collect() } else { vec![] }
        }
        _ => vec![],
    }
}

fn parse_tokens(v: &serde_json::Value, known: &[String]) -> Option<Vec<String>> {
    match v {
        serde_json::Value::Null => Some(vec![]),
        serde_json::Value::String(s) => {
            let parts: Vec<String> = s.split('|').map(|p| p.trim().to_string()).collect();
            if parts.iter().all(|p| known.contains(p)) { Some(parts) } else { None }
        }
        _ => None,
    }
}

fn pattern_from_text(alt: &str) -> Option<BodyPattern> {
    let (Some(start), Some(end)) = (alt.find('{'), alt.rfind('}')) else { return None };
    if end <= start {
        return None;
    }
    let candidate = &alt[start..=end];
    if candidate.contains('<') && candidate.contains('>') {
        // Placeholders such as <n> or <limit>: build an anchored regex.
        let mut re = String::from("^");
        let mut rest = candidate;
        while let Some(open) = rest.find('<') {
            re.push_str(&regex::escape(&rest[..open]));
            match rest[open..].find('>') {
                Some(close) => {
                    re.push_str(".{0,200}?");
                    rest = &rest[open + close + 1..];
                }
                None => {
                    re.push_str(&regex::escape(&rest[open..]));
                    rest = "";
                }
            }
        }
        re.push_str(&regex::escape(rest));
        re.push('$');
        return Regex::new(&re).ok().map(BodyPattern::Regex);
    }
    serde_json::from_str::<serde_json::Value>(candidate).ok().map(BodyPattern::Json)
}

fn parse_bodies(v: &serde_json::Value) -> (Vec<BodyPattern>, bool) {
    let Some(s) = v.as_str() else { return (vec![], false) };
    let passthrough = s.to_ascii_lowercase().contains("backend's own") || s.to_ascii_lowercase().contains("backend body");
    let mut pats = Vec::new();
    // Split on " | " only between JSON alternatives.
    for alt in s.split(" | ") {
        if let Some(p) = pattern_from_text(alt) {
            pats.push(p);
        }
    }
    (pats, passthrough)
}

/// Every embedded catalog, oldest release first.
pub fn catalogs() -> &'static [FerrumCatalog] {
    static C: OnceLock<Vec<FerrumCatalog>> = OnceLock::new();
    C.get_or_init(|| {
        EMBEDDED
            .iter()
            .map(|(id, raw)| {
                let c = load(raw).unwrap_or_else(|e| panic!("embedded Ferrum catalog {id} is invalid: {e}"));
                assert_eq!(c.compatibility_id, *id, "catalog file declares a different compatibility id");
                c
            })
            .collect()
    })
}

/// Compatibility ids that have an embedded catalog, oldest release first.
pub fn compatibility_ids() -> impl Iterator<Item = &'static str> {
    EMBEDDED.iter().map(|(id, _)| *id)
}

/// The catalog for exactly this compatibility id. `None` for any other id:
/// an unknown release never borrows another release's catalog.
pub fn catalog_for(compatibility_id: &str) -> Option<&'static FerrumCatalog> {
    let id = compatibility_id.trim();
    catalogs().iter().find(|c| c.compatibility_id == id)
}

/// The catalog of [`DEFAULT_COMPATIBILITY_ID`].
pub fn default_catalog() -> &'static FerrumCatalog {
    catalog_for(DEFAULT_COMPATIBILITY_ID).expect("the default compatibility id has an embedded catalog")
}

/// Public tokens every embedded catalog defines. This is the only vocabulary
/// rules use for a trusted profile whose compatibility id has no catalog,
/// and only with the coarse meaning the audited releases share.
pub fn shared_tokens() -> &'static [String] {
    static T: OnceLock<Vec<String>> = OnceLock::new();
    T.get_or_init(|| {
        let all = catalogs();
        all.first()
            .map(|first| first.tokens.iter().filter(|t| all.iter().all(|c| c.tokens.contains(*t))).cloned().collect())
            .unwrap_or_default()
    })
}

pub fn load(raw: &str) -> Result<FerrumCatalog, serde_json::Error> {
    let rc: RawCatalog = serde_json::from_str(raw)?;
    let tokens = rc.public_tokens.clone();
    let outcomes = rc
        .outcomes
        .iter()
        .map(|o| {
            let sig = &o.public_signal;
            let (body_patterns, body_passthrough) = parse_bodies(sig.get("body_shape").unwrap_or(&serde_json::Value::Null));
            Outcome {
                id: o.id.clone(),
                family: o.family.clone(),
                statuses: parse_statuses(sig.get("http_status").unwrap_or(&serde_json::Value::Null)),
                tokens: parse_tokens(sig.get("x_gateway_error").unwrap_or(&serde_json::Value::Null), &tokens),
                body_patterns,
                body_passthrough,
                grpc_status: sig.get("grpc_status").and_then(|g| g.as_i64()).map(|g| g as i32),
                evidence_visibility: o.evidence_visibility.clone(),
                shared_signal_with: o.shared_signal_with.clone(),
                minimum_truthful_diagnosis: o.minimum_truthful_diagnosis.clone(),
                must_not_claim: strings(&o.must_not_claim),
                remediation: strings(&o.remediation),
                owner: o.owner.clone(),
                fixture_ids: o.fixture_ids.clone(),
            }
        })
        .collect();
    let marker_spoofable =
        rc.headers.iter().find(|h| h.name.eq_ignore_ascii_case("x-gateway-error")).and_then(|h| h.spoofable_by_backend.as_bool());
    let source_sha = rc.gateway.get("source_sha").and_then(|s| s.as_str()).unwrap_or("").to_string();
    let release_tag = rc.gateway.get("release_tag").and_then(|s| s.as_str()).unwrap_or("").to_string();
    Ok(FerrumCatalog {
        compatibility_id: rc.compatibility_id,
        release_tag,
        source_sha,
        tokens,
        outcomes,
        marker_spoofable,
        token_notes: rc.marker_semantics.tokens,
        absent_notes: rc.marker_semantics.absent,
    })
}

/// Observable signals of an HTTP-family response.
pub struct Signal<'a> {
    pub status: u16,
    pub token: Option<&'a str>,
    pub body_text: &'a str,
    pub body: &'a BodyFacts,
    pub grpc_status: Option<i32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchStrength {
    /// Status, token and exact body text all matched.
    Exact,
    /// Status and token matched; the body is the backend's own pass-through.
    PassThrough,
}

impl FerrumCatalog {
    /// Human-readable release name, e.g. `Ferrum Edge 0.9.7`.
    pub fn release_label(&self) -> String {
        let v = self.release_tag.trim_start_matches('v');
        if v.is_empty() { self.compatibility_id.clone() } else { format!("Ferrum Edge {v}") }
    }

    pub fn is_known_token(&self, t: &str) -> bool {
        self.tokens.iter().any(|k| k == t)
    }

    pub fn outcome(&self, id: &str) -> Option<&Outcome> {
        self.outcomes.iter().find(|o| o.id == id)
    }

    /// All outcomes consistent with the observed signal.
    pub fn match_signal(&self, s: &Signal<'_>) -> Vec<(&Outcome, MatchStrength)> {
        let mut out = Vec::new();
        for o in &self.outcomes {
            if o.statuses.is_empty() || !o.statuses.contains(&s.status) {
                continue;
            }
            match &o.tokens {
                None => continue,
                Some(t) if t.is_empty() => {
                    if s.token.is_some() {
                        continue;
                    }
                }
                Some(t) => match s.token {
                    Some(obs) if t.iter().any(|x| x == obs) => {}
                    _ => continue,
                },
            }
            if let (Some(g), Some(og)) = (s.grpc_status, o.grpc_status)
                && g != og
            {
                continue;
            }
            if o.body_patterns.iter().any(|p| body_matches(p, s)) {
                out.push((o, MatchStrength::Exact));
            } else if o.body_patterns.is_empty() && o.body_passthrough {
                out.push((o, MatchStrength::PassThrough));
            }
        }
        out
    }
}

fn body_matches(p: &BodyPattern, s: &Signal<'_>) -> bool {
    match p {
        BodyPattern::Json(v) => s.body.json_canonical.as_ref() == Some(v),
        BodyPattern::Regex(r) => r.is_match(s.body_text.trim()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::facts::body_facts;

    const TOKENS: [&str; 7] =
        ["connection_failure", "backend_timeout", "backend_error", "circuit_breaker_open", "overload", "config_stale", "concurrency_limit"];

    #[test]
    fn every_embedded_catalog_loads_under_its_own_id_with_all_public_tokens() {
        let ids: Vec<&str> = compatibility_ids().collect();
        assert_eq!(ids, ["ferrum-edge-0.9.5", "ferrum-edge-0.9.7"]);
        for id in ids {
            let c = catalog_for(id).expect("embedded");
            assert_eq!(c.compatibility_id, id);
            assert_eq!(format!("ferrum-edge-{}", c.release_tag.trim_start_matches('v')), id, "release tag matches the id");
            assert_eq!(c.source_sha.len(), 40, "{id}: full source sha");
            for t in TOKENS {
                assert!(c.is_known_token(t), "{id}: missing token {t}");
            }
            assert!(c.outcomes.len() > 50);
            let mut seen = std::collections::HashSet::new();
            assert!(c.outcomes.iter().all(|o| seen.insert(o.id.as_str())), "{id}: duplicate outcome ids");
        }
        assert_eq!(default_catalog().compatibility_id, DEFAULT_COMPATIBILITY_ID);
        assert_eq!(default_catalog().release_label(), "Ferrum Edge 0.9.7");
    }

    #[test]
    fn unknown_compatibility_ids_get_no_catalog_and_only_the_shared_vocabulary() {
        for id in ["ferrum-edge-0.9.6", "ferrum-edge-1.0.0", "", "FERRUM-EDGE-0.9.7"] {
            assert!(catalog_for(id).is_none(), "{id:?} must not borrow another release's catalog");
        }
        assert!(catalog_for(" ferrum-edge-0.9.5 ").is_some(), "surrounding whitespace is not a different release");
        let shared: Vec<&str> = shared_tokens().iter().map(String::as_str).collect();
        assert_eq!(shared, TOKENS, "the coarse vocabulary is identical in every audited release");
    }

    #[test]
    fn backend_unavailable_signal_is_shared_by_many_upstream_causes() {
        for c in catalogs() {
            let body = br#"{"error":"Backend unavailable"}"#;
            let bf = body_facts(Some("application/json"), body);
            let m = c.match_signal(&Signal {
                status: 502,
                token: Some("connection_failure"),
                body_text: std::str::from_utf8(body).unwrap(),
                body: &bf,
                grpc_status: None,
            });
            assert!(
                m.len() > 3,
                "{}: DNS/TCP/TLS/pool causes share one public signal: {:?}",
                c.compatibility_id,
                m.iter().map(|x| &x.0.id).collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn placeholder_bodies_match_as_patterns() {
        for c in catalogs() {
            let body = br#"{"error":"Query parameter count (120) exceeds maximum of 100"}"#;
            let bf = body_facts(Some("application/json"), body);
            let m = c.match_signal(&Signal {
                status: 400,
                token: None,
                body_text: std::str::from_utf8(body).unwrap(),
                body: &bf,
                grpc_status: None,
            });
            assert!(
                m.iter().any(|(o, _)| o.id == "size.query_param_count_exceeded"),
                "{}: {:?}",
                c.compatibility_id,
                m.iter().map(|x| &x.0.id).collect::<Vec<_>>()
            );
        }
    }
}
