//! Ferrum Edge compatibility catalog: the source-audited outcome inventory
//! (`catalog/ferrum/<compat-id>/outcomes.json`) and public-signal matching.
//!
//! Matching compares *observable* signals only (status, `X-Gateway-Error`,
//! body text, gRPC status). Outcomes that share an identical public signal
//! are returned together; the rules then report them as indistinguishable
//! rather than choosing one.

use crate::facts::BodyFacts;
use regex::Regex;
use serde::Deserialize;
use std::sync::OnceLock;

pub const DEFAULT_COMPATIBILITY_ID: &str = "ferrum-edge-0.9.5";
const RAW: &str = include_str!("../../../catalog/ferrum/ferrum-edge-0.9.5/outcomes.json");

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
    pub source_sha: String,
    pub tokens: Vec<String>,
    pub outcomes: Vec<Outcome>,
    /// Whether a backend can make `X-Gateway-Error` appear on a response:
    /// `Some(false)` only when the audit established the gateway strips/overrides it.
    pub marker_spoofable: Option<bool>,
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

pub fn catalog() -> &'static FerrumCatalog {
    static C: OnceLock<FerrumCatalog> = OnceLock::new();
    C.get_or_init(|| load(RAW).expect("embedded Ferrum catalog is valid"))
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
    Ok(FerrumCatalog { compatibility_id: rc.compatibility_id, source_sha, tokens, outcomes, marker_spoofable })
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

    #[test]
    fn embedded_catalog_loads_and_has_all_public_tokens() {
        let c = catalog();
        for t in [
            "connection_failure",
            "backend_timeout",
            "backend_error",
            "circuit_breaker_open",
            "overload",
            "config_stale",
            "concurrency_limit",
        ] {
            assert!(c.is_known_token(t), "missing token {t}");
        }
        assert!(c.outcomes.len() > 50);
    }

    #[test]
    fn backend_unavailable_signal_is_shared_by_many_upstream_causes() {
        let c = catalog();
        let body = br#"{"error":"Backend unavailable"}"#;
        let bf = body_facts(Some("application/json"), body);
        let m = c.match_signal(&Signal {
            status: 502,
            token: Some("connection_failure"),
            body_text: std::str::from_utf8(body).unwrap(),
            body: &bf,
            grpc_status: None,
        });
        assert!(m.len() > 3, "DNS/TCP/TLS/pool causes share one public signal: {:?}", m.iter().map(|x| &x.0.id).collect::<Vec<_>>());
    }

    #[test]
    fn placeholder_bodies_match_as_patterns() {
        let c = catalog();
        let body = br#"{"error":"Query parameter count (120) exceeds maximum of 100"}"#;
        let bf = body_facts(Some("application/json"), body);
        let m = c.match_signal(&Signal {
            status: 400,
            token: None,
            body_text: std::str::from_utf8(body).unwrap(),
            body: &bf,
            grpc_status: None,
        });
        assert!(m.iter().any(|(o, _)| o.id == "size.query_param_count_exceeded"), "{:?}", m.iter().map(|x| &x.0.id).collect::<Vec<_>>());
    }
}
