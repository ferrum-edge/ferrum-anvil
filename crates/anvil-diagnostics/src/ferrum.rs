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
pub const DEFAULT_COMPATIBILITY_ID: &str = "ferrum-edge-0.9.10";

/// Every embedded catalog, oldest release first: (compatibility id, outcomes.json).
const EMBEDDED: &[(&str, &str)] = &[
    ("ferrum-edge-0.9.5", include_str!("../../../catalog/ferrum/ferrum-edge-0.9.5/outcomes.json")),
    ("ferrum-edge-0.9.7", include_str!("../../../catalog/ferrum/ferrum-edge-0.9.7/outcomes.json")),
    ("ferrum-edge-0.9.8", include_str!("../../../catalog/ferrum/ferrum-edge-0.9.8/outcomes.json")),
    ("ferrum-edge-0.9.9", include_str!("../../../catalog/ferrum/ferrum-edge-0.9.9/outcomes.json")),
    ("ferrum-edge-0.9.10", include_str!("../../../catalog/ferrum/ferrum-edge-0.9.10/outcomes.json")),
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
    /// The JSON-RPC error the outcome's body is, when it is one (MCP and A2A
    /// gateway outcomes). Such a body carries the request's id, which no
    /// fixed body pattern matches.
    pub jsonrpc: Option<JsonRpcShape>,
}

/// A JSON-RPC error as an outcome's catalog body shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonRpcShape {
    pub code: i64,
    pub message: String,
    /// `error.data.gateway`, when the body carries that marker.
    pub gateway: Option<String>,
    /// Other codes the outcome's catalog notes list for the same condition.
    pub alternate_codes: Vec<i64>,
    /// Other messages the outcome's catalog notes list with the same code
    /// (matched as exactly as the body's own message).
    pub alternate_messages: Vec<String>,
}

/// Further JSON-RPC error codes an outcome answers with, from its catalog
/// notes ("Distinguishability: Codes: ..."); its body shape shows one.
const JSONRPC_ALTERNATE_CODES: &[(&str, &[i64])] = &[
    ("plugin.mcp_gateway.unknown_item", &[-32008, -32007, -32002, -32601]),
    ("plugin.mcp_gateway.batch_rejections", &[-32009, -32010, -32011]),
];

/// Further messages an outcome answers with under the same code, from its
/// catalog notes ("Messages: ..."); its body shape shows one.
const JSONRPC_ALTERNATE_MESSAGES: &[(&str, &[&str])] = &[("plugin.mcp_gateway.invalid_params", INVALID_PARAMS_MESSAGES)];
const INVALID_PARAMS_MESSAGES: &[&str] = &["Invalid MCP tool call params", "Invalid MCP prompt params", "Invalid MCP resource params"];

/// The JSON-RPC error of a catalog body shape such as
/// `{"jsonrpc":"2.0","id":{id},"error":{"code":-32001,"message":"..."}}`.
fn parse_jsonrpc(id: &str, body_shape: &serde_json::Value) -> Option<JsonRpcShape> {
    static ERROR: OnceLock<Regex> = OnceLock::new();
    static GATEWAY: OnceLock<Regex> = OnceLock::new();
    let shape = body_shape.as_str()?;
    if !shape.contains(r#""jsonrpc":"2.0""#) {
        return None;
    }
    let error = ERROR.get_or_init(|| Regex::new(r#""error":\{"code":(-?\d+),"message":"([^"\\]*)""#).expect("valid regex"));
    let gateway = GATEWAY.get_or_init(|| Regex::new(r#""gateway":"([a-z0-9_]+)""#).expect("valid regex"));
    let c = error.captures(shape)?;
    let alternate_codes = JSONRPC_ALTERNATE_CODES.iter().find(|(o, _)| *o == id).map(|(_, c)| c.to_vec()).unwrap_or_default();
    let alternates = JSONRPC_ALTERNATE_MESSAGES.iter().find(|(o, _)| *o == id);
    let alternate_messages = alternates.map(|(_, m)| m.iter().map(|x| x.to_string()).collect()).unwrap_or_default();
    Some(JsonRpcShape {
        code: c[1].parse().ok()?,
        message: c[2].to_string(),
        gateway: gateway.captures(shape).map(|g| g[1].to_string()),
        alternate_codes,
        alternate_messages,
    })
}

#[derive(Debug)]
pub struct FerrumCatalog {
    pub compatibility_id: String,
    /// Gateway release tag the catalog was audited at (e.g. `v0.9.10`).
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
                jsonrpc: parse_jsonrpc(&o.id, sig.get("body_shape").unwrap_or(&serde_json::Value::Null)),
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

/// A JSON-RPC error response (MCP, A2A) as the client observed it.
pub struct JsonRpcSignal<'a> {
    pub status: u16,
    pub token: Option<&'a str>,
    pub code: i64,
    pub message: &'a str,
    /// `error.data.gateway`.
    pub gateway: Option<&'a str>,
}

/// The JSON-RPC outcomes consistent with a [`JsonRpcSignal`].
#[derive(Debug, Default)]
pub struct JsonRpcMatch<'c> {
    /// Status, code, message and gateway marker all matched.
    pub exact: Vec<&'c Outcome>,
    /// Status and code matched (the body shape's code or one its notes
    /// list), not the message: a server behind the gateway can answer with
    /// the same standard code.
    pub code_only: Vec<&'c Outcome>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchStrength {
    /// Status, token and exact body text all matched.
    Exact,
    /// Status and token matched; the body is the backend's own pass-through.
    PassThrough,
}

impl FerrumCatalog {
    /// Human-readable release name, e.g. `Ferrum Edge 0.9.10`.
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

impl FerrumCatalog {
    /// The outcomes whose body is a JSON-RPC error consistent with `s`.
    /// These bodies echo the request's id, so they are matched on status,
    /// error code, message and the `data.gateway` marker instead of the body
    /// text. A marker the catalog body shows must be present; one it does not
    /// show is allowed (an outcome may add it).
    pub fn match_jsonrpc_error(&self, s: &JsonRpcSignal<'_>) -> JsonRpcMatch<'_> {
        let mut m = JsonRpcMatch::default();
        for o in &self.outcomes {
            let Some(j) = &o.jsonrpc else { continue };
            if !o.statuses.contains(&s.status) {
                continue;
            }
            // These outcomes carry no X-Gateway-Error token.
            if s.token.is_some() && o.tokens.as_ref().is_some_and(|t| t.is_empty()) {
                continue;
            }
            let marker = j.gateway.as_deref().is_none_or(|g| s.gateway == Some(g));
            let message = j.message == s.message || j.alternate_messages.iter().any(|m| m == s.message);
            if j.code == s.code && message && marker {
                m.exact.push(o);
            } else if j.code == s.code || j.alternate_codes.contains(&s.code) {
                m.code_only.push(o);
            }
        }
        m
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

    const TOKENS: [&str; 8] = [
        "connection_failure",
        "backend_timeout",
        "backend_error",
        "circuit_breaker_open",
        "overload",
        "config_stale",
        "concurrency_limit",
        "request_timeout",
    ];

    #[test]
    fn every_embedded_catalog_loads_under_its_own_id_with_all_public_tokens() {
        let ids: Vec<&str> = compatibility_ids().collect();
        assert_eq!(ids, ["ferrum-edge-0.9.5", "ferrum-edge-0.9.7", "ferrum-edge-0.9.8", "ferrum-edge-0.9.9", "ferrum-edge-0.9.10"]);
        for id in ids {
            let c = catalog_for(id).expect("embedded");
            assert_eq!(c.compatibility_id, id);
            assert_eq!(format!("ferrum-edge-{}", c.release_tag.trim_start_matches('v')), id, "release tag matches the id");
            assert_eq!(c.source_sha.len(), 40, "{id}: full source sha");
            let knows_request_timeout = matches!(id, "ferrum-edge-0.9.8" | "ferrum-edge-0.9.9" | "ferrum-edge-0.9.10");
            let expected_tokens: Vec<&str> =
                TOKENS.iter().copied().filter(|token| knows_request_timeout || *token != "request_timeout").collect();
            for t in expected_tokens {
                assert!(c.is_known_token(t), "{id}: missing token {t}");
            }
            assert!(c.outcomes.len() > 50);
            let mut seen = std::collections::HashSet::new();
            assert!(c.outcomes.iter().all(|o| seen.insert(o.id.as_str())), "{id}: duplicate outcome ids");
        }
        assert_eq!(default_catalog().compatibility_id, DEFAULT_COMPATIBILITY_ID);
        assert_eq!(default_catalog().release_label(), "Ferrum Edge 0.9.10");
    }

    /// `request_timeout` joined the closed vocabulary in 0.9.8 (0.9.9 and
    /// 0.9.10 keep it); the older catalogs do not know it, so it is not part
    /// of the shared vocabulary.
    #[test]
    fn request_timeout_is_a_token_of_the_0_9_8_and_later_catalogs_only() {
        for id in ["ferrum-edge-0.9.8", "ferrum-edge-0.9.9", "ferrum-edge-0.9.10"] {
            assert!(catalog_for(id).expect("embedded").is_known_token("request_timeout"), "{id}");
        }
        for id in ["ferrum-edge-0.9.5", "ferrum-edge-0.9.7"] {
            assert!(!catalog_for(id).expect("embedded").is_known_token("request_timeout"), "{id}");
        }
        assert!(!shared_tokens().iter().any(|t| t == "request_timeout"));
    }

    /// Outcomes new in 0.9.9 (the `;` path-parameter refusal, the MCP
    /// tool-call rate limit) match from their public signal in the 0.9.9
    /// catalog only; 0.9.8 never answered them.
    #[test]
    fn outcomes_new_in_0_9_9_match_only_their_own_catalog() {
        let body = br#"{"error":"Request path contains a path parameter"}"#;
        let bf = body_facts(Some("application/json"), body);
        let signal = Signal { status: 400, token: None, body_text: std::str::from_utf8(body).unwrap(), body: &bf, grpc_status: None };
        let ids = |c: &FerrumCatalog| c.match_signal(&signal).into_iter().map(|(o, _)| o.id.clone()).collect::<Vec<_>>();
        assert_eq!(ids(catalog_for("ferrum-edge-0.9.9").unwrap()), ["gateway.routing.path_parameter_refused"]);
        assert!(ids(catalog_for("ferrum-edge-0.9.8").unwrap()).is_empty());
        let rate = JsonRpcSignal { status: 200, token: None, code: -32015, message: "MCP tool-call rate limit exceeded", gateway: None };
        let m = catalog_for("ferrum-edge-0.9.9").unwrap().match_jsonrpc_error(&rate);
        assert_eq!(m.exact.iter().map(|o| o.id.as_str()).collect::<Vec<_>>(), ["plugin.rate_limiting.mcp_tool_calls_exceeded"]);
        assert!(catalog_for("ferrum-edge-0.9.8").unwrap().match_jsonrpc_error(&rate).exact.is_empty());
    }

    /// The `ai_prompt_shield` MCP refusals new in 0.9.10 (a non-UTF-8 request
    /// charset, an unparseable body that may carry a tool call) match from
    /// their public body in the 0.9.10 catalog only. The content-encoding
    /// message existed at 0.9.9 and matches both that catalog and 0.9.10's.
    #[test]
    fn outcomes_new_in_0_9_10_match_only_their_own_catalog() {
        for reason in ["unsupported_charset", "jsonrpc_request_unparseable"] {
            let text = format!(r#"{{"error":"MCP request body could not be inspected","message":"{reason}"}}"#);
            let bf = body_facts(Some("application/json"), text.as_bytes());
            let signal = Signal { status: 400, token: None, body_text: &text, body: &bf, grpc_status: None };
            let ids = |c: &FerrumCatalog| c.match_signal(&signal).into_iter().map(|(o, _)| o.id.clone()).collect::<Vec<_>>();
            let newest = catalog_for("ferrum-edge-0.9.10").unwrap();
            assert_eq!(ids(newest), ["plugin.ai_prompt_shield.mcp_body_uninspectable"], "{reason}");
            assert!(ids(catalog_for("ferrum-edge-0.9.9").unwrap()).is_empty(), "{reason}");
        }

        let text = r#"{"error":"MCP request body could not be inspected","message":"unsupported_content_encoding"}"#;
        let bf = body_facts(Some("application/json"), text.as_bytes());
        let signal = Signal { status: 400, token: None, body_text: text, body: &bf, grpc_status: None };
        let ids = |c: &FerrumCatalog| c.match_signal(&signal).into_iter().map(|(o, _)| o.id.clone()).collect::<Vec<_>>();
        assert_eq!(ids(catalog_for("ferrum-edge-0.9.10").unwrap()), ["plugin.ai_prompt_shield.mcp_body_uninspectable"]);
        assert_eq!(ids(catalog_for("ferrum-edge-0.9.9").unwrap()), ["plugin.ai_prompt_shield.mcp_body_uninspectable"]);
        assert!(ids(catalog_for("ferrum-edge-0.9.8").unwrap()).is_empty());
    }

    #[test]
    fn unknown_compatibility_ids_get_no_catalog_and_only_the_shared_vocabulary() {
        for id in ["ferrum-edge-0.9.6", "ferrum-edge-1.0.0", "", "FERRUM-EDGE-0.9.7"] {
            assert!(catalog_for(id).is_none(), "{id:?} must not borrow another release's catalog");
        }
        assert!(catalog_for(" ferrum-edge-0.9.5 ").is_some(), "surrounding whitespace is not a different release");
        let shared: Vec<&str> = shared_tokens().iter().map(String::as_str).collect();
        let shared_tokens: Vec<&str> = TOKENS.iter().copied().filter(|token| *token != "request_timeout").collect();
        assert_eq!(shared, shared_tokens, "only tokens shared with 0.9.5 and 0.9.7 are release-independent");
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
    fn mcp_gateway_json_rpc_errors_are_read_from_the_catalog_bodies() {
        let c = default_catalog();
        let tool_denied = c.outcome("plugin.mcp_gateway.tool_denied").and_then(|o| o.jsonrpc.clone()).expect("a JSON-RPC body");
        assert_eq!((tool_denied.code, tool_denied.message.as_str()), (-32001, "MCP tool call denied by gateway policy"));
        assert_eq!(tool_denied.gateway, None);
        let upstream = c.outcome("plugin.mcp_gateway.upstream_session_unavailable").and_then(|o| o.jsonrpc.clone()).unwrap();
        assert_eq!(upstream.gateway.as_deref(), Some("mcp_gateway"));
        let a2a = c.outcome("plugin.a2a_gateway.jsonrpc_method_denied").and_then(|o| o.jsonrpc.clone()).unwrap();
        assert_eq!((a2a.code, a2a.gateway.as_deref()), (-32001, Some("a2a_gateway")));
        let unknown = c.outcome("plugin.mcp_gateway.unknown_item").and_then(|o| o.jsonrpc.clone()).unwrap();
        assert!(unknown.alternate_codes.contains(&-32601), "{unknown:?}");
        assert!(c.outcome("plugin.mcp_gateway.session_not_found").is_some_and(|o| o.jsonrpc.is_none()), "an empty body");
        for id in JSONRPC_ALTERNATE_CODES.iter().map(|(id, _)| id).chain(JSONRPC_ALTERNATE_MESSAGES.iter().map(|(id, _)| id)) {
            for cat in catalogs() {
                assert!(cat.outcome(id).is_some_and(|o| o.jsonrpc.is_some()), "{}: {id}", cat.compatibility_id);
            }
        }
    }

    #[test]
    fn a_json_rpc_error_matches_by_code_message_and_marker() {
        let c = default_catalog();
        fn sig(status: u16, code: i64, message: &'static str, gateway: Option<&'static str>) -> JsonRpcSignal<'static> {
            JsonRpcSignal { status, token: None, code, message, gateway }
        }
        let ids = |v: &[&Outcome]| v.iter().map(|o| o.id.clone()).collect::<Vec<_>>();
        let m = c.match_jsonrpc_error(&sig(200, -32001, "MCP tool call denied by gateway policy", None));
        assert_eq!(ids(&m.exact), ["plugin.mcp_gateway.tool_denied"]);
        assert_eq!(ids(&m.code_only), ["plugin.a2a_gateway.jsonrpc_method_denied"], "the same code with another message");
        // A2A's body carries its marker: without it, only the code matches.
        let m = c.match_jsonrpc_error(&sig(200, -32001, "A2A method denied by gateway policy", None));
        assert!(m.exact.is_empty(), "{:?}", ids(&m.exact));
        let m = c.match_jsonrpc_error(&sig(200, -32001, "A2A method denied by gateway policy", Some("a2a_gateway")));
        assert_eq!(ids(&m.exact), ["plugin.a2a_gateway.jsonrpc_method_denied"]);
        // Another status is another outcome.
        assert!(c.match_jsonrpc_error(&sig(403, -32001, "MCP tool call denied by gateway policy", None)).exact.is_empty());
        let m = c.match_jsonrpc_error(&sig(200, -32601, "MCP method not found", None));
        assert!(m.exact.is_empty());
        assert_eq!(ids(&m.code_only), ["plugin.mcp_gateway.unknown_item"], "a code the outcome's notes list");
        let m = c.match_jsonrpc_error(&sig(200, -32602, "Invalid MCP tool arguments", None));
        assert_eq!(ids(&m.exact), ["plugin.mcp_gateway.invalid_params"]);
        for audited in ["Invalid MCP tool call params", "Invalid MCP prompt params", "Invalid MCP resource params"] {
            let m = c.match_jsonrpc_error(&sig(200, -32602, audited, None));
            assert_eq!(ids(&m.exact), ["plugin.mcp_gateway.invalid_params"], "{audited}");
        }
        assert!(c.match_jsonrpc_error(&sig(200, -31999, "other", None)).code_only.is_empty());
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
