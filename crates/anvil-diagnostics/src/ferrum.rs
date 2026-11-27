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

/// The source-audited release new profiles default to. The audit and its
/// qualification status (the hosted all-profile Lab run, also recorded in the
/// catalog's `qualification`) are in `docs/audit/gateway-0.9.21-delta.md`.
pub const DEFAULT_COMPATIBILITY_ID: &str = "ferrum-edge-0.9.21";

const EDGE_0_9_21: &str = include_str!("../../../catalog/ferrum/ferrum-edge-0.9.21/outcomes.json");

/// Every embedded catalog, oldest release first: (compatibility id, outcomes.json).
const EMBEDDED: &[(&str, &str)] = &[
    ("ferrum-edge-0.9.5", include_str!("../../../catalog/ferrum/ferrum-edge-0.9.5/outcomes.json")),
    ("ferrum-edge-0.9.7", include_str!("../../../catalog/ferrum/ferrum-edge-0.9.7/outcomes.json")),
    ("ferrum-edge-0.9.8", include_str!("../../../catalog/ferrum/ferrum-edge-0.9.8/outcomes.json")),
    ("ferrum-edge-0.9.9", include_str!("../../../catalog/ferrum/ferrum-edge-0.9.9/outcomes.json")),
    ("ferrum-edge-0.9.10", include_str!("../../../catalog/ferrum/ferrum-edge-0.9.10/outcomes.json")),
    ("ferrum-edge-0.9.11", include_str!("../../../catalog/ferrum/ferrum-edge-0.9.11/outcomes.json")),
    ("ferrum-edge-0.9.14", include_str!("../../../catalog/ferrum/ferrum-edge-0.9.14/outcomes.json")),
    ("ferrum-edge-0.9.15", include_str!("../../../catalog/ferrum/ferrum-edge-0.9.15/outcomes.json")),
    ("ferrum-edge-0.9.20", include_str!("../../../catalog/ferrum/ferrum-edge-0.9.20/outcomes.json")),
    ("ferrum-edge-0.9.21", EDGE_0_9_21),
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
    /// The release relays a backend's own 3xx-5xx answer to a WebSocket
    /// upgrade instead of replacing it (Ferrum Edge v0.9.21, #7414).
    #[serde(default)]
    websocket_backend_refusals_relayed: bool,
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
    /// HTTP 200 and `grpc_status` with no message: a trailers-only response,
    /// trailers after no message, or a gRPC-Web trailer frame alone. Such an
    /// outcome has no body to compare ([`grpc_status_only`]).
    pub grpc_status_only: bool,
    /// The `grpc-message` values (percent-decoded) the outcome's gRPC
    /// rendering carries (`public_signal.grpc_message`, alternatives split on
    /// ` | `). A gRPC response with the outcome's grpc-status and one of these
    /// messages matches it exactly; the message is gateway-authored text, as
    /// weak as a body.
    pub grpc_messages: Vec<String>,
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
    /// The release relays a backend's own 3xx-5xx answer to a WebSocket
    /// upgrade unchanged and without `X-Gateway-Error` (Ferrum Edge v0.9.21,
    /// #7414), so a tokenless handshake refusal may be the backend's.
    pub relays_websocket_refusals: bool,
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

/// Whether a catalog outcome's public signal is a gRPC status with no message
/// (HTTP 200, a `grpc_status`, and a `body_shape` that is empty, says
/// "empty (trailers-only)" or is a gRPC-Web trailer frame) on a gRPC wire
/// shape (`grpc-status`, `x-grpc-web` or an `application/grpc` content type
/// among its headers, or trailers in its transport). Such a signal has no
/// body: a JSON form its notes give is the plugin's HTTP rendering, which
/// the gRPC client never sees.
fn grpc_status_only(sig: &serde_json::Value, statuses: &[u16], grpc_status: Option<i32>) -> bool {
    if grpc_status.is_none() || statuses != [200] {
        return false;
    }
    let body = match sig.get("body_shape") {
        None | Some(serde_json::Value::Null) => "",
        Some(serde_json::Value::String(s)) => s.trim(),
        Some(_) => return false,
    };
    let lower = body.to_ascii_lowercase();
    let no_message =
        body.is_empty() || lower.starts_with("empty") || lower.starts_with("(empty") || lower.starts_with("grpc-web trailer frame");
    let grpc_header = |(name, value): (&String, &serde_json::Value)| {
        name.eq_ignore_ascii_case("grpc-status")
            || name.eq_ignore_ascii_case("x-grpc-web")
            || (name.eq_ignore_ascii_case("content-type") && value.as_str().is_some_and(|v| v.trim().starts_with("application/grpc")))
    };
    let grpc_wire = sig.get("other_headers").and_then(|h| h.as_object()).is_some_and(|h| h.iter().any(grpc_header))
        || sig.get("transport").and_then(|t| t.as_str()).is_some_and(|t| t.to_ascii_lowercase().contains("trailers"));
    no_message && grpc_wire
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
            let statuses = parse_statuses(sig.get("http_status").unwrap_or(&serde_json::Value::Null));
            let grpc_status = sig.get("grpc_status").and_then(|g| g.as_i64()).map(|g| g as i32);
            let grpc_status_only = grpc_status_only(sig, &statuses, grpc_status);
            Outcome {
                id: o.id.clone(),
                family: o.family.clone(),
                statuses,
                tokens: parse_tokens(sig.get("x_gateway_error").unwrap_or(&serde_json::Value::Null), &tokens),
                body_patterns: if grpc_status_only { vec![] } else { body_patterns },
                body_passthrough,
                grpc_status,
                grpc_status_only,
                grpc_messages: strings(sig.get("grpc_message").unwrap_or(&serde_json::Value::Null))
                    .iter()
                    .flat_map(|m| m.split(" | ").map(|x| x.trim().to_string()).collect::<Vec<_>>())
                    .filter(|m| !m.is_empty())
                    .collect(),
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
        relays_websocket_refusals: rc.websocket_backend_refusals_relayed,
    })
}

/// Observable signals of an HTTP-family response.
pub struct Signal<'a> {
    pub status: u16,
    pub token: Option<&'a str>,
    pub body_text: &'a str,
    pub body: &'a BodyFacts,
    pub grpc_status: Option<i32>,
    /// The gRPC call ended with its status and no message before it
    /// (`Ctx::grpc_status_without_message`).
    pub grpc_no_message: bool,
    /// The call's percent-decoded `grpc-message`, if any.
    pub grpc_message: Option<&'a str>,
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
    /// HTTP status, token and grpc-status matched a gRPC outcome that sends
    /// no message, and none arrived: there is no body to compare, and a
    /// service behind the gateway can answer in the same shape.
    GrpcStatusOnly,
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
            } else if !o.grpc_messages.is_empty()
                && s.grpc_status.is_some()
                && s.grpc_status == o.grpc_status
                && s.grpc_message.is_some_and(|m| o.grpc_messages.iter().any(|x| x == m.trim()))
            {
                out.push((o, MatchStrength::Exact));
            } else if o.grpc_status_only && s.grpc_no_message && s.grpc_status.is_some() && s.grpc_status == o.grpc_status {
                out.push((o, MatchStrength::GrpcStatusOnly));
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
        assert_eq!(
            ids,
            [
                "ferrum-edge-0.9.5",
                "ferrum-edge-0.9.7",
                "ferrum-edge-0.9.8",
                "ferrum-edge-0.9.9",
                "ferrum-edge-0.9.10",
                "ferrum-edge-0.9.11",
                "ferrum-edge-0.9.14",
                "ferrum-edge-0.9.15",
                "ferrum-edge-0.9.20",
                "ferrum-edge-0.9.21",
            ]
        );
        for id in ids {
            let c = catalog_for(id).expect("embedded");
            assert_eq!(c.compatibility_id, id);
            assert_eq!(format!("ferrum-edge-{}", c.release_tag.trim_start_matches('v')), id, "release tag matches the id");
            assert_eq!(c.source_sha.len(), 40, "{id}: full source sha");
            let knows_request_timeout = !matches!(id, "ferrum-edge-0.9.5" | "ferrum-edge-0.9.7");
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
        assert_eq!(default_catalog().release_label(), "Ferrum Edge 0.9.21");
    }

    /// `request_timeout` joined the closed vocabulary in 0.9.8 (0.9.9,
    /// 0.9.10, 0.9.11, 0.9.14, 0.9.15, 0.9.20 and 0.9.21 keep it); the older catalogs do not
    /// know it, so it is not part of the shared vocabulary.
    #[test]
    fn request_timeout_is_a_token_of_the_0_9_8_and_later_catalogs_only() {
        for id in compatibility_ids().skip(2) {
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
        let signal = Signal {
            status: 400,
            token: None,
            body_text: std::str::from_utf8(body).unwrap(),
            body: &bf,
            grpc_status: None,
            grpc_no_message: false,
            grpc_message: None,
        };
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
    /// their public body from 0.9.10 onward, including 0.9.11, 0.9.14, 0.9.15,
    /// 0.9.20 and 0.9.21. The content-encoding message existed at 0.9.9 and
    /// matches all seven.
    #[test]
    fn outcomes_new_in_0_9_10_match_only_their_own_catalog() {
        for reason in ["unsupported_charset", "jsonrpc_request_unparseable"] {
            let text = format!(r#"{{"error":"MCP request body could not be inspected","message":"{reason}"}}"#);
            let bf = body_facts(Some("application/json"), text.as_bytes());
            let signal = Signal {
                status: 400,
                token: None,
                body_text: &text,
                body: &bf,
                grpc_status: None,
                grpc_no_message: false,
                grpc_message: None,
            };
            let ids = |c: &FerrumCatalog| c.match_signal(&signal).into_iter().map(|(o, _)| o.id.clone()).collect::<Vec<_>>();
            for id in [
                "ferrum-edge-0.9.10",
                "ferrum-edge-0.9.11",
                "ferrum-edge-0.9.14",
                "ferrum-edge-0.9.15",
                "ferrum-edge-0.9.20",
                "ferrum-edge-0.9.21",
            ] {
                let catalog = catalog_for(id).unwrap();
                let expected = ["plugin.ai_prompt_shield.mcp_body_uninspectable"];
                assert_eq!(ids(catalog), expected, "{id}: {reason}");
            }
            assert!(ids(catalog_for("ferrum-edge-0.9.9").unwrap()).is_empty(), "{reason}");
        }

        let text = r#"{"error":"MCP request body could not be inspected","message":"unsupported_content_encoding"}"#;
        let bf = body_facts(Some("application/json"), text.as_bytes());
        let signal =
            Signal { status: 400, token: None, body_text: text, body: &bf, grpc_status: None, grpc_no_message: false, grpc_message: None };
        let ids = |c: &FerrumCatalog| c.match_signal(&signal).into_iter().map(|(o, _)| o.id.clone()).collect::<Vec<_>>();
        for id in [
            "ferrum-edge-0.9.10",
            "ferrum-edge-0.9.11",
            "ferrum-edge-0.9.14",
            "ferrum-edge-0.9.15",
            "ferrum-edge-0.9.20",
            "ferrum-edge-0.9.21",
        ] {
            let expected = ["plugin.ai_prompt_shield.mcp_body_uninspectable"];
            assert_eq!(ids(catalog_for(id).unwrap()), expected);
        }
        assert_eq!(ids(catalog_for("ferrum-edge-0.9.9").unwrap()), ["plugin.ai_prompt_shield.mcp_body_uninspectable"]);
        assert!(ids(catalog_for("ferrum-edge-0.9.8").unwrap()).is_empty());
    }

    /// 0.9.14 answers a buffered-collector read error with the eager
    /// collector's body, so that body is ambiguous between the two collectors
    /// from 0.9.14 (0.9.15, 0.9.20 and 0.9.21 keep it) and the old body matches only the earlier
    /// catalogs.
    #[test]
    fn buffered_read_error_body_changed_in_0_9_14() {
        let ids = |id: &str, text: &str| {
            let bf = body_facts(None, text.as_bytes());
            let signal = Signal {
                status: 502,
                token: Some("backend_error"),
                body_text: text,
                body: &bf,
                grpc_status: None,
                grpc_no_message: false,
                grpc_message: None,
            };
            let mut ids: Vec<String> = catalog_for(id).unwrap().match_signal(&signal).into_iter().map(|(o, _)| o.id.clone()).collect();
            ids.sort();
            ids
        };
        let current = r#"{"error":"Backend response body read failed"}"#;
        let old = r#"{"error":"Backend response read error"}"#;
        let both = ["upstream.body_read_failed.buffered_collector", "upstream.body_read_failed.eager_buffer"];
        for id in ["ferrum-edge-0.9.14", "ferrum-edge-0.9.15", "ferrum-edge-0.9.20", "ferrum-edge-0.9.21"] {
            assert_eq!(ids(id, current), both, "{id}");
            assert!(ids(id, old).is_empty(), "{id}");
        }
        assert_eq!(ids("ferrum-edge-0.9.11", current), ["upstream.body_read_failed.eager_buffer"]);
        assert_eq!(ids("ferrum-edge-0.9.11", old), ["upstream.body_read_failed.buffered_collector"]);
    }

    /// The refusals new in 0.9.15 (route protocol admission, the HTTP/1.1
    /// WebSocket non-GET upgrade, request_deduplication's charged Brotli
    /// decode) match from their public body in the 0.9.15 catalog only.
    #[test]
    fn outcomes_new_in_0_9_15_match_only_their_own_catalog() {
        let cases = [
            (403, r#"{"error":"Request protocol not permitted on this route"}"#, "gateway.routing.protocol_not_permitted"),
            (405, r#"{"error":"WebSocket upgrades require GET"}"#, "gateway.routing.websocket_upgrade_requires_get"),
            (
                400,
                r#"{"error":"Request body encoding is invalid or exceeds fingerprint limits"}"#,
                "plugin.request_deduplication.body_encoding_rejected",
            ),
            (503, r#"{"error":"Request decode capacity is temporarily unavailable"}"#, "plugin.request_deduplication.decode_capacity"),
        ];
        for (status, text, expected) in cases {
            let bf = body_facts(Some("application/json"), text.as_bytes());
            let signal =
                Signal { status, token: None, body_text: text, body: &bf, grpc_status: None, grpc_no_message: false, grpc_message: None };
            let ids = |id: &str| catalog_for(id).unwrap().match_signal(&signal).into_iter().map(|(o, _)| o.id.clone()).collect::<Vec<_>>();
            assert_eq!(ids("ferrum-edge-0.9.15"), [expected], "{text}");
            assert!(ids("ferrum-edge-0.9.14").is_empty(), "{text}");
        }
    }

    /// v0.9.15 continues a browser login on the sealed pending-flow cookie when
    /// the instance-local pending-login cache is full, so the 503 that 0.9.14
    /// answered matches no 0.9.15 outcome (it is in `removed_outcomes`).
    /// v0.9.19 (#6833) caps those cookie-only logins and answers the 503 again
    /// once they run out, so 0.9.20 catalogues it as a new outcome.
    #[test]
    fn oidc_state_cache_full_is_absent_from_0_9_15_only() {
        let text = r#"{"error":"OIDC state cache full"}"#;
        let bf = body_facts(Some("application/json"), text.as_bytes());
        let signal =
            Signal { status: 503, token: None, body_text: text, body: &bf, grpc_status: None, grpc_no_message: false, grpc_message: None };
        let ids = |id: &str| catalog_for(id).unwrap().match_signal(&signal).into_iter().map(|(o, _)| o.id.clone()).collect::<Vec<_>>();
        assert_eq!(ids("ferrum-edge-0.9.14"), ["plugin.oidc_relying_party.challenge_browser_state_cache_full"]);
        assert!(ids("ferrum-edge-0.9.15").is_empty());
        assert_eq!(ids("ferrum-edge-0.9.20"), ["plugin.oidc_relying_party.challenge_browser_state_cache_full"]);
        assert_eq!(ids("ferrum-edge-0.9.21"), ["plugin.oidc_relying_party.challenge_browser_state_cache_full"]);
    }

    /// Refusals new between 0.9.15 and 0.9.20 (the proxy hop limit and its
    /// malformed header, key_auth's ambiguous key locations, the pooled
    /// connection ceiling's own 503 and the connect timeout's own 504) match
    /// from their public signal in the 0.9.20 catalog only.
    #[test]
    fn outcomes_new_in_0_9_20_match_only_their_own_catalog() {
        let cases = [
            (508, Some("loop_detected"), r#"{"error":"Proxy hop limit exceeded"}"#, "gateway.admission.proxy_hop_limit"),
            (400, None, r#"{"error":"Invalid X-Ferrum-Hops header"}"#, "frontend_parse.proxy_hops_invalid"),
            (401, None, r#"{"error":"Ambiguous API key locations"}"#, "plugin.key_auth.ambiguous_key_locations"),
            (503, Some("connection_failure"), r#"{"error":"Backend connection limit exceeded"}"#, "upstream.connection_limit.pooled"),
            (504, Some("connection_failure"), r#"{"error":"Backend timeout"}"#, "upstream.connect.timeout"),
        ];
        for (status, token, text, expected) in cases {
            let bf = body_facts(Some("application/json"), text.as_bytes());
            let signal =
                Signal { status, token, body_text: text, body: &bf, grpc_status: None, grpc_no_message: false, grpc_message: None };
            let ids = |id: &str| catalog_for(id).unwrap().match_signal(&signal).into_iter().map(|(o, _)| o.id.clone()).collect::<Vec<_>>();
            assert_eq!(ids("ferrum-edge-0.9.20"), [expected], "{text}");
            assert!(ids("ferrum-edge-0.9.15").is_empty(), "{text}");
        }
        assert!(catalog_for("ferrum-edge-0.9.20").unwrap().is_known_token("loop_detected"));
        assert!(!shared_tokens().iter().any(|t| t == "loop_detected"));

        // A WebSocket upgrade the backend refused after the request went out
        // carries backend_error, a pre-wire dial failure connection_failure;
        // both match the one WebSocket outcome (#6777).
        let text = r#"{"error":"Backend WebSocket connection failed"}"#;
        let bf = body_facts(Some("application/json"), text.as_bytes());
        for token in ["connection_failure", "backend_error"] {
            let signal = Signal {
                status: 502,
                token: Some(token),
                body_text: text,
                body: &bf,
                grpc_status: None,
                grpc_no_message: false,
                grpc_message: None,
            };
            let ids: Vec<String> =
                catalog_for("ferrum-edge-0.9.20").unwrap().match_signal(&signal).into_iter().map(|(o, _)| o.id.clone()).collect();
            assert_eq!(ids, ["protocol.ws.backend_connect_failed"], "{token}");
        }

        // Every emitted status and body of outcomes with several variants
        // matches: ai_rate_limiter's unreadable model (400 or 415),
        // ai_prompt_shield's three reasons, the HBONE relay's dial failures and
        // openapi_validator's parameter problem (#6847, #6838, #6777, #6837).
        let model = r#"{"error":"AI request model unavailable","details":"model_limits requires an uncompressed, parseable request body so the requested model's token budget can be enforced"}"#;
        let mut variants = vec![
            (400, model.to_string(), "plugin.ai_rate_limiter.model_unattributable"),
            (415, model.to_string(), "plugin.ai_rate_limiter.model_unattributable"),
            (502, r#"{"error":"Backend HBONE connection failed"}"#.to_string(), "protocol.hbone.relay_backend_connect_failed"),
            (504, r#"{"error":"Backend HBONE connection timed out"}"#.to_string(), "protocol.hbone.relay_backend_connect_failed"),
            (502, r#"{"error":"DNS resolution for backend failed"}"#.to_string(), "protocol.hbone.relay_backend_connect_failed"),
            (
                400,
                r#"{"type":"about:blank","title":"Request parameter validation failed","status":400,"detail":"Required query parameter 'limit' is missing","operation":"GET /items"}"#.to_string(),
                "plugin.openapi_validator.request_parameter_violation",
            ),
        ];
        // ai_request_guard's generation controls and completion count, and
        // ai_stream_router's untranslatable parameters (#6849, #6824), with
        // substituted values.
        for (text, expected) in [
            (
                r#"{"error":"Invalid max_tokens field","details":"'max_tokens' must be a non-negative integer"}"#,
                "plugin.ai_request_guard.generation_control_invalid",
            ),
            (
                r#"{"error":"Invalid completion count field","details":"'n' must be a non-negative integer"}"#,
                "plugin.ai_request_guard.generation_control_invalid",
            ),
            (
                r#"{"error":"Conflicting field spellings","details":"'generationConfig / generation_config' are both present; send a single spelling"}"#,
                "plugin.ai_request_guard.generation_control_invalid",
            ),
            (
                r#"{"error":"Too many completions requested","details":"Request asks for 2 completions, maximum allowed is 1"}"#,
                "plugin.ai_request_guard.max_choices_exceeded",
            ),
            (
                r#"{"error":{"message":"Invalid request for Anthropic translation: logit_bias is not supported","type":"invalid_request_error","param":"logit_bias","code":"unsupported_parameter"}}"#,
                "plugin.ai_stream_router.parameter_unrepresentable",
            ),
            (
                r#"{"error":{"message":"Invalid request for Gemini translation: n must be 1","type":"invalid_request_error","param":"n","code":"invalid_parameter"}}"#,
                "plugin.ai_stream_router.parameter_unrepresentable",
            ),
        ] {
            variants.push((400, text.to_string(), expected));
        }
        for reason in ["non_utf8_body", "malformed_json", "unsupported_charset"] {
            let text = format!(r#"{{"error":"Request body could not be inspected","message":"{reason}"}}"#);
            variants.push((400, text, "plugin.ai_prompt_shield.body_uninspectable"));
        }
        for (status, text, expected) in &variants {
            let bf = body_facts(Some("application/json"), text.as_bytes());
            let signal = Signal {
                status: *status,
                token: None,
                body_text: text,
                body: &bf,
                grpc_status: None,
                grpc_no_message: false,
                grpc_message: None,
            };
            let ids: Vec<String> =
                catalog_for("ferrum-edge-0.9.20").unwrap().match_signal(&signal).into_iter().map(|(o, _)| o.id.clone()).collect();
            assert_eq!(ids, [*expected], "{status} {text}");
        }
        // The validators' capacity refusals answer the shared capacity bodies,
        // so they stay among that body's candidates. The request side is a
        // plugin reject with no token; the response side replaces a backend
        // response, so the final builder stamps `backend_error` on its 503,
        // as on the core retained-response refusal.
        let request = r#"{"error":"Request inspection capacity exceeded"}"#;
        let response = r#"{"error":"Response buffering capacity exceeded"}"#;
        for (token, text, expected) in [
            (
                None,
                request,
                &[
                    "gateway.capacity.request_decode",
                    "plugin.body_validator.decode_capacity",
                    "plugin.openapi_validator.decode_capacity",
                    "plugin.compression.decode_capacity",
                ][..],
            ),
            (
                Some("backend_error"),
                response,
                &[
                    "gateway.capacity.response_buffer",
                    "plugin.body_validator.response_decode_capacity",
                    "plugin.openapi_validator.response_decode_capacity",
                    "plugin.custom.undeclared_response_body_producer",
                ][..],
            ),
            // A governed synthetic (plugin short-circuit) response refused the
            // same way is finalized on the reject path, which writes no token:
            // the core capacity-only outcome comes first, then the OpenAPI form.
            (
                None,
                response,
                &["gateway.capacity.synthetic_response_buffer", "plugin.openapi_validator.synthetic_response_decode_capacity"][..],
            ),
            (Some("backend_error"), request, &[][..]),
        ] {
            let bf = body_facts(Some("application/json"), text.as_bytes());
            let signal =
                Signal { status: 503, token, body_text: text, body: &bf, grpc_status: None, grpc_no_message: false, grpc_message: None };
            let ids: Vec<String> =
                catalog_for("ferrum-edge-0.9.20").unwrap().match_signal(&signal).into_iter().map(|(o, _)| o.id.clone()).collect();
            assert_eq!(ids, expected, "{token:?} {text}");
        }
        // The core retained-response refusal of a synthetic response sends the
        // same token-less signal, so the two name each other; the backend form
        // (`backend_error`) is a different signal.
        let c = catalog_for("ferrum-edge-0.9.20").unwrap();
        let synthetic = "plugin.openapi_validator.synthetic_response_decode_capacity";
        let core = "gateway.capacity.synthetic_response_buffer";
        assert!(c.outcome(synthetic).unwrap().shared_signal_with.iter().any(|s| s == core));
        assert!(c.outcome(core).unwrap().shared_signal_with.iter().any(|s| s == synthetic));
        assert!(!c.outcome("gateway.capacity.response_buffer").unwrap().shared_signal_with.iter().any(|s| s == synthetic));

        // The Agent Card rewrite refusal is a JSON 502 on the HTTP bindings
        // and, on the gRPC binding, HTTP 200 with grpc-status 13 set by the
        // plugin itself (not the 502's mapped 14).
        let card = catalog_for("ferrum-edge-0.9.20").unwrap().outcome("plugin.a2a_gateway.agent_card_rewrite_failed").unwrap();
        assert_eq!((card.statuses.as_slice(), card.grpc_status), (&[502][..], Some(13)));

        // mcp_gateway's default-deny of prompts and resources (#6819): each
        // message is its own exact outcome.
        let c = catalog_for("ferrum-edge-0.9.20").unwrap();
        for (message, expected) in [
            ("MCP prompt request denied by gateway policy", "plugin.mcp_gateway.prompt_denied"),
            ("MCP resource read denied by gateway policy", "plugin.mcp_gateway.resource_read_denied"),
        ] {
            let m = c.match_jsonrpc_error(&JsonRpcSignal { status: 200, token: None, code: -32001, message, gateway: None });
            assert_eq!(m.exact.iter().map(|o| o.id.as_str()).collect::<Vec<_>>(), [expected], "{message}");
        }
    }

    /// Refusals new between 0.9.20 and 0.9.21 (the token plugins' ambiguous
    /// query alias, the transformers' duplicate-member screen, untranslated
    /// gRPC-Web on a route with gateway-asserted headers, and the repeated
    /// Content-Type guard) match from their public signal in the 0.9.21
    /// catalog only; the removed hmac_auth v1 nonce refusal matches only
    /// 0.9.20.
    #[test]
    fn outcomes_new_in_0_9_21_match_only_their_own_catalog() {
        let ids_for = |id: &str, status: u16, token: Option<&'static str>, text: &str| {
            let bf = body_facts(Some("application/json"), text.as_bytes());
            let signal =
                Signal { status, token, body_text: text, body: &bf, grpc_status: None, grpc_no_message: false, grpc_message: None };
            let mut ids: Vec<String> = catalog_for(id).unwrap().match_signal(&signal).into_iter().map(|(o, _)| o.id.clone()).collect();
            ids.sort();
            ids
        };
        let ambiguous = r#"{"error":"Ambiguous token query parameter"}"#;
        assert_eq!(
            ids_for("ferrum-edge-0.9.21", 401, None, ambiguous),
            [
                "plugin.jwks_auth.ambiguous_query_token",
                "plugin.jwt_auth.ambiguous_query_token",
                "plugin.oauth2_introspection.ambiguous_query_token"
            ]
        );
        assert!(ids_for("ferrum-edge-0.9.20", 401, None, ambiguous).is_empty());
        let cases = [
            (
                400,
                None,
                r#"{"error":"Request body contains duplicate JSON object member names or a JSON document the gateway could not evaluate"}"#,
                "plugin.request_transformer.ambiguous_json_body",
            ),
            (
                502,
                Some("backend_error"),
                r#"{"error":"Backend response body contains duplicate JSON object member names or a JSON document the gateway could not evaluate"}"#,
                "plugin.response_transformer.ambiguous_json_body",
            ),
            (
                415,
                None,
                r#"{"error":"gRPC-Web must be translated on a route with gateway-asserted headers"}"#,
                "gateway.routing.grpc_web_relabelled_on_assertion_route",
            ),
            (
                400,
                None,
                r#"{"error":"Request body could not be inspected","message":"Request blocked because the JSON request body has duplicate member names."}"#,
                "plugin.ai_prompt_shield.uninspectable",
            ),
        ];
        for (status, token, text, expected) in cases {
            assert_eq!(ids_for("ferrum-edge-0.9.21", status, token, text), [expected], "{text}");
            assert!(ids_for("ferrum-edge-0.9.20", status, token, text).is_empty(), "{text}");
        }
        // The repeated Content-Type refusals join the protocol header guard,
        // which 0.9.20 already had for its other bodies.
        for text in [
            r#"{"error":"Request contains multiple Content-Type headers"}"#,
            r#"{"error":"Content-Type header contains more than one media type"}"#,
        ] {
            assert_eq!(ids_for("ferrum-edge-0.9.21", 400, None, text), ["frontend_parse.protocol_header_violation"], "{text}");
            assert!(ids_for("ferrum-edge-0.9.20", 400, None, text).is_empty(), "{text}");
        }
        // hmac_auth's v1 signing profile is gone (#7114), and its nonce refusal with it.
        let v1 = r#"{"error":"HMAC authorization nonce is not accepted by this signing profile"}"#;
        assert_eq!(ids_for("ferrum-edge-0.9.20", 401, None, v1), ["plugin.hmac_auth.nonce_not_accepted_v1"]);
        assert!(ids_for("ferrum-edge-0.9.21", 401, None, v1).is_empty());
        // A backend refusal of a WebSocket upgrade is relayed from 0.9.21
        // (#7414), but the gateway 502 remains for answers it cannot relay,
        // with either token.
        let ws = r#"{"error":"Backend WebSocket connection failed"}"#;
        for token in ["connection_failure", "backend_error"] {
            assert_eq!(ids_for("ferrum-edge-0.9.21", 502, Some(token), ws), ["protocol.ws.backend_connect_failed"], "{token}");
        }
        // The OpenAPI bridge refusal outside the route (#7410) is its own exact JSON-RPC outcome.
        let bridge = JsonRpcSignal {
            status: 200,
            token: None,
            code: -32603,
            message: "OpenAPI bridge operation path is outside this proxy's route",
            gateway: None,
        };
        let m = catalog_for("ferrum-edge-0.9.21").unwrap().match_jsonrpc_error(&bridge);
        assert_eq!(m.exact.iter().map(|o| o.id.as_str()).collect::<Vec<_>>(), ["plugin.mcp_gateway.openapi_bridge_outside_route"]);
        assert!(catalog_for("ferrum-edge-0.9.20").unwrap().match_jsonrpc_error(&bridge).exact.is_empty());
    }

    /// v0.9.21 renders gateway refusals of gRPC-Web calls as an HTTP 200
    /// trailer frame (#7064, #7155): each matches its own outcome exactly by
    /// grpc-status and grpc-message, never by the HTTP status the transaction
    /// log keeps, and a different message with the same grpc-status is only a
    /// status candidate.
    #[test]
    fn framed_grpc_refusals_match_by_status_and_message() {
        let bf = body_facts(Some("application/grpc-web+proto"), b"");
        let ids = |id: &str, token: Option<&'static str>, grpc_status: i32, message: Option<&'static str>| {
            let signal = Signal {
                status: 200,
                token,
                body_text: "",
                body: &bf,
                grpc_status: Some(grpc_status),
                grpc_no_message: true,
                grpc_message: message,
            };
            let mut ids: Vec<(String, MatchStrength)> =
                catalog_for(id).unwrap().match_signal(&signal).into_iter().map(|(o, m)| (o.id.clone(), m)).collect();
            ids.sort_by(|a, b| a.0.cmp(&b.0));
            ids
        };
        let exact = |v: Vec<(String, MatchStrength)>| -> Vec<String> {
            v.into_iter().filter(|(_, m)| *m == MatchStrength::Exact).map(|(id, _)| id).collect()
        };
        for (token, code, message, expected) in [
            (
                None,
                13,
                "gRPC-Web must be translated on a route with gateway-asserted headers",
                "gateway.routing.grpc_web_untranslated_on_assertion_route",
            ),
            (None, 7, "Request protocol not permitted on this route", "gateway.routing.protocol_not_permitted.grpc"),
            (
                Some("circuit_breaker_open"),
                14,
                "Service temporarily unavailable (circuit breaker open)",
                "gateway.admission.circuit_open.grpc",
            ),
        ] {
            assert_eq!(exact(ids("ferrum-edge-0.9.21", token, code, Some(message))), [expected], "{message}");
            assert!(exact(ids("ferrum-edge-0.9.20", token, code, Some(message))).is_empty(), "{message}");
        }
        // Another service's INTERNAL with its own message is not the assertion refusal.
        let other = ids("ferrum-edge-0.9.21", None, 13, Some("database unavailable"));
        assert!(exact(other.clone()).is_empty(), "{other:?}");
        assert!(
            other
                .iter()
                .any(|(id, m)| id == "gateway.routing.grpc_web_untranslated_on_assertion_route" && *m == MatchStrength::GrpcStatusOnly),
            "{other:?}"
        );
        // The breaker rendering needs its token, as the HTTP form does.
        assert!(exact(ids("ferrum-edge-0.9.21", None, 14, Some("Service temporarily unavailable (circuit breaker open)"))).is_empty());
    }

    /// body_validator's v0.9.21 response details are fixed texts; the 502
    /// matches whatever the detail and in either key order (GHSA-84xq-rr63-39pw).
    #[test]
    fn body_validator_response_502_matches_its_fixed_details() {
        for text in [
            r#"{"error":"Response body validation failed","details":"Response body is missing a required field"}"#,
            r#"{"details":"Response body is not valid JSON","error":"Response body validation failed"}"#,
        ] {
            let bf = body_facts(Some("application/json"), text.as_bytes());
            let signal = Signal {
                status: 502,
                token: Some("backend_error"),
                body_text: text,
                body: &bf,
                grpc_status: None,
                grpc_no_message: false,
                grpc_message: None,
            };
            let ids: Vec<String> =
                catalog_for("ferrum-edge-0.9.21").unwrap().match_signal(&signal).into_iter().map(|(o, _)| o.id.clone()).collect();
            assert_eq!(ids, ["plugin.body_validator.response_validation_failed"], "{text}");
        }
    }

    /// Only the 0.9.21 catalog records that the release relays a backend's
    /// own WebSocket upgrade refusal (#7414).
    #[test]
    fn websocket_refusal_relay_is_a_0_9_21_fact() {
        assert!(catalog_for("ferrum-edge-0.9.21").unwrap().relays_websocket_refusals);
        assert!(!catalog_for("ferrum-edge-0.9.20").unwrap().relays_websocket_refusals);
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
                grpc_no_message: false,
                grpc_message: None,
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
        assert_eq!(
            ids(&m.code_only),
            [
                "plugin.a2a_gateway.jsonrpc_method_denied",
                "plugin.a2a_gateway.operation_class_changed",
                "plugin.mcp_gateway.prompt_denied",
                "plugin.mcp_gateway.resource_read_denied"
            ],
            "the same code with another message"
        );
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

    /// gRPC outcomes that answer with a status and no message (HTTP 200,
    /// trailers-only or a gRPC-Web trailer frame) have no body to compare:
    /// they match on status, token and grpc-status when no message arrived,
    /// as a weaker kind of match, and never when one did (#570).
    #[test]
    fn grpc_status_only_outcomes_match_without_a_body() {
        let c = default_catalog();
        let only: Vec<&str> = c.outcomes.iter().filter(|o| o.grpc_status_only).map(|o| o.id.as_str()).collect();
        assert!(only.len() >= 28, "{only:?}");
        for id in [
            "gateway.routing.grpc_requires_post",
            "protocol.grpc.overload_h3",
            "protocol.grpc.route_method_not_allowed",
            "plugin.grpc_deadline.missing_deadline",
            "plugin.grpc_method_router.method_not_permitted",
            "plugin.waf.grpc_reject_mapping",
            "plugin.grpc_web.invalid_request",
        ] {
            let o = c.outcome(id).unwrap_or_else(|| panic!("{id}"));
            assert!(o.grpc_status_only && o.body_patterns.is_empty(), "{id}: {:?}", o.body_patterns);
        }
        // Edge maps the plugin's HTTP 400 to INVALID_ARGUMENT; the generic
        // gRPC-Web rendering has no fixed status, so it is no candidate.
        assert_eq!(c.outcome("plugin.grpc_web.invalid_request").unwrap().grpc_status, Some(3));
        let generic = c.outcome("generic.reject.grpc_web_rendering").unwrap();
        assert!(generic.grpc_status.is_none() && !generic.grpc_status_only);
        // A 200 with a body, or without a gRPC wire shape, is not one.
        for id in ["plugin.oidc_relying_party.logout_short_circuit", "plugin.cors.preflight_unmatched_ignore"] {
            assert!(!c.outcome(id).unwrap().grpc_status_only, "{id}");
        }
        let bf = body_facts(Some("application/grpc"), b"");
        let sig = |token: Option<&'static str>, grpc_status: i32, grpc_no_message: bool| Signal {
            status: 200,
            token,
            body_text: "",
            body: &bf,
            grpc_status: Some(grpc_status),
            grpc_no_message,
            grpc_message: None,
        };
        let ids = |m: Vec<(&Outcome, MatchStrength)>| {
            assert!(
                m.iter().all(|(_, s)| *s == MatchStrength::GrpcStatusOnly),
                "{:?}",
                m.iter().map(|x| (&x.0.id, x.1)).collect::<Vec<_>>()
            );
            m.into_iter().map(|(o, _)| o.id.clone()).collect::<Vec<_>>()
        };
        for cat in catalogs() {
            let m = ids(cat.match_signal(&sig(None, 3, true)));
            for id in ["gateway.routing.grpc_requires_post", "plugin.grpc_deadline.missing_deadline"] {
                assert!(m.iter().any(|x| x == id), "{}: {id} in {m:?}", cat.compatibility_id);
            }
            assert!(!m.iter().any(|x| x == "protocol.grpc.overload_h3"), "another grpc-status: {m:?}");
            let m = ids(cat.match_signal(&sig(Some("overload"), 14, true)));
            assert!(m.iter().any(|x| x == "protocol.grpc.overload_h3"), "{}: {m:?}", cat.compatibility_id);
            assert!(!m.iter().any(|x| x == "protocol.grpc.backend_unavailable"), "a token the outcome does not send: {m:?}");
            // A message arrived: the service answered something, so no outcome without one matches.
            assert!(cat.match_signal(&sig(None, 3, false)).is_empty(), "{}", cat.compatibility_id);
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
                grpc_no_message: false,
                grpc_message: None,
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
