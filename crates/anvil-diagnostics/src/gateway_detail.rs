//! Ferrum Edge gateway diagnostic references (G01; Ferrum Edge v0.9.9 and
//! later, `ferrum.diagnostic_ref.v1`).
//!
//! With `FERRUM_DIAGNOSTIC_REFS=errors` or `all` (the default is `off`), the
//! gateway stamps the error responses it authors with
//! `X-Ferrum-Diagnostic-Ref: fd1_<32 hex>`, or `fd2_<8 hex replica>_<32 hex>`
//! with replica tagging, and resolves a reference only through the
//! authenticated admin lookup `GET /diagnostics/v1/refs/{ref}`. The lookup
//! needs an admin JWT with the `diagnostics:read` scope and an `ns` claim
//! naming the gateway's namespace; the admin role implies neither.
//!
//! The header alone proves nothing: a backend, a plugin or any server that is
//! not Ferrum Edge can send it. A lookup is gateway evidence only when the
//! gateway answered it with a valid record that binds to this exact response:
//! the same reference, status, public token, client protocol and namespace,
//! created while the request was in flight. Every other outcome (no
//! reference, a malformed one, `401`/`403`, the indistinguishable `404`,
//! `429`, a record of another response) leaves the Ferrum findings at their
//! own ceiling.
//!
//! This module is pure: the engine performs the lookup and passes its outcome
//! to the rules as [`GatewayDetail`].

use anvil_domain::execution::{ConnectionObservation, ResponseRecord};
use chrono::{DateTime, Utc};
use serde::Deserialize;

/// Response header carrying the reference.
pub const REF_HEADER: &str = "x-ferrum-diagnostic-ref";
/// Header of a lookup `404` naming the replica that minted a replica-tagged
/// reference another replica was asked for.
pub const OWNER_REPLICA_HEADER: &str = "x-ferrum-diagnostic-owner-replica";
/// The only lookup body version Anvil reads.
pub const SCHEMA_VERSION: &str = "ferrum.diagnostic_ref.v1";
/// Lookup path on the admin listener; the reference is appended.
pub const LOOKUP_PATH: &str = "/diagnostics/v1/refs/";
/// Largest lookup body Anvil reads (a record is a few hundred bytes).
pub const MAX_LOOKUP_BODY_BYTES: usize = 64 * 1024;
/// Clock difference allowed between this computer and the gateway when
/// checking that a record was created while the request was in flight.
pub const CLOCK_SKEW_SECS: i64 = 300;

const MAX_LABEL_LEN: usize = 64;
const MAX_TEXT_LEN: usize = 300;

// The closed vocabularies of `ferrum.diagnostic_ref.v1` that Anvil accepts.
// The contract drift test compares them with the pinned schema.

/// Most attempts a record lists (`detail.attempts`).
pub const MAX_ATTEMPTS: usize = 8;
/// `protocol`.
pub const PROTOCOLS: [&str; 3] = ["http1", "http2", "http3"];
/// `gateway_error` (besides `null`).
pub const TOKENS: [&str; 8] = [
    "connection_failure",
    "backend_timeout",
    "backend_error",
    "circuit_breaker_open",
    "overload",
    "config_stale",
    "concurrency_limit",
    "request_timeout",
];
/// `detail.backend_dispatch`.
pub const DISPATCH: [&str; 4] = ["not_dispatched", "pre_wire_failure", "ambiguous_failure", "backend_response"];
/// `detail.attempts[].backend_dispatch`.
pub const ATTEMPT_DISPATCH: [&str; 3] = ["pre_wire_failure", "ambiguous_failure", "backend_response"];
/// `detail.duration_bucket`.
pub const DURATION_BUCKETS: [&str; 6] = ["lt_10ms", "lt_100ms", "lt_1s", "lt_10s", "ge_10s", "unknown"];
/// `detail.rejection_phase` (besides `null`).
pub const REJECTION_PHASES: [&str; 4] = ["circuit_breaker_open", "concurrency_limit", "overload", "config_stale"];
/// `detail.route_timeout_phase` (besides `null`).
pub const ROUTE_TIMEOUT_PHASES: [&str; 3] = ["before_dispatch", "dispatch", "retry_backoff"];
/// `detail.rejection.source`.
pub const REJECTION_SOURCES: [&str; 3] = ["plugin", "gateway", "routing"];
/// `detail.attempts[].tls.failure`.
pub const TLS_FAILURES: [&str; 11] = [
    "certificate_verification",
    "alert_received",
    "no_certificates_presented",
    "peer_incompatible",
    "peer_misbehaved",
    "invalid_message",
    "unexpected_message",
    "decrypt_error",
    "no_application_protocol",
    "invalid_crl",
    "other",
];

fn is_lower_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// A well-formed reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiagnosticRef {
    pub value: String,
    /// The replica id an `fd2_` reference embeds.
    pub replica: Option<String>,
}

/// Parse `fd1_<32 lowercase hex>` or `fd2_<8 lowercase hex>_<32 lowercase hex>`.
pub fn parse_ref(s: &str) -> Option<DiagnosticRef> {
    if let Some(hex) = s.strip_prefix("fd1_") {
        return is_lower_hex(hex, 32).then(|| DiagnosticRef { value: s.to_string(), replica: None });
    }
    let (replica, hex) = s.strip_prefix("fd2_")?.split_once('_')?;
    if !is_lower_hex(replica, 8) || !is_lower_hex(hex, 32) {
        return None;
    }
    Some(DiagnosticRef { value: s.to_string(), replica: Some(replica.to_string()) })
}

/// A replica id (8 lowercase hex digits), as an owner hint carries it.
pub fn parse_replica(s: &str) -> Option<String> {
    let s = s.trim();
    is_lower_hex(s, 8).then(|| s.to_string())
}

/// A text a response or a record supplied, as a finding may quote it: at
/// most 80 characters, without control characters.
pub fn bounded(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).take(80).collect()
}

/// What a response carries in `X-Ferrum-Diagnostic-Ref`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponseRef {
    Absent,
    Present(DiagnosticRef),
    /// Not a reference the gateway mints, or several different values.
    Invalid(String),
}

pub fn response_ref(r: &ResponseRecord) -> ResponseRef {
    let mut values: Vec<&str> = r.header_values(REF_HEADER).into_iter().map(str::trim).collect();
    values.sort_unstable();
    values.dedup();
    match values.as_slice() {
        [] => ResponseRef::Absent,
        [one] => parse_ref(one).map_or_else(|| ResponseRef::Invalid(bounded(one)), ResponseRef::Present),
        many => ResponseRef::Invalid(bounded(&many.join(", "))),
    }
}

/// The facts of one response that a lookup record must match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    pub reference: DiagnosticRef,
    pub status: u16,
    /// The response's `X-Gateway-Error` value(s), lowercased; `None` without one.
    pub gateway_error: Option<String>,
    /// `http1`, `http2` or `http3`; `None` when the response's version is unknown.
    pub protocol: Option<&'static str>,
    /// The namespace the profile expects, when it names one.
    pub namespace: Option<String>,
    /// The record must have been created inside this window.
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
}

impl Binding {
    /// Bind response `r`, whose request was sent at `sent_at` and which was
    /// received by `received_by`, to its reference.
    pub fn new(
        r: &ResponseRecord,
        reference: DiagnosticRef,
        namespace: Option<&str>,
        sent_at: DateTime<Utc>,
        received_by: DateTime<Utc>,
    ) -> Self {
        let mut tokens: Vec<String> = Vec::new();
        for v in r.header_values("x-gateway-error") {
            for part in v.split(',') {
                let p = part.trim().to_ascii_lowercase();
                if !p.is_empty() && !tokens.contains(&p) {
                    tokens.push(p);
                }
            }
        }
        let skew = chrono::Duration::seconds(CLOCK_SKEW_SECS);
        Binding {
            reference,
            status: r.status,
            gateway_error: (!tokens.is_empty()).then(|| tokens.join(",")),
            protocol: protocol_label(&r.http_version),
            namespace: namespace.map(str::trim).filter(|n| !n.is_empty()).map(String::from),
            not_before: sent_at - skew,
            not_after: received_by + skew,
        }
    }
}

fn protocol_label(version: &str) -> Option<&'static str> {
    match version {
        "HTTP/1.0" | "HTTP/1.1" => Some("http1"),
        "HTTP/2" => Some("http2"),
        "HTTP/3" => Some("http3"),
        _ => None,
    }
}

/// A `ferrum.diagnostic_ref.v1` lookup body. Fields added within the version
/// are ignored; every value Anvil reads is checked by [`parse_view`].
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct RefView {
    pub schema_version: String,
    #[serde(rename = "ref")]
    pub reference: String,
    #[serde(default)]
    pub replica_id: Option<String>,
    pub namespace: String,
    pub created_at: String,
    pub expires_at: String,
    pub protocol: String,
    pub status: u16,
    pub gateway_error: Option<String>,
    pub detail_available: bool,
    pub detail: Option<Detail>,
}

/// The gateway's detail behind a reference (closed vocabularies and operator
/// configuration only).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Detail {
    #[serde(default)]
    pub error_class: Option<String>,
    #[serde(default)]
    pub body_error_class: Option<String>,
    #[serde(default)]
    pub rejection_phase: Option<String>,
    #[serde(default)]
    pub route_timeout_phase: Option<String>,
    pub backend_dispatch: String,
    #[serde(default)]
    pub proxy_id: Option<String>,
    #[serde(default)]
    pub backend_target: Option<String>,
    pub duration_bucket: String,
    #[serde(default)]
    pub rejection: Option<Rejection>,
    #[serde(default)]
    pub attempts: Vec<Attempt>,
    #[serde(default)]
    pub attempts_omitted: u32,
}

/// The policy that refused the request.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Rejection {
    pub source: String,
    pub phase: String,
    #[serde(default)]
    pub plugin: Option<String>,
}

/// One backend attempt, in dispatch order.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Attempt {
    pub attempt: u32,
    pub backend_dispatch: String,
    #[serde(default)]
    pub status: Option<u16>,
    #[serde(default)]
    pub error_class: Option<String>,
    #[serde(default)]
    pub tls: Option<TlsDetail>,
}

/// Closed description of a backend TLS failure.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct TlsDetail {
    pub failure: String,
    #[serde(default)]
    pub reason: Option<String>,
}

fn label_ok(s: &str) -> bool {
    !s.is_empty() && s.len() <= MAX_LABEL_LEN && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b':'))
}

fn text_ok(s: &str) -> bool {
    !s.is_empty() && s.len() <= MAX_TEXT_LEN && !s.chars().any(char::is_control)
}

fn one_of(field: &str, value: &str, allowed: &[&str]) -> Result<(), String> {
    if allowed.contains(&value) { Ok(()) } else { Err(format!("{field} is not one of {}", allowed.join(", "))) }
}

fn label(field: &str, value: &str) -> Result<(), String> {
    if label_ok(value) { Ok(()) } else { Err(format!("{field} is not a label")) }
}

fn is_status(s: u16) -> bool {
    (100..=599).contains(&s)
}

impl RefView {
    /// When the gateway created the record.
    pub fn created(&self) -> Option<DateTime<Utc>> {
        DateTime::parse_from_rfc3339(&self.created_at).ok().map(|t| t.with_timezone(&Utc))
    }

    fn validate(&self) -> Result<(), String> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(format!("schema_version is not {SCHEMA_VERSION}"));
        }
        let reference = parse_ref(&self.reference).ok_or("ref is not a well-formed reference")?;
        if reference.replica != self.replica_id {
            return Err("replica_id does not match ref".into());
        }
        if !text_ok(&self.namespace) {
            return Err("namespace is not a bounded text".into());
        }
        let expires = DateTime::parse_from_rfc3339(&self.expires_at).map_err(|_| "expires_at is not an RFC 3339 time")?;
        match self.created() {
            Some(created) if expires.with_timezone(&Utc) >= created => {}
            Some(_) => return Err("expires_at is before created_at".into()),
            None => return Err("created_at is not an RFC 3339 time".into()),
        }
        one_of("protocol", &self.protocol, &PROTOCOLS)?;
        if !is_status(self.status) {
            return Err("status is not an HTTP status".into());
        }
        if let Some(t) = &self.gateway_error {
            one_of("gateway_error", t, &TOKENS)?;
        }
        if self.detail_available != self.detail.is_some() {
            return Err("detail_available does not match detail".into());
        }
        self.detail.as_ref().map_or(Ok(()), Detail::validate)
    }
}

impl Detail {
    fn validate(&self) -> Result<(), String> {
        for (field, value) in [("error_class", &self.error_class), ("body_error_class", &self.body_error_class)] {
            if let Some(v) = value {
                label(field, v)?;
            }
        }
        if let Some(p) = &self.rejection_phase {
            one_of("rejection_phase", p, &REJECTION_PHASES)?;
        }
        if let Some(p) = &self.route_timeout_phase {
            one_of("route_timeout_phase", p, &ROUTE_TIMEOUT_PHASES)?;
        }
        one_of("backend_dispatch", &self.backend_dispatch, &DISPATCH)?;
        one_of("duration_bucket", &self.duration_bucket, &DURATION_BUCKETS)?;
        if [&self.proxy_id, &self.backend_target].into_iter().flatten().any(|v| !text_ok(v)) {
            return Err("proxy_id or backend_target is not a bounded text".into());
        }
        if let Some(r) = &self.rejection {
            one_of("rejection.source", &r.source, &REJECTION_SOURCES)?;
            label("rejection.phase", &r.phase)?;
            if let Some(p) = &r.plugin {
                label("rejection.plugin", p)?;
            }
        }
        if self.attempts.len() > MAX_ATTEMPTS {
            return Err(format!("more than {MAX_ATTEMPTS} attempts"));
        }
        self.attempts.iter().try_for_each(Attempt::validate)
    }
}

impl Attempt {
    fn validate(&self) -> Result<(), String> {
        if self.attempt == 0 {
            return Err("attempt numbers start at 1".into());
        }
        one_of("attempts.backend_dispatch", &self.backend_dispatch, &ATTEMPT_DISPATCH)?;
        if self.status.is_some_and(|s| !is_status(s)) {
            return Err("an attempt status is not an HTTP status".into());
        }
        if let Some(c) = &self.error_class {
            label("attempts.error_class", c)?;
        }
        if let Some(t) = &self.tls {
            one_of("attempts.tls.failure", &t.failure, &TLS_FAILURES)?;
            if let Some(r) = &t.reason {
                label("attempts.tls.reason", r)?;
            }
        }
        Ok(())
    }
}

/// Parse and check a lookup body. Error texts never quote the body.
pub fn parse_view(body: &[u8]) -> Result<RefView, String> {
    if body.len() > MAX_LOOKUP_BODY_BYTES {
        return Err(format!("the record exceeds {MAX_LOOKUP_BODY_BYTES} bytes"));
    }
    let view: RefView = serde_json::from_slice(body).map_err(|e| format!("not a {SCHEMA_VERSION} record (line {})", e.line()))?;
    view.validate()?;
    Ok(view)
}

/// A record that does not describe the response it was looked up for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mismatch {
    pub field: &'static str,
    /// What the response shows.
    pub response: String,
    /// What the record says.
    pub record: String,
}

fn mismatch(field: &'static str, response: impl Into<String>, record: &str) -> Result<(), Mismatch> {
    Err(Mismatch { field, response: response.into(), record: bounded(record) })
}

/// Whether `view` describes the response `b` was taken from: the same
/// reference, status, public token, client protocol and (when the profile
/// names one) namespace, created while the request was in flight.
pub fn check_binding(view: &RefView, b: &Binding) -> Result<(), Mismatch> {
    if view.reference != b.reference.value {
        return mismatch("ref", b.reference.value.clone(), &view.reference);
    }
    if view.status != b.status {
        return mismatch("status", b.status.to_string(), &view.status.to_string());
    }
    if view.gateway_error != b.gateway_error {
        return mismatch("gateway_error", b.gateway_error.as_deref().unwrap_or("none"), view.gateway_error.as_deref().unwrap_or("none"));
    }
    if let Some(p) = b.protocol
        && view.protocol != p
    {
        return mismatch("protocol", p, &view.protocol);
    }
    if let Some(ns) = &b.namespace
        && &view.namespace != ns
    {
        return mismatch("namespace", ns.clone(), &view.namespace);
    }
    match view.created() {
        Some(t) if t >= b.not_before && t <= b.not_after => Ok(()),
        _ => mismatch("created_at", format!("between {} and {}", b.not_before.to_rfc3339(), b.not_after.to_rfc3339()), &view.created_at),
    }
}

/// Outcome of one lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LookupOutcome {
    /// A valid record that binds to the response.
    Resolved(Box<RefView>),
    /// A valid record of another response (or of another time or namespace).
    Mismatch(Mismatch),
    /// `401` or `403`: the lookup credential was refused.
    Refused { status: u16 },
    /// `404`: unknown, expired, evicted, outside the credential's namespaces,
    /// minted by another replica, or references are off. Ferrum Edge answers
    /// all of these alike.
    NotFound { owner_replica: Option<String> },
    /// `429`: the lookup rate limit.
    RateLimited,
    /// No usable answer: no credential, a transport failure, another status
    /// or a record Anvil does not accept.
    Failed { reason: String },
}

/// What Anvil learned from the gateway's diagnostic reference of one
/// response, for a trusted Ferrum profile with a lookup configured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GatewayDetail {
    /// The response carries no reference.
    NoReference,
    /// The reference is malformed, or several differ: it was not looked up.
    InvalidReference { value: String },
    /// The reference was looked up.
    Looked {
        reference: String,
        /// Origin of the admin listener that was asked.
        endpoint: String,
        /// The lookup travelled over verified TLS or a direct loopback connection.
        channel_authenticated: bool,
        outcome: LookupOutcome,
    },
}

/// Whether a connection went straight to a loopback address, through no
/// proxy and no tunnel: nothing outside this computer could answer on it.
pub fn direct_loopback(c: &ConnectionObservation) -> bool {
    c.via_proxy.is_none()
        && c.tunnel.is_none()
        && c.remote_address.as_deref().and_then(|a| a.parse::<std::net::SocketAddr>().ok()).is_some_and(|a| a.ip().is_loopback())
}

#[cfg(test)]
mod tests {
    use super::*;
    use anvil_domain::execution::{BodyCapture, BodyCompleteness, HeaderEntry};

    const REF: &str = "fd1_3f9c2a7e5b1d4c8a9e0f6b2d7c4a1e5f";

    fn response(status: u16, version: &str, headers: &[(&str, &str)]) -> ResponseRecord {
        ResponseRecord {
            status,
            reason: None,
            http_version: version.into(),
            headers: headers.iter().map(|(n, v)| HeaderEntry { name: n.to_string(), value: v.to_string() }).collect(),
            trailers: vec![],
            trailers_received: false,
            body: BodyCapture {
                completeness: BodyCompleteness::Complete,
                wire_bytes: 0,
                declared_length: None,
                captured_bytes: 0,
                display_truncated: false,
                content_type: Some("application/json".into()),
                content_encoding: None,
                decoded_bytes: None,
                decoding: None,
                decoding_detail: None,
                blob_sha256: None,
            },
        }
    }

    fn record(created_at: &str) -> String {
        format!(
            r#"{{"schema_version":"ferrum.diagnostic_ref.v1","ref":"{REF}","namespace":"ferrum","created_at":"{created_at}","expires_at":"2099-01-01T00:00:00Z","protocol":"http1","status":502,"gateway_error":"connection_failure","detail_available":true,"detail":{{"error_class":"connection_refused","body_error_class":null,"rejection_phase":null,"route_timeout_phase":null,"backend_dispatch":"pre_wire_failure","proxy_id":"core","backend_target":"http://127.0.0.1:19002","duration_bucket":"lt_10ms","attempts":[{{"attempt":1,"backend_dispatch":"pre_wire_failure","error_class":"connection_refused"}}]}}}}"#
        )
    }

    fn binding(r: &ResponseRecord, namespace: Option<&str>) -> Binding {
        let now = Utc::now();
        Binding::new(r, parse_ref(REF).unwrap(), namespace, now - chrono::Duration::seconds(1), now)
    }

    #[test]
    fn references_parse_only_in_the_minted_forms() {
        assert_eq!(parse_ref(REF).map(|r| r.replica), Some(None));
        let tagged = parse_ref("fd2_1a2b3c4d_3f9c2a7e5b1d4c8a9e0f6b2d7c4a1e5f").expect("tagged");
        assert_eq!(tagged.replica.as_deref(), Some("1a2b3c4d"));
        for bad in [
            "",
            "fd1_",
            "fd1_3F9C2A7E5B1D4C8A9E0F6B2D7C4A1E5F",
            "fd1_3f9c2a7e5b1d4c8a9e0f6b2d7c4a1e5",
            "fd1_3f9c2a7e5b1d4c8a9e0f6b2d7c4a1e5f0",
            "fd3_3f9c2a7e5b1d4c8a9e0f6b2d7c4a1e5f",
            "fd2_1a2b3c4d3f9c2a7e5b1d4c8a9e0f6b2d7c4a1e5f",
            "fd2_1A2B3C4D_3f9c2a7e5b1d4c8a9e0f6b2d7c4a1e5f",
            "x-request-id-12345",
        ] {
            assert!(parse_ref(bad).is_none(), "{bad:?}");
        }
        assert_eq!(parse_replica(" 1a2b3c4d "), Some("1a2b3c4d".into()));
        assert_eq!(parse_replica("1A2B3C4D"), None);
    }

    #[test]
    fn the_response_header_is_read_but_never_trusted_by_itself() {
        assert_eq!(response_ref(&response(502, "HTTP/1.1", &[])), ResponseRef::Absent);
        let one = response(502, "HTTP/1.1", &[("X-Ferrum-Diagnostic-Ref", REF)]);
        assert_eq!(response_ref(&one), ResponseRef::Present(parse_ref(REF).unwrap()));
        let repeated = response(502, "HTTP/1.1", &[("x-ferrum-diagnostic-ref", REF), ("x-ferrum-diagnostic-ref", REF)]);
        assert_eq!(response_ref(&repeated), ResponseRef::Present(parse_ref(REF).unwrap()));
        let other = "fd1_00000000000000000000000000000000";
        let two = response(502, "HTTP/1.1", &[("x-ferrum-diagnostic-ref", REF), ("x-ferrum-diagnostic-ref", other)]);
        assert!(matches!(response_ref(&two), ResponseRef::Invalid(_)));
        let forged = response(502, "HTTP/1.1", &[("x-ferrum-diagnostic-ref", "ref-\u{1b}[31m-forged")]);
        assert_eq!(response_ref(&forged), ResponseRef::Invalid("ref-[31m-forged".into()));
    }

    #[test]
    fn a_record_binds_only_to_its_own_response() {
        let r = response(502, "HTTP/1.1", &[("x-gateway-error", "connection_failure"), ("x-ferrum-diagnostic-ref", REF)]);
        let now = Utc::now().to_rfc3339();
        let view = parse_view(record(&now).as_bytes()).expect("valid record");
        assert_eq!(check_binding(&view, &binding(&r, None)), Ok(()));
        assert_eq!(check_binding(&view, &binding(&r, Some("ferrum"))), Ok(()));

        let field = |r: &ResponseRecord, ns: Option<&str>, view: &RefView| check_binding(view, &binding(r, ns)).unwrap_err().field;
        assert_eq!(field(&r, Some("tenant-b"), &view), "namespace");
        let other_status = response(503, "HTTP/1.1", &[("x-gateway-error", "connection_failure")]);
        assert_eq!(field(&other_status, None, &view), "status");
        let other_token = response(502, "HTTP/1.1", &[("x-gateway-error", "backend_error")]);
        assert_eq!(field(&other_token, None, &view), "gateway_error");
        let no_token = response(502, "HTTP/1.1", &[]);
        assert_eq!(field(&no_token, None, &view), "gateway_error");
        let h2 = response(502, "HTTP/2", &[("x-gateway-error", "connection_failure")]);
        assert_eq!(field(&h2, None, &view), "protocol");
        let mut other_ref = binding(&r, None);
        other_ref.reference = parse_ref("fd1_00000000000000000000000000000000").unwrap();
        assert_eq!(check_binding(&view, &other_ref).unwrap_err().field, "ref");
        // A record created long before this request is a replay of another response.
        let old = parse_view(record("2026-01-01T00:00:00Z").as_bytes()).expect("valid record");
        assert_eq!(field(&r, None, &old), "created_at");
    }

    #[test]
    fn only_closed_vocabularies_are_accepted() {
        let now = Utc::now().to_rfc3339();
        let good = record(&now);
        assert!(parse_view(good.as_bytes()).is_ok());
        for (from, to) in [
            ("\"ferrum.diagnostic_ref.v1\"", "\"ferrum.diagnostic_ref.v2\""),
            ("\"protocol\":\"http1\"", "\"protocol\":\"spdy\""),
            ("\"gateway_error\":\"connection_failure\"", "\"gateway_error\":\"connection_refused\""),
            ("\"backend_dispatch\":\"pre_wire_failure\",\"proxy_id\"", "\"backend_dispatch\":\"sent\",\"proxy_id\""),
            ("\"duration_bucket\":\"lt_10ms\"", "\"duration_bucket\":\"12ms\""),
            ("\"error_class\":\"connection_refused\",\"body", "\"error_class\":\"refused <script>\",\"body"),
            ("\"detail_available\":true", "\"detail_available\":false"),
            ("\"status\":502", "\"status\":999"),
            ("\"attempt\":1", "\"attempt\":0"),
        ] {
            let bad = good.replacen(from, to, 1);
            assert_ne!(bad, good, "{from} not found");
            assert!(parse_view(bad.as_bytes()).is_err(), "accepted {to}");
        }
        assert!(parse_view(b"not json").is_err());
        assert!(parse_view(&vec![b' '; MAX_LOOKUP_BODY_BYTES + 1]).is_err());
        let error = parse_view(br#"{"schema_version":"ferrum.diagnostic_ref.v1","ref":"tok-SENSITIVE-echoed"}"#).unwrap_err();
        assert!(!error.contains("tok-SENSITIVE"), "an error never quotes the body: {error}");
    }

    #[test]
    fn only_a_direct_loopback_connection_counts_as_local() {
        let conn = |remote: &str, proxy: Option<&str>| ConnectionObservation {
            id: 1,
            reused: false,
            protocol: None,
            local_address: None,
            remote_address: Some(remote.into()),
            resolved_addresses: vec![],
            resolution_source: None,
            connect_attempts: vec![],
            via_proxy: proxy.map(String::from),
            tls: None,
            prior_requests: 0,
            proxy_header: None,
            tunnel: None,
        };
        assert!(direct_loopback(&conn("127.0.0.1:18090", None)));
        assert!(direct_loopback(&conn("[::1]:18090", None)));
        assert!(!direct_loopback(&conn("192.0.2.10:18090", None)));
        assert!(!direct_loopback(&conn("127.0.0.1:3128", Some("lab proxy"))));
    }
}
