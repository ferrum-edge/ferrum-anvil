//! Regression found by the real-gateway lab (`anvil-lab run auth`,
//! AUTH-X04/X05): a backend 401 that copies a gateway authentication
//! rejection byte for byte, relayed through the gateway, was attributed to the
//! gateway's plugin. The tests reproduce only the public evidence the lab
//! observed — never its private ground truth — plus the genuine gateway
//! rejection that must keep its attribution.

use anvil_diagnostics::{Diagnosis, DiagnosticInput, FerrumTrust, diagnose};
use anvil_domain::diagnostics::{Confidence, SourceScope};
use anvil_domain::execution::{BodyCapture, BodyCompleteness, HeaderEntry, ResponseRecord};
use anvil_domain::outcome::ProtocolStatus;
use anvil_domain::request::Protocol;

fn codes(d: &Diagnosis) -> Vec<&str> {
    d.findings.iter().map(|f| f.code.as_str()).collect()
}

fn response(status: u16, headers: &[(&str, &str)], body: &[u8]) -> ResponseRecord {
    ResponseRecord {
        status,
        reason: None,
        http_version: "HTTP/1.1".into(),
        headers: headers.iter().map(|(n, v)| HeaderEntry { name: n.to_string(), value: v.to_string() }).collect(),
        trailers: vec![],
        trailers_received: false,
        body: BodyCapture {
            completeness: BodyCompleteness::Complete,
            wire_bytes: body.len() as u64,
            declared_length: Some(body.len() as u64),
            captured_bytes: body.len() as u64,
            display_truncated: false,
            content_type: Some("application/json".into()),
            content_encoding: None,
            decoded_bytes: None,
            blob_sha256: None,
        },
    }
}

fn http(r: &ResponseRecord, body: &[u8], trusted: bool) -> Diagnosis {
    let status = ProtocolStatus::Http { status: r.status, reason: None };
    let trust = if trusted {
        FerrumTrust::Trusted { profile_name: "lab".into(), compatibility_id: "ferrum-edge-0.9.5".into(), channel_authenticated: false }
    } else {
        FerrumTrust::NotConfigured
    };
    diagnose(&DiagnosticInput {
        protocol: Protocol::Http,
        method: "GET",
        preparation_failure: None,
        attempts: &[],
        response: Some(r),
        body,
        stream: None,
        protocol_status: &status,
        trust: &trust,
        tls_verification_enabled: true,
        credentials_stripped_on_redirect: false,
        protocol_fallback_from: None,
    })
}

const KEY_AUTH_BODY: &[u8] = br#"{"error":"Invalid API key"}"#;

/// The lab observed that Ferrum Edge 0.9.5 key_auth rejections carry no
/// `Via`, while the backend's own 401 relayed through the same route gets
/// `Via: 1.1 ferrum-edge`. The relayed one must not be attributed to the
/// gateway's authentication plugin.
#[test]
fn auth_x04_backend_401_with_gateway_via_hop_is_not_a_gateway_rejection() {
    let r = response(401, &[("content-type", "application/json"), ("via", "1.1 ferrum-edge")], KEY_AUTH_BODY);
    let d = http(&r, KEY_AUTH_BODY, true);
    assert!(!codes(&d).iter().any(|c| c.starts_with("ferrum.outcome")), "{:?}", codes(&d));
    let f = d.findings.iter().find(|f| f.code == "ferrum.relayed_backend_response").expect("relay finding");
    assert_eq!(f.scope, SourceScope::UpstreamApplication);
    assert!(f.confidence <= Confidence::Likely, "body/header evidence stays at most likely");
    assert!(f.explanation.contains("1.1 ferrum-edge") && f.explanation.contains("plugin.key_auth.invalid_key"), "{}", f.explanation);
    assert!(codes(&d).contains(&"http.unauthorized"));
}

/// Lookalike in the other direction: the genuine gateway rejection (no Via)
/// keeps its gateway-plugin attribution (capped at likely).
#[test]
fn auth_x04_lookalike_gateway_rejection_without_via_keeps_its_attribution() {
    let r = response(401, &[("content-type", "application/json")], KEY_AUTH_BODY);
    let d = http(&r, KEY_AUTH_BODY, true);
    let f = d.findings.iter().find(|f| f.code == "ferrum.outcome").expect("gateway outcome");
    assert_eq!(f.scope, SourceScope::GatewayAdmission);
    assert_eq!(f.confidence, Confidence::Likely);
    assert!(!codes(&d).contains(&"ferrum.relayed_backend_response"));
}

/// A Via hop from some other intermediary is not the gateway's hop and
/// changes nothing; an untrusted destination gets no Ferrum conclusion.
#[test]
fn auth_x04_foreign_via_and_untrusted_destinations_are_unchanged() {
    let r = response(401, &[("via", "1.1 varnish")], KEY_AUTH_BODY);
    let d = http(&r, KEY_AUTH_BODY, true);
    assert!(codes(&d).contains(&"ferrum.outcome"), "{:?}", codes(&d));
    let r = response(401, &[("via", "1.1 ferrum-edge")], KEY_AUTH_BODY);
    let d = http(&r, KEY_AUTH_BODY, false);
    assert!(!codes(&d).iter().any(|c| c.starts_with("ferrum.")), "{:?}", codes(&d));
}

/// AUTH-X05: the fallback-challenge body shared by several gateway paths
/// (ambiguous) is also contradicted by the gateway's Via hop.
#[test]
fn auth_x05_ambiguous_gateway_candidates_are_all_contradicted_by_via() {
    let body = br#"{"error":"Authentication required"}"#;
    let r = response(401, &[("www-authenticate", "ferrum-edge"), ("via", "1.1 ferrum-edge")], body);
    let d = http(&r, body, true);
    assert!(!codes(&d).iter().any(|c| c.starts_with("ferrum.outcome")), "{:?}", codes(&d));
    assert!(codes(&d).contains(&"ferrum.relayed_backend_response"));
    let r = response(401, &[("www-authenticate", "ferrum-edge")], body);
    assert!(codes(&http(&r, body, true)).contains(&"ferrum.outcome_ambiguous"), "without Via the gateway candidates stay listed");
}

/// Gateway-synthesized upstream failures DO carry Via; the relay rule must
/// not touch them (they are not authentication rejections).
#[test]
fn upstream_failure_with_via_keeps_its_token_and_catalog_candidates() {
    let body = br#"{"error":"Backend unavailable"}"#;
    let r = response(502, &[("x-gateway-error", "connection_failure"), ("via", "1.1 ferrum-edge")], body);
    let d = http(&r, body, true);
    assert!(codes(&d).contains(&"ferrum.token.connection_failure"), "{:?}", codes(&d));
    assert!(codes(&d).contains(&"ferrum.outcome_ambiguous"), "{:?}", codes(&d));
    assert!(!codes(&d).contains(&"ferrum.relayed_backend_response"));
}
