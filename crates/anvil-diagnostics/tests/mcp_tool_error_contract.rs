//! `app.mcp_tool_error`: an MCP `tools/call` answered with HTTP 200 and a
//! JSON-RPC result marked `isError: true`. The observation (an error result)
//! is confirmed, but not who wrote it: a Ferrum mcp_gateway OpenAPI bridge
//! writes the same shape when the gateway fails or refuses the REST call it
//! makes for the tool (`plugin.mcp_gateway.openapi_bridge_error_result`, from
//! v0.9.9), and its "(gateway error: …)" text is result content anyone can
//! send. So neither dispatch, origin nor owner is claimed, with or without a
//! trusted Ferrum profile.

use anvil_diagnostics::{Diagnosis, DiagnosticInput, FerrumTrust, diagnose};
use anvil_domain::diagnostics::{Confidence, DiagnosticFinding, Owner, SourceScope};
use anvil_domain::execution::{BodyCapture, BodyCompleteness, HeaderEntry, ResponseRecord};
use anvil_domain::outcome::ProtocolStatus;
use anvil_domain::request::Protocol;

/// The bridge's result for an open breaker (catalog `body_shape`).
const BRIDGE_REFUSAL: &str = r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"HTTP 503 Service Unavailable (gateway error: circuit_breaker_open)\nService unavailable"}],"isError":true}}"#;
/// An ordinary tool reporting its own failure.
const TOOL_FAILURE: &str = r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"order 42 not found"}],"isError":true}}"#;

fn response(body: &[u8]) -> ResponseRecord {
    ResponseRecord {
        status: 200,
        reason: None,
        http_version: "HTTP/1.1".into(),
        headers: vec![HeaderEntry { name: "Content-Type".into(), value: "application/json".into() }],
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
            decoding: None,
            decoding_detail: None,
            blob_sha256: None,
        },
    }
}

fn run(body: &str, trust: FerrumTrust) -> Diagnosis {
    let r = response(body.as_bytes());
    let status = ProtocolStatus::Http { status: 200, reason: None };
    diagnose(&DiagnosticInput {
        protocol: Protocol::Http,
        method: "POST",
        preparation_failure: None,
        attempts: &[],
        response: Some(&r),
        body: body.as_bytes(),
        stream: None,
        protocol_status: &status,
        trust: &trust,
        tls_verification_enabled: true,
        credentials_stripped_on_redirect: false,
        protocol_fallback_from: None,
        workload: None,
        gateway_detail: None,
        redact: None,
    })
}

/// Every trust Anvil can have: none, and each embedded release's trusted
/// profile over plain HTTP and over verified TLS.
fn trusts() -> Vec<FerrumTrust> {
    let mut v = vec![FerrumTrust::NotConfigured];
    for compat in anvil_diagnostics::ferrum::compatibility_ids() {
        for channel_authenticated in [false, true] {
            v.push(FerrumTrust::Trusted { profile_name: "lab".into(), compatibility_id: compat.into(), channel_authenticated });
        }
    }
    v
}

fn tool_error(d: &Diagnosis) -> &DiagnosticFinding {
    d.findings.iter().find(|f| f.code == "app.mcp_tool_error").unwrap_or_else(|| panic!("{:?}", d.findings))
}

#[test]
fn an_error_result_is_confirmed_but_its_origin_and_owner_are_not() {
    for body in [BRIDGE_REFUSAL, TOOL_FAILURE] {
        for trust in trusts() {
            let d = run(body, trust.clone());
            let f = tool_error(&d);
            assert_eq!(f.confidence, Confidence::Confirmed, "{trust:?}");
            assert_eq!(f.scope, SourceScope::Unknown, "{trust:?}");
            assert_eq!(f.owner, Owner::Unknown, "{trust:?}");
            assert!(!f.explanation.contains("reached the tool"), "{trust:?}: {}", f.explanation);
            assert!(f.remediation.iter().all(|r| r.owner == Owner::Unknown), "{trust:?}: {:?}", f.remediation);
            assert!(f.alternatives.iter().any(|a| a.contains("gateway")), "{trust:?}: {:?}", f.alternatives);
            // Nothing else attributes the result to the tool or to a gateway
            // with confirmed confidence on the strength of its text alone.
            for other in d.findings.iter().filter(|x| x.code != "app.mcp_tool_error") {
                let attributed = matches!(
                    other.scope,
                    SourceScope::UpstreamApplication | SourceScope::GatewayAdmission | SourceScope::GatewayToUpstream
                );
                assert!(
                    !(attributed && other.confidence == Confidence::Confirmed),
                    "{trust:?}: {} {:?} {:?}",
                    other.code,
                    other.scope,
                    other.confidence
                );
            }
        }
    }
}

#[test]
fn the_result_text_is_shown_as_reported() {
    let f = tool_error(&run(BRIDGE_REFUSAL, FerrumTrust::NotConfigured)).clone();
    assert!(f.explanation.contains("gateway error: circuit_breaker_open"), "{}", f.explanation);
    let f = tool_error(&run(TOOL_FAILURE, FerrumTrust::NotConfigured)).clone();
    assert!(f.explanation.contains("order 42 not found"), "{}", f.explanation);
}
