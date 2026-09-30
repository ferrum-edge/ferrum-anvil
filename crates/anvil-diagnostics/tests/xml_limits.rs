//! GHSA-mvjp-hhjj-mh63: every XML response up to 256 KiB is parsed to find a
//! SOAP fault. A body whose namespace or attribute work grows with the square
//! of its size is not parsed: no fault is read from it, and a
//! `partial_visibility` warning says why. Normal envelopes are still read.

use anvil_diagnostics::{Diagnosis, DiagnosticInput, FerrumTrust, diagnose};
use anvil_domain::execution::{
    AttemptObservation, AttemptReason, BodyCapture, BodyCompleteness, ByteCounts, DispatchState, HeaderEntry, ResponseRecord,
};
use anvil_domain::outcome::{ProtocolStatus, WarningCode};
use anvil_domain::request::Protocol;
use std::time::{Duration, Instant};

const FAULT: &str = "<Fault><faultcode>Server</faultcode><faultstring>boom</faultstring></Fault>";

fn diagnose_xml(body: &str) -> Diagnosis {
    let attempts = [AttemptObservation {
        early_data: None,
        index: 0,
        reason: AttemptReason::Initial,
        method: "POST".into(),
        url: "http://127.0.0.1:18180/soap".into(),
        started_at: chrono::Utc::now(),
        connection: None,
        phases: vec![],
        dispatch: DispatchState::Sent,
        bytes: ByteCounts::default(),
        response_status: Some(200),
        failure: None,
        duration_us: 1,
    }];
    let r = ResponseRecord {
        status: 200,
        reason: None,
        http_version: "HTTP/1.1".into(),
        headers: vec![HeaderEntry { name: "content-type".into(), value: "text/xml".into() }],
        trailers: vec![],
        trailers_received: false,
        body: BodyCapture {
            completeness: BodyCompleteness::Complete,
            wire_bytes: body.len() as u64,
            declared_length: Some(body.len() as u64),
            captured_bytes: body.len() as u64,
            display_truncated: false,
            content_type: Some("text/xml".into()),
            content_encoding: None,
            decoded_bytes: None,
            decoding: None,
            decoding_detail: None,
            blob_sha256: None,
        },
    };
    let status = ProtocolStatus::Http { status: 200, reason: None };
    diagnose(&DiagnosticInput {
        protocol: Protocol::Http,
        method: "POST",
        preparation_failure: None,
        attempts: &attempts,
        response: Some(&r),
        body: body.as_bytes(),
        stream: None,
        protocol_status: &status,
        trust: &FerrumTrust::NotConfigured,
        tls_verification_enabled: true,
        credentials_stripped_on_redirect: false,
        protocol_fallback_from: None,
        workload: None,
        redact: None,
    })
}

/// `depth` nested elements that each declare a namespace.
fn nested_namespaces(depth: usize) -> String {
    let mut s = String::new();
    for i in 0..depth {
        s.push_str(&format!("<e xmlns:p{i}=\"urn:n{i}\">"));
    }
    s.push_str(&"</e>".repeat(depth));
    s
}

/// `elements` elements with `attributes` attributes each, in the namespace
/// the envelope binds to `p`.
fn wide_elements(elements: usize, attributes: usize) -> String {
    let mut s = String::new();
    for _ in 0..elements {
        s.push_str("<c");
        for i in 0..attributes {
            s.push_str(&format!(" p:a{i}=\"\""));
        }
        s.push_str("/>");
    }
    s
}

/// A SOAP fault envelope binding `p` to a URI of `uri_bytes`, with `extra` after the fault.
fn envelope(uri_bytes: usize, extra: &str) -> String {
    format!("<Envelope xmlns:p=\"{}\"><Body>{FAULT}{extra}</Body></Envelope>", "u".repeat(uri_bytes))
}

#[test]
fn xml_too_complex_to_inspect_is_skipped_with_a_warning() {
    let started = Instant::now();
    let bodies = [
        (envelope(16, &nested_namespaces(2_000)), "more than 1024 namespace declarations"),
        (envelope(500, &wide_elements(1, 300)), "more than 256 attributes on one element"),
        // Each element is within the per-element bound; together they are not.
        (envelope(500, &wide_elements(14, 200)), "attribute pairs"),
        (envelope(600, ""), "a namespace URI longer than 512 bytes"),
    ];
    for (body, why) in &bodies {
        assert!(body.len() <= 256 * 1024, "{why}: the body must be one the diagnostics parse");
        let d = diagnose_xml(body);
        assert_eq!(d.body.soap_fault, None, "{why}");
        assert!(d.body.xml_not_inspected.as_deref().is_some_and(|n| n.contains(why)), "{why}: {:?}", d.body.xml_not_inspected);
        assert!(!d.findings.iter().any(|f| f.code == "app.soap_fault"), "{why}");
        let w = d.warnings.iter().find(|w| w.code == WarningCode::PartialVisibility).expect("a partial_visibility warning");
        assert!(w.message.starts_with("The response XML is too complex to inspect safely ("), "{}", w.message);
        assert!(w.message.contains(why), "{}", w.message);
    }
    assert!(started.elapsed() < Duration::from_secs(10), "took {:?}", started.elapsed());
}

#[test]
fn xml_within_the_limits_is_inspected() {
    for body in [envelope(16, ""), envelope(500, &wide_elements(5, 200)), envelope(16, &nested_namespaces(1_000))] {
        let d = diagnose_xml(&body);
        assert_eq!(d.body.xml_not_inspected, None);
        let fault = d.body.soap_fault.as_ref().expect("the fault is read");
        assert_eq!((fault.code.as_str(), fault.reason.as_str()), ("Server", "boom"));
        assert!(d.findings.iter().any(|f| f.code == "app.soap_fault"));
        assert!(!d.warnings.iter().any(|w| w.code == WarningCode::PartialVisibility), "{:?}", d.warnings);
    }
}
