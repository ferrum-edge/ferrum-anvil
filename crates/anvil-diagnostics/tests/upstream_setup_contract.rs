//! Public-signal contract tests for gateway-to-upstream setup outcomes that
//! the lab cannot (or may not) reproduce live on 0.9.5, 0.9.7, 0.9.8, 0.9.9, 0.9.10 or 0.9.11:
//!
//! * UP-017 ephemeral-port exhaustion (EADDRNOTAVAIL at connect): neither release has a
//!   dial-admission hook, and exhausting the lab host's real ephemeral ports
//!   is unsafe;
//! * UP-019 trust withdrawn: emitted only by the mesh HBONE / sidecar-mTLS
//!   transports when an accepted trust publication withdraws an authority;
//!   there is no mesh/HBONE lab;
//! * UP-018 on the pooled lanes (direct H1 in 0.9.11 / H2 / gRPC / H3 / mesh pools), whose
//!   public signal is the same coarse `connection_failure` family. The
//!   HTTP/1.1 lane runs in `anvil-lab run admission`: reqwest on the historical
//!   releases, direct H1 on 0.9.11 (hosted qualification recorded in
//!   `docs/audit/gateway-0.9.11-delta.md`).
//!
//! These are NOT live reproductions and NOT hook-based tests: they feed only
//! the exact public signal the source-audited catalogs record for each outcome
//! (`catalog/ferrum/ferrum-edge-{0.9.5,0.9.7,0.9.8,0.9.9,0.9.10,0.9.11}/outcomes.json`;
//! every test runs against each embedded release's catalog) through the engine's
//! diagnosis and assert what Anvil may and may not conclude from it. No
//! private ground truth (operator `error_class`) is ever an input.

use anvil_diagnostics::{Diagnosis, DiagnosticInput, FerrumTrust, diagnose};
use anvil_domain::diagnostics::{Confidence, DiagnosticFinding, SourceScope};
use anvil_domain::execution::{BodyCapture, BodyCompleteness, HeaderEntry, ResponseRecord};
use anvil_domain::outcome::ProtocolStatus;
use anvil_domain::request::Protocol;

/// The catalog's public signal shared by DNS / refused / connect-timeout /
/// TLS setup / pool cancellation / port exhaustion / pooled connection
/// ceiling / trust withdrawal (`upstream.*` with `shared_signal_with`).
const BACKEND_UNAVAILABLE: &[u8] = br#"{"error":"Backend unavailable"}"#;

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
            decoding: None,
            decoding_detail: None,
            blob_sha256: None,
        },
    }
}

fn diagnose_http(r: &ResponseRecord, body: &[u8], trust: FerrumTrust) -> Diagnosis {
    let status = ProtocolStatus::Http { status: r.status, reason: None };
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
        workload: None,
        gateway_detail: None,
        redact: None,
    })
}

/// The strongest trust Anvil can have in an audited gateway release: a trusted
/// profile over verified TLS. Markers stay spoofable on every audited release
/// (0.9.5, 0.9.7, 0.9.8, 0.9.9, 0.9.10 and 0.9.11), so attribution never exceeds `likely`.
fn trusted_verified(compat: &str) -> FerrumTrust {
    FerrumTrust::Trusted { profile_name: "lab".into(), compatibility_id: compat.into(), channel_authenticated: true }
}

/// Every embedded release catalog.
fn releases() -> Vec<&'static str> {
    anvil_diagnostics::ferrum::compatibility_ids().collect()
}

fn coarse_connection_failure(trust: FerrumTrust) -> Diagnosis {
    let r = response(502, &[("content-type", "application/json"), ("x-gateway-error", "connection_failure")], BACKEND_UNAVAILABLE);
    diagnose_http(&r, BACKEND_UNAVAILABLE, trust)
}

fn codes(d: &Diagnosis) -> Vec<&str> {
    d.findings.iter().map(|f| f.code.as_str()).collect()
}

/// Confirming an unverified header's observation does not attribute it to a
/// gateway. Every other public Ferrum finding remains at most likely.
fn assert_public_ferrum_confidence(d: &Diagnosis) {
    for f in d.findings.iter().filter(|f| f.code.starts_with("ferrum.")) {
        if f.code == "ferrum.marker.unverified" {
            assert_eq!(f.confidence, Confidence::Confirmed);
            assert_eq!(f.scope, SourceScope::Unknown);
        } else {
            assert!(f.confidence <= Confidence::Likely, "{} confidence is {:?}", f.code, f.confidence);
        }
    }
}

/// Every user-visible statement of a finding that asserts something (title and
/// explanation), lowercased. Alternatives and does-not-prove lists are
/// excluded: naming a cause there is the honest "could also be" form.
fn claim_text(f: &DiagnosticFinding) -> String {
    format!("{} {}", f.title, f.explanation).to_lowercase()
}

/// No finding at or above `likely` may state any of `terms` anywhere in its
/// title or explanation.
fn assert_no_claim_at_likely(d: &Diagnosis, terms: &[&str]) {
    for f in d.findings.iter().filter(|f| f.confidence >= Confidence::Likely) {
        let text = claim_text(f);
        for t in terms {
            assert!(!text.contains(t), "{} ({:?}) claims '{t}': {text}", f.code, f.confidence);
        }
    }
}

/// No finding at or above `likely` is *about* one of `terms`: its code or
/// title names it. (The coarse token's explanation legitimately lists "DNS,
/// TCP connect, TLS, connection-pool" as the undistinguished family; listing
/// the family is not a claim that one member happened.)
fn assert_no_specific_cause_at_likely(d: &Diagnosis, terms: &[&str]) {
    for f in d.findings.iter().filter(|f| f.confidence >= Confidence::Likely) {
        let about = format!("{} {}", f.code, f.title).to_lowercase();
        for t in terms {
            assert!(!about.contains(t), "{} ({:?}) is a '{t}' claim: {}", f.code, f.confidence, f.title);
        }
    }
}

/// The ambiguous catalog finding (unknown confidence) and the candidate ids it
/// lists as evidence.
fn ambiguous_candidates(d: &Diagnosis) -> (&DiagnosticFinding, Vec<String>) {
    let f = d.findings.iter().find(|f| f.code == "ferrum.outcome_ambiguous").expect("the shared signal stays ambiguous");
    let ids = f
        .evidence
        .iter()
        .find(|e| e.key == "catalog.candidates")
        .map(|e| e.value.split(", ").map(String::from).collect())
        .unwrap_or_default();
    (f, ids)
}

/// UP-017 — public-signal contract test, NOT a live reproduction and NOT a
/// dial hook: Ferrum Edge 0.9.5 / 0.9.7 / 0.9.8 / 0.9.9 / 0.9.10 / 0.9.11 have no
/// lab dial-admission hook, and draining
/// the host's ephemeral ports would be unsafe. The gateway answers port
/// exhaustion with the same `502 connection_failure {"error":"Backend
/// unavailable"}` as DNS, refused, TLS and pool failures, so Anvil must keep
/// the whole family ambiguous and never name port exhaustion or host
/// resources as the cause.
#[test]
fn up_017_port_exhaustion_signal_is_coarse_and_hook_free() {
    for trust in releases().into_iter().flat_map(|compat| {
        [
            trusted_verified(compat),
            FerrumTrust::Trusted { profile_name: "lab".into(), compatibility_id: compat.into(), channel_authenticated: false },
        ]
    }) {
        let d = coarse_connection_failure(trust);
        // The coarse token keeps its coarse meaning, capped at likely.
        let tok = d.findings.iter().find(|f| f.code == "ferrum.token.connection_failure").expect("coarse token finding");
        assert_eq!(tok.confidence, Confidence::Likely, "spoofable marker caps at likely on every audited release");
        assert_eq!(tok.scope, SourceScope::GatewayToUpstream);
        // No precise cause at likely or above: port exhaustion and host
        // resources are never stated; DNS / TLS / certificate / refused are
        // never the subject of a finding (the token's explanation lists them
        // only as the undistinguished family).
        assert_no_claim_at_likely(&d, &["port exhaustion", "ephemeral", "eaddrnotavail", "host resource", "out of ports", "certificate"]);
        assert_no_specific_cause_at_likely(&d, &["tls", "dns", "refused", "certificate", "port"]);
        assert!(tok.does_not_prove.iter().any(|s| s.contains("That TLS failed")), "{:?}", tok.does_not_prove);
        // Port exhaustion appears only as an unknown-confidence candidate of
        // the ambiguous family, because the catalog lists it there.
        let (amb, ids) = ambiguous_candidates(&d);
        assert_eq!(amb.confidence, Confidence::Unknown);
        assert!(ids.iter().any(|i| i == "upstream.port_exhaustion"), "{ids:?}");
        for sibling in ["upstream.connect.refused", "upstream.tls.handshake_failed_setup_phase", "upstream.connection_limit.pooled"] {
            assert!(ids.iter().any(|i| i == sibling), "{sibling} missing from {ids:?}");
        }
        assert!(!codes(&d).contains(&"ferrum.outcome"), "no single-cause attribution: {:?}", codes(&d));
        // Nothing points at the caller's own leg or certificate.
        assert!(!d.findings.iter().any(|f| f.scope == SourceScope::ClientToPeer || f.scope == SourceScope::LocalClient));
        assert!(!codes(&d).iter().any(|c| c.starts_with("client.") || c.starts_with("local.")), "{:?}", codes(&d));
    }
}

/// UP-017, untrusted destination: the same bytes from a peer that is not a
/// trusted Ferrum profile get no gateway attribution at all.
#[test]
fn up_017_untrusted_destination_gets_no_gateway_family() {
    let d = coarse_connection_failure(FerrumTrust::NotConfigured);
    assert!(!codes(&d).iter().any(|c| c.starts_with("ferrum.token") || c.starts_with("ferrum.outcome")), "{:?}", codes(&d));
    assert!(codes(&d).contains(&"ferrum.marker.unverified"));
    assert_no_claim_at_likely(&d, &["port exhaustion", "ephemeral", "host resource"]);
}

/// UP-019 — public-signal contract test, NOT a live reproduction: trust
/// withdrawal is emitted only by the mesh HBONE / sidecar-mTLS transports
/// (an accepted gateway trust publication withdrew an authority). Its public
/// signal is the shared `connection_failure` family, so Anvil must not say
/// the destination certificate is malformed, expired or untrusted — at
/// confirmed or likely — nor blame the caller's certificate.
#[test]
fn up_019_trust_withdrawn_signal_makes_no_certificate_claim() {
    for compat in releases() {
        let d = coarse_connection_failure(trusted_verified(compat));
        assert_no_claim_at_likely(
            &d,
            &["certificate", "malformed", "expired", "untrusted", "trust withdrawn", "withdrawn", "revoked", "tls handshake", "mtls"],
        );
        assert_no_specific_cause_at_likely(&d, &["tls", "certificate", "trust"]);
        assert!(!d.findings.iter().any(|f| f.confidence == Confidence::Confirmed && f.code.starts_with("ferrum.")));
        let (amb, ids) = ambiguous_candidates(&d);
        assert_eq!(amb.confidence, Confidence::Unknown);
        assert!(ids.iter().any(|i| i == "upstream.trust_withdrawn"), "{compat}: {ids:?}");
        // The token finding keeps "TLS failed" explicitly unproven and never
        // blames the client's own identity.
        let tok = d.findings.iter().find(|f| f.code == "ferrum.token.connection_failure").expect("coarse token finding");
        assert!(tok.does_not_prove.iter().any(|s| s.contains("That TLS failed")), "{:?}", tok.does_not_prove);
        assert!(tok.does_not_prove.iter().any(|s| s.to_lowercase().contains("client certificate")), "{:?}", tok.does_not_prove);
        assert!(!codes(&d).iter().any(|c| c.starts_with("client.tls") || c.starts_with("local.client_identity")), "{:?}", codes(&d));
    }
}

/// UP-018, pooled lanes (direct H2 / gRPC / H3 / mesh pools): the connection
/// ceiling answers `502 connection_failure "Backend unavailable"`, the shared
/// coarse signal. The honest result is the ambiguous family with the
/// connection ceiling as one unknown-confidence candidate, never a
/// backend-down or application claim.
#[test]
fn up_018_pooled_lane_ceiling_stays_in_the_ambiguous_family() {
    for compat in releases() {
        let d = coarse_connection_failure(trusted_verified(compat));
        let (amb, ids) = ambiguous_candidates(&d);
        assert_eq!(amb.confidence, Confidence::Unknown);
        assert!(ids.iter().any(|i| i == "upstream.connection_limit.pooled"), "{compat}: {ids:?}");
        assert_no_claim_at_likely(&d, &["connection limit", "connection ceiling", "maxconnections", "crash", "backend is down"]);
        assert!(!d.findings.iter().any(|f| f.scope == SourceScope::UpstreamApplication && f.confidence >= Confidence::Likely));
    }
}

/// UP-018, retained reqwest lane — the same public signal the historical
/// admission lab observes, still available to ineligible bodies/retries on
/// 0.9.11: a distinct gateway-authored body with the
/// misleading `backend_error` token. Anvil may say "gateway connection
/// ceiling" (at most likely, gateway admission) but not that the backend is
/// down or that the application returned 503.
#[test]
fn up_018_reqwest_lane_ceiling_is_a_gateway_limit_not_a_backend_failure() {
    for compat in releases() {
        up_018_reqwest_lane_for(compat);
    }
}

fn up_018_reqwest_lane_for(compat: &str) {
    let body = br#"{"error":"Backend connection limit exceeded"}"#;
    let r = response(503, &[("content-type", "application/json"), ("x-gateway-error", "backend_error"), ("via", "1.1 ferrum-edge")], body);
    let d = diagnose_http(&r, body, trusted_verified(compat));
    let o = d.findings.iter().find(|f| f.code == "ferrum.outcome").expect("single catalog match");
    assert!(o.evidence.iter().any(|e| e.key == "catalog.outcome" && e.value == "upstream.connection_limit.reqwest"));
    assert_eq!(o.confidence, Confidence::Likely);
    assert_eq!(o.scope, SourceScope::GatewayAdmission);
    let tok = d.findings.iter().find(|f| f.code == "ferrum.token.backend_error").expect("token finding");
    assert!(tok.confidence <= Confidence::Likely);
    assert_ne!(tok.scope, SourceScope::UpstreamApplication, "backend_error does not pin the application");
    assert!(!codes(&d).contains(&"ferrum.backend_passthrough"), "{:?}", codes(&d));
    assert!(!d.findings.iter().any(|f| f.scope == SourceScope::UpstreamApplication && f.confidence >= Confidence::Likely));
    assert_no_claim_at_likely(&d, &["crash", "backend is down", "unhealthy"]);
    // Lookalike: the application's own 503 through the same gateway (stamped
    // backend_error, its own body) is not called a connection ceiling.
    let app = br#"{"error":"service unavailable","source":"application"}"#;
    let r = response(503, &[("content-type", "application/json"), ("x-gateway-error", "backend_error"), ("via", "1.1 ferrum-edge")], app);
    let d = diagnose_http(&r, app, trusted_verified(compat));
    assert!(!d.findings.iter().flat_map(|f| f.evidence.iter()).any(|e| e.value.contains("upstream.connection_limit")), "{:?}", codes(&d));
}

/// 0.9.11's eligible bodyless HTTP/1.1 first attempt uses the direct pool.
/// Its ceiling shares the pooled setup-failure signal; operator-only proof
/// of maxConnections must never turn this public evidence into one cause.
#[test]
fn up_018_direct_h1_ceiling_uses_the_0_9_11_ambiguous_setup_signal() {
    let compat = "ferrum-edge-0.9.11";
    let direct_h1 = |trust| {
        let mut r = response(502, &[("x-gateway-error", "connection_failure"), ("via", "1.1 ferrum-edge")], BACKEND_UNAVAILABLE);
        // The dispatch failure builder has an empty header map; the finalizer
        // adds the marker and Via, but no Content-Type.
        r.body.content_type = None;
        diagnose_http(&r, BACKEND_UNAVAILABLE, trust)
    };
    for channel_authenticated in [true, false] {
        let trust = FerrumTrust::Trusted { profile_name: "lab".into(), compatibility_id: compat.into(), channel_authenticated };
        let d = direct_h1(trust);
        let tok = d.findings.iter().find(|f| f.code == "ferrum.token.connection_failure").expect("direct-H1 coarse token");
        assert_eq!(tok.confidence, Confidence::Likely);
        assert_eq!(tok.scope, SourceScope::GatewayToUpstream);
        let (amb, ids) = ambiguous_candidates(&d);
        assert_eq!(amb.confidence, Confidence::Unknown);
        assert_eq!(amb.scope, SourceScope::Unknown);
        assert!(ids.iter().any(|id| id == "upstream.connection_limit.pooled"), "{ids:?}");
        assert!(!ids.iter().any(|id| id == "upstream.connection_limit.reqwest"), "{ids:?}");
        assert!(amb.alternatives.iter().any(|s| s.contains("identical")));
        assert!(!codes(&d).contains(&"ferrum.outcome"));
        assert!(!codes(&d).contains(&"ferrum.token.backend_error"));
        assert!(!codes(&d).contains(&"ferrum.backend_passthrough"));
        assert!(d.findings.iter().all(|f| { !f.code.starts_with("ferrum.") || f.confidence <= Confidence::Likely }));
        assert!(!d.findings.iter().any(|f| {
            matches!(f.scope, SourceScope::UpstreamApplication | SourceScope::ClientToPeer) && f.confidence >= Confidence::Likely
        }));
        assert_no_claim_at_likely(&d, &["connection ceiling", "maxconnections", "crash", "unhealthy", "backend is down", "overload"]);
        assert_no_specific_cause_at_likely(&d, &["dns", "tls", "refused", "connection_limit"]);
    }

    let d = direct_h1(FerrumTrust::NotConfigured);
    assert!(codes(&d).contains(&"ferrum.marker.unverified"));
    assert_public_ferrum_confidence(&d);
    assert!(!codes(&d).iter().any(|c| c.starts_with("ferrum.token") || c.starts_with("ferrum.outcome")));

    // A backend's own 502, even with the exact ceiling body, gets backend_error
    // from the finalizer and must not match the connection_failure family.
    let app = br#"{"error":"service unavailable","source":"application"}"#;
    for body in [app.as_slice(), BACKEND_UNAVAILABLE] {
        let r =
            response(502, &[("content-type", "application/json"), ("x-gateway-error", "backend_error"), ("via", "1.1 ferrum-edge")], body);
        for (trust, trusted) in [(trusted_verified(compat), true), (FerrumTrust::NotConfigured, false)] {
            let d = diagnose_http(&r, body, trust);
            assert!(!codes(&d).contains(&"ferrum.token.connection_failure"));
            assert!(!d.findings.iter().flat_map(|f| f.evidence.iter()).any(|e| { e.value.contains("upstream.connection_limit") }));
            assert_public_ferrum_confidence(&d);
            if !trusted {
                assert!(codes(&d).contains(&"ferrum.marker.unverified"));
                assert!(!codes(&d).iter().any(|c| c.starts_with("ferrum.token") || c.starts_with("ferrum.outcome")));
            }
        }
    }
}
