//! AUTH-017: a destination behind an OIDC relying party answers a request
//! without a session with a redirect into the identity provider's login
//! (browser branch) or an OIDC-realm bearer challenge (API branch). The shapes
//! below are the public evidence the auth lab observed from Ferrum Edge
//! 0.9.5's `oidc_relying_party`; the lookalikes must not get the finding.

use anvil_diagnostics::{Diagnosis, DiagnosticInput, FerrumTrust, diagnose};
use anvil_domain::diagnostics::{Confidence, SourceScope};
use anvil_domain::execution::{
    AttemptObservation, AttemptReason, BodyCapture, BodyCompleteness, ByteCounts, DispatchState, HeaderEntry, ResponseRecord,
};
use anvil_domain::outcome::ProtocolStatus;
use anvil_domain::request::Protocol;

const CODE: &str = "auth.browser_session_required";
const AUTHORIZE: &str = "http://127.0.0.1:19102/authorize?response_type=code&client_id=anvil-lab-oidc-rp&redirect_uri=http%3A%2F%2F127.0.0.1%3A18180%2Foauth%2Fcallback&scope=openid&state=s1&nonce=n1&code_challenge=c1&code_challenge_method=S256";

fn attempt(index: u32, reason: AttemptReason, url: &str, status: u16) -> AttemptObservation {
    AttemptObservation {
        early_data: None,
        index,
        reason,
        method: "GET".into(),
        url: url.into(),
        started_at: chrono::Utc::now(),
        connection: None,
        phases: vec![],
        dispatch: DispatchState::Sent,
        bytes: ByteCounts::default(),
        response_status: Some(status),
        failure: None,
        duration_us: 1,
    }
}

fn response(status: u16, headers: &[(&str, &str)], ct: &str, body: &[u8]) -> ResponseRecord {
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
            content_type: Some(ct.into()),
            content_encoding: None,
            decoded_bytes: None,
            blob_sha256: None,
        },
    }
}

fn run(attempts: &[AttemptObservation], r: &ResponseRecord, body: &[u8], trusted: bool) -> Diagnosis {
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
        attempts,
        response: Some(r),
        body,
        stream: None,
        protocol_status: &status,
        trust: &trust,
        tls_verification_enabled: true,
        credentials_stripped_on_redirect: true,
        protocol_fallback_from: None,
    })
}

fn codes(d: &Diagnosis) -> Vec<&str> {
    d.findings.iter().map(|f| f.code.as_str()).collect()
}

/// Browser branch, redirect followed: the final 200 is the IdP's login page.
#[test]
fn auth_017_followed_login_redirect_is_not_an_api_success() {
    let attempts = vec![
        attempt(0, AttemptReason::Initial, "http://127.0.0.1:18180/auth/oidc/echo", 302),
        attempt(1, AttemptReason::Redirect { status: 302 }, AUTHORIZE, 200),
    ];
    let page = b"<html><body><form method=post>Sign in</form></body></html>";
    let r = response(200, &[("content-type", "text/html")], "text/html", page);
    for trusted in [true, false] {
        let d = run(&attempts, &r, page, trusted);
        assert!(d.stopped_at_login, "the API was never evaluated");
        let f = d.findings.iter().find(|f| f.code == CODE).expect("login finding");
        assert_eq!(f.confidence, Confidence::Likely);
        assert_eq!(f.scope, SourceScope::Unknown);
        assert!(f.explanation.contains("127.0.0.1:19102/authorize"), "{}", f.explanation);
        assert!(f.explanation.contains("does not read or import browser cookies"), "{}", f.explanation);
        assert!(!f.explanation.contains('{'), "placeholders filled: {}", f.explanation);
        assert!(f.remediation.iter().any(|r| r.text.contains("explicitly")), "supported path is explicit");
        assert!(
            !f.remediation.iter().any(|r| r.text.to_lowercase().contains("import") && !r.text.contains("never")),
            "never suggests importing browser cookies automatically"
        );
        assert!(f.does_not_prove.iter().any(|x| x.contains("authenticated")));
    }
}

/// Browser branch, redirect not followed: the 302 Location is the evidence.
#[test]
fn auth_017_unfollowed_login_redirect_uses_the_location_header() {
    let attempts = vec![attempt(0, AttemptReason::Initial, "http://127.0.0.1:18180/auth/oidc/echo", 302)];
    let r = response(302, &[("location", AUTHORIZE), ("cache-control", "no-store")], "text/plain", b"");
    let d = run(&attempts, &r, b"", true);
    assert!(d.stopped_at_login);
    assert!(codes(&d).contains(&CODE), "{:?}", codes(&d));
}

/// API branch: 401 with the OIDC-realm bearer challenge.
#[test]
fn auth_017_oidc_realm_challenge_explains_the_browser_session() {
    let body = br#"{"error":"Authentication required"}"#;
    let attempts = vec![attempt(0, AttemptReason::Initial, "http://127.0.0.1:18180/auth/oidc/echo", 401)];
    let r = response(401, &[("www-authenticate", r#"Bearer realm="oidc", error="invalid_token""#)], "application/json", body);
    let d = run(&attempts, &r, body, true);
    let f = d.findings.iter().find(|f| f.code == CODE).expect("login finding");
    assert_eq!(f.confidence, Confidence::Likely);
    assert!(codes(&d).contains(&"http.unauthorized"));
    assert!(!d.stopped_at_login, "a 401 is already an application failure; no override needed");
}

/// Lookalikes: an ordinary redirect, a redirect to a URL that merely mentions
/// `client_id`, a plain bearer challenge, and a request the user sent
/// directly to an authorization endpoint (no redirect) keep their generic
/// meaning.
#[test]
fn auth_017_lookalikes_do_not_get_the_login_finding() {
    let ok = response(200, &[("content-type", "application/json")], "application/json", b"{}");
    let plain_redirect = vec![
        attempt(0, AttemptReason::Initial, "http://127.0.0.1:18180/auth/open/redirect?to=/ok/echo", 302),
        attempt(1, AttemptReason::Redirect { status: 302 }, "http://127.0.0.1:18180/ok/echo?client_id=abc", 200),
    ];
    let d = run(&plain_redirect, &ok, b"{}", true);
    assert!(!codes(&d).contains(&CODE) && !d.stopped_at_login, "{:?}", codes(&d));

    let direct = vec![attempt(0, AttemptReason::Initial, AUTHORIZE, 200)];
    let d = run(&direct, &ok, b"{}", true);
    assert!(!codes(&d).contains(&CODE) && !d.stopped_at_login, "a deliberate request to the IdP is not a login redirect");

    let body = br#"{"error":"invalid token"}"#;
    let plain = response(401, &[("www-authenticate", "Bearer")], "application/json", body);
    let d = run(&[attempt(0, AttemptReason::Initial, "http://127.0.0.1:18180/auth/open/status/401", 401)], &plain, body, true);
    assert!(!codes(&d).contains(&CODE), "{:?}", codes(&d));
}
