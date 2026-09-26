//! TLS 1.3 / QUIC 0-RTT early data end to end through the engine, against
//! real local fixtures (`anvil_fixtures::early_data`) whose ground truth says
//! whether each request really arrived in early data. Ground truth is only
//! compared with Anvil's conclusions, never fed to the diagnostic engine.

use anvil_domain::diagnostics::{Confidence, DiagnosticFinding, SourceScope};
use anvil_domain::execution::*;
use anvil_domain::request::*;
use anvil_domain::settings::{EarlyDataPolicy, HttpVersionPolicy, SettingsOverrides, TimeoutOverrides};
use anvil_domain::tls::{TlsMinVersion, TlsProfile};
use anvil_domain::{Id, auth::AuthConfig};
use anvil_engine::{Engine, ExecutionContext, ExecutionOutput};
use anvil_fixtures::early_data::{self, EarlyMode};
use anvil_fixtures::{LabPki, TlsServerOptions};
use anvil_transport::recorder::EventCtx;
use std::sync::OnceLock;
use tokio_util::sync::CancellationToken;

fn init() {
    anvil_transport::init();
    anvil_fixtures::init();
}

fn pki() -> &'static LabPki {
    static P: OnceLock<LabPki> = OnceLock::new();
    P.get_or_init(LabPki::generate)
}

fn server_tls() -> TlsServerOptions {
    TlsServerOptions::new(pki().server.chain_with(&pki().ca), pki().server.key.clone())
}

fn profile(name: &str) -> TlsProfile {
    TlsProfile {
        id: Id::new(),
        workspace_id: Id::new(),
        name: name.into(),
        verify: true,
        use_system_roots: false,
        extra_roots_pem: vec![pki().ca.cert.clone()],
        client_identity: None,
        bindings: vec![],
        min_version: TlsMinVersion::Tls12,
        server_name_override: None,
        server_spiffe: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

fn policy(extra: &[&str]) -> EarlyDataPolicy {
    EarlyDataPolicy { enabled: true, extra_methods: extra.iter().map(|s| s.to_string()).collect() }
}

/// A request through `tls` with the given early-data policy, forced
/// `version`, and connection reuse off (0-RTT needs a new connection).
fn ctx(method: &str, url: &str, tls: &TlsProfile, early: Option<EarlyDataPolicy>, version: HttpVersionPolicy) -> ExecutionContext {
    let mut s = RequestSpec::http(method, url);
    s.auth = AuthConfig::None;
    if matches!(method, "PUT" | "POST") {
        s.body = Body::Json { text: r#"{"n":1}"#.into() };
    }
    let mut c = ExecutionContext::standalone(s);
    c.isolation = "ws-early".into();
    c.tls_profiles.push(tls.clone());
    c.settings_layers.push((
        "run".into(),
        SettingsOverrides {
            tls_profile_id: Some(tls.id),
            http_version: Some(version),
            keepalive: Some(false),
            early_data: early,
            timeouts: Some(TimeoutOverrides {
                connect_ms: Some(Some(3_000)),
                tls_handshake_ms: Some(Some(3_000)),
                response_headers_ms: Some(Some(5_000)),
                total_ms: Some(Some(15_000)),
                ..Default::default()
            }),
            ..Default::default()
        },
    ));
    c
}

async fn run(e: &Engine, c: &ExecutionContext) -> ExecutionOutput {
    e.execute(c, EventCtx::none(), CancellationToken::new()).await
}

fn codes(o: &ExecutionOutput) -> Vec<String> {
    o.record.findings.iter().map(|f| f.code.clone()).collect()
}

fn finding<'a>(o: &'a ExecutionOutput, code: &str) -> &'a DiagnosticFinding {
    o.record.findings.iter().find(|f| f.code == code).unwrap_or_else(|| panic!("missing {code}; have {:?}", codes(o)))
}

fn early(o: &ExecutionOutput, attempt: usize) -> EarlyDataObservation {
    o.record.attempts[attempt]
        .early_data
        .clone()
        .unwrap_or_else(|| panic!("attempt {attempt} has no early-data evidence: {:?}", o.record.attempts[attempt]))
}

fn status(o: &ExecutionOutput) -> Option<u16> {
    o.record.response.as_ref().map(|r| r.status)
}

// ------------------------------------------------------------- HTTP/3 ---

#[tokio::test]
async fn h3_second_get_is_sent_as_0rtt_and_accepted() {
    init();
    let fx = early_data::serve_h3("127.0.0.1:0", server_tls(), EarlyMode::Accept).await.expect("fixture");
    let e = Engine::new();
    let tls = profile("lab");
    let url = fx.url("/echo");

    let first = run(&e, &ctx("GET", &url, &tls, Some(policy(&[])), HttpVersionPolicy::Http3Only)).await;
    assert_eq!(status(&first), Some(200), "{:?}", first.record.outcome);
    let ed = early(&first, 0);
    assert_eq!(ed.transport, EarlyDataTransport::Quic);
    assert!(!ed.offered && !ed.resumption_attempted);
    assert_eq!(ed.not_used, Some(EarlyDataNotUsed::NoTicket));
    assert!(ed.tickets_received >= 1, "the fixture issues tickets: {ed:?}");
    assert_eq!(ed.ticket_max_early_data, Some(u32::MAX));
    assert!(e.session_tickets_held() >= 1);
    assert!(!codes(&first).iter().any(|c| c.starts_with("early_data.") || c == "request.too_early"), "{:?}", codes(&first));

    let second = run(&e, &ctx("GET", &url, &tls, Some(policy(&[])), HttpVersionPolicy::Http3Only)).await;
    assert_eq!(status(&second), Some(200));
    assert_eq!(second.record.attempts.len(), 1);
    let ed = early(&second, 0);
    assert!(ed.resumption_attempted && ed.offered, "{ed:?}");
    assert_eq!(ed.resumption_accepted, Some(true));
    assert_eq!(ed.accepted, Some(true));
    assert!(ed.bytes > 0 && ed.bytes_estimated);
    assert!(!ed.resent_after_handshake);
    let a = &second.record.attempts[0];
    let tls_obs = a.connection.as_ref().and_then(|c| c.tls.as_ref()).expect("tls evidence");
    assert_eq!(tls_obs.resumed, Some(true));
    assert_eq!(tls_obs.verification, TlsVerification::Verified, "a ticket of a verifying profile comes from a verified handshake");
    assert!(!tls_obs.peer_certificates.is_empty(), "the chain stored with the ticket is shown");
    assert!(a.phase(Phase::QuicHandshake).and_then(|p| p.detail.clone()).unwrap_or_default().contains("0-RTT early data accepted"));
    let f = finding(&second, "early_data.accepted");
    assert_eq!(f.confidence, Confidence::Confirmed);
    assert_eq!(f.scope, SourceScope::ClientToPeer);
    assert!(f.does_not_prove.iter().any(|d| d.to_lowercase().contains("replay")), "{:?}", f.does_not_prove);
    // Fixture ground truth: the second request (only) arrived in 0-RTT.
    let seen = fx.requests();
    assert_eq!(seen.iter().map(|r| r.0).collect::<Vec<_>>(), vec![false, true], "{seen:?}");
}

#[tokio::test]
async fn h3_rejected_early_data_is_resent_after_the_handshake_by_the_transport() {
    init();
    let fx = early_data::serve_h3("127.0.0.1:0", server_tls(), EarlyMode::Accept).await.expect("fixture");
    let e = Engine::new();
    let tls = profile("lab");
    let url = fx.url("/echo");
    run(&e, &ctx("GET", &url, &tls, Some(policy(&[])), HttpVersionPolicy::Http3Only)).await;
    fx.set_mode(EarlyMode::Reject).expect("mode");

    let o = run(&e, &ctx("GET", &url, &tls, Some(policy(&[])), HttpVersionPolicy::Http3Only)).await;
    assert_eq!(status(&o), Some(200), "{:?}", o.record.outcome);
    assert_eq!(o.record.attempts.len(), 1, "a rejected 0-RTT write is not an application retry");
    let ed = early(&o, 0);
    assert!(ed.offered);
    assert_eq!(ed.accepted, Some(false));
    assert!(ed.resent_after_handshake);
    assert_eq!(ed.resumption_accepted, Some(true), "the session resumed; only the early data was refused");
    let writes: Vec<&PhaseTiming> = o.record.attempts[0].phases.iter().filter(|p| p.phase == Phase::RequestWrite).collect();
    assert_eq!(writes.len(), 2, "{writes:?}");
    assert!(writes[1].detail.as_deref().unwrap_or_default().contains("re-sent after the handshake"));
    let f = finding(&o, "early_data.rejected");
    assert_eq!(f.confidence, Confidence::Confirmed);
    assert!(f.explanation.contains("not an application retry"), "{}", f.explanation);
    // The server never saw the rejected early data: one request, after the handshake.
    let seen = fx.requests();
    assert_eq!(seen.last().map(|r| r.0), Some(false));
    assert_eq!(seen.len(), 2, "{seen:?}");
}

#[tokio::test]
async fn h3_425_is_retried_once_after_the_handshake_on_the_same_connection() {
    init();
    let fx = early_data::serve_h3("127.0.0.1:0", server_tls(), EarlyMode::TooEarly { allowed: vec!["GET".into()] }).await.expect("fixture");
    let e = Engine::new();
    let tls = profile("lab");
    let url = fx.url("/echo");
    run(&e, &ctx("GET", &url, &tls, Some(policy(&["PUT"])), HttpVersionPolicy::Http3Only)).await;

    let o = run(&e, &ctx("PUT", &url, &tls, Some(policy(&["PUT"])), HttpVersionPolicy::Http3Only)).await;
    assert_eq!(status(&o), Some(200), "{:?}", o.record.outcome);
    assert_eq!(o.record.attempts.len(), 2);
    assert_eq!(o.record.attempts[0].response_status, Some(425));
    assert_eq!(o.record.attempts[1].reason, AttemptReason::TooEarlyRetry);
    let first = early(&o, 0);
    assert!(first.offered && first.accepted == Some(true), "{first:?}");
    let retry = early(&o, 1);
    assert!(!retry.offered);
    assert_eq!(retry.not_used, Some(EarlyDataNotUsed::RetryAfterTooEarly));
    let conn = |i: usize| o.record.attempts[i].connection.as_ref().expect("connection").clone();
    assert_eq!(conn(0).id, conn(1).id, "the retry uses the connection that answered 425");
    assert!(conn(1).reused);
    let f = finding(&o, "request.too_early");
    assert_eq!(f.confidence, Confidence::Confirmed);
    assert!(f.explanation.contains("HTTP 200"), "{}", f.explanation);
    assert!(finding(&o, "early_data.accepted").confidence == Confidence::Confirmed);
    // Ground truth: the early PUT was refused, the retry arrived after the handshake.
    let seen = fx.requests();
    assert_eq!(seen[1..].to_vec(), vec![(true, "PUT".to_string(), 425), (false, "PUT".to_string(), 200)], "{seen:?}");
}

#[tokio::test]
async fn h3_425_without_early_data_is_retried_once_and_never_again() {
    init();
    // A lookalike: the server answers 425 to everything, including a request
    // Anvil did not send as early data (no ticket yet).
    let fx = early_data::serve_h3("127.0.0.1:0", server_tls(), EarlyMode::AlwaysTooEarly).await.expect("fixture");
    let e = Engine::new();
    let tls = profile("lab");
    let o = run(&e, &ctx("GET", &fx.url("/echo"), &tls, Some(policy(&[])), HttpVersionPolicy::Http3Only)).await;
    assert_eq!(o.record.attempts.len(), 2, "exactly one retry");
    assert_eq!(o.record.attempts.iter().map(|a| a.response_status).collect::<Vec<_>>(), vec![Some(425), Some(425)]);
    assert_eq!(early(&o, 0).not_used, Some(EarlyDataNotUsed::NoTicket));
    let f = finding(&o, "request.too_early");
    assert!(f.explanation.contains("did not send this request as early data"), "{}", f.explanation);
    assert!(f.does_not_prove.iter().any(|d| d.contains("early data")), "{:?}", f.does_not_prove);
    assert_eq!(f.severity, anvil_domain::diagnostics::Severity::Warning);
    assert!(fx.requests().iter().all(|r| !r.0), "{:?}", fx.requests());
    // Without the opt-in a 425 is not retried at all.
    let o = run(&e, &ctx("GET", &fx.url("/echo"), &tls, None, HttpVersionPolicy::Http3Only)).await;
    assert_eq!(o.record.attempts.len(), 1);
    assert!(finding(&o, "request.too_early").explanation.contains("not retried"), "{}", finding(&o, "request.too_early").explanation);
}

#[tokio::test]
async fn h3_ineligible_method_is_sent_after_the_handshake_with_the_reason_recorded() {
    init();
    let fx = early_data::serve_h3("127.0.0.1:0", server_tls(), EarlyMode::Accept).await.expect("fixture");
    let e = Engine::new();
    let tls = profile("lab");
    let url = fx.url("/echo");
    run(&e, &ctx("GET", &url, &tls, Some(policy(&[])), HttpVersionPolicy::Http3Only)).await;
    let o = run(&e, &ctx("POST", &url, &tls, Some(policy(&[])), HttpVersionPolicy::Http3Only)).await;
    assert_eq!(status(&o), Some(200));
    let ed = early(&o, 0);
    assert!(!ed.method_eligible && !ed.offered);
    assert_eq!(ed.not_used, Some(EarlyDataNotUsed::MethodNotEligible));
    assert!(ed.resumption_attempted, "resumption without early data is safe for any method");
    assert_eq!(fx.requests().last().map(|r| r.0), Some(false), "the POST did not arrive in early data");
    assert!(!codes(&o).iter().any(|c| c.starts_with("early_data.accepted")));
}

#[tokio::test]
async fn a_non_idempotent_method_in_the_policy_is_refused_before_traffic() {
    init();
    let fx = early_data::serve_h3("127.0.0.1:0", server_tls(), EarlyMode::Accept).await.expect("fixture");
    let e = Engine::new();
    let tls = profile("lab");
    let o = run(&e, &ctx("GET", &fx.url("/echo"), &tls, Some(policy(&["POST"])), HttpVersionPolicy::Http3Only)).await;
    assert!(o.record.response.is_none());
    let f = o.record.attempts.last().and_then(|a| a.failure.clone()).expect("failure");
    assert_eq!(f.kind, FailureKind::UnsupportedCombination);
    assert_eq!(f.phase, Phase::Prepare);
    assert_eq!(f.field.as_deref(), Some("settings.early_data.extra_methods"));
    assert_eq!(o.record.outcome.dispatch, DispatchState::NotDispatched);
    assert!(fx.requests().is_empty() && !fx.log.saw_connection());
}

#[tokio::test]
async fn h3_tickets_without_early_data_mean_resumption_only() {
    init();
    let fx = early_data::serve_h3("127.0.0.1:0", server_tls(), EarlyMode::Disabled).await.expect("fixture");
    let e = Engine::new();
    let tls = profile("lab");
    let url = fx.url("/echo");
    let first = run(&e, &ctx("GET", &url, &tls, Some(policy(&[])), HttpVersionPolicy::Http3Only)).await;
    assert_eq!(early(&first, 0).ticket_max_early_data, Some(0));
    let o = run(&e, &ctx("GET", &url, &tls, Some(policy(&[])), HttpVersionPolicy::Http3Only)).await;
    assert_eq!(status(&o), Some(200));
    let ed = early(&o, 0);
    assert!(ed.resumption_attempted && !ed.offered);
    assert_eq!(ed.resumption_accepted, Some(true));
    assert_eq!(ed.not_used, Some(EarlyDataNotUsed::TicketWithoutEarlyData));
    assert_eq!(finding(&o, "early_data.ticket_without_early_data").confidence, Confidence::Confirmed);
    assert!(fx.requests().iter().all(|r| !r.0));
}

#[tokio::test]
async fn h3_server_without_tickets_is_reported_and_nothing_is_sent_early() {
    init();
    let fx = early_data::serve_h3("127.0.0.1:0", server_tls(), EarlyMode::NoTickets).await.expect("fixture");
    let e = Engine::new();
    let tls = profile("lab");
    let url = fx.url("/echo");
    for _ in 0..2 {
        let o = run(&e, &ctx("GET", &url, &tls, Some(policy(&[])), HttpVersionPolicy::Http3Only)).await;
        assert_eq!(status(&o), Some(200));
        let ed = early(&o, 0);
        assert_eq!(ed.not_used, Some(EarlyDataNotUsed::NoTicket));
        assert_eq!(ed.tickets_received, 0);
        let f = finding(&o, "early_data.no_ticket");
        assert_eq!(f.severity, anvil_domain::diagnostics::Severity::Info);
    }
    assert_eq!(e.session_tickets_held(), 0);
}

#[tokio::test]
async fn h3_ticket_cache_is_cleared_on_lock_and_never_shared_across_profiles_or_workspaces() {
    init();
    let fx = early_data::serve_h3("127.0.0.1:0", server_tls(), EarlyMode::Accept).await.expect("fixture");
    let e = Engine::new();
    let tls = profile("lab");
    let url = fx.url("/echo");
    run(&e, &ctx("GET", &url, &tls, Some(policy(&[])), HttpVersionPolicy::Http3Only)).await;
    assert!(e.session_tickets_held() >= 1);

    // Another TLS profile with identical settings gets no ticket.
    let other = profile("lab copy");
    let o = run(&e, &ctx("GET", &url, &other, Some(policy(&[])), HttpVersionPolicy::Http3Only)).await;
    assert_eq!(early(&o, 0).not_used, Some(EarlyDataNotUsed::NoTicket), "tickets never cross TLS profiles");
    // Another workspace gets no ticket either.
    let mut c = ctx("GET", &url, &tls, Some(policy(&[])), HttpVersionPolicy::Http3Only);
    c.isolation = "ws-other".into();
    let o = run(&e, &c).await;
    assert_eq!(early(&o, 0).not_used, Some(EarlyDataNotUsed::NoTicket), "tickets never cross workspaces");

    // The vault lock clears every ticket: the next request is a full handshake.
    e.clear_sensitive_state();
    assert_eq!(e.session_tickets_held(), 0);
    let o = run(&e, &ctx("GET", &url, &tls, Some(policy(&[])), HttpVersionPolicy::Http3Only)).await;
    let ed = early(&o, 0);
    assert_eq!(ed.not_used, Some(EarlyDataNotUsed::NoTicket));
    assert!(!ed.resumption_attempted);
    assert!(fx.requests().iter().all(|r| !r.0), "nothing was sent early");
}

#[tokio::test]
async fn h3_early_data_is_off_by_default() {
    init();
    let fx = early_data::serve_h3("127.0.0.1:0", server_tls(), EarlyMode::Accept).await.expect("fixture");
    let e = Engine::new();
    let tls = profile("lab");
    let url = fx.url("/echo");
    for _ in 0..2 {
        let o = run(&e, &ctx("GET", &url, &tls, None, HttpVersionPolicy::Http3Only)).await;
        assert_eq!(status(&o), Some(200));
        assert!(o.record.attempts[0].early_data.is_none(), "no early-data evidence without the opt-in");
    }
    assert_eq!(e.session_tickets_held(), 0, "no ticket cache without the opt-in");
    assert!(fx.requests().iter().all(|r| !r.0));
}

// ---------------------------------------------------- TLS 1.3 over TCP ---

async fn tls_pair(version: HttpVersionPolicy, mode: EarlyMode) -> (early_data::EarlyTlsFixture, Engine, TlsProfile, String) {
    init();
    let fx = early_data::serve_tls("127.0.0.1:0", server_tls(), mode).await.expect("fixture");
    let e = Engine::new();
    let tls = profile("lab");
    let url = fx.url("/echo");
    let first = run(&e, &ctx("GET", &url, &tls, Some(policy(&["PUT"])), version)).await;
    assert_eq!(status(&first), Some(200), "{:?}", first.record.outcome);
    let ed = early(&first, 0);
    assert_eq!(ed.transport, EarlyDataTransport::Tls);
    assert!(!ed.offered && !ed.resumption_attempted, "{ed:?}");
    assert!(ed.tickets_received >= 1, "{ed:?}");
    (fx, e, tls, url)
}

#[tokio::test]
async fn tls_http1_second_get_is_sent_as_early_data_and_accepted() {
    let (fx, e, tls, url) = tls_pair(HttpVersionPolicy::Http1Only, EarlyMode::Accept).await;
    let o = run(&e, &ctx("GET", &url, &tls, Some(policy(&[])), HttpVersionPolicy::Http1Only)).await;
    assert_eq!(status(&o), Some(200), "{:?}", o.record.outcome);
    let ed = early(&o, 0);
    assert!(ed.offered && ed.resumption_attempted, "{ed:?}");
    assert_eq!(ed.accepted, Some(true));
    assert_eq!(ed.resumption_accepted, Some(true));
    assert!(ed.bytes > 0 && !ed.bytes_estimated, "exact TLS plaintext bytes: {ed:?}");
    let a = &o.record.attempts[0];
    let t = a.connection.as_ref().and_then(|c| c.tls.as_ref()).expect("tls");
    assert_eq!(t.resumed, Some(true));
    assert_eq!(t.alpn_negotiated.as_deref(), Some("http/1.1"));
    assert_eq!(t.verification, TlsVerification::Verified);
    let hs = a.phase(Phase::TlsHandshake).expect("tls phase");
    assert_eq!(hs.status, PhaseStatus::Completed);
    assert!(hs.detail.as_deref().unwrap_or_default().contains("early data accepted"), "{hs:?}");
    assert!(hs.end_us.is_some());
    assert_eq!(finding(&o, "early_data.accepted").confidence, Confidence::Confirmed);
    assert_eq!(fx.requests().iter().map(|r| r.0).collect::<Vec<_>>(), vec![false, true], "{:?}", fx.requests());
}

#[tokio::test]
async fn tls_http2_second_get_is_sent_as_early_data_and_accepted() {
    let (fx, e, tls, url) = tls_pair(HttpVersionPolicy::Http2Only, EarlyMode::Accept).await;
    let o = run(&e, &ctx("GET", &url, &tls, Some(policy(&[])), HttpVersionPolicy::Http2Only)).await;
    assert_eq!(status(&o), Some(200), "{:?}", o.record.outcome);
    let ed = early(&o, 0);
    assert!(ed.offered && ed.accepted == Some(true), "{ed:?}");
    assert_eq!(o.record.response.as_ref().map(|r| r.http_version.clone()).as_deref(), Some("HTTP/2"));
    // The HEADERS frame itself, not only the preface, arrived in early data.
    assert_eq!(fx.requests().iter().map(|r| r.0).collect::<Vec<_>>(), vec![false, true], "{:?}", fx.requests());
}

#[tokio::test]
async fn tls_rejected_early_data_is_resent_by_tls_after_the_handshake() {
    let (fx, e, tls, url) = tls_pair(HttpVersionPolicy::Http1Only, EarlyMode::Accept).await;
    fx.set_mode(EarlyMode::Reject);
    let o = run(&e, &ctx("GET", &url, &tls, Some(policy(&[])), HttpVersionPolicy::Http1Only)).await;
    assert_eq!(status(&o), Some(200), "{:?}", o.record.outcome);
    assert_eq!(o.record.attempts.len(), 1);
    let ed = early(&o, 0);
    assert!(ed.offered && ed.bytes > 0, "{ed:?}");
    assert_eq!(ed.accepted, Some(false));
    assert!(ed.resent_after_handshake);
    assert_eq!(finding(&o, "early_data.rejected").confidence, Confidence::Confirmed);
    assert_eq!(fx.requests().last().map(|r| r.0), Some(false), "the server never saw the rejected copy");
    assert_eq!(fx.requests().len(), 2);
}

#[tokio::test]
async fn tls_425_is_retried_once_on_the_same_connection() {
    let (fx, e, tls, url) = tls_pair(HttpVersionPolicy::Http1Only, EarlyMode::TooEarly { allowed: vec!["GET".into()] }).await;
    let o = run(&e, &ctx("PUT", &url, &tls, Some(policy(&["PUT"])), HttpVersionPolicy::Http1Only)).await;
    assert_eq!(status(&o), Some(200), "{:?}", o.record.outcome);
    assert_eq!(o.record.attempts.len(), 2);
    assert_eq!(o.record.attempts[0].response_status, Some(425));
    assert_eq!(o.record.attempts[1].reason, AttemptReason::TooEarlyRetry);
    let conn = |i: usize| o.record.attempts[i].connection.as_ref().expect("connection").clone();
    assert_eq!(conn(0).id, conn(1).id);
    assert_eq!(early(&o, 1).not_used, Some(EarlyDataNotUsed::RetryAfterTooEarly));
    assert!(finding(&o, "request.too_early").explanation.contains("HTTP 200"));
    let seen = fx.requests();
    assert_eq!(seen[1..].to_vec(), vec![(true, "PUT".to_string(), 425), (false, "PUT".to_string(), 200)], "{seen:?}");
}

#[tokio::test]
async fn tls_with_two_offered_protocols_resumes_without_early_data() {
    let (fx, e, tls, url) = tls_pair(HttpVersionPolicy::Auto, EarlyMode::Accept).await;
    let o = run(&e, &ctx("GET", &url, &tls, Some(policy(&[])), HttpVersionPolicy::Auto)).await;
    assert_eq!(status(&o), Some(200));
    let ed = early(&o, 0);
    assert!(!ed.offered);
    assert_eq!(ed.not_used, Some(EarlyDataNotUsed::AlpnNotFixed));
    assert!(ed.resumption_attempted);
    assert_eq!(ed.resumption_accepted, Some(true));
    assert!(fx.requests().iter().all(|r| !r.0));
}
