//! SPIFFE Workload API through the engine: X.509-SVID client identities for
//! TLS profiles and JWT-SVID auth, against the independent Workload API
//! fixture (`anvil_fixtures::workload_api`, a real Unix socket) and the
//! HTTP(S) fixture. Fixture logs are ground truth only (what the Workload
//! API and the destination actually saw); they never feed the engine.
#![cfg(unix)]

use anvil_domain::Id;
use anvil_domain::auth::AuthConfig;
use anvil_domain::diagnostics::{Confidence, Severity, SourceScope};
use anvil_domain::execution::*;
use anvil_domain::outcome::{ApplicationState, ProtocolStatus};
use anvil_domain::request::*;
use anvil_domain::secret::SensitiveValue;
use anvil_domain::settings::{SettingsOverrides, TimeoutOverrides};
use anvil_domain::tls::{ClientIdentity, ServerSpiffeIdentity, TlsProfile};
use anvil_domain::workload::*;
use anvil_engine::{Engine, ExecutionContext, ExecutionOutput};
use anvil_fixtures::http as fx;
use anvil_fixtures::workload_api::{self as wl, Mode};
use anvil_fixtures::{ClientAuth, GroundTruth, TlsServerOptions};
use anvil_transport::recorder::EventCtx;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;
use tokio_util::sync::CancellationToken;

const GW_AUD: &str = "spiffe://anvil.test/gateway";

fn init() {
    anvil_transport::init();
    anvil_fixtures::init();
}

fn sock(tag: &str) -> PathBuf {
    static N: AtomicU32 = AtomicU32::new(0);
    std::env::temp_dir().join(format!("anvil-ewl-{}-{}-{tag}.sock", std::process::id(), N.fetch_add(1, Ordering::Relaxed)))
}

async fn run(e: &Engine, c: &ExecutionContext) -> ExecutionOutput {
    e.execute(c, EventCtx::none(), CancellationToken::new()).await
}

fn codes(o: &ExecutionOutput) -> Vec<String> {
    o.record.findings.iter().map(|f| f.code.clone()).collect()
}

fn finding<'a>(o: &'a ExecutionOutput, code: &str) -> &'a anvil_domain::diagnostics::DiagnosticFinding {
    o.record.findings.iter().find(|f| f.code == code).unwrap_or_else(|| panic!("{code} missing; findings: {:?}", codes(o)))
}

fn evidence(o: &ExecutionOutput) -> &WorkloadApiEvidence {
    o.record.prepared.workload_api.as_ref().expect("workload evidence")
}

fn failure(o: &ExecutionOutput) -> Option<FailureKind> {
    o.record.attempts.last().and_then(|a| a.failure.as_ref()).map(|f| f.kind)
}

fn fast() -> SettingsOverrides {
    SettingsOverrides {
        timeouts: Some(TimeoutOverrides {
            connect_ms: Some(Some(3_000)),
            tls_handshake_ms: Some(Some(3_000)),
            response_headers_ms: Some(Some(5_000)),
            total_ms: Some(Some(15_000)),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn workload_tls(endpoint: &str, trust_bundle: bool, extra_roots: Vec<String>) -> TlsProfile {
    TlsProfile {
        id: Id::new(),
        workspace_id: Id::new(),
        name: "workload identity".into(),
        verify: true,
        use_system_roots: false,
        extra_roots_pem: extra_roots,
        client_identity: Some(ClientIdentity::WorkloadApi { endpoint: endpoint.into(), spiffe_id: None, trust_bundle }),
        bindings: vec![],
        min_version: Default::default(),
        server_name_override: None,
        server_spiffe: Some(ServerSpiffeIdentity { expected_server_spiffe_id: Some(wl::SERVER_ID.into()), trust_domain: None }),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

fn with_tls(url: &str, tls: TlsProfile) -> ExecutionContext {
    let mut c = ExecutionContext::standalone(RequestSpec::http("GET", url));
    let mut o = fast();
    o.tls_profile_id = Some(tls.id);
    c.tls_profiles.push(tls);
    c.settings_layers.push(("run".into(), o));
    c
}

fn jwt_auth(source: JwtSvidSource, endpoint: &str, audiences: &[&str]) -> JwtSvidConfig {
    JwtSvidConfig {
        source,
        audiences: audiences.iter().map(|s| s.to_string()).collect(),
        endpoint: endpoint.into(),
        spiffe_id: None,
        verify_with_bundles: false,
        send_despite_failed_checks: false,
        header_name: "Authorization".into(),
        prefix: "Bearer".into(),
    }
}

fn with_jwt(url: &str, config: JwtSvidConfig) -> ExecutionContext {
    let mut spec = RequestSpec::http("GET", url);
    spec.auth = AuthConfig::JwtSvid { config };
    let mut c = ExecutionContext::standalone(spec);
    c.settings_layers.push(("run".into(), fast()));
    c
}

fn authorization_seen(f: &fx::Fixture) -> Option<String> {
    f.log.last_request_headers()?.into_iter().find(|(n, _)| n.eq_ignore_ascii_case("authorization")).map(|(_, v)| v)
}

fn workload_calls(f: &wl::Fixture, rpc: &str) -> usize {
    f.log.entries().iter().filter(|e| matches!(&e.event, GroundTruth::WorkloadApiCall { rpc: r, .. } if r == rpc)).count()
}

/// A TLS server that verifies client SVIDs against the Workload API's CA
/// and presents an X.509-SVID with only a SPIFFE URI SAN.
async fn mtls_server(w: &wl::Fixture) -> fx::Fixture {
    let server = w.server_svid(wl::SERVER_ID);
    let mut opts = TlsServerOptions::new(server.cert.clone(), server.key.clone());
    opts.client_auth = ClientAuth::Required { ca_pem: w.ca_pem.clone() };
    fx::serve("127.0.0.1:0", Some(opts)).await.unwrap()
}

// ---------------------------------------------------------------- X.509 ---

#[tokio::test]
async fn x509_svid_from_the_workload_api_is_the_tls_client_identity_and_its_bundle_verifies_the_server() {
    init();
    let w = wl::serve(&sock("x509")).await.unwrap();
    let api = mtls_server(&w).await;
    let e = Engine::new();
    let c = with_tls(&api.url("/echo"), workload_tls(&w.uri(), true, vec![]));
    let o = run(&e, &c).await;
    assert_eq!(o.record.response.as_ref().map(|r| r.status), Some(200), "{:?} {:?}", failure(&o), codes(&o));
    let tls = o.record.attempts[0].connection.as_ref().and_then(|c| c.tls.as_ref()).unwrap();
    assert_eq!(tls.verification, TlsVerification::Verified);
    assert_eq!(tls.peer_spiffe_id.as_deref(), Some(wl::SERVER_ID), "server verified by SPIFFE ID with the Workload API bundle");
    let presented = tls.client_certificate_presented.as_ref().expect("client SVID presented");
    assert!(presented.subject_alt_names.iter().any(|s| s == &format!("URI:{}", wl::WORKLOAD_ID)));
    let ev = evidence(&o);
    assert_eq!(ev.calls.len(), 1);
    assert_eq!((ev.calls[0].rpc, &ev.calls[0].result, ev.calls[0].cached), (WorkloadRpc::FetchX509Svid, &WorkloadCallResult::Ok, false));
    assert_eq!(ev.calls[0].endpoint, w.uri());
    assert_eq!(ev.calls[0].endpoint_source, WorkloadEndpointSource::Setting);
    let s = &ev.x509_svids[0];
    assert_eq!((s.spiffe_id.as_str(), s.bundle_trusted, s.bundle_certificates), (wl::WORKLOAD_ID, true, 1));
    assert!(s.refresh_after.is_some());
    // Ground truth: the destination saw the SVID; the key never reaches the record.
    assert!(api.log.entries().iter().any(|e| matches!(&e.event, GroundTruth::TlsHandshakeCompleted { .. })));
    let json = serde_json::to_string(&o.record).unwrap();
    assert!(!json.contains("PRIVATE KEY"), "no key material in the record");

    // Cached until half-life: the second send does not call the Workload API.
    let o2 = run(&e, &c).await;
    assert_eq!(o2.record.response.as_ref().map(|r| r.status), Some(200));
    assert!(evidence(&o2).calls[0].cached);
    assert_eq!(w.issued_x509(), 1);

    // Lock clears the cache: the next send fetches again.
    e.clear_sensitive_state();
    assert!(e.workload.is_empty());
    let o3 = run(&e, &c).await;
    assert!(!evidence(&o3).calls[0].cached);
    assert_eq!(w.issued_x509(), 2);
}

#[tokio::test]
async fn a_short_lived_svid_is_refetched_after_half_its_lifetime() {
    init();
    let w = wl::serve(&sock("rotate")).await.unwrap();
    // Valid from 60 s ago (the fixture backdates) to 66 s from now: the
    // half-life is about 3 s from now.
    w.set_x509_ttl(Duration::from_secs(66));
    let api = mtls_server(&w).await;
    let e = Engine::new();
    let c = with_tls(&api.url("/echo"), workload_tls(&w.uri(), true, vec![]));
    let first = run(&e, &c).await;
    assert_eq!(first.record.response.as_ref().map(|r| r.status), Some(200));
    let cached = run(&e, &c).await;
    assert!(evidence(&cached).calls[0].cached, "reused before half-life");
    tokio::time::sleep(Duration::from_secs(4)).await;
    let second = run(&e, &c).await;
    assert_eq!(second.record.response.as_ref().map(|r| r.status), Some(200));
    assert!(!evidence(&second).calls[0].cached, "re-fetched after half-life");
    assert_eq!(w.issued_x509(), 2);
    let serial = |o: &ExecutionOutput| evidence(o).x509_svids[0].certificate.serial_hex.clone();
    assert_ne!(serial(&first), serial(&second), "the rotated SVID was presented");
}

#[tokio::test]
async fn workload_api_failures_stop_the_request_before_any_traffic() {
    init();
    let w = wl::serve(&sock("fail")).await.unwrap();
    let api = mtls_server(&w).await;
    let e = Engine::new();

    // Unreachable: no socket at the configured path.
    let missing = format!("unix://{}", sock("missing").display());
    let o = run(&e, &with_tls(&api.url("/echo"), workload_tls(&missing, true, vec![]))).await;
    assert_eq!(failure(&o), Some(FailureKind::WorkloadApiUnavailable));
    assert_eq!(o.record.outcome.dispatch, DispatchState::NotDispatched);
    let f = finding(&o, "local.workload_api_unavailable");
    assert_eq!((f.confidence, f.scope), (Confidence::Confirmed, SourceScope::LocalClient));
    assert!(f.explanation.contains(&missing), "{}", f.explanation);
    assert!(f.evidence.iter().any(|e| e.key == "io.error_kind" && e.value == "NotFound"));
    assert!(matches!(evidence(&o).calls[0].result, WorkloadCallResult::Unavailable { .. }));
    assert!(!api.log.saw_connection(), "nothing reached the destination");
    assert!(!codes(&o).iter().any(|c| c.starts_with("client.") || c.starts_with("http.")), "{:?}", codes(&o));

    // Denied: the Workload API refuses to attest this process.
    w.set_mode(Mode::Deny);
    let o = run(&e, &with_tls(&api.url("/echo"), workload_tls(&w.uri(), true, vec![]))).await;
    assert_eq!(failure(&o), Some(FailureKind::WorkloadApiDenied));
    let f = finding(&o, "local.workload_api_denied");
    assert_eq!(f.confidence, Confidence::Confirmed);
    assert!(f.explanation.contains("workload attestation failed"), "{}", f.explanation);
    assert!(f.evidence.iter().any(|e| e.key == "process.uid"), "the attested uid is evidence");
    assert!(f.evidence.iter().any(|e| e.key == "grpc.status" && e.value.contains("PERMISSION_DENIED")));

    // No identity in an OK answer.
    w.set_mode(Mode::NoIdentity);
    let o = run(&e, &with_tls(&api.url("/echo"), workload_tls(&w.uri(), true, vec![]))).await;
    assert_eq!(failure(&o), Some(FailureKind::WorkloadApiDenied));
    finding(&o, "local.workload_api_denied");

    // A selected SPIFFE ID the workload does not hold.
    w.set_mode(Mode::Serve);
    let mut t = workload_tls(&w.uri(), true, vec![]);
    t.client_identity = Some(ClientIdentity::WorkloadApi { endpoint: w.uri(), spiffe_id: Some(wl::SECOND_ID.into()), trust_bundle: true });
    let o = run(&e, &with_tls(&api.url("/echo"), t)).await;
    assert_eq!(failure(&o), Some(FailureKind::WorkloadApiDenied), "{:?}", codes(&o));

    // A Windows named pipe on this platform: refused before traffic.
    let o = run(&e, &with_tls(&api.url("/echo"), workload_tls("npipe:spire-agent", true, vec![]))).await;
    assert_eq!(failure(&o), Some(FailureKind::UnsupportedCombination));
    assert!(!api.log.saw_connection());
}

#[tokio::test]
async fn without_the_bundle_the_workload_svid_server_is_untrusted_and_http_urls_fetch_nothing() {
    init();
    let w = wl::serve(&sock("nobundle")).await.unwrap();
    let api = mtls_server(&w).await;
    let e = Engine::new();
    // trust_bundle off and no CA in the profile: verification cannot pass.
    let mut t = workload_tls(&w.uri(), false, vec![]);
    t.use_system_roots = true;
    let o = run(&e, &with_tls(&api.url("/echo"), t)).await;
    assert!(o.record.response.is_none());
    assert!(!evidence(&o).x509_svids[0].bundle_trusted);
    // A plain-HTTP request with the same TLS profile never calls the Workload API.
    let plain = fx::serve("127.0.0.1:0", None).await.unwrap();
    let before = workload_calls(&w, "FetchX509SVID");
    let o = run(&e, &with_tls(&plain.url("/echo"), workload_tls(&w.uri(), true, vec![]))).await;
    assert_eq!(o.record.response.as_ref().map(|r| r.status), Some(200));
    assert!(o.record.prepared.workload_api.is_none());
    assert_eq!(workload_calls(&w, "FetchX509SVID"), before);
}

// ------------------------------------------------------------------ JWT ---

#[tokio::test]
async fn jwt_svid_from_the_workload_api_is_checked_sent_cached_and_never_recorded() {
    init();
    let w = wl::serve(&sock("jwt")).await.unwrap();
    let api = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    let mut cfg = jwt_auth(JwtSvidSource::WorkloadApi, &w.uri(), &[GW_AUD]);
    cfg.verify_with_bundles = true;
    let c = with_jwt(&api.url("/echo"), cfg);
    let o = run(&e, &c).await;
    assert_eq!(o.record.response.as_ref().map(|r| r.status), Some(200), "{:?} {:?}", failure(&o), codes(&o));
    let seen = authorization_seen(&api).expect("Authorization sent");
    let token = seen.strip_prefix("Bearer ").expect("Bearer scheme");
    let claims = anvil_auth::jwt_svid::decode(token).unwrap().claims;
    assert_eq!(claims["sub"], wl::WORKLOAD_ID);
    let ev = evidence(&o);
    let j = ev.jwt_svid.as_ref().unwrap();
    assert_eq!(j.subject.as_deref(), Some(wl::WORKLOAD_ID));
    assert!(j.checks.iter().all(|c| c.result == CheckResult::Passed), "{:?}", j.checks);
    assert_eq!(j.key_id.as_deref(), Some(w.kid.as_str()));
    assert_eq!(ev.calls.iter().map(|c| c.rpc).collect::<Vec<_>>(), vec![WorkloadRpc::FetchJwtSvid, WorkloadRpc::FetchJwtBundles]);
    // The token is never in the record (headers, evidence, findings).
    let json = serde_json::to_string(&o.record).unwrap();
    assert!(!json.contains(token), "the JWT-SVID leaked into the record");
    assert!(o.record.prepared.auth_label.starts_with("jwt_svid"));
    // Cached: the next send reuses the token and the bundle.
    let o2 = run(&e, &c).await;
    assert_eq!(o2.record.response.as_ref().map(|r| r.status), Some(200));
    assert!(evidence(&o2).calls.iter().all(|c| c.cached));
    assert_eq!(workload_calls(&w, "FetchJWTSVID"), 1);
    assert_eq!(authorization_seen(&api).as_deref(), Some(seen.as_str()));
    // Lock clears it.
    e.clear_sensitive_state();
    run(&e, &c).await;
    assert_eq!(workload_calls(&w, "FetchJWTSVID"), 2);
}

#[tokio::test]
async fn failed_local_checks_refuse_the_request_unless_send_anyway_is_chosen() {
    init();
    let w = wl::serve(&sock("checks")).await.unwrap();
    let api = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    let value = |t: String| JwtSvidSource::Value { token: SensitiveValue::template(t) };

    // Expired (a pre-expired token from a variable).
    let expired = w.mint_jwt(wl::WORKLOAD_ID, &[GW_AUD], -120);
    let o = run(&e, &with_jwt(&api.url("/echo"), jwt_auth(value(expired.clone()), "", &[GW_AUD]))).await;
    assert_eq!(failure(&o), Some(FailureKind::JwtSvidRejectedLocally));
    assert_eq!(o.record.outcome.dispatch, DispatchState::NotDispatched);
    let f = finding(&o, "auth.jwt_svid_expired");
    assert_eq!((f.confidence, f.severity, f.scope), (Confidence::Confirmed, Severity::Error, SourceScope::LocalClient));
    assert!(f.explanation.contains("by this machine's clock"), "{}", f.explanation);
    assert!(!codes(&o).iter().any(|c| c.starts_with("local.")), "no generic local finding next to it: {:?}", codes(&o));
    assert_eq!(api.log.count_requests(), 0, "nothing sent");
    assert!(!serde_json::to_string(&o.record).unwrap().contains(&expired));

    // Wrong audience.
    let other = w.mint_jwt(wl::WORKLOAD_ID, &["spiffe://anvil.test/other"], 300);
    let o = run(&e, &with_jwt(&api.url("/echo"), jwt_auth(value(other), "", &[GW_AUD]))).await;
    let f = finding(&o, "auth.jwt_svid_audience_mismatch");
    assert!(f.explanation.contains(GW_AUD) && f.explanation.contains("spiffe://anvil.test/other"), "{}", f.explanation);

    // Not a JWT-SVID: HMAC-signed, subject not a SPIFFE ID.
    let hs = jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
        &serde_json::json!({"sub": "alice", "aud": [GW_AUD], "exp": 4_000_000_000i64}),
        &jsonwebtoken::EncodingKey::from_secret(b"a-shared-secret-value"),
    )
    .unwrap();
    let o = run(&e, &with_jwt(&api.url("/echo"), jwt_auth(value(hs), "", &[GW_AUD]))).await;
    let f = finding(&o, "auth.jwt_svid_invalid");
    assert!(f.explanation.contains("algorithm") && f.explanation.contains("subject"), "{}", f.explanation);

    // Signed by a key outside the trust domain's JWT bundle.
    let rogue = wl::serve(&sock("rogue")).await.unwrap();
    let forged = rogue.mint_jwt(wl::WORKLOAD_ID, &[GW_AUD], 300);
    let mut cfg = jwt_auth(value(forged), &w.uri(), &[GW_AUD]);
    cfg.verify_with_bundles = true;
    let o = run(&e, &with_jwt(&api.url("/echo"), cfg)).await;
    let f = finding(&o, "auth.jwt_svid_invalid");
    assert!(f.explanation.contains("signature"), "{}", f.explanation);
    assert_eq!(api.log.count_requests(), 0);

    // Send anyway: the check stays as a warning and the verifier's 401 is explained generically.
    let mut cfg = jwt_auth(value(expired), "", &[GW_AUD]);
    cfg.send_despite_failed_checks = true;
    let body = "%7B%22error%22%3A%22Invalid%20or%20unrecognized%20JWT%22%7D";
    let o = run(&e, &with_jwt(&api.url(&format!("/status/401?body={body}")), cfg)).await;
    assert_eq!(o.record.response.as_ref().map(|r| r.status), Some(401));
    assert_eq!(api.log.count_requests(), 1, "sent, as the profile asks");
    assert_eq!(finding(&o, "auth.jwt_svid_expired").severity, Severity::Warning);
    let r = finding(&o, "auth.jwt_svid_rejected");
    assert_eq!((r.confidence, r.scope), (Confidence::Unknown, SourceScope::Unknown));
    assert!(r.explanation.contains("Invalid or unrecognized JWT"), "{}", r.explanation);
    assert!(r.alternatives.iter().any(|a| a.contains("expiry check had failed")), "{:?}", r.alternatives);
    assert!(evidence(&o).jwt_svid.as_ref().unwrap().sent_despite_failed_checks);
}

#[tokio::test]
async fn a_401_after_a_valid_jwt_svid_is_a_generic_refusal_with_the_checks_as_evidence() {
    init();
    let w = wl::serve(&sock("401")).await.unwrap();
    let api = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    let mut cfg = jwt_auth(JwtSvidSource::WorkloadApi, &w.uri(), &["spiffe://anvil.test/not-the-gateway"]);
    cfg.verify_with_bundles = true;
    let o = run(&e, &with_jwt(&api.url("/status/401?body=%7B%22error%22%3A%22Invalid%20or%20unrecognized%20JWT%22%7D"), cfg)).await;
    assert_eq!(o.record.outcome.application, ApplicationState::Failure);
    let r = finding(&o, "auth.jwt_svid_rejected");
    assert_eq!(r.confidence, Confidence::Unknown);
    assert!(r.explanation.contains("audience passed") && r.explanation.contains("signature passed"), "{}", r.explanation);
    assert!(r.alternatives.iter().any(|a| a.contains("expects a different audience")));
    assert!(r.does_not_prove.iter().any(|d| d.contains("signature is invalid")));
    assert!(r.evidence.iter().any(|e| e.key == "jwt_svid.aud" && e.value == "spiffe://anvil.test/not-the-gateway"));
    finding(&o, "http.unauthorized");
    assert!(!codes(&o).iter().any(|c| c.starts_with("auth.jwt_svid_") && c != "auth.jwt_svid_rejected"));
}

#[tokio::test]
async fn jwt_svid_from_a_file_and_workload_api_errors_are_typed() {
    init();
    let w = wl::serve(&sock("file")).await.unwrap();
    let api = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    let path = std::env::temp_dir().join(format!("anvil-jwt-svid-{}.token", std::process::id()));
    std::fs::write(&path, format!("{}\n", w.mint_jwt(wl::WORKLOAD_ID, &[GW_AUD], 300))).unwrap();
    let file = JwtSvidSource::File { path: path.display().to_string() };
    let o = run(&e, &with_jwt(&api.url("/echo"), jwt_auth(file, "", &[GW_AUD]))).await;
    assert_eq!(o.record.response.as_ref().map(|r| r.status), Some(200), "{:?}", codes(&o));
    assert_eq!(evidence(&o).jwt_svid.as_ref().unwrap().source, JwtSvidSourceKind::File);
    std::fs::remove_file(&path).ok();
    let o = run(&e, &with_jwt(&api.url("/echo"), jwt_auth(JwtSvidSource::File { path: path.display().to_string() }, "", &[GW_AUD]))).await;
    assert_eq!(failure(&o), Some(FailureKind::AuthPreparationFailed));

    // An X.509-only Workload API: FetchJWTSVID is UNIMPLEMENTED.
    w.set_mode(Mode::JwtUnimplemented);
    let o = run(&e, &with_jwt(&api.url("/echo"), jwt_auth(JwtSvidSource::WorkloadApi, &w.uri(), &[GW_AUD]))).await;
    assert_eq!(failure(&o), Some(FailureKind::WorkloadApiFailed));
    let f = finding(&o, "local.workload_api_failed");
    assert!(f.explanation.contains("UNIMPLEMENTED"), "{}", f.explanation);
    // Denied.
    w.set_mode(Mode::Deny);
    let o = run(&e, &with_jwt(&api.url("/echo"), jwt_auth(JwtSvidSource::WorkloadApi, &w.uri(), &[GW_AUD]))).await;
    finding(&o, "local.workload_api_denied");
    assert_eq!(api.log.count_requests(), 1, "only the file-sourced request was sent");

    // No audience is a configuration error, before any call.
    let before = workload_calls(&w, "FetchJWTSVID");
    let o = run(&e, &with_jwt(&api.url("/echo"), jwt_auth(JwtSvidSource::WorkloadApi, &w.uri(), &[]))).await;
    assert_eq!(failure(&o), Some(FailureKind::AuthPreparationFailed));
    assert_eq!(workload_calls(&w, "FetchJWTSVID"), before);
}

#[tokio::test]
async fn sse_and_websocket_sessions_carry_the_jwt_svid_and_raw_tcp_refuses_it() {
    init();
    let w = wl::serve(&sock("sse")).await.unwrap();
    let api = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    let mut c = with_jwt(&api.url("/sse?count=1"), jwt_auth(JwtSvidSource::WorkloadApi, &w.uri(), &[GW_AUD]));
    c.spec.protocol = Protocol::Sse;
    c.spec.sse = Some(SseSpec { max_events: 1, idle_timeout_ms: 3_000, last_event_id: None, reconnect: false });
    let o = run(&e, &c).await;
    assert!(matches!(o.record.outcome.protocol_status, ProtocolStatus::Sse { events: 1, .. }), "{:?}", o.record.outcome);
    assert!(authorization_seen(&api).is_some_and(|a| a.starts_with("Bearer ")));
    assert!(evidence(&o).jwt_svid.is_some());

    // A WebSocket upgrade carries it too.
    let mut c = with_jwt(&format!("ws://{}/ws", api.addr), jwt_auth(JwtSvidSource::WorkloadApi, &w.uri(), &[GW_AUD]));
    c.spec.protocol = Protocol::WebSocket;
    c.spec.websocket = Some(WsSpec {
        bootstrap: WsBootstrap::Http1Upgrade,
        subprotocols: vec![],
        messages: vec![],
        expect_messages: 0,
        max_message_bytes: 1 << 20,
        idle_close_ms: 200,
        permessage_deflate: Default::default(),
    });
    let before = api.log.count_requests();
    let o = run(&e, &c).await;
    assert!(matches!(o.record.outcome.protocol_status, ProtocolStatus::WebSocket { .. }), "{:?}", o.record.outcome);
    assert_eq!(api.log.count_requests(), before + 1);
    assert!(authorization_seen(&api).is_some_and(|a| a.starts_with("Bearer ")), "the upgrade request carried the JWT-SVID");
    assert!(evidence(&o).jwt_svid.as_ref().is_some_and(|j| j.checks.iter().all(|c| c.result != CheckResult::Failed)));

    let mut c = with_jwt("tcp://127.0.0.1:9", jwt_auth(JwtSvidSource::WorkloadApi, &w.uri(), &[GW_AUD]));
    c.spec.protocol = Protocol::Tcp;
    let before = workload_calls(&w, "FetchJWTSVID");
    let o = run(&e, &c).await;
    assert_eq!(failure(&o), Some(FailureKind::UnsupportedCombination), "auth on raw TCP is refused, nothing fetched");
    assert_eq!(workload_calls(&w, "FetchJWTSVID"), before);
}

#[tokio::test]
async fn the_effective_request_preview_makes_no_workload_api_call() {
    init();
    let w = wl::serve(&sock("preview")).await.unwrap();
    let mut c = with_jwt("https://127.0.0.1:1/echo", jwt_auth(JwtSvidSource::WorkloadApi, &w.uri(), &[GW_AUD]));
    c.tls_profiles.push(workload_tls(&w.uri(), true, vec![]));
    let p = Engine::new().preview(&c).unwrap();
    assert!(p.auth.starts_with("jwt_svid"));
    assert!(p.inferred.iter().any(|n| n.contains("fetched from the SPIFFE Workload API")), "{:?}", p.inferred);
    assert!(w.log.entries().is_empty(), "the preview never dials the Workload API");
}
