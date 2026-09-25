//! Engine-level scenarios: real sockets + the shared engine + diagnostics.
//! Ground truth from fixtures is used only to check conditions were reached;
//! it is never passed to the diagnostic engine.

use anvil_domain::auth::{AuthConfig, KeyLocation};
use anvil_domain::diagnostics::{Confidence, SourceScope};
use anvil_domain::execution::*;
use anvil_domain::integration::{IntegrationKind, IntegrationProfile};
use anvil_domain::outcome::*;
use anvil_domain::request::{Body, KeyValue, RequestSpec};
use anvil_domain::secret::SensitiveValue;
use anvil_domain::settings::{RetryPolicy, SettingsOverrides};
use anvil_domain::tls::HostBinding;
use anvil_engine::vars::{VarEntry, VarLayer};
use anvil_engine::{Engine, ExecutionContext, ExecutionOutput};
use anvil_fixtures::http as fx;
use anvil_fixtures::raw::{self, RawMode};
use anvil_transport::recorder::EventCtx;
use tokio_util::sync::CancellationToken;

fn init() {
    anvil_transport::init();
    anvil_fixtures::init();
}

async fn run(engine: &Engine, ctx: &ExecutionContext) -> ExecutionOutput {
    engine.execute(ctx, EventCtx::none(), CancellationToken::new()).await
}

fn ctx_for(url: &str) -> ExecutionContext {
    ExecutionContext::standalone(RequestSpec::http("GET", url))
}

fn trusted(ctx: &mut ExecutionContext, host: &str) {
    ctx.integrations.push(IntegrationProfile {
        id: anvil_domain::Id::new(),
        workspace_id: anvil_domain::Id::new(),
        name: "lab gateway".into(),
        kind: IntegrationKind::FerrumGateway {
            hosts: vec![HostBinding { host: host.into(), port: None }],
            compatibility_id: "ferrum-edge-0.9.5".into(),
            require_verified_tls: false,
            detail: None,
            console_url: None,
        },
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    });
}

fn codes(o: &ExecutionOutput) -> Vec<String> {
    o.record.findings.iter().map(|f| f.code.clone()).collect()
}

fn finding<'a>(o: &'a ExecutionOutput, code: &str) -> &'a anvil_domain::diagnostics::DiagnosticFinding {
    o.record.findings.iter().find(|f| f.code == code).unwrap_or_else(|| panic!("missing {code}; have {:?}", codes(o)))
}

fn url_encode(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

#[tokio::test]
async fn trust_001_forged_marker_from_untrusted_api_is_not_attributed() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    let o = run(&e, &ctx_for(&f.url("/status/502?header=X-Gateway-Error:connection_failure"))).await;
    let c = codes(&o);
    assert!(c.contains(&"ferrum.marker.unverified".to_string()), "{c:?}");
    assert!(!c.iter().any(|x| x.starts_with("ferrum.token.")), "no gateway attribution from an untrusted peer: {c:?}");
    assert!(c.contains(&"http.bad_gateway".to_string()));
    assert!(o.record.outcome.warnings.iter().any(|w| w.code == WarningCode::UnverifiedFerrumMarker));
}

#[tokio::test]
async fn trust_005_identical_public_signal_stays_ambiguous_and_capped() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    let body = url_encode(r#"{"error":"Backend unavailable"}"#);
    let mut ctx = ctx_for(&f.url(&format!("/status/502?header=X-Gateway-Error:connection_failure&body={body}")));
    trusted(&mut ctx, "127.0.0.1");
    let o = run(&e, &ctx).await;
    let tok = finding(&o, "ferrum.token.connection_failure");
    assert_eq!(tok.scope, SourceScope::GatewayToUpstream);
    assert!(tok.confidence <= Confidence::Likely, "marker is spoofable and the channel was plain HTTP: {:?}", tok.confidence);
    assert!(tok.does_not_prove.iter().any(|d| d.contains("TLS failed")));
    let amb = finding(&o, "ferrum.outcome_ambiguous");
    assert_eq!(amb.confidence, Confidence::Unknown);
    assert!(amb.alternatives.len() >= 3, "all indistinguishable upstream causes are listed");
    assert!(!o.record.findings.iter().any(|f| f.confidence == Confidence::Confirmed && f.code.contains("tls")), "no confirmed TLS claim");
}

#[tokio::test]
async fn trust_004_conflicting_duplicate_markers() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    let mut ctx = ctx_for(&f.url("/status/503?header=X-Gateway-Error:overload&header=X-Gateway-Error:config_stale"));
    trusted(&mut ctx, "127.0.0.1");
    let o = run(&e, &ctx).await;
    assert_eq!(finding(&o, "ferrum.marker.conflicting").confidence, Confidence::ConflictingEvidence);
    assert!(!codes(&o).iter().any(|c| c.starts_with("ferrum.token.")), "no convenient value is picked");
}

#[tokio::test]
async fn trust_003_unknown_future_token() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    let mut ctx = ctx_for(&f.url("/status/503?header=X-Gateway-Error:quantum_flux"));
    trusted(&mut ctx, "127.0.0.1");
    let o = run(&e, &ctx).await;
    let u = finding(&o, "ferrum.marker.unknown_token");
    assert_eq!(u.confidence, Confidence::Unknown);
    assert!(u.explanation.contains("quantum_flux"));
}

#[tokio::test]
async fn trust_006_and_gw_016_forbidden_never_proves_waf() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    let body = url_encode(r#"{"error":"Forbidden"}"#);
    let mut ctx = ctx_for(&f.url(&format!("/status/403?body={body}")));
    trusted(&mut ctx, "127.0.0.1");
    let o = run(&e, &ctx).await;
    let fb = finding(&o, "http.forbidden");
    assert!(fb.does_not_prove.iter().any(|d| d.contains("WAF")));
    assert!(!o.record.findings.iter().any(|f| f.confidence >= Confidence::Likely && f.title.to_lowercase().contains("waf")));
    // Application lookalike from an untrusted destination: same 403, no gateway claims at all.
    let o2 = run(&e, &ctx_for(&f.url(&format!("/status/403?body={body}")))).await;
    assert!(!codes(&o2).iter().any(|c| c.starts_with("ferrum.")));
}

#[tokio::test]
async fn gw_018_degraded_routing_is_a_warning_on_success() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    let mut ctx = ctx_for(&f.url("/status/200?header=X-Gateway-Upstream-Status:degraded"));
    trusted(&mut ctx, "127.0.0.1");
    let o = run(&e, &ctx).await;
    assert_eq!(o.record.outcome.application, ApplicationState::Success);
    assert_eq!(o.record.outcome.transport, TransportState::Completed);
    assert!(o.record.outcome.warnings.iter().any(|w| w.code == WarningCode::DegradedRouting));
}

#[tokio::test]
async fn trust_007_status_200_then_truncated_body_is_not_success() {
    init();
    let f = raw::serve("127.0.0.1:0", RawMode::ShortBody { declared: 500, sent: 20 }, None).await.unwrap();
    let e = Engine::new();
    let o = run(&e, &ctx_for(&f.url(false, "/"))).await;
    assert_eq!(o.record.outcome.transport, TransportState::Incomplete);
    assert_ne!(o.record.outcome.application, ApplicationState::Success);
    let b = finding(&o, "response.body_incomplete");
    assert_eq!(b.scope, SourceScope::ResponseDelivery);
}

#[tokio::test]
async fn trust_013_response_prompt_injection_is_inert_data() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    let o = run(&e, &ctx_for(&f.url("/injection"))).await;
    assert_eq!(o.record.outcome.application, ApplicationState::Success);
    assert!(o.record.findings.is_empty(), "instructions in a body never create findings or actions: {:?}", codes(&o));
    assert!(!o.record.outcome.summary.contains("ignore previous"));
}

#[tokio::test]
async fn proto_023_soap_fault_and_proto_024_graphql_errors_on_200() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    let o = run(&e, &ctx_for(&f.url("/soap-fault"))).await;
    assert_eq!(o.record.outcome.transport, TransportState::Completed);
    assert_eq!(o.record.outcome.application, ApplicationState::Failure);
    assert!(finding(&o, "app.soap_fault").explanation.contains("Fixture fault"));
    let g = run(&e, &ctx_for(&f.url("/graphql-errors"))).await;
    assert_eq!(g.record.outcome.application, ApplicationState::Failure);
    assert!(finding(&g, "app.graphql_errors").explanation.contains("Partial data"));
}

#[tokio::test]
async fn local_002_unresolved_variable_never_sends() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    let mut ctx = ctx_for(&f.url("/echo"));
    ctx.spec.headers.push(KeyValue::new("Authorization", "Bearer {{token}}"));
    let o = run(&e, &ctx).await;
    assert_eq!(finding(&o, "local.unresolved_variable").scope, SourceScope::LocalClient);
    assert_eq!(o.record.outcome.dispatch, DispatchState::NotDispatched);
    assert_eq!(f.log.count_requests(), 0, "ground truth: nothing reached the server");
}

#[tokio::test]
async fn auth_001_api_key_header_name_reject_then_recover() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    let mut ctx = ctx_for(&f.url("/auth/apikey?name=x-api-key&value=k-123456"));
    ctx.auth_layers = vec![(
        "request".into(),
        AuthConfig::ApiKey { name: "X-Wrong-Key".into(), value: SensitiveValue::template("k-123456"), location: KeyLocation::Header },
    )];
    let bad = run(&e, &ctx).await;
    assert_eq!(bad.record.response.as_ref().unwrap().status, 401);
    ctx.auth_layers = vec![(
        "request".into(),
        AuthConfig::ApiKey { name: "X-API-Key".into(), value: SensitiveValue::template("k-123456"), location: KeyLocation::Header },
    )];
    let good = run(&e, &ctx).await;
    assert_eq!(good.record.response.as_ref().unwrap().status, 200);
    let json = serde_json::to_string(&good.record).unwrap();
    assert!(!json.contains("k-123456"), "the key value never appears in the record");
    assert!(good.record.prepared.auth_label.contains("X-API-Key"));
}

#[tokio::test]
async fn auth_002_query_key_and_data_020_secrets_redacted_everywhere() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    let mut ctx = ctx_for(&f.url("/echo?note={{planted}}"));
    ctx.var_layers = vec![VarLayer {
        label: "environment:lab".into(),
        vars: vec![VarEntry { name: "planted".into(), value: "PLANTED-SECRET-9f8e7d".into(), secret: true }],
    }];
    ctx.spec.headers.push(KeyValue::new("X-Trace", "t-{{planted}}"));
    ctx.spec.body = Body::Json { text: r#"{"password":"hunter2-literal","v":"{{planted}}"}"#.into() };
    ctx.spec.method = "POST".into();
    ctx.auth_layers = vec![(
        "request".into(),
        AuthConfig::ApiKey { name: "api_key".into(), value: SensitiveValue::template("QUERY-KEY-777777"), location: KeyLocation::Query },
    )];
    let o = run(&e, &ctx).await;
    assert_eq!(o.record.response.as_ref().unwrap().status, 200);
    let json = serde_json::to_string(&o.record).unwrap();
    for secret in ["PLANTED-SECRET-9f8e7d", "QUERY-KEY-777777"] {
        assert!(!json.contains(secret), "{secret} leaked into the execution record");
    }
    // Ground truth: the server really received the values.
    let hdrs = f.log.last_request_headers().unwrap();
    assert!(hdrs.iter().any(|(n, v)| n == "x-trace" && v == "t-PLANTED-SECRET-9f8e7d"));
}

#[tokio::test]
async fn tls_018_cross_origin_redirect_drops_credentials() {
    init();
    let a = fx::serve("127.0.0.1:0", None).await.unwrap();
    let b = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    let target = url_encode(&b.url_host("localhost", "/echo"));
    let mut ctx = ctx_for(&a.url(&format!("/redirect?to={target}&status=302")));
    ctx.auth_layers =
        vec![("request".into(), AuthConfig::Bearer { token: SensitiveValue::template("bearer-abcdef"), prefix: "Bearer".into() })];
    let o = run(&e, &ctx).await;
    assert_eq!(o.record.attempts.len(), 2);
    assert!(matches!(o.record.attempts[1].reason, AttemptReason::Redirect { status: 302 }));
    let hdrs = b.log.last_request_headers().unwrap();
    assert!(!hdrs.iter().any(|(n, _)| n == "authorization"), "Authorization must not cross origins");
    assert!(o.record.outcome.warnings.iter().any(|w| w.code == WarningCode::CredentialsStrippedOnRedirect));
}

#[tokio::test]
async fn retries_off_by_default_and_never_replay_possibly_processed_post() {
    init();
    let f = raw::serve("127.0.0.1:0", RawMode::ResetAfterRequest, None).await.unwrap();
    let e = Engine::new();
    let mut ctx = ctx_for(&f.url(false, "/orders"));
    ctx.spec.method = "POST".into();
    ctx.spec.body = Body::Json { text: r#"{"sku":1}"#.into() };
    let o = run(&e, &ctx).await;
    assert_eq!(o.record.attempts.len(), 1);
    // Even with retries enabled, a possibly-processed POST is not retried.
    ctx.settings_layers.push((
        "run".into(),
        SettingsOverrides { retries: Some(RetryPolicy { max_retries: 3, backoff_ms: 1, only_safe: true }), ..Default::default() },
    ));
    let o2 = run(&e, &ctx).await;
    assert_eq!(o2.record.attempts.len(), 1, "POST that may have been processed is never auto-replayed");
    assert!(codes(&o2).contains(&"request.processing_uncertain".to_string()));
}

#[tokio::test]
async fn safe_retry_when_not_dispatched() {
    init();
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    drop(l);
    let e = Engine::new();
    let mut ctx = ctx_for(&format!("http://127.0.0.1:{port}/"));
    ctx.spec.method = "POST".into();
    ctx.settings_layers.push((
        "run".into(),
        SettingsOverrides { retries: Some(RetryPolicy { max_retries: 2, backoff_ms: 1, only_safe: true }), ..Default::default() },
    ));
    let o = run(&e, &ctx).await;
    assert_eq!(o.record.attempts.len(), 3);
    assert!(o.record.attempts.iter().all(|a| a.dispatch == DispatchState::NotDispatched));
    assert!(codes(&o).contains(&"client.connect.refused".to_string()));
}

#[tokio::test]
async fn gzip_body_is_decoded_for_assertions_but_raw_bytes_kept() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    let o = run(&e, &ctx_for(&f.url("/gzip"))).await;
    let r = o.record.response.as_ref().unwrap();
    assert_eq!(r.body.content_encoding.as_deref(), Some("gzip"));
    assert!(o.decoded_body.as_ref().unwrap().starts_with(b"compressed fixture payload"));
    assert!(r.body.decoded_bytes.unwrap() > r.body.wire_bytes, "decoded and wire sizes are distinct");
}
