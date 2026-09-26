//! Target-API authorization code + PKCE through real sockets: a fixture
//! issuer + protected API (`anvil_fixtures::idp`), the loopback listener, a
//! simulated system browser that follows the issuer's redirect, the engine
//! transport for the code exchange, and a real API request with the token.
//! Fixture ground truth (grants seen, API hits) only checks that conditions
//! were reached; it is never fed to the code under test.

use anvil_domain::auth::{AuthConfig, OAuth2Config, OAuthClientAuth, OAuthGrant};
use anvil_domain::execution::{DispatchState, FailureKind};
use anvil_domain::request::RequestSpec;
use anvil_domain::secret::SensitiveValue;
use anvil_domain::settings::SettingsOverrides;
use anvil_domain::tls::{TlsMinVersion, TlsProfile};
use anvil_engine::{Engine, ExecutionContext, ExecutionOutput};
use anvil_fixtures::idp::{AuthorizeBehavior, BrowserVisit, IdpFixture, IdpOptions, raw_get, simulate_browser};
use anvil_identity::api_oauth::{self, authorize_api};
use anvil_identity::{FlowError, FlowEvent, FlowOptions};
use anvil_transport::recorder::EventCtx;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio_util::sync::CancellationToken;

fn init() {
    anvil_transport::init();
    anvil_fixtures::init();
}

fn oauth_ctx(idp: &IdpFixture) -> ExecutionContext {
    let mut spec = RequestSpec::http("GET", &idp.api_url());
    spec.auth = AuthConfig::OAuth2 {
        config: OAuth2Config {
            grant: OAuthGrant::AuthorizationCodePkce,
            token_url: idp.token_endpoint(),
            authorization_url: idp.authorization_endpoint(),
            client_id: idp.client_id(),
            client_secret: SensitiveValue::default(),
            scope: "api.read".into(),
            audience: String::new(),
            client_auth: OAuthClientAuth::RequestBody,
            token_cache_id: None,
            refresh_skew_secs: 30,
        },
    };
    let mut ctx = ExecutionContext::standalone(spec);
    ctx.isolation = "workspace-under-test".into();
    ctx
}

async fn send(engine: &Engine, ctx: &ExecutionContext) -> ExecutionOutput {
    engine.execute(ctx, EventCtx::none(), CancellationToken::new()).await
}

fn failure_kind(o: &ExecutionOutput) -> Option<FailureKind> {
    o.record.attempts.last().and_then(|a| a.failure.as_ref()).map(|f| f.kind)
}

/// Simulated system browser: navigates to the authorization URL in the
/// background (the opener must not wait) and hands back what it saw.
struct Browser {
    visits: Arc<Mutex<Vec<BrowserVisit>>>,
    trust_ca: Option<String>,
}

impl Browser {
    fn new(trust_ca: Option<String>) -> Self {
        Browser { visits: Arc::new(Mutex::new(vec![])), trust_ca }
    }
    fn opener(&self) -> impl Fn(&str) -> Result<(), String> + Send + Sync + use<> {
        let (visits, ca) = (self.visits.clone(), self.trust_ca.clone());
        move |url: &str| {
            let (url, visits, ca) = (url.to_string(), visits.clone(), ca.clone());
            tokio::spawn(async move {
                if let Ok(v) = simulate_browser(&url, ca.as_deref()).await {
                    visits.lock().unwrap().push(v);
                }
            });
            Ok(())
        }
    }
    async fn last_visit(&self) -> BrowserVisit {
        for _ in 0..100 {
            if let Some(v) = self.visits.lock().unwrap().last().cloned() {
                return v;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("the simulated browser never finished");
    }
}

struct Events(Arc<Mutex<Vec<FlowEvent>>>);

impl Events {
    fn new() -> Self {
        Events(Arc::new(Mutex::new(vec![])))
    }
    fn observer(&self) -> impl Fn(FlowEvent) + Send + Sync + use<> {
        let v = self.0.clone();
        move |e| v.lock().unwrap().push(e)
    }
    fn all(&self) -> Vec<FlowEvent> {
        self.0.lock().unwrap().clone()
    }
}

#[tokio::test]
async fn auth_011_pkce_round_trip_then_real_api_request_with_the_token() {
    init();
    let idp = IdpFixture::start(IdpOptions::default()).await.unwrap();
    let engine = Engine::new();
    let ctx = oauth_ctx(&idp);

    // Before sign-in: typed local failure, nothing sent, no grant substituted.
    let o = send(&engine, &ctx).await;
    assert_eq!(failure_kind(&o), Some(FailureKind::OAuthInteractionRequired));
    assert_eq!(o.record.outcome.dispatch, DispatchState::NotDispatched);
    let f = o.record.findings.iter().find(|f| f.code == "local.oauth_interaction_required").expect("sign-in finding");
    assert!(f.explanation.contains("Sign in") && f.remediation.iter().any(|r| r.text.contains("Sign in")), "{f:?}");
    assert_eq!(idp.api_requests(), (0, 0), "the API request was not sent");
    assert!(idp.grants_seen().is_empty(), "no client-credentials fallback");

    let browser = Browser::new(None);
    let events = Events::new();
    let auth = authorize_api(&engine, &ctx, &browser.opener(), &events.observer(), &FlowOptions::default(), &CancellationToken::new())
        .await
        .expect("sign-in completes");
    assert_eq!(auth.grant, OAuthGrant::AuthorizationCodePkce);
    assert_eq!(auth.client_id, idp.client_id());
    assert!(auth.token.refresh_token_available && auth.token.expires_at.is_some());
    assert_eq!(idp.grants_seen(), vec!["authorization_code".to_string()]);

    // The browser saw a static page: no script, no reflected query values.
    let visit = browser.last_visit().await;
    assert_eq!(visit.hops.len(), 2, "authorize → loopback callback: {:?}", visit.hops);
    assert!(visit.hops[1].starts_with("http://127.0.0.1:"));
    assert_eq!(visit.final_status, 200);
    assert!(visit.final_body.contains("close this tab"));
    assert!(!visit.final_body.contains("<script") && !visit.final_body.contains("fx-code"));
    assert!(visit.header("content-security-policy").unwrap_or("").contains("default-src 'none'"));
    assert_eq!(visit.header("cache-control"), Some("no-store"));

    // Events describe progress without codes, verifiers or tokens.
    let ev = events.all();
    assert!(matches!(ev.first(), Some(FlowEvent::ListenerReady { redirect_uri }) if redirect_uri.starts_with("http://127.0.0.1:")));
    assert!(
        ev.iter().any(
            |e| matches!(e, FlowEvent::BrowserOpened { authorization_url } if authorization_url.contains("code_challenge_method=S256"))
        )
    );
    assert!(ev.contains(&FlowEvent::CallbackAccepted) && ev.contains(&FlowEvent::ExchangingCode));
    assert_eq!(ev.last(), Some(&FlowEvent::Completed));
    let serialized = serde_json::to_string(&ev).unwrap();
    assert!(!serialized.contains("fx-code") && !serialized.contains("fx-at") && !serialized.contains("fx-rt"), "{serialized}");

    // The engine now sends with the token and the protected API accepts it.
    let o = send(&engine, &ctx).await;
    assert_eq!(o.record.response.as_ref().map(|r| r.status), Some(200), "{:?}", o.record.findings);
    assert_eq!(idp.api_requests(), (1, 1));
    assert_eq!(idp.grants_seen(), vec!["authorization_code".to_string()], "cached token reused, no further grant");
    let st = api_oauth::token_status(&engine, &ctx).unwrap().expect("token cached");
    assert!(st.refresh_token_available);

    // Signing out forgets the token: back to "sign in first", still not sent.
    assert!(api_oauth::sign_out(&engine, &ctx).unwrap());
    let o = send(&engine, &ctx).await;
    assert_eq!(failure_kind(&o), Some(FailureKind::OAuthInteractionRequired));
    assert_eq!(idp.api_requests(), (1, 1));
}

#[tokio::test]
async fn auth_012_forged_state_is_rejected_without_token_exchange() {
    init();
    let idp = IdpFixture::start(IdpOptions::default()).await.unwrap();
    idp.set_behavior(AuthorizeBehavior::ForgeState);
    let engine = Engine::new();
    let ctx = oauth_ctx(&idp);
    let browser = Browser::new(None);
    let events = Events::new();
    let r = authorize_api(&engine, &ctx, &browser.opener(), &events.observer(), &FlowOptions::default(), &CancellationToken::new()).await;
    assert!(matches!(&r, Err(FlowError::CallbackRejected(m)) if m.contains("state")), "{r:?}");
    assert!(idp.grants_seen().is_empty(), "no token exchange after a state mismatch");
    assert!(api_oauth::token_status(&engine, &ctx).unwrap().is_none());
    assert!(matches!(events.all().last(), Some(FlowEvent::Failed { .. })));
    let visit = browser.last_visit().await;
    assert_eq!(visit.final_status, 400);
    assert!(!visit.final_body.contains("forged"), "nothing reflected");
}

#[tokio::test]
async fn auth_013_stray_callbacks_on_other_paths_or_hosts_are_ignored() {
    init();
    let idp = IdpFixture::start(IdpOptions::default()).await.unwrap();
    let engine = Engine::new();
    let ctx = oauth_ctx(&idp);
    let statuses = Arc::new(Mutex::new(vec![]));
    let s2 = statuses.clone();
    // A hostile local client probes the listener first; then the real browser.
    let opener = move |url: &str| -> Result<(), String> {
        let u = url::Url::parse(url).unwrap();
        let q: std::collections::HashMap<String, String> = u.query_pairs().into_owned().collect();
        let redirect = url::Url::parse(&q["redirect_uri"]).unwrap();
        let state = q["state"].clone();
        let port = redirect.port().unwrap();
        let (url, s2) = (url.to_string(), s2.clone());
        tokio::spawn(async move {
            let wrong_path = format!("http://127.0.0.1:{port}/not-the-callback?code=stolen&state={state}");
            let (a, _, _) = raw_get(&wrong_path, None).await.unwrap();
            let rebinding = format!("http://127.0.0.1:{port}/callback?code=stolen&state={state}");
            let (b, _, _) = raw_get(&rebinding, Some(&format!("evil.example:{port}"))).await.unwrap();
            s2.lock().unwrap().extend([a, b]);
            let _ = simulate_browser(&url, None).await;
        });
        Ok(())
    };
    let events = Events::new();
    let auth = authorize_api(&engine, &ctx, &opener, &events.observer(), &FlowOptions::default(), &CancellationToken::new()).await;
    assert!(auth.is_ok(), "{auth:?}");
    assert_eq!(*statuses.lock().unwrap(), vec![404, 400]);
    let ignored = events.all().iter().filter(|e| matches!(e, FlowEvent::CallbackIgnored { .. })).count();
    assert_eq!(ignored, 2);
    assert_eq!(idp.grants_seen(), vec!["authorization_code".to_string()], "only the genuine code was redeemed");
}

#[tokio::test]
async fn attempt_times_out_and_closes_the_listener() {
    init();
    let idp = IdpFixture::start(IdpOptions::default()).await.unwrap();
    idp.set_behavior(AuthorizeBehavior::NoRedirect);
    let engine = Engine::new();
    let ctx = oauth_ctx(&idp);
    let events = Events::new();
    let opts = FlowOptions { timeout: Duration::from_millis(400), ..Default::default() };
    let started = std::time::Instant::now();
    let r = authorize_api(&engine, &ctx, &Browser::new(None).opener(), &events.observer(), &opts, &CancellationToken::new()).await;
    assert!(matches!(r, Err(FlowError::TimedOut(_))), "{r:?}");
    assert!(started.elapsed() < Duration::from_secs(5));
    let redirect = events
        .all()
        .iter()
        .find_map(|e| match e {
            FlowEvent::ListenerReady { redirect_uri } => Some(redirect_uri.clone()),
            _ => None,
        })
        .unwrap();
    assert!(raw_get(&redirect, None).await.is_err(), "the loopback port is closed after the attempt");
    assert!(idp.grants_seen().is_empty());
}

#[tokio::test]
async fn attempt_can_be_canceled_while_waiting_for_the_browser() {
    init();
    let idp = IdpFixture::start(IdpOptions::default()).await.unwrap();
    idp.set_behavior(AuthorizeBehavior::NoRedirect);
    let engine = Engine::new();
    let ctx = oauth_ctx(&idp);
    let cancel = CancellationToken::new();
    let c2 = cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(200)).await;
        c2.cancel();
    });
    let events = Events::new();
    let r = authorize_api(&engine, &ctx, &Browser::new(None).opener(), &events.observer(), &FlowOptions::default(), &cancel).await;
    assert!(matches!(r, Err(FlowError::Canceled)), "{r:?}");
    assert!(matches!(events.all().last(), Some(FlowEvent::Failed { kind: anvil_identity::FlowErrorKind::Canceled, .. })));
    assert!(idp.grants_seen().is_empty());
}

#[tokio::test]
async fn denied_authorization_is_reported_without_exchange() {
    init();
    let idp = IdpFixture::start(IdpOptions::default()).await.unwrap();
    idp.set_behavior(AuthorizeBehavior::Deny);
    let engine = Engine::new();
    let r = authorize_api(
        &engine,
        &oauth_ctx(&idp),
        &Browser::new(None).opener(),
        &anvil_identity::NoEvents,
        &FlowOptions::default(),
        &CancellationToken::new(),
    )
    .await;
    assert!(matches!(&r, Err(FlowError::AuthorizationDenied(c)) if c == "access_denied"), "{r:?}");
    assert!(idp.grants_seen().is_empty());
}

#[tokio::test]
async fn auth_014_expired_token_is_refreshed_then_revoked_refresh_requires_sign_in() {
    init();
    let idp = IdpFixture::start(IdpOptions { access_token_ttl_secs: 1, ..Default::default() }).await.unwrap();
    let engine = Engine::new();
    let ctx = oauth_ctx(&idp);
    authorize_api(
        &engine,
        &ctx,
        &Browser::new(None).opener(),
        &anvil_identity::NoEvents,
        &FlowOptions::default(),
        &CancellationToken::new(),
    )
    .await
    .unwrap();
    // A 1 s token is inside the 30 s refresh skew: the next send refreshes first.
    idp.set_access_token_ttl(3600);
    let o = send(&engine, &ctx).await;
    assert_eq!(o.record.response.as_ref().map(|r| r.status), Some(200), "{:?}", o.record.findings);
    assert_eq!(idp.grants_seen(), vec!["authorization_code".to_string(), "refresh_token".to_string()]);
    assert_eq!(idp.api_requests(), (1, 1));

    // Expired again and the issuer revoked the refresh token: sign in again,
    // nothing sent, and still never a client-credentials grant.
    idp.set_access_token_ttl(1);
    let _ = api_oauth::sign_out(&engine, &ctx);
    authorize_api(
        &engine,
        &ctx,
        &Browser::new(None).opener(),
        &anvil_identity::NoEvents,
        &FlowOptions::default(),
        &CancellationToken::new(),
    )
    .await
    .unwrap();
    idp.revoke_refresh_tokens();
    let o = send(&engine, &ctx).await;
    assert_eq!(failure_kind(&o), Some(FailureKind::OAuthInteractionRequired));
    let f = o.record.findings.iter().find(|f| f.code == "local.oauth_interaction_required").unwrap();
    assert!(f.explanation.contains("invalid_grant"), "{}", f.explanation);
    assert_eq!(idp.api_requests(), (1, 1), "not sent");
    assert!(!idp.grants_seen().iter().any(|g| g == "client_credentials"));
}

#[tokio::test]
async fn auth_015_issuer_outage_during_refresh_is_a_dependency_failure() {
    init();
    let idp = IdpFixture::start(IdpOptions { access_token_ttl_secs: 1, ..Default::default() }).await.unwrap();
    let engine = Engine::new();
    let ctx = oauth_ctx(&idp);
    authorize_api(
        &engine,
        &ctx,
        &Browser::new(None).opener(),
        &anvil_identity::NoEvents,
        &FlowOptions::default(),
        &CancellationToken::new(),
    )
    .await
    .unwrap();
    idp.set_token_endpoint_down(true);
    let o = send(&engine, &ctx).await;
    assert_eq!(failure_kind(&o), Some(FailureKind::AuthPreparationFailed));
    assert_eq!(o.record.outcome.dispatch, DispatchState::NotDispatched);
    assert_eq!(idp.api_requests(), (0, 0));
    // Recovery: the kept refresh token works once the issuer is back.
    idp.set_token_endpoint_down(false);
    idp.set_access_token_ttl(3600);
    let o = send(&engine, &ctx).await;
    assert_eq!(o.record.response.as_ref().map(|r| r.status), Some(200));
}

#[tokio::test]
async fn code_exchange_uses_the_request_tls_profile() {
    init();
    let pki = anvil_fixtures::LabPki::generate();
    let tls = anvil_fixtures::TlsServerOptions::new(pki.server.chain_with(&pki.ca), pki.server.key.clone());
    let idp = IdpFixture::start(IdpOptions { tls: Some(tls), ..Default::default() }).await.unwrap();
    let engine = Engine::new();

    // Without the lab CA the engine's strict default trust refuses the issuer.
    let ctx = oauth_ctx(&idp);
    let r = authorize_api(
        &engine,
        &ctx,
        &Browser::new(Some(pki.ca.cert.clone())).opener(),
        &anvil_identity::NoEvents,
        &FlowOptions::default(),
        &CancellationToken::new(),
    )
    .await;
    assert!(matches!(&r, Err(FlowError::Exchange(m)) if m.contains("Tls")), "{r:?}");
    assert!(idp.grants_seen().is_empty(), "the TLS handshake failed before any token request");

    // With the request's TLS profile trusting the lab CA, the same flow works.
    let mut ctx = oauth_ctx(&idp);
    let profile = TlsProfile {
        id: anvil_domain::Id::new(),
        workspace_id: anvil_domain::Id::new(),
        name: "lab issuer".into(),
        verify: true,
        use_system_roots: false,
        extra_roots_pem: vec![pki.ca.cert.clone()],
        client_identity: None,
        bindings: vec![],
        min_version: TlsMinVersion::Tls12,
        server_name_override: None,
        server_spiffe: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    ctx.settings_layers.push(("run".into(), SettingsOverrides { tls_profile_id: Some(profile.id), ..Default::default() }));
    ctx.tls_profiles.push(profile);
    authorize_api(
        &engine,
        &ctx,
        &Browser::new(Some(pki.ca.cert.clone())).opener(),
        &anvil_identity::NoEvents,
        &FlowOptions::default(),
        &CancellationToken::new(),
    )
    .await
    .expect("exchange over the profile's trust");
    let o = send(&engine, &ctx).await;
    assert_eq!(o.record.response.as_ref().map(|r| r.status), Some(200), "{:?}", o.record.findings);
}

#[tokio::test]
async fn non_interactive_or_insecure_profiles_are_refused_before_any_browser() {
    init();
    let idp = IdpFixture::start(IdpOptions::default()).await.unwrap();
    let engine = Engine::new();
    let opened = Arc::new(Mutex::new(0));
    let o2 = opened.clone();
    let opener = move |_: &str| -> Result<(), String> {
        *o2.lock().unwrap() += 1;
        Ok(())
    };
    let run = |ctx: ExecutionContext| {
        let (engine, opener) = (&engine, &opener);
        async move { authorize_api(engine, &ctx, opener, &anvil_identity::NoEvents, &FlowOptions::default(), &CancellationToken::new()).await }
    };
    let mut cc = oauth_ctx(&idp);
    if let AuthConfig::OAuth2 { config } = &mut cc.spec.auth {
        config.grant = OAuthGrant::ClientCredentials;
    }
    cc.auth_layers = vec![("request".into(), cc.spec.auth.clone())];
    assert!(matches!(run(cc).await, Err(FlowError::Configuration(m)) if m.contains("client-credentials")));

    let mut insecure = oauth_ctx(&idp);
    if let AuthConfig::OAuth2 { config } = &mut insecure.spec.auth {
        config.authorization_url = "http://issuer.example/authorize".into();
    }
    insecure.auth_layers = vec![("request".into(), insecure.spec.auth.clone())];
    assert!(matches!(run(insecure).await, Err(FlowError::Configuration(m)) if m.contains("https")));

    let mut none = oauth_ctx(&idp);
    none.auth_layers = vec![("request".into(), AuthConfig::None)];
    assert!(matches!(run(none).await, Err(FlowError::Configuration(_))));
    assert_eq!(*opened.lock().unwrap(), 0);
    assert_eq!(idp.authorize_requests(), 0);
}

#[tokio::test]
async fn session_protocols_get_the_same_typed_failure_before_any_handshake() {
    use anvil_domain::request::{Protocol, WsBootstrap, WsMessage, WsSpec};
    init();
    let idp = IdpFixture::start(IdpOptions::default()).await.unwrap();
    let ws_server = anvil_fixtures::http::serve("127.0.0.1:0", None).await.unwrap();
    let mut ctx = oauth_ctx(&idp);
    ctx.spec.protocol = Protocol::WebSocket;
    ctx.spec.url = format!("ws://{}/ws", ws_server.addr);
    ctx.spec.websocket = Some(WsSpec {
        bootstrap: WsBootstrap::Http1Upgrade,
        subprotocols: vec![],
        messages: vec![WsMessage::Text { text: "hello".into() }],
        expect_messages: 0,
        max_message_bytes: 1024,
        idle_close_ms: 500,
    });
    let o = send(&Engine::new(), &ctx).await;
    assert_eq!(failure_kind(&o), Some(FailureKind::OAuthInteractionRequired), "{:?}", o.record.findings);
    assert!(o.record.findings.iter().any(|f| f.code == "local.oauth_interaction_required"));
    assert_eq!(ws_server.log.count_requests(), 0, "no WebSocket handshake was attempted");
    assert!(idp.grants_seen().is_empty());
}
