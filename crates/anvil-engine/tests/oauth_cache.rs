//! OAuth token cache through `Engine::execute`, over real loopback sockets:
//! a changed profile never reuses a token issued for another grant, audience
//! or authorization URL; a cancel or lock while a token request is in flight
//! wins over the late issuer answer; and a send canceled during a refresh
//! does not lose the refresh token the issuer rotated. A workspace delete
//! forgets that workspace's tokens only, wins over its token requests in
//! flight, and a workspace restored with the same id never gets a token
//! from before the delete; an execution or sign-in whose context was built
//! before the delete caches nothing for the workspace.
//!
//! The fixture is one HTTP/1.1 listener serving `/token` (a scriptable
//! issuer that can hold its answer) and `/api` (records the Authorization
//! header it receives). Its counters only check that conditions were reached.

use anvil_auth::oauth::{CachedToken, TokenKey};
use anvil_domain::auth::{AuthConfig, OAuth2Config, OAuthClientAuth, OAuthGrant};
use anvil_domain::execution::{DispatchState, FailureKind};
use anvil_domain::request::RequestSpec;
use anvil_domain::secret::SensitiveValue;
use anvil_engine::oauth_http::{interactive_oauth, redeem_authorization_code, sign_in_generation};
use anvil_engine::{Engine, ExecutionContext, ExecutionOutput};
use anvil_transport::recorder::EventCtx;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

#[derive(Default)]
struct Fixture {
    token_requests: AtomicU64,
    /// Token answers written, each counted once its client closed the
    /// connection: the client is then done with it.
    token_answers: AtomicU64,
    token_forms: Mutex<Vec<String>>,
    api_authorization: Mutex<Vec<String>>,
    /// Hold every token answer until `release` is notified.
    hold: AtomicBool,
    received: Notify,
    release: Notify,
    /// Answer token requests with 503.
    issuer_down: AtomicBool,
    /// Issue a new refresh token (`rt-<n>`) with every token, as a rotating
    /// issuer does.
    rotate: AtomicBool,
}

impl Fixture {
    async fn start() -> (SocketAddr, Arc<Fixture>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let fx = Arc::new(Fixture::default());
        let state = fx.clone();
        tokio::spawn(async move {
            while let Ok((sock, _)) = listener.accept().await {
                tokio::spawn(serve(sock, state.clone()));
            }
        });
        (addr, fx)
    }

    fn api_hits(&self) -> Vec<String> {
        self.api_authorization.lock().unwrap().clone()
    }
}

fn header(head: &str, name: &str) -> Option<String> {
    head.lines().skip(1).find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.trim().eq_ignore_ascii_case(name).then(|| v.trim().to_string())
    })
}

async fn serve(mut sock: TcpStream, fx: Arc<Fixture>) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        match sock.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let len = header(&head, "content-length").and_then(|v| v.parse::<usize>().ok()).unwrap_or(0);
    while buf.len() < head_end + len {
        match sock.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
    let path = head.split_whitespace().nth(1).unwrap_or("").to_string();
    let (status, body) = if path == "/token" {
        let n = fx.token_requests.fetch_add(1, Ordering::SeqCst) + 1;
        fx.token_forms.lock().unwrap().push(String::from_utf8_lossy(&buf[head_end..head_end + len]).to_string());
        if fx.hold.load(Ordering::SeqCst) {
            fx.received.notify_one();
            fx.release.notified().await;
        }
        if fx.issuer_down.load(Ordering::SeqCst) {
            ("503 Service Unavailable", r#"{"error":"temporarily_unavailable"}"#.to_string())
        } else {
            let refresh = if fx.rotate.load(Ordering::SeqCst) { format!(r#","refresh_token":"rt-{n}""#) } else { String::new() };
            ("200 OK", format!(r#"{{"access_token":"late-or-live-{n}","token_type":"Bearer","expires_in":3600{refresh}}}"#))
        }
    } else {
        fx.api_authorization.lock().unwrap().push(header(&head, "authorization").unwrap_or_default());
        ("200 OK", "{}".to_string())
    };
    let response = format!("HTTP/1.1 {status}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len());
    let _ = sock.write_all(response.as_bytes()).await;
    let _ = sock.shutdown().await;
    if path == "/token" {
        while matches!(sock.read(&mut chunk).await, Ok(n) if n > 0) {}
        fx.token_answers.fetch_add(1, Ordering::SeqCst);
    }
}

fn oauth(addr: SocketAddr, grant: OAuthGrant, audience: &str) -> OAuth2Config {
    OAuth2Config {
        grant,
        token_url: format!("http://{addr}/token"),
        authorization_url: format!("http://{addr}/authorize"),
        client_id: "client".into(),
        client_secret: SensitiveValue::default(),
        scope: "api.read".into(),
        audience: audience.into(),
        client_auth: OAuthClientAuth::RequestBody,
        token_cache_id: None,
        refresh_skew_secs: 30,
    }
}

#[tokio::test]
async fn nonliteral_cleartext_issuers_fail_before_any_token_or_api_request_for_all_grants() {
    anvil_transport::init();
    let (addr, fx) = Fixture::start().await;
    for grant in [
        OAuthGrant::ClientCredentials,
        OAuthGrant::RefreshToken,
        OAuthGrant::AuthorizationCodePkce,
    ] {
        let mut config = oauth(addr, grant, "api-a");
        config.token_url = format!("http://issuer.test:{}/token", addr.port());
        config.client_secret = SensitiveValue::template("unused-credential-canary");
        let mut c = ctx(addr, config);
        c.settings_layers.push((
            "test".into(),
            anvil_domain::settings::SettingsOverrides {
                dns_overrides: vec![anvil_domain::settings::DnsOverride {
                    host: "issuer.test".into(),
                    addresses: vec!["127.0.0.1".into()],
                }],
                ..Default::default()
            },
        ));
        let o = send(&Engine::new(), &c).await;
        assert_eq!(failure_kind(&o), Some(FailureKind::AuthPreparationFailed));
        assert!(!serde_json::to_string(&o.record).unwrap().contains("unused-credential-canary"));
    }
    assert_eq!(fx.token_requests.load(Ordering::SeqCst), 0);
    assert!(fx.token_forms.lock().unwrap().is_empty());
    assert!(fx.api_hits().is_empty());
}

#[tokio::test]
async fn https_issuer_acquisition_still_uses_configured_trust_and_delivers_a_token() {
    anvil_transport::init();
    anvil_fixtures::init();
    let pki = anvil_fixtures::LabPki::generate();
    let tls = anvil_fixtures::TlsServerOptions::new(
        pki.server.chain_with(&pki.ca),
        pki.server.key.clone(),
    );
    let issuer = anvil_fixtures::http::serve("127.0.0.1:0", Some(tls)).await.unwrap();
    let (addr, fx) = Fixture::start().await;
    let mut config = oauth(addr, OAuthGrant::ClientCredentials, "api-a");
    config.token_url = format!("https://api.anvil.test:{}/oauth/token", issuer.addr.port());
    config.client_id = "anvil-client".into();
    config.client_secret = SensitiveValue::template("anvil-secret");
    config.client_auth = OAuthClientAuth::BasicHeader;
    let mut c = ctx(addr, config);
    let profile = anvil_domain::tls::TlsProfile {
        id: anvil_domain::Id::new(),
        workspace_id: anvil_domain::Id::new(),
        name: "issuer-trust".into(),
        verify: true,
        use_system_roots: false,
        extra_roots_pem: vec![pki.ca.cert.clone()],
        client_identity: None,
        bindings: vec![],
        min_version: anvil_domain::tls::TlsMinVersion::Tls12,
        server_name_override: None,
        server_spiffe: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    c.settings_layers.push((
        "test".into(),
        anvil_domain::settings::SettingsOverrides {
            tls_profile_id: Some(profile.id),
            dns_overrides: vec![anvil_domain::settings::DnsOverride {
                host: "api.anvil.test".into(),
                addresses: vec!["127.0.0.1".into()],
            }],
            ..Default::default()
        },
    ));
    c.tls_profiles.push(profile);
    let o = send(&Engine::new(), &c).await;
    assert_eq!(status(&o), Some(200));
    assert_eq!(*issuer.state.oauth_token_requests.lock(), 1);
    assert_eq!(fx.api_hits(), vec!["Bearer fx-token-1".to_string()]);
    assert!(!serde_json::to_string(&o.record).unwrap().contains("anvil-secret"));
    issuer.shutdown();
}

fn ctx(addr: SocketAddr, config: OAuth2Config) -> ExecutionContext {
    let mut spec = RequestSpec::http("GET", &format!("http://{addr}/api"));
    spec.auth = AuthConfig::OAuth2 { config };
    let mut ctx = ExecutionContext::standalone(spec);
    ctx.isolation = "workspace-under-test".into();
    ctx
}

async fn send(engine: &Engine, ctx: &ExecutionContext) -> ExecutionOutput {
    engine.execute(ctx, EventCtx::none(), CancellationToken::new()).await
}

fn token(access: &str, refresh: &str, expires_in_secs: i64) -> CachedToken {
    CachedToken {
        access_token: Zeroizing::new(access.into()),
        token_type: "Bearer".into(),
        expires_at: Some(chrono::Utc::now() + chrono::Duration::seconds(expires_in_secs)),
        refresh_token: Some(Zeroizing::new(refresh.into())),
    }
}

/// Cache `t` for the profile of `ctx`, as a completed browser sign-in does.
fn sign_in(engine: &Engine, ctx: &ExecutionContext, t: CachedToken) {
    let target = interactive_oauth(ctx).unwrap();
    let key = target.cache_key();
    assert!(engine.tokens.store_sign_in(key, engine.tokens.generation(key), t));
}

/// `c` in `isolation`.
fn in_workspace(mut c: ExecutionContext, isolation: &str) -> ExecutionContext {
    c.isolation = isolation.into();
    c
}

/// `c` with its epoch taken now, as the app takes it when it builds a
/// context from storage.
fn built_now(engine: &Engine, c: &ExecutionContext) -> ExecutionContext {
    let mut c = c.clone();
    c.epoch = Some(engine.context_epoch(&c.isolation));
    c
}

fn failure_kind(o: &ExecutionOutput) -> Option<FailureKind> {
    o.record.attempts.last().and_then(|a| a.failure.as_ref()).map(|f| f.kind)
}

fn status(o: &ExecutionOutput) -> Option<u16> {
    o.record.response.as_ref().map(|r| r.status)
}

#[tokio::test]
async fn switching_to_an_interactive_grant_never_sends_the_client_credentials_token() {
    anvil_transport::init();
    let (addr, fx) = Fixture::start().await;
    let engine = Engine::new();

    let o = send(&engine, &ctx(addr, oauth(addr, OAuthGrant::ClientCredentials, "api-a"))).await;
    assert_eq!(status(&o), Some(200), "{:?}", o.record.findings);
    assert_eq!(fx.api_hits(), vec!["Bearer late-or-live-1".to_string()]);

    // Same token URL, client, scope and isolation; now an interactive grant.
    for audience in ["api-b", "api-a"] {
        let o = send(&engine, &ctx(addr, oauth(addr, OAuthGrant::AuthorizationCodePkce, audience))).await;
        assert_eq!(failure_kind(&o), Some(FailureKind::OAuthInteractionRequired), "audience {audience}");
        assert_eq!(o.record.outcome.dispatch, DispatchState::NotDispatched);
    }
    assert_eq!(fx.api_hits().len(), 1, "the API request was not sent with the other profile's token");
    assert_eq!(fx.token_requests.load(Ordering::SeqCst), 1, "no grant was substituted");
}

#[tokio::test]
async fn switching_audience_acquires_a_token_for_the_new_audience() {
    anvil_transport::init();
    let (addr, fx) = Fixture::start().await;
    let engine = Engine::new();
    let a = ctx(addr, oauth(addr, OAuthGrant::ClientCredentials, "api-a"));
    let b = ctx(addr, oauth(addr, OAuthGrant::ClientCredentials, "api-b"));

    assert_eq!(status(&send(&engine, &a).await), Some(200));
    assert_eq!(status(&send(&engine, &b).await), Some(200));
    assert_eq!(fx.token_requests.load(Ordering::SeqCst), 2, "api-b got its own token");
    assert!(fx.token_forms.lock().unwrap()[1].contains("audience=api-b"));
    // Each audience keeps its own cached token.
    assert_eq!(status(&send(&engine, &a).await), Some(200));
    assert_eq!(status(&send(&engine, &b).await), Some(200));
    assert_eq!(fx.token_requests.load(Ordering::SeqCst), 2);
    let hits = fx.api_hits();
    assert_eq!(hits, ["Bearer late-or-live-1", "Bearer late-or-live-2", "Bearer late-or-live-1", "Bearer late-or-live-2"]);
}

#[tokio::test]
async fn cancel_and_lock_during_token_request_end_promptly_and_leave_nothing_cached() {
    anvil_transport::init();
    let (addr, fx) = Fixture::start().await;
    let engine = Arc::new(Engine::new());
    let c = ctx(addr, oauth(addr, OAuthGrant::ClientCredentials, "api-a"));
    fx.hold.store(true, Ordering::SeqCst);

    let cancel = CancellationToken::new();
    let run = {
        let (engine, c, cancel) = (engine.clone(), c.clone(), cancel.clone());
        tokio::spawn(async move { engine.execute(&c, EventCtx::none(), cancel).await })
    };
    fx.received.notified().await;
    // What a lock does: cancel executions, then clear the engine.
    cancel.cancel();
    engine.clear_sensitive_state();
    let o = tokio::time::timeout(Duration::from_secs(5), run)
        .await
        .expect("the canceled execution ended while the issuer was still holding its answer")
        .unwrap();
    assert_eq!(failure_kind(&o), Some(FailureKind::Canceled));
    assert_eq!(o.record.outcome.dispatch, DispatchState::NotDispatched);

    // The issuer answers late, then becomes unavailable.
    fx.release.notify_one();
    tokio::time::sleep(Duration::from_millis(100)).await;
    fx.hold.store(false, Ordering::SeqCst);
    fx.issuer_down.store(true, Ordering::SeqCst);
    let o = send(&engine, &c).await;
    assert_eq!(failure_kind(&o), Some(FailureKind::AuthPreparationFailed), "no cached token survived the lock");
    assert!(fx.api_hits().is_empty(), "the API never received a token");
}

#[tokio::test]
async fn lock_during_token_request_discards_the_late_token() {
    anvil_transport::init();
    let (addr, fx) = Fixture::start().await;
    let engine = Arc::new(Engine::new());
    let c = ctx(addr, oauth(addr, OAuthGrant::ClientCredentials, "api-a"));
    fx.hold.store(true, Ordering::SeqCst);

    // An execution nobody cancels: only the clear stands between the late
    // answer and the cache.
    let run = {
        let (engine, c) = (engine.clone(), c.clone());
        tokio::spawn(async move { send(&engine, &c).await })
    };
    fx.received.notified().await;
    engine.clear_sensitive_state();
    fx.release.notify_one();
    let o = tokio::time::timeout(Duration::from_secs(10), run).await.expect("the execution finished").unwrap();
    assert_eq!(failure_kind(&o), Some(FailureKind::Canceled), "{:?}", o.record.attempts);
    assert_eq!(o.record.outcome.dispatch, DispatchState::NotDispatched, "the late token was not sent");

    fx.hold.store(false, Ordering::SeqCst);
    fx.issuer_down.store(true, Ordering::SeqCst);
    let o = send(&engine, &c).await;
    assert_eq!(failure_kind(&o), Some(FailureKind::AuthPreparationFailed), "the late token did not repopulate the cache");
    assert!(fx.api_hits().is_empty());
}

#[tokio::test]
async fn a_sign_in_through_one_authorization_url_is_never_sent_for_another() {
    anvil_transport::init();
    let (addr, fx) = Fixture::start().await;
    let engine = Engine::new();
    // Identical profiles except for the organization the sign-in selects.
    let with_org = |org: &str| {
        let mut config = oauth(addr, OAuthGrant::AuthorizationCodePkce, "api-a");
        config.authorization_url = format!("http://{addr}/authorize?organization={org}");
        ctx(addr, config)
    };
    let (org_a, org_b) = (with_org("org-a"), with_org("org-b"));
    sign_in(&engine, &org_a, token("org-a-token", "org-a-rt", 3600));

    assert_eq!(status(&send(&engine, &org_a).await), Some(200));
    let o = send(&engine, &org_b).await;
    assert_eq!(failure_kind(&o), Some(FailureKind::OAuthInteractionRequired));
    assert_eq!(o.record.outcome.dispatch, DispatchState::NotDispatched);
    assert_eq!(fx.api_hits(), ["Bearer org-a-token"], "org-b never received org-a's token");
    assert_eq!(fx.token_requests.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn canceling_a_send_during_a_refresh_keeps_the_rotated_refresh_token() {
    anvil_transport::init();
    let (addr, fx) = Fixture::start().await;
    let engine = Arc::new(Engine::new());
    let c = ctx(addr, oauth(addr, OAuthGrant::AuthorizationCodePkce, "api-a"));
    sign_in(&engine, &c, token("expired", "rt-0", -10));
    fx.rotate.store(true, Ordering::SeqCst);
    fx.hold.store(true, Ordering::SeqCst);

    let cancel = CancellationToken::new();
    let run = {
        let (engine, c, cancel) = (engine.clone(), c.clone(), cancel.clone());
        tokio::spawn(async move { engine.execute(&c, EventCtx::none(), cancel).await })
    };
    fx.received.notified().await;
    assert!(fx.token_forms.lock().unwrap()[0].contains("refresh_token=rt-0"));
    cancel.cancel();
    let o = tokio::time::timeout(Duration::from_secs(5), run)
        .await
        .expect("the canceled send ended while the issuer was still holding its answer")
        .unwrap();
    assert_eq!(failure_kind(&o), Some(FailureKind::Canceled));
    assert_eq!(o.record.outcome.dispatch, DispatchState::NotDispatched);

    // The issuer rotates the refresh token after the send gave up; the
    // refresh still lands in the cache.
    fx.hold.store(false, Ordering::SeqCst);
    fx.release.notify_one();
    let key = interactive_oauth(&c).unwrap().cache_key().clone();
    let stored = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(t) = engine.tokens.get(&key).filter(|t| t.access_token.as_str() == "late-or-live-1") {
                break t;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the refresh finished after its caller stopped waiting");
    assert_eq!(stored.refresh_token.as_ref().map(|rt| rt.as_str()), Some("rt-1"), "the rotated refresh token was kept");

    // The next send uses it without presenting rt-0 again.
    let o = send(&engine, &c).await;
    assert_eq!(status(&o), Some(200), "{:?}", o.record.attempts);
    assert_eq!(fx.api_hits(), ["Bearer late-or-live-1"]);
    assert_eq!(fx.token_requests.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_workspace_delete_forgets_its_tokens_and_a_restored_workspace_acquires_its_own() {
    anvil_transport::init();
    let (addr, fx) = Fixture::start().await;
    let engine = Engine::new();
    let a = ctx(addr, oauth(addr, OAuthGrant::ClientCredentials, "api-a"));
    let b = in_workspace(a.clone(), "workspace-b");
    let signed_in_a = ctx(addr, oauth(addr, OAuthGrant::AuthorizationCodePkce, "api-a"));
    sign_in(&engine, &signed_in_a, token("signed-in-a", "rt-a", 3600));

    for c in [&a, &b, &a, &b, &signed_in_a] {
        assert_eq!(status(&send(&engine, c).await), Some(200));
    }
    assert_eq!(fx.token_requests.load(Ordering::SeqCst), 2, "each workspace cached its own token");
    let key = |c: &ExecutionContext| interactive_oauth(c).unwrap().cache_key().clone();
    assert!(engine.tokens.get(&key(&signed_in_a)).is_some());

    engine.clear_isolation("workspace-under-test");
    assert!(engine.tokens.get(&key(&signed_in_a)).is_none(), "the sign-in survived its workspace's delete");

    // Restored with the same id: the sign-in is gone and a new token is
    // acquired; workspace-b keeps its token.
    let o = send(&engine, &signed_in_a).await;
    assert_eq!(failure_kind(&o), Some(FailureKind::OAuthInteractionRequired));
    assert_eq!(o.record.outcome.dispatch, DispatchState::NotDispatched);
    assert_eq!(status(&send(&engine, &a).await), Some(200));
    assert_eq!(status(&send(&engine, &b).await), Some(200));
    assert_eq!(fx.token_requests.load(Ordering::SeqCst), 3);
    let hits = fx.api_hits();
    assert_eq!(
        hits,
        [
            "Bearer late-or-live-1",
            "Bearer late-or-live-2",
            "Bearer late-or-live-1",
            "Bearer late-or-live-2",
            "Bearer signed-in-a",
            "Bearer late-or-live-3",
            "Bearer late-or-live-2",
        ]
    );
}

#[tokio::test]
async fn a_workspace_delete_during_a_token_request_discards_the_late_token() {
    anvil_transport::init();
    let (addr, fx) = Fixture::start().await;
    let engine = Arc::new(Engine::new());
    let c = ctx(addr, oauth(addr, OAuthGrant::ClientCredentials, "api-a"));
    fx.hold.store(true, Ordering::SeqCst);

    let run = {
        let (engine, c) = (engine.clone(), c.clone());
        tokio::spawn(async move { send(&engine, &c).await })
    };
    fx.received.notified().await;
    engine.clear_isolation("workspace-under-test");
    fx.release.notify_one();
    let o = tokio::time::timeout(Duration::from_secs(10), run).await.expect("the execution finished").unwrap();
    assert_eq!(failure_kind(&o), Some(FailureKind::Canceled), "{:?}", o.record.attempts);
    assert_eq!(o.record.outcome.dispatch, DispatchState::NotDispatched, "the late token was not sent");

    // The restored workspace finds nothing cached.
    fx.hold.store(false, Ordering::SeqCst);
    fx.issuer_down.store(true, Ordering::SeqCst);
    let o = send(&engine, &c).await;
    assert_eq!(failure_kind(&o), Some(FailureKind::AuthPreparationFailed), "the late token repopulated the cache");
    assert!(fx.api_hits().is_empty());
}

/// A refresh the send stopped waiting for runs on: the delete aborts it, and
/// its rotated token is not stored for the restored workspace.
#[tokio::test]
async fn a_workspace_delete_aborts_a_detached_refresh() {
    anvil_transport::init();
    let (addr, fx) = Fixture::start().await;
    let engine = Arc::new(Engine::new());
    let c = ctx(addr, oauth(addr, OAuthGrant::AuthorizationCodePkce, "api-a"));
    sign_in(&engine, &c, token("expired", "rt-0", -10));
    fx.rotate.store(true, Ordering::SeqCst);
    fx.hold.store(true, Ordering::SeqCst);

    let cancel = CancellationToken::new();
    let run = {
        let (engine, c, cancel) = (engine.clone(), c.clone(), cancel.clone());
        tokio::spawn(async move { engine.execute(&c, EventCtx::none(), cancel).await })
    };
    fx.received.notified().await;
    cancel.cancel();
    let o = tokio::time::timeout(Duration::from_secs(5), run).await.expect("the canceled send ended").unwrap();
    assert_eq!(failure_kind(&o), Some(FailureKind::Canceled));
    engine.clear_isolation("workspace-under-test");
    fx.hold.store(false, Ordering::SeqCst);
    fx.release.notify_one();
    tokio::time::timeout(Duration::from_secs(5), async {
        while fx.token_answers.load(Ordering::SeqCst) < 1 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the issuer answered the refresh and its client closed the connection");

    let key = interactive_oauth(&c).unwrap().cache_key().clone();
    assert!(engine.tokens.get(&key).is_none(), "the refresh stored its token after the workspace delete");
    let o = send(&engine, &c).await;
    assert_eq!(failure_kind(&o), Some(FailureKind::OAuthInteractionRequired));
    assert!(fx.api_hits().is_empty());
}

/// Contexts built before their workspace's delete and executed only after
/// it: a client-credentials token is acquired for the send only, nothing is
/// cached for the workspace, and a token the restored workspace cached is
/// never sent for them.
#[tokio::test]
async fn an_execution_whose_context_was_built_before_its_workspace_delete_caches_no_token() {
    anvil_transport::init();
    let (addr, fx) = Fixture::start().await;
    let engine = Engine::new();
    let cc = ctx(addr, oauth(addr, OAuthGrant::ClientCredentials, "api-a"));
    let pkce = ctx(addr, oauth(addr, OAuthGrant::AuthorizationCodePkce, "api-a"));
    let (stale_cc, stale_pkce) = (built_now(&engine, &cc), built_now(&engine, &pkce));
    engine.clear_isolation("workspace-under-test");

    assert_eq!(status(&send(&engine, &stale_cc).await), Some(200));
    // The key the engine caches `cc`'s token under.
    let cc_key = TokenKey {
        partition: "workspace-under-test".into(),
        token_url: format!("http://{addr}/token"),
        authorization_url: String::new(),
        client_id: "client".into(),
        basic_client_auth: false,
        grant: OAuthGrant::ClientCredentials,
        audience: "api-a".into(),
        scope: "api.read".into(),
        token_cache_id: None,
    };
    assert!(engine.tokens.get(&cc_key).is_none(), "a token was cached for the deleted workspace");

    // The restored workspace caches its own tokens; the stale contexts never
    // use them.
    assert_eq!(status(&send(&engine, &built_now(&engine, &cc)).await), Some(200));
    sign_in(&engine, &pkce, token("restored", "rt", 3600));
    assert_eq!(status(&send(&engine, &stale_cc).await), Some(200));
    let o = send(&engine, &stale_pkce).await;
    assert_eq!(failure_kind(&o), Some(FailureKind::OAuthInteractionRequired), "the restored workspace's sign-in was used");
    assert_eq!(fx.token_requests.load(Ordering::SeqCst), 3, "every stale send acquired its own token");
    assert_eq!(fx.api_hits(), ["Bearer late-or-live-1", "Bearer late-or-live-2", "Bearer late-or-live-3"]);
    assert_eq!(engine.tokens.get(&cc_key).unwrap().access_token.as_str(), "late-or-live-2", "the restored workspace's token was kept");
}

/// A sign-in to a workspace deleted after its context was built redeems
/// nothing, and one whose workspace is deleted while it runs stores nothing.
#[tokio::test]
async fn a_sign_in_across_its_workspace_delete_caches_no_token() {
    anvil_transport::init();
    let (addr, fx) = Fixture::start().await;
    let engine = Engine::new();
    let c = ctx(addr, oauth(addr, OAuthGrant::AuthorizationCodePkce, "api-a"));
    let redirect = "http://127.0.0.1:1/callback";
    let never = CancellationToken::new();

    // Built before the delete, redeemed after it.
    let built = built_now(&engine, &c);
    let target = interactive_oauth(&built).unwrap();
    let generation = sign_in_generation(&engine, &target);
    engine.clear_isolation("workspace-under-test");
    let r = redeem_authorization_code(&engine, &built, &target, generation, "code", "verifier", redirect, &never).await;
    assert!(matches!(r, Err(anvil_auth::AuthError::Canceled(_))), "{r:?}");
    assert_eq!(fx.token_requests.load(Ordering::SeqCst), 0, "the code was redeemed for the deleted workspace");

    // The browser step spans the delete.
    let target = interactive_oauth(&c).unwrap();
    let generation = sign_in_generation(&engine, &target);
    engine.clear_isolation("workspace-under-test");
    let r = redeem_authorization_code(&engine, &c, &target, generation, "code", "verifier", redirect, &never).await;
    assert!(matches!(r, Err(anvil_auth::AuthError::Canceled(_))), "{r:?}");
    assert_eq!(fx.token_requests.load(Ordering::SeqCst), 1);
    assert!(engine.tokens.get(target.cache_key()).is_none(), "the redeemed token was cached after the delete");
}
