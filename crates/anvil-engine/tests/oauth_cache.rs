//! OAuth token cache through `Engine::execute`, over real loopback sockets:
//! a changed profile never reuses a token issued for another grant or
//! audience, and a cancel or lock while a token request is in flight wins
//! over the late issuer answer.
//!
//! The fixture is one HTTP/1.1 listener serving `/token` (a scriptable
//! issuer that can hold its answer) and `/api` (records the Authorization
//! header it receives). Its counters only check that conditions were reached.

use anvil_domain::auth::{AuthConfig, OAuth2Config, OAuthClientAuth, OAuthGrant};
use anvil_domain::execution::{DispatchState, FailureKind};
use anvil_domain::request::RequestSpec;
use anvil_domain::secret::SensitiveValue;
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

#[derive(Default)]
struct Fixture {
    token_requests: AtomicU64,
    token_forms: Mutex<Vec<String>>,
    api_authorization: Mutex<Vec<String>>,
    /// Hold every token answer until `release` is notified.
    hold: AtomicBool,
    received: Notify,
    release: Notify,
    /// Answer token requests with 503.
    issuer_down: AtomicBool,
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
            ("200 OK", format!(r#"{{"access_token":"late-or-live-{n}","token_type":"Bearer","expires_in":3600}}"#))
        }
    } else {
        fx.api_authorization.lock().unwrap().push(header(&head, "authorization").unwrap_or_default());
        ("200 OK", "{}".to_string())
    };
    let response = format!("HTTP/1.1 {status}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len());
    let _ = sock.write_all(response.as_bytes()).await;
    let _ = sock.shutdown().await;
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
