//! The workspace cookie jar applies to the HTTP-based session handshakes
//! (SSE, WebSocket) as to HTTP requests: stored cookies are sent under the
//! same matching rules and workspace isolation, the handshake's `Set-Cookie`
//! is kept, the cookies setting turns both off, a cookie the request sends
//! itself wins over a stored one of the same name, and the cookies of a
//! session that spans a lock are not kept. Fixture ground truth shows what
//! the server received.

use anvil_domain::auth::{AuthConfig, KeyLocation};
use anvil_domain::request::{KeyValue, Protocol, RequestSpec, SseSpec, WsBootstrap, WsMessage, WsSpec};
use anvil_domain::secret::SensitiveValue;
use anvil_domain::settings::SettingsOverrides;
use anvil_engine::{Engine, ExecutionContext, ExecutionOutput};
use anvil_fixtures::GroundTruth;
use anvil_fixtures::gate;
use anvil_fixtures::http as fx;
use anvil_transport::recorder::EventCtx;
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

fn init() {
    anvil_transport::init();
    anvil_fixtures::init();
}

fn get(url: &str) -> ExecutionContext {
    ExecutionContext::standalone(RequestSpec::http("GET", url))
}

fn sse(url: &str) -> ExecutionContext {
    let mut s = RequestSpec::http("GET", url);
    s.protocol = Protocol::Sse;
    s.sse = Some(SseSpec { max_events: 1, idle_timeout_ms: 5_000, last_event_id: None, reconnect: false });
    ExecutionContext::standalone(s)
}

/// A WebSocket that sends one message; with `close_after=1` in the URL the
/// fixture echoes it and closes.
fn ws(url: &str) -> ExecutionContext {
    let mut s = RequestSpec::http("GET", url);
    s.protocol = Protocol::WebSocket;
    s.websocket = Some(WsSpec {
        bootstrap: WsBootstrap::Http1Upgrade,
        subprotocols: vec![],
        messages: vec![WsMessage::Text { text: "hello".into() }],
        expect_messages: 0,
        max_message_bytes: 1024 * 1024,
        idle_close_ms: 1_000,
        permessage_deflate: Default::default(),
    });
    ExecutionContext::standalone(s)
}

fn cookies_off(mut c: ExecutionContext) -> ExecutionContext {
    c.settings_layers.push(("run".into(), SettingsOverrides { cookies: Some(false), ..Default::default() }));
    c
}

fn in_workspace(mut c: ExecutionContext, isolation: &str) -> ExecutionContext {
    c.isolation = isolation.into();
    c
}

async fn run(e: &Engine, c: &ExecutionContext) -> ExecutionOutput {
    e.execute(c, EventCtx::none(), CancellationToken::new()).await
}

/// Run `c` and check that it reached the server and was answered.
async fn ok(e: &Engine, c: &ExecutionContext) -> ExecutionOutput {
    let o = run(e, c).await;
    let failure = o.record.attempts.last().and_then(|a| a.failure.as_ref());
    assert!(o.record.response.is_some(), "{} got no response: {failure:?}", c.spec.url);
    o
}

/// The `Cookie` header of the last request whose target starts with `path`,
/// `None` when that request carried none. Panics when there was no request.
fn cookie_on(f: &fx::Fixture, path: &str) -> Option<String> {
    let headers = f
        .log
        .entries()
        .into_iter()
        .rev()
        .find_map(|e| match e.event {
            GroundTruth::RequestReceived { path: p, headers, .. } if p.starts_with(path) => Some(headers),
            _ => None,
        })
        .unwrap_or_else(|| panic!("no request to {path}"));
    let cookies: Vec<String> = headers.into_iter().filter(|(n, _)| n.eq_ignore_ascii_case("cookie")).map(|(_, v)| v).collect();
    assert!(cookies.len() <= 1, "several Cookie headers: {cookies:?}");
    cookies.into_iter().next()
}

/// A cookie API key named `sid`.
fn sid_cookie_key() -> AuthConfig {
    AuthConfig::ApiKey { name: "sid".into(), value: SensitiveValue::template("from-auth-key"), location: KeyLocation::Cookie }
}

/// An HTTP login that sets the `sid` cookie.
async fn login(e: &Engine, f: &fx::Fixture) {
    ok(e, &get(&f.url("/set-cookie?name=sid&value=audit-only-session"))).await;
}

#[tokio::test]
async fn an_http_login_cookie_is_sent_on_the_sse_handshake() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    login(&e, &f).await;
    ok(&e, &get(&f.url("/echo"))).await;
    assert_eq!(cookie_on(&f, "/echo").as_deref(), Some("sid=audit-only-session"));
    ok(&e, &sse(&f.url("/sse?count=1&interval=1"))).await;
    assert_eq!(cookie_on(&f, "/sse").as_deref(), Some("sid=audit-only-session"));
}

#[tokio::test]
async fn an_http_login_cookie_is_sent_on_the_websocket_handshake() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    // An HttpOnly cookie, set over http: a ws:// handshake is its HTTP
    // counterpart in the jar and carries it.
    login(&e, &f).await;
    ok(&e, &ws(&format!("ws://{}/ws?close_after=1", f.addr))).await;
    assert_eq!(cookie_on(&f, "/ws").as_deref(), Some("sid=audit-only-session"));
}

#[tokio::test]
async fn set_cookie_on_a_session_handshake_is_kept_in_the_jar() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    let o = ok(&e, &sse(&f.url("/sse?count=1&interval=1&set_cookie=sse_sid%3Dfrom-sse"))).await;
    assert!(o.record.response.as_ref().unwrap().header_values("set-cookie")[0].starts_with("sse_sid="));
    ok(&e, &get(&f.url("/echo"))).await;
    assert_eq!(cookie_on(&f, "/echo").as_deref(), Some("sse_sid=from-sse"));

    let e = Engine::new();
    ok(&e, &ws(&format!("ws://{}/ws?close_after=1&set_cookie=ws_sid%3Dfrom-ws", f.addr))).await;
    ok(&e, &get(&f.url("/echo"))).await;
    assert_eq!(cookie_on(&f, "/echo").as_deref(), Some("ws_sid=from-ws"));
}

#[tokio::test]
async fn with_cookies_off_a_session_neither_sends_nor_keeps_cookies() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    login(&e, &f).await;
    ok(&e, &cookies_off(sse(&f.url("/sse?count=1&interval=1")))).await;
    assert_eq!(cookie_on(&f, "/sse"), None);
    ok(&e, &cookies_off(ws(&format!("ws://{}/ws?close_after=1", f.addr)))).await;
    assert_eq!(cookie_on(&f, "/ws"), None);

    let e = Engine::new();
    ok(&e, &cookies_off(sse(&f.url("/sse?count=1&interval=1&set_cookie=sse_sid%3Dfrom-sse")))).await;
    ok(&e, &cookies_off(ws(&format!("ws://{}/ws?close_after=1&set_cookie=ws_sid%3Dfrom-ws", f.addr)))).await;
    ok(&e, &get(&f.url("/echo"))).await;
    assert_eq!(cookie_on(&f, "/echo"), None, "a session with cookies off stored its Set-Cookie");
}

#[tokio::test]
async fn session_cookies_stay_in_their_workspace() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    ok(&e, &in_workspace(get(&f.url("/set-cookie?name=sid&value=audit-only-session")), "workspace-a")).await;
    ok(&e, &in_workspace(sse(&f.url("/sse?count=1&interval=1")), "workspace-b")).await;
    assert_eq!(cookie_on(&f, "/sse"), None, "a cookie of workspace a was sent for workspace b");
    ok(&e, &in_workspace(ws(&format!("ws://{}/ws?close_after=1", f.addr)), "workspace-b")).await;
    assert_eq!(cookie_on(&f, "/ws"), None, "a cookie of workspace a was sent for workspace b");
    ok(&e, &in_workspace(sse(&f.url("/sse?count=1&interval=1")), "workspace-a")).await;
    assert_eq!(cookie_on(&f, "/sse").as_deref(), Some("sid=audit-only-session"));

    // A session's Set-Cookie is kept for its own workspace only.
    ok(&e, &in_workspace(sse(&f.url("/sse?count=1&interval=1&set_cookie=sse_sid%3Dfrom-b")), "workspace-b")).await;
    ok(&e, &in_workspace(get(&f.url("/echo")), "workspace-a")).await;
    assert_eq!(cookie_on(&f, "/echo").as_deref(), Some("sid=audit-only-session"));
    ok(&e, &in_workspace(get(&f.url("/echo")), "workspace-b")).await;
    assert_eq!(cookie_on(&f, "/echo").as_deref(), Some("sse_sid=from-b"));
}

#[tokio::test]
async fn a_cookie_the_request_sends_itself_wins_over_a_stored_one_of_the_same_name() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    ok(&e, &get(&f.url("/set-cookie?name=sid&value=stored"))).await;
    ok(&e, &get(&f.url("/set-cookie?name=theme&value=dark"))).await;

    // A configured Cookie header: sid once (its own value), theme from the jar.
    let configured = |mut c: ExecutionContext| {
        c.spec.headers.push(KeyValue::new("Cookie", "sid=configured"));
        c
    };
    ok(&e, &configured(get(&f.url("/echo")))).await;
    assert_eq!(cookie_on(&f, "/echo").as_deref(), Some("sid=configured; theme=dark"));
    ok(&e, &configured(sse(&f.url("/sse?count=1&interval=1")))).await;
    assert_eq!(cookie_on(&f, "/sse").as_deref(), Some("sid=configured; theme=dark"));

    // A cookie API key: its cookie is sent, the stored one of that name is not.
    let api_key = |mut c: ExecutionContext| {
        c.auth_layers = vec![("request".into(), sid_cookie_key())];
        c
    };
    ok(&e, &api_key(get(&f.url("/echo")))).await;
    assert_eq!(cookie_on(&f, "/echo").as_deref(), Some("sid=from-auth-key; theme=dark"));
    ok(&e, &api_key(ws(&format!("ws://{}/ws?close_after=1", f.addr)))).await;
    assert_eq!(cookie_on(&f, "/ws").as_deref(), Some("sid=from-auth-key; theme=dark"));
}

#[tokio::test]
async fn a_lock_between_session_start_and_its_set_cookie_leaves_the_jar_empty() {
    init();
    let api = fx::serve("127.0.0.1:0", None).await.unwrap();
    let g = gate::tcp(api.addr, 0).await.unwrap();
    let base = g.addr.unwrap();
    let e = Arc::new(Engine::new());
    let c = sse(&format!("http://{base}/sse?count=1&interval=1&set_cookie=sse_sid%3Dbefore-lock"));
    let task = {
        let (e, c) = (e.clone(), c.clone());
        tokio::spawn(async move { run(&e, &c).await })
    };
    tokio::time::timeout(Duration::from_secs(10), g.held()).await.expect("the handshake never connected");
    e.clear_sensitive_state();
    g.release();
    let o = task.await.unwrap();
    // Not canceled: the stream was answered, with its Set-Cookie.
    let response = o.record.response.as_ref().expect("the SSE handshake was answered");
    assert!(response.header_values("set-cookie")[0].starts_with("sse_sid="));
    ok(&e, &get(&format!("http://{base}/echo"))).await;
    assert_eq!(cookie_on(&api, "/echo"), None, "the Set-Cookie of a session that spanned a lock was kept");

    // An interactive WebSocket session, held the same way: its task stores
    // after the lock, and keeps nothing either.
    let g = gate::tcp(api.addr, 0).await.unwrap();
    let base = g.addr.unwrap();
    let h = e.open_session(ws(&format!("ws://{base}/ws?set_cookie=ws_sid%3Dbefore-lock")), EventCtx::none()).await;
    tokio::time::timeout(Duration::from_secs(10), g.held()).await.expect("the handshake never connected");
    e.clear_sensitive_state();
    g.release();
    // Let the handshake finish before closing (a session that already ended
    // refuses the close; its record says why).
    tokio::time::sleep(Duration::from_millis(300)).await;
    let _ = h.close().await;
    let o = h.finish().await;
    let response = o.record.response.as_ref().expect("the WebSocket handshake was answered");
    assert!(response.header_values("set-cookie")[0].starts_with("ws_sid="));
    ok(&e, &get(&format!("http://{base}/echo"))).await;
    assert_eq!(cookie_on(&api, "/echo"), None, "the Set-Cookie of a session that spanned a lock was kept");

    // With no lock in between, a session's cookie is kept again.
    ok(&e, &sse(&api.url("/sse?count=1&interval=1&set_cookie=sse_sid%3Dafter-unlock"))).await;
    ok(&e, &get(&api.url("/echo"))).await;
    assert_eq!(cookie_on(&api, "/echo").as_deref(), Some("sse_sid=after-unlock"));
}
