//! The workspace cookie jar applies to the HTTP-based session handshakes
//! (SSE, WebSocket) and to gRPC calls as to HTTP requests: stored cookies are
//! sent under the same matching rules and workspace isolation, the
//! handshake's (or the call's response headers') `Set-Cookie` is kept, the
//! cookies setting turns both off, a cookie the request sends itself wins
//! over a stored one of the same name, a `wss` handshake or `grpcs` call
//! stands for `https` (so `Secure` applies), and the cookies of a session
//! that spans a lock or the deletion of its workspace are not kept. Fixture
//! ground truth shows what the server received.

use anvil_domain::Id;
use anvil_domain::auth::{AuthConfig, KeyLocation};
use anvil_domain::events::ExecutionEvent;
use anvil_domain::execution::Direction;
use anvil_domain::request::*;
use anvil_domain::secret::{REDACTED, SensitiveValue};
use anvil_domain::settings::{DnsOverride, SettingsOverrides};
use anvil_domain::tls::{TlsMinVersion, TlsProfile};
use anvil_engine::context::MemoryAttachments;
use anvil_engine::vars::{VarEntry, VarLayer};
use anvil_engine::{Engine, ExecutionContext, ExecutionOutput};
use anvil_fixtures::grpc::ECHO_PROTO;
use anvil_fixtures::http as fx;
use anvil_fixtures::{GroundTruth, LabPki, TlsServerOptions, gate};
use anvil_transport::recorder::{EventCtx, EventFn};
use bytes::Bytes;
use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::sync::Notify;
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

/// A name the lab server certificate covers that is not a loopback name, so
/// the jar applies `Secure` to it as to a remote origin.
const TEST_HOST: &str = "api.anvil.test";

/// `c` with [`TEST_HOST`] resolved to 127.0.0.1 and the lab root trusted.
fn on_test_host(mut c: ExecutionContext) -> ExecutionContext {
    let p = TlsProfile {
        id: Id::new(),
        workspace_id: Id::new(),
        name: "lab".into(),
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
    };
    let dns = DnsOverride { host: TEST_HOST.into(), addresses: vec!["127.0.0.1".into()] };
    let run = SettingsOverrides { tls_profile_id: Some(p.id), dns_overrides: vec![dns], ..Default::default() };
    c.settings_layers.push(("run".into(), run));
    c.tls_profiles.push(p);
    c
}

/// Events that signal the first message the session receives (the handshake
/// has completed by then).
fn on_first_received() -> (EventCtx, Arc<Notify>) {
    let received = Arc::new(Notify::new());
    let r = received.clone();
    let sink: EventFn = Arc::new(move |e: ExecutionEvent| {
        if let ExecutionEvent::Message { message, .. } = e
            && message.direction == Direction::Received
        {
            r.notify_one();
        }
    });
    (EventCtx { execution_id: Id::new(), sink: Some(sink) }, received)
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

/// The gRPC echo call's path on the fixture.
const GRPC_PATH: &str = "/anvil.lab.v1.Echo/Unary";

/// A unary gRPC `Echo` call (the `.proto` as its schema, so nothing but the
/// call is sent). With `set_cookie`, the fixture answers with that value as
/// its `Set-Cookie` response header.
fn grpc(url: &str, set_cookie: Option<&str>) -> ExecutionContext {
    let sha = anvil_transport::certs::sha256_hex(ECHO_PROTO.as_bytes());
    let file =
        AttachmentRef::Stored { sha256: sha.clone(), size: ECHO_PROTO.len() as u64, file_name: "echo.proto".into(), media_type: None };
    let mut s = RequestSpec::http("POST", url);
    s.protocol = Protocol::Grpc;
    s.grpc = Some(GrpcSpec {
        service: "anvil.lab.v1.Echo".into(),
        method: "Unary".into(),
        mode: GrpcMode::Unary,
        schema: GrpcSchemaSource::ProtoFiles { files: vec![file] },
        messages: vec![r#"{"message":"hi"}"#.into()],
        metadata: set_cookie.map(|c| KeyValue::new("x-fixture-set-cookie", c)).into_iter().collect(),
        deadline_ms: None,
        plaintext: false,
        wire: GrpcWire::Grpc,
    });
    let mut c = ExecutionContext::standalone(s);
    c.attachments = Arc::new(MemoryAttachments(HashMap::from([(sha, Bytes::from_static(ECHO_PROTO.as_bytes()))])));
    c
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
async fn cumulative_cookie_eviction_and_output_cap_apply_to_redirect_and_session_handshakes() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    // Fill the site count budget through actual HTTP responses, then add one
    // more through a real SSE handshake using the same bounded jar.
    for i in 0..180 {
        ok(&e, &get(&f.url(&format!("/set-cookie?name=c{i}&value=v")))).await;
    }
    let s = ok(
        &e,
        &sse(&f.url("/sse?count=1&interval=1&set_cookie=session%3Dfrom-handshake")),
    )
    .await;
    assert_eq!(s.record.response.as_ref().unwrap().status, 200);
    let to = url::form_urlencoded::byte_serialize(f.url("/echo").as_bytes()).collect::<String>();
    let o = ok(&e, &get(&f.url(&format!("/redirect?status=307&to={to}")))).await;
    assert_eq!(o.record.attempts.len(), 2);
    let cookie = cookie_on(&f, "/echo").unwrap();
    assert_eq!(cookie.split("; ").count(), 180);
    assert!(!cookie.split("; ").any(|p| p == "c0=v"), "creation order breaks equal LRU ties");
    assert!(cookie.contains("session=from-handshake"));
    // Large values exercise the independent header cap on HTTP and SSE, while
    // response state is still larger than one permitted output header.
    for i in 0..4 {
        let path = format!("/set-cookie?name=large{i}&value={}", "v".repeat(3000));
        ok(&e, &get(&f.url(&path))).await;
    }
    ok(&e, &get(&f.url("/echo"))).await;
    assert!(cookie_on(&f, "/echo").unwrap().len() <= 8192);
    ok(&e, &sse(&f.url("/sse?count=1&interval=1"))).await;
    assert!(cookie_on(&f, "/sse").unwrap().len() <= 8192);
    assert!(
        !serde_json::to_string(&o.record).unwrap().contains("from-handshake"),
        "request cookies stay redacted",
    );
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
async fn session_cookie_names_with_secrets_are_refused_and_ordinary_cookies_are_kept() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();

    let secret = "reflected-cookie-secret-4k7w";
    let mut c = sse(&f.url("/sse?count=1&interval=1&set_cookie=reflected%252dcookie-secret-4k7w%3Dordinary&secret={{reflected}}"));
    c.var_layers = vec![VarLayer {
        label: "environment:test".into(),
        vars: vec![VarEntry { name: "reflected".into(), value: secret.into(), secret: true }],
    }];
    let o = ok(&e, &c).await;
    assert!(o.record.prepared.inferred.iter().any(|n| n == "a response cookie was not stored because its name contains a request secret"));
    let set_cookie = o.record.response.as_ref().unwrap().header_values("set-cookie");
    assert_eq!(set_cookie[0], format!("{REDACTED}={REDACTED}; Path=/; HttpOnly"));
    ok(&e, &get(&f.url("/echo"))).await;
    assert_eq!(cookie_on(&f, "/echo"), None, "the session stored a cookie whose name hides a request secret");

    let e = Engine::new();
    ok(&e, &get(&f.url("/set-cookie?name=ordinary&value=kept"))).await;
    ok(&e, &get(&f.url("/echo"))).await;
    assert_eq!(cookie_on(&f, "/echo").as_deref(), Some("ordinary=kept"));
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
    let (events, received) = on_first_received();
    let h = e.open_session(ws(&format!("ws://{base}/ws?set_cookie=ws_sid%3Dbefore-lock")), events).await;
    tokio::time::timeout(Duration::from_secs(10), g.held()).await.expect("the handshake never connected");
    e.clear_sensitive_state();
    g.release();
    // Close once the scripted message is echoed: the handshake has finished
    // and the session is open.
    tokio::time::timeout(Duration::from_secs(10), received.notified()).await.expect("the scripted message was never echoed");
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

#[tokio::test]
async fn a_workspace_delete_while_a_session_or_request_is_in_flight_leaves_no_jar_for_it() {
    init();
    let api = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Arc::new(Engine::new());
    // Another workspace's cookie: the delete leaves it alone.
    ok(&e, &in_workspace(get(&api.url("/set-cookie?name=other&value=kept")), "workspace-b")).await;

    // An SSE session of the deleted workspace, answered after the delete,
    // then an HTTP request held the same way.
    let urls = ["/sse?count=1&interval=1&set_cookie=sse_sid%3Dbefore-delete", "/set-cookie?name=sid&value=before-delete"];
    for (i, path) in urls.into_iter().enumerate() {
        let g = gate::tcp(api.addr, 0).await.unwrap();
        let base = g.addr.unwrap();
        let c = if i == 0 { sse(&format!("http://{base}{path}")) } else { get(&format!("http://{base}{path}")) };
        let c = in_workspace(c, "workspace-a");
        let task = {
            let (e, c) = (e.clone(), c.clone());
            tokio::spawn(async move { run(&e, &c).await })
        };
        tokio::time::timeout(Duration::from_secs(10), g.held()).await.expect("the request never connected");
        e.clear_isolation("workspace-a");
        g.release();
        let o = task.await.unwrap();
        let response = o.record.response.as_ref().unwrap_or_else(|| panic!("{path} was not answered"));
        assert_eq!(response.header_values("set-cookie").len(), 1, "{path}");
        assert!(!e.has_cookie_jar("workspace-a"), "{path}, answered after its workspace was deleted, recreated its jar");
    }

    ok(&e, &in_workspace(get(&api.url("/echo")), "workspace-a")).await;
    assert_eq!(cookie_on(&api, "/echo"), None, "a cookie received after the workspace delete was sent");
    ok(&e, &in_workspace(get(&api.url("/echo")), "workspace-b")).await;
    assert_eq!(cookie_on(&api, "/echo").as_deref(), Some("other=kept"));

    // A session that starts after the delete (a workspace restored with the
    // same id) keeps its cookie again.
    ok(&e, &in_workspace(sse(&api.url("/sse?count=1&interval=1&set_cookie=sse_sid%3Dafter-delete")), "workspace-a")).await;
    ok(&e, &in_workspace(get(&api.url("/echo")), "workspace-a")).await;
    assert_eq!(cookie_on(&api, "/echo").as_deref(), Some("sse_sid=after-delete"));
}

#[tokio::test]
async fn a_secure_cookie_from_a_wss_handshake_is_kept_for_https_and_not_sent_over_ws() {
    init();
    let tls = fx::serve("127.0.0.1:0", Some(server_tls())).await.unwrap();
    let plain = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    let (tls_port, plain_port) = (tls.addr.port(), plain.addr.port());

    // A wss:// handshake stands for https:// in the jar: its Secure cookie is
    // kept, and sent over https:// and on the next wss:// handshake.
    let set = format!("wss://{TEST_HOST}:{tls_port}/ws?close_after=1&set_cookie=sec%3Dfrom-wss%3B%20Secure");
    let o = ok(&e, &on_test_host(ws(&set))).await;
    assert!(o.record.response.as_ref().unwrap().header_values("set-cookie")[0].contains("Secure"));
    ok(&e, &on_test_host(get(&format!("https://{TEST_HOST}:{tls_port}/echo")))).await;
    assert_eq!(cookie_on(&tls, "/echo").as_deref(), Some("sec=from-wss"));
    ok(&e, &on_test_host(ws(&format!("wss://{TEST_HOST}:{tls_port}/ws?close_after=1")))).await;
    assert_eq!(cookie_on(&tls, "/ws").as_deref(), Some("sec=from-wss"));

    // Not over ws:// or http:// to the same host (a cookie is not bound to a
    // port).
    ok(&e, &on_test_host(ws(&format!("ws://{TEST_HOST}:{plain_port}/ws?close_after=1")))).await;
    assert_eq!(cookie_on(&plain, "/ws"), None, "a Secure cookie was sent over ws://");
    ok(&e, &on_test_host(get(&format!("http://{TEST_HOST}:{plain_port}/echo")))).await;
    assert_eq!(cookie_on(&plain, "/echo"), None, "a Secure cookie was sent over http://");
}

#[tokio::test]
async fn an_http_login_cookie_is_sent_on_a_grpc_call() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    // An HttpOnly cookie, set over http: a grpc:// call is its HTTP
    // counterpart in the jar and carries it in its metadata.
    login(&e, &f).await;
    ok(&e, &grpc(&format!("grpc://{}", f.addr), None)).await;
    assert_eq!(cookie_on(&f, GRPC_PATH).as_deref(), Some("sid=audit-only-session"));
    ok(&e, &grpc(&format!("http://{}", f.addr), None)).await;
    assert_eq!(cookie_on(&f, GRPC_PATH).as_deref(), Some("sid=audit-only-session"));
}

#[tokio::test]
async fn set_cookie_on_a_grpc_response_is_kept_in_the_jar() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    let o = ok(&e, &grpc(&format!("grpc://{}", f.addr), Some("grpc_sid=from-grpc; Path=/"))).await;
    assert!(o.record.response.as_ref().unwrap().header_values("set-cookie")[0].starts_with("grpc_sid="));
    ok(&e, &get(&f.url("/echo"))).await;
    assert_eq!(cookie_on(&f, "/echo").as_deref(), Some("grpc_sid=from-grpc"));
    // And sent on the next call.
    ok(&e, &grpc(&format!("grpc://{}", f.addr), None)).await;
    assert_eq!(cookie_on(&f, GRPC_PATH).as_deref(), Some("grpc_sid=from-grpc"));
}

#[tokio::test]
async fn with_cookies_off_a_grpc_call_neither_sends_nor_keeps_cookies() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    login(&e, &f).await;
    ok(&e, &cookies_off(grpc(&format!("grpc://{}", f.addr), None))).await;
    assert_eq!(cookie_on(&f, GRPC_PATH), None);

    let e = Engine::new();
    ok(&e, &cookies_off(grpc(&format!("grpc://{}", f.addr), Some("grpc_sid=from-grpc; Path=/")))).await;
    ok(&e, &get(&f.url("/echo"))).await;
    assert_eq!(cookie_on(&f, "/echo"), None, "a gRPC call with cookies off stored its Set-Cookie");
}

#[tokio::test]
async fn grpc_cookies_stay_in_their_workspace_and_a_request_cookie_wins() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    ok(&e, &in_workspace(get(&f.url("/set-cookie?name=sid&value=audit-only-session")), "workspace-a")).await;
    ok(&e, &in_workspace(get(&f.url("/set-cookie?name=theme&value=dark")), "workspace-a")).await;
    ok(&e, &in_workspace(grpc(&format!("grpc://{}", f.addr), None), "workspace-b")).await;
    assert_eq!(cookie_on(&f, GRPC_PATH), None, "a cookie of workspace a was sent for workspace b");
    ok(&e, &in_workspace(grpc(&format!("grpc://{}", f.addr), Some("grpc_sid=from-b; Path=/")), "workspace-b")).await;
    ok(&e, &in_workspace(get(&f.url("/echo")), "workspace-a")).await;
    let mut sent: Vec<String> = cookie_on(&f, "/echo").unwrap_or_default().split("; ").map(str::to_string).collect();
    sent.sort();
    assert_eq!(sent, ["sid=audit-only-session", "theme=dark"]);
    ok(&e, &in_workspace(get(&f.url("/echo")), "workspace-b")).await;
    assert_eq!(cookie_on(&f, "/echo").as_deref(), Some("grpc_sid=from-b"));

    // A configured Cookie header: sid once (its own value), theme from the jar.
    let mut c = in_workspace(grpc(&format!("grpc://{}", f.addr), None), "workspace-a");
    c.spec.headers.push(KeyValue::new("Cookie", "sid=configured"));
    ok(&e, &c).await;
    assert_eq!(cookie_on(&f, GRPC_PATH).as_deref(), Some("sid=configured; theme=dark"));
}

#[tokio::test]
async fn a_lock_or_workspace_delete_during_a_grpc_call_leaves_no_cookie() {
    init();
    let api = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Arc::new(Engine::new());
    ok(&e, &in_workspace(get(&api.url("/set-cookie?name=other&value=kept")), "workspace-b")).await;
    // The workspace delete first: the lock after it clears every jar.
    for lock in [false, true] {
        let g = gate::tcp(api.addr, 0).await.unwrap();
        let c = in_workspace(grpc(&format!("grpc://{}", g.addr.unwrap()), Some("grpc_sid=in-flight; Path=/")), "workspace-a");
        let task = {
            let (e, c) = (e.clone(), c.clone());
            tokio::spawn(async move { run(&e, &c).await })
        };
        tokio::time::timeout(Duration::from_secs(10), g.held()).await.expect("the call never connected");
        if lock {
            e.clear_sensitive_state();
        } else {
            e.clear_isolation("workspace-a");
        }
        g.release();
        let o = task.await.unwrap();
        // Not canceled: the call was answered, with its Set-Cookie.
        let response = o.record.response.as_ref().expect("the gRPC call was answered");
        assert!(response.header_values("set-cookie")[0].starts_with("grpc_sid="), "lock: {lock}");
        assert!(!e.has_cookie_jar("workspace-a"), "lock: {lock}: a call answered after the clear recreated the jar");
        ok(&e, &in_workspace(get(&api.url("/echo")), "workspace-a")).await;
        assert_eq!(cookie_on(&api, "/echo"), None, "lock: {lock}: the Set-Cookie of a call that spanned the clear was kept");
        if !lock {
            // The delete left the other workspace's jar alone.
            ok(&e, &in_workspace(get(&api.url("/echo")), "workspace-b")).await;
            assert_eq!(cookie_on(&api, "/echo").as_deref(), Some("other=kept"));
        }
    }

    // A call that starts after the delete keeps its cookie again.
    ok(&e, &in_workspace(grpc(&format!("grpc://{}", api.addr), Some("grpc_sid=after-delete; Path=/")), "workspace-a")).await;
    ok(&e, &in_workspace(get(&api.url("/echo")), "workspace-a")).await;
    assert_eq!(cookie_on(&api, "/echo").as_deref(), Some("grpc_sid=after-delete"));
}

#[tokio::test]
async fn a_secure_cookie_from_a_grpcs_call_is_kept_for_https_and_not_sent_over_grpc() {
    init();
    let tls = fx::serve("127.0.0.1:0", Some(server_tls())).await.unwrap();
    let plain = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    let (tls_port, plain_port) = (tls.addr.port(), plain.addr.port());

    // A grpcs:// call stands for https:// in the jar: its Secure cookie is
    // kept, and sent over https:// and on the next grpcs:// call.
    let o = ok(&e, &on_test_host(grpc(&format!("grpcs://{TEST_HOST}:{tls_port}"), Some("sec=from-grpcs; Path=/; Secure")))).await;
    assert!(o.record.response.as_ref().unwrap().header_values("set-cookie")[0].contains("Secure"));
    ok(&e, &on_test_host(get(&format!("https://{TEST_HOST}:{tls_port}/echo")))).await;
    assert_eq!(cookie_on(&tls, "/echo").as_deref(), Some("sec=from-grpcs"));
    ok(&e, &on_test_host(grpc(&format!("grpcs://{TEST_HOST}:{tls_port}"), None))).await;
    assert_eq!(cookie_on(&tls, GRPC_PATH).as_deref(), Some("sec=from-grpcs"));

    // Not over grpc:// to the same host.
    ok(&e, &on_test_host(grpc(&format!("grpc://{TEST_HOST}:{plain_port}"), None))).await;
    assert_eq!(cookie_on(&plain, GRPC_PATH), None, "a Secure cookie was sent over grpc://");
}
