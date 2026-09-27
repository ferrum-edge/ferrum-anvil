//! A header an auth profile produces that is not valid on the wire (a line
//! break pasted with a token, a header name with a space) fails the request
//! locally, before anything is sent, over HTTP, for session handshakes
//! (WebSocket, SSE) and for gRPC calls, and the effective-request preview
//! says the request would not be sent. The error names the header and never
//! holds its value. A configured SSE `Last-Event-ID` that is not a valid
//! header value is refused the same way. Fixture ground truth checks that
//! nothing reached the server.

use anvil_domain::auth::{AuthConfig, KeyLocation};
use anvil_domain::execution::{FailureKind, TransportFailure};
use anvil_domain::request::{GrpcMode, GrpcSchemaSource, GrpcSpec, GrpcWire, Protocol, RequestSpec, SseSpec, WsBootstrap, WsSpec};
use anvil_domain::secret::SensitiveValue;
use anvil_engine::{Engine, ExecutionContext, ExecutionOutput};
use anvil_fixtures::http as fx;
use anvil_transport::recorder::EventCtx;
use tokio_util::sync::CancellationToken;

/// A token as pasted with its trailing line break.
const PASTED_TOKEN: &str = "audit-only-token-5k2q\n";

fn init() {
    anvil_transport::init();
    anvil_fixtures::init();
}

fn spec(protocol: Protocol, url: &str) -> RequestSpec {
    let mut s = RequestSpec::http("GET", url);
    s.protocol = protocol;
    s.websocket = Some(WsSpec {
        bootstrap: WsBootstrap::Http1Upgrade,
        subprotocols: vec![],
        messages: vec![],
        expect_messages: 0,
        max_message_bytes: 1024 * 1024,
        idle_close_ms: 500,
        permessage_deflate: Default::default(),
    });
    s.sse = Some(SseSpec { max_events: 1, idle_timeout_ms: 5_000, last_event_id: None, reconnect: false });
    s
}

fn bearer(token: &str) -> AuthConfig {
    AuthConfig::Bearer { token: SensitiveValue::template(token), prefix: "Bearer".into() }
}

/// An API key sent as the header `name`.
fn header_key(name: &str) -> AuthConfig {
    AuthConfig::ApiKey { name: name.into(), value: SensitiveValue::template("audit-only-token-api"), location: KeyLocation::Header }
}

async fn run(e: &Engine, s: RequestSpec) -> ExecutionOutput {
    e.execute(&ExecutionContext::standalone(s), EventCtx::none(), CancellationToken::new()).await
}

fn failure(o: &ExecutionOutput) -> &TransportFailure {
    o.record.attempts.last().and_then(|a| a.failure.as_ref()).expect("a local failure")
}

/// Refused locally, attributed to auth, naming `header` and never the token.
fn assert_refused(o: &ExecutionOutput, header: &str, f: &fx::Fixture) {
    let fail = failure(o);
    assert_eq!(fail.kind, FailureKind::InvalidHeader, "{fail:?}");
    assert_eq!(fail.field.as_deref(), Some("auth"));
    assert!(fail.message.contains(header), "the error names the header: {}", fail.message);
    let json = serde_json::to_string(&o.record).unwrap();
    assert!(!json.contains("audit-only-token"), "the record holds the credential: {json}");
    assert!(o.record.response.is_none());
    assert_eq!(f.log.count_requests(), 0, "a request reached the server: {:?}", f.log.requests());
    assert!(!f.log.saw_connection(), "a connection was opened");
}

#[tokio::test]
async fn http_bearer_token_with_a_line_break_fails_locally_and_sends_nothing() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    let mut s = spec(Protocol::Http, &f.url("/echo"));
    s.auth = bearer(PASTED_TOKEN);
    let o = run(&e, s).await;
    assert_refused(&o, "Authorization", &f);

    // The same token without the line break is sent.
    let mut s = spec(Protocol::Http, &f.url("/echo"));
    s.auth = bearer(PASTED_TOKEN.trim_end());
    let o = run(&e, s).await;
    assert_eq!(o.record.response.as_ref().map(|r| r.status), Some(200));
    let sent = f.log.last_request_headers().unwrap();
    assert!(sent.iter().any(|(n, v)| n == "authorization" && v == &format!("Bearer {}", PASTED_TOKEN.trim_end())), "{sent:?}");
}

#[tokio::test]
async fn http_api_key_with_an_invalid_header_name_fails_locally_and_sends_nothing() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    let mut s = spec(Protocol::Http, &f.url("/echo"));
    s.auth = header_key("X Api Key");
    let o = run(&e, s).await;
    assert_refused(&o, "X Api Key", &f);
    assert!(failure(&o).message.contains("not a valid header name"), "{}", failure(&o).message);
}

#[tokio::test]
async fn http_invalid_auth_header_in_a_multi_auth_set_fails_the_whole_request() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    let mut s = spec(Protocol::Http, &f.url("/echo"));
    s.auth = AuthConfig::Multi { profiles: vec![header_key("X-Tenant-Key"), bearer(PASTED_TOKEN)] };
    let o = run(&e, s).await;
    assert_refused(&o, "Authorization", &f);
}

#[tokio::test]
async fn websocket_handshake_with_an_invalid_auth_header_sends_nothing() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    let mut s = spec(Protocol::WebSocket, &format!("ws://{}/ws", f.addr));
    s.auth = bearer(PASTED_TOKEN);
    let o = run(&e, s).await;
    assert_refused(&o, "Authorization", &f);
}

#[tokio::test]
async fn sse_handshake_with_an_invalid_auth_header_sends_nothing() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    let mut s = spec(Protocol::Sse, &f.url("/sse?count=1&interval=1"));
    s.auth = bearer(PASTED_TOKEN);
    let o = run(&e, s).await;
    assert_refused(&o, "Authorization", &f);

    // An interactive session is refused the same way.
    let mut s = spec(Protocol::Sse, &f.url("/sse?count=1&interval=1"));
    s.auth = header_key("X Api Key");
    let o = e.open_session(ExecutionContext::standalone(s), EventCtx::none()).await.finish().await;
    assert_refused(&o, "X Api Key", &f);
}

#[tokio::test]
async fn grpc_call_with_an_invalid_auth_header_sends_nothing() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    let mut s = spec(Protocol::Grpc, &format!("grpc://{}", f.addr));
    s.grpc = Some(GrpcSpec {
        service: "anvil.lab.v1.Echo".into(),
        method: "Unary".into(),
        mode: GrpcMode::Unary,
        schema: GrpcSchemaSource::Reflection,
        messages: vec![r#"{"message":"hi"}"#.into()],
        metadata: vec![],
        deadline_ms: None,
        plaintext: false,
        wire: GrpcWire::Grpc,
    });
    s.auth = bearer(PASTED_TOKEN);
    let o = run(&e, s).await;
    assert_refused(&o, "Authorization", &f);
}

#[tokio::test]
async fn sse_last_event_id_with_a_line_break_fails_locally_and_sends_nothing() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    let mut s = spec(Protocol::Sse, &f.url("/sse?count=1&interval=1"));
    s.sse.as_mut().unwrap().last_event_id = Some("evt-7\r\nX-Injected: yes".into());
    let o = run(&e, s).await;
    let fail = failure(&o);
    assert_eq!(fail.kind, FailureKind::InvalidHeader, "{fail:?}");
    assert_eq!(fail.field.as_deref(), Some("sse.last_event_id"));
    assert!(fail.message.contains("sse.last_event_id"), "the error names the field: {}", fail.message);
    assert!(!fail.message.contains("X-Injected"), "the error holds the value: {}", fail.message);
    assert!(o.record.response.is_none());
    assert_eq!(f.log.count_requests(), 0, "a request reached the server: {:?}", f.log.requests());
    assert!(!f.log.saw_connection(), "a connection was opened");

    // A valid id is sent.
    let mut s = spec(Protocol::Sse, &f.url("/sse?count=1&interval=1"));
    s.sse.as_mut().unwrap().last_event_id = Some("evt-7".into());
    let o = run(&e, s).await;
    assert_eq!(o.record.response.as_ref().map(|r| r.status), Some(200));
    let sent = f.log.last_request_headers().unwrap();
    assert!(sent.iter().any(|(n, v)| n == "last-event-id" && v == "evt-7"), "{sent:?}");
}

#[tokio::test]
async fn preview_says_a_request_with_an_invalid_auth_header_would_not_be_sent() {
    init();
    let e = Engine::new();
    let mut s = spec(Protocol::Http, "http://127.0.0.1:9/echo");
    s.auth = bearer(PASTED_TOKEN);
    let p = e.preview(&ExecutionContext::standalone(s)).unwrap();
    let note = p.inferred.iter().find(|i| i.starts_with("the request would not be sent: ")).expect("no note");
    assert!(note.contains("Authorization"), "the note names the header: {note}");
    assert!(!p.headers.iter().any(|h| h.name.eq_ignore_ascii_case("authorization")), "{:?}", p.headers);
    let json = serde_json::to_string(&p).unwrap();
    assert!(!json.contains("audit-only-token"), "the preview holds the credential: {json}");

    // A valid token: the header is shown and nothing is said.
    let mut s = spec(Protocol::Http, "http://127.0.0.1:9/echo");
    s.auth = bearer(PASTED_TOKEN.trim_end());
    let p = e.preview(&ExecutionContext::standalone(s)).unwrap();
    assert!(!p.inferred.iter().any(|i| i.starts_with("the request would not be sent")), "{:?}", p.inferred);
    assert!(p.headers.iter().any(|h| h.name.eq_ignore_ascii_case("authorization")), "{:?}", p.headers);
}
