//! MCP over Streamable HTTP: the session the engine opens for one operation
//! (initialize, notifications/initialized, the call, DELETE), JSON and
//! event-stream answers, the MCP assertions, diagnosis and redaction, against
//! the in-process MCP fixture. The fixture's own record of what it received
//! is ground truth; it is never given to the engine.

use anvil_domain::assertions::{Assertion, AssertionKind, Comparison, Extraction, ExtractionSource};
use anvil_domain::auth::AuthConfig;
use anvil_domain::execution::FailureKind;
use anvil_domain::outcome::{ApplicationState, AssertionState};
use anvil_domain::request::{KeyValue, McpOperation, McpSpec, Protocol, RequestSpec};
use anvil_domain::secret::{REDACTED, SensitiveValue};
use anvil_domain::settings::{SettingsOverrides, TimeoutOverrides};
use anvil_engine::mcp::{STREAMABLE_HTTP_ACCEPT, operation_response};
use anvil_engine::vars::{VarEntry, VarLayer};
use anvil_engine::{Engine, ExecutionContext, ExecutionOutput};
use anvil_fixtures::GroundTruth;
use anvil_fixtures::mcp::{self, Hostile, McpFixture, McpOptions};
use anvil_transport::recorder::EventCtx;
use tokio_util::sync::CancellationToken;

fn init() {
    anvil_transport::init();
    anvil_fixtures::init();
}

async fn run(engine: &Engine, ctx: &ExecutionContext) -> ExecutionOutput {
    engine.execute(ctx, EventCtx::none(), CancellationToken::new()).await
}

fn mcp_ctx(url: &str, operation: McpOperation) -> ExecutionContext {
    let mut spec = RequestSpec::http("POST", url);
    spec.protocol = Protocol::Mcp;
    let mcp: McpSpec = serde_json::from_value(serde_json::json!({ "operation": serde_json::to_value(operation).unwrap() })).unwrap();
    spec.mcp = Some(mcp);
    ExecutionContext::standalone(spec)
}

fn call(name: &str, arguments: &str) -> McpOperation {
    McpOperation::ToolsCall { name: name.into(), arguments: arguments.into() }
}

fn list() -> McpOperation {
    McpOperation::ToolsList { cursor: None }
}

fn check(kind: AssertionKind) -> Assertion {
    Assertion { enabled: true, label: String::new(), kind }
}

fn notes(o: &ExecutionOutput) -> String {
    o.record.prepared.inferred.join("\n")
}

fn codes(o: &ExecutionOutput) -> Vec<String> {
    o.record.findings.iter().map(|f| f.code.clone()).collect()
}

fn status(o: &ExecutionOutput) -> Option<u16> {
    o.record.response.as_ref().map(|r| r.status)
}

/// Requests the fixture received with `Authorization` ending in `token`.
fn authorized_requests(f: &McpFixture, token: &str) -> usize {
    let carries = |headers: &[(String, String)]| headers.iter().any(|(n, v)| n == "authorization" && v.ends_with(token));
    f.log.entries().iter().filter(|e| matches!(&e.event, GroundTruth::RequestReceived { headers, .. } if carries(headers))).count()
}

#[tokio::test]
async fn an_operation_runs_in_a_session_of_its_own() {
    init();
    let f = mcp::serve("127.0.0.1:0", McpOptions::default()).await.unwrap();
    let e = Engine::new();
    let o = run(&e, &mcp_ctx(&f.url(), list())).await;
    assert_eq!(o.record.prepared.protocol, Protocol::Mcp);
    assert_eq!(status(&o), Some(200), "{}", o.record.outcome.summary);
    assert_eq!(o.record.outcome.application, ApplicationState::Success);
    assert_eq!(f.state.methods(), ["initialize", "notifications/initialized", "tools/list"]);
    let calls = f.state.calls();
    assert_eq!(calls.iter().map(|c| c.http_method.as_str()).collect::<Vec<_>>(), ["POST", "POST", "POST", "DELETE"]);
    assert_eq!(calls[1].status, 202, "the notification is accepted");

    // Every request after initialize carries the session and the version.
    let closed = f.state.closed.lock().clone();
    assert_eq!(closed.len(), 1, "the session was ended");
    assert!(calls[0].session.is_none() && calls[0].protocol_version.is_none());
    for c in &calls[1..] {
        assert_eq!(c.session.as_deref(), Some(closed[0].as_str()), "{c:?}");
        assert_eq!(c.protocol_version.as_deref(), Some("2025-11-25"), "{c:?}");
    }
    assert!(calls.iter().filter(|c| c.http_method == "POST").all(|c| c.accept.as_deref() == Some(STREAMABLE_HTTP_ACCEPT)));

    let tools = operation_response(&o).expect("the tools/list response");
    assert_eq!(tools["result"]["tools"].as_array().map(Vec::len), Some(7));
    let n = notes(&o);
    assert!(n.contains("MCP initialize: HTTP 200, protocol version 2025-11-25, server anvil-mcp-fixture 1.0.0"), "{n}");
    assert!(n.contains("MCP notifications/initialized: HTTP 202"), "{n}");
    assert!(n.contains("MCP session closed: DELETE answered HTTP 200"), "{n}");

    // The session id is a credential: sent as a sensitive header, it appears
    // nowhere in the record.
    let header = o.record.prepared.headers.iter().find(|h| h.name.eq_ignore_ascii_case("mcp-session-id")).expect("sent");
    assert_eq!(header.value, REDACTED);
    let json = serde_json::to_string(&o.record).unwrap();
    assert!(!json.contains(&closed[0]), "the session id is in the record");
}

#[tokio::test]
async fn a_tool_call_answered_with_an_event_stream_is_checked_on_its_json_rpc_response() {
    init();
    let f = mcp::serve("127.0.0.1:0", McpOptions { sse: true, ..Default::default() }).await.unwrap();
    let e = Engine::new();
    let mut c = mcp_ctx(&f.url(), call("echo", r#"{"text":"{{greeting}}"}"#));
    let greeting = VarEntry { name: "greeting".into(), value: "hello".into(), secret: false, literal: false };
    c.var_layers.push(VarLayer { label: "test".into(), vars: vec![greeting] });
    let text = "$.result.structuredContent.text".to_string();
    c.spec.assertions = vec![
        check(AssertionKind::JsonRpcResult),
        check(AssertionKind::McpIsError { is_error: false }),
        check(AssertionKind::JsonPath { path: text, comparison: Comparison::Equals, value: "hello".into() }),
    ];
    let source = ExtractionSource::JsonPath { path: "$.result.content[0].text".into() };
    c.spec.extractions = vec![Extraction { variable: "echoed".into(), source, sensitive: false }];
    let o = run(&e, &c).await;
    assert_eq!(o.record.outcome.assertions, AssertionState::Pass, "{:?}", o.record.assertion_results);
    assert_eq!(o.extracted, vec![("echoed".to_string(), "hello".to_string(), false)]);
    assert_eq!(o.record.outcome.application, ApplicationState::Success);
    let n = notes(&o);
    assert!(n.contains("MCP tools/call: the response arrived as an event stream of 2 event(s); the JSON-RPC response was read"), "{n}");
    assert_eq!(f.state.tool_calls("echo"), 1);
    assert_eq!(f.state.closed.lock().len(), 1, "the session opened over event streams was ended");
}

#[tokio::test]
async fn json_rpc_errors_and_tool_errors_are_application_failures() {
    init();
    let f = mcp::serve("127.0.0.1:0", McpOptions::default()).await.unwrap();
    let e = Engine::new();

    let mut unknown = mcp_ctx(&f.url(), call("nope", "{}"));
    unknown.spec.assertions = vec![check(AssertionKind::JsonRpcError { code: -32602 })];
    let o = run(&e, &unknown).await;
    assert_eq!(o.record.outcome.assertions, AssertionState::Pass, "{:?}", o.record.assertion_results);
    assert_eq!(o.record.outcome.application, ApplicationState::Failure);
    assert!(codes(&o).contains(&"app.jsonrpc_error".to_string()), "{:?}", codes(&o));
    assert!(!codes(&o).iter().any(|c| c.starts_with("ferrum.")), "no gateway is declared: {:?}", codes(&o));

    let mut failing = mcp_ctx(&f.url(), call("fail", "{}"));
    failing.spec.assertions = vec![check(AssertionKind::McpIsError { is_error: true }), check(AssertionKind::JsonRpcResult)];
    let o = run(&e, &failing).await;
    assert_eq!(o.record.outcome.assertions, AssertionState::Pass, "{:?}", o.record.assertion_results);
    assert_eq!(o.record.outcome.application, ApplicationState::Failure);
    let tool_error = o.record.findings.iter().find(|x| x.code == "app.mcp_tool_error").expect("the tool's failure");
    assert!(tool_error.explanation.contains("the fixture tool failed on purpose"), "{}", tool_error.explanation);

    let mut schema = mcp_ctx(&f.url(), list());
    schema.spec.assertions = vec![
        check(AssertionKind::ToolPresent { name: "echo".into() }),
        check(AssertionKind::ToolAbsent { name: "fx.echo".into() }),
        check(AssertionKind::ToolInputSchema { name: "echo".into(), schema: Some(r#"{"type":"object"}"#.into()), sha256: None }),
    ];
    let o = run(&e, &schema).await;
    let passed: Vec<bool> = o.record.assertion_results.iter().map(|r| r.passed).collect();
    assert_eq!(passed, [true, true, false], "{:?}", o.record.assertion_results);
    assert!(o.record.assertion_results[2].actual.as_deref().is_some_and(|a| a.starts_with("sha256 ")));
}

#[tokio::test]
async fn a_failed_handshake_is_the_result_and_the_operation_is_not_sent() {
    init();
    let f = mcp::serve("127.0.0.1:0", McpOptions::default()).await.unwrap();
    let e = Engine::new();
    let mut c = mcp_ctx(&format!("http://{}/not-mcp", f.addr), call("echo", r#"{"text":"x"}"#));
    c.spec.assertions = vec![check(AssertionKind::Status { comparison: Comparison::Equals, value: "404".into() })];
    let o = run(&e, &c).await;
    assert_eq!(status(&o), Some(404));
    assert_eq!(o.record.outcome.assertions, AssertionState::Pass, "the request's assertions ran on initialize");
    assert_eq!(o.record.prepared.protocol, Protocol::Mcp);
    let n = notes(&o);
    assert!(n.contains("MCP initialize was answered with HTTP 404, not a session"), "{n}");
    assert!(n.contains("the tools/call request was not sent"), "{n}");
    assert_eq!(f.state.methods(), ["initialize"]);
    assert_eq!(f.state.tool_calls("echo"), 0);
}

#[tokio::test]
async fn without_initialize_the_operation_is_sent_on_its_own() {
    init();
    let f = mcp::serve("127.0.0.1:0", McpOptions::default()).await.unwrap();
    let e = Engine::new();
    let mut c = mcp_ctx(&f.url(), list());
    c.spec.mcp.as_mut().unwrap().initialize = false;
    c.spec.assertions = vec![check(AssertionKind::JsonRpcError { code: -32600 })];
    let o = run(&e, &c).await;
    assert_eq!(status(&o), Some(400));
    assert_eq!(o.record.outcome.assertions, AssertionState::Pass, "{:?}", o.record.assertion_results);
    let calls = f.state.calls();
    assert_eq!(calls.len(), 1, "no handshake and no close: {calls:?}");
    assert_eq!((calls[0].session.as_deref(), calls[0].protocol_version.as_deref()), (None, Some("2025-11-25")));
}

#[tokio::test]
async fn closing_the_session_is_optional_and_a_refused_close_is_reported() {
    init();
    let e = Engine::new();
    let f = mcp::serve("127.0.0.1:0", McpOptions::default()).await.unwrap();
    let mut c = mcp_ctx(&f.url(), list());
    c.spec.mcp.as_mut().unwrap().close_session = false;
    let o = run(&e, &c).await;
    assert!(notes(&o).contains("MCP session left open"), "{}", notes(&o));
    assert_eq!(f.state.sessions.lock().len(), 1);
    assert!(f.state.calls().iter().all(|c| c.http_method == "POST"));

    let no_delete = mcp::serve("127.0.0.1:0", McpOptions { allow_delete: false, ..Default::default() }).await.unwrap();
    let o = run(&e, &mcp_ctx(&no_delete.url(), list())).await;
    assert_eq!(o.record.outcome.application, ApplicationState::Success, "the close does not change the call's outcome");
    assert!(notes(&o).contains("DELETE answered HTTP 405 (the server does not let clients end sessions)"), "{}", notes(&o));
}

#[tokio::test]
async fn the_session_id_and_credentials_are_redacted_wherever_they_show() {
    init();
    let f = mcp::serve("127.0.0.1:0", McpOptions::default()).await.unwrap();
    let e = Engine::new();
    let token = "tok-SENSITIVE-mcp-bearer";
    let mut c = mcp_ctx(&f.url(), call("session", "{}"));
    c.spec.auth = AuthConfig::Bearer { token: SensitiveValue::Template { value: token.into() }, prefix: "Bearer".into() };
    c.auth_layers = vec![("request".into(), c.spec.auth.clone())];
    // The tool answers with the session id: the assertion's actual value quotes it.
    let text = "$.result.content[0].text".to_string();
    c.spec.assertions = vec![check(AssertionKind::JsonPath { path: text, comparison: Comparison::Exists, value: String::new() })];
    let o = run(&e, &c).await;
    assert_eq!(o.record.outcome.assertions, AssertionState::Pass, "{:?}", o.record.assertion_results);
    let sid = f.state.closed.lock().first().cloned().expect("a session");
    let actual = o.record.assertion_results[0].actual.clone().unwrap_or_default();
    assert!(actual.starts_with("session ") && !actual.contains(&sid), "{actual}");
    let json = serde_json::to_string(&o.record).unwrap();
    assert!(!json.contains(&sid) && !json.contains(token), "a credential is in the record");
    // Ground truth: every exchange carried the credential.
    assert_eq!(authorized_requests(&f, token), 4, "initialize, notifications/initialized, tools/call and DELETE");

    let preview = e.preview(&c).expect("a preview");
    assert_eq!(preview.method, "POST");
    assert!(preview.inferred[0].starts_with("MCP: sent after initialize"), "{:?}", preview.inferred);
    let shown = |name: &str| preview.headers.iter().find(|h| h.name.eq_ignore_ascii_case(name)).map(|h| h.value.clone());
    assert_eq!(shown("mcp-session-id").as_deref(), Some(REDACTED));
    assert_eq!(shown("authorization"), Some(format!("Bearer {REDACTED}")));
    let accept = preview.headers.iter().find(|h| h.name.eq_ignore_ascii_case("accept")).map(|h| h.value.as_str());
    assert_eq!(accept, Some(STREAMABLE_HTTP_ACCEPT));
    assert!(preview.body_preview.contains("tools/call"), "{}", preview.body_preview);
}

#[tokio::test]
async fn an_mcp_request_without_its_settings_is_not_sent() {
    init();
    let f = mcp::serve("127.0.0.1:0", McpOptions::default()).await.unwrap();
    let e = Engine::new();
    let mut c = mcp_ctx(&f.url(), list());
    c.spec.mcp = None;
    let o = run(&e, &c).await;
    let failure = o.record.attempts.last().and_then(|a| a.failure.as_ref()).map(|f| f.kind);
    assert_eq!(failure, Some(FailureKind::UnsupportedCombination));
    let mut blank = mcp_ctx(&f.url(), call(" ", "{}"));
    blank.spec.assertions = vec![];
    let o = run(&e, &blank).await;
    let failure = o.record.attempts.last().and_then(|a| a.failure.as_ref()).map(|f| f.kind);
    assert_eq!(failure, Some(FailureKind::BodySerialization));
    assert!(f.state.calls().is_empty(), "nothing was sent");
}

// ---- a hostile server ------------------------------------------------------

fn hostile(mode: Hostile) -> McpOptions {
    McpOptions { hostile: mode, ..Default::default() }
}

/// Every header value the fixture received.
fn received_values(f: &McpFixture) -> Vec<String> {
    f.log
        .entries()
        .into_iter()
        .filter_map(|e| match e.event {
            GroundTruth::RequestReceived { headers, .. } => Some(headers),
            _ => None,
        })
        .flatten()
        .map(|(_, v)| v)
        .collect()
}

/// A session id holding a variable reference is never sent back: resolving it
/// would send the variable's value (here a secret) to the server.
#[tokio::test]
async fn a_session_id_holding_a_variable_reference_is_never_sent_back() {
    init();
    let f = mcp::serve("127.0.0.1:0", hostile(Hostile::SessionId("{{api_token}}"))).await.unwrap();
    let e = Engine::new();
    let secret = "tok-SENSITIVE-mcp-variable";
    let mut c = mcp_ctx(&f.url(), list());
    let token = VarEntry { name: "api_token".into(), value: secret.into(), secret: true, literal: false };
    c.var_layers.push(VarLayer { label: "test".into(), vars: vec![token] });
    let o = run(&e, &c).await;
    assert!(notes(&o).contains("is not a session id Anvil sends back"), "{}", notes(&o));
    assert!(notes(&o).contains("the tools/list request was not sent"), "{}", notes(&o));
    assert_eq!(f.state.methods(), ["initialize"], "nothing else was sent");
    assert!(!received_values(&f).iter().any(|v| v.contains(secret) || v.contains("{{")), "{:?}", received_values(&f));
}

/// A protocol version that is not a plain token is not used, and the session
/// the server opened is ended all the same.
#[tokio::test]
async fn a_bad_protocol_version_ends_the_handshake_and_the_session_is_closed() {
    init();
    let f = mcp::serve("127.0.0.1:0", hostile(Hostile::ProtocolVersion("2025-11-25\r\nX-Injected: 1"))).await.unwrap();
    let e = Engine::new();
    let o = run(&e, &mcp_ctx(&f.url(), list())).await;
    let n = notes(&o);
    assert!(n.contains("not a version token"), "{n}");
    assert!(n.contains("MCP session closed: DELETE answered HTTP 200"), "{n}");
    assert_eq!(f.state.methods(), ["initialize"]);
    assert_eq!(f.state.closed.lock().len(), 1);
    let sent_back = f.state.calls().iter().any(|c| c.protocol_version.as_deref().is_some_and(|v| v.contains("Injected")));
    assert!(!sent_back, "the bad version was never sent");
}

/// A secret the server echoes in its initialize error is redacted in the
/// session's notes (and so in history and exports, which keep the record).
#[tokio::test]
async fn a_secret_echoed_in_the_initialize_error_is_redacted_in_the_notes() {
    init();
    let f = mcp::serve("127.0.0.1:0", hostile(Hostile::InitializeErrorEchoing("x-api-key"))).await.unwrap();
    let e = Engine::new();
    let secret = "tok-SENSITIVE-echoed-key";
    let mut c = mcp_ctx(&f.url(), list());
    c.spec.headers.push(KeyValue { sensitive: true, ..KeyValue::new("X-Api-Key", secret) });
    let o = run(&e, &c).await;
    let n = notes(&o);
    assert!(n.contains(&format!("rejected credential {REDACTED}")), "{n}");
    assert!(!serde_json::to_string(&o.record).unwrap().contains(secret), "the secret is in the record");
    assert!(n.contains("MCP session closed"), "the session initialize opened is ended: {n}");
    assert_eq!(f.state.closed.lock().len(), 1);
}

/// One deadline covers the whole session: an operation answered with an
/// event stream that never ends stops at the request's total timeout, and
/// the close is skipped once the time is up.
#[tokio::test]
async fn an_endless_event_stream_is_bounded_by_the_session_deadline() {
    init();
    let f = mcp::serve("127.0.0.1:0", hostile(Hostile::EndlessStream)).await.unwrap();
    let e = Engine::new();
    let mut c = mcp_ctx(&f.url(), list());
    let timeouts = TimeoutOverrides { total_ms: Some(Some(1500)), ..Default::default() };
    c.settings_layers.push(("run".into(), SettingsOverrides { timeouts: Some(timeouts), ..Default::default() }));
    let started = std::time::Instant::now();
    let o = run(&e, &c).await;
    let took = started.elapsed();
    assert!(took < std::time::Duration::from_secs(6), "took {took:?}");
    let n = notes(&o);
    assert!(n.contains("MCP session deadline (1500 ms"), "{n}");
    assert!(n.contains("MCP session not closed: the session deadline was reached"), "{n}");
    assert_ne!(o.record.outcome.application, ApplicationState::Success, "{}", o.record.outcome.summary);
    assert!(f.state.calls().iter().all(|c| c.http_method == "POST"), "no DELETE after the deadline");
}

/// A redirect of the operation to another origin does not carry the session
/// id there (it is a credential).
#[tokio::test]
async fn a_cross_origin_redirect_drops_the_session_id() {
    init();
    let other = anvil_fixtures::http::serve("127.0.0.1:0", None).await.unwrap();
    let to: &'static str = Box::leak(other.url("/echo").into_boxed_str());
    let f = mcp::serve("127.0.0.1:0", hostile(Hostile::RedirectOperation(to))).await.unwrap();
    let e = Engine::new();
    let o = run(&e, &mcp_ctx(&f.url(), list())).await;
    let headers = other.log.last_request_headers().expect("the redirect was followed");
    assert!(!headers.iter().any(|(n, _)| n.eq_ignore_ascii_case("mcp-session-id")), "{headers:?}");
    assert!(headers.iter().any(|(n, _)| n.eq_ignore_ascii_case("mcp-protocol-version")), "{headers:?}");
    assert!(notes(&o).contains("credential headers withheld on the redirect"), "{}", notes(&o));
    assert_eq!(f.state.closed.lock().len(), 1, "the session is still ended at its own origin");
}

#[tokio::test]
async fn a_cross_origin_redirect_drops_the_session_id_when_credential_forwarding_is_enabled() {
    init();
    let other = anvil_fixtures::http::serve("127.0.0.1:0", None).await.unwrap();
    let to: &'static str = Box::leak(other.url("/echo").into_boxed_str());
    let f = mcp::serve("127.0.0.1:0", hostile(Hostile::RedirectOperation(to))).await.unwrap();
    let e = Engine::new();
    let mut ctx = mcp_ctx(&f.url(), list());
    ctx.settings_layers.push((
        "test".into(),
        SettingsOverrides {
            redirects: Some(anvil_domain::settings::RedirectPolicy {
                follow: true,
                max: 10,
                forward_credentials_cross_origin: true,
            }),
            ..Default::default()
        },
    ));
    let o = run(&e, &ctx).await;
    let headers = other.log.last_request_headers().expect("the redirect was followed");
    assert!(!headers.iter().any(|(n, _)| n.eq_ignore_ascii_case("mcp-session-id")), "{headers:?}");
    assert!(headers.iter().any(|(n, _)| n.eq_ignore_ascii_case("mcp-protocol-version")), "{headers:?}");
    assert!(notes(&o).contains("MCP session header withheld on the cross-origin redirect"), "{}", notes(&o));
}

#[tokio::test]
async fn initialize_does_not_follow_a_cross_origin_redirect() {
    init();
    let other = anvil_fixtures::http::serve("127.0.0.1:0", None).await.unwrap();
    let to: &'static str = Box::leak(other.url("/echo").into_boxed_str());
    let f = mcp::serve("127.0.0.1:0", hostile(Hostile::RedirectInitialize(to))).await.unwrap();
    let e = Engine::new();
    let o = run(&e, &mcp_ctx(&f.url(), list())).await;
    assert_eq!(status(&o), Some(307));
    assert_eq!(f.state.methods(), ["initialize"]);
    assert!(other.log.entries().is_empty(), "initialize redirects are not followed");
    assert!(notes(&o).contains("MCP initialize was answered with HTTP 307, not a session"), "{}", notes(&o));
}
