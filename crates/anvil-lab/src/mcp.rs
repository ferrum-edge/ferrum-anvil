//! Scenarios for the `mcp` gateway profile (HTTP 127.0.0.1:17180): Ferrum
//! Edge's `mcp_gateway` plugin in aggregate-router mode in front of the MCP
//! fixture server (`lab/gateway/mcp.{conf,yaml}`, docs/lab/mcp.md). Anvil
//! runs MCP requests (a session each: initialize, notifications/initialized,
//! the operation, DELETE) and must explain the gateway's policy outcomes
//! (allow, deny, hide, schema validation, unknown tools, a request outside a
//! session) with the release's catalog, while a tool's own failure stays the
//! tool's. The fixture's record of the calls that reached it is the ground
//! truth that the gateway allowed or refused a call; it is never given to
//! the engine.

use crate::fixtures_policy::{Target, catalog_outcome, codes, request};
use crate::gateway::Gateway;
use crate::harness::{self, LabEnv, Outcome, RunCtx};
use crate::profiles::{BoxFut, Profile, RunArgs};
use crate::scenario::{CheckKind, Checks, ScenarioResult};
use anvil_domain::assertions::{Assertion, AssertionKind, Comparison};
use anvil_domain::diagnostics::Confidence;
use anvil_domain::outcome::{ApplicationState, AssertionState};
use anvil_domain::request::{McpOperation, McpSpec, Protocol, RequestSpec};
use anvil_engine::{Engine, ExecutionContext, ExecutionOutput};
use anvil_fixtures::mcp::{self, McpFixture, McpOptions};
use anvil_transport::recorder::EventCtx;
use std::future::Future;
use std::pin::Pin;
use tokio_util::sync::CancellationToken;

pub const TARGET: Target = Target { base: "http://127.0.0.1:17180", port: 17180, profile_name: "lab mcp gateway", isolation: "lab-mcp" };
const ADMIN_PORT: u16 = 17190;
/// The gateway's MCP endpoint (`endpoint.path`).
const ENDPOINT: &str = "/mcp";

pub struct Env {
    pub engine: Engine,
    /// 17101: the upstream MCP server behind the gateway (JSON answers).
    pub upstream: McpFixture,
    /// 17102: the same server answering with event streams, addressed
    /// directly (the positive control; no gateway).
    pub direct_sse: McpFixture,
    pub gateway: Gateway,
    pub trusted: bool,
}

impl LabEnv for Env {
    fn set_trusted(&mut self, trusted: bool) {
        self.trusted = trusted;
    }
    fn operator_logs(&self) -> Vec<std::path::PathBuf> {
        vec![self.gateway.log_path.clone()]
    }
}

type Def = harness::Def<Env>;
type Fut<'a> = Pin<Box<dyn Future<Output = Outcome> + 'a>>;

fn spec_of(operation: McpOperation) -> McpSpec {
    let operation = serde_json::to_value(operation).unwrap_or_default();
    serde_json::from_value(serde_json::json!({ "operation": operation })).expect("a valid MCP spec")
}

fn as_mcp(mut c: ExecutionContext, operation: McpOperation, assertions: Vec<AssertionKind>) -> ExecutionContext {
    c.spec.protocol = Protocol::Mcp;
    c.spec.mcp = Some(spec_of(operation));
    c.spec.assertions = assertions.into_iter().map(|kind| Assertion { enabled: true, label: String::new(), kind }).collect();
    c
}

/// An MCP request to the gateway's endpoint.
fn gateway(env: &Env, operation: McpOperation, assertions: Vec<AssertionKind>) -> ExecutionContext {
    as_mcp(request(&TARGET, env.trusted, "POST", ENDPOINT), operation, assertions)
}

fn call(name: &str, arguments: &str) -> McpOperation {
    McpOperation::ToolsCall { name: name.into(), arguments: arguments.into() }
}

async fn send(env: &Env, c: &ExecutionContext) -> ExecutionOutput {
    env.engine.execute(c, EventCtx::none(), CancellationToken::new()).await
}

fn assertions_pass(c: &mut Checks, o: &ExecutionOutput) {
    let results = o.record.assertion_results.iter();
    let failed: Vec<String> = results.filter(|r| !r.passed).map(|r| format!("{}: {}", r.label, r.message)).collect();
    let passed = o.record.outcome.assertions == AssertionState::Pass;
    c.add(CheckKind::Diagnosis, "the request's MCP assertions pass", passed, failed.join("; "));
}

fn application_failure(c: &mut Checks, o: &ExecutionOutput) {
    let failed = o.record.outcome.application == ApplicationState::Failure;
    c.add(CheckKind::Diagnosis, "an application failure", failed, o.record.outcome.summary.clone());
}

/// With a trusted destination, the release's catalog outcome `outcome` is
/// the explanation (capped at likely: plain HTTP, and a body a server could
/// also send); untrusted, the harness checks that no gateway attribution is
/// made.
fn outcome(c: &mut Checks, env: &Env, o: &ExecutionOutput, outcome: &str) {
    if env.trusted {
        let matched = catalog_outcome(o);
        let detail = format!("{matched:?} {:?}", codes(o));
        c.add(CheckKind::Diagnosis, format!("catalog outcome {outcome}"), matched.as_deref() == Some(outcome), detail);
        c.max_confidence(o, "ferrum.outcome", Confidence::Likely);
    }
    c.has(o, "app.jsonrpc_error");
    application_failure(c, o);
}

/// Ground truth: calls of `tool` that reached the upstream server.
fn reached(c: &mut Checks, env: &Env, tool: &str, before: usize, expected: bool) {
    let n = env.upstream.state.tool_calls(tool) - before;
    let what = if expected { "forwarded" } else { "did not forward" };
    let what = format!("the gateway {what} the {tool} call");
    c.add(CheckKind::GroundTruth, what, (n == 1) == expected, format!("{n} call(s) reached the server"));
}

fn done(o: ExecutionOutput, c: Checks) -> Outcome {
    Outcome { main: Some(o), recovery: None, checks: c, operator_log: vec![] }
}

/// CTRL-MCP-001: the fixture server addressed directly, answering with event
/// streams: the session, the list and a call all succeed.
fn ctrl(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let direct = ExecutionContext::standalone(RequestSpec::http("POST", &env.direct_sse.url()));
        let text = "$.result.structuredContent.text".to_string();
        let checks = vec![
            AssertionKind::JsonRpcResult,
            AssertionKind::McpIsError { is_error: false },
            AssertionKind::JsonPath { path: text, comparison: Comparison::Equals, value: "direct".into() },
        ];
        let o = send(env, &as_mcp(direct, call("echo", r#"{"text":"direct"}"#), checks)).await;
        c.success(CheckKind::Diagnosis, &o);
        assertions_pass(&mut c, &o);
        let notes = o.record.prepared.inferred.join("\n");
        let read = notes.contains("the JSON-RPC response was read from it");
        c.add(CheckKind::Diagnosis, "the JSON-RPC response was read from the event stream", read, notes);
        let methods = env.direct_sse.state.methods();
        let first: Vec<&str> = methods.iter().take(3).map(String::as_str).collect();
        let session = first == ["initialize", "notifications/initialized", "tools/call"];
        c.add(CheckKind::GroundTruth, "the server saw initialize, notifications/initialized, tools/call", session, format!("{methods:?}"));
        c.add(CheckKind::GroundTruth, "the session was ended", !env.direct_sse.state.closed.lock().is_empty(), "");
        c.absent_prefix(&o, "ferrum.");
        done(o, c)
    })
}

/// MCP-001: tools/list through the gateway: allowed and denied tools are
/// listed (denied ones are shown in this profile), the hidden tool and the
/// unconfigured new tool are not, and a listed schema is the server's.
fn mcp001(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let echo_schema = mcp::tools().as_array().and_then(|t| t.first()).map(|t| t["inputSchema"].clone()).unwrap_or_default();
        let sha = anvil_engine::assertions::schema_sha256(&echo_schema);
        let checks = vec![
            AssertionKind::JsonRpcResult,
            AssertionKind::ToolPresent { name: "fx.echo".into() },
            AssertionKind::ToolPresent { name: "fx.delete_all".into() },
            AssertionKind::ToolAbsent { name: "fx.internal_audit".into() },
            AssertionKind::ToolAbsent { name: "fx.new_tool".into() },
            AssertionKind::ToolInputSchema { name: "fx.echo".into(), schema: None, sha256: Some(sha) },
        ];
        let o = send(env, &gateway(env, McpOperation::ToolsList { cursor: None }, checks)).await;
        c.success(CheckKind::Diagnosis, &o);
        assertions_pass(&mut c, &o);
        c.absent_prefix(&o, "ferrum.outcome");
        let listed = env.upstream.state.methods().iter().any(|m| m == "tools/list");
        c.add(CheckKind::GroundTruth, "the gateway listed the upstream server's tools", listed, "");
        done(o, c)
    })
}

/// MCP-002: an allowed tool call is forwarded and answered by the tool;
/// its structured content is checked with JSONPath.
fn mcp002(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let before = env.upstream.state.tool_calls("echo");
        let text = "$.result.structuredContent.text".to_string();
        let checks = vec![
            AssertionKind::JsonRpcResult,
            AssertionKind::McpIsError { is_error: false },
            AssertionKind::JsonPath { path: text, comparison: Comparison::Equals, value: "through the gateway".into() },
        ];
        let o = send(env, &gateway(env, call("fx.echo", r#"{"text":"through the gateway"}"#), checks)).await;
        c.success(CheckKind::Diagnosis, &o);
        assertions_pass(&mut c, &o);
        c.absent_prefix(&o, "ferrum.outcome");
        reached(&mut c, env, "echo", before, true);
        done(o, c)
    })
}

/// A call the gateway refuses with a JSON-RPC error: `code` is asserted,
/// `outcome` is the catalog explanation, and the tool is never reached.
async fn refused(env: &Env, operation: McpOperation, code: i64, catalog: &str, tool: &str) -> Outcome {
    let mut c = Checks::new();
    let before = env.upstream.state.tool_calls(tool);
    let o = send(env, &gateway(env, operation, vec![AssertionKind::JsonRpcError { code }])).await;
    c.status_in(&o, &[200]);
    assertions_pass(&mut c, &o);
    outcome(&mut c, env, &o, catalog);
    reached(&mut c, env, tool, before, false);
    done(o, c)
}

/// MCP-003: a denied tool: JSON-RPC -32001 (tool_denied).
fn mcp003(env: &Env) -> Fut<'_> {
    Box::pin(refused(env, call("fx.delete_all", "{}"), -32001, "plugin.mcp_gateway.tool_denied", "delete_all"))
}

/// MCP-004: a hidden tool, called by name: denied like any tool the policy
/// does not allow (tool_denied), and never listed (MCP-001).
fn mcp004(env: &Env) -> Fut<'_> {
    Box::pin(refused(env, call("fx.internal_audit", "{}"), -32001, "plugin.mcp_gateway.tool_denied", "internal_audit"))
}

/// MCP-005: arguments that fail the tool's inputSchema: -32602
/// (invalid_params), refused before the tool.
fn mcp005(env: &Env) -> Fut<'_> {
    Box::pin(refused(env, call("fx.echo", r#"{"text":42}"#), -32602, "plugin.mcp_gateway.invalid_params", "echo"))
}

/// MCP-006: a tool the catalog does not know: -32003 (unknown_item).
fn mcp006(env: &Env) -> Fut<'_> {
    Box::pin(refused(env, call("fx.nope", "{}"), -32003, "plugin.mcp_gateway.unknown_item", "nope"))
}

/// MCP-007: a request outside a session (initialize off): HTTP 400 with a
/// JSON-RPC error (session_or_version_rejected), never forwarded.
fn mcp007(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let mut ctx = gateway(env, McpOperation::ToolsList { cursor: None }, vec![AssertionKind::JsonRpcError { code: -32600 }]);
        if let Some(m) = ctx.spec.mcp.as_mut() {
            m.initialize = false;
        }
        let o = send(env, &ctx).await;
        c.status_in(&o, &[400]);
        assertions_pass(&mut c, &o);
        if env.trusted {
            let matched = catalog_outcome(&o);
            let ok = matched.as_deref() == Some("plugin.mcp_gateway.session_or_version_rejected");
            c.add(CheckKind::Diagnosis, "catalog outcome session_or_version_rejected", ok, format!("{matched:?}"));
        }
        c.not_success(&o);
        done(o, c)
    })
}

/// MCP-008: a tool that reports its own failure (`isError: true`): the call
/// was allowed and answered; the failure is the tool's, not the gateway's.
fn mcp008(env: &Env) -> Fut<'_> {
    Box::pin(async move {
        let mut c = Checks::new();
        let before = env.upstream.state.tool_calls("fail");
        let checks = vec![AssertionKind::JsonRpcResult, AssertionKind::McpIsError { is_error: true }];
        let o = send(env, &gateway(env, call("fx.fail", "{}"), checks)).await;
        assertions_pass(&mut c, &o);
        c.has(&o, "app.mcp_tool_error");
        c.absent_prefix(&o, "ferrum.outcome");
        c.absent_prefix(&o, "ferrum.jsonrpc_code");
        application_failure(&mut c, &o);
        reached(&mut c, env, "fail", before, true);
        done(o, c)
    })
}

pub fn all() -> Vec<Def> {
    vec![
        Def { id: "CTRL-MCP-001", title: "MCP session straight to the server, answers as event streams", run: ctrl },
        Def { id: "MCP-001", title: "tools/list through the gateway: denied listed, hidden and unconfigured not", run: mcp001 },
        Def { id: "MCP-002", title: "Allowed tool call forwarded; structuredContent checked", run: mcp002 },
        Def { id: "MCP-003", title: "Denied tool: JSON-RPC -32001 explained as tool_denied", run: mcp003 },
        Def { id: "MCP-004", title: "Hidden tool called by name: denied, never forwarded", run: mcp004 },
        Def { id: "MCP-005", title: "Arguments failing the inputSchema: -32602 invalid_params", run: mcp005 },
        Def { id: "MCP-006", title: "Unknown tool: -32003 unknown_item", run: mcp006 },
        Def { id: "MCP-007", title: "Request without a session: 400 session_or_version_rejected", run: mcp007 },
        Def { id: "MCP-008", title: "Tool reports isError: the tool's failure, not the gateway's", run: mcp008 },
    ]
}

pub fn profile() -> Profile {
    Profile {
        name: "mcp",
        about: "MCP over Streamable HTTP through mcp_gateway (aggregate router): allow, deny, hide, schema validation (HTTP 17180)",
        scenarios: || all().into_iter().map(|d| (d.id, d.title)).collect(),
        run: |args| Box::pin(run(args)) as BoxFut<_>,
        up: || Box::pin(up()) as BoxFut<_>,
    }
}

async fn start() -> anyhow::Result<Env> {
    let upstream = mcp::serve("127.0.0.1:17101", McpOptions::default()).await?;
    let direct_sse = mcp::serve("127.0.0.1:17102", McpOptions { sse: true, ..Default::default() }).await?;
    let gateway = Gateway::start("mcp", "mcp.conf", "mcp.yaml", &[], ADMIN_PORT, &[]).await?;
    Ok(Env { engine: Engine::new(), upstream, direct_sse, gateway, trusted: true })
}

async fn run(args: RunArgs) -> anyhow::Result<Vec<ScenarioResult>> {
    let ctx = RunCtx::new("mcp")?;
    let mut env = start().await?;
    let results = harness::run_defs(&ctx, &mut env, all(), &args.only, args.untrusted_pass).await?;
    harness::finish(&ctx, &env, &results)?;
    env.gateway.stop().await;
    Ok(results)
}

async fn up() -> anyhow::Result<()> {
    let env = start().await?;
    let log = env.gateway.log_path.display();
    println!("mcp lab running: gateway {}{ENDPOINT} (admin 127.0.0.1:{ADMIN_PORT}); operator log {log}", TARGET.base);
    println!("MCP server behind it: {} (JSON); direct, event streams: {}", env.upstream.url(), env.direct_sse.url());
    harness::wait_for_shutdown().await?;
    env.gateway.stop().await;
    Ok(())
}
