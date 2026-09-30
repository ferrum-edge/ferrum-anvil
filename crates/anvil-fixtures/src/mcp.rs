//! A Model Context Protocol server over Streamable HTTP (MCP 2025-11-25,
//! "Transports") for engine tests and the `mcp` lab profile. HTTP/1.1 only,
//! one endpoint (`/mcp`), bounded request bodies.
//!
//! * `POST initialize` opens a session: the answer carries an
//!   `Mcp-Session-Id`. Every other POST needs a known session (missing:
//!   400 with a JSON-RPC error; unknown: 404) and, when it sends one, a
//!   supported `MCP-Protocol-Version` (else 400). A POST must accept both
//!   `application/json` and `text/event-stream` (else 406) and send JSON
//!   (else 415).
//! * Notifications (no `id`) are answered `202 Accepted` with no body.
//! * Requests are answered with JSON, or with [`McpOptions::sse`] with an
//!   event stream: a `notifications/message` log event, then the response,
//!   then the end of the stream.
//! * `DELETE` ends the session (405 without [`McpOptions::allow_delete`]);
//!   `GET` is refused with 405 (no server-initiated stream).
//!
//! Tools (`tools/list`, `tools/call`): `echo` (`text`, required; the result
//! also as `structuredContent`), `add` (`a`, `b`: numbers with defaults),
//! `fail` (a result with `isError: true`), `session` (answers with the
//! session id it was called in), and `delete_all`, `internal_audit`,
//! `new_tool` (they answer "ran <name>"; the lab's gateway policy denies,
//! hides or has not configured them). An unknown tool is JSON-RPC error
//! -32602. Resources: `fixture://readme`; prompts: `greet` (`who`).
//!
//! [`McpOptions::hostile`] makes the server misbehave in one way (a session
//! id or protocol version Anvil must not send back, an initialize error that
//! echoes a request header, an operation answered with an endless event
//! stream or a redirect), for the engine's safety tests.
//!
//! What each request asked for is kept in [`McpState`] as ground truth; it
//! is never given to the diagnostic engine.

use crate::log::{GroundTruth, GroundTruthLog};
use bytes::Bytes;
use http::{HeaderValue, Method, Request, Response};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, Limited, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use parking_lot::Mutex;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

/// The endpoint path.
pub const PATH: &str = "/mcp";
/// Protocol versions the fixture accepts; the first is chosen for an
/// unsupported request.
pub const SUPPORTED_VERSIONS: &[&str] = &["2025-11-25", "2025-06-18", "2025-03-26"];
/// Largest request body read.
const MAX_BODY: usize = 1024 * 1024;

type FxBody = BoxBody<Bytes, Infallible>;

#[derive(Debug, Clone, Copy)]
pub struct McpOptions {
    /// Answer requests with an event stream instead of JSON.
    pub sse: bool,
    /// Let clients end their session with `DELETE`.
    pub allow_delete: bool,
    pub hostile: Hostile,
}

impl Default for McpOptions {
    fn default() -> Self {
        McpOptions { sse: false, allow_delete: true, hostile: Hostile::None }
    }
}

/// One way the server misbehaves.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Hostile {
    #[default]
    None,
    /// `initialize` issues this session id (and keeps no session).
    SessionId(&'static str),
    /// `initialize` answers with this protocol version.
    ProtocolVersion(&'static str),
    /// `initialize` opens a session but answers with a JSON-RPC error whose
    /// message quotes the value of this request header.
    InitializeErrorEchoing(&'static str),
    /// Requests after the handshake are answered with an event stream that
    /// never ends (a comment every 100 ms, for up to a minute).
    EndlessStream,
    /// Requests after the handshake are answered `307` to this URL.
    RedirectOperation(&'static str),
}

/// One request the fixture received.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpCall {
    pub http_method: String,
    /// The JSON-RPC method (`None` for a DELETE or a body that is not one).
    pub method: Option<String>,
    /// `params.name` of a `tools/call` or `prompts/get`.
    pub name: Option<String>,
    pub session: Option<String>,
    pub protocol_version: Option<String>,
    pub accept: Option<String>,
    pub status: u16,
}

#[derive(Default)]
pub struct McpState {
    issued: AtomicU64,
    /// Open sessions.
    pub sessions: Mutex<Vec<String>>,
    /// Sessions ended with `DELETE`.
    pub closed: Mutex<Vec<String>>,
    /// Every request, in order.
    pub calls: Mutex<Vec<McpCall>>,
}

impl McpState {
    pub fn calls(&self) -> Vec<McpCall> {
        self.calls.lock().clone()
    }

    /// The JSON-RPC methods received, in order.
    pub fn methods(&self) -> Vec<String> {
        self.calls.lock().iter().filter_map(|c| c.method.clone()).collect()
    }

    /// `tools/call`s of `name` received.
    pub fn tool_calls(&self, name: &str) -> usize {
        self.calls.lock().iter().filter(|c| c.method.as_deref() == Some("tools/call") && c.name.as_deref() == Some(name)).count()
    }
}

pub struct McpFixture {
    pub addr: SocketAddr,
    pub log: GroundTruthLog,
    pub state: Arc<McpState>,
    cancel: CancellationToken,
}

impl McpFixture {
    /// The endpoint URL.
    pub fn url(&self) -> String {
        format!("http://{}{PATH}", self.addr)
    }
}

impl Drop for McpFixture {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

fn reply(status: u16, content_type: Option<&str>, body: impl Into<Bytes>) -> Response<FxBody> {
    let mut b = Response::builder().status(status);
    if let Some(ct) = content_type {
        b = b.header("content-type", ct);
    }
    b.body(Full::new(body.into()).boxed()).unwrap_or_else(|_| Response::new(Full::new(Bytes::new()).boxed()))
}

/// An event stream that starts with a log notification and then only sends
/// comments, until the client goes away (or a minute passes).
fn endless_stream() -> Response<FxBody> {
    let (mut tx, rx) = futures::channel::mpsc::channel::<Result<Frame<Bytes>, Infallible>>(4);
    tokio::spawn(async move {
        use futures::SinkExt;
        let first = "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/message\",\"params\":{}}\n\n";
        if tx.send(Ok(Frame::data(Bytes::from_static(first.as_bytes())))).await.is_err() {
            return;
        }
        for _ in 0..600 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            if tx.send(Ok(Frame::data(Bytes::from_static(b": still working\n\n")))).await.is_err() {
                return;
            }
        }
    });
    let body = StreamBody::new(rx).boxed();
    Response::builder()
        .status(200)
        .header("content-type", "text/event-stream")
        .body(body)
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()).boxed()))
}

fn rpc_error(id: &Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}

fn rpc_result(id: &Value, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

/// The tools `tools/list` answers with.
pub fn tools() -> Value {
    let object = json!({"type": "object"});
    json!([
        {
            "name": "echo",
            "title": "Echo",
            "description": "Returns its text.",
            "inputSchema": {
                "type": "object",
                "properties": {"text": {"type": "string", "description": "Text to echo", "examples": ["hello"]}},
                "required": ["text"]
            },
            "outputSchema": {"type": "object", "properties": {"text": {"type": "string"}}, "required": ["text"]}
        },
        {
            "name": "add",
            "description": "Adds two numbers.",
            "inputSchema": {
                "type": "object",
                "properties": {"a": {"type": "number", "default": 2}, "b": {"type": "number", "default": 3}},
                "required": ["a", "b"]
            }
        },
        {"name": "fail", "description": "Always reports a tool error.", "inputSchema": object},
        {"name": "session", "description": "Returns the session id it was called in.", "inputSchema": object},
        {"name": "delete_all", "description": "A destructive tool the lab policy denies.", "inputSchema": object},
        {"name": "internal_audit", "description": "A tool the lab policy hides.", "inputSchema": object},
        {"name": "new_tool", "description": "A tool the lab policy has not configured.", "inputSchema": object}
    ])
}

fn text_result(text: &str) -> Value {
    json!({"content": [{"type": "text", "text": text}]})
}

fn call_tool(params: &Value, session: &str) -> Result<Value, (i64, String)> {
    let name = params.get("name").and_then(Value::as_str).unwrap_or("");
    let args = params.get("arguments").cloned().unwrap_or_else(|| json!({}));
    match name {
        "echo" => {
            let Some(text) = args.get("text").and_then(Value::as_str) else {
                return Err((-32602, "Invalid params: echo needs a text argument".into()));
            };
            Ok(json!({"content": [{"type": "text", "text": text}], "structuredContent": {"text": text}}))
        }
        "add" => {
            let (Some(a), Some(b)) = (args.get("a").and_then(Value::as_f64), args.get("b").and_then(Value::as_f64)) else {
                return Err((-32602, "Invalid params: add needs numbers a and b".into()));
            };
            Ok(json!({"content": [{"type": "text", "text": format!("{}", a + b)}], "structuredContent": {"sum": a + b}}))
        }
        "fail" => Ok(json!({"content": [{"type": "text", "text": "the fixture tool failed on purpose"}], "isError": true})),
        "session" => Ok(text_result(&format!("session {session}"))),
        "delete_all" | "internal_audit" | "new_tool" => Ok(text_result(&format!("ran {name}"))),
        other => Err((-32602, format!("Unknown tool: {other}"))),
    }
}

/// The result of a request in a session, or its JSON-RPC error.
fn dispatch(method: &str, params: &Value, session: &str) -> Result<Value, (i64, String)> {
    match method {
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({"tools": tools()})),
        "tools/call" => call_tool(params, session),
        "resources/list" => Ok(json!({"resources": [{"uri": "fixture://readme", "name": "readme", "mimeType": "text/plain"}]})),
        "resources/templates/list" => Ok(json!({"resourceTemplates": []})),
        "resources/read" => match params.get("uri").and_then(Value::as_str) {
            Some(uri @ "fixture://readme") => {
                Ok(json!({"contents": [{"uri": uri, "mimeType": "text/plain", "text": "Anvil MCP fixture"}]}))
            }
            _ => Err((-32002, "Resource not found".into())),
        },
        "prompts/list" => Ok(json!({"prompts": [{"name": "greet", "arguments": [{"name": "who", "required": true}]}]})),
        "prompts/get" => {
            let who = params.get("arguments").and_then(|a| a.get("who")).and_then(Value::as_str).unwrap_or("there");
            Ok(json!({"messages": [{"role": "user", "content": {"type": "text", "text": format!("Hello, {who}")}}]}))
        }
        _ => Err((-32601, "Method not found".into())),
    }
}

/// A JSON-RPC answer, as JSON or (with `sse`) as an event stream with a log
/// notification before it.
fn answer(opts: McpOptions, status: u16, message: &Value, session: Option<&str>) -> Response<FxBody> {
    let mut resp = if opts.sse {
        let log = json!({"jsonrpc": "2.0", "method": "notifications/message", "params": {"level": "info", "data": "fixture: working"}});
        let body = format!("event: message\ndata: {log}\n\nid: 1\nevent: message\ndata: {message}\n\n");
        reply(status, Some("text/event-stream"), body)
    } else {
        reply(status, Some("application/json"), message.to_string())
    };
    if let Some(s) = session.and_then(|s| http::HeaderValue::from_str(s).ok()) {
        resp.headers_mut().insert("mcp-session-id", s);
    }
    resp
}

fn header(req: &Request<Incoming>, name: &str) -> Option<String> {
    req.headers().get(name).and_then(|v| v.to_str().ok()).map(str::to_string)
}

/// The parts of a request the endpoint reads.
struct Asked<'a> {
    http_method: &'a Method,
    path: &'a str,
    message: Option<&'a Value>,
    params: &'a Value,
    session: Option<&'a str>,
    version: Option<&'a str>,
    accept: Option<&'a str>,
    content_type: Option<&'a str>,
    /// The header [`Hostile::InitializeErrorEchoing`] quotes.
    echo: Option<&'a str>,
}

async fn route(
    req: Request<Incoming>,
    log: GroundTruthLog,
    state: Arc<McpState>,
    opts: McpOptions,
    addr: SocketAddr,
) -> Response<FxBody> {
    let http_method = req.method().clone();
    let path = req.uri().path().to_string();
    let headers: Vec<(String, String)> =
        req.headers().iter().map(|(n, v)| (n.as_str().to_string(), String::from_utf8_lossy(v.as_bytes()).into_owned())).collect();
    let session = header(&req, "mcp-session-id");
    let version = header(&req, "mcp-protocol-version");
    let accept = header(&req, "accept");
    let content_type = header(&req, "content-type");
    let echo = match opts.hostile {
        Hostile::InitializeErrorEchoing(name) => header(&req, name),
        _ => None,
    };
    let body = match Limited::new(req.into_body(), MAX_BODY).collect().await {
        Ok(b) => b.to_bytes(),
        Err(_) => return reply(413, Some("application/json"), r#"{"error":"fixture request body limit"}"#),
    };
    log.push(GroundTruth::RequestReceived { method: http_method.to_string(), path: path.clone(), body_bytes: body.len() as u64, headers });
    let parsed: Option<Value> = serde_json::from_slice(&body).ok();
    let method = parsed.as_ref().and_then(|v| v.get("method")).and_then(Value::as_str).map(str::to_string);
    let params = parsed.as_ref().and_then(|v| v.get("params")).cloned().unwrap_or(Value::Null);
    let name = params.get("name").and_then(Value::as_str).map(str::to_string);
    let asked = Asked {
        http_method: &http_method,
        path: &path,
        message: parsed.as_ref(),
        params: &params,
        session: session.as_deref(),
        version: version.as_deref(),
        accept: accept.as_deref(),
        content_type: content_type.as_deref(),
        echo: echo.as_deref(),
    };
    let resp = handle(&state, opts, addr, &asked);
    let status = resp.status().as_u16();
    log.push(GroundTruth::ResponseStarted { status });
    let call = McpCall { http_method: http_method.to_string(), method, name, session, protocol_version: version, accept, status };
    state.calls.lock().push(call);
    resp
}

/// Whether `accept` lists a media type (or a wildcard for it).
fn accepts(accept: Option<&str>, media: &str) -> bool {
    let wildcard = format!("{}/*", media.split('/').next().unwrap_or(""));
    let mut listed = accept.unwrap_or("").split(',').map(|m| m.split(';').next().unwrap_or("").trim());
    listed.any(|m| m == media || m == "*/*" || m == wildcard)
}

fn json_error(status: u16, id: &Value, message: &str) -> Response<FxBody> {
    reply(status, Some("application/json"), rpc_error(id, -32600, message).to_string())
}

fn handle(state: &McpState, opts: McpOptions, addr: SocketAddr, r: &Asked<'_>) -> Response<FxBody> {
    if r.path != PATH {
        return reply(404, Some("text/plain"), "not the MCP endpoint");
    }
    let known = |s: &str| state.sessions.lock().iter().any(|x| x == s);
    if *r.http_method == Method::DELETE {
        if !opts.allow_delete {
            return reply(405, None, "");
        }
        return match r.session {
            None => json_error(400, &Value::Null, "Missing Mcp-Session-Id"),
            Some(s) if known(s) => {
                state.sessions.lock().retain(|x| x != s);
                state.closed.lock().push(s.to_string());
                reply(200, None, "")
            }
            Some(_) => reply(404, None, ""),
        };
    }
    if *r.http_method != Method::POST {
        let mut resp = reply(405, None, "");
        resp.headers_mut().insert("allow", http::HeaderValue::from_static("POST, DELETE"));
        return resp;
    }
    let json_body = r.content_type.and_then(|ct| ct.split(';').next()).is_some_and(|m| m.trim().eq_ignore_ascii_case("application/json"));
    if !json_body {
        return json_error(415, &Value::Null, "Content-Type must be application/json");
    }
    if !(accepts(r.accept, "application/json") && accepts(r.accept, "text/event-stream")) {
        return json_error(406, &Value::Null, "Accept must list application/json and text/event-stream");
    }
    let Some(message) = r.message.filter(|v| v.is_object()) else {
        return json_error(400, &Value::Null, "Invalid Request");
    };
    let id = message.get("id").cloned();
    let method = message.get("method").and_then(Value::as_str).unwrap_or("");
    if method == "initialize" {
        let Some(id) = id else { return json_error(400, &Value::Null, "initialize needs an id") };
        let requested = r.params.get("protocolVersion").and_then(Value::as_str).unwrap_or("");
        let supported = SUPPORTED_VERSIONS.iter().find(|v| **v == requested).copied().unwrap_or(SUPPORTED_VERSIONS[0]);
        let chosen = match opts.hostile {
            Hostile::ProtocolVersion(v) => v,
            _ => supported,
        };
        let n = state.issued.fetch_add(1, Ordering::Relaxed);
        let digest = Sha256::digest(format!("{addr}-{n}").as_bytes());
        let tail: String = digest.iter().take(12).map(|b| format!("{b:02x}")).collect();
        let sid = format!("mcp-fixture-{n}-{tail}");
        if let Hostile::SessionId(bad) = opts.hostile {
            let result = json!({"protocolVersion": chosen, "capabilities": {}, "serverInfo": {"name": "hostile", "version": "1"}});
            return answer(opts, 200, &rpc_result(&id, result), Some(bad));
        }
        state.sessions.lock().push(sid.clone());
        if let Hostile::InitializeErrorEchoing(_) = opts.hostile {
            let message = format!("rejected credential {}", r.echo.unwrap_or("(none)"));
            return answer(opts, 200, &rpc_error(&id, -32600, &message), Some(&sid));
        }
        let result = json!({
            "protocolVersion": chosen,
            "capabilities": {"tools": {"listChanged": false}, "resources": {}, "prompts": {}},
            "serverInfo": {"name": "anvil-mcp-fixture", "version": "1.0.0"}
        });
        return answer(opts, 200, &rpc_result(&id, result), Some(&sid));
    }
    let id = id.unwrap_or(Value::Null);
    let Some(session) = r.session else { return json_error(400, &id, "Missing Mcp-Session-Id header") };
    if !known(session) {
        return reply(404, None, "");
    }
    if r.version.is_some_and(|v| !SUPPORTED_VERSIONS.contains(&v)) {
        return json_error(400, &id, "Unsupported MCP-Protocol-Version");
    }
    if id.is_null() && message.get("id").is_none() {
        // A notification.
        return reply(202, None, "");
    }
    match opts.hostile {
        Hostile::EndlessStream => return endless_stream(),
        Hostile::RedirectOperation(to) => {
            let mut resp = reply(307, None, "");
            if let Ok(v) = HeaderValue::from_str(to) {
                resp.headers_mut().insert("location", v);
            }
            return resp;
        }
        _ => {}
    }
    let answered = match dispatch(method, r.params, session) {
        Ok(result) => rpc_result(&id, result),
        Err((code, text)) => rpc_error(&id, code, &text),
    };
    answer(opts, 200, &answered, None)
}

/// Start the fixture. `bind` like `127.0.0.1:0`.
pub async fn serve(bind: &str, opts: McpOptions) -> anyhow::Result<McpFixture> {
    let listener = TcpListener::bind(bind).await?;
    let addr = listener.local_addr()?;
    let log = GroundTruthLog::default();
    let state = Arc::new(McpState::default());
    let cancel = CancellationToken::new();
    let (l2, s2, c2) = (log.clone(), state.clone(), cancel.clone());
    tokio::spawn(async move {
        loop {
            let (stream, peer) = tokio::select! {
                r = listener.accept() => match r { Ok(x) => x, Err(_) => continue },
                _ = c2.cancelled() => break,
            };
            let _ = stream.set_nodelay(true);
            l2.push(GroundTruth::ConnectionAccepted { peer: peer.to_string() });
            let (log, state, cancel) = (l2.clone(), s2.clone(), c2.clone());
            tokio::spawn(async move {
                let svc = service_fn(move |req| {
                    let (log, state) = (log.clone(), state.clone());
                    async move { Ok::<_, Infallible>(route(req, log, state, opts, addr).await) }
                });
                let conn = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(stream), svc);
                tokio::select! {
                    _ = conn => {}
                    _ = cancel.cancelled() => {}
                }
            });
        }
    });
    Ok(McpFixture { addr, log, state, cancel })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tools_answer_as_documented() {
        let echo = call_tool(&json!({"name": "echo", "arguments": {"text": "hi"}}), "s").unwrap();
        assert_eq!(echo["structuredContent"]["text"], "hi");
        assert_eq!(call_tool(&json!({"name": "echo", "arguments": {}}), "s").unwrap_err().0, -32602);
        assert_eq!(call_tool(&json!({"name": "add", "arguments": {"a": 2, "b": 3}}), "s").unwrap()["structuredContent"]["sum"], 5.0);
        assert_eq!(call_tool(&json!({"name": "fail"}), "s").unwrap()["isError"], true);
        assert_eq!(call_tool(&json!({"name": "session"}), "sid-1").unwrap()["content"][0]["text"], "session sid-1");
        assert_eq!(call_tool(&json!({"name": "nope"}), "s").unwrap_err().0, -32602);
        assert_eq!(dispatch("nope/nope", &Value::Null, "s").unwrap_err().0, -32601);
        let tools = tools();
        let names: Vec<&str> = tools.as_array().unwrap().iter().filter_map(|t| t["name"].as_str()).collect();
        assert_eq!(names, ["echo", "add", "fail", "session", "delete_all", "internal_audit", "new_tool"]);
    }

    #[test]
    fn accept_needs_both_media_types() {
        assert!(accepts(Some("application/json, text/event-stream"), "application/json"));
        assert!(accepts(Some("application/json;q=1, text/*"), "text/event-stream"));
        assert!(accepts(Some("*/*"), "text/event-stream"));
        assert!(!accepts(Some("application/json"), "text/event-stream"));
        assert!(!accepts(None, "application/json"));
    }
}
