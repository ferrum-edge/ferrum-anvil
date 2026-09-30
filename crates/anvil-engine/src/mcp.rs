//! MCP (Model Context Protocol) over Streamable HTTP: one operation, sent in
//! a session of its own (docs/protocols.md §3.14).
//!
//! An execution is a short series of HTTP exchanges, each one a complete HTTP
//! execution of the shared engine (auth applied per send, TLS and proxy
//! profiles, redirects, limits, deadlines, cancellation, redaction and
//! diagnosis):
//!
//! 1. `POST initialize`; the answer may carry an `Mcp-Session-Id`;
//! 2. `POST notifications/initialized` (answered `202 Accepted`);
//! 3. `POST` the operation, with the session id and the negotiated
//!    `MCP-Protocol-Version`. The request's assertions and extractions run on
//!    this exchange;
//! 4. `DELETE` the session.
//!
//! A POST may be answered with JSON or with an event stream. From a stream,
//! the checks and the diagnosis read the JSON-RPC response to the request
//! (the event whose `id` is the request's); the stream's other messages are
//! counted. The stream is read under the response limits of any HTTP
//! request, and a stream the server leaves open ends at the body idle or
//! total deadline.
//!
//! The record is the operation's (or, when the handshake fails, the
//! handshake's). Its `prepared.inferred` notes say how the session went. The
//! session id is a credential: it is sent as a sensitive header, so records,
//! previews and exports show it redacted, and no note quotes it. A session id
//! or protocol version the server chose is used only when it is a plain token
//! (visible ASCII, no `{{`), so it can never be read as a variable reference.

use crate::context::ExecutionContext;
use crate::preview::EffectiveRequest;
use crate::record::{self, BodyView};
use crate::redact::Redactor;
use crate::vars::Resolver;
use crate::{Engine, ExecutionOutput, http_exec};
use anvil_domain::execution::{FailureKind, Phase, ResponseRecord, TransportFailure};
use anvil_domain::outcome::{ApplicationState, OutcomeWarning, WarningCode};
use anvil_domain::request::{Body, KeyValue, McpOperation, McpSpec, Protocol};
use anvil_transport::recorder::EventCtx;
use anvil_transport::sse::SseParser;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use serde_json::Value;
use tokio_util::sync::CancellationToken;

/// JSON-RPC id of the `initialize` request.
pub const INITIALIZE_ID: i64 = 1;
/// JSON-RPC id of the operation (a notification has none).
pub const OPERATION_ID: i64 = 2;
/// The `Accept` header Streamable HTTP requires on a POST.
pub const STREAMABLE_HTTP_ACCEPT: &str = "application/json, text/event-stream";
/// The session id header (MCP Streamable HTTP §Session Management).
pub const SESSION_HEADER: &str = "Mcp-Session-Id";
/// The protocol version header sent after `initialize`.
pub const VERSION_HEADER: &str = "MCP-Protocol-Version";
/// The `notifications/initialized` message.
const INITIALIZED: &str = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
/// Longest session id Anvil sends back.
const MAX_SESSION_ID_BYTES: usize = 1024;
/// Longest protocol version token Anvil sends back.
const MAX_VERSION_BYTES: usize = 64;
/// Longest line of a POST's event stream read (one event's data may be four
/// times this, see [`SseParser::max_event_data`]).
const MAX_SSE_LINE_BYTES: usize = 1024 * 1024;
/// Most events read from one POST's event stream.
const MAX_SSE_EVENTS: usize = 10_000;
/// Longest server-chosen text (name, version, error message) a note quotes.
const MAX_NOTE_TEXT: usize = 80;
/// What the effective-request preview shows as the session id.
const SESSION_PLACEHOLDER: &str = "<issued-by-initialize>";
const NO_MCP_SETTINGS: &str = "an MCP request needs its MCP settings (the operation to send)";
const BAD_VERSION: &str = "MCP initialize answered a protocolVersion that is not a version token; the session was not used";
const BAD_SESSION_ID: &str = "the server's Mcp-Session-Id is not a session id Anvil sends back (1 to 1024 visible ASCII characters, without '{{' or '}}'); the session was not used";
const PREVIEW_NOTE: &str = "MCP: sent after initialize and notifications/initialized, with the Mcp-Session-Id that initialize issues and the protocol version the server chose (until then the offered one)";

/// Which of the request's checks an exchange runs.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Checks {
    None,
    /// Assertions only: the handshake's exchange is the result when it fails.
    Assertions,
    All,
}

/// What an exchange's response showed, read before its headers are redacted.
#[derive(Default)]
struct Seen {
    status: Option<u16>,
    /// The `Mcp-Session-Id` the response carried, as received.
    session_id: Option<String>,
    /// The JSON-RPC response to the exchange's request.
    message: Option<Value>,
    /// Events in the response's event stream (`None`: not a stream).
    events: Option<usize>,
    /// Why the event stream was not read to its end.
    stream_error: Option<String>,
}

/// Why the request cannot be built, and the field to fix.
fn invalid(spec: &McpSpec) -> Option<(&'static str, &'static str)> {
    let blank = |s: &str| s.trim().is_empty();
    match &spec.operation {
        McpOperation::ToolsCall { name, .. } if blank(name) => Some(("an MCP tools/call needs the tool's name", "mcp.operation.name")),
        McpOperation::PromptsGet { name, .. } if blank(name) => Some(("an MCP prompts/get needs the prompt's name", "mcp.operation.name")),
        McpOperation::ResourcesRead { uri } if blank(uri) => Some(("an MCP resources/read needs the resource's URI", "mcp.operation.uri")),
        McpOperation::Raw { method, .. } if blank(method) => Some(("a raw MCP message needs its JSON-RPC method", "mcp.operation.method")),
        _ if blank(&spec.protocol_version) => Some(("an MCP request needs the protocol version to offer", "mcp.protocol_version")),
        _ => None,
    }
}

fn json_string(s: &str) -> String {
    Value::String(s.to_string()).to_string()
}

/// A JSON object template (variables allowed), `{}` when blank.
fn object_text(t: &str) -> &str {
    if t.trim().is_empty() { "{}" } else { t }
}

/// The `initialize` request. Its texts are templates: `{{variables}}` in
/// them resolve when the body is prepared, as in any JSON body.
pub fn initialize_body(spec: &McpSpec) -> String {
    let version = if spec.client_version.trim().is_empty() { env!("CARGO_PKG_VERSION") } else { spec.client_version.as_str() };
    let client = format!(r#"{{"name":{},"version":{}}}"#, json_string(&spec.client_name), json_string(version));
    let params = format!(
        r#"{{"protocolVersion":{},"capabilities":{},"clientInfo":{client}}}"#,
        json_string(spec.protocol_version.trim()),
        object_text(&spec.capabilities)
    );
    format!(r#"{{"jsonrpc":"2.0","id":{INITIALIZE_ID},"method":"initialize","params":{params}}}"#)
}

/// The operation's JSON-RPC request (or notification).
pub fn operation_body(op: &McpOperation) -> String {
    let cursor = |c: &Option<String>| c.as_ref().map(|c| format!(r#"{{"cursor":{}}}"#, json_string(c)));
    let params = match op {
        McpOperation::ToolsList { cursor: c }
        | McpOperation::ResourcesList { cursor: c }
        | McpOperation::ResourceTemplatesList { cursor: c }
        | McpOperation::PromptsList { cursor: c } => cursor(c),
        McpOperation::ToolsCall { name, arguments } | McpOperation::PromptsGet { name, arguments } => {
            Some(format!(r#"{{"name":{},"arguments":{}}}"#, json_string(name.trim()), object_text(arguments)))
        }
        McpOperation::ResourcesRead { uri } => Some(format!(r#"{{"uri":{}}}"#, json_string(uri.trim()))),
        McpOperation::Raw { params, .. } => (!params.trim().is_empty()).then(|| params.clone()),
    };
    let id = if op.is_notification() { String::new() } else { format!(r#","id":{OPERATION_ID}"#) };
    let method = json_string(op.method().trim());
    match params {
        Some(p) => format!(r#"{{"jsonrpc":"2.0"{id},"method":{method},"params":{p}}}"#),
        None => format!(r#"{{"jsonrpc":"2.0"{id},"method":{method}}}"#),
    }
}

/// The HTTP request one exchange of the session sends: the request's URL,
/// query parameters, headers, auth and settings, with the MCP headers added.
/// A configured `Content-Type`, `Accept` or `MCP-Protocol-Version` is kept
/// (to test how a server treats it); the session id the handshake issued
/// replaces a configured one.
fn exchange(
    ctx: &ExecutionContext,
    method: &str,
    body: Option<String>,
    session: Option<&str>,
    version: Option<&str>,
    checks: Checks,
) -> ExecutionContext {
    let mut spec = ctx.spec.clone();
    spec.protocol = Protocol::Http;
    spec.method = method.to_string();
    spec.mcp = None;
    spec.grpc = None;
    spec.websocket = None;
    spec.sse = None;
    spec.tcp = None;
    spec.udp = None;
    let has_body = body.is_some();
    spec.body = body.map_or(Body::None, |text| Body::Json { text });
    if checks != Checks::All {
        spec.extractions.clear();
    }
    if checks == Checks::None {
        spec.assertions.clear();
    }
    let configured = |headers: &[KeyValue], name: &str| headers.iter().any(|h| h.enabled && h.name.trim().eq_ignore_ascii_case(name));
    if has_body && !configured(&spec.headers, "content-type") {
        spec.headers.push(KeyValue::new("Content-Type", "application/json"));
    }
    if !configured(&spec.headers, "accept") {
        spec.headers.push(KeyValue::new("Accept", STREAMABLE_HTTP_ACCEPT));
    }
    if let Some(v) = version
        && !configured(&spec.headers, VERSION_HEADER)
    {
        spec.headers.push(KeyValue::new(VERSION_HEADER, v));
    }
    if let Some(id) = session {
        spec.headers.retain(|h| !h.name.trim().eq_ignore_ascii_case(SESSION_HEADER));
        spec.headers.push(KeyValue { sensitive: true, ..KeyValue::new(SESSION_HEADER, id) });
    }
    let mut c = ctx.clone();
    c.spec = spec;
    c
}

fn is_event_stream(content_type: Option<&str>) -> bool {
    content_type.and_then(|ct| ct.split(';').next()).is_some_and(|m| m.trim().eq_ignore_ascii_case("text/event-stream"))
}

/// Whether `v` is the JSON-RPC response to request `id`: a result or an
/// error with that id, or an error with a null id (a server that could not
/// read the request's id).
pub fn is_response_to(v: &Value, id: i64) -> bool {
    let Some(o) = v.as_object() else { return false };
    let (result, error) = (o.contains_key("result"), o.contains_key("error"));
    match o.get("id") {
        Some(Value::Number(n)) => n.as_i64() == Some(id) && (result || error),
        Some(Value::Null) | None => error && !result,
        _ => false,
    }
}

/// The JSON-RPC response to `id` in an event stream, the events read, and
/// why the stream was not read to its end. Bounded: at most
/// [`MAX_SSE_EVENTS`] events of lines up to [`MAX_SSE_LINE_BYTES`].
fn read_event_stream(body: &[u8], id: Option<i64>) -> (Option<Value>, usize, Option<String>) {
    let mut parser = SseParser::new(MAX_SSE_LINE_BYTES);
    let mut events = Vec::new();
    let error = parser.feed_limited(body, &mut events, MAX_SSE_EVENTS).err();
    let mut parsed = events.iter().filter_map(|e| serde_json::from_str::<Value>(&e.data).ok());
    let message = id.and_then(|id| parsed.find(|v| is_response_to(v, id)));
    (message, events.len(), error)
}

/// The JSON-RPC response to `id` in a response body (JSON, or an event
/// stream when `content_type` says so).
pub fn response_in(content_type: Option<&str>, body: &[u8], id: i64) -> Option<Value> {
    if is_event_stream(content_type) {
        return read_event_stream(body, Some(id)).0;
    }
    serde_json::from_slice::<Value>(body).ok().filter(|v| is_response_to(v, id))
}

/// The JSON-RPC response of an MCP execution's operation, if its response
/// held one (the output's decoded body, or its body).
pub fn operation_response(out: &ExecutionOutput) -> Option<Value> {
    let ct = out.record.response.as_ref().and_then(|r| r.body.content_type.as_deref());
    response_in(ct, out.decoded_body.as_ref().unwrap_or(&out.body), OPERATION_ID)
}

/// The view an exchange's checks read: the JSON-RPC response out of an event
/// stream (a JSON body is read as it is). Records what the response showed.
fn viewer(seen: &Mutex<Seen>, id: Option<i64>) -> impl Fn(Option<&ResponseRecord>, &[u8]) -> Option<Bytes> + Sync + '_ {
    move |response: Option<&ResponseRecord>, body: &[u8]| {
        let r = response?;
        let mut s = seen.lock();
        s.status = Some(r.status);
        s.session_id = r.header_values(SESSION_HEADER).first().map(|v| v.to_string());
        if !is_event_stream(r.body.content_type.as_deref()) {
            s.message = id.and_then(|id| serde_json::from_slice::<Value>(body).ok().filter(|v| is_response_to(v, id)));
            return None;
        }
        let (message, events, error) = read_event_stream(body, id);
        s.events = Some(events);
        s.stream_error = error;
        let view = message.as_ref().and_then(|m| serde_json::to_vec(m).ok()).map(Bytes::from);
        s.message = message;
        view
    }
}

/// A plain token a server chose (a protocol version).
fn is_token(v: &str) -> bool {
    !v.is_empty() && v.len() <= MAX_VERSION_BYTES && v.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
}

/// A session id Anvil sends back: 1 to 1024 visible ASCII characters (MCP
/// Streamable HTTP), and no `{{` or `}}`, which the variable resolver would
/// read as a reference.
fn is_session_id(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= MAX_SESSION_ID_BYTES
        && v.bytes().all(|b| (0x21..=0x7e).contains(&b))
        && !v.contains("{{")
        && !v.contains("}}")
}

/// A server-chosen text as a note quotes it: no control characters, cut.
fn quoted(v: Option<&Value>) -> String {
    let s = v.and_then(Value::as_str).unwrap_or("?");
    s.chars().filter(|c| !c.is_control()).take(MAX_NOTE_TEXT).collect()
}

/// `code: message` of a JSON-RPC error object.
fn error_label(e: &Value) -> String {
    let code = e.get("code").map(|c| c.to_string()).unwrap_or_else(|| "?".into());
    format!("{code} ({})", quoted(e.get("message")))
}

/// Why an exchange has no response, or its status.
fn exchange_note(what: &str, out: &ExecutionOutput) -> String {
    match out.record.response.as_ref() {
        Some(r) => format!("MCP {what}: HTTP {}", r.status),
        None => {
            let why = out.record.attempts.last().and_then(|a| a.failure.as_ref()).map(|f| f.message.clone());
            format!("MCP {what}: no response ({})", why.unwrap_or_else(|| out.record.outcome.summary.clone()))
        }
    }
}

/// The session the handshake opened.
struct Session {
    id: Option<String>,
    version: Option<String>,
    note: String,
}

/// The session `initialize` opened, or why there is none.
fn handshake(seen: &Seen, out: &ExecutionOutput, spec: &McpSpec) -> Result<Session, String> {
    let Some(status) = seen.status else { return Err(exchange_note("initialize", out)) };
    if !(200..300).contains(&status) {
        return Err(format!("MCP initialize was answered with HTTP {status}, not a session"));
    }
    let Some(message) = &seen.message else {
        let stream = seen.events.map(|n| format!(" in its event stream of {n} event(s)")).unwrap_or_default();
        return Err(format!("MCP initialize (HTTP {status}) got no JSON-RPC response{stream}"));
    };
    if let Some(e) = message.get("error") {
        return Err(format!("MCP initialize was refused with JSON-RPC error {}", error_label(e)));
    }
    let result = message.get("result");
    let version = match result.and_then(|r| r.get("protocolVersion")) {
        None => None,
        Some(Value::String(v)) if is_token(v) => Some(v.clone()),
        Some(_) => return Err(BAD_VERSION.into()),
    };
    let id = match &seen.session_id {
        None => None,
        Some(id) if is_session_id(id) => Some(id.clone()),
        Some(_) => return Err(BAD_SESSION_ID.into()),
    };
    let server = result
        .and_then(|r| r.get("serverInfo"))
        .map(|s| format!(", server {} {}", quoted(s.get("name")), quoted(s.get("version"))))
        .unwrap_or_default();
    let offered = spec.protocol_version.trim();
    let mut note = format!(
        "MCP initialize: HTTP {status}, protocol version {}{server}; {}",
        version.as_deref().unwrap_or("(not given)"),
        if id.is_some() { "a session id was issued (sent redacted)" } else { "no session id (the server keeps no session)" }
    );
    if let Some(v) = version.as_deref().filter(|v| *v != offered) {
        note.push_str(&format!("; the server chose {v} over the offered {offered}, and the session continued on it"));
    }
    Ok(Session { id, version, note })
}

/// How the operation's response arrived, when it was an event stream.
fn stream_notes(seen: &Seen, method: &str, notes: &mut Vec<String>) {
    let Some(n) = seen.events else { return };
    let read = if seen.message.is_some() {
        "the JSON-RPC response was read from it".to_string()
    } else {
        format!("none of them was the JSON-RPC response to request {OPERATION_ID}")
    };
    notes.push(format!("MCP {method}: the response arrived as an event stream of {n} event(s); {read}"));
    if let Some(e) = &seen.stream_error {
        notes.push(format!("MCP {method}: the event stream was not read to its end: {e}"));
    }
}

fn close_note(out: &ExecutionOutput) -> String {
    match out.record.response.as_ref().map(|r| r.status) {
        Some(s) if (200..300).contains(&s) => format!("MCP session closed: DELETE answered HTTP {s}"),
        Some(405) => "MCP session not closed: DELETE answered HTTP 405 (the server does not let clients end sessions)".into(),
        Some(404) => "MCP session close: DELETE answered HTTP 404 (the server no longer knew the session)".into(),
        Some(s) => format!("MCP session close: DELETE answered HTTP {s}"),
        None => exchange_note("session close (DELETE)", out),
    }
}

fn not_sent(ctx: &ExecutionContext, started_at: DateTime<Utc>, why: &str, field: &str, kind: FailureKind) -> ExecutionOutput {
    let resolver = Resolver::new(ctx.var_layers.clone(), ctx.seed);
    record::local_failure(ctx, &resolver, started_at, TransportFailure::new(Phase::Prepare, kind, why).with_field(field))
}

/// The session's result: `out` (the operation's exchange, or the handshake's
/// when it failed) as an MCP record, with the session's notes around its
/// own. `expects_response`: the exchange's request is not a notification.
fn finish(
    ctx: &ExecutionContext,
    mut out: ExecutionOutput,
    before: Vec<String>,
    after: Vec<String>,
    session: Option<&str>,
    seen: &Seen,
    expects_response: bool,
) -> ExecutionOutput {
    // No note quotes the session id; this is a backstop.
    let redactor = Redactor::new(session.map(|s| vec![s.to_string()]).unwrap_or_default(), ctx.redaction_names.clone());
    let r = &mut out.record;
    r.prepared.protocol = Protocol::Mcp;
    let mut inferred: Vec<String> = before.iter().map(|n| redactor.text(n)).collect();
    inferred.append(&mut r.prepared.inferred);
    inferred.extend(after.iter().map(|n| redactor.text(n)));
    r.prepared.inferred = inferred;
    let answered = r.response.as_ref().is_some_and(|x| (200..300).contains(&x.status));
    if expects_response && answered && seen.message.is_none() && r.outcome.application == ApplicationState::Success {
        // A 2xx without the JSON-RPC response says nothing about the call.
        r.outcome.application = ApplicationState::NotEvaluated;
        r.outcome.warnings.push(OutcomeWarning {
            code: WarningCode::PartialVisibility,
            message: "The response holds no JSON-RPC response to the MCP request, so the MCP outcome was not evaluated".into(),
        });
        r.outcome.summary = record::summary_line(r.outcome.transport, r.outcome.application, &r.outcome.protocol_status, &r.findings);
    }
    out
}

/// Run one MCP request (see the module documentation).
pub(crate) async fn execute(engine: &Engine, ctx: &ExecutionContext, events: EventCtx, cancel: CancellationToken) -> ExecutionOutput {
    let started_at = Utc::now();
    let Some(spec) = ctx.spec.mcp.as_ref() else {
        let why = format!("{NO_MCP_SETTINGS}; nothing was sent");
        return not_sent(ctx, started_at, &why, "mcp", FailureKind::UnsupportedCombination);
    };
    if let Some((why, field)) = invalid(spec) {
        return not_sent(ctx, started_at, &format!("{why}; nothing was sent"), field, FailureKind::BodySerialization);
    }
    let method = spec.operation.method().trim().to_string();
    // The handshake and the close are not the execution the caller follows:
    // their progress events are not forwarded.
    let quiet = EventCtx { execution_id: events.execution_id, sink: None };
    let mut before = Vec::new();
    let mut session: Option<String> = None;
    let mut version = spec.protocol_version.trim().to_string();
    if spec.initialize {
        let seen = Mutex::new(Seen::default());
        // The request's assertions also run on `initialize`: when the
        // handshake fails, its exchange is the result.
        let init = exchange(ctx, "POST", Some(initialize_body(spec)), None, None, Checks::Assertions);
        let out = {
            let view = viewer(&seen, Some(INITIALIZE_ID));
            let view: BodyView<'_> = &view;
            http_exec::execute_viewing(engine, &init, quiet.clone(), cancel.clone(), Some(view)).await
        };
        let seen = seen.into_inner();
        match handshake(&seen, &out, spec) {
            Ok(s) => {
                before.push(s.note);
                session = s.id;
                if let Some(v) = s.version {
                    version = v;
                }
            }
            Err(why) => {
                before.push(why);
                before.push(format!("the {method} request was not sent"));
                return finish(ctx, out, before, vec![], None, &seen, true);
            }
        }
        let notify = exchange(ctx, "POST", Some(INITIALIZED.into()), session.as_deref(), Some(&version), Checks::None);
        let out = http_exec::execute_viewing(engine, &notify, quiet.clone(), cancel.clone(), None).await;
        before.push(exchange_note("notifications/initialized", &out));
        if cancel.is_cancelled() {
            before.push(format!("the {method} request was not sent: the execution was canceled"));
            return finish(ctx, out, before, vec![], session.as_deref(), &Seen::default(), false);
        }
    }
    let id = (!spec.operation.is_notification()).then_some(OPERATION_ID);
    let seen = Mutex::new(Seen::default());
    let op = exchange(ctx, "POST", Some(operation_body(&spec.operation)), session.as_deref(), Some(&version), Checks::All);
    let out = {
        let view = viewer(&seen, id);
        let view: BodyView<'_> = &view;
        http_exec::execute_viewing(engine, &op, events, cancel.clone(), Some(view)).await
    };
    let seen = seen.into_inner();
    let mut after = Vec::new();
    stream_notes(&seen, &method, &mut after);
    if let Some(sid) = session.as_deref() {
        if !spec.close_session {
            after.push("MCP session left open (closing is off for this request)".into());
        } else if cancel.is_cancelled() {
            after.push("MCP session not closed: the execution was canceled".into());
        } else {
            let close = exchange(ctx, "DELETE", None, Some(sid), Some(&version), Checks::None);
            let closed = http_exec::execute_viewing(engine, &close, quiet, cancel.clone(), None).await;
            after.push(close_note(&closed));
        }
    }
    finish(ctx, out, before, after, session.as_deref(), &seen, id.is_some())
}

/// The operation's POST as a send would make it once the session is open:
/// the session id is a placeholder, and the version header is the one
/// offered (the server may choose another). Nothing is sent.
pub(crate) fn preview(engine: &Engine, ctx: &ExecutionContext) -> Result<EffectiveRequest, TransportFailure> {
    let Some(spec) = ctx.spec.mcp.as_ref() else {
        let f = TransportFailure::new(Phase::Prepare, FailureKind::UnsupportedCombination, NO_MCP_SETTINGS);
        return Err(f.with_field("mcp"));
    };
    if let Some((why, field)) = invalid(spec) {
        return Err(TransportFailure::new(Phase::Prepare, FailureKind::BodySerialization, why).with_field(field));
    }
    let session = spec.initialize.then_some(SESSION_PLACEHOLDER);
    let version = spec.protocol_version.trim();
    let op = exchange(ctx, "POST", Some(operation_body(&spec.operation)), session, Some(version), Checks::None);
    let mut p = engine.preview(&op)?;
    let note = match (spec.initialize, spec.close_session) {
        (true, true) => format!("{PREVIEW_NOTE}; a DELETE then ends the session"),
        (true, false) => format!("{PREVIEW_NOTE}; the session is left open (closing is off)"),
        (false, _) => "MCP: sent on its own, without a session (initialize is off)".to_string(),
    };
    p.inferred.insert(0, note);
    Ok(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(op: McpOperation) -> McpSpec {
        serde_json::from_value(serde_json::json!({ "operation": serde_json::to_value(op).unwrap() })).unwrap()
    }

    #[test]
    fn requests_are_json_rpc_with_the_session_ids() {
        let s = spec(McpOperation::ToolsList { cursor: None });
        let init: Value = serde_json::from_str(&initialize_body(&s)).unwrap();
        assert_eq!(init["id"], INITIALIZE_ID);
        assert_eq!(init["method"], "initialize");
        assert_eq!(init["params"]["protocolVersion"], anvil_domain::request::MCP_DEFAULT_PROTOCOL_VERSION);
        assert_eq!(init["params"]["clientInfo"]["name"], "anvil");
        assert_eq!(init["params"]["clientInfo"]["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(init["params"]["capabilities"], serde_json::json!({}));

        let call = McpOperation::ToolsCall { name: "fx.echo".into(), arguments: r#"{"text":"hi \"there\""}"#.into() };
        let call: Value = serde_json::from_str(&operation_body(&call)).unwrap();
        assert_eq!((call["id"].clone(), call["method"].clone()), (Value::from(OPERATION_ID), Value::from("tools/call")));
        assert_eq!(call["params"], serde_json::json!({"name": "fx.echo", "arguments": {"text": "hi \"there\""}}));
        let list = McpOperation::ToolsList { cursor: Some("c-1".into()) };
        let list: Value = serde_json::from_str(&operation_body(&list)).unwrap();
        assert_eq!(list["params"], serde_json::json!({"cursor": "c-1"}));
        let blank = McpOperation::PromptsGet { name: "p".into(), arguments: " ".into() };
        let blank: Value = serde_json::from_str(&operation_body(&blank)).unwrap();
        assert_eq!(blank["params"]["arguments"], serde_json::json!({}));
        let note = McpOperation::Raw { method: "notifications/cancelled".into(), params: r#"{"requestId":7}"#.into(), notification: true };
        let note: Value = serde_json::from_str(&operation_body(&note)).unwrap();
        assert!(note.get("id").is_none(), "a notification has no id: {note}");
        assert_eq!(note["params"]["requestId"], 7);
    }

    #[test]
    fn only_plain_tokens_from_the_server_are_sent_back() {
        assert!(is_session_id("1868a90c-2b3e-4f5a-9d8b-0c1d2e3f4a5b"));
        let long = "a".repeat(MAX_SESSION_ID_BYTES + 1);
        for bad in ["", "has space", "tab\there", "{{api_token}}", "x}}", "é", long.as_str()] {
            assert!(!is_session_id(bad), "{bad:?}");
        }
        assert!(is_token("2025-11-25") && is_token("draft_1.2"));
        assert!(!is_token("{{v}}") && !is_token("2025 11") && !is_token(""));
    }

    #[test]
    fn the_response_is_read_out_of_an_event_stream_by_its_id() {
        let stream = concat!(
            ": keep-alive\n\n",
            "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{}}\n\n",
            "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":9,\"result\":{}}\n\n",
            "id: e-3\nevent: message\ndata: {\"jsonrpc\":\"2.0\",\n",
            "data: \"id\":2,\"result\":{\"tools\":[]}}\n\n",
        );
        let (message, events, error) = read_event_stream(stream.as_bytes(), Some(OPERATION_ID));
        assert_eq!(message, Some(serde_json::json!({"jsonrpc":"2.0","id":2,"result":{"tools":[]}})));
        assert_eq!((events, error), (3, None));
        let other = response_in(Some("text/event-stream; charset=utf-8"), stream.as_bytes(), 9).unwrap();
        assert_eq!(other["id"], 9);
        let null_id = br#"{"jsonrpc":"2.0","id":null,"error":{"code":-32600}}"#;
        assert_eq!(response_in(Some("application/json"), null_id, 2).unwrap()["id"], Value::Null);
        let third = br#"{"jsonrpc":"2.0","id":3,"result":{}}"#;
        assert!(response_in(Some("application/json"), third, 2).is_none(), "another request's response");
        // An event the stream ends inside is not dispatched.
        let cut = "data: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{}}";
        assert_eq!(read_event_stream(cut.as_bytes(), Some(OPERATION_ID)).0, None);
    }

    #[test]
    fn a_line_over_the_bound_stops_the_stream_read() {
        let long = format!("data: {}\n\n", "x".repeat(MAX_SSE_LINE_BYTES + 1));
        let (message, events, error) = read_event_stream(long.as_bytes(), Some(OPERATION_ID));
        assert!(message.is_none() && events == 0 && error.is_some(), "{error:?}");
    }
}
