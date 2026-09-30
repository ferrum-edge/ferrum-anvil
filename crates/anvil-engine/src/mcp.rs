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
use anvil_domain::settings::{SettingsOverrides, TimeoutOverrides};
use anvil_transport::recorder::EventCtx;
use anvil_transport::session::{REDACT_LOOKAHEAD_BYTES, redact_then_cut};
use anvil_transport::sse::SseParser;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use serde_json::Value;
use std::time::Duration;
use tokio::time::Instant;
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

/// A server-chosen text as a note quotes it: no control characters, and at
/// most [`MAX_NOTE_TEXT`] characters, redacted before it is cut (a secret
/// the server echoes across the cut is replaced whole).
fn quoted(v: Option<&Value>, r: &Redactor) -> String {
    let text = v.and_then(Value::as_str).unwrap_or("?");
    let window: String = text.chars().filter(|c| !c.is_control()).take(MAX_NOTE_TEXT + REDACT_LOOKAHEAD_BYTES).collect();
    let cut = window.char_indices().nth(MAX_NOTE_TEXT).map_or(window.len(), |(i, _)| i);
    redact_then_cut(&|x: &str| r.text(x), &window, cut)
}

/// A JSON-RPC error code as a note shows it: the integer, never the
/// server's raw JSON.
fn code_label(e: &Value) -> String {
    e.get("code").and_then(Value::as_i64).map_or_else(|| "(not an integer)".to_string(), |c| c.to_string())
}

/// `code (message)` of a JSON-RPC error object.
fn error_label(e: &Value, r: &Redactor) -> String {
    format!("{} ({})", code_label(e), quoted(e.get("message"), r))
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

/// Why the handshake failed, and the session id it issued nonetheless (a
/// valid one, which the session's close ends).
struct Refused {
    why: String,
    issued: Option<String>,
}

/// The session `initialize` opened, or why there is none. Server texts are
/// quoted redacted with `r`.
fn handshake(seen: &Seen, out: &ExecutionOutput, spec: &McpSpec, r: &Redactor) -> Result<Session, Refused> {
    let refused = |why: String, issued: Option<String>| Refused { why, issued };
    let Some(status) = seen.status else { return Err(refused(exchange_note("initialize", out), None)) };
    if !(200..300).contains(&status) {
        return Err(refused(format!("MCP initialize was answered with HTTP {status}, not a session"), None));
    }
    // A session id the server issued, if Anvil can send it back.
    let issued = seen.session_id.as_deref().filter(|id| is_session_id(id)).map(str::to_string);
    // Quoted server text must not reveal the session id this same response issued.
    let mut known = r.clone();
    if let Some(id) = seen.session_id.as_deref() {
        known.add_secret(id);
    }
    let r = &known;
    let Some(message) = &seen.message else {
        let stream = seen.events.map(|n| format!(" in its event stream of {n} event(s)")).unwrap_or_default();
        return Err(refused(format!("MCP initialize (HTTP {status}) got no JSON-RPC response{stream}"), issued));
    };
    if let Some(e) = message.get("error") {
        return Err(refused(format!("MCP initialize was refused with JSON-RPC error {}", error_label(e, r)), issued));
    }
    let result = message.get("result");
    let version = match result.and_then(|x| x.get("protocolVersion")) {
        None => None,
        Some(Value::String(v)) if is_token(v) => Some(v.clone()),
        Some(_) => return Err(refused(BAD_VERSION.into(), issued)),
    };
    if seen.session_id.is_some() && issued.is_none() {
        return Err(refused(BAD_SESSION_ID.into(), None));
    }
    let server = result
        .and_then(|x| x.get("serverInfo"))
        .map(|s| format!(", server {} {}", quoted(s.get("name"), r), quoted(s.get("version"), r)))
        .unwrap_or_default();
    let offered = spec.protocol_version.trim();
    let mut note = format!(
        "MCP initialize: HTTP {status}, protocol version {}{server}; {}",
        version.as_deref().unwrap_or("(not given)"),
        if issued.is_some() { "a session id was issued (sent redacted)" } else { "no session id (the server keeps no session)" }
    );
    if let Some(v) = version.as_deref().filter(|v| *v != offered) {
        note.push_str(&format!("; the server chose {v} over the offered {offered}, and the session continued on it"));
    }
    Ok(Session { id: issued, version, note })
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

/// A session's exchanges run one after the other within one deadline: the
/// request's effective total timeout, counted from the session's start.
/// Each exchange gets only what is left of it (as its total timeout, and
/// canceled when it is over), and what each exchange's redactor knows is
/// kept to redact the session's notes.
struct Run<'a> {
    engine: &'a Engine,
    cancel: &'a CancellationToken,
    deadline: Option<Instant>,
    total_ms: Option<u64>,
    redactor: Redactor,
    /// The deadline was reached during an exchange.
    timed_out: bool,
}

impl Run<'_> {
    fn expired(&self) -> bool {
        self.deadline.is_some_and(|d| Instant::now() >= d)
    }

    async fn exchange(&mut self, mut c: ExecutionContext, events: EventCtx, view: Option<BodyView<'_>>) -> ExecutionOutput {
        if let Some(d) = self.deadline {
            // Rounded up: the exchange's own deadline is never before the session's.
            let left = d.saturating_duration_since(Instant::now()).as_millis() + 1;
            let timeouts = TimeoutOverrides { total_ms: Some(Some(u64::try_from(left).unwrap_or(u64::MAX))), ..Default::default() };
            c.settings_layers.push(("mcp session".into(), SettingsOverrides { timeouts: Some(timeouts), ..Default::default() }));
        }
        let child = self.cancel.child_token();
        let keep = Mutex::new(None);
        let exec = http_exec::execute_viewing(self.engine, &c, events, child.clone(), view, Some(&keep));
        let out = match self.deadline {
            None => exec.await,
            Some(d) => {
                tokio::pin!(exec);
                let first = tokio::select! {
                    out = &mut exec => Some(out),
                    () = tokio::time::sleep_until(d + DEADLINE_GRACE) => None,
                };
                match first {
                    Some(out) => out,
                    None => {
                        // Attempts after a redirect or a retry each got the
                        // whole remainder: end the exchange now.
                        child.cancel();
                        exec.await
                    }
                }
            }
        };
        if let Some(r) = keep.into_inner() {
            self.redactor.absorb(&r);
        }
        if self.expired() {
            self.timed_out = true;
        }
        out
    }

    fn deadline_note(&self, during: &str) -> String {
        let total = self.total_ms.map(|ms| format!("{ms} ms, ")).unwrap_or_default();
        format!("MCP session deadline ({total}the request's total timeout, over the whole session) reached during {during}")
    }

    /// End the session with `DELETE`, unless closing is off, the execution
    /// was canceled or its time is up.
    async fn close(
        &mut self,
        ctx: &ExecutionContext,
        spec: &McpSpec,
        sid: &str,
        version: &str,
        events: &EventCtx,
        after: &mut Vec<String>,
    ) {
        if !spec.close_session {
            after.push("MCP session left open (closing is off for this request)".into());
        } else if self.cancel.is_cancelled() {
            after.push("MCP session not closed: the execution was canceled".into());
        } else if self.expired() {
            after.push("MCP session not closed: the session deadline was reached".into());
        } else {
            let close = exchange(ctx, "DELETE", None, Some(sid), Some(version), Checks::None);
            let closed = self.exchange(close, events.clone(), None).await;
            after.push(close_note(&closed));
        }
    }
}

/// Grace after the session deadline before an exchange still running is
/// canceled (its own total timeout, set to the remainder, normally ends it).
const DEADLINE_GRACE: Duration = Duration::from_millis(500);

/// What the session adds to its result's record.
#[derive(Default)]
struct Notes {
    before: Vec<String>,
    after: Vec<String>,
    warnings: Vec<String>,
    /// Why the operation was not sent, when it was not.
    not_sent: Option<String>,
}

/// The session's result: `out` (the operation's exchange, or the one before
/// it when the operation was not sent) as an MCP record, with the session's
/// notes around its own, redacted with every exchange's redactor.
/// `expects_response`: the exchange's request is not a notification.
fn finish(
    mut out: ExecutionOutput,
    notes: Notes,
    run: &Run<'_>,
    session: Option<&str>,
    seen: &Seen,
    expects_response: bool,
) -> ExecutionOutput {
    let mut redactor = run.redactor.clone();
    // No note quotes the session id; this is a backstop.
    if let Some(s) = session {
        redactor.add_secret(s);
    }
    let r = &mut out.record;
    r.prepared.protocol = Protocol::Mcp;
    let mut inferred: Vec<String> = notes.before.iter().map(|n| redactor.inferred(n)).collect();
    inferred.append(&mut r.prepared.inferred);
    inferred.extend(notes.after.iter().map(|n| redactor.inferred(n)));
    r.prepared.inferred = inferred;
    for w in &notes.warnings {
        r.outcome.warnings.push(OutcomeWarning { code: WarningCode::PartialVisibility, message: redactor.text(w) });
    }
    let answered = r.response.as_ref().is_some_and(|x| (200..300).contains(&x.status));
    let mut changed = !notes.warnings.is_empty();
    if let Some(why) = &notes.not_sent {
        // The exchange shown is not the operation: its outcome is not the call's.
        if r.outcome.application == ApplicationState::Success {
            r.outcome.application = ApplicationState::NotEvaluated;
        }
        let message = format!("The MCP operation was not sent ({why}), so its outcome was not evaluated");
        r.outcome.warnings.push(OutcomeWarning { code: WarningCode::PartialVisibility, message: redactor.text(&message) });
        changed = true;
    } else if expects_response && answered && seen.message.is_none() && r.outcome.application == ApplicationState::Success {
        // A 2xx without the JSON-RPC response says nothing about the call.
        r.outcome.application = ApplicationState::NotEvaluated;
        r.outcome.warnings.push(OutcomeWarning {
            code: WarningCode::PartialVisibility,
            message: "The response holds no JSON-RPC response to the MCP request, so the MCP outcome was not evaluated".into(),
        });
        changed = true;
    }
    if changed {
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
    let total_ms = crate::settings::resolve(&ctx.settings_layers).timeouts.total_ms;
    let mut run = Run {
        engine,
        cancel: &cancel,
        deadline: total_ms.map(|ms| Instant::now() + Duration::from_millis(ms)),
        total_ms,
        redactor: Redactor::new(vec![], ctx.redaction_names.clone()),
        timed_out: false,
    };
    // The handshake and the close are not the execution the caller follows:
    // their progress events are not forwarded.
    let quiet = EventCtx { execution_id: events.execution_id, sink: None };
    let mut notes = Notes::default();
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
            run.exchange(init, quiet.clone(), Some(view)).await
        };
        let seen = seen.into_inner();
        match handshake(&seen, &out, spec, &run.redactor) {
            Ok(s) => {
                notes.before.push(s.note);
                session = s.id;
                if let Some(v) = s.version {
                    version = v;
                }
            }
            Err(refused) => {
                notes.not_sent = Some(refused.why.clone());
                notes.before.push(refused.why);
                notes.before.push(format!("the {method} request was not sent"));
                if run.timed_out {
                    notes.before.push(run.deadline_note("initialize"));
                }
                // A session the server opened is ended even so.
                if let Some(sid) = refused.issued.as_deref() {
                    run.close(ctx, spec, sid, &version, &quiet, &mut notes.after).await;
                }
                return finish(out, notes, &run, refused.issued.as_deref(), &seen, true);
            }
        }
        let notify = exchange(ctx, "POST", Some(INITIALIZED.into()), session.as_deref(), Some(&version), Checks::None);
        let out = run.exchange(notify, quiet.clone(), None).await;
        notes.before.push(exchange_note("notifications/initialized", &out));
        let stop = if cancel.is_cancelled() {
            Some("the execution was canceled".to_string())
        } else if run.expired() {
            Some(run.deadline_note("initialize and notifications/initialized"))
        } else {
            None
        };
        if let Some(why) = stop {
            notes.before.push(format!("the {method} request was not sent: {why}"));
            notes.not_sent = Some(why);
            if let Some(sid) = session.as_deref() {
                run.close(ctx, spec, sid, &version, &quiet, &mut notes.after).await;
            }
            return finish(out, notes, &run, session.as_deref(), &Seen::default(), false);
        }
        // A server that does not accept the notification may still answer
        // the operation: it is sent, and the refusal is reported.
        let answered = out.record.response.as_ref().map(|r| r.status);
        if !answered.is_some_and(|s| (200..300).contains(&s)) {
            let got = answered.map_or_else(|| "no response".to_string(), |s| format!("HTTP {s}"));
            notes.warnings.push(format!("notifications/initialized was not accepted ({got}); the {method} request was still sent"));
        }
    }
    let id = (!spec.operation.is_notification()).then_some(OPERATION_ID);
    let seen = Mutex::new(Seen::default());
    let op = exchange(ctx, "POST", Some(operation_body(&spec.operation)), session.as_deref(), Some(&version), Checks::All);
    let out = {
        let view = viewer(&seen, id);
        let view: BodyView<'_> = &view;
        run.exchange(op, events, Some(view)).await
    };
    let seen = seen.into_inner();
    stream_notes(&seen, &method, &mut notes.after);
    if session.is_some() && out.record.response.as_ref().is_some_and(|r| r.status == 404) {
        let why = "the server no longer knows the session (it expired or was ended); a new initialize opens another";
        notes.after.push(format!("MCP {method}: HTTP 404 in the session: {why}"));
    }
    if run.timed_out {
        notes.after.push(run.deadline_note(&method));
    }
    if let Some(sid) = session.as_deref() {
        run.close(ctx, spec, sid, &version, &quiet, &mut notes.after).await;
    }
    finish(out, notes, &run, session.as_deref(), &seen, id.is_some())
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
    fn server_text_in_notes_is_redacted_before_it_is_cut() {
        let secret = "tok-SENSITIVE-note-cut";
        let r = Redactor::new(vec![secret.into()], vec![]);
        let text = Value::String(format!("{}{secret}", "n".repeat(MAX_NOTE_TEXT - 3)));
        let q = quoted(Some(&text), &r);
        assert!(!q.contains("tok") && q.ends_with(anvil_domain::secret::REDACTED), "{q}");
        assert_eq!(code_label(&serde_json::json!({"code": "-32001 injected"})), "(not an integer)");
        assert_eq!(code_label(&serde_json::json!({"code": -32001})), "-32001");
    }

    #[test]
    fn a_line_over_the_bound_stops_the_stream_read() {
        let long = format!("data: {}\n\n", "x".repeat(MAX_SSE_LINE_BYTES + 1));
        let (message, events, error) = read_event_stream(long.as_bytes(), Some(OPERATION_ID));
        assert!(message.is_none() && events == 0 && error.is_some(), "{error:?}");
    }
}
