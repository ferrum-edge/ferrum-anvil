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
//! counted. Reading stops once that response has arrived, and the stream is
//! read under the response limits of any HTTP request: a stream that never
//! carries the response ends when the server ends it, or at the body idle or
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
use anvil_diagnostics::facts::MAX_PARSE;
use anvil_domain::Timestamp;
use anvil_domain::execution::{BodyCompleteness, FailureKind, Phase, ResponseRecord, TransportFailure};
use anvil_domain::outcome::{ApplicationState, OutcomeWarning, WarningCode};
use anvil_domain::request::{Body, KeyValue, McpOperation, McpSpec, Protocol};
use anvil_domain::settings::{SettingsOverrides, TimeoutOverrides};
use anvil_transport::decode::IncrementalDecoder;
use anvil_transport::http::{BodyStart, BodyStop, BodyWatch};
use anvil_transport::recorder::EventCtx;
use anvil_transport::session::{REDACT_LOOKAHEAD_BYTES, redact_then_cut};
use anvil_transport::sse::SseParser;
use bytes::Bytes;
use parking_lot::Mutex;
use serde_json::Value;
use std::sync::Arc;
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
    /// Reading stopped once the JSON-RPC response had arrived, before the
    /// server ended the stream.
    stopped: bool,
    /// Bytes of what the diagnosis reads: the body, or the JSON-RPC response
    /// taken out of an event stream.
    diagnosed_bytes: usize,
}

/// Why the request cannot be built, and the field to fix.
fn invalid(spec: &McpSpec) -> Option<(&'static str, &'static str)> {
    let blank = |s: &str| s.trim().is_empty();
    match &spec.operation {
        McpOperation::ToolsCall { name, .. } if blank(name) => Some(("an MCP tools/call needs the tool's name", "mcp.operation.name")),
        McpOperation::PromptsGet { name, .. } if blank(name) => Some(("an MCP prompts/get needs the prompt's name", "mcp.operation.name")),
        McpOperation::ResourcesRead { uri } if blank(uri) => Some(("an MCP resources/read needs the resource's URI", "mcp.operation.uri")),
        McpOperation::Raw { method, .. } if blank(method) => Some(("a raw MCP message needs its JSON-RPC method", "mcp.operation.method")),
        McpOperation::Batch { messages } if blank(messages) => {
            Some(("an MCP batch needs its JSON array of messages", "mcp.operation.messages"))
        }
        // Checked when the text is literal JSON (variables may make it unreadable until it is sent).
        McpOperation::Batch { messages }
            if serde_json::from_str::<Value>(messages).is_ok_and(|v| v.as_array().is_none_or(Vec::is_empty)) =>
        {
            Some(("an MCP batch is a non-empty JSON array of JSON-RPC messages", "mcp.operation.messages"))
        }
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

/// The operation's JSON-RPC request (or notification), or a batch's text as
/// it was written.
pub fn operation_body(op: &McpOperation) -> String {
    operation_body_id(op, OPERATION_ID)
}

/// [`operation_body`] with request id `id` (a later page of a session).
fn operation_body_id(op: &McpOperation, id: i64) -> String {
    if let McpOperation::Batch { messages } = op {
        return messages.clone();
    }
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
        McpOperation::Batch { .. } => None,
    };
    let id = if op.is_notification() { String::new() } else { format!(r#","id":{id}"#) };
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

/// Whether `v` is a JSON integer representable in 64-bit signed or unsigned
/// form (rejects strings, booleans, floats, and out-of-range numbers).
fn is_json_integer(v: &Value) -> bool {
    v.as_i64().is_some() || v.as_u64().is_some()
}

/// Whether `o` has `"jsonrpc": "2.0"` and mutually exclusive `result` or
/// valid JSON-RPC 2.0 `error` object (`code` integer and `message` string,
/// JSON-RPC 2.0 §5.1).
fn has_valid_response_shape(o: &serde_json::Map<String, Value>) -> bool {
    if o.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return false;
    }
    let has_result = o.contains_key("result");
    let has_error_key = o.contains_key("error");
    let has_valid_error = o
        .get("error")
        .and_then(Value::as_object)
        .is_some_and(|e| e.get("code").is_some_and(is_json_integer) && e.get("message").and_then(Value::as_str).is_some());
    (has_result && !has_error_key) || (!has_result && has_valid_error)
}

/// Whether `v` is the JSON-RPC 2.0 response to request `id`: a result or an
/// object error with that id, or an object error with a null or absent id (a
/// server that could not read the request's id).
pub fn is_response_to(v: &Value, id: i64) -> bool {
    let Some(o) = v.as_object() else { return false };
    if !has_valid_response_shape(o) {
        return false;
    }
    let has_error = o.contains_key("error");
    match o.get("id") {
        Some(Value::Number(n)) => n.as_i64() == Some(id),
        Some(Value::Null) | None => has_error,
        _ => false,
    }
}

/// Whether `v` is a JSON-RPC 2.0 response to some request: a result or an
/// object error with a number or string id, or an object error with a null or
/// absent id.
fn is_response(v: &Value) -> bool {
    let Some(o) = v.as_object() else { return false };
    if !has_valid_response_shape(o) {
        return false;
    }
    let has_error = o.contains_key("error");
    match o.get("id") {
        Some(Value::Number(_) | Value::String(_)) => true,
        Some(Value::Null) | None => has_error,
        _ => false,
    }
}

/// The JSON values of an event stream's events, the events read, and why
/// the stream was not read to its end. Bounded: at most [`MAX_SSE_EVENTS`]
/// events of lines up to [`MAX_SSE_LINE_BYTES`].
fn stream_values(body: &[u8]) -> (Vec<Value>, usize, Option<String>) {
    let mut parser = SseParser::new(MAX_SSE_LINE_BYTES);
    let mut events = Vec::new();
    let error = parser.feed_limited(body, &mut events, MAX_SSE_EVENTS).err();
    let values = events.iter().filter_map(|e| serde_json::from_str::<Value>(&e.data).ok()).collect();
    (values, events.len(), error)
}

/// The JSON-RPC response to `id` in an event stream, the events read, and
/// why the stream was not read to its end (see [`stream_values`]).
fn read_event_stream(body: &[u8], id: Option<i64>) -> (Option<Value>, usize, Option<String>) {
    let (values, events, error) = stream_values(body);
    (id.and_then(|id| values.into_iter().find(|v| is_response_to(v, id))), events, error)
}

/// The ids of the requests in a batch body (`None` when it is not a JSON
/// array).
fn batch_ids_of(body: &[u8]) -> Option<Vec<Value>> {
    let v: Value = serde_json::from_slice(body).ok()?;
    Some(v.as_array()?.iter().filter_map(|m| m.get("id").filter(|id| !id.is_null()).cloned()).collect())
}

/// The ids of the batch actually sent (the prepared request body, variables
/// resolved), recorded when its answer starts.
type SentIds = Arc<Mutex<Option<Vec<Value>>>>;

/// A batch's answer out of the values a body holds (a JSON array, one
/// response, or a stream's events, each possibly an array): its responses as
/// one array, or a lone error without an id (the server refused the whole
/// batch) as it is. With the sent request ids known, a response to any other
/// id is not part of the answer.
fn batch_answer(values: Vec<Value>, ids: Option<&[Value]>) -> Option<Value> {
    let flat = values.into_iter().flat_map(|v| match v {
        Value::Array(a) => a,
        other => vec![other],
    });
    let requested = |v: &Value| match (ids, v.get("id")) {
        (_, None | Some(Value::Null)) | (None, _) => true,
        (Some(ids), Some(id)) => ids.contains(id),
    };
    let responses: Vec<Value> = flat.filter(|v| is_response(v) && requested(v)).collect();
    match responses.as_slice() {
        [] => None,
        [lone] if lone.get("id").is_none_or(Value::is_null) => Some(lone.clone()),
        _ => Some(Value::Array(responses)),
    }
}

/// Each sent request id that has no matching response, respecting multiplicity
/// (two requests with the same id require two matching responses).
fn batch_missing_ids(sent_ids: &[Value], responses: &[Value]) -> Vec<Value> {
    let mut used = vec![false; responses.len()];
    let mut missing = Vec::new();
    for id in sent_ids {
        if let Some(pos) = responses.iter().enumerate().position(|(i, r)| !used[i] && r.get("id") == Some(id)) {
            used[pos] = true;
        } else {
            missing.push(id.clone());
        }
    }
    missing
}

/// Whether `values` contains any value more than once.
fn has_duplicate_values(values: &[Value]) -> bool {
    values.iter().enumerate().any(|(i, v)| values[i + 1..].contains(v))
}

/// Whether `responses` has more replies for some id than were sent (or any
/// duplicate id when the sent ids are unknown).
fn batch_has_extra_replies(sent_ids: Option<&[Value]>, responses: &[Value]) -> bool {
    let reply_ids: Vec<&Value> = responses.iter().filter_map(|r| r.get("id").filter(|id| !id.is_null())).collect();
    match sent_ids {
        Some(ids) => reply_ids.iter().any(|rid| {
            let got = reply_ids.iter().filter(|x| *x == rid).count();
            let sent = ids.iter().filter(|x| *x == *rid).count();
            got > sent
        }),
        None => reply_ids.iter().enumerate().any(|(i, rid)| reply_ids[i + 1..].contains(rid)),
    }
}

/// What an exchange's checks read out of its answer.
#[derive(Clone)]
enum Wanted {
    /// The JSON-RPC response to this request id.
    Response(i64),
    /// A batch's responses, with the ids of its requests once known from the
    /// prepared body.
    Batch(Option<Vec<Value>>),
}

impl Wanted {
    /// What the checks read out of the values a body holds.
    fn pick(&self, values: Vec<Value>) -> Option<Value> {
        match self {
            Wanted::Response(id) => values.into_iter().find(|v| is_response_to(v, *id)),
            Wanted::Batch(ids) => batch_answer(values, ids.as_deref()),
        }
    }

    /// The request ids of a batch's answer left without a response (none for
    /// a single request, a refused batch, or unknown ids).
    fn unanswered(&self, answer: Option<&Value>) -> Vec<Value> {
        match (self, answer) {
            (Wanted::Batch(Some(ids)), Some(Value::Array(responses))) => batch_missing_ids(ids, responses),
            _ => Vec::new(),
        }
    }

    /// Whether `answer` is all the exchange waits for: the response, a
    /// response to each request of a batch whose ids are known, or a refusal
    /// of the whole batch.
    fn complete(&self, answer: &Value) -> bool {
        match (self, answer) {
            (Wanted::Response(_), _) => true,
            (Wanted::Batch(Some(ids)), Value::Array(responses)) => !ids.is_empty() && batch_missing_ids(ids, responses).is_empty(),
            (Wanted::Batch(_), Value::Array(_)) => false,
            (Wanted::Batch(_), _) => true,
        }
    }
}

/// Watches one event stream for the answer: its content-coding removed
/// incrementally and its events parsed across chunk boundaries, as they
/// arrive. A stream it cannot decode or parse is never stopped early.
struct AnswerWatch {
    wanted: Wanted,
    decoder: IncrementalDecoder,
    parser: SseParser,
    events: usize,
    /// The JSON-RPC responses seen so far.
    responses: Vec<Value>,
    broken: bool,
}

impl BodyWatch for AnswerWatch {
    fn feed(&mut self, chunk: &[u8]) -> bool {
        if self.broken {
            return false;
        }
        let Ok(decoded) = self.decoder.push(chunk) else {
            self.broken = true;
            return false;
        };
        let mut events = Vec::new();
        // Evaluate every event dispatched before a trailing line error in the
        // same chunk so chunk boundaries cannot change early-stop behavior.
        let parse_err = self.parser.feed_limited(&decoded, &mut events, MAX_SSE_EVENTS.saturating_sub(self.events)).is_err();
        self.events += events.len();
        let values = events.iter().filter_map(|e| serde_json::from_str::<Value>(&e.data).ok());
        let is_batch = matches!(self.wanted, Wanted::Batch(_));
        let before = self.responses.len();
        self.responses.extend(
            values
                .flat_map(|v| match v {
                    Value::Array(a) if is_batch => a,
                    other => vec![other],
                })
                .filter(is_response),
        );
        let done = self.responses.len() > before && self.wanted.pick(self.responses.clone()).is_some_and(|a| self.wanted.complete(&a));
        if parse_err {
            self.broken = true;
        }
        done
    }
}

/// Stop reading a POST's event stream once what the exchange waits for is
/// in it (see [`Wanted::complete`]): the server may keep the stream open
/// after answering. A JSON body is read to its end. For a batch, the ids
/// waited for are always those of the prepared body actually sent, recorded in
/// `sent`.
fn stop_at_answer(wanted: Wanted, sent: SentIds, decompress: bool, max_decoded_bytes: u64) -> BodyStop {
    Arc::new(move |start: &BodyStart<'_>| {
        let wanted = match &wanted {
            Wanted::Batch(_) => {
                // Keep the original POST's batch IDs even if a followed
                // redirect later turns the request into a bodyless GET.
                let mut guard = sent.lock();
                let ids = if guard.is_some() {
                    guard.clone()
                } else {
                    let parsed = batch_ids_of(start.request_body);
                    *guard = parsed.clone();
                    parsed
                };
                Wanted::Batch(ids)
            }
            w => w.clone(),
        };
        if !is_event_stream(start.content_type) {
            return None;
        }
        let has_coding = start
            .content_encoding
            .is_some_and(|ce| ce.split(',').map(str::trim).any(|c| !c.is_empty() && !c.eq_ignore_ascii_case("identity")));
        if has_coding && !decompress {
            return None;
        }
        let decoder = IncrementalDecoder::new(start.content_encoding, max_decoded_bytes)?;
        let watch =
            AnswerWatch { wanted, decoder, parser: SseParser::new(MAX_SSE_LINE_BYTES), events: 0, responses: Vec::new(), broken: false };
        Some(Box::new(watch) as Box<dyn BodyWatch>)
    })
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
    let ct = out.response_metadata.as_ref().and_then(crate::ResponseMetadata::content_type);
    response_in(ct, out.decoded_body.as_ref().unwrap_or(&out.body), OPERATION_ID)
}

/// The view an exchange's checks and diagnosis read: the correlated JSON-RPC
/// response (or batch's matched responses) for both JSON and event-stream
/// replies, while keeping the raw response body on `ExecutionOutput` for
/// evidence. On a 2xx where a response was expected but none matched, returns
/// an empty view so unrelated IDs or non-RPC elements cannot trigger false
/// errors or extractions.
fn viewer(
    seen: &Mutex<Seen>,
    wanted: Option<Wanted>,
    sent: SentIds,
) -> impl Fn(Option<&ResponseRecord>, &[u8]) -> Option<Bytes> + Sync + '_ {
    move |response: Option<&ResponseRecord>, body: &[u8]| {
        let r = response?;
        // A batch's answer is read against the ids actually sent. For a
        // notification-only batch (`Some(vec![])`), keep `Wanted::Batch(Some([]))`
        // so unrelated replies on 2xx/3xx still map to an empty view rather than
        // falling through to raw evaluation (while a null-id batch refusal still
        // surfaces).
        let wanted = wanted.as_ref().map(|w| match w {
            Wanted::Batch(_) => Wanted::Batch(sent.lock().clone()),
            w => w.clone(),
        });
        let mut s = seen.lock();
        s.status = Some(r.status);
        s.session_id = r.header_values(SESSION_HEADER).first().map(|v| v.to_string());
        let message = if !is_event_stream(r.body.content_type.as_deref()) {
            let parsed = serde_json::from_slice::<Value>(body).ok();
            wanted.as_ref().zip(parsed).and_then(|(w, v)| w.pick(vec![v]))
        } else {
            let (values, events, error) = stream_values(body);
            s.events = Some(events);
            s.stream_error = error;
            s.stopped = r.body.completeness == BodyCompleteness::StoppedAfterAnswer;
            wanted.as_ref().and_then(|w| w.pick(values))
        };
        let view = match (&wanted, &message) {
            (Some(_), Some(m)) => serde_json::to_vec(m).ok().map(Bytes::from),
            (Some(_), None) if (200..400).contains(&r.status) => Some(Bytes::new()),
            (None, _) if (300..400).contains(&r.status) => Some(Bytes::new()),
            _ => None,
        };
        s.message = message;
        s.diagnosed_bytes = view.as_ref().map_or(body.len(), Bytes::len);
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
    redact_then_cut(&|x: &str| r.text_any_case(x), &window, cut)
}

/// A JSON-RPC error code as a note shows it: the integer, never the
/// server's raw JSON.
fn code_label(e: &Value) -> String {
    e.get("code")
        .and_then(|v| v.as_i64().map(|c| c.to_string()).or_else(|| v.as_u64().map(|c| c.to_string())))
        .unwrap_or_else(|| "(not an integer)".to_string())
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
fn stream_notes(seen: &Seen, method: &str, batch: bool, notes: &mut Vec<String>) {
    let Some(n) = seen.events else { return };
    let read = match (seen.message.is_some(), batch) {
        (true, false) => "the JSON-RPC response was read from it".to_string(),
        (true, true) => "the batch's JSON-RPC responses were read from it".to_string(),
        (false, false) => format!("none of them was the JSON-RPC response to request {OPERATION_ID}"),
        (false, true) => "none of them was a JSON-RPC response to the batch".to_string(),
    };
    notes.push(format!("MCP {method}: the response arrived as an event stream of {n} event(s); {read}"));
    if seen.stopped {
        notes.push(format!(
            "MCP {method}: Anvil stopped reading the event stream once the JSON-RPC response had arrived (the server had not ended it)"
        ));
    }
    if let Some(e) = &seen.stream_error {
        notes.push(format!("MCP {method}: the event stream was not read to its end: {e}"));
    }
}

/// A JSON-RPC id as a note shows it: a number, or a string quoted (redacted
/// and cut like any server text).
fn id_label(id: Option<&Value>, r: &Redactor) -> String {
    match id {
        Some(Value::Number(n)) => n.to_string(),
        Some(v @ Value::String(_)) => format!("\"{}\"", quoted(Some(v), r)),
        _ => "null".to_string(),
    }
}

/// Most batch responses a note lists one by one.
const MAX_BATCH_NOTED: usize = 10;

/// What a batch's answer held: each response (at most [`MAX_BATCH_NOTED`]
/// listed), the requests left without one, or the refusal of the whole batch.
fn batch_notes(answer: Option<&Value>, ids: Option<&[Value]>, r: &Redactor, notes: &mut Vec<String>) {
    let what = |v: &Value| match v.get("error") {
        Some(e) => format!("id {}: error {}", id_label(v.get("id"), r), error_label(e, r)),
        None => format!("id {}: result", id_label(v.get("id"), r)),
    };
    match answer {
        None => {}
        Some(Value::Array(responses)) => {
            let mut listed: Vec<String> = responses.iter().take(MAX_BATCH_NOTED).map(what).collect();
            if responses.len() > MAX_BATCH_NOTED {
                listed.push(format!("and {} more", responses.len() - MAX_BATCH_NOTED));
            }
            let sent = ids.map(|ids| format!(" to {} request(s)", ids.len())).unwrap_or_default();
            notes.push(format!("MCP JSON-RPC batch: {} response(s){sent}: {}", responses.len(), listed.join("; ")));
            if let Some(ids) = ids {
                let missing: Vec<String> =
                    batch_missing_ids(ids, responses).iter().take(MAX_BATCH_NOTED).map(|id| id_label(Some(id), r)).collect();
                if !missing.is_empty() {
                    notes.push(format!("MCP JSON-RPC batch: no response to request id {}", missing.join(", ")));
                }
            }
        }
        Some(lone) => {
            let e = lone.get("error").map(|e| error_label(e, r)).unwrap_or_default();
            notes.push(format!("MCP JSON-RPC batch: the server refused the whole batch with JSON-RPC error {e}"));
        }
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

fn not_sent(ctx: &ExecutionContext, started_at: Timestamp, why: &str, field: &str, kind: FailureKind) -> ExecutionOutput {
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
    /// Every attempt of every exchange, in order (a load unit counts the
    /// session's whole traffic).
    traffic: Vec<anvil_domain::execution::AttemptObservation>,
    /// First non-completed transport outcome of an auxiliary session exchange
    /// (`notifications/initialized` or the closing `DELETE`), preserved
    /// separately from the operation's record.
    auxiliary_outcome: Option<crate::SessionAuxiliaryOutcome>,
}

impl Run<'_> {
    fn expired(&self) -> bool {
        self.deadline.is_some_and(|d| Instant::now() >= d)
    }

    fn record_auxiliary_failure(
        &mut self,
        exchange: crate::McpAuxiliaryExchange,
        transport: anvil_domain::outcome::TransportState,
        failure: Option<TransportFailure>,
    ) {
        if self.auxiliary_outcome.is_none() {
            self.auxiliary_outcome = Some(crate::SessionAuxiliaryOutcome { exchange, transport, failure });
        }
    }

    async fn exchange(
        &mut self,
        mut c: ExecutionContext,
        events: EventCtx,
        view: Option<BodyView<'_>>,
        stop: Option<BodyStop>,
    ) -> ExecutionOutput {
        if let Some(d) = self.deadline {
            // Rounded up: the exchange's own deadline is never before the session's.
            let left = d.saturating_duration_since(Instant::now()).as_millis() + 1;
            let timeouts = TimeoutOverrides { total_ms: Some(Some(u64::try_from(left).unwrap_or(u64::MAX))), ..Default::default() };
            c.settings_layers.push(("mcp session".into(), SettingsOverrides { timeouts: Some(timeouts), ..Default::default() }));
        }
        let child = self.cancel.child_token();
        let keep = Mutex::new(None);
        let out = {
            // Boxed, as `Engine::execute` boxes each protocol's execution: an
            // HTTP execution's future is large, and the session's future would
            // otherwise hold one for each of its exchanges. Dropped at the end
            // of this block, before `keep` is read.
            let mut exec = Box::pin(http_exec::execute_viewing(self.engine, &c, events, child.clone(), view, Some(&keep), stop));
            match self.deadline {
                None => exec.await,
                Some(d) => {
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
            }
        };
        if let Some(r) = keep.into_inner() {
            self.redactor.absorb(&r);
        }
        if self.expired() {
            self.timed_out = true;
        }
        self.traffic.extend(out.record.attempts.iter().cloned());
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
            self.record_auxiliary_failure(
                crate::McpAuxiliaryExchange::SessionClose,
                anvil_domain::outcome::TransportState::Canceled,
                Some(TransportFailure::new(
                    Phase::Connect,
                    FailureKind::Canceled,
                    "MCP session close (DELETE) was skipped because the execution was canceled",
                )),
            );
        } else if self.expired() {
            after.push("MCP session not closed: the session deadline was reached".into());
            self.record_auxiliary_failure(
                crate::McpAuxiliaryExchange::SessionClose,
                anvil_domain::outcome::TransportState::Incomplete,
                Some(
                    TransportFailure::new(
                        Phase::Connect,
                        FailureKind::TotalTimeout,
                        "MCP session close (DELETE) was skipped because the session deadline was reached",
                    )
                    .with_deadline(self.total_ms),
                ),
            );
        } else {
            let close = exchange(ctx, "DELETE", None, Some(sid), Some(version), Checks::None);
            let closed = self.exchange(close, events.clone(), None, None).await;
            if closed.record.outcome.transport != anvil_domain::outcome::TransportState::Completed {
                self.record_auxiliary_failure(
                    crate::McpAuxiliaryExchange::SessionClose,
                    closed.record.outcome.transport,
                    closed.record.attempts.last().and_then(|a| a.failure.clone()),
                );
            }
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
    /// Requests of a batch its answer left without a response.
    unanswered: usize,
    /// Why a batch's response correlation is ambiguous (duplicate request ids
    /// or extra replies for the same id).
    ambiguous_batch: Option<String>,
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
    if let Some(s) = &seen.session_id {
        redactor.add_secret(s);
    }
    let r = &mut out.record;
    r.prepared.protocol = Protocol::Mcp;
    let mut inferred: Vec<String> = notes.before.iter().map(|n| redactor.inferred(n)).collect();
    inferred.append(&mut r.prepared.inferred);
    inferred.extend(notes.after.iter().map(|n| redactor.inferred(n)));
    r.prepared.inferred = inferred;
    for w in &notes.warnings {
        r.outcome.warnings.push(OutcomeWarning { code: WarningCode::PartialVisibility, message: redactor.text_any_case(w) });
    }
    let answered = r.response.as_ref().is_some_and(|x| (200..300).contains(&x.status));
    let mut changed = !notes.warnings.is_empty();
    if let Some(why) = &notes.not_sent {
        // The exchange shown is not the operation: its outcome is not the call's.
        if r.outcome.application == ApplicationState::Success {
            r.outcome.application = ApplicationState::NotEvaluated;
        }
        let message = format!("The MCP operation was not sent ({why}), so its outcome was not evaluated");
        r.outcome.warnings.push(OutcomeWarning { code: WarningCode::PartialVisibility, message: redactor.text_any_case(&message) });
        changed = true;
    } else if let Some(redirect_status) = r.response.as_ref().map(|x| x.status).filter(|s| (300..400).contains(s))
        && r.outcome.application == ApplicationState::Success
    {
        // A terminal 3xx redirect did not reach an MCP answer (Streamable HTTP
        // requires a 2xx response), so the MCP outcome was not evaluated.
        r.outcome.application = ApplicationState::NotEvaluated;
        r.outcome.warnings.push(OutcomeWarning {
            code: WarningCode::PartialVisibility,
            message: format!("The MCP request ended on a redirect (HTTP {redirect_status}), so the MCP outcome was not evaluated"),
        });
        changed = true;
    } else if expects_response && answered && seen.message.is_none() && r.outcome.application == ApplicationState::Success {
        // A 2xx without the JSON-RPC response says nothing about the call.
        r.outcome.application = ApplicationState::NotEvaluated;
        r.outcome.warnings.push(OutcomeWarning {
            code: WarningCode::PartialVisibility,
            message: "The response holds no JSON-RPC response to the MCP request, so the MCP outcome was not evaluated".into(),
        });
        changed = true;
    } else if notes.unanswered > 0 && answered && r.outcome.application == ApplicationState::Success {
        // A batch is a success only when every request in it was answered.
        r.outcome.application = ApplicationState::NotEvaluated;
        r.outcome.warnings.push(OutcomeWarning {
            code: WarningCode::PartialVisibility,
            message: format!("{} request(s) of the JSON-RPC batch got no response, so the MCP outcome was not evaluated", notes.unanswered),
        });
        changed = true;
    } else if let Some(why) = &notes.ambiguous_batch
        && answered
        && r.outcome.application == ApplicationState::Success
    {
        r.outcome.application = ApplicationState::NotEvaluated;
        r.outcome.warnings.push(OutcomeWarning { code: WarningCode::PartialVisibility, message: redactor.text_any_case(why) });
        changed = true;
    } else if expects_response && seen.diagnosed_bytes > MAX_PARSE && r.outcome.application == ApplicationState::Success {
        // A JSON-RPC error or tool failure in a response this large is not
        // looked for, so a 2xx says nothing about the call.
        r.outcome.application = ApplicationState::NotEvaluated;
        r.outcome.warnings.push(OutcomeWarning {
            code: WarningCode::PartialVisibility,
            message: format!(
                "The JSON-RPC response is over the {} KiB inspected for an error, so the MCP outcome was not evaluated",
                MAX_PARSE / 1024
            ),
        });
        changed = true;
    }
    if changed {
        r.outcome.summary = record::summary_line(r.outcome.transport, r.outcome.application, &r.outcome.protocol_status, &r.findings);
    }
    // This pass covers the findings and the inferred notes too.
    redactor.record_metadata(r);
    out
}

/// Run one MCP request (see the module documentation).
pub(crate) async fn execute(engine: &Engine, ctx: &ExecutionContext, events: EventCtx, cancel: CancellationToken) -> ExecutionOutput {
    let mut none = |_: usize, _: Option<&Value>| -> Option<McpOperation> { None };
    let mut outs = execute_session(engine, ctx, events, cancel, &mut none).await;
    outs.pop().map(|(out, _)| out).unwrap_or_else(|| unreachable_output(ctx))
}

/// A session always yields at least one output; this is its stand-in.
fn unreachable_output(ctx: &ExecutionContext) -> ExecutionOutput {
    not_sent(ctx, Timestamp::now(), "the MCP session produced no exchange", "mcp", FailureKind::UnsupportedCombination)
}

/// One `tools/list` page [`list_tool_pages`] read: its execution and the
/// JSON-RPC response it held.
pub struct ToolPage {
    pub output: ExecutionOutput,
    pub response: Option<Value>,
}

/// Run `tools/list` with the MCP request `ctx` (its operation is replaced)
/// and, while `next_cursor` returns a cursor for the page just read (the
/// page's number from 1 and its JSON-RPC response), the next page **in the
/// same session**, with request ids 2, 3, …: a pagination cursor belongs to
/// the session that issued it. Returns every page sent, or the handshake's
/// exchange when it failed (its response is then `None`).
pub async fn list_tool_pages(
    engine: &Engine,
    ctx: &ExecutionContext,
    events: EventCtx,
    cancel: CancellationToken,
    next_cursor: &mut (dyn FnMut(usize, Option<&Value>) -> Option<String> + Send),
) -> Vec<ToolPage> {
    let mut c = ctx.clone();
    c.spec.protocol = Protocol::Mcp;
    if let Some(m) = c.spec.mcp.as_mut() {
        m.operation = McpOperation::ToolsList { cursor: None };
    }
    // Pin every discovery exchange to the issuing endpoint and session so a
    // redirect cannot supply a cursor for the original endpoint or forward a
    // cursor to another origin.
    c.settings_layers.push((
        "mcp-discover".into(),
        SettingsOverrides {
            redirects: Some(anvil_domain::settings::RedirectPolicy { follow: false, ..Default::default() }),
            ..Default::default()
        },
    ));
    let mut next = |page: usize, response: Option<&Value>| -> Option<McpOperation> {
        next_cursor(page, response).map(|cursor| McpOperation::ToolsList { cursor: Some(cursor) })
    };
    let outs = execute_session(engine, &c, events, cancel, &mut next).await;
    outs.into_iter().map(|(output, response)| ToolPage { output, response }).collect()
}

/// One operation sent in the session, waiting for the session's end to be
/// finished.
struct Sent {
    out: ExecutionOutput,
    notes: Notes,
    seen: Seen,
    expects_response: bool,
    /// Its attempts' place in [`Run::traffic`].
    own: std::ops::Range<usize>,
}

/// Run one MCP session: the handshake, the request's operation, then, while
/// `next` returns another operation for the one just answered (its number
/// from 1 and its JSON-RPC response), that operation in the same session,
/// with the next request id; then the close. Returns each operation's output
/// with its JSON-RPC response (or the handshake's exchange when it failed).
async fn execute_session(
    engine: &Engine,
    ctx: &ExecutionContext,
    events: EventCtx,
    cancel: CancellationToken,
    next: &mut (dyn FnMut(usize, Option<&Value>) -> Option<McpOperation> + Send),
) -> Vec<(ExecutionOutput, Option<Value>)> {
    let started_at = Timestamp::now();
    let Some(spec) = ctx.spec.mcp.as_ref() else {
        let why = format!("{NO_MCP_SETTINGS}; nothing was sent");
        return vec![(not_sent(ctx, started_at, &why, "mcp", FailureKind::UnsupportedCombination), None)];
    };
    if let Some((why, field)) = invalid(spec) {
        return vec![(not_sent(ctx, started_at, &format!("{why}; nothing was sent"), field, FailureKind::BodySerialization), None)];
    }
    let method = spec.operation.method().trim().to_string();
    let settings = crate::settings::resolve(&ctx.settings_layers);
    let total_ms = settings.timeouts.total_ms;
    let decompress = settings.decompress;
    let max_decoded_bytes = settings.limits.max_decoded_bytes;
    let mut run = Run {
        engine,
        cancel: &cancel,
        deadline: total_ms.map(|ms| Instant::now() + Duration::from_millis(ms)),
        total_ms,
        redactor: Redactor::new(vec![], ctx.redaction_names.clone()),
        timed_out: false,
        traffic: Vec::new(),
        auxiliary_outcome: None,
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
        let mut init = exchange(ctx, "POST", Some(initialize_body(spec)), None, None, Checks::Assertions);
        init.settings_layers.push((
            "mcp-initialize".into(),
            SettingsOverrides {
                redirects: Some(anvil_domain::settings::RedirectPolicy { follow: false, ..Default::default() }),
                ..Default::default()
            },
        ));
        let none_sent: SentIds = Arc::new(Mutex::new(None));
        let out = {
            let view = viewer(&seen, Some(Wanted::Response(INITIALIZE_ID)), none_sent.clone());
            let view: BodyView<'_> = &view;
            run.exchange(
                init,
                quiet.clone(),
                Some(view),
                Some(stop_at_answer(Wanted::Response(INITIALIZE_ID), none_sent.clone(), decompress, max_decoded_bytes)),
            )
            .await
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
                let mut out = finish(out, notes, &run, refused.issued.as_deref(), &seen, true);
                out.session_attempts = run.traffic.get(out.record.attempts.len()..).map(<[_]>::to_vec).unwrap_or_default();
                out.session_auxiliary_outcome = run.auxiliary_outcome.clone();
                return vec![(out, None)];
            }
        }
        let notify = exchange(ctx, "POST", Some(INITIALIZED.into()), session.as_deref(), Some(&version), Checks::None);
        let out = run.exchange(notify, quiet.clone(), None, None).await;
        notes.before.push(exchange_note("notifications/initialized", &out));
        if out.record.outcome.transport != anvil_domain::outcome::TransportState::Completed {
            run.record_auxiliary_failure(
                crate::McpAuxiliaryExchange::InitializedNotification,
                out.record.outcome.transport,
                out.record.attempts.last().and_then(|a| a.failure.clone()),
            );
        }
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
            let own = run.traffic.len().saturating_sub(out.record.attempts.len())..run.traffic.len();
            let mut out = finish(out, notes, &run, session.as_deref(), &Seen::default(), false);
            out.session_attempts = others(&run.traffic, &own);
            out.session_auxiliary_outcome = run.auxiliary_outcome.clone();
            return vec![(out, None)];
        }
        // A server that does not accept the notification may still answer
        // the operation: it is sent, and the refusal is reported.
        let answered = out.record.response.as_ref().map(|r| r.status);
        if !answered.is_some_and(|s| (200..300).contains(&s)) {
            let got = answered.map_or_else(|| "no response".to_string(), |s| format!("HTTP {s}"));
            notes.warnings.push(format!("notifications/initialized was not accepted ({got}); the {method} request was still sent"));
        }
    }
    let mut operation = spec.operation.clone();
    let mut id = OPERATION_ID;
    let mut sent: Vec<Sent> = Vec::new();
    let mut events = Some(events);
    loop {
        let method = operation.method().trim().to_string();
        let is_batch = matches!(&operation, McpOperation::Batch { .. });
        // Always observe a batch's prepared bytes (variables resolved) so
        // templated member names or ids determine response expectations.
        let wanted = if is_batch {
            Some(Wanted::Batch(None))
        } else if operation.is_notification() {
            None
        } else {
            Some(Wanted::Response(id))
        };
        let seen = Mutex::new(Seen::default());
        let sent_ids: SentIds = Arc::new(Mutex::new(None));
        let op = exchange(ctx, "POST", Some(operation_body_id(&operation, id)), session.as_deref(), Some(&version), Checks::All);
        // Only the first operation's progress is the caller's execution.
        let op_events = events.take().unwrap_or_else(|| quiet.clone());
        let out = {
            let view = viewer(&seen, wanted.clone(), sent_ids.clone());
            let view: BodyView<'_> = &view;
            run.exchange(
                op,
                op_events,
                Some(view),
                wanted.clone().map(|w| stop_at_answer(w, sent_ids.clone(), decompress, max_decoded_bytes)),
            )
            .await
        };
        let own = run.traffic.len().saturating_sub(out.record.attempts.len())..run.traffic.len();
        let seen = seen.into_inner();
        let mut op_notes = if sent.is_empty() { std::mem::take(&mut notes) } else { Notes::default() };
        if !sent.is_empty() {
            op_notes.before.push(format!("MCP {method}: page {} of the same session (request id {id})", sent.len() + 1));
        }
        stream_notes(&seen, &method, is_batch, &mut op_notes.after);
        let expects_response = if is_batch {
            // Judged against the ids actually sent (variables resolved).
            let ids = sent_ids.lock().clone();
            batch_notes(seen.message.as_ref(), ids.as_deref(), &run.redactor, &mut op_notes.after);
            let unanswered = Wanted::Batch(ids.clone()).unanswered(seen.message.as_ref());
            op_notes.unanswered = unanswered.len();
            if ids.as_deref().is_some_and(has_duplicate_values) {
                op_notes.ambiguous_batch = Some(
                    "the JSON-RPC batch reused a request id more than once, so response correlation is ambiguous and the MCP outcome was not evaluated"
                        .into(),
                );
            } else if matches!(seen.message.as_ref(), Some(Value::Array(responses)) if batch_has_extra_replies(ids.as_deref(), responses)) {
                op_notes.ambiguous_batch = Some(
                    "the server returned multiple JSON-RPC responses for the same batch request id, so the MCP outcome was not evaluated"
                        .into(),
                );
            }
            if spec.initialize && ids.as_deref().is_some_and(|ids| ids.iter().any(|v| v.as_i64() == Some(INITIALIZE_ID))) {
                op_notes.warnings.push(format!(
                    "the JSON-RPC batch reuses request id {INITIALIZE_ID}, the id initialize used in this session; a server may refuse a reused id"
                ));
            }
            !ids.as_ref().is_some_and(Vec::is_empty)
        } else {
            !operation.is_notification()
        };
        if session.is_some() && out.record.response.as_ref().is_some_and(|r| r.status == 404) {
            let why = "the server no longer knows the session (it expired or was ended); a new initialize opens another";
            op_notes.after.push(format!("MCP {method}: HTTP 404 in the session: {why}"));
        }
        if run.timed_out {
            op_notes.after.push(run.deadline_note(&method));
        }
        let message = seen.message.clone();
        let more =
            if cancel.is_cancelled() || run.expired() || !out.record.response.as_ref().is_some_and(|r| (200..300).contains(&r.status)) {
                None
            } else {
                next(sent.len() + 1, message.as_ref())
            };
        sent.push(Sent { out, notes: op_notes, seen, expects_response, own });
        match more {
            Some(op) => {
                operation = op;
                id += 1;
            }
            None => break,
        }
    }
    if let (Some(sid), Some(last)) = (session.as_deref(), sent.last_mut()) {
        run.close(ctx, spec, sid, &version, &quiet, &mut last.notes.after).await;
    }
    let traffic = std::mem::take(&mut run.traffic);
    let auxiliary_outcome = run.auxiliary_outcome.clone();
    let total_sent = sent.len();
    sent.into_iter()
        .enumerate()
        .map(|(i, s)| {
            let message = s.seen.message.clone();
            let mut out = finish(s.out, s.notes, &run, session.as_deref(), &s.seen, s.expects_response);
            out.session_attempts = others(&traffic, &s.own);
            if i + 1 == total_sent {
                out.session_auxiliary_outcome = auxiliary_outcome.clone();
            }
            (out, message)
        })
        .collect()
}

/// The session's traffic other than one exchange's own attempts.
fn others(
    traffic: &[anvil_domain::execution::AttemptObservation],
    own: &std::ops::Range<usize>,
) -> Vec<anvil_domain::execution::AttemptObservation> {
    traffic.iter().enumerate().filter(|(i, _)| !own.contains(i)).map(|(_, a)| a.clone()).collect()
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
        let null_id = br#"{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"Invalid Request"}}"#;
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

    #[test]
    fn response_validation_requires_jsonrpc_2_0_and_exclusive_result_or_object_error() {
        assert!(is_response(&serde_json::json!({"jsonrpc":"2.0","id":2,"result":{}})));
        assert!(is_response(&serde_json::json!({"jsonrpc":"2.0","id":2,"error":{"code":-32600,"message":"Invalid Request"}})));
        assert!(!is_response(&serde_json::json!({"id":2,"result":{}})), "missing jsonrpc 2.0");
        assert!(!is_response(&serde_json::json!({"jsonrpc":"1.0","id":2,"result":{}})), "wrong version");
        assert!(
            !is_response(&serde_json::json!({"jsonrpc":"2.0","id":2,"result":{},"error":{"code":-1,"message":"x"}})),
            "both result and error"
        );
        assert!(!is_response(&serde_json::json!({"jsonrpc":"2.0","id":2,"error":"not-an-object"})), "non-object error");
        assert!(!is_response(&serde_json::json!({"jsonrpc":"2.0","id":2,"error":{}})), "empty error object");
        assert!(!is_response(&serde_json::json!({"jsonrpc":"2.0","id":2,"error":{"code":-32600}})), "error missing message");
        assert!(!is_response(&serde_json::json!({"jsonrpc":"2.0","id":2,"error":{"code":1.5,"message":"float"}})), "float error code");
        assert!(
            is_response(&serde_json::json!({"jsonrpc":"2.0","id":2,"error":{"code":9223372036854775808u64,"message":"large unsigned"}})),
            "u64 integer error code above i64::MAX must be accepted"
        );
        assert_eq!(code_label(&serde_json::json!({"code": 9223372036854775808u64})), "9223372036854775808");
        assert!(!is_response_to(&serde_json::json!({"id":2,"result":{}}), 2));
        assert!(!is_response_to(&serde_json::json!({"jsonrpc":"2.0","id":2,"result":{},"error":{"code":-1,"message":"x"}}), 2));
    }

    #[test]
    fn malformed_batch_watch_stops_early_only_on_lone_null_id_refusal() {
        let stop = stop_at_answer(Wanted::Batch(None), Arc::new(Mutex::new(None)), true, 64 * 1024);
        let mut watch = stop(&BodyStart { request_body: b"[1]", content_type: Some("text/event-stream"), content_encoding: None })
            .expect("malformed batch [1] must still install watch for lone null-id refusal");
        assert!(!watch.feed(b"data: {\"jsonrpc\":\"2.0\",\"id\":99,\"result\":{}}\n\n"), "unrelated response id must not stop watch");
        assert!(
            watch.feed(b"data: {\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32600,\"message\":\"Invalid Request\"}}\n\n"),
            "lone null-id refusal must trigger early stop"
        );
    }

    #[test]
    fn single_request_watch_does_not_stop_on_array_event() {
        let stop = stop_at_answer(Wanted::Response(OPERATION_ID), Arc::new(Mutex::new(None)), true, 64 * 1024);
        let mut watch = stop(&BodyStart { request_body: b"{}", content_type: Some("text/event-stream"), content_encoding: None })
            .expect("watch installed");
        assert!(
            !watch.feed(format!("data: [{{\"jsonrpc\":\"2.0\",\"id\":{OPERATION_ID},\"result\":{{}}}}]\n\n").as_bytes()),
            "array event must not stop a single-request watcher"
        );
        assert!(
            watch.feed(format!("data: {{\"jsonrpc\":\"2.0\",\"id\":{OPERATION_ID},\"result\":{{}}}}\n\n").as_bytes()),
            "top-level response object must stop single-request watcher"
        );
    }

    #[test]
    fn batch_completion_respects_id_multiplicity() {
        let wanted = Wanted::Batch(Some(vec![Value::from(11), Value::from(11)]));
        let one = serde_json::json!([{"jsonrpc":"2.0","id":11,"result":{}}]);
        assert!(!wanted.complete(&one), "one reply must not satisfy two requests with id 11");
        assert_eq!(wanted.unanswered(Some(&one)), vec![Value::from(11)]);
        let two = serde_json::json!([{"jsonrpc":"2.0","id":11,"result":{}},{"jsonrpc":"2.0","id":11,"result":{}}]);
        assert!(wanted.complete(&two));
        assert!(wanted.unanswered(Some(&two)).is_empty());
    }

    #[test]
    fn answer_watch_stops_on_dispatched_answer_even_with_trailing_oversized_line_in_same_chunk() {
        let stop = stop_at_answer(Wanted::Response(OPERATION_ID), Arc::new(Mutex::new(None)), true, 64 * 1024 * 1024);
        let mut watch = stop(&BodyStart { request_body: b"{}", content_type: Some("text/event-stream"), content_encoding: None })
            .expect("watch installed");
        let chunk = format!(
            "event: message\ndata: {{\"jsonrpc\":\"2.0\",\"id\":{OPERATION_ID},\"result\":{{}}}}\n\ndata: {}\n\n",
            "x".repeat(MAX_SSE_LINE_BYTES + 16)
        );
        assert!(watch.feed(chunk.as_bytes()), "dispatched answer before trailing parse error must still trigger stop");
    }

    #[test]
    fn answer_watch_skips_coded_stream_when_decompress_disabled() {
        let stop = stop_at_answer(Wanted::Response(OPERATION_ID), Arc::new(Mutex::new(None)), false, 64 * 1024);
        let watch = stop(&BodyStart { request_body: b"{}", content_type: Some("text/event-stream"), content_encoding: Some("gzip") });
        assert!(watch.is_none(), "coded stream must not be decompressed when decompress is off");
    }
}
