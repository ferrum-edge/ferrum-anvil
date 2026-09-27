//! A secret variable used only in what a session sends once it is open (a
//! WebSocket message or subprotocol, a gRPC message or metadata value, an
//! SSE `Last-Event-ID`) is redacted in the live transcript events and in the
//! stored record, like a secret used in the URL or a header. Each case uses
//! a secret that appears nowhere else in the request, checks from the
//! fixture's ground truth that the value was really sent, and then that
//! neither the events nor the record hold it.

use anvil_domain::events::ExecutionEvent;
use anvil_domain::execution::*;
use anvil_domain::request::*;
use anvil_domain::secret::REDACTED;
use anvil_domain::settings::{SettingsOverrides, TimeoutOverrides};
use anvil_domain::Id;
use anvil_engine::context::MemoryAttachments;
use anvil_engine::vars::{VarEntry, VarLayer};
use anvil_engine::{Engine, ExecutionContext, ExecutionOutput};
use anvil_fixtures::GroundTruth;
use anvil_fixtures::grpc::ECHO_PROTO;
use anvil_fixtures::http as fx;
use anvil_transport::recorder::{EventCtx, EventFn};
use bytes::Bytes;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

fn init() {
    anvil_transport::init();
    anvil_fixtures::init();
}

/// `spec` with `name` as a secret variable holding `value` and short timeouts.
fn with_secret(spec: RequestSpec, name: &str, value: &str) -> ExecutionContext {
    let mut c = ExecutionContext::standalone(spec);
    c.var_layers = vec![VarLayer {
        label: "environment:test".into(),
        vars: vec![VarEntry { name: name.into(), value: value.into(), secret: true }],
    }];
    let timeouts = TimeoutOverrides {
        connect_ms: Some(Some(3_000)),
        response_headers_ms: Some(Some(5_000)),
        total_ms: Some(Some(20_000)),
        ..Default::default()
    };
    c.settings_layers.push(("run".into(), SettingsOverrides { timeouts: Some(timeouts), ..Default::default() }));
    c
}

/// Run `c`, keeping every live event.
async fn run_with_events(e: &Engine, c: &ExecutionContext) -> (ExecutionOutput, Vec<ExecutionEvent>) {
    let seen: Arc<Mutex<Vec<ExecutionEvent>>> = Arc::new(Mutex::new(vec![]));
    let s2 = seen.clone();
    let sink: EventFn = Arc::new(move |e| s2.lock().push(e));
    let o = e.execute(c, EventCtx { execution_id: Id::new(), sink: Some(sink) }, CancellationToken::new()).await;
    let events = seen.lock().clone();
    (o, events)
}

fn stream(o: &ExecutionOutput) -> &StreamTranscript {
    o.record.stream.as_ref().unwrap_or_else(|| panic!("no transcript: {:?}", o.record.attempts.last().and_then(|a| a.failure.as_ref())))
}

/// Neither a live event nor the stored record holds `secret`.
fn assert_not_leaked(label: &str, o: &ExecutionOutput, events: &[ExecutionEvent], secret: &str) {
    assert!(!events.is_empty(), "{label}: no live events were emitted");
    let live = serde_json::to_string(events).unwrap();
    assert!(!live.contains(secret), "{label}: a live event holds the secret: {live}");
    let record = serde_json::to_string(&o.record).unwrap();
    assert!(!record.contains(secret), "{label}: the stored record holds the secret: {record}");
}

fn ws_spec(url: &str, subprotocols: Vec<String>, text: &str) -> RequestSpec {
    let mut s = RequestSpec::http("GET", url);
    s.protocol = Protocol::WebSocket;
    s.websocket = Some(WsSpec {
        bootstrap: WsBootstrap::Http1Upgrade,
        subprotocols,
        messages: vec![WsMessage::Text { text: text.into() }],
        expect_messages: 1,
        max_message_bytes: 1024 * 1024,
        idle_close_ms: 1_000,
        permessage_deflate: Default::default(),
    });
    s
}

/// A unary `Echo` call with the echo service's `.proto` as its schema.
fn grpc_ctx(url: &str, message: &str, metadata: Vec<KeyValue>, secret: (&str, &str)) -> ExecutionContext {
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
        messages: vec![message.into()],
        metadata,
        deadline_ms: None,
        plaintext: false,
        wire: GrpcWire::Grpc,
    });
    let mut c = with_secret(s, secret.0, secret.1);
    c.attachments = Arc::new(MemoryAttachments(HashMap::from([(sha, Bytes::from_static(ECHO_PROTO.as_bytes()))])));
    c
}

fn received_header(f: &fx::Fixture, path: &str, name: &str) -> Option<String> {
    f.log.entries().into_iter().rev().find_map(|e| match e.event {
        GroundTruth::RequestReceived { path: p, headers, .. } if p.starts_with(path) => {
            headers.into_iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v)
        }
        _ => None,
    })
}

#[tokio::test]
async fn a_secret_in_a_websocket_message_is_redacted_live_and_in_the_record() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    let secret = "ws-message-secret-8h3v";
    let url = format!("ws://{}/ws?close_after=1", f.addr);
    let c = with_secret(ws_spec(&url, vec![], "Bearer {{ws_message_secret}}"), "ws_message_secret", secret);
    let (o, events) = run_with_events(&e, &c).await;
    assert!(f.log.entries().iter().any(|e| matches!(e.event, GroundTruth::MessageReceived { .. })), "the message was not sent");
    let sent: Vec<&str> =
        stream(&o).messages.iter().filter(|m| m.direction == Direction::Sent && m.kind == "text").map(|m| m.preview.as_str()).collect();
    assert_eq!(sent, vec![format!("Bearer {REDACTED}")], "the sent message is kept, redacted");
    assert_not_leaked("websocket message", &o, &events, secret);
}

#[tokio::test]
async fn a_secret_websocket_subprotocol_is_redacted_live_and_in_the_record() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    let secret = "subprotocol-secret-5q8r";
    let url = format!("ws://{}/ws?close_after=1", f.addr);
    let c = with_secret(ws_spec(&url, vec!["{{ws_subprotocol}}".into()], "hello"), "ws_subprotocol", secret);
    let (o, events) = run_with_events(&e, &c).await;
    assert_eq!(received_header(&f, "/ws", "sec-websocket-protocol").as_deref(), Some(secret), "the subprotocol was not offered");
    assert!(o.record.response.is_some(), "{:?}", o.record.attempts.last().and_then(|a| a.failure.as_ref()));
    assert_not_leaked("websocket subprotocol", &o, &events, secret);
}

#[tokio::test]
async fn a_secret_in_grpc_metadata_is_redacted_live_and_in_the_record() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    let secret = "grpc-metadata-secret-2w6n";
    let metadata = vec![KeyValue::new("x-client-note", "{{grpc_metadata_secret}}")];
    let c = grpc_ctx(&format!("grpc://{}", f.addr), r#"{"message":"hi"}"#, metadata, ("grpc_metadata_secret", secret));
    let (o, events) = run_with_events(&e, &c).await;
    assert_eq!(received_header(&f, "/anvil.lab.v1.Echo/Unary", "x-client-note").as_deref(), Some(secret), "the metadata was not sent");
    assert!(stream(&o).received_count > 0, "{:?}", o.record.attempts.last().and_then(|a| a.failure.as_ref()));
    assert_not_leaked("gRPC metadata", &o, &events, secret);
}

#[tokio::test]
async fn a_secret_in_a_grpc_message_is_redacted_live_and_in_the_record() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    let secret = "grpc-message-secret-9k4d";
    let c = grpc_ctx(&format!("grpc://{}", f.addr), r#"{"message":"{{grpc_message_secret}}"}"#, vec![], ("grpc_message_secret", secret));
    let (o, events) = run_with_events(&e, &c).await;
    assert!(f.log.entries().iter().any(|e| matches!(e.event, GroundTruth::MessageReceived { .. })), "the message was not sent");
    let messages: Vec<(Direction, &str)> =
        stream(&o).messages.iter().filter(|m| m.kind == "grpc_message").map(|m| (m.direction, m.preview.as_str())).collect();
    let redacted = format!(r#"{{"message":"{REDACTED}"}}"#);
    // The fixture echoes the message: the reply holds the secret too.
    assert_eq!(messages, vec![(Direction::Sent, redacted.as_str()), (Direction::Received, redacted.as_str())]);
    assert_not_leaked("gRPC message", &o, &events, secret);
}

#[tokio::test]
async fn a_secret_sse_last_event_id_is_redacted_live_and_in_the_record() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    let secret = "sse-last-event-id-secret-3m9t";
    let mut s = RequestSpec::http("GET", &f.url("/sse?count=1&interval=1"));
    s.protocol = Protocol::Sse;
    s.sse = Some(SseSpec { max_events: 1, idle_timeout_ms: 5_000, last_event_id: Some("{{sse_last_event_id}}".into()), reconnect: false });
    let c = with_secret(s, "sse_last_event_id", secret);
    let (o, events) = run_with_events(&e, &c).await;
    assert_eq!(received_header(&f, "/sse", "last-event-id").as_deref(), Some(secret), "the Last-Event-ID was not sent");
    assert!(stream(&o).received_count > 0, "{:?}", o.record.attempts.last().and_then(|a| a.failure.as_ref()));
    assert_not_leaked("SSE Last-Event-ID", &o, &events, secret);
}
