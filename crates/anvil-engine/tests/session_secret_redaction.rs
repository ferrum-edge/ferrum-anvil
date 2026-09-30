//! A secret variable used only in what a session sends once it is open (a
//! WebSocket message, binary message or subprotocol, a gRPC message or
//! metadata value, an SSE `Last-Event-ID`, a raw TCP payload in text, base64
//! or hex) is redacted in the live transcript events and in the stored
//! record, like a secret used in the URL or a header, and so are the bytes a
//! secret in an encoded field decodes to, whether the preview shows them as
//! text or as hex. Each case uses a secret that appears nowhere else in the
//! request, checks from the fixture's ground truth that the value was really
//! sent, and then that neither the events nor the record hold it.

use anvil_domain::Id;
use anvil_domain::events::ExecutionEvent;
use anvil_domain::execution::*;
use anvil_domain::request::*;
use anvil_domain::secret::REDACTED;
use anvil_domain::settings::{HttpVersionPolicy, SettingsOverrides, TimeoutOverrides};
use anvil_engine::context::MemoryAttachments;
use anvil_engine::vars::{VarEntry, VarLayer};
use anvil_engine::{Engine, ExecutionContext, ExecutionOutput};
use anvil_fixtures::GroundTruth;
use anvil_fixtures::grpc::ECHO_PROTO;
use anvil_fixtures::http as fx;
use anvil_fixtures::streams::{self, TcpMode};
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
    with_secrets(spec, &[(name, value)])
}

/// `spec` with each `(name, value)` as a secret variable and short timeouts.
fn with_secrets(spec: RequestSpec, secrets: &[(&str, &str)]) -> ExecutionContext {
    let mut c = ExecutionContext::standalone(spec);
    let vars = secrets.iter().map(|(name, value)| VarEntry { name: name.to_string(), value: value.to_string(), secret: true }).collect();
    c.var_layers = vec![VarLayer { label: "environment:test".into(), vars }];
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
    // The messages never quote the evidence: it would hold the secret.
    let live = serde_json::to_string(events).unwrap();
    assert!(!live.contains(secret), "{label}: a live event holds the secret");
    let record = serde_json::to_string(&o.record).unwrap();
    assert!(!record.contains(secret), "{label}: the stored record holds the secret");
}

fn ws_spec(url: &str, subprotocols: Vec<String>, text: &str) -> RequestSpec {
    ws_spec_with(url, subprotocols, WsMessage::Text { text: text.into() })
}

fn ws_spec_with(url: &str, subprotocols: Vec<String>, message: WsMessage) -> RequestSpec {
    let mut s = RequestSpec::http("GET", url);
    s.protocol = Protocol::WebSocket;
    s.websocket = Some(WsSpec {
        bootstrap: WsBootstrap::Http1Upgrade,
        subprotocols,
        messages: vec![message],
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

/// Newline-framed raw TCP to `addr`, reading back one echoed frame per payload.
fn tcp_spec(addr: std::net::SocketAddr, payloads: Vec<StreamPayload>) -> RequestSpec {
    let mut s = RequestSpec::http("GET", &format!("tcp://{addr}"));
    s.protocol = Protocol::Tcp;
    s.tcp = Some(TcpSpec {
        tls: false,
        framing: TcpFraming::NewlineDelimited,
        expect_frames: payloads.len() as u32,
        payloads,
        half_close_after_send: false,
        read_idle_ms: 2_000,
        max_read_bytes: 4096,
        proxy_protocol: None,
    });
    s
}

/// The previews of the transcript entries of `kind` sent (and, from an echo, received).
fn previews<'a>(o: &'a ExecutionOutput, direction: Direction, kind: &str) -> Vec<(&'a str, bool)> {
    let entries = stream(o).messages.iter().filter(|m| m.direction == direction && m.kind == kind);
    entries.map(|m| (m.preview.as_str(), m.preview_is_hex)).collect()
}

fn received_bytes(log: &anvil_fixtures::GroundTruthLog) -> u64 {
    log.entries().iter().map(|e| if let GroundTruth::MessageReceived { bytes } = e.event { bytes } else { 0 }).sum()
}

/// The value of the header `name` in `headers`.
fn value_of(headers: &[HeaderEntry], name: &str) -> Option<String> {
    headers.iter().find(|h| h.name.eq_ignore_ascii_case(name)).map(|h| h.value.clone())
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

// A guard, not a regression test: the subprotocol is also a handshake header,
// which the record's redactor already covered.
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

// A guard, not a regression test: metadata is also a request header, which the
// record's redactor already covered.
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

/// Metadata marked sensitive holding a literal (no secret variable) under a
/// name no rule recognises is redacted by name and by value, as a request
/// header marked sensitive is: in the preview, the live events and the stored
/// record (which a history export serializes as it is), in every wire format.
#[tokio::test]
async fn literal_grpc_metadata_marked_sensitive_is_redacted_in_the_preview_and_the_record() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    let secret = "grpc-literal-metadata-6t1z";
    let url = format!("grpc://{}", f.addr);
    let cases = [
        (GrpcWire::Grpc, HttpVersionPolicy::Auto),
        (GrpcWire::GrpcWeb, HttpVersionPolicy::Auto),
        (GrpcWire::GrpcWebText, HttpVersionPolicy::H2c),
    ];
    for (wire, version) in cases {
        let label = format!("{wire:?}");
        let marked = KeyValue { sensitive: true, ..KeyValue::new("x-private-session", secret) };
        let metadata = vec![marked, KeyValue::new("x-visible-meta", "shown-meta-value")];
        let mut c = grpc_ctx(&url, r#"{"message":"hi"}"#, metadata, ("unused_secret", "unused-secret-value"));
        c.spec.grpc.as_mut().unwrap().wire = wire;
        c.settings_layers.push(("run".into(), SettingsOverrides { http_version: Some(version), ..Default::default() }));

        let p = e.preview(&c).unwrap_or_else(|f| panic!("{label}: the preview failed: {}", f.message));
        assert!(!serde_json::to_string(&p).unwrap().contains(secret), "{label}: the preview holds the marked metadata value");
        let shown = |name: &str| value_of(&p.headers, name);
        assert_eq!(shown("x-private-session").as_deref(), Some(REDACTED), "{label}: the preview does not redact the marked metadata");
        assert_eq!(shown("x-visible-meta").as_deref(), Some("shown-meta-value"), "{label}: the preview does not keep ordinary metadata");

        let (o, events) = run_with_events(&e, &c).await;
        let sent = received_header(&f, "/anvil.lab.v1.Echo/Unary", "x-private-session");
        assert!(sent.as_deref() == Some(secret), "{label}: the marked metadata was not sent");
        assert_not_leaked(&label, &o, &events, secret);
        assert!(stream(&o).received_count > 0, "{label}: {:?}", o.record.attempts.last().and_then(|a| a.failure.as_ref()));
        let prepared = |name: &str| value_of(&o.record.prepared.headers, name);
        assert_eq!(prepared("x-private-session").as_deref(), Some(REDACTED), "{label}: the record does not redact the marked metadata");
        assert_eq!(prepared("x-visible-meta").as_deref(), Some("shown-meta-value"), "{label}: the record does not keep ordinary metadata");
    }
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
    // Events without an `id:` field keep the Last-Event-ID as their event id.
    let mut s = RequestSpec::http("GET", &f.url("/sse?count=1&interval=1&no_id=1"));
    s.protocol = Protocol::Sse;
    s.sse = Some(SseSpec { max_events: 1, idle_timeout_ms: 5_000, last_event_id: Some("{{sse_last_event_id}}".into()), reconnect: false });
    let c = with_secret(s, "sse_last_event_id", secret);
    let (o, events) = run_with_events(&e, &c).await;
    assert_eq!(received_header(&f, "/sse", "last-event-id").as_deref(), Some(secret), "the Last-Event-ID was not sent");
    assert!(stream(&o).received_count > 0, "{:?}", o.record.attempts.last().and_then(|a| a.failure.as_ref()));
    let ids: Vec<Option<&str>> = stream(&o).messages.iter().filter(|m| m.kind == "event").map(|m| m.event_id.as_deref()).collect();
    assert_eq!(ids, vec![Some(REDACTED)], "the event inherits the Last-Event-ID, redacted");
    assert_not_leaked("SSE Last-Event-ID", &o, &events, secret);
}

#[tokio::test]
async fn a_secret_websocket_binary_message_is_redacted_live_and_in_the_record() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    // Upper-case hex: the preview shows the bytes as lower-case hex.
    let secret = "DEADBEEF00C0FFEE11";
    let url = format!("ws://{}/ws?close_after=1", f.addr);
    let message = WsMessage::Binary { hex: "{{ws_binary_secret}}".into() };
    let c = with_secret(ws_spec_with(&url, vec![], message), "ws_binary_secret", secret);
    let (o, events) = run_with_events(&e, &c).await;
    assert_eq!(received_bytes(&f.log), 9, "the message was not sent");
    assert_eq!(previews(&o, Direction::Sent, "binary"), vec![(REDACTED, true)], "the sent message is kept, redacted");
    assert_eq!(previews(&o, Direction::Received, "binary"), vec![(REDACTED, true)], "the echo is redacted");
    assert_not_leaked("websocket binary message", &o, &events, secret);
    assert_not_leaked("websocket binary message (hex preview)", &o, &events, &secret.to_ascii_lowercase());
}

#[tokio::test]
async fn a_secret_in_a_raw_tcp_payload_is_redacted_live_and_in_the_record() {
    init();
    let f = streams::tcp("127.0.0.1:0", TcpMode::Echo, None).await.unwrap();
    let e = Engine::new();
    let secret = "tcp-text-secret-4f7w";
    let payloads = vec![StreamPayload { data: "token={{tcp_text_secret}}".into(), encoding: PayloadEncoding::Text }];
    let c = with_secret(tcp_spec(f.addr, payloads), "tcp_text_secret", secret);
    let (o, events) = run_with_events(&e, &c).await;
    let wire = format!("token={secret}\n");
    assert_eq!(received_bytes(&f.log), wire.len() as u64, "the payload was not sent");
    let redacted = format!("token={REDACTED}");
    assert_eq!(previews(&o, Direction::Sent, "frame"), vec![(redacted.as_str(), false)], "the sent payload is kept, redacted");
    assert_eq!(previews(&o, Direction::Received, "frame"), vec![(redacted.as_str(), false)], "the echo is redacted");
    assert_not_leaked("raw TCP payload", &o, &events, secret);
}

#[tokio::test]
async fn a_secret_in_a_base64_or_hex_tcp_payload_is_redacted_as_the_bytes_it_decodes_to() {
    init();
    let f = streams::tcp("127.0.0.1:0", TcpMode::Echo, None).await.unwrap();
    let e = Engine::new();
    // Sent, and shown as text, decoded.
    let text = "tcp-base64-secret-6c2x";
    let b64 = "dGNwLWJhc2U2NC1zZWNyZXQtNmMyeA==";
    // Not text: shown as lower-case hex. No 0x0a, which would end the frame.
    let hex = "00FF7E01A5C3D2E1F0";
    let payloads = vec![
        StreamPayload { data: "{{tcp_b64_secret}}".into(), encoding: PayloadEncoding::Base64 },
        StreamPayload { data: "{{tcp_hex_secret}}".into(), encoding: PayloadEncoding::Hex },
    ];
    let c = with_secrets(tcp_spec(f.addr, payloads), &[("tcp_b64_secret", b64), ("tcp_hex_secret", hex)]);
    let (o, events) = run_with_events(&e, &c).await;
    assert_eq!(received_bytes(&f.log), (text.len() + 1 + hex.len() / 2 + 1) as u64, "the payloads were not sent");
    let expected = vec![(REDACTED, false), (REDACTED, true)];
    assert_eq!(previews(&o, Direction::Sent, "frame"), expected, "the sent payloads are kept, redacted");
    assert_eq!(previews(&o, Direction::Received, "frame"), expected, "the echoes are redacted");
    for (label, value) in [("base64 template value", b64), ("decoded text", text), ("hex template value", hex)] {
        assert_not_leaked(label, &o, &events, value);
    }
    assert_not_leaked("decoded bytes as hex", &o, &events, &hex.to_ascii_lowercase());
}
