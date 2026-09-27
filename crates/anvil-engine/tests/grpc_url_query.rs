//! A gRPC call is sent to `/<service>/<method>` under the URL's path, with
//! no query. A gRPC URL with a query (or query parameters) is refused before
//! anything is sent, by an automated call, an interactive session and the
//! effective-request preview alike, rather than signed with a query that is
//! never sent.

use anvil_domain::execution::{FailureKind, Phase, TransportFailure};
use anvil_domain::request::*;
use anvil_engine::context::MemoryAttachments;
use anvil_engine::{Engine, ExecutionContext, ExecutionOutput};
use anvil_fixtures::grpc::ECHO_PROTO;
use anvil_fixtures::http as fx;
use anvil_transport::recorder::EventCtx;
use bytes::Bytes;
use std::collections::HashMap;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

fn init() {
    anvil_transport::init();
    anvil_fixtures::init();
}

/// An `Echo` call with the echo service's `.proto` as its schema.
fn grpc(url: &str, method: &str, mode: GrpcMode) -> ExecutionContext {
    let sha = anvil_transport::certs::sha256_hex(ECHO_PROTO.as_bytes());
    let file =
        AttachmentRef::Stored { sha256: sha.clone(), size: ECHO_PROTO.len() as u64, file_name: "echo.proto".into(), media_type: None };
    let mut s = RequestSpec::http("POST", url);
    s.protocol = Protocol::Grpc;
    s.grpc = Some(GrpcSpec {
        service: "anvil.lab.v1.Echo".into(),
        method: method.into(),
        mode,
        schema: GrpcSchemaSource::ProtoFiles { files: vec![file] },
        messages: vec![r#"{"message":"hi"}"#.into()],
        metadata: vec![],
        deadline_ms: None,
        plaintext: false,
        wire: GrpcWire::Grpc,
    });
    let mut c = ExecutionContext::standalone(s);
    c.attachments = Arc::new(MemoryAttachments(HashMap::from([(sha, Bytes::from_static(ECHO_PROTO.as_bytes()))])));
    c
}

fn failure(o: &ExecutionOutput) -> &TransportFailure {
    o.record.attempts.last().and_then(|a| a.failure.as_ref()).expect("a local failure")
}

fn assert_query_refused(label: &str, f: &TransportFailure) {
    assert_eq!((f.phase, f.kind), (Phase::Prepare, FailureKind::UnsupportedCombination), "{label}: {f:?}");
    assert_eq!(f.field.as_deref(), Some("url"), "{label}");
    assert!(f.message.contains("gRPC URL cannot have a query") && f.message.contains("never sent"), "{label}: {}", f.message);
}

#[tokio::test]
async fn a_grpc_url_with_a_query_is_refused_and_nothing_reaches_the_server() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    let url = format!("grpc://{}/?tenant=a", f.addr);
    let o = e.execute(&grpc(&url, "Unary", GrpcMode::Unary), EventCtx::none(), CancellationToken::new()).await;
    assert_query_refused("a URL query", failure(&o));
    assert!(o.record.response.is_none());

    // Query parameters join the URL's query: refused the same way.
    let mut c = grpc(&format!("grpc://{}", f.addr), "Unary", GrpcMode::Unary);
    c.spec.params.push(KeyValue::new("tenant", "a"));
    let o = e.execute(&c, EventCtx::none(), CancellationToken::new()).await;
    assert_query_refused("query parameters", failure(&o));

    // An interactive session, too.
    let h = e.open_session(grpc(&url, "Bidi", GrpcMode::Bidirectional), EventCtx::none()).await;
    assert_query_refused("an interactive session", failure(&h.finish().await));

    assert_eq!(f.log.count_requests(), 0, "a request reached the server: {:?}", f.log.requests());
    assert!(!f.log.saw_connection(), "a connection was opened");

    // Without the query the same call is sent.
    let o = e.execute(&grpc(&format!("grpc://{}/", f.addr), "Unary", GrpcMode::Unary), EventCtx::none(), CancellationToken::new()).await;
    assert!(o.record.response.is_some(), "{:?}", o.record.attempts.last().and_then(|a| a.failure.as_ref()));
    assert!(f.log.requests().iter().any(|(_, p)| p == "/anvil.lab.v1.Echo/Unary"), "{:?}", f.log.requests());
}

#[tokio::test]
async fn the_preview_refuses_a_grpc_url_with_a_query() {
    init();
    let e = Engine::new();
    let err = e.preview(&grpc("grpc://127.0.0.1:50051/prefix?tenant=a", "Unary", GrpcMode::Unary)).err().expect("the preview is refused");
    assert_query_refused("preview", &err);
}
