//! An explicit `Host` header is the authority a request names: `uri-host
//! [":" port]`. For every HTTP-based protocol (HTTP/1.1, HTTP/2 and HTTP/3
//! requests, a WebSocket handshake, an SSE stream and a gRPC call) a host
//! name, an IPv4 address and an IPv6 address in brackets, each with or
//! without a port, are sent as the `Host` or `:authority` the fixture
//! receives. A value with userinfo, a path, a query, a fragment or
//! whitespace, or an IPv6 address without brackets, is refused before
//! anything is sent, and so is one an auth profile would set.

use anvil_domain::Id;
use anvil_domain::auth::{AuthConfig, KeyLocation};
use anvil_domain::execution::*;
use anvil_domain::request::*;
use anvil_domain::secret::SensitiveValue;
use anvil_domain::settings::{HttpVersionPolicy, SettingsOverrides};
use anvil_domain::tls::{TlsMinVersion, TlsProfile};
use anvil_engine::context::MemoryAttachments;
use anvil_engine::{Engine, ExecutionContext, ExecutionOutput};
use anvil_fixtures::grpc::ECHO_PROTO;
use anvil_fixtures::http as fx;
use anvil_fixtures::{GroundTruth, GroundTruthLog, LabPki, TlsServerOptions, h3server};
use anvil_transport::recorder::EventCtx;
use bytes::Bytes;
use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use tokio_util::sync::CancellationToken;

const ACCEPTED: &[&str] =
    &["api.example.test", "api.example.test:8443", "192.0.2.10", "192.0.2.10:8080", "[2001:db8::1]", "[2001:db8::1]:8443"];

/// Refused values, with a word the error gives as the reason.
const REFUSED: &[(&str, &str)] = &[
    ("api.example.test/admin", "a path"),
    ("user@api.example.test", "userinfo"),
    ("api.example.test?x=1", "a query"),
    ("api.example.test#top", "a fragment"),
    ("api.example.test extra", "whitespace"),
    ("2001:db8::1", "brackets"),
];

fn init() {
    anvil_transport::init();
    anvil_fixtures::init();
}

fn pki() -> &'static LabPki {
    static P: OnceLock<LabPki> = OnceLock::new();
    P.get_or_init(LabPki::generate)
}

fn server_tls() -> TlsServerOptions {
    TlsServerOptions::new(pki().server.chain_with(&pki().ca), pki().server.key.clone())
}

/// `s` with the explicit `Host` and the HTTP version policy, if any.
fn with_host(mut s: RequestSpec, host: &str, version: Option<HttpVersionPolicy>) -> ExecutionContext {
    s.headers.push(KeyValue::new("Host", host));
    let mut c = ExecutionContext::standalone(s);
    c.settings_layers.push(("run".into(), SettingsOverrides { http_version: version, ..Default::default() }));
    c
}

/// Trust the lab root (the HTTP/3 fixture).
fn lab_trust(mut c: ExecutionContext) -> ExecutionContext {
    let p = TlsProfile {
        id: Id::new(),
        workspace_id: Id::new(),
        name: "lab".into(),
        verify: true,
        use_system_roots: false,
        extra_roots_pem: vec![pki().ca.cert.clone()],
        client_identity: None,
        bindings: vec![],
        min_version: TlsMinVersion::Tls12,
        server_name_override: None,
        server_spiffe: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    c.settings_layers.push(("trust".into(), SettingsOverrides { tls_profile_id: Some(p.id), ..Default::default() }));
    c.tls_profiles.push(p);
    c
}

fn ws(url: &str, host: &str) -> ExecutionContext {
    let mut s = RequestSpec::http("GET", url);
    s.protocol = Protocol::WebSocket;
    s.websocket = Some(WsSpec {
        bootstrap: WsBootstrap::Http1Upgrade,
        subprotocols: vec![],
        messages: vec![WsMessage::Text { text: "hello".into() }],
        expect_messages: 0,
        max_message_bytes: 1024 * 1024,
        idle_close_ms: 1_000,
        permessage_deflate: Default::default(),
    });
    with_host(s, host, None)
}

fn sse(url: &str, host: &str) -> ExecutionContext {
    let mut s = RequestSpec::http("GET", url);
    s.protocol = Protocol::Sse;
    s.sse = Some(SseSpec { max_events: 1, idle_timeout_ms: 5_000, last_event_id: None, reconnect: false });
    with_host(s, host, Some(HttpVersionPolicy::Http1Only))
}

/// A unary `Echo` call over h2c with the echo service's `.proto` as its schema.
fn grpc(url: &str, host: &str) -> ExecutionContext {
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
        messages: vec![r#"{"message":"hi"}"#.into()],
        metadata: vec![],
        deadline_ms: None,
        plaintext: false,
        wire: GrpcWire::Grpc,
    });
    let mut c = with_host(s, host, None);
    c.attachments = Arc::new(MemoryAttachments(HashMap::from([(sha, Bytes::from_static(ECHO_PROTO.as_bytes()))])));
    c
}

async fn run(e: &Engine, c: &ExecutionContext) -> ExecutionOutput {
    e.execute(c, EventCtx::none(), CancellationToken::new()).await
}

fn failure(o: &ExecutionOutput) -> Option<&TransportFailure> {
    o.record.attempts.last().and_then(|a| a.failure.as_ref())
}

/// The authority of the last request to `path` the fixture received: its
/// `:authority` (HTTP/2, HTTP/3), else its `Host` (HTTP/1.1).
fn received_authority(log: &GroundTruthLog, path: &str) -> String {
    let entries: Vec<GroundTruth> = log.entries().into_iter().map(|e| e.event).collect();
    let i = entries
        .iter()
        .rposition(|e| matches!(e, GroundTruth::RequestReceived { path: p, .. } if p.starts_with(path)))
        .unwrap_or_else(|| panic!("the fixture received no request to {path}"));
    let GroundTruth::RequestReceived { headers, .. } = &entries[i] else { unreachable!() };
    // The fixtures record a request's `:authority` just before the request itself.
    let authority = entries[..i].iter().rev().take_while(|e| !matches!(e, GroundTruth::RequestReceived { .. })).find_map(|e| match e {
        GroundTruth::AuthorityReceived { path: p, authority } if p.starts_with(path) => Some(authority.clone()),
        _ => None,
    });
    let host = headers.iter().find(|(n, _)| n.eq_ignore_ascii_case("host")).map(|(_, v)| v.clone());
    authority.or(host).expect("neither :authority nor Host received")
}

/// Every accepted `Host` is sent as the request's authority; every refused
/// one fails before anything is sent, naming the header and the reason.
async fn check(label: &str, e: &Engine, log: &GroundTruthLog, path: &str, request: impl Fn(&str) -> ExecutionContext) {
    for host in ACCEPTED {
        let o = run(e, &request(host)).await;
        assert!(o.record.response.is_some(), "{label}, Host {host}: no response: {:?}", failure(&o));
        assert_eq!(received_authority(log, path), *host, "{label}: the Host was not sent as the authority");
    }
    for (host, why) in REFUSED {
        let before = log.count_requests();
        let o = run(e, &request(host)).await;
        let f = failure(&o).unwrap_or_else(|| panic!("{label}: Host {host:?} was not refused"));
        assert_eq!((f.phase, f.kind), (Phase::Prepare, FailureKind::InvalidHeader), "{label}, Host {host:?}: {f:?}");
        assert_eq!(f.field.as_deref(), Some("headers[0].value"), "{label}, Host {host:?}");
        assert!(f.message.contains("Host header") && f.message.contains(why), "{label}, Host {host:?}: {}", f.message);
        assert!(o.record.response.is_none(), "{label}, Host {host:?}");
        assert_eq!(log.count_requests(), before, "{label}, Host {host:?}: a request reached the server");
    }
}

#[tokio::test]
async fn http1_and_http2_send_a_valid_host_and_refuse_one_that_is_not_an_authority() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    let url = f.url("/echo");
    let url = url.as_str();
    let http = |version: HttpVersionPolicy| move |host: &str| with_host(RequestSpec::http("GET", url), host, Some(version));
    check("HTTP/1.1", &e, &f.log, "/echo", http(HttpVersionPolicy::Http1Only)).await;
    check("HTTP/2 (h2c)", &e, &f.log, "/echo", http(HttpVersionPolicy::H2c)).await;
}

#[tokio::test]
async fn http3_sends_a_valid_host_and_refuses_one_that_is_not_an_authority() {
    init();
    let f = h3server::serve("127.0.0.1:0", server_tls()).await.unwrap();
    let e = Engine::new();
    let url = f.url("/echo");
    let request = |host: &str| lab_trust(with_host(RequestSpec::http("GET", &url), host, Some(HttpVersionPolicy::Http3Only)));
    check("HTTP/3", &e, &f.log, "/echo", request).await;
}

#[tokio::test]
async fn websocket_sends_a_valid_host_and_refuses_one_that_is_not_an_authority() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    let url = format!("ws://{}/ws?close_after=1", f.addr);
    check("WebSocket", &e, &f.log, "/ws", |host| ws(&url, host)).await;
}

#[tokio::test]
async fn sse_sends_a_valid_host_and_refuses_one_that_is_not_an_authority() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    let url = f.url("/sse?count=1&interval=1");
    check("SSE", &e, &f.log, "/sse", |host| sse(&url, host)).await;
}

#[tokio::test]
async fn grpc_sends_a_valid_host_and_refuses_one_that_is_not_an_authority() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    let url = format!("grpc://{}", f.addr);
    check("gRPC", &e, &f.log, "/anvil.lab.v1.Echo/Unary", |host| grpc(&url, host)).await;
}

#[tokio::test]
async fn a_host_an_auth_profile_would_set_is_refused_when_it_is_not_an_authority() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    let mut s = RequestSpec::http("GET", &f.url("/echo"));
    let host = SensitiveValue::template("gw.example.test/admin");
    s.auth = AuthConfig::ApiKey { name: "Host".into(), value: host, location: KeyLocation::Header };
    let o = run(&e, &ExecutionContext::standalone(s)).await;
    let fail = failure(&o).expect("a local failure");
    assert_eq!((fail.phase, fail.kind), (Phase::Prepare, FailureKind::InvalidHeader), "{fail:?}");
    assert!(fail.message.contains("Host header") && fail.message.contains("a path"), "{}", fail.message);
    assert_eq!(f.log.count_requests(), 0, "a request reached the server");
}
