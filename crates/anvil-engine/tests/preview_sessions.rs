//! The effective-request preview of a session protocol shows the handshake
//! or call its session transport sends: a WebSocket (HTTP/1.1 upgrade and
//! HTTP/2 extended CONNECT), an SSE stream and a gRPC or gRPC-Web call. Each
//! case previews a request with HMAC auth and an explicit `Host`, sends it,
//! and compares the preview with what the fixture received: the method, the
//! request-target, the `Host` / `:authority`, every header whose value does
//! not change per send, and the HMAC signature, which must verify over the
//! preview's method, target and authority. A DPoP proof in the preview is
//! bound to the same method and URL as the one sent. `ws`, `wss`, `grpc` and
//! `grpcs` URLs are previewed, and raw TCP and UDP say they are not. A gRPC
//! call's message is shown as redacted JSON, never as the framed or base64
//! bytes sent, and auth the session refuses is shown as a request that would
//! not be sent, for the reason the session gives.

use anvil_auth::hmac_sig;
use anvil_domain::auth::{AuthConfig, DpopConfig, HmacAlgorithm, HmacConfig, HmacProfile, KeyLocation, WsseConfig, WssePasswordType};
use anvil_domain::execution::{FailureKind, Phase, TransportFailure};
use anvil_domain::request::*;
use anvil_domain::secret::{REDACTED, SensitiveValue};
use anvil_domain::settings::{HttpVersionPolicy, SettingsOverrides};
use anvil_engine::context::MemoryAttachments;
use anvil_engine::preview::EffectiveRequest;
use anvil_engine::vars::{VarEntry, VarLayer};
use anvil_engine::{Engine, ExecutionContext, ExecutionOutput};
use anvil_fixtures::grpc::ECHO_PROTO;
use anvil_fixtures::http as fx;
use anvil_fixtures::{GroundTruth, GroundTruthLog};
use anvil_transport::recorder::EventCtx;
use base64::Engine as _;
use bytes::Bytes;
use std::collections::HashMap;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

/// The explicit `Host`: not the URL's authority (the fixtures listen on
/// 127.0.0.1 with an ephemeral port).
const HOST: &str = "api.example.test:8443";
const USERNAME: &str = "preview-session-client";
const SECRET: &str = "audit-only-hmac-secret-8r3n";
const GRPC_PATH: &str = "/anvil.lab.v1.Echo/Unary";

/// Headers whose value changes on every send (or is redacted in the
/// preview), compared by name only. The `Host` is compared as the authority:
/// over HTTP/2 it is sent as `:authority`.
const PER_SEND: &[&str] = &["authorization", "date", "dpop", "sec-websocket-key", "host"];

fn init() {
    anvil_transport::init();
    anvil_fixtures::init();
}

fn hmac() -> AuthConfig {
    AuthConfig::Hmac {
        config: HmacConfig {
            profile: HmacProfile::FerrumV2,
            username: USERNAME.into(),
            secret: SensitiveValue::template(SECRET),
            algorithm: HmacAlgorithm::HmacSha256,
            digest_header: Default::default(),
            namespace: String::new(),
            allow_unsafe_legacy: false,
        },
    }
}

fn dpop() -> AuthConfig {
    AuthConfig::Dpop {
        config: DpopConfig {
            access_token: SensitiveValue::template("audit-only-dpop-token-5t8c"),
            private_key_pem: SensitiveValue::template(anvil_auth::dpop::generate_key_pem().unwrap()),
            dpop_scheme: true,
            handle_nonce_challenge: true,
        },
    }
}

/// `s` with the explicit `Host`, `auth` and the HTTP version policy, if any.
/// The context takes its auth layer from the spec when it is built, so the
/// auth is set before.
fn with_auth(mut s: RequestSpec, version: Option<HttpVersionPolicy>, auth: AuthConfig) -> ExecutionContext {
    s.headers.push(KeyValue::new("Host", HOST));
    s.auth = auth;
    let mut c = ExecutionContext::standalone(s);
    c.settings_layers.push(("run".into(), SettingsOverrides { http_version: version, ..Default::default() }));
    c
}

fn ws_spec(url: &str, bootstrap: WsBootstrap) -> RequestSpec {
    let mut s = RequestSpec::http("GET", url);
    s.protocol = Protocol::WebSocket;
    s.websocket = Some(WsSpec {
        bootstrap,
        subprotocols: vec![],
        messages: vec![WsMessage::Text { text: "hello".into() }],
        expect_messages: 0,
        max_message_bytes: 1024 * 1024,
        idle_close_ms: 1_000,
        permessage_deflate: Default::default(),
    });
    s
}

fn sse(url: &str, version: HttpVersionPolicy) -> ExecutionContext {
    sse_with(url, version, hmac())
}

fn sse_with(url: &str, version: HttpVersionPolicy, auth: AuthConfig) -> ExecutionContext {
    let mut s = RequestSpec::http("GET", url);
    s.protocol = Protocol::Sse;
    s.sse = Some(SseSpec { max_events: 1, idle_timeout_ms: 5_000, last_event_id: None, reconnect: false });
    with_auth(s, Some(version), auth)
}

/// A unary `Echo` call with the echo service's `.proto` as its schema.
fn grpc(url: &str, wire: GrpcWire, version: HttpVersionPolicy, auth: AuthConfig) -> ExecutionContext {
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
        metadata: vec![KeyValue::new("x-preview-meta", "shown")],
        deadline_ms: Some(5_000),
        plaintext: false,
        wire,
    });
    let mut c = with_auth(s, Some(version), auth);
    c.attachments = Arc::new(MemoryAttachments(HashMap::from([(sha, Bytes::from_static(ECHO_PROTO.as_bytes()))])));
    c
}

async fn run(e: &Engine, c: &ExecutionContext) -> ExecutionOutput {
    e.execute(c, EventCtx::none(), CancellationToken::new()).await
}

fn header<'a>(h: &'a [(String, String)], name: &str) -> Option<&'a str> {
    h.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
}

/// The value of `key="…"` in an HMAC `Authorization` header.
fn auth_param<'a>(authorization: &'a str, key: &str) -> &'a str {
    let start = authorization.find(&format!("{key}=\"")).unwrap_or_else(|| panic!("no {key} in {authorization}")) + key.len() + 2;
    let len = authorization[start..].find('"').expect("unterminated auth-param");
    &authorization[start..start + len]
}

/// The request-target (path and query) of an absolute URL.
fn request_target(url: &str) -> &str {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    rest.find('/').map(|i| &rest[i..]).unwrap_or("/")
}

/// What the fixture received for the last request whose target starts with
/// `path`: its method, target, headers and authority (`:authority`, else
/// `Host`).
struct Received {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
    authority: String,
}

fn received(log: &GroundTruthLog, path: &str) -> Received {
    let entries: Vec<GroundTruth> = log.entries().into_iter().map(|e| e.event).collect();
    let i = entries
        .iter()
        .rposition(|e| matches!(e, GroundTruth::RequestReceived { path: p, .. } if p.starts_with(path)))
        .unwrap_or_else(|| panic!("the fixture received no request to {path}"));
    let GroundTruth::RequestReceived { method, path: target, headers, .. } = entries[i].clone() else { unreachable!() };
    // The fixtures record a request's `:authority` just before the request
    // itself; an HTTP/1.1 request records none.
    let authority = entries[..i].iter().rev().take_while(|e| !matches!(e, GroundTruth::RequestReceived { .. })).find_map(|e| match e {
        GroundTruth::AuthorityReceived { path: p, authority } if p.starts_with(path) => Some(authority.clone()),
        _ => None,
    });
    let authority = match authority {
        Some(a) => a,
        None => header(&headers, "host").expect("neither :authority nor Host received").to_string(),
    };
    Received { method, target, headers, authority }
}

/// Preview `c`, check that it would be sent, send it and return the preview
/// and what the fixture received for `path`.
async fn preview_and_send(label: &str, e: &Engine, c: &ExecutionContext, log: &GroundTruthLog, path: &str) -> (EffectiveRequest, Received) {
    let p = e.preview(c).unwrap_or_else(|f| panic!("{label}: the preview failed: {f:?}"));
    assert!(!p.inferred.iter().any(|i| i.starts_with("the request would not be sent")), "{label}: {:?}", p.inferred);
    let o = run(e, c).await;
    let failure = o.record.attempts.last().and_then(|a| a.failure.as_ref());
    assert!(o.record.response.is_some(), "{label}: no response: {failure:?}");
    (p, received(log, path))
}

/// Compare the preview with what the fixture received, and verify the HMAC
/// signature received over the preview's method, target and authority.
fn assert_preview_sent(label: &str, p: &EffectiveRequest, r: &Received) {
    assert_eq!(p.method, r.method, "{label}: the preview's method differs from the one sent");
    assert_eq!(request_target(&p.url), r.target, "{label}: the preview's request-target differs from the one sent ({})", p.url);
    assert_eq!(p.authority, HOST, "{label}: the preview's authority is not the explicit Host");
    assert_eq!(p.authority, r.authority, "{label}: the preview's authority differs from the one sent");
    for h in &p.headers {
        let name = h.name.to_ascii_lowercase();
        let sent = header(&r.headers, &name);
        assert!(sent.is_some(), "{label}: the preview shows {name}, which was not sent: {:?}", r.headers);
        if !PER_SEND.contains(&name.as_str()) {
            assert_eq!(Some(h.value.as_str()), sent, "{label}: the preview's {name} differs from the one sent");
        }
    }
    let authorization = header(&r.headers, "authorization").unwrap_or_else(|| panic!("{label}: no Authorization received"));
    let (raw_path, raw_query) = request_target(&p.url).split_once('?').unwrap_or((request_target(&p.url), ""));
    let ss = hmac_sig::signing_string(
        HmacProfile::FerrumV2,
        "ferrum",
        USERNAME,
        &p.authority,
        &p.method,
        raw_path,
        raw_query,
        header(&r.headers, "date").unwrap_or_else(|| panic!("{label}: no Date received")),
        header(&r.headers, "content-digest").unwrap_or_else(|| panic!("{label}: no Content-Digest received")),
        Some(auth_param(authorization, "nonce")),
    );
    let mac = hmac_sig::mac(HmacAlgorithm::HmacSha256, SECRET.as_bytes(), ss.as_bytes());
    assert_eq!(
        auth_param(authorization, "signature"),
        base64::engine::general_purpose::STANDARD.encode(mac),
        "{label}: the signature sent does not cover the preview's {} {} for {}",
        p.method,
        p.url,
        p.authority
    );
    let json = serde_json::to_string(p).unwrap();
    assert!(!json.contains(SECRET), "{label}: the preview holds the secret: {json}");
}

/// The claims of the DPoP proof in `headers`.
fn dpop_claims(headers: &[(String, String)]) -> serde_json::Value {
    let proof = header(headers, "dpop").unwrap_or_else(|| panic!("no DPoP proof received: {headers:?}"));
    let payload = proof.split('.').nth(1).expect("the DPoP proof is not a JWT");
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload).expect("the DPoP payload is not base64url");
    serde_json::from_slice(&payload).expect("the DPoP payload is not JSON")
}

/// The `htu` the preview's DPoP proof is bound to.
fn preview_htu(p: &EffectiveRequest) -> &str {
    p.inferred.iter().find_map(|i| i.strip_prefix("auth dpop.htu: ")).unwrap_or_else(|| panic!("no DPoP htu: {:?}", p.inferred))
}

#[tokio::test]
async fn websocket_preview_is_the_http1_upgrade_and_the_http2_extended_connect_sent() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    let url = format!("ws://{}/ws?close_after=1", f.addr);

    let c = with_auth(ws_spec(&url, WsBootstrap::Http1Upgrade), None, hmac());
    let (p, r) = preview_and_send("ws over HTTP/1.1", &e, &c, &f.log, "/ws").await;
    assert_eq!(p.method, "GET");
    assert_eq!(p.url, url, "a ws:// URL is previewed as it is sent");
    assert_eq!(p.destination, f.addr.to_string());
    assert_eq!(p.body_bytes, 0);
    for (name, value) in [("upgrade", "websocket"), ("connection", "Upgrade"), ("sec-websocket-version", "13")] {
        assert!(p.headers.iter().any(|h| h.name.eq_ignore_ascii_case(name) && h.value == value), "no {name}: {:?}", p.headers);
    }
    assert!(p.headers.iter().any(|h| h.name.eq_ignore_ascii_case("sec-websocket-key")), "{:?}", p.headers);
    assert_preview_sent("ws over HTTP/1.1", &p, &r);

    let c = with_auth(ws_spec(&url, WsBootstrap::Http2ExtendedConnect), None, hmac());
    let (p, r) = preview_and_send("ws over HTTP/2", &e, &c, &f.log, "/ws").await;
    assert_eq!(p.method, "CONNECT", "RFC 8441: the wire method, which the signature covers");
    assert_eq!(p.url, url);
    for name in ["host", "upgrade", "connection", "sec-websocket-key"] {
        assert!(!p.headers.iter().any(|h| h.name.eq_ignore_ascii_case(name)), "{name} is not sent over HTTP/2: {:?}", p.headers);
    }
    assert_preview_sent("ws over HTTP/2", &p, &r);
}

#[tokio::test]
async fn websocket_preview_binds_the_dpop_proof_as_sent_over_http2() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    let url = format!("ws://{}/ws?close_after=1", f.addr);
    let c = with_auth(ws_spec(&url, WsBootstrap::Http2ExtendedConnect), None, dpop());
    let p = e.preview(&c).unwrap();
    assert_eq!(p.method, "CONNECT");
    assert_eq!(preview_htu(&p), format!("http://{HOST}/ws"), "the proof is bound to the http counterpart of the ws URL and the Host");

    let o = run(&e, &c).await;
    assert!(o.record.response.is_some(), "{:?}", o.record.attempts.last().and_then(|a| a.failure.as_ref()));
    let claims = dpop_claims(&received(&f.log, "/ws").headers);
    assert_eq!(claims["htm"], p.method.as_str(), "the proof sent is bound to the preview's method");
    assert_eq!(claims["htu"], preview_htu(&p), "the proof sent is bound to the preview's URL");
}

#[tokio::test]
async fn websocket_urls_are_previewed_not_refused() {
    init();
    let e = Engine::new();
    let p = e.preview(&ExecutionContext::standalone(ws_spec("wss://ws.example.test/feed", WsBootstrap::Http1Upgrade))).unwrap();
    assert_eq!(p.url, "wss://ws.example.test/feed");
    assert_eq!(p.destination, "ws.example.test:443");
    assert_eq!(p.authority, "ws.example.test");

    // A URL without a scheme is a WebSocket URL, as the session sends it.
    let p = e.preview(&ExecutionContext::standalone(ws_spec("ws.example.test/feed", WsBootstrap::Http1Upgrade))).unwrap();
    assert!(p.url.starts_with("wss://"), "{}", p.url);
    assert!(p.inferred.iter().any(|i| i == "no scheme given; using wss://"), "{:?}", p.inferred);
}

#[tokio::test]
async fn sse_preview_is_the_request_sent_over_http1_and_http2() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    for (label, version) in [("sse over HTTP/1.1", HttpVersionPolicy::Http1Only), ("sse over HTTP/2", HttpVersionPolicy::H2c)] {
        let c = sse(&f.url("/sse?count=1&interval=1"), version);
        let (p, r) = preview_and_send(label, &e, &c, &f.log, "/sse").await;
        assert_eq!(p.method, "GET");
        for (name, value) in [("accept", "text/event-stream"), ("accept-encoding", "identity"), ("cache-control", "no-cache")] {
            assert!(p.headers.iter().any(|h| h.name.eq_ignore_ascii_case(name) && h.value == value), "{label}: no {name}: {:?}", p.headers);
        }
        assert_preview_sent(label, &p, &r);
    }
}

#[tokio::test]
async fn grpc_preview_is_the_call_sent_over_h2c_and_grpc_web_over_http1() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();

    let c = grpc(&format!("grpc://{}", f.addr), GrpcWire::Grpc, HttpVersionPolicy::Auto, hmac());
    let (p, r) = preview_and_send("gRPC over h2c", &e, &c, &f.log, GRPC_PATH).await;
    assert_eq!(p.method, "POST");
    assert_eq!(p.url, format!("grpc://{}{GRPC_PATH}", f.addr), "a grpc:// URL is previewed with the call's path");
    assert_eq!(p.content_type.as_deref(), Some("application/grpc"));
    assert!(p.body_bytes > 5, "the framed request message: {}", p.body_bytes);
    let expected = [("content-type", "application/grpc"), ("te", "trailers"), ("x-preview-meta", "shown"), ("grpc-timeout", "5000m")];
    for (name, value) in expected {
        assert!(p.headers.iter().any(|h| h.name.eq_ignore_ascii_case(name) && h.value == value), "no {name}: {:?}", p.headers);
    }
    // Content-Digest covers the framed message: the same one as sent.
    assert!(p.headers.iter().any(|h| h.name.eq_ignore_ascii_case("content-digest")), "{:?}", p.headers);
    assert_preview_sent("gRPC over h2c", &p, &r);

    let c = grpc(&f.url(""), GrpcWire::GrpcWeb, HttpVersionPolicy::Http1Only, hmac());
    let (p, r) = preview_and_send("gRPC-Web over HTTP/1.1", &e, &c, &f.log, GRPC_PATH).await;
    assert_eq!(p.method, "POST");
    assert_eq!(p.url, format!("http://{}{GRPC_PATH}", f.addr), "gRPC-Web is previewed with the call's path");
    assert_eq!(p.content_type.as_deref(), Some(anvil_transport::grpc_web::CT_BINARY));
    assert!(p.headers.iter().any(|h| h.name.eq_ignore_ascii_case("x-grpc-web") && h.value == "1"), "{:?}", p.headers);
    assert!(p.headers.iter().any(|h| h.name.eq_ignore_ascii_case("host") && h.value == HOST), "{:?}", p.headers);
    assert_preview_sent("gRPC-Web over HTTP/1.1", &p, &r);
}

#[tokio::test]
async fn grpc_preview_binds_the_dpop_proof_to_the_call_sent() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    let c = grpc(&format!("grpc://{}", f.addr), GrpcWire::Grpc, HttpVersionPolicy::Auto, dpop());
    let p = e.preview(&c).unwrap();
    assert_eq!(preview_htu(&p), format!("http://{HOST}{GRPC_PATH}"), "the proof is bound to the call's path and the Host");

    let o = run(&e, &c).await;
    assert!(o.record.response.is_some(), "{:?}", o.record.attempts.last().and_then(|a| a.failure.as_ref()));
    let claims = dpop_claims(&received(&f.log, GRPC_PATH).headers);
    assert_eq!(claims["htm"], p.method.as_str());
    assert_eq!(claims["htu"], preview_htu(&p));
}

#[tokio::test]
async fn raw_tcp_and_udp_say_the_preview_is_not_supported() {
    init();
    let e = Engine::new();
    for (protocol, url, name) in [(Protocol::Tcp, "tcp://127.0.0.1:9", "raw TCP"), (Protocol::Udp, "udp://127.0.0.1:9", "UDP")] {
        let mut s = RequestSpec::http("GET", url);
        s.protocol = protocol;
        let f = e.preview(&ExecutionContext::standalone(s)).expect_err("a raw session has no request to preview");
        assert_eq!(f.kind, FailureKind::UnsupportedCombination);
        assert!(f.message.starts_with(&format!("preview not supported for {name}")), "{}", f.message);
    }
}

/// A schema whose request message has a `password` field.
const ACCOUNTS_PROTO: &str = r#"syntax = "proto3";
package preview.v1;
message Login { string user = 1; string password = 2; string note = 3; }
service Accounts { rpc Login(Login) returns (Login); }
"#;
/// The value of a secret variable the message uses.
const PLANTED: &str = "planted-grpc-secret-7q2w9e";
/// A password written into the message itself.
const LITERAL_PASSWORD: &str = "literal-grpc-password-4k8d";

/// A unary `Login` call whose message holds a password and a secret variable.
fn grpc_login(url: &str, wire: GrpcWire, version: HttpVersionPolicy) -> ExecutionContext {
    let sha = anvil_transport::certs::sha256_hex(ACCOUNTS_PROTO.as_bytes());
    let file = AttachmentRef::Stored {
        sha256: sha.clone(),
        size: ACCOUNTS_PROTO.len() as u64,
        file_name: "accounts.proto".into(),
        media_type: None,
    };
    let mut s = RequestSpec::http("POST", url);
    s.protocol = Protocol::Grpc;
    s.grpc = Some(GrpcSpec {
        service: "preview.v1.Accounts".into(),
        method: "Login".into(),
        mode: GrpcMode::Unary,
        schema: GrpcSchemaSource::ProtoFiles { files: vec![file] },
        messages: vec![format!(r#"{{"user":"preview-user","password":"{LITERAL_PASSWORD}","note":"{{{{planted}}}}"}}"#)],
        metadata: vec![],
        deadline_ms: None,
        plaintext: false,
        wire,
    });
    let mut c = ExecutionContext::standalone(s);
    c.settings_layers.push(("run".into(), SettingsOverrides { http_version: Some(version), ..Default::default() }));
    let planted = VarEntry { name: "planted".into(), value: PLANTED.into(), secret: true };
    c.var_layers = vec![VarLayer { label: "environment:lab".into(), vars: vec![planted] }];
    c.attachments = Arc::new(MemoryAttachments(HashMap::from([(sha, Bytes::from_static(ACCOUNTS_PROTO.as_bytes()))])));
    c
}

/// The base64 runs that encode `s` wherever it falls in a longer base64
/// text: the groups wholly within it, for each of the three alignments.
fn base64_runs(s: &str) -> Vec<String> {
    (0..3)
        .map(|k| {
            let mut bytes = vec![0u8; k];
            bytes.extend_from_slice(s.as_bytes());
            let enc = base64::engine::general_purpose::STANDARD.encode(&bytes);
            let skip = if k == 0 { 0 } else { 4 };
            enc[skip..enc.len() - 4].to_string()
        })
        .collect()
}

#[tokio::test]
async fn grpc_preview_shows_the_message_as_redacted_json_never_the_framed_or_base64_bytes() {
    init();
    let e = Engine::new();
    let cases = [
        ("gRPC", "grpc://grpc.example.test:50051", GrpcWire::Grpc, HttpVersionPolicy::Auto),
        ("gRPC-Web", "http://grpc.example.test:8080", GrpcWire::GrpcWeb, HttpVersionPolicy::Http1Only),
        ("gRPC-Web text", "http://grpc.example.test:8080", GrpcWire::GrpcWebText, HttpVersionPolicy::Http1Only),
    ];
    for (label, url, wire, version) in cases {
        let p = e.preview(&grpc_login(url, wire, version)).unwrap_or_else(|f| panic!("{label}: the preview failed: {f:?}"));
        let json = serde_json::to_string(&p).unwrap();
        for secret in [PLANTED, LITERAL_PASSWORD] {
            assert!(!json.contains(secret), "{label}: the preview holds {secret}: {json}");
            for run in base64_runs(secret) {
                assert!(!json.contains(&run), "{label}: the preview holds {secret} in base64 ({run}): {json}");
            }
        }
        let message: serde_json::Value = serde_json::from_str(&p.body_preview).unwrap_or_else(|err| panic!("{label}: {err}"));
        assert_eq!(message["user"], "preview-user", "{label}: {}", p.body_preview);
        assert_eq!(message["password"], REDACTED, "{label}: the password field is not redacted: {}", p.body_preview);
        assert_eq!(message["note"], REDACTED, "{label}: the secret variable is not redacted: {}", p.body_preview);
        // The size is still that of the framed message sent.
        assert!(p.body_bytes > 5, "{label}: {}", p.body_bytes);
        let note = format!("it is sent as {} framed bytes", p.body_bytes);
        assert!(p.inferred.iter().any(|i| i.contains(&note)), "{label}: no '{note}': {:?}", p.inferred);
    }
}

/// With server reflection the session encodes the message, and signs the
/// call over it, once the schema is resolved: the preview shows the message
/// as JSON and says that a digest or signature it shows covers an empty body.
#[tokio::test]
async fn grpc_preview_with_server_reflection_shows_the_message_signed_when_the_call_is_sent() {
    init();
    let e = Engine::new();
    for (label, auth) in [("HMAC", hmac()), ("no auth", AuthConfig::None)] {
        let mut c = grpc("grpc://grpc.example.test:50051", GrpcWire::Grpc, HttpVersionPolicy::Auto, auth);
        c.spec.grpc.as_mut().unwrap().schema = GrpcSchemaSource::Reflection;
        let p = e.preview(&c).unwrap_or_else(|f| panic!("{label}: the preview failed: {f:?}"));
        let message: serde_json::Value = serde_json::from_str(&p.body_preview).unwrap_or_else(|err| panic!("{label}: {err}"));
        assert_eq!(message, serde_json::json!({"message": "hi"}), "{label}: the message is not shown");
        assert_eq!(p.body_bytes, 0, "{label}: nothing is encoded before the schema is resolved");
        let note = p.inferred.iter().find(|i| i.starts_with("server reflection:")).unwrap_or_else(|| panic!("{label}: {:?}", p.inferred));
        assert!(note.contains("encoded, and its size known, once the schema is resolved"), "{label}: {note}");
        let signs = note.contains("auth signs the call then, over the framed message sent");
        assert_eq!(signs && note.contains("computed over an empty body"), label == "HMAC", "{label}: {note}");
    }
}

/// The failure the session gives, before anything is sent, for `c`.
async fn session_refusal(e: &Engine, c: &ExecutionContext) -> TransportFailure {
    let o = run(e, c).await;
    let f = o.record.attempts.last().and_then(|a| a.failure.clone()).expect("the session was not refused");
    assert_eq!(f.phase, Phase::Prepare, "{f:?}");
    f
}

/// The reason the preview gives for a request that would not be sent.
fn not_sent(p: &EffectiveRequest) -> &str {
    p.inferred
        .iter()
        .find_map(|i| i.strip_prefix("the request would not be sent: "))
        .unwrap_or_else(|| panic!("the preview does not say the request would not be sent: {:?}", p.inferred))
}

fn wsse() -> AuthConfig {
    AuthConfig::Wsse {
        config: WsseConfig {
            username: "preview-client".into(),
            password: SensitiveValue::template("audit-only-wsse-password-2v6n"),
            password_type: WssePasswordType::PasswordText,
            timestamp_ttl_secs: None,
            saml_assertion: None,
        },
    }
}

#[tokio::test]
async fn ws_security_on_a_session_is_shown_as_not_sent_for_the_session_s_reason() {
    init();
    let e = Engine::new();
    // An event stream carries the request's SOAP body, which WS-Security rewrites.
    let mut s = RequestSpec::http("POST", "http://127.0.0.1:9/events");
    s.protocol = Protocol::Sse;
    s.body = Body::Soap {
        version: SoapVersion::Soap11,
        envelope: r#"<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body/></soap:Envelope>"#.into(),
        action: None,
    };
    s.auth = wsse();
    let c = ExecutionContext::standalone(s);
    let p = e.preview(&c).unwrap();
    let why = not_sent(&p);
    assert!(why.contains("rewrites the message body"), "{why}");
    let f = session_refusal(&e, &c).await;
    assert_eq!((f.kind, f.message.as_str()), (FailureKind::UnsupportedCombination, why));

    // A WebSocket handshake has no body for WS-Security to rewrite: the
    // session refuses the auth, and the preview says why.
    let mut s = ws_spec("ws://127.0.0.1:9/ws", WsBootstrap::Http1Upgrade);
    s.auth = wsse();
    let c = ExecutionContext::standalone(s);
    let p = e.preview(&c).unwrap();
    let why = not_sent(&p);
    let f = session_refusal(&e, &c).await;
    assert_eq!(f.message, why, "the preview's reason differs from the session's");
    let json = serde_json::to_string(&p).unwrap();
    assert!(!json.contains("audit-only-wsse-password-2v6n"), "the preview holds the password: {json}");
}

#[tokio::test]
async fn an_api_key_in_the_query_of_a_grpc_call_is_shown_as_not_sent() {
    init();
    let e = Engine::new();
    let key = AuthConfig::ApiKey {
        name: "api_key".into(),
        value: SensitiveValue::template("audit-only-query-key-6h3j"),
        location: KeyLocation::Query,
    };
    let c = grpc("grpc://127.0.0.1:9", GrpcWire::Grpc, HttpVersionPolicy::Auto, key);
    let p = e.preview(&c).unwrap();
    let why = not_sent(&p);
    assert!(why.contains("adds query parameters"), "{why}");
    assert_eq!(p.url, format!("grpc://127.0.0.1:9{GRPC_PATH}"), "no query is added to the call's path");
    let f = session_refusal(&e, &c).await;
    assert_eq!((f.kind, f.message.as_str()), (FailureKind::UnsupportedCombination, why));
    let json = serde_json::to_string(&p).unwrap();
    assert!(!json.contains("audit-only-query-key-6h3j"), "the preview holds the key: {json}");
}

#[tokio::test]
async fn sse_over_tls_says_the_authority_follows_the_negotiated_version() {
    init();
    let e = Engine::new();
    let mut s = RequestSpec::http("GET", "https://sse.example.test/events");
    s.protocol = Protocol::Sse;
    let p = e.preview(&ExecutionContext::standalone(s)).unwrap();
    assert!(
        p.inferred.iter().any(|i| i.starts_with("the stream is opened over HTTP/2 or HTTP/1.1, as ALPN negotiates")),
        "{:?}",
        p.inferred
    );
    assert!(!p.headers.iter().any(|h| h.name.eq_ignore_ascii_case("host")), "{:?}", p.headers);
}

/// An event stream signs each send afresh: with auth, the preview says the
/// signature it shows is not the one sent, as it does for server reflection.
#[tokio::test]
async fn sse_preview_says_each_send_is_signed_again() {
    init();
    let e = Engine::new();
    let note = "each send (initial, TCP fallback, each reconnection) is signed again when it is sent, not with the signature shown";
    let p = e.preview(&sse("https://sse.example.test/events", HttpVersionPolicy::Http3WithFallback)).unwrap();
    assert!(p.inferred.iter().any(|i| i == note), "{:?}", p.inferred);

    let mut s = RequestSpec::http("GET", "https://sse.example.test/events");
    s.protocol = Protocol::Sse;
    let p = e.preview(&ExecutionContext::standalone(s)).unwrap();
    assert!(!p.inferred.iter().any(|i| i == note), "no auth, nothing is signed: {:?}", p.inferred);
}

/// A multi-auth is signed again when any of its profiles is: HMAC beside an
/// API key gets the note, a bearer token beside an API key does not.
#[tokio::test]
async fn sse_preview_says_a_multi_auth_with_hmac_is_signed_again() {
    init();
    let e = Engine::new();
    let note = "each send (initial, TCP fallback, each reconnection) is signed again when it is sent, not with the signature shown";
    let key = AuthConfig::ApiKey {
        name: "X-Api-Key".into(),
        value: SensitiveValue::template("audit-only-api-key-1w5z"),
        location: KeyLocation::Header,
    };
    let bearer = AuthConfig::Bearer { token: SensitiveValue::template("audit-only-bearer-token-7j3u"), prefix: "Bearer".into() };
    let stream = |auth: AuthConfig| sse_with("https://sse.example.test/events", HttpVersionPolicy::Auto, auth);

    let p = e.preview(&stream(AuthConfig::Multi { profiles: vec![key.clone(), hmac()] })).unwrap();
    assert!(p.auth_varies_per_send, "{}", p.auth);
    assert!(p.inferred.iter().any(|i| i == note), "{:?}", p.inferred);

    let p = e.preview(&stream(AuthConfig::Multi { profiles: vec![bearer, key] })).unwrap();
    assert!(!p.auth_varies_per_send, "{}", p.auth);
    assert!(!p.inferred.iter().any(|i| i == note), "a bearer token and an API key are sent as shown: {:?}", p.inferred);
}
