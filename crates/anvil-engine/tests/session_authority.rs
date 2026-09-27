//! The HTTP-based session transports send an explicit `Host` header as the
//! request's authority, as the HTTP send path does: WebSocket (HTTP/1.1
//! upgrade, HTTP/2 and HTTP/3 extended CONNECT), SSE (HTTP/1.1, HTTP/2,
//! HTTP/3) and gRPC (native over HTTP/2 and HTTP/3, gRPC-Web over HTTP/1.1,
//! HTTP/2 and HTTP/3). The HMAC signature covers that authority and the
//! method on the wire (`CONNECT` for an extended CONNECT WebSocket). Each
//! case checks, from the fixture's ground truth, that the server received
//! the explicit `Host` (as `Host` over HTTP/1.1, as `:authority` over HTTP/2
//! and HTTP/3) and that the signature it received verifies over what it
//! received. A DPoP proof for a WebSocket over HTTP/2 is bound to the same
//! method and authority, with the `http` counterpart of the `ws` URL.

use anvil_auth::hmac_sig;
use anvil_domain::Id;
use anvil_domain::auth::{AuthConfig, DpopConfig, HmacAlgorithm, HmacConfig, HmacProfile};
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
use base64::Engine as _;
use bytes::Bytes;
use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use tokio_util::sync::CancellationToken;

/// The explicit `Host`: not the URL's authority (the fixtures listen on
/// 127.0.0.1 with an ephemeral port).
const HOST: &str = "api.example.test:8443";
const USERNAME: &str = "session-client";
const SECRET: &str = "audit-only-hmac-secret-4k9w";

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
            access_token: SensitiveValue::template("audit-only-dpop-token-7m2q"),
            private_key_pem: SensitiveValue::template(anvil_auth::dpop::generate_key_pem().unwrap()),
            dpop_scheme: true,
            handle_nonce_challenge: true,
        },
    }
}

/// `s` with the explicit `Host`, HMAC auth and the HTTP version policy, if
/// any.
fn signed(s: RequestSpec, version: Option<HttpVersionPolicy>) -> ExecutionContext {
    with_auth(s, version, hmac())
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

/// Trust the lab root (TLS and QUIC fixtures).
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

fn ws(url: &str, bootstrap: WsBootstrap) -> ExecutionContext {
    // The bootstrap chooses the HTTP version.
    signed(ws_spec(url, bootstrap), None)
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
    let mut s = RequestSpec::http("GET", url);
    s.protocol = Protocol::Sse;
    s.sse = Some(SseSpec { max_events: 1, idle_timeout_ms: 5_000, last_event_id: None, reconnect: false });
    signed(s, Some(version))
}

/// A unary `Echo` call with the echo service's `.proto` as its schema.
fn grpc(url: &str, wire: GrpcWire, version: HttpVersionPolicy) -> ExecutionContext {
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
        wire,
    });
    let mut c = signed(s, Some(version));
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

/// Check that the fixture received the explicit `Host` as the authority and
/// that the HMAC signature it received verifies over its method, target,
/// authority, `Date`, digest and nonce.
fn assert_signed_for_host(label: &str, o: &ExecutionOutput, log: &GroundTruthLog, path: &str) {
    let failure = o.record.attempts.last().and_then(|a| a.failure.as_ref());
    assert!(o.record.response.is_some(), "{label}: no response: {failure:?}");
    let r = received(log, path);
    assert_eq!(r.authority, HOST, "{label}: the server did not receive the explicit Host as the authority");
    assert!(
        !r.headers.iter().any(|(n, _)| n.eq_ignore_ascii_case("host")) || header(&r.headers, "host") == Some(HOST),
        "{label}: a Host other than the explicit one was received: {:?}",
        r.headers
    );
    let authorization = header(&r.headers, "authorization").unwrap_or_else(|| panic!("{label}: no Authorization received"));
    let (raw_path, raw_query) = r.target.split_once('?').unwrap_or((r.target.as_str(), ""));
    let ss = hmac_sig::signing_string(
        HmacProfile::FerrumV2,
        "ferrum",
        USERNAME,
        &r.authority,
        &r.method,
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
        "{label}: the signature does not cover what the server received ({} {} for {})",
        r.method,
        r.target,
        r.authority
    );
}

#[tokio::test]
async fn websocket_over_http1_http2_and_http3_sends_and_signs_the_explicit_host() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    let url = format!("ws://{}/ws?close_after=1", f.addr);
    let o = run(&e, &ws(&url, WsBootstrap::Http1Upgrade)).await;
    assert_signed_for_host("ws over HTTP/1.1", &o, &f.log, "/ws");
    assert_eq!(received(&f.log, "/ws").method, "GET");

    let o = run(&e, &ws(&url, WsBootstrap::Http2ExtendedConnect)).await;
    assert_signed_for_host("ws over HTTP/2", &o, &f.log, "/ws");
    assert_eq!(received(&f.log, "/ws").method, "CONNECT", "RFC 8441: the wire method, which the signature covers");
    assert_eq!(o.record.prepared.method, "CONNECT");

    let h3 = h3server::serve("127.0.0.1:0", server_tls()).await.unwrap();
    let url = format!("wss://127.0.0.1:{}/ws?close_after=1", h3.addr.port());
    let o = run(&e, &lab_trust(ws(&url, WsBootstrap::Http3ExtendedConnect))).await;
    assert_signed_for_host("ws over HTTP/3", &o, &h3.log, "/ws");
    assert_eq!(received(&h3.log, "/ws").method, "CONNECT", "RFC 9220: the wire method, which the signature covers");
    assert_eq!(o.record.prepared.method, "CONNECT");
}

#[tokio::test]
async fn websocket_over_http2_binds_the_dpop_proof_to_connect_and_the_explicit_host() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    let url = format!("ws://{}/ws?close_after=1", f.addr);
    let o = run(&e, &with_auth(ws_spec(&url, WsBootstrap::Http2ExtendedConnect), None, dpop())).await;
    let failure = o.record.attempts.last().and_then(|a| a.failure.as_ref());
    assert!(o.record.response.is_some(), "no response: {failure:?}");
    let r = received(&f.log, "/ws");
    assert_eq!(r.method, "CONNECT");
    assert_eq!(r.authority, HOST, "the server did not receive the explicit Host as the authority");
    let proof = header(&r.headers, "dpop").unwrap_or_else(|| panic!("no DPoP proof received: {:?}", r.headers));
    let payload = proof.split('.').nth(1).expect("the DPoP proof is not a JWT");
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload).expect("the DPoP payload is not base64url");
    let claims: serde_json::Value = serde_json::from_slice(&payload).expect("the DPoP payload is not JSON");
    assert_eq!(claims["htm"], "CONNECT", "RFC 8441: the proof is bound to the wire method");
    assert_eq!(claims["htu"], format!("http://{HOST}/ws"), "the proof is not bound to the Host sent");
}

#[tokio::test]
async fn sse_over_http1_http2_and_http3_sends_and_signs_the_explicit_host() {
    init();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let e = Engine::new();
    for (label, version) in [("sse over HTTP/1.1", HttpVersionPolicy::Http1Only), ("sse over HTTP/2", HttpVersionPolicy::H2c)] {
        let o = run(&e, &sse(&f.url("/sse?count=1&interval=1"), version)).await;
        assert_signed_for_host(label, &o, &f.log, "/sse");
    }
    let tls = fx::serve("127.0.0.1:0", Some(server_tls())).await.unwrap();
    let o = run(&e, &lab_trust(sse(&tls.url("/sse?count=1&interval=1"), HttpVersionPolicy::Http2Only))).await;
    assert_signed_for_host("sse over HTTP/2 (TLS)", &o, &tls.log, "/sse");

    let h3 = h3server::serve("127.0.0.1:0", server_tls()).await.unwrap();
    let o = run(&e, &lab_trust(sse(&h3.url("/sse?count=1&interval=1"), HttpVersionPolicy::Http3Only))).await;
    assert_signed_for_host("sse over HTTP/3", &o, &h3.log, "/sse");
}

#[tokio::test]
async fn grpc_over_http2_and_http3_sends_and_signs_the_explicit_host() {
    init();
    let e = Engine::new();
    let path = "/anvil.lab.v1.Echo/Unary";
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let o = run(&e, &grpc(&format!("grpc://{}", f.addr), GrpcWire::Grpc, HttpVersionPolicy::Auto)).await;
    assert_signed_for_host("gRPC over h2c", &o, &f.log, path);

    let tls = fx::serve("127.0.0.1:0", Some(server_tls())).await.unwrap();
    let o = run(&e, &lab_trust(grpc(&format!("grpcs://{}", tls.addr), GrpcWire::Grpc, HttpVersionPolicy::Auto))).await;
    assert_signed_for_host("gRPC over HTTP/2 (TLS)", &o, &tls.log, path);

    let h3 = h3server::serve("127.0.0.1:0", server_tls()).await.unwrap();
    let url = format!("grpcs://127.0.0.1:{}", h3.addr.port());
    let o = run(&e, &lab_trust(grpc(&url, GrpcWire::Grpc, HttpVersionPolicy::Http3Only))).await;
    assert_signed_for_host("gRPC over HTTP/3", &o, &h3.log, path);
}

#[tokio::test]
async fn grpc_web_over_http1_http2_and_http3_sends_and_signs_the_explicit_host() {
    init();
    let e = Engine::new();
    let path = "/anvil.lab.v1.Echo/Unary";
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    for (label, version) in [("gRPC-Web over HTTP/1.1", HttpVersionPolicy::Http1Only), ("gRPC-Web over h2c", HttpVersionPolicy::H2c)] {
        let o = run(&e, &grpc(&format!("http://{}", f.addr), GrpcWire::GrpcWeb, version)).await;
        assert_signed_for_host(label, &o, &f.log, path);
    }
    let h3 = h3server::serve("127.0.0.1:0", server_tls()).await.unwrap();
    let url = format!("https://127.0.0.1:{}", h3.addr.port());
    let o = run(&e, &lab_trust(grpc(&url, GrpcWire::GrpcWeb, HttpVersionPolicy::Http3Only))).await;
    assert_signed_for_host("gRPC-Web over HTTP/3", &o, &h3.log, path);
}
