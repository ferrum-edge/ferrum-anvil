//! A unary gRPC call with a local schema and no request message sends the
//! empty message: a 5-byte frame. Auth signs that frame, not an empty body.
//! From the fixture's ground truth (the body it received and the headers
//! that came with it), the HMAC `Content-Digest` is checked against the
//! bytes that arrived and the signature against what was received, over h2c
//! and HTTP/3. The record's prepared request and the effective-request
//! preview show the same frame and digest.

use anvil_auth::digest::{self, DigestAlg};
use anvil_auth::hmac_sig;
use anvil_domain::Id;
use anvil_domain::auth::{AuthConfig, HmacAlgorithm, HmacConfig, HmacProfile};
use anvil_domain::request::*;
use anvil_domain::secret::SensitiveValue;
use anvil_domain::settings::{HttpVersionPolicy, SettingsOverrides};
use anvil_domain::tls::{TlsMinVersion, TlsProfile};
use anvil_engine::context::MemoryAttachments;
use anvil_engine::{Engine, ExecutionContext};
use anvil_fixtures::grpc::ECHO_PROTO;
use anvil_fixtures::http as fx;
use anvil_fixtures::{GroundTruth, GroundTruthLog, LabPki, TlsServerOptions, h3server};
use anvil_transport::recorder::EventCtx;
use base64::Engine as _;
use bytes::Bytes;
use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use tokio_util::sync::CancellationToken;

const USERNAME: &str = "empty-message-client";
const SECRET: &str = "audit-only-empty-message-hmac-2w7r";
const PATH: &str = "/anvil.lab.v1.Echo/Unary";
/// The empty message, framed: not compressed, length 0.
const EMPTY_FRAME: [u8; 5] = [0, 0, 0, 0, 0];

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

/// A unary `Echo` call with the echo service's `.proto` as its schema, no
/// request message and HMAC auth. The context takes its auth layer from the
/// spec when it is built, so the auth is set before.
fn empty_call(url: &str, version: HttpVersionPolicy) -> ExecutionContext {
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
        messages: vec![],
        metadata: vec![],
        deadline_ms: None,
        plaintext: false,
        wire: GrpcWire::Grpc,
    });
    s.auth = hmac();
    let mut c = ExecutionContext::standalone(s);
    c.settings_layers.push(("run".into(), SettingsOverrides { http_version: Some(version), ..Default::default() }));
    c.attachments = Arc::new(MemoryAttachments(HashMap::from([(sha, Bytes::from_static(ECHO_PROTO.as_bytes()))])));
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

fn header<'a>(h: &'a [(String, String)], name: &str) -> Option<&'a str> {
    h.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
}

/// The value of `key="…"` in an HMAC `Authorization` header.
fn auth_param<'a>(authorization: &'a str, key: &str) -> &'a str {
    let start = authorization.find(&format!("{key}=\"")).unwrap_or_else(|| panic!("no {key} in {authorization}")) + key.len() + 2;
    let len = authorization[start..].find('"').expect("unterminated auth-param");
    &authorization[start..start + len]
}

/// What the fixture received for the call: its method, target, headers,
/// authority (`:authority`) and body.
struct Received {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
    authority: String,
    body: Vec<u8>,
}

fn received(log: &GroundTruthLog) -> Received {
    let entries: Vec<GroundTruth> = log.entries().into_iter().map(|e| e.event).collect();
    let i = entries
        .iter()
        .rposition(|e| matches!(e, GroundTruth::RequestReceived { path, .. } if path == PATH))
        .expect("the fixture received no call to the method");
    let GroundTruth::RequestReceived { method, path: target, headers, .. } = entries[i].clone() else { unreachable!() };
    // The fixtures record a request's `:authority` just before the request itself.
    let authority = entries[..i]
        .iter()
        .rev()
        .find_map(|e| match e {
            GroundTruth::AuthorityReceived { path, authority } if path == PATH => Some(authority.clone()),
            _ => None,
        })
        .expect("no :authority received");
    let body = entries[i..]
        .iter()
        .find_map(|e| match e {
            GroundTruth::GrpcBodyReceived { path, body } if path == PATH => Some(body.clone()),
            _ => None,
        })
        .expect("no request body received");
    Received { method, target, headers, authority, body }
}

/// Preview and send `c`: the fixture received the empty message frame, the
/// Content-Digest it received is the digest of that frame, the signature
/// covers what it received, and the record and the preview show the frame
/// and digest sent.
async fn assert_signed_over_the_empty_frame(label: &str, e: &Engine, c: &ExecutionContext, log: &GroundTruthLog) {
    let p = e.preview(c).unwrap_or_else(|f| panic!("{label}: the preview failed: {f:?}"));
    let o = e.execute(c, EventCtx::none(), CancellationToken::new()).await;
    let failure = o.record.attempts.last().and_then(|a| a.failure.as_ref());
    assert!(o.record.response.is_some(), "{label}: no response: {failure:?}");
    let r = received(log);
    assert_eq!(r.body, EMPTY_FRAME, "{label}: the empty message frame was not received");

    let (name, expected) = digest::header(Default::default(), DigestAlg::Sha256, &r.body);
    let content_digest = header(&r.headers, name).unwrap_or_else(|| panic!("{label}: no {name} received"));
    assert_eq!(content_digest, expected, "{label}: the digest does not cover the body received");
    let (_, over_nothing) = digest::header(Default::default(), DigestAlg::Sha256, b"");
    assert_ne!(content_digest, over_nothing, "{label}: the digest covers an empty body, not the frame sent");

    let authorization = header(&r.headers, "authorization").unwrap_or_else(|| panic!("{label}: no Authorization received"));
    let ss = hmac_sig::signing_string(
        HmacProfile::FerrumV2,
        "ferrum",
        USERNAME,
        &r.authority,
        &r.method,
        &r.target,
        "",
        header(&r.headers, "date").unwrap_or_else(|| panic!("{label}: no Date received")),
        content_digest,
        Some(auth_param(authorization, "nonce")),
    );
    let mac = hmac_sig::mac(HmacAlgorithm::HmacSha256, SECRET.as_bytes(), ss.as_bytes());
    let signature = base64::engine::general_purpose::STANDARD.encode(mac);
    assert_eq!(auth_param(authorization, "signature"), signature, "{label}: the signature does not cover what was received");

    // The record's prepared request is the one signed and sent.
    let prepared = &o.record.prepared;
    assert_eq!(prepared.body_bytes, EMPTY_FRAME.len() as u64, "{label}: the prepared body is not the one sent");
    let prepared_digest = prepared.headers.iter().find(|h| h.name.eq_ignore_ascii_case(name)).map(|h| h.value.as_str());
    assert_eq!(prepared_digest, Some(content_digest), "{label}: the prepared digest is not the one sent");
    assert!(!serde_json::to_string(&o.record).unwrap().contains(SECRET), "{label}: the record holds the HMAC secret");

    // The preview shows the empty message, the frame's size and its digest.
    assert_eq!(p.body_bytes, EMPTY_FRAME.len() as u64, "{label}: the preview's body is not the frame sent");
    let message: serde_json::Value = serde_json::from_str(&p.body_preview).unwrap_or_else(|err| panic!("{label}: {err}"));
    assert_eq!(message, serde_json::json!({}), "{label}: the preview does not show the empty message");
    let preview_digest = p.headers.iter().find(|h| h.name.eq_ignore_ascii_case(name)).map(|h| h.value.as_str());
    assert_eq!(preview_digest, Some(content_digest), "{label}: the preview's digest is not the one sent");
    assert!(p.inferred.iter().any(|i| i.contains("sends the empty message")), "{label}: {:?}", p.inferred);
}

#[tokio::test]
async fn a_unary_call_with_no_message_is_signed_over_the_empty_message_frame_it_sends() {
    init();
    let e = Engine::new();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let c = empty_call(&format!("grpc://{}", f.addr), HttpVersionPolicy::Auto);
    assert_signed_over_the_empty_frame("gRPC over h2c", &e, &c, &f.log).await;

    let h3 = h3server::serve("127.0.0.1:0", server_tls()).await.unwrap();
    let c = lab_trust(empty_call(&format!("grpcs://127.0.0.1:{}", h3.addr.port()), HttpVersionPolicy::Http3Only));
    assert_signed_over_the_empty_frame("gRPC over HTTP/3", &e, &c, &h3.log).await;
}
