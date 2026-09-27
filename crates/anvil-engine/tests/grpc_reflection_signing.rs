//! A gRPC call whose schema comes from server reflection is signed over the
//! framed message it sends, once reflection has resolved the schema and the
//! message is encoded, as a call with a local `.proto` is when it is
//! prepared. From the fixture's ground truth (the body it received and the
//! headers that came with it), the HMAC `Content-Digest` is checked against
//! the bytes that arrived and the signature against what was received, over
//! h2c and HTTP/3. The record's prepared request is the one signed and sent.

use anvil_auth::digest::{self, DigestAlg};
use anvil_auth::hmac_sig;
use anvil_domain::Id;
use anvil_domain::auth::{AuthConfig, HmacAlgorithm, HmacConfig, HmacProfile};
use anvil_domain::request::*;
use anvil_domain::secret::SensitiveValue;
use anvil_domain::settings::{HttpVersionPolicy, SettingsOverrides};
use anvil_domain::tls::{TlsMinVersion, TlsProfile};
use anvil_engine::{Engine, ExecutionContext, ExecutionOutput};
use anvil_fixtures::http as fx;
use anvil_fixtures::{GroundTruth, GroundTruthLog, LabPki, TlsServerOptions, h3server};
use anvil_transport::recorder::EventCtx;
use base64::Engine as _;
use std::sync::OnceLock;
use tokio_util::sync::CancellationToken;

const USERNAME: &str = "reflection-client";
const SECRET: &str = "audit-only-reflection-hmac-6t1p";
const PATH: &str = "/anvil.lab.v1.Echo/Unary";

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

/// A unary `Echo` call with its schema from server reflection, HMAC-signed.
/// The context takes its auth layer from the spec when it is built, so the
/// auth is set before.
fn reflected(url: &str, version: HttpVersionPolicy) -> ExecutionContext {
    let mut s = RequestSpec::http("POST", url);
    s.protocol = Protocol::Grpc;
    s.grpc = Some(GrpcSpec {
        service: "anvil.lab.v1.Echo".into(),
        method: "Unary".into(),
        mode: GrpcMode::Unary,
        schema: GrpcSchemaSource::Reflection,
        messages: vec![r#"{"message":"signed after reflection","count":3}"#.into()],
        metadata: vec![],
        deadline_ms: None,
        plaintext: false,
        wire: GrpcWire::Grpc,
    });
    s.auth = hmac();
    let mut c = ExecutionContext::standalone(s);
    c.settings_layers.push(("run".into(), SettingsOverrides { http_version: Some(version), ..Default::default() }));
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

/// The call succeeded; the Content-Digest the fixture received is the digest
/// of the body it received, and the signature covers what it received.
fn assert_signed_over_the_body_sent(label: &str, o: &ExecutionOutput, log: &GroundTruthLog) {
    let failure = o.record.attempts.last().and_then(|a| a.failure.as_ref());
    assert!(o.record.response.is_some(), "{label}: no response: {failure:?}");
    assert!(o.record.prepared.inferred.iter().any(|i| i.contains("server reflection")), "{label}: {:?}", o.record.prepared.inferred);
    let r = received(log);
    assert!(r.body.len() > 5, "{label}: the framed message was not received: {:?}", r.body);
    let (name, expected) = digest::header(Default::default(), DigestAlg::Sha256, &r.body);
    let content_digest = header(&r.headers, name).unwrap_or_else(|| panic!("{label}: no {name} received"));
    assert_eq!(content_digest, expected, "{label}: the digest does not cover the body received");

    let authorization = header(&r.headers, "authorization").unwrap_or_else(|| panic!("{label}: no Authorization received"));
    let nonce = auth_param(authorization, "nonce");
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
        content_digest,
        Some(nonce),
    );
    let mac = hmac_sig::mac(HmacAlgorithm::HmacSha256, SECRET.as_bytes(), ss.as_bytes());
    let signature = base64::engine::general_purpose::STANDARD.encode(mac);
    assert_eq!(auth_param(authorization, "signature"), signature, "{label}: the signature does not cover what was received");

    // The record's prepared request is the one signed and sent.
    let p = &o.record.prepared;
    assert_eq!(p.body_bytes, r.body.len() as u64, "{label}: the prepared body is not the one sent");
    let prepared_digest = p.headers.iter().find(|h| h.name.eq_ignore_ascii_case(name)).map(|h| h.value.as_str());
    assert_eq!(prepared_digest, Some(content_digest), "{label}: the prepared digest is not the one sent");
    let fact = format!("auth hmac.nonce: {nonce}");
    assert!(p.inferred.contains(&fact), "{label}: the prepared auth facts are not those sent: {:?}", p.inferred);
    assert!(!serde_json::to_string(&o.record).unwrap().contains(SECRET), "{label}: the record holds the HMAC secret");
}

#[tokio::test]
async fn a_call_with_server_reflection_is_signed_over_the_framed_message_sent() {
    init();
    let e = Engine::new();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let o = e.execute(&reflected(&format!("grpc://{}", f.addr), HttpVersionPolicy::Auto), EventCtx::none(), CancellationToken::new()).await;
    assert_signed_over_the_body_sent("gRPC over h2c", &o, &f.log);

    let h3 = h3server::serve("127.0.0.1:0", server_tls()).await.unwrap();
    let c = lab_trust(reflected(&format!("grpcs://127.0.0.1:{}", h3.addr.port()), HttpVersionPolicy::Http3Only));
    let o = e.execute(&c, EventCtx::none(), CancellationToken::new()).await;
    assert_signed_over_the_body_sent("gRPC over HTTP/3", &o, &h3.log);
}
