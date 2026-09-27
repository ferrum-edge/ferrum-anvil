//! A gRPC call whose schema comes from server reflection is signed over the
//! framed message it sends, once reflection has resolved the schema and the
//! message is encoded, as a call with a local `.proto` is when it is
//! prepared, and each reflection request is signed for its own path and
//! framed message, never sent with the call's signature or DPoP proof. From
//! the fixture's ground truth (each body it received and the headers that
//! came with it), the HMAC `Content-Digest` is checked against the bytes
//! that arrived and the signature against what was received, over h2c and
//! HTTP/3, for the call and for every reflection request. The record's
//! prepared request is the one signed and sent, and a token minted for a
//! reflection request is redacted in the record wherever the server echoes
//! it.

use anvil_auth::digest::{self, DigestAlg};
use anvil_auth::hmac_sig;
use anvil_domain::Id;
use anvil_domain::auth::{AuthConfig, DpopConfig, HmacAlgorithm, HmacConfig, HmacProfile, JwtAlgorithm, JwtClaims};
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
const REFLECTION_PATH: &str = "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo";
const REFLECTION_V1ALPHA_PATH: &str = "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo";

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
fn reflected(url: &str, version: HttpVersionPolicy) -> ExecutionContext {
    reflected_with(url, version, hmac())
}

/// A unary `Echo` call with its schema from server reflection and `auth`.
/// The context takes its auth layer from the spec when it is built, so the
/// auth is set before.
fn reflected_with(url: &str, version: HttpVersionPolicy, auth: AuthConfig) -> ExecutionContext {
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
    s.auth = auth;
    let mut c = ExecutionContext::standalone(s);
    c.settings_layers.push(("run".into(), SettingsOverrides { http_version: Some(version), ..Default::default() }));
    c
}

fn dpop() -> AuthConfig {
    AuthConfig::Dpop {
        config: DpopConfig {
            access_token: SensitiveValue::template("audit-only-reflection-dpop-token-3v9k"),
            private_key_pem: SensitiveValue::template(anvil_auth::dpop::generate_key_pem().unwrap()),
            dpop_scheme: true,
            handle_nonce_challenge: true,
        },
    }
}

/// A JWT minted for each request it signs (`iat` is the second it is signed).
fn jwt() -> AuthConfig {
    AuthConfig::Jwt {
        algorithm: JwtAlgorithm::HS256,
        signing_key: SensitiveValue::template("audit-only-reflection-jwt-key-8q2w"),
        claims: JwtClaims { sub: Some(USERNAME.into()), ..Default::default() },
        kid: None,
        header_name: "Authorization".into(),
        prefix: "Bearer".into(),
    }
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

/// What the fixture received for one request: its method, target,
/// headers, authority (`:authority`) and body.
struct Received {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
    authority: String,
    body: Vec<u8>,
}

/// Every request the fixture received for `path`, in order. The requests
/// are sent one after another; the fixtures record a request's
/// `:authority` just before the request itself, and its body once it has
/// been read.
fn requests(log: &GroundTruthLog, path: &str) -> Vec<Received> {
    let entries: Vec<GroundTruth> = log.entries().into_iter().map(|e| e.event).collect();
    let mut out = vec![];
    for (i, e) in entries.iter().enumerate() {
        let GroundTruth::RequestReceived { method, path: target, headers, .. } = e else { continue };
        if target != path {
            continue;
        }
        let authority = entries[..i]
            .iter()
            .rev()
            .find_map(|e| match e {
                GroundTruth::AuthorityReceived { path: p, authority } if p == path => Some(authority.clone()),
                _ => None,
            })
            .expect("no :authority received");
        let body = entries[i..]
            .iter()
            .find_map(|e| match e {
                GroundTruth::GrpcBodyReceived { path: p, body } if p == path => Some(body.clone()),
                _ => None,
            })
            .expect("no request body received");
        out.push(Received { method: method.clone(), target: target.clone(), headers: headers.clone(), authority, body });
    }
    out
}

/// The `Authorization` each request to `path` arrived with, in order.
fn authorizations(log: &GroundTruthLog, path: &str) -> Vec<String> {
    log.entries()
        .into_iter()
        .filter_map(|e| match e.event {
            GroundTruth::RequestReceived { path: p, headers, .. } if p == path => header(&headers, "authorization").map(str::to_string),
            _ => None,
        })
        .collect()
}

/// What the fixture received for the call.
fn received(log: &GroundTruthLog) -> Received {
    requests(log, PATH).pop().expect("the fixture received no call to the method")
}

/// The Content-Digest received is the digest of the body received, and the
/// HMAC signature covers what was received: its method, path, authority,
/// Date, digest and nonce. Returns the nonce.
fn assert_hmac_over_what_was_received(label: &str, r: &Received) -> String {
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
    nonce.to_string()
}

/// The call succeeded; the Content-Digest the fixture received is the digest
/// of the body it received, and the signature covers what it received.
fn assert_signed_over_the_body_sent(label: &str, o: &ExecutionOutput, log: &GroundTruthLog) {
    let failure = o.record.attempts.last().and_then(|a| a.failure.as_ref());
    assert!(o.record.response.is_some(), "{label}: no response: {failure:?}");
    assert!(o.record.prepared.inferred.iter().any(|i| i.contains("server reflection")), "{label}: {:?}", o.record.prepared.inferred);
    let r = received(log);
    assert!(r.body.len() > 5, "{label}: the framed message was not received: {:?}", r.body);
    let nonce = assert_hmac_over_what_was_received(label, &r);

    // The record's prepared request is the one signed and sent.
    let (name, _) = digest::header(Default::default(), DigestAlg::Sha256, &r.body);
    let content_digest = header(&r.headers, name);
    let p = &o.record.prepared;
    assert_eq!(p.body_bytes, r.body.len() as u64, "{label}: the prepared body is not the one sent");
    let prepared_digest = p.headers.iter().find(|h| h.name.eq_ignore_ascii_case(name)).map(|h| h.value.as_str());
    assert_eq!(prepared_digest, content_digest, "{label}: the prepared digest is not the one sent");
    let fact = format!("auth hmac.nonce: {nonce}");
    assert!(p.inferred.contains(&fact), "{label}: the prepared auth facts are not those sent: {:?}", p.inferred);
    assert!(!serde_json::to_string(&o.record).unwrap().contains(SECRET), "{label}: the record holds the HMAC secret");

    // Each reflection request is signed for its own path and body, with a
    // nonce of its own: never sent with the call's signature.
    let reflection = requests(log, REFLECTION_PATH);
    assert!(!reflection.is_empty(), "{label}: the fixture received no reflection request");
    let mut nonces = vec![nonce];
    for (i, r) in reflection.iter().enumerate() {
        let label = format!("{label}, reflection request {i}");
        assert!(r.body.len() > 5, "{label}: the framed reflection request was not received: {:?}", r.body);
        let nonce = assert_hmac_over_what_was_received(&label, r);
        assert!(!nonces.contains(&nonce), "{label}: the nonce {nonce} was sent before");
        nonces.push(nonce);
    }
}

/// The claims of the DPoP proof in `headers`.
fn dpop_claims(headers: &[(String, String)]) -> serde_json::Value {
    let proof = header(headers, "dpop").unwrap_or_else(|| panic!("no DPoP proof received: {headers:?}"));
    let payload = proof.split('.').nth(1).expect("the DPoP proof is not a JWT");
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload).expect("the DPoP payload is not base64url");
    serde_json::from_slice(&payload).expect("the DPoP payload is not JSON")
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

#[tokio::test]
async fn each_reflection_request_carries_a_dpop_proof_of_its_own_bound_to_its_path() {
    init();
    let e = Engine::new();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let c = reflected_with(&format!("grpc://{}", f.addr), HttpVersionPolicy::Auto, dpop());
    let o = e.execute(&c, EventCtx::none(), CancellationToken::new()).await;
    let failure = o.record.attempts.last().and_then(|a| a.failure.as_ref());
    assert!(o.record.response.is_some(), "no response: {failure:?}");

    let call = received(&f.log);
    let claims = dpop_claims(&call.headers);
    assert_eq!(claims["htm"], "POST");
    assert_eq!(claims["htu"], format!("http://{}{PATH}", call.authority), "the call's proof is not bound to its path");
    let mut jtis = vec![claims["jti"].clone()];
    let reflection = requests(&f.log, REFLECTION_PATH);
    assert!(!reflection.is_empty(), "the fixture received no reflection request");
    for (i, r) in reflection.iter().enumerate() {
        let claims = dpop_claims(&r.headers);
        assert_eq!(claims["htm"], "POST", "reflection request {i}");
        assert_eq!(
            claims["htu"],
            format!("http://{}{REFLECTION_PATH}", r.authority),
            "reflection request {i}: the proof is not bound to the reflection path"
        );
        assert!(!jtis.contains(&claims["jti"]), "reflection request {i}: the proof {} was sent before", claims["jti"]);
        jtis.push(claims["jti"].clone());
    }
}

#[tokio::test]
async fn a_token_minted_for_a_reflection_request_and_echoed_in_its_refusal_is_redacted_in_the_record() {
    init();
    let e = Engine::new();
    let f = fx::serve("127.0.0.1:0", None).await.unwrap();
    let mut c = reflected_with(&format!("grpc://{}", f.addr), HttpVersionPolicy::Auto, jwt());
    // v1 answers UNIMPLEMENTED after 1.1 s, so the v1alpha request is signed
    // at a later second than the call, with a token of its own; v1alpha
    // refuses reflection and echoes the Authorization it received.
    c.spec.grpc.as_mut().unwrap().metadata = vec![KeyValue::new("x-fixture-deny-reflection", "echo-authorization")];
    let o = e.execute(&c, EventCtx::none(), CancellationToken::new()).await;

    let (v1, v1alpha) = (authorizations(&f.log, REFLECTION_PATH), authorizations(&f.log, REFLECTION_V1ALPHA_PATH));
    assert_eq!((v1.len(), v1alpha.len()), (1, 1), "one request per reflection version: {v1:?} {v1alpha:?}");
    assert_ne!(v1[0], v1alpha[0], "the v1alpha request was not signed with a token of its own");
    let token = v1alpha[0].strip_prefix("Bearer ").expect("the reflection request carried no bearer token");
    let signature = token.rsplit('.').next().expect("the token is not a JWT");

    // The record (what history stores) keeps the refusal, echo included:
    // grpc-message, the trailer, the note and the finding.
    let record = serde_json::to_string(&o.record).unwrap();
    assert!(record.contains("grpc.reflection_unavailable"), "{record}");
    assert!(record.contains("reflection is disabled for this caller: Bearer "), "the echoed refusal is not in the record: {record}");
    assert!(record.contains("x-fixture-echo"), "the echo trailer is not in the record: {record}");
    assert!(!record.contains(token) && !record.contains(signature), "the record holds the token minted for the reflection request");
    assert!(!record.contains("audit-only-reflection-jwt-key-8q2w"), "the record holds the JWT signing key");
}
