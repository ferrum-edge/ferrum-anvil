//! SPIFFE Workload API fixture: the standard `SpiffeWorkloadAPI` gRPC
//! service (`FetchX509SVID`, `FetchJWTSVID`, `FetchJWTBundles`) on a Unix
//! domain socket. It is written independently of Anvil's client — its own
//! message definitions, framing and HTTP/2 server — so a client bug cannot
//! hide behind shared code.
//!
//! Like a SPIRE agent or Ferrum Edge's in-process server it:
//!
//! * refuses a call without the `workload.spiffe.io: true` metadata with
//!   `INVALID_ARGUMENT`;
//! * mints a **fresh** X.509-SVID (new key, new serial) on every
//!   `FetchX509SVID`, signed by an in-memory CA whose private key is never
//!   written, with a configurable lifetime (rotation tests);
//! * mints ES256 JWT-SVIDs (`sub`, `aud`, `exp`, `iat`, `jti`, `kid` = the
//!   RFC 7638 thumbprint) only for the configured identities, with a
//!   configurable lifetime (negative = already expired);
//! * streams the JWKS per trust domain from `FetchJWTBundles`, keyed
//!   `spiffe://<trust domain>` as SPIRE keys it;
//! * keeps server streams open after the first response, as real servers do.
//!
//! Modes reproduce the failures Anvil must type: `PERMISSION_DENIED`
//! (attestation refused), an OK answer without SVIDs, `UNIMPLEMENTED` JWT
//! RPCs (an X.509-only backend) and an endpoint that never answers. Every
//! call is logged as ground truth (RPC, metadata, audiences, the answer) —
//! never a key or a token.

use crate::http::FxBody;
use crate::log::{GroundTruth, GroundTruthLog};
use crate::pki::Pem;
use base64::Engine;
use bytes::{Bytes, BytesMut};
use http::{HeaderMap, HeaderValue, Request, Response};
use http_body_util::{BodyExt, Full, Limited, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use parking_lot::Mutex;
use prost::Message;
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, SanType,
};
use sha2::Digest;
use std::collections::HashMap;
use std::convert::Infallible;
#[cfg(unix)]
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use time::OffsetDateTime;
use tokio_util::sync::CancellationToken;

pub const TRUST_DOMAIN: &str = "anvil.test";
/// The default identity the fixture attests the caller as.
pub const WORKLOAD_ID: &str = "spiffe://anvil.test/ns/lab/sa/anvil-client";
/// A second identity the caller also holds (SPIFFE ID selection tests).
pub const SECOND_ID: &str = "spiffe://anvil.test/ns/lab/sa/anvil-batch";
/// Identity of TLS servers built with [`Fixture::server_svid`].
pub const SERVER_ID: &str = "spiffe://anvil.test/ns/lab/sa/api";

// Messages as in the upstream workload.proto (independent transcription).
#[derive(Clone, PartialEq, prost::Message)]
struct X509SvidMsg {
    #[prost(string, tag = "1")]
    spiffe_id: String,
    #[prost(bytes = "vec", tag = "2")]
    x509_svid: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    x509_svid_key: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    bundle: Vec<u8>,
    #[prost(string, tag = "5")]
    hint: String,
}

#[derive(Clone, PartialEq, prost::Message)]
struct X509SvidResponseMsg {
    #[prost(message, repeated, tag = "1")]
    svids: Vec<X509SvidMsg>,
    #[prost(bytes = "vec", repeated, tag = "2")]
    crl: Vec<Vec<u8>>,
    #[prost(map = "string, bytes", tag = "3")]
    federated_bundles: HashMap<String, Vec<u8>>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct JwtSvidRequestMsg {
    #[prost(string, repeated, tag = "1")]
    audience: Vec<String>,
    #[prost(string, tag = "2")]
    spiffe_id: String,
}

#[derive(Clone, PartialEq, prost::Message)]
struct JwtSvidMsg {
    #[prost(string, tag = "1")]
    spiffe_id: String,
    #[prost(string, tag = "2")]
    svid: String,
    #[prost(string, tag = "3")]
    hint: String,
}

#[derive(Clone, PartialEq, prost::Message)]
struct JwtSvidResponseMsg {
    #[prost(message, repeated, tag = "1")]
    svids: Vec<JwtSvidMsg>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct JwtBundlesResponseMsg {
    #[prost(map = "string, bytes", tag = "1")]
    bundles: HashMap<String, Vec<u8>>,
}

/// How the fixture answers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Serve,
    /// SVID RPCs answer `PERMISSION_DENIED` ("workload attestation failed",
    /// Ferrum Edge's wording); bundles are still served.
    Deny,
    /// SVID RPCs answer OK with an empty `svids` list.
    NoIdentity,
    /// The JWT RPCs answer `UNIMPLEMENTED` (an X.509-only backend).
    JwtUnimplemented,
    /// Accept the call and never answer.
    Hang,
}

struct State {
    mode: Mode,
    identities: Vec<String>,
    x509_ttl: Duration,
    jwt_ttl_secs: i64,
    issued_x509: u64,
    federated: Vec<(String, Vec<u8>)>,
}

struct Keys {
    ca: CertifiedIssuer<'static, KeyPair>,
    ca_der: Vec<u8>,
    jwt_key_pem: String,
    kid: String,
    jwks: Vec<u8>,
}

pub struct Fixture {
    /// The Unix socket path (`None` for a Windows named pipe).
    pub path: Option<PathBuf>,
    uri: String,
    pub log: GroundTruthLog,
    /// The trust domain's CA certificate (the X.509 bundle).
    pub ca_pem: String,
    /// The JWKS `FetchJWTBundles` serves for [`TRUST_DOMAIN`].
    pub jwks: Vec<u8>,
    /// The key id of the JWT signing key.
    pub kid: String,
    state: Arc<Mutex<State>>,
    keys: Arc<Keys>,
    cancel: CancellationToken,
}

impl Fixture {
    /// `unix:///<path>` or `npipe:<name>`.
    pub fn uri(&self) -> String {
        self.uri.clone()
    }

    pub fn set_mode(&self, mode: Mode) {
        self.state.lock().mode = mode;
    }

    /// Lifetime of JWT-SVIDs minted from now on (negative: already expired).
    pub fn set_jwt_ttl_secs(&self, secs: i64) {
        self.state.lock().jwt_ttl_secs = secs;
    }

    pub fn set_x509_ttl(&self, ttl: Duration) {
        self.state.lock().x509_ttl = ttl;
    }

    /// Identities the caller is attested as (the first is the default).
    pub fn set_identities(&self, ids: &[&str]) {
        self.state.lock().identities = ids.iter().map(|s| s.to_string()).collect();
    }

    /// Also send a federated bundle (recorded by the client, never trusted).
    pub fn add_federated_bundle(&self, trust_domain: &str, ca_pem: &str) {
        let der = crate::tlsserver::certs(ca_pem).into_iter().flat_map(|c| c.to_vec()).collect();
        self.state.lock().federated.push((format!("spiffe://{trust_domain}"), der));
    }

    /// X.509-SVIDs minted so far (each `FetchX509SVID` mints a new one).
    pub fn issued_x509(&self) -> u64 {
        self.state.lock().issued_x509
    }

    /// An X.509-SVID for a TLS server of this trust domain (URI SAN only).
    pub fn server_svid(&self, spiffe_id: &str) -> Pem {
        let (cert, key) = mint_leaf(&self.keys.ca, spiffe_id, Duration::from_secs(3600));
        Pem { cert: pem_cert(&cert), key: key.serialize_pem() }
    }

    /// A JWT-SVID signed by this fixture's key (for the value/file sources).
    pub fn mint_jwt(&self, sub: &str, audiences: &[&str], ttl_secs: i64) -> String {
        sign_jwt(&self.keys, sub, &audiences.iter().map(|s| s.to_string()).collect::<Vec<_>>(), ttl_secs)
    }

    pub fn shutdown(&self) {
        self.cancel.cancel();
        if let Some(p) = &self.path {
            let _ = std::fs::remove_file(p);
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn dn(cn: &str) -> DistinguishedName {
    let mut d = DistinguishedName::new();
    d.push(DnType::OrganizationName, "Ferrum Anvil Workload API Fixture");
    d.push(DnType::CommonName, cn);
    d
}

fn b64u(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

fn pem_cert(der: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut s = String::from("-----BEGIN CERTIFICATE-----\n");
    for c in b64.as_bytes().chunks(64) {
        s.push_str(std::str::from_utf8(c).unwrap_or_default());
        s.push('\n');
    }
    s.push_str("-----END CERTIFICATE-----\n");
    s
}

fn mint_leaf(ca: &CertifiedIssuer<'static, KeyPair>, spiffe_id: &str, ttl: Duration) -> (Vec<u8>, KeyPair) {
    let mut p = CertificateParams::new(Vec::<String>::new()).expect("params");
    p.distinguished_name = dn("anvil-workload-svid");
    p.subject_alt_names.push(SanType::URI(spiffe_id.try_into().expect("uri")));
    p.is_ca = IsCa::ExplicitNoCa;
    p.key_usages = vec![KeyUsagePurpose::DigitalSignature, KeyUsagePurpose::KeyAgreement];
    p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth, ExtendedKeyUsagePurpose::ClientAuth];
    let now = OffsetDateTime::now_utc();
    p.not_before = now - time::Duration::seconds(60);
    p.not_after = now + time::Duration::milliseconds(ttl.as_millis() as i64);
    let key = KeyPair::generate().expect("key");
    let cert = p.signed_by(&key, ca).expect("sign");
    (cert.der().to_vec(), key)
}

fn sign_jwt(keys: &Keys, sub: &str, audiences: &[String], ttl_secs: i64) -> String {
    static SERIAL: AtomicU64 = AtomicU64::new(1);
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
    let exp = now + ttl_secs;
    let claims = serde_json::json!({
        "sub": sub, "aud": audiences, "exp": exp, "iat": now.min(exp - 1),
        "jti": format!("fixture-{}-{}", now, SERIAL.fetch_add(1, Ordering::Relaxed)),
    });
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
    header.typ = Some("JWT".into());
    header.kid = Some(keys.kid.clone());
    let key = jsonwebtoken::EncodingKey::from_ec_pem(keys.jwt_key_pem.as_bytes()).expect("fixture ES256 key");
    jsonwebtoken::encode(&header, &claims, &key).expect("sign JWT-SVID")
}

fn make_keys() -> Keys {
    let mut p = CertificateParams::new(Vec::<String>::new()).expect("params");
    p.distinguished_name = dn("Anvil Workload API Fixture Root");
    p.subject_alt_names.push(SanType::URI(format!("spiffe://{TRUST_DOMAIN}").as_str().try_into().expect("uri")));
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign, KeyUsagePurpose::DigitalSignature];
    p.not_before = OffsetDateTime::now_utc() - time::Duration::days(1);
    p.not_after = OffsetDateTime::now_utc() + time::Duration::days(30);
    let ca = CertifiedIssuer::self_signed(p, KeyPair::generate().expect("ca key")).expect("ca");
    let ca_der = ca.der().to_vec();
    let jwt_key = KeyPair::generate().expect("jwt key");
    let raw = jwt_key.public_key_raw();
    assert_eq!((raw.len(), raw[0]), (65, 4), "uncompressed P-256 point");
    let (x, y) = (b64u(&raw[1..33]), b64u(&raw[33..65]));
    let canonical = format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#);
    let kid = b64u(&sha2::Sha256::digest(canonical.as_bytes()));
    let jwks = serde_json::to_vec(&serde_json::json!({
        "keys": [{"kty": "EC", "crv": "P-256", "x": x, "y": y, "kid": kid, "alg": "ES256", "use": "sig"}]
    }))
    .expect("jwks");
    Keys { ca, ca_der, jwt_key_pem: jwt_key.serialize_pem(), kid, jwks }
}

struct Shared {
    keys: Arc<Keys>,
    state: Arc<Mutex<State>>,
    log: GroundTruthLog,
    cancel: CancellationToken,
}

fn shared() -> Shared {
    Shared {
        keys: Arc::new(make_keys()),
        state: Arc::new(Mutex::new(State {
            mode: Mode::Serve,
            identities: vec![WORKLOAD_ID.to_string()],
            x509_ttl: Duration::from_secs(3600),
            jwt_ttl_secs: 300,
            issued_x509: 0,
            federated: vec![],
        })),
        log: GroundTruthLog::default(),
        cancel: CancellationToken::new(),
    }
}

impl Shared {
    fn fixture(&self, path: Option<PathBuf>, uri: String) -> Fixture {
        Fixture {
            path,
            uri,
            log: self.log.clone(),
            ca_pem: pem_cert(&self.keys.ca_der),
            jwks: self.keys.jwks.clone(),
            kid: self.keys.kid.clone(),
            state: self.state.clone(),
            keys: self.keys.clone(),
            cancel: self.cancel.clone(),
        }
    }

    /// Serve one accepted connection (HTTP/2 gRPC) until it ends or the
    /// fixture shuts down.
    fn serve_connection<I>(&self, io: I)
    where
        I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let (keys, state, log, cancel) = (self.keys.clone(), self.state.clone(), self.log.clone(), self.cancel.clone());
        tokio::spawn(async move {
            let svc = service_fn(move |req| {
                let (keys, state, log) = (keys.clone(), state.clone(), log.clone());
                async move { Ok::<_, Infallible>(handle(req, keys, state, log).await) }
            });
            let conn = hyper::server::conn::http2::Builder::new(TokioExecutor::new()).serve_connection(TokioIo::new(io), svc);
            tokio::select! {
                _ = conn => {}
                _ = cancel.cancelled() => {}
            }
        });
    }
}

/// Serve the Workload API on a Unix socket at `path` (replaced if present).
#[cfg(unix)]
pub async fn serve(path: &Path) -> anyhow::Result<Fixture> {
    let _ = std::fs::remove_file(path);
    let listener = tokio::net::UnixListener::bind(path)?;
    let sh = shared();
    let fixture = sh.fixture(Some(path.to_path_buf()), format!("unix://{}", path.display()));
    tokio::spawn(async move {
        loop {
            let stream = tokio::select! {
                r = listener.accept() => match r { Ok((s, _)) => s, Err(_) => continue },
                _ = sh.cancel.cancelled() => break,
            };
            sh.serve_connection(stream);
        }
    });
    Ok(fixture)
}

/// Serve the Workload API on the Windows named pipe `\\.\pipe\<name>`
/// (SPIRE's transport on Windows); the URI is `npipe:<name>`.
#[cfg(windows)]
pub async fn serve_named_pipe(name: &str) -> anyhow::Result<Fixture> {
    use tokio::net::windows::named_pipe::ServerOptions;
    let pipe = format!(r"\\.\pipe\{name}");
    let mut server = ServerOptions::new().first_pipe_instance(true).create(&pipe)?;
    let sh = shared();
    let fixture = sh.fixture(None, format!("npipe:{name}"));
    tokio::spawn(async move {
        loop {
            tokio::select! {
                r = server.connect() => {
                    if r.is_err() {
                        break;
                    }
                }
                _ = sh.cancel.cancelled() => break,
            }
            let next = match ServerOptions::new().create(&pipe) {
                Ok(n) => n,
                Err(_) => break,
            };
            let connected = std::mem::replace(&mut server, next);
            sh.serve_connection(connected);
        }
    });
    Ok(fixture)
}

fn frame(msg: &impl Message) -> Bytes {
    let body = msg.encode_to_vec();
    let mut b = BytesMut::with_capacity(5 + body.len());
    b.extend_from_slice(&[0]);
    b.extend_from_slice(&(body.len() as u32).to_be_bytes());
    b.extend_from_slice(&body);
    b.freeze()
}

fn full(b: Bytes) -> FxBody {
    Full::new(b).map_err(|e: Infallible| match e {}).boxed()
}

/// Trailers-only error answer.
fn status(code: i32, message: &str) -> Response<FxBody> {
    Response::builder()
        .status(200)
        .header("content-type", "application/grpc")
        .header("grpc-status", code.to_string())
        .header("grpc-message", HeaderValue::from_str(message).unwrap_or(HeaderValue::from_static("error")))
        .body(full(Bytes::new()))
        .unwrap()
}

fn unary(msg: &impl Message) -> Response<FxBody> {
    let (mut tx, rx) = futures::channel::mpsc::channel::<Result<Frame<Bytes>, std::io::Error>>(2);
    let data = frame(msg);
    tokio::spawn(async move {
        use futures::SinkExt;
        let _ = tx.send(Ok(Frame::data(data))).await;
        let mut t = HeaderMap::new();
        t.insert("grpc-status", HeaderValue::from_static("0"));
        let _ = tx.send(Ok(Frame::trailers(t))).await;
    });
    Response::builder().status(200).header("content-type", "application/grpc").body(BodyExt::boxed(StreamBody::new(rx))).unwrap()
}

/// First stream response, then the stream stays open (as a rotating server's
/// does) until the client goes away or a minute passes.
fn stream_first(msg: &impl Message) -> Response<FxBody> {
    let (mut tx, rx) = futures::channel::mpsc::channel::<Result<Frame<Bytes>, std::io::Error>>(2);
    let data = frame(msg);
    tokio::spawn(async move {
        use futures::SinkExt;
        if tx.send(Ok(Frame::data(data))).await.is_err() {
            return;
        }
        for _ in 0..600 {
            if tx.is_closed() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    });
    Response::builder().status(200).header("content-type", "application/grpc").body(BodyExt::boxed(StreamBody::new(rx))).unwrap()
}

async fn handle(req: Request<Incoming>, keys: Arc<Keys>, state: Arc<Mutex<State>>, log: GroundTruthLog) -> Response<FxBody> {
    let rpc = req.uri().path().strip_prefix("/SpiffeWorkloadAPI/").unwrap_or("").to_string();
    let metadata = req.headers().get("workload.spiffe.io").and_then(|v| v.to_str().ok()) == Some("true");
    let body = Limited::new(req.into_body(), 1 << 20).collect().await.map(|b| b.to_bytes()).unwrap_or_default();
    let payload = if body.len() >= 5 { body.slice(5..) } else { Bytes::new() };
    let (mode, identities, x509_ttl, jwt_ttl) = {
        let s = state.lock();
        (s.mode, s.identities.clone(), s.x509_ttl, s.jwt_ttl_secs)
    };
    let mut audiences = vec![];
    let mut requested = String::new();
    let record = |answer: &str, audiences: Vec<String>, requested: String| {
        log.push(GroundTruth::WorkloadApiCall { rpc: rpc.clone(), metadata, audiences, spiffe_id: requested, answer: answer.into() });
    };
    if !metadata {
        record("INVALID_ARGUMENT", vec![], String::new());
        return status(3, "missing required workload.spiffe.io: true metadata");
    }
    if mode == Mode::Hang {
        record("HANG", vec![], String::new());
        tokio::time::sleep(Duration::from_secs(60)).await;
        return status(14, "fixture hang ended");
    }
    let is_jwt = rpc == "FetchJWTSVID" || rpc == "FetchJWTBundles";
    if is_jwt && mode == Mode::JwtUnimplemented {
        record("UNIMPLEMENTED", vec![], String::new());
        return status(12, "the active identity backend cannot mint JWT-SVIDs; only X.509-SVIDs are available on this Workload API");
    }
    let resp = match rpc.as_str() {
        "FetchX509SVID" => match mode {
            Mode::Deny => status(7, "workload attestation failed"),
            Mode::NoIdentity => stream_first(&X509SvidResponseMsg::default()),
            _ => {
                let mut svids = vec![];
                for id in &identities {
                    let (cert, key) = mint_leaf(&keys.ca, id, x509_ttl);
                    svids.push(X509SvidMsg {
                        spiffe_id: id.clone(),
                        x509_svid: cert,
                        x509_svid_key: key.serialize_der(),
                        bundle: keys.ca_der.clone(),
                        hint: String::new(),
                    });
                }
                let federated = {
                    let mut s = state.lock();
                    s.issued_x509 += 1;
                    s.federated.iter().cloned().collect()
                };
                stream_first(&X509SvidResponseMsg { svids, crl: vec![], federated_bundles: federated })
            }
        },
        "FetchJWTSVID" => {
            let r = JwtSvidRequestMsg::decode(payload.as_ref()).unwrap_or_default();
            audiences = r.audience.clone();
            requested = r.spiffe_id.clone();
            if mode == Mode::Deny {
                status(7, "workload attestation failed")
            } else if r.audience.is_empty() {
                status(3, "at least one audience is required")
            } else if !r.spiffe_id.is_empty() && !identities.contains(&r.spiffe_id) {
                status(7, "requested SPIFFE ID is not authorized for this workload")
            } else if mode == Mode::NoIdentity {
                unary(&JwtSvidResponseMsg::default())
            } else {
                let sub = if r.spiffe_id.is_empty() { identities.first().cloned().unwrap_or_default() } else { r.spiffe_id.clone() };
                let token = sign_jwt(&keys, &sub, &r.audience, jwt_ttl);
                unary(&JwtSvidResponseMsg { svids: vec![JwtSvidMsg { spiffe_id: sub, svid: token, hint: String::new() }] })
            }
        }
        "FetchJWTBundles" => {
            let mut bundles = HashMap::new();
            bundles.insert(format!("spiffe://{TRUST_DOMAIN}"), keys.jwks.clone());
            stream_first(&JwtBundlesResponseMsg { bundles })
        }
        _ => status(12, "unknown method"),
    };
    let answer =
        resp.headers().get("grpc-status").and_then(|v| v.to_str().ok()).map(|c| format!("status {c}")).unwrap_or_else(|| "OK".to_string());
    record(&answer, audiences, requested);
    resp
}
