//! SPIFFE Workload API client: the standard `SpiffeWorkloadAPI` service
//! (`workload.proto` in the SPIFFE specifications, as served by SPIRE
//! agents and by Ferrum Edge's in-process Workload API), spoken as gRPC over
//! HTTP/2 on a local Unix domain socket — or a named pipe on Windows.
//!
//! * **Endpoint.** `unix:///path/to/socket` (the SPIFFE Workload Endpoint
//!   URI form; `unix:/path` is accepted too) from the profile, else from the
//!   `SPIFFE_ENDPOINT_SOCKET` environment variable. `npipe:<name>` is a
//!   Windows named pipe (`\\.\pipe\<name>`). `tcp://` endpoints are refused:
//!   a TCP peer carries no kernel credentials, so the server could not
//!   attest the caller.
//! * **Every call** carries the mandatory `workload.spiffe.io: true`
//!   metadata (servers reject a call without it), `grpc-timeout`, and runs
//!   on a fresh connection under one deadline. The service has no proto
//!   package, so the paths are `/SpiffeWorkloadAPI/<Method>`.
//! * **Streams.** `FetchX509SVID` and `FetchJWTBundles` are server streams
//!   that push rotations for as long as the client listens. Anvil reads the
//!   first response and cancels the stream; a later execution re-fetches.
//! * **Typed outcomes.** Connect failures (no socket, permission, nothing
//!   listening), a deadline, a non-OK gRPC status (with its bounded
//!   `grpc-message`), an OK answer without an identity, and undecodable
//!   answers are distinct errors. The server's message text is displayed,
//!   never interpreted.
//! * **Secrets.** SVID private keys and JWT-SVIDs are returned in
//!   `Zeroizing` buffers and the decoded protobuf copies are wiped. Nothing
//!   here logs or records them.
//!
//! The protobuf messages below are transcribed from the upstream
//! `workload.proto` (field numbers and types identical). Ferrum Edge's copy
//! differs only in `ValidateJWTSVIDResponse.claims`, which Anvil does not use:
//! JWT-SVIDs are checked locally against the bundles from `FetchJWTBundles`.

use crate::connector::BoxIo;
use crate::errors::display_chain;
use anvil_domain::workload::{SPIFFE_ENDPOINT_SOCKET, WorkloadCallResult, WorkloadEndpointSource, WorkloadRpc, grpc_code_name};
use base64::Engine as _;
use bytes::{Buf, Bytes, BytesMut};
use chrono::{DateTime, Utc};
use http::{Method, Request};
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http2;
use hyper_util::rt::{TokioExecutor, TokioIo};
use prost::Message;
use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, Instant};
use zeroize::{Zeroize, Zeroizing};

/// Mandatory request metadata (SPIFFE Workload API §5.1).
pub const WORKLOAD_METADATA_KEY: &str = "workload.spiffe.io";
pub const WORKLOAD_METADATA_VALUE: &str = "true";
const SERVICE_PATH: &str = "/SpiffeWorkloadAPI/";
/// Largest Workload API message Anvil accepts.
const MAX_MESSAGE_BYTES: usize = 4 * 1024 * 1024;
/// Largest JWT-SVID accepted from the endpoint.
const MAX_JWT_SVID_BYTES: usize = 16 * 1024;
/// Largest JWKS document accepted per trust domain.
const MAX_JWT_BUNDLE_BYTES: usize = 64 * 1024;
/// Default deadline for one Workload API call.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

// ------------------------------------------------------------ messages ---

#[derive(Clone, PartialEq, prost::Message)]
pub struct X509SvidRequest {}

#[derive(Clone, PartialEq, prost::Message)]
pub struct X509SvidResponse {
    #[prost(message, repeated, tag = "1")]
    pub svids: Vec<X509Svid>,
    #[prost(bytes = "vec", repeated, tag = "2")]
    pub crl: Vec<Vec<u8>>,
    #[prost(map = "string, bytes", tag = "3")]
    pub federated_bundles: HashMap<String, Vec<u8>>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct X509Svid {
    #[prost(string, tag = "1")]
    pub spiffe_id: String,
    /// ASN.1 DER certificate chain, leaf first.
    #[prost(bytes = "vec", tag = "2")]
    pub x509_svid: Vec<u8>,
    /// ASN.1 DER PKCS#8 private key.
    #[prost(bytes = "vec", tag = "3")]
    pub x509_svid_key: Vec<u8>,
    /// ASN.1 DER CA certificates of the SVID's trust domain.
    #[prost(bytes = "vec", tag = "4")]
    pub bundle: Vec<u8>,
    #[prost(string, tag = "5")]
    pub hint: String,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct JwtSvidRequest {
    #[prost(string, repeated, tag = "1")]
    pub audience: Vec<String>,
    #[prost(string, tag = "2")]
    pub spiffe_id: String,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct JwtSvidResponse {
    #[prost(message, repeated, tag = "1")]
    pub svids: Vec<JwtSvid>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct JwtSvid {
    #[prost(string, tag = "1")]
    pub spiffe_id: String,
    #[prost(string, tag = "2")]
    pub svid: String,
    #[prost(string, tag = "3")]
    pub hint: String,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct JwtBundlesRequest {}

#[derive(Clone, PartialEq, prost::Message)]
pub struct JwtBundlesResponse {
    #[prost(map = "string, bytes", tag = "1")]
    pub bundles: HashMap<String, Vec<u8>>,
}

// ------------------------------------------------------------ endpoint ---

/// Where the Workload API listens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EndpointAddress {
    /// Unix domain socket path (absolute).
    Unix(std::path::PathBuf),
    /// Windows named pipe, as `\\.\pipe\<name>`.
    NamedPipe(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    /// The URI as configured (`unix:///run/spire/agent.sock`).
    pub uri: String,
    pub source: WorkloadEndpointSource,
    pub address: EndpointAddress,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EndpointError {
    #[error(
        "no Workload API endpoint is configured and the {SPIFFE_ENDPOINT_SOCKET} environment variable is not set; set the endpoint (for example unix:///run/spire/sockets/agent.sock)"
    )]
    NotConfigured,
    #[error("{0}")]
    Invalid(String),
    /// Valid but not usable on this platform or by design (`tcp://`).
    #[error("{0}")]
    Unsupported(String),
}

/// The endpoint from the profile, else from `SPIFFE_ENDPOINT_SOCKET`.
pub fn resolve_endpoint(configured: &str) -> Result<Endpoint, EndpointError> {
    resolve_endpoint_with(configured, std::env::var(SPIFFE_ENDPOINT_SOCKET).ok())
}

/// [`resolve_endpoint`] with the environment value passed in (testable).
pub fn resolve_endpoint_with(configured: &str, env: Option<String>) -> Result<Endpoint, EndpointError> {
    let (uri, source) = match configured.trim() {
        "" => match env.map(|v| v.trim().to_string()).filter(|v| !v.is_empty()) {
            Some(v) => (v, WorkloadEndpointSource::Environment),
            None => return Err(EndpointError::NotConfigured),
        },
        s => (s.to_string(), WorkloadEndpointSource::Setting),
    };
    let address = parse_address(&uri)?;
    Ok(Endpoint { uri, source, address })
}

/// Parse a Workload API endpoint URI (SPIFFE Workload Endpoint §4).
pub fn parse_address(uri: &str) -> Result<EndpointAddress, EndpointError> {
    let s = uri.trim();
    let invalid = |why: &str| EndpointError::Invalid(format!("'{s}' is not a Workload API endpoint: {why}"));
    let Some((scheme, rest)) = s.split_once(':') else {
        return Err(invalid("it has no scheme; use unix:///path/to/socket"));
    };
    match scheme.to_ascii_lowercase().as_str() {
        "unix" => {
            // `unix:///path` (empty authority) or `unix:/path`.
            let path = match rest.strip_prefix("//") {
                Some(after) if after.starts_with('/') => after,
                Some(_) => return Err(invalid("a unix endpoint has no host part; use unix:///absolute/path")),
                None => rest,
            };
            if path.contains(['?', '#']) {
                return Err(invalid("a unix endpoint has no query or fragment"));
            }
            if !path.starts_with('/') || path.len() < 2 {
                return Err(invalid("the socket path must be absolute"));
            }
            if cfg!(windows) {
                return Err(EndpointError::Unsupported(format!(
                    "'{s}' is a Unix domain socket; on Windows the Workload API (SPIRE) listens on a named pipe: use npipe:<name>"
                )));
            }
            Ok(EndpointAddress::Unix(std::path::PathBuf::from(path)))
        }
        "npipe" => {
            let name = rest.trim_start_matches("//");
            if name.is_empty() || name.contains(['?', '#']) {
                return Err(invalid("a named pipe endpoint is npipe:<pipe name>"));
            }
            if !cfg!(windows) {
                return Err(EndpointError::Unsupported(format!(
                    "'{s}' is a Windows named pipe; on this platform the Workload API listens on a Unix domain socket: use unix:///path/to/socket"
                )));
            }
            let name = name.trim_start_matches(r"\\.\pipe\");
            Ok(EndpointAddress::NamedPipe(format!(r"\\.\pipe\{name}")))
        }
        "tcp" => Err(EndpointError::Unsupported(format!(
            "'{s}' is a TCP endpoint; Anvil connects to the Workload API only on a local Unix socket (or Windows named pipe), where the server can attest the caller from its kernel peer credentials"
        ))),
        _ => Err(invalid("the scheme must be unix (or npipe on Windows)")),
    }
}

// --------------------------------------------------------------- errors ---

/// Why a Workload API call did not produce what was asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallError {
    /// Could not connect or complete the HTTP/2 exchange.
    Unavailable {
        detail: String,
        io_error_kind: Option<String>,
    },
    Timeout {
        deadline_ms: u64,
    },
    /// Non-OK gRPC status; `message` is the bounded, decoded `grpc-message`.
    Status {
        code: i32,
        message: String,
    },
    /// OK, but no usable identity.
    NoIdentity(String),
    /// The answer is not a valid Workload API message.
    Malformed(String),
}

impl CallError {
    pub fn to_result(&self) -> WorkloadCallResult {
        match self {
            CallError::Unavailable { detail, io_error_kind } => {
                WorkloadCallResult::Unavailable { detail: detail.clone(), io_error_kind: io_error_kind.clone() }
            }
            CallError::Timeout { deadline_ms } => WorkloadCallResult::Timeout { deadline_ms: *deadline_ms },
            CallError::Status { code, message } => {
                WorkloadCallResult::Status { code: *code, code_name: grpc_code_name(*code).to_string(), message: message.clone() }
            }
            CallError::NoIdentity(d) => WorkloadCallResult::NoIdentity { detail: d.clone() },
            CallError::Malformed(d) => WorkloadCallResult::Malformed { detail: d.clone() },
        }
    }
}

impl std::fmt::Display for CallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CallError::Unavailable { detail, .. } => write!(f, "{detail}"),
            CallError::Timeout { deadline_ms } => write!(f, "the Workload API did not answer within {deadline_ms} ms"),
            CallError::Status { code, message } if message.is_empty() => {
                write!(f, "the Workload API answered {} ({code})", grpc_code_name(*code))
            }
            CallError::Status { code, message } => {
                write!(f, "the Workload API answered {} ({code}): \"{message}\"", grpc_code_name(*code))
            }
            CallError::NoIdentity(d) | CallError::Malformed(d) => write!(f, "{d}"),
        }
    }
}

/// Bounded, printable `grpc-message` (untrusted text).
fn clean_message(raw: &str) -> String {
    let decoded = crate::grpc::percent_decode(raw);
    let cleaned: String = decoded.chars().filter(|c| !c.is_control()).collect();
    if cleaned.chars().count() > 300 { format!("{}…", cleaned.chars().take(300).collect::<String>()) } else { cleaned }
}

// --------------------------------------------------------------- results ---

/// One X.509-SVID as returned, converted to PEM for the TLS layer.
pub struct FetchedX509Svid {
    pub spiffe_id: String,
    /// Leaf first, then any intermediates, as PEM.
    pub cert_chain_pem: String,
    pub chain_length: usize,
    pub leaf_der: Vec<u8>,
    /// PKCS#8 PEM. Secret.
    pub private_key_pem: Zeroizing<String>,
    /// The trust domain's CA certificates, one PEM each.
    pub bundle_pem: Vec<String>,
    pub hint: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
}

impl std::fmt::Debug for FetchedX509Svid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FetchedX509Svid")
            .field("spiffe_id", &self.spiffe_id)
            .field("chain_length", &self.chain_length)
            .field("private_key_pem", &"‹redacted›")
            .field("not_after", &self.not_after)
            .finish()
    }
}

#[derive(Debug)]
pub struct X509Fetch {
    /// In the endpoint's order; the first is the default identity.
    pub svids: Vec<FetchedX509Svid>,
    /// Trust domains of the federated bundles that came with the answer.
    pub federated_trust_domains: Vec<String>,
}

pub struct FetchedJwtSvid {
    pub spiffe_id: String,
    /// The token. Secret.
    pub token: Zeroizing<String>,
    pub hint: String,
}

impl std::fmt::Debug for FetchedJwtSvid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FetchedJwtSvid").field("spiffe_id", &self.spiffe_id).field("token", &"‹redacted›").finish()
    }
}

/// Outcome of one call plus how long it took (for evidence).
pub struct Timed<T> {
    pub result: Result<T, CallError>,
    pub duration: Duration,
}

// --------------------------------------------------------------- client ---

pub struct WorkloadClient {
    endpoint: Endpoint,
    timeout: Duration,
}

impl WorkloadClient {
    pub fn new(endpoint: Endpoint, timeout: Duration) -> Self {
        WorkloadClient { endpoint, timeout }
    }

    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// `FetchX509SVID`: the first response of the stream.
    pub async fn fetch_x509_svids(&self) -> Timed<X509Fetch> {
        let started = Instant::now();
        let result = async {
            let mut raw = self.call(WorkloadRpc::FetchX509Svid, X509SvidRequest {}.encode_to_vec(), true).await?;
            let decoded = X509SvidResponse::decode(raw.as_slice());
            raw.zeroize();
            let mut resp =
                decoded.map_err(|e| CallError::Malformed(format!("the FetchX509SVID answer is not an X509SVIDResponse: {e}")))?;
            let out = convert_x509(&mut resp);
            for s in &mut resp.svids {
                s.x509_svid_key.zeroize();
            }
            out
        }
        .await;
        Timed { result, duration: started.elapsed() }
    }

    /// `FetchJWTSVID` for `audiences` (and optionally one SPIFFE ID).
    pub async fn fetch_jwt_svid(&self, audiences: &[String], spiffe_id: Option<&str>) -> Timed<FetchedJwtSvid> {
        let started = Instant::now();
        let result = async {
            let req = JwtSvidRequest { audience: audiences.to_vec(), spiffe_id: spiffe_id.unwrap_or_default().to_string() };
            let mut raw = self.call(WorkloadRpc::FetchJwtSvid, req.encode_to_vec(), false).await?;
            let decoded = JwtSvidResponse::decode(raw.as_slice());
            raw.zeroize();
            let mut resp = decoded.map_err(|e| CallError::Malformed(format!("the FetchJWTSVID answer is not a JWTSVIDResponse: {e}")))?;
            let pos = match spiffe_id {
                Some(want) => resp.svids.iter().position(|s| s.spiffe_id == want),
                None => (!resp.svids.is_empty()).then_some(0),
            };
            let result = match pos {
                None if resp.svids.is_empty() => Err(CallError::NoIdentity("the Workload API returned no JWT-SVID".into())),
                None => Err(CallError::NoIdentity(format!(
                    "the Workload API returned no JWT-SVID for {}; it returned {}",
                    spiffe_id.unwrap_or_default(),
                    resp.svids.iter().map(|s| s.spiffe_id.as_str()).collect::<Vec<_>>().join(", ")
                ))),
                Some(i) => {
                    let s = &mut resp.svids[i];
                    if s.svid.is_empty() || s.svid.len() > MAX_JWT_SVID_BYTES {
                        Err(CallError::Malformed(format!("the JWT-SVID is empty or larger than {MAX_JWT_SVID_BYTES} bytes")))
                    } else {
                        Ok(FetchedJwtSvid {
                            spiffe_id: s.spiffe_id.clone(),
                            token: Zeroizing::new(std::mem::take(&mut s.svid)),
                            hint: s.hint.clone(),
                        })
                    }
                }
            };
            for s in &mut resp.svids {
                s.svid.zeroize();
            }
            result
        }
        .await;
        Timed { result, duration: started.elapsed() }
    }

    /// `FetchJWTBundles`: JWKS documents keyed by trust domain name.
    pub async fn fetch_jwt_bundles(&self) -> Timed<BTreeMap<String, Vec<u8>>> {
        let started = Instant::now();
        let result = async {
            let raw = self.call(WorkloadRpc::FetchJwtBundles, JwtBundlesRequest {}.encode_to_vec(), true).await?;
            let resp = JwtBundlesResponse::decode(raw.as_slice())
                .map_err(|e| CallError::Malformed(format!("the FetchJWTBundles answer is not a JWTBundlesResponse: {e}")))?;
            let mut out = BTreeMap::new();
            for (key, jwks) in resp.bundles {
                let td = crate::spiffe::parse_trust_domain(&key)
                    .map_err(|e| CallError::Malformed(format!("a JWT bundle is keyed by '{key}', not a trust domain: {e}")))?;
                if jwks.len() > MAX_JWT_BUNDLE_BYTES {
                    return Err(CallError::Malformed(format!("the JWT bundle for {td} is larger than {MAX_JWT_BUNDLE_BYTES} bytes")));
                }
                out.insert(td, jwks);
            }
            if out.is_empty() {
                return Err(CallError::NoIdentity("the Workload API returned no JWT bundle".into()));
            }
            Ok(out)
        }
        .await;
        Timed { result, duration: started.elapsed() }
    }

    async fn call(&self, rpc: WorkloadRpc, request: Vec<u8>, streaming: bool) -> Result<Vec<u8>, CallError> {
        let deadline_ms = self.timeout.as_millis() as u64;
        match tokio::time::timeout(self.timeout, self.call_inner(rpc, request, streaming)).await {
            Ok(r) => r,
            Err(_) => Err(CallError::Timeout { deadline_ms }),
        }
    }

    async fn connect(&self) -> Result<BoxIo, CallError> {
        match &self.endpoint.address {
            #[cfg(unix)]
            EndpointAddress::Unix(path) => match tokio::net::UnixStream::connect(path).await {
                Ok(s) => Ok(Box::new(s)),
                Err(e) => Err(connect_error(&path.display().to_string(), &e)),
            },
            #[cfg(windows)]
            EndpointAddress::NamedPipe(name) => pipe::connect(name).await.map_err(|e| connect_error(name, &e)),
            #[allow(unreachable_patterns)]
            other => Err(CallError::Unavailable {
                detail: format!("{other:?} endpoints are not available on this platform"),
                io_error_kind: None,
            }),
        }
    }

    async fn call_inner(&self, rpc: WorkloadRpc, request: Vec<u8>, streaming: bool) -> Result<Vec<u8>, CallError> {
        let io = self.connect().await?;
        let (mut sender, conn) =
            http2::Builder::new(TokioExecutor::new()).handshake::<_, Full<Bytes>>(TokioIo::new(io)).await.map_err(|e| {
                CallError::Unavailable {
                    detail: format!(
                        "{} accepted the connection but no HTTP/2 gRPC session started: {}",
                        self.endpoint.uri,
                        display_chain(&e)
                    ),
                    io_error_kind: None,
                }
            })?;
        let conn_task = tokio::spawn(async move {
            let _ = conn.await;
        });
        let result = exchange(&mut sender, rpc, request, streaming, self.timeout).await;
        // Dropping the sender and the connection task ends the connection
        // (a cancelled stream for the long-lived RPCs).
        drop(sender);
        conn_task.abort();
        result
    }
}

fn connect_error(target: &str, e: &std::io::Error) -> CallError {
    use std::io::ErrorKind as K;
    let detail = match e.kind() {
        K::NotFound => format!("no Workload API socket exists at {target}"),
        K::PermissionDenied => {
            format!("permission denied connecting to {target}: the socket's owner, group or mode does not admit this user")
        }
        K::ConnectionRefused => format!("nothing is listening on {target} (a stale socket file, or the Workload API is not running)"),
        _ => format!("could not connect to {target}: {e}"),
    };
    CallError::Unavailable { detail, io_error_kind: Some(crate::errors::io_kind_name(e.kind())) }
}

fn grpc_timeout(d: Duration) -> String {
    crate::grpc::grpc_timeout(d.as_millis() as u64)
}

fn status_of(h: &http::HeaderMap) -> Option<(i32, String)> {
    let code = h.get("grpc-status")?.to_str().ok()?.trim().parse::<i32>().ok()?;
    let message = h.get("grpc-message").and_then(|v| v.to_str().ok()).map(clean_message).unwrap_or_default();
    Some((code, message))
}

/// Send one request and read the first (streaming) or only (unary) message.
async fn exchange(
    sender: &mut http2::SendRequest<Full<Bytes>>,
    rpc: WorkloadRpc,
    request: Vec<u8>,
    streaming: bool,
    timeout: Duration,
) -> Result<Vec<u8>, CallError> {
    let mut framed = BytesMut::with_capacity(5 + request.len());
    framed.extend_from_slice(&[0]);
    framed.extend_from_slice(&(request.len() as u32).to_be_bytes());
    framed.extend_from_slice(&request);
    let req = Request::builder()
        .method(Method::POST)
        .uri(format!("http://localhost{SERVICE_PATH}{}", rpc.method()))
        .header(http::header::CONTENT_TYPE, "application/grpc")
        .header(http::header::TE, "trailers")
        .header(WORKLOAD_METADATA_KEY, WORKLOAD_METADATA_VALUE)
        .header("grpc-timeout", grpc_timeout(timeout))
        .header(http::header::USER_AGENT, concat!("grpc-anvil/", env!("CARGO_PKG_VERSION")))
        .body(Full::new(framed.freeze()))
        .map_err(|e| CallError::Malformed(format!("the request could not be built: {e}")))?;
    let resp = sender.send_request(req).await.map_err(|e| CallError::Unavailable {
        detail: format!("the Workload API closed the connection before answering {}: {}", rpc.method(), display_chain(&e)),
        io_error_kind: None,
    })?;
    let (head, mut body) = resp.into_parts();
    // Trailers-only answer: the status is in the response headers.
    if let Some((code, message)) = status_of(&head.headers) {
        return if code != 0 {
            Err(CallError::Status { code, message })
        } else {
            Err(CallError::Malformed(format!("{} answered OK without a message", rpc.method())))
        };
    }
    if head.status != http::StatusCode::OK {
        return Err(CallError::Malformed(format!("the endpoint answered HTTP {} instead of a gRPC response", head.status.as_u16())));
    }
    let ct = head.headers.get(http::header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or("");
    if !ct.starts_with("application/grpc") {
        return Err(CallError::Malformed(format!("the endpoint answered content-type '{ct}' instead of application/grpc")));
    }
    let mut buf = BytesMut::new();
    let mut message: Option<Vec<u8>> = None;
    loop {
        match body.frame().await {
            Some(Ok(frame)) => {
                if frame.is_trailers() {
                    let trailers = frame.into_trailers().unwrap_or_default();
                    buf.zeroize();
                    return match status_of(&trailers) {
                        Some((0, _)) => {
                            message.ok_or_else(|| CallError::Malformed(format!("{} ended with status OK but no message", rpc.method())))
                        }
                        Some((code, msg)) => {
                            if let Some(mut m) = message {
                                m.zeroize();
                            }
                            Err(CallError::Status { code, message: msg })
                        }
                        None => Err(CallError::Malformed(format!("{} ended without a grpc-status", rpc.method()))),
                    };
                }
                let Ok(data) = frame.into_data() else { continue };
                buf.extend_from_slice(&data);
                if buf.len() >= 5 {
                    if buf[0] != 0 {
                        return Err(CallError::Malformed("the Workload API sent a compressed or invalid gRPC frame".into()));
                    }
                    let len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
                    if len > MAX_MESSAGE_BYTES {
                        return Err(CallError::Malformed(format!("a Workload API message of {len} bytes exceeds {MAX_MESSAGE_BYTES}")));
                    }
                    if buf.len() >= 5 + len {
                        buf.advance(5);
                        let m = buf.split_to(len).to_vec();
                        if streaming {
                            buf.zeroize();
                            return Ok(m);
                        }
                        if message.is_some() {
                            return Err(CallError::Malformed(format!("{} is unary but the endpoint sent several messages", rpc.method())));
                        }
                        message = Some(m);
                    }
                }
            }
            Some(Err(e)) => {
                buf.zeroize();
                return Err(CallError::Unavailable {
                    detail: format!("the {} answer was cut off: {}", rpc.method(), display_chain(&e)),
                    io_error_kind: None,
                });
            }
            None => {
                buf.zeroize();
                return Err(CallError::Malformed(format!("{} ended without a grpc-status", rpc.method())));
            }
        }
    }
}

// ------------------------------------------------------------ X.509 ---

/// Split concatenated ASN.1 DER certificates.
pub fn split_der_certificates(mut data: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    let mut out = Vec::new();
    while !data.is_empty() {
        if data[0] != 0x30 || data.len() < 2 {
            return Err("not a DER certificate sequence".into());
        }
        let (len, header) = match data[1] {
            n if n < 0x80 => (n as usize, 2),
            0x81..=0x84 => {
                let k = (data[1] & 0x7f) as usize;
                if data.len() < 2 + k {
                    return Err("truncated DER length".into());
                }
                (data[2..2 + k].iter().fold(0usize, |acc, b| (acc << 8) | *b as usize), 2 + k)
            }
            _ => return Err("unsupported DER length encoding".into()),
        };
        let total = header.checked_add(len).ok_or("DER length overflow")?;
        if data.len() < total {
            return Err("truncated DER certificate".into());
        }
        out.push(data[..total].to_vec());
        data = &data[total..];
    }
    Ok(out)
}

fn pem(label: &str, der: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut s = format!("-----BEGIN {label}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        s.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        s.push('\n');
    }
    s.push_str(&format!("-----END {label}-----\n"));
    s
}

fn validity(der: &[u8]) -> Result<(DateTime<Utc>, DateTime<Utc>), String> {
    use x509_parser::prelude::*;
    let (_, cert) = X509Certificate::from_der(der).map_err(|e| e.to_string())?;
    let v = cert.validity();
    let nb = DateTime::from_timestamp(v.not_before.timestamp(), 0).ok_or("invalid notBefore")?;
    let na = DateTime::from_timestamp(v.not_after.timestamp(), 0).ok_or("invalid notAfter")?;
    Ok((nb, na))
}

fn convert_x509(resp: &mut X509SvidResponse) -> Result<X509Fetch, CallError> {
    if resp.svids.is_empty() {
        return Err(CallError::NoIdentity("the Workload API returned no X.509-SVID".into()));
    }
    let mut svids = Vec::with_capacity(resp.svids.len());
    for s in &mut resp.svids {
        let bad = |why: String| CallError::Malformed(format!("the X.509-SVID for '{}' is not usable: {why}", s.spiffe_id));
        let chain = split_der_certificates(&s.x509_svid).map_err(|e| bad(format!("its certificate chain: {e}")))?;
        let leaf = chain.first().ok_or_else(|| bad("the certificate chain is empty".into()))?.clone();
        let id = crate::spiffe::svid_id(&leaf).map_err(|p| bad(p.describe()))?;
        if id.as_uri() != s.spiffe_id {
            return Err(bad(format!("the certificate names {}, not the SPIFFE ID the answer states", id.as_uri())));
        }
        if s.x509_svid_key.is_empty() {
            return Err(bad("the private key is missing".into()));
        }
        let (not_before, not_after) = validity(&leaf).map_err(|e| bad(format!("its validity: {e}")))?;
        let bundle = split_der_certificates(&s.bundle).map_err(|e| bad(format!("its trust bundle: {e}")))?;
        svids.push(FetchedX509Svid {
            spiffe_id: s.spiffe_id.clone(),
            cert_chain_pem: chain.iter().map(|c| pem("CERTIFICATE", c)).collect(),
            chain_length: chain.len(),
            leaf_der: leaf,
            private_key_pem: Zeroizing::new(pem("PRIVATE KEY", &s.x509_svid_key)),
            bundle_pem: bundle.iter().map(|c| pem("CERTIFICATE", c)).collect(),
            hint: s.hint.clone(),
            not_before,
            not_after,
        });
    }
    let mut federated: Vec<String> =
        resp.federated_bundles.keys().map(|k| crate::spiffe::parse_trust_domain(k).unwrap_or_else(|_| k.clone())).collect();
    federated.sort();
    Ok(X509Fetch { svids, federated_trust_domains: federated })
}

// ---------------------------------------------------------- named pipe ---

#[cfg(windows)]
mod pipe {
    use crate::connector::BoxIo;
    use std::time::Duration;
    use tokio::net::windows::named_pipe::ClientOptions;

    /// `ERROR_PIPE_BUSY`: every server instance is in use; retry briefly.
    const ERROR_PIPE_BUSY: i32 = 231;

    pub async fn connect(name: &str) -> std::io::Result<BoxIo> {
        loop {
            match ClientOptions::new().open(name) {
                Ok(c) => return Ok(Box::new(c)),
                Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) => tokio::time::sleep(Duration::from_millis(50)).await,
                Err(e) => return Err(e),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_uris() {
        if cfg!(unix) {
            assert_eq!(parse_address("unix:///run/spire/agent.sock").unwrap(), EndpointAddress::Unix("/run/spire/agent.sock".into()));
            assert_eq!(parse_address("unix:/tmp/wl.sock").unwrap(), EndpointAddress::Unix("/tmp/wl.sock".into()));
            assert!(matches!(parse_address("npipe:spire-agent"), Err(EndpointError::Unsupported(_))));
        } else if cfg!(windows) {
            assert_eq!(parse_address("npipe:spire-agent").unwrap(), EndpointAddress::NamedPipe(r"\\.\pipe\spire-agent".into()));
            assert!(matches!(parse_address("unix:///run/spire/agent.sock"), Err(EndpointError::Unsupported(_))));
        }
        for bad in ["/run/spire/agent.sock", "unix://host/run/a.sock", "unix:relative.sock", "unix:///a.sock?x=1", "http://x", "unix:"] {
            assert!(matches!(parse_address(bad), Err(EndpointError::Invalid(_))), "{bad}");
        }
        assert!(matches!(parse_address("tcp://127.0.0.1:8081"), Err(EndpointError::Unsupported(_))));
    }

    #[test]
    fn endpoint_resolution_prefers_the_setting_then_the_environment() {
        // Each platform's native endpoint kind (Unix socket, or named pipe on Windows).
        let (setting, env) =
            if cfg!(windows) { ("npipe:spire-agent", "npipe:env-agent") } else { ("unix:///a/b.sock", "unix:///env.sock") };
        let e = resolve_endpoint_with(setting, Some(env.into())).unwrap();
        assert_eq!((e.uri.as_str(), e.source), (setting, WorkloadEndpointSource::Setting));
        let e = resolve_endpoint_with("  ", Some(env.into())).unwrap();
        assert_eq!((e.uri.as_str(), e.source), (env, WorkloadEndpointSource::Environment));
        assert_eq!(resolve_endpoint_with("", None), Err(EndpointError::NotConfigured));
        assert_eq!(resolve_endpoint_with("", Some(" ".into())), Err(EndpointError::NotConfigured));
    }

    #[test]
    fn der_certificate_sequences_split_exactly() {
        let a = [0x30, 0x03, 1, 2, 3];
        let mut long = vec![0x30, 0x81, 0x80];
        long.extend(std::iter::repeat_n(7u8, 0x80));
        let joined: Vec<u8> = a.iter().copied().chain(long.iter().copied()).collect();
        let parts = split_der_certificates(&joined).unwrap();
        assert_eq!(parts, vec![a.to_vec(), long.clone()]);
        assert!(split_der_certificates(&[]).unwrap().is_empty());
        assert!(split_der_certificates(&[0x30, 0x05, 1]).is_err(), "truncated");
        assert!(split_der_certificates(&[0x04, 0x01, 1]).is_err(), "not a SEQUENCE");
    }

    #[test]
    fn grpc_messages_are_bounded_and_printable() {
        assert_eq!(clean_message("workload%20attestation%20failed"), "workload attestation failed");
        assert_eq!(clean_message("a\u{7}b"), "ab");
        assert!(clean_message(&"x".repeat(500)).chars().count() <= 301);
    }

    #[test]
    fn call_errors_map_to_typed_results() {
        let r = CallError::Status { code: 7, message: "denied".into() }.to_result();
        assert_eq!(r, WorkloadCallResult::Status { code: 7, code_name: "PERMISSION_DENIED".into(), message: "denied".into() });
        assert!(CallError::Timeout { deadline_ms: 5 }.to_string().contains("5 ms"));
    }
}
