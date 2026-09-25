//! gRPC over HTTP/2 (TLS with ALPN `h2`, or h2c with prior knowledge).
//!
//! * Length-prefixed message framing with message boundaries preserved in
//!   the transcript (each message decoded to JSON with the method's type).
//! * `content-type: application/grpc`, `te: trailers`, `grpc-timeout` from
//!   the configured deadline (also enforced locally: when it elapses Anvil
//!   cancels the stream and records that no status was received — it never
//!   fabricates `DEADLINE_EXCEEDED`).
//! * Terminal status from trailers, or from the response headers of a
//!   trailers-only response; `grpc-message` is percent-decoded and
//!   `grpc-status-details-bin` is decoded as `google.rpc.Status`. A missing
//!   status is recorded as missing: HTTP 200 alone is never an RPC success.
//! * Dynamic messages via `prost-reflect`: descriptors from `.proto` sources
//!   compiled in-process by `protox` (imports resolved only among the
//!   provided files plus the bundled well-known types), a serialized
//!   `FileDescriptorSet`, or server reflection (`grpc.reflection.v1`, falling
//!   back to `v1alpha` when v1 is unimplemented).
//! * Unary, client-streaming, server-streaming and bidirectional calls; the
//!   selected mode must match the method descriptor (checked before the call).
//! * Received messages compressed with `gzip` (`grpc-encoding`) are
//!   decompressed with a bound; Anvil does not compress what it sends.

use crate::connector::{ProxyPlan, Target};
use crate::dns::DnsConfig;
use crate::errors::{HyperStage, classify_hyper};
use crate::http::{AttemptOutput, sleep_until_opt};
use crate::recorder::{EventCtx, Recorder};
use crate::session::*;
use crate::tls::PreparedTls;
use anvil_domain::events::{ExecutionEvent, SessionCommand};
use anvil_domain::execution::*;
use anvil_domain::outcome::{GrpcStatusSource, ProtocolStatus};
use anvil_domain::request::GrpcMode;
use anvil_domain::settings::{Limits, Timeouts};
use base64::Engine;
use bytes::{Buf, Bytes, BytesMut};
use http::{HeaderMap, HeaderName, HeaderValue, Method, Request};
use http_body_util::BodyExt;
use hyper::body::{Body, Frame, SizeHint};
use hyper::client::conn::http2;
use prost::Message as _;
use prost_reflect::{DescriptorPool, DynamicMessage, MessageDescriptor, MethodDescriptor};
use std::collections::{HashMap, VecDeque};
use std::convert::Infallible;
use std::io::Read;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

// ------------------------------------------------------------- schemas ---

struct MemoryResolver(HashMap<String, String>);

impl protox::file::FileResolver for MemoryResolver {
    fn open_file(&self, name: &str) -> Result<protox::file::File, protox::Error> {
        match self.0.get(name) {
            Some(src) => protox::file::File::from_source(name, src),
            None => Err(protox::Error::file_not_found(name)),
        }
    }
}

/// Compile `.proto` sources in-process. Imports resolve only among the
/// provided files (by name) and the bundled Google well-known types; nothing
/// is read from disk.
pub fn pool_from_proto_sources(files: &[(String, String)]) -> Result<DescriptorPool, String> {
    if files.is_empty() {
        return Err("no .proto files were provided".into());
    }
    let map: HashMap<String, String> = files.iter().cloned().collect();
    let mut chain = protox::file::ChainFileResolver::new();
    chain.add(MemoryResolver(map));
    chain.add(protox::file::GoogleFileResolver::new());
    let mut compiler = protox::Compiler::with_file_resolver(chain);
    compiler.include_imports(true);
    for (name, _) in files {
        compiler.open_file(name).map_err(|e| format!("{e}"))?;
    }
    Ok(compiler.descriptor_pool())
}

/// Load a serialized `FileDescriptorSet`.
pub fn pool_from_descriptor_set(bytes: &[u8]) -> Result<DescriptorPool, String> {
    DescriptorPool::decode(bytes).map_err(|e| format!("the descriptor set could not be loaded: {e}"))
}

fn mode_of(m: &MethodDescriptor) -> GrpcMode {
    match (m.is_client_streaming(), m.is_server_streaming()) {
        (false, false) => GrpcMode::Unary,
        (false, true) => GrpcMode::ServerStreaming,
        (true, false) => GrpcMode::ClientStreaming,
        (true, true) => GrpcMode::Bidirectional,
    }
}

/// Find `service`/`method` and check that the selected call mode matches.
pub fn resolve_method(pool: &DescriptorPool, service: &str, method: &str, mode: GrpcMode) -> Result<MethodDescriptor, TransportFailure> {
    let svc = pool.get_service_by_name(service).ok_or_else(|| {
        TransportFailure::new(
            Phase::Prepare,
            FailureKind::BodySerialization,
            format!(
                "service '{service}' is not in the loaded schema (available: {})",
                pool.services().map(|s| s.full_name().to_string()).collect::<Vec<_>>().join(", ")
            ),
        )
        .with_field("grpc.service")
    })?;
    let m = svc.methods().find(|m| m.name() == method).ok_or_else(|| {
        TransportFailure::new(
            Phase::Prepare,
            FailureKind::BodySerialization,
            format!(
                "method '{method}' is not defined on '{service}' (available: {})",
                svc.methods().map(|m| m.name().to_string()).collect::<Vec<_>>().join(", ")
            ),
        )
        .with_field("grpc.method")
    })?;
    let actual = mode_of(&m);
    if actual != mode {
        return Err(TransportFailure::new(
            Phase::Prepare,
            FailureKind::UnsupportedCombination,
            format!("'{service}/{method}' is a {actual:?} method but the request selected {mode:?}; choose the matching call mode"),
        )
        .with_field("grpc.mode"));
    }
    Ok(m)
}

/// JSON → protobuf bytes for a message type.
pub fn encode_json(desc: &MessageDescriptor, json: &str) -> Result<Bytes, String> {
    let mut de = serde_json::Deserializer::from_str(json);
    let msg =
        DynamicMessage::deserialize(desc.clone(), &mut de).map_err(|e| format!("not a valid {} JSON message: {e}", desc.full_name()))?;
    de.end().map_err(|e| format!("trailing characters after the JSON message: {e}"))?;
    Ok(Bytes::from(msg.encode_to_vec()))
}

fn decode_to_json(desc: &MessageDescriptor, bytes: &[u8]) -> Result<String, String> {
    let msg = DynamicMessage::decode(desc.clone(), bytes).map_err(|e| e.to_string())?;
    serde_json::to_string(&msg).map_err(|e| e.to_string())
}

/// 5-byte gRPC length prefix + message (uncompressed).
pub fn frame(msg: &[u8]) -> Bytes {
    let mut b = BytesMut::with_capacity(5 + msg.len());
    b.extend_from_slice(&[0]);
    b.extend_from_slice(&(msg.len() as u32).to_be_bytes());
    b.extend_from_slice(msg);
    b.freeze()
}

/// `grpc-timeout` value (at most 8 digits, per the gRPC HTTP/2 spec).
pub fn grpc_timeout(ms: u64) -> String {
    if ms <= 99_999_999 { format!("{ms}m") } else { format!("{}S", (ms / 1000).min(99_999_999)) }
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16)
        {
            out.push(v);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[derive(Clone, PartialEq, prost::Message)]
struct RpcStatus {
    #[prost(int32, tag = "1")]
    code: i32,
    #[prost(string, tag = "2")]
    message: String,
    #[prost(message, repeated, tag = "3")]
    details: Vec<prost_reflect::prost_types::Any>,
}

fn status_details(b64: &str) -> Option<String> {
    let t = b64.trim();
    let raw = base64::engine::general_purpose::STANDARD
        .decode(t)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(t.trim_end_matches('=')))
        .ok()?;
    let st = RpcStatus::decode(raw.as_slice()).ok()?;
    Some(format!(
        "google.rpc.Status code={} message={:?} details=[{}]",
        st.code,
        st.message,
        st.details.iter().map(|d| d.type_url.clone()).collect::<Vec<_>>().join(", ")
    ))
}

// ---------------------------------------------------------- reflection ---

#[derive(Clone, PartialEq, prost::Message)]
struct ReflRequest {
    #[prost(string, tag = "1")]
    host: String,
    #[prost(string, optional, tag = "3")]
    file_by_filename: Option<String>,
    #[prost(string, optional, tag = "4")]
    file_containing_symbol: Option<String>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct FileDescriptorResponse {
    #[prost(bytes = "vec", repeated, tag = "1")]
    file_descriptor_proto: Vec<Vec<u8>>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct ErrorResponse {
    #[prost(int32, tag = "1")]
    error_code: i32,
    #[prost(string, tag = "2")]
    error_message: String,
}

#[derive(Clone, PartialEq, prost::Message)]
struct ReflResponse {
    #[prost(message, optional, tag = "4")]
    file_descriptor_response: Option<FileDescriptorResponse>,
    #[prost(message, optional, tag = "7")]
    error_response: Option<ErrorResponse>,
}

// ---------------------------------------------------------------- body ---

/// Streaming request body fed from a channel; dropping the sender ends the
/// client stream (half-close).
pub struct GrpcBody {
    rx: mpsc::Receiver<Bytes>,
}

impl Body for GrpcBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        match self.rx.poll_recv(cx) {
            Poll::Ready(Some(b)) => Poll::Ready(Some(Ok(Frame::data(b)))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}

// ---------------------------------------------------------------- plan ---

/// Where the method's message types come from.
#[derive(Clone)]
pub enum Schema {
    Pool(DescriptorPool),
    Reflection,
}

#[derive(Clone)]
pub struct GrpcPlan {
    /// TLS (ALPN h2); `None` = h2c with prior knowledge.
    pub tls: Option<Arc<PreparedTls>>,
    pub host: String,
    pub port: u16,
    pub authority: String,
    /// Optional path prefix in front of `/<service>/<method>` (gateway routing).
    pub path_prefix: String,
    pub service: String,
    pub method: String,
    pub mode: GrpcMode,
    pub schema: Schema,
    /// JSON request messages (scripted; interactive commands add more).
    pub messages: Vec<String>,
    /// Metadata and auth headers.
    pub headers: Vec<(HeaderName, HeaderValue)>,
    pub deadline_ms: Option<u64>,
    pub timeouts: Timeouts,
    pub limits: Limits,
    pub dns: DnsConfig,
    pub proxy: Option<ProxyPlan>,
    pub display_url: String,
    /// Per-message receive ceiling (local policy).
    pub max_message_bytes: usize,
    pub transcript: TranscriptLimits,
    pub redact: Option<RedactFn>,
}

impl GrpcPlan {
    fn uri(&self, path: &str) -> String {
        format!("{}://{}{}{}", if self.tls.is_some() { "https" } else { "http" }, self.authority, self.path_prefix, path)
    }
}

async fn next_cmd(rx: &mut Option<CommandRx>) -> Option<SessionCommand> {
    match rx {
        Some(r) => r.recv().await,
        None => std::future::pending().await,
    }
}

fn base_headers(plan: &GrpcPlan) -> HeaderMap {
    let mut h = HeaderMap::new();
    for (n, v) in &plan.headers {
        if n == http::header::HOST
            || n == http::header::CONNECTION
            || n == http::header::TRANSFER_ENCODING
            || n == http::header::UPGRADE
            || n == http::header::CONTENT_LENGTH
            || n.as_str() == "keep-alive"
        {
            continue;
        }
        h.append(n.clone(), v.clone());
    }
    h.insert(http::header::CONTENT_TYPE, HeaderValue::from_static("application/grpc"));
    h.insert(http::header::TE, HeaderValue::from_static("trailers"));
    if !h.contains_key(http::header::USER_AGENT) {
        h.insert(http::header::USER_AGENT, HeaderValue::from_static(concat!("grpc-anvil/", env!("CARGO_PKG_VERSION"))));
    }
    h
}

/// Split complete messages out of the receive buffer.
fn next_message(buf: &mut BytesMut, max: usize) -> Result<Option<(bool, Bytes)>, String> {
    if buf.len() < 5 {
        return Ok(None);
    }
    let flag = buf[0];
    if flag > 1 {
        return Err(format!("invalid gRPC message flag {flag}"));
    }
    let len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
    if len > max {
        return Err(format!("a received message declares {len} bytes, above the local per-message limit of {max}"));
    }
    if buf.len() < 5 + len {
        return Ok(None);
    }
    buf.advance(5);
    Ok(Some((flag == 1, buf.split_to(len).freeze())))
}

fn gunzip(data: &[u8], max: usize) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(data).take(max as u64 + 1).read_to_end(&mut out).map_err(|e| e.to_string())?;
    if out.len() > max {
        return Err(format!("a decompressed message exceeds the local limit of {max} bytes"));
    }
    Ok(out)
}

/// Result of a single-request call used for reflection.
struct OneShot {
    status: Option<u16>,
    version: http::Version,
    headers: Vec<HeaderEntry>,
    trailers: Vec<HeaderEntry>,
    messages: Vec<Bytes>,
    grpc_status: Option<i32>,
    grpc_message: Option<String>,
    failure: Option<TransportFailure>,
}

async fn one_shot(
    sender: &mut http2::SendRequest<GrpcBody>,
    plan: &GrpcPlan,
    path: &str,
    msg: &[u8],
    cancel: &CancellationToken,
) -> OneShot {
    let (tx, rx) = mpsc::channel(1);
    let _ = tx.try_send(frame(msg));
    drop(tx);
    let mut out = OneShot {
        status: None,
        version: http::Version::HTTP_2,
        headers: vec![],
        trailers: vec![],
        messages: vec![],
        grpc_status: None,
        grpc_message: None,
        failure: None,
    };
    let mut req = match Request::builder().method(Method::POST).uri(plan.uri(path)).body(GrpcBody { rx }) {
        Ok(r) => r,
        Err(e) => {
            out.failure =
                Some(TransportFailure::new(Phase::Prepare, FailureKind::InvalidUrl, format!("reflection request could not be built: {e}")));
            return out;
        }
    };
    *req.headers_mut() = base_headers(plan);
    let deadline = deadline_from(plan.timeouts.response_headers_ms.or(Some(30_000)));
    let resp = tokio::select! {
        r = sender.send_request(req) => r,
        _ = sleep_until_opt(deadline) => {
            out.failure = Some(TransportFailure::new(Phase::AwaitResponseHeaders, FailureKind::ResponseHeadersTimeout, "no answer to the reflection request").with_deadline(plan.timeouts.response_headers_ms));
            return out;
        }
        _ = cancel.cancelled() => {
            out.failure = Some(TransportFailure::new(Phase::AwaitResponseHeaders, FailureKind::Canceled, "canceled during server reflection"));
            return out;
        }
    };
    let resp = match resp {
        Ok(r) => r,
        Err(e) => {
            out.failure = Some(classify_hyper(&e, HyperStage::AwaitHeaders));
            return out;
        }
    };
    out.status = Some(resp.status().as_u16());
    out.version = resp.version();
    out.headers = header_entries(resp.headers());
    if let Some(s) = resp.headers().get("grpc-status").and_then(|v| v.to_str().ok()).and_then(|s| s.trim().parse().ok()) {
        out.grpc_status = Some(s);
        out.grpc_message = resp.headers().get("grpc-message").and_then(|v| v.to_str().ok()).map(percent_decode);
    }
    let mut body = resp.into_body();
    let mut buf = BytesMut::new();
    loop {
        let idle = deadline_from(plan.timeouts.body_idle_ms.or(Some(30_000)));
        tokio::select! {
            f = body.frame() => match f {
                None => break,
                Some(Ok(fr)) => {
                    if fr.is_data() {
                        buf.extend_from_slice(&fr.into_data().unwrap_or_default());
                        loop {
                            match next_message(&mut buf, plan.max_message_bytes) {
                                Ok(Some((false, m))) => out.messages.push(m),
                                Ok(Some((true, _))) => {
                                    out.failure = Some(TransportFailure::new(Phase::ResponseBody, FailureKind::HttpProtocolError, "a compressed reflection response was not negotiated"));
                                    return out;
                                }
                                Ok(None) => break,
                                Err(e) => {
                                    out.failure = Some(TransportFailure::new(Phase::ResponseBody, FailureKind::ResponseTooLargeLocal, e));
                                    return out;
                                }
                            }
                        }
                    } else if let Ok(t) = fr.into_trailers() {
                        out.trailers = header_entries(&t);
                        out.grpc_status = t.get("grpc-status").and_then(|v| v.to_str().ok()).and_then(|s| s.trim().parse().ok());
                        out.grpc_message = t.get("grpc-message").and_then(|v| v.to_str().ok()).map(percent_decode);
                    }
                }
                Some(Err(e)) => {
                    out.failure = Some(classify_hyper(&e, HyperStage::Body));
                    return out;
                }
            },
            _ = sleep_until_opt(idle) => {
                out.failure = Some(TransportFailure::new(Phase::ResponseBody, FailureKind::BodyIdleTimeout, "the reflection response stalled"));
                return out;
            }
            _ = cancel.cancelled() => {
                out.failure = Some(TransportFailure::new(Phase::ResponseBody, FailureKind::Canceled, "canceled during server reflection"));
                return out;
            }
        }
    }
    out
}

enum ReflectError {
    /// The reflection exchange produced this last call (evidence) and outcome.
    Refused(Box<OneShot>, ReflectionOutcome),
}

/// Fetch the service's descriptors (and their dependency closure) by
/// server reflection, v1 first and v1alpha when v1 is unimplemented.
async fn reflect(
    sender: &mut http2::SendRequest<GrpcBody>,
    plan: &GrpcPlan,
    cancel: &CancellationToken,
) -> Result<(DescriptorPool, ReflectionOutcome), ReflectError> {
    let services = ["grpc.reflection.v1.ServerReflection", "grpc.reflection.v1alpha.ServerReflection"];
    let mut last: Option<(OneShot, ReflectionOutcome)> = None;
    'svc: for svc in services {
        let path = format!("/{svc}/ServerReflectionInfo");
        let ask = |symbol: Option<String>, file: Option<String>| ReflRequest {
            host: plan.authority.clone(),
            file_containing_symbol: symbol,
            file_by_filename: file,
        };
        let mut files: HashMap<String, prost_reflect::prost_types::FileDescriptorProto> = HashMap::new();
        let mut queue: VecDeque<ReflRequest> = VecDeque::from([ask(Some(plan.service.clone()), None)]);
        let mut requests = 0;
        while let Some(q) = queue.pop_front() {
            requests += 1;
            if requests > 64 {
                break;
            }
            let r = one_shot(sender, plan, &path, &q.encode_to_vec(), cancel).await;
            let outcome = |problem: String, r: &OneShot| ReflectionOutcome {
                service: svc.trim_end_matches(".ServerReflection").to_string(),
                http_status: r.status,
                grpc_status: r.grpc_status,
                grpc_message: r.grpc_message.clone(),
                succeeded: false,
                problem: Some(problem),
            };
            if r.failure.is_some() {
                let o = outcome("the reflection exchange failed at the transport level".into(), &r);
                return Err(ReflectError::Refused(Box::new(r), o));
            }
            match r.grpc_status {
                Some(0) => {}
                Some(12) if requests == 1 => {
                    // UNIMPLEMENTED: this reflection version is not served; try the next.
                    let o = outcome(format!("{svc} is not implemented by the server"), &r);
                    last = Some((r, o));
                    continue 'svc;
                }
                Some(code) => {
                    let o = outcome(format!("server reflection was refused with grpc-status {code}"), &r);
                    return Err(ReflectError::Refused(Box::new(r), o));
                }
                None => {
                    let o = outcome("the reflection call ended without a grpc-status".into(), &r);
                    return Err(ReflectError::Refused(Box::new(r), o));
                }
            }
            let Some(m) = r.messages.first() else {
                let o = outcome("the reflection call returned no response message".into(), &r);
                return Err(ReflectError::Refused(Box::new(r), o));
            };
            let resp = match ReflResponse::decode(m.as_ref()) {
                Ok(x) => x,
                Err(e) => {
                    let o = outcome(format!("the reflection response could not be decoded: {e}"), &r);
                    return Err(ReflectError::Refused(Box::new(r), o));
                }
            };
            if let Some(er) = resp.error_response {
                if q.file_by_filename.as_deref().map(|f| f.starts_with("google/protobuf/")).unwrap_or(false) {
                    continue; // bundled well-known types fill this in below
                }
                let o = outcome(format!("reflection error {}: {}", er.error_code, er.error_message), &r);
                return Err(ReflectError::Refused(Box::new(r), o));
            }
            for raw in resp.file_descriptor_response.map(|f| f.file_descriptor_proto).unwrap_or_default() {
                let Ok(fd) = prost_reflect::prost_types::FileDescriptorProto::decode(raw.as_slice()) else { continue };
                for dep in &fd.dependency {
                    if !files.contains_key(dep) && !queue.iter().any(|x| x.file_by_filename.as_deref() == Some(dep.as_str())) {
                        queue.push_back(ask(None, Some(dep.clone())));
                    }
                }
                files.insert(fd.name().to_string(), fd);
            }
            queue.retain(|x| x.file_by_filename.as_ref().map(|f| !files.contains_key(f)).unwrap_or(true));
        }
        // Well-known imports the server did not return come from protox's bundle.
        let google = protox::file::GoogleFileResolver::new();
        let missing: Vec<String> = files
            .values()
            .flat_map(|f| f.dependency.clone())
            .filter(|d| !files.contains_key(d) && d.starts_with("google/protobuf/"))
            .collect();
        for d in missing {
            if let Ok(f) = protox::file::FileResolver::open_file(&google, &d) {
                files.insert(d.clone(), f.file_descriptor_proto().clone());
            }
        }
        let mut pool = DescriptorPool::new();
        let outcome = ReflectionOutcome {
            service: svc.trim_end_matches(".ServerReflection").to_string(),
            http_status: Some(200),
            grpc_status: Some(0),
            grpc_message: None,
            succeeded: true,
            problem: None,
        };
        return match pool.add_file_descriptor_protos(files.into_values()) {
            Ok(()) => Ok((pool, outcome)),
            Err(e) => Err(ReflectError::Refused(
                Box::new(OneShot {
                    status: Some(200),
                    version: http::Version::HTTP_2,
                    headers: vec![],
                    trailers: vec![],
                    messages: vec![],
                    grpc_status: Some(0),
                    grpc_message: None,
                    failure: None,
                }),
                ReflectionOutcome { succeeded: false, problem: Some(format!("the reflected descriptors are incomplete: {e}")), ..outcome },
            )),
        };
    }
    match last {
        Some((r, o)) => Err(ReflectError::Refused(
            Box::new(r),
            ReflectionOutcome { problem: Some("the server implements neither grpc.reflection.v1 nor v1alpha".into()), ..o },
        )),
        None => Err(ReflectError::Refused(
            Box::new(OneShot {
                status: None,
                version: http::Version::HTTP_2,
                headers: vec![],
                trailers: vec![],
                messages: vec![],
                grpc_status: None,
                grpc_message: None,
                failure: None,
            }),
            ReflectionOutcome {
                service: "grpc.reflection".into(),
                http_status: None,
                grpc_status: None,
                grpc_message: None,
                succeeded: false,
                problem: Some("server reflection was not attempted".into()),
            },
        )),
    }
}

// ----------------------------------------------------------------- run ---

pub async fn run(plan: &GrpcPlan, events: &EventCtx, cancel: &CancellationToken, mut commands: Option<CommandRx>) -> SessionOutput {
    let interactive = commands.is_some();
    let mut rec = Recorder::new(0, events.clone());
    events.emit(ExecutionEvent::AttemptStarted { execution_id: events.execution_id, attempt: 0 });
    let mut obs = new_attempt(0, AttemptReason::Initial, "POST", &plan.display_url);
    let mut facts = SessionFacts::default();
    let early = |rec: Recorder, obs: AttemptObservation, f: TransportFailure, facts: SessionFacts, d: DispatchState| {
        SessionOutput::single(fail_attempt(rec, obs, f, d, events), None, ProtocolStatus::None, facts)
    };
    let total_deadline = if interactive { None } else { deadline_from(plan.timeouts.total_ms) };

    // Local schema: resolve and encode before any traffic.
    let mut method_desc: Option<MethodDescriptor> = None;
    if let Schema::Pool(pool) = &plan.schema {
        match resolve_method(pool, &plan.service, &plan.method, plan.mode) {
            Ok(m) => method_desc = Some(m),
            Err(f) => return early(rec, obs, f, facts, DispatchState::NotDispatched),
        }
    }
    let encode_all = |m: &MethodDescriptor| -> Result<Vec<(Bytes, String)>, TransportFailure> {
        let mut msgs = plan.messages.clone();
        if matches!(plan.mode, GrpcMode::Unary | GrpcMode::ServerStreaming) {
            if msgs.len() > 1 {
                return Err(TransportFailure::new(
                    Phase::Prepare,
                    FailureKind::BodySerialization,
                    format!("a {:?} call sends exactly one request message; {} were given", plan.mode, msgs.len()),
                )
                .with_field("grpc.messages"));
            }
            if msgs.is_empty() {
                msgs.push("{}".into());
            }
        }
        let input = m.input();
        msgs.iter()
            .enumerate()
            .map(|(i, j)| {
                encode_json(&input, j).map(|b| (b, j.clone())).map_err(|e| {
                    TransportFailure::new(Phase::Prepare, FailureKind::BodySerialization, e).with_field(format!("grpc.messages[{i}]"))
                })
            })
            .collect()
    };
    let mut encoded: Option<Vec<(Bytes, String)>> = None;
    if let Some(m) = &method_desc {
        match encode_all(m) {
            Ok(e) => encoded = Some(e),
            Err(f) => return early(rec, obs, f, facts, DispatchState::NotDispatched),
        }
    }

    // ---- connection ----
    let alpn: &[&str] = if plan.tls.is_some() { &["h2"] } else { &[] };
    let target = Target { host: &plan.host, port: plan.port, tls: plan.tls.as_deref(), alpn, http_forward_via_proxy: false };
    let est = match establish_guarded(&mut rec, &target, &plan.dns, &plan.timeouts, plan.proxy.as_ref(), cancel, total_deadline).await {
        Ok(e) => e,
        Err((f, o)) => {
            obs.connection = o;
            return early(rec, obs, f, facts, DispatchState::NotDispatched);
        }
    };
    if plan.tls.is_some() {
        let negotiated = est.observation.tls.as_ref().and_then(|t| t.alpn_negotiated.clone());
        if negotiated.as_deref() != Some("h2") {
            let f = TransportFailure::new(
                Phase::TlsHandshake,
                FailureKind::TlsAlpnMismatch,
                format!(
                    "gRPC needs HTTP/2 (ALPN 'h2') but the peer negotiated {}",
                    negotiated.map(|s| format!("'{s}'")).unwrap_or_else(|| "no ALPN protocol".into())
                ),
            );
            obs.connection = Some(est.observation);
            return early(rec, obs, f, facts, DispatchState::NotDispatched);
        }
    }
    let HttpConn { sender, stats, observation: cobs, .. } = match http_handshake::<GrpcBody>(&mut rec, est, true, &plan.limits).await {
        Ok(x) => x,
        Err((f, o)) => {
            obs.connection = Some(o);
            return early(rec, obs, f, facts, DispatchState::NotDispatched);
        }
    };
    obs.connection = Some(cobs);
    let HttpSender::H2(mut h2) = sender else {
        let f = TransportFailure::new(Phase::ProtocolHandshake, FailureKind::Internal, "gRPC requires an HTTP/2 connection");
        return early(rec, obs, f, facts, DispatchState::NotDispatched);
    };
    let written_before = stats.bytes_written();
    let read_before = stats.bytes_read();

    // ---- server reflection (network schema) ----
    if matches!(plan.schema, Schema::Reflection) {
        let r_idx = rec.start(Phase::AwaitResponseHeaders);
        match reflect(&mut h2, plan, cancel).await {
            Ok((pool, outcome)) => {
                rec.finish_with(r_idx, PhaseStatus::Completed, format!("server reflection via {}", outcome.service));
                facts.notes.push(format!("schema loaded by server reflection ({})", outcome.service));
                facts.grpc_reflection = Some(outcome);
                let m = match resolve_method(&pool, &plan.service, &plan.method, plan.mode) {
                    Ok(m) => m,
                    Err(f) => return early(rec, obs, f, facts, DispatchState::NotDispatched),
                };
                match encode_all(&m) {
                    Ok(e) => encoded = Some(e),
                    Err(f) => return early(rec, obs, f, facts, DispatchState::NotDispatched),
                }
                method_desc = Some(m);
            }
            Err(ReflectError::Refused(shot, outcome)) => {
                rec.finish_with(
                    r_idx,
                    if shot.failure.is_some() { PhaseStatus::Failed } else { PhaseStatus::Completed },
                    format!("server reflection via {}", outcome.service),
                );
                facts.notes.push(format!(
                    "{}; {}/{} was not called",
                    outcome.problem.clone().unwrap_or_else(|| "server reflection failed".into()),
                    plan.service,
                    plan.method
                ));
                facts.grpc_reflection = Some(outcome);
                obs.failure = shot.failure.clone();
                obs.response_status = shot.status;
                obs.bytes.connection_bytes_written = Some(stats.bytes_written().saturating_sub(written_before));
                obs.bytes.connection_bytes_read = Some(stats.bytes_read().saturating_sub(read_before));
                obs.dispatch = DispatchState::NotDispatched;
                let obs = finish_attempt(rec, obs, events);
                let response = shot.status.map(|s| {
                    let mut r = response_record(
                        s,
                        shot.version,
                        shot.headers.clone(),
                        body_capture(BodyCompleteness::Complete, 0, &[], Some("application/grpc".into())),
                    );
                    r.trailers = shot.trailers.clone();
                    r.trailers_received = !shot.trailers.is_empty();
                    r
                });
                return SessionOutput::single(
                    AttemptOutput { observation: obs, response, body: Bytes::new() },
                    None,
                    ProtocolStatus::None,
                    facts,
                );
            }
        }
    }
    let Some(method_desc) = method_desc else {
        let f = TransportFailure::new(Phase::Prepare, FailureKind::Internal, "no method descriptor");
        return early(rec, obs, f, facts, DispatchState::NotDispatched);
    };
    let output_desc = method_desc.output();
    let input_desc = method_desc.input();
    let mut pending: VecDeque<(Bytes, String)> = encoded.unwrap_or_default().into();
    obs.bytes.request_body = pending.iter().map(|(b, _)| 5 + b.len() as u64).sum();

    // ---- the call ----
    let (tx, rx) = mpsc::channel::<Bytes>(64);
    let mut tx = Some(tx);
    let path = format!("/{}/{}", plan.service, plan.method);
    let mut req = match Request::builder().method(Method::POST).uri(plan.uri(&path)).body(GrpcBody { rx }) {
        Ok(r) => r,
        Err(e) => {
            let f = TransportFailure::new(Phase::Prepare, FailureKind::InvalidUrl, format!("the gRPC request could not be built: {e}"))
                .with_field("url");
            return early(rec, obs, f, facts, DispatchState::NotDispatched);
        }
    };
    let mut headers = base_headers(plan);
    if let Some(ms) = plan.deadline_ms
        && let Ok(v) = HeaderValue::from_str(&grpc_timeout(ms))
    {
        headers.insert("grpc-timeout", v);
    }
    let sent_headers = header_entries(&headers);
    obs.bytes.request_headers_logical = logical_header_bytes(&sent_headers) + path.len() as u64;
    obs.bytes.request_headers_estimated = true;
    *req.headers_mut() = headers;

    let mut tr = Transcript::new(rec.t0, plan.transcript, events.clone(), plan.redact.clone());
    let w_idx = rec.start(Phase::RequestWrite);
    let mut w_open = true;
    let mut h_idx: Option<usize> = None;
    let mut s_idx: Option<usize> = None;
    let streaming_request = matches!(plan.mode, GrpcMode::ClientStreaming | GrpcMode::Bidirectional);
    // Header deadline only when the whole request is sent at once.
    let headers_deadline = if streaming_request || interactive { None } else { deadline_from(plan.timeouts.response_headers_ms) };
    let grpc_deadline = plan.deadline_ms.map(|ms| Instant::now() + Duration::from_millis(ms));
    let mut resp_fut = Some(Box::pin(h2.send_request(req)));
    let mut body: Option<hyper::body::Incoming> = None;
    let mut rbuf = BytesMut::new();
    let mut captured = BytesMut::new();
    let mut wire = 0u64;
    let mut status: Option<u16> = None;
    let mut version = http::Version::HTTP_2;
    let mut resp_headers: Vec<HeaderEntry> = vec![];
    let mut trailers: Vec<HeaderEntry> = vec![];
    let mut trailers_received = false;
    let mut grpc_status: Option<i32> = None;
    let mut grpc_message: Option<String> = None;
    let mut source = GrpcStatusSource::Missing;
    let mut encoding: Option<String> = None;
    let mut content_type: Option<String> = None;
    let mut failure: Option<TransportFailure> = None;
    let mut completeness = BodyCompleteness::Incomplete;
    let mut half_close_wanted = !interactive;
    let mut last_progress = Instant::now();

    type Resp = Result<hyper::Response<hyper::body::Incoming>, hyper::Error>;
    enum Ev {
        Resp(Resp),
        Frame(Option<Result<Frame<Bytes>, hyper::Error>>),
        Permit(Result<mpsc::OwnedPermit<Bytes>, mpsc::error::SendError<()>>),
        Cmd(Option<SessionCommand>),
        HeadersTimeout,
        BodyIdle,
        GrpcDeadline,
        Deadline,
        Canceled,
    }
    loop {
        // Automation half-closes as soon as the scripted messages are queued.
        if half_close_wanted && pending.is_empty() && tx.is_some() {
            tx = None;
            if streaming_request {
                tr.control(Direction::Sent, "half_close", b"client stream finished");
            }
            if w_open {
                rec.finish(w_idx, PhaseStatus::Completed);
                w_open = false;
                if h_idx.is_none() && resp_fut.is_some() {
                    h_idx = Some(rec.start(Phase::AwaitResponseHeaders));
                }
            }
        }
        let body_idle = if body.is_some() && !streaming_request && !interactive {
            plan.timeouts.body_idle_ms.map(|ms| last_progress + Duration::from_millis(ms))
        } else {
            None
        };
        let can_send = tx.is_some() && !pending.is_empty();
        let send_handle = if can_send { tx.clone() } else { None };
        let ev = tokio::select! {
            r = async { resp_fut.as_mut().expect("guarded").await }, if resp_fut.is_some() => Ev::Resp(r),
            fr = async { body.as_mut().expect("guarded").frame().await }, if body.is_some() => Ev::Frame(fr),
            p = async { send_handle.expect("guarded").reserve_owned().await }, if can_send => Ev::Permit(p),
            c = next_cmd(&mut commands), if interactive && tx.is_some() => Ev::Cmd(c),
            _ = sleep_until_opt(headers_deadline), if resp_fut.is_some() => Ev::HeadersTimeout,
            _ = sleep_until_opt(body_idle) => Ev::BodyIdle,
            _ = sleep_until_opt(grpc_deadline) => Ev::GrpcDeadline,
            _ = sleep_until_opt(total_deadline) => Ev::Deadline,
            _ = cancel.cancelled() => Ev::Canceled,
        };
        match ev {
            Ev::Resp(Ok(resp)) => {
                resp_fut = None;
                if let Some(i) = h_idx.take() {
                    rec.finish(i, PhaseStatus::Completed);
                }
                let st = resp.status().as_u16();
                status = Some(st);
                version = resp.version();
                obs.response_status = Some(st);
                obs.dispatch = DispatchState::Sent;
                events.emit(ExecutionEvent::ResponseHead { execution_id: events.execution_id, attempt: 0, status: st });
                resp_headers = header_entries(resp.headers());
                obs.bytes.response_headers_logical = Some(logical_header_bytes(&resp_headers));
                content_type = resp.headers().get(http::header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).map(|s| s.to_string());
                encoding = resp.headers().get("grpc-encoding").and_then(|v| v.to_str().ok()).map(|s| s.to_ascii_lowercase());
                if let Some(code) =
                    resp.headers().get("grpc-status").and_then(|v| v.to_str().ok()).and_then(|s| s.trim().parse::<i32>().ok())
                {
                    grpc_status = Some(code);
                    grpc_message = resp.headers().get("grpc-message").and_then(|v| v.to_str().ok()).map(percent_decode);
                    source = GrpcStatusSource::TrailersOnly;
                    facts.grpc_status_details =
                        resp.headers().get("grpc-status-details-bin").and_then(|v| v.to_str().ok()).and_then(status_details);
                }
                if !content_type.as_deref().map(|c| c.starts_with("application/grpc")).unwrap_or(false) {
                    facts.notes.push(format!(
                        "the response content type is {}, not application/grpc",
                        content_type.clone().unwrap_or_else(|| "missing".into())
                    ));
                }
                s_idx = Some(rec.start(Phase::Session));
                body = Some(resp.into_body());
                last_progress = Instant::now();
            }
            Ev::Resp(Err(e)) => {
                resp_fut = None;
                let mut f = classify_hyper(&e, HyperStage::AwaitHeaders);
                if let Some((k, a)) = stats.tls_error() {
                    f.kind = k;
                    f.tls_alert = a;
                }
                failure = Some(f);
                break;
            }
            Ev::Frame(None) => {
                completeness = BodyCompleteness::Complete;
                break;
            }
            Ev::Frame(Some(Ok(fr))) => {
                last_progress = Instant::now();
                if fr.is_data() {
                    let d = fr.into_data().unwrap_or_default();
                    wire += d.len() as u64;
                    let room = (plan.limits.capture_bytes as usize).saturating_sub(captured.len());
                    captured.extend_from_slice(&d[..d.len().min(room)]);
                    rbuf.extend_from_slice(&d);
                    let mut err = None;
                    loop {
                        match next_message(&mut rbuf, plan.max_message_bytes) {
                            Ok(Some((compressed, m))) => {
                                let raw = if compressed {
                                    match encoding.as_deref() {
                                        Some("gzip") => match gunzip(&m, plan.max_message_bytes) {
                                            Ok(v) => Bytes::from(v),
                                            Err(e) => {
                                                err = Some(TransportFailure::new(Phase::Session, FailureKind::DecompressionFailed, e));
                                                break;
                                            }
                                        },
                                        other => {
                                            err = Some(TransportFailure::new(
                                                Phase::Session,
                                                FailureKind::HttpProtocolError,
                                                format!(
                                                    "a compressed message arrived with grpc-encoding {other:?}, which Anvil did not negotiate"
                                                ),
                                            ));
                                            break;
                                        }
                                    }
                                } else {
                                    m
                                };
                                match decode_to_json(&output_desc, &raw) {
                                    Ok(json) => tr.data_text(Direction::Received, "grpc_message", raw.len() as u64, &json),
                                    Err(e) => {
                                        tr.data(Direction::Received, "grpc_message", &raw);
                                        tr.note(
                                            "decode_error",
                                            &format!("message could not be decoded as {}: {e}", output_desc.full_name()),
                                        );
                                    }
                                }
                            }
                            Ok(None) => break,
                            Err(e) => {
                                err = Some(TransportFailure::new(Phase::Session, FailureKind::ResponseTooLargeLocal, e));
                                break;
                            }
                        }
                    }
                    if let Some(f) = err {
                        completeness = if f.kind == FailureKind::ResponseTooLargeLocal {
                            BodyCompleteness::StoppedAtLocalLimit
                        } else {
                            BodyCompleteness::Incomplete
                        };
                        failure = Some(f);
                        break;
                    }
                    if wire > plan.limits.max_response_bytes {
                        completeness = BodyCompleteness::StoppedAtLocalLimit;
                        failure = Some(TransportFailure::new(
                            Phase::Session,
                            FailureKind::ResponseTooLargeLocal,
                            "stopped at the local max_response_bytes limit",
                        ));
                        break;
                    }
                } else if let Ok(t) = fr.into_trailers() {
                    trailers_received = true;
                    trailers = header_entries(&t);
                    if let Some(code) = t.get("grpc-status").and_then(|v| v.to_str().ok()).and_then(|s| s.trim().parse::<i32>().ok()) {
                        grpc_status = Some(code);
                        grpc_message = t.get("grpc-message").and_then(|v| v.to_str().ok()).map(percent_decode);
                        source = GrpcStatusSource::Trailers;
                        facts.grpc_status_details = t.get("grpc-status-details-bin").and_then(|v| v.to_str().ok()).and_then(status_details);
                    }
                }
            }
            Ev::Frame(Some(Err(e))) => {
                let mut f = classify_hyper(&e, HyperStage::Body);
                f.phase = Phase::Session;
                if let Some((k, a)) = stats.tls_error() {
                    f.kind = k;
                    f.tls_alert = a;
                }
                failure = Some(f);
                break;
            }
            Ev::Permit(Ok(p)) => {
                let (b, json) = pending.pop_front().expect("non-empty");
                drop(p.send(frame(&b)));
                tr.data_text(Direction::Sent, "grpc_message", b.len() as u64, &json);
            }
            Ev::Permit(Err(_)) => {
                // The request side of the stream is gone (server finished or reset).
                tx = None;
                pending.clear();
            }
            Ev::Cmd(c) => match c {
                Some(SessionCommand::SendText { text }) => {
                    if !streaming_request && tr.sent_count() + pending.len() as u64 >= 1 {
                        tr.note("unsupported_command", "this call mode sends exactly one request message");
                    } else {
                        match encode_json(&input_desc, &text) {
                            Ok(b) => pending.push_back((b, text)),
                            Err(e) => tr.note("error", &format!("message not sent: {e}")),
                        }
                    }
                }
                Some(SessionCommand::SendBinaryHex { hex }) => match decode_hex(&hex) {
                    Ok(b) => pending.push_back((Bytes::from(b), format!("(pre-encoded bytes) {hex}"))),
                    Err(e) => tr.note("error", &format!("message not sent: {e}")),
                },
                Some(SessionCommand::HalfClose) | Some(SessionCommand::Close { .. }) | None => half_close_wanted = true,
                Some(SessionCommand::Ping) => {
                    tr.note("unsupported_command", "gRPC calls have no ping command (HTTP/2 PINGs are connection-level)")
                }
            },
            Ev::HeadersTimeout => {
                failure = Some(
                    TransportFailure::new(
                        Phase::AwaitResponseHeaders,
                        FailureKind::ResponseHeadersTimeout,
                        "no response headers before the response-header deadline",
                    )
                    .with_deadline(plan.timeouts.response_headers_ms),
                );
                break;
            }
            Ev::BodyIdle => {
                failure = Some(
                    TransportFailure::new(
                        Phase::Session,
                        FailureKind::BodyIdleTimeout,
                        "the response stream stalled longer than the body idle deadline",
                    )
                    .with_deadline(plan.timeouts.body_idle_ms),
                );
                break;
            }
            Ev::GrpcDeadline => {
                failure = Some(
                    TransportFailure::new(
                        Phase::Session,
                        FailureKind::TotalTimeout,
                        format!(
                            "the gRPC deadline ({} ms, sent as grpc-timeout) elapsed before the server returned a status; Anvil canceled the stream. The status is unknown, not DEADLINE_EXCEEDED from the server",
                            plan.deadline_ms.unwrap_or(0)
                        ),
                    )
                    .with_deadline(plan.deadline_ms),
                );
                break;
            }
            Ev::Deadline => {
                failure = Some(
                    TransportFailure::new(Phase::Session, FailureKind::TotalTimeout, "the total deadline elapsed during the call")
                        .with_deadline(plan.timeouts.total_ms),
                );
                break;
            }
            Ev::Canceled => {
                failure = Some(TransportFailure::new(Phase::Session, FailureKind::Canceled, "the call was canceled (RST_STREAM CANCEL)"));
                completeness = BodyCompleteness::Canceled;
                break;
            }
        }
    }
    // Dropping the request sender / response body resets an unfinished stream.
    drop(tx);
    drop(resp_fut);
    drop(body);
    if !rbuf.is_empty() && failure.is_none() {
        failure = Some(TransportFailure::new(
            Phase::Session,
            FailureKind::BodyIncomplete,
            format!("the stream ended inside a message ({} bytes left over)", rbuf.len()),
        ));
        completeness = BodyCompleteness::Incomplete;
    }
    if w_open {
        rec.finish(w_idx, if status.is_some() { PhaseStatus::Completed } else { PhaseStatus::Unknown });
    }
    if let Some(i) = h_idx {
        rec.finish(i, if status.is_some() { PhaseStatus::Completed } else { PhaseStatus::Failed });
    }
    if let Some(i) = s_idx {
        rec.finish(
            i,
            match &failure {
                Some(f) => phase_status_for(f.kind),
                None => PhaseStatus::Completed,
            },
        );
    }
    if let Some(code) = grpc_status {
        let msg = grpc_message.clone().unwrap_or_default();
        tr.control(Direction::Received, "status", format!("grpc-status {code} {msg}").trim().as_bytes());
    }
    if status.is_none() && obs.dispatch != DispatchState::Sent {
        obs.dispatch = if stats.bytes_written() > written_before { DispatchState::MayHaveBeenSent } else { DispatchState::NotDispatched };
    }
    obs.failure = failure;
    obs.bytes.response_body_wire = Some(wire);
    obs.bytes.connection_bytes_written = Some(stats.bytes_written().saturating_sub(written_before));
    obs.bytes.connection_bytes_read = Some(stats.bytes_read().saturating_sub(read_before));
    let obs = finish_attempt(rec, obs, events);
    let redact = |s: String| match &plan.redact {
        Some(r) => r(&s),
        None => s,
    };
    let Some(st) = status else {
        return SessionOutput::single(
            AttemptOutput { observation: obs, response: None, body: Bytes::new() },
            None,
            ProtocolStatus::None,
            facts,
        );
    };
    let captured = captured.freeze();
    let mut response = response_record(st, version, resp_headers, body_capture(completeness, wire, &captured, content_type));
    response.trailers = trailers;
    response.trailers_received = trailers_received;
    let ps = ProtocolStatus::Grpc { http_status: Some(st), grpc_status, grpc_message: grpc_message.map(redact), source };
    SessionOutput::single(AttemptOutput { observation: obs, response: Some(response), body: captured }, Some(tr.finish()), ps, facts)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROTO: &str = r#"syntax = "proto3"; package t.v1;
        import "google/protobuf/timestamp.proto";
        message Req { string name = 1; google.protobuf.Timestamp at = 2; }
        message Rep { string text = 1; }
        service S { rpc U(Req) returns (Rep); rpc B(stream Req) returns (stream Rep); }"#;

    #[test]
    fn proto_sources_compile_in_memory_with_well_known_imports() {
        let pool = pool_from_proto_sources(&[("t.proto".into(), PROTO.into())]).unwrap();
        let m = resolve_method(&pool, "t.v1.S", "U", GrpcMode::Unary).unwrap();
        let b = encode_json(&m.input(), r#"{"name":"x","at":"2024-01-01T00:00:00Z"}"#).unwrap();
        assert!(!b.is_empty());
        assert!(encode_json(&m.input(), r#"{"nope":1}"#).is_err());
        let e = resolve_method(&pool, "t.v1.S", "B", GrpcMode::Unary).unwrap_err();
        assert_eq!(e.kind, FailureKind::UnsupportedCombination, "mode must match the descriptor");
    }

    #[test]
    fn imports_outside_the_provided_files_fail() {
        let src = r#"syntax = "proto3"; import "other/missing.proto"; message A {}"#;
        let e = pool_from_proto_sources(&[("a.proto".into(), src.into())]).unwrap_err();
        assert!(e.contains("missing.proto"), "{e}");
    }

    #[test]
    fn framing_timeout_and_message_decoding() {
        let mut b = BytesMut::new();
        b.extend_from_slice(&frame(b"abc"));
        b.extend_from_slice(&frame(b"")[..3]);
        assert_eq!(next_message(&mut b, 16).unwrap(), Some((false, Bytes::from_static(b"abc"))));
        assert_eq!(next_message(&mut b, 16).unwrap(), None);
        let mut big = BytesMut::from(&[0u8, 0, 0, 1, 0][..]);
        assert!(next_message(&mut big, 16).is_err());
        assert_eq!(grpc_timeout(1500), "1500m");
        assert_eq!(grpc_timeout(200_000_000), "200000S");
        assert_eq!(percent_decode("a%20b%zz"), "a b%zz");
    }
}
