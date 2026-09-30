//! gRPC and gRPC-Web calls.
//!
//! Wire formats and HTTP versions:
//! * **Native gRPC** (`application/grpc`, `te: trailers`) over HTTP/2 — TLS
//!   with ALPN `h2`, or h2c with prior knowledge — or over **HTTP/3** on a
//!   fresh QUIC connection (DNS and the QUIC handshake are measured; there is
//!   no TCP phase). With the HTTP/3-with-fallback policy, an HTTP/3 attempt
//!   that fails before the call was sent is followed by a separate HTTP/2
//!   attempt (`protocol_fallback{from: h3}`); forced HTTP/3 never uses TCP.
//! * **gRPC-Web** binary (`application/grpc-web+proto`) or text
//!   (`application/grpc-web-text`, base64 in both directions) over HTTP/1.1,
//!   HTTP/2 or HTTP/3 per the version policy. Unary and server streaming
//!   only (refused before traffic otherwise). The status is read from the
//!   trailer frame (flag `0x80`) at the end of the body, from the headers of
//!   a trailers-only answer, or — noted as unusual — from HTTP trailers. A
//!   body that ends without any of them has a **missing** status.
//!
//! Common behavior:
//! * Length-prefixed message framing with message boundaries preserved in
//!   the transcript (each message decoded to JSON with the method's type).
//! * `grpc-timeout` from the configured deadline (also enforced locally:
//!   when it elapses Anvil cancels the stream and records that no status was
//!   received — it never fabricates `DEADLINE_EXCEEDED`).
//! * HTTP status and gRPC status are separate; the status source is labeled
//!   (trailers, trailers-only, trailer frame, missing). `grpc-message` is
//!   percent-decoded and `grpc-status-details-bin` is decoded as
//!   `google.rpc.Status`. HTTP 200 alone is never an RPC success.
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
use crate::fence::{Generations, in_isolation};
use crate::grpc_web::{self, FrameError, WireFrame};
use crate::http::{AttemptOutput, sleep_until_opt};
use crate::recorder::{EventCtx, Recorder};
use crate::session::*;
use crate::stats::ConnStats;
use crate::tls::PreparedTls;
use anvil_domain::events::{ExecutionEvent, SessionCommand};
use anvil_domain::execution::*;
use anvil_domain::outcome::{GrpcStatusSource, ProtocolStatus};
use anvil_domain::request::{GrpcMode, GrpcWire};
use anvil_domain::settings::{HttpVersionPolicy, Limits, Timeouts};
use base64::Engine;
use bytes::{Buf, Bytes, BytesMut};
use http::{HeaderMap, HeaderName, HeaderValue, Method, Request};
use http_body_util::BodyExt;
use hyper::body::{Body, Frame, SizeHint};
use hyper::client::conn::{http1, http2};
use prost::Message as _;
use prost_reflect::{DescriptorPool, DynamicMessage, MessageDescriptor, MethodDescriptor};
use std::collections::{HashMap, VecDeque};
use std::convert::Infallible;
use std::future::Future;
use std::io::Read;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
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

pub(crate) fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(hi), Some(lo)) = (hex_value(bytes[i + 1]), hex_value(bytes[i + 2]))
        {
            out.push((hi << 4) | lo);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
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
/// client stream (half-close). `exact` is the whole body length when it is
/// known before sending (gRPC-Web), so HTTP/1.1 sends `Content-Length`.
pub struct GrpcBody {
    rx: mpsc::Receiver<Bytes>,
    exact: Option<u64>,
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
        match self.exact {
            Some(n) => SizeHint::with_exact(n),
            None => SizeHint::default(),
        }
    }
}

// ---------------------------------------------------------------- plan ---

/// Where the method's message types come from.
#[derive(Clone)]
pub enum Schema {
    Pool(DescriptorPool),
    Reflection,
}

/// Signs a request for the path and body it sends: given its path (the
/// URL's path prefix included) and its framed request message, the
/// request's headers (metadata and auth) with the signature over them. An
/// error fails the request before it is sent.
pub type SignFn = Arc<dyn Fn(&str, &Bytes) -> Result<Vec<(HeaderName, HeaderValue)>, TransportFailure> + Send + Sync>;

#[derive(Clone)]
pub struct GrpcPlan {
    /// TLS; `None` = cleartext (h2c for native gRPC; HTTP/1.1 or h2c for gRPC-Web).
    pub tls: Option<Arc<PreparedTls>>,
    pub host: String,
    pub port: u16,
    /// The `:authority` (HTTP/2, HTTP/3) or HTTP/1.1 `Host` (gRPC-Web): the
    /// request's explicit `Host` when it has one (what auth signed).
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
    /// With server reflection, the call's headers are signed here, once the
    /// schema is resolved and the message encoded, over the framed message of
    /// a unary or server-streaming call. They replace `headers` for the call.
    /// `None`: the call is sent with `headers`. The engine sets it only for a
    /// unary or server-streaming call; a call that streams requests is signed
    /// when it is prepared.
    pub sign: Option<SignFn>,
    /// With server reflection, each reflection request is signed here for
    /// its own path and framed message (a fresh signature, nonce or DPoP
    /// proof), and sent with the headers returned in place of `headers`,
    /// which were signed for the call. `None` (no auth): reflection
    /// requests are sent with `headers`.
    pub sign_reflection: Option<SignFn>,
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
    /// Native gRPC, or gRPC-Web binary / text.
    pub wire: GrpcWire,
    /// HTTP version policy. Native gRPC: HTTP/2 (TLS or h2c) unless an
    /// HTTP/3 policy is chosen. gRPC-Web: HTTP/1.1, HTTP/2, h2c, HTTP/3, or
    /// (automatic) ALPN `h2`/`http/1.1` over TLS and HTTP/1.1 in cleartext.
    pub version: HttpVersionPolicy,
    /// PROXY protocol header written at the head of each new TCP connection,
    /// before TLS (TCP legs only; HTTP/3 is refused before traffic).
    pub proxy_header: Option<crate::proxy_protocol::ConnectionHeader>,
    /// Reuse pooled connections from (and return them to) these channels.
    /// `None` (manual calls, interactive sessions, fresh-connection load):
    /// every call opens and closes its own connection.
    pub channels: Option<ChannelUse>,
}

impl GrpcPlan {
    /// Absolute URI (HTTP/2 `:scheme`/`:authority`/`:path`).
    fn uri(&self, path: &str) -> String {
        format!("{}://{}{}{}", if self.tls.is_some() { "https" } else { "http" }, self.authority, self.path_prefix, path)
    }

    /// Origin-form request target (HTTP/1.1).
    fn origin(&self, path: &str) -> String {
        format!("{}{}", self.path_prefix, path)
    }

    fn content_type(&self) -> &'static str {
        match self.wire {
            GrpcWire::Grpc => "application/grpc",
            GrpcWire::GrpcWeb => grpc_web::CT_BINARY,
            GrpcWire::GrpcWebText => grpc_web::CT_TEXT,
        }
    }

    /// The HTTP version used over TCP for this plan (also the target of an
    /// HTTP/3-with-fallback attempt's fallback).
    fn tcp_http(&self) -> TcpHttp {
        match (self.wire.is_web(), self.version) {
            (false, _) => TcpHttp::H2,
            (true, HttpVersionPolicy::Http1Only) => TcpHttp::H1,
            (true, HttpVersionPolicy::Http2Only | HttpVersionPolicy::H2c) => TcpHttp::H2,
            (true, _) => TcpHttp::Negotiate,
        }
    }
}

/// Combinations refused before any traffic; shared by the engine's
/// preparation and this adapter. Returns the explanation and the field.
pub fn unsupported_combination(
    wire: GrpcWire,
    mode: GrpcMode,
    reflection: bool,
    version: HttpVersionPolicy,
    tls: bool,
    proxy: bool,
) -> Option<(String, &'static str)> {
    use HttpVersionPolicy as V;
    if wire.is_web() {
        if matches!(mode, GrpcMode::ClientStreaming | GrpcMode::Bidirectional) {
            return Some((
                format!(
                    "gRPC-Web carries only unary and server-streaming calls, and this is a {mode:?} call: a gRPC-Web client sends the whole request body before it reads the response, so there is no client stream and no half-close. Use native gRPC (HTTP/2 or HTTP/3) for client-streaming and bidirectional methods"
                ),
                "grpc.wire",
            ));
        }
        if reflection {
            return Some((
                "server reflection is a bidirectional-streaming RPC, which gRPC-Web cannot carry; load the service's .proto files or a descriptor set to call it over gRPC-Web".into(),
                "grpc.schema",
            ));
        }
        match version {
            V::H2c if tls => return Some(("h2c (cleartext HTTP/2) cannot be used with a TLS URL".into(), "settings.http_version")),
            V::Http2Only if !tls => {
                return Some((
                    "HTTP/2-only over TLS was selected for a cleartext URL; choose h2c for cleartext HTTP/2".into(),
                    "settings.http_version",
                ));
            }
            _ => {}
        }
    } else if version == V::Http1Only {
        return Some((
            "native gRPC requires HTTP/2 or HTTP/3, and HTTP/1.1-only was selected; gRPC-Web (the grpc_web or grpc_web_text wire) runs over HTTP/1.1".into(),
            "settings.http_version",
        ));
    }
    if matches!(version, V::Http3Only | V::Http3WithFallback) {
        if !tls {
            return Some((
                "gRPC over HTTP/3 needs TLS (QUIC is always encrypted): use a grpcs:// or https:// URL, or HTTP/2 (h2c) for cleartext"
                    .into(),
                "settings.http_version",
            ));
        }
        if proxy {
            return Some(("HTTP/3 cannot be sent through the configured HTTP/SOCKS proxy".into(), "settings.proxy"));
        }
    }
    None
}

async fn next_cmd(rx: &mut Option<CommandRx>) -> Option<SessionCommand> {
    match rx {
        Some(r) => r.recv().await,
        None => std::future::pending().await,
    }
}

/// Request headers for a call: `meta` (metadata and auth) and the wire's own
/// fields.
fn call_headers(plan: &GrpcPlan, meta: &[(HeaderName, HeaderValue)], h1: bool) -> HeaderMap {
    let mut h = HeaderMap::new();
    for (n, v) in meta {
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
    if h1 && let Ok(v) = HeaderValue::from_str(&plan.authority) {
        h.insert(http::header::HOST, v);
    }
    let ct = HeaderValue::from_static(plan.content_type());
    h.insert(http::header::CONTENT_TYPE, ct.clone());
    if plan.wire.is_web() {
        // PROTOCOL-WEB: the response mode follows Accept; ask for the request's own.
        h.insert(http::header::ACCEPT, ct);
        h.insert("x-grpc-web", HeaderValue::from_static("1"));
    } else {
        h.insert(http::header::TE, HeaderValue::from_static("trailers"));
    }
    if !h.contains_key(http::header::USER_AGENT) {
        h.insert(http::header::USER_AGENT, HeaderValue::from_static(concat!("grpc-anvil/", env!("CARGO_PKG_VERSION"))));
    }
    h
}

/// Split complete messages out of the receive buffer (native framing).
fn next_message(buf: &mut BytesMut, max: usize) -> Result<Option<(bool, Bytes)>, FrameError> {
    match grpc_web::next_frame(buf, max, false)? {
        Some(WireFrame::Message { compressed, data }) => Ok(Some((compressed, data))),
        Some(WireFrame::Trailer(_)) => Err(FrameError::Invalid("a trailer frame is not valid in native gRPC".into())),
        None => Ok(None),
    }
}

fn frame_failure(e: FrameError) -> TransportFailure {
    match e {
        FrameError::TooLarge(m) => TransportFailure::new(Phase::Session, FailureKind::ResponseTooLargeLocal, m),
        FrameError::Invalid(m) => TransportFailure::new(Phase::Session, FailureKind::HttpProtocolError, m),
    }
}

fn gunzip(data: &[u8], max: usize) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(data).take(max as u64 + 1).read_to_end(&mut out).map_err(|e| e.to_string())?;
    if out.len() > max {
        return Err(format!("a decompressed message exceeds the local limit of {max} bytes"));
    }
    Ok(out)
}

// ------------------------------------------------------ request streams ---

/// How a call reaches the server over TCP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TcpHttp {
    /// HTTP/2: ALPN `h2` only over TLS, prior knowledge (h2c) in cleartext.
    H2,
    /// HTTP/1.1 (gRPC-Web).
    H1,
    /// gRPC-Web automatic: ALPN `h2`/`http/1.1` over TLS, HTTP/1.1 in cleartext.
    Negotiate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Leg {
    Tcp(TcpHttp),
    Quic,
}

/// A connection ready for request streams.
enum Conn {
    H1(http1::SendRequest<GrpcBody>),
    H2(http2::SendRequest<GrpcBody>),
    H3(crate::h3::SendReq),
}

impl Conn {
    fn is_h1(&self) -> bool {
        matches!(self, Conn::H1(_))
    }

    fn reset_note(&self) -> &'static str {
        match self {
            Conn::H1(_) => "the connection was closed",
            Conn::H2(_) => "RST_STREAM CANCEL",
            Conn::H3(_) => "the HTTP/3 stream was reset with H3_REQUEST_CANCELLED",
        }
    }
}

// ------------------------------------------------------------ channels ---

/// A pooled HTTP/2 or HTTP/3 connection (multiplexed, so it is shared).
#[derive(Clone)]
enum SharedConn {
    H2(http2::SendRequest<GrpcBody>),
    H3 { send: crate::h3::SendReq, quic: quinn::Connection },
}

#[derive(Clone)]
struct SharedChannel {
    conn: SharedConn,
    stats: Arc<ConnStats>,
    template: ConnectionObservation,
    served: Arc<std::sync::atomic::AtomicU32>,
}

impl SharedChannel {
    fn usable(&self) -> bool {
        match &self.conn {
            SharedConn::H2(s) => !s.is_closed(),
            SharedConn::H3 { quic, .. } => quic.close_reason().is_none(),
        }
    }

    /// Whether this is the HTTP/3 channel over `quic`.
    fn is_quic(&self, quic: &quinn::Connection) -> bool {
        matches!(&self.conn, SharedConn::H3 { quic: q, .. } if q.stable_id() == quic.stable_id())
    }
}

/// A pooled HTTP/1.1 connection (gRPC-Web): used by one call at a time.
struct ExclusiveChannel {
    sender: http1::SendRequest<GrpcBody>,
    stats: Arc<ConnStats>,
    template: ConnectionObservation,
    served: u32,
}

/// Reusable gRPC channels of one engine, keyed by destination and security
/// context (host, port, TLS fingerprint, proxy, HTTP version policy, wire,
/// DNS settings). Calls only use them when the plan carries a handle: the
/// load engine enables that for its persistent connection mode, so each
/// virtual user keeps one pooled HTTP/2 or HTTP/3 connection (HTTP/1.1 for
/// gRPC-Web) across its calls. A manual call opens its own connection so its
/// evidence covers the whole setup. HBONE tunnels are never pooled (a tunnel
/// carries one execution's identity and headers).
///
/// Every key starts with the workspace isolation. [`Channels::clear`] (a
/// lock) and [`Channels::clear_isolation`] (a workspace delete) start a new
/// generation: a call of an execution that began before either (see
/// [`ChannelUse::generation`]) does not return its connection to the
/// channels it covers, and the connection closes when the call ends.
#[derive(Default)]
pub struct Channels {
    /// Advanced by the clears; taken first, before `shared` or `exclusive`.
    generations: parking_lot::Mutex<Generations>,
    shared: parking_lot::Mutex<HashMap<String, SharedChannel>>,
    exclusive: parking_lot::Mutex<HashMap<String, Vec<ExclusiveChannel>>>,
}

/// A plan's use of an engine's [`Channels`].
#[derive(Clone)]
pub struct ChannelUse {
    pub channels: Arc<Channels>,
    /// Workspace isolation component of the channel key.
    pub isolation: String,
    /// [`Channels::generation`] when the execution began: after a clear
    /// since then that covers `isolation`, no connection is returned to
    /// the channels.
    pub generation: u64,
}

const MAX_EXCLUSIVE_PER_KEY: usize = 8;

impl Channels {
    pub fn new() -> Self {
        Channels::default()
    }

    /// Drop every pooled connection (e.g. on lock or at the end of a run)
    /// and start a new generation.
    pub fn clear(&self) {
        let mut generations = self.generations.lock();
        generations.clear();
        self.shared.lock().clear();
        self.exclusive.lock().clear();
    }

    /// Drop the pooled connections of one workspace isolation (a workspace
    /// delete) and start a new generation.
    pub fn clear_isolation(&self, isolation: &str) {
        let mut generations = self.generations.lock();
        generations.clear_isolation(isolation);
        self.shared.lock().retain(|k, _| !in_isolation(k, isolation));
        self.exclusive.lock().retain(|k, _| !in_isolation(k, isolation));
    }

    /// The current generation, taken when an execution begins (see
    /// [`ChannelUse::generation`]).
    pub fn generation(&self) -> u64 {
        self.generations.lock().current()
    }

    /// Pooled connections currently held (tests and diagnostics).
    pub fn len(&self) -> usize {
        self.shared.lock().len() + self.exclusive.lock().values().map(Vec::len).sum::<usize>()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn checkout(&self, key: &str) -> Option<Connected> {
        {
            let mut shared = self.shared.lock();
            match shared.get(key) {
                Some(ch) if ch.usable() => {
                    let ch = ch.clone();
                    let mut observation = ch.template.clone();
                    observation.reused = true;
                    observation.prior_requests = ch.served.fetch_add(1, Ordering::SeqCst);
                    let (conn, quic) = match ch.conn {
                        SharedConn::H2(s) => (Conn::H2(s), None),
                        SharedConn::H3 { send, quic } => (Conn::H3(send), Some(quic)),
                    };
                    return Some(Connected { conn, stats: ch.stats, observation, quic });
                }
                Some(_) => {
                    shared.remove(key);
                }
                None => {}
            }
        }
        let mut exclusive = self.exclusive.lock();
        let list = exclusive.get_mut(key)?;
        while let Some(ch) = list.pop() {
            if ch.sender.is_closed() || !ch.sender.is_ready() {
                continue;
            }
            let mut observation = ch.template.clone();
            observation.reused = true;
            observation.prior_requests = ch.served;
            return Some(Connected { conn: Conn::H1(ch.sender), stats: ch.stats, observation, quic: None });
        }
        None
    }

    /// Return a connection after a call. HTTP/2 stays pooled while it is
    /// open; HTTP/3 and HTTP/1.1 only after a clean call (a canceled HTTP/3
    /// stream is not reused: the connection is closed instead). After a
    /// clear since `generation` that covers `key`, it is not pooled.
    async fn checkin(&self, key: &str, generation: u64, c: Connected, clean: bool) {
        let Connected { conn, stats, mut observation, quic } = c;
        let was_reused = observation.reused;
        observation.reused = false;
        match conn {
            Conn::H2(s) => {
                if s.is_closed() {
                    self.shared.lock().remove(key);
                    return;
                }
                let generations = self.generations.lock();
                let mut shared = self.shared.lock();
                if generations.admits(generation, key) && !shared.contains_key(key) {
                    let served = Arc::new(std::sync::atomic::AtomicU32::new(observation.prior_requests + 1));
                    observation.prior_requests = 0;
                    shared.insert(key.to_string(), SharedChannel { conn: SharedConn::H2(s), stats, template: observation, served });
                }
            }
            Conn::H3(send) => {
                let Some(quic) = quic else { return };
                if !clean || quic.close_reason().is_some() {
                    self.shared.lock().remove(key);
                    quic.close(crate::h3::H3_NO_ERROR.into(), b"");
                    return;
                }
                let generations = self.generations.lock();
                let mut shared = self.shared.lock();
                // A reused channel is still pooled: it stays open for the
                // calls that share it.
                let pooled = shared.get(key).map(|ch| ch.is_quic(&quic));
                if pooled == Some(true) {
                    return;
                }
                if pooled.is_some() || !generations.admits(generation, key) {
                    // Not kept (another channel is pooled under the key, or a
                    // lock or a delete of its workspace fenced it). A channel
                    // this call opened is closed now; a reused one is only
                    // dropped, since other calls may still be streaming on it.
                    if !was_reused {
                        quic.close(crate::h3::H3_NO_ERROR.into(), b"");
                    }
                    return;
                }
                let served = Arc::new(std::sync::atomic::AtomicU32::new(observation.prior_requests + 1));
                observation.prior_requests = 0;
                shared.insert(key.to_string(), SharedChannel { conn: SharedConn::H3 { send, quic }, stats, template: observation, served });
            }
            Conn::H1(mut s) => {
                if !clean {
                    return;
                }
                // The HTTP/1.1 connection becomes ready once hyper has
                // processed the end of the response; wait briefly for it.
                let ready = tokio::time::timeout(Duration::from_millis(50), s.ready()).await;
                if !matches!(ready, Ok(Ok(()))) {
                    return;
                }
                let generations = self.generations.lock();
                if !generations.admits(generation, key) {
                    return;
                }
                let mut exclusive = self.exclusive.lock();
                let list = exclusive.entry(key.to_string()).or_default();
                if list.len() < MAX_EXCLUSIVE_PER_KEY {
                    let served = observation.prior_requests + 1;
                    list.push(ExclusiveChannel { sender: s, stats, template: observation, served });
                }
            }
        }
    }
}

/// Pool key for a plan's connection on one leg, in one workspace isolation.
fn channel_key(isolation: &str, plan: &GrpcPlan, leg: Leg) -> String {
    let proxy = plan
        .proxy
        .as_ref()
        .map(|p| format!("{:?}:{}:{}:{}", p.kind, p.host, p.port, p.tls.as_ref().map(|t| t.fingerprint.as_str()).unwrap_or("")))
        .unwrap_or_default();
    let dns = format!("{:?}{:?}{:?}", plan.dns.resolver, plan.dns.overrides, plan.dns.ip_preference);
    // A connection's PROXY header is fixed for its lifetime, so channels with
    // different header plans (or none) are never shared.
    let header = plan.proxy_header.as_ref().map(|h| h.pool_key()).unwrap_or_default();
    // A connection advertises (and HTTP/3 enforces) the header limit it was
    // opened with, so a call with a smaller one never reuses it.
    format!(
        "{}|{:?}|{}:{}|{}|{}|{:?}|{}|{}|{}|fs={}",
        isolation,
        leg,
        plan.host.to_ascii_lowercase(),
        plan.port,
        plan.tls.as_ref().map(|t| t.fingerprint.as_str()).unwrap_or("cleartext"),
        proxy,
        plan.version,
        plan.wire.is_web(),
        crate::certs::sha256_hex(dns.as_bytes()),
        header,
        crate::h3::field_section_limit(&plan.limits)
    )
}

/// Shared between the call loop and the HTTP/3 request-stream tasks.
#[derive(Clone)]
struct StreamCtl {
    /// Connection bytes (TCP) or this stream's DATA bytes (HTTP/3).
    stats: Arc<ConnStats>,
    /// HTTP/3: the request stream was opened (HEADERS handed to QUIC).
    opened: Arc<AtomicBool>,
    /// HTTP/3: reset the request stream (deadline, cancel, local failure).
    abort: CancellationToken,
}

impl StreamCtl {
    fn new(stats: Arc<ConnStats>) -> Self {
        StreamCtl { stats, opened: Arc::new(AtomicBool::new(false)), abort: CancellationToken::new() }
    }
}

type BodyItem = Option<Result<Frame<Bytes>, TransportFailure>>;

/// The response body: hyper's (HTTP/1.1, HTTP/2) or the HTTP/3 downlink
/// task's channel. Errors are typed at the source.
enum RespBody {
    Hyper(hyper::body::Incoming, Arc<ConnStats>),
    H3(mpsc::Receiver<Result<Frame<Bytes>, TransportFailure>>),
}

impl RespBody {
    async fn next(&mut self) -> BodyItem {
        match self {
            RespBody::Hyper(b, stats) => match b.frame().await {
                None => None,
                Some(Ok(f)) => Some(Ok(f)),
                Some(Err(e)) => {
                    let mut f = classify_hyper(&e, HyperStage::Body);
                    if let Some((k, a)) = stats.tls_error() {
                        f.kind = k;
                        f.tls_alert = a;
                    }
                    Some(Err(f))
                }
            },
            RespBody::H3(rx) => rx.recv().await,
        }
    }
}

enum ReflectionBodyEvent {
    Item(BodyItem),
    Idle,
    Deadline,
    Canceled,
}

async fn next_reflection_body_item(
    body: &mut RespBody,
    idle_deadline: Option<Instant>,
    reflection_deadline: Option<Instant>,
    cancel: &CancellationToken,
) -> ReflectionBodyEvent {
    tokio::select! {
        item = body.next() => ReflectionBodyEvent::Item(item),
        _ = sleep_until_opt(idle_deadline) => ReflectionBodyEvent::Idle,
        _ = sleep_until_opt(reflection_deadline) => ReflectionBodyEvent::Deadline,
        _ = cancel.cancelled() => ReflectionBodyEvent::Canceled,
    }
}

struct RespHead {
    status: u16,
    version: http::Version,
    headers: HeaderMap,
    body: RespBody,
}

type HeadFut = Pin<Box<dyn Future<Output = Result<RespHead, TransportFailure>> + Send>>;

/// Open a request stream and send its headers; the request body is fed from
/// `body`. The returned future resolves with the response head.
fn start(
    conn: &mut Conn,
    plan: &GrpcPlan,
    path: &str,
    headers: HeaderMap,
    body: mpsc::Receiver<Bytes>,
    exact: Option<u64>,
    ctl: &StreamCtl,
) -> Result<HeadFut, TransportFailure> {
    let bad = |e: http::Error| {
        TransportFailure::new(Phase::Prepare, FailureKind::InvalidUrl, format!("the gRPC request could not be built: {e}"))
            .with_field("url")
    };
    let hyper_head = |fut: Pin<Box<dyn Future<Output = Result<hyper::Response<hyper::body::Incoming>, hyper::Error>> + Send>>,
                      stats: Arc<ConnStats>|
     -> HeadFut {
        Box::pin(async move {
            match fut.await {
                Ok(resp) => {
                    let (parts, b) = resp.into_parts();
                    Ok(RespHead {
                        status: parts.status.as_u16(),
                        version: parts.version,
                        headers: parts.headers,
                        body: RespBody::Hyper(b, stats),
                    })
                }
                Err(e) => {
                    let mut f = classify_hyper(&e, HyperStage::AwaitHeaders);
                    if let Some((k, a)) = stats.tls_error() {
                        f.kind = k;
                        f.tls_alert = a;
                    }
                    Err(f)
                }
            }
        })
    };
    match conn {
        Conn::H1(s) => {
            let mut req = Request::builder().method(Method::POST).uri(plan.origin(path)).body(GrpcBody { rx: body, exact }).map_err(bad)?;
            *req.headers_mut() = headers;
            Ok(hyper_head(Box::pin(s.send_request(req)), ctl.stats.clone()))
        }
        Conn::H2(s) => {
            let mut req = Request::builder().method(Method::POST).uri(plan.uri(path)).body(GrpcBody { rx: body, exact }).map_err(bad)?;
            *req.headers_mut() = headers;
            Ok(hyper_head(Box::pin(s.send_request(req)), ctl.stats.clone()))
        }
        Conn::H3(send) => {
            let mut req = Request::builder()
                .method(Method::POST)
                .uri(format!("https://{}{}", plan.authority, plan.origin(path)))
                .body(())
                .map_err(bad)?;
            *req.headers_mut() = headers;
            let mut send = send.clone();
            let ctl = ctl.clone();
            Ok(Box::pin(async move {
                let stream = send.send_request(req).await.map_err(|e| {
                    TransportFailure::new(
                        Phase::AwaitResponseHeaders,
                        FailureKind::RequestWriteFailed,
                        format!("the HTTP/3 request stream could not be opened: {e}"),
                    )
                })?;
                ctl.opened.store(true, Ordering::SeqCst);
                let (send_half, mut recv_half) = stream.split();
                tokio::spawn(h3_uplink(send_half, body, ctl.clone()));
                let resp = tokio::select! {
                    r = recv_half.recv_response() => r.map_err(|e| crate::h3::stream_failure(
                        &e,
                        Phase::AwaitResponseHeaders,
                        FailureKind::ResetBeforeResponse,
                        "the HTTP/3 stream ended before response headers",
                    ))?,
                    _ = ctl.abort.cancelled() => {
                        recv_half.stop_sending(h3::error::Code::H3_REQUEST_CANCELLED);
                        return Err(TransportFailure::new(Phase::AwaitResponseHeaders, FailureKind::Canceled, "the HTTP/3 request stream was reset"));
                    }
                };
                let (parts, ()) = resp.into_parts();
                let (tx, rx) = mpsc::channel(16);
                tokio::spawn(h3_downlink(recv_half, tx, ctl));
                Ok(RespHead {
                    status: parts.status.as_u16(),
                    version: http::Version::HTTP_3,
                    headers: parts.headers,
                    body: RespBody::H3(rx),
                })
            }))
        }
    }
}

type H3Send = h3::client::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>;
type H3Recv = h3::client::RequestStream<h3_quinn::RecvStream, Bytes>;

/// HTTP/3 request body: DATA frames from the channel; a closed channel
/// finishes the stream (the client half-close), an abort resets it.
async fn h3_uplink(mut send: H3Send, mut body: mpsc::Receiver<Bytes>, ctl: StreamCtl) {
    enum Up {
        Data(Option<Bytes>),
        Abort,
    }
    loop {
        let next = tokio::select! {
            b = body.recv() => Up::Data(b),
            _ = ctl.abort.cancelled() => Up::Abort,
        };
        match next {
            Up::Data(Some(b)) => {
                let n = b.len();
                if send.send_data(b).await.is_err() {
                    // The peer stopped reading; dropping `body` tells the call loop.
                    return;
                }
                ctl.stats.record_write(n);
            }
            Up::Data(None) => {
                let _ = send.finish().await;
                return;
            }
            Up::Abort => {
                send.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
                return;
            }
        }
    }
}

/// HTTP/3 response body: DATA, then trailers, as frames on a channel; a
/// stream error is sent as a typed failure.
async fn h3_downlink(mut recv: H3Recv, tx: mpsc::Sender<Result<Frame<Bytes>, TransportFailure>>, ctl: StreamCtl) {
    enum Down<T> {
        Data(Result<Option<T>, h3::error::StreamError>),
        Abort,
    }
    loop {
        let next = tokio::select! {
            r = recv.recv_data() => Down::Data(r.map(|o| o.map(|mut c| c.copy_to_bytes(c.remaining())))),
            _ = ctl.abort.cancelled() => Down::Abort,
        };
        match next {
            Down::Data(Ok(Some(d))) => {
                ctl.stats.record_read(d.len());
                if tx.send(Ok(Frame::data(d))).await.is_err() {
                    recv.stop_sending(h3::error::Code::H3_REQUEST_CANCELLED);
                    return;
                }
            }
            Down::Data(Ok(None)) => break,
            Down::Data(Err(e)) => {
                let what = "the HTTP/3 response stream ended abnormally";
                let _ = tx.send(Err(crate::h3::stream_failure(&e, Phase::ResponseBody, FailureKind::BodyReset, what))).await;
                return;
            }
            Down::Abort => {
                recv.stop_sending(h3::error::Code::H3_REQUEST_CANCELLED);
                return;
            }
        }
    }
    // h3 returns the trailers only once the stream ends, so an abort stops
    // this stream alone rather than waiting for the peer.
    let trailers = tokio::select! {
        t = recv.recv_trailers() => t,
        _ = ctl.abort.cancelled() => {
            recv.stop_sending(h3::error::Code::H3_REQUEST_CANCELLED);
            return;
        }
    };
    match trailers {
        Ok(Some(t)) => {
            let _ = tx.send(Ok(Frame::trailers(t))).await;
        }
        Ok(None) => {}
        Err(e) => {
            let what = "the HTTP/3 response trailers could not be read";
            let _ = tx.send(Err(crate::h3::stream_failure(&e, Phase::ResponseBody, FailureKind::BodyReset, what))).await;
        }
    }
}

// ----------------------------------------------------------- reflection ---

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
    /// `failure` is auth's: the request could not be signed and was not sent.
    sign_failed: bool,
}

const REFLECTION_TIMEOUT_MS: u64 = 30_000;

fn reflection_deadline(total_deadline: Option<Instant>, now: Instant) -> (Instant, u64) {
    let cap = now + Duration::from_millis(REFLECTION_TIMEOUT_MS);
    let deadline = total_deadline.map(|deadline| deadline.min(cap)).unwrap_or(cap);
    let deadline_ms = deadline.saturating_duration_since(now).as_millis().try_into().unwrap_or(u64::MAX);
    (deadline, deadline_ms)
}

/// The cumulative wire and decoded bytes received during one reflection attempt.
struct ReflectionBudget {
    used_bytes: usize,
    max_bytes: usize,
}

impl ReflectionBudget {
    fn charge(&mut self, bytes: usize) -> Result<(), TransportFailure> {
        self.used_bytes = self.used_bytes.checked_add(bytes).filter(|total| *total <= self.max_bytes).ok_or_else(|| {
            TransportFailure::new(
                Phase::ResponseBody,
                FailureKind::ResponseTooLargeLocal,
                "server reflection exceeded its cumulative wire and decoded response byte budget",
            )
        })?;
        Ok(())
    }
}

fn append_reflection_data(
    buf: &mut BytesMut,
    data: &[u8],
    budget: &mut ReflectionBudget,
    message_count: &mut usize,
    max_message_bytes: usize,
) -> Result<Vec<Bytes>, TransportFailure> {
    budget.charge(data.len())?;
    buf.extend_from_slice(data);
    let mut messages = Vec::new();
    loop {
        match next_message(buf, max_message_bytes) {
            Ok(Some((false, message))) => {
                *message_count += 1;
                if *message_count > 1 {
                    return Err(TransportFailure::new(
                        Phase::ResponseBody,
                        FailureKind::HttpProtocolError,
                        "the reflection response contained more than one message",
                    ));
                }
                budget.charge(message.len())?;
                messages.push(message);
            }
            Ok(Some((true, _))) => {
                return Err(TransportFailure::new(
                    Phase::ResponseBody,
                    FailureKind::HttpProtocolError,
                    "a compressed reflection response was not negotiated",
                ));
            }
            Ok(None) => break,
            Err(error) => {
                let mut failure = frame_failure(error);
                failure.phase = Phase::ResponseBody;
                return Err(failure);
            }
        }
    }
    Ok(messages)
}

impl OneShot {
    fn empty(status: Option<u16>, grpc_status: Option<i32>) -> Self {
        OneShot {
            status,
            version: http::Version::HTTP_2,
            headers: vec![],
            trailers: vec![],
            messages: vec![],
            grpc_status,
            grpc_message: None,
            failure: None,
            sign_failed: false,
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn one_shot(
    conn: &mut Conn,
    plan: &GrpcPlan,
    path: &str,
    msg: &[u8],
    stats: &Arc<ConnStats>,
    cancel: &CancellationToken,
    reflection_deadline: Option<Instant>,
    reflection_deadline_ms: u64,
    budget: &mut ReflectionBudget,
) -> OneShot {
    let body = frame(msg);
    let mut out = OneShot::empty(None, None);
    if reflection_deadline.is_some_and(|deadline| Instant::now() >= deadline) {
        out.failure = Some(
            TransportFailure::new(Phase::AwaitResponseHeaders, FailureKind::TotalTimeout, "the server reflection deadline elapsed")
                .with_deadline(Some(reflection_deadline_ms)),
        );
        return out;
    }
    // Signed for the reflection request's own path and body, never sent
    // with the signature made for the call.
    let signed = match &plan.sign_reflection {
        Some(sign) => match sign(&plan.origin(path), &body) {
            Ok(h) => Some(h),
            Err(f) => {
                out.failure = Some(f);
                out.sign_failed = true;
                return out;
            }
        },
        None => None,
    };
    let (tx, rx) = mpsc::channel(1);
    let _ = tx.try_send(body);
    drop(tx);
    let ctl = StreamCtl::new(stats.clone());
    let headers = call_headers(plan, signed.as_deref().unwrap_or(&plan.headers), conn.is_h1());
    let fut = match start(conn, plan, path, headers, rx, None, &ctl) {
        Ok(f) => f,
        Err(f) => {
            out.failure = Some(f);
            return out;
        }
    };
    let deadline = deadline_from(plan.timeouts.response_headers_ms.or(Some(30_000)));
    let head = tokio::select! {
        r = fut => r,
        _ = sleep_until_opt(deadline) => Err(TransportFailure::new(Phase::AwaitResponseHeaders, FailureKind::ResponseHeadersTimeout, "no answer to the reflection request").with_deadline(plan.timeouts.response_headers_ms)),
        _ = sleep_until_opt(reflection_deadline) => Err(TransportFailure::new(
            Phase::AwaitResponseHeaders,
            FailureKind::TotalTimeout,
            "the server reflection deadline elapsed",
        ).with_deadline(Some(reflection_deadline_ms))),
        _ = cancel.cancelled() => Err(TransportFailure::new(Phase::AwaitResponseHeaders, FailureKind::Canceled, "canceled during server reflection")),
    };
    let head = match head {
        Ok(h) => h,
        Err(f) => {
            ctl.abort.cancel();
            out.failure = Some(f);
            return out;
        }
    };
    out.status = Some(head.status);
    out.version = head.version;
    out.headers = header_entries(&head.headers);
    if let Some(s) = head.headers.get("grpc-status").and_then(|v| v.to_str().ok()).and_then(|s| s.trim().parse().ok()) {
        out.grpc_status = Some(s);
        out.grpc_message = head.headers.get("grpc-message").and_then(|v| v.to_str().ok()).map(percent_decode);
    }
    let mut body = head.body;
    let mut buf = BytesMut::new();
    let mut message_count = 0usize;
    loop {
        let idle = deadline_from(plan.timeouts.body_idle_ms.or(Some(30_000)));
        let item = match next_reflection_body_item(&mut body, idle, reflection_deadline, cancel).await {
            ReflectionBodyEvent::Item(item) => item,
            ReflectionBodyEvent::Idle => {
                Some(Err(TransportFailure::new(Phase::ResponseBody, FailureKind::BodyIdleTimeout, "the reflection response stalled")))
            }
            ReflectionBodyEvent::Deadline => {
                Some(Err(TransportFailure::new(Phase::ResponseBody, FailureKind::TotalTimeout, "the server reflection deadline elapsed")
                    .with_deadline(Some(reflection_deadline_ms))))
            }
            ReflectionBodyEvent::Canceled => {
                Some(Err(TransportFailure::new(Phase::ResponseBody, FailureKind::Canceled, "canceled during server reflection")))
            }
        };
        match item {
            None => break,
            Some(Ok(fr)) => {
                if fr.is_data() {
                    let data = fr.into_data().unwrap_or_default();
                    match append_reflection_data(&mut buf, &data, budget, &mut message_count, plan.max_message_bytes) {
                        Ok(messages) => out.messages.extend(messages),
                        Err(failure) => {
                            out.failure = Some(failure);
                            ctl.abort.cancel();
                            return out;
                        }
                    }
                } else if let Ok(t) = fr.into_trailers() {
                    out.trailers = header_entries(&t);
                    out.grpc_status = t.get("grpc-status").and_then(|v| v.to_str().ok()).and_then(|s| s.trim().parse().ok());
                    out.grpc_message = t.get("grpc-message").and_then(|v| v.to_str().ok()).map(percent_decode);
                }
            }
            Some(Err(f)) => {
                ctl.abort.cancel();
                out.failure = Some(f);
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
/// server reflection, v1 first and v1alpha when v1 is unimplemented. Runs on
/// the call's own connection (HTTP/2 or HTTP/3).
async fn reflect(
    conn: &mut Conn,
    plan: &GrpcPlan,
    stats: &Arc<ConnStats>,
    cancel: &CancellationToken,
    total_deadline: Option<Instant>,
) -> Result<(DescriptorPool, ReflectionOutcome), ReflectError> {
    // Reflection has its own absolute cap, including interactive calls whose
    // session deadline is intentionally unbounded. The call deadline can only
    // shorten this limit.
    let (reflection_deadline, reflection_deadline_ms) = reflection_deadline(total_deadline, Instant::now());
    let mut budget = ReflectionBudget { used_bytes: 0, max_bytes: usize::try_from(plan.limits.max_response_bytes).unwrap_or(usize::MAX) };
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
            let request = q.encode_to_vec();
            let r =
                one_shot(conn, plan, &path, &request, stats, cancel, Some(reflection_deadline), reflection_deadline_ms, &mut budget).await;
            let outcome = |problem: String, r: &OneShot| ReflectionOutcome {
                service: svc.trim_end_matches(".ServerReflection").to_string(),
                http_status: r.status,
                grpc_status: r.grpc_status,
                grpc_message: r.grpc_message.clone(),
                succeeded: false,
                problem: Some(problem),
                auth_failed: r.sign_failed,
            };
            if let Some(f) = r.failure.as_ref().filter(|_| r.sign_failed) {
                let o = outcome(format!("auth could not be prepared for the reflection request, so it was not sent: {}", f.message), &r);
                return Err(ReflectError::Refused(Box::new(r), o));
            }
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
            auth_failed: false,
        };
        return match pool.add_file_descriptor_protos(files.into_values()) {
            Ok(()) => Ok((pool, outcome)),
            Err(e) => Err(ReflectError::Refused(
                Box::new(OneShot::empty(Some(200), Some(0))),
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
            Box::new(OneShot::empty(None, None)),
            ReflectionOutcome {
                service: "grpc.reflection".into(),
                http_status: None,
                grpc_status: None,
                grpc_message: None,
                succeeded: false,
                problem: Some("server reflection was not attempted".into()),
                auth_failed: false,
            },
        )),
    }
}

// ----------------------------------------------------------------- run ---

/// Pre-traffic work shared by every attempt: the method (local schema) and
/// the encoded scripted messages.
struct Local {
    method: Option<MethodDescriptor>,
    encoded: Option<Vec<(Bytes, String)>>,
}

fn encode_all(plan: &GrpcPlan, m: &MethodDescriptor) -> Result<Vec<(Bytes, String)>, TransportFailure> {
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
}

fn local_checks(plan: &GrpcPlan) -> Result<Local, TransportFailure> {
    if let Some((msg, field)) = unsupported_combination(
        plan.wire,
        plan.mode,
        matches!(plan.schema, Schema::Reflection),
        plan.version,
        plan.tls.is_some(),
        plan.proxy.is_some(),
    ) {
        return Err(TransportFailure::new(Phase::Prepare, FailureKind::UnsupportedCombination, msg).with_field(field));
    }
    let mut local = Local { method: None, encoded: None };
    if let Schema::Pool(pool) = &plan.schema {
        let m = resolve_method(pool, &plan.service, &plan.method, plan.mode)?;
        local.encoded = Some(encode_all(plan, &m)?);
        local.method = Some(m);
    }
    Ok(local)
}

/// Run the call. The HTTP version policy selects HTTP/3 (with an optional,
/// separately recorded TCP fallback when HTTP/3 fails before the call was
/// sent) or a TCP connection; everything that can be checked locally is
/// checked before any traffic.
pub async fn run(plan: &GrpcPlan, events: &EventCtx, cancel: &CancellationToken, mut commands: Option<CommandRx>) -> SessionOutput {
    let local = match local_checks(plan) {
        Ok(l) => l,
        Err(f) => {
            let rec = Recorder::new(0, events.clone());
            events.emit(ExecutionEvent::AttemptStarted { execution_id: events.execution_id, attempt: 0 });
            let obs = new_attempt(0, AttemptReason::Initial, "POST", &plan.display_url);
            return SessionOutput::single(
                fail_attempt(rec, obs, f, DispatchState::NotDispatched, events),
                None,
                ProtocolStatus::None,
                SessionFacts::default(),
            );
        }
    };
    let tcp = Leg::Tcp(plan.tcp_http());
    match plan.version {
        HttpVersionPolicy::Http3Only => attempt(plan, &local, Leg::Quic, 0, AttemptReason::Initial, events, cancel, &mut commands).await,
        HttpVersionPolicy::Http3WithFallback => {
            let first = attempt(plan, &local, Leg::Quic, 0, AttemptReason::Initial, events, cancel, &mut commands).await;
            let fall_back = first.attempts.last().is_some_and(|a| {
                a.response.is_none()
                    && a.observation.dispatch == DispatchState::NotDispatched
                    && a.observation.failure.as_ref().is_some_and(|f| f.kind != FailureKind::Canceled && !f.kind.is_local_preparation())
            }) && !cancel.is_cancelled();
            if !fall_back {
                return first;
            }
            let reason = AttemptReason::ProtocolFallback { from: "h3".into() };
            let mut out = attempt(plan, &local, tcp, 1, reason, events, cancel, &mut commands).await;
            let mut attempts = first.attempts;
            attempts.append(&mut out.attempts);
            out.attempts = attempts;
            out.facts.notes.insert(
                0,
                "HTTP/3 was attempted first and failed before the call was sent; the call was made again over TCP as a separate attempt"
                    .into(),
            );
            out
        }
        _ => attempt(plan, &local, tcp, 0, AttemptReason::Initial, events, cancel, &mut commands).await,
    }
}

struct Connected {
    conn: Conn,
    stats: Arc<ConnStats>,
    observation: ConnectionObservation,
    quic: Option<quinn::Connection>,
}

/// TCP (DNS, connect, proxy, TLS, HTTP/1.1 or HTTP/2 setup) or QUIC (DNS,
/// QUIC handshake with TLS 1.3 inside, HTTP/3 setup).
async fn connect(
    rec: &mut Recorder,
    plan: &GrpcPlan,
    leg: Leg,
    cancel: &CancellationToken,
    total_deadline: Option<Instant>,
) -> Result<Connected, (TransportFailure, Option<ConnectionObservation>)> {
    let t = match leg {
        Leg::Quic => {
            let Some(tls) = plan.tls.clone() else {
                return Err((
                    TransportFailure::new(Phase::Prepare, FailureKind::TlsProfileInvalid, "no TLS configuration for HTTP/3"),
                    None,
                ));
            };
            let c = crate::h3::quic_connect(
                rec,
                &plan.host,
                plan.port,
                &plan.dns,
                &plan.timeouts,
                &plan.limits,
                &tls,
                crate::h3::client_endpoint,
                cancel,
            )
            .await?;
            return Ok(Connected { conn: Conn::H3(c.send), stats: ConnStats::new(), observation: c.observation, quic: Some(c.quic) });
        }
        Leg::Tcp(t) => t,
    };
    let tls = plan.tls.is_some();
    let alpn: &[&str] = match (tls, t) {
        (false, _) => &[],
        (true, TcpHttp::H2) => &["h2"],
        (true, TcpHttp::H1) => &["http/1.1"],
        (true, TcpHttp::Negotiate) => &["h2", "http/1.1"],
    };
    let target = Target { host: &plan.host, port: plan.port, tls: plan.tls.as_deref(), alpn, http_forward_via_proxy: false };
    let header = plan.proxy_header.as_ref().map(crate::connector::PreTlsHeader::of);
    let est = establish_guarded_with(rec, &target, &plan.dns, &plan.timeouts, plan.proxy.as_ref(), cancel, total_deadline, header).await?;
    let negotiated = est.observation.tls.as_ref().and_then(|t| t.alpn_negotiated.clone());
    let use_h2 = match (tls, t) {
        (true, TcpHttp::H2) => {
            if negotiated.as_deref() != Some("h2") {
                let what = if plan.wire.is_web() { "HTTP/2-only gRPC-Web" } else { "gRPC" };
                let f = TransportFailure::new(
                    Phase::TlsHandshake,
                    FailureKind::TlsAlpnMismatch,
                    format!(
                        "{what} needs HTTP/2 (ALPN 'h2') but the peer negotiated {}",
                        negotiated.map(|s| format!("'{s}'")).unwrap_or_else(|| "no ALPN protocol".into())
                    ),
                );
                return Err((f, Some(est.observation)));
            }
            true
        }
        (false, TcpHttp::H2) => true,
        (true, TcpHttp::Negotiate) => negotiated.as_deref() == Some("h2"),
        _ => false,
    };
    let HttpConn { sender, stats, observation, .. } =
        http_handshake::<GrpcBody>(rec, est, use_h2, &plan.limits).await.map_err(|(f, o)| (f, Some(o)))?;
    let conn = match sender {
        HttpSender::H1(s) => Conn::H1(s),
        HttpSender::H2(s) => Conn::H2(s),
    };
    Ok(Connected { conn, stats, observation, quic: None })
}

#[allow(clippy::too_many_arguments)]
async fn attempt(
    plan: &GrpcPlan,
    local: &Local,
    leg: Leg,
    index: u32,
    reason: AttemptReason,
    events: &EventCtx,
    cancel: &CancellationToken,
    commands: &mut Option<CommandRx>,
) -> SessionOutput {
    let interactive = commands.is_some();
    let mut rec = Recorder::new(index, events.clone());
    events.emit(ExecutionEvent::AttemptStarted { execution_id: events.execution_id, attempt: index });
    let mut obs = new_attempt(index, reason, "POST", &plan.display_url);
    let total_deadline = if interactive { None } else { deadline_from(plan.timeouts.total_ms) };
    // Channel reuse (load, persistent mode): never for interactive calls or HBONE tunnels.
    let pool = plan
        .channels
        .as_ref()
        .filter(|_| !interactive && !crate::hbone::is_hbone(plan.proxy.as_ref()))
        .map(|u| (u, channel_key(&u.isolation, plan, leg)));
    let pooled = pool.as_ref().and_then(|(u, key)| u.channels.checkout(key));
    let connected = match pooled {
        Some(c) => {
            let detail = Some("pooled gRPC channel");
            rec.mark(Phase::Dns, PhaseStatus::Reused, detail);
            match leg {
                Leg::Quic => rec.mark(Phase::QuicHandshake, PhaseStatus::Reused, detail),
                Leg::Tcp(_) => {
                    rec.mark(Phase::Connect, PhaseStatus::Reused, detail);
                    if plan.tls.is_some() {
                        rec.mark(Phase::TlsHandshake, PhaseStatus::Reused, detail);
                    }
                }
            }
            c
        }
        None => match connect(&mut rec, plan, leg, cancel, total_deadline).await {
            Ok(c) => c,
            Err((f, cobs)) => {
                obs.connection = cobs;
                return SessionOutput::single(
                    fail_attempt(rec, obs, f, DispatchState::NotDispatched, events),
                    None,
                    ProtocolStatus::None,
                    SessionFacts::default(),
                );
            }
        },
    };
    let Connected { mut conn, stats, observation, quic } = connected;
    obs.connection = Some(observation.clone());
    let cx = CallCx { plan, events, cancel, total_deadline, index };
    let out = exchange(cx, local, &mut conn, stats.clone(), rec, obs, commands).await;
    match pool {
        Some((u, key)) => {
            let last = out.attempts.last();
            let clean = last.is_some_and(|a| {
                a.observation.failure.is_none() && a.response.as_ref().is_some_and(|r| r.body.completeness == BodyCompleteness::Complete)
            });
            u.channels.checkin(&key, u.generation, Connected { conn, stats, observation, quic }, clean).await;
        }
        None => {
            if let Some(q) = quic {
                q.close(crate::h3::H3_NO_ERROR.into(), b"");
            }
        }
    }
    out
}

#[derive(Clone, Copy)]
struct CallCx<'a> {
    plan: &'a GrpcPlan,
    events: &'a EventCtx,
    cancel: &'a CancellationToken,
    total_deadline: Option<Instant>,
    index: u32,
}

/// The terminal status as it is being assembled from the response.
struct Terminal {
    code: Option<i32>,
    message: Option<String>,
    source: GrpcStatusSource,
}

impl Terminal {
    fn read_fields(&mut self, get: impl Fn(&str) -> Option<String>, source: GrpcStatusSource, facts: &mut SessionFacts) -> Option<i32> {
        let code = get("grpc-status").and_then(|s| s.trim().parse::<i32>().ok())?;
        self.code = Some(code);
        self.message = get("grpc-message").map(|m| percent_decode(&m));
        self.source = source;
        facts.grpc_status_details = get("grpc-status-details-bin").and_then(|d| status_details(&d));
        Some(code)
    }
}

fn header_field(h: &HeaderMap) -> impl Fn(&str) -> Option<String> + '_ {
    move |n: &str| h.get(n).and_then(|v| v.to_str().ok()).map(|s| s.to_string())
}

/// Decode one received message and add it to the transcript.
fn deliver(
    tr: &mut Transcript,
    output_desc: &MessageDescriptor,
    encoding: Option<&str>,
    compressed: bool,
    m: Bytes,
    max: usize,
) -> Result<(), TransportFailure> {
    let raw = if compressed {
        match encoding {
            Some("gzip") => {
                Bytes::from(gunzip(&m, max).map_err(|e| TransportFailure::new(Phase::Session, FailureKind::DecompressionFailed, e))?)
            }
            other => {
                return Err(TransportFailure::new(
                    Phase::Session,
                    FailureKind::HttpProtocolError,
                    format!("a compressed message arrived with grpc-encoding {other:?}, which Anvil did not negotiate"),
                ));
            }
        }
    } else {
        m
    };
    match decode_to_json(output_desc, &raw) {
        Ok(json) => tr.data_text(Direction::Received, "grpc_message", raw.len() as u64, &json),
        Err(e) => {
            tr.data(Direction::Received, "grpc_message", &raw);
            tr.note("decode_error", &format!("message could not be decoded as {}: {e}", output_desc.full_name()));
        }
    }
    Ok(())
}

/// Reflection (when the schema comes from the server), then the call.
async fn exchange(
    cx: CallCx<'_>,
    local: &Local,
    conn: &mut Conn,
    stats: Arc<ConnStats>,
    mut rec: Recorder,
    mut obs: AttemptObservation,
    commands: &mut Option<CommandRx>,
) -> SessionOutput {
    let CallCx { plan, events, cancel, total_deadline, index } = cx;
    let interactive = commands.is_some();
    let mut facts = SessionFacts::default();
    let early = |rec: Recorder, obs: AttemptObservation, f: TransportFailure, facts: SessionFacts, d: DispatchState| {
        SessionOutput::single(fail_attempt(rec, obs, f, d, events), None, ProtocolStatus::None, facts)
    };
    let written_before = stats.bytes_written();
    let read_before = stats.bytes_read();
    let mut method_desc = local.method.clone();
    let mut encoded = local.encoded.clone();

    // ---- server reflection (network schema) ----
    if matches!(plan.schema, Schema::Reflection) {
        let r_idx = rec.start(Phase::AwaitResponseHeaders);
        match reflect(conn, plan, &stats, cancel, total_deadline).await {
            Ok((pool, outcome)) => {
                rec.finish_with(r_idx, PhaseStatus::Completed, format!("server reflection via {}", outcome.service));
                facts.notes.push(format!("schema loaded by server reflection ({})", outcome.service));
                facts.grpc_reflection = Some(outcome);
                let m = match resolve_method(&pool, &plan.service, &plan.method, plan.mode) {
                    Ok(m) => m,
                    Err(f) => return early(rec, obs, f, facts, DispatchState::NotDispatched),
                };
                match encode_all(plan, &m) {
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
    let web = plan.wire.is_web();
    let text_request = plan.wire == GrpcWire::GrpcWebText;
    // What goes on the wire for one message: the length-prefixed frame, base64 in text mode.
    let wire_bytes = |b: &[u8]| if text_request { grpc_web::encode_text(&frame(b)) } else { frame(b) };
    let mut pending: VecDeque<(Bytes, String)> = encoded.unwrap_or_default().into();
    // gRPC-Web sends one complete body, so its length is known up front.
    let exact = web.then(|| pending.iter().map(|(b, _)| wire_bytes(b).len() as u64).sum::<u64>());
    obs.bytes.request_body = exact.unwrap_or_else(|| pending.iter().map(|(b, _)| 5 + b.len() as u64).sum());
    let path = format!("/{}/{}", plan.service, plan.method);
    // Auth over the framed message now that it is encoded (server reflection).
    let signed = match &plan.sign {
        Some(sign) => {
            let body = match plan.mode {
                GrpcMode::Unary | GrpcMode::ServerStreaming => pending.iter().map(|(b, _)| wire_bytes(b)).collect::<Vec<_>>().concat(),
                GrpcMode::ClientStreaming | GrpcMode::Bidirectional => vec![],
            };
            match sign(&plan.origin(&path), &Bytes::from(body)) {
                Ok(h) => Some(h),
                Err(f) => return early(rec, obs, f, facts, DispatchState::NotDispatched),
            }
        }
        None => None,
    };

    // ---- the call ----
    let (tx, rx) = mpsc::channel::<Bytes>(64);
    let mut tx = Some(tx);
    let mut headers = call_headers(plan, signed.as_deref().unwrap_or(&plan.headers), conn.is_h1());
    if let Some(ms) = plan.deadline_ms
        && let Ok(v) = HeaderValue::from_str(&grpc_timeout(ms))
    {
        headers.insert("grpc-timeout", v);
    }
    let sent_headers = header_entries(&headers);
    obs.bytes.request_headers_logical = logical_header_bytes(&sent_headers) + path.len() as u64;
    obs.bytes.request_headers_estimated = true;
    let ctl = StreamCtl::new(stats.clone());
    let mut resp_fut = match start(conn, plan, &path, headers, rx, exact, &ctl) {
        Ok(f) => Some(f),
        Err(f) => return early(rec, obs, f, facts, DispatchState::NotDispatched),
    };

    let mut tr = Transcript::new(rec.t0, plan.transcript, events.clone(), plan.redact.clone());
    let w_idx = rec.start(Phase::RequestWrite);
    let mut w_open = true;
    let mut h_idx: Option<usize> = None;
    let mut s_idx: Option<usize> = None;
    let streaming_request = matches!(plan.mode, GrpcMode::ClientStreaming | GrpcMode::Bidirectional);
    // Header deadline only when the whole request is sent at once.
    let headers_deadline = if streaming_request || interactive { None } else { deadline_from(plan.timeouts.response_headers_ms) };
    let grpc_deadline = plan.deadline_ms.map(|ms| Instant::now() + Duration::from_millis(ms));
    let mut body: Option<RespBody> = None;
    let mut rbuf = BytesMut::new();
    let mut captured = BytesMut::new();
    let mut wire = 0u64;
    let mut status: Option<u16> = None;
    let mut version = http::Version::HTTP_2;
    let mut resp_headers: Vec<HeaderEntry> = vec![];
    let mut trailers: Vec<HeaderEntry> = vec![];
    let mut trailers_received = false;
    let mut term = Terminal { code: None, message: None, source: GrpcStatusSource::Missing };
    let mut encoding: Option<String> = None;
    let mut content_type: Option<String> = None;
    let mut failure: Option<TransportFailure> = None;
    let mut completeness = BodyCompleteness::Incomplete;
    let mut half_close_wanted = !interactive;
    let mut last_progress = Instant::now();
    // Response body framing: parse gRPC frames (from base64 text), or keep a
    // non-gRPC body as evidence only.
    let mut parse_frames = true;
    let mut text_body = false;
    let mut b64 = grpc_web::Base64Stream::default();
    let mut trailer_frame = false;
    let mut web_facts = GrpcWebFacts::default();
    // A framing violation seen in an otherwise readable body.
    let mut framing: Option<TransportFailure> = None;

    enum Ev {
        Resp(Result<RespHead, TransportFailure>),
        Frame(BodyItem),
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
            fr = async { body.as_mut().expect("guarded").next().await }, if body.is_some() => Ev::Frame(fr),
            p = async { send_handle.expect("guarded").reserve_owned().await }, if can_send => Ev::Permit(p),
            c = next_cmd(commands), if interactive && tx.is_some() => Ev::Cmd(c),
            _ = sleep_until_opt(headers_deadline), if resp_fut.is_some() => Ev::HeadersTimeout,
            _ = sleep_until_opt(body_idle) => Ev::BodyIdle,
            _ = sleep_until_opt(grpc_deadline) => Ev::GrpcDeadline,
            _ = sleep_until_opt(total_deadline) => Ev::Deadline,
            _ = cancel.cancelled() => Ev::Canceled,
        };
        match ev {
            Ev::Resp(Ok(head)) => {
                resp_fut = None;
                if let Some(i) = h_idx.take() {
                    rec.finish(i, PhaseStatus::Completed);
                }
                let st = head.status;
                status = Some(st);
                version = head.version;
                obs.response_status = Some(st);
                obs.dispatch = DispatchState::Sent;
                events.emit(ExecutionEvent::ResponseHead { execution_id: events.execution_id, attempt: index, status: st });
                resp_headers = header_entries(&head.headers);
                obs.bytes.response_headers_logical = Some(logical_header_bytes(&resp_headers));
                content_type = header_field(&head.headers)("content-type");
                encoding = header_field(&head.headers)("grpc-encoding").map(|s| s.to_ascii_lowercase());
                term.read_fields(header_field(&head.headers), GrpcStatusSource::TrailersOnly, &mut facts);
                match content_type.as_deref() {
                    Some(ct) if grpc_web::is_grpc_web_text(ct) => text_body = true,
                    Some(ct) if grpc_web::is_grpc_family(ct) => text_body = false,
                    Some(ct) => {
                        parse_frames = false;
                        facts.notes.push(format!(
                            "the response content type is {ct}, not {}; the body was kept as evidence and not parsed as gRPC frames",
                            if web { "gRPC-Web" } else { "application/grpc" }
                        ));
                    }
                    None => {
                        text_body = text_request;
                        facts.notes.push(format!(
                            "the response has no content type; the body was parsed as {} gRPC{} frames",
                            if text_body { "base64 text" } else { "binary" },
                            if web { "-Web" } else { "" }
                        ));
                    }
                }
                if let Some(ct) = content_type.as_deref() {
                    if web && grpc_web::is_grpc_family(ct) && !grpc_web::is_grpc_web(ct) {
                        facts.notes.push(format!(
                            "a gRPC-Web request was answered with the native gRPC content type {ct}; native gRPC carries its status in HTTP trailers, not in a gRPC-Web trailer frame"
                        ));
                    } else if !web && grpc_web::is_grpc_web(ct) {
                        facts.notes.push(format!("a native gRPC request was answered with the gRPC-Web content type {ct}"));
                    }
                }
                if web {
                    web_facts.response_content_type = content_type.clone();
                    web_facts.text = parse_frames && text_body;
                }
                s_idx = Some(rec.start(Phase::Session));
                body = Some(head.body);
                last_progress = Instant::now();
            }
            Ev::Resp(Err(f)) => {
                resp_fut = None;
                failure = Some(f);
                break;
            }
            Ev::Frame(None) => {
                completeness = BodyCompleteness::Complete;
                if parse_frames
                    && text_body
                    && framing.is_none()
                    && let Err(e) = b64.finish()
                {
                    failure = Some(TransportFailure::new(
                        Phase::Session,
                        FailureKind::BodyIncomplete,
                        format!("the gRPC-Web text body is truncated: {e}"),
                    ));
                    completeness = BodyCompleteness::Incomplete;
                }
                break;
            }
            Ev::Frame(Some(Ok(fr))) => {
                last_progress = Instant::now();
                if fr.is_data() {
                    let d = fr.into_data().unwrap_or_default();
                    wire += d.len() as u64;
                    let room = (plan.limits.capture_bytes as usize).saturating_sub(captured.len());
                    captured.extend_from_slice(&d[..d.len().min(room)]);
                    if parse_frames && framing.is_none() {
                        let mut err = None;
                        if text_body {
                            if let Err(e) = b64.push(&d, &mut rbuf) {
                                err = Some(TransportFailure::new(
                                    Phase::Session,
                                    FailureKind::HttpProtocolError,
                                    format!("the gRPC-Web text body is not valid base64: {e}"),
                                ));
                            }
                        } else {
                            rbuf.extend_from_slice(&d);
                        }
                        while err.is_none() {
                            let next = match grpc_web::next_frame(&mut rbuf, plan.max_message_bytes, web) {
                                Ok(n) => n,
                                Err(e) => {
                                    err = Some(frame_failure(e));
                                    break;
                                }
                            };
                            match next {
                                None => break,
                                Some(extra) if trailer_frame => {
                                    let what = match &extra {
                                        WireFrame::Trailer(p) => {
                                            let entries = grpc_web::parse_trailer_block(p).unwrap_or_default();
                                            let shown = entries.iter().map(|(n, v)| format!("{n}: {v}")).collect::<Vec<_>>().join("\n");
                                            tr.control(Direction::Received, "trailer_frame", shown.as_bytes());
                                            match grpc_web::trailer_value(&entries, "grpc-status") {
                                                Some(s) => format!(
                                                    "a second trailer frame (grpc-status {s}) followed the first (grpc-status {})",
                                                    term.code.map(|c| c.to_string()).unwrap_or_else(|| "none".into())
                                                ),
                                                None => "a second trailer frame followed the first".into(),
                                            }
                                        }
                                        WireFrame::Message { .. } => "a message frame followed the trailer frame".into(),
                                    };
                                    err = Some(TransportFailure::new(
                                        Phase::Session,
                                        FailureKind::HttpProtocolError,
                                        format!("{what}; gRPC-Web allows exactly one trailer frame, at the end of the body"),
                                    ));
                                    break;
                                }
                                Some(WireFrame::Message { compressed, data }) => {
                                    if let Err(f) =
                                        deliver(&mut tr, &output_desc, encoding.as_deref(), compressed, data, plan.max_message_bytes)
                                    {
                                        err = Some(f);
                                        break;
                                    }
                                }
                                Some(WireFrame::Trailer(payload)) => match grpc_web::parse_trailer_block(&payload) {
                                    Ok(entries) => {
                                        trailer_frame = true;
                                        let shown = entries.iter().map(|(n, v)| format!("{n}: {v}")).collect::<Vec<_>>().join("\n");
                                        tr.control(Direction::Received, "trailer_frame", shown.as_bytes());
                                        let before = (term.code, term.source);
                                        let get = |n: &str| grpc_web::trailer_value(&entries, n).map(|s| s.to_string());
                                        match term.read_fields(get, GrpcStatusSource::TrailerFrame, &mut facts) {
                                            Some(code) => {
                                                if before.1 == GrpcStatusSource::TrailersOnly && before.0 != Some(code) {
                                                    facts.notes.push(format!(
                                                        "the response headers carried grpc-status {} but the trailer frame carried {code}; the trailer frame ends the call and is used",
                                                        before.0.unwrap_or_default()
                                                    ));
                                                }
                                            }
                                            None => facts.notes.push("the gRPC-Web trailer frame carried no grpc-status".into()),
                                        }
                                    }
                                    Err(e) => {
                                        err = Some(TransportFailure::new(
                                            Phase::Session,
                                            FailureKind::HttpProtocolError,
                                            format!("the gRPC-Web trailer frame is malformed: {e}"),
                                        ));
                                        break;
                                    }
                                },
                            }
                        }
                        match err {
                            Some(f) if f.kind == FailureKind::ResponseTooLargeLocal => {
                                completeness = BodyCompleteness::StoppedAtLocalLimit;
                                failure = Some(f);
                                break;
                            }
                            // A framing violation: stop parsing, but read the HTTP body to
                            // its end so its completeness is reported as observed.
                            Some(f) => framing = Some(f),
                            None => {}
                        }
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
                    if web && term.source == GrpcStatusSource::TrailerFrame {
                        if header_field(&t)("grpc-status").is_some() {
                            facts
                                .notes
                                .push("HTTP trailers also carried a grpc-status; the gRPC-Web trailer frame's status is used".into());
                        }
                    } else if let Some(code) = term.read_fields(header_field(&t), GrpcStatusSource::Trailers, &mut facts)
                        && web
                    {
                        web_facts.status_in_http_trailers = true;
                        facts.notes.push(format!(
                            "grpc-status {code} arrived in HTTP trailers, not in a gRPC-Web trailer frame; browser gRPC-Web clients cannot read HTTP trailers"
                        ));
                    }
                }
            }
            Ev::Frame(Some(Err(mut f))) => {
                f.phase = Phase::Session;
                failure = Some(f);
                break;
            }
            Ev::Permit(Ok(p)) => {
                let (b, json) = pending.pop_front().expect("non-empty");
                drop(p.send(wire_bytes(&b)));
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
                    tr.note("unsupported_command", "gRPC calls have no ping command (HTTP/2 and QUIC PINGs are connection-level)")
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
                failure = Some(TransportFailure::new(
                    Phase::Session,
                    FailureKind::Canceled,
                    format!("the call was canceled ({})", conn.reset_note()),
                ));
                completeness = BodyCompleteness::Canceled;
                break;
            }
        }
    }
    // Dropping the request sender / response body resets an unfinished
    // HTTP/2 stream; an unfinished HTTP/3 stream is reset explicitly.
    if failure.is_some() || completeness != BodyCompleteness::Complete {
        ctl.abort.cancel();
    }
    drop(tx);
    drop(resp_fut);
    drop(body);
    if let Some(f) = framing {
        facts.grpc_framing_error = Some(f.message.clone());
        if failure.is_none() {
            failure = Some(f);
        }
    } else if parse_frames && !rbuf.is_empty() && failure.is_none() {
        failure = Some(TransportFailure::new(
            Phase::Session,
            FailureKind::BodyIncomplete,
            format!("the stream ended inside a {} ({} bytes left over)", if web { "gRPC-Web frame" } else { "message" }, rbuf.len()),
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
    if let Some(code) = term.code {
        let msg = term.message.clone().unwrap_or_default();
        tr.control(Direction::Received, "status", format!("grpc-status {code} {msg}").trim().as_bytes());
    }
    if status.is_none() && obs.dispatch != DispatchState::Sent {
        obs.dispatch = if stats.bytes_written() > written_before || ctl.opened.load(Ordering::SeqCst) {
            DispatchState::MayHaveBeenSent
        } else {
            DispatchState::NotDispatched
        };
    }
    if web && status.is_some() {
        web_facts.trailer_frame = trailer_frame;
        web_facts.body_complete = completeness == BodyCompleteness::Complete && failure.is_none();
        facts.grpc_web = Some(web_facts);
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
    let ps =
        ProtocolStatus::Grpc { http_status: Some(st), grpc_status: term.code, grpc_message: term.message.map(redact), source: term.source };
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
    fn a_channel_is_keyed_on_the_header_limit_it_advertises() {
        let pool = pool_from_proto_sources(&[("t.proto".into(), PROTO.into())]).unwrap();
        let plan = |max_response_header_bytes| GrpcPlan {
            tls: None,
            host: "127.0.0.1".into(),
            port: 50051,
            authority: "127.0.0.1:50051".into(),
            path_prefix: String::new(),
            service: "t.v1.S".into(),
            method: "U".into(),
            mode: GrpcMode::Unary,
            schema: Schema::Pool(pool.clone()),
            messages: vec![],
            headers: vec![],
            sign: None,
            sign_reflection: None,
            deadline_ms: None,
            timeouts: Timeouts::default(),
            limits: Limits { max_response_header_bytes, ..Limits::default() },
            dns: DnsConfig::default(),
            proxy: None,
            display_url: String::new(),
            max_message_bytes: 1024,
            transcript: TranscriptLimits::default(),
            redact: None,
            wire: GrpcWire::Grpc,
            version: HttpVersionPolicy::Http3Only,
            proxy_header: None,
            channels: None,
        };
        let key = |limit| channel_key("w", &plan(limit), Leg::Quic);
        assert_ne!(key(16 * 1024), key(64 * 1024), "a larger limit is its own channel");
        // Keyed on the limit HTTP/3 advertises: raw values it clamps alike share.
        assert_eq!(key(0), key(1));
        assert_eq!(key(u64::MAX), key(1 << 62));
    }

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
        assert!(matches!(next_message(&mut big, 16), Err(FrameError::TooLarge(_))));
        // A native stream has no trailer frame: 0x80 is an invalid flag, not a size problem.
        let mut t = BytesMut::from(&[0x80u8, 0, 0, 0, 0][..]);
        assert!(matches!(next_message(&mut t, 16), Err(FrameError::Invalid(_))));
        assert_eq!(grpc_timeout(1500), "1500m");
        assert_eq!(grpc_timeout(200_000_000), "200000S");
        assert_eq!(percent_decode("a%20b%zz"), "a b%zz");
    }

    #[test]
    fn reflection_response_is_bounded_and_single_message() {
        let response = frame(b"response");
        let mut buf = BytesMut::new();
        let mut budget = ReflectionBudget { used_bytes: 0, max_bytes: response.len() + 8 };
        let mut message_count = 0;
        let messages = append_reflection_data(&mut buf, &response, &mut budget, &mut message_count, 64).unwrap();
        assert_eq!(messages, vec![Bytes::from_static(b"response")]);
        assert_eq!(budget.used_bytes, response.len() + 8);

        let mut buf = BytesMut::new();
        let mut budget = ReflectionBudget { used_bytes: 0, max_bytes: 8 };
        let mut message_count = 0;
        let partial = append_reflection_data(&mut buf, &response[..5], &mut budget, &mut message_count, 64).unwrap();
        assert!(partial.is_empty());
        let too_large = append_reflection_data(&mut buf, &response[5..], &mut budget, &mut message_count, 64).unwrap_err();
        assert_eq!(too_large.kind, FailureKind::ResponseTooLargeLocal);

        let mut buf = BytesMut::new();
        let mut budget = ReflectionBudget { used_bytes: 0, max_bytes: response.len() * 2 + 16 };
        let mut message_count = 0;
        let twice = [response.as_ref(), response.as_ref()].concat();
        let extra = append_reflection_data(&mut buf, &twice, &mut budget, &mut message_count, 64).unwrap_err();
        assert_eq!(extra.kind, FailureKind::HttpProtocolError);
    }

    #[test]
    fn reflection_byte_budget_is_cumulative_across_requests() {
        let response = frame(b"response");
        let mut budget = ReflectionBudget { used_bytes: 0, max_bytes: 30 };
        let mut first_buf = BytesMut::new();
        let mut first_message_count = 0;
        append_reflection_data(&mut first_buf, &response, &mut budget, &mut first_message_count, 64).unwrap();
        assert_eq!(budget.used_bytes, 21);

        let mut second_buf = BytesMut::new();
        let mut second_message_count = 0;
        let failure = append_reflection_data(&mut second_buf, &response, &mut budget, &mut second_message_count, 64).unwrap_err();
        assert_eq!(failure.kind, FailureKind::ResponseTooLargeLocal);
    }

    #[tokio::test]
    async fn reflection_deadline_stops_a_stream_that_keeps_trickling_data() {
        let (tx, rx) = mpsc::channel(1);
        tokio::spawn(async move {
            loop {
                if tx.send(Ok(Frame::data(Bytes::from_static(b"x")))).await.is_err() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        });
        let mut body = RespBody::H3(rx);
        let deadline = Instant::now() + Duration::from_millis(40);
        let cancel = CancellationToken::new();
        let mut items = 0;
        loop {
            match next_reflection_body_item(&mut body, None, Some(deadline), &cancel).await {
                ReflectionBodyEvent::Item(Some(Ok(_))) => items += 1,
                ReflectionBodyEvent::Deadline => break,
                ReflectionBodyEvent::Item(None) => panic!("trickling stream ended before its deadline"),
                ReflectionBodyEvent::Item(Some(Err(error))) => panic!("trickling stream failed: {error:?}"),
                ReflectionBodyEvent::Idle => panic!("unexpected idle timeout"),
                ReflectionBodyEvent::Canceled => panic!("unexpected cancellation"),
            }
        }
        assert!(items > 0, "the test stream should deliver data before the deadline");
    }

    #[test]
    fn interactive_reflection_uses_the_absolute_cap() {
        let now = Instant::now();
        let (deadline, deadline_ms) = reflection_deadline(None, now);
        assert_eq!(deadline_ms, REFLECTION_TIMEOUT_MS);
        assert_eq!(deadline, now + Duration::from_millis(REFLECTION_TIMEOUT_MS));
    }

    #[test]
    fn percent_decode_handles_unicode_and_malformed_escapes() {
        assert_eq!(percent_decode("%E2%82%AC"), "€");
        assert_eq!(percent_decode("%€"), "%€");
        assert_eq!(percent_decode("%2G"), "%2G");
        assert_eq!(percent_decode("a%20b"), "a b");
    }

    #[test]
    fn grpc_web_binary_and_text_trailers_percent_decode_messages() {
        let payload = "grpc-status: 13\r\ngrpc-message: %E2%82%AC%zz%€\r\n".as_bytes();
        let mut trailer = BytesMut::with_capacity(5 + payload.len());
        trailer.extend_from_slice(&[0x80]);
        trailer.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        trailer.extend_from_slice(payload);
        for text in [false, true] {
            let mut body = BytesMut::new();
            if text {
                let encoded = grpc_web::encode_text(&trailer);
                let mut decoder = grpc_web::Base64Stream::default();
                decoder.push(&encoded, &mut body).unwrap();
                decoder.finish().unwrap();
            } else {
                body.extend_from_slice(&trailer);
            }
            let WireFrame::Trailer(payload) = grpc_web::next_frame(&mut body, 1024, true).unwrap().unwrap() else {
                panic!("expected a gRPC-Web trailer frame");
            };
            let entries = grpc_web::parse_trailer_block(&payload).unwrap();
            let message = grpc_web::trailer_value(&entries, "grpc-message").unwrap();
            assert_eq!(percent_decode(message), "€%zz%€");
        }
    }

    #[test]
    fn unsupported_combinations_are_refused_before_traffic() {
        use HttpVersionPolicy as V;
        let web = GrpcWire::GrpcWeb;
        let none = |w, m, r, v, tls, proxy| unsupported_combination(w, m, r, v, tls, proxy).is_none();
        let field = |w, m, r, v, tls, proxy| unsupported_combination(w, m, r, v, tls, proxy).map(|(_, f)| f);
        // gRPC-Web: unary and server streaming over H1/H2/H3; never client/bidi or reflection.
        for v in [V::Auto, V::Http1Only, V::Http2Only, V::Http3Only, V::Http3WithFallback] {
            assert!(none(web, GrpcMode::Unary, false, v, true, false), "{v:?}");
            assert!(none(GrpcWire::GrpcWebText, GrpcMode::ServerStreaming, false, v, true, false), "{v:?}");
        }
        assert_eq!(field(web, GrpcMode::ClientStreaming, false, V::Auto, true, false), Some("grpc.wire"));
        assert_eq!(field(web, GrpcMode::Bidirectional, false, V::Auto, false, false), Some("grpc.wire"));
        let (msg, _) = unsupported_combination(web, GrpcMode::Bidirectional, false, V::Auto, true, false).unwrap();
        assert!(msg.contains("unary and server-streaming") && msg.contains("half-close"), "{msg}");
        assert_eq!(field(web, GrpcMode::Unary, true, V::Auto, true, false), Some("grpc.schema"));
        assert_eq!(field(web, GrpcMode::Unary, false, V::H2c, true, false), Some("settings.http_version"));
        assert_eq!(field(web, GrpcMode::Unary, false, V::Http2Only, false, false), Some("settings.http_version"));
        assert!(none(web, GrpcMode::Unary, false, V::H2c, false, false));
        // Native gRPC: never HTTP/1.1; HTTP/3 needs TLS and no proxy.
        let g = GrpcWire::Grpc;
        assert_eq!(field(g, GrpcMode::Unary, false, V::Http1Only, true, false), Some("settings.http_version"));
        assert!(none(g, GrpcMode::Bidirectional, true, V::Http3Only, true, false));
        assert_eq!(field(g, GrpcMode::Unary, false, V::Http3Only, false, false), Some("settings.http_version"));
        assert_eq!(field(g, GrpcMode::Unary, false, V::Http3WithFallback, true, true), Some("settings.proxy"));
    }
}
