//! gRPC fixture: `anvil.lab.v1.Echo` (all four call modes) and
//! `grpc.reflection.v1.ServerReflection`, implemented with raw gRPC framing
//! over the fixture's HTTP/2 server.

use crate::http::FxBody;
use crate::log::{GroundTruth, GroundTruthLog};
use bytes::{Buf, Bytes, BytesMut};
use futures::SinkExt;
use http::{HeaderMap, HeaderValue, Request, Response};
use http_body_util::{BodyExt, StreamBody};
use hyper::body::{Frame, Incoming};
use prost::Message;
use std::sync::OnceLock;

pub const ECHO_PROTO: &str = include_str!("../../../lab/proto/echo.proto");

/// Fixture-only `fail_with` sentinel for `Unary`: reply once, then reset the
/// stream before any terminal status (PROTO-015 ground truth). Not a gRPC code.
pub const ABORT_WITHOUT_STATUS: i32 = -1;

#[derive(Clone, PartialEq, prost::Message)]
pub struct EchoRequest {
    #[prost(string, tag = "1")]
    pub message: String,
    #[prost(int32, tag = "2")]
    pub count: i32,
    #[prost(int32, tag = "3")]
    pub fail_with: i32,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct EchoReply {
    #[prost(string, tag = "1")]
    pub message: String,
    #[prost(int32, tag = "2")]
    pub index: i32,
}

// --- reflection v1 (subset) ---
#[derive(Clone, PartialEq, prost::Message)]
struct ReflRequest {
    #[prost(string, tag = "1")]
    host: String,
    #[prost(string, optional, tag = "3")]
    file_by_filename: Option<String>,
    #[prost(string, optional, tag = "4")]
    file_containing_symbol: Option<String>,
    #[prost(string, optional, tag = "7")]
    list_services: Option<String>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct FileDescriptorResponse {
    #[prost(bytes = "vec", repeated, tag = "1")]
    file_descriptor_proto: Vec<Vec<u8>>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct ServiceResponse {
    #[prost(string, tag = "1")]
    name: String,
}

#[derive(Clone, PartialEq, prost::Message)]
struct ListServiceResponse {
    #[prost(message, repeated, tag = "1")]
    service: Vec<ServiceResponse>,
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
    #[prost(string, tag = "1")]
    valid_host: String,
    #[prost(message, optional, tag = "4")]
    file_descriptor_response: Option<FileDescriptorResponse>,
    #[prost(message, optional, tag = "6")]
    list_services_response: Option<ListServiceResponse>,
    #[prost(message, optional, tag = "7")]
    error_response: Option<ErrorResponse>,
}

/// Serialized FileDescriptorProto for echo.proto (compiled in-process).
pub fn echo_file_descriptor() -> &'static Vec<u8> {
    static FD: OnceLock<Vec<u8>> = OnceLock::new();
    FD.get_or_init(|| {
        let set = echo_descriptor_set();
        set.file.into_iter().find(|f| f.name() == "echo.proto").map(|f| f.encode_to_vec()).unwrap_or_default()
    })
}

pub fn echo_descriptor_set() -> prost_types_compat::FileDescriptorSet {
    let dir = std::env::temp_dir().join(format!("anvil-fixture-proto-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("echo.proto");
    let _ = std::fs::write(&path, ECHO_PROTO);
    protox::compile([path.as_path()], [dir.as_path()]).expect("echo.proto compiles")
}

pub mod prost_types_compat {
    pub use prost_reflect::prost_types::FileDescriptorSet;
}

fn frame(msg: &impl Message) -> Bytes {
    let body = msg.encode_to_vec();
    let mut b = BytesMut::with_capacity(5 + body.len());
    b.extend_from_slice(&[0]);
    b.extend_from_slice(&(body.len() as u32).to_be_bytes());
    b.extend_from_slice(&body);
    b.freeze()
}

fn trailers(status: i32, message: &str) -> HeaderMap {
    let mut t = HeaderMap::new();
    t.insert("grpc-status", HeaderValue::from_str(&status.to_string()).unwrap());
    if !message.is_empty() {
        t.insert("grpc-message", HeaderValue::from_str(message).unwrap_or(HeaderValue::from_static("error")));
    }
    t
}

type Tx = futures::channel::mpsc::Sender<Result<Frame<Bytes>, std::io::Error>>;

/// Incrementally read length-prefixed gRPC messages from a request body.
struct FrameReader {
    body: Incoming,
    buf: BytesMut,
}

impl FrameReader {
    async fn next(&mut self) -> Option<Result<Bytes, String>> {
        loop {
            if self.buf.len() >= 5 {
                let len = u32::from_be_bytes([self.buf[1], self.buf[2], self.buf[3], self.buf[4]]) as usize;
                if len > 4 * 1024 * 1024 {
                    return Some(Err("message too large".into()));
                }
                if self.buf.len() >= 5 + len {
                    self.buf.advance(5);
                    return Some(Ok(self.buf.split_to(len).freeze()));
                }
            }
            match self.body.frame().await {
                Some(Ok(f)) => {
                    if let Ok(d) = f.into_data() {
                        self.buf.extend_from_slice(&d);
                    }
                }
                Some(Err(e)) => return Some(Err(e.to_string())),
                None => {
                    return if self.buf.is_empty() { None } else { Some(Err("truncated gRPC frame".into())) };
                }
            }
        }
    }
}

pub async fn handle(req: Request<Incoming>, log: GroundTruthLog) -> Response<FxBody> {
    let path = req.uri().path().to_string();
    let deny_reflection = req.headers().contains_key("x-fixture-deny-reflection");
    let (tx, rx) = futures::channel::mpsc::channel::<Result<Frame<Bytes>, std::io::Error>>(32);
    let body: FxBody = StreamBody::new(rx).boxed();
    let reader = FrameReader { body: req.into_body(), buf: BytesMut::new() };
    tokio::spawn(run(path, reader, tx, log, deny_reflection));
    Response::builder().status(200).header("content-type", "application/grpc").body(body).unwrap()
}

async fn run(path: String, mut reader: FrameReader, mut tx: Tx, log: GroundTruthLog, deny_reflection: bool) {
    let send = |m: Bytes| Ok(Frame::data(m));
    match path.as_str() {
        "/anvil.lab.v1.Echo/Unary" => {
            let Some(Ok(m)) = reader.next().await else {
                let _ = tx.send(Ok(Frame::trailers(trailers(3, "missing request message")))).await;
                return;
            };
            log.push(GroundTruth::MessageReceived { bytes: m.len() as u64 });
            let req = EchoRequest::decode(m).unwrap_or_default();
            if req.fail_with == ABORT_WITHOUT_STATUS {
                // Lab-only fault: reply, then reset the stream before any terminal status.
                log.push(GroundTruth::FaultApplied { fault: "grpc_abort_before_status".into() });
                let _ = tx.send(send(frame(&EchoReply { message: req.message, index: 0 }))).await;
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                let _ = tx.send(Err(std::io::Error::other("fixture abort before grpc-status"))).await;
                return;
            }
            if req.fail_with != 0 {
                let _ = tx.send(Ok(Frame::trailers(trailers(req.fail_with, "fixture requested failure")))).await;
                return;
            }
            let _ = tx.send(send(frame(&EchoReply { message: req.message, index: 0 }))).await;
            let _ = tx.send(Ok(Frame::trailers(trailers(0, "")))).await;
        }
        "/anvil.lab.v1.Echo/ServerStream" => {
            let Some(Ok(m)) = reader.next().await else {
                return;
            };
            let req = EchoRequest::decode(m).unwrap_or_default();
            for i in 0..req.count.clamp(0, 10_000) {
                if tx.send(send(frame(&EchoReply { message: req.message.clone(), index: i }))).await.is_err() {
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
            let _ = tx
                .send(Ok(Frame::trailers(trailers(req.fail_with, if req.fail_with != 0 { "fixture requested failure" } else { "" }))))
                .await;
        }
        "/anvil.lab.v1.Echo/ClientStream" => {
            let mut n = 0;
            let mut last = String::new();
            let mut fail = 0;
            while let Some(Ok(m)) = reader.next().await {
                let r = EchoRequest::decode(m).unwrap_or_default();
                last = r.message;
                fail = r.fail_with;
                n += 1;
            }
            if fail != 0 {
                let _ = tx.send(Ok(Frame::trailers(trailers(fail, "fixture requested failure")))).await;
                return;
            }
            let _ = tx.send(send(frame(&EchoReply { message: format!("{n} messages; last={last}"), index: n }))).await;
            let _ = tx.send(Ok(Frame::trailers(trailers(0, "")))).await;
        }
        "/anvil.lab.v1.Echo/Bidi" => {
            let mut i = 0;
            while let Some(Ok(m)) = reader.next().await {
                let r = EchoRequest::decode(m).unwrap_or_default();
                if tx.send(send(frame(&EchoReply { message: r.message, index: i }))).await.is_err() {
                    return;
                }
                i += 1;
            }
            let _ = tx.send(Ok(Frame::trailers(trailers(0, "")))).await;
        }
        "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo" | "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo" => {
            if deny_reflection {
                let _ = tx.send(Ok(Frame::trailers(trailers(7, "reflection is disabled for this caller")))).await;
                return;
            }
            while let Some(Ok(m)) = reader.next().await {
                let r = ReflRequest::decode(m).unwrap_or_default();
                let mut resp = ReflResponse { valid_host: r.host.clone(), ..Default::default() };
                if r.list_services.is_some() {
                    resp.list_services_response = Some(ListServiceResponse {
                        service: vec![
                            ServiceResponse { name: "anvil.lab.v1.Echo".into() },
                            ServiceResponse { name: "grpc.reflection.v1.ServerReflection".into() },
                        ],
                    });
                } else if r.file_containing_symbol.as_deref().map(|s| s.starts_with("anvil.lab.v1")).unwrap_or(false)
                    || r.file_by_filename.as_deref() == Some("echo.proto")
                {
                    resp.file_descriptor_response =
                        Some(FileDescriptorResponse { file_descriptor_proto: vec![echo_file_descriptor().clone()] });
                } else {
                    resp.error_response = Some(ErrorResponse { error_code: 5, error_message: "not found".into() });
                }
                if tx.send(send(frame(&resp))).await.is_err() {
                    return;
                }
            }
            let _ = tx.send(Ok(Frame::trailers(trailers(0, "")))).await;
        }
        _ => {
            let _ = tx.send(Ok(Frame::trailers(trailers(12, "unknown method")))).await;
        }
    }
}
