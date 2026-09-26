//! gRPC-Web echo: `anvil.lab.v1.Echo` Unary and ServerStream in binary
//! (`application/grpc-web+proto`) and text (`application/grpc-web-text`)
//! mode, over the HTTP fixture (HTTP/1.1, HTTP/2; [`handle`]) and the HTTP/3
//! fixture ([`handle_h3`]).
//!
//! The request body is read whole (bounded), base64-decoded in text mode and
//! parsed as frames (a request trailer frame, if any, is ignored). The
//! response mode follows the request's. Text responses base64-encode every
//! frame on its own, so `=` padding appears in the middle of the body, as
//! streaming servers produce it. The status is the request's `fail_with`
//! (0 = OK); [`crate::grpc::ABORT_WITHOUT_STATUS`] replies once and then
//! aborts the body before any status.
//!
//! Response shapes, chosen by the `x-fixture-grpc-web` request header:
//! * absent — messages, then a trailer frame (flag `0x80`) with the status;
//! * `trailers-only` — no body; `grpc-status`/`grpc-message` in the headers;
//! * `no-trailer-frame` — messages, then a clean end with no status anywhere;
//! * `extra-trailer-frame` — messages, the trailer frame, then a second
//!   trailer frame with `grpc-status: 2` (invalid framing);
//! * `http-trailers` — messages, then the status in HTTP trailers (only
//!   HTTP/2 and HTTP/3 can carry them to a client that did not send `TE`).

use crate::grpc::{ABORT_WITHOUT_STATUS, EchoReply, EchoRequest, H3Stream, frame};
use crate::http::FxBody;
use crate::log::{GroundTruth, GroundTruthLog};
use base64::Engine;
use bytes::{Buf, Bytes, BytesMut};
use futures::SinkExt;
use http::{HeaderMap, HeaderValue, Request, Response};
use http_body_util::{BodyExt, Limited, StreamBody};
use hyper::body::{Frame, Incoming};
use prost::Message;
use std::time::Duration;

const MAX_REQUEST: usize = 4 * 1024 * 1024;

fn content_type(headers: &HeaderMap) -> String {
    headers.get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("").to_ascii_lowercase()
}

/// `application/grpc-web*` request (binary or text).
pub fn is_grpc_web(headers: &HeaderMap) -> bool {
    content_type(headers).starts_with("application/grpc-web")
}

fn header_list(headers: &HeaderMap) -> Vec<(String, String)> {
    headers.iter().map(|(n, v)| (n.as_str().to_string(), String::from_utf8_lossy(v.as_bytes()).into_owned())).collect()
}

/// A planned response.
struct Reply {
    content_type: &'static str,
    /// Status in the response headers (trailers-only answer).
    header_status: Option<(i32, String)>,
    /// Body chunks, already encoded for the wire (base64 in text mode).
    chunks: Vec<Bytes>,
    /// Status in HTTP trailers.
    trailers: Option<HeaderMap>,
    /// Abort the body after the chunks (no status anywhere).
    abort: bool,
}

/// Pause between response chunks, so server streaming really streams.
const PACE: Duration = Duration::from_millis(5);

fn trailer_frame(status: i32, message: &str) -> Bytes {
    let mut block = format!("grpc-status: {status}\r\n");
    if !message.is_empty() {
        block.push_str(&format!("grpc-message: {message}\r\n"));
    }
    let mut b = BytesMut::with_capacity(5 + block.len());
    b.extend_from_slice(&[0x80]);
    b.extend_from_slice(&(block.len() as u32).to_be_bytes());
    b.extend_from_slice(block.as_bytes());
    b.freeze()
}

/// Message frames of a (decoded) request body; a trailing `0x80` frame is skipped.
fn request_messages(mut body: &[u8]) -> Result<Vec<Bytes>, String> {
    let mut out = Vec::new();
    while !body.is_empty() {
        if body.len() < 5 {
            return Err("truncated gRPC-Web frame header".into());
        }
        let flag = body[0];
        let len = u32::from_be_bytes([body[1], body[2], body[3], body[4]]) as usize;
        if body.len() < 5 + len {
            return Err("truncated gRPC-Web frame".into());
        }
        match flag {
            0x00 => out.push(Bytes::copy_from_slice(&body[5..5 + len])),
            0x80 => {}
            other => return Err(format!("unsupported request frame flag 0x{other:02x}")),
        }
        body.advance(5 + len);
    }
    Ok(out)
}

fn plan(path: &str, headers: &HeaderMap, body: &[u8], log: &GroundTruthLog) -> Reply {
    let text = content_type(headers).starts_with("application/grpc-web-text");
    let shape = headers.get("x-fixture-grpc-web").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    let decoded = if text {
        let clean: Vec<u8> = body.iter().copied().filter(|b| !b.is_ascii_whitespace()).collect();
        base64::engine::general_purpose::STANDARD.decode(clean).map_err(|e| format!("request body is not base64: {e}"))
    } else {
        Ok(body.to_vec())
    };
    let encode = |b: Bytes| if text { Bytes::from(base64::engine::general_purpose::STANDARD.encode(&b)) } else { b };
    let parsed = decoded.and_then(|d| request_messages(&d));
    let (replies, status, message, abort): (Vec<Bytes>, i32, String, bool) = match parsed {
        Err(e) => (vec![], 3, e, false),
        Ok(msgs) => {
            if let Some(m) = msgs.first() {
                log.push(GroundTruth::MessageReceived { bytes: m.len() as u64 });
            }
            let req = msgs.first().map(|m| EchoRequest::decode(m.clone()).unwrap_or_default()).unwrap_or_default();
            let failure = |code: i32| if code != 0 { "fixture requested failure".to_string() } else { String::new() };
            match path {
                "/anvil.lab.v1.Echo/Unary" if req.fail_with == ABORT_WITHOUT_STATUS => {
                    (vec![frame(&EchoReply { message: req.message, index: 0 })], 0, String::new(), true)
                }
                "/anvil.lab.v1.Echo/Unary" if req.fail_with != 0 => (vec![], req.fail_with, failure(req.fail_with), false),
                "/anvil.lab.v1.Echo/Unary" => (vec![frame(&EchoReply { message: req.message, index: 0 })], 0, String::new(), false),
                "/anvil.lab.v1.Echo/ServerStream" => (
                    (0..req.count.clamp(0, 10_000)).map(|i| frame(&EchoReply { message: req.message.clone(), index: i })).collect(),
                    req.fail_with,
                    failure(req.fail_with),
                    false,
                ),
                _ => (vec![], 12, "method not served over gRPC-Web by this fixture".into(), false),
            }
        }
    };
    let mut r = Reply {
        content_type: if text { "application/grpc-web-text" } else { "application/grpc-web+proto" },
        header_status: None,
        chunks: vec![],
        trailers: None,
        abort,
    };
    if abort {
        log.push(GroundTruth::FaultApplied { fault: "grpc_web_abort_before_status".into() });
        r.chunks = replies.into_iter().map(encode).collect();
        return r;
    }
    match shape.as_str() {
        "trailers-only" => {
            log.push(GroundTruth::FaultApplied { fault: "grpc_web_trailers_only".into() });
            r.header_status = Some((status, message));
        }
        "no-trailer-frame" => {
            log.push(GroundTruth::FaultApplied { fault: "grpc_web_no_trailer_frame".into() });
            r.chunks = replies.into_iter().map(encode).collect();
        }
        "extra-trailer-frame" => {
            // Models a hop that appends its own synthesized status after the
            // server's trailer frame (observed live on a pass-through route).
            log.push(GroundTruth::FaultApplied { fault: "grpc_web_extra_trailer_frame".into() });
            r.chunks = replies.into_iter().chain([trailer_frame(status, &message), trailer_frame(2, "")]).map(encode).collect();
        }
        "http-trailers" => {
            log.push(GroundTruth::FaultApplied { fault: "grpc_web_http_trailers".into() });
            r.chunks = replies.into_iter().map(encode).collect();
            let mut t = HeaderMap::new();
            t.insert("grpc-status", HeaderValue::from(status));
            if let Ok(v) = HeaderValue::from_str(&message)
                && !message.is_empty()
            {
                t.insert("grpc-message", v);
            }
            r.trailers = Some(t);
        }
        _ => {
            r.chunks = replies.into_iter().chain(std::iter::once(trailer_frame(status, &message))).map(encode).collect();
        }
    }
    r
}

/// gRPC-Web over the HTTP fixture (HTTP/1.1 or HTTP/2).
pub async fn handle(req: Request<Incoming>, log: GroundTruthLog) -> Response<FxBody> {
    let path = req.uri().path().to_string();
    let method = req.method().to_string();
    let headers = req.headers().clone();
    let body = Limited::new(req.into_body(), MAX_REQUEST).collect().await.map(|b| b.to_bytes()).unwrap_or_default();
    log.push(GroundTruth::RequestReceived { method, path: path.clone(), body_bytes: body.len() as u64, headers: header_list(&headers) });
    let reply = plan(&path, &headers, &body, &log);
    let mut b = Response::builder().status(200).header("content-type", reply.content_type);
    if let Some((code, msg)) = &reply.header_status {
        b = b.header("grpc-status", code.to_string());
        if !msg.is_empty() {
            b = b.header("grpc-message", msg.as_str());
        }
    }
    log.push(GroundTruth::ResponseStarted { status: 200 });
    let (mut tx, rx) = futures::channel::mpsc::channel::<Result<Frame<Bytes>, std::io::Error>>(16);
    tokio::spawn(async move {
        for (i, c) in reply.chunks.into_iter().enumerate() {
            if i > 0 {
                tokio::time::sleep(PACE).await;
            }
            if tx.send(Ok(Frame::data(c))).await.is_err() {
                return;
            }
        }
        if reply.abort {
            tokio::time::sleep(Duration::from_millis(20)).await;
            let _ = tx.send(Err(std::io::Error::other("fixture abort before the gRPC-Web status"))).await;
            return;
        }
        if let Some(t) = reply.trailers {
            let _ = tx.send(Ok(Frame::trailers(t))).await;
        }
    });
    b.body(StreamBody::new(rx).boxed()).unwrap()
}

/// gRPC-Web over the HTTP/3 fixture.
pub async fn handle_h3(req: http::Request<()>, mut stream: H3Stream, log: GroundTruthLog) {
    let path = req.uri().path().to_string();
    let mut body = BytesMut::new();
    while let Ok(Some(mut c)) = stream.recv_data().await {
        let n = c.remaining();
        body.extend_from_slice(&c.copy_to_bytes(n));
        if body.len() > MAX_REQUEST {
            break;
        }
    }
    log.push(GroundTruth::RequestReceived {
        method: req.method().to_string(),
        path: path.clone(),
        body_bytes: body.len() as u64,
        headers: header_list(req.headers()),
    });
    let reply = plan(&path, req.headers(), &body, &log);
    let mut b = http::Response::builder().status(200).header("content-type", reply.content_type).header("x-fixture-protocol", "h3");
    if let Some((code, msg)) = &reply.header_status {
        b = b.header("grpc-status", code.to_string());
        if !msg.is_empty() {
            b = b.header("grpc-message", msg.as_str());
        }
    }
    log.push(GroundTruth::ResponseStarted { status: 200 });
    if stream.send_response(b.body(()).expect("static response")).await.is_err() {
        return;
    }
    for (i, c) in reply.chunks.into_iter().enumerate() {
        if i > 0 {
            tokio::time::sleep(PACE).await;
        }
        if stream.send_data(c).await.is_err() {
            return;
        }
    }
    if reply.abort {
        tokio::time::sleep(Duration::from_millis(20)).await;
        stream.stop_stream(h3::error::Code::H3_INTERNAL_ERROR);
        return;
    }
    if let Some(t) = reply.trailers {
        let _ = stream.send_trailers(t).await;
    }
    let _ = stream.finish().await;
}
