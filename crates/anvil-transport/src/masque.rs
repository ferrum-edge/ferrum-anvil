//! UDP through an HTTP/3 MASQUE proxy: RFC 9298 CONNECT-UDP with RFC 9297
//! HTTP Datagrams.
//!
//! * **Bootstrap.** A fresh QUIC connection to the proxy (DNS and the QUIC
//!   handshake are measured; there is no TCP phase) on which Anvil advertises
//!   `SETTINGS_H3_DATAGRAM`. Nothing is sent on a request stream until the
//!   proxy's SETTINGS arrive and enable extended CONNECT
//!   (`SETTINGS_ENABLE_CONNECT_PROTOCOL`). Then Anvil sends an extended
//!   CONNECT with `:protocol = connect-udp`, `:scheme = https`, the expanded
//!   URI Template as `:path`, and `capsule-protocol: ?1`.
//! * **Answer.** A 2xx opens the tunnel. Any other status is the proxy's
//!   refusal: the status, headers and (bounded) body are kept as evidence and
//!   no datagram is sent. A refusal says nothing about the UDP target.
//! * **Datagrams.** UDP payloads are HTTP Datagrams with Context ID 0 (RFC
//!   9298 §5). They travel in QUIC DATAGRAM frames (quarter stream ID,
//!   context ID, payload) when the proxy's SETTINGS enable HTTP/3 datagrams
//!   and QUIC negotiated DATAGRAM frames; otherwise as DATAGRAM capsules on
//!   the CONNECT stream (RFC 9297 §3.5) — the interoperability profile of
//!   Ferrum Edge, which never negotiates `SETTINGS_H3_DATAGRAM`. Both
//!   encodings are accepted on receive. The request can require QUIC
//!   datagrams, and then fails typed before traffic when they are missing.
//! * **Evidence.** The same per-datagram transcript, counts and response
//!   window as the direct UDP adapter, plus the tunnel facts (proxy status,
//!   SETTINGS, the encoding and per-encoding counts). Delivery to the target
//!   is never inferred: silence is only "no response observed".
//! * **End.** Anvil ends the tunnel when the window elapses, on Close/cancel
//!   or at the total deadline (FIN on the CONNECT stream, then the QUIC
//!   connection closes with `H3_NO_ERROR`). A proxy FIN is a proxy close; a
//!   stream reset, a lost QUIC connection or a FIN inside a capsule is an
//!   abnormal end (incomplete, never success).
//! * DTLS inside the tunnel is not implemented; the engine refuses it before
//!   traffic.

use crate::dns::DnsConfig;
use crate::h3::{H3_NO_ERROR, H3ClientOptions, QuicConnected};
use crate::http::{AttemptOutput, sleep_until_opt};
use crate::recorder::{EventCtx, Recorder};
use crate::session::*;
use crate::tls::PreparedTls;
use anvil_domain::events::{ExecutionEvent, SessionCommand};
use anvil_domain::execution::*;
use anvil_domain::outcome::{ClosedBy, MasqueEncoding, MasqueTunnel, ProtocolStatus};
use anvil_domain::request::MasqueDatagramMode;
use anvil_domain::settings::{Limits, Timeouts};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use http::{HeaderName, HeaderValue, Method, Request};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

/// RFC 9297 §3.5 DATAGRAM capsule type.
pub const CAPSULE_DATAGRAM: u64 = 0x00;
/// RFC 9298 §5: the largest UDP payload an HTTP Datagram with Context ID 0 may carry.
pub const MAX_UDP_PAYLOAD: usize = 65_527;
/// Longest capsule header (type varint + length varint).
const MAX_CAPSULE_HEADER: usize = 16;
/// A Context ID varint is at most 8 bytes.
const CONTEXT_ID_SLACK: usize = 8;

/// A fully prepared CONNECT-UDP exchange (auth already applied to `headers`).
#[derive(Clone)]
pub struct MasquePlan {
    pub proxy_host: String,
    pub proxy_port: u16,
    /// `:authority` of the proxy.
    pub proxy_authority: String,
    /// The expanded URI Template (origin-form path and query).
    pub request_target: String,
    /// `host:port` of the UDP target (evidence only; it is in the path).
    pub target: String,
    pub headers: Vec<(HeaderName, HeaderValue)>,
    pub mode: MasqueDatagramMode,
    pub tls: Arc<PreparedTls>,
    pub dns: DnsConfig,
    pub timeouts: Timeouts,
    pub limits: Limits,
    pub datagrams: Vec<Bytes>,
    /// How long to wait for responses after the last datagram is sent.
    pub response_window_ms: u64,
    /// Stop receiving after this many datagrams.
    pub max_datagrams: u32,
    /// Redacted proxy request URL for evidence.
    pub display_url: String,
    pub transcript: TranscriptLimits,
    pub redact: Option<RedactFn>,
}

// ------------------------------------------------------------------ codec ---

/// Append `v` as a QUIC variable-length integer (RFC 9000 §16).
pub fn put_varint(out: &mut BytesMut, v: u64) {
    if v < 1 << 6 {
        out.put_u8(v as u8);
    } else if v < 1 << 14 {
        out.put_u16(0x4000 | v as u16);
    } else if v < 1 << 30 {
        out.put_u32(0x8000_0000 | v as u32);
    } else {
        out.put_u64(0xc000_0000_0000_0000 | v);
    }
}

/// Read a QUIC varint at `pos`, advancing it. `None` means more bytes are
/// needed (a varint has no malformed encoding, only a truncated one).
pub fn read_varint(buf: &[u8], pos: &mut usize) -> Option<u64> {
    let first = *buf.get(*pos)?;
    let len = 1usize << (first >> 6);
    if buf.len() - *pos < len {
        return None;
    }
    let mut v = u64::from(first & 0x3f);
    for i in 1..len {
        v = (v << 8) | u64::from(buf[*pos + i]);
    }
    *pos += len;
    Some(v)
}

/// A UDP payload as an RFC 9297 DATAGRAM capsule with Context ID 0.
pub fn encode_capsule(payload: &[u8]) -> Bytes {
    let mut out = BytesMut::with_capacity(payload.len() + 10);
    put_varint(&mut out, CAPSULE_DATAGRAM);
    put_varint(&mut out, 1 + payload.len() as u64);
    put_varint(&mut out, 0);
    out.extend_from_slice(payload);
    out.freeze()
}

/// A UDP payload as a QUIC DATAGRAM frame payload: quarter stream ID,
/// Context ID 0, then the payload (RFC 9297 §2.1, RFC 9298 §5).
pub fn encode_quic_datagram(quarter_stream_id: u64, payload: &[u8]) -> Bytes {
    let mut out = BytesMut::with_capacity(payload.len() + 9);
    put_varint(&mut out, quarter_stream_id);
    put_varint(&mut out, 0);
    out.extend_from_slice(payload);
    out.freeze()
}

/// One received QUIC DATAGRAM frame, classified for this tunnel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuicDatagram {
    /// A UDP payload for this tunnel.
    Udp(Bytes),
    /// A context ID that is not registered (RFC 9298 §4: dropped).
    UnregisteredContext(u64),
    /// A datagram for another request stream.
    OtherStream(u64),
    /// Too short to hold the quarter stream ID and context ID.
    Malformed,
}

pub fn decode_quic_datagram(d: &Bytes, quarter_stream_id: u64) -> QuicDatagram {
    let mut pos = 0;
    let Some(q) = read_varint(d, &mut pos) else { return QuicDatagram::Malformed };
    if q != quarter_stream_id {
        return QuicDatagram::OtherStream(q);
    }
    let Some(ctx) = read_varint(d, &mut pos) else { return QuicDatagram::Malformed };
    if ctx != 0 {
        return QuicDatagram::UnregisteredContext(ctx);
    }
    QuicDatagram::Udp(d.slice(pos..))
}

/// One decoded capsule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Capsule {
    /// A DATAGRAM capsule with a Context ID 0 UDP payload.
    Udp(Bytes),
    /// A DATAGRAM capsule for an unregistered context (dropped).
    UnregisteredContext(u64),
    /// A capsule type this client does not implement; its value is skipped
    /// without being buffered (RFC 9297 §3.1).
    Unknown(u64),
}

/// A capsule stream that cannot be parsed further (a length-framed stream
/// cannot be resynchronized, so each of these ends the tunnel).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapsuleError {
    /// A DATAGRAM capsule longer than any UDP payload plus a Context ID.
    TooLarge,
    /// A DATAGRAM capsule too short to hold a Context ID.
    Truncated,
    /// The stream ended inside a capsule (RFC 9297 §3.3: malformed).
    EndedInsideCapsule,
}

impl CapsuleError {
    pub fn describe(self) -> &'static str {
        match self {
            CapsuleError::TooLarge => "a DATAGRAM capsule declared a length larger than any UDP payload",
            CapsuleError::Truncated => "a DATAGRAM capsule was too short to hold a Context ID",
            CapsuleError::EndedInsideCapsule => "the stream ended inside a capsule, which RFC 9297 §3.3 defines as malformed",
        }
    }
}

/// Incremental RFC 9297 capsule reader for the CONNECT stream. Holds at most
/// one partial capsule; unknown capsule values are counted down, never kept.
#[derive(Debug, Default)]
pub struct CapsuleDecoder {
    buf: BytesMut,
    skip: u64,
}

impl CapsuleDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    fn max_value() -> usize {
        MAX_UDP_PAYLOAD + CONTEXT_ID_SLACK
    }

    /// The largest slice to [`push`](Self::push) before draining
    /// [`decode_next`](Self::decode_next): this keeps the buffer under two capsules
    /// however large the DATA frames are.
    pub fn feed_limit() -> usize {
        Self::max_value() + MAX_CAPSULE_HEADER
    }

    pub fn push(&mut self, chunk: &[u8]) {
        self.buf.extend_from_slice(chunk);
    }

    fn advance_skip(&mut self) -> bool {
        let take = self.skip.min(self.buf.len() as u64) as usize;
        self.buf.advance(take);
        self.skip -= take as u64;
        self.skip == 0
    }

    /// The next complete capsule, or `None` when more bytes are needed.
    pub fn decode_next(&mut self) -> Result<Option<Capsule>, CapsuleError> {
        if !self.advance_skip() {
            return Ok(None);
        }
        let mut pos = 0;
        let Some(ty) = read_varint(&self.buf, &mut pos) else { return Ok(None) };
        let Some(len) = read_varint(&self.buf, &mut pos) else { return Ok(None) };
        if ty != CAPSULE_DATAGRAM {
            self.buf.advance(pos);
            self.skip = len;
            self.advance_skip();
            return Ok(Some(Capsule::Unknown(ty)));
        }
        if len > Self::max_value() as u64 {
            return Err(CapsuleError::TooLarge);
        }
        let len = len as usize;
        if self.buf.len() - pos < len {
            return Ok(None);
        }
        self.buf.advance(pos);
        let mut value = self.buf.split_to(len);
        let mut vp = 0;
        let Some(ctx) = read_varint(&value, &mut vp) else { return Err(CapsuleError::Truncated) };
        if ctx != 0 {
            return Ok(Some(Capsule::UnregisteredContext(ctx)));
        }
        value.advance(vp);
        Ok(Some(Capsule::Udp(value.freeze())))
    }

    /// Classify the peer's end of stream: clean only between capsules.
    pub fn finish(&self) -> Result<(), CapsuleError> {
        if self.buf.is_empty() && self.skip == 0 { Ok(()) } else { Err(CapsuleError::EndedInsideCapsule) }
    }
}

// ---------------------------------------------------------------- session ---

async fn next_cmd(rx: &mut Option<CommandRx>) -> Option<SessionCommand> {
    match rx {
        Some(r) => r.recv().await,
        None => std::future::pending().await,
    }
}

fn encoding_name(e: MasqueEncoding) -> &'static str {
    match e {
        MasqueEncoding::QuicDatagram => "QUIC DATAGRAM frames",
        MasqueEncoding::Capsule => "DATAGRAM capsules on the CONNECT stream",
    }
}

type SendHalf = h3::client::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>;

/// Datagram accounting shared by scripted and interactive sends.
struct Tunnel<'a> {
    plan: &'a MasquePlan,
    quic: quinn::Connection,
    tx: SendHalf,
    quarter: u64,
    tr: Transcript,
    status: MasqueTunnel,
    sent: u64,
    capsule_fallback_noted: bool,
}

impl Tunnel<'_> {
    /// Send one UDP payload in the chosen encoding. A payload too large for
    /// a QUIC DATAGRAM frame goes as a capsule in automatic mode and is not
    /// sent when QUIC datagrams are required. Never counts what was not
    /// handed to the connection.
    async fn send(&mut self, payload: &[u8]) -> Result<(), TransportFailure> {
        if payload.len() > MAX_UDP_PAYLOAD {
            self.tr.note("not_sent", &format!("a {}-byte datagram exceeds the RFC 9298 limit of {MAX_UDP_PAYLOAD} bytes", payload.len()));
            return Ok(());
        }
        if self.status.encoding == Some(MasqueEncoding::QuicDatagram) {
            match self.quic.send_datagram(encode_quic_datagram(self.quarter, payload)) {
                Ok(()) => {
                    self.status.sent_quic_datagrams += 1;
                    self.sent += 1;
                    self.tr.data(Direction::Sent, "datagram", payload);
                    return Ok(());
                }
                Err(quinn::SendDatagramError::TooLarge) if self.plan.mode == MasqueDatagramMode::Auto => {
                    if !self.capsule_fallback_noted {
                        self.capsule_fallback_noted = true;
                        self.tr.note(
                            "encoding",
                            "a datagram larger than the QUIC path's DATAGRAM frame limit was sent as a DATAGRAM capsule instead",
                        );
                    }
                }
                Err(quinn::SendDatagramError::TooLarge) => {
                    self.tr.note(
                        "not_sent",
                        &format!(
                            "a {}-byte datagram exceeds the QUIC DATAGRAM frame limit ({} bytes) and QUIC datagrams are required; it was not sent",
                            payload.len(),
                            self.quic.max_datagram_size().unwrap_or(0)
                        ),
                    );
                    return Ok(());
                }
                Err(e) => {
                    return Err(TransportFailure::new(
                        Phase::Session,
                        FailureKind::RequestWriteFailed,
                        format!("sending a QUIC DATAGRAM frame failed: {e}"),
                    ));
                }
            }
        }
        match self.tx.send_data(encode_capsule(payload)).await {
            Ok(()) => {
                self.status.sent_capsules += 1;
                self.sent += 1;
                self.tr.data(Direction::Sent, "datagram", payload);
                Ok(())
            }
            Err(e) => Err(crate::h3::stream_failure(
                &e,
                Phase::Session,
                FailureKind::RequestWriteFailed,
                "sending a DATAGRAM capsule on the CONNECT stream failed",
            )),
        }
    }
}

pub async fn run(plan: &MasquePlan, events: &EventCtx, cancel: &CancellationToken, mut commands: Option<CommandRx>) -> SessionOutput {
    let interactive = commands.is_some();
    let mut rec = Recorder::new(0, events.clone());
    events.emit(ExecutionEvent::AttemptStarted { execution_id: events.execution_id, attempt: 0 });
    let mut obs = new_attempt(0, AttemptReason::Initial, "CONNECT", &plan.display_url);
    let mut facts = SessionFacts::default();
    let total_deadline = if interactive { None } else { deadline_from(plan.timeouts.total_ms) };
    let mut tunnel = MasqueTunnel {
        proxy: format!("{}:{}", plan.proxy_host, plan.proxy_port),
        target: plan.target.clone(),
        extended_connect: None,
        h3_datagrams: None,
        connect_status: None,
        encoding: None,
        sent_quic_datagrams: 0,
        sent_capsules: 0,
        received_quic_datagrams: 0,
        received_capsules: 0,
        dropped: 0,
        closed_by: ClosedBy::NotClosed,
    };
    let udp_status = |t: &MasqueTunnel, sent: u64, received: u64| ProtocolStatus::Udp {
        datagrams_sent: sent,
        datagrams_received: received,
        window_ms: plan.response_window_ms,
        masque: Some(t.clone()),
    };
    let early = |rec: Recorder, obs: AttemptObservation, f: TransportFailure, facts: SessionFacts, status: ProtocolStatus| {
        SessionOutput::single(fail_attempt(rec, obs, f, DispatchState::NotDispatched, events), None, status, facts)
    };
    let close_quic = |q: &quinn::Connection| q.close(H3_NO_ERROR.into(), b"");

    // ---- QUIC + HTTP/3 to the proxy (Anvil advertises SETTINGS_H3_DATAGRAM) ----
    let connected = {
        let connect = crate::h3::quic_connect_with(
            &mut rec,
            &plan.proxy_host,
            plan.proxy_port,
            &plan.dns,
            &plan.timeouts,
            &plan.tls,
            crate::h3::client_endpoint,
            cancel,
            H3ClientOptions { h3_datagrams: true },
        );
        tokio::select! {
            r = connect => Some(r),
            _ = sleep_until_opt(total_deadline) => None,
        }
    };
    let QuicConnected { quic, mut send, observation } = match connected {
        Some(Ok(c)) => c,
        Some(Err((f, cobs))) => {
            obs.connection = cobs;
            return early(rec, obs, f, facts, ProtocolStatus::None);
        }
        None => {
            let f = TransportFailure::new(
                rec.open_phase().unwrap_or(Phase::QuicHandshake),
                FailureKind::TotalTimeout,
                "total deadline elapsed during the QUIC connection to the MASQUE proxy",
            )
            .with_deadline(plan.timeouts.total_ms);
            return early(rec, obs, f, facts, ProtocolStatus::None);
        }
    };
    obs.connection = Some(observation);
    if let Some(c) = obs.connection.as_mut() {
        c.via_proxy = Some(format!("MASQUE CONNECT-UDP proxy {}", plan.proxy_authority));
    }

    // ---- the proxy's SETTINGS: nothing is sent before they allow it ----
    let wait_ms = plan.timeouts.response_headers_ms.unwrap_or(5_000).min(5_000);
    let peer = match crate::h3::await_peer_settings(&send, wait_ms, cancel).await {
        Ok(p) => p,
        Err(why) => {
            close_quic(&quic);
            if why == "canceled" {
                let f = TransportFailure::new(
                    Phase::ProtocolHandshake,
                    FailureKind::Canceled,
                    "canceled while waiting for the proxy's HTTP/3 SETTINGS",
                );
                return early(rec, obs, f, facts, ProtocolStatus::None);
            }
            let mut f = TransportFailure::new(
                Phase::ProtocolHandshake,
                FailureKind::MasqueUnsupported,
                format!(
                    "the MASQUE proxy sent no HTTP/3 SETTINGS within {wait_ms} ms, so it is unknown whether it allows extended CONNECT (RFC 9298 needs it); nothing was sent"
                ),
            );
            f.deadline_ms = Some(wait_ms);
            return early(rec, obs, f, facts, udp_status(&tunnel, 0, 0));
        }
    };
    let quic_datagrams = peer.h3_datagram && quic.max_datagram_size().is_some();
    tunnel.extended_connect = Some(peer.extended_connect);
    tunnel.h3_datagrams = Some(quic_datagrams);
    if !peer.extended_connect {
        close_quic(&quic);
        let f = TransportFailure::new(
            Phase::ProtocolHandshake,
            FailureKind::MasqueUnsupported,
            "the proxy's HTTP/3 SETTINGS do not enable extended CONNECT (SETTINGS_ENABLE_CONNECT_PROTOCOL), so a CONNECT-UDP request cannot be made on this connection; nothing was sent",
        );
        return early(rec, obs, f, facts, udp_status(&tunnel, 0, 0));
    }
    let no_quic_datagrams_why = if !peer.h3_datagram {
        "the proxy's SETTINGS do not enable HTTP/3 datagrams (SETTINGS_H3_DATAGRAM)"
    } else {
        "QUIC did not negotiate DATAGRAM frames (no max_datagram_frame_size transport parameter)"
    };
    let encoding = match plan.mode {
        MasqueDatagramMode::Capsules => MasqueEncoding::Capsule,
        MasqueDatagramMode::QuicDatagrams if quic_datagrams => MasqueEncoding::QuicDatagram,
        MasqueDatagramMode::QuicDatagrams => {
            close_quic(&quic);
            let f = TransportFailure::new(
                Phase::ProtocolHandshake,
                FailureKind::MasqueUnsupported,
                format!("QUIC DATAGRAM frames were required for this tunnel, but {no_quic_datagrams_why}; nothing was sent"),
            );
            return early(rec, obs, f, facts, udp_status(&tunnel, 0, 0));
        }
        MasqueDatagramMode::Auto if quic_datagrams => MasqueEncoding::QuicDatagram,
        MasqueDatagramMode::Auto => MasqueEncoding::Capsule,
    };
    tunnel.encoding = Some(encoding);
    let why = match (plan.mode, encoding) {
        (MasqueDatagramMode::Capsules, _) => "capsules were requested".to_string(),
        (_, MasqueEncoding::QuicDatagram) => "the proxy enabled SETTINGS_H3_DATAGRAM and QUIC negotiated DATAGRAM frames".to_string(),
        (_, MasqueEncoding::Capsule) => format!("{no_quic_datagrams_why} (RFC 9297 §3.5)"),
    };
    let detail = format!("proxy enabled extended CONNECT (RFC 9298); HTTP Datagrams as {}: {why}", encoding_name(encoding));
    rec.mark(Phase::ProtocolHandshake, PhaseStatus::Completed, Some(&detail));
    facts.notes.push(format!(
        "CONNECT-UDP to {} through {}: HTTP Datagrams as {}, because {why}",
        plan.target,
        plan.proxy_authority,
        encoding_name(encoding)
    ));

    // ---- extended CONNECT (:protocol = connect-udp) ----
    let mut req = match Request::builder()
        .method(Method::CONNECT)
        .uri(format!("https://{}{}", plan.proxy_authority, plan.request_target))
        .body(())
    {
        Ok(r) => r,
        Err(e) => {
            close_quic(&quic);
            let f =
                TransportFailure::new(Phase::Prepare, FailureKind::InvalidUrl, format!("the CONNECT-UDP request could not be built: {e}"))
                    .with_field("udp.masque.uri_template");
            return early(rec, obs, f, facts, udp_status(&tunnel, 0, 0));
        }
    };
    for (n, v) in &plan.headers {
        if n == http::header::HOST
            || n == http::header::CONNECTION
            || n == http::header::UPGRADE
            || n == http::header::TRANSFER_ENCODING
            || n.as_str() == "keep-alive"
            || n.as_str() == "capsule-protocol"
        {
            continue;
        }
        req.headers_mut().append(n.clone(), v.clone());
    }
    req.headers_mut().insert("capsule-protocol", HeaderValue::from_static("?1"));
    req.extensions_mut().insert(h3::ext::Protocol::CONNECT_UDP);
    let req_headers = header_entries(req.headers());
    obs.bytes.request_headers_logical = logical_header_bytes(&req_headers) + plan.request_target.len() as u64 + 16;
    obs.bytes.request_headers_estimated = true;
    let before = quic.stats();
    let w_idx = rec.start(Phase::RequestWrite);
    let sent = tokio::select! {
        r = send.send_request(req) => r.map_err(|e| crate::h3::stream_failure(&e, Phase::RequestWrite, FailureKind::RequestWriteFailed,
            "sending the CONNECT-UDP request failed")),
        _ = sleep_until_opt(total_deadline) => Err(TransportFailure::new(Phase::RequestWrite, FailureKind::TotalTimeout,
            "total deadline elapsed while sending the CONNECT-UDP request").with_deadline(plan.timeouts.total_ms)),
        _ = cancel.cancelled() => Err(TransportFailure::new(Phase::RequestWrite, FailureKind::Canceled, "canceled while sending the CONNECT-UDP request")),
    };
    let mut stream = match sent {
        Ok(s) => s,
        Err(f) => {
            close_quic(&quic);
            return early(rec, obs, f, facts, udp_status(&tunnel, 0, 0));
        }
    };
    rec.finish_with(
        w_idx,
        PhaseStatus::Completed,
        "extended CONNECT (:protocol connect-udp, capsule-protocol: ?1) sent on a new request stream",
    );
    let h_idx = rec.start(Phase::AwaitResponseHeaders);
    let headers_deadline = deadline_from(plan.timeouts.response_headers_ms);
    let resp = tokio::select! {
        r = stream.recv_response() => r.map_err(|e| crate::h3::stream_failure(&e, Phase::AwaitResponseHeaders, FailureKind::ResetBeforeResponse,
            "the proxy ended the CONNECT-UDP stream before answering")),
        _ = sleep_until_opt(headers_deadline) => Err(TransportFailure::new(Phase::AwaitResponseHeaders, FailureKind::ResponseHeadersTimeout,
            "the proxy did not answer the CONNECT-UDP request before the response-header deadline").with_deadline(plan.timeouts.response_headers_ms)),
        _ = sleep_until_opt(total_deadline) => Err(TransportFailure::new(Phase::AwaitResponseHeaders, FailureKind::TotalTimeout,
            "total deadline elapsed before the proxy answered").with_deadline(plan.timeouts.total_ms)),
        _ = cancel.cancelled() => Err(TransportFailure::new(Phase::AwaitResponseHeaders, FailureKind::Canceled, "canceled before the proxy answered")),
    };
    let resp = match resp {
        Ok(r) => r,
        Err(f) => {
            close_quic(&quic);
            // The request reached the proxy but no datagram was sent.
            return early(rec, obs, f, facts, udp_status(&tunnel, 0, 0));
        }
    };
    rec.finish(h_idx, PhaseStatus::Completed);
    let status = resp.status().as_u16();
    obs.response_status = Some(status);
    tunnel.connect_status = Some(status);
    events.emit(ExecutionEvent::ResponseHead { execution_id: events.execution_id, attempt: 0, status });
    let headers = header_entries(resp.headers());
    obs.bytes.response_headers_logical = Some(logical_header_bytes(&headers));
    let content_type = resp.headers().get(http::header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).map(|s| s.to_string());

    // ---- refusal: keep the proxy's (bounded) answer as evidence ----
    if !(200..300).contains(&status) {
        let b_idx = rec.start(Phase::ResponseBody);
        let mut captured = BytesMut::new();
        let mut wire = 0u64;
        let mut completeness = BodyCompleteness::Complete;
        loop {
            let idle = deadline_from(plan.timeouts.body_idle_ms.or(Some(5_000)));
            let chunk = tokio::select! {
                c = stream.recv_data() => c,
                _ = sleep_until_opt(idle) => { completeness = BodyCompleteness::Incomplete; break; }
                _ = cancel.cancelled() => { completeness = BodyCompleteness::Canceled; break; }
            };
            match chunk {
                Ok(Some(mut c)) => {
                    let n = c.remaining();
                    let d = c.copy_to_bytes(n);
                    wire += n as u64;
                    let room = (plan.limits.capture_bytes as usize).saturating_sub(captured.len());
                    captured.extend_from_slice(&d[..d.len().min(room)]);
                    if wire > plan.limits.max_response_bytes {
                        completeness = BodyCompleteness::StoppedAtLocalLimit;
                        break;
                    }
                }
                Ok(None) => break,
                Err(_) => {
                    completeness = BodyCompleteness::Incomplete;
                    break;
                }
            }
        }
        rec.finish(b_idx, if completeness == BodyCompleteness::Complete { PhaseStatus::Completed } else { PhaseStatus::Failed });
        close_quic(&quic);
        let mut f = TransportFailure::new(
            Phase::ProtocolHandshake,
            FailureKind::MasqueRefused,
            format!(
                "the MASQUE proxy answered the CONNECT-UDP request for {} with HTTP {status}; no tunnel was opened and no datagram was sent",
                plan.target
            ),
        );
        f.status = Some(status);
        obs.failure = Some(f);
        obs.bytes.response_body_wire = Some(wire);
        let obs = finish_attempt(rec, obs, events);
        let captured = captured.freeze();
        let response = response_record(status, http::Version::HTTP_3, headers, body_capture(completeness, wire, &captured, content_type));
        return SessionOutput::single(
            AttemptOutput { observation: obs, response: Some(response), body: captured },
            None,
            udp_status(&tunnel, 0, 0),
            facts,
        );
    }
    let capsule_protocol = resp.headers().get("capsule-protocol").map(|v| v.as_bytes() == b"?1").unwrap_or(false);
    if !capsule_protocol {
        facts.notes.push(
            "the proxy's 2xx answer did not carry Capsule-Protocol: ?1 (RFC 9297 §3.4); capsules on the stream are still parsed".into(),
        );
    }
    let response = response_record(status, http::Version::HTTP_3, headers, body_capture(BodyCompleteness::NoBody, 0, &[], content_type));

    // ---- the tunnel ----
    let quarter = stream.id().into_inner() / 4;
    let (tx, mut rx) = stream.split();
    let tr = Transcript::new(rec.t0, plan.transcript, events.clone(), plan.redact.clone());
    let mut t = Tunnel { plan, quic: quic.clone(), tx, quarter, tr, status: tunnel, sent: 0, capsule_fallback_noted: false };
    t.tr.note(
        "tunnel",
        &format!(
            "CONNECT-UDP tunnel to {} open through {} (HTTP {status}); HTTP Datagrams as {}",
            plan.target,
            plan.proxy_authority,
            encoding_name(encoding)
        ),
    );
    let s_idx = rec.start(Phase::Session);
    let mut received = 0u64;
    let mut failure: Option<TransportFailure> = None;
    let mut seen: HashSet<[u8; 32]> = HashSet::new();
    let mut decoder = CapsuleDecoder::new();
    let mut dropped_noted = false;

    for d in &plan.datagrams {
        if let Err(f) = t.send(d).await {
            failure = Some(f);
            t.status.closed_by = ClosedBy::Abnormal;
            break;
        }
    }

    let window = Duration::from_millis(plan.response_window_ms);
    let mut window_end = Instant::now() + window;
    let mut stream_open = true;
    enum Ev {
        Quic(Result<Bytes, quinn::ConnectionError>),
        Stream(Result<Option<Bytes>, h3::error::StreamError>),
        Cmd(Option<SessionCommand>),
        WindowEnd,
        Deadline,
        Canceled,
    }
    // What arrived, in either encoding, for this tunnel.
    enum Got {
        Udp(Bytes, MasqueEncoding),
        Dropped(String),
    }
    'session: while failure.is_none() {
        let window_deadline = if interactive { None } else { Some(window_end) };
        let ev = tokio::select! {
            d = quic.read_datagram() => Ev::Quic(d),
            c = rx.recv_data(), if stream_open => Ev::Stream(c.map(|o| o.map(|mut b| { let n = b.remaining(); b.copy_to_bytes(n) }))),
            c = next_cmd(&mut commands), if interactive => Ev::Cmd(c),
            _ = sleep_until_opt(window_deadline) => Ev::WindowEnd,
            _ = sleep_until_opt(total_deadline) => Ev::Deadline,
            _ = cancel.cancelled() => Ev::Canceled,
        };
        let mut got: Vec<Got> = Vec::new();
        match ev {
            Ev::Quic(Ok(d)) => match decode_quic_datagram(&d, quarter) {
                QuicDatagram::Udp(p) => got.push(Got::Udp(p, MasqueEncoding::QuicDatagram)),
                QuicDatagram::UnregisteredContext(c) => {
                    got.push(Got::Dropped(format!("an HTTP Datagram with unregistered context ID {c}")))
                }
                QuicDatagram::OtherStream(q) => {
                    got.push(Got::Dropped(format!("a QUIC DATAGRAM frame for another request stream (quarter ID {q})")))
                }
                QuicDatagram::Malformed => got.push(Got::Dropped("a malformed QUIC DATAGRAM frame".into())),
            },
            Ev::Quic(Err(e)) => {
                let mut f = crate::h3::quic_failure(&e, false, None);
                f.phase = Phase::Session;
                f.message = format!("the QUIC connection to the MASQUE proxy ended during the tunnel: {}", f.message);
                failure = Some(f);
                t.status.closed_by = ClosedBy::Abnormal;
            }
            Ev::Stream(Ok(Some(bytes))) => {
                let mut rest: &[u8] = &bytes;
                while !rest.is_empty() {
                    let n = rest.len().min(CapsuleDecoder::feed_limit());
                    decoder.push(&rest[..n]);
                    rest = &rest[n..];
                    loop {
                        match decoder.decode_next() {
                            Ok(Some(Capsule::Udp(p))) => got.push(Got::Udp(p, MasqueEncoding::Capsule)),
                            Ok(Some(Capsule::UnregisteredContext(c))) => {
                                got.push(Got::Dropped(format!("a DATAGRAM capsule with unregistered context ID {c}")))
                            }
                            Ok(Some(Capsule::Unknown(ty))) => got.push(Got::Dropped(format!("a capsule of unknown type 0x{ty:x}"))),
                            Ok(None) => break,
                            Err(e) => {
                                failure = Some(TransportFailure::new(
                                    Phase::Session,
                                    FailureKind::HttpProtocolError,
                                    format!("the proxy's capsule stream is malformed: {}", e.describe()),
                                ));
                                t.status.closed_by = ClosedBy::Abnormal;
                                break;
                            }
                        }
                    }
                    if failure.is_some() {
                        break;
                    }
                }
            }
            Ev::Stream(Ok(None)) => {
                stream_open = false;
                match decoder.finish() {
                    Ok(()) => {
                        t.status.closed_by = ClosedBy::Peer;
                        t.tr.note("tunnel_closed", "the proxy closed the tunnel (FIN on the CONNECT stream)");
                    }
                    Err(e) => {
                        failure = Some(TransportFailure::new(
                            Phase::Session,
                            FailureKind::BodyIncomplete,
                            format!("the proxy ended the CONNECT-UDP stream abnormally: {}", e.describe()),
                        ));
                        t.status.closed_by = ClosedBy::Abnormal;
                    }
                }
            }
            Ev::Stream(Err(e)) => {
                stream_open = false;
                failure =
                    Some(crate::h3::stream_failure(&e, Phase::Session, FailureKind::BodyReset, "the proxy reset the CONNECT-UDP stream"));
                t.status.closed_by = ClosedBy::Abnormal;
            }
            Ev::Cmd(c) => match c {
                Some(SessionCommand::SendText { text }) => {
                    if let Err(f) = t.send(text.as_bytes()).await {
                        failure = Some(f);
                        t.status.closed_by = ClosedBy::Abnormal;
                    }
                    window_end = Instant::now() + window;
                }
                Some(SessionCommand::SendBinaryHex { hex }) => match decode_hex(&hex) {
                    Ok(b) => {
                        if let Err(f) = t.send(&b).await {
                            failure = Some(f);
                            t.status.closed_by = ClosedBy::Abnormal;
                        }
                        window_end = Instant::now() + window;
                    }
                    Err(e) => t.tr.note("error", &format!("datagram not sent: {e}")),
                },
                Some(SessionCommand::Ping) | Some(SessionCommand::HalfClose) => {
                    t.tr.note("unsupported_command", "UDP has no ping or half-close; send a datagram or Close")
                }
                Some(SessionCommand::Close { .. }) | None => {
                    t.status.closed_by = ClosedBy::Client;
                    break 'session;
                }
            },
            Ev::WindowEnd => {
                t.status.closed_by = ClosedBy::Client;
                break 'session;
            }
            Ev::Deadline => {
                failure = Some(
                    TransportFailure::new(
                        Phase::Session,
                        FailureKind::TotalTimeout,
                        "the total deadline elapsed during the CONNECT-UDP exchange",
                    )
                    .with_deadline(plan.timeouts.total_ms),
                );
                t.status.closed_by = ClosedBy::Timeout;
            }
            Ev::Canceled => {
                failure = Some(TransportFailure::new(Phase::Session, FailureKind::Canceled, "the CONNECT-UDP exchange was canceled"));
                t.status.closed_by = ClosedBy::Client;
            }
        }
        for g in got {
            match g {
                Got::Udp(p, enc) => {
                    received += 1;
                    match enc {
                        MasqueEncoding::QuicDatagram => t.status.received_quic_datagrams += 1,
                        MasqueEncoding::Capsule => t.status.received_capsules += 1,
                    }
                    let mut digest = [0u8; 32];
                    digest.copy_from_slice(&Sha256::digest(&p));
                    if !seen.insert(digest) {
                        facts.repeated_datagrams += 1;
                    }
                    t.tr.data(Direction::Received, "datagram", &p);
                    if received >= plan.max_datagrams as u64 {
                        t.tr.note("note", &format!("stopped receiving at max_datagrams ({})", plan.max_datagrams));
                        t.status.closed_by = ClosedBy::Client;
                        break 'session;
                    }
                }
                Got::Dropped(what) => {
                    t.status.dropped += 1;
                    if !dropped_noted {
                        dropped_noted = true;
                        t.tr.note("dropped", &format!("dropped {what} (RFC 9298 §4 / RFC 9297 §3.1)"));
                    }
                }
            }
        }
        if !stream_open && failure.is_none() {
            break;
        }
    }

    // ---- end of the tunnel ----
    let Tunnel { mut tx, tr, status: tunnel, sent, .. } = t;
    if stream_open && !matches!(failure.as_ref().map(|f| f.kind), Some(FailureKind::Canceled)) {
        // Anvil's own end of the tunnel: a clean FIN on the CONNECT stream.
        let _ = tokio::time::timeout(Duration::from_millis(500), tx.finish()).await;
    }
    let after = quic.stats();
    close_quic(&quic);
    if facts.repeated_datagrams > 0 {
        facts.notes.push(format!(
            "{} received datagram(s) were byte-identical to an earlier received datagram (UDP may duplicate datagrams; the peer may also send identical replies)",
            facts.repeated_datagrams
        ));
    }
    if tunnel.dropped > 0 {
        facts.notes.push(format!(
            "{} HTTP Datagram(s) or capsule(s) not addressed to this tunnel's UDP context were dropped, as RFC 9298 §4 and RFC 9297 §3.1 require",
            tunnel.dropped
        ));
    }
    rec.finish(
        s_idx,
        match &failure {
            Some(f) => phase_status_for(f.kind),
            None => PhaseStatus::Completed,
        },
    );
    obs.dispatch = if sent == 0 {
        DispatchState::NotDispatched
    } else if received > 0 {
        DispatchState::Sent
    } else {
        DispatchState::MayHaveBeenSent
    };
    obs.failure = failure;
    obs.bytes.request_body = tr.sent_bytes();
    obs.bytes.response_body_wire = Some(tr.received_bytes());
    obs.bytes.connection_bytes_written = Some(after.udp_tx.bytes.saturating_sub(before.udp_tx.bytes));
    obs.bytes.connection_bytes_read = Some(after.udp_rx.bytes.saturating_sub(before.udp_rx.bytes));
    let obs = finish_attempt(rec, obs, events);
    let ps = udp_status(&tunnel, sent, received);
    SessionOutput::single(AttemptOutput { observation: obs, response: Some(response), body: Bytes::new() }, Some(tr.finish()), ps, facts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varints_round_trip_at_every_length() {
        for v in [0u64, 63, 64, 16_383, 16_384, (1 << 30) - 1, 1 << 30, (1 << 62) - 1] {
            let mut b = BytesMut::new();
            put_varint(&mut b, v);
            let mut pos = 0;
            assert_eq!(read_varint(&b, &mut pos), Some(v));
            assert_eq!(pos, b.len());
            assert_eq!(read_varint(&b[..b.len() - 1], &mut 0), None, "truncated varints need more bytes");
        }
    }

    #[test]
    fn capsules_decode_across_arbitrary_splits_and_skip_unknown_types() {
        let mut wire = BytesMut::new();
        wire.extend_from_slice(&encode_capsule(b"one"));
        // An unknown capsule type (0x2f) with a 5-byte value, then a DATAGRAM
        // capsule for an unregistered context, then another payload.
        put_varint(&mut wire, 0x2f);
        put_varint(&mut wire, 5);
        wire.extend_from_slice(b"skip!");
        put_varint(&mut wire, CAPSULE_DATAGRAM);
        put_varint(&mut wire, 3);
        put_varint(&mut wire, 2);
        wire.extend_from_slice(b"xy");
        wire.extend_from_slice(&encode_capsule(b""));
        wire.extend_from_slice(&encode_capsule(&[7u8; 300]));
        for split in 1..wire.len() {
            let mut d = CapsuleDecoder::new();
            let mut out = vec![];
            for part in [&wire[..split], &wire[split..]] {
                d.push(part);
                while let Some(c) = d.decode_next().unwrap() {
                    out.push(c);
                }
            }
            assert_eq!(
                out,
                vec![
                    Capsule::Udp(Bytes::from_static(b"one")),
                    Capsule::Unknown(0x2f),
                    Capsule::UnregisteredContext(2),
                    Capsule::Udp(Bytes::new()),
                    Capsule::Udp(Bytes::from(vec![7u8; 300])),
                ],
                "split at {split}"
            );
            assert_eq!(d.finish(), Ok(()));
        }
    }

    #[test]
    fn a_stream_ending_inside_a_capsule_or_oversized_capsules_are_errors() {
        let mut d = CapsuleDecoder::new();
        let c = encode_capsule(b"partial");
        d.push(&c[..4]);
        assert_eq!(d.decode_next(), Ok(None));
        assert_eq!(d.finish(), Err(CapsuleError::EndedInsideCapsule));
        let mut big = BytesMut::new();
        put_varint(&mut big, CAPSULE_DATAGRAM);
        put_varint(&mut big, (MAX_UDP_PAYLOAD + 100) as u64);
        let mut d = CapsuleDecoder::new();
        d.push(&big);
        assert_eq!(d.decode_next(), Err(CapsuleError::TooLarge));
        // An unknown capsule may be arbitrarily long: it is skipped, not buffered.
        let mut unknown = BytesMut::new();
        put_varint(&mut unknown, 0x1234);
        put_varint(&mut unknown, 10 * MAX_UDP_PAYLOAD as u64);
        let mut d = CapsuleDecoder::new();
        d.push(&unknown);
        assert_eq!(d.decode_next(), Ok(Some(Capsule::Unknown(0x1234))));
        d.push(&vec![0u8; CapsuleDecoder::feed_limit()]);
        assert_eq!(d.decode_next(), Ok(None));
        assert!(d.buf.is_empty(), "skipped bytes are not retained");
        assert_eq!(d.finish(), Err(CapsuleError::EndedInsideCapsule));
    }

    #[test]
    fn quic_datagrams_carry_the_quarter_stream_id_and_context() {
        let d = encode_quic_datagram(2, b"hello");
        assert_eq!(&d[..2], &[2, 0]);
        assert_eq!(decode_quic_datagram(&d, 2), QuicDatagram::Udp(Bytes::from_static(b"hello")));
        assert_eq!(decode_quic_datagram(&d, 0), QuicDatagram::OtherStream(2));
        let mut other_ctx = BytesMut::new();
        put_varint(&mut other_ctx, 2);
        put_varint(&mut other_ctx, 4);
        assert_eq!(decode_quic_datagram(&other_ctx.freeze(), 2), QuicDatagram::UnregisteredContext(4));
        assert_eq!(decode_quic_datagram(&Bytes::from_static(&[2]), 2), QuicDatagram::Malformed);
    }
}
