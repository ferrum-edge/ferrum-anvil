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
//! * **Channel.** An open tunnel is a [`DatagramChannel`]: the UDP session
//!   here and a DTLS session ([`crate::dtls`]) run over the same
//!   [`MasqueChannel`], so DTLS records travel as HTTP Datagrams exactly like
//!   UDP payloads.

use crate::datagram::{DatagramChannel, Inbound, Sent};
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
use std::collections::{HashSet, VecDeque};
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

/// The CONNECT-UDP leg: how to reach the proxy and which tunnel to ask for
/// (auth already applied to `headers`). Shared by UDP and DTLS sessions.
#[derive(Clone)]
pub struct MasqueTunnelPlan {
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
    /// Redacted proxy request URL for evidence.
    pub display_url: String,
}

/// A fully prepared UDP exchange through a CONNECT-UDP tunnel.
#[derive(Clone)]
pub struct MasquePlan {
    pub tunnel: MasqueTunnelPlan,
    pub datagrams: Vec<Bytes>,
    /// How long to wait for responses after the last datagram is sent.
    pub response_window_ms: u64,
    /// Stop receiving after this many datagrams.
    pub max_datagrams: u32,
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

// ----------------------------------------------------------------- tunnel ---

async fn next_cmd(rx: &mut Option<CommandRx>) -> Option<SessionCommand> {
    match rx {
        Some(r) => r.recv().await,
        None => std::future::pending().await,
    }
}

pub(crate) fn encoding_name(e: MasqueEncoding) -> &'static str {
    match e {
        MasqueEncoding::QuicDatagram => "QUIC DATAGRAM frames",
        MasqueEncoding::Capsule => "DATAGRAM capsules on the CONNECT stream",
    }
}

type SendHalf = h3::client::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>;
type RecvHalf = h3::client::RequestStream<h3_quinn::RecvStream, Bytes>;

/// Why a CONNECT-UDP bootstrap did not open a tunnel. Nothing was sent
/// through a tunnel; the attempt stays the CONNECT to the proxy.
pub(crate) struct NotOpened {
    failure: TransportFailure,
    /// `None` when the exchange never reached the proxy's HTTP/3 layer.
    tunnel: Option<MasqueTunnel>,
    /// The proxy's refusal (status, headers, bounded body).
    refusal: Option<(ResponseRecord, Bytes)>,
}

impl NotOpened {
    /// The single-attempt output for a tunnel that never opened.
    pub(crate) fn into_output(
        self,
        rec: Recorder,
        obs: AttemptObservation,
        facts: SessionFacts,
        window_ms: u64,
        events: &EventCtx,
    ) -> SessionOutput {
        let status = match self.tunnel {
            Some(t) => ProtocolStatus::Udp { datagrams_sent: 0, datagrams_received: 0, window_ms, masque: Some(t) },
            None => ProtocolStatus::None,
        };
        let mut out = fail_attempt(rec, obs, self.failure, DispatchState::NotDispatched, events);
        if let Some((response, body)) = self.refusal {
            out.response = Some(response);
            out.body = body;
        }
        SessionOutput::single(out, None, status, facts)
    }
}

/// An open CONNECT-UDP tunnel: the [`DatagramChannel`] UDP payloads (and a
/// DTLS session's records) travel through. Counts every datagram per
/// encoding in its [`MasqueTunnel`] and holds the QUIC connection open until
/// [`close`](Self::close).
pub struct MasqueChannel {
    quic: quinn::Connection,
    /// Keeps the HTTP/3 connection's request side alive for the tunnel.
    _requests: crate::h3::SendReq,
    tx: SendHalf,
    rx: RecvHalf,
    quarter: u64,
    mode: MasqueDatagramMode,
    status: MasqueTunnel,
    decoder: CapsuleDecoder,
    queue: VecDeque<Queued>,
    stream_open: bool,
    ended: bool,
    capsule_fallback_noted: bool,
    before: quinn::ConnectionStats,
    /// The CONNECT request's header fields and the proxy's answer.
    connect_headers: Vec<HeaderEntry>,
    response: ResponseRecord,
    proxy_authority: String,
}

/// Decoded input waiting to be delivered, in arrival order.
enum Queued {
    Udp(Bytes, MasqueEncoding),
    Dropped(String),
    Ended(Option<TransportFailure>, String),
}

impl MasqueChannel {
    /// The tunnel facts so far.
    pub fn status(&self) -> &MasqueTunnel {
        &self.status
    }

    /// Record how the session ended the tunnel. An end the channel observed
    /// itself (the proxy's close, or an abnormal end) is kept.
    pub fn set_closed_by(&mut self, by: ClosedBy) {
        if matches!(self.status.closed_by, ClosedBy::NotClosed) {
            self.status.closed_by = by;
        }
    }

    /// End the tunnel: a clean FIN on the CONNECT stream unless the stream
    /// already ended or the session was canceled, then the QUIC connection
    /// closes with `H3_NO_ERROR`. Returns the tunnel facts and the QUIC
    /// connection's UDP bytes written and read while the tunnel was open.
    pub async fn close(mut self, canceled: bool) -> (MasqueTunnel, u64, u64) {
        if self.stream_open && !canceled {
            let _ = tokio::time::timeout(Duration::from_millis(500), self.tx.finish()).await;
        }
        let after = self.quic.stats();
        self.quic.close(H3_NO_ERROR.into(), b"");
        (
            self.status,
            after.udp_tx.bytes.saturating_sub(self.before.udp_tx.bytes),
            after.udp_rx.bytes.saturating_sub(self.before.udp_rx.bytes),
        )
    }

    fn end(&mut self, failure: Option<TransportFailure>, note: &str) {
        self.stream_open = false;
        self.status.closed_by = if failure.is_some() { ClosedBy::Abnormal } else { ClosedBy::Peer };
        self.queue.push_back(Queued::Ended(failure, note.to_string()));
    }

    fn on_quic(&mut self, d: Result<Bytes, quinn::ConnectionError>) {
        match d {
            Ok(d) => match decode_quic_datagram(&d, self.quarter) {
                QuicDatagram::Udp(p) => self.queue.push_back(Queued::Udp(p, MasqueEncoding::QuicDatagram)),
                QuicDatagram::UnregisteredContext(c) => {
                    self.queue.push_back(Queued::Dropped(format!("an HTTP Datagram with unregistered context ID {c}")))
                }
                QuicDatagram::OtherStream(q) => {
                    self.queue.push_back(Queued::Dropped(format!("a QUIC DATAGRAM frame for another request stream (quarter ID {q})")))
                }
                QuicDatagram::Malformed => self.queue.push_back(Queued::Dropped("a malformed QUIC DATAGRAM frame".into())),
            },
            Err(e) => {
                let mut f = crate::h3::quic_failure(&e, false, None);
                f.phase = Phase::Session;
                f.message = format!("the QUIC connection to the MASQUE proxy ended during the tunnel: {}", f.message);
                self.end(Some(f), "the QUIC connection to the proxy ended");
            }
        }
    }

    fn on_stream(&mut self, c: Result<Option<Bytes>, h3::error::StreamError>) {
        match c {
            Ok(Some(bytes)) => {
                let mut rest: &[u8] = &bytes;
                while !rest.is_empty() {
                    let n = rest.len().min(CapsuleDecoder::feed_limit());
                    self.decoder.push(&rest[..n]);
                    rest = &rest[n..];
                    loop {
                        match self.decoder.decode_next() {
                            Ok(Some(Capsule::Udp(p))) => self.queue.push_back(Queued::Udp(p, MasqueEncoding::Capsule)),
                            Ok(Some(Capsule::UnregisteredContext(c))) => {
                                self.queue.push_back(Queued::Dropped(format!("a DATAGRAM capsule with unregistered context ID {c}")))
                            }
                            Ok(Some(Capsule::Unknown(ty))) => {
                                self.queue.push_back(Queued::Dropped(format!("a capsule of unknown type 0x{ty:x}")))
                            }
                            Ok(None) => break,
                            Err(e) => {
                                // A length-framed stream cannot be resynchronized.
                                let f = TransportFailure::new(
                                    Phase::Session,
                                    FailureKind::HttpProtocolError,
                                    format!("the proxy's capsule stream is malformed: {}", e.describe()),
                                );
                                self.end(Some(f), "the proxy's capsule stream is malformed");
                                return;
                            }
                        }
                    }
                }
            }
            Ok(None) => match self.decoder.finish() {
                Ok(()) => self.end(None, "the proxy closed the tunnel (FIN on the CONNECT stream)"),
                Err(e) => {
                    let f = TransportFailure::new(
                        Phase::Session,
                        FailureKind::BodyIncomplete,
                        format!("the proxy ended the CONNECT-UDP stream abnormally: {}", e.describe()),
                    );
                    self.end(Some(f), "the proxy ended the CONNECT-UDP stream inside a capsule");
                }
            },
            Err(e) => {
                let f = crate::h3::stream_failure(&e, Phase::Session, FailureKind::BodyReset, "the proxy reset the CONNECT-UDP stream");
                self.end(Some(f), "the proxy reset the CONNECT-UDP stream");
            }
        }
    }

    /// Re-express the CONNECT attempt as the outer leg of a session that runs
    /// inside this tunnel (DTLS): the QUIC connection, SETTINGS and extended
    /// CONNECT recorded so far become a CONNECT-UDP [`TunnelObservation`], the
    /// attempt keeps one `proxy_tunnel` phase for them and addresses the
    /// target from here on. The proxy's 2xx is tunnel evidence, not a
    /// response of the target.
    pub fn into_outer_leg(&self, rec: &mut Recorder, obs: &mut AttemptObservation, method: &str, url: &str) {
        let outer = std::mem::take(&mut rec.phases);
        let quic = obs.connection.take().unwrap_or_else(|| crate::connector::blank_observation(crate::connector::next_connection_id()));
        let start = outer.iter().filter_map(|p| p.start_us).min();
        let end = outer.iter().filter_map(|p| p.end_us).max();
        let encoding = self.status.encoding.map(encoding_name).unwrap_or("HTTP Datagrams");
        rec.mark(
            Phase::Dns,
            PhaseStatus::NotApplicable,
            Some("the MASQUE proxy resolves the target (the proxy's own DNS is tunnel evidence)"),
        );
        rec.mark(
            Phase::Connect,
            PhaseStatus::NotApplicable,
            Some("datagrams reach the target inside the CONNECT-UDP tunnel (the QUIC connection to the proxy is tunnel evidence)"),
        );
        rec.phases.push(PhaseTiming {
            phase: Phase::ProxyTunnel,
            status: PhaseStatus::Completed,
            start_us: start,
            end_us: end,
            detail: Some(format!(
                "CONNECT-UDP via {} → {} (HTTP {}; {encoding})",
                self.proxy_authority, self.status.target, self.response.status
            )),
        });
        let mut c = crate::connector::blank_observation(crate::connector::next_connection_id());
        c.via_proxy = Some(format!("MASQUE CONNECT-UDP proxy {}", self.proxy_authority));
        c.tunnel = Some(TunnelObservation {
            kind: TunnelKind::ConnectUdp,
            endpoint: format!("{} (MASQUE CONNECT-UDP proxy)", self.status.proxy),
            authority: self.status.target.clone(),
            resolved_addresses: quic.resolved_addresses,
            resolution_source: quic.resolution_source,
            connect_attempts: quic.connect_attempts,
            local_address: quic.local_address,
            remote_address: quic.remote_address,
            phases: outer,
            tls: quic.tls,
            connect_headers: self.connect_headers.clone(),
            connect_status: Some(self.response.status),
            response_headers: self.response.headers.clone(),
            refusal_body: None,
            refusal_body_truncated: false,
            failure: None,
            datagrams: None,
        });
        obs.connection = Some(c);
        obs.method = method.to_string();
        obs.url = url.to_string();
        obs.response_status = None;
        obs.bytes = ByteCounts::default();
    }
}

impl DatagramChannel for MasqueChannel {
    /// Send one UDP payload in the chosen encoding. A payload too large for a
    /// QUIC DATAGRAM frame goes as a capsule in automatic mode and is not sent
    /// when QUIC datagrams are required. Never counts what was not handed to
    /// the connection.
    async fn send(&mut self, payload: &[u8]) -> Result<Sent, TransportFailure> {
        if payload.len() > MAX_UDP_PAYLOAD {
            return Ok(Sent::NotSent(format!("a {}-byte datagram exceeds the RFC 9298 limit of {MAX_UDP_PAYLOAD} bytes", payload.len())));
        }
        let mut note = None;
        if self.status.encoding == Some(MasqueEncoding::QuicDatagram) {
            match self.quic.send_datagram(encode_quic_datagram(self.quarter, payload)) {
                Ok(()) => {
                    self.status.sent_quic_datagrams += 1;
                    return Ok(Sent::Sent(None));
                }
                Err(quinn::SendDatagramError::TooLarge) if self.mode == MasqueDatagramMode::Auto => {
                    if !self.capsule_fallback_noted {
                        self.capsule_fallback_noted = true;
                        note = Some(
                            "a datagram larger than the QUIC path's DATAGRAM frame limit was sent as a DATAGRAM capsule instead"
                                .to_string(),
                        );
                    }
                }
                Err(quinn::SendDatagramError::TooLarge) => {
                    return Ok(Sent::NotSent(format!(
                        "a {}-byte datagram exceeds the QUIC DATAGRAM frame limit ({} bytes) and QUIC datagrams are required; it was not sent",
                        payload.len(),
                        self.quic.max_datagram_size().unwrap_or(0)
                    )));
                }
                Err(e) => {
                    self.status.closed_by = ClosedBy::Abnormal;
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
                Ok(Sent::Sent(note))
            }
            Err(e) => {
                self.status.closed_by = ClosedBy::Abnormal;
                Err(crate::h3::stream_failure(
                    &e,
                    Phase::Session,
                    FailureKind::RequestWriteFailed,
                    "sending a DATAGRAM capsule on the CONNECT stream failed",
                ))
            }
        }
    }

    /// The next UDP payload (either encoding), a dropped item, or the end of
    /// the tunnel. Decoded input is queued in `self` before anything else is
    /// awaited, so dropping this future loses nothing.
    async fn recv(&mut self) -> Inbound {
        enum Ev {
            Quic(Result<Bytes, quinn::ConnectionError>),
            Stream(Result<Option<Bytes>, h3::error::StreamError>),
        }
        loop {
            if let Some(q) = self.queue.pop_front() {
                return match q {
                    Queued::Udp(p, enc) => {
                        match enc {
                            MasqueEncoding::QuicDatagram => self.status.received_quic_datagrams += 1,
                            MasqueEncoding::Capsule => self.status.received_capsules += 1,
                        }
                        Inbound::Datagram(p)
                    }
                    Queued::Dropped(what) => {
                        self.status.dropped += 1;
                        Inbound::Dropped(what)
                    }
                    Queued::Ended(failure, note) => {
                        self.ended = true;
                        Inbound::Ended { failure, note }
                    }
                };
            }
            if self.ended {
                return std::future::pending().await;
            }
            let stream_open = self.stream_open;
            let ev = tokio::select! {
                d = self.quic.read_datagram() => Ev::Quic(d),
                c = self.rx.recv_data(), if stream_open => Ev::Stream(c.map(|o| o.map(|mut b| { let n = b.remaining(); b.copy_to_bytes(n) }))),
            };
            match ev {
                Ev::Quic(d) => self.on_quic(d),
                Ev::Stream(c) => self.on_stream(c),
            }
        }
    }

    fn max_datagram(&self) -> Option<usize> {
        // A QUIC DATAGRAM frame carries the quarter stream ID and Context ID 0
        // in front of the payload; capsules carry any UDP payload.
        match self.status.encoding {
            Some(MasqueEncoding::QuicDatagram) => {
                let mut ids = BytesMut::new();
                put_varint(&mut ids, self.quarter);
                put_varint(&mut ids, 0);
                self.quic.max_datagram_size().map(|m| m.saturating_sub(ids.len()))
            }
            _ => None,
        }
    }
}

/// Open a CONNECT-UDP tunnel: a fresh QUIC connection to the proxy (Anvil
/// advertises `SETTINGS_H3_DATAGRAM`), the proxy's SETTINGS (nothing is sent
/// before they allow extended CONNECT), then the extended CONNECT and its
/// answer. Phases go into `rec` and the QUIC connection into `obs`.
pub(crate) async fn open(
    plan: &MasqueTunnelPlan,
    rec: &mut Recorder,
    obs: &mut AttemptObservation,
    facts: &mut SessionFacts,
    events: &EventCtx,
    cancel: &CancellationToken,
    total_deadline: Option<Instant>,
) -> Result<MasqueChannel, NotOpened> {
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
    let close_quic = |q: &quinn::Connection| q.close(H3_NO_ERROR.into(), b"");
    let not_opened = |failure: TransportFailure, tunnel: Option<MasqueTunnel>| NotOpened { failure, tunnel, refusal: None };

    // ---- QUIC + HTTP/3 to the proxy (Anvil advertises SETTINGS_H3_DATAGRAM) ----
    let connected = {
        let connect = crate::h3::quic_connect_with(
            rec,
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
            return Err(not_opened(f, None));
        }
        None => {
            let f = TransportFailure::new(
                rec.open_phase().unwrap_or(Phase::QuicHandshake),
                FailureKind::TotalTimeout,
                "total deadline elapsed during the QUIC connection to the MASQUE proxy",
            )
            .with_deadline(plan.timeouts.total_ms);
            return Err(not_opened(f, None));
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
                return Err(not_opened(f, None));
            }
            let mut f = TransportFailure::new(
                Phase::ProtocolHandshake,
                FailureKind::MasqueUnsupported,
                format!(
                    "the MASQUE proxy sent no HTTP/3 SETTINGS within {wait_ms} ms, so it is unknown whether it allows extended CONNECT (RFC 9298 needs it); nothing was sent"
                ),
            );
            f.deadline_ms = Some(wait_ms);
            return Err(not_opened(f, Some(tunnel)));
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
        return Err(not_opened(f, Some(tunnel)));
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
            return Err(not_opened(f, Some(tunnel)));
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
            return Err(not_opened(f, Some(tunnel)));
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
            return Err(not_opened(f, Some(tunnel)));
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
            return Err(not_opened(f, Some(tunnel)));
        }
    };
    rec.finish(h_idx, PhaseStatus::Completed);
    let status = resp.status().as_u16();
    obs.response_status = Some(status);
    tunnel.connect_status = Some(status);
    events.emit(ExecutionEvent::ResponseHead { execution_id: events.execution_id, attempt: obs.index, status });
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
        obs.bytes.response_body_wire = Some(wire);
        let captured = captured.freeze();
        let response = response_record(status, http::Version::HTTP_3, headers, body_capture(completeness, wire, &captured, content_type));
        return Err(NotOpened { failure: f, tunnel: Some(tunnel), refusal: Some((response, captured)) });
    }
    let capsule_protocol = resp.headers().get("capsule-protocol").map(|v| v.as_bytes() == b"?1").unwrap_or(false);
    if !capsule_protocol {
        facts.notes.push(
            "the proxy's 2xx answer did not carry Capsule-Protocol: ?1 (RFC 9297 §3.4); capsules on the stream are still parsed".into(),
        );
    }
    let response = response_record(status, http::Version::HTTP_3, headers, body_capture(BodyCompleteness::NoBody, 0, &[], content_type));
    let quarter = stream.id().into_inner() / 4;
    let (tx, rx) = stream.split();
    Ok(MasqueChannel {
        quic,
        _requests: send,
        tx,
        rx,
        quarter,
        mode: plan.mode,
        status: tunnel,
        decoder: CapsuleDecoder::new(),
        queue: VecDeque::new(),
        stream_open: true,
        ended: false,
        capsule_fallback_noted: false,
        before,
        connect_headers: req_headers,
        response,
        proxy_authority: plan.proxy_authority.clone(),
    })
}

/// The inspector note for items the tunnel dropped.
pub(crate) fn note_dropped(facts: &mut SessionFacts, tunnel: &MasqueTunnel) {
    if tunnel.dropped > 0 {
        facts.notes.push(format!(
            "{} HTTP Datagram(s) or capsule(s) not addressed to this tunnel's UDP context were dropped, as RFC 9298 §4 and RFC 9297 §3.1 require",
            tunnel.dropped
        ));
    }
}

// ------------------------------------------------------------ UDP session ---

/// Send one UDP payload through the tunnel and record it (or why it was not sent).
async fn send_recorded(chan: &mut MasqueChannel, tr: &mut Transcript, sent: &mut u64, payload: &[u8]) -> Result<(), TransportFailure> {
    match chan.send(payload).await? {
        Sent::Sent(note) => {
            *sent += 1;
            tr.data(Direction::Sent, "datagram", payload);
            if let Some(n) = note {
                tr.note("encoding", &n);
            }
        }
        Sent::NotSent(why) => tr.note("not_sent", &why),
    }
    Ok(())
}

pub async fn run(plan: &MasquePlan, events: &EventCtx, cancel: &CancellationToken, mut commands: Option<CommandRx>) -> SessionOutput {
    let interactive = commands.is_some();
    let mut rec = Recorder::new(0, events.clone());
    events.emit(ExecutionEvent::AttemptStarted { execution_id: events.execution_id, attempt: 0 });
    let mut obs = new_attempt(0, AttemptReason::Initial, "CONNECT", &plan.tunnel.display_url);
    let mut facts = SessionFacts::default();
    let total_deadline = if interactive { None } else { deadline_from(plan.tunnel.timeouts.total_ms) };
    let mut chan = match open(&plan.tunnel, &mut rec, &mut obs, &mut facts, events, cancel, total_deadline).await {
        Ok(c) => c,
        Err(n) => return n.into_output(rec, obs, facts, plan.response_window_ms, events),
    };
    let response = chan.response.clone();
    let encoding = chan.status.encoding.unwrap_or(MasqueEncoding::Capsule);

    // ---- the tunnel ----
    let mut tr = Transcript::new(rec.t0, plan.transcript, events.clone(), plan.redact.clone());
    tr.note(
        "tunnel",
        &format!(
            "CONNECT-UDP tunnel to {} open through {} (HTTP {}); HTTP Datagrams as {}",
            plan.tunnel.target,
            plan.tunnel.proxy_authority,
            response.status,
            encoding_name(encoding)
        ),
    );
    let s_idx = rec.start(Phase::Session);
    let mut sent = 0u64;
    let mut received = 0u64;
    let mut failure: Option<TransportFailure> = None;
    let mut seen: HashSet<[u8; 32]> = HashSet::new();
    let mut dropped_noted = false;

    for d in &plan.datagrams {
        if let Err(f) = send_recorded(&mut chan, &mut tr, &mut sent, d).await {
            failure = Some(f);
            break;
        }
    }

    let window = Duration::from_millis(plan.response_window_ms);
    let mut window_end = Instant::now() + window;
    enum Ev {
        In(Inbound),
        Cmd(Option<SessionCommand>),
        WindowEnd,
        Deadline,
        Canceled,
    }
    while failure.is_none() {
        let window_deadline = if interactive { None } else { Some(window_end) };
        let ev = tokio::select! {
            i = chan.recv() => Ev::In(i),
            c = next_cmd(&mut commands), if interactive => Ev::Cmd(c),
            _ = sleep_until_opt(window_deadline) => Ev::WindowEnd,
            _ = sleep_until_opt(total_deadline) => Ev::Deadline,
            _ = cancel.cancelled() => Ev::Canceled,
        };
        match ev {
            Ev::In(Inbound::Datagram(p)) => {
                received += 1;
                let mut digest = [0u8; 32];
                digest.copy_from_slice(&Sha256::digest(&p));
                if !seen.insert(digest) {
                    facts.repeated_datagrams += 1;
                }
                tr.data(Direction::Received, "datagram", &p);
                if received >= plan.max_datagrams as u64 {
                    tr.note("note", &format!("stopped receiving at max_datagrams ({})", plan.max_datagrams));
                    chan.set_closed_by(ClosedBy::Client);
                    break;
                }
            }
            Ev::In(Inbound::Dropped(what)) => {
                if !dropped_noted {
                    dropped_noted = true;
                    tr.note("dropped", &format!("dropped {what} (RFC 9298 §4 / RFC 9297 §3.1)"));
                }
            }
            Ev::In(Inbound::Ended { failure: Some(f), .. }) => failure = Some(f),
            Ev::In(Inbound::Ended { failure: None, note }) => {
                tr.note("tunnel_closed", &note);
                break;
            }
            Ev::In(Inbound::PortUnreachable(e) | Inbound::Error(e)) => tr.note("error", &format!("receive error: {e}")),
            Ev::Cmd(c) => match c {
                Some(SessionCommand::SendText { text }) => {
                    if let Err(f) = send_recorded(&mut chan, &mut tr, &mut sent, text.as_bytes()).await {
                        failure = Some(f);
                    }
                    window_end = Instant::now() + window;
                }
                Some(SessionCommand::SendBinaryHex { hex }) => match decode_hex(&hex) {
                    Ok(b) => {
                        if let Err(f) = send_recorded(&mut chan, &mut tr, &mut sent, &b).await {
                            failure = Some(f);
                        }
                        window_end = Instant::now() + window;
                    }
                    Err(e) => tr.note("error", &format!("datagram not sent: {e}")),
                },
                Some(SessionCommand::Ping) | Some(SessionCommand::HalfClose) => {
                    tr.note("unsupported_command", "UDP has no ping or half-close; send a datagram or Close")
                }
                Some(SessionCommand::Close { .. }) | None => {
                    chan.set_closed_by(ClosedBy::Client);
                    break;
                }
            },
            Ev::WindowEnd => {
                chan.set_closed_by(ClosedBy::Client);
                break;
            }
            Ev::Deadline => {
                failure = Some(
                    TransportFailure::new(
                        Phase::Session,
                        FailureKind::TotalTimeout,
                        "the total deadline elapsed during the CONNECT-UDP exchange",
                    )
                    .with_deadline(plan.tunnel.timeouts.total_ms),
                );
                chan.set_closed_by(ClosedBy::Timeout);
            }
            Ev::Canceled => {
                failure = Some(TransportFailure::new(Phase::Session, FailureKind::Canceled, "the CONNECT-UDP exchange was canceled"));
                chan.set_closed_by(ClosedBy::Client);
            }
        }
    }

    // ---- end of the tunnel ----
    let canceled = matches!(failure.as_ref().map(|f| f.kind), Some(FailureKind::Canceled));
    let (tunnel, written, read) = chan.close(canceled).await;
    if facts.repeated_datagrams > 0 {
        facts.notes.push(format!(
            "{} received datagram(s) were byte-identical to an earlier received datagram (UDP may duplicate datagrams; the peer may also send identical replies)",
            facts.repeated_datagrams
        ));
    }
    note_dropped(&mut facts, &tunnel);
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
    obs.bytes.connection_bytes_written = Some(written);
    obs.bytes.connection_bytes_read = Some(read);
    let obs = finish_attempt(rec, obs, events);
    let ps = ProtocolStatus::Udp {
        datagrams_sent: sent,
        datagrams_received: received,
        window_ms: plan.response_window_ms,
        masque: Some(tunnel),
    };
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
