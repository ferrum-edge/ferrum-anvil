//! Raw TCP / TLS exchanges (arbitrary bytes, never assumed to be a known
//! application protocol).
//!
//! * Connection setup reuses the shared connector (DNS → TCP → proxy tunnel
//!   → TLS with the profile's trust and client identity), so phases and TLS
//!   evidence match HTTP.
//! * Payloads are sent with an explicit framing preset: none, newline
//!   delimited, or a big-endian u16/u32 length prefix. Received bytes are
//!   split with the same preset; without a preset each read is recorded as a
//!   chunk (TCP itself has no message boundaries).
//! * Half-close (`shutdown(Write)`, a TLS `close_notify` first) keeps the read
//!   side open so a peer that replies after the client finished is recorded.
//! * Stop conditions: expected frame count, max read bytes, read-idle
//!   timeout, peer close, total deadline, cancel, or a Close command.

use crate::connector::{ProxyPlan, Target};
use crate::dns::DnsConfig;
use crate::http::{AttemptOutput, sleep_until_opt};
use crate::recorder::{EventCtx, Recorder};
use crate::session::*;
use crate::tls::PreparedTls;
use anvil_domain::events::{ExecutionEvent, SessionCommand};
use anvil_domain::execution::*;
use anvil_domain::outcome::{ClosedBy, ProtocolStatus};
use anvil_domain::request::TcpFraming;
use anvil_domain::settings::Timeouts;
use bytes::{Buf, Bytes, BytesMut};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

#[derive(Clone)]
pub struct TcpPlan {
    pub host: String,
    pub port: u16,
    /// TLS to the destination (`tls://`), with the profile's trust/identity.
    pub tls: Option<Arc<PreparedTls>>,
    pub alpn: Vec<String>,
    pub proxy: Option<ProxyPlan>,
    pub dns: DnsConfig,
    pub timeouts: Timeouts,
    pub framing: TcpFraming,
    /// Logical payloads (framing is applied when sending).
    pub payloads: Vec<Bytes>,
    pub half_close_after_send: bool,
    pub read_idle_ms: u64,
    pub max_read_bytes: u64,
    pub expect_frames: u32,
    pub display_url: String,
    pub transcript: TranscriptLimits,
    pub redact: Option<RedactFn>,
    /// PROXY protocol header written after connect, before TLS.
    pub proxy_header: Option<crate::proxy_protocol::HeaderPlan>,
}

/// Apply a framing preset to one payload.
pub fn encode_frame(framing: TcpFraming, payload: &[u8]) -> Result<Bytes, String> {
    Ok(match framing {
        TcpFraming::None => Bytes::copy_from_slice(payload),
        TcpFraming::NewlineDelimited => {
            let mut b = BytesMut::from(payload);
            if !payload.ends_with(b"\n") {
                b.extend_from_slice(b"\n");
            }
            b.freeze()
        }
        TcpFraming::LengthPrefixedU16 => {
            let len =
                u16::try_from(payload.len()).map_err(|_| format!("a {}-byte payload does not fit a u16 length prefix", payload.len()))?;
            let mut b = BytesMut::with_capacity(payload.len() + 2);
            b.extend_from_slice(&len.to_be_bytes());
            b.extend_from_slice(payload);
            b.freeze()
        }
        TcpFraming::LengthPrefixedU32 => {
            let len = u32::try_from(payload.len()).map_err(|_| "payload does not fit a u32 length prefix".to_string())?;
            let mut b = BytesMut::with_capacity(payload.len() + 4);
            b.extend_from_slice(&len.to_be_bytes());
            b.extend_from_slice(payload);
            b.freeze()
        }
    })
}

/// Incremental frame splitter for received bytes.
pub struct Deframer {
    framing: TcpFraming,
    buf: BytesMut,
    max_frame: usize,
}

impl Deframer {
    pub fn new(framing: TcpFraming, max_frame: usize) -> Self {
        Deframer { framing, buf: BytesMut::new(), max_frame: max_frame.max(1) }
    }

    /// Push bytes and return complete frames (payloads without delimiters or
    /// prefixes). Errors when a declared frame exceeds the bound.
    pub fn push(&mut self, data: &[u8]) -> Result<Vec<Bytes>, String> {
        if self.framing == TcpFraming::None {
            return Ok(vec![Bytes::copy_from_slice(data)]);
        }
        self.buf.extend_from_slice(data);
        let mut out = Vec::new();
        loop {
            match self.framing {
                TcpFraming::NewlineDelimited => match self.buf.iter().position(|b| *b == b'\n') {
                    Some(i) => {
                        let mut line = self.buf.split_to(i + 1);
                        line.truncate(i);
                        if line.last() == Some(&b'\r') {
                            line.truncate(i - 1);
                        }
                        out.push(line.freeze());
                    }
                    None => {
                        if self.buf.len() > self.max_frame {
                            return Err(format!("no newline within {} bytes", self.max_frame));
                        }
                        break;
                    }
                },
                TcpFraming::LengthPrefixedU16 | TcpFraming::LengthPrefixedU32 => {
                    let hl = if self.framing == TcpFraming::LengthPrefixedU16 { 2 } else { 4 };
                    if self.buf.len() < hl {
                        break;
                    }
                    let len = if hl == 2 {
                        u16::from_be_bytes([self.buf[0], self.buf[1]]) as usize
                    } else {
                        u32::from_be_bytes([self.buf[0], self.buf[1], self.buf[2], self.buf[3]]) as usize
                    };
                    if len > self.max_frame {
                        return Err(format!("a received frame declares {len} bytes, above the local limit of {}", self.max_frame));
                    }
                    if self.buf.len() < hl + len {
                        break;
                    }
                    self.buf.advance(hl);
                    out.push(self.buf.split_to(len).freeze());
                }
                TcpFraming::None => break,
            }
        }
        Ok(out)
    }

    /// Bytes received that do not (yet) form a complete frame.
    pub fn leftover(&self) -> &[u8] {
        &self.buf
    }
}

async fn next_cmd(rx: &mut Option<CommandRx>) -> Option<SessionCommand> {
    match rx {
        Some(r) => r.recv().await,
        None => std::future::pending().await,
    }
}

enum Stop {
    Peer,
    Client,
    Idle,
    Failed(TransportFailure, ClosedBy),
}

pub async fn run(plan: &TcpPlan, events: &EventCtx, cancel: &CancellationToken, mut commands: Option<CommandRx>) -> SessionOutput {
    let interactive = commands.is_some();
    let mut rec = Recorder::new(0, events.clone());
    events.emit(ExecutionEvent::AttemptStarted { execution_id: events.execution_id, attempt: 0 });
    let method = if plan.tls.is_some() { "TLS" } else { "TCP" };
    let mut obs = new_attempt(0, AttemptReason::Initial, method, &plan.display_url);
    let facts = SessionFacts::default();
    let total_deadline = if interactive { None } else { deadline_from(plan.timeouts.total_ms) };

    // Encode everything before connecting: framing errors are local.
    let mut frames = Vec::with_capacity(plan.payloads.len());
    for (i, p) in plan.payloads.iter().enumerate() {
        match encode_frame(plan.framing, p) {
            Ok(f) => frames.push((p.clone(), f)),
            Err(e) => {
                let f = TransportFailure::new(Phase::Prepare, FailureKind::BodySerialization, e).with_field(format!("tcp.payloads[{i}]"));
                return SessionOutput::single(
                    fail_attempt(rec, obs, f, DispatchState::NotDispatched, events),
                    None,
                    ProtocolStatus::None,
                    facts,
                );
            }
        }
    }

    let alpn: Vec<&str> = plan.alpn.iter().map(|s| s.as_str()).collect();
    let target = Target { host: &plan.host, port: plan.port, tls: plan.tls.as_deref(), alpn: &alpn, http_forward_via_proxy: false };
    let redact = plan.redact.clone();
    let header = plan.proxy_header.as_ref().map(|p| crate::connector::PreTlsHeader {
        plan: p,
        redact: redact.as_deref().map(|r| r as &(dyn Fn(&str) -> String + Send + Sync)),
    });
    let est =
        match establish_guarded_with(&mut rec, &target, &plan.dns, &plan.timeouts, plan.proxy.as_ref(), cancel, total_deadline, header)
            .await
        {
            Ok(e) => e,
            Err((f, o)) => {
                obs.connection = o;
                return SessionOutput::single(
                    fail_attempt(rec, obs, f, DispatchState::NotDispatched, events),
                    None,
                    ProtocolStatus::None,
                    facts,
                );
            }
        };
    let mut cobs = est.observation;
    cobs.protocol = Some(if plan.tls.is_some() { "tls".into() } else { "tcp".into() });
    obs.connection = Some(cobs);
    let stats = est.stats;
    let (mut rd, mut wr) = tokio::io::split(est.io);
    let mut tr = Transcript::new(rec.t0, plan.transcript, events.clone(), plan.redact.clone());
    if let Some(h) = obs.connection.as_ref().and_then(|c| c.proxy_header.as_ref()) {
        match hex::decode(&h.hex) {
            Ok(bytes) => tr.control(Direction::Sent, "proxy_protocol_header", &bytes),
            Err(_) => tr.note("proxy_protocol_header", &crate::proxy_protocol::header_summary(h)),
        }
    }
    let s_idx = rec.start(Phase::Session);
    let kind = if plan.framing == TcpFraming::None { "bytes" } else { "frame" };
    let mut bytes_sent = 0u64;
    let mut bytes_received = 0u64;
    let mut half_closed = false;
    let mut frames_received = 0u64;
    let mut deframer = Deframer::new(plan.framing, plan.max_read_bytes.min(64 * 1024 * 1024) as usize);
    if plan.framing == TcpFraming::None && plan.expect_frames > 0 {
        tr.note("note", "expect_frames is ignored without a framing preset: TCP has no message boundaries");
    }
    let mut stop: Option<Stop> = None;

    // ---- scripted sends ----
    for (payload, wire) in &frames {
        let r = tokio::select! {
            r = async { wr.write_all(wire).await?; wr.flush().await } => r,
            _ = cancel.cancelled() => {
                stop = Some(Stop::Failed(TransportFailure::new(Phase::Session, FailureKind::Canceled, "canceled while sending"), ClosedBy::Client));
                break;
            }
            _ = sleep_until_opt(deadline_from(plan.timeouts.request_write_ms)) => {
                stop = Some(Stop::Failed(TransportFailure::new(Phase::RequestWrite, FailureKind::RequestWriteTimeout,
                    "the payload could not be written before the write deadline (peer not reading?)").with_deadline(plan.timeouts.request_write_ms), ClosedBy::Client));
                break;
            }
        };
        match r {
            Ok(()) => {
                bytes_sent += wire.len() as u64;
                tr.data(Direction::Sent, kind, payload);
            }
            Err(e) => {
                let mut f =
                    TransportFailure::new(Phase::RequestWrite, FailureKind::RequestWriteFailed, format!("writing the payload failed: {e}"));
                f.io_error_kind = Some(format!("{:?}", e.kind()));
                if let Some((k, a)) = stats.tls_error() {
                    f.kind = k;
                    f.tls_alert = a;
                }
                stop = Some(Stop::Failed(f, ClosedBy::Abnormal));
                break;
            }
        }
    }
    if stop.is_none() && plan.half_close_after_send {
        match wr.shutdown().await {
            Ok(()) => {
                half_closed = true;
                tr.control(Direction::Sent, "half_close", b"write side closed (FIN); still reading");
            }
            Err(e) => tr.note("error", &format!("half-close failed: {e}")),
        }
    }

    // ---- read loop ----
    let mut buf = vec![0u8; 64 * 1024];
    let mut last_read = Instant::now();
    let idle = Duration::from_millis(plan.read_idle_ms.max(1));
    enum Ev {
        Read(std::io::Result<usize>),
        Cmd(Option<SessionCommand>),
        Idle,
        Deadline,
        Canceled,
    }
    while stop.is_none() {
        let idle_deadline = if interactive { None } else { Some(last_read + idle) };
        let ev = tokio::select! {
            r = rd.read(&mut buf) => Ev::Read(r),
            c = next_cmd(&mut commands), if interactive => Ev::Cmd(c),
            _ = sleep_until_opt(idle_deadline) => Ev::Idle,
            _ = sleep_until_opt(total_deadline) => Ev::Deadline,
            _ = cancel.cancelled() => Ev::Canceled,
        };
        match ev {
            Ev::Read(Ok(0)) => stop = Some(Stop::Peer),
            Ev::Read(Ok(n)) => {
                last_read = Instant::now();
                bytes_received += n as u64;
                match deframer.push(&buf[..n]) {
                    Ok(fs) => {
                        for f in fs {
                            frames_received += 1;
                            tr.data(Direction::Received, kind, &f);
                        }
                    }
                    Err(e) => {
                        let f = TransportFailure::new(Phase::Session, FailureKind::ResponseTooLargeLocal, format!("{e} (local limit)"));
                        stop = Some(Stop::Failed(f, ClosedBy::Client));
                        continue;
                    }
                }
                if plan.framing != TcpFraming::None
                    && plan.expect_frames > 0
                    && frames_received >= plan.expect_frames as u64
                    && !interactive
                {
                    stop = Some(Stop::Client);
                } else if bytes_received >= plan.max_read_bytes {
                    tr.note("note", &format!("stopped reading at the configured max_read_bytes ({})", plan.max_read_bytes));
                    stop = Some(Stop::Client);
                }
            }
            Ev::Read(Err(e)) => {
                let kind = match e.kind() {
                    std::io::ErrorKind::UnexpectedEof => FailureKind::BodyIncomplete,
                    _ => FailureKind::BodyReset,
                };
                let mut f = TransportFailure::new(Phase::Session, kind, format!("the connection failed while reading: {e}"));
                f.io_error_kind = Some(format!("{:?}", e.kind()));
                f.os_error_code = e.raw_os_error();
                if let Some((k, a)) = stats.tls_error() {
                    f.kind = k;
                    f.tls_alert = a;
                }
                stop = Some(Stop::Failed(f, ClosedBy::Abnormal));
            }
            Ev::Cmd(c) => match c {
                Some(SessionCommand::SendText { text }) => {
                    send_cmd(&mut wr, &mut tr, plan.framing, kind, text.as_bytes(), &mut bytes_sent, &mut stop, half_closed).await
                }
                Some(SessionCommand::SendBinaryHex { hex }) => match decode_hex(&hex) {
                    Ok(b) => send_cmd(&mut wr, &mut tr, plan.framing, kind, &b, &mut bytes_sent, &mut stop, half_closed).await,
                    Err(e) => tr.note("error", &format!("payload not sent: {e}")),
                },
                Some(SessionCommand::HalfClose) => {
                    if !half_closed {
                        match wr.shutdown().await {
                            Ok(()) => {
                                half_closed = true;
                                tr.control(Direction::Sent, "half_close", b"write side closed (FIN); still reading");
                            }
                            Err(e) => tr.note("error", &format!("half-close failed: {e}")),
                        }
                    }
                }
                Some(SessionCommand::Ping) => tr.note("unsupported_command", "raw TCP has no ping; send a payload instead"),
                Some(SessionCommand::Close { .. }) | None => stop = Some(Stop::Client),
            },
            Ev::Idle => stop = Some(Stop::Idle),
            Ev::Deadline => {
                let f =
                    TransportFailure::new(Phase::Session, FailureKind::TotalTimeout, "the total deadline elapsed during the TCP session")
                        .with_deadline(plan.timeouts.total_ms);
                stop = Some(Stop::Failed(f, ClosedBy::Timeout));
            }
            Ev::Canceled => {
                stop = Some(Stop::Failed(
                    TransportFailure::new(Phase::Session, FailureKind::Canceled, "the TCP session was canceled"),
                    ClosedBy::Client,
                ))
            }
        }
    }
    if !deframer.leftover().is_empty() {
        let n = deframer.leftover().len();
        tr.control(Direction::Received, "partial_frame", &deframer.leftover()[..n.min(4096)]);
    }
    let (closed_by, failure) = match stop.unwrap_or(Stop::Client) {
        Stop::Peer => (ClosedBy::Peer, None),
        Stop::Client => (ClosedBy::Client, None),
        Stop::Idle => (ClosedBy::Timeout, None),
        Stop::Failed(f, by) => (by, Some(f)),
    };
    // Close our side (best effort, bounded).
    if !half_closed {
        let _ = tokio::time::timeout(Duration::from_millis(250), wr.shutdown()).await;
    }
    drop((rd, wr));
    rec.finish(
        s_idx,
        match &failure {
            Some(f) => phase_status_for(f.kind),
            None => PhaseStatus::Completed,
        },
    );
    obs.dispatch = if bytes_sent > 0 && bytes_received > 0 {
        DispatchState::Sent
    } else if stats.bytes_written() > 0 && bytes_sent > 0 {
        DispatchState::MayHaveBeenSent
    } else {
        DispatchState::NotDispatched
    };
    obs.failure = failure;
    obs.bytes.request_body = bytes_sent;
    obs.bytes.response_body_wire = Some(bytes_received);
    obs.bytes.connection_bytes_written = Some(stats.bytes_written());
    obs.bytes.connection_bytes_read = Some(stats.bytes_read());
    let obs = finish_attempt(rec, obs, events);
    let ps = ProtocolStatus::Tcp { bytes_sent, bytes_received, half_closed, closed_by };
    SessionOutput::single(AttemptOutput { observation: obs, response: None, body: Bytes::new() }, Some(tr.finish()), ps, facts)
}

#[allow(clippy::too_many_arguments)]
async fn send_cmd<W: tokio::io::AsyncWrite + Unpin>(
    wr: &mut W,
    tr: &mut Transcript,
    framing: TcpFraming,
    kind: &str,
    payload: &[u8],
    bytes_sent: &mut u64,
    stop: &mut Option<Stop>,
    half_closed: bool,
) {
    if half_closed {
        tr.note("error", "payload not sent: the write side is already half-closed");
        return;
    }
    let wire = match encode_frame(framing, payload) {
        Ok(w) => w,
        Err(e) => {
            tr.note("error", &format!("payload not sent: {e}"));
            return;
        }
    };
    match async {
        wr.write_all(&wire).await?;
        wr.flush().await
    }
    .await
    {
        Ok(()) => {
            *bytes_sent += wire.len() as u64;
            tr.data(Direction::Sent, kind, payload);
        }
        Err(e) => {
            let mut f = TransportFailure::new(Phase::Session, FailureKind::RequestWriteFailed, format!("writing the payload failed: {e}"));
            f.io_error_kind = Some(format!("{:?}", e.kind()));
            *stop = Some(Stop::Failed(f, ClosedBy::Abnormal));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn framing_round_trip() {
        for framing in [TcpFraming::NewlineDelimited, TcpFraming::LengthPrefixedU16, TcpFraming::LengthPrefixedU32] {
            let mut d = Deframer::new(framing, 1024);
            let mut wire = Vec::new();
            wire.extend_from_slice(&encode_frame(framing, b"alpha").unwrap());
            wire.extend_from_slice(&encode_frame(framing, b"beta").unwrap());
            let (a, b) = wire.split_at(3);
            let mut got = d.push(a).unwrap();
            got.extend(d.push(b).unwrap());
            assert_eq!(got, vec![Bytes::from_static(b"alpha"), Bytes::from_static(b"beta")], "{framing:?}");
            assert!(d.leftover().is_empty());
        }
    }

    #[test]
    fn oversized_frames_are_local_errors() {
        assert!(encode_frame(TcpFraming::LengthPrefixedU16, &vec![0u8; 70_000]).is_err());
        let mut d = Deframer::new(TcpFraming::LengthPrefixedU32, 16);
        assert!(d.push(&[0, 0, 1, 0]).is_err());
    }
}
