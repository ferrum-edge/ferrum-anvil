//! UDP through a mesh HBONE tunnel (Ferrum Mesh datagram-over-HBONE).
//!
//! * **Bootstrap.** The byte-stream tunnel's outer leg
//!   ([`crate::hbone::endpoint_leg`]: DNS, TCP, mutual TLS with the client
//!   SVID and the endpoint's verified identity, ALPN `h2`), then an HTTP/2
//!   `CONNECT` with `:authority = host:port` of the UDP destination (IPv6
//!   bracketed), no `:scheme`, `:path` or `:protocol`, and the `udp`
//!   protocol marker (`x-ferrum-mesh-protocol: udp`, or `x-istio-protocol:
//!   udp`). The marker is what makes the endpoint relay datagrams to a UDP
//!   socket instead of splicing bytes to a TCP connection.
//! * **Framing.** After a `2xx`, both directions carry
//!   `[u16 big-endian length][payload]` records on the stream's DATA frames:
//!   one record per datagram, at most 65,535 payload bytes, zero-length
//!   records kept, records split across DATA frames or several packed into
//!   one. A datagram over the limit is refused locally and never sent.
//! * **Why `h2` directly.** hyper's CONNECT upgrade reports the peer's
//!   `RST_STREAM(CANCEL)` as a clean end of stream. Driving `h2` keeps the
//!   endpoint's `END_STREAM` and a reset (with its code) apart in the
//!   evidence.
//! * **Evidence.** The outer leg is the [`TunnelObservation`], exactly as
//!   for the byte-stream tunnel, plus its [`HboneDatagramChannel`]: records
//!   sent and received, local refusals, a truncated trailing record and how
//!   the stream ended. Transcript, counts, the response window and the
//!   dispatch rules are the direct UDP adapter's: silence is only "no
//!   response observed". ICMP errors toward the destination reach the
//!   endpoint's socket, never Anvil.
//! * **End.** Anvil ends the tunnel with `END_STREAM` when the window
//!   elapses, on Close or at `max_datagrams`, and resets it on cancel or at
//!   the total deadline. The endpoint's `END_STREAM` is the peer's close; a
//!   reset, a lost connection or a stream that ends inside a record is an
//!   abnormal end (incomplete, never success).
//!
//! One fresh HBONE connection carries one tunnel (never pooled), as for the
//! byte-stream tunnel.

use crate::connector::{self, ProxyPlan};
use crate::dns::DnsConfig;
use crate::errors::{HyperStage, classify_h2};
use crate::hbone::{self, Leg};
use crate::http::{AttemptOutput, sleep_until_opt};
use crate::recorder::{EventCtx, Recorder};
use crate::session::*;
use crate::stats::ConnStats;
use anvil_domain::events::{ExecutionEvent, SessionCommand};
use anvil_domain::execution::*;
use anvil_domain::outcome::{ClosedBy, ProtocolStatus};
use anvil_domain::settings::Timeouts;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use http::{Method, Request};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

/// Largest datagram one record carries (the `u16` length prefix).
pub const MAX_RECORD_PAYLOAD: usize = 65_535;
/// Bytes of a record's length prefix.
pub const RECORD_PREFIX: usize = 2;
/// How long Anvil waits, after its own `END_STREAM`, for the endpoint to end
/// its side (so the close is delivered, not discarded by a local reset).
const CLOSE_LINGER: Duration = Duration::from_millis(500);

// ------------------------------------------------------------------ codec ---

/// One datagram as a record, or `None` when it exceeds [`MAX_RECORD_PAYLOAD`].
pub fn encode_record(payload: &[u8]) -> Option<Bytes> {
    if payload.len() > MAX_RECORD_PAYLOAD {
        return None;
    }
    let mut out = BytesMut::with_capacity(RECORD_PREFIX + payload.len());
    out.put_u16(payload.len() as u16);
    out.extend_from_slice(payload);
    Some(out.freeze())
}

/// Incremental record reader for the tunnel stream (a byte stream: DATA
/// frames split and pack records freely). Keeps at most one incomplete
/// record between chunks once drained.
#[derive(Debug, Default)]
pub struct RecordDecoder {
    buf: BytesMut,
}

impl RecordDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, chunk: &[u8]) {
        self.buf.extend_from_slice(chunk);
    }

    /// The next complete record's payload (possibly empty), or `None` when
    /// more bytes are needed.
    pub fn next_record(&mut self) -> Option<Bytes> {
        if self.buf.len() < RECORD_PREFIX {
            return None;
        }
        let len = u16::from_be_bytes([self.buf[0], self.buf[1]]) as usize;
        if self.buf.len() < RECORD_PREFIX + len {
            return None;
        }
        self.buf.advance(RECORD_PREFIX);
        Some(self.buf.split_to(len).freeze())
    }

    /// Bytes buffered for an incomplete record: a truncated tail if the
    /// stream ends now (it is discarded, never delivered as a datagram).
    pub fn pending(&self) -> usize {
        self.buf.len()
    }
}

// ------------------------------------------------------------------ tunnel ---

/// A fully prepared UDP exchange through an HBONE endpoint.
#[derive(Clone)]
pub struct HboneUdpPlan {
    /// The UDP destination (the `CONNECT` authority).
    pub host: String,
    pub port: u16,
    /// The HBONE endpoint; its `connect_headers` carry the `udp` marker.
    pub proxy: ProxyPlan,
    pub dns: DnsConfig,
    pub timeouts: Timeouts,
    pub datagrams: Vec<Bytes>,
    /// How long to wait for responses after the last datagram is sent.
    pub response_window_ms: u64,
    /// Stop receiving after this many datagrams.
    pub max_datagrams: u32,
    pub display_url: String,
    pub transcript: TranscriptLimits,
    pub redact: Option<RedactFn>,
}

/// An open datagram tunnel: the `CONNECT` stream's halves and the HTTP/2
/// connection that carries it.
pub struct DatagramTunnel {
    tx: h2::SendStream<Bytes>,
    rx: h2::RecvStream,
    sender: h2::client::SendRequest<Bytes>,
    conn: tokio::task::JoinHandle<()>,
    stats: Arc<ConnStats>,
}

fn datagram_leg_failure(mut t: TunnelObservation, f: TransportFailure) -> (TransportFailure, TunnelObservation) {
    t.datagrams = Some(HboneDatagramChannel::new());
    (f, t)
}

/// Open the datagram tunnel to `host:port` through the HBONE endpoint `p`
/// (whose `connect_headers` carry the `udp` marker). The outer phases go to
/// the tunnel observation, on the clock of `rec`.
pub async fn open(
    rec: &Recorder,
    p: &ProxyPlan,
    host: &str,
    port: u16,
    dns_cfg: &DnsConfig,
    timeouts: &Timeouts,
) -> Result<(DatagramTunnel, TunnelObservation), (TransportFailure, TunnelObservation)> {
    let Leg { mut sub, mut t, stream, stats, authority } = match hbone::endpoint_leg(rec, p, host, port, dns_cfg, timeouts).await {
        Ok(l) => l,
        Err((f, t)) => return Err(datagram_leg_failure(t, f)),
    };
    t.datagrams = Some(HboneDatagramChannel::new());
    let endpoint = &p.label;
    macro_rules! bail {
        ($attempt:expr, $inner:expr) => {{
            let attempt: TransportFailure = $attempt;
            let inner: TransportFailure = $inner;
            return Err(hbone::leg_failure(sub, t, attempt, inner));
        }};
    }
    let deadline = hbone::ms(timeouts.connect_ms);

    // ---- HTTP/2 preface (driven with h2 directly) ----
    let h2_idx = sub.start(Phase::ProtocolHandshake);
    let mut builder = h2::client::Builder::new();
    builder
        .initial_window_size(2 * 1024 * 1024)
        .initial_connection_window_size(5 * 1024 * 1024)
        .max_header_list_size(64 * 1024)
        .max_send_buffer_size(1024 * 1024)
        .enable_push(false);
    let handshake = builder.handshake::<_, Bytes>(stream);
    let handshake = match deadline {
        Some(d) => tokio::time::timeout(d, handshake).await.map_err(|_| d),
        None => Ok(handshake.await),
    };
    let (sender, conn) = match handshake {
        Ok(Ok(x)) => x,
        Ok(Err(e)) => {
            let mut f = classify_h2(&e, HyperStage::Handshake);
            let kind = if hbone::tls_tap(&mut f, &stats) { FailureKind::HboneEndpointTlsFailed } else { FailureKind::HboneProtocolError };
            let a = hbone::outer_failure(kind, &f, format!("the HTTP/2 connection to the HBONE endpoint {endpoint} failed: {}", f.message));
            bail!(a, f)
        }
        Err(d) => {
            let f = TransportFailure::new(
                Phase::ProtocolHandshake,
                FailureKind::HboneProtocolError,
                format!("the HTTP/2 preface with the HBONE endpoint did not complete within {} ms", d.as_millis()),
            )
            .with_deadline(Some(d.as_millis() as u64));
            let a = hbone::outer_failure(FailureKind::HboneProtocolError, &f, f.message.clone());
            bail!(a, f)
        }
    };
    let conn = tokio::spawn(async move {
        let _ = conn.await;
    });
    sub.finish_with(h2_idx, PhaseStatus::Completed, "HTTP/2 connection preface");

    // ---- CONNECT with the udp marker ----
    let c_idx = sub.start(Phase::ProxyTunnel);
    let mut req = match Request::builder().method(Method::CONNECT).uri(authority.as_str()).body(()) {
        Ok(r) => r,
        Err(e) => {
            conn.abort();
            let f = TransportFailure::new(
                Phase::Prepare,
                FailureKind::InvalidUrl,
                format!("'{authority}' is not a valid CONNECT authority: {e}"),
            )
            .with_field("url");
            sub.finish(c_idx, PhaseStatus::NotApplicable);
            bail!(f.clone(), f)
        }
    };
    for (n, v) in &p.connect_headers {
        req.headers_mut().append(n.clone(), v.clone());
    }
    let exchange = async {
        let mut ready = sender.clone().ready().await?;
        let (response, tx) = ready.send_request(req, false)?;
        Ok::<_, h2::Error>((response.await?, tx))
    };
    let answered = match deadline {
        Some(d) => tokio::time::timeout(d, exchange).await.map_err(|_| d),
        None => Ok(exchange.await),
    };
    let (resp, mut tx) = match answered {
        Ok(Ok(x)) => x,
        Ok(Err(e)) => {
            let mut f = classify_h2(&e, HyperStage::AwaitHeaders);
            f.phase = Phase::ProxyTunnel;
            let kind = if hbone::tls_tap(&mut f, &stats) { FailureKind::HboneEndpointTlsFailed } else { FailureKind::HboneProtocolError };
            let a = hbone::outer_failure(
                kind,
                &f,
                format!(
                    "the HBONE endpoint {endpoint} did not answer the datagram CONNECT to {authority}: {}; the destination was not contacted",
                    f.message
                ),
            );
            bail!(a, f)
        }
        Err(d) => {
            let f = TransportFailure::new(
                Phase::ProxyTunnel,
                FailureKind::HboneProtocolError,
                format!("the HBONE endpoint did not answer the datagram CONNECT to {authority} within {} ms", d.as_millis()),
            )
            .with_deadline(Some(d.as_millis() as u64));
            let a = hbone::outer_failure(FailureKind::HboneProtocolError, &f, f.message.clone());
            bail!(a, f)
        }
    };
    let status = resp.status().as_u16();
    t.connect_status = Some(status);
    t.response_headers = header_entries(resp.headers());
    let mut rx = resp.into_body();

    if !(200..300).contains(&status) {
        // Keep the refusal (status + bounded body) as evidence; no record was sent.
        let idle = Duration::from_millis(timeouts.body_idle_ms.unwrap_or(5_000).min(5_000));
        let mut captured = BytesMut::new();
        let mut truncated = false;
        loop {
            match tokio::time::timeout(idle, rx.data()).await {
                Ok(Some(Ok(d))) => {
                    let _ = rx.flow_control().release_capacity(d.len());
                    let room = hbone::MAX_REFUSAL_BODY.saturating_sub(captured.len());
                    if d.len() > room {
                        truncated = true;
                    }
                    captured.extend_from_slice(&d[..d.len().min(room)]);
                    if truncated {
                        break;
                    }
                }
                Ok(None) => break,
                Ok(Some(Err(_))) | Err(_) => {
                    truncated = true;
                    break;
                }
            }
        }
        tx.send_reset(h2::Reason::CANCEL);
        drop((tx, rx, sender));
        if !captured.is_empty() {
            t.refusal_body = Some(String::from_utf8_lossy(&captured).into_owned());
        }
        t.refusal_body_truncated = truncated;
        let mut f = TransportFailure::new(
            Phase::ProxyTunnel,
            FailureKind::HboneConnectRefused,
            format!(
                "the HBONE endpoint {endpoint} refused the datagram CONNECT to {authority} with HTTP {status}; no tunnel was opened and no datagram was sent"
            ),
        );
        f.status = Some(status);
        sub.finish_with(c_idx, PhaseStatus::Failed, format!("CONNECT {authority} → {status}"));
        t.phases = std::mem::take(&mut sub.phases);
        t.failure = Some(f.clone());
        return Err((f, t));
    }
    sub.finish_with(c_idx, PhaseStatus::Completed, format!("CONNECT {authority} → {status} (datagram tunnel)"));
    t.phases = std::mem::take(&mut sub.phases);
    Ok((DatagramTunnel { tx, rx, sender, conn, stats }, t))
}

/// Write one record, waiting for HTTP/2 send capacity (a record may span
/// DATA frames). `Err` names why the stream no longer takes data.
async fn write_record(tx: &mut h2::SendStream<Bytes>, mut record: Bytes) -> Result<(), String> {
    while !record.is_empty() {
        tx.reserve_capacity(record.len());
        match std::future::poll_fn(|cx| tx.poll_capacity(cx)).await {
            Some(Ok(0)) => tokio::task::yield_now().await,
            Some(Ok(n)) => {
                let chunk = record.split_to(n.min(record.len()));
                tx.send_data(chunk, false).map_err(|e| format!("the tunnel stream no longer accepts data ({e})"))?;
            }
            Some(Err(e)) => return Err(format!("the tunnel stream no longer accepts data ({e})")),
            None => return Err("the tunnel stream is closed for sending".into()),
        }
    }
    Ok(())
}

/// Datagram accounting shared by scripted and interactive sends.
struct Channel {
    tx: h2::SendStream<Bytes>,
    tr: Transcript,
    facts: HboneDatagramChannel,
    /// Why the stream stopped accepting records (the endpoint closed or
    /// reset it); later datagrams are recorded as not sent.
    send_closed: Option<String>,
}

impl Channel {
    /// Frame and write one datagram. A datagram over the record limit is
    /// refused and recorded; nothing is counted that the stream did not take.
    async fn send(&mut self, payload: &[u8]) {
        let Some(record) = encode_record(payload) else {
            self.facts.oversize_refused += 1;
            self.tr.note(
                "not_sent",
                &format!(
                    "a {}-byte datagram exceeds the {MAX_RECORD_PAYLOAD} bytes one HBONE datagram record can carry; it was refused locally and not sent",
                    payload.len()
                ),
            );
            return;
        };
        if let Some(why) = &self.send_closed {
            self.tr.note("not_sent", &format!("a {}-byte datagram was not sent: {why}", payload.len()));
            return;
        }
        match write_record(&mut self.tx, record).await {
            Ok(()) => {
                self.facts.records_sent += 1;
                self.tr.data(Direction::Sent, "datagram", payload);
            }
            Err(why) => {
                self.tr.note("not_sent", &format!("a {}-byte datagram was not sent: {why}", payload.len()));
                self.send_closed = Some(why);
            }
        }
    }
}

async fn next_cmd(rx: &mut Option<CommandRx>) -> Option<SessionCommand> {
    match rx {
        Some(r) => r.recv().await,
        None => std::future::pending().await,
    }
}

fn reason_name(code: u32) -> String {
    format!("{:?}", h2::Reason::from(code))
}

pub async fn run(plan: &HboneUdpPlan, events: &EventCtx, cancel: &CancellationToken, mut commands: Option<CommandRx>) -> SessionOutput {
    let interactive = commands.is_some();
    let mut rec = Recorder::new(0, events.clone());
    events.emit(ExecutionEvent::AttemptStarted { execution_id: events.execution_id, attempt: 0 });
    let mut obs = new_attempt(0, AttemptReason::Initial, "UDP", &plan.display_url);
    let mut facts = SessionFacts::default();
    let total_deadline = if interactive { None } else { deadline_from(plan.timeouts.total_ms) };
    let udp_status = |sent: u64, received: u64| ProtocolStatus::Udp {
        datagrams_sent: sent,
        datagrams_received: received,
        window_ms: plan.response_window_ms,
        masque: None,
    };
    let mut cobs = connector::blank_observation(connector::next_connection_id());
    cobs.protocol = Some("udp".into());
    cobs.via_proxy = Some(plan.proxy.label.clone());

    // ---- the tunnel (the whole outer leg is one proxy_tunnel phase) ----
    rec.mark(Phase::Dns, PhaseStatus::NotApplicable, Some("the HBONE endpoint resolves the destination (outer DNS: tunnel evidence)"));
    rec.mark(
        Phase::Connect,
        PhaseStatus::NotApplicable,
        Some("UDP is connectionless; the HBONE endpoint opens the UDP socket toward the destination (outer TCP: tunnel evidence)"),
    );
    let idx = rec.start(Phase::ProxyTunnel);
    let opened = tokio::select! {
        r = open(&rec, &plan.proxy, &plan.host, plan.port, &plan.dns, &plan.timeouts) => Ok(r),
        _ = sleep_until_opt(total_deadline) => Err(TransportFailure::new(Phase::ProxyTunnel, FailureKind::TotalTimeout,
            "the total deadline elapsed while opening the HBONE datagram tunnel").with_deadline(plan.timeouts.total_ms)),
        _ = cancel.cancelled() => Err(TransportFailure::new(Phase::ProxyTunnel, FailureKind::Canceled,
            "canceled while opening the HBONE datagram tunnel")),
    };
    let (tunnel, t) = match opened {
        Ok(Ok(x)) => x,
        Ok(Err((f, t))) => {
            let timed_out = t.failure.as_ref().is_some_and(|i| i.deadline_ms.is_some());
            rec.finish_with(
                idx,
                if timed_out { PhaseStatus::TimedOut } else { PhaseStatus::Failed },
                format!("HBONE datagram tunnel via {}", plan.proxy.label),
            );
            cobs.tunnel = Some(t);
            obs.connection = Some(cobs);
            return SessionOutput::single(fail_attempt(rec, obs, f, DispatchState::NotDispatched, events), None, udp_status(0, 0), facts);
        }
        Err(f) => {
            rec.finish(idx, phase_status_for(f.kind));
            let mut t = hbone::blank(&plan.proxy, &hbone::authority(&plan.host, plan.port));
            t.datagrams = Some(HboneDatagramChannel::new());
            t.failure = Some(f.clone());
            cobs.tunnel = Some(t);
            obs.connection = Some(cobs);
            return SessionOutput::single(fail_attempt(rec, obs, f, DispatchState::NotDispatched, events), None, udp_status(0, 0), facts);
        }
    };
    let status = t.connect_status.unwrap_or(200);
    let authority = t.authority.clone();
    let marker = t
        .connect_headers
        .iter()
        .find(|h| h.name == "x-ferrum-mesh-protocol" || h.name == "x-istio-protocol")
        .map(|h| format!("{}: {}", h.name, h.value))
        .unwrap_or_else(|| "no protocol marker".into());
    rec.finish_with(
        idx,
        PhaseStatus::Completed,
        format!("HBONE datagram tunnel via {} (CONNECT {authority} → {status}, {marker})", plan.proxy.label),
    );
    cobs.tunnel = Some(t);
    obs.connection = Some(cobs);
    facts.notes.push(format!(
        "UDP to {authority} through the HBONE endpoint {}: CONNECT with {marker}; each datagram is one [u16 length][payload] record on the CONNECT stream",
        plan.proxy.label
    ));

    let DatagramTunnel { tx, mut rx, sender, conn, stats } = tunnel;
    let (written_before, read_before) = (stats.bytes_written(), stats.bytes_read());
    let tr = Transcript::new(rec.t0, plan.transcript, events.clone(), plan.redact.clone());
    let mut ch = Channel { tx, tr, facts: HboneDatagramChannel::new(), send_closed: None };
    ch.tr.note("tunnel", &format!("HBONE datagram tunnel to {authority} open through {} (HTTP {status}; {marker})", plan.proxy.label));
    let s_idx = rec.start(Phase::Session);
    let mut received = 0u64;
    let mut failure: Option<TransportFailure> = None;
    let mut seen: HashSet<[u8; 32]> = HashSet::new();
    let mut decoder = RecordDecoder::new();
    let mut stream_open = true;

    for d in &plan.datagrams {
        tokio::select! {
            _ = ch.send(d) => {}
            _ = sleep_until_opt(total_deadline) => {
                failure = Some(TransportFailure::new(Phase::Session, FailureKind::TotalTimeout,
                    "the total deadline elapsed while sending datagrams into the HBONE tunnel").with_deadline(plan.timeouts.total_ms));
                ch.facts.closed_by = ClosedBy::Timeout;
                break;
            }
            _ = cancel.cancelled() => {
                failure = Some(TransportFailure::new(Phase::Session, FailureKind::Canceled, "the UDP exchange through the HBONE tunnel was canceled"));
                ch.facts.closed_by = ClosedBy::Client;
                break;
            }
        }
    }

    let window = Duration::from_millis(plan.response_window_ms);
    let mut window_end = Instant::now() + window;
    enum Ev {
        Data(Option<Result<Bytes, h2::Error>>),
        Cmd(Option<SessionCommand>),
        WindowEnd,
        Deadline,
        Canceled,
    }
    'session: while failure.is_none() {
        let window_deadline = if interactive { None } else { Some(window_end) };
        let ev = tokio::select! {
            d = rx.data(), if stream_open => Ev::Data(d),
            c = next_cmd(&mut commands), if interactive => Ev::Cmd(c),
            _ = sleep_until_opt(window_deadline) => Ev::WindowEnd,
            _ = sleep_until_opt(total_deadline) => Ev::Deadline,
            _ = cancel.cancelled() => Ev::Canceled,
        };
        match ev {
            Ev::Data(Some(Ok(chunk))) => {
                let _ = rx.flow_control().release_capacity(chunk.len());
                decoder.push(&chunk);
                while let Some(p) = decoder.next_record() {
                    received += 1;
                    ch.facts.records_received += 1;
                    let mut digest = [0u8; 32];
                    digest.copy_from_slice(&Sha256::digest(&p));
                    if !seen.insert(digest) {
                        facts.repeated_datagrams += 1;
                    }
                    ch.tr.data(Direction::Received, "datagram", &p);
                    if received >= plan.max_datagrams as u64 {
                        ch.tr.note("note", &format!("stopped receiving at max_datagrams ({})", plan.max_datagrams));
                        ch.facts.closed_by = ClosedBy::Client;
                        break 'session;
                    }
                }
            }
            Ev::Data(None) => {
                stream_open = false;
                let tail = decoder.pending();
                if tail > 0 {
                    ch.facts.truncated_tail_bytes = tail as u64;
                    ch.facts.closed_by = ClosedBy::Abnormal;
                    ch.tr.note(
                        "tunnel_closed",
                        &format!("the HBONE endpoint ended the tunnel inside a datagram record; {tail} byte(s) of the incomplete record were discarded"),
                    );
                    failure = Some(TransportFailure::new(
                        Phase::Session,
                        FailureKind::BodyIncomplete,
                        format!(
                            "the HBONE endpoint ended the datagram tunnel inside a record: {tail} byte(s) of an incomplete [u16 length][payload] record were discarded"
                        ),
                    ));
                } else {
                    ch.facts.closed_by = ClosedBy::Peer;
                    ch.tr.note("tunnel_closed", "the HBONE endpoint ended the datagram tunnel (END_STREAM on the CONNECT stream)");
                }
                break 'session;
            }
            Ev::Data(Some(Err(e))) => {
                stream_open = false;
                let mut f = classify_h2(&e, HyperStage::Body);
                f.phase = Phase::Session;
                if hbone::tls_tap(&mut f, &stats) {
                    f.phase = Phase::Session;
                }
                let how = match f.h2_error_code {
                    Some(c) if e.is_reset() => format!("the HBONE endpoint reset the tunnel stream (RST_STREAM {})", reason_name(c)),
                    Some(c) => format!("the HTTP/2 connection to the HBONE endpoint ended (GOAWAY {})", reason_name(c)),
                    None => format!("the connection to the HBONE endpoint was lost: {}", f.message),
                };
                ch.facts.reset_code = f.h2_error_code.map(reason_name);
                ch.facts.closed_by = ClosedBy::Abnormal;
                ch.tr.note("tunnel_closed", &how);
                f.message = format!("the datagram tunnel ended abnormally: {how}");
                failure = Some(f);
            }
            Ev::Cmd(c) => match c {
                Some(SessionCommand::SendText { text }) => {
                    ch.send(text.as_bytes()).await;
                    window_end = Instant::now() + window;
                }
                Some(SessionCommand::SendBinaryHex { hex }) => match decode_hex(&hex) {
                    Ok(b) => {
                        ch.send(&b).await;
                        window_end = Instant::now() + window;
                    }
                    Err(e) => ch.tr.note("error", &format!("datagram not sent: {e}")),
                },
                Some(SessionCommand::Ping) | Some(SessionCommand::HalfClose) => {
                    ch.tr.note("unsupported_command", "UDP has no ping or half-close; send a datagram or Close")
                }
                Some(SessionCommand::Close { .. }) | None => {
                    ch.facts.closed_by = ClosedBy::Client;
                    break 'session;
                }
            },
            Ev::WindowEnd => {
                ch.facts.closed_by = ClosedBy::Client;
                break 'session;
            }
            Ev::Deadline => {
                failure = Some(
                    TransportFailure::new(Phase::Session, FailureKind::TotalTimeout, "the total deadline elapsed during the UDP exchange")
                        .with_deadline(plan.timeouts.total_ms),
                );
                ch.facts.closed_by = ClosedBy::Timeout;
            }
            Ev::Canceled => {
                failure = Some(TransportFailure::new(Phase::Session, FailureKind::Canceled, "the UDP exchange was canceled"));
                ch.facts.closed_by = ClosedBy::Client;
            }
        }
    }

    // ---- end of the tunnel ----
    let Channel { mut tx, tr, facts: channel, send_closed } = ch;
    let aborted = matches!(failure.as_ref().map(|f| f.kind), Some(FailureKind::Canceled | FailureKind::TotalTimeout));
    if aborted {
        tx.send_reset(h2::Reason::CANCEL);
    } else if send_closed.is_none() && tx.send_data(Bytes::new(), true).is_ok() && stream_open {
        // Anvil's own clean end: wait briefly for the endpoint to end its
        // side, so the END_STREAM is delivered rather than discarded by the
        // reset h2 sends when a half-open stream is dropped. Nothing read
        // now is counted: the session is over.
        let _ = tokio::time::timeout(CLOSE_LINGER, async {
            while let Some(Ok(d)) = rx.data().await {
                let _ = rx.flow_control().release_capacity(d.len());
            }
        })
        .await;
    }
    let (written_after, read_after) = (stats.bytes_written(), stats.bytes_read());
    // Dropping the last handles lets h2 send GOAWAY and close the connection.
    drop((tx, rx, sender));
    let mut conn = conn;
    if tokio::time::timeout(CLOSE_LINGER, &mut conn).await.is_err() {
        conn.abort();
    }
    let sent = channel.records_sent;
    if facts.repeated_datagrams > 0 {
        facts.notes.push(format!(
            "{} received datagram(s) were byte-identical to an earlier received datagram (UDP may duplicate datagrams; the peer may also send identical replies)",
            facts.repeated_datagrams
        ));
    }
    if channel.oversize_refused > 0 {
        facts.notes.push(format!(
            "{} datagram(s) over {MAX_RECORD_PAYLOAD} bytes were refused locally and not sent (one HBONE datagram record carries at most {MAX_RECORD_PAYLOAD} bytes)",
            channel.oversize_refused
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
    obs.bytes.connection_bytes_written = Some(written_after.saturating_sub(written_before));
    obs.bytes.connection_bytes_read = Some(read_after.saturating_sub(read_before));
    if let Some(t) = obs.connection.as_mut().and_then(|c| c.tunnel.as_mut()) {
        t.datagrams = Some(channel);
    }
    let obs = finish_attempt(rec, obs, events);
    SessionOutput::single(
        AttemptOutput { observation: obs, response: None, body: Bytes::new() },
        Some(tr.finish()),
        udp_status(sent, received),
        facts,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wire(datagrams: &[&[u8]]) -> BytesMut {
        let mut w = BytesMut::new();
        for d in datagrams {
            w.extend_from_slice(&encode_record(d).unwrap());
        }
        w
    }

    fn decode_in(parts: &[&[u8]]) -> (Vec<Bytes>, usize) {
        let mut d = RecordDecoder::new();
        let mut out = vec![];
        for p in parts {
            d.push(p);
            while let Some(r) = d.next_record() {
                out.push(r);
            }
        }
        (out, d.pending())
    }

    #[test]
    fn records_are_a_big_endian_u16_length_then_the_payload() {
        assert_eq!(&encode_record(b"hi").unwrap()[..], &[0x00, 0x02, b'h', b'i']);
        assert_eq!(&encode_record(b"").unwrap()[..], &[0x00, 0x00], "a zero-length datagram is a bare prefix");
        let max = encode_record(&vec![7u8; MAX_RECORD_PAYLOAD]).unwrap();
        assert_eq!(&max[..2], &[0xff, 0xff]);
        assert_eq!(max.len(), RECORD_PREFIX + MAX_RECORD_PAYLOAD);
        assert!(encode_record(&vec![0u8; MAX_RECORD_PAYLOAD + 1]).is_none(), "one byte over the u16 limit is refused");
    }

    #[test]
    fn every_two_way_split_decodes_the_same_records() {
        let datagrams: [&[u8]; 5] = [b"one", b"", &[0xab; 300], b"x", b""];
        let w = wire(&datagrams);
        for split in 0..=w.len() {
            let (out, pending) = decode_in(&[&w[..split], &w[split..]]);
            assert_eq!(
                out.iter().map(|b| b.to_vec()).collect::<Vec<_>>(),
                datagrams.iter().map(|d| d.to_vec()).collect::<Vec<_>>(),
                "split at {split}"
            );
            assert_eq!(pending, 0, "split at {split}");
        }
    }

    #[test]
    fn every_three_way_split_and_byte_by_byte_feeding_decode_the_same_records() {
        let datagrams: [&[u8]; 4] = [b"alpha", b"", b"gamma-delta", &[0u8; 1]];
        let w = wire(&datagrams);
        let expected: Vec<Vec<u8>> = datagrams.iter().map(|d| d.to_vec()).collect();
        for a in 0..=w.len() {
            for b in a..=w.len() {
                let (out, pending) = decode_in(&[&w[..a], &w[a..b], &w[b..]]);
                assert_eq!(out.iter().map(|x| x.to_vec()).collect::<Vec<_>>(), expected, "splits at {a}/{b}");
                assert_eq!(pending, 0);
            }
        }
        let bytes: Vec<&[u8]> = w.chunks(1).collect();
        let (out, _) = decode_in(&bytes);
        assert_eq!(out.len(), expected.len());
    }

    #[test]
    fn a_maximal_record_survives_any_chunking() {
        let big: Vec<u8> = (0..MAX_RECORD_PAYLOAD).map(|i| (i % 251) as u8).collect();
        let w = wire(&[&big, b"after"]);
        for chunk in [1usize, 2, 3, 16 * 1024, 65_537, w.len()] {
            let parts: Vec<&[u8]> = w.chunks(chunk).collect();
            let (out, pending) = decode_in(&parts);
            assert_eq!(out.len(), 2, "chunk {chunk}");
            assert_eq!(&out[0][..], &big[..]);
            assert_eq!(&out[1][..], b"after");
            assert_eq!(pending, 0);
        }
    }

    #[test]
    fn several_records_in_one_chunk_including_empty_ones() {
        let w = wire(&[b"", b"a", b"", b"bc"]);
        let (out, pending) = decode_in(&[&w]);
        assert_eq!(out, vec![Bytes::new(), Bytes::from_static(b"a"), Bytes::new(), Bytes::from_static(b"bc")]);
        assert_eq!(pending, 0);
    }

    #[test]
    fn a_truncated_tail_is_pending_and_never_delivered() {
        // A whole record, then a prefix claiming 16 bytes with only 4 present.
        let mut w = wire(&[b"whole"]);
        w.extend_from_slice(&[0x00, 0x10, 1, 2, 3, 4]);
        let (out, pending) = decode_in(&[&w]);
        assert_eq!(out, vec![Bytes::from_static(b"whole")]);
        assert_eq!(pending, 6, "prefix and partial payload are the truncated tail");
        // Half a length prefix.
        let (out, pending) = decode_in(&[&[0x00]]);
        assert!(out.is_empty());
        assert_eq!(pending, 1);
    }
}
