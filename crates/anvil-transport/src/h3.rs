//! HTTP/3 over QUIC (quinn + h3) with measured QUIC phases.
//!
//! There is no TCP phase on this path: DNS then QUIC handshake (which
//! includes TLS 1.3). Forced HTTP/3 never sends over TCP; the engine records
//! any fallback as a separate attempt.
//!
//! 0-RTT early data (only with the early-data opt-in, see
//! [`EarlyDataIntent`]): a new connection resumes a session ticket from the
//! [`TicketCache`]; when the ticket allows early data, `Connecting::into_0rtt`
//! hands over the connection before the handshake completes, HTTP/3 is set up
//! and the request is written as 0-RTT data, and the handshake outcome says
//! whether the server accepted it. A rejected request was discarded by the
//! server unread, so it is written once more on the established connection
//! (recorded as `resent_after_handshake`, never as an application retry).

use crate::dns;
use crate::errors::display_chain;
use crate::http::{AttemptOutput, EarlyDataIntent, HttpPlan, sleep_until_opt};
use crate::recorder::{EventCtx, Recorder};
use crate::tickets::{HandshakeGuard, ResumptionContext, TicketCache, TicketTransport};
use crate::tls;
use anvil_domain::events::ExecutionEvent;
use anvil_domain::execution::*;
use bytes::{Buf, Bytes, BytesMut};
use chrono::Utc;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

pub(crate) type SendReq = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;

#[derive(Clone)]
struct H3Conn {
    send: SendReq,
    quic: quinn::Connection,
    template: ConnectionObservation,
    served: Arc<std::sync::atomic::AtomicU32>,
}

pub struct H3Transport {
    endpoints: Mutex<HashMap<bool, quinn::Endpoint>>,
    pool: Mutex<HashMap<String, H3Conn>>,
    /// QUIC session tickets for 0-RTT (used only under the early-data opt-in).
    pub tickets: TicketCache,
    /// The connection that answered `425 Too Early`, kept (even with
    /// connection reuse off) for the one retry the engine sends on it after
    /// the handshake (RFC 8470 §5.2).
    too_early: Mutex<HashMap<String, H3Conn>>,
}

impl Default for H3Transport {
    fn default() -> Self {
        Self::new()
    }
}

pub(crate) fn quic_failure(e: &quinn::ConnectionError, during_handshake: bool, deadline: Option<u64>) -> TransportFailure {
    use quinn::ConnectionError as C;
    let phase = if during_handshake { Phase::QuicHandshake } else { Phase::AwaitResponseHeaders };
    let mut f = TransportFailure::new(phase, FailureKind::QuicOther, display_chain(e));
    match e {
        C::TimedOut => {
            f.kind = if during_handshake { FailureKind::QuicHandshakeTimeout } else { FailureKind::QuicIdleTimeout };
            f.deadline_ms = deadline;
        }
        C::TransportError(te) => {
            let code = u64::from(te.code);
            f.quic_error_code = Some(code);
            // CRYPTO_ERROR range carries the TLS alert (RFC 9001 §4.8).
            if (0x100..=0x1ff).contains(&code) {
                let alert = rustls::AlertDescription::from((code - 0x100) as u8);
                let (k, name) = crate::errors::classify_rustls(&rustls::Error::AlertReceived(alert), !during_handshake);
                f.kind = k;
                f.tls_alert = name;
            } else {
                f.kind = FailureKind::QuicTransportError;
            }
        }
        C::ConnectionClosed(c) => {
            let code = u64::from(c.error_code);
            f.quic_error_code = Some(code);
            if (0x100..=0x1ff).contains(&code) {
                let alert = rustls::AlertDescription::from((code - 0x100) as u8);
                let (k, name) = crate::errors::classify_rustls(&rustls::Error::AlertReceived(alert), !during_handshake);
                f.kind = k;
                f.tls_alert = name;
            } else {
                f.kind = FailureKind::QuicTransportError;
            }
        }
        C::ApplicationClosed(a) => {
            f.kind = FailureKind::QuicApplicationClosed;
            f.quic_error_code = Some(u64::from(a.error_code));
        }
        _ => {}
    }
    f
}

/// A typed failure for an h3 stream error, keeping the peer's HTTP/3
/// application error code (e.g. `H3_INTERNAL_ERROR` on a reset) as evidence.
pub(crate) fn stream_failure(e: &h3::error::StreamError, phase: Phase, kind: FailureKind, what: &str) -> TransportFailure {
    use h3::error::StreamError as S;
    let mut f = TransportFailure::new(phase, kind, format!("{what}: {e}"));
    match e {
        S::RemoteTerminate { code } | S::StreamError { code, .. } => f.quic_error_code = Some(code.value()),
        _ => {}
    }
    f
}

/// `H3_NO_ERROR` (RFC 9114 §8.1): the code Anvil closes its QUIC connections with.
pub(crate) const H3_NO_ERROR: u32 = 0x100;

/// A fresh client-side QUIC endpoint (one UDP socket).
pub(crate) fn client_endpoint(v6: bool) -> Result<quinn::Endpoint, TransportFailure> {
    let bind: SocketAddr = if v6 { "[::]:0".parse().unwrap() } else { "0.0.0.0:0".parse().unwrap() };
    quinn::Endpoint::client(bind).map_err(|e| {
        TransportFailure::new(Phase::Prepare, FailureKind::AddressUnavailable, format!("could not open a UDP socket for QUIC: {e}"))
    })
}

/// A QUIC connection with HTTP/3 set up on it (driver already running).
pub(crate) struct QuicConnected {
    pub quic: quinn::Connection,
    pub send: SendReq,
    pub observation: ConnectionObservation,
}

/// HTTP/3 client options beyond the defaults.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct H3ClientOptions {
    /// Advertise `SETTINGS_H3_DATAGRAM = 1` (RFC 9297 §2.1.1), so the peer
    /// may send HTTP/3 datagrams in QUIC DATAGRAM frames. quinn advertises
    /// the QUIC `max_datagram_frame_size` transport parameter by default.
    pub h3_datagrams: bool,
}

/// What the peer's HTTP/3 SETTINGS frame allows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PeerSettings {
    /// `SETTINGS_ENABLE_CONNECT_PROTOCOL` (RFC 9220 §3).
    pub extended_connect: bool,
    /// `SETTINGS_H3_DATAGRAM` (RFC 9297 §2.1.1).
    pub h3_datagram: bool,
}

/// Wait up to `ms` for the peer's SETTINGS frame. `Err("timeout")` when it
/// did not arrive in time (nothing can be concluded), `Err("canceled")` on
/// cancel.
pub(crate) async fn await_peer_settings(send: &SendReq, ms: u64, cancel: &CancellationToken) -> Result<PeerSettings, &'static str> {
    use h3::ConnectionState;
    let deadline = Instant::now() + Duration::from_millis(ms);
    loop {
        // Borrowed once the peer's SETTINGS frame has arrived; before that h3
        // hands out RFC 9114 defaults, which say nothing about the peer.
        if let std::borrow::Cow::Borrowed(s) = send.settings() {
            return Ok(PeerSettings { extended_connect: s.enable_extended_connect(), h3_datagram: s.enable_datagram() });
        }
        if Instant::now() >= deadline {
            return Err("timeout");
        }
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(5)) => {}
            _ = cancel.cancelled() => return Err("canceled"),
        }
    }
}

/// DNS, QUIC handshake (TLS 1.3 inside) and HTTP/3 connection setup, each
/// recorded as a phase. There is no TCP phase. On failure the connection
/// observation gathered so far (resolution, TLS evidence) is returned when
/// there is any.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn quic_connect(
    rec: &mut Recorder,
    host: &str,
    port: u16,
    dns_cfg: &dns::DnsConfig,
    timeouts: &anvil_domain::settings::Timeouts,
    prepared: &Arc<tls::PreparedTls>,
    endpoint: impl FnOnce(bool) -> Result<quinn::Endpoint, TransportFailure>,
    cancel: &CancellationToken,
) -> Result<QuicConnected, (TransportFailure, Option<ConnectionObservation>)> {
    quic_connect_with(rec, host, port, dns_cfg, timeouts, prepared, endpoint, cancel, H3ClientOptions::default()).await
}

/// [`quic_connect`] with explicit HTTP/3 client options.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn quic_connect_with(
    rec: &mut Recorder,
    host: &str,
    port: u16,
    dns_cfg: &dns::DnsConfig,
    timeouts: &anvil_domain::settings::Timeouts,
    prepared: &Arc<tls::PreparedTls>,
    endpoint: impl FnOnce(bool) -> Result<quinn::Endpoint, TransportFailure>,
    cancel: &CancellationToken,
    options: H3ClientOptions,
) -> Result<QuicConnected, (TransportFailure, Option<ConnectionObservation>)> {
    let mut cobs = crate::connector::blank_observation(crate::connector::next_connection_id());
    rec.mark(Phase::Connect, PhaseStatus::NotApplicable, Some("QUIC has no TCP connect"));
    let dns_idx = rec.start(Phase::Dns);
    let res = match dns::resolve(host, port, dns_cfg, timeouts.dns_ms.map(Duration::from_millis)).await {
        Ok(r) => r,
        Err(f) => {
            rec.finish(dns_idx, PhaseStatus::Failed);
            return Err((f, Some(cobs)));
        }
    };
    if res.source == "literal" || res.source == "override" {
        rec.phases[dns_idx].status = PhaseStatus::NotApplicable;
        rec.phases[dns_idx].start_us = None;
    } else {
        rec.finish(dns_idx, PhaseStatus::Completed);
    }
    cobs.resolved_addresses = res.addrs.iter().map(|a| a.to_string()).collect();
    cobs.resolution_source = Some(res.source.to_string());
    let addr = res.addrs[0];
    cobs.remote_address = Some(addr.to_string());
    let (cfg, sn, handle) = tls::client_config_observed(prepared, host, &["h3"], true).map_err(|f| (f, None))?;
    let quic_cfg = quinn::crypto::rustls::QuicClientConfig::try_from(cfg).map_err(|e| {
        (TransportFailure::new(Phase::Prepare, FailureKind::TlsProfileInvalid, format!("TLS profile cannot be used for QUIC: {e}")), None)
    })?;
    let mut client_cfg = quinn::ClientConfig::new(Arc::new(quic_cfg));
    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Some(Duration::from_secs(10)));
    if let Ok(idle) = quinn::IdleTimeout::try_from(Duration::from_secs(30)) {
        transport.max_idle_timeout(Some(idle));
    }
    client_cfg.transport_config(Arc::new(transport));
    let ep = endpoint(addr.is_ipv6()).map_err(|f| (f, None))?;
    let sni = match &sn {
        rustls_pki_types::ServerName::DnsName(d) => d.as_ref().to_string(),
        _ => host.to_string(),
    };
    let hs_idx = rec.start(Phase::QuicHandshake);
    let connecting = match ep.connect_with(client_cfg, addr, &sni) {
        Ok(c) => c,
        Err(e) => {
            rec.finish(hs_idx, PhaseStatus::Failed);
            let f = TransportFailure::new(Phase::QuicHandshake, FailureKind::QuicOther, format!("QUIC connect could not start: {e}"));
            return Err((f, None));
        }
    };
    let hs_deadline = timeouts.tls_handshake_ms.or(timeouts.connect_ms);
    let result = tokio::select! {
        r = connecting => r.map_err(|e| quic_failure(&e, true, hs_deadline)),
        _ = sleep_until_opt(hs_deadline.map(|ms| Instant::now() + Duration::from_millis(ms))) => Err(
            TransportFailure::new(Phase::QuicHandshake, FailureKind::QuicHandshakeTimeout,
                format!("no QUIC handshake completed within {} ms (UDP may be blocked, or the server does not serve HTTP/3 here)", hs_deadline.unwrap_or(0)))
            .with_deadline(hs_deadline)),
        _ = cancel.cancelled() => Err(TransportFailure::new(Phase::QuicHandshake, FailureKind::Canceled, "canceled during QUIC handshake")),
    };
    let quic = match result {
        Ok(c) => c,
        Err(mut f) => {
            rec.finish(hs_idx, if f.kind == FailureKind::QuicHandshakeTimeout { PhaseStatus::TimedOut } else { PhaseStatus::Failed });
            let tls_obs = tls::observe(&handle, prepared, false);
            if let TlsVerification::Failed { problem, .. } = &tls_obs.verification {
                f.kind = *problem;
            }
            cobs.tls = Some(tls_obs);
            return Err((f, Some(cobs)));
        }
    };
    rec.finish(hs_idx, PhaseStatus::Completed);
    let mut tls_obs = tls::observe(&handle, prepared, true);
    tls_obs.version = Some("TLSv1_3".into());
    tls_obs.alpn_negotiated = quic
        .handshake_data()
        .and_then(|d| d.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
        .and_then(|d| d.protocol.map(|p| String::from_utf8_lossy(&p).into_owned()));
    cobs.tls = Some(tls_obs);
    cobs.protocol = Some("h3".into());
    cobs.local_address = ep.local_addr().ok().map(|a| a.to_string());
    let ph = rec.start(Phase::ProtocolHandshake);
    let built = h3::client::builder().enable_datagram(options.h3_datagrams).build(h3_quinn::Connection::new(quic.clone())).await;
    let (mut driver, send) = match built {
        Ok(x) => x,
        Err(e) => {
            rec.finish(ph, PhaseStatus::Failed);
            let f = TransportFailure::new(Phase::ProtocolHandshake, FailureKind::QuicOther, format!("HTTP/3 connection setup failed: {e}"));
            return Err((f, Some(cobs)));
        }
    };
    rec.finish(ph, PhaseStatus::Completed);
    tokio::spawn(async move {
        let _ = futures::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });
    Ok(QuicConnected { quic, send, observation: cobs })
}

/// A QUIC connection whose request may still be early data.
enum Fresh {
    /// The handshake completed before any request byte was written.
    Established(Box<(H3Conn, EarlyTrack)>),
    /// 0-RTT: HTTP/3 is set up on the resumed connection and the handshake
    /// is still in flight.
    ZeroRtt(Box<ZeroRttConn>),
}

struct ZeroRttConn {
    quic: quinn::Connection,
    send: SendReq,
    driver: h3::client::Connection<h3_quinn::Connection, Bytes>,
    accepted: quinn::ZeroRttAccepted,
    cobs: ConnectionObservation,
    handle: tls::ObservationHandle,
    guard: HandshakeGuard,
    hs_idx: usize,
    hs_deadline: Option<Instant>,
    track: EarlyTrack,
}

/// Early-data evidence being gathered for one attempt.
struct EarlyTrack {
    obs: EarlyDataObservation,
    /// The context's ticket counter when the attempt began (tickets that
    /// arrive after it are counted for this attempt).
    tickets: Option<(Arc<ResumptionContext>, u32)>,
}

impl EarlyTrack {
    fn new(intent: EarlyDataIntent) -> Self {
        EarlyTrack { obs: crate::http::early_observation(intent, EarlyDataTransport::Quic), tickets: None }
    }

    fn finish(mut self) -> EarlyDataObservation {
        if let Some((ctx, before)) = &self.tickets {
            let n = ctx.store.received().saturating_sub(*before);
            self.obs.tickets_received = n;
            self.obs.ticket_max_early_data = if n > 0 { ctx.store.newest_max_early() } else { None };
        }
        self.obs
    }
}

/// What an HTTP/3 request stream costs as early data before QPACK: the
/// pseudo-headers and fields as `name: value` lines (an estimate; QPACK
/// usually compresses them).
fn logical_header_bytes(plan: &HttpPlan, uri: &str) -> u64 {
    let pseudo = plan.method.as_str().len() + uri.len() + 30;
    let fields: usize = plan.headers.iter().map(|(n, v)| n.as_str().len() + v.len() + 4).sum();
    (pseudo + fields) as u64
}

fn build_request(plan: &HttpPlan) -> Result<(http::Request<()>, String), TransportFailure> {
    let explicit_host = plan.headers.iter().find(|(n, _)| n == http::header::HOST).map(|(_, v)| v.to_str().unwrap_or("").to_string());
    let uri = format!("https://{}{}", explicit_host.unwrap_or_else(|| plan.authority.clone()), plan.request_target);
    let mut req = http::Request::builder().method(plan.method.clone()).uri(uri.clone());
    for (n, v) in &plan.headers {
        if n == http::header::HOST
            || n == http::header::CONNECTION
            || n == http::header::TRANSFER_ENCODING
            || n == http::header::UPGRADE
            || n.as_str() == "keep-alive"
        {
            continue;
        }
        req = req.header(n, v);
    }
    req.body(())
        .map(|r| (r, uri))
        .map_err(|e| TransportFailure::new(Phase::Prepare, FailureKind::InvalidHeader, format!("request could not be built: {e}")))
}

type ClientStream = h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

/// A 0-RTT handshake in flight, checked inline (no task hop) right before
/// each request write: bytes handed to QUIC before quinn reported the
/// handshake complete travelled as 0-RTT early data. `done_at` is when Anvil
/// first saw completion (the handshake phase's end).
struct HandshakeWatch {
    fut: quinn::ZeroRttAccepted,
    result: Option<bool>,
    done_at: Option<Instant>,
    early_bytes: u64,
}

impl HandshakeWatch {
    fn new(fut: quinn::ZeroRttAccepted) -> Self {
        HandshakeWatch { fut, result: None, done_at: None, early_bytes: 0 }
    }

    fn done(&mut self) -> bool {
        use futures::FutureExt;
        if self.result.is_none()
            && let Some(r) = (&mut self.fut).now_or_never()
        {
            self.result = Some(r);
            self.done_at = Some(Instant::now());
        }
        self.result.is_some()
    }

    fn count(&mut self, n: u64) {
        if !self.done() {
            self.early_bytes += n;
        }
    }

    /// The handshake outcome: `true` when the server accepted the early data.
    async fn wait(&mut self) -> bool {
        if let Some(r) = self.result {
            return r;
        }
        let r = (&mut self.fut).await;
        self.result = Some(r);
        self.done_at = Some(Instant::now());
        r
    }
}

/// Whether a stream error says the stream was opened in 0-RTT that the
/// server rejected (quinn's typed `ZeroRttRejected`, carried through h3).
fn is_zero_rtt_rejected(e: &h3::error::StreamError) -> bool {
    match e {
        h3::error::StreamError::Undefined(inner) => {
            matches!(inner.downcast_ref::<quinn::ReadError>(), Some(quinn::ReadError::ZeroRttRejected))
                || matches!(inner.downcast_ref::<quinn::WriteError>(), Some(quinn::WriteError::ZeroRttRejected))
        }
        _ => false,
    }
}

/// What writing a request produced: its stream once the HEADERS went out,
/// and the send-side error that stopped the body or the FIN, if any. A
/// server may answer and stop reading before the whole request arrived, so a
/// write error does not always mean there is no response.
struct Written {
    stream: Option<ClientStream>,
    error: Option<h3::error::StreamError>,
}

/// Write the request (headers, body in 64 KiB DATA frames, FIN), counting
/// early bytes when `early` is given.
async fn write_request(
    send: &SendReq,
    plan: &HttpPlan,
    req: http::Request<()>,
    header_bytes: u64,
    mut early: Option<&mut HandshakeWatch>,
) -> Written {
    let mut send = send.clone();
    if let Some(w) = early.as_deref_mut() {
        w.count(header_bytes);
    }
    let mut stream = match send.send_request(req).await {
        Ok(s) => s,
        Err(e) => return Written { stream: None, error: Some(e) },
    };
    let mut body = plan.body.clone();
    while !body.is_empty() {
        let chunk = body.split_to(body.len().min(64 * 1024));
        if let Some(w) = early.as_deref_mut() {
            w.count(chunk.len() as u64);
        }
        if let Err(e) = stream.send_data(chunk).await {
            return Written { stream: Some(stream), error: Some(e) };
        }
    }
    let error = stream.finish().await.err();
    Written { stream: Some(stream), error }
}

fn phase_status(kind: FailureKind) -> PhaseStatus {
    match kind {
        FailureKind::Canceled => PhaseStatus::Canceled,
        FailureKind::QuicHandshakeTimeout
        | FailureKind::TotalTimeout
        | FailureKind::ResponseHeadersTimeout
        | FailureKind::BodyIdleTimeout
        | FailureKind::DnsTimeout => PhaseStatus::TimedOut,
        _ => PhaseStatus::Failed,
    }
}

fn fail_attempt(
    mut rec: Recorder,
    mut obs: AttemptObservation,
    f: TransportFailure,
    dispatch: DispatchState,
    track: Option<EarlyTrack>,
    events: &EventCtx,
) -> AttemptOutput {
    rec.close_open(phase_status(f.kind));
    events.emit(ExecutionEvent::AttemptFailed { execution_id: events.execution_id, attempt: obs.index, kind: f.kind });
    obs.duration_us = rec.us();
    obs.phases = std::mem::take(&mut rec.phases);
    obs.dispatch = dispatch;
    obs.failure = Some(f);
    if let Some(t) = track {
        obs.early_data = Some(t.finish());
    }
    AttemptOutput { observation: obs, response: None, body: Bytes::new() }
}

/// DNS for a QUIC destination (there is no TCP connect phase).
async fn resolve_quic(
    rec: &mut Recorder,
    host: &str,
    port: u16,
    dns_cfg: &dns::DnsConfig,
    timeouts: &anvil_domain::settings::Timeouts,
    cobs: &mut ConnectionObservation,
) -> Result<SocketAddr, TransportFailure> {
    rec.mark(Phase::Connect, PhaseStatus::NotApplicable, Some("QUIC has no TCP connect"));
    let dns_idx = rec.start(Phase::Dns);
    let res = match dns::resolve(host, port, dns_cfg, timeouts.dns_ms.map(Duration::from_millis)).await {
        Ok(r) => r,
        Err(f) => {
            rec.finish(dns_idx, PhaseStatus::Failed);
            return Err(f);
        }
    };
    if res.source == "literal" || res.source == "override" {
        rec.phases[dns_idx].status = PhaseStatus::NotApplicable;
        rec.phases[dns_idx].start_us = None;
    } else {
        rec.finish(dns_idx, PhaseStatus::Completed);
    }
    cobs.resolved_addresses = res.addrs.iter().map(|a| a.to_string()).collect();
    cobs.resolution_source = Some(res.source.to_string());
    let addr = res.addrs[0];
    cobs.remote_address = Some(addr.to_string());
    Ok(addr)
}

fn client_transport() -> Arc<quinn::TransportConfig> {
    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Some(Duration::from_secs(10)));
    if let Ok(idle) = quinn::IdleTimeout::try_from(Duration::from_secs(30)) {
        transport.max_idle_timeout(Some(idle));
    }
    Arc::new(transport)
}

fn negotiated_alpn(quic: &quinn::Connection) -> Option<String> {
    quic.handshake_data()
        .and_then(|d| d.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
        .and_then(|d| d.protocol.map(|p| String::from_utf8_lossy(&p).into_owned()))
}

/// TLS evidence once a resumable connection's handshake completed: resumed
/// when a ticket was offered and the verifier saw no certificate.
fn resumable_tls(
    quic: &quinn::Connection,
    handle: &tls::ObservationHandle,
    prepared: &tls::PreparedTls,
    ticket_offered: bool,
) -> (TlsObservation, bool) {
    let alpn = negotiated_alpn(quic);
    let resumed = ticket_offered && !handle.certificate_seen();
    if resumed {
        let chain: Vec<rustls_pki_types::CertificateDer<'static>> = quic
            .peer_identity()
            .and_then(|p| p.downcast::<Vec<rustls_pki_types::CertificateDer<'static>>>().ok())
            .map(|b| *b)
            .unwrap_or_default();
        (tls::resumed_observation(handle, prepared, &chain, Some("TLSv1_3".into()), None, alpn), true)
    } else {
        let mut o = tls::observe(handle, prepared, true);
        o.version = Some("TLSv1_3".into());
        o.alpn_negotiated = alpn;
        o.resumed = Some(false);
        (o, false)
    }
}

async fn h3_setup(
    rec: &mut Recorder,
    quic: &quinn::Connection,
    detail: Option<&str>,
) -> Result<(h3::client::Connection<h3_quinn::Connection, Bytes>, SendReq), TransportFailure> {
    let ph = rec.start(Phase::ProtocolHandshake);
    match h3::client::builder().build(h3_quinn::Connection::new(quic.clone())).await {
        Ok(x) => {
            match detail {
                Some(d) => rec.finish_with(ph, PhaseStatus::Completed, d),
                None => rec.finish(ph, PhaseStatus::Completed),
            }
            Ok(x)
        }
        Err(e) => {
            rec.finish(ph, PhaseStatus::Failed);
            Err(TransportFailure::new(Phase::ProtocolHandshake, FailureKind::QuicOther, format!("HTTP/3 connection setup failed: {e}")))
        }
    }
}

fn spawn_driver(mut driver: h3::client::Connection<h3_quinn::Connection, Bytes>) {
    tokio::spawn(async move {
        let _ = futures::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });
}

impl H3Transport {
    pub fn new() -> Self {
        H3Transport {
            endpoints: Mutex::new(HashMap::new()),
            pool: Mutex::new(HashMap::new()),
            tickets: TicketCache::new(),
            too_early: Mutex::new(HashMap::new()),
        }
    }

    /// Drop pooled connections and every session ticket.
    pub fn clear(&self) {
        self.pool.lock().clear();
        self.too_early.lock().clear();
        self.tickets.clear();
    }

    /// Drop the pooled connections and session tickets of one isolation.
    pub fn clear_isolation(&self, isolation: &str) {
        let prefix = format!("{isolation}|");
        self.pool.lock().retain(|k, _| !k.starts_with(&prefix));
        self.too_early.lock().retain(|k, _| !k.starts_with(&prefix));
        self.tickets.clear_isolation(isolation);
    }

    fn endpoint(&self, v6: bool) -> Result<quinn::Endpoint, TransportFailure> {
        let mut eps = self.endpoints.lock();
        if let Some(e) = eps.get(&v6) {
            return Ok(e.clone());
        }
        let ep = client_endpoint(v6)?;
        eps.insert(v6, ep.clone());
        Ok(ep)
    }

    /// A new QUIC connection through the session-ticket cache: resumes a
    /// ticket when one exists and, for [`EarlyDataIntent::Send`], returns
    /// before the handshake completes when the ticket allows 0-RTT.
    async fn connect_resumable(
        &self,
        rec: &mut Recorder,
        plan: &HttpPlan,
        prepared: &Arc<tls::PreparedTls>,
        cancel: &CancellationToken,
    ) -> Result<Fresh, (TransportFailure, Option<ConnectionObservation>, EarlyTrack)> {
        let intent = plan.early_data;
        let mut track = EarlyTrack::new(intent);
        let mut cobs = crate::connector::blank_observation(crate::connector::next_connection_id());
        let addr = match resolve_quic(rec, &plan.host, plan.port, &plan.dns, &plan.timeouts, &mut cobs).await {
            Ok(a) => a,
            Err(f) => return Err((f, Some(cobs), track)),
        };
        let ctx = self.tickets.context(&plan.isolation, TicketTransport::Quic, &plan.host, plan.port, prepared, &["h3"]);
        track.tickets = Some((ctx.clone(), ctx.store.received()));
        let (sn, handle) = match tls::routed_handle(prepared, &plan.host, &["h3"]) {
            Ok(x) => x,
            Err(f) => return Err((f, None, track)),
        };
        let hs_ms = plan.timeouts.tls_handshake_ms.or(plan.timeouts.connect_ms);
        let hs_deadline = hs_ms.map(|ms| Instant::now() + Duration::from_millis(ms));
        // Handshakes of one ticket context are serialized so the shared
        // verifier's evidence belongs to this connection.
        let q = rec.start(Phase::Queue);
        let guard = tokio::select! {
            g = ctx.begin(&handle) => g,
            _ = sleep_until_opt(hs_deadline) => {
                rec.finish_with(q, PhaseStatus::TimedOut, "waiting for another handshake of the same session-ticket context");
                let f = TransportFailure::new(Phase::Queue, FailureKind::QuicHandshakeTimeout, "another handshake to this server with the same TLS profile did not finish before the handshake deadline").with_deadline(hs_ms);
                return Err((f, Some(cobs), track));
            }
            _ = cancel.cancelled() => {
                rec.finish(q, PhaseStatus::Canceled);
                return Err((TransportFailure::new(Phase::Queue, FailureKind::Canceled, "canceled before the QUIC handshake"), Some(cobs), track));
            }
        };
        rec.finish(q, PhaseStatus::Completed);
        let want_early = intent == EarlyDataIntent::Send;
        let cfg = match ctx.config(prepared, &["h3"], true, want_early) {
            Ok(c) => c,
            Err(f) => return Err((f, None, track)),
        };
        let quic_cfg = match quinn::crypto::rustls::QuicClientConfig::try_from(cfg) {
            Ok(c) => c,
            Err(e) => {
                let f = TransportFailure::new(
                    Phase::Prepare,
                    FailureKind::TlsProfileInvalid,
                    format!("TLS profile cannot be used for QUIC: {e}"),
                );
                return Err((f, None, track));
            }
        };
        let mut client_cfg = quinn::ClientConfig::new(Arc::new(quic_cfg));
        client_cfg.transport_config(client_transport());
        let ep = match self.endpoint(addr.is_ipv6()) {
            Ok(e) => e,
            Err(f) => return Err((f, None, track)),
        };
        let sni = match &sn {
            rustls_pki_types::ServerName::DnsName(d) => d.as_ref().to_string(),
            _ => plan.host.clone(),
        };
        let hs_idx = rec.start(Phase::QuicHandshake);
        let connecting = match ep.connect_with(client_cfg, addr, &sni) {
            Ok(c) => c,
            Err(e) => {
                rec.finish(hs_idx, PhaseStatus::Failed);
                let f = TransportFailure::new(Phase::QuicHandshake, FailureKind::QuicOther, format!("QUIC connect could not start: {e}"));
                return Err((f, None, track));
            }
        };
        cobs.local_address = ep.local_addr().ok().map(|a| a.to_string());
        // The ClientHello was built by `connect_with`: the store knows whether
        // it took a ticket, and what that ticket allows.
        let taken = ctx.store.taken();
        let connecting = if want_early {
            match connecting.into_0rtt() {
                Ok((quic, accepted)) => {
                    track.obs.resumption_attempted = true;
                    track.obs.offered = true;
                    track.obs.not_used = None;
                    cobs.protocol = Some("h3".into());
                    let (driver, send) = match h3_setup(rec, &quic, Some("HTTP/3 set up in 0-RTT (before the handshake completed)")).await {
                        Ok(x) => x,
                        Err(f) => {
                            quic.close(H3_NO_ERROR.into(), b"");
                            return Err((f, Some(cobs), track));
                        }
                    };
                    return Ok(Fresh::ZeroRtt(Box::new(ZeroRttConn {
                        quic,
                        send,
                        driver,
                        accepted,
                        cobs,
                        handle,
                        guard,
                        hs_idx,
                        hs_deadline,
                        track,
                    })));
                }
                Err(c) => {
                    // No usable early-data ticket: a ticket that allows early
                    // data but produced no 0-RTT keys had expired.
                    track.obs.not_used = Some(match taken {
                        Some(0) => EarlyDataNotUsed::TicketWithoutEarlyData,
                        _ => EarlyDataNotUsed::NoTicket,
                    });
                    c
                }
            }
        } else {
            connecting
        };
        let ticket_offered = matches!(taken, Some(0)) || (taken.is_some() && !want_early);
        track.obs.resumption_attempted = ticket_offered;
        let result = tokio::select! {
            r = connecting => r.map_err(|e| quic_failure(&e, true, hs_ms)),
            _ = sleep_until_opt(hs_deadline) => Err(
                TransportFailure::new(Phase::QuicHandshake, FailureKind::QuicHandshakeTimeout,
                    format!("no QUIC handshake completed within {} ms (UDP may be blocked, or the server does not serve HTTP/3 here)", hs_ms.unwrap_or(0)))
                .with_deadline(hs_ms)),
            _ = cancel.cancelled() => Err(TransportFailure::new(Phase::QuicHandshake, FailureKind::Canceled, "canceled during QUIC handshake")),
        };
        let quic = match result {
            Ok(c) => c,
            Err(mut f) => {
                rec.finish(hs_idx, phase_status(f.kind));
                let tls_obs = tls::observe(&handle, prepared, false);
                if let TlsVerification::Failed { problem, .. } = &tls_obs.verification {
                    f.kind = *problem;
                }
                cobs.tls = Some(tls_obs);
                drop(guard);
                return Err((f, Some(cobs), track));
            }
        };
        let (tls_obs, resumed) = resumable_tls(&quic, &handle, prepared, ticket_offered);
        drop(guard);
        rec.finish_with(hs_idx, PhaseStatus::Completed, if resumed { "resumed session (TLS 1.3 PSK)" } else { "full handshake" });
        if ticket_offered {
            track.obs.resumption_accepted = Some(resumed);
        }
        cobs.tls = Some(tls_obs);
        cobs.protocol = Some("h3".into());
        let (driver, send) = match h3_setup(rec, &quic, None).await {
            Ok(x) => x,
            Err(f) => return Err((f, Some(cobs), track)),
        };
        spawn_driver(driver);
        Ok(Fresh::Established(Box::new((
            H3Conn { send, quic, template: cobs, served: Arc::new(std::sync::atomic::AtomicU32::new(0)) },
            track,
        ))))
    }

    pub async fn execute(
        &self,
        plan: &HttpPlan,
        index: u32,
        reason: AttemptReason,
        events: &EventCtx,
        cancel: &CancellationToken,
    ) -> AttemptOutput {
        let mut rec = Recorder::new(index, events.clone());
        events.emit(ExecutionEvent::AttemptStarted { execution_id: events.execution_id, attempt: index });
        let mut obs = AttemptObservation {
            early_data: None,
            index,
            reason,
            method: plan.method.to_string(),
            url: plan.display_url.clone(),
            started_at: Utc::now(),
            connection: None,
            phases: vec![],
            dispatch: DispatchState::NotDispatched,
            bytes: ByteCounts { request_body: plan.body.len() as u64, request_headers_estimated: true, ..Default::default() },
            response_status: None,
            failure: None,
            duration_us: 0,
        };
        let early_on = plan.early_data != EarlyDataIntent::Off;
        let local_track = || early_on.then(|| EarlyTrack::new(plan.early_data));
        if !plan.https {
            let f = TransportFailure::new(Phase::Prepare, FailureKind::UnsupportedCombination, "HTTP/3 requires an https:// URL")
                .with_field("settings.http_version");
            return fail_attempt(rec, obs, f, DispatchState::NotDispatched, None, events);
        }
        if plan.proxy.is_some() {
            let f = TransportFailure::new(
                Phase::Prepare,
                FailureKind::UnsupportedCombination,
                "HTTP/3 cannot be sent through the configured proxy (HTTP CONNECT, SOCKS5 and HBONE tunnels carry TCP only)",
            )
            .with_field("settings.proxy");
            return fail_attempt(rec, obs, f, DispatchState::NotDispatched, None, events);
        }
        let Some(prepared) = plan.tls.clone() else {
            let f = TransportFailure::new(Phase::Prepare, FailureKind::TlsProfileInvalid, "no TLS configuration for HTTP/3");
            return fail_attempt(rec, obs, f, DispatchState::NotDispatched, None, events);
        };
        let (req, uri) = match build_request(plan) {
            Ok(r) => r,
            Err(f) => return fail_attempt(rec, obs, f, DispatchState::NotDispatched, None, events),
        };
        let header_bytes = logical_header_bytes(plan, &uri);
        obs.bytes.request_headers_logical = header_bytes;
        let total_deadline = plan.timeouts.total_ms.map(|ms| Instant::now() + Duration::from_millis(ms));
        let key = format!("{}|h3://{}:{}|{}", plan.isolation, plan.host.to_ascii_lowercase(), plan.port, prepared.fingerprint);

        // The retry after `425 Too Early` goes out on the connection that
        // answered it, whose handshake is complete.
        let handed = match plan.early_data {
            EarlyDataIntent::Hold(EarlyDataNotUsed::RetryAfterTooEarly) => {
                self.too_early.lock().remove(&key).filter(|c| c.quic.close_reason().is_none())
            }
            _ => None,
        };
        let pooled = handed.or_else(|| {
            if plan.keepalive {
                let p = self.pool.lock().get(&key).cloned();
                p.filter(|c| c.quic.close_reason().is_none())
            } else {
                None
            }
        });
        let mut track: Option<EarlyTrack> = None;
        let (conn, reused, zero) = match pooled {
            Some(c) => {
                rec.mark(Phase::Dns, PhaseStatus::Reused, Some("pooled QUIC connection"));
                rec.mark(Phase::QuicHandshake, PhaseStatus::Reused, Some("pooled QUIC connection"));
                track = local_track().map(|mut t| {
                    if t.obs.not_used.is_none() {
                        t.obs.not_used = Some(EarlyDataNotUsed::ConnectionReused);
                    }
                    t
                });
                (Some(c), true, None)
            }
            None if early_on => match self.connect_resumable(&mut rec, plan, &prepared, cancel).await {
                Ok(Fresh::Established(b)) => {
                    let (c, t) = *b;
                    track = Some(t);
                    if plan.keepalive {
                        self.pool.lock().insert(key.clone(), c.clone());
                    }
                    (Some(c), false, None)
                }
                Ok(Fresh::ZeroRtt(z)) => (None, false, Some(z)),
                Err((f, cobs, t)) => {
                    obs.connection = cobs;
                    return fail_attempt(rec, obs, f, DispatchState::NotDispatched, Some(t), events);
                }
            },
            None => {
                let connected = match quic_connect(
                    &mut rec,
                    &plan.host,
                    plan.port,
                    &plan.dns,
                    &plan.timeouts,
                    &prepared,
                    |v6| self.endpoint(v6),
                    cancel,
                )
                .await
                {
                    Ok(c) => c,
                    Err((f, cobs)) => {
                        obs.connection = cobs;
                        return fail_attempt(rec, obs, f, DispatchState::NotDispatched, None, events);
                    }
                };
                let QuicConnected { quic, send, observation: cobs, .. } = connected;
                let c = H3Conn { send, quic, template: cobs, served: Arc::new(std::sync::atomic::AtomicU32::new(0)) };
                if plan.keepalive {
                    self.pool.lock().insert(key.clone(), c.clone());
                }
                (Some(c), false, None)
            }
        };

        // ---- 0-RTT: write the request as early data, then learn whether the server took it ----
        let mut head: Option<http::Response<()>> = None;
        let mut poolable = true;
        let (conn, stream) = if let Some(z) = zero {
            let ZeroRttConn { quic, send, driver, accepted, mut cobs, handle, guard, hs_idx, hs_deadline, track: mut track_z } = *z;
            let mut watch = HandshakeWatch::new(accepted);
            let w_idx = rec.start(Phase::RequestWrite);
            let write_deadline = plan.timeouts.request_write_ms.map(|ms| Instant::now() + Duration::from_millis(ms));
            let sent = tokio::select! {
                w = write_request(&send, plan, req, header_bytes, Some(&mut watch)) => Ok(w),
                _ = sleep_until_opt(write_deadline) => Err(TransportFailure::new(Phase::RequestWrite, FailureKind::RequestWriteTimeout, "the HTTP/3 request could not be sent before the write deadline").with_deadline(plan.timeouts.request_write_ms)),
                _ = cancel.cancelled() => Err(TransportFailure::new(Phase::RequestWrite, FailureKind::Canceled, "canceled while sending")),
            };
            // Early data covers the request only when its HEADERS went out
            // before the handshake completed; on a fast path (loopback) the
            // handshake can win the race against HTTP/3 setup.
            let in_early_data = watch.early_bytes > 0;
            if in_early_data {
                track_z.obs.bytes = watch.early_bytes;
                track_z.obs.bytes_estimated = true;
            } else {
                track_z.obs.offered = false;
                track_z.obs.not_used = Some(EarlyDataNotUsed::HandshakeCompletedFirst);
            }
            let written = match sent {
                Ok(w) => w,
                Err(f) => {
                    quic.close(H3_NO_ERROR.into(), b"");
                    obs.connection = Some(cobs);
                    return fail_attempt(rec, obs, f, DispatchState::MayHaveBeenSent, Some(track_z), events);
                }
            };
            let write_detail = match (&written.error, in_early_data) {
                (None, true) => "written as 0-RTT early data".to_string(),
                (None, false) => "written after the handshake completed (it finished before HTTP/3 was set up)".to_string(),
                (Some(e), _) => format!("the write stopped: {e}"),
            };
            rec.finish_with(w_idx, if written.error.is_none() { PhaseStatus::Completed } else { PhaseStatus::Unknown }, write_detail);
            let hs_ms = plan.timeouts.tls_handshake_ms.or(plan.timeouts.connect_ms);
            let accepted = tokio::select! {
                a = watch.wait() => a,
                _ = sleep_until_opt(hs_deadline) => {
                    quic.close(H3_NO_ERROR.into(), b"");
                    obs.connection = Some(cobs);
                    let f = TransportFailure::new(Phase::QuicHandshake, FailureKind::QuicHandshakeTimeout,
                        format!("the QUIC handshake did not complete within {} ms after the request was sent as 0-RTT early data", hs_ms.unwrap_or(0))).with_deadline(hs_ms);
                    return fail_attempt(rec, obs, f, DispatchState::MayHaveBeenSent, Some(track_z), events);
                }
                _ = cancel.cancelled() => {
                    quic.close(H3_NO_ERROR.into(), b"");
                    obs.connection = Some(cobs);
                    let f = TransportFailure::new(Phase::QuicHandshake, FailureKind::Canceled, "canceled during the QUIC handshake (the request was already sent as 0-RTT early data)");
                    return fail_attempt(rec, obs, f, DispatchState::MayHaveBeenSent, Some(track_z), events);
                }
            };
            // The handshake phase ends when Anvil first saw completion.
            let done_at = watch.done_at;
            let close_hs = |rec: &mut Recorder, status: PhaseStatus, detail: &str| {
                rec.finish_with(hs_idx, status, detail);
                if let Some(at) = done_at {
                    rec.phases[hs_idx].end_us = Some(rec.us_at(at));
                }
            };
            if let Some(reason) = quic.close_reason() {
                close_hs(&mut rec, PhaseStatus::Failed, "the handshake failed after the request was written");
                let mut f = quic_failure(&reason, true, hs_ms);
                let tls_obs = tls::observe(&handle, &prepared, false);
                if let TlsVerification::Failed { problem, .. } = &tls_obs.verification {
                    f.kind = *problem;
                }
                cobs.tls = Some(tls_obs);
                obs.connection = Some(cobs);
                drop(guard);
                // The server may have acted on the early data before the
                // handshake failed.
                return fail_attempt(rec, obs, f, DispatchState::MayHaveBeenSent, Some(track_z), events);
            }
            let (tls_obs, resumed) = resumable_tls(&quic, &handle, &prepared, true);
            drop(guard);
            track_z.obs.resumption_accepted = Some(resumed);
            if in_early_data {
                track_z.obs.accepted = Some(accepted);
            }
            cobs.tls = Some(tls_obs);
            close_hs(
                &mut rec,
                PhaseStatus::Completed,
                match (accepted, resumed) {
                    (true, _) => "resumed session; 0-RTT early data accepted",
                    (false, true) => "resumed session; 0-RTT early data rejected by the server",
                    (false, false) => "full handshake; 0-RTT early data rejected by the server",
                },
            );
            // After a rejection, a request stream opened in 0-RTT fails at
            // once with quinn's typed ZeroRttRejected (the server discarded
            // it unread); one opened after the handshake completed is live and
            // must not be sent twice.
            let mut written = written;
            let rejected_copy = if accepted {
                false
            } else {
                match written.stream.as_mut() {
                    None => written.error.as_ref().is_some_and(is_zero_rtt_rejected),
                    Some(s) => {
                        use futures::FutureExt;
                        match s.recv_response().now_or_never() {
                            Some(Err(e)) if is_zero_rtt_rejected(&e) => true,
                            Some(Err(e)) => {
                                obs.connection = Some(cobs);
                                let f = stream_failure(
                                    &e,
                                    Phase::AwaitResponseHeaders,
                                    FailureKind::ResetBeforeResponse,
                                    "the HTTP/3 stream ended before a response",
                                );
                                return fail_attempt(rec, obs, f, DispatchState::MayHaveBeenSent, Some(track_z), events);
                            }
                            Some(Ok(h)) => {
                                head = Some(h);
                                false
                            }
                            None => false,
                        }
                    }
                }
            };
            let (send, stream) = if !rejected_copy {
                // The request reached an established stream (a stopped
                // write still leaves the response to read: a server may
                // answer, e.g. 425, and stop reading).
                let Some(s) = written.stream.take() else {
                    quic.close(H3_NO_ERROR.into(), b"");
                    obs.connection = Some(cobs);
                    let f = TransportFailure::new(
                        Phase::RequestWrite,
                        FailureKind::RequestWriteFailed,
                        format!("sending the HTTP/3 request failed: {}", written.error.map(|e| e.to_string()).unwrap_or_default()),
                    );
                    return fail_attempt(rec, obs, f, DispatchState::MayHaveBeenSent, Some(track_z), events);
                };
                if accepted {
                    spawn_driver(driver);
                } else {
                    // Rejected, but the request went out after the handshake
                    // on a live stream: that is the only copy. This HTTP/3
                    // connection's own control streams were rejected, so it
                    // is not reused.
                    track_z.obs.offered = false;
                    track_z.obs.accepted = None;
                    track_z.obs.bytes = 0;
                    track_z.obs.bytes_estimated = false;
                    track_z.obs.not_used = Some(EarlyDataNotUsed::HandshakeCompletedFirst);
                    poolable = false;
                    drop(driver);
                }
                (send, s)
            } else {
                // The server discarded the early data unread: set HTTP/3 up
                // again on the now established connection and send the same
                // request once more. This is the transport delivering the
                // request, not an application retry.
                drop(written);
                drop(send);
                drop(driver);
                track_z.obs.resent_after_handshake = true;
                let (driver, send) = match h3_setup(&mut rec, &quic, Some("set up again after the server rejected 0-RTT")).await {
                    Ok(x) => x,
                    Err(f) => {
                        obs.connection = Some(cobs);
                        return fail_attempt(rec, obs, f, DispatchState::NotDispatched, Some(track_z), events);
                    }
                };
                spawn_driver(driver);
                let (req, _) = match build_request(plan) {
                    Ok(r) => r,
                    Err(f) => return fail_attempt(rec, obs, f, DispatchState::NotDispatched, Some(track_z), events),
                };
                let w2 = rec.start(Phase::RequestWrite);
                let sent = tokio::select! {
                    w = write_request(&send, plan, req, header_bytes, None) => w,
                    _ = sleep_until_opt(write_deadline) => {
                        obs.connection = Some(cobs);
                        let f = TransportFailure::new(Phase::RequestWrite, FailureKind::RequestWriteTimeout, "the HTTP/3 request could not be sent before the write deadline").with_deadline(plan.timeouts.request_write_ms);
                        return fail_attempt(rec, obs, f, DispatchState::MayHaveBeenSent, Some(track_z), events);
                    }
                    _ = cancel.cancelled() => {
                        obs.connection = Some(cobs);
                        let f = TransportFailure::new(Phase::RequestWrite, FailureKind::Canceled, "canceled while sending");
                        return fail_attempt(rec, obs, f, DispatchState::MayHaveBeenSent, Some(track_z), events);
                    }
                };
                match sent {
                    Written { stream: Some(s), error } => {
                        match error {
                            None => rec.finish_with(
                                w2,
                                PhaseStatus::Completed,
                                "re-sent after the handshake: the server rejected the early data",
                            ),
                            Some(e) => {
                                rec.finish_with(w2, PhaseStatus::Unknown, format!("re-sent after the handshake; the write stopped: {e}"))
                            }
                        }
                        (send, s)
                    }
                    Written { stream: None, error } => {
                        rec.finish(w2, PhaseStatus::Failed);
                        obs.connection = Some(cobs);
                        let f = TransportFailure::new(
                            Phase::RequestWrite,
                            FailureKind::RequestWriteFailed,
                            format!("sending the HTTP/3 request failed: {}", error.map(|e| e.to_string()).unwrap_or_default()),
                        );
                        return fail_attempt(rec, obs, f, DispatchState::MayHaveBeenSent, Some(track_z), events);
                    }
                }
            };
            let c = H3Conn { send, quic, template: cobs, served: Arc::new(std::sync::atomic::AtomicU32::new(0)) };
            if plan.keepalive && poolable {
                self.pool.lock().insert(key.clone(), c.clone());
            }
            track = Some(track_z);
            (c, stream)
        } else {
            let conn = conn.expect("connection or 0-RTT");
            let mut cobs = conn.template.clone();
            cobs.reused = reused;
            cobs.prior_requests = conn.served.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            obs.connection = Some(cobs);
            let w_idx = rec.start(Phase::RequestWrite);
            let write_deadline = plan.timeouts.request_write_ms.map(|ms| Instant::now() + Duration::from_millis(ms));
            let stream = tokio::select! {
                w = write_request(&conn.send, plan, req, header_bytes, None) => match w {
                    Written { stream: Some(s), error: None } => {
                        rec.finish(w_idx, PhaseStatus::Completed);
                        s
                    }
                    // The server may have answered and stopped reading.
                    Written { stream: Some(s), error: Some(e) } => {
                        rec.finish_with(w_idx, PhaseStatus::Unknown, format!("the write stopped before the whole request was sent: {e}"));
                        s
                    }
                    Written { stream: None, error } => {
                        rec.finish(w_idx, PhaseStatus::Failed);
                        self.pool.lock().remove(&key);
                        let f = TransportFailure::new(Phase::RequestWrite, FailureKind::RequestWriteFailed, format!("sending the HTTP/3 request failed: {}", error.map(|e| e.to_string()).unwrap_or_default()));
                        return fail_attempt(rec, obs, f, DispatchState::MayHaveBeenSent, track, events);
                    }
                },
                _ = sleep_until_opt(write_deadline) => {
                    let f = TransportFailure::new(Phase::RequestWrite, FailureKind::RequestWriteTimeout, "the HTTP/3 request could not be sent before the write deadline").with_deadline(plan.timeouts.request_write_ms);
                    return fail_attempt(rec, obs, f, DispatchState::MayHaveBeenSent, track, events);
                }
                _ = cancel.cancelled() => {
                    let f = TransportFailure::new(Phase::RequestWrite, FailureKind::Canceled, "canceled while sending");
                    return fail_attempt(rec, obs, f, DispatchState::MayHaveBeenSent, track, events);
                }
            };
            (conn, stream)
        };
        if obs.connection.is_none() {
            let mut cobs = conn.template.clone();
            cobs.prior_requests = conn.served.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            obs.connection = Some(cobs);
        }
        let out = self.read_response(rec, obs, stream, plan, index, events, cancel, total_deadline, track, head).await;
        // Only an eligible request is retried after 425 (the engine's rule).
        if plan.early_data == EarlyDataIntent::Send
            && out.observation.failure.is_none()
            && out.response.as_ref().map(|r| r.status) == Some(425)
        {
            self.too_early.lock().insert(key, conn);
        }
        out
    }

    #[allow(clippy::too_many_arguments)]
    async fn read_response(
        &self,
        mut rec: Recorder,
        mut obs: AttemptObservation,
        mut stream: ClientStream,
        plan: &HttpPlan,
        index: u32,
        events: &EventCtx,
        cancel: &CancellationToken,
        total_deadline: Option<Instant>,
        track: Option<EarlyTrack>,
        head: Option<http::Response<()>>,
    ) -> AttemptOutput {
        let h_idx = rec.start(Phase::AwaitResponseHeaders);
        let headers_deadline = plan.timeouts.response_headers_ms.map(|ms| Instant::now() + Duration::from_millis(ms));
        let resp = tokio::select! {
            r = async { match head { Some(h) => Ok(h), None => stream.recv_response().await } } => match r {
                Ok(r) => r,
                Err(e) => {
                    rec.finish(h_idx, PhaseStatus::Failed);
                    let f = TransportFailure::new(Phase::AwaitResponseHeaders, FailureKind::ResetBeforeResponse, format!("the HTTP/3 stream ended before a response: {e}"));
                    return fail_attempt(rec, obs, f, DispatchState::MayHaveBeenSent, track, events);
                }
            },
            _ = sleep_until_opt(headers_deadline) => {
                let f = TransportFailure::new(Phase::AwaitResponseHeaders, FailureKind::ResponseHeadersTimeout, "no HTTP/3 response headers before the response-header deadline").with_deadline(plan.timeouts.response_headers_ms);
                return fail_attempt(rec, obs, f, DispatchState::MayHaveBeenSent, track, events);
            }
            _ = sleep_until_opt(total_deadline) => {
                let f = TransportFailure::new(Phase::AwaitResponseHeaders, FailureKind::TotalTimeout, "total deadline elapsed").with_deadline(plan.timeouts.total_ms);
                return fail_attempt(rec, obs, f, DispatchState::MayHaveBeenSent, track, events);
            }
            _ = cancel.cancelled() => {
                let f = TransportFailure::new(Phase::AwaitResponseHeaders, FailureKind::Canceled, "canceled before response headers");
                return fail_attempt(rec, obs, f, DispatchState::MayHaveBeenSent, track, events);
            }
        };
        rec.finish(h_idx, PhaseStatus::Completed);
        obs.dispatch = DispatchState::Sent;
        let status = resp.status().as_u16();
        obs.response_status = Some(status);
        events.emit(ExecutionEvent::ResponseHead { execution_id: events.execution_id, attempt: index, status });
        let headers: Vec<HeaderEntry> = resp
            .headers()
            .iter()
            .map(|(n, v)| HeaderEntry { name: n.as_str().to_string(), value: String::from_utf8_lossy(v.as_bytes()).into_owned() })
            .collect();
        obs.bytes.response_headers_logical = Some(headers.iter().map(|h| (h.name.len() + h.value.len() + 4) as u64).sum());
        let content_type = resp.headers().get(http::header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).map(|s| s.to_string());
        let content_encoding = resp.headers().get(http::header::CONTENT_ENCODING).and_then(|v| v.to_str().ok()).map(|s| s.to_string());
        let declared_length =
            resp.headers().get(http::header::CONTENT_LENGTH).and_then(|v| v.to_str().ok()).and_then(|s| s.parse::<u64>().ok());

        let b_idx = rec.start(Phase::ResponseBody);
        let mut captured = BytesMut::new();
        let mut wire = 0u64;
        let mut failure = None;
        let mut completeness = BodyCompleteness::Complete;
        let idle = plan.timeouts.body_idle_ms.map(Duration::from_millis);
        loop {
            let idle_deadline = idle.map(|d| Instant::now() + d);
            tokio::select! {
                r = stream.recv_data() => match r {
                    Ok(Some(mut chunk)) => {
                        let n = chunk.remaining();
                        wire += n as u64;
                        let data = chunk.copy_to_bytes(n);
                        let room = (plan.limits.capture_bytes as usize).saturating_sub(captured.len());
                        if room > 0 {
                            captured.extend_from_slice(&data[..data.len().min(room)]);
                        }
                        if wire > plan.limits.max_response_bytes {
                            completeness = BodyCompleteness::StoppedAtLocalLimit;
                            failure = Some(TransportFailure::new(Phase::ResponseBody, FailureKind::ResponseTooLargeLocal, "stopped reading at the local max_response_bytes limit"));
                            break;
                        }
                    }
                    Ok(None) => break,
                    Err(e) => {
                        completeness = BodyCompleteness::Incomplete;
                        failure = Some(TransportFailure::new(Phase::ResponseBody, FailureKind::BodyReset, format!("the HTTP/3 response stream ended abnormally: {e}")));
                        break;
                    }
                },
                _ = sleep_until_opt(idle_deadline) => {
                    completeness = BodyCompleteness::Incomplete;
                    failure = Some(TransportFailure::new(Phase::ResponseBody, FailureKind::BodyIdleTimeout, "response body stalled").with_deadline(plan.timeouts.body_idle_ms));
                    break;
                }
                _ = cancel.cancelled() => {
                    completeness = BodyCompleteness::Canceled;
                    failure = Some(TransportFailure::new(Phase::ResponseBody, FailureKind::Canceled, "canceled while reading the body"));
                    break;
                }
            }
        }
        let mut trailers = Vec::new();
        let mut trailers_received = false;
        if failure.is_none()
            && let Ok(Some(t)) = stream.recv_trailers().await
        {
            trailers_received = true;
            trailers = t
                .iter()
                .map(|(n, v)| HeaderEntry { name: n.as_str().to_string(), value: String::from_utf8_lossy(v.as_bytes()).into_owned() })
                .collect();
        }
        if (plan.method == http::Method::HEAD || status == 204 || status == 304) && failure.is_none() {
            completeness = BodyCompleteness::NoBody;
        }
        rec.finish(b_idx, if failure.is_none() { PhaseStatus::Completed } else { PhaseStatus::Failed });
        obs.bytes.response_body_wire = Some(wire);
        obs.failure = failure;
        obs.duration_us = rec.us();
        obs.phases = std::mem::take(&mut rec.phases);
        obs.early_data = track.map(EarlyTrack::finish);
        let captured = captured.freeze();
        let response = ResponseRecord {
            status,
            reason: http::StatusCode::from_u16(status).ok().and_then(|s| s.canonical_reason().map(|r| r.to_string())),
            http_version: "HTTP/3".into(),
            headers,
            trailers,
            trailers_received,
            body: BodyCapture {
                completeness,
                wire_bytes: wire,
                declared_length,
                captured_bytes: captured.len() as u64,
                display_truncated: wire > captured.len() as u64,
                content_type,
                content_encoding,
                decoded_bytes: None,
                blob_sha256: if captured.is_empty() { None } else { Some(crate::certs::sha256_hex(&captured)) },
            },
        };
        AttemptOutput { observation: obs, response: Some(response), body: captured }
    }
}
