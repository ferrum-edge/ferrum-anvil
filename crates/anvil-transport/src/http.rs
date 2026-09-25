//! Instrumented HTTP/1.1 and HTTP/2 execution with an isolation-keyed pool.
//!
//! One call to [`HttpTransport::execute`] performs one logical attempt (plus a
//! transparent re-dispatch when hyper proves a pooled request was never
//! serialized — recorded as its own attempt). Redirects, retries and auth
//! re-signing belong to the engine.

use crate::connector::{self, BoxIo, Established, ProxyPlan, Target};
use crate::dns::DnsConfig;
use crate::errors::{HyperStage, classify_hyper};
use crate::recorder::{EventCtx, Recorder};
use crate::stats::ConnStats;
use crate::tls::PreparedTls;
use anvil_domain::events::ExecutionEvent;
use anvil_domain::execution::*;
use anvil_domain::settings::{HttpVersionPolicy, Limits, Timeouts};
use anvil_domain::tls::ProxyKind;
use bytes::{Bytes, BytesMut};
use chrono::Utc;
use http::{HeaderName, HeaderValue, Method, Request, Uri};
use http_body_util::BodyExt;
use hyper::body::{Body, Frame, Incoming, SizeHint};
use hyper::client::conn::{http1, http2};
use hyper_util::rt::{TokioExecutor, TokioIo};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::convert::Infallible;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

const CHUNK: usize = 64 * 1024;

/// Fully prepared single-attempt HTTP request (final bytes; auth already applied).
#[derive(Clone)]
pub struct HttpPlan {
    pub method: Method,
    pub https: bool,
    /// Host used for DNS and TLS SNI/verification.
    pub host: String,
    pub port: u16,
    /// Value for `Host` / `:authority` (defaults to host[:port]).
    pub authority: String,
    /// Origin-form request target (`/path?query`), sent verbatim.
    pub request_target: String,
    pub headers: Vec<(HeaderName, HeaderValue)>,
    pub body: Bytes,
    pub version: HttpVersionPolicy,
    pub timeouts: Timeouts,
    pub limits: Limits,
    pub keepalive: bool,
    pub dns: DnsConfig,
    pub proxy: Option<ProxyPlan>,
    pub tls: Option<Arc<PreparedTls>>,
    /// Workspace/security-context isolation component of the pool key.
    pub isolation: String,
    /// Redacted URL for evidence.
    pub display_url: String,
}

pub struct AttemptOutput {
    pub observation: AttemptObservation,
    pub response: Option<ResponseRecord>,
    pub body: Bytes,
}

// ------------------------------------------------------------------ body ---

struct WriteSignal {
    done: AtomicBool,
    notify: Notify,
}

/// Request body that yields 64 KiB frames and signals when the final frame
/// has been handed to the connection.
struct InstrumentedBody {
    data: Bytes,
    signal: Arc<WriteSignal>,
}

impl InstrumentedBody {
    fn new(data: Bytes) -> (Self, Arc<WriteSignal>) {
        let signal = Arc::new(WriteSignal { done: AtomicBool::new(false), notify: Notify::new() });
        if data.is_empty() {
            signal.done.store(true, Ordering::SeqCst);
        }
        (InstrumentedBody { data, signal: signal.clone() }, signal)
    }
}

impl Body for InstrumentedBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        if self.data.is_empty() {
            if !self.signal.done.swap(true, Ordering::SeqCst) {
                self.signal.notify.notify_waiters();
            }
            return Poll::Ready(None);
        }
        let n = self.data.len().min(CHUNK);
        let chunk = self.data.split_to(n);
        if self.data.is_empty() && !self.signal.done.swap(true, Ordering::SeqCst) {
            self.signal.notify.notify_waiters();
        }
        Poll::Ready(Some(Ok(Frame::data(chunk))))
    }

    fn is_end_stream(&self) -> bool {
        self.data.is_empty()
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.data.len() as u64)
    }
}

// ------------------------------------------------------------------ pool ---

#[derive(Clone)]
enum Sender {
    H1(Arc<tokio::sync::Mutex<http1::SendRequest<InstrumentedBody>>>),
    H2(http2::SendRequest<InstrumentedBody>),
}

#[derive(Clone)]
struct Pooled {
    sender: Sender,
    stats: Arc<ConnStats>,
    template: ConnectionObservation,
    served: Arc<std::sync::atomic::AtomicU32>,
    idle_since: Instant,
    closed: Arc<AtomicBool>,
}

impl Pooled {
    fn is_usable(&self) -> bool {
        if self.closed.load(Ordering::SeqCst) {
            return false;
        }
        match &self.sender {
            Sender::H1(s) => s.try_lock().map(|s| !s.is_closed() && s.is_ready()).unwrap_or(false),
            Sender::H2(s) => !s.is_closed(),
        }
    }
}

/// Connection pool keyed by isolation + destination + security context.
#[derive(Default)]
pub struct Pool {
    idle: Mutex<HashMap<String, Vec<Pooled>>>,
}

const MAX_IDLE_PER_KEY: usize = 8;
const IDLE_TTL: Duration = Duration::from_secs(90);

impl Pool {
    fn checkout(&self, key: &str) -> Option<Pooled> {
        let mut map = self.idle.lock();
        let list = map.get_mut(key)?;
        list.retain(|p| p.is_usable() && p.idle_since.elapsed() < IDLE_TTL);
        // HTTP/2 connections stay pooled and are shared (multiplexed).
        if let Some(p) = list.iter().find(|p| matches!(p.sender, Sender::H2(_))) {
            return Some(p.clone());
        }
        list.pop()
    }

    fn checkin(&self, key: &str, mut p: Pooled) {
        if matches!(p.sender, Sender::H2(_)) {
            let mut map = self.idle.lock();
            let list = map.entry(key.to_string()).or_default();
            if !list.iter().any(|x| x.template.id == p.template.id) {
                list.push(p);
            }
            return;
        }
        p.idle_since = Instant::now();
        let mut map = self.idle.lock();
        let list = map.entry(key.to_string()).or_default();
        if list.len() < MAX_IDLE_PER_KEY {
            list.push(p);
        }
    }

    fn evict(&self, key: &str, conn_id: u64) {
        let mut map = self.idle.lock();
        if let Some(list) = map.get_mut(key) {
            list.retain(|p| p.template.id != conn_id);
        }
    }

    /// Drop every pooled connection (e.g. on vault lock or workspace switch).
    pub fn clear(&self) {
        self.idle.lock().clear();
    }

    /// Drop pooled connections whose key starts with an isolation prefix.
    pub fn clear_isolation(&self, isolation: &str) {
        self.idle.lock().retain(|k, _| !k.starts_with(&format!("{isolation}|")));
    }
}

fn pool_key(plan: &HttpPlan) -> String {
    let proxy = plan.proxy.as_ref().map(|p| format!("{:?}:{}:{}", p.kind, p.host, p.port)).unwrap_or_default();
    let tls = plan.tls.as_ref().map(|t| t.fingerprint.clone()).unwrap_or_default();
    let dns = format!("{:?}{:?}{:?}", plan.dns.resolver, plan.dns.overrides, plan.dns.ip_preference);
    format!(
        "{}|{}://{}:{}|{}|{}|{:?}|{}",
        plan.isolation,
        if plan.https { "https" } else { "http" },
        plan.host.to_ascii_lowercase(),
        plan.port,
        proxy,
        tls,
        plan.version,
        crate::certs::sha256_hex(dns.as_bytes())
    )
}

// ------------------------------------------------------------- transport ---

#[derive(Default)]
pub struct HttpTransport {
    pub pool: Pool,
}

fn alpn_for(policy: HttpVersionPolicy) -> &'static [&'static str] {
    match policy {
        HttpVersionPolicy::Http1Only => &["http/1.1"],
        HttpVersionPolicy::Http2Only => &["h2"],
        _ => &["h2", "http/1.1"],
    }
}

fn is_idempotent(m: &Method) -> bool {
    matches!(*m, Method::GET | Method::HEAD | Method::OPTIONS | Method::TRACE | Method::PUT | Method::DELETE)
}

impl HttpTransport {
    pub fn new() -> Self {
        HttpTransport::default()
    }

    /// Execute one logical attempt. Returns one output, or two when a pooled
    /// connection proved (typed) that the request was never serialized and a
    /// fresh connection was used.
    pub async fn execute(
        &self,
        plan: &HttpPlan,
        index: u32,
        reason: AttemptReason,
        events: &EventCtx,
        cancel: &CancellationToken,
    ) -> Vec<AttemptOutput> {
        let key = pool_key(plan);
        let mut outputs = Vec::new();
        let mut attempt_reason = reason;
        let mut allow_pool = plan.keepalive;
        for attempt_index in index..index + 2 {
            let (out, redispatch) = self.execute_once(plan, &key, attempt_index, attempt_reason.clone(), allow_pool, events, cancel).await;
            outputs.push(out);
            if !redispatch {
                break;
            }
            attempt_reason = AttemptReason::Retry { after: FailureKind::ClosedBeforeResponse };
            allow_pool = false;
        }
        outputs
    }

    #[allow(clippy::too_many_arguments)]
    async fn execute_once(
        &self,
        plan: &HttpPlan,
        key: &str,
        index: u32,
        reason: AttemptReason,
        allow_pool: bool,
        events: &EventCtx,
        cancel: &CancellationToken,
    ) -> (AttemptOutput, bool) {
        let started_at = Utc::now();
        let mut rec = Recorder::new(index, events.clone());
        events.emit(ExecutionEvent::AttemptStarted { execution_id: events.execution_id, attempt: index });
        let total_deadline = plan.timeouts.total_ms.map(|ms| Instant::now() + Duration::from_millis(ms));
        let mut obs = AttemptObservation {
            index,
            reason,
            method: plan.method.to_string(),
            url: plan.display_url.clone(),
            started_at,
            connection: None,
            phases: vec![],
            dispatch: DispatchState::NotDispatched,
            bytes: ByteCounts { request_body: plan.body.len() as u64, ..Default::default() },
            response_status: None,
            failure: None,
            duration_us: 0,
        };

        let fail = |mut rec: Recorder, mut obs: AttemptObservation, f: TransportFailure, dispatch: DispatchState| -> AttemptOutput {
            let st = match f.kind {
                FailureKind::Canceled => PhaseStatus::Canceled,
                FailureKind::TotalTimeout
                | FailureKind::ResponseHeadersTimeout
                | FailureKind::RequestWriteTimeout
                | FailureKind::BodyIdleTimeout
                | FailureKind::ConnectTimeout
                | FailureKind::TlsHandshakeTimeout
                | FailureKind::DnsTimeout => PhaseStatus::TimedOut,
                _ => PhaseStatus::Failed,
            };
            rec.close_open(st);
            events.emit(ExecutionEvent::AttemptFailed { execution_id: events.execution_id, attempt: obs.index, kind: f.kind });
            obs.duration_us = rec.us();
            obs.phases = std::mem::take(&mut rec.phases);
            obs.dispatch = dispatch;
            obs.failure = Some(f);
            AttemptOutput { observation: obs, response: None, body: Bytes::new() }
        };

        // Unsupported combinations fail before any traffic.
        if plan.version == HttpVersionPolicy::H2c && plan.https {
            let f = TransportFailure::new(
                Phase::Prepare,
                FailureKind::UnsupportedCombination,
                "h2c (cleartext HTTP/2) cannot be used with an https:// URL",
            )
            .with_field("settings.http_version");
            return (fail(rec, obs, f, DispatchState::NotDispatched), false);
        }
        if matches!(plan.version, HttpVersionPolicy::Http2Only) && !plan.https {
            let f = TransportFailure::new(
                Phase::Prepare,
                FailureKind::UnsupportedCombination,
                "HTTP/2-only over TLS was selected for an http:// URL; choose h2c for cleartext HTTP/2",
            )
            .with_field("settings.http_version");
            return (fail(rec, obs, f, DispatchState::NotDispatched), false);
        }
        if plan.https && plan.tls.is_none() {
            let f = TransportFailure::new(Phase::Prepare, FailureKind::TlsProfileInvalid, "no TLS configuration for https request");
            return (fail(rec, obs, f, DispatchState::NotDispatched), false);
        }

        // ---- acquire a connection ----
        let q = rec.start(Phase::Queue);
        let pooled = if allow_pool { self.pool.checkout(key) } else { None };
        let (conn, reused) = match pooled {
            Some(p) => {
                rec.finish(q, PhaseStatus::Completed);
                rec.mark(Phase::Dns, PhaseStatus::Reused, Some("pooled connection"));
                rec.mark(Phase::Connect, PhaseStatus::Reused, Some("pooled connection"));
                if plan.https {
                    rec.mark(Phase::TlsHandshake, PhaseStatus::Reused, Some("pooled connection"));
                }
                (p, true)
            }
            None => {
                rec.finish(q, PhaseStatus::Completed);
                let forward = plan.proxy.as_ref().map(|p| p.kind == ProxyKind::Http && !plan.https).unwrap_or(false);
                let alpn: &[&str] = if plan.https { alpn_for(plan.version) } else { &[] };
                let target = Target { host: &plan.host, port: plan.port, tls: plan.tls.as_deref(), alpn, http_forward_via_proxy: forward };
                let est = tokio::select! {
                    r = connector::establish(&mut rec, &target, &plan.dns, &plan.timeouts, plan.proxy.as_ref()) => r,
                    _ = cancel.cancelled() => {
                        let f = TransportFailure::new(rec.open_phase().unwrap_or(Phase::Connect), FailureKind::Canceled, "canceled during connection setup");
                        return (fail(rec, obs, f, DispatchState::NotDispatched), false);
                    }
                    _ = sleep_until_opt(total_deadline) => {
                        let f = TransportFailure::new(rec.open_phase().unwrap_or(Phase::Connect), FailureKind::TotalTimeout, "total deadline elapsed during connection setup")
                            .with_deadline(plan.timeouts.total_ms);
                        return (fail(rec, obs, f, DispatchState::NotDispatched), false);
                    }
                };
                let est = match est {
                    Ok(e) => e,
                    Err((f, cobs)) => {
                        obs.connection = Some(cobs);
                        return (fail(rec, obs, f, DispatchState::NotDispatched), false);
                    }
                };
                match self.handshake(&mut rec, plan, est).await {
                    Ok(p) => (p, false),
                    Err((f, cobs)) => {
                        obs.connection = Some(cobs);
                        return (fail(rec, obs, f, DispatchState::NotDispatched), false);
                    }
                }
            }
        };
        let mut cobs = conn.template.clone();
        cobs.reused = reused;
        cobs.prior_requests = conn.served.load(Ordering::SeqCst);
        obs.connection = Some(cobs);

        // ---- build the request ----
        let is_h2 = matches!(conn.sender, Sender::H2(_));
        let absolute_form = !is_h2 && plan.proxy.as_ref().map(|p| p.kind == ProxyKind::Http && !plan.https).unwrap_or(false);
        let explicit_host = plan.headers.iter().find(|(n, _)| n == http::header::HOST).map(|(_, v)| v.to_str().unwrap_or("").to_string());
        let authority = explicit_host.clone().unwrap_or_else(|| plan.authority.clone());
        let uri_str = if is_h2 || absolute_form {
            format!("{}://{}{}", if plan.https { "https" } else { "http" }, authority, plan.request_target)
        } else {
            plan.request_target.clone()
        };
        let uri: Uri = match uri_str.parse() {
            Ok(u) => u,
            Err(e) => {
                let f = TransportFailure::new(Phase::Prepare, FailureKind::InvalidUrl, format!("request target is not a valid URI: {e}"))
                    .with_field("url");
                if !reused || matches!(conn.sender, Sender::H1(_)) {
                    self.pool.checkin(key, conn);
                }
                return (fail(rec, obs, f, DispatchState::NotDispatched), false);
            }
        };
        let (body, signal) = InstrumentedBody::new(plan.body.clone());
        let mut req = Request::builder().method(plan.method.clone()).uri(uri);
        let mut header_bytes: u64 = 0;
        if !is_h2 && explicit_host.is_none() {
            req = req.header(http::header::HOST, plan.authority.as_str());
            header_bytes += 6 + plan.authority.len() as u64 + 2;
        }
        for (n, v) in &plan.headers {
            if is_h2
                && (n == http::header::HOST
                    || n == http::header::CONNECTION
                    || n == http::header::TRANSFER_ENCODING
                    || n.as_str() == "keep-alive"
                    || n == http::header::UPGRADE)
            {
                continue; // connection-specific fields are illegal in HTTP/2
            }
            header_bytes += n.as_str().len() as u64 + 2 + v.len() as u64 + 2;
            req = req.header(n, v);
        }
        header_bytes += (plan.method.as_str().len() + plan.request_target.len() + 12) as u64;
        obs.bytes.request_headers_logical = header_bytes;
        obs.bytes.request_headers_estimated = is_h2;
        let req = match req.body(body) {
            Ok(r) => r,
            Err(e) => {
                let f = TransportFailure::new(Phase::Prepare, FailureKind::InvalidHeader, format!("request could not be built: {e}"))
                    .with_field("headers");
                return (fail(rec, obs, f, DispatchState::NotDispatched), false);
            }
        };

        // ---- send and await response headers ----
        let written_before = conn.stats.bytes_written();
        let read_before = conn.stats.bytes_read();
        conn.stats.mark_awaiting_read();
        let w_idx = rec.start(Phase::RequestWrite);
        let write_deadline = plan.timeouts.request_write_ms.map(|ms| Instant::now() + Duration::from_millis(ms));
        let mut headers_deadline: Option<Instant> = None;
        let mut h_idx: Option<usize> = None;
        let signal_wait = signal.clone();
        let mut write_done = signal.done.load(Ordering::SeqCst);
        if write_done {
            rec.finish(w_idx, PhaseStatus::Completed);
            h_idx = Some(rec.start(Phase::AwaitResponseHeaders));
            headers_deadline = plan.timeouts.response_headers_ms.map(|ms| Instant::now() + Duration::from_millis(ms));
        }

        let send_result: Result<hyper::Response<Incoming>, (hyper::Error, bool)> = {
            let conn_sender = conn.sender.clone();
            let fut = async move {
                match conn_sender {
                    Sender::H1(s) => {
                        let mut guard = s.lock().await;
                        let fut = guard.try_send_request(req);
                        drop(guard);
                        fut.await.map_err(|mut e| {
                            let unsent = e.take_message().is_some();
                            (e.into_error(), unsent)
                        })
                    }
                    Sender::H2(mut s) => s.try_send_request(req).await.map_err(|mut e| {
                        let unsent = e.take_message().is_some();
                        (e.into_error(), unsent)
                    }),
                }
            };
            tokio::pin!(fut);
            loop {
                tokio::select! {
                    r = &mut fut => break r,
                    _ = signal_wait.notify.notified(), if !write_done => {
                        write_done = true;
                        rec.finish(w_idx, PhaseStatus::Completed);
                        h_idx = Some(rec.start(Phase::AwaitResponseHeaders));
                        headers_deadline = plan.timeouts.response_headers_ms.map(|ms| Instant::now() + Duration::from_millis(ms));
                    }
                    _ = sleep_until_opt(write_deadline), if !write_done => {
                        let dispatch = dispatch_from_bytes(&conn.stats, written_before);
                        self.pool.evict(key, conn.template.id);
                        let f = TransportFailure::new(Phase::RequestWrite, FailureKind::RequestWriteTimeout,
                            "the request could not be fully handed to the connection before the write deadline (peer not reading?)")
                            .with_deadline(plan.timeouts.request_write_ms);
                        return (finalize_fail(fail(rec, obs, f, dispatch), &conn.stats, written_before, read_before), false);
                    }
                    _ = sleep_until_opt(headers_deadline), if write_done => {
                        let dispatch = dispatch_from_bytes(&conn.stats, written_before);
                        self.pool.evict(key, conn.template.id);
                        let f = TransportFailure::new(Phase::AwaitResponseHeaders, FailureKind::ResponseHeadersTimeout,
                            "no response headers arrived before the response-header deadline")
                            .with_deadline(plan.timeouts.response_headers_ms);
                        return (finalize_fail(fail(rec, obs, f, dispatch), &conn.stats, written_before, read_before), false);
                    }
                    _ = sleep_until_opt(total_deadline) => {
                        let dispatch = dispatch_from_bytes(&conn.stats, written_before);
                        self.pool.evict(key, conn.template.id);
                        let f = TransportFailure::new(rec.open_phase().unwrap_or(Phase::AwaitResponseHeaders), FailureKind::TotalTimeout,
                            "total deadline elapsed before response headers").with_deadline(plan.timeouts.total_ms);
                        return (finalize_fail(fail(rec, obs, f, dispatch), &conn.stats, written_before, read_before), false);
                    }
                    _ = cancel.cancelled() => {
                        let dispatch = dispatch_from_bytes(&conn.stats, written_before);
                        self.pool.evict(key, conn.template.id);
                        let f = TransportFailure::new(rec.open_phase().unwrap_or(Phase::AwaitResponseHeaders), FailureKind::Canceled,
                            "canceled before response headers arrived");
                        return (finalize_fail(fail(rec, obs, f, dispatch), &conn.stats, written_before, read_before), false);
                    }
                }
            }
        };

        let resp = match send_result {
            Ok(r) => r,
            Err((e, unsent)) => {
                self.pool.evict(key, conn.template.id);
                let mut f = classify_hyper(&e, HyperStage::AwaitHeaders);
                apply_tls_tap(&mut f, &conn.stats);
                if !write_done {
                    f.phase = Phase::RequestWrite;
                }
                let dispatch = if unsent || f.kind == FailureKind::H2RefusedStream {
                    DispatchState::NotDispatched
                } else {
                    dispatch_from_bytes(&conn.stats, written_before)
                };
                // A pooled connection that provably never received the request
                // is re-dispatched once on a fresh connection.
                let redispatch = unsent && reused;
                if unsent {
                    f.message = format!("{} (the request was not written to the connection)", f.message);
                }
                return (finalize_fail(fail(rec, obs, f, dispatch), &conn.stats, written_before, read_before), redispatch);
            }
        };

        // ---- response head ----
        if !write_done {
            rec.finish_with(w_idx, PhaseStatus::Unknown, "response arrived before the request body was fully sent");
        }
        let head_at = Instant::now();
        let first_byte = conn.stats.first_read_after_mark();
        if let Some(i) = h_idx {
            rec.finish(i, PhaseStatus::Completed);
            if let Some(fb) = first_byte {
                let off = rec.us_at(fb);
                rec.phases[i].detail = Some(format!("first response byte at +{} µs (connection-level)", off));
            }
        }
        let _ = head_at;
        obs.dispatch = DispatchState::Sent;
        let status = resp.status().as_u16();
        obs.response_status = Some(status);
        events.emit(ExecutionEvent::ResponseHead { execution_id: events.execution_id, attempt: index, status });
        let version = match resp.version() {
            http::Version::HTTP_10 => "HTTP/1.0",
            http::Version::HTTP_11 => "HTTP/1.1",
            http::Version::HTTP_2 => "HTTP/2",
            http::Version::HTTP_3 => "HTTP/3",
            _ => "HTTP/?",
        }
        .to_string();
        let headers: Vec<HeaderEntry> = resp
            .headers()
            .iter()
            .map(|(n, v)| HeaderEntry { name: n.as_str().to_string(), value: String::from_utf8_lossy(v.as_bytes()).into_owned() })
            .collect();
        let resp_header_bytes: u64 = headers.iter().map(|h| (h.name.len() + h.value.len() + 4) as u64).sum::<u64>() + 17;
        obs.bytes.response_headers_logical = Some(resp_header_bytes);
        let content_type = resp.headers().get(http::header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).map(|s| s.to_string());
        let content_encoding = resp.headers().get(http::header::CONTENT_ENCODING).and_then(|v| v.to_str().ok()).map(|s| s.to_string());
        let declared_length =
            resp.headers().get(http::header::CONTENT_LENGTH).and_then(|v| v.to_str().ok()).and_then(|s| s.parse::<u64>().ok());
        let conn_close = resp
            .headers()
            .get_all(http::header::CONNECTION)
            .iter()
            .any(|v| v.to_str().map(|s| s.to_ascii_lowercase().contains("close")).unwrap_or(false));
        let no_body = plan.method == Method::HEAD || status == 204 || status == 304 || (100..200).contains(&status);

        // ---- body ----
        let b_idx = rec.start(Phase::ResponseBody);
        let mut body = resp.into_body();
        let mut captured = BytesMut::new();
        let mut wire: u64 = 0;
        let mut trailers: Vec<HeaderEntry> = Vec::new();
        let mut trailers_received = false;
        let mut failure: Option<TransportFailure> = None;
        let mut completeness = BodyCompleteness::Complete;
        let mut last_progress = Instant::now();
        let idle = plan.timeouts.body_idle_ms.map(Duration::from_millis);
        loop {
            let idle_deadline = idle.map(|d| Instant::now() + d);
            tokio::select! {
                f = body.frame() => match f {
                    None => break,
                    Some(Ok(frame)) => {
                        if frame.is_data() {
                            let data = frame.into_data().unwrap_or_default();
                            wire += data.len() as u64;
                            let room = (plan.limits.capture_bytes as usize).saturating_sub(captured.len());
                            if room > 0 {
                                captured.extend_from_slice(&data[..data.len().min(room)]);
                            }
                            if last_progress.elapsed() > Duration::from_millis(100) {
                                last_progress = Instant::now();
                                events.emit(ExecutionEvent::BodyProgress { execution_id: events.execution_id, bytes: wire });
                            }
                            if wire > plan.limits.max_response_bytes {
                                completeness = BodyCompleteness::StoppedAtLocalLimit;
                                failure = Some(TransportFailure::new(Phase::ResponseBody, FailureKind::ResponseTooLargeLocal,
                                    format!("stopped reading after {} bytes: the local max_response_bytes limit was reached (this is a local limit, not a peer fault)", plan.limits.max_response_bytes)));
                                break;
                            }
                        } else if let Ok(t) = frame.into_trailers() {
                            trailers_received = true;
                            trailers = t.iter().map(|(n, v)| HeaderEntry { name: n.as_str().to_string(), value: String::from_utf8_lossy(v.as_bytes()).into_owned() }).collect();
                        }
                    }
                    Some(Err(e)) => {
                        completeness = BodyCompleteness::Incomplete;
                        let mut f = classify_hyper(&e, HyperStage::Body);
                        apply_tls_tap(&mut f, &conn.stats);
                        failure = Some(f);
                        break;
                    }
                },
                _ = sleep_until_opt(idle_deadline) => {
                    completeness = BodyCompleteness::Incomplete;
                    failure = Some(TransportFailure::new(Phase::ResponseBody, FailureKind::BodyIdleTimeout,
                        "response body stalled longer than the body idle deadline").with_deadline(plan.timeouts.body_idle_ms));
                    break;
                }
                _ = sleep_until_opt(total_deadline) => {
                    completeness = BodyCompleteness::Incomplete;
                    failure = Some(TransportFailure::new(Phase::ResponseBody, FailureKind::TotalTimeout,
                        "total deadline elapsed while reading the response body").with_deadline(plan.timeouts.total_ms));
                    break;
                }
                _ = cancel.cancelled() => {
                    completeness = BodyCompleteness::Canceled;
                    failure = Some(TransportFailure::new(Phase::ResponseBody, FailureKind::Canceled, "canceled while reading the response body"));
                    break;
                }
            }
        }
        if no_body && failure.is_none() {
            completeness = BodyCompleteness::NoBody;
        }
        let body_status = match (&failure, completeness) {
            (None, _) => PhaseStatus::Completed,
            (Some(f), _) if f.kind == FailureKind::Canceled => PhaseStatus::Canceled,
            (Some(f), _) if matches!(f.kind, FailureKind::BodyIdleTimeout | FailureKind::TotalTimeout) => PhaseStatus::TimedOut,
            _ => PhaseStatus::Failed,
        };
        rec.finish(b_idx, body_status);

        obs.bytes.response_body_wire = Some(wire);
        obs.bytes.connection_bytes_written = Some(conn.stats.bytes_written().saturating_sub(written_before));
        obs.bytes.connection_bytes_read = Some(conn.stats.bytes_read().saturating_sub(read_before));
        conn.served.fetch_add(1, Ordering::SeqCst);

        // ---- pool return ----
        let reusable = failure.is_none() && plan.keepalive && !conn_close;
        match &conn.sender {
            Sender::H1(_) => {
                if reusable {
                    self.pool.checkin(key, conn.clone());
                } else {
                    conn.closed.store(true, Ordering::SeqCst);
                    self.pool.evict(key, conn.template.id);
                }
            }
            Sender::H2(s) => {
                if s.is_closed() || !plan.keepalive {
                    self.pool.evict(key, conn.template.id);
                } else if !reused {
                    self.pool.checkin(key, conn.clone());
                }
            }
        }

        let captured = captured.freeze();
        let blob = if captured.is_empty() { None } else { Some(crate::certs::sha256_hex(&captured)) };
        let response = ResponseRecord {
            status,
            reason: http::StatusCode::from_u16(status).ok().and_then(|s| s.canonical_reason().map(|r| r.to_string())),
            http_version: version,
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
                blob_sha256: blob,
            },
        };
        if let Some(f) = &failure {
            events.emit(ExecutionEvent::AttemptFailed { execution_id: events.execution_id, attempt: index, kind: f.kind });
        }
        obs.failure = failure;
        obs.duration_us = rec.us();
        obs.phases = std::mem::take(&mut rec.phases);
        let _ = is_idempotent;
        (AttemptOutput { observation: obs, response: Some(response), body: captured }, false)
    }

    async fn handshake(
        &self,
        rec: &mut Recorder,
        plan: &HttpPlan,
        est: Established,
    ) -> Result<Pooled, (TransportFailure, ConnectionObservation)> {
        let Established { io, stats, mut observation } = est;
        let negotiated = observation.tls.as_ref().and_then(|t| t.alpn_negotiated.clone());
        let use_h2 = match plan.version {
            HttpVersionPolicy::H2c => true,
            HttpVersionPolicy::Http2Only => {
                if negotiated.as_deref() != Some("h2") {
                    let f = TransportFailure::new(
                        Phase::TlsHandshake,
                        FailureKind::TlsAlpnMismatch,
                        format!(
                            "HTTP/2 was required but the peer negotiated {}",
                            negotiated.as_deref().map(|s| format!("'{s}'")).unwrap_or_else(|| "no ALPN protocol".into())
                        ),
                    );
                    return Err((f, observation));
                }
                true
            }
            HttpVersionPolicy::Http1Only => false,
            _ => negotiated.as_deref() == Some("h2"),
        };
        let idx = rec.start(Phase::ProtocolHandshake);
        let closed = Arc::new(AtomicBool::new(false));
        let io: TokioIo<BoxIo> = TokioIo::new(io);
        let sender = if use_h2 {
            let mut b = http2::Builder::new(TokioExecutor::new());
            b.max_header_list_size(plan.limits.max_response_header_bytes.min(u32::MAX as u64) as u32);
            match b.handshake::<_, InstrumentedBody>(io).await {
                Ok((s, conn)) => {
                    let c = closed.clone();
                    tokio::spawn(async move {
                        let _ = conn.await;
                        c.store(true, Ordering::SeqCst);
                    });
                    observation.protocol = Some("h2".into());
                    Sender::H2(s)
                }
                Err(e) => {
                    rec.finish(idx, PhaseStatus::Failed);
                    return Err((classify_hyper(&e, HyperStage::Handshake), observation));
                }
            }
        } else {
            let mut b = http1::Builder::new();
            b.max_buf_size((plan.limits.max_response_header_bytes as usize).max(8192));
            match b.handshake::<_, InstrumentedBody>(io).await {
                Ok((s, conn)) => {
                    let c = closed.clone();
                    tokio::spawn(async move {
                        let _ = conn.await;
                        c.store(true, Ordering::SeqCst);
                    });
                    observation.protocol = Some("http/1.1".into());
                    Sender::H1(Arc::new(tokio::sync::Mutex::new(s)))
                }
                Err(e) => {
                    rec.finish(idx, PhaseStatus::Failed);
                    return Err((classify_hyper(&e, HyperStage::Handshake), observation));
                }
            }
        };
        rec.finish(idx, PhaseStatus::Completed);
        Ok(Pooled {
            sender,
            stats,
            template: observation,
            served: Arc::new(std::sync::atomic::AtomicU32::new(0)),
            idle_since: Instant::now(),
            closed,
        })
    }
}

/// Prefer the typed TLS error captured at the I/O boundary when the HTTP
/// layer only reports a generic protocol/connection failure.
fn apply_tls_tap(f: &mut TransportFailure, stats: &ConnStats) {
    if f.tls_alert.is_some() || f.kind.is_tls_verification() {
        return;
    }
    if let Some((kind, alert)) = stats.tls_error() {
        f.kind = kind;
        f.tls_alert = alert;
    }
}

fn dispatch_from_bytes(stats: &ConnStats, written_before: u64) -> DispatchState {
    if stats.bytes_written() > written_before { DispatchState::MayHaveBeenSent } else { DispatchState::NotDispatched }
}

fn finalize_fail(mut out: AttemptOutput, stats: &ConnStats, written_before: u64, read_before: u64) -> AttemptOutput {
    out.observation.bytes.connection_bytes_written = Some(stats.bytes_written().saturating_sub(written_before));
    out.observation.bytes.connection_bytes_read = Some(stats.bytes_read().saturating_sub(read_before));
    out
}

pub async fn sleep_until_opt(at: Option<Instant>) {
    match at {
        Some(t) => tokio::time::sleep_until(tokio::time::Instant::from_std(t)).await,
        None => std::future::pending::<()>().await,
    }
}
