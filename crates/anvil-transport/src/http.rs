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
    /// PROXY protocol header written once at the head of each new connection,
    /// before TLS. Part of the pool key: a connection keeps the header it was
    /// opened with and is never shared with another header (or none).
    pub proxy_header: Option<crate::proxy_protocol::ConnectionHeader>,
    /// Why a configured header is not sent on this attempt (a redirect to
    /// another listener); recorded as a `not_applicable` header phase.
    pub proxy_header_withheld: Option<String>,
    /// How the 0-RTT early-data opt-in applies to this attempt.
    pub early_data: EarlyDataIntent,
}

/// How the early-data opt-in applies to one attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum EarlyDataIntent {
    /// The opt-in is off: ordinary connections, no session-ticket cache.
    #[default]
    Off,
    /// Send the request as early data on a new connection that resumes a
    /// ticket allowing it (otherwise after the handshake, with the reason).
    Send,
    /// Resume a ticket when there is one, but never send early data.
    Hold(EarlyDataNotUsed),
}

/// The evidence an attempt under the opt-in starts from.
pub(crate) fn early_observation(intent: EarlyDataIntent, transport: EarlyDataTransport) -> EarlyDataObservation {
    EarlyDataObservation {
        transport,
        method_eligible: !matches!(intent, EarlyDataIntent::Hold(EarlyDataNotUsed::MethodNotEligible)),
        resumption_attempted: false,
        resumption_accepted: None,
        offered: false,
        accepted: None,
        bytes: 0,
        bytes_estimated: false,
        resent_after_handshake: false,
        not_used: match intent {
            EarlyDataIntent::Hold(r) => Some(r),
            _ => None,
        },
        tickets_received: 0,
        ticket_max_early_data: None,
    }
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
    /// When an HTTP/1.1 connection was last returned to the pool.
    idle_since: Instant,
    closed: Arc<AtomicBool>,
    /// Requests in flight on the connection. Only an HTTP/2 connection stays
    /// pooled while it carries requests (they share it), so its idleness is
    /// read from here.
    streams: Arc<Mutex<StreamUse>>,
}

struct StreamUse {
    active: usize,
    /// When the last request in flight ended (or the connection was opened).
    idle_since: Instant,
}

/// One request's use of a shared HTTP/2 connection. While any is held the
/// connection is busy: it is never expired or evicted as idle.
struct StreamLease(Arc<Mutex<StreamUse>>);

impl Drop for StreamLease {
    fn drop(&mut self) {
        let mut u = self.0.lock();
        u.active = u.active.saturating_sub(1);
        if u.active == 0 {
            u.idle_since = Instant::now();
        }
    }
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

    /// Count one more request on a shared HTTP/2 connection. An HTTP/1.1
    /// connection is out of the pool while it is used, so it needs none.
    fn lease(&self) -> Option<StreamLease> {
        if !matches!(self.sender, Sender::H2(_)) {
            return None;
        }
        self.streams.lock().active += 1;
        Some(StreamLease(self.streams.clone()))
    }

    /// Since when the connection has carried no request; `None` while an
    /// HTTP/2 connection has requests in flight.
    fn idle_start(&self) -> Option<Instant> {
        match self.sender {
            Sender::H1(_) => Some(self.idle_since),
            Sender::H2(_) => {
                let u = self.streams.lock();
                (u.active == 0).then_some(u.idle_since)
            }
        }
    }

    /// Dead, or idle for at least `ttl`.
    fn expired(&self, now: Instant, ttl: Duration) -> bool {
        !self.is_usable() || self.idle_start().is_some_and(|t| now.saturating_duration_since(t) >= ttl)
    }
}

const MAX_IDLE_PER_KEY: usize = 8;
const MAX_IDLE_TOTAL: usize = 64;
const IDLE_TTL: Duration = Duration::from_secs(90);
/// Maximum time to keep a connection that answered `425 Too Early` for its retry.
const TOO_EARLY_TTL: Duration = Duration::from_secs(10);

/// Bounds of the idle connection pool.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PoolLimits {
    /// Connections kept per pool key; the key's longest idle is closed
    /// first when a returned one would exceed it.
    pub max_idle_per_key: usize,
    /// Idle connections kept across all keys; the longest idle is closed
    /// first when a new one would exceed it.
    pub max_idle_total: usize,
    /// How long a connection may stay idle before it is closed, whether or
    /// not its key is used again.
    pub idle_ttl: Duration,
}

impl Default for PoolLimits {
    fn default() -> Self {
        PoolLimits { max_idle_per_key: MAX_IDLE_PER_KEY, max_idle_total: MAX_IDLE_TOTAL, idle_ttl: IDLE_TTL }
    }
}

/// What the pool holds right now.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PoolStats {
    /// Pool keys with at least one connection.
    pub keys: usize,
    /// Pooled connections, idle or carrying HTTP/2 requests.
    pub connections: usize,
    /// Pooled connections carrying no request.
    pub idle: usize,
}

/// Connection pool keyed by isolation + destination + security context.
///
/// Idle connections are bounded per key and in total, and a background sweep
/// closes those idle longer than the TTL even when their key is never used
/// again. The sweep runs only while the pool holds connections.
pub struct Pool {
    shared: Arc<PoolShared>,
}

struct PoolShared {
    limits: PoolLimits,
    state: Mutex<PoolState>,
}

#[derive(Default)]
struct PoolState {
    idle: HashMap<String, Vec<Pooled>>,
    /// The connection that answered `425 Too Early` to early data, kept
    /// (even with connection reuse off) for the engine's one retry on it
    /// after the handshake (RFC 8470 §5.2).
    too_early: HashMap<String, Pooled>,
    sweeper: Option<tokio::task::JoinHandle<()>>,
}

impl Default for Pool {
    fn default() -> Self {
        Pool::with_limits(PoolLimits::default())
    }
}

impl Pool {
    pub fn with_limits(limits: PoolLimits) -> Self {
        Pool { shared: Arc::new(PoolShared { limits, state: Mutex::new(PoolState::default()) }) }
    }

    pub fn limits(&self) -> PoolLimits {
        self.shared.limits
    }

    pub fn stats(&self) -> PoolStats {
        let state = self.shared.state.lock();
        let mut stats = PoolStats { keys: state.idle.len(), ..PoolStats::default() };
        for p in state.idle.values().flatten() {
            stats.connections += 1;
            if p.idle_start().is_some() {
                stats.idle += 1;
            }
        }
        stats
    }

    fn checkout(&self, key: &str) -> Option<(Pooled, Option<StreamLease>)> {
        let now = Instant::now();
        let ttl = self.shared.limits.idle_ttl;
        let (found, stale) = {
            let mut state = self.shared.state.lock();
            let list = state.idle.get_mut(key)?;
            let stale: Vec<Pooled> = list.extract_if(.., |p| p.expired(now, ttl)).collect();
            // HTTP/2 connections stay pooled and are shared (multiplexed).
            let found = match list.iter().find(|p| matches!(p.sender, Sender::H2(_))) {
                Some(p) => {
                    let lease = p.lease();
                    Some((p.clone(), lease))
                }
                None => list.pop().map(|p| (p, None)),
            };
            if list.is_empty() {
                state.idle.remove(key);
            }
            (found, stale)
        };
        // Closed outside the lock.
        drop(stale);
        found
    }

    fn checkin(&self, key: &str, mut p: Pooled) {
        let limits = self.shared.limits;
        p.idle_since = Instant::now();
        let mut dropped = Vec::new();
        {
            let mut state = self.shared.state.lock();
            let list = state.idle.entry(key.to_string()).or_default();
            if list.iter().any(|x| x.template.id == p.template.id) {
                // A shared HTTP/2 connection is already pooled.
                return;
            }
            if list.len() >= limits.max_idle_per_key {
                // The key is full: close its longest-idle connection, not
                // the one returned now (the freshest).
                let oldest = list.iter().enumerate().filter_map(|(i, x)| x.idle_start().map(|t| (t, i))).min_by_key(|(t, _)| *t);
                if let Some((_, i)) = oldest {
                    dropped.push(list.remove(i));
                }
            }
            if list.len() < limits.max_idle_per_key {
                list.push(p);
            } else {
                dropped.push(p);
            }
            if state.idle.get(key).is_some_and(Vec::is_empty) {
                state.idle.remove(key);
            }
            evict_over_cap(&mut state.idle, limits.max_idle_total, &mut dropped);
            self.ensure_sweeper(&mut state);
        }
        drop(dropped);
    }

    fn evict(&self, key: &str, conn_id: u64) {
        let removed: Vec<Pooled> = {
            let mut state = self.shared.state.lock();
            let Some(list) = state.idle.get_mut(key) else { return };
            let removed = list.extract_if(.., |p| p.template.id == conn_id).collect();
            if list.is_empty() {
                state.idle.remove(key);
            }
            removed
        };
        drop(removed);
    }

    /// The connection kept for the retry after `425 Too Early`, if it is
    /// still usable.
    fn take_too_early(&self, key: &str) -> Option<(Pooled, Option<StreamLease>)> {
        let ttl = self.shared.limits.idle_ttl.min(TOO_EARLY_TTL);
        let (found, discarded) = {
            let mut state = self.shared.state.lock();
            let p = state.too_early.remove(key)?;
            if p.expired(Instant::now(), ttl) || !p.is_usable() {
                (None, Some(p))
            } else {
                let lease = p.lease();
                (Some((p, lease)), None)
            }
        };
        drop(discarded);
        found
    }

    fn keep_too_early(&self, key: &str, mut p: Pooled) {
        p.idle_since = Instant::now();
        let replaced = {
            let mut state = self.shared.state.lock();
            let replaced = state.too_early.insert(key.to_string(), p);
            self.ensure_sweeper(&mut state);
            replaced
        };
        drop(replaced);
    }

    /// Start the background sweep unless it is running. It holds only a
    /// weak reference to the pool and stops once the pool is empty.
    fn ensure_sweeper(&self, state: &mut PoolState) {
        if state.sweeper.as_ref().is_some_and(|h| !h.is_finished()) {
            return;
        }
        let Ok(rt) = tokio::runtime::Handle::try_current() else { return };
        let weak = Arc::downgrade(&self.shared);
        let every = sweep_interval(self.shared.limits.idle_ttl.min(TOO_EARLY_TTL));
        state.sweeper = Some(rt.spawn(async move {
            loop {
                tokio::time::sleep(every).await;
                let Some(shared) = weak.upgrade() else { return };
                if !shared.sweep(Instant::now()) {
                    return;
                }
            }
        }));
    }

    /// Drop every pooled connection (e.g. on vault lock or workspace switch).
    pub fn clear(&self) {
        let removed = {
            let mut state = self.shared.state.lock();
            (std::mem::take(&mut state.idle), std::mem::take(&mut state.too_early))
        };
        drop(removed);
    }

    /// Drop pooled connections whose key starts with an isolation prefix.
    pub fn clear_isolation(&self, isolation: &str) {
        let prefix = format!("{isolation}|");
        let removed: (Vec<_>, Vec<_>) = {
            let mut state = self.shared.state.lock();
            let idle = state.idle.extract_if(|k, _| k.starts_with(&prefix)).collect();
            let too_early = state.too_early.extract_if(|k, _| k.starts_with(&prefix)).collect();
            (idle, too_early)
        };
        drop(removed);
    }
}

impl Drop for PoolShared {
    fn drop(&mut self) {
        // The sweep holds only a weak reference and would end on its next
        // tick; end it now instead.
        if let Some(sweeper) = self.state.get_mut().sweeper.take() {
            sweeper.abort();
        }
    }
}

impl PoolShared {
    /// Close dead, expired and over-cap idle connections. Returns whether
    /// the pool still holds any; the sweeper stops otherwise.
    fn sweep(&self, now: Instant) -> bool {
        self.sweep_at(now, true)
    }

    fn sweep_at(&self, now: Instant, forget_sweeper_when_empty: bool) -> bool {
        let ttl = self.limits.idle_ttl;
        let too_early_ttl = ttl.min(TOO_EARLY_TTL);
        let mut dropped = Vec::new();
        let more = {
            let mut state = self.state.lock();
            state.idle.retain(|_, list| {
                dropped.extend(list.extract_if(.., |p| p.expired(now, ttl)));
                !list.is_empty()
            });
            evict_over_cap(&mut state.idle, self.limits.max_idle_total, &mut dropped);
            dropped.extend(state.too_early.extract_if(|_, p| p.expired(now, too_early_ttl)).map(|(_, p)| p));
            let more = !state.idle.is_empty() || !state.too_early.is_empty();
            if !more && forget_sweeper_when_empty {
                state.sweeper = None;
            }
            more
        };
        drop(dropped);
        more
    }
}

/// How often the sweep runs: a connection is closed at most a sixth of the
/// TTL (and at most 15 s) after it expired.
fn sweep_interval(ttl: Duration) -> Duration {
    (ttl / 6).clamp(Duration::from_millis(10), Duration::from_secs(15))
}

/// Move the longest-idle connections to `out` until at most `max` remain
/// idle. HTTP/2 connections carrying requests are not idle and stay.
fn evict_over_cap(idle: &mut HashMap<String, Vec<Pooled>>, max: usize, out: &mut Vec<Pooled>) {
    let mut count = idle.values().flatten().filter(|p| p.idle_start().is_some()).count();
    while count > max {
        let oldest = idle
            .iter()
            .flat_map(|(k, list)| list.iter().enumerate().filter_map(move |(i, p)| p.idle_start().map(|t| (t, k, i))))
            .min_by_key(|(t, _, _)| *t)
            .map(|(_, k, i)| (k.clone(), i));
        let Some((key, i)) = oldest else { break };
        if let Some(list) = idle.get_mut(&key) {
            out.push(list.remove(i));
            if list.is_empty() {
                idle.remove(&key);
            }
        }
        count -= 1;
    }
}

fn pool_key(plan: &HttpPlan) -> String {
    let proxy = plan
        .proxy
        .as_ref()
        .map(|p| format!("{:?}:{}:{}:{}", p.kind, p.host, p.port, p.tls.as_ref().map(|t| t.fingerprint.as_str()).unwrap_or("")))
        .unwrap_or_default();
    let tls = plan.tls.as_ref().map(|t| t.fingerprint.clone()).unwrap_or_default();
    let dns = format!("{:?}{:?}{:?}", plan.dns.resolver, plan.dns.overrides, plan.dns.ip_preference);
    let header = plan.proxy_header.as_ref().map(|h| h.pool_key()).unwrap_or_default();
    format!(
        "{}|{}://{}:{}|{}|{}|{:?}|{}|pp:{}",
        plan.isolation,
        if plan.https { "https" } else { "http" },
        plan.host.to_ascii_lowercase(),
        plan.port,
        proxy,
        tls,
        plan.version,
        crate::certs::sha256_hex(dns.as_bytes()),
        header
    )
}

// ------------------------------------------------------------- transport ---

#[derive(Default)]
pub struct HttpTransport {
    pub pool: Pool,
    /// TLS 1.3 session tickets for early data over TCP (used only under the
    /// early-data opt-in).
    pub tickets: crate::tickets::TicketCache,
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

    /// A transport whose connection pool uses `limits` instead of the defaults.
    pub fn with_pool_limits(limits: PoolLimits) -> Self {
        HttpTransport { pool: Pool::with_limits(limits), ..HttpTransport::default() }
    }

    /// Run one pool sweep as if the clock read `now`; not part of the API.
    #[doc(hidden)]
    pub fn sweep_pool_at(&self, now: Instant) {
        self.pool.shared.sweep_at(now, false);
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
        // HBONE tunnels carry one execution's identity and headers: fresh per attempt.
        let mut allow_pool = plan.keepalive && !crate::hbone::is_hbone(plan.proxy.as_ref());
        for attempt_index in (index..).take(2) {
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
        let mut early = (plan.early_data != EarlyDataIntent::Off && plan.https).then(|| EarlyAttempt {
            obs: early_observation(plan.early_data, EarlyDataTransport::Tls),
            info: None,
            send: false,
            t0: None,
        });
        let (mut out, redispatch) = self.execute_once_inner(plan, key, index, reason, allow_pool, events, cancel, &mut early).await;
        if let Some(e) = early {
            let t0 = e.t0.unwrap_or_else(Instant::now);
            e.finish(&mut out.observation, t0);
        }
        (out, redispatch)
    }

    #[allow(clippy::too_many_arguments)]
    async fn execute_once_inner(
        &self,
        plan: &HttpPlan,
        key: &str,
        index: u32,
        reason: AttemptReason,
        allow_pool: bool,
        events: &EventCtx,
        cancel: &CancellationToken,
        early: &mut Option<EarlyAttempt>,
    ) -> (AttemptOutput, bool) {
        let started_at = Utc::now();
        let mut rec = Recorder::new(index, events.clone());
        if let Some(e) = early.as_mut() {
            e.t0 = Some(rec.t0);
        }
        events.emit(ExecutionEvent::AttemptStarted { execution_id: events.execution_id, attempt: index });
        let total_deadline = plan.timeouts.total_ms.map(|ms| Instant::now() + Duration::from_millis(ms));
        let mut obs = AttemptObservation {
            early_data: None,
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
        // The retry after `425 Too Early` goes out on the connection that
        // answered it, whose handshake is complete.
        let handed = match plan.early_data {
            EarlyDataIntent::Hold(EarlyDataNotUsed::RetryAfterTooEarly) => self.pool.take_too_early(key),
            _ => None,
        };
        let pooled = handed.or_else(|| if allow_pool { self.pool.checkout(key) } else { None });
        let mut deferred: Option<ConnTask> = None;
        // `_stream` is held until the attempt ends: a shared HTTP/2
        // connection carrying this request is busy, not idle.
        let (mut conn, reused, _stream) = match pooled {
            Some((p, stream)) => {
                rec.finish(q, PhaseStatus::Completed);
                rec.mark(Phase::Dns, PhaseStatus::Reused, Some("pooled connection"));
                rec.mark(Phase::Connect, PhaseStatus::Reused, Some("pooled connection"));
                if p.template.proxy_header.is_some() {
                    let sent_on =
                        format!("sent once when connection #{} was opened; a reused connection does not send it again", p.template.id);
                    rec.mark(Phase::ProxyProtocolHeader, PhaseStatus::Reused, Some(&sent_on));
                }
                if let Some(why) = &plan.proxy_header_withheld {
                    rec.mark(Phase::ProxyProtocolHeader, PhaseStatus::NotApplicable, Some(why));
                }
                if plan.https {
                    rec.mark(Phase::TlsHandshake, PhaseStatus::Reused, Some("pooled connection"));
                }
                if let Some(e) = early.as_mut()
                    && e.obs.not_used.is_none()
                {
                    e.obs.not_used = Some(EarlyDataNotUsed::ConnectionReused);
                }
                (p, true, stream)
            }
            None => {
                rec.finish(q, PhaseStatus::Completed);
                let forward = plan.proxy.as_ref().map(|p| p.kind == ProxyKind::Http && !plan.https).unwrap_or(false);
                let alpn: &[&str] = if plan.https { alpn_for(plan.version) } else { &[] };
                let target = Target { host: &plan.host, port: plan.port, tls: plan.tls.as_deref(), alpn, http_forward_via_proxy: forward };
                let header = plan.proxy_header.as_ref().map(connector::PreTlsHeader::of);
                // Under the early-data opt-in a direct TLS connection goes
                // through the session-ticket cache. Early data itself needs a
                // single offered protocol (it is written before ALPN is known).
                let resumption = match (early.as_mut(), plan.tls.clone()) {
                    (Some(e), Some(prepared)) if plan.proxy.is_none() => {
                        let wants = plan.early_data == EarlyDataIntent::Send;
                        e.send = wants && alpn.len() == 1;
                        if wants && alpn.len() > 1 {
                            e.obs.not_used = Some(EarlyDataNotUsed::AlpnNotFixed);
                        }
                        Some(connector::TlsResumption { tickets: &self.tickets, isolation: &plan.isolation, prepared, send_early: e.send })
                    }
                    (Some(e), _) => {
                        if e.obs.not_used.is_none() {
                            e.obs.not_used = Some(EarlyDataNotUsed::ThroughProxy);
                        }
                        None
                    }
                    _ => None,
                };
                let connecting = async {
                    match resumption {
                        Some(r) => connector::establish_resumable(&mut rec, &target, &plan.dns, &plan.timeouts, r, header).await,
                        None => (
                            connector::establish_with(&mut rec, &target, &plan.dns, &plan.timeouts, plan.proxy.as_ref(), header).await,
                            None,
                        ),
                    }
                };
                let est = tokio::select! {
                    (r, info) = connecting => {
                        if let (Some(e), Some(i)) = (early.as_mut(), info) {
                            e.info = Some(i);
                        }
                        r
                    }
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
                if let Some(why) = &plan.proxy_header_withheld {
                    mark_withheld(&mut rec, why);
                }
                let est = match est {
                    Ok(e) => e,
                    Err((f, cobs)) => {
                        obs.connection = Some(cobs);
                        return (fail(rec, obs, f, DispatchState::NotDispatched), false);
                    }
                };
                let early_alpn =
                    early.as_ref().and_then(|e| e.info.as_ref()).and_then(|i| i.early.as_ref()).and_then(|_| alpn.first().copied());
                match self.handshake(&mut rec, plan, est, early_alpn).await {
                    Ok((p, task)) => {
                        deferred = task;
                        let stream = p.lease();
                        (p, false, stream)
                    }
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
            // With TLS early data in flight the connection task starts only
            // now that the request is queued, so its first write is the
            // request itself, as early data.
            let deferred = deferred.take();
            let fut = async move {
                match conn_sender {
                    Sender::H1(s) => {
                        let mut guard = s.lock().await;
                        let fut = guard.try_send_request(req);
                        drop(guard);
                        if let Some(task) = deferred {
                            tokio::spawn(task);
                        }
                        fut.await.map_err(|mut e| {
                            let unsent = e.take_message().is_some();
                            (e.into_error(), unsent)
                        })
                    }
                    Sender::H2(mut s) => {
                        let fut = s.try_send_request(req);
                        if let Some(task) = deferred {
                            tokio::spawn(task);
                        }
                        fut.await.map_err(|mut e| {
                            let unsent = e.take_message().is_some();
                            (e.into_error(), unsent)
                        })
                    }
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
                } else if f.kind == FailureKind::RequestWriteFailed {
                    // The request was fully written: a broken pipe now means
                    // the peer closed the connection before responding (e.g.
                    // an HTTP/2 GOAWAY covering this stream, then close).
                    f.kind = FailureKind::ClosedBeforeResponse;
                    f.message = format!("{} (after the request was fully written)", f.message);
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
        // A connection whose handshake completed during the request keeps
        // its final TLS evidence for later requests.
        if let Some(t) = early.as_ref().and_then(|e| e.info.as_ref()).and_then(|i| i.early.as_ref()).and_then(|p| p.state.observation()) {
            conn.template.tls = Some(t);
        }
        let tunneled = crate::hbone::is_hbone(plan.proxy.as_ref());
        // Only an eligible request is retried after 425 (the engine's rule).
        let kept_for_retry = plan.early_data == EarlyDataIntent::Send && status == 425 && failure.is_none() && !conn_close && !tunneled;
        if kept_for_retry {
            self.pool.keep_too_early(key, conn.clone());
        }
        let reusable = failure.is_none() && plan.keepalive && !conn_close && !tunneled;
        match &conn.sender {
            Sender::H1(_) => {
                if reusable {
                    self.pool.checkin(key, conn.clone());
                } else if !kept_for_retry {
                    conn.closed.store(true, Ordering::SeqCst);
                    self.pool.evict(key, conn.template.id);
                }
            }
            Sender::H2(s) => {
                if s.is_closed() || !plan.keepalive || tunneled {
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
                decoding: None,
                decoding_detail: None,
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

    /// Set up HTTP/1.1 or HTTP/2 over an established stream. With
    /// `early_alpn` (TLS early data in flight, so nothing is negotiated yet)
    /// the protocol is the single one offered, and the connection task is
    /// returned instead of spawned: it must start only after the request is
    /// queued, or its first flush would finish the handshake before the
    /// request was written as early data.
    async fn handshake(
        &self,
        rec: &mut Recorder,
        plan: &HttpPlan,
        est: Established,
        early_alpn: Option<&str>,
    ) -> Result<(Pooled, Option<ConnTask>), (TransportFailure, ConnectionObservation)> {
        let Established { io, stats, mut observation } = est;
        let defer = early_alpn.is_some();
        let mut deferred: Option<ConnTask> = None;
        let negotiated = observation.tls.as_ref().and_then(|t| t.alpn_negotiated.clone()).or_else(|| early_alpn.map(String::from));
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
                    let task: ConnTask = Box::pin(async move {
                        let _ = conn.await;
                        c.store(true, Ordering::SeqCst);
                    });
                    if defer {
                        deferred = Some(task);
                    } else {
                        tokio::spawn(task);
                    }
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
                    let task: ConnTask = Box::pin(async move {
                        let _ = conn.await;
                        c.store(true, Ordering::SeqCst);
                    });
                    if defer {
                        deferred = Some(task);
                    } else {
                        tokio::spawn(task);
                    }
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
        Ok((
            Pooled {
                sender,
                stats,
                template: observation,
                served: Arc::new(std::sync::atomic::AtomicU32::new(0)),
                idle_since: Instant::now(),
                closed,
                streams: Arc::new(Mutex::new(StreamUse { active: 0, idle_since: Instant::now() })),
            },
            deferred,
        ))
    }
}

/// A hyper connection task whose start was deferred (TLS early data).
type ConnTask = Pin<Box<dyn std::future::Future<Output = ()> + Send>>;

/// Early-data bookkeeping of one TCP attempt under the opt-in.
struct EarlyAttempt {
    obs: EarlyDataObservation,
    info: Option<crate::early_tls::ResumableInfo>,
    /// The ClientHello was allowed to offer early data.
    send: bool,
    /// The attempt recorder's clock origin.
    t0: Option<Instant>,
}

impl EarlyAttempt {
    /// Complete the attempt's early-data evidence once the attempt ended:
    /// the handshake outcome, early bytes, tickets that arrived; close the
    /// TLS phase of an early-data handshake at its measured completion.
    fn finish(mut self, obs: &mut AttemptObservation, t0: Instant) {
        if let Some(info) = &self.info {
            let e = &mut self.obs;
            match &info.early {
                Some(p) => {
                    e.resumption_attempted = true;
                    e.bytes = p.state.early_bytes();
                    // Early data covers the request only when bytes went into it.
                    e.offered = e.bytes > 0;
                    e.not_used = if e.offered { None } else { Some(EarlyDataNotUsed::HandshakeCompletedFirst) };
                    if let Some(done) = p.state.done() {
                        e.accepted = e.offered.then_some(done.early_accepted);
                        e.resumption_accepted = Some(done.resumed);
                        e.resent_after_handshake = !done.early_accepted && e.bytes > 0;
                        if let Some(ph) = obs.phases.get_mut(p.tls_phase) {
                            ph.end_us = Some(done.at.saturating_duration_since(t0).as_micros() as u64);
                            ph.status = PhaseStatus::Completed;
                            ph.detail = Some(
                                match (done.early_accepted, done.resumed) {
                                    (true, _) => "resumed session; TLS 1.3 early data accepted (completed while the request was written)",
                                    (false, true) => "resumed session; early data rejected by the server",
                                    (false, false) => "full handshake; early data rejected by the server",
                                }
                                .into(),
                            );
                        }
                        if let (Some(c), Some(t)) = (obs.connection.as_mut(), p.state.observation()) {
                            c.tls = Some(t);
                        }
                    }
                }
                None => {
                    // A ticket that allowed early data but produced none had expired.
                    let offered_ticket = match (self.send, info.taken) {
                        (_, None) => false,
                        (true, Some(n)) => n == 0,
                        (false, Some(_)) => true,
                    };
                    e.resumption_attempted = offered_ticket;
                    if offered_ticket {
                        e.resumption_accepted = info.resumed;
                    }
                    if self.send && e.not_used.is_none() {
                        e.not_used =
                            Some(if info.taken == Some(0) { EarlyDataNotUsed::TicketWithoutEarlyData } else { EarlyDataNotUsed::NoTicket });
                    }
                }
            }
            let n = info.ctx.store.received().saturating_sub(info.tickets_before);
            e.tickets_received = n;
            e.ticket_max_early_data = if n > 0 { info.ctx.store.newest_max_early() } else { None };
        }
        obs.early_data = Some(self.obs);
    }
}

/// Record a configured PROXY header that this attempt does not send, where
/// it would have been written (before the TLS handshake).
fn mark_withheld(rec: &mut Recorder, why: &str) {
    let at = rec.phases.iter().position(|p| p.phase == Phase::TlsHandshake).unwrap_or(rec.phases.len());
    rec.phases.insert(
        at,
        PhaseTiming {
            phase: Phase::ProxyProtocolHeader,
            status: PhaseStatus::NotApplicable,
            start_us: None,
            end_us: None,
            detail: Some(why.into()),
        },
    );
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

#[cfg(test)]
mod tests {
    use super::*;

    fn start_sweeper(t: &HttpTransport) {
        let mut state = t.pool.shared.state.lock();
        t.pool.ensure_sweeper(&mut state);
    }

    fn sweeper(t: &HttpTransport) -> Option<tokio::task::AbortHandle> {
        t.pool.shared.state.lock().sweeper.as_ref().map(|h| h.abort_handle())
    }

    #[tokio::test(start_paused = true)]
    async fn the_sweeper_stops_on_an_empty_pool_and_starts_again() {
        let t = HttpTransport::new();
        start_sweeper(&t);
        let first = sweeper(&t).expect("the sweeper runs");
        let every = sweep_interval(t.pool.limits().idle_ttl);

        // Its first sweep finds the pool empty: it ends and is forgotten.
        tokio::time::sleep(every * 2).await;
        assert!(first.is_finished());
        assert!(sweeper(&t).is_none(), "a stopped sweeper is cleared, so the next connection starts a new one");

        // A new one starts and sweeps like the first: it too ends on the
        // empty pool and is forgotten.
        start_sweeper(&t);
        let second = sweeper(&t).expect("the sweeper runs again");
        assert_ne!(second.id(), first.id(), "a new sweeper was started");
        tokio::time::sleep(every * 2).await;
        assert!(second.is_finished());
        assert!(sweeper(&t).is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn dropping_the_transport_ends_the_sweeper_at_once() {
        let t = HttpTransport::new();
        start_sweeper(&t);
        let task = sweeper(&t).expect("the sweeper runs");
        drop(t);

        // Time is paused and does not advance while this task yields, so the
        // sweeper ends only because the drop aborted it, not on its next tick.
        for _ in 0..100 {
            if task.is_finished() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(task.is_finished(), "the sweeper outlived its pool");
    }
}
