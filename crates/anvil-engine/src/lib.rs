//! Anvil's shared execution engine.
//!
//! The same code prepares and executes a request for the desktop app, the
//! CLI, the collection runner and load workers, so "manual Send succeeds but
//! load sends different bytes" cannot happen by construction.

// Typed `TransportFailure` evidence is returned by value by design (see
// anvil-transport); boxing it would only obscure the evidence flow.

pub mod assertions;
pub mod context;
mod h3_exec;
pub mod http_exec;
pub mod lint;
mod local_checks;
pub mod oauth_http;
mod pkcs12;
pub mod prepare;
pub mod preview;
mod proxy_protocol;
pub mod record;
pub mod redact;
pub mod sessions;
pub mod settings;
pub mod vars;
pub mod workload;

use anvil_domain::execution::{ExecutionRecord, ResponseRecord, TransportFailure};
use anvil_domain::request::Protocol;
use anvil_transport::http::{CacheFence, HttpTransport};
use anvil_transport::recorder::EventCtx;
use anvil_transport::tls::{PreparedTls, TlsSettings};
use bytes::Bytes;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio_util::sync::CancellationToken;

pub use context::ExecutionContext;
pub use sessions::{SessionError, SessionHandle};

/// Result of one execution.
#[derive(Debug, Clone)]
pub struct ExecutionOutput {
    pub record: ExecutionRecord,
    /// Raw captured response bytes (bounded by the capture limit).
    pub body: Bytes,
    /// Decoded (decompressed) bytes when a content-coding was applied.
    pub decoded_body: Option<Bytes>,
    /// Iteration-local extracted variables: (name, value, sensitive).
    pub extracted: Vec<(String, String, bool)>,
    /// Typed facts a session adapter observed beyond the record (e.g. echoed
    /// and repeated datagram payloads). Not persisted; `None` for HTTP and
    /// for sessions that failed during preparation.
    pub session_facts: Option<anvil_transport::session::SessionFacts>,
}

pub struct Engine {
    /// Shared so a token refresh can finish on a task of its own.
    pub http: Arc<HttpTransport>,
    pub h3: anvil_transport::h3::H3Transport,
    pub tokens: Arc<anvil_auth::oauth::TokenCache>,
    /// Reusable gRPC channels. `None` (the default, manual Send): every gRPC
    /// call opens its own connection. The load engine sets this on each
    /// virtual user's engine, and calls then reuse a pooled connection
    /// whenever the effective `keepalive` setting is on.
    pub grpc_channels: Option<Arc<anvil_transport::grpc::Channels>>,
    /// SPIFFE Workload API SVIDs and JWT bundles (memory only).
    pub workload: Arc<workload::WorkloadCache>,
    tls: Mutex<HashMap<String, Arc<PreparedTls>>>,
    cookies: CookieJars,
    /// Advanced by [`Engine::clear_sensitive_state`] before it clears
    /// anything (see [`SensitiveEpoch`]).
    epoch: Arc<AtomicU64>,
}

/// The workspace cookie jars (one per isolation), with the engine's epoch
/// that fences what is stored in them. Cloned into an interactive session's
/// task, which stores its handshake cookies after the `&Engine` it was
/// opened from is no longer borrowed.
#[derive(Clone)]
pub(crate) struct CookieJars {
    jars: Arc<Mutex<Jars>>,
    epoch: Arc<AtomicU64>,
}

#[derive(Default)]
struct Jars {
    by_isolation: HashMap<String, cookie_store::CookieStore>,
    /// Advanced for an isolation by [`Engine::clear_isolation`] (a workspace
    /// delete) when it removes that isolation's jar; 0 when never cleared.
    generations: HashMap<String, u64>,
}

impl Jars {
    fn generation(&self, isolation: &str) -> u64 {
        self.generations.get(isolation).copied().unwrap_or(0)
    }
}

impl CookieJars {
    /// The stored cookies that match `t` under cookie rules (domain, path,
    /// `Secure`, expiry), as `name=value` pairs.
    pub(crate) fn header(&self, isolation: &str, t: &prepare::Target) -> Option<String> {
        let url = url::Url::parse(&t.url()).ok()?;
        let jars = self.jars.lock();
        let jar = jars.by_isolation.get(isolation)?;
        let pairs: Vec<String> = jar.get_request_values(&url).map(|(n, v)| format!("{n}={v}")).collect();
        if pairs.is_empty() { None } else { Some(pairs.join("; ")) }
    }

    /// Keep the response's cookies, unless the jars were cleared since
    /// `epoch` (a lock while the request was in flight) or the isolation's
    /// jar was removed since then (its workspace was deleted).
    pub(crate) fn store(&self, epoch: SensitiveEpoch, isolation: &str, t: &prepare::Target, r: &ResponseRecord) {
        let set_cookie = r.header_values("set-cookie");
        if set_cookie.is_empty() {
            return;
        }
        let Ok(url) = url::Url::parse(&t.url()) else { return };
        let mut jars = self.jars.lock();
        // Checked under the jars' lock: a lock or a workspace delete either
        // advanced its counter before this point or empties the jar after it.
        if self.epoch.load(Ordering::SeqCst) != epoch.epoch || epoch.jar != Some(jars.generation(isolation)) {
            return;
        }
        let jar = jars.by_isolation.entry(isolation.to_string()).or_default();
        for v in set_cookie {
            let _ = jar.parse(v, &url);
        }
    }

    fn generation(&self, isolation: &str) -> u64 {
        self.jars.lock().generation(isolation)
    }

    /// Remove the isolation's jar and start its next generation: a store of
    /// an execution that started before this is refused.
    fn clear_isolation(&self, isolation: &str) {
        let mut jars = self.jars.lock();
        jars.by_isolation.remove(isolation);
        let g = jars.generations.entry(isolation.to_string()).or_default();
        *g = g.wrapping_add(1);
    }
}

/// The engine's sensitive-state epoch when an execution started, with the
/// transports' cache generations taken at the same point. A lock
/// ([`Engine::clear_sensitive_state`]) starts a new epoch, and what an
/// execution of an earlier epoch prepares or receives afterwards is not
/// kept: its cookies, its prepared TLS material (client identity keys and
/// session-ticket stores), its connections and its session tickets. An
/// execution's epoch ([`Engine::execution_epoch`]) also holds its workspace
/// cookie jar's generation: after a workspace delete
/// ([`Engine::clear_isolation`]) its cookies are not kept either.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SensitiveEpoch {
    epoch: u64,
    transport: CacheFence,
    /// The generation of the execution's workspace cookie jar; `None` for an
    /// epoch taken for no workspace, which keeps no cookies.
    jar: Option<u64>,
}

impl SensitiveEpoch {
    /// The connection-pool and ticket-cache generations to plan attempts with
    /// ([`anvil_transport::http::HttpPlan::fence`]).
    pub fn transport(&self) -> CacheFence {
        self.transport
    }
}

impl Default for Engine {
    fn default() -> Self {
        Self::new()
    }
}

impl Engine {
    pub fn new() -> Self {
        anvil_transport::init();
        let epoch = Arc::new(AtomicU64::new(0));
        Engine {
            http: Arc::new(HttpTransport::new()),
            h3: anvil_transport::h3::H3Transport::new(),
            tokens: Arc::new(anvil_auth::oauth::TokenCache::new()),
            grpc_channels: None,
            workload: Arc::new(workload::WorkloadCache::default()),
            tls: Mutex::new(HashMap::new()),
            cookies: CookieJars { jars: Arc::default(), epoch: epoch.clone() },
            epoch,
        }
    }

    /// The current sensitive-state epoch, for work outside a workspace
    /// execution (it keeps no cookies).
    pub fn sensitive_epoch(&self) -> SensitiveEpoch {
        loop {
            let epoch = self.epoch.load(Ordering::SeqCst);
            let transport = CacheFence { tcp: self.http.cache_generations(), quic: self.h3.cache_generations() };
            // A lock advances the epoch before it clears the transports: an
            // unchanged epoch means the generations are not newer than it.
            if self.epoch.load(Ordering::SeqCst) == epoch {
                return SensitiveEpoch { epoch, transport, jar: None };
            }
        }
    }

    /// The current sensitive-state epoch with the generation of
    /// `isolation`'s cookie jar, taken when an execution in that workspace
    /// starts.
    pub fn execution_epoch(&self, isolation: &str) -> SensitiveEpoch {
        let jar = self.cookies.generation(isolation);
        SensitiveEpoch { jar: Some(jar), ..self.sensitive_epoch() }
    }

    fn is_current(&self, epoch: SensitiveEpoch) -> bool {
        self.epoch.load(Ordering::SeqCst) == epoch.epoch
    }

    /// Execute a request of any supported protocol.
    pub async fn execute(&self, ctx: &ExecutionContext, events: EventCtx, cancel: CancellationToken) -> ExecutionOutput {
        match ctx.spec.protocol {
            Protocol::Http => http_exec::execute(self, ctx, events, cancel).await,
            Protocol::WebSocket | Protocol::Grpc | Protocol::Sse | Protocol::Tcp | Protocol::Udp => {
                sessions::execute(self, ctx, events, cancel).await
            }
        }
    }

    /// Validated TLS material, cached by profile key. A key
    /// `<profile variant>|<material hash>` replaces an entry of the same
    /// variant with other material, so a rotated Workload API SVID does not
    /// leave the superseded key material behind. For an execution of an
    /// earlier `epoch` (a lock since it started) the material is prepared
    /// but not cached: it holds a client identity's private key and a
    /// session-ticket store.
    pub fn prepared_tls(&self, epoch: SensitiveEpoch, key: &str, s: &TlsSettings) -> Result<Arc<PreparedTls>, TransportFailure> {
        if let Some(p) = self.tls.lock().get(key) {
            return Ok(p.clone());
        }
        let mut p = anvil_transport::tls::prepare(s)?;
        p.profile_key = key.to_string();
        let p = Arc::new(p);
        let mut cache = self.tls.lock();
        // Checked under the cache's lock, before the variant's entries are
        // dropped: a clear either advanced the epoch before this point or
        // empties the cache after it.
        if !self.is_current(epoch) {
            return Ok(p);
        }
        if let Some((variant, _)) = key.rsplit_once('|') {
            let prefix = format!("{variant}|");
            cache.retain(|k, _| !k.starts_with(&prefix));
        }
        cache.insert(key.to_string(), p.clone());
        Ok(p)
    }

    /// Prepared TLS configurations held (for tests and the lock check).
    pub fn prepared_tls_len(&self) -> usize {
        self.tls.lock().len()
    }

    pub fn cookie_header(&self, isolation: &str, t: &prepare::Target) -> Option<String> {
        self.cookies.header(isolation, t)
    }

    /// Keep the response's cookies in the workspace jar, unless the jar was
    /// cleared since `epoch` (a lock or a workspace delete while the request
    /// was in flight).
    pub fn store_cookies(&self, epoch: SensitiveEpoch, isolation: &str, t: &prepare::Target, r: &ResponseRecord) {
        self.cookies.store(epoch, isolation, t, r);
    }

    /// The workspace cookie jars, for a session task to store into.
    pub(crate) fn cookie_jars(&self) -> CookieJars {
        self.cookies.clone()
    }

    /// Whether `isolation` has a cookie jar (for tests).
    pub fn has_cookie_jar(&self, isolation: &str) -> bool {
        self.cookies.jars.lock().by_isolation.contains_key(isolation)
    }

    /// Clear every per-session sensitive cache (on vault lock, workspace
    /// close or explicit reset): pooled authenticated connections, TLS/QUIC
    /// session tickets, tokens, Workload API SVIDs, cookies and prepared
    /// client identities.
    pub fn clear_sensitive_state(&self) {
        // First: from here on, a cookie store or a prepared TLS configuration
        // checked against an earlier epoch is refused. The Workload API
        // cache, the HTTP and HTTP/3 connection pools and the ticket caches
        // fence what is in flight the same way when they are cleared below
        // (the transports against the generations the execution took with
        // its epoch).
        self.epoch.fetch_add(1, Ordering::SeqCst);
        self.http.pool.clear();
        self.http.tickets.clear();
        self.h3.clear();
        if let Some(c) = &self.grpc_channels {
            c.clear();
        }
        self.tokens.clear();
        self.workload.clear();
        self.tls.lock().clear();
        self.cookies.jars.lock().by_isolation.clear();
    }

    /// Clear one workspace's caches (on workspace delete). A cookie store of
    /// an execution in that workspace that started before this is refused.
    pub fn clear_isolation(&self, isolation: &str) {
        self.http.pool.clear_isolation(isolation);
        self.http.tickets.clear_isolation(isolation);
        self.h3.clear_isolation(isolation);
        self.cookies.clear_isolation(isolation);
    }

    /// Session tickets held for 0-RTT, over TCP and QUIC (for tests and the
    /// lock check).
    pub fn session_tickets_held(&self) -> usize {
        self.http.tickets.tickets_held() + self.h3.tickets.tickets_held()
    }
}
