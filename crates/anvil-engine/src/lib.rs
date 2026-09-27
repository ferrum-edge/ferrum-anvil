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
use anvil_transport::http::HttpTransport;
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
    cookies: Mutex<HashMap<String, cookie_store::CookieStore>>,
    /// Advanced by [`Engine::clear_sensitive_state`] before it clears
    /// anything (see [`SensitiveEpoch`]).
    epoch: AtomicU64,
}

/// The engine's sensitive-state epoch when an execution started. A lock
/// ([`Engine::clear_sensitive_state`]) starts a new epoch, and what an
/// execution of an earlier epoch receives afterwards (cookies) is not kept.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SensitiveEpoch(u64);

impl Default for Engine {
    fn default() -> Self {
        Self::new()
    }
}

impl Engine {
    pub fn new() -> Self {
        anvil_transport::init();
        Engine {
            http: Arc::new(HttpTransport::new()),
            h3: anvil_transport::h3::H3Transport::new(),
            tokens: Arc::new(anvil_auth::oauth::TokenCache::new()),
            grpc_channels: None,
            workload: Arc::new(workload::WorkloadCache::default()),
            tls: Mutex::new(HashMap::new()),
            cookies: Mutex::new(HashMap::new()),
            epoch: AtomicU64::new(0),
        }
    }

    /// The current sensitive-state epoch, taken when an execution starts.
    pub fn sensitive_epoch(&self) -> SensitiveEpoch {
        SensitiveEpoch(self.epoch.load(Ordering::SeqCst))
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
    /// leave the superseded key material behind.
    pub fn prepared_tls(&self, key: &str, s: &TlsSettings) -> Result<Arc<PreparedTls>, TransportFailure> {
        if let Some(p) = self.tls.lock().get(key) {
            return Ok(p.clone());
        }
        let mut p = anvil_transport::tls::prepare(s)?;
        p.profile_key = key.to_string();
        let p = Arc::new(p);
        let mut cache = self.tls.lock();
        if let Some((variant, _)) = key.rsplit_once('|') {
            let prefix = format!("{variant}|");
            cache.retain(|k, _| !k.starts_with(&prefix));
        }
        cache.insert(key.to_string(), p.clone());
        Ok(p)
    }

    pub fn cookie_header(&self, isolation: &str, t: &prepare::Target) -> Option<String> {
        let url = url::Url::parse(&t.url()).ok()?;
        let jars = self.cookies.lock();
        let jar = jars.get(isolation)?;
        let pairs: Vec<String> = jar.get_request_values(&url).map(|(n, v)| format!("{n}={v}")).collect();
        if pairs.is_empty() { None } else { Some(pairs.join("; ")) }
    }

    /// Keep the response's cookies in the workspace jar, unless the jar was
    /// cleared since `epoch` (a lock while the request was in flight).
    pub fn store_cookies(&self, epoch: SensitiveEpoch, isolation: &str, t: &prepare::Target, r: &ResponseRecord) {
        let Ok(url) = url::Url::parse(&t.url()) else { return };
        let mut jars = self.cookies.lock();
        // Checked under the jar's lock: a clear either advanced the epoch
        // before this point or empties the jar after it.
        if self.epoch.load(Ordering::SeqCst) != epoch.0 {
            return;
        }
        let jar = jars.entry(isolation.to_string()).or_default();
        for v in r.header_values("set-cookie") {
            let _ = jar.parse(v, &url);
        }
    }

    /// Clear every per-session sensitive cache (on vault lock, workspace
    /// close or explicit reset): pooled authenticated connections, TLS/QUIC
    /// session tickets, tokens, Workload API SVIDs, cookies and prepared
    /// client identities.
    pub fn clear_sensitive_state(&self) {
        // First: from here on, a cookie store checked against an earlier
        // epoch is refused. The Workload API cache, the HTTP and HTTP/3
        // connection pools and the ticket caches fence what is in flight the
        // same way when they are cleared below.
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
        self.cookies.lock().clear();
    }

    pub fn clear_isolation(&self, isolation: &str) {
        self.http.pool.clear_isolation(isolation);
        self.http.tickets.clear_isolation(isolation);
        self.h3.clear_isolation(isolation);
        self.cookies.lock().remove(isolation);
    }

    /// Session tickets held for 0-RTT, over TCP and QUIC (for tests and the
    /// lock check).
    pub fn session_tickets_held(&self) -> usize {
        self.http.tickets.tickets_held() + self.h3.tickets.tickets_held()
    }
}
