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
mod session_preview;
pub mod sessions;
pub mod settings;
pub mod vars;
pub mod workload;

use anvil_domain::execution::{ExecutionRecord, ResponseRecord, TransportFailure};
use anvil_domain::request::Protocol;
use anvil_transport::grpc::ChannelUse;
use anvil_transport::http::{CacheFence, HttpTransport};
use anvil_transport::recorder::EventCtx;
use anvil_transport::tls::{PreparedTls, TlsSettings};
use bytes::Bytes;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::pin::Pin;
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
    /// Prepared TLS configurations by isolation (workspace) and profile key
    /// (see [`Engine::prepared_tls`]).
    tls: Mutex<HashMap<(String, String), Arc<PreparedTls>>>,
    cookies: CookieJars,
    /// Advanced by [`Engine::clear_sensitive_state`] before it clears
    /// anything (see [`SensitiveEpoch`]).
    epoch: Arc<AtomicU64>,
    /// Tells this engine's [`ContextEpoch`]s from other engines' ones.
    id: u64,
}

/// Source of `Engine::id`.
static NEXT_ENGINE_ID: AtomicU64 = AtomicU64::new(0);

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
    /// delete) when it removes that isolation's jar, before that isolation's
    /// prepared TLS configurations are dropped; 0 when never cleared.
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

/// The engine's sensitive-state epoch when an execution started (or when its
/// context was built, see [`ContextEpoch`]), with the transports' cache
/// generations taken at the same point. A lock
/// ([`Engine::clear_sensitive_state`]) starts a new epoch, and what an
/// execution of an earlier epoch prepares or receives afterwards is not
/// kept: its cookies, its prepared TLS material (client identity keys), its
/// connections, its gRPC channels and its session tickets. A workspace
/// delete ([`Engine::clear_isolation`]) does not start a new epoch: it
/// starts a new generation of that workspace's cookie jar and prepared TLS
/// configurations (held by an execution's epoch, see
/// [`Engine::execution_epoch`]) and of the transports' caches for that
/// workspace, and an execution in it that started (or whose context was
/// built) before the delete keeps none of its cookies, prepared TLS
/// material, connections, gRPC channels or session tickets. Other
/// workspaces' executions are not affected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SensitiveEpoch {
    epoch: u64,
    transport: CacheFence,
    /// The generation of the engine's gRPC channels (0 when it keeps none).
    channels: u64,
    /// The generation of the execution's workspace (its cookie jar and its
    /// prepared TLS configurations); `None` for an epoch taken for no
    /// workspace, which keeps no cookies and caches no TLS material.
    jar: Option<u64>,
}

/// An execution epoch taken when an execution context was built
/// ([`Engine::context_epoch`]), carried by [`ExecutionContext::epoch`]. An
/// execution of that context on the engine that took it, in the workspace it
/// was taken for, starts with it: a lock or a delete of the workspace that
/// lands after the context was built, even before the execution starts,
/// fences that execution as one in flight. It holds nothing else: an
/// execution on another engine (a load run's), or of a context whose
/// isolation was changed since, takes its epoch when it starts.
#[derive(Clone, Debug)]
pub struct ContextEpoch {
    engine: u64,
    isolation: String,
    epoch: SensitiveEpoch,
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
            id: NEXT_ENGINE_ID.fetch_add(1, Ordering::Relaxed),
        }
    }

    /// The current sensitive-state epoch, for work outside a workspace
    /// execution (it keeps no cookies).
    pub fn sensitive_epoch(&self) -> SensitiveEpoch {
        self.snapshot(None, || {})
    }

    /// The current sensitive-state epoch with the generation of
    /// `isolation`'s cookie jar, taken when an execution in that workspace
    /// starts.
    pub fn execution_epoch(&self, isolation: &str) -> SensitiveEpoch {
        self.snapshot(Some(isolation), || {})
    }

    /// The execution epoch of `isolation`, taken when an execution context
    /// for that workspace is built, before anything is read for it (see
    /// [`ExecutionContext::epoch`]). A context built before a workspace
    /// delete but executed after it keeps nothing for the deleted workspace;
    /// one built after the delete (a workspace restored with the same id)
    /// is not affected.
    pub fn context_epoch(&self, isolation: &str) -> ContextEpoch {
        ContextEpoch { engine: self.id, isolation: isolation.to_string(), epoch: self.execution_epoch(isolation) }
    }

    /// The epoch an execution of `ctx` starts with: the one taken when the
    /// context was built, when this engine took it for the context's
    /// workspace; otherwise the current one.
    pub(crate) fn epoch_for(&self, ctx: &ExecutionContext) -> SensitiveEpoch {
        match &ctx.epoch {
            Some(c) if c.engine == self.id && c.isolation == ctx.isolation => c.epoch,
            _ => self.execution_epoch(&ctx.isolation),
        }
    }

    /// The epoch, `isolation`'s jar generation and the transports' and gRPC
    /// channels' generations, all taken between the same two points: no lock
    /// and no delete of `isolation` started in between. A snapshot never
    /// takes a transport or channel generation newer than its jar
    /// generation; a snapshot taken during a delete is post-delete for
    /// cookies and TLS material and keeps no connection, ticket or channel.
    /// `between` runs after the epoch and the jar generation are read (a test
    /// lands a clear there).
    fn snapshot(&self, isolation: Option<&str>, mut between: impl FnMut()) -> SensitiveEpoch {
        loop {
            let epoch = self.epoch.load(Ordering::SeqCst);
            let jar = isolation.map(|i| self.cookies.generation(i));
            between();
            let transport = CacheFence { tcp: self.http.cache_generations(), quic: self.h3.cache_generations() };
            let channels = self.grpc_channels.as_ref().map_or(0, |c| c.generation());
            // A lock advances the epoch, and a workspace delete its jar's
            // generation, before it clears the transports and channels: an
            // unchanged epoch and jar generation mean the transports' and
            // channels' generations are not newer than them. Otherwise the
            // execution could keep connections and tickets for a workspace
            // whose delete refuses its cookies.
            if self.epoch.load(Ordering::SeqCst) == epoch && isolation.map(|i| self.cookies.generation(i)) == jar {
                return SensitiveEpoch { epoch, transport, channels, jar };
            }
        }
    }

    /// The engine's gRPC channels for a call of an execution of `epoch` in
    /// `isolation`; `None` when the engine keeps none.
    pub(crate) fn grpc_channels_for(&self, epoch: SensitiveEpoch, isolation: &str) -> Option<ChannelUse> {
        let channels = self.grpc_channels.clone()?;
        Some(ChannelUse { channels, isolation: isolation.to_string(), generation: epoch.channels })
    }

    fn is_current(&self, epoch: SensitiveEpoch) -> bool {
        self.epoch.load(Ordering::SeqCst) == epoch.epoch
    }

    /// Execute a request of any supported protocol. Each protocol's execution
    /// runs boxed, so the future a caller awaits stays small: a caller that
    /// awaits several executions inline (a gRPC call's is large) does not
    /// hold their state on its own stack.
    pub async fn execute(&self, ctx: &ExecutionContext, events: EventCtx, cancel: CancellationToken) -> ExecutionOutput {
        match ctx.spec.protocol {
            Protocol::Http => self.boxed_http(ctx, events, cancel).await,
            Protocol::WebSocket | Protocol::Grpc | Protocol::Sse | Protocol::Tcp | Protocol::Udp => {
                self.boxed_session(ctx, events, cancel).await
            }
        }
    }

    /// An HTTP execution, boxed in a frame of its own: [`Engine::execute`]'s
    /// frame never holds it, nor a session's beside it.
    fn boxed_http<'a>(
        &'a self,
        ctx: &'a ExecutionContext,
        events: EventCtx,
        cancel: CancellationToken,
    ) -> Pin<Box<impl Future<Output = ExecutionOutput> + 'a>> {
        Box::pin(http_exec::execute(self, ctx, events, cancel))
    }

    /// A session execution (WebSocket, gRPC, SSE, TCP, UDP), boxed as
    /// [`Engine::boxed_http`] is.
    fn boxed_session<'a>(
        &'a self,
        ctx: &'a ExecutionContext,
        events: EventCtx,
        cancel: CancellationToken,
    ) -> Pin<Box<impl Future<Output = ExecutionOutput> + 'a>> {
        Box::pin(sessions::execute(self, ctx, events, cancel))
    }

    /// Validated TLS material, cached per isolation (workspace) by profile
    /// key: the material holds a client identity's private key and its
    /// connections' session store (key-exchange hints only: they never
    /// resume a session), so one workspace never uses another's, and a
    /// workspace delete drops its entries. A key
    /// `<profile variant>|<material hash>` replaces an entry of the same
    /// variant with other material in the same isolation, so a
    /// rotated Workload API SVID does not leave the superseded key material
    /// behind. For an execution of an earlier `epoch` (a lock, or a delete of
    /// its workspace, since it started) or of no workspace, the material is
    /// prepared but neither taken from the cache nor cached.
    pub fn prepared_tls(
        &self,
        epoch: SensitiveEpoch,
        isolation: &str,
        key: &str,
        s: &TlsSettings,
    ) -> Result<Arc<PreparedTls>, TransportFailure> {
        let entry = (isolation.to_string(), key.to_string());
        {
            let cache = self.tls.lock();
            if let Some(p) = cache.get(&entry).filter(|_| self.tls_cacheable(epoch, isolation)) {
                return Ok(p.clone());
            }
        }
        let mut p = anvil_transport::tls::prepare(s)?;
        p.profile_key = key.to_string();
        let p = Arc::new(p);
        let mut cache = self.tls.lock();
        // Checked under the cache's lock, before the variant's entries are
        // dropped: a lock or a delete of the workspace either advanced its
        // counter before this point or empties the cache after it.
        if !self.tls_cacheable(epoch, isolation) {
            return Ok(p);
        }
        if let Some((variant, _)) = key.rsplit_once('|') {
            let prefix = format!("{variant}|");
            cache.retain(|(i, k), _| i != isolation || !k.starts_with(&prefix));
        }
        cache.insert(entry, p.clone());
        Ok(p)
    }

    /// Whether an execution of `epoch` in `isolation` may use and fill the
    /// prepared TLS cache: no lock and no delete of its workspace since it
    /// started. Called under the cache's lock.
    fn tls_cacheable(&self, epoch: SensitiveEpoch, isolation: &str) -> bool {
        self.is_current(epoch) && epoch.jar == Some(self.cookies.generation(isolation))
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

    /// Clear one workspace's caches (on workspace delete). An execution in
    /// that workspace that started before this keeps nothing it prepares or
    /// receives afterwards in them: no cookie, prepared TLS configuration,
    /// pooled connection, gRPC channel or session ticket. The sensitive-state
    /// epoch is not advanced, so other workspaces' executions are not
    /// affected.
    pub fn clear_isolation(&self, isolation: &str) {
        // First: from here on, a cookie store or a prepared TLS configuration
        // of an execution in this workspace that started earlier is refused.
        self.cookies.clear_isolation(isolation);
        self.tls.lock().retain(|(i, _), _| i != isolation);
        self.http.pool.clear_isolation(isolation);
        self.http.tickets.clear_isolation(isolation);
        self.h3.clear_isolation(isolation);
        if let Some(c) = &self.grpc_channels {
            c.clear_isolation(isolation);
        }
    }

    /// Session tickets held for resumption (for tests and the lock check):
    /// those of the 0-RTT ticket caches over TCP and QUIC. Outside the
    /// early-data opt-in none is kept: a prepared TLS configuration's session
    /// store keeps only key-exchange hints (see
    /// [`anvil_transport::tls::PreparedTls`]).
    pub fn session_tickets_held(&self) -> usize {
        self.http.tickets.tickets_held() + self.h3.tickets.tickets_held()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A workspace delete that lands after an execution read its jar's
    /// generation but before it read the transports' generations: the
    /// execution's epoch is taken again, after the delete, so it does not
    /// refuse its cookies while keeping its connections and tickets.
    #[tokio::test]
    async fn an_execution_epoch_is_taken_on_one_side_of_a_workspace_delete() {
        let e = Engine::new();
        let mut deleted = false;
        let epoch = e.snapshot(Some("workspace-a"), || {
            if !deleted {
                deleted = true;
                e.clear_isolation("workspace-a");
            }
        });
        assert!(deleted);
        assert_eq!(epoch, e.execution_epoch("workspace-a"), "the epoch mixes generations from both sides of the delete");
        assert_eq!(epoch.jar, Some(1));
    }

    /// A context's epoch holds for the engine that took it and the workspace
    /// it was taken for: after that workspace's delete, an execution of the
    /// context still starts with the epoch from before it. Another engine, or
    /// a context moved to another workspace, takes a current epoch, and a
    /// context built after the delete starts after it.
    #[tokio::test]
    async fn a_context_epoch_holds_on_its_engine_for_its_workspace_only() {
        let (e, other) = (Engine::new(), Engine::new());
        let mut ctx = ExecutionContext::standalone(anvil_domain::request::RequestSpec::http("GET", "http://127.0.0.1:1/"));
        ctx.isolation = "workspace-a".into();
        ctx.epoch = Some(e.context_epoch("workspace-a"));
        e.clear_isolation("workspace-a");
        other.clear_isolation("workspace-a");
        assert_eq!(e.epoch_for(&ctx).jar, Some(0), "the context's epoch is not the one taken before the delete");
        assert_eq!(other.epoch_for(&ctx), other.execution_epoch("workspace-a"));
        let mut moved = ctx.clone();
        moved.isolation = "workspace-b".into();
        assert_eq!(e.epoch_for(&moved), e.execution_epoch("workspace-b"));
        ctx.epoch = Some(e.context_epoch("workspace-a"));
        assert_eq!(e.epoch_for(&ctx), e.execution_epoch("workspace-a"), "a context built after the delete starts before it");
        assert_eq!(e.epoch_for(&ctx).jar, Some(1));
    }
}
