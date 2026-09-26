//! The session-ticket cache behind TLS 1.3 / QUIC 0-RTT early data.
//!
//! Early data needs a ticket from an earlier connection to the same server,
//! and rustls resumes a ticket only when the connection uses the same
//! certificate verifier and client-certificate resolver *instances* that
//! obtained it. A [`ResumptionContext`] therefore keeps one verifier, one
//! resolver and one ticket store per isolation key; the observing verifier's
//! evidence is routed to the connection that holds the context's handshake
//! gate, so concurrent handshakes of one context are serialized (handshakes of
//! other contexts are not).
//!
//! Isolation: a context — and so every ticket — belongs to exactly one
//! workspace isolation, transport (a QUIC ticket carries the server's QUIC
//! transport parameters and is only offered to its QUIC listener), host and
//! port, TLS profile fingerprint (trust anchors, verification, SPIFFE
//! identity, SNI override, minimum version and the client certificate chain)
//! and ALPN list. Tickets live in memory only: they are never persisted,
//! exported or shared, and [`TicketCache::clear`] drops them with the vault
//! lock, as pooled connections and OAuth tokens are dropped.

use crate::tls::{self, ObservationHandle, ObservingClientCert, ObservingVerifier, PreparedTls, SlotCell, SlotHandle};
use anvil_domain::execution::TransportFailure;
use parking_lot::Mutex;
use rustls::client::{ClientSessionMemoryCache, ClientSessionStore, Tls12ClientSessionValue, Tls13ClientSessionValue};
use rustls::{ClientConfig, NamedGroup};
use rustls_pki_types::ServerName;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

/// Tickets kept per context (rustls' own in-memory cache keeps 8 per server).
const MAX_TICKETS: usize = 8;
/// Contexts kept before an arbitrary one is dropped (each holds at most 8 tickets).
const MAX_CONTEXTS: usize = 256;

/// The transport a ticket was issued on; QUIC and TCP tickets never mix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TicketTransport {
    Quic,
    Tls,
}

/// In-memory session tickets and resumption contexts of one transport.
#[derive(Default)]
pub struct TicketCache {
    contexts: Mutex<HashMap<String, Arc<ResumptionContext>>>,
}

impl TicketCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Forget every ticket (vault lock, reset).
    pub fn clear(&self) {
        self.contexts.lock().clear();
    }

    /// Forget the tickets of one workspace isolation.
    pub fn clear_isolation(&self, isolation: &str) {
        let prefix = format!("{isolation}|");
        self.contexts.lock().retain(|k, _| !k.starts_with(&prefix));
    }

    /// Session tickets currently held, over all contexts.
    pub fn tickets_held(&self) -> usize {
        self.contexts.lock().values().map(|c| c.store.len()).sum()
    }

    /// Resumption contexts currently held.
    pub fn contexts(&self) -> usize {
        self.contexts.lock().len()
    }

    /// The context for one isolation key, created on first use.
    pub(crate) fn context(
        &self,
        isolation: &str,
        transport: TicketTransport,
        host: &str,
        port: u16,
        prepared: &PreparedTls,
        alpn: &[&str],
    ) -> Arc<ResumptionContext> {
        let key = format!(
            "{isolation}|{}|{}:{port}|{}|{}|{}",
            match transport {
                TicketTransport::Quic => "quic",
                TicketTransport::Tls => "tls",
            },
            host.to_ascii_lowercase(),
            prepared.profile_key,
            prepared.fingerprint,
            alpn.join(",")
        );
        let mut map = self.contexts.lock();
        if let Some(c) = map.get(&key) {
            return c.clone();
        }
        if map.len() >= MAX_CONTEXTS
            && let Some(k) = map.keys().next().cloned()
        {
            map.remove(&k);
        }
        let ctx = Arc::new(ResumptionContext::new(prepared));
        map.insert(key, ctx.clone());
        ctx
    }
}

/// One isolation key's stable verifier, resolver and ticket store.
pub(crate) struct ResumptionContext {
    cell: Arc<SlotCell>,
    verifier: Arc<ObservingVerifier>,
    resolver: Arc<ObservingClientCert>,
    pub(crate) store: Arc<TicketStore>,
    gate: Arc<tokio::sync::Mutex<()>>,
}

/// Held from the start of a context's handshake until it completed or
/// failed; routes the context's verifier to this connection's evidence.
pub(crate) struct HandshakeGuard {
    _gate: tokio::sync::OwnedMutexGuard<()>,
}

impl ResumptionContext {
    fn new(prepared: &PreparedTls) -> Self {
        let cell = SlotCell::new(Arc::new(Mutex::new(SlotHandle::default())));
        let (verifier, resolver) = tls::stable_identity(prepared, cell.clone());
        ResumptionContext { cell, verifier, resolver, store: Arc::new(TicketStore::default()), gate: Arc::new(tokio::sync::Mutex::new(())) }
    }

    /// Wait for the handshake gate, then route the verifier and resolver to
    /// `handle`'s evidence and forget which ticket the previous connection took.
    pub(crate) async fn begin(&self, handle: &ObservationHandle) -> HandshakeGuard {
        let gate = self.gate.clone().lock_owned().await;
        self.cell.route_to(handle.slot());
        self.store.reset_take();
        HandshakeGuard { _gate: gate }
    }

    /// A client config that resumes from (and stores into) this context, and
    /// offers early data when `early_data` and the ticket allows it.
    pub(crate) fn config(
        &self,
        prepared: &PreparedTls,
        alpn: &[&str],
        tls13_only: bool,
        early_data: bool,
    ) -> Result<ClientConfig, TransportFailure> {
        tls::resumable_config(prepared, self.verifier.clone(), self.resolver.clone(), self.store.clone(), alpn, tls13_only, early_data)
    }
}

/// TLS 1.3 tickets of one context (one server name), newest last, plus what
/// the evidence needs: how many arrived, what the newest allows, and whether
/// the current connection took one.
#[derive(Debug, Default)]
pub(crate) struct TicketStore {
    /// Key-exchange hints and TLS 1.2 sessions (rustls' own cache).
    other: OtherSessions,
    tls13: Mutex<VecDeque<Tls13ClientSessionValue>>,
    received: AtomicU32,
    newest_max_early: Mutex<Option<u32>>,
    taken: Mutex<Option<u32>>,
}

#[derive(Debug)]
struct OtherSessions(ClientSessionMemoryCache);

impl Default for OtherSessions {
    fn default() -> Self {
        OtherSessions(ClientSessionMemoryCache::new(4))
    }
}

impl TicketStore {
    pub(crate) fn len(&self) -> usize {
        self.tls13.lock().len()
    }

    /// Tickets that arrived since the store was created.
    pub(crate) fn received(&self) -> u32 {
        self.received.load(Ordering::SeqCst)
    }

    /// `max_early_data_size` of the newest ticket that arrived.
    pub(crate) fn newest_max_early(&self) -> Option<u32> {
        *self.newest_max_early.lock()
    }

    /// `max_early_data_size` of the ticket the current connection took, when it took one.
    pub(crate) fn taken(&self) -> Option<u32> {
        *self.taken.lock()
    }

    fn reset_take(&self) {
        *self.taken.lock() = None;
    }
}

impl ClientSessionStore for TicketStore {
    fn set_kx_hint(&self, server_name: ServerName<'static>, group: NamedGroup) {
        self.other.0.set_kx_hint(server_name, group);
    }

    fn kx_hint(&self, server_name: &ServerName<'_>) -> Option<NamedGroup> {
        self.other.0.kx_hint(server_name)
    }

    fn set_tls12_session(&self, server_name: ServerName<'static>, value: Tls12ClientSessionValue) {
        self.other.0.set_tls12_session(server_name, value);
    }

    fn tls12_session(&self, server_name: &ServerName<'_>) -> Option<Tls12ClientSessionValue> {
        self.other.0.tls12_session(server_name)
    }

    fn remove_tls12_session(&self, server_name: &ServerName<'static>) {
        self.other.0.remove_tls12_session(server_name);
    }

    fn insert_tls13_ticket(&self, _server_name: ServerName<'static>, value: Tls13ClientSessionValue) {
        *self.newest_max_early.lock() = Some(value.max_early_data_size());
        let mut q = self.tls13.lock();
        if q.len() >= MAX_TICKETS {
            q.pop_front();
        }
        q.push_back(value);
        self.received.fetch_add(1, Ordering::SeqCst);
    }

    fn take_tls13_ticket(&self, _server_name: &ServerName<'static>) -> Option<Tls13ClientSessionValue> {
        let t = self.tls13.lock().pop_back();
        if let Some(v) = &t {
            *self.taken.lock() = Some(v.max_early_data_size());
        }
        t
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::TlsSettings;

    fn prepared(verify: bool) -> PreparedTls {
        crate::init();
        tls::prepare(&TlsSettings { verify, use_system_roots: false, ..Default::default() }).expect("profile")
    }

    #[test]
    fn contexts_are_isolated_by_every_key_component() {
        let cache = TicketCache::new();
        let p = prepared(false);
        let other_profile = tls::prepare(&TlsSettings {
            verify: false,
            use_system_roots: false,
            server_name_override: Some("other.test".into()),
            ..Default::default()
        })
        .expect("profile");
        let a = cache.context("ws-a", TicketTransport::Quic, "Example.test", 443, &p, &["h3"]);
        assert!(Arc::ptr_eq(&a, &cache.context("ws-a", TicketTransport::Quic, "example.test", 443, &p, &["h3"])));
        for b in [
            cache.context("ws-b", TicketTransport::Quic, "example.test", 443, &p, &["h3"]),
            cache.context("ws-a", TicketTransport::Tls, "example.test", 443, &p, &["h3"]),
            cache.context("ws-a", TicketTransport::Quic, "example.test", 8443, &p, &["h3"]),
            cache.context("ws-a", TicketTransport::Quic, "other.test", 443, &p, &["h3"]),
            cache.context("ws-a", TicketTransport::Quic, "example.test", 443, &other_profile, &["h3"]),
            cache.context("ws-a", TicketTransport::Tls, "example.test", 443, &p, &["h2"]),
        ] {
            assert!(!Arc::ptr_eq(&a, &b), "a context must not be shared across isolation keys");
            assert!(!Arc::ptr_eq(&a.store, &b.store));
            assert!(!Arc::ptr_eq(&a.verifier, &b.verifier), "tickets resume only with their own verifier");
        }
        assert_eq!(cache.contexts(), 7);
        cache.clear_isolation("ws-b");
        assert_eq!(cache.contexts(), 6);
        cache.clear();
        assert_eq!(cache.contexts(), 0);
        assert_eq!(cache.tickets_held(), 0);
    }
}
