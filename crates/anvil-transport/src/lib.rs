//! Anvil's instrumented protocol adapters.
//!
//! All network activity runs here (never in the UI webview). Every adapter
//! produces typed evidence: measured phases, typed failures, dispatch state,
//! TLS observations and byte counts. Adapters never fabricate a measurement
//! they did not observe.

// `TransportFailure` (and failure + partial evidence tuples) are deliberately
// returned by value: they are the typed evidence every adapter produces and
// are consumed once, not propagated through hot paths.

pub mod certs;
pub mod connector;
pub mod decode;
pub mod dns;
pub mod dtls;
pub mod errors;
pub mod grpc;
pub mod grpc_web;
pub mod h3;
pub mod hbone;
pub mod http;
pub mod masque;
pub mod net;
pub mod proxy_protocol;
pub mod rawtcp;
pub mod recorder;
pub mod session;
pub mod spiffe;
pub mod sse;
pub mod stats;
pub mod tls;
pub mod udp;
pub mod ws;

pub use recorder::{EventCtx, EventFn};

/// Adapter identity recorded in every execution record.
pub const ADAPTER_VERSION: &str = concat!("anvil-transport/", env!("CARGO_PKG_VERSION"));

/// Install the process-wide rustls crypto provider (idempotent).
pub fn init() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}
