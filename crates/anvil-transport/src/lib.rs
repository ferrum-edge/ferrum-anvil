//! Anvil's instrumented protocol adapters.
//!
//! All network activity runs here (never in the UI webview). Every adapter
//! produces typed evidence: measured phases, typed failures, dispatch state,
//! TLS observations and byte counts. Adapters never fabricate a measurement
//! they did not observe.

pub mod certs;
pub mod connector;
pub mod decode;
pub mod dns;
pub mod errors;
pub mod http;
pub mod net;
pub mod recorder;
pub mod stats;
pub mod tls;

pub use recorder::{EventCtx, EventFn};

/// Adapter identity recorded in every execution record.
pub const ADAPTER_VERSION: &str = concat!("anvil-transport/", env!("CARGO_PKG_VERSION"));

/// Install the process-wide rustls crypto provider (idempotent).
pub fn init() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}
