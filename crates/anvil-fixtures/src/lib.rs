//! Deterministic fault fixtures and ephemeral PKI for Anvil tests and the
//! local failure lab.
//!
//! This crate is lab/test-only. Release builds of the desktop app and CLI do
//! not depend on it (verified by the release artifact check).

pub mod dns;
pub mod dtls;
pub mod grpc;
pub mod h3server;
pub mod http;
pub mod log;
pub mod pki;
pub mod raw;
pub mod streams;
pub mod tlsserver;

pub use log::{GroundTruth, GroundTruthLog};
pub use pki::LabPki;
pub use tlsserver::{ClientAuth, TlsServerOptions};

/// Install the rustls provider for fixture servers (idempotent).
pub fn init() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}
