//! Anvil's native load engine.
//!
//! Every send goes through [`anvil_engine::Engine::execute`] — the same
//! preparation, per-send auth generation (fresh HMAC nonces, DPoP proofs, JWT
//! time claims), TLS policy, transport and outcome classifier as a manual
//! Send — so a load run cannot send different bytes than the request editor
//! (LOAD-008).
//!
//! * [`executor`]: closed (virtual users), open (arrival rate) and iteration
//!   workloads; weighted mixes, sequential chains with extraction, datasets,
//!   warmup exclusion, abort rules, connection modes; bounded everywhere.
//! * [`metrics`]: mergeable HDR histograms per shard, merged before any
//!   percentile is computed; censored timeouts; bounded failure samples.
//! * [`worker`] / [`controller`]: the `anvil-load-worker` process (job on
//!   stdin, never argv; NDJSON progress/report on stdout) and the library
//!   side that spawns it, forwards cancel and survives a worker crash.
//! * [`report`] / [`html`]: JSON (with integrity hash), CSV and standalone
//!   offline HTML reports.
//! * [`compare`]: run comparison that refuses to equate incompatible runs.
//!
//! See `docs/load.md` for semantics and measured numbers.

pub mod compare;
pub mod controller;
pub mod dataset;
pub mod executor;
pub mod health;
pub mod html;
pub mod job;
pub mod metrics;
pub mod report;
pub mod schedule;
pub mod worker;

pub use compare::{Comparison, compare};
pub use controller::LoadController;
pub use dataset::{Dataset, DatasetFormat};
pub use executor::{LoadJob, LoadRun, Progress, ProgressSink, RunOptions, validate_plan};
pub use job::WorkerJob;

/// Engine identifier recorded in every report.
pub const ENGINE_NAME: &str = "anvil-native";

/// Engine build identity: load crate version plus the transport adapter
/// version (both change measurement semantics).
pub fn engine_version() -> String {
    format!("anvil-load/{}+{}", env!("CARGO_PKG_VERSION"), anvil_transport::ADAPTER_VERSION)
}

#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    /// The plan or job is invalid; nothing was sent.
    #[error("invalid load plan: {0}")]
    Invalid(String),
    /// Load runs never start without an explicit user acknowledgement of the
    /// destination, planned rate and ownership reminder.
    #[error("load run not acknowledged: the user must confirm the destination, planned load and authorization before traffic starts")]
    NotAcknowledged,
    /// A requested capability is not implemented; refused rather than faked.
    #[error("unsupported: {0}")]
    Unsupported(String),
    #[error("worker I/O: {0}")]
    Io(String),
    #[error("worker protocol: {0}")]
    Protocol(String),
    #[error("report: {0}")]
    Report(String),
}
