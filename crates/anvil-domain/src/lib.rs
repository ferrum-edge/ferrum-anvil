//! Versioned data contracts shared by the Anvil desktop shell, CLI, collection
//! runner and load workers.
//!
//! These types are the single source for the JSON Schemas published under
//! `contracts/schemas/` and for the generated TypeScript bindings used by the
//! renderer. Every persistent object carries a stable id, schema version,
//! timestamps and explicit ownership references.
//!
//! Design rules enforced by these contracts (see the build plan §5, §9, §10):
//! * transport completion, application status and assertion results are kept
//!   distinct ([`outcome::ExecutionOutcome`]);
//! * every attempt records a typed [`execution::DispatchState`] rather than a
//!   message-derived guess;
//! * a measurement that was not observed is `None`, never a fabricated zero;
//! * secrets are typed references ([`secret::SensitiveValue`]), never plain
//!   exportable strings.

pub mod assertions;
pub mod auth;
pub mod diagnostics;
pub mod events;
pub mod execution;
pub mod ids;
pub mod integration;
pub mod load;
pub mod outcome;
pub mod proxy_protocol;
pub mod request;
pub mod runner;
pub mod schema;
pub mod secret;
pub mod settings;
pub mod tls;
pub mod workload;
pub mod workspace;

pub use ids::Id;

/// Version of the persisted/exported object schema. Bump with a migration.
pub const SCHEMA_VERSION: u32 = 1;

/// Version of the transport adapter event contract.
pub const ADAPTER_CONTRACT_VERSION: u32 = 1;
