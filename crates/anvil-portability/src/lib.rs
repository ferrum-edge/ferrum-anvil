//! Portable workspaces and whole-app backups.
//!
//! Bundle layout (zip):
//! ```text
//! manifest.json                 format/version, mode, counts, exclusions, placeholders, vault params
//! workspace/objects.json        object graph with sensitive literals replaced by placeholders
//! settings/portable.json        portable app settings (backups)
//! attachments/<sha256>          content-addressed attachments
//! history/records.jsonl         optional redacted run history
//! secrets/portable-vault.enc    optional Argon2id + XChaCha20-Poly1305 vault (never plaintext)
//! checksums.json                sha256 of every entry
//! ```
//! Checksums detect corruption; the vault's AEAD authenticates its contents
//! under the export passphrase. Neither proves who created the bundle.

pub mod bundle;
pub mod graph;
pub mod plan;
pub mod sanitize;
pub mod validate;

pub use bundle::{BundleError, BundleKind, ExportMode, ExportOptions, Manifest, Opened};
pub use graph::{PortableGraph, SecretValue};
pub use plan::{ConflictPolicy, ImportPlan};

pub const WORKSPACE_EXTENSION: &str = "anvil-workspace";
pub const BACKUP_EXTENSION: &str = "anvil-backup";
