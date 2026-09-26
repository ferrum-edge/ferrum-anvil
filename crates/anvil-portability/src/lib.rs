//! Portable workspaces and whole-app backups.
//!
//! Bundle layout (zip):
//! ```text
//! manifest.json                 format/version, mode, counts, exclusions, placeholders, vault params
//! workspace/objects.json        object graph with sensitive literals replaced by placeholders
//! attachments/<sha256>          content-addressed attachments
//! history/records.jsonl         optional redacted run history
//! secrets/portable-vault.enc    optional Argon2id + XChaCha20-Poly1305 vault (never plaintext)
//! checksums.json                sha256 of every entry
//! ```
//! Checksums detect corruption. An encrypted bundle's vault is sealed with
//! the SHA-256 of every other entry (manifest included) as associated data,
//! so it opens only inside the exact bundle it was exported with: a change to
//! any entry refuses the whole import before any value is restored. Entries
//! stay readable without the passphrase (only the vault is encrypted), and
//! nothing proves who created the bundle. `settings/portable.json` is never
//! written; it marks a legacy full backup, which is refused.

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
