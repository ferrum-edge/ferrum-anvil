//! Anvil local persistence.
//!
//! * [`vault`] — profile header, data-key wrapping (passphrase + recovery key
//!   or OS keychain), unlock/recovery;
//! * [`store`] — encrypted SQLite object store with backend-enforced locking,
//!   durable migrations, history retention and restore checkpoints;
//! * [`crypto`] — XChaCha20-Poly1305 envelopes and Argon2id derivation.

pub mod crypto;
pub mod store;
pub mod vault;

pub use crypto::{KdfParams, Key};
pub use store::{Store, StoreError, StoreTx, kind};
pub use vault::{ProfileHeader, VaultError};

/// Default platform data directory for Anvil profiles.
pub fn default_data_dir() -> std::path::PathBuf {
    let base = if cfg!(target_os = "macos") {
        std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join("Library/Application Support"))
    } else if cfg!(target_os = "windows") {
        std::env::var_os("APPDATA").map(std::path::PathBuf::from)
    } else {
        std::env::var_os("XDG_DATA_HOME")
            .map(std::path::PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(".local/share")))
    };
    base.unwrap_or_else(|| std::path::PathBuf::from(".")).join("Ferrum Anvil")
}
