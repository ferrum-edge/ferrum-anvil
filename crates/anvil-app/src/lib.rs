//! Application services for Ferrum Anvil, shared by the desktop shell and
//! the CLI. All security-relevant state (vault key, lock) lives here and in
//! `anvil-storage`; UI layers only call these services.

pub mod backup;
pub mod exec;
pub mod file_grants;
pub mod identity;
pub mod load;
pub mod port;
pub mod profiles;
pub mod runner;
pub mod specs;
pub mod token_files;
pub mod workspace;

use anvil_engine::Engine;
use anvil_storage::vault::ProfileHeader;
use anvil_storage::{Key, Store, StoreError};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("Anvil is locked")]
    Locked,
    #[error("{0} not found")]
    NotFound(String),
    #[error("{0}")]
    Invalid(String),
    #[error("{0}")]
    Vault(#[from] anvil_storage::VaultError),
    #[error("{0}")]
    Bundle(#[from] anvil_portability::BundleError),
    #[error("{0}")]
    Backup(#[from] backup::BackupError),
    #[error("storage: {0}")]
    Store(StoreError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    /// Linked-identity unlock policy refusals (typed; never a key problem).
    #[error("{0}")]
    Identity(#[from] identity::IdentityPolicyError),
    /// Interactive sign-in (browser flow) failures.
    #[error("{0}")]
    SignIn(#[from] anvil_identity::FlowError),
}

impl From<StoreError> for AppError {
    fn from(e: StoreError) -> Self {
        match e {
            StoreError::Locked => AppError::Locked,
            other => AppError::Store(other),
        }
    }
}

pub type Result<T> = std::result::Result<T, AppError>;

/// An opened profile: storage + the shared engine.
pub struct App {
    pub header: ProfileHeader,
    pub dir: PathBuf,
    pub store: Arc<Store>,
    pub engine: Arc<Engine>,
    /// Set by the desktop shell: a JWT-SVID token file is read only if the
    /// user bound it in the native dialog (see [`App::confine_token_files`]).
    confined_token_files: AtomicBool,
}

impl App {
    pub fn open(dir: PathBuf, header: ProfileHeader, key: Key) -> Result<App> {
        let store = Arc::new(Store::open(&dir, key)?);
        let app = App { header, dir, store, engine: Arc::new(Engine::new()), confined_token_files: AtomicBool::new(false) };
        app.ensure_settings()?;
        app.pin_attachment_blobs()?;
        Ok(app)
    }

    pub fn is_locked(&self) -> bool {
        self.store.is_locked()
    }

    /// Lock: drop the key and every cached credential/connection. Active
    /// runs must be canceled by the caller (policy: stop runs on lock).
    pub fn lock(&self) {
        self.store.lock();
        self.engine.clear_sensitive_state();
    }

    pub fn unlock(&self, key: Key) -> Result<()> {
        self.store.unlock(key)?;
        Ok(())
    }

    pub fn settings(&self) -> Result<anvil_domain::settings::AppSettings> {
        Ok(self.store.get(anvil_storage::kind::APP_SETTINGS, &settings_id())?.unwrap_or_default())
    }

    pub fn save_settings(&self, s: &anvil_domain::settings::AppSettings) -> Result<()> {
        self.store.put(anvil_storage::kind::APP_SETTINGS, &settings_id(), None, None, 0.0, s)?;
        Ok(())
    }

    fn ensure_settings(&self) -> Result<()> {
        if self.store.get::<anvil_domain::settings::AppSettings>(anvil_storage::kind::APP_SETTINGS, &settings_id())?.is_none() {
            self.save_settings(&Default::default())?;
        }
        Ok(())
    }
}

/// Fixed id of the singleton app-settings object.
pub fn settings_id() -> anvil_domain::Id {
    anvil_domain::Id(uuid::Uuid::from_u128(0x00000000_0000_7000_8000_000000000001))
}
