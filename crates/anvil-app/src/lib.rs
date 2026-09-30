//! Application services for Ferrum Anvil, shared by the desktop shell and
//! the CLI. All security-relevant state (vault key, lock) lives here and in
//! `anvil-storage`; UI layers only call these services.

pub mod backup;
pub mod cleanup;
pub mod device_identity;
pub mod drift;
pub mod exec;
pub mod file_grants;
pub mod identity;
pub mod linked_files;
pub mod load;
pub mod logging;
pub mod port;
pub mod profiles;
pub mod runner;
pub mod specs;
pub mod standards;
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
    /// The caller canceled the operation before it wrote anything.
    #[error("canceled; nothing was written")]
    Canceled,
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
    /// Shared with every [`App::shared`] handle.
    confined_token_files: Arc<AtomicBool>,
    /// Load runs by workspace, for a lock or a workspace delete to stop.
    load_runs: Arc<load::LoadRuns>,
}

impl App {
    pub fn open(dir: PathBuf, header: ProfileHeader, key: Key) -> Result<App> {
        let store = Arc::new(Store::open(&dir, key)?);
        let confined_token_files = Arc::new(AtomicBool::new(false));
        let load_runs = Arc::default();
        let app = App { header, dir, store, engine: Arc::new(Engine::new()), confined_token_files, load_runs };
        app.ensure_settings()?;
        app.pin_attachment_blobs()?;
        app.clean_up_storage_on_open();
        Ok(app)
    }

    /// Another handle on this opened profile: the same store, engine and
    /// token-file confinement. Work moved to a blocking thread (see
    /// [`off_runtime`]) runs on one.
    pub(crate) fn shared(&self) -> App {
        App {
            header: self.header.clone(),
            dir: self.dir.clone(),
            store: self.store.clone(),
            engine: self.engine.clone(),
            confined_token_files: self.confined_token_files.clone(),
            load_runs: self.load_runs.clone(),
        }
    }

    pub fn is_locked(&self) -> bool {
        self.store.is_locked()
    }

    /// Lock: drop the key and every cached credential/connection, and stop
    /// every registered load run (see [`App::register_load_run`]). Other
    /// active runs must be canceled by the caller (policy: stop runs on lock).
    pub fn lock(&self) {
        self.store.lock();
        self.engine.clear_sensitive_state();
        self.stop_load_runs();
    }

    pub fn unlock(&self, key: Key) -> Result<()> {
        self.store.unlock(key)?;
        Ok(())
    }

    /// Unlock with `key` only if `gate` still allows it once the key is
    /// checked (see [`Store::unlock_if`]); otherwise `key` is not kept and
    /// the error is `Locked`.
    pub fn unlock_if(&self, key: Key, gate: impl FnOnce() -> bool) -> Result<()> {
        self.store.unlock_if(key, gate)?;
        Ok(())
    }

    pub fn settings(&self) -> Result<anvil_domain::settings::AppSettings> {
        Ok(self.store.get(anvil_storage::kind::APP_SETTINGS, &settings_id())?.unwrap_or_default())
    }

    pub fn save_settings(&self, s: &anvil_domain::settings::AppSettings) -> Result<()> {
        let mut next = s.clone();
        next.api_standards.legacy_rulesets.clear();
        self.store.put(anvil_storage::kind::APP_SETTINGS, &settings_id(), None, None, 0.0, &next)?;
        Ok(())
    }

    fn ensure_settings(&self) -> Result<()> {
        self.store.atomically(|tx| {
            let stored_settings: Option<anvil_domain::settings::AppSettings> = tx.get(anvil_storage::kind::APP_SETTINGS, &settings_id())?;
            let needs_settings = stored_settings.is_none();
            let mut settings = stored_settings.unwrap_or_default();
            let legacy = std::mem::take(&mut settings.api_standards.legacy_rulesets);
            if needs_settings || !legacy.is_empty() {
                let existing = tx.object_meta(anvil_storage::kind::API_RULESET)?;
                let mut order = existing.iter().map(|row| row.sort_key).fold(-1.0_f64, f64::max) + 1.0;
                let mut ids: std::collections::HashSet<String> = existing.into_iter().map(|row| row.id).collect();
                for ruleset in legacy {
                    let id = ruleset.id.to_string();
                    if ids.contains(&id) {
                        // A stored row has an `updated_at`; the legacy copy
                        // has only `added_at`, so those timestamps cannot be
                        // compared. Keep the existing row as authoritative.
                        tracing::warn!(id = %id, kept = "stored record", "legacy API ruleset id collides with an existing record");
                        continue;
                    }
                    if ruleset.text.len() > anvil_domain::settings::MAX_STORED_RULESET_BYTES {
                        tracing::warn!(
                            id = %id,
                            bytes = ruleset.text.len(),
                            limit = anvil_domain::settings::MAX_STORED_RULESET_BYTES,
                            "dropping oversized legacy API ruleset during migration"
                        );
                        continue;
                    }
                    tx.put(anvil_storage::kind::API_RULESET, &ruleset.id, None, None, order, &ruleset)?;
                    ids.insert(id);
                    order += 1.0;
                }
                tx.put(anvil_storage::kind::APP_SETTINGS, &settings_id(), None, None, 0.0, &settings)?;
            }
            Ok(())
        })?;
        Ok(())
    }
}

/// Run `f`, which waits on the store or derives a key, on a blocking thread,
/// so it never holds an async runtime worker: a long store transaction on
/// another thread (an import, a folder delete) then delays only the work
/// that waits for it, and the task awaiting `f` can still see a cancel. A
/// panic in `f` resumes in the caller; `Canceled` means the runtime shut down
/// before `f` started.
pub async fn off_runtime<T: Send + 'static>(f: impl FnOnce() -> Result<T> + Send + 'static) -> Result<T> {
    match tokio::task::spawn_blocking(f).await {
        Ok(r) => r,
        Err(e) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
        Err(_) => Err(AppError::Canceled),
    }
}

/// Run `f`, which waits on the store, from synchronous code that an async
/// task calls (a runner step's history record, a secret lookup): on a
/// worker of a multi-thread runtime, the worker first hands its other tasks
/// to another thread ([`tokio::task::block_in_place`]), so they keep running;
/// anywhere else `f` runs as it is.
pub(crate) fn blocking_in_place<T>(f: impl FnOnce() -> T) -> T {
    use tokio::runtime::{Handle, RuntimeFlavor};
    match Handle::try_current() {
        Ok(h) if h.runtime_flavor() == RuntimeFlavor::MultiThread => tokio::task::block_in_place(f),
        _ => f(),
    }
}

/// Fixed id of the singleton app-settings object.
pub fn settings_id() -> anvil_domain::Id {
    anvil_domain::Id(uuid::Uuid::from_u128(0x00000000_0000_7000_8000_000000000001))
}
