//! Desktop backend state. The vault key lives only in `anvil-app`/`anvil-storage`;
//! lock enforcement happens here and there, never only in the webview.

use anvil_app::App;
use anvil_app::profiles::ProfileManager;
use anvil_domain::Id;
use parking_lot::{Mutex, RwLock};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Instant, SystemTime};
use tokio_util::sync::CancellationToken;

pub struct DesktopState {
    pub profiles: ProfileManager,
    pub app: RwLock<Option<Arc<App>>>,
    /// Running executions (for cancel and lock-time stop).
    pub running: Mutex<HashMap<Id, CancellationToken>>,
    /// Load runs in worker processes, by run key (cancel and lock-time stop).
    pub load_runs: Mutex<HashMap<String, CancellationToken>>,
    /// Open interactive sessions by execution id.
    pub sessions: Mutex<HashMap<String, crate::cmd_sessions::SessionSlot>>,
    pub last_activity: Mutex<Instant>,
    /// Wall-clock/monotonic pair used to detect system suspend.
    pub clock_probe: Mutex<(Instant, SystemTime)>,
}

impl DesktopState {
    pub fn new(root: std::path::PathBuf) -> Self {
        DesktopState {
            profiles: ProfileManager::new(root),
            app: RwLock::new(None),
            running: Mutex::new(HashMap::new()),
            load_runs: Mutex::new(HashMap::new()),
            sessions: Mutex::new(HashMap::new()),
            last_activity: Mutex::new(Instant::now()),
            clock_probe: Mutex::new((Instant::now(), SystemTime::now())),
        }
    }

    pub fn touch(&self) {
        *self.last_activity.lock() = Instant::now();
    }

    /// The unlocked app, or an error the UI renders as the lock screen.
    pub fn app(&self) -> Result<Arc<App>, String> {
        let g = self.app.read();
        match g.as_ref() {
            Some(a) if !a.is_locked() => {
                self.touch();
                Ok(a.clone())
            }
            Some(_) => Err("LOCKED".into()),
            None => Err("NO_PROFILE".into()),
        }
    }

    /// Lock: stop active runs (policy: stop runs on lock), drop keys and
    /// cached credentials/connections.
    pub fn lock(&self) {
        for (_, t) in self.running.lock().drain() {
            t.cancel();
        }
        // Load workers are asked to stop and finalize a partial report
        // (completion `stopped_by_lock` is recorded by the run policy).
        for t in self.load_runs.lock().values() {
            t.cancel();
        }
        // Interactive sessions are aborted; their watcher records the result.
        let open: Vec<_> = self.sessions.lock().values().cloned().collect();
        for slot in open {
            tauri::async_runtime::spawn(async move {
                if let Some(s) = slot.lock().await.as_ref() {
                    s.cancel();
                }
            });
        }
        if let Some(a) = self.app.read().as_ref() {
            a.lock();
        }
    }
}
