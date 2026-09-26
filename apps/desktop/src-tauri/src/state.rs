//! Desktop backend state. The vault key lives only in `anvil-app`/`anvil-storage`;
//! lock enforcement happens here and there, never only in the webview.

use anvil_app::App;
use anvil_app::file_grants::FileGrants;
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
    /// Load runs in worker processes, by run key: (user cancel, lock stop).
    pub load_runs: Mutex<HashMap<String, (CancellationToken, CancellationToken)>>,
    /// Load reports that finished while the vault was locked (stop-on-lock);
    /// saved at the next unlock. Reports are already redacted.
    pub pending_load_reports: Mutex<Vec<anvil_domain::load::LoadReport>>,
    /// Open interactive sessions by execution id.
    pub sessions: Mutex<HashMap<String, crate::cmd_sessions::SessionSlot>>,
    /// Files the user chose in native dialogs this session; file commands
    /// accept only these grants, never a path from the webview.
    pub file_grants: FileGrants,
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
            pending_load_reports: Mutex::new(Vec::new()),
            file_grants: FileGrants::default(),
            last_activity: Mutex::new(Instant::now()),
            clock_probe: Mutex::new((Instant::now(), SystemTime::now())),
        }
    }

    pub fn touch(&self) {
        *self.last_activity.lock() = Instant::now();
    }

    /// Make `app` the open profile. The desktop confines JWT-SVID token
    /// files to the ones bound in its native dialog.
    pub fn set_app(&self, app: App) {
        app.confine_token_files();
        *self.app.write() = Some(Arc::new(app));
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

    /// Persist reports that finished while locked. Called after unlock.
    pub fn flush_pending_reports(&self) {
        let pending: Vec<_> = std::mem::take(&mut *self.pending_load_reports.lock());
        if pending.is_empty() {
            return;
        }
        match self.app() {
            Ok(app) => {
                for r in &pending {
                    let _ = app.save_load_report(r);
                }
            }
            Err(_) => self.pending_load_reports.lock().extend(pending),
        }
    }

    /// Lock: stop active runs (policy: stop runs on lock), drop keys,
    /// cached credentials/connections and file-dialog grants.
    pub fn lock(&self) {
        self.file_grants.revoke_all();
        for (_, t) in self.running.lock().drain() {
            t.cancel();
        }
        // Load workers are asked to stop and finalize a partial report
        // (completion `stopped_by_lock` is recorded by the run policy).
        for (_, lock) in self.load_runs.lock().values() {
            lock.cancel();
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
