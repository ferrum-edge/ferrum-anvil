//! Desktop backend state. The vault key lives only in `anvil-app`/`anvil-storage`;
//! lock enforcement happens here and there, never only in the webview.

use anvil_app::App;
use anvil_app::file_grants::FileGrants;
use anvil_app::profiles::ProfileManager;
use anvil_domain::Id;
use parking_lot::{Mutex, RwLock};
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::sync::Arc;
use std::time::{Instant, SystemTime};
use tokio_util::sync::CancellationToken;

/// Cancellation tokens of running executions, by execution id. Each
/// registration has its own `Arc`, which identifies it: an entry is removed
/// only by the registration that inserted it.
pub type Running = Mutex<HashMap<Id, Arc<CancellationToken>>>;

pub struct DesktopState {
    pub profiles: ProfileManager,
    pub app: RwLock<Option<Arc<App>>>,
    /// Running executions (for cancel and lock-time stop).
    pub running: Arc<Running>,
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
            running: Arc::new(Mutex::new(HashMap::new())),
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
    /// files to the ones bound in its native dialog. File-dialog grants belong
    /// to the profile they were chosen in, so switching revokes them, as a
    /// lock does.
    pub fn set_app(&self, app: App) {
        app.confine_token_files();
        *self.app.write() = Some(Arc::new(app));
        // After the swap: a choice that starts from now on sees only the new
        // profile, and one still open from before grants nothing.
        self.file_grants.revoke_all();
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
        // The app locks before the drain below. An execution registers before
        // it asks for the app, so one registered after the drain is refused by
        // `app()`, and one registered before it is canceled here.
        if let Some(a) = self.app.read().as_ref() {
            a.lock();
        }
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
    }
}

/// An execution's entry in [`DesktopState::running`], removed when this is
/// dropped: on success, on an early return and on a panic alike. It owns a
/// handle to the registry, so a spawned task can hold it.
pub struct PendingEntry {
    running: Arc<Running>,
    id: Id,
    token: Arc<CancellationToken>,
}

impl PendingEntry {
    /// Register a fresh token for `id`, so a cancel (or a lock) can reach the
    /// execution from now on. Refused while `id` is still registered: the
    /// running execution keeps its token, and its entry is not removed by
    /// anyone else.
    pub fn register(running: &Arc<Running>, id: Id) -> Result<Self, String> {
        let token = Arc::new(CancellationToken::new());
        match running.lock().entry(id) {
            Entry::Occupied(_) => return Err(format!("execution {id} is already running")),
            Entry::Vacant(v) => {
                v.insert(token.clone());
            }
        }
        Ok(PendingEntry { running: running.clone(), id, token })
    }

    pub fn token(&self) -> &CancellationToken {
        &self.token
    }

    /// The open/cancel handshake. Runs `open` unless the entry is canceled
    /// first (then `None`, and `publish` is never called). Otherwise `publish`
    /// makes the result reachable elsewhere *before* the entry is retired, so a
    /// concurrent cancel always finds one of the two. The flag says a cancel
    /// landed after `open` completed: the caller must then stop what it published.
    pub async fn open<T, P>(self, open: impl Future<Output = T>, publish: impl FnOnce(T) -> P) -> Option<(P, bool)> {
        let token = CancellationToken::clone(&self.token);
        let opened = tokio::select! {
            v = open => v,
            _ = token.cancelled() => return None,
        };
        let published = publish(opened);
        drop(self);
        // Checked only after retiring: a cancel from now on finds the published value.
        Some((published, token.is_cancelled()))
    }
}

impl Drop for PendingEntry {
    fn drop(&mut self) {
        // A lock drains the registry, after which the id can be registered
        // again: that newer entry is not this one's to remove.
        let mut running = self.running.lock();
        if running.get(&self.id).is_some_and(|t| Arc::ptr_eq(t, &self.token)) {
            running.remove(&self.id);
        }
    }
}

/// Cancel the running execution `id`. Returns whether it was registered.
pub fn cancel_pending(running: &Running, id: &Id) -> bool {
    match running.lock().get(id) {
        Some(t) => {
            t.cancel();
            true
        }
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::oneshot;

    #[tokio::test]
    async fn cancel_before_the_open_completes_abandons_it() {
        let running = Arc::new(Running::default());
        let id = Id::new();
        let (started_tx, started_rx) = oneshot::channel();
        let (_done_tx, done_rx) = oneshot::channel::<()>();
        let pending = PendingEntry::register(&running, id).unwrap();
        let open = async move {
            started_tx.send(()).unwrap();
            done_rx.await
        };
        let cancel = async {
            started_rx.await.unwrap();
            assert!(cancel_pending(&running, &id));
        };
        let (opened, ()) = tokio::join!(pending.open(open, |_| panic!("an abandoned open is never published")), cancel);
        assert!(opened.is_none());
        assert!(running.lock().is_empty());
        assert!(!cancel_pending(&running, &id));
    }

    #[tokio::test]
    async fn cancel_between_publish_and_retire_is_reported() {
        let running = Arc::new(Running::default());
        let id = Id::new();
        let pending = PendingEntry::register(&running, id).unwrap();
        let publish = |s| {
            // The entry is still registered while the result is published.
            assert!(cancel_pending(&running, &id));
            s
        };
        let opened = pending.open(async { "session" }, publish).await;
        assert_eq!(opened, Some(("session", true)));
        assert!(running.lock().is_empty());
    }

    #[tokio::test]
    async fn open_without_cancel_retires_the_entry() {
        let running = Arc::new(Running::default());
        let id = Id::new();
        let (tx, rx) = oneshot::channel();
        let pending = PendingEntry::register(&running, id).unwrap();
        assert!(running.lock().contains_key(&id));
        tx.send("session").unwrap();
        let opened = pending.open(async { rx.await.unwrap() }, |s| s).await;
        assert_eq!(opened, Some(("session", false)));
        assert!(running.lock().is_empty());
        // A cancel from now on no longer finds the entry: it goes to the published value.
        assert!(!cancel_pending(&running, &id));
    }

    #[tokio::test]
    async fn a_panicking_open_removes_the_entry() {
        let running = Arc::new(Running::default());
        let id = Id::new();
        let shared = running.clone();
        let task = tokio::spawn(async move {
            let pending = PendingEntry::register(&shared, id).unwrap();
            pending.open(async { panic!("open failed") }, |()| ()).await
        });
        assert!(task.await.unwrap_err().is_panic());
        assert!(running.lock().is_empty());
    }

    #[test]
    fn an_early_return_removes_the_entry() {
        let running = Arc::new(Running::default());
        let id = Id::new();
        let fails = || -> Result<(), String> {
            let _pending = PendingEntry::register(&running, id)?;
            assert!(running.lock().contains_key(&id));
            Err("LOCKED".into())
        };
        assert!(fails().is_err());
        assert!(running.lock().is_empty());
    }

    #[test]
    fn an_id_still_registered_is_refused() {
        let running = Arc::new(Running::default());
        let id = Id::new();
        let first = PendingEntry::register(&running, id).unwrap();
        let second = PendingEntry::register(&running, id).map(|_| ());
        assert_eq!(second, Err(format!("execution {id} is already running")));
        // The refusal leaves the first execution's entry and token in place.
        assert!(cancel_pending(&running, &id));
        assert!(first.token().is_cancelled());
        drop(first);
        assert!(running.lock().is_empty());
        // Once retired, the id can be registered again.
        let again = PendingEntry::register(&running, id).unwrap();
        assert!(!again.token().is_cancelled());
    }

    #[test]
    fn a_drained_guard_leaves_a_newer_registration_in_place() {
        let running = Arc::new(Running::default());
        let id = Id::new();
        let old = PendingEntry::register(&running, id).unwrap();
        // A lock drains the registry while the old execution still holds its guard.
        for (_, t) in running.lock().drain() {
            t.cancel();
        }
        let new = PendingEntry::register(&running, id).unwrap();
        drop(old);
        // The old guard does not remove the newer entry, which stays cancelable.
        assert!(running.lock().contains_key(&id));
        assert!(cancel_pending(&running, &id));
        assert!(new.token().is_cancelled());
        drop(new);
        assert!(running.lock().is_empty());
    }

    #[tokio::test]
    async fn an_owned_entry_is_retired_by_a_spawned_task() {
        let running = Arc::new(Running::default());
        let id = Id::new();
        let pending = PendingEntry::register(&running, id).unwrap();
        tokio::spawn(async move {
            assert!(!pending.token().is_cancelled());
            drop(pending);
        })
        .await
        .unwrap();
        assert!(running.lock().is_empty());
    }
}
