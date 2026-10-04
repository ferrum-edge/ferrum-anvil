//! Desktop backend state. The vault key lives only in `anvil-app`/`anvil-storage`;
//! lock enforcement happens here and there, never only in the webview.

use anvil_app::file_grants::FileGrants;
use anvil_app::profiles::ProfileManager;
use anvil_app::{App, AppError};
use anvil_domain::Id;
use anvil_domain::load::LoadReport;
use parking_lot::{Mutex, RwLock};
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::time::{Instant, SystemTime};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

/// Cancellation tokens of running attempts (executions, imports and
/// previews, or sign-ins), by attempt id. Each registration has its own
/// `Arc`, which identifies it: an entry is removed only by the registration
/// that inserted it.
pub type Running = Mutex<HashMap<Id, Arc<CancellationToken>>>;

/// Load runs in worker processes, by run key: (user cancel, lock stop).
pub type LoadRuns = Mutex<HashMap<String, (CancellationToken, CancellationToken)>>;

/// The vault a profile opened: its folder, its id and the check value of its
/// data key. The same profile opened again has the same identity; another
/// profile never does. Work started under a profile records only into it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultId {
    dir: PathBuf,
    profile_id: String,
    key_check: String,
}

impl VaultId {
    pub fn of(app: &App) -> Self {
        VaultId { dir: app.dir.clone(), profile_id: app.header.profile_id.clone(), key_check: app.header.key_check.clone() }
    }
}

/// Reports held for the vault they belong to until it is next unlocked.
pub struct PendingReports<T> {
    entries: Mutex<Vec<(VaultId, T)>>,
}

impl<T> Default for PendingReports<T> {
    fn default() -> Self {
        PendingReports { entries: Mutex::new(Vec::new()) }
    }
}

impl<T> PendingReports<T> {
    pub fn push(&self, vault: VaultId, report: T) {
        self.entries.lock().push((vault, report));
    }

    /// Remove and return the reports of `vault`, oldest first. The reports of
    /// other vaults stay held for them.
    pub fn take_for(&self, vault: &VaultId) -> Vec<T> {
        let mut entries = self.entries.lock();
        let (taken, kept) = std::mem::take(&mut *entries).into_iter().partition::<Vec<_>, _>(|(v, _)| v == vault);
        *entries = kept;
        taken.into_iter().map(|(_, r)| r).collect()
    }
}

pub struct DesktopState {
    pub profiles: ProfileManager,
    pub app: RwLock<Option<Arc<App>>>,
    /// Bumped by every lock and every profile switch, before either takes
    /// effect. Work that ran off the lock (a key derivation, a blocking
    /// store read) compares it with the value it saw when it started, so an
    /// unlock never outlives a lock that landed meanwhile, and a read's result
    /// is not returned once one has.
    lock_epoch: AtomicU64,
    /// Running executions (for cancel and lock-time stop).
    pub running: Arc<Running>,
    /// Bundle imports and previews started with an attempt id (for
    /// `import_cancel` and lock-time stop). Apart from `running`, so an
    /// import's id never cancels an execution, nor an execution's an import.
    pub imports: Arc<Running>,
    /// OAuth sign-ins (for `oauth_cancel` and lock-time stop). Apart from
    /// `running` and `imports`, for the same reason.
    pub sign_ins: Arc<Running>,
    /// The one import worker allowed at a time. A canceled import's worker
    /// keeps deriving its key (within the header's memory bound) until the
    /// derivation ends, so a new import is refused until it has, rather than
    /// run beside it; the worker holds the permit until it has ended.
    pub import_worker: Arc<Semaphore>,
    /// Load runs in worker processes (for cancel and lock-time stop).
    pub load_runs: Arc<LoadRuns>,
    /// Load reports that finished while their profile was locked
    /// (stop-on-lock, or another profile opened), by the vault they belong to;
    /// saved when that profile is next unlocked. Reports are already redacted.
    pub pending_load_reports: PendingReports<LoadReport>,
    /// Open interactive sessions by execution id, with the profile each was
    /// opened under.
    pub sessions: Mutex<HashMap<String, (Arc<App>, crate::cmd_sessions::SessionSlot)>>,
    /// Files the user chose in native dialogs this session; file commands
    /// accept only these grants, never a path from the webview. Shared with
    /// the worker threads that read a chosen file.
    pub file_grants: Arc<FileGrants>,
    pub last_activity: Mutex<Instant>,
    /// Wall-clock/monotonic pair used to detect system suspend.
    pub clock_probe: Mutex<(Instant, SystemTime)>,
}

impl DesktopState {
    pub fn new(root: std::path::PathBuf) -> Self {
        DesktopState {
            profiles: ProfileManager::new(root),
            app: RwLock::new(None),
            lock_epoch: AtomicU64::new(0),
            running: Arc::new(Mutex::new(HashMap::new())),
            imports: Arc::new(Mutex::new(HashMap::new())),
            sign_ins: Arc::new(Mutex::new(HashMap::new())),
            import_worker: Arc::new(Semaphore::new(1)),
            load_runs: Arc::new(Mutex::new(HashMap::new())),
            sessions: Mutex::new(HashMap::new()),
            pending_load_reports: PendingReports::default(),
            file_grants: Arc::default(),
            last_activity: Mutex::new(Instant::now()),
            clock_probe: Mutex::new((Instant::now(), SystemTime::now())),
        }
    }

    pub fn touch(&self) {
        *self.last_activity.lock() = Instant::now();
    }

    /// The current lock epoch (see the `lock_epoch` field). Taken
    /// before work that runs off the lock, and compared once it has ended.
    pub fn epoch(&self) -> u64 {
        self.lock_epoch.load(Ordering::SeqCst)
    }

    /// Make `app` the open profile, unless a lock or another profile switch
    /// landed since the epoch `seen` was taken: then `app` is locked and
    /// dropped, and the error is `LOCKED`. The desktop confines JWT-SVID token
    /// files to the ones bound in its native dialog. File-dialog grants belong
    /// to the profile they were chosen in, so switching revokes them, as a
    /// lock does. The previous profile is locked and its work stopped, so
    /// nothing it started records into this one or keeps its key in memory.
    pub fn set_app_since(&self, app: App, seen: u64) -> Result<(), String> {
        self.set_app_since_with(app, seen, |_| {})
    }

    fn set_app_since_with(&self, app: App, seen: u64, published: impl FnOnce(&Arc<App>)) -> Result<(), String> {
        app.confine_token_files();
        let swapped = {
            let mut g = self.app.write();
            // A lock bumps the epoch before it reads the app, so one that
            // bumps after this exchange waits for the guard and locks `app`.
            match self.lock_epoch.compare_exchange(seen, seen + 1, Ordering::SeqCst, Ordering::SeqCst) {
                Ok(_) => {
                    // Revoke while publication is still excluded by `app`'s
                    // write guard. No caller can obtain the new profile with
                    // grants (or claims) from the one it replaces.
                    self.file_grants.revoke_all();
                    let app = Arc::new(app);
                    let previous = g.replace(app.clone());
                    published(&app);
                    Ok(previous)
                }
                Err(_) => Err(app),
            }
        };
        let previous = match swapped {
            Ok(previous) => previous,
            // Never published, so locked once the guard is released: a lock
            // or a status read does not wait for it.
            Err(rejected) => {
                rejected.lock();
                return Err("LOCKED".into());
            }
        };
        // An execution registers before it asks for the app, so one that got
        // the previous profile registered before the swap and is stopped
        // below; one registered after the stop gets this profile.
        if let Some(previous) = previous {
            previous.lock();
        }
        self.stop_work();
        Ok(())
    }

    /// Unlock `app`, the open profile opened again, with `key`, unless a lock
    /// or another profile switch landed since the epoch `seen` was taken: then
    /// it stays locked and the error is `LOCKED`.
    pub fn unlock_since(&self, app: &App, key: anvil_storage::Key, seen: u64) -> Result<(), String> {
        // `app` is already published, so the epoch is checked by the gate,
        // under the write lock of the store's key and before the key is set:
        // no other thread can use `app` unlocked until it has passed. A lock
        // (and a profile switch) bumps the epoch before it locks the app,
        // which takes that write lock, so either the gate sees the bump and
        // the key is never set, or the key is set first and that lock
        // clears it.
        app.unlock_if(key, || self.epoch() == seen).map_err(crate::commands::e)
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

    /// Whether `app` is still the open profile (unlocked or not).
    pub fn is_current(&self, app: &Arc<App>) -> bool {
        self.app.read().as_ref().is_some_and(|a| Arc::ptr_eq(a, app))
    }

    /// Hold a load report of `vault` that could not be saved because that
    /// profile is locked, and save it now if the profile is open again.
    pub fn hold_report(&self, vault: VaultId, report: LoadReport) {
        self.pending_load_reports.push(vault, report);
        self.flush_pending_reports();
    }

    /// Persist the held reports of the open profile if it is unlocked; the
    /// reports of other profiles stay held. Called after unlock.
    pub fn flush_pending_reports(&self) {
        // Not `app()`: a background flush is no user activity.
        let app = match self.app.read().as_ref() {
            Some(a) if !a.is_locked() => a.clone(),
            _ => return,
        };
        let vault = VaultId::of(&app);
        for r in self.pending_load_reports.take_for(&vault) {
            // Locked again meanwhile: held for the next unlock.
            if let Err(AppError::Locked) = app.save_load_report(&r) {
                self.pending_load_reports.push(vault.clone(), r);
            }
        }
    }

    /// Lock: stop active runs (policy: stop runs on lock), drop keys,
    /// cached credentials/connections and file-dialog grants.
    pub fn lock(&self) {
        // First, so an unlock or a read still running off the lock sees it.
        self.lock_epoch.fetch_add(1, Ordering::SeqCst);
        {
            // Exclude new chooser/app readers until both revocation and the
            // key drop finish; none can issue a grant in between them.
            let app = self.app.write();
            self.file_grants.revoke_all();
            if let Some(a) = app.as_ref() {
                a.lock();
            }
        }
        // The app locks before the drain below. An execution registers before
        // it asks for the app, so one registered after the drain is refused by
        // `app()`, and one registered before it is canceled here.
        self.stop_work();
    }

    /// Cancel registered executions, imports and sign-ins, stop load workers
    /// and abort sessions.
    fn stop_work(&self) {
        for registry in [&self.running, &self.imports, &self.sign_ins] {
            for (_, t) in registry.lock().drain() {
                t.cancel();
            }
        }
        // Load workers are asked to stop and finalize a partial report
        // (completion `stopped_by_lock` is recorded by the run policy).
        for (_, lock) in self.load_runs.lock().values() {
            lock.cancel();
        }
        // Interactive sessions are aborted; their watcher records the result.
        let open: Vec<_> = self.sessions.lock().values().map(|(_, slot)| slot.clone()).collect();
        for slot in open {
            tauri::async_runtime::spawn(async move {
                if let Some(s) = slot.lock().await.as_ref() {
                    s.cancel();
                }
            });
        }
    }
}

/// An attempt's entry in a registry ([`DesktopState::running`],
/// [`DesktopState::imports`] or [`DesktopState::sign_ins`]), removed when
/// this is dropped: on success, on an early return and on a panic alike. It
/// owns a handle to the registry, so a spawned task can hold it.
pub struct PendingEntry {
    running: Arc<Running>,
    id: Id,
    token: Arc<CancellationToken>,
}

impl PendingEntry {
    /// Register a fresh token for `id`, so a cancel (or a lock) can reach the
    /// attempt from now on. Refused while `id` is still registered: the
    /// running attempt keeps its token, and its entry is not removed by
    /// anyone else.
    pub fn register(running: &Arc<Running>, id: Id) -> Result<Self, String> {
        let token = Arc::new(CancellationToken::new());
        match running.lock().entry(id) {
            Entry::Occupied(_) => return Err(format!("attempt {id} is already running")),
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

/// A load run's entry in [`DesktopState::load_runs`] under a fresh run key,
/// removed when this is dropped. It owns a handle to the registry, so the
/// run's task can hold it.
pub struct LoadRunEntry {
    runs: Arc<LoadRuns>,
    key: String,
    cancel: CancellationToken,
    lock: CancellationToken,
}

impl LoadRunEntry {
    /// Register a run, so a cancel (or a lock) can reach it from now on.
    pub fn register(runs: &Arc<LoadRuns>) -> Self {
        let key = Id::new().to_string();
        let (cancel, lock) = (CancellationToken::new(), CancellationToken::new());
        runs.lock().insert(key.clone(), (cancel.clone(), lock.clone()));
        LoadRunEntry { runs: runs.clone(), key, cancel, lock }
    }

    pub fn key(&self) -> &str {
        &self.key
    }

    /// Canceled by the user.
    pub fn cancel_token(&self) -> &CancellationToken {
        &self.cancel
    }

    /// Canceled by a lock or when another profile opens.
    pub fn lock_token(&self) -> &CancellationToken {
        &self.lock
    }
}

impl Drop for LoadRunEntry {
    fn drop(&mut self) {
        self.runs.lock().remove(&self.key);
    }
}

/// Settles the race between canceling a bundle import or backup restore and its
/// writes:
/// whichever claims the gate first wins. A canceled import never writes, and
/// one whose writes have begun is never reported as canceled.
#[derive(Default)]
pub struct ImportGate(AtomicU8);

impl ImportGate {
    const OPEN: u8 = 0;
    const WRITING: u8 = 1;
    const ABANDONED: u8 = 2;

    /// Claim the writes for the import; `false` once it was abandoned.
    pub fn begin_writes(&self) -> bool {
        self.0.compare_exchange(Self::OPEN, Self::WRITING, Ordering::AcqRel, Ordering::Acquire).is_ok()
    }

    /// Abandon the import; `false` once its writes have begun.
    pub fn abandon(&self) -> bool {
        match self.0.compare_exchange(Self::OPEN, Self::ABANDONED, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => true,
            Err(state) => state == Self::ABANDONED,
        }
    }
}

/// Cancel the running attempt `id`. Returns whether it was registered.
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
pub(crate) mod tests {
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
    fn an_abandoned_import_never_begins_its_writes() {
        let gate = ImportGate::default();
        assert!(gate.abandon());
        assert!(!gate.begin_writes());
        assert!(gate.abandon(), "abandoning again changes nothing");
    }

    #[test]
    fn an_import_whose_writes_began_is_not_abandoned() {
        let gate = ImportGate::default();
        assert!(gate.begin_writes());
        assert!(!gate.abandon());
        assert!(!gate.begin_writes(), "the writes are claimed once");
    }

    #[test]
    fn an_id_still_registered_is_refused() {
        let running = Arc::new(Running::default());
        let id = Id::new();
        let first = PendingEntry::register(&running, id).unwrap();
        let second = PendingEntry::register(&running, id).map(|_| ());
        assert_eq!(second, Err(format!("attempt {id} is already running")));
        // The refusal leaves the first attempt's entry and token in place.
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

    /// A data folder removed when the test ends.
    pub(crate) struct TempRoot(pub(crate) PathBuf);

    impl TempRoot {
        pub(crate) fn new() -> Self {
            TempRoot(std::env::temp_dir().join(format!("anvil-desktop-state-{}", Id::new())))
        }
    }

    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    pub(crate) const PASSPHRASE: &str = "correct horse battery";

    pub(crate) fn create(st: &DesktopState, name: &str) -> (App, PathBuf) {
        let (summary, key, _) = st.profiles.create_passphrase(name, PASSPHRASE, anvil_storage::KdfParams::testing()).unwrap();
        let header = anvil_storage::vault::read_header(&summary.dir).unwrap();
        (App::open(summary.dir.clone(), header, key).unwrap(), summary.dir)
    }

    fn reopen(dir: &std::path::Path) -> App {
        let (header, key) = ProfileManager::unlock(dir, anvil_app::profiles::Unlock::Passphrase(PASSPHRASE)).unwrap();
        App::open(dir.to_path_buf(), header, key).unwrap()
    }

    #[tokio::test]
    async fn a_vault_id_names_the_profile_not_the_instance() {
        let root = TempRoot::new();
        let st = DesktopState::new(root.0.clone());
        let (a, a_dir) = create(&st, "A");
        let (b, _) = create(&st, "B");
        let a_id = VaultId::of(&a);
        assert_ne!(a_id, VaultId::of(&b));
        drop(a);
        assert_eq!(VaultId::of(&reopen(&a_dir)), a_id);
    }

    #[tokio::test]
    async fn switching_profiles_locks_the_previous_one_and_stops_its_work() {
        let root = TempRoot::new();
        let st = DesktopState::new(root.0.clone());
        let (a, _) = create(&st, "A");
        let (b, _) = create(&st, "B");
        st.set_app_since(a, st.epoch()).unwrap();
        let previous = st.app().unwrap();
        // Work started under the first profile.
        let execution = PendingEntry::register(&st.running, Id::new()).unwrap();
        let load_run = LoadRunEntry::register(&st.load_runs);
        st.set_app_since(b, st.epoch()).unwrap();
        assert!(previous.is_locked());
        assert!(!st.is_current(&previous));
        assert!(execution.token().is_cancelled());
        assert!(load_run.lock_token().is_cancelled());
        assert!(!load_run.cancel_token().is_cancelled());
        // Nothing the previous profile started records into it any more.
        assert!(matches!(previous.settings(), Err(AppError::Locked)));
        let current = st.app().unwrap();
        assert!(!current.is_locked());
        assert!(!Arc::ptr_eq(&current, &previous));
        // Work started from now on is not stopped by the earlier switch.
        let later = PendingEntry::register(&st.running, Id::new()).unwrap();
        assert!(!later.token().is_cancelled());
    }

    #[test]
    fn paused_profile_publication_has_already_revoked_the_previous_vaults_private_key_grants() {
        use anvil_app::file_grants::GrantError;
        use std::sync::mpsc;

        let root = TempRoot::new();
        let st = DesktopState::new(root.0.clone());
        let (a, a_dir) = create(&st, "A");
        let (b, _) = create(&st, "B");
        let workspace = a.create_workspace("keys").unwrap().meta.id;
        b.save_workspace(a.workspace(&workspace).unwrap()).unwrap();
        st.set_app_since(a, st.epoch()).unwrap();
        let a = st.app().unwrap();
        let path = root.0.join("key.pem");
        std::fs::write(&path, "vault-only canary").unwrap();
        let generation = st.file_grants.generation();
        let grant = st.file_grants.grant_private_key(&a, &path).unwrap();
        let (published_tx, published_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        std::thread::scope(|scope| {
            let switch_st = &st;
            let switch = scope.spawn(move || {
                switch_st.set_app_since_with(b, switch_st.epoch(), |published| {
                    assert!(published_tx.send(published.clone()).is_ok());
                    release_rx.recv_timeout(std::time::Duration::from_secs(30)).unwrap();
                })
            });
            let published = published_rx.recv_timeout(std::time::Duration::from_secs(10)).unwrap();
            // Publication is paused under its write guard. Try the real A
            // grant directly against B in the former publish/revoke interval.
            assert!(st.file_grants.is_empty());
            assert!(st.file_grants.import_private_key(&published, &grant.token, &workspace, "wrong").is_err());
            // A chooser still open from A cannot issue a replacement either.
            assert_eq!(st.file_grants.grant_private_key_at(&a, &path, generation), Err(GrantError::Revoked),);
            assert!(a.store.list_secret_ids(None).unwrap().is_empty());
            assert!(published.store.list_secret_ids(None).unwrap().is_empty());
            release_tx.send(()).unwrap();
            switch.join().unwrap().unwrap();
        });
        let (_, key) = ProfileManager::unlock(&a_dir, anvil_app::profiles::Unlock::Passphrase(PASSPHRASE)).unwrap();
        a.unlock(key).unwrap();
        assert!(a.store.list_secret_ids(None).unwrap().is_empty());
        assert!(st.app().unwrap().store.list_secret_ids(None).unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_lock_during_an_unlock_leaves_no_profile_open() {
        let root = TempRoot::new();
        let st = DesktopState::new(root.0.clone());
        let (a, _) = create(&st, "A");
        // The epoch is taken before the key derivation, and a lock lands during it.
        let seen = st.epoch();
        st.lock();
        assert_eq!(st.set_app_since(a, seen), Err("LOCKED".to_string()));
        assert!(st.app().is_err());
        assert!(st.app.read().is_none());
    }

    #[tokio::test]
    async fn a_lock_during_an_unlock_of_the_open_profile_leaves_it_locked() {
        let root = TempRoot::new();
        let st = DesktopState::new(root.0.clone());
        let (a, dir) = create(&st, "A");
        st.set_app_since(a, st.epoch()).unwrap();
        st.lock();
        let open = st.app.read().clone().unwrap();
        assert!(open.is_locked());
        let seen = st.epoch();
        let (_, key) = ProfileManager::unlock(&dir, anvil_app::profiles::Unlock::Passphrase(PASSPHRASE)).unwrap();
        st.lock();
        assert_eq!(st.unlock_since(&open, key, seen), Err("LOCKED".to_string()));
        assert!(open.is_locked());
        assert_eq!(st.app().map(|_| ()), Err("LOCKED".to_string()));
        // Without a lock meanwhile, the unlock holds.
        let seen = st.epoch();
        let (_, key) = ProfileManager::unlock(&dir, anvil_app::profiles::Unlock::Passphrase(PASSPHRASE)).unwrap();
        st.unlock_since(&open, key, seen).unwrap();
        assert!(st.app().is_ok());
    }

    #[tokio::test]
    async fn an_unlock_refused_by_the_epoch_never_makes_the_open_profile_usable() {
        let root = TempRoot::new();
        let st = DesktopState::new(root.0.clone());
        let (a, dir) = create(&st, "A");
        st.set_app_since(a, st.epoch()).unwrap();
        st.lock();
        let open = st.app.read().clone().unwrap();
        let seen = st.epoch();
        st.lock();
        let done = std::sync::atomic::AtomicBool::new(false);
        std::thread::scope(|s| {
            // Polls the published app for the whole unlock: it is never
            // handed out, since the key is never set.
            let poller = s.spawn(|| {
                let mut polls = 0u32;
                while !done.load(Ordering::SeqCst) || polls == 0 {
                    assert_eq!(st.app().map(|_| ()), Err("LOCKED".to_string()));
                    polls += 1;
                }
            });
            for _ in 0..3 {
                let (_, key) = ProfileManager::unlock(&dir, anvil_app::profiles::Unlock::Passphrase(PASSPHRASE)).unwrap();
                assert_eq!(st.unlock_since(&open, key, seen), Err("LOCKED".to_string()));
                assert!(open.is_locked());
            }
            done.store(true, Ordering::SeqCst);
            poller.join().unwrap();
        });
        assert!(matches!(open.settings(), Err(AppError::Locked)));
    }

    #[tokio::test]
    async fn imports_and_executions_are_canceled_in_their_own_registries() {
        let root = TempRoot::new();
        let st = DesktopState::new(root.0.clone());
        let id = Id::new();
        let execution = PendingEntry::register(&st.running, id).unwrap();
        let import = PendingEntry::register(&st.imports, id).unwrap();
        // The same id in the other registry is another entry.
        assert!(cancel_pending(&st.imports, &id));
        assert!(import.token().is_cancelled());
        assert!(!execution.token().is_cancelled());
        drop(import);
        assert!(!cancel_pending(&st.imports, &id));
        assert!(!execution.token().is_cancelled());
        // A lock stops both.
        let later = PendingEntry::register(&st.imports, Id::new()).unwrap();
        st.lock();
        assert!(execution.token().is_cancelled());
        assert!(later.token().is_cancelled());
        assert!(st.imports.lock().is_empty());
    }

    #[tokio::test]
    async fn sign_ins_and_executions_are_canceled_in_their_own_registries() {
        let root = TempRoot::new();
        let st = DesktopState::new(root.0.clone());
        let id = Id::new();
        let execution = PendingEntry::register(&st.running, id).unwrap();
        let import = PendingEntry::register(&st.imports, id).unwrap();
        let sign_in = PendingEntry::register(&st.sign_ins, id).unwrap();
        // A sign-in's cancel reaches only the sign-in...
        assert!(cancel_pending(&st.sign_ins, &id));
        assert!(sign_in.token().is_cancelled());
        assert!(!execution.token().is_cancelled());
        assert!(!import.token().is_cancelled());
        drop(sign_in);
        assert!(!cancel_pending(&st.sign_ins, &id));
        // ...and an execution's never reaches a sign-in.
        let sign_in = PendingEntry::register(&st.sign_ins, id).unwrap();
        assert!(cancel_pending(&st.running, &id));
        assert!(execution.token().is_cancelled());
        assert!(!sign_in.token().is_cancelled());
        assert!(!import.token().is_cancelled());
        // A lock stops every one of them.
        st.lock();
        assert!(sign_in.token().is_cancelled());
        assert!(import.token().is_cancelled());
        assert!(st.sign_ins.lock().is_empty());
        assert!(st.running.lock().is_empty());
    }

    #[tokio::test]
    async fn held_reports_are_taken_only_by_their_own_vault() {
        let root = TempRoot::new();
        let st = DesktopState::new(root.0.clone());
        let (a, a_dir) = create(&st, "A");
        let (b, _) = create(&st, "B");
        let (a_id, b_id) = (VaultId::of(&a), VaultId::of(&b));
        drop(a);
        let pending = PendingReports::default();
        pending.push(a_id.clone(), "a1");
        pending.push(b_id.clone(), "b1");
        pending.push(a_id.clone(), "a2");
        assert_eq!(pending.take_for(&b_id), vec!["b1"]);
        assert!(pending.take_for(&b_id).is_empty());
        // The same profile opened again takes its own reports.
        assert_eq!(pending.take_for(&VaultId::of(&reopen(&a_dir))), vec!["a1", "a2"]);
        assert!(pending.take_for(&a_id).is_empty());
    }

    #[test]
    fn a_load_run_is_reachable_until_its_entry_is_dropped() {
        let runs = Arc::new(LoadRuns::default());
        let entry = LoadRunEntry::register(&runs);
        let key = entry.key().to_string();
        runs.lock().get(&key).unwrap().0.cancel();
        assert!(entry.cancel_token().is_cancelled());
        assert!(!entry.lock_token().is_cancelled());
        drop(entry);
        assert!(runs.lock().is_empty());
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
