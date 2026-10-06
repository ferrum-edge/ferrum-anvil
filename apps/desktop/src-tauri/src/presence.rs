//! Trusted user presence for changes that weaken how the open profile is
//! protected. An unlocked webview is not trusted to vouch for the user: a
//! command that replaces the unlock credential, lifts a workspace's
//! device-identity seal, opens an imported collection to its workspace or
//! weakens the lock policy asks in a native dialog that the backend shows
//! itself, and goes ahead only on the user's answer there. No argument the
//! webview passes stands in for that answer, and each answer authorizes only
//! the one change it was asked for, under the lock epoch it was asked in: a
//! lock or a profile switch while the dialog is open refuses the change.
//! Changes that only strengthen protection are not asked about.
//!
//! A passphrase change right after an unlock with the recovery key is not
//! asked about either: that unlock proved the recovery key to the backend.
//! The proof is held for [`RECOVERY_REAUTH_TTL`] in the lock epoch it was
//! made in, and the next passphrase change uses it up.
//!
//! The idle lock does not rely on the webview alone either. Its activity
//! reports (`touch`, and every data command) postpone the idle lock only
//! within [`RENDERER_ACTIVITY_CEILING`] of the last native sign of the
//! user: an unlock, an answer in a native confirmation, or the window
//! gaining focus, which the OS reports to the backend. A webview that keeps
//! reporting activity cannot keep the profile open indefinitely.

use crate::commands::{R, e};
use crate::state::DesktopState;
use anvil_app::App;
use anvil_domain::Id;
use anvil_domain::settings::{AppSettings, LockPolicy};
use anvil_domain::workspace::Folder;
use anvil_storage::KdfParams;
use anvil_storage::vault::KeychainConversion;
use parking_lot::Mutex;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tauri::Window;
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons, MessageDialogKind};

/// What a command returns when the user declined, or closed, the native
/// confirmation it asked. A code, like `LOCKED` and `CANCELED`: the UI words it.
pub(crate) const NOT_CONFIRMED: &str = "NOT_CONFIRMED";

/// How long the webview's activity reports alone keep the idle lock off
/// (or the idle timeout, if longer).
pub(crate) const RENDERER_ACTIVITY_CEILING: Duration = Duration::from_secs(4 * 60 * 60);

/// How long an unlock with the recovery key lets the next passphrase change
/// go ahead without a native confirmation.
pub(crate) const RECOVERY_REAUTH_TTL: Duration = Duration::from_secs(10 * 60);

/// A question the backend asks the user in a native dialog. Its text comes
/// from the backend, never from the webview.
pub(crate) struct Prompt {
    pub title: &'static str,
    pub message: String,
    pub ok: &'static str,
}

/// Asks the user directly, in a way the webview cannot answer for them.
pub(crate) trait Presence: Sync {
    /// Whether the user chose `prompt.ok`. Closing the dialog is a refusal.
    fn confirm(&self, prompt: Prompt) -> impl Future<Output = bool> + Send;
}

/// The native message dialog, attached to the window the command came from.
pub(crate) struct NativePresence(pub Window);

impl Presence for NativePresence {
    fn confirm(&self, prompt: Prompt) -> impl Future<Output = bool> + Send {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let window = &self.0;
        let dialog = window
            .dialog()
            .message(prompt.message)
            .title(prompt.title)
            .kind(MessageDialogKind::Warning)
            .buttons(MessageDialogButtons::OkCancelCustom(prompt.ok.into(), "Cancel".into()));
        #[cfg(any(windows, target_os = "macos"))]
        let dialog = dialog.parent(window);
        dialog.show(move |ok| {
            let _ = tx.send(ok);
        });
        // A dialog that goes away without an answer is a refusal.
        async move { rx.await.unwrap_or(false) }
    }
}

/// Native signs of the user, kept by the backend (see the module docs).
pub struct PresenceState {
    native: Mutex<Instant>,
    /// The lock epoch of the last unlock with the recovery key, and when it was.
    recovery: Mutex<Option<(u64, Instant)>>,
}

impl Default for PresenceState {
    fn default() -> Self {
        PresenceState { native: Mutex::new(Instant::now()), recovery: Mutex::new(None) }
    }
}

impl PresenceState {
    /// A native sign the user is there: an unlock, an answer in a native
    /// confirmation, or the window gaining focus. Never a webview report.
    pub fn saw_user(&self) {
        *self.native.lock() = Instant::now();
    }

    /// Time since the last native sign of the user.
    pub fn native_idle(&self) -> Duration {
        self.native.lock().elapsed()
    }

    /// The open profile was unlocked with its recovery key in lock epoch `epoch`.
    pub fn recovery_unlocked(&self, epoch: u64) {
        *self.recovery.lock() = Some((epoch, Instant::now()));
    }

    /// Use up the proof of a recovery-key unlock, if it was made in lock
    /// epoch `epoch` and is still fresh. Taken whatever the outcome, so it
    /// authorizes at most one passphrase change.
    fn take_recovery_reauth(&self, epoch: u64) -> bool {
        matches!(self.recovery.lock().take(), Some((seen, at)) if seen == epoch && at.elapsed() <= RECOVERY_REAUTH_TTL)
    }
}

/// Whether the idle lock is due under a timeout of `idle_minutes` (0 =
/// never): after that long without an activity report, or without a native
/// sign of the user for [`RENDERER_ACTIVITY_CEILING`] (or the timeout, if
/// longer) however often the webview reports activity.
pub(crate) fn idle_lock_due(idle_minutes: u32, reported_idle: Duration, native_idle: Duration) -> bool {
    if idle_minutes == 0 {
        return false;
    }
    let limit = Duration::from_secs(u64::from(idle_minutes) * 60);
    reported_idle > limit || native_idle > limit.max(RENDERER_ACTIVITY_CEILING)
}

/// Ask the user, natively, to go ahead with `prompt` for the open, unlocked
/// profile. Returns the lock epoch the answer is bound to; the change must
/// be made under it (see [`fenced`]).
pub(crate) async fn confirm(st: &DesktopState, presence: &impl Presence, prompt: Prompt) -> R<u64> {
    let seen = st.epoch();
    st.app()?;
    if !presence.confirm(prompt).await {
        return Err(NOT_CONFIRMED.into());
    }
    if st.epoch() != seen {
        return Err("LOCKED".into());
    }
    st.presence.saw_user();
    Ok(seen)
}

/// The open, unlocked profile, if no lock or profile switch landed since `seen`.
pub(crate) fn fenced(st: &DesktopState, seen: u64) -> R<Arc<App>> {
    let app = st.app()?;
    if st.epoch() != seen {
        return Err("LOCKED".into());
    }
    Ok(app)
}

fn profile_name(st: &DesktopState) -> R<String> {
    Ok(st.app()?.header.display_name.clone())
}

/// Replace the passphrase of the open profile, once the user confirmed it
/// natively or just unlocked it with the recovery key.
pub(crate) async fn change_passphrase(st: &DesktopState, presence: &impl Presence, new_passphrase: String, kdf: KdfParams) -> R<()> {
    let now = st.epoch();
    let seen = if st.presence.take_recovery_reauth(now) {
        now
    } else {
        let message = format!(
            "Change the passphrase of the profile “{}”? From now on only the new passphrase (or the recovery key) unlocks it.\n\nOnly continue if you asked for this change yourself.",
            profile_name(st)?
        );
        let prompt = Prompt { title: "Change the profile passphrase", message, ok: "Change passphrase" };
        confirm(st, presence, prompt).await?
    };
    let app = fenced(st, seen)?;
    anvil_app::off_runtime(move || app.change_passphrase(&new_passphrase, kdf)).await.map_err(e)
}

/// Protect the open OS-keychain profile with a passphrase instead, once the
/// user confirmed it natively.
pub(crate) async fn convert_to_passphrase(
    st: &DesktopState,
    presence: &impl Presence,
    new_passphrase: String,
    kdf: KdfParams,
) -> R<KeychainConversion> {
    let message = format!(
        "Protect the profile “{}” with a passphrase instead of the OS keychain? From now on only the new passphrase (or the new recovery key) unlocks it.\n\nOnly continue if you asked for this change yourself.",
        profile_name(st)?
    );
    let prompt = Prompt { title: "Set a profile passphrase", message, ok: "Set passphrase" };
    let seen = confirm(st, presence, prompt).await?;
    let app = fenced(st, seen)?;
    anvil_app::off_runtime(move || app.convert_to_passphrase(&new_passphrase, kdf)).await.map_err(e)
}

/// Lift the device-identity seal of `ws`, once the user confirmed it
/// natively. A workspace that is not sealed is left as it is, unasked.
/// Returns whether it was sealed.
pub(crate) async fn allow_device_identity(st: &DesktopState, presence: &impl Presence, ws: Id) -> R<bool> {
    let app = st.app()?;
    if !app.device_identity_sealed(&ws).map_err(e)? {
        return Ok(false);
    }
    let message = format!(
        "Let requests in the workspace “{}” use this device's workload identity (JWT-SVID or X.509-SVID) and its gateway profiles' diagnostic reference lookups? A bundle import or backup restore wrote into it.\n\nOnly continue if you trust what was imported or restored.",
        app.workspace(&ws).map_err(e)?.name
    );
    let prompt = Prompt { title: "Allow this device's workload identity", message, ok: "Allow" };
    let seen = confirm(st, presence, prompt).await?;
    fenced(st, seen)?.allow_device_identity(&ws).map_err(e)
}

/// Open the import root `folder` to its workspace (`allow`), once the user
/// confirmed it natively, or isolate it again, unasked.
pub(crate) async fn set_workspace_scope(st: &DesktopState, presence: &impl Presence, folder: Id, allow: bool) -> R<Folder> {
    let app = st.app()?;
    let f = app.folder(&folder).map_err(e)?;
    if !allow || !f.import_root || f.use_workspace_scope {
        // Isolating, already open, or not an import root (refused there).
        return app.set_import_root_workspace_scope(&folder, allow).map_err(e);
    }
    let message = format!(
        "Open “{}” to its workspace on this device? Its requests will also use the workspace's variables, active environment and auth, variables of folders above it, values extracted and dataset rows from the rest of a run, and this device's workload identity (JWT-SVID or X.509-SVID) and TLS client identities.\n\nOnly continue if you trust what was imported.",
        f.name
    );
    let prompt = Prompt { title: "Open imported collection to the workspace", message, ok: "Open to workspace" };
    let seen = confirm(st, presence, prompt).await?;
    fenced(st, seen)?.set_import_root_workspace_scope(&folder, true).map_err(e)
}

/// How `new` protects the profile less than `old`, in words; empty if it
/// does not.
pub(crate) fn lock_weakening(old: &LockPolicy, new: &LockPolicy) -> Vec<String> {
    let mut out = Vec::new();
    match (old.idle_minutes, new.idle_minutes) {
        (0, _) => {}
        (_, 0) => out.push("never lock after inactivity".to_string()),
        (was, now) if now > was => out.push(format!("lock after {now} minutes of inactivity instead of {was}")),
        _ => {}
    }
    if old.lock_on_os_lock && !new.lock_on_os_lock {
        out.push("no longer lock when the computer sleeps".into());
    }
    if old.clear_clipboard_on_lock && !new.clear_clipboard_on_lock {
        out.push("no longer clear the clipboard on lock".into());
    }
    out
}

/// Save the settings dialog's settings. A change that weakens the lock
/// policy is saved only once the user confirmed it natively, and only over
/// the policy it was asked against.
pub(crate) async fn save_settings(st: &DesktopState, presence: &impl Presence, settings: AppSettings) -> R<()> {
    let app = st.app()?;
    let stored = app.settings().map_err(e)?.lock;
    let weaker = lock_weakening(&stored, &settings.lock);
    let app = if weaker.is_empty() {
        app
    } else {
        let message = format!(
            "Change the lock settings of the profile “{}”? Anvil would {}.\n\nOnly continue if you asked for this change yourself.",
            app.header.display_name,
            weaker.join(", and ")
        );
        let prompt = Prompt { title: "Weaken the lock settings", message, ok: "Save" };
        let seen = confirm(st, presence, prompt).await?;
        fenced(st, seen)?
    };
    if !app.save_settings_if_lock_is(&settings, &stored).map_err(e)? {
        return Err("the lock settings changed meanwhile; review them and save again".into());
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod testing {
    use super::{Presence, Prompt};
    use parking_lot::Mutex;

    /// Answers every confirmation with `yes`, after running `during` (which
    /// stands in for what happens while the dialog is open), and keeps the
    /// messages it was asked.
    pub(crate) struct Answer<F = fn()> {
        yes: bool,
        during: F,
        pub(crate) asked: Mutex<Vec<String>>,
    }

    fn nothing() {}

    impl Answer {
        pub(crate) fn yes() -> Self {
            Answer { yes: true, during: nothing, asked: Mutex::new(Vec::new()) }
        }

        pub(crate) fn no() -> Self {
            Answer { yes: false, during: nothing, asked: Mutex::new(Vec::new()) }
        }
    }

    impl<F: Fn() + Sync> Answer<F> {
        pub(crate) fn with(yes: bool, during: F) -> Self {
            Answer { yes, during, asked: Mutex::new(Vec::new()) }
        }

        pub(crate) fn times(&self) -> usize {
            self.asked.lock().len()
        }
    }

    impl<F: Fn() + Sync> Presence for Answer<F> {
        fn confirm(&self, prompt: Prompt) -> impl Future<Output = bool> + Send {
            (self.during)();
            self.asked.lock().push(prompt.message);
            let yes = self.yes;
            async move { yes }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::Answer;
    use super::*;
    use crate::state::tests::{PASSPHRASE, TempRoot, create};
    use anvil_app::device_identity::DeviceIdentitySeal;
    use anvil_app::profiles::{ProfileManager, Unlock};
    use anvil_storage::kind;

    const NEW_PASSPHRASE: &str = "a different passphrase";

    /// A desktop state with an unlocked passphrase profile open.
    fn opened() -> (TempRoot, DesktopState, std::path::PathBuf) {
        let root = TempRoot::new();
        let st = DesktopState::new(root.0.clone());
        let (app, dir) = create(&st, "P");
        st.set_app_since(app, st.epoch()).unwrap();
        (root, st, dir)
    }

    fn opens_with(dir: &std::path::Path, passphrase: &str) -> bool {
        ProfileManager::unlock(dir, Unlock::Passphrase(passphrase)).is_ok()
    }

    #[tokio::test]
    async fn a_passphrase_change_is_refused_unless_confirmed_natively() {
        let (_root, st, dir) = opened();
        let no = Answer::no();
        let r = change_passphrase(&st, &no, NEW_PASSPHRASE.into(), KdfParams::testing()).await;
        assert_eq!(r, Err(NOT_CONFIRMED.to_string()));
        assert_eq!(no.times(), 1);
        assert!(opens_with(&dir, PASSPHRASE), "the old passphrase still opens the profile");
        assert!(!opens_with(&dir, NEW_PASSPHRASE));

        let yes = Answer::yes();
        change_passphrase(&st, &yes, NEW_PASSPHRASE.into(), KdfParams::testing()).await.unwrap();
        assert_eq!(yes.times(), 1);
        assert!(yes.asked.lock()[0].contains("“P”"), "the dialog names the profile");
        assert!(opens_with(&dir, NEW_PASSPHRASE));
    }

    #[tokio::test]
    async fn each_passphrase_change_asks_again() {
        let (_root, st, dir) = opened();
        let yes = Answer::yes();
        change_passphrase(&st, &yes, NEW_PASSPHRASE.into(), KdfParams::testing()).await.unwrap();
        // An earlier answer authorizes nothing more.
        let no = Answer::no();
        let r = change_passphrase(&st, &no, PASSPHRASE.into(), KdfParams::testing()).await;
        assert_eq!(r, Err(NOT_CONFIRMED.to_string()));
        assert_eq!(no.times(), 1);
        assert!(opens_with(&dir, NEW_PASSPHRASE));
    }

    #[tokio::test]
    async fn a_lock_while_the_dialog_is_open_refuses_the_change_even_once_unlocked_again() {
        let (_root, st, dir) = opened();
        let app = st.app().unwrap();
        let relock = || {
            st.lock();
            let (_, key) = ProfileManager::unlock(&dir, Unlock::Passphrase(PASSPHRASE)).unwrap();
            st.unlock_since(&app, key, st.epoch()).unwrap();
        };
        let yes = Answer::with(true, relock);
        let r = change_passphrase(&st, &yes, NEW_PASSPHRASE.into(), KdfParams::testing()).await;
        assert_eq!(r, Err("LOCKED".to_string()));
        assert!(st.app().is_ok(), "the profile is unlocked again");
        assert!(opens_with(&dir, PASSPHRASE));
        assert!(!opens_with(&dir, NEW_PASSPHRASE));
    }

    #[tokio::test]
    async fn a_recovery_unlock_authorizes_one_passphrase_change_in_its_epoch() {
        let (_root, st, dir) = opened();
        st.presence.recovery_unlocked(st.epoch());
        let no = Answer::no();
        change_passphrase(&st, &no, NEW_PASSPHRASE.into(), KdfParams::testing()).await.unwrap();
        assert_eq!(no.times(), 0, "the recovery key was the proof");
        assert!(opens_with(&dir, NEW_PASSPHRASE));
        // Used up: the next change is asked about, and refused here.
        let r = change_passphrase(&st, &no, PASSPHRASE.into(), KdfParams::testing()).await;
        assert_eq!(r, Err(NOT_CONFIRMED.to_string()));
        assert_eq!(no.times(), 1);
        assert!(opens_with(&dir, NEW_PASSPHRASE));
    }

    #[tokio::test]
    async fn a_recovery_unlock_from_an_earlier_epoch_authorizes_nothing() {
        let (_root, st, dir) = opened();
        let app = st.app().unwrap();
        st.presence.recovery_unlocked(st.epoch());
        st.lock();
        let (_, key) = ProfileManager::unlock(&dir, Unlock::Passphrase(PASSPHRASE)).unwrap();
        st.unlock_since(&app, key, st.epoch()).unwrap();
        let no = Answer::no();
        let r = change_passphrase(&st, &no, NEW_PASSPHRASE.into(), KdfParams::testing()).await;
        assert_eq!(r, Err(NOT_CONFIRMED.to_string()));
        assert_eq!(no.times(), 1);
        assert!(opens_with(&dir, PASSPHRASE));
    }

    #[tokio::test]
    async fn a_keychain_conversion_is_refused_unless_confirmed_natively() {
        let (_root, st, dir) = opened();
        let no = Answer::no();
        let r = convert_to_passphrase(&st, &no, NEW_PASSPHRASE.into(), KdfParams::testing()).await;
        // Refused before the profile's protection is even looked at.
        assert_eq!(r.map(|_| ()), Err(NOT_CONFIRMED.to_string()));
        assert_eq!(no.times(), 1);
        assert!(opens_with(&dir, PASSPHRASE));
    }

    #[tokio::test]
    async fn sensitive_changes_are_refused_while_locked_without_asking() {
        let (_root, st, _dir) = opened();
        st.lock();
        let yes = Answer::yes();
        let ws = Id::new();
        assert_eq!(change_passphrase(&st, &yes, NEW_PASSPHRASE.into(), KdfParams::testing()).await, Err("LOCKED".to_string()));
        assert_eq!(convert_to_passphrase(&st, &yes, NEW_PASSPHRASE.into(), KdfParams::testing()).await.map(|_| ()), Err("LOCKED".into()));
        assert_eq!(allow_device_identity(&st, &yes, ws).await, Err("LOCKED".to_string()));
        assert_eq!(save_settings(&st, &yes, AppSettings::default()).await, Err("LOCKED".to_string()));
        assert_eq!(yes.times(), 0);
    }

    /// A workspace sealed from this device's workload identity, as a bundle
    /// import or backup restore leaves it.
    fn sealed_workspace(st: &DesktopState) -> Id {
        let app = st.app().unwrap();
        let ws = app.create_workspace("Imported").unwrap().meta.id;
        let seal = DeviceIdentitySeal { workspace_id: ws, sealed_at: chrono::Utc::now() };
        app.store.put(kind::DEVICE_IDENTITY_SEAL, &ws, Some(&ws), None, 0.0, &seal).unwrap();
        assert!(app.device_identity_sealed(&ws).unwrap());
        ws
    }

    #[tokio::test]
    async fn a_device_identity_seal_is_lifted_only_once_confirmed_natively() {
        let (_root, st, _dir) = opened();
        let ws = sealed_workspace(&st);
        let no = Answer::no();
        assert_eq!(allow_device_identity(&st, &no, ws).await, Err(NOT_CONFIRMED.to_string()));
        assert!(st.app().unwrap().device_identity_sealed(&ws).unwrap(), "still sealed");
        let yes = Answer::yes();
        assert_eq!(allow_device_identity(&st, &yes, ws).await, Ok(true));
        assert!(yes.asked.lock()[0].contains("“Imported”"));
        assert!(!st.app().unwrap().device_identity_sealed(&ws).unwrap());
        // Nothing left to lift: not asked.
        let again = Answer::no();
        assert_eq!(allow_device_identity(&st, &again, ws).await, Ok(false));
        assert_eq!(again.times(), 0);
    }

    #[tokio::test]
    async fn an_import_root_is_opened_only_once_confirmed_natively_and_isolated_unasked() {
        let (_root, st, _dir) = opened();
        let app = st.app().unwrap();
        let ws = app.create_workspace("W").unwrap().meta.id;
        // As a spec or collection import leaves its root folder.
        let mut f = app.create_folder(&ws, None, "Petstore").unwrap();
        f.import_root = true;
        app.store.put(kind::FOLDER, &f.meta.id, Some(&f.workspace_id), f.parent_id.as_ref(), f.sort_key, &f).unwrap();
        let root = f.meta.id;
        let no = Answer::no();
        assert_eq!(set_workspace_scope(&st, &no, root, true).await.map(|_| ()), Err(NOT_CONFIRMED.to_string()));
        assert!(!app.folder(&root).unwrap().use_workspace_scope);
        let yes = Answer::yes();
        assert!(set_workspace_scope(&st, &yes, root, true).await.unwrap().use_workspace_scope);
        assert_eq!(yes.times(), 1);
        // Isolating again strengthens it: not asked.
        let unasked = Answer::no();
        assert!(!set_workspace_scope(&st, &unasked, root, false).await.unwrap().use_workspace_scope);
        assert_eq!(unasked.times(), 0);
    }

    #[test]
    fn only_a_weaker_lock_policy_counts_as_weakening() {
        let base = LockPolicy::default();
        let with = |f: fn(&mut LockPolicy)| {
            let mut p = LockPolicy::default();
            f(&mut p);
            p
        };
        assert!(lock_weakening(&base, &base).is_empty());
        assert!(lock_weakening(&base, &with(|p| p.idle_minutes = 5)).is_empty(), "a shorter timeout is stronger");
        assert_eq!(lock_weakening(&base, &with(|p| p.idle_minutes = 0)).len(), 1);
        assert_eq!(lock_weakening(&base, &with(|p| p.idle_minutes = 60)).len(), 1);
        assert_eq!(lock_weakening(&base, &with(|p| p.lock_on_os_lock = false)).len(), 1);
        assert_eq!(lock_weakening(&base, &with(|p| p.clear_clipboard_on_lock = false)).len(), 1);
        // From "never", any timeout is stronger.
        let never = with(|p| p.idle_minutes = 0);
        assert!(lock_weakening(&never, &with(|p| p.idle_minutes = 600)).is_empty());
        assert!(lock_weakening(&with(|p| p.lock_on_os_lock = false), &base).is_empty());
    }

    #[tokio::test]
    async fn a_weaker_lock_policy_is_saved_only_once_confirmed_natively() {
        let (_root, st, _dir) = opened();
        let app = st.app().unwrap();
        let mut weaker = app.settings().unwrap();
        weaker.lock.idle_minutes = 0;
        weaker.lock.lock_on_os_lock = false;
        let no = Answer::no();
        assert_eq!(save_settings(&st, &no, weaker.clone()).await, Err(NOT_CONFIRMED.to_string()));
        assert_eq!(app.settings().unwrap().lock, LockPolicy::default());
        let yes = Answer::yes();
        save_settings(&st, &yes, weaker.clone()).await.unwrap();
        assert_eq!(app.settings().unwrap().lock, weaker.lock);
        assert_eq!(yes.times(), 1);
    }

    #[tokio::test]
    async fn other_settings_and_a_stronger_lock_policy_are_saved_unasked() {
        let (_root, st, _dir) = opened();
        let app = st.app().unwrap();
        let mut stronger = app.settings().unwrap();
        stronger.lock.idle_minutes = 5;
        stronger.autosave = !stronger.autosave;
        let unasked = Answer::no();
        save_settings(&st, &unasked, stronger.clone()).await.unwrap();
        assert_eq!(unasked.times(), 0);
        let saved = app.settings().unwrap();
        assert_eq!((saved.lock, saved.autosave), (stronger.lock, stronger.autosave));
    }

    #[tokio::test]
    async fn a_confirmation_is_not_applied_over_a_lock_policy_changed_while_it_was_asked() {
        let (_root, st, _dir) = opened();
        let app = st.app().unwrap();
        let mut weaker = app.settings().unwrap();
        weaker.lock.idle_minutes = 0;
        let meanwhile = || {
            let mut other = app.settings().unwrap();
            other.lock.idle_minutes = 1;
            app.save_settings_keeping_standards(&other).unwrap();
        };
        let yes = Answer::with(true, meanwhile);
        assert!(save_settings(&st, &yes, weaker).await.unwrap_err().contains("changed meanwhile"));
        assert_eq!(app.settings().unwrap().lock.idle_minutes, 1);
    }

    #[test]
    fn activity_reports_alone_cannot_hold_off_the_idle_lock() {
        let minute = Duration::from_secs(60);
        // Reported activity within the timeout, native presence recent: not due.
        assert!(!idle_lock_due(15, minute, minute));
        // No activity report for longer than the timeout: due.
        assert!(idle_lock_due(15, 16 * minute, minute));
        // Constant reports, but no native sign of the user past the ceiling: due.
        assert!(idle_lock_due(15, Duration::ZERO, RENDERER_ACTIVITY_CEILING + minute));
        // A timeout longer than the ceiling is the bound instead.
        assert!(!idle_lock_due(600, Duration::ZERO, RENDERER_ACTIVITY_CEILING + minute));
        assert!(idle_lock_due(600, Duration::ZERO, 601 * minute));
        // Never locking when idle was itself confirmed natively.
        assert!(!idle_lock_due(0, Duration::MAX, Duration::MAX));
    }

    #[test]
    fn an_activity_report_is_no_native_sign_of_the_user() {
        let root = TempRoot::new();
        let st = DesktopState::new(root.0.clone());
        std::thread::sleep(Duration::from_millis(20));
        for _ in 0..5 {
            st.touch();
        }
        assert!(st.presence.native_idle() >= Duration::from_millis(20), "touch never counts as native presence");
        st.presence.saw_user();
        assert!(st.presence.native_idle() < Duration::from_millis(20));
    }
}
