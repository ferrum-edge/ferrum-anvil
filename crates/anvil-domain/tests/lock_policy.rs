//! The lock policy holds only what the app enforces, and settings stored by
//! a build that still had `autosave`, `run_policy` and
//! `clear_clipboard_on_lock` open unchanged otherwise.

use anvil_domain::settings::{AppSettings, LockPolicy};

#[test]
fn settings_stored_with_the_removed_fields_still_open() {
    let mut stored = serde_json::to_value(AppSettings::default()).unwrap();
    stored["autosave"] = true.into();
    stored["lock"]["run_policy"] = "stop_runs".into();
    stored["lock"]["clear_clipboard_on_lock"] = false.into();
    stored["lock"]["idle_minutes"] = 5.into();
    let opened: AppSettings = serde_json::from_value(stored).unwrap();
    assert_eq!(opened.lock, LockPolicy { idle_minutes: 5, lock_on_os_lock: true });
    let saved = serde_json::to_value(&opened).unwrap();
    assert!(saved.get("autosave").is_none());
    assert_eq!(saved["lock"].as_object().unwrap().len(), 2, "{saved}");
}

#[test]
fn only_the_timeout_and_locking_on_sleep_can_weaken_the_lock_policy() {
    let base = LockPolicy::default();
    assert_eq!(base.weakening(&LockPolicy { idle_minutes: 0, ..base.clone() }), ["never lock after inactivity"]);
    assert_eq!(base.weakening(&LockPolicy { lock_on_os_lock: false, ..base.clone() }), ["no longer lock when the computer sleeps"]);
    assert!(base.weakening(&LockPolicy { idle_minutes: 1, ..base.clone() }).is_empty());
}
