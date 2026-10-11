//! Ferrum Anvil desktop shell.

mod cmd_diagnostic_import;
mod cmd_drift;
mod cmd_files;
mod cmd_identity;
mod cmd_load;
mod cmd_runner;
mod cmd_sessions;
mod cmd_specs;
mod cmd_standards;
mod cmd_update;
mod commands;
mod draft_authority;
#[cfg(test)]
mod payload_tests;
mod presence;
mod state;

pub use cmd_load::LOAD_WORKER_FLAG;

/// Entry point when the executable is re-launched as a load worker: read
/// one job from stdin, stream progress and the report to stdout, exit.
/// Exits the process directly: dropping the runtime would wait for the
/// blocking stdin reader thread and the worker would never terminate.
pub fn run_load_worker() -> ! {
    anvil_transport::init();
    // Windows gives the main thread only 1 MiB of stack (Linux/macOS: 8 MiB);
    // drive the worker from a thread with more.
    let main = std::thread::Builder::new().name("anvil-load-worker".into()).stack_size(MAIN_STACK).spawn(|| {
        let rt = match runtime() {
            Ok(rt) => rt,
            Err(err) => {
                eprintln!("load worker: {err}");
                std::process::exit(70);
            }
        };
        let code = rt.block_on(anvil_load::worker::run_stdio());
        std::process::exit(code)
    });
    match main {
        Ok(t) => {
            let _ = t.join();
            std::process::exit(101)
        }
        Err(err) => {
            eprintln!("load worker: {err}");
            std::process::exit(70)
        }
    }
}

/// Stack for a thread that drives a top-level future (see `run_load_worker`).
const MAIN_STACK: usize = 16 << 20;
/// Stack for async runtime workers (Tokio's default is 2 MiB), where commands,
/// sessions and collection runs are polled.
const WORKER_STACK: usize = 8 << 20;

fn runtime() -> std::io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread().thread_stack_size(WORKER_STACK).enable_all().build()
}

use state::DesktopState;
use std::time::{Duration, Instant, SystemTime};
use tauri::{Emitter, Manager};

pub fn run() {
    anvil_transport::init();
    // Give Tauri a runtime whose workers have larger stacks than the default.
    // The runtime must outlive the app, so it is intentionally leaked.
    match runtime() {
        Ok(rt) => tauri::async_runtime::set(Box::leak(Box::new(rt)).handle().clone()),
        Err(err) => eprintln!("could not build the async runtime, using Tauri's default: {err}"),
    }
    let data_dir = std::env::var_os("ANVIL_DATA_DIR").map(std::path::PathBuf::from).unwrap_or_else(anvil_storage::default_data_dir);
    let builder = tauri::Builder::default().plugin(tauri_plugin_dialog::init()).plugin(tauri_plugin_updater::Builder::new().build());
    #[cfg(feature = "e2e")]
    let builder = builder.plugin(tauri_plugin_wdio_webdriver::init());
    builder
        .manage(DesktopState::new(data_dir))
        .setup(|app| {
            // Warnings and notices (a stored object that does not decode, a
            // cleanup that did not finish) go to a bounded log file in the
            // app's log directory; ANVIL_LOG sets another level.
            match app.path().app_log_dir() {
                Ok(dir) => {
                    if let Err(err) = anvil_app::logging::log_to_file(&dir, anvil_app::logging::LevelFilter::INFO) {
                        eprintln!("could not open the log file in {}: {err}", dir.display());
                    }
                }
                Err(err) => eprintln!("no log directory: {err}"),
            }
            #[cfg(feature = "e2e")]
            e2e_unlock(&app.state::<DesktopState>());
            let handle = app.handle().clone();
            // Auto-lock: idle timeout and suspend detection (the monotonic clock
            // does not advance while the machine sleeps; the wall clock does).
            tauri::async_runtime::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    let st = handle.state::<DesktopState>();
                    let open = st.app.read().as_ref().cloned();
                    let (idle_minutes, lock_on_sleep, owner) = match open {
                        Some(a) => {
                            if a.is_locked() {
                                st.lock_integrity_if_current(&a);
                                continue;
                            }
                            // Read on a blocking thread: the store may be held by a long transaction.
                            let reading = a.clone();
                            match anvil_app::off_runtime(move || reading.settings()).await {
                                Ok(s) => (s.lock.idle_minutes, s.lock.lock_on_os_lock, Some(a)),
                                Err(_) => {
                                    if st.lock_if_current(&a) {
                                        let _ = handle.emit("locked", "profile integrity");
                                    }
                                    continue;
                                }
                            }
                        }
                        None => (0, false, None),
                    };
                    let suspended = {
                        let mut p = st.clock_probe.lock();
                        let mono = p.0.elapsed();
                        let wall = SystemTime::now().duration_since(p.1).unwrap_or_default();
                        *p = (Instant::now(), SystemTime::now());
                        wall > mono + Duration::from_secs(30)
                    };
                    let Some(owner) = owner else { continue };
                    let idle_hit = st.idle_lock_due(idle_minutes);
                    if (idle_hit || (suspended && lock_on_sleep)) && st.lock_if_current(&owner) {
                        let _ = handle.emit("locked", if idle_hit { "idle" } else { "suspend" });
                    }
                }
            });
            Ok(())
        })
        // The OS reports focus to the backend directly: a native sign of the
        // user for the idle lock, which the webview's reports are not.
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::Focused(true) = event {
                window.state::<DesktopState>().presence.saw_user();
            }
        })
        .invoke_handler(commands::with_execution_commands(tauri::generate_handler![
            cmd_diagnostic_import::diagnostic_import_preview,
            commands::app_status,
            commands::profiles_list,
            commands::profile_create,
            commands::profile_unlock,
            commands::profile_enroll_unlinked,
            commands::app_lock,
            commands::profile_change_passphrase,
            commands::profile_convert_to_passphrase,
            commands::touch,
            commands::system_info,
            commands::workspaces_list,
            commands::workspace_create,
            commands::workspace_save,
            commands::workspace_delete,
            commands::workspace_device_identity_sealed,
            commands::workspace_allow_device_identity,
            commands::tree_get,
            commands::folder_create,
            commands::folder_get,
            commands::folder_save,
            commands::folder_set_workspace_scope,
            commands::folder_move,
            commands::folder_delete,
            commands::request_create,
            commands::request_get,
            commands::request_save,
            commands::request_move,
            commands::request_duplicate,
            commands::request_delete,
            commands::search,
            commands::environments_list,
            commands::environment_save,
            commands::environment_delete,
            commands::secret_create,
            commands::dpop_generate_key,
            commands::tls_profiles_list,
            commands::tls_profile_save,
            commands::proxy_profiles_list,
            commands::proxy_profile_save,
            commands::integrations_list,
            commands::integration_save,
            commands::settings_get,
            commands::settings_save,
            commands::storage_cleanup_last,
            commands::storage_cleanup_now,
            commands::storage_undecodable_revisions,
            commands::storage_revisions_remove,
            commands::cancel_execution,
            commands::history_list,
            commands::history_get,
            commands::history_clear,
            commands::lint_body,
            commands::jwt_inspect,
            commands::workload_probe,
            commands::export_preview,
            commands::export_to_path,
            commands::import_preview,
            commands::import_apply,
            commands::import_cancel,
            commands::attachment_add,
            commands::read_certificate_file,
            commands::import_private_key_file,
            commands::import_pkcs12_file,
            cmd_files::file_choose,
            cmd_files::certificate_file_choose,
            cmd_files::private_key_file_choose,
            cmd_files::token_files_list,
            cmd_files::token_file_remove,
            cmd_files::linked_file_status,
            cmd_load::load_plans,
            cmd_load::load_plan_save,
            cmd_load::load_plan_delete,
            cmd_load::load_preflight,
            cmd_load::load_plan_check,
            cmd_load::load_run_start,
            cmd_load::load_run_cancel,
            cmd_load::load_reports,
            cmd_load::load_report,
            cmd_load::load_report_delete,
            cmd_load::load_report_export,
            cmd_load::load_compare,
            cmd_load::datasets_list,
            cmd_load::dataset_add,
            cmd_runner::scenarios_list,
            cmd_runner::scenario_create,
            cmd_runner::scenario_save,
            cmd_runner::scenario_trust,
            cmd_runner::scenario_delete,
            cmd_runner::run_start,
            cmd_runner::run_cancel,
            cmd_runner::run_reports,
            cmd_runner::run_report,
            cmd_runner::run_report_delete,
            cmd_runner::run_report_export,
            cmd_identity::oauth_sign_in,
            cmd_identity::oauth_cancel,
            cmd_identity::oauth_token_status,
            cmd_identity::oauth_sign_out,
            cmd_identity::login_providers,
            cmd_specs::spec_preview,
            cmd_specs::spec_import,
            cmd_specs::spec_sources,
            cmd_specs::spec_reimport_plan,
            cmd_specs::spec_reimport_apply,
            cmd_standards::standards_view,
            cmd_standards::standards_ruleset_text,
            cmd_standards::standards_add,
            cmd_standards::standards_replace,
            cmd_standards::standards_remove,
            cmd_standards::standards_set_enabled,
            cmd_standards::standards_set_recommended,
            cmd_standards::standards_lint,
            cmd_standards::standards_report_export,
            cmd_drift::drift_report,
            cmd_drift::drift_check_execution,
            cmd_drift::drift_revise,
            cmd_drift::drift_reimport_plan,
            cmd_drift::drift_reimport_apply,
            cmd_drift::drift_export,
            cmd_update::update_check_on_launch,
            cmd_update::update_check,
            cmd_update::update_install,
            cmd_update::update_restart,
            cmd_update::update_open_release_page,
        ]))
        .run(tauri::generate_context!())
        .expect("error while running Ferrum Anvil");
}

/// Test-only: create/unlock a passphrase profile from the environment so
/// native E2E runs never type credentials into the UI. Compiled only with the
/// `e2e` feature; release builds do not contain this code (checked by
/// `scripts/release-check.sh`).
#[cfg(feature = "e2e")]
fn e2e_unlock(st: &DesktopState) {
    let (Some(name), Some(pass)) = (std::env::var("ANVIL_E2E_PROFILE").ok(), std::env::var("ANVIL_E2E_PASSPHRASE").ok()) else {
        return;
    };
    let dir = match st.profiles.list().into_iter().find(|p| p.display_name == name) {
        Some(p) => p.dir,
        None => match st.profiles.create_passphrase(&name, &pass, anvil_storage::KdfParams::interactive()) {
            Ok((s, _, _)) => s.dir,
            Err(e) => return eprintln!("e2e: create profile failed: {e}"),
        },
    };
    let seen = st.epoch();
    match anvil_app::profiles::ProfileManager::unlock(&dir, anvil_app::profiles::Unlock::Passphrase(&pass)) {
        Ok((header, key)) => match anvil_app::App::open(dir, header, key) {
            Ok(app) => {
                if let Err(e) = st.set_app_since(app, seen) {
                    eprintln!("e2e: open failed: {e}");
                }
            }
            Err(e) => eprintln!("e2e: open failed: {e}"),
        },
        Err(e) => eprintln!("e2e: unlock failed: {e}"),
    }
}
