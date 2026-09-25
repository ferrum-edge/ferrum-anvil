//! Ferrum Anvil desktop shell.

mod cmd_load;
mod cmd_sessions;
mod cmd_specs;
mod commands;
mod state;

pub use cmd_load::LOAD_WORKER_FLAG;

/// Entry point when the executable is re-launched as a load worker: read
/// one job from stdin, stream progress and the report to stdout, exit.
/// Exits the process directly: dropping the runtime would wait for the
/// blocking stdin reader thread and the worker would never terminate.
pub fn run_load_worker() -> ! {
    anvil_transport::init();
    let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(err) => {
            eprintln!("load worker: {err}");
            std::process::exit(70);
        }
    };
    let code = rt.block_on(anvil_load::worker::run_stdio());
    std::process::exit(code)
}

use state::DesktopState;
use std::time::{Duration, Instant, SystemTime};
use tauri::{Emitter, Manager};

pub fn run() {
    anvil_transport::init();
    let data_dir = std::env::var_os("ANVIL_DATA_DIR").map(std::path::PathBuf::from).unwrap_or_else(anvil_storage::default_data_dir);
    let builder = tauri::Builder::default().plugin(tauri_plugin_dialog::init());
    #[cfg(feature = "e2e")]
    let builder = builder.plugin(tauri_plugin_wdio_webdriver::init());
    builder
        .manage(DesktopState::new(data_dir))
        .setup(|app| {
            #[cfg(feature = "e2e")]
            e2e_unlock(&app.state::<DesktopState>());
            let handle = app.handle().clone();
            // Auto-lock: idle timeout and suspend detection (the monotonic clock
            // does not advance while the machine sleeps; the wall clock does).
            tauri::async_runtime::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    let st = handle.state::<DesktopState>();
                    let (idle_minutes, lock_on_sleep, unlocked) = {
                        let g = st.app.read();
                        match g.as_ref() {
                            Some(a) if !a.is_locked() => {
                                let s = a.settings().unwrap_or_default();
                                (s.lock.idle_minutes, s.lock.lock_on_os_lock, true)
                            }
                            _ => (0, false, false),
                        }
                    };
                    let suspended = {
                        let mut p = st.clock_probe.lock();
                        let mono = p.0.elapsed();
                        let wall = SystemTime::now().duration_since(p.1).unwrap_or_default();
                        *p = (Instant::now(), SystemTime::now());
                        wall > mono + Duration::from_secs(30)
                    };
                    if !unlocked {
                        continue;
                    }
                    let idle = st.last_activity.lock().elapsed();
                    let idle_hit = idle_minutes > 0 && idle > Duration::from_secs(idle_minutes as u64 * 60);
                    if idle_hit || (suspended && lock_on_sleep) {
                        st.lock();
                        let _ = handle.emit("locked", if idle_hit { "idle" } else { "suspend" });
                    }
                }
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::app_status,
            commands::profiles_list,
            commands::profile_create,
            commands::profile_unlock,
            commands::app_lock,
            commands::profile_change_passphrase,
            commands::touch,
            commands::system_info,
            commands::workspaces_list,
            commands::workspace_create,
            commands::workspace_save,
            commands::workspace_delete,
            commands::tree_get,
            commands::folder_create,
            commands::folder_get,
            commands::folder_save,
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
            commands::secret_update,
            commands::dpop_generate_key,
            commands::tls_profiles_list,
            commands::tls_profile_save,
            commands::proxy_profiles_list,
            commands::proxy_profile_save,
            commands::integrations_list,
            commands::integration_save,
            commands::settings_get,
            commands::settings_save,
            commands::effective_request,
            commands::send_request,
            commands::cancel_execution,
            commands::history_list,
            commands::history_get,
            commands::history_clear,
            commands::lint_body,
            commands::jwt_inspect,
            commands::export_preview,
            commands::export_to_path,
            commands::import_preview,
            commands::import_apply,
            commands::attachment_add,
            commands::read_text_file,
            cmd_load::load_plans,
            cmd_load::load_plan_save,
            cmd_load::load_plan_delete,
            cmd_load::load_preflight,
            cmd_load::load_run_start,
            cmd_load::load_run_cancel,
            cmd_load::load_reports,
            cmd_load::load_report,
            cmd_load::load_report_delete,
            cmd_load::load_report_export,
            cmd_load::load_compare,
            cmd_load::datasets_list,
            cmd_load::dataset_add,
            cmd_sessions::session_open,
            cmd_sessions::session_send,
            cmd_sessions::session_cancel,
            cmd_specs::spec_preview,
            cmd_specs::spec_import,
            cmd_specs::spec_sources,
            cmd_specs::spec_reimport_plan,
            cmd_specs::spec_reimport_apply,
        ])
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
    match anvil_app::profiles::ProfileManager::unlock(&dir, anvil_app::profiles::Unlock::Passphrase(&pass)) {
        Ok((header, key)) => match anvil_app::App::open(dir, header, key) {
            Ok(app) => *st.app.write() = Some(std::sync::Arc::new(app)),
            Err(e) => eprintln!("e2e: open failed: {e}"),
        },
        Err(e) => eprintln!("e2e: unlock failed: {e}"),
    }
}
