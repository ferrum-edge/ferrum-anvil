// Prevents an additional console window on Windows in release.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    // The app re-launches itself as the load worker (fixed, non-secret flag;
    // the job arrives on stdin) so heavy traffic never runs in the UI process.
    if std::env::args_os().nth(1).is_some_and(|a| a == anvil_desktop_lib::LOAD_WORKER_FLAG) {
        std::process::exit(anvil_desktop_lib::run_load_worker());
    }
    anvil_desktop_lib::run();
}
