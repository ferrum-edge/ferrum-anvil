//! Managed load worker. Reads one job from stdin (never argv), streams
//! NDJSON progress and a final report to stdout. See `anvil_load::worker`.

fn main() {
    if std::env::args_os().len() > 1 {
        eprintln!("anvil-load-worker takes no arguments; the job is read from stdin");
        std::process::exit(64);
    }
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().expect("tokio runtime");
    let code = rt.block_on(anvil_load::worker::run_stdio());
    // Exit without waiting for the blocking stdin reader thread.
    std::process::exit(code);
}
