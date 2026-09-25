//! Managed load worker. Reads one job from stdin (never argv), streams
//! NDJSON progress and a final report to stdout. See `anvil_load::worker`.

fn main() {
    if std::env::args_os().len() > 1 {
        eprintln!("anvil-load-worker takes no arguments; the job is read from stdin");
        std::process::exit(64);
    }
    // Windows gives the main thread only 1 MiB of stack; drive the worker
    // from a thread with more, like the CLI and the desktop app do.
    let main = std::thread::Builder::new()
        .name("anvil-load-worker".into())
        .stack_size(16 << 20)
        .spawn(|| {
            let rt = tokio::runtime::Builder::new_multi_thread().thread_stack_size(8 << 20).enable_all().build().expect("tokio runtime");
            let code = rt.block_on(anvil_load::worker::run_stdio());
            // Exit without waiting for the blocking stdin reader thread.
            std::process::exit(code);
        })
        .expect("start the worker thread");
    let _ = main.join();
    std::process::exit(101);
}
