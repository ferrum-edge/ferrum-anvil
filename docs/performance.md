# Resource and performance budgets

These are measurements of release builds on one machine, and the initial
budgets derived from them. They are not product claims or benchmarks. Load
engine throughput and worker cost are measured separately in
[load.md](load.md#measured-on-this-hardware-not-product-claims).

Budgets are ceilings with headroom over what was measured. A result above a
budget is a regression to investigate, not a release blocker by itself. CI
does not enforce them yet: RSS and startup time differ enough between
operating systems that each platform needs its own measured baseline first.

## Measured

Apple M4, 10 cores, 16 GB, macOS 26 (Darwin 25.6), arm64, commit `92a4f61`.
The host was also running builds. Each figure is from the release profile.

| What | How | Observed |
|---|---|---|
| Desktop app bundle | `npx tauri build --ci --bundles app,dmg`; `du -sk` | `.app` 34.1 MiB; `.dmg` 13.8 MiB; raw `anvil-desktop` 34.1 MiB |
| CLI binary | `cargo build --release -p anvil-cli` | `anvil` 28.3 MiB |
| Desktop idle memory, lock screen | production binary, fresh `ANVIL_DATA_DIR`, `ps -o rss` at 2, 5 and 10 s, three launches | 87–97 MiB RSS in the app process; 18–24 threads |
| Desktop memory through the full native E2E suite | release build with the test-only `e2e` feature (`npx tauri build --no-bundle --features e2e`), `ps` sampled every 200 ms during the nine spec files the suite had at that commit (requests, diagnosis, TLS failure, a 300-request load run, history, reports, lock) | app peak 236 MiB RSS; load worker peak 21 MiB RSS |
| CLI start | `anvil --version`, 20 runs | median 10 ms, p90 12 ms |
| Profile creation | `anvil profile create --passphrase-stdin` | 191 ms (dominated by the passphrase KDF) |
| One CLI request, end to end | `anvil send --url http://127.0.0.1:<port>/ --passphrase-stdin --no-history` to a local server, 10 runs: unlock, send, diagnose, print | median 115 ms, max 150 ms; peak RSS 87 MiB |

RSS of the desktop app in the table above covers the Rust process only. Automated
cross-platform cold-start (`ui_ready`) and webview helper memory measurements run
in [`.github/workflows/perf.yml`](../.github/workflows/perf.yml) (`perf-summary`
artifact and workflow step summary) via `scripts/perf/measure_desktop.py` on
macOS 15, Ubuntu 26.04 (Xvfb), and Windows 2025.

### Automated desktop performance workflow (`perf.yml`)

Each OS runs two independent runners, launching the release-profile app (default
features, no `e2e` hook) six times with a fresh `ANVIL_DATA_DIR`:

- **Startup readiness (`ui_ready`):** `LockScreen` emits `ui_ready` once profiles
  are read and an interactive form is on screen (or when automatic keychain
  unlock fails and falls back to the unlock form); `Workbench` emits `ui_ready`
  once the initial workspace read (or default workspace creation) finishes. The
  backend logs only the first milestone per process with its `pid` and
  `startup_ms`.
- **First launch vs. later launches:** Launch 1 runs right after extracting the
  build artifact on a shared VM, so its file-cache state is uncontrolled; it is
  reported separately from the median of later launches.
- **Webview helper attribution and isolation:**
  - **Linux (WebKitGTK):** `WebKitWebProcess`, `WebKitNetworkProcess`, and
    `WebKitGPUProcess` descendants of the app PID (verified per-launch process
    tree). WebKitGTK stores both its cache and data under Tauri's
    `app_local_data_dir()` (`XDG_DATA_HOME`), so it retains the runner's normal
    XDG data directory across launches unless `XDG_DATA_HOME` is redirected;
    `ANVIL_DATA_DIR` isolates Anvil's own storage only.
  - **Windows (WebView2):** `msedgewebview2.exe` descendants of the app PID
    (working set and private bytes). Each launch sets a fresh temporary
    `WEBVIEW2_USER_DATA_FOLDER`, which the desktop shell wires into Tauri's
    `WebviewWindowBuilder::data_directory`, so every launch owns an isolated
    WebView2 browser session (later launches do not reuse a warm WebView2 disk
    cache).
  - **macOS (WebKit XPC):** `com.apple.WebKit.*` XPC services are spawned by
    `launchd`. Attribution first checks `launchctl procinfo` for
    `responsible pid == app_pid` (verified). When a binary is launched directly
    rather than via LaunchServices, macOS assigns both the app and its XPC
    helpers the spawning shell/runner as their responsible PID; the harness then
    falls back to provisional attribution (new WebKit services sharing the app's
    responsible PID, or PID-delta if `procinfo` returns no owners). Provisional
    attribution is never used to authorize `SIGKILL`.
- **Artifacts:** Each run publishes the per-lane JSON files and `summary.md`
  under the `perf-summary` artifact (including explicit missing-lane rows if any
  of the six lanes fails to upload a result) and appends `summary.md` to the
  workflow step summary.

## Budgets (macOS arm64)

| Budget | Ceiling | Measured |
|---|---|---|
| `.dmg` download size | 20 MiB | 13.8 MiB |
| Desktop idle RSS at the lock screen | 150 MiB | 87–97 MiB |
| Desktop peak RSS through the E2E suite | 350 MiB | 236 MiB |
| Load worker peak RSS (small run) | 64 MiB | 21 MiB (up to 37 MiB in the heavier runs in load.md) |
| CLI start | 50 ms | 10 ms |
| CLI unlock + one local request | 400 ms | 115 ms |

## Response size limits

Three settings (`limits.*`, on any settings layer) bound how much of a
response body is read and held:

| Limit | Default | What it bounds |
|---|---|---|
| `limits.capture_bytes` | 8 MiB | The prefix of the body kept for display, history, assertions and extractions. A longer body is still read and counted, but marked display-truncated. |
| `limits.max_response_bytes` | 256 MiB | How much of the body is read from the network before reading stops with a local `response_too_large_local` failure. |
| `limits.max_decoded_bytes` | 64 MiB | The decoded size of a gzip, deflate, br or zstd body, held in memory beside the captured bytes. |

A load run lowers the capture to at most 1 MiB per send; see
[load.md](load.md#parity-with-manual-send). When only a prefix of the body is
captured, body assertions and extractions are not evaluated, and neither is the
application outcome of a SOAP or GraphQL request.

## Not measured yet

- Sustained memory and responsiveness under very large responses and long
  sessions (hours) in the desktop app.
- Platform-specific CI enforcement thresholds (Linux, Windows, and macOS
  baselines are collected in `perf.yml`, not release-gating yet).
