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
| Desktop memory through the full native E2E suite | release build with the test-only `e2e` feature (`npx tauri build --no-bundle --features e2e`), `ps` sampled every 200 ms during all nine spec files (requests, diagnosis, TLS failure, a 300-request load run, history, reports, lock) | app peak 236 MiB RSS; load worker peak 21 MiB RSS |
| CLI start | `anvil --version`, 20 runs | median 10 ms, p90 12 ms |
| Profile creation | `anvil profile create --passphrase-stdin` | 191 ms (dominated by the passphrase KDF) |
| One CLI request, end to end | `anvil send --url http://127.0.0.1:<port>/ --passphrase-stdin --no-history` to a local server, 10 runs: unlock, send, diagnose, print | median 115 ms, max 150 ms; peak RSS 87 MiB |

RSS of the desktop app covers the Rust process only. WebKit (macOS), WebKitGTK
(Linux) and WebView2 (Windows) render in separate helper processes, which are
not included and are not yet measured.

## Budgets (macOS arm64)

| Budget | Ceiling | Measured |
|---|---|---|
| `.dmg` download size | 20 MiB | 13.8 MiB |
| Desktop idle RSS at the lock screen | 150 MiB | 87–97 MiB |
| Desktop peak RSS through the E2E suite | 350 MiB | 236 MiB |
| Load worker peak RSS (small run) | 64 MiB | 21 MiB (up to 37 MiB in the heavier runs in load.md) |
| CLI start | 50 ms | 10 ms |
| CLI unlock + one local request | 400 ms | 115 ms |
| Response bytes captured per send | `limits.capture_bytes`: 8 MiB by default; load runs clamp it to 1 MiB by default | — |

The capture row is a configurable setting, not a universal bound on memory
per send. Three byte counts are separate:

- **Captured bytes** (`limits.capture_bytes`): the prefix of the response body
  kept for display, history, assertions and extractions. The default for a
  normal send is 8 MiB. A request or settings layer can set it higher or
  lower. A load run adds a `run:load` layer that lowers it to
  `min(request setting, 1 MiB)` by default (the load executor's
  `response_capture_bytes` option; see [load.md](load.md)). A body larger
  than the capture is still read to the end and counted, but it is marked
  display-truncated, and body assertions and extractions are not evaluated
  against the prefix.
- **Wire-read bytes** (`limits.max_response_bytes`, 256 MiB by default): how
  much of the body is read from the network before reading stops with a local
  `response_too_large` outcome. Bytes past the capture are counted, not kept.
- **Decoded bytes** (`limits.max_decoded_bytes`, 64 MiB by default): the
  ceiling on a content-decoded (gzip, deflate, br, zstd) body, which is
  decoded from the captured bytes and held in memory alongside them.

## Not measured yet

- Desktop cold start to an interactive window. The E2E harness does not time
  it, and the release build has no hook to report it.
- Webview helper process memory on every platform.
- Linux and Windows figures of any kind: those lanes run in CI but have not
  been measured.
- Very large responses and long sessions (hours) in the desktop app.
