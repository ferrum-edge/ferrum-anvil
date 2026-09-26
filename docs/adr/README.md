# Architecture decision records

| # | Decision | Status |
|---|---|---|
| [0001](0001-tauri-rust-react.md) | Tauri 2 + Rust core + React/TypeScript renderer | Accepted |
| [0002](0002-typed-transport-evidence.md) | Instrumented hyper/rustls/quinn transport with typed phase evidence | Accepted |
| [0003](0003-deterministic-diagnostics.md) | Deterministic, catalog-worded diagnostics with confidence ceilings | Accepted |
| [0004](0004-encrypted-local-store.md) | Encrypted SQLite store, Argon2id/keychain key wrapping, recovery key | Accepted |
| [0005](0005-portable-bundles.md) | Portable bundles with placeholder sanitisation and passphrase encryption | Accepted |
| [0006](0006-load-worker-process.md) | Native load engine in a self-launched worker process | Accepted |
| [0007](0007-real-gateway-lab.md) | Failure lab driven by the pinned real gateway binary | Accepted |
| [0008](0008-licensing-and-dependencies.md) | Licensing, dependency and native-library decisions | Accepted |
| [0009](0009-test-hooks-excluded-from-release.md) | Test-only WebDriver and unlock hooks behind a cargo feature | Accepted |
| [0010](0010-identity-separation.md) | Three identities; app login is never a vault key | Accepted |
| [0011](0011-per-protocol-load-units.md) | Per-protocol load units with typed denominators; one unit kind per plan | Accepted |
