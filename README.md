# Ferrum Anvil

**Put your APIs to the test.**

Ferrum Anvil is a local-first desktop and command-line API client for Windows,
macOS and Linux. It builds and sends requests, runs repeatable tests and load
tests, and explains failures using what actually happened on the wire rather
than rewording status codes. It works offline with no account, and has deeper,
explicitly bounded troubleshooting for Ferrum Edge gateways.

> Status: pre-release. There are no signed installers yet (signing is pending
> owner credentials; see `docs/release.md`). Build from source for now.

## What it does

- **Build and send**: workspaces with nested folders, saved requests with
  immutable revisions, environments and variables, history. Requests can
  use HTTP/1.1, HTTP/2 (TLS or h2c) and HTTP/3; WebSocket (HTTP/1.1 Upgrade
  or HTTP/2 extended CONNECT); gRPC in all four modes; SSE; TCP/TLS;
  UDP/DTLS. Interactive sessions let you send and receive messages live.
- **Auth and TLS**:
  - Auth types: API key, Basic, Bearer, JWT signing, OAuth 2.0, Ferrum HMAC
    v2, DPoP, WS-Security, and multi-auth.
  - OAuth 2.0 supports client credentials, refresh, and auth code + PKCE via
    the system browser.
  - TLS: mTLS with PEM or PKCS#12 client certificates bound to hosts, and
    private CA roots.
  - Verification is on by default. A bypass is scoped to a profile and
    warned about.
- **Understand the failure**: every response is analysed by deterministic
  rules over typed evidence.
  - The evidence covers DNS, connect and TLS phases, dispatch state, HTTP/2
    signals, body completeness, gRPC trailers and WebSocket close codes.
  - Each finding carries a confidence (confirmed, likely, unknown or
    conflicting), the leg it is about, an owner, what the evidence does
    *not* prove, alternatives, and next steps.
  - Ferrum Edge markers count only for gateways you declare, are capped at
    "likely", and are never refined into causes the gateway does not
    expose. See `docs/diagnostics.md`.
- **Test under load**: open (arrival rate), closed (virtual users) and
  iteration workloads run in a separate worker process with the same
  request preparation as Send. Reports include balanced ledgers, HDR
  percentiles, a timeline, generator health, exports (HTML, JSON, CSV) and
  run comparison.
- **Import and share**:
  - Import OpenAPI 2.0–3.2, WSDL 1.1, Postman, Insomnia, cURL and HAR with a
    preview report.
  - Export portable workspace bundles (share safely without secrets, or
    encrypted), or full encrypted backups that restore on a clean machine.
- **Local protection**: everything is encrypted on disk (XChaCha20-Poly1305).
  Unlock with a passphrase and recovery key, or the OS keychain, and set an
  idle or sleep auto-lock. The lock is enforced in the backend.

## Build and run

Requirements: Rust (stable, see `rust-toolchain.toml`), Node ≥ 22. On Linux,
Tauri's WebKitGTK dependencies are also required.

```bash
cargo build --workspace                   # engine, CLI, lab
cargo test --workspace --exclude anvil-desktop
cd apps/desktop && npm ci && npx tauri dev   # desktop app (dev)
```

CLI quick start:

```bash
anvil profile create me          # passphrase from --passphrase-stdin or ANVIL_PASSPHRASE
anvil workspace create Demo
anvil add Demo "Health" --url https://example.com/health
anvil send Health --workspace Demo
anvil import-spec Demo openapi.yaml     # OpenAPI/WSDL/Postman/Insomnia/cURL/HAR
anvil run Demo --folder Smoke --junit report.xml
```

Real-gateway failure lab (pinned Ferrum Edge release, loopback only):

```bash
lab/scripts/fetch-gateway.sh              # download + verify the pinned binary
cargo run -p anvil-lab -- list            # profiles
cargo run -p anvil-lab -- run all --untrusted-pass
cargo run -p anvil-lab -- up core         # keep the core lab up for manual testing
```

## Documentation

| Topic | Document |
|---|---|
| Architecture and crates | `docs/architecture.md`, `docs/adr/` |
| Diagnostics and the Ferrum catalog | `docs/diagnostics.md`, `docs/audit/` |
| Proposed gateway diagnostic contract | `docs/g01-gateway-diagnostic-contract.md` |
| Storage, lock, recovery, migration | `docs/storage-and-recovery.md` |
| Threat model | `docs/threat-model.md` |
| Protocols | `docs/protocols.md` |
| Imports | `docs/import.md` |
| Load testing | `docs/load.md` |
| Collection runner | `docs/runner.md` |
| App identity and OAuth | `docs/identity.md` |
| Failure lab | `docs/lab/` |
| CI and releases | `docs/ci.md`, `docs/release.md` |
| Measured resource budgets | `docs/performance.md` |
| Failure-matrix coverage | `docs/verification/matrix-coverage.md` |
| Sample workspace and saved reports | `samples/` |

## License

Dual-licensed: [PolyForm Noncommercial 1.0.0](LICENSE) for noncommercial use,
and a [commercial license](LICENSE-COMMERCIAL.md) for commercial use.
