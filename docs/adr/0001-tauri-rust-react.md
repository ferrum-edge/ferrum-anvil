# ADR 0001: Tauri 2, Rust core, React/TypeScript renderer

## Context
Anvil must run on Windows, macOS and Linux, work offline, keep secrets out of a
browser runtime, and share one execution engine across the desktop, the CLI,
the collection runner and the load worker (plan §4).

## Decision
- Tauri 2 shell with a Rust backend. All network, TLS, auth, storage and
  diagnostics code is Rust, in reusable crates (`crates/*`).
- React 19 + TypeScript renderer with a strict CSP. It talks to the backend
  only through typed IPC commands and events. Types are generated from the
  Rust JSON Schemas, so the UI cannot drift from the contracts.
- The CLI links the same `anvil-app` services.

## Consequences
- The engine is identical everywhere, so a manual Send and a load iteration
  send the same bytes.
- The webview can be compromised by rendered content without gaining network
  or vault access: it has no such capabilities, and no response is ever
  rendered as HTML.
- WebKitGTK on Linux and WKWebView on macOS bring platform quirks: native
  select menus, autocorrect (disabled globally for inputs), and
  `acceptFirstMouse` (enabled).
