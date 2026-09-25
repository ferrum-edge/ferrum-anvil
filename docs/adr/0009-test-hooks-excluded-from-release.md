# ADR 0009: Test hooks only behind a cargo feature

## Decision
- The embedded WebDriver (`tauri-plugin-wdio-webdriver`) and the environment-
  driven profile unlock used by native E2E are compiled only with the
  `anvil-desktop` cargo feature `e2e`.
- Release builds never enable the feature. `scripts/release-check.sh`
  inspects the release binaries for plugin symbols and the e2e unlock
  strings, and fails the release if they are present.
- Mock identity providers follow the same rule (`mock-provider` feature).

## Consequences
- E2E tests drive the real native engine without typing credentials into
  the UI, and shipped artifacts contain no driver port or backdoor unlock.
