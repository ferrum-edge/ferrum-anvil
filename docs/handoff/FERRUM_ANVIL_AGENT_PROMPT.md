# Ferrum Anvil — implementing agent instructions

Build **Ferrum Anvil — “Put your APIs to the test”** using the accompanying `FERRUM_ANVIL_BUILD_PLAN.md` as the product specification and `FERRUM_ANVIL_FAILURE_MATRIX.json` as a seed acceptance catalog. These files are requirements, not evidence of completed implementation or passing tests.

## Mission

Deliver a standalone Windows/macOS/Linux API and network testing desktop app that works without Ferrum Edge or an account. Implement the defined workspaces, folders, saved requests, full portable backup/restore, auth/TLS, live lint, spec import, timing/sizes, collection tests, native load testing, and offline reports. Its differentiating feature is accurate, evidence-based Ferrum troubleshooting with safe remediation and explicit uncertainty.

The full build must progress beyond the usable core beta to the full requested v1 capability gate. Do not quietly omit advanced protocol/auth requirements or social-protection workflows and call the entire assignment complete. Features awaiting genuine dependencies must remain explicitly unavailable rather than replaced with success-shaped stubs.

## Start with actual repositories and source truth

1. Locate/create the intended `ferrum-edge/ferrum-anvil` working tree according to authorized repository policies. Inspect existing repo state before creating anything. Read all applicable agent and contribution instructions.
2. Inspect current `ferrum-edge/ferrum-edge` and select exact source and released-binary compatibility targets. The plan’s reviewed source SHA is `8ef06f2cece2847b552b7858c73fa9a1a265442f`; it is not a release availability claim. Reconcile changes since that snapshot.
3. Audit the relevant typed error classes, public marker writers, rejection phases, protocol completion paths, auth canonicalization, plugin outcomes, and test fixtures. Produce a source-linked outcome inventory before claiming comprehensive coverage.
4. Confirm `ferrum-edge/ferrumedge` is the website working tree. It is a static HTML/CSS/JS site; retain its architecture and existing tests. Foundry/Nexus changes, where needed, are separate narrowly scoped integrations.
5. Record license, native-library, platform, encryption, OAuth/provider and release-signing decisions. Do not copy gateway code into differently licensed components without permission. The inspected wrk license is modified Apache; do not assume it meets a strict Apache-2.0 requirement.

## Architecture and working order

Prefer the proposed Tauri/Rust/React-TypeScript architecture with a shared native transport, auth, evidence and execution core used by desktop, CLI and load workers. Perform the A01 cross-platform feasibility spikes, especially native TLS/mTLS phases, HTTP/2 trailers, H3, DTLS, PKCS#12, local vault behavior and native desktop E2E. Change an implementation choice only through a documented decision preserving the requirements.

Execute the plan’s work packages in dependency order, with small reviewable PRs. First prove the vertical slice: real desktop → real gateway → controlled backend, saved request, actual failure analysis, workspace export/re-import into a clean profile, then successful recovery. Avoid a large mocked UI before this proof. Parallelize independent work only after shared request/event contracts are stable.

Implement storage, vault and export semantics early. Implement auth signing after final request preparation and reuse it unchanged from the load engine. Keep expensive load execution out of the UI process. Treat all remote content and imports as untrusted and bound resource use.

## Diagnostic invariants

- Keep transport completion, application status and assertion results distinct.
- Preserve client-to-peer versus gateway-to-upstream attribution.
- Do not turn the seven coarse `X-Gateway-Error` values into unsupported precise causes.
- In particular, `connection_failure` is not definitely TLS; `backend_error` is not proof the application returned that error; `overload` is not always CPU pressure; a missing marker does not prove upstream origin; a 403 does not prove WAF.
- TLS failures can precede HTTP. HTTP200 can precede an incomplete body or a failed gRPC result. Reused connections do not have new per-request handshakes.
- Use typed phase observations. A message containing “handshake” is not sufficient proof of dispatch safety. Retain per-attempt and whole-request uncertainty; never automatically replay a possibly processed non-idempotent operation.
- Emit confirmed/likely/unknown/conflicting findings according to evidence. Unknown is correct where information is insufficient. Never score a guessed exact answer above an honest supported answer.
- Any proposed detailed gateway diagnostic API/header is NEW WORK. It must be versioned, gateway-owned, least-privilege, bounded, tenant-safe, redacted and tested. Keep existing public tokens unchanged.
- No mandatory cloud service or LLM for diagnostics. No remote response text can instruct the app to expose secrets, change settings or execute code.

## Data, auth and safety invariants

Portable workspace and full-app backups must restore into a clean installation without the original OS keychain. Default sharing excludes secrets; explicit sensitive transfers use portable authenticated encryption. Import is previewed, validated and atomic, with safe conflict policies and rollback. Do not run scripts, requests, load plans or insecure TLS settings merely because they were imported.

Distinguish application login from API auth, and frontend client identity from the gateway’s backend identity. A social identity is not a vault decryption key. Enforce locking in the backend, not only a UI overlay. Handle offline/recovery policy explicitly. Keep provider secrets outside the desktop executable and avoid inventing token endpoints or valid issuer assertions.

Verification remains enabled by default. Show scope and warning for explicit bypass. Do not suggest disabling WAF/TLS as the default fix. Redact bodies, URLs, cookies, headers, logs and datasets as well as named secret variables. Audit database side files, attachments, indexes, crash reports and temporary files for plaintext leakage.

## Implement and execute verification

Implement the 182 seed scenarios in `FERRUM_ANVIL_FAILURE_MATRIX.json`, expanding them to match the actual supported inventory. They are scenario requirements, not ready-to-run tests. For each, provide reproducible setup, independent ground truth, available public evidence, optional authorized detail evidence, expected confidence/alternatives, forbidden claims, remediation, recovery, OS/protocol coverage and result artifacts.

Run real gateway behavior for critical TLS/mTLS/network/auth/WAF/admission/streaming cases. Do not substitute a fake header or injected enum for every end-to-end path. Clearly distinguish unit tests, controlled fault hooks, natural live failures, renderer tests, native E2E and packaged-app smoke tests. Never feed hidden fixture ground truth into a public-only diagnostic test. Verify misleading lookalikes and recovery, not just positive detections.

Run formatting, lints, type checks, unit/property/contract/integration tests, actual native E2E and package/security checks as appropriate. Record exact commands and outputs. Test all advertised OS and protocol capabilities. Ensure production artifacts exclude test-only WebDriver servers, mock commands and fault hooks. Establish and record measured resource/performance budgets; do not invent throughput claims.

## Release and website gate

Create release evidence tying source SHA, version, platform/architecture, artifact filename/hash/signature, test results, compatibility catalog and screenshots together. Actual provider registrations and signing/notarization credentials may need owner-supplied deployment secrets. When unavailable, state the concrete blocked deliverable and continue all independent work; never fake a production login or signed release.

Only after the relevant product-release gate passes, update the static website using the plan’s path checklist. Add Anvil to desktop/mobile navigation, product sections, downloads, release notes and guides. Use real screenshots and actual verified artifact URLs. Do not infer downloads from package versions or publish unsupported claims. Run the existing website tests and link checker plus accessibility and layout checks. A staged website PR is acceptable before release; “available now” is not.

## Completion report

Return repository/PR/commit references, implemented capabilities and limitations, exact test and platform results including failures/skips, signed artifact and checksum references, migration/recovery documentation, diagnostic catalog coverage, the reproducible local lab workflow, and the website PR/publication status. Identify unresolved dependencies honestly. A build that compiles, a mocked UI or a set of unexecuted tests is not a finished product.
