# Ferrum Anvil
## Put your APIs to the test

**Product specification, implementation handoff, diagnostic contract, verification plan, and website rollout**  
Prepared: September 25, 2026  
Status: Proposed build plan. No Anvil application, gateway changes, test runs, releases, or website changes are represented as completed.

## 1. Product decision

Build a standalone, offline-first API and network testing desktop application for Windows, macOS, and Linux. It must work against ordinary endpoints without Ferrum Edge, a Ferrum account, an administrative connection, or a hosted service. Its Ferrum-specific advantage is evidence-based troubleshooting: explain the observed failure, identify the responsible connection leg or policy when evidence permits, describe what remains uncertain, and suggest safe next steps.

The product promise is **“Send the request. See what happened. Know what to check next.”** Do not promise an exact root cause for every possible failure. Instead require coverage of every inventoried Ferrum outcome in the supported compatibility catalog, plus truthful handling of unknown, contradictory, and unavailable evidence.

A local TLS failure may happen before any HTTP headers exist. Several public Ferrum headers deliberately combine different underlying causes. A reset or silent UDP peer may be intrinsically ambiguous. A correct “not enough evidence to distinguish these causes” is a successful diagnosis, not an implementation failure.

### Fit within the suite

| Product | Responsibility | Anvil relationship |
|---|---|---|
| Ferrum Edge | API/AI gateway and service-mesh runtime | Primary diagnostic integration; still just one destination type |
| Ferrum Foundry | Gateway configuration and administration UI | Read-only context/deep links; no duplicate management plane |
| Ferrum Nexus | API publication, discovery, access, and credential workflows | Import published OpenAPI documents and invoke URLs; receive explicit credential references, not invisible credential copying |
| GitForgeOps | Declarative gateway configuration through Git workflows | Share sanitized collections/tests alongside API changes; do not bypass Git approvals |
| Ferrum Anvil | Request authoring, execution, verification, load testing, and troubleshooting | Local desktop plus a shared headless execution engine |

Existing suite roles are documented by the website [W1]. Reuse the suite’s visual language, not its administrative authority. Never silently edit gateway configuration or rotate credentials to “fix” a failing request.

### Repository boundaries

Propose a new repository `ferrum-edge/ferrum-anvil`; first check whether it now exists. Implement any necessary gateway additions in `ferrum-edge/ferrum-edge`. The website repository is **`ferrum-edge/ferrumedge`**, already identified and inspected. Foundry and Nexus integration changes should be small, separate PRs only when necessary.

Read the applicable `AGENTS.md`, `CLAUDE.md`, `.agents`, `.claude/rules`, contribution, license, and CI instructions in each actual working tree. The gateway currently allows development database resets; do not carry that rule into a shipped desktop app containing customer work. Anvil needs durable migrations and recovery from its first public release.

## 2. Research findings that change the design

### 2.1 Ferrum’s current public diagnostic contract

Research inspected gateway snapshot **`8ef06f2cece2847b552b7858c73fa9a1a265442f`**, including `src/retry.rs`, `docs/error_classification.md`, `FEATURES.md`, and `CLAUDE.md` [G1–G4]. This is a source snapshot, **not a claim that every behavior is present in the latest published binary**. The implementation must independently pin and test actual released binaries and the integration build.

At that snapshot, `ErrorClass::ALL` contains 19 classifications, while `X-Gateway-Error` exposes seven coarse tokens. Its public error vocabulary applies to HTTP-family 5xx paths, not to every gateway rejection.

| Existing signal | Safe interpretation | Inference Anvil must not make |
|---|---|---|
| `connection_failure` | Gateway reports a backend setup/pre-dispatch problem | “Definitely TLS,” “definitely DNS,” or “your desktop certificate is wrong” |
| `backend_timeout` | Gateway reports a backend timeout | Exact read/write/header/handshake stage without additional phase evidence |
| `backend_error` | Backend-related or gateway-observed failure with this coarse classification | Proof that the destination application itself returned the status |
| `circuit_breaker_open` | Gateway rejected this attempt at its circuit-breaker fence | Proof that no earlier retry/attempt reached an upstream |
| `overload` | Gateway refusal in the token’s supported mapping | Always CPU overload: the mapping also includes a response-transformer output ceiling |
| `config_stale` | Data-plane stale-configuration fence | A problem fixable by changing the client payload |
| `concurrency_limit` | Adaptive-concurrency admission rejection | Necessarily a backend crash or application rate-limit response |
| `X-Gateway-Upstream-Status: degraded` | Gateway reports fallback/degraded upstream selection | That an otherwise successful request failed |

The degraded-routing marker is documented in the load-balancing source and guide [G8]. The source taxonomy to inventory and regression-test is:

```text
connection_timeout        connection_refused        connection_reset
connection_closed         dns_lookup_error          tls_error
read_write_timeout        client_disconnect         protocol_error
response_body_too_large   gateway_buffer_capacity   request_body_too_large
connection_pool_error     port_exhaustion           graceful_remote_close
dispatch_policy_rejected  backend_connection_limit  trust_withdrawn
request_error
```

Specific counterexamples matter. `gateway_buffer_capacity` is gateway-local retained-buffer capacity, not proof of an unhealthy application. A backend mTLS failure on the HTTP/1 pooled path can lose the typed handshake evidence and appear as a pool cancellation or conservatively classified post-connect failure. A `200` can precede an incomplete response body. An HTTP `200` can carry a failed gRPC status in trailers. Source comments, docs, and historical troubleshooting text can drift: prefer current typed behavior, validated contracts, and live observations over simplistic message matching [G1, G2].

### 2.2 Practical ideas from other clients

Use Postman’s collection/request organization, environments, assertions, and reusable execution workflow as baseline interaction patterns [E1]. Use Insomnia’s scoped exports, whole-data transfer, external collection/spec import, and CLI-friendly workflow as portability references [E2]. Use SoapUI’s project/test organization and WSDL-driven request workflow as the SOAP baseline [E3]. These are feature inspirations, not a requirement to reproduce entire products, their UI, proprietary formats perfectly, or paid functionality.

Anvil’s differentiation should be **Ferrum-specific, phase-aware, trustworthy explanations with portable local evidence**, not merely “supports collections” or “integrates with a gateway.” Do not make unverified exclusivity claims about competing products.

### 2.3 Load-engine licensing and correctness

The inspected `wrk` license identifies itself as a **Modified Apache 2.0 License**, not unmodified Apache-2.0 [L1]. Do not silently treat it as satisfying a strict Apache-2.0-only dependency requirement.

Recommend an Anvil-owned native load engine sharing the request transport and auth implementation. Apache JMeter is a possible optional Apache-licensed adapter [E4], not the default dependency. Its documentation specifies CLI execution for load and notes that HTTP samplers accept untrusted certificates by default [E5]. An adapter must prove strict certificate/hostname validation and other settings parity or refuse the unsupported configuration. A separate JVM and bundled dependencies require their own license inventory; the runner’s license does not describe every redistributed component.

The application’s first-party license is a product-owner decision. The current gateway is PolyForm Noncommercial with dual commercial licensing [G4]. Do not import gateway code into an Apache-licensed Anvil crate without an explicit rights/license decision. A clean, separately specified protocol adapter avoids unnecessary runtime coupling.

## 3. Delivery scope and release naming

Use two explicit capability gates, not a single enormous unverified “MVP.” **Core beta is a usable first milestone, not completion of the full requested product.** Full v1 closes the requested protocol, auth, diagnostics, and protected-login surface below. Features not completed must remain labeled beta/unsupported and must not be advertised as supported.

| Capability | Core beta | Full requested v1 |
|---|---|---|
| Workspaces, nested folders, saved requests, history, environments | Required | Required |
| Portable workspace and entire-app backup/restore | Required | Required |
| HTTP/1.1, HTTPS, HTTP/2; REST, JSON/XML, basic SOAP, GraphQL-over-HTTP, SSE | Required | Required |
| WebSocket H1 and gRPC unary | Required | Required |
| HTTP/3, gRPC streaming, WS extended CONNECT, TCP/TLS, UDP/DTLS | Parallel spikes; clearly gated | Required for the practical protocol surface in section 7 |
| Basic, bearer, API key, JWT helper, mTLS, OAuth token flows | Required | Required |
| Ferrum HMAC v2, JWKS/DPoP binding, remaining Ferrum auth presentations and SOAP security | Implement in parallel | Required; exact supported profiles documented |
| JSON/XML lint, request assertions, collection runner, dynamic data | Required | Required |
| OpenAPI 3.0/3.1 import, blank/sample generation | Required | Required |
| Swagger 2.0, OpenAPI 3.2, WSDL support | Explicit importer milestones | Required request-generation coverage; unsupported constructs reported |
| Current Ferrum headers plus client-side diagnostics | Required | Required |
| Authenticated detailed gateway diagnostics and source-outcome inventory coverage | Contract first | Required where public evidence cannot meet the target |
| Native load testing and portable reports | Required HTTP-family baseline | Protocol-specific capabilities must match published matrix |
| No-login and encrypted local lock | Required | Required |
| Social login/provider-managed identity | Adapter design | Google, GitHub, Facebook production integrations, subject to supported provider flows and real app registrations |
| Signed desktop distributions, cross-platform E2E, documented compatibility | Required for public beta | Required |

Cloud workspace synchronization, collaborative editing, distributed load farms, an extension marketplace, a browser traffic recorder, Kubernetes workload enrollment, eBPF capture, and a full gateway admin console are not required for v1. They must not delay the local product. An optional JMeter pack is also not a release prerequisite.

### Definition of a useful first vertical slice

On one development machine, run a real Ferrum gateway and controlled backend, create/save a request, send it from the real desktop shell, view native phase evidence, deliberately break the backend, receive an appropriately cautious Ferrum diagnosis, export the workspace, re-import it into a clean profile, and repeat successfully. Do this before building a large polished UI with mocked networking.

## 4. Architecture

### 4.1 Recommended implementation

Use **Tauri 2 + Rust + React/TypeScript/Vite**. The React toolchain aligns with Foundry’s inspected package manifest [G6]; Tauri provides the desktop shell [E6]. These are architectural recommendations, not a reason to pin historical dependency versions from this document. Select reviewed stable versions, commit lockfiles, document license choices, and run the spikes below before depending on a capability.

All actual API/network execution must happen in the Rust backend or its controlled worker processes, not in the UI webview. Keep secrets, certificate selection, socket instrumentation, and protocol behavior out of browser `fetch`. Render remote responses as untrusted content with no Tauri authority. Ordinary desktop calls must not falsely fail because of browser CORS; a separate browser-compatibility/preflight helper may explain CORS behavior without claiming the desktop is a browser.

```text
apps/desktop/                 React UI, Tauri shell, accessibility and navigation
crates/anvil-domain/          Versioned request/config/outcome data contracts
crates/anvil-transport/       Instrumented protocol adapters, pooling, cancellation
crates/anvil-auth/            Auth generation, token lifecycle, signing
crates/anvil-diagnostics/     Evidence normalization, deterministic rules, explanations
crates/anvil-storage/         Encrypted persistence, migrations, retention, recovery
crates/anvil-portability/     Workspace/backups/specs/collection adapters
crates/anvil-runner/          Collection execution, assertions, datasets
crates/anvil-load/            Scheduling, workers, histograms, reports
crates/anvil-cli/             Headless execution using the same libraries
contracts/                    JSON Schema and generated TypeScript bindings
catalog/ferrum/               Versioned diagnostics, compatibility and provenance
lab/                          Gateway/backend/fault fixtures and orchestration
/tests/                       Unit, contract, integration, native E2E, security
/docs/                        User, maintainer, architecture and release evidence
```

Do not link the entire gateway runtime into the desktop app. The shared contract should be a small permissively usable schema/specification with intentionally selected licensing, not a gateway internal type dump.

### 4.2 Transport adapter contract

Each adapter exposes: capability declaration, prepare/validate, execute/cancel, structured events, resource usage, and protocol-specific final outcome. UI/CLI/runner/load should consume the same prepared request and events.

Prefer an explicitly instrumented Tokio/Hyper/rustls HTTP path, with evaluated QUIC/H3 and gRPC libraries behind the same abstraction. A high-level HTTP library is acceptable only if it exposes the required phases and typed failures; do not invent DNS/TLS measurements from a total duration. DTLS needs its own audited implementation choice; TLS support does not establish DTLS support. An OpenSSL-based adapter is a candidate to evaluate, not an assumed finished dependency.

**Blocking feasibility spikes:** Windows/macOS/Linux native TLS and mTLS; custom roots and hostname mismatch; HTTP/2 trailers and streaming cancellation; H3 forced negotiation and fallback reporting; DTLS certificate support; gRPC reflection/proto loading; PKCS#12 import; local vault/keychain behavior; signed packaging; cross-platform native E2E. Record supported versions/features and limitations in architecture decision records. No success-shaped stub for an unsupported transport.

Pool isolation keys must include workspace/security context, destination authority, proxy route, protocol policy, TLS verification/root profile, client certificate identity, and other settings that affect a connection. A request in one workspace must never inherit another workspace’s authenticated connection or cookies. Bound connection counts, buffer size, event queues, retained bodies, and cancellation drain time.

### 4.3 Process and privilege boundaries

The UI receives redacted outcomes and explicitly requested response data. The core owns secret resolution and network activity. Load runs execute in a managed worker process so a busy runner does not freeze the UI. The worker receives a bounded configuration and scoped credentials through authenticated local IPC, not a public TCP server or command-line secrets.

Use a strict content-security policy and narrowly scoped Tauri capabilities. No broad shell permission, arbitrary executable path from an import, remote HTML with application privileges, or untrusted plugin execution. Updater and optional engine downloads must verify signatures/hashes and origin. No request payloads, tokens, or private API URLs leave the machine for telemetry by default.

## 5. Core desktop experience and data model

### 5.1 Workspace UX

Left sidebar: workspace switcher, searchable folder/request tree, environments, collections/tests, load plans, history. Main area: request tabs, method/protocol selector, destination, send/cancel, and panels for parameters, headers, auth, body, certificates, assertions, and settings. Response area: body/messages, headers/trailers, cookies, timing, sizes, diagnostics, and execution log. The diagnostic summary should be visible without replacing the raw evidence.

Support named folders at multiple levels, drag/reorder/move, duplicate, rename, tags, descriptions, favorites, unsaved drafts, explicit save, autosave preference, undo, search across names/URLs, keyboard shortcuts, dark/light themes, resizing, high-DPI displays, and accessible focus states. Preserve original response bytes separately from formatted views. Large content must be virtualized or streamed to bounded storage rather than freezing syntax highlighting.

Store immutable request revisions for reproducible history. Editing a saved request must not retroactively change a previous run. History retention by age and bytes is configurable; a user can turn response-body history off. Redaction applies to history and logs as well as exports.

### 5.2 Minimum domain objects

`Workspace`, `Folder`, `RequestDefinition`, `RequestRevision`, `Environment`, `Variable`, `AuthProfile`, `TlsProfile`, `ProxyProfile`, `Dataset`, `Assertion`, `Scenario`, `LoadPlan`, `Execution`, `ConnectionObservation`, `AttemptObservation`, `DiagnosticFinding`, `Attachment`, `IntegrationProfile`, `UserProfile`, and `AppSettings`.

Every persistent object has stable IDs, schema version, created/updated timestamps, and explicit ownership references. Prevent ancestry cycles and orphaned request references. Secrets are typed references, never ordinary exportable string fields. Binary body attachments are content-addressed and bounded. Historical outcomes record schema version, adapter version, gateway compatibility profile, diagnostic catalog version, and exact request revision.

### 5.3 Settings and variable resolution

Effective non-secret request settings resolve deterministically: application defaults → workspace → ancestor folders → request → explicit run override. Environment variables use a separate documented chain: app defaults → workspace base → selected environment → folder/request variables → iteration dataset → run-local extracted values. Unresolved variables fail validation rather than silently becoming empty strings. Cycles and excessive expansion fail with helpful field paths.

Provide an **Effective request** inspector showing values, their sources, the final destination, modified headers, auth identity label, proxy and certificate selections, and omitted secrets. Never mutate the saved request during a run. A run uses a frozen environment snapshot, except explicitly defined iteration-local extraction and token refresh.

Settings include redirects, retries, protocol forcing/fallback, DNS overrides, IPv4/IPv6 preference, HTTP/SOCKS proxy support where implemented, `NO_PROXY` semantics, system/custom roots, certificate mapping, separate timeout classes, body/header limits, decompression, cookie persistence, keepalive, connection limits, lint policy, inferred headers, history retention, redaction, lock behavior, and update preferences. Unsupported combinations fail before traffic.

## 6. Request construction, lint, and verification

Bodies: none, raw text, JSON, XML, form URL-encoded, multipart with files, binary file/bytes, GraphQL query/variables, SOAP envelopes, and protocol-specific message editors. Support repeated headers and parameters where legal, enabled/disabled entries, clear override semantics, and previews of transmitted encoding. HTTP/2 pseudoheaders belong to protocol handling, not arbitrary user-supplied ordinary headers.

Live JSON/XML syntax lint must be debounced and bounded, with line/column messages. Disable XML external entities, remote DTD/schema fetching, and unbounded expansion. Schema validation is optional and distinct from syntax validity. Invalid bodies remain intentionally sendable under an explicit “send anyway” policy because the product is a testing client; invalid framing that the transport cannot safely represent must be rejected honestly.

Content-type inference is configurable globally and per request. Never overwrite an explicit header silently. Show the proposed inferred type and why; compute multipart boundaries correctly; preserve encoding; support SOAP 1.1/1.2 distinctions. Complete interpolation, transformations, inference, and serialization **before** body-dependent HMAC/DPoP/SOAP signing. Do not format, normalize, or compress already-signed bytes unexpectedly.

Add no-code assertions for status, allowed status set, headers/trailers, JSONPath, XPath, JSON Schema, body content, latency, gRPC terminal status, stream message count, and diagnostic category. An assertion failure is separate from transport and application failures. Support response extraction into iteration-local variables for chained requests. Start with declarative templates and functions: UUID, timestamp, counter, bounded random selection, seeded generated values, and CSV/JSON rows.

Optional scripts must run in a resource-limited sandbox with no OS, filesystem, subprocess, or arbitrary networking access by default. Imported scripts are disabled until trusted. Do not promise complete Postman JavaScript compatibility; import supported constructs and report everything else.

## 7. Protocol capability matrix

Separate **interactive execution**, **collection automation**, **load generation**, and **diagnostic detail** for each protocol. Support is not a single boolean.

| Protocol/use case | Required behavior | Important boundary |
|---|---|---|
| HTTP/1.1 and HTTPS | Methods, headers, bodies, cookies, redirects, streaming, TLS/mTLS | Preserve incomplete-message and connection-stage evidence |
| HTTP/2 / h2c | ALPN or explicit cleartext mode, headers/trailers, stream cancellation | Connection events and per-stream events are different |
| HTTP/3 | Explicit/automatic policy, QUIC diagnostics, negotiation/fallback reporting | Forced H3 must not secretly send H2; UDP failure is not necessarily server failure |
| WebSocket WS/WSS | Messages text/binary, ping/pong, subprotocols, close codes, session export | Normal closure is not a network error |
| WebSocket over H2/H3 | Extended CONNECT profiles matching Ferrum support | Separate tested feature gate from H1 Upgrade |
| gRPC / gRPC TLS | Proto files/descriptors, optional reflection, unary/client/server/bidi streams | Decode terminal trailers; HTTP 200 is not RPC success |
| SSE | Stream events, timestamps, reconnect controls, event IDs | Explicit cancellation/idle policy rather than infinite body buffering |
| TCP / TLS | Text/hex/binary, framing presets, half-close, idle deadlines, mTLS | Arbitrary bytes are not automatically a known application protocol |
| UDP / DTLS | Destination and payload, response window, datagram boundaries, session settings | Silence proves only “no response observed”; not successful delivery or definite outage |
| SOAP / GraphQL | Structured HTTP workflows and application-level faults/errors | Not separate wire transports; parse errors even on HTTP 200 |
| TLS passthrough/mesh destination | Correct client TLS to the reachable endpoint, optional approved identity | Cannot inspect an opaque middlebox’s internal cause without explicit telemetry |

HTTP1/2 load is required in core beta. For full v1, provide sensible per-protocol load actions for H3, unary gRPC, WS messages/sessions, TCP framed exchanges, and UDP/DTLS datagrams, with protocol-specific denominators and completion semantics. Long-lived stream load needs explicit session/message metrics; it is not ordinary request-per-second. Unsupported combinations must be disabled and documented, not emulated without notice. Mesh provisioning, PROXY-protocol tooling, Unix sockets, and specialized application codecs can follow as separately scoped enhancements.

## 8. Auth and TLS

### 8.1 Keep three identities separate

1. The user unlocking Anvil.
2. The client identity Anvil presents to a gateway or ordinary destination.
3. The gateway’s identity when it connects to its backend.

Changing identity 2 does not fix a certificate or secret misconfigured for identity 3. The UI and every diagnostic must preserve that distinction.

### 8.2 Required auth profiles

Ferrum’s inspected feature documentation names the following auth families [G3]. Verify the precise input format, canonicalization, and supported algorithms against the selected source/release before implementation.

| Family | Anvil implementation | Verification focus |
|---|---|---|
| None / inherited | Explicitly clear or inherit auth | No leftover header/cookie/client identity |
| API key | Configurable header/query location; secret reference | Exact key name, duplicates, precedence, query redaction |
| Basic | Standard credential generation | Encoding and safe redirect handling |
| Bearer | Existing token, secret variable, generated token profile | Token never sent to a different origin by redirect |
| JWT HS256 | Claims editor, expiry/not-before/issuer/audience, user-supplied signing secret | Ferrum consumer claim and admin claim differences; decoding is not verification |
| JWKS JWT | Obtain trusted issuer token; inspect/optionally verify with approved keys | `kid`, issuer, audience, algorithms, time bounds, unknown rotation |
| OAuth2 | Auth code + PKCE, client credentials where appropriate, refresh and optional supported device flow | State, redirect binding, external browser, secret handling, refresh races |
| OIDC relying-party session | Explicit browser/session workflow supported by gateway integration or user-authorized cookie input | Do not assume system-browser cookies automatically appear in Anvil |
| mTLS | Target-specific client cert/key and trust profile | Correct connection leg, certificate selection, expiry, chain and key match |
| HMAC | Exact `ferrum-hmac-v2` signer, final-byte digest, fresh nonce per attempt | Method/authority/raw path/query/namespace/Date/digest/canonicalization; replay tests |
| DPoP / certificate-bound tokens | Per-request proof generation and correct token binding | New proof per send/retry, URI/method/token hash, key identity and nonce handling |
| LDAP-backed auth | Generate the HTTP-facing credential presentation accepted by the gateway plugin | Invalid credentials versus unreachable directory; not an LDAP admin tool |
| SOAP WS-Security | UsernameToken text/digest, freshness/nonces; audited X.509 XML signature support; user-provided trusted SAML assertions | Namespace/canonicalization, signed references, replay, UTF encodings, certificate trust |
| Combined auth / ACL | Multiple explicit profiles and group/scope hints | Match gateway’s multi-auth semantics; no accidental identity override |

Ferrum’s admin API validates JWTs but does not mint them [G4]. Anvil must not invent a gateway token endpoint. Signing a test JWT requires a user-authorized secret/key; production issuer tokens come from that issuer. SAML support does not mean Anvil fabricates valid identity-provider assertions.

For HMAC, the current v2 profile uses exactly one supported digest field, binds a fresh nonce and final authority/path/body data, and is single-use. Never cache a signed request and replay its nonce during a load test. Legacy v1 needs an explicit unsafe-compatibility choice and must stay disabled by default. DPoP proofs similarly need fresh replay identifiers and correct request binding [G3].

Use audited libraries for cryptography and XML signatures, with independent golden interoperability vectors and negative tests. Do not implement cryptographic primitives, certificate validation, XML canonicalization, or OAuth protocol rules from scratch.

### 8.3 TLS settings and safe defaults

Provide system trust, private CA bundles, PEM cert/key, encrypted keys, and PKCS#12 import where supported. Show certificate subject/issuer/SAN, validity, fingerprints, key-match status, and relevant usage errors without exposing the key. Bind client certificates to explicit host/port/protocol profiles; warn about broad wildcards.

**TLS disabled** means the user chose a plaintext protocol such as HTTP. **Certificate verification disabled** means encryption remains but peer authentication is bypassed. Separate these controls. Verification is enabled by default. Bypass is a request/target-scoped diagnostic option with a persistent warning, not the first recommended remediation or an automatically imported active setting. Never install test roots into the user’s global OS store silently.

SNI, HTTP Host/authority, network destination IP, and certificate hostname verification are related but distinct. An advanced editor may expose them with an effective-destination preview. Test all combinations with redirects, proxies, TLS session reuse, and auth signing.

## 9. Smart diagnostics: the primary product subsystem

### 9.1 Outcome model

Do not collapse everything into an HTTP status. Record:

```text
ExecutionOutcome
  transport: completed | failed | canceled | incomplete | unknown
  application: success | failure | not_evaluated
  assertions: pass | fail | not_run
  warnings: [degraded_routing, insecure_tls, partial_visibility, ...]
  protocol_status: HTTP / gRPC / WebSocket / other typed result
  findings: [DiagnosticFinding]
```

A finding contains `code`, short title, plain-language explanation, evidence references, scope/connection leg, confidence, possible alternatives, safe remediation, owner role, and “what would confirm this.” Confidence is `confirmed`, `likely`, `unknown`, or `conflicting_evidence`; use qualitative terms, not invented probability percentages.

Source scope includes local validation/client, configured forward proxy, client-to-peer transport, gateway admission/configuration, gateway-to-upstream transport, upstream application, response delivery, and unknown. Confidence belongs to each claim: “TLS handshake did not complete” can be confirmed while “the gateway requires a client certificate” is only likely.

### 9.2 Evidence engine

Normalize typed events, certificate validation results, HTTP headers and trailers, gRPC statuses/details, WS close information, complete/partial body status, current Ferrum markers, approved diagnostic envelopes, and optional correlated operator evidence. Preserve evidence provenance and timestamps. Treat body text as untrusted data, never instructions.

Rules are deterministic, offline, versioned, schema-validated, and testable. Each rule declares required/contradictory evidence, supported gateway contract versions, predicates, priority, grouping, explanation template, remediation, and fixture IDs. The classification engine must be separate from UI wording. Optional future LLM text assistance may summarize redacted evidence only with consent; it cannot upgrade confidence or invent facts and is not required for the product.

Prefer native measured phase evidence and authenticated, version-compatible gateway fields. Body-pattern heuristics and generic status meanings are weak evidence. Handle repeated/conflicting headers, case insensitivity, stripping proxies, future tokens, forged marker headers, and mixed-version gateways. A `Server` string or arbitrary `X-Gateway-Error` from an unknown endpoint does not authenticate Ferrum. Allow an explicitly trusted Ferrum destination profile; show “Ferrum-like header observed” when identity remains unverified.

Do not equate the gateway’s conservative `request_reached_wire` retry predicate with proof that the application processed or did not process a whole request. Retain per-attempt `dispatch_state` as `not_dispatched`, `sent`, `may_have_been_sent`, or `unknown`, and separately summarize all attempts. Default automatic retries off. Never automatically retry a possibly processed non-idempotent operation merely because the UI calls it a connection problem.

### 9.3 Source-driven coverage inventory

Create `catalog/ferrum/<compatibility-id>/outcomes.json` from an explicit audit of:

- Public header constants and writers; protocol-specific headers/trailers/body errors.
- `ErrorClass::ALL`, native setup-error kinds, stream disconnect causes/directions.
- Gateway rejection phases and terminal admission fences.
- All enabled built-in plugin rejection/result paths, including auth, WAF, rate/size limits, validators, transformation, caching/fallback, AI/LLM policies, and custom-plugin generic behavior.
- Frontend protocol parser/listener errors that happen before request context exists.
- Connection and body completion paths after headers were committed.

For each entry record source path/line or symbol and SHA, condition, protocol, observed signal, whether public/authenticated/local-only evidence is available, minimum truthful diagnosis, remediation, and positive/negative fixture IDs. Generated inventory plus manual reconciliation is appropriate; a grep count alone is not proof of completeness. New unmapped variants/rejection phases must fail the contract-drift gate. Unknown third-party custom plugin outcomes require a generic explanation or an explicit signed/schema-validated local rule extension, never invented exact coverage.

### 9.4 Gateway enhancement needed for precise attribution

Keep all seven existing tokens unchanged. Add an **optional, versioned diagnostic contract** for distinctions existing responses do not expose. The fields and endpoints below are proposals, not existing Ferrum APIs.

Proposed `DiagnosticEnvelopeV1`:

```json
{
  "schema_version": 1,
  "request_id": "opaque-gateway-generated-id",
  "outcome_origin": "gateway",
  "code": "upstream.tls.handshake_failed",
  "phase": "upstream_tls",
  "dispatch_state": "not_dispatched",
  "attempt_index": 0,
  "attempt_count": 1,
  "http_response_origin": "gateway",
  "upstream_http_status": null,
  "rejection_phase": null,
  "plugin_family": null,
  "evidence_level": "typed_phase",
  "retry_policy_hint": "manual_review",
  "details_available": true
}
```

Enums are illustrative proposal values. Bind them to actual typed construction sites and test them; do not derive `phase=upstream_tls` from a coarse token or error-string substring. Use narrow reason/subreason codes for trust failures, handshake timeout, upload timeout, header wait, body idle timeout, auth expiry/scope, policy categories, and other genuinely observed distinctions. Unknown stays unknown. Do not fill null fields with guesses.

Delivery design:

1. Small, gateway-authored safe metadata on HTTP responses or appropriate gRPC metadata/trailers, only where protocol state permits. Proposed names might use `X-Ferrum-Diagnostic-*`; document final choices in a versioned specification.
2. Optional authenticated, read-only detail lookup for operators, e.g. a proposed diagnostic resource scoped to a gateway/namespace/request. Use a dedicated least-privilege credential and explicit integration profile; do not distribute broad administrator JWTs to every caller.
3. Optional local import of redacted transaction logs or a support bundle for offline enrichment. Exact correlation requires a real matching identifier or reliable connection context; timestamp coincidence alone is not confirmation.

Metadata is produced from gateway-owned terminal outcomes after transformations, not supplied by the backend. Strip or ignore spoofed incoming/upstream copies of reserved diagnostic fields; preserve multi-hop provenance only through an explicit trusted chain. Version compatibility and authenticated TLS to the trusted gateway are minimum provenance requirements. Signed detail is an optional extra when metadata crosses untrusted intermediaries, with an independently trusted verification key.

Disclosure modes should be off/coarse/authenticated-detail. No raw backend private addresses, credentials, matched WAF payloads/rules, sensitive claims, secrets, or internal exception strings in ordinary public responses. Limit retention, entry size, rate, lookup scope and TTL; protect against enumeration and cross-tenant access. Never make a secret request ID an authorization mechanism by itself. A bounded opt-in diagnostic ring or existing observability sink is preferable to an unbounded new transaction database.

Pre-HTTP TLS rejection, opaque L4 traffic, and some parser failures cannot receive a retrofit HTTP header. The desktop uses its local transport evidence; privileged operator-side evidence is optional. Post-header streaming failures require terminal trailers when legal, transport completion evidence, and/or operator logs. Do not change already-sent status codes or corrupt successful protocol streams to force diagnostics into them.

### 9.5 Example customer explanations

**Existing header only:** “Ferrum Edge reports that it could not prepare a connection to the destination. This header combines DNS, TCP, TLS, connection-pool, and related setup failures. Check the configured backend host and port, gateway DNS/network access, and backend TLS settings. The response does not identify which setup step failed.”

**Trusted typed upstream TLS evidence:** “The secure connection from Ferrum Edge to the destination failed during the TLS handshake. Your connection to Ferrum Edge completed. The gateway operator should check the destination certificate chain/name and the gateway’s upstream client certificate when mTLS is required.”

**Client certificate rejected during setup:** “The peer rejected this TLS setup. The observed alert is consistent with a client-certificate problem. Check the certificate selected for this host, its private key, validity, and trusted issuer. No HTTP response was received.” Upgrade the specific cause to confirmed only when the evidence supports it.

**403 without provenance:** “The service refused this request. This response alone does not distinguish gateway authorization, a WAF/policy block, or application authorization. Check the response details, credential scope, and a correlated gateway diagnostic.”

**200 with truncated body:** “Response headers arrived, but the response body did not finish. Do not treat this as a successful complete response or automatically replay a non-idempotent request.”

Every explanation offers an evidence drawer, a copyable redacted support bundle, suggested owner (caller/gateway operator/API owner), and reversible high-level checks. Never make “disable TLS verification,” “disable the WAF,” or “increase every timeout” the default fix.

## 10. Timing, sizes, and request accounting

Capture monotonic timestamps for queueing, DNS, TCP connection, TLS handshake, request upload, first response headers/first body byte, body transfer, completion, and cancellation where the adapter actually observes them. Record redirects and retries as separate attempts and connections. For QUIC, identify the actual setup phases the implementation can measure rather than inventing a TCP phase.

Report connection reuse/resumption, negotiated protocol, remote address where permitted, certificate summary, upload/download bytes, and the accounting scope. Reused connection DNS/TLS is **not applicable/reused**, not a fresh zero-millisecond handshake. Concurrent stages may overlap; do not force every chart to sum phase measurements as though all activity is sequential. Distinguish first response headers from first data byte, and gateway-reported time from desktop-observed time.

TTFB is not pure backend computation. Upstream TLS, gateway processing, queuing, retries, and backend time cannot be independently measured by the desktop without gateway evidence. Unknown measurements must be blank/labeled unavailable, not fabricated from subtraction.

Sizes must distinguish request/response body bytes, decoded/decompressed bytes, logical header/trailer sizes, and actual wire bytes where measured. HTTP/2 HPACK, HTTP/3 QPACK, TLS encryption, framing, and multiplexed connections make per-request physical bytes different from logical header length. Mark estimated logical serialization sizes as estimates. Never call character count “network bytes.” Account for UTF encodings, binary content, compressed responses and incomplete streams. Enforce decompression and display-size limits independently.

A session inspector should make it easy to answer: Which connection? Which attempt? Which cert? Which protocol? Did headers arrive? Was the body complete? What was retried? Which measurement is unavailable?

## 11. OpenAPI, WSDL, and migration imports

Accept OpenAPI JSON/YAML from files, clipboard, and explicitly fetched URLs. Request-generation coverage must include Swagger 2.0 and OpenAPI 3.0, 3.1, and 3.2 through staged importer milestones; the 3.2 specification exists and must not silently be treated as 3.1 [E8]. Feature detection, dialect handling and explicit unsupported-construct warnings matter more than a version-string checkbox.

Import wizard: choose workspace/folder, server/environment, operation grouping (tags or paths), auth placeholders, inclusion of optional fields, blank versus example/sample payloads, overwrite/reimport policy, and attachment locations. Resolve server variables and operation overrides, proper path/query serialization and encoding, parameter styles, request content types, multipart bodies, and security alternatives/conjunctions.

Sample precedence: explicit selected example → compatible default/enum → schema-based seeded generator. Validate generated examples against the selected dialect; show unresolved/unsupported constraints. Honor required fields, read-only/write-only context, nullable types, lengths/ranges, composition and bounded references. Recursive and contradictory schemas must produce a useful warning, not infinite generation or a claim that arbitrary placeholder data is valid. Blank mode produces editable requests and placeholders without invented real credentials.

Maintain the imported source and source hash. Link requests by operation ID where stable, otherwise method/path plus source identity. Reimport must show a diff and preserve user edits unless approved; deleted spec operations do not silently delete customer work. Never send an imported request automatically.

External `$ref`, WSDL/XSD imports, local file references, and remote examples require explicit trust policy. Bound depth, count, size, time and redirects; block cross-origin credential forwarding and unauthorized file reads. Do not let an imported public spec cause automatic internal-network scans or cloud metadata requests. User-requested ordinary private API calls remain allowed; background import resolution is a different trust boundary.

Core migration adapters: cURL, Postman collection/environment formats, Insomnia documented collection/environment formats, and HAR with explicit credential/body redaction. Import supported objects, retain the original artifact, and report unsupported scripts/auth/plugins rather than dropping them silently. WSDL import should create SOAP operation requests and configurable blank/sample envelopes; XSD validation and advanced security use the same safe XML policy.

## 12. Portable workspaces and whole-app backup

Propose `.anvil-workspace`, `.anvil-backup`, and `.anvil-run` bundles with published schemas. A versioned archive contains a manifest, object graph, content-addressed attachments, optional datasets/specs, optional run reports, and checksums. An encrypted bundle wraps authenticated payloads using reviewed crypto libraries; document KDF/version parameters and distinguish corruption detection from provenance authentication.

```text
manifest.json
workspace/objects.json
settings/portable.json
specs/...
attachments/<content-hash>
datasets/...
runs/...                       optional
secrets/portable-vault.enc      optional, never plaintext by default
checksums.json
```

Workspace export includes folder order, requests, environments, non-secret auth configuration, TLS profile metadata, assertions, scenarios, and selected fixtures. Whole-app export includes **all portable application settings and saved workspaces**, with explicit toggles for history, response bodies, run reports, and secret material. Device-specific OS keychain handles, installed provider sessions, local master keys, machine paths, and executable locations are not transferable credentials; report them and request safe rebinding.

Offer: **Share safely** (secrets excluded with placeholders), **Encrypted transfer** (explicitly selected secrets/private certs re-encrypted for the recipient), and **Full personal backup** (portable state plus explicitly selected encrypted sensitive data). Export previews list included/excluded data. Scan query strings, headers, cookies, bodies, response data, logs, test datasets, JWT helpers, and private keys, not just variables named password. Redaction is best effort for arbitrary content; give the user a preview and secure-transfer option rather than promising an omniscient detector.

Import is a dry-run preview with merge/replace/duplicate choices, ID conflict mapping, schema migration and validation, missing-file/secret prompts, then an atomic transaction. Take a restore checkpoint before replacement. Test duplicate import idempotency, cross-OS paths, Unicode, older schema versions, future schema refusal/read-only preview, corruption, interruption, and disk-full recovery. Reject archive traversal, symlinks, absolute-path writes, decompression bombs, dangerous auto-run content, and settings that silently weaken TLS or execute external code.

A full backup must be restorable on a clean installation without the original machine’s keychain. Encryption therefore needs an explicit user-controlled export passphrase or other documented portable recipient key, not an opaque copy of OS-bound ciphertext.

## 13. No-login, lock, and social-login modes

### Local/no-account mode

All ordinary functionality works offline without a Ferrum account. Keep data local. Use OS protection and encrypted secret storage where available; be explicit that an already-unlocked OS session is not equivalent to a separately locked vault. When a Linux secret service is unavailable, provide a local passphrase vault rather than silently storing plaintext.

### Local protected mode

Let the user create a local profile name and unlock passphrase. Encrypt the full sensitive workspace/history/attachment data, not merely the token variables; URLs and bodies often contain sensitive information. Include database journals/WAL, temporary files, search indexes, cached previews, attachments, backups and crash diagnostics in the plaintext-leak audit. Use a random data-encryption key, wrapped by a reviewed passphrase-derived key and optionally an OS user-presence-gated mechanism. A local username is a profile selector, not an independent OS security boundary.

Lock on configured inactivity, OS lock/suspend, or explicit action. The backend must deny privileged IPC while locked, stop or explicitly hand off active runs according to a visible policy, redact UI state, clear clipboard when feasible, and release unwrapped keys and sensitive buffers to the practical extent the runtime permits. A hidden webview overlay without backend locking is not acceptable. Do not claim protection against malware controlling the already-unlocked process.

Recovery must be explicit: recovery key or portable encrypted backup. Password reset alone cannot decrypt a vault whose only key was lost. Restoring a different user’s backup must not overwrite the recipient’s login/session identity.

### Social/provider-protected mode

Provide Google, GitHub, and Facebook through provider-specific supported native flows or a minimal identity broker that normalizes them. Do not assume every provider is an interchangeable OIDC issuer or supports the same public-client flow. Store provider client secrets only in an appropriate backend, never in the shipped desktop bundle. Actual registered application IDs, redirect URIs, callback validation and provider approval are production prerequisites, not placeholders that count as complete.

Use external-system-browser authorization and PKCE where supported, with state/nonce/issuer/audience/callback checks, following native-app OAuth guidance [E7]. App login is separate from target API OAuth tokens and workspaces. Provider identity by itself is **not an encryption key**. Use a separate local vault key and intentional unlock/recovery policy; do not derive encryption from an email or provider subject.

For normal offline-first use, recommend provider identity binding plus local passphrase or OS-user-presence vault unlock. An optional online-only lock policy may require fresh provider authentication, but must explain its availability dependency and separately authorized recovery path. Neither mode implies cloud workspace synchronization. A minimal account broker, when used, should receive identity/session information only, not customer API bodies or private keys. Mock providers support CI; real-provider acceptance tests with test accounts are still required before claiming production provider support.

## 14. Load testing and saved analysis

### 14.1 Native engine first

Run the same prepared request, auth generation, TLS policy, protocol adapter, and outcome classifier from a separate native worker. This avoids “manual Send succeeds, load sends different bytes” defects. Keep Rust async concurrency bounded. Precompile templates and assertions, but generate fresh nonces/proofs and time-bound signatures for every actual send. Pool/cert/isolation rules remain identical.

Support fixed virtual users (closed workload), target arrival rate (open workload), ramp stages, step tests, spike tests, soak duration, iteration count, pacing/think time, weighted scenarios, CSV/JSON datasets, sequential request chains, response extraction, fresh/persistent connection modes, custom headers, auth refresh, timeouts, and abort rules. Show destination, planned rate/concurrency/duration, and an ownership/authorization reminder before an explicit start. Never auto-start traffic from imported plans.

Open workloads must distinguish scheduled arrivals from actual starts, track scheduling delay and dropped iterations, and never build an unbounded queue. Closed workloads are allowed but labeled: slowing responses reduce offered rate. Use mergeable latency histograms; retain queue-inclusive measurements where appropriate and report censored timeouts explicitly. Do not hide overload with averages or call a corrected synthetic histogram the same as observed request latency.

### 14.2 Metrics and reporting

Persist run ID, immutable plan/revision, random seed, dataset hash, engine/build version, protocol/TLS profile, environment summary, warmup inclusion, timestamps and phase settings. Store scheduled/started/completed/canceled/dropped counts, throughput/achieved rate, in-flight requests, network failures, protocol/application failures, assertion failures, response status distributions, byte rates, p50/p90/p95/p99, min/max/mean, histogram counts, and phase durations where measured. Keep success and failure latency distributions distinguishable.

For gRPC/WS/TCP/UDP, define denominators and completion separately: RPCs, messages, sessions, framed exchanges, sent/received datagrams. UDP packets sent are not acknowledgments. A graceful WS close is not a failed HTTP request. Never average worker percentile values; merge compatible histograms before computing percentiles.

Collect load-generator CPU, memory, descriptor/socket use, scheduling lag and configured caps. Warn when the generator cannot sustain the target. Distinguish generator saturation, gateway signals and backend symptoms. A gateway and runner on the same laptop contend for resources; this lab establishes correctness, not headline production throughput. Set benchmark baselines on dedicated documented hardware after measurement, not by inventing RPS targets.

Progress events must be throttled and bounded. Store bounded representative failure samples per category; do not retain every response body at high load. Stream raw optional samples to bounded files. Cancellation and app exit must terminate worker traffic safely and finalize a partial report. Persist after worker crash or disk-full failure as far as possible, explicitly labeled incomplete.

Export JSON, CSV data generated by the product, standalone HTML summaries, and native run bundles. Reports require no network to view, contain no executable injected response content, and default to redacted data. Compare runs only when their engine, workload, warmup and measurement semantics are compatible; display important differences.

### 14.3 Optional Apache JMeter adapter

Only add after native functionality works. Pin the verified distribution, checksum/signature, notices, runtime requirements and supported samplers. Translate a declared supported subset to a JMX plan and run non-GUI. Keep secrets out of argv/process-visible logs; use restricted temporary files or IPC with cleanup. Validate TLS/hostname/mTLS behavior against the same fixtures; block any unsupported strict-validation request. Record adapter version and warn that engine metrics cannot automatically be compared as identical. Arbitrary imported JMX/plugin execution is outside the safe default trust model.

## 15. Local integration and failure laboratory

### 15.1 Topology and profiles

```text
Anvil desktop / Anvil CLI
       |
  optional client-leg fault fixture
       |
Ferrum Edge frontend: HTTP(S), H2, H3, WS, gRPC, TCP/TLS, UDP/DTLS
       |
  controlled upstream DNS / upstream-leg fault fixtures
       |
Deterministic backend services and application responses

Optional profiles: CP + DP; OAuth/JWKS/introspection; LDAP; OPA; Redis replay;
SOAP signed fixtures; mesh/HBONE trust-policy cases; operator diagnostic reader.
```

Use Docker Compose for portable gateway/backends where feasible and native fixture helpers where needed. Linux-only packet shaping requires an explicitly privileged optional profile; it must not become an undocumented Windows/macOS requirement. A small controllable TCP/protocol fixture can cover resets, delayed handshakes/headers/chunks and truncated bodies cross-platform. Prefer independently controlled DNS and response timing over unreliable public internet endpoints.

Pin gateway source SHA and selected release digest separately. Include all enabled feature flags. Bind exposed test ports to loopback, generate ephemeral fixture certificates/keys, avoid real provider credentials, and put strict resource/time limits around tests. Never trust the fixture CA globally. Both direct-backend and through-gateway requests are required to separate client defects from integration defects.

Every fixture has an explicit readiness check and ground-truth event log. Record whether the gateway/backend saw a connection, request headers, application bytes, and the selected fault. Compare ground truth with what Anvil was actually allowed to observe. **Do not feed private ground truth to the diagnostic engine and then call the result a public-header success.** Enhanced-diagnostics tests use only the authorized contract being tested.

### 15.2 Scenario acceptance contract

The companion `FERRUM_ANVIL_FAILURE_MATRIX.json` is a seed catalog, not executed tests. Each scenario must be implemented with a fixture and expanded into actual test records containing:

```text
scenario ID; category; required protocol/features; gateway SHA/image;
setup; fault injection; expected fixture ground truth;
public evidence; optional authenticated evidence; expected finding(s);
maximum defensible confidence; alternatives/unknowns; forbidden claims;
remediation category; recovery step; redaction assertions;
UI/CLI assertion; platform matrix; result/artifact paths.
```

For every injected fault, run a positive recovery request after removing it. For every strong diagnosis, run a deceptively similar case that must **not** receive that diagnosis. Different root causes sharing identical observable signals must receive appropriately indistinguishable cautious explanations. Native browser UI tests, CLI tests, source unit tests, and end-to-end desktop tests are separate evidence types.

### 15.3 Required scenario families

| Family | Cases to verify | Critical assertion |
|---|---|---|
| Local validation/client | Invalid URL, missing variable/file, proxy configuration, cancellation, local limits | Do not blame a gateway that was never called |
| Frontend network | DNS failures, connect refused/timeout, TLS trust/name/expiry, missing/wrong mTLS, protocol mismatch | Correct client-to-peer leg; no invented HTTP headers |
| Upstream network | Gateway DNS/connect/TLS failures, mTLS, write/header/body idle timeout, reset/truncation/pool/ports | Existing coarse marker versus optional precise evidence |
| Gateway admission | Circuit breaker, overload/drain, adaptive concurrency, stale DP config, no route/method, size limits | Gateway-owned policy, correct owner, no automatic bypass |
| Authentication | Every supported auth family, expiry/scope/signature/replay/provider failure, mixed auth | Differentiate credential rejection from identity-provider availability only with evidence |
| WAF/policy | WAF positive block, ACL/OPA/IP/geo, validator rejection, backend 403 lookalikes | Status alone never proves WAF |
| Responses/streams | Application 4xx/5xx, HTTP200 failure bodies, gRPC trailers, WS closes, partial data | Completion and application status are independent |
| Protocols | H1/H2/H3, h2c, WS bootstrap variants, gRPC stream modes, TCP/TLS, UDP/DTLS | Advertised capability exercised, not inferred from a dependency |
| Metadata trust | Forged/missing/duplicated/conflicting/future headers, namespace access, post-transform restoration | No false confirmed origin or secret disclosure |
| Data/security | Export/import round trip, encrypted restore, malicious archives/XML/HTML, vault lock, redirects | No secrets or privileged execution across trust boundaries |
| Load | Arrival scheduling, generator saturation, percentile correctness, auth refresh, cancellation, report replay | Complete accounting and equivalent request semantics |
| Release/website | Native installer launch, update signature, offline start, real asset links, navigation | Product exists and works before website claims availability |

### 15.4 Gateway source coverage and extension cases

Exercise all 19 canonical classes and all seven public tokens through the relevant live paths when deterministic construction is practical. Scarce-resource classes such as port exhaustion may require a bounded test-specific admission/fault hook rather than stressing the host OS. Test hooks must be compile-time/lab-only and absent from release binaries; label hook-based tests separately from naturally produced live failures. Real mTLS/network/timeout cases must not be replaced wholesale with injected enums.

Expand coverage to the full source inventory, including plugin-specific AI/LLM budget/content/tool-governance outcomes, quota/cache/fallback semantics, custom-plugin generic rejections, transformation failures and contract validation. Where a provider is external, use a protocol-faithful controlled mock and state that it verifies adapter behavior, not the live provider’s availability. Every supported plugin outcome needs at least a truthful generic result even when public reason detail is intentionally withheld.

CP/DP tests must genuinely create a stale configuration fence rather than merely returning a fake `config_stale` header. Likewise, circuit-breaker, rate-limit, concurrency, HMAC replay, and WAF tests should drive the real configured gateway behavior. Backend 403/5xx control cases must prove Anvil does not attribute the same response to the gateway without evidence.

## 16. Automated verification and CI

**Unit/contract tests:** variable precedence, request serialization, encoding, redaction, import graph validation, schema migration, deterministic diagnostics, evidence contradictions, auth vectors, deadline state machines, histogram math, and worker accounting. Property/fuzz tests cover malformed headers, JSON/YAML/XML, archives, protocol messages, oversized metadata, recursive refs, and unknown diagnostic values. Require no panic/crash from bounded untrusted inputs.

**Integration tests:** real protocol peers with the shared Rust engine; gateway headers/log/diagnostic consistency; optional operator authorization; byte-exact HMAC/DPoP/SOAP interop; original and new gateway profiles; direct versus proxied paths; all user modes; exported workspace restoration on a clean profile.

**Native desktop E2E:** use WebdriverIO’s Tauri embedded-driver approach on Windows, macOS and Linux after a feasibility spike. Current Tauri documentation describes this cross-platform option; direct `tauri-driver` alone is Windows/Linux [E9]. Test-only WebDriver/IPC mocking plugins must be excluded from production packages, with a release check proving no driver port/backend access remains. At least one happy path and each critical error family must traverse the actual native engine without network-command mocks. Run installer/user-presence/dialog/update smoke tests on the packaged app too; instrumented E2E builds alone are not packaging evidence.

**UI/component tests:** editor, folder tree, accessibility, lint rendering, evidence drawer, confidence wording, settings scope, charts, export preview, lock states and empty/error states. Playwright/browser-mode tests are useful for the renderer but are not proof the native network/TLS path works.

**Security/release checks:** lockfiles, vulnerability and license audit, SBOM, secret scan, updater integrity, origin-bound credentials, permissions, signing/notarization, least-privilege diagnostic API, and no release test hooks. Run Rust formatting/lint/tests and frontend typecheck/lint/test; use actual repo commands and keep external dependency versions pinned.

Suggested CI lanes: fast PR units/contracts; targeted live failure groups on PR; broader protocol/auth matrix on merge/nightly; full platform installers/security/regression before a tag. Every public feature must link to a passing native or appropriate integration test and a release artifact. Do not make nightly success a substitute for required PR checks after a relevant change.

### Release gates

- No known critical/high-severity security, data-loss, secret-leak, or false-confirmed-attribution defects.
- Every advertised auth/protocol capability has positive, negative, and recovery coverage on its supported platform matrix.
- All inventoried diagnostic outcomes map to a rule, truthful unknown fallback, or explicit documented visibility limitation; new catalog drift fails CI.
- Zero false **confirmed** diagnoses in the adversarial fixture set. Unknown answers are scored against expected uncertainty, not penalized for honesty.
- All current seven tokens and 19 source classes are accounted for; no inference that source unit coverage equals live coverage.
- Whole-app and workspace round trips succeed across supported OSes; locked and encrypted export modes pass restore and corruption tests.
- Native worker cancellation, memory/event bounds, load accounting, and report reproduction pass measured budgets documented in CI. Establish numeric budgets from the reference hardware; do not invent production throughput promises.
- Signed/notarized installers where applicable, release checksums/signatures, clean-install smoke tests, and compatible signed update tests exist for every displayed download.
- Website claims, screenshots, platform matrix, versions and downloads match the actual validated release.

## 17. Agent work breakdown and dependency order

| ID | Work package | Depends on | Required deliverables / exit proof |
|---|---|---|---|
| A00 | Repository/source audit and product decisions | None | Exact SHAs/releases, license decision log, capability inventory, threat model, initial backlog |
| A01 | Native feasibility spikes | A00 | Real three-OS TLS/mTLS/trailers, H3/DTLS/auth/driver decisions, packaging proof |
| A02 | Domain contracts and repository scaffold | A00 | JSON schemas, generated bindings, core event API, CI, architecture decisions |
| A03 | Persistence, vault and portability | A02 | Durable data model, lock enforcement, workspace/full-backup round trips, migrations |
| A04 | HTTP-family execution and essential UI | A01,A02 | Actual send/cancel, headers/bodies/cookies, typed phases, cert/profile isolation |
| A05 | Baseline auth and request preparation | A03,A04 | API key/Basic/bearer/JWT/OAuth/mTLS, exact rendered-request preview, negative auth tests |
| A06 | Current-contract diagnostic engine | A00,A04 | Seven-token rules, local failures, confidence/evidence UI, ambiguity/lookalike tests |
| G01 | Versioned gateway detail contract | A00,A02 | Separate reviewed Edge PR, safe fields, authorization, source provenance, disclosure/performance tests |
| A07 | Specs/imports/assertions/collection runner | A03,A04,A05 | OAS staged dialects, WSDL/migration adapters, blank/sample modes, extraction/assertions |
| A08 | Native load engine and reports | A04,A05,A07 | Bounded worker, open/closed scheduling, accurate metrics, saved/offline reports |
| A09 | Expanded protocol adapters | A01,A04 | H3, grpc streams, extended WS, TCP/TLS/UDP/DTLS feature matrix and native tests |
| A10 | Advanced Ferrum auth and binding | A05,A07,A09 | HMAC v2, DPoP, OIDC session approach, LDAP presentation, SOAP signature/assertion profiles |
| A11 | Provider-protected app login | A03 | Native/broker flows, registered provider integration, local vault/recovery/offline policy |
| A12 | Enhanced diagnostics and full fault catalog | A06,G01,A09,A10 | Live lab, source-inventory mapping, operator detail, all appropriate fixture assertions |
| A13 | Release hardening and documentation | All required release capabilities | Platform installers, signatures/SBOM, release evidence manifest, reproducible demo workspaces |
| W01 | Website and suite links | A13 for publication | Website PR, real screenshots/assets, tested docs/navigation, release-accurate claims |

Parallelize only after stable interfaces are agreed. Persistence/portability, transport, diagnostics catalog, and UI can proceed in separate branches; auth canonicalization must share the same prepared-request contract with load. Assign one owner to cross-cutting transport/event types to avoid parallel incompatible rewrites. Use incremental PRs with actual tests, not a single giant generated code dump.

Recommended early sequence: A00/A01/A02 → minimal A03/A04/A06 → first real vertical slice → A05/A07/A08. Do not wait for social login or every exotic protocol before validating the core diagnostic value. Full v1 remains gated on its promised matrix rather than silently dropping the remaining user requirements.

## 18. Website rollout after verification

The actual website is static HTML/CSS/JS published from `main` by GitHub Pages, with no application build step [G5]. Shared navigation/footer is in `assets/js/components.js` [G7]. Preserve this architecture. Do not migrate the site to a new framework or deploy an unrelated login backend in the website repo.

### Concrete proposed changes

| Path/surface | Change |
|---|---|
| `anvil.html` | Product landing page using existing styles, exact product name/tagline, practical examples and limitations |
| `assets/js/components.js` | Add Anvil to Tools, mobile navigation, footer and active-navigation logic; preserve root/subdirectory resolution |
| `index.html` | Suite card/section explaining Anvil alongside Foundry/Nexus/GitForgeOps |
| `download.html` | Anvil downloads separated from gateway downloads, explicit OS/architecture/version/checksums |
| `releases.html` or existing release surface | Actual Anvil release notes and compatibility; inspect existing convention first |
| `guides/anvil-*.html` | Getting started, Ferrum diagnostics, auth/TLS, portable data, load tests and interpretation |
| `assets/` | Real screenshots from the release candidate, accessible alt text, optimized assets |
| Sitemap/search/social metadata | Add actual pages using repository conventions; SoftwareApplication metadata with accurate OS/version |
| Tests/link checker | Cover new navigation, extensionless links, anchors, release asset URLs and missing platform cases |

Suggested landing copy:

> **Ferrum Anvil**  
> **Put your APIs to the test.**  
> A desktop API client for Windows, macOS, and Linux. Build requests, run repeatable tests, inspect performance, and troubleshoot Ferrum Edge with explanations grounded in what actually happened.

Present three main workflows: **Build and send**, **Understand the failure**, **Test under load**. Explain “works with any API” and “enhanced diagnostics with supported Ferrum Edge versions” separately. Include the offline/no-account statement, local lock choices, supported auth/protocol matrix, data export/redaction behavior, license terms, minimum OS versions established by tests, and clear support documentation.

Use actual screenshots demonstrating a normal call, a backend setup failure with evidence, a frontend certificate issue, and a saved load report. Do not fabricate a polished screenshot with working-looking unsupported controls, benchmark throughput, testimonials, complete root-cause guarantees, or unavailable release downloads.

Treat release artifacts as the source of truth. A release evidence manifest should contain Anvil version, commit, signed asset name, OS/architecture, checksum, gateway compatibility IDs, passed test runs, known limitations, and screenshot source build. The website agent must validate URLs and hashes rather than guessing GitHub asset names from a version string.

The website’s existing documented checks are [G5]:

```bash
node --test "tests/**/*.test.js"
python3 scripts/check_links.py
python3 scripts/check_links.py --external all
```

Add desktop/mobile visual and keyboard checks, downloads on unsupported platforms, and actual signed-app launch validation. Stage the website PR before release if helpful, but do not merge/publish “available now” until required release assets and evidence are real. Public launch occurs only after product checks, platform availability, and truthful claims align.

## 19. Required completion artifacts

The implementing agent must finish with a runnable product and evidence, not just generated source:

- Anvil source, scoped gateway PRs where necessary, reviewed architecture/threat-model decisions, lockfiles and licensing/NOTICE/SBOM records.
- Versioned public data schemas, diagnostic catalog with source provenance, supported gateway/protocol/auth matrix, and update/migration policy.
- Local lab with one documented start/test/stop workflow, actual scenario implementations, raw machine-readable results, redacted failure evidence, and desktop screenshots tied to builds.
- CLI and desktop releases built from the same core, installation/update instructions, portable sample workspaces and saved sample run reports.
- Explicit report of commands executed, environments, passed/failed/skipped tests, integration uncertainties, known limitations and unimplemented features. Never mark a skip as a pass.
- Website PR and verification evidence linked to the exact release, merged/published only after the corresponding gate.

## 20. Sources and evidence provenance

These references distinguish existing inspected behavior from proposed Anvil requirements. Repository code may change; re-pin and reconcile during A00. The private website references below are canonical repository paths, not temporary access URLs.

**[G1] Ferrum typed classifications and constants:** `ferrum-edge/ferrum-edge`, `src/retry.rs`, source lines 1–270 at `8ef06f2cece2847b552b7858c73fa9a1a265442f`.  
`https://github.com/ferrum-edge/ferrum-edge/blob/8ef06f2cece2847b552b7858c73fa9a1a265442f/src/retry.rs`

**[G2] Ferrum classification, phase ambiguity, body failures, headers:** `docs/error_classification.md`, same SHA; inspected beginning and source lines 170–460.  
`https://github.com/ferrum-edge/ferrum-edge/blob/8ef06f2cece2847b552b7858c73fa9a1a265442f/docs/error_classification.md`

**[G3] Ferrum protocols/authentication:** `FEATURES.md`, same SHA, source lines 1–195.  
`https://github.com/ferrum-edge/ferrum-edge/blob/8ef06f2cece2847b552b7858c73fa9a1a265442f/FEATURES.md`

**[G4] Gateway development rules, admin JWT, licensing:** `CLAUDE.md`, same SHA.  
`https://github.com/ferrum-edge/ferrum-edge/blob/8ef06f2cece2847b552b7858c73fa9a1a265442f/CLAUDE.md`

**[G5] Website architecture and checks:** `ferrum-edge/ferrumedge`, `README.md`, read September 25, 2026; blob `72a2abf771c18399cad1d4e428fb3a5248a8dea2`. Its September 15 release audit is historical, not verification of the latest release.  
`https://github.com/ferrum-edge/ferrumedge/blob/main/README.md`

**[G6] Foundry frontend toolchain:** `ferrum-edge/ferrum-foundry`, `package.json`, read September 25, 2026; blob `0aa6d5b2b3835cd6f518b87c1ae7994c791cb04e`.  
`https://github.com/ferrum-edge/ferrum-foundry/blob/main/package.json`

**[G7] Website navigation:** `ferrum-edge/ferrumedge`, `assets/js/components.js`, source lines 1–160; blob `8773497489d338fb83a55022be060f88e77a7840`.  
`https://github.com/ferrum-edge/ferrumedge/blob/main/assets/js/components.js`

**[G8] Degraded upstream selection:** `src/load_balancer.rs` and `docs/load_balancing.md`, inspected search excerpts at the gateway SHA above.  
`https://github.com/ferrum-edge/ferrum-edge/blob/8ef06f2cece2847b552b7858c73fa9a1a265442f/docs/load_balancing.md`

**[L1] wrk’s actual modified license:** `wg/wrk`, `LICENSE`, read September 25, 2026; blob `801b0a1924dbe2649d262a91b9f7d1848bedfc94`.  
`https://github.com/wg/wrk/blob/master/LICENSE`

**[W1] Suite product roles:** `https://ferrumedge.com/`, read September 25, 2026.

**[E1] Postman collections reference:** `https://learning.postman.com/docs/use/use-collections/overview/`

**[E2] Insomnia import/export reference:** `https://developer.konghq.com/insomnia/import-export/`

**[E3] SoapUI project workflow:** `https://www.soapui.org/docs/getting-started/projects/working-with-projects/`

**[E4] Apache JMeter project:** `https://jmeter.apache.org/`

**[E5] JMeter execution and certificate defaults:** `https://jmeter.apache.org/usermanual/get-started.html`

**[E6] Tauri architecture/start:** `https://v2.tauri.app/start/`

**[E7] Native-app OAuth guidance, RFC 8252:** `https://www.rfc-editor.org/rfc/rfc8252`

**[E8] OpenAPI 3.2 specification:** `https://spec.openapis.org/oas/v3.2.0.html`

**[E9] Current Tauri native WebDriver options:** `https://v2.tauri.app/develop/tests/webdriver/`

External documentation was reviewed September 25, 2026. Proposed names, contracts, schemas, UI, milestones and acceptance criteria in this plan are design recommendations, not claims about already available features.
