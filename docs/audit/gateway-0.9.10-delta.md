# Ferrum Edge 0.9.9 → 0.9.10: client-observable delta (A00 addendum)

| Item | Value |
|---|---|
| Compatibility ids | `ferrum-edge-0.9.5`, `ferrum-edge-0.9.7`, `ferrum-edge-0.9.8`, `ferrum-edge-0.9.9` (unchanged) and `ferrum-edge-0.9.10` (new, the default for new profiles and the lab's default pin) |
| Releases compared | tag `v0.9.9` = `234717ce41965cd1e2b5c6c761a25475c5d7628c` (`234717c`) → tag `v0.9.10` = `ee040d5e3281fde424aa65f5b18004852c5b53b0` (`ee040d5`, the merge commit of release PR #5956) |
| Audit date | 2026-10-01 |
| Machine-readable inventory | [`catalog/ferrum/ferrum-edge-0.9.10/outcomes.json`](../../catalog/ferrum/ferrum-edge-0.9.10/outcomes.json): **553** outcomes (552 + 1 added, none removed), 2 changed, 1,416 source citations |
| Baseline audit | [`gateway-0.9.9-delta.md`](gateway-0.9.9-delta.md) and [`catalog/ferrum/ferrum-edge-0.9.9/outcomes.json`](../../catalog/ferrum/ferrum-edge-0.9.9/outcomes.json) |
| Source diff | 4 files under `src/` differ; 412 insertions and 62 deletions (`src/plugins/ai_prompt_shield.rs` +166/−15, `src/plugins/ai_transcript_audit.rs` +121/−46, `src/plugins/utils/mcp_jsonrpc.rs` +113, `src/plugins/mcp_gateway.rs` +12/−1) |
| Merges | #5954 (`7b42fe4`, "Fail closed on uninspectable MCP prompt-shield batches"; GHSA-4f9m-cfqg-fhx9, GHSA-f2jp-59r9-fp64) and the release PR #5956 (`9dae5c9`, `ee040d5`) |
| Wire libraries | `Cargo.lock` changes only the crate's own version (`0.9.9` → `0.9.10`); rustls, hyper (vendored, same three patches), h2, h3, quinn and reqwest are unchanged |
| Release pin | `lab/gateway/RELEASE.lock` = `lab/gateway/releases/v0.9.10.lock`: the published `.sha256` of each release asset (identical to the GitHub asset digests) |
| Contracts | unchanged: `contracts/ferrum-contracts/` stays at `ferrum-contracts` `contracts-edge-0.9.9` (`25c4e9e`). v0.9.10 changes no contract source, and `ferrum-contracts` `docs/versioning.md` maps Edge v0.9.10 to that tag |

All `path:line` citations below are at `v0.9.10` (`ee040d5`) unless marked otherwise.

## Method

- **Read-only.** Both tags were read with `git show` / `git diff` from a clone of
  `ferrum-edge/ferrum-edge`. The gateway repository was never checked out, built or run.
- **Mechanical carry-forward.** Every source citation of the 552 carried outcomes was remapped
  through the `v0.9.9..v0.9.10` line map of its file. Only the four files above differ; 57
  citations point into them, and none landed in a changed hunk. The cited line text is identical in
  both trees. The prose `path:line` references to those files were remapped the same way
  (`ai_prompt_shield.rs:1202` → `:1232`, `:2053` → `:2178`; `mcp_gateway.rs:4833` → `:4835`). Every
  citation carries sha `ee040d5`.
- **Changed-function screen.** Each outcome that cites one of the four files was re-read against
  the hunks of its file: the `ai_prompt_shield` outcomes (`before_proxy`, `on_final_request_body`),
  the `mcp_gateway` outcomes (only `content_type_is_json` and the new
  `mcp_request_content_type_is_json` change), and `ai_transcript_audit`'s `audit_unavailable`
  (request staging). Public literals (status, JSON body, header names, JSON-RPC code) were compared
  between the trees.
- **Literal diff.** One proxied-response literal is new, the message values of an existing body:
  `ai_prompt_shield`'s `{"error":"MCP request body could not be inspected","message":"<reason>"}`
  (`src/plugins/ai_prompt_shield.rs:528`) now also carries the reasons `unsupported_charset` and
  `jsonrpc_request_unparseable`. No literal is removed. `mcp_gateway` adds no literal: the charset
  refusal reuses its `-32600` "Invalid MCP JSON-RPC request".
- **CHANGELOG.** The three `[0.9.10]` Security entries were checked against the code. The release
  PR changes only version strings (Cargo, Helm charts and examples), `CHANGELOG.md` and
  `docs/plugins.md`.
- **Mechanical checks of the result.** The catalog was generated from the 0.9.9 catalog by a script
  that refuses any citation landing in a changed hunk and checks the text of every new citation.
  Every public body of the new outcome was matched against all 0.9.9 and 0.9.10 outcomes: it matches
  only the new outcome, and only in the 0.9.10 catalog. The drift test
  (`crates/anvil-diagnostics/tests/catalog_drift.rs`) checks the five catalogs for internal
  consistency in CI.
- **Not verified live.** This change was prepared without running the lab or any test. GitHub CI
  runs the `core` profile against the new default pin on the pull request; the nightly lab runs
  every profile against v0.9.10, v0.9.9, v0.9.8, v0.9.7 and v0.9.5.
- **Not a completeness proof.** As with the earlier audits, only strings seen in code are
  recorded.

## Unchanged: the marker contract and G01

`src/retry.rs`, `src/proxy/` and `src/diagnostic_ref.rs` are byte-identical. The eight
`X-Gateway-Error` tokens, the 19 error classes, the gateway-owned header list and
`X-Ferrum-Diagnostic-Ref` (with its admin lookup) are unchanged. The 0.9.10 catalog's
`marker_semantics` carry the 0.9.9 sentences with the release name changed, and its `headers` are
the 0.9.9 ones. Marker-derived claims stay capped at likely; a bound G01 lookup record remains the
only way to `confirmed`.

## New outcome

| Outcome | Public signal | Where | Notes |
|---|---|---|---|
| `plugin.ai_prompt_shield.mcp_body_uninspectable` | 400 `{"error":"MCP request body could not be inspected","message":"<reason>"}`, reason `unsupported_charset`, `jsonrpc_request_unparseable` or `unsupported_content_encoding` | `src/plugins/ai_prompt_shield.rs:528`, `:1967`, `:1973`, `:2050`, `:2353`, `:2390`, `:2413`; `src/plugins/utils/mcp_jsonrpc.rs:79`, `:196` | See below. `scan_fields: mcp_arguments` only. |

The three reasons:

- **`unsupported_charset`** (GHSA-4f9m-cfqg-fhx9). With `reject` or `redact`, an in-scope request
  whose `Content-Type` declares a `charset` other than `utf-8` / `utf8` (case-insensitive,
  optionally quoted, whitespace tolerated), or uses any RFC 2231 `charset*` form, is refused before
  the body is parsed (`:1973`). The same rule is applied again to the final `Content-Type`
  (`:2353`). `content_type_charset_is_utf8` (`mcp_jsonrpc.rs:79`) makes the decision; a request
  with no `charset` is unaffected. `warn` records `ai_shield_warnings=unsupported_charset` and
  forwards the request.
- **`jsonrpc_request_unparseable`** (GHSA-f2jp-59r9-fp64). With `reject` or `redact`, a body the
  whole-document JSON parse refuses is now refused when `may_carry_tool_call`
  (`mcp_jsonrpc.rs:196`) flags it, in `before_proxy` (`:2050`) and at the final re-check (`:2413`).
  It flags a body that:
  - starts with a byte-order mark;
  - is UTF-16 / UTF-32 JSON;
  - has `/`, `#` or a non-ASCII character as its first character after ASCII whitespace;
  - or is an object or array that names `tools/call` or contains a JSON escape.

  This covers a batch nested past serde_json's recursion limit, which `mcp_gateway` still admits
  member by member. The final re-check also refuses any non-UTF-8 body (`:2390`), which
  `before_proxy` never saw as text. Bodies that cannot name a call still pass uninspected: an empty
  bridged body, REST bodies, base64 `grpc-web-text` and malformed JSON naming no call. `warn`
  records `ai_shield_warnings=jsonrpc_request_unparseable` and forwards the request.
- **`unsupported_content_encoding`**. Not new: v0.9.9 already refused a non-identity
  `Content-Encoding` with this body, in every action including `warn`
  (`src/plugins/ai_prompt_shield.rs:1858@234717c`). The 0.9.9 catalog did not record it. It is
  recorded here as the outcome's third reason (`drift` `catalog_gaps_backfilled`, the precedent of
  the 0.9.8 catalog), and the 0.9.9 catalog stays as audited.

`ai_prompt_shield` runs at priority 2925, before `mcp_gateway` at 2992. On a route with both, an
enforcing shield answers this 400 for a non-UTF-8 charset; without the shield, `mcp_gateway`
answers `-32600` (below).

## Changed outcomes

| Outcome | Change | Evidence |
|---|---|---|
| `plugin.mcp_gateway.invalid_request` | Also answered, before routing, for a request whose `Content-Type` `charset` is not `utf-8` / `utf8` or uses an RFC 2231 `charset*` form (GHSA-4f9m-cfqg-fhx9). Same HTTP 200 JSON-RPC `-32600` "Invalid MCP JSON-RPC request" body with `id: null`; responses keep the plain media-type check. | `src/plugins/mcp_gateway.rs:1671`, `:7941`, `:7287` |
| `plugin.ai_transcript_audit.audit_unavailable` | With `capture.mcp_tool_calls`, a body the whole-document parse refuses but that may carry a `tools/call` is now staged as an MCP audit candidate. Such a body counts against the staging permits and retained budget, so `sink.on_buffer_full: reject` can answer this 503 for more requests. Same signal. | `src/plugins/ai_transcript_audit.rs:3788` |

Two outcomes gain only a cross-reference to the new outcome in their notes:
`plugin.ai_prompt_shield.uninspectable` and `plugin.ai_prompt_shield.mcp_arguments_refused`.
Neither changes its signal: the deferred-body `Request body could not be inspected` path is
unchanged, because the deferred check still runs before the new non-UTF-8 branch at `:2390`.

`ai_transcript_audit`'s other changes are visible only in operator records. It now records MCP
tool calls in bodies the whole-document parse refuses, using the bounded recognizer, and keys
their arguments when the body is within the scan ceiling.

## Anvil changes this delta drives

- **Catalogs.** `anvil_diagnostics::ferrum` embeds `ferrum-edge-0.9.10` and makes it the default for
  new profiles (desktop dialog, CLI `--trust-ferrum`). The new refusal matches only a profile
  declaring `ferrum-edge-0.9.10`. A new unit test, `outcomes_new_in_0_9_10_match_only_their_own_catalog`,
  checks all three messages against the 0.9.10 and 0.9.9 catalogs.
- **Wording.** No new finding codes: the new outcome is worded from the catalog through
  `ferrum.outcome`, and no `X-Gateway-Error` token is new.
- **Contracts.** No re-vendoring: `PIN` stays `contracts-edge-0.9.9`. The contract drift test
  (`crates/anvil-diagnostics/tests/contracts_adoption.rs`) now compares the pinned vocabularies with
  the 0.9.9 and the 0.9.10 catalogs (the releases the tag covers) instead of the 0.9.9 catalog
  alone. It also requires the lab's default pin to be one of them, so a later pin bump has to decide
  the contract tag explicitly.
- **Lab.** The default pin is v0.9.10 (`lab/gateway/RELEASE.lock`,
  `lab/gateway/releases/v0.9.10.lock`). v0.9.9 joins the earlier supported releases and the nightly
  matrix. `available_releases()` now lists releases in version order, so `v0.9.10` sorts after
  `v0.9.9`. The lab profiles validate on v0.9.10 unchanged: `src/config/` and every plugin key set
  the lab uses are byte-identical (`lab/gateway/lint-profiles.rb`).

## Lab

No scenario changes its expectation on v0.9.10, and none needs a `release_at_least("v0.9.10")` gate.
The lab configures no `ai_prompt_shield` or `ai_transcript_audit`. Anvil's MCP requests (the `mcp`
profile) send `Content-Type: application/json` without a `charset`. Every other profile is untouched
by the four changed files.

## Not verified live (source only)

- The new refusal and the `mcp_gateway` charset refusal: no lab profile configures
  `ai_prompt_shield` with `scan_fields: mcp_arguments` or sends a non-UTF-8 charset.
- That the lab's existing expectations hold on v0.9.10: they are expected to, since nothing they
  exercise changed. Evidence comes from the pull request's `core` run and a dispatched `all` run on
  v0.9.10.
