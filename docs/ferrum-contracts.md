# Ferrum contracts

Anvil vendors the Ferrum Edge contracts it consumes under
[`contracts/ferrum-contracts`](../contracts/ferrum-contracts). The current pin
is recorded in `contracts/ferrum-contracts/PIN`: published tag
`contracts-edge-0.9.20`, commit `39da322083044c2e92617209e62983c92387f0ad`,
targeting immutable Edge v0.9.20 (`e4a606a00352674daaef08636e3e359e6c48ba18`).
Publication is verified by [canonical PR #47](https://github.com/ferrum-edge/ferrum-contracts/pull/47),
the successful [main validation](https://github.com/ferrum-edge/ferrum-contracts/actions/runs/41611708250)
and the [tag release](https://github.com/ferrum-edge/ferrum-contracts/releases/tag/contracts-edge-0.9.20).
The lab and new-profile default select v0.9.20, source-audited with
[hosted Anvil qualification](audit/gateway-0.9.20-delta.md#qualification-status)
recorded. Earlier catalogs stay embedded for existing profiles, each tied to
its own contracts tag; their lab locks were retired (see
[lab/README.md](lab/README.md)):

| Edge release | Contracts tag |
| --- | --- |
| v0.9.20 | `contracts-edge-0.9.20` |
| v0.9.15 | `contracts-edge-0.9.15` |
| v0.9.14 | `contracts-edge-0.9.14` |
| v0.9.11 | `contracts-edge-0.9.11` |
| v0.9.9, v0.9.10 | `contracts-edge-0.9.9` (or its additive r2 revision) |

Vendored files keep their historical PROPOSED descriptions and
preparation-time publication wording byte-exact; current publication facts
are documented here. Owner (Alloy) availability remains unreleased. The
`route_protocol_admission` rejection phase added in v0.9.15 maps to no token.

`contracts-edge-0.9.20` changes four vendored files: the gateway error and
header vocabularies (Edge v0.9.20 provenance; the closed token vocabulary adds
`loop_detected`, the proxy hop limit 508, so it has nine tokens; the 19 error
classes and their mappings are unchanged), the diagnostic-ref schema (adds
`loop_detected` to `gateway_error` and `detail.rejection_phase`, both accepted
by Anvil's reader) and the negative manifest. The manifest names five new
invalid diagnostic-ref fixtures, so they and their five valid counterparts are
vendored: diagnostic-ref fixtures are now 10 valid and 12 invalid. Because the
older catalogs lack `loop_detected`, the pinned vocabulary covers the 0.9.20
catalog only; the table above keeps each older release's mapping. Import
semantics are in
[shared-diagnostics-import.md](architecture/shared-diagnostics-import.md), and
the v0.9.20 delta in [the Edge delta audit](audit/gateway-0.9.20-delta.md#contracts-and-g01).

## What CI checks

Hosted `anvil-diagnostics` gates parse `PIN` strictly (positional headers;
sorted, unique, canonical rows; no `PIN` self-row), refuse a symbolic link or
any other non-regular entry under the vendored tree, and check every vendored
byte against `PIN` and exact adopted file presence; token/class/header parity with the 0.9.20
catalog; the current owner source
identity; local DiagnosticFinding schema parity; and strict diagnostic-ref
reader vocabularies. All original fixtures and precise negative expectations
are exercised by the independent schema gate and the real parser. Alloy
report parity removes only `$id`/`x-contract`, including description parity.
The lab default must be covered by the pin, and its catalog source must match
its release lock. These pinned checks use no network and do not establish
live gateway compatibility; the weekly Edge main check below is the one that
reads the network.

## Checking against Edge main

The pin binds these checks to a released Edge, so they cannot see a change
that has landed only on Edge `main`. The weekly `edge-main-drift.yml` workflow
is the early warning for that (ferrum-edge/ferrum-contracts#76). It runs three
ignored tests in `crates/anvil-diagnostics/tests/contracts_adoption.rs`:

- `edge_main_vocabulary_matches_anvils_reader` reads Edge `main`'s
  `src/retry.rs` at the resolved commit (`ANVIL_EDGE_MAIN_RETRY_RS`). It
  compares the `X-Gateway-Error` tokens in `HTTP_OBSERVABILITY_ERROR_CLASSES`
  and the `ErrorClass::as_str` labels with Anvil's lookup reader
  (`gateway_detail::TOKENS`, `gateway_detail::ERROR_CLASSES`) and the
  `ferrum.token.*` wording. ferrum-contracts' vocabularies describe the
  release and record main's changes only in prose (`main_branch_delta.summary`),
  so only Edge's source shows a value main adds.
- `contracts_main_vocabularies_match_anvil` and
  `contracts_main_diagnostic_ref_matches_anvils_reader` run the pinned parity
  assertions against ferrum-contracts `main` (`ANVIL_CONTRACTS_MAIN_DIR`):
  every path `PIN` lists, plus every diagnostic-ref and DiagnosticFinding
  fixture main has, at one resolved contracts commit.

```bash
ANVIL_CONTRACTS_MAIN_DIR=/path/to/contracts-files ANVIL_EDGE_MAIN_RETRY_RS=/path/to/retry.rs \
  cargo test -p anvil-diagnostics --test contracts_adoption -- --ignored --exact \
  contracts_main_vocabularies_match_anvil contracts_main_diagnostic_ref_matches_anvils_reader \
  edge_main_vocabulary_matches_anvils_reader
```

The workflow first lists the ignored tests and stops if any of the three is
missing, so a rename cannot turn the check into a run of nothing. A failure, or
a vendored path missing on `main`, is a finding. A check that could not run (a
fetch, setup or listing failure) is an error. Either one opens or updates the
one issue labelled `edge-main-drift` whose body starts with the workflow's
marker, and only a clean run closes it. On a pull request or a dispatch from
another branch, which never reach the issue job, the check job itself fails.
The issue names both commits, the `main_branch_delta` commit and how far Edge
`main` has moved past it, and quotes the delta summaries for review. Only the
issue job holds `issues: write`, with the repository's own `GITHUB_TOKEN`. It
is never a required check. The real-gateway lab is not run against Edge `main`:
a lab run diagnoses with the audited catalog of its gateway's release, and
`main` has none.

## Bumping the pin

1. Choose an immutable `contracts-edge-*` release tag and resolve its commit
   SHA (dereference annotated tags).
2. Download the scoped vocabulary, schema, and fixture files from that tag
   into `contracts/ferrum-contracts`, preserving their paths and bytes.
3. Update `PIN` in the canonical consumer format of ferrum-contracts
   [`docs/consumer-pins.md`](https://github.com/ferrum-edge/ferrum-contracts/blob/main/docs/consumer-pins.md):
   `tag <tag>`, `commit <sha>`, then one `<sha256>  <path>` row (two spaces)
   per vendored file, sorted by path byte by byte, with LF endings and a final
   newline. From `contracts/ferrum-contracts`,
   `grep -E '^[0-9a-f]{64}  ' PIN | sha256sum -c` (`shasum -a 256 -c` on macOS)
   checks the hashes.
4. Reconcile local catalogs, token mappings, and schemas with the new contract.
   Keep older Edge compatibility catalogs tied to their own releases.
5. Run the normal CI suite. Its pinned-contract checks must pass before
   merging the update.

The pinned contract checks perform no network access; the downloaded files and
hashes are committed with the change. Only the weekly Edge main check reads the
two public repositories at their current `main` (see
[Checking against Edge main](#checking-against-edge-main)).
