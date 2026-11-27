# Ferrum contracts

Anvil vendors the Ferrum Edge contracts it consumes under
[`contracts/ferrum-contracts`](../contracts/ferrum-contracts). The current pin
is recorded in `contracts/ferrum-contracts/PIN`: published tag
`contracts-edge-0.9.21`, commit `92d8da5be93ea1ece9f47729b1f7aa10ae8a7c3f`,
targeting immutable Edge v0.9.21 (`f9915358c8032214f4034a17c28cdf72d14006c3`).
Its release record is `docs/releases/contracts-edge-0.9.21.md` at that tag, and the
[tag release](https://github.com/ferrum-edge/ferrum-contracts/releases/tag/contracts-edge-0.9.21)
records the signed-tag verification.
The lab and new-profile default select v0.9.21, source-audited (hosted Anvil
qualification status in
[the delta audit](audit/gateway-0.9.21-delta.md#qualification-status)).
Earlier catalogs stay embedded for existing profiles, each tied to its own
contracts tag; their lab locks were retired (see [lab/README.md](lab/README.md)):

| Edge release | Contracts tag |
| --- | --- |
| v0.9.21 | `contracts-edge-0.9.21` |
| v0.9.20 | `contracts-edge-0.9.20` |
| v0.9.15 | `contracts-edge-0.9.15` |
| v0.9.14 | `contracts-edge-0.9.14` |
| v0.9.11 | `contracts-edge-0.9.11` |
| v0.9.9, v0.9.10 | `contracts-edge-0.9.9` (or its additive r2 revision) |

Vendored files keep their historical PROPOSED descriptions and
preparation-time publication wording byte-exact; current publication facts
are documented here. Owner (Alloy) availability remains unreleased. The
`route_protocol_admission` rejection phase added in v0.9.15 maps to no token.

`contracts-edge-0.9.21` changes three vendored files and adds two. The gateway
error vocabulary (Edge v0.9.21 provenance; `circuit_breaker_open` keeps only the
`circuit_breaker_open` rejection phase because HTTP/3 no longer logs the
`circuit_breaker` alias; the nine tokens, 19 error classes and mappings are
unchanged), the header vocabulary (repinned; no gateway diagnostic header added,
removed or renamed) and the negative manifest change. The manifest names one new
invalid diagnostic-ref fixture, `grpc-post-required-as-detail-phase.json`, so it
and its valid counterpart (an `all`-mode gRPC-Web reference resolving with
`status: 200` and raw phase `grpc_post_required`, both accepted by Anvil's
reader) are vendored: diagnostic-ref fixtures are now 11 valid and 13 invalid.
The schemas are byte-identical. The pinned vocabulary covers the 0.9.21 catalog
only; the table above keeps each older release's mapping. The v0.9.21 delta is
in [the Edge delta audit](audit/gateway-0.9.21-delta.md#contracts-and-g01).

Previously, `contracts-edge-0.9.20` changed four vendored files: the gateway error and
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
byte against `PIN` and exact adopted file presence; token/class/header parity with the 0.9.21
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

### Pending for the Edge 1.0.0 and `contracts-edge-1.0.0` adoption

The audit below was made against the Edge candidate commit `f1b4d3739d`
(prepared as 1.0.0). Anvil pins v0.9.21 and `contracts-edge-0.9.21`, and adopts
1.0.0 only after both the Edge release and its contracts release are available.
The adoption PR follows the v0.9.21 adoption ([audit](audit/gateway-0.9.21-delta.md)):

- **Lab pin.**
  - Add `lab/gateway/releases/v1.0.0.lock` and repin `lab/gateway/RELEASE.lock`
    from the published asset digests.
  - Decide whether v0.9.21 stays supported. The Lab supports one release at a
    time, so retiring it removes `lab/gateway/releases/v0.9.21.lock` and
    `--release v0.9.21` stops working.
  - Update the supported-release and ordering tests in
    `crates/anvil-lab/src/gateway.rs` and the matrix comment in `lab.yml`.
- **Versioned Lab commands and default-pin statements.** These name v0.9.21 and
  must move to the new pin, or to version-free wording where it reads naturally
  (`docs/ci.md` refers to "the default pin in `lab/gateway/RELEASE.lock`"). If
  the v0.9.21 lock is retired, every runnable `v0.9.21` example below fails with
  exit 2:
  - runnable fetch and run commands: `docs/ci.md` (`fetch-gateway.sh v0.9.21`,
    `--release v0.9.21`), `docs/lab/README.md` (the same commands and the
    `ferrum-edge-0.9.21` compatibility id), `lab/scripts/fetch-gateway.sh` (its
    usage comment) and `crates/anvil-lab/src/main.rs` (the `--release`
    examples);
  - "current default pin" statements:
    - `docs/load.md` ("`lab/gateway/RELEASE.lock`, v0.9.21, the only supported
      release");
    - `docs/protocols.md` (§3.3 and the mesh coverage paragraph, "the default
      pin, v0.9.21");
    - `README.md` (the Lab line), `docs/lab/README.md` (the selected default),
      `docs/diagnostics.md` (the catalog table default and the "only supported
      release" sentence) and ADR 0007;
    - `docs/completion-report.md` (gateway compatibility target, Lab profiles,
      supported gateway release);
    - the UP-017 and UP-019 reasons in `docs/verification/matrix-status.json`
      and both matrix-coverage files;
    - the header of `lab/gateway/lint-profiles.rb` and the profile header
      comments in `lab/gateway/*.yaml` / `*.conf`.
- **Lab profiles.**
  - `lab/gateway/lint-profiles.rb` already leaves out the passive health-check
    keys that `f1b4d3739d` removes (`gateway_error_codes`,
    `split_external_local_origin_errors`).
  - Every Lab profile and Admin body (`cpdp-seed-*.json`, the `cpdp` tick route)
    was checked against that commit's `openapi.yaml` and uses only declared keys.
  - Every key of the native mesh documents was found in that commit's mesh config
    structs; that check was by name only.
  - Repeat both checks at the published tag.
- **Catalog.**
  - Derive `catalog/ferrum/ferrum-edge-1.0.0/outcomes.json` from 0.9.21, set
    `DEFAULT_COMPATIBILITY_ID` and embed the new catalog.
  - In `crates/anvil-diagnostics/src/ferrum.rs`,
    `unknown_compatibility_ids_get_no_catalog_and_only_the_shared_vocabulary`
    uses `ferrum-edge-1.0.0` as an unknown id; change that.
  - Update the per-release test lists, `Dialogs.tsx` `FERRUM_COMPATIBILITY`,
    e2e spec 06 and the `.gitleaks.toml` catalog allowlist path.
- **Contracts.**
  - Follow the bump steps above.
  - Then update `contracts_adoption.rs` (tag, commit, provenance,
    `PINNED_RELEASES`, file list, fixture count) and the canonical fixture counts
    in `diagnostic_import.rs`, `cmd_diagnostic_import.rs` and e2e spec 11.
- **Evidence.** Add a `docs/audit/gateway-1.0.0-delta.md` audit, update this page
  and the README contracts line, and dispatch the hosted Lab against the new pin.

The pinned contract checks perform no network access; the downloaded files and
hashes are committed with the change. Only the weekly Edge main check reads the
two public repositories at their current `main` (see
[Checking against Edge main](#checking-against-edge-main)).
