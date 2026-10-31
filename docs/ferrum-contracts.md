# Ferrum contracts

Anvil vendors the Ferrum Edge contracts it consumes under
[`contracts/ferrum-contracts`](../contracts/ferrum-contracts). The current pin
is recorded in `contracts/ferrum-contracts/PIN`: published tag
`contracts-edge-0.9.15`, commit `6fb64c5dc2e014204c17609fc717d976f3b4589e`,
targeting immutable Edge v0.9.15 (`25b37395ff61bfea0f3ffd189d9011c4984fa755`).
Publication is verified by [canonical PR #23](https://github.com/ferrum-edge/ferrum-contracts/pull/23),
the successful [main validation](https://github.com/ferrum-edge/ferrum-contracts/actions/runs/37841329610)
and the [tag release](https://github.com/ferrum-edge/ferrum-contracts/releases/tag/contracts-edge-0.9.15).
The lab and new-profile default select v0.9.15, with
[hosted Anvil qualification](audit/gateway-0.9.15-delta.md#qualification-status)
recorded. Earlier catalogs and locks remain supported, each tied to its own
contracts tag:

| Edge release | Contracts tag |
| --- | --- |
| v0.9.15 | `contracts-edge-0.9.15` |
| v0.9.14 | `contracts-edge-0.9.14` |
| v0.9.11 | `contracts-edge-0.9.11` |
| v0.9.9, v0.9.10 | `contracts-edge-0.9.9` (or its additive r2 revision) |

Vendored files keep their historical PROPOSED descriptions and
preparation-time publication wording byte-exact; current publication facts
are documented here. Owner (Alloy) availability remains unreleased. The
`route_protocol_admission` rejection phase added in v0.9.15 maps to no token.
Import semantics are in
[shared-diagnostics-import.md](architecture/shared-diagnostics-import.md), and
the v0.9.15 delta in [the Edge delta audit](audit/gateway-0.9.15-delta.md).

## What CI checks

Hosted `anvil-diagnostics` gates check every vendored byte against `PIN` and
exact adopted file presence; token/class/header parity with the
0.9.9/0.9.10/0.9.11/0.9.14/0.9.15 catalogs; the current owner source
identity; local DiagnosticFinding schema parity; and strict diagnostic-ref
reader vocabularies. All original fixtures and precise negative expectations
are exercised by the independent schema gate and the real parser. Alloy
report parity removes only `$id`/`x-contract`, including description parity.
The lab default must be covered by the pin, and its catalog source must match
its release lock. These checks use no network and do not establish live
gateway compatibility.

## Bumping the pin

1. Choose an immutable `contracts-edge-*` release tag and resolve its commit
   SHA (dereference annotated tags).
2. Download the scoped vocabulary, schema, and fixture files from that tag
   into `contracts/ferrum-contracts`, preserving their paths and bytes.
3. Update `PIN` with the tag, commit SHA, and SHA-256 of every vendored file.
4. Reconcile local catalogs, token mappings, and schemas with the new contract.
   Keep older Edge compatibility catalogs tied to their own releases.
5. Run the normal CI suite. Its pinned-contract checks must pass before
   merging the update.

Contract checks perform no network access; the downloaded files and hashes
are committed with the change.
