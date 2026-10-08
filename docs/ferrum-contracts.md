# Ferrum contracts

Anvil vendors the Ferrum Edge contracts it consumes under
[`contracts/ferrum-contracts`](../contracts/ferrum-contracts). The current pin
is recorded in `contracts/ferrum-contracts/PIN`: published tag
`contracts-edge-0.9.14`, commit `ddbdd845733b7046c4393ac951011dafb774db33`,
targeting immutable Edge v0.9.14 (`9bd4d5f9caa4ebe8f0ea13e76d8a6e2172eaca7d`).
Publication is verified by [canonical PR #22](https://github.com/ferrum-edge/ferrum-contracts/pull/22),
the successful [main validation](https://github.com/ferrum-edge/ferrum-contracts/actions/runs/37755967635)
and the [tag release](https://github.com/ferrum-edge/ferrum-contracts/releases/tag/contracts-edge-0.9.14).
The lab and new-profile default now select the separately source-audited
v0.9.14 candidate, pending hosted Anvil qualification. Earlier catalogs and locks
remain supported; v0.9.11 retains its mapping to `contracts-edge-0.9.11` and
v0.9.9/v0.9.10 to `contracts-edge-0.9.9` (or its additive r2 revision).

Every existing adopted canonical path is copied byte-exact from the new tag; four
change. The refreshed Edge vocabularies retain all eight tokens, 19 classes, the three
reader headers and their first availability (diagnostic-ref remains v0.9.9);
`gateway-errors.json` adds the v0.9.14 reclassification notes for backend HTTP/2
resets and buffered read errors without changing a class, token or status. The
diagnostic-ref schema only re-reads its provenance at v0.9.12 source, and the
diagnostic-report schema and every diagnostic fixture are byte-identical to
`contracts-edge-0.9.11`. The diagnostic-report metadata records EXISTING/implemented shared v1 and the
accepted unchanged wire freeze at qualified Alloy owner
`81cbb410d34ff5fba1f3d54cfd2e7ebccaed397e`. Owner availability remains unreleased.
Historical PROPOSED descriptions and preparation-time publication wording inside
immutable vendor files remain exact; current publication facts are documented here.
Wire constraints, fixtures, bounds and open-enum/unknown-member semantics do not change.
The full negative manifest adds other scopes while preserving every original
precise diagnostic failure path/keyword/top-keyword. Those scopes do not add import formats.

Read-only import keeps supplied claims unverified with unknown Anvil confidence;
it performs no apply, persistence, network fetch, Edge lookup, trust/confirmed escalation
or timing attribution. The existing real Alloy exporter golden and source/PIN stay
historical Edge 0.9.10 evidence at owner `0c260f5379939ff46d681666bfbcd65b8518b08d`.
See [shared-diagnostics-import.md](architecture/shared-diagnostics-import.md) and
[the Edge delta audit](audit/gateway-0.9.14-delta.md).

Hosted `anvil-diagnostics` gates check every vendor byte against PIN, exact adopted
file presence, token/class/header parity with the 0.9.9/0.9.10/0.9.11/0.9.14 catalogs,
the current owner source identity, local DiagnosticFinding schema parity and
strict diagnostic-ref reader vocabularies. All original fixtures and negative
expectations remain exercised by the independent schema gate and real parser;
Alloy report parity removes only `$id`/`x-contract`, including description parity.
The lab default must be covered by the pin and its catalog source must match its
release lock. Parsing checks do not establish live gateway compatibility.

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
