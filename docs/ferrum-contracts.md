# Ferrum contracts

Anvil vendors the Ferrum Edge contracts it consumes under
[`contracts/ferrum-contracts`](../contracts/ferrum-contracts). The current pin
is recorded in `contracts/ferrum-contracts/PIN`: tag
`contracts-edge-0.9.9`, commit `25c4e9e00033d7941a1dd0ab733fa74e735546ae` (Ferrum Edge
v0.9.9). The tag also covers Ferrum Edge v0.9.10, the lab's default pin:
v0.9.10 changed no contract source, so `ferrum-contracts` maps it to the same
tag. That tag marks `X-Ferrum-Diagnostic-Ref` released in v0.9.9 and
publishes `schemas/diagnostic-ref/v1.schema.json` with its fixtures under
`contracts/ferrum-contracts`. Anvil reads the header and lookup record (see
[diagnostics.md](diagnostics.md#gateway-diagnostic-references-g01)).
The offline `anvil-diagnostics` test suite checks every vendored file against
its pinned SHA-256, compares the local gateway vocabulary, header list and
DiagnosticFinding schema with the vendor copy (the vocabulary against the
catalog of every Edge release the tag covers; the lab's default pin must be one
of them), compares Anvil's diagnostic reference reader with the pinned
`diagnostic-ref` schema's vocabularies, and validates the shared schema
fixtures (the `diagnostic-ref` ones also through Anvil's reader).

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
