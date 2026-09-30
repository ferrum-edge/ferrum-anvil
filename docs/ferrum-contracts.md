# Ferrum contracts

Anvil vendors the Ferrum Edge contracts it consumes under
[`contracts/ferrum-contracts`](../contracts/ferrum-contracts). The current pin
is recorded in `contracts/ferrum-contracts/PIN`: tag
`contracts-edge-0.9.8`, commit `89ef3917ce6bba142dce50b84f2033d81eb429dd`.
The offline `anvil-diagnostics` test suite checks every vendored file against
its pinned SHA-256, compares the local gateway vocabulary and DiagnosticFinding
schema with the vendor copy, and validates the shared schema fixtures.

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
