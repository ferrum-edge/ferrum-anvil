# Portable bundle resource policy: owner decision required

Status: proposal only. No budget, bundle format, backup compatibility or
public API change is implemented by this document.

The validation-order and allocation-accounting changes associated with
GHSA-jqq4-v58m-6fcw reject invalid directory declarations and mandatory
metadata before payload expansion. They preserve 1 GiB aggregate inflated
bytes, 512 MiB per entry, the integer-quotient compression-ratio limit of
200 and 20,000 entries. Metadata has the same per-entry limit. Attachments
are hashed during reading and their buffers move into `Opened.graph`.

This does not fully remediate the advisory's memory concern. A valid
untrusted bundle, with syntactically valid metadata and matching hashes,
can still retain close to 1 GiB of attachments. Checksums do not authenticate
a share-safe bundle's author. Mandatory metadata itself can be large, and
ZIP directory parsing happens before the application checks its count.
The input archive, parsed objects/history/metadata, vault plaintext and KDF
allocations add overhead beyond the inflated-byte budget. Peak resident
memory has not been measured. Incremental hashing alone cannot eliminate
retention while the public `Opened` contract owns attachment byte vectors.

## Candidate policy for human approval

For normal bundle preview/import, reduce the aggregate inflated-byte budget
to **64 MiB** and the per-entry budget to **32 MiB**, including metadata.
Keep the ratio and entry-count limits unchanged. Count all expanded bytes,
even when their buffers are subsequently released, against the same
cumulative work budget. Retain preflight and the bounded actual-read checks.
These proposed numbers need hosted memory measurements and a corpus of
legitimate exports before approval; they are not a process-memory guarantee.

Compatibility effects:

- Existing format 1 share-safe and format 2 encrypted-transfer bundles above
  either proposed limit would be refused by ordinary preview/import.
  Otherwise their format and vault AAD remain unchanged.
- The exporter can currently produce larger archives. A follow-up must
  decide whether to refuse such exports with a clear preview error, offer
  splitting, or supply an explicitly approved large-import path. Do not
  silently create exports ordinary import cannot open.
- Full backups use the separate ANVILBAK format. This proposal does not
  change that reader or its limits. Any backup-policy change requires its
  own assessment and owner approval.

The repository/product owner, with the security owner, must explicitly
approve the 64 MiB/32 MiB values, the refusal of previously accepted large
bundles, exporter behavior, and whether an exception path is permitted.
Root must prepare that concrete compatibility decision for human approval
before implementing smaller accepted budgets. No such approval is assumed
by this patch.

## Alternative if large-bundle compatibility must be preserved

Introduce a separate streaming/staged import result with attachment handles,
then migrate preview and apply callers away from `Opened`'s owned byte map.
Keep the current accepted byte limits, but add an approved resource policy
for staging, parser allocations, cumulative work, cancellation and cleanup.
That requires portability/API ownership plus desktop/import/storage owner
coordination; leaving the current `open` API in active use retains its risk.
The human owner must decide whether that API and product-flow change is
preferred to refusing large bundles, and approve staging/storage costs.

Root owns the PR, independent security review and hosted CI. Before claiming
full remediation, obtain the owner decision, measure hosted peak memory on
valid and invalid representative archives, and verify the chosen policy's
compatibility and recovery behavior. This proposal contains no exploit
archive or private proof-of-concept data.
